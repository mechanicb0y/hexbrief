"""Faithfulness gate for LLM text: nothing invented gets published.

Checks, in order:
1. the JSON matches ``brief.schema.json``;
2. every cited ``F#`` exists in the input findings;
3. every IP, domain, URL, hash, CVE and ATT&CK ID that appears anywhere in the
   LLM's text exists in the input findings (defanged forms are refanged first);
4. banned hype phrases are absent.

Facts are extracted with deliberately broad regexes: a false alarm only costs a
retry, while a missed invention would be published.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from jsonschema import Draft202012Validator

from hexbrief.llm.client import load_schema

BANNED_PHRASES = (
    "unprecedented",
    "devastating",
    "game-changer",
    "game changer",
    "massive attack",
    "cyber pearl harbor",
    "catastrophic",
    "nightmare",
    "apocalypse",
)

_FILE_EXTS = {
    "exe",
    "dll",
    "sys",
    "bat",
    "cmd",
    "ps1",
    "vbs",
    "js",
    "jar",
    "py",
    "sh",
    "bin",
    "dat",
    "zip",
    "rar",
    "7z",
    "iso",
    "img",
    "lnk",
    "msi",
    "doc",
    "docx",
    "docm",
    "xls",
    "xlsx",
    "xlsm",
    "ppt",
    "pptx",
    "pdf",
    "rtf",
    "txt",
    "csv",
    "json",
    "xml",
    "html",
    "htm",
    "php",
    "asp",
    "aspx",
    "jsp",
    "elf",
    "apk",
    "dmg",
    "hta",
    "one",
    "wsf",
    "log",
    "tmp",
    "cfg",
}

RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
RE_ATTACK = re.compile(r"\b(?:T\d{4}(?:\.\d{3})?|TA\d{4}|G\d{4}|S\d{4}|M\d{4})\b")
RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>\]\)]+", re.IGNORECASE)
# Not followed by a digit or ".digit" (a sentence-ending "." is fine: "C2 at 1.2.3.4.").
RE_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)")
RE_HASH = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")
RE_DOMAIN = re.compile(
    r"\b(?=[a-z0-9-]{1,63}\.)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b",
    re.IGNORECASE,
)


def refang(text: str) -> str:
    """Undo common defanging so 1.2.3[.]4 and hxxp:// are checked like the real thing."""
    out = text.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
    out = re.sub(r"\bhxxp", "http", out, flags=re.IGNORECASE)
    return out.replace("[:]", ":").replace("[://]", "://")


@dataclass(frozen=True)
class Facts:
    cves: set[str] = field(default_factory=set)
    attack_ids: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)


def extract(text: str) -> Facts:
    t = refang(text)
    urls = {u.rstrip(".,;:").lower() for u in RE_URL.findall(t)}
    without_urls = RE_URL.sub(" ", t)
    ips: set[str] = set()
    for cand in RE_IPV4.findall(without_urls):
        try:
            ips.add(str(ipaddress.ip_address(cand)))
        except ValueError:
            continue
    domains = {
        d.lower()
        for d in RE_DOMAIN.findall(RE_IPV4.sub(" ", without_urls))
        if d.rsplit(".", 1)[-1].lower() not in _FILE_EXTS
    }
    return Facts(
        cves={c.upper() for c in RE_CVE.findall(t)},
        attack_ids=set(RE_ATTACK.findall(t)),
        urls=urls,
        ips=ips,
        domains=domains,
        hashes={h.lower() for h in RE_HASH.findall(t)},
    )


def _texts(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _texts(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _texts(v)


def allowed_facts(findings: list[dict[str, Any]]) -> Facts:
    """Everything the model is allowed to mention: facts extracted from the input."""
    blob = "\n".join(_texts(findings))
    f = extract(blob)
    # URL hosts are allowed as domains too.
    hosts = {re.sub(r"^[a-z]+://", "", u).split("/")[0].split(":")[0] for u in f.urls}
    return Facts(f.cves, f.attack_ids, f.urls, f.ips, f.domains | hosts, f.hashes)


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str]
    invented: dict[str, list[str]]


def validate_narrative(
    narrative: dict[str, Any] | None, findings: list[dict[str, Any]]
) -> ValidationResult:
    errors: list[str] = []
    invented: dict[str, list[str]] = {}
    if narrative is None:
        return ValidationResult(False, ["no JSON object produced"], invented)

    schema_errors = sorted(
        Draft202012Validator(load_schema()).iter_errors(narrative), key=lambda e: list(e.path)
    )
    for e in schema_errors[:10]:
        where = "/".join(str(p) for p in e.path) or "(root)"
        errors.append(f"schema: {where}: {e.message}")

    known_ids = {str(f.get("id")) for f in findings}
    for threat in narrative.get("top_threats") or []:
        for fid in threat.get("finding_ids") or []:
            if fid not in known_ids:
                errors.append(f"cites {fid}, which is not in the findings")
    text = "\n".join(_texts(narrative))
    for fid in set(re.findall(r"\[(F\d{1,3})\]", text)) - known_ids:
        errors.append(f"cites [{fid}] in prose, which is not in the findings")

    have, allowed = extract(text), allowed_facts(findings)
    for kind in ("cves", "attack_ids", "urls", "ips", "domains", "hashes"):
        bad = sorted(getattr(have, kind) - getattr(allowed, kind))
        if bad:
            invented[kind] = bad
            errors.append(f"mentions {kind} not in the findings: {', '.join(bad[:5])}")

    low = text.lower()
    for phrase in BANNED_PHRASES:
        if phrase in low:
            errors.append(f'banned phrase: "{phrase}"')
    return ValidationResult(not errors, errors, invented)
