"""Defanging: make indicators unclickable in human-readable output.

Machine outputs (STIX, JSON) keep real values; Markdown, HTML, PDF and the public
archive always use these forms:
    1.2.3.4                -> 1.2.3[.]4
    evil.example.com       -> evil[.]example[.]com
    https://evil.com/a.b   -> hxxps://evil[.]com/a.b
"""

from __future__ import annotations

import re

from hexbrief.model import Ioc
from hexbrief.validate import RE_DOMAIN, RE_IPV4, RE_URL, refang


def defang_ip(value: str) -> str:
    if ":" in value:  # IPv6
        return value.replace(":", "[:]")
    head, _, tail = value.rpartition(".")
    return f"{head}[.]{tail}" if head else value


def defang_domain(value: str) -> str:
    return value.replace(".", "[.]")


def defang_url(value: str) -> str:
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://([^/?#]*)(.*)$", value)
    if not m:
        return value.replace(".", "[.]")
    scheme, host, rest = m.groups()
    scheme = {"http": "hxxp", "https": "hxxps", "ftp": "fxp"}.get(scheme.lower(), scheme)
    return f"{scheme}://{host.replace('.', '[.]').replace(':', '[:]')}{rest}"


def defang_ioc(ioc: Ioc) -> str:
    if ioc.type in ("ipv4", "ipv6"):
        return defang_ip(ioc.value)
    if ioc.type == "domain":
        return defang_domain(ioc.value)
    if ioc.type == "url":
        return defang_url(ioc.value)
    return ioc.value  # hashes are safe as-is


def defang_text(text: str) -> str:
    """Defang every URL, IPv4 and domain inside free text (e.g. LLM prose).

    Already-defanged input is refanged first so nothing gets double-bracketed.
    """
    t = refang(text)
    t = RE_URL.sub(lambda m: defang_url(m.group(0)), t)
    # Protect the defanged URLs from the next passes.
    parts = re.split(r"(\b(?:hxxps?|fxp)://\S+)", t)
    for i, part in enumerate(parts):
        if i % 2 == 1:
            continue
        part = RE_IPV4.sub(lambda m: defang_ip(m.group(0)), part)
        part = RE_DOMAIN.sub(lambda m: _maybe_domain(m.group(0)), part)
        parts[i] = part
    return "".join(parts)


_KEEP = {"e.g", "i.e", "u.s", "etc"}
_FILEISH = re.compile(r"\.(exe|dll|ps1|lnk|bin|bat|vbs|js|docx?|xlsx?|pdf|iso|msi|hta)$", re.I)


def _maybe_domain(token: str) -> str:
    if token.lower() in _KEEP or _FILEISH.search(token):
        return token
    return defang_domain(token)
