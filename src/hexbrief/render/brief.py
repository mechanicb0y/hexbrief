"""Render a BriefResult to Markdown and HTML (human outputs: always defanged).

Every string that came from a feed or the model is untrusted. HTML is protected by
Jinja2 autoescaping. Markdown gets ``md_escape``, which neutralises raw HTML, links,
images and table pipes, so a feed title can't inject a clickable ``javascript:``
link or a fake heading into a brief that may be published.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from hexbrief.render.defang import defang_ioc, defang_text

METHOD_NOTE = "Narrative written by a local AI model; every fact is checked against cited sources."
FACTS_ONLY_NOTE = (
    "Facts-only brief: the AI narrative did not pass validation, so only data-derived "
    "sections are shown."
)

_env = Environment(
    loader=PackageLoader("hexbrief.render", "templates"),
    autoescape=select_autoescape(enabled_extensions=("html.j2",), default=False),
    undefined=StrictUndefined,
    trim_blocks=False,
    lstrip_blocks=False,
    keep_trailing_newline=True,
)

_MD_SPECIAL = re.compile(r"([\\`*_\[\]()|#!])")


def md_escape(text: str) -> str:
    """Escape Markdown/HTML control characters in untrusted text (one line).

    ``<`` / ``>`` become entities (raw HTML is never emitted); link, emphasis,
    heading and table characters get a backslash.
    """
    one_line = " ".join(str(text).split())
    escaped = _MD_SPECIAL.sub(r"\\\1", one_line.replace("&", "&amp;"))
    return escaped.replace("<", "&lt;").replace(">", "&gt;")


def md_code(text: str) -> str:
    """Content for a `code span`: backticks and pipes can't break out of it."""
    return str(text).replace("`", "'").replace("|", "%7C")


def _identity(text: str) -> str:
    return str(text)


def _map_strings(obj: Any, fn: Callable[[str], str]) -> Any:
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, dict):
        return {k: _map_strings(v, fn) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_map_strings(v, fn) for v in obj]
    return obj


def context(
    result: Any,
    *,
    esc: Callable[[str], str] = _identity,
    code: Callable[[str], str] = _identity,
    max_iocs: int = 150,
) -> dict[str, Any]:
    """Template context. ``result`` is an ``engine.BriefResult``."""

    def txt(s: str) -> str:
        return esc(defang_text(s))

    top = []
    iocs, total = [], 0
    for fid, f in result.top:
        top.append(
            {
                "fid": fid,
                "title": txt(f.title),
                "summary": txt(f.summary[:700]),
                "score": int(f.score),
                "reasons": [esc(r) for r in f.reasons],
                "sources": [txt(s) for s in f.sources],
                "tlp": f.tlp,
                "confidence": f.confidence,
                "cves": [code(c) for c in sorted(f.cves)],
                "attack_ids": [code(a) for a in sorted(f.attack_ids)],
                "malware": [txt(m) for m in sorted(f.malware)],
            }
        )
        for ioc in f.iocs:
            total += 1
            if len(iocs) < max_iocs:
                iocs.append({"fid": fid, "type": ioc.type, "value": code(defang_ioc(ioc))})
    techniques = [
        (code(t), n)
        for t, n in Counter(t for _, f in result.top for t in f.attack_ids).most_common(25)
    ]
    # From kev_new, not from finding kind: a KEV entry merged into a report (shared
    # CVE) must still be listed here.
    kev_rows: dict[str, dict[str, Any]] = {}
    for f in result.all_findings:
        for cve, name in f.kev_new.items():
            kev_rows.setdefault(
                cve, {"cve": code(cve), "title": txt(name), "ransomware": f.ransomware}
            )
    kev = [kev_rows[c] for c in sorted(kev_rows)]
    sources = sorted({txt(s) for _, f in result.top for s in f.sources})
    urls = sorted({u for _, f in result.top for u in f.source_urls})[:30]
    return {
        "day": result.day,
        "tlp": result.tlp,
        "window_start": result.window_start,
        "window_end": result.window_end,
        "generated": result.generated,
        "narrative": _map_strings(result.narrative, txt),
        "top": top,
        "kev": kev[:30],
        "techniques": techniques,
        "iocs": iocs,
        "iocs_truncated": max(0, total - len(iocs)),
        "sources": sources + [txt(u) for u in urls],
        "others_count": len(result.others),
        "method_note": METHOD_NOTE if result.llm_ok else FACTS_ONLY_NOTE,
    }


def to_markdown(result: Any) -> str:
    return _env.get_template("brief.md.j2").render(**context(result, esc=md_escape, code=md_code))


def to_html(result: Any) -> str:
    return _env.get_template("brief.html.j2").render(**context(result))
