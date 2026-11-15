"""Render a BriefResult to Markdown and HTML (human outputs: always defanged)."""

from __future__ import annotations

from collections import Counter
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


def _defang_narrative(n: dict[str, Any]) -> dict[str, Any]:
    if isinstance(n, str):
        return defang_text(n)  # type: ignore[return-value]
    if isinstance(n, dict):
        return {k: _defang_narrative(v) for k, v in n.items()}
    if isinstance(n, list):
        return [_defang_narrative(v) for v in n]  # type: ignore[return-value]
    return n


def context(result: Any, *, max_iocs: int = 150) -> dict[str, Any]:
    """Template context. ``result`` is an ``engine.BriefResult``."""
    top = []
    iocs, total = [], 0
    for fid, f in result.top:
        top.append(
            {
                "fid": fid,
                "title": defang_text(f.title),
                "summary": defang_text(f.summary[:700]),
                "score": int(f.score),
                "reasons": f.reasons,
                "sources": f.sources,
                "tlp": f.tlp,
                "confidence": f.confidence,
                "cves": sorted(f.cves),
                "attack_ids": sorted(f.attack_ids),
                "malware": sorted(f.malware),
            }
        )
        for ioc in f.iocs:
            total += 1
            if len(iocs) < max_iocs:
                iocs.append({"fid": fid, "type": ioc.type, "value": defang_ioc(ioc)})
    techniques = Counter(t for _, f in result.top for t in f.attack_ids).most_common(25)
    kev = [
        {"cve": c, "title": defang_text(f.title.split(": ", 1)[-1]), "ransomware": f.ransomware}
        for f in result.all_findings
        if f.in_kev and f.kind == "vulnerability"
        for c in sorted(f.cves)
    ]
    sources = sorted({s for _, f in result.top for s in f.sources})
    urls = sorted({u for _, f in result.top for u in f.source_urls})[:30]
    return {
        "day": result.day,
        "tlp": result.tlp,
        "window_start": result.window_start,
        "window_end": result.window_end,
        "generated": result.generated,
        "narrative": _defang_narrative(result.narrative),
        "top": top,
        "kev": kev[:30],
        "techniques": techniques,
        "iocs": iocs,
        "iocs_truncated": max(0, total - len(iocs)),
        "sources": sources + [defang_text(u) for u in urls],
        "others_count": len(result.others),
        "method_note": METHOD_NOTE if result.llm_ok else FACTS_ONLY_NOTE,
    }


def to_markdown(result: Any) -> str:
    return _env.get_template("brief.md.j2").render(**context(result))


def to_html(result: Any) -> str:
    return _env.get_template("brief.html.j2").render(**context(result))
