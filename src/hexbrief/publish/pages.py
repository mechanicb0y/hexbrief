"""The public archive for GitHub Pages: ``site/`` (TLP:CLEAR, defanged HTML only).

Only the public view is ever written here (``public.public_view``), and this module
refuses anything that isn't TLP:CLEAR as a second, independent check.
"""

from __future__ import annotations

import html
import json
import re
from pathlib import Path

from hexbrief.engine import BriefResult
from hexbrief.publish.public import is_clear
from hexbrief.render.brief import to_html, to_markdown

_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def write_brief(result: BriefResult, site: Path) -> Path:
    if not is_clear(result.tlp) or any(not is_clear(f.tlp) for _, f in result.top):
        raise ValueError("refusing to publish a non-TLP:CLEAR brief to the public archive")
    if not _DAY.match(result.day):
        raise ValueError(f"bad day {result.day!r}")
    briefs = site / "briefs"
    briefs.mkdir(parents=True, exist_ok=True)
    page = briefs / f"{result.day}.html"
    page.write_text(to_html(result), encoding="utf-8")
    (briefs / f"{result.day}.md").write_text(to_markdown(result), encoding="utf-8")
    meta = {
        "day": result.day,
        "bluf": result.narrative.get("bluf", ""),
        "llm_ok": result.llm_ok,
        "top": len(result.top),
    }
    (briefs / f"{result.day}.meta.json").write_text(json.dumps(meta) + "\n", encoding="utf-8")
    write_index(site)
    return page


def write_index(site: Path) -> Path:
    from hexbrief.render.defang import defang_text

    briefs = sorted((site / "briefs").glob("*.meta.json"), reverse=True)
    items = []
    for m in briefs:
        meta = json.loads(m.read_text(encoding="utf-8"))
        day = str(meta.get("day", ""))
        if not _DAY.match(day):
            continue
        bluf = html.escape(defang_text(str(meta.get("bluf", "")))[:280])
        tag = "" if meta.get("llm_ok") else ' <span class="tag">facts-only</span>'
        items.append(f'<li><a href="briefs/{day}.html">{day}</a>{tag}<p>{bluf}</p></li>')
    body = "\n".join(items) or "<li>No briefs yet.</li>"
    index = site / "index.html"
    index.write_text(
        INDEX.replace("{{ITEMS}}", body).replace("{{COUNT}}", str(len(items))), encoding="utf-8"
    )
    return index


INDEX = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer">
<title>HexBrief archive</title>
<style>
:root{--bg:#f7f7f5;--fg:#1b1d1f;--muted:#5d6166;--line:#d9dad6;--accent:#0f766e}
@media (prefers-color-scheme:dark){:root{--bg:#111315;--fg:#e7e7e4;--muted:#a2a6aa;--line:#2b2e31;--accent:#2dd4bf}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:860px;margin:0 auto;padding:24px 16px 64px} h1{margin:.2em 0}
ul{list-style:none;padding:0} li{border-bottom:1px solid var(--line);padding:12px 0}
li a{font-weight:700;color:var(--accent)} li p{margin:.3em 0 0;color:var(--muted)}
.tag{font-size:.8rem;border:1px solid var(--line);border-radius:999px;padding:0 .5em;color:var(--muted)}
.tlp{display:inline-block;padding:.15em .6em;border-radius:4px;background:#e9f7ef;color:#14532d;font-weight:700}
</style></head>
<body><main>
<p><span class="tlp">TLP:CLEAR</span></p>
<h1>HexBrief: daily threat-intel briefs</h1>
<p>Automated daily briefs from public STIX/TAXII feeds, MISP and OpenCTI, written by a
<strong>local</strong> LLM and fact-checked against source data before publishing.
Indicators are defanged. {{COUNT}} brief(s).</p>
<ul>
{{ITEMS}}
</ul>
<p style="color:var(--muted);font-size:.9rem">Narratives are written by a local AI model;
every fact is checked against cited sources. Source code: github.com/mechanicb0y/hexbrief</p>
</main></body></html>
"""
