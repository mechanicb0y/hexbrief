"""The daily brief pipeline (Phase 5).

collect -> normalize -> KEV cross-check -> dedupe -> score -> top N to the LLM
-> validate (hard gate) + completeness -> retry x2 with feedback -> facts-only
fallback -> render (md/html/json, STIX Report) -> run log.

Nothing reaches an output without passing ``hexbrief.validate``.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from hexbrief.model import Finding, max_tlp
from hexbrief.normalize import dedupe, is_asean, is_education
from hexbrief.scoring import rank
from hexbrief.validate import validate_narrative

log = logging.getLogger(__name__)
MYT = ZoneInfo("Asia/Kuala_Lumpur")

Collector = Callable[[datetime, int], list[Finding]]


@dataclass
class BriefResult:
    day: str
    window_start: str
    window_end: str
    generated: str
    tlp: str
    narrative: dict[str, Any]
    llm_ok: bool
    top: list[tuple[str, Finding]]
    others: list[Finding]
    all_findings: list[Finding]
    run_log: dict[str, Any] = field(default_factory=dict)


def completeness_errors(narrative: dict[str, Any], llm_findings: list[dict[str, Any]]) -> list[str]:
    """Omissions the faithfulness check can't see (ADR-005)."""
    errs: list[str] = []
    cited = {
        fid
        for t in narrative.get("top_threats") or []
        if isinstance(t, dict)
        for fid in (t.get("finding_ids") or [])
        if isinstance(fid, str)
    }
    for f in llm_findings[:3]:
        if f["id"] not in cited:
            errs.append(f"completeness: top-ranked finding {f['id']} is not covered in top_threats")
    lens = [f["id"] for f in llm_findings if f.get("_lens")]
    watch = str(narrative.get("education_asean_watch") or "")
    if lens and not any(fid in watch for fid in lens):
        errs.append(
            "completeness: education_asean_watch must cover finding(s) "
            f"{', '.join(lens)} (education / Malaysia / ASEAN) and cite them as [F#]"
        )
    return errs


def facts_only_narrative(top: list[tuple[str, Finding]]) -> dict[str, Any]:
    """Deterministic fallback built only from data (no model)."""
    threats = [
        {
            "finding_ids": [fid],
            "headline": f.title[:140],
            "why_it_matters": "; ".join(f.reasons[:4]) or "Ranked by HexBrief scoring.",
            "actions": [
                "Review the finding and its sources",
                "Check exposure to the listed CVEs / indicators",
            ],
        }
        for fid, f in top[:5]
    ]
    lens = [fid for fid, f in top if is_education(f) or is_asean(f)]
    return {
        "bluf": f"Facts-only brief: {len(top)} top findings ranked by rule-based scoring; "
        "see the tables below.",
        "top_threats": threats,
        "trends": "",
        "education_asean_watch": (
            "Relevant findings: " + ", ".join(f"[{x}]" for x in lens)
            if lens
            else "Nothing notable today."
        ),
        "confidence_note": "No AI narrative today (validation failed); data only.",
    }


def run(
    collectors: dict[str, Collector],
    *,
    now: datetime | None = None,
    hours: int = 24,
    top_n: int = 8,
    writer: Any | None = None,
    fallback_writer: Any | None = None,
    max_retries: int = 2,
    enrich: Callable[[list[Finding]], None] | None = None,
) -> BriefResult:
    started = time.perf_counter()
    now = now or datetime.now(UTC)
    day = now.astimezone(MYT).date().isoformat()
    runlog: dict[str, Any] = {"day": day, "hours": hours, "sources": {}, "llm": {}}

    findings: list[Finding] = []
    for name, collect in collectors.items():
        t0 = time.perf_counter()
        try:
            got = collect(now, hours)
            findings += got
            runlog["sources"][name] = {
                "ok": True,
                "findings": len(got),
                "seconds": round(time.perf_counter() - t0, 1),
            }
        except Exception as exc:  # one bad source must not kill the brief
            log.warning("source %s failed: %s", name, type(exc).__name__)
            runlog["sources"][name] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"[:300]}

    if enrich is not None:
        enrich(findings)  # e.g. KEV cross-check: mark CVEs known to be exploited
    merged = dedupe(findings)
    ranked = rank(merged, now)
    top = [(f"F{i}", f) for i, f in enumerate(ranked[:top_n], start=1)]
    others = ranked[top_n:]
    llm_findings = []
    for fid, f in top:
        row = f.for_llm(fid)
        row["_lens"] = is_education(f) or is_asean(f)
        llm_findings.append(row)
    model_input = [{k: v for k, v in r.items() if not k.startswith("_")} for r in llm_findings]
    runlog.update(
        {"findings_in": len(findings), "after_dedupe": len(merged), "top": [fid for fid, _ in top]}
    )

    narrative, llm_ok = None, False
    attempts: list[dict[str, Any]] = []
    for w in (writer, fallback_writer):
        if w is None or llm_ok or not top:
            continue
        feedback, previous = None, None
        for attempt in range(max_retries + 1):
            res = w.write(model_input, feedback=feedback, previous=previous, seed=7 + attempt)
            val = validate_narrative(res.parsed, model_input)
            comp = completeness_errors(res.parsed or {}, llm_findings) if val.ok else []
            attempts.append(
                {
                    "model": w.model,
                    "seconds": round(res.seconds, 1),
                    "output_tokens": res.output_tokens,
                    "valid": val.ok,
                    "complete": not comp,
                    "errors": (val.errors + comp)[:10],
                    "error": res.error,
                }
            )
            if val.ok and (not comp or attempt == max_retries):
                # Faithful is mandatory; completeness is best effort after retries.
                narrative, llm_ok = res.parsed, True
                break
            feedback, previous = val.errors + comp, res.raw or None
    runlog["llm"] = {
        "ok": llm_ok,
        "attempts": attempts,
        "first_try_pass": bool(attempts and attempts[0]["valid"]),
    }
    if not llm_ok:
        narrative = facts_only_narrative(top)

    tlp = max_tlp(*(f.tlp for _, f in top)) if top else "TLP:CLEAR"
    start_local = (now - timedelta(hours=hours)).astimezone(MYT)
    result = BriefResult(
        day=day,
        window_start=start_local.strftime("%Y-%m-%d %H:%M"),
        window_end=now.astimezone(MYT).strftime("%Y-%m-%d %H:%M"),
        generated=now.astimezone(MYT).strftime("%Y-%m-%d %H:%M MYT"),
        tlp=tlp,
        narrative=narrative or {},
        llm_ok=llm_ok,
        top=top,
        others=others,
        all_findings=ranked,
        run_log=runlog,
    )
    runlog["tlp"] = tlp
    runlog["runtime_seconds"] = round(time.perf_counter() - started, 1)
    return result


def finding_json(f: Finding, fid: str | None = None) -> dict[str, Any]:
    d = asdict(f)
    d["fid"] = fid
    d["first_seen"] = f.first_seen.isoformat() if f.first_seen else None
    for k in ("cves", "attack_ids", "malware", "actors", "sectors", "countries"):
        d[k] = sorted(d[k])
    d["iocs"] = [{"type": i.type, "value": i.value} for i in f.iocs]
    return d


def write_outputs(result: BriefResult, out_dir: Path, runs_dir: Path) -> dict[str, Path]:
    """brief.md/html (defanged), brief.json + brief.stix.json (real values), run log."""
    from hexbrief.render.brief import to_html, to_markdown
    from hexbrief.stix_out import report_bundle
    from hexbrief.stixkit.bundle import validate as validate_stix

    out_dir.mkdir(parents=True, exist_ok=True)
    runs_dir.mkdir(parents=True, exist_ok=True)
    md = to_markdown(result)
    paths = {
        "md": out_dir / "brief.md",
        "html": out_dir / "brief.html",
        "json": out_dir / "brief.json",
        "stix": out_dir / "brief.stix.json",
        "runlog": runs_dir / f"{result.day}.json",
    }
    paths["md"].write_text(md, encoding="utf-8")
    paths["html"].write_text(to_html(result), encoding="utf-8")
    # brief.json also carries lower-ranked findings, so its label must cover them too.
    exported_others = result.others[:500]
    json_tlp = max_tlp(result.tlp, *(f.tlp for f in exported_others))
    result.run_log["json_tlp"] = json_tlp
    paths["json"].write_text(
        json.dumps(
            {
                "day": result.day,
                "tlp": json_tlp,
                "tlp_top": result.tlp,
                "generated": result.generated,
                "llm_ok": result.llm_ok,
                "window": [result.window_start, result.window_end],
                "narrative": result.narrative,
                "top": [finding_json(f, fid) for fid, f in result.top],
                "others": [finding_json(f) for f in exported_others],
            },
            indent=1,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    bundle = report_bundle(
        result.day,
        f"HexBrief daily threat brief {result.day}",
        md,
        [f for _, f in result.top],
        result.tlp,
        datetime.now(UTC),
    )
    stix_report = validate_stix(bundle)
    result.run_log["stix_valid"] = stix_report.is_valid
    if not stix_report.is_valid:
        result.run_log["stix_errors"] = stix_report.errors[:5]
    paths["stix"].write_text(json.dumps(bundle, indent=1, ensure_ascii=False), encoding="utf-8")
    paths["runlog"].write_text(json.dumps(result.run_log, indent=1, default=str), encoding="utf-8")
    return paths


def finding_from_json(d: dict[str, Any]) -> Finding:
    """Inverse of ``finding_json``."""
    from hexbrief.model import Ioc

    f = Finding(key=d["key"], kind=d["kind"], title=d["title"])
    for k, v in d.items():
        if k in ("fid", "key", "kind", "title"):
            continue
        if k == "iocs":
            v = [Ioc(i["type"], i["value"]) for i in v]
        elif k == "first_seen":
            v = datetime.fromisoformat(v) if v else None
        elif k in ("cves", "attack_ids", "malware", "actors", "sectors", "countries"):
            v = set(v)
        setattr(f, k, v)
    return f


def load_result(brief_json: Path) -> BriefResult:
    """Rebuild a BriefResult from brief.json (re-render / re-publish without a new run)."""
    data = json.loads(brief_json.read_text(encoding="utf-8"))
    top = [(d["fid"], finding_from_json(d)) for d in data["top"]]
    others = [finding_from_json(d) for d in data["others"]]
    return BriefResult(
        day=data["day"],
        window_start=data["window"][0],
        window_end=data["window"][1],
        generated=data.get("generated", data["window"][1]),
        tlp=data.get("tlp_top", data["tlp"]),
        narrative=data["narrative"],
        llm_ok=data["llm_ok"],
        top=top,
        others=others,
        all_findings=[f for _, f in top] + others,
        run_log={},
    )
