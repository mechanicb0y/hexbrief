"""End-to-end engine tests with fake collectors and a fake LLM (no services)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from hexbrief.engine import completeness_errors, run, write_outputs
from hexbrief.model import Finding, Ioc

NOW = datetime(2026, 11, 15, 23, 0, tzinfo=UTC)  # 07:00 MYT on 16 Nov


def kev_finding() -> Finding:
    return Finding(
        key="CVE-2026-20001",
        kind="vulnerability",
        title="CVE-2026-20001: VPN RCE",
        summary="Exploited VPN appliance flaw.",
        sources=["CISA KEV"],
        first_seen=NOW - timedelta(hours=5),
        confidence=95,
        cves={"CVE-2026-20001"},
        in_kev=True,
        exploited=True,
    )


def report_finding() -> Finding:
    return Finding(
        key="report--1",
        kind="report",
        title="Phishing against universities in Malaysia delivers ExampleRAT",
        summary="Scholarship-themed lures; uses CVE-2026-20001 for follow-on access.",
        sources=["AlienVault OTX"],
        first_seen=NOW - timedelta(hours=3),
        confidence=70,
        iocs=[Ioc("domain", "scholarship-portal.example.test"), Ioc("ipv4", "198.51.100.23")],
        cves={"CVE-2026-20001"},
        attack_ids={"T1566.001"},
        sectors={"education"},
        countries={"Malaysia"},
        stix_ids=["report--0f0f0f0f-0000-4000-8000-000000000001"],
    )


def cluster_finding() -> Finding:
    return Finding(
        key="cluster:abuse.ch:ThreatFox botnet_cc: ExampleBot",
        kind="indicators",
        title="ThreatFox botnet_cc: ExampleBot (2 indicators)",
        sources=["abuse.ch"],
        first_seen=NOW - timedelta(hours=1),
        confidence=100,
        iocs=[Ioc("ipv4", "203.0.113.45"), Ioc("ipv4", "203.0.113.46")],
    )


COLLECTORS = {
    "kev": lambda now, h: [kev_finding()],
    "opencti": lambda now, h: [report_finding(), cluster_finding()],
    "broken": lambda now, h: (_ for _ in ()).throw(ConnectionError("down")),
}


@dataclass
class FakeResult:
    parsed: dict[str, Any] | None
    raw: str = ""
    seconds: float = 0.1
    output_tokens: int = 10
    error: str | None = None


class FakeWriter:
    def __init__(self, answers: list[dict[str, Any] | None], model: str = "fake") -> None:
        self.answers, self.model, self.calls = list(answers), model, []

    def write(self, findings, *, feedback=None, previous=None, seed=7):  # noqa: ANN001
        self.calls.append({"findings": findings, "feedback": feedback, "previous": previous})
        ans = self.answers.pop(0) if self.answers else None
        return FakeResult(ans, raw=json.dumps(ans) if ans else "")


def good(ids: list[str]) -> dict[str, Any]:
    return {
        "bluf": "A phishing campaign targets Malaysian universities and a VPN flaw is exploited.",
        "top_threats": [
            {
                "finding_ids": [i],
                "headline": f"Threat {i}",
                "why_it_matters": "Matters to us.",
                "actions": ["Patch and monitor"],
            }
            for i in ids
        ],
        "trends": "",
        "education_asean_watch": "Universities in Malaysia are targeted [F1].",
        "confidence_note": "Public sources only.",
    }


def test_merges_scores_and_survives_a_broken_source() -> None:
    w = FakeWriter([good(["F1", "F2"])])
    res = run(COLLECTORS, now=NOW, writer=w)
    assert res.run_log["sources"]["broken"]["ok"] is False
    assert res.run_log["findings_in"] == 3
    assert res.run_log["after_dedupe"] == 2  # report + KEV merged on the shared CVE
    fid, top = res.top[0]
    assert fid == "F1" and top.kind == "report" and top.in_kev
    assert set(top.sources) == {"AlienVault OTX", "CISA KEV"}
    assert res.llm_ok and res.narrative["top_threats"][0]["finding_ids"] == ["F1"]


def test_planted_fake_ioc_is_never_published() -> None:
    bad = good(["F1", "F2"])
    bad["bluf"] += " C2 at 192.0.2.250 and CVE-2025-99999 via T1055."
    w = FakeWriter([bad, bad, bad])
    res = run(COLLECTORS, now=NOW, writer=w)
    assert not res.llm_ok  # facts-only fallback
    assert "192.0.2.250" not in json.dumps(res.narrative)
    assert len(w.calls) == 3
    assert "192.0.2.250" in " ".join(w.calls[1]["feedback"])  # errors fed back
    assert w.calls[1]["previous"]  # and the rejected answer


def test_retry_fixes_the_answer() -> None:
    bad = good(["F1"])
    bad["trends"] = "Also 192.0.2.250."
    w = FakeWriter([bad, good(["F1", "F2"])])
    res = run(COLLECTORS, now=NOW, writer=w)
    assert res.llm_ok and len(res.run_log["llm"]["attempts"]) == 2
    assert res.run_log["llm"]["first_try_pass"] is False


def test_fallback_model_is_used_when_primary_fails() -> None:
    primary = FakeWriter([None, None, None], model="primary")
    fallback = FakeWriter([good(["F1", "F2"])], model="fallback")
    res = run(COLLECTORS, now=NOW, writer=primary, fallback_writer=fallback)
    assert res.llm_ok
    assert [a["model"] for a in res.run_log["llm"]["attempts"]][-1] == "fallback"


def test_first_faithful_answer_is_kept_when_retries_get_worse() -> None:
    incomplete = good(["F2"])  # faithful, but F1 (top) not covered
    w = FakeWriter([incomplete, None, None])  # retries then fail to parse
    res = run(COLLECTORS, now=NOW, writer=w)
    assert res.llm_ok and res.narrative == incomplete
    assert res.run_log["llm"]["complete"] is False


def test_completeness_requires_top_and_lens_findings() -> None:
    llm = [{"id": "F1", "_lens": True}, {"id": "F2"}, {"id": "F3"}]
    narrative = good(["F2"])
    narrative["education_asean_watch"] = "Nothing notable today."
    errs = completeness_errors(narrative, llm)
    assert any("F1" in e and "top_threats" in e for e in errs)
    assert any("education_asean_watch" in e for e in errs)


def test_outputs_defanged_for_humans_real_for_machines(tmp_path: Path) -> None:
    res = run(COLLECTORS, now=NOW, writer=FakeWriter([good(["F1", "F2"])]))
    paths = write_outputs(res, tmp_path / "out", tmp_path / "runs")
    md, html = paths["md"].read_text("utf-8"), paths["html"].read_text("utf-8")
    for human in (md, html):
        assert "198.51.100[.]23" in human and "scholarship-portal[.]example[.]test" in human
        assert "198.51.100.23" not in human
    machine = paths["json"].read_text("utf-8")
    assert "198.51.100.23" in machine and "[.]" not in machine
    bundle = json.loads(paths["stix"].read_text("utf-8"))
    report = next(o for o in bundle["objects"] if o["type"] == "report")
    assert report["report_types"] == ["threat-report"]
    assert "report--0f0f0f0f-0000-4000-8000-000000000001" in report["object_refs"]
    assert res.run_log["stix_valid"] is True
    assert "Narrative written by a local AI model" in md


def test_markdown_neutralises_injected_links_and_html(tmp_path: Path) -> None:
    evil = report_finding()
    evil.title = "Click [here](javascript:alert(1)) <img src=x onerror=alert(1)> | # fake"
    cols = {"opencti": lambda now, h: [evil]}
    res = run(cols, now=NOW, writer=None)
    md = write_outputs(res, tmp_path / "o", tmp_path / "r")["md"].read_text("utf-8")
    assert "](javascript:" not in md and "<img" not in md
    html = (tmp_path / "o" / "brief.html").read_text("utf-8")
    assert "<img src=x" not in html


def test_json_label_covers_lower_ranked_findings(tmp_path: Path) -> None:
    amber = cluster_finding()
    amber.tlp = "TLP:AMBER"
    amber.confidence = 1
    cols = {"kev": lambda now, h: [kev_finding()], "x": lambda now, h: [amber]}
    res = run(cols, now=NOW, writer=None, top_n=1)
    assert res.tlp == "TLP:CLEAR"
    data = json.loads(write_outputs(res, tmp_path / "o", tmp_path / "r")["json"].read_text())
    assert data["tlp"] == "TLP:AMBER" and data["tlp_top"] == "TLP:CLEAR"


def test_kev_table_survives_merge_into_report(tmp_path: Path) -> None:
    kev = kev_finding()
    kev.kev_new = {"CVE-2026-20001": "VPN RCE"}
    cols = {"kev": lambda now, h: [kev], "opencti": lambda now, h: [report_finding()]}
    res = run(cols, now=NOW, writer=None)
    assert res.run_log["after_dedupe"] == 1
    md = write_outputs(res, tmp_path / "o", tmp_path / "r")["md"].read_text("utf-8")
    assert "| CVE-2026-20001 | VPN RCE |" in md


def test_facts_only_without_llm(tmp_path: Path) -> None:
    res = run(COLLECTORS, now=NOW, writer=None)
    assert not res.llm_ok
    md = write_outputs(res, tmp_path / "o", tmp_path / "r")["md"].read_text("utf-8")
    assert "Facts-only brief" in md


def test_misp_snapshot_round_trip(tmp_path: Path, monkeypatch) -> None:  # noqa: ANN001
    from hexbrief import pipeline
    from hexbrief.engine import finding_json

    monkeypatch.setattr(pipeline, "RUNS", tmp_path)
    f = report_finding()
    pipeline.snapshot_path(NOW).write_text(json.dumps([finding_json(f)]), encoding="utf-8")
    loaded = pipeline.load_misp_snapshot(NOW)
    assert loaded and loaded[0].iocs == f.iocs and loaded[0].cves == f.cves
    assert pipeline.load_misp_snapshot(NOW + timedelta(days=2)) is None


def test_demo_runs_offline_and_passes_the_gate(tmp_path: Path) -> None:
    from hexbrief.demo_mode import demo_run

    res = demo_run()  # recorded findings + recorded narrative, no services
    assert res.llm_ok, res.run_log["llm"]
    assert res.tlp == "TLP:CLEAR" and len(res.top) == 8
    paths = write_outputs(res, tmp_path / "o", tmp_path / "r")
    assert res.run_log["stix_valid"] is True
    assert "Narrative written by a local AI model" in paths["md"].read_text("utf-8")
