"""Faithfulness gate: planted fakes must fail, a clean answer must pass."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from hexbrief.validate import extract, refang, validate_narrative

FINDINGS = json.loads(
    (Path(__file__).parent / "fixtures" / "brief_findings.json").read_text(encoding="utf-8")
)

CLEAN = {
    "bluf": "A VPN appliance flaw (CVE-2026-20001) is being exploited and a phishing "
    "campaign is targeting ASEAN universities [F2].",
    "top_threats": [
        {
            "finding_ids": ["F1"],
            "headline": "Exploited VPN appliance vulnerability",
            "why_it_matters": "Universities expose VPNs to staff and students; T1190 gives "
            "attackers a direct way in.",
            "actions": ["Patch CVE-2026-20001 within 7 days", "Review VPN logs for anomalies"],
        },
        {
            "finding_ids": ["F2", "F7"],
            "headline": "Scholarship-themed phishing delivers ExampleRAT",
            "why_it_matters": "Staff are the target; the lure uses T1566.001 and PowerShell "
            "(T1059.001).",
            "actions": ["Block scholarship-portal.example.test", "Alert on LNK files in ZIPs"],
        },
    ],
    "trends": "Initial access via edge devices and phishing remains the main theme.",
    "education_asean_watch": "Universities in Malaysia and Indonesia are targeted [F2].",
    "confidence_note": "Based on public sources only; victim counts are unknown.",
}


def test_clean_answer_passes() -> None:
    result = validate_narrative(CLEAN, FINDINGS)
    assert result.ok, result.errors


def _plant(text: str) -> dict:
    bad = copy.deepcopy(CLEAN)
    bad["trends"] = text
    return bad


@pytest.mark.parametrize(
    ("planted", "kind"),
    [
        ("Also seen: C2 at 192.0.2.99.", "ips"),
        ("Related to CVE-2025-99999.", "cves"),
        ("They also used T1055 process injection.", "attack_ids"),
        ("Payload hosted at evil-cdn.example.org.", "domains"),
        ("See hxxps://evil-cdn[.]example[.]org/x for details.", "urls"),
        ("Dropper hash " + "ab" * 32 + ".", "hashes"),
        ("Defanged C2 192.0.2[.]77 was also reported.", "ips"),
    ],
)
def test_planted_fakes_fail(planted: str, kind: str) -> None:
    result = validate_narrative(_plant(planted), FINDINGS)
    assert not result.ok
    assert kind in result.invented, result.errors


def test_planted_ip_cve_and_attack_all_reported_together() -> None:
    result = validate_narrative(
        _plant("C2 192.0.2.99 exploits CVE-2025-99999 using T1055."), FINDINGS
    )
    assert {"ips", "cves", "attack_ids"} <= result.invented.keys()


def test_unknown_finding_id_fails() -> None:
    bad = copy.deepcopy(CLEAN)
    bad["top_threats"][0]["finding_ids"] = ["F42"]
    assert any("F42" in e for e in validate_narrative(bad, FINDINGS).errors)
    bad = _plant("As noted in [F99], things are bad.")
    assert any("F99" in e for e in validate_narrative(bad, FINDINGS).errors)


def test_schema_and_banned_phrases() -> None:
    bad = copy.deepcopy(CLEAN)
    del bad["bluf"]
    assert any("schema" in e for e in validate_narrative(bad, FINDINGS).errors)
    bad = _plant("An unprecedented wave of attacks.")
    assert any("banned" in e for e in validate_narrative(bad, FINDINGS).errors)
    assert not validate_narrative(None, FINDINGS).ok


def test_defanged_input_iocs_are_allowed_in_either_form() -> None:
    ok = _plant("Block scholarship-portal[.]example[.]test and 198.51.100[.]23.")
    assert validate_narrative(ok, FINDINGS).ok


def test_file_names_are_not_domains() -> None:
    assert extract("The LNK runs powershell.exe and drops update.bin").domains == set()


def test_refang() -> None:
    assert refang("hxxps://a[.]b[.]c") == "https://a.b.c"
