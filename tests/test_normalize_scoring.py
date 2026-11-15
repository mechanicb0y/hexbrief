from __future__ import annotations

from datetime import UTC, date, datetime

from hexbrief.collectors.kev import findings_added_since
from hexbrief.collectors.opencti import OpenCTIWindow
from hexbrief.model import Finding, Ioc, iocs_from_pattern, max_tlp
from hexbrief.normalize import canonical_source, dedupe, from_opencti
from hexbrief.scoring import rank, score

NOW = datetime(2026, 11, 15, 23, 0, tzinfo=UTC)


def test_patterns_to_iocs() -> None:
    p = (
        "[ipv4-addr:value = '198.51.100.7'] OR [domain-name:value = 'a.example.test'] OR "
        "[url:value = 'http://x.test/it\\'s'] OR [file:hashes.'SHA-256' = '" + "AB" * 32 + "']"
    )
    assert iocs_from_pattern(p) == [
        Ioc("ipv4", "198.51.100.7"),
        Ioc("domain", "a.example.test"),
        Ioc("url", "http://x.test/it's"),
        Ioc("sha256", "ab" * 32),
    ]


def test_max_tlp_fails_safe() -> None:
    assert max_tlp("TLP:CLEAR", "TLP:WHITE") == "TLP:CLEAR"
    assert max_tlp("TLP:CLEAR", "TLP:GREEN") == "TLP:GREEN"
    assert max_tlp("TLP:CLEAR", "weird") == "TLP:AMBER"


def test_source_aliases_count_once() -> None:
    assert canonical_source("Cybersecurity and Infrastructure Security Agency") == "CISA KEV"
    assert canonical_source("AlienVault") == "AlienVault OTX"


def _report(objects: list) -> dict:
    return {
        "id": "x",
        "standard_id": "report--00000000-0000-4000-8000-000000000001",
        "name": "Campaign",
        "description": "d",
        "published": "2026-11-15T01:00:00Z",
        "confidence": 70,
        "createdBy": {"id": "i", "name": "AlienVault"},
        "objectMarking": [{"definition_type": "TLP", "definition": "TLP:CLEAR"}],
        "externalReferences": [{"url": "https://otx.example.test/p/1"}, {"url": "javascript:x"}],
        "objects": objects,  # pycti flattens edges into a list
    }


def test_from_opencti_reads_report_objects_and_clusters_indicators() -> None:
    w = OpenCTIWindow(
        hours=24,
        since="",
        entities={
            "report": [
                _report(
                    [
                        {
                            "entity_type": "Attack-Pattern",
                            "x_mitre_id": "T1566.001",
                            "name": "Spearphishing",
                        },
                        {"entity_type": "Vulnerability", "name": "cve-2026-20001"},
                        {"entity_type": "Sector", "name": "Education"},
                        {"entity_type": "Country", "name": "Malaysia"},
                        {
                            "id": "ind-1",
                            "entity_type": "Indicator",
                            "pattern": "[ipv4-addr:value = '198.51.100.7']",
                        },
                    ]
                )
            ],
            "indicator": [
                {"id": "ind-1", "name": "dup", "pattern": "[ipv4-addr:value = '198.51.100.7']"},
                {
                    "id": "ind-2",
                    "name": "ThreatFox botnet_cc: ExampleBot",
                    "confidence": 100,
                    "pattern": "[ipv4-addr:value = '203.0.113.1']",
                    "createdBy": {"name": "abuse.ch"},
                },
            ],
            "vulnerability": [{"name": "CVE-2002-0367", "createdBy": {"name": "CISA"}}],
        },
    )
    fs = from_opencti(w)
    kinds = sorted(f.kind for f in fs)
    assert kinds == ["indicators", "report"]  # vulnerabilities are off by default
    rep = next(f for f in fs if f.kind == "report")
    assert rep.attack_ids == {"T1566.001"} and rep.cves == {"CVE-2026-20001"}
    assert rep.sectors == {"education"} and rep.countries == {"Malaysia"}
    assert rep.sources == ["AlienVault OTX"] and rep.source_urls == ["https://otx.example.test/p/1"]
    cluster = next(f for f in fs if f.kind == "indicators")
    assert cluster.iocs == [Ioc("ipv4", "203.0.113.1")]  # ind-1 belongs to the report
    assert cluster.malware == {"ExampleBot"}


def test_kev_window() -> None:
    cat = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-1",
                "dateAdded": "2026-11-15",
                "vulnerabilityName": "A",
                "knownRansomwareCampaignUse": "Known",
            },
            {"cveID": "CVE-2020-1", "dateAdded": "2020-01-01"},
        ]
    }
    fs = findings_added_since(cat, date(2026, 11, 14))
    assert [f.key for f in fs] == ["CVE-2026-1"] and fs[0].ransomware and fs[0].in_kev


def test_dedupe_does_not_let_big_clusters_swallow_each_other() -> None:
    a = Finding("c1", "indicators", "A", iocs=[Ioc("ipv4", "203.0.113.1")])
    b = Finding("c2", "indicators", "B", iocs=[Ioc("ipv4", "203.0.113.1")])
    assert len(dedupe([a, b])) == 2
    r = Finding("r", "report", "R", iocs=[Ioc("ipv4", "203.0.113.1")])
    assert len(dedupe([a, r])) == 1


def test_scoring_reasons_and_broad_lists() -> None:
    narrow = Finding(
        "n",
        "report",
        "Attack on universities",
        sectors={"education"},
        countries={"Malaysia"},
        first_seen=NOW,
        confidence=80,
        in_kev=True,
    )
    broad = Finding(
        "b",
        "report",
        "Campaign",
        confidence=80,
        first_seen=NOW,
        sectors={"education", "a", "b", "c", "d", "e"},
        countries={f"C{i}" for i in range(9)} | {"Malaysia"},
    )
    score(narrow, NOW)
    score(broad, NOW)
    assert "+30 in CISA KEV" in narrow.reasons and "+20 Malaysia" in narrow.reasons
    assert any("education among 6 sectors" in r for r in broad.reasons)
    assert narrow.score > broad.score
    assert [f.key for f in rank([broad, narrow], NOW)] == ["n", "b"]
