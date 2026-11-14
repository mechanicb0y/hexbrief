from __future__ import annotations

import json

import stix2

from hexbrief.stixkit.bundle import HEXBRIEF_IDENTITY_ID, build_demo_bundle, count_by_type, validate
from hexbrief.stixkit.markings import TLP_CLEAR, tlp2_id, tlp_level_of


def _objects() -> list[dict]:
    return json.loads(build_demo_bundle().serialize())["objects"]


def test_demo_bundle_passes_stix2_validator() -> None:
    report = validate(build_demo_bundle())
    assert report.is_valid, report.errors
    assert report.warnings == []


def test_every_object_is_tlp_clear_and_created_by_hexbrief() -> None:
    clear = tlp2_id("clear")
    for o in _objects():
        if o["type"] == "marking-definition":
            continue
        assert o["object_marking_refs"] == [clear], o["id"]
        if o["type"] != "identity":
            assert o["created_by_ref"] == HEXBRIEF_IDENTITY_ID


def test_bundle_shape() -> None:
    counts = count_by_type(_objects())
    assert counts == {
        "marking-definition": 1,
        "identity": 1,
        "malware": 1,
        "indicator": 1,
        "relationship": 1,
    }
    rel = next(o for o in _objects() if o["type"] == "relationship")
    assert rel["relationship_type"] == "indicates"
    assert rel["source_ref"].startswith("indicator--")
    assert rel["target_ref"].startswith("malware--")


def test_demo_uses_documentation_ip_only() -> None:
    ind = next(o for o in _objects() if o["type"] == "indicator")
    assert "198.51.100." in ind["pattern"]  # RFC 5737 TEST-NET-2


def test_validator_catches_a_broken_pattern() -> None:
    data = json.loads(build_demo_bundle().serialize())
    ind = next(o for o in data["objects"] if o["type"] == "indicator")
    ind["pattern"] = "[ipv4-addr:value = '1"
    assert not validate(data).is_valid


def test_tlp_clear_matches_official_oasis_definition() -> None:
    assert TLP_CLEAR["id"] == "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
    assert TLP_CLEAR["name"] == "TLP:CLEAR"


def test_tlp_white_maps_to_clear() -> None:
    assert tlp2_id("white") == tlp2_id("clear")
    assert tlp_level_of(stix2.TLP_WHITE.id) == "clear"
    assert tlp_level_of(stix2.TLP_GREEN.id) == "green"
    assert tlp_level_of(tlp2_id("amber+strict")) == "amber+strict"
    assert tlp_level_of("marking-definition--00000000-0000-4000-8000-000000000000") is None
