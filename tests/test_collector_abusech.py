"""abuse.ch collector: recorded-shape responses via respx; no network."""

from __future__ import annotations

import json

import pytest
import respx

from hexbrief.collectors.abusech import (
    THREATFOX_API,
    URLHAUS_RECENT,
    AbuseChError,
    AbuseChPull,
    pull,
    stix_pattern,
    to_stix_bundle,
)
from hexbrief.stixkit.bundle import validate

KEY = "test-auth-key-not-real"
TF_ROW = {
    "ioc": "198.51.100.23:8080",
    "ioc_type": "ip:port",
    "threat_type": "botnet_cc",
    "malware_printable": "ExampleBot",
    "confidence_level": 100,
    "first_seen": "2026-11-15 12:48:11 UTC",
    "tags": ["botnet", "ExampleBot"],
    "reference": "https://example.org/report",
}
UH_ROW = {
    "url": "http://malware.example.test/payload.bin",
    "threat": "malware_download",
    "tags": None,
    "date_added": "2026-11-15 12:47:05 UTC",
    "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
}
URLHAUS = URLHAUS_RECENT.format(limit=500)


@respx.mock
def test_auth_key_goes_in_header_not_url() -> None:
    tf = respx.post(THREATFOX_API).respond(200, json={"query_status": "ok", "data": [TF_ROW]})
    uh = respx.get(URLHAUS).respond(200, json={"query_status": "ok", "urls": [UH_ROW]})
    got = pull(KEY)
    assert len(got.threatfox) == 1 and len(got.urlhaus) == 1
    for route in (tf, uh):
        req = route.calls.last.request
        assert req.headers["Auth-Key"] == KEY
        assert KEY not in str(req.url)
    assert json.loads(tf.calls.last.request.content) == {"query": "get_iocs", "days": 1}


@respx.mock
def test_refused_key_is_a_clear_error() -> None:
    respx.post(THREATFOX_API).respond(401, json={"query_status": "unknown_auth_key"})
    with pytest.raises(AbuseChError, match="Auth-Key"):
        pull(KEY)


@respx.mock
def test_empty_day_is_fine() -> None:
    respx.post(THREATFOX_API).respond(200, json={"query_status": "no_result", "data": None})
    respx.get(URLHAUS).respond(200, json={"query_status": "no_results"})
    assert pull(KEY) == AbuseChPull()


def test_missing_key_and_bad_days() -> None:
    with pytest.raises(AbuseChError):
        pull("")
    with pytest.raises(ValueError):
        pull(KEY, days=30)


@pytest.mark.parametrize(
    ("ioc_type", "value", "expected"),
    [
        ("ip:port", "198.51.100.23:8080", "[ipv4-addr:value = '198.51.100.23']"),
        ("ip:port", "2001:db8::1:443", "[ipv6-addr:value = '2001:db8::1']"),
        ("ip:port", "[2001:db8::1]:443", "[ipv6-addr:value = '2001:db8::1']"),
        ("ip:port", "not-an-ip:80", None),
        ("sha256_hash", "ab" * 10, None),  # hex but wrong length
        ("md5_hash", "a" * 32, "[file:hashes.'MD5' = '" + "a" * 32 + "']"),
        ("domain", "bad.example.test", "[domain-name:value = 'bad.example.test']"),
        ("url", "http://x.test/a'b", "[url:value = 'http://x.test/a\\'b']"),
        ("sha256_hash", "AB" * 32, "[file:hashes.'SHA-256' = '" + "ab" * 32 + "']"),
        ("md5_hash", "not-hex", None),
        ("unknown", "x", None),
    ],
)
def test_stix_patterns(ioc_type: str, value: str, expected: str | None) -> None:
    assert stix_pattern(ioc_type, value) == expected


def test_zero_confidence_is_kept() -> None:
    row = dict(TF_ROW, confidence_level=0)
    bundle = to_stix_bundle(AbuseChPull(threatfox=[row]))
    ind = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert ind["confidence"] == 0


def test_bundle_is_valid_tlp_clear_and_deterministic() -> None:
    data = AbuseChPull(threatfox=[TF_ROW, TF_ROW], urlhaus=[UH_ROW])
    bundle = to_stix_bundle(data)
    report = validate(bundle)
    assert report.is_valid, report.errors
    types = [o["type"] for o in bundle["objects"]]
    assert types.count("indicator") == 2  # duplicate ThreatFox row collapsed
    assert types.count("malware") == 1 and types.count("relationship") == 1
    for o in bundle["objects"]:
        if o["type"] not in ("marking-definition",):
            assert o["object_marking_refs"] == [
                "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487"
            ]
    again = to_stix_bundle(data)
    ids = sorted(o["id"] for o in bundle["objects"])
    assert ids == sorted(o["id"] for o in again["objects"])
