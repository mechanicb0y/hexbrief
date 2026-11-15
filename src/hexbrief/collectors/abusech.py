"""abuse.ch ThreatFox + URLhaus via their authenticated APIs (Phase 3).

In November 2026 abuse.ch retired the anonymous CSV exports that the OpenCTI
ThreatFox/URLhaus connectors use (HTTP 410 Gone). The APIs need a free Auth-Key,
which is sent **as a header** (never in a URL, so it can't leak via logs or
history). Indicators are handled as text only; nothing here contacts them.

``to_stix_bundle`` turns the results into STIX 2.1 indicators (+ malware where
ThreatFox names the family), all TLP:CLEAR, created by an "abuse.ch" identity, so
they can be pushed into OpenCTI as a fifth source and used by the brief engine.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from hexbrief.stixkit.markings import TLP_CLEAR, tlp2_id

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_RECENT = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/"
ABUSECH_IDENTITY_ID = "identity--3b7a6f56-6b1e-4d3a-9c7c-5c2b2a9e0b11"


class AbuseChError(Exception):
    """abuse.ch answered with an error or an unexpected shape."""


@dataclass(frozen=True)
class AbuseChPull:
    threatfox: list[dict[str, Any]] = field(default_factory=list)
    urlhaus: list[dict[str, Any]] = field(default_factory=list)


def _client(auth_key: str, transport: httpx.BaseTransport | None = None) -> httpx.Client:
    if not auth_key or auth_key == "__replace_me__":
        raise AbuseChError("ABUSECH_AUTH_KEY is not set")
    return httpx.Client(
        headers={"Auth-Key": auth_key, "User-Agent": "hexbrief/0.1"},
        timeout=60,
        trust_env=False,
        transport=transport,
    )


def pull(
    auth_key: str,
    *,
    days: int = 1,
    urlhaus_limit: int = 500,
    transport: httpx.BaseTransport | None = None,
) -> AbuseChPull:
    """ThreatFox IOCs from the last ``days`` (1-7) and the most recent URLhaus URLs."""
    if not 1 <= days <= 7:
        raise ValueError("ThreatFox allows days=1..7")
    with _client(auth_key, transport) as http:
        tf = http.post(THREATFOX_API, json={"query": "get_iocs", "days": days})
        if tf.status_code in (401, 403):
            raise AbuseChError(f"ThreatFox refused the Auth-Key (HTTP {tf.status_code})")
        tf.raise_for_status()
        tf_body = tf.json()
        if tf_body.get("query_status") not in ("ok", "no_result"):
            raise AbuseChError(f"ThreatFox: {tf_body.get('query_status')}")
        uh = http.get(URLHAUS_RECENT.format(limit=urlhaus_limit))
        if uh.status_code in (401, 403):
            raise AbuseChError(f"URLhaus refused the Auth-Key (HTTP {uh.status_code})")
        uh.raise_for_status()
        uh_body = uh.json()
        if uh_body.get("query_status") not in ("ok", "no_results"):
            raise AbuseChError(f"URLhaus: {uh_body.get('query_status')}")
    return AbuseChPull(
        threatfox=list(tf_body.get("data") or []),
        urlhaus=list(uh_body.get("urls") or []),
    )


# --------------------------------------------------------------------- STIX
_HASH_KEYS = {"md5_hash": "MD5", "sha1_hash": "SHA-1", "sha256_hash": "SHA-256"}


def _q(value: str) -> str:
    """Escape a value for a STIX pattern string literal."""
    return value.replace("\\", "\\\\").replace("'", "\\'")


def stix_pattern(ioc_type: str, value: str) -> str | None:
    """STIX 2.1 pattern for a ThreatFox/URLhaus IOC, or None if unsupported."""
    value = value.strip()
    if ioc_type == "ip:port":
        ip = value.rsplit(":", 1)[0]
        kind = "ipv6-addr" if ":" in ip else "ipv4-addr"
        return f"[{kind}:value = '{_q(ip)}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{_q(value)}']"
    if ioc_type == "url":
        return f"[url:value = '{_q(value)}']"
    if ioc_type in _HASH_KEYS and re.fullmatch(r"[0-9a-fA-F]+", value):
        return f"[file:hashes.'{_HASH_KEYS[ioc_type]}' = '{value.lower()}']"
    return None


def _ts(value: str | None) -> str:
    """abuse.ch '2026-11-15 12:48:11 UTC' -> STIX timestamp."""
    if value:
        try:
            dt = datetime.strptime(value.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S")
            return dt.replace(tzinfo=UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        except ValueError:
            pass
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.000Z")


_ID_NAMESPACE = uuid.UUID("a1d1b3f0-55e4-4c9b-8a5f-4c6f9e2b7a10")  # fixed HexBrief namespace


def _stix_id(kind: str, *parts: str) -> str:
    """Deterministic UUIDv5 id, so re-imports update objects instead of duplicating them."""
    return f"{kind}--{uuid.uuid5(_ID_NAMESPACE, '|'.join(parts))}"


def to_stix_bundle(data: AbuseChPull) -> dict[str, Any]:
    """STIX 2.1 bundle (dict): identity, TLP:CLEAR, indicators, malware, relationships."""
    clear = tlp2_id("clear")
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": ABUSECH_IDENTITY_ID,
        "created": "2026-11-15T00:00:00.000Z",
        "modified": "2026-11-15T00:00:00.000Z",
        "name": "abuse.ch",
        "identity_class": "organization",
        "object_marking_refs": [clear],
    }
    objects: list[dict[str, Any]] = [TLP_CLEAR, identity]
    malware_ids: dict[str, str] = {}

    def add_indicator(
        pattern: str,
        name: str,
        when: str,
        labels: list[str],
        conf: int,
        ref: str | None,
        family: str | None,
    ) -> None:
        ind = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": _stix_id("indicator", pattern),
            "created": when,
            "modified": when,
            "name": name,
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": when,
            "indicator_types": ["malicious-activity"],
            "labels": sorted({lb for lb in labels if lb})[:10],
            "confidence": max(0, min(100, conf)),
            "created_by_ref": ABUSECH_IDENTITY_ID,
            "object_marking_refs": [clear],
        }
        if ref:
            ind["external_references"] = [{"source_name": "abuse.ch", "url": ref}]
        objects.append(ind)
        if family:
            mid = malware_ids.get(family)
            if mid is None:
                mid = _stix_id("malware", family.lower())
                malware_ids[family] = mid
                objects.append(
                    {
                        "type": "malware",
                        "spec_version": "2.1",
                        "id": mid,
                        "created": when,
                        "modified": when,
                        "name": family,
                        "is_family": True,
                        "created_by_ref": ABUSECH_IDENTITY_ID,
                        "object_marking_refs": [clear],
                    }
                )
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": _stix_id("relationship", ind["id"], "indicates", mid),
                    "created": when,
                    "modified": when,
                    "relationship_type": "indicates",
                    "source_ref": ind["id"],
                    "target_ref": mid,
                    "created_by_ref": ABUSECH_IDENTITY_ID,
                    "object_marking_refs": [clear],
                }
            )

    for row in data.threatfox:
        pattern = stix_pattern(str(row.get("ioc_type", "")), str(row.get("ioc", "")))
        if not pattern:
            continue
        family = row.get("malware_printable")
        family = None if not family or family == "Unknown malware" else str(family)
        add_indicator(
            pattern,
            f"ThreatFox {row.get('threat_type', 'ioc')}: {family or 'unknown family'}",
            _ts(row.get("first_seen")),
            [str(t) for t in (row.get("tags") or [])] + ["threatfox"],
            int(row.get("confidence_level") or 50),
            row.get("reference") or None,
            family,
        )
    for row in data.urlhaus:
        url = str(row.get("url") or "")
        if not url:
            continue
        add_indicator(
            stix_pattern("url", url) or "",
            f"URLhaus {row.get('threat', 'url')}",
            _ts(row.get("date_added")),
            [str(t) for t in (row.get("tags") or [])] + ["urlhaus"],
            80,
            row.get("urlhaus_reference") or None,
            None,
        )
    # De-duplicate by id (the same IOC can appear in both feeds or twice in one).
    unique: dict[str, dict[str, Any]] = {}
    for obj in objects:
        unique.setdefault(obj["id"], obj)
    return {
        "type": "bundle",
        "id": _stix_id("bundle", datetime.now(UTC).isoformat()),
        "objects": list(unique.values()),
    }
