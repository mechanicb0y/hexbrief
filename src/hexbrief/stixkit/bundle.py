"""Build, validate and summarize STIX 2.1 bundles."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

import stix2
from stix2validator import ValidationOptions, validate_string

from hexbrief.stixkit.markings import TLP_CLEAR, tlp2_id

# A fixed id so every bundle HexBrief makes is "created by" the same identity.
HEXBRIEF_IDENTITY_ID = "identity--5f7b1a2c-8e3d-4c6a-9b0e-1d2f3a4b5c6d"


def hexbrief_identity() -> stix2.Identity:
    return stix2.Identity(
        id=HEXBRIEF_IDENTITY_ID,
        created="2026-11-14T00:00:00.000Z",
        modified="2026-11-14T00:00:00.000Z",
        name="HexBrief",
        identity_class="system",
        description="Automated daily threat-intel brief (open-source portfolio project).",
        object_marking_refs=[tlp2_id("clear")],
        allow_custom=True,
    )


def build_demo_bundle(now: datetime | None = None) -> stix2.Bundle:
    """Indicator --indicates--> malware, all TLP:CLEAR, created by HexBrief.

    Uses a documentation-only IP (RFC 5737 TEST-NET-2) and a made-up malware
    family, so the bundle is safe to publish and contains no real indicator.
    """
    now = now or datetime.now(UTC)
    clear = tlp2_id("clear")
    identity = hexbrief_identity()
    malware = stix2.Malware(
        name="ExampleRAT (fictional)",
        is_family=True,
        malware_types=["remote-access-trojan"],
        description="Fictional malware family used only for HexBrief tests and demos.",
        created_by_ref=identity.id,
        object_marking_refs=[clear],
        created=now,
        modified=now,
        allow_custom=True,
    )
    indicator = stix2.Indicator(
        name="ExampleRAT C2 address (documentation IP)",
        description="Test indicator: an RFC 5737 documentation address, not a real C2.",
        pattern="[ipv4-addr:value = '198.51.100.7']",
        pattern_type="stix",
        valid_from=now,
        indicator_types=["malicious-activity"],
        confidence=50,
        created_by_ref=identity.id,
        object_marking_refs=[clear],
        created=now,
        modified=now,
        allow_custom=True,
    )
    rel = stix2.Relationship(
        source_ref=indicator.id,
        relationship_type="indicates",
        target_ref=malware.id,
        created_by_ref=identity.id,
        object_marking_refs=[clear],
        created=now,
        modified=now,
        allow_custom=True,
    )
    # TLP 2.0 markings are not built into stix2, so the marking object is passed as a dict.
    return stix2.Bundle(TLP_CLEAR, identity, malware, indicator, rel, allow_custom=True)


@dataclass
class ValidationReport:
    is_valid: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def validate(bundle: stix2.Bundle | dict[str, Any] | str) -> ValidationReport:
    """Validate with the OASIS stix2-validator (strict STIX 2.1 checks)."""
    text = bundle if isinstance(bundle, str) else _to_json(bundle)
    results = validate_string(text, ValidationOptions(version="2.1"))

    # stix2-validator 3.3 returns one ObjectValidationResults for a bundle; its
    # errors/warnings may be strings or objects with a .message attribute.
    def _msgs(items: Iterable[Any]) -> list[str]:
        return [str(getattr(i, "message", i)) for i in items or []]

    return ValidationReport(
        is_valid=bool(results.is_valid),
        errors=_msgs(results.errors),
        warnings=_msgs(results.warnings),
    )


def count_by_type(objects: Iterable[dict[str, Any]]) -> Counter[str]:
    """Count STIX objects by their ``type`` property."""
    return Counter(str(o.get("type", "?")) for o in objects)


@dataclass(frozen=True)
class AttackSummary:
    """Counts of live ATT&CK objects (not revoked, not deprecated)."""

    techniques: int = 0
    subtechniques: int = 0
    tactics: int = 0
    groups: int = 0
    software: int = 0
    skipped: int = 0  # objects in the five categories above that are revoked or deprecated

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


_SOFTWARE_TYPES = frozenset({"malware", "tool"})


def _attack_category(obj: Mapping[str, Any]) -> str | None:
    """Map an ATT&CK STIX object to a summary field, or None if it is not counted."""
    kind = obj.get("type")
    if kind == "attack-pattern":
        return "subtechniques" if obj.get("x_mitre_is_subtechnique") is True else "techniques"
    if kind == "x-mitre-tactic":
        return "tactics"
    if kind == "intrusion-set":
        return "groups"
    if kind in _SOFTWARE_TYPES:
        return "software"
    return None


def summarize_attack(objects: Iterable[Mapping[str, Any]]) -> AttackSummary:
    """Count ATT&CK techniques, sub-techniques, tactics, groups and software.

    Revoked and deprecated objects are not counted; they are tallied in ``skipped``.
    Flags must be the JSON boolean ``true``, so ``"revoked": false`` is not skipped.
    If the same id appears more than once (several versions of one object), only the
    newest ``modified`` version counts, so a repeated or overlapping fetch never
    double-counts and a later revocation wins.
    """
    latest: dict[str, Mapping[str, Any]] = {}
    for obj in objects:
        obj_id = obj.get("id")
        if not obj_id:
            continue
        seen = latest.get(obj_id)
        if seen is None or str(obj.get("modified", "")) > str(seen.get("modified", "")):
            latest[obj_id] = obj

    counts: Counter[str] = Counter()
    for obj in latest.values():
        category = _attack_category(obj)
        if category is None:
            continue
        if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
            counts["skipped"] += 1
        else:
            counts[category] += 1
    return AttackSummary(**counts)


def _to_json(bundle: stix2.Bundle | dict[str, Any]) -> str:
    if isinstance(bundle, dict):
        return json.dumps(bundle)
    return str(bundle.serialize())
