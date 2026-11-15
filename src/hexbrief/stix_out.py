"""The brief as a STIX 2.1 Report (machine output: real values, never defanged)."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from hexbrief.model import Finding
from hexbrief.stixkit.bundle import HEXBRIEF_IDENTITY_ID
from hexbrief.stixkit.markings import tlp2_id, tlp2_marking

_STIX_ID = re.compile(
    r"^[a-z][a-z0-9-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_NS = uuid.UUID("5d0c7b2e-1f4a-4f0e-9a3b-7e2c1d9f8a64")


def report_bundle(
    day: str,
    title: str,
    description: str,
    findings: list[Finding],
    tlp: str,
    published: datetime,
    labels: tuple[str, ...] = ("hexbrief",),
) -> dict[str, Any]:
    level = tlp.split(":", 1)[-1].lower()
    marking = tlp2_marking(level)
    ts = published.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity = {
        "type": "identity",
        "spec_version": "2.1",
        "id": HEXBRIEF_IDENTITY_ID,
        "created": "2026-11-14T00:00:00.000Z",
        "modified": "2026-11-14T00:00:00.000Z",
        "name": "HexBrief",
        "identity_class": "system",
        "object_marking_refs": [tlp2_id("clear")],
    }
    refs: list[str] = []
    for f in findings:
        refs += [s for s in f.stix_ids if _STIX_ID.match(s) and s not in refs]
    report = {
        "type": "report",
        "spec_version": "2.1",
        # Deterministic per day: re-running the same day updates the same Report.
        "id": f"report--{uuid.uuid5(_NS, 'hexbrief-daily-' + day)}",
        "created": ts,
        "modified": ts,
        "name": title,
        "description": description,
        "report_types": ["threat-report"],
        "published": ts,
        "object_refs": refs or [HEXBRIEF_IDENTITY_ID],
        "labels": list(labels),
        "created_by_ref": HEXBRIEF_IDENTITY_ID,
        "object_marking_refs": [marking["id"]],
    }
    objects = [marking, identity, report]
    if level != "clear":
        objects.insert(0, tlp2_marking("clear"))  # the identity is always TLP:CLEAR
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
