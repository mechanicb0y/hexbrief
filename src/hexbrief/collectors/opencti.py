"""Read recent intel from OpenCTI with pycti (Phase 3). Read-only.

OpenCTI vocabulary, as used here:
- It stores a STIX 2.1 **knowledge graph**: entities (reports, malware, intrusion
  sets, vulnerabilities), observables (raw values) and indicators (detection rules),
  linked by relationships.
- **Connectors** bring data in, and **workers** write it from the RabbitMQ queues.
- Every object carries **confidence** (0-100), **markings** (TLP) and, for
  indicators, an ``x_opencti_score``.

pycti is pinned to the platform version (ADR-004). The collector only calls
``<entity>.list``; nothing here writes to OpenCTI.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

# Entity collections we read, keyed by the pycti attribute name.
ENTITY_TYPES: tuple[str, ...] = (
    "report",
    "indicator",
    "vulnerability",
    "malware",
    "intrusion_set",
)


class _Lister(Protocol):
    def list(self, **kwargs: Any) -> Any: ...


class OpenCTIReader(Protocol):
    """The slice of ``pycti.OpenCTIApiClient`` we use. Tests pass a fake."""

    report: _Lister
    indicator: _Lister
    vulnerability: _Lister
    malware: _Lister
    intrusion_set: _Lister


@dataclass(frozen=True)
class OpenCTIWindow:
    """Entities created or updated in the window, grouped by type."""

    hours: int
    since: str
    entities: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        return {k: len(v) for k, v in self.entities.items()}

    @property
    def sources(self) -> Counter[str]:
        """Who created what (``createdBy`` name), a rough per-feed count."""
        names: Counter[str] = Counter()
        for rows in self.entities.values():
            for row in rows:
                author = (row.get("createdBy") or {}).get("name") or "unknown"
                names[str(author)] += 1
        return names


def connect(url: str, token: str, verify: bool | str = True, timeout: int = 120) -> OpenCTIReader:
    """Create a pycti client. It runs a health check against the platform at once."""
    from pycti import OpenCTIApiClient  # lazy: unit tests don't need a server

    return OpenCTIApiClient(  # type: ignore[no-any-return]
        url, token, log_level="error", ssl_verify=verify, requests_timeout=timeout
    )


def window_filter(since_iso: str) -> dict[str, Any]:
    """OpenCTI 6+/7 filter group: ``updated_at >= since``."""
    return {
        "mode": "and",
        "filters": [{"key": ["updated_at"], "values": [since_iso], "operator": "gte"}],
        "filterGroups": [],
    }


def collect_window(
    api: OpenCTIReader,
    hours: int = 24,
    *,
    now: datetime | None = None,
    types: tuple[str, ...] = ENTITY_TYPES,
) -> OpenCTIWindow:
    """Everything of ``types`` created or updated in the last ``hours`` hours.

    ``updated_at`` (not ``created``) is used so that an older report that gained
    new indicators today still counts as news. Results come back fully paged
    (``getAll=True``).
    """
    if hours <= 0:
        raise ValueError("hours must be positive")
    now = now or datetime.now(UTC)
    since = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    entities: dict[str, list[dict[str, Any]]] = {}
    for kind in types:
        lister = getattr(api, kind)
        rows = lister.list(
            filters=window_filter(since),
            getAll=True,
            orderBy="updated_at",
            orderMode="desc",
        )
        if rows is None:
            raise RuntimeError(f"OpenCTI returned nothing for {kind!r} (auth or API error?)")
        entities[kind] = [dict(r) for r in rows]
    return OpenCTIWindow(hours=hours, since=since, entities=entities)


REPORT_ATTRS = """
    id
    standard_id
    name
    description
    published
    created
    updated_at
    confidence
    report_types
    createdBy { ... on Identity { id name } }
    objectMarking { id definition_type definition }
    objectLabel { id value }
    externalReferences { edges { node { id source_name url } } }
    objects(all: true) {
        edges {
            node {
                ... on BasicObject { id entity_type }
                ... on StixObject { standard_id }
                ... on AttackPattern { name x_mitre_id }
                ... on Vulnerability { name }
                ... on Malware { name }
                ... on IntrusionSet { name }
                ... on ThreatActor { name }
                ... on Sector { name }
                ... on Country { name }
                ... on Region { name }
                ... on Indicator {
                    name pattern pattern_type
                    objectMarking { id definition_type definition }
                }
            }
        }
    }
"""

INDICATOR_ATTRS = """
    id
    standard_id
    name
    pattern
    pattern_type
    created
    updated_at
    confidence
    x_opencti_score
    createdBy { ... on Identity { id name } }
    objectMarking { id definition_type definition }
    objectLabel { id value }
    externalReferences { edges { node { id source_name url } } }
"""

VULN_ATTRS = """
    id
    standard_id
    name
    description
    created
    updated_at
    confidence
    x_opencti_cisa_kev
    createdBy { ... on Identity { id name } }
    objectMarking { id definition_type definition }
    objectLabel { id value }
"""


def collect_for_brief(
    api: OpenCTIReader, hours: int = 24, *, now: datetime | None = None
) -> OpenCTIWindow:
    """Reports (with their objects), indicators and vulnerabilities for the brief.

    Uses custom attribute sets so one query per type returns everything the
    normalizer needs (ATT&CK ids, CVE names, patterns, markings, authors).
    """
    if hours <= 0:
        raise ValueError("hours must be positive")
    now = now or datetime.now(UTC)
    since = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    entities: dict[str, list[dict[str, Any]]] = {}
    for kind, attrs in (
        ("report", REPORT_ATTRS),
        ("indicator", INDICATOR_ATTRS),
        ("vulnerability", VULN_ATTRS),
    ):
        rows = getattr(api, kind).list(
            filters=window_filter(since),
            getAll=True,
            customAttributes=attrs,
            orderBy="updated_at",
            orderMode="desc",
        )
        if rows is None:
            raise RuntimeError(f"OpenCTI returned nothing for {kind!r} (auth or API error?)")
        entities[kind] = [dict(r) for r in rows]
    return OpenCTIWindow(hours=hours, since=since, entities=entities)


def tlp_of(entity: dict[str, Any]) -> str | None:
    """The entity's TLP marking (``TLP:CLEAR`` etc.), or None if it has none."""
    for marking in entity.get("objectMarking") or []:
        name = str(marking.get("definition") or "")
        if name.upper().startswith("TLP:"):
            return name.upper().replace("TLP:WHITE", "TLP:CLEAR")
    return None
