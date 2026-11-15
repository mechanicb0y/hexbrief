"""Turn raw collector output into Findings, then merge duplicates across sources."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from hexbrief.collectors.opencti import OpenCTIWindow, tlp_of
from hexbrief.model import Finding, Ioc, iocs_from_pattern

ASEAN = {
    "malaysia",
    "singapore",
    "indonesia",
    "thailand",
    "philippines",
    "vietnam",
    "viet nam",
    "brunei",
    "brunei darussalam",
    "cambodia",
    "laos",
    "lao people's democratic republic",
    "myanmar",
    "timor-leste",
}


def _dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


# Same organisation under different names must count as ONE source.
SOURCE_ALIASES = {
    "cybersecurity and infrastructure security agency": "CISA KEV",
    "cisa": "CISA KEV",
    "the mitre corporation": "MITRE ATT&CK",
    "alienvault": "AlienVault OTX",
}


def canonical_source(name: str) -> str:
    return SOURCE_ALIASES.get(name.strip().lower(), name.strip())


def _author(row: dict[str, Any]) -> str:
    return canonical_source(str((row.get("createdBy") or {}).get("name") or "OpenCTI"))


def _nodes(value: Any) -> list[dict[str, Any]]:
    """GraphQL ``{edges: [{node}]}`` or pycti's already-flattened list -> list of nodes."""
    if isinstance(value, dict):
        return [e.get("node") or {} for e in value.get("edges") or []]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _refs(row: dict[str, Any]) -> list[str]:
    urls = [str(n.get("url") or "") for n in _nodes(row.get("externalReferences"))]
    return [u for u in urls if u.startswith(("http://", "https://"))][:5]


def _labels(row: dict[str, Any]) -> set[str]:
    return {str(lb.get("value", "")).lower() for lb in row.get("objectLabel") or []}


def _objects(row: dict[str, Any]) -> list[dict[str, Any]]:
    return _nodes(row.get("objects"))


def from_opencti(
    window: OpenCTIWindow, *, max_cluster_iocs: int = 200, include_vulnerabilities: bool = False
) -> list[Finding]:
    """Reports, indicator clusters and (optionally) vulnerabilities as findings.

    Vulnerabilities are off by default: the KEV connector re-touches the whole
    catalogue, so ``updated_at`` says nothing about news. New KEV entries come from
    the direct KEV collector (``dateAdded``) instead.
    """
    out: list[Finding] = []
    in_reports: set[str] = set()

    for r in window.entities.get("report", []):
        f = Finding(
            key=str(r.get("standard_id") or r.get("id")),
            kind="report",
            title=str(r.get("name") or "Report"),
            summary=str(r.get("description") or "")[:1500],
            sources=[_author(r)],
            source_urls=_refs(r),
            first_seen=_dt(r.get("published")) or _dt(r.get("created")),
            tlp=tlp_of(r) or "TLP:CLEAR",
            confidence=int(r.get("confidence") or 50),
            stix_ids=[str(r.get("standard_id"))] if r.get("standard_id") else [],
        )
        for obj in _objects(r):
            et = obj.get("entity_type")
            name = str(obj.get("name") or "")
            if et == "Attack-Pattern" and obj.get("x_mitre_id"):
                f.attack_ids.add(str(obj["x_mitre_id"]))
            elif et == "Vulnerability" and name.upper().startswith("CVE-"):
                f.cves.add(name.upper())
            elif et == "Malware" and name:
                f.malware.add(name)
            elif et in ("Intrusion-Set", "Threat-Actor-Group", "Threat-Actor") and name:
                f.actors.add(name)
            elif et == "Sector" and name:
                f.sectors.add(name.lower())
            elif et in ("Country", "Region") and name:
                f.countries.add(name)
            elif et == "Indicator":
                f.iocs += iocs_from_pattern(str(obj.get("pattern") or ""))
                if obj.get("id"):
                    in_reports.add(str(obj["id"]))
        f.iocs = sorted(set(f.iocs))
        out.append(f)

    for v in window.entities.get("vulnerability", []) if include_vulnerabilities else []:
        name = str(v.get("name") or "").upper()
        if not name.startswith("CVE-"):
            continue
        kev = bool(v.get("x_opencti_cisa_kev")) or "cisa" in _author(v).lower()
        out.append(
            Finding(
                key=name,
                kind="vulnerability",
                title=name,
                summary=str(v.get("description") or "")[:1200],
                sources=[_author(v)],
                first_seen=_dt(v.get("created")),
                tlp=tlp_of(v) or "TLP:CLEAR",
                confidence=int(v.get("confidence") or 50),
                cves={name},
                in_kev=kev,
                exploited=kev,
                stix_ids=[str(v.get("standard_id"))] if v.get("standard_id") else [],
            )
        )

    # Indicators that aren't part of a report: cluster by (author, name) so 1,000
    # ThreatFox rows become a handful of "N IOCs for family X" findings.
    clusters: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for ind in window.entities.get("indicator", []):
        if str(ind.get("id")) in in_reports:
            continue
        clusters[(_author(ind), str(ind.get("name") or "Indicators"))].append(ind)
    for (author, name), rows in clusters.items():
        iocs: list[Ioc] = []
        for row in rows:
            iocs += iocs_from_pattern(str(row.get("pattern") or ""))
        iocs = sorted(set(iocs))[:max_cluster_iocs]
        if not iocs:
            continue
        labels = set().union(*(_labels(r) for r in rows))
        firsts = [d for d in (_dt(r.get("created")) for r in rows) if d]
        family = name.split(":", 1)[1].strip() if ":" in name else ""
        out.append(
            Finding(
                key=f"cluster:{author}:{name}",
                kind="indicators",
                title=f"{name} ({len(iocs)} indicators)",
                summary=f"{len(iocs)} indicators reported by {author}."
                + (f" Labels: {', '.join(sorted(labels)[:8])}." if labels else ""),
                sources=[author],
                source_urls=sorted({u for r in rows for u in _refs(r)})[:3],
                first_seen=min(firsts) if firsts else None,
                tlp=max((tlp_of(r) or "TLP:CLEAR" for r in rows), key=_tlp_rank),
                confidence=max(int(r.get("confidence") or 0) for r in rows),
                iocs=iocs,
                malware={family} if family and family.lower() != "unknown family" else set(),
                stix_ids=[str(r["standard_id"]) for r in rows if r.get("standard_id")][:200],
            )
        )
    return out


def _tlp_rank(tlp: str) -> int:
    from hexbrief.model import TLP_ORDER

    return TLP_ORDER.index(tlp) if tlp in TLP_ORDER else 2


def from_misp(window: Any) -> list[Finding]:
    """MISP events (after ``fresh_only``) -> one finding per event."""
    by_event: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for a in window.attributes:
        by_event[str(a.get("event_id"))].append(a)
    kind_map = {
        "ip-dst": "ipv4",
        "ip-src": "ipv4",
        "domain": "domain",
        "hostname": "domain",
        "url": "url",
        "md5": "md5",
        "sha1": "sha1",
        "sha256": "sha256",
        "sha512": "sha512",
    }
    out: list[Finding] = []
    for ev in window.events:
        eid = str(ev.get("id"))
        attrs = by_event.get(eid, [])
        if not attrs:
            continue
        iocs, wl = [], 0
        for a in attrs:
            t = kind_map.get(str(a.get("type")))
            if t:
                iocs.append(Ioc(t, str(a.get("value"))))
            wl += bool(a.get("warnings"))
        tags = {str(t.get("name", "")).lower() for t in ev.get("Tag") or []}
        tlp = next((t.upper() for t in tags if t.startswith("tlp:")), "tlp:clear").upper()
        out.append(
            Finding(
                key=str(ev.get("uuid") or eid),
                kind="misp-event",
                title=str(ev.get("info") or f"MISP event {eid}"),
                summary=f"MISP event with {len(attrs)} fresh IDS attributes.",
                sources=["MISP (CIRCL OSINT / Botvrij)"],
                first_seen=_dt(ev.get("date")),
                tlp=tlp.replace("TLP:WHITE", "TLP:CLEAR"),
                confidence=60,
                iocs=sorted(set(iocs))[:200],
                warninglist_hits=wl,
                attack_ids={
                    t.split("=")[-1].strip('"').split(" - ")[-1]
                    for t in tags
                    if "mitre-attack-pattern" in t and " - t" in t
                },
            )
        )
    return out


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge findings that share a CVE or an IOC (union-find), keeping provenance.

    The merged finding keeps the title of its most specific member: a report or
    vulnerability beats an indicator cluster.
    """
    parent = list(range(len(findings)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}

    def ioc_keys(f: Finding) -> list[str]:
        return [f"ioc:{i_.type}:{i_.value.lower()}" for i_ in f.iocs]

    # Pass 1: CVEs (all kinds) and IOCs of reports/events/vulnerabilities claim keys.
    for i, f in enumerate(findings):
        keys = [f"cve:{c}" for c in f.cves]
        if f.kind != "indicators":
            keys += ioc_keys(f)
        for k in keys:
            if k in owner:
                parent[find(i)] = find(owner[k])
            else:
                owner[k] = i
    # Pass 2: indicator clusters JOIN a story that shares one of their IOCs, but
    # never claim IOC keys themselves, so two big clusters sharing one IP can't
    # swallow each other.
    for i, f in enumerate(findings):
        if f.kind == "indicators":
            for k in ioc_keys(f):
                if k in owner:
                    parent[find(i)] = find(owner[k])
                    break
    groups: dict[int, list[Finding]] = defaultdict(list)
    for i, f in enumerate(findings):
        groups[find(i)].append(f)
    rank = {"report": 0, "misp-event": 1, "vulnerability": 2, "indicators": 3}
    merged: list[Finding] = []
    for members in groups.values():
        members.sort(key=lambda f: (rank.get(f.kind, 9), -len(f.summary)))
        head = members[0]
        for m in members[1:]:
            head.merge(m)
        merged.append(head)
    return merged


def is_asean(f: Finding) -> bool:
    return any(c.lower() in ASEAN for c in f.countries) or "asean" in f.summary.lower()


def is_education(f: Finding) -> bool:
    text = f"{f.title} {f.summary} {' '.join(f.sectors)}".lower()
    return any(w in text for w in ("education", "universit", "academ", "school", "student"))
