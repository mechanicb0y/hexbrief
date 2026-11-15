"""The normalized Finding: one unit of news, whatever source it came from.

Every finding keeps its provenance (sources, source URLs, STIX ids), so any claim
in the brief can be traced back to data.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

TLP_ORDER = ("TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED")


def max_tlp(*levels: str | None) -> str:
    """The most restrictive TLP among ``levels`` (unknown counts as AMBER: fail safe)."""
    best = 0
    for lvl in levels:
        norm = (lvl or "").upper().replace("TLP:WHITE", "TLP:CLEAR")
        best = max(best, TLP_ORDER.index(norm) if norm in TLP_ORDER else 2)
    return TLP_ORDER[best]


@dataclass(frozen=True, order=True)
class Ioc:
    type: str  # ipv4 | ipv6 | domain | url | md5 | sha1 | sha256 | sha512
    value: str


_PATTERN_PARTS = re.compile(
    r"(ipv4-addr|ipv6-addr|domain-name|url):value\s*=\s*'((?:\\'|[^'])*)'"
    r"|file:hashes\.'?(MD5|SHA-1|SHA-256|SHA-512)'?\s*=\s*'([0-9a-fA-F]+)'",
)
_KIND = {"ipv4-addr": "ipv4", "ipv6-addr": "ipv6", "domain-name": "domain", "url": "url"}
_HASH = {"MD5": "md5", "SHA-1": "sha1", "SHA-256": "sha256", "SHA-512": "sha512"}


def iocs_from_pattern(pattern: str) -> list[Ioc]:
    """Pull simple equality IOCs out of a STIX pattern (complex logic is ignored)."""
    out: list[Ioc] = []
    for kind, value, hash_kind, hash_value in _PATTERN_PARTS.findall(pattern or ""):
        if kind:
            out.append(Ioc(_KIND[kind], value.replace("\\'", "'")))
        elif hash_kind:
            out.append(Ioc(_HASH[hash_kind], hash_value.lower()))
    return out


@dataclass
class Finding:
    key: str  # stable id from the source (STIX id, CVE, MISP uuid)
    kind: str  # vulnerability | report | indicators | misp-event
    title: str
    summary: str = ""
    sources: list[str] = field(default_factory=list)
    source_urls: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    tlp: str = "TLP:CLEAR"
    confidence: int = 50
    iocs: list[Ioc] = field(default_factory=list)
    cves: set[str] = field(default_factory=set)
    attack_ids: set[str] = field(default_factory=set)
    malware: set[str] = field(default_factory=set)
    actors: set[str] = field(default_factory=set)
    sectors: set[str] = field(default_factory=set)
    countries: set[str] = field(default_factory=set)
    in_kev: bool = False
    # CVEs newly added to KEV in the window -> vulnerability name (survives merges)
    kev_new: dict[str, str] = field(default_factory=dict)
    exploited: bool = False
    ransomware: bool = False
    warninglist_hits: int = 0
    stix_ids: list[str] = field(default_factory=list)
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)

    def merge(self, other: Finding) -> None:
        """Fold ``other`` (same story from another source) into this finding."""
        for src in other.sources:
            if src not in self.sources:
                self.sources.append(src)
        for url in other.source_urls:
            if url not in self.source_urls:
                self.source_urls.append(url)
        seen = set(self.iocs)
        self.iocs += [i for i in other.iocs if i not in seen]
        self.cves |= other.cves
        self.attack_ids |= other.attack_ids
        self.malware |= other.malware
        self.actors |= other.actors
        self.sectors |= other.sectors
        self.countries |= other.countries
        self.in_kev |= other.in_kev
        self.kev_new.update(other.kev_new)
        self.exploited |= other.exploited
        self.ransomware |= other.ransomware
        self.warninglist_hits += other.warninglist_hits
        self.confidence = max(self.confidence, other.confidence)
        self.tlp = max_tlp(self.tlp, other.tlp)
        self.stix_ids += [s for s in other.stix_ids if s not in self.stix_ids]
        if other.first_seen and (not self.first_seen or other.first_seen < self.first_seen):
            self.first_seen = other.first_seen
        if len(other.summary) > len(self.summary):
            self.summary = other.summary

    def for_llm(self, fid: str, max_iocs: int = 8) -> dict[str, Any]:
        """The compact view the LLM sees (``F#`` id, no internal keys)."""
        return {
            "id": fid,
            "type": self.kind,
            "title": self.title,
            "summary": self.summary[:600],
            "sources": self.sources,
            "first_seen": self.first_seen.date().isoformat() if self.first_seen else None,
            "tlp": self.tlp,
            "confidence": self.confidence,
            "in_kev": self.in_kev or None,
            "cves": sorted(self.cves),
            "attack_ids": sorted(self.attack_ids),
            "malware": sorted(self.malware),
            "actors": sorted(self.actors),
            "iocs": [i.value for i in self.iocs[:max_iocs]],
            "ioc_count": len(self.iocs) or None,
            "sectors": sorted(self.sectors),
            "countries": sorted(self.countries),
        }
