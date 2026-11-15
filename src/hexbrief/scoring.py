"""Transparent, rule-based ranking. No AI: every point has a written reason.

Weights are deliberately simple so an analyst can predict the ranking and argue
with it. Each finding gets ``score`` and ``reasons`` (shown in the brief appendix).
"""

from __future__ import annotations

from datetime import UTC, datetime

from hexbrief.model import Finding
from hexbrief.normalize import is_asean, is_education

WEIGHTS = {
    "in_kev": 30,  # CISA confirmed exploitation in the wild
    "exploited": 15,  # other evidence of exploitation
    "ransomware": 10,  # known ransomware use
    "fresh_24h": 10,  # first seen in the last 24 h
    "fresh_72h": 5,  # first seen in the last 72 h
    "per_extra_source": 8,  # each independent source beyond the first (max 3)
    "confidence_per_10": 1,  # +1 per 10 points of source confidence
    "education": 20,  # our lens: universities
    "government": 5,
    "malaysia": 20,  # our lens: Malaysia ...
    "asean": 10,  # ... and ASEAN
    "has_attack": 3,  # mapped to ATT&CK, so it is actionable for detection
    "warninglist": -15,  # IOCs hit known-benign lists (likely false positives)
    "report_bonus": 5,  # analysed reporting beats raw IOC dumps
}


def score(f: Finding, now: datetime | None = None) -> Finding:
    now = now or datetime.now(UTC)
    pts: list[tuple[int, str]] = []
    if f.in_kev:
        pts.append((WEIGHTS["in_kev"], "in CISA KEV"))
    if f.exploited and not f.in_kev:
        pts.append((WEIGHTS["exploited"], "exploited in the wild"))
    if f.ransomware:
        pts.append((WEIGHTS["ransomware"], "known ransomware use"))
    if f.first_seen:
        age_h = (now - f.first_seen).total_seconds() / 3600
        if age_h <= 24:
            pts.append((WEIGHTS["fresh_24h"], "new in the last 24 h"))
        elif age_h <= 72:
            pts.append((WEIGHTS["fresh_72h"], "new in the last 72 h"))
    extra = min(len(set(f.sources)) - 1, 3)
    if extra > 0:
        pts.append((extra * WEIGHTS["per_extra_source"], f"{extra + 1} independent sources"))
    pts.append((f.confidence // 10 * WEIGHTS["confidence_per_10"], f"confidence {f.confidence}"))
    # Lens bonuses. Feed reports often tag long lists of "targeted" sectors and
    # countries; a match buried in a list of 20 is weaker evidence than one named in
    # the title or summary, so broad lists get a reduced bonus.
    text = f"{f.title} {f.summary}".lower()
    broad_sectors = len(f.sectors) > 5
    broad_countries = len(f.countries) > 8
    if is_education(f):
        named = any(w in text for w in ("education", "universit", "academ", "student"))
        if named or not broad_sectors:
            pts.append((WEIGHTS["education"], "education sector"))
        else:
            pts.append((WEIGHTS["education"] // 3, f"education among {len(f.sectors)} sectors"))
    if "government" in {s.lower() for s in f.sectors}:
        pts.append((WEIGHTS["government"], "government sector"))
    in_my = any(c.lower() == "malaysia" for c in f.countries) or "malaysia" in text
    if in_my:
        if "malaysia" in text or not broad_countries:
            pts.append((WEIGHTS["malaysia"], "Malaysia"))
        else:
            pts.append((WEIGHTS["malaysia"] // 3, f"Malaysia among {len(f.countries)} countries"))
    elif is_asean(f):
        if "asean" in text or not broad_countries:
            pts.append((WEIGHTS["asean"], "ASEAN"))
        else:
            pts.append((WEIGHTS["asean"] // 3, f"ASEAN among {len(f.countries)} countries"))
    if f.attack_ids:
        pts.append((WEIGHTS["has_attack"], "ATT&CK-mapped"))
    if f.kind in ("report", "misp-event"):
        pts.append((WEIGHTS["report_bonus"], "analysed report"))
    if f.iocs and f.warninglist_hits >= len(f.iocs):
        pts.append((WEIGHTS["warninglist"], "all IOCs hit warninglists"))
    f.score = float(sum(p for p, _ in pts))
    f.reasons = [f"{'+' if p >= 0 else ''}{p} {why}" for p, why in pts if p]
    return f


def rank(findings: list[Finding], now: datetime | None = None) -> list[Finding]:
    """Score and sort, highest first; ties broken by title for stable output."""
    for f in findings:
        score(f, now)
    return sorted(findings, key=lambda f: (-f.score, f.title))
