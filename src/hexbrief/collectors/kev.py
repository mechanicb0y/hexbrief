"""CISA Known Exploited Vulnerabilities, read directly (cross-check on dateAdded).

KEV is the strongest single prioritisation signal: CISA only adds a CVE when there
is reliable evidence of exploitation in the wild.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import Any

import httpx

from hexbrief.model import Finding

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch(transport: httpx.BaseTransport | None = None) -> dict[str, Any]:
    with httpx.Client(
        timeout=60, trust_env=False, transport=transport, headers={"User-Agent": "hexbrief/0.1"}
    ) as http:
        r = http.get(KEV_URL)
        r.raise_for_status()
        data = r.json()
    if not isinstance(data, dict) or "vulnerabilities" not in data:
        raise ValueError("unexpected KEV format")
    return data


def findings_added_since(catalog: dict[str, Any], since: date) -> list[Finding]:
    """One finding per KEV entry whose ``dateAdded`` is on/after ``since``."""
    out: list[Finding] = []
    for v in catalog.get("vulnerabilities", []):
        try:
            added = date.fromisoformat(str(v.get("dateAdded")))
        except ValueError:
            continue
        if added < since:
            continue
        cve = str(v.get("cveID", "")).upper()
        if not cve.startswith("CVE-"):
            continue
        ransomware = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
        out.append(
            Finding(
                key=cve,
                kind="vulnerability",
                title=f"{cve}: {v.get('vulnerabilityName') or 'vulnerability'}",
                summary=(
                    f"{v.get('shortDescription', '')} Added to CISA KEV on {added}; "
                    f"federal due date {v.get('dueDate', 'unknown')}."
                    + (" Known use in ransomware campaigns." if ransomware else "")
                ).strip(),
                sources=["CISA KEV"],
                source_urls=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
                first_seen=datetime.combine(added, datetime.min.time(), UTC),
                tlp="TLP:CLEAR",
                confidence=95,
                cves={cve},
                in_kev=True,
                kev_new={cve: str(v.get("vulnerabilityName") or cve)},
                exploited=True,
                ransomware=ransomware,
            )
        )
    return out


def kev_cves(catalog: dict[str, Any]) -> set[str]:
    return {str(v.get("cveID", "")).upper() for v in catalog.get("vulnerabilities", [])}


def window_start(now: datetime, hours: int) -> date:
    """KEV dates are days (US time), so widen the window to whole days."""
    return (now - timedelta(hours=hours)).date() - timedelta(days=1)
