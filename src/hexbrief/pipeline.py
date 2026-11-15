"""Wire real collectors to the engine (used by ``hexbrief run``)."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from hexbrief.engine import Collector
from hexbrief.model import Finding


def build_collectors() -> tuple[dict[str, Collector], Any]:
    """Collectors keyed by name, plus an ``enrich`` hook (KEV cross-check)."""
    from hexbrief.collectors import kev

    catalog: dict[str, Any] = {}

    def kev_collector(now: datetime, hours: int) -> list[Finding]:
        catalog.update(kev.fetch())
        return kev.findings_added_since(catalog, kev.window_start(now, hours))

    def opencti_collector(now: datetime, hours: int) -> list[Finding]:
        from hexbrief.collectors.opencti import collect_for_brief, connect
        from hexbrief.normalize import from_opencti

        url, token = os.environ.get("OPENCTI_URL", ""), os.environ.get("OPENCTI_TOKEN", "")
        if not url or not token:
            raise RuntimeError("OPENCTI_URL / OPENCTI_TOKEN not set")
        return from_opencti(collect_for_brief(connect(url, token), hours, now=now))

    def misp_collector(now: datetime, hours: int) -> list[Finding]:
        from hexbrief.collectors.misp import collect_window, connect, fresh_only
        from hexbrief.normalize import from_misp

        url, key = os.environ.get("MISP_URL", ""), os.environ.get("MISP_API_KEY", "")
        if not url or not key:
            raise RuntimeError("MISP_URL / MISP_API_KEY not set")
        verify_raw = os.environ.get("MISP_VERIFY_SSL", "true")
        verify: bool | str = {"true": True, "false": False}.get(verify_raw.lower(), verify_raw)
        misp = connect(url, key, verify=verify, timeout=30)
        # fresh_only: feed re-publication makes old events look new (ADR-003 / Phase 2).
        return from_misp(fresh_only(collect_window(misp, hours), hours, now=now))

    def enrich(findings: list[Finding]) -> None:
        known = kev.kev_cves(catalog) if catalog else set()
        for f in findings:
            if f.cves & known:
                f.exploited = True  # scoring: "exploited in the wild"

    collectors: dict[str, Collector] = {
        "cisa_kev": kev_collector,
        "opencti": opencti_collector,
        "misp": misp_collector,
    }
    return collectors, enrich
