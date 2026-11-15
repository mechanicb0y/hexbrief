"""Read recent intel from MISP with PyMISP (Phase 2).

MISP vocabulary, as used here:
- *event*: one story (a report, a campaign) that holds attributes and objects.
- *attribute*: one value (ip-dst, domain, sha256...). ``to_ids`` = good enough to
  alert/block on; everything else is context.
- *warninglist*: known-benign values (public DNS, top sites, cloud ranges). Searching
  with ``enforceWarninglist`` drops attributes that hit one.

PyMISP is pinned to the 2.5 line to match the MISP 2.5.51 server (ADR-003).
The collector is read-only: it only calls ``search``.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol


class MispSearch(Protocol):
    """The one PyMISP method we use. Tests pass a fake with the same shape."""

    def search(self, controller: str = ..., return_format: str = ..., **kwargs: Any) -> Any: ...


@dataclass(frozen=True)
class MispWindow:
    """What MISP published in the window, plus quick counts for the run log."""

    hours: int
    events: list[dict[str, Any]] = field(default_factory=list)
    attributes: list[dict[str, Any]] = field(default_factory=list)

    @property
    def attribute_types(self) -> Counter[str]:
        return Counter(str(a.get("type", "?")) for a in self.attributes)

    @property
    def ids_attributes(self) -> int:
        return sum(1 for a in self.attributes if a.get("to_ids") is True)

    @property
    def warninglist_hits(self) -> int:
        """Attributes kept but flagged by a warninglist (scoring subtracts for these)."""
        return sum(1 for a in self.attributes if a.get("warnings"))


def connect(url: str, key: str, verify: bool | str = True, timeout: float = 60) -> MispSearch:
    """Create a PyMISP client. ``verify`` may be a path to MISP's CA/cert file.

    Note: PyMISP contacts the server inside its constructor (version check).
    """
    from pymisp import PyMISP  # imported lazily so unit tests don't need a server

    return PyMISP(url, key, ssl=verify, timeout=timeout, tool="hexbrief")


def _unwrap(rows: Any, key: str) -> list[dict[str, Any]]:
    """restSearch returns ``[{"Event": {...}}]`` for events and
    ``{"Attribute": [...]}`` for attributes. Normalize both to a list of dicts."""
    if isinstance(rows, dict) and "errors" in rows:
        raise RuntimeError(f"MISP search failed: {rows['errors']}")
    if isinstance(rows, dict):
        rows = rows.get(key, [])
    out: list[dict[str, Any]] = []
    for row in rows or []:
        out.append(row.get(key, row) if isinstance(row, dict) else row)
    return out


def collect_window(
    misp: MispSearch,
    hours: int = 24,
    *,
    ids_only: bool = True,
    drop_warninglist_hits: bool = False,
    page_size: int = 1000,
    max_pages: int = 1000,
) -> MispWindow:
    """Events and attributes *published* in the last ``hours`` hours.

    Warninglist hits are **flagged, not dropped** by default: each hit carries a
    ``warnings`` list, so scoring can subtract for it and the appendix can show it.
    We never use MISP's ``enforceWarninglist`` here, because MISP applies it *after*
    paging: a page of 1000 can come back with 974 rows, which looks like the last
    page and silently ends the loop. (Found live on 2026-11-15; see TROUBLESHOOTING.)
    """
    if hours <= 0:
        raise ValueError("hours must be positive")
    since = f"{hours}h"
    events = _unwrap(
        misp.search(
            controller="events",
            publish_timestamp=since,
            published=True,
            metadata=True,  # event headers + tags only; attributes come next
            include_event_tags=True,
            pythonify=False,
        ),
        "Event",
    )
    attributes: list[dict[str, Any]] = []
    for page in range(1, max_pages + 1):
        rows = _unwrap(
            misp.search(
                controller="attributes",
                publish_timestamp=since,
                published=True,
                to_ids=True if ids_only else None,
                include_event_tags=True,
                include_event_uuid=True,
                includeWarninglistHits=True,
                limit=page_size,
                page=page,
                pythonify=False,
            ),
            "Attribute",
        )
        attributes.extend(rows)
        if len(rows) < page_size:  # safe: nothing filters rows after paging now
            break
    else:
        raise RuntimeError(f"more than {max_pages * page_size} attributes; narrow the window")
    if drop_warninglist_hits:
        attributes = [a for a in attributes if not a.get("warnings")]
    return MispWindow(hours=hours, events=events, attributes=attributes)


_MAX_CLOCK_SKEW = timedelta(minutes=5)


def _attribute_time(attribute: Mapping[str, Any]) -> datetime | None:
    """An attribute's own ``timestamp`` (Unix seconds, usually sent as a string) in UTC.

    Returns None when it is missing or cannot be parsed.
    """
    raw = attribute.get("timestamp")
    if raw is None or isinstance(raw, bool):  # bool is an int subclass, never a time
        return None
    try:
        return datetime.fromtimestamp(int(str(raw).strip()), UTC)
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def fresh_only(
    window: MispWindow,
    hours: int,
    *,
    now: datetime | None = None,
    max_clock_skew: timedelta = _MAX_CLOCK_SKEW,
) -> MispWindow:
    """Keep only attributes whose *own* ``timestamp`` is in the last ``hours`` hours.

    ``collect_window`` selects by the event's publish time, and feed events are often
    re-published, so an event published today can still carry attributes from 2015.
    This filter looks at each attribute's own ``timestamp`` instead.

    - A missing or unparsable timestamp counts as old and is dropped: nothing shows it
      is fresh.
    - A timestamp more than ``max_clock_skew`` in the future is dropped too; a few
      minutes of skew between MISP and this machine is tolerated.
    - Events left without any fresh attribute are dropped. Events and attributes are
      matched on ``event_id``, or on ``event_uuid`` when the attribute carries one.

    Returns a new ``MispWindow``; the input window is not changed.
    """
    if hours <= 0:
        raise ValueError("hours must be positive")
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    oldest, newest = now - timedelta(hours=hours), now + max_clock_skew

    kept = [
        a
        for a in window.attributes
        if (t := _attribute_time(a)) is not None and oldest <= t <= newest
    ]
    event_ids = {str(a["event_id"]) for a in kept if a.get("event_id") is not None}
    event_uuids = {str(a["event_uuid"]) for a in kept if a.get("event_uuid")}
    events = [
        e
        for e in window.events
        if (e.get("id") is not None and str(e["id"]) in event_ids)
        or (e.get("uuid") and str(e["uuid"]) in event_uuids)
    ]
    return MispWindow(hours=hours, events=events, attributes=kept)


def event_as_stix(misp: MispSearch, event_id: int | str) -> dict[str, Any]:
    """Export one event as a STIX 2.1 bundle, converted server-side by MISP (misp-stix)."""
    bundle = misp.search(
        controller="events",
        return_format="stix2",
        eventid=event_id,
        pythonify=False,
        **{"stix-version": "2.1"},
    )
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise RuntimeError(f"MISP did not return a STIX bundle for event {event_id}")
    return bundle
