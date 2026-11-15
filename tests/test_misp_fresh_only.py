"""fresh_only(): keep attributes by their own timestamp. Offline, fixed clock."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from hexbrief.collectors.misp import MispWindow, fresh_only

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
OLD_2015 = int(datetime(2015, 6, 1, tzinfo=UTC).timestamp())


def ts(dt: datetime) -> str:
    return str(int(dt.timestamp()))  # MISP sends epoch seconds as a string


def attr(n: int, event_id: str, timestamp: Any, **extra: Any) -> dict[str, Any]:
    return {"id": str(n), "event_id": event_id, "type": "ip-dst", "timestamp": timestamp, **extra}


def event(event_id: str, uuid: str | None = None) -> dict[str, Any]:
    e: dict[str, Any] = {"id": event_id, "info": f"event {event_id}"}
    if uuid:
        e["uuid"] = uuid
    return e


def test_2015_attribute_dropped_fresh_one_kept_and_empty_event_dropped() -> None:
    window = MispWindow(
        hours=24,
        events=[event("1"), event("2")],
        attributes=[
            attr(1, "1", ts(NOW - timedelta(hours=1))),  # fresh
            attr(2, "1", str(OLD_2015)),  # same event, from 2015
            attr(3, "2", str(OLD_2015)),  # event 2 only has old data
        ],
    )
    fresh = fresh_only(window, 24, now=NOW)
    assert [a["id"] for a in fresh.attributes] == ["1"]
    assert [e["id"] for e in fresh.events] == ["1"]
    assert fresh.hours == 24


@pytest.mark.parametrize("bad", [None, "", "  ", "abc", "1.5e9x", True, "-99999999999999999"])
def test_missing_or_bad_timestamp_counts_as_old(bad: Any) -> None:
    window = MispWindow(hours=24, events=[event("1")], attributes=[attr(1, "1", bad)])
    fresh = fresh_only(window, 24, now=NOW)
    assert fresh.attributes == [] and fresh.events == []


def test_attribute_without_timestamp_key_counts_as_old() -> None:
    a = {"id": "1", "event_id": "1", "type": "domain"}
    fresh = fresh_only(MispWindow(hours=24, events=[event("1")], attributes=[a]), 24, now=NOW)
    assert fresh.attributes == []


@pytest.mark.parametrize(
    ("when", "kept"),
    [
        (NOW - timedelta(hours=24), True),  # exactly at the start of the window
        (NOW - timedelta(hours=24, seconds=1), False),  # one second too old
        (NOW, True),
        (NOW + timedelta(minutes=4), True),  # small clock skew is tolerated
        (NOW + timedelta(hours=1), False),  # far future is not "fresh"
    ],
)
def test_window_edges(when: datetime, kept: bool) -> None:
    window = MispWindow(hours=24, events=[event("1")], attributes=[attr(1, "1", ts(when))])
    assert bool(fresh_only(window, 24, now=NOW).attributes) is kept


def test_int_timestamp_also_works() -> None:
    a = attr(1, "1", int((NOW - timedelta(hours=2)).timestamp()))
    assert fresh_only(MispWindow(hours=24, attributes=[a]), 24, now=NOW).attributes == [a]


def test_shorter_window_than_collected() -> None:
    window = MispWindow(
        hours=24,
        events=[event("1")],
        attributes=[
            attr(1, "1", ts(NOW - timedelta(hours=2))),
            attr(2, "1", ts(NOW - timedelta(hours=10))),
        ],
    )
    fresh = fresh_only(window, 6, now=NOW)
    assert [a["id"] for a in fresh.attributes] == ["1"]
    assert fresh.hours == 6


def test_events_matched_by_uuid_when_attribute_has_no_event_id() -> None:
    a = {"id": "1", "event_uuid": "u-1", "timestamp": ts(NOW)}
    window = MispWindow(
        hours=24, events=[event("7", uuid="u-1"), event("8", uuid="u-2")], attributes=[a]
    )
    assert [e["id"] for e in fresh_only(window, 24, now=NOW).events] == ["7"]


def test_input_window_is_not_changed() -> None:
    attrs = [attr(1, "1", str(OLD_2015))]
    window = MispWindow(hours=24, events=[event("1")], attributes=attrs)
    fresh_only(window, 24, now=NOW)
    assert window.attributes == attrs and len(window.events) == 1


def test_naive_now_is_treated_as_utc() -> None:
    a = attr(1, "1", ts(NOW - timedelta(hours=1)))
    naive = NOW.replace(tzinfo=None)
    assert fresh_only(MispWindow(hours=24, attributes=[a]), 24, now=naive).attributes == [a]


def test_invalid_hours() -> None:
    with pytest.raises(ValueError):
        fresh_only(MispWindow(hours=24), 0, now=NOW)
