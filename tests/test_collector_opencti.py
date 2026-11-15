"""Unit tests for the OpenCTI collector. A fake stands in for pycti; no server needed."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from hexbrief.collectors.opencti import ENTITY_TYPES, collect_window, tlp_of, window_filter


class FakeLister:
    def __init__(self, rows: Any) -> None:
        self.rows = rows
        self.calls: list[dict[str, Any]] = []

    def list(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return self.rows


class FakeOpenCTI:
    def __init__(self, **rows: Any) -> None:
        for kind in ENTITY_TYPES:
            setattr(self, kind, FakeLister(rows.get(kind, [])))


NOW = datetime(2026, 11, 15, 7, 0, tzinfo=UTC)


def test_window_filter_shape() -> None:
    f = window_filter("2026-11-14T07:00:00.000Z")
    assert f["mode"] == "and"
    assert f["filters"] == [
        {"key": ["updated_at"], "values": ["2026-11-14T07:00:00.000Z"], "operator": "gte"}
    ]
    assert f["filterGroups"] == []


def test_collects_every_type_with_window_and_paging() -> None:
    api = FakeOpenCTI(
        report=[{"id": "r1", "createdBy": {"name": "AlienVault"}}],
        indicator=[{"id": "i1", "createdBy": {"name": "ThreatFox"}}, {"id": "i2"}],
    )
    window = collect_window(api, hours=24, now=NOW)
    assert window.since == "2026-11-14T07:00:00.000Z"
    assert window.counts == {
        "report": 1,
        "indicator": 2,
        "vulnerability": 0,
        "malware": 0,
        "intrusion_set": 0,
    }
    call = api.indicator.calls[0]
    assert call["getAll"] is True
    assert call["filters"]["filters"][0]["values"] == ["2026-11-14T07:00:00.000Z"]
    assert window.sources == {"AlienVault": 1, "ThreatFox": 1, "unknown": 1}


def test_api_error_is_not_an_empty_day() -> None:
    api = FakeOpenCTI()
    api.report = FakeLister(None)
    with pytest.raises(RuntimeError, match="report"):
        collect_window(api, now=NOW)


def test_empty_day() -> None:
    window = collect_window(FakeOpenCTI(), now=NOW)
    assert sum(window.counts.values()) == 0


def test_invalid_window() -> None:
    with pytest.raises(ValueError):
        collect_window(FakeOpenCTI(), hours=0)


@pytest.mark.parametrize(
    ("markings", "expected"),
    [
        ([{"definition": "TLP:CLEAR"}], "TLP:CLEAR"),
        ([{"definition": "TLP:WHITE"}], "TLP:CLEAR"),
        ([{"definition": "PAP:GREEN"}, {"definition": "TLP:AMBER+STRICT"}], "TLP:AMBER+STRICT"),
        ([], None),
        (None, None),
    ],
)
def test_tlp_of(markings: Any, expected: str | None) -> None:
    assert tlp_of({"objectMarking": markings}) == expected
