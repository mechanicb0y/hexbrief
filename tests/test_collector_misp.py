"""Unit tests for the MISP collector. A fake stands in for PyMISP; no server needed.

The response shapes are recorded from MISP 2.5 restSearch.
"""

from __future__ import annotations

from typing import Any

import pytest

from hexbrief.collectors.misp import collect_window, event_as_stix


class FakeMisp:
    def __init__(
        self, events: Any = None, attribute_pages: list[Any] | None = None, stix: Any = None
    ) -> None:
        self.events = events if events is not None else []
        self.pages = attribute_pages or [{"Attribute": []}]
        self.stix = stix
        self.calls: list[dict[str, Any]] = []

    def search(self, controller: str = "events", return_format: str = "json", **kw: Any) -> Any:
        self.calls.append({"controller": controller, "return_format": return_format, **kw})
        if return_format == "stix2":
            return self.stix
        if controller == "events":
            return self.events
        return self.pages[kw["page"] - 1]


def attr(n: int, type_: str = "ip-dst", to_ids: bool = True) -> dict[str, Any]:
    return {"id": str(n), "type": type_, "value": f"198.51.100.{n}", "to_ids": to_ids}


def test_window_filters_published_ids_and_warninglists() -> None:
    misp = FakeMisp(
        events=[{"Event": {"id": "1", "info": "x"}}],
        attribute_pages=[{"Attribute": [attr(1), attr(2, "domain")]}],
    )
    window = collect_window(misp, hours=24)
    ev_call, at_call = misp.calls
    assert ev_call["controller"] == "events"
    assert ev_call["publish_timestamp"] == "24h"
    assert ev_call["published"] is True
    assert at_call["controller"] == "attributes"
    assert at_call["to_ids"] is True
    assert at_call["enforce_warninglist"] is True
    assert window.events == [{"id": "1", "info": "x"}]
    assert window.attribute_types == {"ip-dst": 1, "domain": 1}
    assert window.ids_attributes == 2


def test_context_attributes_when_ids_only_is_off() -> None:
    misp = FakeMisp()
    collect_window(misp, hours=6, ids_only=False, enforce_warninglist=False)
    at_call = misp.calls[1]
    assert at_call["to_ids"] is None
    assert at_call["enforce_warninglist"] is False
    assert at_call["publish_timestamp"] == "6h"


def test_pages_until_a_short_page() -> None:
    full = {"Attribute": [attr(i) for i in range(3)]}
    misp = FakeMisp(attribute_pages=[full, full, {"Attribute": [attr(9)]}])
    window = collect_window(misp, page_size=3)
    assert len(window.attributes) == 7
    assert [c["page"] for c in misp.calls[1:]] == [1, 2, 3]


def test_too_many_pages_is_an_error_not_a_silent_cut() -> None:
    full = {"Attribute": [attr(1)]}
    misp = FakeMisp(attribute_pages=[full, full])
    with pytest.raises(RuntimeError, match="narrow the window"):
        collect_window(misp, page_size=1, max_pages=2)


def test_empty_day() -> None:
    window = collect_window(FakeMisp(events=[], attribute_pages=[{"Attribute": []}]))
    assert window.events == [] and window.attributes == []


def test_misp_error_response_raises() -> None:
    misp = FakeMisp(events={"errors": [403, {"message": "Authentication failed."}]})
    with pytest.raises(RuntimeError, match="MISP search failed"):
        collect_window(misp)


def test_invalid_window() -> None:
    with pytest.raises(ValueError):
        collect_window(FakeMisp(), hours=0)


def test_event_as_stix_asks_for_stix_21() -> None:
    misp = FakeMisp(stix={"type": "bundle", "id": "bundle--x", "objects": []})
    assert event_as_stix(misp, 42)["type"] == "bundle"
    call = misp.calls[0]
    assert call["return_format"] == "stix2"
    assert call["stix-version"] == "2.1"
    assert call["eventid"] == 42


def test_event_as_stix_rejects_non_bundle() -> None:
    with pytest.raises(RuntimeError):
        event_as_stix(FakeMisp(stix={"errors": "nope"}), 1)
