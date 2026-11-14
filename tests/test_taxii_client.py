"""Unit tests for the TAXII 2.1 client. No network: every response is mocked with respx."""

from __future__ import annotations

import logging

import httpx
import pytest
import respx

from hexbrief.stixkit.taxii import (
    TAXII_MEDIA_TYPE,
    TaxiiAuthError,
    TaxiiClient,
    TaxiiNotFoundError,
    TaxiiProtocolError,
    TaxiiRetryError,
)

ROOT = "https://taxii.example.test/api/"
COLL = "c0ffee00-0000-4000-8000-000000000001"
OBJECTS_URL = f"{ROOT}collections/{COLL}/objects/"
JSON = {"Content-Type": TAXII_MEDIA_TYPE}


def obj(n: int) -> dict:
    return {"type": "indicator", "id": f"indicator--00000000-0000-4000-8000-{n:012d}"}


def client(**kw) -> TaxiiClient:
    sleeps: list[float] = []
    c = TaxiiClient(sleep=sleeps.append, backoff=0.01, **kw)
    c.sleeps = sleeps  # type: ignore[attr-defined]
    return c


@respx.mock
def test_sends_taxii_accept_header() -> None:
    route = respx.get(f"{ROOT}collections/").respond(200, json={"collections": []}, headers=JSON)
    with client() as c:
        assert c.collections(ROOT) == []
    assert route.calls.last.request.headers["Accept"] == TAXII_MEDIA_TYPE


@respx.mock
def test_relative_api_roots_are_made_absolute() -> None:
    respx.get("https://taxii.example.test/taxii2/").respond(
        200, json={"title": "t", "api_roots": ["/api/v21", "https://other.test/x/"]}, headers=JSON
    )
    with client() as c:
        roots = c.api_roots("https://taxii.example.test/taxii2/")
    assert roots == ["https://taxii.example.test/api/v21/", "https://other.test/x/"]


@respx.mock
def test_follows_next_cursor_and_sends_filters() -> None:
    route = respx.get(OBJECTS_URL).mock(
        side_effect=[
            httpx.Response(
                200, json={"more": True, "next": "p2", "objects": [obj(1), obj(2)]}, headers=JSON
            ),
            httpx.Response(200, json={"more": False, "objects": [obj(3)]}, headers=JSON),
        ]
    )
    with client() as c:
        got = list(
            c.objects(
                ROOT, COLL, added_after="2026-11-13T23:00:00Z", limit=2, match={"type": "indicator"}
            )
        )
    assert [o["id"][-1] for o in got] == ["1", "2", "3"]
    first, second = (call.request.url.params for call in route.calls)
    assert first["added_after"] == "2026-11-13T23:00:00Z"
    assert first["limit"] == "2"
    assert first["match[type]"] == "indicator"
    assert "next" not in first
    assert second["next"] == "p2"


@respx.mock
def test_falls_back_to_date_added_header_when_no_next() -> None:
    route = respx.get(OBJECTS_URL).mock(
        side_effect=[
            httpx.Response(
                200,
                json={"more": True, "objects": [obj(1)]},
                headers={**JSON, "X-TAXII-Date-Added-Last": "2026-11-14T01:00:00.000Z"},
            ),
            httpx.Response(200, json={"more": False, "objects": [obj(2)]}, headers=JSON),
        ]
    )
    with client() as c:
        assert len(list(c.objects(ROOT, COLL))) == 2
    assert route.calls[1].request.url.params["added_after"] == "2026-11-14T01:00:00.000Z"


@respx.mock
def test_same_cursor_is_fine_if_pages_advance() -> None:
    # medallion reuses one session id as `next` for every page
    respx.get(OBJECTS_URL).mock(
        side_effect=[
            httpx.Response(
                200, json={"more": True, "next": "s1", "objects": [obj(1)]}, headers=JSON
            ),
            httpx.Response(
                200, json={"more": True, "next": "s1", "objects": [obj(2)]}, headers=JSON
            ),
            httpx.Response(200, json={"more": False, "objects": [obj(3)]}, headers=JSON),
        ]
    )
    with client() as c:
        assert len(list(c.objects(ROOT, COLL))) == 3


@respx.mock
def test_identical_pages_stop_instead_of_looping_forever() -> None:
    respx.get(OBJECTS_URL).respond(
        200, json={"more": True, "next": "same", "objects": [obj(1)]}, headers=JSON
    )
    with client() as c, pytest.raises(TaxiiProtocolError, match="not advancing"):
        list(c.objects(ROOT, COLL))


@respx.mock
def test_more_true_with_empty_page_stops() -> None:
    respx.get(OBJECTS_URL).respond(
        200, json={"more": True, "next": "x", "objects": []}, headers=JSON
    )
    with client() as c, pytest.raises(TaxiiProtocolError, match="not advancing"):
        list(c.objects(ROOT, COLL))


@respx.mock
def test_empty_collection() -> None:
    respx.get(OBJECTS_URL).respond(200, json={"more": False}, headers=JSON)
    with client() as c:
        assert list(c.objects(ROOT, COLL)) == []


@respx.mock
def test_retries_5xx_then_succeeds() -> None:
    route = respx.get(f"{ROOT}collections/").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(502),
            httpx.Response(200, json={"collections": [{"id": COLL}]}, headers=JSON),
        ]
    )
    with client() as c:
        assert c.collections(ROOT)[0]["id"] == COLL
        assert len(c.sleeps) == 2
    assert route.call_count == 3


@respx.mock
def test_honours_retry_after_on_429() -> None:
    respx.get(f"{ROOT}collections/").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "7"}),
            httpx.Response(200, json={"collections": []}, headers=JSON),
        ]
    )
    with client() as c:
        c.collections(ROOT)
        assert c.sleeps == [7.0]


@respx.mock
def test_gives_up_after_max_retries() -> None:
    route = respx.get(f"{ROOT}collections/").respond(500)
    with client(max_retries=2) as c, pytest.raises(TaxiiRetryError):
        c.collections(ROOT)
    assert route.call_count == 3


@respx.mock
def test_retries_network_errors_on_get() -> None:
    respx.get(f"{ROOT}collections/").mock(
        side_effect=[
            httpx.ConnectError("boom"),
            httpx.Response(200, json={"collections": []}, headers=JSON),
        ]
    )
    with client() as c:
        assert c.collections(ROOT) == []


@respx.mock
def test_auth_error_is_typed_and_not_retried() -> None:
    route = respx.get(f"{ROOT}collections/").respond(401, json={"title": "Unauthorized"})
    with client() as c, pytest.raises(TaxiiAuthError) as err:
        c.collections(ROOT)
    assert err.value.status_code == 401
    assert route.call_count == 1


@respx.mock
def test_not_found_is_typed() -> None:
    respx.get(OBJECTS_URL).respond(404)
    with client() as c, pytest.raises(TaxiiNotFoundError):
        list(c.objects(ROOT, COLL))


@respx.mock
def test_post_is_not_retried_on_500() -> None:
    route = respx.post(OBJECTS_URL).respond(500)
    with client() as c, pytest.raises(Exception) as err:
        c.add_objects(ROOT, COLL, [obj(1)])
    assert not isinstance(err.value, TaxiiRetryError)
    assert route.call_count == 1


@respx.mock
def test_post_sends_envelope_with_taxii_content_type() -> None:
    route = respx.post(OBJECTS_URL).respond(
        202, json={"id": "s1", "status": "complete", "success_count": 1}, headers=JSON
    )
    with client() as c:
        status = c.add_objects(ROOT, COLL, [obj(1)])
    req = route.calls.last.request
    assert req.headers["Content-Type"] == TAXII_MEDIA_TYPE
    assert b'"objects"' in req.content
    assert status["success_count"] == 1


@respx.mock
def test_non_json_response_is_a_protocol_error() -> None:
    respx.get(f"{ROOT}collections/").respond(
        200, text="<html>login</html>", headers={"Content-Type": "text/html"}
    )
    with client() as c, pytest.raises(TaxiiProtocolError):
        c.collections(ROOT)


def test_rejects_credentials_in_url() -> None:
    with client() as c, pytest.raises(ValueError, match="credentials"):
        c.collections("https://user:secret@taxii.example.test/api/")


@respx.mock
def test_password_never_logged(caplog: pytest.LogCaptureFixture) -> None:
    secret = "S3cr3t-do-not-log"
    respx.get(f"{ROOT}collections/").mock(
        side_effect=[httpx.Response(503), httpx.Response(401, json={"title": "Unauthorized"})]
    )
    caplog.set_level(logging.DEBUG)
    with client(auth=("hexbrief", secret)) as c, pytest.raises(TaxiiAuthError) as err:
        c.collections(ROOT)
    assert secret not in caplog.text
    assert secret not in str(err.value)
