"""A thin TAXII 2.1 client on httpx (see docs/adr/002-taxii-tooling.md).

TAXII 2.1 in one breath: a *discovery* endpoint lists *API roots*; each API root
holds *collections*; each collection serves STIX *objects* inside an *envelope*
(``{"more": bool, "next": str, "objects": [...]}``). Clients page with ``limit``
and ``next``, and ask only for newer data with ``added_after``.

Design rules (owner's requirements, 2026-11-14):
- Accept ``application/taxii+json;version=2.1`` on every request.
- Follow ``more``/``next`` pagination; support ``added_after`` and ``limit``.
- Timeouts always set; TLS verification on by default.
- Retry with exponential backoff on 429 and 5xx (honouring Retry-After).
- Typed errors; credentials never appear in logs or exception messages.
"""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable, Iterator, Sequence
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE = "application/stix+json;version=2.1"

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
# A POST may already have been processed when the server answers 500/502/504,
# so we retry writes only when the server says it did not take the request.
RETRY_STATUSES_WRITE = frozenset({429, 503})

log = logging.getLogger(__name__)


# --------------------------------------------------------------------- errors
class TaxiiError(Exception):
    """Base class for every error this client raises."""


class TaxiiHTTPError(TaxiiError):
    """The server answered with an HTTP error status."""

    def __init__(self, status_code: int, method: str, url: str, detail: str = "") -> None:
        self.status_code = status_code
        self.method = method
        self.url = url
        msg = f"{method} {url} -> HTTP {status_code}"
        super().__init__(f"{msg}: {detail}" if detail else msg)


class TaxiiAuthError(TaxiiHTTPError):
    """401/403: missing or wrong credentials, or no permission for this collection."""


class TaxiiNotFoundError(TaxiiHTTPError):
    """404: unknown API root, collection or object."""


class TaxiiRetryError(TaxiiError):
    """Retries were exhausted on a transient failure (429, 5xx or a network error)."""


class TaxiiProtocolError(TaxiiError):
    """The server's answer is not valid TAXII 2.1 (bad JSON, content type or pagination)."""


# --------------------------------------------------------------------- client
def _ensure_slash(url: str) -> str:
    return url if url.endswith("/") else url + "/"


def _check_url(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError(f"TAXII URL must be http(s): {url!r}")
    if parts.username or parts.password:
        # Credentials in a URL end up in logs and shell history. Use auth= instead.
        raise ValueError("TAXII URL must not contain credentials; pass auth=(user, password)")
    return url


class TaxiiClient:
    """Minimal synchronous TAXII 2.1 client.

    >>> with TaxiiClient(timeout=30) as c:
    ...     roots = c.api_roots("https://attack-taxii.mitre.org/taxii2/")
    """

    def __init__(
        self,
        *,
        auth: tuple[str, str] | None = None,
        timeout: float = 30.0,
        verify: bool = True,
        max_retries: int = 4,
        backoff: float = 1.0,
        max_backoff: float = 30.0,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not verify:
            log.warning("TLS verification is OFF for this TAXII client (lab use only)")
        self._http = httpx.Client(
            auth=auth,
            timeout=timeout,
            verify=verify,
            transport=transport,
            headers={"Accept": TAXII_MEDIA_TYPE, "User-Agent": "hexbrief-stixkit/0.1"},
            follow_redirects=False,
        )
        self.max_retries = max_retries
        self.backoff = backoff
        self.max_backoff = max_backoff
        self._sleep = sleep

    # context manager -------------------------------------------------------
    def __enter__(self) -> TaxiiClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    # low level -------------------------------------------------------------
    def _delay(self, attempt: int, response: httpx.Response | None) -> float:
        if response is not None:
            retry_after = response.headers.get("Retry-After", "")
            if retry_after.isdigit():
                return min(float(retry_after), self.max_backoff)
        # exponential backoff with jitter: 1s, 2s, 4s, ... (+0-25%)
        base = self.backoff * (2**attempt)
        return min(base * (1 + random.uniform(0, 0.25)), self.max_backoff)  # noqa: S311

    def _request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        json_body: Any = None,
    ) -> httpx.Response:
        _check_url(url)
        retry_on = RETRY_STATUSES if method == "GET" else RETRY_STATUSES_WRITE
        headers = {"Content-Type": TAXII_MEDIA_TYPE} if json_body is not None else None
        for attempt in range(self.max_retries + 1):
            response: httpx.Response | None = None
            try:
                response = self._http.request(
                    method, url, params=params, json=json_body, headers=headers
                )
            except httpx.TransportError as exc:
                # Network trouble. Only safe to repeat for reads.
                if method != "GET" or attempt == self.max_retries:
                    raise TaxiiRetryError(f"{method} {url}: {type(exc).__name__}") from exc
                log.warning("%s %s: %s, retrying", method, url, type(exc).__name__)
            else:
                log.debug("%s %s -> %s", method, response.url, response.status_code)
                if response.status_code < 400:
                    return response
                if response.status_code not in retry_on:
                    self._raise_for(response, method, url)
                if attempt == self.max_retries:
                    raise TaxiiRetryError(
                        f"{method} {url}: still HTTP {response.status_code} "
                        f"after {self.max_retries} retries"
                    )
                log.warning("%s %s -> HTTP %s, retrying", method, url, response.status_code)
            self._sleep(self._delay(attempt, response))
        raise AssertionError("unreachable")  # pragma: no cover

    @staticmethod
    def _raise_for(response: httpx.Response, method: str, url: str) -> None:
        detail = ""
        try:
            body = response.json()
            if isinstance(body, dict):
                detail = str(body.get("title") or body.get("description") or "")[:200]
        except ValueError:
            pass
        status = response.status_code
        cls: type[TaxiiHTTPError] = TaxiiHTTPError
        if status in (401, 403):
            cls = TaxiiAuthError
        elif status == 404:
            cls = TaxiiNotFoundError
        raise cls(status, method, url, detail)

    def _get_json(
        self, url: str, params: dict[str, str] | None = None
    ) -> tuple[Any, httpx.Response]:
        response = self._request("GET", url, params=params)
        ctype = response.headers.get("Content-Type", "")
        if "json" not in ctype:
            raise TaxiiProtocolError(f"GET {url}: expected TAXII JSON, got {ctype or 'no type'!r}")
        try:
            return response.json(), response
        except ValueError as exc:
            raise TaxiiProtocolError(f"GET {url}: response is not valid JSON") from exc

    # TAXII endpoints -------------------------------------------------------
    def discovery(self, discovery_url: str) -> dict[str, Any]:
        """GET the discovery resource (server title, default and api_roots)."""
        data, _ = self._get_json(_ensure_slash(discovery_url))
        return dict(data)

    def api_roots(self, discovery_url: str) -> list[str]:
        """Return absolute API root URLs. Servers may list them relative (MITRE does)."""
        disc = self.discovery(discovery_url)
        return [_ensure_slash(urljoin(discovery_url, root)) for root in disc.get("api_roots", [])]

    def api_root_info(self, api_root: str) -> dict[str, Any]:
        data, _ = self._get_json(_ensure_slash(api_root))
        return dict(data)

    def collections(self, api_root: str) -> list[dict[str, Any]]:
        data, _ = self._get_json(_ensure_slash(api_root) + "collections/")
        return list(data.get("collections", []))

    def objects(
        self,
        api_root: str,
        collection_id: str,
        *,
        added_after: str | None = None,
        limit: int | None = None,
        match: dict[str, str] | None = None,
        max_pages: int = 10_000,
    ) -> Iterator[dict[str, Any]]:
        """Yield every STIX object in a collection, following pagination.

        ``match`` takes TAXII filters without the prefix, e.g. ``{"type": "indicator"}``.
        """
        url = f"{_ensure_slash(api_root)}collections/{collection_id}/objects/"
        params: dict[str, str] = {}
        if added_after:
            params["added_after"] = added_after
        if limit:
            params["limit"] = str(limit)
        for key, value in (match or {}).items():
            params[f"match[{key}]"] = value

        # Loop guard. We can't compare cursors: `next` is opaque, and some servers
        # (medallion) reuse the same session id for every page. Instead stop if a
        # page is identical to the previous one, or if the server says "more" but
        # sends nothing.
        last_page: tuple[str, ...] | None = None
        for _page in range(max_pages):
            envelope, response = self._get_json(url, params=params)
            page_objects = envelope.get("objects", []) or []
            page_key = tuple(f"{o.get('id')}|{o.get('modified', '')}" for o in page_objects)
            if envelope.get("more") and (not page_objects or page_key == last_page):
                raise TaxiiProtocolError(f"{url}: pagination is not advancing; stopping")
            last_page = page_key
            yield from page_objects
            if not envelope.get("more"):
                return
            # Preferred: the server's opaque `next` cursor.
            cursor = envelope.get("next")
            if cursor:
                params["next"] = str(cursor)
            else:
                # Fallback in the spec: resume after the last object's date added.
                last_added = response.headers.get("X-TAXII-Date-Added-Last")
                if not last_added:
                    raise TaxiiProtocolError(
                        f"{url}: more=true but no `next` cursor or date header"
                    )
                params.pop("next", None)
                params["added_after"] = last_added
        raise TaxiiProtocolError(f"{url}: more than {max_pages} pages; stopping")

    def add_objects(
        self, api_root: str, collection_id: str, objects: Sequence[dict[str, Any]]
    ) -> dict[str, Any]:
        """POST objects to a collection. Returns the TAXII status resource."""
        url = f"{_ensure_slash(api_root)}collections/{collection_id}/objects/"
        response = self._request("POST", url, json_body={"objects": list(objects)})
        try:
            return dict(response.json())
        except ValueError as exc:
            raise TaxiiProtocolError(f"POST {url}: status response is not valid JSON") from exc

    def status(self, api_root: str, status_id: str) -> dict[str, Any]:
        data, _ = self._get_json(f"{_ensure_slash(api_root)}status/{status_id}/")
        return dict(data)
