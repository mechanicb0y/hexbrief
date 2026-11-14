"""Round trip against the local medallion server: push a bundle, pull it back.

Start the server first: scripts\\taxii-up.ps1. Skipped if it isn't running.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from hexbrief.stixkit.bundle import build_demo_bundle, validate
from hexbrief.stixkit.taxii import TaxiiAuthError, TaxiiClient
from tests.conftest import setting

pytestmark = pytest.mark.integration

DISCOVERY = setting("TAXII_URL", "http://127.0.0.1:5000/taxii2/")
COLLECTION_TITLE = "daily-briefs"


def _server_up() -> bool:
    try:
        httpx.get(DISCOVERY, timeout=2)
        return True
    except httpx.HTTPError:
        return False


@pytest.fixture(scope="module")
def taxii() -> TaxiiClient:
    if not _server_up():
        pytest.skip("medallion not running (scripts/taxii-up.ps1)")
    user, password = setting("TAXII_USER"), setting("TAXII_PASSWORD")
    if not user or not password:
        pytest.skip("TAXII_USER/TAXII_PASSWORD not set (scripts/gen-secrets.ps1)")
    with TaxiiClient(auth=(user, password), timeout=10) as c:
        yield c


def _daily_briefs(c: TaxiiClient) -> tuple[str, str]:
    root = c.api_roots(DISCOVERY)[0]
    coll = next(x for x in c.collections(root) if x["title"] == COLLECTION_TITLE)
    return root, coll["id"]


def test_wrong_password_is_rejected() -> None:
    if not _server_up():
        pytest.skip("medallion not running")
    with (
        TaxiiClient(auth=("hexbrief", "wrong-password"), timeout=10) as c,
        pytest.raises(TaxiiAuthError),
    ):
        c.collections(c.api_roots(DISCOVERY)[0])


def test_push_then_pull_back(taxii: TaxiiClient) -> None:
    root, coll_id = _daily_briefs(taxii)
    bundle = json.loads(build_demo_bundle().serialize())
    assert validate(bundle).is_valid
    sent_ids = {o["id"] for o in bundle["objects"]}
    since = (datetime.now(UTC) - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    status = taxii.add_objects(root, coll_id, bundle["objects"])
    for _ in range(20):  # the spec allows asynchronous processing
        if status.get("status") == "complete":
            break
        time.sleep(0.5)
        status = taxii.status(root, status["id"])
    assert status["status"] == "complete"
    assert status["failure_count"] == 0, status.get("failures")

    # Page size 2 forces the client through the pagination path.
    everything = {o["id"]: o for o in taxii.objects(root, coll_id, limit=2)}
    assert sent_ids <= everything.keys()
    for o in bundle["objects"]:
        assert everything[o["id"]]["type"] == o["type"]

    # added_after returns only objects first added in this run. The identity and
    # TLP marking have fixed ids, so after the first run they are not "new" any more:
    # re-sending the same version doesn't change its date_added.
    fresh = {o["id"] for o in taxii.objects(root, coll_id, added_after=since, limit=2)}
    new_ids = {
        o["id"] for o in bundle["objects"] if o["type"] in ("malware", "indicator", "relationship")
    }
    assert new_ids <= fresh
