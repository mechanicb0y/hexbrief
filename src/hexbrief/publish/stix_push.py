"""Push the brief's STIX Report to OpenCTI and to the lab TAXII server (medallion).

OpenCTI: imported with the least-privilege *importer* token (ADR-004). The Report
carries the label ``hexbrief``, so OpenCTI's ``daily-briefs`` TAXII collection
(filtered on that label) serves it over TAXII 2.1 automatically.
"""

from __future__ import annotations

import json
from typing import Any

from hexbrief.stixkit.taxii import TaxiiClient


def push_opencti(bundle: dict[str, Any], url: str, importer_token: str) -> None:
    from pycti import OpenCTIApiClient

    if not importer_token:
        raise RuntimeError("OPENCTI_IMPORTER_TOKEN missing (scripts/opencti_setup.py)")
    objects = [o for o in bundle["objects"] if o["type"] != "marking-definition"]
    api = OpenCTIApiClient(url, importer_token, log_level="error")
    api.stix2.import_bundle_from_json(json.dumps({**bundle, "objects": objects}), update=True)


def push_taxii(
    bundle: dict[str, Any],
    discovery: str,
    user: str,
    password: str,
    collection_title: str = "daily-briefs",
) -> dict[str, Any]:
    with TaxiiClient(auth=(user, password), timeout=30) as c:
        root = c.api_roots(discovery)[0]
        coll = next(x for x in c.collections(root) if x.get("title") == collection_title)
        return c.add_objects(root, coll["id"], bundle["objects"])
