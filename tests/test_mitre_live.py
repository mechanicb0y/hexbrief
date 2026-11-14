"""Live smoke test against MITRE's public ATT&CK TAXII 2.1 server.

Never runs in CI. Run it by hand with:  $env:HEXBRIEF_LIVE=1; pytest -m live
"""

from __future__ import annotations

import os
from itertools import islice

import pytest

from hexbrief.stixkit.taxii import TaxiiClient

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.environ.get("HEXBRIEF_LIVE") != "1", reason="set HEXBRIEF_LIVE=1"),
]

MITRE = "https://attack-taxii.mitre.org/taxii2/"


def test_mitre_enterprise_attack_first_page() -> None:
    with TaxiiClient(timeout=60) as c:
        roots = c.api_roots(MITRE)
        assert "https://attack-taxii.mitre.org/api/v21/" in roots
        colls = c.collections("https://attack-taxii.mitre.org/api/v21/")
        enterprise = next(x for x in colls if x["title"] == "Enterprise ATT&CK")
        first = list(
            islice(
                c.objects("https://attack-taxii.mitre.org/api/v21/", enterprise["id"], limit=50), 50
            )
        )
    assert len(first) == 50
    assert all("--" in o["id"] and "type" in o for o in first)
