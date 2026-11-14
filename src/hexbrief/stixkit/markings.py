"""TLP 2.0 marking definitions for STIX 2.1.

The stix2 library only ships TLP 1.0 (TLP_WHITE etc.). TLP 2.0 markings are
defined by OASIS as marking-definition objects that carry a property extension.
The ids and contents below are copied from the official OASIS definitions:
https://github.com/oasis-open/cti-stix-common-objects/tree/main/extension-definition-specifications/tlp-2.0

Rule from the master prompt: old TLP:WHITE maps to TLP:CLEAR.
"""

from __future__ import annotations

from typing import Any

TLP2_EXTENSION_ID = "extension-definition--60a3c5c5-0d10-413e-aab3-9e08dde9e88d"

_TLP2_IDS = {
    "clear": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "green": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    "amber": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
    "amber+strict": "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
    "red": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
}

# TLP 1.0 ids (as shipped by stix2) -> TLP 2.0 level.
_TLP1_TO_TLP2 = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "clear",  # TLP:WHITE
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
}


def tlp2_marking(level: str) -> dict[str, Any]:
    """Return the official TLP 2.0 marking-definition object as a dict."""
    level = level.lower()
    if level == "white":
        level = "clear"
    if level not in _TLP2_IDS:
        raise ValueError(f"unknown TLP level: {level!r}")
    return {
        "type": "marking-definition",
        "spec_version": "2.1",
        "id": _TLP2_IDS[level],
        "created": "2022-10-01T00:00:00.000Z",
        "name": f"TLP:{level.upper()}",
        "extensions": {
            TLP2_EXTENSION_ID: {"extension_type": "property-extension", "tlp_2_0": level},
        },
    }


def tlp2_id(level: str) -> str:
    """Return the TLP 2.0 marking-definition id for a level ('white' maps to 'clear')."""
    return str(tlp2_marking(level)["id"])


def tlp_level_of(marking_id: str) -> str | None:
    """Map a TLP 1.0 or 2.0 marking-definition id to a TLP 2.0 level, or None if not TLP."""
    for level, mid in _TLP2_IDS.items():
        if mid == marking_id:
            return level
    return _TLP1_TO_TLP2.get(marking_id)


TLP_CLEAR = tlp2_marking("clear")
