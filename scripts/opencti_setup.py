"""One-time OpenCTI lab setup (Phase 3). Admin-only; run by hand, never by the pipeline.

    python scripts/opencti_setup.py

Idempotent. It creates:
1. the label ``hexbrief`` (later put on every brief Report);
2. the TAXII 2.1 collection ``daily-briefs`` (Reports labelled ``hexbrief``), under
   OpenCTI's own TAXII server (Data sharing);
3. a least-privilege reader: role "HexBrief reader" (KNOWLEDGE + API token + TAXII
   read), group "HexBrief readers" (all TLP markings, local use), user
   automation@hexbrief.lab;
4. a 365-day API token for that reader, written to the repo .env as OPENCTI_TOKEN.

No password or token is ever printed.
"""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

import requests
from pycti import OpenCTIApiClient

REPO = Path(__file__).resolve().parents[1]
STACK_ENV = REPO / "docker" / "opencti" / ".env.opencti"
REPO_ENV = REPO / ".env"
URL = "http://127.0.0.1:8088"
READER_EMAIL = "automation@hexbrief.lab"
READER_CAPS = ("KNOWLEDGE", "APIACCESS", "APIACCESS_USETOKEN", "TAXIIAPI")


def read_env(path: Path) -> dict[str, str]:
    return dict(
        (k.strip(), v.strip())
        for k, v in (
            line.split("=", 1)
            for line in path.read_text(encoding="utf-8").splitlines()
            if "=" in line and not line.lstrip().startswith("#")
        )
    )


def set_env(path: Path, key: str, value: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if line.split("=", 1)[0].strip() == key:
            lines[i] = f"{key}={value}"
            break
    else:
        lines.append(f"{key}={value}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def gql(token: str, query: str, variables: dict | None = None) -> dict:
    r = requests.post(
        f"{URL}/graphql",
        json={"query": query, "variables": variables or {}},
        headers={"Authorization": f"Bearer {token}"},
        timeout=60,
    )
    r.raise_for_status()
    body = r.json()
    if body.get("errors"):
        # Error messages from OpenCTI never contain our secrets.
        sys.exit(f"GraphQL error: {[e.get('message') for e in body['errors']]}")
    return body["data"]


def main() -> None:
    env = read_env(STACK_ENV)
    admin_token = env["OPENCTI_ADMIN_TOKEN"]
    api = OpenCTIApiClient(URL, admin_token, log_level="error")

    # 1. label
    label = api.label.read_or_create_unchecked(value="hexbrief", color="#0f766e")
    label_id = label["id"]
    print("label hexbrief: ok")

    # 2. TAXII collection for daily briefs
    found = gql(
        admin_token,
        'query { taxiiCollections(search: "daily-briefs") { edges { node { id name } } } }',
    )["taxiiCollections"]["edges"]
    if not any(e["node"]["name"] == "daily-briefs" for e in found):
        filters = {
            "mode": "and",
            "filters": [
                {"key": ["entity_type"], "values": ["Report"], "operator": "eq", "mode": "or"},
                {"key": ["objectLabel"], "values": [label_id], "operator": "eq", "mode": "or"},
            ],
            "filterGroups": [],
        }
        gql(
            admin_token,
            "mutation($input: TaxiiCollectionAddInput!) "
            "{ taxiiCollectionAdd(input: $input) { id } }",
            {
                "input": {
                    "name": "daily-briefs",
                    "description": "HexBrief daily briefs (STIX 2.1 Reports labelled hexbrief).",
                    "filters": json.dumps(filters),
                    "taxii_public": False,
                }
            },
        )
        print("TAXII collection daily-briefs: created")
    else:
        print("TAXII collection daily-briefs: exists")

    # 3. least-privilege reader
    caps = {c["name"]: c["id"] for c in api.capability.list()}
    role = next((r for r in api.role.list() if r["name"] == "HexBrief reader"), None)
    if role is None:
        role = api.role.create(
            name="HexBrief reader", description="Read-only knowledge + API token"
        )
        for cap in READER_CAPS:
            api.role.add_capability(id=role["id"], capability_id=caps[cap])
    group = next((g for g in api.group.list() if g["name"] == "HexBrief readers"), None)
    if group is None:
        group = api.group.create(
            name="HexBrief readers",
            description="HexBrief collectors",
            group_confidence_level={"max_confidence": 100, "overrides": []},
        )
        if group is None:
            sys.exit("group creation failed (see OpenCTI logs)")
        api.group.add_role(id=group["id"], role_id=role["id"])
        markings = [m["id"] for m in api.marking_definition.list() if m["definition_type"] == "TLP"]
        for mid in markings:
            api.group.add_allowed_marking(id=group["id"], marking_id=mid)
    user = next((u for u in api.user.list() if u.get("user_email") == READER_EMAIL), None)
    if user is None:
        password = secrets.token_urlsafe(32)
        user = api.user.create(
            name="HexBrief automation",
            user_email=READER_EMAIL,
            password=password,
            groups=[group["id"]],
        )
        set_env(STACK_ENV, "OPENCTI_READER_PASSWORD", password)
        print(f"user {READER_EMAIL}: created (password stored in .env.opencti, not shown)")
    else:
        print(f"user {READER_EMAIL}: exists")

    # 4. token for the reader: tokens are minted by their owner, so log in as the reader
    password = read_env(STACK_ENV).get("OPENCTI_READER_PASSWORD")
    if not password:
        sys.exit("OPENCTI_READER_PASSWORD missing; cannot mint the reader token")
    session = requests.Session()
    r = session.post(
        f"{URL}/graphql",
        json={
            "query": "mutation($input: UserLoginInput!) { token(input: $input) }",
            "variables": {"input": {"email": READER_EMAIL, "password": password}},
        },
        timeout=60,
    )
    r.raise_for_status()
    login = r.json()
    if login.get("errors"):
        sys.exit(f"reader login failed: {[e.get('message') for e in login['errors']]}")
    minted = session.post(
        f"{URL}/graphql",
        json={
            "query": 'mutation { userTokenAdd(input: {name: "hexbrief-collector", '
            "duration: DAYS_365}) { token_id plaintext_token } }"
        },
        timeout=60,
    ).json()
    if minted.get("errors"):
        sys.exit(f"token mint failed: {[e.get('message') for e in minted['errors']]}")
    set_env(REPO_ENV, "OPENCTI_URL", URL)
    set_env(REPO_ENV, "OPENCTI_TOKEN", minted["data"]["userTokenAdd"]["plaintext_token"])
    print("reader token (365 days) written to .env as OPENCTI_TOKEN (not shown)")


if __name__ == "__main__":
    main()
