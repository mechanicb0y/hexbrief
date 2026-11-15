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
# Least privilege: the brief engine only reads; the abuse.ch importer may create and
# update knowledge but is capped at confidence 50, so it can never overwrite data
# from higher-confidence sources (security review, 2026-11-15).
PRINCIPALS = (
    {
        "name": "HexBrief automation",
        "email": "automation@hexbrief.lab",
        "role": "HexBrief reader",
        "group": "HexBrief readers",
        "description": "Read-only knowledge + API token (brief engine)",
        "caps": ("KNOWLEDGE", "APIACCESS", "APIACCESS_USETOKEN", "TAXIIAPI"),
        "max_confidence": 100,
        "password_key": "OPENCTI_READER_PASSWORD",
        "token_name": "hexbrief-collector",
        "token_key": "OPENCTI_TOKEN",
        "token_file": REPO_ENV,
    },
    {
        "name": "HexBrief abuse.ch importer",
        "email": "importer@hexbrief.lab",
        "role": "HexBrief importer",
        "group": "HexBrief importers",
        "description": "Create/update knowledge only, confidence capped at 50",
        "caps": (
            "KNOWLEDGE",
            "KNOWLEDGE_KNUPDATE",
            "KNOWLEDGE_KNPARTICIPATE",
            "APIACCESS",
            "APIACCESS_USETOKEN",
        ),
        "max_confidence": 50,
        "password_key": "OPENCTI_IMPORTER_PASSWORD",
        "token_name": "hexbrief-abusech-importer",
        "token_key": "OPENCTI_IMPORTER_TOKEN",
        "token_file": STACK_ENV,
    },
)


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

    # 3. least-privilege principals
    caps = {c["name"]: c["id"] for c in api.capability.list()}
    tlp_markings = [m["id"] for m in api.marking_definition.list() if m["definition_type"] == "TLP"]
    for p in PRINCIPALS:
        ensure_principal(api, p, caps, tlp_markings)
        if read_env(p["token_file"]).get(p["token_key"], "") not in ("", "__replace_me__"):
            print(f"{p['email']}: token already in {p['token_file'].name}, not minting another")
            continue
        token = mint_token(p)
        set_env(p["token_file"], p["token_key"], token)
        print(
            f"{p['email']}: token (365 days) written to {p['token_file'].name} "
            f"as {p['token_key']} (not shown)"
        )
    set_env(REPO_ENV, "OPENCTI_URL", URL)


def ensure_principal(api: OpenCTIApiClient, p: dict, caps: dict, markings: list[str]) -> None:
    role = next((r for r in api.role.list() if r["name"] == p["role"]), None)
    if role is None:
        role = api.role.create(name=p["role"], description=p["description"])
        for cap in p["caps"]:
            api.role.add_capability(id=role["id"], capability_id=caps[cap])
    group = next((g for g in api.group.list() if g["name"] == p["group"]), None)
    if group is None:
        group = api.group.create(
            name=p["group"],
            description=p["description"],
            group_confidence_level={"max_confidence": p["max_confidence"], "overrides": []},
        )
        if group is None:
            sys.exit(f"group creation failed for {p['group']} (see OpenCTI logs)")
        api.group.add_role(id=group["id"], role_id=role["id"])
        for mid in markings:
            api.group.add_allowed_marking(id=group["id"], marking_id=mid)
    user = next((u for u in api.user.list() if u.get("user_email") == p["email"]), None)
    if user is None:
        password = secrets.token_urlsafe(32)
        api.user.create(
            name=p["name"], user_email=p["email"], password=password, groups=[group["id"]]
        )
        set_env(STACK_ENV, p["password_key"], password)
        print(f"user {p['email']}: created (password stored in .env.opencti, not shown)")


def mint_token(p: dict) -> str:
    """API tokens are minted by their owner, so log in as that user first."""
    password = read_env(STACK_ENV).get(p["password_key"])
    if not password:
        sys.exit(f"{p['password_key']} missing; cannot mint a token for {p['email']}")
    session = requests.Session()
    r = session.post(
        f"{URL}/graphql",
        json={
            "query": "mutation($input: UserLoginInput!) { token(input: $input) }",
            "variables": {"input": {"email": p["email"], "password": password}},
        },
        timeout=60,
    )
    r.raise_for_status()
    if r.json().get("errors"):
        sys.exit(f"login failed for {p['email']}: {[e.get('message') for e in r.json()['errors']]}")
    minted = session.post(
        f"{URL}/graphql",
        json={
            "query": "mutation($n: String!) { userTokenAdd(input: {name: $n, "
            "duration: DAYS_365}) { token_id plaintext_token } }",
            "variables": {"n": p["token_name"]},
        },
        timeout=60,
    ).json()
    if minted.get("errors"):
        sys.exit(f"token mint failed: {[e.get('message') for e in minted['errors']]}")
    return str(minted["data"]["userTokenAdd"]["plaintext_token"])


if __name__ == "__main__":
    main()
