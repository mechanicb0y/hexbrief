"""Lab setup for MISP feeds (Phase 2). Admin-only; run by hand, never by the pipeline.

    python scripts/misp_feeds.py list
    python scripts/misp_feeds.py cache            # cache CIRCL OSINT + Botvrij (no DB writes)
    python scripts/misp_feeds.py fetch            # enable + fetch them into the DB
    python scripts/misp_feeds.py warninglists     # update + enable all warninglists

Reads BASE_URL / ADMIN_KEY from docker/misp/.env.misp and trusts the lab CA.
No key or password is ever printed.
"""

from __future__ import annotations

import sys
from pathlib import Path

from pymisp import PyMISP

REPO = Path(__file__).resolve().parents[1]
ENV = REPO / "docker" / "misp" / ".env.misp"
CA = REPO / "docker" / "misp" / "upstream" / "ssl" / "ca.pem"
# Owner's choice (ADR-003). Never abuse.ch here: those feed URLs embed the Auth-Key.
WANTED = ("CIRCL OSINT Feed", "The Botvrij.eu Data")


def _env() -> dict[str, str]:
    env: dict[str, str] = {}
    for line in ENV.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def misp() -> PyMISP:
    env = _env()
    return PyMISP(
        env["BASE_URL"], env["ADMIN_KEY"], ssl=str(CA), timeout=120, tool="hexbrief-setup"
    )


def wanted_feeds(m: PyMISP) -> list[dict]:
    feeds = [f["Feed"] for f in m.feeds(pythonify=False)]
    chosen = [f for f in feeds if f["name"] in WANTED]
    missing = set(WANTED) - {f["name"] for f in chosen}
    if missing:
        sys.exit(f"default feeds not found: {sorted(missing)}")
    return chosen


def main(cmd: str) -> None:
    m = misp()
    if cmd == "list":
        for f in m.feeds(pythonify=False):
            f = f["Feed"]
            print(
                f"{f['id']:>3} enabled={f['enabled']!s:5} cache={f['caching_enabled']!s:5} "
                f"{f['source_format']:6} {f['name']}"
            )
    elif cmd == "cache":
        for f in wanted_feeds(m):
            m.enable_feed_cache(f["id"])
            print(f["name"], "->", m.cache_feed(f["id"]))
    elif cmd == "fetch":
        for f in wanted_feeds(m):
            m.enable_feed(f["id"])
            print(f["name"], "->", m.fetch_feed(f["id"]))
    elif cmd == "warninglists":
        print("update ->", m.update_warninglists())
        lists = m.warninglists(pythonify=False)
        rows = lists.get("Warninglists", lists) if isinstance(lists, dict) else lists
        ids = [int(w["Warninglist"]["id"]) for w in rows]
        result = m.toggle_warninglist(warninglist_id=ids, force_enable=True) if ids else "none"
        print("enable ->", str(result)[:200])
        print(f"{len(ids)} warninglists")
    elif cmd == "automation":
        create_automation_user(m)
    else:
        sys.exit(__doc__)


def create_automation_user(m: PyMISP) -> None:
    """Read-only user for the collector; its API key goes straight into the repo .env."""
    from pymisp import MISPUser

    email = "automation@hexbrief.lab"
    roles = {r["Role"]["name"]: r["Role"]["id"] for r in m.roles(pythonify=False)}
    role_id = roles.get("Read Only")
    if role_id is None:
        sys.exit(f"no 'Read Only' role; roles are {sorted(roles)}")
    users = [u["User"] for u in m.users(pythonify=False)]
    admin_org = next(u["org_id"] for u in users if u["id"] == "1")
    existing = next((u for u in users if u["email"] == email), None)
    if existing is None:
        user = MISPUser()
        user.email, user.org_id, user.role_id = email, admin_org, role_id
        created = m.add_user(user, pythonify=False)
        user_id = created["User"]["id"]
        print(f"created {email} (role Read Only)")
    else:
        user_id = existing["id"]
        print(f"{email} exists (id {user_id})")
    key = m.get_new_authkey(user_id)  # shown once by MISP; never printed here
    _set_env_value(REPO / ".env", "MISP_API_KEY", str(key))
    _set_env_value(REPO / ".env", "MISP_URL", "https://127.0.0.1:8443")
    _set_env_value(REPO / ".env", "MISP_VERIFY_SSL", str(CA))
    print("MISP_URL, MISP_API_KEY (not shown) and MISP_VERIFY_SSL written to .env")


def _set_env_value(path: Path, key: str, value: str) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if line.split("=", 1)[0].strip() == key:
            lines[i] = f"{key}={value}"
            break
    else:
        lines.append(f"{key}={value}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "")
