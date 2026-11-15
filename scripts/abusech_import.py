"""Import abuse.ch ThreatFox + URLhaus into OpenCTI (replaces the retired CSV connectors).

    python scripts/abusech_import.py [--days 1] [--dry-run]

Reads ABUSECH_AUTH_KEY from the repo .env (sent as a header, never in a URL) and
a dedicated importer token from docker/opencti/.env.opencti (create/update knowledge,
confidence capped at 50; never the admin token). Prints counts only.
Phase 7 runs this daily.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from hexbrief.collectors.abusech import pull, to_stix_bundle  # noqa: E402
from hexbrief.stixkit.bundle import count_by_type, validate  # noqa: E402


def read_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=1)
    ap.add_argument("--dry-run", action="store_true", help="build + validate, don't import")
    args = ap.parse_args()

    key = read_env(REPO / ".env").get("ABUSECH_AUTH_KEY", "")
    data = pull(key, days=args.days)
    bundle = to_stix_bundle(data)
    report = validate(bundle)
    print(f"ThreatFox rows: {len(data.threatfox)}, URLhaus rows: {len(data.urlhaus)}")
    print("bundle:", dict(count_by_type(bundle["objects"])), "valid:", report.is_valid)
    if not report.is_valid:
        print("refusing to import an invalid bundle:", report.errors[:5])
        return 1
    if args.dry_run:
        return 0

    from pycti import OpenCTIApiClient

    # Least privilege: a dedicated importer (create/update knowledge, confidence <= 50),
    # never the admin token. Created by scripts/opencti_setup.py.
    token = read_env(REPO / "docker" / "opencti" / ".env.opencti").get("OPENCTI_IMPORTER_TOKEN")
    if not token:
        print("OPENCTI_IMPORTER_TOKEN missing: run scripts/opencti_setup.py")
        return 1
    api = OpenCTIApiClient("http://127.0.0.1:8088", token, log_level="error")
    # The return value only lists top-level results, so it is not a reliable count.
    # OpenCTI ships TLP 2.0 markings with the same OASIS ids; re-creating them needs
    # SETTINGS_SETMARKINGS, which the importer deliberately lacks. Refs still resolve.
    bundle["objects"] = [o for o in bundle["objects"] if o["type"] != "marking-definition"]
    api.stix2.import_bundle_from_json(json.dumps(bundle), update=True)
    print("import finished; check with: hexbrief opencti recent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
