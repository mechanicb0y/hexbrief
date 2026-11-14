"""Write medallion's users file from env vars, then start medallion.

medallion keeps users as plain-text passwords in its config, so the password is
never baked into the image or committed: it comes from .env at container start
and lives only in a temp file inside the container.
"""

import json
import os
import sys
import tempfile

user = os.environ.get("TAXII_USER", "")
password = os.environ.get("TAXII_PASSWORD", "")
if not user or not password or "__replace_me__" in (user, password):
    sys.exit("TAXII_USER / TAXII_PASSWORD are not set. Run scripts/gen-secrets.ps1 first.")

conf_dir = tempfile.mkdtemp(prefix="medallion.d.")
with open(os.path.join(conf_dir, "users.json"), "w", encoding="utf-8") as fh:
    json.dump({"users": {user: password}}, fh)
os.chmod(os.path.join(conf_dir, "users.json"), 0o600)

# Inside the container we listen on all interfaces; compose publishes the port
# on 127.0.0.1 only, so nothing outside this PC can reach it.
os.execvp(  # noqa: S606
    "medallion",  # noqa: S607 - installed by pip on the image's PATH
    [
        "medallion",
        "--host",
        "0.0.0.0",  # noqa: S104 - container-internal; published on 127.0.0.1 only
        "--port",
        "5000",
        "--conf-dir",
        conf_dir,
        "/opt/taxii/config.json",
    ],
)
