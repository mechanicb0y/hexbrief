# Troubleshooting

Every error we hit, with the log lines, the cause and the fix.

### medallion crashes with `No module named 'pkg_resources'` (2026-11-14, Phase 1)
- **Symptom:** the container exits at start; the traceback ends in `medallion/backends/__init__.py: import pkg_resources`.
- **Cause:** medallion (last commit 2023) imports `pkg_resources`, which newer setuptools versions no longer include. The `python:3.12-slim` image pulls a recent setuptools.
- **Fix:** `pip install "setuptools<81"` in `docker/taxii/Dockerfile`, before medallion.
- **Prevention:** pin the build and treat medallion as lab-only (ADR-002).

### Round-trip test: "server repeated pagination cursor" (2026-11-14, Phase 1)
- **Symptom:** the client stopped after page 1 against medallion with `limit=2`.
- **Cause:** medallion returns the **same** `next` id on every page (a server-side session), and our first loop guard rejected repeated cursors. `next` is opaque, so the spec allows this.
- **Fix:** the loop guard now stops only when a page is identical to the previous one, or when `more=true` comes with no objects. Unit tests cover both cases.

### Round-trip test: pushed identity missing from `added_after` results (2026-11-14, Phase 1)
- **Cause:** not a bug. The identity and the TLP marking have fixed ids, so from the second run on, the server already holds that exact version and its date_added stays the old one.
- **Fix:** the test checks the full collection for every id, and checks `added_after` only for objects that get fresh ids each run.

### MITRE TAXII returns HTTP 429 (2026-11-14, Phase 1)
- **Symptom:** `hexbrief taxii count` against Enterprise ATT&CK got 429 on the first request, retried 4 times (~4 minutes), then gave up with `TaxiiRetryError`.
- **Cause:** MITRE rate-limits per client. Earlier test calls had used up the allowance, and the server sends no `Retry-After` header.
- **Fix:** wait and retry later. ATT&CK changes about twice a year, so later phases cache it locally instead of pulling it daily.

### PowerShell 5.1 mangles UTF-8 docs (2026-11-14, Phase 1)
- **Symptom:** an em dash became `â€”` after a `Get-Content | Set-Content` edit.
- **Cause:** Windows PowerShell 5.1 reads UTF-8 files without a BOM as ANSI.
- **Fix:** edit text files with an editor, or with `[IO.File]::ReadAllText/WriteAllLines` and an explicit `UTF8Encoding($false)`.

### MISP nginx exits: "BASE_URL starts with https://, but SSL certificate is NOT present" (2026-11-14, Phase 2)
- **Cause:** misp-docker expects `ssl/cert.pem` and `ssl/key.pem` when BASE_URL is https.
- **Fix:** `misp-up.ps1` creates a private lab CA and a server cert for 127.0.0.1 once (`docker/misp/make-cert.sh`) and discards the CA key. Clients trust `ca.pem`, so TLS verification stays on. Python 3.13's strict X.509 checks pass because the CA has proper `basicConstraints`/`keyUsage`.
- **Note:** `curl.exe --cacert` on Windows (schannel) ignores the file. Test with Python/httpx instead.

### `misp-up.ps1`: "dependency misp-modules/misp-core failed to start: unhealthy" (2026-11-15, Phase 2)
- **Cause:** on Windows, misp-core re-syncs its files into the bind mount on **every** start, which takes ~7 minutes. Upstream healthchecks give up after ~11 s (modules) and ~75 s (core), and Compose aborts while the containers keep starting.
- **Fix:** `misp-up.ps1` re-runs `docker compose up -d` (idempotent) every 30 s for up to 20 minutes.
- **Gotcha:** `docker compose ... 2>&1` under `$ErrorActionPreference='Stop'` in PS 5.1 turns compose's stderr warnings into terminating errors. Don't redirect stderr there.

### MISP collector returned only 974 attributes (2026-11-15, Phase 2)
- **Symptom:** `hexbrief misp recent` reported 974 attributes while the DB held 615k, all inside the window.
- **Cause:** with `enforceWarninglist`, MISP filters attributes **after** paging. Page 1 (`limit=1000`) came back with 974 rows, and the "short page = last page" rule stopped the loop. Probe: `limit=5000` returned 4,760 rows with the filter, 5,000 without, and 240 rows had `warnings`.
- **Fix:** request `includeWarninglistHits=True`, keep every row, and flag hits (`MispWindow.warninglist_hits`) so scoring can subtract them. There is a regression test for it.
- **Lesson:** any server-side filter applied after pagination breaks "short page = done".

### MISP would reset the admin password on every start (2026-11-15, Phase 2)
- **Found while reading upstream code:** `core/files/configure_misp.sh` → `init_user` runs `cake User change_pw "$ADMIN_EMAIL" "$ADMIN_PASSWORD"` on **every** container start whenever `ADMIN_PASSWORD` is set.
- **Effect:** the owner's new password would quietly revert to the generated one at the next `misp-up.ps1`.
- **Fix:** after the first login, the `ADMIN_PASSWORD` line is removed from `docker/misp/.env.misp` (that path logs "setting admin password skipped"). The template says so too.

### OpenCTI LTS: "LTS_REQUIRED_ACTIVATION: You must activate your LTS license" (2026-11-15, Phase 3)
- **Symptom:** the platform container reported healthy, but every GraphQL call (pycti, every connector) failed. Connectors exited with "OpenCTI API is not reachable".
- **Cause:** the `-lts` images are licensed: the API is blocked until an LTS license is activated.
- **Fix:** switched to the community release `7.261109.3` (ADR-004). No license is needed.

### OpenCTI connectors exit at start: "OpenCTI API is not reachable" (2026-11-15, Phase 3)
- **Cause:** the health endpoint passes slightly before the API accepts connector registrations.
- **Fix:** connectors use `restart: "on-failure:20"` (bounded), so they retry until the platform is ready.

### ThreatFox / URLhaus connectors: HTTP 410 Gone (2026-11-15, Phase 3)
- **Symptom:** both connectors logged errors and imported nothing.
- **Cause:** abuse.ch retired the anonymous CSV exports (`/export/csv/recent/`, `/downloads/csv_recent/` → 410). The APIs still work, but they require the free Auth-Key.
- **Fix:** removed those two connectors. `collectors/abusech.py` + `scripts/abusech_import.py` use the APIs, with the Auth-Key sent as a header.

### OpenCTI TAXII2 connector can't reach medallion: "127.0.0.1:5000 … connection refused" (2026-11-15, Phase 3)
- **Cause:** medallion's discovery listed *absolute* API roots (`http://127.0.0.1:5000/hexbrief/`). Inside a container, 127.0.0.1 is the container itself.
- **Fix:** `docker/taxii/data.json` lists **relative** roots (`/hexbrief/`), so every client resolves them against the URL it used. That's `host.docker.internal` for the connector and 127.0.0.1 for us. Our own client already handled relative roots.

### abuse.ch import: FORBIDDEN_ACCESS with the importer token (2026-11-15, Phase 3)
- **Cause:** the bundle contains the TLP:CLEAR `marking-definition`. Creating markings needs `SETTINGS_SETMARKINGS`, which the least-privilege importer intentionally lacks.
- **Fix:** strip `marking-definition` objects before import. OpenCTI already has TLP 2.0 markings with the same OASIS ids, so `object_marking_refs` still resolve.

### First LLM call: Ollama HTTP 500 (2026-11-15, Phase 5)
- **Symptom:** the first `/api/chat` of a run returned 500 after ~30 s. The retries succeeded.
- **Cause:** a cold model load next to a running OpenCTI (RAM pressure). Ollama answers 500 while it is still loading.
- **Fix:** the writer waits 10 s and retries once on 5xx before counting a failed attempt. The engine's validator retries cover the rest.

### OpenCTI collector: `KeyError: 'id'` / `'list' object has no attribute 'get'` (2026-11-15, Phase 5)
- **Cause:** pycti post-processes results. It needs `id` inside `createdBy`/`objectMarking`/`objectLabel`/`externalReferences` when you pass `customAttributes`, and it flattens `{edges: [{node}]}` into plain lists.
- **Fix:** request those ids, and normalize both shapes with `normalize._nodes()`.

### Everything looked like news: 1,797 KEV vulnerabilities "updated today" (2026-11-15, Phase 5)
- **Cause:** the KEV connector re-touches the whole catalogue, so `updated_at` says nothing about news.
- **Fix:** OpenCTI vulnerabilities are not standalone findings. New KEV entries come from the direct KEV collector (`dateAdded`), and the catalogue is used as a cross-check (`exploited`).

## Template

### <short error title> (YYYY-MM-DD, Phase N)
- **Symptom:** what we saw (relevant log lines, secrets redacted)
- **Cause:** the root cause
- **Fix:** what changed, as a command or file diff
- **Prevention:** how to avoid it next time

---

### Docker containers ignore `vm.max_map_count` from .wslconfig (2026-11-14, Phase 0)
- **Symptom:** after adding `kernelCommandLine = "sysctl.vm.max_map_count=1048575"` under `[wsl2]` and running `wsl --shutdown`, `/proc/cmdline` showed the argument and the kali distro saw the new value. But `docker run --rm alpine sysctl vm.max_map_count` still returned `262144`.
- **Cause:** Docker Desktop's own VM setup sets `vm.max_map_count = 262144` after boot, which overrides the kernel command line value for containers.
- **Fix:** set the value at runtime from a privileged container: `docker run --rm --privileged alpine sysctl -w vm.max_map_count=1048575`. Verified: containers then read `1048575`. The setting resets whenever Docker Desktop restarts, so `scripts/up.ps1` (Phase 3) will run this before starting OpenSearch.
- **Prevention:** always check the value from inside a container, not from a WSL distro. 262144 is Elastic's minimum, so OpenSearch still starts if the step is missed. 1048575 is OpenCTI's documented value.
