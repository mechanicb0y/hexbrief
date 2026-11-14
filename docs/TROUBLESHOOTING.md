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
