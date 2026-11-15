# ADR-006: Daily automation, operations and CI

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

The brief must run every day at 07:00 MYT unattended, with the Standard path's RAM limit (MISP and OpenCTI never together), on a Windows laptop where Docker Desktop and the owner's git credentials live in the user session.

## Decision

1. **Scheduler: Windows Task Scheduler** (`scripts/install-schedule.ps1`), not a scheduler container. A container can't start Docker Desktop, run the host's Ollama on the GPU, or push with the owner's Git Credential Manager. The task runs as the current user at 07:00 with *run when available* (catches up after sleep/off), *wake to run*, no overlapping instances, and a 3 h limit. Installing it changes a Windows setting, so **the owner runs it once**.
2. **`scripts/daily.ps1`** is idempotent and retries each step (3 tries, 30/60 s back-off):
   1. Docker up, then `hexbrief doctor --no-services` (fail fast).
   2. MISP session: `misp-up` → feed fetch → `hexbrief misp snapshot` (fresh findings saved to `runs/misp-<day>.json`) → `misp-down`. MISP is optional (degraded, not failed).
   3. OpenCTI session: `opencti-up` + medallion → abuse.ch import → `hexbrief run --push --pages`. The MISP collector falls back to the day's snapshot.
   4. Commit and push `site/` **only from a clean `main`**, never from a feature branch.
   5. Stacks down. Backup on Sundays.
   - Re-runs overwrite that day's outputs and update the same STIX Report (deterministic id). The transcript goes to `runs/daily-<day>.log` and the structured run log to `runs/<day>.json`.
3. **`hexbrief doctor`** checks keys (names only, never values; unclosed quotes are reported as malformed, fixing issue #2), Docker, OpenCTI, MISP, medallion, Ollama + model, disk and the last run.
4. **Backups:** `scripts/backup.ps1` writes tar.gz of the `hexbrief-*` volumes (mounted read-only) to `backups/<date>/` while the stacks are down, and keeps the newest 4.
5. **CI (GitHub Actions):** ruff, pytest with medallion as a container (the TAXII round trip runs in CI with a random masked password), bandit, pip-audit and gitleaks. Actions are pinned by SHA, Dependabot runs weekly (pip, actions, docker), and no live keys or feeds are used.
   - **pip-audit ignores 4 IDs**, all transitive pins of pycti 7.261109.3: `opentelemetry-api~=1.35` (CVE-2026-114603, CVE-2026-126360) and `setuptools~=82.0` (PYSEC-2026-3447, GHSA-xmj3-9gf7-h52w). Upgrading them breaks pycti's declared requirements. HexBrief doesn't export pycti telemetry, and setuptools isn't used at runtime. Remove each ignore when pycti ships the fixed versions; Dependabot will surface it.
6. **mypy is not a CI gate yet.** It was added to the toolchain list but the codebase hasn't been typed to a passing baseline. This is listed as a known gap.

## Consequences

- The PC must be on (or able to wake) and logged in around 07:00. A missed run is caught up when the session is available.
- A degraded day (MISP or a feed down) still produces a brief. The run log says what was missing.
- The "7 days unattended" done-criterion is measured from the task's first scheduled run after the owner installs it.
