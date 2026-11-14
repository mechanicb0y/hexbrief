# ADR-003: MISP deployment, client version and feeds

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

MISP is the second store, after OpenCTI. On the Standard path (ADR-001) it must not compete with OpenCTI for RAM; about 6 GB of host RAM is free with the current workload. Upstream ships a Docker setup (`MISP/misp-docker`) that publishes ports 80/443 on all interfaces and uses default secrets (`example`, `redispassword`, `supervisor`).

## Decision

1. **Upstream, pinned:** `MISP/misp-docker` at commit `2efbdce` (2026-11-11), with images `misp-core:v2.5.51`, `misp-nginx:v2.5.51` and `misp-modules:v3.1.4`, the latest at build time. `scripts/misp-up.ps1` checks the commit out into `docker/misp/upstream/` (git-ignored). Only our override and template live in the repo.
2. **Override** (`docker/misp/compose.override.yml`):
   - HTTPS on **127.0.0.1:8443 only**. Port 80 belongs to Windows HTTP.sys, 8080 to other local work and 5000 to medallion.
   - No mail relay.
   - `restart: "no"`, because MISP runs **on demand** (`misp-up.ps1` / `misp-down.ps1`) and is never left running alongside a heavy OpenCTI import.
   - Lab sizing: InnoDB buffer 512 MB, PHP 1 GB, 3 FPM children.
3. **Secrets:** every password and key is generated into `docker/misp/.env.misp` (git-ignored) by `gen-secrets.ps1`. `DISABLE_PRINTING_PLAINTEXT_CREDENTIALS=true` keeps them out of container logs. The owner does the first login and changes the admin password.
4. **PyMISP `==2.5.34.4`, not 3.0.0.** PyMISP 3.0.0 (2026-11-06) is a new major aligned with **MISP 3.0** (STIX 1 export dropped, MISP 3.0 analyst-data types). Its changelog does not state support for MISP 2.5.x servers, so we stay on the 2.5 line (latest 2.5.34.4, 2026-09-17) to match MISP 2.5.51. Revisit when the server moves to MISP 3.
5. **Feeds:** CIRCL OSINT and Botvrij.eu only. **Cache first**, check the event count and DB size, then fetch. **No abuse.ch MISP feeds:** they embed the Auth-Key in the feed URL stored inside MISP. abuse.ch comes in through OpenCTI connectors (Phase 3).
6. **Collector:** `hexbrief.collectors.misp` is read-only. It searches by `publish_timestamp` window, defaults to `to_ids` only, and uses `enforceWarninglist` so known-benign values never reach scoring. STIX export is done server-side (`returnFormat=stix2`, `stix-version=2.1`).

## Consequences

- The first boot is slow (around 5+ minutes) because MISP copies its files into Windows bind mounts.
- MISP data survives `misp-down.ps1` (named volumes are kept). Deleting it is a separate, deliberate step.
- The self-signed TLS cert means clients must be pointed at MISP's cert file, not run with verification disabled.
- Moving to MISP 3 later means bumping the image tags and PyMISP together, under a new ADR.
