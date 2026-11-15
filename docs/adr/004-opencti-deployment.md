# ADR-004: OpenCTI deployment, version and connectors

- **Status:** Accepted
- **Date:** 2026-11-15

## Context

OpenCTI is the main store and the STIX 2.1 knowledge graph. The laptop runs the Standard path (ADR-001): a 14 GB WSL cap, about 6–8 GB free when MISP is down, and port 8080 is taken by other local work. Upstream's `OpenCTI-Platform/docker` compose now bundles XTM One, Postgres, an XTM composer with the Docker socket mounted, and unpinned `latest` tags.

## Decision

1. **Version: community release `7.261109.3`** (latest stable patch, 2026-11). Platform, worker and every connector use the **same tag**, as OpenCTI requires. pycti is pinned to `7.261109.3`.
   - *Changed from the owner's LTS pick (`7.260811.0-lts.2`) on 2026-11-15.* The LTS images refused every API call with `LTS_REQUIRED_ACTIVATION: You must activate your LTS license`, so the LTS line needs a paid Filigran license. The project rule is free/open-source only, and Enterprise-only features are out of scope, so the community release is used. Upgrading means bumping the tags as each patch ships.
2. **Own trimmed compose** (`docker/opencti/compose.yml`): Redis 8.10.1, Elasticsearch 8.19.21, Silo (maintained MinIO build) `RELEASE.2026-11-12`, RabbitMQ 4.3.7, platform and 1 worker. There is no XTM One/composer, so no Docker socket is handed to any container.
3. **Network:** UI/API on **127.0.0.1:8088** only. Elasticsearch, MinIO, RabbitMQ and Redis are not published at all, so ES security is off *inside* the private compose network.
4. **Lab sizing:** ES heap 2 GB (container limit 3 GB), platform heap 3 GB (limit 4 GB), 1 worker, and connectors at 256 MB each. `restart: "no"`, because the stack runs on demand (`opencti-up.ps1` / `opencti-down.ps1`). MISP is stopped first unless `-WithMisp` is given. The `vm.max_map_count` runtime fix runs on every start (TROUBLESHOOTING).
5. **Secrets** (admin password/token, encryption key, health key, MinIO, RabbitMQ, connector UUIDs) are generated into `docker/opencti/.env.opencti` (git-ignored). Feed keys come from the repo `.env`. Telemetry is off.
6. **Connectors:**
   - MITRE ATT&CK, Enterprise only, every 7 days.
   - CISA KEV, daily, TLP:CLEAR.
   - AlienVault OTX, every 6 h; pulses from 2026-11-01 only, so the first run doesn't pull years of data.
   - **ThreatFox + URLhaus: not via the official connectors.** Those read abuse.ch's anonymous CSV exports, which abuse.ch retired (HTTP **410 Gone**, checked 2026-11-15). HexBrief's own `collectors/abusech.py` calls the authenticated APIs with the free Auth-Key **in a header**, converts the results to a validated, deterministic TLP:CLEAR STIX bundle, and `scripts/abusech_import.py` imports it (first run: 1,732 indicators, 56 malware families). Phase 7 runs it daily.
   - MISP connector (profile `misp`, on demand) pulls from the lab MISP **with TLS verified** against the lab CA, mounted read-only. The MISP cert now includes `host.docker.internal` in its SANs.
   - TAXII2 connector (profile `taxii`, on demand) pulls from our medallion to demonstrate TAXII *in*.
7. **Dependency conflict:** pycti 7.26xx pins `requests<2.34`, while PyMISP ≥2.5.34.2 needs `requests>=2.34.2`. PyMISP is pinned to **2.5.34.1** (newest compatible, still the 2.5 line for MISP 2.5.51). `pip check` is clean.

8. **Least privilege for our own clients** (from the security review): the brief engine uses `automation@hexbrief.lab` (role *HexBrief reader*: KNOWLEDGE + API token + TAXII read). The abuse.ch importer uses `importer@hexbrief.lab` (create/update knowledge only, **group max confidence 50**, so it cannot overwrite higher-confidence data). Both tokens last 365 days, are minted by their owners and are stored in git-ignored env files. The admin token is used only by `opencti_setup.py`. External references from feeds are kept only if they are plain `http(s)` URLs with a host.

## Consequences

- The first boot builds the ES indices and runs migrations, which takes several minutes. `opencti-up.ps1` retries `compose up` for up to 25 minutes.
- Running OpenCTI and MISP together exceeds the RAM budget, so the MISP→OpenCTI sync is a deliberate, occasional run (`misp-up.ps1`, then `opencti-up.ps1 -WithMisp`).
- On each OpenCTI patch release, bump every image tag (the compose file uses one tag) and pycti together.
