# ADR-002: TAXII 2.1 tooling: own client on httpx, medallion pinned for the lab

- **Status:** Accepted
- **Date:** 2026-11-14

## Context

The master prompt names four OASIS libraries. Their maintenance status on PyPI and GitHub, checked 2026-11-14:

| Package | Last release | Last commit | Verdict |
|---|---|---|---|
| stix2 | 3.0.2 (Feb 2026) | active | keep |
| stix2-validator | 3.3.2 (Nov 2026) | active | keep |
| taxii2-client | 2.3.0 (Mar 2021) | Jun 2023 | replace |
| medallion (TAXII server) | 3.0.0 (Jul 2020) | Jun 2023 | lab-only, pinned |

## Decision

1. **Write our own thin TAXII 2.1 client** (`src/hexbrief/stixkit/taxii.py`) on httpx, which is maintained. Requirements set by the owner:
   - `Accept: application/taxii+json;version=2.1` on every request
   - follow `more`/`next` pagination; support `added_after` and `limit`. When a server sends `more=true` without `next`, fall back to the `X-TAXII-Date-Added-Last` header.
   - timeouts always set; TLS verification on by default
   - retry with exponential backoff and jitter on 429/5xx, honouring `Retry-After`. Writes (POST) retry only on 429/503, because a 500 may mean the server already stored the data.
   - typed errors (`TaxiiAuthError`, `TaxiiNotFoundError`, `TaxiiRetryError`, `TaxiiProtocolError`). Credentials are never logged, and URLs that embed credentials are rejected.
   - unit tests with respx, a round-trip test against local medallion, and a live smoke test against MITRE that is skipped unless `HEXBRIEF_LIVE=1` (never in CI)
2. **Run medallion from a pinned commit** (`39e76bf`, the last commit, June 2023) in Docker as a **127.0.0.1-only lab server**, using the memory backend, read-only root filesystem, all capabilities dropped and a non-root user. The password comes from `.env` at start-up (`scripts/gen-secrets.ps1`) and is never baked into the image.
3. **Phase 3** may move the public-facing collection to OpenCTI's own TAXII collections. medallion stays as the CI service and test server.

## Consequences

- About 250 lines of client code to own and test. In exchange we have no stale dependency, and the owner learns the protocol rather than a wrapper.
- medallion needs `setuptools<81`, because it still imports `pkg_resources`. It runs Flask's development server, which is acceptable for a localhost lab and never acceptable for exposure.
- Memory backend: a container restart empties the collection. That is fine for tests. Persistent publishing comes in Phase 6.
- **Learned while building:** medallion reuses one session id as `next` for every page. A guard that compares cursors would have broken against it, so the loop guard compares page contents instead.
- MITRE's TAXII server rate-limits with HTTP 429 and sends no `Retry-After` header. Pull ATT&CK rarely (it changes about twice a year), and cache it locally in later phases.
