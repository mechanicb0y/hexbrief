# Progress

_Any new session reads this first._

## Current phase
**Phase 2 — MISP** (branch `phase-2-misp`). Resumed 2026-11-15.

## Next (Phase 2)
- [ ] Owner: log in at https://127.0.0.1:8443 and change the admin password (if not done)
- [ ] Owner's task + 3 questions, checkpoint, PR
- When done for the day: `scripts\misp-down.ps1` (never `down -v`). Start: `scripts\misp-up.ps1` (~7 min on Windows).

## Done
- 2026-11-14: Hardware check done (owner ran it). Standard path chosen, see [ADR-001](adr/001-hardware-path.md).
- 2026-11-14: Repo skeleton, Docker disk on D:, `.wslconfig` (14 GB/8 CPU; `vm.max_map_count` runtime fix, see TROUBLESHOOTING), Ollama models on D: (old C: copy kept until the owner says), gh + gitleaks + pre-commit.
- 2026-11-14: **Phase 0 merged** (PR #1). Issue #2 open (check-env unclosed quote, fix in Phase 7).
- 2026-11-14: **Phase 1 merged** (PR #3): stixkit (httpx TAXII 2.1 client, TLP 2.0 markings, validated bundles), medallion on 127.0.0.1:5000, owner's `summarize_attack()`. Enterprise ATT&CK cached in `data/attack/` (26,699 objects).
- 2026-11-14: Phase 2 so far (ADR-003):
  - misp-docker pinned to `2efbdce`, images MISP v2.5.51 / modules v3.1.4, HTTPS on 127.0.0.1:8443 only, generated secrets in `docker\misp\.env.misp`, `misp-up.ps1` / `misp-down.ps1`.
  - Lab CA + server cert (`docker\misp\upstream\ssl\ca.pem`), so TLS is verified. The CA key was discarded.
  - PyMISP pinned to 2.5.34.4 (3.0.0 targets MISP 3.0).
  - 225 warninglists enabled. CIRCL OSINT + Botvrij fully fetched on 2026-11-15: 2,112 events, 615,190 attributes, DB 1.44 GB (no limit needed). Daily fetch/cache interval set (MISP's scheduler, while MISP runs; Phase 7 starts it daily).
  - The collector now flags warninglist hits instead of using `enforceWarninglist`, which broke paging (see TROUBLESHOOTING).
  - Read-only `automation@hexbrief.lab`; its key is in `.env` (`MISP_API_KEY`, never printed).
  - `collectors/misp.py` + `hexbrief misp recent|stix`; 50 tests green.

## Notes for Phase 5
- `publish_timestamp` is when **our** MISP published an event, so a feed fetch makes 2015 events look new. The daily window must also check the source timestamp/date.

## Blockers
- None.
