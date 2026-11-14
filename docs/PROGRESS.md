# Progress

_Any new session reads this first._

## Current phase
**Phase 2 — MISP** (branch `phase-2-misp`, pushed, no PR yet). **Paused 2026-11-15 06:30 MYT** at a safe point.

## Resume here (next session)
1. Start Docker Desktop, then `scripts\misp-up.ps1`. Data is kept in the `hexbrief-misp_*` volumes and the first boot is already done, so it starts much faster this time.
2. **Owner:** if not already done, log in at https://127.0.0.1:8443 as `admin@hexbrief.lab` (password = `ADMIN_PASSWORD` in `docker\misp\.env.misp`) and change the password.
3. **The feed fetch was interrupted.** At the stop point the DB was 900 MB with 1,376 events and 202,660 attributes, so CIRCL OSINT + Botvrij were partly loaded. Re-run `.venv\Scripts\python.exe scripts\misp_feeds.py fetch`. MISP skips events it already has, so it resumes. Watch the DB size and stop at 5 GB.
4. Then: schedule the daily feed fetch, update the docs (README MISP section, troubleshooting, learning log), run the pre-push checks, the owner's task + 3 questions, checkpoint, PR.
5. When done for the day: `scripts\misp-down.ps1` (never `down -v`).

## Done
- 2026-11-14: Hardware check done (owner ran it). Standard path chosen, see [ADR-001](adr/001-hardware-path.md).
- 2026-11-14: Repo skeleton, Docker disk on D:, `.wslconfig` (14 GB/8 CPU; `vm.max_map_count` runtime fix, see TROUBLESHOOTING), Ollama models on D: (old C: copy kept until the owner says), gh + gitleaks + pre-commit.
- 2026-11-14: **Phase 0 merged** (PR #1). Issue #2 open (check-env unclosed quote, fix in Phase 7).
- 2026-11-14: **Phase 1 merged** (PR #3): stixkit (httpx TAXII 2.1 client, TLP 2.0 markings, validated bundles), medallion on 127.0.0.1:5000, owner's `summarize_attack()`. Enterprise ATT&CK cached in `data/attack/` (26,699 objects).
- 2026-11-14: Phase 2 so far (ADR-003):
  - misp-docker pinned to `2efbdce`, images MISP v2.5.51 / modules v3.1.4, HTTPS on 127.0.0.1:8443 only, generated secrets in `docker\misp\.env.misp`, `misp-up.ps1` / `misp-down.ps1`.
  - Lab CA + server cert (`docker\misp\upstream\ssl\ca.pem`), so TLS is verified. The CA key was discarded.
  - PyMISP pinned to 2.5.34.4 (3.0.0 targets MISP 3.0).
  - 225 warninglists enabled; CIRCL OSINT + Botvrij cached, fetch partly done.
  - Read-only `automation@hexbrief.lab`; its key is in `.env` (`MISP_API_KEY`, never printed).
  - `collectors/misp.py` + `hexbrief misp recent|stix`; 50 tests green.

## Notes for Phase 5
- `publish_timestamp` is when **our** MISP published an event, so a feed fetch makes 2015 events look new. The daily window must also check the source timestamp/date.

## Blockers
- None.
