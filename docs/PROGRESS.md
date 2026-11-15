# Progress

_Any new session reads this first._

## Mode
**Autonomy mode** (owner's standing orders, 2026-11-15, until v1.0.0). Decide, record in one line, keep going. Report once per phase. Merge own PRs when green and reviewed. Stop only for owner-only actions.

## Current phase
**Phase 4 — Local LLM** (branch `phase-4-llm`), finishing. Next: Phase 5 brief engine.

## Decisions log (one line each)
- 2026-11-15: OpenCTI version = community `7.261109.3`, not LTS. LTS needs a paid license (ADR-004).
- 2026-11-15: PyMISP pinned to 2.5.34.1 so it shares `requests<2.34` with pycti (ADR-004).
- 2026-11-15: abuse.ch via public *recent* CSV exports in OpenCTI connectors, so no Auth-Key goes into a URL (ADR-004).
- 2026-11-15: The OpenCTI collector uses a dedicated read-only user/token. The admin token is used for setup only.
- 2026-11-15: MISP lab cert re-issued with a `host.docker.internal` SAN so the MISP connector verifies TLS.
- 2026-11-15: OpenCTI dashboard screenshot moved to Phase 8 (README visuals pass) to avoid scripted logins now.
- 2026-11-15: abuse.ch retired its anonymous CSV exports (410), so ThreatFox/URLhaus come in through our own API importer with a least-privilege importer user (confidence ≤ 50).
- 2026-11-15: MISP→OpenCTI connector runs in a deliberate `-WithMisp` session (RAM). First run scheduled with Phase 7's daily job.
- 2026-11-15: LLM = qwen3.5:4b (fallback llama3.2:3b). All 3 candidates were 100% faithful; qwen3.5:4b had the best content (ADR-005, `docs/benchmarks/llm-2026-11-15.md`).
- 2026-11-15: Phase 5 adds a completeness check (validators catch inventions, not omissions) and a prompt v2 rule against unsupported trend claims.
- 2026-11-15: Phase 3 done-criteria met: OpenCTI holds data from 5 sources (MITRE, CISA KEV, AlienVault OTX, abuse.ch, HexBrief via TAXII2/medallion) with ATT&CK links.

## Done
- 2026-11-14: Hardware check, Standard path ([ADR-001](adr/001-hardware-path.md)). Docker disk on D:, `.wslconfig` (14 GB/8 CPU), Ollama models on D: (old C: copy kept until the owner says).
- 2026-11-14: **Phase 0 merged** (PR #1). Issue #2 open (check-env unclosed quote → Phase 7).
- 2026-11-14: **Phase 1 merged** (PR #3): stixkit, medallion on 127.0.0.1:5000, Enterprise ATT&CK cached in `data/attack/`.
- 2026-11-15: **Phase 2 merged** (PR #4): MISP v2.5.51 on 127.0.0.1:8443 (on demand), lab CA, 2,112 feed events / 615k attributes, read-only MISP collector.
- 2026-11-15: Phase 3 so far:
  - Trimmed OpenCTI compose on 127.0.0.1:8088 with generated secrets, `opencti-up.ps1` / `opencti-down.ps1` (ADR-004).
  - Connectors running: MITRE, CISA KEV, OTX, ThreatFox, URLhaus; MISP/TAXII2 run on demand.
  - `scripts/opencti_setup.py`: label `hexbrief`, TAXII collection `daily-briefs`, read-only reader + 365-day token in `.env`.
  - `collectors/opencti.py` + `hexbrief opencti recent`.

## Next
- Phase 4 — local LLM benchmark (Ollama; 4 GB VRAM).

## Notes for Phase 5
- `publish_timestamp` is when **our** MISP published an event, so a feed fetch makes 2015 events look new. Use the attribute's own timestamp/first_seen (`fresh_only`).
- OpenCTI window uses `updated_at`.

## Owner-only items pending
- None. (Autonomy mode section added to CLAUDE.md by the owner, 2026-11-15. ACT containers were stopped by the owner's own `docker stop`; leave them.)

## Blockers
- None.
