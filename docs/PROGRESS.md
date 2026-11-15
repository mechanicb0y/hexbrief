# Progress

_Any new session reads this first._

## Mode
**Autonomy mode** (owner's standing orders, 2026-11-15, until v1.0.0). Decide, record in one line, keep going. Report once per phase. Merge own PRs when green and reviewed. Stop only for owner-only actions.

## Current phase
**Phase 8 — Quality + demo** (branch `phase-8-demo`), finishing. Next: Phase 9 portfolio launch (v1.0.0).

## Decisions log (Phase 8)
- `hexbrief demo` uses recorded TLP:CLEAR findings + a recorded narrative shipped in the package, and runs the recorded text through the same validator (no keys, no Docker; `--llm` writes it live).
- Engine fix after the daily dry run fell back to facts-only: keep the best faithful answer across retries, completeness requires only the top lens finding, `num_ctx` 12288.
- HTML brief redesigned around the TLP strip (official colours, top and bottom, print-safe). README rewritten demo-first; `docs/architecture.md` + `docs/sample-brief.md` added.

## Decisions log (Phase 7)
- Task Scheduler (user task, 07:00, catch-up, wake) via `scripts/install-schedule.ps1`, which **the owner runs once** (Windows setting). ADR-006.
- Daily job order: MISP session → snapshot → MISP down → OpenCTI + medallion → abuse.ch import → brief + publish → push `site/` only from clean `main` → stacks down → Sunday backup.
- pip-audit: 4 pycti-pinned transitive CVEs ignored with reasons (ADR-006). mypy is not a CI gate yet.
- Issue #2 fixed in `hexbrief doctor` (unclosed quote = malformed).
- "7 days unattended" starts counting from the first scheduled run.

## Decisions log (Phase 6)
- PDF via local headless Edge/Chrome (no extra dependency; strict CSP, throwaway profile).
- Public archive = HTML + MD only (defanged). No public JSON/STIX: machine outputs with real IOCs stay local, in OpenCTI and TAXII.
- Public summaries limited to 240 characters + source link (third-party text).
- Unmarked data fails closed to TLP:AMBER (security review).
- The HTML design pass (frontend-design) is deferred to Phase 8 with the README visuals.
- First public brief: 2026-11-15 (TLP:CLEAR, LLM narrative validated on the first try).

## Decisions log (Phase 5)
- Findings: reports, indicator clusters (by author + name), new KEV entries (direct feed), MISP events (after `fresh_only`). OpenCTI vulnerabilities are not standalone findings (KEV connector re-touches all).
- Scoring weights live in `scoring.py` with written reasons. Broad target lists get 1/3 lens bonus.
- Completeness is best effort (accepted after retries); faithfulness is a hard gate.
- Prompt v2: no unsupported trend/role claims, cite lens findings, no technique names.
- Brief TLP = most restrictive TLP among top findings (unknown → AMBER, fail safe).

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

- 2026-11-15: Phases 3–7 merged (PRs #5–#9). Pages live, CI green, daily dry run OK.
- 2026-11-15: Phase 8: demo mode (fresh clone → brief in ~5 min), HTML redesign, README/architecture.

## Next
- Phase 9 — v1.0.0 tag, CHANGELOG, write-up, LinkedIn draft, resume bullets, 20 interview Q&A.

## Notes for Phase 5
- `publish_timestamp` is when **our** MISP published an event, so a feed fetch makes 2015 events look new. Use the attribute's own timestamp/first_seen (`fresh_only`).
- OpenCTI window uses `updated_at`.

## Owner-only items pending
- Run `scripts\install-schedule.ps1` once (Task Scheduler). The "7 days unattended" count starts at the first scheduled run.
- (Autonomy mode section added to CLAUDE.md by the owner, 2026-11-15. ACT containers were stopped by the owner's own `docker stop`; leave them.)

## Blockers
- None.
