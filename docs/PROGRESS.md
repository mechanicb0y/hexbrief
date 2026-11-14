# Progress

_Any new session reads this first._

## Current phase
**Phase 1 — STIX 2.1 and TAXII 2.1 by hand** (branch `phase-1-stixkit`)

## Done
- 2026-11-14: Hardware check done (owner ran it). Standard path chosen, see [ADR-001](adr/001-hardware-path.md).
- 2026-11-14: Repo skeleton created: LICENSE (Apache-2.0), .gitignore, .gitattributes, .env.example, pyproject.toml, pre-commit config (ruff, gitleaks), README skeleton, CLAUDE.md, docs/.
- 2026-11-14: Phase 0 primer (CTI levels, intelligence lifecycle mapped to HexBrief).
- 2026-11-14: Docker Desktop disk image moved to `D:\DockerData`.
- 2026-11-14: `.wslconfig` applied (14 GB, 8 GB swap, 8 CPUs). The `vm.max_map_count` needs a runtime fix at stack start, see TROUBLESHOOTING.md.
- 2026-11-14: Ollama models on `D:\ollama\models`, set in the Ollama app's Settings → Model location. The app setting overrides the `OLLAMA_MODELS` env var. The old C: copy is kept until the owner says to delete it.
- 2026-11-14: gh CLI (user scope) and gitleaks installed. pre-commit hooks installed in `.venv`. gitleaks over the full history found no leaks.
- 2026-11-14: Public repo `mechanicb0y/hexbrief` created.
- 2026-11-14: OTX and abuse.ch keys in `.env`; `scripts/check-env.ps1` (owner's task) passes, with the inline-comment fix reviewed.
- 2026-11-14: **Phase 0 merged** (PR #1).

- 2026-11-14: Phase 0 re-quiz answered (with help; quiz cold later). ADR-002 accepted. Issue #2 logged (check-env unclosed quote).
- 2026-11-14: stixkit built: httpx TAXII 2.1 client, official TLP 2.0 markings, bundle builder and validator, `hexbrief taxii collections|count|push` and `hexbrief stix demo-bundle`.
- 2026-11-14: medallion (pinned 39e76bf) in Docker on 127.0.0.1:5000, `hexbrief` API root, `daily-briefs` collection. Round-trip test passes; 28 tests green.

- 2026-11-14: Owner's task `summarize_attack()` (87f17a6), 37 tests green. Phase 1 questions answered (with help).
- 2026-11-14: Enterprise ATT&CK pulled once over TAXII 2.1: 26,699 objects in 186 s, cached to `data/attack/` (git-ignored). Live counts: 227 techniques, 479 sub-techniques, 15 tactics, 178 groups, 842 software, 179 revoked/deprecated skipped.

## Next (Phase 1)
- [ ] Review fix in `summarize_attack`: compare `modified` as datetimes, not strings
- [ ] Merge PR #3

## Next phase
Phase 2 — MISP (misp-docker, feeds, warninglists, PyMISP).

## Blockers
- None.
