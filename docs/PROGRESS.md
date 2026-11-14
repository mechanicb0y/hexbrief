# Progress

_Any new session reads this first._

## Current phase
**Phase 0 — Prep, hardware path, repo** (branch `phase-0-setup`, PR open)

## Done
- 2026-11-14: Hardware check done (owner ran it). Standard path chosen, see [ADR-001](adr/001-hardware-path.md).
- 2026-11-14: Repo skeleton created: LICENSE (Apache-2.0), .gitignore, .gitattributes, .env.example, pyproject.toml, pre-commit config (ruff, gitleaks), README skeleton, CLAUDE.md, docs/.
- 2026-11-14: Phase 0 primer (CTI levels, intelligence lifecycle mapped to HexBrief).
- 2026-11-14: Docker Desktop disk image moved to `D:\DockerData`.
- 2026-11-14: `.wslconfig` applied (14 GB, 8 GB swap, 8 CPUs). The `vm.max_map_count` needs a runtime fix at stack start, see TROUBLESHOOTING.md.
- 2026-11-14: Ollama models on `D:\ollama\models`, set in the Ollama app's Settings → Model location. The app setting overrides the `OLLAMA_MODELS` env var. The old C: copy is kept until the owner says to delete it.
- 2026-11-14: gh CLI (user scope) and gitleaks installed. pre-commit hooks installed in `.venv`. gitleaks over the full history found no leaks.
- 2026-11-14: Public repo `mechanicb0y/hexbrief` created; Phase 0 PR opened.

## Next (Phase 0)
- [ ] Owner: sign up for an AlienVault OTX key and an abuse.ch Auth-Key, and put them in `.env` (never in chat)
- [ ] Your-turn task, 3 interview questions, checkpoint, merge the PR

## Next phase
Phase 1 — STIX 2.1 and TAXII 2.1 by hand (stixkit, medallion).

## Blockers
- None.
