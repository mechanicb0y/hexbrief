# Progress

_Any new session reads this first._

## Current phase
**Phase 0 — Prep, hardware path, repo** (branch `phase-0-setup`)

## Done
- 2026-11-14: Hardware check done (owner ran it). Standard path chosen, see [ADR-001](adr/001-hardware-path.md).
- 2026-11-14: Repo skeleton created: LICENSE (Apache-2.0), .gitignore, .gitattributes, .env.example, pyproject.toml, pre-commit config (ruff, gitleaks), README skeleton, CLAUDE.md, docs/.

## Next (Phase 0)
- [ ] Phase 0 primer: CTI types and the intelligence lifecycle mapped to HexBrief
- [ ] Owner OK, then: move Docker Desktop disk image to D:
- [ ] Owner OK, then: set `OLLAMA_MODELS` to a folder on D:
- [ ] Owner OK, then: write `.wslconfig` and the `vm.max_map_count` setting (verified against current OpenCTI docs)
- [ ] Owner OK, then: install gh CLI with winget, or open PRs in the browser
- [ ] Install pre-commit in a venv and run it on all files
- [ ] Create public repo `mechanicb0y/hexbrief`, push `main` + `phase-0-setup`, open the PR
- [ ] Owner: sign up for an AlienVault OTX key and an abuse.ch Auth-Key, and put them in `.env` (never in chat)
- [ ] Your-turn task, 3 interview questions, checkpoint

## Blockers
- None.
