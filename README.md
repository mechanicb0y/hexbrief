# HexBrief

> A self-updating threat-intel brief: public feeds in over STIX/TAXII, correlated in MISP and OpenCTI, written up each morning by a **local** LLM, and fact-checked so it never invents an indicator.

**Status:** Phase 6 (publish): briefs go to PDF, OpenCTI/TAXII and a public TLP:CLEAR archive. See [docs/PROGRESS.md](docs/PROGRESS.md).

<!-- Demo GIF and link to today's sample brief go here (Phase 8). -->

## How it works

1. Free feeds (MITRE ATT&CK over TAXII 2.1, CISA KEV, abuse.ch, AlienVault OTX, CIRCL OSINT) flow into MISP and OpenCTI.
2. Every day at 07:00 MYT the brief engine reads the last 24 hours from both stores.
3. Findings are deduplicated and ranked by transparent rules (not AI).
4. A local model (Ollama) writes the narrative and cites findings by ID; a validator rejects any IP, domain, hash, CVE or ATT&CK ID that isn't in the source data.
5. The brief is published as Markdown, HTML, PDF, JSON and a STIX 2.1 Report over TAXII 2.1, and TLP:CLEAR briefs go to a public archive.

<!-- Architecture diagram (Phase 8). -->

## Quickstart

_Coming in Phase 8: `hexbrief demo` builds a brief from recorded data with no API keys and no MISP/OpenCTI._

## STIX/TAXII in and out

`stixkit` is a small STIX 2.1 / TAXII 2.1 toolkit ([ADR-002](docs/adr/002-taxii-tooling.md)):

- **In:** a thin TAXII 2.1 client on httpx. It follows pagination, supports `added_after` and `limit`, retries 429/5xx with backoff, raises typed errors and never logs credentials.
- **Out:** STIX 2.1 bundles built with `stix2`, marked with the official OASIS **TLP 2.0** markings, checked by `stix2-validator`, and pushed to a lab TAXII 2.1 server (medallion, bound to 127.0.0.1).

```powershell
pip install -e ".[dev]"
hexbrief taxii collections                        # MITRE ATT&CK TAXII 2.1 server
hexbrief stix demo-bundle --out demo-bundle.json  # indicator -indicates-> malware, TLP:CLEAR
scripts\gen-secrets.ps1; scripts\taxii-up.ps1     # local TAXII server on 127.0.0.1:5000
hexbrief taxii push demo-bundle.json http://127.0.0.1:5000/hexbrief/ <collection-id>
pytest                                            # unit + round-trip tests
```

## MISP (lab store)

Official `MISP/misp-docker` pinned to MISP v2.5.51 ([ADR-003](docs/adr/003-misp-deployment.md)). It runs **on demand**, HTTPS on 127.0.0.1:8443 only, with generated secrets and a private lab CA so TLS stays verified.

```powershell
scripts\misp-up.ps1                       # start (first boot ~7 min on Windows)
python scripts\misp_feeds.py fetch        # CIRCL OSINT + Botvrij (no abuse.ch feeds in MISP)
hexbrief misp recent --hours 24           # counts only: events, attribute types, warninglist hits
hexbrief misp stix 2 --out event.json     # one event as a validated STIX 2.1 bundle
scripts\misp-down.ps1                     # stop; data is kept
```

The collector uses a **read-only** MISP user. Warninglist hits are flagged for scoring, not silently dropped.

## OpenCTI (knowledge graph)

OpenCTI community `7.261109.3` in a trimmed, pinned compose ([ADR-004](docs/adr/004-opencti-deployment.md)). The UI is on 127.0.0.1:8088 only, and backing services are not published. Connectors: MITRE ATT&CK, CISA KEV and AlienVault OTX, plus MISP and TAXII2 on demand. abuse.ch ThreatFox + URLhaus come in through HexBrief's own API importer, because abuse.ch retired the CSV exports the official connectors use.

```powershell
scripts\opencti-up.ps1                 # stops MISP first; -WithMisp / -WithTaxii add those connectors
python scripts\opencti_setup.py        # once: label, `daily-briefs` TAXII collection, read-only token
python scripts\abusech_import.py       # ThreatFox + URLhaus via API (Auth-Key in a header)
hexbrief opencti recent --hours 24     # counts by type and author (read-only user)
scripts\opencti-down.ps1               # stop; data is kept
```

## How the brief stays truthful

- The narrative is written by a **local** model (`qwen3.5:4b` via Ollama, [ADR-005](docs/adr/005-llm-model.md)) with JSON-schema structured output and temperature 0.1. It only sees ranked findings and cites them as `[F#]`.
- `hexbrief.validate` is a hard gate. It refangs the text, extracts every IP (v4/v6), domain, URL, hash (MD5â€“SHA-512), CVE and ATT&CK ID, and rejects anything not present in the input. Planted fakes are covered by tests.
- On failure the engine retries twice with the errors **and the rejected answer** fed back, then tries the fallback model, then publishes a **facts-only** brief. Unchecked text is never published.
- A completeness check (top-3 findings covered; education/Malaysia/ASEAN findings cited in the watch section) catches omissions the faithfulness check can't see.

## Publish

`hexbrief run --push --pages [--notify]` does everything in one go:
- `brief.pdf` printed from the self-contained HTML by a local headless Edge/Chrome (strict CSP, no network);
- the STIX 2.1 Report goes into **OpenCTI** (least-privilege importer token, label `hexbrief`), so OpenCTI's own TAXII 2.1 collection **`daily-briefs`** serves it, and into the lab **medallion** collection;
- the **TLP:CLEAR public view** goes to `site/` for GitHub Pages. Non-CLEAR findings are dropped, and if any were in the top 8 the AI narrative is replaced with facts-only text. Third-party text is quoted briefly with source links, and every indicator is defanged;
- an optional Discord/Telegram post of the public BLUF (`WEBHOOK_URL`, off by default).

`hexbrief republish YYYY-MM-DD` re-renders a past day's public page from `brief.json` without a new run.

## Run it

```powershell
scripts\opencti-up.ps1          # data source (MISP optional: scripts\misp-up.ps1)
hexbrief run                    # today's brief → out\YYYY-MM-DD\brief.{md,html,json,stix.json}
hexbrief run --no-llm           # facts-only, no model
```

Pipeline: collect (OpenCTI, CISA KEV, MISP) → normalize to findings → KEV cross-check → dedupe (shared CVE/IOC) → rule-based score ([`scoring.py`](src/hexbrief/scoring.py)) → top 8 to the local LLM → validate → render (defanged for humans, real values in JSON/STIX) → run log in `runs/`. One failing source never stops the brief.
- Benchmark: [`docs/benchmarks/llm-2026-11-15.md`](docs/benchmarks/llm-2026-11-15.md).

## Security and ethics

- Every service binds to `127.0.0.1`; only the GitHub Pages archive is public.
- Only TLP:CLEAR content is published. TLP:GREEN and above stays local.
- Indicators are handled as text only: never visited, resolved or downloaded. They are defanged in human-readable outputs.
- Intel goes only to a local LLM, never to a cloud AI API.
- Secrets live in a git-ignored `.env`; gitleaks runs on every commit and in CI.

## Design decisions

- [ADR-001: Hardware path and lab sizing](docs/adr/001-hardware-path.md)
- [ADR-002: TAXII tooling (own client, pinned medallion)](docs/adr/002-taxii-tooling.md)
- [ADR-003: MISP deployment, PyMISP pin and feeds](docs/adr/003-misp-deployment.md)
- [ADR-004: OpenCTI deployment, version and connectors](docs/adr/004-opencti-deployment.md)
- [ADR-005: Local LLM for the brief narrative](docs/adr/005-llm-model.md)

## License

[Apache-2.0](LICENSE)
