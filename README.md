# HexBrief

> A self-updating threat-intel brief: public feeds in over STIX/TAXII, correlated in MISP and OpenCTI, written up each morning by a **local** LLM, and fact-checked so it never invents an indicator.

**Status:** Phase 1 (STIX/TAXII toolkit). See [docs/PROGRESS.md](docs/PROGRESS.md).

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

## How the brief stays truthful

_Phase 5._

## Security and ethics

- Every service binds to `127.0.0.1`; only the GitHub Pages archive is public.
- Only TLP:CLEAR content is published. TLP:GREEN and above stays local.
- Indicators are handled as text only: never visited, resolved or downloaded. They are defanged in human-readable outputs.
- Intel goes only to a local LLM, never to a cloud AI API.
- Secrets live in a git-ignored `.env`; gitleaks runs on every commit and in CI.

## Design decisions

- [ADR-001: Hardware path and lab sizing](docs/adr/001-hardware-path.md)
- [ADR-002: TAXII tooling (own client, pinned medallion)](docs/adr/002-taxii-tooling.md)

## License

[Apache-2.0](LICENSE)
