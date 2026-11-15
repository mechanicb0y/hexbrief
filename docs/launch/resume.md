# Resume bullets

The rule from the master prompt is real numbers from the run logs, never invented. Numbers marked ✅ are measured now. Brackets fill in after the first 7 scheduled days: run `python scripts/run_stats.py` and copy the numbers it prints.

- Built an automated CTI pipeline that ingests **7** open-source feeds into MISP and OpenCTI, normalized to STIX 2.1. The feeds are MITRE ATT&CK via TAXII 2.1, CISA KEV, abuse.ch ThreatFox and URLhaus, AlienVault OTX, and the CIRCL and Botvrij MISP feeds. Each day's run correlates and dedupes about **160 findings into 143** ✅ (first scheduled day), using rule-based scoring with written reasons.
- Engineered a local-LLM daily intel brief on a 4 GB laptop GPU. Its validation layer blocks any IP, domain, URL, hash, CVE or ATT&CK ID not present in the source data, with **0 invented facts in 9/9 benchmark runs across 3 models** ✅. **[X]%** of drafts passed on the first attempt over **[D]** days.
- Published briefs as STIX 2.1 Reports over a TAXII 2.1 collection and a TLP:CLEAR GitHub Pages archive. Unmarked data fails closed to TLP:AMBER, and indicators are defanged in all human outputs. The project ships with **182 automated tests** ✅, plus CI with gitleaks secret scanning, bandit, pip-audit, SHA-pinned actions and Dependabot.

Short version for a skills line: STIX 2.1 / TAXII 2.1, MISP, OpenCTI, TLP 2.0, Python, Docker, Ollama (local LLM), GitHub Actions.
