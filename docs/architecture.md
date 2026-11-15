# Architecture

```mermaid
flowchart LR
  subgraph Feeds["Public feeds (TLP:CLEAR)"]
    ATT["MITRE ATT&CK<br/>TAXII 2.1"]
    KEV["CISA KEV"]
    OTX["AlienVault OTX"]
    ABU["abuse.ch<br/>ThreatFox + URLhaus API"]
    CIRCL["CIRCL OSINT<br/>Botvrij (MISP feeds)"]
  end

  subgraph Lab["Lab on 127.0.0.1 (Docker)"]
    MISP["MISP 2.5<br/>events · warninglists"]
    OCTI["OpenCTI 7<br/>STIX 2.1 knowledge graph"]
    MED["medallion<br/>TAXII 2.1 server"]
    OLL["Ollama<br/>qwen3.5:4b (local)"]
  end

  subgraph Engine["hexbrief run"]
    COL["collect<br/>OpenCTI · KEV · MISP snapshot"]
    NOR["normalize + dedupe<br/>Findings with provenance"]
    SCO["rule-based scoring<br/>KEV · exploited · lens"]
    LLM["LLM writes prose<br/>cites [F#] only"]
    VAL{"validator<br/>nothing invented"}
    REN["render<br/>defanged for humans"]
  end

  subgraph Out["Outputs"]
    FILES["brief.md / html / pdf / json"]
    STIX["STIX 2.1 Report"]
    PAGES["GitHub Pages<br/>TLP:CLEAR archive"]
  end

  ATT --> OCTI
  KEV --> OCTI
  OTX --> OCTI
  ABU -->|"importer token,<br/>confidence ≤ 50"| OCTI
  CIRCL --> MISP
  MISP -->|"connector (on demand)"| OCTI
  KEV --> COL
  OCTI -->|"read-only token"| COL
  MISP -->|"snapshot"| COL
  COL --> NOR --> SCO --> LLM
  OLL -.-> LLM
  LLM --> VAL
  VAL -->|"pass"| REN
  VAL -->|"fail ×3"| FACTS["facts-only brief"] --> REN
  REN --> FILES
  REN --> STIX
  STIX -->|"push"| OCTI
  STIX -->|"push"| MED
  OCTI -->|"TAXII collection<br/>daily-briefs"| CONS["TAXII consumers"]
  REN -->|"public view<br/>CLEAR only"| PAGES
```

## In words

1. Feeds flow into MISP (CIRCL OSINT, Botvrij) and OpenCTI (MITRE ATT&CK over TAXII 2.1, CISA KEV, AlienVault OTX, and abuse.ch via HexBrief's own API importer).
2. At 07:00 MYT, `scripts/daily.ps1` runs MISP alone and snapshots its fresh findings, then OpenCTI, then `hexbrief run`. The two never run at the same time, because they don't fit in RAM together.
3. The engine normalizes everything into findings that keep their sources, deduplicates them on shared CVEs and IOCs, and ranks them with written rules.
4. The top 8 go to a **local** model, which writes prose that cites `[F#]`. A validator rejects any IP, domain, URL, hash, CVE or ATT&CK ID that isn't in the data. After 3 failed tries the brief is published facts-only.
5. Humans get defanged Markdown, HTML and PDF. Machines get JSON and a STIX 2.1 Report, which is pushed to OpenCTI (served over TAXII as `daily-briefs`) and to medallion. The TLP:CLEAR public view goes to GitHub Pages.
6. Every service binds to 127.0.0.1. Only the Pages site is public.

| Component | Where | ADR |
|---|---|---|
| Hardware path, lab sizing | `.wslconfig`, compose limits | [001](adr/001-hardware-path.md) |
| TAXII client + medallion | `src/hexbrief/stixkit/`, `docker/taxii/` | [002](adr/002-taxii-tooling.md) |
| MISP | `docker/misp/`, `collectors/misp.py` | [003](adr/003-misp-deployment.md) |
| OpenCTI + connectors | `docker/opencti/`, `collectors/opencti.py` | [004](adr/004-opencti-deployment.md) |
| Local LLM | `src/hexbrief/llm/`, `validate.py` | [005](adr/005-llm-model.md) |
| Automation, CI | `scripts/daily.ps1`, `.github/workflows/` | [006](adr/006-automation.md) |
