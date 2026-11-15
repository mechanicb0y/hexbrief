# How I built a self-updating threat intel brief with STIX/TAXII, MISP, OpenCTI and a local LLM

Every morning a SOC lead needs one page that answers three questions: what changed overnight, does it touch us, and what should we do first. Public threat intel is plentiful, but it is scattered across feeds and formats, and much of it is noise. HexBrief is my answer. It collects free feeds, correlates them, ranks them with written rules, and has a local language model write the page. A validator then makes sure the model didn't invent a single indicator.

The code is on [GitHub](https://github.com/mechanicb0y/hexbrief), and the public briefs are at [mechanicb0y.github.io/hexbrief](https://mechanicb0y.github.io/hexbrief/). If you have Python, `pip install .` then `hexbrief demo` gives you a full brief in about five minutes, with no keys and no Docker.

## The shape of it

- **Collect.** MITRE ATT&CK comes in over TAXII 2.1, alongside CISA's Known Exploited Vulnerabilities, AlienVault OTX, abuse.ch ThreatFox and URLhaus, and the CIRCL and Botvrij MISP feeds. Everything lands in MISP or OpenCTI as STIX 2.1, on my laptop, bound to 127.0.0.1.
- **Correlate.** The engine pulls the last 24 hours and turns each record into a *finding* that keeps its sources, STIX ids, TLP and confidence. It merges findings that share a CVE or an indicator. On the first scheduled day, 160 findings went in and 143 came out.
- **Rank.** Scoring is deliberately not done by the model. Fixed weights cover CISA KEV listing, evidence of exploitation, recency, independent sources, confidence, and relevance to education, Malaysia and ASEAN. Every score carries its reasons, so an analyst can disagree with a specific rule instead of with a black box.
- **Write.** The top 8 findings go to `qwen3.5:4b` running in Ollama on a 4 GB laptop GPU, with a JSON schema and temperature 0.1. The model writes the bottom line, why each threat matters and what to do, and cites findings as `[F1]`, `[F2]`.
- **Check.** A validator refangs the text and extracts every IPv4, IPv6, domain, URL, hash, CVE and ATT&CK ID. Anything that isn't in the input fails the draft. Failed drafts are retried with the errors and the rejected answer fed back, then the fallback model gets a try, and after that HexBrief publishes a facts-only brief. Text that failed validation is never published.
- **Publish.** Humans get defanged Markdown, HTML and PDF. Machines get JSON and a STIX 2.1 `report`, pushed to OpenCTI (served over TAXII 2.1 as `daily-briefs`) and to a medallion TAXII server. Only TLP:CLEAR briefs go to the public archive, and that check lives in code and again in CI.

## Three things I learned

**1. Make the model's job small.** My first instinct was to give the LLM the data and ask for a brief. The version that works gives it prose only. Tables, the KEV list, ATT&CK techniques and the indicator appendix are rendered straight from data. The model can only cite findings by ID. That shrinks the hallucination surface to the narrative, which a validator can actually check. In the benchmark, 9 of 9 runs across three models came back with zero invented facts.

**2. Retries can make things worse.** The first unattended dry run published a facts-only brief. Two things combined. The completeness rule demanded that one section cite five findings, which forced retries. Each retry added the previous answer to the prompt, until the model ran out of context and returned truncated JSON. The fix was to keep the best faithful answer across attempts, to require only what matters (the top lens finding), and to raise the context window. It's now a regression test. In a pipeline, a retry must never be worse than the first try.

**3. Fail closed on sharing.** TLP is the part of threat intel that can get someone hurt, so every default leans private. Data with no marking is treated as TLP:AMBER. A finding takes the strictest TLP of its indicators. The Pages publisher refuses anything that isn't CLEAR, and human outputs are defanged everywhere, including IPs inside URL paths, which a security review caught. Indicators are only ever text: HexBrief never visits, resolves or downloads them.

## Running it on a laptop

MISP and OpenCTI don't fit in 24 GB of RAM together with Ollama. The daily job therefore runs MISP alone, snapshots its fresh findings and shuts it down. It then starts OpenCTI, imports abuse.ch, writes and publishes the brief, and stops the stacks. The whole run took about 7 minutes on the first scheduled day, most of it the model. Windows Task Scheduler runs it at 07:00 Malaysia time, because the job needs Docker Desktop, the GPU and git credentials from the user session.

## What's next

An ATT&CK Navigator layer every week, a cloud-lite mode that runs in GitHub Actions on KEV, ThreatFox and ATT&CK only, and a priority intelligence requirements file that drives the scoring instead of constants in code.

The design decisions are written up as ADRs in the repo, and every error I hit is in `docs/TROUBLESHOOTING.md`.
