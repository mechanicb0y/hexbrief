# Interview prep

Study notes for each phase: what you need to know, then likely interview questions with model answers. Each answer uses HexBrief as the example. That is the point: in an interview you say "in my project, I…".

---

## Phase 0: CTI basics, lab sizing, secrets

**What you need to know**
- **CTI levels:** *strategic* (leaders, trends, months), *operational* (SOC lead, campaigns/TTPs, weeks), *tactical* (tools, IOCs, hours to days). One HexBrief brief serves all three: BLUF + Education/ASEAN watch, top threats + ATT&CK, IOC appendix + STIX.
- **Intelligence lifecycle:** Direction → Collection → Processing → Analysis → Dissemination → Feedback. Feedback must change real settings (scoring weights, feed confidence, prompt or model, PIRs).
- **Secrets:** `.gitignore` is prevention, gitleaks is detection (pre-commit + CI, because hooks can be skipped). If a key leaks, **rotate first**: deleting the commit doesn't un-leak it.

**Q&A**
1. *Who consumes strategic vs operational vs tactical intel?* A CISO wants strategic trends for budget and risk. A SOC lead wants operational campaigns/TTPs to plan detections. Firewalls and SIEMs want tactical IOCs in machine format (STIX), because they read STIX, not prose. Tactical goes stale fastest: attackers swap IPs and hashes cheaply (bottom of the Pyramid of Pain).
2. *Walk me through the lifecycle with your project.* Direction = what I care about (education, Malaysia/ASEAN, exploited CVEs) as scoring weights. Collection = TAXII/feeds into MISP and OpenCTI. Processing = STIX normalization, dedupe, warninglists. Analysis = rule-based scoring + a local LLM that writes prose, gated by a validator. Dissemination = md/html/pdf, STIX Report over TAXII, a Pages archive. Feedback = run logs and reader reactions change weights, feeds and prompts.
3. *Your API key got pushed to a public repo. What do you do?* Revoke and rotate it at the provider immediately, then check its logs for misuse, then clean the repo. Bots scrape GitHub within seconds, so the key counts as stolen.
4. *How did you size a CTI lab on a 24 GB laptop?* OpenCTI's documented minimums are ~18 GB. I capped WSL at 14 GB, shrank the Elasticsearch heap, ran MISP only on demand and never at the same time as heavy OpenCTI imports, and wrote the trade-offs in ADR-001.

---

## Phase 1: STIX 2.1 and TAXII 2.1

**What you need to know**
- **SDO** = analysis objects (indicator, malware, attack-pattern, report, identity). **SCO** = raw facts (ipv4-addr, domain-name, file). **SRO** = links (relationship, sighting). Bundle = an envelope of objects.
- **Indicator vs observable:** an indicator is a *rule* (a STIX pattern + `valid_from`) that means "if you see this, it means X". An observable just says "this was seen". A **sighting** links the two: "this indicator was seen here".
- **TLP 2.0 in STIX** uses fixed OASIS marking-definition ids (TLP:CLEAR = `marking-definition--94868c89…`), which makes them machine-enforceable. stix2 3.0.2 only ships TLP 1.0, so HexBrief defines TLP 2.0 itself. A fixed id says *what* the label means, not that the producer applied it honestly.
- **TAXII 2.1:** discovery → API roots → collections → objects, inside an envelope with `more`/`next`. Use `added_after` for incremental pulls. `next` is opaque: medallion reuses one id for every page, so detect loops by page content.
- **Retries:** GETs are idempotent, so retry 429/5xx with backoff. Retry POSTs only on 429/503, because a 500 may mean the write already happened.

**Q&A**
1. *Indicator vs observable?* See above. Example: an IP in a phishing header is observed data. Once analysis ties it to C2, it becomes an indicator with a pattern, and a sighting records where we saw it.
2. *Why write your own TAXII client?* taxii2-client and medallion were last updated in 2023 (ADR-002). About 250 lines on httpx gave me pagination, `added_after`, typed errors, backoff and no credential logging, and I learned the protocol rather than a wrapper.
3. *A TAXII pull fails with 500 on page 3 of 10. What now?* Retry the same page with backoff, and keep pages 1–2. If the server's session expired, resume with `added_after` = the last good object. If it still fails, report a partial result clearly, never a complete one.
4. *How is ATT&CK represented in STIX?* Techniques are `attack-pattern` objects (`x_mitre_is_subtechnique` marks sub-techniques), tactics are `x-mitre-tactic`, groups `intrusion-set`, software `malware`/`tool`. 82% of the 26,699 Enterprise objects are relationships. Filter out `revoked` and `x_mitre_deprecated` objects, and compare `modified` as datetimes, not strings.

---

## Phase 2: MISP

**What you need to know**
- **Event** = one story. **Attribute** = one value. **Object** = grouped attributes. **`to_ids`** = good enough to alert or block on; everything else is context.
- **Tags/taxonomies** = controlled labels (tlp:clear). **Galaxies/clusters** = threat actors, ATT&CK, and similar knowledge.
- **Warninglists** = known-benign values. HexBrief **flags** hits for scoring rather than dropping them. 66,948 of 515,818 IDS attributes (13%) hit a warninglist after the first fetch.
- **Feed vs sync:** a feed is a one-way pull of public data (CIRCL OSINT, Botvrij). Sync is MISP-to-MISP sharing with partners (ISAC/CERT), with trust agreements. A feed can also be *cached only*, which gives correlation without import.
- **Gotchas found:**
  - `publish_timestamp` is *our* MISP's publish time, so a fetch makes 2015 events look new.
  - `enforceWarninglist` filters *after* paging, which broke the "short page = done" rule.
  - misp-docker re-applies `ADMIN_PASSWORD` on every start.

**Q&A**
1. *What does to_ids mean and why default to it?* An analyst judged the value specific enough for automated detection. The brief's IOC appendix and STIX indicators are meant to be acted on, so non-IDS values (victim IPs, abused legitimate hosts) would cause false positives. Non-IDS data is still useful context for the narrative and for retro-hunting.
2. *How do you handle 8.8.8.8 in a feed?* Flag it, don't drop it. Real signal: malware that hard-codes 8.8.8.8 to bypass the corporate resolver, on a network where internal DNS is enforced. Noise: a sandbox report that lists every IP the OS touched. Blocking it would break DNS for everyone.
3. *Feed or sync for a SOC?* Sync with an ISAC/CERT gets non-public TLP:GREEN/AMBER intel faster and lets you share back, at the cost of trust agreements and an exposed, managed instance. My lab uses public feeds because it is single-user and localhost only.
4. *Tell me about a bug you found in your pipeline.* The MISP collector saw 974 of 615k attributes. MISP applies `enforceWarninglist` after paging, so a filtered page looked like the last one. I proved it by comparing page sizes with and without the filter (4,760 vs 5,000; 240 rows had warnings), switched to `includeWarninglistHits`, and added a regression test.

---

## Phase 3: OpenCTI

**What you need to know**
- OpenCTI is a **STIX 2.1 knowledge graph**: *entities* (report, malware, intrusion-set, vulnerability), *observables* (raw values) and *indicators* (detection rules), joined by *relationships*. MISP thinks in events; OpenCTI thinks in a graph.
- **Architecture:** the platform (GraphQL API + UI) uses Elasticsearch (storage/search), Redis (cache/streams), RabbitMQ (queues) and MinIO/S3 (files). **Connectors** push STIX bundles into queues, and **workers** write them into the graph. Connector types: external import, internal enrichment, stream, import/export file.
- **Confidence** (0–100) is on every object. Indicators also get an **x_opencti_score**. **Markings** (TLP) control who sees what: a group sees only the markings it is allowed.
- **Data sharing:** TAXII 2.1 collections and live streams. HexBrief's `daily-briefs` collection serves Reports labelled `hexbrief`.
- **Gotchas found:**
  - The LTS images need a paid license (`LTS_REQUIRED_ACTIVATION`), so I switched to the community release.
  - The health endpoint passes before connectors can register, so connectors use bounded restarts.
  - pycti and PyMISP pin conflicting `requests` versions, so I pinned PyMISP 2.5.34.1.
  - API tokens can only be minted by their owner, so the setup logs in as the reader to mint its token.

**Q&A**
1. *Entity vs observable vs indicator in OpenCTI?* An observable is a raw fact (an IP). An indicator is a detection rule built on it (a STIX pattern + score + validity). An entity is analysis (the malware family or intrusion set the indicator `indicates`). The value of the graph is the relationships between them.
2. *How does data get into OpenCTI?* External-import connectors (MITRE, KEV, OTX, abuse.ch, MISP, TAXII2) fetch on a schedule, convert to STIX bundles and send them to RabbitMQ. Workers consume the queues and write to Elasticsearch through the platform. That decoupling is why a slow import never blocks the UI.
3. *How did you apply least privilege?* The collector uses a dedicated "HexBrief reader" role (KNOWLEDGE read + API token + TAXII read, nothing else) with a 365-day token minted by that user. The admin token is only used for one-time setup. Everything listens on 127.0.0.1, and the backing services aren't published at all.
4. *You chose LTS but run the community release. Why?* The LTS images block the API until a paid license is activated. The project rule is free/open-source only, so I recorded the change in ADR-004 and pinned the latest community patch, with every image on one tag.
5. *Why not run MISP and OpenCTI together?* RAM: OpenCTI's minimums alone are ~18 GB, and my WSL cap is 14 GB. MISP runs on demand, and the MISP→OpenCTI connector runs only in a deliberate `-WithMisp` session.

---

## Phase 4: Local LLM

**What you need to know**
- **Why LLMs hallucinate:** they predict likely text, not true text. An IP that "looks right" is very likely. HexBrief's answer: the model never sources facts. It writes prose about given findings, cites them by `[F#]`, and a validator blocks any IP/domain/URL/hash/CVE/ATT&CK ID that is not in the input.
- **Structured output:** Ollama's `format` takes a JSON schema and constrains decoding, so the output is always parseable and the right shape (36/36 attempts valid in the benchmark).
- **Temperature** ≤ 0.2 (enforced in code): low randomness, so answers stay faithful and repeatable.
- **Quantization** (Q4) shrinks weights about 4×. **Context window / KV cache**: an 8k context costs extra VRAM, so even a 3–4B model spilled to the CPU on a 4 GB GPU.
- **Why local:** TLP (intel never leaves the machine), privacy, no per-token cost, works offline.
- **Faithful ≠ complete:** all three models passed the validator, but llama3.2:3b *omitted* the education finding. Validators catch inventions, not omissions, so Phase 5 adds a completeness check.
- **Validator bypasses I closed** (security review): IPv6, SHA-512, `(dot)`/`{.}` defangs, lowercase `t1055`, TLD-like extensions (`.zip`, `.sh`), unparseable IPs (fail closed), sentence-ending IPs.

**Q&A**
1. *How do you stop an LLM from inventing IOCs?* Facts come from data and the model only writes prose, with structured output and low temperature. A hard gate regex-extracts every indicator/CVE/technique from the text, refangs first, and requires each one to exist in the input. It retries twice with the errors fed back, then falls back to a facts-only brief. Unchecked text is never published.
2. *How did you pick the model?* I benchmarked llama3.2:3b, qwen3.5:4b and qwen3.5:9b on a fixed fixture (time, JSON validity, facts surviving validation). All were faithful, so quality decided: qwen3.5:4b covered more threats and caught the education angle in ~90 s, which is fine for a 07:00 batch job (ADR-005).
3. *What can't your validator catch?* Omissions and wrong-but-allowed claims, e.g. calling a phishing IP a "C2". Mitigations: deterministic tables rendered from data, a completeness check, a prompt rule against unsupported trend claims, and a human reading the brief.
4. *Why not a cloud model?* TLP:GREEN+ intel must not leave the machine. A cloud model would be allowed only for TLP:CLEAR data and only with explicit approval.

---

## Phase 5: Brief engine

**What you need to know**
- **Pipeline:** collect → normalize to a `Finding` (keeps provenance: sources, URLs, STIX ids) → KEV cross-check → dedupe → score → LLM → validate → render → run log.
- **Dedupe** is union-find on shared CVEs or IOCs. Indicator clusters may *join* a report that shares an IOC but never claim IOCs themselves, otherwise two big ThreatFox clusters sharing one IP would merge into nonsense (a bug a test caught).
- **Scoring is rules, not AI:** KEV +30, exploited +15, ransomware +10, fresh +10/+5, +8 per extra independent source, confidence, education/Malaysia/ASEAN lens, −15 if every IOC hits a warninglist. Reasons are printed per finding. Source aliases ("Cybersecurity and Infrastructure Security Agency" = "CISA KEV") stop one organisation counting twice. Long "targeted sectors/countries" lists get a reduced bonus.
- **Two gates:** *faithfulness* (hard, nothing invented) and *completeness* (best effort, nothing important left out).
- **Fallbacks:** retries with the rejected answer + errors, then a fallback model, then a facts-only brief. One broken source is logged and skipped.
- **Outputs:** humans get defanged Markdown/HTML. Machines get real values in JSON and a validated STIX 2.1 Report (deterministic id per day, so re-runs update it).
- **First live run (2026-11-15):** 133 findings → 129 after dedupe → top 8. qwen3.5:4b passed on attempt 3 (a cold-start 500, then a completeness retry). The STIX bundle is valid, and the run took about 8 min.

**Q&A**
1. *Walk me through how a brief is made.* See the pipeline above. The key point is that facts are rendered from data (tables, IOC appendix, KEV list) and the model only writes prose about IDs it was given.
2. *How do you rank 2,000 indicators a day?* Cluster indicators by source and family, merge stories that share CVEs/IOCs, then apply transparent weights. KEV and exploitation dominate, then recency, corroboration and my education/ASEAN lens. Every score has written reasons, so an analyst can disagree with a specific rule.
3. *What happens when the model fails?* It retries twice with the validator errors and its own rejected answer, then uses the fallback model, then publishes a facts-only brief. The run log records every attempt, and that is where the "first-try pass rate" résumé number comes from.
4. *Why both a faithfulness and a completeness check?* Faithfulness catches inventions; completeness catches omissions. In the benchmark a small model invented nothing but silently skipped the most relevant (education) finding.
5. *What is still imperfect?* Semantic mistakes the regexes can't see, such as pairing a technique ID with the wrong name. Mitigation: the prompt forbids technique names and names are rendered from data. A human reads the brief before anything non-CLEAR leaves the machine.

---

## Phase 6: Publish and share

**What you need to know**
- **TLP in practice:** the private brief's TLP is the strictest among its findings. Unmarked data **fails closed to AMBER** (security review). The public archive gets a separate *public view*: CLEAR findings only, and the AI narrative is dropped if anything non-CLEAR was in the top 8, because the prose could mention it. Two independent guards follow: `pages.write_brief` refuses non-CLEAR, and the Pages workflow greps for GREEN/AMBER/RED before deploying.
- **STIX out, TAXII out:** each brief is a STIX 2.1 `report` (`report_types: threat-report`, `object_refs` to the underlying objects, label `hexbrief`). The id is deterministic per day, so re-runs update the same Report. Pushing it into OpenCTI makes OpenCTI's own TAXII 2.1 collection `daily-briefs` serve it (verified: a TAXII GET returns the Report).
- **Defang everywhere humans read:** IPs, domains, URL hosts **and IPs inside URL paths** (an audit of the first public page found one). Machine outputs keep real values.
- **Untrusted text in published pages:** feed titles and LLM prose are escaped for Markdown and autoescaped in HTML, the CSP is `default-src 'none'`, and the referrer policy is `no-referrer`.

**Q&A**
1. *How do you make sure nothing sensitive gets published?* TLP on every finding, with unmarked = AMBER. The public view filters to CLEAR, the publisher refuses non-CLEAR, and CI refuses non-CLEAR markings. A narrative is only reused when every top finding was CLEAR.
2. *How do consumers get your brief by machine?* As a STIX 2.1 Report over TAXII 2.1: from OpenCTI's `daily-briefs` collection, or from the lab medallion. Both were tested with a GET after the push.
3. *What did you learn auditing your own public page?* Defanging the URL host isn't enough. An IP in the URL *path* was still raw, so now IPs are defanged anywhere in a URL. Always audit what you publish with a scanner, not by eye.
4. *Why print PDF with a headless browser?* The HTML is already the source of truth, and a local Edge/Chrome is available on Windows, so there are no extra dependencies. The page loads nothing external, and a throwaway profile keeps the user's browser data out of it.

---

## Phase 7: Automation and hardening

**What you need to know**
- **Idempotent daily job:** re-running a day overwrites that day's outputs and updates the *same* STIX Report (deterministic id), so retries are safe. Each step retries with back-off; optional steps (MISP, abuse.ch, medallion) degrade the run instead of failing it.
- **Resource-aware orchestration:** MISP runs first and its fresh findings are snapshotted, then OpenCTI runs, because both don't fit in RAM. The MISP collector falls back to the snapshot.
- **Why Task Scheduler and not a container scheduler:** the job needs Docker Desktop, the host GPU (Ollama) and the owner's git credentials, all of which live in the Windows user session.
- **Supply chain:** actions pinned by commit SHA, Dependabot weekly, pip-audit in CI. Four transitive CVEs are pinned by pycti and are explicitly ignored with a written reason and a removal trigger, not silently.
- **`hexbrief doctor`:** checks names-only secrets, services, model, disk and the last run. Its `.env` parser treats an unclosed quote as malformed (closed issue #2).

**Q&A**
1. *How do you make a daily pipeline reliable?* Idempotent steps, retries with back-off, optional vs required steps, one run log per day, a health check before work, and degraded output instead of no output. Then measure it: the done-criterion is 7 consecutive unattended days.
2. *What would you do about a CVE in a transitive dependency you can't upgrade?* Confirm the vulnerable path is reachable or not (pycti's telemetry exporter isn't used; setuptools isn't used at runtime), suppress that specific ID with the reason in code and in an ADR, set a removal trigger (pycti release), and let Dependabot surface it. Never blanket-ignore.
3. *How do you keep secrets out of CI?* No live keys in CI at all: tests use fixtures and a throwaway medallion password generated per run and masked. gitleaks scans full history on every push/PR.
4. *Why push the public page only from a clean `main`?* So a scheduled job can never publish half-finished branch work. The job checks branch and cleanliness and otherwise keeps the page locally and marks the run "degraded".

## Phase 8: Quality and demo mode

**What you need to know**
- **`hexbrief demo`:** builds a complete brief from 48 recorded TLP:CLEAR findings and a recorded narrative shipped inside the package. The recorded text still goes through the faithfulness validator, so the demo proves the pipeline, not just the templates. No keys, Docker or Ollama needed; `--llm` writes the narrative live.
- **Why the daily dry run fell back to facts-only:** the completeness rule asked for too much, and each retry added the previous answer to the prompt until the context overflowed and the JSON was cut off. The fix keeps the best faithful answer across retries, requires only the top lens finding, and raises `num_ctx` to 12288. Lesson: measure the prompt size, and never let a retry be worse than the first try.
- **HTML design:** the identity is the TLP strip in its official FIRST colour, top and bottom of every page and in print, so a reader can't miss the sharing level. Strict CSP, no external fonts or scripts.
- **README order:** pitch and screenshot, diagram, demo-first quickstart, STIX/TAXII, truthfulness, security. A reviewer gets a result in five minutes before reading anything.

**Q&A**
1. *How can someone evaluate your project without your API keys?* `pip install .` then `hexbrief demo`: recorded public data, same scoring, same validator, same renderers, about five minutes on a fresh clone.
2. *Isn't a recorded narrative cheating?* It's labelled as recorded, it passes the same gate a live answer must pass, and `--llm` regenerates it live. CI runs the demo as a test, so a validator or template change that breaks it fails the build.
3. *Tell me about a production bug you fixed.* The first daily dry run published facts-only. Root cause: retries grew the prompt past the model's context, so the JSON was truncated, and a too-strict completeness rule triggered the retries. I kept the first faithful answer, relaxed completeness to what matters (the top lens finding), raised the context, and added a regression test.

## Phase 9: Launch, the 20 questions

**What you need to know**
- v1.0.0 = Phases 0–8 merged, CHANGELOG, and the launch kit in `docs/launch/` (the write-up, the LinkedIn draft with a video shot list, resume bullets).
- Resume numbers come only from `python scripts/run_stats.py` over `runs/*.json`. The bracketed ones fill in after 7 scheduled days.

**Q&A**
1. *Pitch HexBrief in 30 seconds.* It's a daily threat-intel brief for a SOC lead. Free feeds come in over STIX/TAXII into MISP and OpenCTI, and the engine ranks the last 24 hours with written rules. A local LLM writes the page, and a validator blocks any indicator or CVE that isn't in the data. Output goes out as STIX 2.1 over TAXII and to a TLP:CLEAR archive.
2. *STIX vs the MISP format?* STIX 2.1 is an OASIS standard graph: SDOs (indicator, malware, report), SCOs (observables like ipv4-addr) and SROs (relationships), with patterns for detection. MISP's native format is event-centric: an event holds attributes and objects, with tags and galaxies for context. MISP is great for sharing and correlating events. STIX is better for a typed knowledge graph and interchange. HexBrief reads both and normalizes to one finding model.
3. *What is TAXII?* It's a REST API for exchanging STIX. A discovery endpoint leads to API roots, which hold collections, which hold objects in envelopes, with `added_after` and `next` for paging. TAXII is transport and STIX is content.
4. *Indicator vs observable?* An observable (SCO) is a fact that something was seen, like an IP address. An indicator (SDO) is a pattern plus context that says this is worth detecting, such as `[ipv4-addr:value = '198.51.100.7']` with validity, confidence and kill-chain phase. Not every observable is malicious.
5. *Explain TLP 2.0.* There are four levels. CLEAR is public. GREEN is the community, not public. AMBER is the recipient's organization and its clients on a need-to-know basis (AMBER+STRICT limits it to the organization only). RED is the named recipients only. TLP:WHITE became CLEAR. HexBrief marks every object, treats unmarked data as AMBER, raises a finding to its strictest indicator's TLP, and publishes only CLEAR.
6. *Why a local LLM?* Shared intel can carry sharing restrictions, so it shouldn't go to a third-party API. Local also means no cost per run, reproducibility (pinned model, temperature 0.1) and offline operation. The trade-offs are a smaller model and slower runs, which is why the model only writes prose and a validator checks it.
7. *How do you stop the model from hallucinating?* Shrink its job: facts are rendered from data, and the model writes prose that cites `[F#]`. A JSON schema constrains the output. A validator refangs the text and checks every IP, domain, URL, hash, CVE and ATT&CK ID against the input. On failure the errors are fed back for a retry, then the fallback model gets a try, then a facts-only brief ships. Unvalidated text is never published.
8. *What can't the validator catch?* Wrong claims that use no checkable token, like "this actor targets banks" when it doesn't, or a correct IOC tied to the wrong finding. Mitigations: citations per claim, the completeness check, low temperature, a label on the narrative saying it is AI-written, and the data tables beside it so a reader can verify.
9. *What are warninglists?* MISP lists of known-benign values (top domains, public DNS resolvers, RFC1918, cloud ranges). Feed indicators that hit them are likely false positives. I use `includeWarninglistHits` to flag them instead of `enforceWarninglist`, because enforcing broke paging. Blocking a public DNS resolver because a feed listed it is a classic outage.
10. *How do you handle false positives?* Warninglists, confidence from the source, needing corroboration for a higher score, freshness windows, and keeping indicators as context in a brief rather than auto-blocking. A blocklist export would only take high-confidence, warninglist-clean, TLP:CLEAR network IOCs.
11. *Pyramid of Pain: where do HexBrief's indicators sit?* Most feed IOCs are hashes, IPs and domains, at the bottom of the pyramid, where they are cheap for the attacker to change and decay fast. That's why the brief leads with KEV vulnerabilities and ATT&CK techniques (TTPs at the top), and treats IOCs as an appendix for detection teams.
12. *How do you measure brief quality?* Faithfulness is 0 unvalidated tokens, enforced. Completeness means the top and lens findings are covered. The rest is measured: first-try pass rate, facts-only days, runtime, findings in vs after dedupe (`run_stats.py`), and analyst feedback on whether the top 3 were the right top 3. A next step would be a labelled set of past days to score ranking against.
13. *Why rule-based scoring and not let the LLM rank?* It's explainable, repeatable and testable. Each score carries reasons like "in CISA KEV" or "2 independent sources", so an analyst can challenge a rule. An LLM ranking is non-deterministic and hard to audit.
14. *How does dedupe work?* It uses union-find over shared CVEs and IOCs, in two passes so clusters don't swallow each other. A merged finding keeps every source, STIX id and the strictest TLP. Example: a KEV entry and an OTX report on the same CVE become one finding with two sources, which also raises its corroboration score.
15. *Why both MISP and OpenCTI?* MISP is strongest at feed ingestion, correlation and sharing communities. OpenCTI is a STIX-native knowledge graph with ATT&CK, relationships and TAXII collections. Running both shows I can work with either at an employer. On a 24 GB laptop they run one after the other, with a MISP snapshot in between.
16. *What would break first at scale?* RAM for MISP and OpenCTI together, then the single local model's throughput. Fixes: run OpenCTI on its own host with Elasticsearch tuned, put workers per connector, batch the LLM per section, or use a bigger GPU. The engine itself is stateless per day and idempotent.
17. *How do you keep secrets safe in a public repo?* Keys live only in a git-ignored `.env`, `.env.example` holds placeholders, and secrets are generated by script. gitleaks runs in pre-commit and in CI over full history, CI has no live keys, the doctor prints names only, and the process is to rotate at once if anything leaks.
18. *What's the security model of the lab?* Every service binds to 127.0.0.1. Pinned images, generated secrets, a lab CA for MISP TLS, least-privilege tokens (read-only reader, confidence-capped importer), indicators never visited or resolved, a strict CSP on the HTML brief, and defanged human output.
19. *What was the hardest bug?* The first unattended run went facts-only. Retries grew the prompt past the context window, which produced truncated JSON, and an over-strict completeness rule caused the retries in the first place. I fixed it by keeping the best faithful answer, relaxing completeness to what matters, and raising `num_ctx`, then added a regression test.
20. *What would you add next?* A priority intelligence requirements YAML that drives scoring (sectors, regions, tech stack), an ATT&CK Navigator layer each week, a cloud-lite mode in Actions for KEV, ThreatFox and ATT&CK, and a sightings loop from home-lab logs back into OpenCTI to measure which intel was actually seen.
