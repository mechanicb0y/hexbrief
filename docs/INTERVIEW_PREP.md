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
