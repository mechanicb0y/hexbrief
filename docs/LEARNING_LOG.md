# Learning log

One entry per concept: date, concept, gotcha, one interview question.

| Date | Concept | Gotcha | Interview question |
|---|---|---|---|
| 2026-11-14 | Lab sizing for OpenCTI | Its documented minimums (~18 GB) exceed a WSL cap of 14 GB, so heaps must be shrunk and imports throttled | "How would you size a CTI lab on a 24 GB laptop, and what trade-offs did you accept?" |
| 2026-11-14 | CTI levels: strategic / operational / tactical | Tactical IOCs go stale in days, and machines consume them as STIX, not prose. Same brief, three audiences | "Who consumes strategic vs operational vs tactical intel, and in what format?" |
| 2026-11-14 | Intelligence lifecycle | Feedback has to change real settings (feed confidence, scoring weights, prompt/model, PIRs) or it's just a report | "Walk me through the intelligence lifecycle using a project you built." |
| 2026-11-14 | Secrets: prevention vs detection | .gitignore protects one file name; gitleaks is pattern-based and skippable with --no-verify, so CI runs it too. A leaked key must be rotated even after a history rewrite | "Your API key got pushed to a public repo. What do you do, in order?" |
| 2026-11-14 | Parsing .env safely (check-env.ps1) | PS 5.1 leaves $PSScriptRoot empty in param() defaults; an inline `# comment` after a placeholder made it look "set" | "How do you validate config without ever logging secret values?" |

| 2026-11-14 | TLP 2.0 in STIX | stix2 3.0.2 only ships TLP 1.0 (TLP_WHITE). TLP 2.0 markings are OASIS marking-definitions with a property extension, using fixed ids | "How do you mark a STIX object TLP:CLEAR, and why does the marking have a fixed id?" |
| 2026-11-14 | TAXII pagination | `next` is opaque: medallion reuses one id for every page, so detect loops by page content, not cursor | "How does TAXII 2.1 pagination work, and how do you stop a client looping forever?" |
| 2026-11-14 | `added_after` and date_added | Re-sending an object with the same id+modified doesn't change its date_added, so it won't appear as "new" | "Why might an object you just pushed not show up in an added_after query?" |
| 2026-11-14 | Retry safety | Retry GETs on 5xx; retry POSTs only on 429/503, because the write may already have happened | "Which HTTP errors are safe to retry, and for which methods?" |
| 2026-11-14 | ATT&CK as STIX | 26,699 objects, 82% of them relationships. Techniques are `attack-pattern` (+`x_mitre_is_subtechnique`); revoked/deprecated objects stay in the feed and must be filtered | "How is ATT&CK represented in STIX, and what do you filter out before using it?" |
| 2026-11-14 | Comparing STIX timestamps | `modified` strings with different fractional precision don't sort correctly as text (`…00Z` > `…00.500Z`); parse them first | "Why can't you compare ISO 8601 timestamps as strings?" |

**Re-quiz:** the Phase 0 answers were drafted with Claude's help. The owner re-answered at the start of Phase 1, again with help (2026-11-14). **Quiz cold, with no help, in a later phase** on: CTI levels and staleness, lifecycle order and feedback, and the leaked-key response (rotate first).
