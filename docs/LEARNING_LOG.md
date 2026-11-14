# Learning log

One entry per concept: date, concept, gotcha, one interview question.

| Date | Concept | Gotcha | Interview question |
|---|---|---|---|
| 2026-11-14 | Lab sizing for OpenCTI | Its documented minimums (~18 GB) exceed a WSL cap of 14 GB, so heaps must be shrunk and imports throttled | "How would you size a CTI lab on a 24 GB laptop, and what trade-offs did you accept?" |
| 2026-11-14 | CTI levels: strategic / operational / tactical | Tactical IOCs go stale in days, and machines consume them as STIX, not prose. Same brief, three audiences | "Who consumes strategic vs operational vs tactical intel, and in what format?" |
| 2026-11-14 | Intelligence lifecycle | Feedback has to change real settings (feed confidence, scoring weights, prompt/model, PIRs) or it's just a report | "Walk me through the intelligence lifecycle using a project you built." |
| 2026-11-14 | Secrets: prevention vs detection | .gitignore protects one file name; gitleaks is pattern-based and skippable with --no-verify, so CI runs it too. A leaked key must be rotated even after a history rewrite | "Your API key got pushed to a public repo. What do you do, in order?" |
| 2026-11-14 | Parsing .env safely (check-env.ps1) | PS 5.1 leaves $PSScriptRoot empty in param() defaults; an inline `# comment` after a placeholder made it look "set" | "How do you validate config without ever logging secret values?" |

**Re-quiz:** the Phase 0 answers were drafted with Claude's help. Quiz the owner again on all three Phase 0 questions, closed-book and in their own words, at the start of Phase 1.
