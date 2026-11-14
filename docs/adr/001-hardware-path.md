# ADR-001: Hardware path and lab sizing

- **Status:** Accepted (sizing values to be verified against current docs before they are applied)
- **Date:** 2026-11-14

## Context

The lab runs on one Windows laptop:

| Item | Value |
|---|---|
| CPU | Intel i5-12450H, 8 cores / 12 threads (4P + 4E) |
| RAM | 23.7 GB total, about 10 GB free at idle |
| GPU | NVIDIA RTX 3050 Laptop, 4 GB VRAM |
| Disk | C: ~87 GB free (NVMe), D: ~143 GB free (SSD) |
| OS | Windows 11 Home 24H2, Docker Desktop + WSL2 |
| LLM runtime | Ollama, `llama3.2:3b` already pulled |

OpenCTI's documented minimums add up to roughly 18 GB RAM (OpenSearch/Elasticsearch ≥ 8 GB, platform ≥ 8 GB, plus Redis, RabbitMQ and MinIO). MISP adds a few GB more. Running everything at once (the Full path) needs ≥ 32 GB.

## Decision

**Standard path.**

- OpenCTI and Ollama run locally.
- MISP runs on demand and never during a heavy OpenCTI import.
- Docker Desktop's disk image moves to D: before any image is pulled, and `OLLAMA_MODELS` points to a folder on D:. Both need the owner's OK first.
- WSL2 gets a cap in `.wslconfig`, proposed as `memory=14GB`, `swap=8GB`, `processors=8`. The OpenSearch/Elasticsearch heap is shrunk to lab size. Values are checked against current OpenCTI docs, and the owner OKs them, before anything is written.
- The `vm.max_map_count` setting that OpenSearch requires is applied using the method currently documented for Docker Desktop.
- **LLM:** 4 GB VRAM fits only ~3–4B models fully on the GPU. In Phase 4 we benchmark `llama3.2:3b` against one current 4B model and one 7–8B model with partial CPU offload. Speed matters less for a 07:00 batch job. The result goes in its own ADR.

## Applied and verified (2026-11-14)

- Docker Desktop disk image moved to `D:\DockerData\DockerDesktopWSL`; `docker run hello-world` works.
- `%UserProfile%\.wslconfig`: `memory=14GB`, `swap=8GB`, `processors=8`, `kernelCommandLine = "sysctl.vm.max_map_count=1048575"` (the method was checked against Microsoft's wsl-config docs, and the value against OpenCTI's install docs).
- After `wsl --shutdown`: `docker info` reports 14.66 GB (≈13.7 GiB) and 8 CPUs.
- `vm.max_map_count`: Docker Desktop resets it to 262144 for containers, so it is raised at stack start-up instead. See TROUBLESHOOTING.md.

## Consequences

- OpenCTI runs below its documented minimum. Expect slower imports. Connectors are throttled or run one at a time, and the first big ATT&CK import may take a while.
- MISP data reaches OpenCTI through the MISP connector only while MISP is up. As a fallback, the CIRCL OSINT feed can go into OpenCTI directly.
- A 14 GB WSL cap leaves ~10 GB for Windows and Ollama. If the brief run competes with OpenCTI for RAM, the scheduled run may pause heavy connectors first (Phase 7).
- If this proves too tight, the options are the Lite path (MISP + a small model locally) or a paid cloud VM for OpenCTI. The VM costs money and needs the owner's OK.
