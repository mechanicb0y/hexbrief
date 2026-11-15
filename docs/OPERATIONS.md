# Operations

## Daily

- **Scheduled:** `scripts\install-schedule.ps1` (once) registers "HexBrief daily" at 07:00. `-Remove` deletes it.
- **By hand:** `scripts\daily.ps1` (`-SkipMisp`, `-NoPublish`, `-KeepRunning`).
- **Health:** `hexbrief doctor`.
- **Logs:** `runs\daily-<day>.log` (transcript) and `runs\<day>.json` (counts per source, findings in/out, every LLM attempt, STIX validity, publish steps).

## Start / stop

| Stack | Start | Stop (keeps data) |
|---|---|---|
| OpenCTI 127.0.0.1:8088 | `scripts\opencti-up.ps1` | `scripts\opencti-down.ps1` |
| MISP 127.0.0.1:8443 | `scripts\misp-up.ps1` (~7 min on Windows) | `scripts\misp-down.ps1` |
| medallion 127.0.0.1:5000 | `scripts\taxii-up.ps1` | `scripts\taxii-down.ps1` |

Never run `docker compose down -v` (it deletes data). Never run MISP and a heavy OpenCTI import together (RAM).

## Backups and restore

- `scripts\backup.ps1` (stacks down) writes `backups\<date>\hexbrief-*.tar.gz` and keeps 4 sets.
- **Restore one volume** (stack down), e.g. OpenCTI's Elasticsearch:
  ```powershell
  docker run --rm -v hexbrief-opencti_esdata:/data -v D:\ART\hexbrief\backups\2026-11-22:/b alpine:3.22 sh -c "rm -rf /data/* && tar xzf /b/hexbrief-opencti_esdata.tar.gz -C /data"
  ```

## Updating (security fixes)

- **OpenCTI:** set the new tag on every `image:` in `docker/opencti/compose.yml` (one tag for all) and pin `pycti` to the same version in `pyproject.toml`. Then `opencti-down`, `opencti-up`, `pip install -e .[dev]`, `pytest`, `hexbrief doctor`. Check the OpenCTI "breaking changes" page first.
- **MISP:** bump `CORE_TAG`/`CORE_RUNNING_TAG` and `MODULES_*` in `docker/misp/env.misp.template` **and** in your local `.env.misp`, and the pinned commit in `misp-up.ps1`. Keep PyMISP on a compatible line (ADR-003/004).
- **medallion / Python deps / Actions:** Dependabot opens PRs weekly. Merge when CI is green.
- Record each upgrade in `docs/PROGRESS.md`. A new ADR is only needed if behaviour changes.

## Secrets

- `.env` (repo), `docker/misp/.env.misp` and `docker/opencti/.env.opencti` are git-ignored. `scripts\gen-secrets.ps1` fills placeholders only.
- **If a key leaks:** rotate it at the provider first (OTX, abuse.ch, OpenCTI tokens through the UI, MISP keys with `scripts/misp_feeds.py automation`), then clean up.
