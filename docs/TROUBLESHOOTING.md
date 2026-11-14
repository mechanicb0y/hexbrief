# Troubleshooting

Every error we hit, with the log lines, the cause and the fix.

## Template

### <short error title> (YYYY-MM-DD, Phase N)
- **Symptom:** what we saw (relevant log lines, secrets redacted)
- **Cause:** the root cause
- **Fix:** what changed, as a command or file diff
- **Prevention:** how to avoid it next time

---

### Docker containers ignore `vm.max_map_count` from .wslconfig (2026-11-14, Phase 0)
- **Symptom:** after adding `kernelCommandLine = "sysctl.vm.max_map_count=1048575"` under `[wsl2]` and running `wsl --shutdown`, `/proc/cmdline` showed the argument and the kali distro saw the new value. But `docker run --rm alpine sysctl vm.max_map_count` still returned `262144`.
- **Cause:** Docker Desktop's own VM setup sets `vm.max_map_count = 262144` after boot, which overrides the kernel command line value for containers.
- **Fix:** set the value at runtime from a privileged container: `docker run --rm --privileged alpine sysctl -w vm.max_map_count=1048575`. Verified: containers then read `1048575`. The setting resets whenever Docker Desktop restarts, so `scripts/up.ps1` (Phase 3) will run this before starting OpenSearch.
- **Prevention:** always check the value from inside a container, not from a WSL distro. 262144 is Elastic's minimum, so OpenSearch still starts if the step is missed. 1048575 is OpenCTI's documented value.
