"""``hexbrief doctor``: is everything the daily run needs in place?

Checks are read-only and never print a secret value. Each check returns
(status, detail) where status is "ok", "warn" or "fail". "fail" = the daily
brief cannot run as configured; "warn" = it runs, degraded.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parents[2]
PLACEHOLDER = "__replace_me__"
REQUIRED_KEYS = ("ABUSECH_AUTH_KEY", "OTX_API_KEY", "OPENCTI_URL", "OPENCTI_TOKEN")
OPTIONAL_KEYS = ("MISP_URL", "MISP_API_KEY", "TAXII_USER", "TAXII_PASSWORD", "OLLAMA_MODEL")


@dataclass
class Check:
    name: str
    status: str
    detail: str


# ------------------------------------------------------------------ .env parsing
_QUOTED = re.compile(r"""^(["'])(.*)\1(\s+#.*)?$""")


def parse_env_value(raw: str) -> tuple[str | None, str | None]:
    """Return (value, problem). Mirrors common dotenv rules.

    - ``KEY=value # comment``: comment stripped (a '#' after whitespace).
    - ``KEY="value"`` / ``'value'``: quotes removed, '#' inside kept.
    - an opening quote without its closing quote is **malformed**, not "set"
      (GitHub issue #2).
    """
    v = raw.strip()
    if v[:1] in ("'", '"'):
        m = _QUOTED.match(v)
        if not m:
            return None, "unclosed quote"
        return m.group(2), None
    return re.sub(r"(^|\s)#.*$", "", v).strip(), None


def read_env(path: Path) -> dict[str, tuple[str | None, str | None]]:
    out: dict[str, tuple[str | None, str | None]] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        if s.startswith("export "):
            s = s[7:].strip()
        k, raw = s.split("=", 1)
        out[k.strip()] = parse_env_value(raw)
    return out


def check_env(path: Path = REPO / ".env") -> list[Check]:
    env = read_env(path)
    if not env:
        return [Check(".env", "fail", f"missing or empty: {path}")]
    out: list[Check] = []
    for keys, level in ((REQUIRED_KEYS, "fail"), (OPTIONAL_KEYS, "warn")):
        for k in keys:
            value, problem = env.get(k, (None, "missing"))
            if problem:
                out.append(Check(f"env {k}", level, problem))
            elif not value or value == PLACEHOLDER:
                out.append(Check(f"env {k}", level, "not set"))
            else:
                out.append(Check(f"env {k}", "ok", "set"))  # never the value
    return out


# ------------------------------------------------------------------ services
def _http(
    name: str,
    url: str,
    ok_codes: tuple[int, ...] = (200,),
    level: str = "fail",
    verify: bool | str = True,
    **kw: object,
) -> Check:
    try:
        r = httpx.get(url, timeout=10, verify=verify, trust_env=False, **kw)  # type: ignore[arg-type]
    except httpx.HTTPError as exc:
        return Check(name, level, f"unreachable ({type(exc).__name__})")
    if r.status_code in ok_codes:
        return Check(name, "ok", f"HTTP {r.status_code}")
    return Check(name, level, f"HTTP {r.status_code}")


def check_docker() -> Check:
    exe = shutil.which("docker")
    if not exe:
        return Check("docker", "fail", "docker CLI not found")
    try:
        r = subprocess.run(  # noqa: S603 - fixed argv, resolved docker CLI
            [exe, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return Check("docker", "fail", "docker info timed out")
    if r.returncode != 0:
        return Check("docker", "fail", "engine not running (start Docker Desktop)")
    return Check("docker", "ok", f"engine {r.stdout.strip()}")


def check_ollama(host: str, model: str) -> Check:
    try:
        tags = httpx.get(f"{host}/api/tags", timeout=10, trust_env=False).json()
    except (httpx.HTTPError, ValueError) as exc:
        return Check("ollama", "warn", f"unreachable ({type(exc).__name__}): facts-only briefs")
    names = {m.get("name") for m in tags.get("models", [])}
    if model in names:
        return Check("ollama", "ok", f"{model} present")
    return Check("ollama", "warn", f"model {model} not pulled (have: {', '.join(sorted(names))})")


def check_disk(path: str, min_gb: float = 20) -> Check:
    try:
        free = shutil.disk_usage(path).free / 1e9
    except OSError:
        return Check(f"disk {path}", "warn", "not found")
    status = "ok" if free >= min_gb else ("warn" if free >= min_gb / 2 else "fail")
    return Check(f"disk {path}", status, f"{free:.0f} GB free")


def check_last_run(runs: Path = REPO / "runs", max_age_h: int = 30) -> Check:
    logs = sorted(p for p in runs.glob("????-??-??.json"))
    if not logs:
        return Check("last run", "warn", "no run logs yet")
    data = json.loads(logs[-1].read_text(encoding="utf-8"))
    age = datetime.now(UTC) - datetime.fromtimestamp(logs[-1].stat().st_mtime, UTC)
    detail = (
        f"{logs[-1].stem}: llm={'ok' if data.get('llm', {}).get('ok') else 'facts-only'}, "
        f"stix_valid={data.get('stix_valid')}"
    )
    return Check("last run", "ok" if age < timedelta(hours=max_age_h) else "warn", detail)


def run_checks(services: bool = True) -> list[Check]:
    env = {k: v for k, (v, _p) in read_env(REPO / ".env").items() if v}
    checks = check_env()
    checks.append(check_docker())
    if services:
        checks.append(
            _http(
                "opencti",
                env.get("OPENCTI_URL", "http://127.0.0.1:8088") + "/graphql",
                ok_codes=(200, 400, 401, 405),
                level="warn",
            )
        )
        misp_verify: bool | str = env.get("MISP_VERIFY_SSL", "true")
        misp_verify = {"true": True, "false": False}.get(str(misp_verify).lower(), misp_verify)
        checks.append(
            _http(
                "misp",
                env.get("MISP_URL", "https://127.0.0.1:8443") + "/users/login",
                level="warn",
                verify=misp_verify,
            )
        )
        checks.append(
            _http(
                "taxii (medallion)",
                "http://127.0.0.1:5000/taxii2/",
                ok_codes=(200, 401),
                level="warn",
            )
        )
        checks.append(
            check_ollama(
                env.get("OLLAMA_HOST", "http://127.0.0.1:11434"),
                env.get("OLLAMA_MODEL", "qwen3.5:4b"),
            )
        )
    checks += [check_disk("C:\\"), check_disk("D:\\"), check_last_run()]
    return checks


def render(checks: list[Check], echo: Callable[[str], None] = print) -> int:
    icon = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL"}
    for c in checks:
        echo(f"[{icon[c.status]}] {c.name:22} {c.detail}")
    fails = sum(c.status == "fail" for c in checks)
    warns = sum(c.status == "warn" for c in checks)
    echo(f"{len(checks)} checks: {fails} fail, {warns} warn")
    return 1 if fails else 0
