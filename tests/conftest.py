from __future__ import annotations

import os
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def read_env(path: Path = REPO / ".env") -> dict[str, str]:
    """Tiny .env reader for tests. Values are never printed."""
    env: dict[str, str] = {}
    if not path.is_file():
        return env
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def setting(name: str, default: str = "") -> str:
    """Environment variable first (CI), then the local .env file."""
    return os.environ.get(name) or read_env().get(name, default)
