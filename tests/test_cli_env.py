from __future__ import annotations

from pathlib import Path

import pytest

from hexbrief import cli


def test_env_loader_reads_only_allow_listed_keys(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = tmp_path / ".env"
    env.write_text(
        "TAXII_USER=alice\nTAXII_PASSWORD='pw'\nHTTPS_PROXY=http://evil.test:8080\n"
        "SSL_CERT_FILE=/tmp/evil.pem\n",
        encoding="utf-8",
    )
    for key in ("TAXII_USER", "TAXII_PASSWORD", "HTTPS_PROXY", "SSL_CERT_FILE"):
        # setenv first so monkeypatch records the original state and restores it
        # afterwards; otherwise the loader's writes would leak into later tests.
        monkeypatch.setenv(key, "x")
        monkeypatch.delenv(key)
    cli._load_env_file(env)
    import os

    assert os.environ["TAXII_USER"] == "alice"
    assert os.environ["TAXII_PASSWORD"] == "pw"
    assert "HTTPS_PROXY" not in os.environ
    assert "SSL_CERT_FILE" not in os.environ


def test_env_file_is_resolved_from_repo_not_cwd() -> None:
    assert Path(cli.__file__).resolve().parents[2] / ".env" == cli.REPO_ENV
