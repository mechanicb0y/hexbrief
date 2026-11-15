"""PDF export by printing the (self-contained) HTML brief with a local headless
Chromium (Edge or Chrome, both standard on Windows). No extra Python dependency.

The HTML has a strict CSP (``default-src 'none'``) and no external resources, so the
browser makes no network requests while printing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

_CANDIDATES = (
    r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe",
    r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
    r"%LocalAppData%\Google\Chrome\Application\chrome.exe",
)


def find_browser() -> str | None:
    override = os.environ.get("HEXBRIEF_PDF_BROWSER")
    if override and Path(override).is_file():
        return override
    for cand in _CANDIDATES:
        path = Path(os.path.expandvars(cand))
        if path.is_file():
            return str(path)
    for name in ("chromium", "chromium-browser", "google-chrome", "msedge"):
        found = shutil.which(name)
        if found:
            return found
    return None


def html_to_pdf(html_path: Path, pdf_path: Path, timeout: int = 120) -> Path:
    browser = find_browser()
    if browser is None:
        raise RuntimeError("no Edge/Chrome/Chromium found for PDF export")
    pdf_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="hexbrief-pdf-") as profile:
        cmd = [
            browser,
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--disable-extensions",
            "--no-pdf-header-footer",
            f"--user-data-dir={profile}",  # throwaway profile: no user data involved
            f"--print-to-pdf={pdf_path.resolve()}",
            html_path.resolve().as_uri(),
        ]
        subprocess.run(cmd, check=True, timeout=timeout, capture_output=True)  # noqa: S603
    if not pdf_path.is_file() or pdf_path.stat().st_size < 1000:
        raise RuntimeError("PDF export produced no output")
    return pdf_path
