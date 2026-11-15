"""HexBrief command line (typer). Phase 1 adds the `taxii` and `stix` commands."""

from __future__ import annotations

import json
import os
from pathlib import Path

import typer

from hexbrief.stixkit.bundle import build_demo_bundle, count_by_type, validate
from hexbrief.stixkit.taxii import TaxiiClient, TaxiiError

app = typer.Typer(help="HexBrief: grounded daily threat-intel brief.", no_args_is_help=True)
taxii_app = typer.Typer(help="Talk to TAXII 2.1 servers.", no_args_is_help=True)
stix_app = typer.Typer(help="Build and validate STIX 2.1 bundles.", no_args_is_help=True)
app.add_typer(taxii_app, name="taxii")
app.add_typer(stix_app, name="stix")
misp_app = typer.Typer(help="Read from the lab MISP (read-only).", no_args_is_help=True)
app.add_typer(misp_app, name="misp")
opencti_app = typer.Typer(help="Read from the lab OpenCTI (read-only).", no_args_is_help=True)
app.add_typer(opencti_app, name="opencti")

MITRE_DISCOVERY = "https://attack-taxii.mitre.org/taxii2/"


# Repo root for an editable install (src/hexbrief/cli.py -> repo). Never the current
# directory: a .env planted in whatever folder you run from must not be trusted.
REPO_ENV = Path(__file__).resolve().parents[2] / ".env"
# Only these keys are read. Loading everything would let a .env set things like
# HTTPS_PROXY or SSL_CERT_FILE and silently redirect or weaken TLS. (Phase 5 moves
# config to pydantic-settings.)
_ENV_ALLOW = frozenset(
    {
        "TAXII_USER",
        "TAXII_PASSWORD",
        "MISP_URL",
        "MISP_API_KEY",
        "MISP_VERIFY_SSL",
        "OPENCTI_URL",
        "OPENCTI_TOKEN",
    }
)


def _load_env_file(path: Path = REPO_ENV) -> None:
    """Copy allow-listed keys from .env into os.environ (existing variables win).

    Values are never printed.
    """
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = (part.strip() for part in line.split("=", 1))
            if key in _ENV_ALLOW:
                os.environ.setdefault(key, value.strip('"').strip("'"))


def _client(use_auth: bool) -> TaxiiClient:
    auth = None
    if use_auth:
        _load_env_file()
        user, password = os.environ.get("TAXII_USER", ""), os.environ.get("TAXII_PASSWORD", "")
        if not user or not password:
            raise typer.BadParameter(
                "TAXII_USER / TAXII_PASSWORD not set (scripts/gen-secrets.ps1)"
            )
        auth = (user, password)
    return TaxiiClient(auth=auth, timeout=60)


@taxii_app.command("collections")
def taxii_collections(
    discovery_url: str = typer.Argument(MITRE_DISCOVERY, help="TAXII 2.1 discovery URL"),
    auth: bool = typer.Option(False, "--auth", help="Use TAXII_USER/TAXII_PASSWORD from .env"),
) -> None:
    """List API roots and their collections."""
    try:
        with _client(auth) as c:
            title = c.discovery(discovery_url).get("title", "?")
            typer.echo(f"Server: {title}")
            roots = c.api_roots(discovery_url)
            # MITRE lists one root per ATT&CK release; show the default one only.
            for root in roots[:1] if "mitre.org" in discovery_url else roots:
                typer.echo(f"\nAPI root {root}")
                for coll in c.collections(root):
                    rw = ("r" if coll.get("can_read") else "-") + (
                        "w" if coll.get("can_write") else "-"
                    )
                    typer.echo(f"  [{rw}] {coll['id']}  {coll.get('title', '')}")
    except TaxiiError as exc:
        typer.echo(f"TAXII error: {exc}", err=True)
        raise typer.Exit(1) from exc


@taxii_app.command("count")
def taxii_count(
    api_root: str = typer.Argument(..., help="API root URL"),
    collection_id: str = typer.Argument(..., help="Collection id"),
    added_after: str | None = typer.Option(None, help="Only objects added after this timestamp"),
    page_size: int = typer.Option(500, help="Objects per page (limit)"),
    auth: bool = typer.Option(False, "--auth", help="Use TAXII_USER/TAXII_PASSWORD from .env"),
) -> None:
    """Pull a whole collection and count objects by STIX type."""
    try:
        with _client(auth) as c:
            counts = count_by_type(
                c.objects(api_root, collection_id, added_after=added_after, limit=page_size)
            )
    except TaxiiError as exc:
        typer.echo(f"TAXII error: {exc}", err=True)
        raise typer.Exit(1) from exc
    for stix_type, n in counts.most_common():
        typer.echo(f"{n:>7}  {stix_type}")
    typer.echo(f"{sum(counts.values()):>7}  total")


@taxii_app.command("push")
def taxii_push(
    bundle_file: Path = typer.Argument(..., exists=True, dir_okay=False),
    api_root: str = typer.Argument(..., help="API root URL"),
    collection_id: str = typer.Argument(..., help="Collection id"),
) -> None:
    """Validate a STIX bundle file, then add its objects to a collection."""
    bundle = json.loads(bundle_file.read_text(encoding="utf-8"))
    report = validate(bundle)
    if not report.is_valid:
        typer.echo("Refusing to push an invalid bundle:\n  " + "\n  ".join(report.errors), err=True)
        raise typer.Exit(1)
    try:
        with _client(True) as c:
            status = c.add_objects(api_root, collection_id, bundle["objects"])
    except TaxiiError as exc:
        typer.echo(f"TAXII error: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(
        f"status={status.get('status')} success={status.get('success_count')} "
        f"failure={status.get('failure_count')} pending={status.get('pending_count')}"
    )


@stix_app.command("demo-bundle")
def stix_demo_bundle(
    out: Path = typer.Option(Path("demo-bundle.json"), help="Where to write the bundle"),
) -> None:
    """Build the TLP:CLEAR demo bundle (indicator -> indicates -> malware) and validate it."""
    bundle = build_demo_bundle()
    report = validate(bundle)
    out.write_text(bundle.serialize(pretty=True), encoding="utf-8")
    typer.echo(f"Wrote {out} ({len(bundle.objects)} objects); valid={report.is_valid}")
    for line in report.errors + report.warnings:
        typer.echo(f"  {line}")
    if not report.is_valid:
        raise typer.Exit(1)


def _misp():  # -> MispSearch
    from hexbrief.collectors.misp import connect

    _load_env_file()
    url, key = os.environ.get("MISP_URL", ""), os.environ.get("MISP_API_KEY", "")
    if not url or not key or key == "__replace_me__":
        raise typer.BadParameter("MISP_URL / MISP_API_KEY not set in .env")
    raw_verify = os.environ.get("MISP_VERIFY_SSL", "true")
    # true/false, or a path to MISP's certificate (preferred for the self-signed lab cert)
    verify: bool | str = {"true": True, "false": False}.get(raw_verify.lower(), raw_verify)
    if verify is False:
        typer.echo("WARNING: TLS verification is off for MISP (lab only).", err=True)
    return connect(url, key, verify=verify)


@misp_app.command("recent")
def misp_recent(
    hours: int = typer.Option(24, help="Window in hours (by publish time)"),
    all_attributes: bool = typer.Option(False, help="Include non-IDS context attributes"),
) -> None:
    """Summarize what MISP published in the window (counts only, no values)."""
    from hexbrief.collectors.misp import collect_window

    window = collect_window(_misp(), hours=hours, ids_only=not all_attributes)
    typer.echo(f"Window: last {hours} h")
    typer.echo(f"Events published: {len(window.events)}")
    for ev in window.events[:10]:
        typer.echo(f"  #{ev.get('id')}  {str(ev.get('info', ''))[:90]}")
    typer.echo(
        f"Attributes: {len(window.attributes)} ({window.ids_attributes} to_ids, "
        f"{window.warninglist_hits} warninglist hits)"
    )
    for attr_type, n in window.attribute_types.most_common(10):
        typer.echo(f"  {n:>6}  {attr_type}")


@misp_app.command("stix")
def misp_stix(
    event_id: str = typer.Argument(..., help="MISP event id"),
    out: Path = typer.Option(Path("misp-event.stix.json"), help="Output file"),
) -> None:
    """Export one MISP event as a STIX 2.1 bundle and validate it."""
    from hexbrief.collectors.misp import event_as_stix

    bundle = event_as_stix(_misp(), event_id)
    report = validate(bundle)
    out.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    types = count_by_type(bundle.get("objects", []))
    typer.echo(f"Wrote {out}: {sum(types.values())} objects, valid={report.is_valid}")
    for stix_type, n in types.most_common():
        typer.echo(f"  {n:>5}  {stix_type}")
    for line in report.errors[:10]:
        typer.echo(f"  ERROR {line}")


@opencti_app.command("recent")
def opencti_recent(hours: int = typer.Option(24, help="Window in hours (by updated_at)")) -> None:
    """Counts of reports, indicators, vulnerabilities, malware and intrusion sets updated."""
    from hexbrief.collectors.opencti import collect_window, connect

    _load_env_file()
    url, token = os.environ.get("OPENCTI_URL", ""), os.environ.get("OPENCTI_TOKEN", "")
    if not url or not token or token == "__replace_me__":  # noqa: S105 - placeholder check
        raise typer.BadParameter("OPENCTI_URL / OPENCTI_TOKEN not set in .env")
    window = collect_window(connect(url, token), hours=hours)
    typer.echo(f"Window: updated since {window.since}")
    for kind, n in window.counts.items():
        typer.echo(f"  {n:>6}  {kind}")
    typer.echo("By author (top 10):")
    for author, n in window.sources.most_common(10):
        typer.echo(f"  {n:>6}  {author}")


@app.command("run")
def run_brief(
    date: str = typer.Option("today", help="'today' (now) or YYYY-MM-DD (window ends 07:00 MYT)"),
    hours: int = typer.Option(24, help="Window length in hours"),
    top: int = typer.Option(8, help="Findings sent to the LLM"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Facts-only brief, no model"),
    out: Path = typer.Option(Path("out"), help="Output root (git-ignored)"),
) -> None:
    """Build today's brief: collect, score, write (local LLM), validate, render."""
    import logging
    from datetime import UTC, datetime
    from zoneinfo import ZoneInfo

    from hexbrief.engine import run, write_outputs
    from hexbrief.llm.client import OllamaWriter
    from hexbrief.pipeline import build_collectors

    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    _load_env_file()
    if date == "today":
        now = datetime.now(UTC)
    else:
        day = datetime.strptime(date, "%Y-%m-%d").replace(
            hour=7, tzinfo=ZoneInfo("Asia/Kuala_Lumpur")
        )
        now = day.astimezone(UTC)
    collectors, enrich = build_collectors()
    host = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")
    writer = fallback = None
    if not no_llm:
        writer = OllamaWriter(os.environ.get("OLLAMA_MODEL", "qwen3.5:4b"), host=host)
        fb = os.environ.get("OLLAMA_FALLBACK_MODEL")
        fallback = OllamaWriter(fb, host=host) if fb else None
    try:
        result = run(
            collectors,
            now=now,
            hours=hours,
            top_n=top,
            writer=writer,
            fallback_writer=fallback,
            enrich=enrich,
        )
    finally:
        for w in (writer, fallback):
            if w is not None:
                w.close()
    paths = write_outputs(result, out / result.day, Path("runs"))
    rl = result.run_log
    for name, s in rl["sources"].items():
        status = f"{s['findings']} findings" if s.get("ok") else f"FAILED ({s.get('error')})"
        typer.echo(f"  source {name:9} {status}")
    typer.echo(
        f"findings {rl['findings_in']} -> {rl['after_dedupe']} after dedupe; "
        f"top {len(result.top)} to the LLM"
    )
    llm = rl["llm"]
    typer.echo(
        f"LLM: {'validated narrative' if result.llm_ok else 'FACTS-ONLY fallback'} "
        f"after {len(llm['attempts'])} attempt(s); first try "
        f"{'passed' if llm['first_try_pass'] else 'failed'}"
    )
    typer.echo(
        f"TLP {result.tlp}; STIX valid: {rl.get('stix_valid')}; runtime {rl['runtime_seconds']}s"
    )
    for k, p in paths.items():
        typer.echo(f"  {k:6} {p}")


if __name__ == "__main__":  # pragma: no cover
    app()
