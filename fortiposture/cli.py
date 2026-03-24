# fortiposture — FortiGate firewall configuration security posture assessment
# Copyright (C) 2026 cloud-cyber-guard
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""CLI entry point for fortiposture (typer app)."""

import logging
import sys
from pathlib import Path
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import box

from fortiposture.database import get_engine, init_db, drop_db, get_session
from fortiposture.parser.conf_parser import FortiConfParser as FortiParser
from fortiposture.parser.normalizer import FortiNormalizer
from fortiposture.analysis.checks import run_all_checks
from fortiposture.models.schema import Device, PostureScore
from fortiposture.output.html_report import generate_html_report
from fortiposture.output.csv_export import export_findings_csv

app = typer.Typer(
    name="fortiposture",
    help="FortiGate firewall configuration security posture assessment.",
    add_completion=False,
    invoke_without_command=True,
)


@app.callback()
def _callback(ctx: typer.Context):
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_GRADE_COLORS = {"A": "green", "B": "cyan", "C": "yellow", "D": "dark_orange", "F": "red"}
_SEV_COLORS = {"CRITICAL": "red", "HIGH": "dark_orange", "MEDIUM": "blue", "LOW": "green"}


@app.command()
def scan(
    input_dir: Path = typer.Option(
        ..., "--input-dir", "-i",
        help="Directory containing .conf files.",
        exists=True, file_okay=False, dir_okay=True, resolve_path=True,
    ),
    output: Path = typer.Option(
        Path("report.html"), "--output", "-o",
        help="Output HTML report path.",
    ),
    db: Path = typer.Option(
        Path("fortiposture.db"), "--db",
        help="SQLite database path.",
    ),
    csv_out: Optional[Path] = typer.Option(
        None, "--csv",
        help="Export all findings to a single CSV file.",
    ),
    csv_dir: Optional[Path] = typer.Option(
        None, "--csv-dir",
        help="Export per-device CSV files to this directory.",
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity",
        help="Filter findings to this severity and above (CRITICAL/HIGH/MEDIUM/LOW).",
    ),
    device_filter: Optional[str] = typer.Option(
        None, "--device",
        help="Only report on devices matching this hostname (substring match).",
    ),
    fresh: bool = typer.Option(
        False, "--fresh",
        help="Drop and recreate the database before scanning.",
    ),
    no_color: bool = typer.Option(
        False, "--no-color",
        help="Disable color output.",
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q",
        help="Suppress progress output; only print errors.",
    ),
):
    """Scan FortiGate .conf files and generate a security posture report."""
    console = Console(no_color=no_color, stderr=False)
    err_console = Console(stderr=True, no_color=no_color)

    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    # --- Database setup ---
    engine = get_engine(db)
    if fresh:
        if not quiet:
            console.print(f"[yellow]Dropping database: {db}[/yellow]")
        drop_db(engine)
    init_db(engine)
    session = get_session(engine)

    # --- Discover .conf files ---
    conf_files = sorted(input_dir.glob("*.conf"))
    if not conf_files:
        err_console.print(f"[red]No .conf files found in {input_dir}[/red]")
        raise typer.Exit(1)

    if not quiet:
        console.print(f"\n[bold]fortiposture[/bold] — scanning {len(conf_files)} file(s) in [cyan]{input_dir}[/cyan]\n")

    parser = FortiParser()
    normalizer = FortiNormalizer()
    all_devices: List[Device] = []
    all_findings = []

    # --- Parse & ingest ---
    for conf_file in conf_files:
        if not quiet:
            console.print(f"  [dim]Parsing[/dim] {conf_file.name} ...", end=" ")
        try:
            parsed = parser.parse_file(conf_file)
            devices = normalizer.ingest(parsed, conf_file, session)
            if not quiet:
                console.print(f"[green]{len(devices)} device(s)[/green]")
        except Exception as e:
            if not quiet:
                console.print(f"[red]ERROR[/red]")
            err_console.print(f"  [red]Failed to parse {conf_file.name}: {e}[/red]")
            continue

        # Filter by device hostname if requested
        if device_filter:
            devices = [d for d in devices if device_filter.lower() in d.hostname.lower()]

        all_devices.extend(devices)

    if not all_devices:
        err_console.print("[red]No devices ingested.[/red]")
        raise typer.Exit(1)

    # --- Run checks ---
    if not quiet:
        console.print()

    for device in all_devices:
        if not quiet:
            console.print(f"  [dim]Checking[/dim] {device.hostname} ...", end=" ")
        try:
            findings = run_all_checks(device, session)
            if severity:
                min_order = _SEVERITY_ORDER.get(severity.upper(), 3)
                findings = [f for f in findings if _SEVERITY_ORDER.get(f.severity, 99) <= min_order]
            all_findings.extend(findings)
            if not quiet:
                counts = {s: sum(1 for f in findings if f.severity == s) for s in _SEVERITY_ORDER}
                parts = [f"[{_SEV_COLORS[s]}]{counts[s]} {s.lower()}[/{_SEV_COLORS[s]}]" for s in _SEVERITY_ORDER if counts[s]]
                console.print(", ".join(parts) if parts else "[green]clean[/green]")
        except Exception as e:
            if not quiet:
                console.print("[red]ERROR[/red]")
            err_console.print(f"  [red]Check failed for {device.hostname}: {e}[/red]")

    session.commit()

    # --- Rich summary table ---
    if not quiet:
        console.print()
        _print_summary_table(console, all_devices, session)

    # --- HTML report ---
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    generate_html_report(all_devices, session, output)
    if not quiet:
        console.print(f"\n[bold green]Report written:[/bold green] {output}")

    # --- CSV export ---
    if csv_out:
        csv_out = Path(csv_out)
        csv_out.parent.mkdir(parents=True, exist_ok=True)
        export_findings_csv(all_findings, csv_out)
        if not quiet:
            console.print(f"[bold green]CSV written:[/bold green] {csv_out}")

    if csv_dir:
        csv_dir = Path(csv_dir)
        csv_dir.mkdir(parents=True, exist_ok=True)
        for device in all_devices:
            device_findings = [f for f in all_findings if f.device_id == device.id]
            safe_name = device.hostname.replace("/", "_")
            out_csv = csv_dir / f"{safe_name}.csv"
            export_findings_csv(device_findings, out_csv)
        if not quiet:
            console.print(f"[bold green]Per-device CSVs written to:[/bold green] {csv_dir}")

    session.close()


def _print_summary_table(console: Console, devices: List[Device], session) -> None:
    table = Table(
        title="Security Posture Summary",
        box=box.ROUNDED,
        show_lines=False,
        highlight=True,
    )
    table.add_column("Device", style="bold")
    table.add_column("Policies", justify="right")
    table.add_column("Critical", justify="right", style="red")
    table.add_column("High", justify="right", style="dark_orange")
    table.add_column("Medium", justify="right", style="blue")
    table.add_column("Low", justify="right", style="green")
    table.add_column("Score", justify="right", style="bold")
    table.add_column("Grade", justify="center")

    for device in devices:
        score_obj = (
            session.query(PostureScore)
            .filter_by(device_id=device.id)
            .order_by(PostureScore.id.desc())
            .first()
        )
        score = str(score_obj.score) if score_obj else "N/A"
        grade = score_obj.grade if score_obj else "N/A"
        grade_color = _GRADE_COLORS.get(grade, "white")
        table.add_row(
            device.hostname,
            str(len(device.policies)),
            str(score_obj.critical_count if score_obj else 0),
            str(score_obj.high_count if score_obj else 0),
            str(score_obj.medium_count if score_obj else 0),
            str(score_obj.low_count if score_obj else 0),
            score,
            f"[{grade_color}]{grade}[/{grade_color}]",
        )

    console.print(table)
