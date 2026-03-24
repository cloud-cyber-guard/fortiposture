#!/usr/bin/env python3
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

"""FortiManager bulk export companion script.

Connects to a FortiManager instance via API token and downloads .conf backups
for all managed devices. Output files are saved to --output directory for use
with `fortiposture scan`.

Usage:
    python fmg_export.py --host 10.1.1.1 --token <api_token> --output ./configs

Requirements:
    pip install pyfortimanager
"""

import sys
from pathlib import Path

import typer

app = typer.Typer(
    name="fmg-export",
    help="Export FortiGate configs from FortiManager via API.",
    add_completion=False,
)


@app.command()
def export(
    host: str = typer.Option(..., "--host", help="FortiManager hostname or IP."),
    token: str = typer.Option(..., "--token", help="FortiManager API token (never username/password)."),
    output: Path = typer.Option(
        Path("./configs"), "--output", "-o",
        help="Directory to save exported .conf files.",
    ),
    adom: str = typer.Option("root", "--adom", help="FortiManager ADOM name."),
    no_ssl_verify: bool = typer.Option(False, "--no-ssl-verify", help="Disable SSL certificate verification."),
    port: int = typer.Option(443, "--port", help="FortiManager HTTPS port."),
):
    """Export FortiGate .conf backups from FortiManager."""
    try:
        import pyfortimanager
    except ImportError:
        typer.echo(
            "ERROR: pyfortimanager is not installed. "
            "Install with: pip install pyfortimanager",
            err=True,
        )
        raise typer.Exit(1)

    output.mkdir(parents=True, exist_ok=True)
    typer.echo(f"Connecting to FortiManager at {host}:{port} (ADOM: {adom}) ...")

    try:
        fmg = pyfortimanager.api(
            host=host,
            token=token,
            port=port,
            disable_request_warnings=no_ssl_verify,
            verify=not no_ssl_verify,
        )
    except Exception as e:
        typer.echo(f"ERROR: Failed to connect to FortiManager: {e}", err=True)
        raise typer.Exit(1)

    # List managed devices
    try:
        response = fmg.get_devices(adom=adom)
        devices = response.get("result", [{}])[0].get("data", []) or []
    except Exception as e:
        typer.echo(f"ERROR: Failed to list devices: {e}", err=True)
        raise typer.Exit(1)

    if not devices:
        typer.echo(f"No devices found in ADOM '{adom}'.")
        raise typer.Exit(0)

    typer.echo(f"Found {len(devices)} device(s). Exporting configs ...")
    exported = 0
    failed = 0

    for dev in devices:
        name = dev.get("name") or dev.get("hostname") or "unknown"
        try:
            result = fmg.exec_script(
                adom=adom,
                device=name,
                script="show full-configuration",
            )
            config_text = result.get("result", [{}])[0].get("data", {}).get("output", "")
            if not config_text:
                typer.echo(f"  WARNING: Empty config for {name}", err=True)
                failed += 1
                continue
            out_file = output / f"{name}.conf"
            out_file.write_text(config_text, encoding="utf-8")
            typer.echo(f"  Exported: {out_file}")
            exported += 1
        except Exception as e:
            typer.echo(f"  ERROR exporting {name}: {e}", err=True)
            failed += 1

    typer.echo(f"\nDone. Exported: {exported}, Failed: {failed}")
    if failed:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
