# fortiposture

> Offline security posture assessment for FortiGate firewall configuration backups.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://www.python.org/)

`fortiposture` is an open source CLI tool that ingests FortiGate firewall configuration backup files (`.conf` format), parses them, runs automated security posture checks against 11 rule categories, stores all results in a local SQLite database, and generates a self-contained HTML report. It works **entirely offline** — no live firewall connections required.

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Getting Your Config Files](#getting-your-config-files)
- [Usage](#usage)
  - [scan command](#scan-command)
  - [All options](#all-options)
  - [FortiManager bulk export](#fortimanager-bulk-export)
- [Security Checks](#security-checks)
- [Scoring & Grading](#scoring--grading)
- [HTML Report](#html-report)
- [CSV Export](#csv-export)
- [Database](#database)
- [Architecture](#architecture)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Parse FortiGate `.conf` files** — handles nested config blocks, multi-value sets, quoted values, VDOM-aware configs, and varying firmware versions
- **11 security checks** across policy rules, admin accounts, logging, and password policy
- **CRITICAL / HIGH / MEDIUM / LOW** severity classification with per-check remediation steps and compliance references (NIST, PCI DSS, CIS)
- **Posture scoring** (0–100) with letter grades (A–F)
- **Self-contained HTML report** — single file, dark/light mode, sortable tables, expandable findings — no CDN or external dependencies
- **CSV export** for integration with spreadsheets and SIEMs
- **SQLite persistence** — results accumulate across runs; re-importing the same file is idempotent (hash-checked)
- **FortiManager companion** (`fmg_export.py`) for bulk config export across managed devices

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/cloud-cyber-guard/fortiposture.git
cd fortiposture
python -m venv .venv && source .venv/bin/activate
pip install -e .

# 2. Point it at a directory of .conf files
python main.py scan --input-dir ./configs --output report.html

# 3. Open report.html in your browser
```

Terminal output:

```
fortiposture — scanning 3 file(s) in ./configs

  Parsing fw-core.conf ... 1 device(s)
  Parsing fw-edge.conf ... 1 device(s)
  Parsing fw-dmz.conf  ... 1 device(s)

  Checking fw-core-01 ... 2 critical, 5 high, 1 medium
  Checking fw-edge-01 ... 1 critical, 3 high, 2 medium
  Checking fw-dmz-01  ... clean

  ╭─────────────┬──────────┬──────────┬──────┬────────┬─────┬───────┬───────╮
  │ Device      │ Policies │ Critical │ High │ Medium │ Low │ Score │ Grade │
  ├─────────────┼──────────┼──────────┼──────┼────────┼─────┼───────┼───────┤
  │ fw-core-01  │       18 │        2 │    5 │      1 │   0 │    30 │   F   │
  │ fw-edge-01  │       12 │        1 │    3 │      2 │   0 │    50 │   D   │
  │ fw-dmz-01   │        6 │        0 │    0 │      2 │   0 │    90 │   A   │
  ╰─────────────┴──────────┴──────────┴──────┴────────┴─────┴───────┴───────╯

Report written: report.html
```

---

## Installation

### From source (recommended for now)

```bash
git clone https://github.com/cloud-cyber-guard/fortiposture.git
cd fortiposture
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e .
```

### Requirements

- Python 3.11+
- Dependencies are installed automatically via `pip install -e .`

| Package | Purpose |
|---------|---------|
| `sqlalchemy >= 2.0` | ORM and SQLite persistence |
| `typer >= 0.12` | CLI argument parsing |
| `rich >= 13.0` | Terminal formatting and tables |
| `alembic >= 1.13` | Database migrations |

For FortiManager export only:

```bash
pip install -e ".[fmg]"   # adds pyfortimanager
```

### Verify installation

```bash
python main.py --help
```

---

## Getting Your Config Files

`fortiposture` works with FortiGate full configuration backup files. These are the same files you get from **System > Configuration > Backup** in the FortiGate web UI, or via CLI:

```bash
execute backup config tftp <filename> <tftp-server-ip>
# or
execute backup full-config flash <filename>
```

Save files with a `.conf` extension and place them in a directory:

```
configs/
├── fw-core.conf
├── fw-edge.conf
└── fw-dmz.conf
```

> **Note:** `fortiposture` never connects to live firewalls during analysis. All processing is done from the static backup file.

---

## Usage

### scan command

```bash
python main.py scan --input-dir <path> --output <report.html>
```

Scans all `.conf` files in `--input-dir`, runs all security checks, and writes an HTML report.

### All options

| Option | Default | Description |
|--------|---------|-------------|
| `--input-dir` / `-i` | *(required)* | Directory containing `.conf` files |
| `--output` / `-o` | `report.html` | Output HTML report path |
| `--db` | `fortiposture.db` | SQLite database path |
| `--csv` | — | Export all findings to a single CSV file |
| `--csv-dir` | — | Export per-device CSV files to this directory |
| `--severity` | — | Filter findings to this severity and above (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`) |
| `--device` | — | Only report on devices matching this hostname (substring) |
| `--fresh` | `false` | Drop and recreate the database before scanning |
| `--no-color` | `false` | Disable color terminal output |
| `--quiet` / `-q` | `false` | Suppress progress output; only print errors |

### Examples

```bash
# Basic scan
python main.py scan --input-dir ./configs

# Save report and CSV
python main.py scan --input-dir ./configs --output reports/june.html --csv reports/june.csv

# Only show CRITICAL and HIGH findings
python main.py scan --input-dir ./configs --severity HIGH

# Target a specific device
python main.py scan --input-dir ./configs --device fw-core

# Fresh scan (drop previous results)
python main.py scan --input-dir ./configs --fresh

# Per-device CSVs for ticket creation
python main.py scan --input-dir ./configs --csv-dir ./findings/
```

### FortiManager bulk export

If you manage multiple FortiGates through FortiManager, use the companion script to pull all configs at once:

```bash
python fmg_export.py --host 10.1.1.1 --token <api_token> --output ./configs
```

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | *(required)* | FortiManager IP or hostname |
| `--token` | *(required)* | API token (never username/password) |
| `--output` / `-o` | `./configs` | Directory to save `.conf` files |
| `--adom` | `root` | FortiManager ADOM name |
| `--port` | `443` | HTTPS port |
| `--no-ssl-verify` | `false` | Disable SSL certificate verification |

> **Security note:** Only API tokens are accepted. Username/password authentication is intentionally not supported.

---

## Security Checks

`fortiposture` runs 11 checks across four categories. See [docs/checks.md](docs/checks.md) for full details on each check including evidence format, remediation steps, and compliance mappings.

### Policy checks

| Check ID | Severity | Condition |
|----------|----------|-----------|
| `ANY_ANY_RULE` | 🔴 CRITICAL | ACCEPT rule with src=any, dst=any, service=ALL |
| `LOGGING_DISABLED` | 🟠 HIGH | ACCEPT rule with traffic logging disabled |
| `SHADOWED_RULE` | 🟠 HIGH | Rule that can never be matched — a broader ACCEPT rule above it covers the same traffic space |
| `RISKY_SERVICE_EXPOSED` | 🟠 HIGH | ACCEPT rule permitting Telnet (23), FTP (21), RDP (3389), TFTP (69), SMB (445), NetBIOS (139), MSSQL (1433), MySQL (3306), or VNC (5900) |
| `MISSING_DENY_ALL` | 🟠 HIGH | No explicit deny-all as the final rule in the policy list |
| `BROAD_DESTINATION` | 🟡 MEDIUM | ACCEPT rule with specific source but destination=any |
| `DISABLED_POLICY` | 🟢 LOW | ACCEPT rule that is disabled (rule bloat indicator) |

### Admin account checks

| Check ID | Severity | Condition |
|----------|----------|-----------|
| `ADMIN_NO_MFA` | 🔴 CRITICAL | Local password admin without two-factor authentication |
| `ADMIN_UNRESTRICTED_ACCESS` | 🟠 HIGH | Admin account with no trusted hosts configured |

### Logging checks

| Check ID | Severity | Condition |
|----------|----------|-----------|
| `LOGGING_NOT_CONFIGURED` | 🟡 MEDIUM | No external logging destination (syslog, FortiAnalyzer, or FortiCloud) enabled |

### Password policy checks

| Check ID | Severity | Condition |
|----------|----------|-----------|
| `WEAK_PASSWORD_POLICY` | 🟡 MEDIUM | Password policy not configured, or minimum length < 8 |

---

## Scoring & Grading

Each device starts at a score of 100. Points are deducted per finding:

| Severity | Deduction per finding |
|----------|-----------------------|
| CRITICAL | −20 (floor: 0) |
| HIGH | −10 |
| MEDIUM | −5 |
| LOW | −2 |

Letter grades:

| Grade | Score range |
|-------|-------------|
| **A** | 90–100 |
| **B** | 75–89 |
| **C** | 60–74 |
| **D** | 40–59 |
| **F** | 0–39 |

---

## HTML Report

The report is a **single self-contained HTML file** — no external dependencies, no CDN, no fonts loaded from the internet. It can be emailed, archived, or opened offline.

**Report structure:**

- **Header** — timestamp, device count, aggregate stats
- **Summary stats** — total critical/high/medium/low across all devices
- **Executive summary table** — sortable by any column; device, policy count, finding counts by severity, posture score and grade
- **Per-device sections:**
  - Score gauge with letter grade
  - Policy and admin account counts
  - Expandable findings — each finding shows description, numbered remediation steps, compliance references, and raw evidence JSON

**Design:**
- Respects `prefers-color-scheme` — dark mode by default, light mode for print
- Print-friendly (expanded findings don't collapse on print)
- No JavaScript required to read; JS only enables table sorting

---

## CSV Export

CSV files contain one row per finding with the following columns:

| Column | Description |
|--------|-------------|
| `device` | Device hostname |
| `check_id` | Check identifier (e.g. `ANY_ANY_RULE`) |
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `title` | Short finding title |
| `affected_object` | Policy name, admin username, or config section |
| `description` | Full finding description |
| `remediation` | Numbered remediation steps |
| `references` | JSON array of compliance references |
| `evidence` | JSON object with raw config values that triggered the finding |

Use `--csv` for a single file covering all devices, or `--csv-dir` to get one file per device.

---

## Database

Results are stored in a SQLite database (`fortiposture.db` by default). The database accumulates findings across runs — re-importing the same config file is safe and idempotent (the file hash is checked before ingestion).

Key tables:

| Table | Contents |
|-------|----------|
| `device` | Hostname, firmware version, source file, import timestamp |
| `firewall_policy` | All parsed policies with action, status, logging, NAT |
| `address_object` | Named address objects |
| `service_object` | Named service objects with port ranges |
| `admin_account` | Admin usernames, auth type, MFA status, trusted hosts |
| `logging_config` | Syslog/FortiAnalyzer/FortiCloud settings |
| `finding` | All check results with severity, description, remediation, evidence |
| `posture_score` | Score and grade per analysis run |
| `analysis_run` | Timestamps and check list for each run |

Use `--fresh` to wipe and recreate the database. Use `--db <path>` to maintain separate databases per project or environment.

---

## Architecture

See [docs/architecture.md](docs/architecture.md) for the full pipeline diagram and module reference.

**At a glance:**

```
.conf files  →  Parser  →  Normalizer  →  SQLite DB  →  Checks  →  Scorer  →  Report
```

1. **Parser** (`fortiposture/parser/conf_parser.py`) — converts raw `.conf` text into a nested Python dict; handles VDOM-aware configs, multi-value sets, quoted strings, nested blocks
2. **Normalizer** (`fortiposture/parser/normalizer.py`) — maps the parsed dict to SQLAlchemy ORM model instances; handles address/service/policy/admin/logging/interface ingestion; idempotent via file hash
3. **Database** (`fortiposture/database.py`) — SQLite via SQLAlchemy ORM; all tables defined in `fortiposture/models/schema.py`
4. **Checks** (`fortiposture/analysis/checks.py`) — 11 independent check functions, each returning a list of `Finding` objects; orchestrated by `run_all_checks()`
5. **Scorer** (`fortiposture/analysis/scoring.py`) — pure function, deducts points by severity, returns (score, grade)
6. **Report** (`fortiposture/output/html_report.py`) — generates the self-contained HTML; `fortiposture/output/csv_export.py` handles CSV

---

## Development

### Setup

```bash
git clone https://github.com/cloud-cyber-guard/fortiposture.git
cd fortiposture
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Run tests

```bash
pytest tests/ -v
pytest tests/ -v --cov=fortiposture --cov-report=term-missing
```

### Project structure

```
fortiposture/
├── main.py                         # CLI shim (python main.py scan ...)
├── fmg_export.py                   # FortiManager bulk export
├── pyproject.toml
├── requirements.txt
├── fortiposture/
│   ├── __init__.py
│   ├── cli.py                      # typer app (scan command)
│   ├── database.py                 # engine, session factory
│   ├── parser/
│   │   ├── conf_parser.py          # .conf → nested dict
│   │   └── normalizer.py           # nested dict → ORM models
│   ├── models/
│   │   └── schema.py               # SQLAlchemy ORM (all tables)
│   ├── analysis/
│   │   ├── checks.py               # 11 security checks
│   │   └── scoring.py              # score + grade calculation
│   └── output/
│       ├── html_report.py          # self-contained HTML report
│       └── csv_export.py           # CSV findings export
├── tests/
│   ├── conftest.py                 # shared pytest fixtures
│   ├── fixtures/                   # synthetic .conf test files
│   │   ├── simple_policy.conf      # clean — 0 expected findings
│   │   ├── any_any_rule.conf       # triggers ANY_ANY_RULE
│   │   ├── shadowed_rules.conf     # triggers SHADOWED_RULE
│   │   ├── missing_deny_all.conf   # triggers MISSING_DENY_ALL
│   │   ├── weak_admin.conf         # triggers ADMIN_NO_MFA + ADMIN_UNRESTRICTED_ACCESS
│   │   └── multi_vdom.conf         # VDOM-aware config
│   ├── test_parser.py
│   ├── test_normalizer.py
│   ├── test_schema.py
│   ├── test_checks.py
│   └── test_output.py
└── docs/
    ├── checks.md                   # detailed check reference
    └── architecture.md             # pipeline and data flow
```

### Adding a new check

1. Add a function `check_<name>(device, session) -> List[Finding]` in `fortiposture/analysis/checks.py`
2. Add the function to the `ALL_CHECKS` list at the bottom of the file
3. Add a test fixture if a new config pattern is needed
4. Add a test in `tests/test_checks.py`
5. Document the check in `docs/checks.md`

---

## Contributing

Contributions are welcome. Please:

1. Fork the repository and create a feature branch
2. Write tests for any new check or behaviour
3. Ensure `pytest tests/ -v` passes
4. Open a pull request with a description of what the check detects and why it matters

---

## License

`fortiposture` is licensed under the [GNU Affero General Public License v3.0](LICENSE).

Copyright (C) 2026 cloud-cyber-guard

> This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

---

> **Disclaimer:** This tool is provided for informational and audit purposes only. Findings should be reviewed by a qualified network security engineer before any remediation actions are taken. The authors accept no liability for actions taken based on this tool's output.
