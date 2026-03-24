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

import csv
import io
import pytest
from pathlib import Path
from tests.conftest import ingest_fixture
from fortiposture.analysis.checks import run_all_checks
from fortiposture.analysis.scoring import calculate_score
from fortiposture.output.html_report import generate_html_report
from fortiposture.output.csv_export import export_findings_csv


def test_html_report_generates(db_session, tmp_path):
    devices = ingest_fixture("simple_policy.conf", db_session)
    findings = run_all_checks(devices[0], db_session)
    out = tmp_path / "report.html"
    generate_html_report(devices, db_session, out)
    assert out.exists()
    assert out.stat().st_size > 1000


def test_html_report_contains_hostname(db_session, tmp_path):
    devices = ingest_fixture("simple_policy.conf", db_session)
    run_all_checks(devices[0], db_session)
    out = tmp_path / "report.html"
    generate_html_report(devices, db_session, out)
    content = out.read_text()
    assert "fw-clean-01" in content


def test_html_report_self_contained(db_session, tmp_path):
    """Report must not load external CSS, JS, or font assets (CDN/unpkg/etc).
    Footer links to AGPL/GitHub are allowed — they are hyperlinks, not asset loads."""
    devices = ingest_fixture("simple_policy.conf", db_session)
    run_all_checks(devices[0], db_session)
    out = tmp_path / "report.html"
    generate_html_report(devices, db_session, out)
    content = out.read_text()
    # No external CSS or JS asset loads
    assert "cdn.jsdelivr.net" not in content
    assert "unpkg.com" not in content
    assert "cdnjs.cloudflare.com" not in content
    assert '<script src="http' not in content
    assert '<link rel="stylesheet" href="http' not in content


def test_csv_export_columns(db_session, tmp_path):
    devices = ingest_fixture("any_any_rule.conf", db_session)
    findings = run_all_checks(devices[0], db_session)
    out = tmp_path / "findings.csv"
    export_findings_csv(findings, out)
    with open(out) as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) > 0
    expected_cols = {"device", "check_id", "severity", "title", "affected_object", "description"}
    assert expected_cols.issubset(set(rows[0].keys()))


def test_csv_handles_none_values(db_session, tmp_path):
    devices = ingest_fixture("simple_policy.conf", db_session)
    findings = run_all_checks(devices[0], db_session)
    out = tmp_path / "findings.csv"
    export_findings_csv(findings, out)
    content = out.read_text()
    assert "None" not in content


def test_score_floor_at_zero():
    score, grade = calculate_score(critical=10, high=10, medium=10, low=10)
    assert score == 0


def test_grade_boundaries():
    assert calculate_score(0, 0, 0, 0) == (100, "A")
    assert calculate_score(0, 1, 0, 0) == (90, "A")
    assert calculate_score(0, 2, 1, 0) == (75, "B")
    assert calculate_score(0, 4, 0, 0) == (60, "C")
    assert calculate_score(0, 6, 0, 0) == (40, "D")
    assert calculate_score(0, 7, 0, 0) == (30, "F")
