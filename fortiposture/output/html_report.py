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

"""Self-contained HTML report generator for fortiposture."""

import html
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from sqlalchemy.orm import Session

from fortiposture.models.schema import Device, Finding, PostureScore


_SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#d97706",
    "MEDIUM": "#2563eb",
    "LOW": "#16a34a",
}

_CSS = """
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg: #0f172a; --surface: #1e293b; --border: #334155;
  --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8;
  --critical: #dc2626; --high: #d97706; --medium: #2563eb; --low: #16a34a;
}
@media (prefers-color-scheme: light) {
  :root {
    --bg: #f8fafc; --surface: #ffffff; --border: #e2e8f0;
    --text: #0f172a; --muted: #64748b; --accent: #0284c7;
  }
}
body { background: var(--bg); color: var(--text); font-family: system-ui, sans-serif; font-size: 14px; line-height: 1.6; }
a { color: var(--accent); }
.container { max-width: 1200px; margin: 0 auto; padding: 24px 16px; }
header { border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px; }
header h1 { font-size: 22px; font-weight: 700; color: var(--accent); }
header p { color: var(--muted); font-size: 12px; margin-top: 4px; }
.stats { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
.stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px 20px; flex: 1; min-width: 140px; }
.stat-card .label { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }
.stat-card .value { font-size: 28px; font-weight: 700; margin-top: 4px; }
table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); margin-bottom: 24px; }
th { background: var(--border); text-align: left; padding: 10px 14px; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; color: var(--muted); cursor: pointer; user-select: none; }
th:hover { color: var(--text); }
td { padding: 10px 14px; border-top: 1px solid var(--border); vertical-align: top; }
tr:hover td { background: rgba(255,255,255,.03); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; color: #fff; }
.badge-CRITICAL { background: var(--critical); }
.badge-HIGH { background: var(--high); }
.badge-MEDIUM { background: var(--medium); }
.badge-LOW { background: var(--low); }
.badge-A { background: var(--low); }
.badge-B { background: #0891b2; }
.badge-C { background: var(--medium); }
.badge-D { background: var(--high); }
.badge-F { background: var(--critical); }
.device-section { margin-bottom: 40px; }
.device-header { display: flex; align-items: center; gap: 16px; margin-bottom: 16px; flex-wrap: wrap; }
.device-header h2 { font-size: 18px; font-weight: 600; }
.score-gauge { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 12px 20px; display: flex; align-items: center; gap: 16px; }
.score-number { font-size: 32px; font-weight: 700; }
details { border: 1px solid var(--border); border-radius: 6px; margin-bottom: 4px; overflow: hidden; }
details summary { padding: 8px 14px; cursor: pointer; list-style: none; display: flex; align-items: center; gap: 10px; }
details summary::-webkit-details-marker { display: none; }
details[open] summary { border-bottom: 1px solid var(--border); background: rgba(255,255,255,.03); }
.finding-body { padding: 14px; background: var(--surface); }
.finding-body h4 { color: var(--muted); font-size: 11px; text-transform: uppercase; margin-bottom: 4px; margin-top: 12px; }
.finding-body h4:first-child { margin-top: 0; }
.finding-body pre { background: var(--bg); border: 1px solid var(--border); border-radius: 4px; padding: 10px; font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; }
.finding-body ol { padding-left: 20px; }
.finding-body li { margin-bottom: 4px; }
.tag-list { display: flex; gap: 6px; flex-wrap: wrap; }
.tag { background: var(--border); border-radius: 4px; padding: 2px 8px; font-size: 11px; color: var(--muted); }
footer { border-top: 1px solid var(--border); padding-top: 16px; margin-top: 32px; color: var(--muted); font-size: 11px; text-align: center; }
@media print {
  details { break-inside: avoid; }
  details[open] { display: block; }
}
"""

_JS = """
function sortTable(table, col) {
  var rows = Array.from(table.querySelectorAll('tbody tr'));
  var asc = table.dataset.sortCol == col && table.dataset.sortDir == 'asc';
  rows.sort(function(a, b) {
    var av = a.cells[col] ? a.cells[col].textContent.trim() : '';
    var bv = b.cells[col] ? b.cells[col].textContent.trim() : '';
    var an = parseFloat(av), bn = parseFloat(bv);
    if (!isNaN(an) && !isNaN(bn)) return asc ? bn - an : an - bn;
    return asc ? bv.localeCompare(av) : av.localeCompare(bv);
  });
  var tbody = table.querySelector('tbody');
  rows.forEach(function(r) { tbody.appendChild(r); });
  table.dataset.sortCol = col;
  table.dataset.sortDir = asc ? 'desc' : 'asc';
}
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('th[data-col]').forEach(function(th) {
    th.addEventListener('click', function() {
      sortTable(th.closest('table'), parseInt(th.dataset.col));
    });
  });
});
"""


def _h(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text) if text is not None else "")


def _badge(text: str, kind: str) -> str:
    cls = f"badge badge-{html.escape(kind)}"
    return f'<span class="{cls}">{_h(text)}</span>'


def _severity_badge(severity: str) -> str:
    return _badge(severity, severity)


def _grade_badge(grade: str) -> str:
    return _badge(grade, grade)


def _render_finding(finding: Finding, idx: int) -> str:
    refs = []
    try:
        refs = json.loads(finding.standard_references or "[]")
    except (ValueError, TypeError):
        pass

    evidence_str = ""
    try:
        ev = json.loads(finding.evidence or "{}")
        evidence_str = json.dumps(ev, indent=2)
    except (ValueError, TypeError):
        evidence_str = finding.evidence or ""

    remediation_lines = (finding.remediation or "").strip().split("\n")
    remediation_html = "<ol>" + "".join(
        f"<li>{_h(line.lstrip('0123456789. '))}</li>"
        for line in remediation_lines if line.strip()
    ) + "</ol>"

    refs_html = ""
    if refs:
        tags = "".join(f'<span class="tag">{_h(r)}</span>' for r in refs)
        refs_html = f'<h4>References</h4><div class="tag-list">{tags}</div>'

    return f"""
<details id="finding-{idx}">
  <summary>
    {_severity_badge(finding.severity)}
    <span style="font-weight:600">{_h(finding.title)}</span>
    <span style="color:var(--muted);font-size:12px;margin-left:auto">{_h(finding.affected_object_name or "")}</span>
  </summary>
  <div class="finding-body">
    <h4>Description</h4>
    <p>{_h(finding.description)}</p>
    <h4>Remediation</h4>
    {remediation_html}
    {refs_html}
    <h4>Evidence</h4>
    <pre>{_h(evidence_str)}</pre>
  </div>
</details>
"""


def _render_device_section(device: Device, session: Session) -> str:
    # Get latest posture score
    score_obj = (
        session.query(PostureScore)
        .filter_by(device_id=device.id)
        .order_by(PostureScore.id.desc())
        .first()
    )

    score = score_obj.score if score_obj else "N/A"
    grade = score_obj.grade if score_obj else "N/A"
    critical = score_obj.critical_count if score_obj else 0
    high = score_obj.high_count if score_obj else 0
    medium = score_obj.medium_count if score_obj else 0
    low = score_obj.low_count if score_obj else 0

    findings = (
        session.query(Finding)
        .filter_by(device_id=device.id)
        .order_by(Finding.severity, Finding.id)
        .all()
    )

    score_color = _SEVERITY_COLORS.get("LOW", "#16a34a")
    if isinstance(score, int):
        if score < 40:
            score_color = _SEVERITY_COLORS["CRITICAL"]
        elif score < 60:
            score_color = _SEVERITY_COLORS["HIGH"]
        elif score < 75:
            score_color = _SEVERITY_COLORS["MEDIUM"]

    vdom_label = f" <span style='color:var(--muted);font-size:13px'>VDOM: {_h(device.vdom)}</span>" if device.vdom else ""
    fw_label = f" <span style='color:var(--muted);font-size:13px'>{_h(device.firmware_version or '')}</span>"

    findings_html = ""
    for i, f in enumerate(findings):
        findings_html += _render_finding(f, f.id)

    if not findings_html:
        findings_html = "<p style='color:var(--low);padding:12px'>No findings — clean configuration.</p>"

    policy_count = len(device.policies)
    admin_count = len(device.admins)

    return f"""
<div class="device-section">
  <div class="device-header">
    <h2>{_h(device.hostname)}{vdom_label}{fw_label}</h2>
    <div class="score-gauge">
      <div class="score-number" style="color:{score_color}">{score}</div>
      <div>
        <div>{_grade_badge(grade)}</div>
        <div style="color:var(--muted);font-size:11px;margin-top:4px">Posture Score</div>
      </div>
    </div>
    <div style="color:var(--muted);font-size:12px;line-height:1.8">
      <div>Policies: <strong style="color:var(--text)">{policy_count}</strong></div>
      <div>Admins: <strong style="color:var(--text)">{admin_count}</strong></div>
    </div>
    <div style="font-size:12px;line-height:1.8">
      <div><span style="color:var(--critical)">&#9679;</span> {critical} Critical</div>
      <div><span style="color:var(--high)">&#9679;</span> {high} High</div>
      <div><span style="color:var(--medium)">&#9679;</span> {medium} Medium</div>
      <div><span style="color:var(--low)">&#9679;</span> {low} Low</div>
    </div>
  </div>
  {findings_html}
</div>
"""


def generate_html_report(devices: List[Device], session: Session, out_path: Path) -> None:
    """Generate a self-contained HTML posture report."""
    out_path = Path(out_path)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total_devices = len(devices)

    # Aggregate stats across all devices
    all_scores = []
    total_critical = total_high = total_medium = total_low = 0
    for device in devices:
        score_obj = (
            session.query(PostureScore)
            .filter_by(device_id=device.id)
            .order_by(PostureScore.id.desc())
            .first()
        )
        if score_obj:
            all_scores.append(score_obj.score)
            total_critical += score_obj.critical_count
            total_high += score_obj.high_count
            total_medium += score_obj.medium_count
            total_low += score_obj.low_count

    avg_score = round(sum(all_scores) / len(all_scores)) if all_scores else "N/A"

    # Executive summary table rows
    summary_rows = ""
    for device in devices:
        score_obj = (
            session.query(PostureScore)
            .filter_by(device_id=device.id)
            .order_by(PostureScore.id.desc())
            .first()
        )
        score = score_obj.score if score_obj else "N/A"
        grade = score_obj.grade if score_obj else "N/A"
        crit = score_obj.critical_count if score_obj else 0
        high = score_obj.high_count if score_obj else 0
        med = score_obj.medium_count if score_obj else 0
        low_ = score_obj.low_count if score_obj else 0
        policies = len(device.policies)
        summary_rows += f"""
<tr>
  <td><strong>{_h(device.hostname)}</strong>{' <small style="color:var(--muted)">' + _h(device.vdom) + '</small>' if device.vdom else ''}</td>
  <td>{policies}</td>
  <td style="color:var(--critical);font-weight:600">{crit}</td>
  <td style="color:var(--high);font-weight:600">{high}</td>
  <td style="color:var(--medium)">{med}</td>
  <td style="color:var(--low)">{low_}</td>
  <td><strong>{score}</strong></td>
  <td>{_grade_badge(grade)}</td>
</tr>"""

    device_sections = "".join(_render_device_section(d, session) for d in devices)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FortiPosture Security Report — {_h(timestamp)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
  <header>
    <h1>FortiPosture Security Report</h1>
    <p>Generated: {_h(timestamp)} &nbsp;|&nbsp; Devices: {total_devices}</p>
  </header>

  <div class="stats">
    <div class="stat-card">
      <div class="label">Avg Score</div>
      <div class="value">{avg_score}</div>
    </div>
    <div class="stat-card">
      <div class="label">Critical</div>
      <div class="value" style="color:var(--critical)">{total_critical}</div>
    </div>
    <div class="stat-card">
      <div class="label">High</div>
      <div class="value" style="color:var(--high)">{total_high}</div>
    </div>
    <div class="stat-card">
      <div class="label">Medium</div>
      <div class="value" style="color:var(--medium)">{total_medium}</div>
    </div>
    <div class="stat-card">
      <div class="label">Low</div>
      <div class="value" style="color:var(--low)">{total_low}</div>
    </div>
  </div>

  <h2 style="margin-bottom:12px">Executive Summary</h2>
  <table>
    <thead>
      <tr>
        <th data-col="0">Device</th>
        <th data-col="1">Policies</th>
        <th data-col="2">Critical</th>
        <th data-col="3">High</th>
        <th data-col="4">Medium</th>
        <th data-col="5">Low</th>
        <th data-col="6">Score</th>
        <th data-col="7">Grade</th>
      </tr>
    </thead>
    <tbody>{summary_rows}</tbody>
  </table>

  <h2 style="margin-bottom:20px">Device Details</h2>
  {device_sections}

  <footer>
    <p>
      <a href="https://github.com/cloud-cyber-guard/fortiposture">fortiposture</a>
      &nbsp;&mdash;&nbsp;
      Licensed under <a href="https://www.gnu.org/licenses/agpl-3.0.html">AGPL-3.0</a>
      &nbsp;&mdash;&nbsp;
      This report is provided for informational purposes only. Verify findings before remediation.
    </p>
  </footer>
</div>
<script>{_JS}</script>
</body>
</html>
"""

    out_path.write_text(html_content, encoding="utf-8")
