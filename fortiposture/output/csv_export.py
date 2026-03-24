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

"""CSV export for findings."""

import csv
from pathlib import Path
from typing import List
from fortiposture.models.schema import Finding


def export_findings_csv(findings: List[Finding], output_path: Path) -> None:
    output_path = Path(output_path)
    fieldnames = [
        "device", "check_id", "severity", "title",
        "affected_object", "description", "remediation", "references", "evidence",
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            # Resolve device hostname via direct device relationship
            device_name = ""
            try:
                if finding.device:
                    device_name = finding.device.hostname or ""
            except Exception:
                device_name = str(finding.device_id)

            writer.writerow({
                "device": device_name,
                "check_id": finding.check_id or "",
                "severity": finding.severity or "",
                "title": finding.title or "",
                "affected_object": finding.affected_object_name or "",
                "description": finding.description or "",
                "remediation": finding.remediation or "",
                "references": finding.standard_references or "",
                "evidence": finding.evidence or "",
            })
