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

"""Utility functions for fortiposture."""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ConfScanResult:
    files: list[Path] = field(default_factory=list)
    folders_visited: int = 0
    limit_reached: bool = False


def find_conf_files(
    path: Path,
    max_depth: int = 5,
    max_folders: int = 100,
) -> ConfScanResult:
    """Recursively find .conf files under path.

    Args:
        path: Root directory to search.
        max_depth: Maximum subdirectory nesting depth (0 = root only).
        max_folders: Maximum total directories to visit.

    Returns:
        ConfScanResult with sorted file list, folder count, and limit flag.
    """
    if max_folders < 1:
        raise ValueError(f"max_folders must be >= 1, got {max_folders}")

    result = ConfScanResult()

    def _walk(current: Path, depth: int) -> None:
        if result.folders_visited >= max_folders:
            result.limit_reached = True
            return
        result.folders_visited += 1
        result.files.extend(current.glob("*.conf"))
        if depth < max_depth:
            for sub in sorted(current.iterdir()):
                if sub.is_dir():
                    _walk(sub, depth + 1)

    _walk(path, 0)
    result.files = sorted(result.files)
    return result
