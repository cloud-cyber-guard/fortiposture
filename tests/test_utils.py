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

import pytest
from pathlib import Path
from fortiposture.utils import find_conf_files, ConfScanResult


def _make_tree(tmp_path, structure):
    """Create a directory tree from a dict: {'file.conf': None, 'sub/': {'file.conf': None}}"""
    for name, children in structure.items():
        if name.endswith("/"):
            d = tmp_path / name.rstrip("/")
            d.mkdir()
            if children:
                _make_tree(d, children)
        else:
            (tmp_path / name).write_text("config")


def test_finds_conf_files_in_root(tmp_path):
    _make_tree(tmp_path, {"a.conf": None, "b.conf": None, "ignore.txt": None})
    result = find_conf_files(tmp_path)
    assert len(result.files) == 2
    assert all(f.suffix == ".conf" for f in result.files)
    assert result.limit_reached is False


def test_finds_conf_files_in_subdirectory(tmp_path):
    _make_tree(tmp_path, {"a.conf": None, "sub/": {"b.conf": None}})
    result = find_conf_files(tmp_path)
    assert len(result.files) == 2


def test_depth_zero_no_recursion(tmp_path):
    _make_tree(tmp_path, {"a.conf": None, "sub/": {"b.conf": None}})
    result = find_conf_files(tmp_path, max_depth=0)
    assert len(result.files) == 1
    assert result.files[0].name == "a.conf"


def test_depth_limit_excludes_deep_files(tmp_path):
    _make_tree(tmp_path, {"a.conf": None, "l1/": {"b.conf": None, "l2/": {"c.conf": None}}})
    result = find_conf_files(tmp_path, max_depth=1)
    assert len(result.files) == 2
    names = {f.name for f in result.files}
    assert "a.conf" in names
    assert "b.conf" in names
    assert "c.conf" not in names


def test_max_folders_limit(tmp_path):
    # Create 5 subdirs each with a .conf file
    for i in range(5):
        d = tmp_path / f"sub{i}"
        d.mkdir()
        (d / "fw.conf").write_text("config")
    result = find_conf_files(tmp_path, max_folders=3)
    assert result.limit_reached is True
    assert result.folders_visited == 3


def test_files_returned_sorted(tmp_path):
    _make_tree(tmp_path, {"c.conf": None, "a.conf": None, "b.conf": None})
    result = find_conf_files(tmp_path)
    names = [f.name for f in result.files]
    assert names == sorted(names)


def test_sibling_folders_all_scanned(tmp_path):
    # 10 sibling folders — all should be visited within default limits
    for i in range(10):
        d = tmp_path / f"region{i}"
        d.mkdir()
        (d / f"fw{i}.conf").write_text("config")
    result = find_conf_files(tmp_path)
    assert len(result.files) == 10
    assert result.limit_reached is False


def test_max_folders_zero_raises(tmp_path):
    (tmp_path / "a.conf").write_text("config")
    with pytest.raises(ValueError, match="max_folders must be >= 1"):
        find_conf_files(tmp_path, max_folders=0)
