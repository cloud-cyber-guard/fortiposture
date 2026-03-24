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

"""
FortiGate .conf file parser.

Parses the hierarchical FortiOS config block format into nested Python dicts.
Output structure:
  {
    "system global": {"hostname": "...", ...},
    "firewall policy": {"1": {...}, "2": {...}},
    "_vdoms": {"root": {...}, "dmz": {...}},   # only if VDOM-enabled
  }
"""

import logging
import re
import shlex
from pathlib import Path

logger = logging.getLogger(__name__)


def _parse_value(raw: str) -> "str | list[str]":
    """Parse a set value — returns list for multi-value, str for single.

    FortiOS uses two distinct multi-value patterns:
    - Quoted list:  ``"HTTP" "HTTPS"``  → multiple independent values → list
    - Unquoted pair: ``10.0.0.0 255.0.0.0`` → single compound value → str

    We distinguish them by checking whether the raw string contains quote
    characters.  If it does, every token is individually quoted (FortiOS
    style) and should be returned as a list.  If there are no quotes, the
    space-separated tokens form a single logical value (e.g. an IP + mask).
    """
    raw = raw.strip()
    if not raw:
        return ""
    has_quotes = '"' in raw or "'" in raw
    try:
        tokens = shlex.split(raw)
    except ValueError:
        tokens = raw.split()
    if len(tokens) > 1 and has_quotes:
        return tokens
    return " ".join(tokens) if len(tokens) > 1 else tokens[0]


class FortiConfParser:
    """Parses FortiGate .conf backup files into nested dicts."""

    def parse_file(self, path: Path) -> dict:
        path = Path(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.error("Cannot read %s: %s", path, e)
            return {}
        return self.parse_text(text)

    def parse_text(self, text: str) -> dict:
        lines = text.splitlines()
        return self._parse(lines)

    def _parse(self, lines: list) -> dict:
        """Top-level parse — detects VDOM mode and dispatches."""
        is_vdom = any(
            re.match(r"^config\s+vdom\s*$", ln.strip()) for ln in lines
        )
        if is_vdom:
            return self._parse_vdom(lines)
        return self._parse_block(iter(lines))

    def _parse_vdom(self, lines: list) -> dict:
        """Parse a VDOM-enabled config file.

        Structure:
          config global  → goes into top-level result
          config vdom
            edit <name>
            config firewall policy ...
            next
          end
        """
        result: dict = {"_vdoms": {}}
        it = iter(lines)
        current_vdom: "str | None" = None
        in_global = False
        in_vdom_block = False
        in_vdom_config = False
        vdom_lines: list = []
        vdom_depth: int = 0  # nesting depth of edit blocks inside a VDOM

        for line in it:
            stripped = line.strip()

            if stripped.startswith("#"):
                continue

            if re.match(r"^config\s+global\s*$", stripped):
                in_global = True
                global_lines: list = []
                continue

            if in_global:
                if stripped == "end":
                    in_global = False
                    global_data = self._parse_block(iter(global_lines))
                    result.update(global_data)
                else:
                    global_lines.append(line)
                continue

            if re.match(r"^config\s+vdom\s*$", stripped) and not in_vdom_block:
                in_vdom_block = True
                continue

            if in_vdom_block and not in_vdom_config:
                if stripped == "end":
                    in_vdom_block = False
                    continue

                # Detect "edit <name>" — start of a per-VDOM config block
                m = re.match(r"^edit\s+(\S+)\s*$", stripped)
                if m:
                    current_vdom = m.group(1).strip('"')
                    result["_vdoms"][current_vdom] = {}
                    vdom_lines = []
                    vdom_depth = 0
                    in_vdom_config = True
                continue

            if in_vdom_config:
                # Track nesting depth so we only treat the VDOM-level "next"
                # as the boundary, not "next" tokens inside nested edit blocks.
                if stripped == "next":
                    if vdom_depth == 0 and current_vdom:
                        vdom_data = self._parse_block(iter(vdom_lines))
                        result["_vdoms"][current_vdom] = vdom_data
                        current_vdom = None
                        vdom_lines = []
                        in_vdom_config = False
                    else:
                        if vdom_depth > 0:
                            vdom_depth -= 1
                        vdom_lines.append(line)
                elif re.match(r"^edit\s+", stripped):
                    vdom_depth += 1
                    vdom_lines.append(line)
                else:
                    vdom_lines.append(line)
                continue

        return result

    def _parse_block(self, it, _nested: bool = False) -> dict:
        """Parse a sequence of lines into a dict.

        When *_nested* is True the parser is being called recursively to handle
        a ``config … end`` sub-block; in that case it returns as soon as it
        sees the matching ``end``.  At the top level (``_nested=False``) an
        ``end`` simply closes the current section and parsing continues.
        """
        result: dict = {}
        current_section: "str | None" = None
        current_entry_id: "str | None" = None
        current_entry: dict = {}

        for line in it:
            stripped = line.strip()

            if not stripped or stripped.startswith("#"):
                continue

            m = re.match(r"^config\s+(.+)$", stripped)
            if m:
                section_name = m.group(1).strip()
                if current_entry_id is not None:
                    # Nested config inside an edit block — recurse
                    nested = self._parse_block(it, _nested=True)
                    current_entry[section_name] = nested
                else:
                    # Top-level (or VDOM-level) section — recurse to collect
                    # all entries until the matching end, then merge
                    section_data = self._parse_block(it, _nested=True)
                    existing = result.setdefault(section_name, {})
                    existing.update(section_data)
                    current_section = None  # section is now fully consumed
                continue

            m = re.match(r'^edit\s+(.+)$', stripped)
            if m:
                raw_id = m.group(1).strip().strip('"')
                current_entry_id = raw_id
                current_entry = {}
                continue

            m = re.match(r'^set\s+(\S+)\s*(.*)?$', stripped)
            if m:
                key = m.group(1)
                raw_val = (m.group(2) or "").strip()
                val = _parse_value(raw_val)
                if current_entry_id is not None:
                    current_entry[key] = val
                elif current_section is not None:
                    result.setdefault(current_section, {})[key] = val
                else:
                    result[key] = val
                continue

            if stripped.startswith("unset "):
                continue

            if stripped == "next":
                if current_entry_id is not None:
                    # Store the completed entry into either the current section
                    # or directly into result (for flat blocks like log setting)
                    if current_section is not None:
                        result.setdefault(current_section, {})[current_entry_id] = current_entry
                    else:
                        # This block IS the section (called recursively from a
                        # config … end context); entries go straight into result
                        result[current_entry_id] = current_entry
                current_entry_id = None
                current_entry = {}
                continue

            if stripped == "end":
                if _nested:
                    # Return the collected data to the caller
                    return result
                # Top-level end: section is already closed by the recursive
                # approach above, nothing to do
                continue

        return result
