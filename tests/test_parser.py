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
from fortiposture.parser.conf_parser import FortiConfParser

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_hostname():
    parser = FortiConfParser()
    result = parser.parse_file(FIXTURES / "simple_policy.conf")
    assert result["system global"]["hostname"] == "fw-clean-01"


def test_parse_policy_count():
    parser = FortiConfParser()
    result = parser.parse_file(FIXTURES / "simple_policy.conf")
    policies = result.get("firewall policy", {})
    assert len(policies) == 4


def test_parse_multi_value_set():
    """set srcaddr "addr1" "addr2" must yield a list."""
    parser = FortiConfParser()
    result = parser.parse_file(FIXTURES / "simple_policy.conf")
    policy_1 = result["firewall policy"]["1"]
    assert isinstance(policy_1["service"], list)
    policy_1_services = result["firewall policy"]["1"]["service"]
    assert "HTTP" in policy_1_services
    assert "HTTPS" in policy_1_services


def test_parse_address_objects():
    parser = FortiConfParser()
    result = parser.parse_file(FIXTURES / "simple_policy.conf")
    addrs = result.get("firewall address", {})
    assert "net-internal" in addrs
    assert addrs["net-internal"]["subnet"] == "10.0.0.0 255.0.0.0"


def test_parse_admin_accounts():
    parser = FortiConfParser()
    result = parser.parse_file(FIXTURES / "simple_policy.conf")
    admins = result.get("system admin", {})
    assert "admin" in admins
    assert admins["admin"]["two-factor"] == "fortitoken"


def test_parse_admin_no_mfa():
    parser = FortiConfParser()
    result = parser.parse_file(FIXTURES / "weak_admin.conf")
    admins = result.get("system admin", {})
    assert "admin" in admins
    assert "two-factor" not in admins["admin"]


def test_parse_logging_config():
    parser = FortiConfParser()
    result = parser.parse_file(FIXTURES / "simple_policy.conf")
    syslog = result.get("log syslogd setting", {})
    assert syslog.get("status") == "enable"
    assert syslog.get("server") == "192.168.1.100"


def test_parse_missing_section_graceful():
    """Missing sections return empty dict, no exception."""
    parser = FortiConfParser()
    result = parser.parse_file(FIXTURES / "simple_policy.conf")
    assert result.get("vpn ssl settings", {}) == {}


def test_parse_vdom_config():
    parser = FortiConfParser()
    result = parser.parse_file(FIXTURES / "multi_vdom.conf")
    assert "_vdoms" in result
    vdoms = result["_vdoms"]
    assert "root" in vdoms
    assert "dmz" in vdoms
    root_policies = vdoms["root"].get("firewall policy", {})
    assert len(root_policies) == 2


def test_parse_service_objects():
    parser = FortiConfParser()
    result = parser.parse_file(FIXTURES / "simple_policy.conf")
    services = result.get("firewall service custom", {})
    assert "HTTP" in services
    assert services["HTTP"]["tcp-portrange"] == "80"
