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

"""Tests for the FortiNormalizer — parsed dict → ORM models."""

import pytest
from tests.conftest import ingest_fixture
from fortiposture.models.schema import Device, FirewallPolicy, AddressObject, AdminAccount, LoggingConfig


def test_device_hostname_extracted(db_session):
    devices = ingest_fixture("simple_policy.conf", db_session)
    assert len(devices) == 1
    assert devices[0].hostname == "fw-clean-01"


def test_policy_count(db_session):
    devices = ingest_fixture("simple_policy.conf", db_session)
    assert len(devices[0].policies) == 4


def test_address_objects_ingested(db_session):
    devices = ingest_fixture("simple_policy.conf", db_session)
    addrs = {a.name for a in devices[0].addresses}
    assert "net-internal" in addrs


def test_admin_with_two_factor(db_session):
    devices = ingest_fixture("simple_policy.conf", db_session)
    admin = db_session.query(AdminAccount).filter_by(device_id=devices[0].id, username="admin").first()
    assert admin is not None
    assert admin.two_factor_auth is True


def test_admin_no_two_factor(db_session):
    devices = ingest_fixture("weak_admin.conf", db_session)
    admin = db_session.query(AdminAccount).filter_by(device_id=devices[0].id, username="admin").first()
    assert admin is not None
    assert admin.two_factor_auth is False


def test_admin_trusted_hosts_parsed(db_session):
    import json
    devices = ingest_fixture("simple_policy.conf", db_session)
    admin = db_session.query(AdminAccount).filter_by(device_id=devices[0].id, username="admin").first()
    trusted = json.loads(admin.trusted_hosts)
    assert len(trusted) > 0


def test_admin_no_trusted_hosts(db_session):
    import json
    devices = ingest_fixture("weak_admin.conf", db_session)
    admin = db_session.query(AdminAccount).filter_by(device_id=devices[0].id, username="admin").first()
    trusted = json.loads(admin.trusted_hosts)
    assert trusted == []


def test_logging_syslog_enabled(db_session):
    devices = ingest_fixture("simple_policy.conf", db_session)
    syslog = db_session.query(LoggingConfig).filter_by(
        device_id=devices[0].id, log_type="syslog"
    ).first()
    assert syslog is not None
    assert syslog.enabled is True
    assert syslog.server == "192.168.1.100"


def test_idempotent_reimport(db_session):
    """Importing the same file twice must not create duplicate devices."""
    ingest_fixture("simple_policy.conf", db_session)
    ingest_fixture("simple_policy.conf", db_session)
    count = db_session.query(Device).filter_by(hostname="fw-clean-01").count()
    assert count == 1


def test_vdom_creates_two_devices(db_session):
    devices = ingest_fixture("multi_vdom.conf", db_session)
    assert len(devices) == 2
    vdoms = {d.vdom for d in devices}
    assert "root" in vdoms
    assert "dmz" in vdoms


def test_address_type_classification(db_session):
    devices = ingest_fixture("simple_policy.conf", db_session)
    net_internal = db_session.query(AddressObject).filter_by(
        device_id=devices[0].id, name="net-internal"
    ).first()
    assert net_internal is not None
    assert net_internal.address_type == "network"
