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

"""Tests for ORM schema creation and basic DB operations."""

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from fortiposture.models.schema import Base, Device, FirewallPolicy, AdminAccount, Finding
from fortiposture.database import get_engine, init_db, drop_db, get_session


def test_schema_creates_all_tables():
    engine = create_engine("sqlite:///:memory:")
    init_db(engine)
    inspector = inspect(engine)
    tables = inspector.get_table_names()
    expected = {
        "device", "firewall_policy", "address_object", "service_object",
        "address_group", "service_group", "policy_container", "interface",
        "admin_account", "logging_config", "analysis_run", "finding", "posture_score",
    }
    assert expected.issubset(set(tables))


def test_device_insert_and_query():
    engine = create_engine("sqlite:///:memory:")
    init_db(engine)
    Session = sessionmaker(engine)
    session = Session()
    device = Device(hostname="test-fw", vendor="fortigate", source_file_hash="abc123")
    session.add(device)
    session.commit()
    result = session.query(Device).filter_by(hostname="test-fw").first()
    assert result is not None
    assert result.vendor == "fortigate"


def test_drop_db_removes_tables():
    engine = create_engine("sqlite:///:memory:")
    init_db(engine)
    drop_db(engine)
    inspector = inspect(engine)
    assert inspector.get_table_names() == []


def test_get_session_returns_session():
    engine = get_engine(":memory:")
    init_db(engine)
    session = get_session(engine)
    assert session is not None
    session.close()
