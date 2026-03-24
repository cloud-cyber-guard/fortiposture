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

"""Shared pytest fixtures."""

import pytest
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from fortiposture.models.schema import Base
from fortiposture.parser.conf_parser import FortiConfParser
from fortiposture.parser.normalizer import FortiNormalizer

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def db_session():
    """In-memory SQLite session, fresh per test."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def parser():
    return FortiConfParser()


@pytest.fixture
def normalizer():
    return FortiNormalizer()


def ingest_fixture(fixture_name: str, session, parser=None, normalizer=None):
    """Helper: parse + ingest a named fixture file."""
    if parser is None:
        parser = FortiConfParser()
    if normalizer is None:
        normalizer = FortiNormalizer()
    path = FIXTURES / fixture_name
    parsed = parser.parse_file(path)
    devices = normalizer.ingest(parsed, path, session)
    return devices
