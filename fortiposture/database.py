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

"""SQLite engine and session factory."""

from pathlib import Path
from typing import Union
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from fortiposture.models.schema import Base


def get_engine(db_path: Union[Path, str] = "fortiposture.db"):
    db_path = Path(db_path)
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    return engine


def init_db(engine) -> None:
    """Create all tables."""
    Base.metadata.create_all(engine)


def drop_db(engine) -> None:
    """Drop all tables (used with --fresh flag)."""
    Base.metadata.drop_all(engine)


def get_session(engine) -> Session:
    factory = sessionmaker(bind=engine)
    return factory()
