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

"""SQLAlchemy ORM models for fortiposture."""

import json
from datetime import datetime
from sqlalchemy import (
    Boolean, Column, DateTime, ForeignKey, Integer, String, Text,
    Table, UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


# ---------- Association tables ----------

policy_src_address = Table(
    "policy_src_address", Base.metadata,
    Column("policy_id", Integer, ForeignKey("firewall_policy.id"), primary_key=True),
    Column("address_id", Integer, ForeignKey("address_object.id"), primary_key=True),
)

policy_dst_address = Table(
    "policy_dst_address", Base.metadata,
    Column("policy_id", Integer, ForeignKey("firewall_policy.id"), primary_key=True),
    Column("address_id", Integer, ForeignKey("address_object.id"), primary_key=True),
)

policy_service = Table(
    "policy_service", Base.metadata,
    Column("policy_id", Integer, ForeignKey("firewall_policy.id"), primary_key=True),
    Column("service_id", Integer, ForeignKey("service_object.id"), primary_key=True),
)

addrgrp_member_address = Table(
    "addrgrp_member_address", Base.metadata,
    Column("group_id", Integer, ForeignKey("address_group.id"), primary_key=True),
    Column("address_id", Integer, ForeignKey("address_object.id"), primary_key=True),
)

svcgrp_member = Table(
    "svcgrp_member", Base.metadata,
    Column("group_id", Integer, ForeignKey("service_group.id"), primary_key=True),
    Column("service_id", Integer, ForeignKey("service_object.id"), primary_key=True),
)


# ---------- Core models ----------

class Device(Base):
    __tablename__ = "device"

    id = Column(Integer, primary_key=True)
    hostname = Column(String, nullable=False)
    vendor = Column(String, default="fortigate")
    firmware_version = Column(String)
    serial_number = Column(String)
    model = Column(String)
    source_file = Column(String)
    source_file_hash = Column(String)
    imported_at = Column(DateTime, default=datetime.utcnow)
    vdom = Column(String, default="")  # "" = not VDOM-aware; VDOM configs use VDOM name
    vendor_data = Column(Text)  # JSON — stores system password-policy section

    __table_args__ = (
        UniqueConstraint("hostname", "vdom", "source_file_hash", name="uq_device"),
    )

    policies = relationship("FirewallPolicy", back_populates="device")
    addresses = relationship("AddressObject", back_populates="device")
    services = relationship("ServiceObject", back_populates="device")
    interfaces = relationship("Interface", back_populates="device")
    admins = relationship("AdminAccount", back_populates="device")
    logging_configs = relationship("LoggingConfig", back_populates="device")
    analysis_runs = relationship("AnalysisRun", back_populates="device")
    findings = relationship("Finding", back_populates="device")
    scores = relationship("PostureScore", back_populates="device")


class AddressObject(Base):
    __tablename__ = "address_object"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    name = Column(String, nullable=False)
    address_type = Column(String)  # network/host/range/fqdn/any/wildcard
    value = Column(String)
    comment = Column(Text)
    vendor_data = Column(Text)  # JSON

    device = relationship("Device", back_populates="addresses")


class AddressGroup(Base):
    __tablename__ = "address_group"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    name = Column(String, nullable=False)
    comment = Column(Text)

    members = relationship("AddressObject", secondary=addrgrp_member_address)


class ServiceObject(Base):
    __tablename__ = "service_object"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    name = Column(String, nullable=False)
    protocol = Column(String)  # tcp/udp/tcp_udp/icmp/all
    port_range_start = Column(Integer)
    port_range_end = Column(Integer)
    comment = Column(Text)
    vendor_data = Column(Text)  # JSON

    device = relationship("Device", back_populates="services")


class ServiceGroup(Base):
    __tablename__ = "service_group"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    name = Column(String, nullable=False)

    members = relationship("ServiceObject", secondary=svcgrp_member)


class PolicyContainer(Base):
    __tablename__ = "policy_container"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    name = Column(String, nullable=False)
    container_type = Column(String, default="global")  # vdom/global


class FirewallPolicy(Base):
    __tablename__ = "firewall_policy"

    id = Column(Integer, primary_key=True)
    container_id = Column(Integer, ForeignKey("policy_container.id"))
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    native_id = Column(String)
    name = Column(String)
    sequence_num = Column(Integer)
    action = Column(String)        # accept/deny/drop
    status = Column(String, default="enabled")
    log_traffic = Column(String, default="disable")
    nat_enabled = Column(Boolean, default=False)
    src_interfaces = Column(Text)  # JSON array
    dst_interfaces = Column(Text)  # JSON array
    schedule = Column(String)
    comments = Column(Text)
    vendor_data = Column(Text)     # JSON

    device = relationship("Device", back_populates="policies")
    src_addresses = relationship("AddressObject", secondary=policy_src_address)
    dst_addresses = relationship("AddressObject", secondary=policy_dst_address)
    services = relationship("ServiceObject", secondary=policy_service)


class Interface(Base):
    __tablename__ = "interface"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    name = Column(String, nullable=False)
    ip_address = Column(String)
    netmask = Column(String)
    zone = Column(String)
    interface_type = Column(String)
    status = Column(String)
    allowaccess = Column(Text)  # JSON array
    vdom = Column(String)
    description = Column(Text)

    device = relationship("Device", back_populates="interfaces")


class AdminAccount(Base):
    __tablename__ = "admin_account"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    username = Column(String, nullable=False)
    auth_type = Column(String, default="local")  # local/radius/ldap/tacacs+
    two_factor_auth = Column(Boolean, default=False)
    two_factor_auth_type = Column(String)
    access_profile = Column(String)
    trusted_hosts = Column(Text)  # JSON array
    password_must_change = Column(Boolean, default=False)

    device = relationship("Device", back_populates="admins")


class LoggingConfig(Base):
    __tablename__ = "logging_config"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    log_type = Column(String)  # local/syslog/fortianalyzer/forticloud
    enabled = Column(Boolean, default=False)
    server = Column(String)
    port = Column(Integer)
    log_level = Column(String)
    traffic_log = Column(Boolean, default=False)
    event_log = Column(Boolean, default=False)

    device = relationship("Device", back_populates="logging_configs")


class AnalysisRun(Base):
    __tablename__ = "analysis_run"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    status = Column(String, default="running")
    checks_run = Column(Text)   # JSON list of check IDs
    total_findings = Column(Integer, default=0)

    device = relationship("Device", back_populates="analysis_runs")
    findings = relationship("Finding", back_populates="analysis_run")
    score = relationship("PostureScore", uselist=False, back_populates="analysis_run")


class Finding(Base):
    __tablename__ = "finding"

    id = Column(Integer, primary_key=True)
    analysis_run_id = Column(Integer, ForeignKey("analysis_run.id"), nullable=False)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    check_id = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # CRITICAL/HIGH/MEDIUM/LOW
    title = Column(String, nullable=False)
    description = Column(Text)
    remediation = Column(Text)
    standard_references = Column(Text)  # JSON
    policy_id = Column(Integer, ForeignKey("firewall_policy.id"))
    affected_object_name = Column(String)
    evidence = Column(Text)  # JSON

    analysis_run = relationship("AnalysisRun", back_populates="findings")
    device = relationship("Device", back_populates="findings")


class PostureScore(Base):
    __tablename__ = "posture_score"

    id = Column(Integer, primary_key=True)
    analysis_run_id = Column(Integer, ForeignKey("analysis_run.id"), nullable=False)
    device_id = Column(Integer, ForeignKey("device.id"), nullable=False)
    score = Column(Integer, nullable=False)
    grade = Column(String, nullable=False)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)

    analysis_run = relationship("AnalysisRun", back_populates="score")
    device = relationship("Device", back_populates="scores")
