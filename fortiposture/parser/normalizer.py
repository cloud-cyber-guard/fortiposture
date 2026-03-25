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

"""Maps parsed FortiGate config dicts → SQLAlchemy ORM model instances."""

import hashlib
import json
import logging
from pathlib import Path
from typing import List, Optional, Tuple
from sqlalchemy.orm import Session
from fortiposture.models.schema import (
    Device, AddressObject, ServiceObject, FirewallPolicy,
    PolicyContainer, Interface, AdminAccount, LoggingConfig,
)

logger = logging.getLogger(__name__)


def _file_hash(path: Path) -> str:
    h = hashlib.sha256()
    h.update(Path(path).read_bytes())
    return h.hexdigest()


def _listify(val) -> list:
    """Ensure a parsed value is always a list."""
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


def _parse_int(val) -> Optional[int]:
    """Parse int from string, stripping quotes and whitespace."""
    if val is None:
        return None
    try:
        return int(str(val).strip().strip('"'))
    except (ValueError, TypeError):
        return None


def _strip_quotes(val) -> Optional[str]:
    """Strip surrounding quotes from parsed string values."""
    if val is None:
        return None
    return str(val).strip('"')


def _parse_port_range(portrange_str: str) -> Tuple[Optional[int], Optional[int]]:
    """Parse '80', '1024-65535', '443' → (start, end)."""
    if not portrange_str:
        return None, None
    parts = str(portrange_str).split("-")
    try:
        start = int(parts[0])
        end = int(parts[1]) if len(parts) > 1 else start
        return start, end
    except (ValueError, IndexError):
        return None, None


class FortiNormalizer:
    """Normalizes parsed config dict → ORM objects, writes to DB session."""

    def ingest(self, parsed: dict, source_file: Path, session: Session) -> List[Device]:
        """
        Ingest parsed config into DB. Returns list of Device objects created.
        Skips if device with same hostname+vdom+hash already exists.
        """
        source_file = Path(source_file)
        file_hash = _file_hash(source_file)

        if "_vdoms" in parsed:
            devices = self._ingest_vdom(parsed, source_file, file_hash, session)
        else:
            devices = [self._ingest_single(parsed, source_file, file_hash, session, vdom="")]
        session.commit()
        return devices

    # ------------------------------------------------------------------
    # VDOM ingestion
    # ------------------------------------------------------------------

    def _ingest_vdom(self, parsed: dict, source_file: Path, file_hash: str, session: Session) -> List[Device]:
        devices = []
        global_data = {k: v for k, v in parsed.items() if k != "_vdoms"}
        for vdom_name, vdom_data in parsed["_vdoms"].items():
            merged = {**global_data, **vdom_data}
            device = self._ingest_single(merged, source_file, file_hash, session, vdom=vdom_name)
            devices.append(device)
        return devices

    # ------------------------------------------------------------------
    # Single device ingestion
    # ------------------------------------------------------------------

    def _ingest_single(self, parsed: dict, source_file: Path, file_hash: str, session: Session, vdom: str) -> Device:
        global_cfg = parsed.get("system global", {})
        hostname = global_cfg.get("hostname", source_file.stem).strip('"')

        # Idempotency check
        existing = session.query(Device).filter_by(
            hostname=hostname, vdom=vdom, source_file_hash=file_hash
        ).first()
        if existing:
            logger.info("Skipping %s (already imported)", hostname)
            return existing

        device = Device(
            hostname=hostname,
            vendor="fortigate",
            firmware_version=global_cfg.get("firmware-version"),
            model=global_cfg.get("fortigate-model"),
            source_file=str(source_file),
            source_file_hash=file_hash,
            vdom=vdom,
            vendor_data=json.dumps({
                "system password-policy": parsed.get("system password-policy", {}),
                "system ntp": parsed.get("system ntp", {}),
                "vpn ipsec phase1-interface": parsed.get("vpn ipsec phase1-interface", {}),
                "vpn ipsec phase2-interface": parsed.get("vpn ipsec phase2-interface", {}),
                "system snmp community": parsed.get("system snmp community", {}),
                "system snmp user": parsed.get("system snmp user", {}),
                "vpn ssl settings": parsed.get("vpn ssl settings", {}),
                "firewall local-in-policy": parsed.get("firewall local-in-policy", {}),
            }),
        )
        session.add(device)
        session.flush()  # get device.id

        try:
            self._ingest_addresses(parsed, device, session)
            self._ingest_services(parsed, device, session)
            self._ingest_policies(parsed, device, session)
            self._ingest_interfaces(parsed, device, session)
            self._ingest_admins(parsed, device, session)
            self._ingest_logging(parsed, device, session)
            session.flush()
            return device
        except Exception as e:
            logger.warning("Failed to ingest %s: %s", hostname, e)
            session.rollback()
            raise

    # ------------------------------------------------------------------
    # Addresses
    # ------------------------------------------------------------------

    def _ingest_addresses(self, parsed: dict, device: Device, session: Session):
        for name, data in parsed.get("firewall address", {}).items():
            addr_type = self._classify_address(data)
            value = data.get("subnet") or data.get("fqdn") or data.get("start-ip") or data.get("wildcard")
            obj = AddressObject(
                device_id=device.id,
                name=_strip_quotes(name),
                address_type=addr_type,
                value=value,
                comment=_strip_quotes(data.get("comment")),
                vendor_data=json.dumps(data),
            )
            session.add(obj)

    def _classify_address(self, data: dict) -> str:
        t = data.get("type", "")
        if t == "ipmask":
            return "network"
        if t == "iprange":
            return "range"
        if t == "fqdn":
            return "fqdn"
        if t == "wildcard":
            return "wildcard"
        name = data.get("name", "")
        if name.lower() == "all":
            return "any"
        if data.get("subnet"):
            return "network"
        return "host"

    # ------------------------------------------------------------------
    # Services
    # ------------------------------------------------------------------

    def _ingest_services(self, parsed: dict, device: Device, session: Session):
        # Synthesize built-in "ALL" service — system object never in firewall service custom
        all_svc = ServiceObject(
            device_id=device.id,
            name="ALL",
            protocol="all",
            port_range_start=0,
            port_range_end=65535,
        )
        session.add(all_svc)

        for name, data in parsed.get("firewall service custom", {}).items():
            protocol = "tcp"
            port_str = data.get("tcp-portrange", "")
            if data.get("udp-portrange") and not data.get("tcp-portrange"):
                protocol = "udp"
                port_str = data.get("udp-portrange", "")
            elif data.get("udp-portrange") and data.get("tcp-portrange"):
                protocol = "tcp_udp"

            start, end = _parse_port_range(str(port_str).split()[0] if port_str else "")
            obj = ServiceObject(
                device_id=device.id,
                name=_strip_quotes(name),
                protocol=protocol,
                port_range_start=start,
                port_range_end=end,
                comment=_strip_quotes(data.get("comment")),
                vendor_data=json.dumps(data),
            )
            session.add(obj)

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def _ingest_policies(self, parsed: dict, device: Device, session: Session):
        container = PolicyContainer(
            device_id=device.id,
            name=device.vdom or "global",
            container_type="vdom" if device.vdom else "global",
        )
        session.add(container)
        session.flush()

        # Build address/service lookup maps
        addr_map = {a.name: a for a in session.query(AddressObject).filter_by(device_id=device.id).all()}
        svc_map = {s.name: s for s in session.query(ServiceObject).filter_by(device_id=device.id).all()}

        for seq, (native_id, data) in enumerate(parsed.get("firewall policy", {}).items(), start=1):
            action_raw = data.get("action", "deny").lower()
            action = action_raw if action_raw in ("accept", "deny", "drop") else "deny"

            status_raw = data.get("status", "enable")
            status = "enabled" if status_raw == "enable" else "disabled"

            log_traffic = data.get("logtraffic", "disable")

            policy = FirewallPolicy(
                device_id=device.id,
                container_id=container.id,
                native_id=native_id,
                name=_strip_quotes(data.get("name")),
                sequence_num=seq,
                action=action,
                status=status,
                log_traffic=log_traffic,
                nat_enabled=data.get("nat", "disable") == "enable",
                src_interfaces=json.dumps(_listify(data.get("srcintf"))),
                dst_interfaces=json.dumps(_listify(data.get("dstintf"))),
                schedule=data.get("schedule"),
                comments=_strip_quotes(data.get("comments")),
                vendor_data=json.dumps(data),
            )

            # Resolve address/service many-to-many
            for name in _listify(data.get("srcaddr")):
                if name in addr_map:
                    policy.src_addresses.append(addr_map[name])
            for name in _listify(data.get("dstaddr")):
                if name in addr_map:
                    policy.dst_addresses.append(addr_map[name])
            for name in _listify(data.get("service")):
                if name in svc_map:
                    policy.services.append(svc_map[name])

            session.add(policy)

    # ------------------------------------------------------------------
    # Interfaces
    # ------------------------------------------------------------------

    def _ingest_interfaces(self, parsed: dict, device: Device, session: Session):
        for name, data in parsed.get("system interface", {}).items():
            ip_str = data.get("ip", "")
            parts = ip_str.split() if ip_str else []
            ip = parts[0] if parts else None
            mask = parts[1] if len(parts) > 1 else None
            obj = Interface(
                device_id=device.id,
                name=_strip_quotes(name),
                ip_address=ip,
                netmask=mask,
                zone=data.get("zone"),
                interface_type=data.get("type"),
                status=data.get("status"),
                allowaccess=json.dumps(_listify(data.get("allowaccess"))),
                vdom=data.get("vdom"),
                description=_strip_quotes(data.get("description")),
            )
            session.add(obj)

    # ------------------------------------------------------------------
    # Admins
    # ------------------------------------------------------------------

    def _ingest_admins(self, parsed: dict, device: Device, session: Session):
        for username, data in parsed.get("system admin", {}).items():
            two_factor = data.get("two-factor", "disable") != "disable"
            two_factor_type = data.get("two-factor") if two_factor else None

            trusted = []
            for i in range(1, 11):
                th = data.get(f"trusthost{i}")
                if th and th not in ("0.0.0.0 0.0.0.0", ""):
                    trusted.append(th)

            obj = AdminAccount(
                device_id=device.id,
                username=_strip_quotes(username),
                auth_type="local",
                two_factor_auth=two_factor,
                two_factor_auth_type=two_factor_type,
                access_profile=data.get("accprofile"),
                trusted_hosts=json.dumps(trusted),
                password_must_change=data.get("password-must-change", "disable") == "enable",
            )
            session.add(obj)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _ingest_logging(self, parsed: dict, device: Device, session: Session):
        log_sources = [
            ("log syslogd setting", "syslog"),
            ("log fortianalyzer setting", "fortianalyzer"),
            ("log disk setting", "local"),
        ]
        for section_key, log_type in log_sources:
            data = parsed.get(section_key, {})
            if not data:
                obj = LoggingConfig(device_id=device.id, log_type=log_type, enabled=False)
            else:
                obj = LoggingConfig(
                    device_id=device.id,
                    log_type=log_type,
                    enabled=data.get("status", "disable") == "enable",
                    server=data.get("server"),
                    port=_parse_int(data.get("port")),
                    log_level=data.get("severity"),
                    traffic_log=data.get("traffic-log", "disable") == "enable",
                    event_log=data.get("event-log", "disable") == "enable",
                )
            session.add(obj)
