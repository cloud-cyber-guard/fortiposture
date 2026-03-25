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

"""Security posture checks for FortiGate device configurations."""

import ipaddress
import json
import logging
from datetime import datetime
from typing import List, Optional

from sqlalchemy.orm import Session

from fortiposture.models.schema import (
    AdminAccount, AnalysisRun, Device, Finding, FirewallPolicy,
    LoggingConfig, PostureScore,
)
from fortiposture.analysis.scoring import calculate_score

logger = logging.getLogger(__name__)

RISKY_PORTS = {
    21: ("FTP", "Use SFTP or SCP instead. FTP transmits credentials in plaintext."),
    23: ("Telnet", "Use SSH instead. Telnet transmits data in plaintext."),
    69: ("TFTP", "Restrict to isolated management networks or disable."),
    139: ("NetBIOS", "Block at perimeter. NetBIOS is not routable and exposes Windows shares."),
    445: ("SMB/CIFS", "Block at perimeter. SMB is frequently exploited (EternalBlue, WannaCry)."),
    1433: ("MSSQL", "Never expose database ports directly. Use application-layer access."),
    3306: ("MySQL", "Never expose database ports directly. Use application-layer access."),
    3389: ("RDP", "Restrict to VPN-gated access only. RDP is a primary ransomware vector."),
    5900: ("VNC", "Restrict to internal management networks with strong authentication."),
}


def _is_any(addresses) -> bool:
    """True if address list contains 'all' (the any/all object)."""
    return any(a.name.lower() in ("all", "any") for a in addresses)


def _is_all_service(services) -> bool:
    """True if service list contains ALL."""
    return any(s.name.upper() == "ALL" for s in services)


def _addr_to_network(addr_obj) -> Optional[ipaddress.IPv4Network]:
    """Convert AddressObject to IPv4Network for subnet containment checks."""
    if not addr_obj.value:
        return None
    try:
        # value is "10.0.0.0 255.0.0.0" or "10.0.0.0/8"
        val = addr_obj.value.replace(" ", "/")
        return ipaddress.IPv4Network(val, strict=False)
    except ValueError:
        return None


def _port_range_contains(outer_start, outer_end, inner_start, inner_end) -> bool:
    if None in (outer_start, outer_end, inner_start, inner_end):
        return False
    return outer_start <= inner_start and outer_end >= inner_end


def _policy_covers(broader: FirewallPolicy, narrower: FirewallPolicy) -> bool:
    """Return True if broader ACCEPT rule shadows narrower rule."""
    if broader.action != "accept" or broader.status != "enabled":
        return False
    if broader.sequence_num >= narrower.sequence_num:
        return False

    # Source address containment
    if not _is_any(broader.src_addresses):
        b_nets = [_addr_to_network(a) for a in broader.src_addresses]
        n_nets = [_addr_to_network(a) for a in narrower.src_addresses]
        if not all(
            any(b and n and (b.supernet_of(n) or b == n) for b in b_nets if b)
            for n in n_nets if n
        ):
            return False

    # Destination address containment
    if not _is_any(broader.dst_addresses):
        b_nets = [_addr_to_network(a) for a in broader.dst_addresses]
        n_nets = [_addr_to_network(a) for a in narrower.dst_addresses]
        if not all(
            any(b and n and (b.supernet_of(n) or b == n) for b in b_nets if b)
            for n in n_nets if n
        ):
            return False

    # Service containment
    if not _is_all_service(broader.services):
        for n_svc in narrower.services:
            covered = False
            for b_svc in broader.services:
                if b_svc.name == n_svc.name:
                    covered = True
                    break
                if _port_range_contains(
                    b_svc.port_range_start, b_svc.port_range_end,
                    n_svc.port_range_start, n_svc.port_range_end,
                ):
                    covered = True
                    break
            if not covered:
                return False

    return True


def _parse_allowaccess(raw: Optional[str]) -> set:
    """Parse Interface.allowaccess JSON into a set of lowercase protocol names.

    Handles both ['https ssh ping'] (single compound string) and
    ['https', 'ssh', 'ping'] (proper list) storage formats.
    """
    items = json.loads(raw or "[]")
    result = set()
    for item in items:
        for part in str(item).split():
            result.add(part.lower())
    return result


_WAN_NAME_PATTERNS = ("wan", "internet", "external", "outside", "untrust", "public")
_RFC1918 = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
]


def _is_wan_interface(iface) -> bool:
    """True if interface is WAN-facing (by name pattern or public IP)."""
    name = (iface.name or "").lower()
    if any(pat in name for pat in _WAN_NAME_PATTERNS):
        return True
    if iface.ip_address:
        try:
            addr = ipaddress.IPv4Address(iface.ip_address)
            if not any(addr in net for net in _RFC1918):
                return True
        except ValueError:
            pass
    return False


# ------------------------------------------------------------------
# Individual checks
# ------------------------------------------------------------------

def check_any_any_rule(device: Device, session: Session) -> List[Finding]:
    findings = []
    for policy in device.policies:
        if policy.action != "accept" or policy.status != "enabled":
            continue
        if _is_any(policy.src_addresses) and _is_any(policy.dst_addresses) and _is_all_service(policy.services):
            findings.append(Finding(
                device_id=device.id,
                check_id="ANY_ANY_RULE",
                severity="CRITICAL",
                title="Accept-all rule (any/any/ALL)",
                description=(
                    f"Policy '{policy.name}' (seq {policy.sequence_num}) accepts all traffic "
                    "from any source to any destination on all services. This effectively "
                    "disables the firewall."
                ),
                remediation=(
                    "1. Remove or disable this rule immediately.\n"
                    "2. Replace with explicit rules permitting only required traffic.\n"
                    "3. Implement a default deny-all rule at the bottom of the policy list."
                ),
                standard_references=json.dumps([
                    "NIST SP 800-41 Rev 1 Sec 3.3",
                    "CIS FortiGate Benchmark 1.1.1",
                    "PCI DSS 1.2.1",
                ]),
                affected_object_name=policy.name,
                evidence=json.dumps({
                    "policy_name": policy.name,
                    "sequence_num": policy.sequence_num,
                    "action": policy.action,
                    "src": [a.name for a in policy.src_addresses],
                    "dst": [a.name for a in policy.dst_addresses],
                    "service": [s.name for s in policy.services],
                }),
            ))
    return findings


def check_logging_disabled(device: Device, session: Session) -> List[Finding]:
    findings = []
    for policy in device.policies:
        if policy.action != "accept" or policy.status != "enabled":
            continue
        if policy.log_traffic == "disable":
            findings.append(Finding(
                device_id=device.id,
                check_id="LOGGING_DISABLED",
                severity="HIGH",
                title="Traffic logging disabled on accept rule",
                description=(
                    f"Policy '{policy.name}' (seq {policy.sequence_num}) accepts traffic "
                    "but has logging disabled. This creates blind spots in audit trails."
                ),
                remediation=(
                    "1. Set logtraffic to 'all' or 'utm' on this policy.\n"
                    "2. Ensure logs are forwarded to an external SIEM or syslog server."
                ),
                standard_references=json.dumps([
                    "PCI DSS 10.2",
                    "NIST SP 800-92",
                    "CIS FortiGate Benchmark 1.2",
                ]),
                affected_object_name=policy.name,
                evidence=json.dumps({
                    "policy_name": policy.name,
                    "sequence_num": policy.sequence_num,
                    "log_traffic": policy.log_traffic,
                }),
            ))
    return findings


def check_shadowed_rules(device: Device, session: Session) -> List[Finding]:
    findings = []
    policies = sorted(
        [p for p in device.policies if p.status == "enabled"],
        key=lambda p: p.sequence_num,
    )
    for i, narrower in enumerate(policies):
        if narrower.action != "accept":
            continue
        for broader in policies[:i]:
            if _policy_covers(broader, narrower):
                findings.append(Finding(
                    device_id=device.id,
                    check_id="SHADOWED_RULE",
                    severity="HIGH",
                    title=f"Shadowed rule: '{narrower.name}'",
                    description=(
                        f"Policy '{narrower.name}' (seq {narrower.sequence_num}) can never "
                        f"be matched because policy '{broader.name}' (seq {broader.sequence_num}) "
                        "already covers its entire traffic space."
                    ),
                    remediation=(
                        "1. Review both rules and determine which is intended.\n"
                        "2. Remove or reorder the shadowed rule.\n"
                        "3. If the shadowed rule has stricter controls, reorder it above the broader rule."
                    ),
                    standard_references=json.dumps([
                        "CIS FortiGate Benchmark",
                        "NIST SP 800-41",
                    ]),
                    affected_object_name=narrower.name,
                    evidence=json.dumps({
                        "shadowed_policy": narrower.name,
                        "shadowed_seq": narrower.sequence_num,
                        "shadowing_policy": broader.name,
                        "shadowing_seq": broader.sequence_num,
                    }),
                ))
                break  # one finding per shadowed rule
    return findings


def check_risky_service_exposed(device: Device, session: Session) -> List[Finding]:
    findings = []
    for policy in device.policies:
        if policy.action != "accept" or policy.status != "enabled":
            continue
        for svc in policy.services:
            if svc.port_range_start is None:
                continue
            for port, (svc_name, rationale) in RISKY_PORTS.items():
                start = svc.port_range_start or 0
                end = svc.port_range_end or start
                if start <= port <= end:
                    findings.append(Finding(
                        device_id=device.id,
                        check_id="RISKY_SERVICE_EXPOSED",
                        severity="HIGH",
                        title=f"Risky service exposed: {svc_name} (port {port})",
                        description=(
                            f"Policy '{policy.name}' (seq {policy.sequence_num}) permits "
                            f"{svc_name} (TCP/UDP {port}) traffic."
                        ),
                        remediation=(
                            f"1. {rationale}\n"
                            "2. Replace with encrypted or application-layer alternatives.\n"
                            "3. If required, restrict to specific source/destination IPs."
                        ),
                        standard_references=json.dumps([
                            "DISA STIG FortiGate",
                            "CIS FortiGate Benchmark",
                        ]),
                        affected_object_name=policy.name,
                        evidence=json.dumps({
                            "policy_name": policy.name,
                            "service": svc.name,
                            "port": port,
                            "protocol": svc.protocol,
                        }),
                    ))
    return findings


def check_missing_deny_all(device: Device, session: Session) -> List[Finding]:
    policies = sorted(
        [p for p in device.policies if p.status == "enabled"],
        key=lambda p: p.sequence_num,
    )
    if not policies:
        return []
    last = policies[-1]
    is_deny_all = (
        last.action in ("deny", "drop")
        and _is_any(last.src_addresses)
        and _is_any(last.dst_addresses)
        and _is_all_service(last.services)
    )
    if not is_deny_all:
        return [Finding(
            device_id=device.id,
            check_id="MISSING_DENY_ALL",
            severity="HIGH",
            title="No explicit deny-all rule at end of policy list",
            description=(
                "The policy list does not end with an explicit deny-all rule. "
                "While FortiGate has an implicit deny, best practice requires an "
                "explicit deny-all as the final rule for audit trail purposes."
            ),
            remediation=(
                "1. Add an explicit deny-all rule as the final policy.\n"
                "2. Set action=deny, src=any, dst=any, service=ALL.\n"
                "3. Enable logging on the deny-all rule to capture blocked traffic."
            ),
            standard_references=json.dumps([
                "CIS FortiGate Benchmark 1.1.2",
                "PCI DSS 1.2.1",
                "NIST SP 800-41",
            ]),
            affected_object_name=last.name or f"seq {last.sequence_num}",
            evidence=json.dumps({
                "last_rule_name": last.name,
                "last_rule_action": last.action,
                "last_rule_seq": last.sequence_num,
            }),
        )]
    return []


def check_admin_no_mfa(device: Device, session: Session) -> List[Finding]:
    affected = []
    has_super_admin = False
    total = 0
    for admin in device.admins:
        if admin.auth_type != "local":
            continue
        total += 1
        if not admin.two_factor_auth:
            is_super = (admin.access_profile or "").lower() in ("super_admin", "super-admin")
            affected.append({
                "username": admin.username,
                "access_profile": admin.access_profile,
                "is_super_admin": is_super,
            })
            if is_super:
                has_super_admin = True

    if not affected:
        return []

    severity = "CRITICAL" if has_super_admin else "HIGH"
    return [Finding(
        device_id=device.id,
        check_id="ADMIN_NO_MFA",
        severity=severity,
        title=f"{len(affected)} of {total} admin account(s) lack MFA",
        description=(
            f"{len(affected)} local admin account(s) have no multi-factor authentication. "
            + ("One or more are super_admin — immediate risk." if has_super_admin else "")
        ),
        remediation=(
            "Enable two-factor authentication (FortiToken, email, or SMS) for all admin accounts. "
            "Prefer FortiToken hardware or mobile tokens. "
            "Consider integrating with RADIUS/LDAP with MFA enforcement."
        ),
        standard_references=json.dumps([
            "NIST SP 800-63B",
            "CIS FortiGate Benchmark 1.3",
            "PCI DSS 8.3",
        ]),
        evidence=json.dumps({
            "affected_accounts": affected,
            "total_local_accounts": total,
        }),
    )]


def check_admin_unrestricted_access(device: Device, session: Session) -> List[Finding]:
    affected = []
    total = len(device.admins)
    for admin in device.admins:
        trusted = json.loads(admin.trusted_hosts or "[]")
        if not trusted:
            affected.append({
                "username": admin.username,
                "access_profile": admin.access_profile,
            })

    if not affected:
        return []

    return [Finding(
        device_id=device.id,
        check_id="ADMIN_UNRESTRICTED_ACCESS",
        severity="HIGH",
        title=f"{len(affected)} of {total} admin account(s) have no trusted hosts",
        description=(
            f"{len(affected)} admin account(s) have no trusted hosts configured, "
            "allowing login from any IP address."
        ),
        remediation=(
            "Configure trusted hosts on all admin accounts to restrict access to specific IP ranges. "
            "Use management VLAN IP ranges only. "
            "Set trusthost1 through trusthost10 to cover management workstation IPs."
        ),
        standard_references=json.dumps(["CIS FortiGate Benchmark"]),
        evidence=json.dumps({
            "affected_accounts": affected,
            "total_accounts": total,
        }),
    )]


def check_logging_not_configured(device: Device, session: Session) -> List[Finding]:
    external_logs = session.query(LoggingConfig).filter_by(device_id=device.id).filter(
        LoggingConfig.log_type.in_(["syslog", "fortianalyzer", "forticloud"]),
        LoggingConfig.enabled == True,
    ).all()
    if not external_logs:
        log_status = {
            lc.log_type: lc.enabled
            for lc in session.query(LoggingConfig).filter_by(device_id=device.id).all()
        }
        return [Finding(
            device_id=device.id,
            check_id="LOGGING_NOT_CONFIGURED",
            severity="MEDIUM",
            title="No external logging destination configured",
            description=(
                "No external logging (syslog, FortiAnalyzer, or FortiCloud) is enabled. "
                "Local disk logging alone is insufficient for compliance and forensics."
            ),
            remediation=(
                "1. Configure syslog forwarding to a SIEM.\n"
                "2. Or connect device to FortiAnalyzer.\n"
                "3. Ensure log integrity with external storage."
            ),
            standard_references=json.dumps([
                "PCI DSS 10.5",
                "NIST SP 800-92",
            ]),
            affected_object_name="logging configuration",
            evidence=json.dumps(log_status),
        )]
    return []


def check_weak_password_policy(device: Device, session: Session) -> List[Finding]:
    """
    Requires: Device.vendor_data (JSON Text column) storing parsed "system password-policy" dict.
    """
    try:
        vd = json.loads(device.vendor_data or "{}")
        # Support both old format (flat dict) and new format (nested with key)
        if "system password-policy" in vd:
            pwd_policy = vd["system password-policy"]
        else:
            pwd_policy = vd  # backward compat with old DB rows
    except (ValueError, TypeError):
        pwd_policy = {}

    if not pwd_policy:
        return [Finding(
            device_id=device.id,
            check_id="WEAK_PASSWORD_POLICY",
            severity="MEDIUM",
            title="Password policy not configured",
            description="No system password policy is configured on this device.",
            remediation=(
                "1. Enable: config system password-policy → set status enable\n"
                "2. Set minimum-length to at least 12.\n"
                "3. Require upper-case, lower-case, number, non-alphanumeric."
            ),
            standard_references=json.dumps(["NIST SP 800-63B", "CIS FortiGate Benchmark 1.3"]),
            affected_object_name="system password-policy",
            evidence=json.dumps({"policy": "not configured"}),
        )]

    min_length = int(pwd_policy.get("minimum-length", 0))
    if min_length < 8:
        return [Finding(
            device_id=device.id,
            check_id="WEAK_PASSWORD_POLICY",
            severity="MEDIUM",
            title=f"Weak password policy: minimum length {min_length} (< 8)",
            description=f"Password minimum length is {min_length}, below recommended minimum of 8.",
            remediation="Set minimum-length to at least 12 and enable complexity requirements.",
            standard_references=json.dumps(["NIST SP 800-63B", "CIS FortiGate Benchmark 1.3"]),
            affected_object_name="system password-policy",
            evidence=json.dumps(pwd_policy),
        )]
    return []


def check_disabled_policy(device: Device, session: Session) -> List[Finding]:
    findings = []
    for policy in device.policies:
        if policy.action == "accept" and policy.status == "disabled":
            findings.append(Finding(
                device_id=device.id,
                check_id="DISABLED_POLICY",
                severity="LOW",
                title=f"Disabled accept rule: '{policy.name}'",
                description=(
                    f"Policy '{policy.name}' (seq {policy.sequence_num}) is an accept "
                    "rule that is disabled. Disabled rules indicate rule bloat."
                ),
                remediation=(
                    "1. Review whether this rule is still needed.\n"
                    "2. If not needed, remove it entirely.\n"
                    "3. If needed, re-enable with proper justification."
                ),
                standard_references=json.dumps(["CIS FortiGate Benchmark"]),
                affected_object_name=policy.name,
                evidence=json.dumps({
                    "policy_name": policy.name,
                    "sequence_num": policy.sequence_num,
                    "status": policy.status,
                }),
            ))
    return findings


def check_broad_destination(device: Device, session: Session) -> List[Finding]:
    findings = []
    for policy in device.policies:
        if policy.action != "accept" or policy.status != "enabled":
            continue
        if _is_any(policy.dst_addresses) and not _is_any(policy.src_addresses):
            findings.append(Finding(
                device_id=device.id,
                check_id="BROAD_DESTINATION",
                severity="MEDIUM",
                title=f"Broad destination (any) with specific source: '{policy.name}'",
                description=(
                    f"Policy '{policy.name}' (seq {policy.sequence_num}) has a specific "
                    "source address but destination=any. The destination should be scoped."
                ),
                remediation=(
                    "1. Define explicit destination address objects.\n"
                    "2. Replace 'all' destination with specific server or subnet objects."
                ),
                standard_references=json.dumps(["NIST SP 800-41"]),
                affected_object_name=policy.name,
                evidence=json.dumps({
                    "policy_name": policy.name,
                    "src": [a.name for a in policy.src_addresses],
                    "dst": "all",
                }),
            ))
    return findings


def check_http_admin_enabled(device: Device, session: Session) -> List[Finding]:
    """Flag any interface that allows HTTP (unencrypted) management access."""
    http_ifaces = []
    for iface in device.interfaces:
        if iface.status and iface.status.lower() == "down":
            continue
        protocols = _parse_allowaccess(iface.allowaccess)
        if "http" in protocols:
            http_ifaces.append({
                "interface": iface.name,
                "ip_address": iface.ip_address,
                "allowaccess": sorted(protocols),
            })

    if not http_ifaces:
        return []

    return [Finding(
        device_id=device.id,
        check_id="HTTP_ADMIN_ENABLED",
        severity="HIGH",
        title=f"HTTP management access enabled on {len(http_ifaces)} interface(s)",
        description=(
            f"HTTP (unencrypted) is allowed for admin access on: "
            f"{', '.join(i['interface'] for i in http_ifaces)}. "
            "HTTP transmits credentials and session cookies in cleartext."
        ),
        remediation=(
            "Remove 'http' from allowaccess on all interfaces. "
            "Use only 'https' for web-based management access."
        ),
        standard_references=json.dumps([
            "CIS FortiGate Benchmark 1.3",
            "NIST SP 800-41",
            "PCI DSS 2.2.7",
        ]),
        evidence=json.dumps({"http_interfaces": http_ifaces}),
    )]


def check_management_access_exposed(device: Device, session: Session) -> List[Finding]:
    """Flag WAN-facing interfaces that allow management protocols (HTTPS, SSH, HTTP)."""
    _MGMT_PROTOCOLS = {"https", "ssh", "http"}
    exposed = []
    for iface in device.interfaces:
        if iface.status and iface.status.lower() == "down":
            continue
        if not _is_wan_interface(iface):
            continue
        protocols = _parse_allowaccess(iface.allowaccess)
        mgmt_allowed = protocols & _MGMT_PROTOCOLS
        if mgmt_allowed:
            exposed.append({
                "interface": iface.name,
                "ip_address": iface.ip_address,
                "management_protocols": sorted(mgmt_allowed),
            })

    if not exposed:
        return []

    return [Finding(
        device_id=device.id,
        check_id="MANAGEMENT_ACCESS_EXPOSED",
        severity="HIGH",
        title=f"Management access exposed on {len(exposed)} WAN-facing interface(s)",
        description=(
            f"Management protocols (HTTPS/SSH/HTTP) are allowed on WAN-facing interface(s): "
            f"{', '.join(i['interface'] for i in exposed)}."
        ),
        remediation=(
            "Restrict management access to dedicated management interfaces or specific trusted IPs only. "
            "Use trusted hosts on admin accounts and Local-In policies to restrict access to the firewall itself."
        ),
        standard_references=json.dumps([
            "CIS FortiGate Benchmark 1.3.1",
            "NIST SP 800-41",
            "DISA STIG FortiGate",
        ]),
        evidence=json.dumps({"wan_interfaces": exposed}),
    )]


def check_geoblock_absent(device: Device, session: Session) -> List[Finding]:
    """Flag when no GeoIP blocking is configured or geo objects not used in deny rules."""
    from fortiposture.models.schema import AddressObject as _AO

    # Find all geography address objects for this device
    all_addrs = session.query(_AO).filter_by(device_id=device.id).all()
    geo_names = set()
    for addr in all_addrs:
        try:
            raw = json.loads(addr.vendor_data or "{}")
        except (ValueError, TypeError):
            raw = {}
        if raw.get("type") == "geography":
            geo_names.add(addr.name)

    if not geo_names:
        return [Finding(
            device_id=device.id,
            check_id="GEOBLOCK_ABSENT",
            severity="MEDIUM",
            title="No GeoIP blocking configured",
            description=(
                "No geography-based address objects were found. "
                "Geographic blocking reduces attack surface from high-risk regions."
            ),
            remediation=(
                "Implement geographic blocking for countries with no business relationship. "
                "In FortiGate: Policy & Objects > Addresses > Create New > Type: Geography. "
                "Add to a DENY rule before the default deny-all."
            ),
            standard_references=json.dumps([
                "CIS FortiGate Benchmark",
                "NIST SP 800-41",
            ]),
            evidence=json.dumps({
                "geo_objects_defined": 0,
                "used_in_deny_rules": False,
            }),
        )]

    # Case B: geo objects exist — check if any appear in DENY policies
    used_in_deny = False
    for policy in device.policies:
        if policy.action not in ("deny", "drop"):
            continue
        for addr in policy.src_addresses:
            if addr.name in geo_names:
                used_in_deny = True
                break
        if used_in_deny:
            break

    if used_in_deny:
        return []

    return [Finding(
        device_id=device.id,
        check_id="GEOBLOCK_ABSENT",
        severity="MEDIUM",
        title="GeoIP objects defined but not used in deny rules",
        description=(
            f"Geography address objects exist ({', '.join(sorted(geo_names))}) "
            "but none are referenced in any DENY policy rule."
        ),
        remediation=(
            "Create a DENY policy rule that uses the geography address objects as source. "
            "Place it before any ACCEPT rules to ensure it takes effect."
        ),
        standard_references=json.dumps([
            "CIS FortiGate Benchmark",
            "NIST SP 800-41",
        ]),
        evidence=json.dumps({
            "geo_objects_defined": len(geo_names),
            "geo_object_names": sorted(geo_names),
            "used_in_deny_rules": False,
        }),
    )]


def check_geoblock_bypass_risk(device: Device, session: Session) -> List[Finding]:
    """Flag when geo blocking is active but SSL VPN portal lacks Local-In geo policies."""
    from fortiposture.models.schema import AddressObject as _AO

    # Condition 1: geo objects used in deny rules?
    all_addrs = session.query(_AO).filter_by(device_id=device.id).all()
    geo_names = set()
    for addr in all_addrs:
        try:
            raw = json.loads(addr.vendor_data or "{}")
        except (ValueError, TypeError):
            raw = {}
        if raw.get("type") == "geography":
            geo_names.add(addr.name)

    geo_in_deny = False
    for policy in device.policies:
        if policy.action not in ("deny", "drop"):
            continue
        for addr in policy.src_addresses:
            if addr.name in geo_names:
                geo_in_deny = True
                break
        if geo_in_deny:
            break

    if not geo_in_deny:
        return []  # No geo blocking → nothing to bypass

    # Condition 2: SSL VPN enabled?
    try:
        vd = json.loads(device.vendor_data or "{}")
    except (ValueError, TypeError):
        vd = {}
    ssl_settings = vd.get("vpn ssl settings", {})
    ssl_enabled = ssl_settings.get("status", "disable") == "enable"

    if not ssl_enabled:
        return []  # No SSL VPN → no bypass risk

    # Condition 3: Local-In policies referencing geo objects?
    local_in = vd.get("firewall local-in-policy", {})
    has_localin_geo = False
    for _, lip_data in local_in.items():
        if not isinstance(lip_data, dict):
            continue
        src = lip_data.get("srcaddr", "")
        # srcaddr may be a string or list
        if isinstance(src, list):
            srcs = src
        else:
            srcs = [src]
        for s in srcs:
            if str(s) in geo_names:
                has_localin_geo = True
                break
        if has_localin_geo:
            break

    if has_localin_geo:
        return []  # Local-In geo policies present → risk mitigated

    return [Finding(
        device_id=device.id,
        check_id="GEOBLOCK_BYPASS_RISK",
        severity="HIGH",
        title="GeoIP blocks do not protect SSL VPN (missing Local-In policy)",
        description=(
            "GeoIP blocking via IPv4 policies only filters traffic passing THROUGH the firewall. "
            "SSL VPN portal and management interfaces are governed by Local-In policies. "
            "Blocked countries can still reach the SSL VPN portal."
        ),
        remediation=(
            "Create Local-In policies to apply geographic restrictions to the FortiGate management "
            "and SSL VPN interfaces. Example:\n"
            "  config firewall local-in-policy\n"
            "    edit 1\n"
            "      set intf \"wan1\"\n"
            "      set srcaddr \"<geo-group>\"\n"
            "      set dstaddr \"all\"\n"
            "      set action deny\n"
            "      set schedule \"always\"\n"
            "    next\n"
            "  end"
        ),
        standard_references=json.dumps([
            "Fortinet KB: Local-In Policies and Geoblocking",
            "CIS FortiGate Benchmark",
            "DISA STIG FortiGate",
        ]),
        evidence=json.dumps({
            "geo_objects_defined": sorted(geo_names),
            "ssl_vpn_enabled": ssl_enabled,
            "local_in_geo_policies": has_localin_geo,
        }),
    )]


# ------------------------------------------------------------------
# Orchestrator
# ------------------------------------------------------------------

ALL_CHECKS = [
    check_any_any_rule,
    check_logging_disabled,
    check_shadowed_rules,
    check_risky_service_exposed,
    check_missing_deny_all,
    check_admin_no_mfa,
    check_admin_unrestricted_access,
    check_logging_not_configured,
    check_weak_password_policy,
    check_disabled_policy,
    check_broad_destination,
    check_http_admin_enabled,
    check_management_access_exposed,
    check_geoblock_absent,
    check_geoblock_bypass_risk,
]


def run_all_checks(device: Device, session: Session) -> List[Finding]:
    """Run all checks against a device, persist findings, return list."""
    run = AnalysisRun(
        device_id=device.id,
        started_at=datetime.utcnow(),
        checks_run=json.dumps([c.__name__ for c in ALL_CHECKS]),
    )
    session.add(run)
    session.flush()

    all_findings = []
    for check_fn in ALL_CHECKS:
        try:
            findings = check_fn(device, session)
            for f in findings:
                f.analysis_run_id = run.id
                session.add(f)
            all_findings.extend(findings)
        except Exception as e:
            logger.warning("Check %s failed for %s: %s", check_fn.__name__, device.hostname, e)

    counts = {
        "CRITICAL": sum(1 for f in all_findings if f.severity == "CRITICAL"),
        "HIGH": sum(1 for f in all_findings if f.severity == "HIGH"),
        "MEDIUM": sum(1 for f in all_findings if f.severity == "MEDIUM"),
        "LOW": sum(1 for f in all_findings if f.severity == "LOW"),
    }
    score, grade = calculate_score(**{k.lower(): v for k, v in counts.items()})

    posture = PostureScore(
        analysis_run_id=run.id,
        device_id=device.id,
        score=score,
        grade=grade,
        critical_count=counts["CRITICAL"],
        high_count=counts["HIGH"],
        medium_count=counts["MEDIUM"],
        low_count=counts["LOW"],
    )
    session.add(posture)

    run.completed_at = datetime.utcnow()
    run.status = "completed"
    run.total_findings = len(all_findings)
    session.commit()

    return all_findings
