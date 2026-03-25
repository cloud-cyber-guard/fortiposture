# Security Checks Reference

This document describes all 19 security checks performed by `fortiposture`, including detection logic, evidence format, remediation guidance, and compliance mappings.

---

## Table of Contents

- [Policy Checks](#policy-checks)
  - [ANY_ANY_RULE](#any_any_rule)
  - [LOGGING_DISABLED](#logging_disabled)
  - [SHADOWED_RULE](#shadowed_rule)
  - [RISKY_SERVICE_EXPOSED](#risky_service_exposed)
  - [MISSING_DENY_ALL](#missing_deny_all)
  - [BROAD_DESTINATION](#broad_destination)
  - [DISABLED_POLICY](#disabled_policy)
- [Admin Account Checks](#admin-account-checks)
  - [ADMIN_NO_MFA](#admin_no_mfa)
  - [ADMIN_UNRESTRICTED_ACCESS](#admin_unrestricted_access)
- [Logging Checks](#logging-checks)
  - [LOGGING_NOT_CONFIGURED](#logging_not_configured)
- [Password Policy Checks](#password-policy-checks)
  - [WEAK_PASSWORD_POLICY](#weak_password_policy)
- [Interface Checks](#interface-checks)
  - [HTTP_ADMIN_ENABLED](#http_admin_enabled)
  - [MANAGEMENT_ACCESS_EXPOSED](#management_access_exposed)
- [Geographic Access Checks](#geographic-access-checks)
  - [GEOBLOCK_ABSENT](#geoblock_absent)
  - [GEOBLOCK_BYPASS_RISK](#geoblock_bypass_risk)
- [Firmware Checks](#firmware-checks)
  - [FIRMWARE_EOL](#firmware_eol)
- [System Configuration Checks](#system-configuration-checks)
  - [NTP_NOT_CONFIGURED](#ntp_not_configured)
- [VPN Checks](#vpn-checks)
  - [WEAK_CRYPTO_VPN](#weak_crypto_vpn)
- [SNMP Checks](#snmp-checks)
  - [SNMP_WEAK_VERSION](#snmp_weak_version)
- [Compliance Mapping](#compliance-mapping)

---

## Policy Checks

### ANY_ANY_RULE

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **Check ID** | `ANY_ANY_RULE` |
| **Category** | Firewall policy |

**What it detects**

An enabled ACCEPT rule where the source address is `all` (any), the destination address is `all` (any), and the service is `ALL`. This rule effectively disables the firewall — all traffic from any source to any destination on any port is permitted.

**Detection logic**

```
policy.action == "accept"
AND policy.status == "enabled"
AND src_addresses contains "all" or "any"
AND dst_addresses contains "all" or "any"
AND services contains "ALL"
```

**Evidence JSON**

```json
{
  "policy_name": "test-policy",
  "sequence_num": 1,
  "action": "accept",
  "src": ["all"],
  "dst": ["all"],
  "service": ["ALL"]
}
```

**Remediation**

1. Remove or disable this rule immediately.
2. Replace with explicit rules permitting only the specific traffic flows required.
3. Implement a default deny-all rule at the bottom of the policy list.

**Compliance references**

- NIST SP 800-41 Rev 1, Section 3.3 — *Policies for traffic filtering*
- CIS FortiGate Benchmark 1.1.1
- PCI DSS 1.2.1 — *Restrict inbound and outbound traffic to that which is necessary*

---

### LOGGING_DISABLED

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Check ID** | `LOGGING_DISABLED` |
| **Category** | Firewall policy |

**What it detects**

An enabled ACCEPT rule with `set logtraffic disable`. Without logging, permitted traffic flows leave no audit trail, making forensic investigation and compliance reporting impossible.

**Detection logic**

```
policy.action == "accept"
AND policy.status == "enabled"
AND policy.log_traffic == "disable"
```

**Evidence JSON**

```json
{
  "policy_name": "internal-to-internet",
  "sequence_num": 3,
  "log_traffic": "disable"
}
```

**Remediation**

1. Set `logtraffic` to `all` or `utm` on this policy.
2. Ensure logs are forwarded to an external SIEM or syslog server (see `LOGGING_NOT_CONFIGURED`).

**Compliance references**

- PCI DSS 10.2 — *Implement audit logs to reconstruct events*
- NIST SP 800-92 — *Guide to computer security log management*
- CIS FortiGate Benchmark 1.2

---

### SHADOWED_RULE

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Check ID** | `SHADOWED_RULE` |
| **Category** | Firewall policy |

**What it detects**

An ACCEPT rule that can never be matched because a broader ACCEPT rule earlier in the policy list already covers its entire traffic space. The shadowed rule is dead code — it will never be evaluated.

**Detection logic**

Rules are sorted by sequence number. For each ACCEPT rule (the "narrower" rule), fortiposture checks all preceding ACCEPT rules (the "broader" rules) to determine if one shadows it:

- **Source address containment**: the broader rule's source is `all`, or every source subnet of the narrower rule is a subnet of (or equal to) a source subnet of the broader rule (`ipaddress.subnet_of`)
- **Destination address containment**: same logic applied to destination addresses
- **Service containment**: the broader rule's service is `ALL`, or every service port range of the narrower rule falls within a port range of the broader rule

All three conditions must hold simultaneously for shadowing to be detected.

**Example config that triggers this check:**

```
config firewall policy
    edit 1
        set name "broad-rule"
        set srcaddr "10.0.0.0/8"
        set dstaddr "all"
        set service "TCP-80"
        set action accept
    next
    edit 2
        set name "narrow-rule"
        set srcaddr "10.1.0.0/16"   ← subnet of 10.0.0.0/8
        set dstaddr "all"
        set service "TCP-80"        ← same service
        set action accept
    next
end
```

Rule 2 is shadowed by Rule 1.

**Evidence JSON**

```json
{
  "shadowed_policy": "narrow-rule",
  "shadowed_seq": 2,
  "shadowing_policy": "broad-rule",
  "shadowing_seq": 1
}
```

**Remediation**

1. Review both rules and determine which represents the intended configuration.
2. Remove the shadowed rule if it is no longer needed.
3. If the shadowed rule has stricter controls than the broader rule, reorder it above the broader rule.

**Compliance references**

- CIS FortiGate Benchmark — *Remove unused and shadowed rules*
- NIST SP 800-41 — *Firewall rule set review*

---

### RISKY_SERVICE_EXPOSED

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Check ID** | `RISKY_SERVICE_EXPOSED` |
| **Category** | Firewall policy |

**What it detects**

An enabled ACCEPT rule that permits traffic on one or more services known to be high-risk due to inherent protocol weaknesses, known exploits, or cleartext transmission.

**Monitored ports**

| Port | Protocol | Risk |
|------|----------|------|
| 21 | FTP | Cleartext credentials; use SFTP or SCP instead |
| 23 | Telnet | Cleartext session; use SSH instead |
| 69 | TFTP | No authentication; restrict to isolated management networks |
| 139 | NetBIOS | Not routable; exposes Windows file shares |
| 445 | SMB/CIFS | Primary vector for EternalBlue, WannaCry, ransomware |
| 1433 | MSSQL | Direct database port exposure; use application-layer access |
| 3306 | MySQL | Direct database port exposure; use application-layer access |
| 3389 | RDP | Primary ransomware delivery vector; restrict to VPN-gated access |
| 5900 | VNC | Weak authentication; restrict to internal management networks |

**Detection logic**

For each service object in each enabled ACCEPT policy, if the service's port range (`port_range_start` to `port_range_end`) contains any of the monitored ports, a finding is raised.

**Evidence JSON**

```json
{
  "policy_name": "office-to-servers",
  "service": "RDP",
  "port": 3389,
  "protocol": "tcp"
}
```

**Remediation**

Specific per port. General guidance:

1. Replace cleartext protocols (FTP, Telnet) with encrypted alternatives (SFTP/SCP, SSH).
2. Expose database ports (MSSQL, MySQL) only through application-layer access, never directly.
3. If RDP or VNC access is required, restrict to VPN-only access with MFA enforced.
4. Scope all rules with the most specific source and destination addresses possible.

**Compliance references**

- DISA STIG FortiGate — *Restrict access to risky services*
- CIS FortiGate Benchmark — *Limit exposure of risky protocols*

---

### MISSING_DENY_ALL

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Check ID** | `MISSING_DENY_ALL` |
| **Category** | Firewall policy |

**What it detects**

The policy list does not end with an explicit `deny all` rule (action=deny/drop, src=any, dst=any, service=ALL).

FortiGate has an implicit deny-all at the end of every policy list. However, best practice requires an **explicit** deny-all rule because:

- The explicit rule generates a log entry for every blocked connection, creating an audit trail
- Implicit denies are invisible — you cannot verify they are working without an explicit rule
- Compliance frameworks (PCI DSS, NIST) require explicit policy and audit evidence

**Detection logic**

```
last_enabled_policy.action NOT IN ("deny", "drop")
OR last_enabled_policy.src_addresses does NOT contain "all"
OR last_enabled_policy.dst_addresses does NOT contain "all"
OR last_enabled_policy.services does NOT contain "ALL"
```

**Evidence JSON**

```json
{
  "last_rule_name": "allow-internal",
  "last_rule_action": "accept",
  "last_rule_seq": 10
}
```

**Remediation**

1. Add an explicit deny-all rule as the final policy in the list.
2. Configuration: `action=deny`, `srcaddr=all`, `dstaddr=all`, `service=ALL`.
3. Enable logging on the deny-all rule (`set logtraffic all`) to capture all blocked traffic.

**Compliance references**

- CIS FortiGate Benchmark 1.1.2
- PCI DSS 1.2.1
- NIST SP 800-41

---

### BROAD_DESTINATION

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Check ID** | `BROAD_DESTINATION` |
| **Category** | Firewall policy |

**What it detects**

An enabled ACCEPT rule with a specific named source address but `destination=all`. The source restriction suggests the rule was intended to be scoped, but the destination was left wide open. This violates the principle of least privilege.

**Detection logic**

```
policy.action == "accept"
AND policy.status == "enabled"
AND dst_addresses contains "all"
AND src_addresses does NOT contain "all"
```

**Evidence JSON**

```json
{
  "policy_name": "workstations-outbound",
  "src": ["WORKSTATION-SUBNET"],
  "dst": "all"
}
```

**Remediation**

1. Define explicit destination address objects (server subnets, specific IP ranges).
2. Replace the `all` destination with the specific servers or subnets that users in the source actually need to reach.

**Compliance references**

- NIST SP 800-41 — *Principle of least privilege in firewall rules*

---

### DISABLED_POLICY

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **Check ID** | `DISABLED_POLICY` |
| **Category** | Firewall policy |

**What it detects**

An ACCEPT rule with `status=disabled`. Disabled rules are indicators of rule bloat — policies that were once active and were disabled rather than deleted. Over time these accumulate and make rule review difficult.

**Detection logic**

```
policy.action == "accept"
AND policy.status == "disabled"
```

**Evidence JSON**

```json
{
  "policy_name": "old-vpn-access",
  "sequence_num": 7,
  "status": "disabled"
}
```

**Remediation**

1. Review whether this rule is still needed.
2. If not needed, remove it entirely rather than leaving it disabled.
3. If it will be re-enabled, document the justification in the rule's comments field.

**Compliance references**

- CIS FortiGate Benchmark — *Remove unused policies*

---

## Admin Account Checks

### ADMIN_NO_MFA

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL or HIGH (see severity tiers below) |
| **Check ID** | `ADMIN_NO_MFA` |
| **Category** | Admin accounts |

**What it detects**

One or more local-password admin accounts without two-factor authentication enabled. A single compromised password is sufficient to gain full administrative access to the firewall — there is no second factor to stop an attacker.

One finding is raised **per device**, aggregating all affected accounts. The severity depends on the highest-privilege account affected.

**Severity tiers**

| Condition | Severity |
|-----------|----------|
| Any `super_admin` profile account lacks MFA | CRITICAL |
| Only non-super-admin accounts lack MFA | HIGH |

**Detection logic**

```
FOR each local admin account on the device:
    IF admin.auth_type == "local" AND admin.two_factor_auth == False:
        add to affected list

IF any affected account has accprofile == "super_admin":
    severity = CRITICAL
ELSE:
    severity = HIGH
```

**Evidence JSON**

```json
{
  "affected_accounts": ["admin", "readonly-user"],
  "total_local_accounts": 3
}
```

**Remediation**

1. Enable two-factor authentication: `config system admin → edit <username> → set two-factor <method>`
2. Supported methods: `fortitoken` (hardware token), `fortitoken-cloud`, `email`, `sms`
3. FortiToken hardware or mobile tokens are preferred over email/SMS.
4. Consider integrating admin authentication with a RADIUS or LDAP server that enforces MFA at the directory level.

**Compliance references**

- NIST SP 800-63B — *Digital Identity Guidelines (MFA requirements)*
- CIS FortiGate Benchmark 1.3
- PCI DSS 8.3 — *Secure individual non-consumer authentication*

---

### ADMIN_UNRESTRICTED_ACCESS

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Check ID** | `ADMIN_UNRESTRICTED_ACCESS` |
| **Category** | Admin accounts |

**What it detects**

One or more admin accounts with no trusted hosts configured. Without trusted hosts, the management interface can be accessed from any IP address — increasing the attack surface for credential-based attacks.

One finding is raised **per device**, aggregating all affected accounts.

**Detection logic**

```
FOR each admin account on the device:
    IF admin.trusted_hosts == [] or null:
        add to affected list
```

**Evidence JSON**

```json
{
  "affected_accounts": ["admin", "auditor"]
}
```

**Remediation**

1. Configure trusted hosts to restrict admin logins to specific IP ranges:
   `config system admin → edit <username> → set trusthost1 <ip/mask>`
2. Use management VLAN IP ranges or dedicated jump host IPs only.
3. FortiGate supports up to 10 trusted host entries per admin (`trusthost1` through `trusthost10`).

**Compliance references**

- CIS FortiGate Benchmark — *Restrict admin access to management subnets*

---

## Logging Checks

### LOGGING_NOT_CONFIGURED

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Check ID** | `LOGGING_NOT_CONFIGURED` |
| **Category** | Logging |

**What it detects**

No external logging destination is enabled. "External" means any of: syslog, FortiAnalyzer, or FortiCloud. Local disk logging alone is insufficient because:

- Disk logs are lost when the device fails or is replaced
- Local logs can be tampered with by an attacker who gains admin access
- Compliance frameworks require tamper-evident, centrally stored logs

**Detection logic**

No `LoggingConfig` record for this device has `log_type IN ('syslog', 'fortianalyzer', 'forticloud')` with `enabled=True`.

**Evidence JSON**

```json
{
  "syslog": false,
  "fortianalyzer": false,
  "forticloud": false
}
```

**Remediation**

1. Configure syslog forwarding to a SIEM: `config log syslogd setting → set status enable → set server <ip>`
2. Or connect to FortiAnalyzer: `config log fortianalyzer setting → set status enable → set server <ip>`
3. Ensure the external log store has integrity controls (write-once storage, hash verification).

**Compliance references**

- PCI DSS 10.5 — *Secure audit trails so they cannot be altered*
- NIST SP 800-92 — *Guide to computer security log management*

---

## Password Policy Checks

### WEAK_PASSWORD_POLICY

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Check ID** | `WEAK_PASSWORD_POLICY` |
| **Category** | Password policy |

**What it detects**

Two conditions trigger this check:

1. **No password policy configured** — `config system password-policy` is absent or empty
2. **Minimum length below 8** — `set minimum-length` is set but the value is less than 8

**Detection logic**

```
device.vendor_data (password-policy section) is empty or null
→ "not configured" finding

OR

device.vendor_data["minimum-length"] < 8
→ "weak minimum length" finding
```

**Evidence JSON (not configured)**

```json
{
  "policy": "not configured"
}
```

**Evidence JSON (weak length)**

```json
{
  "status": "enable",
  "minimum-length": "6",
  "must-contain": "upper-case-letter lower-case-letter number"
}
```

**Remediation**

```
config system password-policy
    set status enable
    set minimum-length 12
    set must-contain upper-case-letter lower-case-letter number non-alphanumeric
    set expire-status enable
    set expire-day 90
end
```

**Compliance references**

- NIST SP 800-63B — *Memorized secret authenticators (password requirements)*
- CIS FortiGate Benchmark 1.3

---

## Interface Checks

### HTTP_ADMIN_ENABLED

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Check ID** | `HTTP_ADMIN_ENABLED` |
| **Category** | Interface configuration |

**What it detects**

HTTP is included in the `allowaccess` list for one or more interfaces, meaning the firewall management GUI is accessible over unencrypted HTTP. Administrative credentials and session tokens are transmitted in cleartext.

**Detection logic**

```
FOR each interface on the device:
    IF "http" IN interface.allowaccess:
        raise finding
```

**Evidence JSON**

```json
{
  "interfaces": ["port1", "mgmt"]
}
```

**Remediation**

1. Remove `http` from the `allowaccess` list on all interfaces:
   `config system interface → edit <name> → set allowaccess https ssh`
2. Use HTTPS only for management GUI access.
3. If HTTP redirect is required for user experience, configure it at the application layer, not the firewall management plane.

**Compliance references**

- CIS FortiGate Benchmark — *Disable HTTP admin access*
- DISA STIG FortiGate — *Use encrypted protocols for management*
- NIST SP 800-41 — *Secure management plane communications*

---

### MANAGEMENT_ACCESS_EXPOSED

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Check ID** | `MANAGEMENT_ACCESS_EXPOSED` |
| **Category** | Interface configuration |

**What it detects**

Management protocols (HTTPS, SSH, ping, HTTP, SNMP) are enabled on interfaces whose names indicate WAN-facing connectivity (`wan1`, `wan2`, `port1`, `untrust`, `outside`, `internet`, `external`, `uplink`). This exposes the management plane directly to the internet.

**Detection logic**

```
FOR each interface on the device:
    IF interface.name matches a WAN interface pattern:
        IF interface.allowaccess contains any management protocol:
            raise finding
```

WAN interface patterns (case-insensitive): `wan1`, `wan2`, `port1`, `untrust`, `outside`, `internet`, `external`, `uplink`.

**Evidence JSON**

```json
{
  "interfaces": [
    {"name": "wan1", "allowaccess": ["https", "ping", "ssh"]},
    {"name": "wan2", "allowaccess": ["https"]}
  ]
}
```

**Remediation**

1. Remove all management protocols from WAN-facing interfaces:
   `config system interface → edit wan1 → set allowaccess ping`
2. Restrict management access to dedicated out-of-band (OOB) interfaces or a management VLAN.
3. If remote management over WAN is required, use trusted host restrictions on admin accounts to limit access to known IP ranges.

**Compliance references**

- CIS FortiGate Benchmark — *Restrict management access to trusted interfaces*
- NIST SP 800-41 — *Separate management plane from data plane*

---

## Geographic Access Checks

### GEOBLOCK_ABSENT

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Check ID** | `GEOBLOCK_ABSENT` |
| **Category** | Geographic access control |

**What it detects**

No geography-type address objects are referenced in deny policies. This means the firewall has no country-level blocking rules. Without geographic restrictions, traffic from high-risk regions reaches the firewall management plane and data plane uninhibited.

**Detection logic**

```
geo_objects = address objects with type == "geography"
deny_policies = firewall policies with action IN ("deny", "drop")

IF len(geo_objects) == 0:
    raise finding (no geo objects at all)
ELIF none of the geo_objects appear in deny_policies:
    raise finding (geo objects exist but unused in deny rules)
```

**Evidence JSON**

```json
{
  "geo_objects_count": 0,
  "geo_in_deny_rules": false
}
```

**Remediation**

1. Create geography-type address objects for high-risk countries:
   `config firewall address → edit "COUNTRY-XX" → set type geography → set country XX`
2. Add these objects to deny policies that apply to inbound traffic from WAN interfaces.
3. Review Fortinet's threat intelligence feeds for recommended country block lists.

**Compliance references**

- CIS FortiGate Benchmark — *Implement geographic access restrictions*

---

### GEOBLOCK_BYPASS_RISK

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Check ID** | `GEOBLOCK_BYPASS_RISK` |
| **Category** | Geographic access control |

**What it detects**

Geography-based blocking is active in IPv4 firewall policies (geo objects appear in deny rules), SSL VPN is enabled, but no Local-In policies reference geography objects. This is a bypass risk: IPv4 firewall deny rules do not apply to SSL VPN and management traffic — those flows are governed by Local-In policies. The geo blocking is therefore incomplete.

**Detection logic**

```
geo_in_deny_rules == True        (geo blocking active in IPv4 policies)
AND ssl_vpn_enabled == True      (SSL VPN is listening)
AND local_in_geo_policies == 0   (no Local-In policies with geo objects)
→ raise finding
```

**Evidence JSON**

```json
{
  "geo_objects_defined": 3,
  "ssl_vpn_enabled": true,
  "local_in_geo_policies": 0
}
```

**Remediation**

1. Create Local-In policies that reference geography address objects for WAN interfaces:
   ```
   config firewall local-in-policy
       edit 1
           set intf "wan1"
           set srcaddr "BLOCKED-COUNTRIES"
           set dstaddr "all"
           set action deny
           set schedule "always"
       next
   end
   ```
2. Apply Local-In geo deny rules before any SSL VPN or management allow rules.
3. Test that blocked-country clients cannot reach the SSL VPN portal.

**Compliance references**

- Fortinet KB — *Local-In policies for SSL VPN access control*
- CIS FortiGate Benchmark — *Restrict SSL VPN access by geography*
- DISA STIG FortiGate — *Limit remote access entry points*

---

## Firmware Checks

### FIRMWARE_EOL

| Field | Value |
|-------|-------|
| **Severity** | HIGH, MEDIUM, or LOW (see severity tiers below) |
| **Check ID** | `FIRMWARE_EOL` |
| **Category** | Firmware lifecycle |

**What it detects**

The FortiGate is running end-of-life or unsupported firmware. EOL firmware no longer receives security patches, leaving known vulnerabilities permanently unaddressed.

**Severity tiers**

| Condition | Severity |
|-----------|----------|
| Major version < 7.0 (e.g., 6.x, 5.x) | HIGH |
| Version is 7.0.x or 7.1.x | MEDIUM |
| Version string present but unparseable | LOW |
| Version >= 7.2 | Not flagged |

**Detection logic**

```
version_string = device.firmware_version
parsed = parse major.minor from version_string

IF parsed major < 7:       severity = HIGH
ELIF minor in (0, 1):      severity = MEDIUM
ELIF parse fails:          severity = LOW
ELSE (>= 7.2):             no finding
```

**Evidence JSON**

```json
{
  "raw_firmware_version": "v6.4.9,build1966,220519",
  "parsed_version": "6.4",
  "eol_status": "end-of-life"
}
```

**Remediation**

1. Plan an upgrade to FortiOS 7.2 or later (current long-term support branch).
2. Review the Fortinet upgrade path tool before upgrading — intermediate versions may be required.
3. Test the upgrade in a lab environment or during a maintenance window.
4. After upgrade, verify all VPN tunnels, routing, and policy functionality.

**Compliance references**

- Fortinet Product Lifecycle — *FortiOS end-of-support dates*
- NIST SP 800-40 Rev 3 — *Guide to Enterprise Patch Management Planning*

---

## System Configuration Checks

### NTP_NOT_CONFIGURED

| Field | Value |
|-------|-------|
| **Severity** | MEDIUM |
| **Check ID** | `NTP_NOT_CONFIGURED` |
| **Category** | System configuration |

**What it detects**

NTP synchronization is absent or misconfigured. This includes: the NTP configuration block is entirely absent, `ntpsync` is set to `disable`, or no NTP server addresses are configured. Inaccurate system time undermines log forensics, certificate validation, and time-based compliance controls.

**Detection logic**

```
ntp_data = device.vendor_data["ntp"] (if present)

IF ntp_data is absent:
    reason = "ntp block absent"
ELIF ntp_data["ntpsync"] == "disable":
    reason = "ntpsync disabled"
ELIF count of configured servers == 0:
    reason = "no servers configured"
ELSE:
    no finding
```

**Evidence JSON**

```json
{
  "ntp_block_present": false,
  "ntpsync": null,
  "server_count": 0,
  "reason": "ntp block absent"
}
```

**Remediation**

```
config system ntp
    set ntpsync enable
    set type custom
    config ntpserver
        edit 1
            set server "pool.ntp.org"
        next
        edit 2
            set server "time.cloudflare.com"
        next
    end
end
```

Configure at least two NTP servers for redundancy. Prefer servers in the same geographic region as the device.

**Compliance references**

- PCI DSS 10.4.3 — *Time synchronization settings are applied*
- CIS FortiGate Benchmark — *Configure NTP for accurate timekeeping*
- NIST SP 800-41 — *Synchronize firewall clocks to a trusted time source*

---

## VPN Checks

### WEAK_CRYPTO_VPN

| Field | Value |
|-------|-------|
| **Severity** | HIGH or MEDIUM (see severity tiers below) |
| **Check ID** | `WEAK_CRYPTO_VPN` |
| **Category** | VPN configuration |

**What it detects**

IPSec VPN phase1 or phase2 proposals using cryptographic algorithms that are known to be weak or broken. One finding is raised per device at the worst severity observed across all VPN tunnels.

**Severity tiers**

| Condition | Severity |
|-----------|----------|
| Any tunnel uses: encryption=DES/3DES/null; hash=MD5; or DH group 1, 2, or 5 | HIGH |
| Any tunnel uses hash=SHA-1 (with no HIGH-tier weaknesses) | MEDIUM |

**Weak algorithm reference**

| Algorithm type | Weak values | Reason |
|----------------|-------------|--------|
| Encryption | `des`, `3des`, `null` | DES/3DES broken; null = no encryption |
| Hash/integrity | `md5` | Collision attacks; use SHA-256 or better |
| Hash/integrity | `sha1` | Deprecated; use SHA-256 or better |
| DH group | `1`, `2`, `5` | Key exchange too weak; use group 14+ |

**Detection logic**

```
FOR each VPN phase1/phase2 on the device:
    IF encryption in ("des", "3des", "null")
    OR hash in ("md5")
    OR dhgrp in (1, 2, 5):
        severity = HIGH
    ELIF hash == "sha1":
        severity = MEDIUM (if no HIGH already found)

Raise one finding at worst severity, listing all affected tunnels.
```

**Evidence JSON**

```json
{
  "weak_tunnels": [
    {
      "tunnel_name": "branch-vpn",
      "phase": "phase1",
      "severity": "HIGH",
      "weak_algorithms": ["3des", "md5", "dhgrp:2"]
    },
    {
      "tunnel_name": "partner-vpn",
      "phase": "phase2",
      "severity": "MEDIUM",
      "weak_algorithms": ["sha1"]
    }
  ]
}
```

**Remediation**

1. Update phase1 proposals to use strong algorithms:
   ```
   config vpn ipsec phase1-interface
       edit <tunnel-name>
           set proposal aes256-sha256
           set dhgrp 14
       next
   end
   ```
2. Update phase2 proposals:
   ```
   config vpn ipsec phase2-interface
       edit <tunnel-name>
           set proposal aes256-sha256
           set pfs enable
           set dhgrp 14
       next
   end
   ```
3. Coordinate algorithm changes with the remote VPN peer — both ends must match.
4. Prefer AES-256 encryption, SHA-256 or SHA-384 integrity, and DH group 14 (2048-bit) or higher.

**Compliance references**

- NIST SP 800-77 Rev 1 — *Guide to IPsec VPNs*
- PCI DSS 4.2.1 — *Strong cryptography in transit*
- DISA STIG FortiGate — *VPN cryptographic algorithm requirements*

---

## SNMP Checks

### SNMP_WEAK_VERSION

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **Check ID** | `SNMP_WEAK_VERSION` |
| **Category** | SNMP configuration |

**What it detects**

SNMPv1 or SNMPv2c communities are configured on the device. Both versions use community strings as the sole authentication mechanism, with no encryption. Community strings are transmitted in cleartext and are trivial to capture on a network segment.

**Note on evidence logging:** Community string values are never included in findings evidence to avoid storing credentials in the database. Only community names and status are recorded.

**Detection logic**

```
snmp_data = device.vendor_data["snmp"]

FOR each community in snmp_data:
    IF community is configured (any status):
        raise finding
```

**Evidence JSON**

```json
{
  "communities": [
    {"name": "public", "status": "enable"},
    {"name": "monitoring", "status": "enable"}
  ]
}
```

**Remediation**

1. Disable all SNMPv1/v2c communities:
   `config system snmp community → delete <id>`
2. Configure SNMPv3 with authentication and encryption (authPriv security level):
   ```
   config system snmp user
       edit "monitor-user"
           set security-level auth-priv
           set auth-proto sha256
           set priv-proto aes256
       next
   end
   ```
3. Use unique, strong credentials for each SNMPv3 user.
4. Restrict SNMP access to specific management host IPs.

**Compliance references**

- NIST SP 800-161 Rev 1 — *Cybersecurity Supply Chain Risk Management*
- CIS FortiGate Benchmark — *Disable SNMPv1/v2c*
- PCI DSS 2.2.7 — *All non-console administrative access is encrypted*

---

## Compliance Mapping

Quick reference: which checks map to which compliance frameworks.

| Check ID | NIST SP 800-41 | NIST SP 800-63B | NIST SP 800-92 | NIST SP 800-77 | NIST SP 800-40 | PCI DSS | CIS FortiGate | DISA STIG |
|----------|:--------------:|:----------------:|:--------------:|:--------------:|:--------------:|:-------:|:-------------:|:---------:|
| `ANY_ANY_RULE` | ✓ | | | | | 1.2.1 | 1.1.1 | |
| `LOGGING_DISABLED` | | | ✓ | | | 10.2 | 1.2 | |
| `SHADOWED_RULE` | ✓ | | | | | | ✓ | |
| `RISKY_SERVICE_EXPOSED` | | | | | | | ✓ | ✓ |
| `MISSING_DENY_ALL` | ✓ | | | | | 1.2.1 | 1.1.2 | |
| `BROAD_DESTINATION` | ✓ | | | | | | | |
| `DISABLED_POLICY` | | | | | | | ✓ | |
| `ADMIN_NO_MFA` | | ✓ | | | | 8.3 | 1.3 | |
| `ADMIN_UNRESTRICTED_ACCESS` | | | | | | | ✓ | |
| `LOGGING_NOT_CONFIGURED` | | | ✓ | | | 10.5 | | |
| `WEAK_PASSWORD_POLICY` | | ✓ | | | | | 1.3 | |
| `HTTP_ADMIN_ENABLED` | ✓ | | | | | | ✓ | ✓ |
| `MANAGEMENT_ACCESS_EXPOSED` | ✓ | | | | | | ✓ | |
| `GEOBLOCK_ABSENT` | | | | | | | ✓ | |
| `GEOBLOCK_BYPASS_RISK` | | | | | | | ✓ | ✓ |
| `FIRMWARE_EOL` | | | | | ✓ | | | |
| `NTP_NOT_CONFIGURED` | ✓ | | | | | 10.4.3 | ✓ | |
| `WEAK_CRYPTO_VPN` | | | | ✓ | | 4.2.1 | | ✓ |
| `SNMP_WEAK_VERSION` | | | | | | 2.2.7 | ✓ | |
