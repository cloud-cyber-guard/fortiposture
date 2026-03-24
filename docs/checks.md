# Security Checks Reference

This document describes all 11 security checks performed by `fortiposture`, including detection logic, evidence format, remediation guidance, and compliance mappings.

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
| **Severity** | CRITICAL |
| **Check ID** | `ADMIN_NO_MFA` |
| **Category** | Admin accounts |

**What it detects**

A local-password admin account without two-factor authentication enabled. A single compromised password is sufficient to gain full administrative access to the firewall — there is no second factor to stop an attacker.

**Detection logic**

```
admin.auth_type == "local"
AND admin.two_factor_auth == False
```

**Evidence JSON**

```json
{
  "username": "admin",
  "auth_type": "local",
  "two_factor_auth": false
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

An admin account with no trusted hosts configured. Without trusted hosts, the management interface can be accessed from any IP address — increasing the attack surface for credential-based attacks.

**Detection logic**

```
admin.trusted_hosts == [] or null
```

**Evidence JSON**

```json
{
  "username": "admin",
  "trusted_hosts": []
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

## Compliance Mapping

Quick reference: which checks map to which compliance frameworks.

| Check ID | NIST SP 800-41 | NIST SP 800-63B | NIST SP 800-92 | PCI DSS | CIS FortiGate | DISA STIG |
|----------|:--------------:|:----------------:|:--------------:|:-------:|:-------------:|:---------:|
| `ANY_ANY_RULE` | ✓ | | | 1.2.1 | 1.1.1 | |
| `LOGGING_DISABLED` | | | ✓ | 10.2 | 1.2 | |
| `SHADOWED_RULE` | ✓ | | | | ✓ | |
| `RISKY_SERVICE_EXPOSED` | | | | | ✓ | ✓ |
| `MISSING_DENY_ALL` | ✓ | | | 1.2.1 | 1.1.2 | |
| `BROAD_DESTINATION` | ✓ | | | | | |
| `DISABLED_POLICY` | | | | | ✓ | |
| `ADMIN_NO_MFA` | | ✓ | | 8.3 | 1.3 | |
| `ADMIN_UNRESTRICTED_ACCESS` | | | | | ✓ | |
| `LOGGING_NOT_CONFIGURED` | | | ✓ | 10.5 | | |
| `WEAK_PASSWORD_POLICY` | | ✓ | | | 1.3 | |
