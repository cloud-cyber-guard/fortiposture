# Sample Config Files

These are synthetic FortiGate configuration files for testing `fortiposture`. They are not from real devices.

## Files

### fw-hq-clean.conf
A well-configured headquarters firewall (FortiOS 7.2.8). MFA enabled, trusted hosts set, NTP configured, syslog + FortiAnalyzer logging, geo-blocking in place, explicit deny-all rule. Expected result: clean or near-clean posture score.

### fw-branch-risky.conf
A poorly configured branch office firewall (FortiOS 6.4.9 — end of life). Multiple issues including: no MFA, no trusted hosts, weak password policy, HTTP admin enabled on WAN, SNMPv2c with default community string, any-any rule with logging disabled, RDP exposed inbound, weak VPN crypto (3DES/MD5), disabled policy bloat, no NTP, no geo-blocking, no external logging, no deny-all rule. Expected result: low posture score with many findings.

## Usage

```bash
fortiposture scan --input-dir docs/examples --output sample-report.html
```
