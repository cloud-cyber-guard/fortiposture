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

import json

import pytest
from tests.conftest import ingest_fixture
from fortiposture.analysis.checks import run_all_checks
from fortiposture.analysis.scoring import calculate_score


def test_any_any_rule_detected(db_session):
    devices = ingest_fixture("any_any_rule.conf", db_session)
    findings = run_all_checks(devices[0], db_session)
    check_ids = [f.check_id for f in findings]
    assert "ANY_ANY_RULE" in check_ids


def test_any_any_rule_deny_not_flagged(db_session):
    """deny-all any/any must NOT trigger ANY_ANY_RULE."""
    devices = ingest_fixture("simple_policy.conf", db_session)
    findings = run_all_checks(devices[0], db_session)
    any_any = [f for f in findings if f.check_id == "ANY_ANY_RULE"]
    assert len(any_any) == 0


def test_logging_disabled_detected(db_session):
    """A policy with logtraffic=disable should trigger LOGGING_DISABLED."""
    devices = ingest_fixture("any_any_rule.conf", db_session)
    # any_any_rule.conf policies have logtraffic=all so use missing_deny_all
    devices2 = ingest_fixture("missing_deny_all.conf", db_session)
    # inject a policy with logging disabled for this test
    from fortiposture.models.schema import FirewallPolicy, AddressObject
    policy = db_session.query(FirewallPolicy).filter_by(
        device_id=devices2[0].id, action="accept"
    ).first()
    policy.log_traffic = "disable"
    db_session.commit()
    findings = run_all_checks(devices2[0], db_session)
    assert any(f.check_id == "LOGGING_DISABLED" for f in findings)


def test_shadowed_rule_detected(db_session):
    devices = ingest_fixture("shadowed_rules.conf", db_session)
    findings = run_all_checks(devices[0], db_session)
    assert any(f.check_id == "SHADOWED_RULE" for f in findings)


def test_shadow_subnet_containment(db_session):
    """10.1.0.0/16 is shadowed by 10.0.0.0/8."""
    devices = ingest_fixture("shadowed_rules.conf", db_session)
    findings = run_all_checks(devices[0], db_session)
    shadowed = [f for f in findings if f.check_id == "SHADOWED_RULE"]
    assert len(shadowed) >= 1
    assert "narrow-rule-shadowed" in shadowed[0].affected_object_name


def test_missing_deny_all_detected(db_session):
    devices = ingest_fixture("missing_deny_all.conf", db_session)
    findings = run_all_checks(devices[0], db_session)
    assert any(f.check_id == "MISSING_DENY_ALL" for f in findings)


def test_admin_no_mfa_single_finding_per_device(db_session):
    """Aggregation: weak_admin has 2 accounts without MFA → must produce exactly 1 Finding."""
    devices = ingest_fixture("weak_admin.conf", db_session)
    findings = run_all_checks(devices[0], db_session)
    mfa_findings = [f for f in findings if f.check_id == "ADMIN_NO_MFA"]
    assert len(mfa_findings) == 1


def test_admin_no_mfa_super_admin_is_critical(db_session):
    """super_admin without MFA → CRITICAL severity."""
    devices = ingest_fixture("weak_admin.conf", db_session)
    findings = run_all_checks(devices[0], db_session)
    mfa_findings = [f for f in findings if f.check_id == "ADMIN_NO_MFA"]
    assert len(mfa_findings) == 1
    assert mfa_findings[0].severity == "CRITICAL"


def test_admin_no_mfa_with_mfa_not_counted(db_session):
    """Admin WITH MFA (simple_policy.conf) must NOT trigger ADMIN_NO_MFA."""
    devices = ingest_fixture("simple_policy.conf", db_session)
    findings = run_all_checks(devices[0], db_session)
    assert not any(f.check_id == "ADMIN_NO_MFA" for f in findings)


def test_admin_no_mfa_evidence_lists_accounts(db_session):
    """Evidence JSON must list affected usernames."""
    devices = ingest_fixture("weak_admin.conf", db_session)
    findings = run_all_checks(devices[0], db_session)
    mfa_finding = next(f for f in findings if f.check_id == "ADMIN_NO_MFA")
    ev = json.loads(mfa_finding.evidence)
    usernames = [a["username"] for a in ev["affected_accounts"]]
    assert "admin" in usernames


def test_admin_unrestricted_single_finding_per_device(db_session):
    """Aggregation: weak_admin has 2 accounts without trusted hosts → exactly 1 Finding."""
    devices = ingest_fixture("weak_admin.conf", db_session)
    findings = run_all_checks(devices[0], db_session)
    unr_findings = [f for f in findings if f.check_id == "ADMIN_UNRESTRICTED_ACCESS"]
    assert len(unr_findings) == 1


def test_admin_unrestricted_evidence_lists_accounts(db_session):
    """Evidence must list affected usernames."""
    devices = ingest_fixture("weak_admin.conf", db_session)
    findings = run_all_checks(devices[0], db_session)
    unr = next(f for f in findings if f.check_id == "ADMIN_UNRESTRICTED_ACCESS")
    ev = json.loads(unr.evidence)
    assert len(ev["affected_accounts"]) == 2


def test_clean_config_no_critical_findings(db_session):
    devices = ingest_fixture("simple_policy.conf", db_session)
    findings = run_all_checks(devices[0], db_session)
    critical = [f for f in findings if f.severity == "CRITICAL"]
    assert len(critical) == 0


def test_score_calculation():
    from fortiposture.analysis.scoring import calculate_score
    score, grade = calculate_score(critical=1, high=2, medium=1, low=0)
    # 100 - 20 - 20 - 5 = 55
    assert score == 55
    assert grade == "D"


def test_score_floor_at_zero():
    score, grade = calculate_score(critical=10, high=0, medium=0, low=0)
    assert score == 0
    assert grade == "F"


def test_grade_boundaries():
    assert calculate_score(0, 0, 0, 0) == (100, "A")
    assert calculate_score(0, 1, 0, 0) == (90, "A")   # 100-10=90 → A
    assert calculate_score(0, 3, 0, 0)[1] == "C"      # 100-30=70 → C
    assert calculate_score(0, 5, 0, 0)[1] == "D"      # 100-50=50 → D
    assert calculate_score(0, 7, 0, 0)[1] == "F"      # 100-70=30 → F
