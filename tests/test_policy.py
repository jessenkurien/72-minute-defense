import copy

import pytest

from seventytwo.models import Authority
from seventytwo.policy.schema import ContainmentPolicy, attest


def test_template_policy_verifies(policy):
    ok, problems = policy.verify()
    assert ok, problems


def test_tampering_after_attestation_invalidates(policy):
    tampered = copy.deepcopy(policy)
    tampered.tiers[2].ceiling.hosts = 500  # someone quietly widened the blast radius
    ok, problems = tampered.verify()
    assert not ok
    assert any("different policy body" in p for p in problems)


def test_missing_required_role_blocks(policy):
    p = copy.deepcopy(policy)
    p.attestations = [s for s in p.attestations if s.role != "CISO"]
    ok, problems = p.verify()
    assert not ok and any("CISO" in x for x in problems)


def test_reattesting_restores_validity(policy):
    p = copy.deepcopy(policy)
    p.tiers[2].ceiling.hosts = 20
    p.attestations = [attest(p, r, "re-attester") for r in p.required_attestation_roles]
    assert p.verify()[0]


def test_template_policy_can_never_arm(policy):
    problems = policy.arming_problems(policy.digest(), on=policy.effective_from)
    assert any("template" in p for p in problems)


def test_operational_policy_requires_out_of_band_digest_pin(policy):
    p = copy.deepcopy(policy)
    p.template = False
    p.attestations = [attest(p, r, "test approver") for r in p.required_attestation_roles]
    assert any("digest pin" in problem for problem in p.arming_problems(None, on=p.effective_from))
    assert any("does not match" in problem for problem in p.arming_problems("0" * 64, on=p.effective_from))
    assert p.arming_problems(p.digest(), on=p.effective_from) == []


def test_tier_selection_and_critical_floor(policy):
    assert policy.tier_for_score(10) is None
    assert policy.tier_for_score(30).name == "watch"
    assert policy.tier_for_score(50).name == "friction"
    assert policy.tier_for_score(70).name == "contain"
    assert policy.tier_for_score(90).name == "sever"
    # critical: floor, not cap
    assert policy.tier_for_score(30, critical=True).name == "contain"
    assert policy.tier_for_score(90, critical=True).name == "sever"


def test_highest_automatic_below(policy):
    sever = policy.tier("sever")
    assert policy.highest_automatic_below(sever, 90).name == "contain"


def test_schema_rejects_unordered_tiers(policy):
    data = policy.model_dump(mode="json")
    data["tiers"][0], data["tiers"][1] = data["tiers"][1], data["tiers"][0]
    with pytest.raises(ValueError):
        ContainmentPolicy.model_validate(data)


def test_schema_requires_approvers_for_two_person(policy):
    data = policy.model_dump(mode="json")
    data["tiers"][3]["approver_roles"] = []
    with pytest.raises(ValueError):
        ContainmentPolicy.model_validate(data)


def test_authority_enum_order_used_in_escalation():
    assert Authority.TWO_PERSON != Authority.AUTOMATIC
