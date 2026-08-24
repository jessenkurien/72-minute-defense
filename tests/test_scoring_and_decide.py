from datetime import timedelta

import pytest
from conftest import T0, ev, host, user

from seventytwo.engine.decide import decide
from seventytwo.models import Authority, Entity, EntityType, Verb
from seventytwo.scoring import score_events


def test_single_weak_signal_stays_below_watch(catalog, policy, ctx):
    s = score_events([ev("anomalous_login", 0, user(), confidence=0.8)], catalog)[0]
    assert s.score < 25
    assert decide(s, policy, ctx).tier is None


def test_chain_scores_higher_than_repeats(catalog):
    chain = score_events([ev("anomalous_login", 0, user()), ev("credential_dumping", 8, user())], catalog)[0]
    repeat = score_events(
        [ev("anomalous_login", 0, user()), ev("anomalous_login", 8, user(), i="x")], catalog
    )[0]
    assert chain.score > repeat.score
    assert chain.distance_to_impact == 4


def test_repeated_signal_cannot_inflate_score(catalog):
    single = score_events([ev("anomalous_login", 0, user())], catalog)[0]
    repeated = score_events(
        [ev("anomalous_login", 0, user(), i="one"), ev("anomalous_login", 1, user(), i="two")], catalog
    )[0]
    assert repeated.score == single.score


def test_exact_delivery_retry_is_deduplicated_and_conflict_rejected(catalog):
    original = ev("anomalous_login", 0, user(), i="vendor-1")
    assert len(score_events([original, original.model_copy(deep=True)], catalog)[0].events) == 1
    conflict = original.model_copy(update={"confidence": 0.5})
    with pytest.raises(ValueError, match="conflicting duplicate event id"):
        score_events([original, conflict], catalog)


def test_user_and_host_cluster_together(catalog):
    events = [
        ev("anomalous_login", 0, user(), related=[host()]),
        ev("credential_dumping", 8, host(), related=[user()]),
    ]
    scores = score_events(events, catalog)
    assert len(scores) == 1
    assert {e.key() for e in scores[0].cluster} == {"user:j.doe@example.com", "host:ws-4471"}
    assert scores[0].entity.type == EntityType.USER  # identity is primary


def test_decay_lowers_old_evidence(catalog):
    fresh = score_events([ev("credential_dumping", 0, user())], catalog, now=T0)[0].score
    stale = score_events([ev("credential_dumping", 0, user())], catalog, now=T0 + timedelta(hours=12))[
        0
    ].score
    assert stale < fresh / 3


def test_critical_signal_alone_forces_contain(catalog, policy, ctx):
    s = score_events([ev("backup_tamper", 0, user(), related=[host()])], catalog)[0]
    assert s.critical
    plan = decide(s, policy, ctx)
    assert plan.tier.name == "contain" and plan.authority == Authority.AUTOMATIC
    verbs = {a.verb for a in plan.actions}
    assert Verb.DISABLE_USER in verbs and Verb.ISOLATE_HOST in verbs


def test_low_confidence_critical_signal_does_not_force_tier(catalog, policy, ctx):
    s = score_events([ev("backup_tamper", 0, user(), confidence=0.2)], catalog)[0]
    assert not s.critical
    assert decide(s, policy, ctx).tier is None


def test_missing_alert_still_crosses_threshold(catalog, policy, ctx):
    events = [
        ev("anomalous_login", 0, user(), related=[host()]),
        ev("rmm_tool_installed", 16, host(), related=[user()]),
        ev("mass_file_enumeration", 28, user()),
    ]
    s = score_events(events, catalog)[0]
    assert decide(s, policy, ctx).tier.name in ("contain", "sever")


def test_protected_principal_escalates_to_two_person(catalog, policy, ctx):
    ceo = user("ceo@example.com")
    s = score_events([ev("backup_tamper", 0, ceo, related=[host("ws-1")])], catalog)[0]
    plan = decide(s, policy, ctx)
    assert plan.authority == Authority.TWO_PERSON
    assert any("protected pattern" in r for r in plan.reasons)


def test_crown_jewel_host_escalates(catalog, policy, ctx):
    s = score_events(
        [ev("shadow_copy_deletion", 0, host("pay-app-03", "crowdstrike"), related=[user("ops@example.com")])],
        catalog,
    )[0]
    plan = decide(s, policy, ctx)
    assert plan.authority == Authority.TWO_PERSON
    assert "payments" in plan.blast_radius.services


def test_ceiling_breach_escalates_to_single_approver(catalog, policy, ctx):
    hosts = [host(f"ws-{i}") for i in range(12)]
    s = score_events([ev("backup_tamper", 0, user(), related=hosts)], catalog)[0]
    plan = decide(s, policy, ctx)
    assert plan.authority == Authority.SINGLE_APPROVER
    assert plan.blast_radius.over_ceiling


def test_ceiling_counts_unique_entities_not_actions(catalog, policy, ctx):
    policy.tier("contain").ceiling.users = 1
    score = score_events([ev("backup_tamper", 0, user(), related=[host()])], catalog)[0]
    plan = decide(score, policy, ctx)
    assert sum(action.target.type == EntityType.USER for action in plan.actions) > 1
    assert not any("user(s)" in item for item in plan.blast_radius.over_ceiling)


def test_unknown_asset_escalates_fail_safe(catalog, policy, ctx):
    unknown = host("unmapped-prod-99")
    score = score_events([ev("backup_tamper", 0, unknown)], catalog)[0]
    plan = decide(score, policy, ctx)
    assert plan.authority == Authority.TWO_PERSON
    assert any("absent from the business context" in reason for reason in plan.reasons)


def test_fallback_runs_preauthorized_tier_while_sever_waits(catalog, policy, ctx):
    events = [
        ev("anomalous_login", 0, user(), related=[host()]),
        ev("credential_dumping", 8, host(), related=[user()]),
        ev("rmm_tool_installed", 16, host(), related=[user()]),
    ]
    s = score_events(events, catalog)[0]
    plan = decide(s, policy, ctx)
    assert plan.tier.name == "sever" and plan.authority == Authority.TWO_PERSON
    assert plan.fallback is not None and plan.fallback.tier.name == "contain"
    assert {a.verb for a in plan.fallback.actions} >= {Verb.DISABLE_USER, Verb.ISOLATE_HOST}


def test_unknown_signal_raises(catalog):
    with pytest.raises(KeyError):
        score_events([ev("not_a_signal", 0, user())], catalog)


def test_cloud_account_entity_supported(catalog, policy, ctx):
    acct = Entity(type=EntityType.CLOUD_ACCOUNT, id="222222222222", platform="aws")
    sp = Entity(type=EntityType.SERVICE_PRINCIPAL, id="svc-dev-ci", platform="aws")
    s = score_events(
        [ev("snapshot_shared_external", 0, acct, related=[sp]), ev("logging_disabled", 5, acct)], catalog
    )[0]
    plan = decide(s, policy, ctx)
    assert plan.tier is not None
