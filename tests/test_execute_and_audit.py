import copy
import json
from datetime import datetime, timedelta, timezone

from conftest import ev, host, user

from seventytwo.adapters.mock import MockAdapter
from seventytwo.engine.audit import AuditLog
from seventytwo.engine.decide import decide
from seventytwo.engine.execute import Approval, execute
from seventytwo.models import Verb
from seventytwo.policy import attest
from seventytwo.scoring import score_events


def _critical_plan(catalog, policy, ctx):
    s = score_events([ev("backup_tamper", 0, user(), related=[host()])], catalog)[0]
    return decide(s, policy, ctx)


def test_dry_run_by_default(catalog, policy, ctx, audit):
    plan = _critical_plan(catalog, policy, ctx)
    m = MockAdapter()
    rep = execute(plan, policy, {"mock": m}, audit)
    assert rep.dry_run and rep.contained and len(m.calls) == len(plan.actions)
    kinds = [r["kind"] for r in audit.records()]
    assert kinds[0] == "decision" and "action" in kinds


def test_armed_refused_for_template_policy(catalog, policy, ctx, audit):
    bad = copy.deepcopy(policy)
    plan = _critical_plan(catalog, bad, ctx)
    rep = execute(plan, bad, {"mock": MockAdapter()}, audit, armed=True)
    assert not rep.executed and "template policies" in rep.blocked_reason
    assert audit.records()[-1]["kind"] == "blocked"


def _operational(policy, monkeypatch):
    p = copy.deepcopy(policy)
    p.template = False
    today = datetime.now(timezone.utc).date()
    p.effective_from = today - timedelta(days=1)
    p.review_by = today + timedelta(days=30)
    p.attestations = [attest(p, role, "test approver") for role in p.required_attestation_roles]
    monkeypatch.setenv("SEVENTYTWO_POLICY_DIGEST", p.digest())
    return p


def test_live_approver_tier_rejects_cli_text(catalog, policy, ctx, audit, monkeypatch):
    p = _operational(policy, monkeypatch)
    plan = _critical_plan(catalog, p, ctx)
    approvals = [Approval("IR Lead", "alice", "INC-1"), Approval("CISO", "bob", "INC-1")]
    rep = execute(plan, p, {"mock": MockAdapter()}, audit, armed=True, approvals=approvals)
    assert not rep.executed
    assert "trusted integration" in rep.blocked_reason


def test_disallowed_role_and_same_person_do_not_satisfy_two_person(catalog, policy, ctx, audit):
    score = score_events([ev("backup_tamper", 0, user("ceo@example.com"), related=[host("ws-9")])], catalog)[
        0
    ]
    plan = decide(score, policy, ctx)
    wrong = [Approval("IR Lead", "alice", "INC-1"), Approval("Helpdesk", "bob", "INC-1")]
    assert (
        "not allowed" in execute(plan, policy, {"mock": MockAdapter()}, audit, approvals=wrong).blocked_reason
    )
    duplicate_identity = [Approval("IR Lead", "Alice", "INC-1"), Approval("CISO", " alice ", "INC-1")]
    assert (
        "requires 2"
        in execute(plan, policy, {"mock": MockAdapter()}, audit, approvals=duplicate_identity).blocked_reason
    )


def test_two_person_requires_two_distinct_approvers(catalog, policy, ctx, audit):
    s = score_events([ev("backup_tamper", 0, user("ceo@example.com"), related=[host("ws-9")])], catalog)[0]
    plan = decide(s, policy, ctx)
    one = [Approval("IR Lead", "alice", "INC-1")]
    rep = execute(plan, policy, {"mock": MockAdapter()}, audit, approvals=one)
    assert not rep.executed and "requires 2" in rep.blocked_reason
    same_person_twice = one + [Approval("IR Lead", "alice", "INC-1")]
    rep = execute(plan, policy, {"mock": MockAdapter()}, audit, approvals=same_person_twice)
    assert not rep.executed
    two = one + [Approval("CISO", "bob", "INC-1")]
    rep = execute(plan, policy, {"mock": MockAdapter()}, audit, approvals=two)
    assert rep.contained
    last_action = [r for r in audit.records() if r["kind"] == "action"][-1]
    assert {a["name"] for a in last_action["approvals"]} == {"alice", "bob"}


def test_fallback_executes_while_awaiting_approval(catalog, policy, ctx, audit):
    events = [
        ev("anomalous_login", 0, user(), related=[host()]),
        ev("credential_dumping", 8, host(), related=[user()]),
        ev("rmm_tool_installed", 16, host(), related=[user()]),
    ]
    plan = decide(score_events(events, catalog)[0], policy, ctx)
    m = MockAdapter()
    rep = execute(plan, policy, {"mock": m}, audit)
    assert rep.executed and "awaiting approval" in rep.blocked_reason
    assert {a.verb for a in m.calls} >= {Verb.DISABLE_USER, Verb.ISOLATE_HOST}
    assert Verb.QUARANTINE_ACCOUNT not in {a.verb for a in m.calls}


def test_failed_adapter_action_is_recorded_not_raised(catalog, policy, ctx, audit):
    plan = _critical_plan(catalog, policy, ctx)
    rep = execute(plan, policy, {"mock": MockAdapter(fail_verbs={Verb.ISOLATE_HOST})}, audit)
    assert not rep.contained
    assert any(not r.ok for r in rep.executed)


def test_audit_chain_detects_modification_and_deletion(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(5):
        log.append("test", "unit", n=i)
    assert log.verify()[0]
    lines = (tmp_path / "a.jsonl").read_text().splitlines()
    rec = json.loads(lines[2])
    rec["n"] = 99
    (tmp_path / "a.jsonl").write_text("\n".join(lines[:2] + [json.dumps(rec)] + lines[3:]) + "\n")
    ok, _count, msg = log.verify()
    assert not ok and "modified" in msg
    (tmp_path / "a.jsonl").write_text("\n".join(lines[:1] + lines[2:]) + "\n")
    ok, _count, msg = log.verify()
    assert not ok and "deleted" in msg


def test_no_adapter_for_platform_is_skipped(catalog, policy, ctx, audit):
    from seventytwo.adapters.okta import OktaAdapter

    plan = _critical_plan(catalog, policy, ctx)  # targets are entra/defender
    rep = execute(plan, policy, {"okta": OktaAdapter()}, audit)
    assert rep.skipped and not rep.executed
