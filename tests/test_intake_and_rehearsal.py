import json
from pathlib import Path

from click.testing import CliRunner

from seventytwo.cli import main
from seventytwo.intake import normalize
from seventytwo.rehearsal import load_scenario, rehearse

ROOT = Path(__file__).resolve().parent.parent


def test_sentinel_normalization_and_unmapped():
    payload = [
        {
            "AlertName": "Backup deleted or retention reduced",
            "TimeGenerated": "2026-08-24T10:00:00Z",
            "SystemAlertId": "a1",
            "Entities": [
                {"Type": "account", "Name": "j.doe", "UPNSuffix": "example.com"},
                {"Type": "host", "HostName": "ws-1"},
            ],
        },
        {"AlertName": "Some rule nobody mapped", "TimeGenerated": "2026-08-24T10:01:00Z", "Entities": []},
    ]
    events, unmapped = normalize("sentinel", payload)
    assert len(events) == 1 and events[0].signal == "backup_tamper"
    assert events[0].entity.id == "j.doe@example.com" and events[0].related[0].id == "ws-1"
    assert unmapped == ["Some rule nobody mapped"]


def test_splunk_falcon_guardduty_normalization():
    sp = {
        "sid": "s1",
        "result": {
            "search_name": "ESCU - Rclone Execution",
            "_time": "2026-08-24T10:00:00Z",
            "user": "m.roe",
            "dest": "ws-2",
        },
    }
    fa = {
        "event": {
            "DetectName": "ShadowCopyDeletion",
            "UserName": "m.roe",
            "SensorId": "aid1",
            "ProcessStartTime": 1787000000,
            "DetectId": "d1",
        }
    }
    gd = {
        "detail": {
            "type": "Stealth:IAMUser/CloudTrailLoggingDisabled",
            "id": "g1",
            "updatedAt": "2026-08-24T10:00:00Z",
            "severity": 8,
            "accountId": "111111111111",
            "resource": {"accessKeyDetails": {"userName": "svc-deploy", "userType": "AssumedRole"}},
        }
    }
    e1, _ = normalize("splunk", sp)
    e2, _ = normalize("falcon", fa)
    e3, _ = normalize("guardduty", gd)
    assert (
        e1[0].signal == "exfil_tool_present"
        and e2[0].signal == "shadow_copy_deletion"
        and e3[0].signal == "logging_disabled"
    )
    assert e3[0].entity.type.value == "service_principal" and e3[0].related[0].type.value == "cloud_account"


def test_all_shipped_scenarios_pass(policy, ctx, catalog, audit):
    for sp in sorted((ROOT / "scenarios").glob("*.yaml")):
        r = rehearse(load_scenario(sp), policy, catalog, ctx, audit)
        assert r.passed, (sp.name, r.metrics())


def test_fast72_contained_with_margin(policy, ctx, catalog, audit):
    r = rehearse(load_scenario(ROOT / "scenarios" / "fast-72.yaml"), policy, catalog, ctx, audit)
    assert r.contain_minute is not None and r.contain_minute < 30
    assert r.margin_minutes > 40 and r.authority_used == "automatic"
    assert r.friction_minute is not None and r.friction_minute < r.contain_minute


def test_two_person_cost_is_visible(policy, ctx, catalog, audit):
    r = rehearse(
        load_scenario(ROOT / "scenarios" / "crown-jewel-two-person.yaml"), policy, catalog, ctx, audit
    )
    assert r.authority_used == "two_person" and r.contained_before_exfil
    assert "IR Lead" in r.approvals_used and "CISO" in r.approvals_used


def test_slow_approvers_lose_the_race(policy, ctx, catalog, audit):
    sc = load_scenario(ROOT / "scenarios" / "crown-jewel-two-person.yaml")
    for a in sc.approvals:
        a["response_minutes"] = 60
    r = rehearse(sc, policy, catalog, ctx, audit)
    assert r.contain_minute is not None and not r.contained_before_exfil


def test_cli_rehearse_and_gate(tmp_path):
    out = tmp_path / "out"
    r = CliRunner().invoke(
        main, ["rehearse", "--out", str(out), "--audit", str(tmp_path / "a.jsonl"), "--fail-if-late"]
    )
    assert r.exit_code == 0, r.output
    assert (out / "dashboard.html").exists() and (out / "fast-72.svg").exists()
    m = json.loads((out / "fast-72.json").read_text())
    assert m["passed"] and m["margin_minutes"] > 0
    assert m["project"]["creator"] == "Jessen Kurien"
    assert "Created by Jessen Kurien" in (out / "dashboard.html").read_text(encoding="utf-8")
    assert "Jessen Kurien" in (out / "fast-72.md").read_text(encoding="utf-8")


def test_cli_act_dry_run_generic(tmp_path):
    events = [
        {
            "id": "e1",
            "ts": "2026-08-24T10:00:00Z",
            "signal": "backup_tamper",
            "source": "test",
            "entity": {"type": "user", "id": "j.doe@example.com", "platform": "entra"},
            "related": [{"type": "host", "id": "ws-4471", "platform": "defender"}],
        }
    ]
    ep = tmp_path / "events.json"
    ep.write_text(json.dumps(events))
    r = CliRunner().invoke(
        main,
        [
            "act",
            "--events",
            str(ep),
            "--audit",
            str(tmp_path / "a.jsonl"),
            "--json",
            str(tmp_path / "o.json"),
        ],
    )
    assert r.exit_code == 0, r.output
    assert "DRY-RUN" in r.output and "identity.disable_user" in r.output
    o = json.loads((tmp_path / "o.json").read_text())
    assert o[0]["tier"] == "contain" and not o[0]["blocked"]


def test_cli_act_with_real_adapters_dry_run_shows_requests(tmp_path):
    events = [
        {
            "id": "e1",
            "ts": "2026-08-24T10:00:00Z",
            "signal": "backup_tamper",
            "source": "test",
            "entity": {"type": "user", "id": "j.doe@example.com", "platform": "entra"},
            "related": [{"type": "host", "id": "ws-77", "platform": "defender"}],
        }
    ]
    ep = tmp_path / "events.json"
    ep.write_text(json.dumps(events))
    r = CliRunner().invoke(
        main,
        ["act", "--events", str(ep), "--audit", str(tmp_path / "a.jsonl"), "--adapters", "entra,defender"],
    )
    assert r.exit_code == 0, r.output
    assert "graph.microsoft.com/v1.0/users/j.doe%40example.com" in r.output
    assert "/machines/ws-77/isolate" in r.output


def test_cli_policy_verify_and_audit_verify(tmp_path):
    assert CliRunner().invoke(main, ["policy", "verify"]).exit_code == 0
    CliRunner().invoke(main, ["rehearse", "--out", str(tmp_path / "o"), "--audit", str(tmp_path / "a.jsonl")])
    r = CliRunner().invoke(main, ["audit", "verify", "--audit", str(tmp_path / "a.jsonl")])
    assert r.exit_code == 0 and "chain intact" in r.output
