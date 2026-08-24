"""Adapters are tested for (a) exact dry-run requests and (b) live calls against an httpx mock
transport / botocore stubber. No real tenant is touched."""

import json

import httpx
import pytest

from seventytwo.adapters.aws import AWSAdapter
from seventytwo.adapters.crowdstrike import CrowdStrikeAdapter
from seventytwo.adapters.defender import DefenderAdapter
from seventytwo.adapters.entra import EntraAdapter
from seventytwo.adapters.okta import OktaAdapter
from seventytwo.models import Action, Entity, EntityType, Verb


def act(verb, etype, eid, platform):
    return Action(verb=verb, target=Entity(type=etype, id=eid, platform=platform), tier="contain", reason="t")


def test_entra_dry_run_requests():
    a = EntraAdapter(token_provider=lambda: "tok")
    r = a.execute(act(Verb.DISABLE_USER, EntityType.USER, "u1", "entra"))
    assert r.dry_run and r.ok and r.request["method"] == "PATCH"
    assert r.request["url"].endswith("/users/u1") and r.request["body"] == {"accountEnabled": False}
    r = a.execute(act(Verb.REVOKE_SESSIONS, EntityType.USER, "u1", "entra"))
    assert r.request["url"].endswith("/users/u1/revokeSignInSessions")
    r = a.execute(act(Verb.REVOKE_SESSIONS, EntityType.SERVICE_PRINCIPAL, "sp1", "entra"))
    assert not r.ok and not r.request


def test_entra_live_call_uses_bearer(monkeypatch):
    seen = {}

    def handler(req: httpx.Request):
        seen["auth"] = req.headers["authorization"]
        seen["url"] = str(req.url)
        seen["body"] = req.content
        return httpx.Response(204)

    transport = httpx.MockTransport(handler)
    orig = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: orig(transport=transport, **kw))
    a = EntraAdapter(token_provider=lambda: "tok123")
    r = a.execute(act(Verb.DISABLE_USER, EntityType.USER, "u1", "entra"), dry_run=False)
    assert r.ok and seen["auth"] == "Bearer tok123" and json.loads(seen["body"]) == {"accountEnabled": False}


def test_defender_isolate_and_revert():
    a = DefenderAdapter(token_provider=lambda: "tok")
    r = a.execute(act(Verb.ISOLATE_HOST, EntityType.HOST, "m-1", "defender"))
    assert r.request["url"].startswith("https://api.security.microsoft.com/api/")
    assert r.request["url"].endswith("/machines/m-1/isolate") and r.request["body"]["IsolationType"] == "Full"
    rv = a.revert(act(Verb.ISOLATE_HOST, EntityType.HOST, "m-1", "defender"))
    assert rv.request["url"].endswith("/machines/m-1/unisolate")
    assert not a.execute(act(Verb.DISABLE_USER, EntityType.USER, "u", "defender")).ok


def test_okta_dry_run_without_env(monkeypatch):
    monkeypatch.delenv("OKTA_ORG_URL", raising=False)
    a = OktaAdapter()
    r = a.execute(act(Verb.DISABLE_USER, EntityType.USER, "00u1", "okta"))
    assert r.ok and "/lifecycle/suspend" in r.request["url"]
    r = a.execute(act(Verb.REVOKE_SESSIONS, EntityType.USER, "00u1", "okta"))
    assert r.request["method"] == "DELETE" and "oauthTokens=true" in r.request["url"]


def test_okta_live_uses_ssws(monkeypatch):
    monkeypatch.setenv("OKTA_ORG_URL", "https://acme.okta.com")
    monkeypatch.setenv("OKTA_API_TOKEN", "sswstok")
    seen = {}

    def handler(req):
        seen["auth"] = req.headers["authorization"]
        seen["url"] = str(req.url)
        return httpx.Response(200, json={})

    orig = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kw: orig(transport=httpx.MockTransport(handler), **kw))
    r = OktaAdapter().execute(act(Verb.DISABLE_USER, EntityType.USER, "00u1", "okta"), dry_run=False)
    assert (
        r.ok
        and seen["auth"] == "SSWS sswstok"
        and seen["url"] == "https://acme.okta.com/api/v1/users/00u1/lifecycle/suspend"
    )


def test_crowdstrike_contain_and_lift(monkeypatch):
    monkeypatch.delenv("FALCON_BASE_URL", raising=False)
    a = CrowdStrikeAdapter(token_provider=lambda: "tok")
    r = a.execute(act(Verb.ISOLATE_HOST, EntityType.HOST, "aid123", "crowdstrike"))
    assert "action_name=contain" in r.request["url"] and r.request["body"] == {"ids": ["aid123"]}
    assert (
        "lift_containment"
        in a.revert(act(Verb.ISOLATE_HOST, EntityType.HOST, "aid123", "crowdstrike")).request["url"]
    )


def test_aws_dry_run_builds_requests(monkeypatch):
    monkeypatch.delenv("SEVENTYTWO_QUARANTINE_SCP_ID", raising=False)
    a = AWSAdapter(session=object())  # never used in dry-run
    r = a.execute(act(Verb.DISABLE_USER, EntityType.USER, "alice", "aws"))
    assert (
        r.ok
        and r.request["op"] == "put_user_policy"
        and r.request["PolicyDocument"]["Statement"][0]["Effect"] == "Deny"
    )
    r = a.execute(act(Verb.QUARANTINE_ACCOUNT, EntityType.CLOUD_ACCOUNT, "111111111111", "aws"))
    assert r.request["service"] == "organizations" and r.request["TargetId"] == "111111111111"
    r = a.execute(act(Verb.REVOKE_SESSIONS, EntityType.SERVICE_PRINCIPAL, "deploy-role", "aws"))
    assert r.request["op"] == "put_role_policy" and r.request["RoleName"] == "deploy-role"
    assert "aws:TokenIssueTime" in json.dumps(r.request["PolicyDocument"])
    r = a.execute(act(Verb.REVOKE_SESSIONS, EntityType.USER, "alice", "aws"))
    assert r.request["op"] == "put_user_policy" and r.request["UserName"] == "alice"
    r = a.execute(act(Verb.LOCK_BACKUP_VAULT, EntityType.BACKUP_VAULT, "prod-backup-vault", "aws"))
    assert "put_backup_vault_lock_configuration" in r.request["op"]
    assert r.request["mode"].startswith("governance") and "ChangeableForDays" not in r.request


def test_aws_live_deactivate_keys_with_stubber():
    boto3 = pytest.importorskip("boto3")
    from botocore.stub import Stubber

    session = boto3.Session(region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="y")
    iam = session.client("iam")
    stub = Stubber(iam)
    stub.add_response(
        "list_access_keys",
        {
            "AccessKeyMetadata": [
                {"UserName": "alice", "AccessKeyId": "TESTACCESSKEY00000000", "Status": "Active"}
            ]
        },
        {"UserName": "alice"},
    )
    stub.add_response(
        "update_access_key",
        {},
        {"UserName": "alice", "AccessKeyId": "TESTACCESSKEY00000000", "Status": "Inactive"},
    )
    stub.activate()

    class S:  # minimal session shim returning the stubbed client
        def client(self, name):
            assert name == "iam"
            return iam

    r = AWSAdapter(session=S()).execute(
        act(Verb.DEACTIVATE_KEYS, EntityType.USER, "alice", "aws"), dry_run=False
    )
    assert r.ok and r.request["deactivated"] == 1
    stub.assert_no_pending_responses()
