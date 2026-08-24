"""AWS adapter (boto3; IAM, Organizations, Backup).

Credentials: standard AWS credential chain (prefer an SSO/OIDC role scoped to these calls).

Verbs:
  identity.revoke_sessions      -> attach inline deny policy with aws:TokenIssueTime < now to the role/user
                                   (AWS-documented pattern for revoking active sessions)
  identity.disable_user         -> attach managed 72md-Quarantine (Deny *) policy to IAM user
  identity.disable_service_principal -> same, for IAM role
  cloud.deactivate_keys         -> iam:UpdateAccessKey Status=Inactive for every key on the user
  cloud.quarantine_account      -> organizations:AttachPolicy(SCP 72MD_QUARANTINE_SCP_ID) to the account
  backup.lock_vault             -> apply AWS Backup Vault Lock in reversible governance mode

All boto3 calls are built but not sent in dry-run; the request is returned for review.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import ClassVar

from ..models import Action, ActionResult, EntityType, Verb
from .base import Adapter

QUARANTINE_POLICY_NAME = "72md-Quarantine"
QUARANTINE_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}


class AWSAdapter(Adapter):
    name = "aws"
    platform_aliases = ("amazon",)
    supported: ClassVar[set[Verb]] = {
        Verb.REVOKE_SESSIONS,
        Verb.DISABLE_USER,
        Verb.DISABLE_SERVICE_PRINCIPAL,
        Verb.DEACTIVATE_KEYS,
        Verb.QUARANTINE_ACCOUNT,
        Verb.LOCK_BACKUP_VAULT,
    }

    def __init__(self, session=None):
        self._session = session

    def _client(self, svc: str):
        if self._session is None:
            import boto3

            self._session = boto3.Session()
        return self._session.client(svc)

    def execute(self, action: Action, dry_run: bool = True) -> ActionResult:
        v, t = action.verb, action.target
        try:
            if v == Verb.REVOKE_SESSIONS and t.type in {EntityType.USER, EntityType.SERVICE_PRINCIPAL}:
                now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                doc = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Deny",
                            "Action": "*",
                            "Resource": "*",
                            "Condition": {"DateLessThan": {"aws:TokenIssueTime": now}},
                        }
                    ],
                }
                is_role = t.type == EntityType.SERVICE_PRINCIPAL
                req = {
                    "service": "iam",
                    "op": "put_role_policy" if is_role else "put_user_policy",
                    "PolicyName": "72md-RevokeOlderSessions",
                    "PolicyDocument": doc,
                }
                req["RoleName" if is_role else "UserName"] = t.id
                if dry_run:
                    return self._aws_result(action, req)
                kwargs = {
                    "PolicyName": req["PolicyName"],
                    "PolicyDocument": json.dumps(req["PolicyDocument"]),
                    "RoleName" if is_role else "UserName": t.id,
                }
                getattr(self._client("iam"), req["op"])(**kwargs)
                return self._aws_result(action, req, dry_run=False)

            if v == Verb.DISABLE_SERVICE_PRINCIPAL and t.type == EntityType.SERVICE_PRINCIPAL:
                req = {
                    "service": "iam",
                    "op": "put_role_policy",
                    "RoleName": t.id,
                    "PolicyName": QUARANTINE_POLICY_NAME,
                    "PolicyDocument": QUARANTINE_DOC,
                }
                if dry_run:
                    return self._aws_result(action, req)
                self._client("iam").put_role_policy(
                    RoleName=t.id,
                    PolicyName=QUARANTINE_POLICY_NAME,
                    PolicyDocument=json.dumps(QUARANTINE_DOC),
                )
                return self._aws_result(action, req, dry_run=False)

            if v == Verb.DISABLE_USER and t.type == EntityType.USER:
                req = {
                    "service": "iam",
                    "op": "put_user_policy",
                    "UserName": t.id,
                    "PolicyName": QUARANTINE_POLICY_NAME,
                    "PolicyDocument": QUARANTINE_DOC,
                }
                if dry_run:
                    return self._aws_result(action, req)
                self._client("iam").put_user_policy(
                    UserName=t.id,
                    PolicyName=QUARANTINE_POLICY_NAME,
                    PolicyDocument=json.dumps(QUARANTINE_DOC),
                )
                return self._aws_result(action, req, dry_run=False)

            if v == Verb.DEACTIVATE_KEYS and t.type == EntityType.USER:
                req = {
                    "service": "iam",
                    "op": "update_access_key(Status=Inactive) for each key",
                    "UserName": t.id,
                }
                if dry_run:
                    return self._aws_result(action, req)
                iam = self._client("iam")
                keys = iam.list_access_keys(UserName=t.id)["AccessKeyMetadata"]
                for k in keys:
                    iam.update_access_key(UserName=t.id, AccessKeyId=k["AccessKeyId"], Status="Inactive")
                req["deactivated"] = len(keys)
                return self._aws_result(action, req, dry_run=False)

            if v == Verb.QUARANTINE_ACCOUNT and t.type == EntityType.CLOUD_ACCOUNT:
                scp = (
                    self.env("SEVENTYTWO_QUARANTINE_SCP_ID", required=not dry_run)
                    or "<SEVENTYTWO_QUARANTINE_SCP_ID>"
                )
                req = {"service": "organizations", "op": "attach_policy", "PolicyId": scp, "TargetId": t.id}
                if dry_run:
                    return self._aws_result(action, req)
                self._client("organizations").attach_policy(PolicyId=scp, TargetId=t.id)
                return self._aws_result(action, req, dry_run=False)

            if v == Verb.LOCK_BACKUP_VAULT and t.type == EntityType.BACKUP_VAULT:
                req = {
                    "service": "backup",
                    "op": "put_backup_vault_lock_configuration",
                    "BackupVaultName": t.id,
                    "MinRetentionDays": 7,
                    "mode": "governance (ChangeableForDays omitted; removable by an authorized administrator)",
                }
                if dry_run:
                    return self._aws_result(action, req)
                b = self._client("backup")
                desc = b.describe_backup_vault(BackupVaultName=t.id)
                if desc.get("Locked"):
                    req["already_locked"] = True
                    return self._aws_result(action, req, dry_run=False, detail="vault already locked")
                b.put_backup_vault_lock_configuration(
                    BackupVaultName=t.id, MinRetentionDays=req["MinRetentionDays"]
                )
                return self._aws_result(action, req, dry_run=False)
        except Exception as e:  # noqa: BLE001 - optional boto versions expose different exception classes
            return ActionResult(
                action=action, adapter=self.name, dry_run=dry_run, ok=False, detail=f"aws error: {e}"
            )
        return self._unsupported(action, dry_run)

    def revert(self, action: Action, dry_run: bool = True) -> ActionResult:
        v, t = action.verb, action.target
        try:
            if v == Verb.DISABLE_USER:
                req = {
                    "service": "iam",
                    "op": "delete_user_policy",
                    "UserName": t.id,
                    "PolicyName": QUARANTINE_POLICY_NAME,
                }
                if not dry_run:
                    self._client("iam").delete_user_policy(UserName=t.id, PolicyName=QUARANTINE_POLICY_NAME)
            elif v == Verb.DISABLE_SERVICE_PRINCIPAL and t.type == EntityType.SERVICE_PRINCIPAL:
                req = {
                    "service": "iam",
                    "op": "delete_role_policy",
                    "RoleName": t.id,
                    "PolicyName": QUARANTINE_POLICY_NAME,
                }
                if not dry_run:
                    self._client("iam").delete_role_policy(RoleName=t.id, PolicyName=QUARANTINE_POLICY_NAME)
            elif v == Verb.REVOKE_SESSIONS and t.type in {EntityType.USER, EntityType.SERVICE_PRINCIPAL}:
                is_role = t.type == EntityType.SERVICE_PRINCIPAL
                req = {
                    "service": "iam",
                    "op": "delete_role_policy" if is_role else "delete_user_policy",
                    "PolicyName": "72md-RevokeOlderSessions",
                }
                req["RoleName" if is_role else "UserName"] = t.id
                if not dry_run:
                    kwargs = {"PolicyName": req["PolicyName"], "RoleName" if is_role else "UserName": t.id}
                    getattr(self._client("iam"), req["op"])(**kwargs)
            elif v == Verb.QUARANTINE_ACCOUNT:
                scp = self.env("SEVENTYTWO_QUARANTINE_SCP_ID", required=not dry_run) or "<SCP>"
                req = {"service": "organizations", "op": "detach_policy", "PolicyId": scp, "TargetId": t.id}
                if not dry_run:
                    self._client("organizations").detach_policy(PolicyId=scp, TargetId=t.id)
            elif v == Verb.LOCK_BACKUP_VAULT and t.type == EntityType.BACKUP_VAULT:
                req = {
                    "service": "backup",
                    "op": "delete_backup_vault_lock_configuration",
                    "BackupVaultName": t.id,
                    "mode": "governance",
                }
                if not dry_run:
                    self._client("backup").delete_backup_vault_lock_configuration(BackupVaultName=t.id)
            else:
                return ActionResult(
                    action=action,
                    adapter=self.name,
                    dry_run=dry_run,
                    ok=True,
                    detail="not reversible / nothing to revert",
                )
            return self._aws_result(action, req, dry_run=dry_run, detail="revert")
        except Exception as e:  # noqa: BLE001 - optional boto versions expose different exception classes
            return ActionResult(
                action=action, adapter=self.name, dry_run=dry_run, ok=False, detail=f"aws revert error: {e}"
            )

    def _aws_result(self, action: Action, req: dict, dry_run: bool = True, detail: str = "") -> ActionResult:
        return ActionResult(
            action=action,
            adapter=self.name,
            dry_run=dry_run,
            ok=True,
            detail=detail
            or (
                f"DRY-RUN would call {req['service']}.{req['op']}"
                if dry_run
                else f"{req['service']}.{req['op']} ok"
            ),
            request=req,
        )
