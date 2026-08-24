# Adapters

Adapters target documented vendor APIs with the deploying organization's own credentials. Dry-run is the default and returns a request preview. Some live operations require runtime discovery, so the preview is not always the complete final request sequence. Credentials come from environment variables or the AWS credential chain.

| Adapter | Platform | Verbs | Auth | Test status |
|---|---|---|---|---|
| `entra` | Microsoft Entra ID (Graph v1.0) | revoke_sessions (users), disable_user, disable_service_principal | `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET` (client credentials) | mock transport only; tenant validation required |
| `defender` | Defender for Endpoint (Machine Actions API) | isolate_host (+ unisolate recovery) | same app registration, legacy token scope `api.securitycenter.microsoft.com/.default`, permission `Machine.Isolate`; requests use `api.security.microsoft.com` | mock transport only; test-device validation required |
| `okta` | Okta Users API | revoke_sessions (+ OAuth tokens), disable_user (suspend/unsuspend), require_mfa_reset | `OKTA_ORG_URL` + `OKTA_API_TOKEN` (SSWS) or `OKTA_BEARER` | mock transport only; tenant validation required |
| `crowdstrike` | Falcon Hosts API | isolate_host (contain / lift_containment) | `FALCON_CLIENT_ID`, `FALCON_CLIENT_SECRET`, optional `FALCON_BASE_URL` | mock transport only; tenant validation required |
| `aws` | IAM, Organizations, AWS Backup (boto3) | revoke_sessions (TokenIssueTime deny), disable_user, disable_service_principal, deactivate_keys, quarantine_account (SCP), governance-mode lock_backup_vault | AWS credential chain; `SEVENTYTWO_QUARANTINE_SCP_ID` for account quarantine | botocore Stubber/dry-run tests only; sandbox validation required |
| `mock` | any | all | none | used by rehearsal and tests |

## Least-privilege permissions

Grant each adapter identity only the verbs the policy uses. Suggested minimums:

- Entra app: determine the least-privilege permissions for each enabled action from current Microsoft Graph documentation. User disablement requires `User.EnableDisableAccount.All` plus `User.Read.All`; use administrative units or other scoping controls where supported.
- Defender app: `Machine.Isolate` only.
- Okta: a dedicated service app with `okta.users.manage`; exclude super-admin groups via Okta's admin role scoping.
- AWS: a role limited to `iam:PutUserPolicy`, `iam:PutRolePolicy`, `iam:DeleteUserPolicy`, `iam:DeleteRolePolicy`, `iam:ListAccessKeys`, `iam:UpdateAccessKey`, `organizations:AttachPolicy/DetachPolicy` on the quarantine SCP, and the required Backup Vault Lock calls. Deny on break-glass principals by resource ARN.
- CrowdStrike: API client with `Hosts: Write` only.

## Platform tags

Entities carry a `platform` tag (`entra`, `defender`, `okta`, `crowdstrike`, `aws`) so the executor routes each action to the right adapter. Intake normalizers set defaults per source; override them in `intake_map.yaml` or in the business context map.

## Validating a real adapter safely

1. Create a disposable test user/device in a non-production tenant and complete change approval.
2. Create a non-template, effective policy with authenticated attestations and independently pin its digest.
3. Review the dry-run preview, then test one narrowly scoped action through a trusted operator workflow. Do not use CLI approval text to authorize a live approver-tier action.
4. Confirm the effect in the vendor console and exercise the documented recovery path.
5. Record the date, API version, tenant type, request/response evidence, failure behavior, and reviewer. Never add tenant identifiers or secrets to this public repository.

Documentation was last reviewed on 2026-08-24 against the vendors' published API guidance. That review is not a substitute for tenant validation. In particular, Microsoft currently documents [`api.security.microsoft.com` for the Defender machine-action request](https://learn.microsoft.com/en-us/defender-endpoint/api/isolate-machine) while retaining the legacy `api.securitycenter.microsoft.com/.default` resource for [some application tokens](https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp). AWS documents the [`aws:TokenIssueTime` deny-policy pattern](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html) for role-session revocation and [omission of `ChangeableForDays`](https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html) for governance-mode Backup Vault Lock.

## Roadmap

Trusted approval integrations with signed, expiring, plan-bound payloads; external audit anchors; recovery workflow; Azure RBAC / Conditional Access; Google Workspace and GCP; SentinelOne; and Duo.
