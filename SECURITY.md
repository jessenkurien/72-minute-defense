# Security Policy

## Reporting a vulnerability

If you find a way to make `72md` execute a live action without a valid operational policy and the required verified approvals, to bypass the digest pin, to modify the interior of the audit log without breaking the chain, or to extract credentials, please use [GitHub's private vulnerability reporting for this repository](https://github.com/jessenkurien/72-minute-defense/security/advisories/new). Please do not open a public issue or disclose exploit details before a coordinated fix can be evaluated.

Include the affected release or commit, deployment mode, impact, prerequisites, minimal reproduction steps, and any suggested mitigation. Do not include credentials, tenant identifiers, production logs, personal data, or other secrets. If a safe reproduction requires sensitive material, first describe the issue without attaching that material.

Reports are reviewed on a best-effort basis. Please do not rely on this volunteer-maintained project for emergency vendor response or a guaranteed remediation timeline. Credit will be offered in release notes unless you prefer otherwise.

## Scope

In scope: `seventytwo/`, `policy/`, `scenarios/`, `.github/workflows/`. Out of scope: vulnerabilities in the vendor APIs the adapters call (report to the vendor), and the deploying organization's own credential hygiene.

## Responsible use

This software can disable accounts, isolate hosts, and quarantine cloud accounts. Use it only on systems you own or are authorized to administer, under a policy your organization has approved. Dry-run is the default for a reason.

## Supported versions

Security fixes are considered on a best-effort basis for the current development branch and latest tagged release:

| Version | Supported |
|---|---|
| `main` | Yes; development branch, best effort |
| Latest tagged release (currently `v0.1.0`) | Yes; best effort |
| Earlier releases | No |

Users should reproduce a report against `main` when practical. No response-time or remediation-time service level is provided by the community project. Commercial support, if separately agreed, is governed by the applicable written agreement rather than this policy.
