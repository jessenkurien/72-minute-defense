# Security Policy

## Reporting a vulnerability

If you find a way to make `72md` execute a live action without a valid operational policy and the required verified approvals, to bypass the digest pin, to modify the interior of the audit log without breaking the chain, or to extract credentials, please use GitHub's private vulnerability reporting for this repository. Please do not open a public issue.

Reports are reviewed on a best-effort basis. Please do not rely on this volunteer-maintained project for emergency vendor response or a guaranteed remediation timeline. Credit will be offered in release notes unless you prefer otherwise.

## Scope

In scope: `seventytwo/`, `policy/`, `scenarios/`, `.github/workflows/`. Out of scope: vulnerabilities in the vendor APIs the adapters call (report to the vendor), and the deploying organization's own credential hygiene.

## Responsible use

This software can disable accounts, isolate hosts, and quarantine cloud accounts. Use it only on systems you own or are authorized to administer, under a policy your organization has approved. Dry-run is the default for a reason.

## Supported versions

Only the latest release on `main` receives fixes.
