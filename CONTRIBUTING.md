# Contributing

Thank you. Three kinds of contribution matter most, in this order: rehearsal scenarios from real incident patterns (anonymized), intake mappings for rule names in the wild, and adapter validation on real tenants.

## Ground rules

- Sign your commits off under the [Developer Certificate of Origin](https://developercertificate.org/) (`git commit -s`). By doing so you certify you have the right to contribute the code under the MIT license.
- Never include real identifiers, tenant names, hostnames, or audit logs. Scenarios use `example.com`-style names.
- Every adapter change needs a test with `httpx.MockTransport` (or a botocore Stubber) asserting the request preview and live-call parameters.
- Every scoring or policy-schema change must keep `72md rehearse --fail-if-late` green, and the template policy must be re-attested (`72md policy attest`) if its body changed.
- Do not add a runtime dependency without saying why in the PR; the small surface is deliberate.

## Validating an adapter on a real tenant

Follow `docs/adapters.md` → "Validating a real adapter safely". Record the date, API version, and tenant type in the adapter table. Never paste credentials or tenant ids into an issue.

## Reporting security issues

See `SECURITY.md`. Please do not open public issues for anything that could let the engine act without authority.
