"""The 72-Minute Defense (`72md`).

Pre-authorized ransomware containment as digest-attested policy-as-code, executed across identity,
endpoint, cloud and backup platforms, and measured against the attacker's clock.

Dry-run by default. Live actions require an armed run against a non-template, effective,
independently pinned policy with verified attestations.
"""

__version__ = "0.1.0"
PROJECT_NAME = "The 72-Minute Defense"
PROJECT_CREATOR = "Jessen Kurien"
PROJECT_URL = "https://github.com/jessenkurien/72-minute-defense"
ATTACKER_CLOCK_MINUTES = 72  # Unit 42 GIRR 2026: quickest-quartile time-to-exfiltration benchmark
