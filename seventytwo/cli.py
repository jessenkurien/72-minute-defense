"""`72md` command-line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import yaml
from pydantic import ValidationError

from . import __version__
from .adapters import build_adapters
from .engine import Approval, AuditLog, decide, execute, load_context
from .intake import normalize
from .policy import attest, load_policy
from .rehearsal import load_scenario, rehearse
from .report import dashboard_html, timeline_markdown, timeline_svg
from .scoring import load_catalog, score_events

ROOT = Path(__file__).resolve().parent.parent
PACKAGE_DATA = Path(__file__).resolve().parent / "data"
DEFAULT_POLICY = (
    ROOT / "policy" / "containment-authority.yaml"
    if (ROOT / "policy" / "containment-authority.yaml").is_file()
    else PACKAGE_DATA / "default-containment-authority.yaml"
)
DEFAULT_CONTEXT = (
    ROOT / "policy" / "business-context.yaml"
    if (ROOT / "policy" / "business-context.yaml").is_file()
    else PACKAGE_DATA / "default-business-context.yaml"
)
DEFAULT_SCENARIOS = ROOT / "scenarios" if (ROOT / "scenarios").is_dir() else PACKAGE_DATA / "scenarios"
DEFAULT_AUDIT = Path("audit/72md-audit.jsonl")


def _load(policy_path):
    try:
        return load_policy(policy_path)
    except (OSError, TypeError, ValueError, ValidationError, yaml.YAMLError) as e:
        msg = str(e).splitlines()
        click.echo(
            f"policy invalid ({policy_path}): "
            + "; ".join(line.strip() for line in msg if "error" in line.lower() or "Value" in line)[:400],
            err=True,
        )
        sys.exit(1)


def _common(policy, context, audit):
    return _load(policy), load_context(context), AuditLog(audit)


@click.group()
@click.version_option(__version__, prog_name="72md")
def main() -> None:
    """The 72-Minute Defense: pre-authorized ransomware containment, measured against the attacker's clock."""
    # Windows may otherwise expose a legacy cp1252 console and crash on timeline symbols.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="replace")


# ---------------------------------------------------------------- policy
@main.group()
def policy() -> None:
    """Containment Authority Policy: validate, attest, verify, explain."""


@policy.command("verify")
@click.option(
    "--policy", "policy_path", type=click.Path(path_type=Path), default=DEFAULT_POLICY, show_default=True
)
def policy_verify(policy_path):
    p = _load(policy_path)
    ok, problems = p.verify()
    click.echo(f"policy v{p.version} for {p.organization} · digest {p.digest()[:16]}…")
    for t in p.tiers:
        click.echo(
            f"  tier {t.name:<8} ≥{t.threshold:<3} {t.authority.value:<16} {', '.join(v.value for v in t.actions)}"
        )
    click.echo(
        f"  protections: {len(p.protections.principals)} principal pattern(s), {len(p.protections.hosts)} host pattern(s), "
        f"criticality floor {p.protections.criticality_at_least}"
    )
    label = "illustrative digest attestations" if p.template else "digest attestations"
    click.echo(f"  {label}: " + ("VALID" if ok else "INVALID"))
    if ok and p.template:
        click.echo("  live execution: BLOCKED — this is a public template")
    elif ok:
        click.echo("  live execution: requires an effective policy and an out-of-band digest pin")
    for pr in problems:
        click.echo(f"    ! {pr}")
    sys.exit(0 if ok else 1)


@policy.command("attest")
@click.option(
    "--policy", "policy_path", type=click.Path(path_type=Path), default=DEFAULT_POLICY, show_default=True
)
@click.option("--role", required=True)
@click.option("--name", required=True)
def policy_attest(policy_path, role, name):
    """Print a digest attestation; authenticate the person in a protected review system."""
    p = _load(policy_path)
    s = attest(p, role, name)
    click.echo(
        "  - " + json.dumps({"role": s.role, "name": s.name, "date": s.date.isoformat(), "digest": s.digest})
    )


# ---------------------------------------------------------------- decide / act
@main.command()
@click.option(
    "--events",
    "events_path",
    type=click.Path(path_type=Path),
    required=True,
    help="JSON file: list of events (generic) or vendor payload with --format",
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["generic", "sentinel", "splunk", "falcon", "guardduty"]),
    default="generic",
    show_default=True,
)
@click.option(
    "--policy", "policy_path", type=click.Path(path_type=Path), default=DEFAULT_POLICY, show_default=True
)
@click.option(
    "--context", "context_path", type=click.Path(path_type=Path), default=DEFAULT_CONTEXT, show_default=True
)
@click.option(
    "--audit", "audit_path", type=click.Path(path_type=Path), default=DEFAULT_AUDIT, show_default=True
)
@click.option(
    "--adapters",
    "adapter_names",
    default="",
    help="Comma list: entra,defender,okta,crowdstrike,aws. Empty = mock.",
)
@click.option(
    "--arm", is_flag=True, help="EXECUTE live actions. Template policies cannot be armed. Default is dry-run."
)
@click.option(
    "--approve", multiple=True, help="Simulation approval as ROLE:NAME:REF. It cannot authorize a live run."
)
@click.option("--json", "json_out", type=click.Path(path_type=Path))
def act(events_path, fmt, policy_path, context_path, audit_path, adapter_names, arm, approve, json_out):
    """Score events, decide under the policy, and execute (dry-run unless --arm)."""
    p, ctx, audit = _common(policy_path, context_path, audit_path)
    payload = json.loads(Path(events_path).read_text(encoding="utf-8"))
    events, unmapped = normalize(fmt, payload)
    for u in unmapped:
        click.echo(f"  ! unmapped alert ignored: {u}", err=True)
    if not events:
        click.echo("no events after normalization")
        sys.exit(1)
    catalog = load_catalog()
    scores = score_events(events, catalog)
    adapters = build_adapters([a for a in adapter_names.split(",") if a], mock=not adapter_names)
    approvals = []
    for raw in approve:
        parts = raw.split(":", 2)
        if len(parts) != 3 or not all(part.strip() for part in parts):
            raise click.ClickException("--approve must be ROLE:NAME:REF with no empty fields")
        approvals.append(Approval(*parts, verified=False, source="cli_simulation"))
    out = []
    for s in scores:
        plan = decide(s, p, ctx)
        rep = execute(plan, p, adapters, audit, armed=arm, approvals=approvals)
        _print_plan(plan, rep, arm)
        out.append(
            {
                "subject": s.entity.key(),
                "score": s.score,
                "tier": plan.tier.name if plan.tier else None,
                "authority": plan.authority.value,
                "actions": [f"{a.verb.value}→{a.target.key()}" for a in plan.actions],
                "blocked": rep.blocked_reason,
                "executed": [r.model_dump(mode="json") for r in rep.executed],
                "reasons": plan.reasons,
            }
        )
    if json_out:
        Path(json_out).write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
        click.echo(f"  → {json_out}")


def _print_plan(plan, rep, armed):
    s = plan.subject
    click.echo("")
    click.echo(
        f"  {s.entity.key()}  score {s.score}  stages {[x.value for x in s.stages_seen]}  {s.distance_to_impact} to impact"
        + ("  CRITICAL" if s.critical else "")
    )
    click.echo(f"  cluster: {', '.join(e.key() for e in s.cluster)}")
    for r in plan.reasons:
        click.echo(f"    · {r}")
    if plan.blast_radius.services:
        click.echo(
            f"    · blast radius: services {plan.blast_radius.services}, max criticality {plan.blast_radius.max_criticality}, owners {plan.blast_radius.owners}"
        )
    if rep.blocked_reason:
        click.echo(f"    ■ {rep.blocked_reason}")
    for r in rep.executed:
        tag = "LIVE" if not r.dry_run else "DRY-RUN"
        click.echo(
            f"    {'✓' if r.ok else '✗'} [{tag}] {r.action.verb.value} → {r.action.target.key()} via {r.adapter}: {r.detail}"
        )
        if r.dry_run and r.request:
            click.echo(
                f"         would send: {r.request.get('method', '')} {r.request.get('url', r.request.get('op', ''))}"
            )
    for sk in rep.skipped:
        click.echo(f"    – skipped: {sk}")


# ---------------------------------------------------------------- rehearse
@main.command()
@click.option(
    "--scenario",
    "scenarios",
    multiple=True,
    type=click.Path(path_type=Path),
    help="Scenario YAML (repeatable). Default: all in ./scenarios",
)
@click.option(
    "--policy", "policy_path", type=click.Path(path_type=Path), default=DEFAULT_POLICY, show_default=True
)
@click.option(
    "--context", "context_path", type=click.Path(path_type=Path), default=DEFAULT_CONTEXT, show_default=True
)
@click.option(
    "--audit",
    "audit_path",
    type=click.Path(path_type=Path),
    default=Path("audit/72md-rehearsal.jsonl"),
    show_default=True,
)
@click.option("--out", "out_dir", type=click.Path(path_type=Path), default=Path("out"), show_default=True)
@click.option(
    "--restore-hours",
    type=float,
    default=None,
    help="Proven restore time from your last recovery drill, for the dashboard tile.",
)
@click.option(
    "--fail-if-late",
    is_flag=True,
    help="Exit 2 if any scenario is not contained before the attacker clock (CI gate for policy changes).",
)
def rehearse_cmd(scenarios, policy_path, context_path, audit_path, out_dir, restore_hours, fail_if_late):
    """Replay synthetic intrusions through the policy and report time-to-contain vs the 72-minute clock."""
    p, ctx, audit = _common(policy_path, context_path, audit_path)
    catalog = load_catalog()
    paths = list(scenarios) or sorted(DEFAULT_SCENARIOS.glob("*.yaml"))
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    late = False
    for sp in paths:
        sc = load_scenario(sp)
        r = rehearse(sc, p, catalog, ctx, audit)
        results.append(r)
        m = r.metrics()
        flag = "✓" if r.passed else "✗"
        click.echo(
            f"  {flag} {sc.name:<28} expect {sc.expect:<9} detect {m['time_to_detect_minutes']!s:>5}  friction {m['friction_minute']!s:>5}  "
            f"contain {m['time_to_contain_minutes']!s:>6}  margin {m['margin_minutes']!s:>6}  authority {m['authority_used']}"
        )
        (out_dir / f"{sc.name}.md").write_text(timeline_markdown(r), encoding="utf-8")
        (out_dir / f"{sc.name}.svg").write_text(timeline_svg(r), encoding="utf-8")
        (out_dir / f"{sc.name}.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
        late = late or not r.passed
    ok, _problems = p.verify()
    summary = {
        "organization": p.organization,
        "version": p.version,
        "attacker_clock": p.attacker_clock_minutes,
        "attestations": (
            "illustrative digest checks valid" if ok and p.template else "valid" if ok else "INVALID"
        ),
    }
    _audit_ok, _count, msg = audit.verify()
    (out_dir / "dashboard.html").write_text(
        dashboard_html(results, summary, msg, restore_hours), encoding="utf-8"
    )
    click.echo(
        f"\n  dashboard → {out_dir / 'dashboard.html'}   timelines → {out_dir}/*.md|svg|json   audit: {msg}"
    )
    if fail_if_late and late:
        sys.exit(2)


# ---------------------------------------------------------------- audit
@main.group()
def audit() -> None:
    """Hash-chained audit log."""


@audit.command("verify")
@click.option(
    "--audit", "audit_path", type=click.Path(path_type=Path), default=DEFAULT_AUDIT, show_default=True
)
def audit_verify(audit_path):
    ok, _count, msg = AuditLog(audit_path).verify()
    click.echo(("OK   " if ok else "FAIL ") + msg)
    sys.exit(0 if ok else 1)


@audit.command("show")
@click.option(
    "--audit", "audit_path", type=click.Path(path_type=Path), default=DEFAULT_AUDIT, show_default=True
)
@click.option("--last", default=20, show_default=True)
def audit_show(audit_path, last):
    for r in AuditLog(audit_path).records()[-last:]:
        extra = {k: v for k, v in r.items() if k not in ("ts", "kind", "actor", "prev", "hash")}
        click.echo(f"{r['ts']}  {r['kind']:<18} {r['actor']:<16} {json.dumps(extra, default=str)[:140]}")


@main.command()
def adapters_cmd() -> None:
    """List platform adapters and the verbs each supports."""
    from .adapters import REAL

    for n, cls in REAL.items():
        click.echo(f"{n:<12} {', '.join(sorted(v.value for v in cls.supported))}")


main.add_command(adapters_cmd, "adapters")

if __name__ == "__main__":
    main()
