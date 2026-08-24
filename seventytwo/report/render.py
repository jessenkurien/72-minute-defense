"""Board-facing outputs: the timeline SVG, a Markdown timeline, and a one-page HTML dashboard."""

from __future__ import annotations

import html
from datetime import datetime, timezone

from .. import PROJECT_CREATOR, PROJECT_NAME, PROJECT_URL
from ..rehearsal.runner import RehearsalResult

SURFACE, INK, INK2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9"
CRIT, GOOD, SERIOUS, BLUE, GOODTXT = "#d03b3b", "#0ca30c", "#ec835a", "#2a78d6", "#006300"
FONT = 'font-family="system-ui,-apple-system,Segoe UI,Helvetica,Arial,sans-serif"'


def timeline_svg(r: RehearsalResult, width: int = 1400) -> str:
    T1 = max(130.0, r.attacker_exfil_minute * 1.4, (r.contain_minute or 0) + 20)
    X0, X1 = 230, width - 60
    x = lambda t: X0 + (t / T1) * (X1 - X0)
    H = 570
    s = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{H}" viewBox="0 0 {width} {H}">',
        f'<rect width="{width}" height="{H}" fill="{SURFACE}"/>',
        f'<text x="40" y="44" {FONT} font-size="26" font-weight="700" fill="{INK}">Rehearsal · {html.escape(r.scenario)}</text>',
    ]
    ax = 400
    for t in range(0, int(T1) + 1, 10):
        s.append(f'<line x1="{x(t):.1f}" y1="90" x2="{x(t):.1f}" y2="{ax}" stroke="{GRID}"/>')
        s.append(
            f'<text x="{x(t):.1f}" y="{ax + 22}" {FONT} font-size="12" fill="{MUTED}" text-anchor="middle">{t}</text>'
        )
    s.append(
        f'<text x="{X1}" y="{ax + 44}" {FONT} font-size="12" fill="{MUTED}" text-anchor="end">minutes since first malicious activity</text>'
    )
    ex = x(r.attacker_exfil_minute)
    s.append(
        f'<line x1="{ex:.1f}" y1="80" x2="{ex:.1f}" y2="{ax}" stroke="{CRIT}" stroke-width="2" stroke-dasharray="6 5"/>'
    )
    s.append(f'<rect x="{ex - 100:.1f}" y="76" width="200" height="26" rx="6" fill="{CRIT}"/>')
    s.append(
        f'<text x="{ex:.1f}" y="94" {FONT} font-size="13" font-weight="700" fill="#fff" text-anchor="middle">{r.attacker_exfil_minute:g} min · EXFILTRATION</text>'
    )

    def lane(y, title, color):
        s.append(f'<rect x="40" y="{y - 16}" width="5" height="32" rx="2" fill="{color}"/>')
        s.append(
            f'<text x="56" y="{y + 5}" {FONT} font-size="15" font-weight="700" fill="{INK}">{title}</text>'
        )

    ya, yd = 160, 290
    lane(ya, "Attacker", CRIT)
    s.append(f'<line x1="{x(0):.1f}" y1="{ya}" x2="{ex:.1f}" y2="{ya}" stroke="{CRIT}" stroke-width="2"/>')
    up = True
    for e in [t for t in r.timeline if t.kind == "attacker" and not t.text.startswith("EXFILTRATION")]:
        s.append(
            f'<circle cx="{x(e.minute):.1f}" cy="{ya}" r="7" fill="{CRIT}" stroke="{SURFACE}" stroke-width="2"/>'
        )
        s.append(
            f'<text x="{x(e.minute):.1f}" y="{ya - 16 if up else ya + 26}" {FONT} font-size="11" fill="{INK2}" text-anchor="middle">{html.escape(e.text[:34])}</text>'
        )
        up = not up
    lane(yd, "72-Minute Defense", GOOD)
    if r.friction_minute is not None:
        s.append(
            f'<circle cx="{x(r.friction_minute):.1f}" cy="{yd}" r="6" fill="{SERIOUS}" stroke="{SURFACE}" stroke-width="2"/>'
        )
        s.append(
            f'<text x="{x(r.friction_minute):.1f}" y="{yd + 42}" {FONT} font-size="11" fill="{INK2}" text-anchor="middle">friction {r.friction_minute:g}</text>'
        )
    if r.detect_minute is not None:
        s.append(
            f'<circle cx="{x(r.detect_minute):.1f}" cy="{yd}" r="7" fill="{BLUE}" stroke="{SURFACE}" stroke-width="2"/>'
        )
        s.append(
            f'<text x="{x(r.detect_minute):.1f}" y="{yd + 26}" {FONT} font-size="11" fill="{INK2}" text-anchor="middle">detect {r.detect_minute:g}</text>'
        )
    if r.contain_minute is not None:
        c0 = r.detect_minute or 0
        s.append(
            f'<rect x="{x(c0):.1f}" y="{yd - 8}" width="{max(2, x(r.contain_minute) - x(c0)):.1f}" height="16" rx="4" fill="{BLUE}" opacity="0.6"/>'
        )
        s.append(
            f'<circle cx="{x(r.contain_minute):.1f}" cy="{yd}" r="8" fill="{GOOD}" stroke="{SURFACE}" stroke-width="2"/>'
        )
        s.append(
            f'<text x="{x(r.contain_minute):.1f}" y="{yd - 16}" {FONT} font-size="12" font-weight="700" fill="{GOODTXT}" text-anchor="middle">contained {r.contain_minute:g}</text>'
        )
        if r.contained_before_exfil:
            s.append(
                f'<rect x="{x(r.contain_minute):.1f}" y="{yd - 5}" width="{ex - x(r.contain_minute):.1f}" height="10" rx="5" fill="{GOOD}" opacity="0.18"/>'
            )
            s.append(
                f'<text x="{(x(r.contain_minute) + ex) / 2:.1f}" y="{yd + 30}" {FONT} font-size="12" font-weight="700" fill="{GOODTXT}" text-anchor="middle">{r.margin_minutes:g}-minute margin</text>'
            )
        else:
            s.append(
                f'<text x="{x(r.contain_minute):.1f}" y="{yd + 30}" {FONT} font-size="12" font-weight="700" fill="{CRIT}" text-anchor="middle">{abs(r.margin_minutes):g} min too late</text>'
            )
    elif r.expect == "no_action":
        s.append(
            f'<text x="{x(10):.1f}" y="{yd + 5}" {FONT} font-size="13" font-weight="700" fill="{GOODTXT}">NO ACTION — correct: a lone weak signal must not contain (over-blocking is how automatic containment gets switched off)</text>'
        )
    else:
        s.append(
            f'<text x="{x(10):.1f}" y="{yd + 5}" {FONT} font-size="13" font-weight="700" fill="{CRIT}">NOT CONTAINED — policy never authorized an executable action</text>'
        )
    # tiles
    tiles = [
        (f"{r.attacker_exfil_minute:g} min", "attacker clock", CRIT),
        (f"{r.detect_minute if r.detect_minute is not None else '—'}", "detect (min)", BLUE),
        (
            f"{r.contain_minute if r.contain_minute is not None else '—'}",
            "contain (min)",
            GOOD if r.contained_before_exfil else CRIT,
        ),
        (
            f"{r.margin_minutes if r.margin_minutes is not None else '—'}",
            "margin (min)",
            GOODTXT if r.contained_before_exfil else CRIT,
        ),
        (r.authority_used or "—", "authority used", INK2),
    ]
    tw = (width - 80 - 4 * 16) / 5
    for i, (big, small, col) in enumerate(tiles):
        tx = 40 + i * (tw + 16)
        s.append(
            f'<rect x="{tx:.1f}" y="{ax + 70}" width="{tw:.1f}" height="70" rx="8" fill="#fff" stroke="{GRID}"/>'
        )
        s.append(f'<rect x="{tx:.1f}" y="{ax + 70}" width="5" height="70" rx="2" fill="{col}"/>')
        s.append(
            f'<text x="{tx + 18:.1f}" y="{ax + 106}" {FONT} font-size="26" font-weight="700" fill="{INK}">{html.escape(str(big))}</text>'
        )
        s.append(f'<text x="{tx + 18:.1f}" y="{ax + 128}" {FONT} font-size="12" fill="{INK2}">{small}</text>')
    s.append(
        f'<text x="{width - 60}" y="554" {FONT} font-size="12" fill="{MUTED}" text-anchor="end">{PROJECT_NAME} · Created by {PROJECT_CREATOR}</text>'
    )
    s.append("</svg>")
    return "\n".join(s)


def timeline_markdown(r: RehearsalResult) -> str:
    m = r.metrics()
    lines = [
        f"# Rehearsal timeline — {r.scenario}",
        "",
        (
            f"**Time to detect:** {m['time_to_detect_minutes']} min · "
            f"**Time to contain:** {m['time_to_contain_minutes']} min · "
            f"**Attacker clock:** {m['attacker_clock_minutes']:g} min · "
            f"**Margin:** {m['margin_minutes']} min · **Authority:** {m['authority_used']}"
        ),
        "",
        "| Minute | Kind | Event |",
        "|---:|---|---|",
    ]
    for t in r.timeline:
        lines.append(f"| {t.minute:g} | {t.kind} | {t.text.replace('|', '/')} |")
    if r.final_plan:
        lines += ["", "## Final decision", ""] + [f"- {x}" for x in r.final_plan.reasons]
        if r.final_plan.blast_radius.services:
            lines.append(
                f"- blast radius services: {', '.join(r.final_plan.blast_radius.services)} (max criticality {r.final_plan.blast_radius.max_criticality})"
            )
    lines += ["", f"_Created by [{PROJECT_CREATOR}]({PROJECT_URL}) · {PROJECT_NAME}_"]
    return "\n".join(lines) + "\n"


def dashboard_html(
    results: list[RehearsalResult],
    policy_summary: dict,
    audit_status: str,
    restore_hours: float | None = None,
) -> str:
    svgs = "\n".join(f'<section class="card">{timeline_svg(r)}</section>' for r in results)
    ok = [r for r in results if r.passed]
    contained = [r for r in results if r.contain_minute is not None]
    worst = max(r.contain_minute for r in contained) if contained else None
    best_margin = min((r.margin_minutes for r in results if r.margin_minutes is not None), default=None)
    rows = "".join(
        f"<tr><td>{html.escape(r.scenario)}</td><td>{r.detect_minute}</td><td>{r.contain_minute}</td>"
        f"<td>{r.margin_minutes}</td><td>{r.expect}</td><td>{'PASS' if r.passed else 'FAIL'}</td><td>{r.authority_used or '—'}</td></tr>"
        for r in results
    )
    gen = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>The 72-Minute Defense — board view</title>
<style>
body{{margin:0;background:#f9f9f7;color:#0b0b0b;font-family:system-ui,-apple-system,'Segoe UI',sans-serif}}
main{{max-width:1480px;margin:0 auto;padding:32px 24px}} h1{{font-size:30px;margin:0 0 4px}} .sub{{color:#52514e;margin:0 0 24px}}
.tiles{{display:grid;grid-template-columns:repeat(5,1fr);gap:14px;margin-bottom:24px}}
.tile{{background:#fff;border:1px solid #e1e0d9;border-radius:10px;padding:16px 18px;border-left:6px solid #2a78d6}}
.tile b{{display:block;font-size:34px}} .tile span{{color:#52514e;font-size:13px}}
.card{{background:#fff;border:1px solid #e1e0d9;border-radius:10px;padding:8px;margin-bottom:20px;overflow-x:auto}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e1e0d9;border-radius:10px}} th,td{{padding:10px 12px;text-align:left;border-bottom:1px solid #e1e0d9;font-size:14px}}
.foot{{color:#898781;font-size:12px;margin-top:24px}}
</style></head><body><main>
<h1>The 72-Minute Defense</h1>
<p class="sub">{html.escape(policy_summary.get("organization", ""))} · policy v{policy_summary.get("version", "?")} · {policy_summary.get("attestations", "?")} · generated {gen}</p>
<div class="tiles">
<div class="tile" style="border-left-color:#d03b3b"><b>{policy_summary.get("attacker_clock", 72)} min</b><span>attacker time to exfiltration (Unit 42, 2026)</span></div>
<div class="tile" style="border-left-color:#0ca30c"><b>{worst if worst is not None else "—"} min</b><span>worst-case time to contain across {len(results)} rehearsal(s)</span></div>
<div class="tile" style="border-left-color:#006300"><b>{best_margin if best_margin is not None else "—"} min</b><span>smallest safety margin</span></div>
<div class="tile" style="border-left-color:#2a78d6"><b>{len(ok)}/{len(results)}</b><span>scenarios behaved as the policy intends</span></div>
<div class="tile" style="border-left-color:#52514e"><b>{f"{restore_hours:g} h" if restore_hours else "—"}</b><span>reported restore-drill input</span></div>
</div>
<table><thead><tr><th>Scenario</th><th>Detect (min)</th><th>Contain (min)</th><th>Margin (min)</th><th>Expected</th><th>Result</th><th>Authority</th></tr></thead><tbody>{rows}</tbody></table>
<br/>{svgs}
<p class="foot"><strong>Created by <a href="{PROJECT_URL}">{PROJECT_CREATOR}</a>.</strong> Audit log: {html.escape(audit_status)}. Attacker clock from Unit 42 Global Incident Response Report 2026. Defender timings are rehearsal outputs against this policy; production numbers come from real activations recorded in the audit log.</p>
</main></body></html>"""
