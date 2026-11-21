"""
PrismRedline GUI
Local web dashboard that reflects the full engagement: phase progress, scope,
discovered hosts and services, findings, MITRE ATT&CK mapping, and the evidence
trail. Read-only view over the same state files the agent writes.
"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import uvicorn
from pathlib import Path
import json

try:
    import yaml
except ImportError:
    yaml = None

app = FastAPI(title="PrismRedline")

BASE = Path(__file__).parent

PHASES = [
    "Pre-Engagement",
    "Reconnaissance",
    "Scanning & Enum",
    "Vuln Analysis",
    "Exploitation",
    "Post-Exploitation",
    "Reporting",
]

SEV_COLORS = {
    "critical": "#f87171",
    "high": "#fb923c",
    "medium": "#fbbf24",
    "low": "#60a5fa",
    "info": "#9ca3af",
}


def load_json(name: str, default):
    p = BASE / name
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default


def load_yaml(name: str) -> dict:
    if yaml is None:
        return {}
    p = BASE / name
    if not p.exists():
        return {}
    try:
        return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def phase_tracker(current: int) -> str:
    cells = []
    for i, name in enumerate(PHASES, 1):
        if i < current:
            cls = "done"
        elif i == current:
            cls = "active"
        else:
            cls = "todo"
        cells.append(
            f'<div class="step {cls}"><div class="dot">{i}</div>'
            f'<div class="plabel">{name}</div></div>'
        )
    return '<div class="tracker">' + "".join(cells) + "</div>"


def hosts_table(hosts: dict) -> str:
    if not hosts:
        return "<p class='muted'>No hosts discovered yet.</p>"
    rows = []
    for host, info in hosts.items():
        ports = info.get("ports", [])
        if ports:
            svc = "".join(
                f'<span class="chip">{p.get("port")}/{p.get("proto","tcp")} '
                f'{p.get("service","")}</span>'
                for p in ports
            )
        else:
            svc = '<span class="muted">no services recorded</span>'
        steps = len(info.get("steps", []))
        rows.append(
            f"<tr><td class='mono'>{host}</td><td>{svc}</td>"
            f"<td class='num'>{steps}</td></tr>"
        )
    return (
        "<table><thead><tr><th>Host</th><th>Services</th>"
        "<th>Steps</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def findings_list(findings: list) -> str:
    if not findings:
        return "<p class='muted'>No findings recorded yet.</p>"
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(
        findings, key=lambda f: order.get(str(f.get("severity", "")).lower(), 9)
    )
    items = []
    for f in findings:
        sev = str(f.get("severity", "Info"))
        color = SEV_COLORS.get(sev.lower(), "#9ca3af")
        items.append(
            f'<li><span class="sev" style="background:{color}">{sev}</span>'
            f'<span class="ftitle">{f.get("title","Untitled")}</span>'
            f'<span class="fhost mono">{f.get("host","")}</span></li>'
        )
    return "<ul class='findings'>" + "".join(items) + "</ul>"


def mitre_table(hosts_present: bool) -> str:
    attack = load_yaml("attack_map.yaml")
    tech = attack.get("techniques", {})
    if not tech:
        return "<p class='muted'>No ATT&CK mapping available.</p>"
    rows = "".join(
        f"<tr><td class='mono'>{tid}</td><td>{t.get('name','')}</td>"
        f"<td>{t.get('tactic','')}</td><td class='num'>{t.get('phase','')}</td></tr>"
        for tid, t in tech.items()
    )
    return (
        "<table><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th>"
        "<th>Phase</th></tr></thead><tbody>" + rows + "</tbody></table>"
    )


def scan_log(scans: list) -> str:
    if not scans:
        return "<p class='muted'>No scans recorded yet.</p>"
    rows = []
    for s in scans[-12:][::-1]:
        ts = str(s.get("timestamp", ""))[:19].replace("T", " ")
        rows.append(
            f"<tr><td class='mono'>{s.get('tool','')}</td>"
            f"<td class='mono'>{s.get('target','')}</td>"
            f"<td class='mono muted'>{s.get('flags','')}</td>"
            f"<td class='muted'>{ts}</td></tr>"
        )
    return (
        "<table><thead><tr><th>Tool</th><th>Target</th><th>Flags</th>"
        "<th>When (UTC)</th></tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )


@app.get("/", response_class=HTMLResponse)
async def index():
    phase = load_json("phase.json", {"current": 1, "name": "Pre-Engagement & Scoping"})
    scope = load_json("scope.json", {"name": "unscoped", "allowed": []})
    state = load_json("state.json", {"hosts": {}, "scans": []})
    findings = load_json("findings.json", [])

    current = int(phase.get("current", 1))
    hosts = state.get("hosts", {})
    scans = state.get("scans", [])
    allowed = scope.get("allowed", [])

    report_exists = (BASE / "report.md").exists()

    scope_items = "".join(f"<li class='mono'>{a}</li>" for a in allowed) or \
        "<li class='muted'>No scope defined</li>"

    stat_cards = f"""
      <div class="stat"><div class="snum">{current}/7</div><div class="slabel">Phase</div></div>
      <div class="stat"><div class="snum">{len(hosts)}</div><div class="slabel">Hosts</div></div>
      <div class="stat"><div class="snum">{len(allowed)}</div><div class="slabel">In scope</div></div>
      <div class="stat"><div class="snum">{len(findings)}</div><div class="slabel">Findings</div></div>
      <div class="stat"><div class="snum">{len(scans)}</div><div class="slabel">Scans</div></div>
      <div class="stat"><div class="snum">{'yes' if report_exists else 'no'}</div><div class="slabel">Report</div></div>
    """

    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <title>PrismRedline</title>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta http-equiv="refresh" content="15">
      <style>
        :root {{
          --bg:#0b0e14; --panel:#141924; --panel2:#1b2130; --line:#2a3242;
          --text:#e6e9ef; --muted:#8893a7; --accent:#7dd3fc; --ok:#86efac;
        }}
        * {{ box-sizing:border-box; }}
        body {{ font-family:ui-sans-serif,system-ui,'Segoe UI',sans-serif;
          background:var(--bg); color:var(--text); margin:0; padding:24px; }}
        .wrap {{ max-width:1080px; margin:0 auto; }}
        header {{ display:flex; align-items:baseline; gap:14px; flex-wrap:wrap; }}
        h1 {{ color:var(--accent); margin:0; font-size:1.7rem; letter-spacing:.3px; }}
        .tag {{ color:var(--muted); font-size:.92rem; }}
        .badge {{ margin-left:auto; font-size:.72rem; color:#fecaca;
          border:1px solid #7f1d1d; background:#2a0f12; padding:3px 9px; border-radius:999px; }}
        .grid {{ display:grid; grid-template-columns:2fr 1fr; gap:16px; margin-top:18px; }}
        @media (max-width:820px) {{ .grid {{ grid-template-columns:1fr; }} }}
        .panel {{ background:var(--panel); border:1px solid var(--line);
          border-radius:12px; padding:16px 18px; margin-bottom:16px; }}
        .panel h2 {{ font-size:.82rem; text-transform:uppercase; letter-spacing:.8px;
          color:var(--muted); margin:0 0 12px; font-weight:600; }}
        .stats {{ display:grid; grid-template-columns:repeat(6,1fr); gap:10px; }}
        @media (max-width:820px) {{ .stats {{ grid-template-columns:repeat(3,1fr); }} }}
        .stat {{ background:var(--panel2); border:1px solid var(--line); border-radius:10px;
          padding:12px; text-align:center; }}
        .snum {{ font-size:1.4rem; font-weight:700; color:var(--text); }}
        .slabel {{ font-size:.72rem; color:var(--muted); text-transform:uppercase; letter-spacing:.6px; }}
        .tracker {{ display:flex; gap:6px; }}
        .step {{ flex:1; text-align:center; }}
        .step .dot {{ width:28px; height:28px; line-height:28px; border-radius:50%;
          margin:0 auto 6px; font-size:.82rem; font-weight:700;
          background:var(--panel2); color:var(--muted); border:1px solid var(--line); }}
        .step .plabel {{ font-size:.68rem; color:var(--muted); }}
        .step.done .dot {{ background:#14351f; color:var(--ok); border-color:#1f5134; }}
        .step.active .dot {{ background:var(--accent); color:#06283a; border-color:var(--accent); }}
        .step.active .plabel {{ color:var(--text); font-weight:600; }}
        table {{ width:100%; border-collapse:collapse; font-size:.86rem; }}
        th {{ text-align:left; color:var(--muted); font-weight:600; font-size:.74rem;
          text-transform:uppercase; letter-spacing:.5px; padding:6px 8px; border-bottom:1px solid var(--line); }}
        td {{ padding:7px 8px; border-bottom:1px solid #1e2533; vertical-align:top; }}
        .mono {{ font-family:ui-monospace,'Cascadia Code',Consolas,monospace; }}
        .num {{ text-align:right; color:var(--muted); }}
        .muted {{ color:var(--muted); }}
        .chip {{ display:inline-block; background:var(--panel2); border:1px solid var(--line);
          border-radius:6px; padding:2px 7px; margin:2px 4px 2px 0; font-size:.76rem;
          font-family:ui-monospace,monospace; }}
        ul {{ list-style:none; padding:0; margin:0; }}
        .findings li {{ display:flex; align-items:center; gap:10px; padding:7px 0;
          border-bottom:1px solid #1e2533; }}
        .sev {{ color:#0b0e14; font-weight:700; font-size:.68rem; padding:2px 8px;
          border-radius:999px; min-width:62px; text-align:center; text-transform:uppercase; }}
        .ftitle {{ flex:1; }}
        .fhost {{ color:var(--muted); font-size:.8rem; }}
        .scope li {{ padding:5px 0; border-bottom:1px solid #1e2533; }}
        footer {{ color:var(--muted); font-size:.78rem; margin-top:6px; text-align:center; }}
      </style>
    </head>
    <body>
      <div class="wrap">
        <header>
          <h1>PrismRedline</h1>
          <span class="tag">Engagement: {scope.get('name','unscoped')}</span>
          <span class="badge">AUTHORIZED USE ONLY</span>
        </header>

        <div class="panel" style="margin-top:16px">
          <div class="stats">{stat_cards}</div>
        </div>

        <div class="panel">
          <h2>Phase Progress</h2>
          {phase_tracker(current)}
        </div>

        <div class="grid">
          <div>
            <div class="panel">
              <h2>Hosts &amp; Services</h2>
              {hosts_table(hosts)}
            </div>
            <div class="panel">
              <h2>Findings ({len(findings)})</h2>
              {findings_list(findings)}
            </div>
            <div class="panel">
              <h2>MITRE ATT&amp;CK Coverage</h2>
              {mitre_table(bool(hosts))}
            </div>
          </div>
          <div>
            <div class="panel">
              <h2>Scope</h2>
              <ul class="scope">{scope_items}</ul>
            </div>
            <div class="panel">
              <h2>Evidence / Scan Log</h2>
              {scan_log(scans)}
            </div>
          </div>
        </div>

        <footer>Read-only view &middot; auto-refreshes every 15s &middot;
          raw output saved under <span class="mono">evidence/</span> &middot;
          report via <span class="mono">python report.py</span></footer>
      </div>
    </body>
    </html>
    """
    return html


if __name__ == "__main__":
    print("PrismRedline GUI -> http://127.0.0.1:8088")
    uvicorn.run(app, host="127.0.0.1", port=8088)
