"""
PrismRedline report generator.
Professional format with a clear attack chain section.
Produces Markdown and a basic HTML export.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

BASE = Path(__file__).parent
TEMPLATE = BASE / "report_template.md"


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


def build_attack_chain(hosts: dict) -> str:
    if not hosts:
        return (
            "No attack chain has been recorded for this engagement.\n\n"
            "When findings are present, this section will summarize the full path:\n"
            "Initial access vector -> Privilege escalation -> Lateral movement / pivoting -> Final objective."
        )
    lines = ["The following high-level chain was observed during the engagement:\n"]
    for i, (ip, info) in enumerate(hosts.items(), 1):
        note = info.get("chain_note", "See detailed findings for this host.")
        lines.append(f"{i}. **{ip}** - {note}")
    lines.append(
        "\nEach step below is documented with the relevant enumeration, "
        "access method, and evidence required to understand the path."
    )
    return "\n".join(lines)


def build_detailed_findings(hosts: dict) -> str:
    if not hosts:
        return "_No target-specific findings recorded._\n"
    sections = []
    for ip, info in hosts.items():
        steps = info.get("steps", [])
        if not steps:
            steps = [
                {"title": "Relevant Enumeration", "detail": "Port and service discovery that identified the entry point."},
                {"title": "Initial Access", "detail": "Method and evidence used to obtain a foothold."},
                {"title": "Privilege Escalation", "detail": "Steps taken to reach the highest privilege on this host."},
            ]
        body = ""
        for n, step in enumerate(steps, 1):
            title = step.get("title", f"Step {n}")
            detail = step.get("detail", "")
            commands = step.get("commands", [])
            cmd = ""
            if commands:
                cmd = "\n```\n" + "\n".join(commands) + "\n```\n"
            body += f"#### {n}. {title}\n{detail}\n{cmd}\n"
        sections.append(f"### {ip}\n\n{body}")
    return "\n".join(sections)


def build_findings_section() -> str:
    findings = load_json("findings.json", [])
    if not findings:
        return "_No structured findings recorded. Use findings.py to add them._\n"
    lines = []
    for f in findings:
        lines.append(
            f"### {f.get('title')} ({f.get('severity', 'Unrated')})\n"
            f"**Host:** {f.get('host', 'n/a')}\n\n"
            f"{f.get('evidence', '')}\n\n"
            f"**Remediation:** {f.get('remediation', '')}\n"
        )
    return "\n".join(lines)


def build_mitre() -> str:
    attack = load_yaml("attack_map.yaml")
    techniques = attack.get("techniques", {})
    if not techniques:
        return "_No ATT&CK mapping available._\n"
    lines = [
        "| ID | Technique | Tactic | Relevant Phase |",
        "|----|-----------|--------|----------------|",
    ]
    for tid, info in techniques.items():
        lines.append(
            f"| {tid} | {info.get('name', '')} | {info.get('tactic', '')} | {info.get('phase', '')} |"
        )
    lines.append(
        "\n_Mapping is indicative. Note specific techniques observed in the detailed findings._"
    )
    return "\n".join(lines)


def build_resources() -> str:
    attack = load_yaml("attack_map.yaml")
    resources = attack.get("resources", [])
    if not resources:
        return "_None listed._\n"
    return "\n".join(
        f"- **{r.get('name')}** - {r.get('use')} ({r.get('url')})" for r in resources
    )


def generate(output: str = "report.md") -> Path:
    scope = load_json("scope.json", {"name": "Unnamed Engagement", "allowed": []})
    state = load_json("state.json", {"hosts": {}})
    hosts = state.get("hosts", {})

    replacements = {
        "{{engagement_name}}": scope.get("name", "Unnamed Engagement"),
        "{{date}}": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "{{operator}}": "PrismRedline",
        "{{risk_summary}}": "See Attack Chain and Detailed Findings" if hosts else "In progress",
        "{{impact_summary}}": (
            f"{len(hosts)} host(s) were assessed. "
            "Refer to the Attack Chain section for the path taken and the Detailed Findings for evidence."
            if hosts
            else "No hosts have been fully assessed yet."
        ),
        "{{scope_list}}": "\n".join(f"- {a}" for a in scope.get("allowed", [])) or "- Not defined",
        "{{attack_chain}}": build_attack_chain(hosts),
        "{{detailed_findings}}": build_detailed_findings(hosts)
        + "\n\n## Recorded Findings\n\n"
        + build_findings_section(),
        "{{mitre_mapping}}": build_mitre(),
        "{{resources}}": build_resources(),
        "{{host_inventory}}": "\n".join(f"- {ip}" for ip in hosts) or "- None recorded",
    }

    text = TEMPLATE.read_text(encoding="utf-8")
    for k, v in replacements.items():
        text = text.replace(k, v)

    out = BASE / output
    out.write_text(text, encoding="utf-8")
    print(f"Report written to {out}")
    return out


def generate_html(md_path: Path) -> Path:
    """Minimal HTML export of the markdown report."""
    body = md_path.read_text(encoding="utf-8")
    html = (
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>PrismRedline Report</title>"
        "<style>body{font-family:system-ui,sans-serif;max-width:800px;margin:2rem auto;line-height:1.5;}"
        "pre{background:#f4f4f4;padding:1rem;overflow:auto;}</style></head><body><pre>"
        + body.replace("&", "&amp;").replace("<", "&lt;")
        + "</pre></body></html>"
    )
    out = md_path.with_suffix(".html")
    out.write_text(html, encoding="utf-8")
    print(f"HTML report: {out}")
    return out


if __name__ == "__main__":
    path = generate()
    generate_html(path)
