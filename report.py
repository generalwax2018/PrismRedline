"""
PrisimRedline report generator.
Produces per-machine sections with ordered steps (enumeration → foothold → privesc)
and an optional AD chain narrative.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).parent
TEMPLATE = BASE / "report_template.md"


def load_json(name: str, default):
    p = BASE / name
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text())
    except Exception:
        return default


def machine_section(ip: str, info: dict) -> str:
    """Build a standalone-style section for one host."""
    steps = info.get("steps", [])
    if not steps:
        steps = [
            {"title": "Enumeration", "detail": "Relevant port scan and service discovery that led to the foothold."},
            {"title": "Initial Access", "detail": "Commands and evidence used to obtain a foothold."},
            {"title": "Privilege Escalation", "detail": "Steps from initial access to highest privilege obtained."},
        ]

    step_text = ""
    for i, step in enumerate(steps, 1):
        title = step.get("title", f"Step {i}")
        detail = step.get("detail", "")
        commands = step.get("commands", [])
        cmd_block = ""
        if commands:
            cmd_block = "\n```\n" + "\n".join(commands) + "\n```\n"
        step_text += f"### {i}. {title}\n{detail}\n{cmd_block}\n"

    return f"""### Target: {ip}

The following steps are in order and document the path from relevant enumeration to the highest privilege obtained.

{step_text}
"""


def ad_section(hosts: dict) -> str:
    """Placeholder AD chain narrative + follow-up steps."""
    if not hosts:
        return "_No multi-host chain recorded._\n"

    return """### Attack Chain Overview

_Describe the full path here: initial vector → privilege escalation → pivoting method → access to subsequent hosts → final objective._

### Detailed Steps

Follow the same ordered format as standalone targets (relevant enumeration, access method, evidence) for each hop in the chain.

"""


def generate(output: str = "report.md"):
    scope = load_json("scope.json", {"name": "Unnamed", "allowed": []})
    phase = load_json("phase.json", {"current": 1})
    state = load_json("state.json", {"hosts": {}, "scans": []})

    hosts = state.get("hosts", {})
    # For now treat all recorded hosts as standalones; AD grouping can be added later
    standalone_text = ""
    for ip, info in hosts.items():
        standalone_text += machine_section(ip, info)

    if not standalone_text:
        standalone_text = "_No standalone targets recorded yet._\n"

    host_lines = [f"- {ip}" for ip in hosts.keys()] or ["- No hosts recorded"]

    replacements = {
        "{{engagement_name}}": scope.get("name", "Unnamed Engagement"),
        "{{date}}": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "{{operator}}": "PrisimRedline",
        "{{scope}}": ", ".join(scope.get("allowed", [])) or "Not defined",
        "{{risk_summary}}": "See per-target sections" if hosts else "Assessment in progress",
        "{{scope_list}}": "\n".join(f"- {a}" for a in scope.get("allowed", [])) or "- None defined",
        "{{standalone_sections}}": standalone_text,
        "{{ad_section}}": ad_section(hosts),
        "{{host_inventory}}": "\n".join(host_lines),
    }

    text = TEMPLATE.read_text()
    for k, v in replacements.items():
        text = text.replace(k, v)

    out = BASE / output
    out.write_text(text)
    print(f"Report written to {out}")
    return out


if __name__ == "__main__":
    generate()
