"""
PrisimRedline report generator.
Produces a professional engagement report from scope, phase, and state data.
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


def generate(output: str = "report.md"):
    scope = load_json("scope.json", {"name": "Unnamed", "allowed": []})
    phase = load_json("phase.json", {"current": 1, "name": "Pre-Engagement"})
    state = load_json("state.json", {"hosts": {}, "scans": []})

    hosts = state.get("hosts", {})
    host_lines = []
    for ip, info in hosts.items():
        last = info.get("last_scan", "n/a")
        host_lines.append(f"- {ip} (last scan: {last})")

    scope_list = "\n".join(f"- {a}" for a in scope.get("allowed", [])) or "- None defined"

    findings = "_No structured findings recorded yet. Complete vulnerability analysis and exploitation phases to populate this section._"

    replacements = {
        "{{engagement_name}}": scope.get("name", "Unnamed Engagement"),
        "{{date}}": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "{{operator}}": "PrisimRedline",
        "{{scope}}": ", ".join(scope.get("allowed", [])) or "Not defined",
        "{{risk_summary}}": "Assessment in progress" if phase.get("current", 1) < 7 else "See findings below",
        "{{key_findings}}": "- Pending completion of later phases",
        "{{scope_list}}": scope_list,
        "{{findings}}": findings,
        "{{host_inventory}}": "\n".join(host_lines) or "- No hosts recorded",
    }

    text = TEMPLATE.read_text()
    for k, v in replacements.items():
        text = text.replace(k, v)

    out_path = BASE / output
    out_path.write_text(text)
    print(f"Report written to {out_path}")
    return out_path


if __name__ == "__main__":
    generate()
