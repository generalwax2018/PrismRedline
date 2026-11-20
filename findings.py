"""
Findings helper for PrisimRedline.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).parent
FINDINGS_FILE = BASE / "findings.json"


def load_findings():
    if not FINDINGS_FILE.exists():
        return []
    try:
        return json.loads(FINDINGS_FILE.read_text())
    except Exception:
        return []


def add_finding(title: str, host: str, severity: str, evidence: str, remediation: str = ""):
    findings = load_findings()
    findings.append({
        "title": title,
        "host": host,
        "severity": severity,
        "evidence": evidence,
        "remediation": remediation,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    FINDINGS_FILE.write_text(json.dumps(findings, indent=2))
    return findings[-1]


if __name__ == "__main__":
    import sys
    if len(sys.argv) >= 5:
        add_finding(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5] if len(sys.argv) > 5 else "")
        print("Finding added.")
    else:
        print("Usage: python findings.py 'title' host severity 'evidence' ['remediation']")
