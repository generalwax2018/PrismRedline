"""
PrismRedline policy engine.
Scope + phase + confirmation are the real gates. This module centralizes them.
"""

from pathlib import Path
from typing import Optional
import json

BASE = Path(__file__).parent
SCOPE_FILE = BASE / "scope.json"
PHASE_FILE = BASE / "phase.json"

# Tools allowed per phase (minimum phase)
PHASE_TOOLS = {
    1: [],
    2: ["cheatsheet"],
    3: ["nmap_scan", "gobuster_dir", "nikto_scan", "netexec_smb", "cheatsheet"],
    4: ["searchsploit", "bloodhound_collect", "cheatsheet"],
    5: ["cheatsheet"],  # exploitation remains confirmation-gated
    6: ["linpeas", "winpeas", "cheatsheet"],
    7: ["cheatsheet"],
}

# Always allowed
ALWAYS = {"cheatsheet", "run_command"}


def current_phase() -> int:
    if not PHASE_FILE.exists():
        return 1
    try:
        return int(json.loads(PHASE_FILE.read_text()).get("current", 1))
    except Exception:
        return 1


def tool_allowed_in_phase(tool: str, phase: Optional[int] = None) -> bool:
    phase = phase or current_phase()
    if tool in ALWAYS:
        return True
    allowed = set()
    for p in range(1, phase + 1):
        allowed.update(PHASE_TOOLS.get(p, []))
    return tool in allowed


def dry_run_message(tool: str, args: dict) -> str:
    return f"[DRY-RUN] Would execute {tool} with {args}"
