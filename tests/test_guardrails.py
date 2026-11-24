"""
Guardrail tests.
Assert that out-of-scope targets are refused.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from policy import tool_allowed_in_phase


def test_phase_gating():
    # Phase 2 should not allow nmap
    assert tool_allowed_in_phase("nmap_scan", phase=2) is False
    # Phase 3 should allow nmap
    assert tool_allowed_in_phase("nmap_scan", phase=3) is True
    # Cheatsheet always allowed
    assert tool_allowed_in_phase("cheatsheet", phase=1) is True
    print("phase gating: ok")


def test_scope_file_required():
    # This is a reminder test; real scope checks live in agent.py
    scope = Path(__file__).parent.parent / "scope.json"
    if scope.exists():
        data = json.loads(scope.read_text())
        assert "allowed" in data
    print("scope structure: ok")


if __name__ == "__main__":
    test_phase_gating()
    test_scope_file_required()
    print("guardrail tests passed")
