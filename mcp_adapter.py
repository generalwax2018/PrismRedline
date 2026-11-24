"""
Simple MCP-style tool adapter.
PrismRedline can call external tool servers while still applying its own gates.
"""

from typing import Any, Callable, Dict


class MCPAdapter:
    """Thin adapter so external MCP tools still pass through PrismRedline policy."""

    def __init__(self):
        self.tools: Dict[str, Callable] = {}

    def register(self, name: str, func: Callable):
        self.tools[name] = func

    def call(self, name: str, args: dict, policy_check: Callable) -> Any:
        if name not in self.tools:
            return f"Unknown MCP tool: {name}"
        # Policy check must return empty string to proceed
        blocked = policy_check(name, args)
        if blocked:
            return blocked
        return self.tools[name](args)


# Example registration point for future mcp-kali-server tools
adapter = MCPAdapter()
