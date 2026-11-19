#!/usr/bin/env python3
"""
PrisimRedline - Local AI red team assistant that follows the classic pentesting phases.
Runs against Ollama on your local GPU (RTX 3090 recommended).
"""

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cli import status
from rich.markdown import Markdown
from rich.prompt import Prompt, Confirm
import requests

console = Console()

# Configuration
OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen3:14b"
SCOPE_FILE = "scope.json"
PHASE_FILE = "phase.json"
STATE_FILE = "state.json"  # hosts, ports, reachability

PHASES = [
    "1. Pre-Engagement & Scoping",
    "2. Reconnaissance (OSINT)",
    "3. Scanning & Enumeration",
    "4. Vulnerability Analysis",
    "5. Exploitation",
    "6. Post-Exploitation & Privilege Escalation",
    "7. Reporting & Remediation",
]

# Allowed tools and their safe wrappers
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "nmap_scan",
            "description": "Run an nmap scan against a target. Only use on authorized targets.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP address or hostname to scan"},
                    "flags": {"type": "string", "description": "nmap flags (e.g. -sV -T4 -F)", "default": "-sV -T4 -F"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "gobuster_dir",
            "description": "Run gobuster directory brute force against a web target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "Base URL (http://target)"},
                    "wordlist": {"type": "string", "description": "Path to wordlist", "default": "/usr/share/wordlists/dirb/common.txt"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "nikto_scan",
            "description": "Run nikto web vulnerability scanner.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL or IP:port to scan"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": "Run a safe shell command. Use for enumeration or analysis only. Dangerous commands are blocked.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to run"},
                },
                "required": ["command"],
            },
        },
    },
]

DANGEROUS_PATTERNS = [
    "rm -rf", "dd if=", "mkfs", "format", ":(){ :|:& };:",
    "msfconsole", "exploit", "payload", "hydra", "john",
]


def load_scope() -> Optional[Dict]:
    path = Path(SCOPE_FILE)
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def in_scope(target: str) -> bool:
    scope = load_scope()
    if not scope:
        return False
    allowed = scope.get("allowed", [])
    # Simple substring / exact match for v1
    return any(target.startswith(a) or a in target for a in allowed)


def require_scope(target: str) -> str:
    """Ensure target is in scope. Offer to create/update scope.json if needed."""
    scope = load_scope()
    if not scope:
        console.print("[yellow]No scope.json found.[/yellow]")
        if Confirm.ask(f"Create scope.json and allow '{target}'?", default=True):
            create_scope(target)
            return ""
        return "BLOCKED: Scope required for active tools."

    if not in_scope(target):
        console.print(f"[yellow]{target} is not in the current scope.[/yellow]")
        if Confirm.ask(f"Add '{target}' to scope.json?", default=True):
            add_to_scope(target)
            return ""
        return f"BLOCKED: {target} is not in scope."

    return ""


def create_scope(first_target: str):
    name = Prompt.ask("Engagement name", default="engagement")
    scope = {
        "name": name,
        "allowed": [first_target],
        "created": datetime.now(timezone.utc).isoformat(),
        "notes": "Created interactively by AI Kali agent. Only authorized targets."
    }
    Path(SCOPE_FILE).write_text(json.dumps(scope, indent=2))
    console.print(f"[green]Created {SCOPE_FILE} with target {first_target}[/green]")


def load_state() -> Dict:
    path = Path(STATE_FILE)
    if not path.exists():
        return {"hosts": {}, "scans": []}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {"hosts": {}, "scans": []}


def save_state(state: Dict):
    Path(STATE_FILE).write_text(json.dumps(state, indent=2))


def record_scan(target: str, output: str, flags: str = ""):
    """Store nmap-style results so later phases can use them."""
    state = load_state()
    entry = {
        "target": target,
        "flags": flags,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "output_preview": output[:2000],
    }
    state.setdefault("scans", []).append(entry)
    # Simple host tracking
    hosts = state.setdefault("hosts", {})
    if target not in hosts:
        hosts[target] = {"ports": [], "notes": []}
    hosts[target]["last_scan"] = entry["timestamp"]
    save_state(state)
    console.print(f"[dim]Recorded scan of {target} in state.json[/dim]")
    scope = load_scope() or {"name": "engagement", "allowed": []}
    if target not in scope.get("allowed", []):
        scope.setdefault("allowed", []).append(target)
        Path(SCOPE_FILE).write_text(json.dumps(scope, indent=2))
        console.print(f"[green]Added {target} to scope.[/green]")


def load_phase() -> int:
    path = Path(PHASE_FILE)
    if not path.exists():
        return 1
    try:
        return int(json.loads(path.read_text()).get("current", 1))
    except Exception:
        return 1


def set_phase(n: int):
    data = {"current": n, "name": PHASES[n - 1] if 1 <= n <= len(PHASES) else "unknown"}
    Path(PHASE_FILE).write_text(json.dumps(data, indent=2))
    console.print(f"[cyan]Phase → {data['name']}[/cyan]")


def advance_phase():
    current = load_phase()
    if current < len(PHASES):
        set_phase(current + 1)
    else:
        console.print("[green]All phases complete.[/green]")


def is_safe_command(cmd: str) -> bool:
    cmd_lower = cmd.lower()
    return not any(pat in cmd_lower for pat in DANGEROUS_PATTERNS)


def run_tool(name: str, args: Dict[str, Any]) -> str:
    """Execute a tool and return its output."""
    try:
        if name == "nmap_scan":
            target = args.get("target", "")
            flags = args.get("flags", "-sV -T4 -F")
            blocked = require_scope(target)
            if blocked:
                return blocked
            if not Confirm.ask(f"Run nmap {flags} against {target}?", default=False):
                return "Scan cancelled by user."
            cmd = f"nmap {flags} {target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
            output = result.stdout + result.stderr
            record_scan(target, output, flags)
            return output

        elif name == "gobuster_dir":
            url = args.get("url", "")
            wordlist = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            blocked = require_scope(url)
            if blocked:
                return blocked
            if not Confirm.ask(f"Run gobuster against {url}?", default=False):
                return "Scan cancelled by user."
            cmd = f"gobuster dir -u {url} -w {wordlist} -q"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
            return result.stdout + result.stderr

        elif name == "nikto_scan":
            target = args.get("target", "")
            blocked = require_scope(target)
            if blocked:
                return blocked
            if not Confirm.ask(f"Run nikto against {target}?", default=False):
                return "Scan cancelled by user."
            cmd = f"nikto -h {target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
            return result.stdout + result.stderr

        elif name == "run_command":
            command = args.get("command", "")
            if not is_safe_command(command):
                return "Command blocked: potentially dangerous."
            if not Confirm.ask(f"Run command: {command}?", default=False):
                return "Command cancelled by user."
            result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
            return result.stdout + result.stderr

        else:
            return f"Unknown tool: {name}"

    except subprocess.TimeoutExpired:
        return "Tool timed out."
    except Exception as e:
        return f"Error running tool: {str(e)}"


def chat_with_ollama(messages: List[Dict], model: str = DEFAULT_MODEL) -> Dict:
    """Send messages to Ollama and return the response."""
    payload = {
        "model": model,
        "messages": messages,
        "tools": TOOLS,
        "stream": False,
    }
    try:
        resp = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=120)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        console.print(f"[red]Ollama error: {e}[/red]")
        return {}


def main():
    console.print("[bold green]AI Kali Agent[/bold green]")
    console.print("Local tool-calling assistant for authorized penetration testing.\n")

    scope = load_scope()
    if scope:
        console.print(f"[green]Scope loaded:[/green] {scope.get('name', 'unnamed')}")
        console.print(f"Allowed: {scope.get('allowed', [])}\n")
    else:
        console.print("[yellow]No scope.json found. It will be created the first time an active tool is requested.[/yellow]\n")

    current = load_phase()
    console.print(f"[cyan]Current phase: {PHASES[current - 1]}[/cyan]")
    console.print("[dim]Type 'next phase' to advance, or just work and the agent will stay in order.[/dim]\n")

    try:
        requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
    except Exception:
        console.print("[red]Ollama does not appear to be running. Start it with: ollama serve[/red]")
        sys.exit(1)

    messages: List[Dict[str, Any]] = [
        {
            "role": "system",
            "content": (
                "You are an AI red team assistant on a Kali workstation. "
                "You MUST follow these phases in order and never skip ahead:\n"
                "1. Pre-Engagement & Scoping — confirm rules of engagement and allowed targets.\n"
                "2. Reconnaissance (OSINT) — passive information gathering only.\n"
                "3. Scanning & Enumeration — active probing of in-scope targets.\n"
                "4. Vulnerability Analysis — map findings to known weaknesses.\n"
                "5. Exploitation — only after confirmation and only to prove the issue.\n"
                "6. Post-Exploitation & Privilege Escalation — document access obtained.\n"
                "7. Reporting & Remediation — clear findings, impact, and fixes.\n\n"
                "Before any active tool, confirm the target is in scope. "
                "State the current phase at the start of each major action. "
                "Prefer passive techniques until the scanning phase. "
                "Only operate against authorized targets."
            ),
        }
    ]

    while True:
        try:
            user_input = Prompt.ask("\n[bold cyan]You[/bold cyan]")
            if user_input.lower() in ("exit", "quit", "q"):
                break
            if user_input.lower() in ("next phase", "advance", "next"):
                advance_phase()
                continue

            messages.append({"role": "user", "content": user_input})

            # Agentic loop
            for _ in range(8):  # max tool rounds
                response = chat_with_ollama(messages)
                if not response:
                    break

                message = response.get("message", {})
                messages.append(message)

                # Check for tool calls
                tool_calls = message.get("tool_calls", [])
                if not tool_calls:
                    content = message.get("content", "")
                    if content:
                        console.print(Markdown(content))
                    break

                # Execute tools
                for tool_call in tool_calls:
                    fn = tool_call.get("function", {})
                    name = fn.get("name")
                    args_str = fn.get("arguments", "{}")
                    try:
                        args = json.loads(args_str) if isinstance(args_str, str) else args_str
                    except json.JSONDecodeError:
                        args = {}

                    console.print(f"[yellow]Calling tool: {name}[/yellow]")
                    result = run_tool(name, args)
                    console.print(f"[dim]{result[:500]}...[/dim]" if len(result) > 500 else f"[dim]{result}[/dim]")

                    messages.append({
                        "role": "tool",
                        "content": result,
                        "tool_call_id": tool_call.get("id", name),
                    })

        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted.[/yellow]")
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")


if __name__ == "__main__":
    main()
