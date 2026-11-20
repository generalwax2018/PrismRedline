#!/usr/bin/env python3
"""
PrismRedline - Local AI red team assistant that follows the classic pentesting phases.
Runs against Ollama on your local GPU (RTX 3090 recommended).
"""

import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from rich.console import Console
from rich.markdown import Markdown
from rich.prompt import Prompt, Confirm

console = Console()

# Configuration (overridable via environment)
OLLAMA_URL = os.environ.get("PRISM_OLLAMA_URL", "http://127.0.0.1:11434")
DEFAULT_MODEL = os.environ.get("PRISM_MODEL", "qwen3:14b")

BASE = Path(__file__).parent
SCOPE_FILE = BASE / "scope.json"
PHASE_FILE = BASE / "phase.json"
STATE_FILE = BASE / "state.json"  # hosts, ports, reachability
EVIDENCE_DIR = BASE / "evidence"

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
            "name": "linpeas",
            "description": "Run LinPEAS privilege escalation enumeration on a Linux host you already have access to. Phase 6.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Host where you have a shell or can execute"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "winpeas",
            "description": "Run WinPEAS privilege escalation enumeration on a Windows host you already have access to. Phase 6.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Host where you have a shell or can execute"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "netexec_smb",
            "description": "Run NetExec (nxc) SMB enumeration against an in-scope target. Traditional AD discovery. Phase 3-4.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP or hostname"},
                    "username": {"type": "string", "description": "Optional username"},
                    "password": {"type": "string", "description": "Optional password"},
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "bloodhound_collect",
            "description": "Collect BloodHound data (SharpHound/bloodhound-python) from an in-scope AD environment. Phase 4.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain to collect"},
                    "dc": {"type": "string", "description": "Domain controller IP"},
                },
                "required": ["domain"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cheatsheet",
            "description": "Look up a local cheatsheet (nmap, privesc, ad) for traditional commands.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "nmap, privesc, or ad"},
                },
                "required": ["name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": "Run an arbitrary shell command on the Kali workstation. Blocked for destructive patterns; always requires confirmation. Use sparingly.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "The shell command to run"},
                },
                "required": ["command"],
            },
        },
    },
]

DANGEROUS_PATTERNS = [
    "rm -rf", "dd if=", "mkfs", "format", ":(){ :|:& };:",
    "msfconsole", "exploit", "payload", "hydra", "john",
    "> /dev/sd", "shutdown", "reboot", "init 0",
]


# --------------------------------------------------------------------------- #
# Scope handling
# --------------------------------------------------------------------------- #
def load_scope() -> Optional[Dict]:
    if not SCOPE_FILE.exists():
        return None
    try:
        return json.loads(SCOPE_FILE.read_text())
    except Exception:
        return None


def _host_from_target(target: str) -> str:
    """Normalize a target (URL, IP:port, host) down to a bare host/IP."""
    target = target.strip()
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    # strip a trailing :port if host part isn't an IPv6 literal
    if target.count(":") == 1:
        return target.split(":", 1)[0]
    return target


def _matches_entry(host: str, entry: str) -> bool:
    """Match a host/IP against a scope entry (CIDR, single IP, or hostname)."""
    entry = entry.strip()
    # CIDR or IP range
    try:
        net = ipaddress.ip_network(entry, strict=False)
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False  # host is a name, entry is a network -> no match
    except ValueError:
        pass
    # Exact IP equality
    try:
        if ipaddress.ip_address(entry) == ipaddress.ip_address(host):
            return True
    except ValueError:
        pass
    # Hostname: exact or subdomain match (case-insensitive)
    h, e = host.lower(), entry.lower()
    return h == e or h.endswith("." + e)


def in_scope(target: str) -> bool:
    scope = load_scope()
    if not scope:
        return False
    host = _host_from_target(target)
    return any(_matches_entry(host, a) for a in scope.get("allowed", []))


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
        "allowed": [_host_from_target(first_target)],
        "created": datetime.now(timezone.utc).isoformat(),
        "notes": "Created interactively by PrismRedline. Only authorized targets.",
    }
    SCOPE_FILE.write_text(json.dumps(scope, indent=2))
    console.print(f"[green]Created {SCOPE_FILE.name} with target {first_target}[/green]")


def add_to_scope(target: str):
    scope = load_scope() or {"name": "engagement", "allowed": []}
    entry = _host_from_target(target)
    if entry not in scope.get("allowed", []):
        scope.setdefault("allowed", []).append(entry)
        SCOPE_FILE.write_text(json.dumps(scope, indent=2))
        console.print(f"[green]Added {entry} to scope.[/green]")


# --------------------------------------------------------------------------- #
# State / evidence handling
# --------------------------------------------------------------------------- #
def load_state() -> Dict:
    if not STATE_FILE.exists():
        return {"hosts": {}, "scans": []}
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {"hosts": {}, "scans": []}


def save_state(state: Dict):
    STATE_FILE.write_text(json.dumps(state, indent=2))


def _parse_nmap_ports(output: str) -> List[Dict[str, str]]:
    """Pull open ports/services out of nmap text output."""
    ports = []
    for line in output.splitlines():
        m = re.match(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(.*)$", line.strip())
        if m and m.group(3) in ("open", "open|filtered"):
            ports.append({"port": m.group(1), "proto": m.group(2), "service": m.group(4).strip()})
    return ports


def save_evidence(tool: str, target: str, output: str) -> Path:
    """Persist raw tool output so the report has an auditable evidence trail."""
    EVIDENCE_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", f"{tool}_{_host_from_target(target) or 'local'}_{ts}")
    path = EVIDENCE_DIR / f"{safe}.txt"
    path.write_text(output)
    return path


def record_scan(target: str, output: str, flags: str = "", tool: str = "nmap"):
    """Store results so later phases and the report can use them."""
    state = load_state()
    evidence_path = save_evidence(tool, target, output)
    entry = {
        "tool": tool,
        "target": target,
        "flags": flags,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence": str(evidence_path.relative_to(BASE)),
        "output_preview": output[:2000],
    }
    state.setdefault("scans", []).append(entry)

    host = _host_from_target(target)
    hosts = state.setdefault("hosts", {})
    if host not in hosts:
        hosts[host] = {"ports": [], "notes": []}
    hosts[host]["last_scan"] = entry["timestamp"]
    if tool == "nmap":
        found = _parse_nmap_ports(output)
        if found:
            hosts[host]["ports"] = found
    save_state(state)
    console.print(f"[dim]Recorded {tool} scan of {host} (evidence: {entry['evidence']})[/dim]")


# --------------------------------------------------------------------------- #
# Phase handling
# --------------------------------------------------------------------------- #
def load_phase() -> int:
    if not PHASE_FILE.exists():
        return 1
    try:
        return int(json.loads(PHASE_FILE.read_text()).get("current", 1))
    except Exception:
        return 1


def set_phase(n: int):
    data = {"current": n, "name": PHASES[n - 1] if 1 <= n <= len(PHASES) else "unknown"}
    PHASE_FILE.write_text(json.dumps(data, indent=2))
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


# --------------------------------------------------------------------------- #
# Tool execution
# --------------------------------------------------------------------------- #
def _run(cmd: str, timeout: int) -> str:
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return (result.stdout or "") + (result.stderr or "")


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
            cmd = f"nmap {flags} {shlex.quote(target)}"
            output = _run(cmd, 300)
            record_scan(target, output, flags, tool="nmap")
            return output

        elif name == "gobuster_dir":
            url = args.get("url", "")
            wordlist = args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            blocked = require_scope(url)
            if blocked:
                return blocked
            if not Confirm.ask(f"Run gobuster against {url}?", default=False):
                return "Scan cancelled by user."
            cmd = f"gobuster dir -u {shlex.quote(url)} -w {shlex.quote(wordlist)} -q"
            output = _run(cmd, 300)
            record_scan(url, output, tool="gobuster")
            return output

        elif name == "nikto_scan":
            target = args.get("target", "")
            blocked = require_scope(target)
            if blocked:
                return blocked
            if not Confirm.ask(f"Run nikto against {target}?", default=False):
                return "Scan cancelled by user."
            cmd = f"nikto -h {shlex.quote(target)}"
            output = _run(cmd, 300)
            record_scan(target, output, tool="nikto")
            return output

        elif name == "linpeas":
            target = args.get("target", "")
            blocked = require_scope(target)
            if blocked:
                return blocked
            console.print(
                "[yellow]Note: LinPEAS enumerates the host it runs ON. Run this on the "
                "foothold host, not the Kali box, unless Kali itself is the target.[/yellow]"
            )
            if not Confirm.ask(f"Download + run LinPEAS locally (context: {target})?", default=False):
                return "Cancelled."
            # Download to a file first so it is auditable rather than piping curl|bash.
            lp = EVIDENCE_DIR / "linpeas.sh"
            EVIDENCE_DIR.mkdir(exist_ok=True)
            dl = _run(
                "curl -sL -o " + shlex.quote(str(lp)) +
                " https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh",
                120,
            )
            if not lp.exists() or lp.stat().st_size == 0:
                return f"Failed to download LinPEAS. {dl}"
            output = _run(f"bash {shlex.quote(str(lp))}", 600)
            record_scan(target, output, tool="linpeas")
            return output

        elif name == "winpeas":
            target = args.get("target", "")
            blocked = require_scope(target)
            if blocked:
                return blocked
            if not Confirm.ask(f"Record WinPEAS step for {target}?", default=False):
                return "Cancelled."
            return ("WinPEAS: transfer winPEASx64.exe to the host and execute. "
                    "Record output in evidence/ and the host steps.")

        elif name == "netexec_smb":
            target = args.get("target", "")
            blocked = require_scope(target)
            if blocked:
                return blocked
            if not Confirm.ask(f"Run NetExec SMB against {target}?", default=False):
                return "Cancelled."
            user = args.get("username", "")
            password = args.get("password", "")
            auth = f"-u {shlex.quote(user)} -p {shlex.quote(password)}" if user else ""
            cmd = f"nxc smb {shlex.quote(target)} {auth}".strip()
            output = _run(cmd, 180)
            record_scan(target, output, tool="netexec")
            return output

        elif name == "bloodhound_collect":
            domain = args.get("domain", "")
            dc = args.get("dc", "")
            blocked = require_scope(dc or domain)
            if blocked:
                return blocked
            if not Confirm.ask(f"Collect BloodHound data for {domain}?", default=False):
                return "Cancelled."
            if dc:
                cmd = f"bloodhound-python -d {shlex.quote(domain)} -u '' -p '' -ns {shlex.quote(dc)} -c all"
            else:
                cmd = f"bloodhound-python -d {shlex.quote(domain)} -c all"
            output = _run(cmd, 600)
            record_scan(dc or domain, output, tool="bloodhound")
            return output

        elif name == "cheatsheet":
            sheet = args.get("name", "").lower()
            path = Path("cheatsheets") / f"{sheet}.md"
            if not path.exists():
                return f"No cheatsheet named '{sheet}'. Available: nmap, privesc, ad"
            return path.read_text()

        elif name == "run_command":
            command = args.get("command", "")
            if not is_safe_command(command):
                return "Command blocked: potentially dangerous pattern detected."
            if not Confirm.ask(f"Run command: {command}?", default=False):
                return "Command cancelled by user."
            return _run(command, 120)

        else:
            return f"Unknown tool: {name}"

    except subprocess.TimeoutExpired:
        return "Tool timed out."
    except FileNotFoundError as e:
        return f"Tool not installed or not on PATH: {e}"
    except Exception as e:
        return f"Error running tool: {str(e)}"


# --------------------------------------------------------------------------- #
# Ollama
# --------------------------------------------------------------------------- #
def chat_with_ollama(messages: List[Dict], model: str = DEFAULT_MODEL) -> Dict:
    """Send messages to Ollama and return the response."""
    payload = {"model": model, "messages": messages, "tools": TOOLS, "stream": False}
    try:
        resp = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=300)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        console.print(f"[red]Ollama error: {e}[/red]")
        return {}


SYSTEM_PROMPT = (
    "You are an AI red team assistant. "
    "Follow the foundational phases in order before moving to the next:\n"
    "1. Pre-Engagement & Scoping\n"
    "2. Reconnaissance\n"
    "3. Scanning & Enumeration\n"
    "4. Vulnerability Analysis\n"
    "5. Exploitation\n"
    "6. Post-Exploitation & Privilege Escalation\n"
    "7. Reporting & Remediation\n\n"
    "Complete the objectives of the current phase before advancing. "
    "If something does not work, return to an earlier phase and gather more information. "
    "Traditional tools support the phases but do not replace the sequence. "
    "Only operate against authorized targets."
)


def add_step(target: str, title: str, detail: str, commands: List[str] = None):
    """Record a step against a host for the report."""
    state = load_state()
    hosts = state.setdefault("hosts", {})
    host = hosts.setdefault(target, {"ports": [], "notes": [], "steps": []})
    host.setdefault("steps", []).append({
        "title": title,
        "detail": detail,
        "commands": commands or [],
    })
    save_state(state)


def discover_hosts(target: str):
    """Phase 3: host discovery + basic port scan, record results, advance when done."""
    from cli import status
    blocked = require_scope(target)
    if blocked:
        console.print(f"[red]{blocked}[/red]")
        return

    status.info(f"Phase 3 — Discovering hosts in {target}")
    cmd = f"nmap -sn {target}"
    status.update("Running host discovery...")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=180)
    output = result.stdout + result.stderr
    record_scan(target, output, "-sn")
    add_step(target, "Host Discovery", "nmap -sn to identify live hosts", [cmd])

    live = []
    for line in output.splitlines():
        if "Nmap scan report for" in line:
            host = line.split("for")[-1].strip()
            live.append(host)

    status.info(f"Found {len(live)} live host(s)")
    if not live:
        status.done("No live hosts")
        return

    for i, host in enumerate(live, 1):
        status.progress(i, len(live), prefix=f"Scanning {host} ")
        pcmd = f"nmap -sV -T4 -F {host}"
        pres = subprocess.run(pcmd, shell=True, capture_output=True, text=True, timeout=120)
        pout = pres.stdout + pres.stderr
        record_scan(host, pout, "-sV -T4 -F")
        add_step(host, "Service Enumeration", "Top ports and versions", [pcmd])

    status.done("Scanning complete")
    if load_phase() <= 3:
        set_phase(4)
        status.info("Advanced to Phase 4 — Vulnerability Analysis")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="PrisimRedline")
    parser.add_argument("--target", help="CIDR or host to start phased discovery against")
    args = parser.parse_args()

    console.print("[bold green]PrisimRedline[/bold green]")
    console.print("Local AI red team assistant\n")

    if args.target:
        if not load_scope():
            create_scope(args.target)
        elif not in_scope(args.target):
            if Confirm.ask(f"Add {args.target} to scope?", default=True):
                add_to_scope(args.target)
        set_phase(3)
        discover_hosts(args.target)
        console.print("\n[green]Discovery finished. Continuing to chat.[/green]\n")

    scope = load_scope()
    if scope:
        console.print(f"[green]Scope:[/green] {scope.get('name', 'unnamed')} — {scope.get('allowed', [])}")
    current = load_phase()
    console.print(f"[cyan]Phase: {PHASES[current - 1]}[/cyan]")
    console.print("[dim]Type 'next phase' to advance, 'exit' to quit.[/dim]\n")

    try:
        requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
    except Exception:
        console.print("[yellow]Ollama not detected. Chat features limited.[/yellow]")

    messages: List[Dict[str, Any]] = [{"role": "system", "content": SYSTEM_PROMPT}]

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

                tool_calls = message.get("tool_calls", [])
                if not tool_calls:
                    content = message.get("content", "")
                    if content:
                        console.print(Markdown(content))
                    break

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
                    preview = f"{result[:500]}..." if len(result) > 500 else result
                    console.print(f"[dim]{preview}[/dim]")

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
