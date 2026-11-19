# PrismRedline

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![CI](https://github.com/generalwax2018/PrismRedline/actions/workflows/ci.yml/badge.svg)](https://github.com/generalwax2018/PrismRedline/actions/workflows/ci.yml)

Local AI-powered red team assistant that follows the classic pentesting phases. Runs on Ollama + real Kali tools.

> ⚠️ **Authorized use only.** This is an offensive security tool. Use it **only**
> against systems you own or have **explicit written permission** to test. You are
> responsible for complying with all applicable laws. See [`SECURITY.md`](SECURITY.md).

## Architecture

```
You (terminal)
    ↓
PrismRedline agent (Python)
    ↓
Ollama (local model on 3090)
    ↓
Tool wrappers (nmap, gobuster, nikto, sqlmap, etc.)
    ↓
Real tools running on Kali
```

## Quick Start (on Kali or Debian-based)

### 1. Install dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv nmap gobuster nikto sqlmap
# Optional but recommended
sudo apt install -y metasploit-framework enum4linux-ng hydra john
```

### 2. Install Ollama
```bash
curl -fsSL https://ollama.com/install.sh | sh
# Or follow the official Kali/manual method if you prefer
```

### 3. Pull a good tool-calling model
```bash
ollama pull qwen3:14b
# Alternatives that work well on 3090:
# ollama pull qwen3:32b
# ollama pull llama3.1:8b
```

### 4. Set up the agent
```bash
cd PrismRedline
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python agent.py
```

## Configuration
Override defaults via environment variables:
```bash
export PRISM_MODEL="qwen3:32b"              # default: qwen3:14b
export PRISM_OLLAMA_URL="http://127.0.0.1:11434"
```

## Safety Notes
- Active tools require scope. If `scope.json` is missing or the target is not listed, the agent will offer to create or update it interactively.
- Scope matching understands CIDR ranges (`10.0.0.0/8`), single IPs, and hostnames (with subdomain matching) — not loose substrings.
- High-risk tools still require human confirmation. The `run_command` tool is confirmation-gated and blocks destructive patterns.
- Raw tool output is saved under `evidence/` and summarized in `state.json` for the report's audit trail.
- `scope.json`, `state.json`, `phase.json`, `report.md`, and `evidence/` are git-ignored so live engagement data is never committed.
- Run only against systems you own or have explicit written permission to test.

## How this differs from Microsoft’s red team agents
- Local model + real Kali tools (not locked to Foundry/Azure)
- Explicit Pre-Engagement & Scoping gate before any active scan
- Full phase-aware workflow instead of limited recon/web or AI-safety probing
- You control the tools, the scope, and the session

## Report Generation

```bash
python report.py
```

Produces `report.md` from current scope, phase, and host state. Professional structure without vendor-specific content.

### CLI (default)
```bash
python agent.py
```
One-line status updates and text progress bars. No screen scrolling spam.

### GUI
```bash
python gui.py
```
Open http://127.0.0.1:8088 for phase, scope, and host summary.
- Wire this into the official `mcp-kali-server` for more tools.
- Add HexStrike AI for the full 150+ tool set.
- Build a simple web UI on top of the agent.
- Add structured reporting and session state.
