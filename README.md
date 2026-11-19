# PrisimRedline
Local AI-powered red team assistant that follows the classic pentesting phases. Runs on Ollama + real Kali tools.

## Architecture

```
You (terminal)
    ↓
PrisimRedline agent (Python)
    ↓
Ollama (local model on 3090)
    ↓
Tool wrappers (nmap, gobuster, nikto, sqlmap, etc.)
    ↓
Real tools running on Kali
```

## Tool Inventory

See `tools.yaml` for the maintained list of traditional tools by phase.  
`setup.sh` installs the `core` tools. Optional and future tools can be added as the project grows.  
The goal is a clear, versioned inventory rather than an ad-hoc set of binaries.

Works on any system where the tools are available:
- Kali Linux
- Parrot OS
- Bare-bones Debian / Ubuntu (use the installer below)

### Optional tool bootstrap (Debian-based)
```bash
chmod +x setup.sh
./setup.sh
```
Installs nmap, gobuster, nikto, exploitdb, and related packages.  
Re-runnable. Does not replace a full pentest distro; it only adds what the agent calls.

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
cd PrisimRedline
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python agent.py
```

## Safety Notes
- Active tools require scope. If `scope.json` is missing or the target is not listed, the agent will offer to create or update it interactively.
- High-risk tools still require human confirmation.
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
