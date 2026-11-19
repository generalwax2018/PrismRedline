#!/usr/bin/env bash
# PrisimRedline tool bootstrap
# Installs traditional pentest tools on Debian-based systems (Kali, Parrot, Ubuntu, Debian).
# Safe to re-run.

set -e

echo "PrisimRedline — installing core tools"

if ! command -v apt-get >/dev/null 2>&1; then
  echo "apt-get not found. This installer supports Debian-based systems only."
  echo "On other distros, install nmap, gobuster, nikto, and searchsploit manually."
  exit 1
fi

sudo apt-get update
sudo apt-get install -y \
  nmap \
  gobuster \
  nikto \
  exploitdb \
  smbclient \
  python3 \
  python3-pip \
  python3-venv \
  curl \
  git

# NetExec (nxc) — preferred modern name
if ! command -v nxc >/dev/null 2>&1; then
  pip3 install --user netexec || true
fi

# Optional but useful
sudo apt-get install -y seclists 2>/dev/null || true

echo ""
echo "Core tools installed."
echo "LinPEAS/WinPEAS are fetched at runtime when needed."
echo "BloodHound collection uses bloodhound-python (pip install bloodhound if desired)."
echo ""
echo "Next: install Ollama and pull a model, then run the agent."
