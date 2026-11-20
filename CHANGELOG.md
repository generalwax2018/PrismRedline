# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims
to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- Restored `report.py`. The module had regressed to a stub that called
  undefined `generate()` / `generate_html()`. Report generation works again.

## [0.1.0] - 2026-11-19

First public baseline.

### Added
- Phase-aware agentic workflow over Ollama with a scoping/consent gate.
- Tool wrappers: nmap, gobuster, nikto, NetExec (SMB), BloodHound collection,
  LinPEAS/WinPEAS, and a guarded `run_command`.
- CIDR / single-IP / hostname (with subdomain) scope matching via `ipaddress`.
- Evidence trail: raw tool output saved under `evidence/`, parsed nmap ports in
  `state.json`.
- Professional engagement report generator with MITRE ATT&CK mapping.
- CLI status mode and a simple FastAPI GUI.
- Packaging (`pyproject.toml`), unit tests, and CI.

### Fixed
- `agent.py` crashed on startup due to a missing `Console` import.
- `report.py` had no `generate()` function (dangling module-level code).
- Scope matching used loose substring comparison that never matched CIDRs and
  allowed false positives (e.g. `110.0.0.10` vs `10.0.0.0/8`).
- Shell arguments are now quoted (`shlex.quote`).

[Unreleased]: https://github.com/generalwax2018/PrismRedline/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/generalwax2018/PrismRedline/releases/tag/v0.1.0
