# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project aims
to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1-beta] - 2026-11-24

### Added
- Dashboard (`gui.py`) now shows phase progress, hosts and services,
  severity-ranked findings, an ATT&CK reference table, and the scan/evidence log.
- Tests for `--target` discovery host parsing.

### Changed
- `--target` discovery now asks for confirmation, honors the phase gate,
  scans only in-scope hosts, and shell-quotes targets.
- Minimum supported Python is now 3.10 (CI covers 3.10-3.13).

### Fixed
- Packaging: `policy`, `findings` and `mcp_adapter` were missing from the
  installed modules, so `agent.py` failed to import when pip-installed.
- Discovery failed on hosts that nmap reports as `name (ip)`.
- Lint errors (ruff) and the CI Python 3.9 job.
## [0.1.0-beta] - 2026-11-20

First public beta.

### Added
- Phase gating is now enforced in `run_tool`: a tool is refused until its phase
  has been reached (the `policy.py` gate is wired into execution, not just tested).

### Fixed
- Report generation now writes UTF-8 explicitly, fixing a `UnicodeEncodeError`
  on platforms whose default encoding is not UTF-8 (e.g. Windows).
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

[Unreleased]: https://github.com/generalwax2018/PrismRedline/compare/v0.1.1-beta...HEAD
[0.1.1-beta]: https://github.com/generalwax2018/PrismRedline/compare/v0.1.0-beta...v0.1.1-beta
[0.1.0-beta]: https://github.com/generalwax2018/PrismRedline/compare/v0.1.0...v0.1.0-beta
[0.1.0]: https://github.com/generalwax2018/PrismRedline/releases/tag/v0.1.0
