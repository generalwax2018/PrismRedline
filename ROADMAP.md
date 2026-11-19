# Roadmap

Rough direction, not a commitment. Issues labeled `good first issue` are the
easiest entry points.

## Near term (0.2.x)
- Single source of truth for tools: have `agent.py` build its tool list and
  `setup.sh` build its install list from `tools.yaml`.
- More unit tests: report rendering, nmap parsing, phase transitions.
- Config file / `.env` support for model, Ollama URL, default wordlists.
- Structured logging to a session log in addition to `evidence/`.

## Mid term
- More tool wrappers from `tools.yaml` (masscan, ffuf, searchsploit, nuclei,
  enum4linux-ng), each behind the scope + confirmation gates.
- Richer `state.json` schema (per-host services, creds vault reference, findings).
- Report export to HTML/PDF in addition to Markdown.

## Longer term / ideas
- Optional integration with `mcp-kali-server` for a larger tool set.
- Pluggable model backends beyond Ollama.
- Web GUI that can drive scans, not just display state.

Have an idea? Open a feature request.
