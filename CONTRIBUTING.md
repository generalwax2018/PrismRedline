# Contributing to PrismRedline

Thanks for your interest in contributing! PrismRedline is a local AI red-team
assistant that follows the classic pentesting phases.

## Ground rules

- This is an **authorized-testing tool**. Contributions must not add
  functionality whose primary purpose is to evade authorization, exfiltrate
  data, or facilitate illegal access. Keep the scoping/consent gates intact.
- Be respectful — see `CODE_OF_CONDUCT.md`.

## Development setup

```bash
git clone https://github.com/generalwax2018/PrismRedline.git
cd PrismRedline
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -e ".[dev]"            # installs pytest + ruff
```

To run the agent you also need [Ollama](https://ollama.com/) with a
tool-calling model (e.g. `ollama pull qwen3:14b`). Most tests do **not**
require Ollama or Kali tools.

## Before you open a PR

```bash
ruff check .        # lint
pytest              # tests
```

- Add tests for new logic where practical. Pure logic (scope matching, report
  rendering, parsing) should be unit-tested without network or external tools.
- Keep changes focused; one logical change per PR.
- Update `README.md` / `CHANGELOG.md` if behavior or usage changes.
- If you add a tool, update `tools.yaml`, the agent's tool wiring, and
  `setup.sh` so they stay in sync.

## Commit style

Short imperative subject lines (e.g. "Add masscan tool wrapper"). Reference
issues with `#123` where relevant.

## Reporting bugs / requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/`.
