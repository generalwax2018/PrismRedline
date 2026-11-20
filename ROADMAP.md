# Roadmap

PrismRedline is not trying to be the most autonomous or the tool with the most wrappers.  
The goal is the assistant you can run on a real engagement and defend in the report:  
scope-first, phase-disciplined, evidence-producing, and air-gappable.

## Near term
- [x] MCP client layer (adapter in place; wire external servers next)
- [x] Real policy engine (phase-aware gating in `policy.py`)
- [x] Findings as first-class (severity, CVSS, retest field)
- [x] Phase checklist in CLI
- [x] Report HTML export
- [x] Example lab template
- [x] Guardrail test suite (`tests/test_guardrails.py`)

## Mid term
- **Report as the product** — HTML/PDF export, CVSS, retest tracking. Clients pay for the deliverable.
- **Reproducible examples** — Published runs against known lab targets with full evidence and reports.
- **Guardrail eval suite** — Tests that attempt out-of-scope actions and assert refusal.
- **Pluggable model backends** — Keep local-by-default; allow optional frontier models for planning only.

## Longer term
- Interactive GUI (approve/deny, view evidence, drive the engagement).
- Optional verified-team distribution controls.

The differentiation is the methodology and the audit trail, not raw autonomy.
