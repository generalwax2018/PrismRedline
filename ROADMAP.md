# Roadmap

PrismRedline is not trying to be the most autonomous or the tool with the most wrappers.  
The goal is the assistant you can run on a real engagement and defend in the report:  
scope-first, phase-disciplined, evidence-producing, and air-gappable.

## Near term
- **MCP client layer** — Front an MCP tool server (mcp-kali-server or similar) with the existing scope + confirmation + phase gates. Breadth without losing the safety model.
- **Real policy engine** — Move beyond substring filters. Binary allowlist, phase-aware tool gating, dry-run mode, and a tamper-evident evidence log.
- **Findings as first-class** — Structured findings with severity, evidence links, and remediation. Report pulls from them cleanly.
- **Phase checklist in CLI/GUI** — Show what is done vs. remaining before advancing.

## Mid term
- **Report as the product** — HTML/PDF export, CVSS, retest tracking. Clients pay for the deliverable.
- **Reproducible examples** — Published runs against known lab targets with full evidence and reports.
- **Guardrail eval suite** — Tests that attempt out-of-scope actions and assert refusal.
- **Pluggable model backends** — Keep local-by-default; allow optional frontier models for planning only.

## Longer term
- Interactive GUI (approve/deny, view evidence, drive the engagement).
- Optional verified-team distribution controls.

The differentiation is the methodology and the audit trail, not raw autonomy.
