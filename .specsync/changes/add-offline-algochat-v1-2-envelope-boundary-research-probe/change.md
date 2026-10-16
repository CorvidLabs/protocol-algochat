---
id: add-offline-algochat-v1-2-envelope-boundary-research-probe
state: draft
type: refactor
base_commit: 9c854edfb069bddc8cfa76e160c3ba8daebcbb65
---

# Add offline AlgoChat v1.2 envelope boundary research probe

## Intent

Add offline AlgoChat v1.2 envelope boundary research probe

## Affected Canonical Specs

- None

## Acceptance Criteria

- Agent-proposed checks: compare published vectors with real local crypto; distinguish authentication rejection from setup or parsing failures; exercise both PSK decrypt roles and corrupted-wrap isolation; bound representable uint32 spans with failing-before evidence; preserve unresolved protocol decisions and explicit client-audit limits.

## No-spec Rationale

Research-only executable tests and audit notes for existing protocol documents; no canonical module spec or production wire/API behavior is changed. All normative decisions remain unresolved.
