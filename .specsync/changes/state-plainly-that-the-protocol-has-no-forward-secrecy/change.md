---
id: state-plainly-that-the-protocol-has-no-forward-secrecy
state: implementing
type: bug_fix
base_commit: 1d9b77ef9372df8817ff05b2f27dd2118b186d4b
---

# State plainly that the protocol has no forward secrecy

## Intent

State plainly that the protocol has no forward secrecy

## Affected Canonical Specs

- `protocol`

## Acceptance Criteria

- PROTOCOL.md, SECURITY.md, README.md, and index.html no longer claim forward secrecy; SECURITY.md and README state the property is not provided and point to PROTOCOL.md 11.1; fledge trust verify passes

## No-spec Rationale

Documentation-only correction of a false forward-secrecy claim; no wire-format, code, or spec-module changes
