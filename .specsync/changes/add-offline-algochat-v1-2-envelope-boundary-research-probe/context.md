---
change: add-offline-algochat-v1-2-envelope-boundary-research-probe
artifact: context
---

# Context

Leif authorized focused project audits, local tests and reviewable PRs. This is
an offline research/reference harness for existing AlgoChat 1.2 documents, not a
production client implementation, Raven audit or protocol revision.

Independent review found missing PSK sender/patterned-note observations and an
upper uint32 measurement defect. Those were corrected with actual failing-before
boundary tests, 21 passing tests and 34 matched controls. A coordinator-only wording
correction additionally states both bounds of the 401-counter domain.

PR #21 retains ownership of ML-KEM and the unapproved pair-secret proposal.
Minimum note length, PSK check ordering, signature binding, Unicode example,
rollover and fragmentation decisions remain unresolved. Existing lifecycle
records, sources, policy and canonical protocol documents remain unchanged.
This complete definition is agent-proposed and UNAPPROVED, not human acceptance.
