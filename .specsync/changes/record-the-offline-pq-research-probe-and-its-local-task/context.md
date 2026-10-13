---
change: record-the-offline-pq-research-probe-and-its-local-task
artifact: context
---

# Context

Leif requested a Raven/AlgoChat PQ research spike and local audit work. The
published bounded research candidate adds an offline primitive harness and
`pq-spike = "node scripts/pq-spike.mjs"` to `fledge.toml`; its two proposal
documents keep research/unshipped status explicit. This packet describes that
existing scope and supplies its missing native draft declaration. It proposes
no production cryptography, protocol version, wire format, identity,
authentication, recovery or forward-secrecy change.

The exact declared paths are `scripts/pq-spike.mjs`, `fledge.toml`,
`docs/proposals/pq-audit-spike.md` and
`docs/proposals/post-quantum-pair-secret.md`. The current Trust workflow already
selects SpecSync 6.1.0; it needs no additional edit for this packet. All canonical
protocol obligations, fixed vectors, accepted/historical records and global
metadata remain unchanged. The five existing lifecycle audit findings are
baseline debt, not claims resolved by this new draft.

The installed-runtime probe uses Node/OpenSSL only, generates temporary keys,
compares boolean secret equality and prints metadata/limits. ML-KEM parameter
sizes are measured; 48-byte sender wrap and per-note framing costs are explicit
research assumptions. No new account, install, wallet/signing action, chain
transaction, cloud quantum job, outside reviewer contact or security acceptance
is part of this scope.
