---
change: state-plainly-that-the-protocol-has-no-forward-secrecy
artifact: context
---

# Context

The protocol spec and related project documents claimed AlgoChat provides
forward secrecy. Verified against `ts-algochat/src/crypto/encryption.ts`,
this is false: the sender's ephemeral public key travels in the on-chain
envelope, so any long-term private key (or the recovery phrase that derives
it) plus that permanently public value recovers every message key —
retroactively and irreversibly, since ciphertext stays publicly retrievable
on Algorand forever.

PR #10 (`docs/correct-forward-secrecy-claim`) corrected `PROTOCOL.md`.
Review by 0xGaspar (CHANGES_REQUESTED) flagged that `SECURITY.md`,
`README.md`, and `index.html` still asserted the false claim, which would
leave the repo self-contradictory on a security property.

Constraints: documentation-only; no protocol, wire-format, or code change;
the `ratchet_counter` wire field name is retained for compatibility; the
change is deliberately test-neutral.
