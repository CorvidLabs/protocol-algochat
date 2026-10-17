---
change: add-offline-algochat-v1-2-envelope-boundary-research-probe
artifact: plan
---

# Plan

## Approach

Use installed Node stdlib X25519, HKDF-SHA256 and ChaCha20-Poly1305 against the
published deterministic vectors. Separate valid decrypts, authentication
rejections, setup errors, parsing and counter-rule failures. Measure only the
representable counter domain without choosing rollover or a new wire rule.

## Steps

1. Read protocol, implementation pseudocode and test vectors at the pinned base.
2. Add one deterministic offline probe, its focused tests and an audit note.
3. Independently review claims against actual observations.
4. Reproduce the span bug before correction; verify sender/recipient wrap
   isolation and patterned PSK rejection after real AEAD setup.
5. Record final hashes, full reports, 21 tests and 34 control outputs.
6. Qualify the committed range, record truthful unsigned agent provenance and
   publish only a coordinator-reviewed draft. Human review/finalization pending.

## Out of scope

No client/Raven changes, new dependencies, network, wallets, signatures, chain
transactions, durable replay state, PQ handshake, fragmentation, counter wrap,
policy changes, human intent capture or lifecycle acceptance.

## Risks

Reference tests can overstate client security or mistake setup failures for
authentication rejection. Positive exact-plaintext checks, separate setup flags
and corruption controls distinguish those paths. Published test keys are public
vectors; private/symmetric values are omitted from emitted JSON. This is not an
independent crypto-library, ACVP, side-channel or production security audit.

## Constraints consulted

Repository and parent AGENTS, PROTOCOL, TEST-VECTORS, IMPLEMENTATION, SECURITY,
docs/HLD, existing native validation and unchanged Trust/Attest policies.
