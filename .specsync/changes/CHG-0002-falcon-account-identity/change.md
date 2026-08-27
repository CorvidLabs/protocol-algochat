---
id: CHG-0002-falcon-account-identity
state: implementing
type: documentation
base_commit: b917a3263deca3e7d15f341b96511b9a0029806b
---

# Document Falcon-1024 Algorand account identity as protocol 1.2 without changing 0x01/0x02 envelopes

## Intent

Document Falcon-1024 Algorand account identity as protocol 1.2 without changing 0x01/0x02 envelopes

## Affected Canonical Specs

- None

## Acceptance Criteria

- PROTOCOL.md, IMPLEMENTATION.md, SECURITY.md, TEST-VECTORS.md, and README.md describe Falcon-1024 as an Algorand authorizing signature for AlgoChat payments; encryption seed is 32-byte mnemonic entropy; 0x01/0x02 envelopes and existing test vectors are unchanged; Ed25519 import stays valid; Falcon minimum fee is 3x minFee; key discovery authorship is the payment signature; bun scripts/validate.ts passes.

## No-spec Rationale

This repository's normative contract is PROTOCOL.md (plus IMPLEMENTATION.md, SECURITY.md, and TEST-VECTORS.md). There is no specs/<module> canonical spec for the wire protocol.
