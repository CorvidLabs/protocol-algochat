---
change: CHG-0002-falcon-account-identity
artifact: requirements
---

# Requirements

### REQ-protocol-001

The protocol SHALL derive X25519 encryption keys from the 32-byte entropy of
the 25-word Algorand mnemonic, independent of the authorizing signature
scheme.

Acceptance Criteria

- PROTOCOL.md §4.1 names mnemonic entropy as the IKM, and states that this
  is identical to Ed25519 `sk[0:32]` for classical accounts.
- TEST-VECTORS.md §1 still uses the same 32-byte seeds and expected outputs.

### REQ-protocol-002

The protocol SHALL allow an AlgoChat payment to be authorized by either an
Ed25519 `sig` or a Falcon-1024 `pqsig`, without changing the note envelope.

Acceptance Criteria

- PROTOCOL.md documents both schemes, address derivation at a high level,
  and that the same mnemonic yields different addresses per scheme.
- Envelope sections 5–8 are unchanged.

### REQ-protocol-003

A Falcon-1024 authorized AlgoChat payment SHALL use at least three times the
network minimum fee.

Acceptance Criteria

- PROTOCOL.md and README.md state Ed25519 ≈ 0.001 ALGO and Falcon-1024 ≈
  0.003 ALGO at the current 1,000 µAlgo min-fee.

### REQ-protocol-004

Key discovery SHALL treat the authorizing signature of the key-publish or
message payment as the binding between Algorand identity and the X25519
public key carried in the envelope. Optional Ed25519 signatures over the
X25519 key remain defined but MUST NOT be required for Falcon accounts.

Acceptance Criteria

- PROTOCOL.md §10.2 and SECURITY.md say authorship is the payment signature.
- IMPLEMENTATION.md does not require Ed25519 announce signatures for Falcon
  senders.

### REQ-protocol-005

The spec SHALL NOT claim that Falcon account identity makes message contents
quantum-resistant.

Acceptance Criteria

- SECURITY.md splits identity (Falcon) from key exchange (X25519 / PSK).
