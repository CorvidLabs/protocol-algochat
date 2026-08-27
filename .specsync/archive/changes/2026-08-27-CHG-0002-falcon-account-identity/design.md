---
change: CHG-0002-falcon-account-identity
artifact: design
---

# Design

## Layers

| Layer | Primitive | Falcon change? |
| --- | --- | --- |
| Account authorization | Ed25519 `sig` or Falcon-1024 `pqsig` | Additive |
| Encryption seed | 32-byte mnemonic entropy → HKDF → X25519 | Wording only |
| Envelope | `0x01` / `0x02` in the payment note | None |
| Key discovery | Sender of a valid payment + envelope `sender_pubkey` | Authorship = tx sig |

## Create vs import

- **Create:** implementations MAY generate Falcon-1024 by default.
- **Import without a scheme:** MUST recover the Ed25519 account (same 58-char
  address as Pera and AlgoChat v1.1).
- **Import with Falcon:** MUST pass an explicit scheme. Same words, different
  address.
- **Rekey:** an existing Ed25519 account MAY set its auth address to a Falcon
  address; the public address stays the same; later payments MUST be
  Falcon-signed and pay the Falcon fee.

## Out of scope

- Hybrid PQ-KEM envelopes (ML-KEM). That is a later protocol id.
- Raising the 1,024-byte envelope budget even if consensus v42 allows larger
  notes. Envelopes stay specified against 1,024 bytes.
- Native PQ multisig.
