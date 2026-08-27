---
change: document-falcon-1024-algorand-account-identity-as-protocol-1-2-without-changing-0x01-0x02-envelopes
artifact: context
---

# Context

Algorand consensus v42 (algod 5.0.0, August 2026) added native Falcon-1024
accounts authorized by a `pqsig` envelope. The same 25-word mnemonic remains
the master secret. Ed25519 and Falcon-1024 addresses derived from one mnemonic
are different. Falcon-signed payments pay a 3× minimum fee (base plus a 2×
scheme contribution).

AlgoChat v1.1 treats identity as an Ed25519 Algorand account and derives
X25519 encryption keys from `algorand_account_private_key[0:32]`. That slice
is mnemonic entropy for Ed25519 and is **wrong** if taken from a Falcon
secret key (2305 bytes). Implementations that generate Falcon wallets need
the spec to name the encryption seed as mnemonic entropy, not as a signing-key
prefix.

This change is documentation-only. Envelope bytes for `0x01` and `0x02` do
not change. Existing test vectors remain canonical. Key-exchange quantum
resistance is still PSK (`0x02`) or a future hybrid KEM; Falcon does not
replace that.

## Constraints

- Do not alter test-vector inputs or outputs.
- Do not claim message contents are quantum-safe because the account is Falcon.
- Import of a classical 25-word mnemonic MUST still recover the Ed25519
  address unless the caller opts into Falcon derivation or rekeys.
- New-account generation MAY default to Falcon; that is an implementation
  choice, recorded here as allowed.
