---
change: state-plainly-that-the-protocol-has-no-forward-secrecy
artifact: testing
---

# Testing

Documentation-only change; no build or test impact.

- Crypto claims verified against `ts-algochat/src/crypto/encryption.ts`:
  sender generates the ephemeral pair (line 59), recipient decryption
  `x25519ECDH(recipientPrivateKey, envelope.ephemeralPublicKey)` (line 161),
  sender-copy path mirrors it (line 182)
- Repo-wide grep confirms no forward-secrecy claims remain outside the
  corrected negations and pointers to `PROTOCOL.md` §11.1
- `fledge trust verify` passes (validate lane: 5 protocol documents,
  6 implementations)
