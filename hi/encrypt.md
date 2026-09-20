---
hi: 1
families: [ENCRYPT]
---

# Encrypt

## Intent

The note is a private memo on a public payment. Only the two of us can read it, and a flipped bit should just fail.

## Criteria

- **ENCRYPT-1**  Only the sender and recipient can read a message.
  - **ENCRYPT-1.a**  If someone tampers with the bytes, decryption fails closed and never leaks plaintext.
