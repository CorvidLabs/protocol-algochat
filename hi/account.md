---
hi: 1
families: [ACCOUNT]
---

# Account

## Intent

I want new accounts to be Falcon if the chain supports it, without silently moving anyone who still has a classical 25-word phrase.

## Criteria

- **ACCOUNT-1**  A new identity can be a Falcon-1024 account that signs payments with pqsig.
  - **ACCOUNT-1.a**  Importing a 25-word phrase without naming a scheme recovers the classical Ed25519 account.
- **ACCOUNT-2**  Falcon identity does not make X25519 key exchange quantum-safe.
