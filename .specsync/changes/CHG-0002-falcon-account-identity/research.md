---
change: CHG-0002-falcon-account-identity
artifact: research
---

# Research

## Protocol facts (Algorand v5 / consensus v42)

- Address: `SHA512-256("PQA" || scheme || salt || pk)` with scheme `f1` for
  Falcon-1024. Same 58-character encoding as Ed25519 addresses.
- Key seed: `SHA512-256("PQK" || scheme || 256-bit mnemonic entropy)`.
- Minimum fee: base + 2× base for Falcon-1024 = 3,000 µAlgo at a 1,000 µAlgo
  min-fee.
- SDKs with native `pqsig`: js-algorand-sdk 3.7.0, py-algorand-sdk 2.12.0,
  go-algorand-sdk 2.12.0.

## Local evidence

A throwaway Falcon-1024 account funded from the Raven TestNet bank posted a
0-amount note `raven-pq-probe` as `pqsig` scheme `f1`. Confirmed TestNet
round 66733334, txid `NYB44HOFUYVS6JU3LL6YPUYW4MRJA6LZKCBQT6F66U6QHNYXYLNQ`.
Fee 3,000 µAlgo. The same flow confirmed on AlgoKit LocalNet (algod 5.0.0).

## Ruled out

- Treating Falcon `sk[0:32]` as the AlgoChat encryption seed.
- Silently mapping an imported 25-word phrase to a Falcon address (would
  empty-wallet a Pera/v1.1 recovery).
- Requiring a new Ed25519 signature over the X25519 key for Falcon senders.
  The payment `pqsig` already binds the sender address.
