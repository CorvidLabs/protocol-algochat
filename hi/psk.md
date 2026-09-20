---
hi: 1
families: [PSK]
---

# Psk

## Intent

Falcon on the payment is not enough for the envelope. If I share a secret out of band, that should actually mix into the message key.

## Criteria

- **PSK-1**  I can add a pre-shared key so the message key does not rest on X25519 alone.
