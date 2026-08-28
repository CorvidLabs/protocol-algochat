---
change: pin-trust-1-2-0-rc-2-so-lifecycle-and-contract-share-one-specsync-6-0-0-rc-9
artifact: plan
---

# Plan

1. Replace `CorvidLabs/trust@e964e042… # v1.2.0-rc.1` in `.github/workflows/trust.yml`
   with `CorvidLabs/trust@fcebc62303f89ad6573113313d75d0d26d7d2477 # v1.2.0-rc.2`.
2. Leave `.trust.toml` unchanged.
3. Run `fledge lanes run verify`.
