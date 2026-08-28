---
change: pin-trust-1-2-0-rc-1-so-ci-uses-specsync-6-0-0-rc-9
artifact: plan
---

# Plan

1. Replace `CorvidLabs/trust@9d32b578… # v1.0.0` in `.github/workflows/trust.yml`
   with `CorvidLabs/trust@e964e042f7f2756333d4c46e685a4a6dc09077de # v1.2.0-rc.1`.
2. Leave `.trust.toml` profile, coverage, and provenance mode unchanged.
3. Run `fledge lanes run verify`.
