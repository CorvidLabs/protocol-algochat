---
change: pin-trust-1-2-0-rc-2-so-lifecycle-and-contract-share-one-specsync-6-0-0-rc-9
artifact: context
---

# Context

Trust 1.2.0-rc.1 already pinned SpecSync 6.0.0-rc.9 for the contract gate.
v1.2.0-rc.2 (fcebc62, #32) uses that same SpecSync for lifecycle as well, so
the two gates cannot disagree on CLI version.

Pin the composed action to `fcebc62303f89ad6573113313d75d0d26d7d2477`.
Prerelease; do not move the protected `v1` channel (still 1.1.2).

No protocol text changes.
