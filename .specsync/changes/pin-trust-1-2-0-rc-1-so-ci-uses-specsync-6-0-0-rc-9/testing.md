---
change: pin-trust-1-2-0-rc-1-so-ci-uses-specsync-6-0-0-rc-9
artifact: testing
---

# Testing

```
fledge lanes run verify
```

Hosted Trust on the PR must install SpecSync 6.0.0-rc.9 and load the slug
change ID. No protocol-document semantics change, so `bun scripts/validate.ts`
is the local lane.
