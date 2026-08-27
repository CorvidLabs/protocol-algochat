---
change: document-falcon-1024-algorand-account-identity-as-protocol-1-2-without-changing-0x01-0x02-envelopes
artifact: testing
---

# Testing

This change is specification text. Verification is:

```
bun scripts/validate.ts
fledge lanes run verify
```

The validator checks that the five required documents exist and that
`implementations.json` has unique ids. It does not parse protocol semantics.

Cross-language envelope tests in `test-algochat` MUST remain green without
Falcon, because `0x01`/`0x02` vectors are unchanged. Sending-path Falcon
coverage belongs in ts-algochat / swift-algochat follow-ups, not this repo.
