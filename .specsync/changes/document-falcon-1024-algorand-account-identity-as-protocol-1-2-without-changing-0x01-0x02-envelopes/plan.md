---
change: document-falcon-1024-algorand-account-identity-as-protocol-1-2-without-changing-0x01-0x02-envelopes
artifact: plan
---

# Plan

1. Rewrite PROTOCOL.md §4.1 seed wording; add §4.3 identity and §10.3 fees;
   bump to 1.2.
2. Align IMPLEMENTATION.md, SECURITY.md, TEST-VECTORS.md, README.md, and the
   GitHub Pages `index.html`.
3. Leave implementations.json and language repos to follow-up PRs.
4. Run `bun scripts/validate.ts` / `fledge lanes run verify`.
5. Open a PR. Definition approval and review stay human gates.
