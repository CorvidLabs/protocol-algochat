---
change: record-the-offline-pq-research-probe-and-its-local-task
artifact: testing
---

# Testing and evidence boundary

The existing exact `fledge.toml` task is `pq-spike = "node scripts/pq-spike.mjs"`.
It is an independent local research command, not an added step in the ordinary
`verify` lane. The unchanged verify lane runs `bun scripts/validate.ts`.

Preserved corrected-source receipt `150915-CODEX-0f5019.json` exited 0 using
installed Node 26.10.0/OpenSSL 3.6.5. Its frozen script SHA256 is
`2e313128d18a4678cd957f975492e113ea390200dda0a7e87e61ba25f9f8c9c8`.
It records 16 round trips and ten negative cases for each of ML-KEM-512/768/1024:
48 round trips and 30 negative cases total. Negative cases are three corruption
positions, wrong recipient, zero ciphertext, three invalid lengths, changed
associated data and changed authentication tag. The output records raw public
key/ciphertext sizes and explicit framing assumptions, not generated keys.
The current packet preserves that script hash. No crypto suite is repeated
merely to author this record.

Use installed SpecSync 6.1.0 for bounded native draft shows/audit and a faithful
no-approval fixture to validate definition/delta/ownership constraints. Compare
all protected paths and global/older records before/after. Native show questions
being empty is not a passing whole-repository audit or lifecycle approval.
The whole audit retains its five old baseline findings plus the new unapproved
meaningful script path until authorized lifecycle action occurs. Root must run
applicable exact committed-range Trust/provenance before publication.
