---
id: record-the-offline-pq-research-probe-and-its-local-task
state: draft
type: documentation
base_commit: e80ab3eae8237f4f9358df775cc363de4265ed93
---

# Record the offline PQ research probe and its local task

## Intent

Record the offline PQ research probe and its local task

## Affected Canonical Specs

- None

## Acceptance Criteria

- The packet declares exactly the existing offline scripts/pq-spike.mjs harness, its fledge.toml pq-spike task, and the two direct research proposal documents; no shipped cryptography, protocol or runtime behavior changes.
- Preserved installed-runtime evidence for the exact frozen harness records 16 ML-KEM round trips and ten negative cases for each of three parameter sets, and output contains metadata and explicit limits without generated private/shared-key bytes.
- Research documents retain unshipped status and explicit framing assumptions, with no claim of independent implementation/KAT/FIPS qualification, application audit, quantum attack execution or accepted new protocol format.
- SpecSync 6.1.0 records all deterministic draft answers and selected artifacts while approvals/reopenings/acceptance remain empty and every older record, global sequence and canonical obligation stays byte-identical.

## No-spec Rationale

This bounded packet describes an existing offline research harness and its local pq-spike task, with unshipped proposal documentation. It changes no shipped AlgoChat cryptography, identity, protocol version, wire format, authentication, recovery behavior or canonical runtime contract. Parameter and framing comparisons are research assumptions, not an accepted protocol format or security audit.
