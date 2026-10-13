# PQ and security review spike

Status: research, October 13, 2026. No protocol version, client encryption,
identity or recovery behavior changes. The pair-secret proposal remains unshipped.

## Parameter choice and transport cost

| Parameter | NIST category | Encapsulation key | Ciphertext |
| --- | --- | --- | --- |
| ML-KEM-512 | 1 | 800 bytes | 768 bytes |
| ML-KEM-768 | 3 | 1,184 bytes | 1,088 bytes |
| ML-KEM-1024 | 5 | 1,568 bytes | 1,568 bytes |

These are raw algorithm sizes. NIST recommends 768 as the usual default; 1024
provides a higher margin with larger objects and more work. Category numbers
are attack-cost comparisons, not a measurement obtained by trying a quantum
computer. See [FIPS 203, section 8](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).

The spike uses 1024 as Leif's preferred candidate and measures 768 as the
fallback comparison. Neither fits a whole key or ciphertext in one 1,024-byte
note. Two notes is possible only after budgeting the complete framing. For
example, ciphertext plus the proposed 48-byte sender recovery wrap fits in two
notes with 64 bytes of framing per note, but 1024 needs three notes if framing
takes 224 bytes per note. At the same framing size, 768 still needs two.

`fledge run pq-spike` uses an already installed Node runtime with ML-KEM support.
It generates temporary keys, checks raw public-key/ciphertext lengths, runs
16 encapsulation/decapsulation round trips per parameter, and checks corruption,
wrong recipient, invalid lengths, associated data and authentication tags.
It prints sizes, timings, case counts and explicit limits, never secret keys.
Bun is still used for the repository's ordinary document validation; the
installed Bun runtime does not expose the required KEM functions.

The KEM returns a different secret for correctly sized corrupted ciphertext.
It does not serve as a ciphertext-validity oracle: the authenticated payload
must reject the wrong secret. The harness demonstrates that distinction with
standard ChaCha20-Poly1305. It does not implement AlgoChat's proposed combiner,
wire format or message processing. Node's native and Web Crypto paths share
OpenSSL, so they do not count as independent implementations or known-answer
qualification. [Node crypto documentation](https://nodejs.org/api/crypto.html#cryptoencapsulatekey-callback).

## What an independent review must cover

Primitive selection is one boundary; protocol authentication and key
confirmation are separate. [NIST SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final)
describes these additional requirements. The following cases are an audit
plan, not claims that the current implementation has passed them:

| Surface | Adversarial case | Evidence required before release |
| --- | --- | --- |
| Key/address binding | Substitute a key, signer or network through an untrusted indexer | Independently verify the authorizing signature and bind network, identities and algorithm to the transcript |
| Split note assembly | Mix pairs, messages, keys or ciphertext chunks; reorder, replay or omit a part | Complete authenticated transcript; exact lengths; bounded incomplete state; no partially accepted handshake |
| Negotiation | Remove a PQ announcement or present a classical-only peer | Explicit downgrade policy; a requested PQ conversation must not silently become classical |
| Hybrid construction | Change either shared secret, roles, algorithm, genesis hash or key version | Reviewed combiner with unambiguous encoding, domain separation and independent vectors |
| Recovery | Restore sender and recipient on fresh devices, including simultaneous handshakes | Same pair secret and history, no raw shared secret on chain; fail closed on missing/corrupted wraps |
| Resource bounds | Many incomplete handshakes or candidates, oversized lengths and stale streams | Caps on memory, work, candidate trials, time and fees; cancellation without persistent secret leakage |
| Secret handling | Leaked phrase, storage dump, logs, clipboard, camera callback or backup | Documented compromise consequences; lifecycle tests; no claims of forward secrecy for phrase-restorable history |
| Implementation | Malformed keys, corrupted ciphertext and backend differences | Pinned NIST/ACVP vectors, independently implemented cross-checks, parser fuzzing and target-specific timing review |

Raven delegates protocol cryptography to its released AlgoChat engine. Its
scanner, storage, signing-intent validation and deployment path need review
alongside the engine. Falcon transaction authorization does not replace a
post-quantum confidentiality handshake. A ledger records ciphertext and public
metadata permanently; a later phrase compromise remains relevant even if the
KEM is sound.

The proposal's phrase-derived key seeds need a separate review of entropy,
domain separation and recovery. NIST permits seed representations/imports that
produce the prescribed key outputs; that does not itself validate deriving
those seeds from a mnemonic or make this application FIPS validated.
[NIST seed-format FAQ](https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs).

## Quantum access and useful testing

[IBM Quantum Open Plan](https://eu-de.quantum.cloud.ibm.com/docs/en/guides/plans-overview)
offers cloud QPU experiments, currently up to ten minutes per rolling 28-day
window. [Amazon Braket](https://docs.aws.amazon.com/braket/latest/developerguide/braket-devices.html)
offers several QPUs and simulators. Account eligibility, scheduling and pricing
need checking before use. No account, payment or cloud job is created by this spike.

These services are useful for learning circuits. Failure to break a real KEM
on today's QPU does not establish its security. Start with conformance vectors,
cross-implementation checks, bounded fuzzing and independent review of the
composition. IBM's [research roadmap](https://research.ibm.com/quantum-computing)
still describes fault-tolerant computing as future work; this spike makes no
claim to have executed a quantum attack.

## Review package

Freeze one engine/client/spec revision set and publish its exact versions and
hashes to the reviewer. Include threat model, recovery/identity design, accepted
risks, dependencies, build instructions, local attack fixtures and complete
receipts. Request a protocol cryptographer's review of the construction and a
separate implementation/client/deployment review. Agree scope and budget before
commissioning either; no outside reviewer has been contacted by this spike.

Passing internal tests, an agent review, a wallet challenge or using standardized
primitives is not an independent audit of Raven/AlgoChat. Report vulnerabilities
through the affected repository's private reporting process; keep exploit
details and sensitive receipts out of public proposal comments.
