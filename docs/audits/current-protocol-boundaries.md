# Current protocol boundaries

**Status:** research note, 2026-10-15. This is a research/reference reading of shipped AlgoChat 1.2. It does not change the wire format, wallets, key recovery, or production crypto.

The executable companion is `scripts/protocol-boundary-probe.mjs`, exercised by `scripts/protocol-boundary-probe.test.mjs`. Both use Node's built-in `node:crypto` and `node:test`. They use the published test seeds, ephemeral key, and nonce. They do not contain wallet mnemonics, and they do not open a network connection or submit a transaction.

A passing harness does not audit Raven, prove that a client validates notes, bind an Algorand `sig` or `pqsig`, persist replay state, or qualify any registered implementation. Node is one implementation of the named primitives. It is not an ACVP run and it is not a second independent implementation.

## Shipped surface

v1.2 envelopes use version `0x01` and protocol `0x01` (standard) or `0x02` (ratcheting PSK). The primitives are X25519, HKDF-SHA256, and ChaCha20-Poly1305, as in PROTOCOL.md section 3. Falcon-1024 authorizes a payment. It is not an envelope mode. Standard replay protection is transaction uniqueness (PROTOCOL.md section 11.2). PSK mode adds the counter window in section 8.5. SECURITY.md says longer messages require application-level fragmentation. The header has no fragment field. docs/HLD.md states that the protocol has no fragmentation.

This note does not rerun the ML-KEM-512/768/1024 size spike. That spike and the shelved pair-secret proposal belong to draft PR 21 (`0xleif/docs/pq-pair-secret`, head `e78a1f245382670acf05c29cb87aa25acd07ca4e` in the coordinator preflight). v1.2 has no post-quantum key-exchange mode and no downgrade-negotiation byte. Nothing in this probe adopts that proposal.

## Exact vectors

The harness recomputes the following TEST-VECTORS.md literals and compares them to Node. The JSON report stores match flags and the public note hex. It does not print private keys, symmetric keys, or position keys.

| Case | What is checked |
| --- | --- |
| 1.1, 1.2 | HKDF encryption seed and X25519 public key for seeds `0x00` and `0x01` |
| 2.1, 4.5 | Patterned minimum notes: 142 bytes (`0x01`/`0x01`) and 146 bytes (`0x01`/`0x02`, counter `0`) |
| 3.1 | Recipient and sender shared secrets, both symmetric keys, 43-byte ciphertext, 48-byte sender wrap, 169-byte note, and both decrypt paths |
| 3.2 | Round trip of the printed literal. See `unicode-vector-length` below |
| 4.1, 4.2, 4.3 | Session and position keys at counters 0, 99, and 100; hybrid keys; 173-byte PSK note; recipient open (`canonical-psk-recipient-opens`) and sender open through `encrypted_sender_key` (`canonical-psk-sender-opens`). Deriving the sender key during encryption is not that sender open |
| 4.4 | Counters 0, 51, 249, and 250 accepted, 251 out of range, 50 replay, against `peer_last_counter = 50` with 50 already seen. Both written check orders agree |
| 6.1, 6.2, 6.3 | Documented JSON payloads fit in the 882-byte plaintext budget |
| 8.1, 8.2, 8.3, 8.4 | Empty notes are 142 and 146 bytes. Plaintexts of 882 and 878 bytes produce a 1024-byte note and round-trip. 883 and 879 bytes return `MESSAGE_TOO_LARGE` and emit no note |

## Negative controls

Each authentication failure below is a ChaCha20-Poly1305 rejection after X25519 and HKDF have produced 32-byte keys and after a 16-byte tag has been accepted by the cipher. A short tag, a short note, an unknown version, an unknown protocol, a missing PSK, and a counter-window rejection are separate results. They are not counted as authentication failures.

| Control | Result |
| --- | --- |
| Flip one ciphertext byte, or one tag byte, of the 3.1 note | `DECRYPTION_FAILED` |
| Replace the 12-byte nonce with 12 bytes of `0x05` | `DECRYPTION_FAILED` |
| Decrypt 3.1 with the seed-`0x00` private key and the real recipient public key in the transcript | `DECRYPTION_FAILED` |
| Flip one `sender_pubkey` byte and open as the recipient | `DECRYPTION_FAILED` |
| Minimum patterned standard note from case 2.1 | Parses, then `DECRYPTION_FAILED` (`garbage-pattern-fails-aead`) |
| Minimum patterned PSK note from case 4.5 | Counter 0 is accepted under PROTOCOL.md section 8.4 with `peer_last_counter = 0`, an empty seen set, and the published 32-byte `0xAA` PSK. The recipient open then returns `DECRYPTION_FAILED` after key and tag setup (`psk-garbage-pattern-fails-aead`). Matching the 146-byte length and `010200000000` prefix is a separate check and is not this result |
| Drop the last byte of the 169-byte note (168 bytes, still at least 142) | `DECRYPTION_FAILED` |
| Flip one byte of the standard `encrypted_sender_key` | Recipient path still opens. Sender path returns `DECRYPTION_FAILED` after setup |
| Flip one byte of the PSK `encrypted_sender_key` | Recipient path still opens the published plaintext (`psk-sender-wrap-bit-flip-recipient-opens`). Sender path returns `DECRYPTION_FAILED` after the sender-key AEAD is set up (`psk-sender-wrap-bit-flip-sender-fails`). The recipient success shows the failure is the wrap branch. This is not a new production requirement |
| 141-byte prefix, test-vector length rule | `INVALID_ENVELOPE` before AEAD |
| 126-byte header, IMPLEMENTATION.md length rule | `HARNESS_TAG_SHORT` before `setAuthTag`. Not `DECRYPTION_FAILED` |
| `0x0101AABB` and a 32-byte note | `INVALID_ENVELOPE` before AEAD |
| Version `0x02` with a long suffix | `UNKNOWN_VERSION` before AEAD |
| Protocol `0x03` with a long suffix | `UNKNOWN_PROTOCOL` before AEAD |
| Relabel the 3.1 note as protocol `0x02` and open with the test PSK, counter gate off | `DECRYPTION_FAILED`. No fallback to `0x01` |
| Relabel the 4.3 note as protocol `0x01` | `DECRYPTION_FAILED`. No fallback to `0x02` |
| Open the 4.3 note with no PSK | `PSK_NOT_FOUND` before AEAD |
| Open the 4.3 note with 32 bytes of `0xBB` | `DECRYPTION_FAILED` |
| 15-byte buffer passed to the AEAD helper | `HARNESS_TAG_SHORT`. Node's own `ERR_CRYPTO_INVALID_AUTH_TAG` is classified as a setup exception and is not an authentication result |
| Counter 251 against Test Case 4.4 state | `PSK_COUNTER_OUT_OF_RANGE` before AEAD. The same note opens when the gate is not applied, so the rejection is the counter rule |
| Same standard note opened twice | Both opens succeed. The note is not a replay token |

`HARNESS_TAG_SHORT`, `HARNESS_SETUP_EXCEPTION`, `HARNESS_COUNTER_UNSPECIFIED`, and `HARNESS_UNEXPECTED` are harness classifications so a setup failure cannot be reported as a protocol rejection. They are not new protocol error codes.

## Authenticated binding

Section 6.1 encryption takes the sender public key, the recipient public key, and an ephemeral private key. It does not take the sender's long-term private key. The harness checks two consequences with synthetic plaintexts:

- A note built under the seed-`0x00` public key, addressed to the seed-`0x02` recipient, opens on the recipient path. Dispatch labels the role `recipient` because the public keys differ.
- A note whose `sender_pubkey` is a copy of the decryptor's own public key opens, and combined dispatch labels the role `sender`, because IMPLEMENTATION.md compares `myPublicKey` with `envelope.senderPublicKey` before choosing a branch. Building that note still does not require the decryptor's private key.

The recipient transcript covers `envelope.sender_pubkey`, so flipping that field makes the recipient path fail authentication. `decryptAsSender` mixes the caller's own public key, not the envelope field. Those are readings of the current pseudocode. Whether a client must tie the field to the payment's authorizing signature is unresolved. This harness does not check `sig` or `pqsig`.

PSK mode adds the initial PSK to the HKDF input. The published PSK note does not open with a different 32-byte PSK. The same binding limit remains for someone who has the PSK: the envelope still does not carry the payment signature.

## Replay, order, and downgrade

Standard mode has no counter in the note. Opening the same bytes twice succeeds. Section 11.2 places that replay protection on the blockchain. This registry harness cannot execute that check.

PSK Test Case 4.4 is applied as written, independently of decryption, in both orders:

- PROTOCOL.md section 8.4: seen counter, then too old, then too far ahead.
- IMPLEMENTATION.md: too far ahead, then too old, then seen counter.

Counters 0, 51, 249, and 250 are accepted for `peer_last_counter = 50`. Counter 250 is exactly 200 ahead, so the written `>` test does not reject it. Counter 251 is rejected. Counter 50 is a replay when it is already in the seen set. A separate script accepts 52, then 51, then 53, and then rejects a second 52. The seen set grows by one per newly accepted counter. The harness does not prune it.

The too-old clause is `peer_last_counter > 200` and `counter < peer_last_counter - 200`. Counter 0 is still inside the window when `peer_last_counter` is 200. It is outside when `peer_last_counter` is 201. That is the written inequality, not an extra rule.

Unknown version `0x02` and unknown protocol `0x03` are rejected before key derivation. Relabeling a valid note as the other shipped mode fails authentication. The harness does not fall back from one mode to the other. A post-quantum downgrade policy is proposal text on PR 21. It is not part of v1.2 and it is not defined here.

The sender's own PSK decrypt path, as written, does not apply the counter gate. The recipient path does. The harness follows that split. `canonical-psk-sender-opens` opens the published 4.3 note with the published sender keys and the published PSK, with the counter gate off, and checks the sender role, exact plaintext, and successful AEAD setup. `canonical-psk-recipient-opens` is the separate recipient open of the same note.

## Resource budgets

The header field widths are `1+1+32+32+12+48 = 126` and, for PSK, those same fields plus a 4-byte counter, totaling 130. There is no index, count, message id, or length prefix.

| Mode | Header | Auth tag | Maximum plaintext | Maximum note |
| --- | --- | --- | --- | --- |
| Standard `0x01` | 126 | 16 | 882 | 1024 |
| PSK `0x02` | 130 | 16 | 878 | 1024 |

Reserving 0, 1, 8, 16, or 32 bytes inside that plaintext leaves 882, 881, 874, 866, and 850 bytes in standard mode, and 878, 877, 870, 862, and 846 bytes in PSK mode. That is a measurement of the existing budget (`fragment-byte-budget`). It is not a fragment header and it does not change the wire format.

An oversized plaintext emits zero partial notes.

The counter is a 32-bit unsigned integer. `windowSpan` reports only counters that fit in that field. Its upper endpoint is the smaller of `last + 200` and `UINT32_MAX`. That cap is a measurement of representable values. Counter rollover is not defined by this measurement, and neither is saturation or a rule that the sender stops.

For `200 <= last <= UINT32_MAX - 200`, the written window contains 401 counters (`last - 200` through `last + 200`, inclusive). That holds at `peer_last_counter = 250` and at `UINT32_MAX - 200`. At `peer_last_counter = 50` the too-old clause is off, so the inclusive span is 0 through 250 (251 counters). At `UINT32_MAX - 199`, `last + 200` is `UINT32_MAX + 1`, which `classifyCounter` refuses as `HARNESS_COUNTER_UNSPECIFIED`; the reported span has 400 representable counters and ends at `UINT32_MAX`. At `UINT32_MAX` the reported span has 201 representable counters, from `UINT32_MAX - 200` through `UINT32_MAX`. The JSON report records these three bounds and the `classifyCounter` code at each endpoint. The seen set has no written cap, and pruning is not authorized by the text. Wrap, saturation, and stopping remain the open `counter-wrap` decision.

## Fragmentation

The probe does not reassemble fragments and does not invent a production framing rule. Identical deterministic encryptions produce identical note bytes, so the note has no hidden per-copy index that could order or deduplicate application fragments. Out-of-order and duplicate behavior that does exist is the PSK counter schedule above, which is per note, not per fragment.

## Decisions left open

These are missing or conflicting statements in the current documents. They are not new requirements.

| Id | Topic |
| --- | --- |
| `minimum-length` | TEST-VECTORS.md uses 142/146 bytes, including the tag. IMPLEMENTATION.md accepts a 126/130-byte header. The harness runs both readings and does not choose a production rule. |
| `psk-check-order` | When counter 50 has been seen and `peer_last_counter` is 300, section 8.4 reports `PSK_COUNTER_REPLAY` and the implementation pseudocode reports `PSK_COUNTER_OUT_OF_RANGE`. |
| `sender-pubkey-payment-binding` | Section 10.2 names the payment signature as the account binding. The decrypt pseudocode does not compare the envelope key with the transaction sender. |
| `sender-unwrap-covers-local-key` | The sender unwrap mixes the caller's public key. The recipient path mixes the envelope field. Combined dispatch uses an equality check to pick the branch. |
| `initial-peer-counter` | No sentinel is defined for `peer_last_counter` before the first accepted message. Scripted checks use the Test Case 4.4 state. |
| `seen-set-pruning` | Replay rejection is a MUST. The window is a SHOULD. No rule allows forgetting a seen counter. |
| `counter-wrap` | The counter is a 32-bit integer that increments by one. Wrap, saturation, and stopping are not specified. Values outside that range are `HARNESS_COUNTER_UNSPECIFIED` and are not given a protocol result. |
| `unicode-vector-length` | The Test Case 3.2 literal `Hello! Bonjour! Hallo! Ciao! Hola!` is 34 UTF-8 bytes. The same case says 51. The literal is what the harness round-trips. TEST-VECTORS.md was not edited. |
| `key-publish-publickey` | Section 9.3 includes `publicKey`. Test Case 6.3 is `{"type":"key-publish"}` only. Already listed in docs/HLD.md. |
| `fragment-split-unit` | Independent plaintexts, or a new protocol byte, are not chosen. |
| `fragment-identity` | Index, count, message id, and total length are not specified. |
| `fragment-byte-budget` | A marker inside the current plaintext would spend the 882/878-byte budget. No marker is defined. |
| `fragment-reassembly-bound` | No bound is specified for incomplete fragment state. |
| `fragment-duplicate` | No rule says whether a repeated fragment is a replay, a replacement, or an error. |
| `fragment-order` | No rule says whether out-of-order fragments are accepted, or whether partial plaintext is released. |
| `fragment-transport-group` | Atomic groups versus separate payments are not specified. |
| `fragment-transcript` | Per-fragment authentication and an outer transcript are not specified. |
| `fragment-psk-counter` | No rule assigns PSK counters across the notes of one logical message. |
| `fragment-standard-replay` | Standard fragment replay has no in-envelope rule beyond transaction uniqueness, which this harness cannot execute. |

## How to run

From this worktree, with no extra packages:

```sh
node --test scripts/protocol-boundary-probe.test.mjs
node scripts/protocol-boundary-probe.mjs
```

The second command prints deterministic JSON. It includes the vector match flags, each control's expected and observed code, both PSK check orders, the plaintext-budget measurement, the open decision ids, and the limits above.

## Limits

- Passing this harness is not evidence about Raven, about any client in `implementations.json`, or about Algorand consensus.
- Transaction-id replay, durable PSK state, mnemonic storage, and memory wiping are specified for implementations and are not executed here.
- The two PSK check orders are both reported. Picking one would be a protocol edit, and this note does not make that edit.
- PR 21's ML-KEM measurements and pair-secret framing budgets are unchanged and were not repeated.
