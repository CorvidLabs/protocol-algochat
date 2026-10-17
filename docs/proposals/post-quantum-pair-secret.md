# Proposal: post-quantum pair secret

**Status: shelved.** Designed, not scheduled. Nothing here is part of the
protocol until a future version adopts it. See [When to revisit](#when-to-revisit).

The [October 2026 research spike](pq-audit-spike.md) compares ML-KEM-1024 and
ML-KEM-768 with explicit framing budgets, an offline primitive harness and an
independent-review plan. It does not implement or activate this proposal.

## Problem

Standard mode (`0x01`) derives every message key from X25519 alone
([4](../../PROTOCOL.md#4-key-derivation), [6](../../PROTOCOL.md#6-encryption)).
Every envelope stays on the public ledger forever, and it carries the ephemeral
public key; the recipient's long-term public key is public too
([10.2](../../PROTOCOL.md#102-key-discovery)). A quantum computer able to solve
X25519 could therefore read every standard-mode message ever sent, from the
ledger alone, with no one's recovery phrase: "harvest now, decrypt later".
ChaCha20-Poly1305 and HKDF-SHA256 are not the part that fails.

PSK mode (`0x02`, [8](../../PROTOCOL.md#8-psk-ratcheting-mode-protocol-0x02))
already resists this: the message key mixes a 32-byte `initial_psk` that never
goes on the chain, so breaking X25519 is not enough. Its weakness is adoption:
the PSK has to be exchanged out of band ([8.6](../../PROTOCOL.md#86-psk-exchange)),
so most chats never use it.

## Constraints

- **Note size.** A note holds 1024 bytes; standard mode leaves 882 bytes of
  plaintext and PSK mode 878 ([5.3](../../PROTOCOL.md#53-size-constraints-standard-mode),
  [5.6](../../PROTOCOL.md#56-psk-size-constraints)).
- **ML-KEM sizes** (FIPS 203): the ML-KEM-512 ciphertext is 768 bytes, ML-KEM-768
  1088, ML-KEM-1024 1568; encapsulation keys are 800, 1184 and 1568 bytes. The
  768 and 1024 ciphertexts do not fit in one note at all, and ML-KEM-512 (NIST
  category 1) would leave at most 114 bytes of text. Post-quantum key exchange
  cannot reasonably be added message by message.
- **Recoverable history.** An account's 25 words restore its history on any
  device, by re-deriving keys and re-reading the chain. Any new secret must be
  re-derivable from the recovery phrase plus the chain, or history stops coming
  back.

## Design

Use ML-KEM **once per pair of accounts** to establish PSK mode's `initial_psk`
automatically, then send every later message in PSK mode, unchanged. Per-message
size, fees and the PSK key schedule stay exactly as they are.

1. **Encapsulation key.** Each account derives an ML-KEM-1024 key pair
   deterministically from the same 32-byte mnemonic entropy that
   [4.1](../../PROTOCOL.md#41-encryption-key-pair) uses as IKM, under its own
   HKDF-SHA256 salt and info (never from the X25519 `encryption_seed`): the
   32-byte `d` and `z` inputs of FIPS 203 `ML-KEM.KeyGen_internal` come from that
   derivation. The phrase alone re-creates the decapsulation key.
2. **Publication.** The account publishes its 1568-byte encapsulation key to
   itself as a two-note public announcement (a new note type, which current
   readers skip as unreadable). As with X25519 keys, the binding to the address is the
   payment's authorizing signature ([10.2](../../PROTOCOL.md#102-key-discovery)).
3. **Handshake.** The first party to start checks the peer's published key
   (the FIPS 203 encapsulation key check) and sends the peer one ML-KEM-1024
   encapsulation to it: a 1568-byte ciphertext in two notes. Both sides now hold
   the 32-byte shared secret `ss`: the sender from encapsulation, the recipient
   by decapsulating with its phrase-derived key.
   The handshake notes also carry `ss` wrapped for the sender alone:
   ChaCha20-Poly1305 under a one-time key from HKDF-SHA256 over the sender's
   mnemonic entropy, with the handshake transcript in `info` (48 bytes). The
   transcript includes the fresh ciphertext, so each key is used once and a
   fixed all-zero nonce is safe. Only the
   sender's phrase opens it, and it involves no X25519, so it stays
   quantum-safe. Without it, a sender restoring from the phrase could not recover
   `ss`: encapsulation randomness never reaches the chain, and only the
   recipient can decapsulate.
4. **Hybrid pair secret.** The `initial_psk` for the pair is

   ```
   initial_psk = HKDF-SHA256(
       ikm:  ss || X25519(own_static_private, peer_static_public),
       salt: SHA-256(transcript),
       info: "AlgoChat-PQ-PairSecret",
       length: 32
   )
   ```

   where `transcript` covers both addresses and both X25519 public keys, each
   pair in one canonical order (for example, sorted by address bytes), the
   encapsulation key, the ciphertext, and the network's genesis hash. The X25519 term keeps the pair secret classically secure if ML-KEM were
   ever broken; the ML-KEM term keeps it quantum-secure. Hybrid KEMs such as
   X-Wing are an alternative to this combiner (an open question below).
5. **Messages.** From then on the pair uses PSK mode with that `initial_psk`.
   A quantum attacker who breaks X25519 still lacks the PSK.
6. **Races and re-reads.** If both sides start a handshake at once, each
   produces a candidate `initial_psk` (four handshake notes instead of two).
   Senders SHOULD use the earliest confirmed handshake between the pair; readers
   try each candidate, and the AEAD tag identifies the right one. After restoring
   from the phrase, a device re-reads the handshake notes and re-derives the same
   secrets: the recipient by decapsulating, the sender by opening its own wrap.
7. **Authenticity.** A handshake counts only in a payment between the two
   addresses whose authorizing signature the reader has verified, the same check
   as for any message. The static X25519 term means a third party who injects a
   handshake (for example through a dishonest indexer) cannot compute the
   resulting pair secret; at worst it causes a mismatch that readers resolve by
   trying candidates.
8. **Rollout.** A client uses this only when both accounts have published an
   encapsulation key, and falls back to today's modes otherwise. The new note
   types need a protocol version bump and a transition in which old clients keep
   receiving what they read today.

**Estimated cost, assuming the complete framed key and ciphertext each fit in
two notes:** two notes per account, once, and two notes per pair, once (four if both
start at once). The framing and sender-wrap budget must be measured before
this estimate is a wire-format promise; the research spike shows a framing size
at which ML-KEM-1024 needs a third note. At the minimum network fee of 0.001 ALGO per note, or 0.003 for a
Falcon payer ([10.3](../../PROTOCOL.md#103-fees)), two notes cost 0.002 ALGO, or
0.006 for a Falcon payer, plus any payment `amount` the implementation attaches.

## What it does not change

- **No forward secrecy.** The pair secret is re-derivable from the recovery
  phrase and the chain, by design, so a leaked phrase still opens that account's
  whole history ([11.1](../../PROTOCOL.md#111-forward-secrecy--not-provided)).
  Forward secrecy and phrase-restorable history exclude each other for the same
  messages. A separate, optional mode with random, deleted keys (history not
  restorable) would be its own proposal.
- **Metadata** stays public ([11.3](../../PROTOCOL.md#113-metadata-leakage)), and
  the handshake notes show which pairs turned this on.
- **Active quantum attackers.** Encapsulation keys are bound by Ed25519 or
  Falcon payment signatures. A future attacker able to forge Ed25519 could
  publish a false key for an Ed25519 account and sit in the middle of a new
  handshake; Falcon-1024 accounts ([4.3](../../PROTOCOL.md#43-algorand-account-identity))
  are not exposed to that. Handshakes completed before such an attacker exists
  stay protected against passive decryption.

## Open questions

- ML-KEM-1024 (NIST category 5) or ML-KEM-768 (category 3): both can use two notes
  for the key and ciphertext with sufficiently small framing. The complete
  budget, including the sender wrap, determines whether 1024 needs a third note.
- The combiner: the HKDF construction above, or a standard hybrid KEM (X-Wing).
- Recovering the sender's `ss`: the self-wrap above, or deriving the
  encapsulation randomness `m` from the mnemonic entropy and the parts of the
  transcript that exist before the ciphertext (addresses, keys, genesis hash, a
  per-handshake nonce), then using `ML-KEM.Encaps_internal`. That saves the 48
  bytes but departs from FIPS 203's use of fresh randomness.
- Key generation from the mnemonic entropy likewise replaces FIPS 203's random
  `d` and `z` with a derivation. That is what keeps the decapsulation key
  recoverable; reviewers should confirm it, since FIPS compliance is not a goal
  here but soundness is.
- Whether safety numbers should also cover the encapsulation key.
- Implementations: `@noble/post-quantum` (TypeScript) implements ML-KEM and states
  it has not been independently audited. The Swift side needs an implementation
  that works on every supported OS version.
- Test vectors: deterministic key generation from a seed, encapsulation with
  fixed randomness, and the combiner output, cross-checked by an independent
  implementation.

## When to revisit

Schedule this when a partner or grant asks for post-quantum messaging, when
there is credible news of a cryptographically relevant quantum computer, or when
usage grows. It needs a protocol version bump, a transition period and an
independent review before release.
