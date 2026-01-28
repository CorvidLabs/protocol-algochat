# Security Considerations

## Threat Model

### What AlgoChat Protects Against

1. **Message Content Disclosure** - Only sender and recipient can decrypt messages
2. **Message Tampering** - Authenticated encryption detects modifications
3. **Replay Attacks** - Blockchain transaction uniqueness prevents replays
4. **Past Message Exposure** - Forward secrecy via ephemeral keys

### What AlgoChat Does NOT Protect Against

1. **Metadata Analysis** - Sender/recipient addresses, timing, and message sizes are visible
2. **Endpoint Compromise** - Malware on user devices can access decrypted messages
3. **Key Compromise** - Future messages to a compromised key are readable (without PSK)
4. **Traffic Analysis** - Transaction patterns may reveal communication patterns
5. **Algorand Network Attacks** - Protocol relies on blockchain security
6. **Quantum Attacks on Key Exchange** - X25519 is vulnerable to quantum computers. **With PSK mode (`0x02`)**, an attacker must also compromise the pre-shared key, providing defense-in-depth. See [PSK Security Properties](#psk-security-properties) below.

## Cryptographic Guarantees

### Confidentiality

- Messages encrypted with ChaCha20-Poly1305 (256-bit key)
- Keys derived using X25519 ECDH (128-bit security level)
- HKDF-SHA256 for key derivation with domain separation

### Integrity

- ChaCha20-Poly1305 provides authenticated encryption
- 128-bit authentication tag detects tampering
- Blockchain immutability prevents post-hoc modification

### Forward Secrecy

- Each message uses a fresh ephemeral key pair
- Compromise of long-term keys does not reveal past messages
- Ephemeral private keys are never stored

## Key Management

### Key Derivation

- Encryption keys derived from Algorand account seed
- Deterministic derivation enables key recovery from mnemonic
- HKDF with domain-specific salt prevents key reuse across protocols

### Key Storage

Implementations should:
- Store private keys in secure enclaves when available
- Use biometric protection for key access
- Clear keys from memory after use (see Memory Clearing below)
- Never log or transmit private keys

### Memory Clearing

Sensitive data (private keys, symmetric keys, plaintext, PSK material, derived session/position PSKs) must be cleared from memory after use. Standard deallocation does not guarantee memory is zeroed.

**Language-specific guidance:**

| Language | Recommended Approach |
|----------|---------------------|
| C/C++ | `sodium_memzero()` (libsodium) or `explicit_bzero()` |
| Rust | `zeroize` crate with `Zeroizing<T>` wrapper |
| Swift | `Data.resetBytes(in:)` or SecureBytes patterns |
| TypeScript/JS | Overwrite buffer contents, then discard reference |
| Python | `ctypes.memset()` or `secrets` module patterns |
| Kotlin/Java | Overwrite `ByteArray` contents before GC |
| Go | `crypto/subtle.ConstantTimeCopy` to zero, or `memguard` |

**Important**: Garbage-collected languages cannot guarantee immediate clearing. Use native bindings (e.g., libsodium wrappers) for maximum security.

### Key Discovery

- Public keys discovered from transaction history
- Key publish transactions enable proactive key distribution
- Out-of-band key exchange supported

### PSK Key Management

When using PSK mode (`0x02`):

- **Generation**: The initial PSK MUST be generated using a CSPRNG (32 bytes)
- **Exchange**: The PSK SHOULD be exchanged in-person or over an authenticated, confidential channel (e.g., QR code shown face-to-face)
- **Storage**: The initial PSK MUST be stored in secure storage (Keychain, secure enclave, encrypted database). It is the root of trust for the entire PSK ratchet chain.
- **Counter State**: Ratchet counter state (send counter, peer last counter, seen counters) MUST be persisted to prevent replay attacks and counter drift across app restarts
- **Rotation**: There is no automatic PSK rotation. Users SHOULD periodically exchange a new PSK if long-term security is desired beyond the ratchet mechanism.
- **Revocation**: To revoke a PSK relationship, both parties must delete their stored PSK. Messages encrypted with the old PSK remain decryptable if the old PSK is retained.

## PSK Security Properties

### Hybrid Key Derivation

PSK mode (`0x02`) derives symmetric keys from the concatenation of the X25519 shared secret and the ratcheted PSK: `IKM = shared_secret || current_psk`. This means:

- If X25519 is broken (e.g., by a quantum computer) but the PSK remains secret, messages remain confidential
- If the PSK is compromised but X25519 remains secure, messages remain confidential
- An attacker must compromise **both** to decrypt messages

This is a defense-in-depth strategy, not a replacement for post-quantum cryptography. When standardized PQ algorithms become available, they should replace X25519 directly.

### Session Forward Secrecy

The ratchet mechanism provides bounded forward secrecy within sessions:

- Each session (100 messages) derives a unique `session_psk` from the `initial_psk`
- Each message position derives a unique `position_psk` from the `session_psk`
- Compromising a `position_psk` exposes only that one message
- Compromising a `session_psk` exposes at most 100 messages in that session
- Compromising the `initial_psk` exposes all past and future PSK-derived keys

Note: True forward secrecy (where past messages are safe even after full key compromise) is provided by the ephemeral X25519 keys, not by the PSK ratchet. The PSK ratchet adds **breadth limitation** -- if the initial PSK is compromised at some point, earlier sessions are equally exposed.

### PSK Threat Matrix

| Threat | No PSK (`0x01`) | Ratcheting PSK (`0x02`) |
|--------|-----------------|-------------------------|
| Classical key exchange attack | Vulnerable | Protected (requires PSK) |
| Quantum key exchange attack | Vulnerable | Protected (requires PSK) |
| Long-term key compromise (future msgs) | Vulnerable | Protected (requires PSK) |
| Long-term key compromise (past msgs) | Protected (ephemeral keys) | Protected (ephemeral keys) |
| PSK compromise only | N/A | Protected (X25519 still required) |
| Both X25519 + PSK compromised | N/A | Vulnerable |
| Endpoint compromise | Vulnerable | Vulnerable |
| Metadata analysis | Visible | Visible |

### PSK Known Limitations

- **Counter drift**: If a device loses counter state (e.g., app reinstall), it may produce counters outside the peer's acceptance window. Recovery requires manual counter reset or PSK re-exchange.
- **~100 message blast radius**: Compromising a session PSK exposes up to 100 messages in that session. This is a design tradeoff for out-of-order delivery support.
- **Initial PSK is root of trust**: The entire ratchet chain is derived from the initial PSK. If the initial PSK was compromised during exchange, all derived keys are compromised.
- **No backward secrecy within a session**: The deterministic ratchet allows any position within a session to be derived from the session PSK. A ciphertext-dependent ratchet would provide backward secrecy but break out-of-order delivery.
- **Protocol mode visible**: The protocol byte (`0x01` vs `0x02`) reveals whether PSK is in use, which is metadata leakage.

## Known Limitations

### Message Size

- Maximum plaintext: 882 bytes
- Longer messages require application-level fragmentation

### Deniability

- Sender public key in envelope provides sender attribution
- Messages cannot be plausibly denied

### Group Messaging

- Protocol designed for 1:1 messaging
- Group chats require multiple encryptions or protocol extension

## Recommendations

### For Implementers

1. Use audited cryptographic libraries (libsodium, @noble/ciphers, CryptoKit, etc.)
2. Implement constant-time operations where applicable:
   - Authentication tag comparison (use `crypto_verify_*` or `timingSafeEqual`)
   - Key comparison operations
   - Any branching on secret data
3. Validate all inputs before processing
4. Handle errors without leaking information (same error response for all auth failures)
5. Clear sensitive data from memory (see Memory Clearing section above)
6. Use secure random number generators (`/dev/urandom`, `SecRandomCopyBytes`, `crypto.getRandomValues`)
7. (PSK) Validate ratchet counters against the acceptance window before attempting decryption
8. (PSK) Persist counter state reliably -- loss of counter state degrades replay protection
9. (PSK) Set a reasonable counter window (recommended: 200) to balance out-of-order tolerance with replay resistance
10. (PSK) Provide clear UI indicators distinguishing PSK-protected conversations from standard ones

### For Users

1. Protect your Algorand mnemonic
2. Use devices you trust
3. Verify recipient addresses carefully
4. Be aware of metadata exposure
5. Report suspicious behavior
6. (PSK) Exchange PSKs in person when possible -- the security of PSK mode depends entirely on the secrecy of the initial PSK
7. (PSK) Verify the PSK fingerprint (e.g., first 8 hex characters) with your contact after exchange
8. (PSK) Understand that PSK mode is defense-in-depth -- it strengthens security but does not replace the need for device security and mnemonic protection

## Reporting Vulnerabilities

**Do NOT report security vulnerabilities as public GitHub issues.**

Please use one of these private channels:

1. **GitHub Security Advisory** (preferred): [Report a vulnerability](https://github.com/CorvidLabs/protocol-algochat/security/advisories/new)
2. **Email**: security@corvidlabs.io (PGP key available on request)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)
- Your contact information for follow-up

We aim to acknowledge reports within 48 hours and provide an initial assessment within 7 days. We will coordinate disclosure timing with you.
