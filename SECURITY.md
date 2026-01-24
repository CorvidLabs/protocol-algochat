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
3. **Key Compromise** - Future messages to a compromised key are readable
4. **Traffic Analysis** - Transaction patterns may reveal communication patterns
5. **Algorand Network Attacks** - Protocol relies on blockchain security

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

Sensitive data (private keys, symmetric keys, plaintext) must be cleared from memory after use. Standard deallocation does not guarantee memory is zeroed.

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

### For Users

1. Protect your Algorand mnemonic
2. Use devices you trust
3. Verify recipient addresses carefully
4. Be aware of metadata exposure
5. Report suspicious behavior

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
