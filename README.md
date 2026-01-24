# AlgoChat Protocol

[![License](https://img.shields.io/github/license/CorvidLabs/protocol-algochat)](https://github.com/CorvidLabs/protocol-algochat/blob/main/LICENSE)
[![Status](https://img.shields.io/badge/protocol-1.0-green)](https://corvidlabs.github.io/protocol-algochat/)

End-to-end encrypted messaging protocol for the Algorand blockchain.

## Overview

AlgoChat enables secure peer-to-peer messaging using Algorand transactions as the transport layer. Messages are encrypted client-side using modern cryptographic primitives and stored immutably on-chain.

## Features

- **End-to-End Encryption** - X25519 key agreement + ChaCha20-Poly1305
- **Forward Secrecy** - Per-message ephemeral keys protect past messages
- **Bidirectional Decryption** - Both sender and recipient can decrypt
- **Immutable Storage** - Messages permanently recorded on blockchain
- **Decentralized** - No central server controls delivery
- **Reply Support** - Thread conversations with context

## Documentation

| Document | Description |
|----------|-------------|
| [PROTOCOL.md](PROTOCOL.md) | Full protocol specification |
| [IMPLEMENTATION.md](IMPLEMENTATION.md) | Language-agnostic implementation guide |
| [TEST-VECTORS.md](TEST-VECTORS.md) | Canonical test vectors for verification |
| [SECURITY.md](SECURITY.md) | Security considerations and threat model |

## Implementations

| Language | Repository | Status |
|----------|------------|--------|
| Swift | [swift-algochat](https://github.com/CorvidLabs/swift-algochat) | Production |
| TypeScript | [ts-algochat](https://github.com/CorvidLabs/ts-algochat) | Active |
| Python | [py-algochat](https://github.com/CorvidLabs/py-algochat) | Active |
| Rust | [rs-algochat](https://github.com/CorvidLabs/rs-algochat) | Active |
| Kotlin | [kt-algochat](https://github.com/CorvidLabs/kt-algochat) | Active |
| Angular | [algochat-web](https://github.com/CorvidLabs/algochat-web) | Active |

See the [Implementation Status Dashboard](https://corvidlabs.github.io/protocol-algochat/status.html) for live test results.

## Quick Reference

### Wire Format (v1)

```
[version: 1][protocol: 1][sender_pubkey: 32][ephemeral_pubkey: 32][nonce: 12][encrypted_sender_key: 48][ciphertext: variable]
```

**Header size**: 126 bytes
**Max message**: 882 bytes plaintext (1024 bytes total envelope)

### Cryptographic Primitives

| Function | Algorithm |
|----------|-----------|
| Key Agreement | X25519 ECDH |
| Encryption | ChaCha20-Poly1305 |
| Key Derivation | HKDF-SHA256 |

### Transport

Messages are transmitted as the `note` field of Algorand payment transactions:
- Minimum payment: 0 ALGO
- Sender pays transaction fee (~0.001 ALGO)
- Note field limit: 1024 bytes

## Contributing

Contributions are welcome. Please read the protocol specification before proposing changes.

## License

MIT License - See [LICENSE](LICENSE) for details.
