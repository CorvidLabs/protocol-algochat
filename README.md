# AlgoChat Protocol

[![License](https://img.shields.io/github/license/CorvidLabs/protocol-algochat)](https://github.com/CorvidLabs/protocol-algochat/blob/main/LICENSE)
[![Status](https://img.shields.io/badge/protocol-1.1-green)](https://corvidlabs.github.io/protocol-algochat/)

Encrypted, immutable annotations for Algorand transactions.

## What Is This?

AlgoChat is a protocol for attaching **end-to-end encrypted messages** to Algorand transactions. Think of it as cryptographic memos that only the sender and recipient can read, permanently recorded on-chain.

**This is not a general-purpose messaging app.** For everyday chat, use Signal or Matrix. AlgoChat serves a specific niche: encrypted communication that is provably tied to blockchain transactions.

## Use Cases

- **Payment Memos** - Attach private notes to payments ("Invoice #1234", "March rent")
- **On-Chain Attestations** - Cryptographic proof that you said X to Y at time Z
- **Transaction Receipts** - Encrypted confirmation details readable by both parties
- **Audit Trails** - Immutable, timestamped communication records
- **Escrow Instructions** - Private terms attached to smart contract interactions

## Limitations

Be aware of what this protocol cannot do:

| Limitation | Details |
|------------|---------|
| **882-byte messages** | Maximum plaintext size (standard mode); 878 bytes in PSK mode. No images, files, or long texts. |
| **Metadata visible** | Sender/recipient addresses and timing are public on-chain |
| **No message deletion** | Blockchain is immutable; messages persist forever |
| **Cost per message** | ~0.001 ALGO transaction fee (see [Economics](#economics)) |
| **4.5s latency** | Algorand block finality time |
| **No deniability** | Sender attribution is included in the envelope |

## Economics

Each message costs ~0.001 ALGO in transaction fees. However, Algorand staking rewards can offset or exceed this cost, effectively making messaging free for participants.

**Staking Options:**

| Method | Minimum | Notes |
|--------|---------|-------|
| Solo staking | 30,000 ALGO | Run your own node |
| Delegated staking | 30,000 ALGO | Delegate to a node operator |
| Liquid staking | Any amount | Via protocols like Folks Finance |
| Staking pools | Any amount | Community-operated pools |

**Example at ~5% APY:**

| ALGO Staked | Annual Rewards | Messages Funded/Year |
|-------------|----------------|----------------------|
| 30,000 | ~1,500 ALGO | ~1,500,000 |
| 100,000 | ~5,000 ALGO | ~5,000,000 |

*Note: APY rates are illustrative and vary by governance period. Actual rewards depend on total network participation and governance proposals. Check current rates at [Algorand Foundation](https://algorand.foundation).*

Users with less than 30K ALGO can participate through liquid staking or pools. The more you contribute to Algorand infrastructure, the more utility you extract—active participants get free encrypted communications, while casual users pay minimal per-message fees.

## Security Properties

| Property | Status |
|----------|--------|
| Message content confidentiality | Protected (E2EE) |
| Message integrity | Protected (authenticated encryption) |
| Forward secrecy | Protected (ephemeral keys per message) |
| Replay attacks | Protected (blockchain uniqueness + PSK counter) |
| Quantum resistance (key exchange) | Optional (PSK mode provides defense-in-depth) |
| PSK session forward secrecy | Optional (100-message session boundaries in PSK mode) |
| Metadata privacy | **Not protected** (addresses, timing visible) |
| Traffic analysis | **Not protected** |

See [SECURITY.md](SECURITY.md) for the full threat model.

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

## Technical Summary

### Cryptographic Primitives

| Function | Algorithm | Reference |
|----------|-----------|-----------|
| Key Agreement | X25519 ECDH | RFC 7748 |
| Encryption | ChaCha20-Poly1305 | RFC 8439 |
| Key Derivation | HKDF-SHA256 | RFC 5869 |

These are the same primitives used by Signal, WireGuard, and TLS 1.3.

### Wire Format (v1 Standard - `0x01`)

```
[version: 1][protocol: 1][sender_pubkey: 32][ephemeral_pubkey: 32][nonce: 12][encrypted_sender_key: 48][ciphertext: variable]
```

- **Header size**: 126 bytes (fixed overhead)
- **Max plaintext**: 882 bytes
- **Total envelope**: 1024 bytes (Algorand note field limit)

### Wire Format (v1.1 PSK - `0x02`)

```
[version: 1][protocol: 2][ratchet_counter: 4][sender_pubkey: 32][ephemeral_pubkey: 32][nonce: 12][encrypted_sender_key: 48][ciphertext: variable]
```

- **Header size**: 130 bytes (126 + 4-byte ratchet counter)
- **Max plaintext**: 878 bytes
- **Hybrid key derivation**: X25519 ECDH + ratcheted pre-shared key

### Transport

Messages are the `note` field of standard Algorand payment transactions:

```
sender  → recipient
amount  = 0 ALGO (or any payment amount)
note    = <encrypted AlgoChat envelope>
fee     = ~0.001 ALGO
```

## Legal Notice

This software is provided for legitimate uses including:
- Private payment annotations
- Confidential business communications
- Research and educational purposes

**Users are responsible for compliance with applicable laws.** This includes but is not limited to:
- Export controls on cryptographic software
- AML/KYC regulations in your jurisdiction
- Data protection laws (GDPR, CCPA, etc.)
- Sanctions compliance

This protocol does not provide lawful intercept capabilities and cannot comply with key escrow requirements. Consult legal counsel before deploying in regulated environments.

## Contributing

Contributions are welcome. Please read the protocol specification before proposing changes.

## License

MIT License - See [LICENSE](LICENSE) for details.
