# AlgoChat Protocol Specification

**Version**: 1.0
**Status**: Stable

## 1. Overview

AlgoChat is an end-to-end encrypted messaging protocol that uses the Algorand blockchain as a transport and storage layer. Messages are encrypted client-side using modern cryptographic primitives and transmitted as transaction notes.

## 2. Design Goals

1. **Privacy** - Only sender and recipient can read messages
2. **Forward Secrecy** - Compromised keys don't expose past messages
3. **Bidirectional Decryption** - Sender can decrypt their own sent messages. This enables chat history display on the sender's device without storing plaintext locally—messages can be re-decrypted from the blockchain on any authorized device.
4. **Immutability** - Messages cannot be altered after transmission
5. **Decentralization** - No trusted third parties required
6. **Simplicity** - Minimal protocol complexity

## 3. Cryptographic Primitives

| Function | Algorithm | Reference |
|----------|-----------|-----------|
| Key Agreement | X25519 ECDH | RFC 7748 |
| Authenticated Encryption | ChaCha20-Poly1305 | RFC 8439 |
| Key Derivation | HKDF-SHA256 | RFC 5869 |

## 4. Key Derivation

See [TEST-VECTORS.md](./TEST-VECTORS.md#1-key-derivation) for canonical test vectors to verify your implementation.

### 4.1 Encryption Key Pair

Each participant derives an X25519 key pair from their Algorand account seed:

```
seed = algorand_account_private_key[0:32]  // First 32 bytes
salt = "AlgoChat-v1-encryption"
info = "x25519-key"

encryption_seed = HKDF-SHA256(seed, salt, info, 32)
private_key = encryption_seed
public_key = X25519_PUBLIC(private_key)
```

### 4.2 Ephemeral Key Pair

Each message uses a fresh ephemeral key pair:

```
ephemeral_private = RANDOM(32)
ephemeral_public = X25519_PUBLIC(ephemeral_private)
```

## 5. Envelope Format

### 5.1 Wire Format

```
┌─────────────────────────────────────────────────────────────────┐
│ version (1) │ protocol (1) │ sender_pubkey (32) │ ephemeral (32)│
├─────────────────────────────────────────────────────────────────┤
│ nonce (12) │ encrypted_sender_key (48) │ ciphertext (variable) │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Field Definitions

| Field | Size | Description |
|-------|------|-------------|
| version | 1 byte | Protocol version (0x01) |
| protocol | 1 byte | Protocol identifier (0x01 = AlgoChat) |
| sender_pubkey | 32 bytes | Sender's X25519 public key |
| ephemeral_pubkey | 32 bytes | Per-message ephemeral public key |
| nonce | 12 bytes | Random nonce for ChaCha20-Poly1305 |
| encrypted_sender_key | 48 bytes | Encrypted symmetric key for sender (32 + 16 tag) |
| ciphertext | variable | Encrypted message + 16-byte auth tag |

### 5.3 Size Constraints

- **Header size**: 126 bytes (fixed)
- **Algorand note limit**: 1024 bytes
- **Maximum ciphertext**: 898 bytes (1024 - 126)
- **Maximum plaintext**: 882 bytes (898 - 16 auth tag)

## 6. Encryption

### 6.1 Message Encryption (Sender → Recipient)

```
// Generate ephemeral key pair
ephemeral_private, ephemeral_public = GENERATE_KEYPAIR()

// Derive shared secret with recipient
shared_secret = X25519(ephemeral_private, recipient_public_key)

// Derive symmetric key
info = "AlgoChatV1" || sender_public_key || recipient_public_key
symmetric_key = HKDF-SHA256(shared_secret, ephemeral_public, info, 32)

// Encrypt message
nonce = RANDOM(12)
ciphertext = ChaCha20-Poly1305-ENCRYPT(symmetric_key, nonce, plaintext)
```

### 6.2 Sender Key Encryption (Self-Decryption)

To allow the sender to decrypt their own messages:

```
// Derive shared secret with self
sender_shared_secret = X25519(ephemeral_private, sender_public_key)

// Derive sender encryption key
sender_info = "AlgoChatV1-SenderKey" || sender_public_key
sender_encryption_key = HKDF-SHA256(sender_shared_secret, ephemeral_public, sender_info, 32)

// Encrypt the symmetric key
encrypted_sender_key = ChaCha20-Poly1305-ENCRYPT(sender_encryption_key, nonce, symmetric_key)
```

## 7. Decryption

### 7.1 Recipient Decryption

```
// Derive shared secret
shared_secret = X25519(recipient_private_key, ephemeral_public_key)

// Derive symmetric key
info = "AlgoChatV1" || sender_public_key || recipient_public_key
symmetric_key = HKDF-SHA256(shared_secret, ephemeral_public_key, info, 32)

// Decrypt message
plaintext = ChaCha20-Poly1305-DECRYPT(symmetric_key, nonce, ciphertext)
```

### 7.2 Sender Decryption (Own Messages)

```
// Derive shared secret with self
sender_shared_secret = X25519(sender_private_key, ephemeral_public_key)

// Derive sender decryption key
sender_info = "AlgoChatV1-SenderKey" || sender_public_key
sender_decryption_key = HKDF-SHA256(sender_shared_secret, ephemeral_public_key, sender_info, 32)

// Decrypt the symmetric key
symmetric_key = ChaCha20-Poly1305-DECRYPT(sender_decryption_key, nonce, encrypted_sender_key)

// Decrypt message
plaintext = ChaCha20-Poly1305-DECRYPT(symmetric_key, nonce, ciphertext)
```

## 8. Message Payload

### 8.1 Text Message

```json
{
    "text": "Hello, world!"
}
```

### 8.2 Reply Message

```json
{
    "text": "This is a reply",
    "replyTo": {
        "txid": "ABC123...",
        "preview": "Original message preview..."
    }
}
```

### 8.3 Key Publish

Used to publish encryption public key for key discovery:

```json
{
    "type": "key-publish",
    "publicKey": "<base64-encoded-public-key>"
}
```

## 9. Transport Layer

### 9.1 Algorand Transaction

Messages are sent as payment transactions:

```
{
    "type": "pay",
    "sender": "<sender-algorand-address>",
    "receiver": "<recipient-algorand-address>",
    "amount": 0,
    "note": "<encrypted-envelope-bytes>"
}
```

### 9.2 Key Discovery

To message someone, you need their X25519 public key. Discovery methods:

1. **Transaction History** - Scan recipient's sent transactions for `sender_pubkey` in envelopes
2. **Key Publish Transaction** - Look for key-publish messages sent to self
3. **Out-of-Band** - Exchange keys through another channel

**Filtering for AlgoChat transactions:**

When querying the indexer, filter by note prefix `0x0101` (version byte + protocol byte):

```
notePrefix = [0x01, 0x01]
```

This efficiently filters transactions to only those with AlgoChat envelopes. See [IMPLEMENTATION.md](./IMPLEMENTATION.md) for pseudocode examples.

## 10. Security Considerations

### 10.1 Forward Secrecy

Each message uses a fresh ephemeral key pair. Compromise of long-term keys does not reveal past messages.

### 10.2 Replay Protection

The blockchain provides replay protection through transaction uniqueness.

### 10.3 Metadata Leakage

The following metadata is visible on-chain:
- Sender Algorand address
- Recipient Algorand address
- Timestamp (block time)
- Message size (approximate)

### 10.4 Key Compromise

If a recipient's private key is compromised:
- Past messages remain secure (forward secrecy)
- Future messages to that key are compromised
- Sender's copies remain secure (different key derivation)

## 11. Constants

```
PROTOCOL_VERSION = 0x01
PROTOCOL_ID = 0x01
MAX_NOTE_SIZE = 1024
HEADER_SIZE = 126
MAX_PAYLOAD_SIZE = 882

KEY_DERIVATION_SALT = "AlgoChat-v1-encryption"
KEY_DERIVATION_INFO = "x25519-key"
ENCRYPTION_INFO_PREFIX = "AlgoChatV1"
SENDER_KEY_INFO_PREFIX = "AlgoChatV1-SenderKey"
```

## 12. Test Vectors

See [TEST-VECTORS.md](./TEST-VECTORS.md) for canonical test vectors that enable cross-implementation verification.

## 13. Version History

| Version | Changes |
|---------|---------|
| 1.0 | Initial specification |
