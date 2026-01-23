# AlgoChat Implementation Guide

Language-agnostic pseudocode for implementing the AlgoChat protocol.

## Dependencies

Your implementation needs:

1. **X25519** - Elliptic curve Diffie-Hellman
2. **ChaCha20-Poly1305** - Authenticated encryption
3. **HKDF-SHA256** - Key derivation
4. **Algorand SDK** - Transaction creation and submission

## Core Functions

### Key Derivation

```pseudocode
function deriveEncryptionKeys(algorandSeed: bytes[32]) -> KeyPair:
    salt = encode("AlgoChat-v1-encryption")
    info = encode("x25519-key")

    encryptionSeed = HKDF_SHA256(
        ikm: algorandSeed,
        salt: salt,
        info: info,
        length: 32
    )

    privateKey = encryptionSeed
    publicKey = X25519_GetPublicKey(privateKey)

    return KeyPair(privateKey, publicKey)
```

### Ephemeral Key Generation

```pseudocode
function generateEphemeralKeyPair() -> KeyPair:
    privateKey = secureRandomBytes(32)
    publicKey = X25519_GetPublicKey(privateKey)
    return KeyPair(privateKey, publicKey)
```

### Message Encryption

```pseudocode
function encryptMessage(
    plaintext: string,
    senderPrivateKey: bytes[32],
    senderPublicKey: bytes[32],
    recipientPublicKey: bytes[32]
) -> Envelope:

    messageBytes = encode(plaintext)

    if length(messageBytes) > 882:
        throw Error("Message too large")

    // Generate ephemeral key pair
    ephemeral = generateEphemeralKeyPair()

    // Derive shared secret with recipient
    sharedSecret = X25519_ECDH(ephemeral.privateKey, recipientPublicKey)

    // Derive symmetric key
    info = concat("AlgoChatV1", senderPublicKey, recipientPublicKey)
    symmetricKey = HKDF_SHA256(
        ikm: sharedSecret,
        salt: ephemeral.publicKey,
        info: info,
        length: 32
    )

    // Encrypt message
    nonce = secureRandomBytes(12)
    ciphertext = ChaCha20Poly1305_Encrypt(symmetricKey, nonce, messageBytes)

    // Encrypt symmetric key for sender (bidirectional decryption)
    senderSharedSecret = X25519_ECDH(ephemeral.privateKey, senderPublicKey)
    senderInfo = concat("AlgoChatV1-SenderKey", senderPublicKey)
    senderEncryptionKey = HKDF_SHA256(
        ikm: senderSharedSecret,
        salt: ephemeral.publicKey,
        info: senderInfo,
        length: 32
    )
    encryptedSenderKey = ChaCha20Poly1305_Encrypt(senderEncryptionKey, nonce, symmetricKey)

    return Envelope(
        version: 0x01,
        protocolId: 0x01,
        senderPublicKey: senderPublicKey,
        ephemeralPublicKey: ephemeral.publicKey,
        nonce: nonce,
        encryptedSenderKey: encryptedSenderKey,
        ciphertext: ciphertext
    )
```

### Message Decryption

```pseudocode
function decryptMessage(
    envelope: Envelope,
    myPrivateKey: bytes[32],
    myPublicKey: bytes[32]
) -> string | null:

    weAreSender = (myPublicKey == envelope.senderPublicKey)

    if weAreSender:
        plaintext = decryptAsSender(envelope, myPrivateKey, myPublicKey)
    else:
        plaintext = decryptAsRecipient(envelope, myPrivateKey, myPublicKey)

    // Check for special payload types
    payload = parseJSON(plaintext)
    if payload.type == "key-publish":
        return null  // Not a user message

    return payload.text


function decryptAsRecipient(
    envelope: Envelope,
    recipientPrivateKey: bytes[32],
    recipientPublicKey: bytes[32]
) -> bytes:

    // Derive shared secret
    sharedSecret = X25519_ECDH(recipientPrivateKey, envelope.ephemeralPublicKey)

    // Derive symmetric key
    info = concat("AlgoChatV1", envelope.senderPublicKey, recipientPublicKey)
    symmetricKey = HKDF_SHA256(
        ikm: sharedSecret,
        salt: envelope.ephemeralPublicKey,
        info: info,
        length: 32
    )

    // Decrypt message
    return ChaCha20Poly1305_Decrypt(symmetricKey, envelope.nonce, envelope.ciphertext)


function decryptAsSender(
    envelope: Envelope,
    senderPrivateKey: bytes[32],
    senderPublicKey: bytes[32]
) -> bytes:

    // Derive shared secret with self
    sharedSecret = X25519_ECDH(senderPrivateKey, envelope.ephemeralPublicKey)

    // Derive sender decryption key
    senderInfo = concat("AlgoChatV1-SenderKey", senderPublicKey)
    senderDecryptionKey = HKDF_SHA256(
        ikm: sharedSecret,
        salt: envelope.ephemeralPublicKey,
        info: senderInfo,
        length: 32
    )

    // Decrypt the symmetric key
    symmetricKey = ChaCha20Poly1305_Decrypt(
        senderDecryptionKey,
        envelope.nonce,
        envelope.encryptedSenderKey
    )

    // Decrypt message
    return ChaCha20Poly1305_Decrypt(symmetricKey, envelope.nonce, envelope.ciphertext)
```

### Envelope Serialization

```pseudocode
function serializeEnvelope(envelope: Envelope) -> bytes:
    return concat(
        [envelope.version],           // 1 byte
        [envelope.protocolId],        // 1 byte
        envelope.senderPublicKey,     // 32 bytes
        envelope.ephemeralPublicKey,  // 32 bytes
        envelope.nonce,               // 12 bytes
        envelope.encryptedSenderKey,  // 48 bytes
        envelope.ciphertext           // variable
    )


function deserializeEnvelope(data: bytes) -> Envelope:
    if length(data) < 126:
        throw Error("Envelope too short")

    version = data[0]
    protocolId = data[1]

    if version != 0x01 or protocolId != 0x01:
        throw Error("Unknown protocol version")

    return Envelope(
        version: version,
        protocolId: protocolId,
        senderPublicKey: data[2:34],
        ephemeralPublicKey: data[34:66],
        nonce: data[66:78],
        encryptedSenderKey: data[78:126],
        ciphertext: data[126:]
    )
```

### Transaction Creation

```pseudocode
function createMessageTransaction(
    sender: AlgorandAddress,
    recipient: AlgorandAddress,
    envelope: Envelope,
    algodClient: AlgodClient
) -> SignedTransaction:

    params = algodClient.getTransactionParams()

    txn = PaymentTransaction(
        sender: sender,
        receiver: recipient,
        amount: 0,
        note: serializeEnvelope(envelope),
        suggestedParams: params
    )

    return txn
```

### Key Discovery

```pseudocode
function discoverPublicKey(
    address: AlgorandAddress,
    indexerClient: IndexerClient
) -> bytes[32] | null:

    // Search sent transactions
    transactions = indexerClient.searchTransactions(
        sender: address,
        notePrefix: [0x01, 0x01],  // version + protocol
        limit: 100
    )

    for txn in transactions:
        try:
            envelope = deserializeEnvelope(txn.note)
            return envelope.senderPublicKey
        catch:
            continue

    return null
```

## Data Structures

```pseudocode
struct KeyPair:
    privateKey: bytes[32]
    publicKey: bytes[32]

struct Envelope:
    version: uint8
    protocolId: uint8
    senderPublicKey: bytes[32]
    ephemeralPublicKey: bytes[32]
    nonce: bytes[12]
    encryptedSenderKey: bytes[48]
    ciphertext: bytes[]

struct Message:
    id: string           // Transaction ID
    sender: string       // Algorand address
    recipient: string    // Algorand address
    content: string      // Decrypted text
    timestamp: DateTime
    direction: "sent" | "received"
    replyContext?: ReplyContext

struct ReplyContext:
    txid: string
    preview: string

struct MessagePayload:
    text: string
    replyTo?: ReplyReference

struct ReplyReference:
    txid: string
    preview: string

struct KeyPublishPayload:
    type: "key-publish"
    publicKey: string  // Base64 encoded
```

## Error Handling

```pseudocode
enum AlgoChatError:
    INVALID_ENVELOPE      // Malformed envelope data
    UNKNOWN_VERSION       // Unsupported protocol version
    DECRYPTION_FAILED     // Authentication tag mismatch
    MESSAGE_TOO_LARGE     // Exceeds 882 byte limit
    KEY_NOT_FOUND         // Could not discover recipient key
    TRANSACTION_FAILED    // Blockchain submission error
```

## Testing Vectors

### Key Derivation Test

```
Input seed (hex): 0x0000...0000 (32 zero bytes)
Salt: "AlgoChat-v1-encryption"
Info: "x25519-key"

Expected private key (hex): <implementation-specific>
Expected public key (hex): <implementation-specific>
```

### Encryption Test

Use known test vectors to verify your implementation matches other implementations.

## Security Checklist

- [ ] Use cryptographically secure random number generator
- [ ] Clear sensitive data from memory after use
- [ ] Validate envelope format before processing
- [ ] Handle decryption failures gracefully
- [ ] Never log or expose private keys
- [ ] Use constant-time comparison for authentication tags
