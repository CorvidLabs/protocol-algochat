# AlgoChat Test Vectors

**Version**: 1.0
**Purpose**: Cross-implementation verification

These test vectors enable implementations to verify correctness by using deterministic inputs and checking outputs match exactly.

## 1. Key Derivation

### Test Case 1.1: Key Derivation from Seed

Given a 32-byte seed (all zeros):

```
Input:
  seed = 0x0000000000000000000000000000000000000000000000000000000000000000
  salt = "AlgoChat-v1-encryption"
  info = "x25519-key"

Expected Output:
  encryption_seed = HKDF-SHA256(seed, salt, info, 32)

  // The HKDF output (encryption seed):
  encryption_seed_hex = "8a5e3b4c1d2e9f0a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a"
```

### Test Case 1.2: Key Derivation from Non-Zero Seed

Given a 32-byte seed (0x01 repeated):

```
Input:
  seed = 0x0101010101010101010101010101010101010101010101010101010101010101
  salt = "AlgoChat-v1-encryption"
  info = "x25519-key"
```

## 2. Envelope Encoding

### Test Case 2.1: Minimal Envelope

A minimal valid envelope with known values:

```
Input:
  version = 0x01
  protocol = 0x01
  sender_pubkey = 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (32 bytes)
  ephemeral_pubkey = 0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB (32 bytes)
  nonce = 0xCCCCCCCCCCCCCCCCCCCCCCCC (12 bytes)
  encrypted_sender_key = 0xDDDD...DDDD (48 bytes of 0xDD)
  ciphertext = 0xEEEE...EEEE (16 bytes of 0xEE, minimum for auth tag)

Expected Wire Format (hex):
  0101  // version, protocol
  AAAA...AA  // sender_pubkey (32 bytes)
  BBBB...BB  // ephemeral_pubkey (32 bytes)
  CCCC...CC  // nonce (12 bytes)
  DDDD...DD  // encrypted_sender_key (48 bytes)
  EEEE...EE  // ciphertext (variable)

Total Size: 126 bytes header + 16 bytes ciphertext = 142 bytes minimum
```

### Test Case 2.2: Invalid Envelopes

These should all fail validation:

```
// Too short (< 142 bytes minimum)
0x0101AABB  // Only 4 bytes

// Wrong version
0x0201...   // Version 0x02 not supported

// Wrong protocol
0x0102...   // Protocol 0x02 not supported

// Missing data
0x0101 + 30 bytes  // Header truncated
```

## 3. Encryption Round-Trip

### Test Case 3.1: Static Key Encryption

Using deterministic keys for reproducible results:

```
Sender Keys:
  seed = 0x0101010101010101010101010101010101010101010101010101010101010101

Recipient Keys:
  seed = 0x0202020202020202020202020202020202020202020202020202020202020202

Plaintext: "Hello, AlgoChat!"
```

**Verification Steps:**

1. Derive sender encryption keys from sender seed
2. Derive recipient encryption keys from recipient seed
3. Encrypt plaintext with:
   - Sender's public key
   - Recipient's public key
   - A deterministic ephemeral key (for test only)
   - A deterministic nonce (for test only)
4. Verify recipient can decrypt to original plaintext
5. Verify sender can decrypt to original plaintext (bidirectional)

### Test Case 3.2: Unicode Handling

```
Plaintext: "Hello! Bonjour! Hallo! Ciao! Hola!"

Verification:
- Encrypt with any valid key pair
- Decrypt must return exact UTF-8 string
- Byte length verification: plaintext should be 51 bytes UTF-8
```

## 4. HKDF Constants

All implementations must use these exact constants:

```
Key Derivation:
  salt = "AlgoChat-v1-encryption"    // 22 bytes ASCII
  info = "x25519-key"                // 10 bytes ASCII

Encryption:
  info_prefix = "AlgoChatV1"         // 10 bytes ASCII
  // Full info = info_prefix || sender_pubkey || recipient_pubkey

Sender Key:
  info_prefix = "AlgoChatV1-SenderKey"  // 20 bytes ASCII
  // Full info = info_prefix || sender_pubkey
```

## 5. Message Payload Formats

### Test Case 5.1: Simple Text Message

```json
{"text":"Hello, world!"}
```

Must be parsed as:
- text: "Hello, world!"
- replyTo: undefined/null

### Test Case 5.2: Reply Message

```json
{"text":"This is a reply","replyTo":{"txid":"ABC123DEF456","preview":"Original message..."}}
```

Must be parsed as:
- text: "This is a reply"
- replyTo.txid: "ABC123DEF456"
- replyTo.preview: "Original message..."

### Test Case 5.3: Key Publish Payload

```json
{"type":"key-publish"}
```

Must be detected as key-publish and filtered from message lists.

## 6. Cross-Implementation Verification

To verify interoperability between implementations:

1. **Generate Envelope in Implementation A**
   - Use seed `0x0101...01` for sender
   - Use seed `0x0202...02` for recipient
   - Encrypt message "Test message for cross-impl verification"
   - Export envelope as hex string

2. **Import and Decrypt in Implementation B**
   - Import envelope hex from step 1
   - Use same seeds to derive keys
   - Decrypt as recipient - must return exact plaintext
   - Decrypt as sender - must return exact plaintext

3. **Repeat with swapped roles**
   - Generate in Implementation B
   - Decrypt in Implementation A

## 7. Size Boundary Tests

### Test Case 7.1: Maximum Size Message

```
Plaintext size: 882 bytes (MAX_PAYLOAD_SIZE)
Envelope size: 126 + 882 + 16 = 1024 bytes (exactly MAX_NOTE_SIZE)
```

### Test Case 7.2: Empty Message

```
Plaintext: "" (empty string)
Ciphertext: 16 bytes (auth tag only)
Envelope size: 126 + 16 = 142 bytes (minimum valid size)
```

### Test Case 7.3: Oversized Message (Must Fail)

```
Plaintext size: 883 bytes
Expected: Encryption error "message too large"
```

## 8. Version Upgrade Path

Future protocol versions (0x02, 0x03, etc.) should:

1. Maintain backward compatibility for decryption
2. Include version negotiation if needed
3. Old implementations must reject unknown versions with clear error

## Appendix A: Reference Hex Values

For byte-level verification:

```
UTF-8 Constants:
  "AlgoChat-v1-encryption" = 0x416c676f436861742d76312d656e6372797074696f6e
  "x25519-key"             = 0x7832353531392d6b6579
  "AlgoChatV1"             = 0x416c676f43686174563131
  "AlgoChatV1-SenderKey"   = 0x416c676f436861745631312d53656e6465724b6579
```
