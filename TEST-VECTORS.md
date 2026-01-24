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
  salt = "AlgoChat-v1-encryption" (UTF-8)
  info = "x25519-key" (UTF-8)

Expected Output:
  encryption_seed = HKDF-SHA256(seed, salt, info, 32)
  encryption_seed_hex = "1bd5f8356b720b8fc639fdd240409d4f76fa0ec52ebcd5351e80235d1ceed32f"
  public_key_hex      = "7e8d332a8d69b9a69fd394b5dfb9716b1ec442482c7374c257dbb1f7a61e1014"
```

### Test Case 1.2: Key Derivation from Non-Zero Seed

Given a 32-byte seed (0x01 repeated):

```
Input:
  seed = 0x0101010101010101010101010101010101010101010101010101010101010101
  salt = "AlgoChat-v1-encryption" (UTF-8)
  info = "x25519-key" (UTF-8)

Expected Output:
  encryption_seed_hex = "d94c1062a49c32ef69e3dc1c26c2fb06ca5d4e70b437c98ee12ea84e4d6e708c"
  public_key_hex      = "cec4b54db91870aef26b5fb00a5cad74a146c69ab5bd241ba8247e977e3ee86c"
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

Using deterministic keys for reproducible results. **WARNING**: In production, ephemeral keys and nonces MUST be randomly generated. These deterministic values are for testing only.

```
Sender (seed 0x01 repeated):
  private_key = d94c1062a49c32ef69e3dc1c26c2fb06ca5d4e70b437c98ee12ea84e4d6e708c
  public_key  = cec4b54db91870aef26b5fb00a5cad74a146c69ab5bd241ba8247e977e3ee86c

Recipient (seed 0x02 repeated):
  private_key = 65f0757ead8b4214b1fe3374eb309cfd4c8d70fb8f3b3cd7152d5d031a5c32ee
  public_key  = 5d5da7177c24372f08fbd5f2acaf1a94296a9fd1d747e03a370ab162ed484d09

Ephemeral (derived from seed 0x03 repeated - TEST ONLY):
  private_key = 28d42355e2702856cf164e837854636bfaf31bbf3c67b845d52967f1f0fd1624
  public_key  = a56fa4362f0646d8818192d769727ca9dca7fc60730b69b632fc7bb370757f53

Nonce (TEST ONLY): 040404040404040404040404

Plaintext (JSON): {"text":"Hello, AlgoChat!"}
Plaintext (hex):  7b2274657874223a2248656c6c6f2c20416c676f4368617421227d

Intermediate Values:
  shared_secret (eph→recipient) = 3d4a443a1a0cafb7bb0eee148334f307e862ba9b5d517b475c903f8245ff1750
  symmetric_key                 = 46c424fb9d8004597f8ebd3d13f6c76147e0f483f51eb7ecf92ba13c84a52df6
  shared_secret (eph→sender)    = 86a66e48b0821f96ec63514f37ab235c2805bdb4b1b2fce695ff8a75c287eb16
  sender_encryption_key         = 98f6d0a310b1e690cb57fd709b2ab3abf4800430979128daccc724f278e08c2c

Expected Outputs:
  ciphertext (43 bytes):           fe1961dd7e1b600f439b401d2e68ed121ccc9ee49affb0c854e4676ce4da495edf12944cb1aa5431e1ce98
  encrypted_sender_key (48 bytes): da920f09c621960fa09f1da7218c88dd53e6a04a6053635c9c38aa9dfb52f142809219686c92e5d8c438dbf66318db24

Full Envelope (169 bytes):
  0101cec4b54db91870aef26b5fb00a5cad74a146c69ab5bd241ba8247e977e3ee86c
  a56fa4362f0646d8818192d769727ca9dca7fc60730b69b632fc7bb370757f53
  040404040404040404040404
  da920f09c621960fa09f1da7218c88dd53e6a04a6053635c9c38aa9dfb52f142809219686c92e5d8c438dbf66318db24
  fe1961dd7e1b600f439b401d2e68ed121ccc9ee49affb0c854e4676ce4da495edf12944cb1aa5431e1ce98
```

**Verification Steps:**

1. Derive sender encryption keys from sender seed
2. Derive recipient encryption keys from recipient seed
3. Parse envelope and verify fields match expected values
4. Decrypt as recipient - must return exact plaintext
5. Decrypt as sender (via encrypted_sender_key) - must return exact plaintext

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
UTF-8 Constants (hex):
  "AlgoChat-v1-encryption" = 416c676f436861742d76312d656e6372797074696f6e (22 bytes)
  "x25519-key"             = 7832353531392d6b6579 (10 bytes)
  "AlgoChatV1"             = 416c676f436861745631 (10 bytes)
  "AlgoChatV1-SenderKey"   = 416c676f4368617456312d53656e6465724b6579 (20 bytes)

Protocol Constants:
  version    = 0x01
  protocol   = 0x01
  notePrefix = 0x0101  (used for key discovery transaction filtering)
```
