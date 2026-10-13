// Offline research only. This is not an AlgoChat protocol implementation.
import assert from "node:assert/strict";
import {
    createCipheriv, createDecipheriv, decapsulate, encapsulate,
    generateKeyPairSync, randomBytes, timingSafeEqual, webcrypto,
} from "node:crypto";
import { performance } from "node:perf_hooks";

const parameters = [
    { name: "ML-KEM-512", category: 1, publicKeyBytes: 800, ciphertextBytes: 768 },
    { name: "ML-KEM-768", category: 3, publicKeyBytes: 1184, ciphertextBytes: 1088 },
    { name: "ML-KEM-1024", category: 5, publicKeyBytes: 1568, ciphertextBytes: 1568 },
];
const noteLimit = 1024;
const senderWrapBytes = 48;
const iterations = 16;
const results = [];

function noteCount(payloadBytes, framingBytes) {
    assert(Number.isSafeInteger(payloadBytes) && payloadBytes > 0);
    assert(Number.isSafeInteger(framingBytes) && framingBytes >= 0 && framingBytes < noteLimit);
    return Math.ceil(payloadBytes / (noteLimit - framingBytes));
}

function median(samples) {
    const sorted = [...samples].sort((a, b) => a - b);
    return sorted[Math.floor(sorted.length / 2)];
}

function encrypt(key, nonce, aad, plaintext) {
    const cipher = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad);
    return {
        ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final()]),
        tag: cipher.getAuthTag(),
    };
}

function decrypt(key, nonce, aad, encrypted) {
    const cipher = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    cipher.setAAD(aad);
    cipher.setAuthTag(encrypted.tag);
    return Buffer.concat([cipher.update(encrypted.ciphertext), cipher.final()]);
}

// Boundaries discriminate framing cost; they are not a proposed wire format.
assert.equal(noteCount(1024, 0), 1);
assert.equal(noteCount(1025, 0), 2);
assert.equal(noteCount(1568 + senderWrapBytes, 64), 2);
assert.equal(noteCount(1568 + senderWrapBytes, 224), 3);
assert.equal(noteCount(1088 + senderWrapBytes, 224), 2);
assert.throws(() => noteCount(1, 1024));
assert.throws(() => noteCount(1, -1));

for (const parameter of parameters) {
    const algorithm = parameter.name.toLowerCase();
    const keyPair = generateKeyPairSync(algorithm);
    const otherPair = generateKeyPairSync(algorithm);
    const spki = keyPair.publicKey.export({ type: "spki", format: "der" });
    const imported = await webcrypto.subtle.importKey(
        "spki", spki, { name: parameter.name }, true, ["encapsulateBits"],
    );
    const rawKey = await webcrypto.subtle.exportKey("raw-public", imported);
    assert.equal(rawKey.byteLength, parameter.publicKeyBytes);

    const samples = { encapsulate: [], decapsulate: [] };
    let last;
    for (let iteration = 0; iteration < iterations; iteration++) {
        const start = performance.now();
        const encapsulated = encapsulate(keyPair.publicKey);
        const middle = performance.now();
        const recovered = decapsulate(keyPair.privateKey, encapsulated.ciphertext);
        const end = performance.now();
        assert.equal(encapsulated.ciphertext.length, parameter.ciphertextBytes);
        assert.equal(encapsulated.sharedKey.length, 32);
        assert.equal(timingSafeEqual(recovered, encapsulated.sharedKey), true, "shared secrets must match");
        samples.encapsulate.push(middle - start);
        samples.decapsulate.push(end - middle);
        last?.sharedKey.fill(0);
        recovered.fill(0);
        last = encapsulated;
    }

    const nonce = randomBytes(12);
    const aad = Buffer.from("offline-pq-spike-only");
    const plaintext = Buffer.from("local test payload");
    const encrypted = encrypt(last.sharedKey, nonce, aad, plaintext);
    assert.deepEqual(decrypt(last.sharedKey, nonce, aad, encrypted), plaintext);

    // Correct-length invalid ciphertexts yield an implicit rejection secret.
    // An application must authenticate its payload, not expect a KEM exception.
    for (const index of [0, Math.floor(last.ciphertext.length / 2), last.ciphertext.length - 1]) {
        const corrupt = Buffer.from(last.ciphertext);
        corrupt[index] ^= 1;
        const rejectedKey = decapsulate(keyPair.privateKey, corrupt);
        assert.equal(rejectedKey.length, 32);
        assert.equal(timingSafeEqual(rejectedKey, last.sharedKey), false, "corruption must change the shared secret");
        assert.throws(() => decrypt(rejectedKey, nonce, aad, encrypted));
        rejectedKey.fill(0);
    }
    const wrongKey = decapsulate(otherPair.privateKey, last.ciphertext);
    assert.equal(timingSafeEqual(wrongKey, last.sharedKey), false, "wrong recipient must change the shared secret");
    assert.throws(() => decrypt(wrongKey, nonce, aad, encrypted));
    wrongKey.fill(0);
    const zeroCiphertextKey = decapsulate(keyPair.privateKey, Buffer.alloc(last.ciphertext.length));
    assert.equal(timingSafeEqual(zeroCiphertextKey, last.sharedKey), false, "zero ciphertext must change the secret");
    assert.throws(() => decrypt(zeroCiphertextKey, nonce, aad, encrypted));
    zeroCiphertextKey.fill(0);
    for (const length of [0, last.ciphertext.length - 1, last.ciphertext.length + 1]) {
        assert.throws(() => decapsulate(keyPair.privateKey, Buffer.alloc(length)));
    }
    assert.throws(() => decrypt(last.sharedKey, nonce, Buffer.from("different transcript"), encrypted));
    const badTag = { ...encrypted, tag: Buffer.from(encrypted.tag) };
    badTag.tag[0] ^= 1;
    assert.throws(() => decrypt(last.sharedKey, nonce, aad, badTag));
    last.sharedKey.fill(0);

    results.push({
        ...parameter,
        iterations,
        negativeCasesPassed: 10,
        medianMs: {
            encapsulate: Number(median(samples.encapsulate).toFixed(4)),
            decapsulate: Number(median(samples.decapsulate).toFixed(4)),
        },
        assumedFraming: [32, 64, 128, 224, 256].map((framingBytes) => ({
            framingBytes,
            keyAnnouncementNotes: noteCount(parameter.publicKeyBytes, framingBytes),
            handshakeNotesWithSenderWrap: noteCount(parameter.ciphertextBytes + senderWrapBytes, framingBytes),
        })),
    });
}

console.log(JSON.stringify({
    status: "offline-research-checks-passed",
    node: process.versions.node,
    openssl: process.versions.openssl,
    noteLimit,
    senderWrapBytes,
    results,
    limits: [
        "No AlgoChat transport, authentication, hybrid combiner or recovery integration is implemented.",
        "Node and its Web Crypto API use the same OpenSSL backend; this is not an independent implementation comparison.",
        "Random round trips and adversarial cases are not NIST known-answer testing, FIPS validation, a timing audit or evidence of quantum resistance.",
        "Framing sizes are explicit budget assumptions, not a negotiated or accepted protocol format.",
    ],
}, null, 2));
