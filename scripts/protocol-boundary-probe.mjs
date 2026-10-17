/**
 * Research/reference harness for the shipped AlgoChat 1.2 envelope.
 *
 * It checks published TEST-VECTORS.md bytes with Node's built-in X25519,
 * HKDF-SHA256, and ChaCha20-Poly1305. A passing run does not audit Raven,
 * prove that a client validates notes, bind a transaction signature, persist
 * replay state, or qualify a registered implementation.
 *
 * ML-KEM sizes and the shelved pair-secret proposal are not measured here.
 * Ephemeral keys and nonces are the published test patterns, not mnemonics,
 * and this file does not send transactions or open a network connection.
 */

import {
    createCipheriv,
    createDecipheriv,
    createHash,
    createPrivateKey,
    createPublicKey,
    diffieHellman,
    hkdfSync,
} from "node:crypto";
import path from "node:path";
import { pathToFileURL } from "node:url";

const PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
const AEAD_FAILURE = "Unsupported state or unable to authenticate data";

export const PROTOCOL_VERSION = 0x01;
export const PROTOCOL_STANDARD = 0x01;
export const PROTOCOL_PSK = 0x02;
export const COUNTER_WINDOW = 200;
export const PSK_SESSION_SIZE = 100;
export const MAX_NOTE_SIZE = 1024;
export const HEADER_SIZE = 126;
export const PSK_HEADER_SIZE = 130;
export const TAG_SIZE = 16;
export const MAX_PLAINTEXT = 882;
export const PSK_MAX_PLAINTEXT = 878;

export const LAYOUT = Object.freeze({
    standard: Object.freeze({
        header: HEADER_SIZE,
        minimumWithTag: HEADER_SIZE + TAG_SIZE,
        maxPlaintext: MAX_PLAINTEXT,
        sender: 2,
        ephemeral: 34,
        nonce: 66,
        wrap: 78,
        ciphertext: HEADER_SIZE,
    }),
    psk: Object.freeze({
        header: PSK_HEADER_SIZE,
        minimumWithTag: PSK_HEADER_SIZE + TAG_SIZE,
        maxPlaintext: PSK_MAX_PLAINTEXT,
        counter: 2,
        sender: 6,
        ephemeral: 38,
        nonce: 70,
        wrap: 82,
        ciphertext: PSK_HEADER_SIZE,
    }),
});

/** Hex literals copied from TEST-VECTORS.md at the pinned base. */
export const PUBLISHED = Object.freeze({
    seed00: "00".repeat(32),
    seed01: "01".repeat(32),
    seed02: "02".repeat(32),
    seed03: "03".repeat(32),
    seed00Private: "1bd5f8356b720b8fc639fdd240409d4f76fa0ec52ebcd5351e80235d1ceed32f",
    seed00Public: "7e8d332a8d69b9a69fd394b5dfb9716b1ec442482c7374c257dbb1f7a61e1014",
    seed01Private: "d94c1062a49c32ef69e3dc1c26c2fb06ca5d4e70b437c98ee12ea84e4d6e708c",
    seed01Public: "cec4b54db91870aef26b5fb00a5cad74a146c69ab5bd241ba8247e977e3ee86c",
    seed02Private: "65f0757ead8b4214b1fe3374eb309cfd4c8d70fb8f3b3cd7152d5d031a5c32ee",
    seed02Public: "5d5da7177c24372f08fbd5f2acaf1a94296a9fd1d747e03a370ab162ed484d09",
    seed03Private: "28d42355e2702856cf164e837854636bfaf31bbf3c67b845d52967f1f0fd1624",
    seed03Public: "a56fa4362f0646d8818192d769727ca9dca7fc60730b69b632fc7bb370757f53",
    nonce: "040404040404040404040404",
    plaintextHex: "7b2274657874223a2248656c6c6f2c20416c676f4368617421227d",
    plaintextText: "{\"text\":\"Hello, AlgoChat!\"}",
    sharedRecipient: "3d4a443a1a0cafb7bb0eee148334f307e862ba9b5d517b475c903f8245ff1750",
    symmetricKey: "46c424fb9d8004597f8ebd3d13f6c76147e0f483f51eb7ecf92ba13c84a52df6",
    sharedSender: "86a66e48b0821f96ec63514f37ab235c2805bdb4b1b2fce695ff8a75c287eb16",
    senderKey: "98f6d0a310b1e690cb57fd709b2ab3abf4800430979128daccc724f278e08c2c",
    ciphertext: "fe1961dd7e1b600f439b401d2e68ed121ccc9ee49affb0c854e4676ce4da495edf12944cb1aa5431e1ce98",
    encryptedSenderKey: "da920f09c621960fa09f1da7218c88dd53e6a04a6053635c9c38aa9dfb52f142809219686c92e5d8c438dbf66318db24",
    initialPsk: "aa".repeat(32),
    session0: "a031707ea9e9e50bd8ea4eb9a2bd368465ea1aff14caab293d38954b4717e888",
    position0: "2918fd486b9bd024d712f6234b813c0f4167237d60c2c1fca37326b20497c165",
    position99: "5b48a50a25261f6b63fe9c867b46be46de4d747c3477db6290045ba519a4d38b",
    session1: "994cffbb4f84fa5410d44574bb9fa7408a8c2f1ed2b3a00f5168fc74c71f7cea",
    position100: "7a15d3add6a28858e6a1f1ea0d22bdb29b7e129a1330c4908d9b46a460992694",
    pskSymmetricKey: "cf082d0fbd4d380a5278cc29b3d584ede66f29776f86cbc8c065a9c5705de9d1",
    pskSenderKey: "ca575ea2874b1f074930026f7a2729cc1543f593bc185712e65be4eab6660a59",
    pskCiphertext: "e12310ee1bb20af305c081c781ca5c812851be7463629020db38b18eecb9e1ba17f3cdb5eb3b61b4a0d8af",
    pskEncryptedSenderKey: "1e52d902edadbb55263ded7fdd3cbaf39224813d2b528ac8977ad7a826a2a74965f97d8460a288ee6ed2b1b233b76e62",
    unicodeLiteral: "Hello! Bonjour! Hallo! Ciao! Hola!",
    unicodeDocumentedByteLength: 51,
    payload61: "{\"text\":\"Hello, world!\"}",
    payload62: "{\"text\":\"This is a reply\",\"replyTo\":{\"txid\":\"ABC123DEF456\",\"preview\":\"Original message...\"}}",
    payload63: "{\"type\":\"key-publish\"}",
});

export const VECTOR_44_STATE = Object.freeze({
    peerLastCounter: 50,
    seenCounters: Object.freeze([50]),
});

export const OPEN_DECISIONS = Object.freeze([
    Object.freeze({
        id: "minimum-length",
        topic: "malformed envelope",
        text: "TEST-VECTORS.md rejects standard notes under 142 bytes and PSK notes under 146 bytes. IMPLEMENTATION.md accepts a 126-byte or 130-byte header and leaves a short remainder to decryption. Both are recorded. This harness does not choose a production rule.",
    }),
    Object.freeze({
        id: "psk-check-order",
        topic: "replay",
        text: "PROTOCOL.md section 8.4 checks a seen counter before the window. IMPLEMENTATION.md checks the window before the seen set. They disagree when a counter is both seen and outside the window. The reported error differs. This harness runs both readings.",
    }),
    Object.freeze({
        id: "sender-pubkey-payment-binding",
        topic: "authenticated binding",
        text: "Section 6.1 does not use the sender long-term private key. Section 10.2 names the payment's authorizing signature as the account binding. The decrypt pseudocode does not compare envelope.sender_pubkey with the key known for the transaction sender. Signature checks are outside this registry harness.",
    }),
    Object.freeze({
        id: "sender-unwrap-covers-local-key",
        topic: "authenticated binding",
        text: "decryptAsSender mixes the caller's public key into HKDF. The recipient path mixes envelope.sender_pubkey. Combined dispatch compares those public keys and then picks a branch. The documents do not say whether a client must refuse the sender branch when the payment signature has not covered the field.",
    }),
    Object.freeze({
        id: "initial-peer-counter",
        topic: "replay",
        text: "Section 8.4 does not define peer_last_counter before any message has been accepted. The scripted checks below use the explicit state in Test Case 4.4.",
    }),
    Object.freeze({
        id: "seen-set-pruning",
        topic: "resource budget",
        text: "A seen counter MUST be rejected. A counter outside the window SHOULD be rejected. No rule says a seen counter may be forgotten once it falls behind the window. This harness does not prune.",
    }),
    Object.freeze({
        id: "counter-wrap",
        topic: "replay",
        text: "The ratchet counter is a 32-bit unsigned integer that increments by one. Wrap, saturation, and stopping at 2^32-1 are not specified. This harness does not define them.",
    }),
    Object.freeze({
        id: "unicode-vector-length",
        topic: "test vector",
        text: "Test Case 3.2 prints an ASCII literal and also says the plaintext should be 51 UTF-8 bytes. The literal is 34 bytes. TEST-VECTORS.md was not changed.",
    }),
    Object.freeze({
        id: "key-publish-publickey",
        topic: "payload",
        text: "PROTOCOL.md section 9.3 includes publicKey in a key-publish payload. Test Case 6.3 is {\"type\":\"key-publish\"} with no publicKey. Already listed in docs/HLD.md. Not resolved here.",
    }),
    Object.freeze({
        id: "fragment-split-unit",
        topic: "fragmentation",
        text: "SECURITY.md says longer messages need application-level fragmentation. The envelope has no fragment fields. Whether a larger message is several independent plaintexts or a new protocol byte is not specified.",
    }),
    Object.freeze({
        id: "fragment-identity",
        topic: "fragmentation",
        text: "No field identifies fragments of one logical message. Index, count, message id, and total length are not specified.",
    }),
    Object.freeze({
        id: "fragment-byte-budget",
        topic: "fragmentation",
        text: "Any application marker placed in the current plaintext consumes the 882-byte standard budget or the 878-byte PSK budget. The numbers below are that measurement. They are not a header.",
    }),
    Object.freeze({
        id: "fragment-reassembly-bound",
        topic: "fragmentation",
        text: "No bound is specified for incomplete fragment state: count, stored bytes, time, or open messages.",
    }),
    Object.freeze({
        id: "fragment-duplicate",
        topic: "fragmentation",
        text: "No rule says whether a repeated fragment is a replay, a replacement, or an error. Identical standard envelopes decrypt again; the note itself is not a replay token.",
    }),
    Object.freeze({
        id: "fragment-order",
        topic: "fragmentation",
        text: "No rule says whether out-of-order fragments are accepted, or whether any plaintext is released before the set is complete.",
    }),
    Object.freeze({
        id: "fragment-transport-group",
        topic: "fragmentation",
        text: "No rule says whether related notes must be one atomic Algorand group or may be separate payments.",
    }),
    Object.freeze({
        id: "fragment-transcript",
        topic: "fragmentation",
        text: "No rule says which bytes each fragment authenticates, or whether an outer transcript covers the set.",
    }),
    Object.freeze({
        id: "fragment-psk-counter",
        topic: "fragmentation",
        text: "No rule assigns PSK counters when one logical message occupies more than one note.",
    }),
    Object.freeze({
        id: "fragment-standard-replay",
        topic: "fragmentation",
        text: "Standard mode has no in-envelope replay counter. Section 11.2 places standard replay protection on transaction uniqueness. This harness cannot submit or store transactions.",
    }),
]);

const LIMITS = Object.freeze([
    "This repository is a protocol and document registry. The harness is a research reading of PROTOCOL.md and TEST-VECTORS.md, not a client.",
    "A pass does not audit Raven, prove client validation, bind sig or pqsig, persist replay state, or audit registered implementations.",
    "Node crypto is one implementation of the named primitives. It is not a second independent implementation and it is not an ACVP run.",
    "No ML-KEM parameter, encapsulation, or note-count experiment is run. PR 21 owns that spike.",
    "Falcon-1024 is an account signature in v1.2, not an envelope mode. This harness does not build payments.",
    "Standard-mode replay is specified as blockchain transaction uniqueness. Re-opening the same note succeeds here because no ledger is consulted.",
    "PSK counter decisions are in-memory readings of the two written check orders. They are not durable client state.",
    "The harness does not define fragment reassembly, a downgrade negotiation, or a post-quantum wire format.",
    "Memory wiping and tag-comparison timing are not measured. Authentication failure is taken from Node's AEAD exception.",
]);

/**
 * @param {Buffer} seed
 * @returns {{ privateKey: Buffer, publicKey: Buffer }}
 */
export function deriveKeyPair(seed) {
    const privateKey = hkdf(
        seed,
        Buffer.from("AlgoChat-v1-encryption"),
        Buffer.from("x25519-key"),
    );
    return { privateKey, publicKey: x25519Public(privateKey) };
}

/**
 * @param {Buffer} initialPsk
 * @param {number} counter
 * @returns {{ sessionIndex: number, position: number, sessionPsk: Buffer, positionPsk: Buffer }}
 */
export function derivePosition(initialPsk, counter) {
    if (!isUint32(counter)) {
        throw new Error("counter is outside the 32-bit values this reference derives");
    }
    const sessionIndex = Math.floor(counter / PSK_SESSION_SIZE);
    const position = counter % PSK_SESSION_SIZE;
    const sessionPsk = hkdf(initialPsk, Buffer.from("AlgoChat-PSK-Session"), uint32be(sessionIndex));
    const positionPsk = hkdf(sessionPsk, Buffer.from("AlgoChat-PSK-Position"), uint32be(position));
    return { sessionIndex, position, sessionPsk, positionPsk };
}

/**
 * @param {Buffer} bytes
 * @returns {object}
 */
export function inspectEnvelope(bytes) {
    const buffer = Buffer.from(bytes);
    const inspected = {
        length: buffer.length,
        version: buffer.length > 0 ? buffer[0] : null,
        protocol: buffer.length > 1 ? buffer[1] : null,
        mode: null,
        headerSize: null,
        minimumWithTag: null,
        headerRule: null,
        testVectorRule: null,
        ciphertextLength: null,
        tagComplete: false,
        stop: null,
    };
    if (buffer.length < 2) {
        inspected.stop = { code: "INVALID_ENVELOPE", stage: "parse", reason: "fewer than 2 bytes" };
        return inspected;
    }
    if (buffer[0] !== PROTOCOL_VERSION) {
        inspected.stop = { code: "UNKNOWN_VERSION", stage: "parse", reason: "version is not 0x01" };
        return inspected;
    }
    if (buffer[1] !== PROTOCOL_STANDARD && buffer[1] !== PROTOCOL_PSK) {
        inspected.stop = {
            code: "UNKNOWN_PROTOCOL",
            stage: "parse",
            reason: "protocol is not 0x01 or 0x02",
        };
        return inspected;
    }
    const mode = buffer[1] === PROTOCOL_STANDARD ? "standard" : "psk";
    const layout = LAYOUT[mode];
    inspected.mode = mode;
    inspected.headerSize = layout.header;
    inspected.minimumWithTag = layout.minimumWithTag;
    inspected.headerRule = buffer.length < layout.header ? "INVALID_ENVELOPE" : "ACCEPT";
    inspected.testVectorRule = buffer.length < layout.minimumWithTag ? "INVALID_ENVELOPE" : "ACCEPT";
    if (buffer.length >= layout.header) {
        inspected.ciphertextLength = buffer.length - layout.header;
        inspected.tagComplete = inspected.ciphertextLength >= TAG_SIZE;
    }
    return inspected;
}

/**
 * @param {Buffer} envelope
 * @param {"test-vector" | "header"} lengthRule
 * @returns {object}
 */
export function readFields(envelope, lengthRule) {
    const buffer = Buffer.from(envelope);
    const inspected = inspectEnvelope(buffer);
    if (inspected.stop) {
        return { ok: false, ...inspected.stop, aeadAttempted: false, setupCompleted: false, plaintext: null };
    }
    const rule = lengthRule === "header" ? inspected.headerRule : inspected.testVectorRule;
    if (rule !== "ACCEPT") {
        return {
            ok: false,
            code: "INVALID_ENVELOPE",
            stage: "length",
            mode: inspected.mode,
            lengthRule,
            aeadAttempted: false,
            setupCompleted: false,
            plaintext: null,
        };
    }
    if (!inspected.tagComplete) {
        return {
            ok: false,
            code: "HARNESS_TAG_SHORT",
            stage: "framing",
            mode: inspected.mode,
            lengthRule,
            aeadAttempted: false,
            setupCompleted: false,
            plaintext: null,
        };
    }
    const layout = LAYOUT[inspected.mode];
    const fields = {
        ok: true,
        mode: inspected.mode,
        lengthRule,
        version: buffer[0],
        protocol: buffer[1],
        senderPublicKey: buffer.subarray(layout.sender, layout.sender + 32),
        ephemeralPublicKey: buffer.subarray(layout.ephemeral, layout.ephemeral + 32),
        nonce: buffer.subarray(layout.nonce, layout.nonce + 12),
        encryptedSenderKey: buffer.subarray(layout.wrap, layout.wrap + 48),
        ciphertext: buffer.subarray(layout.ciphertext),
    };
    if (inspected.mode === "psk") {
        fields.counter = buffer.readUInt32BE(layout.counter);
    }
    return fields;
}

/**
 * @param {object} input
 * @returns {object}
 */
export function encryptStandard(input) {
    return encryptMessage(input, "standard");
}

/**
 * @param {object} input
 * @returns {object}
 */
export function encryptPsk(input) {
    return encryptMessage(input, "psk");
}

/**
 * @param {Buffer} envelope
 * @param {object} context
 * @returns {object}
 */
export function openEnvelope(envelope, context) {
    const lengthRule = context.lengthRule ?? "test-vector";
    const fields = readFields(envelope, lengthRule);
    if (!fields.ok) {
        return fields;
    }
    if (fields.mode === "psk" && !Buffer.isBuffer(context.initialPsk)) {
        return {
            ok: false,
            code: "PSK_NOT_FOUND",
            stage: "psk",
            mode: "psk",
            role: context.role ?? null,
            aeadAttempted: false,
            setupCompleted: false,
            plaintext: null,
        };
    }
    if (fields.mode === "psk" && context.initialPsk.length !== 32) {
        return unexpected("psk", "PSK must be 32 bytes before decryption is attempted");
    }
    const role = resolveRole(fields, context);
    if (fields.mode === "psk" && role === "recipient" && context.applyCounterGate === true) {
        const decision = classifyCounter(context.counterState, fields.counter, context.counterOrder ?? "protocol-8.4");
        if (!decision.accepted) {
            return {
                ok: false,
                code: decision.code,
                stage: "counter",
                reason: decision.reason,
                mode: "psk",
                role,
                counter: fields.counter,
                aeadAttempted: false,
                setupCompleted: false,
                plaintext: null,
            };
        }
    }
    if (!Buffer.isBuffer(context.privateKey) || context.privateKey.length !== 32) {
        return unexpected("setup", "a 32-byte private key is required before AEAD");
    }
    if (!Buffer.isBuffer(context.publicKey) || context.publicKey.length !== 32) {
        return unexpected("setup", "a 32-byte public key is required before AEAD");
    }
    const opened = openFields(fields, role, context.privateKey, context.publicKey, context.initialPsk ?? null);
    opened.role = role;
    opened.lengthRule = lengthRule;
    return opened;
}

/**
 * @param {object | null | undefined} state
 * @param {number} counter
 * @param {"protocol-8.4" | "implementation-pseudocode"} order
 * @returns {object}
 */
export function classifyCounter(state, counter, order) {
    if (!isUint32(counter)) {
        return {
            accepted: false,
            code: "HARNESS_COUNTER_UNSPECIFIED",
            reason: "outside the 32-bit values this reference classifies",
            order,
        };
    }
    const normalized = normalizeState(state);
    if (!normalized || (order !== "protocol-8.4" && order !== "implementation-pseudocode")) {
        return {
            accepted: false,
            code: "HARNESS_UNEXPECTED",
            reason: "counter state or order is not one of the two written readings",
            order,
        };
    }
    const tooFarAhead = counter > normalized.peerLastCounter + COUNTER_WINDOW;
    const tooOld = normalized.peerLastCounter > COUNTER_WINDOW
        && counter < normalized.peerLastCounter - COUNTER_WINDOW;
    const replay = normalized.seenCounters.includes(counter);
    const checks = order === "protocol-8.4"
        ? [
            ["replay", replay, "PSK_COUNTER_REPLAY"],
            ["too-old", tooOld, "PSK_COUNTER_OUT_OF_RANGE"],
            ["too-far-ahead", tooFarAhead, "PSK_COUNTER_OUT_OF_RANGE"],
        ]
        : [
            ["too-far-ahead", tooFarAhead, "PSK_COUNTER_OUT_OF_RANGE"],
            ["too-old", tooOld, "PSK_COUNTER_OUT_OF_RANGE"],
            ["replay", replay, "PSK_COUNTER_REPLAY"],
        ];
    for (const [reason, hit, code] of checks) {
        if (hit) {
            return { accepted: false, code, reason, order };
        }
    }
    return { accepted: true, code: "ACCEPT", reason: "unseen-inside-window", order };
}

/**
 * @param {object} state
 * @param {number} counter
 * @param {"protocol-8.4" | "implementation-pseudocode"} order
 * @returns {{ decision: object, state: object }}
 */
export function applyCounter(state, counter, order) {
    const decision = classifyCounter(state, counter, order);
    if (!decision.accepted) {
        return { decision, state: copyState(state) };
    }
    const seenCounters = state.seenCounters.includes(counter)
        ? state.seenCounters.slice()
        : state.seenCounters.concat(counter);
    return {
        decision,
        state: {
            peerLastCounter: Math.max(state.peerLastCounter, counter),
            seenCounters,
        },
    };
}

/**
 * Inclusive uint32 counters the written inequalities accept for a fixed peer last counter.
 * The upper endpoint is capped at 0xffffffff because that is the last value the four-byte
 * field and classifyCounter both treat as a counter. The cap is a measurement of that
 * domain. It does not define rollover, saturation, or sender stopping.
 * @param {number} peerLastCounter
 * @returns {{ low: number, high: number, count: number, mathematicalHigh: number, capped: boolean, domain: "representable-uint32", rolloverDefined: false }}
 */
export function windowSpan(peerLastCounter) {
    if (!isUint32(peerLastCounter)) {
        throw new Error("peer last counter is outside the 32-bit values this reference measures");
    }
    const mathematicalHigh = peerLastCounter + COUNTER_WINDOW;
    const low = peerLastCounter > COUNTER_WINDOW ? peerLastCounter - COUNTER_WINDOW : 0;
    const high = mathematicalHigh > 0xffffffff ? 0xffffffff : mathematicalHigh;
    return {
        low,
        high,
        count: high - low + 1,
        mathematicalHigh,
        capped: high !== mathematicalHigh,
        domain: "representable-uint32",
        rolloverDefined: false,
    };
}

/**
 * @param {number} peerLastCounter
 * @returns {object}
 */
function measuredWindow(peerLastCounter) {
    const span = windowSpan(peerLastCounter);
    const state = { peerLastCounter, seenCounters: [] };
    const order = "protocol-8.4";
    const low = classifyCounter(state, span.low, order).code;
    const high = classifyCounter(state, span.high, order).code;
    const belowLow = span.low === 0 ? null : classifyCounter(state, span.low - 1, order).code;
    const aboveHigh = classifyCounter(state, span.high + 1, order).code;
    return {
        peerLastCounter,
        ...span,
        classifyCounter: { order, low, high, belowLow, aboveHigh },
        endpointsAccepted: low === "ACCEPT" && high === "ACCEPT",
        aboveHighRefused: aboveHigh !== "ACCEPT",
    };
}

/**
 * Bytes left inside the existing plaintext budget. Not a fragment header.
 * @param {"standard" | "psk"} mode
 * @param {number} reservedInsidePlaintext
 * @returns {object}
 */
export function plaintextBudget(mode, reservedInsidePlaintext) {
    const maxPlaintext = mode === "standard" ? MAX_PLAINTEXT : PSK_MAX_PLAINTEXT;
    return {
        mode,
        maxPlaintext,
        reservedInsidePlaintext,
        remainingPlaintext: maxPlaintext - reservedInsidePlaintext,
        wireFormatChanged: false,
    };
}

/**
 * @param {Error | unknown} error
 * @returns {object}
 */
export function classifyAeadError(error) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "ERR_CRYPTO_INVALID_AUTH_TAG") {
        return {
            ok: false,
            code: "HARNESS_SETUP_EXCEPTION",
            stage: "framing",
            aeadAttempted: false,
            setupCompleted: false,
            plaintext: null,
        };
    }
    if (error instanceof Error && error.name === "Error" && error.message === AEAD_FAILURE) {
        return {
            ok: false,
            code: "DECRYPTION_FAILED",
            stage: "aead",
            aeadAttempted: true,
            setupCompleted: true,
            plaintext: null,
        };
    }
    return unexpected("aead", error instanceof Error ? error.message : "non-error throw");
}

/**
 * @param {Buffer} key
 * @param {Buffer} nonce
 * @param {Buffer} packed
 * @returns {object}
 */
export function openAead(key, nonce, packed) {
    if (!Buffer.isBuffer(packed) || packed.length < TAG_SIZE) {
        return {
            ok: false,
            code: "HARNESS_TAG_SHORT",
            stage: "framing",
            aeadAttempted: false,
            setupCompleted: false,
            plaintext: null,
        };
    }
    if (!Buffer.isBuffer(key) || key.length !== 32 || !Buffer.isBuffer(nonce) || nonce.length !== 12) {
        return unexpected("framing", "AEAD inputs were not 32-byte key and 12-byte nonce");
    }
    try {
        const decipher = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: TAG_SIZE });
        decipher.setAuthTag(packed.subarray(packed.length - TAG_SIZE));
        const plaintext = Buffer.concat([
            decipher.update(packed.subarray(0, packed.length - TAG_SIZE)),
            decipher.final(),
        ]);
        return {
            ok: true,
            code: "OK",
            stage: "aead",
            aeadAttempted: true,
            setupCompleted: true,
            plaintext,
        };
    } catch (error) {
        return classifyAeadError(error);
    }
}

/**
 * @returns {object}
 */
export function buildReport() {
    const fixtures = loadFixtures();
    const vectors = vectorEvidence(fixtures);
    const controls = collectControls(fixtures).map((item) => ({
        id: item.id,
        claim: item.claim,
        expected: item.expected,
        observed: item.observed,
        matched: sameControl(item.expected, item.observed),
    }));
    const orders = ["protocol-8.4", "implementation-pseudocode"];
    const testCase44 = [51, 0, 249, 251, 50].map((counter) => {
        const readings = Object.fromEntries(orders.map((order) => [
            order,
            classifyCounter(VECTOR_44_STATE, counter, order),
        ]));
        return { counter, readings, ordersAgree: readings["protocol-8.4"].code === readings["implementation-pseudocode"].code };
    });
    const divergenceState = { peerLastCounter: 300, seenCounters: [50] };
    const divergence = {
        state: divergenceState,
        counter: 50,
        readings: Object.fromEntries(orders.map((order) => [order, classifyCounter(divergenceState, 50, order)])),
    };
    const outOfOrder = scriptCounters(
        { peerLastCounter: 50, seenCounters: [50] },
        [52, 51, 53, 52],
        "protocol-8.4",
    );
    const budgets = [0, 1, 8, 16, 32].flatMap((reserved) => [
        plaintextBudget("standard", reserved),
        plaintextBudget("psk", reserved),
    ]);
    return {
        harness: "research-reference",
        protocol: "AlgoChat 1.2",
        node: process.versions.node,
        randomness: "none",
        network: false,
        chainTransactions: false,
        mlKemMeasured: false,
        wireFormatChanged: false,
        vectors,
        controls,
        counterWindow: {
            testCase44,
            divergence,
            outOfOrder,
            windowAt50: windowSpan(50),
            windowAt200: windowSpan(200),
            windowAt201: windowSpan(201),
            windowAt250: windowSpan(250),
            representableBounds: {
                uint32Max: 0xffffffff,
                rolloverDefined: false,
                note: "Upper endpoints are capped at the four-byte maximum. This measurement does not define counter wrap, saturation, or sender stopping.",
                atLastEqualsMaxMinus200: measuredWindow(0xffffffff - 200),
                atLastEqualsMaxMinus199: measuredWindow(0xffffffff - 199),
                atLastEqualsMax: measuredWindow(0xffffffff),
            },
            seenSetPruned: false,
        },
        sizes: measureSizes(fixtures),
        framing: {
            shippedFragmentFields: false,
            headerFieldSizes: {
                standard: [1, 1, 32, 32, 12, 48],
                psk: [1, 1, 4, 32, 32, 12, 48],
            },
            budgets,
            duplicateStandardEnvelopesIdentical: fixtures.standard.envelope.equals(encryptStandard({
                senderPublicKey: fixtures.sender.publicKey,
                recipientPublicKey: fixtures.recipient.publicKey,
                ephemeralPrivateKey: fixtures.ephemeralPrivateKey,
                nonce: fixtures.nonce,
                plaintext: fixtures.plaintext,
            }).envelope),
            partialNotesEmittedForOversizedPlaintext: 0,
        },
        openDecisions: OPEN_DECISIONS,
        limits: LIMITS,
        pqProposal: {
            executed: false,
            reason: "PR 21 owns the ML-KEM size spike and the unapproved pair-secret proposal. v1.2 has no PQ envelope mode and no downgrade-negotiation byte.",
        },
    };
}

function runningAsCli() {
    const entry = process.argv[1];
    if (!entry) {
        return false;
    }
    return import.meta.url === pathToFileURL(path.resolve(entry)).href;
}

if (runningAsCli()) {
    process.stdout.write(`${JSON.stringify(buildReport(), null, 2)}\n`);
}

function loadFixtures() {
    const sender = deriveKeyPair(Buffer.alloc(32, 0x01));
    const recipient = deriveKeyPair(Buffer.alloc(32, 0x02));
    const other = deriveKeyPair(Buffer.alloc(32, 0x00));
    const ephemeralPrivateKey = deriveKeyPair(Buffer.alloc(32, 0x03)).privateKey;
    const nonce = Buffer.alloc(12, 0x04);
    const initialPsk = Buffer.alloc(32, 0xaa);
    const plaintext = Buffer.from(PUBLISHED.plaintextText);
    const standard = encryptStandard({
        senderPublicKey: sender.publicKey,
        recipientPublicKey: recipient.publicKey,
        ephemeralPrivateKey,
        nonce,
        plaintext,
    });
    const psk = encryptPsk({
        senderPublicKey: sender.publicKey,
        recipientPublicKey: recipient.publicKey,
        ephemeralPrivateKey,
        nonce,
        plaintext,
        initialPsk,
        counter: 0,
    });
    return { sender, recipient, other, ephemeralPrivateKey, nonce, initialPsk, plaintext, standard, psk };
}

function vectorEvidence(fixtures) {
    const sender = deriveKeyPair(Buffer.alloc(32, 0x01));
    const recipient = deriveKeyPair(Buffer.alloc(32, 0x02));
    const zero = deriveKeyPair(Buffer.alloc(32, 0x00));
    const ephemeral = deriveKeyPair(Buffer.alloc(32, 0x03));
    const sharedRecipient = x25519Shared(ephemeral.privateKey, recipient.publicKey);
    const sharedSender = x25519Shared(ephemeral.privateKey, sender.publicKey);
    const symmetricKey = hkdf(
        sharedRecipient,
        ephemeral.publicKey,
        Buffer.concat([Buffer.from("AlgoChatV1"), sender.publicKey, recipient.publicKey]),
    );
    const senderKey = hkdf(
        sharedSender,
        ephemeral.publicKey,
        Buffer.concat([Buffer.from("AlgoChatV1-SenderKey"), sender.publicKey]),
    );
    const position0 = derivePosition(fixtures.initialPsk, 0);
    const position99 = derivePosition(fixtures.initialPsk, 99);
    const position100 = derivePosition(fixtures.initialPsk, 100);
    const pskSymmetric = hkdf(
        Buffer.concat([sharedRecipient, position0.positionPsk]),
        ephemeral.publicKey,
        Buffer.concat([Buffer.from("AlgoChatV1-PSK"), sender.publicKey, recipient.publicKey]),
    );
    const pskSender = hkdf(
        Buffer.concat([sharedSender, position0.positionPsk]),
        ephemeral.publicKey,
        Buffer.concat([Buffer.from("AlgoChatV1-PSK-SenderKey"), sender.publicKey]),
    );
    const comparisons = {
        "1.1-private": [zero.privateKey, PUBLISHED.seed00Private],
        "1.1-public": [zero.publicKey, PUBLISHED.seed00Public],
        "1.2-private": [sender.privateKey, PUBLISHED.seed01Private],
        "1.2-public": [sender.publicKey, PUBLISHED.seed01Public],
        "3.1-recipient-private": [recipient.privateKey, PUBLISHED.seed02Private],
        "3.1-recipient-public": [recipient.publicKey, PUBLISHED.seed02Public],
        "3.1-ephemeral-private": [ephemeral.privateKey, PUBLISHED.seed03Private],
        "3.1-ephemeral-public": [ephemeral.publicKey, PUBLISHED.seed03Public],
        "3.1-plaintext": [fixtures.plaintext, PUBLISHED.plaintextHex],
        "3.1-shared-recipient": [sharedRecipient, PUBLISHED.sharedRecipient],
        "3.1-symmetric-key": [symmetricKey, PUBLISHED.symmetricKey],
        "3.1-shared-sender": [sharedSender, PUBLISHED.sharedSender],
        "3.1-sender-key": [senderKey, PUBLISHED.senderKey],
        "3.1-ciphertext": [fixtures.standard.envelope.subarray(LAYOUT.standard.ciphertext), PUBLISHED.ciphertext],
        "3.1-encrypted-sender-key": [fixtures.standard.envelope.subarray(LAYOUT.standard.wrap, LAYOUT.standard.ciphertext), PUBLISHED.encryptedSenderKey],
        "4.1-session-0": [position0.sessionPsk, PUBLISHED.session0],
        "4.1-position-0": [position0.positionPsk, PUBLISHED.position0],
        "4.1-position-99": [position99.positionPsk, PUBLISHED.position99],
        "4.1-session-100": [position100.sessionPsk, PUBLISHED.session1],
        "4.1-position-100": [position100.positionPsk, PUBLISHED.position100],
        "4.2-psk-symmetric-key": [pskSymmetric, PUBLISHED.pskSymmetricKey],
        "4.2-psk-sender-key": [pskSender, PUBLISHED.pskSenderKey],
        "4.3-ciphertext": [fixtures.psk.envelope.subarray(LAYOUT.psk.ciphertext), PUBLISHED.pskCiphertext],
        "4.3-encrypted-sender-key": [fixtures.psk.envelope.subarray(LAYOUT.psk.wrap, LAYOUT.psk.ciphertext), PUBLISHED.pskEncryptedSenderKey],
    };
    const fields = Object.fromEntries(Object.entries(comparisons).map(([id, [actual, expected]]) => [
        id,
        { matches: Buffer.from(actual).equals(Buffer.from(expected, typeof expected === "string" ? "hex" : undefined)), bytes: Buffer.from(actual).length },
    ]));
    const standardHex = fixtures.standard.envelope.toString("hex");
    const pskHex = fixtures.psk.envelope.toString("hex");
    const expectedStandard = `0101${PUBLISHED.seed01Public}${PUBLISHED.seed03Public}${PUBLISHED.nonce}${PUBLISHED.encryptedSenderKey}${PUBLISHED.ciphertext}`;
    const expectedPsk = `010200000000${PUBLISHED.seed01Public}${PUBLISHED.seed03Public}${PUBLISHED.nonce}${PUBLISHED.pskEncryptedSenderKey}${PUBLISHED.pskCiphertext}`;
    fields["3.1-envelope"] = { matches: standardHex === expectedStandard, bytes: fixtures.standard.envelope.length };
    fields["4.3-envelope"] = { matches: pskHex === expectedPsk, bytes: fixtures.psk.envelope.length };
    const patterned = patternedEnvelope("standard");
    const patternedPsk = patternedEnvelope("psk");
    fields["2.1-minimum"] = { matches: patterned.length === 142 && patterned.subarray(0, 2).equals(Buffer.from([0x01, 0x01])), bytes: patterned.length };
    fields["4.5-minimum"] = { matches: patternedPsk.length === 146 && patternedPsk.subarray(0, 6).equals(Buffer.from("010200000000", "hex")), bytes: patternedPsk.length };
    const unicodeBytes = Buffer.from(PUBLISHED.unicodeLiteral);
    fields["3.2-literal-length"] = {
        matches: unicodeBytes.length === 34 && unicodeBytes.length !== PUBLISHED.unicodeDocumentedByteLength,
        bytes: unicodeBytes.length,
        documentedBytes: PUBLISHED.unicodeDocumentedByteLength,
    };
    return {
        allMatched: Object.values(fields).every((field) => field.matches),
        fields,
        canonicalStandardHex: standardHex,
        canonicalPskHex: pskHex,
    };
}

/**
 * @param {object} fixtures
 * @returns {Array<{ id: string, claim: string, expected: object, observed: object }>}
 */
export function collectControls(fixtures = loadFixtures()) {
    const cases = [];
    const recipientContext = {
        role: "recipient",
        privateKey: fixtures.recipient.privateKey,
        publicKey: fixtures.recipient.publicKey,
    };
    const senderContext = {
        role: "sender",
        privateKey: fixtures.sender.privateKey,
        publicKey: fixtures.sender.publicKey,
    };
    const hello = PUBLISHED.plaintextHex;

    add(cases, "canonical-recipient-opens", "published standard envelope decrypts for the recipient", (
        openEnvelope(fixtures.standard.envelope, recipientContext)
    ), { ok: true, code: "OK", stage: "aead", aeadAttempted: true, setupCompleted: true, plaintextHex: hello });

    add(cases, "canonical-sender-opens", "published standard envelope decrypts for the sender", (
        openEnvelope(fixtures.standard.envelope, senderContext)
    ), { ok: true, code: "OK", stage: "aead", aeadAttempted: true, setupCompleted: true, plaintextHex: hello });

    add(cases, "canonical-psk-recipient-opens", "published PSK envelope decrypts for the recipient", (
        openEnvelope(fixtures.psk.envelope, { ...recipientContext, initialPsk: fixtures.initialPsk, applyCounterGate: false })
    ), { ok: true, code: "OK", stage: "aead", role: "recipient", aeadAttempted: true, setupCompleted: true, plaintextHex: hello });

    add(cases, "canonical-psk-sender-opens", "published PSK envelope decrypts for the sender through encrypted_sender_key; the sender path does not apply the counter gate", (
        openEnvelope(fixtures.psk.envelope, { ...senderContext, initialPsk: fixtures.initialPsk, applyCounterGate: false })
    ), { ok: true, code: "OK", stage: "aead", role: "sender", aeadAttempted: true, setupCompleted: true, plaintextHex: hello });

    add(cases, "ciphertext-bit-flip", "one flipped ciphertext byte fails AEAD after key setup", (
        openEnvelope(flip(fixtures.standard.envelope, LAYOUT.standard.ciphertext), recipientContext)
    ), { ok: false, code: "DECRYPTION_FAILED", stage: "aead", aeadAttempted: true, setupCompleted: true, plaintextHex: null });

    add(cases, "tag-bit-flip", "one flipped tag byte fails AEAD after key setup", (
        openEnvelope(flip(fixtures.standard.envelope, fixtures.standard.envelope.length - 1), recipientContext)
    ), { ok: false, code: "DECRYPTION_FAILED", stage: "aead", aeadAttempted: true, setupCompleted: true, plaintextHex: null });

    add(cases, "sender-wrap-bit-flip-recipient-opens", "a flipped sender wrap does not stop the recipient path", (
        openEnvelope(flip(fixtures.standard.envelope, LAYOUT.standard.wrap), recipientContext)
    ), { ok: true, code: "OK", stage: "aead", aeadAttempted: true, setupCompleted: true, plaintextHex: hello });

    add(cases, "sender-wrap-bit-flip-sender-fails", "a flipped sender wrap fails the sender path after setup", (
        openEnvelope(flip(fixtures.standard.envelope, LAYOUT.standard.wrap), senderContext)
    ), { ok: false, code: "DECRYPTION_FAILED", stage: "aead", aeadAttempted: true, setupCompleted: true, plaintextHex: null });

    const flippedPskWrap = flip(fixtures.psk.envelope, LAYOUT.psk.wrap);
    const pskContext = { initialPsk: fixtures.initialPsk, applyCounterGate: false };
    add(cases, "psk-sender-wrap-bit-flip-recipient-opens", "a flipped PSK sender wrap does not stop the recipient path", (
        openEnvelope(flippedPskWrap, { ...recipientContext, ...pskContext })
    ), { ok: true, code: "OK", stage: "aead", role: "recipient", aeadAttempted: true, setupCompleted: true, plaintextHex: hello });

    add(cases, "psk-sender-wrap-bit-flip-sender-fails", "a flipped PSK sender wrap fails the sender unwrap after AEAD setup", (
        openEnvelope(flippedPskWrap, { ...senderContext, ...pskContext })
    ), { ok: false, code: "DECRYPTION_FAILED", stage: "aead", role: "sender", aeadAttempted: true, setupCompleted: true, plaintextHex: null });

    const replacedNonce = Buffer.from(fixtures.standard.envelope);
    replacedNonce.fill(0x05, LAYOUT.standard.nonce, LAYOUT.standard.nonce + 12);
    add(cases, "nonce-replacement", "a different 12-byte nonce fails AEAD after key setup", (
        openEnvelope(replacedNonce, recipientContext)
    ), { ok: false, code: "DECRYPTION_FAILED", stage: "aead", aeadAttempted: true, setupCompleted: true, plaintextHex: null });

    add(cases, "wrong-recipient-private-key", "a different valid private key fails AEAD after ECDH and HKDF", (
        openEnvelope(fixtures.standard.envelope, {
            role: "recipient",
            privateKey: fixtures.other.privateKey,
            publicKey: fixtures.recipient.publicKey,
        })
    ), { ok: false, code: "DECRYPTION_FAILED", stage: "aead", aeadAttempted: true, setupCompleted: true, plaintextHex: null });

    add(cases, "sender-pubkey-bit-flip", "a flipped sender_pubkey fails the recipient AEAD after setup", (
        openEnvelope(flip(fixtures.standard.envelope, LAYOUT.standard.sender), recipientContext)
    ), { ok: false, code: "DECRYPTION_FAILED", stage: "aead", aeadAttempted: true, setupCompleted: true, plaintextHex: null });

    add(cases, "garbage-pattern-fails-aead", "a minimum patterned standard envelope parses and then fails AEAD", (
        openEnvelope(patternedEnvelope("standard"), recipientContext)
    ), { ok: false, code: "DECRYPTION_FAILED", stage: "aead", aeadAttempted: true, setupCompleted: true, plaintextHex: null });

    add(cases, "psk-garbage-pattern-fails-aead", "case 4.5 patterned PSK note accepts counter 0 against peer_last 0 with the published PSK and then fails AEAD", (
        openEnvelope(patternedEnvelope("psk"), {
            ...recipientContext,
            initialPsk: fixtures.initialPsk,
            applyCounterGate: true,
            counterOrder: "protocol-8.4",
            counterState: { peerLastCounter: 0, seenCounters: [] },
        })
    ), { ok: false, code: "DECRYPTION_FAILED", stage: "aead", role: "recipient", aeadAttempted: true, setupCompleted: true, plaintextHex: null });

    add(cases, "truncate-one-byte-fails-aead", "dropping the last byte still has a 16-byte tag slice and fails AEAD", (
        openEnvelope(fixtures.standard.envelope.subarray(0, fixtures.standard.envelope.length - 1), recipientContext)
    ), { ok: false, code: "DECRYPTION_FAILED", stage: "aead", aeadAttempted: true, setupCompleted: true, plaintextHex: null });

    add(cases, "below-test-vector-minimum", "141 bytes fail the test-vector length rule before AEAD", (
        openEnvelope(fixtures.standard.envelope.subarray(0, 141), recipientContext)
    ), { ok: false, code: "INVALID_ENVELOPE", stage: "length", aeadAttempted: false, setupCompleted: false, plaintextHex: null });

    add(cases, "header-only-not-aead", "a 126-byte header is short-tag framing under the header reading, not an AEAD failure", (
        openEnvelope(fixtures.standard.envelope.subarray(0, HEADER_SIZE), { ...recipientContext, lengthRule: "header" })
    ), { ok: false, code: "HARNESS_TAG_SHORT", stage: "framing", aeadAttempted: false, setupCompleted: false, plaintextHex: null });

    add(cases, "four-byte-envelope", "0x0101AABB is an invalid envelope before AEAD", (
        openEnvelope(Buffer.from("0101aabb", "hex"), recipientContext)
    ), { ok: false, code: "INVALID_ENVELOPE", stage: "length", aeadAttempted: false, setupCompleted: false, plaintextHex: null });

    add(cases, "thirty-two-byte-envelope", "a 32-byte note is an invalid envelope before AEAD", (
        openEnvelope(Buffer.concat([Buffer.from([0x01, 0x01]), Buffer.alloc(30, 0x11)]), recipientContext)
    ), { ok: false, code: "INVALID_ENVELOPE", stage: "length", aeadAttempted: false, setupCompleted: false, plaintextHex: null });

    add(cases, "unknown-version", "version 0x02 is rejected before AEAD", (
        openEnvelope(Buffer.concat([Buffer.from([0x02, 0x01]), Buffer.alloc(140, 0)]), recipientContext)
    ), { ok: false, code: "UNKNOWN_VERSION", stage: "parse", aeadAttempted: false, setupCompleted: false, plaintextHex: null });

    add(cases, "unknown-protocol", "protocol 0x03 is rejected before AEAD", (
        openEnvelope(Buffer.concat([Buffer.from([0x01, 0x03]), Buffer.alloc(140, 0)]), recipientContext)
    ), { ok: false, code: "UNKNOWN_PROTOCOL", stage: "parse", aeadAttempted: false, setupCompleted: false, plaintextHex: null });

    const asPsk = Buffer.from(fixtures.standard.envelope);
    asPsk[1] = PROTOCOL_PSK;
    add(cases, "standard-bytes-read-as-psk", "relabeling a standard note as PSK fails AEAD and does not fall back", (
        openEnvelope(asPsk, { ...recipientContext, initialPsk: fixtures.initialPsk, applyCounterGate: false })
    ), { ok: false, code: "DECRYPTION_FAILED", stage: "aead", aeadAttempted: true, setupCompleted: true, plaintextHex: null });

    const asStandard = Buffer.from(fixtures.psk.envelope);
    asStandard[1] = PROTOCOL_STANDARD;
    add(cases, "psk-bytes-read-as-standard", "relabeling a PSK note as standard fails AEAD and does not fall back", (
        openEnvelope(asStandard, recipientContext)
    ), { ok: false, code: "DECRYPTION_FAILED", stage: "aead", aeadAttempted: true, setupCompleted: true, plaintextHex: null });

    add(cases, "short-tag-is-not-aead-failure", "a 15-byte packed input is rejected before setAuthTag", (
        openAead(Buffer.alloc(32, 1), Buffer.alloc(12, 2), Buffer.alloc(15, 3))
    ), { ok: false, code: "HARNESS_TAG_SHORT", stage: "framing", aeadAttempted: false, setupCompleted: false, plaintextHex: null });

    add(cases, "missing-psk-is-not-aead-failure", "a PSK note without a supplied PSK is PSK_NOT_FOUND before AEAD", (
        openEnvelope(fixtures.psk.envelope, recipientContext)
    ), { ok: false, code: "PSK_NOT_FOUND", stage: "psk", aeadAttempted: false, setupCompleted: false, plaintextHex: null });

    add(cases, "wrong-psk-fails-aead", "a different 32-byte PSK fails AEAD after ECDH and HKDF", (
        openEnvelope(fixtures.psk.envelope, {
            ...recipientContext,
            initialPsk: Buffer.alloc(32, 0xbb),
            applyCounterGate: false,
        })
    ), { ok: false, code: "DECRYPTION_FAILED", stage: "aead", aeadAttempted: true, setupCompleted: true, plaintextHex: null });

    const ahead = encryptPsk({
        senderPublicKey: fixtures.sender.publicKey,
        recipientPublicKey: fixtures.recipient.publicKey,
        ephemeralPrivateKey: fixtures.ephemeralPrivateKey,
        nonce: fixtures.nonce,
        plaintext: fixtures.plaintext,
        initialPsk: fixtures.initialPsk,
        counter: 251,
    });
    add(cases, "counter-251-gate-rejects-before-aead", "Test Case 4.4 rejects counter 251 before decryption", (
        openEnvelope(ahead.envelope, {
            ...recipientContext,
            initialPsk: fixtures.initialPsk,
            applyCounterGate: true,
            counterOrder: "protocol-8.4",
            counterState: VECTOR_44_STATE,
        })
    ), { ok: false, code: "PSK_COUNTER_OUT_OF_RANGE", stage: "counter", aeadAttempted: false, setupCompleted: false, plaintextHex: null });

    add(cases, "counter-251-without-gate-opens", "the same counter 251 note opens when the counter gate is not applied", (
        openEnvelope(ahead.envelope, { ...recipientContext, initialPsk: fixtures.initialPsk, applyCounterGate: false })
    ), { ok: true, code: "OK", stage: "aead", aeadAttempted: true, setupCompleted: true, plaintextHex: hello });

    const first = openEnvelope(fixtures.standard.envelope, recipientContext);
    const second = openEnvelope(fixtures.standard.envelope, recipientContext);
    add(cases, "standard-note-opens-twice", "the same standard note decrypts twice; the envelope is not a replay token", (
        { ...second, ok: first.ok && second.ok, plaintext: first.plaintext }
    ), { ok: true, code: "OK", stage: "aead", aeadAttempted: true, setupCompleted: true, plaintextHex: hello });

    const thirdParty = encryptStandard({
        senderPublicKey: fixtures.other.publicKey,
        recipientPublicKey: fixtures.recipient.publicKey,
        ephemeralPrivateKey: fixtures.ephemeralPrivateKey,
        nonce: fixtures.nonce,
        plaintext: Buffer.from("{\"text\":\"synthetic-third-party\"}"),
    });
    add(cases, "third-party-sender-opens", "encryption needs the recipient public key, not the sender private key, and the recipient can open it", (
        openEnvelope(thirdParty.envelope, { ...recipientContext, role: "dispatch" })
    ), { ok: true, code: "OK", stage: "aead", role: "recipient", aeadAttempted: true, setupCompleted: true, plaintextHex: Buffer.from("{\"text\":\"synthetic-third-party\"}").toString("hex") });

    const selfLabeled = encryptStandard({
        senderPublicKey: fixtures.recipient.publicKey,
        recipientPublicKey: fixtures.recipient.publicKey,
        ephemeralPrivateKey: fixtures.ephemeralPrivateKey,
        nonce: fixtures.nonce,
        plaintext: Buffer.from("{\"text\":\"synthetic-self-dispatch\"}"),
    });
    add(cases, "self-dispatch-labels-sender", "a note whose sender_pubkey equals the decryptor public key takes the sender branch and opens", (
        openEnvelope(selfLabeled.envelope, { ...recipientContext, role: "dispatch" })
    ), { ok: true, code: "OK", stage: "aead", role: "sender", aeadAttempted: true, setupCompleted: true, plaintextHex: Buffer.from("{\"text\":\"synthetic-self-dispatch\"}").toString("hex") });

    const tooLarge = encryptStandard({
        senderPublicKey: fixtures.sender.publicKey,
        recipientPublicKey: fixtures.recipient.publicKey,
        ephemeralPrivateKey: fixtures.ephemeralPrivateKey,
        nonce: fixtures.nonce,
        plaintext: Buffer.alloc(MAX_PLAINTEXT + 1, 0x61),
    });
    add(cases, "oversized-standard", "883 plaintext bytes are refused before AEAD and emit no note", (
        tooLarge
    ), { ok: false, code: "MESSAGE_TOO_LARGE", stage: "size", aeadAttempted: false, setupCompleted: false, plaintextHex: null });

    const tooLargePsk = encryptPsk({
        senderPublicKey: fixtures.sender.publicKey,
        recipientPublicKey: fixtures.recipient.publicKey,
        ephemeralPrivateKey: fixtures.ephemeralPrivateKey,
        nonce: fixtures.nonce,
        plaintext: Buffer.alloc(PSK_MAX_PLAINTEXT + 1, 0x61),
        initialPsk: fixtures.initialPsk,
        counter: 0,
    });
    add(cases, "oversized-psk", "879 PSK plaintext bytes are refused before AEAD and emit no note", (
        tooLargePsk
    ), { ok: false, code: "MESSAGE_TOO_LARGE", stage: "size", aeadAttempted: false, setupCompleted: false, plaintextHex: null });

    return cases;
}

function add(cases, id, claim, result, expected) {
    cases.push({ id, claim, expected, observed: observe(result) });
}

function observe(result) {
    return {
        ok: result.ok === true,
        code: result.code ?? null,
        stage: result.stage ?? null,
        role: result.role ?? null,
        aeadAttempted: result.aeadAttempted === true,
        setupCompleted: result.setupCompleted === true,
        plaintextHex: Buffer.isBuffer(result.plaintext) ? result.plaintext.toString("hex") : null,
        envelopeLength: Buffer.isBuffer(result.envelope) ? result.envelope.length : null,
    };
}

function sameControl(expected, observed) {
    return Object.entries(expected).every(([key, value]) => observed[key] === value);
}

function measureSizes(fixtures) {
    const samples = [
        ["standard-empty", "standard", Buffer.alloc(0)],
        ["standard-max", "standard", Buffer.alloc(MAX_PLAINTEXT, 0x61)],
        ["psk-empty", "psk", Buffer.alloc(0)],
        ["psk-max", "psk", Buffer.alloc(PSK_MAX_PLAINTEXT, 0x61)],
    ];
    return Object.fromEntries(samples.map(([id, mode, plaintext]) => {
        const encrypted = mode === "standard"
            ? encryptStandard({
                senderPublicKey: fixtures.sender.publicKey,
                recipientPublicKey: fixtures.recipient.publicKey,
                ephemeralPrivateKey: fixtures.ephemeralPrivateKey,
                nonce: fixtures.nonce,
                plaintext,
            })
            : encryptPsk({ senderPublicKey: fixtures.sender.publicKey, recipientPublicKey: fixtures.recipient.publicKey, ephemeralPrivateKey: fixtures.ephemeralPrivateKey, nonce: fixtures.nonce, plaintext, initialPsk: fixtures.initialPsk, counter: 0 });
        const opened = encrypted.ok
            ? openEnvelope(encrypted.envelope, {
                role: "recipient",
                privateKey: fixtures.recipient.privateKey,
                publicKey: fixtures.recipient.publicKey,
                initialPsk: mode === "psk" ? fixtures.initialPsk : undefined,
                applyCounterGate: false,
            })
            : null;
        return [id, {
            plaintextLength: plaintext.length,
            envelopeLength: encrypted.envelope?.length ?? null,
            roundTrip: opened?.ok === true && Buffer.isBuffer(opened.plaintext) && opened.plaintext.equals(plaintext),
            envelopeSha256: encrypted.envelope ? sha256Hex(encrypted.envelope) : null,
        }];
    }));
}

function scriptCounters(initial, counters, order) {
    const steps = [];
    let state = copyState(initial);
    for (const counter of counters) {
        const applied = applyCounter(state, counter, order);
        state = applied.state;
        steps.push({
            counter,
            code: applied.decision.code,
            accepted: applied.decision.accepted,
            peerLastCounter: state.peerLastCounter,
            seenCount: state.seenCounters.length,
        });
    }
    return { order, steps };
}

function encryptMessage(input, mode) {
    const plaintext = Buffer.from(input.plaintext);
    const maxPlaintext = mode === "standard" ? MAX_PLAINTEXT : PSK_MAX_PLAINTEXT;
    if (plaintext.length > maxPlaintext) {
        return {
            ok: false,
            code: "MESSAGE_TOO_LARGE",
            stage: "size",
            aeadAttempted: false,
            setupCompleted: false,
            plaintext: null,
            envelope: null,
        };
    }
    const ephemeralPublicKey = x25519Public(input.ephemeralPrivateKey);
    const recipientShared = x25519Shared(input.ephemeralPrivateKey, input.recipientPublicKey);
    const senderShared = x25519Shared(input.ephemeralPrivateKey, input.senderPublicKey);
    let messageInfo = Buffer.concat([
        Buffer.from(mode === "standard" ? "AlgoChatV1" : "AlgoChatV1-PSK"),
        input.senderPublicKey,
        input.recipientPublicKey,
    ]);
    let senderInfo = Buffer.concat([
        Buffer.from(mode === "standard" ? "AlgoChatV1-SenderKey" : "AlgoChatV1-PSK-SenderKey"),
        input.senderPublicKey,
    ]);
    let messageIkm = recipientShared;
    let senderIkm = senderShared;
    let prefix = Buffer.from([PROTOCOL_VERSION, PROTOCOL_STANDARD]);
    if (mode === "psk") {
        const { positionPsk } = derivePosition(input.initialPsk, input.counter);
        messageIkm = Buffer.concat([recipientShared, positionPsk]);
        senderIkm = Buffer.concat([senderShared, positionPsk]);
        prefix = Buffer.concat([Buffer.from([PROTOCOL_VERSION, PROTOCOL_PSK]), uint32be(input.counter)]);
        positionPsk.fill(0);
    }
    const messageKey = hkdf(messageIkm, ephemeralPublicKey, messageInfo);
    const senderKey = hkdf(senderIkm, ephemeralPublicKey, senderInfo);
    const ciphertext = aeadSeal(messageKey, input.nonce, plaintext);
    const encryptedSenderKey = aeadSeal(senderKey, input.nonce, messageKey);
    const envelope = Buffer.concat([
        prefix,
        input.senderPublicKey,
        ephemeralPublicKey,
        input.nonce,
        encryptedSenderKey,
        ciphertext,
    ]);
    messageKey.fill(0);
    senderKey.fill(0);
    messageIkm.fill(0);
    senderIkm.fill(0);
    messageInfo = null;
    senderInfo = null;
    return {
        ok: true,
        code: "OK",
        stage: "size",
        aeadAttempted: true,
        setupCompleted: true,
        plaintext: null,
        envelope,
    };
}

function openFields(fields, role, privateKey, publicKey, initialPsk) {
    const ephemeralPrivateSide = x25519Shared(privateKey, fields.ephemeralPublicKey);
    let positionPsk = null;
    if (fields.mode === "psk") {
        positionPsk = derivePosition(initialPsk, fields.counter).positionPsk;
    }
    if (role === "sender") {
        const info = Buffer.concat([
            Buffer.from(fields.mode === "standard" ? "AlgoChatV1-SenderKey" : "AlgoChatV1-PSK-SenderKey"),
            publicKey,
        ]);
        const ikm = positionPsk === null ? ephemeralPrivateSide : Buffer.concat([ephemeralPrivateSide, positionPsk]);
        const senderKey = hkdf(ikm, fields.ephemeralPublicKey, info);
        const wrapped = openAead(senderKey, fields.nonce, fields.encryptedSenderKey);
        senderKey.fill(0);
        ikm.fill(0);
        if (positionPsk !== null) {
            positionPsk.fill(0);
        }
        if (!wrapped.ok || !Buffer.isBuffer(wrapped.plaintext) || wrapped.plaintext.length !== 32) {
            if (Buffer.isBuffer(wrapped.plaintext)) {
                wrapped.plaintext.fill(0);
            }
            return {
                ...wrapped,
                ok: false,
                code: wrapped.ok ? "HARNESS_UNEXPECTED" : wrapped.code,
                plaintext: null,
                mode: fields.mode,
            };
        }
        const opened = openAead(wrapped.plaintext, fields.nonce, fields.ciphertext);
        wrapped.plaintext.fill(0);
        opened.mode = fields.mode;
        return opened;
    }
    const info = Buffer.concat([
        Buffer.from(fields.mode === "standard" ? "AlgoChatV1" : "AlgoChatV1-PSK"),
        fields.senderPublicKey,
        publicKey,
    ]);
    const ikm = positionPsk === null ? ephemeralPrivateSide : Buffer.concat([ephemeralPrivateSide, positionPsk]);
    const messageKey = hkdf(ikm, fields.ephemeralPublicKey, info);
    const opened = openAead(messageKey, fields.nonce, fields.ciphertext);
    messageKey.fill(0);
    ikm.fill(0);
    if (positionPsk !== null) {
        positionPsk.fill(0);
    }
    opened.mode = fields.mode;
    return opened;
}

function resolveRole(fields, context) {
    if (context.role === "dispatch") {
        return context.publicKey.equals(fields.senderPublicKey) ? "sender" : "recipient";
    }
    return context.role === "sender" ? "sender" : "recipient";
}

function patternedEnvelope(mode) {
    const parts = [Buffer.from([PROTOCOL_VERSION, mode === "standard" ? PROTOCOL_STANDARD : PROTOCOL_PSK])];
    if (mode === "psk") {
        parts.push(Buffer.alloc(4, 0));
    }
    parts.push(
        Buffer.alloc(32, 0xaa),
        Buffer.alloc(32, 0xbb),
        Buffer.alloc(12, 0xcc),
        Buffer.alloc(48, 0xdd),
        Buffer.alloc(16, 0xee),
    );
    return Buffer.concat(parts);
}

function flip(buffer, offset) {
    const copy = Buffer.from(buffer);
    copy[offset] ^= 0x01;
    return copy;
}

function hkdf(ikm, salt, info) {
    return Buffer.from(hkdfSync("sha256", ikm, salt, info, 32));
}

function x25519Public(privateKey) {
    const key = createPrivateKey({
        key: Buffer.concat([PKCS8_PREFIX, privateKey]),
        format: "der",
        type: "pkcs8",
    });
    const spki = createPublicKey(key).export({ type: "spki", format: "der" });
    if (spki.length !== SPKI_PREFIX.length + 32 || !spki.subarray(0, SPKI_PREFIX.length).equals(SPKI_PREFIX)) {
        throw new Error("X25519 SPKI prefix did not match the Node encoding this harness measured");
    }
    return Buffer.from(spki.subarray(SPKI_PREFIX.length));
}

function x25519Shared(privateKey, publicKey) {
    const priv = createPrivateKey({
        key: Buffer.concat([PKCS8_PREFIX, privateKey]),
        format: "der",
        type: "pkcs8",
    });
    const pub = createPublicKey({
        key: Buffer.concat([SPKI_PREFIX, publicKey]),
        format: "der",
        type: "spki",
    });
    const shared = Buffer.from(diffieHellman({ privateKey: priv, publicKey: pub }));
    if (shared.length !== 32) {
        throw new Error("X25519 shared secret was not 32 bytes");
    }
    return shared;
}

function aeadSeal(key, nonce, plaintext) {
    const cipher = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: TAG_SIZE });
    return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function uint32be(value) {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32BE(value);
    return buffer;
}

function isUint32(value) {
    return Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff;
}

function normalizeState(state) {
    if (typeof state !== "object" || state === null || !isUint32(state.peerLastCounter)) {
        return null;
    }
    if (!Array.isArray(state.seenCounters) || state.seenCounters.some((value) => !isUint32(value))) {
        return null;
    }
    return state;
}

function copyState(state) {
    return {
        peerLastCounter: state.peerLastCounter,
        seenCounters: state.seenCounters.slice(),
    };
}

function unexpected(stage, message) {
    return {
        ok: false,
        code: "HARNESS_UNEXPECTED",
        stage,
        aeadAttempted: false,
        setupCompleted: false,
        plaintext: null,
        message,
    };
}

export function sha256Hex(bytes) {
    return createHash("sha256").update(bytes).digest("hex");
}
