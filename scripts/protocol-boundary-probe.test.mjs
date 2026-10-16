import assert from "node:assert/strict";
import { createDecipheriv } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";

import {
    COUNTER_WINDOW,
    HEADER_SIZE,
    LAYOUT,
    MAX_NOTE_SIZE,
    MAX_PLAINTEXT,
    OPEN_DECISIONS,
    PSK_HEADER_SIZE,
    PSK_MAX_PLAINTEXT,
    PUBLISHED,
    VECTOR_44_STATE,
    applyCounter,
    buildReport,
    classifyAeadError,
    classifyCounter,
    collectControls,
    deriveKeyPair,
    derivePosition,
    encryptPsk,
    encryptStandard,
    inspectEnvelope,
    openAead,
    openEnvelope,
    plaintextBudget,
    readFields,
    windowSpan,
} from "./protocol-boundary-probe.mjs";

const testVectors = readFileSync(new URL("../TEST-VECTORS.md", import.meta.url), "utf8");
const protocol = readFileSync(new URL("../PROTOCOL.md", import.meta.url), "utf8");
const security = readFileSync(new URL("../SECURITY.md", import.meta.url), "utf8");
const implementation = readFileSync(new URL("../IMPLEMENTATION.md", import.meta.url), "utf8");
const hld = readFileSync(new URL("../docs/HLD.md", import.meta.url), "utf8");
const audit = readFileSync(new URL("../docs/audits/current-protocol-boundaries.md", import.meta.url), "utf8");

describe("published vectors", () => {
    it("embeds hex literals that TEST-VECTORS.md actually contains", () => {
        const literals = [
            PUBLISHED.seed00,
            PUBLISHED.seed01,
            PUBLISHED.seed00Private,
            PUBLISHED.seed00Public,
            PUBLISHED.seed01Private,
            PUBLISHED.seed01Public,
            PUBLISHED.seed02Private,
            PUBLISHED.seed02Public,
            PUBLISHED.seed03Private,
            PUBLISHED.seed03Public,
            PUBLISHED.nonce,
            PUBLISHED.plaintextHex,
            PUBLISHED.sharedRecipient,
            PUBLISHED.symmetricKey,
            PUBLISHED.sharedSender,
            PUBLISHED.senderKey,
            PUBLISHED.ciphertext,
            PUBLISHED.encryptedSenderKey,
            PUBLISHED.session0,
            PUBLISHED.position0,
            PUBLISHED.position99,
            PUBLISHED.session1,
            PUBLISHED.position100,
            PUBLISHED.pskSymmetricKey,
            PUBLISHED.pskSenderKey,
            PUBLISHED.pskCiphertext,
            PUBLISHED.pskEncryptedSenderKey,
            PUBLISHED.unicodeLiteral,
            PUBLISHED.payload61,
            PUBLISHED.payload62,
            PUBLISHED.payload63,
        ];
        for (const literal of literals) {
            assert.equal(testVectors.includes(literal), true, literal);
        }
        assert.match(testVectors, /0x02 repeated/);
        assert.match(testVectors, /0x03 repeated/);
        assert.equal(testVectors.toLowerCase().includes(PUBLISHED.initialPsk), true);
    });

    it("matches every published field, including the 169-byte and 173-byte notes", () => {
        const report = buildReport();
        assert.equal(report.vectors.allMatched, true);
        assert.equal(report.vectors.fields["3.1-envelope"].bytes, 169);
        assert.equal(report.vectors.fields["4.3-envelope"].bytes, 173);
        assert.equal(report.vectors.fields["2.1-minimum"].bytes, 142);
        assert.equal(report.vectors.fields["4.5-minimum"].bytes, 146);
        assert.equal(report.vectors.canonicalStandardHex.length, 169 * 2);
        assert.equal(report.vectors.canonicalPskHex.length, 173 * 2);
        assert.equal(report.mlKemMeasured, false);
        assert.equal(report.wireFormatChanged, false);
        assert.equal(report.network, false);
    });

    it("records the 34-byte Unicode literal against the document's 51-byte sentence", () => {
        const report = buildReport();
        assert.equal(report.vectors.fields["3.2-literal-length"].bytes, 34);
        assert.equal(report.vectors.fields["3.2-literal-length"].documentedBytes, 51);
        assert.equal(Buffer.from(PUBLISHED.unicodeLiteral).length, 34);
        const sender = deriveKeyPair(Buffer.alloc(32, 0x01));
        const recipient = deriveKeyPair(Buffer.alloc(32, 0x02));
        const encrypted = encryptStandard({
            senderPublicKey: sender.publicKey,
            recipientPublicKey: recipient.publicKey,
            ephemeralPrivateKey: deriveKeyPair(Buffer.alloc(32, 0x03)).privateKey,
            nonce: Buffer.alloc(12, 0x04),
            plaintext: Buffer.from(PUBLISHED.unicodeLiteral),
        });
        const opened = openEnvelope(encrypted.envelope, {
            role: "recipient",
            privateKey: recipient.privateKey,
            publicKey: recipient.publicKey,
        });
        assert.equal(opened.ok, true);
        assert.equal(opened.plaintext.toString("utf8"), PUBLISHED.unicodeLiteral);
    });
});

describe("negative controls", () => {
    it("meets every claimed code, and success and failure are not the same stub", () => {
        const controls = collectControls();
        assert.equal(controls.length >= 25, true);
        for (const item of controls) {
            assert.deepEqual(
                pick(item.observed, Object.keys(item.expected)),
                item.expected,
                `${item.id}: ${item.claim}`,
            );
        }
        const byId = Object.fromEntries(controls.map((item) => [item.id, item]));
        assert.equal(byId["canonical-recipient-opens"].observed.plaintextHex, PUBLISHED.plaintextHex);
        assert.equal(byId["canonical-psk-recipient-opens"].observed.role, "recipient");
        assert.equal(byId["canonical-psk-sender-opens"].observed.role, "sender");
        assert.equal(byId["canonical-psk-sender-opens"].observed.plaintextHex, PUBLISHED.plaintextHex);
        assert.equal(byId["canonical-psk-sender-opens"].observed.aeadAttempted, true);
        assert.equal(byId["canonical-psk-sender-opens"].observed.setupCompleted, true);
        assert.equal(byId["psk-sender-wrap-bit-flip-recipient-opens"].observed.role, "recipient");
        assert.equal(byId["psk-sender-wrap-bit-flip-recipient-opens"].observed.plaintextHex, PUBLISHED.plaintextHex);
        assert.equal(byId["psk-sender-wrap-bit-flip-sender-fails"].observed.role, "sender");
        assert.equal(byId["psk-sender-wrap-bit-flip-sender-fails"].observed.code, "DECRYPTION_FAILED");
        assert.equal(byId["psk-sender-wrap-bit-flip-sender-fails"].observed.aeadAttempted, true);
        assert.equal(byId["psk-sender-wrap-bit-flip-sender-fails"].observed.setupCompleted, true);
        assert.notEqual(byId["psk-sender-wrap-bit-flip-sender-fails"].observed.code, "HARNESS_SETUP_EXCEPTION");
        assert.equal(byId["garbage-pattern-fails-aead"].observed.code, "DECRYPTION_FAILED");
        assert.equal(byId["psk-garbage-pattern-fails-aead"].observed.role, "recipient");
        assert.equal(byId["psk-garbage-pattern-fails-aead"].observed.code, "DECRYPTION_FAILED");
        assert.equal(byId["psk-garbage-pattern-fails-aead"].observed.aeadAttempted, true);
        assert.equal(byId["psk-garbage-pattern-fails-aead"].observed.setupCompleted, true);
        assert.notEqual(byId["psk-garbage-pattern-fails-aead"].observed.code, "HARNESS_SETUP_EXCEPTION");
        assert.equal(byId["ciphertext-bit-flip"].observed.code, "DECRYPTION_FAILED");
        assert.equal(byId["ciphertext-bit-flip"].observed.aeadAttempted, true);
        assert.notEqual(byId["below-test-vector-minimum"].observed.code, "DECRYPTION_FAILED");
        assert.equal(byId["below-test-vector-minimum"].observed.aeadAttempted, false);
        assert.equal(byId["header-only-not-aead"].observed.code, "HARNESS_TAG_SHORT");
        assert.equal(byId["short-tag-is-not-aead-failure"].observed.aeadAttempted, false);
        assert.equal(byId["missing-psk-is-not-aead-failure"].observed.code, "PSK_NOT_FOUND");
        assert.equal(byId["counter-251-gate-rejects-before-aead"].observed.aeadAttempted, false);
        assert.equal(byId["counter-251-without-gate-opens"].observed.aeadAttempted, true);
        assert.equal(byId["oversized-standard"].observed.envelopeLength, null);
        assert.equal(byId["self-dispatch-labels-sender"].observed.role, "sender");
        assert.equal(byId["third-party-sender-opens"].observed.role, "recipient");
    });

    it("does not count Node's short-tag setup exception as an authentication failure", () => {
        let thrown = null;
        try {
            const decipher = createDecipheriv("chacha20-poly1305", Buffer.alloc(32, 7), Buffer.alloc(12, 8), {
                authTagLength: 16,
            });
            decipher.setAuthTag(Buffer.alloc(15, 9));
        } catch (error) {
            thrown = error;
        }
        assert.equal(thrown?.code, "ERR_CRYPTO_INVALID_AUTH_TAG");
        const classified = classifyAeadError(thrown);
        assert.equal(classified.code, "HARNESS_SETUP_EXCEPTION");
        assert.notEqual(classified.code, "DECRYPTION_FAILED");
        assert.equal(classified.aeadAttempted, false);
        const refused = openAead(Buffer.alloc(32, 7), Buffer.alloc(12, 8), Buffer.alloc(15, 9));
        assert.equal(refused.code, "HARNESS_TAG_SHORT");
    });
});

describe("length readings", () => {
    it("keeps the test-vector minimum and the header minimum apart", () => {
        const headerOnly = Buffer.concat([
            Buffer.from([0x01, 0x01]),
            Buffer.alloc(32, 0xaa),
            Buffer.alloc(32, 0xbb),
            Buffer.alloc(12, 0xcc),
            Buffer.alloc(48, 0xdd),
        ]);
        assert.equal(headerOnly.length, 126);
        const inspected = inspectEnvelope(headerOnly);
        assert.equal(inspected.headerRule, "ACCEPT");
        assert.equal(inspected.testVectorRule, "INVALID_ENVELOPE");
        assert.equal(inspected.tagComplete, false);
        assert.equal(readFields(headerOnly, "test-vector").code, "INVALID_ENVELOPE");
        assert.equal(readFields(headerOnly, "header").code, "HARNESS_TAG_SHORT");
        assert.equal(readFields(headerOnly, "header").aeadAttempted, false);

        const almost = Buffer.concat([headerOnly, Buffer.alloc(15, 0xee)]);
        assert.equal(almost.length, 141);
        assert.equal(inspectEnvelope(almost).testVectorRule, "INVALID_ENVELOPE");
        assert.equal(inspectEnvelope(almost).headerRule, "ACCEPT");
        assert.equal(inspectEnvelope(Buffer.concat([almost, Buffer.alloc(1, 0xee)])).testVectorRule, "ACCEPT");
    });
});

describe("PSK counter readings", () => {
    it("agrees with Test Case 4.4 in both document orders", () => {
        const expected = new Map([
            [51, "ACCEPT"],
            [0, "ACCEPT"],
            [249, "ACCEPT"],
            [250, "ACCEPT"],
            [251, "PSK_COUNTER_OUT_OF_RANGE"],
            [50, "PSK_COUNTER_REPLAY"],
        ]);
        for (const order of ["protocol-8.4", "implementation-pseudocode"]) {
            for (const [counter, code] of expected) {
                const decision = classifyCounter(VECTOR_44_STATE, counter, order);
                assert.equal(decision.code, code, `${order} counter ${counter}`);
                assert.equal(decision.accepted, code === "ACCEPT");
            }
        }
    });

    it("reports different errors when a seen counter is also outside the window", () => {
        const state = { peerLastCounter: 300, seenCounters: [50] };
        const protocolReading = classifyCounter(state, 50, "protocol-8.4");
        const implementationReading = classifyCounter(state, 50, "implementation-pseudocode");
        assert.equal(protocolReading.code, "PSK_COUNTER_REPLAY");
        assert.equal(protocolReading.reason, "replay");
        assert.equal(implementationReading.code, "PSK_COUNTER_OUT_OF_RANGE");
        assert.equal(implementationReading.reason, "too-old");
        assert.notEqual(protocolReading.code, implementationReading.code);
    });

    it("accepts an out-of-order unseen counter and then rejects the duplicate", () => {
        let state = { peerLastCounter: 50, seenCounters: [50] };
        for (const counter of [52, 51, 53]) {
            const applied = applyCounter(state, counter, "protocol-8.4");
            assert.equal(applied.decision.code, "ACCEPT");
            state = applied.state;
        }
        assert.equal(state.peerLastCounter, 53);
        assert.equal(state.seenCounters.length, 4);
        const duplicate = applyCounter(state, 52, "implementation-pseudocode");
        assert.equal(duplicate.decision.code, "PSK_COUNTER_REPLAY");
        assert.equal(duplicate.state.seenCounters.length, 4);
    });

    it("follows the written too-old guard and the inclusive window edges", () => {
        assert.equal(COUNTER_WINDOW, 200);
        assert.equal(classifyCounter({ peerLastCounter: 200, seenCounters: [] }, 0, "protocol-8.4").code, "ACCEPT");
        assert.equal(classifyCounter({ peerLastCounter: 201, seenCounters: [] }, 0, "protocol-8.4").code, "PSK_COUNTER_OUT_OF_RANGE");
        assert.deepEqual(windowSpan(50), representableSpan(0, 250));
        assert.deepEqual(windowSpan(200), representableSpan(0, 400));
        assert.deepEqual(windowSpan(201), representableSpan(1, 401));
        assert.deepEqual(windowSpan(250), representableSpan(50, 450));
        assert.equal(classifyCounter({ peerLastCounter: 0xffffffff, seenCounters: [] }, 0x100000000, "protocol-8.4").code, "HARNESS_COUNTER_UNSPECIFIED");
    });

    it("keeps 401 representable counters when last + 200 is still a uint32", () => {
        const peerLast = 0xffffffff - 200;
        const span = windowSpan(peerLast);
        const state = { peerLastCounter: peerLast, seenCounters: [] };
        assert.deepEqual(span, representableSpan(peerLast - 200, 0xffffffff, 0xffffffff));
        assert.equal(span.capped, false);
        assert.equal(classifyCounter(state, span.low, "protocol-8.4").code, "ACCEPT");
        assert.equal(classifyCounter(state, span.high, "protocol-8.4").code, "ACCEPT");
        assert.equal(classifyCounter(state, span.low - 1, "protocol-8.4").code, "PSK_COUNTER_OUT_OF_RANGE");
        assert.equal(classifyCounter(state, span.high + 1, "protocol-8.4").code, "HARNESS_COUNTER_UNSPECIFIED");
    });

    it("caps the span at UINT32_MAX when last is UINT32_MAX - 199", () => {
        const peerLast = 0xffffffff - 199;
        const span = windowSpan(peerLast);
        const state = { peerLastCounter: peerLast, seenCounters: [] };
        assert.deepEqual(span, representableSpan(peerLast - 200, 0xffffffff, 0x100000000));
        assert.equal(span.count, 400);
        assert.equal(span.capped, true);
        assert.equal(classifyCounter(state, span.high, "protocol-8.4").code, "ACCEPT");
        assert.equal(classifyCounter(state, span.low, "protocol-8.4").code, "ACCEPT");
        assert.equal(classifyCounter(state, span.low - 1, "protocol-8.4").code, "PSK_COUNTER_OUT_OF_RANGE");
        assert.equal(classifyCounter(state, 0x100000000, "protocol-8.4").code, "HARNESS_COUNTER_UNSPECIFIED");
    });

    it("caps the span at UINT32_MAX when last is UINT32_MAX", () => {
        const span = windowSpan(0xffffffff);
        const state = { peerLastCounter: 0xffffffff, seenCounters: [] };
        assert.deepEqual(span, representableSpan(0xffffffff - 200, 0xffffffff, 0xffffffff + 200));
        assert.equal(span.count, 201);
        assert.equal(span.capped, true);
        assert.equal(classifyCounter(state, span.low, "protocol-8.4").code, "ACCEPT");
        assert.equal(classifyCounter(state, span.high, "protocol-8.4").code, "ACCEPT");
        assert.equal(classifyCounter(state, span.low - 1, "protocol-8.4").code, "PSK_COUNTER_OUT_OF_RANGE");
        assert.equal(classifyCounter(state, 0x100000000, "protocol-8.4").code, "HARNESS_COUNTER_UNSPECIFIED");
    });

    it("records those uint32 bounds in the JSON report and leaves rollover undefined", () => {
        const bounds = buildReport().counterWindow.representableBounds;
        assert.equal(bounds.uint32Max, 0xffffffff);
        assert.equal(bounds.rolloverDefined, false);
        assert.equal(bounds.atLastEqualsMaxMinus200.count, 401);
        assert.equal(bounds.atLastEqualsMaxMinus200.capped, false);
        assert.equal(bounds.atLastEqualsMaxMinus200.high, 0xffffffff);
        assert.equal(bounds.atLastEqualsMaxMinus200.endpointsAccepted, true);
        assert.equal(bounds.atLastEqualsMaxMinus200.classifyCounter.aboveHigh, "HARNESS_COUNTER_UNSPECIFIED");
        assert.equal(bounds.atLastEqualsMaxMinus199.count, 400);
        assert.equal(bounds.atLastEqualsMaxMinus199.capped, true);
        assert.equal(bounds.atLastEqualsMaxMinus199.mathematicalHigh, 0x100000000);
        assert.equal(bounds.atLastEqualsMaxMinus199.high, 0xffffffff);
        assert.equal(bounds.atLastEqualsMaxMinus199.classifyCounter.high, "ACCEPT");
        assert.equal(bounds.atLastEqualsMaxMinus199.classifyCounter.belowLow, "PSK_COUNTER_OUT_OF_RANGE");
        assert.equal(bounds.atLastEqualsMaxMinus199.classifyCounter.aboveHigh, "HARNESS_COUNTER_UNSPECIFIED");
        assert.equal(bounds.atLastEqualsMax.count, 201);
        assert.equal(bounds.atLastEqualsMax.capped, true);
        assert.equal(bounds.atLastEqualsMax.mathematicalHigh, 0xffffffff + 200);
        assert.equal(bounds.atLastEqualsMax.classifyCounter.low, "ACCEPT");
        assert.equal(bounds.atLastEqualsMax.classifyCounter.high, "ACCEPT");
        assert.equal(bounds.atLastEqualsMax.classifyCounter.belowLow, "PSK_COUNTER_OUT_OF_RANGE");
        assert.equal(bounds.atLastEqualsMax.classifyCounter.aboveHigh, "HARNESS_COUNTER_UNSPECIFIED");
        assert.equal(bounds.atLastEqualsMax.endpointsAccepted, true);
        assert.equal(bounds.atLastEqualsMax.aboveHighRefused, true);
    });
});

describe("resource budgets", () => {
    it("round-trips the empty and maximum plaintexts at exactly 1024 bytes and refuses one byte more", () => {
        const report = buildReport();
        assert.equal(report.sizes["standard-empty"].envelopeLength, 142);
        assert.equal(report.sizes["standard-empty"].roundTrip, true);
        assert.equal(report.sizes["psk-empty"].envelopeLength, 146);
        assert.equal(report.sizes["psk-empty"].roundTrip, true);
        assert.equal(report.sizes["standard-max"].plaintextLength, MAX_PLAINTEXT);
        assert.equal(report.sizes["standard-max"].envelopeLength, MAX_NOTE_SIZE);
        assert.equal(report.sizes["standard-max"].roundTrip, true);
        assert.equal(report.sizes["psk-max"].plaintextLength, PSK_MAX_PLAINTEXT);
        assert.equal(report.sizes["psk-max"].envelopeLength, MAX_NOTE_SIZE);
        assert.equal(report.sizes["psk-max"].roundTrip, true);
        assert.deepEqual(report.framing.headerFieldSizes.standard.reduce((sum, size) => sum + size, 0), HEADER_SIZE);
        assert.deepEqual(report.framing.headerFieldSizes.psk.reduce((sum, size) => sum + size, 0), PSK_HEADER_SIZE);
        assert.equal(report.framing.shippedFragmentFields, false);
        assert.equal(report.framing.duplicateStandardEnvelopesIdentical, true);
        assert.equal(report.framing.partialNotesEmittedForOversizedPlaintext, 0);
        for (const reserved of [0, 1, 8, 16, 32]) {
            assert.equal(plaintextBudget("standard", reserved).remainingPlaintext, 882 - reserved);
            assert.equal(plaintextBudget("psk", reserved).remainingPlaintext, 878 - reserved);
            assert.equal(plaintextBudget("standard", reserved).wireFormatChanged, false);
        }
    });

    it("fits the documented JSON payloads in one note and does not add a fragment id", () => {
        for (const payload of [PUBLISHED.payload61, PUBLISHED.payload62, PUBLISHED.payload63]) {
            assert.equal(Buffer.from(payload).length <= MAX_PLAINTEXT, true, payload);
        }
        assert.equal(LAYOUT.standard.header, 126);
        assert.equal(Object.hasOwn(LAYOUT.standard, "fragmentIndex"), false);
        assert.equal(Object.hasOwn(LAYOUT.psk, "fragmentIndex"), false);
    });
});

describe("PSK sender unwrap and patterned note", () => {
    it("decrypts the published PSK envelope as the sender and isolates a corrupted wrap", () => {
        const sender = deriveKeyPair(Buffer.alloc(32, 0x01));
        const recipient = deriveKeyPair(Buffer.alloc(32, 0x02));
        const envelope = Buffer.from(buildReport().vectors.canonicalPskHex, "hex");
        const psk = Buffer.alloc(32, 0xaa);
        assert.equal(envelope.length, 173);
        const senderOpen = openEnvelope(envelope, {
            role: "sender",
            privateKey: sender.privateKey,
            publicKey: sender.publicKey,
            initialPsk: psk,
            applyCounterGate: false,
        });
        assert.equal(senderOpen.ok, true);
        assert.equal(senderOpen.role, "sender");
        assert.equal(senderOpen.code, "OK");
        assert.equal(senderOpen.stage, "aead");
        assert.equal(senderOpen.aeadAttempted, true);
        assert.equal(senderOpen.setupCompleted, true);
        assert.equal(senderOpen.plaintext.toString("hex"), PUBLISHED.plaintextHex);

        const flipped = Buffer.from(envelope);
        flipped[LAYOUT.psk.wrap] ^= 0x01;
        const senderFailed = openEnvelope(flipped, {
            role: "sender",
            privateKey: sender.privateKey,
            publicKey: sender.publicKey,
            initialPsk: psk,
            applyCounterGate: false,
        });
        assert.equal(senderFailed.ok, false);
        assert.equal(senderFailed.role, "sender");
        assert.equal(senderFailed.code, "DECRYPTION_FAILED");
        assert.equal(senderFailed.stage, "aead");
        assert.equal(senderFailed.aeadAttempted, true);
        assert.equal(senderFailed.setupCompleted, true);
        assert.equal(senderFailed.plaintext, null);
        assert.notEqual(senderFailed.code, "HARNESS_SETUP_EXCEPTION");

        const recipientOpen = openEnvelope(flipped, {
            role: "recipient",
            privateKey: recipient.privateKey,
            publicKey: recipient.publicKey,
            initialPsk: psk,
            applyCounterGate: false,
        });
        assert.equal(recipientOpen.ok, true);
        assert.equal(recipientOpen.role, "recipient");
        assert.equal(recipientOpen.code, "OK");
        assert.equal(recipientOpen.aeadAttempted, true);
        assert.equal(recipientOpen.setupCompleted, true);
        assert.equal(recipientOpen.plaintext.toString("hex"), PUBLISHED.plaintextHex);
    });

    it("rejects the case 4.5 patterned PSK note only after counter acceptance and AEAD setup", () => {
        const patterned = Buffer.concat([
            Buffer.from("010200000000", "hex"),
            Buffer.alloc(32, 0xaa),
            Buffer.alloc(32, 0xbb),
            Buffer.alloc(12, 0xcc),
            Buffer.alloc(48, 0xdd),
            Buffer.alloc(16, 0xee),
        ]);
        assert.equal(patterned.length, 146);
        const state = { peerLastCounter: 0, seenCounters: [] };
        assert.equal(classifyCounter(state, 0, "protocol-8.4").code, "ACCEPT");
        const recipient = deriveKeyPair(Buffer.alloc(32, 0x02));
        const opened = openEnvelope(patterned, {
            role: "recipient",
            privateKey: recipient.privateKey,
            publicKey: recipient.publicKey,
            initialPsk: Buffer.alloc(32, 0xaa),
            applyCounterGate: true,
            counterOrder: "protocol-8.4",
            counterState: state,
        });
        assert.equal(opened.role, "recipient");
        assert.equal(opened.code, "DECRYPTION_FAILED");
        assert.equal(opened.stage, "aead");
        assert.equal(opened.aeadAttempted, true);
        assert.equal(opened.setupCompleted, true);
        assert.equal(opened.plaintext, null);
        assert.notEqual(opened.code, "HARNESS_SETUP_EXCEPTION");
        assert.notEqual(opened.code, "HARNESS_TAG_SHORT");
        assert.notEqual(opened.code, "PSK_NOT_FOUND");
        const control = buildReport().controls.find((item) => item.id === "psk-garbage-pattern-fails-aead");
        assert.equal(control.matched, true);
        assert.equal(control.observed.code, "DECRYPTION_FAILED");
        assert.equal(control.observed.setupCompleted, true);
        assert.equal(control.observed.aeadAttempted, true);
    });
});

describe("documents and report hygiene", () => {
    it("cites the shipped contract and leaves the open decisions in the audit note", () => {
        assert.match(protocol, /COUNTER_WINDOW\s+=\s+200/);
        assert.match(protocol, /MAX_PAYLOAD_SIZE\s+=\s+882/);
        assert.match(protocol, /PSK_MAX_PAYLOAD_SIZE\s+=\s+878/);
        assert.match(protocol, /MAX_NOTE_SIZE\s+=\s+1024/);
        assert.match(protocol, /has_seen_counter/);
        assert.match(implementation, /seenCounters\.contains/);
        assert.match(security, /application-level fragmentation/);
        assert.match(hld, /protocol has no fragmentation/);
        assert.match(testVectors, /142 bytes minimum/);
        assert.match(testVectors, /146 bytes minimum/);
        for (const decision of OPEN_DECISIONS) {
            assert.equal(audit.includes(decision.id), true, decision.id);
        }
        assert.match(audit, /research\/reference/);
        assert.match(audit, /does not audit Raven/);
        assert.match(audit, /ML-KEM/);
        assert.match(audit, /canonical-psk-sender-opens/);
        assert.match(audit, /psk-sender-wrap-bit-flip-sender-fails/);
        assert.match(audit, /psk-garbage-pattern-fails-aead/);
        assert.match(audit, /400 representable counters/);
        assert.match(audit, /201 representable counters/);
        assert.match(audit, /rollover is not defined/);
    });

    it("omits published private keys and symmetric keys from the JSON report", () => {
        const encoded = JSON.stringify(buildReport());
        for (const secret of [
            PUBLISHED.seed00Private,
            PUBLISHED.seed01Private,
            PUBLISHED.seed02Private,
            PUBLISHED.seed03Private,
            PUBLISHED.symmetricKey,
            PUBLISHED.senderKey,
            PUBLISHED.pskSymmetricKey,
            PUBLISHED.pskSenderKey,
            PUBLISHED.position0,
        ]) {
            assert.equal(encoded.includes(secret), false, secret);
        }
    });

    it("derives session 0 and session 1 from the published schedule", () => {
        const initial = Buffer.alloc(32, 0xaa);
        const first = derivePosition(initial, 0);
        const later = derivePosition(initial, 99);
        const next = derivePosition(initial, 100);
        assert.equal(first.sessionIndex, 0);
        assert.equal(later.sessionIndex, 0);
        assert.equal(next.sessionIndex, 1);
        assert.equal(first.sessionPsk.equals(later.sessionPsk), true);
        assert.equal(first.sessionPsk.equals(next.sessionPsk), false);
        assert.equal(first.positionPsk.equals(later.positionPsk), false);
    });
});

function pick(object, keys) {
    return Object.fromEntries(keys.map((key) => [key, object[key]]));
}

function representableSpan(low, high, mathematicalHigh = high) {
    return {
        low,
        high,
        count: high - low + 1,
        mathematicalHigh,
        capped: mathematicalHigh !== high,
        domain: "representable-uint32",
        rolloverDefined: false,
    };
}
