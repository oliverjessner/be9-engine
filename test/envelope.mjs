import { participantHooks, exchangePublicKeys, isAuthenticationFailure } from './participants.mjs';
import { encodeBase64url, decodeBase64url, encodeEnvelopeAAD } from '../lib/bundle.mjs';

QUnit.module('v2 authenticated envelope', hooks => {
    participantHooks(hooks);
    hooks.beforeEach(async function () { await exchangePublicKeys(this.alice, this.bob, this.eve); });
    QUnit.test('Independent peers authenticate binary data and all ordered expectations', async function (assert) {
        const { alice, bob } = this;
        const expected = { sender: alice.id, receiver: bob.id, contextID: 'independent-context', purpose: 'data' };
        const bytes = new Uint8Array([0, 255, 1]);
        await alice.engine.openContext(expected.contextID);
        const envelope = await alice.engine.encryptEnvelope(alice.id, bob.id, bytes, { contextID: expected.contextID, purpose: expected.purpose });
        assert.true((await bob.engine.decryptEnvelope(structuredClone(envelope), expected)).every((value, index) => value === bytes[index]), 'Actual recipient independently authenticates all bytes');
        assert.true((await bob.engine.decryptEnvelope(envelope, expected)).length === 3, 'Low-level archive decryption is repeatable');
        for (const changed of [{ contextID: 'wrong' }, { sender: '103' }, { receiver: '103' }, { purpose: 'attachment' }]) {
            await assert.rejects(bob.engine.decryptEnvelope(envelope, { ...expected, ...changed }), error => error.code === 'ENVELOPE_EXPECTATION_MISMATCH', 'An unchanged packet fails an independently wrong expectation');
        }
    });
    QUnit.test('Every header field is either schema-rejected or fails authentication', async function (assert) {
        const { alice, bob } = this;
        const expected = { sender: alice.id, receiver: bob.id, contextID: 'header-fields', purpose: 'data' };
        await alice.engine.openContext(expected.contextID);
        const envelope = await alice.engine.encryptEnvelope(alice.id, bob.id, new Uint8Array([1]), { contextID: expected.contextID, purpose: expected.purpose });
        const changes = { version: 1, suite: 'unknown', contextID: 'modified', sender: '103', receiver: '103',
            senderFingerprint: encodeBase64url(new Uint8Array(32)), receiverFingerprint: encodeBase64url(new Uint8Array(32)),
            purpose: 'attachment', salt: encodeBase64url(new Uint8Array(32)), iv: encodeBase64url(new Uint8Array(12)), sequence: '2',
            group: { groupID: 'gTest', epoch: '1', generation: encodeBase64url(new Uint8Array(32)) } };
        for (const [field, value] of Object.entries(changes)) {
            const altered = { ...envelope, header: { ...envelope.header, [field]: value } };
            const expectedCode = ['version', 'suite', 'group'].includes(field) ? 'INVALID_ENVELOPE'
                : ['contextID', 'sender', 'receiver', 'purpose'].includes(field) ? 'ENVELOPE_EXPECTATION_MISMATCH'
                    : field.endsWith('Fingerprint') ? 'DERIVATION_KEY_MISMATCH' : undefined;
            await assert.rejects(bob.engine.decryptEnvelope(altered, expected), error => expectedCode
                ? error.code === expectedCode : isAuthenticationFailure(error), 'Changing ' + field + ' cannot release plaintext');
        }
        const sequence = { ...envelope, header: { ...envelope.header, sequence: '2' } };
        await assert.rejects(bob.engine.decryptEnvelope(sequence, expected), isAuthenticationFailure, 'Valid sequence changes specifically fail native AAD authentication');
        const ciphertext = decodeBase64url(envelope.ciphertext); ciphertext[0] ^= 1;
        await assert.rejects(bob.engine.decryptEnvelope({ ...envelope, ciphertext: encodeBase64url(ciphertext) }, expected), isAuthenticationFailure, 'Body tampering never returns plaintext');
        assert.true((await bob.engine.decryptEnvelope(envelope, expected)).length === 1, 'Failures do not change the valid packet');
    });
    QUnit.test('Strict field schema rejects extras, lossy sequence numbers and missing expectations', async function (assert) {
        const { alice, bob } = this;
        const expected = { sender: alice.id, receiver: bob.id, contextID: 'schema', purpose: 'data' };
        await alice.engine.openContext(expected.contextID);
        const envelope = await alice.engine.encryptEnvelope(alice.id, bob.id, new Uint8Array(), { contextID: expected.contextID, purpose: expected.purpose });
        for (const header of [{ ...envelope.header, sequence: 1 }, { ...envelope.header, sequence: '01' },
            { ...envelope.header, sequence: '18446744073709551616' }, { ...envelope.header, extra: true }]) {
            await assert.rejects(bob.engine.decryptEnvelope({ ...envelope, header }, expected), error => error.code === 'INVALID_ENVELOPE', 'Ambiguous or unsupported schema rejects');
        }
        let reads = 0;
        const accessor = { ...envelope.header };
        Object.defineProperty(accessor, 'sequence', { enumerable: true, get() { reads++; return '1'; } });
        await assert.rejects(bob.engine.decryptEnvelope({ ...envelope, header: accessor }, expected), error => error.code === 'INVALID_ENVELOPE', 'Accessors are not wire-data fields');
        assert.strictEqual(reads, 0, 'Header validation never invokes caller accessors');
        const hidden = { ...envelope.header }; Object.defineProperty(hidden, 'sequence', { value: '1', enumerable: false });
        await assert.rejects(bob.engine.decryptEnvelope({ ...envelope, header: hidden }, expected), error => error.code === 'INVALID_ENVELOPE', 'Non-enumerable wire fields are rejected');
        await assert.rejects(bob.engine.decryptEnvelope(envelope), error => error.code === 'ENVELOPE_EXPECTATION_REQUIRED', 'No expectations are inferred wholesale from untrusted data');
    });
});

QUnit.module('v2 envelope / independent public encoding vector', () => {
    QUnit.test('AAD matches independent Python struct/SHA-256 encoding through the full uint64 range', async function (assert) {
        const header = { version: 2, suite: 'BE9-P384-HKDF-SHA256-A256GCM', contextID: 'ctx🌍', sender: '101', receiver: '102',
            senderFingerprint: encodeBase64url(new Uint8Array(32)), receiverFingerprint: encodeBase64url(new Uint8Array(32).fill(1)),
            purpose: 'data', salt: encodeBase64url(new Uint8Array(32).fill(2)), iv: encodeBase64url(new Uint8Array(12).fill(3)),
            sequence: '18446744073709551615', group: null };
        const aad = encodeEnvelopeAAD(header);
        const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', aad))].map(byte => byte.toString(16).padStart(2, '0')).join('');
        assert.strictEqual(digest, '4823db3985f140873fd6c93cfa25b41d7067dd6694a04e6253af901e07012ca1', 'Deterministic public header bytes match independent encoding');
        assert.strictEqual(aad.length, 255, 'All length prefixes and fields are accounted for');
    });
});
