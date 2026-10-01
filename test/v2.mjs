// Independent Node/OpenSSL P-384, HKDF-SHA-256 and AES-GCM fixture.
const vector = {
    "alicePublic": {
        "crv": "P-384",
        "kty": "EC",
        "x": "qofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3",
        "y": "NhfeSpYmLG9dnpi_kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f",
        "ext": true,
        "key_ops": []
    },
    "bobPublic": {
        "crv": "P-384",
        "kty": "EC",
        "x": "CNmZBXuj0tlpJgBFxVuX8IkCWVmm9DTWUdIH0Z-5bp5P4Ohuvg5k-FuWqcdSld9h",
        "y": "joDx-lsbPO23v-jf_W26dLJ12HW8bMQ-kE5QXyVqtCVf_UPpTTniLWFQHnAKlA6A",
        "ext": true,
        "key_ops": []
    },
    "metadata": {
        "version": 2,
        "suite": "BE8-P384-HKDF-SHA256-A256GCM",
        "contextID": "vector|:\u0000👩🏽‍💻",
        "sender": "101",
        "receiver": "102",
        "senderFingerprint": "-W6Wzot_wuerYbKBVKfGEks3iY2EALna-hBqObnPuJE",
        "receiverFingerprint": "RJeIyeZx-uMuuFmPQfS7sxrKAPa7I7moF1bysQHuh5s",
        "purpose": "data",
        "salt": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    },
    "infoDigest": "d31cc465d8c6db94fd1b1d7a1260f2c0c2f508ea8fdd39c3d20cc75dbb96a668",
    "ciphertext": "6e625ccb93a88c12b52df1b3efa3385d02ad8fbc84e73fcbf681d0af9dabb79691d6c97d2a084967"
};

import Be8, { STORES, V2_SUITE, encodeV2DerivationInfo, jwkThumbprint } from '../lib/bundle.mjs';
import { hkdfAES, decode32, encodeBase64url } from '../lib/v2.mjs';
import { participantHooks, exchangePublicKeys, isAuthenticationFailure } from './participants.mjs';
import { readRecord } from './database.mjs';
import { encryptLegacyFixture } from './legacy-fixture.mjs';

const hex = value => Uint8Array.from(value.match(/../g) || [], byte => parseInt(byte, 16));
const hexString = bytes => [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, '0')).join('');
const range = (start, length) => Uint8Array.from({ length }, (_, index) => start + index);
const encryption = { name: 'AES-GCM', iv: new Uint8Array(12), tagLength: 128 };
const knownMessage = new TextEncoder().encode('Public HKDF fixture');

async function fixedOwner(context, id, scalar, publicKey) {
    const database = await context.open();
    const bytes = new Uint8Array(48); bytes[47] = scalar;
    // Fixed public test scalars stay inside the corresponding local fixture.
    const privateKey = await crypto.subtle.importKey('jwk', { ...publicKey,
        d: encodeBase64url(bytes), key_ops: ['deriveBits'] }, { name: 'ECDH', namedCurve: 'P-384' }, false, ['deriveBits']);
    bytes.fill(0);
    const tx = database.transaction([STORES.scopes, STORES.publicKeys, STORES.privateKeys], 'readwrite');
    tx.objectStore(STORES.scopes).add({ namespace: id, accID: id });
    tx.objectStore(STORES.publicKeys).add({ namespace: id, accID: id, key: publicKey });
    tx.objectStore(STORES.privateKeys).add({ namespace: id, accID: id, key: privateKey, publicKey });
    await database.whenIdle();
    const engine = new Be8(id, database.connection);
    await engine.setup();
    return { engine, database, keyReference: (await engine.generatePrivAndPubKey()).keyReference };
}

QUnit.module('v2 / P-384 ECDH plus HKDF-SHA-256', hooks => {
    participantHooks(hooks);

    // RFC 5869 A.1/A.2/A.3: compare AES encryption using the first 32 known OKM
    // bytes. No export is enabled on the HKDF-derived production key.
    for (const [label, ikm, salt, info, expected] of [
        ['A.1', new Uint8Array(22).fill(0x0b), hex('000102030405060708090a0b0c'), hex('f0f1f2f3f4f5f6f7f8f9'),
            '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf'],
        ['A.2', range(0, 80), range(0x60, 80), range(0xb0, 80),
            'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c'],
        ['A.3', new Uint8Array(22).fill(0x0b), new Uint8Array(), new Uint8Array(),
            '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d'],
    ]) {
        QUnit.test('RFC 5869 ' + label + ' through non-extractable AES interoperability', async function (assert) {
            const secret = new Uint8Array(ikm);
            const actual = await hkdfAES(secret, salt, info, 'data');
            const reference = await crypto.subtle.importKey('raw', hex(expected), 'AES-GCM', false, ['encrypt']);
            const [cipher, known] = await Promise.all([
                crypto.subtle.encrypt(encryption, actual, knownMessage), crypto.subtle.encrypt(encryption, reference, knownMessage),
            ]);
            assert.true(hexString(cipher) === hexString(known), 'HKDF matches the published SHA-256 OKM prefix without exporting a derived key');
            assert.false(actual.extractable, 'The production AES key is non-extractable');
            assert.true(secret.every(byte => byte === 0), 'The JS IKM view is overwritten after native HKDF import');
            await assert.rejects(crypto.subtle.exportKey('raw', actual), error => error.name === 'InvalidAccessError', 'Export remains denied');
        });
    }

    QUnit.test('Full 384-bit ECDH and deterministic field encoding match an independent Node/OpenSSL vector', async function (assert) {
        const alice = await fixedOwner(this, '101', 1, vector.alicePublic);
        const bob = await fixedOwner(this, '102', 2, vector.bobPublic);
        const info = encodeV2DerivationInfo(vector.metadata);
        assert.strictEqual(hexString(await crypto.subtle.digest('SHA-256', info)), vector.infoDigest,
            'Length prefixes, field ordering, Unicode and raw fingerprint encoding match the independent vector');
        const key = await alice.engine.getDerivedKey(vector.bobPublic, alice.keyReference, vector.metadata);
        const recipient = await bob.engine.getDerivedKey(vector.alicePublic, bob.keyReference, structuredClone(vector.metadata));
        const plaintext = new TextEncoder().encode('v2 full-width P-384 test');
        const ciphertext = await crypto.subtle.encrypt(encryption, key, plaintext);
        assert.true(hexString(ciphertext) === vector.ciphertext, 'The full 48-byte ECDH output produces the independent HKDF/AES-GCM result');
        assert.true(new TextDecoder().decode(await crypto.subtle.decrypt(encryption, recipient, ciphertext)) === 'v2 full-width P-384 test',
            'The independent recipient derives an interoperable native key');
        assert.true(key !== recipient && !key.extractable && !recipient.extractable, 'Participants retain distinct non-extractable keys');
    });

    QUnit.test('New contexts generate public salts; recipient reuses metadata and does not generate randomness', async function (assert) {
        const { alice, bob } = this;
        const first = await alice.createContext(bob.publicKey, { contextID: 'shared context' });
        const second = await alice.createContext(bob.publicKey, { contextID: 'shared context' });
        assert.true(first.derivation.salt !== second.derivation.salt, 'Separate new contexts have fresh salts');
        assert.strictEqual(decode32(first.derivation.salt).length, 32, 'The public salt has 32 bytes');
        assert.strictEqual(first.derivation.suite, V2_SUITE, 'The suite is explicit');
        assert.strictEqual(first.derivation.senderFingerprint, await jwkThumbprint(alice.publicKey), 'Sender fingerprint comes from the actual local key');
        assert.strictEqual(first.derivation.receiverFingerprint, await jwkThumbprint(bob.publicKey), 'Receiver fingerprint comes from the actual peer key');
        const transfer = structuredClone(first.derivation);
        const recipient = await bob.derive(alice.publicKey, transfer);
        const packet = await alice.engine.encryptText(first.key, 'Transferred salt');
        assert.true(await bob.engine.decryptText(recipient, packet.cipherText, packet.iv) === 'Transferred salt', 'Receiver metadata deterministically recreates the key');
        assert.true(JSON.stringify(transfer) === JSON.stringify(first.derivation), 'Recipient derivation does not replace the salt or mutate public metadata');
        const repeated = await bob.derive(alice.publicKey, transfer);
        assert.true(await bob.engine.decryptText(repeated, packet.cipherText, packet.iv) === 'Transferred salt', 'Repeated receiver derivation remains interoperable');
    });

    for (const variation of ['salt', 'context', 'purpose', 'direction']) {
        QUnit.test('Different ' + variation + ' is cryptographically separated with the same ECDH pair', async function (assert) {
            const { alice, bob } = this;
            const context = await alice.createContext(bob.publicKey, { contextID: 'ctx|:📎' });
            const packet = await alice.engine.encryptText(context.key, 'Domain-separated data');
            const changed = { ...context.derivation };
            if (variation === 'salt') { const salt = decode32(changed.salt); salt[0] ^= 1; changed.salt = encodeBase64url(salt); }
            if (variation === 'context') changed.contextID += ':different';
            if (variation === 'purpose') changed.purpose = 'attachment';
            if (variation === 'direction') {
                [changed.sender, changed.receiver] = [changed.receiver, changed.sender];
                [changed.senderFingerprint, changed.receiverFingerprint] = [changed.receiverFingerprint, changed.senderFingerprint];
            }
            const wrong = await bob.derive(alice.publicKey, changed);
            await assert.rejects(bob.engine.decryptText(wrong, packet.cipherText, packet.iv), isAuthenticationFailure,
                'A valid but different context yields a different AES key');
            const correct = await bob.derive(alice.publicKey, context.derivation);
            assert.true(await bob.engine.decryptText(correct, packet.cipherText, packet.iv) === 'Domain-separated data', 'The original metadata still works');
        });
    }

    QUnit.test('Key wrapping has a separate purpose and only wrap/unwrap usages', async function (assert) {
        const { alice, bob } = this;
        const context = await alice.createContext(bob.publicKey, { purpose: 'key-wrap' });
        const recipient = await bob.derive(alice.publicKey, context.derivation);
        assert.deepEqual(context.key.usages, ['wrapKey', 'unwrapKey'], 'Wrapping purpose does not permit direct data encryption');
        const publicKey = await crypto.subtle.importKey('jwk', alice.publicKey, { name: 'ECDH', namedCurve: 'P-384' }, true, []);
        const wrapped = await crypto.subtle.wrapKey('jwk', publicKey, context.key, encryption);
        const restored = await crypto.subtle.unwrapKey('jwk', wrapped, recipient, encryption,
            { name: 'ECDH', namedCurve: 'P-384' }, true, []);
        assert.strictEqual(await jwkThumbprint(await crypto.subtle.exportKey('jwk', restored)), await jwkThumbprint(alice.publicKey),
            'Independent peers interoperate when wrapping a public test key');
        const changed = { ...context.derivation, salt: encodeBase64url(new Uint8Array(32)) };
        const wrong = await bob.derive(alice.publicKey, changed);
        await assert.rejects(crypto.subtle.unwrapKey('jwk', wrapped, wrong, encryption,
            { name: 'ECDH', namedCurve: 'P-384' }, true, []), isAuthenticationFailure, 'Wrapping authentication fails under another salt');
        await assert.rejects(alice.engine.encryptText(context.key, 'Wrong usage'), error => error.name === 'InvalidAccessError', 'Wrapping keys cannot silently become data keys');
        const data = await bob.derive(alice.publicKey, { ...context.derivation, purpose: 'data' });
        await assert.rejects(crypto.subtle.decrypt(encryption, data, wrapped), isAuthenticationFailure,
            'With the same salt and endpoint keys, the data purpose derives different AES material from key-wrap');
        await assert.rejects(crypto.subtle.unwrapKey('jwk', wrapped, data, encryption,
            { name: 'ECDH', namedCurve: 'P-384' }, true, []), error => error.name === 'InvalidAccessError', 'Data keys cannot silently become wrapping keys');
        await assert.rejects(crypto.subtle.exportKey('raw', context.key), error => error.name === 'InvalidAccessError', 'Wrapping key export is denied');
    });

    QUnit.test('Actual fingerprints and local IDs are enforced, not caller-provided aliases', async function (assert) {
        const { alice, bob, eve } = this;
        const context = await alice.createContext(bob.publicKey);
        await assert.rejects(bob.derive(eve.publicKey, context.derivation), error => error.code === 'DERIVATION_KEY_MISMATCH', 'A different peer key cannot retain the declared sender fingerprint');
        await assert.rejects(bob.derive(alice.publicKey, { ...context.derivation, receiverFingerprint: await jwkThumbprint(eve.publicKey) }),
            error => error.code === 'DERIVATION_KEY_MISMATCH', 'A caller cannot replace the actual local fingerprint');
        await assert.rejects(eve.derive(alice.publicKey, context.derivation), error => error.code === 'INVALID_DERIVATION_CONTEXT', 'An unrelated local endpoint cannot derive for Bob');
        await assert.rejects(bob.createContext(alice.publicKey, { receiver: bob.id }), error => error.code === 'INVALID_DERIVATION_CONTEXT', 'A self endpoint cannot claim a different public key');
    });

    QUnit.test('Metadata is strict, deterministic and never inferred from ciphertexts', async function (assert) {
        const { alice, bob } = this;
        const context = await alice.createContext(bob.publicKey, { contextID: 'a|b:c\u0000' });
        const keyReference = (await bob.engine.generatePrivAndPubKey()).keyReference;
        await assert.rejects(bob.engine.getDerivedKey(alice.publicKey, keyReference), error => error.code === 'DERIVATION_CONTEXT_REQUIRED', 'No metadata means no implicit salt or legacy fallback');
        for (const metadata of [
            { ...context.derivation, version: 1 }, { ...context.derivation, suite: 'unknown' },
            { ...context.derivation, salt: '' }, { ...context.derivation, purpose: 'unknown' },
            { ...context.derivation, contextID: '\ud800' }, { ...context.derivation, extra: true },
        ]) {
            await assert.rejects(bob.derive(alice.publicKey, metadata), error => error.code === 'INVALID_DERIVATION_CONTEXT', 'Unsupported or ambiguous metadata is rejected explicitly');
        }
        const reordered = Object.fromEntries(Object.entries(context.derivation).reverse());
        assert.true(hexString(encodeV2DerivationInfo(reordered)) === hexString(encodeV2DerivationInfo(context.derivation)), 'Property order does not affect info bytes');
        assert.true(hexString(encodeV2DerivationInfo({ ...context.derivation, contextID: 'a' })) !== hexString(encodeV2DerivationInfo(context.derivation)), 'Field lengths make separator-like contexts unambiguous');
        const normalized = await alice.createContext(bob.publicKey, { contextID: 'é' });
        const decomposed = { ...normalized.derivation, contextID: 'e\u0301' };
        assert.true(hexString(encodeV2DerivationInfo(normalized.derivation)) !== hexString(encodeV2DerivationInfo(decomposed)), 'Unicode normalization is not silently applied');
    });

    QUnit.test('Convenience APIs transfer metadata, enforce purpose/context and never fall back after authentication failure', async function (assert) {
        const { alice, bob } = this;
        await exchangePublicKeys(alice, bob);
        const packet = await alice.engine.encryptTextSimple(alice.id, bob.id, 'Bound context', { contextID: 'application context' });
        assert.true(await bob.engine.decryptTextSimple(alice.id, bob.id, packet.cipherText, packet.iv, packet.derivation,
            { contextID: 'application context' }) === 'Bound context', 'The receiver can check its application-supplied expected context');
        await assert.rejects(bob.engine.decryptTextSimple(alice.id, bob.id, packet.cipherText, packet.iv, packet.derivation,
            { contextID: 'other context' }), error => error.code === 'INVALID_DERIVATION_CONTEXT', 'Unexpected application context is refused');
        await assert.rejects(bob.engine.decryptImageSimple(alice.id, bob.id, packet.cipherText, packet.iv, packet.derivation),
            error => error.code === 'INVALID_DERIVATION_CONTEXT', 'Text data cannot be interpreted as an attachment context');
        await assert.rejects(bob.engine.decryptTextSimple(alice.id, bob.id, packet.cipherText, packet.iv),
            error => error.code === 'DERIVATION_CONTEXT_REQUIRED', 'Legacy-looking packets are not auto-detected');
        const altered = { ...packet.derivation, contextID: 'tampered' };
        await assert.rejects(bob.engine.decryptTextSimple(alice.id, bob.id, packet.cipherText, packet.iv, altered), isAuthenticationFailure,
            'Authentication failure under changed metadata is propagated without trying legacy');
        const image = await alice.engine.encryptImageSimple(alice.id, bob.id, '', { contextID: 'attachment' });
        assert.strictEqual(image.derivation.purpose, 'attachment', 'Image convenience uses the attachment domain');
        assert.true(await bob.engine.decryptImageSimple(alice.id, bob.id, image.cipherImage, image.iv, image.derivation) === '', 'Existing image content API interoperates under the new KDF');
    });

    QUnit.test('Existing deriveKey-only non-extractable identities survive and remain explicit legacy readers', async function (assert) {
        const database = await this.open();
        const oldPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, false, ['deriveKey']);
        const ownPublic = await crypto.subtle.exportKey('jwk', oldPair.publicKey);
        const tx = database.transaction([STORES.scopes, STORES.publicKeys, STORES.privateKeys], 'readwrite');
        tx.objectStore(STORES.scopes).put({ namespace: '104', accID: '104' });
        tx.objectStore(STORES.publicKeys).put({ namespace: '104', accID: '104', key: ownPublic });
        tx.objectStore(STORES.privateKeys).put({ namespace: '104', accID: '104', key: oldPair.privateKey, publicKey: ownPublic });
        await database.whenIdle();
        const engine = new Be8('104', database.connection);
        await engine.setup();
        await engine.addPublicKey(this.bob.id, this.bob.publicKey, { trust: 'confirmed' });
        const { keyReference } = await engine.generatePrivAndPubKey();
        await assert.rejects(engine.createDerivationContext(this.bob.publicKey, keyReference,
            { contextID: 'no silent replacement', sender: '104', receiver: this.bob.id, purpose: 'data' }),
        error => error.code === 'V2_KEY_USAGE_UNAVAILABLE', 'v2 cannot mutate an existing non-extractable key usage');
        assert.strictEqual(await jwkThumbprint(await engine.getMyPublicKey()), await jwkThumbprint(ownPublic), 'Unsupported v2 usage does not change identity');
        const pub = await crypto.subtle.importKey('jwk', this.bob.publicKey, { name: 'ECDH', namedCurve: 'P-384' }, true, []);
        const historical = await crypto.subtle.deriveKey({ name: 'ECDH', public: pub }, oldPair.privateKey,
            { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
        const packet = await encryptLegacyFixture(historical, 'Historical direct ECDH ciphertext');
        const reader = await engine.getLegacyDerivedKey(this.bob.publicKey, keyReference);
        assert.deepEqual(reader.usages, ['decrypt'], 'The explicit old KDF exposes only a decrypt-capable AES key');
        assert.true(await engine.decryptTextLegacy(reader, packet.cipherText, packet.iv) === 'Historical direct ECDH ciphertext', 'Old data remains readable with the exact original KDF');
        const newPeerReader = await this.bob.engine.getLegacyDerivedKey(ownPublic, (await this.bob.engine.generatePrivAndPubKey()).keyReference);
        assert.true(await this.bob.engine.decryptTextLegacy(newPeerReader, packet.cipherText, packet.iv) === 'Historical direct ECDH ciphertext', 'deriveBits-only peers reproduce the explicit historical AES prefix');
        await assert.rejects(engine.encryptText(reader, 'Forbidden legacy write'), error => error.name === 'InvalidAccessError', 'The old KDF cannot silently encrypt new data');
        await assert.rejects(crypto.subtle.exportKey('jwk', await readRecord(database, 'privateKeys', '104')),
            error => error.name === 'InvalidAccessError', 'The retained old private key is still non-extractable');
    });
});
