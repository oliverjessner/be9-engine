import { encodeBase64url } from '../lib/encoding.mjs';

// Historical UUID/UTF-8 + padded Base64 creation belongs only to test fixtures.
// Native WebCrypto remains genuine; no new production legacy writer exists.
export async function encryptLegacyFixture(key, text) {
    const iv = crypto.randomUUID();
    const bytes = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new TextEncoder().encode(iv), tagLength: 128 },
        key, new TextEncoder().encode(text));
    const unpadded = encodeBase64url(bytes).replace(/-/g, '+').replace(/_/g, '/');
    return { cipherText: unpadded + '='.repeat((4 - unpadded.length % 4) % 4), iv };
}

// Test-only retained ECDH group records. The private key never leaves this
// participant's local database; only the public half is exchanged.
export async function createLegacyGroup(engine, database, version, groupID) {
    const { STORES } = await import('../lib/bundle.mjs');
    const { withTransaction, requestResult } = await import('../lib/persistence.mjs');
    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, false, ['deriveBits']);
    const publicKey = await crypto.subtle.exportKey('jwk', pair.publicKey);
    await withTransaction(database.connection, [STORES.groupKeys], 'readwrite', tx => {
        const store = tx.objectStore(STORES.groupKeys);
        return requestResult(store.get([engine.getAccID(), groupID, version]), existing => existing ? undefined
            : requestResult(store.add({ namespace: engine.getAccID(), groupID, version, key: publicKey, privateKey: pair.privateKey })));
    });
    return engine.getLegacyGroupKeyReference(groupID, version);
}
export async function legacyToPublic(participant, publicKey, text) {
    const { readRecord } = await import('./database.mjs');
    const privateKey = await readRecord(participant.database, 'privateKeys', participant.id);
    const peer = await crypto.subtle.importKey('jwk', publicKey, { name: 'ECDH', namedCurve: 'P-384' }, false, []);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: peer }, privateKey, 384));
    try {
        const key = await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt']);
        return encryptLegacyFixture(key, text);
    } finally { bits.fill(0); }
}
export async function legacyGroupToPublic(participant, groupID, version, publicKey, text) {
    const { STORES } = await import('../lib/bundle.mjs');
    const { withTransaction, requestResult } = await import('../lib/persistence.mjs');
    const record = await withTransaction(participant.database.connection, [STORES.groupKeys], 'readonly', tx =>
        requestResult(tx.objectStore(STORES.groupKeys).get([participant.id, groupID, version])));
    const peer = await crypto.subtle.importKey('jwk', publicKey, { name: 'ECDH', namedCurve: 'P-384' }, false, []);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: peer }, record.privateKey, 384));
    try {
        const key = await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt']);
        return encryptLegacyFixture(key, text);
    } finally { bits.fill(0); }
}

export async function legacyGroupHKDFPacket(participant, groupID, version, peerPublic, text) {
    const { STORES } = await import('../lib/bundle.mjs');
    const { withTransaction, requestResult } = await import('../lib/persistence.mjs');
    const { createV2Metadata, hkdfAES, encodeV2DerivationInfo, decode32 } = await import('../lib/v2.mjs');
    const { BE8_V2_SUITE } = await import('../lib/legacy-be8.mjs');
    const record = await withTransaction(participant.database.connection, [STORES.groupKeys], 'readonly', tx =>
        requestResult(tx.objectStore(STORES.groupKeys).get([participant.id, groupID, version])));
    const sender = groupID + ':' + version;
    const derivation = { ...await createV2Metadata(sender, record.key, peerPublic,
        { sender, receiver: peerPublic.accID, contextID: 'historic HKDF group', purpose: 'data' }), suite: BE8_V2_SUITE };
    const peer = await crypto.subtle.importKey('jwk', peerPublic, { name: 'ECDH', namedCurve: 'P-384' }, false, []);
    const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: peer }, record.privateKey, 384));
    const key = await hkdfAES(bits, decode32(derivation.salt), encodeV2DerivationInfo(derivation, true), 'data');
    return { ...await encryptLegacyFixture(key, text), derivation };
}
