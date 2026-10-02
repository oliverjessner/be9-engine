// Test-only historical layouts/writers, all with native crypto. Every owner
// reads its private key only from its own database. Only public keys, public
// metadata and encrypted packets are passed between participants.
import { STORES, jwkThumbprint, encodeBase64url, decodeBase64url } from '../lib/bundle.mjs';
import { BE8_STORES, BE8_V2_SUITE, BE8_GROUP_SUITE, BE8_DOMAINS } from '../lib/legacy-be8.mjs';
import { withTransaction, requestResult } from '../lib/persistence.mjs';
import { hkdfAES, encodeV2DerivationInfo } from '../lib/v2.mjs';
import { encodeEnvelopeAAD } from '../lib/envelope.mjs';
import { encodeGroupInfo } from '../lib/group-profile.mjs';
import { streamIdentity } from '../lib/replay.mjs';
export const rows = (database, name) => withTransaction(database.connection, [name], 'readonly', tx => requestResult(tx.objectStore(name).getAll()));
export async function toBe8Layout(context, peer, extraUpgrade) {
    peer.database.close();
    const database = await context.open(peer.database.name, { version: 2, skipEngineSchema: true, upgrade(db, tx) {
        for (const key of Object.keys(STORES)) tx.objectStore(STORES[key]).name = BE8_STORES[key];
        if (extraUpgrade) extraUpgrade(db, tx);
    } });
    return { id: peer.id, publicKey: peer.publicKey, database };
}
async function ownPrivate(owner) {
    return withTransaction(owner.database.connection, [BE8_STORES.privateKeys], 'readonly', tx =>
        requestResult(tx.objectStore(BE8_STORES.privateKeys).get([owner.id, owner.id]), record => record.key));
}
export async function be8Packet(owner, receiverPublic, value, { purpose = 'data', contextID = 'old context', sequence = '1', group = null } = {}) {
    const metadata = { version: 2, suite: BE8_V2_SUITE, contextID, sender: owner.id, receiver: receiverPublic.accID,
        senderFingerprint: await jwkThumbprint(owner.publicKey), receiverFingerprint: await jwkThumbprint(receiverPublic),
        purpose, salt: encodeBase64url(crypto.getRandomValues(new Uint8Array(32))) };
    const peer = await crypto.subtle.importKey('jwk', receiverPublic, { name: 'ECDH', namedCurve: 'P-384' }, false, []);
    const bytes = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: peer }, await ownPrivate(owner), 384));
    const key = await hkdfAES(bytes, decodeBase64url(metadata.salt), encodeV2DerivationInfo(metadata, true), purpose);
    const header = { ...metadata, sequence, group, iv: encodeBase64url(crypto.getRandomValues(new Uint8Array(12))) };
    const plaintext = typeof value === 'string' ? new TextEncoder().encode(value) : value;
    const algorithm = { name: 'AES-GCM', tagLength: 128, iv: decodeBase64url(header.iv), additionalData: encodeEnvelopeAAD(header, true) };
    const encrypted = purpose === 'key-wrap'
        ? await crypto.subtle.wrapKey('raw', await crypto.subtle.importKey('raw', plaintext, 'AES-GCM', true, ['encrypt', 'decrypt']), key, algorithm)
        : await crypto.subtle.encrypt(algorithm, key, plaintext);
    return { header, ciphertext: encodeBase64url(encrypted) };
}
export async function be8Epoch(owner, recipients, groupID = 'gOld', epoch = '1') {
    const secret = crypto.getRandomValues(new Uint8Array(32));
    try {
        const group = { groupID, epoch, generation: encodeBase64url(await crypto.subtle.digest('SHA-256', secret)) };
        const key = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
        await withTransaction(owner.database.connection, [BE8_STORES.groupEpochs, BE8_STORES.activeEpochs], 'readwrite', tx => {
            tx.objectStore(BE8_STORES.groupEpochs).put({ namespace: owner.id, ...group, issuer: owner.id, key });
            return requestResult(tx.objectStore(BE8_STORES.activeEpochs).put({ namespace: owner.id, groupID, epoch }));
        });
        const packages = [];
        for (const recipient of recipients) packages.push(await be8Packet(owner, recipient.publicKey, secret, { purpose: 'key-wrap', contextID: 'old handoff', group }));
        return { ...group, issuer: owner.id, packages };
    } finally { secret.fill(0); }
}
export async function be8GroupPacket(owner, group, value, { purpose = 'data', sequence = '1' } = {}) {
    const record = await withTransaction(owner.database.connection, [BE8_STORES.groupEpochs], 'readonly', tx =>
        requestResult(tx.objectStore(BE8_STORES.groupEpochs).get([owner.id, group.groupID, group.epoch])));
    const header = { version: 2, suite: BE8_GROUP_SUITE, contextID: 'old group context', sender: owner.id, receiver: group.groupID,
        senderFingerprint: await jwkThumbprint(owner.publicKey), receiverFingerprint: group.generation, purpose,
        salt: encodeBase64url(crypto.getRandomValues(new Uint8Array(32))), sequence,
        iv: encodeBase64url(crypto.getRandomValues(new Uint8Array(12))), group: { groupID: group.groupID, epoch: group.epoch, generation: group.generation } };
    const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: decodeBase64url(header.salt), info: encodeGroupInfo(header, true) }, record.key,
        { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', tagLength: 128, iv: decodeBase64url(header.iv), additionalData: encodeEnvelopeAAD(header, true) }, key,
        typeof value === 'string' ? new TextEncoder().encode(value) : value);
    return { header, ciphertext: encodeBase64url(ciphertext) };
}
export async function seedBe8Receive(owner, header, accepted = false) {
    const streamID = await streamIdentity(header, true);
    await withTransaction(owner.database.connection, [BE8_STORES.contexts, BE8_STORES.receiveState], 'readwrite', tx => {
        tx.objectStore(BE8_STORES.contexts).put({ namespace: owner.id, contextID: header.contextID, status: 'open', streams: [{ streamID, direction: 'receive' }] });
        return requestResult(tx.objectStore(BE8_STORES.receiveState).put({ namespace: owner.id, contextID: header.contextID, streamID,
            highest: accepted ? header.sequence : '0', bitmap: '0'.repeat(31) + (accepted ? '1' : '0') }));
    });
}
export async function seedBe8Budget(owner, metadata) {
    const prefix = new TextEncoder().encode('BE8-GCM-USAGE');
    const { version, suite, contextID, sender, receiver, senderFingerprint, receiverFingerprint, purpose, salt } = metadata;
    const info = encodeV2DerivationInfo({ version, suite, contextID, sender, receiver, senderFingerprint, receiverFingerprint, purpose, salt }, true);
    const value = new Uint8Array(prefix.length + 32 + info.length); value.set(prefix); value.set(decodeBase64url(metadata.salt), prefix.length); value.set(info, prefix.length + 32);
    const derivationID = encodeBase64url(await crypto.subtle.digest('SHA-256', value));
    await withTransaction(owner.database.connection, [BE8_STORES.keyUsage], 'readwrite', tx => requestResult(tx.objectStore(BE8_STORES.keyUsage).put({ derivationID, encryptions: 65536, blocks: 65536 })));
    return derivationID;
}
// Public AAD vector is also retained independently from the new Be9 vector.
export const oldAADVector = { version: 2, suite: BE8_V2_SUITE, contextID: 'ctx🌍', sender: '101', receiver: '102',
    senderFingerprint: encodeBase64url(new Uint8Array(32)), receiverFingerprint: encodeBase64url(new Uint8Array(32).fill(1)), purpose: 'data',
    salt: encodeBase64url(new Uint8Array(32).fill(2)), iv: encodeBase64url(new Uint8Array(12).fill(3)), sequence: '18446744073709551615', group: null };
export const oldAADHash = '7c90bdeadf7097ef265a27f361e41fd8e70bf2b2bee5ec62cf6b327efa411b31';
export { BE8_DOMAINS };
