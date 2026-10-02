/* global BigInt */
import { engineError } from './persistence.mjs';
import { derivationSnapshot, createV2Metadata, deriveV2AES, encodeV2DerivationInfo, encodeFields, decode32, scalarString } from './v2.mjs';
import { encodeBase64url, decodeBase64url, bytesSnapshot } from './encoding.mjs';
import { payloadSnapshot } from './aes.mjs';
import { derivationUsageID } from './usage.mjs';
import { GROUP_SUITE, groupDerivationSnapshot, encodeGroupInfo } from './group-profile.mjs';
import { V2_LIMITS } from './limits.mjs';

export const MAX_SEQUENCE = (1n << 64n) - 1n;
const text = value => new TextEncoder().encode(value);
const metadataFields = ['version', 'suite', 'contextID', 'sender', 'receiver', 'senderFingerprint', 'receiverFingerprint', 'purpose', 'salt'];
const headerFields = [...metadataFields, 'iv', 'sequence', 'group'];
export function invalidEnvelope() { return engineError('invalid or unsupported v2 envelope', 'INVALID_ENVELOPE'); }
export function exactObject(value, fields) {
    try {
        if (!value || typeof value !== 'object' || Array.isArray(value)
            || Reflect.ownKeys(value).length !== fields.length || !fields.every(field => Object.hasOwn(value, field))) throw invalidEnvelope();
        const snapshot = {};
        for (const field of fields) {
            const descriptor = Object.getOwnPropertyDescriptor(value, field);
            if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw invalidEnvelope();
            snapshot[field] = descriptor.value;
        }
        return snapshot;
    } catch { throw invalidEnvelope(); }
}
export function sequenceValue(value) {
    if (typeof value !== 'string' || value.length > 20 || !/^(0|[1-9][0-9]*)$/.test(value)) throw invalidEnvelope();
    const number = BigInt(value);
    if (number > MAX_SEQUENCE) throw invalidEnvelope();
    return number;
}
export function uint64(value) {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, sequenceValue(value), false);
    return bytes;
}
export function groupSnapshot(value) {
    if (value === null) return null;
    value = exactObject(value, ['groupID', 'epoch', 'generation']);
    if (typeof value.groupID !== 'string' || value.groupID.length > 128 || !/^g[A-Za-z0-9_-]+$/.test(value.groupID)
        || sequenceValue(value.epoch) === 0n) throw invalidEnvelope();
    decode32(value.generation);
    return Object.freeze({ groupID: value.groupID, epoch: value.epoch, generation: value.generation });
}
export function headerMetadata(header) {
    const value = Object.fromEntries(metadataFields.map(field => [field, header[field]]));
    return header.suite === GROUP_SUITE ? groupDerivationSnapshot(value) : derivationSnapshot(value);
}
export function headerSnapshot(value) {
    try {
        value = exactObject(value, headerFields);
        const metadata = headerMetadata(value);
        const iv = decodeBase64url(value.iv, 12);
        if (iv.length !== 12 || sequenceValue(value.sequence) === 0n) throw invalidEnvelope();
        const group = groupSnapshot(value.group);
        if (metadata.suite === GROUP_SUITE) {
            if (!group || group.groupID !== metadata.receiver || group.generation !== metadata.receiverFingerprint) throw invalidEnvelope();
        } else {
            if (!/^(0|[1-9][0-9]*)$/.test(metadata.sender) || !/^(0|[1-9][0-9]*)$/.test(metadata.receiver)
                || (group !== null) !== (metadata.purpose === 'key-wrap')) throw invalidEnvelope();
        }
        return Object.freeze({ ...metadata, iv: value.iv, sequence: value.sequence, group });
    } catch { throw invalidEnvelope(); }
}
export function envelopeSnapshot(value) {
    value = exactObject(value, ['header', 'ciphertext']);
    const header = headerSnapshot(value.header);
    if (typeof value.ciphertext !== 'string') throw invalidEnvelope();
    const payload = payloadSnapshot(value.ciphertext, header.iv);
    return { header, payload, ciphertext: value.ciphertext };
}
export function encodeEnvelopeAAD(value) {
    const h = headerSnapshot(value);
    const g = h.group;
    const aad = encodeFields('BE8-ENVELOPE-AAD', [h.suite === GROUP_SUITE ? encodeGroupInfo(h) : encodeV2DerivationInfo(headerMetadata(h)), decode32(h.salt),
        decodeBase64url(h.iv, 12), uint64(h.sequence), text(g ? 'group' : ''),
        text(g?.groupID || ''), g ? uint64(g.epoch) : new Uint8Array(), g ? decode32(g.generation) : new Uint8Array()]);
    if (aad.length > 4096) throw invalidEnvelope();
    return aad;
}
export function checkExpected(header, expected, localID) {
    if (!expected || typeof expected !== 'object') throw engineError('independent envelope expectations are required', 'ENVELOPE_EXPECTATION_REQUIRED');
    scalarString(expected.contextID);
    if (expected.sender !== header.sender || expected.receiver !== header.receiver
        || expected.contextID !== header.contextID || expected.purpose !== header.purpose || header.receiver !== localID) {
        throw engineError('envelope does not match the expected endpoints, context or purpose', 'ENVELOPE_EXPECTATION_MISMATCH');
    }
}

// One byte-based authenticated operation. Wrapping is internal; no public
// group-secret decoder or private-key export is introduced.
export async function sealBytes(key, header, bytes) {
    const additionalData = encodeEnvelopeAAD(header);
    const algorithm = { name: 'AES-GCM', iv: decodeBase64url(header.iv, 12), tagLength: 128, additionalData };
    if (header.purpose === 'key-wrap') {
        if (bytes.length !== 32 || !header.group) throw invalidEnvelope();
        const temporary = await crypto.subtle.importKey('raw', bytes, 'AES-GCM', true, ['encrypt', 'decrypt']);
        return encodeBase64url(await crypto.subtle.wrapKey('raw', temporary, key, algorithm));
    }
    return encodeBase64url(await crypto.subtle.encrypt(algorithm, key, bytes));
}
export async function openBytes(key, snapshot) {
    const h = snapshot.header;
    const algorithm = { name: 'AES-GCM', iv: snapshot.payload.iv, tagLength: 128, additionalData: encodeEnvelopeAAD(h) };
    if (h.purpose === 'key-wrap') {
        if (snapshot.payload.bytes.length !== 48 || !h.group) throw invalidEnvelope();
        const temporary = await crypto.subtle.unwrapKey('raw', snapshot.payload.bytes, key, algorithm, 'AES-GCM', true, ['encrypt', 'decrypt']);
        return new Uint8Array(await crypto.subtle.exportKey('raw', temporary));
    }
    return new Uint8Array(await crypto.subtle.decrypt(algorithm, key, snapshot.payload.bytes));
}

export class Envelopes {
    constructor(keys, localID, replay) { this.keys = keys; this.localID = localID; this.replay = replay; }
    async seal(sender, receiver, value, { contextID, purpose, group = null } = {}) {
        if (typeof receiver === 'string' && receiver.startsWith('g')) throw engineError('ECDH group endpoints are legacy-only', 'LEGACY_GROUP_API');
        if (sender !== this.localID) throw engineError('Missing private key for local sender account', 'INVALID_PRIVATE_KEY');
        const bytes = bytesSnapshot(value, V2_LIMITS.plaintextBytes);
        scalarString(contextID);
        const [peer, privateKey, own] = await this.keys.endpointKeys(receiver, sender, true);
        if (!peer) throw engineError('Missing public key for selected peer', 'INVALID_KEY');
        if (!privateKey) throw engineError('Missing private key for local endpoint', 'INVALID_PRIVATE_KEY');
        const metadata = await createV2Metadata(sender, own, peer, { contextID, sender, receiver, purpose });
        const key = await deriveV2AES(sender, own, peer, privateKey, metadata);
        const sequence = await this.replay.reserve({ ...metadata, group });
        const template = headerSnapshot({ ...metadata, iv: encodeBase64url(new Uint8Array(12)), sequence, group });
        await this.keys.reserveUsage(await derivationUsageID(metadata), bytes.length, encodeEnvelopeAAD(template).length);
        const header = headerSnapshot({ ...template, iv: encodeBase64url(crypto.getRandomValues(new Uint8Array(12))) });
        return { header, ciphertext: await sealBytes(key, header, bytes) };
    }
    async open(value, expected) {
        const snapshot = envelopeSnapshot(value);
        expected = expected && { sender: expected.sender, receiver: expected.receiver, contextID: expected.contextID, purpose: expected.purpose };
        if (snapshot.header.suite === GROUP_SUITE) throw invalidEnvelope();
        checkExpected(snapshot.header, expected, this.localID);
        const [peer, privateKey, own] = await this.keys.endpointKeys(snapshot.header.sender, expected.receiver, true);
        if (!peer) throw engineError('Missing public key for selected peer', 'INVALID_KEY');
        if (!privateKey) throw engineError('Missing private key for local endpoint', 'INVALID_PRIVATE_KEY');
        const key = await deriveV2AES(expected.receiver, own, peer, privateKey, headerMetadata(snapshot.header));
        return { header: snapshot.header, bytes: await openBytes(key, snapshot) };
    }
}
