import { BE8_V2_SUITE, BE8_DOMAINS } from './legacy-be8.mjs';
import { engineError } from './persistence.mjs';
import { preparePublicKey, privateCryptoKey } from './crypto-keys.mjs';
import { fingerprintValue } from './trust.mjs';
import { encodeBase64url, decodeBase64url } from './encoding.mjs';

export { encodeBase64url } from './encoding.mjs';

export const V2_SUITE = 'BE9-P384-HKDF-SHA256-A256GCM';
export const V2_PURPOSES = Object.freeze(['data', 'attachment', 'key-wrap']);
const fields = ['version', 'suite', 'contextID', 'sender', 'receiver', 'senderFingerprint', 'receiverFingerprint', 'purpose', 'salt'];
const encoder = new TextEncoder();

function fail(message = 'invalid v2 derivation context', code = 'INVALID_DERIVATION_CONTEXT') {
    return engineError(message, code);
}

export function scalarString(value, maxBytes = 1024) {
    if (typeof value !== 'string' || !value.length || value.length > maxBytes) throw fail();
    // Reject lone UTF-16 surrogates rather than silently replacing them in UTF-8.
    for (const character of value) {
        const code = character.codePointAt(0);
        if (code >= 0xd800 && code <= 0xdfff) throw fail();
    }
    const bytes = encoder.encode(value);
    if (bytes.length > maxBytes) throw fail();
    return bytes;
}

export function decode32(value) {
    fingerprintValue(value);
    const bytes = decodeBase64url(value, 32);
    if (bytes.length !== 32) throw fail();
    return bytes;
}

function endpoint(value) {
    scalarString(value, 256);
    if (!/^(0|[1-9][0-9]*)$/.test(value) && !/^g[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(value)) throw fail();
    if (value.startsWith('g') && !Number.isSafeInteger(Number(value.slice(value.lastIndexOf(':') + 1)))) throw fail();
    return value;
}

export function derivationSnapshot(value, legacy = false) {
    if (!value) throw fail('v2 derivation metadata is required; use the explicit legacy reader for old ciphertexts', 'DERIVATION_CONTEXT_REQUIRED');
    try {
        if (typeof value !== 'object' || Array.isArray(value)
            || Object.keys(value).length !== fields.length || !fields.every(field => Object.keys(value).includes(field))) throw fail();
        const snapshot = Object.fromEntries(fields.map(field => [field, value[field]]));
        if (snapshot.version !== 2 || snapshot.suite !== (legacy ? BE8_V2_SUITE : V2_SUITE) || !V2_PURPOSES.includes(snapshot.purpose)) throw fail();
        scalarString(snapshot.contextID);
        endpoint(snapshot.sender);
        endpoint(snapshot.receiver);
        decode32(snapshot.salt);
        decode32(snapshot.senderFingerprint);
        decode32(snapshot.receiverFingerprint);
        return Object.freeze(snapshot);
    } catch {
        throw fail();
    }
}

// Fixed domain prefix plus eight ordered, uint32-BE length-prefixed byte strings.
// No separators, normalization, optional fields or object serialization enter info.
export function encodeV2DerivationInfo(metadata, legacy = false) {
    const context = derivationSnapshot(metadata, legacy);
    const values = [
        encoder.encode('2'), encoder.encode(context.suite), scalarString(context.contextID),
        scalarString(context.sender, 256), scalarString(context.receiver, 256),
        decode32(context.senderFingerprint), decode32(context.receiverFingerprint), encoder.encode(context.purpose),
    ];
    return encodeFields(legacy ? BE8_DOMAINS.pairInfo : 'BE9-HKDF-INFO', values);
}

export function encodeFields(domain, values) {
    const prefix = encoder.encode(domain);
    const info = new Uint8Array(prefix.length + values.reduce((length, value) => length + 4 + value.length, 0));
    info.set(prefix);
    const view = new DataView(info.buffer);
    let offset = prefix.length;
    for (const value of values) {
        view.setUint32(offset, value.length, false);
        offset += 4;
        info.set(value, offset);
        offset += value.length;
    }
    return info;
}

export async function createV2Metadata(localID, ownPublicKey, peerPublicKey, options) {
    if (!options || typeof options !== 'object' || Array.isArray(options)) throw fail();
    // Snapshot all application inputs before crypto yields.
    const { contextID, sender, receiver, purpose } = options;
    if (sender !== localID) throw fail('only the sender creates a new derivation context');
    scalarString(contextID);
    endpoint(sender);
    endpoint(receiver);
    if (!V2_PURPOSES.includes(purpose)) throw fail();
    const [own, peer] = await Promise.all([preparePublicKey(ownPublicKey), preparePublicKey(peerPublicKey)]);
    if (sender === receiver && own.fingerprint !== peer.fingerprint) throw fail();
    const salt = crypto.getRandomValues(new Uint8Array(32));
    return derivationSnapshot({ version: 2, suite: V2_SUITE, contextID, sender, receiver,
        senderFingerprint: own.fingerprint, receiverFingerprint: peer.fingerprint, purpose, salt: encodeBase64url(salt) });
}

// Internal helper also exercised against RFC 5869 public test vectors.
// It never returns IKM, PRK, raw AES bytes or an extractable derived key.
export async function hkdfAES(secret, salt, info, purpose, readOnly = false) {
    if (!V2_PURPOSES.includes(purpose)) throw fail();
    let material;
    try {
        material = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);
    } finally { secret.fill(0); }
    const usages = purpose === 'key-wrap' ? (readOnly ? ['unwrapKey'] : ['wrapKey', 'unwrapKey']) : (readOnly ? ['decrypt'] : ['encrypt', 'decrypt']);
    return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info }, material,
        { name: 'AES-GCM', length: 256 }, false, usages);
}

export async function deriveV2AES(localID, ownPublicKey, peerPublicKey, privateKey, metadata, legacy = false) {
    const context = derivationSnapshot(metadata, legacy);
    const priv = privateCryptoKey(privateKey);
    if (priv.usages[0] !== 'deriveBits') {
        throw fail('stored non-extractable deriveKey-only identity cannot derive v2; it is retained for explicit legacy reading', 'V2_KEY_USAGE_UNAVAILABLE');
    }
    if (localID !== context.sender && localID !== context.receiver) throw fail('local endpoint is not a participant in this context');
    const [own, peer] = await Promise.all([preparePublicKey(ownPublicKey), preparePublicKey(peerPublicKey)]);
    const sending = localID === context.sender;
    const ownExpected = sending ? context.senderFingerprint : context.receiverFingerprint;
    const peerExpected = sending ? context.receiverFingerprint : context.senderFingerprint;
    if (own.fingerprint !== ownExpected || peer.fingerprint !== peerExpected) {
        throw fail('derivation fingerprints do not match the actual endpoint keys', 'DERIVATION_KEY_MISMATCH');
    }
    const imported = await crypto.subtle.importKey('jwk', peer.key,
        { name: 'ECDH', namedCurve: 'P-384' }, peer.key.ext, []);
    let secret;
    try {
        // P-384's complete fixed-width ECDH x-coordinate, including leading zeros.
        secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: imported }, priv, 384));
        if (secret.length !== 48) throw fail('unexpected P-384 ECDH output length');
        return await hkdfAES(secret, decode32(context.salt), encodeV2DerivationInfo(context, legacy), context.purpose, legacy);
    } finally {
        // Best effort only: WebCrypto/runtime copies and GC are outside our control.
        secret?.fill(0);
    }
}
