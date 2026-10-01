import { engineError } from './persistence.mjs';

const ecdh = Object.freeze({ name: 'ECDH', namedCurve: 'P-384' });
const usages = Object.freeze(['deriveKey']);

// Copy only key fields: embedded caller metadata cannot replace storage IDs.
export function keySnapshot(key, allowPrivate = false) {
    try {
        if (!key || typeof key !== 'object' || Array.isArray(key)
            || key.kty !== 'EC' || key.crv !== 'P-384'
            || typeof key.x !== 'string' || !key.x || typeof key.y !== 'string' || !key.y
            || typeof key.ext !== 'boolean' || !Array.isArray(key.key_ops)
            || !key.key_ops.every(op => typeof op === 'string')
            || (key.d !== undefined && (!allowPrivate || typeof key.d !== 'string' || !key.d))) {
            throw engineError('invalid key data', 'INVALID_KEY');
        }
        const snapshot = { kty: key.kty, crv: key.crv, x: key.x, y: key.y,
            ext: key.ext, key_ops: [...key.key_ops] };
        if (allowPrivate && key.d !== undefined) snapshot.d = key.d;
        return snapshot;
    } catch {
        throw engineError('invalid key data', 'INVALID_KEY');
    }
}

export function publicPart(key) {
    const snapshot = keySnapshot(key, true);
    return { kty: snapshot.kty, crv: snapshot.crv, x: snapshot.x, y: snapshot.y, ext: true, key_ops: [] };
}

export function privateCryptoKey(key) {
    if (key?.d !== undefined) {
        throw engineError('explicit private JWK migration required', 'PRIVATE_KEY_MIGRATION_REQUIRED');
    }
    if (!(key instanceof CryptoKey) || key.type !== 'private' || key.extractable
        || key.algorithm.name !== 'ECDH' || key.algorithm.namedCurve !== 'P-384'
        || key.usages.length !== 1 || key.usages[0] !== 'deriveKey') {
        throw engineError('a non-extractable P-384 ECDH private CryptoKey is required', 'INVALID_PRIVATE_KEY');
    }
    return key;
}

function cloneable(key) {
    try {
        privateCryptoKey(structuredClone(key));
    } catch {
        throw engineError('browser cannot store non-extractable CryptoKeys; use a browser with CryptoKey structured clone support',
            'CRYPTOKEY_STORAGE_UNSUPPORTED');
    }
    return key;
}

export async function generatePair() {
    const pair = await crypto.subtle.generateKey(ecdh, false, usages);
    return [await crypto.subtle.exportKey('jwk', pair.publicKey), cloneable(privateCryptoKey(pair.privateKey))];
}

export async function deriveAES(publicJWK, privateKey) {
    const pub = keySnapshot(publicJWK);
    const priv = privateCryptoKey(privateKey);
    let imported;
    try {
        imported = await crypto.subtle.importKey('jwk', pub, ecdh, true, []);
    } catch {
        throw engineError('invalid public ECDH key', 'INVALID_KEY');
    }
    return crypto.subtle.deriveKey({ name: 'ECDH', public: imported }, priv,
        { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

// Only the explicit persistence migration calls this. No private export occurs.
export async function migratePair(publicJWK, privateJWK) {
    try {
        const pub = keySnapshot(publicJWK);
        const priv = keySnapshot(privateJWK, true);
        if (!priv.d || pub.x !== priv.x || pub.y !== priv.y
            || ![priv.x, priv.y, priv.d].every(value => /^[A-Za-z0-9_-]{64}$/.test(value))) {
            throw new Error();
        }
        const imported = await crypto.subtle.importKey('jwk', priv, ecdh, false, usages);
        // Validate the scalar against the exact public point (including y).
        // A temporary non-extractable signing import verifies the existing pair;
        // it is never stored, returned, or used by the encryption protocol.
        const signatureAlgorithm = { name: 'ECDSA', namedCurve: 'P-384' };
        const signingKey = await crypto.subtle.importKey('jwk', { ...priv, key_ops: ['sign'] },
            signatureAlgorithm, false, ['sign']);
        const verifyingKey = await crypto.subtle.importKey('jwk', { ...publicPart(pub), key_ops: ['verify'] },
            signatureAlgorithm, true, ['verify']);
        const challenge = new TextEncoder().encode('be8 private-key migration validation');
        const parameters = { name: 'ECDSA', hash: 'SHA-384' };
        const signature = await crypto.subtle.sign(parameters, signingKey, challenge);
        if (!await crypto.subtle.verify(parameters, verifyingKey, signature, challenge)) throw new Error();
        return [pub, cloneable(privateCryptoKey(imported))];
    } catch (error) {
        if (error.code === 'CRYPTOKEY_STORAGE_UNSUPPORTED') throw error;
        throw engineError('private JWK validation failed; original records retained', 'INVALID_PRIVATE_KEY');
    }
}
