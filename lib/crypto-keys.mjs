import { engineError } from './persistence.mjs';

const ecdh = Object.freeze({ name: 'ECDH', namedCurve: 'P-384' });
const usages = Object.freeze(['deriveKey']);

// Copy only key fields: embedded caller metadata cannot replace storage IDs.
export function keySnapshot(key, allowPrivate = false) {
    try {
        const has = field => field in key;
        if (!key || typeof key !== 'object' || Array.isArray(key)
            || !['kty', 'crv', 'x', 'y'].every(field => Object.hasOwn(key, field))
            || key.kty !== 'EC' || key.crv !== 'P-384'
            || ![key.x, key.y].every(value => typeof value === 'string' && /^[A-Za-z0-9_-]{64}$/.test(value))
            || (has('ext') && typeof key.ext !== 'boolean')
            || (has('use') && key.use !== 'enc')
            || (has('alg') && key.alg !== 'ECDH-ES')
            || (has('key_ops') && (!Array.isArray(key.key_ops)
                || (!allowPrivate && key.key_ops.length !== 0)
                || !key.key_ops.every(op => ['deriveKey', 'deriveBits'].includes(op))
                || new Set(key.key_ops).size !== key.key_ops.length))
            || ['p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some(has)
            || (has('d') && (!allowPrivate || typeof key.d !== 'string' || !/^[A-Za-z0-9_-]{64}$/.test(key.d)))) {
            throw engineError('invalid key data', 'INVALID_KEY');
        }
        const snapshot = { kty: key.kty, crv: key.crv, x: key.x, y: key.y,
            ext: has('ext') ? key.ext : true, key_ops: has('key_ops') ? [...key.key_ops] : [] };
        if (allowPrivate && has('d')) snapshot.d = key.d;
        return snapshot;
    } catch {
        throw engineError('invalid key data', 'INVALID_KEY');
    }
}

export async function validatePublicKey(publicJWK) {
    const key = keySnapshot(publicJWK);
    try {
        // Native import validates the actual curve point, beyond JSON shape.
        await crypto.subtle.importKey('jwk', key, ecdh, key.ext, []);
    } catch {
        throw engineError('invalid public P-384 ECDH key', 'INVALID_KEY');
    }
    return key;
}

function base64url(bytes) {
    return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function preparePublicKey(publicJWK) {
    const key = await validatePublicKey(publicJWK);
    // RFC 7638 section 3.2: only required EC public members, lexicographic order.
    const canonical = JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x, y: key.y });
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
    return { key, fingerprint: base64url(digest) };
}

export async function jwkThumbprint(publicJWK) {
    return (await preparePublicKey(publicJWK)).fingerprint;
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
    const pub = await validatePublicKey(publicJWK);
    const priv = privateCryptoKey(privateKey);
    let imported;
    try {
        imported = await crypto.subtle.importKey('jwk', pub, ecdh, pub.ext, []);
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
