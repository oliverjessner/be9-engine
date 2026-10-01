import { engineError } from './persistence.mjs';
import { decodeBytes, encodeBase64url, decodeLegacyBase64 } from './encoding.mjs';
import { V2_LIMITS } from './limits.mjs';

export function requireAES(key, usage) {
    if (!key) throw engineError('no derived key passed to AES operation', 'INVALID_KEY');
    if (!(key instanceof CryptoKey) || key.type !== 'secret' || key.algorithm.name !== 'AES-GCM'
        || key.algorithm.length !== 256 || key.extractable) {
        throw engineError('a non-extractable AES-256-GCM key is required', 'INVALID_KEY');
    }
    if (!key.usages.includes(usage)) throw new DOMException('AES key does not permit this operation', 'InvalidAccessError');
}

export function payloadSnapshot(ciphertext, iv, legacy = false) {
    if (iv === undefined || iv === null) throw engineError('no iv (Initialization vector) passed to decrypt', 'INVALID_IV');
    let nonce;
    if (legacy) {
        if (typeof iv !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(iv)) {
            throw engineError('invalid legacy UUID IV', 'INVALID_IV');
        }
        // UUID bytes were ASCII/UTF-8. No random bytes pass through text codecs.
        nonce = Uint8Array.from(iv, character => character.charCodeAt(0));
    } else {
        try { nonce = decodeBytes(iv, V2_LIMITS.ivBytes); }
        catch { throw engineError('v2 IV must be exactly 12 bytes in canonical base64url or binary', 'INVALID_IV'); }
        if (nonce.length !== V2_LIMITS.ivBytes) throw engineError('v2 IV must be exactly 12 bytes', 'INVALID_IV');
    }
    const bytes = legacy ? decodeLegacyBase64(ciphertext) : decodeBytes(ciphertext);
    if (bytes.length < V2_LIMITS.tagBits / 8) throw engineError('ciphertext is shorter than the GCM tag', 'INVALID_CIPHERTEXT');
    return { bytes, iv: nonce };
}

export async function encryptPayload(key, bytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, bytes);
    return { cipherText: encodeBase64url(ciphertext), iv: encodeBase64url(iv) };
}

export function decryptPayload(key, payload) {
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv: payload.iv, tagLength: 128 }, key, payload.bytes);
}
