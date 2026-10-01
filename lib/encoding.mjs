import { engineError } from './persistence.mjs';
import { V2_LIMITS } from './limits.mjs';

const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const ciphertextLimit = V2_LIMITS.plaintextBytes + V2_LIMITS.tagBits / 8;

function invalid() { return engineError('invalid binary encoding', 'INVALID_ENCODING'); }
function oversized() { return engineError('input exceeds the v2 size limit', 'INPUT_TOO_LARGE'); }

// Always snapshot caller-owned BufferSources before an asynchronous operation.
export function bytesSnapshot(value, limit = ciphertextLimit) {
    if (!Number.isSafeInteger(limit) || limit < 0 || limit > ciphertextLimit) throw invalid();
    try {
        let view;
        if (value instanceof ArrayBuffer) view = new Uint8Array(value);
        else if (ArrayBuffer.isView(value) && value.buffer instanceof ArrayBuffer) {
            view = new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
        } else throw invalid();
        if (view.length > limit) throw oversized();
        return new Uint8Array(view);
    } catch (error) {
        if (error?.code) throw error;
        throw invalid();
    }
}

export function encodeBase64url(value) {
    const bytes = bytesSnapshot(value);
    const parts = [];
    // Multiples of three let separately encoded chunks join without padding.
    for (let offset = 0; offset < bytes.length; offset += 12288) {
        let binary = '';
        const end = Math.min(offset + 12288, bytes.length);
        for (let index = offset; index < end; index++) binary += String.fromCharCode(bytes[index]);
        parts.push(btoa(binary));
    }
    return parts.join('').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function decodeBase64url(value, limit = ciphertextLimit) {
    if (!Number.isSafeInteger(limit) || limit < 0 || limit > ciphertextLimit) throw invalid();
    if (typeof value !== 'string') throw invalid();
    if (value.length > Math.ceil(limit * 8 / 6)) throw oversized();
    const remainder = value.length % 4;
    if (remainder === 1 || !/^[A-Za-z0-9_-]*$/.test(value)) throw invalid();
    const last = alphabet.indexOf(value[value.length - 1]);
    if ((remainder === 2 && (last & 15)) || (remainder === 3 && (last & 3))) throw invalid();
    const length = Math.floor(value.length * 6 / 8);
    if (length > limit) throw oversized();
    let binary;
    try { binary = atob(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - remainder) % 4)); }
    catch { throw invalid(); }
    const bytes = new Uint8Array(length);
    for (let index = 0; index < length; index++) bytes[index] = binary.charCodeAt(index);
    return bytes;
}

export function decodeBytes(value, limit = ciphertextLimit) {
    return typeof value === 'string' ? decodeBase64url(value, limit) : bytesSnapshot(value, limit);
}

export function encodeText(value) {
    if (typeof value !== 'string') throw engineError('text must be a Unicode string', 'INVALID_TEXT');
    if (value.length > V2_LIMITS.plaintextBytes) throw oversized();
    let length = 0;
    for (const character of value) {
        const point = character.codePointAt(0);
        if (point >= 0xd800 && point <= 0xdfff) throw engineError('text contains an invalid Unicode scalar', 'INVALID_TEXT');
        length += point < 128 ? 1 : point < 2048 ? 2 : point < 65536 ? 3 : 4;
        if (length > V2_LIMITS.plaintextBytes) throw oversized();
    }
    return new TextEncoder().encode(value);
}

export function decodeText(bytes) {
    try { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
    catch { throw engineError('decrypted content is not valid UTF-8 text', 'INVALID_TEXT'); }
}

// Exact historical padded standard Base64; never used by v2 decoding.
export function decodeLegacyBase64(value) {
    if (typeof value !== 'string') throw invalid();
    if (value.length > 4 * Math.ceil(ciphertextLimit / 3)) throw oversized();
    const unpadded = value.replace(/=+$/, '');
    if (value.length % 4 || value.length - unpadded.length !== (4 - unpadded.length % 4) % 4
        || !/^[A-Za-z0-9+/]*$/.test(unpadded)) throw invalid();
    return decodeBase64url(unpadded.replace(/\+/g, '-').replace(/\//g, '_'));
}
