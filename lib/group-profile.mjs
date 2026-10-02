/* global BigInt */
import { BE8_GROUP_SUITE, BE8_DOMAINS } from './legacy-be8.mjs';
import { engineError } from './persistence.mjs';
import { scalarString, decode32, encodeFields } from './v2.mjs';
import { encodeBase64url } from './encoding.mjs';
export const GROUP_SUITE = 'BE9-GROUP-HKDF-SHA256-A256GCM';
const fields = ['version', 'suite', 'contextID', 'sender', 'receiver', 'senderFingerprint', 'receiverFingerprint', 'purpose', 'salt'];
export function groupDerivationSnapshot(value, legacy = false) {
    const result = Object.fromEntries(fields.map(field => [field, value[field]]));
    if (result.version !== 2 || result.suite !== (legacy ? BE8_GROUP_SUITE : GROUP_SUITE) || !['data', 'attachment'].includes(result.purpose)
        || typeof result.sender !== 'string' || !/^(0|[1-9][0-9]*)$/.test(result.sender)
        || typeof result.receiver !== 'string' || result.receiver.length > 128 || !/^g[A-Za-z0-9_-]+$/.test(result.receiver)) {
        throw engineError('invalid group derivation', 'INVALID_ENVELOPE');
    }
    scalarString(result.contextID);
    scalarString(result.sender, 256);
    decode32(result.senderFingerprint); decode32(result.receiverFingerprint); decode32(result.salt);
    return Object.freeze(result);
}
export function encodeGroupInfo(header, legacy = false) {
    const h = groupDerivationSnapshot(header, legacy);
    const g = header.group;
    if (!g || g.groupID !== h.receiver || g.generation !== h.receiverFingerprint) throw engineError('group binding mismatch', 'INVALID_ENVELOPE');
    const epoch = new Uint8Array(8);
    new DataView(epoch.buffer).setBigUint64(0, BigInt(g.epoch), false);
    return encodeFields(legacy ? BE8_DOMAINS.groupInfo : 'BE9-GROUP-HKDF-INFO', [scalarString('2'), scalarString(h.suite), scalarString(h.contextID),
        scalarString(h.sender, 256), scalarString(h.receiver), decode32(h.senderFingerprint), decode32(h.receiverFingerprint),
        scalarString(h.purpose), scalarString(g.groupID), epoch, decode32(g.generation)]);
}
export async function groupGeneration(bytes) { return encodeBase64url(await crypto.subtle.digest('SHA-256', bytes)); }
export async function importGroupSecret(bytes) {
    try {
        const key = await crypto.subtle.importKey('raw', bytes, 'HKDF', false, ['deriveKey']);
        if (typeof structuredClone !== 'function') throw new Error();
        const clone = structuredClone(key);
        requireGroupSecret(clone);
        return key;
    } catch { throw engineError('browser must support non-extractable CryptoKey structured clone', 'CRYPTOKEY_STORAGE_UNSUPPORTED'); }
}
export function requireGroupSecret(key) {
    if (!(key instanceof CryptoKey) || key.algorithm.name !== 'HKDF' || key.type !== 'secret' || key.extractable
        || key.usages.length !== 1 || key.usages[0] !== 'deriveKey') throw engineError('invalid persisted group secret', 'INVALID_GROUP_KEY');
    return key;
}
export async function deriveGroupAES(key, header, legacy = false) {
    return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: decode32(header.salt), info: encodeGroupInfo(header, legacy) },
        requireGroupSecret(key), { name: 'AES-GCM', length: 256 }, false, legacy ? ['decrypt'] : ['encrypt', 'decrypt']);
}
