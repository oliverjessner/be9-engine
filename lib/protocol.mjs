import { engineError } from './persistence.mjs';
import { exactObject, uint64 } from './envelope.mjs';
import { encodeFields, scalarString, decode32 } from './v2.mjs';
import { encodeBase64url, decodeBase64url } from './encoding.mjs';
import { V2_LIMITS } from './limits.mjs';

export const RATCHET_SUITE = 'BE9-RATCHET-P384-HKDF-SHA256-A256GCM';
export const SIGNED_GROUP_SUITE = 'BE9-SIGNED-GROUP-HKDF-SHA256-A256GCM';
export const SESSION_LIMITS = Object.freeze({ sessions: 32, registry: 1024, skipped: 64, gap: 64,
    ratchetSteps: 128, retries: 32, recipients: 256, contextStreams: 1024, headerBytes: 4096, contextBytes: 1024,
    ciphertextBytes: V2_LIMITS.plaintextBytes + 16 });
export const fail = code => engineError('protocol operation rejected', code);
export const text = value => scalarString(value);
export const fields = (domain, values) => encodeFields(domain, values.map(value => typeof value === 'string' ? text(value) : value));
export const randomID = () => encodeBase64url(crypto.getRandomValues(new Uint8Array(32)));
export const hash = async bytes => encodeBase64url(await crypto.subtle.digest('SHA-256', bytes));
export function exact(value, names, code = 'INVALID_ENVELOPE') {
    try { return exactObject(value, names); } catch { throw fail(code); }
}
export function endpoint(value) {
    scalarString(value, 256);
    if (!/^(0|[1-9][0-9]*)$/.test(value)) throw fail('INVALID_ACCOUNT');
    return value;
}
export function purpose(value) {
    if (!['data', 'attachment'].includes(value)) throw fail('INVALID_PURPOSE');
    return value;
}
export function point(value) {
    const key = exact(value, ['kty', 'crv', 'x', 'y']);
    if (key.kty !== 'EC' || key.crv !== 'P-384' || ![key.x, key.y].every(v => typeof v === 'string' && /^[A-Za-z0-9_-]{64}$/.test(v))) throw fail('INVALID_KEY');
    return Object.freeze(key);
}
export function publicPoint(key) { return point({ kty: key.kty, crv: key.crv, x: key.x, y: key.y }); }
export const pointBytes = key => fields('BE9-P384-PUBLIC', [key.kty, key.crv, decodeBase64url(key.x, 48), decodeBase64url(key.y, 48)]);
export const samePoint = (a, b) => !!a && !!b && a.kty === b.kty && a.crv === b.crv && a.x === b.x && a.y === b.y;
export const counterBytes = uint64;
export { decode32 };
export function boundedHeader(bytes) {
    if (bytes.length > SESSION_LIMITS.headerBytes) throw fail('INVALID_ENVELOPE');
    return bytes;
}
export function schemaAvailable(keys, stores) {
    const db = typeof keys.connection.transaction === 'function' ? keys.connection : keys.connection.result;
    if (stores.some(name => !db.objectStoreNames.contains(name))) throw fail('SCHEMA_UPGRADE_REQUIRED');
}

export const native = promise => promise.catch(error => {
    if (typeof error?.code === 'string') throw error;
    throw fail('CRYPTO_OPERATION_FAILED');
});
