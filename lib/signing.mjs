import { STORES, requestResult } from './persistence.mjs';
import { preparePublicKey } from './crypto-keys.mjs';
import { nextTrust, trustDecision, fingerprintValue } from './trust.mjs';
import { encodeBase64url, decodeBase64url } from './encoding.mjs';
import { exact, endpoint, publicPoint, samePoint, fail, hash, fields, schemaAvailable, native } from './protocol.mjs';

const algorithm = { name: 'ECDSA', namedCurve: 'P-384' };
const parameters = { name: 'ECDSA', hash: 'SHA-384' };
export const IDENTITY_STORES = [STORES.publicKeys, STORES.trust, STORES.signingKeys, STORES.signingTrust];
export function signingPrivate(key) {
    if (!(key instanceof CryptoKey) || key.type !== 'private' || key.extractable || key.algorithm.name !== 'ECDSA'
        || key.algorithm.namedCurve !== 'P-384' || key.usages.length !== 1 || key.usages[0] !== 'sign') throw fail('SIGNING_STATE_LOST');
    return key;
}
export function signingSnapshot(key) {
    // Accept public usage metadata, never private members; metadata is not trust.
    if (!key || typeof key !== 'object' || ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some(name => name in key) || Reflect.ownKeys(key).some(k => !['kty', 'crv', 'x', 'y', 'ext', 'key_ops', 'use', 'alg', 'accID', 'verified'].includes(k))) throw fail('INVALID_KEY');
    for (const name of Reflect.ownKeys(key)) {
        const descriptor = Object.getOwnPropertyDescriptor(key, name);
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) throw fail('INVALID_KEY');
    }
    if ((key.use !== undefined && key.use !== 'sig') || (key.alg !== undefined && key.alg !== 'ES384')
        || (key.ext !== undefined && typeof key.ext !== 'boolean')
        || (key.key_ops !== undefined && (!Array.isArray(key.key_ops) || key.key_ops.length > 1 || key.key_ops.some(op => op !== 'verify')))) throw fail('INVALID_KEY');
    return publicPoint(key);
}
export async function prepareSigning(key) {
    const publicKey = signingSnapshot(key);
    try {
        const native = await crypto.subtle.importKey('jwk', publicKey, algorithm, true, ['verify']);
        // RFC 7638 prescribed public members only.
        const canonical = JSON.stringify({ crv: publicKey.crv, kty: publicKey.kty, x: publicKey.x, y: publicKey.y });
        return { publicKey, native, fingerprint: await hash(new TextEncoder().encode(canonical)) };
    } catch { throw fail('INVALID_KEY'); }
}
export async function sign(key, bytes) {
    try { return encodeBase64url(await crypto.subtle.sign(parameters, signingPrivate(key), bytes)); }
    catch (error) { if (typeof error.code === 'string') throw error; throw fail('SIGNING_FAILED'); }
}
export function signatureBytes(value) {
    try { const bytes = decodeBase64url(value, 96); if (bytes.length !== 96) throw new Error(); return bytes; }
    catch { throw fail('INVALID_SIGNATURE'); }
}
export async function verify(publicKey, signature, bytes) {
    const encoded = signatureBytes(signature);
    const prepared = await prepareSigning(publicKey);
    if (!await native(crypto.subtle.verify(parameters, prepared.native, encoded, bytes))) throw fail('INVALID_SIGNATURE');
}
async function pair() {
    const generated = await native(crypto.subtle.generateKey(algorithm, false, ['sign', 'verify']));
    const publicKey = publicPoint(await crypto.subtle.exportKey('jwk', generated.publicKey));
    try { signingPrivate(structuredClone(generated.privateKey)); }
    catch { throw fail('CRYPTOKEY_STORAGE_UNSUPPORTED'); }
    return { publicKey, privateKey: generated.privateKey, fingerprint: (await prepareSigning(publicKey)).fingerprint };
}
function readIdentities(tx, keys, peer) {
    return Promise.all([
        [STORES.publicKeys, keys.accID], [STORES.publicKeys, peer], [STORES.trust, peer],
        [STORES.signingKeys, keys.accID], [STORES.signingTrust, peer],
    ].map(([store, id]) => requestResult(tx.objectStore(store).get([keys.namespace, id]))));
}
function sameRows(a, b) {
    return a.every((row, i) => {
        const other = b[i];
        if (!row || !other) return row === other;
        return row.namespace === other.namespace && row.accID === other.accID && row.peerID === other.peerID
            && row.fingerprint === other.fingerprint && row.identityFingerprint === other.identityFingerprint
            && row.status === other.status && ((!row.key && !row.publicKey && !other.key && !other.publicKey) || samePoint(row.key || row.publicKey, other.key || other.publicKey));
    });
}
function registryState(registry) {
    if (!registry || !Number.isSafeInteger(registry.generation) || registry.generation < 0
        || !['active', 'invalidated'].includes(registry.status)) throw fail('SIGNING_STATE_LOST');
    try { fingerprintValue(registry.fingerprint); } catch { throw fail('SIGNING_STATE_LOST'); }
    return registry;
}
function canInitialize(registry, generation) {
    if (!registry) return;
    registryState(registry);
    if (registry.status !== 'invalidated' || registry.generation >= generation) throw fail('SIGNING_STATE_LOST');
}
const footprintStores = [STORES.sessions, STORES.ratchetState, STORES.skippedKeys];
function footprint(tx, namespace) {
    return Promise.all([STORES.sessionRegistry, ...footprintStores].map(name =>
        requestResult(tx.objectStore(name).index('namespace').getAllKeys(namespace, 1)))).then(rows => rows.some(row => row.length > 0));
}
export class Signing {
    constructor(keys) { this.keys = keys; }
    async setup() {
        schemaAvailable(this.keys, [STORES.signingKeys, STORES.sessionRegistry, ...footprintStores]);
        const own = await this.keys.myPublicKey();
        if (!own) throw fail('SESSION_IDENTITY_MISMATCH');
        const identityFingerprint = (await preparePublicKey(own)).fingerprint;
        const [current, registry, scope, inUse] = await this.keys.run([STORES.signingKeys, STORES.sessionRegistry, ...footprintStores], 'readonly', tx => Promise.all([
            requestResult(tx.objectStore(STORES.signingKeys).get([this.keys.namespace, this.keys.accID])),
            requestResult(tx.objectStore(STORES.sessionRegistry).get([this.keys.namespace, '@signing'])),
            requestResult(tx.objectStore(STORES.scopes).get(this.keys.namespace)),
            footprint(tx, this.keys.namespace),
        ]));
        if (!scope) throw fail('SIGNING_STATE_LOST');
        if (current) { await this.validateLocal(current, identityFingerprint); return this.publicIdentity(current); }
        if (!registry && inUse) throw fail('SIGNING_STATE_LOST');
        canInitialize(registry, scope.generation || 0);
        const candidate = { namespace: this.keys.namespace, accID: this.keys.accID, ...await pair(), identityFingerprint };
        const winner = await this.keys.run([STORES.signingKeys, STORES.sessionRegistry, ...footprintStores], 'readwrite', tx =>
            requestResult(tx.objectStore(STORES.signingKeys).get([this.keys.namespace, this.keys.accID]), found => {
                if (found) return found;
                const store = tx.objectStore(STORES.sessionRegistry);
                return requestResult(store.get([this.keys.namespace, '@signing']), known => {
                    canInitialize(known, scope.generation || 0);
                    return footprint(tx, this.keys.namespace).then(inUse => {
                        if (!known && inUse) throw fail('SIGNING_STATE_LOST');
                        tx.objectStore(STORES.signingKeys).add(candidate);
                        return requestResult(store.put({ namespace: this.keys.namespace, sessionID: '@signing', status: 'active', generation: scope.generation || 0,
                            fingerprint: candidate.fingerprint }), () => candidate);
                    });
                });
            }));
        await this.validateLocal(winner, identityFingerprint);
        return this.publicIdentity(winner);
    }
    publicIdentity(row) { return { publicKey: publicPoint(row.publicKey), fingerprint: row.fingerprint, identityFingerprint: row.identityFingerprint }; }
    async validateLocal(row, identityFingerprint) {
        if (!row || row.namespace !== this.keys.namespace || row.accID !== this.keys.accID || row.identityFingerprint !== identityFingerprint) throw fail('SIGNING_STATE_LOST');
        const [registry, scope] = await this.keys.run([STORES.sessionRegistry], 'readonly', tx => Promise.all([
            requestResult(tx.objectStore(STORES.sessionRegistry).get([this.keys.namespace, '@signing'])),
            requestResult(tx.objectStore(STORES.scopes).get(this.keys.namespace)),
        ]));
        registryState(registry);
        if (!scope || registry.generation !== (scope.generation || 0) || registry.status !== 'active' || registry.fingerprint !== row.fingerprint) throw fail('SIGNING_STATE_LOST');
        const prepared = await prepareSigning(row.publicKey);
        if (prepared.fingerprint !== row.fingerprint) throw fail('SIGNING_STATE_LOST');
        const challenge = fields('BE9-SIGNING-LOCAL-CHECK', [this.keys.accID, identityFingerprint]);
        try { await verify(row.publicKey, await sign(row.privateKey, challenge), challenge); }
        catch { throw fail('SIGNING_STATE_LOST'); }
    }
    async getPublic() {
        const current = await this.keys.run([STORES.signingKeys], 'readonly', tx => requestResult(tx.objectStore(STORES.signingKeys).get([this.keys.namespace, this.keys.accID])));
        if (!current) throw fail('SIGNING_STATE_LOST');
        await this.validateLocal(current, (await preparePublicKey(await this.keys.myPublicKey())).fingerprint);
        return this.publicIdentity(current);
    }
    async import(peer, value, options = {}) {
        endpoint(peer); if (peer === this.keys.accID) throw fail('INVALID_ACCOUNT');
        // Validate and snapshot all fields before any yield.
        const publicKey = signingSnapshot(value);
        const decision = trustDecision(options);
        const identityFingerprint = fingerprintValue(options.identityFingerprint);
        const original = await this.peerBinding(peer, identityFingerprint);
        const prepared = await prepareSigning(publicKey);
        return this.keys.run([STORES.publicKeys, STORES.trust, STORES.signingTrust], 'readwrite', tx => {
            const store = tx.objectStore(STORES.signingTrust);
            return requestResult(tx.objectStore(STORES.publicKeys).get([this.keys.namespace, peer]), pub => {
                return requestResult(tx.objectStore(STORES.trust).get([this.keys.namespace, peer]), trusted => {
                    if (!pub || !samePoint(pub.key, original.key) || !trusted || trusted.status === 'unverified' || trusted.fingerprint !== identityFingerprint) throw fail('UNTRUSTED_SIGNING_KEY');
                    // The key point is also captured and checked natively below before commit.
                    return requestResult(store.get([this.keys.namespace, peer]), current => {
                        if (current && current.identityFingerprint !== identityFingerprint) throw fail('SESSION_IDENTITY_MISMATCH');
                        const status = nextTrust(current, prepared.fingerprint, decision, !current);
                        const row = { namespace: this.keys.namespace, peerID: peer, key: prepared.publicKey, fingerprint: prepared.fingerprint, identityFingerprint, status };
                        return requestResult(store.put(row), () => ({ peerID: peer, fingerprint: row.fingerprint, identityFingerprint, status }));
                    });
                });
            });
        });
    }
    async replace(peer, value, confirmation) {
        endpoint(peer); const publicKey = signingSnapshot(value);
        confirmation = exact(confirmation, ['expectedPreviousFingerprint', 'confirmedNewFingerprint', 'identityFingerprint'], 'INVALID_TRUST_DECISION');
        const expected = fingerprintValue(confirmation.expectedPreviousFingerprint);
        const confirmed = fingerprintValue(confirmation.confirmedNewFingerprint);
        const identityFingerprint = fingerprintValue(confirmation.identityFingerprint);
        const prepared = await prepareSigning(publicKey);
        const original = await this.peerBinding(peer, identityFingerprint);
        if (confirmed !== prepared.fingerprint) throw fail('FINGERPRINT_MISMATCH');
        return this.keys.run([STORES.signingTrust, STORES.trust, STORES.publicKeys], 'readwrite', tx => requestResult(tx.objectStore(STORES.trust).get([this.keys.namespace, peer]), identity => {
            if (!identity || identity.status === 'unverified' || identity.fingerprint !== identityFingerprint) throw fail('UNTRUSTED_SIGNING_KEY');
            const store = tx.objectStore(STORES.signingTrust);
            return requestResult(tx.objectStore(STORES.publicKeys).get([this.keys.namespace, peer]), pub => {
                if (!pub || !samePoint(pub.key, original.key)) throw fail('SESSION_IDENTITY_MISMATCH');
                return requestResult(store.get([this.keys.namespace, peer]), current => {
                    if (!current || current.fingerprint !== expected) throw fail('PUBLIC_KEY_CHANGED');
                    return requestResult(store.put({ namespace: this.keys.namespace, peerID: peer, key: prepared.publicKey, fingerprint: confirmed, identityFingerprint, status: 'confirmed' }));
                });
            });
        }));
    }
    async peerBinding(peer, fingerprint) {
        const [pub, trust] = await this.keys.run([STORES.publicKeys, STORES.trust], 'readonly', tx => Promise.all([
            requestResult(tx.objectStore(STORES.publicKeys).get([this.keys.namespace, peer])),
            requestResult(tx.objectStore(STORES.trust).get([this.keys.namespace, peer])),
        ]));
        if (!pub || !trust || !['confirmed', 'tofu'].includes(trust.status) || trust.fingerprint !== fingerprint
            || (await preparePublicKey(pub.key)).fingerprint !== fingerprint) throw fail('UNTRUSTED_SIGNING_KEY');
        return pub;
    }
    async rotate(options) {
        const { expectedPreviousFingerprint } = exact(options, ['expectedPreviousFingerprint'], 'INVALID_TRUST_DECISION');
        fingerprintValue(expectedPreviousFingerprint);
        const current = await this.getPublic();
        const candidate = { namespace: this.keys.namespace, accID: this.keys.accID, identityFingerprint: current.identityFingerprint, ...await pair() };
        return this.keys.run([STORES.signingKeys, STORES.sessionRegistry], 'readwrite', tx => requestResult(tx.objectStore(STORES.signingKeys).get([this.keys.namespace, this.keys.accID]), row => {
            if (!row || row.fingerprint !== expectedPreviousFingerprint) throw fail('PUBLIC_KEY_CHANGED');
            tx.objectStore(STORES.signingKeys).put(candidate);
            return requestResult(tx.objectStore(STORES.sessionRegistry).get([this.keys.namespace, '@signing']), registry => {
                if (!registry) throw fail('SIGNING_STATE_LOST');
                return requestResult(tx.objectStore(STORES.sessionRegistry).put({ ...registry, fingerprint: candidate.fingerprint }), () => this.publicIdentity(candidate));
            });
        }));
    }
    async snapshot(peer) {
        endpoint(peer);
        schemaAvailable(this.keys, IDENTITY_STORES);
        const rows = await this.keys.run(IDENTITY_STORES, 'readonly', tx => readIdentities(tx, this.keys, peer));
        const [own, remote, trust, localSigning, remoteSigning] = rows;
        if (!own || !remote || (peer !== this.keys.accID && (!trust || !['confirmed', 'tofu'].includes(trust.status)))) throw fail('UNTRUSTED_PEER');
        const local = await preparePublicKey(own.key), other = await preparePublicKey(remote.key);
        if (peer !== this.keys.accID && other.fingerprint !== trust.fingerprint) throw fail('SESSION_IDENTITY_MISMATCH');
        await this.validateLocal(localSigning, local.fingerprint);
        const selectedSigning = peer === this.keys.accID ? { key: localSigning.publicKey, fingerprint: localSigning.fingerprint, identityFingerprint: localSigning.identityFingerprint, status: 'confirmed' } : remoteSigning;
        if (!selectedSigning || !['confirmed', 'tofu'].includes(selectedSigning.status) || selectedSigning.identityFingerprint !== other.fingerprint) throw fail('UNTRUSTED_SIGNING_KEY');
        const pub = await prepareSigning(selectedSigning.key);
        if (pub.fingerprint !== selectedSigning.fingerprint) throw fail('UNTRUSTED_SIGNING_KEY');
        return { rows, peer, localFingerprint: local.fingerprint, peerFingerprint: other.fingerprint,
            localSigningFingerprint: localSigning.fingerprint, peerSigningFingerprint: pub.fingerprint,
            privateKey: localSigning.privateKey, publicKey: pub.publicKey };
    }
    check(tx, snapshot) {
        return readIdentities(tx, this.keys, snapshot.peer).then(rows => {
            if (!sameRows(snapshot.rows, rows)) throw fail('SESSION_IDENTITY_MISMATCH');
        });
    }
}
