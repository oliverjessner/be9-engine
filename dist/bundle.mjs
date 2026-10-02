function getTypeOfKey(id) {
    if (!id) {
        throw new Error('engine: id is required in getTypeOfKey');
    }
    if (id.charAt(0) === 'g') {
        return 'group';
    }
    if (id.charAt(0) === 'c') {
        return 'channel';
    }

    return 'dialog';
}

const STORES = Object.freeze({
    scopes: 'be8.scopes',
    publicKeys: 'be8.publicKeys',
    privateKeys: 'be8.privateKeys',
    groupKeys: 'be8.groupKeys',
    groupEpochs: 'be8.groupEpochs',
    activeEpochs: 'be8.activeEpochs',
    trust: 'be8.trust',
    keyUsage: 'be8.keyUsage',
    contexts: 'be8.contexts',
    sendState: 'be8.sendState',
    receiveState: 'be8.receiveState',
});

function engineError(message, code = 'INVALID_STATE') {
    const error = new Error('engine: ' + message);
    error.code = code;
    return error;
}

function databaseError(error) {
    const failure =
        error?.name === 'DataCloneError'
            ? engineError(
                  'browser cannot store CryptoKeys; CryptoKey structured clone support is required',
                  'CRYPTOKEY_STORAGE_UNSUPPORTED'
              )
            : engineError('IndexedDB operation failed', 'PERSISTENCE_ERROR');
    const names = [
        'AbortError',
        'ConstraintError',
        'DataCloneError',
        'DataError',
        'InvalidStateError',
        'NotFoundError',
        'QuotaExceededError',
        'ReadOnlyError',
        'TransactionInactiveError',
        'UnknownError',
        'VersionError',
    ];
    failure.name = names.includes(error?.name)
        ? error.name
        : 'PersistenceError';
    return failure;
}

function databaseConnection(connection) {
    try {
        const db =
            typeof connection?.transaction === 'function'
                ? connection
                : connection?.result;
        if (typeof db?.transaction !== 'function') {
            throw engineError(
                'database connection is not ready',
                'DATABASE_NOT_READY'
            );
        }
        return db;
    } catch {
        throw engineError(
            'database connection is not ready',
            'DATABASE_NOT_READY'
        );
    }
}

// Must be called synchronously by the application's onupgradeneeded handler.
// Only engine-owned stores are created. Existing stores and records are retained.
function upgradeBe8Schema(db, transaction) {
    if (transaction?.mode !== 'versionchange' || transaction.db !== db) {
        throw engineError(
            'schema integration requires a versionchange transaction',
            'SCHEMA_ERROR'
        );
    }
    const definitions = [
        [STORES.scopes, 'namespace'],
        [STORES.publicKeys, ['namespace', 'accID']],
        [STORES.privateKeys, ['namespace', 'accID']],
        [STORES.groupKeys, ['namespace', 'groupID', 'version']],
        [STORES.groupEpochs, ['namespace', 'groupID', 'epoch']],
        [STORES.activeEpochs, ['namespace', 'groupID']],
        [STORES.trust, ['namespace', 'peerID']],
        [STORES.keyUsage, 'derivationID'],
        [STORES.contexts, ['namespace', 'contextID']],
        [STORES.sendState, ['namespace', 'contextID', 'streamID']],
        [STORES.receiveState, ['namespace', 'contextID', 'streamID']],
    ];
    try {
        for (const [name, keyPath] of definitions) {
            const store = db.objectStoreNames.contains(name)
                ? transaction.objectStore(name)
                : db.createObjectStore(name, { keyPath });
            if (
                JSON.stringify(store.keyPath) !== JSON.stringify(keyPath) ||
                store.autoIncrement
            ) {
                throw engineError(
                    'incompatible engine store schema',
                    'SCHEMA_ERROR'
                );
            }
            if (name !== STORES.scopes && name !== STORES.keyUsage) {
                if (!store.indexNames.contains('namespace')) {
                    store.createIndex('namespace', 'namespace');
                }
                const index = store.index('namespace');
                if (
                    index.keyPath !== 'namespace' ||
                    index.unique ||
                    index.multiEntry
                ) {
                    throw engineError(
                        'incompatible engine index schema',
                        'SCHEMA_ERROR'
                    );
                }
            }
        }
    } catch {
        try {
            transaction.abort();
        } catch {
            /* Already aborted. */
        }
        throw engineError(
            'schema integration failed; upgrade aborted',
            'SCHEMA_ERROR'
        );
    }
}

// A successful request is not a successful transaction. The callback may only
// schedule further native requests synchronously in this success event.
function requestResult(request, consume = (value) => value) {
    return new Promise((resolve, reject) => {
        const tx = request.transaction;
        const cleanup = () => {
            request.removeEventListener('success', success);
            request.removeEventListener('error', failure);
            tx?.removeEventListener('abort', abort);
        };
        const success = () => {
            cleanup();
            try {
                resolve(consume(request.result));
            } catch (error) {
                reject(
                    error instanceof Error && typeof error.code === 'string'
                        ? error
                        : databaseError(error)
                );
            }
        };
        const failure = () => {
            cleanup();
            reject(databaseError(request.error));
        };
        const abort = () => {
            cleanup();
            reject(databaseError(tx.error || { name: 'AbortError' }));
        };
        request.addEventListener('success', success, { once: true });
        request.addEventListener('error', failure, { once: true });
        tx?.addEventListener('abort', abort, { once: true });
    });
}

function transactionComplete(tx) {
    return new Promise((resolve, reject) => {
        let failed;
        const cleanup = () => {
            tx.removeEventListener('complete', complete);
            tx.removeEventListener('error', error);
            tx.removeEventListener('abort', abort);
        };
        const complete = () => {
            cleanup();
            if (failed) reject(failed);
            else resolve();
        };
        const abort = () => {
            cleanup();
            reject(failed || databaseError(tx.error || { name: 'AbortError' }));
        };
        const error = (event) => {
            failed = databaseError(event.target.error || tx.error);
            // Even if another listener prevents the request's default abort,
            // this operation must roll back instead of reporting partial success.
            try {
                tx.abort();
            } catch {
                /* A terminal event will settle the promise. */
            }
        };
        tx.addEventListener('complete', complete, { once: true });
        tx.addEventListener('error', error);
        tx.addEventListener('abort', abort, { once: true });
    });
}

// operation must schedule requests immediately; no crypto, timers or unrelated
// asynchronous work may run while a transaction is open.
async function withTransaction(connection, stores, mode, operation) {
    let tx;
    try {
        tx = databaseConnection(connection).transaction(stores, mode);
    } catch (error) {
        throw databaseError(error);
    }
    const completed = transactionComplete(tx);
    let result;
    try {
        result = operation(tx);
    } catch (error) {
        result = Promise.reject(error);
    }
    const requested = Promise.resolve(result).catch((error) => {
        try {
            tx.abort();
        } catch {
            /* Already complete or aborted. */
        }
        throw error instanceof Error && typeof error.code === 'string'
            ? error
            : databaseError(error);
    });
    const [work, commit] = await Promise.allSettled([requested, completed]);
    if (work.status === 'rejected') throw work.reason;
    if (commit.status === 'rejected') throw commit.reason;
    return work.value;
}

const V2_LIMITS = Object.freeze({
    ivBytes: 12,
    tagBits: 128,
    plaintextBytes: 16 * 1024 * 1024,
    encryptions: 2 ** 16,
    blocks: 2 ** 24,
});

const alphabet =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const ciphertextLimit = V2_LIMITS.plaintextBytes + V2_LIMITS.tagBits / 8;

function invalid() {
    return engineError('invalid binary encoding', 'INVALID_ENCODING');
}
function oversized() {
    return engineError('input exceeds the v2 size limit', 'INPUT_TOO_LARGE');
}

// Always snapshot caller-owned BufferSources before an asynchronous operation.
function bytesSnapshot(value, limit = ciphertextLimit) {
    if (!Number.isSafeInteger(limit) || limit < 0 || limit > ciphertextLimit)
        throw invalid();
    try {
        let view;
        if (value instanceof ArrayBuffer) view = new Uint8Array(value);
        else if (
            ArrayBuffer.isView(value) &&
            value.buffer instanceof ArrayBuffer
        ) {
            view = new Uint8Array(
                value.buffer,
                value.byteOffset,
                value.byteLength
            );
        } else throw invalid();
        if (view.length > limit) throw oversized();
        return new Uint8Array(view);
    } catch (error) {
        if (error?.code) throw error;
        throw invalid();
    }
}

function encodeBase64url(value) {
    const bytes = bytesSnapshot(value);
    const parts = [];
    // Multiples of three let separately encoded chunks join without padding.
    for (let offset = 0; offset < bytes.length; offset += 12288) {
        let binary = '';
        const end = Math.min(offset + 12288, bytes.length);
        for (let index = offset; index < end; index++)
            binary += String.fromCharCode(bytes[index]);
        parts.push(btoa(binary));
    }
    return parts
        .join('')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

function decodeBase64url(value, limit = ciphertextLimit) {
    if (!Number.isSafeInteger(limit) || limit < 0 || limit > ciphertextLimit)
        throw invalid();
    if (typeof value !== 'string') throw invalid();
    if (value.length > Math.ceil((limit * 8) / 6)) throw oversized();
    const remainder = value.length % 4;
    if (remainder === 1 || !/^[A-Za-z0-9_-]*$/.test(value)) throw invalid();
    const last = alphabet.indexOf(value[value.length - 1]);
    if ((remainder === 2 && last & 15) || (remainder === 3 && last & 3))
        throw invalid();
    const length = Math.floor((value.length * 6) / 8);
    if (length > limit) throw oversized();
    let binary;
    try {
        binary = atob(
            value.replace(/-/g, '+').replace(/_/g, '/') +
                '='.repeat((4 - remainder) % 4)
        );
    } catch {
        throw invalid();
    }
    const bytes = new Uint8Array(length);
    for (let index = 0; index < length; index++)
        bytes[index] = binary.charCodeAt(index);
    return bytes;
}

function decodeBytes(value, limit = ciphertextLimit) {
    return typeof value === 'string'
        ? decodeBase64url(value, limit)
        : bytesSnapshot(value, limit);
}

function encodeText(value) {
    if (typeof value !== 'string')
        throw engineError('text must be a Unicode string', 'INVALID_TEXT');
    if (value.length > V2_LIMITS.plaintextBytes) throw oversized();
    let length = 0;
    for (const character of value) {
        const point = character.codePointAt(0);
        if (point >= 0xd800 && point <= 0xdfff)
            throw engineError(
                'text contains an invalid Unicode scalar',
                'INVALID_TEXT'
            );
        length += point < 128 ? 1 : point < 2048 ? 2 : point < 65536 ? 3 : 4;
        if (length > V2_LIMITS.plaintextBytes) throw oversized();
    }
    return new TextEncoder().encode(value);
}

function decodeText(bytes) {
    try {
        return new TextDecoder('utf-8', {
            fatal: true,
            ignoreBOM: true,
        }).decode(bytes);
    } catch {
        throw engineError(
            'decrypted content is not valid UTF-8 text',
            'INVALID_TEXT'
        );
    }
}

// Exact historical padded standard Base64; never used by v2 decoding.
function decodeLegacyBase64(value) {
    if (typeof value !== 'string') throw invalid();
    if (value.length > 4 * Math.ceil(ciphertextLimit / 3)) throw oversized();
    const unpadded = value.replace(/=+$/, '');
    if (
        value.length % 4 ||
        value.length - unpadded.length !== (4 - (unpadded.length % 4)) % 4 ||
        !/^[A-Za-z0-9+/]*$/.test(unpadded)
    )
        throw invalid();
    return decodeBase64url(unpadded.replace(/\+/g, '-').replace(/\//g, '_'));
}

const ecdh = Object.freeze({ name: 'ECDH', namedCurve: 'P-384' });
const usages = Object.freeze(['deriveBits']);

// Copy only key fields: embedded caller metadata cannot replace storage IDs.
function keySnapshot(key, allowPrivate = false) {
    try {
        const has = (field) => field in key;
        if (
            !key ||
            typeof key !== 'object' ||
            Array.isArray(key) ||
            !['kty', 'crv', 'x', 'y'].every((field) =>
                Object.hasOwn(key, field)
            ) ||
            key.kty !== 'EC' ||
            key.crv !== 'P-384' ||
            ![key.x, key.y].every(
                (value) =>
                    typeof value === 'string' &&
                    /^[A-Za-z0-9_-]{64}$/.test(value)
            ) ||
            (has('ext') && typeof key.ext !== 'boolean') ||
            (has('use') && key.use !== 'enc') ||
            (has('alg') && key.alg !== 'ECDH-ES') ||
            (has('key_ops') &&
                (!Array.isArray(key.key_ops) ||
                    (!allowPrivate && key.key_ops.length !== 0) ||
                    !key.key_ops.every((op) =>
                        ['deriveKey', 'deriveBits'].includes(op)
                    ) ||
                    new Set(key.key_ops).size !== key.key_ops.length)) ||
            ['p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some(has) ||
            (has('d') &&
                (!allowPrivate ||
                    typeof key.d !== 'string' ||
                    !/^[A-Za-z0-9_-]{64}$/.test(key.d)))
        ) {
            throw engineError('invalid key data', 'INVALID_KEY');
        }
        const snapshot = {
            kty: key.kty,
            crv: key.crv,
            x: key.x,
            y: key.y,
            ext: has('ext') ? key.ext : true,
            key_ops: has('key_ops') ? [...key.key_ops] : [],
        };
        if (allowPrivate && has('d')) snapshot.d = key.d;
        return snapshot;
    } catch {
        throw engineError('invalid key data', 'INVALID_KEY');
    }
}

async function validatePublicKey(publicJWK) {
    const key = keySnapshot(publicJWK);
    try {
        // Native import validates the actual curve point, beyond JSON shape.
        await crypto.subtle.importKey('jwk', key, ecdh, key.ext, []);
    } catch {
        throw engineError('invalid public P-384 ECDH key', 'INVALID_KEY');
    }
    return key;
}

async function preparePublicKey(publicJWK) {
    const key = await validatePublicKey(publicJWK);
    // RFC 7638 section 3.2: only required EC public members, lexicographic order.
    const canonical = JSON.stringify({
        crv: key.crv,
        kty: key.kty,
        x: key.x,
        y: key.y,
    });
    const digest = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(canonical)
    );
    return { key, fingerprint: encodeBase64url(digest) };
}

async function jwkThumbprint(publicJWK) {
    return (await preparePublicKey(publicJWK)).fingerprint;
}

function publicPart(key) {
    const snapshot = keySnapshot(key, true);
    return {
        kty: snapshot.kty,
        crv: snapshot.crv,
        x: snapshot.x,
        y: snapshot.y,
        ext: true,
        key_ops: [],
    };
}

function privateCryptoKey(key) {
    if (key?.d !== undefined) {
        throw engineError(
            'explicit private JWK migration required',
            'PRIVATE_KEY_MIGRATION_REQUIRED'
        );
    }
    if (
        !(key instanceof CryptoKey) ||
        key.type !== 'private' ||
        key.extractable ||
        key.algorithm.name !== 'ECDH' ||
        key.algorithm.namedCurve !== 'P-384' ||
        key.usages.length !== 1 ||
        !['deriveBits', 'deriveKey'].includes(key.usages[0])
    ) {
        throw engineError(
            'a non-extractable P-384 ECDH private CryptoKey is required',
            'INVALID_PRIVATE_KEY'
        );
    }
    return key;
}

function cloneable(key) {
    try {
        privateCryptoKey(structuredClone(key));
    } catch {
        throw engineError(
            'browser cannot store non-extractable CryptoKeys; use a browser with CryptoKey structured clone support',
            'CRYPTOKEY_STORAGE_UNSUPPORTED'
        );
    }
    return key;
}

async function generatePair() {
    const pair = await crypto.subtle.generateKey(ecdh, false, usages);
    return [
        await crypto.subtle.exportKey('jwk', pair.publicKey),
        cloneable(privateCryptoKey(pair.privateKey)),
    ];
}

async function deriveLegacyAES(publicJWK, privateKey) {
    const pub = await validatePublicKey(publicJWK);
    const priv = privateCryptoKey(privateKey);
    let imported;
    try {
        imported = await crypto.subtle.importKey('jwk', pub, ecdh, pub.ext, []);
    } catch {
        throw engineError('invalid public ECDH key', 'INVALID_KEY');
    }
    if (priv.usages[0] === 'deriveKey') {
        return crypto.subtle.deriveKey(
            { name: 'ECDH', public: imported },
            priv,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );
    }
    let secret;
    try {
        secret = new Uint8Array(
            await crypto.subtle.deriveBits(
                { name: 'ECDH', public: imported },
                priv,
                384
            )
        );
        // Native legacy ECDH-to-AES selected the first 256 ECDH output bits.
        return await crypto.subtle.importKey(
            'raw',
            secret.subarray(0, 32),
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
    } finally {
        secret?.fill(0);
    }
}

// Only the explicit persistence migration calls this. No private export occurs.
async function migratePair(publicJWK, privateJWK) {
    try {
        const pub = keySnapshot(publicJWK);
        const priv = keySnapshot(privateJWK, true);
        if (
            !priv.d ||
            pub.x !== priv.x ||
            pub.y !== priv.y ||
            ![priv.x, priv.y, priv.d].every((value) =>
                /^[A-Za-z0-9_-]{64}$/.test(value)
            )
        ) {
            throw new Error();
        }
        const imported = await crypto.subtle.importKey(
            'jwk',
            { ...priv, key_ops: [...usages] },
            ecdh,
            false,
            usages
        );
        // Validate the scalar against the exact public point (including y).
        // A temporary non-extractable signing import verifies the existing pair;
        // it is never stored, returned, or used by the encryption protocol.
        const signatureAlgorithm = { name: 'ECDSA', namedCurve: 'P-384' };
        const signingKey = await crypto.subtle.importKey(
            'jwk',
            { ...priv, key_ops: ['sign'] },
            signatureAlgorithm,
            false,
            ['sign']
        );
        const verifyingKey = await crypto.subtle.importKey(
            'jwk',
            { ...publicPart(pub), key_ops: ['verify'] },
            signatureAlgorithm,
            true,
            ['verify']
        );
        const challenge = new TextEncoder().encode(
            'be8 private-key migration validation'
        );
        const parameters = { name: 'ECDSA', hash: 'SHA-384' };
        const signature = await crypto.subtle.sign(
            parameters,
            signingKey,
            challenge
        );
        if (
            !(await crypto.subtle.verify(
                parameters,
                verifyingKey,
                signature,
                challenge
            ))
        )
            throw new Error();
        return [pub, cloneable(privateCryptoKey(imported))];
    } catch (error) {
        if (error.code === 'CRYPTOKEY_STORAGE_UNSUPPORTED') throw error;
        throw engineError(
            'private JWK validation failed; original records retained',
            'INVALID_PRIVATE_KEY'
        );
    }
}

function fingerprintValue(value) {
    // A canonical, unpadded base64url encoding of a 32-byte SHA-256 digest.
    if (
        typeof value !== 'string' ||
        !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(value)
    ) {
        throw engineError(
            'invalid SHA-256 JWK thumbprint',
            'INVALID_FINGERPRINT'
        );
    }
    return value;
}

// This is a separate local argument, never read from an imported key/entry.
function trustDecision(options = {}) {
    if (
        !options ||
        typeof options !== 'object' ||
        Array.isArray(options) ||
        (options.trust !== undefined && options.trust !== 'confirmed') ||
        (options.tofu !== undefined && typeof options.tofu !== 'boolean')
    ) {
        throw engineError(
            'invalid local trust decision',
            'INVALID_TRUST_DECISION'
        );
    }
    return {
        ...(options.expectedFingerprint !== undefined
            ? {
                  expectedFingerprint: fingerprintValue(
                      options.expectedFingerprint
                  ),
              }
            : {}),
        ...(options.trust !== undefined ? { trust: options.trust } : {}),
        tofu: options.tofu === true,
    };
}

function checkTrustRecord(record) {
    if (!record) return undefined;
    fingerprintValue(record.fingerprint);
    if (!['unverified', 'confirmed', 'tofu'].includes(record.status)) {
        throw engineError(
            'invalid persisted trust state',
            'INVALID_TRUST_STATE'
        );
    }
    return record;
}

function nextTrust(current, fingerprint, decision, firstContact) {
    checkTrustRecord(current);
    if (
        decision.expectedFingerprint !== undefined &&
        decision.expectedFingerprint !== fingerprint
    ) {
        throw engineError(
            'public key does not match the expected fingerprint',
            'FINGERPRINT_MISMATCH'
        );
    }
    if (current && current.fingerprint !== fingerprint) {
        throw engineError(
            'peer public key changed; explicit replacement required',
            'PUBLIC_KEY_CHANGED'
        );
    }
    if (
        decision.expectedFingerprint !== undefined ||
        decision.trust === 'confirmed'
    )
        return 'confirmed';
    if (current?.status === 'confirmed' || current?.status === 'tofu')
        return current.status;
    // TOFU is a first-contact policy, never a later confirmation or key change.
    if (firstContact && decision.tofu) return 'tofu';
    return 'unverified';
}

/* global WeakRef */

function accountID(id) {
    if (typeof id !== 'string' || !/^(0|[1-9][0-9]*)$/.test(id)) {
        throw engineError(
            'no acc id or wrong type passed to the constructor',
            'INVALID_ACCOUNT'
        );
    }
    return id;
}

function namespaceID(namespace) {
    if (
        typeof namespace !== 'string' ||
        !namespace.length ||
        namespace !== namespace.trim() ||
        [...namespace].some(
            (character) =>
                character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127
        )
    ) {
        throw engineError('invalid namespace', 'INVALID_NAMESPACE');
    }
    return namespace;
}

function groupID(id) {
    if (typeof id !== 'string' || !/^g[A-Za-z0-9_-]+$/.test(id)) {
        throw engineError('invalid group identifier', 'INVALID_GROUP');
    }
    return id;
}

function groupVersion(version) {
    if (typeof version === 'string' && /^[1-9][0-9]*$/.test(version))
        version = Number(version);
    if (!Number.isSafeInteger(version) || version < 1) {
        throw engineError('invalid group version', 'INVALID_GROUP');
    }
    return version;
}

function peerID(id) {
    if (typeof id === 'string' && id.startsWith('g')) {
        const [group, version, extra] = id.split(':');
        if (extra !== undefined)
            throw engineError('invalid group identifier', 'INVALID_GROUP');
        return groupID(group) + ':' + groupVersion(version);
    }
    return accountID(id);
}

function localDecisions(options, ids) {
    if (
        !options ||
        typeof options !== 'object' ||
        Array.isArray(options) ||
        (options.decisions !== undefined && !Array.isArray(options.decisions))
    ) {
        throw engineError(
            'invalid local trust options',
            'INVALID_TRUST_DECISION'
        );
    }
    const fallback = trustDecision({ tofu: options.tofu });
    const decisions = new Map();
    for (const entry of options.decisions || []) {
        const id = peerID(entry.peerID);
        if (!ids.includes(id) || decisions.has(id)) {
            throw engineError(
                'trust decision must select one imported endpoint',
                'INVALID_TRUST_DECISION'
            );
        }
        decisions.set(
            id,
            trustDecision({
                expectedFingerprint: entry.expectedFingerprint,
                trust: entry.trust,
                tofu: entry.tofu === undefined ? fallback.tofu : entry.tofu,
            })
        );
    }
    return (id) => decisions.get(id) || fallback;
}

function samePublic(left, right) {
    return (
        left.kty === right.kty &&
        left.crv === right.crv &&
        left.x === right.x &&
        left.y === right.y
    );
}

function identityPair(publicRecord, privateRecord) {
    if (!publicRecord && !privateRecord) return null;
    if (!publicRecord || !privateRecord) {
        throw engineError(
            'incomplete identity; existing keys are retained',
            'INCOMPLETE_IDENTITY'
        );
    }
    const publicKey = keySnapshot(publicRecord.key);
    const privateKey = privateCryptoKey(privateRecord.key);
    if (!samePublic(publicKey, keySnapshot(privateRecord.publicKey))) {
        throw engineError(
            'inconsistent identity; existing keys are retained',
            'INCOMPLETE_IDENTITY'
        );
    }
    return [publicKey, privateKey];
}

function groupPair(record) {
    if (!record) return undefined;
    if (record.key?.d !== undefined) privateCryptoKey(record.key);
    return [
        keySnapshot(record.key),
        record.privateKey ? privateCryptoKey(record.privateKey) : undefined,
    ];
}

// Weak registrations coordinate live instances in this JS realm; persisted
// generations are authoritative across connections, reloads and other realms.
const liveScopes = new Map();
function scopeState(record) {
    const status =
        record && Object.hasOwn(record, 'status') ? record.status : 'active';
    const generation =
        record && Object.hasOwn(record, 'generation') ? record.generation : 0;
    if (
        !['active', 'invalidated'].includes(status) ||
        !Number.isSafeInteger(generation) ||
        generation < 0
    ) {
        throw engineError(
            'invalid namespace lifecycle state',
            'INVALID_LIFECYCLE'
        );
    }
    return { status, generation };
}
class KeyStore {
    #generation;
    #blocked = false;
    #transactions = new Set();
    #databaseName;
    #registered = false;
    onLock = () => {};
    assertActive() {
        if (this.#blocked)
            throw engineError(
                'local namespace is invalidated; explicit reinitialize() required',
                'ENGINE_LOCKED'
            );
    }
    lock() {
        this.#blocked = true;
        this.onLock();
        for (const tx of this.#transactions) {
            try {
                tx.abort();
            } catch {
                /* Terminal transaction. */
            }
        }
    }
    #register(tx) {
        this.#databaseName = tx.db.name;
        if (this.#registered || typeof WeakRef !== 'function') return;
        if (!liveScopes.has(tx.db.name)) liveScopes.set(tx.db.name, new Map());
        const scopes = liveScopes.get(tx.db.name);
        if (!scopes.has(this.namespace)) scopes.set(this.namespace, new Set());
        scopes.get(this.namespace).add(new WeakRef(this));
        this.#registered = true;
    }
    #lockPeers() {
        const registered = liveScopes
            .get(this.#databaseName)
            ?.get(this.namespace);
        for (const reference of registered || []) {
            const keys = reference.deref();
            if (!keys) registered.delete(reference);
            else if (
                keys.accID === this.accID &&
                (this.#generation === undefined ||
                    keys.#generation === undefined ||
                    keys.#generation === this.#generation)
            )
                keys.lock();
        }
    }
    #track(tx) {
        this.#register(tx);
        this.#transactions.add(tx);
        const release = () => this.#transactions.delete(tx);
        tx.addEventListener('complete', release, { once: true });
        tx.addEventListener('abort', release, { once: true });
    }
    checkLifecycle() {
        return this.run([], 'readonly', () => undefined);
    }

    constructor(connection, accID, namespace = accID) {
        this.connection = connection;
        this.accID = accountID(accID);
        this.namespace = namespaceID(namespace);
    }

    #checkOwner(record) {
        if (record && record.accID !== this.accID) {
            throw engineError(
                'namespace belongs to another account',
                'ACCOUNT_MISMATCH'
            );
        }
    }

    #scope(tx, write, work) {
        const scopes = tx.objectStore(STORES.scopes);
        return requestResult(scopes.get(this.namespace), (record) => {
            this.assertActive();
            this.#checkOwner(record);
            const state = scopeState(record);
            if (!record && this.#generation !== undefined)
                throw engineError(
                    'namespace lifecycle record is missing; no automatic reset is allowed',
                    'INVALID_LIFECYCLE'
                );
            if (
                state.status !== 'active' ||
                (this.#generation !== undefined &&
                    state.generation !== this.#generation)
            ) {
                this.lock();
                throw engineError(
                    'namespace generation has been invalidated',
                    'ENGINE_LOCKED'
                );
            }
            if (record) this.#generation ??= state.generation;
            if (!record && write) {
                scopes.add({
                    namespace: this.namespace,
                    accID: this.accID,
                    status: 'active',
                    generation: 0,
                });
                tx.addEventListener(
                    'complete',
                    () => {
                        this.#generation ??= 0;
                    },
                    { once: true }
                );
            }
            return work(tx);
        });
    }

    run(stores, mode, work) {
        this.assertActive();
        return withTransaction(
            this.connection,
            [STORES.scopes, ...new Set(stores)],
            mode,
            (tx) => {
                this.#track(tx);
                return this.#scope(tx, mode === 'readwrite', work);
            }
        );
    }

    async reserveUsage(derivationID, byteLength, aadLength = 0) {
        fingerprintValue(derivationID);
        if (
            !databaseConnection(this.connection).objectStoreNames.contains(
                STORES.keyUsage
            )
        ) {
            throw engineError(
                'application must upgrade its schema with upgradeBe8Schema() before v2 encryption',
                'SCHEMA_UPGRADE_REQUIRED'
            );
        }
        if (
            !Number.isSafeInteger(byteLength) ||
            byteLength < 0 ||
            byteLength > V2_LIMITS.plaintextBytes
        ) {
            throw engineError(
                'input exceeds the v2 size limit',
                'INPUT_TOO_LARGE'
            );
        }
        if (
            !Number.isSafeInteger(aadLength) ||
            aadLength < 0 ||
            aadLength > 4096
        )
            throw engineError('invalid AAD size', 'INVALID_ENVELOPE');
        const blocks =
            Math.ceil(byteLength / 16) + Math.ceil(aadLength / 16) + 1;
        return this.run([STORES.keyUsage], 'readwrite', (tx) => {
            const store = tx.objectStore(STORES.keyUsage);
            return requestResult(store.get(derivationID), (current) => {
                const record = current || {
                    derivationID,
                    encryptions: 0,
                    blocks: 0,
                };
                if (
                    !Number.isSafeInteger(record.encryptions) ||
                    record.encryptions < 0 ||
                    record.encryptions > V2_LIMITS.encryptions ||
                    !Number.isSafeInteger(record.blocks) ||
                    record.blocks < record.encryptions ||
                    record.blocks > V2_LIMITS.blocks
                ) {
                    throw engineError(
                        'invalid persisted GCM usage state',
                        'INVALID_USAGE_STATE'
                    );
                }
                if (
                    record.encryptions >= V2_LIMITS.encryptions ||
                    record.blocks + blocks > V2_LIMITS.blocks
                ) {
                    throw engineError(
                        'GCM key usage budget exhausted; create a new derivation context',
                        'KEY_USAGE_EXHAUSTED'
                    );
                }
                return requestResult(
                    store.put({
                        derivationID,
                        encryptions: record.encryptions + 1,
                        blocks: record.blocks + blocks,
                    })
                );
            });
        });
    }

    async identity() {
        return this.run(
            [STORES.publicKeys, STORES.privateKeys],
            'readonly',
            (tx) => {
                const key = [this.namespace, this.accID];
                return Promise.all([
                    requestResult(tx.objectStore(STORES.publicKeys).get(key)),
                    requestResult(tx.objectStore(STORES.privateKeys).get(key)),
                ]).then(([pub, priv]) => identityPair(pub, priv));
            }
        );
    }

    async legacyPresent() {
        const db = databaseConnection(this.connection);
        const stores = ['publicKeys', 'privateKeys'].filter((name) =>
            db.objectStoreNames.contains(name)
        );
        if (!stores.length) return false;
        return withTransaction(this.connection, stores, 'readonly', (tx) =>
            Promise.all(
                stores.map((name) =>
                    requestResult(tx.objectStore(name).get(this.accID))
                )
            ).then((records) => records.some(Boolean))
        );
    }

    // Candidate keys have been generated/imported before opening this transaction.
    // Concurrent initializers recheck inside the same multi-store write lock.
    async storeIdentity(candidate) {
        const db = databaseConnection(this.connection);
        const legacy = ['publicKeys', 'privateKeys'].filter((name) =>
            db.objectStoreNames.contains(name)
        );
        return this.run(
            [STORES.publicKeys, STORES.privateKeys, ...legacy],
            'readwrite',
            (tx) => {
                const key = [this.namespace, this.accID];
                const pubStore = tx.objectStore(STORES.publicKeys);
                const privStore = tx.objectStore(STORES.privateKeys);
                return requestResult(pubStore.get(key), (pub) =>
                    requestResult(privStore.get(key), (priv) => {
                        const current = identityPair(pub, priv);
                        if (current) return current;
                        const checkLegacy = (index) => {
                            if (index < legacy.length) {
                                return requestResult(
                                    tx
                                        .objectStore(legacy[index])
                                        .get(this.accID),
                                    (record) => {
                                        if (record)
                                            throw engineError(
                                                'explicit legacy identity migration required',
                                                'LEGACY_IDENTITY'
                                            );
                                        return checkLegacy(index + 1);
                                    }
                                );
                            }
                            const [publicKey, privateKey] = candidate;
                            return requestResult(
                                pubStore.add({
                                    namespace: this.namespace,
                                    accID: this.accID,
                                    key: publicKey,
                                }),
                                () =>
                                    requestResult(
                                        privStore.add({
                                            namespace: this.namespace,
                                            accID: this.accID,
                                            key: privateKey,
                                            publicKey,
                                        }),
                                        () => candidate
                                    )
                            );
                        };
                        return checkLegacy(0);
                    })
                );
            }
        );
    }

    async addPublicKeys(entries, options = {}) {
        let copied;
        try {
            copied = entries.map(({ accID, publicKey }) => ({
                accID: accountID(accID),
                key: keySnapshot(publicKey),
            }));
        } catch {
            throw engineError('invalid public-key entries', 'INVALID_KEY');
        }
        const decisionFor = localDecisions(
            options,
            copied.map((entry) => entry.accID)
        );
        const prepared = await Promise.all(
            copied.map(async (entry) => ({
                ...entry,
                ...(await preparePublicKey(entry.key)),
                decision: decisionFor(entry.accID),
            }))
        );
        return this.run(
            [STORES.publicKeys, STORES.privateKeys, STORES.trust],
            'readwrite',
            (tx) => {
                const store = tx.objectStore(STORES.publicKeys);
                const trust = tx.objectStore(STORES.trust);
                return requestResult(
                    tx
                        .objectStore(STORES.privateKeys)
                        .get([this.namespace, this.accID]),
                    (own) => {
                        const next = (index) => {
                            if (index === prepared.length) return undefined;
                            const entry = prepared[index];
                            const storageKey = [this.namespace, entry.accID];
                            return requestResult(
                                store.get(storageKey),
                                (existing) =>
                                    requestResult(
                                        trust.get(storageKey),
                                        (current) => {
                                            if (
                                                entry.accID === this.accID &&
                                                own
                                            ) {
                                                if (
                                                    !samePublic(
                                                        entry.key,
                                                        own.publicKey ||
                                                            publicPart(own.key)
                                                    )
                                                ) {
                                                    throw engineError(
                                                        'cannot replace the public half of an existing identity',
                                                        'IDENTITY_CONFLICT'
                                                    );
                                                }
                                                nextTrust(
                                                    undefined,
                                                    entry.fingerprint,
                                                    entry.decision,
                                                    false
                                                );
                                                return next(index + 1);
                                            }
                                            if (
                                                existing &&
                                                !samePublic(
                                                    keySnapshot(existing.key),
                                                    entry.key
                                                )
                                            ) {
                                                throw engineError(
                                                    'peer public key changed; explicit replacement required',
                                                    'PUBLIC_KEY_CHANGED'
                                                );
                                            }
                                            const status = nextTrust(
                                                current,
                                                entry.fingerprint,
                                                entry.decision,
                                                !existing && !current
                                            );
                                            return requestResult(
                                                store.put({
                                                    namespace: this.namespace,
                                                    accID: entry.accID,
                                                    key: entry.key,
                                                }),
                                                () =>
                                                    requestResult(
                                                        trust.put({
                                                            namespace:
                                                                this.namespace,
                                                            peerID: entry.accID,
                                                            fingerprint:
                                                                entry.fingerprint,
                                                            status,
                                                        }),
                                                        () => next(index + 1)
                                                    )
                                            );
                                        }
                                    )
                            );
                        };
                        return next(0);
                    }
                );
            }
        );
    }

    async peerTrust(id) {
        const peer = peerID(id);
        return this.run([STORES.trust], 'readonly', (tx) =>
            requestResult(
                tx.objectStore(STORES.trust).get([this.namespace, peer]),
                (record) => {
                    checkTrustRecord(record);
                    return record
                        ? {
                              peerID: peer,
                              fingerprint: record.fingerprint,
                              status: record.status,
                          }
                        : undefined;
                }
            )
        );
    }

    async replacePublicKey(
        id,
        publicKey,
        { expectedPreviousFingerprint, confirmedNewFingerprint } = {}
    ) {
        const peer = accountID(id);
        if (peer === this.accID)
            throw engineError(
                'own identity cannot be replaced through the peer API',
                'IDENTITY_CONFLICT'
            );
        const previous = fingerprintValue(expectedPreviousFingerprint);
        const confirmed = fingerprintValue(confirmedNewFingerprint);
        const prepared = await preparePublicKey(publicKey);
        if (confirmed !== prepared.fingerprint) {
            throw engineError(
                'new key does not match the confirmed fingerprint',
                'FINGERPRINT_MISMATCH'
            );
        }
        const snapshot = await this.run(
            [STORES.publicKeys, STORES.trust],
            'readonly',
            (tx) =>
                Promise.all([
                    requestResult(
                        tx
                            .objectStore(STORES.publicKeys)
                            .get([this.namespace, peer])
                    ),
                    requestResult(
                        tx.objectStore(STORES.trust).get([this.namespace, peer])
                    ),
                ])
        );
        checkTrustRecord(snapshot[1]);
        if (
            !snapshot[0] ||
            !snapshot[1] ||
            snapshot[1].fingerprint !== previous ||
            (await jwkThumbprint(snapshot[0].key)) !== previous
        ) {
            throw engineError(
                'previous fingerprint no longer matches; replacement refused',
                'TRUST_CONFLICT'
            );
        }
        const originalKey = keySnapshot(snapshot[0].key);
        return this.run(
            [STORES.publicKeys, STORES.trust],
            'readwrite',
            (tx) => {
                const store = tx.objectStore(STORES.publicKeys);
                const trust = tx.objectStore(STORES.trust);
                const storageKey = [this.namespace, peer];
                return requestResult(store.get(storageKey), (existing) =>
                    requestResult(trust.get(storageKey), (current) => {
                        checkTrustRecord(current);
                        if (
                            !existing ||
                            !current ||
                            current.fingerprint !== previous ||
                            !samePublic(existing.key, originalKey)
                        ) {
                            throw engineError(
                                'previous fingerprint no longer matches; replacement refused',
                                'TRUST_CONFLICT'
                            );
                        }
                        return requestResult(
                            store.put({
                                namespace: this.namespace,
                                accID: peer,
                                key: prepared.key,
                            }),
                            () =>
                                requestResult(
                                    trust.put({
                                        namespace: this.namespace,
                                        peerID: peer,
                                        fingerprint: prepared.fingerprint,
                                        status: 'confirmed',
                                    }),
                                    () => undefined
                                )
                        );
                    })
                );
            }
        );
    }

    async publicKeys() {
        return this.run([STORES.publicKeys], 'readonly', (tx) =>
            requestResult(
                tx
                    .objectStore(STORES.publicKeys)
                    .index('namespace')
                    .getAll(this.namespace),
                (records) =>
                    records.map((record) => ({
                        accID: record.accID,
                        publicKey: {
                            ...keySnapshot(record.key),
                            accID: record.accID,
                        },
                    }))
            )
        );
    }

    async myPublicKey() {
        return this.run([STORES.publicKeys], 'readonly', (tx) =>
            requestResult(
                tx
                    .objectStore(STORES.publicKeys)
                    .get([this.namespace, this.accID]),
                (record) =>
                    record
                        ? { ...keySnapshot(record.key), accID: this.accID }
                        : undefined
            )
        );
    }

    async groupKeys() {
        return this.run([STORES.groupKeys], 'readonly', (tx) =>
            requestResult(
                tx
                    .objectStore(STORES.groupKeys)
                    .index('namespace')
                    .getAll(this.namespace),
                (records) =>
                    records.map((record) => ({
                        groupID: record.groupID,
                        version: record.version,
                        groupKey: {
                            ...publicPart(record.key),
                            groupID: record.groupID,
                            version: record.version,
                        },
                    }))
            )
        );
    }

    async groupKey(id, version) {
        return this.run([STORES.groupKeys], 'readonly', (tx) =>
            requestResult(
                tx
                    .objectStore(STORES.groupKeys)
                    .get([this.namespace, groupID(id), groupVersion(version)]),
                (record) => groupPair(record)
            )
        );
    }

    async addGroupKeys(id, entries, options = {}) {
        const group = groupID(id);
        let copied;
        try {
            copied = entries.map(({ version, groupKey }) => ({
                version: groupVersion(version),
                key: keySnapshot(groupKey),
            }));
        } catch {
            throw engineError('invalid group-key entries', 'INVALID_KEY');
        }
        const decisionFor = localDecisions(
            options,
            copied.map((entry) => group + ':' + entry.version)
        );
        const prepared = await Promise.all(
            copied.map(async (entry) => ({
                ...entry,
                ...(await preparePublicKey(entry.key)),
                decision: decisionFor(group + ':' + entry.version),
            }))
        );
        return this.run([STORES.groupKeys, STORES.trust], 'readwrite', (tx) => {
            const store = tx.objectStore(STORES.groupKeys);
            const trust = tx.objectStore(STORES.trust);
            // Chain native success events to validate each immutable version,
            // including repeated versions within the same caller batch.
            const putNext = (index) => {
                if (index === prepared.length) return undefined;
                const { version, key, fingerprint, decision } = prepared[index];
                const storageKey = [this.namespace, group, version];
                return requestResult(store.get(storageKey), (existing) => {
                    if (existing && !samePublic(existing.key, key)) {
                        throw engineError(
                            'group version already has a different key',
                            'GROUP_CONFLICT'
                        );
                    }
                    // A public reimport must never erase a retained private key.
                    if (existing?.key.d !== undefined)
                        privateCryptoKey(existing.key);
                    const retained = existing || { key };
                    const write = () =>
                        requestResult(
                            store.put({
                                namespace: this.namespace,
                                groupID: group,
                                version,
                                key: retained.key,
                                ...(retained.privateKey
                                    ? {
                                          privateKey: privateCryptoKey(
                                              retained.privateKey
                                          ),
                                      }
                                    : {}),
                            }),
                            () => putNext(index + 1)
                        );
                    if (retained.privateKey) {
                        nextTrust(undefined, fingerprint, decision, false);
                        return write();
                    }
                    const peer = group + ':' + version;
                    return requestResult(
                        trust.get([this.namespace, peer]),
                        (current) => {
                            const status = nextTrust(
                                current,
                                fingerprint,
                                decision,
                                !existing && !current
                            );
                            return requestResult(
                                trust.put({
                                    namespace: this.namespace,
                                    peerID: peer,
                                    fingerprint,
                                    status,
                                }),
                                write
                            );
                        }
                    );
                });
            };
            return putNext(0);
        });
    }

    async endpointKeys(publicID, privateID, requireTrust = false) {
        const parse = (id) => {
            if (typeof id === 'string' && id.startsWith('g')) {
                const parts = id.split(':');
                if (parts.length !== 2)
                    throw engineError(
                        'invalid group identifier',
                        'INVALID_GROUP'
                    );
                return {
                    store: STORES.groupKeys,
                    key: [
                        this.namespace,
                        groupID(parts[0]),
                        groupVersion(parts[1]),
                    ],
                };
            }
            return {
                store: STORES.publicKeys,
                key: [this.namespace, accountID(id)],
            };
        };
        const pub = parse(publicID);
        const priv = parse(privateID);
        const own = parse(privateID);
        if (priv.store === STORES.publicKeys) priv.store = STORES.privateKeys;
        const [publicRecord, privateKey, trust, ownRecord] = await this.run(
            [
                pub.store,
                priv.store,
                own.store,
                ...(requireTrust ? [STORES.trust] : []),
            ],
            'readonly',
            (tx) =>
                Promise.all([
                    requestResult(tx.objectStore(pub.store).get(pub.key)),
                    // Only this scope's account private identity may ever be selected.
                    priv.store === STORES.privateKeys &&
                    privateID !== this.accID
                        ? undefined
                        : requestResult(
                              tx.objectStore(priv.store).get(priv.key),
                              (record) =>
                                  record
                                      ? priv.store === STORES.privateKeys
                                          ? privateCryptoKey(record.key)
                                          : groupPair(record)[1]
                                      : undefined
                          ),
                    requireTrust
                        ? requestResult(
                              tx
                                  .objectStore(STORES.trust)
                                  .get([this.namespace, peerID(publicID)])
                          )
                        : undefined,
                    requestResult(tx.objectStore(own.store).get(own.key)),
                ])
        );
        const publicKey = publicRecord
            ? pub.store === STORES.groupKeys
                ? publicPart(publicRecord.key)
                : keySnapshot(publicRecord.key)
            : undefined;
        const local =
            publicID === this.accID ||
            (pub.store === STORES.groupKeys && publicRecord?.privateKey);
        if (publicKey && requireTrust && !local) {
            checkTrustRecord(trust);
            if (!trust || trust.status === 'unverified') {
                throw engineError(
                    'peer public key requires an explicit local trust decision',
                    'UNTRUSTED_PUBLIC_KEY'
                );
            }
            if ((await jwkThumbprint(publicKey)) !== trust.fingerprint) {
                throw engineError(
                    'persisted key and trust fingerprint disagree',
                    'INVALID_TRUST_STATE'
                );
            }
        }
        const ownPublicKey = ownRecord
            ? own.store === STORES.groupKeys
                ? publicPart(ownRecord.key)
                : keySnapshot(ownRecord.key)
            : undefined;
        return [publicKey, privateKey, ownPublicKey];
    }

    async migratePublicKeyTrust() {
        const snapshot = await this.run(
            [STORES.publicKeys, STORES.groupKeys],
            'readonly',
            (tx) =>
                Promise.all([
                    requestResult(
                        tx
                            .objectStore(STORES.publicKeys)
                            .index('namespace')
                            .getAll(this.namespace)
                    ),
                    requestResult(
                        tx
                            .objectStore(STORES.groupKeys)
                            .index('namespace')
                            .getAll(this.namespace)
                    ),
                ])
        );
        const entries = [
            ...snapshot[0]
                .filter((record) => record.accID !== this.accID)
                .map((record) => ({
                    peerID: accountID(record.accID),
                    store: STORES.publicKeys,
                    storageKey: [this.namespace, record.accID],
                    key: record.key,
                })),
            ...snapshot[1]
                .filter(
                    (record) =>
                        !record.privateKey && record.key?.d === undefined
                )
                .map((record) => ({
                    peerID:
                        groupID(record.groupID) +
                        ':' +
                        groupVersion(record.version),
                    store: STORES.groupKeys,
                    storageKey: [
                        this.namespace,
                        record.groupID,
                        record.version,
                    ],
                    key: record.key,
                })),
        ];
        const prepared = await Promise.all(
            entries.map(async (entry) => ({
                ...entry,
                ...(await preparePublicKey(entry.key)),
            }))
        );
        return this.run(
            [STORES.publicKeys, STORES.groupKeys, STORES.trust],
            'readwrite',
            (tx) => {
                const trust = tx.objectStore(STORES.trust);
                let migratedPeers = 0;
                const next = (index) => {
                    if (index === prepared.length) return { migratedPeers };
                    const entry = prepared[index];
                    return requestResult(
                        tx.objectStore(entry.store).get(entry.storageKey),
                        (existing) => {
                            if (
                                !existing ||
                                !samePublic(
                                    keySnapshot(existing.key),
                                    entry.key
                                ) ||
                                (entry.store === STORES.groupKeys &&
                                    existing.privateKey)
                            ) {
                                throw engineError(
                                    'public records changed during trust migration',
                                    'MIGRATION_CONFLICT'
                                );
                            }
                            return requestResult(
                                trust.get([this.namespace, entry.peerID]),
                                (current) => {
                                    checkTrustRecord(current);
                                    if (current) {
                                        if (
                                            current.fingerprint !==
                                            entry.fingerprint
                                        ) {
                                            throw engineError(
                                                'persisted key and trust state disagree',
                                                'INVALID_TRUST_STATE'
                                            );
                                        }
                                        return next(index + 1);
                                    }
                                    migratedPeers++;
                                    return requestResult(
                                        trust.add({
                                            namespace: this.namespace,
                                            peerID: entry.peerID,
                                            fingerprint: entry.fingerprint,
                                            status: 'unverified',
                                        }),
                                        () => next(index + 1)
                                    );
                                }
                            );
                        }
                    );
                };
                return next(0);
            }
        );
    }

    async migratePrivateKeys({
        legacyIdentity = false,
        legacyGroups = [],
    } = {}) {
        if (
            typeof legacyIdentity !== 'boolean' ||
            !Array.isArray(legacyGroups)
        ) {
            throw engineError('invalid migration options', 'INVALID_KEY');
        }
        const selected = legacyGroups.map((entry) => ({
            groupID: groupID(entry.groupID),
            version: groupVersion(entry.version),
            legacyVersion: entry.version,
        }));
        if (
            new Set(
                selected.map((entry) => entry.groupID + ':' + entry.version)
            ).size !== selected.length
        ) {
            throw engineError(
                'duplicate legacy group selection',
                'INVALID_GROUP'
            );
        }
        const db = databaseConnection(this.connection);
        const legacy = ['publicKeys', 'privateKeys'].filter((name) =>
            db.objectStoreNames.contains(name)
        );
        if (selected.length && !db.objectStoreNames.contains('groupKeys')) {
            throw engineError(
                'legacy group store is missing',
                'INCOMPLETE_IDENTITY'
            );
        }
        const stores = [
            STORES.publicKeys,
            STORES.privateKeys,
            STORES.groupKeys,
            ...legacy,
            ...(selected.length ? ['groupKeys'] : []),
        ];
        // The same request chain reads the preparation snapshot and rechecks it
        // inside the write lock. All crypto work happens between transactions.
        const read = (tx, consume) => {
            const requests = [
                () =>
                    tx
                        .objectStore(STORES.publicKeys)
                        .get([this.namespace, this.accID]),
                () =>
                    tx
                        .objectStore(STORES.privateKeys)
                        .get([this.namespace, this.accID]),
                () =>
                    tx
                        .objectStore(STORES.groupKeys)
                        .index('namespace')
                        .getAll(this.namespace),
                ...legacy.map(
                    (name) => () => tx.objectStore(name).get(this.accID)
                ),
                ...selected.map(
                    (entry) => () =>
                        tx
                            .objectStore('groupKeys')
                            .get([entry.groupID, entry.legacyVersion])
                ),
            ];
            const records = [];
            const next = (index) =>
                index === requests.length
                    ? consume(records)
                    : requestResult(requests[index](), (record) => {
                          records.push(record);
                          return next(index + 1);
                      });
            return next(0);
        };
        const snapshot = await this.run(stores, 'readonly', (tx) =>
            read(tx, (records) => records)
        );
        const [pub, priv, groups] = snapshot;
        const flat = snapshot.slice(3, 3 + legacy.length);
        let pair;
        let migratedIdentity = false;
        if (pub || priv) {
            if (!pub || !priv)
                throw engineError(
                    'incomplete identity; originals retained',
                    'INCOMPLETE_IDENTITY'
                );
            if (priv.key?.d !== undefined) {
                pair = await migratePair(pub.key, priv.key);
                migratedIdentity = true;
            } else pair = identityPair(pub, priv);
        }
        if (flat.some(Boolean)) {
            if (!legacyIdentity)
                throw engineError(
                    'explicit legacy identity migration required',
                    'LEGACY_IDENTITY'
                );
            const flatPub = flat[legacy.indexOf('publicKeys')];
            const flatPriv = flat[legacy.indexOf('privateKeys')];
            if (!flatPub || !flatPriv)
                throw engineError(
                    'incomplete legacy identity; originals retained',
                    'INCOMPLETE_IDENTITY'
                );
            const imported = await migratePair(flatPub, flatPriv);
            if (pair && !samePublic(pair[0], imported[0])) {
                throw engineError(
                    'legacy and scoped identities differ; originals retained',
                    'IDENTITY_CONFLICT'
                );
            }
            pair = imported;
            migratedIdentity = true;
        }
        if (!pair)
            throw engineError(
                'migration requires an existing identity; no keys generated',
                'INCOMPLETE_IDENTITY'
            );
        const replacements = [];
        for (const record of groups) {
            groupID(record.groupID);
            groupVersion(record.version);
            if (record.key?.d !== undefined) {
                const imported = await migratePair(
                    publicPart(record.key),
                    record.key
                );
                replacements.push({
                    namespace: this.namespace,
                    groupID: record.groupID,
                    version: record.version,
                    key: imported[0],
                    privateKey: imported[1],
                });
            } else groupPair(record);
        }
        for (let index = 0; index < selected.length; index++) {
            const entry = selected[index];
            const record = snapshot[3 + legacy.length + index];
            if (!record)
                throw engineError(
                    'selected legacy group is missing',
                    'INCOMPLETE_IDENTITY'
                );
            const imported = await migratePair(publicPart(record), record);
            const existing = groups.find(
                (group) =>
                    group.groupID === entry.groupID &&
                    group.version === entry.version
            );
            if (existing && !samePublic(existing.key, imported[0])) {
                throw engineError(
                    'legacy group conflicts with scoped version; originals retained',
                    'GROUP_CONFLICT'
                );
            }
            const replacement = {
                namespace: this.namespace,
                groupID: entry.groupID,
                version: entry.version,
                key: imported[0],
                privateKey: imported[1],
            };
            const previous = replacements.findIndex(
                (group) =>
                    group.groupID === entry.groupID &&
                    group.version === entry.version
            );
            if (previous < 0) replacements.push(replacement);
            else replacements[previous] = replacement;
        }
        // JSON is only an internal conflict comparison, never a persisted backup
        // or an error value. CryptoKey capabilities are compared by their metadata.
        const describe = (records) =>
            JSON.stringify(records, (name, value) =>
                value instanceof CryptoKey
                    ? {
                          type: value.type,
                          extractable: value.extractable,
                          algorithm: value.algorithm,
                          usages: value.usages,
                      }
                    : value
            );
        const expected = describe(snapshot);
        if (!migratedIdentity && !replacements.length)
            return { migratedIdentity: false, migratedGroups: 0 };
        return this.run(stores, 'readwrite', (tx) =>
            read(tx, (current) => {
                if (describe(current) !== expected) {
                    throw engineError(
                        'records changed during migration; retry explicitly',
                        'MIGRATION_CONFLICT'
                    );
                }
                const writes = [];
                if (migratedIdentity) {
                    const metadata = {
                        namespace: this.namespace,
                        accID: this.accID,
                    };
                    writes.push(() =>
                        tx
                            .objectStore(STORES.publicKeys)
                            .put({ ...metadata, key: pair[0] })
                    );
                    writes.push(() =>
                        tx
                            .objectStore(STORES.privateKeys)
                            .put({
                                ...metadata,
                                key: pair[1],
                                publicKey: pair[0],
                            })
                    );
                    for (const name of legacy)
                        writes.push(() =>
                            tx.objectStore(name).delete(this.accID)
                        );
                }
                for (const record of replacements)
                    writes.push(() =>
                        tx.objectStore(STORES.groupKeys).put(record)
                    );
                for (const entry of selected) {
                    writes.push(() =>
                        tx
                            .objectStore('groupKeys')
                            .delete([entry.groupID, entry.legacyVersion])
                    );
                }
                const next = (index) =>
                    index === writes.length
                        ? {
                              migratedIdentity,
                              migratedGroups: replacements.length,
                          }
                        : requestResult(writes[index](), () => next(index + 1));
                return next(0);
            })
        );
    }

    async invalidate() {
        // A previously validated owner can immediately invalidate other live
        // instances. An unbound/wrong owner must first pass the native scope check.
        if (this.#generation !== undefined) this.#lockPeers();
        const db = databaseConnection(this.connection);
        const owned = Object.values(STORES).filter(
            (name) =>
                name !== STORES.scopes &&
                name !== STORES.keyUsage &&
                db.objectStoreNames.contains(name)
        );
        return withTransaction(
            this.connection,
            [STORES.scopes, ...owned],
            'readwrite',
            (tx) => {
                this.#register(tx);
                const scopes = tx.objectStore(STORES.scopes);
                return requestResult(scopes.get(this.namespace), (record) => {
                    this.#checkOwner(record);
                    const state = scopeState(record);
                    if (state.status === 'invalidated') {
                        this.#lockPeers();
                        return;
                    }
                    if (
                        this.#generation !== undefined &&
                        state.generation !== this.#generation
                    )
                        throw engineError(
                            'stale instance cannot delete a new namespace generation',
                            'ENGINE_LOCKED'
                        );
                    if (state.generation === Number.MAX_SAFE_INTEGER)
                        throw engineError(
                            'namespace generation exhausted',
                            'GENERATION_EXHAUSTED'
                        );
                    this.#lockPeers();
                    const removals = owned.map((name) => {
                        const store = tx.objectStore(name);
                        return requestResult(
                            store.index('namespace').getAllKeys(this.namespace),
                            (keys) =>
                                Promise.all(
                                    keys.map((key) =>
                                        requestResult(store.delete(key))
                                    )
                                )
                        );
                    });
                    const tombstone = requestResult(
                        scopes.put({
                            namespace: this.namespace,
                            accID: this.accID,
                            status: 'invalidated',
                            generation: state.generation + 1,
                        })
                    );
                    return Promise.all([...removals, tombstone]).then(
                        () => undefined
                    );
                });
            }
        );
        // Legacy unscoped/application stores and shared per-actual-key usage
        // reservations remain: deletion must neither claim ownership nor refund.
    }
    async reinitializationState() {
        return withTransaction(
            this.connection,
            [STORES.scopes],
            'readonly',
            (tx) => {
                this.#register(tx);
                return requestResult(
                    tx.objectStore(STORES.scopes).get(this.namespace),
                    (record) => {
                        this.#checkOwner(record);
                        const state = scopeState(record);
                        if (state.status !== 'invalidated')
                            throw engineError(
                                'commit panic() before explicit reinitialization',
                                'REINITIALIZATION_REQUIRED'
                            );
                        if (state.generation === Number.MAX_SAFE_INTEGER)
                            throw engineError(
                                'namespace generation exhausted',
                                'GENERATION_EXHAUSTED'
                            );
                        return state.generation;
                    }
                );
            }
        );
    }
    async reinitialize(candidate, expectedGeneration, valid) {
        return withTransaction(
            this.connection,
            [STORES.scopes, STORES.publicKeys, STORES.privateKeys],
            'readwrite',
            (tx) => {
                this.#track(tx);
                const scopes = tx.objectStore(STORES.scopes);
                return requestResult(scopes.get(this.namespace), (record) => {
                    this.#checkOwner(record);
                    const state = scopeState(record);
                    if (
                        !valid() ||
                        state.status !== 'invalidated' ||
                        state.generation !== expectedGeneration
                    )
                        throw engineError(
                            'reinitialization was invalidated or lost its generation',
                            'ENGINE_LOCKED'
                        );
                    const [publicKey, privateKey] = candidate;
                    tx.objectStore(STORES.publicKeys).add({
                        namespace: this.namespace,
                        accID: this.accID,
                        key: publicKey,
                    });
                    tx.objectStore(STORES.privateKeys).add({
                        namespace: this.namespace,
                        accID: this.accID,
                        key: privateKey,
                        publicKey,
                    });
                    return requestResult(
                        scopes.put({
                            namespace: this.namespace,
                            accID: this.accID,
                            status: 'active',
                            generation: state.generation + 1,
                        }),
                        () => state.generation + 1
                    );
                });
            }
        );
    }
    resume(generation) {
        this.#generation = generation;
        this.#blocked = false;
    }
}

const V2_SUITE = 'BE8-P384-HKDF-SHA256-A256GCM';
const V2_PURPOSES = Object.freeze(['data', 'attachment', 'key-wrap']);
const fields$1 = [
    'version',
    'suite',
    'contextID',
    'sender',
    'receiver',
    'senderFingerprint',
    'receiverFingerprint',
    'purpose',
    'salt',
];
const encoder = new TextEncoder();

function fail(
    message = 'invalid v2 derivation context',
    code = 'INVALID_DERIVATION_CONTEXT'
) {
    return engineError(message, code);
}

function scalarString(value, maxBytes = 1024) {
    if (typeof value !== 'string' || !value.length || value.length > maxBytes)
        throw fail();
    // Reject lone UTF-16 surrogates rather than silently replacing them in UTF-8.
    for (const character of value) {
        const code = character.codePointAt(0);
        if (code >= 0xd800 && code <= 0xdfff) throw fail();
    }
    const bytes = encoder.encode(value);
    if (bytes.length > maxBytes) throw fail();
    return bytes;
}

function decode32(value) {
    fingerprintValue(value);
    const bytes = decodeBase64url(value, 32);
    if (bytes.length !== 32) throw fail();
    return bytes;
}

function endpoint(value) {
    scalarString(value, 256);
    if (
        !/^(0|[1-9][0-9]*)$/.test(value) &&
        !/^g[A-Za-z0-9_-]+:[1-9][0-9]*$/.test(value)
    )
        throw fail();
    if (
        value.startsWith('g') &&
        !Number.isSafeInteger(Number(value.slice(value.lastIndexOf(':') + 1)))
    )
        throw fail();
    return value;
}

function derivationSnapshot(value) {
    if (!value)
        throw fail(
            'v2 derivation metadata is required; use the explicit legacy reader for old ciphertexts',
            'DERIVATION_CONTEXT_REQUIRED'
        );
    try {
        if (
            typeof value !== 'object' ||
            Array.isArray(value) ||
            Object.keys(value).length !== fields$1.length ||
            !fields$1.every((field) => Object.keys(value).includes(field))
        )
            throw fail();
        const snapshot = Object.fromEntries(
            fields$1.map((field) => [field, value[field]])
        );
        if (
            snapshot.version !== 2 ||
            snapshot.suite !== V2_SUITE ||
            !V2_PURPOSES.includes(snapshot.purpose)
        )
            throw fail();
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
function encodeV2DerivationInfo(metadata) {
    const context = derivationSnapshot(metadata);
    const values = [
        encoder.encode('2'),
        encoder.encode(context.suite),
        scalarString(context.contextID),
        scalarString(context.sender, 256),
        scalarString(context.receiver, 256),
        decode32(context.senderFingerprint),
        decode32(context.receiverFingerprint),
        encoder.encode(context.purpose),
    ];
    return encodeFields('BE8-HKDF-INFO', values);
}

function encodeFields(domain, values) {
    const prefix = encoder.encode(domain);
    const info = new Uint8Array(
        prefix.length +
            values.reduce((length, value) => length + 4 + value.length, 0)
    );
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

async function createV2Metadata(localID, ownPublicKey, peerPublicKey, options) {
    if (!options || typeof options !== 'object' || Array.isArray(options))
        throw fail();
    // Snapshot all application inputs before crypto yields.
    const { contextID, sender, receiver, purpose } = options;
    if (sender !== localID)
        throw fail('only the sender creates a new derivation context');
    scalarString(contextID);
    endpoint(sender);
    endpoint(receiver);
    if (!V2_PURPOSES.includes(purpose)) throw fail();
    const [own, peer] = await Promise.all([
        preparePublicKey(ownPublicKey),
        preparePublicKey(peerPublicKey),
    ]);
    if (sender === receiver && own.fingerprint !== peer.fingerprint)
        throw fail();
    const salt = crypto.getRandomValues(new Uint8Array(32));
    return derivationSnapshot({
        version: 2,
        suite: V2_SUITE,
        contextID,
        sender,
        receiver,
        senderFingerprint: own.fingerprint,
        receiverFingerprint: peer.fingerprint,
        purpose,
        salt: encodeBase64url(salt),
    });
}

// Internal helper also exercised against RFC 5869 public test vectors.
// It never returns IKM, PRK, raw AES bytes or an extractable derived key.
async function hkdfAES(secret, salt, info, purpose) {
    if (!V2_PURPOSES.includes(purpose)) throw fail();
    let material;
    try {
        material = await crypto.subtle.importKey('raw', secret, 'HKDF', false, [
            'deriveKey',
        ]);
    } finally {
        secret.fill(0);
    }
    const usages =
        purpose === 'key-wrap'
            ? ['wrapKey', 'unwrapKey']
            : ['encrypt', 'decrypt'];
    return crypto.subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt, info },
        material,
        { name: 'AES-GCM', length: 256 },
        false,
        usages
    );
}

async function deriveV2AES(
    localID,
    ownPublicKey,
    peerPublicKey,
    privateKey,
    metadata
) {
    const context = derivationSnapshot(metadata);
    const priv = privateCryptoKey(privateKey);
    if (priv.usages[0] !== 'deriveBits') {
        throw fail(
            'stored non-extractable deriveKey-only identity cannot derive v2; it is retained for explicit legacy reading',
            'V2_KEY_USAGE_UNAVAILABLE'
        );
    }
    if (localID !== context.sender && localID !== context.receiver)
        throw fail('local endpoint is not a participant in this context');
    const [own, peer] = await Promise.all([
        preparePublicKey(ownPublicKey),
        preparePublicKey(peerPublicKey),
    ]);
    const sending = localID === context.sender;
    const ownExpected = sending
        ? context.senderFingerprint
        : context.receiverFingerprint;
    const peerExpected = sending
        ? context.receiverFingerprint
        : context.senderFingerprint;
    if (own.fingerprint !== ownExpected || peer.fingerprint !== peerExpected) {
        throw fail(
            'derivation fingerprints do not match the actual endpoint keys',
            'DERIVATION_KEY_MISMATCH'
        );
    }
    const imported = await crypto.subtle.importKey(
        'jwk',
        peer.key,
        { name: 'ECDH', namedCurve: 'P-384' },
        peer.key.ext,
        []
    );
    let secret;
    try {
        // P-384's complete fixed-width ECDH x-coordinate, including leading zeros.
        secret = new Uint8Array(
            await crypto.subtle.deriveBits(
                { name: 'ECDH', public: imported },
                priv,
                384
            )
        );
        if (secret.length !== 48)
            throw fail('unexpected P-384 ECDH output length');
        return await hkdfAES(
            secret,
            decode32(context.salt),
            encodeV2DerivationInfo(context),
            context.purpose
        );
    } finally {
        // Best effort only: WebCrypto/runtime copies and GC are outside our control.
        secret?.fill(0);
    }
}

function requireAES(key, usage) {
    if (!key)
        throw engineError(
            'no derived key passed to AES operation',
            'INVALID_KEY'
        );
    if (
        !(key instanceof CryptoKey) ||
        key.type !== 'secret' ||
        key.algorithm.name !== 'AES-GCM' ||
        key.algorithm.length !== 256 ||
        key.extractable
    ) {
        throw engineError(
            'a non-extractable AES-256-GCM key is required',
            'INVALID_KEY'
        );
    }
    if (!key.usages.includes(usage))
        throw new DOMException(
            'AES key does not permit this operation',
            'InvalidAccessError'
        );
}

function payloadSnapshot(ciphertext, iv, legacy = false) {
    if (iv === undefined || iv === null)
        throw engineError(
            'no iv (Initialization vector) passed to decrypt',
            'INVALID_IV'
        );
    let nonce;
    if (legacy) {
        if (
            typeof iv !== 'string' ||
            !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(
                iv
            )
        ) {
            throw engineError('invalid legacy UUID IV', 'INVALID_IV');
        }
        // UUID bytes were ASCII/UTF-8. No random bytes pass through text codecs.
        nonce = Uint8Array.from(iv, (character) => character.charCodeAt(0));
    } else {
        try {
            nonce = decodeBytes(iv, V2_LIMITS.ivBytes);
        } catch {
            throw engineError(
                'v2 IV must be exactly 12 bytes in canonical base64url or binary',
                'INVALID_IV'
            );
        }
        if (nonce.length !== V2_LIMITS.ivBytes)
            throw engineError('v2 IV must be exactly 12 bytes', 'INVALID_IV');
    }
    const bytes = legacy
        ? decodeLegacyBase64(ciphertext)
        : decodeBytes(ciphertext);
    if (bytes.length < V2_LIMITS.tagBits / 8)
        throw engineError(
            'ciphertext is shorter than the GCM tag',
            'INVALID_CIPHERTEXT'
        );
    return { bytes, iv: nonce };
}

async function encryptPayload(key, bytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        key,
        bytes
    );
    return { cipherText: encodeBase64url(ciphertext), iv: encodeBase64url(iv) };
}

function decryptPayload(key, payload) {
    return crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: payload.iv, tagLength: 128 },
        key,
        payload.bytes
    );
}

// Only actual, validated derivation inputs enter this identity. No caller alias
// or storage namespace can make the same HKDF key get a fresh local budget.
async function derivationUsageID(derivation) {
    const info = encodeV2DerivationInfo(derivation);
    return usageIdentity(derivation.salt, info);
}

async function usageIdentity(salt, info) {
    const prefix = new TextEncoder().encode('BE8-GCM-USAGE');
    const bytes = new Uint8Array(prefix.length + 32 + info.length);
    bytes.set(prefix);
    bytes.set(decode32(salt), prefix.length);
    bytes.set(info, prefix.length + 32);
    return encodeBase64url(await crypto.subtle.digest('SHA-256', bytes));
}

/* global BigInt */
const GROUP_SUITE = 'BE8-GROUP-HKDF-SHA256-A256GCM';
const fields = [
    'version',
    'suite',
    'contextID',
    'sender',
    'receiver',
    'senderFingerprint',
    'receiverFingerprint',
    'purpose',
    'salt',
];
function groupDerivationSnapshot(value) {
    const result = Object.fromEntries(
        fields.map((field) => [field, value[field]])
    );
    if (
        result.version !== 2 ||
        result.suite !== GROUP_SUITE ||
        !['data', 'attachment'].includes(result.purpose) ||
        typeof result.sender !== 'string' ||
        !/^(0|[1-9][0-9]*)$/.test(result.sender) ||
        typeof result.receiver !== 'string' ||
        result.receiver.length > 128 ||
        !/^g[A-Za-z0-9_-]+$/.test(result.receiver)
    ) {
        throw engineError('invalid group derivation', 'INVALID_ENVELOPE');
    }
    scalarString(result.contextID);
    scalarString(result.sender, 256);
    decode32(result.senderFingerprint);
    decode32(result.receiverFingerprint);
    decode32(result.salt);
    return Object.freeze(result);
}
function encodeGroupInfo(header) {
    const h = groupDerivationSnapshot(header);
    const g = header.group;
    if (
        !g ||
        g.groupID !== h.receiver ||
        g.generation !== h.receiverFingerprint
    )
        throw engineError('group binding mismatch', 'INVALID_ENVELOPE');
    const epoch = new Uint8Array(8);
    new DataView(epoch.buffer).setBigUint64(0, BigInt(g.epoch), false);
    return encodeFields('BE8-GROUP-HKDF-INFO', [
        scalarString('2'),
        scalarString(h.suite),
        scalarString(h.contextID),
        scalarString(h.sender, 256),
        scalarString(h.receiver),
        decode32(h.senderFingerprint),
        decode32(h.receiverFingerprint),
        scalarString(h.purpose),
        scalarString(g.groupID),
        epoch,
        decode32(g.generation),
    ]);
}
async function groupGeneration(bytes) {
    return encodeBase64url(await crypto.subtle.digest('SHA-256', bytes));
}
async function importGroupSecret(bytes) {
    try {
        const key = await crypto.subtle.importKey('raw', bytes, 'HKDF', false, [
            'deriveKey',
        ]);
        if (typeof structuredClone !== 'function') throw new Error();
        const clone = structuredClone(key);
        requireGroupSecret(clone);
        return key;
    } catch {
        throw engineError(
            'browser must support non-extractable CryptoKey structured clone',
            'CRYPTOKEY_STORAGE_UNSUPPORTED'
        );
    }
}
function requireGroupSecret(key) {
    if (
        !(key instanceof CryptoKey) ||
        key.algorithm.name !== 'HKDF' ||
        key.type !== 'secret' ||
        key.extractable ||
        key.usages.length !== 1 ||
        key.usages[0] !== 'deriveKey'
    )
        throw engineError(
            'invalid persisted group secret',
            'INVALID_GROUP_KEY'
        );
    return key;
}
async function deriveGroupAES(key, header) {
    return crypto.subtle.deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: decode32(header.salt),
            info: encodeGroupInfo(header),
        },
        requireGroupSecret(key),
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

/* global BigInt */

const MAX_SEQUENCE = (1n << 64n) - 1n;
const text = (value) => new TextEncoder().encode(value);
const metadataFields = [
    'version',
    'suite',
    'contextID',
    'sender',
    'receiver',
    'senderFingerprint',
    'receiverFingerprint',
    'purpose',
    'salt',
];
const headerFields = [...metadataFields, 'iv', 'sequence', 'group'];
function invalidEnvelope() {
    return engineError(
        'invalid or unsupported v2 envelope',
        'INVALID_ENVELOPE'
    );
}
function exactObject(value, fields) {
    try {
        if (
            !value ||
            typeof value !== 'object' ||
            Array.isArray(value) ||
            Reflect.ownKeys(value).length !== fields.length ||
            !fields.every((field) => Object.hasOwn(value, field))
        )
            throw invalidEnvelope();
        const snapshot = {};
        for (const field of fields) {
            const descriptor = Object.getOwnPropertyDescriptor(value, field);
            if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value'))
                throw invalidEnvelope();
            snapshot[field] = descriptor.value;
        }
        return snapshot;
    } catch {
        throw invalidEnvelope();
    }
}
function sequenceValue(value) {
    if (
        typeof value !== 'string' ||
        value.length > 20 ||
        !/^(0|[1-9][0-9]*)$/.test(value)
    )
        throw invalidEnvelope();
    const number = BigInt(value);
    if (number > MAX_SEQUENCE) throw invalidEnvelope();
    return number;
}
function uint64(value) {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, sequenceValue(value), false);
    return bytes;
}
function groupSnapshot(value) {
    if (value === null) return null;
    value = exactObject(value, ['groupID', 'epoch', 'generation']);
    if (
        typeof value.groupID !== 'string' ||
        value.groupID.length > 128 ||
        !/^g[A-Za-z0-9_-]+$/.test(value.groupID) ||
        sequenceValue(value.epoch) === 0n
    )
        throw invalidEnvelope();
    decode32(value.generation);
    return Object.freeze({
        groupID: value.groupID,
        epoch: value.epoch,
        generation: value.generation,
    });
}
function headerMetadata(header) {
    const value = Object.fromEntries(
        metadataFields.map((field) => [field, header[field]])
    );
    return header.suite === GROUP_SUITE
        ? groupDerivationSnapshot(value)
        : derivationSnapshot(value);
}
function headerSnapshot(value) {
    try {
        value = exactObject(value, headerFields);
        const metadata = headerMetadata(value);
        const iv = decodeBase64url(value.iv, 12);
        if (iv.length !== 12 || sequenceValue(value.sequence) === 0n)
            throw invalidEnvelope();
        const group = groupSnapshot(value.group);
        if (metadata.suite === GROUP_SUITE) {
            if (
                !group ||
                group.groupID !== metadata.receiver ||
                group.generation !== metadata.receiverFingerprint
            )
                throw invalidEnvelope();
        } else {
            if (
                !/^(0|[1-9][0-9]*)$/.test(metadata.sender) ||
                !/^(0|[1-9][0-9]*)$/.test(metadata.receiver) ||
                (group !== null) !== (metadata.purpose === 'key-wrap')
            )
                throw invalidEnvelope();
        }
        return Object.freeze({
            ...metadata,
            iv: value.iv,
            sequence: value.sequence,
            group,
        });
    } catch {
        throw invalidEnvelope();
    }
}
function envelopeSnapshot(value) {
    value = exactObject(value, ['header', 'ciphertext']);
    const header = headerSnapshot(value.header);
    if (typeof value.ciphertext !== 'string') throw invalidEnvelope();
    const payload = payloadSnapshot(value.ciphertext, header.iv);
    return { header, payload, ciphertext: value.ciphertext };
}
function encodeEnvelopeAAD(value) {
    const h = headerSnapshot(value);
    const g = h.group;
    const aad = encodeFields('BE8-ENVELOPE-AAD', [
        h.suite === GROUP_SUITE
            ? encodeGroupInfo(h)
            : encodeV2DerivationInfo(headerMetadata(h)),
        decode32(h.salt),
        decodeBase64url(h.iv, 12),
        uint64(h.sequence),
        text(g ? 'group' : ''),
        text(g?.groupID || ''),
        g ? uint64(g.epoch) : new Uint8Array(),
        g ? decode32(g.generation) : new Uint8Array(),
    ]);
    if (aad.length > 4096) throw invalidEnvelope();
    return aad;
}
function checkExpected(header, expected, localID) {
    if (!expected || typeof expected !== 'object')
        throw engineError(
            'independent envelope expectations are required',
            'ENVELOPE_EXPECTATION_REQUIRED'
        );
    scalarString(expected.contextID);
    if (
        expected.sender !== header.sender ||
        expected.receiver !== header.receiver ||
        expected.contextID !== header.contextID ||
        expected.purpose !== header.purpose ||
        header.receiver !== localID
    ) {
        throw engineError(
            'envelope does not match the expected endpoints, context or purpose',
            'ENVELOPE_EXPECTATION_MISMATCH'
        );
    }
}

// One byte-based authenticated operation. Wrapping is internal; no public
// group-secret decoder or private-key export is introduced.
async function sealBytes(key, header, bytes) {
    const additionalData = encodeEnvelopeAAD(header);
    const algorithm = {
        name: 'AES-GCM',
        iv: decodeBase64url(header.iv, 12),
        tagLength: 128,
        additionalData,
    };
    if (header.purpose === 'key-wrap') {
        if (bytes.length !== 32 || !header.group) throw invalidEnvelope();
        const temporary = await crypto.subtle.importKey(
            'raw',
            bytes,
            'AES-GCM',
            true,
            ['encrypt', 'decrypt']
        );
        return encodeBase64url(
            await crypto.subtle.wrapKey('raw', temporary, key, algorithm)
        );
    }
    return encodeBase64url(await crypto.subtle.encrypt(algorithm, key, bytes));
}
async function openBytes(key, snapshot) {
    const h = snapshot.header;
    const algorithm = {
        name: 'AES-GCM',
        iv: snapshot.payload.iv,
        tagLength: 128,
        additionalData: encodeEnvelopeAAD(h),
    };
    if (h.purpose === 'key-wrap') {
        if (snapshot.payload.bytes.length !== 48 || !h.group)
            throw invalidEnvelope();
        const temporary = await crypto.subtle.unwrapKey(
            'raw',
            snapshot.payload.bytes,
            key,
            algorithm,
            'AES-GCM',
            true,
            ['encrypt', 'decrypt']
        );
        return new Uint8Array(await crypto.subtle.exportKey('raw', temporary));
    }
    return new Uint8Array(
        await crypto.subtle.decrypt(algorithm, key, snapshot.payload.bytes)
    );
}

class Envelopes {
    constructor(keys, localID, replay) {
        this.keys = keys;
        this.localID = localID;
        this.replay = replay;
    }
    async seal(
        sender,
        receiver,
        value,
        { contextID, purpose, group = null } = {}
    ) {
        if (typeof receiver === 'string' && receiver.startsWith('g'))
            throw engineError(
                'ECDH group endpoints are legacy-only',
                'LEGACY_GROUP_API'
            );
        if (sender !== this.localID)
            throw engineError(
                'Missing private key for local sender account',
                'INVALID_PRIVATE_KEY'
            );
        const bytes = bytesSnapshot(value, V2_LIMITS.plaintextBytes);
        scalarString(contextID);
        const [peer, privateKey, own] = await this.keys.endpointKeys(
            receiver,
            sender,
            true
        );
        if (!peer)
            throw engineError(
                'Missing public key for selected peer',
                'INVALID_KEY'
            );
        if (!privateKey)
            throw engineError(
                'Missing private key for local endpoint',
                'INVALID_PRIVATE_KEY'
            );
        const metadata = await createV2Metadata(sender, own, peer, {
            contextID,
            sender,
            receiver,
            purpose,
        });
        const key = await deriveV2AES(sender, own, peer, privateKey, metadata);
        const sequence = await this.replay.reserve({ ...metadata, group });
        const template = headerSnapshot({
            ...metadata,
            iv: encodeBase64url(new Uint8Array(12)),
            sequence,
            group,
        });
        await this.keys.reserveUsage(
            await derivationUsageID(metadata),
            bytes.length,
            encodeEnvelopeAAD(template).length
        );
        const header = headerSnapshot({
            ...template,
            iv: encodeBase64url(crypto.getRandomValues(new Uint8Array(12))),
        });
        return { header, ciphertext: await sealBytes(key, header, bytes) };
    }
    async open(value, expected) {
        const snapshot = envelopeSnapshot(value);
        expected = expected && {
            sender: expected.sender,
            receiver: expected.receiver,
            contextID: expected.contextID,
            purpose: expected.purpose,
        };
        if (snapshot.header.suite === GROUP_SUITE) throw invalidEnvelope();
        checkExpected(snapshot.header, expected, this.localID);
        const [peer, privateKey, own] = await this.keys.endpointKeys(
            snapshot.header.sender,
            expected.receiver,
            true
        );
        if (!peer)
            throw engineError(
                'Missing public key for selected peer',
                'INVALID_KEY'
            );
        if (!privateKey)
            throw engineError(
                'Missing private key for local endpoint',
                'INVALID_PRIVATE_KEY'
            );
        const key = await deriveV2AES(
            expected.receiver,
            own,
            peer,
            privateKey,
            headerMetadata(snapshot.header)
        );
        return {
            header: snapshot.header,
            bytes: await openBytes(key, snapshot),
        };
    }
}

function groupOptions(options, purpose = false) {
    if (
        !options ||
        typeof options !== 'object' ||
        Array.isArray(options) ||
        Reflect.ownKeys(options).some(
            (field) =>
                !['contextID', ...(purpose ? ['purpose'] : [])].includes(field)
        )
    ) {
        throw engineError(
            'group options allow only contextID and an explicit envelope purpose',
            'INVALID_OPTIONS'
        );
    }
    return {
        contextID: options.contextID,
        ...(purpose ? { purpose: options.purpose } : {}),
    };
}
function epochID(id, epoch) {
    groupID(id);
    if (id.length > 128 || sequenceValue(epoch) === 0n)
        throw engineError('invalid group epoch', 'INVALID_GROUP');
    return { groupID: id, epoch };
}
function metadata(record) {
    if (!record)
        throw engineError(
            'group epoch is not available locally',
            'GROUP_EPOCH_MISSING'
        );
    const group = groupSnapshot({
        groupID: record.groupID,
        epoch: record.epoch,
        generation: record.generation,
    });
    accountID(record.issuer);
    return Object.freeze({ ...group, issuer: record.issuer });
}
function equal(left, right) {
    return ['groupID', 'epoch', 'generation', 'issuer'].every(
        (field) => left[field] === right[field]
    );
}
class Groups {
    constructor(keys, envelopes, replay, localID) {
        Object.assign(this, { keys, envelopes, replay, localID });
    }
    async record(id, epoch) {
        const selected = epochID(id, epoch);
        return this.keys.run([STORES.groupEpochs], 'readonly', (tx) =>
            requestResult(
                tx
                    .objectStore(STORES.groupEpochs)
                    .get([
                        this.keys.namespace,
                        selected.groupID,
                        selected.epoch,
                    ]),
                (record) => {
                    metadata(record);
                    requireGroupSecret(record.key);
                    return record;
                }
            )
        );
    }
    async store(record) {
        metadata(record);
        requireGroupSecret(record.key);
        return this.keys.run([STORES.groupEpochs], 'readwrite', (tx) => {
            const store = tx.objectStore(STORES.groupEpochs);
            return requestResult(
                store.get([this.keys.namespace, record.groupID, record.epoch]),
                (current) => {
                    if (current) {
                        if (!equal(metadata(current), metadata(record)))
                            throw engineError(
                                'immutable group epoch already has another generation or issuer',
                                'GROUP_EPOCH_CONFLICT'
                            );
                        requireGroupSecret(current.key);
                        return metadata(current);
                    }
                    return requestResult(
                        store.add({
                            ...record,
                            namespace: this.keys.namespace,
                        }),
                        () => metadata(record)
                    );
                }
            );
        });
    }
    async create(id, epoch, recipients, options) {
        const selected = epochID(id, epoch);
        options = groupOptions(options);
        const contextID = options.contextID;
        scalarString(contextID);
        if (!Array.isArray(recipients) || recipients.length > 256)
            throw engineError(
                'explicit recipient array of at most 256 accounts required',
                'INVALID_ACCOUNT'
            );
        recipients = recipients.map(accountID);
        if (
            new Set(recipients).size !== recipients.length ||
            recipients.includes(this.localID)
        )
            throw engineError(
                'duplicate or local recipient',
                'INVALID_ACCOUNT'
            );
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        try {
            const generation = await groupGeneration(bytes);
            const key = await importGroupSecret(bytes);
            const group = { ...selected, generation };
            const packages = [];
            // No membership records. Each recipient supplies only a trusted public key.
            for (const receiver of recipients) {
                packages.push({
                    recipient: receiver,
                    envelope: await this.envelopes.seal(
                        this.localID,
                        receiver,
                        bytes,
                        { contextID, purpose: 'key-wrap', group }
                    ),
                });
            }
            const result = await this.store({
                ...group,
                issuer: this.localID,
                key,
            });
            return { epoch: result, packages };
        } finally {
            bytes.fill(0);
        }
    }
    async import(value, expected) {
        const packet = envelopeSnapshot(value);
        const group = groupSnapshot(
            expected && {
                groupID: expected.groupID,
                epoch: expected.epoch,
                generation: expected.generation,
            }
        );
        const copied = expected && {
            sender: expected.sender,
            receiver: expected.receiver,
            contextID: expected.contextID,
            purpose: 'key-wrap',
        };
        if (
            !packet.header.group ||
            !equal(
                { ...packet.header.group, issuer: packet.header.sender },
                { ...group, issuer: copied?.sender }
            )
        ) {
            throw engineError(
                'key package does not match expected issuer, group, epoch and generation',
                'ENVELOPE_EXPECTATION_MISMATCH'
            );
        }
        const opened = await this.envelopes.open(
            { header: packet.header, ciphertext: packet.ciphertext },
            copied
        );
        try {
            if ((await groupGeneration(opened.bytes)) !== group.generation)
                throw engineError(
                    'group generation digest mismatch',
                    'INVALID_GROUP_KEY'
                );
            const key = await importGroupSecret(opened.bytes);
            return await this.store({ ...group, issuer: copied.sender, key });
        } finally {
            opened.bytes.fill(0);
        }
    }
    async activate(id, epoch, { expectedCurrentEpoch } = {}) {
        epochID(id, epoch);
        if (expectedCurrentEpoch !== null) epochID(id, expectedCurrentEpoch);
        return this.keys.run(
            [STORES.groupEpochs, STORES.activeEpochs],
            'readwrite',
            (tx) => {
                const active = tx.objectStore(STORES.activeEpochs);
                return requestResult(
                    tx
                        .objectStore(STORES.groupEpochs)
                        .get([this.keys.namespace, id, epoch]),
                    (record) => {
                        metadata(record);
                        requireGroupSecret(record.key);
                        return requestResult(
                            active.get([this.keys.namespace, id]),
                            (current) => {
                                if (
                                    (current?.epoch ?? null) !==
                                    expectedCurrentEpoch
                                )
                                    throw engineError(
                                        'active epoch changed concurrently',
                                        'GROUP_EPOCH_CONFLICT'
                                    );
                                if (
                                    current &&
                                    sequenceValue(epoch) <
                                        sequenceValue(current.epoch)
                                )
                                    throw engineError(
                                        'old epochs are archive-only',
                                        'GROUP_EPOCH_DOWNGRADE'
                                    );
                                return requestResult(
                                    active.put({
                                        namespace: this.keys.namespace,
                                        groupID: id,
                                        epoch,
                                    }),
                                    () => metadata(record)
                                );
                            }
                        );
                    }
                );
            }
        );
    }
    async epochs(id) {
        if (id !== undefined) groupID(id);
        return this.keys.run([STORES.groupEpochs], 'readonly', (tx) =>
            requestResult(
                tx
                    .objectStore(STORES.groupEpochs)
                    .index('namespace')
                    .getAll(this.keys.namespace),
                (rows) =>
                    rows
                        .filter((row) => id === undefined || row.groupID === id)
                        .map(metadata)
            )
        );
    }
    async active(id) {
        groupID(id);
        return this.keys.run(
            [STORES.groupEpochs, STORES.activeEpochs],
            'readonly',
            (tx) =>
                requestResult(
                    tx
                        .objectStore(STORES.activeEpochs)
                        .get([this.keys.namespace, id]),
                    (active) =>
                        active
                            ? requestResult(
                                  tx
                                      .objectStore(STORES.groupEpochs)
                                      .get([
                                          this.keys.namespace,
                                          id,
                                          active.epoch,
                                      ]),
                                  metadata
                              )
                            : undefined
                )
        );
    }
    async stream(expected) {
        expected = expected && {
            groupID: expected.groupID,
            epoch: expected.epoch,
            generation: expected.generation,
            sender: expected.sender,
            contextID: expected.contextID,
            purpose: expected.purpose,
        };
        const group = groupSnapshot({
            groupID: expected?.groupID,
            epoch: expected?.epoch,
            generation: expected?.generation,
        });
        accountID(expected?.sender);
        scalarString(expected?.contextID);
        if (!['data', 'attachment'].includes(expected?.purpose))
            throw engineError('invalid group purpose', 'INVALID_PURPOSE');
        const record = await this.record(group.groupID, group.epoch);
        if (record.generation !== group.generation)
            throw engineError(
                'expected group generation differs from local epoch',
                'GROUP_EPOCH_CONFLICT'
            );
        const [publicKey] = await this.keys.endpointKeys(
            expected.sender,
            this.localID,
            true
        );
        if (!publicKey)
            throw engineError(
                'expected sender key is unavailable',
                'INVALID_KEY'
            );
        return {
            record,
            header: {
                version: 2,
                suite: GROUP_SUITE,
                contextID: expected.contextID,
                sender: expected.sender,
                receiver: group.groupID,
                senderFingerprint: await jwkThumbprint(publicKey),
                receiverFingerprint: group.generation,
                purpose: expected.purpose,
                group,
            },
        };
    }
    async openReceive(expected) {
        const { header } = await this.stream(expected);
        await this.replay.openContext(header.contextID);
        await this.replay.initialize(header, 'receive');
    }
    async seal(id, value, options) {
        const bytes = bytesSnapshot(value, V2_LIMITS.plaintextBytes);
        options = groupOptions(options, true);
        const contextID = options.contextID;
        scalarString(contextID);
        const active = await this.active(id);
        if (!active)
            throw engineError(
                'explicitly activate a group epoch first',
                'GROUP_EPOCH_NOT_ACTIVE'
            );
        const { record, header: base } = await this.stream({
            ...active,
            sender: this.localID,
            contextID,
            purpose: options?.purpose,
        });
        const metadata = {
            ...base,
            salt: encodeBase64url(crypto.getRandomValues(new Uint8Array(32))),
        };
        const key = await deriveGroupAES(record.key, metadata);
        const sequence = await this.replay.reserve(metadata);
        const template = headerSnapshot({
            ...metadata,
            sequence,
            iv: encodeBase64url(new Uint8Array(12)),
        });
        await this.keys.reserveUsage(
            await usageIdentity(template.salt, encodeGroupInfo(template)),
            bytes.length,
            encodeEnvelopeAAD(template).length
        );
        const header = headerSnapshot({
            ...template,
            iv: encodeBase64url(crypto.getRandomValues(new Uint8Array(12))),
        });
        return { header, ciphertext: await sealBytes(key, header, bytes) };
    }
    async open(value, expected) {
        const packet = envelopeSnapshot(value);
        // Copy expectations before storage or crypto yields.
        expected = expected && {
            sender: expected.sender,
            contextID: expected.contextID,
            purpose: expected.purpose,
            groupID: expected.groupID,
            epoch: expected.epoch,
            generation: expected.generation,
        };
        const h = packet.header;
        if (
            h.suite !== GROUP_SUITE ||
            !h.group ||
            h.sender !== expected?.sender ||
            h.contextID !== expected?.contextID ||
            h.purpose !== expected?.purpose ||
            h.group.groupID !== expected?.groupID ||
            h.group.epoch !== expected?.epoch ||
            h.group.generation !== expected?.generation
        ) {
            throw engineError(
                'group envelope differs from independent expectations',
                'ENVELOPE_EXPECTATION_MISMATCH'
            );
        }
        const { record, header } = await this.stream(expected);
        if (
            header.senderFingerprint !== h.senderFingerprint ||
            header.receiverFingerprint !== h.receiverFingerprint
        )
            throw engineError(
                'group key generation or sender fingerprint mismatch',
                'DERIVATION_KEY_MISMATCH'
            );
        const key = await deriveGroupAES(record.key, h);
        return { header: h, bytes: await openBytes(key, packet) };
    }
}

/* global BigInt */

const REPLAY_WINDOW = 128;
const MASK = (1n << 128n) - 1n;
const emptyBitmap = '0'.repeat(32);
async function streamIdentity(header) {
    const g = header.group;
    const fields = [
        header.suite,
        header.contextID,
        header.sender,
        header.receiver,
        header.senderFingerprint,
        header.receiverFingerprint,
        header.purpose,
        g?.groupID || '',
        g?.epoch || '',
        g?.generation || '',
    ];
    const bytes = encodeFields(
        'BE8-REPLAY-STREAM',
        fields.map((value) => new TextEncoder().encode(value))
    );
    return encodeBase64url(await crypto.subtle.digest('SHA-256', bytes));
}
function contextRecord(record) {
    if (!record)
        throw engineError(
            'explicitly open the local context first',
            'CONTEXT_NOT_OPEN'
        );
    if (record.status === 'closed')
        throw engineError(
            'context is permanently closed; use a fresh context ID',
            'CONTEXT_CLOSED'
        );
    if (
        record.status !== 'open' ||
        !Array.isArray(record.streams) ||
        record.streams.length > 1024 ||
        !record.streams.every(
            (entry) =>
                entry &&
                typeof entry.streamID === 'string' &&
                /^[A-Za-z0-9_-]{43}$/.test(entry.streamID) &&
                ['send', 'receive'].includes(entry.direction)
        )
    )
        throw engineError('invalid context state', 'STATE_LOST');
    return record;
}
class Replay {
    constructor(keys) {
        this.keys = keys;
    }
    async openContext(contextID) {
        scalarString(contextID);
        return this.keys.run([STORES.contexts], 'readwrite', (tx) => {
            const store = tx.objectStore(STORES.contexts);
            return requestResult(
                store.get([this.keys.namespace, contextID]),
                (current) => {
                    if (current) {
                        contextRecord(current);
                        return { contextID, status: 'open' };
                    }
                    return requestResult(
                        store.add({
                            namespace: this.keys.namespace,
                            contextID,
                            status: 'open',
                            streams: [],
                        }),
                        () => ({ contextID, status: 'open' })
                    );
                }
            );
        });
    }
    async closeContext(contextID) {
        scalarString(contextID);
        return this.keys.run([STORES.contexts], 'readwrite', (tx) => {
            const store = tx.objectStore(STORES.contexts);
            return requestResult(
                store.get([this.keys.namespace, contextID]),
                (record) => {
                    if (!record)
                        throw engineError(
                            'context is not open',
                            'CONTEXT_NOT_OPEN'
                        );
                    if (record.status === 'closed') return;
                    contextRecord(record);
                    return requestResult(
                        store.put({ ...record, status: 'closed' })
                    );
                }
            );
        });
    }
    async initialize(header, direction) {
        const streamID = await streamIdentity(header);
        const name =
            direction === 'send' ? STORES.sendState : STORES.receiveState;
        return this.keys.run([STORES.contexts, name], 'readwrite', (tx) => {
            const contexts = tx.objectStore(STORES.contexts);
            const states = tx.objectStore(name);
            return requestResult(
                contexts.get([this.keys.namespace, header.contextID]),
                (value) => {
                    const context = contextRecord(value);
                    const known = context.streams.some(
                        (entry) =>
                            entry.streamID === streamID &&
                            entry.direction === direction
                    );
                    return requestResult(
                        states.get([
                            this.keys.namespace,
                            header.contextID,
                            streamID,
                        ]),
                        (state) => {
                            if (known) {
                                if (!state)
                                    throw engineError(
                                        'registered stream state is missing; no reset is allowed',
                                        'STATE_LOST'
                                    );
                                return streamID;
                            }
                            if (state || context.streams.length >= 1024)
                                throw engineError(
                                    'inconsistent or exhausted context state',
                                    'STATE_LOST'
                                );
                            const base = {
                                namespace: this.keys.namespace,
                                contextID: header.contextID,
                                streamID,
                            };
                            states.add(
                                direction === 'send'
                                    ? { ...base, last: '0' }
                                    : {
                                          ...base,
                                          highest: '0',
                                          bitmap: emptyBitmap,
                                      }
                            );
                            return requestResult(
                                contexts.put({
                                    ...context,
                                    streams: [
                                        ...context.streams,
                                        { streamID, direction },
                                    ],
                                }),
                                () => streamID
                            );
                        }
                    );
                }
            );
        });
    }
    async reserve(header) {
        const streamID = await this.initialize(header, 'send');
        return this.keys.run(
            [STORES.contexts, STORES.sendState],
            'readwrite',
            (tx) =>
                requestResult(
                    tx
                        .objectStore(STORES.contexts)
                        .get([this.keys.namespace, header.contextID]),
                    (context) => {
                        contextRecord(context);
                        const store = tx.objectStore(STORES.sendState);
                        return requestResult(
                            store.get([
                                this.keys.namespace,
                                header.contextID,
                                streamID,
                            ]),
                            (record) => {
                                if (!record)
                                    throw engineError(
                                        'send counter is missing',
                                        'STATE_LOST'
                                    );
                                const last = sequenceValue(record.last);
                                if (last === MAX_SEQUENCE)
                                    throw engineError(
                                        'uint64 send counter exhausted',
                                        'COUNTER_EXHAUSTED'
                                    );
                                const sequence = String(last + 1n);
                                return requestResult(
                                    store.put({ ...record, last: sequence }),
                                    () => sequence
                                );
                            }
                        );
                    }
                )
        );
    }
    async accept(header) {
        const streamID = await streamIdentity(header);
        return this.keys.run(
            [STORES.contexts, STORES.receiveState],
            'readwrite',
            (tx) =>
                requestResult(
                    tx
                        .objectStore(STORES.contexts)
                        .get([this.keys.namespace, header.contextID]),
                    (value) => {
                        const context = contextRecord(value);
                        if (
                            !context.streams.some(
                                (entry) =>
                                    entry.streamID === streamID &&
                                    entry.direction === 'receive'
                            )
                        )
                            throw engineError(
                                'explicitly initialize expected receive stream first',
                                'STREAM_NOT_OPEN'
                            );
                        const store = tx.objectStore(STORES.receiveState);
                        return requestResult(
                            store.get([
                                this.keys.namespace,
                                header.contextID,
                                streamID,
                            ]),
                            (record) => {
                                if (
                                    !record ||
                                    typeof record.bitmap !== 'string' ||
                                    !/^[0-9a-f]{32}$/.test(record.bitmap)
                                )
                                    throw engineError(
                                        'receive state is missing or invalid',
                                        'STATE_LOST'
                                    );
                                let highest = sequenceValue(record.highest);
                                let bitmap = BigInt('0x' + record.bitmap);
                                if (
                                    (highest < 128n &&
                                        bitmap >> highest !== 0n) ||
                                    (highest > 0n && !(bitmap & 1n))
                                )
                                    throw engineError(
                                        'invalid receive window',
                                        'STATE_LOST'
                                    );
                                const sequence = sequenceValue(header.sequence);
                                if (sequence > highest) {
                                    const distance = sequence - highest;
                                    bitmap =
                                        distance >= 128n
                                            ? 1n
                                            : ((bitmap << distance) | 1n) &
                                              MASK;
                                    highest = sequence;
                                } else {
                                    const distance = highest - sequence;
                                    if (distance >= 128n)
                                        throw engineError(
                                            'sequence is outside the replay window',
                                            'REPLAY_TOO_OLD'
                                        );
                                    const bit = 1n << distance;
                                    if (bitmap & bit)
                                        throw engineError(
                                            'sequence was already accepted',
                                            'REPLAY_DUPLICATE'
                                        );
                                    bitmap |= bit;
                                }
                                return requestResult(
                                    store.put({
                                        ...record,
                                        highest: String(highest),
                                        bitmap: bitmap
                                            .toString(16)
                                            .padStart(32, '0'),
                                    })
                                );
                            }
                        );
                    }
                )
        );
    }
}

class Be8 {
    static upgradeBe8Schema = upgradeBe8Schema;
    static STORES = STORES;
    static jwkThumbprint = jwkThumbprint;
    static V2_SUITE = V2_SUITE;
    static GROUP_SUITE = GROUP_SUITE;
    static encodeV2DerivationInfo = encodeV2DerivationInfo;
    static encodeBase64url = encodeBase64url;
    static decodeBase64url = decodeBase64url;
    static V2_LIMITS = V2_LIMITS;
    static encodeEnvelopeAAD = encodeEnvelopeAAD;
    static REPLAY_WINDOW = REPLAY_WINDOW;

    #keys;
    #envelopes;
    #replay;
    #groups;
    #accID;
    #setupPromise;
    #references = new WeakMap();
    #derivedKeys = new WeakMap();
    #generation = {};
    #guarded = new WeakMap();
    #panicPromise;
    #reinitializePromise;

    #invalidateLocal() {
        this.#generation = {};
        this.#references = new WeakMap();
        this.#derivedKeys = new WeakMap();
        this.#guarded = new WeakMap();
        this.#setupPromise = undefined;
    }
    #guard(method, args) {
        const generation = this.#generation;
        let original;
        try {
            this.#keys.assertActive();
            original = method.apply(this, args);
        } catch (error) {
            return Promise.reject(error);
        }
        if (this.#guarded.has(original)) return this.#guarded.get(original);
        const guarded = Promise.resolve(original).then(async (result) => {
            try {
                this.#keys.assertActive();
                if (generation !== this.#generation)
                    throw engineError(
                        'operation generation invalidated',
                        'ENGINE_LOCKED'
                    );
                await this.#keys.checkLifecycle();
                this.#keys.assertActive();
                if (generation !== this.#generation)
                    throw engineError(
                        'operation generation invalidated',
                        'ENGINE_LOCKED'
                    );
                return result;
            } catch (error) {
                if (result instanceof Uint8Array) result.fill(0);
                throw error;
            }
        });
        this.#guarded.set(original, guarded);
        return guarded;
    }

    constructor(accID, indexedDB, { namespace = accID } = {}) {
        this.#accID = accountID(accID);
        namespaceID(namespace);
        if (!indexedDB)
            throw engineError(
                'no indexedDB passed to the constructor',
                'DATABASE_NOT_READY'
            );
        this.#keys = new KeyStore(indexedDB, accID, namespace);
        this.#replay = new Replay(this.#keys);
        this.#envelopes = new Envelopes(this.#keys, this.#accID, this.#replay);
        this.#groups = new Groups(
            this.#keys,
            this.#envelopes,
            this.#replay,
            this.#accID
        );
        this.#keys.onLock = () => this.#invalidateLocal();
        // Guard every public async operation, including raw AES/archive/getters.
        // Invoke synchronously so each method snapshots caller inputs before yields.
        for (const name of Object.getOwnPropertyNames(Be8.prototype)) {
            if (
                ['constructor', 'getAccID', 'panic', 'reinitialize'].includes(
                    name
                )
            )
                continue;
            const method = Be8.prototype[name];
            Object.defineProperty(this, name, {
                value: (...args) => this.#guard(method, args),
            });
        }
    }

    setup(options = {}) {
        if (Object.keys(options).length) {
            return Promise.reject(
                engineError(
                    'use migratePrivateKeys() for explicit migration',
                    'PRIVATE_KEY_MIGRATION_REQUIRED'
                )
            );
        }
        if (this.#setupPromise) return this.#setupPromise;
        const pending = this.#initialize();
        this.#setupPromise = pending;
        const reset = () => {
            if (this.#setupPromise === pending) this.#setupPromise = undefined;
        };
        pending.then(reset, reset);
        return pending;
    }

    async #initialize() {
        await this.#ensureIdentity();
        return this.getCachedKeys();
    }

    async #ensureIdentity() {
        const current = await this.#keys.identity();
        if (current) return current;
        if (await this.#keys.legacyPresent()) {
            throw engineError(
                'explicit legacy identity migration required',
                'LEGACY_IDENTITY'
            );
        }
        return this.#keys.storeIdentity(await generatePair());
    }

    // References carry no key material and are usable only by this instance.
    #publicResult(publicKey, endpoint) {
        this.#keys.assertActive();
        const keyReference = Object.freeze({});
        this.#references.set(keyReference, {
            endpoint,
            x: publicKey.x,
            y: publicKey.y,
        });
        return { publicKey, keyReference };
    }

    async migratePrivateKeys(options) {
        return this.#keys.migratePrivateKeys(options);
    }

    getAccID() {
        return this.#accID;
    }

    // Read committed state instead of maintaining per-instance key caches.
    // Separate instances/tabs may mutate this namespace between calls.
    async hasGeneratedKeys() {
        return !!(await this.#keys.identity());
    }

    async hasKey(id) {
        const type = getTypeOfKey(id);
        if (type === 'channel') return false;
        if (type === 'group')
            throw engineError(
                'use hasLegacyGroupKey() for retained ECDH group records',
                'LEGACY_GROUP_API'
            );
        accountID(id);
        return id === this.#accID && !!(await this.#keys.identity());
    }

    async addPublicKeys(publicKeys = [], options = {}) {
        if (!Array.isArray(publicKeys))
            throw engineError('public keys must be an array', 'INVALID_KEY');
        await this.#keys.addPublicKeys(publicKeys, options);
    }

    async addPublicKey(
        accID,
        key,
        { expectedFingerprint, trust, tofu = false } = {}
    ) {
        await this.addPublicKeys([{ accID, publicKey: key }], {
            tofu,
            decisions: [{ peerID: accID, expectedFingerprint, trust }],
        });
    }

    async getPeerTrust(id) {
        return this.#keys.peerTrust(id);
    }
    async migratePublicKeyTrust() {
        return this.#keys.migratePublicKeyTrust();
    }
    async replacePublicKey(id, publicKey, confirmation) {
        return this.#keys.replacePublicKey(id, publicKey, confirmation);
    }

    async addGroupKeys() {
        throw engineError(
            'use symmetric group epochs or explicitly addLegacyGroupKeys for retained ECDH data',
            'LEGACY_GROUP_API'
        );
    }

    async addLegacyGroupKeys(group, groupKeys, options = {}) {
        if (!Array.isArray(groupKeys) || !groupKeys.length) {
            throw engineError(
                'group keys must be a nonempty array',
                'INVALID_KEY'
            );
        }
        await this.#keys.addGroupKeys(group, groupKeys, options);
    }

    async getMyPublicKey() {
        return this.#keys.myPublicKey();
    }
    async getCachedKeys() {
        return this.#keys.publicKeys();
    }
    async getCachedLegacyGroupKeys() {
        return this.#keys.groupKeys();
    }

    async getCachedLegacyGroupVersions(group) {
        groupID(group);
        const keys = await this.getCachedLegacyGroupKeys();
        return keys
            .filter((key) => key.groupID === group)
            .map((key) => key.version)
            .sort((a, b) => b - a);
    }

    async generateGroupKeys() {
        throw engineError(
            'new groups require createGroupEpoch()',
            'LEGACY_GROUP_API'
        );
    }

    async hasLegacyGroupKey(group, version) {
        return !!(await this.#keys.groupKey(group, version));
    }

    async getLegacyGroupKeyReference(group, version) {
        const id = groupID(group),
            v = groupVersion(version);
        const pair = await this.#keys.groupKey(id, v);
        if (!pair || !pair[1])
            throw engineError(
                'retained legacy private group key is missing',
                'INVALID_PRIVATE_KEY'
            );
        return this.#publicResult(pair[0], id + ':' + v);
    }

    async createGroupEpoch(group, epoch, recipients, options) {
        return this.#groups.create(group, epoch, recipients, options);
    }
    async importGroupEpoch(envelope, expected) {
        return this.#groups.import(envelope, expected);
    }
    async activateGroupEpoch(group, epoch, options) {
        return this.#groups.activate(group, epoch, options);
    }
    async getGroupEpochs(group) {
        return this.#groups.epochs(group);
    }
    async getActiveGroupEpoch(group) {
        return this.#groups.active(group);
    }
    async encryptGroupEnvelope(group, bytes, options) {
        return this.#groups.seal(group, bytes, options);
    }
    async decryptGroupEnvelope(envelope, expected) {
        return (await this.#groups.open(envelope, expected)).bytes;
    }
    async encryptGroupText(group, text, options) {
        return this.#groups.seal(group, encodeText(text), {
            ...groupOptions(options),
            purpose: 'data',
        });
    }
    async encryptGroupImage(group, image, options) {
        return this.#groups.seal(group, encodeText(image), {
            ...groupOptions(options),
            purpose: 'attachment',
        });
    }
    async decryptGroupText(envelope, expected) {
        if (expected?.purpose !== 'data')
            throw engineError('text purpose required', 'INVALID_PURPOSE');
        return decodeText((await this.#groups.open(envelope, expected)).bytes);
    }
    async decryptGroupImage(envelope, expected) {
        if (expected?.purpose !== 'attachment')
            throw engineError('attachment purpose required', 'INVALID_PURPOSE');
        return decodeText((await this.#groups.open(envelope, expected)).bytes);
    }
    async openReceiveGroupContext(expected) {
        return this.#groups.openReceive(expected);
    }
    async receiveGroupEnvelope(envelope, expected) {
        const result = await this.#groups.open(envelope, expected);
        await this.#replay.accept(result.header);
        return result.bytes;
    }
    async receiveGroupText(envelope, expected) {
        if (expected?.purpose !== 'data')
            throw engineError('text purpose required', 'INVALID_PURPOSE');
        const result = await this.#groups.open(envelope, expected);
        const text = decodeText(result.bytes);
        await this.#replay.accept(result.header);
        return text;
    }
    async receiveGroupImage(envelope, expected) {
        if (expected?.purpose !== 'attachment')
            throw engineError('attachment purpose required', 'INVALID_PURPOSE');
        const result = await this.#groups.open(envelope, expected);
        const text = decodeText(result.bytes);
        await this.#replay.accept(result.header);
        return text;
    }

    // Idempotent: never returns a private JWK or a private CryptoKey.
    async generatePrivAndPubKey() {
        const [publicKey] = await this.#ensureIdentity();
        return this.#publicResult(publicKey, this.#accID);
    }

    async #localPair(keyReference, legacy = false) {
        if (!keyReference)
            throw engineError(
                'no private key passed to getDerivedKey',
                'INVALID_PRIVATE_KEY'
            );
        const reference = this.#references.get(keyReference);
        if (!reference) {
            // Preserve precise private-JWK/extractability errors, but v2 cannot
            // bind actual local public coordinates from an arbitrary CryptoKey.
            privateCryptoKey(keyReference);
            throw engineError(
                'v2 requires an opaque local key reference',
                'INVALID_LOCAL_REFERENCE'
            );
        }
        if (reference.endpoint.startsWith('g') && !legacy)
            throw engineError(
                'ECDH group references are legacy-only',
                'LEGACY_GROUP_API'
            );
        const keys = await this.#keys.endpointKeys(
            reference.endpoint,
            reference.endpoint
        );
        if (
            !keys[0] ||
            keys[0].x !== reference.x ||
            keys[0].y !== reference.y
        ) {
            throw engineError(
                'local key reference is no longer valid',
                'KEY_REFERENCE_INVALID'
            );
        }
        return {
            endpoint: reference.endpoint,
            publicKey: keys[0],
            privateKey: keys[1],
        };
    }

    async createDerivationContext(publicKey, keyReference, options) {
        if (!publicKey)
            throw engineError(
                'no public key passed to getDerivedKey',
                'INVALID_KEY'
            );
        publicKey = keySnapshot(publicKey);
        const copied = options && {
            contextID: options.contextID,
            sender: options.sender,
            receiver: options.receiver,
            purpose: options.purpose,
        };
        if (
            (typeof copied?.sender === 'string' &&
                copied.sender.startsWith('g')) ||
            (typeof copied?.receiver === 'string' &&
                copied.receiver.startsWith('g'))
        )
            throw engineError(
                'ECDH group endpoints are legacy-only',
                'LEGACY_GROUP_API'
            );
        const local = await this.#localPair(keyReference);
        const derivation = await createV2Metadata(
            local.endpoint,
            local.publicKey,
            publicKey,
            copied
        );
        const key = await deriveV2AES(
            local.endpoint,
            local.publicKey,
            publicKey,
            local.privateKey,
            derivation
        );
        await this.#trackDerivedKey(key, local.endpoint, derivation);
        return { key, derivation };
    }

    async getDerivedKey(publicKey, keyReference, metadata) {
        if (!publicKey)
            throw engineError(
                'no public key passed to getDerivedKey',
                'INVALID_KEY'
            );
        publicKey = keySnapshot(publicKey);
        // Copy transferred metadata synchronously, before storage or crypto yields.
        const context = metadata ? derivationSnapshot(metadata) : undefined;
        if (
            context?.sender.startsWith('g') ||
            context?.receiver.startsWith('g')
        )
            throw engineError(
                'ECDH group contexts require an explicit legacy reader',
                'LEGACY_GROUP_API'
            );
        const local = await this.#localPair(keyReference);
        const key = await deriveV2AES(
            local.endpoint,
            local.publicKey,
            publicKey,
            local.privateKey,
            context
        );
        await this.#trackDerivedKey(key, local.endpoint, context);
        return key;
    }

    // Explicit, decrypt-only legacy KDF. Never selected after an auth failure.
    async getLegacyDerivedKey(publicKey, privateKey) {
        if (!publicKey)
            throw engineError(
                'no public key passed to legacy derivation',
                'INVALID_KEY'
            );
        publicKey = keySnapshot(publicKey);
        if (this.#references.has(privateKey))
            privateKey = (await this.#localPair(privateKey, true)).privateKey;
        await this.#keys.checkLifecycle();
        return deriveLegacyAES(publicKey, privateKey);
    }

    async #trackDerivedKey(key, localID, derivation) {
        const generation = this.#generation;
        const derivationID = await derivationUsageID(derivation);
        await this.#keys.checkLifecycle();
        this.#keys.assertActive();
        if (generation !== this.#generation)
            throw engineError(
                'derived key generation invalidated',
                'ENGINE_LOCKED'
            );
        this.#derivedKeys.set(key, {
            derivationID,
            sending: localID === derivation.sender,
        });
    }

    async #encryptBytes(key, bytes) {
        requireAES(key, 'encrypt');
        await this.#keys.checkLifecycle();
        const registered = this.#derivedKeys.get(key);
        if (registered) {
            if (!registered.sending)
                throw engineError(
                    'incoming directional key cannot encrypt; create a reverse context',
                    'INVALID_DERIVATION_CONTEXT'
                );
            // Reservation commits before generating a nonce or invoking AES.
            // Failure after commit consumes the reservation; never refund it.
            await this.#keys.reserveUsage(
                registered.derivationID,
                bytes.length
            );
        }
        return encryptPayload(key, bytes);
    }

    async encryptBytes(key, value) {
        requireAES(key, 'encrypt');
        return this.#encryptBytes(
            key,
            bytesSnapshot(value, V2_LIMITS.plaintextBytes)
        );
    }

    async decryptBytes(key, ciphertext, iv) {
        requireAES(key, 'decrypt');
        const payload = payloadSnapshot(ciphertext, iv);
        await this.#keys.checkLifecycle();
        return new Uint8Array(await decryptPayload(key, payload));
    }

    async encryptText(key, text = '') {
        requireAES(key, 'encrypt');
        return this.#encryptBytes(key, encodeText(text));
    }

    async decryptText(key, ciphertext, iv) {
        requireAES(key, 'decrypt');
        const payload = payloadSnapshot(ciphertext, iv);
        await this.#keys.checkLifecycle();
        return decodeText(await decryptPayload(key, payload));
    }

    async encryptImage(key, base64Image) {
        requireAES(key, 'encrypt');
        const packet = await this.#encryptBytes(key, encodeText(base64Image));
        return { cipherImage: packet.cipherText, iv: packet.iv };
    }

    async decryptImage(key, cipherImage, iv) {
        return this.decryptText(key, cipherImage, iv);
    }

    #simpleOptions(options = {}) {
        if (
            !options ||
            typeof options !== 'object' ||
            Array.isArray(options) ||
            Reflect.ownKeys(options).some((field) => field !== 'contextID')
        )
            throw engineError(
                'only contextID is an allowed convenience option',
                'INVALID_OPTIONS'
            );
        return { contextID: options.contextID };
    }

    async openContext(contextID) {
        return this.#replay.openContext(contextID);
    }
    async closeContext(contextID) {
        return this.#replay.closeContext(contextID);
    }
    async openReceiveContext(expected) {
        if (
            !expected ||
            expected.receiver !== this.#accID ||
            !['data', 'attachment'].includes(expected.purpose)
        )
            throw engineError(
                'independent receive expectations required',
                'ENVELOPE_EXPECTATION_REQUIRED'
            );
        expected = {
            sender: expected.sender,
            receiver: expected.receiver,
            contextID: expected.contextID,
            purpose: expected.purpose,
        };
        const [peer, privateKey, own] = await this.#keys.endpointKeys(
            expected.sender,
            expected.receiver,
            true
        );
        if (!peer || !privateKey)
            throw engineError(
                'receive endpoint keys are missing',
                'INVALID_KEY'
            );
        const metadata = {
            version: 2,
            suite: V2_SUITE,
            ...expected,
            senderFingerprint: await jwkThumbprint(peer),
            receiverFingerprint: await jwkThumbprint(own),
            group: null,
        };
        await this.#replay.openContext(expected.contextID);
        await this.#replay.initialize(metadata, 'receive');
    }
    async receiveEnvelope(envelope, expected) {
        if (!expected || !['data', 'attachment'].includes(expected.purpose))
            throw engineError(
                'data receive expectations required',
                'ENVELOPE_EXPECTATION_REQUIRED'
            );
        const opened = await this.#envelopes.open(envelope, expected);
        await this.#replay.accept(opened.header);
        return opened.bytes;
    }
    async receiveText(envelope, expected) {
        if (expected?.purpose !== 'data')
            throw engineError('text purpose expected', 'INVALID_PURPOSE');
        const opened = await this.#envelopes.open(envelope, expected);
        const result = decodeText(opened.bytes);
        await this.#replay.accept(opened.header);
        return result;
    }
    async receiveImage(envelope, expected) {
        if (expected?.purpose !== 'attachment')
            throw engineError('attachment purpose expected', 'INVALID_PURPOSE');
        const opened = await this.#envelopes.open(envelope, expected);
        const result = decodeText(opened.bytes);
        await this.#replay.accept(opened.header);
        return result;
    }

    async encryptEnvelope(sender, receiver, bytes, options) {
        if (
            options &&
            (typeof options !== 'object' ||
                Array.isArray(options) ||
                Reflect.ownKeys(options).some(
                    (field) => !['contextID', 'purpose'].includes(field)
                ))
        )
            throw engineError(
                'envelope options allow only contextID and purpose',
                'INVALID_OPTIONS'
            );
        if (!options || !['data', 'attachment'].includes(options.purpose))
            throw engineError('invalid envelope purpose', 'INVALID_PURPOSE');
        return this.#envelopes.seal(sender, receiver, bytes, {
            contextID: options.contextID,
            purpose: options.purpose,
        });
    }

    async decryptEnvelope(envelope, expected) {
        if (!expected || !['data', 'attachment'].includes(expected.purpose))
            throw engineError(
                'independent data envelope expectations required',
                'ENVELOPE_EXPECTATION_REQUIRED'
            );
        return (await this.#envelopes.open(envelope, expected)).bytes;
    }

    async encryptTextSimple(sender, receiver, text = '', options = {}) {
        const bytes = encodeText(text);
        const supplied = this.#simpleOptions(options).contextID;
        const contextID = supplied ?? crypto.randomUUID();
        if (supplied === undefined) await this.openContext(contextID);
        return this.encryptEnvelope(sender, receiver, bytes, {
            contextID,
            purpose: 'data',
        });
    }

    async decryptTextSimple(sender, receiver, envelope, options = {}) {
        const copied = envelopeSnapshot(envelope);
        const contextID =
            this.#simpleOptions(options).contextID ?? copied.header.contextID;
        return decodeText(
            await this.decryptEnvelope(
                { header: copied.header, ciphertext: copied.ciphertext },
                { sender, receiver, contextID, purpose: 'data' }
            )
        );
    }

    async encryptImageSimple(sender, receiver, image, options = {}) {
        const bytes = encodeText(image);
        const supplied = this.#simpleOptions(options).contextID;
        const contextID = supplied ?? crypto.randomUUID();
        if (supplied === undefined) await this.openContext(contextID);
        return this.encryptEnvelope(sender, receiver, bytes, {
            contextID,
            purpose: 'attachment',
        });
    }

    async decryptImageSimple(sender, receiver, envelope, options = {}) {
        const copied = envelopeSnapshot(envelope);
        const contextID =
            this.#simpleOptions(options).contextID ?? copied.header.contextID;
        return decodeText(
            await this.decryptEnvelope(
                { header: copied.header, ciphertext: copied.ciphertext },
                { sender, receiver, contextID, purpose: 'attachment' }
            )
        );
    }

    // Explicit read path for retained pre-envelope HKDF packets. No fallback;
    // historical UUID encoding is selected by a separate local option.
    async #unframedLegacy(
        sender,
        receiver,
        ciphertext,
        iv,
        derivation,
        purpose,
        options = {}
    ) {
        if (
            !options ||
            typeof options !== 'object' ||
            Array.isArray(options) ||
            Reflect.ownKeys(options).some(
                (field) => !['contextID', 'legacyUUID'].includes(field)
            ) ||
            (options.legacyUUID !== undefined &&
                typeof options.legacyUUID !== 'boolean')
        )
            throw engineError(
                'invalid explicit legacy read options',
                'INVALID_OPTIONS'
            );
        const contextID = options.contextID;
        const payload = payloadSnapshot(
            ciphertext,
            iv,
            options.legacyUUID === true
        );
        const metadata = derivationSnapshot(derivation);
        if (
            metadata.sender !== sender ||
            metadata.receiver !== receiver ||
            metadata.purpose !== purpose ||
            (contextID !== undefined && metadata.contextID !== contextID)
        )
            throw engineError(
                'legacy HKDF context mismatch',
                'INVALID_DERIVATION_CONTEXT'
            );
        const [peer, privateKey, own] = await this.#keys.endpointKeys(
            sender,
            receiver,
            true
        );
        if (!peer)
            throw engineError(
                'Missing public key for selected peer',
                'INVALID_KEY'
            );
        if (!privateKey)
            throw engineError(
                'Missing private key for local endpoint',
                'INVALID_PRIVATE_KEY'
            );
        const key = await deriveV2AES(
            receiver,
            own,
            peer,
            privateKey,
            metadata
        );
        return decodeText(await decryptPayload(key, payload));
    }
    async decryptTextUnframedLegacy(
        sender,
        receiver,
        ciphertext,
        iv,
        derivation,
        options = {}
    ) {
        return this.#unframedLegacy(
            sender,
            receiver,
            ciphertext,
            iv,
            derivation,
            'data',
            options
        );
    }
    async decryptImageUnframedLegacy(
        sender,
        receiver,
        ciphertext,
        iv,
        derivation,
        options = {}
    ) {
        return this.#unframedLegacy(
            sender,
            receiver,
            ciphertext,
            iv,
            derivation,
            'attachment',
            options
        );
    }

    async decryptTextLegacy(key, ciphertext, iv) {
        requireAES(key, 'decrypt');
        const payload = payloadSnapshot(ciphertext, iv, true);
        await this.#keys.checkLifecycle();
        return decodeText(await decryptPayload(key, payload));
    }

    async decryptImageLegacy(key, cipherImage, iv) {
        return this.decryptTextLegacy(key, cipherImage, iv);
    }

    async #legacySimple(sender, receiver, ciphertext, iv) {
        const payload = payloadSnapshot(ciphertext, iv, true);
        const [publicKey, privateKey] = await this.#keys.endpointKeys(
            sender,
            receiver,
            true
        );
        if (!publicKey)
            throw engineError(
                'Missing public key for selected peer',
                'INVALID_KEY'
            );
        if (!privateKey)
            throw engineError(
                'Missing private key for local endpoint',
                'INVALID_PRIVATE_KEY'
            );
        const key = await deriveLegacyAES(publicKey, privateKey);
        return decodeText(await decryptPayload(key, payload));
    }

    async decryptTextSimpleLegacy(sender, receiver, ciphertext, iv) {
        return this.#legacySimple(sender, receiver, ciphertext, iv);
    }

    async decryptImageSimpleLegacy(sender, receiver, cipherImage, iv) {
        return this.#legacySimple(sender, receiver, cipherImage, iv);
    }

    panic() {
        // Synchronous lock even if opening/deleting the database subsequently fails.
        this.#keys.lock();
        if (this.#panicPromise) return this.#panicPromise;
        const pending = this.#keys.invalidate();
        this.#panicPromise = pending;
        pending.catch(() => {
            if (this.#panicPromise === pending) this.#panicPromise = undefined;
        });
        return pending;
    }
    reinitialize() {
        if (this.#reinitializePromise) return this.#reinitializePromise;
        const pending = this.#reinitialize();
        this.#reinitializePromise = pending;
        const reset = () => {
            if (this.#reinitializePromise === pending)
                this.#reinitializePromise = undefined;
        };
        pending.then(reset, reset);
        return pending;
    }
    async #reinitialize() {
        this.#keys.lock();
        const generation = this.#generation;
        if (this.#panicPromise) await this.#panicPromise;
        const previous = await this.#keys.reinitializationState();
        const candidate = await generatePair();
        const next = await this.#keys.reinitialize(
            candidate,
            previous,
            () => generation === this.#generation
        );
        if (generation !== this.#generation)
            throw engineError('reinitialization invalidated', 'ENGINE_LOCKED');
        this.#keys.resume(next);
        this.#panicPromise = undefined;
        try {
            await this.#keys.checkLifecycle();
            return await this.getCachedKeys();
        } catch (error) {
            this.#keys.lock();
            throw error;
        }
    }
}

export {
    GROUP_SUITE,
    REPLAY_WINDOW,
    STORES,
    V2_LIMITS,
    V2_SUITE,
    decodeBase64url,
    Be8 as default,
    encodeBase64url,
    encodeEnvelopeAAD,
    encodeV2DerivationInfo,
    jwkThumbprint,
    upgradeBe8Schema,
};
