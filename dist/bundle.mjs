// generates an Initialization vector
function generateIV() {
    // a nonce (number once) is an arbitrary string that can be used just once in a cryptographic communication
    const nonce = self.crypto.randomUUID();
    return new TextEncoder().encode(nonce);
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';

    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    return window.btoa(binary);
}

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
            if (name !== STORES.scopes) {
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

const ecdh = Object.freeze({ name: 'ECDH', namedCurve: 'P-384' });
const usages = Object.freeze(['deriveKey']);

// Copy only key fields: embedded caller metadata cannot replace storage IDs.
function keySnapshot(key, allowPrivate = false) {
    try {
        if (
            !key ||
            typeof key !== 'object' ||
            Array.isArray(key) ||
            key.kty !== 'EC' ||
            key.crv !== 'P-384' ||
            typeof key.x !== 'string' ||
            !key.x ||
            typeof key.y !== 'string' ||
            !key.y ||
            typeof key.ext !== 'boolean' ||
            !Array.isArray(key.key_ops) ||
            !key.key_ops.every((op) => typeof op === 'string') ||
            (key.d !== undefined &&
                (!allowPrivate || typeof key.d !== 'string' || !key.d))
        ) {
            throw engineError('invalid key data', 'INVALID_KEY');
        }
        const snapshot = {
            kty: key.kty,
            crv: key.crv,
            x: key.x,
            y: key.y,
            ext: key.ext,
            key_ops: [...key.key_ops],
        };
        if (allowPrivate && key.d !== undefined) snapshot.d = key.d;
        return snapshot;
    } catch {
        throw engineError('invalid key data', 'INVALID_KEY');
    }
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
        key.usages[0] !== 'deriveKey'
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

async function deriveAES(publicJWK, privateKey) {
    const pub = keySnapshot(publicJWK);
    const priv = privateCryptoKey(privateKey);
    let imported;
    try {
        imported = await crypto.subtle.importKey('jwk', pub, ecdh, true, []);
    } catch {
        throw engineError('invalid public ECDH key', 'INVALID_KEY');
    }
    return crypto.subtle.deriveKey(
        { name: 'ECDH', public: imported },
        priv,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
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
            priv,
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

class KeyStore {
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
            this.#checkOwner(record);
            if (!record && write)
                scopes.add({ namespace: this.namespace, accID: this.accID });
            return work(tx);
        });
    }

    run(stores, mode, work) {
        return withTransaction(
            this.connection,
            [STORES.scopes, ...new Set(stores)],
            mode,
            (tx) => this.#scope(tx, mode === 'readwrite', work)
        );
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

    async addPublicKeys(entries) {
        let copied;
        try {
            copied = entries.map(({ accID, publicKey }) => ({
                accID: accountID(accID),
                key: keySnapshot(publicKey),
            }));
        } catch {
            throw engineError('invalid public-key entries', 'INVALID_KEY');
        }
        return this.run(
            [STORES.publicKeys, STORES.privateKeys],
            'readwrite',
            (tx) => {
                const store = tx.objectStore(STORES.publicKeys);
                return requestResult(
                    tx
                        .objectStore(STORES.privateKeys)
                        .get([this.namespace, this.accID]),
                    (own) => {
                        for (const entry of copied) {
                            if (
                                entry.accID === this.accID &&
                                own &&
                                !samePublic(
                                    entry.key,
                                    own.publicKey || publicPart(own.key)
                                )
                            ) {
                                throw engineError(
                                    'cannot replace the public half of an existing identity',
                                    'IDENTITY_CONFLICT'
                                );
                            }
                        }
                        return Promise.all(
                            copied.map((entry) =>
                                requestResult(
                                    store.put({
                                        namespace: this.namespace,
                                        accID: entry.accID,
                                        key: entry.key,
                                    })
                                )
                            )
                        ).then(() => undefined);
                    }
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

    async addGroupKeys(id, entries) {
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
        return this.run([STORES.groupKeys], 'readwrite', (tx) => {
            const store = tx.objectStore(STORES.groupKeys);
            // Chain native success events to validate each immutable version,
            // including repeated versions within the same caller batch.
            const putNext = (index) => {
                if (index === copied.length) return undefined;
                const { version, key } = copied[index];
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
                    return requestResult(
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
                });
            };
            return putNext(0);
        });
    }

    async createGroup(id, version, pair) {
        const group = groupID(id);
        const v = groupVersion(version);
        return this.run([STORES.groupKeys], 'readwrite', (tx) => {
            const store = tx.objectStore(STORES.groupKeys);
            return requestResult(
                store.get([this.namespace, group, v]),
                (existing) => {
                    if (existing) {
                        const pair = groupPair(existing);
                        if (!pair[1])
                            throw engineError(
                                'existing group key has no private half',
                                'GROUP_CONFLICT'
                            );
                        return pair;
                    }
                    return requestResult(
                        store.add({
                            namespace: this.namespace,
                            groupID: group,
                            version: v,
                            key: pair[0],
                            privateKey: pair[1],
                        }),
                        () => pair
                    );
                }
            );
        });
    }

    async endpointKeys(publicID, privateID) {
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
        if (priv.store === STORES.publicKeys) priv.store = STORES.privateKeys;
        return this.run([pub.store, priv.store], 'readonly', (tx) =>
            Promise.all([
                requestResult(
                    tx.objectStore(pub.store).get(pub.key),
                    (record) => (record ? publicPart(record.key) : undefined)
                ),
                // Only this scope's account private identity may ever be selected.
                priv.store === STORES.privateKeys && privateID !== this.accID
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
            ])
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

    async clear() {
        await this.run(
            [STORES.publicKeys, STORES.privateKeys, STORES.groupKeys],
            'readwrite',
            (tx) =>
                Promise.all(
                    [
                        STORES.publicKeys,
                        STORES.privateKeys,
                        STORES.groupKeys,
                    ].map((name) => {
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
                    })
                )
        );
        // The namespace/account binding is retained; unrelated accounts and
        // application stores, including legacy records, are never cleared.
    }
}

class Be8 {
    static upgradeBe8Schema = upgradeBe8Schema;
    static STORES = STORES;

    #keys;
    #accID;
    #setupPromise;
    #references = new WeakMap();

    constructor(accID, indexedDB, { namespace = accID } = {}) {
        this.#accID = accountID(accID);
        namespaceID(namespace);
        if (!indexedDB)
            throw engineError(
                'no indexedDB passed to the constructor',
                'DATABASE_NOT_READY'
            );
        this.#keys = new KeyStore(indexedDB, accID, namespace);
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
        if (type === 'group') {
            const [group, version, extra] = id.split(':');
            if (extra !== undefined)
                throw engineError('invalid group identifier', 'INVALID_GROUP');
            return !!(await this.#keys.groupKey(group, version));
        }
        accountID(id);
        return id === this.#accID && !!(await this.#keys.identity());
    }

    async addPublicKeys(publicKeys = []) {
        if (!Array.isArray(publicKeys))
            throw engineError('public keys must be an array', 'INVALID_KEY');
        await this.#keys.addPublicKeys(publicKeys);
    }

    async addPublicKey(accID, key) {
        await this.addPublicKeys([{ accID, publicKey: key }]);
    }

    async addGroupKeys(group, groupKeys) {
        if (!Array.isArray(groupKeys) || !groupKeys.length) {
            throw engineError(
                'group keys must be a nonempty array',
                'INVALID_KEY'
            );
        }
        await this.#keys.addGroupKeys(group, groupKeys);
    }

    async getMyPublicKey() {
        return this.#keys.myPublicKey();
    }
    async getCachedKeys() {
        return this.#keys.publicKeys();
    }
    async getCachedGroupKeys() {
        return this.#keys.groupKeys();
    }

    async getCachedGroupVersions(group) {
        groupID(group);
        const keys = await this.getCachedGroupKeys();
        return keys
            .filter((key) => key.groupID === group)
            .map((key) => key.version)
            .sort((a, b) => b - a);
    }

    async generateGroupKeys(version, group) {
        const v = groupVersion(version);
        const id = groupID(group);
        let pair = await this.#keys.groupKey(id, v);
        if (pair && !pair[1])
            throw engineError(
                'existing group key has no private half',
                'GROUP_CONFLICT'
            );
        if (!pair)
            pair = await this.#keys.createGroup(id, v, await generatePair());
        return this.#publicResult(pair[0], id + ':' + v);
    }

    // Idempotent: never returns a private JWK or a private CryptoKey.
    async generatePrivAndPubKey() {
        const [publicKey] = await this.#ensureIdentity();
        return this.#publicResult(publicKey, this.#accID);
    }

    async getDerivedKey(publicKey, privateKey) {
        if (!publicKey)
            throw engineError(
                'no public key passed to getDerivedKey',
                'INVALID_KEY'
            );
        if (!privateKey)
            throw engineError(
                'no private key passed to getDerivedKey',
                'INVALID_PRIVATE_KEY'
            );
        const reference = this.#references.get(privateKey);
        if (reference) {
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
            privateKey = keys[1];
        }
        return deriveAES(publicKey, privateKey);
    }

    async encryptText(derivedKey, text = '') {
        const encodedText = new TextEncoder().encode(text);
        const iv = generateIV();
        const stringifiedIV = new TextDecoder().decode(iv);
        const algorithm = {
            name: 'AES-GCM',
            iv,
        };

        if (!derivedKey) {
            throw new Error('engine: no derived key passed to encryptText');
        }

        return window.crypto.subtle
            .encrypt(algorithm, derivedKey, encodedText)
            .then(function (encryptedData) {
                const uintArray = new Uint8Array(encryptedData);
                const string = String.fromCharCode.apply(null, uintArray);
                const cipherText = window.btoa(string);

                return { cipherText, iv: stringifiedIV };
            });
    }

    async decryptText(derivedKey, cipherText = '', iv) {
        const mstring = window.atob(cipherText);
        const uintArray = new Uint8Array(
            [...mstring].map((char) => char.charCodeAt(0))
        );
        const parsedIV = new TextEncoder('utf-8').encode(iv);
        const algorithm = {
            name: 'AES-GCM',
            iv: parsedIV,
        };

        if (!derivedKey) {
            throw new Error('engine: no derived key passed to decryptText');
        }
        if (!iv) {
            throw new Error(
                'engine: no iv (Initialization vector) passed to decryptText'
            );
        }

        return window.crypto.subtle
            .decrypt(algorithm, derivedKey, uintArray)
            .then(function (decryptedData) {
                return new TextDecoder().decode(decryptedData);
            });
    }

    async encryptTextSimple(accIDSender, accIDReceiver, text) {
        const [publicKey, privateKey] = await this.#keys.endpointKeys(
            accIDReceiver,
            accIDSender
        );

        if (!publicKey) {
            throw new Error(
                `engine: Missing public key for ${accIDReceiver} at encryptTextSimple`
            );
        }
        if (!privateKey) {
            throw new Error(
                `engine: Missing private key for ${accIDSender} at encryptTextSimple`
            );
        }

        const derivedKey = await this.getDerivedKey(publicKey, privateKey);

        return await this.encryptText(derivedKey, text);
    }

    async decryptTextSimple(accIDSender, accIDReceiver, cipherText, iv) {
        const [publicKey, privateKey] = await this.#keys.endpointKeys(
            accIDSender,
            accIDReceiver
        );

        if (!publicKey) {
            throw new Error(
                `engine: Missing public key for ${accIDSender} at decryptTextSimple`
            );
        }
        if (!privateKey) {
            throw new Error(
                `engine: Missing private key for ${accIDReceiver} at decryptTextSimple`
            );
        }

        const derivedKey = await this.getDerivedKey(publicKey, privateKey);

        return await this.decryptText(derivedKey, cipherText, iv);
    }

    async encryptImage(derivedKey, base64Image) {
        const encodedText = new TextEncoder().encode(base64Image);
        const iv = generateIV();
        const stringifiedIV = new TextDecoder().decode(iv);

        if (!derivedKey) {
            throw new Error('engine: no derived key passed to decryptText');
        }

        return window.crypto.subtle
            .encrypt({ name: 'AES-GCM', iv }, derivedKey, encodedText)
            .then(function (encryptedData) {
                return {
                    cipherImage: arrayBufferToBase64(encryptedData),
                    iv: stringifiedIV,
                };
            });
    }

    async decryptImage(derivedKey, cipherImage, iv) {
        const mstring = window.atob(cipherImage);
        const uintArray = new Uint8Array(
            [...mstring].map((char) => char.charCodeAt(0))
        );
        const parsedIV = new TextEncoder('utf-8').encode(iv);
        const algorithm = {
            name: 'AES-GCM',
            iv: parsedIV,
        };

        if (!derivedKey) {
            throw new Error('engine: no derived key passed to decryptText');
        }

        return window.crypto.subtle
            .decrypt(algorithm, derivedKey, uintArray)
            .then(function (decryptedData) {
                return new TextDecoder().decode(decryptedData);
            });
    }

    async encryptImageSimple(accIDSender, accIDReceiver, base64Image) {
        const [publicKey, privateKey] = await this.#keys.endpointKeys(
            accIDReceiver,
            accIDSender
        );

        if (!publicKey) {
            throw new Error(
                `engine: Missing public key for ${accIDSender} at encryptImageSimple`
            );
        }
        if (!privateKey) {
            throw new Error(
                `engine: Missing private key for ${accIDReceiver} at encryptImageSimple`
            );
        }

        const derivedKey = await this.getDerivedKey(publicKey, privateKey);

        return await this.encryptImage(derivedKey, base64Image);
    }

    async decryptImageSimple(accIDSender, accIDReceiver, cipherImage, iv) {
        const [publicKey, privateKey] = await this.#keys.endpointKeys(
            accIDSender,
            accIDReceiver
        );

        if (!publicKey) {
            throw new Error(
                `engine: Missing public key for ${accIDSender} at decryptImageSimple`
            );
        }
        if (!privateKey) {
            throw new Error(
                `engine: Missing private key for ${accIDReceiver} at decryptImageSimple`
            );
        }

        const derivedKey = await this.getDerivedKey(publicKey, privateKey);

        return await this.decryptImage(derivedKey, cipherImage, iv);
    }

    async panic() {
        await this.#keys.clear();
    }
}

export { STORES, Be8 as default, upgradeBe8Schema };
