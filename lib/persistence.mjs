import { BE8_STORES } from './legacy-be8.mjs';
export const STORES = Object.freeze({
    scopes: 'be9.scopes',
    publicKeys: 'be9.publicKeys',
    privateKeys: 'be9.privateKeys',
    groupKeys: 'be9.groupKeys',
    groupEpochs: 'be9.groupEpochs',
    activeEpochs: 'be9.activeEpochs',
    trust: 'be9.trust',
    keyUsage: 'be9.keyUsage',
    contexts: 'be9.contexts',
    sendState: 'be9.sendState',
    receiveState: 'be9.receiveState',
    signingKeys: 'be9.signingKeys',
    signingTrust: 'be9.signingTrust',
    sessionRegistry: 'be9.sessionRegistry',
    sessions: 'be9.sessions',
    ratchetState: 'be9.ratchetState',
    skippedKeys: 'be9.skippedKeys',
});

export function engineError(message, code = 'INVALID_STATE') {
    const error = new Error('engine: ' + message);
    error.code = code;
    return error;
}

function databaseError(error) {
    const failure = error?.name === 'DataCloneError'
        ? engineError('browser cannot store CryptoKeys; CryptoKey structured clone support is required', 'CRYPTOKEY_STORAGE_UNSUPPORTED')
        : engineError('IndexedDB operation failed', 'PERSISTENCE_ERROR');
    const names = ['AbortError', 'ConstraintError', 'DataCloneError', 'DataError',
        'InvalidStateError', 'NotFoundError', 'QuotaExceededError', 'ReadOnlyError',
        'TransactionInactiveError', 'UnknownError', 'VersionError'];
    failure.name = names.includes(error?.name) ? error.name : 'PersistenceError';
    return failure;
}

export function databaseConnection(connection) {
    try {
        const db = typeof connection?.transaction === 'function' ? connection : connection?.result;
        if (typeof db?.transaction !== 'function') {
            throw engineError('database connection is not ready', 'DATABASE_NOT_READY');
        }
        return db;
    } catch {
        throw engineError('database connection is not ready', 'DATABASE_NOT_READY');
    }
}

// Must be called synchronously by the application's onupgradeneeded handler.
// Only engine-owned stores are created. Existing stores and records are retained.
export function upgradeBe9Schema(db, transaction) {
    if (transaction?.mode !== 'versionchange' || transaction.db !== db) {
        throw engineError('schema integration requires a versionchange transaction', 'SCHEMA_ERROR');
    }
    try { requireBe9Schema(db); } catch (error) { transaction.abort(); throw error; }
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
        [STORES.signingKeys, ['namespace', 'accID']],
        [STORES.signingTrust, ['namespace', 'peerID']],
        [STORES.sessionRegistry, ['namespace', 'sessionID']],
        [STORES.sessions, ['namespace', 'sessionID']],
        [STORES.ratchetState, ['namespace', 'sessionID']],
        [STORES.skippedKeys, ['namespace', 'sessionID', 'chain', 'number']],
    ];
    try {
        for (const [name, keyPath] of definitions) {
            const store = db.objectStoreNames.contains(name)
                ? transaction.objectStore(name) : db.createObjectStore(name, { keyPath });
            if (JSON.stringify(store.keyPath) !== JSON.stringify(keyPath) || store.autoIncrement) {
                throw engineError('incompatible engine store schema', 'SCHEMA_ERROR');
            }
            if (name !== STORES.scopes && name !== STORES.keyUsage) {
                if (!store.indexNames.contains('namespace')) {
                    store.createIndex('namespace', 'namespace');
                }
                const index = store.index('namespace');
                if (index.keyPath !== 'namespace' || index.unique || index.multiEntry) {
                    throw engineError('incompatible engine index schema', 'SCHEMA_ERROR');
                }
            }
            if (name === STORES.skippedKeys) {
                if (!store.indexNames.contains('session')) store.createIndex('session', ['namespace', 'sessionID']);
                const session = store.index('session');
                if (JSON.stringify(session.keyPath) !== JSON.stringify(['namespace', 'sessionID']) || session.unique || session.multiEntry) throw engineError('incompatible session index', 'SCHEMA_ERROR');
            }
        }
    } catch {
        try { transaction.abort(); } catch { /* Already aborted. */ }
        throw engineError('schema integration failed; upgrade aborted', 'SCHEMA_ERROR');
    }
}

// Explicit integration into the application's own version upgrade. Renaming
// IDBObjectStore.name preserves records, indexes and CryptoKeys atomically;
// abort restores all original names. No merge, deletion, export or key rotation.
export function requireBe9Schema(connection) {
    const db = databaseConnection(connection);
    if (Object.values(BE8_STORES).some(name => db.objectStoreNames.contains(name))) {
        throw engineError('explicit migrateBe8Schema() is required before using Be9 stores', 'LEGACY_SCHEMA_MIGRATION_REQUIRED');
    }
}
export function migrateBe8Schema(db, transaction) {
    if (transaction?.mode !== 'versionchange' || transaction.db !== db) throw engineError('migration requires an application versionchange transaction', 'SCHEMA_ERROR');
    try {
        const names = Object.keys(BE8_STORES).filter(key => db.objectStoreNames.contains(BE8_STORES[key]));
        // Validate all conflicts first; even empty target stores must not be
        // silently replaced. The caller resolves conflicts explicitly.
        if (names.some(key => db.objectStoreNames.contains(STORES[key]))) throw engineError('both legacy and current engine stores exist; explicit conflict resolution required', 'SCHEMA_MIGRATION_CONFLICT');
        for (const key of names) transaction.objectStore(BE8_STORES[key]).name = STORES[key];
        upgradeBe9Schema(db, transaction);
        return { migratedStores: names.length };
    } catch (error) {
        try { transaction.abort(); } catch { /* Already terminal. */ }
        throw error?.code === 'SCHEMA_MIGRATION_CONFLICT' ? error : engineError('legacy schema migration failed; upgrade aborted', 'SCHEMA_ERROR');
    }
}

// A successful request is not a successful transaction. The callback may only
// schedule further native requests synchronously in this success event.
export function requestResult(request, consume = value => value) {
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
                reject(error instanceof Error && typeof error.code === 'string' ? error : databaseError(error));
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

export function transactionComplete(tx) {
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
        const error = event => {
            failed = databaseError(event.target.error || tx.error);
            // Even if another listener prevents the request's default abort,
            // this operation must roll back instead of reporting partial success.
            try { tx.abort(); } catch { /* A terminal event will settle the promise. */ }
        };
        tx.addEventListener('complete', complete, { once: true });
        tx.addEventListener('error', error);
        tx.addEventListener('abort', abort, { once: true });
    });
}

// operation must schedule requests immediately; no crypto, timers or unrelated
// asynchronous work may run while a transaction is open.
export async function withTransaction(connection, stores, mode, operation) {
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
    const requested = Promise.resolve(result).catch(error => {
        try { tx.abort(); } catch { /* Already complete or aborted. */ }
        throw error instanceof Error && typeof error.code === 'string' ? error : databaseError(error);
    });
    const [work, commit] = await Promise.allSettled([requested, completed]);
    if (work.status === 'rejected') throw work.reason;
    if (commit.status === 'rejected') throw commit.reason;
    return work.value;
}
