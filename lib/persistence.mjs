export const STORES = Object.freeze({
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
export function upgradeBe8Schema(db, transaction) {
    if (transaction?.mode !== 'versionchange' || transaction.db !== db) {
        throw engineError('schema integration requires a versionchange transaction', 'SCHEMA_ERROR');
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
        }
    } catch {
        try { transaction.abort(); } catch { /* Already aborted. */ }
        throw engineError('schema integration failed; upgrade aborted', 'SCHEMA_ERROR');
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
