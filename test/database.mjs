// Observe real IndexedDB requests and transactions. Do not add a synthetic
// transaction.complete property or change the engine's persistence semantics.
import { upgradeBe8Schema, STORES } from '../lib/bundle.mjs';

export async function openDatabase(name = 'be8-test-' + crypto.randomUUID(), options = {}) {
    const request = indexedDB.open(name, options.version || 1);
    let upgradeFailed = false;
    request.addEventListener('upgradeneeded', () => {
        const db = request.result;
        try {
            if (!options.skipEngineSchema) upgradeBe8Schema(db, request.transaction);
            if (options.upgrade) options.upgrade(db, request.transaction);
        } catch {
            upgradeFailed = true;
            try { request.transaction.abort(); } catch { /* Already aborted. */ }
        }
    });
    const db = await new Promise((resolve, reject) => {
        request.addEventListener('success', () => resolve(request.result), { once: true });
        request.addEventListener('error', () => reject(new Error(upgradeFailed ? 'Test database upgrade failed' : 'Test database open failed')), { once: true });
        request.addEventListener('blocked', () => reject(new Error('Test database open blocked')), { once: true });
    });
    const pending = new Set();
    let failures = 0;
    let observer;

    function transaction(...args) {
        const tx = db.transaction(...args);
        const record = { mode: tx.mode };
        record.done = new Promise(resolve => {
            tx.addEventListener('complete', () => {
                pending.delete(record);
                resolve();
            }, { once: true });
            tx.addEventListener('abort', () => {
                failures++;
                pending.delete(record);
                resolve();
            }, { once: true });
        });
        pending.add(record);
        if (observer) observer(tx);
        return tx;
    }

    return {
        name,
        // All returned transactions and requests are native browser objects.
        connection: { result: { transaction, objectStoreNames: db.objectStoreNames } },
        native: db,
        observe: callback => { observer = callback; },
        acknowledgeAborts: () => { const count = failures; failures = 0; return count; },
        transaction,
        pendingWrites: () => [...pending].filter(record => record.mode === 'readwrite').length,
        async whenIdle() {
            while (pending.size) {
                await Promise.all([...pending].map(record => record.done));
            }
            if (failures) {
                throw new Error('Test database transaction aborted');
            }
        },
        close: () => db.close(),
    };
}

export function requestResult(request) {
    return new Promise((resolve, reject) => {
        request.addEventListener('success', () => resolve(request.result), { once: true });
        request.addEventListener('error', () => reject(new Error('Test database request failed')), { once: true });
    });
}

export async function readRecord(database, store, key) {
    const name = STORES[store] || store;
    const tx = database.transaction(name, 'readonly');
    const scopedKey = STORES[store] && !Array.isArray(key) ? [key, key] : key;
    const value = await requestResult(tx.objectStore(name).get(scopedKey));
    await database.whenIdle();
    return STORES[store] ? value?.key : value;
}

export async function storedIDs(database, store = 'privateKeys', namespace) {
    const name = STORES[store] || store;
    const tx = database.transaction(name, 'readonly');
    const objectStore = tx.objectStore(name);
    const request = namespace === undefined ? objectStore.getAllKeys() : objectStore.index('namespace').getAllKeys(namespace);
    const ids = await requestResult(request);
    await database.whenIdle();
    return STORES[store] ? ids.map(key => key[1]) : ids;
}

export async function deleteDatabase(name) {
    const request = indexedDB.deleteDatabase(name);
    await new Promise((resolve, reject) => {
        request.addEventListener('success', resolve, { once: true });
        request.addEventListener('error', () => reject(new Error('Test database deletion failed')), { once: true });
        request.addEventListener('blocked', () => reject(new Error('Test database deletion blocked')), { once: true });
    });
}
