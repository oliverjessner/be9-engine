// Observe real IndexedDB requests and transactions. Do not add a synthetic
// transaction.complete property or change the engine's persistence semantics.
export async function openDatabase(name = 'be8-test-' + crypto.randomUUID()) {
    const request = indexedDB.open(name, 1);
    request.addEventListener('upgradeneeded', () => {
        const db = request.result;
        db.createObjectStore('publicKeys', { keyPath: 'accID' });
        db.createObjectStore('privateKeys', { keyPath: 'accID' });
        db.createObjectStore('groupKeys', { keyPath: ['groupID', 'version'] });
    });
    const db = await new Promise((resolve, reject) => {
        request.addEventListener('success', () => resolve(request.result), { once: true });
        request.addEventListener('error', () => reject(new Error('Test database open failed')), { once: true });
        request.addEventListener('blocked', () => reject(new Error('Test database open blocked')), { once: true });
    });
    const pending = new Set();
    let failed = false;

    function transaction(...args) {
        const tx = db.transaction(...args);
        const record = { mode: tx.mode };
        record.done = new Promise(resolve => {
            tx.addEventListener('complete', () => {
                pending.delete(record);
                resolve();
            }, { once: true });
            tx.addEventListener('abort', () => {
                failed = true;
                pending.delete(record);
                resolve();
            }, { once: true });
        });
        pending.add(record);
        return tx;
    }

    return {
        name,
        // All returned transactions and requests are native browser objects.
        connection: { result: { transaction } },
        transaction,
        pendingWrites: () => [...pending].filter(record => record.mode === 'readwrite').length,
        async whenIdle() {
            while (pending.size) {
                await Promise.all([...pending].map(record => record.done));
            }
            if (failed) {
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
    const tx = database.transaction(store, 'readonly');
    const value = await requestResult(tx.objectStore(store).get(key));
    await database.whenIdle();
    return value;
}

export async function storedIDs(database, store = 'privateKeys') {
    const tx = database.transaction(store, 'readonly');
    const ids = await requestResult(tx.objectStore(store).getAllKeys());
    await database.whenIdle();
    return ids;
}

export async function deleteDatabase(name) {
    const request = indexedDB.deleteDatabase(name);
    await new Promise((resolve, reject) => {
        request.addEventListener('success', resolve, { once: true });
        request.addEventListener('error', () => reject(new Error('Test database deletion failed')), { once: true });
        request.addEventListener('blocked', () => reject(new Error('Test database deletion blocked')), { once: true });
    });
}
