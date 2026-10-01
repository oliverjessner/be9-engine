import {
    STORES, engineError, databaseConnection, requestResult, withTransaction,
} from './persistence.mjs';

export function accountID(id) {
    if (typeof id !== 'string' || !/^(0|[1-9][0-9]*)$/.test(id)) {
        throw engineError('no acc id or wrong type passed to the constructor', 'INVALID_ACCOUNT');
    }
    return id;
}

export function namespaceID(namespace) {
    if (typeof namespace !== 'string' || !namespace.length || namespace !== namespace.trim()
        || [...namespace].some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)) {
        throw engineError('invalid namespace', 'INVALID_NAMESPACE');
    }
    return namespace;
}

export function groupID(id) {
    if (typeof id !== 'string' || !/^g[A-Za-z0-9_-]+$/.test(id)) {
        throw engineError('invalid group identifier', 'INVALID_GROUP');
    }
    return id;
}

export function groupVersion(version) {
    if (typeof version === 'string' && /^[1-9][0-9]*$/.test(version)) version = Number(version);
    if (!Number.isSafeInteger(version) || version < 1) {
        throw engineError('invalid group version', 'INVALID_GROUP');
    }
    return version;
}

// Copy only JWK fields. Untrusted embedded metadata can never choose a storage
// key or override separately supplied account, namespace, group or version data.
export function keySnapshot(key, allowPrivate = false) {
    try {
        if (!key || typeof key !== 'object' || Array.isArray(key)
            || key.kty !== 'EC' || key.crv !== 'P-384'
            || typeof key.x !== 'string' || !key.x || typeof key.y !== 'string' || !key.y
            || typeof key.ext !== 'boolean' || !Array.isArray(key.key_ops)
            || !key.key_ops.every(op => typeof op === 'string')
            || (key.d !== undefined && (!allowPrivate || typeof key.d !== 'string' || !key.d))) {
            throw engineError('invalid key data', 'INVALID_KEY');
        }
        const snapshot = {
            kty: key.kty, crv: key.crv, x: key.x, y: key.y,
            ext: key.ext, key_ops: [...key.key_ops],
        };
        if (allowPrivate && key.d !== undefined) snapshot.d = key.d;
        return snapshot;
    } catch {
        throw engineError('invalid key data', 'INVALID_KEY');
    }
}

export function publicPart(key) {
    const { d: ignored, ...publicKey } = keySnapshot(key, true);
    void ignored;
    publicKey.key_ops = [];
    return publicKey;
}

function samePublic(left, right) {
    return left.kty === right.kty && left.crv === right.crv && left.x === right.x && left.y === right.y;
}

function identityPair(publicRecord, privateRecord) {
    if (!publicRecord && !privateRecord) return null;
    if (!publicRecord || !privateRecord) {
        throw engineError('incomplete identity; existing keys are retained', 'INCOMPLETE_IDENTITY');
    }
    const publicKey = keySnapshot(publicRecord.key);
    const privateKey = keySnapshot(privateRecord.key, true);
    if (!privateKey.d || !samePublic(publicKey, privateKey)) {
        throw engineError('inconsistent identity; existing keys are retained', 'INCOMPLETE_IDENTITY');
    }
    return [publicKey, privateKey];
}

export class KeyStore {
    constructor(connection, accID, namespace = accID) {
        this.connection = connection;
        this.accID = accountID(accID);
        this.namespace = namespaceID(namespace);
    }

    #checkOwner(record) {
        if (record && record.accID !== this.accID) {
            throw engineError('namespace belongs to another account', 'ACCOUNT_MISMATCH');
        }
    }

    #scope(tx, write, work) {
        const scopes = tx.objectStore(STORES.scopes);
        return requestResult(scopes.get(this.namespace), record => {
            this.#checkOwner(record);
            if (!record && write) scopes.add({ namespace: this.namespace, accID: this.accID });
            return work(tx);
        });
    }

    run(stores, mode, work) {
        return withTransaction(this.connection, [STORES.scopes, ...new Set(stores)], mode,
            tx => this.#scope(tx, mode === 'readwrite', work));
    }

    async identity() {
        return this.run([STORES.publicKeys, STORES.privateKeys], 'readonly', tx => {
            const key = [this.namespace, this.accID];
            return Promise.all([
                requestResult(tx.objectStore(STORES.publicKeys).get(key)),
                requestResult(tx.objectStore(STORES.privateKeys).get(key)),
            ]).then(([pub, priv]) => identityPair(pub, priv));
        });
    }

    async legacyPresent() {
        const db = databaseConnection(this.connection);
        const stores = ['publicKeys', 'privateKeys'].filter(name => db.objectStoreNames.contains(name));
        if (!stores.length) return false;
        return withTransaction(this.connection, stores, 'readonly', tx => Promise.all(stores.map(name =>
            requestResult(tx.objectStore(name).get(this.accID)))).then(records => records.some(Boolean)));
    }

    // Candidate keys have been generated/imported before opening this transaction.
    // Concurrent initializers recheck inside the same multi-store write lock.
    async storeIdentity(candidate, legacyAllowed = false) {
        const db = databaseConnection(this.connection);
        const legacy = ['publicKeys', 'privateKeys'].filter(name => db.objectStoreNames.contains(name));
        return this.run([STORES.publicKeys, STORES.privateKeys, ...legacy], 'readwrite', tx => {
            const key = [this.namespace, this.accID];
            const pubStore = tx.objectStore(STORES.publicKeys);
            const privStore = tx.objectStore(STORES.privateKeys);
            return requestResult(pubStore.get(key), pub =>
                requestResult(privStore.get(key), priv => {
                    const current = identityPair(pub, priv);
                    if (current) return current;
                    const checkLegacy = index => {
                        if (index < legacy.length) {
                            return requestResult(tx.objectStore(legacy[index]).get(this.accID), record => {
                                if (record && !legacyAllowed) {
                                    throw engineError('explicit legacy identity migration required', 'LEGACY_IDENTITY');
                                }
                                if (legacyAllowed) {
                                    const expected = legacy[index] === 'publicKeys' ? candidate[0] : candidate[1];
                                    if (!record || !samePublic(record, expected) || record.d !== expected.d) {
                                        throw engineError('legacy identity changed during adoption', 'IDENTITY_CONFLICT');
                                    }
                                }
                                return checkLegacy(index + 1);
                            });
                        }
                        const [publicKey, privateKey] = candidate;
                        return Promise.all([
                            requestResult(pubStore.add({ namespace: this.namespace, accID: this.accID, key: publicKey })),
                            requestResult(privStore.add({ namespace: this.namespace, accID: this.accID, key: privateKey })),
                        ]).then(() => candidate);
                    };
                    return checkLegacy(0);
                }));
        });
    }

    async addPublicKeys(entries) {
        let copied;
        try {
            copied = entries.map(({ accID, publicKey }) => ({
                accID: accountID(accID), key: keySnapshot(publicKey),
            }));
        } catch {
            throw engineError('invalid public-key entries', 'INVALID_KEY');
        }
        return this.run([STORES.publicKeys, STORES.privateKeys], 'readwrite', tx => {
            const store = tx.objectStore(STORES.publicKeys);
            return requestResult(tx.objectStore(STORES.privateKeys).get([this.namespace, this.accID]), own => {
                for (const entry of copied) {
                    if (entry.accID === this.accID && own && !samePublic(entry.key, own.key)) {
                        throw engineError('cannot replace the public half of an existing identity', 'IDENTITY_CONFLICT');
                    }
                }
                return Promise.all(copied.map(entry => requestResult(store.put({
                    namespace: this.namespace, accID: entry.accID, key: entry.key,
                })))).then(() => undefined);
            });
        });
    }

    async publicKeys() {
        return this.run([STORES.publicKeys], 'readonly', tx =>
            requestResult(tx.objectStore(STORES.publicKeys).index('namespace').getAll(this.namespace), records =>
                records.map(record => ({
                    accID: record.accID, publicKey: { ...keySnapshot(record.key), accID: record.accID },
                }))));
    }

    async myPublicKey() {
        return this.run([STORES.publicKeys], 'readonly', tx =>
            requestResult(tx.objectStore(STORES.publicKeys).get([this.namespace, this.accID]), record =>
                record ? { ...keySnapshot(record.key), accID: this.accID } : undefined));
    }

    async groupKeys() {
        return this.run([STORES.groupKeys], 'readonly', tx =>
            requestResult(tx.objectStore(STORES.groupKeys).index('namespace').getAll(this.namespace), records =>
                records.map(record => ({
                    groupID: record.groupID, version: record.version,
                    groupKey: { ...keySnapshot(record.key, true), groupID: record.groupID, version: record.version },
                }))));
    }

    async groupKey(id, version) {
        return this.run([STORES.groupKeys], 'readonly', tx =>
            requestResult(tx.objectStore(STORES.groupKeys).get([this.namespace, groupID(id), groupVersion(version)]),
                record => record ? keySnapshot(record.key, true) : undefined));
    }

    async addGroupKeys(id, entries) {
        const group = groupID(id);
        let copied;
        try {
            copied = entries.map(({ version, groupKey }) => ({
                version: groupVersion(version), key: keySnapshot(groupKey, true),
            }));
        } catch {
            throw engineError('invalid group-key entries', 'INVALID_KEY');
        }
        return this.run([STORES.groupKeys], 'readwrite', tx => {
            const store = tx.objectStore(STORES.groupKeys);
            // Chain native success events to validate each immutable version,
            // including repeated versions within the same caller batch.
            const putNext = index => {
                if (index === copied.length) return undefined;
                const { version, key } = copied[index];
                const storageKey = [this.namespace, group, version];
                return requestResult(store.get(storageKey), existing => {
                    if (existing && (!samePublic(existing.key, key)
                        || (existing.key.d && key.d && existing.key.d !== key.d))) {
                        throw engineError('group version already has a different key', 'GROUP_CONFLICT');
                    }
                    // A public reimport must never erase a retained private key.
                    const retained = existing?.key.d ? existing.key : key;
                    return requestResult(store.put({
                        namespace: this.namespace, groupID: group, version, key: retained,
                    }), () => putNext(index + 1));
                });
            };
            return putNext(0);
        });
    }

    async createGroup(id, version, pair) {
        const group = groupID(id);
        const v = groupVersion(version);
        return this.run([STORES.groupKeys], 'readwrite', tx => {
            const store = tx.objectStore(STORES.groupKeys);
            return requestResult(store.get([this.namespace, group, v]), existing => {
                if (existing) {
                    const key = keySnapshot(existing.key, true);
                    if (!key.d) throw engineError('existing group key has no private half', 'GROUP_CONFLICT');
                    return [publicPart(key), key];
                }
                return requestResult(store.add({
                    namespace: this.namespace, groupID: group, version: v, key: pair[1],
                }), () => pair);
            });
        });
    }

    async endpointKeys(publicID, privateID) {
        const parse = id => {
            if (typeof id === 'string' && id.startsWith('g')) {
                const parts = id.split(':');
                if (parts.length !== 2) throw engineError('invalid group identifier', 'INVALID_GROUP');
                return { store: STORES.groupKeys, key: [this.namespace, groupID(parts[0]), groupVersion(parts[1])] };
            }
            return { store: STORES.publicKeys, key: [this.namespace, accountID(id)] };
        };
        const pub = parse(publicID);
        const priv = parse(privateID);
        if (priv.store === STORES.publicKeys) priv.store = STORES.privateKeys;
        return this.run([pub.store, priv.store], 'readonly', tx => Promise.all([
            requestResult(tx.objectStore(pub.store).get(pub.key), record => record ? publicPart(record.key) : undefined),
            // Only this scope's account private identity may ever be selected.
            priv.store === STORES.privateKeys && privateID !== this.accID ? undefined :
                requestResult(tx.objectStore(priv.store).get(priv.key), record =>
                    record?.key.d ? keySnapshot(record.key, true) : undefined),
        ]));
    }

    async clear() {
        await this.run([STORES.publicKeys, STORES.privateKeys, STORES.groupKeys], 'readwrite', tx =>
            Promise.all([STORES.publicKeys, STORES.privateKeys, STORES.groupKeys].map(name => {
                const store = tx.objectStore(name);
                return requestResult(store.index('namespace').getAllKeys(this.namespace), keys =>
                    Promise.all(keys.map(key => requestResult(store.delete(key)))));
            })));
        // The namespace/account binding is retained; unrelated accounts and
        // application stores, including legacy records, are never cleared.
    }
}

// Explicit legacy read only: never called after an authentication error.
export async function readLegacyIdentity(connection, accID) {
    accountID(accID);
    const records = await withTransaction(connection, ['publicKeys', 'privateKeys'], 'readonly', tx =>
        Promise.all(['publicKeys', 'privateKeys'].map(name =>
            requestResult(tx.objectStore(name).get(accID)))));
    const [pub, priv] = records;
    return identityPair(pub && { key: pub }, priv && { key: priv });
}
