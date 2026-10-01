import {
    STORES, engineError, databaseConnection, requestResult, withTransaction,
} from './persistence.mjs';
import { keySnapshot, publicPart, privateCryptoKey, migratePair } from './crypto-keys.mjs';

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

function samePublic(left, right) {
    return left.kty === right.kty && left.crv === right.crv && left.x === right.x && left.y === right.y;
}

function identityPair(publicRecord, privateRecord) {
    if (!publicRecord && !privateRecord) return null;
    if (!publicRecord || !privateRecord) {
        throw engineError('incomplete identity; existing keys are retained', 'INCOMPLETE_IDENTITY');
    }
    const publicKey = keySnapshot(publicRecord.key);
    const privateKey = privateCryptoKey(privateRecord.key);
    if (!samePublic(publicKey, keySnapshot(privateRecord.publicKey))) {
        throw engineError('inconsistent identity; existing keys are retained', 'INCOMPLETE_IDENTITY');
    }
    return [publicKey, privateKey];
}

function groupPair(record) {
    if (!record) return undefined;
    if (record.key?.d !== undefined) privateCryptoKey(record.key);
    return [keySnapshot(record.key), record.privateKey ? privateCryptoKey(record.privateKey) : undefined];
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
    async storeIdentity(candidate) {
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
                                if (record) throw engineError('explicit legacy identity migration required', 'LEGACY_IDENTITY');
                                return checkLegacy(index + 1);
                            });
                        }
                        const [publicKey, privateKey] = candidate;
                        return requestResult(pubStore.add({ namespace: this.namespace, accID: this.accID, key: publicKey }),
                            () => requestResult(privStore.add({ namespace: this.namespace, accID: this.accID,
                                key: privateKey, publicKey }), () => candidate));
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
                    if (entry.accID === this.accID && own && !samePublic(entry.key, own.publicKey || publicPart(own.key))) {
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
                    groupKey: { ...publicPart(record.key), groupID: record.groupID, version: record.version },
                }))));
    }

    async groupKey(id, version) {
        return this.run([STORES.groupKeys], 'readonly', tx =>
            requestResult(tx.objectStore(STORES.groupKeys).get([this.namespace, groupID(id), groupVersion(version)]),
                record => groupPair(record)));
    }

    async addGroupKeys(id, entries) {
        const group = groupID(id);
        let copied;
        try {
            copied = entries.map(({ version, groupKey }) => ({
                version: groupVersion(version), key: keySnapshot(groupKey),
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
                    if (existing && !samePublic(existing.key, key)) {
                        throw engineError('group version already has a different key', 'GROUP_CONFLICT');
                    }
                    // A public reimport must never erase a retained private key.
                    if (existing?.key.d !== undefined) privateCryptoKey(existing.key);
                    const retained = existing || { key };
                    return requestResult(store.put({
                        namespace: this.namespace, groupID: group, version, key: retained.key,
                        ...(retained.privateKey ? { privateKey: privateCryptoKey(retained.privateKey) } : {}),
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
                    const pair = groupPair(existing);
                    if (!pair[1]) throw engineError('existing group key has no private half', 'GROUP_CONFLICT');
                    return pair;
                }
                return requestResult(store.add({
                    namespace: this.namespace, groupID: group, version: v, key: pair[0], privateKey: pair[1],
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
                    record ? (priv.store === STORES.privateKeys ? privateCryptoKey(record.key) : groupPair(record)[1]) : undefined),
        ]));
    }

    async migratePrivateKeys({ legacyIdentity = false, legacyGroups = [] } = {}) {
        if (typeof legacyIdentity !== 'boolean' || !Array.isArray(legacyGroups)) {
            throw engineError('invalid migration options', 'INVALID_KEY');
        }
        const selected = legacyGroups.map(entry => ({
            groupID: groupID(entry.groupID), version: groupVersion(entry.version), legacyVersion: entry.version,
        }));
        if (new Set(selected.map(entry => entry.groupID + ':' + entry.version)).size !== selected.length) {
            throw engineError('duplicate legacy group selection', 'INVALID_GROUP');
        }
        const db = databaseConnection(this.connection);
        const legacy = ['publicKeys', 'privateKeys'].filter(name => db.objectStoreNames.contains(name));
        if (selected.length && !db.objectStoreNames.contains('groupKeys')) {
            throw engineError('legacy group store is missing', 'INCOMPLETE_IDENTITY');
        }
        const stores = [STORES.publicKeys, STORES.privateKeys, STORES.groupKeys, ...legacy,
            ...(selected.length ? ['groupKeys'] : [])];
        // The same request chain reads the preparation snapshot and rechecks it
        // inside the write lock. All crypto work happens between transactions.
        const read = (tx, consume) => {
            const requests = [
                () => tx.objectStore(STORES.publicKeys).get([this.namespace, this.accID]),
                () => tx.objectStore(STORES.privateKeys).get([this.namespace, this.accID]),
                () => tx.objectStore(STORES.groupKeys).index('namespace').getAll(this.namespace),
                ...legacy.map(name => () => tx.objectStore(name).get(this.accID)),
                ...selected.map(entry => () => tx.objectStore('groupKeys').get([entry.groupID, entry.legacyVersion])),
            ];
            const records = [];
            const next = index => index === requests.length ? consume(records)
                : requestResult(requests[index](), record => { records.push(record); return next(index + 1); });
            return next(0);
        };
        const snapshot = await this.run(stores, 'readonly', tx => read(tx, records => records));
        const [pub, priv, groups] = snapshot;
        const flat = snapshot.slice(3, 3 + legacy.length);
        let pair;
        let migratedIdentity = false;
        if (pub || priv) {
            if (!pub || !priv) throw engineError('incomplete identity; originals retained', 'INCOMPLETE_IDENTITY');
            if (priv.key?.d !== undefined) {
                pair = await migratePair(pub.key, priv.key);
                migratedIdentity = true;
            } else pair = identityPair(pub, priv);
        }
        if (flat.some(Boolean)) {
            if (!legacyIdentity) throw engineError('explicit legacy identity migration required', 'LEGACY_IDENTITY');
            const flatPub = flat[legacy.indexOf('publicKeys')];
            const flatPriv = flat[legacy.indexOf('privateKeys')];
            if (!flatPub || !flatPriv) throw engineError('incomplete legacy identity; originals retained', 'INCOMPLETE_IDENTITY');
            const imported = await migratePair(flatPub, flatPriv);
            if (pair && !samePublic(pair[0], imported[0])) {
                throw engineError('legacy and scoped identities differ; originals retained', 'IDENTITY_CONFLICT');
            }
            pair = imported;
            migratedIdentity = true;
        }
        if (!pair) throw engineError('migration requires an existing identity; no keys generated', 'INCOMPLETE_IDENTITY');
        const replacements = [];
        for (const record of groups) {
            groupID(record.groupID);
            groupVersion(record.version);
            if (record.key?.d !== undefined) {
                const imported = await migratePair(publicPart(record.key), record.key);
                replacements.push({ namespace: this.namespace, groupID: record.groupID,
                    version: record.version, key: imported[0], privateKey: imported[1] });
            } else groupPair(record);
        }
        for (let index = 0; index < selected.length; index++) {
            const entry = selected[index];
            const record = snapshot[3 + legacy.length + index];
            if (!record) throw engineError('selected legacy group is missing', 'INCOMPLETE_IDENTITY');
            const imported = await migratePair(publicPart(record), record);
            const existing = groups.find(group => group.groupID === entry.groupID && group.version === entry.version);
            if (existing && !samePublic(existing.key, imported[0])) {
                throw engineError('legacy group conflicts with scoped version; originals retained', 'GROUP_CONFLICT');
            }
            const replacement = { namespace: this.namespace, groupID: entry.groupID,
                version: entry.version, key: imported[0], privateKey: imported[1] };
            const previous = replacements.findIndex(group => group.groupID === entry.groupID && group.version === entry.version);
            if (previous < 0) replacements.push(replacement);
            else replacements[previous] = replacement;
        }
        // JSON is only an internal conflict comparison, never a persisted backup
        // or an error value. CryptoKey capabilities are compared by their metadata.
        const describe = records => JSON.stringify(records, (name, value) => value instanceof CryptoKey
            ? { type: value.type, extractable: value.extractable, algorithm: value.algorithm, usages: value.usages } : value);
        const expected = describe(snapshot);
        if (!migratedIdentity && !replacements.length) return { migratedIdentity: false, migratedGroups: 0 };
        return this.run(stores, 'readwrite', tx => read(tx, current => {
            if (describe(current) !== expected) {
                throw engineError('records changed during migration; retry explicitly', 'MIGRATION_CONFLICT');
            }
            const writes = [];
            if (migratedIdentity) {
                const metadata = { namespace: this.namespace, accID: this.accID };
                writes.push(() => tx.objectStore(STORES.publicKeys).put({ ...metadata, key: pair[0] }));
                writes.push(() => tx.objectStore(STORES.privateKeys).put({ ...metadata, key: pair[1], publicKey: pair[0] }));
                for (const name of legacy) writes.push(() => tx.objectStore(name).delete(this.accID));
            }
            for (const record of replacements) writes.push(() => tx.objectStore(STORES.groupKeys).put(record));
            for (const entry of selected) {
                writes.push(() => tx.objectStore('groupKeys').delete([entry.groupID, entry.legacyVersion]));
            }
            const next = index => index === writes.length ? { migratedIdentity, migratedGroups: replacements.length }
                : requestResult(writes[index](), () => next(index + 1));
            return next(0);
        }));
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
