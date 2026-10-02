/* global WeakRef */
import {
    STORES, engineError, databaseConnection, requestResult, withTransaction, requireBe9Schema,
} from './persistence.mjs';
import { keySnapshot, publicPart, privateCryptoKey, migratePair, preparePublicKey, jwkThumbprint } from './crypto-keys.mjs';
import { trustDecision, fingerprintValue, checkTrustRecord, nextTrust } from './trust.mjs';
import { V2_LIMITS } from './limits.mjs';

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

export function peerID(id) {
    if (typeof id === 'string' && id.startsWith('g')) {
        const [group, version, extra] = id.split(':');
        if (extra !== undefined) throw engineError('invalid group identifier', 'INVALID_GROUP');
        return groupID(group) + ':' + groupVersion(version);
    }
    return accountID(id);
}

function localDecisions(options, ids) {
    if (!options || typeof options !== 'object' || Array.isArray(options)
        || (options.decisions !== undefined && !Array.isArray(options.decisions))) {
        throw engineError('invalid local trust options', 'INVALID_TRUST_DECISION');
    }
    const fallback = trustDecision({ tofu: options.tofu });
    const decisions = new Map();
    for (const entry of options.decisions || []) {
        const id = peerID(entry.peerID);
        if (!ids.includes(id) || decisions.has(id)) {
            throw engineError('trust decision must select one imported endpoint', 'INVALID_TRUST_DECISION');
        }
        decisions.set(id, trustDecision({ expectedFingerprint: entry.expectedFingerprint,
            trust: entry.trust, tofu: entry.tofu === undefined ? fallback.tofu : entry.tofu }));
    }
    return id => decisions.get(id) || fallback;
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

// Weak registrations coordinate live instances in this JS realm; persisted
// generations are authoritative across connections, reloads and other realms.
const liveScopes = new Map();
function scopeState(record) {
    const status = record && Object.hasOwn(record, 'status') ? record.status : 'active';
    const generation = record && Object.hasOwn(record, 'generation') ? record.generation : 0;
    if (!['active', 'invalidated'].includes(status) || !Number.isSafeInteger(generation) || generation < 0) {
        throw engineError('invalid namespace lifecycle state', 'INVALID_LIFECYCLE');
    }
    return { status, generation };
}
export class KeyStore {
    #generation;
    #blocked = false;
    #transactions = new Set();
    #databaseName;
    #registered = false;
    onLock = () => {};
    assertActive() {
        if (this.#blocked) throw engineError('local namespace is invalidated; explicit reinitialize() required', 'ENGINE_LOCKED');
    }
    lock() {
        this.#blocked = true;
        this.onLock();
        for (const tx of this.#transactions) { try { tx.abort(); } catch { /* Terminal transaction. */ } }
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
        const registered = liveScopes.get(this.#databaseName)?.get(this.namespace);
        for (const reference of registered || []) {
            const keys = reference.deref();
            if (!keys) registered.delete(reference);
            else if (keys.accID === this.accID && (this.#generation === undefined || keys.#generation === undefined || keys.#generation === this.#generation)) keys.lock();
        }
    }
    #track(tx) {
        this.#register(tx);
        this.#transactions.add(tx);
        const release = () => this.#transactions.delete(tx);
        tx.addEventListener('complete', release, { once: true });
        tx.addEventListener('abort', release, { once: true });
    }
    checkLifecycle() { return this.run([], 'readonly', () => undefined); }

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
            this.assertActive();
            this.#checkOwner(record);
            const state = scopeState(record);
            if (!record && this.#generation !== undefined) throw engineError('namespace lifecycle record is missing; no automatic reset is allowed', 'INVALID_LIFECYCLE');
            if (state.status !== 'active' || (this.#generation !== undefined && state.generation !== this.#generation)) {
                this.lock();
                throw engineError('namespace generation has been invalidated', 'ENGINE_LOCKED');
            }
            if (record) this.#generation ??= state.generation;
            if (!record && write) {
                scopes.add({ namespace: this.namespace, accID: this.accID, status: 'active', generation: 0 });
                tx.addEventListener('complete', () => { this.#generation ??= 0; }, { once: true });
            }
            return work(tx);
        });
    }

    run(stores, mode, work) {
        this.assertActive();
        requireBe9Schema(this.connection);
        return withTransaction(this.connection, [STORES.scopes, ...new Set(stores)], mode, tx => {
            this.#track(tx);
            return this.#scope(tx, mode === 'readwrite', work);
        });
    }

    async reserveUsage(derivationID, byteLength, aadLength = 0) {
        fingerprintValue(derivationID);
        if (!databaseConnection(this.connection).objectStoreNames.contains(STORES.keyUsage)) {
            throw engineError('application must upgrade its schema with upgradeBe9Schema() before v2 encryption', 'SCHEMA_UPGRADE_REQUIRED');
        }
        if (!Number.isSafeInteger(byteLength) || byteLength < 0 || byteLength > V2_LIMITS.plaintextBytes) {
            throw engineError('input exceeds the v2 size limit', 'INPUT_TOO_LARGE');
        }
        if (!Number.isSafeInteger(aadLength) || aadLength < 0 || aadLength > 4096) throw engineError('invalid AAD size', 'INVALID_ENVELOPE');
        const blocks = Math.ceil(byteLength / 16) + Math.ceil(aadLength / 16) + 1;
        return this.run([STORES.keyUsage], 'readwrite', tx => {
            const store = tx.objectStore(STORES.keyUsage);
            return requestResult(store.get(derivationID), current => {
                const record = current || { derivationID, encryptions: 0, blocks: 0 };
                if (!Number.isSafeInteger(record.encryptions) || record.encryptions < 0 || record.encryptions > V2_LIMITS.encryptions
                    || !Number.isSafeInteger(record.blocks) || record.blocks < record.encryptions || record.blocks > V2_LIMITS.blocks) {
                    throw engineError('invalid persisted GCM usage state', 'INVALID_USAGE_STATE');
                }
                if (record.encryptions >= V2_LIMITS.encryptions || record.blocks + blocks > V2_LIMITS.blocks) {
                    throw engineError('GCM key usage budget exhausted; create a new derivation context', 'KEY_USAGE_EXHAUSTED');
                }
                return requestResult(store.put({ derivationID, encryptions: record.encryptions + 1, blocks: record.blocks + blocks }));
            });
        });
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
        requireBe9Schema(db);
        const stores = ['publicKeys', 'privateKeys'].filter(name => db.objectStoreNames.contains(name));
        if (!stores.length) return false;
        return withTransaction(this.connection, stores, 'readonly', tx => Promise.all(stores.map(name =>
            requestResult(tx.objectStore(name).get(this.accID)))).then(records => records.some(Boolean)));
    }

    // Candidate keys have been generated/imported before opening this transaction.
    // Concurrent initializers recheck inside the same multi-store write lock.
    async storeIdentity(candidate) {
        const db = databaseConnection(this.connection);
        requireBe9Schema(db);
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

    async addPublicKeys(entries, options = {}) {
        let copied;
        try {
            copied = entries.map(({ accID, publicKey }) => ({ accID: accountID(accID), key: keySnapshot(publicKey) }));
        } catch {
            throw engineError('invalid public-key entries', 'INVALID_KEY');
        }
        const decisionFor = localDecisions(options, copied.map(entry => entry.accID));
        const prepared = await Promise.all(copied.map(async entry => ({ ...entry, ...await preparePublicKey(entry.key),
            decision: decisionFor(entry.accID) })));
        return this.run([STORES.publicKeys, STORES.privateKeys, STORES.trust], 'readwrite', tx => {
            const store = tx.objectStore(STORES.publicKeys);
            const trust = tx.objectStore(STORES.trust);
            return requestResult(tx.objectStore(STORES.privateKeys).get([this.namespace, this.accID]), own => {
                const next = index => {
                    if (index === prepared.length) return undefined;
                    const entry = prepared[index];
                    const storageKey = [this.namespace, entry.accID];
                    return requestResult(store.get(storageKey), existing => requestResult(trust.get(storageKey), current => {
                        if (entry.accID === this.accID && own) {
                            if (!samePublic(entry.key, own.publicKey || publicPart(own.key))) {
                                throw engineError('cannot replace the public half of an existing identity', 'IDENTITY_CONFLICT');
                            }
                            nextTrust(undefined, entry.fingerprint, entry.decision, false);
                            return next(index + 1);
                        }
                        if (existing && !samePublic(keySnapshot(existing.key), entry.key)) {
                            throw engineError('peer public key changed; explicit replacement required', 'PUBLIC_KEY_CHANGED');
                        }
                        const status = nextTrust(current, entry.fingerprint, entry.decision, !existing && !current);
                        return requestResult(store.put({ namespace: this.namespace, accID: entry.accID, key: entry.key }),
                            () => requestResult(trust.put({ namespace: this.namespace, peerID: entry.accID,
                                fingerprint: entry.fingerprint, status }), () => next(index + 1)));
                    }));
                };
                return next(0);
            });
        });
    }

    async peerTrust(id) {
        const peer = peerID(id);
        return this.run([STORES.trust], 'readonly', tx => requestResult(
            tx.objectStore(STORES.trust).get([this.namespace, peer]), record => {
                checkTrustRecord(record);
                return record ? { peerID: peer, fingerprint: record.fingerprint, status: record.status } : undefined;
            }));
    }

    async replacePublicKey(id, publicKey, { expectedPreviousFingerprint, confirmedNewFingerprint } = {}) {
        const peer = accountID(id);
        if (peer === this.accID) throw engineError('own identity cannot be replaced through the peer API', 'IDENTITY_CONFLICT');
        const previous = fingerprintValue(expectedPreviousFingerprint);
        const confirmed = fingerprintValue(confirmedNewFingerprint);
        const prepared = await preparePublicKey(publicKey);
        if (confirmed !== prepared.fingerprint) {
            throw engineError('new key does not match the confirmed fingerprint', 'FINGERPRINT_MISMATCH');
        }
        const snapshot = await this.run([STORES.publicKeys, STORES.trust], 'readonly', tx => Promise.all([
            requestResult(tx.objectStore(STORES.publicKeys).get([this.namespace, peer])),
            requestResult(tx.objectStore(STORES.trust).get([this.namespace, peer])),
        ]));
        checkTrustRecord(snapshot[1]);
        if (!snapshot[0] || !snapshot[1] || snapshot[1].fingerprint !== previous
            || await jwkThumbprint(snapshot[0].key) !== previous) {
            throw engineError('previous fingerprint no longer matches; replacement refused', 'TRUST_CONFLICT');
        }
        const originalKey = keySnapshot(snapshot[0].key);
        return this.run([STORES.publicKeys, STORES.trust], 'readwrite', tx => {
            const store = tx.objectStore(STORES.publicKeys);
            const trust = tx.objectStore(STORES.trust);
            const storageKey = [this.namespace, peer];
            return requestResult(store.get(storageKey), existing => requestResult(trust.get(storageKey), current => {
                checkTrustRecord(current);
                if (!existing || !current || current.fingerprint !== previous || !samePublic(existing.key, originalKey)) {
                    throw engineError('previous fingerprint no longer matches; replacement refused', 'TRUST_CONFLICT');
                }
                return requestResult(store.put({ namespace: this.namespace, accID: peer, key: prepared.key }),
                    () => requestResult(trust.put({ namespace: this.namespace, peerID: peer,
                        fingerprint: prepared.fingerprint, status: 'confirmed' }), () => undefined));
            }));
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

    async addGroupKeys(id, entries, options = {}) {
        const group = groupID(id);
        let copied;
        try {
            copied = entries.map(({ version, groupKey }) => ({
                version: groupVersion(version), key: keySnapshot(groupKey),
            }));
        } catch {
            throw engineError('invalid group-key entries', 'INVALID_KEY');
        }
        const decisionFor = localDecisions(options, copied.map(entry => group + ':' + entry.version));
        const prepared = await Promise.all(copied.map(async entry => ({ ...entry, ...await preparePublicKey(entry.key),
            decision: decisionFor(group + ':' + entry.version) })));
        return this.run([STORES.groupKeys, STORES.trust], 'readwrite', tx => {
            const store = tx.objectStore(STORES.groupKeys);
            const trust = tx.objectStore(STORES.trust);
            // Chain native success events to validate each immutable version,
            // including repeated versions within the same caller batch.
            const putNext = index => {
                if (index === prepared.length) return undefined;
                const { version, key, fingerprint, decision } = prepared[index];
                const storageKey = [this.namespace, group, version];
                return requestResult(store.get(storageKey), existing => {
                    if (existing && !samePublic(existing.key, key)) {
                        throw engineError('group version already has a different key', 'GROUP_CONFLICT');
                    }
                    // A public reimport must never erase a retained private key.
                    if (existing?.key.d !== undefined) privateCryptoKey(existing.key);
                    const retained = existing || { key };
                    const write = () => requestResult(store.put({
                        namespace: this.namespace, groupID: group, version, key: retained.key,
                        ...(retained.privateKey ? { privateKey: privateCryptoKey(retained.privateKey) } : {}),
                    }), () => putNext(index + 1));
                    if (retained.privateKey) { nextTrust(undefined, fingerprint, decision, false); return write(); }
                    const peer = group + ':' + version;
                    return requestResult(trust.get([this.namespace, peer]), current => {
                        const status = nextTrust(current, fingerprint, decision, !existing && !current);
                        return requestResult(trust.put({ namespace: this.namespace, peerID: peer, fingerprint, status }), write);
                    });
                });
            };
            return putNext(0);
        });
    }

    async endpointKeys(publicID, privateID, requireTrust = false) {
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
        const own = parse(privateID);
        if (priv.store === STORES.publicKeys) priv.store = STORES.privateKeys;
        const [publicRecord, privateKey, trust, ownRecord] = await this.run([pub.store, priv.store, own.store, ...(requireTrust ? [STORES.trust] : [])], 'readonly', tx => Promise.all([
            requestResult(tx.objectStore(pub.store).get(pub.key)),
            // Only this scope's account private identity may ever be selected.
            priv.store === STORES.privateKeys && privateID !== this.accID ? undefined :
                requestResult(tx.objectStore(priv.store).get(priv.key), record =>
                    record ? (priv.store === STORES.privateKeys ? privateCryptoKey(record.key) : groupPair(record)[1]) : undefined),
            requireTrust ? requestResult(tx.objectStore(STORES.trust).get([this.namespace, peerID(publicID)])) : undefined,
            requestResult(tx.objectStore(own.store).get(own.key)),
        ]));
        const publicKey = publicRecord ? (pub.store === STORES.groupKeys ? publicPart(publicRecord.key) : keySnapshot(publicRecord.key)) : undefined;
        const local = publicID === this.accID || (pub.store === STORES.groupKeys && publicRecord?.privateKey);
        if (publicKey && requireTrust && !local) {
            checkTrustRecord(trust);
            if (!trust || trust.status === 'unverified') {
                throw engineError('peer public key requires an explicit local trust decision', 'UNTRUSTED_PUBLIC_KEY');
            }
            if (await jwkThumbprint(publicKey) !== trust.fingerprint) {
                throw engineError('persisted key and trust fingerprint disagree', 'INVALID_TRUST_STATE');
            }
        }
        const ownPublicKey = ownRecord ? (own.store === STORES.groupKeys ? publicPart(ownRecord.key) : keySnapshot(ownRecord.key)) : undefined;
        return [publicKey, privateKey, ownPublicKey];
    }

    async migratePublicKeyTrust() {
        const snapshot = await this.run([STORES.publicKeys, STORES.groupKeys], 'readonly', tx => Promise.all([
            requestResult(tx.objectStore(STORES.publicKeys).index('namespace').getAll(this.namespace)),
            requestResult(tx.objectStore(STORES.groupKeys).index('namespace').getAll(this.namespace)),
        ]));
        const entries = [
            ...snapshot[0].filter(record => record.accID !== this.accID).map(record => ({
                peerID: accountID(record.accID), store: STORES.publicKeys, storageKey: [this.namespace, record.accID], key: record.key,
            })),
            ...snapshot[1].filter(record => !record.privateKey && record.key?.d === undefined).map(record => ({
                peerID: groupID(record.groupID) + ':' + groupVersion(record.version), store: STORES.groupKeys,
                storageKey: [this.namespace, record.groupID, record.version], key: record.key,
            })),
        ];
        const prepared = await Promise.all(entries.map(async entry => ({ ...entry, ...await preparePublicKey(entry.key) })));
        return this.run([STORES.publicKeys, STORES.groupKeys, STORES.trust], 'readwrite', tx => {
            const trust = tx.objectStore(STORES.trust);
            let migratedPeers = 0;
            const next = index => {
                if (index === prepared.length) return { migratedPeers };
                const entry = prepared[index];
                return requestResult(tx.objectStore(entry.store).get(entry.storageKey), existing => {
                    if (!existing || !samePublic(keySnapshot(existing.key), entry.key)
                        || (entry.store === STORES.groupKeys && existing.privateKey)) {
                        throw engineError('public records changed during trust migration', 'MIGRATION_CONFLICT');
                    }
                    return requestResult(trust.get([this.namespace, entry.peerID]), current => {
                        checkTrustRecord(current);
                        if (current) {
                            if (current.fingerprint !== entry.fingerprint) {
                                throw engineError('persisted key and trust state disagree', 'INVALID_TRUST_STATE');
                            }
                            return next(index + 1);
                        }
                        migratedPeers++;
                        return requestResult(trust.add({ namespace: this.namespace, peerID: entry.peerID,
                            fingerprint: entry.fingerprint, status: 'unverified' }), () => next(index + 1));
                    });
                });
            };
            return next(0);
        });
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
        requireBe9Schema(db);
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

    async invalidate() {
        // A previously validated owner can immediately invalidate other live
        // instances. An unbound/wrong owner must first pass the native scope check.
        if (this.#generation !== undefined) this.#lockPeers();
        const db = databaseConnection(this.connection);
        requireBe9Schema(db);
        const owned = Object.values(STORES).filter(name => name !== STORES.scopes && name !== STORES.keyUsage && db.objectStoreNames.contains(name));
        return withTransaction(this.connection, [STORES.scopes, ...owned], 'readwrite', tx => {
            this.#register(tx);
            const scopes = tx.objectStore(STORES.scopes);
            return requestResult(scopes.get(this.namespace), record => {
                this.#checkOwner(record);
                const state = scopeState(record);
                if (state.status === 'invalidated') { this.#lockPeers(); return; }
                if (this.#generation !== undefined && state.generation !== this.#generation) throw engineError('stale instance cannot delete a new namespace generation', 'ENGINE_LOCKED');
                if (state.generation === Number.MAX_SAFE_INTEGER) throw engineError('namespace generation exhausted', 'GENERATION_EXHAUSTED');
                this.#lockPeers();
                const removals = owned.map(name => {
                    const store = tx.objectStore(name);
                    return requestResult(store.index('namespace').getAllKeys(this.namespace), keys =>
                        Promise.all(keys.map(key => requestResult(store.delete(key)))));
                });
                const tombstone = requestResult(scopes.put({ namespace: this.namespace, accID: this.accID,
                    status: 'invalidated', generation: state.generation + 1 }));
                return Promise.all([...removals, tombstone]).then(() => undefined);
            });
        });
        // Legacy unscoped/application stores and shared per-actual-key usage
        // reservations remain: deletion must neither claim ownership nor refund.
    }
    async reinitializationState() {
        requireBe9Schema(this.connection);
        return withTransaction(this.connection, [STORES.scopes], 'readonly', tx => {
            this.#register(tx);
            return requestResult(tx.objectStore(STORES.scopes).get(this.namespace), record => {
                this.#checkOwner(record);
                const state = scopeState(record);
                if (state.status !== 'invalidated') throw engineError('commit panic() before explicit reinitialization', 'REINITIALIZATION_REQUIRED');
                if (state.generation === Number.MAX_SAFE_INTEGER) throw engineError('namespace generation exhausted', 'GENERATION_EXHAUSTED');
                return state.generation;
            });
        });
    }
    async reinitialize(candidate, expectedGeneration, valid) {
        requireBe9Schema(this.connection);
        return withTransaction(this.connection, [STORES.scopes, STORES.publicKeys, STORES.privateKeys], 'readwrite', tx => {
            this.#track(tx);
            const scopes = tx.objectStore(STORES.scopes);
            return requestResult(scopes.get(this.namespace), record => {
                this.#checkOwner(record);
                const state = scopeState(record);
                if (!valid() || state.status !== 'invalidated' || state.generation !== expectedGeneration) throw engineError('reinitialization was invalidated or lost its generation', 'ENGINE_LOCKED');
                const [publicKey, privateKey] = candidate;
                tx.objectStore(STORES.publicKeys).add({ namespace: this.namespace, accID: this.accID, key: publicKey });
                tx.objectStore(STORES.privateKeys).add({ namespace: this.namespace, accID: this.accID, key: privateKey, publicKey });
                return requestResult(scopes.put({ namespace: this.namespace, accID: this.accID, status: 'active', generation: state.generation + 1 }),
                    () => state.generation + 1);
            });
        });
    }
    resume(generation) { this.#generation = generation; this.#blocked = false; }
}
