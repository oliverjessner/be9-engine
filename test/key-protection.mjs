import Be8, { STORES } from '../lib/bundle.mjs';
import { participantHooks, exchangePublicKeys } from './participants.mjs';
import { readRecord, requestResult, storedIDs } from './database.mjs';
import { withTransaction, requestResult as nativeResult } from '../lib/persistence.mjs';

const algorithm = { name: 'ECDH', namedCurve: 'P-384' };

// Genuine exportable WebCrypto keys exist only to construct old-format data.
// These fixtures remain local to their owner, never shared with participants.
async function legacyPair() {
    const pair = await crypto.subtle.generateKey(algorithm, true, ['deriveKey', 'deriveBits']);
    return Promise.all([crypto.subtle.exportKey('jwk', pair.publicKey), crypto.subtle.exportKey('jwk', pair.privateKey)]);
}

async function fingerprint(key) {
    const canonical = JSON.stringify({ crv: key.crv, kty: key.kty, x: key.x, y: key.y });
    const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
    return [...new Uint8Array(bytes)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

async function settles(operation) {
    let deadline;
    try {
        return await Promise.race([
            operation.then(value => ({ value }), error => ({ error })),
            new Promise((resolve, reject) => {
                deadline = setTimeout(() => reject(new Error('Operation did not settle')), 5000);
            }),
        ]);
    } finally { clearTimeout(deadline); }
}

function noPrivateJWK(value) {
    if (!value || typeof value !== 'object' || value instanceof CryptoKey) return true;
    return !Object.hasOwn(value, 'd') && Object.values(value).every(noPrivateJWK);
}

async function scopedFixture(context) {
    const database = await context.open();
    const identity = await legacyPair();
    const group = await legacyPair();
    const tx = database.transaction([STORES.scopes, STORES.publicKeys, STORES.privateKeys, STORES.groupKeys], 'readwrite');
    tx.objectStore(STORES.scopes).put({ namespace: '104', accID: '104' });
    tx.objectStore(STORES.publicKeys).put({ namespace: '104', accID: '104', key: identity[0] });
    tx.objectStore(STORES.privateKeys).put({ namespace: '104', accID: '104', key: identity[1] });
    tx.objectStore(STORES.groupKeys).put({ namespace: '104', groupID: 'g200', version: 1, key: group[1] });
    await database.whenIdle();
    return { database, identity, group, engine: new Be8('104', database.connection) };
}

async function records(database, names) {
    const tx = database.transaction(names, 'readonly');
    const rows = await Promise.all(names.map(name => requestResult(tx.objectStore(name).getAll())));
    await database.whenIdle();
    return rows;
}

QUnit.module('Non-extractable local keys / explicit migration', hooks => {
    participantHooks(hooks);

    QUnit.test('Committed identity and group keys deny private exports; getters and generation expose only public data', async function (assert) {
        const { alice, bob } = this;
        const generated = await alice.engine.generatePrivAndPubKey();
        const group = await alice.engine.generateGroupKeys(1, 'g200');
        const rows = await records(alice.database, [STORES.privateKeys, STORES.groupKeys, STORES.publicKeys]);
        const privateKey = rows[0][0].key;
        const groupPrivate = rows[1][0].privateKey;
        for (const key of [privateKey, groupPrivate]) {
            assert.true(key instanceof CryptoKey && key.type === 'private' && !key.extractable,
                'IndexedDB restores a native non-extractable private CryptoKey');
            assert.deepEqual(key.usages, ['deriveKey'], 'Only the required ECDH usage is allowed');
            for (const format of ['jwk', 'pkcs8']) {
                await assert.rejects(crypto.subtle.exportKey(format, key),
                    error => error instanceof DOMException && error.name === 'InvalidAccessError', 'Private export is denied');
            }
        }
        const aes = await alice.engine.getDerivedKey(bob.publicKey, generated.keyReference);
        assert.false(aes.extractable, 'Derived AES keys are non-extractable');
        assert.deepEqual(aes.usages, ['encrypt', 'decrypt'], 'AES allows only encryption and decryption');
        await assert.rejects(crypto.subtle.exportKey('raw', aes),
            error => error instanceof DOMException && error.name === 'InvalidAccessError', 'Derived AES export is denied');
        assert.true(noPrivateJWK(rows), 'New database records contain no private d field');
        const getters = [await alice.engine.getMyPublicKey(), await alice.engine.getCachedKeys(),
            await alice.engine.getCachedGroupKeys(), generated, group];
        assert.true(noPrivateJWK(getters), 'No public getter or generation result contains private JWK material');
        assert.deepEqual(Object.keys(generated).sort(), ['keyReference', 'publicKey'], 'Generation has a documented public result');
        assert.deepEqual(Object.keys(generated.keyReference), [], 'The local reference contains no enumerable key material');
        const receiver = await bob.engine.generatePrivAndPubKey();
        const groupAES = await alice.engine.getDerivedKey(bob.publicKey, group.keyReference);
        const receiverAES = await bob.engine.getDerivedKey(group.publicKey, receiver.keyReference);
        const packet = await alice.engine.encryptText(groupAES, 'Local group reference');
        assert.true(await bob.engine.decryptText(receiverAES, packet.cipherText, packet.iv) === 'Local group reference',
            'A local group reference derives interoperably without exposing private material');
        assert.false(Object.hasOwn(getters[2][0].groupKey, 'privateKey'), 'The group getter does not expose the stored private CryptoKey');
        assert.strictEqual(Be8.readLegacyIdentity, undefined, 'The old private-JWK inspection API is removed');
    });

    QUnit.test('References are local capabilities; a fresh reference after reopening keeps cryptographic identity', async function (assert) {
        const { alice, bob } = this;
        await exchangePublicKeys(alice, bob);
        const before = await alice.engine.generatePrivAndPubKey();
        await assert.rejects(bob.engine.getDerivedKey(alice.publicKey, before.keyReference),
            error => error.code === 'INVALID_PRIVATE_KEY', 'A different instance cannot use the opaque reference');
        await assert.rejects(alice.engine.getDerivedKey(bob.publicKey, structuredClone(before.keyReference)),
            error => error.code === 'INVALID_PRIVATE_KEY', 'Cloning the reference does not copy the capability');
        const packet = await bob.engine.encryptTextSimple(bob.id, alice.id, 'Before reload');
        alice.database.close();
        const database = await this.open(alice.database.name);
        const reopened = new Be8(alice.id, database.connection);
        await reopened.setup();
        const after = await reopened.generatePrivAndPubKey();
        assert.true(await fingerprint(before.publicKey) === await fingerprint(after.publicKey), 'Reload preserves the fingerprint');
        assert.true(await reopened.decryptTextSimple(bob.id, alice.id, packet.cipherText, packet.iv) === 'Before reload',
            'An already encrypted packet decrypts after reload');
        const derived = await reopened.getDerivedKey(bob.publicKey, after.keyReference);
        const reply = await reopened.encryptText(derived, 'After reload');
        assert.true(await bob.engine.decryptTextSimple(alice.id, bob.id, reply.cipherText, reply.iv) === 'After reload',
            'A fresh local reference encrypts interoperably after reload');
        const stored = await readRecord(database, 'privateKeys', alice.id);
        await assert.rejects(crypto.subtle.exportKey('jwk', stored),
            error => error.name === 'InvalidAccessError', 'Restored private keys remain non-extractable');
    });

    QUnit.test('Explicit scoped migration keeps identity, group fingerprint, old ciphertexts and reload interoperability', async function (assert) {
        const fixture = await scopedFixture(this);
        const { engine, database, identity, group } = fixture;
        await this.bob.engine.addPublicKey('104', identity[0]);
        await this.bob.engine.addGroupKeys('g200', [{ version: 1, groupKey: group[0] }]);
        await engine.addPublicKey(this.bob.id, this.bob.publicKey);
        const packet = await this.bob.engine.encryptTextSimple(this.bob.id, '104', 'Before migration');
        const groupPacket = await this.bob.engine.encryptTextSimple(this.bob.id, 'g200:1', 'Old group');
        const blocked = await settles(engine.setup());
        assert.true(blocked.error instanceof Error && blocked.error.code === 'PRIVATE_KEY_MIGRATION_REQUIRED',
            'Default setup requires an explicit migration, without generating a replacement');
        database.acknowledgeAborts();
        assert.true(noPrivateJWK(await engine.getCachedGroupKeys()), 'Even old-format group getters project only the public half');
        const result = await settles(engine.migratePrivateKeys());
        assert.true(!result.error && result.value.migratedIdentity && result.value.migratedGroups === 1, 'Identity and group migration commit together');
        assert.strictEqual(database.pendingWrites(), 0, 'Migration success waits for commit');
        assert.true(await fingerprint(await engine.getMyPublicKey()) === await fingerprint(identity[0]), 'Identity fingerprint is unchanged');
        const groups = await engine.getCachedGroupKeys();
        assert.true(await fingerprint(groups[0].groupKey) === await fingerprint(group[0]), 'Group fingerprint is unchanged');
        const rows = await records(database, [STORES.privateKeys, STORES.groupKeys]);
        assert.true(noPrivateJWK(rows), 'All selected original private JWKs were replaced, with no hidden backup');
        await assert.rejects(crypto.subtle.exportKey('jwk', rows[0][0].key), error => error.name === 'InvalidAccessError', 'Migrated private export is denied');
        database.close();
        const reopened = new Be8('104', (await this.open(database.name)).connection);
        await reopened.setup();
        assert.true(await reopened.decryptTextSimple(this.bob.id, '104', packet.cipherText, packet.iv) === 'Before migration', 'Old identity ciphertext decrypts after migration and reload');
        assert.true(await reopened.decryptTextSimple(this.bob.id, 'g200:1', groupPacket.cipherText, groupPacket.iv) === 'Old group', 'Old group ciphertext decrypts after migration and reload');
        const reply = await reopened.encryptTextSimple('104', this.bob.id, 'Migrated reply');
        assert.true(await this.bob.engine.decryptTextSimple('104', this.bob.id, reply.cipherText, reply.iv) === 'Migrated reply', 'Migrated owner encrypts in the opposite direction');
        const repeated = await reopened.migratePrivateKeys();
        assert.true(!repeated.migratedIdentity && repeated.migratedGroups === 0, 'Repeat migration does not rotate keys');
    });

    QUnit.test('An abort after a successful migration write retains every original and explicit retry succeeds', async function (assert) {
        const { engine, database, identity, group } = await scopedFixture(this);
        let successfulWrite = false;
        database.observe(tx => {
            if (tx.mode === 'readwrite' && tx.objectStoreNames.contains(STORES.privateKeys)) {
                tx.addEventListener('success', event => {
                    if (event.target.source?.name === STORES.privateKeys && Array.isArray(event.target.result)) {
                        successfulWrite = true;
                        tx.abort();
                    }
                }, { capture: true });
            }
        });
        const result = await settles(engine.migratePrivateKeys());
        database.observe(undefined);
        assert.true(successfulWrite, 'A real private-key write succeeded before the native transaction abort');
        assert.true(result.error instanceof Error, 'Aborted migration rejects and settles');
        assert.strictEqual(database.acknowledgeAborts(), 1, 'One migration transaction aborted');
        const oldPrivate = await readRecord(database, 'privateKeys', '104');
        const oldGroup = await readRecord(database, 'groupKeys', ['104', 'g200', 1]);
        assert.true(oldPrivate.d === identity[1].d && oldGroup.d === group[1].d, 'Both original private JWKs survive rollback unchanged');
        assert.true((await engine.getMyPublicKey()).x === identity[0].x, 'The public identity was not changed');
        const retried = await settles(engine.migratePrivateKeys());
        assert.true(!retried.error && retried.value.migratedIdentity, 'Explicit retry after rollback succeeds');
        assert.true(noPrivateJWK(await records(database, [STORES.privateKeys, STORES.groupKeys])), 'Retry leaves no private JWK backup');
    });

    QUnit.test('Invalid scalar or mismatched public coordinates reject without deleting or generating keys', async function (assert) {
        const { engine, database, identity } = await scopedFixture(this);
        const another = await legacyPair();
        for (const invalid of [{ ...identity[1], d: another[1].d }, { ...identity[1], d: 'invalid' }]) {
            const tx = database.transaction(STORES.privateKeys, 'readwrite');
            tx.objectStore(STORES.privateKeys).put({ namespace: '104', accID: '104', key: invalid });
            await database.whenIdle();
            const result = await settles(engine.migratePrivateKeys());
            assert.true(result.error instanceof Error && result.error.code === 'INVALID_PRIVATE_KEY', 'Native validation rejects invalid private material');
            assert.true((await readRecord(database, 'privateKeys', '104')).d === invalid.d, 'The original invalid record is retained for application recovery');
            assert.true(await fingerprint(await engine.getMyPublicKey()) === await fingerprint(identity[0]), 'No replacement identity was generated');
            assert.deepEqual(await storedIDs(database), ['104'], 'No additional private record was created');
        }
    });

    QUnit.test('Concurrent group mutation during migration prevents stale replacement and keeps new data', async function (assert) {
        const { engine, database, identity } = await scopedFixture(this);
        const changed = await legacyPair();
        let mutated = false;
        database.observe(tx => {
            if (tx.mode === 'readonly' && tx.objectStoreNames.contains(STORES.groupKeys)) {
                tx.addEventListener('success', event => {
                    if (!mutated && event.target.source?.objectStore?.name === STORES.groupKeys) {
                        mutated = true;
                        const write = database.transaction(STORES.groupKeys, 'readwrite');
                        write.objectStore(STORES.groupKeys).put({ namespace: '104', groupID: 'g200', version: 1, key: changed[1] });
                    }
                }, { capture: true });
            }
        });
        const result = await settles(engine.migratePrivateKeys());
        database.observe(undefined);
        assert.true(mutated, 'A separate native transaction changed the migration snapshot');
        assert.true(result.error instanceof Error && result.error.code === 'MIGRATION_CONFLICT', 'Stale migration rejects rather than overwriting the mutation');
        database.acknowledgeAborts();
        assert.true((await readRecord(database, 'groupKeys', ['104', 'g200', 1])).d === changed[1].d, 'The concurrent group value remains intact');
        assert.true((await readRecord(database, 'privateKeys', '104')).d === identity[1].d, 'The identity was not partially migrated');
        const retry = await settles(engine.migratePrivateKeys());
        assert.true(!retry.error, 'A fresh explicit migration snapshot succeeds');
    });

    QUnit.test('Private JWK insertion and derivation are rejected outside the migration path', async function (assert) {
        const pair = await legacyPair();
        await assert.rejects(this.alice.engine.getDerivedKey(this.bob.publicKey, pair[1]),
            error => error.code === 'PRIVATE_KEY_MIGRATION_REQUIRED', 'Low-level derivation cannot silently import a private JWK');
        await assert.rejects(this.alice.engine.addGroupKeys('g200', [{ version: 1, groupKey: pair[1] }]),
            error => error.code === 'INVALID_KEY', 'The ordinary group insertion API accepts only public keys');
        await assert.rejects(this.alice.engine.addPublicKey(this.bob.id, pair[1]),
            error => error.code === 'INVALID_KEY', 'Public insertion cannot accept private components');
        const exported = await crypto.subtle.importKey('jwk', pair[1], algorithm, true, ['deriveKey']);
        await assert.rejects(this.alice.engine.getDerivedKey(this.bob.publicKey, exported),
            error => error.code === 'INVALID_PRIVATE_KEY', 'Extractable private CryptoKeys cannot bypass the default');
        assert.deepEqual(await this.alice.engine.getCachedGroupVersions('g200'), [], 'Rejected private insertion creates no group record');
    });

    QUnit.test('Explicit flat migration including selected private groups rolls back deletions on abort', async function (assert) {
        const database = await this.open(undefined, { upgrade(db) {
            db.createObjectStore('publicKeys', { keyPath: 'accID' });
            db.createObjectStore('privateKeys', { keyPath: 'accID' });
            db.createObjectStore('groupKeys', { keyPath: ['groupID', 'version'] });
        } });
        const identity = await legacyPair();
        const group = await legacyPair();
        const tx = database.transaction(['publicKeys', 'privateKeys', 'groupKeys'], 'readwrite');
        tx.objectStore('publicKeys').put({ ...identity[0], accID: '104' });
        tx.objectStore('privateKeys').put({ ...identity[1], accID: '104' });
        tx.objectStore('privateKeys').put({ ...group[1], accID: '999' });
        tx.objectStore('groupKeys').put({ ...group[1], groupID: 'g200', version: '1' });
        await database.whenIdle();
        const engine = new Be8('104', database.connection);
        const options = { legacyIdentity: true, legacyGroups: [{ groupID: 'g200', version: '1' }] };
        let deleted = false;
        database.observe(tx => {
            if (tx.mode === 'readwrite' && tx.objectStoreNames.contains('privateKeys')) {
                tx.addEventListener('success', event => {
                    if (event.target.source?.name === 'privateKeys' && event.target.result === undefined) {
                        deleted = true;
                        tx.abort();
                    }
                }, { capture: true });
            }
        });
        const failed = await settles(engine.migratePrivateKeys(options));
        database.observe(undefined);
        assert.true(deleted && failed.error instanceof Error, 'Successful legacy deletion followed by abort rejects migration');
        database.acknowledgeAborts();
        assert.true((await readRecord(database, 'privateKeys', '104')) === undefined, 'No scoped private identity escaped rollback');
        const before = await records(database, ['privateKeys', 'groupKeys']);
        assert.true(before[0].some(record => record.accID === '104' && record.d === identity[1].d)
            && before[1][0].d === group[1].d, 'Both selected original private records survive');
        const success = await settles(engine.migratePrivateKeys(options));
        assert.true(!success.error && success.value.migratedGroups === 1, 'Explicit flat migration commits identity and selected group');
        assert.true(await fingerprint(await engine.getMyPublicKey()) === await fingerprint(identity[0]), 'Flat migration keeps the public fingerprint');
        const remaining = await records(database, ['privateKeys', 'groupKeys']);
        assert.true(remaining[0].length === 1 && remaining[0][0].accID === '999' && remaining[1].length === 0,
            'Selected private originals are gone after success; other accounts remain untouched');
        assert.true(noPrivateJWK(await records(database, [STORES.privateKeys, STORES.groupKeys])), 'New scoped records have no plaintext backup');
    });
    QUnit.test('Missing CryptoKey clone capability rejects generation and migration without a JWK fallback', async function (assert) {
        const fixture = await scopedFixture(this);
        const empty = await this.open();
        const fresh = new Be8('105', empty.connection);
        const originalClone = window.structuredClone;
        let generation;
        let migration;
        try {
            // Capability absence only; native WebCrypto is never mocked.
            window.structuredClone = undefined;
            generation = await settles(fresh.generatePrivAndPubKey());
            migration = await settles(fixture.engine.migratePrivateKeys());
        } finally { window.structuredClone = originalClone; }
        for (const result of [generation, migration]) {
            assert.true(result.error instanceof Error && result.error.code === 'CRYPTOKEY_STORAGE_UNSUPPORTED',
                'An unsupported browser receives a clear storage-capability error');
            assert.true(result.error.message.includes('CryptoKey'), 'The error names the required browser capability');
        }
        assert.deepEqual(await storedIDs(empty), [], 'No exportable fallback identity was stored');
        assert.true((await readRecord(fixture.database, 'privateKeys', '104')).d === fixture.identity[1].d,
            'Migration failure keeps the original private record');
    });

    QUnit.test('A native DataCloneError after a public write rejects storage and rolls back the queued mutation', async function (assert) {
        const database = await this.open();
        const result = await settles(withTransaction(database.connection, [STORES.publicKeys, STORES.privateKeys], 'readwrite', tx =>
            nativeResult(tx.objectStore(STORES.publicKeys).put({ namespace: '104', accID: '104', key: this.alice.publicKey }),
                () => nativeResult(tx.objectStore(STORES.privateKeys).put({ namespace: '104', accID: '104',
                    // An actually unclonable value triggers the native browser error.
                    key: () => undefined })))));
        assert.true(result.error instanceof Error && result.error.code === 'CRYPTOKEY_STORAGE_UNSUPPORTED'
            && result.error.name === 'DataCloneError', 'Native clone failure is propagated as a meaningful Error');
        assert.strictEqual(database.acknowledgeAborts(), 1, 'The failed storage transaction aborted');
        assert.deepEqual(await storedIDs(database, 'publicKeys'), [], 'The successful public write was rolled back');
        assert.deepEqual(await storedIDs(database), [], 'No private fallback or partial identity remains');
    });

    QUnit.test('Concurrent migrations settle without rotation; namespace ownership also protects migration', async function (assert) {
        const { engine, database, identity } = await scopedFixture(this);
        const secondDB = await this.open(database.name);
        const other = new Be8('104', secondDB.connection);
        const concurrent = await settles(Promise.allSettled([engine.migratePrivateKeys(), other.migratePrivateKeys()]));
        assert.true(!concurrent.error, 'All independent migration promises settle');
        assert.true(concurrent.value.some(result => result.status === 'fulfilled'), 'At least one atomic migration commits');
        assert.true(concurrent.value.every(result => result.status === 'fulfilled' || result.reason.code === 'MIGRATION_CONFLICT'),
            'A stale concurrent migration can only report a conflict');
        database.acknowledgeAborts();
        secondDB.acknowledgeAborts();
        const repeated = await settles(other.migratePrivateKeys());
        assert.true(!repeated.error && !repeated.value.migratedIdentity, 'Explicit retry sees the committed migration');
        assert.true(await fingerprint(await engine.getMyPublicKey()) === await fingerprint(identity[0]), 'The shared identity remains unchanged');
        const wrongOwner = new Be8('105', database.connection, { namespace: '104' });
        const refused = await settles(wrongOwner.migratePrivateKeys());
        assert.true(refused.error instanceof Error && refused.error.code === 'ACCOUNT_MISMATCH', 'A different account cannot migrate this namespace');
        database.acknowledgeAborts();
        assert.true(noPrivateJWK(await records(database, [STORES.privateKeys, STORES.groupKeys])), 'The winning migration has no leftover private JWKs');
    });

    QUnit.test('A reference to a cleared identity cannot silently select a replacement key', async function (assert) {
        const { engine } = this.alice;
        const before = await engine.generatePrivAndPubKey();
        await engine.panic();
        await engine.setup();
        await assert.rejects(engine.getDerivedKey(this.bob.publicKey, before.keyReference),
            error => error.code === 'KEY_REFERENCE_INVALID', 'The old capability is invalid after explicit clearing and new setup');
    });

});
