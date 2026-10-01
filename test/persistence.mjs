import Be8, { STORES, upgradeBe8Schema } from '../lib/bundle.mjs';
import { requestResult, transactionComplete, withTransaction } from '../lib/persistence.mjs';
import { participantHooks, exchangePublicKeys, createParticipant, isAuthenticationFailure } from './participants.mjs';
import { storedIDs, readRecord } from './database.mjs';

// These are failure deadlines, never fixed readiness waits. A hung operation
// rejects the TEST rather than being mistaken for an expected engine rejection.
async function outcome(promise) {
    let timer;
    const deadline = new Promise((resolve, reject) => {
        timer = setTimeout(() => reject(new Error('Test operation did not settle')), 5000);
    });
    try {
        return await Promise.race([
            Promise.resolve(promise).then(value => ({ status: 'fulfilled', value }),
                error => ({ status: 'rejected', error })),
            deadline,
        ]);
    } finally {
        clearTimeout(timer);
    }
}

function rejected(assert, result, message) {
    assert.strictEqual(result.status, 'rejected', message);
    assert.true(result.error instanceof Error, 'Failure is an Error object');
}

function abortSuccessfulWrite(database, storeName, seen) {
    database.observe(tx => {
        if (tx.mode !== 'readwrite' || !tx.objectStoreNames.contains(storeName)) return;
        tx.addEventListener('success', event => {
            if (event.target.source?.name === storeName && Array.isArray(event.target.result)
                && event.target.result.length === 2 && typeof event.target.result[0] === 'string') {
                seen.success = true;
                tx.abort();
            }
        }, { capture: true });
    });
}

QUnit.module('Persistence / native failures and concurrency', hooks => {
    participantHooks(hooks);

    QUnit.test('An aborted identity transaction rolls back both halves after one successful write', async function (assert) {
        const database = await this.open();
        const engine = new Be8('104', database.connection);
        const seen = {};
        abortSuccessfulWrite(database, STORES.publicKeys, seen);
        const result = await outcome(engine.generatePrivAndPubKey());
        rejected(assert, result, 'Generation rejects instead of reporting a successful request as a commit');
        assert.true(seen.success, 'The public-key write actually succeeded before the transaction was aborted');
        assert.strictEqual(database.pendingWrites(), 0, 'The rejection waits for the terminal transaction signal');
        database.observe(undefined);
        assert.strictEqual(database.acknowledgeAborts(), 1, 'One native transaction aborted');
        assert.deepEqual(await storedIDs(database, 'publicKeys'), [], 'Public write was rolled back');
        assert.deepEqual(await storedIDs(database), [], 'Private write was rolled back');
        assert.false(await engine.hasGeneratedKeys(), 'No uncommitted identity is exposed');
        await outcome(engine.setup());
        assert.true(await engine.hasGeneratedKeys(), 'An explicit retry succeeds after the failure');
    });

    QUnit.test('A real constraint error rejects the whole batch even when another listener prevents default', async function (assert) {
        const database = await this.open(undefined, { upgrade(db, tx) {
            tx.objectStore(STORES.publicKeys).createIndex('testUniquePoint', ['namespace', 'key.x'], { unique: true });
        } });
        const engine = new Be8('104', database.connection);
        await engine.setup();
        database.observe(tx => tx.addEventListener('error', event => event.preventDefault()));
        const result = await outcome(engine.addPublicKeys([
            { accID: '102', publicKey: this.bob.publicKey },
            { accID: '103', publicKey: this.bob.publicKey },
        ]));
        rejected(assert, result, 'A native unique-index violation rejects the batch');
        assert.strictEqual(result.error?.name, 'ConstraintError', 'The native failure category is preserved without raw data');
        database.observe(undefined);
        assert.strictEqual(database.acknowledgeAborts(), 1, 'The failed batch was aborted');
        assert.deepEqual(await storedIDs(database, 'publicKeys'), ['104'], 'No partial batch is stored');
        await assert.rejects(engine.encryptTextSimple('104', '102', 'Input'), /Missing public key/,
            'An uncommitted peer key is unavailable to the engine');
        await outcome(engine.addPublicKey('102', this.bob.publicKey));
        assert.deepEqual(await storedIDs(database, 'publicKeys'), ['102', '104'], 'A later mutation still completes');
    });

    QUnit.test('Read failure in setup does not generate an identity and can be retried', async function (assert) {
        const database = await this.open();
        const engine = new Be8('104', database.connection);
        let writes = 0;
        database.observe(tx => {
            if (tx.mode === 'readwrite') writes++;
            if (tx.mode === 'readonly' && tx.objectStoreNames.contains(STORES.privateKeys)) {
                tx.addEventListener('success', event => {
                    if (event.target.source?.name === STORES.privateKeys) tx.abort();
                }, { capture: true });
            }
        });
        rejected(assert, await outcome(engine.setup()), 'setup rejects a native read abort');
        assert.strictEqual(writes, 0, 'No identity write is attempted after a failed read');
        database.observe(undefined);
        assert.strictEqual(database.acknowledgeAborts(), 1, 'The failed read transaction terminated');
        assert.deepEqual(await storedIDs(database), [], 'No replacement identity was stored');
        const result = await outcome(engine.setup());
        assert.strictEqual(result.status, 'fulfilled', 'The setup single-flight resets after failure');
        assert.true(await engine.hasGeneratedKeys(), 'Retry produces an identity only after a successful read');
    });

    QUnit.test('Closed database operations settle as Errors, including setup and mutations', async function (assert) {
        const database = await this.open();
        const engine = new Be8('104', database.connection);
        database.close();
        for (const operation of [
            () => engine.setup(), () => engine.getCachedKeys(), () => engine.getMyPublicKey(),
            () => engine.addPublicKey('102', this.bob.publicKey), () => engine.panic(),
        ]) {
            rejected(assert, await outcome(operation()), 'The closed database rejects without hanging');
        }
    });

    QUnit.test('Request results and transaction completion remain separate; pending aborts settle', async function (assert) {
        const database = await this.open();
        const tx = database.transaction(STORES.publicKeys, 'readonly');
        const done = transactionComplete(tx);
        const request = requestResult(tx.objectStore(STORES.publicKeys).getAll());
        tx.abort();
        const results = await outcome(Promise.allSettled([request, done]));
        assert.strictEqual(results.status, 'fulfilled', 'Both observer promises settled');
        assert.true(results.value.every(result => result.status === 'rejected' && result.reason instanceof Error),
            'The aborted request and transaction each reject as Errors');
        assert.strictEqual(database.acknowledgeAborts(), 1, 'Native abort was observed');
    });

    QUnit.test('Success of a read request followed by abort still rejects the read method', async function (assert) {
        const database = this.alice.database;
        let readSucceeded = false;
        database.observe(tx => {
            if (tx.mode !== 'readonly' || !tx.objectStoreNames.contains(STORES.publicKeys)) return;
            tx.addEventListener('success', event => {
                if (event.target.source?.name === STORES.publicKeys) {
                    readSucceeded = true;
                    tx.abort();
                }
            }, { capture: true });
        });
        rejected(assert, await outcome(this.alice.engine.getMyPublicKey()), 'A successful request cannot conceal an aborted transaction');
        assert.true(readSucceeded, 'The read request succeeded before abort');
        database.observe(undefined);
        assert.strictEqual(database.acknowledgeAborts(), 1, 'The transaction terminated');
        assert.true(await this.alice.engine.hasGeneratedKeys(), 'The persisted identity remains intact');
    });

    QUnit.test('Synchronous scheduling errors abort already queued writes', async function (assert) {
        const database = this.alice.database;
        const result = await outcome(withTransaction(database.connection, [STORES.publicKeys], 'readwrite', tx => {
            tx.objectStore(STORES.publicKeys).put({
                namespace: this.alice.id, accID: this.bob.id, key: this.bob.publicKey,
            });
            throw new Error('Test scheduling error');
        }));
        rejected(assert, result, 'Scheduling failure rejects the transaction');
        assert.strictEqual(database.acknowledgeAborts(), 1, 'The transaction aborted');
        assert.deepEqual(await storedIDs(database, 'publicKeys'), ['101'], 'The queued mutation was rolled back');
    });

    QUnit.test('Parallel setup on one instance is coalesced and repeat setup retains the identity', async function (assert) {
        const database = await this.open();
        const engine = new Be8('104', database.connection);
        const first = engine.setup();
        assert.strictEqual(engine.setup(), first, 'Parallel initialization shares a single pending promise');
        const result = await outcome(Promise.all([first, engine.setup(), engine.setup()]));
        assert.strictEqual(result.status, 'fulfilled', 'All setup callers settle');
        const before = await engine.getMyPublicKey();
        await outcome(engine.setup());
        const after = await engine.getMyPublicKey();
        assert.true(before.x === after.x && before.y === after.y, 'Repeated setup does not rotate the identity');
        assert.deepEqual(await storedIDs(database), ['104'], 'Exactly one private identity is present');
    });

    QUnit.test('Independent connections racing setup retain the same committed identity', async function (assert) {
        const database = await this.open();
        const secondDB = await this.open(database.name);
        const left = new Be8('104', database.connection);
        const right = new Be8('104', secondDB.connection);
        const result = await outcome(Promise.all([left.setup(), right.setup()]));
        assert.strictEqual(result.status, 'fulfilled', 'Both independent initializers finish');
        const leftKey = await left.getMyPublicKey();
        const rightKey = await right.getMyPublicKey();
        assert.true(leftKey.x === rightKey.x && leftKey.y === rightKey.y, 'Both retain the winner of the atomic initialization');
        const regenerated = await right.generatePrivAndPubKey();
        assert.true(regenerated.publicKey.x === leftKey.x, 'Explicit generation is idempotent rather than implicit rotation');
        assert.deepEqual(await storedIDs(database), ['104'], 'One private identity is committed');
        await left.addPublicKey(this.bob.id, this.bob.publicKey);
        await this.bob.engine.addPublicKey('104', leftKey);
        const packet = await right.encryptTextSimple('104', this.bob.id, 'Independent connection');
        assert.true(await this.bob.engine.decryptTextSimple('104', this.bob.id, packet.cipherText, packet.iv) === 'Independent connection',
            'The other connection sees a committed public-key mutation without stale state');
    });

    QUnit.test('Parallel mutations on independent connections agree with the final database state', async function (assert) {
        const database = this.alice.database;
        const secondDB = await this.open(database.name);
        const other = new Be8(this.alice.id, secondDB.connection);
        await other.setup();
        const result = await outcome(Promise.all([
            this.alice.engine.addPublicKey(this.bob.id, this.bob.publicKey),
            other.addPublicKey(this.bob.id, this.eve.publicKey),
        ]));
        assert.strictEqual(result.status, 'fulfilled', 'Both concurrent mutations commit');
        const stored = await readRecord(database, 'publicKeys', [this.alice.id, this.bob.id]);
        assert.true(stored.x === this.eve.publicKey.x, 'The last scheduled transaction wins');
        const packet = await this.alice.engine.encryptTextSimple(this.alice.id, this.bob.id, 'Latest committed key');
        const eveKey = await this.eve.derive(this.alice.publicKey);
        assert.true(await this.eve.engine.decryptText(eveKey, packet.cipherText, packet.iv) === 'Latest committed key',
            'The earlier instance reads the final committed key instead of an older cached value');
        const bobKey = await this.bob.derive(this.alice.publicKey);
        await assert.rejects(this.bob.engine.decryptText(bobKey, packet.cipherText, packet.iv),
            isAuthenticationFailure, 'The replaced peer key is no longer used for encryption');
    });

    QUnit.test('All read methods open readonly transactions', async function (assert) {
        const modes = [];
        this.alice.database.observe(tx => modes.push(tx.mode));
        await this.alice.engine.getCachedKeys();
        await this.alice.engine.getMyPublicKey();
        await this.alice.engine.getCachedGroupKeys();
        await this.alice.engine.getCachedGroupVersions('g200');
        await this.alice.engine.hasGeneratedKeys();
        await this.alice.engine.hasKey(this.alice.id);
        this.alice.database.observe(undefined);
        assert.true(modes.length >= 6 && modes.every(mode => mode === 'readonly'), 'Queries never open write transactions');
    });

    QUnit.test('Caller metadata and later object mutation cannot replace storage identity', async function (assert) {
        const key = { ...this.bob.publicKey, key_ops: [...this.bob.publicKey.key_ops],
            accID: this.eve.id, namespace: 'other', groupID: 'gwrong', version: 999 };
        const pending = this.alice.engine.addPublicKey(this.bob.id, key);
        key.x = this.eve.publicKey.x;
        key.y = this.eve.publicKey.y;
        key.key_ops.push('untrusted');
        await outcome(pending);
        const stored = await readRecord(this.alice.database, 'publicKeys', [this.alice.id, this.bob.id]);
        assert.true(stored.x === this.bob.publicKey.x && stored.y === this.bob.publicKey.y, 'The call snapshots JWK values');
        assert.false(stored.key_ops.includes('untrusted'), 'Nested caller arrays cannot mutate the saved key');
        assert.deepEqual(await storedIDs(this.alice.database, 'publicKeys'), ['101', '102'], 'Separately supplied account ID wins');
        await this.alice.engine.addGroupKeys('g200', [{ version: 1, groupKey: {
            ...this.bob.publicKey, namespace: 'other', groupID: 'gwrong', version: 999,
        } }]);
        const groups = await this.alice.engine.getCachedGroupKeys();
        assert.true(groups.length === 1 && groups[0].groupID === 'g200' && groups[0].version === 1,
            'Separately supplied group metadata wins');
    });

    QUnit.test('Existing identity public half cannot be overwritten or silently repaired', async function (assert) {
        rejected(assert, await outcome(this.alice.engine.addPublicKey(this.alice.id, this.bob.publicKey)),
            'A conflicting public half is rejected');
        assert.strictEqual(this.alice.database.acknowledgeAborts(), 1, 'The conflicting identity mutation aborted');
        assert.true(await this.alice.engine.hasGeneratedKeys(), 'The original complete identity remains');
        const database = await this.open();
        const incomplete = new Be8('104', database.connection);
        await incomplete.addPublicKey('104', this.bob.publicKey);
        const result = await outcome(incomplete.setup());
        rejected(assert, result, 'An existing incomplete identity is not replaced');
        assert.strictEqual(result.error?.code, 'INCOMPLETE_IDENTITY', 'The caller gets an explicit incomplete-identity error');
        assert.strictEqual(database.acknowledgeAborts(), 1, 'The incomplete-identity validation terminated the read transaction');
        assert.deepEqual(await storedIDs(database), [], 'No new private identity was generated');
        assert.deepEqual(await storedIDs(database, 'publicKeys'), ['104'], 'The existing public half was retained');
    });

    QUnit.test('Shared application database isolates accounts and namespace ownership', async function (assert) {
        const database = await this.open();
        const alice = new Be8('201', database.connection);
        const bob = new Be8('202', database.connection);
        await outcome(Promise.all([alice.setup(), bob.setup()]));
        const alicePub = await alice.getMyPublicKey();
        const bobPub = await bob.getMyPublicKey();
        await outcome(Promise.all([alice.addPublicKey('202', bobPub), bob.addPublicKey('201', alicePub)]));
        const packet = await alice.encryptTextSimple('201', '202', 'Shared database');
        assert.true(await bob.decryptTextSimple('201', '202', packet.cipherText, packet.iv) === 'Shared database',
            'Separate scopes interoperate using public exchange in the same application database');
        assert.deepEqual(await storedIDs(database, 'privateKeys', '201'), ['201'], 'Alice scope contains only Alice private key');
        assert.deepEqual(await storedIDs(database, 'privateKeys', '202'), ['202'], 'Bob scope contains only Bob private key');
        const wrongOwner = new Be8('203', database.connection, { namespace: '201' });
        for (const operation of [() => wrongOwner.setup(), () => wrongOwner.getCachedKeys(),
            () => wrongOwner.addPublicKey('202', this.bob.publicKey), () => wrongOwner.panic()]) {
            const result = await outcome(operation());
            rejected(assert, result, 'A different account cannot claim an already bound namespace');
            assert.strictEqual(result.error?.code, 'ACCOUNT_MISMATCH', 'The owner mismatch is explicit');
        }
        database.acknowledgeAborts();
        await alice.panic();
        assert.false(await alice.hasGeneratedKeys(), 'Explicit panic clears only Alice scope');
        assert.true(await bob.hasGeneratedKeys(), 'Bob retains his identity');
        assert.true((await bob.getMyPublicKey()).x === bobPub.x, 'Bob public identity is unchanged');
        assert.deepEqual(await storedIDs(database), ['202'], 'Only Alice private key was removed');
    });

    QUnit.test('Same account in different explicit namespaces retains separate identities', async function (assert) {
        const database = await this.open();
        const one = new Be8('201', database.connection, { namespace: 'tenant:one' });
        const two = new Be8('201', database.connection, { namespace: 'tenant:two' });
        await outcome(Promise.all([one.setup(), two.setup()]));
        const first = await one.getMyPublicKey();
        const second = await two.getMyPublicKey();
        assert.true(first.x !== second.x, 'The namespaces do not share private identity state');
        await one.addPublicKey(this.bob.id, this.bob.publicKey);
        assert.strictEqual((await two.getCachedKeys()).length, 1, 'Public peer caches do not leak across namespaces');
        for (const id of ['', ' ', '01', '-1', '1e2', 1]) {
            assert.throws(() => new Be8(id, database.connection), Error, 'Invalid or ambiguous account identifiers are rejected');
        }
        assert.throws(() => new Be8('201', database.connection, { namespace: ' ' }), Error, 'Empty namespace is rejected');
    });

    QUnit.test('Two different accounts racing for one namespace cannot both bind or mix data', async function (assert) {
        const database = await this.open();
        const one = new Be8('201', database.connection, { namespace: 'shared' });
        const two = new Be8('202', database.connection, { namespace: 'shared' });
        const result = await outcome(Promise.allSettled([one.setup(), two.setup()]));
        assert.strictEqual(result.status, 'fulfilled', 'Both competing initializers settled');
        assert.strictEqual(result.value.filter(value => value.status === 'fulfilled').length, 1, 'Exactly one account owns the namespace');
        const loser = result.value.find(value => value.status === 'rejected');
        assert.true(loser.reason instanceof Error && loser.reason.code === 'ACCOUNT_MISMATCH', 'The other account is explicitly rejected');
        assert.strictEqual(database.acknowledgeAborts(), 1, 'The losing initializer rolled back');
        const ids = await storedIDs(database, 'privateKeys', 'shared');
        assert.strictEqual(ids.length, 1, 'Only one private identity is committed');
        assert.deepEqual(await storedIDs(database, 'publicKeys', 'shared'), ids, 'Public and private halves belong to the same account');
    });

    QUnit.test('An incompatible schema aborts the application upgrade without replacing data', async function (assert) {
        const original = await this.open(undefined, { skipEngineSchema: true, upgrade(db) {
            db.createObjectStore(STORES.groupKeys, { keyPath: 'wrong' });
            db.createObjectStore('appSettings', { keyPath: 'id' });
        } });
        const tx = original.transaction('appSettings', 'readwrite');
        tx.objectStore('appSettings').put({ id: 'setting', value: true });
        await original.whenIdle();
        original.close();
        rejected(assert, await outcome(this.open(original.name, { version: 2 })), 'The incompatible upgrade fails and settles');
        const reopened = await this.open(original.name, { skipEngineSchema: true });
        assert.strictEqual(reopened.native.version, 1, 'The schema version was rolled back');
        assert.false(reopened.native.objectStoreNames.contains(STORES.scopes), 'Partially created engine stores were rolled back');
        assert.true((await readRecord(reopened, 'appSettings', 'setting')).value, 'Application records were preserved');
        assert.throws(() => upgradeBe8Schema(reopened.native), Error, 'Schema integration cannot run outside versionchange');
    });

    QUnit.test('Generated group private key persists, racing generation is idempotent, and versions cannot be overwritten', async function (assert) {
        const { alice, bob } = this;
        const secondDB = await this.open(alice.database.name);
        const other = new Be8(alice.id, secondDB.connection);
        await other.setup();
        const result = await outcome(Promise.all([
            alice.engine.generateGroupKeys(1, 'g200'), other.generateGroupKeys(1, 'g200'),
        ]));
        assert.strictEqual(result.status, 'fulfilled', 'Both group generators settle');
        assert.true(result.value[0].publicKey.x === result.value[1].publicKey.x, 'Both receive the committed group identity');
        const groupPublic = result.value[0].publicKey;
        await exchangePublicKeys(alice, bob);
        await bob.engine.addGroupKeys('g200', [{ version: 1, groupKey: groupPublic }]);
        await alice.engine.addGroupKeys('g200', [{ version: 1, groupKey: groupPublic }]);
        rejected(assert, await outcome(alice.engine.addGroupKeys('g200', [{ version: 1, groupKey: bob.publicKey }])),
            'A different key cannot overwrite the same group version');
        alice.database.acknowledgeAborts();
        const reopened = await createParticipant(alice.id, await this.open(alice.database.name));
        const packet = await bob.engine.encryptTextSimple(bob.id, 'g200:1', 'Retained private group key');
        assert.true(await reopened.engine.decryptTextSimple(bob.id, 'g200:1', packet.cipherText, packet.iv) === 'Retained private group key',
            'The reopened owner retains its private group key even after public reimport');
    });

    QUnit.test('Scoped panic aborts atomically and preserves application-owned stores', async function (assert) {
        const database = await this.open(undefined, { upgrade(db) {
            db.createObjectStore('appSettings', { keyPath: 'id' });
        } });
        const engine = new Be8('104', database.connection);
        await engine.setup();
        await engine.addPublicKey(this.bob.id, this.bob.publicKey);
        await engine.generateGroupKeys(1, 'g200');
        const tx = database.transaction('appSettings', 'readwrite');
        tx.objectStore('appSettings').put({ id: 'setting', value: true });
        await database.whenIdle();
        database.observe(tx => {
            if (tx.mode === 'readwrite' && tx.objectStoreNames.contains(STORES.groupKeys)) {
                tx.addEventListener('success', event => {
                    if (event.target.source?.name === STORES.publicKeys && event.target.result === undefined) tx.abort();
                }, { capture: true });
            }
        });
        rejected(assert, await outcome(engine.panic()), 'An abort during deletion rejects panic');
        database.observe(undefined);
        assert.strictEqual(database.acknowledgeAborts(), 1, 'The deletion transaction terminated');
        assert.true(await engine.hasGeneratedKeys(), 'Both identity halves survived rollback');
        assert.true(await engine.hasKey('g200:1'), 'The group key survived rollback');
        assert.strictEqual((await engine.getCachedKeys()).length, 2, 'Peer public keys survived rollback');
        await engine.panic();
        assert.false(await engine.hasGeneratedKeys(), 'Successful panic clears the current scope');
        assert.true((await readRecord(database, 'appSettings', 'setting')).value, 'Unrelated application data remains');
    });

    QUnit.test('Schema integration retains legacy stores; explicit migration atomically replaces the selected identity', async function (assert) {
        const original = await this.open(undefined, { skipEngineSchema: true, upgrade(db) {
            db.createObjectStore('publicKeys', { keyPath: 'accID' });
            db.createObjectStore('privateKeys', { keyPath: 'accID' });
            db.createObjectStore('groupKeys', { keyPath: ['groupID', 'version'] });
            db.createObjectStore('application', { keyPath: 'id' });
        } });
        rejected(assert, await outcome(new Be8('104', original.connection).setup()),
            'An application without schema integration is rejected instead of automatically upgraded');
        const cryptoPair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveKey', 'deriveBits']);
        const legacyPair = await Promise.all([crypto.subtle.exportKey('jwk', cryptoPair.publicKey),
            crypto.subtle.exportKey('jwk', cryptoPair.privateKey)]);
        // This owner's legacy identity is only migrated into its own new scope,
        // never into another participant's engine.
        const tx = original.transaction(['publicKeys', 'privateKeys', 'application'], 'readwrite');
        tx.objectStore('publicKeys').put({ ...legacyPair[0], accID: '104' });
        tx.objectStore('privateKeys').put({ ...legacyPair[1], accID: '104' });
        tx.objectStore('application').put({ id: 'setting', value: true });
        await original.whenIdle();
        original.close();
        const database = await this.open(original.name, { version: 2, upgrade(db, tx) { upgradeBe8Schema(db, tx); } });
        const owner = new Be8('104', database.connection);
        const result = await outcome(owner.setup());
        rejected(assert, result, 'Default setup refuses to silently create a new legacy identity');
        assert.strictEqual(result.error?.code, 'LEGACY_IDENTITY', 'The explicit migration requirement is reported');
        assert.deepEqual(await storedIDs(database), [], 'No new private identity was generated');
        const adoption = await outcome(owner.migratePrivateKeys({ legacyIdentity: true }));
        assert.strictEqual(adoption.status, 'fulfilled', 'Explicit identity adoption succeeds');
        assert.true((await owner.getMyPublicKey()).x === legacyPair[0].x, 'The same identity is retained');
        assert.strictEqual((await storedIDs(database, 'privateKeys')).length, 1, 'One scoped private identity is present');
        const oldTx = database.transaction(['publicKeys', 'privateKeys'], 'readonly');
        const oldCounts = await Promise.all(['publicKeys', 'privateKeys'].map(name =>
            requestResult(oldTx.objectStore(name).count())));
        await database.whenIdle();
        assert.deepEqual(oldCounts, [0, 0], 'Successful migration removes the original private JWK and its public identity record atomically');
        assert.true((await readRecord(database, 'application', 'setting')).value, 'Application records remain unchanged');
    });
});
