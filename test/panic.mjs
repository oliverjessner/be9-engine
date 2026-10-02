import Be8, { STORES, jwkThumbprint } from '../lib/bundle.mjs';
import { participantHooks, exchangePublicKeys } from './participants.mjs';
import { withTransaction, requestResult } from '../lib/persistence.mjs';
const locked = error => error.code === 'ENGINE_LOCKED';
const failed = error => error instanceof Error;
const rows = (database, name) => withTransaction(database.connection, [name], 'readonly', tx => requestResult(tx.objectStore(name).getAll()));
function workerCall(worker, message) {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => finish(undefined, new Error('Worker fixture deadline exceeded')), 5000);
        const finish = (value, error) => { clearTimeout(timeout); worker.removeEventListener('message', onMessage); worker.removeEventListener('error', onError); error ? reject(error) : resolve(value); };
        const onMessage = event => finish(event.data);
        const onError = () => finish(undefined, new Error('Worker fixture failed'));
        worker.addEventListener('message', onMessage, { once: true }); worker.addEventListener('error', onError, { once: true });
        worker.postMessage(message);
    });
}
QUnit.module('Panic / namespace lifecycle invalidation', hooks => {
    participantHooks(hooks);
    QUnit.test('Panic locks synchronously, commits a tombstone, releases references and is idempotent', async function (assert) {
        const { alice, bob } = this; await exchangePublicKeys(alice, bob);
        const before = await alice.engine.generatePrivAndPubKey();
        const context = await alice.createContext(bob.publicKey);
        const pending = alice.engine.panic();
        assert.strictEqual(alice.engine.panic(), pending, 'Concurrent repeat shares deletion promise');
        await assert.rejects(alice.engine.encryptText(context.key, 'Input'), locked, 'Even raw AES operations reject immediately');
        await assert.rejects(alice.engine.generatePrivAndPubKey(), locked, 'No new identity operation is accepted');
        await assert.rejects(alice.engine.getDerivedKey(bob.publicKey, before.keyReference, context.derivation), locked, 'Old references cannot resume an invalidated instance');
        await pending;
        assert.strictEqual(alice.database.pendingWrites(), 0, 'Deletion success follows commit');
        for (const name of [STORES.privateKeys, STORES.publicKeys, STORES.trust, STORES.contexts, STORES.sendState, STORES.receiveState]) assert.deepEqual(await rows(alice.database, name), [], 'Selected security store was cleared');
        const scope = (await rows(alice.database, STORES.scopes))[0];
        assert.strictEqual(scope.status, 'invalidated', 'Persistent tombstone survives deletion');
        assert.strictEqual(scope.generation, 1, 'Persistent generation advances');
        assert.strictEqual(alice.engine.panic(), pending, 'Post-commit repeat remains idempotent');
        assert.true(await bob.engine.hasGeneratedKeys(), 'Independent recipient identity is unchanged');
    });
    QUnit.test('Encryption invalidated after a committed reservation releases no result or new state', async function (assert) {
        const { alice, bob } = this; await exchangePublicKeys(alice, bob); await alice.engine.openContext('pending encryption');
        let deletion;
        alice.database.observe(tx => {
            if (!deletion && tx.mode === 'readwrite' && tx.objectStoreNames.contains(STORES.keyUsage)) tx.addEventListener('complete', () => { deletion = alice.engine.panic(); }, { once: true });
        });
        await assert.rejects(alice.engine.encryptTextSimple(alice.id, bob.id, 'Pending plaintext', { contextID: 'pending encryption' }), locked, 'Pending encryption never releases a packet after invalidation');
        alice.database.observe(undefined); assert.true(!!deletion, 'Native reservation completion triggered panic'); await deletion;
        alice.database.acknowledgeAborts();
        assert.deepEqual(await rows(alice.database, STORES.privateKeys), [], 'No late identity survives');
        assert.deepEqual(await rows(alice.database, STORES.sendState), [], 'No late send state survives');
        assert.strictEqual((await rows(alice.database, STORES.keyUsage)).length, 1, 'Committed actual-key nonce reservation is never refunded');
    });
    QUnit.test('Authenticated receive invalidated at commit never releases plaintext', async function (assert) {
        const { alice, bob } = this; await exchangePublicKeys(alice, bob); await alice.engine.openContext('pending receive');
        const expected = { sender: alice.id, receiver: bob.id, contextID: 'pending receive', purpose: 'data' };
        await bob.engine.openReceiveContext(expected);
        const packet = await alice.engine.encryptTextSimple(alice.id, bob.id, 'Pending output', { contextID: 'pending receive' });
        let deletion;
        bob.database.observe(tx => { if (!deletion && tx.mode === 'readwrite' && tx.objectStoreNames.contains(STORES.receiveState)) tx.addEventListener('complete', () => { deletion = bob.engine.panic(); }, { once: true }); });
        await assert.rejects(bob.engine.receiveText(packet, expected), locked, 'Commit alone cannot release output after local invalidation');
        bob.database.observe(undefined); assert.true(!!deletion, 'A real acceptance transaction completed'); await deletion; bob.database.acknowledgeAborts();
        assert.deepEqual(await rows(bob.database, STORES.receiveState), [], 'Replay state is deleted with keys');
    });
    QUnit.test('Initialization invalidated while pending cannot persist or return a replacement identity', async function (assert) {
        const database = await this.open(); const engine = new Be8('104', database.connection); let deletion;
        database.observe(tx => { if (!deletion && tx.mode === 'readonly' && tx.objectStoreNames.contains(STORES.privateKeys)) tx.addEventListener('complete', () => { deletion = engine.panic(); }, { once: true }); });
        await assert.rejects(engine.setup(), failed, 'Pending initialization settles without success'); database.observe(undefined); await deletion; database.acknowledgeAborts();
        assert.true(!!deletion, 'Native initial read completion triggered invalidation');
        assert.deepEqual(await rows(database, STORES.privateKeys), [], 'No identity write can follow invalidation');
        await assert.rejects(engine.setup(), locked, 'Retry requires explicit reinitialization');
        const reopened = new Be8('104', (await this.open(database.name)).connection);
        await assert.rejects(reopened.setup(), locked, 'Restart cannot replace invalidated identity');
        this.databases.forEach(db => db.acknowledgeAborts());
    });
    QUnit.test('Aborted deletion leaves every security record intact but instances locked; explicit retry succeeds', async function (assert) {
        const { alice, bob } = this; await exchangePublicKeys(alice, bob);
        await alice.engine.openContext('group wrapping');
        await alice.engine.createGroupEpoch('gPending', '1', [bob.id], { contextID: 'group wrapping' });
        await alice.engine.activateGroupEpoch('gPending', '1', { expectedCurrentEpoch: null });
        const otherDB = await this.open(alice.database.name); const other = new Be8(alice.id, otherDB.connection); await other.setup();
        const before = await Promise.all(Object.values(STORES).map(name => rows(alice.database, name)));
        let abort = false;
        alice.database.observe(tx => { if (tx.mode === 'readwrite' && tx.objectStoreNames.contains(STORES.groupEpochs)) tx.addEventListener('success', event => {
            if (!abort && event.target.source?.name === STORES.privateKeys && event.target.result === undefined) { abort = true; tx.abort(); }
        }, { capture: true }); });
        await assert.rejects(alice.engine.panic(), failed, 'Successful delete request followed by abort rejects panic');
        alice.database.observe(undefined); assert.true(abort, 'A native delete succeeded before abort'); alice.database.acknowledgeAborts(); otherDB.acknowledgeAborts();
        await assert.rejects(alice.engine.setup(), locked, 'Initiating instance remains locked after failure');
        await assert.rejects(other.setup(), locked, 'Other live instance is conservatively locked too');
        assert.deepEqual(await Promise.all(Object.values(STORES).map(name => rows(alice.database, name))), before, 'Keys, epochs, active selection, replay and lifecycle all rolled back');
        await assert.rejects(alice.engine.reinitialize(), error => error.code === 'REINITIALIZATION_REQUIRED', 'Failed deletion cannot bypass the required tombstone'); alice.database.acknowledgeAborts();
        await alice.engine.panic();
        for (const name of [STORES.groupEpochs, STORES.activeEpochs, STORES.contexts, STORES.sendState]) assert.deepEqual(await rows(alice.database, name), [], 'Successful retry deletes grouped security state');
    });
    QUnit.test('Another connection is immediately locked; restart and explicit reinitialization preserve lifecycle boundaries', async function (assert) {
        const { alice, bob } = this; await exchangePublicKeys(alice, bob); const previous = await jwkThumbprint(alice.publicKey);
        const otherDB = await this.open(alice.database.name); const other = new Be8(alice.id, otherDB.connection); await other.setup();
        const oldRef = await other.generatePrivAndPubKey(); const context = await other.createDerivationContext(bob.publicKey, oldRef.keyReference, { contextID: 'other realm', sender: alice.id, receiver: bob.id, purpose: 'data' });
        const pending = alice.engine.panic(); await assert.rejects(other.encryptText(context.key, 'Blocked'), locked, 'Other connection cannot use cached derived key immediately'); await pending;
        alice.database.close(); otherDB.close(); const restartedDB = await this.open(alice.database.name); const restarted = new Be8(alice.id, restartedDB.connection);
        await assert.rejects(restarted.setup(), locked, 'Restart sees persistent invalidation'); restartedDB.acknowledgeAborts();
        const first = restarted.reinitialize(); assert.strictEqual(restarted.reinitialize(), first, 'Parallel explicit reinitialization coalesces'); await first;
        assert.notStrictEqual(await jwkThumbprint(await restarted.getMyPublicKey()), previous, 'Explicit reinitialization creates a new identity');
        await assert.rejects(other.setup(), locked, 'Old instance never adopts the new generation');
        await assert.rejects(restarted.getDerivedKey(bob.publicKey, oldRef.keyReference, context.derivation), error => error.code === 'INVALID_PRIVATE_KEY', 'Old reference does not cross into the new generation');
        assert.strictEqual((await rows(restartedDB, STORES.scopes))[0].generation, 2, 'Reinitialization advances generation separately');
        await assert.rejects(restarted.encryptTextSimple(alice.id, bob.id, 'Untrusted after reset'), error => error.code === 'INVALID_KEY', 'New generation must explicitly reinstall peer trust');
    });
    QUnit.test('Persisted invalidation also blocks cached keys in a separate JS realm and stale panic cannot delete a new identity', async function (assert) {
        const { alice } = this;
        const worker = new Worker('/test/panic-worker.mjs', { type: 'module' });
        try {
            assert.strictEqual((await workerCall(worker, { command: 'open', name: alice.database.name, accID: alice.id })).status, 'ready', 'Worker owns its own native key and connection');
            await alice.engine.panic();
            assert.deepEqual(await workerCall(worker, { command: 'probe' }), { encryption: 'ENGINE_LOCKED', setup: 'ENGINE_LOCKED' }, 'Persistent state blocks stale raw AES and setup across realms');
            await alice.engine.reinitialize(); const current = await alice.engine.getMyPublicKey();
            assert.deepEqual(await workerCall(worker, { command: 'panic' }), { panic: 'ENGINE_LOCKED' }, 'Stale generation cannot delete a newly initialized identity');
            assert.strictEqual((await alice.engine.getMyPublicKey()).x, current.x, 'New identity remains usable and unchanged');
        } finally { worker.terminate(); }
    });
    QUnit.test('Deletion is namespace-local; foreign accounts, unscoped legacy data and application stores remain intact', async function (assert) {
        const database = await this.open(undefined, { upgrade(db) { db.createObjectStore('appData', { keyPath: 'id' }); db.createObjectStore('privateKeys', { keyPath: 'accID' }); } });
        const first = new Be8('104', database.connection, { namespace: 'first' }); const second = new Be8('105', database.connection, { namespace: 'second' });
        await first.setup(); await second.setup(); const original = await second.getMyPublicKey();
        await withTransaction(database.connection, ['appData', 'privateKeys'], 'readwrite', tx => { tx.objectStore('appData').put({ id: 'setting', value: true }); return requestResult(tx.objectStore('privateKeys').put({ accID: '106', marker: 'application-owned legacy data' })); });
        const before = await rows(database, 'privateKeys');
        await first.panic(); assert.strictEqual((await second.getMyPublicKey()).x, original.x, 'Foreign account remains available');
        assert.deepEqual(await rows(database, 'privateKeys'), before, 'Unscoped data is not claimed by panic');
        assert.deepEqual(await rows(database, 'appData'), [{ id: 'setting', value: true }], 'Application store is untouched');
        assert.strictEqual((await rows(database, STORES.privateKeys)).length, 1, 'Only selected namespace private record is removed');
    });
    QUnit.test('Malformed or lost lifecycle state never defaults to a new active identity', async function (assert) {
        const { alice } = this; const original = (await rows(alice.database, STORES.scopes))[0];
        const change = value => withTransaction(alice.database.connection, [STORES.scopes], 'readwrite', tx => requestResult(value
            ? tx.objectStore(STORES.scopes).put(value) : tx.objectStore(STORES.scopes).delete(alice.id)));
        for (const patch of [{ status: null }, { generation: null }, { generation: -1 }]) {
            await change({ ...original, ...patch });
            await assert.rejects(alice.engine.setup(), error => error.code === 'INVALID_LIFECYCLE', 'Present malformed fields do not receive old-schema defaults'); alice.database.acknowledgeAborts();
            assert.strictEqual((await rows(alice.database, STORES.privateKeys)).length, 1, 'Original key is retained without replacement');
        }
        await change(undefined);
        await assert.rejects(alice.engine.setup(), error => error.code === 'INVALID_LIFECYCLE', 'Previously bound instance refuses a missing lifecycle record'); alice.database.acknowledgeAborts();
        assert.strictEqual((await rows(alice.database, STORES.privateKeys)).length, 1, 'State loss does not delete or rotate the original identity');
    });
    QUnit.test('Panic during reinitialization aborts a successful key request and never releases or persists the new generation', async function (assert) {
        const { alice } = this; await alice.engine.panic(); let interruption, triggered = false;
        alice.database.observe(tx => { if (tx.mode === 'readwrite' && tx.objectStoreNames.contains(STORES.privateKeys)) tx.addEventListener('success', event => {
            if (!triggered && event.target.source?.name === STORES.privateKeys && Array.isArray(event.target.result)) { triggered = true; interruption = alice.engine.panic(); }
        }, { capture: true }); });
        await assert.rejects(alice.engine.reinitialize(), failed, 'Pending reinitialization does not escape subsequent panic'); alice.database.observe(undefined); await interruption; alice.database.acknowledgeAborts();
        assert.true(triggered, 'A native candidate-key request was successful before invalidation');
        assert.deepEqual(await rows(alice.database, STORES.privateKeys), [], 'No candidate identity survived rollback');
        assert.strictEqual((await rows(alice.database, STORES.scopes))[0].status, 'invalidated', 'Persistent tombstone remains intact');
        await assert.rejects(alice.engine.setup(), locked, 'Instance remains locked');
    });
});
