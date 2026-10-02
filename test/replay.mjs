import Be9, { STORES } from '../lib/bundle.mjs';
import { participantHooks, exchangePublicKeys } from './participants.mjs';
import { requestResult } from './database.mjs';
import { streamIdentity } from '../lib/replay.mjs';

const code = value => error => error instanceof Error && error.code === value;
async function row(database, store, key) {
    const tx = database.transaction(store, 'readonly');
    const value = await requestResult(tx.objectStore(store).get(key));
    await database.whenIdle();
    return value;
}
QUnit.module('v2 persistent receive and send sequences', hooks => {
    participantHooks(hooks);
    hooks.beforeEach(async function () {
        await exchangePublicKeys(this.alice, this.bob, this.eve);
        this.expected = { sender: this.alice.id, receiver: this.bob.id, contextID: 'replay-context', purpose: 'data' };
        await this.alice.engine.openContext(this.expected.contextID);
        await this.bob.engine.openReceiveContext(this.expected);
        this.send = text => this.alice.engine.encryptTextSimple(this.alice.id, this.bob.id, text, { contextID: this.expected.contextID });
    });
    QUnit.test('Repeated archive reads remain valid but duplicate acceptance rejects', async function (assert) {
        const packet = await this.send('one');
        assert.strictEqual(packet.header.sequence, '1', 'First sequence is canonical uint64');
        assert.true(await this.bob.engine.receiveText(packet, this.expected) === 'one', 'First authenticated receive commits');
        assert.strictEqual(this.bob.database.pendingWrites(), 0, 'Plaintext was returned only after commit');
        await assert.rejects(this.bob.engine.receiveText(packet, this.expected), code('REPLAY_DUPLICATE'), 'The same packet cannot be accepted twice');
        this.bob.database.acknowledgeAborts();
        assert.true(await this.bob.engine.decryptTextSimple('101', '102', packet) === 'one', 'Stored data remains decryptable');
        assert.true(await this.bob.engine.decryptTextSimple('101', '102', packet) === 'one', 'Archive reads never advance the window');
    });
    QUnit.test('Out-of-order inside the bounded window accepts; older data is rejected for receive', async function (assert) {
        const packets = [];
        for (let index = 0; index < 130; index++) packets.push(await this.send(String(index)));
        assert.true(await this.bob.engine.receiveText(packets[129], this.expected) === '129', 'Authenticated high sequence moves the window');
        assert.true(await this.bob.engine.receiveText(packets[2], this.expected) === '2', 'Distance 127 remains in the window');
        await assert.rejects(this.bob.engine.receiveText(packets[1], this.expected), code('REPLAY_TOO_OLD'), 'Distance 128 is outside the window');
        this.bob.database.acknowledgeAborts();
        const id = await streamIdentity(packets[129].header);
        const state = await row(this.bob.database, STORES.receiveState, ['102', this.expected.contextID, id]);
        assert.strictEqual(state.bitmap.length, 32, 'Replay state is a fixed 128-bit bitmap, not message history');
    });
    QUnit.test('Two connections processing the same packet accept at most once', async function (assert) {
        const packet = await this.send('parallel');
        const database = await this.open(this.bob.database.name);
        const other = new Be9('102', database.connection); await other.setup();
        const results = await Promise.allSettled([this.bob.engine.receiveText(packet, this.expected), other.receiveText(packet, this.expected)]);
        assert.strictEqual(results.filter(value => value.status === 'fulfilled').length, 1, 'One transaction commits acceptance');
        assert.true(results.some(value => value.reason?.code === 'REPLAY_DUPLICATE'), 'The other reports a duplicate');
        this.bob.database.acknowledgeAborts(); database.acknowledgeAborts();
    });
    QUnit.test('Forged high sequences and invalid authenticated text do not move the receive window', async function (assert) {
        const packet = await this.send('valid');
        await assert.rejects(this.bob.engine.receiveText({ ...packet, header: { ...packet.header, sequence: '18446744073709551615' } }, this.expected),
            error => error.name === 'OperationError', 'AAD authentication rejects the forged high counter');
        const binary = await this.alice.engine.encryptEnvelope('101', '102', new Uint8Array([255]), { contextID: this.expected.contextID, purpose: this.expected.purpose });
        await assert.rejects(this.bob.engine.receiveText(binary, this.expected), code('INVALID_TEXT'), 'Invalid text adapter output rejects before acceptance');
        assert.true(await this.bob.engine.receiveText(packet, this.expected) === 'valid', 'The first valid packet is still unseen');
    });
    QUnit.test('Restart retains both send counter and replay state', async function (assert) {
        const packet = await this.send('before restart');
        await this.bob.engine.receiveText(packet, this.expected);
        this.alice.database.close(); this.bob.database.close();
        const a = new Be9('101', (await this.open(this.alice.database.name)).connection);
        const bdb = await this.open(this.bob.database.name); const b = new Be9('102', bdb.connection);
        await Promise.all([a.setup(), b.setup()]);
        await a.openContext(this.expected.contextID); await b.openReceiveContext(this.expected);
        const next = await a.encryptTextSimple('101', '102', 'after restart', { contextID: this.expected.contextID });
        assert.strictEqual(next.header.sequence, '2', 'Reopening is idempotent rather than a counter reset');
        await assert.rejects(b.receiveText(packet, this.expected), code('REPLAY_DUPLICATE'), 'Previously accepted packet remains seen after restart');
        bdb.acknowledgeAborts();
        assert.true(await b.receiveText(next, this.expected) === 'after restart', 'The new sequence is accepted');
    });
    QUnit.test('Counter overflow, state loss and closed contexts never reset implicitly', async function (assert) {
        const packet = await this.send('seed');
        const id = await streamIdentity(packet.header); const key = ['101', this.expected.contextID, id];
        const original = await row(this.alice.database, STORES.sendState, key);
        const tx = this.alice.database.transaction(STORES.sendState, 'readwrite');
        tx.objectStore(STORES.sendState).put({ ...original, last: '18446744073709551614' }); await this.alice.database.whenIdle();
        assert.strictEqual((await this.send('final')).header.sequence, '18446744073709551615', 'Max uint64 value is lossless and usable once');
        await assert.rejects(this.send('overflow'), code('COUNTER_EXHAUSTED'), 'No wrap to zero'); this.alice.database.acknowledgeAborts();
        const deleting = this.alice.database.transaction(STORES.sendState, 'readwrite'); deleting.objectStore(STORES.sendState).delete(key); await this.alice.database.whenIdle();
        await assert.rejects(this.send('lost'), code('STATE_LOST'), 'A context registry detects missing stream state'); this.alice.database.acknowledgeAborts();
        await this.bob.engine.closeContext(this.expected.contextID);
        await assert.rejects(this.bob.engine.receiveText(packet, this.expected), code('CONTEXT_CLOSED'), 'Closed context cannot accept packets'); this.bob.database.acknowledgeAborts();
        await assert.rejects(this.bob.engine.openReceiveContext(this.expected), code('CONTEXT_CLOSED'), 'Closing is permanent for that ID'); this.bob.database.acknowledgeAborts();
        assert.true(await this.bob.engine.decryptTextSimple('101', '102', packet) === 'seed', 'Closing still permits archive reads');
    });
    QUnit.test('Concurrent senders reserve unique sequences; reverse direction needs its own receive stream', async function (assert) {
        const database = await this.open(this.alice.database.name);
        const other = new Be9('101', database.connection); await other.setup();
        const packets = await Promise.all(Array.from({ length: 8 }, (_, index) => (index % 2 ? other : this.alice.engine)
            .encryptTextSimple('101', '102', String(index), { contextID: this.expected.contextID })));
        assert.deepEqual(packets.map(packet => packet.header.sequence).sort(), ['1', '2', '3', '4', '5', '6', '7', '8'], 'Independent native connections assign each positive sequence exactly once');
        assert.strictEqual((await Promise.all(packets.map(packet => this.bob.engine.receiveText(packet, this.expected)))).length, 8, 'Each unique packet can independently commit acceptance');
        await this.bob.engine.openContext(this.expected.contextID);
        const reverse = await this.bob.engine.encryptTextSimple('102', '101', 'Reverse', { contextID: this.expected.contextID });
        const expected = { ...this.expected, sender: '102', receiver: '101' };
        await assert.rejects(this.alice.engine.receiveText(reverse, expected), code('STREAM_NOT_OPEN'), 'An outgoing context never implicitly authorizes its reverse receive stream'); this.alice.database.acknowledgeAborts();
        await this.alice.engine.openReceiveContext(expected);
        assert.strictEqual(reverse.header.sequence, '1', 'Reverse direction has an independent counter');
        assert.strictEqual(await this.alice.engine.receiveText(reverse, expected), 'Reverse', 'Explicitly initialized reverse stream interoperates');
    });
    QUnit.test('Impossible or missing receive windows fail closed without updates or implicit resets', async function (assert) {
        const packet = await this.send('window validation');
        const id = await streamIdentity(packet.header); const key = ['102', this.expected.contextID, id];
        const original = await row(this.bob.database, STORES.receiveState, key);
        for (const patch of [{ highest: '0', bitmap: '0'.repeat(31) + '1' }, { highest: '1', bitmap: '8' + '0'.repeat(30) + '1' }]) {
            const before = { ...original, ...patch };
            const tx = this.bob.database.transaction(STORES.receiveState, 'readwrite'); tx.objectStore(STORES.receiveState).put(before); await this.bob.database.whenIdle();
            await assert.rejects(this.bob.engine.receiveText(packet, this.expected), code('STATE_LOST'), 'Impossible persisted replay bitmap rejects'); this.bob.database.acknowledgeAborts();
            assert.deepEqual(await row(this.bob.database, STORES.receiveState, key), before, 'Rejected receive leaves the invalid persisted window unchanged');
        }
        const restore = this.bob.database.transaction(STORES.receiveState, 'readwrite'); restore.objectStore(STORES.receiveState).put(original); await this.bob.database.whenIdle();
        assert.strictEqual(await this.bob.engine.receiveText(packet, this.expected), 'window validation', 'Only explicit restoration of the correct fixture state permits acceptance');
        const removing = this.bob.database.transaction(STORES.receiveState, 'readwrite'); removing.objectStore(STORES.receiveState).delete(key); await this.bob.database.whenIdle();
        await assert.rejects(this.bob.engine.receiveText(packet, this.expected), code('STATE_LOST'), 'Missing receive record cannot accept a prior packet'); this.bob.database.acknowledgeAborts();
        await assert.rejects(this.bob.engine.openReceiveContext(this.expected), code('STATE_LOST'), 'Existing stream registry prevents a missing window from being recreated'); this.bob.database.acknowledgeAborts();
        assert.strictEqual(await row(this.bob.database, STORES.receiveState, key), undefined, 'No silent reset created a new window');
    });
    QUnit.test('A failed reservation consumes the already committed send sequence', async function (assert) {
        let aborted = false;
        this.alice.database.observe(tx => {
            if (tx.mode === 'readwrite' && tx.objectStoreNames.contains(STORES.keyUsage)) tx.addEventListener('success', event => {
                if (event.target.source?.name === STORES.keyUsage && typeof event.target.result === 'string') { aborted = true; tx.abort(); }
            }, { capture: true });
        });
        await assert.rejects(this.send('failure'), code('PERSISTENCE_ERROR'), 'Native reservation abort prevents encryption success');
        this.alice.database.observe(undefined); this.alice.database.acknowledgeAborts();
        assert.true(aborted, 'The failure used a genuine native transaction abort');
        assert.strictEqual((await this.send('retry')).header.sequence, '2', 'Failed encryption never reuses its reserved sequence');
    });
    QUnit.test('Receive transaction abort releases no plaintext and an explicit retry is possible', async function (assert) {
        const packet = await this.send('commit boundary');
        this.bob.database.observe(tx => {
            if (tx.mode === 'readwrite' && tx.objectStoreNames.contains(STORES.receiveState)) tx.addEventListener('success', event => {
                if (event.target.source?.name === STORES.receiveState && Array.isArray(event.target.result)) tx.abort();
            }, { capture: true });
        });
        await assert.rejects(this.bob.engine.receiveText(packet, this.expected), code('PERSISTENCE_ERROR'), 'Successful request without commit never releases plaintext');
        this.bob.database.observe(undefined); this.bob.database.acknowledgeAborts();
        assert.true(await this.bob.engine.receiveText(packet, this.expected) === 'commit boundary', 'Rollback left the packet unseen');
    });
});
