import Be9, { STORES, V2_SUITE, GROUP_SUITE, upgradeBe9Schema, migrateBe8Schema, encodeBe8DerivationInfo, encodeBe8EnvelopeAAD } from '../lib/bundle.mjs';
import { participantHooks, exchangePublicKeys, changedCiphertext, changedIV, isAuthenticationFailure } from './participants.mjs';
import { withTransaction, requestResult } from '../lib/persistence.mjs';
import { BE8_STORES } from '../lib/legacy-be8.mjs';
import { rows, toBe8Layout, be8Packet, be8Epoch, be8GroupPacket, seedBe8Receive, seedBe8Budget, oldAADVector, oldAADHash } from './be8-legacy-fixture.mjs';
import { vector } from './be8-legacy-vectors.mjs';
const fail = code => error => error.code === code;
const hex = buffer => [...new Uint8Array(buffer)].map(byte => byte.toString(16).padStart(2, '0')).join('');
async function migrate(context, owner, version = 3) {
    owner.database.close();
    const database = await context.open(owner.database.name, { version, skipEngineSchema: true, upgrade(db, tx) { migrateBe8Schema(db, tx); } });
    const engine = new Be9(owner.id, database.connection); await engine.setup();
    return { ...owner, database, engine };
}
function expected(packet) { const { sender, receiver, contextID, purpose } = packet.header; return { sender, receiver, contextID, purpose }; }
QUnit.module('Be9 rename / explicit Be8 migration and readers', hooks => {
    participantHooks(hooks);
    QUnit.test('Current names and fixed legacy codecs have separate suites and preserve old independent vectors', async function (assert) {
        assert.strictEqual(Be9.name, 'Be9', 'Constructor has the current project name');
        assert.true(V2_SUITE.startsWith('BE9-') && GROUP_SUITE.startsWith('BE9-'), 'New suite identifiers are Be9');
        assert.true(Object.values(STORES).every(name => name.startsWith('be9.')), 'All current stores are Be9');
        assert.strictEqual(Be9.upgradeBe8Schema, undefined, 'Old unqualified schema API is removed');
        assert.strictEqual(typeof Be9.upgradeBe9Schema, 'function', 'New schema helper is exposed on the constructor');
        assert.strictEqual(hex(await crypto.subtle.digest('SHA-256', encodeBe8DerivationInfo(vector.metadata))), vector.infoDigest, 'Frozen Be8 info still matches the independent Node vector');
        assert.strictEqual(hex(await crypto.subtle.digest('SHA-256', encodeBe8EnvelopeAAD(oldAADVector))), oldAADHash, 'Frozen Be8 AAD still matches the independent Python vector');
    });
    QUnit.test('Unmigrated databases fail closed; atomic renaming preserves identity, keys, trust, counters and foreign stores', async function (assert) {
        const { alice, bob, eve } = this; await exchangePublicKeys(alice, bob);
        await alice.engine.addPublicKey(eve.id, eve.publicKey);
        const owner = await toBe8Layout(this, alice, db => db.createObjectStore('appData', { keyPath: 'id' }));
        await withTransaction(owner.database.connection, ['appData'], 'readwrite', tx => requestResult(tx.objectStore('appData').put({ id: 'application', retained: true })));
        const packet = await be8Packet(owner, bob.publicKey, 'Migration keeps ciphertext');
        const budget = await seedBe8Budget(owner, packet.header);
        await seedBe8Receive(owner, packet.header);
        await withTransaction(owner.database.connection, [BE8_STORES.scopes, BE8_STORES.sendState], 'readwrite', tx => {
            tx.objectStore(BE8_STORES.scopes).put({ namespace: 'another-local-namespace', accID: '104', status: 'invalidated', generation: 7 });
            return requestResult(tx.objectStore(BE8_STORES.sendState).put({ namespace: owner.id, contextID: packet.header.contextID, streamID: 'A'.repeat(43), last: '9' }));
        });
        const allBefore = await Promise.all(Object.values(BE8_STORES).map(name => rows(owner.database, name)));
        const blocked = new Be9(owner.id, owner.database.connection);
        await assert.rejects(blocked.setup(), fail('LEGACY_SCHEMA_MIGRATION_REQUIRED'), 'Setup never generates another identity beside old stores');
        assert.deepEqual(await rows(owner.database, BE8_STORES.privateKeys), allBefore[2], 'Original private records are untouched');
        const current = await migrate(this, owner);
        const allAfter = await Promise.all(Object.keys(BE8_STORES).map(key => rows(current.database, STORES[key])));
        assert.deepEqual(allAfter, allBefore, 'Every structured record and security counter survives rename');
        assert.strictEqual((await current.engine.getMyPublicKey()).x, alice.publicKey.x, 'Migration preserves cryptographic identity');
        assert.strictEqual((await current.engine.getPeerTrust('103')).status, 'unverified', 'Unverified records are never promoted to trusted');
        assert.true(Object.values(BE8_STORES).every(name => !current.database.native.objectStoreNames.contains(name)), 'Known old store names are gone after commit');
        assert.deepEqual(await rows(current.database, 'appData'), [{ id: 'application', retained: true }], 'Application-owned store is not renamed or deleted');
        const privateKey = allAfter[2][0].key;
        await assert.rejects(crypto.subtle.exportKey('jwk', privateKey), error => error.name === 'InvalidAccessError', 'Preserved private keys remain non-extractable');
        assert.strictEqual(allAfter[7][0].derivationID, budget, 'Old actual-key usage identities are not rewritten or reset');
        current.database.close(); const reopened = new Be9(owner.id, (await this.open(current.database.name, { version: 3 })).connection); await reopened.setup();
        assert.strictEqual((await reopened.getMyPublicKey()).x, alice.publicKey.x, 'Reload preserves the same identity');
    });
    QUnit.test('Native upgrade abort and target conflicts retain all original names, data and keys', async function (assert) {
        const owner = await toBe8Layout(this, this.alice); const before = await rows(owner.database, BE8_STORES.privateKeys); owner.database.close();
        let renamed = false;
        await assert.rejects(this.open(owner.database.name, { version: 3, skipEngineSchema: true, upgrade(db, tx) { migrateBe8Schema(db, tx); renamed = db.objectStoreNames.contains(STORES.privateKeys); tx.abort(); } }), Error, 'Upgrade abort is reported');
        const retained = await this.open(owner.database.name, { version: 2 });
        assert.true(renamed, 'Real native store rename succeeded before the abort');
        assert.true(retained.native.objectStoreNames.contains(BE8_STORES.privateKeys) && !retained.native.objectStoreNames.contains(STORES.privateKeys), 'Aborted upgrade restores old names');
        assert.deepEqual(await rows(retained, BE8_STORES.privateKeys), before, 'Aborted upgrade preserves native private CryptoKeys'); retained.close();
        let conflict;
        await assert.rejects(this.open(owner.database.name, { version: 3, skipEngineSchema: true, upgrade(db, tx) {
            db.createObjectStore(STORES.privateKeys, { keyPath: ['namespace', 'accID'] });
            try { migrateBe8Schema(db, tx); } catch (error) { conflict = error.code; throw error; }
        } }), Error, 'Conflict aborts rather than merging or overwriting');
        assert.strictEqual(conflict, 'SCHEMA_MIGRATION_CONFLICT', 'Ambiguous target reports a specific migration conflict');
        const retry = await this.open(owner.database.name, { version: 2 });
        assert.deepEqual(await rows(retry, BE8_STORES.privateKeys), before, 'Conflict retains all originals'); retry.close();
        const migrated = await migrate(this, owner); assert.strictEqual((await migrated.engine.getMyPublicKey()).x, this.alice.publicKey.x, 'Explicit retry completes without rotation');
    });
    QUnit.test('Default schema upgrade refuses to hide old stores; migration is idempotent and requires native versionchange', async function (assert) {
        const owner = await toBe8Layout(this, this.alice); owner.database.close(); let code;
        await assert.rejects(this.open(owner.database.name, { version: 3, skipEngineSchema: true, upgrade(db, tx) { try { upgradeBe9Schema(db, tx); } catch (error) { code = error.code; throw error; } } }), Error, 'New schema cannot silently coexist with historical engine stores');
        assert.strictEqual(code, 'LEGACY_SCHEMA_MIGRATION_REQUIRED', 'Explicit migration is required');
        const current = await migrate(this, owner); const fingerprint = (await current.engine.getMyPublicKey()).x; current.database.close(); let count;
        const again = await this.open(owner.database.name, { version: 4, skipEngineSchema: true, upgrade(db, tx) { count = migrateBe8Schema(db, tx).migratedStores; } });
        assert.strictEqual(count, 0, 'Repeat integration is idempotent with no old stores');
        const engine = new Be9(owner.id, again.connection); await engine.setup(); assert.strictEqual((await engine.getMyPublicKey()).x, fingerprint, 'Repeat migration does not rotate identity');
        assert.throws(() => migrateBe8Schema(again.native), Error, 'Migration cannot run outside versionchange');
    });
    QUnit.test('Incompatible legacy schema aborts renaming without replacing or deleting records', async function (assert) {
        // Exercise a real incompatible index in native IndexedDB.
        const owner = await toBe8Layout(this, this.alice, (db, tx) => {
            const store = tx.objectStore(BE8_STORES.publicKeys);
            store.deleteIndex('namespace'); store.createIndex('namespace', 'namespace', { unique: true });
        });
        const before = await rows(owner.database, BE8_STORES.privateKeys); owner.database.close(); let code;
        await assert.rejects(this.open(owner.database.name, { version: 3, skipEngineSchema: true, upgrade(db, tx) {
            try { migrateBe8Schema(db, tx); } catch (error) { code = error.code; throw error; }
        } }), Error, 'Schema validation failure aborts the entire native upgrade');
        assert.strictEqual(code, 'SCHEMA_ERROR', 'Mismatch reports the migration/schema error');
        const retained = await this.open(owner.database.name, { version: 2 });
        assert.true(retained.native.objectStoreNames.contains(BE8_STORES.privateKeys) && !retained.native.objectStoreNames.contains(STORES.privateKeys), 'No partial rename or new store survives');
        assert.deepEqual(await rows(retained, BE8_STORES.privateKeys), before, 'Original non-extractable keys survive incompatible schema');
    });
    QUnit.test('Both directions, images and empty Be8 packets remain explicit reads; tampering never falls back', async function (assert) {
        const { alice, bob, eve } = this; await exchangePublicKeys(alice, bob, eve);
        const oldAlice = await toBe8Layout(this, alice); const oldBob = await toBe8Layout(this, bob); const oldEve = await toBe8Layout(this, eve);
        const toBob = await be8Packet(oldAlice, bob.publicKey, 'Legacy Unicode 🌍'); const toAlice = await be8Packet(oldBob, alice.publicKey, '');
        const image = await be8Packet(oldAlice, bob.publicKey, 'data:image/png;base64,AP8=', { purpose: 'attachment' });
        const a = await migrate(this, oldAlice); const b = await migrate(this, oldBob); const e = await migrate(this, oldEve);
        assert.strictEqual(await b.engine.decryptBe8Text(toBob, expected(toBob)), 'Legacy Unicode 🌍', 'Actual recipient independently reads Be8');
        assert.strictEqual(await a.engine.decryptBe8Text(toAlice, expected(toAlice)), '', 'Reverse direction and empty content remain readable');
        assert.strictEqual(await b.engine.decryptBe8Image(image, expected(image)), 'data:image/png;base64,AP8=', 'Existing image string format remains readable');
        await assert.rejects(b.engine.decryptEnvelope(toBob, expected(toBob)), fail('INVALID_ENVELOPE'), 'Modern reader never silently selects Be8');
        await assert.rejects(b.engine.decryptBe8Text({ ...toBob, ciphertext: changedCiphertext(toBob.ciphertext) }, expected(toBob)), isAuthenticationFailure, 'Corrupted historical ciphertext fails native authentication');
        await assert.rejects(b.engine.decryptBe8Text({ ...toBob, header: { ...toBob.header, iv: changedIV(toBob.header.iv) } }, expected(toBob)), isAuthenticationFailure, 'Wrong historical IV fails native authentication');
        await assert.rejects(b.engine.decryptBe8Text({ ...toBob, header: { ...toBob.header, suite: V2_SUITE } }, expected(toBob)), fail('INVALID_ENVELOPE'), 'Changing the suite never activates another KDF');
        await assert.rejects(e.engine.decryptBe8Text(toBob, { ...expected(toBob), receiver: eve.id }), fail('ENVELOPE_EXPECTATION_MISMATCH'), 'Third endpoint cannot claim a Be8 package');
        const current = await a.engine.encryptTextSimple(a.id, b.id, 'New Be9 packet'); assert.strictEqual(current.header.suite, V2_SUITE, 'Only Be9 packets are newly created');
        assert.strictEqual(await b.engine.decryptTextSimple(a.id, b.id, current), 'New Be9 packet', 'Migrated identities interoperate with new KDF');
        await assert.rejects(b.engine.decryptBe8Text(current, expected(current)), fail('INVALID_ENVELOPE'), 'Legacy reader never silently selects Be9');
    });
    QUnit.test('Migrated replay state still rejects old duplicates, accepts unseen old sequences and separates Be9 streams', async function (assert) {
        await exchangePublicKeys(this.alice, this.bob); const a = await toBe8Layout(this, this.alice); const b = await toBe8Layout(this, this.bob);
        const one = await be8Packet(a, this.bob.publicKey, 'Seen'); const two = await be8Packet(a, this.bob.publicKey, 'Unseen', { sequence: '2' });
        await seedBe8Receive(b, one.header, true);
        const alice = await migrate(this, a); const bob = await migrate(this, b); const exp = expected(one);
        await bob.engine.openReceiveBe8Context(exp);
        await assert.rejects(bob.engine.receiveBe8Text(one, exp), fail('REPLAY_DUPLICATE'), 'Prior Be8 acceptance survives schema rename'); bob.database.acknowledgeAborts();
        assert.strictEqual(await bob.engine.receiveBe8Text(two, exp), 'Unseen', 'Unseen historical sequence can commit');
        await assert.rejects(bob.engine.receiveBe8Text(two, exp), fail('REPLAY_DUPLICATE'), 'New historical acceptance remains atomic'); bob.database.acknowledgeAborts();
        await alice.engine.openContext(exp.contextID); await bob.engine.openReceiveContext(exp);
        const current = await alice.engine.encryptTextSimple(alice.id, bob.id, 'Be9 stream', { contextID: exp.contextID });
        assert.strictEqual(current.header.sequence, '1', 'New protocol has an independent actual-key stream');
        assert.strictEqual(await bob.engine.receiveText(current, exp), 'Be9 stream', 'Be9 acceptance does not reset old Be8 window');
        bob.database.close(); const db = await this.open(bob.database.name, { version: 3 }); const restored = new Be9(bob.id, db.connection); await restored.setup();
        await assert.rejects(restored.receiveBe8Text(two, exp), fail('REPLAY_DUPLICATE'), 'Historical replay rejection persists through reload'); db.acknowledgeAborts();
    });
    QUnit.test('Historical group keys/packages remain private and bind issuer/recipient/group; new data uses Be9 group suite', async function (assert) {
        await exchangePublicKeys(this.alice, this.bob, this.eve);
        const a = await toBe8Layout(this, this.alice), b = await toBe8Layout(this, this.bob), e = await toBe8Layout(this, this.eve);
        const epoch = await be8Epoch(a, [b]); const packet = await be8GroupPacket(a, epoch, 'Old group');
        const image = await be8GroupPacket(a, epoch, 'data:image/png;base64,AP8=', { purpose: 'attachment', sequence: '2' });
        const alice = await migrate(this, a), bob = await migrate(this, b), eve = await migrate(this, e);
        const handoff = { sender: alice.id, receiver: bob.id, contextID: 'old handoff', groupID: epoch.groupID, epoch: epoch.epoch, generation: epoch.generation };
        await assert.rejects(bob.engine.importGroupEpoch(epoch.packages[0], handoff), fail('INVALID_ENVELOPE'), 'Current importer never guesses Be8 wrapping');
        await assert.rejects(eve.engine.importBe8GroupEpoch(epoch.packages[0], { ...handoff, receiver: eve.id }), fail('ENVELOPE_EXPECTATION_MISMATCH'), 'Wrong recipient cannot obtain group material');
        await assert.rejects(bob.engine.importBe8GroupEpoch({ ...epoch.packages[0], ciphertext: changedCiphertext(epoch.packages[0].ciphertext) }, handoff), isAuthenticationFailure, 'Tampered old key package installs nothing');
        await bob.engine.importBe8GroupEpoch(epoch.packages[0], handoff);
        const exp = { sender: alice.id, contextID: 'old group context', purpose: 'data', groupID: epoch.groupID, epoch: epoch.epoch, generation: epoch.generation };
        assert.strictEqual(await bob.engine.decryptBe8GroupText(packet, exp), 'Old group', 'Encrypted handoff restores interoperability without raw secret exchange');
        assert.strictEqual(await bob.engine.decryptBe8GroupImage(image, { ...exp, purpose: 'attachment' }), 'data:image/png;base64,AP8=', 'Old group attachment remains readable');
        await assert.rejects(bob.engine.decryptGroupText(packet, exp), fail('INVALID_ENVELOPE'), 'Current group reader refuses old profile');
        await bob.engine.openReceiveBe8GroupContext(exp); assert.strictEqual(await bob.engine.receiveBe8GroupText(packet, exp), 'Old group', 'Explicit group replay acceptance works');
        await assert.rejects(bob.engine.receiveBe8GroupText(packet, exp), fail('REPLAY_DUPLICATE'), 'Group duplicates reject'); bob.database.acknowledgeAborts();
        await bob.engine.activateGroupEpoch(epoch.groupID, epoch.epoch, { expectedCurrentEpoch: null }); await bob.engine.openContext('new group context');
        const fresh = await bob.engine.encryptGroupText(epoch.groupID, 'Be9 group', { contextID: 'new group context' });
        assert.strictEqual(fresh.header.suite, GROUP_SUITE, 'Retained secret uses the current suite for new data');
        assert.strictEqual(await alice.engine.decryptGroupText(fresh, { ...exp, sender: bob.id, contextID: 'new group context' }), 'Be9 group', 'Migrated operative key interoperates under new group info');
        const key = (await rows(bob.database, STORES.groupEpochs))[0].key;
        await assert.rejects(crypto.subtle.exportKey('raw', key), error => error instanceof DOMException && ['InvalidAccessError', 'NotSupportedError'].includes(error.name), 'No migration/export shortcut exposes group secret');
        await alice.engine.panic(); await assert.rejects(alice.engine.decryptBe8GroupText(packet, exp), fail('ENGINE_LOCKED'), 'Legacy readers obey panic lifecycle too');
    });
    QUnit.test('Migrated tombstones remain locked, retain generation and never create another identity implicitly', async function (assert) {
        await this.alice.engine.panic(); const old = await toBe8Layout(this, this.alice); old.database.close();
        const db = await this.open(old.database.name, { version: 3, skipEngineSchema: true, upgrade: migrateBe8Schema });
        const engine = new Be9(old.id, db.connection);
        await assert.rejects(engine.setup(), fail('ENGINE_LOCKED'), 'Migration cannot unlock panic'); db.acknowledgeAborts();
        assert.strictEqual((await rows(db, STORES.scopes))[0].generation, 1, 'Lifecycle generation is not reset');
        assert.deepEqual(await rows(db, STORES.privateKeys), [], 'No replacement identity was created');
        await engine.reinitialize(); assert.strictEqual((await rows(db, STORES.scopes))[0].generation, 2, 'Only explicit reinitialization advances the generation');
    });
});
