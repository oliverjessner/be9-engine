import Be8, { STORES, GROUP_SUITE } from '../lib/bundle.mjs';
import { participantHooks, exchangePublicKeys, createParticipant, changedCiphertext, changedIV, isAuthenticationFailure } from './participants.mjs';
import { withTransaction, requestResult } from '../lib/persistence.mjs';
import { createLegacyGroup, legacyGroupToPublic, legacyToPublic, legacyGroupHKDFPacket } from './legacy-fixture.mjs';
const groupID = 'g200';
function expectation(sender, epoch, contextID = 'group data', purpose = 'data') { return { ...epoch, sender, contextID, purpose }; }
async function create(owner, peers, epoch = '1') {
    await owner.engine.openContext('group handoff');
    const result = await owner.engine.createGroupEpoch(groupID, epoch, peers.map(peer => peer.id), { contextID: 'group handoff' });
    for (const peer of peers) {
        const packet = result.packages.find(item => item.recipient === peer.id).envelope;
        await peer.engine.importGroupEpoch(structuredClone(packet), { ...result.epoch, sender: owner.id, receiver: peer.id, contextID: 'group handoff' });
    }
    return result;
}
async function activate(peer, epoch, previous = null) {
    await peer.engine.activateGroupEpoch(groupID, epoch, { expectedCurrentEpoch: previous });
    await peer.engine.openContext('group data');
}
QUnit.module('Symmetric group epochs / isolated instances', hooks => {
    participantHooks(hooks);
    QUnit.test('Encrypted recipient-specific handoffs enable three local instances without exporting secrets', async function (assert) {
        const { alice, bob, eve } = this;
        await exchangePublicKeys(alice, bob, eve);
        const result = await create(alice, [bob, eve]);
        assert.deepEqual(Object.keys(result).sort(), ['epoch', 'packages'], 'Public result contains only metadata and encrypted packages');
        assert.strictEqual(result.packages.length, 2, 'Only the explicitly supplied recipients get packages');
        for (const peer of [alice, bob, eve]) {
            assert.strictEqual(await peer.engine.getActiveGroupEpoch(groupID), undefined, 'Creation/import does not implicitly activate an epoch');
            const rows = await withTransaction(peer.database.connection, [STORES.groupEpochs], 'readonly', tx => requestResult(tx.objectStore(STORES.groupEpochs).getAll()));
            assert.strictEqual(rows.length, 1, 'Own database retains one independent epoch record');
            assert.true(rows[0].key instanceof CryptoKey && !rows[0].key.extractable, 'Operative group secret is non-extractable');
            assert.deepEqual(rows[0].key.usages, ['deriveKey'], 'Persisted HKDF material only derives keys');
            await assert.rejects(crypto.subtle.exportKey('raw', rows[0].key), error => error.name === 'InvalidAccessError', 'Stored group export fails');
            assert.deepEqual(await peer.engine.getGroupEpochs(groupID), [result.epoch], 'Getter exposes only public epoch metadata');
            assert.false(Object.hasOwn(rows[0], 'd'), 'Group record has no private JWK field');
            await activate(peer, '1');
        }
        await assert.rejects(alice.engine.encryptGroupText(groupID, 'Input', { contextID: 'group data', iv: new Uint8Array(12) }), error => error.code === 'INVALID_OPTIONS', 'Group convenience API rejects custom IV options');
        const toGroup = await alice.engine.encryptGroupText(groupID, 'Grüße 🌍', { contextID: 'group data' });
        assert.strictEqual(toGroup.header.suite, GROUP_SUITE, 'Group data uses an explicitly separate suite');
        for (const peer of [bob, eve]) assert.strictEqual(await peer.engine.decryptGroupText(structuredClone(toGroup), expectation(alice.id, result.epoch)), 'Grüße 🌍', 'Independent recipient derives and decrypts');
        const reply = await bob.engine.encryptGroupText(groupID, '', { contextID: 'group data' });
        assert.strictEqual(await alice.engine.decryptGroupText(reply, expectation(bob.id, result.epoch)), '', 'Reverse direction and empty text work');
        const image = 'data:image/png;base64,' + 'AP8A'.repeat(100000);
        const attachment = await eve.engine.encryptGroupImage(groupID, image, { contextID: 'group data' });
        assert.true(await bob.engine.decryptGroupImage(attachment, expectation(eve.id, result.epoch, 'group data', 'attachment')) === image, 'Existing image string API works with larger data');
    });
    QUnit.test('Wrong recipient, issuer, group, epoch and modified packages never install or activate secrets', async function (assert) {
        const { alice, bob, eve } = this;
        await exchangePublicKeys(alice, bob, eve);
        await alice.engine.openContext('group handoff');
        const result = await alice.engine.createGroupEpoch(groupID, '1', [bob.id], { contextID: 'group handoff' });
        const packet = result.packages[0].envelope;
        const expected = { ...result.epoch, sender: alice.id, receiver: bob.id, contextID: 'group handoff' };
        for (const mismatch of [{ sender: eve.id }, { receiver: eve.id }, { groupID: 'gOther' }, { epoch: '2' }, { contextID: 'other' }]) {
            await assert.rejects(bob.engine.importGroupEpoch(packet, { ...expected, ...mismatch }), error => error.code === 'ENVELOPE_EXPECTATION_MISMATCH', 'Independent expectation mismatch fails');
        }
        await assert.rejects(eve.engine.importGroupEpoch(packet, { ...expected, receiver: eve.id }), error => error.code === 'ENVELOPE_EXPECTATION_MISMATCH', 'Unselected third party cannot import Bob package');
        for (const tampered of [{ ...packet, ciphertext: changedCiphertext(packet.ciphertext) },
            { ...packet, header: { ...packet.header, iv: changedIV(packet.header.iv) } },
            { ...packet, header: { ...packet.header, sequence: '2' } }]) {
            await assert.rejects(bob.engine.importGroupEpoch(tampered, expected), isAuthenticationFailure, 'Tampered ciphertext or authenticated header fails native GCM');
        }
        assert.deepEqual(await bob.engine.getGroupEpochs(groupID), [], 'Failed imports have no persisted epoch');
        assert.strictEqual(await bob.engine.getActiveGroupEpoch(groupID), undefined, 'No failed import activates state');
        await assert.rejects(bob.engine.decryptEnvelope(packet, { sender: alice.id, receiver: bob.id, contextID: 'group handoff', purpose: 'key-wrap' }), error => error.code === 'ENVELOPE_EXPECTATION_REQUIRED', 'Public byte decoder cannot extract a group secret');
        await bob.engine.importGroupEpoch(packet, expected);
        await bob.engine.importGroupEpoch(packet, expected);
        assert.strictEqual((await bob.engine.getGroupEpochs(groupID)).length, 1, 'Confirmed identical epoch import is idempotent');
    });
    QUnit.test('A fresh independent epoch excludes a prior holder while archived epochs remain readable', async function (assert) {
        const { alice, bob, eve } = this;
        await exchangePublicKeys(alice, bob, eve);
        const first = await create(alice, [bob, eve]);
        for (const peer of [alice, bob, eve]) await activate(peer, '1');
        const archived = await alice.engine.encryptGroupText(groupID, 'Old epoch', { contextID: 'group data' });
        const second = await create(alice, [bob], '2');
        assert.notStrictEqual(first.epoch.generation, second.epoch.generation, 'Fresh random material has another generation');
        assert.strictEqual(second.packages.length, 1, 'Next epoch has only the explicitly selected recipient');
        await activate(alice, '2', '1'); await activate(bob, '2', '1');
        const current = await alice.engine.encryptGroupText(groupID, 'New epoch', { contextID: 'group data' });
        assert.strictEqual(await bob.engine.decryptGroupText(current, expectation(alice.id, second.epoch)), 'New epoch', 'Retained recipient independently decrypts the new epoch');
        await assert.rejects(eve.engine.decryptGroupText(current, expectation(alice.id, second.epoch)), error => error.code === 'GROUP_EPOCH_MISSING', 'Excluded holder has no new epoch secret'); eve.database.acknowledgeAborts();
        for (const peer of [bob, eve]) assert.strictEqual(await peer.engine.decryptGroupText(archived, expectation(alice.id, first.epoch)), 'Old epoch', 'Old archive remains decryptable with its retained key');
        await assert.rejects(bob.engine.activateGroupEpoch(groupID, '1', { expectedCurrentEpoch: '2' }), error => error.code === 'GROUP_EPOCH_DOWNGRADE', 'Archive epoch cannot replace a newer active epoch');
        bob.database.acknowledgeAborts();
        assert.strictEqual((await bob.engine.getActiveGroupEpoch(groupID)).epoch, '2', 'Active epoch remains unchanged');
    });
    QUnit.test('Replay acceptance is persisted per actual group epoch and sender; archive reads remain repeatable', async function (assert) {
        const { alice, bob } = this;
        await exchangePublicKeys(alice, bob);
        const first = await create(alice, [bob]); await activate(alice, '1');
        const expected = expectation(alice.id, first.epoch);
        await bob.engine.openReceiveGroupContext(expected);
        const packet = await alice.engine.encryptGroupText(groupID, 'Once', { contextID: 'group data' });
        assert.strictEqual(await bob.engine.receiveGroupText(packet, expected), 'Once', 'Stateful group receive commits');
        await assert.rejects(bob.engine.receiveGroupText(packet, expected), error => error.code === 'REPLAY_DUPLICATE', 'Duplicate group packet is rejected'); bob.database.acknowledgeAborts();
        bob.database.close();
        const reopened = await createParticipant(bob.id, await this.open(bob.database.name));
        assert.strictEqual(await reopened.engine.decryptGroupText(packet, expected), 'Once', 'Archive works after reload');
        await assert.rejects(reopened.engine.receiveGroupText(packet, expected), error => error.code === 'REPLAY_DUPLICATE', 'Replay state survives reload'); reopened.database.acknowledgeAborts();
        const second = await create(alice, [reopened], '2'); await activate(alice, '2', '1');
        const nextExpected = expectation(alice.id, second.epoch); await reopened.engine.openReceiveGroupContext(nextExpected);
        const next = await alice.engine.encryptGroupText(groupID, 'New stream', { contextID: 'group data' });
        assert.strictEqual(next.header.sequence, '1', 'New actual group epoch has its own sequence stream');
        assert.strictEqual(await reopened.engine.receiveGroupText(next, nextExpected), 'New stream', 'New epoch acceptance is independent');
    });
    QUnit.test('Concurrent activation uses CAS; conflicting immutable epochs and aborted imports preserve prior records', async function (assert) {
        const { alice, bob } = this; await exchangePublicKeys(alice, bob);
        const first = await create(alice, [bob]); const second = await create(alice, [bob], '2');
        const connection = await this.open(bob.database.name); const other = new Be8(bob.id, connection.connection); await other.setup();
        const results = await Promise.allSettled([bob.engine.activateGroupEpoch(groupID, '1', { expectedCurrentEpoch: null }), other.activateGroupEpoch(groupID, '2', { expectedCurrentEpoch: null })]);
        assert.strictEqual(results.filter(item => item.status === 'fulfilled').length, 1, 'Only one competing activation commits');
        assert.strictEqual(results.find(item => item.status === 'rejected').reason.code, 'GROUP_EPOCH_CONFLICT', 'Loser reports explicit CAS conflict');
        bob.database.acknowledgeAborts(); connection.acknowledgeAborts();
        await assert.rejects(alice.engine.createGroupEpoch(groupID, '1', [bob.id], { contextID: 'group handoff' }), error => error.code === 'GROUP_EPOCH_CONFLICT', 'Existing epoch cannot be silently overwritten'); alice.database.acknowledgeAborts();
        assert.deepEqual(await alice.engine.getGroupEpochs(groupID), [first.epoch, second.epoch], 'Committed generations remain unchanged');
        const third = await create(alice, [], '3');
        assert.strictEqual(third.packages.length, 0, 'Local-only epoch needs no membership data');
        const rawPackage = await alice.engine.createGroupEpoch('gAbort', '1', [bob.id], { contextID: 'group handoff' });
        let aborted = false;
        bob.database.observe(tx => { if (tx.mode === 'readwrite' && tx.objectStoreNames.contains(STORES.groupEpochs)) tx.addEventListener('success', event => {
            if (!aborted && event.target.source?.name === STORES.groupEpochs && Array.isArray(event.target.result)) { aborted = true; tx.abort(); }
        }, { capture: true }); });
        await assert.rejects(bob.engine.importGroupEpoch(rawPackage.packages[0].envelope, { ...rawPackage.epoch, sender: alice.id, receiver: bob.id, contextID: 'group handoff' }), error => error instanceof Error, 'Import success waits for transaction completion');
        bob.database.observe(undefined); bob.database.acknowledgeAborts();
        assert.true(aborted, 'Native epoch write succeeded before abort'); assert.deepEqual(await bob.engine.getGroupEpochs('gAbort'), [], 'Aborted import retains no new secret');
    });
    QUnit.test('Group data authenticates headers and rejects mismatched independent expectations', async function (assert) {
        const { alice, bob } = this; await exchangePublicKeys(alice, bob); const result = await create(alice, [bob]); await activate(alice, '1');
        const expected = expectation(alice.id, result.epoch); const packet = await alice.engine.encryptGroupText(groupID, 'AAD', { contextID: 'group data' });
        for (const patch of [{ iv: changedIV(packet.header.iv) }, { sequence: '2' }, { salt: changedIV(packet.header.salt) }]) {
            await assert.rejects(bob.engine.decryptGroupText({ ...packet, header: { ...packet.header, ...patch } }, expected), isAuthenticationFailure, 'Group AAD/KDF tampering fails authentication');
        }
        for (const patch of [{ epoch: '2' }, { sender: bob.id }, { contextID: 'other' }, { purpose: 'attachment' }]) {
            await assert.rejects(bob.engine.decryptGroupEnvelope(packet, { ...expected, ...patch }), error => error.code === 'ENVELOPE_EXPECTATION_MISMATCH', 'Independent group expectation mismatch fails');
        }
    });
    QUnit.test('Retained ECDH groups are explicit legacy readers only and never generate new v2 group identities', async function (assert) {
        const { alice, bob } = this; await exchangePublicKeys(alice, bob);
        await assert.rejects(alice.engine.generateGroupKeys(1, groupID), error => error.code === 'LEGACY_GROUP_API', 'New ECDH group generation is disabled');
        const group = await createLegacyGroup(alice.engine, alice.database, 1, groupID);
        await assert.rejects(bob.engine.addGroupKeys(groupID, [{ version: 1, groupKey: group.publicKey }]), error => error.code === 'LEGACY_GROUP_API', 'Ambiguous old importer requires explicit legacy naming');
        await bob.engine.addLegacyGroupKeys(groupID, [{ version: 1, groupKey: group.publicKey }], { decisions: [{ peerID: groupID + ':1', trust: 'confirmed' }] });
        const outbound = await legacyGroupToPublic(alice, groupID, 1, bob.publicKey, 'Legacy outbound');
        const inbound = await legacyToPublic(bob, group.publicKey, 'Legacy inbound');
        assert.strictEqual(await bob.engine.decryptTextSimpleLegacy(groupID + ':1', bob.id, outbound.cipherText, outbound.iv), 'Legacy outbound', 'Historic owner-to-peer ciphertext remains readable');
        assert.strictEqual(await alice.engine.decryptTextSimpleLegacy(bob.id, groupID + ':1', inbound.cipherText, inbound.iv), 'Legacy inbound', 'Historic reverse direction remains readable');
        const historicalHKDF = await legacyGroupHKDFPacket(alice, groupID, 1, bob.publicKey, 'Historic HKDF group');
        assert.strictEqual(await bob.engine.decryptTextUnframedLegacy(groupID + ':1', bob.id, historicalHKDF.cipherText, historicalHKDF.iv, historicalHKDF.derivation,
            { contextID: 'historic HKDF group', legacyUUID: true }), 'Historic HKDF group', 'Historic HKDF group UUID packets have an explicit bounded reader');
        const local = await bob.engine.generatePrivAndPubKey();
        await assert.rejects(bob.engine.createDerivationContext(group.publicKey, local.keyReference, { sender: bob.id, receiver: groupID + ':1', contextID: 'forbidden', purpose: 'data' }),
            error => error.code === 'LEGACY_GROUP_API', 'Modern primitive senders cannot target ECDH group endpoints');
        assert.deepEqual(await bob.engine.getCachedLegacyGroupVersions(groupID), [1], 'Retained public legacy version is explicit');
        assert.deepEqual(await alice.engine.getGroupEpochs(groupID), [], 'Legacy records do not become symmetric epochs');
    });
});
