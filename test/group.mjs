import {
    participantHooks, exchangePublicKeys, isAuthenticationFailure, createParticipant,
} from './participants.mjs';
import { readRecord } from './database.mjs';

const groupID = 'g200';

async function publishGroupEndpoint(owner, peers, version) {
    // Only the public half leaves Alice. Her engine retains the private half.
    const [publicKey] = await owner.engine.generateGroupKeys(version, groupID);
    for (const peer of peers) {
        await peer.engine.addGroupKeys(groupID, [{
            version, groupKey: structuredClone(publicKey),
        }]);
        await peer.database.whenIdle();
    }
    return groupID + ':' + version;
}

// This is pairwise ECDH with a group-key endpoint, not a broadcast or membership
// protocol. No private group key or derived AES key is distributed to peers.
QUnit.module('Groups / public endpoint interoperability', hooks => {
    participantHooks(hooks);

    QUnit.test('Group owner and Bob communicate with independent private keys in both directions', async function (assert) {
        const { alice, bob, eve } = this;
        await exchangePublicKeys(alice, bob, eve);
        const group = await publishGroupEndpoint(alice, [bob, eve], 1);
        const toBob = structuredClone(await alice.engine.encryptTextSimple(group, bob.id, 'From the group endpoint'));
        const toGroup = structuredClone(await bob.engine.encryptTextSimple(bob.id, group, 'To the group endpoint'));
        assert.true(await bob.engine.decryptTextSimple(group, bob.id, toBob.cipherText, toBob.iv) === 'From the group endpoint',
            'Bob uses his own private key and the public group endpoint key');
        assert.true(await alice.engine.decryptTextSimple(bob.id, group, toGroup.cipherText, toGroup.iv) === 'To the group endpoint',
            'Alice uses her retained private group key and Bob public key');
        const stored = await readRecord(bob.database, 'groupKeys', [bob.id, groupID, 1]);
        assert.false(Object.hasOwn(stored, 'd'), 'Bob stores only the public group JWK');
        await assert.rejects(eve.engine.decryptTextSimple(group, eve.id, toBob.cipherText, toBob.iv),
            isAuthenticationFailure, 'Another private key cannot decrypt the Bob packet even with the public group key');
    });

    QUnit.test('Version changes require the matching public endpoint key; old versions remain readable', async function (assert) {
        const { alice, bob, eve } = this;
        await exchangePublicKeys(alice, bob, eve);
        const v1 = await publishGroupEndpoint(alice, [bob, eve], 1);
        const oldPacket = structuredClone(await alice.engine.encryptTextSimple(v1, bob.id, 'Version one'));
        const v2 = await publishGroupEndpoint(alice, [bob, eve], 2);
        const newPacket = structuredClone(await alice.engine.encryptTextSimple(v2, bob.id, 'Version two'));
        assert.true(await bob.engine.decryptTextSimple(v2, bob.id, newPacket.cipherText, newPacket.iv) === 'Version two',
            'The matching version independently decrypts');
        await assert.rejects(bob.engine.decryptTextSimple(v2, bob.id, oldPacket.cipherText, oldPacket.iv),
            isAuthenticationFailure, 'A different group version fails authentication');
        assert.true(await bob.engine.decryptTextSimple(v1, bob.id, oldPacket.cipherText, oldPacket.iv) === 'Version one',
            'Previously installed public versions are retained');
        await assert.rejects(eve.engine.decryptTextSimple(v2, eve.id, newPacket.cipherText, newPacket.iv),
            isAuthenticationFailure, 'The third private key still cannot decrypt a packet for Bob');
        assert.deepEqual(await bob.engine.getCachedGroupVersions(groupID), [2, 1], 'Both versions remain cached');
    });

    QUnit.test('Persisted public group endpoint survives reopening the receiver database', async function (assert) {
        const { alice, bob } = this;
        await exchangePublicKeys(alice, bob);
        const group = await publishGroupEndpoint(alice, [bob], 1);
        const packet = structuredClone(await alice.engine.encryptTextSimple(group, bob.id, 'Persisted public endpoint'));
        await bob.database.whenIdle();
        bob.database.close();
        const reopened = await createParticipant(bob.id, await this.open(bob.database.name));
        assert.true(await reopened.engine.decryptTextSimple(group, bob.id, packet.cipherText, packet.iv) === 'Persisted public endpoint',
            'setup restores the public group key alongside the local private identity key');
    });
});
