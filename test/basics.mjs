import Be9 from '../lib/bundle.mjs';
import { storedIDs } from './database.mjs';
import { createParticipant, exchangePublicKeys, participantHooks } from './participants.mjs';

QUnit.module('Basics / isolated persistence', hooks => {
    participantHooks(hooks);

    QUnit.test('Separate databases retain only each endpoint private key', async function (assert) {
        const participants = [this.alice, this.bob, this.eve];
        assert.strictEqual(new Set(participants.map(peer => peer.database.name)).size, 3, 'Three separate databases');
        for (const peer of participants) {
            assert.true(await peer.engine.hasGeneratedKeys(), 'The endpoint has generated its own key pair');
            assert.deepEqual(await storedIDs(peer.database), [peer.id], 'Only its own private key is persisted');
            assert.false(Object.hasOwn(peer.publicKey, 'd'), 'The exchanged JWK has no private component');
        }
        assert.strictEqual(new Set(participants.map(peer => peer.publicKey.x)).size, 3, 'Independent key pairs');
    });

    QUnit.test('Public-key exchange populates caches without copying private keys', async function (assert) {
        const participants = [this.alice, this.bob, this.eve];
        await exchangePublicKeys(...participants);
        for (const peer of participants) {
            const keys = await peer.engine.getCachedKeys();
            await peer.database.whenIdle();
            assert.deepEqual(keys.map(key => key.accID).sort(), ['101', '102', '103'], 'Public cache includes all three endpoints');
            assert.true(keys.every(({ publicKey }) => publicKey.crv === 'P-384' && !Object.hasOwn(publicKey, 'd')),
                'The cache contains public P-384 JWKs only');
            assert.deepEqual(await storedIDs(peer.database), [peer.id], 'Public exchange leaves private storage isolated');
        }
    });

    QUnit.test('Reopen after committed writes restores keys and interoperability', async function (assert) {
        const { alice, bob } = this;
        await exchangePublicKeys(alice, bob);
        const packet = structuredClone(await alice.engine.encryptTextSimple(alice.id, bob.id, 'Before reopening'));
        const publicBefore = structuredClone(bob.publicKey);
        await bob.database.whenIdle();
        bob.database.close();
        const reopened = await createParticipant(bob.id, await this.open(bob.database.name));
        assert.true(await reopened.engine.hasGeneratedKeys(), 'setup restores both keys');
        assert.true(JSON.stringify(reopened.publicKey) === JSON.stringify(publicBefore), 'The persisted public key is unchanged');
        assert.deepEqual(await storedIDs(reopened.database), [bob.id], 'Only the recipient private key is restored');
        assert.true(await reopened.engine.decryptTextSimple(alice.id, bob.id, packet) === 'Before reopening',
            'A restored receiver decrypts a packet encrypted before close');
        const response = await reopened.engine.encryptTextSimple(bob.id, alice.id, 'After reopening');
        assert.true(await alice.engine.decryptTextSimple(bob.id, alice.id, response) === 'After reopening',
            'The restored receiver also encrypts a response');
    });

    QUnit.test('Persistence contract: generation resolves only after write transactions complete', async function (assert) {
        const database = await this.open();
        const engine = new Be9('104', database.connection);
        await engine.generatePrivAndPubKey();
        assert.strictEqual(database.pendingWrites(), 0, 'Key generation must await native transaction completion');
        await database.whenIdle();
        assert.deepEqual(await storedIDs(database), ['104'], 'The private key is present after actual commit');
    });

    QUnit.test('Persistence contract: addPublicKeys resolves only after write transactions complete', async function (assert) {
        await this.alice.engine.addPublicKeys([{ accID: this.bob.id, publicKey: structuredClone(this.bob.publicKey) }]);
        assert.strictEqual(this.alice.database.pendingWrites(), 0, 'Public-key storage must await native transaction completion');
        await this.alice.database.whenIdle();
        assert.deepEqual(await storedIDs(this.alice.database, 'publicKeys'), ['101', '102'],
            'The public key is present after actual commit');
    });
});
