import Be8 from '../lib/bundle.mjs';
import { participantHooks, exchangePublicKeys } from './participants.mjs';

QUnit.module('Exceptions / independent participants', hooks => {
    participantHooks(hooks);

    QUnit.test('Constructor rejects a missing identifier or database', function (assert) {
        assert.throws(() => new Be8(), /no acc id or wrong type/, 'Missing identifier is rejected');
        assert.throws(() => new Be8('101'), /no indexedDB/, 'Missing database is rejected');
    });

    for (const kind of ['Text', 'Image']) {
        QUnit.test(kind + ' simplified API rejects missing sender private key', async function (assert) {
            const { bob } = this;
            await assert.rejects(bob.engine['encrypt' + kind + 'Simple']('999', bob.id, 'Test input'),
                /Missing private key/, 'The endpoint cannot encrypt with another identity private key');
        });

        QUnit.test(kind + ' simplified API rejects missing receiver public key', async function (assert) {
            const { alice } = this;
            await assert.rejects(alice.engine['encrypt' + kind + 'Simple'](alice.id, '999', 'Test input'),
                /Missing public key/, 'A missing receiver public key is rejected');
        });
    }

    QUnit.test('getDerivedKey rejects a missing public key or local private reference', async function (assert) {
        await assert.rejects(this.alice.engine.getDerivedKey(), /no public key/, 'Missing public JWK is rejected');
        await assert.rejects(this.alice.engine.getDerivedKey(this.bob.publicKey), /no private key/,
            'Missing local private key reference is rejected');
    });

    QUnit.test('Text API rejects a missing derived key', async function (assert) {
        await assert.rejects(this.alice.engine.encryptText(), /no derived key/, 'Missing encryption key is rejected');
        await assert.rejects(this.bob.engine.decryptText(), /no derived key/, 'Missing decryption key is rejected');
    });

    QUnit.test('Actual recipient rejects a missing text IV', async function (assert) {
        const { alice, bob } = this;
        await exchangePublicKeys(alice, bob);
        const { cipherText } = await alice.engine.encryptTextSimple(alice.id, bob.id, 'Test input');
        await assert.rejects(bob.engine.decryptTextSimple(alice.id, bob.id, cipherText),
            /no iv/, 'The actual recipient rejects a missing IV');
    });
});
