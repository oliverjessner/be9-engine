import {
    participantHooks, exchangePublicKeys, changedCiphertext, changedIV,
    isAuthenticationFailure,
} from './participants.mjs';

QUnit.module('Text / independent participants', hooks => {
    participantHooks(hooks);

    for (const [label, text] of [
        ['ASCII', 'Hello world'],
        ['Unicode', 'Grüße 👩🏽‍💻 — 日本語 — العربية — e\u0301\u0000'],
        ['empty content', ''],
    ]) {
        QUnit.test('Low-level API, both directions: ' + label, async function (assert) {
            const { alice, bob } = this;
            const aliceKey = await alice.derive(structuredClone(bob.publicKey));
            const bobKey = await bob.derive(structuredClone(alice.publicKey));
            assert.true(aliceKey !== bobKey, 'Endpoints hold distinct CryptoKey objects');
            const toBob = structuredClone(await alice.engine.encryptText(aliceKey, text));
            const toAlice = structuredClone(await bob.engine.encryptText(bobKey, text));
            assert.true(await bob.engine.decryptText(bobKey, toBob.cipherText, toBob.iv) === text,
                'Bob decrypts the Alice packet with his locally derived key');
            assert.true(await alice.engine.decryptText(aliceKey, toAlice.cipherText, toAlice.iv) === text,
                'Alice decrypts the Bob packet with her locally derived key');
        });

        QUnit.test('Simplified API uses the actual receiver, both directions: ' + label, async function (assert) {
            const { alice, bob } = this;
            await exchangePublicKeys(alice, bob);
            const toBob = structuredClone(await alice.engine.encryptTextSimple(alice.id, bob.id, text));
            const toAlice = structuredClone(await bob.engine.encryptTextSimple(bob.id, alice.id, text));
            assert.true(await bob.engine.decryptTextSimple(alice.id, bob.id, toBob.cipherText, toBob.iv) === text,
                'Bob independently decrypts Alice to Bob');
            assert.true(await alice.engine.decryptTextSimple(bob.id, alice.id, toAlice.cipherText, toAlice.iv) === text,
                'Alice independently decrypts Bob to Alice');
        });
    }

    QUnit.test('Repeated content produces distinct IVs and ciphertexts', async function (assert) {
        const { alice, bob } = this;
        await exchangePublicKeys(alice, bob);
        const first = await alice.engine.encryptTextSimple(alice.id, bob.id, 'Repeated content');
        const second = await alice.engine.encryptTextSimple(alice.id, bob.id, 'Repeated content');
        assert.notStrictEqual(first.iv, second.iv, 'IVs differ');
        assert.true(first.cipherText !== second.cipherText, 'Ciphertexts differ');
        for (const packet of [first, second]) {
            assert.true(await bob.engine.decryptTextSimple(alice.id, bob.id, packet.cipherText, packet.iv) === 'Repeated content',
                'The receiver can independently decrypt each packet');
        }
    });

    QUnit.test('Third participant cannot decrypt either direction using its own private key', async function (assert) {
        const { alice, bob, eve } = this;
        await exchangePublicKeys(alice, bob, eve);
        for (const [sender, receiver] of [[alice, bob], [bob, alice]]) {
            const packet = structuredClone(await sender.engine.encryptTextSimple(sender.id, receiver.id, 'Private content'));
            await assert.rejects(eve.engine.decryptTextSimple(sender.id, eve.id, packet.cipherText, packet.iv),
                isAuthenticationFailure, 'A third locally generated private key fails GCM authentication');
            await assert.rejects(eve.engine.decryptTextSimple(sender.id, receiver.id, packet.cipherText, packet.iv),
                /Missing private key/, 'The third endpoint does not possess the recipient private key');
        }
    });

    for (const scenario of ['ciphertext', 'IV', 'key']) {
        QUnit.test('Rejects a wrong ' + scenario + ' in both directions', async function (assert) {
            const { alice, bob, eve } = this;
            for (const [sender, receiver] of [[alice, bob], [bob, alice]]) {
                const senderKey = await sender.derive(receiver.publicKey);
                const receiverKey = await receiver.derive(sender.publicKey);
                const packet = structuredClone(await sender.engine.encryptText(senderKey, 'Authenticated content'));
                const ciphertext = scenario === 'ciphertext' ? changedCiphertext(packet.cipherText) : packet.cipherText;
                const iv = scenario === 'IV' ? changedIV(packet.iv) : packet.iv;
                const key = scenario === 'key' ? await receiver.derive(eve.publicKey) : receiverKey;
                await assert.rejects(receiver.engine.decryptText(key, ciphertext, iv), isAuthenticationFailure,
                    'Validly encoded but incorrect inputs fail authentication');
                assert.true(await receiver.engine.decryptText(receiverKey, packet.cipherText, packet.iv) === 'Authenticated content',
                    'The original packet still decrypts on the receiver');
            }
        });
    }
});
