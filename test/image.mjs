import {
    participantHooks, exchangePublicKeys, changedCiphertext, changedIV,
    isAuthenticationFailure,
} from './participants.mjs';

const base64Img = 'data:image/png;base64,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';

QUnit.module('Images / independent participants', hooks => {
    participantHooks(hooks);

    for (const [label, image] of [['existing PNG data URL', base64Img], ['empty content', '']]) {
        QUnit.test('Low-level image API, both directions: ' + label, async function (assert) {
            const { alice, bob } = this;
            const aliceKey = await alice.derive(bob.publicKey);
            const bobKey = await bob.derive(alice.publicKey);
            assert.true(aliceKey !== bobKey, 'Separate locally derived CryptoKeys');
            const toBob = structuredClone(await alice.engine.encryptImage(aliceKey, image));
            const toAlice = structuredClone(await bob.engine.encryptImage(bobKey, image));
            for (const packet of [toBob, toAlice]) {
                assert.true(packet.cipherImage !== image, 'Encrypted output differs from input');
                assert.true(packet.cipherImage.length > image.length, 'Ciphertext includes authentication overhead');
            }
            assert.true(await bob.engine.decryptImage(bobKey, toBob.cipherImage, toBob.iv) === image,
                'Bob independently restores the exact image input');
            assert.true(await alice.engine.decryptImage(aliceKey, toAlice.cipherImage, toAlice.iv) === image,
                'Alice independently restores the exact image input');
        });

        QUnit.test('Simplified image API uses the actual receiver, both directions: ' + label, async function (assert) {
            const { alice, bob } = this;
            await exchangePublicKeys(alice, bob);
            const toBob = structuredClone(await alice.engine.encryptImageSimple(alice.id, bob.id, image));
            const toAlice = structuredClone(await bob.engine.encryptImageSimple(bob.id, alice.id, image));
            assert.true(await bob.engine.decryptImageSimple(alice.id, bob.id, toBob.cipherImage, toBob.iv) === image,
                'The Bob engine decrypts Alice to Bob');
            assert.true(await alice.engine.decryptImageSimple(bob.id, alice.id, toAlice.cipherImage, toAlice.iv) === image,
                'The Alice engine decrypts Bob to Alice');
        });
    }

    QUnit.test('Third participant cannot decrypt image packets in either direction', async function (assert) {
        const { alice, bob, eve } = this;
        await exchangePublicKeys(alice, bob, eve);
        for (const [sender, receiver] of [[alice, bob], [bob, alice]]) {
            const packet = structuredClone(await sender.engine.encryptImageSimple(sender.id, receiver.id, base64Img));
            await assert.rejects(eve.engine.decryptImageSimple(sender.id, eve.id, packet.cipherImage, packet.iv),
                isAuthenticationFailure, 'A third locally generated private key fails authentication');
            await assert.rejects(eve.engine.decryptImageSimple(sender.id, receiver.id, packet.cipherImage, packet.iv),
                /Missing private key/, 'The third endpoint has no recipient private key');
        }
    });

    for (const scenario of ['ciphertext', 'IV', 'key']) {
        QUnit.test('Image API rejects a wrong ' + scenario + ' in both directions', async function (assert) {
            const { alice, bob, eve } = this;
            for (const [sender, receiver] of [[alice, bob], [bob, alice]]) {
                const senderKey = await sender.derive(receiver.publicKey);
                const receiverKey = await receiver.derive(sender.publicKey);
                const packet = structuredClone(await sender.engine.encryptImage(senderKey, base64Img));
                const ciphertext = scenario === 'ciphertext' ? changedCiphertext(packet.cipherImage) : packet.cipherImage;
                const iv = scenario === 'IV' ? changedIV(packet.iv) : packet.iv;
                const key = scenario === 'key' ? await receiver.derive(eve.publicKey) : receiverKey;
                await assert.rejects(receiver.engine.decryptImage(key, ciphertext, iv), isAuthenticationFailure,
                    'Validly encoded but incorrect image inputs fail authentication');
                assert.true(await receiver.engine.decryptImage(receiverKey, packet.cipherImage, packet.iv) === base64Img,
                    'The original image packet still decrypts');
            }
        });
    }
});
