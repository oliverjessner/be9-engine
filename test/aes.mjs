import { participantHooks, changedCiphertext, changedIV, isAuthenticationFailure } from './participants.mjs';

// Single-instance AES unit tests. They do not establish multiparty ECDH or
// group authorization: each round trip intentionally reuses one local AES key.
QUnit.module('AES-GCM / single-instance unit tests', hooks => {
    participantHooks(hooks);

    QUnit.test('Local AES round trip and authentication failures', async function (assert) {
        const engine = this.alice.engine;
        const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        const wrongKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
        for (const text of ['Local unit input', 'Unicode 🐈 日本語', '']) {
            const packet = await engine.encryptText(key, text);
            assert.true(await engine.decryptText(key, packet.cipherText, packet.iv) === text, 'Local AES round trip succeeds');
            await assert.rejects(engine.decryptText(wrongKey, packet.cipherText, packet.iv),
                isAuthenticationFailure, 'An independently generated AES key fails authentication');
            await assert.rejects(engine.decryptText(key, changedCiphertext(packet.cipherText), packet.iv),
                isAuthenticationFailure, 'Altered bytes fail authentication');
            await assert.rejects(engine.decryptText(key, packet.cipherText, changedIV(packet.iv)),
                isAuthenticationFailure, 'An altered IV fails authentication');
        }
    });
});
