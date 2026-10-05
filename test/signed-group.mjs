import { STORES, SIGNED_GROUP_SUITE, encodeBase64url } from '../lib/bundle.mjs';
import { participantHooks, changedCiphertext, changedIV } from './participants.mjs';
import { signingPeers, code, rejected, read, reload, failureDeadline, acknowledge } from './session-fixture.mjs';
import { encodeSignedGroupInfo, encodeSignedGroupAAD, groupSignatureInput } from '../lib/signed-group.mjs';
import { sign } from '../lib/signing.mjs';
import { decodeBase64url } from '../lib/encoding.mjs';
async function epoch(alice, peers, number = '1', previous = null) {
    await alice.engine.openContext('signed key handoff');
    const created = await alice.engine.createGroupEpoch('gSigned', number, peers.map(p => p.id), { contextID: 'signed key handoff' });
    await alice.engine.activateGroupEpoch('gSigned', number, { expectedCurrentEpoch: previous });
    for (const peer of peers) {
        await peer.engine.importGroupEpoch(created.packages.find(p => p.recipient === peer.id).envelope,
            { sender: alice.id, receiver: peer.id, contextID: 'signed key handoff', groupID: 'gSigned', epoch: number, generation: created.epoch.generation });
        await peer.engine.activateGroupEpoch('gSigned', number, { expectedCurrentEpoch: previous });
    }
    return { sender: alice.id, groupID: 'gSigned', epoch: number, generation: created.epoch.generation, contextID: 'signed data', purpose: 'data' };
}
QUnit.module('Signed groups / independent sender authorship', hooks => {
    participantHooks(hooks);
    QUnit.test('Native signatures, independent decryption, replay, images, reverse direction and archive naming', async function (assert) {
        const { alice, bob, eve } = this; await signingPeers(alice, bob, eve); const expected = await epoch(alice, [bob, eve]);
        await alice.engine.openContext(expected.contextID); await bob.engine.openReceiveSignedGroupContext(expected);
        const packet = await alice.engine.encryptSignedGroupText('gSigned', 'Signed 🐈', { contextID: expected.contextID });
        assert.strictEqual(packet.header.suite, SIGNED_GROUP_SUITE, 'Dedicated signed group suite');
        assert.strictEqual(await bob.engine.receiveSignedGroupText(packet, expected), 'Signed 🐈', 'Actual receiver verifies sender and decrypts');
        await assert.rejects(bob.engine.receiveSignedGroupText(packet, expected), code('REPLAY_DUPLICATE'), 'Duplicate cannot commit'); acknowledge(this);
        assert.strictEqual(await bob.engine.decryptArchivedSignedGroupText(packet, expected), 'Signed 🐈', 'Explicit archive decrypt is repeatable');
        assert.strictEqual(await bob.engine.decryptArchivedSignedGroupText(packet, expected), 'Signed 🐈', 'Archive does not consume live state');
        await assert.rejects(bob.engine.receiveSignedGroupText(packet, packet.header), code('ENVELOPE_EXPECTATION_REQUIRED'), 'Wire header is not an independent expectation object');
        await alice.engine.openReceiveSignedGroupContext({ ...expected, sender: bob.id });
        const reverse = await bob.engine.encryptSignedGroupText('gSigned', '', { contextID: expected.contextID });
        assert.strictEqual(await alice.engine.receiveSignedGroupText(reverse, { ...expected, sender: bob.id }), '', 'Reverse direction and empty contents work');
        const imageExpected = { ...expected, purpose: 'attachment' }; await bob.engine.openReceiveSignedGroupContext(imageExpected);
        const image = await alice.engine.encryptSignedGroupImage('gSigned', 'data:image/png;base64,AP8=', { contextID: expected.contextID });
        assert.strictEqual(await bob.engine.receiveSignedGroupImage(image, imageExpected), 'data:image/png;base64,AP8=', 'Signed existing image API');
        const restored = await reload(this, bob);
        await assert.rejects(restored.engine.receiveSignedGroupText(packet, expected), code('REPLAY_DUPLICATE'), 'Acceptance survives another connection'); acknowledge(this);
        await assert.rejects(bob.engine.decryptGroupText({ header: packet.header, ciphertext: packet.ciphertext }, expected), code('INVALID_ENVELOPE'), 'Old unsigned reader cannot autodetect the signed suite');
    });
    QUnit.test('Every signed field and ciphertext is authenticated before epoch/key selection', async function (assert) {
        const { alice, bob, eve } = this; await signingPeers(alice, bob, eve); const expected = await epoch(alice, [bob, eve]);
        await alice.engine.openContext(expected.contextID); await bob.engine.openReceiveSignedGroupContext(expected);
        const packet = await alice.engine.encryptSignedGroupText('gSigned', 'all fields', { contextID: expected.contextID });
        const changes = { version: 2, suite: 'BE9-GROUP-HKDF-SHA256-A256GCM', contextID: 'changed context', sender: eve.id,
            senderFingerprint: encodeBase64url(new Uint8Array(32)), receiverFingerprint: encodeBase64url(new Uint8Array(32)), purpose: 'attachment',
            salt: encodeBase64url(new Uint8Array(32)), iv: changedIV(packet.header.iv), sequence: '2',
            senderSigningFingerprint: encodeBase64url(new Uint8Array(32)),
            group: { ...packet.header.group, epoch: '2' }, receiver: 'gOther' };
        for (const [field, value] of Object.entries(changes)) await assert.rejects(bob.engine.receiveSignedGroupEnvelope({ ...packet, header: { ...packet.header, [field]: value } }, expected), rejected, 'Changed ' + field + ' is refused');
        for (const field of ['groupID', 'epoch', 'generation']) {
            const value = { groupID: 'gOther', epoch: '2', generation: encodeBase64url(new Uint8Array(32)) }[field];
            const changedGroup = { ...packet.header.group, [field]: value };
            const changed = { ...packet, header: { ...packet.header, group: changedGroup,
                ...(field === 'groupID' ? { receiver: value } : {}), ...(field === 'generation' ? { receiverFingerprint: value } : {}) } };
            await assert.rejects(bob.engine.receiveSignedGroupEnvelope(changed, { ...expected, [field]: value }), code('INVALID_SIGNATURE'), 'Changed ' + field + ' cannot reach an unknown epoch lookup');
        }
        await assert.rejects(bob.engine.receiveSignedGroupText({ ...packet, ciphertext: changedCiphertext(packet.ciphertext) }, expected), code('INVALID_SIGNATURE'), 'Ciphertext hash is signed');
        await assert.rejects(bob.engine.receiveSignedGroupText({ ...packet, signature: changedCiphertext(packet.signature) }, expected), code('INVALID_SIGNATURE'), 'Bad signature fails');
        await assert.rejects(bob.engine.receiveSignedGroupText({ ...packet, signature: 'AA' }, expected), code('INVALID_SIGNATURE'), 'Signature must be the exact 96-byte native format');
        assert.strictEqual(await bob.engine.receiveSignedGroupText(packet, expected), 'all fields', 'Attack attempts consume no live acceptance state');
    });
    QUnit.test('Mallory knows the same epoch secret and can encrypt as Alice, but cannot sign as Alice', async function (assert) {
        const { alice, bob, eve: mallory } = this; await signingPeers(alice, bob, mallory); const expected = await epoch(alice, [bob, mallory]);
        await alice.engine.openContext(expected.contextID); await bob.engine.openReceiveSignedGroupContext(expected);
        const legitimate = await alice.engine.encryptSignedGroupText('gSigned', 'Alice', { contextID: expected.contextID });
        const header = { ...legitimate.header, sequence: '2', salt: encodeBase64url(crypto.getRandomValues(new Uint8Array(32))), iv: encodeBase64url(crypto.getRandomValues(new Uint8Array(12))) };
        // Mallory uses only Mallory's own local non-extractable keys. No secrets
        // or derived keys are passed from Alice/Bob to this attack fixture.
        const localEpoch = await new Promise((resolve, reject) => {
            const tx = mallory.database.transaction(STORES.groupEpochs, 'readonly');
            const request = tx.objectStore(STORES.groupEpochs).get([mallory.id, 'gSigned', '1']);
            request.onsuccess = () => resolve(request.result); request.onerror = () => reject(new Error('Native fixture read failed'));
        });
        await mallory.database.whenIdle();
        const key = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: decodeBase64url(header.salt), info: encodeSignedGroupInfo(header) }, localEpoch.key,
            { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
        const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: decodeBase64url(header.iv), tagLength: 128, additionalData: encodeSignedGroupAAD(header) }, key, new TextEncoder().encode('forged Alice')));
        const ownSigner = await read(mallory, 'signingKeys', mallory.id);
        const signature = await sign(ownSigner.privateKey, await groupSignatureInput(header, ciphertext));
        const forged = { header, ciphertext: encodeBase64url(ciphertext), signature };
        await assert.rejects(bob.engine.receiveSignedGroupText(forged, expected), code('INVALID_SIGNATURE'), 'A valid shared-secret GCM ciphertext and Mallory signature cannot authenticate Alice');
        assert.strictEqual(await bob.engine.receiveSignedGroupText(legitimate, expected), 'Alice', 'Genuine author signature works');
    });
    QUnit.test('Unknown/unverified signing identities and confirmed rotation bind old sessions/messages', async function (assert) {
        const { alice, bob, eve } = this; const identities = await signingPeers(alice, bob, eve); const expected = await epoch(alice, [bob, eve]);
        await alice.engine.openContext(expected.contextID); await bob.engine.openReceiveSignedGroupContext(expected);
        const packet = await alice.engine.encryptSignedGroupText('gSigned', 'old signer', { contextID: expected.contextID });
        const current = identities[0];
        const rotated = await alice.engine.rotateSigningIdentity({ expectedPreviousFingerprint: current.fingerprint });
        const results = await Promise.allSettled([bob.engine.replaceSigningPublicKey(alice.id, rotated.publicKey, { expectedPreviousFingerprint: current.fingerprint, confirmedNewFingerprint: rotated.fingerprint, identityFingerprint: rotated.identityFingerprint }),
            bob.engine.replaceSigningPublicKey(alice.id, identities[2].publicKey, { expectedPreviousFingerprint: current.fingerprint, confirmedNewFingerprint: identities[2].fingerprint, identityFingerprint: rotated.identityFingerprint })]);
        assert.strictEqual(results.filter(r => r.status === 'fulfilled').length, 1, 'Concurrent signer replacement is compare-and-swap'); acknowledge(this);
        // The winner is made explicit for the following assertions, without undoing CAS.
        const now = await new Promise(resolve => { const tx = bob.database.transaction(STORES.signingTrust, 'readonly'); const request = tx.objectStore(STORES.signingTrust).get([bob.id, alice.id]); request.onsuccess = () => resolve(request.result); });
        await bob.database.whenIdle();
        if (now.fingerprint !== rotated.fingerprint) await bob.engine.replaceSigningPublicKey(alice.id, rotated.publicKey, { expectedPreviousFingerprint: now.fingerprint, confirmedNewFingerprint: rotated.fingerprint, identityFingerprint: rotated.identityFingerprint });
        await assert.rejects(bob.engine.receiveSignedGroupText(packet, expected), code('SESSION_IDENTITY_MISMATCH'), 'Old signer rejects after explicit confirmed rotation');
        await bob.engine.openReceiveSignedGroupContext(expected);
        const fresh = await alice.engine.encryptSignedGroupText('gSigned', 'new signer', { contextID: expected.contextID });
        assert.strictEqual(await bob.engine.receiveSignedGroupText(fresh, expected), 'new signer', 'New sender stream uses the confirmed new signing key');
        const tx = eve.database.transaction(STORES.signingTrust, 'readwrite'); tx.objectStore(STORES.signingTrust).delete([eve.id, alice.id]); await eve.database.whenIdle();
        await assert.rejects(eve.engine.receiveSignedGroupText(fresh, expected), code('UNTRUSTED_SIGNING_KEY'), 'Unknown signing key cannot be obtained from the envelope');
    });
    QUnit.test('New epochs are live-only after explicit activation; old signed data remains an explicit archive', async function (assert) {
        const { alice, bob, eve } = this; await signingPeers(alice, bob, eve); const expected = await epoch(alice, [bob, eve]);
        await alice.engine.openContext(expected.contextID); await bob.engine.openReceiveSignedGroupContext(expected);
        const old = await alice.engine.encryptSignedGroupText('gSigned', 'past epoch', { contextID: expected.contextID });
        const next = await epoch(alice, [bob], '2', '1'); await bob.engine.openReceiveSignedGroupContext(next);
        await assert.rejects(bob.engine.receiveSignedGroupText(old, expected), code('GROUP_EPOCH_NOT_ACTIVE'), 'Retired epoch cannot commit live acceptance'); acknowledge(this);
        assert.strictEqual(await bob.engine.decryptArchivedSignedGroupText(old, expected), 'past epoch', 'Explicit archive retains old secret readability');
        const fresh = await alice.engine.encryptSignedGroupText('gSigned', 'future excluded', { contextID: expected.contextID });
        await assert.rejects(eve.engine.decryptArchivedSignedGroupText(fresh, next), code('GROUP_EPOCH_MISSING'), 'Excluded instance has no new epoch secret');
        assert.strictEqual(await bob.engine.receiveSignedGroupText(fresh, next), 'future excluded', 'Included recipient handles signed new epoch');
        await assert.rejects(bob.engine.activateGroupEpoch('gSigned', '1', { expectedCurrentEpoch: '2' }), code('GROUP_EPOCH_DOWNGRADE'), 'Signed profile keeps immutable no-downgrade semantics'); acknowledge(this);
    });
    QUnit.test('Live signed receive cannot output before acceptance commit, including concurrent connections', async function (assert) {
        const { alice, bob } = this; await signingPeers(alice, bob); const expected = await epoch(alice, [bob]);
        await alice.engine.openContext(expected.contextID); await bob.engine.openReceiveSignedGroupContext(expected);
        const packet = await alice.engine.encryptSignedGroupText('gSigned', 'atomic signed', { contextID: expected.contextID }); let wrote = false;
        bob.database.observe(tx => { if (tx.mode === 'readwrite' && tx.objectStoreNames.contains(STORES.receiveState)) tx.addEventListener('success', event => {
            if (event.target.source?.name === STORES.receiveState && Array.isArray(event.target.result)) { wrote = true; tx.abort(); }
        }, { capture: true }); });
        await assert.rejects(failureDeadline(bob.engine.receiveSignedGroupText(packet, expected)), code('PERSISTENCE_ERROR'), 'Native abort returns no plaintext');
        bob.database.observe(undefined); acknowledge(this); assert.true(wrote, 'Successful native request is followed by abort');
        const b = await reload(this, bob);
        const results = await Promise.allSettled([bob.engine.receiveSignedGroupText(packet, expected), b.engine.receiveSignedGroupText(packet, expected)]);
        assert.strictEqual(results.filter(r => r.status === 'fulfilled').length, 1, 'Concurrent signature-authenticated acceptance has one winner');
        assert.true(results.filter(r => r.status === 'rejected').every(r => r.reason.code === 'REPLAY_DUPLICATE'), 'Duplicate loser sees committed replay state'); acknowledge(this);
    });
});
