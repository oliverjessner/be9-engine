import { vector } from './ratchet-vector.mjs';
import Be9, { STORES, RATCHET_SUITE, SESSION_LIMITS, encodeRatchetAAD, encodeBase64url } from '../lib/bundle.mjs';
import { chainStep, messageKey, advanceReceive, rootStep, gcm } from '../lib/ratchet.mjs';
import { participantHooks, changedCiphertext, changedIV } from './participants.mjs';
import { signingPeers, connect, code, rejected, read, all, change, reload, failureDeadline, acknowledge } from './session-fixture.mjs';

QUnit.module('Authenticated sessions / native ratchet', hooks => {
    participantHooks(hooks);
    QUnit.test('Independent signed bootstrap, bidirectional chains, Unicode, empty, binary and image APIs', async function (assert) {
        const { alice, bob, eve } = this; await signingPeers(alice, bob, eve);
        const s = await connect(alice, bob);
        const texts = ['Unicode 🐈 ä 漢字', '', 'third'];
        for (const text of texts) {
            const packet = await alice.engine.encryptRatchetText(s.sessionID, text);
            assert.strictEqual(packet.header.suite, RATCHET_SUITE, 'New session always writes ratchet suite');
            assert.strictEqual(await bob.engine.receiveRatchetText(packet, s.toBob), text, 'Independent receiver derives each key');
        }
        for (let i = 0; i < 4; i++) {
            const reply = await bob.engine.encryptRatchetText(s.sessionID, 'reply');
            assert.strictEqual(await alice.engine.receiveRatchetText(reply, s.toAlice), 'reply', 'Reverse direction ratchets');
            const next = await alice.engine.encryptRatchetText(s.sessionID, 'next');
            assert.strictEqual(await bob.engine.receiveRatchetText(next, s.toBob), 'next', 'Fresh alternating DH steps interoperate');
        }
        const image = 'data:image/png;base64,' + 'AP8='.repeat(500000);
        const packet = await alice.engine.encryptRatchetImage(s.sessionID, image);
        assert.strictEqual(await bob.engine.receiveRatchetImage(packet, { ...s.toBob, purpose: 'attachment' }), image, 'Existing image text API supports large contents');
        const bytes = new Uint8Array([0, 255, 128, 0]);
        const binary = await bob.engine.encryptRatchetEnvelope(s.sessionID, bytes, { purpose: 'data' });
        assert.deepEqual(await alice.engine.receiveRatchetEnvelope(binary, s.toAlice), bytes, 'Binary roundtrip');
        assert.true((await alice.engine.getSession(s.sessionID)).ratchetSteps >= 4, 'Metadata reports real DH transitions');
        await assert.rejects(eve.engine.receiveRatchetText(binary, { ...s.toAlice, receiver: eve.id }), code('ENVELOPE_EXPECTATION_MISMATCH'), 'Unrelated instance cannot receive');
        assert.deepEqual(Object.keys(await alice.engine.getSession(s.sessionID)).sort(), ['contextID', 'peerID', 'ratchetSteps', 'receiveNumber', 'sendNumber', 'sessionID', 'status'].sort(), 'Inspection exposes metadata only');
    });

    QUnit.test('Signing identity is separate, non-extractable, idempotent, strictly public and reloadable', async function (assert) {
        const results = await Promise.all(Array.from({ length: 5 }, () => this.alice.engine.setupSigningIdentity()));
        assert.true(results.every(r => r.fingerprint === results[0].fingerprint), 'Parallel setup retains one signing identity');
        const row = await read(this.alice, 'signingKeys', this.alice.id);
        assert.false(Object.hasOwn(row.publicKey, 'd'), 'Public record has no scalar');
        assert.false(row.privateKey.extractable, 'Signing private key is non-extractable');
        assert.deepEqual(row.privateKey.usages, ['sign'], 'Only signing is permitted');
        assert.notEqual(row.publicKey.x, this.alice.publicKey.x, 'ECDSA uses independent secret material');
        await assert.rejects(crypto.subtle.exportKey('jwk', row.privateKey), error => error.name === 'InvalidAccessError', 'Native export is refused');
        const reopened = await reload(this, this.alice);
        assert.deepEqual(await reopened.engine.getSigningPublicKey(), results[0], 'Signing identity survives another connection');
        await change(this.alice, 'signingKeys', this.alice.id, () => undefined);
        await assert.rejects(failureDeadline(reopened.engine.setupSigningIdentity()), code('SIGNING_STATE_LOST'), 'Missing signing identity is never silently regenerated');
        acknowledge(this);
    });
    QUnit.test('Trust must be local: quarantine, explicit TOFU, wrong fingerprints and private signing JWK refusal', async function (assert) {
        const { alice, bob } = this;
        const a = await alice.engine.setupSigningIdentity(), b = await bob.engine.setupSigningIdentity();
        await alice.engine.addPublicKey(bob.id, bob.publicKey);
        await assert.rejects(alice.engine.createSession(bob.id, { contextID: 'trust' }), code('UNTRUSTED_PEER'), 'Unverified ECDH identity cannot start a session');
        await alice.engine.addPublicKey(bob.id, bob.publicKey, { trust: 'confirmed' });
        await alice.engine.addSigningPublicKey(bob.id, { ...b.publicKey, verified: true }, { identityFingerprint: b.identityFingerprint });
        await assert.rejects(alice.engine.createSession(bob.id, { contextID: 'trust' }), code('UNTRUSTED_SIGNING_KEY'), 'Network verified flag is not trust');
        await assert.rejects(alice.engine.addSigningPublicKey(bob.id, b.publicKey, { identityFingerprint: b.identityFingerprint, expectedFingerprint: a.fingerprint }), code('FINGERPRINT_MISMATCH'), 'Wrong expected thumbprint rejects');
        await assert.rejects(alice.engine.addSigningPublicKey(bob.id, { ...b.publicKey, d: 'A'.repeat(64) }, { identityFingerprint: b.identityFingerprint, trust: 'confirmed' }), code('INVALID_KEY'), 'Private material is rejected rather than stripped');
        await alice.engine.addSigningPublicKey(bob.id, b.publicKey, { identityFingerprint: b.identityFingerprint, trust: 'confirmed' });
        await bob.engine.addPublicKey(alice.id, alice.publicKey, { tofu: true });
        await bob.engine.addSigningPublicKey(alice.id, a.publicKey, { identityFingerprint: a.identityFingerprint, tofu: true });
        const s = await connect(alice, bob, 'trust');
        assert.strictEqual(await bob.engine.receiveRatchetText(await alice.engine.encryptRatchetText(s.sessionID, 'TOFU'), s.toBob), 'TOFU', 'Explicit first-contact TOFU can authorize the native bootstrap');
        acknowledge(this);
    });
    QUnit.test('Bootstrap signature and every identity/session binding are validated before installation', async function (assert) {
        const { alice, bob, eve } = this; await signingPeers(alice, bob, eve);
        const offer = await alice.engine.createSession(bob.id, { contextID: 'bootstrap' });
        const exp = { sender: alice.id, receiver: bob.id, sessionID: offer.header.sessionID, contextID: 'bootstrap' };
        await assert.rejects(bob.engine.acceptSession({ ...offer, signature: changedCiphertext(offer.signature) }, exp), code('INVALID_SIGNATURE'), 'Wrong signature rejects');
        await assert.rejects(bob.engine.acceptSession({ ...offer, header: { ...offer.header, ratchetPublicKey: (await eve.engine.getSigningPublicKey()).publicKey } }, exp), code('INVALID_SIGNATURE'), 'Substituted valid P-384 point is not signed');
        await assert.rejects(bob.engine.acceptSession({ ...offer, header: { ...offer.header, senderIdentityFingerprint: encodeBase64url(new Uint8Array(32)) } }, exp), code('SESSION_IDENTITY_MISMATCH'), 'Wrong identity fingerprint rejects');
        await assert.rejects(bob.engine.acceptSession(offer, offer.header), code('ENVELOPE_EXPECTATION_REQUIRED'), 'Entire network header is not an expectation schema');
        assert.strictEqual((await all(bob, 'sessions')).length, 0, 'Rejected bootstraps install no state');
        const answer = await bob.engine.acceptSession(offer, exp);
        await assert.rejects(alice.engine.finishSession({ ...answer, signature: changedCiphertext(answer.signature) }, { ...exp, sender: bob.id, receiver: alice.id }), code('INVALID_SIGNATURE'), 'Answer also requires authenticated peer signature');
        await alice.engine.finishSession(answer, { ...exp, sender: bob.id, receiver: alice.id });
        await assert.rejects(bob.engine.acceptSession(offer, exp), code('SESSION_ALREADY_EXISTS'), 'Replayed signed offers cannot reset a session');
        acknowledge(this);
    });
    QUnit.test('Strict ratchet header and independent expectations; tampering has no state effect or downgrade', async function (assert) {
        const { alice, bob, eve } = this; await signingPeers(alice, bob, eve); const s = await connect(alice, bob);
        const packet = await alice.engine.encryptRatchetText(s.sessionID, 'authenticated');
        const before = await read(bob, 'ratchetState', s.sessionID);
        const modifications = {
            version: 2, suite: 'BE9-P384-HKDF-SHA256-A256GCM', sessionID: encodeBase64url(new Uint8Array(32)), contextID: 'other',
            sender: eve.id, receiver: eve.id, senderIdentityFingerprint: encodeBase64url(new Uint8Array(32)), receiverIdentityFingerprint: encodeBase64url(new Uint8Array(32)),
            senderSigningFingerprint: encodeBase64url(new Uint8Array(32)), receiverSigningFingerprint: encodeBase64url(new Uint8Array(32)), generation: encodeBase64url(new Uint8Array(32)),
            ratchetPublicKey: (await eve.engine.getSigningPublicKey()).publicKey, previousChainLength: '1', messageNumber: '1', purpose: 'attachment', iv: changedIV(packet.header.iv),
        };
        for (const [field, value] of Object.entries(modifications)) await assert.rejects(bob.engine.receiveRatchetText({ ...packet, header: { ...packet.header, [field]: value } }, s.toBob), rejected, 'Changing authenticated ' + field + ' is refused');
        await assert.rejects(bob.engine.receiveRatchetText({ ...packet, ciphertext: changedCiphertext(packet.ciphertext) }, s.toBob), code('AUTHENTICATION_FAILED'), 'Ciphertext tampering rejects');
        await assert.rejects(bob.engine.receiveRatchetText(packet, packet.header), code('ENVELOPE_EXPECTATION_REQUIRED'), 'A wire header cannot act as independent expectations');
        for (const [name, value] of Object.entries({ sender: eve.id, receiver: eve.id, sessionID: encodeBase64url(new Uint8Array(32)), contextID: 'other', purpose: 'attachment' })) {
            await assert.rejects(bob.engine.receiveRatchetEnvelope(packet, { ...s.toBob, [name]: value }), code('ENVELOPE_EXPECTATION_MISMATCH'), 'Independent ' + name + ' mismatch rejects');
        }
        await assert.rejects(bob.engine.receiveRatchetText({ ...packet, header: { ...packet.header, messageNumber: '01' } }, s.toBob), rejected, 'Noncanonical counter rejects');
        await assert.rejects(bob.engine.receiveRatchetText({ ...packet, header: { ...packet.header, iv: 'AA' } }, s.toBob), rejected, 'Wrong IV size rejects');
        await assert.rejects(bob.engine.receiveRatchetText({ ...packet, ciphertext: 'AA' }, s.toBob), rejected, 'Short GCM input rejects');
        assert.strictEqual((await read(bob, 'ratchetState', s.sessionID)).tag, before.tag, 'No invalid header or authentication failure changes state');
        assert.strictEqual(await bob.engine.receiveRatchetText(packet, s.toBob), 'authenticated', 'Original packet still works');
        await assert.rejects(alice.engine.receiveRatchetText(packet, s.toBob), code('ENVELOPE_EXPECTATION_MISMATCH'), 'Reflection to sender rejects');
    });
    QUnit.test('Skipped keys survive reload across retired chains and are deleted exactly once', async function (assert) {
        const { alice, bob } = this; await signingPeers(alice, bob); const s = await connect(alice, bob);
        const packets = [];
        for (let i = 0; i < 3; i++) packets.push(await alice.engine.encryptRatchetText(s.sessionID, String(i)));
        await bob.engine.receiveRatchetText(packets[0], s.toBob);
        const reply = await bob.engine.encryptRatchetText(s.sessionID, 'reply'); await alice.engine.receiveRatchetText(reply, s.toAlice);
        const fresh = await alice.engine.encryptRatchetText(s.sessionID, 'new DH'); await bob.engine.receiveRatchetText(fresh, s.toBob);
        assert.strictEqual((await all(bob, 'skippedKeys')).length, 2, 'Previous chain length saves the two missing old-chain keys');
        const reloaded = await reload(this, bob);
        assert.strictEqual(await reloaded.engine.receiveRatchetText(packets[2], s.toBob), '2', 'Old chain out-of-order decryption uses only its stored seed');
        assert.strictEqual(await reloaded.engine.receiveRatchetText(packets[1], s.toBob), '1', 'Remaining skipped seed is independently consumed');
        assert.strictEqual((await all(bob, 'skippedKeys')).length, 0, 'Used message material is removed');
        await assert.rejects(bob.engine.receiveRatchetText(packets[2], s.toBob), code('RATCHET_DUPLICATE'), 'Retired chain cannot be restarted');
        const current = await read(alice, 'ratchetState', s.sessionID);
        assert.false(current.root.extractable || current.sendChain.extractable, 'Root and chain extractability flags remain false, independently of native export error order');
        await assert.rejects(crypto.subtle.exportKey('raw', current.root), error => error instanceof DOMException && ['InvalidAccessError', 'NotSupportedError'].includes(error.name), 'Stored root is non-extractable');
        await assert.rejects(crypto.subtle.exportKey('raw', current.sendChain), error => error instanceof DOMException && ['InvalidAccessError', 'NotSupportedError'].includes(error.name), 'Stored chain is non-extractable');
        await assert.rejects(crypto.subtle.exportKey('jwk', current.localPrivate), error => error.name === 'InvalidAccessError', 'Fresh ratchet private key is non-extractable');
    });
    QUnit.test('Message gap and aggregate skipped-key limits reject before commit', async function (assert) {
        const { alice, bob } = this; await signingPeers(alice, bob); const s = await connect(alice, bob);
        const packet = await alice.engine.encryptRatchetText(s.sessionID, 'first');
        await assert.rejects(bob.engine.receiveRatchetText({ ...packet, header: { ...packet.header, messageNumber: String(SESSION_LIMITS.gap + 1) } }, s.toBob), code('RATCHET_MESSAGE_TOO_FAR'), 'Bounded message gap');
        const packets = [packet];
        for (let i = 1; i <= SESSION_LIMITS.skipped + 2; i++) packets.push(await alice.engine.encryptRatchetText(s.sessionID, String(i)));
        await bob.engine.receiveRatchetText(packets[SESSION_LIMITS.skipped], s.toBob);
        assert.strictEqual((await all(bob, 'skippedKeys')).length, SESSION_LIMITS.skipped, 'At the hard bound, exactly the skipped seeds are retained');
        await assert.rejects(bob.engine.receiveRatchetText(packets[SESSION_LIMITS.skipped + 2], s.toBob), code('SKIPPED_KEY_LIMIT'), 'Another gap cannot exceed aggregate capacity');
        assert.strictEqual((await all(bob, 'skippedKeys')).length, SESSION_LIMITS.skipped, 'Limit error does not mutate inventory');
    });
    QUnit.test('Current state cannot derive consumed past keys; DH exchange heals a captured local state', async function (assert) {
        const { alice, bob } = this; await signingPeers(alice, bob); const s = await connect(alice, bob);
        const old = await alice.engine.encryptRatchetText(s.sessionID, 'past'); await bob.engine.receiveRatchetText(old, s.toBob);
        // Inspect compromised Alice material only in Alice's own closure/database.
        const compromised = await read(alice, 'ratchetState', s.sessionID);
        const next = await chainStep(compromised.sendChain, compromised.transcript);
        const wrong = await messageKey(next.seed, old.header, compromised.transcript, 'decrypt');
        const oldBytes = await import('../lib/encoding.mjs').then(m => m.decodeBase64url(old.ciphertext));
        await assert.rejects(gcm(wrong, old.header, oldBytes, encodeRatchetAAD(old.header), true), code('AUTHENTICATION_FAILED'), 'Advanced chain cannot reconstruct a consumed past message key');
        assert.strictEqual((await all(alice, 'skippedKeys')).length, 0, 'Sender never persists message keys');
        assert.false(Object.keys(compromised).some(name => /seed|messageKey|oldChain/i.test(name)), 'Persisted state contains no consumed seed or old chain');
        const reply = await bob.engine.encryptRatchetText(s.sessionID, 'one'); await alice.engine.receiveRatchetText(reply, s.toAlice);
        const a = await alice.engine.encryptRatchetText(s.sessionID, 'fresh Alice DH'); await bob.engine.receiveRatchetText(a, s.toBob);
        const healed = await bob.engine.encryptRatchetText(s.sessionID, 'fresh Bob DH');
        const exposedRoot = await rootStep(compromised.root, compromised.localPrivate, reply.header.ratchetPublicKey, compromised.transcript);
        const exposedStep = await chainStep(exposedRoot.chain, compromised.transcript);
        const stale = { ...compromised, root: exposedRoot.root, receiveChain: exposedStep.chain, receiveNumber: '1',
            remotePreviousChainLength: '0', remotePublic: reply.header.ratchetPublicKey, remoteFingerprint: await Be9.jwkThumbprint(reply.header.ratchetPublicKey) };
        const staleProposal = await advanceReceive(stale, [], healed.header);
        const staleKey = await messageKey(staleProposal.seed, healed.header, staleProposal.state.transcript, 'decrypt');
        const bytes = await import('../lib/encoding.mjs').then(m => m.decodeBase64url(healed.ciphertext));
        await assert.rejects(gcm(staleKey, healed.header, bytes, encodeRatchetAAD(healed.header), true), code('AUTHENTICATION_FAILED'), 'Old captured root and DH private cannot decrypt after both peers introduce fresh entropy');
        assert.strictEqual(await alice.engine.receiveRatchetText(healed, s.toAlice), 'fresh Bob DH', 'Healthy state can decrypt the recovered chain');
    });
    QUnit.test('Concurrent sends and receives across connections commit one unique counter/acceptance', async function (assert) {
        const { alice, bob } = this; await signingPeers(alice, bob); const s = await connect(alice, bob);
        const a = await reload(this, alice), b = await reload(this, bob);
        const packets = await failureDeadline(Promise.all(Array.from({ length: 8 }, (_, i) => (i % 2 ? alice : a).engine.encryptRatchetText(s.sessionID, String(i)))));
        assert.strictEqual(new Set(packets.map(p => p.header.messageNumber)).size, 8, 'Every committed send has a distinct chain number');
        const duplicate = await failureDeadline(Promise.allSettled([bob.engine.receiveRatchetText(packets[0], s.toBob), b.engine.receiveRatchetText(packets[0], s.toBob)]));
        assert.strictEqual(duplicate.filter(r => r.status === 'fulfilled').length, 1, 'Exactly one duplicate reception wins');
        assert.true(duplicate.filter(r => r.status === 'rejected').every(r => r.reason.code === 'RATCHET_DUPLICATE'), 'Loser reloads and observes consumed material');
        const different = await failureDeadline(Promise.allSettled(packets.slice(1).map((p, i) => (i % 2 ? bob : b).engine.receiveRatchetText(p, s.toBob))));
        assert.true(different.every(r => r.status === 'fulfilled'), 'Concurrent different packets, including initial DH receive, all converge');
        const fresh = await reload(this, bob);
        await assert.rejects(fresh.engine.receiveRatchetText(packets[0], s.toBob), code('RATCHET_DUPLICATE'), 'Replay rejection survives reload');
        acknowledge(this);
    });
    for (const [name, damage, expected] of [
        ['changed peer account', p => change(p.peer, 'sessions', p.id, row => ({ ...row, peerID: '103' })), 'SESSION_STATE_LOST'],
        ['changed local role', p => change(p.peer, 'sessions', p.id, row => ({ ...row, initiator: true })), 'SESSION_STATE_LOST'],
        ['missing session', p => change(p.peer, 'sessions', p.id, () => undefined), 'SESSION_STATE_LOST'],
        ['missing state', p => change(p.peer, 'ratchetState', p.id, () => undefined), 'RATCHET_STATE_LOST'],
        ['valid-looking changed counter', p => change(p.peer, 'ratchetState', p.id, row => ({ ...row, receiveNumber: '1' })), 'RATCHET_STATE_LOST'],
        ['wrong ratchet public', p => change(p.peer, 'ratchetState', p.id, row => ({ ...row, localPublic: { kty: 'EC', crv: 'P-384', x: p.peer.publicKey.x, y: p.peer.publicKey.y } })), 'RATCHET_STATE_LOST'],
        ['missing session registry', p => change(p.peer, 'sessionRegistry', p.id, () => undefined), 'SESSION_STATE_LOST'],
    ]) QUnit.test('Storage damage fails closed: ' + name, async function (assert) {
        await signingPeers(this.alice, this.bob); const s = await connect(this.alice, this.bob);
        const packet = await this.alice.engine.encryptRatchetText(s.sessionID, 'cannot release');
        await damage({ peer: this.bob, id: s.sessionID });
        const b = await reload(this, this.bob);
        await assert.rejects(failureDeadline(b.engine.receiveRatchetText(packet, s.toBob)), code(expected), 'Corrupt persisted state is not reset, and operation settles');
        acknowledge(this);
    });
    QUnit.test('Missing skipped record fails closed and does not expose the remaining plaintext', async function (assert) {
        await signingPeers(this.alice, this.bob); const s = await connect(this.alice, this.bob);
        const first = await this.alice.engine.encryptRatchetText(s.sessionID, 'first');
        const second = await this.alice.engine.encryptRatchetText(s.sessionID, 'second');
        await this.bob.engine.receiveRatchetText(second, s.toBob);
        const tx = this.bob.database.transaction(STORES.skippedKeys, 'readwrite');
        tx.objectStore(STORES.skippedKeys).clear(); await this.bob.database.whenIdle();
        await assert.rejects(this.bob.engine.receiveRatchetText(first, s.toBob), code('RATCHET_STATE_LOST'), 'Inventory detects missing seed'); acknowledge(this);
    });
    QUnit.test('Native transaction abort after successful state write cannot release plaintext or advance state', async function (assert) {
        await signingPeers(this.alice, this.bob); const s = await connect(this.alice, this.bob);
        const packet = await this.alice.engine.encryptRatchetText(s.sessionID, 'atomic');
        const before = await read(this.bob, 'ratchetState', s.sessionID); let wrote = false;
        this.bob.database.observe(tx => {
            if (tx.mode === 'readwrite' && tx.objectStoreNames.contains(STORES.ratchetState)) tx.addEventListener('success', event => {
                if (event.target.source?.name === STORES.ratchetState && Array.isArray(event.target.result)) { wrote = true; tx.abort(); }
            }, { capture: true });
        });
        await assert.rejects(failureDeadline(this.bob.engine.receiveRatchetText(packet, s.toBob)), code('PERSISTENCE_ERROR'), 'No plaintext before native commit');
        this.bob.database.observe(undefined); acknowledge(this);
        assert.true(wrote, 'Real successful state request preceded native abort');
        assert.strictEqual((await read(this.bob, 'ratchetState', s.sessionID)).tag, before.tag, 'Atomic rollback retains previous state');
        assert.strictEqual(await this.bob.engine.receiveRatchetText(packet, s.toBob), 'atomic', 'Explicit retry can commit original message');
    });
    QUnit.test('Native send abort, UTF-8 validation, session close and identity replacement retain fail-closed semantics', async function (assert) {
        await signingPeers(this.alice, this.bob, this.eve); const s = await connect(this.alice, this.bob);
        const before = await read(this.alice, 'ratchetState', s.sessionID);
        this.alice.database.observe(tx => { if (tx.mode === 'readwrite' && tx.objectStoreNames.contains(STORES.ratchetState)) tx.abort(); });
        await assert.rejects(failureDeadline(this.alice.engine.encryptRatchetText(s.sessionID, 'aborted')), code('PERSISTENCE_ERROR'), 'Aborted reservation returns no packet');
        this.alice.database.observe(undefined); acknowledge(this);
        assert.strictEqual((await read(this.alice, 'ratchetState', s.sessionID)).tag, before.tag, 'Uncommitted state stays unchanged');
        const packet = await this.alice.engine.encryptRatchetEnvelope(s.sessionID, new Uint8Array([255]), { purpose: 'data' });
        await assert.rejects(this.bob.engine.receiveRatchetText(packet, s.toBob), code('INVALID_TEXT'), 'Invalid text must not consume a receive key');
        assert.deepEqual(await this.bob.engine.receiveRatchetEnvelope(packet, s.toBob), new Uint8Array([255]), 'Binary receiver can subsequently commit');
        await this.alice.engine.closeSession(s.sessionID);
        await assert.rejects(this.alice.engine.encryptRatchetText(s.sessionID, 'closed'), code('SESSION_CLOSED'), 'Closed IDs cannot reset');
        assert.strictEqual((await all(this.alice, 'skippedKeys')).length, 0, 'Close deletes skipped secrets');
        const replacement = await connect(this.alice, this.bob, 'explicit replacement');
        assert.notEqual(replacement.sessionID, s.sessionID, 'Replacement is an explicit fresh session');
        const previous = await this.alice.engine.getPeerTrust(this.bob.id);
        const fingerprint = await Be9.jwkThumbprint(this.eve.publicKey);
        await this.alice.engine.replacePublicKey(this.bob.id, this.eve.publicKey, { expectedPreviousFingerprint: previous.fingerprint, confirmedNewFingerprint: fingerprint });
        await assert.rejects(this.alice.engine.encryptRatchetText(replacement.sessionID, 'old binding'), code('UNTRUSTED_SIGNING_KEY'), 'Identity replacement cannot silently rebind existing signing/session state');
        acknowledge(this);
    });
    QUnit.test('Panic removes secrets but retains closed session tombstones and blocks in-flight operations', async function (assert) {
        await signingPeers(this.alice, this.bob); const s = await connect(this.alice, this.bob);
        const packet = await this.alice.engine.encryptRatchetText(s.sessionID, 'panic');
        const operation = this.bob.engine.receiveRatchetText(packet, s.toBob);
        const observed = operation.then(() => undefined, error => error);
        await this.bob.engine.panic();
        assert.strictEqual((await failureDeadline(observed)).code, 'ENGINE_LOCKED', 'In-flight receive cannot release after local panic');
        for (const store of ['sessions', 'ratchetState', 'skippedKeys', 'signingKeys', 'signingTrust']) assert.strictEqual((await all(this.bob, store)).length, 0, 'Panic deletes ' + store);
        const registry = await read(this.bob, 'sessionRegistry', s.sessionID);
        assert.strictEqual(registry.status, 'closed', 'Retained tombstone prohibits old-session reuse');
        await this.bob.engine.reinitialize(); await this.bob.engine.setupSigningIdentity();
        await assert.rejects(this.bob.engine.getSession(s.sessionID), code('SESSION_STATE_LOST'), 'New lifecycle cannot resume discarded state');
        acknowledge(this);
    });

    QUnit.test('Pending capacity, strict caller options, signer rotation and namespace isolation', async function (assert) {
        const { alice, bob } = this; await signingPeers(alice, bob);
        await assert.rejects(alice.engine.createSession(bob.id, { contextID: 'x', iv: 'override' }), code('INVALID_OPTIONS'), 'Caller cannot choose a ratchet IV or session alias');
        await assert.rejects(alice.engine.createSession(bob.id, { contextID: 'x'.repeat(SESSION_LIMITS.contextBytes + 1) }), rejected, 'Oversized context rejects before native key work');
        const sessions = [];
        for (let i = 0; i < SESSION_LIMITS.sessions; i++) sessions.push(await alice.engine.createSession(bob.id, { contextID: 'capacity ' + i }));
        await assert.rejects(failureDeadline(alice.engine.createSession(bob.id, { contextID: 'over capacity' })), code('SESSION_LIMIT'), 'Pending and active sessions share a hard bound'); acknowledge(this);
        await alice.engine.closeSession(sessions[0].header.sessionID);
        const replacement = await alice.engine.createSession(bob.id, { contextID: 'available slot' });
        assert.notEqual(replacement.header.sessionID, sessions[0].header.sessionID, 'Closing frees a slot but not a historical ID');
        const other = new Be9('104', alice.database.connection, { namespace: 'isolated namespace' });
        await other.setup(); await other.setupSigningIdentity();
        await assert.rejects(other.getSession(replacement.header.sessionID), code('SESSION_NOT_FOUND'), 'Another namespace sees no session metadata');
        const wrongOwner = new Be9('105', alice.database.connection, { namespace: alice.id });
        await assert.rejects(wrongOwner.setupSigningIdentity(), code('ACCOUNT_MISMATCH'), 'Another account cannot initialize a signer in this namespace'); acknowledge(this);
        const original = await alice.engine.getSigningPublicKey();
        await alice.engine.rotateSigningIdentity({ expectedPreviousFingerprint: original.fingerprint });
        await assert.rejects(alice.engine.getSession(replacement.header.sessionID), code('SESSION_IDENTITY_MISMATCH'), 'Local signing rotation invalidates bound pending sessions');
        await alice.engine.panic();
        assert.strictEqual((await other.getSigningPublicKey()).identityFingerprint, await Be9.jwkThumbprint(await other.getMyPublicKey()), 'Panic respects other namespace ownership');
    });
    QUnit.test('Concurrent old-chain receive and DH transition preserve skipped acceptance', async function (assert) {
        await signingPeers(this.alice, this.bob); const s = await connect(this.alice, this.bob);
        const zero = await this.alice.engine.encryptRatchetText(s.sessionID, 'zero');
        const old = await this.alice.engine.encryptRatchetText(s.sessionID, 'old pending');
        await this.bob.engine.receiveRatchetText(zero, s.toBob);
        await this.alice.engine.receiveRatchetText(await this.bob.engine.encryptRatchetText(s.sessionID, 'rotate'), s.toAlice);
        const fresh = await this.alice.engine.encryptRatchetText(s.sessionID, 'fresh DH');
        const b = await reload(this, this.bob);
        const accepted = await failureDeadline(Promise.all([this.bob.engine.receiveRatchetText(old, s.toBob), b.engine.receiveRatchetText(fresh, s.toBob)]));
        assert.deepEqual(accepted.sort(), ['fresh DH', 'old pending'], 'Either commit order converges without key reuse'); acknowledge(this);
        await assert.rejects(b.engine.receiveRatchetText(old, s.toBob), code('RATCHET_DUPLICATE'), 'Old accepted chain cannot reopen after concurrent transition');
    });
    QUnit.test('Session close wins against concurrent state advancement and retained IDs cannot reopen', async function (assert) {
        await signingPeers(this.alice, this.bob); const s = await connect(this.alice, this.bob);
        const packet = await this.alice.engine.encryptRatchetText(s.sessionID, 'racing close');
        const outcome = this.bob.engine.receiveRatchetText(packet, s.toBob).then(() => 'accepted', error => error.code);
        await this.bob.engine.closeSession(s.sessionID);
        assert.strictEqual(await failureDeadline(outcome), 'SESSION_CLOSED', 'Closed tombstone wins a still-calculating receive'); acknowledge(this);
        await assert.rejects(this.bob.engine.acceptSession(s.offer, { sender: this.alice.id, receiver: this.bob.id, sessionID: s.sessionID, contextID: s.contextID }), code('SESSION_ALREADY_EXISTS'), 'Signed replay cannot erase a closed tombstone'); acknowledge(this);
    });
    QUnit.test('Native write constraint and schema upgrade abort retain all existing state', async function (assert) {
        await signingPeers(this.alice, this.bob); const s = await connect(this.alice, this.bob);
        const before = await read(this.alice, 'ratchetState', s.sessionID);
        this.alice.database.close();
        const database = await this.open(this.alice.database.name, { version: 2, upgrade(db, tx) {
            tx.objectStore(STORES.sessionRegistry).createIndex('nativeTestRevision', 'revision', { unique: true });
            tx.objectStore(STORES.sessionRegistry).add({ namespace: 'test constraint namespace', sessionID: 'reserved', revision: before.revision + 1 });
        } });
        const engine = new Be9(this.alice.id, database.connection); await engine.setup();
        await assert.rejects(failureDeadline(engine.encryptRatchetText(s.sessionID, 'write constraint')), error => error.code === 'PERSISTENCE_ERROR' && error.name === 'ConstraintError', 'A genuine native constraint abort cannot return a packet');
        database.acknowledgeAborts();
        assert.strictEqual((await read({ ...this.alice, database }, 'ratchetState', s.sessionID)).tag, before.tag, 'All state writes rolled back together');
        database.close();
        await assert.rejects(this.open(database.name, { version: 3, upgrade(db, tx) { tx.objectStore(STORES.signingKeys).clear(); tx.abort(); } }), Error, 'Native upgrade abort does not delete signing records');
        const restored = await this.open(database.name, { version: 2 });
        const reloaded = new Be9(this.alice.id, restored.connection); await reloaded.setup();
        assert.strictEqual((await reloaded.getSigningPublicKey()).identityFingerprint, await Be9.jwkThumbprint(this.alice.publicKey), 'Signing identity survives failed upgrade');
        assert.strictEqual((await reloaded.getSession(s.sessionID)).sendNumber, before.sendNumber, 'Ratchet counters survive failed write/upgrade');
    });

    QUnit.test('Ratchet KDF unit: independent Node/OpenSSL root, chain and message vector plus Python AAD', async function (assert) {
        // Known scalar is a LOCAL unit fixture; no private key travels to any participant.
        const scalar = new Uint8Array(48); scalar[47] = 1;
        const privateKey = await crypto.subtle.importKey('jwk', { ...vector.alicePublic, d: encodeBase64url(scalar), key_ops: ['deriveBits'], ext: false }, { name: 'ECDH', namedCurve: 'P-384' }, false, ['deriveBits']); scalar.fill(0);
        const { decodeBase64url } = await import('../lib/encoding.mjs');
        const root = await crypto.subtle.importKey('raw', decodeBase64url(vector.rootInput), 'HKDF', false, ['deriveBits', 'deriveKey']);
        const step = await rootStep(root, privateKey, vector.bobPublic, vector.transcript);
        const chain = await chainStep(step.chain, vector.transcript);
        const key = await messageKey(chain.seed, vector.header, vector.transcript, 'decrypt');
        const aad = encodeRatchetAAD(vector.header);
        const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', aad))].map(v => v.toString(16).padStart(2, '0')).join('');
        assert.strictEqual(digest, vector.aadDigest, 'Exact length prefixes, UTF-8, point, identities, counter order and domain match independent Python');
        assert.strictEqual(new TextDecoder().decode(await gcm(key, vector.header, decodeBase64url(vector.ciphertext), aad, true)), 'Independent ratchet vector 🐈', 'Native browser derives the independent Node/OpenSSL full-width DH/HKDF message key without export');
        assert.false(key.extractable, 'Vector interoperability leaves AES export disabled');
    });

    QUnit.test('Ratchet transition limit is explicit, with no static-suite fallback', async function (assert) {
        await signingPeers(this.alice, this.bob); const s = await connect(this.alice, this.bob);
        await this.bob.engine.receiveRatchetText(await this.alice.engine.encryptRatchetText(s.sessionID, 'first'), s.toBob);
        await this.alice.engine.receiveRatchetText(await this.bob.engine.encryptRatchetText(s.sessionID, 'reply'), s.toAlice);
        const packet = await this.alice.engine.encryptRatchetText(s.sessionID, 'fresh point');
        const current = await read(this.bob, 'ratchetState', s.sessionID);
        // A boundary unit fixture uses real native state; it does not simulate
        // a 128-exchange integration or replace any cryptographic primitive.
        await assert.rejects(advanceReceive({ ...current, steps: SESSION_LIMITS.ratchetSteps }, [], packet.header), code('RATCHET_LIMIT'), 'A new remote point cannot advance an exhausted session');
        assert.strictEqual(await this.bob.engine.receiveRatchetText(packet, s.toBob), 'fresh point', 'Unmodified live state still performs real native DH');
    });
    QUnit.test('Missing new schema requires explicit application integration and preserves existing identity', async function (assert) {
        const database = await this.open(undefined, { upgrade(db) {
            for (const key of ['signingKeys', 'signingTrust', 'sessionRegistry', 'sessions', 'ratchetState', 'skippedKeys']) db.deleteObjectStore(STORES[key]);
        } });
        const old = new Be9('104', database.connection); await old.setup(); const before = await old.getMyPublicKey();
        await assert.rejects(old.setupSigningIdentity(), code('SCHEMA_UPGRADE_REQUIRED'), 'No CryptoKey/JWK fallback or implicit schema takeover');
        database.close(); const integrated = await this.open(database.name, { version: 2 });
        const current = new Be9('104', integrated.connection); await current.setup(); await current.setupSigningIdentity();
        assert.strictEqual(await Be9.jwkThumbprint(await current.getMyPublicKey()), await Be9.jwkThumbprint(before), 'Application upgrade preserves the ECDH identity');
    });

    QUnit.test('Aborted panic rolls back new stores; lifetime tombstones cannot be silently recycled', async function (assert) {
        await signingPeers(this.alice, this.bob); const s = await connect(this.alice, this.bob);
        const packet = await this.alice.engine.encryptRatchetText(s.sessionID, 'after rollback');
        const before = await read(this.bob, 'ratchetState', s.sessionID); let removed = false;
        this.bob.database.observe(tx => { if (tx.mode === 'readwrite' && tx.objectStoreNames.contains(STORES.signingKeys)) tx.addEventListener('success', event => {
            if (event.target.source?.name === STORES.signingKeys && event.target.result === undefined) { removed = true; tx.abort(); }
        }, { capture: true }); });
        await assert.rejects(failureDeadline(this.bob.engine.panic()), code('PERSISTENCE_ERROR'), 'Failed panic cannot claim committed deletion');
        this.bob.database.observe(undefined); acknowledge(this); assert.true(removed, 'A real successful deletion preceded abort');
        assert.strictEqual((await read(this.bob, 'ratchetState', s.sessionID)).tag, before.tag, 'Aborted invalidation retains all ratchet state');
        const b = await reload(this, this.bob);
        assert.strictEqual(await b.engine.receiveRatchetText(packet, s.toBob), 'after rollback', 'Original identity, trust, root and chains remain usable after explicit fresh object opens unchanged generation');
        const tx = this.alice.database.transaction(STORES.sessionRegistry, 'readwrite');
        for (let i = 0; i < SESSION_LIMITS.registry; i++) tx.objectStore(STORES.sessionRegistry).put({ namespace: this.alice.id, sessionID: 'unit-tombstone-' + i, status: 'closed', revision: 1 });
        await this.alice.database.whenIdle();
        await assert.rejects(this.alice.engine.createSession(this.bob.id, { contextID: 'lifetime exhausted' }), code('SESSION_LIMIT'), 'Retained historical IDs enforce a lifetime registry cap even with closed entries'); acknowledge(this);
    });

    QUnit.test('Corrupted signing-generation marker cannot authorize a new identity', async function (assert) {
        await this.alice.engine.setupSigningIdentity();
        const before = await read(this.alice, 'sessionRegistry', '@signing');
        await change(this.alice, 'signingKeys', this.alice.id, () => undefined);
        for (const bad of [{ ...before, generation: undefined }, { ...before, generation: before.generation + 1, status: 'invalidated' }, { ...before, status: undefined }]) {
            await change(this.alice, 'sessionRegistry', '@signing', () => bad);
            await assert.rejects(this.alice.engine.setupSigningIdentity(), code('SIGNING_STATE_LOST'), 'Missing keys plus a corrupted marker never mint another signer');
            assert.strictEqual((await all(this.alice, 'signingKeys')).length, 0, 'No replacement key was persisted');
        }
    });

    QUnit.test('Separate worker realm and main realm reserve distinct counters from the same local session', async function (assert) {
        await signingPeers(this.alice, this.bob); const s = await connect(this.alice, this.bob);
        const worker = new Worker(new URL('./ratchet-worker.mjs', import.meta.url), { type: 'module' });
        try {
            const response = new Promise((resolve, reject) => {
                worker.onmessage = event => event.data.packet ? resolve(event.data.packet) : reject(new Error('Worker operation failed'));
                worker.onerror = () => reject(new Error('Worker infrastructure failed'));
            });
            worker.postMessage({ databaseName: this.alice.database.name, accountID: this.alice.id, sessionID: s.sessionID });
            const packets = await failureDeadline(Promise.all([response, this.alice.engine.encryptRatchetText(s.sessionID, 'Alice main realm')]));
            assert.notEqual(packets[0].header.messageNumber, packets[1].header.messageNumber, 'Native database lock/CAS coordinates different JS realms');
            assert.strictEqual(await this.bob.engine.receiveRatchetText(packets[0], s.toBob), 'Alice worker', 'Actual receiver interoperates with worker-owned derivation');
            assert.strictEqual(await this.bob.engine.receiveRatchetText(packets[1], s.toBob), 'Alice main realm', 'Main-realm message uses another single-use key'); acknowledge(this);
        } finally { worker.terminate(); }
    });

    QUnit.test('Missing signer and marker cannot masquerade as first setup when any session footprint remains', async function (assert) {
        await signingPeers(this.alice, this.bob); const s = await connect(this.alice, this.bob);
        await change(this.alice, 'signingKeys', this.alice.id, () => undefined);
        await change(this.alice, 'sessionRegistry', '@signing', () => undefined);
        await assert.rejects(this.alice.engine.setupSigningIdentity(), code('SIGNING_STATE_LOST'), 'Partial data loss does not create a replacement signing identity');
        assert.strictEqual((await all(this.alice, 'signingKeys')).length, 0, 'No new private signing key was persisted');
        assert.strictEqual((await read(this.alice, 'sessions', s.sessionID)).status, 'active', 'Original session data is retained for explicit recovery/destruction');
    });
});
