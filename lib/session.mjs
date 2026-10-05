import { generatePair } from './crypto-keys.mjs';
import { sign, verify } from './signing.mjs';
import { fail, randomID, hash, publicPoint, exact, endpoint, purpose, RATCHET_SUITE, SESSION_LIMITS } from './protocol.mjs';
import { bootstrapHeader, bootstrapBytes, bootstrapPacket, bootstrapExpected, binding, reverse, ratchetHeader, ratchetPacket, encodeRatchetAAD, expectations, checkExpectations } from './ratchet-envelope.mjs';
import { initialRoot, rootStep, blankState, advanceSend, advanceReceive, messageKey, gcm } from './ratchet.mjs';
import { SessionStore } from './session-store.mjs';
import { scalarString } from './v2.mjs';
import { bytesSnapshot, encodeBase64url, decodeText } from './encoding.mjs';
import { V2_LIMITS } from './limits.mjs';

function matchIdentity(header, identity, outgoing) {
    const localPrefix = outgoing ? 'sender' : 'receiver', peerPrefix = outgoing ? 'receiver' : 'sender';
    if (header[localPrefix + 'IdentityFingerprint'] !== identity.localFingerprint || header[peerPrefix + 'IdentityFingerprint'] !== identity.peerFingerprint
        || header[localPrefix + 'SigningFingerprint'] !== identity.localSigningFingerprint || header[peerPrefix + 'SigningFingerprint'] !== identity.peerSigningFingerprint) throw fail('SESSION_IDENTITY_MISMATCH');
}
export class Sessions {
    constructor(keys, signing) { this.keys = keys; this.signing = signing; this.store = new SessionStore(keys, signing); }
    async create(peer, options) {
        endpoint(peer); const { contextID } = exact(options, ['contextID'], 'INVALID_OPTIONS'); scalarString(contextID);
        const identity = await this.signing.snapshot(peer), [publicKey, privateKey] = await generatePair();
        const header = bootstrapHeader({ version: 3, suite: RATCHET_SUITE, sessionID: randomID(), contextID,
            sender: this.keys.accID, receiver: peer, senderIdentityFingerprint: identity.localFingerprint, receiverIdentityFingerprint: identity.peerFingerprint,
            senderSigningFingerprint: identity.localSigningFingerprint, receiverSigningFingerprint: identity.peerSigningFingerprint,
            generation: randomID(), ratchetPublicKey: publicPoint(publicKey) });
        const signature = await sign(identity.privateKey, bootstrapBytes(header));
        await this.store.create({ sessionID: header.sessionID, status: 'pending', peerID: peer, initiator: true, offer: header, pendingPrivate: privateKey }, null, identity);
        return { header, signature };
    }
    async accept(value, expected) {
        const packet = bootstrapPacket(value), exp = bootstrapExpected(expected);
        checkExpectations(packet.header, exp, this.keys.accID);
        const identity = await this.signing.snapshot(exp.sender); matchIdentity(packet.header, identity, false);
        await verify(identity.publicKey, packet.signature, bootstrapBytes(packet.header));
        const [publicKey, privateKey] = await generatePair();
        const answer = bootstrapHeader({ ...reverse(packet.header, publicKey), offerHash: await hash(bootstrapBytes(packet.header)) }, true);
        const signature = await sign(identity.privateKey, bootstrapBytes(answer, true));
        const { root, transcript } = await initialRoot(privateKey, packet.header.ratchetPublicKey, packet.header, answer);
        const state = await blankState(exp.sessionID, root, transcript, publicKey, privateKey, packet.header.ratchetPublicKey);
        await this.store.create({ sessionID: exp.sessionID, status: 'active', peerID: exp.sender, initiator: false, offer: packet.header, answer }, state, identity);
        return { header: answer, signature };
    }
    async finish(value, expected) {
        const packet = bootstrapPacket(value, true), exp = bootstrapExpected(expected);
        checkExpectations(packet.header, exp, this.keys.accID);
        const snapshot = await this.store.snapshot(exp.sessionID);
        if (snapshot.session.status !== 'pending') throw fail('SESSION_ALREADY_EXISTS');
        const identity = await this.signing.snapshot(snapshot.session.peerID); matchIdentity(packet.header, identity, false);
        const offer = snapshot.session.offer, reversed = reverse(offer, packet.header.ratchetPublicKey);
        if (Object.keys(binding(reversed)).some(k => reversed[k] !== packet.header[k]) || packet.header.offerHash !== await hash(bootstrapBytes(offer))) throw fail('SESSION_BOOTSTRAP_INVALID');
        await verify(identity.publicKey, packet.signature, bootstrapBytes(packet.header, true));
        const initial = await initialRoot(snapshot.session.pendingPrivate, packet.header.ratchetPublicKey, offer, packet.header);
        const [localPublic, localPrivate] = await generatePair();
        const step = await rootStep(initial.root, localPrivate, packet.header.ratchetPublicKey, initial.transcript);
        const state = await blankState(exp.sessionID, step.root, initial.transcript, localPublic, localPrivate, packet.header.ratchetPublicKey);
        state.sendChain = step.chain;
        const session = { namespace: this.keys.namespace, sessionID: exp.sessionID, peerID: snapshot.session.peerID, initiator: true, status: 'active', offer, answer: packet.header };
        await this.store.commit(snapshot, state, [], identity, session);
        return this.inspect(exp.sessionID);
    }
    async bound(snapshot) {
        const identity = await this.signing.snapshot(snapshot.session.peerID);
        matchIdentity(snapshot.session.initiator ? snapshot.session.offer : snapshot.session.answer, identity, true);
        return identity;
    }
    async inspect(id) {
        const snapshot = await this.store.snapshot(id); await this.bound(snapshot);
        return { sessionID: id, peerID: snapshot.session.peerID, contextID: snapshot.session.offer.contextID, status: snapshot.session.status,
            sendNumber: snapshot.state?.sendNumber || '0', receiveNumber: snapshot.state?.receiveNumber || '0', ratchetSteps: snapshot.state?.steps || 0 };
    }
    async seal(id, value, options) {
        this.store.id(id); const bytes = bytesSnapshot(value, V2_LIMITS.plaintextBytes);
        const purposeValue = purpose(exact(options, ['purpose'], 'INVALID_OPTIONS').purpose);
        for (let attempt = 0; attempt < SESSION_LIMITS.retries; attempt++) {
            const snapshot = await this.store.snapshot(id), identity = await this.bound(snapshot);
            if (snapshot.session.status !== 'active') throw fail('SESSION_NOT_READY');
            const { state, seed } = await advanceSend(snapshot.state);
            const base = snapshot.session.initiator ? snapshot.session.offer : snapshot.session.answer;
            const header = ratchetHeader({ ...binding(base), ratchetPublicKey: state.localPublic,
                previousChainLength: state.previousChainLength, messageNumber: snapshot.state.sendNumber, purpose: purposeValue,
                iv: encodeBase64url(crypto.getRandomValues(new Uint8Array(12))) });
            const key = await messageKey(seed, header, state.transcript, 'encrypt');
            try { await this.store.commit(snapshot, state, snapshot.skipped, identity); }
            catch (error) { if (error.code === 'RATCHET_CONFLICT') continue; throw error; }
            // The committed chain step is burned on any subsequent error.
            const ciphertext = encodeBase64url(await gcm(key, header, bytes, encodeRatchetAAD(header)));
            return { header, ciphertext };
        }
        throw fail('RATCHET_CONFLICT');
    }
    async receive(value, expected, text = false) {
        const packet = ratchetPacket(value), exp = expectations(expected);
        checkExpectations(packet.header, exp, this.keys.accID);
        for (let attempt = 0; attempt < SESSION_LIMITS.retries; attempt++) {
            const snapshot = await this.store.snapshot(exp.sessionID), identity = await this.bound(snapshot);
            if (snapshot.session.status !== 'active') throw fail('SESSION_NOT_READY');
            const incoming = snapshot.session.initiator ? snapshot.session.answer : snapshot.session.offer;
            if (Object.keys(binding(incoming)).some(k => incoming[k] !== packet.header[k])) throw fail('SESSION_IDENTITY_MISMATCH');
            const proposed = await advanceReceive(snapshot.state, snapshot.skipped, packet.header);
            const key = await messageKey(proposed.seed, packet.header, proposed.state.transcript, 'decrypt');
            const bytes = await gcm(key, packet.header, packet.payload.bytes, encodeRatchetAAD(packet.header), true);
            let result;
            try {
                result = text ? decodeText(bytes) : bytes;
                await this.store.commit(snapshot, proposed.state, proposed.skipped, identity);
            } catch (error) {
                bytes.fill(0);
                if (error.code === 'RATCHET_CONFLICT') continue;
                throw error;
            }
            if (text) bytes.fill(0);
            return result;
        }
        throw fail('RATCHET_CONFLICT');
    }
    close(id) { return this.store.close(id); }
}
