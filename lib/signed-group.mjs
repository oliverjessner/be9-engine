import { STORES, requestResult } from './persistence.mjs';
import { exact, fields, decode32, purpose, fail, boundedHeader, SIGNED_GROUP_SUITE } from './protocol.mjs';
import { headerSnapshot, encodeEnvelopeAAD } from './envelope.mjs';
import { GROUP_SUITE, encodeGroupInfo, requireGroupSecret } from './group-profile.mjs';
import { encodeBase64url, bytesSnapshot, decodeText } from './encoding.mjs';
import { payloadSnapshot } from './aes.mjs';
import { V2_LIMITS } from './limits.mjs';
import { IDENTITY_STORES, sign, verify, signatureBytes } from './signing.mjs';
import { streamIdentity } from './replay.mjs';
import { usageIdentity } from './usage.mjs';
import { gcm } from './ratchet.mjs';
const names = ['version', 'suite', 'contextID', 'sender', 'receiver', 'senderFingerprint', 'receiverFingerprint', 'purpose', 'salt', 'iv', 'sequence', 'group', 'senderSigningFingerprint'];
function header(value) {
    const h = exact(value, names);
    if (h.version !== 3 || h.suite !== SIGNED_GROUP_SUITE) throw fail('INVALID_ENVELOPE');
    decode32(h.senderSigningFingerprint);
    const previous = { ...h, version: 2, suite: GROUP_SUITE }; delete previous.senderSigningFingerprint;
    const checked = headerSnapshot(previous);
    return Object.freeze({ ...checked, version: 3, suite: SIGNED_GROUP_SUITE, senderSigningFingerprint: h.senderSigningFingerprint });
}
export function encodeSignedGroupInfo(value) {
    const h = header(value);
    return fields('BE9-SIGNED-GROUP-KEY', [new Uint8Array([3]), h.suite, encodeGroupInfo({ ...h, version: 2, suite: GROUP_SUITE }), decode32(h.senderSigningFingerprint)]);
}
export function encodeSignedGroupAAD(value) {
    const h = header(value), previous = { ...h, version: 2, suite: GROUP_SUITE }; delete previous.senderSigningFingerprint;
    return boundedHeader(fields('BE9-SIGNED-GROUP-AAD', [encodeSignedGroupInfo(h), encodeEnvelopeAAD(previous)]));
}
export async function groupSignatureInput(h, ciphertext) {
    return fields('BE9-GROUP-MESSAGE-SIGNATURE', [encodeSignedGroupAAD(h), new Uint8Array(await crypto.subtle.digest('SHA-256', ciphertext))]);
}
function expectations(value) {
    return exact(value, ['sender', 'contextID', 'purpose', 'groupID', 'epoch', 'generation'], 'ENVELOPE_EXPECTATION_REQUIRED');
}
async function aes(epoch, h, usage) {
    return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: decode32(h.salt), info: encodeSignedGroupInfo(h) },
        requireGroupSecret(epoch.key), { name: 'AES-GCM', length: 256 }, false, [usage]);
}
export class SignedGroups {
    constructor(keys, groups, signing, replay) { this.keys = keys; this.groups = groups; this.signing = signing; this.replay = replay; }
    async liveCheck(tx, expected, identity, work) {
        return this.signing.check(tx, identity).then(() => requestResult(tx.objectStore(STORES.activeEpochs).get([this.keys.namespace, expected.groupID]), active => {
            if (!active || active.epoch !== expected.epoch) throw fail('GROUP_EPOCH_NOT_ACTIVE');
            return requestResult(tx.objectStore(STORES.groupEpochs).get([this.keys.namespace, expected.groupID, expected.epoch]), epoch => {
                if (!epoch || epoch.generation !== expected.generation) throw fail('GROUP_EPOCH_CONFLICT');
                return work();
            });
        }));
    }
    async openReceive(value) {
        const expected = expectations(value);
        const identity = await this.signing.snapshot(expected.sender);
        const { header: base } = await this.groups.stream(expected);
        const metadata = { ...base, version: 3, suite: SIGNED_GROUP_SUITE, senderSigningFingerprint: identity.peerSigningFingerprint };
        const active = await this.groups.active(expected.groupID);
        if (!active || active.epoch !== expected.epoch || active.generation !== expected.generation) throw fail('GROUP_EPOCH_NOT_ACTIVE');
        await this.replay.openContext(expected.contextID); await this.replay.initialize(metadata, 'receive');
    }
    async seal(id, value, options) {
        options = exact(options, ['contextID', 'purpose'], 'INVALID_OPTIONS'); purpose(options.purpose);
        const bytes = bytesSnapshot(value, V2_LIMITS.plaintextBytes);
        const identity = await this.signing.snapshot(this.keys.accID);
        const active = await this.groups.active(id); if (!active) throw fail('GROUP_EPOCH_NOT_ACTIVE');
        const { record, header: base } = await this.groups.stream({ ...active, sender: this.keys.accID, ...options });
        const metadata = { ...base, version: 3, suite: SIGNED_GROUP_SUITE, senderSigningFingerprint: identity.localSigningFingerprint,
            salt: encodeBase64url(crypto.getRandomValues(new Uint8Array(32))) };
        const sequence = await this.replay.reserve(metadata);
        const h = header({ ...metadata, sequence, iv: encodeBase64url(crypto.getRandomValues(new Uint8Array(12))) });
        await this.keys.reserveUsage(await usageIdentity(h.salt, encodeSignedGroupInfo(h)), bytes.length, encodeSignedGroupAAD(h).length);
        const ciphertext = await gcm(await aes(record, h, 'encrypt'), h, bytes, encodeSignedGroupAAD(h));
        const signature = await sign(identity.privateKey, await groupSignatureInput(h, ciphertext));
        await this.keys.run([...IDENTITY_STORES, STORES.activeEpochs, STORES.groupEpochs], 'readonly', tx => this.liveCheck(tx, active, identity, () => undefined));
        return { header: h, ciphertext: encodeBase64url(ciphertext), signature };
    }
    async open(value, expectedValue, receive = true, asText = false) {
        const packet = exact(value, ['header', 'ciphertext', 'signature']);
        const h = header(packet.header), expected = expectations(expectedValue);
        const payload = payloadSnapshot(packet.ciphertext, h.iv); signatureBytes(packet.signature);
        if (h.sender !== expected.sender || h.contextID !== expected.contextID || h.purpose !== expected.purpose
            || h.group.groupID !== expected.groupID || h.group.epoch !== expected.epoch || h.group.generation !== expected.generation) throw fail('ENVELOPE_EXPECTATION_MISMATCH');
        // Verify locally trusted sender identity and signature BEFORE epoch lookup/decryption.
        const identity = await this.signing.snapshot(h.sender);
        if (identity.peerFingerprint !== h.senderFingerprint || identity.peerSigningFingerprint !== h.senderSigningFingerprint) throw fail('SESSION_IDENTITY_MISMATCH');
        await verify(identity.publicKey, packet.signature, await groupSignatureInput(h, payload.bytes));
        const { record } = await this.groups.stream(expected);
        const bytes = await gcm(await aes(record, h, 'decrypt'), h, payload.bytes, encodeSignedGroupAAD(h), true);
        let result;
        try {
            result = asText ? decodeText(bytes) : bytes;
            const streamID = await streamIdentity(h);
            await this.keys.run([...IDENTITY_STORES, STORES.activeEpochs, STORES.groupEpochs, ...(receive ? [STORES.contexts, STORES.receiveState] : [])], receive ? 'readwrite' : 'readonly', tx => receive
                ? this.liveCheck(tx, expected, identity, () => this.replay.acceptInTransaction(tx, h, streamID))
                : this.signing.check(tx, identity));
        } catch (error) { bytes.fill(0); throw error; }
        if (asText) bytes.fill(0);
        return result;
    }
}
