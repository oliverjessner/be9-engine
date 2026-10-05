import { exact, endpoint, point, publicPoint, pointBytes, purpose, decode32, fields, counterBytes, boundedHeader, RATCHET_SUITE, fail } from './protocol.mjs';
import { scalarString } from './v2.mjs';
import { decodeBase64url } from './encoding.mjs';
import { sequenceValue } from './envelope.mjs';
import { payloadSnapshot } from './aes.mjs';
import { signatureBytes } from './signing.mjs';
const bindingFields = ['version', 'suite', 'sessionID', 'contextID', 'sender', 'receiver', 'senderIdentityFingerprint', 'receiverIdentityFingerprint',
    'senderSigningFingerprint', 'receiverSigningFingerprint', 'generation'];
export function binding(value) {
    if (value.version !== 3 || value.suite !== RATCHET_SUITE) throw fail('INVALID_ENVELOPE');
    endpoint(value.sender); endpoint(value.receiver);
    if (value.sender === value.receiver) throw fail('INVALID_ACCOUNT');
    scalarString(value.contextID);
    for (const name of ['sessionID', 'generation', ...bindingFields.filter(n => n.endsWith('Fingerprint'))]) decode32(value[name]);
    return Object.fromEntries(bindingFields.map(name => [name, value[name]]));
}
export function bindingBytes(value) {
    const b = binding(value);
    return [new Uint8Array([3]), b.suite, decode32(b.sessionID), b.contextID, b.sender, b.receiver,
        decode32(b.senderIdentityFingerprint), decode32(b.receiverIdentityFingerprint), decode32(b.senderSigningFingerprint), decode32(b.receiverSigningFingerprint), decode32(b.generation)];
}
export function bootstrapHeader(value, answer = false) {
    const h = exact(value, [...bindingFields, 'ratchetPublicKey', ...(answer ? ['offerHash'] : [])], 'SESSION_BOOTSTRAP_INVALID');
    try { binding(h); h.ratchetPublicKey = point(h.ratchetPublicKey); if (answer) decode32(h.offerHash); }
    catch { throw fail('SESSION_BOOTSTRAP_INVALID'); }
    return Object.freeze(h);
}
export function bootstrapBytes(value, answer = false) {
    const h = bootstrapHeader(value, answer);
    return boundedHeader(fields(answer ? 'BE9-SESSION-ANSWER' : 'BE9-SESSION-OFFER', [...bindingBytes(h), pointBytes(h.ratchetPublicKey), ...(answer ? [decode32(h.offerHash)] : [])]));
}
export function bootstrapPacket(value, answer = false) {
    const p = exact(value, ['header', 'signature'], 'SESSION_BOOTSTRAP_INVALID');
    p.header = bootstrapHeader(p.header, answer); signatureBytes(p.signature);
    return p;
}
export function ratchetHeader(value) {
    const h = exact(value, [...bindingFields, 'ratchetPublicKey', 'previousChainLength', 'messageNumber', 'purpose', 'iv']);
    binding(h); h.ratchetPublicKey = point(h.ratchetPublicKey);
    sequenceValue(h.previousChainLength); sequenceValue(h.messageNumber); purpose(h.purpose);
    if (decodeBase64url(h.iv, 12).length !== 12) throw fail('INVALID_IV');
    return Object.freeze(h);
}
export function encodeRatchetAAD(value) {
    const h = ratchetHeader(value);
    return boundedHeader(fields('BE9-RATCHET-AAD', [...bindingBytes(h), pointBytes(h.ratchetPublicKey), counterBytes(h.previousChainLength), counterBytes(h.messageNumber), h.purpose, decodeBase64url(h.iv, 12)]));
}
export function ratchetPacket(value) {
    const p = exact(value, ['header', 'ciphertext']);
    const h = ratchetHeader(p.header);
    return { header: h, ciphertext: p.ciphertext, payload: payloadSnapshot(p.ciphertext, h.iv) };
}
export function expectations(value) {
    const e = exact(value, ['sender', 'receiver', 'sessionID', 'contextID', 'purpose'], 'ENVELOPE_EXPECTATION_REQUIRED');
    endpoint(e.sender); endpoint(e.receiver); decode32(e.sessionID); scalarString(e.contextID); purpose(e.purpose);
    return Object.freeze(e);
}
export function bootstrapExpected(value) {
    const e = exact(value, ['sender', 'receiver', 'sessionID', 'contextID'], 'ENVELOPE_EXPECTATION_REQUIRED');
    endpoint(e.sender); endpoint(e.receiver); decode32(e.sessionID); scalarString(e.contextID);
    return e;
}
export function checkExpectations(header, expected, localID) {
    if (header.receiver !== localID || Object.keys(expected).some(name => header[name] !== expected[name])) throw fail('ENVELOPE_EXPECTATION_MISMATCH');
}
export function reverse(b, publicKey) {
    return { ...binding(b), sender: b.receiver, receiver: b.sender,
        senderIdentityFingerprint: b.receiverIdentityFingerprint, receiverIdentityFingerprint: b.senderIdentityFingerprint,
        senderSigningFingerprint: b.receiverSigningFingerprint, receiverSigningFingerprint: b.senderSigningFingerprint,
        ratchetPublicKey: publicPoint(publicKey) };
}
