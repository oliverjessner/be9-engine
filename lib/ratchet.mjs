/* global BigInt */
import { generatePair, validatePublicKey, privateCryptoKey, jwkThumbprint } from './crypto-keys.mjs';
import { fields, fail, hash, decode32, counterBytes, pointBytes, SESSION_LIMITS, publicPoint, native } from './protocol.mjs';
import { bootstrapBytes, bindingBytes } from './ratchet-envelope.mjs';
import { encodeBase64url, decodeBase64url } from './encoding.mjs';
import { sequenceValue, MAX_SEQUENCE } from './envelope.mjs';

const zero = new Uint8Array(32);
export function requireSecret(key, seed = false) {
    if (!(key instanceof CryptoKey) || key.type !== 'secret' || key.extractable || key.algorithm.name !== 'HKDF'
        || !key.usages.includes('deriveKey') || (!seed && !key.usages.includes('deriveBits'))
        || key.usages.length !== (seed ? 1 : 2)) throw fail('RATCHET_STATE_LOST');
    return key;
}
async function importSecret(bytes, seed = false) {
    return native(crypto.subtle.importKey('raw', bytes, 'HKDF', false, seed ? ['deriveKey'] : ['deriveBits', 'deriveKey']));
}
async function expand(key, salt, info, length) {
    return new Uint8Array(await native(crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, requireSecret(key), length)));
}
export async function dh(privateKey, publicKey) {
    const imported = await crypto.subtle.importKey('jwk', await validatePublicKey(publicKey), { name: 'ECDH', namedCurve: 'P-384' }, false, []);
    return new Uint8Array(await native(crypto.subtle.deriveBits({ name: 'ECDH', public: imported }, privateCryptoKey(privateKey), 384)));
}
export async function validatePair(privateKey, publicKey) {
    const [probePublic, probePrivate] = await generatePair();
    let a, b;
    try {
        a = await dh(privateKey, probePublic); b = await dh(probePrivate, publicKey);
        let mismatch = 0; for (let i = 0; i < a.length; i++) mismatch |= a[i] ^ b[i];
        if (mismatch) throw fail('RATCHET_STATE_LOST');
    } finally { a?.fill(0); b?.fill(0); }
}
export async function initialRoot(privateKey, remotePublic, offer, answer) {
    let secret, bytes;
    const transcript = await hash(fields('BE9-RATCHET-SESSION', [bootstrapBytes(offer), bootstrapBytes(answer, true)]));
    try {
        secret = await dh(privateKey, remotePublic);
        const input = await importSecret(secret);
        bytes = await expand(input, decode32(transcript), fields('BE9-RATCHET-SESSION-ROOT', [decode32(transcript)]), 256);
        return { root: await importSecret(bytes), transcript };
    } finally { secret?.fill(0); bytes?.fill(0); }
}
export async function rootStep(root, privateKey, remotePublic, transcript) {
    let secret, bytes;
    try {
        secret = await dh(privateKey, remotePublic);
        // HKDF salt is the full fresh DH secret; prior non-extractable root is IKM.
        bytes = await expand(root, secret, fields('BE9-RATCHET-ROOT', [decode32(transcript)]), 512);
        return { root: await importSecret(bytes.subarray(0, 32)), chain: await importSecret(bytes.subarray(32)) };
    } finally { secret?.fill(0); bytes?.fill(0); }
}
export async function chainStep(chain, transcript) {
    let bytes;
    try {
        bytes = await expand(chain, zero, fields('BE9-RATCHET-CHAIN', [decode32(transcript)]), 512);
        return { chain: await importSecret(bytes.subarray(0, 32)), seed: await importSecret(bytes.subarray(32), true) };
    } finally { bytes?.fill(0); }
}
export async function messageKey(seed, header, transcript, usage) {
    return native(crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: zero,
        info: fields('BE9-RATCHET-MESSAGE', [decode32(transcript), ...bindingBytes(header), pointBytes(header.ratchetPublicKey), counterBytes(header.previousChainLength), counterBytes(header.messageNumber), header.purpose]) },
    requireSecret(seed, true), { name: 'AES-GCM', length: 256 }, false, [usage]));
}
export async function blankState(sessionID, root, transcript, localPublic, localPrivate, remotePublic) {
    return { sessionID, revision: 0, root, transcript, localPublic: publicPoint(localPublic), localPrivate,
        remotePublic: publicPoint(remotePublic), remoteFingerprint: await jwkThumbprint(remotePublic),
        sendChain: null, receiveChain: null, sendNumber: '0', receiveNumber: '0', previousChainLength: '0', remotePreviousChainLength: null,
        steps: 0, retired: [], skipped: [] };
}
async function commitment(key, domain) {
    if (!key) return new Uint8Array();
    const native = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: zero, info: fields(domain, ['state']) },
        key, { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', native, fields('BE9-STATE-COMMITMENT', [domain])));
}
export async function stateTag(state, session, skipped) {
    requireSecret(state.root);
    const send = await commitment(state.sendChain, 'BE9-RATCHET-STATE-SEND');
    const receive = await commitment(state.receiveChain, 'BE9-RATCHET-STATE-RECEIVE');
    const inventory = [];
    for (const item of skipped) inventory.push(fields('BE9-RATCHET-STATE-SKIP', [decode32(item.chain), counterBytes(item.number), counterBytes(item.previousChainLength), await commitment(item.seed, 'BE9-RATCHET-STATE-SEED')]));
    const body = fields('BE9-RATCHET-STATE', [session.namespace, session.peerID, new Uint8Array([session.initiator ? 1 : 0]), session.status, bootstrapBytes(session.offer), bootstrapBytes(session.answer, true), decode32(state.transcript),
        counterBytes(String(state.revision)), pointBytes(state.localPublic), pointBytes(state.remotePublic), decode32(state.remoteFingerprint),
        counterBytes(state.sendNumber), counterBytes(state.receiveNumber), counterBytes(state.previousChainLength),
        state.remotePreviousChainLength === null ? new Uint8Array() : counterBytes(state.remotePreviousChainLength), counterBytes(String(state.steps)), send, receive,
        fields('BE9-RATCHET-RETIRED', state.retired.map(decode32)), fields('BE9-RATCHET-INVENTORY', inventory)]);
    const mac = await crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: zero, info: fields('BE9-RATCHET-STATE-AUTH', [decode32(state.transcript)]) }, state.root,
        { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign']);
    return encodeBase64url(await crypto.subtle.sign('HMAC', mac, body));
}
export async function validateState(state, session, skipped, registry) {
    try {
        if (!state || state.sessionID !== session.sessionID || state.revision !== registry.revision || state.tag !== registry.tag
            || !Number.isSafeInteger(state.revision) || state.revision < 0 || !Number.isInteger(state.steps) || state.steps < 0 || state.steps > SESSION_LIMITS.ratchetSteps
            || !Array.isArray(state.retired) || state.retired.length !== state.steps || state.retired.length > SESSION_LIMITS.ratchetSteps || new Set(state.retired).size !== state.retired.length
            || !Array.isArray(state.skipped) || state.skipped.length > SESSION_LIMITS.skipped || state.skipped.length !== skipped.length) throw new Error();
        requireSecret(state.root); if (state.sendChain) requireSecret(state.sendChain); if (state.receiveChain) requireSecret(state.receiveChain);
        for (const name of ['sendNumber', 'receiveNumber', 'previousChainLength']) sequenceValue(state[name]);
        if (state.remotePreviousChainLength !== null) sequenceValue(state.remotePreviousChainLength);
        if (!state.sendChain && state.sendNumber !== '0' || !state.receiveChain && state.receiveNumber !== '0') throw new Error();
        for (let i = 0; i < skipped.length; i++) {
            const item = skipped[i], ref = state.skipped[i];
            if (!item || item.sessionID !== session.sessionID || item.namespace !== state.namespace || item.chain !== ref.chain || item.number !== ref.number) throw new Error();
            decode32(item.chain); sequenceValue(item.number); sequenceValue(item.previousChainLength); requireSecret(item.seed, true);
        }
        if (await jwkThumbprint(state.remotePublic) !== state.remoteFingerprint || await stateTag(state, session, skipped) !== state.tag) throw new Error();
        await validatePair(state.localPrivate, state.localPublic);
    } catch { throw fail('RATCHET_STATE_LOST'); }
}
export async function advanceSend(state) {
    if (!state.sendChain) throw fail('SESSION_NOT_READY');
    if (sequenceValue(state.sendNumber) === MAX_SEQUENCE) throw fail('COUNTER_EXHAUSTED');
    const { chain, seed } = await chainStep(state.sendChain, state.transcript);
    return { seed, state: { ...state, sendChain: chain, sendNumber: String(sequenceValue(state.sendNumber) + 1n) } };
}
export async function advanceReceive(source, saved, header) {
    const state = { ...source, retired: [...source.retired] }, skipped = [...saved];
    const fingerprint = await jwkThumbprint(header.ratchetPublicKey);
    const existing = skipped.findIndex(item => item.chain === fingerprint && item.number === header.messageNumber);
    if (existing !== -1) {
        const [item] = skipped.splice(existing, 1);
        if (item.previousChainLength !== header.previousChainLength) throw fail('INVALID_ENVELOPE');
        return { state, skipped, seed: item.seed };
    }
    async function skipTo(until) {
        const target = sequenceValue(until), current = sequenceValue(state.receiveNumber);
        if (target < current) throw fail('RATCHET_DUPLICATE');
        if (target - current > BigInt(SESSION_LIMITS.gap)) throw fail('RATCHET_MESSAGE_TOO_FAR');
        if (skipped.length + Number(target - current) > SESSION_LIMITS.skipped) throw fail('SKIPPED_KEY_LIMIT');
        if (target > current && !state.receiveChain) throw fail('RATCHET_STATE_LOST');
        while (sequenceValue(state.receiveNumber) < target) {
            const step = await chainStep(state.receiveChain, state.transcript);
            skipped.push({ namespace: state.namespace, sessionID: state.sessionID, chain: state.remoteFingerprint,
                number: state.receiveNumber, previousChainLength: state.remotePreviousChainLength, seed: step.seed });
            state.receiveChain = step.chain; state.receiveNumber = String(sequenceValue(state.receiveNumber) + 1n);
        }
    }
    if (fingerprint !== state.remoteFingerprint) {
        if (state.retired.includes(fingerprint)) throw fail('RATCHET_DUPLICATE');
        if (state.steps >= SESSION_LIMITS.ratchetSteps) throw fail('RATCHET_LIMIT');
        await skipTo(header.previousChainLength);
        state.retired.push(state.remoteFingerprint);
        state.previousChainLength = state.sendNumber; state.sendNumber = '0'; state.receiveNumber = '0';
        state.remotePublic = header.ratchetPublicKey; state.remoteFingerprint = fingerprint; state.remotePreviousChainLength = header.previousChainLength;
        const receive = await rootStep(state.root, state.localPrivate, state.remotePublic, state.transcript);
        state.root = receive.root; state.receiveChain = receive.chain;
        const [publicKey, privateKey] = await generatePair(); state.localPublic = publicPoint(publicKey); state.localPrivate = privateKey;
        const send = await rootStep(state.root, privateKey, state.remotePublic, state.transcript);
        state.root = send.root; state.sendChain = send.chain; state.steps++;
    } else if (header.previousChainLength !== state.remotePreviousChainLength) throw fail('INVALID_ENVELOPE');
    await skipTo(header.messageNumber);
    if (sequenceValue(state.receiveNumber) === MAX_SEQUENCE) throw fail('COUNTER_EXHAUSTED');
    const step = await chainStep(state.receiveChain, state.transcript);
    state.receiveChain = step.chain; state.receiveNumber = String(sequenceValue(state.receiveNumber) + 1n);
    return { state, skipped, seed: step.seed };
}
export async function gcm(key, header, bytes, aad, decrypt = false) {
    try { return new Uint8Array(await crypto.subtle[decrypt ? 'decrypt' : 'encrypt']({ name: 'AES-GCM', tagLength: 128, iv: decodeBase64url(header.iv, 12), additionalData: aad }, key, bytes)); }
    catch { throw fail('AUTHENTICATION_FAILED'); }
}
