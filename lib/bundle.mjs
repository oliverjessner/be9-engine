import { getTypeOfKey } from './util.mjs';
import { KeyStore, accountID, namespaceID, groupID, groupVersion } from './key-store.mjs';
import { generatePair, deriveLegacyAES, jwkThumbprint, privateCryptoKey, keySnapshot } from './crypto-keys.mjs';
import { engineError, upgradeBe8Schema, STORES } from './persistence.mjs';
import { createV2Metadata, derivationSnapshot, deriveV2AES, V2_SUITE, encodeV2DerivationInfo } from './v2.mjs';
import { bytesSnapshot, encodeText, decodeText, encodeBase64url, decodeBase64url } from './encoding.mjs';
import { requireAES, payloadSnapshot, encryptPayload, decryptPayload } from './aes.mjs';
import { derivationUsageID } from './usage.mjs';
import { V2_LIMITS } from './limits.mjs';
import { Groups, groupOptions } from './groups.mjs';
import { GROUP_SUITE } from './group-profile.mjs';
import { Replay, REPLAY_WINDOW } from './replay.mjs';
import { jwkThumbprint as fingerprint } from './crypto-keys.mjs';
import { Envelopes, envelopeSnapshot, encodeEnvelopeAAD } from './envelope.mjs';

export { upgradeBe8Schema, STORES } from './persistence.mjs';
export { jwkThumbprint } from './crypto-keys.mjs';
export { V2_SUITE, encodeV2DerivationInfo } from './v2.mjs';
export { encodeBase64url, decodeBase64url } from './encoding.mjs';
export { V2_LIMITS } from './limits.mjs';
export { GROUP_SUITE } from './group-profile.mjs';
export { REPLAY_WINDOW } from './replay.mjs';
export { encodeEnvelopeAAD } from './envelope.mjs';

export default class Be8 {
    static upgradeBe8Schema = upgradeBe8Schema;
    static STORES = STORES;
    static jwkThumbprint = jwkThumbprint;
    static V2_SUITE = V2_SUITE;
    static GROUP_SUITE = GROUP_SUITE;
    static encodeV2DerivationInfo = encodeV2DerivationInfo;
    static encodeBase64url = encodeBase64url;
    static decodeBase64url = decodeBase64url;
    static V2_LIMITS = V2_LIMITS;
    static encodeEnvelopeAAD = encodeEnvelopeAAD;
    static REPLAY_WINDOW = REPLAY_WINDOW;

    #keys;
    #envelopes;
    #replay;
    #groups;
    #accID;
    #setupPromise;
    #references = new WeakMap();
    #derivedKeys = new WeakMap();
    #generation = {};
    #guarded = new WeakMap();
    #panicPromise;
    #reinitializePromise;

    #invalidateLocal() {
        this.#generation = {};
        this.#references = new WeakMap();
        this.#derivedKeys = new WeakMap();
        this.#guarded = new WeakMap();
        this.#setupPromise = undefined;
    }
    #guard(method, args) {
        const generation = this.#generation;
        let original;
        try { this.#keys.assertActive(); original = method.apply(this, args); }
        catch (error) { return Promise.reject(error); }
        if (this.#guarded.has(original)) return this.#guarded.get(original);
        const guarded = Promise.resolve(original).then(async result => {
            try {
                this.#keys.assertActive();
                if (generation !== this.#generation) throw engineError('operation generation invalidated', 'ENGINE_LOCKED');
                await this.#keys.checkLifecycle();
                this.#keys.assertActive();
                if (generation !== this.#generation) throw engineError('operation generation invalidated', 'ENGINE_LOCKED');
                return result;
            } catch (error) {
                if (result instanceof Uint8Array) result.fill(0);
                throw error;
            }
        });
        this.#guarded.set(original, guarded);
        return guarded;
    }

    constructor(accID, indexedDB, { namespace = accID } = {}) {
        this.#accID = accountID(accID);
        namespaceID(namespace);
        if (!indexedDB) throw engineError('no indexedDB passed to the constructor', 'DATABASE_NOT_READY');
        this.#keys = new KeyStore(indexedDB, accID, namespace);
        this.#replay = new Replay(this.#keys);
        this.#envelopes = new Envelopes(this.#keys, this.#accID, this.#replay);
        this.#groups = new Groups(this.#keys, this.#envelopes, this.#replay, this.#accID);
        this.#keys.onLock = () => this.#invalidateLocal();
        // Guard every public async operation, including raw AES/archive/getters.
        // Invoke synchronously so each method snapshots caller inputs before yields.
        for (const name of Object.getOwnPropertyNames(Be8.prototype)) {
            if (['constructor', 'getAccID', 'panic', 'reinitialize'].includes(name)) continue;
            const method = Be8.prototype[name];
            Object.defineProperty(this, name, { value: (...args) => this.#guard(method, args) });
        }
    }

    setup(options = {}) {
        if (Object.keys(options).length) {
            return Promise.reject(engineError('use migratePrivateKeys() for explicit migration', 'PRIVATE_KEY_MIGRATION_REQUIRED'));
        }
        if (this.#setupPromise) return this.#setupPromise;
        const pending = this.#initialize();
        this.#setupPromise = pending;
        const reset = () => { if (this.#setupPromise === pending) this.#setupPromise = undefined; };
        pending.then(reset, reset);
        return pending;
    }

    async #initialize() {
        await this.#ensureIdentity();
        return this.getCachedKeys();
    }

    async #ensureIdentity() {
        const current = await this.#keys.identity();
        if (current) return current;
        if (await this.#keys.legacyPresent()) {
            throw engineError('explicit legacy identity migration required', 'LEGACY_IDENTITY');
        }
        return this.#keys.storeIdentity(await generatePair());
    }

    // References carry no key material and are usable only by this instance.
    #publicResult(publicKey, endpoint) {
        this.#keys.assertActive();
        const keyReference = Object.freeze({});
        this.#references.set(keyReference, { endpoint, x: publicKey.x, y: publicKey.y });
        return { publicKey, keyReference };
    }

    async migratePrivateKeys(options) { return this.#keys.migratePrivateKeys(options); }

    getAccID() { return this.#accID; }

    // Read committed state instead of maintaining per-instance key caches.
    // Separate instances/tabs may mutate this namespace between calls.
    async hasGeneratedKeys() { return !!await this.#keys.identity(); }

    async hasKey(id) {
        const type = getTypeOfKey(id);
        if (type === 'channel') return false;
        if (type === 'group') throw engineError('use hasLegacyGroupKey() for retained ECDH group records', 'LEGACY_GROUP_API');
        accountID(id);
        return id === this.#accID && !!await this.#keys.identity();
    }

    async addPublicKeys(publicKeys = [], options = {}) {
        if (!Array.isArray(publicKeys)) throw engineError('public keys must be an array', 'INVALID_KEY');
        await this.#keys.addPublicKeys(publicKeys, options);
    }

    async addPublicKey(accID, key, { expectedFingerprint, trust, tofu = false } = {}) {
        await this.addPublicKeys([{ accID, publicKey: key }], {
            tofu, decisions: [{ peerID: accID, expectedFingerprint, trust }],
        });
    }

    async getPeerTrust(id) { return this.#keys.peerTrust(id); }
    async migratePublicKeyTrust() { return this.#keys.migratePublicKeyTrust(); }
    async replacePublicKey(id, publicKey, confirmation) { return this.#keys.replacePublicKey(id, publicKey, confirmation); }

    async addGroupKeys() { throw engineError('use symmetric group epochs or explicitly addLegacyGroupKeys for retained ECDH data', 'LEGACY_GROUP_API'); }

    async addLegacyGroupKeys(group, groupKeys, options = {}) {
        if (!Array.isArray(groupKeys) || !groupKeys.length) {
            throw engineError('group keys must be a nonempty array', 'INVALID_KEY');
        }
        await this.#keys.addGroupKeys(group, groupKeys, options);
    }

    async getMyPublicKey() { return this.#keys.myPublicKey(); }
    async getCachedKeys() { return this.#keys.publicKeys(); }
    async getCachedLegacyGroupKeys() { return this.#keys.groupKeys(); }

    async getCachedLegacyGroupVersions(group) {
        groupID(group);
        const keys = await this.getCachedLegacyGroupKeys();
        return keys.filter(key => key.groupID === group).map(key => key.version).sort((a, b) => b - a);
    }

    async generateGroupKeys() { throw engineError('new groups require createGroupEpoch()', 'LEGACY_GROUP_API'); }

    async hasLegacyGroupKey(group, version) { return !!await this.#keys.groupKey(group, version); }

    async getLegacyGroupKeyReference(group, version) {
        const id = groupID(group), v = groupVersion(version);
        const pair = await this.#keys.groupKey(id, v);
        if (!pair || !pair[1]) throw engineError('retained legacy private group key is missing', 'INVALID_PRIVATE_KEY');
        return this.#publicResult(pair[0], id + ':' + v);
    }

    async createGroupEpoch(group, epoch, recipients, options) { return this.#groups.create(group, epoch, recipients, options); }
    async importGroupEpoch(envelope, expected) { return this.#groups.import(envelope, expected); }
    async activateGroupEpoch(group, epoch, options) { return this.#groups.activate(group, epoch, options); }
    async getGroupEpochs(group) { return this.#groups.epochs(group); }
    async getActiveGroupEpoch(group) { return this.#groups.active(group); }
    async encryptGroupEnvelope(group, bytes, options) { return this.#groups.seal(group, bytes, options); }
    async decryptGroupEnvelope(envelope, expected) { return (await this.#groups.open(envelope, expected)).bytes; }
    async encryptGroupText(group, text, options) { return this.#groups.seal(group, encodeText(text), { ...groupOptions(options), purpose: 'data' }); }
    async encryptGroupImage(group, image, options) { return this.#groups.seal(group, encodeText(image), { ...groupOptions(options), purpose: 'attachment' }); }
    async decryptGroupText(envelope, expected) {
        if (expected?.purpose !== 'data') throw engineError('text purpose required', 'INVALID_PURPOSE');
        return decodeText((await this.#groups.open(envelope, expected)).bytes);
    }
    async decryptGroupImage(envelope, expected) {
        if (expected?.purpose !== 'attachment') throw engineError('attachment purpose required', 'INVALID_PURPOSE');
        return decodeText((await this.#groups.open(envelope, expected)).bytes);
    }
    async openReceiveGroupContext(expected) { return this.#groups.openReceive(expected); }
    async receiveGroupEnvelope(envelope, expected) {
        const result = await this.#groups.open(envelope, expected);
        await this.#replay.accept(result.header);
        return result.bytes;
    }
    async receiveGroupText(envelope, expected) {
        if (expected?.purpose !== 'data') throw engineError('text purpose required', 'INVALID_PURPOSE');
        const result = await this.#groups.open(envelope, expected);
        const text = decodeText(result.bytes);
        await this.#replay.accept(result.header);
        return text;
    }
    async receiveGroupImage(envelope, expected) {
        if (expected?.purpose !== 'attachment') throw engineError('attachment purpose required', 'INVALID_PURPOSE');
        const result = await this.#groups.open(envelope, expected);
        const text = decodeText(result.bytes);
        await this.#replay.accept(result.header);
        return text;
    }

    // Idempotent: never returns a private JWK or a private CryptoKey.
    async generatePrivAndPubKey() {
        const [publicKey] = await this.#ensureIdentity();
        return this.#publicResult(publicKey, this.#accID);
    }

    async #localPair(keyReference, legacy = false) {
        if (!keyReference) throw engineError('no private key passed to getDerivedKey', 'INVALID_PRIVATE_KEY');
        const reference = this.#references.get(keyReference);
        if (!reference) {
            // Preserve precise private-JWK/extractability errors, but v2 cannot
            // bind actual local public coordinates from an arbitrary CryptoKey.
            privateCryptoKey(keyReference);
            throw engineError('v2 requires an opaque local key reference', 'INVALID_LOCAL_REFERENCE');
        }
        if (reference.endpoint.startsWith('g') && !legacy) throw engineError('ECDH group references are legacy-only', 'LEGACY_GROUP_API');
        const keys = await this.#keys.endpointKeys(reference.endpoint, reference.endpoint);
        if (!keys[0] || keys[0].x !== reference.x || keys[0].y !== reference.y) {
            throw engineError('local key reference is no longer valid', 'KEY_REFERENCE_INVALID');
        }
        return { endpoint: reference.endpoint, publicKey: keys[0], privateKey: keys[1] };
    }

    async createDerivationContext(publicKey, keyReference, options) {
        if (!publicKey) throw engineError('no public key passed to getDerivedKey', 'INVALID_KEY');
        publicKey = keySnapshot(publicKey);
        const copied = options && { contextID: options.contextID, sender: options.sender, receiver: options.receiver, purpose: options.purpose };
        if ((typeof copied?.sender === 'string' && copied.sender.startsWith('g')) || (typeof copied?.receiver === 'string' && copied.receiver.startsWith('g'))) throw engineError('ECDH group endpoints are legacy-only', 'LEGACY_GROUP_API');
        const local = await this.#localPair(keyReference);
        const derivation = await createV2Metadata(local.endpoint, local.publicKey, publicKey, copied);
        const key = await deriveV2AES(local.endpoint, local.publicKey, publicKey, local.privateKey, derivation);
        await this.#trackDerivedKey(key, local.endpoint, derivation);
        return { key, derivation };
    }

    async getDerivedKey(publicKey, keyReference, metadata) {
        if (!publicKey) throw engineError('no public key passed to getDerivedKey', 'INVALID_KEY');
        publicKey = keySnapshot(publicKey);
        // Copy transferred metadata synchronously, before storage or crypto yields.
        const context = metadata ? derivationSnapshot(metadata) : undefined;
        if (context?.sender.startsWith('g') || context?.receiver.startsWith('g')) throw engineError('ECDH group contexts require an explicit legacy reader', 'LEGACY_GROUP_API');
        const local = await this.#localPair(keyReference);
        const key = await deriveV2AES(local.endpoint, local.publicKey, publicKey, local.privateKey, context);
        await this.#trackDerivedKey(key, local.endpoint, context);
        return key;
    }

    // Explicit, decrypt-only legacy KDF. Never selected after an auth failure.
    async getLegacyDerivedKey(publicKey, privateKey) {
        if (!publicKey) throw engineError('no public key passed to legacy derivation', 'INVALID_KEY');
        publicKey = keySnapshot(publicKey);
        if (this.#references.has(privateKey)) privateKey = (await this.#localPair(privateKey, true)).privateKey;
        await this.#keys.checkLifecycle();
        return deriveLegacyAES(publicKey, privateKey);
    }

    async #trackDerivedKey(key, localID, derivation) {
        const generation = this.#generation;
        const derivationID = await derivationUsageID(derivation);
        await this.#keys.checkLifecycle();
        this.#keys.assertActive();
        if (generation !== this.#generation) throw engineError('derived key generation invalidated', 'ENGINE_LOCKED');
        this.#derivedKeys.set(key, {
            derivationID,
            sending: localID === derivation.sender,
        });
    }

    async #encryptBytes(key, bytes) {
        requireAES(key, 'encrypt');
        await this.#keys.checkLifecycle();
        const registered = this.#derivedKeys.get(key);
        if (registered) {
            if (!registered.sending) throw engineError('incoming directional key cannot encrypt; create a reverse context', 'INVALID_DERIVATION_CONTEXT');
            // Reservation commits before generating a nonce or invoking AES.
            // Failure after commit consumes the reservation; never refund it.
            await this.#keys.reserveUsage(registered.derivationID, bytes.length);
        }
        return encryptPayload(key, bytes);
    }

    async encryptBytes(key, value) {
        requireAES(key, 'encrypt');
        return this.#encryptBytes(key, bytesSnapshot(value, V2_LIMITS.plaintextBytes));
    }

    async decryptBytes(key, ciphertext, iv) {
        requireAES(key, 'decrypt');
        const payload = payloadSnapshot(ciphertext, iv);
        await this.#keys.checkLifecycle();
        return new Uint8Array(await decryptPayload(key, payload));
    }

    async encryptText(key, text = '') {
        requireAES(key, 'encrypt');
        return this.#encryptBytes(key, encodeText(text));
    }

    async decryptText(key, ciphertext, iv) {
        requireAES(key, 'decrypt');
        const payload = payloadSnapshot(ciphertext, iv);
        await this.#keys.checkLifecycle();
        return decodeText(await decryptPayload(key, payload));
    }

    async encryptImage(key, base64Image) {
        requireAES(key, 'encrypt');
        const packet = await this.#encryptBytes(key, encodeText(base64Image));
        return { cipherImage: packet.cipherText, iv: packet.iv };
    }

    async decryptImage(key, cipherImage, iv) {
        return this.decryptText(key, cipherImage, iv);
    }

    #simpleOptions(options = {}) {
        if (!options || typeof options !== 'object' || Array.isArray(options)
            || Reflect.ownKeys(options).some(field => field !== 'contextID')) throw engineError('only contextID is an allowed convenience option', 'INVALID_OPTIONS');
        return { contextID: options.contextID };
    }

    async openContext(contextID) { return this.#replay.openContext(contextID); }
    async closeContext(contextID) { return this.#replay.closeContext(contextID); }
    async openReceiveContext(expected) {
        if (!expected || expected.receiver !== this.#accID || !['data', 'attachment'].includes(expected.purpose)) throw engineError('independent receive expectations required', 'ENVELOPE_EXPECTATION_REQUIRED');
        expected = { sender: expected.sender, receiver: expected.receiver, contextID: expected.contextID, purpose: expected.purpose };
        const [peer, privateKey, own] = await this.#keys.endpointKeys(expected.sender, expected.receiver, true);
        if (!peer || !privateKey) throw engineError('receive endpoint keys are missing', 'INVALID_KEY');
        const metadata = { version: 2, suite: V2_SUITE, ...expected,
            senderFingerprint: await fingerprint(peer), receiverFingerprint: await fingerprint(own), group: null };
        await this.#replay.openContext(expected.contextID);
        await this.#replay.initialize(metadata, 'receive');
    }
    async receiveEnvelope(envelope, expected) {
        if (!expected || !['data', 'attachment'].includes(expected.purpose)) throw engineError('data receive expectations required', 'ENVELOPE_EXPECTATION_REQUIRED');
        const opened = await this.#envelopes.open(envelope, expected);
        await this.#replay.accept(opened.header);
        return opened.bytes;
    }
    async receiveText(envelope, expected) {
        if (expected?.purpose !== 'data') throw engineError('text purpose expected', 'INVALID_PURPOSE');
        const opened = await this.#envelopes.open(envelope, expected);
        const result = decodeText(opened.bytes);
        await this.#replay.accept(opened.header);
        return result;
    }
    async receiveImage(envelope, expected) {
        if (expected?.purpose !== 'attachment') throw engineError('attachment purpose expected', 'INVALID_PURPOSE');
        const opened = await this.#envelopes.open(envelope, expected);
        const result = decodeText(opened.bytes);
        await this.#replay.accept(opened.header);
        return result;
    }

    async encryptEnvelope(sender, receiver, bytes, options) {
        if (options && (typeof options !== 'object' || Array.isArray(options) || Reflect.ownKeys(options).some(field => !['contextID', 'purpose'].includes(field)))) throw engineError('envelope options allow only contextID and purpose', 'INVALID_OPTIONS');
        if (!options || !['data', 'attachment'].includes(options.purpose)) throw engineError('invalid envelope purpose', 'INVALID_PURPOSE');
        return this.#envelopes.seal(sender, receiver, bytes, { contextID: options.contextID, purpose: options.purpose });
    }

    async decryptEnvelope(envelope, expected) {
        if (!expected || !['data', 'attachment'].includes(expected.purpose)) throw engineError('independent data envelope expectations required', 'ENVELOPE_EXPECTATION_REQUIRED');
        return (await this.#envelopes.open(envelope, expected)).bytes;
    }

    async encryptTextSimple(sender, receiver, text = '', options = {}) {
        const bytes = encodeText(text);
        const supplied = this.#simpleOptions(options).contextID;
        const contextID = supplied ?? crypto.randomUUID();
        if (supplied === undefined) await this.openContext(contextID);
        return this.encryptEnvelope(sender, receiver, bytes, { contextID, purpose: 'data' });
    }

    async decryptTextSimple(sender, receiver, envelope, options = {}) {
        const copied = envelopeSnapshot(envelope);
        const contextID = this.#simpleOptions(options).contextID ?? copied.header.contextID;
        return decodeText(await this.decryptEnvelope({ header: copied.header, ciphertext: copied.ciphertext }, { sender, receiver, contextID, purpose: 'data' }));
    }

    async encryptImageSimple(sender, receiver, image, options = {}) {
        const bytes = encodeText(image);
        const supplied = this.#simpleOptions(options).contextID;
        const contextID = supplied ?? crypto.randomUUID();
        if (supplied === undefined) await this.openContext(contextID);
        return this.encryptEnvelope(sender, receiver, bytes, { contextID, purpose: 'attachment' });
    }

    async decryptImageSimple(sender, receiver, envelope, options = {}) {
        const copied = envelopeSnapshot(envelope);
        const contextID = this.#simpleOptions(options).contextID ?? copied.header.contextID;
        return decodeText(await this.decryptEnvelope({ header: copied.header, ciphertext: copied.ciphertext }, { sender, receiver, contextID, purpose: 'attachment' }));
    }

    // Explicit read path for retained pre-envelope HKDF packets. No fallback;
    // historical UUID encoding is selected by a separate local option.
    async #unframedLegacy(sender, receiver, ciphertext, iv, derivation, purpose, options = {}) {
        if (!options || typeof options !== 'object' || Array.isArray(options)
            || Reflect.ownKeys(options).some(field => !['contextID', 'legacyUUID'].includes(field))
            || (options.legacyUUID !== undefined && typeof options.legacyUUID !== 'boolean')) throw engineError('invalid explicit legacy read options', 'INVALID_OPTIONS');
        const contextID = options.contextID;
        const payload = payloadSnapshot(ciphertext, iv, options.legacyUUID === true);
        const metadata = derivationSnapshot(derivation);
        if (metadata.sender !== sender || metadata.receiver !== receiver || metadata.purpose !== purpose
            || (contextID !== undefined && metadata.contextID !== contextID)) throw engineError('legacy HKDF context mismatch', 'INVALID_DERIVATION_CONTEXT');
        const [peer, privateKey, own] = await this.#keys.endpointKeys(sender, receiver, true);
        if (!peer) throw engineError('Missing public key for selected peer', 'INVALID_KEY');
        if (!privateKey) throw engineError('Missing private key for local endpoint', 'INVALID_PRIVATE_KEY');
        const key = await deriveV2AES(receiver, own, peer, privateKey, metadata);
        return decodeText(await decryptPayload(key, payload));
    }
    async decryptTextUnframedLegacy(sender, receiver, ciphertext, iv, derivation, options = {}) {
        return this.#unframedLegacy(sender, receiver, ciphertext, iv, derivation, 'data', options);
    }
    async decryptImageUnframedLegacy(sender, receiver, ciphertext, iv, derivation, options = {}) {
        return this.#unframedLegacy(sender, receiver, ciphertext, iv, derivation, 'attachment', options);
    }

    async decryptTextLegacy(key, ciphertext, iv) {
        requireAES(key, 'decrypt');
        const payload = payloadSnapshot(ciphertext, iv, true);
        await this.#keys.checkLifecycle();
        return decodeText(await decryptPayload(key, payload));
    }

    async decryptImageLegacy(key, cipherImage, iv) {
        return this.decryptTextLegacy(key, cipherImage, iv);
    }

    async #legacySimple(sender, receiver, ciphertext, iv) {
        const payload = payloadSnapshot(ciphertext, iv, true);
        const [publicKey, privateKey] = await this.#keys.endpointKeys(sender, receiver, true);
        if (!publicKey) throw engineError('Missing public key for selected peer', 'INVALID_KEY');
        if (!privateKey) throw engineError('Missing private key for local endpoint', 'INVALID_PRIVATE_KEY');
        const key = await deriveLegacyAES(publicKey, privateKey);
        return decodeText(await decryptPayload(key, payload));
    }

    async decryptTextSimpleLegacy(sender, receiver, ciphertext, iv) {
        return this.#legacySimple(sender, receiver, ciphertext, iv);
    }

    async decryptImageSimpleLegacy(sender, receiver, cipherImage, iv) {
        return this.#legacySimple(sender, receiver, cipherImage, iv);
    }

    panic() {
        // Synchronous lock even if opening/deleting the database subsequently fails.
        this.#keys.lock();
        if (this.#panicPromise) return this.#panicPromise;
        const pending = this.#keys.invalidate();
        this.#panicPromise = pending;
        pending.catch(() => { if (this.#panicPromise === pending) this.#panicPromise = undefined; });
        return pending;
    }
    reinitialize() {
        if (this.#reinitializePromise) return this.#reinitializePromise;
        const pending = this.#reinitialize();
        this.#reinitializePromise = pending;
        const reset = () => { if (this.#reinitializePromise === pending) this.#reinitializePromise = undefined; };
        pending.then(reset, reset);
        return pending;
    }
    async #reinitialize() {
        this.#keys.lock();
        const generation = this.#generation;
        if (this.#panicPromise) await this.#panicPromise;
        const previous = await this.#keys.reinitializationState();
        const candidate = await generatePair();
        const next = await this.#keys.reinitialize(candidate, previous, () => generation === this.#generation);
        if (generation !== this.#generation) throw engineError('reinitialization invalidated', 'ENGINE_LOCKED');
        this.#keys.resume(next);
        this.#panicPromise = undefined;
        try {
            await this.#keys.checkLifecycle();
            return await this.getCachedKeys();
        } catch (error) { this.#keys.lock(); throw error; }
    }
}
