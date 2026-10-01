import { getTypeOfKey } from './util.mjs';
import { KeyStore, accountID, namespaceID, groupID, groupVersion } from './key-store.mjs';
import { generatePair, deriveLegacyAES, jwkThumbprint, privateCryptoKey, keySnapshot } from './crypto-keys.mjs';
import { engineError, upgradeBe8Schema, STORES } from './persistence.mjs';
import { createV2Metadata, derivationSnapshot, deriveV2AES, V2_SUITE, encodeV2DerivationInfo } from './v2.mjs';
import { bytesSnapshot, encodeText, decodeText, encodeBase64url, decodeBase64url } from './encoding.mjs';
import { requireAES, payloadSnapshot, encryptPayload, decryptPayload } from './aes.mjs';
import { derivationUsageID } from './usage.mjs';
import { V2_LIMITS } from './limits.mjs';

export { upgradeBe8Schema, STORES } from './persistence.mjs';
export { jwkThumbprint } from './crypto-keys.mjs';
export { V2_SUITE, encodeV2DerivationInfo } from './v2.mjs';
export { encodeBase64url, decodeBase64url } from './encoding.mjs';
export { V2_LIMITS } from './limits.mjs';

export default class Be8 {
    static upgradeBe8Schema = upgradeBe8Schema;
    static STORES = STORES;
    static jwkThumbprint = jwkThumbprint;
    static V2_SUITE = V2_SUITE;
    static encodeV2DerivationInfo = encodeV2DerivationInfo;
    static encodeBase64url = encodeBase64url;
    static decodeBase64url = decodeBase64url;
    static V2_LIMITS = V2_LIMITS;

    #keys;
    #accID;
    #setupPromise;
    #references = new WeakMap();
    #derivedKeys = new WeakMap();

    constructor(accID, indexedDB, { namespace = accID } = {}) {
        this.#accID = accountID(accID);
        namespaceID(namespace);
        if (!indexedDB) throw engineError('no indexedDB passed to the constructor', 'DATABASE_NOT_READY');
        this.#keys = new KeyStore(indexedDB, accID, namespace);
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
        if (type === 'group') {
            const [group, version, extra] = id.split(':');
            if (extra !== undefined) throw engineError('invalid group identifier', 'INVALID_GROUP');
            return !!await this.#keys.groupKey(group, version);
        }
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

    async addGroupKeys(group, groupKeys, options = {}) {
        if (!Array.isArray(groupKeys) || !groupKeys.length) {
            throw engineError('group keys must be a nonempty array', 'INVALID_KEY');
        }
        await this.#keys.addGroupKeys(group, groupKeys, options);
    }

    async getMyPublicKey() { return this.#keys.myPublicKey(); }
    async getCachedKeys() { return this.#keys.publicKeys(); }
    async getCachedGroupKeys() { return this.#keys.groupKeys(); }

    async getCachedGroupVersions(group) {
        groupID(group);
        const keys = await this.getCachedGroupKeys();
        return keys.filter(key => key.groupID === group).map(key => key.version).sort((a, b) => b - a);
    }

    async generateGroupKeys(version, group) {
        const v = groupVersion(version);
        const id = groupID(group);
        let pair = await this.#keys.groupKey(id, v);
        if (pair && !pair[1]) throw engineError('existing group key has no private half', 'GROUP_CONFLICT');
        if (!pair) pair = await this.#keys.createGroup(id, v, await generatePair());
        return this.#publicResult(pair[0], id + ':' + v);
    }

    // Idempotent: never returns a private JWK or a private CryptoKey.
    async generatePrivAndPubKey() {
        const [publicKey] = await this.#ensureIdentity();
        return this.#publicResult(publicKey, this.#accID);
    }

    async #localPair(keyReference) {
        if (!keyReference) throw engineError('no private key passed to getDerivedKey', 'INVALID_PRIVATE_KEY');
        const reference = this.#references.get(keyReference);
        if (!reference) {
            // Preserve precise private-JWK/extractability errors, but v2 cannot
            // bind actual local public coordinates from an arbitrary CryptoKey.
            privateCryptoKey(keyReference);
            throw engineError('v2 requires an opaque local key reference', 'INVALID_LOCAL_REFERENCE');
        }
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
        const local = await this.#localPair(keyReference);
        const key = await deriveV2AES(local.endpoint, local.publicKey, publicKey, local.privateKey, context);
        await this.#trackDerivedKey(key, local.endpoint, context);
        return key;
    }

    // Explicit, decrypt-only legacy KDF. Never selected after an auth failure.
    async getLegacyDerivedKey(publicKey, privateKey) {
        if (!publicKey) throw engineError('no public key passed to legacy derivation', 'INVALID_KEY');
        publicKey = keySnapshot(publicKey);
        if (this.#references.has(privateKey)) privateKey = (await this.#localPair(privateKey)).privateKey;
        return deriveLegacyAES(publicKey, privateKey);
    }

    async #simpleDerivation(sender, receiver, sending, purpose, metadata, options = {}) {
        const localID = sending ? sender : receiver;
        const peerID = sending ? receiver : sender;
        const context = !sending && metadata ? derivationSnapshot(metadata) : undefined;
        if (!options || typeof options !== 'object' || Array.isArray(options)
            || Reflect.ownKeys(options).some(field => field !== 'contextID')) {
            throw engineError('convenience options allow only contextID, never a custom IV or key alias', 'INVALID_OPTIONS');
        }
        const contextID = options.contextID;
        const [publicKey, privateKey, ownPublic] = await this.#keys.endpointKeys(peerID, localID, true);
        if (!publicKey) throw engineError('Missing public key for selected peer', 'INVALID_KEY');
        if (!privateKey) throw engineError('Missing private key for local endpoint', 'INVALID_PRIVATE_KEY');
        let derivation;
        if (sending) {
            derivation = await createV2Metadata(localID, ownPublic, publicKey, {
                contextID: contextID === undefined ? crypto.randomUUID() : contextID,
                sender, receiver, purpose,
            });
        } else {
            derivation = derivationSnapshot(context);
            if (derivation.sender !== sender || derivation.receiver !== receiver || derivation.purpose !== purpose
                || (contextID !== undefined && derivation.contextID !== contextID)) {
                throw engineError('v2 context does not match this operation', 'INVALID_DERIVATION_CONTEXT');
            }
        }
        const key = await deriveV2AES(localID, ownPublic, publicKey, privateKey, derivation);
        await this.#trackDerivedKey(key, localID, derivation);
        return { key, derivation };
    }

    async #trackDerivedKey(key, localID, derivation) {
        this.#derivedKeys.set(key, {
            derivationID: await derivationUsageID(derivation),
            sending: localID === derivation.sender,
        });
    }

    async #encryptBytes(key, bytes) {
        requireAES(key, 'encrypt');
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
        return new Uint8Array(await decryptPayload(key, payload));
    }

    async encryptText(key, text = '') {
        requireAES(key, 'encrypt');
        return this.#encryptBytes(key, encodeText(text));
    }

    async decryptText(key, ciphertext, iv) {
        requireAES(key, 'decrypt');
        const payload = payloadSnapshot(ciphertext, iv);
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

    async encryptTextSimple(sender, receiver, text = '', options = {}) {
        const bytes = encodeText(text);
        const context = await this.#simpleDerivation(sender, receiver, true, 'data', undefined, options);
        return { ...await this.#encryptBytes(context.key, bytes), derivation: context.derivation };
    }

    async decryptTextSimple(sender, receiver, ciphertext, iv, derivation, options = {}) {
        const payload = payloadSnapshot(ciphertext, iv);
        const context = await this.#simpleDerivation(sender, receiver, false, 'data', derivation, options);
        return decodeText(await decryptPayload(context.key, payload));
    }

    async encryptImageSimple(sender, receiver, base64Image, options = {}) {
        const bytes = encodeText(base64Image);
        const context = await this.#simpleDerivation(sender, receiver, true, 'attachment', undefined, options);
        const packet = await this.#encryptBytes(context.key, bytes);
        return { cipherImage: packet.cipherText, iv: packet.iv, derivation: context.derivation };
    }

    async decryptImageSimple(sender, receiver, cipherImage, iv, derivation, options = {}) {
        const payload = payloadSnapshot(cipherImage, iv);
        const context = await this.#simpleDerivation(sender, receiver, false, 'attachment', derivation, options);
        return decodeText(await decryptPayload(context.key, payload));
    }

    async decryptTextLegacy(key, ciphertext, iv) {
        requireAES(key, 'decrypt');
        const payload = payloadSnapshot(ciphertext, iv, true);
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

    async panic() { await this.#keys.clear(); }
}
