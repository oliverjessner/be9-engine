import { generateIV, arrayBufferToBase64, getTypeOfKey } from './util.mjs';
import { KeyStore, accountID, namespaceID, groupID, groupVersion } from './key-store.mjs';
import { generatePair, deriveLegacyAES, jwkThumbprint, privateCryptoKey, keySnapshot } from './crypto-keys.mjs';
import { engineError, upgradeBe8Schema, STORES } from './persistence.mjs';
import { createV2Metadata, derivationSnapshot, deriveV2AES, V2_SUITE, encodeV2DerivationInfo } from './v2.mjs';

export { upgradeBe8Schema, STORES } from './persistence.mjs';
export { jwkThumbprint } from './crypto-keys.mjs';
export { V2_SUITE, encodeV2DerivationInfo } from './v2.mjs';

export default class Be8 {
    static upgradeBe8Schema = upgradeBe8Schema;
    static STORES = STORES;
    static jwkThumbprint = jwkThumbprint;
    static V2_SUITE = V2_SUITE;
    static encodeV2DerivationInfo = encodeV2DerivationInfo;

    #keys;
    #accID;
    #setupPromise;
    #references = new WeakMap();

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
        return { key, derivation };
    }

    async getDerivedKey(publicKey, keyReference, metadata) {
        if (!publicKey) throw engineError('no public key passed to getDerivedKey', 'INVALID_KEY');
        publicKey = keySnapshot(publicKey);
        // Copy transferred metadata synchronously, before storage or crypto yields.
        const context = metadata ? derivationSnapshot(metadata) : undefined;
        const local = await this.#localPair(keyReference);
        return deriveV2AES(local.endpoint, local.publicKey, publicKey, local.privateKey, context);
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
        return { key: await deriveV2AES(localID, ownPublic, publicKey, privateKey, derivation), derivation };
    }

    async encryptText (derivedKey, text = '') {
        const encodedText = new TextEncoder().encode(text);
        const iv = generateIV();
        const stringifiedIV = new TextDecoder().decode(iv);
        const algorithm = { 
            name: 'AES-GCM', 
            iv
        };

        if (!derivedKey) {
            throw new Error('engine: no derived key passed to encryptText');
        }
    
        return window.crypto.subtle.encrypt(algorithm, derivedKey, encodedText).then(function (encryptedData) {
            const uintArray = new Uint8Array(encryptedData);
            const string = String.fromCharCode.apply(null, uintArray);
            const cipherText = window.btoa(string);
          
            return { cipherText, iv: stringifiedIV };
        });
    }

    async decryptText (derivedKey, cipherText = '', iv) {
        const mstring = window.atob(cipherText);
        const uintArray = new Uint8Array([...mstring].map((char) => char.charCodeAt(0)));
        const parsedIV = new TextEncoder('utf-8').encode(iv);
        const algorithm = {
            name: 'AES-GCM',
            iv: parsedIV,
        };

        if (!derivedKey) {
            throw new Error('engine: no derived key passed to decryptText');
        }
        if (!iv) {
            throw new Error('engine: no iv (Initialization vector) passed to decryptText');
        }
    
        return window.crypto.subtle.decrypt(algorithm, derivedKey, uintArray).then(function (decryptedData) {
            return new TextDecoder().decode(decryptedData);
        });
    }

    async encryptTextSimple(sender, receiver, text, options = {}) {
        const context = await this.#simpleDerivation(sender, receiver, true, 'data', undefined, options);
        return { ...await this.encryptText(context.key, text), derivation: context.derivation };
    }

    async decryptTextSimple(sender, receiver, cipherText, iv, derivation, options = {}) {
        const context = await this.#simpleDerivation(sender, receiver, false, 'data', derivation, options);
        return this.decryptText(context.key, cipherText, iv);
    }

    async decryptTextSimpleLegacy(sender, receiver, cipherText, iv) {
        const [publicKey, privateKey] = await this.#keys.endpointKeys(sender, receiver, true);
        if (!publicKey) throw engineError('Missing public key for selected peer', 'INVALID_KEY');
        if (!privateKey) throw engineError('Missing private key for local endpoint', 'INVALID_PRIVATE_KEY');
        return this.decryptText(await deriveLegacyAES(publicKey, privateKey), cipherText, iv);
    }

    async encryptImage (derivedKey, base64Image) {
        const encodedText = new TextEncoder().encode(base64Image);
        const iv = generateIV();
        const stringifiedIV = new TextDecoder().decode(iv);
        
        if (!derivedKey) {
            throw new Error('engine: no derived key passed to decryptText');
        }
    
        return window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, derivedKey, encodedText).then(function (encryptedData) {
            return {
                cipherImage: arrayBufferToBase64(encryptedData),
                iv: stringifiedIV
            };
        });
    }

    async decryptImage (derivedKey, cipherImage, iv) {
        const mstring = window.atob(cipherImage);
        const uintArray = new Uint8Array([...mstring].map((char) => char.charCodeAt(0)));
        const parsedIV = new TextEncoder('utf-8').encode(iv);
        const algorithm = {
            name: 'AES-GCM',
            iv: parsedIV,
        };

        if (!derivedKey) {
            throw new Error('engine: no derived key passed to decryptText');
        }
    
        return window.crypto.subtle.decrypt(algorithm, derivedKey, uintArray).then(function (decryptedData) {
            return new TextDecoder().decode(decryptedData);
        });
    }

    async encryptImageSimple(sender, receiver, base64Image, options = {}) {
        const context = await this.#simpleDerivation(sender, receiver, true, 'attachment', undefined, options);
        return { ...await this.encryptImage(context.key, base64Image), derivation: context.derivation };
    }

    async decryptImageSimple(sender, receiver, cipherImage, iv, derivation, options = {}) {
        const context = await this.#simpleDerivation(sender, receiver, false, 'attachment', derivation, options);
        return this.decryptImage(context.key, cipherImage, iv);
    }

    async decryptImageSimpleLegacy(sender, receiver, cipherImage, iv) {
        const [publicKey, privateKey] = await this.#keys.endpointKeys(sender, receiver, true);
        if (!publicKey) throw engineError('Missing public key for selected peer', 'INVALID_KEY');
        if (!privateKey) throw engineError('Missing private key for local endpoint', 'INVALID_PRIVATE_KEY');
        return this.decryptImage(await deriveLegacyAES(publicKey, privateKey), cipherImage, iv);
    }

    async panic() { await this.#keys.clear(); }
}
