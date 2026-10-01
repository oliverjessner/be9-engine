import { generateIV, arrayBufferToBase64, getTypeOfKey } from './util.mjs';
import { KeyStore, accountID, namespaceID, groupID, groupVersion } from './key-store.mjs';
import { generatePair, deriveAES, jwkThumbprint } from './crypto-keys.mjs';
import { engineError, upgradeBe8Schema, STORES } from './persistence.mjs';

export { upgradeBe8Schema, STORES } from './persistence.mjs';
export { jwkThumbprint } from './crypto-keys.mjs';

export default class Be8 {
    static upgradeBe8Schema = upgradeBe8Schema;
    static STORES = STORES;
    static jwkThumbprint = jwkThumbprint;

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

    async getDerivedKey(publicKey, privateKey) {
        if (!publicKey) throw engineError('no public key passed to getDerivedKey', 'INVALID_KEY');
        if (!privateKey) throw engineError('no private key passed to getDerivedKey', 'INVALID_PRIVATE_KEY');
        const reference = this.#references.get(privateKey);
        if (reference) {
            const keys = await this.#keys.endpointKeys(reference.endpoint, reference.endpoint);
            if (!keys[0] || keys[0].x !== reference.x || keys[0].y !== reference.y) {
                throw engineError('local key reference is no longer valid', 'KEY_REFERENCE_INVALID');
            }
            privateKey = keys[1];
        }
        return deriveAES(publicKey, privateKey);
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

    async encryptTextSimple (accIDSender, accIDReceiver, text) {
        const [publicKey, privateKey] = await this.#keys.endpointKeys(accIDReceiver, accIDSender, true);
        
        if (!publicKey) {
            throw new Error(`engine: Missing public key for ${accIDReceiver} at encryptTextSimple`);
        }
        if (!privateKey) {
            throw new Error(`engine: Missing private key for ${accIDSender} at encryptTextSimple`);
        }

        const derivedKey = await this.getDerivedKey(publicKey, privateKey);

        return await this.encryptText(derivedKey, text);
    }

    async decryptTextSimple (accIDSender, accIDReceiver, cipherText, iv) {
        const [publicKey, privateKey] = await this.#keys.endpointKeys(accIDSender, accIDReceiver, true);
        
        if (!publicKey) {
            throw new Error(`engine: Missing public key for ${accIDSender} at decryptTextSimple`);
        }
        if (!privateKey) {
            throw new Error(`engine: Missing private key for ${accIDReceiver} at decryptTextSimple`);
        }

        const derivedKey = await this.getDerivedKey(publicKey, privateKey);

        return await this.decryptText(derivedKey, cipherText, iv);
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

    async encryptImageSimple (accIDSender, accIDReceiver, base64Image) {
        const [publicKey, privateKey] = await this.#keys.endpointKeys(accIDReceiver, accIDSender, true);
        
        if (!publicKey) {
            throw new Error(`engine: Missing public key for ${accIDSender} at encryptImageSimple`);
        }
        if (!privateKey) {
            throw new Error(`engine: Missing private key for ${accIDReceiver} at encryptImageSimple`);
        }

        const derivedKey = await this.getDerivedKey(publicKey, privateKey);
        
        return await this.encryptImage(derivedKey, base64Image);
    }

    async decryptImageSimple (accIDSender, accIDReceiver, cipherImage, iv) {
        const [publicKey, privateKey] = await this.#keys.endpointKeys(accIDSender, accIDReceiver, true);
        
        if (!publicKey) {
            throw new Error(`engine: Missing public key for ${accIDSender} at decryptImageSimple`);
        }
        if (!privateKey) {
            throw new Error(`engine: Missing private key for ${accIDReceiver} at decryptImageSimple`);
        }

        const derivedKey = await this.getDerivedKey(publicKey, privateKey);

        return await this.decryptImage(derivedKey, cipherImage, iv);
    }

    async panic() { await this.#keys.clear(); }
}
