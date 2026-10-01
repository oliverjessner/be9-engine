import { generateIV, arrayBufferToBase64, getTypeOfKey } from './util.mjs';
import { KeyStore, accountID, namespaceID, groupID, groupVersion, publicPart, readLegacyIdentity } from './key-store.mjs';
import { engineError, upgradeBe8Schema, STORES } from './persistence.mjs';

export { upgradeBe8Schema, STORES } from './persistence.mjs';
export { readLegacyIdentity } from './key-store.mjs';

const keyUsages = Object.freeze(['deriveKey', 'deriveBits']);
const algorithmType = 'ECDH';
const algorithm = Object.freeze({ name: algorithmType, namedCurve: 'P-384' });
const format = 'jwk';

async function generatePair() {
    const { publicKey, privateKey } = await window.crypto.subtle.generateKey(algorithm, true, keyUsages);
    return Promise.all([
        window.crypto.subtle.exportKey(format, publicKey),
        window.crypto.subtle.exportKey(format, privateKey),
    ]);
}

export default class Be8 {
    static upgradeBe8Schema = upgradeBe8Schema;
    static readLegacyIdentity = readLegacyIdentity;
    static STORES = STORES;

    #keys;
    #accID;
    #setupPromise;

    constructor(accID, indexedDB, { namespace = accID } = {}) {
        this.#accID = accountID(accID);
        namespaceID(namespace);
        if (!indexedDB) throw engineError('no indexedDB passed to the constructor', 'DATABASE_NOT_READY');
        this.#keys = new KeyStore(indexedDB, accID, namespace);
    }

    setup({ legacyIdentity = false } = {}) {
        if (this.#setupPromise) return this.#setupPromise;
        const pending = this.#initialize(legacyIdentity);
        this.#setupPromise = pending;
        const reset = () => { if (this.#setupPromise === pending) this.#setupPromise = undefined; };
        pending.then(reset, reset);
        return pending;
    }

    async #initialize(legacyIdentity) {
        await this.#ensureIdentity(legacyIdentity);
        return this.getCachedKeys();
    }

    async #ensureIdentity(legacyIdentity = false) {
        const current = await this.#keys.identity();
        if (current) return current;
        let pair;
        let usingLegacy = false;
        if (await this.#keys.legacyPresent()) {
            if (!legacyIdentity) {
                throw engineError('explicit legacy identity migration required', 'LEGACY_IDENTITY');
            }
            pair = await readLegacyIdentity(this.#keys.connection, this.#accID);
            usingLegacy = true;
            if (!pair) throw engineError('legacy identity is missing', 'INCOMPLETE_IDENTITY');
            // Import validation occurs before opening a write transaction.
            await Promise.all([
                window.crypto.subtle.importKey(format, pair[0], algorithm, true, []),
                window.crypto.subtle.importKey(format, pair[1], algorithm, true, keyUsages),
            ]);
        } else {
            pair = await generatePair();
        }
        return this.#keys.storeIdentity(pair, usingLegacy);
    }

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

    async addPublicKeys(publicKeys = []) {
        if (!Array.isArray(publicKeys)) throw engineError('public keys must be an array', 'INVALID_KEY');
        await this.#keys.addPublicKeys(publicKeys);
    }

    async addPublicKey(accID, key) {
        await this.addPublicKeys([{ accID, publicKey: key }]);
    }

    async addGroupKeys(group, groupKeys) {
        if (!Array.isArray(groupKeys) || !groupKeys.length) {
            throw engineError('group keys must be a nonempty array', 'INVALID_KEY');
        }
        await this.#keys.addGroupKeys(group, groupKeys);
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
        const current = await this.#keys.groupKey(id, v);
        if (current) {
            if (!current.d) throw engineError('existing group key has no private half', 'GROUP_CONFLICT');
            return [publicPart(current), current];
        }
        const pair = await generatePair();
        return this.#keys.createGroup(id, v, pair);
    }

    // Idempotent: generating again does not silently rotate an existing identity.
    async generatePrivAndPubKey() { return this.#ensureIdentity(); }

    async getDerivedKey (publicKey, privateKey) {
        if (!publicKey) {
            throw new Error('engine: no public key passed to getDerivedKey');
        }
        if (!privateKey) {
            throw new Error('engine: no private key passed to getDerivedKey');
        }
        
        const publicKeyProm = window.crypto.subtle.importKey(format, publicKey, algorithm, true, []);
        const privateKeyProm = window.crypto.subtle.importKey(format, privateKey, algorithm, true, keyUsages);
    
        return Promise.all([publicKeyProm, privateKeyProm]).then(function ([publicKey, privateKey]) {
            const algorithm = { 
                name: 'AES-GCM', // Advanced Encryption Standard Galois/Counter Mode 
                length: 256 
            };

            return window.crypto.subtle.deriveKey({ name: algorithmType, public: publicKey }, privateKey, algorithm, true, ['encrypt', 'decrypt']);
        });
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
        const [publicKey, privateKey] = await this.#keys.endpointKeys(accIDReceiver, accIDSender);
        
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
        const [publicKey, privateKey] = await this.#keys.endpointKeys(accIDSender, accIDReceiver);
        
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
        const [publicKey, privateKey] = await this.#keys.endpointKeys(accIDReceiver, accIDSender);
        
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
        const [publicKey, privateKey] = await this.#keys.endpointKeys(accIDSender, accIDReceiver);
        
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
