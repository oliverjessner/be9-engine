// A second JS realm exercises persisted lifecycle checks, not the same-realm
// weak registry. Only public control metadata and sanitized error codes cross.
import Be8 from '../lib/bundle.mjs';
let engine, key, db;
async function code(work) { try { await work(); return 'UNEXPECTED_SUCCESS'; } catch (error) { return error.code || 'UNEXPECTED_ERROR'; } }
self.onmessage = async event => {
    try {
        if (event.data.command === 'open') {
            const request = indexedDB.open(event.data.name);
            db = await new Promise((resolve, reject) => {
                request.onsuccess = () => resolve(request.result);
                request.onerror = () => reject(new Error());
            });
            engine = new Be8(event.data.accID, db);
            await engine.setup();
            key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
            self.postMessage({ status: 'ready' });
        } else if (event.data.command === 'probe') {
            const encryption = await code(() => engine.encryptText(key, 'Local fixture'));
            const setup = await code(() => engine.setup());
            self.postMessage({ encryption, setup });
        } else if (event.data.command === 'panic') {
            self.postMessage({ panic: await code(() => engine.panic()) });
        }
    } catch { self.postMessage({ status: 'fixture-error' }); }
};
