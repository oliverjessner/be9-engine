// Separate native JS realm, same local participant/database. Only public packet
// data leaves this realm; no CryptoKey or private bytes cross postMessage.
import Be9 from '../lib/bundle.mjs';
self.addEventListener('message', async event => {
    const { databaseName, accountID, sessionID } = event.data;
    let database;
    try {
        const request = indexedDB.open(databaseName);
        request.onupgradeneeded = () => request.transaction.abort();
        database = await new Promise((resolve, reject) => {
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(new Error());
            request.onblocked = () => reject(new Error());
        });
        const engine = new Be9(accountID, database);
        await engine.setup();
        self.postMessage({ packet: await engine.encryptRatchetText(sessionID, 'Alice worker') });
    } catch (error) {
        self.postMessage({ errorCode: typeof error.code === 'string' ? error.code : 'WORKER_TEST_FAILED' });
    } finally { database?.close(); }
});
