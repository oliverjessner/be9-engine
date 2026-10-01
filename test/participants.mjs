import Be8 from '../lib/bundle.mjs';
import { openDatabase, deleteDatabase } from './database.mjs';

// Opaque local key references stay inside each participant's closure. Only public JWKs are
// exchanged. The derive method always uses this participant's local private key.
export async function createParticipant(id, database) {
    const engine = new Be8(id, database.connection);
    await engine.setup();
    await database.whenIdle();
    const { keyReference } = await engine.generatePrivAndPubKey();
    const storedPublicKey = await engine.getMyPublicKey();
    await database.whenIdle();
    const { crv, ext, key_ops, kty, x, y } = storedPublicKey;
    const publicKey = { crv, ext, key_ops, kty, x, y };
    return {
        id, engine, database, publicKey,
        derive: peerPublicKey => engine.getDerivedKey(peerPublicKey, keyReference),
    };
}

export async function exchangePublicKeys(...participants) {
    for (const receiver of participants) {
        const peers = participants.filter(peer => peer !== receiver);
        await receiver.engine.addPublicKeys(peers.map(peer => ({
            accID: peer.id,
            publicKey: structuredClone(peer.publicKey),
        })));
        await receiver.database.whenIdle();
    }
}

export function participantHooks(hooks) {
    hooks.beforeEach(async function () {
        this.databases = [];
        this.open = async (name, options) => {
            const database = await openDatabase(name, options);
            this.databases.push(database);
            return database;
        };
        this.alice = await createParticipant('101', await this.open());
        this.bob = await createParticipant('102', await this.open());
        this.eve = await createParticipant('103', await this.open());
    });
    hooks.afterEach(async function () {
        // Only delete unique databases created by this test. Never use panic()
        // to clear a shared/application database.
        const results = await Promise.allSettled(this.databases.map(db => db.whenIdle()));
        this.databases.forEach(db => db.close());
        await Promise.all([...new Set(this.databases.map(db => db.name))].map(deleteDatabase));
        if (results.some(result => result.status === 'rejected')) {
            throw new Error('Test database cleanup observed an aborted transaction');
        }
    });
}

export function changedCiphertext(ciphertext) {
    const bytes = Uint8Array.from(atob(ciphertext), character => character.charCodeAt(0));
    bytes[0] ^= 1;
    return btoa(String.fromCharCode(...bytes));
}

export function changedIV(iv) {
    // Preserve the legacy IV's length and encoding while changing one byte.
    return (iv[0] === '0' ? '1' : '0') + iv.slice(1);
}

export function isAuthenticationFailure(error) {
    return error instanceof DOMException && error.name === 'OperationError';
}
