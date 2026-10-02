import Be8 from '../lib/bundle.mjs';
import { openDatabase, deleteDatabase } from './database.mjs';
import { encodeBase64url, decodeBase64url } from '../lib/encoding.mjs';

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
    const publicKey = { crv, ext, key_ops, kty, x, y, accID: id };
    return {
        id, engine, database, publicKey,
        createContext: (peerPublicKey, { purpose = 'data', contextID = crypto.randomUUID(), receiver = peerPublicKey.accID } = {}) =>
            engine.createDerivationContext(peerPublicKey, keyReference, { contextID, sender: id, receiver, purpose }),
        derive: (peerPublicKey, derivation) => engine.getDerivedKey(peerPublicKey, keyReference, derivation),
    };
}

export async function exchangePublicKeys(...participants) {
    for (const receiver of participants) {
        const peers = participants.filter(peer => peer !== receiver);
        await receiver.engine.addPublicKeys(peers.map(peer => ({
            accID: peer.id,
            publicKey: structuredClone(peer.publicKey),
        })), {
            // The test application explicitly trusts its known local participants.
            // No decision is read from the exchanged key objects.
            decisions: peers.map(peer => ({ peerID: peer.id, trust: 'confirmed' })),
        });
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
    const bytes = decodeBase64url(ciphertext);
    bytes[0] ^= 1;
    return encodeBase64url(bytes);
}

export function changedIV(iv) {
    const bytes = decodeBase64url(iv);
    bytes[0] ^= 1;
    return encodeBase64url(bytes);
}

export function isAuthenticationFailure(error) {
    return error instanceof DOMException && error.name === 'OperationError';
}

export function packetMetadata(packet) {
    const { version, suite, contextID, sender, receiver, senderFingerprint, receiverFingerprint, purpose, salt } = packet.header;
    return { version, suite, contextID, sender, receiver, senderFingerprint, receiverFingerprint, purpose, salt };
}
