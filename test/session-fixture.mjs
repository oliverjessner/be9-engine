import Be9, { STORES } from '../lib/bundle.mjs';
import { exchangePublicKeys } from './participants.mjs';
import { withTransaction, requestResult } from '../lib/persistence.mjs';
export const code = name => error => error instanceof Error && error.code === name;
export const rejected = error => error instanceof Error;
export async function signingPeers(...peers) {
    await exchangePublicKeys(...peers);
    const publicIdentities = await Promise.all(peers.map(peer => peer.engine.setupSigningIdentity()));
    for (let i = 0; i < peers.length; i++) for (let j = 0; j < peers.length; j++) if (i !== j) {
        await peers[i].engine.addSigningPublicKey(peers[j].id, publicIdentities[j].publicKey,
            { identityFingerprint: publicIdentities[j].identityFingerprint, expectedFingerprint: publicIdentities[j].fingerprint });
    }
    return publicIdentities;
}
export async function connect(alice, bob, contextID = 'ratchet test context') {
    const offer = await alice.engine.createSession(bob.id, { contextID });
    // Expectations originate in the local test application, independently of wire headers.
    const sessionID = (await alice.engine.getSession(offer.header.sessionID)).sessionID;
    const exp = { sender: alice.id, receiver: bob.id, sessionID, contextID };
    const answer = await bob.engine.acceptSession(offer, exp);
    await alice.engine.finishSession(answer, { ...exp, sender: bob.id, receiver: alice.id });
    return { sessionID, contextID, offer, answer,
        toBob: { ...exp, purpose: 'data' }, toAlice: { ...exp, sender: bob.id, receiver: alice.id, purpose: 'data' } };
}
export async function reload(context, peer) {
    const database = await context.open(peer.database.name);
    const engine = new Be9(peer.id, database.connection); await engine.setup();
    return { ...peer, database, engine };
}
export const read = (peer, store, id) => withTransaction(peer.database.connection, [STORES[store]], 'readonly', tx => requestResult(tx.objectStore(STORES[store]).get([peer.id, id])));
export const all = (peer, store) => withTransaction(peer.database.connection, [STORES[store]], 'readonly', tx => requestResult(tx.objectStore(STORES[store]).index('namespace').getAll(peer.id)));
export const change = (peer, store, id, mutate) => withTransaction(peer.database.connection, [STORES[store]], 'readwrite', tx => requestResult(tx.objectStore(STORES[store]).get([peer.id, id]), row => {
    const next = mutate(row); return requestResult(next === undefined ? tx.objectStore(STORES[store]).delete([peer.id, id]) : tx.objectStore(STORES[store]).put(next));
}));
export async function failureDeadline(promise) {
    let timer;
    try { return await Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Operation did not settle')), 5000); })]); }
    finally { clearTimeout(timer); }
}
export function acknowledge(context) { for (const db of context.databases) db.acknowledgeAborts(); }
