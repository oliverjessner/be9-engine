import { STORES, requestResult } from './persistence.mjs';
import { IDENTITY_STORES } from './signing.mjs';
import { fail, SESSION_LIMITS, schemaAvailable, decode32 } from './protocol.mjs';
import { validateState, stateTag, validatePair } from './ratchet.mjs';
import { bootstrapBytes } from './ratchet-envelope.mjs';
import { hash } from './protocol.mjs';

export const SESSION_STORES = [STORES.sessionRegistry, STORES.sessions, STORES.ratchetState, STORES.skippedKeys];
export class SessionStore {
    constructor(keys, signing) { this.keys = keys; this.signing = signing; }
    id(id) { decode32(id); schemaAvailable(this.keys, SESSION_STORES); return [this.keys.namespace, id]; }
    async snapshot(id) {
        const key = this.id(id);
        const snapshot = await this.keys.run(SESSION_STORES, 'readonly', tx => Promise.all([
            requestResult(tx.objectStore(STORES.sessionRegistry).get(key)),
            requestResult(tx.objectStore(STORES.sessions).get(key)),
            requestResult(tx.objectStore(STORES.ratchetState).get(key), state => {
                if (!state || !Array.isArray(state.skipped) || state.skipped.length > SESSION_LIMITS.skipped) return { state, skipped: [] };
                if (!state.skipped.every(ref => ref && typeof ref.chain === 'string' && typeof ref.number === 'string')) throw fail('RATCHET_STATE_LOST');
                return requestResult(tx.objectStore(STORES.skippedKeys).index('session').getAll(key, SESSION_LIMITS.skipped + 1), rows => {
                    if (rows.length !== state.skipped.length) throw fail('RATCHET_STATE_LOST');
                    const skipped = state.skipped.map(ref => rows.find(row => row.chain === ref.chain && row.number === ref.number));
                    return { state, skipped };
                });
            }),
        ]));
        const [registry, session, ratchet] = snapshot;
        if (!registry) { if (session || ratchet.state) throw fail('SESSION_STATE_LOST'); throw fail('SESSION_NOT_FOUND'); }
        if (!session) throw fail('SESSION_STATE_LOST');
        if (session.namespace !== this.keys.namespace || session.sessionID !== id || session.status !== registry.status || !['pending', 'active', 'closed'].includes(session.status)) throw fail('SESSION_STATE_LOST');
        if (session.status === 'closed') throw fail('SESSION_CLOSED');
        if (typeof session.initiator !== 'boolean' || session.offer?.sessionID !== id
            || (session.initiator ? session.offer.sender : session.offer.receiver) !== this.keys.accID
            || (session.initiator ? session.offer.receiver : session.offer.sender) !== session.peerID) throw fail('SESSION_STATE_LOST');
        if (session.status === 'active') {
            if (!ratchet.state || ratchet.state.namespace !== this.keys.namespace) throw fail('RATCHET_STATE_LOST');
            await validateState(ratchet.state, session, ratchet.skipped, registry);
        } else {
            if (ratchet.state || !session.initiator || registry.revision !== 0 || session.offer?.sessionID !== id || await hash(bootstrapBytes(session.offer)) !== registry.tag) throw fail('SESSION_STATE_LOST');
            await validatePair(session.pendingPrivate, session.offer.ratchetPublicKey);
        }
        return { registry, session, ...ratchet };
    }
    async create(session, state, identity) {
        const key = this.id(session.sessionID);
        session = { ...session, namespace: this.keys.namespace };
        if (state) { state = { ...state, namespace: this.keys.namespace }; state.tag = await stateTag(state, session, []); }
        const registry = { namespace: this.keys.namespace, sessionID: session.sessionID, status: session.status,
            revision: 0, tag: state?.tag || await hash(bootstrapBytes(session.offer)) };
        return this.keys.run([...SESSION_STORES, ...IDENTITY_STORES], 'readwrite', tx =>
            requestResult(tx.objectStore(STORES.sessionRegistry).index('namespace').getAll(this.keys.namespace, SESSION_LIMITS.registry + 2), rows => {
                if (rows.some(row => row.sessionID === session.sessionID)) throw fail('SESSION_ALREADY_EXISTS');
                if (rows.length >= SESSION_LIMITS.registry || rows.filter(row => row.sessionID !== '@signing' && ['active', 'pending'].includes(row.status)).length >= SESSION_LIMITS.sessions) throw fail('SESSION_LIMIT');
                return this.signing.check(tx, identity).then(() => requestResult(tx.objectStore(STORES.sessions).get(key), existing => {
                    if (existing) throw fail('SESSION_STATE_LOST');
                    tx.objectStore(STORES.sessionRegistry).add(registry);
                    tx.objectStore(STORES.sessions).add(session);
                    if (state) tx.objectStore(STORES.ratchetState).add(state);
                }));
            }));
    }
    async commit(snapshot, state, skipped, identity, session = snapshot.session) {
        const key = this.id(session.sessionID);
        state = { ...state, namespace: this.keys.namespace, revision: snapshot.registry.revision + 1,
            skipped: skipped.map(({ chain, number }) => ({ chain, number })) };
        if (!Number.isSafeInteger(state.revision)) throw fail('COUNTER_EXHAUSTED');
        state.tag = await stateTag(state, session, skipped);
        await this.keys.run([...SESSION_STORES, ...IDENTITY_STORES], 'readwrite', tx =>
            requestResult(tx.objectStore(STORES.sessionRegistry).get(key), registry => {
                if (!registry) throw fail('SESSION_STATE_LOST');
                if (registry.status === 'closed') throw fail('SESSION_CLOSED');
                if (registry.revision !== snapshot.registry.revision || registry.tag !== snapshot.registry.tag || registry.status !== snapshot.registry.status) throw fail('RATCHET_CONFLICT');
                return this.signing.check(tx, identity).then(() => requestResult(tx.objectStore(STORES.sessions).get(key), existing => {
                    if (!existing || existing.status !== snapshot.session.status || existing.peerID !== snapshot.session.peerID || existing.initiator !== snapshot.session.initiator) throw fail('SESSION_STATE_LOST');
                    return requestResult(tx.objectStore(STORES.ratchetState).get(key), current => {
                        if (!snapshot.state && current) throw fail('RATCHET_STATE_LOST');
                        if (snapshot.state && (!current || current.tag !== snapshot.state.tag || current.revision !== snapshot.state.revision)) throw fail('RATCHET_STATE_LOST');
                        if (current && snapshot.state && ['sendNumber', 'receiveNumber', 'previousChainLength', 'remotePreviousChainLength', 'steps', 'transcript', 'remoteFingerprint'].some(name => current[name] !== snapshot.state[name])) throw fail('RATCHET_STATE_LOST');
                        return requestResult(tx.objectStore(STORES.skippedKeys).index('session').getAll(key, SESSION_LIMITS.skipped + 1), rows => {
                            if (rows.length !== snapshot.skipped.length || !snapshot.skipped.every(item => rows.some(row => row.chain === item.chain && row.number === item.number))) throw fail('RATCHET_STATE_LOST');
                            // Both reads and writes use the same native transaction lock.
                            for (const ref of snapshot.state?.skipped || []) tx.objectStore(STORES.skippedKeys).delete([...key, ref.chain, ref.number]);
                            for (const row of skipped) tx.objectStore(STORES.skippedKeys).put(row);
                            tx.objectStore(STORES.sessions).put(session);
                            tx.objectStore(STORES.ratchetState).put(state);
                            return requestResult(tx.objectStore(STORES.sessionRegistry).put({ ...registry, status: session.status, revision: state.revision, tag: state.tag }));
                        });
                    });
                }));
            }));
    }
    async close(id) {
        const key = this.id(id);
        return this.keys.run(SESSION_STORES, 'readwrite', tx => requestResult(tx.objectStore(STORES.sessionRegistry).get(key), registry => {
            if (!registry) throw fail('SESSION_NOT_FOUND');
            if (registry.status === 'closed') return;
            return requestResult(tx.objectStore(STORES.ratchetState).get(key), state => {
                if (state?.skipped?.length > SESSION_LIMITS.skipped) throw fail('RATCHET_STATE_LOST');
                for (const ref of state?.skipped || []) tx.objectStore(STORES.skippedKeys).delete([...key, ref.chain, ref.number]);
                tx.objectStore(STORES.ratchetState).delete(key);
                tx.objectStore(STORES.sessions).put({ namespace: this.keys.namespace, sessionID: id, status: 'closed' });
                return requestResult(tx.objectStore(STORES.sessionRegistry).put({ ...registry, status: 'closed' }));
            });
        }));
    }
}
