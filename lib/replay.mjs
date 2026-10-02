/* global BigInt */
import { BE8_DOMAINS } from './legacy-be8.mjs';
import { engineError, STORES, requestResult } from './persistence.mjs';
import { scalarString, encodeFields } from './v2.mjs';
import { encodeBase64url } from './encoding.mjs';
import { sequenceValue, MAX_SEQUENCE } from './envelope.mjs';

export const REPLAY_WINDOW = 128;
const MASK = (1n << 128n) - 1n;
const emptyBitmap = '0'.repeat(32);
export async function streamIdentity(header, legacy = false) {
    const g = header.group;
    const fields = [header.suite, header.contextID, header.sender, header.receiver, header.senderFingerprint,
        header.receiverFingerprint, header.purpose, g?.groupID || '', g?.epoch || '', g?.generation || ''];
    const bytes = encodeFields(legacy ? BE8_DOMAINS.replay : 'BE9-REPLAY-STREAM', fields.map(value => new TextEncoder().encode(value)));
    return encodeBase64url(await crypto.subtle.digest('SHA-256', bytes));
}
function contextRecord(record) {
    if (!record) throw engineError('explicitly open the local context first', 'CONTEXT_NOT_OPEN');
    if (record.status === 'closed') throw engineError('context is permanently closed; use a fresh context ID', 'CONTEXT_CLOSED');
    if (record.status !== 'open' || !Array.isArray(record.streams) || record.streams.length > 1024
        || !record.streams.every(entry => entry && typeof entry.streamID === 'string' && /^[A-Za-z0-9_-]{43}$/.test(entry.streamID)
            && ['send', 'receive'].includes(entry.direction))) throw engineError('invalid context state', 'STATE_LOST');
    return record;
}
export class Replay {
    constructor(keys) { this.keys = keys; }
    async openContext(contextID) {
        scalarString(contextID);
        return this.keys.run([STORES.contexts], 'readwrite', tx => {
            const store = tx.objectStore(STORES.contexts);
            return requestResult(store.get([this.keys.namespace, contextID]), current => {
                if (current) { contextRecord(current); return { contextID, status: 'open' }; }
                return requestResult(store.add({ namespace: this.keys.namespace, contextID, status: 'open', streams: [] }), () => ({ contextID, status: 'open' }));
            });
        });
    }
    async closeContext(contextID) {
        scalarString(contextID);
        return this.keys.run([STORES.contexts], 'readwrite', tx => {
            const store = tx.objectStore(STORES.contexts);
            return requestResult(store.get([this.keys.namespace, contextID]), record => {
                if (!record) throw engineError('context is not open', 'CONTEXT_NOT_OPEN');
                if (record.status === 'closed') return;
                contextRecord(record);
                return requestResult(store.put({ ...record, status: 'closed' }));
            });
        });
    }
    async initialize(header, direction, legacy = false) {
        const streamID = await streamIdentity(header, legacy);
        const name = direction === 'send' ? STORES.sendState : STORES.receiveState;
        return this.keys.run([STORES.contexts, name], 'readwrite', tx => {
            const contexts = tx.objectStore(STORES.contexts);
            const states = tx.objectStore(name);
            return requestResult(contexts.get([this.keys.namespace, header.contextID]), value => {
                const context = contextRecord(value);
                const known = context.streams.some(entry => entry.streamID === streamID && entry.direction === direction);
                return requestResult(states.get([this.keys.namespace, header.contextID, streamID]), state => {
                    if (known) {
                        if (!state) throw engineError('registered stream state is missing; no reset is allowed', 'STATE_LOST');
                        return streamID;
                    }
                    if (state || context.streams.length >= 1024) throw engineError('inconsistent or exhausted context state', 'STATE_LOST');
                    const base = { namespace: this.keys.namespace, contextID: header.contextID, streamID };
                    states.add(direction === 'send' ? { ...base, last: '0' } : { ...base, highest: '0', bitmap: emptyBitmap });
                    return requestResult(contexts.put({ ...context, streams: [...context.streams, { streamID, direction }] }), () => streamID);
                });
            });
        });
    }
    async reserve(header) {
        const streamID = await this.initialize(header, 'send');
        return this.keys.run([STORES.contexts, STORES.sendState], 'readwrite', tx =>
            requestResult(tx.objectStore(STORES.contexts).get([this.keys.namespace, header.contextID]), context => {
                contextRecord(context);
                const store = tx.objectStore(STORES.sendState);
                return requestResult(store.get([this.keys.namespace, header.contextID, streamID]), record => {
                    if (!record) throw engineError('send counter is missing', 'STATE_LOST');
                    const last = sequenceValue(record.last);
                    if (last === MAX_SEQUENCE) throw engineError('uint64 send counter exhausted', 'COUNTER_EXHAUSTED');
                    const sequence = String(last + 1n);
                    return requestResult(store.put({ ...record, last: sequence }), () => sequence);
                });
            }));
    }
    async accept(header, legacy = false) {
        const streamID = await streamIdentity(header, legacy);
        return this.keys.run([STORES.contexts, STORES.receiveState], 'readwrite', tx =>
            requestResult(tx.objectStore(STORES.contexts).get([this.keys.namespace, header.contextID]), value => {
                const context = contextRecord(value);
                if (!context.streams.some(entry => entry.streamID === streamID && entry.direction === 'receive')) throw engineError('explicitly initialize expected receive stream first', 'STREAM_NOT_OPEN');
                const store = tx.objectStore(STORES.receiveState);
                return requestResult(store.get([this.keys.namespace, header.contextID, streamID]), record => {
                    if (!record || typeof record.bitmap !== 'string' || !/^[0-9a-f]{32}$/.test(record.bitmap)) throw engineError('receive state is missing or invalid', 'STATE_LOST');
                    let highest = sequenceValue(record.highest);
                    let bitmap = BigInt('0x' + record.bitmap);
                    if ((highest < 128n && (bitmap >> highest) !== 0n) || (highest > 0n && !(bitmap & 1n))) throw engineError('invalid receive window', 'STATE_LOST');
                    const sequence = sequenceValue(header.sequence);
                    if (sequence > highest) {
                        const distance = sequence - highest;
                        bitmap = distance >= 128n ? 1n : ((bitmap << distance) | 1n) & MASK;
                        highest = sequence;
                    } else {
                        const distance = highest - sequence;
                        if (distance >= 128n) throw engineError('sequence is outside the replay window', 'REPLAY_TOO_OLD');
                        const bit = 1n << distance;
                        if (bitmap & bit) throw engineError('sequence was already accepted', 'REPLAY_DUPLICATE');
                        bitmap |= bit;
                    }
                    return requestResult(store.put({ ...record, highest: String(highest), bitmap: bitmap.toString(16).padStart(32, '0') }));
                });
            }));
    }
}
