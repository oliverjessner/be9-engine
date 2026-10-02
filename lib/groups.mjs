import { STORES, engineError, requestResult } from './persistence.mjs';
import { accountID, groupID } from './key-store.mjs';
import { jwkThumbprint } from './crypto-keys.mjs';
import { scalarString } from './v2.mjs';
import { bytesSnapshot, encodeBase64url } from './encoding.mjs';
import { V2_LIMITS } from './limits.mjs';
import { GROUP_SUITE, importGroupSecret, groupGeneration, requireGroupSecret, deriveGroupAES, encodeGroupInfo } from './group-profile.mjs';
import { groupSnapshot, sequenceValue, headerSnapshot, envelopeSnapshot, encodeEnvelopeAAD, sealBytes, openBytes } from './envelope.mjs';
import { usageIdentity } from './usage.mjs';
export function groupOptions(options, purpose = false) {
    if (!options || typeof options !== 'object' || Array.isArray(options)
        || Reflect.ownKeys(options).some(field => !['contextID', ...(purpose ? ['purpose'] : [])].includes(field))) {
        throw engineError('group options allow only contextID and an explicit envelope purpose', 'INVALID_OPTIONS');
    }
    return { contextID: options.contextID, ...(purpose ? { purpose: options.purpose } : {}) };
}
function epochID(id, epoch) {
    groupID(id);
    if (id.length > 128 || sequenceValue(epoch) === 0n) throw engineError('invalid group epoch', 'INVALID_GROUP');
    return { groupID: id, epoch };
}
function metadata(record) {
    if (!record) throw engineError('group epoch is not available locally', 'GROUP_EPOCH_MISSING');
    const group = groupSnapshot({ groupID: record.groupID, epoch: record.epoch, generation: record.generation });
    accountID(record.issuer);
    return Object.freeze({ ...group, issuer: record.issuer });
}
function equal(left, right) { return ['groupID', 'epoch', 'generation', 'issuer'].every(field => left[field] === right[field]); }
export class Groups {
    constructor(keys, envelopes, replay, localID) { Object.assign(this, { keys, envelopes, replay, localID }); }
    async record(id, epoch) {
        const selected = epochID(id, epoch);
        return this.keys.run([STORES.groupEpochs], 'readonly', tx =>
            requestResult(tx.objectStore(STORES.groupEpochs).get([this.keys.namespace, selected.groupID, selected.epoch]), record => {
                metadata(record); requireGroupSecret(record.key); return record;
            }));
    }
    async store(record) {
        metadata(record); requireGroupSecret(record.key);
        return this.keys.run([STORES.groupEpochs], 'readwrite', tx => {
            const store = tx.objectStore(STORES.groupEpochs);
            return requestResult(store.get([this.keys.namespace, record.groupID, record.epoch]), current => {
                if (current) {
                    if (!equal(metadata(current), metadata(record))) throw engineError('immutable group epoch already has another generation or issuer', 'GROUP_EPOCH_CONFLICT');
                    requireGroupSecret(current.key);
                    return metadata(current);
                }
                return requestResult(store.add({ ...record, namespace: this.keys.namespace }), () => metadata(record));
            });
        });
    }
    async create(id, epoch, recipients, options) {
        const selected = epochID(id, epoch);
        options = groupOptions(options);
        const contextID = options.contextID;
        scalarString(contextID);
        if (!Array.isArray(recipients) || recipients.length > 256) throw engineError('explicit recipient array of at most 256 accounts required', 'INVALID_ACCOUNT');
        recipients = recipients.map(accountID);
        if (new Set(recipients).size !== recipients.length || recipients.includes(this.localID)) throw engineError('duplicate or local recipient', 'INVALID_ACCOUNT');
        const bytes = crypto.getRandomValues(new Uint8Array(32));
        try {
            const generation = await groupGeneration(bytes);
            const key = await importGroupSecret(bytes);
            const group = { ...selected, generation };
            const packages = [];
            // No membership records. Each recipient supplies only a trusted public key.
            for (const receiver of recipients) {
                packages.push({ recipient: receiver, envelope: await this.envelopes.seal(this.localID, receiver, bytes,
                    { contextID, purpose: 'key-wrap', group }) });
            }
            const result = await this.store({ ...group, issuer: this.localID, key });
            return { epoch: result, packages };
        } finally { bytes.fill(0); }
    }
    async import(value, expected) {
        const packet = envelopeSnapshot(value);
        const group = groupSnapshot(expected && { groupID: expected.groupID, epoch: expected.epoch, generation: expected.generation });
        const copied = expected && { sender: expected.sender, receiver: expected.receiver, contextID: expected.contextID, purpose: 'key-wrap' };
        if (!packet.header.group || !equal({ ...packet.header.group, issuer: packet.header.sender }, { ...group, issuer: copied?.sender })) {
            throw engineError('key package does not match expected issuer, group, epoch and generation', 'ENVELOPE_EXPECTATION_MISMATCH');
        }
        const opened = await this.envelopes.open({ header: packet.header, ciphertext: packet.ciphertext }, copied);
        try {
            if (await groupGeneration(opened.bytes) !== group.generation) throw engineError('group generation digest mismatch', 'INVALID_GROUP_KEY');
            const key = await importGroupSecret(opened.bytes);
            return await this.store({ ...group, issuer: copied.sender, key });
        } finally { opened.bytes.fill(0); }
    }
    async activate(id, epoch, { expectedCurrentEpoch } = {}) {
        epochID(id, epoch);
        if (expectedCurrentEpoch !== null) epochID(id, expectedCurrentEpoch);
        return this.keys.run([STORES.groupEpochs, STORES.activeEpochs], 'readwrite', tx => {
            const active = tx.objectStore(STORES.activeEpochs);
            return requestResult(tx.objectStore(STORES.groupEpochs).get([this.keys.namespace, id, epoch]), record => {
                metadata(record); requireGroupSecret(record.key);
                return requestResult(active.get([this.keys.namespace, id]), current => {
                    if ((current?.epoch ?? null) !== expectedCurrentEpoch) throw engineError('active epoch changed concurrently', 'GROUP_EPOCH_CONFLICT');
                    if (current && sequenceValue(epoch) < sequenceValue(current.epoch)) throw engineError('old epochs are archive-only', 'GROUP_EPOCH_DOWNGRADE');
                    return requestResult(active.put({ namespace: this.keys.namespace, groupID: id, epoch }), () => metadata(record));
                });
            });
        });
    }
    async epochs(id) {
        if (id !== undefined) groupID(id);
        return this.keys.run([STORES.groupEpochs], 'readonly', tx => requestResult(tx.objectStore(STORES.groupEpochs).index('namespace').getAll(this.keys.namespace),
            rows => rows.filter(row => id === undefined || row.groupID === id).map(metadata)));
    }
    async active(id) {
        groupID(id);
        return this.keys.run([STORES.groupEpochs, STORES.activeEpochs], 'readonly', tx =>
            requestResult(tx.objectStore(STORES.activeEpochs).get([this.keys.namespace, id]), active => active
                ? requestResult(tx.objectStore(STORES.groupEpochs).get([this.keys.namespace, id, active.epoch]), metadata) : undefined));
    }
    async stream(expected) {
        expected = expected && { groupID: expected.groupID, epoch: expected.epoch, generation: expected.generation, sender: expected.sender, contextID: expected.contextID, purpose: expected.purpose };
        const group = groupSnapshot({ groupID: expected?.groupID, epoch: expected?.epoch, generation: expected?.generation });
        accountID(expected?.sender); scalarString(expected?.contextID);
        if (!['data', 'attachment'].includes(expected?.purpose)) throw engineError('invalid group purpose', 'INVALID_PURPOSE');
        const record = await this.record(group.groupID, group.epoch);
        if (record.generation !== group.generation) throw engineError('expected group generation differs from local epoch', 'GROUP_EPOCH_CONFLICT');
        const [publicKey] = await this.keys.endpointKeys(expected.sender, this.localID, true);
        if (!publicKey) throw engineError('expected sender key is unavailable', 'INVALID_KEY');
        return { record, header: { version: 2, suite: GROUP_SUITE, contextID: expected.contextID,
            sender: expected.sender, receiver: group.groupID, senderFingerprint: await jwkThumbprint(publicKey),
            receiverFingerprint: group.generation, purpose: expected.purpose, group } };
    }
    async openReceive(expected) {
        const { header } = await this.stream(expected);
        await this.replay.openContext(header.contextID);
        await this.replay.initialize(header, 'receive');
    }
    async seal(id, value, options) {
        const bytes = bytesSnapshot(value, V2_LIMITS.plaintextBytes);
        options = groupOptions(options, true);
        const contextID = options.contextID;
        scalarString(contextID);
        const active = await this.active(id);
        if (!active) throw engineError('explicitly activate a group epoch first', 'GROUP_EPOCH_NOT_ACTIVE');
        const { record, header: base } = await this.stream({ ...active, sender: this.localID, contextID, purpose: options?.purpose });
        const metadata = { ...base, salt: encodeBase64url(crypto.getRandomValues(new Uint8Array(32))) };
        const key = await deriveGroupAES(record.key, metadata);
        const sequence = await this.replay.reserve(metadata);
        const template = headerSnapshot({ ...metadata, sequence, iv: encodeBase64url(new Uint8Array(12)) });
        await this.keys.reserveUsage(await usageIdentity(template.salt, encodeGroupInfo(template)), bytes.length, encodeEnvelopeAAD(template).length);
        const header = headerSnapshot({ ...template, iv: encodeBase64url(crypto.getRandomValues(new Uint8Array(12))) });
        return { header, ciphertext: await sealBytes(key, header, bytes) };
    }
    async open(value, expected) {
        const packet = envelopeSnapshot(value);
        // Copy expectations before storage or crypto yields.
        expected = expected && { sender: expected.sender, contextID: expected.contextID, purpose: expected.purpose,
            groupID: expected.groupID, epoch: expected.epoch, generation: expected.generation };
        const h = packet.header;
        if (h.suite !== GROUP_SUITE || !h.group || h.sender !== expected?.sender || h.contextID !== expected?.contextID || h.purpose !== expected?.purpose
            || h.group.groupID !== expected?.groupID || h.group.epoch !== expected?.epoch || h.group.generation !== expected?.generation) {
            throw engineError('group envelope differs from independent expectations', 'ENVELOPE_EXPECTATION_MISMATCH');
        }
        const { record, header } = await this.stream(expected);
        if (header.senderFingerprint !== h.senderFingerprint || header.receiverFingerprint !== h.receiverFingerprint) throw engineError('group key generation or sender fingerprint mismatch', 'DERIVATION_KEY_MISMATCH');
        const key = await deriveGroupAES(record.key, h);
        return { header: h, bytes: await openBytes(key, packet) };
    }
}
