import Be8, { STORES, upgradeBe8Schema, jwkThumbprint } from '../lib/bundle.mjs';
import { participantHooks, exchangePublicKeys, isAuthenticationFailure } from './participants.mjs';
import { readRecord, requestResult, storedIDs } from './database.mjs';

// P-384 public point computed independently with Node createECDH, scalar 1;
// expected RFC 7638 canonical JSON hashed with Node createHash('sha256').
const vector = {
    crv: 'P-384', kty: 'EC',
    x: 'qofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3',
    y: 'NhfeSpYmLG9dnpi_kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f',
};
const vectorFingerprint = '-W6Wzot_wuerYbKBVKfGEks3iY2EALna-hBqObnPuJE';

async function settles(promise) {
    let timer;
    try {
        return await Promise.race([
            promise.then(value => ({ value }), error => ({ error })),
            new Promise((resolve, reject) => { timer = setTimeout(() => reject(new Error('Trust operation did not settle')), 5000); }),
        ]);
    } finally { clearTimeout(timer); }
}

async function rawTrust(database, namespace, id) {
    const tx = database.transaction(STORES.trust, 'readonly');
    const value = await requestResult(tx.objectStore(STORES.trust).get([namespace, id]));
    await database.whenIdle();
    return value;
}

QUnit.module('Public-key validation and local peer trust', hooks => {
    participantHooks(hooks);

    QUnit.test('RFC 7638 thumbprints match an independent vector and ignore optional fields and account metadata', async function (assert) {
        assert.strictEqual(await jwkThumbprint(vector), vectorFingerprint, 'The SHA-256 base64url thumbprint matches the independent vector');
        const reordered = { y: vector.y, verified: true, accID: '999', x: vector.x, kid: 'transport label',
            kty: 'EC', namespace: 'different', crv: 'P-384', use: 'enc', alg: 'ECDH-ES', ext: false, key_ops: [] };
        assert.strictEqual(await Be8.jwkThumbprint(reordered), vectorFingerprint, 'Optional JWK fields, metadata and property ordering are excluded');
        assert.notStrictEqual(await jwkThumbprint(this.bob.publicKey), await jwkThumbprint(this.eve.publicKey), 'Independent public keys have different fingerprints');
        assert.true(/^[A-Za-z0-9_-]{43}$/.test(vectorFingerprint), 'Fingerprint encoding is unpadded base64url SHA-256');
    });

    QUnit.test('Imports reject wrong type, curve, coordinates, usage and private fields before any write', async function (assert) {
        const key = this.bob.publicKey;
        const invalid = [
            { ...key, kty: 'RSA' }, { ...key, crv: 'P-256' }, { ...key, x: 'short' },
            { ...key, x: key.x + '=' }, { ...key, y: '*'.repeat(64) },
            { ...key, x: 'A'.repeat(64), y: 'A'.repeat(64) },
            { ...key, x: '_'.repeat(64) }, { ...key, use: 'sig' }, { ...key, alg: 'ES384' },
            { ...key, key_ops: ['deriveKey'] }, { ...key, key_ops: ['verify'] },
            { ...key, ext: 'true' }, { ...key, d: undefined }, { ...key, d: 'A'.repeat(64) },
            { ...key, k: 'private' }, { ...key, p: 'private' },
        ];
        let writes = 0;
        this.alice.database.observe(tx => { if (tx.mode === 'readwrite') writes++; });
        for (const publicKey of invalid) {
            const result = await settles(this.alice.engine.addPublicKey(this.bob.id, publicKey, { trust: 'confirmed' }));
            assert.true(result.error instanceof Error && result.error.code === 'INVALID_KEY', 'Invalid public data is rejected with a generic Error');
        }
        this.alice.database.observe(undefined);
        assert.strictEqual(writes, 0, 'Native point validation and format checks finish before opening a write transaction');
        assert.deepEqual(await storedIDs(this.alice.database, 'publicKeys'), ['101'], 'No invalid peer key was stored');
        assert.strictEqual(await this.alice.engine.getPeerTrust(this.bob.id), undefined, 'Invalid imports created no trust record');
        await assert.rejects(this.alice.engine.getDerivedKey({ ...key, use: 'sig' }, (await this.alice.engine.generatePrivAndPubKey()).keyReference),
            error => error.code === 'INVALID_KEY', 'Primitive derivation also validates public usage');
    });

    QUnit.test('First contact stores unverified trust; imported verified flags never authorize convenience operations', async function (assert) {
        const { alice, bob } = this;
        await alice.engine.addPublicKeys([{ accID: bob.id, publicKey: { ...bob.publicKey, verified: true },
            verified: true, trust: 'confirmed', expectedFingerprint: await jwkThumbprint(bob.publicKey) }]);
        const trust = await alice.engine.getPeerTrust(bob.id);
        assert.strictEqual(trust.status, 'unverified', 'Trust flags and fingerprints embedded in imported objects are ignored');
        assert.strictEqual(trust.fingerprint, await jwkThumbprint(bob.publicKey), 'The unverified fingerprint is persisted');
        assert.strictEqual((await rawTrust(alice.database, alice.id, bob.id)).status, 'unverified', 'A dedicated namespace/peer trust record exists');
        await assert.rejects(alice.engine.encryptTextSimple(alice.id, bob.id, 'Unverified'), error => error.code === 'UNTRUSTED_PUBLIC_KEY', 'Text encryption refuses an unverified peer');
        await assert.rejects(alice.engine.encryptImageSimple(alice.id, bob.id, ''), error => error.code === 'UNTRUSTED_PUBLIC_KEY', 'Image encryption refuses an unverified peer');
        const incoming = await bob.engine.encryptText(await bob.derive(alice.publicKey), 'Unverified sender');
        await assert.rejects(alice.engine.decryptTextSimple(bob.id, alice.id, incoming.cipherText, incoming.iv),
            error => error.code === 'UNTRUSTED_PUBLIC_KEY', 'Convenience decryption also refuses an unverified sender');
        await alice.engine.addPublicKey(bob.id, bob.publicKey, { trust: 'confirmed' });
        assert.strictEqual((await alice.engine.getPeerTrust(bob.id)).status, 'confirmed', 'A separate explicit local decision authorizes the same key');
        assert.true(await alice.engine.decryptTextSimple(bob.id, alice.id, incoming.cipherText, incoming.iv) === 'Unverified sender', 'Confirmation enables actual recipient decryption');
    });

    QUnit.test('Wrong expected fingerprints reject first contact and preserve an existing confirmed key', async function (assert) {
        const { alice, bob, eve } = this;
        const wrong = await jwkThumbprint(eve.publicKey);
        const failed = await settles(alice.engine.addPublicKey(bob.id, bob.publicKey, { expectedFingerprint: wrong }));
        assert.true(failed.error?.code === 'FINGERPRINT_MISMATCH', 'A wrong expected fingerprint is rejected');
        alice.database.acknowledgeAborts();
        assert.strictEqual(await alice.engine.getPeerTrust(bob.id), undefined, 'First-contact failure leaves no trust record');
        assert.deepEqual(await storedIDs(alice.database, 'publicKeys'), ['101'], 'First-contact failure leaves no peer key');
        const fingerprint = await jwkThumbprint(bob.publicKey);
        await alice.engine.addPublicKey(bob.id, bob.publicKey, { expectedFingerprint: fingerprint });
        const reimport = await settles(alice.engine.addPublicKey(bob.id, bob.publicKey, { expectedFingerprint: wrong }));
        assert.true(reimport.error?.code === 'FINGERPRINT_MISMATCH', 'A wrong expectation cannot silently pass on reimport');
        alice.database.acknowledgeAborts();
        const current = await alice.engine.getPeerTrust(bob.id);
        assert.true(current.fingerprint === fingerprint && current.status === 'confirmed', 'The original confirmed trust record remains unchanged');
        assert.true((await readRecord(alice.database, 'publicKeys', [alice.id, bob.id])).x === bob.publicKey.x, 'The original public key remains unchanged');
        await assert.rejects(alice.engine.addPublicKey(eve.id, eve.publicKey, { expectedFingerprint: 'not a fingerprint' }),
            error => error.code === 'INVALID_FINGERPRINT', 'Malformed fingerprint arguments are rejected');
    });

    QUnit.test('Explicit TOFU authorizes only first contact and cannot approve a later key change', async function (assert) {
        const { alice, bob, eve } = this;
        await alice.engine.addPublicKey(bob.id, bob.publicKey, { tofu: true });
        assert.strictEqual((await alice.engine.getPeerTrust(bob.id)).status, 'tofu', 'First contact is labeled TOFU rather than independently confirmed');
        const packet = await alice.engine.encryptTextSimple(alice.id, bob.id, 'Explicit TOFU');
        assert.true(await bob.engine.decryptText(await bob.derive(alice.publicKey), packet.cipherText, packet.iv) === 'Explicit TOFU', 'Explicit TOFU enables interoperability');
        await alice.engine.addPublicKey(bob.id, bob.publicKey);
        assert.strictEqual((await alice.engine.getPeerTrust(bob.id)).status, 'tofu', 'Unchanged reimport retains the TOFU decision');
        const changed = await settles(alice.engine.addPublicKey(bob.id, eve.publicKey, { tofu: true }));
        assert.true(changed.error?.code === 'PUBLIC_KEY_CHANGED', 'TOFU never authorizes a later key change');
        alice.database.acknowledgeAborts();
        await alice.engine.addPublicKey(eve.id, eve.publicKey);
        await alice.engine.addPublicKey(eve.id, eve.publicKey, { tofu: true });
        assert.strictEqual((await alice.engine.getPeerTrust(eve.id)).status, 'unverified', 'TOFU cannot retroactively confirm an existing unverified contact');
        await alice.engine.addPublicKey(bob.id, bob.publicKey, { expectedFingerprint: await jwkThumbprint(bob.publicKey) });
        assert.strictEqual((await alice.engine.getPeerTrust(bob.id)).status, 'confirmed', 'Independent local confirmation can upgrade TOFU');
    });

    QUnit.test('Confirmed reimport is idempotent; ordinary imports cannot replace a confirmed peer even with a new confirmation', async function (assert) {
        const { alice, bob, eve } = this;
        const original = await jwkThumbprint(bob.publicKey);
        await alice.engine.addPublicKey(bob.id, bob.publicKey, { trust: 'confirmed' });
        await alice.engine.addPublicKey(bob.id, { ...bob.publicKey, kid: 'new label', verified: false });
        assert.true((await alice.engine.getPeerTrust(bob.id)).status === 'confirmed', 'Metadata-only reimport retains confirmation');
        for (const decision of [{}, { trust: 'confirmed' }, { expectedFingerprint: await jwkThumbprint(eve.publicKey) }]) {
            const result = await settles(alice.engine.addPublicKey(bob.id, eve.publicKey, decision));
            assert.true(result.error?.code === 'PUBLIC_KEY_CHANGED', 'Replacement requires the separate API in every import mode');
            alice.database.acknowledgeAborts();
        }
        assert.strictEqual((await alice.engine.getPeerTrust(bob.id)).fingerprint, original, 'Ordinary imports preserve the old fingerprint');
        assert.true((await readRecord(alice.database, 'publicKeys', [alice.id, bob.id])).x === bob.publicKey.x, 'Ordinary imports preserve the old point');
    });

    QUnit.test('Explicit replacement requires both fingerprints and updates key and confirmation atomically', async function (assert) {
        const { alice, bob, eve } = this;
        const previous = await jwkThumbprint(bob.publicKey);
        const next = await jwkThumbprint(eve.publicKey);
        await exchangePublicKeys(alice, bob);
        const wrongNew = await settles(alice.engine.replacePublicKey(bob.id, eve.publicKey,
            { expectedPreviousFingerprint: previous, confirmedNewFingerprint: previous }));
        assert.true(wrongNew.error?.code === 'FINGERPRINT_MISMATCH', 'The newly confirmed fingerprint must match the candidate');
        const wrongOld = await settles(alice.engine.replacePublicKey(bob.id, eve.publicKey,
            { expectedPreviousFingerprint: next, confirmedNewFingerprint: next }));
        assert.true(wrongOld.error?.code === 'TRUST_CONFLICT', 'The expected previous fingerprint must match the current peer');
        assert.strictEqual((await alice.engine.getPeerTrust(bob.id)).fingerprint, previous, 'Both rejected replacements retain the original trust');
        await alice.engine.replacePublicKey(bob.id, { ...eve.publicKey, accID: eve.id, namespace: 'wrong' },
            { expectedPreviousFingerprint: previous, confirmedNewFingerprint: next });
        assert.strictEqual(alice.database.pendingWrites(), 0, 'Replacement resolves only after commit');
        const trust = await alice.engine.getPeerTrust(bob.id);
        assert.true(trust.fingerprint === next && trust.status === 'confirmed', 'New point and explicit confirmation commit together');
        assert.deepEqual(await storedIDs(alice.database, 'publicKeys'), ['101', '102'], 'Embedded account metadata cannot change the selected peer');
        const packet = await alice.engine.encryptTextSimple(alice.id, bob.id, 'Confirmed replacement');
        assert.true(await eve.engine.decryptText(await eve.derive(alice.publicKey), packet.cipherText, packet.iv) === 'Confirmed replacement', 'Convenience derivation sees the newly committed key');
        await assert.rejects(bob.engine.decryptText(await bob.derive(alice.publicKey), packet.cipherText, packet.iv), isAuthenticationFailure, 'The previous private key no longer decrypts new packets');
        const stale = await settles(alice.engine.replacePublicKey(bob.id, bob.publicKey,
            { expectedPreviousFingerprint: previous, confirmedNewFingerprint: previous }));
        assert.true(stale.error?.code === 'TRUST_CONFLICT', 'A stale previous fingerprint cannot undo the change');
        await assert.rejects(alice.engine.replacePublicKey(alice.id, eve.publicKey,
            { expectedPreviousFingerprint: await jwkThumbprint(alice.publicKey), confirmedNewFingerprint: next }),
        error => error.code === 'IDENTITY_CONFLICT', 'The peer replacement API cannot rotate the local private identity');
    });

    QUnit.test('Abort after replacement key success preserves both original public key and trust', async function (assert) {
        const { alice, bob, eve } = this;
        await alice.engine.addPublicKey(bob.id, bob.publicKey, { trust: 'confirmed' });
        const previous = await jwkThumbprint(bob.publicKey);
        let written = false;
        alice.database.observe(tx => {
            if (tx.mode === 'readwrite' && tx.objectStoreNames.contains(STORES.trust)) {
                tx.addEventListener('success', event => {
                    if (event.target.source?.name === STORES.publicKeys && Array.isArray(event.target.result)) {
                        written = true; tx.abort();
                    }
                }, { capture: true });
            }
        });
        const result = await settles(alice.engine.replacePublicKey(bob.id, eve.publicKey,
            { expectedPreviousFingerprint: previous, confirmedNewFingerprint: await jwkThumbprint(eve.publicKey) }));
        alice.database.observe(undefined);
        assert.true(written && result.error instanceof Error, 'Successful native key write followed by abort rejects replacement');
        assert.strictEqual(alice.database.acknowledgeAborts(), 1, 'One transaction rolled back');
        assert.strictEqual((await alice.engine.getPeerTrust(bob.id)).fingerprint, previous, 'The original trust fingerprint survived rollback');
        assert.true((await readRecord(alice.database, 'publicKeys', [alice.id, bob.id])).x === bob.publicKey.x, 'The original point survived rollback');
    });

    QUnit.test('Concurrent confirmed replacements compare-and-swap across independent connections', async function (assert) {
        const { alice, bob, eve } = this;
        await alice.engine.addPublicKey(bob.id, bob.publicKey, { trust: 'confirmed' });
        const secondDB = await this.open(alice.database.name);
        const other = new Be8(alice.id, secondDB.connection);
        await other.setup();
        const previous = await jwkThumbprint(bob.publicKey);
        const candidates = [eve.publicKey, vector];
        const newFingerprints = await Promise.all(candidates.map(key => jwkThumbprint(key)));
        const result = await settles(Promise.allSettled([
            alice.engine.replacePublicKey(bob.id, candidates[0], { expectedPreviousFingerprint: previous, confirmedNewFingerprint: newFingerprints[0] }),
            other.replacePublicKey(bob.id, candidates[1], { expectedPreviousFingerprint: previous, confirmedNewFingerprint: newFingerprints[1] }),
        ]));
        assert.true(!result.error, 'Both competing update promises settle');
        assert.strictEqual(result.value.filter(entry => entry.status === 'fulfilled').length, 1, 'Exactly one replacement wins compare-and-swap');
        assert.true(result.value.find(entry => entry.status === 'rejected').reason.code === 'TRUST_CONFLICT', 'The stale competing replacement is rejected specifically');
        alice.database.acknowledgeAborts(); secondDB.acknowledgeAborts();
        const stored = await readRecord(alice.database, 'publicKeys', [alice.id, bob.id]);
        const finalFingerprint = await jwkThumbprint(stored);
        assert.true(newFingerprints.includes(finalFingerprint), 'The final point belongs to the winning confirmed candidate');
        assert.strictEqual((await alice.engine.getPeerTrust(bob.id)).fingerprint, finalFingerprint, 'One instance reads the matching committed trust');
        assert.strictEqual((await other.getPeerTrust(bob.id)).fingerprint, finalFingerprint, 'The other connection sees the same committed trust');
    });

    QUnit.test('Bulk imports cannot bypass replacement checks or partially commit keys and trust', async function (assert) {
        const { alice, bob, eve } = this;
        await alice.engine.addPublicKey(bob.id, bob.publicKey, { trust: 'confirmed' });
        const failed = await settles(alice.engine.addPublicKeys([
            { accID: eve.id, publicKey: eve.publicKey }, { accID: bob.id, publicKey: eve.publicKey },
        ], { decisions: [{ peerID: eve.id, trust: 'confirmed' }, { peerID: bob.id, trust: 'confirmed' }] }));
        assert.true(failed.error?.code === 'PUBLIC_KEY_CHANGED', 'A confirmed bulk decision does not authorize replacement');
        alice.database.acknowledgeAborts();
        assert.strictEqual(await alice.engine.getPeerTrust(eve.id), undefined, 'The earlier trust write in the batch rolled back');
        assert.deepEqual(await storedIDs(alice.database, 'publicKeys'), ['101', '102'], 'The earlier public-key write rolled back');
        const invalid = await settles(alice.engine.addPublicKeys([
            { accID: eve.id, publicKey: eve.publicKey }, { accID: '104', publicKey: { ...bob.publicKey, x: 'A'.repeat(64), y: 'A'.repeat(64) } },
        ], { tofu: true }));
        assert.true(invalid.error?.code === 'INVALID_KEY', 'Bulk TOFU still validates every native curve point');
        assert.strictEqual(await alice.engine.getPeerTrust(eve.id), undefined, 'Invalid bulk data grants no earlier trust');
        const duplicate = await settles(alice.engine.addPublicKeys([
            { accID: eve.id, publicKey: eve.publicKey }, { accID: eve.id, publicKey: bob.publicKey },
        ], { tofu: true }));
        assert.true(duplicate.error?.code === 'PUBLIC_KEY_CHANGED', 'Conflicting repeated peer IDs cannot bypass checks within a batch');
        alice.database.acknowledgeAborts();
        assert.strictEqual(await alice.engine.getPeerTrust(eve.id), undefined, 'Repeated-ID failure rolls the entire batch back');
    });

    QUnit.test('Remote group endpoints require separate decisions and retain immutable public versions', async function (assert) {
        const { alice, bob } = this;
        await exchangePublicKeys(alice, bob);
        const { publicKey } = await alice.engine.generateGroupKeys(1, 'g200');
        await bob.engine.addGroupKeys('g200', [{ version: 1, groupKey: { ...publicKey, verified: true }, verified: true }]);
        assert.strictEqual((await bob.engine.getPeerTrust('g200:1')).status, 'unverified', 'Imported group verification flags are ignored');
        await assert.rejects(bob.engine.encryptTextSimple(bob.id, 'g200:1', 'Group'), error => error.code === 'UNTRUSTED_PUBLIC_KEY', 'Remote group convenience use is blocked by default');
        await bob.engine.addGroupKeys('g200', [{ version: 1, groupKey: publicKey }],
            { decisions: [{ peerID: 'g200:1', expectedFingerprint: await jwkThumbprint(publicKey) }] });
        const packet = await bob.engine.encryptTextSimple(bob.id, 'g200:1', 'Confirmed group');
        assert.true(await alice.engine.decryptTextSimple(bob.id, 'g200:1', packet.cipherText, packet.iv) === 'Confirmed group', 'Explicit group confirmation enables the owner round trip');
        const changed = await settles(bob.engine.addGroupKeys('g200', [{ version: 1, groupKey: this.eve.publicKey }], { tofu: true }));
        assert.true(changed.error?.code === 'GROUP_CONFLICT', 'Existing group version immutability remains enforced');
        bob.database.acknowledgeAborts();
        assert.strictEqual((await bob.engine.getPeerTrust('g200:1')).fingerprint, await jwkThumbprint(publicKey), 'Rejected group change leaves its trust intact');
    });

    QUnit.test('Trust persists across reopen, stays namespace-local and is cleared atomically by panic', async function (assert) {
        const { alice, bob } = this;
        const expected = await jwkThumbprint(bob.publicKey);
        await alice.engine.addPublicKey(bob.id, bob.publicKey, { expectedFingerprint: expected });
        const isolated = new Be8(alice.id, alice.database.connection, { namespace: 'isolated' });
        await isolated.setup();
        await isolated.addPublicKey(bob.id, bob.publicKey);
        assert.strictEqual((await isolated.getPeerTrust(bob.id)).status, 'unverified', 'Confirmation does not leak to another namespace');
        await assert.rejects(isolated.encryptTextSimple(alice.id, bob.id, 'Other namespace'), error => error.code === 'UNTRUSTED_PUBLIC_KEY', 'The isolated namespace remains blocked');
        const wrongOwner = new Be8('104', alice.database.connection, { namespace: alice.id });
        const denied = await settles(wrongOwner.getPeerTrust(bob.id));
        assert.true(denied.error?.code === 'ACCOUNT_MISMATCH', 'Another account cannot read this namespace trust');
        alice.database.acknowledgeAborts();
        const database = await this.open(alice.database.name);
        const reopened = new Be8(alice.id, database.connection);
        await reopened.setup();
        assert.strictEqual((await reopened.getPeerTrust(bob.id)).fingerprint, expected, 'Reopening restores committed trust');
        assert.strictEqual((await reopened.getPeerTrust(bob.id)).status, 'confirmed', 'Reopening preserves the explicit decision');
        await reopened.panic();
        assert.strictEqual(await reopened.getPeerTrust(bob.id), undefined, 'Explicit panic clears trust with the selected namespace keys');
        assert.strictEqual((await isolated.getPeerTrust(bob.id)).status, 'unverified', 'Other namespace trust is retained');
    });

    QUnit.test('Schema upgrade and explicit trust migration never promote old unchecked records', async function (assert) {
        const database = await this.open(undefined, { upgrade(db) {
            // Reproduce the previous engine schema using actual native stores.
            db.deleteObjectStore(STORES.trust);
            db.createObjectStore('appSettings', { keyPath: 'id' });
        } });
        const owner = new Be8('104', database.connection);
        await owner.setup();
        const tx = database.transaction([STORES.publicKeys, STORES.groupKeys, 'appSettings'], 'readwrite');
        tx.objectStore(STORES.publicKeys).put({ namespace: '104', accID: this.bob.id, key: { ...this.bob.publicKey, verified: true }, verified: true });
        tx.objectStore(STORES.groupKeys).put({ namespace: '104', groupID: 'g200', version: 1, key: this.eve.publicKey, verified: true });
        tx.objectStore('appSettings').put({ id: 'unchanged', value: true });
        await database.whenIdle();
        const ownBefore = await owner.getMyPublicKey();
        database.close();
        const upgraded = await this.open(database.name, { version: 2, upgrade(db, tx) { upgradeBe8Schema(db, tx); } });
        const engine = new Be8('104', upgraded.connection);
        await engine.setup();
        assert.strictEqual(await engine.getPeerTrust(this.bob.id), undefined, 'Schema integration grants no old peer trust');
        await assert.rejects(engine.encryptTextSimple('104', this.bob.id, 'Old unchecked'), error => error.code === 'UNTRUSTED_PUBLIC_KEY', 'Absent old trust cannot authorize convenience use');
        const migration = await engine.migratePublicKeyTrust();
        assert.strictEqual(migration.migratedPeers, 2, 'Explicit migration creates namespace-local records for old identity and group peers');
        assert.strictEqual((await engine.getPeerTrust(this.bob.id)).status, 'unverified', 'Old verified fields are never treated as proof');
        assert.strictEqual((await engine.getPeerTrust('g200:1')).status, 'unverified', 'Old public group data also remains unverified');
        assert.strictEqual((await engine.migratePublicKeyTrust()).migratedPeers, 0, 'Trust migration is idempotent');
        assert.true((await engine.getMyPublicKey()).x === ownBefore.x, 'Trust migration preserves the local cryptographic identity');
        assert.true((await readRecord(upgraded, 'appSettings', 'unchanged')).value, 'Application data is retained');
        await engine.addPublicKey(this.bob.id, this.bob.publicKey, { tofu: true });
        assert.strictEqual((await engine.getPeerTrust(this.bob.id)).status, 'unverified', 'Old unchecked imports cannot become TOFU on later contact');
        await engine.addPublicKey(this.bob.id, this.bob.publicKey, { trust: 'confirmed' });
        await engine.migratePublicKeyTrust();
        assert.strictEqual((await engine.getPeerTrust(this.bob.id)).status, 'confirmed', 'Migration retains a subsequent real local confirmation');
    });
    QUnit.test('Native trust-store write errors roll back public keys and trust even after successful key writes', async function (assert) {
        const database = await this.open(undefined, { upgrade(db, tx) {
            tx.objectStore(STORES.trust).createIndex('testUniqueFingerprint', ['namespace', 'fingerprint'], { unique: true });
        } });
        const engine = new Be8('104', database.connection);
        await engine.setup();
        let publicWrites = 0;
        database.observe(tx => {
            if (tx.mode !== 'readwrite') return;
            tx.addEventListener('error', event => event.preventDefault());
            tx.addEventListener('success', event => {
                if (event.target.source?.name === STORES.publicKeys && Array.isArray(event.target.result)) publicWrites++;
            }, { capture: true });
        });
        const result = await settles(engine.addPublicKeys([
            { accID: '102', publicKey: this.bob.publicKey }, { accID: '103', publicKey: this.bob.publicKey },
        ], { decisions: [{ peerID: '102', trust: 'confirmed' }, { peerID: '103', trust: 'confirmed' }] }));
        database.observe(undefined);
        assert.true(result.error instanceof Error && result.error.name === 'ConstraintError', 'A real trust-index violation propagates as an Error');
        assert.strictEqual(publicWrites, 2, 'Both native public-key writes succeeded before the trust-store failure');
        assert.strictEqual(database.acknowledgeAborts(), 1, 'The error forced rollback despite prevented default');
        assert.deepEqual(await storedIDs(database, 'publicKeys'), ['104'], 'Every public mutation was rolled back');
        assert.strictEqual(await engine.getPeerTrust('102'), undefined, 'The earlier trust mutation was rolled back');
        assert.strictEqual(await engine.getPeerTrust('103'), undefined, 'The failed trust record is absent');
        await engine.addPublicKey('102', this.bob.publicKey, { trust: 'confirmed' });
        assert.strictEqual((await engine.getPeerTrust('102')).status, 'confirmed', 'A subsequent valid mutation completes normally');
    });

    QUnit.test('Aborted trust migration keeps old keys, leaves no partial authorization and can be explicitly retried', async function (assert) {
        const { alice, bob, eve } = this;
        const tx = alice.database.transaction(STORES.publicKeys, 'readwrite');
        tx.objectStore(STORES.publicKeys).put({ namespace: alice.id, accID: bob.id, key: bob.publicKey });
        tx.objectStore(STORES.publicKeys).put({ namespace: alice.id, accID: eve.id, key: eve.publicKey });
        await alice.database.whenIdle();
        let added = false;
        alice.database.observe(tx => {
            if (tx.mode !== 'readwrite' || !tx.objectStoreNames.contains(STORES.trust)) return;
            tx.addEventListener('success', event => {
                if (event.target.source?.name === STORES.trust && Array.isArray(event.target.result)) {
                    added = true; tx.abort();
                }
            }, { capture: true });
        });
        const result = await settles(alice.engine.migratePublicKeyTrust());
        alice.database.observe(undefined);
        assert.true(added && result.error instanceof Error, 'Native abort after trust-add success rejects migration');
        assert.strictEqual(alice.database.acknowledgeAborts(), 1, 'The migration transaction terminated');
        assert.deepEqual(await storedIDs(alice.database, 'publicKeys'), ['101', '102', '103'], 'All original public keys remain intact');
        assert.strictEqual(await alice.engine.getPeerTrust(bob.id), undefined, 'No partial trust record survived');
        assert.strictEqual(await alice.engine.getPeerTrust(eve.id), undefined, 'Later peer trust is also absent');
        assert.strictEqual((await alice.engine.migratePublicKeyTrust()).migratedPeers, 2, 'A fresh explicit migration commits both unchecked records');
        assert.strictEqual((await alice.engine.getPeerTrust(bob.id)).status, 'unverified', 'Retry creates no false confirmation');
    });

});
