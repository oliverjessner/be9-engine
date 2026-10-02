import Be9, { STORES, V2_LIMITS, encodeBase64url, decodeBase64url, jwkThumbprint } from '../lib/bundle.mjs';
import { derivationUsageID } from '../lib/usage.mjs';
import { participantHooks, exchangePublicKeys, packetMetadata } from './participants.mjs';
import { readRecord } from './database.mjs';
import { encryptLegacyFixture } from './legacy-fixture.mjs';

const equal = (left, right) => left.length === right.length && left.every((byte, index) => byte === right[index]);
const code = expected => error => error instanceof Error && error.code === expected;
const nativeKey = () => crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
const sample = length => Uint8Array.from({ length }, (_, index) => index % 256);

async function seedUsage(database, derivation, encryptions, blocks) {
    const derivationID = await derivationUsageID(derivation);
    const tx = database.transaction(STORES.keyUsage, 'readwrite');
    tx.objectStore(STORES.keyUsage).put({ derivationID, encryptions, blocks });
    await database.whenIdle();
    return derivationID;
}

QUnit.module('v2 / binary encoding, nonces and persisted usage', hooks => {
    participantHooks(hooks);

    QUnit.test('Binary codecs preserve 0x00/0xff, offset views and large arrays without variadic conversion', async function (assert) {
        for (const bytes of [new Uint8Array(), sample(256), sample(1024 * 1024 + 1)]) {
            const encoded = encodeBase64url(bytes);
            assert.true(/^[A-Za-z0-9_-]*$/.test(encoded), 'Only the unpadded base64url alphabet is emitted');
            assert.true(equal(decodeBase64url(encoded), bytes), 'Every byte, including zero and 255, round trips');
        }
        assert.strictEqual(encodeBase64url(new Uint8Array([251, 239, 255])), '--__', 'URL-safe alphabet replaces standard Base64 punctuation');
        const view = new DataView(new Uint8Array([9, 0, 255, 8]).buffer, 1, 2);
        assert.true(equal(decodeBase64url(encodeBase64url(view)), new Uint8Array([0, 255])), 'View offsets and byte lengths are respected');
        const key = await nativeKey();
        const packet = await this.alice.engine.encryptBytes(key, view);
        assert.strictEqual(decodeBase64url(packet.iv).length, 12, 'New IV has exactly 96 bits');
        assert.strictEqual(packet.iv.length, 16, 'The IV wire value has exactly 16 unpadded characters');
        assert.strictEqual(decodeBase64url(packet.cipherText).length, 18, 'Ciphertext includes an explicit 16-byte GCM tag');
        assert.true(equal(await this.alice.engine.decryptBytes(key, packet.cipherText, packet.iv), new Uint8Array([0, 255])), 'Binary payload is never decoded as text');
        assert.true(equal(await this.alice.engine.decryptBytes(key, decodeBase64url(packet.cipherText), decodeBase64url(packet.iv)),
            new Uint8Array([0, 255])), 'Binary ciphertext and IV inputs also work');
        const empty = await this.alice.engine.encryptBytes(key, new Uint8Array());
        assert.strictEqual(decodeBase64url(empty.cipherText).length, 16, 'An empty payload still has the full 128-bit tag');
        assert.strictEqual((await this.alice.engine.decryptBytes(key, empty.cipherText, empty.iv)).length, 0, 'Empty binary payload round trips');
    });

    QUnit.test('A deterministic native fixture with binary IV bytes never needs UTF-8 conversion', async function (assert) {
        const key = await nativeKey();
        // Only this fixture supplies an IV; no production random-source override.
        const iv = new Uint8Array([0, 255, 128, 192, 1, 2, 3, 4, 5, 6, 254, 0]);
        const bytes = new Uint8Array([0, 255, 254, 128]);
        const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, bytes);
        assert.true(equal(await this.alice.engine.decryptBytes(key, encodeBase64url(cipher), encodeBase64url(iv)), bytes), 'All binary IV and payload bytes remain exact');
        await assert.rejects(this.alice.engine.decryptText(key, encodeBase64url(cipher), encodeBase64url(iv)), code('INVALID_TEXT'),
            'Authenticated binary plaintext is not silently replaced with lossy text');
    });

    QUnit.test('Unicode, BOM and large image text interoperate between independent peers', async function (assert) {
        const { alice, bob } = this;
        await exchangePublicKeys(alice, bob);
        for (const text of ['', '\u0000\uffff👩🏽‍💻日本語', '\ufeffBOM stays text', 'é e\u0301']) {
            const packet = await alice.engine.encryptTextSimple(alice.id, bob.id, text);
            assert.true(await bob.engine.decryptTextSimple(alice.id, bob.id, packet) === text,
                'Unicode text round trips without normalization or BOM loss');
        }
        const raw = sample(2 * 1024 * 1024 + 1);
        const unpadded = encodeBase64url(raw).replace(/-/g, '+').replace(/_/g, '/');
        const image = 'data:image/png;base64,' + unpadded + '='.repeat((4 - unpadded.length % 4) % 4);
        const packet = await alice.engine.encryptImageSimple(alice.id, bob.id, image);
        assert.true(await bob.engine.decryptImageSimple(alice.id, bob.id, packet) === image,
            'A multi-megabyte image preserves the existing string API without argument/stack overflow');
        assert.strictEqual(packet.header.purpose, 'attachment', 'Large image remains in the attachment domain');
    });

    QUnit.test('Malformed and noncanonical Base64url is rejected before AES or storage', async function (assert) {
        const key = await nativeKey();
        const iv = encodeBase64url(new Uint8Array(12));
        const context = await this.alice.createContext(this.bob.publicKey);
        const header = { ...context.derivation, iv, sequence: '1', group: null };
        let transactions = 0;
        this.bob.database.observe(() => transactions++);
        for (const encoded of ['A', 'AA=', 'AA==', 'AB', 'AAB', 'A+B/', 'a b', 'a\nb', '\u00ff', '====', '_w=', 'data:']) {
            assert.throws(() => decodeBase64url(encoded), code('INVALID_ENCODING'), 'Invalid alphabet, padding, length or unused bits reject');
            await assert.rejects(this.bob.engine.decryptTextSimple('101', '102', { header, ciphertext: encoded }), code('INVALID_ENCODING'),
                'Malformed ciphertext rejects before ECDH metadata or database reads');
        }
        assert.strictEqual(transactions, 0, 'No expensive convenience key lookup started');
        this.bob.database.observe(undefined);
        assert.true(equal(decodeBase64url('_w'), new Uint8Array([255])), 'Canonical last-byte encoding remains accepted');
        await assert.rejects(this.alice.engine.decryptBytes(key, '', iv), code('INVALID_CIPHERTEXT'), 'Empty ciphertext cannot hold a tag');
        await assert.rejects(this.alice.engine.decryptBytes(key, encodeBase64url(new Uint8Array(15)), iv), code('INVALID_CIPHERTEXT'), 'A partial tag is refused');
    });

    QUnit.test('IV size is exactly 12 bytes and old UUIDs are refused on v2 paths', async function (assert) {
        const key = await nativeKey();
        const cipher = encodeBase64url(new Uint8Array(16));
        for (const iv of [undefined, null, '', new Uint8Array(0), new Uint8Array(11), new Uint8Array(13),
            encodeBase64url(new Uint8Array(11)), encodeBase64url(new Uint8Array(13)), crypto.randomUUID(), 'A'.repeat(100000)]) {
            await assert.rejects(this.alice.engine.decryptBytes(key, cipher, iv), code('INVALID_IV'), 'Wrong IV representation or size rejects before GCM');
        }
    });

    QUnit.test('Oversized and invalid inputs reject before native key derivation and reservation', async function (assert) {
        const context = await this.alice.createContext(this.bob.publicKey);
        const header = { ...context.derivation, iv: encodeBase64url(new Uint8Array(12)), sequence: '1', group: null };
        let transactions = 0;
        this.alice.database.observe(() => transactions++);
        for (const text of ['x'.repeat(V2_LIMITS.plaintextBytes + 1), '€'.repeat(Math.floor(V2_LIMITS.plaintextBytes / 3) + 1)]) {
            await assert.rejects(this.alice.engine.encryptTextSimple('101', '102', text), code('INPUT_TOO_LARGE'), 'UTF-8 byte size is bounded before encoding/derivation');
        }
        await assert.rejects(this.alice.engine.encryptImageSimple('101', '102', '\ud800'), code('INVALID_TEXT'), 'Lone surrogates are not silently replaced');
        const oversized = 'A'.repeat(Math.ceil((V2_LIMITS.plaintextBytes + 16) * 8 / 6) + 1);
        await assert.rejects(this.alice.engine.decryptTextSimple('102', '101', { header, ciphertext: oversized }),
            code('INPUT_TOO_LARGE'), 'Wire size rejects before Base64 decoding or KDF');
        for (const options of [{ iv: new Uint8Array(12) }, { random: () => new Uint8Array(12) }, { keyId: 'new-alias' }]) {
            await assert.rejects(this.alice.engine.encryptTextSimple('101', '102', 'small', options), code('INVALID_OPTIONS'), 'Convenience encryption cannot supply an IV, random source or key alias');
        }
        assert.strictEqual(transactions, 0, 'No key read or write transaction was opened');
        this.alice.database.observe(undefined);
        const key = await nativeKey();
        await assert.rejects(this.alice.engine.encryptBytes(key, new Uint8Array(V2_LIMITS.plaintextBytes + 1)), code('INPUT_TOO_LARGE'), 'Binary plaintext limit is the same');
        await assert.rejects(this.alice.engine.decryptBytes(key, new Uint8Array(V2_LIMITS.plaintextBytes + 17), new Uint8Array(12)), code('INPUT_TOO_LARGE'), 'Binary ciphertext limit includes precisely one tag');
    });

    QUnit.test('Caller-owned plaintext and ciphertext are snapshotted before asynchronous work', async function (assert) {
        const { alice, bob } = this;
        const context = await alice.createContext(bob.publicKey);
        const recipient = await bob.derive(alice.publicKey, context.derivation);
        const bytes = new Uint8Array([0, 255, 1]);
        const pending = alice.engine.encryptBytes(context.key, bytes);
        bytes.fill(9);
        const packet = await pending;
        const cipher = decodeBase64url(packet.cipherText);
        const iv = decodeBase64url(packet.iv);
        const reading = bob.engine.decryptBytes(recipient, cipher, iv);
        cipher.fill(0); iv.fill(0);
        assert.true(equal(await reading, new Uint8Array([0, 255, 1])), 'Later caller mutations do not alter the native operation');
        await assert.rejects(bob.engine.encryptBytes(recipient, new Uint8Array([1])), code('INVALID_DERIVATION_CONTEXT'), 'A recipient creates a reverse directional context for engine encryption');
    });

    QUnit.test('Reservations commit before success; re-deriving and reloading the same key cannot reset count', async function (assert) {
        const { alice, bob } = this;
        const context = await alice.createContext(bob.publicKey);
        const id = await derivationUsageID(context.derivation);
        await alice.engine.encryptText(context.key, 'one');
        assert.strictEqual(alice.database.pendingWrites(), 0, 'The budget reservation is committed before ciphertext is returned');
        const first = await readRecord(alice.database, 'keyUsage', id);
        assert.true(first.encryptions === 1 && first.blocks === 2, 'One encryption and GHASH/length blocks were reserved');
        const same = await alice.derive(bob.publicKey, structuredClone(context.derivation));
        assert.true(same !== context.key, 'A fresh native CryptoKey object still denotes the same derivation');
        await alice.engine.encryptImage(same, 'two');
        assert.strictEqual((await readRecord(alice.database, 'keyUsage', id)).encryptions, 2, 'Text/image share the actual-key budget');
        alice.database.close();
        const database = await this.open(alice.database.name);
        const reloaded = new Be9(alice.id, database.connection);
        await reloaded.setup();
        const local = await reloaded.generatePrivAndPubKey();
        const key = await reloaded.getDerivedKey(bob.publicKey, local.keyReference, context.derivation);
        await reloaded.encryptText(key, 'three');
        assert.strictEqual((await readRecord(database, 'keyUsage', id)).encryptions, 3, 'Native IndexedDB persistence survives restart');
        await assert.rejects(reloaded.getDerivedKey(bob.publicKey, local.keyReference, { ...context.derivation, keyId: 'alias' }),
            code('INVALID_DERIVATION_CONTEXT'), 'An arbitrary key alias cannot change validated KDF identity');
    });

    QUnit.test('Concurrent connections compete atomically for the last permitted encryption', async function (assert) {
        const { alice, bob } = this;
        const context = await alice.createContext(bob.publicKey);
        const id = await seedUsage(alice.database, context.derivation, V2_LIMITS.encryptions - 1, V2_LIMITS.encryptions - 1);
        const database = await this.open(alice.database.name);
        const other = new Be9(alice.id, database.connection);
        await other.setup();
        const key = await other.getDerivedKey(bob.publicKey, (await other.generatePrivAndPubKey()).keyReference, context.derivation);
        const results = await Promise.allSettled(Array.from({ length: 8 }, (_, index) => index % 2
            ? other.encryptText(key, '') : alice.engine.encryptText(context.key, '')));
        assert.strictEqual(results.filter(result => result.status === 'fulfilled').length, 1, 'Exactly one operation can commit the final reservation');
        assert.true(results.filter(result => result.status === 'rejected').every(result => result.reason.code === 'KEY_USAGE_EXHAUSTED'), 'Every excess invocation settles with the specific exhaustion error');
        alice.database.acknowledgeAborts(); database.acknowledgeAborts();
        const row = await readRecord(database, 'keyUsage', id);
        assert.true(row.encryptions === V2_LIMITS.encryptions && row.blocks === V2_LIMITS.encryptions, 'No lost update or count beyond the bound');
    });

    QUnit.test('Convenience calls reserve their actual key, while invalid inputs leave counters untouched', async function (assert) {
        const { alice, bob } = this;
        await exchangePublicKeys(alice, bob);
        const packet = await alice.engine.encryptTextSimple(alice.id, bob.id, 'budgeted');
        const id = await derivationUsageID(packetMetadata(packet));
        assert.strictEqual((await readRecord(alice.database, 'keyUsage', id)).encryptions, 1, 'The secure convenience path commits a real per-key reservation');
        assert.true(await bob.engine.decryptTextSimple(alice.id, bob.id, packet) === 'budgeted', 'Independent recipient still interoperates');
        assert.strictEqual(await readRecord(bob.database, 'keyUsage', id), undefined, 'Reading a ciphertext does not reserve encryption capacity');
        const key = await alice.derive(bob.publicKey, packetMetadata(packet));
        await assert.rejects(alice.engine.encryptText(key, '\ud800'), code('INVALID_TEXT'), 'Bad text is refused before a reservation');
        assert.strictEqual((await readRecord(alice.database, 'keyUsage', id)).encryptions, 1, 'Validation errors do not consume capacity');
    });

    QUnit.test('A native counter write error rolls back and cannot produce a ciphertext', async function (assert) {
        const { alice, bob } = this;
        alice.database.close();
        const database = await this.open(alice.database.name, { version: 2, upgrade(db, tx) {
            // Test-only native constraint, not a synthetic storage failure.
            tx.objectStore(STORES.keyUsage).createIndex('testUniqueCount', 'encryptions', { unique: true });
        } });
        const engine = new Be9(alice.id, database.connection);
        await engine.setup();
        const local = await engine.generatePrivAndPubKey();
        const options = { sender: alice.id, receiver: bob.id, purpose: 'data', contextID: 'write error' };
        const first = await engine.createDerivationContext(bob.publicKey, local.keyReference, options);
        const second = await engine.createDerivationContext(bob.publicKey, local.keyReference, options);
        await engine.encryptText(first.key, 'committed');
        await assert.rejects(engine.encryptText(second.key, 'must fail'), error => error.code === 'PERSISTENCE_ERROR' && error.name === 'ConstraintError',
            'Native IndexedDB write failure is propagated instead of encryption success');
        database.acknowledgeAborts();
        assert.strictEqual(await readRecord(database, 'keyUsage', await derivationUsageID(second.derivation)), undefined, 'Failed reservation is not partially retained');
        assert.strictEqual((await readRecord(database, 'keyUsage', await derivationUsageID(first.derivation))).encryptions, 1, 'The previously committed counter is unchanged');
    });

    QUnit.test('Aggregate block limit, malformed state and reservation abort fail closed', async function (assert) {
        const { alice, bob } = this;
        const context = await alice.createContext(bob.publicKey);
        const id = await seedUsage(alice.database, context.derivation, 16, V2_LIMITS.blocks - 2);
        await alice.engine.encryptText(context.key, 'last block');
        await assert.rejects(alice.engine.encryptText(context.key, ''), code('KEY_USAGE_EXHAUSTED'), 'Aggregate GHASH budget is independent of invocation count');
        alice.database.acknowledgeAborts();
        assert.strictEqual((await readRecord(alice.database, 'keyUsage', id)).blocks, V2_LIMITS.blocks, 'The block limit is not exceeded');
        await seedUsage(alice.database, context.derivation, -1, 0);
        await assert.rejects(alice.engine.encryptText(context.key, ''), code('INVALID_USAGE_STATE'), 'Invalid persisted counters cannot silently reset');
        alice.database.acknowledgeAborts();
        await seedUsage(alice.database, context.derivation, 0, 0);
        let written = false;
        alice.database.observe(tx => {
            if (tx.mode === 'readwrite' && tx.objectStoreNames.contains(STORES.keyUsage)) {
                tx.addEventListener('success', event => {
                    if (event.target.source?.name === STORES.keyUsage && event.target.result === id) { written = true; tx.abort(); }
                }, { capture: true });
            }
        });
        await assert.rejects(alice.engine.encryptText(context.key, 'aborted'), code('PERSISTENCE_ERROR'), 'A successful individual write is not authorization to encrypt before commit');
        alice.database.observe(undefined);
        assert.true(written, 'The test aborted a real transaction after a successful counter write');
        alice.database.acknowledgeAborts();
        assert.strictEqual((await readRecord(alice.database, 'keyUsage', id)).encryptions, 0, 'The aborted write was rolled back and no packet was returned');
        await alice.engine.encryptText(context.key, 'explicit retry');
        assert.strictEqual((await readRecord(alice.database, 'keyUsage', id)).encryptions, 1, 'A fresh operation succeeds after rollback');
    });

    QUnit.test('Namespace aliases and panic cannot reset the budget for the same actual local key', async function (assert) {
        const { alice, bob } = this;
        const context = await alice.createContext(bob.publicKey);
        const id = await seedUsage(alice.database, context.derivation, V2_LIMITS.encryptions, V2_LIMITS.encryptions);
        // Same local owner, same database; no private key goes to another participant.
        const own = await readRecord(alice.database, 'privateKeys', alice.id);
        const tx = alice.database.transaction([STORES.scopes, STORES.publicKeys, STORES.privateKeys], 'readwrite');
        tx.objectStore(STORES.scopes).put({ namespace: 'alias', accID: alice.id });
        tx.objectStore(STORES.publicKeys).put({ namespace: 'alias', accID: alice.id, key: alice.publicKey });
        tx.objectStore(STORES.privateKeys).put({ namespace: 'alias', accID: alice.id, key: own, publicKey: alice.publicKey });
        await alice.database.whenIdle();
        const alias = new Be9(alice.id, alice.database.connection, { namespace: 'alias' });
        await alias.setup();
        const key = await alias.getDerivedKey(bob.publicKey, (await alias.generatePrivAndPubKey()).keyReference, context.derivation);
        await assert.rejects(alias.encryptText(key, ''), code('KEY_USAGE_EXHAUSTED'), 'Storage namespace is not part of the budget identity');
        alice.database.acknowledgeAborts();
        await alice.engine.panic();
        assert.strictEqual((await readRecord(alice.database, 'keyUsage', id)).encryptions, V2_LIMITS.encryptions, 'Clearing identities does not refund security state');
    });

    QUnit.test('The application integrates the new store explicitly without replacing its identity', async function (assert) {
        const database = await this.open(undefined, { upgrade(db) { db.deleteObjectStore(STORES.keyUsage); } });
        const engine = new Be9('104', database.connection);
        await engine.setup();
        const local = await engine.generatePrivAndPubKey();
        const context = await engine.createDerivationContext(this.bob.publicKey, local.keyReference,
            { contextID: 'schema upgrade', sender: '104', receiver: this.bob.id, purpose: 'data' });
        await assert.rejects(engine.encryptText(context.key, 'requires schema'), code('SCHEMA_UPGRADE_REQUIRED'), 'No counter fallback or implicit database upgrade');
        database.close();
        const upgraded = await this.open(database.name, { version: 2 });
        const reloaded = new Be9('104', upgraded.connection);
        await reloaded.setup();
        assert.strictEqual(await jwkThumbprint(await reloaded.getMyPublicKey()), await jwkThumbprint(local.publicKey), 'The application upgrade preserves cryptographic identity');
        const key = await reloaded.getDerivedKey(this.bob.publicKey, (await reloaded.generatePrivAndPubKey()).keyReference, context.derivation);
        const packet = await reloaded.encryptText(key, 'upgraded');
        assert.true(await reloaded.decryptText(key, packet.cipherText, packet.iv) === 'upgraded', 'Encryption succeeds after the application integrates the counter store');
    });

    QUnit.test('UUID/UTF-8 and padded Base64 remain explicit legacy readers only', async function (assert) {
        const key = await nativeKey();
        const legacy = await encryptLegacyFixture(key, 'Legacy Unicode 🐈');
        await assert.rejects(this.alice.engine.decryptText(key, legacy.cipherText, legacy.iv), code('INVALID_IV'), 'The new reader never automatically identifies the old wire format');
        assert.true(await this.alice.engine.decryptTextLegacy(key, legacy.cipherText, legacy.iv) === 'Legacy Unicode 🐈', 'Explicit legacy formatting remains readable');
        assert.true(await this.alice.engine.decryptImageLegacy(key, legacy.cipherText, legacy.iv) === 'Legacy Unicode 🐈', 'Image legacy uses the same explicit decoder');
        const modern = await this.alice.engine.encryptText(key, 'new');
        await assert.rejects(this.alice.engine.decryptTextLegacy(key, modern.cipherText, modern.iv), code('INVALID_IV'), 'Legacy does not auto-detect v2 either');
    });
});
