# be8-engine
Be8 is a reusable JavaScript ESM cryptography engine using native WebCrypto
ECDH with P-384 and AES-GCM. Applications supply data, public keys, trust
decisions, context, and an application-owned IndexedDB connection.

## usage

The constructor takes a canonical nonnegative decimal account ID, a ready native
`IDBDatabase` (or an existing request/adapter whose `result` is that database),
and optional `{ namespace }`. The namespace defaults to the account ID. IDs such
as empty strings, whitespace, negative numbers, `01`, and exponent notation are
rejected. Namespace strings must be nonempty, trimmed, and free of control
characters. The engine does not open, close, replace, or upgrade the database.

The application integrates the engine schema into its own upgrade handler and
chooses its database name and version:

```javascript
import Be8, { upgradeBe8Schema } from 'be8-engine';

const request = indexedDB.open('my-application', 2); // Application-owned version.
let upgradeError;
request.onupgradeneeded = () => {
    try {
        upgradeBe8Schema(request.result, request.transaction);
        // Integrate other application stores here.
    } catch (error) {
        upgradeError = error; // The helper has already aborted its failed upgrade.
    }
};
const db = await new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(upgradeError || new Error('Application database open failed'));
    request.onblocked = () => reject(new Error('Application database upgrade blocked'));
});
db.addEventListener('versionchange', () => db.close()); // Application lifecycle.

const be8 = new Be8('1', db, { namespace: '1' });
await be8.setup();
const hasKeys = await be8.hasGeneratedKeys();
```

`upgradeBe8Schema(db, transaction)` is synchronous and requires the application's
native versionchange transaction. Repeated calls are safe for a matching schema.
Incompatible engine store/index definitions abort the upgrade; no store is deleted
or replaced. The engine uses these dedicated stores alongside application stores:

| Store | Primary key | Contents |
| --- | --- | --- |
| `be8.scopes` | `namespace` | Permanent account/namespace binding |
| `be8.publicKeys` | `[namespace, accID]` | Public JWK in a separate `key` field |
| `be8.privateKeys` | `[namespace, accID]` | Non-extractable private ECDH `CryptoKey` in `key`, public JWK in `publicKey` |
| `be8.groupKeys` | `[namespace, groupID, version]` | Public JWK in `key`, optional non-extractable ECDH `CryptoKey` in `privateKey` |

The three key stores have a nonunique `namespace` index. A namespace is bound to
one account on its first successful mutation. A different account cannot read,
write, initialize, or clear it. The same account can use multiple explicitly
chosen namespaces, each with its own identity. The application must treat these
stores as engine-owned records; arbitrary direct edits are not a synchronization
or authorization API.

Public/private identity writes share one native transaction. Group private CryptoKeys
are persisted together with their public JWK in one record using native Structured Clone. Cryptographic
generation/import happens before the write transaction. All mutation promises
resolve only after native transaction completion; request success alone cannot
report a commit. Request errors force rollback even if another event listener
prevents the default abort. Persistence and storage validation failures are
`Error` objects with generic messages and stable `code` values; persistence
failures use `PERSISTENCE_ERROR` and a sanitized
native category in `name`. CryptoKey clone failures use
`CRYPTOKEY_STORAGE_UNSUPPORTED` with an explanation of the required browser
capability. No private-JWK fallback is attempted. Raw request errors, key values, and plaintexts are not
logged or attached as error causes.

Persistent reads use `readonly`. There are no per-instance key caches: simplified
encryption/decryption reads both endpoint keys in one committed database snapshot.
Independent instances/connections therefore see committed mutations on their next
operation. Concurrent overlapping write transactions are ordered by IndexedDB.
Commit completion is not a guarantee against every hardware or power-loss failure;
see [native transaction semantics](https://developer.mozilla.org/en-US/docs/Web/API/IDBTransaction).

`setup()` coalesces parallel calls on one instance. Independent instances recheck
the identity under the same write lock, retaining whichever complete pair was
committed first. Repeated setup/generation retains that pair. Missing one half,
inconsistent coordinates, and database failures reject instead of replacing the
identity. There is no implicit identity rotation.
`setup()` accepts no migration options. Migration is a separate explicit
operation; setup never silently imports old private JWKs.

### Non-extractable local keys and migration

New identity and local group private keys are P-384 ECDH `CryptoKey` objects with
`extractable: false` and only `['deriveKey']`. Public keys remain exportable JWKs.
Derived AES-GCM keys also have `extractable: false`, with only
`['encrypt', 'decrypt']`. No normal engine operation exports private keys.
The required browser capabilities are native WebCrypto, IndexedDB CryptoKey
Structured Clone, and `structuredClone()` preserving a non-extractable CryptoKey.
Missing clone support rejects with `CRYPTOKEY_STORAGE_UNSUPPORTED`; it does not
store JWKs instead. See [WebCrypto key generation and serialization](https://www.w3.org/TR/2017/REC-WebCryptoAPI-20170126/).

Existing private JWKs require an explicit application migration decision:

```javascript
// Convert this namespace's existing identity and private group JWK records.
// Call before setup when setup reports PRIVATE_KEY_MIGRATION_REQUIRED.
const { migratedIdentity, migratedGroups } = await be8.migratePrivateKeys();
await be8.setup();
```

For an old unscoped `publicKeys`/`privateKeys` identity, default setup reports
`LEGACY_IDENTITY`. Integrate the engine schema through the application's upgrade
handler first, then explicitly adopt that account's existing identity:

```javascript
await be8.migratePrivateKeys({
    legacyIdentity: true,
    // Optional, explicit application-owned selection of old local private groups.
    // Old group ownership cannot be inferred by the engine.
    // Keep the original IndexedDB version key type (number or canonical string).
    legacyGroups: [{ groupID: 'g10300', version: '1' }],
});
await be8.setup();
```

Migration validates the existing public/private pair, imports the private JWK
non-extractably, and verifies that its scalar matches the exact public point.
A temporary non-extractable ECDSA signing import is used only for that validation;
it is never stored or returned and does not change the encryption protocol.
All crypto work finishes before the write transaction. The engine rechecks the
original records under the write lock, replaces all selected records atomically,
and resolves only after commit. Concurrent changes reject with
`MIGRATION_CONFLICT`; retry requires a fresh explicit call. Validation errors,
storage errors, or transaction aborts retain every original. Missing or incomplete
identity data rejects; migration never generates replacement keys.

Successful migration replaces scoped private JWKs in place. For the selected old
unscoped identity, both original public/private records are deleted in the same
transaction that stores the new identity. Selected old private group records are
also deleted in that commit. There is no retained plaintext backup or new private
export API. Unselected old groups, other accounts, application stores, and existing
ciphertexts are untouched. The application must explicitly choose each old local
private group it owns; the engine does not migrate unrelated data or infer trust
for old peer public keys. Old public group records can still be imported through
`addGroupKeys()`.

This operation preserves public fingerprints and cryptographic identity. It does
not change the KDF, nonce, cipher, or envelope profile, and it never runs after
ciphertext authentication failure. Existing browser/application backups outside
these selected records are not erased by this migration.

**Malicious JavaScript in the same execution context can still misuse these keys**,
for example by reading CryptoKeys from IndexedDB or calling engine encryption and
decryption methods. Non-extractable means WebCrypto denies key export; it does not
mean XSS-safe, hardware-protected, or inaccessible to browser/profile owners.
It also does not guarantee forensic erasure of prior JWK storage.

### Caller changes

- `generatePrivAndPubKey()` and `generateGroupKeys(version, groupID)` now return
  `{ publicKey, keyReference }` after commit, replacing the old private-JWK tuple.
  Generation remains idempotent. Only `publicKey` may be exchanged with peers.
- `keyReference` is an opaque frozen object bound to this engine instance and the
  committed identity/group public coordinates. It contains no key material, cannot
  be serialized or cloned into a usable reference, and becomes invalid if the
  selected identity is cleared/replaced. After reopening, call generation again
  to obtain a fresh reference to the same committed key.
- `getDerivedKey(publicJWK, keyReference)` derives a non-extractable AES key.
  It also accepts a native non-extractable P-384 ECDH private CryptoKey with exactly
  `['deriveKey']` for local caller-owned keys. Private JWKs and extractable private
  CryptoKeys are rejected; there is no implicit JWK import path.
- `getMyPublicKey()`, `getCachedKeys()`, and `getCachedGroupKeys()` expose only
  public JWKs and public metadata. Group getters project the public half of old
  records as well; they never return a private `d` or stored private CryptoKey.
- `addPublicKeys()` and `addGroupKeys()` accept only public JWKs, snapshot key
  fields, and cannot let embedded metadata override explicit storage IDs.
  Reimporting the public half of a modern local group retains its private key.
  Existing private-JWK groups must be migrated before mutation or private use.
- `setup({ legacyIdentity: true })` and the named/static `readLegacyIdentity()`
  private-JWK export are removed. Use `migratePrivateKeys()` explicitly, then
  `setup()`. Public async APIs and the simplified text/image call signatures
  remain available. `hasGeneratedKeys()`/`hasKey()` are promises; await them.
- Group IDs match `g[A-Za-z0-9_-]+`; versions are positive safe integers, with
  canonical decimal strings accepted and normalized for new records. A group
  version cannot be replaced with different public coordinates.
- `panic()` still explicitly clears only the current namespace's key records
  atomically, retaining its account binding, application stores, other namespaces,
  and unselected legacy records. It never deletes the application database.
- Named ESM/static integration exports are `upgradeBe8Schema` and `STORES`.
  The IIFE remains a callable `be8` constructor with the same static helpers.

## hasGeneratedKeys()

Checks the committed identity pair in this namespace. Returns a Promise<boolean>.

```javascript
await be8.hasGeneratedKeys();
```

## getAccID
Return the accID.

```javascript
be8.getAccID();
```

## async addPublicKeys(publicKeys = [])
Stores a caller-selected batch of peer public keys atomically in the current namespace.

```javascript
const publicKeys = [{ accID: '2', publicKey: bobPublicJWK }];
await be8.addPublicKeys(publicKeys);
```

## async addPublicKey(accID, key)
Stores one peer public key and resolves only after commit.

```javascript
await be8.addPublicKey('2', bobPublicJWK);
```

## async addGroupKeys(groupID, keys)
Group keys are stored separately in the current namespace.

```javascript
await be8.addGroupKeys('g10300', [{ version: 1, groupKey: publicGroupJWK }]);
```

## async generatePrivAndPubKey()
Returns the existing or newly committed public JWK and an opaque local key reference. Existing identities are retained.

```javascript
const { publicKey, keyReference } = await be8.generatePrivAndPubKey();
```

## async generateGroupKeys(version, groupID)
Generates or restores a local group identity in the current namespace after commit.

```javascript
const { publicKey, keyReference } = await be8.generateGroupKeys(1, 'g10300');
```

## async getDerivedKey(publicKey, keyReference)
Derives a non-extractable AES-GCM key from a peer public JWK and a local key reference.

```javascript
const { keyReference } = await be8.generatePrivAndPubKey();
const derivedKey = await be8.getDerivedKey(bobPublicJWK, keyReference);
```

## async encryptText(derivedKey, text = '')
After creating a [derivedKey](#async-getderivedkeypublickey-keyreference) we can start to encrypt text messages. encryptText returns a cipherText and a iv (Initialization vector).

```javascript
const text = 'Hello World';
const derivedKey = await be8.getDerivedKey(publicKey, keyReference);
const { cipherText, iv } = await be8.encryptText(derivedKey, text);
```

## async decryptText(derivedKey, cipherText, iv)
With the help of the key, the cipherText and an iv, we can decrypt messages.

```javascript
const cipherText = 'ASDASD9324/&§$jn';
const iv = '213210931249713409';
const derivedKey = await be8.getDerivedKey(publicKey, keyReference);
const text = await be8.decryptText(derivedKey, cipherText, iv);
```

## encryptTextSimple(accIDSender, accIDReceiver, text)
encryptTextSimple is a compound function of [encryptText](#async-encrypttextderivedkey-text) and [getDerivedKey](#async-getderivedkeypublickey-keyreference). It uses the ids instead of keys.
The derivedKey is generated inside the function.

```javascript
const accIDSender = be8.getAccID();
const accIDReceiver = '2';
const text = 'Hello World';
const cipherText = await be8.encryptTextSimple(accIDSender, accIDReceiver, text);
```

## async decryptTextSimple(accIDSender, accIDReceiver, cipherText, iv)
decryptTextSimple is a compound function of [decryptText](#async-decrypttextderivedkey-text) and [getDerivedKey](#async-getderivedkeypublickey-keyreference). It uses the ids instead of keys.
The derivedKey is generated inside the function.

```javascript
const accIDSender = be8.getAccID();
const accIDReceiver = '2';
const cipherText = 'sadadwWE=)AWLKASDS';
const iv = '2139484765456789';
const text = await bobEngine.decryptTextSimple(accIDSender, accIDReceiver, cipherText, iv);
```

## async encryptImage(derivedKey, base64Image)
Accepts the derivedKey and an image encoded as base64 so it can creates a "cipherImage" and
an iv.

```javascript
const { cipherImage, iv } = await be8.encryptImage(derivedKey, base64Image);
```

## async decryptImage(derivedKey, cipherImage, iv)
Uses the derivedKey, the cipherImage and the iv to decrypt a base64Image.

```javascript
const base64Image = await be8.decryptImage(derivedKey, cipherImage, iv);
```

## async encryptImageSimple (accIDSender, accIDReceiver, base64Image)

```javascript
const base64Image = await be8.encryptImageSimple(accIDSender, accIDReceiver, base64Image);
```

## async decryptImageSimple (accIDSender, accIDReceiver, cipherImage, iv)


```javascript
const base64Image = await be8.decryptImageSimple(accIDSender, accIDReceiver, cipherImage, iv);
```

## Scripts
### building
Rollup creates two versions one is a esm6 version and a minified iife one.
Both can be found in /dist.

```bash
npm run build
```

### Testing

The automated QUnit suite runs the source modules in headless Chromium with
native WebCrypto and IndexedDB. It requires Node.js 20 or newer. Install the
development dependencies and the Playwright browser once:

```bash
npm ci
npx playwright install chromium
```

On Linux CI hosts, use `npx playwright install --with-deps chromium` when browser
system libraries are missing. Playwright is a development dependency only.
See the [Playwright library documentation](https://playwright.dev/docs/library).

Run the full suite:

```bash
npm test
```

Exit codes are `0` for a complete passing suite, `1` for failed assertions, and
`2` for browser, resource, capability, timeout, or infrastructure errors. Output
contains test names and assertion counts; assertion values, browser exceptions,
console data, and stacks are not copied into the runner output.

For the interactive QUnit page, run `npm run test:manual` and open
http://127.0.0.1:3000/. QUnit assets are served locally, with no CDN dependency.
The loopback server only serves test assets; participants exchange public keys,
public metadata, and encrypted packets directly in test code, without networking.

Each test creates separate, uniquely named databases for Alice, Bob, and Eve.
Each participant retains its own private key. Integration tests derive a key
independently at each endpoint or use the simplified API on the actual recipient.
Private CryptoKeys, local references, legacy private JWK fixtures, and derived AES
keys are never exchanged between participants.
Readiness and cleanup use native IndexedDB open, request, complete, and abort
events, rather than fixed delays. Only the test-created databases are deleted.

`test/aes.mjs` contains separate single-instance AES unit tests. Group tests
exercise pairwise ECDH with Alice's local private group key, Bob's own private
identity key, and the corresponding exchanged public keys. They do not claim
broadcast encryption, membership enforcement, invitation handling, or protection
based on group membership. Different versions must authenticate independently;
old installed versions remain available.

#### Validation and remaining limits

The revised persistence suite extends the independent-participant tests with
native transaction aborts after successful requests, real unique-index write
errors, prevented-default error events, closed connections, pending-request
abort settlement, synchronous scheduling errors, parallel setup and mutations,
restart, namespace ownership races, schema upgrade rollback, and explicit legacy
identity migration. `test/key-protection.mjs` additionally verifies native private
and AES export refusal, records without `d`, opaque references, reload
interoperability, fingerprint preservation, old ciphertext readability, scoped
and selected unscoped group migration, abort after writes/deletions, mismatched
scalars, missing clone capability, native DataCloneError rollback, and concurrent
migration conflict handling. The previous commit contract assertions remain strict and now pass.
Timeouts in the runner and failure tests are failure deadlines, not readiness
waits. Test output excludes assertion data and raw browser errors.

The suite exercises native Chromium WebCrypto/IndexedDB. Other browsers,
hardware failures, and storage exhaustion beyond native constraint/abort error
paths were not validated here. Application-level trust decisions remain with the
caller. Group tests establish pairwise ECDH, not broadcast encryption or group
membership enforcement. This change does not define or implement the v2 KDF,
nonce, or envelope profile and is not a security audit.

Run `npm test` for the automated source suite and `npm run build` to regenerate
both outputs in `dist/`. The suite imports `lib/` directly. No runtime dependency
was added for persistence.
