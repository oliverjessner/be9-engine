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
| `be8.privateKeys` | `[namespace, accID]` | Local private identity JWK in `key` |
| `be8.groupKeys` | `[namespace, groupID, version]` | Local public or private group JWK in `key` |

The three key stores have a nonunique `namespace` index. A namespace is bound to
one account on its first successful mutation. A different account cannot read,
write, initialize, or clear it. The same account can use multiple explicitly
chosen namespaces, each with its own identity. The application must treat these
stores as engine-owned records; arbitrary direct edits are not a synchronization
or authorization API.

Public/private identity writes share one native transaction. Group private keys
are persisted together with their public coordinates in one record. Cryptographic
generation/import happens before the write transaction. All mutation promises
resolve only after native transaction completion; request success alone cannot
report a commit. Request errors force rollback even if another event listener
prevents the default abort. Persistence and storage validation failures are
`Error` objects with generic messages and stable `code` values; persistence
failures use `PERSISTENCE_ERROR` and a sanitized
native category in `name`. Raw request errors, key values, and plaintexts are not
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
Parallel calls use the options of the first pending `setup()` call; after a
failure, the application can retry with an explicit legacy adoption decision.

### Legacy identity integration

Old `publicKeys`, `privateKeys`, and `groupKeys` stores are left intact. If an old
identity exists for this account but no scoped identity exists, default
`setup()` rejects with `LEGACY_IDENTITY`. It does not silently generate new keys.

After an explicit application decision, `await be8.setup({ legacyIdentity: true })`
reads and validates that account's old pair, then copies it atomically into the
selected namespace. It rechecks the legacy pair under the write lock and rejects
if it changed. This copies only the local identity, retaining the original
records. It does not infer ownership of old peer/group caches or migrate any
ciphertexts. The application must explicitly select trusted peer/group records
and import them through `addPublicKeys()`/`addGroupKeys()` when needed.

The named `readLegacyIdentity(connection, accID)` export provides an explicit,
readonly inspection of the old local pair. It returns `[publicJWK, privateJWK]`
or `null`; incomplete data rejects. None of these paths runs automatically after
a ciphertext authentication error. This storage upgrade does not change the KDF,
nonce, cipher, or envelope profile.

### Caller changes

- `hasGeneratedKeys()` and `hasKey(id)` now return promises: callers must `await`
  them instead of testing the truthiness of a promise.
- `addPublicKey()` is asynchronous; `addPublicKey()`, `addPublicKeys()`, and
  `addGroupKeys()` resolve to `undefined` after commit. They no longer expose
  mutable internal maps or meaningless arrays of `undefined`.
- `generatePrivAndPubKey()` is idempotent and consistently returns the existing
  or newly committed `[publicJWK, privateJWK]`. It cannot silently rotate keys.
- `generateGroupKeys(version, groupID)` requires both arguments, persists the
  local group identity, and always returns `[publicJWK, privateJWK]`. Group IDs
  match `g[A-Za-z0-9_-]+`; versions are positive safe integers (canonical decimal
  strings are accepted and normalized). A group key at an existing version
  cannot be replaced by different coordinates/private material. Reimporting its
  public half retains an already stored private half.
- Caller key objects are snapshotted and only JWK fields are copied. Embedded
  `accID`, `namespace`, `groupID`, or `version` cannot override explicit metadata.
  Public-key insertion rejects private JWKs and rejects replacing the public
  half of this namespace's own identity with different coordinates.
- `panic()` explicitly clears only the current namespace's key records in one
  transaction. It retains the account binding, application stores, other
  namespaces, and legacy records. It never deletes the application's database.
- The ESM build adds named `upgradeBe8Schema`, `STORES`, and
  `readLegacyIdentity` exports. The IIFE remains a callable `be8` constructor;
  its integration helpers are `be8.upgradeBe8Schema`, `be8.STORES`, and
  `be8.readLegacyIdentity` (also available on the ESM constructor).

Local identity/group export APIs can return private JWKs to their owner as before.
Only their public halves belong in participant-to-participant exchanges.

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
Returns the existing or newly generated public/private pair after atomic IndexedDB storage. Existing identities are retained.

```javascript
const [publicKey, privateKey] = await be8.generatePrivAndPubKey();
```

## async generateGroupKeys(version, groupID)
Generates or restores a local group identity in the current namespace after commit.

```javascript
const [publicKey, privateKey] = await be8.generateGroupKeys(1, 'g10300');
```

## async getDerivedKey(publicKey, privateKey)
Generates a derived key out of the public and private key. 

```javascript
const [, ownPrivateJWK] = await be8.generatePrivAndPubKey();
const derivedKey = await be8.getDerivedKey(bobPublicJWK, ownPrivateJWK);
```

## async encryptText(derivedKey, text = '')
After creating a [derivedKey](#async-getderivedkeypublickeyjwk-privatekeyjwk) we can start to encrypt text messages. encryptText returns a cipherText and a iv (Initialization vector).
 
```javascript
const text = 'Hello World';
const derivedKey = await be8.getDerivedKey(publicKey, privateKey);
const { cipherText, iv } = await be8.encryptText(derivedKey, text);
```

## async decryptText(derivedKey, cipherText, iv)
With the help of the key, the cipherText and an iv, we can decrypt messages.

```javascript
const cipherText = 'ASDASD9324/&§$jn';
const iv = '213210931249713409';
const derivedKey = await be8.getDerivedKey(publicKey, privateKey);
const text = await be8.decryptText(derivedKey, cipherText, iv);
```

## encryptTextSimple(accIDSender, accIDReceiver, text)
encryptTextSimple is a compound function of [encryptText](#async-encrypttextderivedkey-text) and [getDerivedKey](#async-getderivedkeypublickey-privatekey). It uses the ids instead of keys. 
The derivedKey is generated inside the function.

```javascript
const accIDSender = be8.getAccID();
const accIDReceiver = '2';
const text = 'Hello World';
const cipherText = await be8.encryptTextSimple(accIDSender, accIDReceiver, text);
```

## async decryptTextSimple(accIDSender, accIDReceiver, cipherText, iv)
decryptTextSimple is a compound function of [decryptText](#async-decrypttextderivedkey-text) and [getDerivedKey](#async-getderivedkeypublickey-privatekey). It uses the ids instead of keys. 
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
Private JWKs and derived AES keys are never exchanged between participants.
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
restart, namespace ownership races, schema upgrade rollback, and legacy identity
adoption. The previous commit contract assertions remain strict and now pass.
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
