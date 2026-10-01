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
| `be8.trust` | `[namespace, peerID]` | SHA-256 thumbprint and local `unverified`, `confirmed`, or `tofu` status |

The three key stores and the trust store have a nonunique `namespace` index. A namespace is bound to
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
encryption/decryption reads both endpoint keys and the peer trust record in one
committed database snapshot.
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

### Public-key validation, fingerprints and local trust

All public import paths validate EC/P-384 keys with canonical unpadded base64url
coordinates of exactly 48 bytes each, then use native WebCrypto import to check
that they describe a valid curve point. Private fields (including an explicitly
present `d: undefined`) are rejected. Optional `ext` must be boolean, `key_ops`
must be an empty array for ECDH public keys, `use` may only be `enc`, and `alg`
may only be `ECDH-ES`. Absent `ext`/`key_ops` normalize to `true`/`[]`. Other
public labels and account metadata are ignored. Accepting the key's ECDH usage
label does not implement JOSE ECDH-ES or its KDF/envelope. Primitive derivation
validates the same supported public-key profile.

```javascript
import Be8, { jwkThumbprint } from 'be8-engine';
const fingerprint = await jwkThumbprint(bobPublicJWK);
// Also available as Be8.jwkThumbprint(), including on the IIFE constructor.
```

The thumbprint follows [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html):
SHA-256 of UTF-8 JSON containing only `crv`, `kty`, `x`, `y`, in that exact
lexicographic order, without whitespace. The returned digest is canonical
unpadded base64url (43 characters). Optional JWK members, property order,
account IDs, namespace, and verification labels do not enter the hash.

Ordinary imports never replace an existing different point. New peer keys are
stored with a separate namespace-local trust record as `unverified` by default.
Convenience text/image encryption **and** decryption reject these peers with
`UNTRUSTED_PUBLIC_KEY`. The application can confirm the key through a separate
local argument, either using an independently established expected fingerprint
or making its own explicit trust decision:

```javascript
// Default: retain the key for inspection, without authorizing convenience use.
await be8.addPublicKey('2', bobPublicJWK);

// A fingerprint supplied by the application from its independent trust process.
await be8.addPublicKey('2', bobPublicJWK, { expectedFingerprint: independentlyConfirmedFingerprint });

// Alternatively, the application explicitly takes responsibility for trust.
await be8.addPublicKey('2', bobPublicJWK, { trust: 'confirmed' });
const trust = await be8.getPeerTrust('2');
// { peerID: '2', fingerprint, status: 'unverified' | 'confirmed' | 'tofu' }
// undefined means no persisted decision exists; it never grants authorization.
```

**A fingerprint from the same unconfirmed source as the key does not independently
confirm the peer's identity.** The engine checks equality, not the provenance of
an application's decision. Imported `verified: true`, `trust`, or fingerprint
fields inside a JWK or key entry are never evidence of trust. Do not copy network
objects into the separate local decision argument.

TOFU is enabled only explicitly, per import:

```javascript
await be8.addPublicKey('2', bobPublicJWK, { tofu: true });
```

TOFU grants convenience use only for a genuinely new contact with neither an
existing public record nor a trust record. Its status remains `tofu`, distinct
from `confirmed`; it offers no independent identity proof on first contact. It
cannot retroactively approve an old unverified contact, authorize a changed key,
or downgrade a confirmed decision. Confirming the same key later can promote
TOFU to `confirmed`. Reimporting an unchanged confirmed/TOFU key without a new
decision preserves its status. A wrong expected fingerprint rejects with
`FINGERPRINT_MISMATCH`; a different ordinary peer import rejects with
`PUBLIC_KEY_CHANGED`, preserving the old public key and trust record.

Bulk decisions are a separate application-owned list selected by `peerID`:

```javascript
await be8.addPublicKeys([
    { accID: '2', publicKey: bobPublicJWK },
    { accID: '3', publicKey: carolPublicJWK },
], { decisions: [
    { peerID: '2', expectedFingerprint: independentlyConfirmedBobFingerprint },
    { peerID: '3', trust: 'confirmed' },
] });
// Optional { tofu: true } applies first-contact TOFU to undecided entries.
```

Every key is validated and hashed before the write transaction. Bulk imports
recheck keys and trust under one write lock, including repeated peer IDs. Any
validation, fingerprint, replacement, or native write failure rejects the entire
batch. Public records and trust records commit together. Decisions cannot override
separately supplied account or namespace metadata.

Remote public group endpoints use the same policy, with `peerID: 'g10300:1'`:

```javascript
await be8.addGroupKeys('g10300', [{ version: 1, groupKey: publicGroupJWK }], {
    decisions: [{ peerID: 'g10300:1', expectedFingerprint: independentlyConfirmedGroupFingerprint }],
});
```

Existing group versions remain immutable (`GROUP_CONFLICT` on changed coordinates);
use a new explicit version rather than replacing a retained group identity.
The namespace's own identity and locally generated/migrated private group keys
are local keys, not remote peer trust decisions. Primitive `getDerivedKey()` and
raw AES methods do not infer peer identity: callers of these lower-level APIs
must enforce their own trust policy. Use the convenience methods for persisted
peer-trust enforcement.

### Explicit peer key replacement and old trust records

Peer replacement is a separate compare-and-swap operation:

```javascript
await be8.replacePublicKey('2', newBobPublicJWK, {
    expectedPreviousFingerprint: previouslyStoredBobFingerprint,
    confirmedNewFingerprint: independentlyConfirmedNewBobFingerprint,
});
```

Both fingerprints are required. The new confirmed fingerprint must match the
validated candidate. The engine validates the current point/fingerprint and
rechecks it in the write transaction. If another connection changes the peer,
the stale replacement rejects with `TRUST_CONFLICT`. Public key and `confirmed`
trust state replace the previous records atomically, only reporting success after
commit. This API cannot rotate the local private identity or mutate a group
version. It does not create a public-key history; callers needing old public keys
for old ciphertexts must retain that public context explicitly. Already-running
crypto operations may finish with the committed snapshot they read before a
replacement; a trust update is not cancellation of in-flight work.

Existing applications must increment their own database version and call
`upgradeBe8Schema()` in their upgrade handler to create `be8.trust`. The helper
only creates/checks dedicated engine schema; it does not validate or confirm old
keys. Records lacking trust remain unauthorized. After integrating the schema,
the application can explicitly initialize trust records for the old scoped public
peer/group records:

```javascript
const { migratedPeers } = await be8.migratePublicKeyTrust();
```

This validates existing public keys and atomically adds only missing `unverified`
trust records. It preserves public keys, private identity, application data, and
existing valid local decisions. Old `verified` flags are ignored. Invalid data or
concurrent changes reject without partial migration. Old unchecked contacts cannot
become TOFU by reimport; confirm the unchanged key explicitly, or use the separate
replacement API after the old fingerprint is recorded. Private-JWK migration
remains a separate operation and never confirms old remote public keys.

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
- `panic()` still explicitly clears only the current namespace's key and trust records
  atomically, retaining its account binding, application stores, other namespaces,
  and unselected legacy records. It never deletes the application database.
- Public imports remain async but no longer silently replace peers. Calls without
  local trust options retain first-contact data as unverified. Convenience calls
  now require a confirmed or explicitly TOFU peer; update callers accordingly.
- Added `getPeerTrust()`, `replacePublicKey()`, and `migratePublicKeyTrust()`.
- Named ESM/static exports are `upgradeBe8Schema`, `STORES`, and `jwkThumbprint`.
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

## async addPublicKeys(publicKeys = [], options = {})
Stores a validated batch and its local trust decisions atomically. Without
separate decisions, first-contact keys remain unverified. Changed peer keys reject.

```javascript
const publicKeys = [{ accID: '2', publicKey: bobPublicJWK }];
await be8.addPublicKeys(publicKeys);
```

## async addPublicKey(accID, key, decision = {})
Stores one peer public key and local trust state, resolving only after commit.
Confirm through a separate local argument before convenience use.

```javascript
await be8.addPublicKey('2', bobPublicJWK, { expectedFingerprint: independentlyConfirmedFingerprint });
```

## async addGroupKeys(groupID, keys, options = {})
Remote public group endpoints require their own separate local trust decision.

```javascript
await be8.addGroupKeys('g10300', [{ version: 1, groupKey: publicGroupJWK }], {
    decisions: [{ peerID: 'g10300:1', trust: 'confirmed' }],
});
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
migration conflict handling. `test/trust.mjs` verifies an independent RFC 7638
vector, strict native point/usage validation, first-contact quarantine, ignored
network verification flags, wrong expected fingerprints, TOFU, idempotent
reimports, bulk rollback, explicit replacements and concurrent compare-and-swap,
trust persistence/isolation, and old schema migration without false verification.
The participant fixtures make separate explicit local decisions for their known
synthetic peers; no trust record is taken from an exchanged key object.
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
