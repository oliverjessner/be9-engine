# be9-engine
Be9 is a reusable JavaScript ESM cryptography engine using native WebCrypto
P-384 ECDH plus HKDF-SHA-256 and AES-256-GCM. Applications supply data, public keys, trust
decisions, context, and an application-owned IndexedDB connection.

The constructor is `Be9`, the classic-script global is `be9`, and schema
integration uses `upgradeBe9Schema`. Existing `be8.*` databases require the
explicit `migrateBe8Schema` application upgrade. New encryption uses Be9 suite
and domain identifiers; retained Be8 ciphertexts require explicit Be8 readers.
See [rename and migration](docs/be9-migration.md) for breaking changes, code,
compatibility APIs and validation results.

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
import Be9, { upgradeBe9Schema } from 'be9-engine';

const request = indexedDB.open('my-application', 2); // Application-owned version.
let upgradeError;
request.onupgradeneeded = () => {
    try {
        upgradeBe9Schema(request.result, request.transaction);
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

const be9 = new Be9('1', db, { namespace: '1' });
await be9.setup();
const hasKeys = await be9.hasGeneratedKeys();
```

`upgradeBe9Schema(db, transaction)` is synchronous and requires the application's
native versionchange transaction. Repeated calls are safe for a matching schema.
Incompatible engine store/index definitions abort the upgrade; no store is deleted
or replaced. The engine uses these dedicated stores alongside application stores:

| Store | Primary key | Contents |
| --- | --- | --- |
| `be9.scopes` | `namespace` | Permanent account/namespace binding, lifecycle status and generation |
| `be9.publicKeys` | `[namespace, accID]` | Public JWK in a separate `key` field |
| `be9.privateKeys` | `[namespace, accID]` | Non-extractable private ECDH `CryptoKey` in `key`, public JWK in `publicKey` |
| `be9.groupKeys` | `[namespace, groupID, version]` | Retained legacy public JWK in `key`, optional non-extractable ECDH `CryptoKey` in `privateKey` |
| `be9.trust` | `[namespace, peerID]` | SHA-256 thumbprint and local `unverified`, `confirmed`, or `tofu` status |
| `be9.groupEpochs` | `[namespace, groupID, epoch]` | Non-extractable symmetric HKDF key and public generation/issuer metadata |
| `be9.activeEpochs` | `[namespace, groupID]` | Explicit active epoch selection |
| `be9.contexts` | `[namespace, contextID]` | Open/closed state and bounded stream registry |
| `be9.sendState` | `[namespace, contextID, streamID]` | Committed uint64 send counter |
| `be9.receiveState` | `[namespace, contextID, streamID]` | Highest uint64 sequence and 128-bit replay bitmap |
| `be9.keyUsage` | `derivationID` | Database-wide encryption/GHASH counters keyed by validated actual derivation |

All namespace-scoped stores other than `be9.scopes` have a nonunique `namespace` index. The
usage store is global to this database and has no namespace index. A namespace is bound to
one account on its first successful mutation. A different account cannot read,
write, initialize, or clear it. The same account can use multiple explicitly
chosen namespaces, each with its own identity. The application must treat these
stores as engine-owned records; arbitrary direct edits are not a synchronization
or authorization API.

Public/private identity writes share one native transaction. Retained legacy group private CryptoKeys
are persisted together with their public JWK; new symmetric epochs occupy separate records. Both use native Structured Clone. Cryptographic
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
import Be9, { jwkThumbprint } from 'be9-engine';
const fingerprint = await jwkThumbprint(bobPublicJWK);
// Also available as Be9.jwkThumbprint(), including on the IIFE constructor.
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
await be9.addPublicKey('2', bobPublicJWK);

// A fingerprint supplied by the application from its independent trust process.
await be9.addPublicKey('2', bobPublicJWK, { expectedFingerprint: independentlyConfirmedFingerprint });

// Alternatively, the application explicitly takes responsibility for trust.
await be9.addPublicKey('2', bobPublicJWK, { trust: 'confirmed' });
const trust = await be9.getPeerTrust('2');
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
await be9.addPublicKey('2', bobPublicJWK, { tofu: true });
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
await be9.addPublicKeys([
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

Retained legacy public ECDH group endpoints use the same policy, with `peerID: 'g10300:1'`:

```javascript
await be9.addLegacyGroupKeys('g10300', [{ version: 1, groupKey: publicGroupJWK }], {
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
await be9.replacePublicKey('2', newBobPublicJWK, {
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
`upgradeBe9Schema()` in their upgrade handler to create `be9.trust`. The helper
only creates/checks dedicated engine schema; it does not validate or confirm old
keys. Records lacking trust remain unauthorized. After integrating the schema,
the application can explicitly initialize trust records for the old scoped public
peer/group records:

```javascript
const { migratedPeers } = await be9.migratePublicKeyTrust();
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
`extractable: false` and only `['deriveBits']`. Public keys remain exportable JWKs.
Derived AES-GCM keys also have `extractable: false`. Data and attachment keys
allow only `['encrypt', 'decrypt']`; wrapping keys allow only
`['wrapKey', 'unwrapKey']`. Explicit legacy AES readers allow only `decrypt`. No normal engine operation exports private keys.
The required browser capabilities are native WebCrypto, IndexedDB CryptoKey
Structured Clone, and `structuredClone()` preserving a non-extractable CryptoKey.
Missing clone support rejects with `CRYPTOKEY_STORAGE_UNSUPPORTED`; it does not
store JWKs instead. See [WebCrypto key generation and serialization](https://www.w3.org/TR/2017/REC-WebCryptoAPI-20170126/).

Existing private JWKs require an explicit application migration decision:

```javascript
// Convert this namespace's existing identity and private group JWK records.
// Call before setup when setup reports PRIVATE_KEY_MIGRATION_REQUIRED.
const { migratedIdentity, migratedGroups } = await be9.migratePrivateKeys();
await be9.setup();
```

For an old unscoped `publicKeys`/`privateKeys` identity, default setup reports
`LEGACY_IDENTITY`. Integrate the engine schema through the application's upgrade
handler first, then explicitly adopt that account's existing identity:

```javascript
await be9.migratePrivateKeys({
    legacyIdentity: true,
    // Optional, explicit application-owned selection of old local private groups.
    // Old group ownership cannot be inferred by the engine.
    // Keep the original IndexedDB version key type (number or canonical string).
    legacyGroups: [{ groupID: 'g10300', version: '1' }],
});
await be9.setup();
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
`addLegacyGroupKeys()`.

This operation preserves public fingerprints and cryptographic identity. It
imports private keys with only `deriveBits`, enabling the v2 KDF and the explicit
legacy reader without rewriting any ciphertext. It never runs after ciphertext
authentication failure. Existing browser/application backups outside
these selected records are not erased by this migration.

**Malicious JavaScript in the same execution context can still misuse these keys**,
for example by reading CryptoKeys from IndexedDB or calling engine encryption and
decryption methods. Non-extractable means WebCrypto denies key export; it does not
mean XSS-safe, hardware-protected, or inaccessible to browser/profile owners.
It also does not guarantee forensic erasure of prior JWK storage.

### Caller changes

- `generatePrivAndPubKey()` returns `{ publicKey, keyReference }` after commit,
  retaining an existing identity. Private JWK tuples and the old private export
  helper are removed; migration is explicitly `migratePrivateKeys()`, never setup.
- The opaque reference belongs to one local instance and committed identity.
  References and CryptoKeys stay local. Reload obtains a fresh reference;
  panic discards references and derivation registrations.
- `createDerivationContext(publicJWK, reference, { contextID, sender, receiver,
  purpose })` and `getDerivedKey(publicJWK, reference, derivation)` use full-width
  ECDH/HKDF with actual fingerprints and non-extractable AES. Modern endpoint
  contexts use account IDs. Raw AES methods retain their signatures and caller
  trust/context responsibilities; they have no implicit envelope or replay check.
- Simple text/image encryption now returns `{ header, ciphertext }`.
  Simple decryptors take `(sender, receiver, envelope, { contextID })`.
  The application should independently supply its expected context.
  Other convenience options, including custom IVs, reject. Sender must be the
  local account and receiver must match the decrypting engine's account.
- `encryptEnvelope(sender, receiver, bytes, { contextID, purpose })` and
  `decryptEnvelope(envelope, { sender, receiver, contextID, purpose })` use the
  strictly authenticated [envelope profile](docs/envelope-state.md).
  `encodeEnvelopeAAD` exposes deterministic public header bytes.
- Open application contexts explicitly with `openContext`. `closeContext`
  permanently closes that ID. Simple sending without context creates a fresh
  random context. Archive decryptors remain repeatable. For replay protection,
  initialize independent expectations via `openReceiveContext`, then use
  `receiveEnvelope`, `receiveText` or `receiveImage`. Output follows replay commit.
- New groups use `createGroupEpoch`, recipient-specific encrypted packages,
  `importGroupEpoch` and explicit CAS `activateGroupEpoch`. Group encryptors use
  the active epoch; archive decryptors require an explicitly expected epoch.
  Getters expose metadata only. See [group APIs and limits](docs/group-epochs.md).
- `generateGroupKeys` and ambiguous `addGroupKeys` reject `LEGACY_GROUP_API`.
  Retained ECDH groups use `addLegacyGroupKeys`, `getCachedLegacyGroupKeys`,
  `getCachedLegacyGroupVersions`, `hasLegacyGroupKey`, `getLegacyGroupKeyReference`
  and explicit legacy readers. They never become symmetric epochs implicitly.
- New encrypted values are strict unpadded Base64url, with 12 random IV bytes and
  128-bit GCM tags. Byte/text/image helpers share 16 MiB bounds. Private and
  derived/operative symmetric keys are non-extractable. Existing image strings
  remain text; use byte APIs for raw image bytes.
- Be9 ciphertext/IV/HKDF tuples use `decryptTextUnframedLegacy` or its image
  equivalent. Retained Be8 HKDF tuples instead use `decryptBe8TextUnframedLegacy`
  or `decryptBe8ImageUnframedLegacy`. Only explicitly selected `{ legacyUUID: true }` accepts the earlier
  UUID/padded-Base64 HKDF representation. Direct-ECDH data uses `getLegacyDerivedKey`
  and `decryptText/Image(Simple)Legacy`. No validation/authentication failure
  selects another format. DeriveKey-only identities remain available for legacy
  reading; unsupported v2 usage never silently rotates them.
- All public imports validate keys and separate local trust decisions. Ordinary
  imports never replace a changed key; explicit replacement uses fingerprint CAS.
  Bulk imports cannot bypass policy. Embedded account/trust metadata cannot
  override separate arguments. Old unverified records remain unverified.
- Integrate all additional stores with `upgradeBe9Schema` in the application's
  version upgrade. Native request success is insufficient: mutations wait for
  commit. Persistent actual-key usage limits survive reload and namespace aliases;
  raw/cloned keys and direct WebCrypto require caller accounting.
- `panic()` now immediately locks, invalidates in-flight results, deletes only
  selected namespace keys and replay/security state atomically, and commits a
  tombstone. Failure leaves it locked. `setup()` cannot unlock/recreate identity;
  use explicit `reinitialize()` after successful panic. Other live/stale instances
  cannot adopt that new generation. [Lifecycle contract](docs/lifecycle.md).
- Named ESM and constructor static helpers: `upgradeBe9Schema`, `STORES`,
  `jwkThumbprint`, `V2_SUITE`, `GROUP_SUITE`, `encodeV2DerivationInfo`,
  `encodeEnvelopeAAD`, `encodeBase64url`, `decodeBase64url`, `V2_LIMITS`,
  `REPLAY_WINDOW`.
  Explicit compatibility helpers are `migrateBe8Schema`, `encodeBe8DerivationInfo`
  and `encodeBe8EnvelopeAAD`; they never enable new Be8 encryption.

## hasGeneratedKeys()

Checks the committed identity pair in this namespace. Returns a Promise<boolean>.

```javascript
await be9.hasGeneratedKeys();
```

## getAccID
Return the accID.

```javascript
be9.getAccID();
```

## async addPublicKeys(publicKeys = [], options = {})
Stores a validated batch and its local trust decisions atomically. Without
separate decisions, first-contact keys remain unverified. Changed peer keys reject.

```javascript
const publicKeys = [{ accID: '2', publicKey: bobPublicJWK }];
await be9.addPublicKeys(publicKeys);
```

## async addPublicKey(accID, key, decision = {})
Stores one peer public key and local trust state, resolving only after commit.
Confirm through a separate local argument before convenience use.

```javascript
await be9.addPublicKey('2', bobPublicJWK, { expectedFingerprint: independentlyConfirmedFingerprint });
```

## async addLegacyGroupKeys(groupID, keys, options = {})
Remote public group endpoints require their own separate local trust decision.

```javascript
await be9.addLegacyGroupKeys('g10300', [{ version: 1, groupKey: publicGroupJWK }], {
    decisions: [{ peerID: 'g10300:1', trust: 'confirmed' }],
});
```

## async generatePrivAndPubKey()
Returns the existing or newly committed public JWK and an opaque local key reference. Existing identities are retained.

```javascript
const { publicKey, keyReference } = await be9.generatePrivAndPubKey();
```

## Group epochs and explicit legacy reads

New groups use independent symmetric 256-bit epochs, encrypted pairwise key
packages and separate activation. See [group-epochs.md](docs/group-epochs.md)
for creation/import, active/archive APIs, replay and caller changes.
`generateGroupKeys()` rejects: production code does not create new ECDH groups.
`getLegacyGroupKeyReference(groupID, version)` restores only an existing local
private ECDH group reference for explicit legacy readers.

## v2 derivation and encryption

The [v2 profile](docs/v2-profile.md) specifies full-width P-384 ECDH,
HKDF-SHA-256, AES-256-GCM, salt transfer, exact length-prefixed info encoding,
96-bit random nonces, canonical Base64url and persistent usage limits.
Only public keys, public metadata and encrypted packets travel between peers.
Applications own peer trust and context; the engine binds the actual key
fingerprints and ordered endpoints.

```javascript
// Independent engines, each with its own database and private key.
const aliceLocal = await alice.generatePrivAndPubKey();
const bobLocal = await bob.generatePrivAndPubKey();
const context = await alice.createDerivationContext(
    bobLocal.publicKey, aliceLocal.keyReference,
    { contextID: 'example', sender: '1', receiver: '2', purpose: 'data' },
);
const packet = { ...await alice.encryptText(context.key, 'Hello World'),
    derivation: context.derivation };
const receiverKey = await bob.getDerivedKey(
    aliceLocal.publicKey, bobLocal.keyReference, packet.derivation,
);
const text = await bob.decryptText(receiverKey, packet.cipherText, packet.iv);
```

`encryptText(key, text = '')` / `decryptText(key, cipherText, iv)` retain their
raw AES signatures, with ciphertext/IV now encoded as canonical Base64url.
`encryptImage(key, base64Image)` / `decryptImage(key, cipherImage, iv)` retain the
existing image-string API. Use a separately created `attachment` context for
images. `encryptBytes(key, bytes)` / `decryptBytes(key, ciphertext, iv)` handle
raw binary plaintext; decryption returns a Uint8Array. Text decoding is strict
UTF-8 and preserves BOMs. Primitive APIs require the application's own
peer-trust and expected-context checks.

Only the originating engine registers v2 keys for persistent usage accounting.
Caller-supplied or cloned native AES keys and direct WebCrypto operations remain
low-level APIs: the caller must coordinate nonce discipline and the same per-key
  invocation/block limits across all writers. See the [budget contract](docs/v2-profile.md#persistent-usage-budget).

## simplified text and image APIs

After each engine separately imports and locally confirms the other's public
key (or explicitly enables first-contact TOFU), the convenience APIs perform
committed peer-trust checks and internal v2 derivation:

```javascript
await alice.openContext('example');
const packet = await alice.encryptTextSimple('1', '2', 'Hello World', {
    contextID: 'example',
});
const text = await bob.decryptTextSimple(
    '1', '2', packet,
    { contextID: 'example' },
);

const imagePacket = await alice.encryptImageSimple('1', '2', base64Image);
const image = await bob.decryptImageSimple(
    '1', '2', imagePacket,
);
```

Text uses purpose `data`; images use `attachment`. An omitted sender context ID
gets a public random UUID. Every new derivation gets a fresh public 32-byte salt;
the recipient reuses the transferred salt. Encryption returns a complete
authenticated envelope; decryption takes that envelope. Sender/receiver arguments
keep the original packet direction on both engines. Reverse communication creates
a new context with reversed endpoints and actual fingerprints.

Explicit old-data readers are `getLegacyDerivedKey(publicJWK, localReference)`,
`decryptTextSimpleLegacy(sender, receiver, cipherText, iv)` and
`decryptImageSimpleLegacy(sender, receiver, cipherImage, iv)`. Legacy derivation
returns a non-extractable decrypt-only AES key. No automatic detection or retry
exists. UUID/UTF-8 IVs and padded Base64 are accepted only by explicit
`decryptTextLegacy()` / `decryptImageLegacy()` or the legacy convenience readers.
For older HKDF packets with UUID IVs, derive with their original v2 metadata and
use the explicit legacy wire decoder, retaining HKDF rather than selecting the
old direct-ECDH KDF. Existing ciphertext is not rewritten or deleted.
These helpers do not yet implement the authenticated v2 envelope; see
[integration limits](docs/v2-profile.md#envelope-integration-status-and-limits).

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
exercise recipient-specific encrypted handoff to three isolated engines,
non-extractable symmetric epochs, bidirectional data, image strings, next-epoch
exclusion, archive/replay/reload, immutable epochs, activation CAS and explicit
retained ECDH legacy readers. No private keys or already derived keys are shared.

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
`test/v2.mjs` checks RFC 5869 HKDF-SHA-256 vectors, an independent Node/OpenSSL
full-width P-384/HKDF/AES-GCM vector, independent peer derivation, salt/context/
direction/purpose separation, strict field encoding, native wrapping usages,
actual key fingerprints, transferred salt, and old deriveKey-only identity
retention. Historical UUID packets reject before v2 crypto; authentication
failure with modern metadata also never triggers a legacy retry. No derived key
export is enabled for equality tests. `test/encoding.mjs` verifies binary and
large-array roundtrips, native fixed IV fixtures, Unicode/BOM, image text over
2 MiB, strict encoding/IV/tag/size limits, pre-derivation validation, and committed
usage counters across reload, re-derivation, parallel connections, namespace
aliases and panic. Native transaction aborts and unique-index write errors
verify reservation rollback; application-owned schema integration is covered.
`test/envelope.mjs` validates every header field and an independent Python AAD
vector. `test/replay.mjs` exercises bounded windows, overflow, missing/closed
state, concurrent acceptance and commit failures. `test/panic.mjs` checks
in-flight crypto/setup/reinitialization, native delete rollback, idempotency,
other connections, a separate module worker realm, restart and namespace/store
isolation. The participant fixtures make separate explicit local decisions for their known
synthetic peers; no trust record is taken from an exchanged key object.
Timeouts in the runner and failure tests are failure deadlines, not readiness
waits. Test output excludes assertion data and raw browser errors.

The suite exercises native Chromium WebCrypto/IndexedDB. Other browsers,
hardware failures, and storage exhaustion beyond native constraint/abort error
paths were not validated here. Application-level trust decisions remain with the
caller. The [v2 profile](docs/v2-profile.md), authenticated
[envelope and replay state](docs/envelope-state.md), [group epochs](docs/group-epochs.md)
and [local invalidation](docs/lifecycle.md) are implemented. Shared group secrets
do not prove individual authorship or enforce membership. Random IVs do not guarantee
collision freedom; state coordination is limited to one application-owned
database and assumes preserved counters. This is not a security audit, and no
guaranteed secret-memory erasure is claimed.

Run `npm test` for the automated source suite and `npm run build` to regenerate
both outputs in `dist/`. The default suite imports `lib/`. After build, `npm test -- --bundle esm` and
`npm test -- --bundle iife` run the same native integration suite against each
generated constructor. The IIFE is evaluated unchanged with an ESM adapter for
tests/workers; public codec/persistence unit helpers still import source modules. No runtime dependency
was added for persistence.

Abschluss und vollständige Dateiliste für Todo 6–9: [Umsetzungsbericht](docs/todo6-9.md).
