# Be8 v2 cryptographic profile

This specifies the implemented KDF and its public metadata for protocol version
`2`, suite `BE8-P384-HKDF-SHA256-A256GCM`. It is one v2 profile, not a menu of
automatically detected algorithms. Unsupported versions/suites reject. The
nonce, binary encoding and encryption budget are specified below. The
authenticated v2 envelope is still to be specified and implemented; these
helpers do not claim to implement that envelope.

## Cryptographic derivation

1. Use the local non-extractable P-384 ECDH private CryptoKey and the validated
   peer P-384 public point. New and explicitly migrated private keys allow only
   `deriveBits`.
2. Call native WebCrypto ECDH `deriveBits(..., 384)`. The input keying material
   (IKM) is the entire 48-byte, fixed-width, big-endian shared x-coordinate,
   including leading zeros. Do not truncate it to an AES key.
3. Import that IKM as a non-extractable WebCrypto HKDF key with only `deriveKey`.
4. Use HKDF-SHA-256 with the 32-byte public salt and `info` defined below, deriving
   exactly 32 bytes as a non-extractable AES-256-GCM CryptoKey.

This uses HKDF Extract and Expand as defined in
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html), through
[native WebCrypto ECDH and HKDF](https://www.w3.org/TR/2017/REC-WebCryptoAPI-20170126/).
There is no custom HMAC, elliptic-curve implementation, exported PRK/OKM, or
cached shared secret. The JS secret view is overwritten immediately after HKDF
import, including failed imports, and again when derivation exits. This is best
effort: native/runtime copies and garbage collection prevent any guarantee of
memory erasure.

The sender generates a fresh 32-byte salt with `crypto.getRandomValues()` for
each new derivation context. Salt is public and travels with the ciphertext and
metadata. The receiver decodes that exact salt; it never creates a replacement
salt when decrypting. Reusing a received context intentionally recreates the
same key. A new context creation generates a fresh salt even when the application
reuses its context ID.

## Public metadata

The `derivation` object has exactly these nine own enumerable fields. Property
order is immaterial; extra or missing fields reject. It contains no key material.

| Field | Wire value / validation |
| --- | --- |
| `version` | JSON number `2` |
| `suite` | Exact string `BE8-P384-HKDF-SHA256-A256GCM` |
| `contextID` | Nonempty Unicode scalar string, at most 1024 UTF-8 bytes |
| `sender` | Canonical endpoint string, at most 256 UTF-8 bytes |
| `receiver` | Canonical endpoint string, at most 256 UTF-8 bytes |
| `senderFingerprint` | RFC 7638 SHA-256 thumbprint of the actual sender public key |
| `receiverFingerprint` | RFC 7638 SHA-256 thumbprint of the actual receiver public key |
| `purpose` | Exact string `data`, `attachment`, or `key-wrap` |
| `salt` | Canonical unpadded base64url encoding of exactly 32 random bytes |

Fingerprints likewise use canonical unpadded base64url (32 digest bytes, 43
characters). The thumbprint includes only `crv`, `kty`, `x`, `y` from the validated
EC JWK; optional fields and account metadata do not enter it. Engine derivation
recomputes both fingerprints from the actual local and peer public keys and
rejects mismatches with `DERIVATION_KEY_MISMATCH`.

Endpoints are canonical nonnegative decimal account IDs (`0` or a digit `1`–`9`
followed by digits), or `g[A-Za-z0-9_-]+:<version>` with a canonical positive safe
integer version. They are application-supplied identifiers, not server accounts
or identity verification. For local group keys the local endpoint is the exact
group/version in the opaque key reference. Sender and receiver keep their
original order on both sides: Bob receiving Alice's packet does not swap them.
The local reference must belong to the declared sender or receiver. A self
endpoint may only use the same public fingerprint on both sides.

Context strings undergo no Unicode normalization. Lone UTF-16 surrogates reject
rather than being replaced during UTF-8 encoding. Separators, NUL, and other
valid scalar characters are unambiguous under the length encoding below.

## Exact HKDF-info encoding

Start with the 13 ASCII bytes `BE8-HKDF-INFO`, without a NUL terminator. Append
exactly eight fields in the following order. Each field is encoded as a 4-byte
unsigned **big-endian byte length**, followed by that many bytes. No separators,
JSON serialization, optional fields, or trailing bytes occur.

| Position | Bytes |
| --- | --- |
| 1 | UTF-8 `2` (one byte `0x32`) |
| 2 | UTF-8 suite string |
| 3 | UTF-8 `contextID` |
| 4 | UTF-8 `sender` |
| 5 | UTF-8 `receiver` |
| 6 | Raw 32 decoded `senderFingerprint` bytes |
| 7 | Raw 32 decoded `receiverFingerprint` bytes |
| 8 | UTF-8 `purpose` |

Salt is the separate HKDF salt input, not an info field. The named ESM export and
constructor static helper `encodeV2DerivationInfo(derivation)` expose these public
info bytes for integration and interoperability. `V2_SUITE` exposes the suite
identifier. Neither helper exports secret material.

This encoding separates Alice-to-Bob from Bob-to-Alice even for the same ECDH
pair, salt, context and purpose. Purposes separate keys independently of direction:

| Purpose | AES usages | Convenience API |
| --- | --- | --- |
| `data` | `encrypt`, `decrypt` | Text |
| `attachment` | `encrypt`, `decrypt` | Existing base64 image API |
| `key-wrap` | `wrapKey`, `unwrapKey` | None; use native WebCrypto with the derived key |

The wrapping purpose does not add a private-key export or wrapping subsystem.
The engine's private keys remain non-extractable.

## APIs and caller changes

The primitive sender API requires an opaque local reference, public peer key,
and explicit ordered context. The receiver uses its own reference and the
transferred metadata. Only public keys, metadata, and ciphertext/IV are exchanged:

```javascript
const aliceLocal = await alice.generatePrivAndPubKey();
const bobLocal = await bob.generatePrivAndPubKey();
const { key, derivation } = await alice.createDerivationContext(
    bobLocal.publicKey, aliceLocal.keyReference,
    { contextID: 'application-context', sender: '1', receiver: '2', purpose: 'data' },
);
const packet = { ...await alice.encryptText(key, 'Hello'), derivation };
const receivingKey = await bob.getDerivedKey(
    aliceLocal.publicKey, bobLocal.keyReference, packet.derivation,
);
const text = await bob.decryptText(receivingKey, packet.cipherText, packet.iv);
```

Primitive `getDerivedKey(publicJWK, localReference, derivation)` no longer accepts
arbitrary private CryptoKeys: the engine needs the stored local public point to
bind its actual fingerprint. It derives v2 only and never invents missing
metadata. Applications using primitive APIs own their peer-trust checks and
expected context/purpose checks; fingerprints supplied in metadata do not grant
trust. Keys and references remain local and are not exchanged.

Keys created/re-derived through an engine are registered for its persistent
encryption budget. An incoming directional key cannot encrypt through that
engine: create a reverse context instead. Native WebCrypto remains accessible,
and its direct use is a low-level caller responsibility described below.

Convenience operations retain the persisted peer-trust policy and read local
public/private keys and peer public/trust state from one committed snapshot:

```javascript
// Both peers have separately imported and locally confirmed the other's key.
const packet = await alice.encryptTextSimple('1', '2', 'Hello', {
    contextID: 'application-context',
});
const text = await bob.decryptTextSimple(
    '1', '2', packet.cipherText, packet.iv, packet.derivation,
    { contextID: 'application-context' },
);
```

Text encryption now returns `{ cipherText, iv, derivation }`; image encryption
returns `{ cipherImage, iv, derivation }`. Decryption requires `derivation` as its
fifth argument. The optional final `{ contextID }` argument checks the receiver's
application-supplied expected context. Encryption without a context ID chooses
`crypto.randomUUID()` for the public context ID. It always creates a new random
salt. Images use purpose `attachment`, text uses `data`; convenience decryption
checks IDs, purpose, and any expected context before native decryption.

Missing metadata rejects with `DERIVATION_CONTEXT_REQUIRED`; invalid version,
suite, fields, IDs, purpose, or context rejects with `INVALID_DERIVATION_CONTEXT`.
An AES authentication failure propagates without another derivation attempt.
There is no automatic algorithm detection or fallback.

## Explicit legacy read compatibility

Old ciphertext uses the historical direct ECDH-to-AES-256 derivation exclusively:

```javascript
const key = await bob.getLegacyDerivedKey(alicePublicJWK, bobLocalReference);
const text = await bob.decryptTextLegacy(key, oldCipherText, oldIV);
// Or use the persisted, trusted peer keys with the explicit convenience reader:
const text2 = await bob.decryptTextSimpleLegacy('1', '2', oldCipherText, oldIV);
// decryptImageSimpleLegacy(sender, receiver, cipherImage, iv) is equivalent.
```

The application selects this path from its own explicit old-data context, never
in response to authentication failure. The resulting non-extractable AES key
allows only `decrypt`, so these APIs cannot encrypt new legacy packets. Existing
non-extractable `deriveKey`-only ECDH keys use the exact original WebCrypto
derivation. New `deriveBits`-only keys reproduce it by importing the first 32
bytes of the full 48-byte ECDH result; the temporary JS bytes are overwritten.
The low-level legacy method additionally accepts a native non-extractable
P-384 private CryptoKey with exactly one supported usage for caller-owned old
keys. It does not accept private JWKs or exportable private keys.

A stored non-extractable `deriveKey`-only private key cannot acquire `deriveBits`
without exporting it. Setup and reload therefore retain that identity and its
legacy readability; v2 derivation explicitly rejects with
`V2_KEY_USAGE_UNAVAILABLE`. No identity is silently regenerated, deleted, or
exported. Existing private-JWK migration imports the same validated identity
with only `deriveBits`; it preserves fingerprints, enables v2, and retains the
explicit legacy reader. No new migration/export path bypasses non-extractability.

Only explicit `decryptTextLegacy()` / `decryptImageLegacy()` and the legacy
convenience readers accept historical lowercase v4 UUID IV strings (36 ASCII
bytes, the same bytes as the old UTF-8 encoding) and canonical padded standard
Base64 ciphertext. Modern readers reject UUID IVs before key lookup or GCM;
they do not infer format from them. Legacy reads also enforce the bounded
ciphertext size below; oversized original packets are retained but refused.
No legacy writer is provided.

Packets created during the earlier HKDF implementation with UUID IVs retain
their HKDF key selection: explicitly derive using their original v2 metadata,
then call `decryptTextLegacy()` or `decryptImageLegacy()` for the old wire format.
Do not select the old direct-ECDH KDF for those packets. This is an explicit
application decision; neither authentication failure nor format validation
triggers a second algorithm or decoder.

## Nonces, binary encoding and input limits

All new engine AES encryption uses
`crypto.getRandomValues(new Uint8Array(12))`. AES-GCM parameters explicitly set
`tagLength: 128` on both encryption and decryption. The ciphertext is WebCrypto's
raw ciphertext followed by its 16-byte authentication tag. An empty plaintext
therefore produces 16 ciphertext bytes. The IV is exactly 12 bytes.

Engine encryption returns IV and ciphertext as canonical **unpadded Base64url**:
alphabet `A-Z a-z 0-9 - _`, no whitespace, no `+`, `/`, or `=`, no non-ASCII
characters. A length congruent to 1 modulo 4 is invalid; unused bits in the last
sextet must be zero. An IV serializes to exactly 16 characters. No TextEncoder or
TextDecoder operates on IVs, ciphertext, or other random byte material. Neither
standard padded Base64 nor a UUID string is a valid modern wire value.

The public named ESM / constructor static `encodeBase64url()` and
`decodeBase64url()` helpers implement this encoding. The decoder's optional byte
limit may lower the fixed maximum, never increase it. Encoding uses bounded
12,288-byte chunks aligned to three bytes, without variadic calls over a whole
array. Binary inputs are ArrayBuffer or views over an ordinary ArrayBuffer;
view offsets are respected and data is snapshotted before asynchronous work.
SharedArrayBuffer-backed inputs reject rather than permit concurrent mutations.

`encryptBytes(key, bytes)` returns `{ cipherText, iv }` in Base64url;
`decryptBytes(key, ciphertext, iv)` returns a Uint8Array. The decryptor accepts
either Base64url or binary BufferSources, including binary IVs. Text/image
decryptors accept the same encrypted representation. TextEncoder/TextDecoder
are reserved for actual text; decoding is fatal UTF-8 and preserves an initial
BOM. Lone surrogates are refused on text encryption. The existing image API
still encrypts/decrypts its base64/data-URL **text**, using the shared payload
helpers; use the byte API for raw image bytes.

`V2_LIMITS` is a frozen named ESM / constructor static object:

| Rule | Limit |
| --- | --- |
| IV | Exactly 12 bytes |
| GCM tag | Exactly 128 bits / 16 bytes |
| Plaintext | At most 16 MiB after UTF-8 encoding, or binary byte length |
| Ciphertext including tag | 16 bytes through 16 MiB + 16 bytes |
| Encrypted payload Base64url | At most `ceil((16 MiB + 16) * 8 / 6)` characters |
| Encryptions per derived key | 65,536 (`2^16`) |
| Aggregate GHASH blocks reserved for encryption per derived key | `2^24` |

Encoded lengths are checked before decoding/allocation. Invalid encodings, IV
lengths and partial tags reject before GCM, and before key lookup/HKDF in the
convenience path. UTF-8 plaintext size is counted before its allocation. Errors
are sanitized `Error` objects: `INVALID_ENCODING`, `INVALID_IV`,
`INVALID_CIPHERTEXT`, `INVALID_TEXT` or `INPUT_TOO_LARGE`. No bytes, text or keys
are copied into messages. Convenience options allow only `contextID`; custom
IVs, random sources and key-ID aliases reject with `INVALID_OPTIONS`. No production
encryption API accepts a caller IV. Deterministic IVs occur only in native test
fixtures, not through mocked cryptographic primitives.

## Persistent usage budget

The budget is a conservative engine policy based on the IV uniqueness and
invocation constraints of [NIST SP 800-38D, sections 5.2.1, 8.2.2 and
8.3](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf).
Its random-IV ceiling is `2^32` invocations per key; this profile chooses `2^16`.
For independent uniformly random 96-bit nonces, the union/birthday bound is
`q(q-1)/2^97`, below `2^-65` at our ceiling. It is a probability bound, not
absolute collision freedom. The 16 MiB message cap is far below GCM's
`2^36 - 32` byte plaintext limit. The additional `2^24`-block lifetime cap is a
conservative engineering choice to limit aggregate GHASH input, not a claim of
full 256-bit authentication security. Full 128-bit tags are always required.

Each operation reserves `ceil(plaintextBytes / 16) + 1` GHASH blocks: ciphertext
blocks plus the mandatory length block. Current helpers have no AAD; a future
AAD envelope must include its additional blocks in the accounting. Reservations
are counted even if a subsequent GCM operation fails; they are never refunded.
Validation failures occurring before a reservation consume nothing. These
counters account for encryption; reading ciphertext does not consume encryption
capacity or establish a verification-attempt limit.

All convenience encryption and engine helper encryption with a v2 key created
or re-derived by that same engine reserve capacity atomically in native IndexedDB
**before nonce generation or GCM**. The promise waits for transaction commit.
Exhaustion rejects with `KEY_USAGE_EXHAUSTED`; invalid persisted counters reject
with `INVALID_USAGE_STATE`. Native write/abort failures reject rather than return
ciphertext. Concurrent instances/connections are serialized under the same
write lock. Re-deriving a CryptoKey, reloading an engine or changing a storage
namespace does not reset the budget.

The actual derivation identity is canonical Base64url SHA-256 of this byte
sequence: ASCII `BE8-GCM-USAGE` (13 bytes), the 32 raw salt bytes, then the complete
`encodeV2DerivationInfo()` result. Fingerprints have already been verified against
the actual keys before registration. Identity thus includes all key-selecting
HKDF inputs and purposes; its equality relies on the hash/KDF's collision
resistance. There is no independently selectable `keyId`. Changing a genuine KDF
input derives a different key and legitimately starts a different budget.

The application must increment its own IndexedDB version and invoke
`upgradeBe8Schema()` in its upgrade handler to add `be8.keyUsage`. Its primary key
is `derivationID`; records contain only that hash and numeric `encryptions` and
`blocks`. It has no namespace index: the same actual derivation shares one budget
throughout this database, including namespace aliases. No identity or ciphertext
is rewritten by the upgrade. Encryption with a registered key before integration
rejects with `SCHEMA_UPGRADE_REQUIRED`; there is no implicit upgrade or volatile
counter fallback. `panic()` retains these security counters to prevent resetting
retained derivations. Records are not automatically garbage-collected.

This is coordination **within one application-owned database**. Applications
must not restore counters backwards, selectively delete them, or copy the same
identity/context to independent databases and expect global accounting. Native
commit signals are not guarantees against every storage or power-loss rollback.

### Low-level caller responsibilities

Raw AES keys supplied by the caller, transferred/cloned CryptoKeys, and direct
WebCrypto calls have no engine-owned derivation registration. The raw byte/text/
image helpers still generate 96-bit random nonces and validate sizes/encoding,
and require non-extractable AES-256-GCM keys with the appropriate native usages,
but cannot identify such keys across arbitrary native clones or maintain their
usage state. The caller must enforce the same per-actual-key invocation/block
limits across all writers and ensure nonce discipline. A key obtained from a
different engine does not transfer its registration. Engine-created keys used
outside their originating engine likewise require caller accounting. Native
key wrapping/unwrapping remains a low-level operation: use purpose `key-wrap`,
96-bit nonces and `tagLength: 128`, with caller-owned limits. No counter guarantee
is claimed for direct native operations or copied databases.

## Envelope integration status and limits

Persist and transfer the entire public `derivation` object alongside the encrypted
payload and IV. It provides the exact salt and KDF metadata needed for the later
authenticated v2 envelope. This change does not serialize such an envelope or
authenticate an envelope header as AES-GCM AAD. Changing a KDF field changes the
key and causes native authentication failure, but that does not implement header
canonicalization, envelope validation, or replay state.

The new binary/Base64url representation and nonce rules above apply to all new
engine payloads. No automatic envelope/profile detection is provided. The
authenticated envelope, header/AAD canonicalization and replay state remain
outside these helpers.

Malicious JavaScript in the same execution context can still misuse stored
CryptoKeys or invoke engine operations. Non-extractable does not mean XSS-safe
or hardware-protected. Fingerprints taken from the same unconfirmed source as
the key do not independently verify identity. This work is not a security audit.

## Verification

`test/v2.mjs` checks RFC 5869 SHA-256 vectors A.1/A.2/A.3 through native AES
interoperability with non-extractable keys, plus a fixed independent Node/OpenSSL
P-384/HKDF/AES-GCM vector covering the full 48-byte ECDH output and exact Unicode
field encoding. Other tests cover independently stored participant identities,
fresh/reused salt, changed salt/context/direction/purpose, actual fingerprints,
wrapping separation/usages, strict metadata, explicit legacy reads, and retained
old `deriveKey`-only identities. Migration tests verify that a historical UUID
packet is rejected before v2 crypto, with no legacy retry. Integration key equality is
established through successful decryption; derived key export remains disabled.
`test/encoding.mjs` covers binary 0x00/0xff and offset/large array roundtrips,
native fixed binary IV fixtures, Unicode/BOM, image text over 2 MiB, strict
Base64url/IV/tag/size validation, input snapshots, and persistent count/block
exhaustion across re-derivation, reload, concurrent connections and namespace
aliases. Native transaction abort and unique-index write errors verify rollback;
schema upgrade and explicit legacy-format reads are also covered.
