# Be8 v2 derivation profile

This specifies the implemented KDF and its public metadata for protocol version
`2`, suite `BE8-P384-HKDF-SHA256-A256GCM`. It is one v2 profile, not a menu of
automatically detected algorithms. Unsupported versions/suites reject. The
authenticated v2 envelope and its nonce rules are still to be specified and
implemented; these helpers do not claim to implement that envelope.

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
const text = await bob.decryptText(key, oldCipherText, oldIV);
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

## Envelope integration status and limits

Persist and transfer the entire public `derivation` object alongside the encrypted
payload and IV. It provides the exact salt and KDF metadata needed for the later
authenticated v2 envelope. This change does not serialize such an envelope or
authenticate an envelope header as AES-GCM AAD. Changing a KDF field changes the
key and causes native authentication failure, but that does not implement header
canonicalization, envelope validation, or replay state.

The raw text/image AES helpers retain their existing payload representation and
UUID-based IV encoding; they are profile-neutral primitives, not the finalized
v2 nonce/envelope contract. No automatic envelope/profile detection is provided.

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
old `deriveKey`-only identities. Migration tests verify that a readable historical
ciphertext still fails under v2, with no legacy retry. Integration key equality is
established through successful decryption; derived key export remains disabled.
