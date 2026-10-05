# Authenticated session bootstrap (profile 3)

A session is local cryptographic state, separate from accounts, conversations and
transport. Applications supply account IDs, public keys, trust decisions, context
and independently retained expectations. No transport or server directory exists.

Each identity has two **independently generated** P-384 pairs: existing ECDH and
new ECDSA. Signing private keys are non-extractable CryptoKeys with only `sign`;
public keys use `verify`. ECDH ratchet private keys permit only `deriveBits`.
Signing public JWK validation requires EC/P-384, native point validation, canonical
48-byte coordinates, no private members, `use: sig`/`alg: ES384` if present, and
only public verification usages. Thumbprints follow RFC 7638's four required EC
members. Account or trust metadata is excluded.

`setupSigningIdentity()` explicitly creates this separate pair after `setup()`.
It is idempotent across connections. A retained `@signing` registry marker makes
missing private records an error rather than a trigger for a new identity.
`getSigningPublicKey()` returns `{ publicKey, fingerprint, identityFingerprint }`.
No private signing, ratchet, chain, root or message-key getter exists.

Peer ECDH and signing keys must each be `confirmed` or explicitly first-contact
`tofu`. `addSigningPublicKey(peer, publicJWK, decision)` takes a **separate local**
argument `{ identityFingerprint, expectedFingerprint?, trust?, tofu? }`. Without
a signing decision the record stays `unverified`. A network `verified: true`
never supplies trust. A fingerprint from the same unconfirmed source as its key
is not independent identity verification. No verification UI is supplied.

Replacement is explicit compare-and-swap:
`replaceSigningPublicKey(peer, publicJWK, { expectedPreviousFingerprint,
confirmedNewFingerprint, identityFingerprint })`.
`rotateSigningIdentity({ expectedPreviousFingerprint })` changes the local signer
only after native commit; the application must separately confirm its public key
at peers. Sessions are permanently bound to **both** identities' actual ECDH and
signing fingerprints. Current local/peer trust and key points are rechecked at
commit. Replacement causes bound sessions to fail closed; close them explicitly
and establish fresh sessions. There is no automatic rebind or reset.

## Exchange

1. Initiator calls `createSession(peer, { contextID })`. This generates a random
   32-byte session ID and generation plus fresh non-extractable ratchet pair A0.
   A signed offer is returned **after** pending state commits.
2. Responder calls `acceptSession(offer, expected)`. It checks schema, independent
   expectations, both locally trusted fingerprints, then ECDSA signature. It
   generates fresh pair B0 and returns a signed answer after active state commits.
3. Initiator calls `finishSession(answer, expectedReverse)`. It checks signature,
   reversed account/fingerprint bindings, generation, context, ID and offer hash;
   derives the shared initial root and replaces A0 with fresh A1 atomically.
4. Initiator sends first. Responder cannot send before receiving that first
   authenticated A1 message (`SESSION_NOT_READY`). Its first receive establishes
   its sending chain. Thereafter both directions can send independently.

This is an interactive two-message bootstrap, not a prekey/server protocol.
Applications may exchange packets directly; the engine never sends them.
Lost answers require an explicit fresh session, not an implicit retry/reset.
Replayed offers/answers cannot replace existing state or reuse a retired ID.
There is no handshake timeout/clock dependency; explicitly close unused pending
sessions to free active-session capacity.

## Exact binary format

All domains are literal ASCII, followed by uint32 big-endian length-prefixed
fields using existing `encodeFields()`. UTF-8 has no normalization and rejects
lone surrogates. Digests/IDs are canonical unpadded Base64url on wire, raw 32 bytes
in binary fields. Version is one byte `03`. Counters are uint64 big-endian.

Both headers have the exact fields, in this ordered binary encoding:

`version, suite, sessionID, contextID, sender, receiver,
senderIdentityFingerprint, receiverIdentityFingerprint,
senderSigningFingerprint, receiverSigningFingerprint, generation,
ratchetPublicKey`.

Suite is `BE9-RATCHET-P384-HKDF-SHA256-A256GCM`. Accounts are canonical decimal
strings (maximum 256 UTF-8 bytes). Context is nonempty, maximum 1024 UTF-8 bytes.
`ratchetPublicKey` is exactly `{ kty, crv, x, y }`, encoded under
`BE9-P384-PUBLIC` as length-prefixed `EC`, `P-384`, raw x and y (48 bytes each).

Offer signature input is `BE9-SESSION-OFFER` with the ordered fields above.
Answer swaps sender/receiver and both ordered identity fingerprints, keeps
session/context/generation, replaces the point with B0, and appends `offerHash`:
SHA-256 of canonical offer bytes **excluding signature**. Answer signature input
uses `BE9-SESSION-ANSWER`. ECDSA uses SHA-384; wire signature is the native
96-byte P1363 r||s encoded as canonical Base64url. No arbitrary JSON object is
signed. Signature bytes are not used as session identity (ECDSA malleability).

`{ header, signature }` is the exact bootstrap packet. Extra fields, accessors,
symbols and incorrect signatures reject. There is no wire-controlled suite
selection. Independent expectations are exactly
`{ sender, receiver, sessionID, contextID }`. Passing the entire header rejects.
The engine cannot infer whether a caller copied those four values from untrusted
input; provenance is the application's responsibility.

The initial transcript digest is SHA-256 of `BE9-RATCHET-SESSION` with canonical
offer bytes and canonical answer bytes as two length-prefixed fields. Initial
root: HKDF-SHA-256 with full 48-byte ECDH(A0,B0) as IKM, transcript digest as salt,
`BE9-RATCHET-SESSION-ROOT` with the raw transcript digest as info, output 32 bytes.
The output is imported as a non-extractable HKDF key. Static identity ECDH is
**not** an input to ratchet message derivation.
