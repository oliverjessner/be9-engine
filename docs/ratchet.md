# Pairwise ratchet profile 3

This is a documented Be9 profile using native WebCrypto, not an implementation
claim of Signal interoperability. The DH/symmetric state-machine order follows
the [Double Ratchet specification, sections 2–3](https://signal.org/docs/specifications/doubleratchet/).
Its KDF instantiation below differs, including a reversed root salt/IKM placement
that keeps the previous root as a non-extractable CryptoKey. It requires external
cryptographic review. HKDF primitives are native SHA-256 per
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869).

## State and derivation

Active state contains a non-extractable root HKDF CryptoKey, local fresh P-384
ECDH ratchet pair, remote public point/fingerprint, sending/receiving HKDF chains,
Ns/Nr/PN counters, remote PN, bounded skipped-key inventory, retired remote point
fingerprints, transcript digest, revision and state authentication tag. Chains
and roots permit only `deriveBits`/`deriveKey`. Skipped seeds permit `deriveKey`
only. No consumed message key or previous chain/root/private ratchet pair is
persisted. Best-effort zeroing of temporary raw secrets is not guaranteed memory
or disk erasure; WebCrypto/browser copies remain outside engine control.

All KDFs use HKDF-SHA-256 with the binary length-prefix codec documented in
[bootstrap](session-bootstrap.md). A zero salt means 32 literal zero bytes.

* **Root step:** IKM = previous non-extractable root, salt = full fresh 48-byte
  ECDH output; info = `BE9-RATCHET-ROOT` with raw transcript digest; 64-byte output
  split into next root (first 32) and new chain (last 32). Both are imported as
  non-extractable HKDF keys; the temporary output and DH bytes are nulled.
* **Chain step:** IKM = current chain, zero salt; info = `BE9-RATCHET-CHAIN` with
  transcript digest; 64-byte output split into next chain and one message seed.
  Import both non-extractably and null output bytes. There is no backward API.
* **Message key:** IKM = seed, zero salt; info = `BE9-RATCHET-MESSAGE` containing
  transcript digest, the ordered binding fields of the header (version through
  generation), encoded ratchet public point, PN, message number and purpose.
  Derive non-extractable AES-256-GCM with only `encrypt` **or** `decrypt`.
  `data` and `attachment` are distinct; key-wrap is not a ratchet purpose.

Each sender uses a seed once, regardless of application aliases or purposes.
Every message key has one engine encryption invocation, a fresh random 96-bit
IV and explicit 128-bit GCM tag. The 16 MiB plaintext limit and 4096-byte AAD limit
are far below GCM's per-invocation limits. There is no keyId/budget-reset input.
Random IVs are probabilistic; no absolute collision guarantee is asserted.

The bootstrap initializes Bob with R0, B0, remote A0 and no chains; Alice with
fresh A1, remote B0, R1 and sending chain from RootStep(R0,DH(A1,B0)).
When a **new** remote point arrives:

1. Save skipped keys through incoming PN in the old receive chain, within bounds.
2. Retire the old remote fingerprint. Save local Ns as PN; set Ns/Nr to zero.
3. Mix DH(current local private, new remote point) into root; set receive chain.
4. Generate a fresh local non-extractable ratchet pair.
5. Mix DH(new local private, remote point) into root; set send chain.
6. Advance receiving chain to incoming message number; authenticate GCM.
7. Commit the proposed root, chains, DH pair, counters, skipped changes and revision
   together. On authentication failure none of these changes persist.

On ordinary receive in the same chain PN must match the chain's authenticated
PN. Missing numbers become skipped seeds. Receiving a skipped key removes it
in the same acceptance commit. Consumed/retired numbers reject as duplicates.
Counters start at zero and are canonical uint64 decimal strings; exhaustion
requires an explicit fresh session.

## Envelope and replay

Exact header: all bootstrap binding fields (version through generation),
`ratchetPublicKey, previousChainLength, messageNumber, purpose, iv`.
`{ header, ciphertext }` is the only packet shape. IV is exactly 12 bytes;
ciphertext is canonical unpadded Base64url, at least 16 bytes (tag) and at most
16 MiB + 16. AAD is `BE9-RATCHET-AAD` with the ordered binding fields, encoded
point, PN, number, purpose and raw IV. All fields enter AAD, including both
signing fingerprints, generation, direction and context.

Live expectations are exactly
`{ sender, receiver, sessionID, contextID, purpose }`, from independent application
state. A whole header rejects. Removing extra fields from untrusted data does
not make it independent; the engine cannot establish caller provenance.

Ratchet sessions do not use the v2 128-bit replay window: persisted chain
advancement plus atomically deleted skipped seeds provides acceptance tracking.
Registry tombstones prohibit ID reuse; revisions prevent concurrent double use.
Existing v2/Be8 replay stores and semantics remain intact. There is **no** ratchet
archive decrypt method: past keys have been consumed. Applications choose their
own plaintext archival policy outside this engine. This adds no message history.

## Persistence, corruption and crash behavior

Read a committed native snapshot, perform all WebCrypto **outside** transactions,
then compare-and-swap revision and state tag in a new native write transaction.
Recheck current identity/trust bindings under the same lock. Commit success
means native `complete`, never request `success`. Up to 32 conflict retries use
fresh snapshots; exhaustion fails with `RATCHET_CONFLICT`, never a volatile lock.
This works across engine objects, database connections and browser realms using
the same database. No await of crypto/timers/services occurs inside transactions.

Send commits next chain/number **before** GCM; any later error or crash burns the
step. No refund. Receive authenticates and validates text first, then commits;
plaintext is returned only after commit and lifecycle checks. A crash after
acceptance but before application processing is not exactly-once application
execution. No engine retries application actions.

A root-derived HMAC-SHA-256 authenticates namespace/peer/local role/status and public state/counters/points/revision/
transcript, ordered skipped inventory and independently derived chain/seed
commitments. Domains are `BE9-RATCHET-STATE-AUTH`, `BE9-RATCHET-STATE`,
`BE9-RATCHET-STATE-SEND`, `BE9-RATCHET-STATE-RECEIVE`,
`BE9-RATCHET-STATE-SEED`, `BE9-STATE-COMMITMENT`,
`BE9-RATCHET-STATE-SKIP`, `BE9-RATCHET-RETIRED`, `BE9-RATCHET-INVENTORY`.
A fresh native DH challenge checks functional ECDH consistency of local private
and public keys. ECDH returns an x-coordinate and does not distinguish a point
from its negation; the exact stored public representation is additionally bound
by the state MAC and signed bootstrap. This is not an export or proof of the
private scalar's canonical public y-coordinate.
Registry revision/tag and inventory must agree. Missing session, chain, seed,
registry or valid-looking changed counters reject; no automatic initialization.
The tag is corruption detection, **not** trusted monotonic storage: an attacker
with JS/key access can recompute it, and a complete consistent snapshot rollback
cannot be detected. Restoring/copying active state risks key/nonce reuse.

## Hard limits

Exported `SESSION_LIMITS` centralizes new limits:

| Limit | Value |
| --- | ---: |
| Active + pending sessions per namespace | 32 |
| Lifetime registry rows, including signing marker | 1024 |
| Skipped seeds per session | 64 |
| Maximum receive number gap (per chain transition) | 64 |
| DH receive transitions / retained remote fingerprints | 128 |
| CAS attempts per operation | 32 |
| Group recipients per encrypted handoff | 256 |
| Canonical authenticated header | 4096 bytes |
| Streams per static/signed group context | 1024 |
| Context | 1024 UTF-8 bytes |
| Ciphertext | 16 MiB + 16 bytes |

Unused skipped seeds remain until consumed or explicit session close/panic; the
engine never silently evicts them to make a forged header pass. Thus compromise
can reveal up to 64 pending messages. There is no clock-based expiry. Close old
sessions and create fresh ones explicitly when limits are reached. Lifetime
registry limits deliberately require a new application namespace once exhausted;
no automatic tombstone garbage collection may reset safety boundaries.

## Security assumptions

Forward secrecy relies on old state disposal and absence of external snapshots.
Identity ECDH compromise alone does not reconstruct session DH/root/message keys.
State compromise exposes current chains and queued skipped seeds. Symmetric
advancement alone cannot recover confidentiality. Recovery needs **both** peers
to contribute fresh DH material unknown to an attacker who has ceased access;
the next exchange alone may still depend on a stolen private ratchet key. Active
interception, continued JS access, stolen signing keys, lost peer messages, storage
rollback and retained browser/backup copies limit or defeat these properties.
This profile has no post-quantum guarantee, secure enclave or external audit.

Verification includes an independent Node/OpenSSL full-width P-384/root/chain/
message AES-GCM vector; its canonical AAD digest was independently reproduced
with Python length-prefix/uint64 encoding. Native integration tests keep all
private and derived keys local to each participant.
