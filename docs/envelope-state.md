# v2 envelope and local security state

This page specifies the Be9 profile. Retained Be8 packets require the explicitly
named readers and database migration in [Be9 migration](be9-migration.md).

New convenience encryption returns `{ header, ciphertext }`, not the old
ciphertext/IV/derivation tuple. `encryptEnvelope(sender, receiver, bytes,
{ contextID, purpose })` handles bytes; text/image Simple APIs are thin text
adapters. Ciphertext is canonical Base64url including the 128-bit GCM tag.

Envelope/header/group fields must be own enumerable data properties; accessors,
symbol/extra fields and missing fields reject without invoking accessors.
The header has exactly twelve fields: the nine v2 derivation fields documented
in `v2-profile.md`, plus `iv` (12 bytes as Base64url), `sequence` (canonical
positive decimal unsigned 64-bit string), and `group` (null for pairwise data).
For internal key transfer, group metadata is exactly `{ groupID, epoch,
generation }`; epoch is a positive unsigned 64-bit decimal string, generation a
32-byte digest in Base64url. Header schema, purposes, suite/version, lengths and
ciphertext limits reject before key derivation.

AAD uses the same `encodeFields(domain, byteFields)` codec as HKDF: ASCII domain
prefix followed by ordered uint32-BE length-prefixed byte fields. For envelope
AAD the domain is `BE9-ENVELOPE-AAD`, followed by complete HKDF-info bytes, raw
32-byte salt, raw 12-byte IV, 8-byte big-endian sequence, group marker, group ID,
8-byte group epoch and raw generation digest (empty fields for null group).
Every header field is bound. AAD provides integrity, not metadata secrecy.
GHASH reservations include ciphertext, AAD and the final length block.

`decryptEnvelope(envelope, { sender, receiver, contextID, purpose })` requires
independent expectations. It checks the local private endpoint and persisted
peer trust, never selects algorithms from untrusted headers and never retries
other formats or keys. It is a repeatable archive operation. Text/image Simple
readers take `(sender, receiver, envelope, { contextID })`; specify the expected
context from application state. Omitting the optional context accepts any
context, while endpoints, actual fingerprints and purpose remain independently
checked. Do not copy all expectations from the received header.

Retained pre-envelope HKDF packets have explicit
`decryptTextUnframedLegacy()` / `decryptImageUnframedLegacy()` readers. Historical
UUID/direct-ECDH readers remain separately explicit. Neither is an automatic
fallback. Raw AES helpers remain low-level APIs with caller-owned trust/context
and usage responsibilities.

## Send and receive state

`openContext(contextID)` explicitly creates/reopens an open local context;
`closeContext(contextID)` permanently closes that ID, retaining tombstones and
stream bindings. Reopening a closed ID rejects; choose a fresh ID. Envelope
sending with an application context requires it to be open. Simple sending
without a context chooses a fresh random context ID and initializes that new
context, rather than resuming an old one.

Before envelope encryption, a native committed reservation assigns the next
positive uint64 sequence. No Number conversion occurs; 18446744073709551615 is
usable once and then `COUNTER_EXHAUSTED` rejects. Failed encryption may burn a
sequence; it never refunds it. Send states bind namespace, context, ordered
endpoints, actual fingerprints, suite/purpose and structured group generation.
Salt is deliberately excluded from stream identity so per-packet salt changes
cannot reset sequences. Stream identity uses the common length-prefix codec
with domain `BE9-REPLAY-STREAM` and SHA-256 of those public fields.

`openReceiveContext({ sender, receiver, contextID, purpose })` initializes the
expected stream using actual trusted peer and local public fingerprints, not
values taken from a received packet. `receiveEnvelope()`, `receiveText()` and
`receiveImage()` authenticate first, then atomically check/update a 128-packet
sliding window, and only release output after commit. Text validation also
precedes acceptance. Duplicate sequences reject with `REPLAY_DUPLICATE`;
distance 128 or more behind the highest rejects with `REPLAY_TOO_OLD`. State
stores only a highest uint64 and fixed 128-bit bitmap, never packet contents.
Parallel connections cannot both commit acceptance of the same packet.

`decryptEnvelope()` and Simple decryptors remain repeatable archive reads;
they do not change replay state and work on closed contexts. Unknown receive
streams reject with `STREAM_NOT_OPEN`; unopened contexts reject with
`CONTEXT_NOT_OPEN`. An explicit bounded registry (at most 1024 send/receive
bindings per context) detects missing counter/window rows and rejects with
`STATE_LOST`, including attempted reinitialization. Invalid state fails closed.

Applications integrate `be9.contexts`, `be9.sendState`, `be9.receiveState` through
their own schema upgrade. A complete database/registry loss cannot be
cryptographically distinguished from a new installation: do not resume old
context IDs after loss; establish fresh contexts independently. Selective
resets and storage rollback undermine this state. A crash after acceptance
commit but before an application action may make a packet non-receivable again;
no exactly-once guarantee for downstream actions is claimed. There are no
network retries, delivery statuses, receipts or message-history stores.
