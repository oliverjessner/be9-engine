# Local namespace invalidation

Existing `be8.*` databases require [explicit schema migration](be9-migration.md)
before using Be9. That migration preserves these lifecycle boundaries.

`panic()` immediately locks the calling engine, drops opaque references and
engine derivation registrations, and aborts its still-open native transactions.
No new engine operation is accepted; key/trust getters, setup, raw AES and legacy readers are
also guarded. In-flight results are checked against a local lifecycle token and
the persisted namespace generation before output. Pending initialization/import
cannot schedule new writes after lock; pending native WebCrypto may finish,
but its result is discarded. Temporary byte outputs are overwritten best-effort
when possible. Immutable JS strings, native copies and garbage collection cannot
be reliably erased. The engine has no retained private/group key cache.

A single committed native transaction deletes selected namespace public/private
keys, trust, retained scoped ECDH group records, symmetric group epochs and active
selection, contexts, send counters and replay windows. It writes a tombstone to
`be9.scopes`: `{ namespace, accID, status: 'invalidated', generation }`.
The permanent owner binding is retained. Generation is an integer from 0 through
`Number.MAX_SAFE_INTEGER`, advancing on panic and explicit reinitialization;
exhaustion fails closed. Existing scope records without lifecycle fields are
interpreted as active generation 0, retaining their identity and trust. A bound
instance refuses a missing/invalid lifecycle record instead of resetting it.

Deletion success is reported only after native `complete`. Errors/aborts reject
and leave the calling instance locked. Known live same-generation instances in
the same JS realm are synchronously locked through weak registrations and release
references too; if deletion fails they conservatively remain locked. Failure does
not claim a persistent tombstone: restart can see the retained pre-abort records.
Explicitly retry panic to complete deletion. Repeated pending/successful calls
share the same promise and are idempotent. After failure, the next panic retries
storage while preserving the local lock. A wrong account cannot invalidate or
notify the true namespace owner.

Across separate realms/tabs/connections, persisted generations are authoritative:
each scoped read/write checks owner/status/generation, raw crypto checks before
invocation, and every public async result checks again before release. Stale
instances do not adopt a newly active generation. A stale panic cannot delete a
newer identity. Other realms cannot be synchronously notified without separate
local coordination; native operations already running there may complete, but
persisted checks prevent subsequent stale result release. Coordination is
limited to the same application database and retained lifecycle state.

After successful panic, `setup()`/generation cannot silently create another
identity, including after restart. Explicitly call `reinitialize()` to create a
new non-extractable identity outside the transaction and atomically replace the
matching invalidated generation. Parallel calls on one instance coalesce;
competing instances cannot both replace the same tombstone. The requesting
instance resumes only after commit, clears its prior panic promise, and must
explicitly reinstall peer keys/trust and establish fresh contexts/epochs.
Old instances/references stay invalid. Calling panic during reinitialization
invalidates its token and aborts pending candidate writes.

```js
await engine.panic();       // Immediately locked, success means deletion committed.
// engine.setup() still rejects ENGINE_LOCKED; no implicit new identity.
// At the application's explicit later decision:
await engine.reinitialize(); // New identity, new generation, empty peer trust.
```

Panic never deletes a database, schema, application store, another namespace, or
unselected unscoped legacy data. Database-wide `be9.keyUsage` reservations are
retained deliberately: namespaces/aliases can refer to the same actual key, so
clearing them would refund another writer's security budget. They contain only
public derivation hashes/counts, no key material. They are not automatically
collected. Their retention is part of the per-actual-key budget contract.

This is logical deletion and invalidation within the engine's responsibility.
There is no guarantee of physical overwrite, removal from browser/application
backups, storage snapshots, restored databases, already copied CryptoKeys or
secrets, or forensic recovery. Direct native use of an already-held CryptoKey
remains outside engine control. Malicious JavaScript in the same context can
bypass engine logic/use stored keys; non-extractable is neither XSS-safe nor
hardware-protected. No wrapping-key erasure claim, complete security claim or
passed audit is made.

## Profile 3 state

Signing, session, ratchet and skipped-key records participate in the same native
namespace-generation invalidation. Session registry rows are retained and marked
closed; the signing-generation marker survives. They cannot be blanket-deleted
with operational state. See the exact [delete/retain policy](ratchet-migration.md#lifecycle-and-storage-ownership).
