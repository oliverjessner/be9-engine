# Migration to authenticated sessions and signed groups

The application increments its **own** IndexedDB version and invokes
`upgradeBe9Schema(db, versionchangeTransaction)` in `onupgradeneeded`. This adds
six scoped stores and the required indexes, validating existing definitions:
`be9.signingKeys`, `be9.signingTrust`, `be9.sessionRegistry`, `be9.sessions`,
`be9.ratchetState`, `be9.skippedKeys`. Existing engine/application records and
CryptoKeys remain; databases are never replaced/deleted. Native upgrade abort
rolls back all schema changes. Missing integration fails closed; no JWK fallback.

Existing ECDH identities, trusted public keys, v2 replay/usage counters, epochs
and explicit Be8 readers are preserved. `migrateBe8Schema()` retains its eleven
historical mappings and also integrates the new stores. Legacy private JWK
migration remains explicit `migratePrivateKeys()`. It does not mint signing keys
from old ECDH scalars or upgrade unknown trust records.

After setup, explicitly call `setupSigningIdentity()`, exchange **public** signing
keys and independently confirm their fingerprints/ECDH bindings. Existing
unverified keys remain unverified. Call `createSession`/`acceptSession`/
`finishSession` for fresh cryptographic sessions; new session writers always use
suite 3 per-message keys. There is no conversion of a static v2 context into a
ratchet session. Applications must retain bootstrap IDs/contexts independently
for receiver expectations. All private keys stay local.

## Public API choices

| Use | Recommended API |
| --- | --- |
| New session bootstrap | `createSession`, `acceptSession`, `finishSession` |
| Pairwise send | `encryptRatchetEnvelope`, `encryptRatchetText`, `encryptRatchetImage` |
| Pairwise live acceptance | `receiveRatchetEnvelope`, `receiveRatchetText`, `receiveRatchetImage` |
| Session inspection/destruction | `getSession` (metadata only), `closeSession` |
| Group send | `encryptSignedGroupEnvelope/Text/Image` |
| Group expected live stream | `openReceiveSignedGroupContext` |
| Group live acceptance | `receiveSignedGroupEnvelope/Text/Image` |
| Signed group archive | `decryptArchivedSignedGroupEnvelope/Text/Image` |
| Existing static v2 archive | `decryptArchivedEnvelope/Text/Image` |
| Existing unsigned group archive | `decryptArchivedGroupEnvelope/Text/Image` |
| Be8/unframed/UUID/direct-ECDH archive | Existing explicitly named Be8/Legacy readers |

Old `decryptEnvelope`, `decryptTextSimple`, `decryptImageSimple`, `decryptGroup*`
and raw AES decryption remain compatibility archive/low-level operations; they
are deprecated for live receipt, with **no hidden semantic change**. Old v2
`encrypt*Simple`/`encryptEnvelope` and unsigned `encryptGroup*` are retained for
explicit static-profile compatibility; they do not gain forward secrecy or
individual group authorship. Existing `receive*`/`receiveGroup*` retain v2 replay
semantics and do not verify the new signatures. Prefer the explicit new signed
methods. No overload autodetects protocol from network fields.

Archives can be repeatedly decrypted; live methods consume acceptance state.
There is no ratchet archive API or secret-export workaround. Retain old encrypted
data and use its explicit profile reader; do not rewrite authenticated headers.

## Lifecycle and storage ownership

| New store | `panic()` / explicit close policy |
| --- | --- |
| signingKeys | Delete local public/private pair on panic; explicit new lifecycle required |
| signingTrust | Delete local peer signing decisions on panic; reconfirm independently |
| sessions | Delete on panic; replace with metadata-only closed row on close |
| ratchetState | Delete on panic/close, including old chains and DH private |
| skippedKeys | Delete on panic/close; single-use delete on normal acceptance |
| sessionRegistry | Retain on panic/close; mark sessions closed, retain revisions/tags and signing generation/status marker |

The signing marker is set to `invalidated` by committed panic; a new signer
requires that explicit marker plus a newer active namespace generation. Missing,
malformed or future markers never authorize generation of replacement keys.
If a signer and its marker are both absent but any session/ratchet/skipped/registry
footprint remains, initialization also fails closed instead of pretending first use.

The existing namespace lifecycle tombstone and actual-key GCM usage counters
remain. Group sender sequence/replay state lives in existing scoped stores and
is removed on panic under that generation's identity invalidation; global usage
reservations are retained. New signing/session identity is created only after
explicit `reinitialize()` and signing setup. Retained session IDs never restart.

`SESSION_NOT_FOUND` differs from `SESSION_STATE_LOST`; `RATCHET_STATE_LOST` covers
missing/damaged chain, skipped or DH state. Other stable errors include
`SESSION_ALREADY_EXISTS`, `SESSION_CLOSED`, `SESSION_NOT_READY`,
`SESSION_IDENTITY_MISMATCH`, `SESSION_BOOTSTRAP_INVALID`, `INVALID_SIGNATURE`,
`UNTRUSTED_SIGNING_KEY`, `SIGNING_STATE_LOST`, `RATCHET_MESSAGE_TOO_FAR`,
`SKIPPED_KEY_LIMIT`, `RATCHET_LIMIT`, `RATCHET_DUPLICATE`, `RATCHET_CONFLICT`,
`SESSION_LIMIT`, `CRYPTO_OPERATION_FAILED`, `AUTHENTICATION_FAILED`, `SCHEMA_UPGRADE_REQUIRED` and existing
persistence/lifecycle/trust errors. Messages contain no raw keys, plaintext,
header values or native error details. Failures never trigger a Legacy fallback.
