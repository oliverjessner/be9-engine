# Security properties and boundaries

Properties below describe implemented mechanisms under intact application-owned
storage and independent local trust. Native browser tests exercise specified
attacks; they do not establish a complete security proof or passed audit.

| Property | Pairwise ratchet (3) | Signed group (3) | Static v2 / explicit legacy |
| --- | --- | --- | --- |
| Confidentiality | Per-message AES-GCM keys | Epoch secret + purpose/sender KDF | Static identity-derived or epoch keys |
| Integrity | Full header AAD and GCM | Full header/ciphertext signature + GCM | v2 AAD/GCM; older unframed data lacks header AAD |
| Peer authentication | Locally trusted separate signers authenticate bootstrap | Local ECDH + signing trust, encrypted epoch handoff | Local ECDH trust on supported convenience paths |
| Sender authentication | Pairwise authenticated session; either endpoint can simulate transcripts | ECDSA signature from locally trusted sender | Pairwise shared-key; unsigned group holders can forge authorship |
| Forward secrecy | Consumed prior message material disposed; bounded skipped-key exception | None for a retained epoch secret | None for static ECDH/epoch secrets |
| Post-compromise recovery | Fresh DH exchange after attacker stops access, under stated conditions | None within an epoch; explicit fresh secret distribution needed | None within static key context |
| Replay protection | Atomic chain progression + single-use skipped seeds | Persistent 128-packet window on live receive | v2/Be8 live window; archive readers repeatable |
| Out-of-order | Up to 64 skipped seeds across bounded DH chains | Live window 128; archive repeatable | Live window 128 where available |

## Compromise matrix

| Compromise | Consequence |
| --- | --- |
| Identity ECDH private | Static pairwise archive keys can be reconstructed from public metadata; recorded old epoch handoffs can expose epochs; active v2 key-handoff forgery under that ECDH identity also becomes possible. Does not alone derive independently bootstrapped ratchet keys. New bootstrap still requires trusted signing identity. |
| Identity signing private | Forge bootstrap/group authorship for that identity; active session takeover through new explicitly accepted bootstrap becomes possible. Does not alone reconstruct prior ratchet or group AES keys. Rotate/reconfirm trust and replace affected sessions explicitly. |
| Current ratchet state | Current/future symmetric chains and pending skipped seeds exposed. Disposed prior chains/messages remain separated absent snapshots. Recovery requires fresh uncompromised DH from both endpoints and termination of active access/interception. |
| Group epoch secret | Every ciphertext/key-purpose in that epoch can be decrypted and GCM data fabricated; recipient-specific encrypted wrapping must also be considered. Signed messages still need the claimed sender's signing key. |
| Group sender signing private | Claimed sender authorship can be forged; signature compromise alone does not reveal the epoch secret. Holders with both can fabricate fully valid messages. |

A new group epoch only excludes a peer from **future** secrets. It cannot erase
knowledge of previously shared secrets, prevent an included participant from
sharing them, or provide retrospective revocation. Signed live receive requires
an independently expected **active** epoch; old signed epochs remain explicit
archives. Existing unsigned group APIs retain their old semantics and are
obsolete for authenticated authorship.

Malicious JavaScript in the same execution context can read/use stored CryptoKeys
and invoke signing/decryption despite non-extractability. Non-extractable does
not mean XSS-safe, hardware protected or physically uneraseable. Browser IndexedDB
is not secure monotonic storage or a secure enclave. Rollback, restoring backups,
or copying active cryptographic state to another database can invalidate nonce,
usage, replay and forward-secrecy assumptions. Native commit events are not a
universal power-loss durability guarantee. No secure disk/memory erasure is claimed.

Independent expectations are application decisions, not data taken from the
message. Strict schemas reject `expected = envelope.header`, but a deliberately
constructed subset copied from that header has no provable provenance. Fingerprints
copied from the same unconfirmed source as the keys do not independently establish
identity. No server authentication, transport, membership, roles, invitations,
message synchronization/history or verification interface is included.

The pairwise suite uses P-384, not a post-quantum ratchet. Its HKDF root profile,
bootstrap, state tags and group signature composition are Be9-specific. There is
no Signal or MLS interoperability promise and no external security audit.

Signer replacement intentionally rejects previously signed packets, including
archive reads under the old signer. There is no historical signing-key trust
store or automatic old-key retry. Retained epoch archives remain readable while
their expected signer/identity is still locally trusted. Explicit trust changes
are application decisions and do not rewrite or delete ciphertext.

Epoch key handoff retains the explicit static v2 ECDH wrapping profile; the new
ECDSA signature covers group **messages**, not those key-distribution packages.
Group wrapping has no ratchet forward secrecy and remains affected by identity
ECDH compromise. Generation/issuer/recipient expectations must be independent
application decisions; sender signatures do not supply membership management.

Complete loss of all profile-3 records and all their markers is indistinguishable
from first use to an engine without an external trusted state anchor. Keep
independent application identity/session expectations and never resume old IDs
after loss. Partial loss with surviving session footprints fails closed.
