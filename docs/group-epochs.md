For new sender-authenticated messages use `encryptSignedGroup*`,
`openReceiveSignedGroupContext`, `receiveSignedGroup*` and
`decryptArchivedSignedGroup*` from [profile 3](ratchet-migration.md).
The APIs below describe the retained **unsigned v2 compatibility profile**;
its live/archive behavior is unchanged. The new signed live path requires the
active expected epoch and verifies locally trusted ECDSA authorship before
selecting an epoch key. Only the explicit signed archive path permits retired epochs.

# Symmetric group epochs

This page specifies new Be9 packages. Retained Be8 key packages/group data use
the explicit readers described in [Be9 migration](be9-migration.md).

New groups use independent random 32-byte secrets as non-extractable HKDF
CryptoKeys (`deriveKey` only), stored by `[namespace, groupID, epoch]` in
`be9.groupEpochs`. They are separate from retained ECDH group records. Epochs
are canonical positive uint64 decimal strings; IDs match `g[A-Za-z0-9_-]+`
with at most 128 ASCII characters. `generation` is SHA-256 of the random secret,
as canonical Base64url. It binds the actual secret generation, not a caller alias.

```js
await alice.openContext('handoff-42');
const { epoch, packages } = await alice.createGroupEpoch(
  'gProject', '1', ['102', '103'], { contextID: 'handoff-42' });
// Transfer only public epoch metadata and each recipient's encrypted envelope.
await bob.importGroupEpoch(packages[0].envelope, {
  sender: '101', receiver: '102', contextID: 'handoff-42',
  groupID: 'gProject', epoch: '1', generation: epoch.generation
});
await alice.activateGroupEpoch('gProject', '1', { expectedCurrentEpoch: null });
await alice.openContext('data-42');
const packet = await alice.encryptGroupText('gProject', 'Example', { contextID: 'data-42' });
const expected = { sender: '101', contextID: 'data-42', purpose: 'data',
  groupID: 'gProject', epoch: '1', generation: epoch.generation };
const archivedText = await bob.decryptGroupText(packet, expected);
await bob.openReceiveGroupContext(expected);
const acceptedText = await bob.receiveGroupText(packet, expected);
```

Recipients must already have explicit local trusted public keys. The recipient
array (at most 256 unique non-local accounts) is used only for package creation;
no membership list is persisted. Key packages use the existing pairwise P-384
suite with HKDF purpose `key-wrap`, AES-GCM wrapping, and authenticated structured
group metadata. Import checks independently expected issuer, recipient, context,
group, epoch and generation before storing. Raw secret bytes and temporary
extractable wrapping targets remain internal; bytes are overwritten best-effort.
Public byte/archive/receive APIs cannot unwrap key packages to secret material.

Creation and import never activate an epoch. `activateGroupEpoch()` atomically
compares `expectedCurrentEpoch` (null for first activation) and cannot downgrade
to an older epoch. Epoch records are immutable; identical confirmed import is
idempotent, another issuer/generation rejects. Creation failures may consume
send sequences and nonce reservations without releasing packages. Old records
are retained for archive reads. `getGroupEpochs()` and `getActiveGroupEpoch()`
project public metadata only, never CryptoKeys or raw secret material.

Group data has the separate fixed suite `BE9-GROUP-HKDF-SHA256-A256GCM`.
The header retains the exact envelope schema. Receiver is the group ID;
receiverFingerprint is the generation digest; group is the structured
`{ groupID, epoch, generation }`. SenderFingerprint is the actual locally trusted
public sender fingerprint. The HKDF-info domain is `BE9-GROUP-HKDF-INFO`, followed
by the same length-prefixed fields as pairwise info, then group ID (UTF-8), epoch
(8-byte big endian), generation (raw 32 bytes). Group secret is HKDF input,
SHA-256 is the hash, public per-packet salt is 32 fresh random bytes, output is
non-extractable AES-256-GCM for `encrypt`/`decrypt`. Purposes data and attachment
are distinct; direction/sender, context and actual generation are bound.
AAD, random IVs, tag/size/usage limits and committed sequence/replay rules are
shared with the pairwise profile. Group replay streams bind group and epoch.
Archive decryptors use the explicitly expected stored epoch, independently of
which epoch is active. Text/image adapters preserve their existing string inputs;
byte methods are `encryptGroupEnvelope`, `decryptGroupEnvelope`,
`receiveGroupEnvelope`. Stateful text/image receivers validate text before commit.

All holders of a group secret can forward it and can forge another holder's
claimed sender metadata. Shared group keys do not prove individual authorship;
sender fingerprint binding is not a signature. New epochs exclude recipients
only from newly distributed secrets, and do not revoke already known old keys.
There is no membership enforcement, MLS, invitation system or transport.

Old `generateGroupKeys` and ambiguous `addGroupKeys` reject with
`LEGACY_GROUP_API`; no production writer creates new ECDH groups. Retained records
use explicit `addLegacyGroupKeys`, `getCachedLegacyGroupKeys/Versions`,
`getLegacyGroupKeyReference`, and legacy KDF/ciphertext readers. They are not
silently converted to symmetric epochs. Application schema upgrades call
`upgradeBe9Schema` to add group epoch and active-selection stores, retaining
other stores and records. Malicious JavaScript in the same context can still
use non-extractable keys; they are not XSS-safe or hardware-backed.
