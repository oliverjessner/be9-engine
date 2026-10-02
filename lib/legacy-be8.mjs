// Exact frozen historical identifiers, used only by explicitly selected readers
// and schema migration. New writers never select this profile.
export const BE8_V2_SUITE = 'BE8-P384-HKDF-SHA256-A256GCM';
export const BE8_GROUP_SUITE = 'BE8-GROUP-HKDF-SHA256-A256GCM';
export const BE8_DOMAINS = Object.freeze({
    pairInfo: 'BE8-HKDF-INFO', groupInfo: 'BE8-GROUP-HKDF-INFO',
    aad: 'BE8-ENVELOPE-AAD', replay: 'BE8-REPLAY-STREAM',
});
export const BE8_STORES = Object.freeze({
    scopes: 'be8.scopes', publicKeys: 'be8.publicKeys', privateKeys: 'be8.privateKeys',
    groupKeys: 'be8.groupKeys', groupEpochs: 'be8.groupEpochs', activeEpochs: 'be8.activeEpochs',
    trust: 'be8.trust', keyUsage: 'be8.keyUsage', contexts: 'be8.contexts',
    sendState: 'be8.sendState', receiveState: 'be8.receiveState',
});
