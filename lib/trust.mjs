import { engineError } from './persistence.mjs';

export function fingerprintValue(value) {
    // A canonical, unpadded base64url encoding of a 32-byte SHA-256 digest.
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(value)) {
        throw engineError('invalid SHA-256 JWK thumbprint', 'INVALID_FINGERPRINT');
    }
    return value;
}

// This is a separate local argument, never read from an imported key/entry.
export function trustDecision(options = {}) {
    if (!options || typeof options !== 'object' || Array.isArray(options)
        || (options.trust !== undefined && options.trust !== 'confirmed')
        || (options.tofu !== undefined && typeof options.tofu !== 'boolean')) {
        throw engineError('invalid local trust decision', 'INVALID_TRUST_DECISION');
    }
    return {
        ...(options.expectedFingerprint !== undefined ? { expectedFingerprint: fingerprintValue(options.expectedFingerprint) } : {}),
        ...(options.trust !== undefined ? { trust: options.trust } : {}),
        tofu: options.tofu === true,
    };
}

export function checkTrustRecord(record) {
    if (!record) return undefined;
    fingerprintValue(record.fingerprint);
    if (!['unverified', 'confirmed', 'tofu'].includes(record.status)) {
        throw engineError('invalid persisted trust state', 'INVALID_TRUST_STATE');
    }
    return record;
}

export function nextTrust(current, fingerprint, decision, firstContact) {
    checkTrustRecord(current);
    if (decision.expectedFingerprint !== undefined && decision.expectedFingerprint !== fingerprint) {
        throw engineError('public key does not match the expected fingerprint', 'FINGERPRINT_MISMATCH');
    }
    if (current && current.fingerprint !== fingerprint) {
        throw engineError('peer public key changed; explicit replacement required', 'PUBLIC_KEY_CHANGED');
    }
    if (decision.expectedFingerprint !== undefined || decision.trust === 'confirmed') return 'confirmed';
    if (current?.status === 'confirmed' || current?.status === 'tofu') return current.status;
    // TOFU is a first-contact policy, never a later confirmation or key change.
    if (firstContact && decision.tofu) return 'tofu';
    return 'unverified';
}
