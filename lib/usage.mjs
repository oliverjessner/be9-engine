import { encodeV2DerivationInfo, decode32 } from './v2.mjs';
import { encodeBase64url } from './encoding.mjs';

// Only actual, validated derivation inputs enter this identity. No caller alias
// or storage namespace can make the same HKDF key get a fresh local budget.
export async function derivationUsageID(derivation) {
    const info = encodeV2DerivationInfo(derivation);
    const prefix = new TextEncoder().encode('BE8-GCM-USAGE');
    const bytes = new Uint8Array(prefix.length + 32 + info.length);
    bytes.set(prefix);
    bytes.set(decode32(derivation.salt), prefix.length);
    bytes.set(info, prefix.length + 32);
    return encodeBase64url(await crypto.subtle.digest('SHA-256', bytes));
}
