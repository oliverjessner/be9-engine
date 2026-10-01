import { encodeBase64url } from '../lib/encoding.mjs';

// Historical UUID/UTF-8 + padded Base64 creation belongs only to test fixtures.
// Native WebCrypto remains genuine; no new production legacy writer exists.
export async function encryptLegacyFixture(key, text) {
    const iv = crypto.randomUUID();
    const bytes = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new TextEncoder().encode(iv), tagLength: 128 },
        key, new TextEncoder().encode(text));
    const unpadded = encodeBase64url(bytes).replace(/-/g, '+').replace(/_/g, '/');
    return { cipherText: unpadded + '='.repeat((4 - unpadded.length % 4) % 4), iv };
}
