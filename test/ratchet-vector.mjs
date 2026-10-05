// Independent Node/OpenSSL HKDF/root/chain/AES-GCM unit vector; known local scalar 1.
export const vector = {
    "alicePublic": {
        "kty": "EC",
        "crv": "P-384",
        "x": "qofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3",
        "y": "NhfeSpYmLG9dnpi_kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f"
    },
    "bobPublic": {
        "kty": "EC",
        "crv": "P-384",
        "x": "CNmZBXuj0tlpJgBFxVuX8IkCWVmm9DTWUdIH0Z-5bp5P4Ohuvg5k-FuWqcdSld9h",
        "y": "joDx-lsbPO23v-jf_W26dLJ12HW8bMQ-kE5QXyVqtCVf_UPpTTniLWFQHnAKlA6A"
    },
    "rootInput": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
    "transcript": "VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVU",
    "header": {
        "version": 3,
        "suite": "BE9-RATCHET-P384-HKDF-SHA256-A256GCM",
        "sessionID": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
        "contextID": "vector|:\u0000👩🏽‍💻",
        "sender": "101",
        "receiver": "102",
        "senderIdentityFingerprint": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI",
        "receiverIdentityFingerprint": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM",
        "senderSigningFingerprint": "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ",
        "receiverSigningFingerprint": "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU",
        "generation": "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY",
        "ratchetPublicKey": {
            "kty": "EC",
            "crv": "P-384",
            "x": "qofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3",
            "y": "NhfeSpYmLG9dnpi_kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f"
        },
        "previousChainLength": "7",
        "messageNumber": "9",
        "purpose": "attachment",
        "iv": "AAECAwQFBgcICQoL"
    },
    "aadDigest": "1ee586f756f35829e58ada80a07cb9dceecf5d2023d3438e6a6fc3b700dd6019",
    "ciphertext": "Q33tGWcO6GAqKkszjcFn839PfSrkOyOQHgaExsQk8SpJkjWoEImZj0aYMKV8DDY"
};
