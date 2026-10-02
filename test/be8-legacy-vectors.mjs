// Independent Node/OpenSSL P-384, HKDF-SHA-256 and AES-GCM fixture.
export const vector = {
    "alicePublic": {
        "crv": "P-384",
        "kty": "EC",
        "x": "qofKIr6LBTeOscce8yCtdG4dO2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3",
        "y": "NhfeSpYmLG9dnpi_kpLcKfj0Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5f",
        "ext": true,
        "key_ops": []
    },
    "bobPublic": {
        "crv": "P-384",
        "kty": "EC",
        "x": "CNmZBXuj0tlpJgBFxVuX8IkCWVmm9DTWUdIH0Z-5bp5P4Ohuvg5k-FuWqcdSld9h",
        "y": "joDx-lsbPO23v-jf_W26dLJ12HW8bMQ-kE5QXyVqtCVf_UPpTTniLWFQHnAKlA6A",
        "ext": true,
        "key_ops": []
    },
    "metadata": {
        "version": 2,
        "suite": "BE8-P384-HKDF-SHA256-A256GCM",
        "contextID": "vector|:\u0000👩🏽‍💻",
        "sender": "101",
        "receiver": "102",
        "senderFingerprint": "-W6Wzot_wuerYbKBVKfGEks3iY2EALna-hBqObnPuJE",
        "receiverFingerprint": "RJeIyeZx-uMuuFmPQfS7sxrKAPa7I7moF1bysQHuh5s",
        "purpose": "data",
        "salt": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
    },
    "infoDigest": "d31cc465d8c6db94fd1b1d7a1260f2c0c2f508ea8fdd39c3d20cc75dbb96a668",
    "ciphertext": "6e625ccb93a88c12b52df1b3efa3385d02ad8fbc84e73fcbf681d0af9dabb79691d6c97d2a084967"
};

