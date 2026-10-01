Auftrag: Vereinheitliche Nonce-Erzeugung und binäre Kodierung für v2.

Implementierung:

1. Neue AES-GCM-IVs mit crypto.getRandomValues(new Uint8Array(12)) erzeugen.
2. IVs und Ciphertexte ausschließlich binär beziehungsweise als streng
   definiertes Base64url serialisieren.
3. TextEncoder/TextDecoder nur für tatsächlichen Text verwenden.
   Niemals zufällige Bytes darüber hin- und zurückkonvertieren.
4. Gemeinsame Encoding-Helpers für Text- und Bildverschlüsselung schaffen.
5. Große Bytearrays ohne String.fromCharCode.apply() über das gesamte Array
   verarbeiten, damit keine Argument-/Stack-Limits erreicht werden.
6. Fehlerhafte Kodierungen, unzulässige IV-Längen, zu kurze Ciphertexte
   und übergroße Eingaben vor teuren Operationen zurückweisen.
7. AES-GCM mit explizitem tagLength: 128 verwenden.
8. In sicheren Convenience-Methoden keine benutzerdefinierte IV zulassen.
   Deterministische Zufallsquellen ausschließlich in internen Test-Fixtures.
9. Ein konservatives, anhand der GCM-Anforderungen begründetes
   Nutzungsbudget pro tatsächlichem Schlüssel definieren.
   Zustandsbehaftete APIs müssen dessen Überschreitung verhindern.
   Nicht durch neue frei wählbare keyId-Aliase umgehbar machen.
10. Bei Low-Level-APIs verbleibende Nonce-/Nutzungsgrenzen ausdrücklich
    als Verantwortung des Aufrufers dokumentieren.
11. Das bisherige UUID-/UTF-8-Format nur explizit im Legacy-Lesepfad erhalten.

Tests:
Binäre Roundtrips einschließlich 0x00 und 0xff, Unicode-Klartexte,
größere Bilddaten, ungültiges Base64url und falsche IV-Längen.

Keine absolute Kollisionsfreiheit zufälliger IVs behaupten.
