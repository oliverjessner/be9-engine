Auftrag: Ersetze im neuen Verschlüsselungsprofil die direkte
ECDH-zu-AES-Ableitung durch ECDH plus HKDF.

Implementierung:

1. Für das bestehende P-384-Profil zunächst den vollständigen ECDH-Output
   über deriveBits() gewinnen.
2. Dieses Material intern mit WebCrypto-HKDF-SHA-256 verarbeiten.
   Daraus nicht exportierbare AES-256-GCM-Schlüssel ableiten.
3. Das v2-Profil einschließlich KDF und Feldkodierung dokumentieren.
4. Für neue Ableitungskontexte einen öffentlichen zufälligen Salt erzeugen.
   Der Empfänger verwendet denselben übertragenen Salt und erzeugt beim
   Entschlüsseln keinen neuen.
5. HKDF-info eindeutig und deterministisch kodieren:
   Protokollversion, Suite, Kontext-ID, Sender, Empfänger,
   tatsächliche Schlüssel-Fingerprints und Verwendungszweck.
6. Sender und Empfänger geordnet binden:
   Alice-zu-Bob und Bob-zu-Alice müssen unterschiedliche Schlüssel erhalten.
7. Datenverschlüsselung, Anhänge und Schlüssel-Wrapping über getrennte
   Verwendungszwecke unterscheiden.
8. Keine mehrdeutige String-Konkatenation mit Trennzeichen verwenden.
9. Salt und Ableitungsmetadaten für die spätere authentifizierte
   v2-Envelope bereitstellen.
10. Temporäre Secret-Bytearrays möglichst kurz halten und best-effort
    überschreiben. Keine garantierte Speicherlöschung behaupten.
11. Alte Ciphertexte ausschließlich mit der expliziten bisherigen
    Legacy-Ableitung lesen. Keine automatische Algorithmuserkennung.

Tests:
HKDF-Testvektoren, unabhängige Ableitung durch zwei Parteien,
abweichender Salt, abweichender Kontext, Richtung und Verwendungszweck.

Schlüsselgleichheit im Integrationstest über erfolgreiche Interoperabilität
prüfen, nicht durch erneutes Aktivieren von Schlüssel-Exporten.
