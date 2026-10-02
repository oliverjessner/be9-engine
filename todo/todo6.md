Auftrag: Führe für v2 eine streng definierte kryptografische Envelope ein.

Implementierung:

1. Definiere eine kleine Envelope für verschlüsselte Daten mit:
   Version, Suite, Sender-/Empfängerreferenz, Schlüsselreferenzen,
   Kontext-ID, Verwendungszweck, KDF-Salt, IV und Ciphertext.
   Replay-relevante Sequenzfelder im gemeinsamen Profil berücksichtigen.
2. Keine Chat-spezifischen Felder wie Zustellstatus, Lesebestätigung
   oder Benutzerprofile hinzufügen.
3. Alle sicherheitsrelevanten Headerfelder deterministisch kodieren
   und als AES-GCM additionalData authentifizieren.
4. Nur explizit unterstützte Versionen und Suites akzeptieren.
   Der empfangene Header darf keine beliebigen Algorithmen auswählen.
5. Header-Schema, Datentypen, Pflichtfelder und Größenlimits strikt prüfen.
6. Der Aufrufer muss beim Entschlüsseln den erwarteten Kontext angeben können.
   Eigene Account-ID und erwarteten Peer gegen die Envelope prüfen.
   Nicht sämtliche Erwartungen aus dem unbestätigten Header selbst ableiten.
7. KDF-Kontext und Envelope müssen dieselbe eindeutige Feldkodierung verwenden.
8. Bei Authentifizierungsfehlern niemals Klartext zurückgeben und niemals
   auf ein anderes Format oder einen anderen Schlüssel durchprobieren.
9. Unterschiedliche Zwecke wie Text, Anhang und Key-Wrapping binden.
10. Eine gemeinsame Byte-basierte Crypto-Funktion verwenden;
    Text- und Bildmethoden bleiben dünne Adapter.

Tests:
Jedes authentifizierte Headerfeld einzeln verändern und Ablehnung prüfen.
Zusätzlich eine vollständig unveränderte gültige Envelope unter einem
falschen erwarteten Kontext, Empfänger oder Verwendungszweck ablehnen.

AAD schützt Metadatenintegrität, verbirgt diese Metadaten aber nicht.

Status: Implementiert; Profil und Aufruferänderungen in docs/envelope-state.md.
Native Browser-Prüfung: Envelope-Header-Manipulation, unabhängige Erwartungen und Interoperabilität.

Gemeinsamer Abschlusslauf: Quelle, ESM und IIFE jeweils 140 Tests / 859 Assertions;
Dateiliste und Grenzen in docs/todo6-9.md.
