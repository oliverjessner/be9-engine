Auftrag: Entferne die standardmäßige Speicherung und Rückgabe privater JWKs.

Implementierung:

1. Private ECDH-Schlüssel nicht exportierbar erzeugen.
   Nur tatsächlich benötigte keyUsages erlauben.
2. Private Schlüssel intern als CryptoKey verwalten und über Structured Clone
   in IndexedDB speichern. Öffentliche Schlüssel dürfen exportierbar bleiben.
3. Alle betroffenen Ableitungs-, Setup- und Persistenzmethoden anpassen.
4. generatePrivAndPubKey() darf keinen privaten JWK mehr zurückgeben.
   Verwende eine klar dokumentierte Rückgabe mit öffentlichem Schlüssel
   und gegebenenfalls einer opaken lokalen Schlüsselreferenz.
5. Abgeleitete AES-Schlüssel ebenfalls standardmäßig nicht exportierbar halten.
6. Public-Key-Getter dürfen niemals private Schlüsselbestandteile liefern.
7. Implementiere eine explizite Migration vorhandener privater JWKs:
   validieren, nicht exportierbar importieren und anschließend atomar
   durch den neuen Datensatz ersetzen.
8. Die Migration darf die kryptografische Identität nicht verändern.
   Bei Fehlern keine Originaldaten löschen und keine neuen Keys erzeugen.
9. Vorhandene Daten nicht über einen versteckten Klartext-Backup-Pfad behalten.
   Keine neue Exportfunktion hinzufügen, die die Schutzmaßnahme umgeht.
10. Fehlende Browserunterstützung für die erforderliche Speicherung
    mit einem verständlichen Fehler behandeln, nicht mit JWK-Fallback.

Tests:

- Reload und weitere Ver-/Entschlüsselung funktionieren.
- exportKey() auf gespeicherten privaten Schlüsseln schlägt fehl.
- Neue Datensätze enthalten kein privates d-Feld.
- Migration erhält den öffentlichen Fingerprint.
- Abgebrochene Migration verursacht keinen Schlüsselverlust.

Dokumentiere ausdrücklich:
Bösartiges JavaScript im selben Ausführungskontext kann Schlüssel weiterhin
missbrauchen. Non-extractable bedeutet nicht XSS-sicher oder hardwaregeschützt.
