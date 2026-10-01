Auftrag: Verhindere ungeprüfte und stille Public-Key-Ersetzungen.

Implementierung:

1. Öffentliche JWKs strikt validieren:
   erlaubter Schlüsseltyp, unterstützte Kurve, gültige Koordinaten,
   passende Verwendung und keine privaten Bestandteile.
2. Einen stabilen SHA-256-JWK-Thumbprint nach RFC 7638 implementieren.
   Bei EC-Schlüsseln nur die dort vorgeschriebenen öffentlichen Felder
   berücksichtigen. Account-Metadaten gehören nicht in den Thumbprint.
3. Einen persistierten Trust Record pro lokalem Namespace und Peer einführen.
4. Die Anwendung muss einen erwarteten Fingerprint beziehungsweise
   eine explizite lokale Vertrauensentscheidung übergeben können.
   Ein Feld "verified: true" aus einem importierten Netzwerkobjekt
   darf niemals als Vertrauensnachweis gelten.
5. Standardmäßig unbekannte Schlüssel nicht automatisch für sichere
   Convenience-Operationen freigeben.
6. Optionales TOFU nur ausdrücklich aktivierbar machen.
   Erstkontakt und spätere Schlüsselwechsel klar unterscheiden.
7. Derselbe bereits bestätigte Schlüssel darf idempotent importiert werden.
   Ein anderer Schlüssel muss mit einem spezifischen Fehler abgewiesen werden.
   Der bisherige Schlüssel bleibt unverändert.
8. Schlüsselwechsel über eine getrennte, explizite API ermöglichen:
   erwarteter bisheriger Fingerprint plus neu bestätigter Fingerprint.
   Compare-and-swap-Verhalten atomar implementieren.
9. Bulk-Importe dürfen diese Prüfungen nicht umgehen.
10. Bestehende ungeprüfte Datensätze bei der Migration nicht stillschweigend
    zu verifizierten Schlüsseln erklären.

Tests:
Fingerprint-Stabilität, falscher erwarteter Fingerprint, Erstkontakt,
TOFU, unveränderter Reimport, Schlüsselwechsel und konkurrierende Updates.

Keine Verifikationsoberfläche und keinen Schlüsselserver bauen.
Dokumentieren: Ein Fingerprint aus derselben unbestätigten Quelle wie der
Schlüssel bestätigt nicht unabhängig die Identität.
