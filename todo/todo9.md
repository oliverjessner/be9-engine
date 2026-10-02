Auftrag: Überarbeite panic() als verlässliche lokale Schlüsselinvalidierung
und Löschoperation mit präzisen Grenzen.

Implementierung:

1. Die Engine unmittelbar beim Aufruf in einen gesperrten Zustand versetzen.
   Keine neuen kryptografischen Operationen mehr annehmen.
2. Laufende Operationen dürfen nach dieser Invalidierung keine neuen
   Schlüssel persistieren, Caches wiederbefüllen oder Ergebnisse freigeben.
   Dafür einen überprüfbaren Lifecycle-/Generation-Mechanismus verwenden.
3. In-Memory-Referenzen auf private, symmetrische und abgeleitete Schlüssel
   sowie gegebenenfalls Session-Zustände freigeben.
4. Ausschließlich Daten des vorgesehenen Engine-Namespace löschen.
   Keine fremden Accounts, fremden Object Stores oder gesamte
   Anwendungsdatenbanken ungefragt löschen.
5. Schlüssel, zugehörigen Replay-Zustand und weitere sicherheitsrelevante
   Datensätze konsistent über die Persistenzschicht entfernen.
6. Erst nach erfolgreichem Transaktionsabschluss Löschung bestätigen.
7. Bei Persistenzfehlern bleibt die Instanz gesperrt.
   Fehler sichtbar melden; keinen erfolgreichen Panic vortäuschen.
8. Wiederholte Aufrufe müssen ein definiertes idempotentes Verhalten haben.
9. Weitere Instanzen desselben Namespace berücksichtigen:
   invalidierten Zustand nicht aus alten Caches weiterverwenden.
10. Anschließende Neuinitialisierung muss ausdrücklich erfolgen.
    Nicht automatisch eine neue Identität erzeugen.

Tests:
Parallel laufende Verschlüsselung, wiederholter Aufruf, Transaktionsabbruch,
weitere Instanz, Neustart und Unversehrtheit anderer Namespaces.

Dokumentation:
Dies ist logische Löschung und Invalidierung im Verantwortungsbereich
der Engine. Keine garantierte physische Überschreibung, Entfernung aus
Backups oder Löschung bereits kopierter Schlüssel behaupten.

Keine scheinbare "cryptographic erasure" durch einen Wrapping-Key
einbauen, dessen Kopien im selben unkontrollierten Speicher verbleiben.

Status: Implementiert; Lifecycle, Aufruferänderungen und Grenzen in docs/lifecycle.md.
Native Browser-Tests prüfen unmittelbare Sperre, laufende Ver-/Entschlüsselung,
Initialisierung/Neuinitialisierung, idempotente Wiederholung, Abbruch/Rollback,
weitere Verbindung und Worker-Ausführungsumgebung, Neustart sowie Namespace-
und Anwendungsdaten-Isolation. Keine physische Löschgarantie.

Gemeinsamer Abschlusslauf: Quelle, ESM und IIFE jeweils 140 Tests / 859 Assertions;
Dateiliste und Grenzen in docs/todo6-9.md.
