Auftrag: Behebe die asynchronen und atomaren Persistenzfehler der Engine.

Implementierung:

1. Kapsle native IndexedDB-Requests und Transaktionen in kleine Helpers.
   Request-Ergebnisse und Transaktionsabschluss getrennt behandeln.
   complete, error und abort zuverlässig auswerten.
2. Entferne await tx.complete, sofern kein entsprechender Wrapper existiert.
   Entferne wirkungslose Promise.all-Aufrufe über undefined-Werte.
   Event-Handler gehören an Requests beziehungsweise Transaktionen,
   nicht an Object Stores.
3. Öffentliche Mutationsmethoden dürfen erst nach erfolgreichem Commit
   Erfolg melden. Fehler müssen als Error-Objekte propagiert werden.
4. Zusammengehörige Public-/Private-Key-Datensätze atomar speichern.
   Kryptografische Berechnungen vor der Schreibtransaktion erledigen.
   Keine beliebigen asynchronen Arbeiten in offenen Transaktionen abwarten.
5. In-Memory-Caches nicht vor einem erfolgreichen Commit aktualisieren.
   Konkurrierende Änderungen dürfen Cache und Datenbank nicht auseinanderziehen.
6. Reine Leseoperationen mit readonly ausführen.
7. setup() muss wiederholbar und gegen parallele Initialisierung abgesichert
   sein. Datenbankfehler dürfen keine neue Identität erzeugen.
8. Account-/Namespace-Zuordnung validieren. Daten verschiedener Accounts
   dürfen sich weder überschreiben noch versehentlich vermischen.
9. Übergebene Schlüsselobjekte dürfen durch Object-Spreading keine
   Account-IDs oder andere vom Aufrufer getrennt übergebene Metadaten ersetzen.
10. Die Anwendung bleibt Eigentümerin ihrer Datenbank.
    Schema-Upgrades als dokumentierte Integrationsfunktion bereitstellen,
    nicht die gesamte Datenbank ungefragt übernehmen oder ersetzen.

Tests:
Transaktionsabbruch nach erfolgreichem Einzelrequest, Schreibfehler,
paralleles setup(), parallele Mutationen, Neustart sowie Account-Isolation.
Zusätzlich prüfen, dass keine Promise dauerhaft hängen bleibt.
