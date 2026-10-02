Auftrag: Ergänze Replay-Schutz für die Annahme verschlüsselter Pakete,
ohne gewöhnliches wiederholtes Entschlüsseln gespeicherter Daten zu verhindern.

Implementierung:

1. Trenne Low-Level-Decryption von einer zustandsbehafteten Receive-API.
   Nur die Receive-API verändert Replay-Zustand.
2. Verwende authentifizierte Sequenznummern aus der v2-Envelope.
   Große Zähler verlustfrei kodieren und Überlauf explizit behandeln.
3. Zustand mindestens an lokalen Namespace, Kontext, Sender,
   tatsächliche Schlüsselgeneration und gegebenenfalls Gruppenepoche binden.
4. Ein begrenztes Sliding Window für Out-of-Order-Pakete implementieren.
   Keine unbegrenzt wachsende Liste sämtlicher Nachrichten speichern.
5. Sendezähler vor Verwendung atomar reservieren.
   Fehlgeschlagene Verschlüsselungen dürfen reservierte Werte verbrauchen,
   aber niemals zur Wiederverwendung führen.
6. Mehrere Engine-Instanzen mit derselben Persistenz berücksichtigen.
   Ein reiner In-Memory-Mutex genügt dafür nicht.
7. Empfangene Daten zunächst kryptografisch authentifizieren.
   Erst anschließend Replay-Zustand atomar prüfen und fortschreiben.
   Klartext erst nach erfolgreichem Commit an den Aufrufer zurückgeben.
8. Ungültige Pakete dürfen das Empfangsfenster nicht verschieben.
9. Parallele Verarbeitung desselben Pakets darf höchstens einmal
   zu erfolgreicher Annahme führen.
10. Neustart, geschlossene Kontexte und State-Verlust definieren.
    Keine stillschweigende Wiederaufnahme mit zurückgesetzten Zählern.
11. Dokumentiere Grenzen bei Storage-Rollback und Absturz nach Commit.
    Nicht "exactly once" für nachgelagerte Anwendungsaktionen behaupten.

Tests:
Duplikate, Out-of-Order innerhalb/außerhalb des Fensters, Parallelität,
gefälschte hohe Zähler, Neustart und Counter-Overflow.

Keine Zustellung, Empfangsbestätigungen oder Netzwerk-Retries implementieren.

Status: Implementiert; Sende-/Replay-Vertrag in docs/envelope-state.md.
Native Browser-Prüfung: Duplikate, 128er-Fenster, Parallelität, AAD-Fälschung,
Neustart, uint64-Überlauf, State-Verlust und reale Commit-Abbrüche.

Gemeinsamer Abschlusslauf: Quelle, ESM und IIFE jeweils 140 Tests / 859 Assertions;
Dateiliste und Grenzen in docs/todo6-9.md.
