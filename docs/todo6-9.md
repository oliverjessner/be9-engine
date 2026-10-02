# Abschluss: Todo 6 → 7 → 8 → 9

In dieser Reihenfolge implementiert:

1. Strikte v2-Envelope mit deterministisch authentifiziertem Header und unabhängig
   übergebenen Erwartungen; gemeinsame Byte-Operation für Text/Bild/Key-Wrapping.
2. Wiederholbare Archivlesepfade und getrennte zustandsbehaftete Annahme mit
   persistierten uint64-Sequenzen und atomarem 128-Paket-Replay-Fenster.
3. Unabhängige symmetrische Gruppenepochen, empfängergebundene verschlüsselte
   Übergabepakete, unveränderliche Datensätze, explizite CAS-Aktivierung und
   ausschließlich explizite ECDH-Gruppen-Legacy-Lesepfade.
4. Sofortige lokale Panic-Sperre, Schutz laufender Operationen durch Lifecycle/
   Generation, atomare Namespace-Löschung mit Tombstone und ausdrückliche
   Neuinitialisierung. Andere Verbindungen und ein separater Worker wurden geprüft.

## Aufruferänderungen

Simple-Methoden verwenden jetzt `{ header, ciphertext }`. Eigene Kontexte müssen
vor dem Senden geöffnet werden. `decrypt*` liest Archive wiederholt; `receive*`
prüft/committet Replay-Zustand nach Authentifizierung und vor Ausgabe. Gruppen
verwenden `createGroupEpoch`, `importGroupEpoch`, `activateGroupEpoch` und die
separaten Group-Envelope/Text/Image-Methoden. Alte `generateGroupKeys`/
`addGroupKeys` sind gesperrt; bestehende Daten haben explizite Legacy-APIs.
Nach Panic kann `setup()` keine Identität neu erzeugen: `reinitialize()` ist
bewusst erforderlich, erzeugt eine neue Identität und verlangt neue lokale
Vertrauensentscheidungen/Kontexte. Die Anwendung integriert neue Stores über
`upgradeBe8Schema` in ihrem eigenen Versionsupgrade.

Die genauen Signaturen, Feldkodierungen, Fehler und Integrationspflichten stehen
in [Envelope und Replay](envelope-state.md), [Gruppenepochen](group-epochs.md),
[Lifecycle](lifecycle.md) und [KDF/Nonce/Budget](v2-profile.md).

## Tatsächlich ausgeführte Abschlussprüfungen

| Prüfung | Ergebnis |
| --- | --- |
| `npm test` | Native Chromium: 140 Tests, 859/859 Assertions, Exit 0 |
| `npm test -- --bundle esm` | Gebautes ESM: 140 Tests, 859/859 Assertions, Exit 0 |
| `npm test -- --bundle iife` | Gebautes IIFE mit ESM-Testadapter: 140 Tests, 859/859 Assertions, Exit 0 |
| `npm run build` | Beide dist-Dateien über Rollup erzeugt, Exit 0 |
| `./node_modules/.bin/eslint lib/*.mjs` | Exit 0 |
| `git diff --check` | Exit 0 |

Alle drei Browserläufe meldeten null Browser-/Ressourcenfehler. Native WebCrypto
und IndexedDB wurden verwendet; keine erfundenen Crypto-Mocks und keine
Teilnehmer-Netzwerkkommunikation. Codec-/Persistenz-Unit-Helpers importieren auch
in Bundle-Läufen den Quellcode; die Engine-Konstruktoren und ihre vollständigen
Operationen stammen jeweils aus dem ausgewählten Bundle.

Die Tests decken Header-/Ciphertext-Manipulation, unabhängige Erwartungen,
Interoperabilität, Richtung, Unicode/Leertext/Bilder, Replay/Overflow/State-Loss,
parallele Reservierung/Annahme, Epochenwechsel/Ausschluss, CAS, Exportverweigerung,
Neustart und native Commit-/Abbruchgrenzen ab. Fehlgeschlagene Assertions wurden
als Befunde behoben; insbesondere wird die erste lokale Generation erst nach
Commit gebunden. Assertions wurden nicht zugunsten fehlender Merkmale gelockert.

## Grenzen

Nur Chromium wurde geprüft. Speicherverlust/-Rollback untergräbt Replay-,
Budget- und Lifecycle-Zustand; nach Verlust keine alten Kontexte fortsetzen.
Eine Annahme ist keine Exactly-once-Garantie für nachgelagerte Anwendungsaktionen.
Gruppengeheimnisse können weitergegeben werden und beweisen keine individuelle
Autorenschaft; neue Epochen entziehen keine bereits bekannten alten Schlüssel.
Panic ist logische Invalidierung/Löschung, keine physische Überschreibung oder
Löschung von Backups/Kopien. Bereits laufendes natives WebCrypto ist nicht
abbrechbar; Ergebnisse werden gesperrt. Bösartiges JavaScript im selben Kontext
kann Schlüssel weiterhin missbrauchen. Non-extractable ist weder XSS-sicher
noch hardwaregeschützt. Kein bestandenes Audit oder vollständige Sicherheit
wird behauptet. Keine zusätzlichen Runtime-Abhängigkeiten oder Messenger-Funktionen.

## Geänderte Dateien

### Engine

- [lib/bundle.mjs](../lib/bundle.mjs)
- [lib/envelope.mjs](../lib/envelope.mjs)
- [lib/group-profile.mjs](../lib/group-profile.mjs)
- [lib/groups.mjs](../lib/groups.mjs)
- [lib/key-store.mjs](../lib/key-store.mjs)
- [lib/persistence.mjs](../lib/persistence.mjs)
- [lib/replay.mjs](../lib/replay.mjs)
- [lib/usage.mjs](../lib/usage.mjs)
- [lib/v2.mjs](../lib/v2.mjs)

### Tests und Browser-Werkzeuge

- [test/basics.mjs](../test/basics.mjs)
- [test/encoding.mjs](../test/encoding.mjs)
- [test/envelope.mjs](../test/envelope.mjs)
- [test/exceptions.mjs](../test/exceptions.mjs)
- [test/group.mjs](../test/group.mjs)
- [test/image.mjs](../test/image.mjs)
- [test/key-protection.mjs](../test/key-protection.mjs)
- [test/legacy-fixture.mjs](../test/legacy-fixture.mjs)
- [test/panic-worker.mjs](../test/panic-worker.mjs)
- [test/panic.mjs](../test/panic.mjs)
- [test/participants.mjs](../test/participants.mjs)
- [test/persistence.mjs](../test/persistence.mjs)
- [test/replay.mjs](../test/replay.mjs)
- [test/run-browser.mjs](../test/run-browser.mjs)
- [test/server.mjs](../test/server.mjs)
- [test/suite.mjs](../test/suite.mjs)
- [test/text.mjs](../test/text.mjs)
- [test/trust.mjs](../test/trust.mjs)
- [test/v2.mjs](../test/v2.mjs)

### Profil und Dokumentation

- [docs/envelope-state.md](../docs/envelope-state.md)
- [docs/group-epochs.md](../docs/group-epochs.md)
- [docs/lifecycle.md](../docs/lifecycle.md)
- [docs/todo6-9.md](../docs/todo6-9.md)
- [docs/v2-profile.md](../docs/v2-profile.md)

### Aufgabenstatus

- [todo/todo6.md](../todo/todo6.md)
- [todo/todo7.md](../todo/todo7.md)
- [todo/todo8.md](../todo/todo8.md)
- [todo/todo9.md](../todo/todo9.md)

### Build-Ausgaben

- [dist/bundle.min.js](../dist/bundle.min.js)
- [dist/bundle.mjs](../dist/bundle.mjs)

### Repository-Dokumentation

- [README.md](../README.md)
