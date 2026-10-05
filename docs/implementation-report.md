# Technischer Abschlussbericht: Sessions, Ratchet und Gruppen-Signaturen

## Implemented

Die bestehende Engine wurde um authentifizierte paarweise Sessions mit frischen
DH-Ratchet-Paaren, symmetrischen Chains und einmaligen Message Keys erweitert.
Neue Gruppennachrichten erhalten separat geprüfte ECDSA-Sender-Signaturen.
Native WebCrypto/IndexedDB, JavaScript/ESM und anwendungseigene Datenbanken bleiben
erhalten. Keine Runtime-Abhängigkeit, Benutzerverwaltung, UI, Kommunikation,
Serverdienste, Telemetrie oder Nachrichtenhistorie wurde ergänzt.

Neue Verantwortlichkeiten sind auf Signing, Session-Orchestrierung, Session-
Persistenz, Ratchet, Envelope-Codec und signierte Gruppen verteilt. `bundle.mjs`
bleibt Public API. Bestehende v2-/Be8-/Legacy-Sicherheitsprüfungen bleiben erhalten.
Distributionsdateien wurden ausschließlich mit Rollup generiert.

Geänderte und neue Dateien:

- [.github/workflows/ci.yml](../.github/workflows/ci.yml)
- [README.md](../README.md)
- [build/rollup.config.js](../build/rollup.config.js)
- [dist/bundle.min.js](../dist/bundle.min.js)
- [dist/bundle.mjs](../dist/bundle.mjs)
- [docs/be9-migration.md](../docs/be9-migration.md)
- [docs/group-epochs.md](../docs/group-epochs.md)
- [docs/implementation-report.md](../docs/implementation-report.md)
- [docs/lifecycle.md](../docs/lifecycle.md)
- [docs/ratchet-migration.md](../docs/ratchet-migration.md)
- [docs/ratchet.md](../docs/ratchet.md)
- [docs/security-properties.md](../docs/security-properties.md)
- [docs/session-bootstrap.md](../docs/session-bootstrap.md)
- [lib/bundle.mjs](../lib/bundle.mjs)
- [lib/groups.mjs](../lib/groups.mjs)
- [lib/key-store.mjs](../lib/key-store.mjs)
- [lib/persistence.mjs](../lib/persistence.mjs)
- [lib/protocol.mjs](../lib/protocol.mjs)
- [lib/ratchet-envelope.mjs](../lib/ratchet-envelope.mjs)
- [lib/ratchet.mjs](../lib/ratchet.mjs)
- [lib/replay.mjs](../lib/replay.mjs)
- [lib/session-store.mjs](../lib/session-store.mjs)
- [lib/session.mjs](../lib/session.mjs)
- [lib/signed-group.mjs](../lib/signed-group.mjs)
- [lib/signing.mjs](../lib/signing.mjs)
- [package.json](../package.json)
- [test/be8-legacy-fixture.mjs](../test/be8-legacy-fixture.mjs)
- [test/check-build.mjs](../test/check-build.mjs)
- [test/group.mjs](../test/group.mjs)
- [test/key-protection.mjs](../test/key-protection.mjs)
- [test/ratchet-vector.mjs](../test/ratchet-vector.mjs)
- [test/ratchet-worker.mjs](../test/ratchet-worker.mjs)
- [test/ratchet.mjs](../test/ratchet.mjs)
- [test/rename.mjs](../test/rename.mjs)
- [test/run-browser.mjs](../test/run-browser.mjs)
- [test/run-matrix.mjs](../test/run-matrix.mjs)
- [test/server.mjs](../test/server.mjs)
- [test/session-fixture.mjs](../test/session-fixture.mjs)
- [test/signed-group.mjs](../test/signed-group.mjs)
- [test/suite.mjs](../test/suite.mjs)
- [test/v2.mjs](../test/v2.mjs)

## Protocol changes

Version 3 führt getrennte Suites ein:
`BE9-RATCHET-P384-HKDF-SHA256-A256GCM` und
`BE9-SIGNED-GROUP-HKDF-SHA256-A256GCM`.

Der signierte Offer/Answer-Bootstrap bindet Account-Richtung, Kontext, Session-ID,
Generation und beide tatsächlichen ECDH-/Signing-Fingerprints an frische A0/B0-
Public Keys. SHA-384/ECDSA P-384 signiert deterministisch kodierte Daten. Alice
ersetzt A0 nach dem Bootstrap durch A1 und sendet zuerst; Bob erstellt seine
Send-Chain beim ersten authentifizierten Empfang.

Root-KDF: vollständiger P-384-DH-Output als HKDF-SHA-256-Salt, vorheriger
nicht-extrahierbarer Root als IKM; Ausgabe wird in neuen Root und Chain geteilt.
Diese ausdrücklich dokumentierte Instanziierung ist Be9-spezifisch und weicht
von der üblichen Root-Salt/IKM-Zuordnung ab. Chain-KDF liefert nächsten Chain Key
und einen Message Seed; Message-KDF bindet Richtung, sämtliche Identitäten,
Kontext, Generation, Ratchet-Punkt, Counter und Verwendungszweck. AES-256-GCM
verwendet einmalige Message Keys, zufällige 12-Byte-IVs und 128-Bit-Tags.

Alle neuen KDF-/AAD-/Signatur-/State-Domänen sind getrennt. Kodierung erfolgt
binär über uint32-Längenpräfixe, uint64-Counter, striktes UTF-8 und kanonisches
Base64url. Signierte Gruppen authentifizieren vollständige AAD plus SHA-256 des
Ciphertexts unter `BE9-GROUP-MESSAGE-SIGNATURE`. Der Verifikationsschlüssel kommt
stets aus lokalem Trust; Signaturprüfung erfolgt vor Epoch-Schlüsselauswahl.

Ratchet-Akzeptanz verwendet persistente Chain-Fortschritte und atomar verbrauchte
Skipped Seeds statt eines zweiten 128-Paket-Fensters. Das v2-/Be8-Fenster bleibt
unverändert; signierte Gruppen verwenden es einschließlich Signing-Fingerprint
als Teil ihrer Stream-Identität.

## New persistence state

Sechs neue Stores: `signingKeys`, `signingTrust`, `sessionRegistry`, `sessions`,
`ratchetState`, `skippedKeys`, jeweils unter `be9.*` und mit Namespace-Index.
Skipped Keys besitzen zusätzlich einen Session-Index. Native Requests und
Transaktionen verwenden die bestehende kleine Persistenzschicht; keine Crypto-
Operation wird in einer offenen Transaktion abgewartet.

Root, Chains, Skipped Seeds, ECDH-Ratchet-Private und ECDSA-Signing-Private werden
nicht-extrahierbar als CryptoKeys gespeichert. Kein privater JWK-Backup-Pfad.
Eine Root-abgeleitete HMAC prüft State, Rolle, Peer/Namespace, Counter, Punkte,
Revisionsnummer und geordnete Key-Commitments/Skipped-Inventare. Ein nativer DH-
Challenge prüft funktionale ECDH-Konsistenz; genaue öffentliche Repräsentationen
sind MAC-/Signatur-gebunden. Der x-Koordinatenvergleich allein unterscheidet
keinen Punkt von seiner Negation.

Snapshot → Crypto → Revisions-CAS gilt für Send/Receive über verschiedene
Instanzen, Verbindungen und JS-Kontexte. Send-Fortschritt committed vor GCM;
anschließende Fehler verbrennen den Schritt. Receive gibt nur nach Authentifizierung,
Textvalidierung und erfolgreichem Commit Plaintext zurück. Datenverlust löst
keinen Reset und keine automatische Identity-Generierung aus.

Panic löscht operative Signing-/Session-/Chain-/Skipped-Daten, behält Session-
Tombstones und markiert sie geschlossen. Der Signing-Marker wird ausdrücklich
invalidiert; nur ein neuer aktiver Namespace nach expliziter Reinitialisierung
kann eine neue Signing-Identität autorisieren. Beschädigte Marker können das
nicht umgehen. Bestehende globale tatsächliche GCM-Key-Budgets bleiben erhalten.

## Public API changes

Neue Signing-APIs: `setupSigningIdentity`, `getSigningPublicKey`,
`addSigningPublicKey`, `replaceSigningPublicKey`, `rotateSigningIdentity`.
Signing-Trust ist eine eigenständige lokale Entscheidung mit explizitem
ECDH-Fingerprint-Binding. Normaler Reimport darf keinen Key ersetzen.

Neue Session-APIs: `createSession`, `acceptSession`, `finishSession`, `getSession`
(Metadaten), `closeSession`, `encryptRatchetEnvelope/Text/Image`,
`receiveRatchetEnvelope/Text/Image`.

Neue Gruppen-APIs: `encryptSignedGroupEnvelope/Text/Image`,
`openReceiveSignedGroupContext`, `receiveSignedGroupEnvelope/Text/Image`,
`decryptArchivedSignedGroupEnvelope/Text/Image`.

Explizite Archive-Namen: `decryptArchivedEnvelope/Text/Image` und
`decryptArchivedGroupEnvelope/Text/Image`. Bestehende unqualifizierte APIs bleiben
mit ihrer bisherigen Semantik als dokumentierte statische/Archive-Kompatibilität
erhalten. Keine automatische Suite-Erkennung, Legacy-Wiederholung oder versteckte
Konvertierung. Es gibt keinen Ratchet-Archive-Reader und keine Secret-Getter.

Live-Expectations haben exakte eigene Schemas; ein kompletter Envelope-Header
wird zurückgewiesen. Eine manuell kopierte Teilmenge kann die Engine nicht als
unabhängig verifizieren. Herkunft und Vertrauensentscheidung bleiben bei der
Anwendung. Neue signierte Gruppen-Live-Receives verlangen die aktive erwartete
Epoch; nur ihr ausdrücklich benannter Archive-Pfad akzeptiert alte Epochs.

## Migration

Die Anwendung erhöht ihre eigene IndexedDB-Version und ruft synchron
`upgradeBe9Schema` in ihrer Versionchange-Transaktion auf. Bestehende Daten,
Namespaces, Schlüssel, Zähler und App-Stores bleiben erhalten. Die explizite Be8-
Migration behält die elf historischen Mappings und integriert neue Stores.

Anschließend Signing-Identitäten ausdrücklich erzeugen, öffentliche Signing-
Schlüssel unabhängig bestätigen und neue Sessions aufbauen. Vorhandene statische
Ciphertexte bleiben bei ihren expliziten v2-/Be8-/Legacy-Readern. Kein vorhandener
Ciphertext wird überschrieben oder still in eine Ratchet-Session umgewandelt.
Missing CryptoKey-Clone-Support führt zu einem verständlichen Fehler ohne JWK-
Fallback. [Migration und vollständige Parameter](ratchet-migration.md).

## Tests added

37 zusätzliche Tests gegenüber der Ausgangsbasis (150 Tests/936 Assertions).
Der endgültige Stand umfasst 187 Tests und 1141 Assertions pro Browser/Variante.
Abgedeckt sind unter anderem:

- Signierter Bootstrap beider Parteien, Confirmed/TOFU, Quarantäne, falsche
  Fingerprints/Signaturen/Punkte, Replays und unabhängige Expectations.
- Bidirektionale Chains und mehrere native DH-Wechsel; Unicode, leere Daten,
  Binärdaten und große Bilder; manipulierte Header/IV/Counter/Ciphertexte.
- Out-of-order über alte Chains, Reload und atomarer einmaliger Seed-Verbrauch;
  Gap-/Skipped-/Session-/Registry-/Ratchet-Grenzen und Datenverlust.
- Consumed-Key-Tests und Recovery-Test mit zuvor lokal kompromittiertem State;
  unabhängiger Node/OpenSSL-DH/HKDF/AES-Vektor und Python-AAD-Digest.
- Parallele Sends/Receives aus zwei Verbindungen, konkurrierender Chain-Wechsel,
  getrennte Worker-Realm, Session-Close und Lifecycle-/Panic-Rennen.
- Native Transaktionsabbrüche nach erfolgreichen Requests, echte Unique-Index-
  Schreibfehler, Upgrade-/Panic-Rollback und Failure-Deadlines gegen Hängenbleiben.
- Signing-Rotation/CAS, beschädigte Generation-Marker und Namespace-Isolation.
- Mallory mit demselben Epoch-Secret erzeugt gültige GCM-Daten als Alice, besitzt
  aber keine Alice-Signatur: Empfänger verweigert Akzeptanz. Außerdem Header- und
  Ciphertext-Signaturmanipulation, unbekannte Signer, Rotation, Epoch-Aktivierung,
  Exklusion, Live/Archive, Replay und Commit-Abbruch.

Keine neuen Crypto-Mocks. AES-/KDF-Vektoren bleiben klar lokale Unit-Fixtures;
Integrationsteilnehmer tauschen ausschließlich öffentliche Daten und Pakete aus.
Worker und Main-Realm gehören derselben lokalen Alice-Identität; private oder
abgeleitete Keys gehen nicht über `postMessage`.

Tatsächlich ausgeführte Abschlussprüfungen:

| Prüfung | Ergebnis |
| --- | --- |
| `npm run build` | Erfolgreich, ESLint-Buildfehler sind fatal |
| `npm run test:all` | Alle neun Zellen: jeweils 187 Tests / 1141 Assertions, Exit 0 |
| `npm run test:build` | Erfolgreich: beide Dist-Dateien bytegleich nach Neubuild |
| `npm pack --dry-run --json` | Erfolgreich; beide Distributionsdateien enthalten |
| `git diff --check` | Erfolgreich |
| Quellenprüfung auf Secret-Getter, private Exports, Logs, Fallback, Transaktionen und unbeschränkte Wire-Collections | Keine neue solche API, keine privaten Runtime-JWK-Exports, keine Engine-Logs/Legacy-Fallbacks; neue Collections hart begrenzt |

Browsermatrix mit Playwright 1.63.0, natives macOS, Node v26.10.0; alle neun
Läufe ohne Browserfehler oder Ressourcenfehler, ausgeführt am 5. Oktober 2026:

| Browser | Source | ESM | IIFE |
| --- | --- | --- | --- |
| Chromium 153.0.8010.12 | 187 / 1141 bestanden | 187 / 1141 bestanden | 187 / 1141 bestanden |
| Firefox 155.0 | 187 / 1141 bestanden | 187 / 1141 bestanden | 187 / 1141 bestanden |
| Playwright WebKit 26.6 | 187 / 1141 bestanden | 187 / 1141 bestanden | 187 / 1141 bestanden |

Exportverweigerung für HKDF wird browsergerecht mit den beiden bekannten nativen
Fehlern `InvalidAccessError`/`NotSupportedError` geprüft, zusätzlich bleibt die
Nicht-Extrahierbarkeit separat geprüft. Usage-Mengen werden exakt verglichen,
aber ihre browserabhängige Reihenfolge nicht vorausgesetzt. Authentifizierungs-
und Zustandsprüfungen wurden dafür nicht reduziert.

CI ist als neun Ubuntu/Node-22-Matrixjobs eingerichtet: npm ci, native Browser-
Installation, Build, committed-dist-Vergleich, Tests, erneute Build-Prüfung und
Package-Dry-Run. Der Remote-GitHub-Actions-Lauf wurde hier nicht ausgelöst.

## Security properties gained

Neue paarweise Message Keys hängen nicht direkt am langfristigen Identity-ECDH.
Aktueller fortgeschrittener State bietet keinen Engine-Pfad zurück zu konsumierten
vergangenen Keys; Queued-Skipped-Seeds sind die dokumentierte Ausnahme.
Frische beidseitige DH-Beiträge ermöglichen Recovery unter den dokumentierten
Annahmen, sobald ein Angreifer den State nicht mehr lesen/steuern kann.

Gruppen-Secret-Wissen allein autorisiert keine fremde ECDSA-Sender-Signatur.
Live-Akzeptanz und State-Commit sind gekoppelt, Wiederholung/Zustandsverlust sind
explizite Fehler, unbekannte öffentliche Keys werden nicht automatisch vertraut.
Diese Aussagen sind Konstruktion und getestete Mechanismen unter Annahmen,
kein vollständiger kryptografischer Beweis und kein bestandenes Security-Audit.
Siehe [Property-/Kompromittierungsmatrix](security-properties.md).

## Known limitations

Bösartiges JS im selben Kontext kann nicht-extrahierbare CryptoKeys weiterhin
missbrauchen. Non-extractable ist weder XSS-sicher noch hardwaregeschützt.
Best-effort Byte-Nullung und logische DB-Löschung sind keine garantierte Speicher-
oder Datenträgerlöschung. Browser-/Backup-Kopien können frühere Keys bewahren.

Vollständig konsistenter Storage-Rollback, Kopieren aktiver Sessions in andere
Datenbanken und fehlende monotone Hardware-Persistenz untergraben State-Sicherheit.
HMAC-State-Tags erkennen Inkonsistenzen, nicht einen Angreifer mit JS/Root-Zugriff.
Vollständiger Verlust aller Profil-3-Daten einschließlich sämtlicher Marker ist
ohne externe vertrauenswürdige Anker nicht von Ersteinrichtung unterscheidbar;
unabhängige App-Expectations müssen verhindern, dass alte Sessions fortgesetzt werden.
Receive-Commit ist keine Exactly-once-Garantie für nachgelagerte Anwendungsaktionen.

Recovery setzt frische geheime Beiträge beider Parteien, beendeten State-Zugriff
und fehlenden fortdauernden aktiven MITM voraus. Signing-Kompromittierung erlaubt
Impersonation. Es gibt keine Post-Quantum-, Signal- oder MLS-Kompatibilitätsgarantie.

Maximal 64 Skipped Seeds verbleiben ohne Uhr-/Expiry-Abhängigkeit bis Nutzung,
Close oder Panic. Interaktiver Bootstrap erfordert einen verfügbaren Peer; der
Responder sendet erst nach dem ersten Initiator-Paket. Neue Sessions sind bei
erschöpften Limits ausdrücklich erforderlich; Tombstones werden nicht recycelt.

Gruppen behalten Epoch-Geheimnisse statt einer Gruppen-Ratchet. Epoch-Handoff
bleibt statisches v2-ECDH-Wrapping: ECDH-Kompromittierung betrifft dessen
Vertraulichkeit und Fälschbarkeit. Die neue ECDSA-Authentifizierung signiert
Gruppennachrichten, nicht die bestehenden Handoff-Pakete. Neue Epochs
widerrufen altes Wissen nicht rückwirkend. Bestätigte Signing-Rotation macht alte
Signaturen auch im Archive-Pfad nicht mehr automatisch vertrauenswürdig; es gibt
keinen historischen Signing-Key-Store/Fallback. Statische v2-Kompatibilitäts-Writer
haben keine Ratchet-FS; unsignierte Gruppen keine individuelle Senderauthentizität.

Lokale Tests verwenden Playwright-Browser unter macOS. Ubuntu-CI, andere reale
Browser-Versionen, Hardwarefehler und Quota-Erschöpfung jenseits nativer Abort-/
Constraint-Pfade wurden hier nicht ausgeführt. Es wurde nichts gepusht/publiziert.

## Remaining audit questions

Die zweite eigene Review prüfte Schlüssel-/Nonce-Wiederverwendung, CAS/State-
Rollback, Account-/Rollenbindung, Unknown-key-share, Reflection, Suite-Downgrade,
Cross-Protocol- und Signature-Confusion sowie native Transaktionsgrenzen.
Zusätzliche Befunde führten zu strengeren Rollen-/Peer-Bindings, vollständiger
Skipped-Inventarprüfung und einem ausdrücklich invalidierten Signing-Marker;
fehlende oder beschädigte Metadaten sowie ein fehlender Signer/Marker bei
überlebendem Session-Footprint autorisieren keine neue Identität.

Offen für unabhängige externe Prüfung bleiben insbesondere:

1. Kryptografische Analyse der konkreten Root-HKDF-Instanziierung mit geheimem
   DH-Salt, ihrer Recovery-Annahmen und des gesamten Offer/Answer-Protokolls.
2. KDF-/State-Commitment-Komposition unter partieller Kompromittierung,
   einschließlich langfristig gespeicherter Skipped Seeds.
3. Umfassendere aktive Angriffsszenarien über mehrere verlorene DH-Nachrichten,
   Plattform-/Storage-Rollback und eingeschränkte Browser-Durability.
4. Fachliche Eignung der konservativen Limits und Anwendungspolitik für Trust,
   Schlüsselerneuerung, Archive und unabhängig gespeicherte Expectations.
