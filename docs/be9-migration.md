# Umbenennung auf Be9

Projektname, Konstruktor, Beispiele, Build-Global, Tests, Paketmetadaten und
aktuelle Store-/Profilnamen verwenden Be9. Die Paket-Links folgen dem bestehenden
Git-Remote `oliverjessner/be9-engine`. Es wurden keine Remote-Repositories oder
veröffentlichten npm-Pakete umbenannt oder veröffentlicht.

## Aufruferänderungen

| Bisher | Jetzt |
| --- | --- |
| Standardimport/Konstruktor `Be8` | `Be9` |
| Klassischer Script-Global `be8` | `be9` |
| `upgradeBe8Schema(db, tx)` | `upgradeBe9Schema(db, tx)` für das aktuelle Schema |
| Engine-Stores `be8.*` | `be9.*` nach explizitem `migrateBe8Schema(db, tx)` |
| Neue paarweise Pakete | `BE9-P384-HKDF-SHA256-A256GCM` |
| Neue Gruppenpakete | `BE9-GROUP-HKDF-SHA256-A256GCM` |

Der Standardimport bleibt ein Standardimport; sein lokaler JavaScript-Name ist
frei wählbar. Es gibt keinen alten Script-Global oder `upgradeBe8Schema`-Alias.
Das Paket heißt `be9-engine`; der Lockfile-Kopf stimmt mit Version `0.3.3`
überein. Abhängigkeiten wurden dafür nicht geändert.

Die neuen KDF-, AAD-, Replay- und Budget-Domänen beginnen mit `BE9-`. Die
Feldkodierung und Version `2` bleiben unverändert; das Suite-Feld unterscheidet
die Profile. Deshalb entstehen andere abgeleitete AES-Schlüssel. Fingerprints
der vorhandenen öffentlichen Schlüssel und lokale Identitäten bleiben gleich.
Kein bestehender Ciphertext oder Header darf durch String-Ersetzung umbenannt
werden: Das würde KDF und Authentifizierung ändern.

## Explizite Migration der anwendungseigenen Datenbank

Die Anwendung wählt Datenbankname und eine höhere Version, schließt ihre alten
Verbindungen und ruft synchron im eigenen `onupgradeneeded` auf:

```javascript
import Be9, { migrateBe8Schema } from 'be9-engine';

const request = indexedDB.open('my-application', 3); // Eigene Version passend erhöhen.
let upgradeError;
request.onupgradeneeded = () => {
    try {
        migrateBe8Schema(request.result, request.transaction);
        // Andere anwendungseigene Schemaänderungen hier integrieren.
    } catch (error) {
        upgradeError = error; // Die fehlgeschlagene Migration wurde abgebrochen.
    }
};
const db = await new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(upgradeError || new Error('Database upgrade failed'));
    request.onblocked = () => reject(new Error('Database upgrade blocked'));
});
db.addEventListener('versionchange', () => db.close());
const engine = new Be9('1', db);
await engine.setup();
```

`migrateBe8Schema` ist ein benannter ESM-Export und `Be9.migrateBe8Schema`.
Er verlangt eine native `versionchange`-Transaktion. Er benennt ausschließlich
die elf bekannten Engine-Stores über `IDBObjectStore.name` um und integriert
fehlende aktuelle Stores. Datensätze, Indizes, Structured-Clone-CryptoKeys,
Namespaces, Account-Zuordnungen, Trust-Status, Lifecycle-Generationen, Tombstones,
Kontextregister, Replay-Fenster, Sendesequenzen und Nutzungszähler werden erhalten.
Unverifizierte Schlüssel bleiben unverifiziert. Andere Anwendungs-Stores bleiben
unberührt. Die Datenbank wird weder ersetzt noch gelöscht.

Der synchrone Rückgabewert `{ migratedStores }` bedeutet noch keinen Commit.
Erfolg steht erst mit dem erfolgreichen Open-Request nach Abschluss der gesamten
Upgrade-Transaktion fest. Bei Abbruch werden auch bereits erfolgte Umbenennungen
zurückgerollt. Wiederholung ohne alte Stores ist idempotent. Unpassende
Store-/Indexdefinitionen führen zu `SCHEMA_ERROR`. Koexistierende alte und neue
Ziel-Stores führen zu `SCHEMA_MIGRATION_CONFLICT`; es gibt kein stilles Zusammenführen,
Überschreiben oder Löschen. Die Anwendung muss einen solchen Konflikt ausdrücklich
auflösen und dabei ihre Originaldaten erhalten.

`setup()` und `upgradeBe9Schema()` verweigern bekannte alte Engine-Stores mit
`LEGACY_SCHEMA_MIGRATION_REQUIRED`. Sie erzeugen keine Identität neben den alten
Daten. Für neue Datenbanken genügt `upgradeBe9Schema`. Eine zuvor invalidierte
Identität bleibt nach Migration gesperrt; nur das bereits vorhandene explizite
`reinitialize()` kann eine neue Generation erzeugen.

Diese Schema-Migration exportiert und importiert keine Schlüssel. Bereits
vorhandene private JWKs werden damit nicht automatisch konvertiert. Dafür bleibt
nach Schema-Integration die separate explizite `migrateLegacyIdentity()` nötig.
Unscoped historische Stores (`publicKeys`, `privateKeys`, `groupKeys`) werden
dabei wie bisher nur ausdrücklich und für die gewählten Datensätze behandelt.
Nicht exportierbare `deriveKey`-only Identitäten behalten ihre Legacy-Lesbarkeit;
sie erhalten durch Umbenennen keine `deriveBits`-Usage.

## Ausschließlich explizite Be8-Lesepfade

Neue Pakete entstehen ausschließlich mit Be9. Die Anwendung wählt historische
Lesepfade anhand ihres eigenen Datenkontexts. Es gibt keine automatische
Profilerkennung und keinen zweiten Versuch nach Validierungs- oder
Authentifizierungsfehlern.

| Historisches Format | Explizite Methoden |
| --- | --- |
| Paarweise Be8-Envelope, Archiv | `decryptBe8Envelope`, `decryptBe8Text`, `decryptBe8Image` |
| Paarweise Be8-Envelope, zustandsbehaftete Annahme | `openReceiveBe8Context`, `receiveBe8Envelope`, `receiveBe8Text`, `receiveBe8Image` |
| Be8-HKDF-Tupel ohne Envelope | `getBe8DerivedKey`, `decryptBe8TextUnframedLegacy`, `decryptBe8ImageUnframedLegacy` |
| Verschlüsseltes Be8-Gruppenschlüsselpaket | `importBe8GroupEpoch` |
| Be8-Gruppenarchiv | `decryptBe8GroupEnvelope`, `decryptBe8GroupText`, `decryptBe8GroupImage` |
| Be8-Gruppenannahme | `openReceiveBe8GroupContext`, `receiveBe8GroupEnvelope`, `receiveBe8GroupText`, `receiveBe8GroupImage` |

Envelope-/Gruppenmethoden verwenden dieselben unabhängig vorzugebenden
Erwartungen wie ihre aktuellen Gegenstücke, mit unveränderten historischen
Headern. Gruppenimport aktiviert keine Epoche automatisch. Private/operative
Schlüssel bleiben lokal und nicht exportierbar. `getBe8DerivedKey` erlaubt nur
`data`/`attachment` und liefert einen Schlüssel ausschließlich mit `decrypt`.
Key-Wrapping wird nur intern im expliziten Gruppenimport entpackt.

Die öffentlichen Codec-Helfer `encodeBe8DerivationInfo` und
`encodeBe8EnvelopeAAD` kodieren ausschließlich öffentliche Metadaten nach dem
eingefrorenen Profil; sie sind ebenfalls als Konstruktor-Statics verfügbar.
Alte Suite-/Domänen-/Store-Literale sind in `lib/legacy-be8.mjs` gekapselt.
Verbleibende Be8-Namen kennzeichnen ausschließlich diese Kompatibilität,
Migration, historische Test-Fixtures und ihre Dokumentation.

Be8-Replay-Stream-IDs werden mit der ursprünglichen Domäne berechnet. Frühere
Annahmen werden auch nach Migration/Reload als Duplikate abgewiesen. Die
aktuellen Be9-Streams sind getrennt, weil Suite und KDF-Domäne andere tatsächliche
Schlüssel ergeben. Alte Budget-Datensätze bleiben unverändert erhalten; es gibt
keine Be8-Verschlüsselungs-API, die einen neuen Zähler für alte Schlüssel erzeugt.
Vorhandene symmetrische Gruppenepochen können nach expliziter Aktivierung für
neue Be9-Pakete verwendet werden. Das ist keine Gruppenrotation oder Änderung
des ursprünglichen Gruppengeheimnisses.

Die bisherigen direkten ECDH-/UUID-Leser `getLegacyDerivedKey` und
`decryptText/Image(Simple)Legacy` bleiben bestehen. HKDF-Tupel mit UUID-IV benötigen
zusätzlich ausdrücklich `{ legacyUUID: true }`; die Be8-Variante benötigt auch
die ausdrücklich benannte Be8-Methode. Die unqualifizierten
`decryptText/ImageUnframedLegacy` verwenden nun Be9-HKDF-Metadaten.

## Grenzen

Native IndexedDB-Schemaumbenennung und Structured Clone für CryptoKeys werden
benötigt. Es gibt keinen privaten-JWK-Fallback. Nur Chromium wurde geprüft.
Speicherverlust/-Rollback untergräbt Budget-, Replay- und Lifecycle-Zustand.
Bösartiges JavaScript im selben Ausführungskontext kann Schlüssel weiterhin
missbrauchen: Non-extractable bedeutet weder XSS-sicher noch hardwaregeschützt.
Die Prüfungen sind kein Sicherheitsaudit und behaupten keine vollständige Sicherheit.

## Tatsächlich ausgeführte Prüfungen

| Befehl | Ergebnis |
| --- | --- |
| `npm test` | Quellcode: 150 Tests, 936/936 Assertions, Exit 0 |
| `npm test -- --bundle esm` | Gebautes ESM: 150 Tests, 936/936 Assertions, Exit 0 |
| `npm test -- --bundle iife` | Gebautes IIFE: 150 Tests, 936/936 Assertions, Exit 0 |
| `npm run build` | Beide dist-Dateien über Rollup erzeugt, Exit 0 |
| `./node_modules/.bin/eslint lib/*.mjs` | Exit 0 |
| `git diff --check` | Exit 0 |

Alle Browserläufe verwenden natives Chromium-WebCrypto und IndexedDB und melden
null Browser-/Ressourcenfehler. Die bereits vorhandenen 140 Tests bleiben aktiv;
zehn zusätzliche Tests prüfen Namen, gefrorene unabhängige Node/Python-Vektoren,
Be8-Lesen in beide Richtungen, Unicode/Leertext/Bild-API, falsche IV und
Ciphertext-Manipulation, falschen Empfänger, Gruppenübergabe, Exportverweigerung,
Migration/Reload, Trust-/Account-/Counter-Erhalt, Abbruch nach Umbenennung,
Zielkonflikte, inkompatible Indizes, Replay und persistierte Panic-Tombstones.
Keine privaten Schlüssel oder abgeleiteten CryptoKeys werden zwischen
Teilnehmern geteilt; historische Writer existieren ausschließlich als native
Test-Fixtures. Bundle-Läufe verwenden den jeweils gebauten Engine-Konstruktor;
interne Codec-/Persistenz-Unit-Helpers importieren weiterhin den Quellcode.

## Geänderte Dateien

### Engine

- [lib/bundle.mjs](../lib/bundle.mjs)
- [lib/crypto-keys.mjs](../lib/crypto-keys.mjs)
- [lib/envelope.mjs](../lib/envelope.mjs)
- [lib/group-profile.mjs](../lib/group-profile.mjs)
- [lib/groups.mjs](../lib/groups.mjs)
- [lib/key-store.mjs](../lib/key-store.mjs)
- [lib/legacy-be8.mjs](../lib/legacy-be8.mjs)
- [lib/persistence.mjs](../lib/persistence.mjs)
- [lib/replay.mjs](../lib/replay.mjs)
- [lib/usage.mjs](../lib/usage.mjs)
- [lib/v2.mjs](../lib/v2.mjs)

### Tests und Browser-Werkzeuge

- [test/basics.mjs](../test/basics.mjs)
- [test/be8-legacy-fixture.mjs](../test/be8-legacy-fixture.mjs)
- [test/be8-legacy-vectors.mjs](../test/be8-legacy-vectors.mjs)
- [test/database.mjs](../test/database.mjs)
- [test/encoding.mjs](../test/encoding.mjs)
- [test/envelope.mjs](../test/envelope.mjs)
- [test/exceptions.mjs](../test/exceptions.mjs)
- [test/group.mjs](../test/group.mjs)
- [test/index.html](../test/index.html)
- [test/key-protection.mjs](../test/key-protection.mjs)
- [test/legacy-fixture.mjs](../test/legacy-fixture.mjs)
- [test/panic-worker.mjs](../test/panic-worker.mjs)
- [test/panic.mjs](../test/panic.mjs)
- [test/participants.mjs](../test/participants.mjs)
- [test/persistence.mjs](../test/persistence.mjs)
- [test/rename.mjs](../test/rename.mjs)
- [test/replay.mjs](../test/replay.mjs)
- [test/run-browser.mjs](../test/run-browser.mjs)
- [test/server.mjs](../test/server.mjs)
- [test/suite.mjs](../test/suite.mjs)
- [test/trust.mjs](../test/trust.mjs)
- [test/v2.mjs](../test/v2.mjs)

### Dokumentation

- [README.md](../README.md)
- [docs/be9-migration.md](../docs/be9-migration.md)
- [docs/envelope-state.md](../docs/envelope-state.md)
- [docs/group-epochs.md](../docs/group-epochs.md)
- [docs/lifecycle.md](../docs/lifecycle.md)
- [docs/todo6-9.md](../docs/todo6-9.md)
- [docs/v2-profile.md](../docs/v2-profile.md)

### Build, Paketmetadaten und Logo

- [assets/be9-logo.svg](../assets/be9-logo.svg)
- [build/rollup.config.js](../build/rollup.config.js)
- [build/rollup.iife.config.js](../build/rollup.iife.config.js)
- [package-lock.json](../package-lock.json)
- [package.json](../package.json)

### Generierte Build-Ausgaben

- [dist/bundle.min.js](../dist/bundle.min.js)
- [dist/bundle.mjs](../dist/bundle.mjs)
