Auftrag: Härte die Gruppenschlüssel-API, ohne ein Mitgliederverwaltungs-
oder MLS-System zu implementieren.

Implementierung:

1. Trenne im neuen Profil Gruppenschlüssel klar von asymmetrischen
   Public-/Private-Key-Datensätzen.
2. Verwende für neue Gruppenepochen frisch erzeugtes symmetrisches
   256-Bit-Schlüsselmaterial mit einem dokumentierten Verwendungsprofil.
3. groupID und Epoche strukturiert speichern, nicht über mehrdeutige
   zusammengesetzte Strings als einziges Datenmodell.
4. Die Anwendung übergibt die Empfänger einer neuen Epoche ausdrücklich.
   Diese Liste dient nur zur Erstellung verschlüsselter Key-Pakete.
   Keine Rollen, Einladungen oder eigene Mitglieder-Datenbank hinzufügen.
5. Für jeden freigegebenen Empfänger ein verschlüsseltes Übergabepaket
   über die bereits abgesicherte paarweise Engine-Funktion erzeugen.
   Separaten KDF-/AAD-Verwendungszweck für Key-Wrapping nutzen.
6. Rohes Gruppenschlüsselmaterial darf die öffentliche API nicht verlassen.
   Für die Erstellung notwendiges exportierbares oder rohes Material
   ausschließlich kurzzeitig intern halten.
   Persistierte operative Schlüssel nicht exportierbar speichern.
7. Importierte Pakete an erwarteten Aussteller, Empfänger, Gruppe
   und Epoche binden. Vor erfolgreicher Prüfung nichts aktivieren.
8. Alte Epochen nicht still überschreiben oder als aktuelle aktivieren.
   Archiventschlüsselung und aktive Verschlüsselung unterscheiden.
9. Eine neue Epoche muss unabhängig erzeugt werden, nicht aus einem
   alten Gruppengeheimnis ableitbar sein.
10. Getter liefern öffentliche Metadaten, keine Gruppen-Secrets.
11. Bisherige ECDH-Gruppendaten ausschließlich explizit als Legacy behandeln.

Tests:
Drei isolierte Teilnehmer, verschlüsselte Schlüsselübergabe, falscher
Empfänger, manipulierte Pakete und Ausschluss vom nächsten Epochenwechsel.

Dokumentieren:
Wer ein Gruppengeheimnis besitzt, kann es weitergeben.
Gemeinsame Gruppenschlüssel beweisen keine individuelle Autorenschaft.
Eine neue Epoche entzieht niemandem bereits bekannte alte Schlüssel.
