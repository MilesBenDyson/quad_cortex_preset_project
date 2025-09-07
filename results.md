\# Quad Cortex Backup Analysis – Ergebnisse



\## 🎯 Projektziel

Untersuchung der \*\*Quad Cortex Backup-Dateien\*\* (`.json`) mit dem Ziel:

\- Aufbau einer Toolchain zur Analyse von Presets

\- Versuch, die internen Preset-Daten (Payload) zu entschlüsseln

\- Erstellung eines praktischen Backup-Explorers für Metadaten



---



\## ✅ Erreichte Schritte



1\. \*\*Projektstruktur \& GitHub\*\*

&nbsp;  - Repository angelegt (`quad\_cortex\_preset\_project`)

&nbsp;  - Skriptordner für Analyse (`01\_ngp\_analysis`) und Generator (`02\_ngp\_generator`)



2\. \*\*Backup-Parsing\*\*

&nbsp;  - Haupt-Backup-Dateien (`Local backup X.json`) können eingelesen werden

&nbsp;  - Metadaten (Author, Name, Erstellungszeit) werden ausgelesen und in einer Übersicht dargestellt



3\. \*\*Payload-Extraktion\*\*

&nbsp;  - Payload (`payload.raw`) erfolgreich aus den Backups extrahiert

&nbsp;  - Analyse mit String-Suche, Magic-Bytes-Scans und Block-Segmentierung



4\. \*\*Kompressions-/Dekompressions-Versuche\*\*

&nbsp;  - Tests mit GZIP, ZLIB, ZSTD

&nbsp;  - Kein Erfolg → Daten sind nicht komprimiert, sondern verschlüsselt



5\. \*\*Statistische Analyse\*\*

&nbsp;  - Entropie-Analyse der Payload-Blöcke: ~7.996 (nahe Maximum von 8.0)

&nbsp;  - Ergebnis: starker Hinweis auf \*\*Verschlüsselung\*\* statt Kompression



6\. \*\*Differential-Backup-Test\*\*

&nbsp;  - Zwei Backups erstellt:

&nbsp;    - Backup A: Preset mit Gain 5.5

&nbsp;    - Backup B: identisches Preset, Gain 6.0

&nbsp;  - Ergebnis: \*\*kompletter Payload unterschiedlich\*\*  

&nbsp;    → spricht für Verschlüsselung mit neuem Schlüssel/IV pro Backup



---



\## 📊 Erkenntnisse



\- Klartext-Metadaten (z. B. Author, Datum, Name) sind frei zugänglich

\- Payload ist vollständig \*\*verschlüsselt\*\* (nicht nur obfuskiert oder komprimiert)

\- Änderungen in Presets führen zu komplett neuen Ciphertext-Blöcken

\- Ohne Zugriff auf den Schlüssel (z. B. via Firmware/Software-RE) ist eine Dekodierung aktuell nicht möglich



---



\## 🚀 Nützliche Ergebnisse fürs Portfolio



\- \*\*Backup Explorer Tool\*\* (`backup\_explorer.py`)  

&nbsp; → Listet alle Backups + Metadaten tabellarisch auf

\- \*\*Diff Tool\*\* (`backup\_diff.py`)  

&nbsp; → Vergleicht zwei Backups blockweise, zeigt Unterschiede an

\- \*\*Analyse-Skripte\*\* für:

&nbsp; - Payload-Extraktion

&nbsp; - String-Suche

&nbsp; - Entropie- und Blockstatistik



---



\## 📌 Fazit



Dieses Projekt zeigt einen vollständigen \*\*Reverse-Engineering-Ansatz\*\*:

\- Struktur der Dateien nachvollzogen

\- Metadaten extrahiert

\- Payload analysiert und klassifiziert

\- Einschränkung erkannt (Verschlüsselung als technische Barriere)



Obwohl die Payload nicht entschlüsselt werden konnte, ist das Ergebnis ein \*\*wertvolles Analyse-Framework\*\*:

\- Demonstriert methodisches Vorgehen (Extraction → Analysis → Diff)

\- Schafft praktische Tools (Explorer, Diff-Tool)

\- Bietet eine klare Basis für künftige Arbeiten (z. B. Firmware-RE, Kryptanalyse)



---



\## 🔮 Next Steps (optional)



\- Reverse Engineering von \*\*Cortex Control\*\* oder QC Firmware

\- Suche nach bekannten Schlüsseln oder Hardcoded IVs

\- Erweiterung des Explorers zu einem vollständigen \*\*Backup Manager\*\*



