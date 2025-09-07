# Quad Cortex Preset Project

Dieses Projekt untersucht die **Backup- und Preset-Dateien** (`.json`, `.ngp`) des Neural DSP Quad Cortex.

Ziel war es:
- Preset-Ideen als `.ngp` Dateien nutzbar zu machen  
- den Aufbau der QC-Backups zu analysieren  
- Tools zur Verwaltung und Analyse von Backups zu entwickeln  

---

## 📂 Projektstruktur

### 01_ngp_analysis
Analyse von existierenden Backup-Dateien:

- **Backup Explorer** (`backup_explorer.py`)  
  → Listet Backups inkl. Metadaten (Author, Datum, Name)

- **Diff Tool** (`backup_diff.py`)  
  → Vergleicht Payloads blockweise und zeigt Unterschiede

- Weitere Skripte:  
  - Payload-Extraktion  
  - String-Suche  
  - Entropie-Analyse  

### 02_ngp_generator
Geplant: Automatische Erzeugung von Presets  
(zurzeit noch nicht umgesetzt)

---

## ✅ Ergebnisse

- Metadaten aus Backups sind im Klartext lesbar  
- Payload ist **vollständig verschlüsselt** (nicht nur komprimiert/obfuskiert)  
- Selbst kleine Änderungen im Preset führen zu einem komplett neuen Ciphertext  
- Ohne Kenntnis des Schlüssels ist eine Dekodierung aktuell nicht möglich  

👉 Detaillierte Analyse siehe [RESULTS.md](results.md)

---

## 🚀 Nutzen fürs Portfolio

Dieses Projekt zeigt:
- Methodisches Vorgehen bei Datei-/Backup-Analyse  
- Entwicklung praktischer Python-Tools  
- Dokumentation von Grenzen und Erkenntnissen  

Damit ist es ein starkes **Showcase-Projekt** für Reverse Engineering & Python-Tooling.  

---

## 🔮 Nächste Schritte (optional)

- Reverse Engineering von **Cortex Control** oder Firmware  
- Suche nach bekannten Schlüsseln oder Hardcoded IVs  
- Ausbau des Explorers zu einem vollständigen **Backup Manager**  
