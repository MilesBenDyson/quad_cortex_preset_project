import os, json, argparse

HERE = os.path.dirname(__file__)
SCAN_DIR = os.path.join(os.path.dirname(HERE), "scan")
META_DIR = os.path.join(SCAN_DIR, "Metadata")

def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def extract_meta(backup_path, meta_path=None):
    # 1) aus Hauptdatei lesen
    data = load_json(backup_path)
    created = data.get("created") or data.get("date") or "?"
    author = data.get("author") or data.get("author_id") or "?"
    name = data.get("name") or os.path.basename(backup_path)

    # 2) Fallback: Meta-Datei
    if (created == "?" or author == "?") and meta_path and os.path.exists(meta_path):
        meta = load_json(meta_path)
        created = created if created != "?" else meta.get("created") or meta.get("downloadTime") or "?"
        author = author if author != "?" else meta.get("author") or "?"
        # id oder sonstige Infos
        meta_id = meta.get("id")
    else:
        meta_id = None

    return created, author, name, meta_id

def main():
    ap = argparse.ArgumentParser(description="QC Backup Explorer – Übersicht aller Backups + Metadaten")
    ap.add_argument("--dir", default=SCAN_DIR, help="Backup-Verzeichnis (default: scan/)")
    args = ap.parse_args()

    backups = [f for f in os.listdir(args.dir) if f.endswith(".json") and not f.endswith("_meta.json")]
    if not backups:
        print("Keine Backups gefunden.")
        return

    print(f"📂 Gefundene Backups in {args.dir}:")
    for b in sorted(backups):
        backup_path = os.path.join(args.dir, b)

        # passendes _meta.json suchen
        base = b.replace(".json", "")
        candidates = [
            os.path.join(META_DIR, base + "_meta.json"),
            os.path.join(args.dir, base + "_meta.json"),
        ]
        meta_path = next((p for p in candidates if os.path.exists(p)), None)

        created, author, name, meta_id = extract_meta(backup_path, meta_path)
        size = os.path.getsize(backup_path)

        line = f"- {b} | {size/1024:.1f} KB | created={created} | author={author} | name={name}"
        if meta_id:
            line += f" | id={meta_id[:8]}…"  # nur die ersten 8 Zeichen anzeigen
        print(line)

if __name__ == "__main__":
    main()
