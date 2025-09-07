import os, json, argparse, hashlib

HERE = os.path.dirname(__file__)
ANALYSIS_DIR = os.path.dirname(HERE)
SCAN_DIR = os.path.join(ANALYSIS_DIR, "scan")

def sha256_short(b: bytes, n=12):
    return hashlib.sha256(b).hexdigest()[:n]

def load_backup(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data

def extract_payload(data):
    # payload im JSON → base64? oder raw-binary-string?
    payload = data.get("payload")
    if not payload:
        return None
    # Payload kann ein String mit Binärdaten sein
    if isinstance(payload, str):
        # als Zeichenkette (hex oder raw) → in Bytes umwandeln
        try:
            return payload.encode("latin-1")
        except Exception:
            return payload.encode("utf-8", "replace")
    if isinstance(payload, bytes):
        return payload
    return None

def split_blocks(blob, blocksize=65536):
    """ Teilt Payload in feste Blöcke (z. B. 64 KB) zum Vergleich """
    return [blob[i:i+blocksize] for i in range(0, len(blob), blocksize)]

def main():
    ap = argparse.ArgumentParser(description="Vergleicht zwei QC-Backups blockweise")
    ap.add_argument("file1", help="Backup A (JSON)")
    ap.add_argument("file2", help="Backup B (JSON)")
    ap.add_argument("--blocksize", type=int, default=65536, help="Blockgröße (default 64 KB)")
    args = ap.parse_args()

    data1 = load_backup(args.file1)
    data2 = load_backup(args.file2)

    payload1 = extract_payload(data1)
    payload2 = extract_payload(data2)

    if payload1 is None or payload2 is None:
        print("❌ Konnte Payload in den Backups nicht finden.")
        return

    if len(payload1) != len(payload2):
        print(f"⚠️ Unterschiedliche Payload-Länge: {len(payload1)} vs {len(payload2)}")

    blocks1 = split_blocks(payload1, args.blocksize)
    blocks2 = split_blocks(payload2, args.blocksize)

    total = min(len(blocks1), len(blocks2))
    diffs = 0
    print(f"📊 Vergleich: {args.file1} vs {args.file2}")
    print(f"   Payload-Größe: {len(payload1)} Bytes, in {len(blocks1)} Blöcken à {args.blocksize}")

    for i in range(total):
        h1 = sha256_short(blocks1[i])
        h2 = sha256_short(blocks2[i])
        if h1 != h2:
            print(f"❌ Block {i:03d} unterscheidet sich | {h1} vs {h2}")
            diffs += 1
        else:
            print(f"✅ Block {i:03d} identisch ({h1})")

    print(f"\nErgebnis: {diffs} unterschiedliche Blöcke von {total}")

if __name__ == "__main__":
    main()
