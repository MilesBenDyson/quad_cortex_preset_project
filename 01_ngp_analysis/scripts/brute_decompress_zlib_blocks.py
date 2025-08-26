import os, json, argparse, hashlib, zlib, io, zipfile

# Pfade (relativ zur Skript-Position)
HERE = os.path.dirname(__file__)
ANALYSIS_DIR = os.path.dirname(HERE)
RAW_DIR = os.path.join(ANALYSIS_DIR, "members_zlib_raw")
OUT_DIR = os.path.join(ANALYSIS_DIR, "members_attempts")
MANIFEST = os.path.join(RAW_DIR, "_manifest_zlib_raw.json")

MAX_OUTPUT_BYTES = 50_000_000  # 50 MB Schutzlimit

def sha16(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]

def detect_kind(b: bytes) -> str:
    if b.startswith(b"PK\x03\x04"): return "zip"
    if b.startswith(b"\x1f\x8b\x08"): return "gzip"
    h = b.lstrip()[:1]
    if h in (b"{", b"["):
        try:
            json.loads(b.decode("utf-8"))
            return "json"
        except Exception:
            return "text_like"
    return "bin"

def ensure_dir(p): os.makedirs(p, exist_ok=True)

def save_result(base, data: bytes, note: str):
    kind = detect_kind(data)
    if kind == "zip":
        path = base + ".zip"
        with open(path, "wb") as f: f.write(data)
        # optional: entpacken
        zdir = base + "_zip"
        ensure_dir(zdir)
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                zf.extractall(zdir)
        except Exception as e:
            with open(base + "_zip_error.txt", "w", encoding="utf-8") as f:
                f.write(str(e))
        return path, kind

    if kind in ("json", "text_like"):
        # JSON hübsch, sonst Text
        try:
            obj = json.loads(data.decode("utf-8"))
            path = base + ".json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
            return path, "json"
        except Exception:
            path = base + ".txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write(data.decode("utf-8", "replace"))
            return path, "text"

    # default BIN
    path = base + ".bin"
    with open(path, "wb") as f: f.write(data)
    return path, "bin"

def try_decompress(data: bytes, offset: int, wbits: int):
    # Nutze decompressobj, damit wir bei korrupten Enden nicht crashen
    try:
        decomp = zlib.decompressobj(wbits)
        out = decomp.decompress(data[offset:], MAX_OUTPUT_BYTES)
        out += decomp.flush()
        if len(out) == 0:
            return None
        return out
    except Exception:
        return None

def load_manifest():
    with open(MANIFEST, "r", encoding="utf-8") as f:
        return json.load(f)

def pick_blocks(manifest, top=None, indices=None):
    if indices:
        idxset = set(indices)
        return [r for r in manifest if r["index"] in idxset]
    # sonst nach Größe sortieren
    sorted_ = sorted(manifest, key=lambda r: r["size"], reverse=True)
    return sorted_[:top] if top else sorted_

def main():
    ap = argparse.ArgumentParser(description="Brute-force ZLIB Dekompression auf raw Blocks")
    ap.add_argument("--top", type=int, default=3, help="Größte N Blöcke testen (Default: 3)")
    ap.add_argument("--indices", type=str, help="Konkrete Block-Indizes, Komma-separiert (z.B. 45,36)")
    ap.add_argument("--max-offset", type=int, default=128, help="Offset-Scan (Bytes) ab 0..max-offset")
    ap.add_argument("--wbits", type=str, default="15,-15,31,47",
                    help="wbits-Kombinationen (Komma): 15(zlib),-15(raw),31(gzip),47(auto)")
    args = ap.parse_args()

    ensure_dir(OUT_DIR)
    manifest = load_manifest()
    indices = None
    if args.indices:
        indices = [int(x.strip()) for x in args.indices.split(",") if x.strip().isdigit()]

    targets = pick_blocks(manifest, top=args.top, indices=indices)
    print(f"📦 Zu testen: {len(targets)} Blöcke | wbits={args.wbits} | max_offset={args.max_offset}")

    wbits_list = [int(x.strip()) for x in args.wbits.split(",")]

    for rec in targets:
        idx = rec["index"]
        fpath = rec["file"]
        size = rec["size"]
        base_dir = os.path.join(OUT_DIR, f"idx_{idx}_off_{rec['offset']}_size_{size}")
        ensure_dir(base_dir)
        print(f"\n—— Block idx={idx}  off={rec['offset']}  size={size}  sha={rec['sha256_16']} ——")

        with open(fpath, "rb") as f:
            blob = f.read()

        hits = []
        for off in range(0, min(args.max_offset, len(blob))):
            for wb in wbits_list:
                out = try_decompress(blob, off, wb)
                if out:
                    tag = f"ok_off_{off}_w{wb}_{sha16(out)}"
                    base = os.path.join(base_dir, tag)
                    path, kind = save_result(base, out, note=f"offset={off},wbits={wb}")
                    hits.append((off, wb, kind, len(out), os.path.basename(path)))
                    print(f"  ✅ Treffer: off={off:3d}  wbits={wb:3d}  kind={kind:<5}  len={len(out):8d}  → {os.path.basename(path)}")

        if not hits:
            print("  ❌ keine gültige Dekompression in diesem Scanbereich gefunden.")
        else:
            # kleine Zusammenfassung speichern
            with open(os.path.join(base_dir, "_hits.json"), "w", encoding="utf-8") as f:
                json.dump([
                    {"offset": off, "wbits": wb, "kind": kind, "length": ln, "file": fn}
                    for (off, wb, kind, ln, fn) in hits
                ], f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()
