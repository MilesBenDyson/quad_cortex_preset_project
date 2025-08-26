import os, json, argparse, hashlib, zlib, io, zipfile

HERE = os.path.dirname(__file__)
ANALYSIS_DIR = os.path.dirname(HERE)
RAW_DIR = os.path.join(ANALYSIS_DIR, "members_zlib_raw")
OUT_DIR = os.path.join(ANALYSIS_DIR, "members_attempts_deep")
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

def save_result(base, data: bytes):
    kind = detect_kind(data)
    if kind == "zip":
        path = base + ".zip"
        with open(path, "wb") as f: f.write(data)
        # optional: auspacken
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

    path = base + ".bin"
    with open(path, "wb") as f: f.write(data)
    return path, "bin"

def stream_try_decompress(data: bytes, offset: int, wbits: int, min_bytes:int, chunk:int=4096):
    """
    Versucht streaming-basiert zu dekomprimieren (robuster als one-shot).
    Gibt (out_bytes | None, consumed_bytes) zurück.
    """
    try:
        d = zlib.decompressobj(wbits)
        out = bytearray()
        pos = offset
        # in Stücken füttern, bis Fehler kommt oder Ende erreicht
        while pos < len(data) and len(out) < MAX_OUTPUT_BYTES:
            nxt = min(pos + chunk, len(data))
            piece = data[pos:nxt]
            if not piece:
                break
            try:
                out.extend(d.decompress(piece, MAX_OUTPUT_BYTES - len(out)))
                pos = nxt
                # wenn der Stream sauber endet:
                if d.unused_data:
                    break
            except zlib.error:
                # Stream ist kaputt/endet hier → abbrechen, Partial-Out behalten
                break
        if len(out) >= min_bytes:
            return bytes(out), (pos - offset)
        return None, 0
    except Exception:
        return None, 0

def load_manifest():
    with open(MANIFEST, "r", encoding="utf-8") as f:
        return json.load(f)

def pick_blocks(manifest, top=None, indices=None):
    if indices:
        idxset = set(indices)
        return [r for r in manifest if r["index"] in idxset]
    sorted_ = sorted(manifest, key=lambda r: r["size"], reverse=True)
    return sorted_[:top] if top else sorted_

def main():
    ap = argparse.ArgumentParser(description="Deep brute-force zlib-like streams in raw blocks (offset + wbits + streaming).")
    ap.add_argument("--top", type=int, default=3, help="Größte N Blöcke testen (Default: 3)")
    ap.add_argument("--indices", type=str, help="Konkrete Block-Indizes, Komma-separiert (z.B. 45,36,188)")
    ap.add_argument("--max-offset", type=int, default=4096, help="Offsets 0..N-1 pro Block testen")
    ap.add_argument("--step", type=int, default=8, help="Offset-Schrittweite (Default: 8)")
    ap.add_argument("--min-bytes", type=int, default=512, help="Minimale Ausgabegröße, um als Treffer zu zählen")
    ap.add_argument("--wbits", type=str, default="-15,-14,-13,-12,-11,-10,-9,-8,8,9,10,11,12,13,14,15,31,47",
                    help="wbits-Kandidaten (Komma, inkl. raw/auto/gzip)")
    args = ap.parse_args()

    ensure_dir(OUT_DIR)
    manifest = load_manifest()
    indices = None
    if args.indices:
        indices = [int(x.strip()) for x in args.indices.split(",") if x.strip().isdigit()]

    targets = pick_blocks(manifest, top=args.top, indices=indices)
    print(f"🎯 Targets: {len(targets)} | wbits={args.wbits} | max_offset={args.max_offset} | step={args.step} | min_bytes={args.min_bytes}")

    wbits_list = [int(x.strip()) for x in args.wbits.split(",")]

    for rec in targets:
        idx, size, off = rec["index"], rec["size"], rec["offset"]
        base_dir = os.path.join(OUT_DIR, f"idx_{idx}_off_{off}_size_{size}")
        ensure_dir(base_dir)
        print(f"\n—— Block idx={idx} | file={os.path.basename(rec['file'])} | size={size} ——")

        with open(rec["file"], "rb") as f:
            blob = f.read()

        hits = []
        for o in range(0, min(args.max_offset, len(blob)), args.step):
            for wb in wbits_list:
                out, consumed = stream_try_decompress(blob, o, wb, min_bytes=args.min_bytes)
                if out:
                    tag = f"ok_off_{o}_w{wb}_{sha16(out)}"
                    base = os.path.join(base_dir, tag)
                    path, kind = save_result(base, out)
                    hits.append({"offset": o, "wbits": wb, "kind": kind,
                                 "length": len(out), "consumed": consumed,
                                 "file": os.path.basename(path)})
                    print(f"  ✅ off={o:4d} wbits={wb:3d} kind={kind:<5} len={len(out):8d} → {os.path.basename(path)}")

        if not hits:
            print("  ❌ keine Treffer in diesem Bereich.")
        else:
            with open(os.path.join(base_dir, "_hits.json"), "w", encoding="utf-8") as f:
                json.dump(hits, f, ensure_ascii=False, indent=2)

if __name__ == "__main__":
    main()
