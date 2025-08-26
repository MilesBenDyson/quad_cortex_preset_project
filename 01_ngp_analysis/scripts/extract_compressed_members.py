import os, io, re, json, argparse, hashlib, gzip, zipfile, zlib

# ---- Einstellungen
DEFAULT_INPUT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "extracted", "payload.raw")
DEFAULT_OUT   = os.path.join(os.path.dirname(os.path.dirname(__file__)), "members")

def ensure_dir(p):
    os.makedirs(p, exist_ok=True)

def sha16(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]

def detect_kind(b: bytes) -> str:
    if b.startswith(b"PK\x03\x04"): return "zip"
    if b.startswith(b"\x1f\x8b\x08"): return "gzip"
    head = b.lstrip()[:1]
    if head in (b"{", b"["):
        try:
            json.loads(b.decode("utf-8"))
            return "json"
        except Exception:
            pass
    return "bin"

def save_bytes(path, data: bytes):
    ensure_dir(os.path.dirname(path))
    with open(path, "wb") as f: f.write(data)
    return path

def save_text_or_json(basepath, data: bytes):
    # JSON hübsch, sonst .txt
    try:
        txt = data.decode("utf-8")
        try:
            obj = json.loads(txt)
            path = basepath + ".json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
            return path, "json"
        except Exception:
            path = basepath + ".txt"
            with open(path, "w", encoding="utf-8") as f:
                f.write(txt)
            return path, "text"
    except UnicodeDecodeError:
        path = basepath + ".bin"
        with open(path, "wb") as f:
            f.write(data)
        return path, "bin"

def try_decompress_gzip_from(data: bytes, offset: int):
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data[offset:])) as gz:
            return gz.read()
    except Exception:
        return None

def try_decompress_zlib_from(data: bytes, offset: int):
    # Versuche mit zlib-Header (wbits=15) und „raw deflate“ (wbits=-15)
    for wbits in (15, -15):
        try:
            return zlib.decompress(data[offset:], wbits)
        except Exception:
            pass
    return None

def extract_zip_members(raw: bytes, out_dir: str, tag: str):
    # Entpackt ZIP in Unterordner
    zdir = os.path.join(out_dir, f"zip_{tag}")
    ensure_dir(zdir)
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        zf.extractall(zdir)
        names = zf.namelist()
    return zdir, names

def main():
    ap = argparse.ArgumentParser(description="Extract embedded GZIP/ZLIB members from payload.raw")
    ap.add_argument("-i", "--input", default=DEFAULT_INPUT, help="Pfad zu payload.raw")
    ap.add_argument("-o", "--out",   default=DEFAULT_OUT,   help="Ausgabeordner für extrahierte Members")
    ap.add_argument("--max", type=int, default=200, help="Max. Versuche pro Typ (gzip/zlib)")
    args = ap.parse_args()

    ensure_dir(args.out)
    with open(args.input, "rb") as f:
        blob = f.read()

    print(f"🔎 Datei: {args.input}  Größe: {len(blob)} bytes  sha256:{sha16(blob)}")

    # ---- GZIP: Signatur 1F 8B 08 suchen
    gzip_hits = [m.start() for m in re.finditer(b"\x1f\x8b\x08", blob)]
    print(f"[scan] GZIP-Signaturen gefunden: {len(gzip_hits)}")
    ok_gzip = 0
    for i, off in enumerate(gzip_hits[:args.max]):
        dec = try_decompress_gzip_from(blob, off)
        if not dec:
            continue
        ok_gzip += 1
        tag = f"gzip_off_{off}_#{i:03d}_{sha16(dec)}"
        base = os.path.join(args.out, tag)
        kind = detect_kind(dec)
        if kind == "zip":
            # ZIP extrahieren
            zdir, names = extract_zip_members(dec, args.out, tag)
            print(f"[GZIP→ZIP] off={off} → {zdir}  ({len(names)} Dateien)")
        elif kind == "json":
            path, _ = save_text_or_json(base, dec)
            print(f"[GZIP→JSON] off={off} → {path}")
        else:
            path = base + ".bin"
            save_bytes(path, dec)
            print(f"[GZIP→BIN ] off={off} → {path} ({len(dec)} bytes)")

    print(f"[✓] Erfolgreiche GZIP-Extraktionen: {ok_gzip}/{len(gzip_hits)}")

    # ---- ZLIB: typische Header 78 01 / 78 9C / 78 DA
    zlib_hits = [m.start() for m in re.finditer(b"\x78[\x01\x9c\xda]", blob)]
    print(f"[scan] ZLIB-Signaturen gefunden: {len(zlib_hits)}")
    ok_zlib = 0
    for i, off in enumerate(zlib_hits[:args.max]):
        dec = try_decompress_zlib_from(blob, off)
        if not dec:
            continue
        ok_zlib += 1
        tag = f"zlib_off_{off}_#{i:03d}_{sha16(dec)}"
        base = os.path.join(args.out, tag)
        kind = detect_kind(dec)
        if kind == "zip":
            zdir, names = extract_zip_members(dec, args.out, tag)
            print(f"[ZLIB→ZIP ] off={off} → {zdir}  ({len(names)} Dateien)")
        elif kind == "json":
            path, _ = save_text_or_json(base, dec)
            print(f"[ZLIB→JSON] off={off} → {path}")
        else:
            path = base + ".bin"
            save_bytes(path, dec)
            print(f"[ZLIB→BIN ] off={off} → {path} ({len(dec)} bytes)")

    print(f"[✓] Erfolgreiche ZLIB-Extraktionen: {ok_zlib}/{len(zlib_hits)}")
    print(f"📂 Ausgabeordner: {args.out}")

if __name__ == "__main__":
    main()
