import os, sys, json, base64, binascii, hashlib, argparse, io, gzip, zipfile

# Optional: Zstandard unterstützen, wenn installiert
try:
    import zstandard as zstd  # pip install zstandard
except Exception:
    zstd = None

MAGICS = {
    b"PK\x03\x04": "zip",
    b"\x1f\x8b": "gzip",
    b"\x28\xb5\x2f\xfd": "zstd",
    b"RIFF": "wav",
    b"fLaC": "flac",
    b"OggS": "ogg",
}

def detect_format(b: bytes) -> str:
    for sig, name in MAGICS.items():
        if b.startswith(sig):
            return name
    # JSON? (heuristisch)
    head = b.lstrip()[:1]
    if head in (b"{", b"["):
        try:
            json.loads(b.decode("utf-8"))
            return "json"
        except Exception:
            pass
    return "binary"

def write_file(path: str, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    return path

def extract_zip(raw: bytes, out_dir: str):
    zdir = os.path.join(out_dir, "payload_contents")
    os.makedirs(zdir, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        zf.extractall(zdir)
        names = zf.namelist()
    return zdir, names

def try_gzip_decompress(raw: bytes) -> bytes | None:
    try:
        return gzip.decompress(raw)
    except Exception:
        return None

def try_zstd_decompress(raw: bytes) -> bytes | None:
    if not zstd:
        return None
    try:
        dctx = zstd.ZstdDecompressor()
        return dctx.decompress(raw)
    except Exception:
        return None

def summarize(path: str, raw: bytes, label: str):
    sha = hashlib.sha256(raw).hexdigest()
    print(f"→ {label}: {path}  [{len(raw)} bytes]  sha256={sha[:16]}…")

def main():
    ap = argparse.ArgumentParser(description="QC backup.json → payload extrahieren & erkennen")
    ap.add_argument("input", help="Pfad zu backup.json")
    ap.add_argument("-o", "--out", default="01_ngp_analysis/extracted", help="Ausgabeordner")
    args = ap.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        doc = json.load(f)

    if "payload" not in doc:
        print("Kein 'payload' im JSON gefunden.")
        sys.exit(1)

    # 1) Base64 → Bytes
    try:
        raw = base64.b64decode(doc["payload"])
    except binascii.Error:
        print("payload ist keine gültige Base64-Daten.")
        sys.exit(1)

    os.makedirs(args.out, exist_ok=True)
    raw_path = os.path.join(args.out, "payload.raw")
    write_file(raw_path, raw)
    summarize(raw_path, raw, "RAW")

    # 2) Typ erkennen
    kind = detect_format(raw)
    print(f"Erkannter Typ: {kind}")

    # 3) Handling pro Typ
    if kind == "zip":
        zip_path = os.path.join(args.out, "payload.zip")
        write_file(zip_path, raw)
        summarize(zip_path, raw, "ZIP")
        zdir, names = extract_zip(raw, args.out)
        print(f"ZIP entpackt nach: {zdir}")
        for n in names[:20]:
            print(f"  - {n}")
        if len(names) > 20:
            print(f"  … (+{len(names)-20} weitere)")

    elif kind == "gzip":
        gz_path = os.path.join(args.out, "payload.gz")
        write_file(gz_path, raw)
        summarize(gz_path, raw, "GZIP")
        dec = try_gzip_decompress(raw)
        if dec:
            dec_path = os.path.join(args.out, "payload_gzip_dec.bin")
            write_file(dec_path, dec)
            summarize(dec_path, dec, "GZIP→BIN")
            sub_kind = detect_format(dec)
            print(f"Innerer Typ nach GZIP: {sub_kind}")
            # Falls inneres wiederum ZIP/JSON ist, kann man hier rekursiv weiter verarbeiten.

    elif kind == "zstd":
        zstd_path = os.path.join(args.out, "payload.zst")
        write_file(zstd_path, raw)
        summarize(zstd_path, raw, "ZSTD")
        if zstd:
            dec = try_zstd_decompress(raw)
            if dec:
                dec_path = os.path.join(args.out, "payload_zstd_dec.bin")
                write_file(dec_path, dec)
                summarize(dec_path, dec, "ZSTD→BIN")
                sub_kind = detect_format(dec)
                print(f"Innerer Typ nach ZSTD: {sub_kind}")
        else:
            print("Hinweis: Für ZSTD bitte 'pip install zstandard' installieren.")

    elif kind == "json":
        json_path = os.path.join(args.out, "payload.json")
        write_file(json_path, raw)
        print(f"JSON gespeichert: {json_path}")

    elif kind in ("wav", "flac", "ogg"):
        ext = {"wav": ".wav", "flac": ".flac", "ogg": ".ogg"}[kind]
        path = os.path.join(args.out, f"payload{ext}")
        write_file(path, raw)
        summarize(path, raw, kind.upper())

    else:
        # Unbekannt → trotzdem speichern (haben wir schon als payload.raw)
        print("Unbekannter Binärtyp. Rohdaten liegen als payload.raw vor.")
        # Bonus-Heuristik: Falls eingebettetes ZIP erkennbar → suchen
        idx = raw.find(b"PK\x03\x04")
        if idx != -1:
            print(f"Gefundenes eingebettetes ZIP bei Offset {idx}. Extrahiere…")
            embedded = raw[idx:]
            zip_path = os.path.join(args.out, "payload_embedded.zip")
            write_file(zip_path, embedded)
            try:
                zdir, names = extract_zip(embedded, args.out)
                print(f"Eingebettetes ZIP entpackt nach: {zdir}")
                for n in names[:20]:
                    print(f"  - {n}")
            except Exception as e:
                print(f"ZIP-Extraktion fehlgeschlagen: {e}")

if __name__ == "__main__":
    main()
