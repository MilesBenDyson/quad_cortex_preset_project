import os, re, io, json, gzip, zipfile, argparse, hashlib, base64, binascii
from typing import List, Tuple

# Optional: Zstandard (empfohlen)
try:
    import zstandard as zstd  # pip install zstandard
except Exception:
    zstd = None

PRINTABLE = bytes(range(0x20, 0x7f)) + b"\t"
MAGICS = {
    b"PK\x03\x04": "zip",
    b"\x1f\x8b":   "gzip",
    b"\x28\xb5\x2f\xfd": "zstd",
    b"RIFF": "wav",
    b"fLaC": "flac",
    b"OggS": "ogg",
}

def project_paths():
    # script: .../01_ngp_analysis/scripts/scan_payload.py
    here = os.path.dirname(__file__)
    analysis_dir = os.path.dirname(here)                  # .../01_ngp_analysis
    extracted_dir = os.path.join(analysis_dir, "extracted")
    return here, analysis_dir, extracted_dir

def find_all(data: bytes, needle: bytes) -> List[int]:
    pos, hits = 0, []
    while True:
        pos = data.find(needle, pos)
        if pos == -1: break
        hits.append(pos)
        pos += 1
    return hits

def ascii_strings(data: bytes, min_len=5) -> List[Tuple[int, bytes]]:
    s, out, start = [], [], None
    for i, b in enumerate(data):
        if b in PRINTABLE:
            if start is None: start = i
            s.append(b)
        else:
            if start is not None and len(s) >= min_len:
                out.append((start, bytes(s)))
            s, start = [], None
    if start is not None and len(s) >= min_len:
        out.append((start, bytes(s)))
    return out

def utf16le_strings(data: bytes, min_len=5) -> List[Tuple[int, bytes]]:
    out = []
    i = 0
    while i + 2*min_len <= len(data):
        j = i
        ok = 0
        buf = []
        while j + 1 < len(data):
            ch = data[j]
            z  = data[j+1]
            if z == 0 and (ch in PRINTABLE):
                buf.append(ch)
                ok += 1
                j += 2
            else:
                break
        if ok >= min_len:
            out.append((i, bytes(buf)))
            i = j
        else:
            i += 1
    return out

def try_gzip(raw: bytes):
    try:
        return gzip.decompress(raw)
    except Exception:
        return None

def try_zstd(raw: bytes):
    if not zstd:
        return None
    try:
        d = zstd.ZstdDecompressor()
        return d.decompress(raw)
    except Exception:
        return None

def write(path: str, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

def write_text(path: str, text: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)

def hexdump(data: bytes, offset: int, length: int = 256) -> str:
    chunk = data[offset:offset+length]
    lines = []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i+16]
        hexpart = " ".join(f"{b:02x}" for b in row)
        asciip = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{offset+i:08x}  {hexpart:<48}  {asciip}")
    return "\n".join(lines)

def detect_kind(b: bytes) -> str:
    for sig, name in MAGICS.items():
        if b.startswith(sig):
            return name
    head = b.lstrip()[:1]
    if head in (b"{", b"["):
        try:
            json.loads(b.decode("utf-8"))
            return "json"
        except Exception:
            pass
    return "binary"

def main():
    here, analysis_dir, extracted_dir = project_paths()

    ap = argparse.ArgumentParser(description="Scan QC payload.raw for embedded artifacts.")
    ap.add_argument("-i", "--input", default=os.path.join(extracted_dir, "payload.raw"),
                    help="Pfad zur payload.raw (Default: 01_ngp_analysis/extracted/payload.raw)")
    ap.add_argument("-o", "--out", default=os.path.join(analysis_dir, "scan"),
                    help="Ausgabeordner (Default: 01_ngp_analysis/scan)")
    ap.add_argument("--minlen", type=int, default=6, help="min. Stringlänge")
    ap.add_argument("--maxhits", type=int, default=1000, help="max. Treffer pro Kategorie")
    args = ap.parse_args()

    with open(args.input, "rb") as f:
        blob = f.read()
    os.makedirs(args.out, exist_ok=True)

    # 1) Strings (ASCII & UTF-16LE)
    asc = ascii_strings(blob, min_len=args.minlen)
    u16 = utf16le_strings(blob, min_len=args.minlen)

    write_text(os.path.join(args.out, "strings_ascii.txt"),
               "\n".join(f"{off:08x}: {s.decode('latin-1', 'replace')}" for off, s in asc[:args.maxhits]))
    write_text(os.path.join(args.out, "strings_utf16le.txt"),
               "\n".join(f"{off:08x}: {s.decode('latin-1', 'replace')}" for off, s in u16[:args.maxhits]))
    print(f"[+] ASCII-Strings: {len(asc)}  → {os.path.join(args.out, 'strings_ascii.txt')}")
    print(f"[+] UTF16LE-Strings: {len(u16)} → {os.path.join(args.out, 'strings_utf16le.txt')}")

    # 2) Magic scans
    report = {"file": args.input, "size": len(blob), "hits": {}}
    for sig, name in MAGICS.items():
        hits = find_all(blob, sig)
        report["hits"][name] = hits
        print(f"[scan] {name}: {len(hits)} Treffer")
        # für jeden Treffer: Hex-Vorschau schreiben
        for k, off in enumerate(hits[:min(len(hits), 20)]):
            hd = hexdump(blob, off, 128)
            write_text(os.path.join(args.out, f"hexdump_{name}_{k:03d}_off_{off}.txt"), hd)

    # 3) Eingebettete ZIPs extrahieren
    for off in report["hits"].get("zip", []):
        try:
            zdir = os.path.join(args.out, f"embedded_zip_off_{off}")
            os.makedirs(zdir, exist_ok=True)
            with zipfile.ZipFile(io.BytesIO(blob[off:])) as zf:
                zf.extractall(zdir)
            print(f"[+] ZIP extrahiert @ {off} → {zdir}")
        except Exception as e:
            write_text(os.path.join(args.out, f"zip_error_off_{off}.txt"), f"{e}")

    # 4) GZIP / ZSTD Frames dekomprimieren (ab jedem Treffer)
    for off in report["hits"].get("gzip", []):
        dec = try_gzip(blob[off:])
        if dec:
            path = os.path.join(args.out, f"gzip_off_{off}.bin")
            write(path, dec)
            kind = detect_kind(dec)
            print(f"[+] GZIP @ {off} → {path} (kind={kind}, {len(dec)} bytes)")
    for off in report["hits"].get("zstd", []):
        if zstd:
            try:
                d = zstd.ZstdDecompressor().decompress(blob[off:])
                path = os.path.join(args.out, f"zstd_off_{off}.bin")
                write(path, d)
                kind = detect_kind(d)
                print(f"[+] ZSTD @ {off} → {path} (kind={kind}, {len(d)} bytes)")
            except Exception as e:
                write_text(os.path.join(args.out, f"zstd_error_off_{off}.txt"), str(e))
        else:
            print("[i] ZSTD-Treffer gefunden, aber Modul nicht installiert (pip install zstandard).")

    # 5) JSON-Schnipsel heuristisch (Fenster um '{')
    brace_hits = [m.start() for m in re.finditer(rb"\{", blob)]

    preview_path = os.path.join(args.out, "json_previews.txt")
    previews = []
    for idx, off in enumerate(brace_hits[:200]):  # Deckel drauf
        window = blob[max(0, off - 64): off + 512]
        try:
            txt = window.decode("utf-8", "ignore")
        except Exception:
            txt = repr(window[:128])
        previews.append(f"-- offset {off} --\n{txt}\n")
    write_text(preview_path, "\n".join(previews))
    print(f"[+] JSON-Previews (heuristisch) → {preview_path} ({len(brace_hits)} '{{' gesamt; 200 gezeigt)")

    # 6) Manifest speichern
    manifest = {
        "file": args.input,
        "size": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "hits": report["hits"],
        "outputs": {
            "strings_ascii": os.path.join(args.out, "strings_ascii.txt"),
            "strings_utf16le": os.path.join(args.out, "strings_utf16le.txt"),
            "json_previews": preview_path,
        }
    }
    with open(os.path.join(args.out, "_manifest_scan.json"), "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print(f"[✓] Manifest → {os.path.join(args.out, '_manifest_scan.json')}")
    print("Done.")

if __name__ == "__main__":
    main()

