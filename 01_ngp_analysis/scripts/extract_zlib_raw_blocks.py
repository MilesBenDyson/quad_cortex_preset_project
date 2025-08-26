import os, re, json, argparse, hashlib

# Default-Pfade relativ zur Skript-Position
HERE = os.path.dirname(__file__)
ANALYSIS_DIR = os.path.dirname(HERE)  # .../01_ngp_analysis
INPUT_DEFAULT = os.path.join(ANALYSIS_DIR, "extracted", "payload.raw")
OUT_DEFAULT   = os.path.join(ANALYSIS_DIR, "members_zlib_raw")

def ensure_dir(p): os.makedirs(p, exist_ok=True)
def sha16(b: bytes) -> str: return hashlib.sha256(b).hexdigest()[:16]

def hexdump(data: bytes, length: int = 256) -> str:
    chunk, lines = data[:length], []
    for i in range(0, len(chunk), 16):
        row = chunk[i:i+16]
        hexpart = " ".join(f"{b:02x}" for b in row)
        asciip  = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{i:08x}  {hexpart:<48}  {asciip}")
    return "\n".join(lines)

def main():
    ap = argparse.ArgumentParser(description="Roh-Extraktion aller ZLIB-Blöcke aus payload.raw (ohne zu dekomprimieren)")
    ap.add_argument("-i", "--input", default=INPUT_DEFAULT, help="Pfad zu payload.raw")
    ap.add_argument("-o", "--out",   default=OUT_DEFAULT,   help="Ausgabeordner")
    ap.add_argument("--max", type=int, default=100000, help="Sicherheitslimit für Anzahl Blöcke")
    args = ap.parse_args()

    with open(args.input, "rb") as f:
        blob = f.read()
    ensure_dir(args.out)

    # typische ZLIB-Header: 78 01 / 78 9C / 78 DA
    hits = [m.start() for m in re.finditer(rb"\x78[\x01\x9c\xda]", blob)]
    if not hits:
        print("Keine ZLIB-Signaturen gefunden.")
        return

    # Blöcke sind von hit[i] bis hit[i+1]-1 (letzter Block bis EOF)
    blocks = []
    for idx, off in enumerate(hits[:min(len(hits), args.max)]):
        start = off
        end   = hits[idx+1] if idx+1 < len(hits) else len(blob)
        blocks.append((idx, start, end))

    manifest = []
    total = 0
    for i, start, end in blocks:
        raw = blob[start:end]
        size = len(raw)
        total += size
        hdr  = f"{raw[:2].hex()}" if size >= 2 else ""
        tag  = f"zlib_raw_off_{start}_idx_{i}"
        bin_path = os.path.join(args.out, f"{tag}.bin")
        with open(bin_path, "wb") as f:
            f.write(raw)

        # kleine Vorschau als hexdump
        hd_path = os.path.join(args.out, f"{tag}_hexdump.txt")
        with open(hd_path, "w", encoding="utf-8") as f:
            f.write(hexdump(raw, 256))

        rec = {
            "index": i,
            "offset": start,
            "end": end,
            "size": size,
            "sha256_16": sha16(raw),
            "header_bytes_hex": hdr,
            "file": bin_path,
            "hexdump": hd_path,
        }
        manifest.append(rec)

    # Manifest schreiben + kurze Zusammenfassung
    mani_path = os.path.join(args.out, "_manifest_zlib_raw.json")
    with open(mani_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    largest = sorted(manifest, key=lambda r: r["size"], reverse=True)[:10]
    print(f"ZLIB-Rohblöcke: {len(manifest)}  | Gesamtbytes (summiert): {total}")
    print(f"Manifest: {mani_path}")
    print("Größte 10 Blöcke:")
    for r in largest:
        print(f"  idx {r['index']:4d} | off {r['offset']:8d} | size {r['size']:8d} | sha:{r['sha256_16']} | {os.path.basename(r['file'])}")

if __name__ == "__main__":
    main()
