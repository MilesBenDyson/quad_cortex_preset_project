import os, json, argparse, math
from collections import Counter

HERE = os.path.dirname(__file__)
ANALYSIS_DIR = os.path.dirname(HERE)
RAW_DIR = os.path.join(ANALYSIS_DIR, "members_zlib_raw")
MANIFEST = os.path.join(RAW_DIR, "_manifest_zlib_raw.json")

def entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

def analyze_block(path: str, max_bytes: int = 50000):
    with open(path, "rb") as f:
        blob = f.read(max_bytes)  # nur ersten Teil, reicht für Statistik
    ent = entropy(blob)
    counts = Counter(blob)
    top = counts.most_common(10)
    return {
        "file": os.path.basename(path),
        "size": os.path.getsize(path),
        "entropy": round(ent, 3),
        "top10": [(f"0x{b:02x}", n) for b, n in top],
    }

def main():
    ap = argparse.ArgumentParser(description="Statistische Analyse von ZLIB-Rohblöcken (Entropie, Byte-Histogramm).")
    ap.add_argument("--indices", type=str, help="Block-Indizes (z.B. 45,36,188)")
    args = ap.parse_args()

    with open(MANIFEST, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    if args.indices:
        indices = [int(x.strip()) for x in args.indices.split(",")]
        targets = [rec for rec in manifest if rec["index"] in indices]
    else:
        # default: größte 3
        targets = sorted(manifest, key=lambda r: r["size"], reverse=True)[:3]

    results = []
    for rec in targets:
        res = analyze_block(rec["file"])
        results.append(res)
        print(f"📦 {res['file']} | size={res['size']} | entropy={res['entropy']}")
        print("   Top10 Bytes:", res["top10"])

    out = os.path.join(ANALYSIS_DIR, "block_entropy_report.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n✅ Report gespeichert: {out}")

if __name__ == "__main__":
    main()
