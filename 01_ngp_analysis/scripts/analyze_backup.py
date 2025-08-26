import os, re, json, base64, binascii, argparse, hashlib
from typing import Any

# ---------- Einstellungen ----------
DEFAULT_OUT = "01_ngp_analysis/extracted"
B64_RE = re.compile(r'^[A-Za-z0-9+/=\s]+$')

# ---------- Utils ----------
def safe(name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9._-]+', "_", name)[:90] or "field"

def is_base64(s: str) -> bool:
    if not isinstance(s, str) or len(s) < 8 or not B64_RE.match(s):
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except binascii.Error:
        return False

def sniff_ext(data: bytes) -> str:
    if data[:4] == b"RIFF": return ".wav"
    if data[:4] == b"fLaC": return ".flac"
    if data[:4] == b"OggS": return ".ogg"
    if data[:2] == b"PK":   return ".zip"
    return ".bin"

def try_utf8(b: bytes):
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return None

# ---------- Walker ----------
class Extractor:
    def __init__(self, out_dir: str):
        self.out = out_dir
        os.makedirs(self.out, exist_ok=True)
        self.counter = 0
        self.manifest = []

    def save_bytes(self, data: bytes, hint: str) -> str:
        self.counter += 1
        ext = sniff_ext(data)
        path = os.path.join(self.out, f"{self.counter:04d}_{safe(hint)}{ext}")
        with open(path, "wb") as f:
            f.write(data)
        return path

    def save_text(self, text: str, hint: str) -> str:
        self.counter += 1
        # JSON hübsch machen, falls möglich
        try:
            obj = json.loads(text)
            path = os.path.join(self.out, f"{self.counter:04d}_{safe(hint)}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(obj, f, ensure_ascii=False, indent=2)
            return path
        except Exception:
            path = os.path.join(self.out, f"{self.counter:04d}_{safe(hint)}.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            return path

    def handle_string(self, s: str, path_hint: str):
        if not is_base64(s):
            return
        raw = base64.b64decode(s)
        sha = hashlib.sha256(raw).hexdigest()[:16]
        text = try_utf8(raw)
        if text is not None and text.strip():
            out = self.save_text(text, path_hint)
            kind = "text"
            size = len(raw)
        else:
            out = self.save_bytes(raw, path_hint)
            kind = "binary"
            size = len(raw)
        self.manifest.append({"path": path_hint, "kind": kind, "size": size, "sha256_16": sha, "file": out})
        print(f"[{kind.upper():5}] {path_hint} → {out} ({size} bytes, sha256:{sha})")

    def walk(self, node: Any, path="root"):
        if isinstance(node, dict):
            for k, v in node.items():
                self.walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                self.walk(v, f"{path}[{i}]")
        elif isinstance(node, str):
            self.handle_string(node, path)

    def write_manifest(self):
        man_path = os.path.join(self.out, "_manifest.json")
        with open(man_path, "w", encoding="utf-8") as f:
            json.dump(self.manifest, f, ensure_ascii=False, indent=2)
        print(f"\nManifest geschrieben: {man_path}")

def main():
    ap = argparse.ArgumentParser(description="QC Backup JSON analysieren und Base64-Blöcke extrahieren.")
    ap.add_argument("input", help="Pfad zur backup.json")
    ap.add_argument("-o", "--out", default=DEFAULT_OUT, help="Ausgabeordner (default: 01_ngp_analysis/extracted)")
    args = ap.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    print(f"🔍 Datei geladen: {args.input}")
    ex = Extractor(args.out)
    ex.walk(data)
    ex.write_manifest()
    print("\n✅ Fertig.")

if __name__ == "__main__":
    main()
