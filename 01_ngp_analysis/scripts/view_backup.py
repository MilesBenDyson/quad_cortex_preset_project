import json

INPUT_FILE = r"C:\Users\bensc\Desktop\IT\Projekte\quad_cortex_preset_project\01_ngp_analysis\samples\backup.json"


with open(INPUT_FILE, "r", encoding="utf-8") as f:
    data = json.load(f)

print("🔍 QC-Backup Übersicht\n")

for key, value in data.items():
    if key in ("payload", "payload_hash"):
        print(f"{key}: <BINARY, {len(value)} chars>")
    else:
        print(f"{key}: {value}")

