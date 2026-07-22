import json
from pathlib import Path

import pandas as pd
import requests

CSV_FILE = Path.home() / "hybrid-ids" / "results" / "hybrid_predictions.csv"
ES_URL = "http://localhost:9200"
INDEX_NAME = "hybrid-ids-results"
CHUNK_SIZE = 100

df = pd.read_csv(CSV_FILE, low_memory=False)

print("[+] Loaded predictions:")
print(CSV_FILE)
print("[+] Rows:", len(df))

def clean_value(v):
    if pd.isna(v):
        return None
    return v

events = []

for _, row in df.iterrows():
    doc = {
        "@timestamp": clean_value(row.get("timestamp")),
        "suricata": {
            "alert": clean_value(row.get("suricata_alert")),
        },
        "ml": {
            "binary_prediction": clean_value(row.get("ml_binary_prediction")),
            "attack_type": clean_value(row.get("ml_attack_type")),
        },
        "hybrid": {
            "decision": clean_value(row.get("hybrid_decision")),
        },
        "dataset": {
            "original_label": clean_value(row.get("original_dataset_label")),
        },
        "network": {
            "transport_number": clean_value(row.get("Protocol")),
        },
        "flow": {
            "duration": clean_value(row.get("Flow Duration")),
        },
    }

    if "Source IP" in row:
        doc["source"] = {
            "ip": clean_value(row.get("Source IP")),
            "port": clean_value(row.get("Source Port")),
        }

    if "Destination IP" in row:
        doc["destination"] = {
            "ip": clean_value(row.get("Destination IP")),
            "port": clean_value(row.get("Destination Port")),
        }

    events.append(doc)

print("[+] Uploading using Elasticsearch bulk API...")

sent = 0

for start in range(0, len(events), CHUNK_SIZE):
    chunk = events[start:start + CHUNK_SIZE]

    bulk_lines = []
    for doc in chunk:
        bulk_lines.append(json.dumps({"index": {"_index": INDEX_NAME}}))
        bulk_lines.append(json.dumps(doc, default=str))

    bulk_body = "\n".join(bulk_lines) + "\n"

    response = requests.post(
        f"{ES_URL}/_bulk",
        data=bulk_body,
        headers={"Content-Type": "application/x-ndjson"},
        timeout=120,
    )

    if response.status_code not in [200, 201]:
        print("[!] Upload error:")
        print(response.status_code)
        print(response.text[:1000])
        raise SystemExit(1)

    result = response.json()
    if result.get("errors"):
        print("[!] Bulk upload had item errors.")
        print(json.dumps(result, indent=2)[:2000])
        raise SystemExit(1)

    sent += len(chunk)
    print(f"[+] Sent {sent}/{len(events)}")

print("[+] Done.")
print(f"[+] Uploaded to index: {INDEX_NAME}")
