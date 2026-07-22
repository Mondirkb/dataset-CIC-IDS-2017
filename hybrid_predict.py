import pandas as pd
import numpy as np
import joblib
import requests
from datetime import datetime, timezone
from pathlib import Path
import json

def load_suricata_alert_pairs(eve_json_path):
    alert_pairs = set()
    if not eve_json_path or not Path(eve_json_path).exists():
        return alert_pairs
    with open(eve_json_path) as f:
        for line in f:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "alert":
                src = event.get("src_ip")
                dst = event.get("dest_ip")
                if src and dst:
                    alert_pairs.add((src, dst))
                    alert_pairs.add((dst, src))
    return alert_pairs

# ============================================================
# Configuration
# ============================================================

BASE_DIR = Path.home() / "hybrid-ids"
MODEL_DIR = BASE_DIR / "models"
DATA_DIR = BASE_DIR / "data"
RESULTS_DIR = BASE_DIR / "results"

INPUT_CSV = DATA_DIR / "test_flows.csv"
OUTPUT_CSV = RESULTS_DIR / "hybrid_predictions.csv"

import sys
SURICATA_EVE_JSON = sys.argv[2] if len(sys.argv) > 2 else None

ES_URL = "http://localhost:9200"
INDEX_NAME = "hybrid-ids-results"

# For first test use 5000 rows.
# Later you can change this to None to process all rows.
ROW_LIMIT = 5000

# ============================================================
# Model paths
# ============================================================

BINARY_MODEL_PATH = MODEL_DIR / "random_forest_binary_cicids2017.pkl"
BINARY_SCALER_PATH = MODEL_DIR / "scaler_binary_cicids2017.pkl"

MULTI_MODEL_PATH = MODEL_DIR / "random_forest_multiclass_cicids2017.pkl"
MULTI_SCALER_PATH = MODEL_DIR / "scaler_multiclass_cicids2017.pkl"
LABEL_ENCODER_PATH = MODEL_DIR / "label_encoder_multiclass_cicids2017.pkl"

# ============================================================
# CICIDS2017 features used during training
# ============================================================

FEATURES = [
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min"
]

# Some CICFlowMeter/CICIDS files may use slightly different names
COLUMN_ALIASES = {
    "Fwd Packets Length Total": "Total Length of Fwd Packets",
    "Bwd Packets Length Total": "Total Length of Bwd Packets",
    "Fwd Seg Size Min": "min_seg_size_forward"
}

# ============================================================
# Helper functions
# ============================================================

def check_file(path):
    if not path.exists():
        raise FileNotFoundError(f"Missing file: {path}")


def safe_int(value):
    try:
        if pd.isna(value):
            return None
        return int(float(value))
    except Exception:
        return None


def safe_float(value):
    try:
        if pd.isna(value):
            return None
        return float(value)
    except Exception:
        return None


def hybrid_decision(suricata_alert, ml_binary_prediction):
    if suricata_alert == "YES" and ml_binary_prediction == "ATTACK":
        return "HIGH_CONFIDENCE_ATTACK"
    elif suricata_alert == "YES" and ml_binary_prediction == "BENIGN":
        return "SUSPICIOUS_REVIEW"
    elif suricata_alert == "NO" and ml_binary_prediction == "ATTACK":
        return "POSSIBLE_UNKNOWN_ATTACK"
    else:
        return "NORMAL"


def send_to_elasticsearch(events):
    sent = 0

    for event in events:
        response = requests.post(
            f"{ES_URL}/{INDEX_NAME}/_doc",
            json=event,
            timeout=10
        )

        if response.status_code in [200, 201]:
            sent += 1
        else:
            print("Elasticsearch error:")
            print(response.status_code, response.text[:500])

    print(f"Sent {sent}/{len(events)} events to Elasticsearch index: {INDEX_NAME}")


# ============================================================
# Main script
# ============================================================

def main():
    RESULTS_DIR.mkdir(exist_ok=True)

    required_files = [
        BINARY_MODEL_PATH,
        BINARY_SCALER_PATH,
        MULTI_MODEL_PATH,
        MULTI_SCALER_PATH,
        LABEL_ENCODER_PATH,
        INPUT_CSV
    ]

    for path in required_files:
        check_file(path)

    print("[+] Loading models...")

    binary_model = joblib.load(BINARY_MODEL_PATH)
    binary_scaler = joblib.load(BINARY_SCALER_PATH)

    multi_model = joblib.load(MULTI_MODEL_PATH)
    multi_scaler = joblib.load(MULTI_SCALER_PATH)
    label_encoder = joblib.load(LABEL_ENCODER_PATH)

    print("[+] Loading CSV data...")

    df = pd.read_csv(INPUT_CSV, low_memory=False)

    # Remove spaces from column names
    df.columns = df.columns.str.strip()

    # Rename alternative feature names if needed
    df.rename(columns=COLUMN_ALIASES, inplace=True)

    if ROW_LIMIT is not None:
        df = df.head(ROW_LIMIT)

    print(f"[+] Rows loaded: {len(df)}")

    missing = [col for col in FEATURES if col not in df.columns]

    if missing:
        print("\n[!] Missing required feature columns:")
        for col in missing:
            print(" -", col)
        raise ValueError("Input CSV does not contain all required CICIDS2017 features.")

    X = df[FEATURES].copy()
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    print("[+] Running binary prediction...")

    X_binary_scaled = binary_scaler.transform(X)
    binary_pred = binary_model.predict(X_binary_scaled)
    binary_labels = ["BENIGN" if pred == 0 else "ATTACK" for pred in binary_pred]

    print("[+] Running multi-class attack-type prediction...")

    X_multi_scaled = multi_scaler.transform(X)
    multi_pred_encoded = multi_model.predict(X_multi_scaled)
    multi_labels = label_encoder.inverse_transform(multi_pred_encoded)

    alert_pairs = load_suricata_alert_pairs(SURICATA_EVE_JSON)
    print(f"[+] Loaded {len(alert_pairs)} Suricata alert IP pairs")

    suricata_alerts = []
    for i in range(len(df)):
        src_ip = str(df.iloc[i]["Source IP"]) if "Source IP" in df.columns else None
        dst_ip = str(df.iloc[i]["Destination IP"]) if "Destination IP" in df.columns else None
        if src_ip and dst_ip and (src_ip, dst_ip) in alert_pairs:
            suricata_alerts.append("YES")
        else:
            suricata_alerts.append("NO")

    print("[+] Building hybrid output...")

    output_rows = []
    es_events = []

    for i in range(len(df)):
        ml_binary = binary_labels[i]

        # Important correction:
        # If binary model says BENIGN, attack type must be BENIGN.
        # Multi-class attack type is used only when binary model says ATTACK.
        if ml_binary == "ATTACK":
            ml_attack_type = str(multi_labels[i])
        else:
            ml_attack_type = "BENIGN"

        suricata = suricata_alerts[i]
        final_decision = hybrid_decision(suricata, ml_binary)

        original_label = None
        if "Label" in df.columns:
            original_label = str(df.iloc[i]["Label"])

        timestamp = datetime.now(timezone.utc).isoformat()

        row = {
            "timestamp": timestamp,
            "suricata_alert": suricata,
            "ml_binary_prediction": ml_binary,
            "ml_attack_type": ml_attack_type,
            "hybrid_decision": final_decision,
            "original_dataset_label": original_label
        }

        optional_columns = [
            "Source IP",
            "Source Port",
            "Destination IP",
            "Destination Port",
            "Protocol",
            "Flow Duration"
        ]

        for col in optional_columns:
            if col in df.columns:
                row[col] = df.iloc[i][col]

        output_rows.append(row)

        es_event = {
            "@timestamp": timestamp,
            "suricata": {
                "alert": suricata
            },
            "ml": {
                "binary_prediction": ml_binary,
                "attack_type": ml_attack_type
            },
            "hybrid": {
                "decision": final_decision
            },
            "dataset": {
                "original_label": original_label
            }
        }

        if "Source IP" in df.columns:
            es_event["source"] = {
                "ip": str(df.iloc[i]["Source IP"])
            }

        if "Destination IP" in df.columns:
            es_event["destination"] = {
                "ip": str(df.iloc[i]["Destination IP"])
            }

        if "Source Port" in df.columns:
            es_event["source_port"] = safe_int(df.iloc[i]["Source Port"])

        if "Destination Port" in df.columns:
            es_event["destination_port"] = safe_int(df.iloc[i]["Destination Port"])

        if "Protocol" in df.columns:
            es_event["network"] = {
                "transport_number": safe_int(df.iloc[i]["Protocol"])
            }

        if "Flow Duration" in df.columns:
            es_event["flow"] = {
                "duration": safe_float(df.iloc[i]["Flow Duration"])
            }

        es_events.append(es_event)

    output_df = pd.DataFrame(output_rows)
    output_df.to_csv(OUTPUT_CSV, index=False)

    print(f"[+] Predictions saved to: {OUTPUT_CSV}")

    print("[+] Sending results to Elasticsearch...")
    send_to_elasticsearch(es_events)

    print("\n[+] Done.")
    print("\nSample output:")
    print(output_df.head(10))


if __name__ == "__main__":
    main()
