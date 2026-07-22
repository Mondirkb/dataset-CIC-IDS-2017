import pandas as pd
import numpy as np
from pathlib import Path
import sys

if len(sys.argv) < 2:
    print("Usage: python3 convert_nfstream_to_cicids_like.py <nfstream_csv_file>")
    sys.exit(1)

INPUT_FILE = Path(sys.argv[1]).expanduser()
OUTPUT_FILE = Path.home() / "hybrid-ids" / "data" / "test_flows.csv"

df = pd.read_csv(INPUT_FILE, low_memory=False)
df.columns = df.columns.str.strip()

print("[+] Loaded NFStream CSV:")
print(INPUT_FILE)
print("[+] Shape:", df.shape)

def col(name, default=0):
    if name in df.columns:
        return pd.to_numeric(df[name], errors="coerce").fillna(default)
    return pd.Series([default] * len(df))

out = pd.DataFrame()

# Approximate mapping: NFStream -> CICIDS2017-like selected features
out["Protocol"] = col("protocol")
out["Flow Duration"] = col("bidirectional_duration_ms") * 1000

out["Total Fwd Packets"] = col("src2dst_packets")
out["Total Backward Packets"] = col("dst2src_packets")

out["Total Length of Fwd Packets"] = col("src2dst_bytes")
out["Total Length of Bwd Packets"] = col("dst2src_bytes")

out["Fwd Packet Length Max"] = col("src2dst_max_ps")
out["Fwd Packet Length Min"] = col("src2dst_min_ps")
out["Fwd Packet Length Mean"] = col("src2dst_mean_ps")
out["Fwd Packet Length Std"] = col("src2dst_stddev_ps")

# Not directly available in NFStream, filled for compatibility
out["min_seg_size_forward"] = 0
out["Active Mean"] = 0
out["Active Std"] = 0
out["Active Max"] = 0
out["Active Min"] = 0
out["Idle Mean"] = 0
out["Idle Std"] = 0
out["Idle Max"] = 0
out["Idle Min"] = 0

# Keep label and addressing metadata
out["Label"] = df["Label"] if "Label" in df.columns else "UNKNOWN"
out["Source IP"] = df["src_ip"] if "src_ip" in df.columns else "unknown"
out["Destination IP"] = df["dst_ip"] if "dst_ip" in df.columns else "unknown"
out["Source Port"] = df["src_port"] if "src_port" in df.columns else 0
out["Destination Port"] = df["dst_port"] if "dst_port" in df.columns else 0

out = out.replace([np.inf, -np.inf], 0).fillna(0)

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
out.to_csv(OUTPUT_FILE, index=False)

print("[+] Saved CICIDS-like test file:")
print(OUTPUT_FILE)
print("[+] Output shape:", out.shape)
print("\n[+] Label distribution:")
print(out["Label"].value_counts())
