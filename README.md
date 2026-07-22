# Hybrid Intrusion Detection System — ML Pipeline (CICIDS2017)


---

## Overview

The system combines two complementary detection layers:

- **Suricata** — signature-based detection on captured traffic (`eve.json` alerts).
- **Machine Learning** — Random Forest models trained on CICIDS2017, applied to flow-level features extracted with NFStream.

The two outputs are merged by a hybrid decision layer and (optionally) sent to Elasticsearch for visualization in Kibana.

```
Raw traffic (PCAP)
   ├──► Suricata  ───────────────► eve.json alerts
   └──► NFStream  ───────────────► flow CSV
                                        │
                         convert_nfstream_to_cicids_like.py
                                        │
                                        ▼
                              hybrid_predict.py
                    (loads trained models + Suricata alerts)
                                        │
                                        ▼
                         hybrid_predictions.csv + Elasticsearch
```

---

## Repository Structure

| File | Purpose |
|---|---|
| `data_processing.ipynb` | Loads raw CICIDS2017 CSVs, preprocesses the data, and trains/evaluates the binary Random Forest, binary Neural Network, and multi-class Random Forest models. |
| `convert_nfstream_to_cicids_like.py` | Converts an NFStream-exported flow CSV (from locally captured traffic) into a CICIDS2017-compatible format usable by the trained models. |
| `hybrid_predict.py` | Loads the trained models, runs predictions on the converted flow CSV, correlates them with Suricata `eve.json` alerts, and produces the final hybrid decision for each flow. |
| `upload_predictions_bulk.py` | Uploads the hybrid prediction results to an Elasticsearch index (`hybrid-ids-results`) via the bulk API, for visualization in Kibana. |

---

## Requirements

```
pandas
numpy
scikit-learn
tensorflow
imbalanced-learn
matplotlib
seaborn
joblib
requests
```

Install with:

```bash
pip install -r requirements.txt
```

---

## Usage

### 1. Train the models

Open `data_processing.ipynb` in Google Colab (or Jupyter). It expects the raw CICIDS2017 CSV files (one per day) in a configured folder, and will:

1. Clean the data (remove nulls, duplicates, strip whitespace).
2. Select the 19 flow-level features used throughout this project.
3. Train a **binary Random Forest** (benign vs. attack) and a **binary Neural Network** for comparison.
4. Train a **multi-class Random Forest** for attack-type classification.
5. Save the trained models, scalers, and label encoder (see [Trained Models](#trained-models) below).

### 2. Convert local capture to CICIDS2017-like format

After capturing traffic and extracting flows with NFStream:

```bash
python3 convert_nfstream_to_cicids_like.py <nfstream_output.csv>
```

This produces `~/hybrid-ids/data/test_flows.csv`, using the mapping documented in the script (some fields — `min_seg_size_forward` and the `Active`/`Idle` statistics — are not available from NFStream and are filled with `0`; see the thesis, Section "Feature Compatibility", for the full field-by-field mapping and its implications).

### 3. Run the hybrid prediction

```bash
python3 hybrid_predict.py <nfstream_output.csv> <suricata_eve.json>
```

This loads the trained models from `~/hybrid-ids/models/`, runs the binary and multi-class predictions, correlates each flow with Suricata alerts (by source/destination IP pair), and writes `~/hybrid-ids/results/hybrid_predictions.csv`. If Elasticsearch is running locally, results are also pushed to it automatically.

### 4. (Optional) Bulk upload to Elasticsearch

```bash
python3 upload_predictions_bulk.py
```

---

## Trained Models

The trained models, scalers, and label encoder are hosted on Google Drive (too large for this repository):

**[Download trained models (Google Drive)](https://drive.google.com/drive/folders/1UWT5NuHcpmZuX9ibA8TUZLUPmWmjJgvt?usp=sharing)**

| File | Description | Result |
|---|---|---|
| `random_forest_binary_cicids2017.pkl` | Binary Random Forest (benign vs. attack), 50 estimators | Accuracy 98.59%, FPR 1.40% |
| `scaler_binary_cicids2017.pkl` | Min-Max scaler fitted on the binary training set | — |
| `neural_network_binary_cicids2017.keras` | Binary Neural Network (128→64→32→1, sigmoid) | Accuracy 86.08% |
| `random_forest_multiclass_cicids2017.pkl` | Multi-class Random Forest, 100 estimators | Accuracy 93.90% |
| `scaler_multiclass_cicids2017.pkl` | Min-Max scaler fitted on the multi-class training set | — |
| `label_encoder_multiclass_cicids2017.pkl` | Label encoder mapping class indices to CICIDS2017 attack names | — |

> After downloading, place the files in `~/hybrid-ids/models/` before running `hybrid_predict.py`.

---

## Dataset

This project uses the **CICIDS2017** dataset, created by the Canadian Institute for Cybersecurity (University of New Brunswick). The raw dataset is not included in this repository due to its size; it can be obtained from the official source:

**https://www.unb.ca/cic/datasets/ids-2017.html**

---

## Results Summary

| Experiment | Accuracy | Precision | Recall | F1-score | FPR |
|---|---|---|---|---|---|
| Binary Random Forest | 98.59% | 94.51% | 98.55% | 96.49% | 1.40% |
| Binary Neural Network | 86.08% | 58.90% | 96.83% | 73.25% | 16.55% |
| Multi-class Random Forest | 93.90% | 98.00%* | 94.00%* | 96.00%* | — |

\* weighted average across all classes.

Full methodology, preprocessing details, and discussion are provided in the accompanying thesis.

---


---

## License

This project is released for academic purposes . See `LICENSE` for details (or contact the author for reuse permissions).
