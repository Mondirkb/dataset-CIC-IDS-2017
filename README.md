# Hybrid Intrusion Detection System — ML Pipeline (CICIDS2017)

This repository contains the code used to train the machine-learning models on the **CICIDS2017** dataset and to run the **hybrid detection pipeline**, which combines Suricata rule-based alerts with trained Random Forest models on locally captured network traffic.


---

## Overview

The system combines two complementary detection layers:

- **Suricata** — signature-based detection on captured traffic (`eve.json` alerts).
- **Machine Learning** — Random Forest models trained on CICIDS2017, applied to flow-level features extracted with NFStream.

The two outputs are merged by a hybrid decision layer and optionally sent to Elasticsearch for visualization in Kibana.

```
Raw traffic (PCAP)
   ├──► Suricata  ───────────────► eve.json alerts
   └──► NFStream  ───────────────► flow CSV
                                        │
                         convert_nfstream_to_cicids_like.py
                                        │
                                        ▼
                              hybrid_predict.py
                    (trained models + five-tuple alert correlation)
                                        │
                                        ▼
                         hybrid_predictions_<scenario>.csv
                                  + Elasticsearch
```

---

## Repository Structure

| File | Purpose |
|---|---|
| `data_processing.ipynb` | Loads raw CICIDS2017 CSVs, preprocesses the data, and trains/evaluates the binary Random Forest, binary Neural Network, and multi-class Random Forest models. |
| `convert_nfstream_to_cicids_like.py` | Converts an NFStream-exported flow CSV into a CICIDS2017-compatible format usable by the trained models. |
| `hybrid_predict.py` | Loads the trained models, runs predictions on the converted flow CSV, correlates each flow with Suricata `eve.json` alerts by exact five-tuple, and produces the final hybrid decision. |
| `verify_retrain.py` | Reproduces the retraining result reported in the thesis (0% → 99.99% detection on local SynFlood traffic). |
| `upload_predictions_bulk.py` | Uploads hybrid prediction results to an Elasticsearch index (`hybrid-ids-results`) via the bulk API. |

---

## Alert-to-Flow Correlation

Each flow is matched to Suricata alerts using its **normalised five-tuple** — source and destination address and port, plus transport protocol, with the two endpoints ordered so that direction does not affect the key.

Direction-normalisation is necessary because Suricata reports the alerting packet's direction (server-to-client for HTTP response events), while NFStream always records the flow initiator as the source.

Matching on host addresses alone is inadequate in a small laboratory: the captures used here contain only three distinct address pairs across several thousand flows, so a single alert would mark an entire scenario as detected. An earlier version of this pipeline used host-pair matching and reported the Nmap scenario as 100% detected on the basis of eight alerting five-tuples across 3,021 flows.

Alerts are additionally classified as **attack-specific** or **generic**. Signatures written for a particular attack technique are counted separately from Suricata's own protocol-decode events (`SURICATA HTTP`/`STREAM`), informational rules (`ET INFO`, `ET POLICY`), and any `local.rules` entry — none of which indicate recognition of an attack.

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
nfstream
```

```bash
pip install -r requirements.txt
```

---

## Usage

### 1. Train the models

Open `data_processing.ipynb` in Google Colab (or Jupyter). It expects the raw CICIDS2017 CSV files (one per day) in a configured folder, and will:

1. Clean the data (remove nulls, duplicates, strip whitespace).
2. Select the flow-level features used throughout this project.
3. Train a **binary Random Forest** (benign vs. attack) and a **binary Neural Network** for comparison.
4. Train a **multi-class Random Forest** for attack-type classification.
5. Save the trained models, scalers, and label encoder.

Two feature sets are used: a **19-feature** set matching the original CICIDS2017 selection, and a reduced **10-feature** set restricted to fields NFStream can actually compute. The 10-feature models are the ones consumed by `hybrid_predict.py`; the nine excluded fields (`min_seg_size_forward` and the `Active`/`Idle` statistics) have no NFStream equivalent and would otherwise be filled with a constant `0` for every local flow.

### 2. Convert a local capture

```bash
python3 convert_nfstream_to_cicids_like.py <nfstream_output.csv>
```

Writes `~/hybrid-ids/data/test_flows.csv`, retaining the identifier columns (`Source IP`, `Source Port`, `Destination IP`, `Destination Port`, `Protocol`) required for five-tuple alert correlation.

### 3. Run the hybrid prediction

```bash
python3 hybrid_predict.py <run_label> <path_to_eve.json> [input.csv]
```

Example:

```bash
python3 convert_nfstream_to_cicids_like.py flows/nmap_scan_dvwa_nfstream.csv
python3 hybrid_predict.py nmap_scan suricata-logs/nmap_scan/eve.json
```

Writes `~/hybrid-ids/results/hybrid_predictions_<run_label>.csv` and prints a per-scenario summary:

```
  SCENARIO: nmap_scan
  Flows                          : 3021
  Flows with any Suricata alert  : 8 (0.26%)
  Flows with attack-specific sig : 5 (0.17%)
  Flows flagged by ML            : 0 (0.00%)
```

Each scenario must be run against its own `eve.json`. Set `SEND_TO_ES = False` in the script to skip the Elasticsearch upload.

### 4. Reproduce the retraining experiment

```bash
python3 verify_retrain.py
```

---

## Trained Models

Hosted on Google Drive (too large for this repository):

**[Download trained models (Google Drive)](https://drive.google.com/drive/folders/1UWT5NuHcpmZuX9ibA8TUZLUPmWmjJgvt?usp=sharing)**

| File | Description | Result |
|---|---|---|
| `random_forest_binary_cicids2017.pkl` | Binary RF, 19 features, 50 estimators | 98.59% acc, 1.40% FPR |
| `random_forest_multiclass_cicids2017.pkl` | Multi-class RF, 19 features, 100 estimators, 15 classes | 93.90% acc |
| `neural_network_binary_cicids2017.keras` | Binary NN (128→64→32→1, sigmoid) | 86.08% acc, 16.55% FPR |
| `random_forest_binary_10features.pkl` | Binary RF, 10 NFStream-computable features | 98.11% acc |
| `random_forest_multiclass_10features.pkl` | Multi-class RF, 10 features | — |
| `random_forest_binary_10f_plus_synflood.pkl` | Binary RF retrained with local SynFlood traffic added | 98.15% acc on CICIDS2017; 99.99% on local flood |
| `scaler_*.pkl`, `label_encoder_*.pkl` | Min-Max scalers and multi-class label encoder | — |

Place the files in `~/hybrid-ids/models/` before running `hybrid_predict.py`.

---

## Dataset

### 1. CICIDS2017 (training)

Created by the Canadian Institute for Cybersecurity (University of New Brunswick). Not included here due to size:

**https://www.unb.ca/cic/datasets/ids-2017.html**

Note that CICFlowMeter, the tool used to generate CICIDS2017's features, has documented implementation issues — see Engelen et al. (2021), Rosay et al. (2021), and Lanvin et al. (2023). These are discussed in the thesis and are directly relevant to the results below.

### 2. Laboratory-captured traffic (local evaluation)

Five scenarios generated in an isolated VirtualBox laboratory (Kali Linux attacker ↔ DVWA victim, host-only network, no external access), provided in [`data/`](data/):

| Scenario | Flow CSV | Description |
|---|---|---|
| Benign browsing | `data/flows/benign_browsing_flows.csv` | Normal interaction with DVWA. |
| Nmap scan | `data/flows/nmap_scan_flows.csv` | Port and service reconnaissance. |
| SQL injection | `data/flows/sqlmap_sql_injection_flows.csv` | Tautology-based injection against DVWA. |
| Reflected XSS | `data/flows/xss_reflected_flows.csv` | Reflected XSS payload submission. |
| HTTP flood | `data/flows/http_flood_flows.csv` | High request-rate flood. |

All traffic was captured exclusively inside the private, isolated laboratory; no external network or third-party system was targeted at any point.

---

## Results

### CICIDS2017 held-out test set

| Model | Accuracy | Precision | Recall | F1 | FPR |
|---|---|---|---|---|---|
| Binary Random Forest | 98.59% | 94.51% | 98.55% | 96.49% | 1.40% |
| Binary Neural Network | 86.08% | 58.90% | 96.83% | 73.25% | 16.55% |
| Multi-class Random Forest | 93.90% | 98.00%\* | 94.00%\* | 96.00%\* | — |

\* weighted average across 15 classes. 5-fold cross-validation confirms stability (binary: 98.60% ± 0.01%).

### Local laboratory validation

Benchmark performance does **not** transfer to locally captured traffic. Using exact five-tuple correlation:

| Scenario | Flows | Any Suricata alert | Attack-specific signature | ML |
|---|---|---|---|---|
| Benign browsing | 27 | 18.52% (5) | 0.00% (0) | 0.00% |
| Nmap scan | 3,021 | 0.26% (8) | 0.17% (5) | 0.00% |
| SQL injection | 3,976 | 4.05% (161) | 0.00% (0) | 0.00% |
| Reflected XSS | 192 | 0.00% (0) | 0.00% (0) | 0.00% |
| HTTP flood | 1,932 | 99.79% (1,928) | 0.00% (0) | 0.00% |

Three findings:

1. **The ML layer flagged no local flow in any scenario**, despite detecting CICIDS2017 DDoS at 99.86% with the same model and the same ten features. The cause is a domain shift: the model learned DDoS as a *bidirectional exchange pattern* (mean 4.47 forward vs. 3.26 backward packets), not as packet volume. A unidirectional flood does not match that representation regardless of size.

2. **Alert coverage is not attack recognition.** The HTTP-flood scenario shows an alert on 99.79% of flows, but every one is `SURICATA HTTP Response excessive header repetition` (SID 2221036) — a generic protocol-decode event raised on the server's response. Benign browsing produced alerts on 18.52% of its flows, proportionally more than the Nmap scan, confirming these events are not discriminative. The loaded rule set contained 575 XSS signatures; none matched the reflected-XSS payload.

3. **The gap is closable but does not generalise.** Merging 65,543 local SynFlood flows into the CICIDS2017 training set raised local detection from 0% to 99.99% at under two points of benchmark accuracy. The same retrained model classified only 4 of 7 flows from `nping` — a different tool executing the same technique — because `nping` used two source ports for 200,000 packets while `hping3` varied its source port, collapsing the capture into 7 flows instead of 65,543. This is a difference in flow construction upstream of the model entirely.

Full methodology and discussion are in the accompanying thesis.

---

## License

Released for academic purposes. See `LICENSE` for details, or contact the author for reuse permissions.
