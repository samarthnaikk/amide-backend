#!/usr/bin/env python3

import pandas as pd
import numpy as np
from scipy.stats import entropy
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from lightgbm import LGBMClassifier
import warnings
import time

warnings.filterwarnings("ignore")  # keep logs clean


LOG_FILE = "network_logs.csv"


# ============================================================
# 1. LOAD LOG DATA
# ============================================================

print("[*] Loading logs...")
df = pd.read_csv(LOG_FILE)

df["timestamp"] = pd.to_datetime(df["timestamp"])
df["ts_float"] = df["timestamp"].astype("int64") / 1e9
df = df.sort_values("timestamp")


# ============================================================
# 2. FEATURE ENGINEERING
# ============================================================

print("[*] Computing flow features...")

df["iat"] = df.groupby(["src_ip", "src_port", "dst_ip", "dst_port"])["ts_float"].diff().fillna(0)
df["seq_delta"] = df.groupby(["src_ip", "src_port", "dst_ip", "dst_port"])["seq"].diff().fillna(0)
df["ack_delta"] = df.groupby(["src_ip", "src_port", "dst_ip", "dst_port"])["ack"].diff().fillna(0)


def build_flow_features(flow):
    p = flow["packet_size"].values
    iat = flow["iat"].values

    hist = np.histogram(p, bins=10, density=True)[0]
    p_entropy = entropy(hist + 1e-9)

    iat_hist = np.histogram(iat, bins=10, density=True)[0]
    iat_entropy = entropy(iat_hist + 1e-9)

    return pd.Series({
        "psize_mean": p.mean(),
        "psize_std": p.std(),
        "psize_entropy": p_entropy,
        "iat_mean": iat.mean(),
        "iat_std": iat.std(),
        "iat_entropy": iat_entropy,
        "seq_delta_std": flow["seq_delta"].std(),
        "ack_delta_std": flow["ack_delta"].std(),
        "window_mean": flow["window"].mean(),
    })


flows = df.groupby(
    ["src_ip", "src_port", "dst_ip", "dst_port"],
    group_keys=False
).apply(build_flow_features).fillna(0)

print(f"[*] Extracted {len(flows)} flows.")


# ============================================================
# 3. SCALING
# ============================================================

print("[*] Scaling feature matrix...")
scaler = StandardScaler()
X = scaler.fit_transform(flows)


# ============================================================
# 4. UNSUPERVISED LABELING (IFOREST + LOF)
# ============================================================

print("[*] Building unsupervised anomaly labelers...")
iso = IsolationForest(contamination=0.20, n_estimators=400, bootstrap=True, random_state=42)
lof = LocalOutlierFactor(contamination=0.20, n_neighbors=20)

print("    - IsolationForest: OK")
iso_labels = iso.fit_predict(X)

print("    - LocalOutlierFactor: OK")
lof_labels = lof.fit_predict(X)

anom = np.logical_or(iso_labels == -1, lof_labels == -1).astype(int)

flows["pseudo_label"] = anom
anom_count = int(anom.sum())
perc = (anom_count / len(flows)) * 100

print(f"[!] Pseudo-labeled anomalies detected: {anom_count} / {len(flows)} ({perc:.2f}%)")


# ============================================================
# 5. LIGHTGBM MODEL SETUP
# ============================================================

print("\n============================================================")
print("             LIGHTGBM MODEL CONFIGURATION")
print("------------------------------------------------------------")

model = LGBMClassifier(
    boosting_type="dart",
    n_estimators=600,
    learning_rate=0.03,
    num_leaves=16,
    max_depth=6,
    subsample=0.90,
    colsample_bytree=0.90,
    min_gain_to_split=0.0,
    min_data_in_leaf=3,
    min_sum_hessian_in_leaf=1e-5,
    objective="binary",
    verbose=-1
)

for k, v in model.get_params().items():
    print(f" {k:25s}: {v}")

print("============================================================\n")


# ============================================================
# 6. TRAINING WITH PROGRESS BARS
# ============================================================

print("[*] Training LightGBM...")
print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

model.fit(X, flows["pseudo_label"])

print("\n[+] LightGBM training finished successfully.")


# ============================================================
# 7. PREDICTION
# ============================================================

print("[*] Predicting breach probability...")
probs = model.predict_proba(X)[:, 1]

flows["breach_probability"] = probs
flows["breach_predicted"] = (probs >= 0.6).astype(int)

print("[+] Breach threshold = 0.60")
print(f"[!] Final predicted breaches: {flows['breach_predicted'].sum()}")


# ============================================================
# 8. SAVE RESULT
# ============================================================

flows.to_csv("lightgbm_breach_predictions.csv")
print("[+] Saved results to lightgbm_breach_predictions.csv")
print("[DONE]")
