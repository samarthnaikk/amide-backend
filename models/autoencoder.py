#!/usr/bin/env python3
"""
Autoencoder-based Unsupervised Breach Detection
Input logs: timestamp,src_ip,src_port,dst_ip,dst_port,packet_size,tcp_flags,seq,ack,window
"""

import pandas as pd
import numpy as np
from scipy.stats import entropy
from sklearn.preprocessing import StandardScaler
from sklearn.mixture import GaussianMixture
import tensorflow as tf
from tensorflow.keras import layers, models

LOG_FILE = "network_logs.csv"

# ============================================================
# 1. LOAD LOG DATA
# ============================================================

print("[*] Loading logs...")
df = pd.read_csv(LOG_FILE)

df["timestamp"] = pd.to_datetime(df["timestamp"])
df = df.sort_values("timestamp")
df["ts_float"] = df["timestamp"].astype(np.int64) / 1e9


# ============================================================
# 2. FEATURE ENGINEERING – FLOW-LEVEL
# ============================================================

print("[*] Calculating flow-based features...")

df["iat"] = df.groupby(
    ["src_ip", "src_port", "dst_ip", "dst_port"]
)["ts_float"].diff().fillna(0)

df["seq_delta"] = df.groupby(
    ["src_ip", "src_port", "dst_ip", "dst_port"]
)["seq"].diff().fillna(0)

df["ack_delta"] = df.groupby(
    ["src_ip", "src_port", "dst_ip", "dst_port"]
)["ack"].diff().fillna(0)


def flow_features(flow):

    p = flow["packet_size"].values
    iat = flow["iat"].values
    wnd = flow["window"].values
    sd = flow["seq_delta"].values
    ad = flow["ack_delta"].values

    # Packet-size entropy
    hist = np.histogram(p, bins=10, density=True)[0]
    p_entropy = entropy(hist + 1e-9)

    return pd.Series({
        "psize_mean": p.mean(),
        "psize_std": p.std(),
        "iat_mean": iat.mean(),
        "iat_std": iat.std(),
        "window_mean": wnd.mean(),
        "seq_delta_std": sd.std(),
        "ack_delta_std": ad.std(),
        "psize_entropy": p_entropy
    })


flows = df.groupby(
    ["src_ip", "src_port", "dst_ip", "dst_port"]
).apply(flow_features).fillna(0)

print(f"[*] Extracted {len(flows)} flows.")


# ============================================================
# 3. SCALE FEATURES
# ============================================================

scaler = StandardScaler()
X = scaler.fit_transform(flows.values)

print("[*] Features scaled.")


# ============================================================
# 4. AUTOENCODER MODEL
# ============================================================

print("[*] Building autoencoder model...")

input_dim = X.shape[1]

inputs = layers.Input(shape=(input_dim,))
e = layers.Dense(32, activation="relu")(inputs)
e = layers.Dense(16, activation="relu")(e)
latent = layers.Dense(8, activation="relu")(e)

d = layers.Dense(16, activation="relu")(latent)
d = layers.Dense(32, activation="relu")(d)
outputs = layers.Dense(input_dim, activation="linear")(d)

autoencoder = models.Model(inputs, outputs)
autoencoder.compile(optimizer="adam", loss="mse")

autoencoder.summary()

print("[*] Training autoencoder...")
autoencoder.fit(
    X, X,
    epochs=30,
    batch_size=32,
    validation_split=0.1,
    verbose=1
)


# ============================================================
# 5. RECONSTRUCTION ERROR = ANOMALY SCORE
# ============================================================

print("[*] Computing anomaly scores...")

preds = autoencoder.predict(X)
mse = np.mean((X - preds) ** 2, axis=1)
flows["recon_error"] = mse


# ============================================================
# 6. BREACH PROBABILITY USING GAUSSIAN MIXTURE MODEL
#    (2 clusters: normal & suspicious)
# ============================================================

print("[*] Fitting Gaussian Mixture Model for breach probability...")

m = GaussianMixture(n_components=2, random_state=42)
m.fit(mse.reshape(-1, 1))

breach_prob = m.predict_proba(mse.reshape(-1, 1))
breach_prob = breach_prob[:, breach_prob.mean(axis=0).argmax()]  # take "anomalous" cluster

flows["breach_probability"] = breach_prob


# ============================================================
# 7. FINAL BREACH PREDICTION
# ============================================================

threshold_prob = 0.60   # you can tune this cutoff

flows["breach_predicted"] = flows["breach_probability"] > threshold_prob

print(f"[+] Breach threshold probability = {threshold_prob}")
print("[*] Breach predictions complete.")


# ============================================================
# 8. SAVE RESULTS
# ============================================================

flows.to_csv("breach_predictions.csv")
print("[+] Saved results to breach_predictions.csv")

num_breaches = flows["breach_predicted"].sum()
print(f"[!] Predicted potential breaches: {num_breaches}")


print("[DONE]")
