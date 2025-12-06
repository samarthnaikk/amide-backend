import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from xgboost import XGBClassifier
import argparse
import warnings

warnings.filterwarnings("ignore")

# ----------------------------------------------------------
# 1. LOAD LOGS AND FEATURE ENGINEERING
# ----------------------------------------------------------

def flow_features(flow):
    packet_sizes = flow["packet_size"].values
    times = flow["timestamp"].values

    return pd.Series({
        "packet_count": len(packet_sizes),
        "packet_min": float(packet_sizes.min()),
        "packet_max": float(packet_sizes.max()),
        "packet_mean": float(packet_sizes.mean()),
        "packet_std": float(packet_sizes.std(ddof=0)),
        "interarrival_mean": float(np.mean(np.diff(times))) if len(times) > 1 else 0.0,
        "interarrival_std": float(np.std(np.diff(times))) if len(times) > 1 else 0.0,
        "bytes_total": float(packet_sizes.sum()),
    })


def extract_flows(path):
    print("[*] Loading logs...")
    df = pd.read_csv(path)

    df["timestamp"] = pd.to_numeric(df["timestamp"], errors="coerce").fillna(0)

    print("[*] Calculating flow-level features...")

    flows = (
        df.groupby(["src_ip", "dst_ip", "src_port", "dst_port"], group_keys=False)
          .apply(flow_features)
          .reset_index()
          .fillna(0)
    )

    print(f"[*] Extracted {len(flows)} flows.")
    return flows


# ----------------------------------------------------------
# 2. LSTM AUTOENCODER (COMPLEX, MULTI-LAYER)
# ----------------------------------------------------------

class LSTMAutoencoder(nn.Module):
    def __init__(self, input_dim, hidden_dim=64, latent_dim=32):
        super().__init__()

        self.encoder = nn.LSTM(input_dim, hidden_dim, batch_first=True, num_layers=2)
        self.enc_linear = nn.Linear(hidden_dim, latent_dim)

        self.dec_linear = nn.Linear(latent_dim, hidden_dim)
        self.decoder = nn.LSTM(hidden_dim, input_dim, batch_first=True, num_layers=2)

    def forward(self, x):
        enc_out, _ = self.encoder(x)
        h_last = enc_out[:, -1, :]
        z = torch.relu(self.enc_linear(h_last))
        dec_h = torch.relu(self.dec_linear(z)).unsqueeze(1)
        dec_out, _ = self.decoder(dec_h.repeat(1, x.size(1), 1))
        return dec_out


# ----------------------------------------------------------
# 3. TRAIN AUTOENCODER
# ----------------------------------------------------------

def train_autoencoder(model, X_tensor, device):
    print("[*] Training LSTM autoencoder...")

    criterion = nn.MSELoss()
    optim = torch.optim.Adam(model.parameters(), lr=0.001)

    for epoch in range(1, 31):
        model.train()
        optim.zero_grad()

        recon = model(X_tensor.to(device))
        loss = criterion(recon, X_tensor.to(device))
        loss.backward()
        optim.step()

        print(f"Epoch {epoch}/30 - Loss: {loss.item():.4f}")

    print("[+] Autoencoder training completed.")
    return model


# ----------------------------------------------------------
# 4. ANOMALY SCORING (NO NUMPY USED!)
# ----------------------------------------------------------

def compute_ae_scores(model, X_tensor, device):
    print("[*] Computing anomaly scores...")

    model.eval()
    with torch.no_grad():
        recon = model(X_tensor.to(device))
        mse = torch.mean((X_tensor - recon) ** 2, dim=(1, 2))

    scores = mse.cpu().tolist()  # PURE PYTHON, NO NUMPY
    print("[+] Scores computed safely without NumPy.")
    return scores


# ----------------------------------------------------------
# 5. MAIN PIPELINE
# ----------------------------------------------------------

def main(logfile):

    flows = extract_flows(logfile)

    features = [
        "packet_count", "packet_min", "packet_max", "packet_mean",
        "packet_std", "interarrival_mean", "interarrival_std", "bytes_total"
    ]

    print("[*] Scaling features...")
    scaler = StandardScaler()
    X = scaler.fit_transform(flows[features])

    device = "cpu"
    print(f"[*] Using device: {device}")

    # Torch input shape: (batch, seq_len=1, features)
    X_tensor = torch.tensor(X, dtype=torch.float32).unsqueeze(1)

    # Build model
    print("[*] Building LSTM autoencoder...")
    model = LSTMAutoencoder(input_dim=X.shape[1]).to(device)

    # Train
    model = train_autoencoder(model, X_tensor, device)

    # Anomaly scoring
    flows["ae_score"] = compute_ae_scores(model, X_tensor, device)

    # Isolation Forest Pseudo Labels
    print("[*] Generating anomaly labels via Isolation Forest...")
    iso = IsolationForest(contamination=0.15, random_state=42)
    labels = iso.fit_predict(flows[features])
    flows["label"] = (labels == -1).astype(int)
    print(f"[!] Pseudo anomalies: {flows['label'].sum()}")

    # Train XGBoost classifier
    print("[*] Training XGBoost...")

    clf = XGBClassifier(
        n_estimators=400,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        reg_lambda=2,
        tree_method="hist"
    )

    clf.fit(X, flows["label"])

    # Predict breach probability
    probs = clf.predict_proba(X)[:, 1]
    flows["breach_prob"] = probs

    threshold = 0.6
    flows["breach"] = (probs >= threshold).astype(int)

    print(f"[!] Total predicted breaches: {flows['breach'].sum()}")

    flows.to_csv("xgb_lstm_predictions.csv", index=False)
    print("[+] Results saved to xgb_lstm_predictions.csv")
    print("[DONE]")


# ----------------------------------------------------------
# RUN
# ----------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--logfile", type=str, required=True)
    args = parser.parse_args()

    main(args.logfile)
