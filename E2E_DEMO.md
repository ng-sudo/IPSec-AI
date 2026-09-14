# IPSecAI End-to-End Demonstration

This procedure connects the completed components:

`IPsec testbed -> traffic generation -> PCAP capture -> packet analysis -> feature extraction -> AI classification -> security assessment -> risk scoring -> FastAPI -> React dashboard -> reports`

The Python integration test [tests/test_end_to_end_workflow.py](tests/test_end_to_end_workflow.py) runs the same contract with controlled PCAP fixtures, a trained scikit-learn model, FastAPI's test client, and both report generators. It verifies that secure and weak VPN configuration inputs produce different security findings and risk scores.

## 1. Generate secure and weak captures on Linux

Run on a Linux host with root/CAP_NET_ADMIN and the testbed prerequisites installed. The secure baseline is `scen_01`; the intentionally weaker comparison is `scen_08`, which disables PFS and uses AES-128-CBC.

```bash
cd testbed/scripts
sudo ./run_scenario.sh scen_01_tunnel_aes128cbc_sha256_dh14_pfs_ipv4 --traffic-type tcp
sudo ./run_scenario.sh scen_08_tunnel_aes128cbc_sha256_dh14_nopfs_ipv4 --traffic-type tcp
```

Each run renders strongSwan configuration, establishes the namespace VPN, generates one traffic class, captures IKE/ESP/AH traffic, validates the tunnel, and writes a PCAP plus sidecar under `dataset/raw/`. Run additional catalog scenarios and traffic types to provide at least three scenario groups for leakage-safe train/validation/test splits.

Check each capture before continuing:

```bash
python3 testbed/validate/check_pcap.py dataset/raw/<capture>.pcap
```

## 2. Build the dataset and train the model

From the repository root:

```bash
python3 -m dataset build dataset/raw dataset/processed --seed 26160
python3 -m ml_classifier train dataset/processed/manifest.json models/esp-traffic.joblib
```

The dataset builder rejects mixed traffic labels. The classifier uses scalar flow features only and selects between Random Forest and Gradient Boosting using measured validation macro-F1.

## 3. Start the API

```bash
IPSECAI_MODEL_PATH=models/esp-traffic.joblib \
  uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

OpenAPI is available at `http://127.0.0.1:8000/docs`.

Upload/select a capture and analyze it through the API:

```bash
curl -F "file=@dataset/raw/<capture>.pcap" http://127.0.0.1:8000/api/v1/captures
curl -X POST http://127.0.0.1:8000/api/v1/captures/<capture_id>/analyze \
  -H 'Content-Type: application/json' \
  -d '{"vpn_configuration":{"ipsec_mode":"tunnel","ike_version":2,"encryption":"aes128cbc","integrity":"sha256","prf":"sha256","dh_group":"modp2048","pfs_enabled":true,"ip_version":4,"auth_method":"psk"}}' \
  > analysis.json
```

The response is the source of truth for the dashboard and reports. It contains packet analysis, features, model prediction/confidence/version, findings, risk score, threat matrix, and metadata statuses.

## 4. Run the dashboard

In a second terminal:

```bash
cd frontend
VITE_API_URL=http://127.0.0.1:8000 npm run dev
```

Open `http://127.0.0.1:5173`, upload or select a capture, enter any known VPN context, and run analysis. The UI does not contain sample analysis values; it renders the API response and marks missing values unavailable.

## 5. Generate reports from the same result

```bash
python3 -m reporting analysis.json reports/<capture_id>
```

This writes `executive.md`, `technical.md`, and `reports.json`. Both reports use the same structured API result displayed by the dashboard.

## Verification checklist

- Packet count and byte statistics match direct packet analysis.
- AI class, confidence, and model version come from the persisted trained model.
- Security findings retain evidence and status.
- Missing key lifetime, replay, or configuration data remains unavailable.
- Risk scores are produced by the documented project-specific weights and status policy.
- `CompleteAnalysisResponse` validates the API payload used by the dashboard.
- Reports are generated from that same response and include its score/evidence.
- Secure and weak scenarios differ in PFS, cipher/authentication findings, and risk posture.

Run all tests:

```bash
python3 -m pytest -q
cd frontend && npm test && npm run build
```

The Linux testbed itself cannot run on Windows; the controlled Python end-to-end test provides a reproducible cross-platform integration check for every downstream stage.
