# IPSecAI FastAPI Backend

The backend integration layer is available from `backend.app:app` and keeps orchestration outside route handlers.

## Run

```bash
uvicorn backend.app:app --reload
```

The interactive OpenAPI documentation is available at `/docs`; the machine-readable schema is at `/openapi.json`.

For AI classification, configure a persisted classifier bundle when creating the app:

```python
from backend.app import create_app

app = create_app(
    storage_dir="dataset/uploads",
    model_path="models/esp-traffic.joblib",
)
```

Without a configured bundle, prediction, confidence, and model version are returned with `status: unavailable`; the API never fabricates a prediction.

## Endpoints

- `POST /api/v1/captures`: upload a `.pcap` or `.pcapng` file.
- `GET /api/v1/captures`: list captures available for selection.
- `POST /api/v1/captures/{capture_id}/analyze`: run packet analysis, feature extraction, optional AI classification, deterministic security assessment, and risk scoring.
- `GET /health`: report service health and classifier availability.

The analysis response includes packet-analysis observations, feature observations, prediction confidence, security findings, category/risk scores, threat matrix entries, and metadata inference. Observable fields use `status: observed`; derived values use `status: inferred`; fields unavailable from the PCAP, supplied configuration, or configured model use `status: unavailable`.

## Analysis request

The analysis endpoint accepts VPN configuration metadata when available, for example:

```json
{
  "vpn_configuration": {
    "ipsec_mode": "tunnel",
    "ike_version": 2,
    "encryption": "aes256gcm16",
    "integrity": null,
    "prf": "sha256",
    "dh_group": "ecp384",
    "pfs_enabled": true,
    "ip_version": 4,
    "auth_method": "cert"
  }
}
```

Omitted configuration remains unavailable in the security assessment and risk score. The API performs no frontend rendering, security scoring logic, packet parsing logic, or ML implementation inside route handlers.

## Limitations

- Capture storage is local process-backed storage intended for the prototype.
- Uploaded files are size-limited to 100 MiB and restricted to PCAP extensions.
- A model must be trained and configured separately for AI predictions.
- Encrypted payload contents are not inspected.
