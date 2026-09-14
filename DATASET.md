# IPSecAI Encrypted ESP Dataset

The dataset pipeline creates capture-level records for encrypted ESP traffic-type classification. It does not train or run an ML model.

## Collection process

1. Render and deploy one controlled strongSwan scenario.
2. Run the scenario once for one traffic type using `--traffic-type icmp|tcp|udp|iperf`.
3. Capture IKE/ESP/AH metadata with `testbed/scripts/capture.sh`.
4. Store the PCAP and its `.meta.json` sidecar under `dataset/raw/`.
5. Build manifests with:

```bash
python3 -m dataset build dataset/raw dataset/processed --seed 26160
```

The sidecar must contain `scenario_id`, a `labels` object, and exactly one `traffic_type` either at the sidecar top level or in `labels`. A scenario's configured `traffic_types` list is accepted only when it contains one value. Combined traffic captures are rejected because they do not have a single ground-truth class.

Example testbed command:

```bash
sudo testbed/scripts/run_scenario.sh scen_01_tunnel_aes128cbc_sha256_dh14_pfs_ipv4 --traffic-type tcp
```

## Record contents

Each record contains:

- `capture_id` and `pcap_file`
- `scenario_id`
- `vpn_configuration`: IP version, tunnel/transport mode, IKE version, cipher, integrity, PRF, DH group, PFS, and authentication method
- `traffic_type`: the ground-truth encrypted traffic class
- `protocol_metadata`: observable IKE/IPsec/ESP/AH metadata
- `flow_features`: packet count, byte count, packet-size statistics, inter-arrival statistics, duration/rates, ESP ratio, SPI/sequence features, and directionality summary
- `labels`: classification and scenario labels
- `split`: `train`, `validation`, or `test`

Encrypted payload contents are never extracted.

## Split strategy and leakage prevention

Splits are assigned at `scenario_id` group level using a deterministic SHA-256 ordering and the supplied seed. Every capture belonging to one scenario remains in exactly one split. Captures are never randomly divided packet-by-packet or flow-by-flow across splits. The validator rejects a manifest where a scenario or capture occurs in multiple splits.

At least three distinct scenarios are required to build all three splits. Use separate scenario configurations and repeated captures to increase dataset size without weakening the group boundary. The output contains `manifest.json`, `train.jsonl`, `validation.jsonl`, `test.jsonl`, and `validation.json`.

Validate an existing manifest with:

```bash
python3 -m dataset validate dataset/processed/manifest.json
```

## Limitations

- Dataset quality depends on the controlled testbed establishing the intended SA and generating the requested traffic.
- A capture-level traffic label assumes one traffic generator per capture; mixtures are intentionally unsupported.
- Scenario-level separation can make the test set small when only a few scenarios exist.
- Flow features are metadata and timing/size statistics only; encrypted application content is unavailable.
- The split strategy prevents scenario leakage but does not measure environmental or implementation diversity outside the configured testbed.
