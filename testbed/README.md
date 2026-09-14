# Phase 1: Controlled IPsec VPN Testbed

This directory contains the controlled Linux-based IPsec environment used to generate reproducible labeled traffic for the PS 26160 project. It is limited to Phase 1 only: scenario-driven IPsec configuration, deployment, validation, and PCAP capture.

## Scope

Included in this phase:

- strongSwan-based testbed topology
- scenario templates and declarative scenario definitions
- namespace-based Linux VPN setup
- capture and validation scripts
- reproducible packet-generation flow for labeled traffic

Excluded from this phase:

- ML analysis
- dashboard or UI
- packet classification model implementation
- fabricated analysis results

## Prerequisites

Run this testbed on a Linux host with root privileges. The following tools are required:

- Linux kernel with IPsec/XFRM support
- root or CAP_NET_ADMIN access
- strongSwan package (`charon`, `swanctl`, `ipsec`)
- `iproute2` (`ip`, `tc`, `ss`)
- Python 3.10+
- `tcpdump` or `tshark`
- `ping` / `ping6`
- optional: `iperf3`, `nc` for traffic generation

Install on Debian/Ubuntu-like systems:

```bash
sudo apt-get update
sudo apt-get install -y strongswan iproute2 python3 python3-yaml python3-jinja2 python3-jsonschema tcpdump tshark iputils-ping iperf3 netcat-openbsd
```

## Project layout

- `scenarios/scenarios.yaml` — scenario catalog
- `scenarios/schema.yaml` — scenario validation schema
- `configs/templates/` — Jinja2 templates for strongSwan config
- `configs/generated/` — rendered scenario configs (not tracked)
- `scripts/` — setup, deployment, traffic, capture, and teardown scripts
- `validate/` — tunnel and PCAP validation helpers

## Setup flow

1. Render scenario files:

```bash
cd testbed/scripts
python3 render_configs.py --scenario scen_01_tunnel_aes128cbc_sha256_dh14_pfs_ipv4
```

2. Create namespaces:

```bash
sudo ./setup_namespaces.sh
```

3. Deploy the scenario:

```bash
sudo ./deploy_scenario.sh scen_01_tunnel_aes128cbc_sha256_dh14_pfs_ipv4 --timeout 30
```

4. Start capture:

```bash
sudo ./capture.sh scen_01_tunnel_aes128cbc_sha256_dh14_pfs_ipv4 --duration 30
```

5. Generate traffic:

```bash
sudo ./generate_traffic.sh scen_01_tunnel_aes128cbc_sha256_dh14_pfs_ipv4
```

6. Validate the tunnel:

```bash
sudo ./validate/validate_tunnel.sh scen_01_tunnel_aes128cbc_sha256_dh14_pfs_ipv4
```

7. Cleanup:

```bash
sudo ./teardown_namespaces.sh
```

## Scenario-driven configuration

The testbed is configured via `testbed/scenarios/scenarios.yaml` instead of duplicating scripts. Each entry defines the required PS dimensions:

- mode: tunnel or transport
- encryption: AES-CBC or AES-GCM
- integrity: HMAC or implicit AEAD
- dh_group: modp2048 / ecp256 / ecp384
- pfs: enabled or disabled
- ip_version: IPv4 or IPv6
- traffic_types: icmp, tcp, udp, iperf

The renderer validates the scenario against `testbed/scenarios/schema.yaml` and writes strongSwan configuration files into the generated folder.

## Validation commands

Use these commands to verify that a request has been established as expected:

```bash
sudo ./validate/validate_tunnel.sh <scenario_id>
python3 ./validate/check_pcap.py /path/to/scenario_capture.pcap
```

A successful validation means:

- each peer has at least one active ESP SA in `ip xfrm state`
- the tunnel can pass basic reachability checks
- the capture contains IPsec-related packets

## Known limitations

- The testbed is intentionally Linux-specific and relies on strongSwan + kernel XFRM.
- It is designed for reproducible, controlled traffic generation, not general internet traffic emulation.
- Packet analysis remains at the validation layer only; no ML classification system is part of this phase.
- Some AEAD and IPv6 kernel combinations require a sufficiently modern Linux kernel.
