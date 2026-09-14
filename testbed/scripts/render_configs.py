#!/usr/bin/env python3
"""
render_configs.py — PS 26160 IPSecAI Testbed Config Renderer
=============================================================
Loads testbed/scenarios/scenarios.yaml, validates every scenario entry
against testbed/scenarios/schema.yaml, then renders four Jinja2 templates
per scenario into testbed/configs/generated/<scenario_id>/.

Also writes a labels.json sidecar in each generated directory, which the
ML pipeline (Phase 2+) uses to associate PCAP files with ground-truth labels.

Usage
-----
    # Render all scenarios
    python3 render_configs.py

    # Render a single scenario
    python3 render_configs.py --scenario scen_01_tunnel_aes128cbc_sha256_dh14_pfs_ipv4

    # Dry-run (validate only, no files written)
    python3 render_configs.py --dry-run

    # Custom PSK (overrides auto-generated PSK)
    python3 render_configs.py --psk "MyTestbedSecret123"

Requirements
------------
    pip install Jinja2 PyYAML jsonschema

Exit codes
----------
    0  — success
    1  — validation error (schema violation)
    2  — template rendering error
    3  — I/O error
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import secrets
import string
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Dependency imports with helpful error messages
# ---------------------------------------------------------------------------
try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is not installed. Run: pip install PyYAML", file=sys.stderr)
    sys.exit(3)

try:
    import jsonschema
    from jsonschema import validate, ValidationError
except ImportError:
    print("ERROR: jsonschema is not installed. Run: pip install jsonschema", file=sys.stderr)
    sys.exit(3)

try:
    from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError
except ImportError:
    print("ERROR: Jinja2 is not installed. Run: pip install Jinja2", file=sys.stderr)
    sys.exit(3)

# ---------------------------------------------------------------------------
# Path constants (relative to this script's location)
# ---------------------------------------------------------------------------
SCRIPT_DIR    = Path(__file__).resolve().parent
TESTBED_DIR   = SCRIPT_DIR.parent
SCENARIOS_DIR = TESTBED_DIR / "scenarios"
TEMPLATES_DIR = TESTBED_DIR / "configs" / "templates"
GENERATED_DIR = TESTBED_DIR / "configs" / "generated"

SCENARIOS_FILE = SCENARIOS_DIR / "scenarios.yaml"
SCHEMA_FILE    = SCENARIOS_DIR / "schema.yaml"

# Templates to render per scenario
TEMPLATES = {
    "swanctl.conf":    "swanctl.conf.j2",      # Primary IKEv2 path
    "ipsec.conf":      "ipsec.conf.j2",         # Legacy / IKEv1 fallback
    "ipsec.secrets":   "ipsec.secrets.j2",      # PSK / cert secrets
    "strongswan.conf": "strongswan.conf.j2",    # Daemon settings
}

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("render_configs")


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def generate_psk(length: int = 32) -> str:
    """Generate a cryptographically random PSK string."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def load_yaml(path: Path) -> Any:
    """Load a YAML file and return the parsed object."""
    try:
        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except FileNotFoundError:
        log.error("File not found: %s", path)
        sys.exit(3)
    except yaml.YAMLError as exc:
        log.error("YAML parse error in %s: %s", path, exc)
        sys.exit(3)


def validate_scenario(scenario: dict, schema: dict, scenario_index: int) -> None:
    """Validate a single scenario dict against the JSON Schema."""
    try:
        validate(instance=scenario, schema=schema)
    except ValidationError as exc:
        log.error(
            "Schema validation failed for scenario #%d (id=%s):\n  %s",
            scenario_index,
            scenario.get("id", "<unknown>"),
            exc.message,
        )
        log.error("  Path: %s", " -> ".join(str(p) for p in exc.absolute_path))
        sys.exit(1)


def build_template_context(scenario: dict, psk_secret: str) -> dict:
    """Build the Jinja2 template rendering context for a scenario."""
    return {
        "scenario": type("Scenario", (), scenario)(),   # dot-access wrapper
        "psk_secret": psk_secret,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def render_template(env: Environment, template_name: str, context: dict) -> str:
    """Render a single Jinja2 template and return the result string."""
    try:
        template = env.get_template(template_name)
        return template.render(**context)
    except TemplateError as exc:
        log.error("Template rendering error in %s: %s", template_name, exc)
        sys.exit(2)


def write_file(path: Path, content: str, dry_run: bool) -> None:
    """Write content to a file, creating parent directories as needed."""
    if dry_run:
        log.info("  [DRY-RUN] Would write: %s (%d bytes)", path, len(content))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    log.info("  Wrote: %s", path)


def build_labels(scenario: dict, psk_secret: str, generated_at: str) -> dict:
    """
    Build the labels.json sidecar for a scenario.

    This JSON file is the ground-truth label set consumed by the ML pipeline
    (Phase 2+). It is written alongside the rendered configs and is also
    copied next to each PCAP file by capture.sh.
    """
    return {
        "schema_version": "1.0",
        "generated_at": generated_at,
        "scenario": {
            "id":           scenario["id"],
            "name":         scenario["name"],
            "description":  scenario["description"],
        },
        "labels": {
            # IPsec dimensions — ground truth for ML classification
            "ipsec_mode":       scenario["mode"],           # tunnel | transport
            "ike_version":      scenario["ike_version"],    # 1 | 2
            "encryption":       scenario["encryption"],     # aes128cbc | aes256cbc | aes128gcm16 | aes256gcm16
            "integrity":        scenario.get("integrity"),  # sha256 | sha384 | sha512 | null
            "prf":              scenario["prf"],             # sha256 | sha384 | sha512
            "dh_group":         scenario["dh_group"],       # modp2048 | ecp256 | ecp384
            "pfs_enabled":      scenario["pfs"],            # true | false
            "ip_version":       scenario["ip_version"],     # 4 | 6
            "auth_method":      scenario["auth_method"],    # psk | cert
            "traffic_types":    scenario["traffic_types"],  # [icmp, tcp, udp, iperf]
            # Derived labels for ML feature engineering
            "is_aead":          "gcm" in scenario["encryption"],
            "cipher_bits":      128 if "128" in scenario["encryption"] else 256,
            "dh_group_bits":    _dh_group_bits(scenario["dh_group"]),
            "min_kernel":       scenario.get("min_kernel"),
        },
        "tags": scenario.get("tags", []),
        # Capture metadata (filled in by capture.sh at runtime)
        "capture": {
            "pcap_file":        None,   # set by capture.sh
            "duration_seconds": scenario["capture_duration"],
            "interface":        None,   # set by capture.sh
            "timestamp_start":  None,   # set by capture.sh
            "timestamp_end":    None,   # set by capture.sh
            "packet_count":     None,   # set by check_pcap.py
        },
    }


def _dh_group_bits(dh_group: str) -> int:
    """Return the security-bit equivalent of a DH group identifier."""
    mapping = {
        "modp2048": 2048,
        "ecp256":   256,
        "ecp384":   384,
    }
    return mapping.get(dh_group, 0)


# ---------------------------------------------------------------------------
# Main rendering logic
# ---------------------------------------------------------------------------

def render_scenario(
    scenario: dict,
    env: Environment,
    schema: dict,
    scenario_index: int,
    psk_override: str | None,
    dry_run: bool,
) -> None:
    """Validate and render all config files for a single scenario."""
    scenario_id = scenario.get("id", f"scenario_{scenario_index}")
    log.info("Processing scenario: %s", scenario_id)

    # 1. Validate against schema
    validate_scenario(scenario, schema, scenario_index)

    # 2. Generate or use provided PSK
    psk_secret = psk_override if psk_override else generate_psk()

    # 3. Build template context
    generated_at = datetime.now(timezone.utc).isoformat()
    context = {
        "scenario": type("Scenario", (), scenario)(),
        "psk_secret": psk_secret,
        "generated_at": generated_at,
    }

    # 4. Output directory for this scenario
    out_dir = GENERATED_DIR / scenario_id

    # 5. Render each template
    for output_filename, template_filename in TEMPLATES.items():
        rendered = render_template(env, template_filename, context)
        write_file(out_dir / output_filename, rendered, dry_run)

    # 6. Write labels.json sidecar
    labels = build_labels(scenario, psk_secret, generated_at)
    labels_json = json.dumps(labels, indent=2, ensure_ascii=False)
    write_file(out_dir / "labels.json", labels_json, dry_run)

    # 7. Write a README for the generated directory
    readme_content = (
        f"# Generated configs for: {scenario_id}\n\n"
        f"**Scenario:** {scenario.get('name', '')}\n\n"
        f"Generated at: {generated_at}\n\n"
        "## Files\n\n"
        "| File | Purpose |\n"
        "|------|---------|\n"
        "| `swanctl.conf`    | Modern IKEv2 config (swanctl/VICI) |\n"
        "| `ipsec.conf`      | Legacy config (IKEv1 / fallback) |\n"
        "| `ipsec.secrets`   | PSK / cert secrets (**never commit**) |\n"
        "| `strongswan.conf` | Daemon settings (logging, plugins) |\n"
        "| `labels.json`     | Ground-truth labels for ML pipeline |\n\n"
        "> **WARNING:** `ipsec.secrets` and `swanctl.conf` contain the PSK.\n"
        "> This directory is `.gitignore`'d. Do not commit these files.\n"
    )
    write_file(out_dir / "README.md", readme_content, dry_run)

    log.info("  Scenario %s rendered successfully.", scenario_id)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Render strongSwan configs from scenarios.yaml",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--scenario", "-s",
        metavar="SCENARIO_ID",
        help="Render only this scenario ID (default: render all)",
    )
    parser.add_argument(
        "--dry-run", "-n",
        action="store_true",
        help="Validate and render but do not write any files",
    )
    parser.add_argument(
        "--psk",
        metavar="SECRET",
        help="Use this PSK for all scenarios instead of auto-generating",
    )
    parser.add_argument(
        "--scenarios-file",
        metavar="PATH",
        default=str(SCENARIOS_FILE),
        help=f"Path to scenarios.yaml (default: {SCENARIOS_FILE})",
    )
    parser.add_argument(
        "--schema-file",
        metavar="PATH",
        default=str(SCHEMA_FILE),
        help=f"Path to schema.yaml (default: {SCHEMA_FILE})",
    )
    parser.add_argument(
        "--output-dir",
        metavar="PATH",
        default=str(GENERATED_DIR),
        help=f"Output directory for generated configs (default: {GENERATED_DIR})",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose (DEBUG) logging",
    )
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Override paths if provided
    scenarios_file = Path(args.scenarios_file)
    schema_file    = Path(args.schema_file)
    generated_dir  = Path(args.output_dir)

    log.info("Loading scenarios from: %s", scenarios_file)
    log.info("Loading schema from:    %s", schema_file)
    log.info("Output directory:       %s", generated_dir)

    # Load scenarios and schema
    scenarios_data = load_yaml(scenarios_file)
    schema_data    = load_yaml(schema_file)

    if not isinstance(scenarios_data, dict) or "scenarios" not in scenarios_data:
        log.error("scenarios.yaml must have a top-level 'scenarios' key.")
        sys.exit(1)

    scenarios = scenarios_data["scenarios"]
    log.info("Found %d scenario(s) in %s", len(scenarios), scenarios_file)

    # Filter to a single scenario if requested
    if args.scenario:
        scenarios = [s for s in scenarios if s.get("id") == args.scenario]
        if not scenarios:
            log.error("Scenario '%s' not found in %s", args.scenario, scenarios_file)
            sys.exit(1)
        log.info("Rendering single scenario: %s", args.scenario)

    # Set up Jinja2 environment
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        undefined=StrictUndefined,      # Fail on undefined variables
        trim_blocks=True,               # Remove newline after block tags
        lstrip_blocks=True,             # Strip leading whitespace from block tags
        keep_trailing_newline=True,
    )

    # Render each scenario
    success_count = 0
    for idx, scenario in enumerate(scenarios, start=1):
        try:
            render_scenario(
                scenario=scenario,
                env=env,
                schema=schema_data,
                scenario_index=idx,
                psk_override=args.psk,
                dry_run=args.dry_run,
            )
            success_count += 1
        except SystemExit:
            raise
        except Exception as exc:
            log.error("Unexpected error rendering scenario #%d: %s", idx, exc)
            if args.verbose:
                import traceback
                traceback.print_exc()
            sys.exit(2)

    if args.dry_run:
        log.info("DRY-RUN complete. %d scenario(s) validated successfully.", success_count)
    else:
        log.info(
            "Rendering complete. %d/%d scenario(s) written to %s",
            success_count, len(scenarios), generated_dir,
        )


if __name__ == "__main__":
    main()
