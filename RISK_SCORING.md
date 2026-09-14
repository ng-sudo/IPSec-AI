# IPsec Risk and Security Scoring

The `risk_engine` package converts deterministic findings from `security_engine` into category scores, an overall security score, a risk level, and threat/risk matrix data. It does not parse packets, run ML, generate reports, or provide frontend functionality.

## Project-specific methodology

This is an IPSecAI project methodology, not an official external standard.

| Category | Weight |
| --- | ---: |
| Cryptographic Strength | 25% |
| Configuration Compliance | 20% |
| SA Security | 15% |
| Key Management | 15% |
| Replay Protection | 10% |
| PFS | 5% |
| Metadata Exposure | 10% |

Each available finding is converted from severity to a category score using the default penalties:

- `info`: 0% penalty, score 100
- `low`: 15% penalty, score 85
- `medium`: 40% penalty, score 60
- `high`: 70% penalty, score 30
- `critical`: 100% penalty, score 0

A category score is the mean of its available finding scores. The overall score is the configured weighted average. When some categories are unavailable, the engine computes a partial score from known category weights, exposes `known_weight`, marks `score_status` as `partial`, and sets `risk_level` to `insufficient_data`. When no category is known, `overall_score` is `null`. Missing information never becomes a secure score.

For complete scores, risk levels are project thresholds: `info` at 80-100, `low` at 60-79.99, `moderate` at 40-59.99, `high` at 20-39.99, and `critical` below 20. Partial or unavailable scores always use `insufficient_data`.

## Threat/risk matrix

Each category becomes a matrix entry containing its security score, status, evidence, configured impact from 1 to 5, and a likelihood from 1 to 5 derived from the highest known finding severity. These likelihood and impact values are project-specific display data, not a standardized threat model.

## Configuration

```python
from risk_engine import RiskScoringEngine, ScoringConfig

config = ScoringConfig(weights={
    "cryptographic_strength": 0.30,
    "configuration_compliance": 0.20,
    "sa_security": 0.15,
    "key_management": 0.10,
    "replay_protection": 0.10,
    "pfs": 0.05,
    "metadata_exposure": 0.10,
})
result = RiskScoringEngine(config).score(assessment)
```

The result preserves rule IDs and evidence for every category so a score can be traced back to the source findings.

## Limitations

- The score reflects only the findings supplied by the deterministic assessment engine.
- A complete score does not prove real-world security or compliance.
- Partial scores are normalized over known weights and must be interpreted with `score_status` and `known_weight`.
- Severity-to-penalty, risk thresholds, likelihood, impact, and category weights are policy choices for this project.
