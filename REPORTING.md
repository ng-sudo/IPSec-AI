# IPSecAI Reporting Module

The `reporting` package generates executive and technical reports from an actual `CompleteAnalysisResponse` or its JSON mapping. It does not parse packets, run ML, assess security, calculate risk, or invent missing values.

## Usage

```python
from reporting import generate_reports, write_reports

bundle = generate_reports(analysis_response)
write_reports(analysis_response, "reports/capture-123")
```

The output directory contains:

- `executive.md`: concise posture, score, risk level, key findings, and recommendations.
- `technical.md`: full protocol, configuration, traffic, AI, findings, controls, scoring, matrix, and limitations detail.
- `reports.json`: structured report sections and fields.

The CLI accepts JSON captured from the FastAPI analysis endpoint:

```bash
python3 -m reporting analysis.json reports/capture-123
```

## Status handling

Every report field carries `observed`, `inferred`, or `unavailable`. Unavailable values are rendered as `Unavailable` and are not replaced with defaults. Findings preserve their original status, evidence, explanation, severity, and recommendation. Reports also state when risk scoring is partial or unavailable.

## Architecture

`generator.py` contains shared extraction, section construction, and Markdown rendering. Executive and technical reports reuse those sections while selecting different levels of detail. `models.py` defines the structured report contract, allowing future API or document renderers to consume the same report data without duplicating analysis logic.

## Limitations

Reports are only as complete as the supplied analysis result. They do not infer configuration absent from the result, inspect encrypted payloads, or claim compliance beyond the deterministic assessment and scoring layers.
