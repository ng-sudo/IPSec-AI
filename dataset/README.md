# Dataset Package

The `dataset` package builds and validates capture-level JSONL manifests for encrypted ESP traffic classification.

```bash
python3 -m dataset build dataset/raw dataset/processed
python3 -m dataset validate dataset/processed/manifest.json
```

See the repository-level [DATASET.md](../DATASET.md) for collection, feature, labeling, split, and limitation details.
