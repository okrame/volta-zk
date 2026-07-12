# Benchmark artifacts

`results/` is the append-only source data for the P0–P7 tables and figures.
Files use `<milestone>-<date>-<gitsha>.json`; helpers add a numeric suffix
instead of overwriting an existing run. A run of record must report
`git_dirty: false` and a complete machine/cloud fingerprint.

Do not rename a result to make it look like a different commit or hardware
run. Diagnostic/quick runs remain in place and are filtered by
`scripts/report.py` rather than deleted.

`weights/` contains tracked manifests/goldens plus generated large files.
`gpt2s-q.bin` and `model.safetensors` are deliberately ignored; regenerate
them with `scripts/export_gpt2.py` and validate all frozen artifacts with:

```bash
sha256sum -c benchmarks/weights/SHA256SUMS
```

Large profiler traces belong in the ignored `benchmarks/raw/` or
`benchmarks/tmp/` directories, not in `results/`.
