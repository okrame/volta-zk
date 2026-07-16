# Fase-D Code Estimators audit

These execution-only shims reproduce the fase-D regular-LPN estimates pinned
in `docs/fase-d-realpcg-default-design.md`. They target
`1234wangtr/Code_estimators` commit
`969ef60c30cb84c25502d6b7c968f43a362bb438`; they do not change an attack
formula, candidate set, field model, or minimization rule.

From a clean checkout of that exact commit:

```bash
git apply /path/to/volta-zk/scripts/estimators/fase_d_hybrid_logsumexp.patch

PYTHONPATH=. UV_CACHE_DIR=/tmp/volta-estimator-uv-cache \
uv run --offline --with numpy==2.5.1 --with scipy==1.18.0 \
python /path/to/volta-zk/scripts/estimators/fase_d_agb_vectorized.py \
  117440512 6520000 1792

PYTHONPATH=. UV_CACHE_DIR=/tmp/volta-estimator-uv-cache \
uv run --offline --with numpy==2.5.1 --with scipy==1.18.0 \
python /path/to/volta-zk/scripts/estimators/fase_d_agb2_sparse.py \
  117440512 6520000 1792

PYTHONPATH=. UV_CACHE_DIR=/tmp/volta-estimator-uv-cache \
uv run --offline --with numpy==2.5.1 --with scipy==1.18.0 \
python /path/to/volta-zk/scripts/estimators/fase_d_remaining.py
```

Expected top-level results:

```text
AGB=213.85
ISD=208.85010924741465
HYB=199.59980442282708
RISD=227.92519270931604
AGB2=213.85
minimum=199.59980442282708
```

The legacy AGB scan rechecks its winning `(f,mu,d)=(1792,2141,2)` with the
upstream 170-digit `Decimal` implementation. The AGB2 sparse cache preserves
the upstream default-float64 cache's zero value and assignment coercion. The
third command invokes the original ISD and regular-ISD functions and the HYB
function with only the checked-in log-sum-exp patch; it avoids invoking the
two categories intentionally covered by the first two commands.
