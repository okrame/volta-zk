# X4c cryptographic build identity and conservative schema-3 migration

## Decision

Future real-weight X4c onboarding and accelerated-online records use schema 3
and a versioned `crypto_build_id`. Schema-2 records and validators remain
immutable and retain their exact same-commit requirement.

The schema-3 admission rule replaces:

`online.git_sha == onboarding.git_sha`

with all of:

1. exact onboarding-record SHA-256;
2. identical nonzero `crypto_build_id` and identity scheme;
3. exact protocol/design/input/configuration/cohort identities;
4. exact five coefficient SHA-256 digests and five roots;
5. exact durable census before and after rebuild;
6. a fresh-process rebuild that reproduces all five roots;
7. a clean online producer source and complete fail-closed lifecycle receipt.

The producer Git SHA and complete clean-source bundle SHA-256 remain mandatory
audit fields, but they need not equal the onboarding producer fields.

## Identity surface

`volta-x4c-crypto-build-v1` is a domain-separated BLAKE3 digest over a
canonical, path-sorted stream. Each entry encodes the relative UTF-8 path
length and bytes followed by the file length and bytes.

The included surface is conservative:

- all Rust `src/**/*.rs`, workspace/crate `Cargo.toml`, `Cargo.lock`,
  `.cargo/config.toml` and `build.rs`;
- all CUDA `.cu`, `.cuh`, `.cpp` and `.h` sources;
- all Lean `.lean` sources plus the Lean toolchain and lake manifests;
- the frozen X4c lifecycle, quantization and private-weight specifications;
- this identity specification.

Python validators, validator tests, status/handoff documentation and benchmark
results are excluded. A change to production Rust, CUDA, Lean, build
configuration or a frozen specification changes the identity conservatively.
Refactoring observability out of a production Rust module may make the surface
more granular later; until then such a Rust edit intentionally requires a new
onboarding.

`clean_source_sha256` is not repurposed. It remains the complete producer
bundle identity and continues to domain-separate the zero-soundness-credit
direct-fold diagnostic sampling.

## Validation receipt

Validation is not written back into an immutable hardware record. The
schema-3 validator emits a separate append-only receipt containing:

- schema and receipt milestone;
- online and onboarding SHA-256;
- rebuild-admission marker SHA-256;
- `crypto_build_id`;
- validator Git SHA and clean/dirty state;
- validator implementation SHA-256;
- validation timestamp;
- exact accepted rule-set identifier and `overall_pass`.

A validator-only correction therefore creates a new receipt for the same two
hardware records. It cannot alter either record, root or durable artifact.

## Forty-five-minute operational target

The registered campaign target is **2,700 seconds** from the first workload
after the pod is reachable through completion of the fresh rebuild. It is the
owner's economic estimate, not a strict deadline. Provider queue/provisioning
latency is reported separately because the repository cannot control it.

The pod wrapper records one shared elapsed wall across onboarding (when
needed) and rebuild. It does not apply a timeout, kill the runner, or turn a
target miss into a validator failure. The online runner writes an append-only,
hash-anchored rebuild-admission marker after all cryptographic, durable,
ownership and cleanup gates pass; no online candidate begins before that
marker exists. Both record and marker state whether the diagnostic target was
met.

A target miss is reported for investigation before another expensive
campaign, but the current run continues unless an independent fail-closed
invariant fails. CPU fallback remains forbidden for that independent reason.
A reused compatible onboarding still requires its durable tier to be
available. Because the previous pod's 9.6-GB durable tier was intentionally
removed, the next pod must perform one new schema-3 onboarding and preserve
its five coefficient files plus five roots on transferable storage.

## Negative requirements

Schema 3 must reject:

- missing or malformed identity/receipt fields;
- differing identity scheme or digest;
- any input, design, config, cohort, coefficient digest or root mismatch;
- dirty producer or validator source;
- modified onboarding bytes;
- durable census drift or incomplete rebuild;
- missing or internally inconsistent campaign timing evidence;
- an automatic CPU fallback.

Changing only `scripts/report.py`, its tests, ledger/handoff prose or raw
results must not change `crypto_build_id`.
