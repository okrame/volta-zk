# VOLTA-ZK — working instructions

Research prototype for designated-verifier proofs of fixed-point transformer
inference using VOLE-MAC blind GKR.

## Start here

Read the [active design](docs/c7.1/design.md), then the relevant sections of
the [specifications](docs/c7.1/specs.md) and [security proof](docs/c7.1/security.md). Use
the [documentation index](docs/README.md) for procedures, reusable evidence
and history. Load historical material only when the task
needs it; earlier milestones and their runbooks are not current authority.

The owner's current instructions take precedence. The five active documents
define the construction, implementation status, test procedures and authorization.
Resolve an actual conflict explicitly instead of importing an
old gate or treating an implementation choice as a new permission request.

## Working autonomously

Proceed with authorized local work and routine implementation choices. Ask
only when a missing decision changes the requested scope, protocol guarantees,
trust model or spending authorization. A historical failure remains a failure
of that construction; assess its premises when reusing the component.
An active hard stop blocks the affected line until its stated condition is
resolved, without blocking independent authorized work.

Preserve unrelated work. Use scoped commits for completed work. Run checks
proportionate to the change; documentation edits need document checks, not
protocol builds. Read [local tests](docs/c7.1/local-tests.md)
before compilation or artifact generation, and [RunPod tests](docs/c7.1/runpod-tests.md)
before provider work. Local work stays small; E2E/heavy runs require authorized
hardware and explicit spending approval.

## Living documentation and immutable evidence

The five active documents are editable summaries. Replace stale statements
when results, open issues, authorization or next actions change; Git preserves
revisions. Record substantive decisions with their reason and evidence links.
Keep dated evidence and superseded decisions in `docs/c7.1-history`.
Keep only design.md, specs.md, security.md, local-tests.md and runpod-tests.md
in `docs/c7.1`; other repository entry points contain navigation only.
Update affected documents together; there is no mandatory capsule word count.

Raw benchmark records, research sources and frozen historical snapshots are
immutable. New runs use new files under
`benchmarks/results/<milestone>-<date>-<gitsha>.json`; a run of record needs a
clean tree and `git_dirty: false`. Preserve failures and provenance. Correct a
record through a linked new record, never by overwriting the old result.

## Scientific boundaries

Distinguish targets, analytic screens, component checks and measured complete
results. A `credit:false` screen grants no protocol or hardware credit. Trace
runtime claims to applicable Lean lemmas and state any undischarged assumptions
in the active design before relying on them. Frozen formal milestones and
quantization references change only when their protocol statement changes.

Use the active design's semantics and complete resource accounting. PCS
openings terminate in VOLE-authenticated values; session correlations are
one-time and domain-separated. No per-token proof/PCS shortcuts. Production
uses real/AES PCG and fails closed, including on unavailable GPU execution.

## Research sources

Relevant online PDFs have standing owner authorization for AnyDoc conversion.
Save each PDF and same-stem Markdown under `/home/okrame/projects/volta-zk/sota`,
read the Markdown, and never overwrite existing sources. No per-PDF approval.
