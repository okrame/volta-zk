# Current status — C7.1 Gemma-31B

Updated 2026-09-07. This is an editable working summary; Git retains previous
versions. [Documentation index](README.md) · [Design](c7.1-gemma31b-design.md)
· [Historical ledger](prototype-status-history-2026-09-07.md).

## Active authority — read first

C7.1 is the active construction: stateful private-weight Gemma-31B with
session VOLE-MAC boundaries and committed-weight evaluations. Earlier lines
are historical; reuse requires checking their hypotheses and counterexamples.
The [active design](c7.1-gemma31b-design.md) defines the relation, model identity,
security games and resource accounting.

**Targets, not measurements:** 45–50 s warm complete prover; 6.4–8.2 s verifier
on four CPU cores of this VM's class; preferred 30 MB, maximum 35 MB complete
certificate. Soundness and malicious-verifier privacy must each exceed 78 bits
lifetime. Up to four packed-W proof reads on the same H100 as inference;
6,442,450,944-byte total temporary arena, GPU peak below 80 billion bytes,
no spill, second weight copy or full codeword. Persistent model setup is capped
at 2.10× packed W. Exact scopes are in design §§1, 7 and 8.

**Preserved choices:** pinned checkpoint, Goldilocks/Fp3, offline classical ROM,
global Q64 and 2^20 attempts. Initial workload 100+50, then continuations through
4,096 total context tokens. ModelSetup is Delta-independent; residency,
connection, finite capacity, roots and attempts have separate costs. Slots and
correlations are never reused. One sequential user, live KV preserved; optional
ACK and distinct first activation do not reset consumption or security limits.

**Authorization:** small local preparation and checks may proceed autonomously.
No owner decision is pending. No provider contact, paid GPU, weight download,
heavy build or E2E is authorized now. Every E2E/heavy run requires authorized
hardware and explicit spending authorization after local preparation. See
[build procedures](procedures/build-and-test.md) and [RunPod procedures](procedures/runpod.md).
The owner's 2026-09-07 request prioritizes a complete algorithm with analytic
feasibility proofs before prover implementation and measurements.

## Evidence and open obligations

- The [G1 feasibility analysis](c7.1-feasibility.md) is concluded; admission
  of a complete algorithm is **not passed**. It defines six testable criteria,
  gives a conditional linear-work screen for the clear Hobbit carrier, and
  rejects two specific direct instantiations: reused split masks without
  cross-proof restrictions, and the fixed-width Fp3 column codec at
  `b_P=2^24`, 357 queries per half (35,094,528 bytes for columns alone).
  Neither result proves C7.1 impossible; base-field and different masking
  constructions remain open. See the dossier for premises and scope.
- The [C7.1 diagnostic](../scripts/c7_1_gemma_plan.py) and
  [ten focused tests](../tests/test_c7_1_gemma_plan.py) check paired-fold
  arithmetic, service accounting, candidate integer/Fp3 decompositions,
  and the new two-proof masking counterexample and exact carrier counts.
  The broader 86 non-native Python checks passed during the main integration
  (`bce620f`). They do not prove full cryptography or hardware feasibility.
- The complete carrier/blind MAC/PCS composition and four-read full-prover
  schedule remain unproved. GKR and witness regeneration must fit the same
  source-read and memory accounting; output-bound FS constrains folding order.
- `C71FsLifetimeSound`, adaptive ROM transfer and malicious-verifier privacy
  still need their runtime premises and complete lifetime event/query census.
  Existing conditional Lean lemmas do not discharge these obligations.
- Complete certificate compilation, the physical live-memory schedule and
  full Gemma prover/verifier measurements remain outstanding. No C7.1 E2E,
  security, certificate-size, timing or memory credit is claimed.

## Next work

Follow [design §10](c7.1-gemma31b-design.md#10-ordine-del-lavoro-dopo-lautorizzazione-a-quattro-letture):
first specify and prove a private opening into the session MAC, with mask-root
refresh bound to the same Delta-independent model commitment. Study justified
Fp leaves/code with Fp3 challenges/MAC and fresh masks per attempt; this is not
yet an adopted carrier or a free refresh. Alongside it, close witness and form
availability within the four W reads. Complete the relation, both lifetime
proofs and full certificate/resource accounting before admitting prover
implementation. Then prepare the small checks and, after hardware/spending
authorization, the complete composition case and real Gemma workloads.
The [next constructive obligation](c7.1-feasibility.md#6-prossimo-obbligo-costruttivo)
specifies the required mathematical deliverable; no new owner decision is pending.

## Documentation decision

On 2026-09-07 the owner chose a minimal C7.1 wiki: editable status/design,
immutable evidence, and separate build/RunPod procedures. C7 was merged into
main (`bce620f`), eight missing research files were versioned (`4f7edf0`), and
the C7 worktree was closed before this reorganization. The pre-wiki ledger is
preserved byte-for-byte in the linked historical snapshot. Routine checks
belong in commit/task validation; this page changes when the working state does.
