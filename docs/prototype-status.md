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
- [G2: committed MAC opening](c7.1-committed-mac-opening.md) is **active,
  not closed**. A private PCS-verifier circuit derives a local binding-into-MAC
  guarantee from circuit soundness, anchor binding and ordinary PCS soundness;
  it does not assume `BindsIntoMac` as its own conclusion. The literal codec
  using one 8-byte correction per leaf bit is excluded at 357 queries for
  every power-of-two block: even the arena-maximal block needs 41,674,752
  bytes for those corrections alone. The A2 repair now specifies a grouped
  Goldilocks arithmetic hash and a private 30-round power-layer GKR: its
  endpoint is a linear combination of the same authenticated inputs, with
  no new trace PCS. At `b_P=2^24`, 357 study queries, the outer hash/anchor
  payload is 11,200,376 bytes before framing and other components. This is
  component accounting, not complete-certificate or hash-security credit.
- [A3: bounded RS and private recursion](c7.1-recursive-rs-opening.md)
  specifies the previously missing encoder and inner opening down to 32
  private E cells. A fixed algorithmic block cap proves at most 52 source
  FFT butterflies per padded cell; it is a new carrier, not unchanged Hobbit.
  Its component payload is 13,960,568 bytes, including the A2 hash/anchor.
  Known proof arrays total 6,070,425,696 bytes in a conservative union;
  uncompiled staging and the Gemma witness are not included. The interactive
  fixed-oracle argument binds a unique decoded message, not exact codeword
  well-formedness. Compiling arbitrary private roots into the required
  oracles, the precise model relation and adaptive FS remain open; no honest
  setup assumption or complete feasibility credit is introduced.
- The [C7.1 diagnostic](../scripts/c7_1_gemma_plan.py) and
  [focused tests](../tests/test_c7_1_gemma_plan.py) check paired-fold
  arithmetic, service accounting, candidate integer/Fp3 decompositions,
  the two-proof masking counterexample, exact carrier/bit-codec counts,
  the product-check identity and simulator with the C7.1 MAC sign, and A2's
  degree-8/9 round reduction, single input endpoint and resource counts.
  A3 adds small FFT/form/recursion identities and a malformed-codeword
  counterexample distinguishing proximity from exact well-formedness.
  The broader 86 non-native Python checks passed during the main integration
  (`bce620f`). They do not prove full cryptography or hardware feasibility.
- The complete carrier/blind MAC/PCS composition and four-read full-prover
  schedule remain unproved. GKR and witness regeneration must fit the same
  source-read and memory accounting; output-bound FS constrains folding order.
  The literal generic Hobbit wrapper with trace replay requires at least
  seven source-recomputing traversals. The historical operator census omits
  scalar shapes/dtypes and cannot certify the missing witness liveness.
- `C71FsLifetimeSound`, adaptive ROM transfer and malicious-verifier privacy
  still need their runtime premises and complete lifetime event/query census.
  Existing conditional Lean lemmas do not discharge these obligations.
- Complete certificate compilation, the physical live-memory schedule and
  full Gemma prover/verifier measurements remain outstanding. No C7.1 E2E,
  security, certificate-size, timing or memory credit is claimed.

## Next work

Follow [design §10](c7.1-gemma31b-design.md#10-ordine-del-lavoro-dopo-lautorizzazione-a-quattro-letture):
continue G2 with A3: prove the private-root/oracle compilation and precise
commitment–W relation, then compose the binding argument with the concrete
hash/PCS assumptions and FS. A3's finite inner recursion and hash checker
add no W reads after queried source columns exist; they do not supply the
missing Gemma witness. The static model anchor keeps PCS openings private,
without reusing G1's public split mask. Setup hash work remains substantial;
the bounded encoder and known grouped-commitment arrays occupy 5,637,144,576
bytes, before uncompiled runtime staging. Alongside it, close witness and form
availability within the four W reads. Complete the relation, both lifetime
proofs and full certificate/resource accounting before admitting prover
implementation. Then prepare the small checks and, after hardware/spending
authorization, the complete composition case and real Gemma workloads.
The [remaining G2 obligation](c7.1-committed-mac-opening.md#7-prossimo-obbligo-e-controlli)
specifies the required mathematical deliverable; no new owner decision is pending.

## Documentation decision

On 2026-09-07 the owner chose a minimal C7.1 wiki: editable status/design,
immutable evidence, and separate build/RunPod procedures. C7 was merged into
main (`bce620f`), eight missing research files were versioned (`4f7edf0`), and
the C7 worktree was closed before this reorganization. The pre-wiki ledger is
preserved byte-for-byte in the linked historical snapshot. Routine checks
belong in commit/task validation; this page changes when the working state does.
