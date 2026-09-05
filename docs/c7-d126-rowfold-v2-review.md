# C7-ROWFOLD-v2 source review — 2026-09-05

**Report identified; proposal NO-GO as written; D126 still BLOCKED.**
The owner supplied `/home/okrame/.claude/jobs/6ce710fb/tmp/D126-ROWFOLD-report.md`,
previously uninspected. Its [immutable copy](c7-d126-rowfold-v2-source-20260904.md)
has SHA-256 `1be8cf1d94ddefe83c86f79751411a26b12c4eeda5cb3e956f5e9604e9d290e4`.
The former “report absent” assertion is withdrawn. The existing local design
GO suffices; no duplicate GO is required. No protocol implementation is added.

## Actual schedule versus the earlier controls

Source Section 2.1 precommits the persisted oracle in setup. Its two online
passes are row partials/combination, then selected openings, with the fresh
chain between them. It is an interactive q266/root8192 proposal, not the
active offline q357/root4096 implementation. The earlier standard-WHIR
51.54-GB dense-state screen and three-pass Hobbit comparison are **not
derivations of this v2**. V2's combination really is 6.44 GB, but that is
not its total temporary memory. The proposed `c7_rowfold.rs` does not exist.

## Explicit complexity violation

Section 6 charges `N*ceil(log2(2q))`, then calls the coefficient independent
of q by substituting q266. This is the forbidden `N log q` dependence.
The fresh-chain `n'*log(n')` and opening `n'*log(q)` terms also depend on
`n'=N/m`; declaring n' fixed by a profile does not place them in `P(q,h)`.
The suggested `rust/volta-pcs/src/ntt.rs` implements a complete transform and
full-output allocation, not the proposed selected-output second pass.

## Total arena and H100

Section 5.3 lists retained `v=24*2^28=6,442,450,944` bytes **plus** a separate
one-limb NTT buffer `8*2^29=4,294,967,296` bytes. Their sum alone is
**10,737,418,240 bytes**, exceeding the total 6,442,450,944-byte arena.
The referenced `NttPlan` additionally stores `2^28` eight-byte twiddles,
2,147,483,648 bytes. No schedule eliminating these simultaneous objects is
provided. The four fresh compact trees require another 754,640,128 hash
bytes, before salt/runtime state and auxiliary values. The source's “11.5 GB”
row also does not include its separately listed 536.9-MB source window;
treating that window as an alias of resident W does not fix the arena excess.

W + full 4096-token KV + staging + terminal scalars + v + NTT + those hashes
already totals 76,833,747,968 bytes. Retaining all currently counted logical
outputs in i16 would give **80,517,596,416 bytes**; adding the referenced
twiddles raises that to **82,665,080,064 bytes**. These are conditional
coexistence rejections, not a universal H100 impossibility result. Full
physical liveness remains BLOCKED, including B, other chains/masks, GKR and
CUDA/runtime. No large allocation was attempted.

## EvalLink is not a general identity

Section 2.1 defines `v=sum_i r_i M_i` and wants to bind
`F=sum_i r_i <Q_i,M_i>` by one linear evaluation of v. For nonzero r_i,
`F=<Q,v>` for **all** M_i requires every Q_i to equal the same Q: compare
each independent source coefficient. Section 3.1 instead permits different
row-restricted forms; no shared Q or alternative relation is constructed.

An exact ordinary EQ-form counterexample over Goldilocks is:

```text
equality point (a,b)=(3/4,2/3)
Q_0=(1/12,1/6), Q_1=(1/4,1/2); sum Q_i=1, so no all-c burn
r=(2,3); Delta M_0=(3,0), Delta M_1=(-2,0)
Delta v=0, but Delta F=2*(3/12)+3*(-2/4)=-1.
```

All changed source cells fit i16; fixed mask/padding coordinates can be
added without changing the difference. A linear functional of unchanged v
cannot distinguish these cases. This refutes Theorem A.1's general identity,
not an end-to-end forgery against implemented Gemma. Repair requires another
retained statistic/relation or a proved common-form compiler restriction.

## Interactive mask-lifetime counterexample

Lemma 4.4 permits arbitrary nonzero row challenges and arbitrary tapes.
Section 4.3 divides chain exposure among 141 rows without an adaptive rank
proof. Across two attempts with the same root masks, choose weights all one,
then change just row i to two. At matching clear fresh-oracle positions x,
the opening difference is exactly `RS(M_i||rho_i)(x)`.

With the report's q266 and 32-point first cosets, each pair can reveal 8,512
distinct evaluations of that chosen row. New cosets across **965 pairs**
use **1,930 of the allowed 8,192 attempts** and reveal **8,214,080** values,
exceeding its mask dimension 8,208,384 by 5,696. For a fully occupied row,
Vandermonde ranks imply at least that many live-data functionals beyond mask
randomness. No hash collision, PCG break or VOLE-correlation reuse is needed.

A tiny Goldilocks check isolates a row with two pairs of clear coset openings
and reconstructs its two live and two mask coefficients by elimination.
This refutes the advertised arbitrary-challenge **interactive** privacy
argument. It is **not an attack on a future offline-FS variant**, whose
challenges cannot simply be chosen this way. That variant needs a new
multi-session rank proof; it cannot inherit Lemma 4.4.

## Q64, certificate and lower-bound claims

The source explicitly uses `Q_FS=0` and 141 interactive row exchanges for W.
Its 88-bit claim does not establish offline-Q64 security. Multiplying its
displayed four-plane miss term by one global Q64 factor gives about 44.400
bits at q266, or 82.168 bits at q357: **conditional query-only arithmetic**,
not a ROM reduction or total security. No extra attempt factor is applied.
Its fixed-rate rowfold schedule also differs from the active nonuniform q
vector, so the current 79.481814-bit envelope cannot be transferred to v2.

Section 5.3 itself marks complete certificate and H100 coexistence BLOCKED.
Its 3,454,808-byte W stream is not a complete Gemma proof. The last fresh tree
has only 349 logical leaves, so `2q=532` is not an attainable unique-leaf
count; separate reservation caps must not be called exact serialized bytes.
Full codec, B and GKR remain absent. Neither 30 MB nor 45--50 s is established.

PB is expressly a product bound for a particular combine-then-open family.
LB-1' step (i) does not justify its universal conclusion: producing payloads
during a pass does not imply all positions were fixed before the entire
pass. The adaptive schedule/retained state and preservation of all allowed
source and commitment-dependent checks need proof. Thus “every hash carrier
is impossible” is not established. The rejections here rely on v2's own
formulas and counterexamples, not on that universal assertion.

The existing focused tests check source identification/digest, the arena
arithmetic, the EQ-form obstruction and the interactive row-isolation
example. They provide no offline Gemma protocol or performance credit.
