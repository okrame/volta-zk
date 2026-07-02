# Protocol Sketch

This file tracks the formal objects that need to be written before prototype
work becomes meaningful.

## Minimal Authenticated Value Interface

Let `F` be the base field and `E` be an extension field for statistical
soundness. The designated verifier samples a session MAC key `Delta in E`.

For an authenticated value `x`, the prover holds `(x, m_x)` and the verifier
holds `k_x` such that:

```text
k_x = m_x + Delta * x
```

Fresh correlations are expanded from a silent-VOLE/PCG seed and consumed once.

## Authentication

To authenticate `x`, start from a fresh random authenticated mask `r`.

```text
P sends delta = x - r
P keeps m_x = m_r
V computes k_x = k_r + Delta * delta
```

The correction is masked by `r`, so it should be simulatable as a random field
element under the VOLE idealization.

## Zero Opening

To prove that authenticated `y` equals zero:

```text
P sends m_y
V accepts iff k_y == m_y
```

Any nonzero error requires guessing `Delta` and should fail except with
probability about `1 / |E|`.

## MLE Functional Check

For a tensor `x` and point `r`, define:

```text
z = <eq(r, .), x>
```

The prover computes `z` and the corresponding MAC functional. The verifier
streams its keys:

```text
k_z = <eq(r, .), k_x>
```

The equality relation is then checked through the authenticated-value interface.

Open question: in the blind transcript version, avoid revealing `z` itself and
keep all derived claims authenticated.

## Blind GKR Target

Formalize a GKR/sumcheck transcript where:

- round polynomial coefficients are authenticated values;
- verifier challenges remain public;
- linear consistency checks are accumulated into one random linear combination;
- final low-degree products are discharged by a QuickSilver-like multiplication
  check;
- no activation MLE value is opened in the clear.

## Security Proof Tasks

- malicious-verifier zero-knowledge simulator;
- soundness of blind sumcheck under authenticated claims;
- composition with LogUp-style lookup checks;
- one-time use and domain separation of VOLE correlations;
- multi-session and append-only cache soundness.
