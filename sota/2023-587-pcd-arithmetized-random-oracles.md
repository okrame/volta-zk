# Proof-Carrying Data From Arithmetized Random Oracles

### Megan Chen Alessandro Chiesa Tom Gur

megchen@bu.edu alessandro.chiesa@epfl.ch Tom.Gur@warwick.ac.uk Boston University EPFL University of Warwick

### Jack O’Connor Nicholas Spooner

Jack.O-Connor@warwick.ac.uk nicholas.spooner@warwick.ac.uk University of Warwick University of Warwick

### April 24, 2023

**Abstract**

Proof-carrying data (PCD) is a powerful cryptographic primitive that allows mutually distrustful parties to perform distributed computation in an efficiently verifiable manner. Known constructions of PCD are obtained by recursively-composing SNARKs or related primitives. SNARKs with desirable properties such as transparent setup are constructed in the random oracle model. However, using such SNARKs to construct PCD requires heuristically instantiating the oracle and using it in a non-black-box way. [CCS22] constructed SNARKs in the low-degree random oracle model, circumventing this issue, but instantiating their model in the real world appears difficult. In this paper, we introduce a new model: the *arithmetized random oracle model* (AROM). We provide a plausible standard-model (software-only) instantiation of the AROM, and we construct PCD in the AROM, given only a standard-model collision-resistant hash function. Furthermore, our PCD construction is for arbitrary-depth compliance predicates. We obtain our PCD construction by showing how to construct SNARKs in the AROM for computations that query the oracle, given an accumulation scheme for oracle queries in the AROM. We then construct such an accumulation scheme for the AROM. We give an efficient “lazy sampling” algorithm (an *emulator*) for the ARO up to some error. Our emulator enables us to prove the security of cryptographic constructs in the AROM and that zkSNARKs in the ROM also satisfy zero-knowledge in the AROM. The algorithm is non-trivial, and relies on results in algebraic query complexity and the combinatorial nullstellensatz.

**Keywords**: proof-carrying data; random oracle model; arithmetization

## Contents

**1 Introduction 3**

1.1 Our results. ................................................3
1.2 Related work...............................................4
**2 Techniques 6**

2.1 Starting point: the low-degree random oracle model.. ........................ .6
2.2 The arithmetized random oracle model.. ............................... .6
2.3 Building PCD secure in the AROM.................................. .9
2.4 Emulation of the ARO..........................................11
**3 Preliminaries 14**

3.1 Notations.................................................14
3.2 Linear algebra and the combinatorial nullstellensatz. ..........................15
3.3 Non-interactive arguments in oracle models...............................15
3.4 Proof-carrying data. ...........................................17
3.5 Accumulation schemes..........................................18
3.6 Commitment schemes. ..........................................19
3.7 Constraint detection for low-degree polynomials. ............................20
3.8 Forking lemmas.. ............................................21
3.9 Identical-until-bad .. ...........................................21
**4 Arithmetized random oracle model 23**

**5 Stateful emulation of the ARO 24**

5.1 Inefficient stateful emulator for low-degree extensions ..........................25
5.2 Stateful emulator for the ARO......................................27
5.3 Proof of Theorem 5.4...........................................28
5.4 Efficiently implementing Construction 5.11...............................30
**6 From ROM to AROM security 35**

6.1 Emulating access to the witness oracle. .................................35
6.2 Stateful emulator for the ARO w.r.t. the random oracle.........................35
6.3 Security in the ROM is preserved in the AROM.............................36
6.4 Commitment schemes in the AROM. ..................................36
**7 Zero-finding game in the AROM 38**

7.1 Partial oracles...............................................38
7.2 Proof of Lemma 7.1. ...........................................39
**8 Accumulation scheme 42**

8.1 Construction ................................................42
8.2 Completeness...............................................43
8.3 Soundness .................................................44
8.4 Zero knowledge.. ............................................45
8.5 Efficiency.................................................46
**9 PCD in the AROM 48**

9.1 SNARKs in the AROM...... ....................................48
9.2 PCD from SNARKs in the AROM....................................53
**Acknowledgments 54**

**References 54**

## 1 Introduction

Proof-carrying data (PCD) [CT10] is a powerful cryptographic primitive that allows mutually distrustful parties to perform distributed computation in an efficiently verifiable manner. The notion of PCD generalizes incrementally-verifiable computation (IVC) [Val08] and has recently found exciting applications in enforcing language semantics [CTV13], verifiable MapReduce computations [CTV15], image authentication [NT16], verifiable registries [TFZBT22], blockchains [Mina; BMRS20; CCDW20; KB23], and more. All known PCD constructions (and practical IVC constructions) are obtained via *recursive proof compo-* *sition*, a general framework for building PCD from simpler primitives such as SNARKs [BCCT13; BCTV14; COS20] or accumulation schemes [BGH19; BCMS20; BDFG21; BCLMS21; KST22]. While the specific constructions differ, the high-level idea remains the same: to prove the correctness of *t* steps of computation given proof of correctness for *t −* 1 steps, one proves that “the *t*-th step is correct *and* there exists a valid proof for the first *t −* 1 steps”. The statement that “there exists a valid proof” refers to the *verifier* of the underlying SNARK or accumulation scheme. As such, the resulting PCD scheme makes non-black-box use of the verifier for the underlying scheme. This leads to a significant theoretical problem when trying to prove security for constructions based on recursive composition: almost all known constructions of SNARKs, and all known constructions of accumulation schemes, are proven secure in the random oracle model (ROM). The random oracle is an inherently black-box object; in particular, it is believed that there is no “nontrivial” proof system for statements about the random oracle. Most prior work in the area [COS20; BCMS20; BCLMS21] avoids this problem using a *heuristic step*: they assume that there exists some concrete hash function such that replacing the random oracle with the hash function yields a secure SNARK or accumulation scheme in the standard model (without oracles), and then apply recursive composition to this heuristic scheme. Two prior works [CT10; CCS22] propose a different approach: endow the random oracle with some additional structure. The PCD construction in [CT10] is in a model where the random oracle additionally *signs* its responses using a standard-model signature scheme; the verifier can then check query-answer pairs by verifying the signature rather than querying the oracle. Trading cryptographic structure for algebraic structure, [CCS22] construct PCD in the *low-degree random oracle model* (LDROM), where parties have access to a random low-degree multivariate polynomial. Both of these oracle models can be instantiated using hardware tokens. Unfortunately, we do not have any standard model (i.e., software-only) instantiation of these oracles, even heuristically. This is in contrast to the (usual) random oracle model, where empirical evidence suggests that “natural” schemes remain secure provided the oracle is replaced with a suitably “random-looking” hash function [BR93]. Our goal in this work is to design a new oracle model that simultaneously achieves both desiderata: (a) there exists a PCD scheme in this model under standard assumptions; and (b) the oracle can be heuristically instantiated.

### 1.1 Our results

In this work we introduce and study a new oracle model, the arithmetized random oracle model (AROM), which provides a random oracle and a corresponding “arithmetization” oracle. As in the standard ROM, the random oracle is an idealized model of some concrete hash function *H*. The arithmetization oracle is an idealized model of a certain *arithmetization* of *H*, which is a low-degree polynomial *PH*that can be efficiently computed from the circuit of *H*. As such, the AROM has a plausible heuristic instantiation: replace the random oracle by *H* and the arithmetization oracle by *PH*, for a suitable hash function *H*.

Our main result is a construction of PCD in the AROM, based on the [CCS22] construction of PCD in the LDROM. By instantiating the AROM with a suitable hash function, we obtain a candidate “real-world” construction of PCD. Formally, we prove the following theorem.

**Theorem 1** (informal)**.** *There exists transparent¹ (zero-knowledge) PCD in the AROM (for computations in* *the AROM), assuming the existence of collision-resistant hash functions in the standard model.*

Our PCD construction is provably secure (in the AROM) for *all* efficient compliance predicates. This stands in contrast to all other constructions of PCD (with the exception of [CT10], but including [CCS22]), whose security proofs are limited to constant-depth recursion. This is because, like [CT10], our PCD construction preserves the straightline extraction property of the underlying SNARK. 2 To prove our main theorem, we develop various tools for analyzing cryptographic constructions in the AROM. Our key result here is to show that the additional power provided by the AROM does not help the adversary win any game defined with respect to the random oracle alone.

**Theorem 2** (informal)**.** *Any construction that is secure in the ROM is secure in the AROM.*

An immediate consequence of this theorem is that any construction that is secure in the standard model is secure in the AROM. In contrast, we do not know whether an analogous statement holds in the LDROM. We remark that this result is meaningful even outside the present context: it provides evidence that security in the ROM implies security against a specific type of non-black-box attack, namely, attacks that treat the *arithmetization* of the hash function as a black box. **Comparison to other oracle models.** As discussed above, both the ROM and the LDROM fall short of our goal. While the ROM has a well-established heuristic instantiation, it is unlikely to support a PCD scheme. PCD exists in the LDROM, but we do not know how to instantiate the oracle. The AROM offers, in some sense, the “best of both worlds”: a provable construction of PCD *and* a plausible heuristic instantiation. Moreover, the proposed instantiation of the AROM does not rely on any cryptography beyond “random-oracle-like” hash functions. As such, there are no barriers to implementing our scheme. **Post-quantum security.** Our scheme does not rely on any pre-quantum assumption; it is plausibly post- quantum secure. Moreover, it is conceivable that the scheme is in fact *provably* post-quantum secure in the “quantum-accessible” AROM; we leave this intriguing question to future work.

### 1.2 Related work

**PCD and IVC in the ROM.** There is theoretical evidence that, unlike for SNARKs, there is no construction of PCD and IVC in the ROM (even allowing for additional “mild” cryptographic assumptions like standard- model CRHs). First, [CL20] shows that the PCP theorem does not hold for various cryptographically relevant oracle models, such as the ROM and the LDROM. This suggests that succinct proofs for computations relative to these oracles may be out of reach. Nevertheless, [CCS22] shows that this is not the whole story by constructing SNARKs for LDROM computations, particularly PCD, from a cryptographic assumption. Second, [HN23] shows various impossibilities for IVC in the ROM. For example, if a particular type of commitment scheme exists, then zero-knowledge IVC (without a CRS) does not exist in the ROM. This result holds even if the IVC construction were to rely on “standard” cryptographic assumptions. 3

1 The only setup required is a uniform reference string. 2 Some other prior PCD constructions are also based on SNARKs with straightline extraction (e.g., [Val08; COS20]). However, this property is lost after the heuristic step is applied. 3 The paper claims that this result holds for constructions that use *falsifiable* assumptions but does not show this explicitly. Nonetheless, one can check that the proof does work for “benign” cryptographic assumptions.

**Pseudorandom oracles.** [JLLW22] introduce the *pseudorandom oracle model* (PROM) and apply it towards obfuscation. Similarly to the AROM, the PROM aims to capture cryptographic schemes that make a non-black-box use of the random oracle. We outline the PROM and explain how it differs from the AROM. The PROM is specified relative to a (standard model) pseudorandom function family *Fk*, and has two interfaces. The first accepts a key *k* and outputs a random handle *h* (and stores (*h,k*)). The second accepts a handle *h* and an input *x* and outputs *Fk*(*x*), where *k* is the key corresponding to *h*. By the security of the PRF, a party holding only *h* cannot distinguish the latter interface from a random oracle. On the other hand, a party holding the key *k* can use the circuit for *Fk*in a non-black-box way. [JLLW22] constructs ideal obfuscation from functional encryption in the PROM. The key difference between the AROM and the PROM is that the PROM “separates” non-black-box and black-box access to the oracle. Specifically, non-black-box access to the PROM is available only to parties that know *k*, whereas random oracle security holds only against parties that do not know *k*. *In the AROM,* *there is no such asymmetry: all parties have the same access to the oracle.* This is important in the context of recursive composition (which we study) since completeness requires that both the prover and the verifier have non-black-box access to the oracle. Still, soundness relies on the security of the random oracle against the prover. It is an exciting open question to understand whether, despite this apparent barrier, recursive composition is possible in the PROM. **Augmented random oracles.** [Zha22] defines the *augmented* random oracle model to analyze the resilience of cryptographic transformations in the ROM against uninstantiability results. While ideas about modeling non-black-box access to the random oracle (and the abbreviation “AROM”) are common to both the augmented ROM and the arithmetized ROM, the models are very different both technically and in their applications. We briefly summarize [Zha22] and then explain how our model differs. Let ro denote the random oracle, and Π denote some protocol. A cryptographic transformation *T* usually comes with a guarantee like “if Π is a secure X, then *T* ro

(Π) is a secure Y”. An uninstantiability result for *T*
typically shows that there exists some Π such that *T* *H*

(Π) is insecure for every polynomial-size circuit *H*.
Known uninstantiability results use some non-black-box technique to provide a “trapdoor” that can be used with respect to any *H* but is useless for ro. The augmented ROM captures this paradigm by requiring *T* ro

(Π)
to be secure even if Π has access to an oracle *M* that provides some functionality permitted by non-black-box access to *H*, but with respect to ro. [Zha22] shows that key uninstantiability results for transformations (e.g., Fiat–Shamir for arguments [GK03]) lead to insecure protocols in the augmented ROM. The augmented ROM is a tool for proving a stronger form of security for random oracle transformations. In particular, no “honest” scheme ever accesses the oracle *M*; indeed, the oracle *M* is chosen adversarially (and may be trivial). On the other hand, in the arithmetized ROM, honest parties use the non-black-box access provided by the arithmetization oracle, whose functionality is (mostly) fixed by the model itself.

## 2 Techniques

Recall that our goal in this work is to construct proof-carrying data (PCD). Our approach follows the widely- used template of *recursive proof composition*. However, our setting imposes several technical and conceptual challenges. We begin by outlining a vital issue in proving security for this type of construction, which our work seeks to address. Recursive proof composition refers to a set of techniques that enable the construction of PCD (and IVC) from SNARKs or accumulation schemes. With few notable exceptions (e.g., [Gro16]), all constructions of SNARKs and accumulation schemes rely on the Fiat–Shamir heuristic, which converts an interactive public-coin argument system into a non-interactive argument via a cryptographic hash function *H*. For all of these SNARK constructions, it is unknown whether this heuristic can be realized from any concrete (i.e., falsifiable) cryptographic assumption; indeed, there is evidence that this may not be possible [GW11]. However, we can prove these schemes secure in the ROM, treating the hash function *H* as a truly random function ro to which the adversary has black-box access. This leads to a fundamental tension in proving security for the recursive composition of these protocols. On the one hand, to prove security for the protocol itself, we assume that the adversary treats the hash function *H* as a black box. On the other hand, when recursively composing, the *honest* protocol treats *H* in a non-black-box way: specifically, as a concrete polynomial-size circuit. The prior work [CL20; HN23] discussed in Section 1.2 suggests that non-black-box use of *H* may be necessary to achieve PCD (and IVC).

### 2.1 Starting point: the low-degree random oracle model

The work of [CCS22] addresses the aforementioned tension by introducing a new oracle model called the *low-degree random oracle model* (LDROM). They then show how to construct PCD via recursive composition in the LDROM (i.e., using the oracle as a black box). In the LDROM, all parties have oracle access to a uniformly random low-degree multivariate polynomial *ρ*ˆ: F *m* *→* F. Restricting *ρ*ˆ to *{*0*,*1*}* *m* *⊆* F *m* recovers the usual random oracle, and [CCS22] show that rele- vant security properties of the random oracle continue to hold in the LDROM; in particular, Micali’s SNARK [Mic00] is secure in the LDROM. Unlike the random oracle, the LDROM admits a *query accumulation* *scheme*: a verifier, with the help of an untrusted accumulation proof, can check the correctness of *n* queries to *ρ*ˆ using only *O*(1) queries to *ρ*ˆ. [CCS22] construct such an accumulation scheme and use it to build PCD. **Instantiating the LDROM.** [CCS22] observe that the LDROM can be instantiated using a hardware token that implements the structured PRF of [BGV11]. Of course, schemes involving hardware tokens have significant drawbacks; finding a plausible “software-only” instantiation would be much preferable. [CCS22] suggest a natural strategy: given a “random-oracle-like” hash function *H*, convert it into an arithmetic circuit gate-by-gate. Such a circuit does define a polynomial with which we could instantiate the LDROM. Unfortunately, as noted in [CCS22], for widely-used hash functions, the degree of this polynomial will be large (at least 2 25 ). Since the complexity of the verifier in the query accumulation scheme is linear in the degree of the oracle, the resulting PCD scheme would be prohibitively expensive.

### 2.2 The arithmetized random oracle model

Given the above difficulty, a natural next step is to consider techniques for *reducing the degree* of the resulting arithmetic circuit. Since the degree of an arithmetic circuit grows exponentially in its depth, a natural approach is to try to reduce the depth of the circuit for *H*. This can be achieved via the well-known NP

reduction from circuit satisfiability to 3-SAT (a depth-two formula). The output of the reduction is a boolean formula Φ*H*with the following property: there is an efficiently computable *witness function WH*such that ( 1 if *H*(*x*) = *y* and *WH*(*x*) = *z* Φ*H*(*x,y,z*) =*.* 0 otherwise

Converting Φ*H*into an arithmetic formula (gate-by-gate) yields a polynomial *PH*of total degree *O*(*|H |*) that agrees with Φ*H*on boolean inputs. *PH*is *not* a low-degree extension of *H* (rather of Φ*H*) and so this is not a candidate instantiation of the LDROM. As we note later, however, the low-degree structure of *PH*will nonetheless allow us to build a query accumulation scheme, inspired by that of [CCS22]. Moreover, the statement “*H*(*x*) = *y*” can be verified by querying *PH*only, given *z* as a witness. It is therefore plausible that, following the template developed in the prior work, we can obtain a secure construction of PCD that makes only black-box use of *H* and *PH*. Of course, given the current state of knowledge, we can only hope to prove that this PCD scheme is secure in some idealized model. In particular, we would like to model *H* as a random oracle. It is then necessary to answer the question: *if H is a random oracle, what should PHlook like?* A central modeling contribution of our work is to propose an answer to this question. **A new oracle model: the AROM.** We refer to our proposed oracle model as the *arithmetized random* *oracle model* (AROM). Before presenting the model, we discuss two key modeling challenges that arise. Both relate to the fact that the black-box behavior of *PH*depends in a non-black-box way on *H*.

- **Challenge #1:** *WH***is circuit-dependent.** For a concrete circuit *H* and input *x*, *WH*(*x*) is a vector representing the assignment to the internal wires of *H* on input *x*. This of course depends on the size and structure of the circuit for *H*, which is no longer meaningful when *H* is replaced by a random oracle. We handle this conservatively, by allowing *WH*to be adversarial. That is, we require that completeness, soundness, and zero-knowledge hold *regardless* of the choice of *WH*, which we allow to depend on *x* and the random oracle, and may even itself be randomized. There is, however, an important caveat. While we allow our *WH*to depend on the random oracle, we must restrict this dependency; otherwise, the adversary could use *WH*to learn information that it cannot otherwise obtain (e.g., *WH*could encode a collision in *H*). Similarly, if *WH*is computationally unbounded, the adversary could use it to break standard-model cryptography. As such, we restrict *WH*to have an efficient implementation (in particular, it can only make polynomially-many queries to *H*).
- **Challenge #2:** *PH***is not the unique extension.** Even after we have fixed *WH*(and hence Φ*H*), *PH*has a huge number of remaining degrees of freedom. This is because it is of individual degree larger than 1, but its behavior is specified only on boolean inputs. This is a more challenging issue to resolve: letting *PH*be chosen adversarially from the set of extensions of Φ*H*would make the adversary unrealistically powerful (see Remark 2.1). Instead, we model *PH*as a uniformly random polynomial of the appropriate degree whose restriction to the hypercube is Φ*H*. We propose that this captures the inability of the adversary to leverage the structure of *H* (and hence *PH*) in breaking security. We leave to future work the question of whether this modeling choice can be weakened (again see Remark 2.1). We now give an informal definition of the AROM; for details see Section 4. In the AROM, all parties (honest and malicious) have access to three oracles (ro*,*wo*,*vob): •a *random oracle* ro : *{*0*,*1*}*
*m* *→{*0*,*1*}* *λ* drawn uniformly at random;

•a *witness oracle* wo : *{*0*,*1*}* *m* *→{*0*,*1*}* *w* that is an arbitrary PPT-computable function (see below);

- an *extended verification oracle* (arithmetization oracle) vob : F
*m*+*λ*+*w* *→* F that is a random extension of individual degree *d ≥* 2 of the verification oracle vo : *{*0*,*1*}* *m*+*λ*+*w* *→{*0*,*1*}* defined as follows: ( 1 if ro(*x*) = *y* and wo(*x*) = *z* vo(*x,y,z*) :=*.* 0 otherwise

### We discuss each oracle in turn.

•The random oracle ro models the hash function *H*, as in the standard ROM.

- The witness oracle wo models the witness function *WH*. It is defined via a polynomial-size oracle circuit *B* chosen arbitrarily before the oracle is sampled. On a query *x*, wo outputs *B*
ro (*x,µx*) where *µx*is sampled uniformly at random (and is not resampled if *x* is queried again). The inclusion of *µx*allows our definition to subsume, e.g., modeling *WH*as a random oracle. The efficiency requirement is necessary to allow for efficient simulation of wo (it prevents wo from being used to break standard-model cryptography).

- The verification function vo models the boolean formula Φ*H*. Indeed, the definition of vo is directly obtained from the definition of Φ*H*by replacing *H* with ro and *WH*with wo.
- The extended verification oracle vob models the polynomial *PH*. The requirement that *d ≥* 2 arises from a technical concern: as noted in [JKRS09], access to the unique multilinear (*d* = 1) extension of a function can be surprisingly powerful. (E.g., an adversary with access to the multilinear extension of vo can efficiently invert ro, see Remark 2.1.) Requiring *d ≥* 2 avoids this issue and is sufficient for our security proofs. In any case, we want to match the degree of vob to that of *PH*for some concrete hash function *H*, and the degree of *PH*will be at least 2 in each variable.
4

A construction that makes black-box use of *H,WH,* Φ*H*can be analyzed in the AROM as suggested by the above discussion: replace *H* with ro, *WH*with wo, and *PH*with vob (with matching degree bound *d*). In Section 2.3 we describe our construction of PCD in the AROM. This construction relies on a “lazy sampling” procedure for the AROM, a key technical contribution that we describe in Section 2.4. **AROM vs. LDROM.** Superficially the AROM and LDROM seem quite similar; indeed, they both aim to capture some arithmetization of the random oracle. However, there are notable differences between the two models, even putting aside the differing instantiability considerations. We highlight a few such differences.

- The LDRO is a low-degree extension over a field F of a random function *{*0*,*1*}*
*m* *→* F. Hence the security of the LDRO as a random oracle depends on *|*F*|*. The ARO decouples the choice of F from the random oracle: one may choose the codomain *{*0*,*1*}* *λ* of ro independently from the field F over which vob is defined. The security of ro (even in the presence of vob) depends only on *λ*. That said, in *both* the LDROM and the AROM, the security of their respective query accumulation schemes depends on *|*F*|*.

- The LDRO is a linear code random oracle; i.e., it is sampled at random from a linear space over F. The ARO is also sampled uniformly from some set, but this set does not form a linear space. This means that tools developed in [CCS22] for analyzing linear code random oracles do not directly apply. That said, the ARO does have *some* linear structure: the oracle vob is sampled uniformly from the (affine) space of low-degree extensions of vo. This fact will be useful for emulating the AROM. 4 The degree of a variable in *PH* is equal to the number of clauses in Φ*H* in which it appears. Every wire appears in at least two clauses in Φ*H*: once as an output and once as an input.

- The LDRO has security properties (e.g. collision resistance, unconditional SNARKs) even when *d* = 1 (i.e., it is a random *multilinear* polynomial). The ARO is not even one-way when *d* = 1. **Remark 2.1** (choice of extension)**.** We set vob to be a random extension of vo of individual degree *d ≥* 2. We explain why setting vob to be an arbitrary extension of vo would grant the adversary too much power. First consider the case when vob is the unique multilinear extension of vo (*d* = 1). Given oracle access to a multilinear polynomial *P* over a field F of characteristic different from 2, a single query to *P* suffices to
P efficiently evaluate the sum *x∈{*0*,*1*}n* *P* (*x*) [JKRS09]. We can use this capability and the structure of vo to invert ro: given a target image *y ∈{*0*,*1*}* *λ*, perform a binary search for a preimage of *y* by evaluating the P sum *x* 1 *,z* vob ((*x₀,x₁*)*,y,z*) for different prefixes *x₀*. Next consider the higher-degree case: vob is an *adversarially-chosen* extension of vo of degree *d ≥* 2. Given oracle access to a polynomial *P* of individual degree *d*, a single query to *P* suffices to efficiently P evaluate the sum *x∈Hn* *P* (*x*) where *H* is a multiplicative subgroup of F with *|H | > d* [CFS17, Lemma

A.4]. Assume that F has such a subgroup *H* of size *d* + 1, and fix two elements *a,b ∈ H*. Let *g*: F *→* F be the unique linear function with *g*(*a*) = 0 and *g*(*b*) = 1. Choose vob to be the polynomial of minimal
*n*

|individual degree satisfying: vo|b (x,y,z) = vo(x,y,z) for (x,y,z) ∈ {0, 1}||
|---|---|---|
|n n||n|
|x∈H|n x∈{0,1}|n|

, and vob (*w*)=0 for *w ∈* *g*(*H*) *n* *\{*0*,*1*}* *n*. Note that vob, and hence also vob *◦ g* *n*, has individual degree at most *|H |−* 1 = *d*, P P
and *n* vob (*g*(*x₁*)*,...,g*(*x*)) = *n* vo(*x₁,...,x*). We can then use binary search as in the
multilinear case to invert ro. The above gives some justification for modeling vob as a *random* low-degree extension of vo. Of course, there are many choices that lie in between adversarial and random. For example, one could set vob to be drawn from an adversarially-chosen distribution with “enough” entropy. It is not clear, however, whether such a choice would be substantially closer to “reality” than our choice.

### 2.3 Building PCD secure in the AROM

Prior work [CCS22] shows that to obtain PCD in an oracle model *O*, it suffices to construct: (i) a SNARK for NP relative to *O*; and (ii) an accumulation scheme for *O*-queries relative to *O*. Further, the resulting PCD scheme is zero-knowledge if the SNARK and accumulation scheme also satisfy zero-knowledge. The PCD construction in the LDROM in [CCS22] follows by establishing these results for the LDROM. Similarly, our construction of PCD will follow by establishing these results for the AROM.

**(i) SNARKs in the AROM.** [CCS22] prove that Micali’s SNARK remains (information-theoretically) secure in the LDROM, via a rewinding argument. In the AROM, we show a much more general theorem. **Theorem 3** (informal)**.** *Let* p *be a predicate that queries* ro*, and let A be an algorithm querying* (ro*,*wo*,*vob) *that outputs x satisfying* p
ro *with probability ε. Then there is an algorithm B, of similar efficiency to A, that* *queries* ro *only and outputs x satisfying* p ro *with probability ε −* negl(*λ*)*.*

Theorem 3 follows directly from our emulator for vob, which we discuss further in Section 2.4. It is *not* known whether a similar result holds for the LDROM. As an illustrative example, we can use Theorem 3 to prove that the ARO is collision-resistant. By applying Theorem 3 to the predicate p ro that, given (*x,x* *′*

) *∈{*0*,*1*}* *m*
*×{*0*,*1*}* *m*, checks that *x ̸*= *x* *′* and ro(*x*) = ro(*x* *′* ), we deduce that the ARO is collision-resistant from the fact that the RO is collision-resistant. We use Theorem 3 to prove knowledge soundness and zero knowledge of Micali’s SNARK in the AROM.

- **Knowledge soundness.** We use Theorem 3 to prove that Micali’s SNARK is secure in the AROM, via a *straightline* extractor. Informally, since we can cast knowledge soundness of Micali’s SNARK as an

oracle predicate p, any adversary *A* that breaks that security property in the AROM can be transformed via Theorem 3 into an adversary *B* that breaks it in the ROM. We can then apply the straightline extractor for Micali’s SNARK to *B*. Since *B* invokes *A* in a straightline manner, the resulting AROM extractor is also straightline.

- **Zero-knowledge.** We prove that Micali’s SNARK is zero knowledge in the AROM. Our zero knowledge simulator that *programs* the oracle; this is a commonality with the zero knowledge simulators for Micali’s SNARK in both the ROM and in the LDROM (see [CCS22]). To program the oracle, the simulator relies on a slightly stronger version of our emulator, which emulates oracle queries conditioned on an input list of (real) oracle query-answer pairs. Our hybrid argument invokes Theorem 3 and the Micali SNARK’s zero knowledge property in the ROM. Informally, we move between hybrids in the ROM vs. AROM using Theorem 3, setting the predicate p to be any distinguisher between hybrids. **(ii) An accumulation scheme for ARO queries.** The accumulation scheme for LDRO queries in [CCS22] is obtained by applying the Fiat–Shamir transformation to the (interactive public-coin) query reduction protocol of [KR08]. We follow the same template in the case of the ARO. The first observation is that it suffices to accumulate queries to vob only, because a query to ro or wo can be verified via a query to vob.
5 The [KR08] query reduction protocol itself works for any low-degree polynomial: in particular, for vob. As in [CCS22], the central challenge is showing soundness of the Fiat–Shamir transformation in this setting. Note that here we *cannot* appeal to our general theorem above because the verification predicate queries vob. The soundness of our accumulation scheme is captured by a *zero-finding game* (ZFG). First explicitly described by [BCMS20], the most basic form of a ZFG challenges the adversary to output a commitment cm (under a standard-model commitment scheme) to a low-degree polynomial *f ̸≡* 0 such that *f*(ro(cm)) = 0. Intuitively this is hard because *f* is fixed by cm before ro(cm) is known, and so the probability that *f*(ro(cm)) = 0 cannot be much larger than the probability that *f* (*α*) = 0 for a random *α ∈* F, which is negligible for large fields. [CCS22] shows that a more general version of the ZFG holds in the LDROM, where the ZFG polynomial may depend in a restricted way on the LDRO itself. That is, they show that it is hard to find a commitment cm to polynomials *f,g* such that *f − ρ*ˆ*◦ g ̸≡* 0 but (*f − ρ*ˆ*◦ g*)(ˆ*ρ*(cm)) = 0. The security of our construction depends on the hardness of a similar problem in the AROM, captured by the following lemma.

**Lemma 1** (informal)**.** *It is hard for any polynomial-size adversary with access to the ARO* (ro*,*wo*,*vob) *to find a* *commitment* cm *to a pair of low-degree polynomials f,g such that f −*vob *◦g ̸≡* 0 *but* (*f −*vob *◦g*)(ro(cm)) = 0*.*

We prove Lemma 1 by adapting the proof of the ZFG in [CCS22]. The proof relies on a *forking lemma* in the LDROM, which in turn relies on the ability to efficiently simulate the oracle in order to sample a forking transcript. For the AROM, we will rely on the emulator described in Section 2.4. The proof proceeds as follows. Looking ahead, we note that the emulator answers queries to vob using some polynomial *P*. We show that the adversary cannot win the ZFG when vob is replaced by *P*. This argument uses the forking lemma with respect to the emulator, and follows [CCS22], with one difference: this approach does not require a bespoke forking lemma as in [CCS22], and can be carried out using a general forking lemma [BN06, Lemma 1]. This general forking lemma is designed for random oracle adversaries, however, as we have already replaced vob with the emulator we can “perfectly emulate” *P* using the emulator. Further, we can perfectly emulate wo using the witness circuit *B*. This allows us to reduce the ZFG adversary to a random oracle adversary and thus apply the general forking lemma. Then, since the emulator is statistically indistinguishable from vob, the adversary cannot win the original ZFG. 5 Recall that ro(*x*) = *y* and wo(*x*) = *z* if and only if vob (*x,y,z*) = 1.

Before we describe our emulator, we discuss an important feature of our PCD construction. **Extraction and PCD depth.** Almost all constructions of PCD suffer from the “extractor blowup” problem. To obtain a PCD transcript of depth *d*, we apply the SNARK extractor to itself *d* times. If the extractor *c cd* corresponding to a size-*S* adversary is of size *S*, then the final extractor size is *s*, where *s* is the size of the original PCD adversary. As a result, one obtains meaningful security guarantees when *d* is a constant. There is a single construction that does not suffer from this issue: the construction of [CT10]. This is because their SNARK (in their signed random oracle model) is straightline (or “list”) extractable. Micali’s SNARK is also straightline extractable in the ROM [Val08]. Of course, after heuristically instantiating the oracle there is no longer any notion of “straightline”. On the other hand, we can easily show that Micali’s SNARK is straightline extractable in the AROM. (We do not know how to show this in the LDROM; [CCS22] instead gives a rewinding extractor for Micali’s SNARK.) As a result, our PCD construction is *secure for arbitrary recursion depth*.

### 2.4 Emulation of the ARO

As discussed in Section 2.3, we aim to construct PCD in the AROM by proving that cryptographic properties in the ROM, specifically knowledge soundness and zero-knowledge of the Micali SNARK, also hold in the AROM. To this end, we design an efficient algorithm *M* that answers queries in a way that is statistically indistinguishable from answers of the ARO. We refer to such an algorithm as an *emulator M* for the AROM. 6 Recall that the ARO consists of a tuple of oracles (ro*,*wo*,*vob). Our emulator *M* achieves a special (stronger) type of emulation: given oracle access to some ro and wo, *M* can efficiently emulate vob drawn from the ARO distribution *conditioned* on (ro*,*wo). 7 We use this type of emulation to prove Theorem 3.

**Lemma 2** (informal)**.** *There exists a probabilistic algorithm M such that for every security parameter λ ∈* N*,* *query bound t ∈* N*, and t-query adversary A,*

h

||h|i|
|---|---|---|
||(ro,wo,vo b)||
|(ro,wo,vo b)←O(λ)||(ro,wo,vo b)←O(λ)|

(ro*,*wo) i <u>t</u> Pr *A* = 1 *−* Pr *A* *M* = 1 *≤* *λ*

*.* (1)
2

*Moreover, M is* **pass-through** *with respect to* (ro*,*wo)*: it answers queries to those oracles by forwarding* *them to the corresponding “real” oracle (and recording the answers).*

We refer to the absolute difference in Equation 1 as the *emulation error*. An emulator is *perfect* if it has zero emulation error. **Prior oracle emulators.** Recall that a random oracle is a function ro chosen uniformly from (*{*0*,*1*}* *m* *→* *λ*

|{0, 1} ). It has a well-known perfect (stateless) emulator M|||that “lazily” samples answers: given a list|||
|---|---|---|---|---|---|
||λ ro|λ t λ|′|m ro ro|′|
|′||′|||ro|

ro of query-answer pairs tr *∈* (*{*0*,*1*}* *m* *×{*0*,*1*}* *λ* ) *t* and a new query *x ∈ {*0*,*1*}* *m*, *M* generates a query answer *y ∈{*0*,*1*}*, depending on if there exists an entry (*x,y*) *∈* tr. If so, *M* returns *y* := *y* and tr. Otherwise, *M* uniformly samples *y ←{*0*,*1*}* and returns the sampled answer *y* and the updated list tr = tr *∪{*(*x,y*)*}*. Note that the lists tr and tr can be omitted from the input and output if *M* maintains the list of known query-answer pairs in its state. The low-degree random oracle [CCS22] also has a perfect emulator, based on *succinct constraint detection* for the Reed–Muller code [BCFGRS17]. 6 Emulators are sometimes known as “lazy samplers” or “simulators”. In this paper we reserve the word *simulator* to refer to zero knowledge simulators. 7 A further strengthening is the ability to emulate oracle queries conditioned on an input list of (real) oracle query-answer pairs. We use this additional property to show that Micali’s SNARK maintains zero knowledge in the AROM (see Section 2.3).

**Challenges for the ARO.** The low-degree structure of vob may suggest that succinct constraint detection directly yields a construction of *M* (ro*,*wo) with perfect emulation. However, the “sparsity” of vo implies that the set of all possible vob is *not* a linear space, as we now explain. Recall that for *x ∈{*0*,*1*}* *m* *,y ∈* *{*0*,*1*}* *λ* *,z ∈{*0*,*1*}* *w*, vob (*x,y,z*) = vo(*x,y,z*) = 1 if and only if *y* = ro(*x*) and *z* = wo(*x*), and 0 otherwise.

|b b, vo are extended verification oracles, vo|b b = vo + vo|b may not be an extended verification||
|---|---|---|---|
|1 2|1 ′ (ro,wo)|2 ′||
||||8|

Hence, if vo1 2 *′* 1 2 oracle because there may exist *x,y₁,y₂,z₁,z₂* such that vob *′* (*x,y₁,z₁*) = vob *′* (*x,y₂,z₂*) = 1 and *y₁ ̸*= *y₂*. Hence, unlike for the LDRO, *we cannot directly construct M from succinct constraint detection*. **Our approach.** We adopt a novel approach to simulation. First, we design a query-efficient but time- inefficient perfect emulator for a random low-degree extension *f*ˆ of a given arbitrary function *f*. This *almost* suffices for our goal because vob is a random low-degree extension of the function vo defined by (ro*,*wo), which we can efficiently compute at any point by querying ro and wo. Second, we additionally achieve time-efficient emulation by leveraging the *sparsity* of vo, at the cost of a small statistical emulation error.

**(1) Time-inefficient emulation of a random low-degree extension.** Let *f* : *{*0*,*1*}*
*n* *→* F be a function and *f*

||f||
|---|---|---|
|LD|LD||
|n|w||
|n|n||
|||n|
|||n t|

*d ∈* N a degree bound. We seek an emulator *M* such that *M* answers queries in a way that is identically distributed to a random extension *f*ˆ of *f* with individual degree at most *d*. We fix some notation. For *w ∈ {*0*,*1*}*, we denote by *δ* the unique multilinear polynomial with *δ* *w*(*w*) = 1 and *δw*(*x*) = 0 for all *x ∈{*0*,*1*} \{w}*. For a set *S ⊆* F, we say that *w* is *S*-bad if for every *n*-variate polynomial *Q* of individual degree at most *d* such that (i) *Q*(*x*) = 0 for every *x ∈{*0*,*1*} \{w}* and (ii) *Q*(*z*) = 0 for every *z ∈ S*, it holds that *Q*(*w*) = 0. For a query-answer list tr *∈* (F *×* F), we denote the query set supp(tr) := *{x* : (*x,y*) *∈* tr*}*. Intuitively, *w* is *S*-bad if *f* (*w*) can be deduced from *f*ˆ*|S*, i.e. given the evaluation table of *f* everywhere except at *w* and partial knowledge about the structure of a low-degree extension *f*ˆ. Note that *S*-badness is monotone with respect to *S* and that if *w ∈ S* then *w* is *S*-bad. The query-efficient but time-inefficient emulator *M*LDworks as follows. *f ∗* *M* LD (tr*,x*): *∗* P

1.Let *S* := supp(tr) *∪{x}*, and *W* be the set of *S*-bad points. Set *P* (*X⃗*) :=
*w∈W* *f* (*w*) *· δw*(*X⃗*). ( *n* tr(*x*) *− P*(*x*) if *x ∈* supp(tr)

2.Define *g*: supp(tr) *∪{*0*,*1*} →* F by *g*(*x*) :=
*n*. 0 if *x ∈{*0*,*1*}*

3.Sample a random degree-*d* extension *g*ˆ of *g*.
4.Return *y* := ˆ*g*(*x*) + *P* (*x*) and tr
*′* := tr *∪{*(*x* *∗* *,y*)*}*.

Observe that *g* is well-defined since if *w ∈* supp(tr) *∩{*0*,*1*}* *n* then *w ∈ W* and tr(*w*) = *f* (*w*) by assumption. Moreover, *g*ˆ +*P* is a low-degree extension of the function *f* *′* : *{*0*,*1*}* *n* *→* F given by *f* *′*

(*w*) = 0
for *S*-good *w* and *f* *′*

(*w*) = *f* (*w*) for *S*-bad *w*. That is, *f*
*′* is consistent with *f* at every point the adversary “knows”, and is zero elsewhere. *g*ˆ + *P* is also consistent with all prior queries as recorded in tr. We show later that this is sufficient to perfectly emulate a random low-degree extension of *f*. The query complexity of *M*LDis equal to the size of *W*, i.e., the number of *S*-bad points. Aaronson and Wigderson [AW09, Lemma 4.3] proved that, provided *d ≥* 2, the number of *S*-bad points is at most *|S|* = *|*supp(tr)*|* + 1. Moreover since *S*-badness is monotone, querying *M*LD*t* times results in *t* queries to *f* across the whole execution.

**(2) Time-efficient emulation from sparsity.** There are two sources of time-inefficiency in the emulator *M*LD: (i) sampling the polynomial *g*ˆ; (ii) computing the set *W*. We consider each of these difficulties in turn. 8 In contrast, emulating the low-degree random oracle (as in [CCS22]) corresponds to emulating *f*ˆ for a *random* function *f* that the emulator *samples itself*. This considerably simplifies the task, and in particular enables a time-efficient perfect emulation.

(i) *Sampling g*ˆ*.* Since *g*ˆ has an exponentially-large description, we cannot sample it explicitly. Instead, we might hope to make use of the random multivariate polynomial sampling algorithm of [BCFGRS17], which achieves the following guarantee. **Lemma 3.** *There is an efficient probabilistic algorithm* LDSample *such that for every degree bound* *d ∈* N*, set S ⊆* F
*n* *, map h*: *S →* F*, q ∈* F *n* *, and α ∈* F*,*

Pr[LDSample(1 *d* *,S,h,x*) = *α*] = Pr[*P* (*x*) = *α | P |S*= *h*]*,*

*where P is a uniformly random n-variate polynomial of individual degree at most d.* 9

We do not know how to use LDSample to sample *g*ˆ directly, since that would require *S* = supp(tr) *∪* *{*0*,*1*}* *n* and so LDSample would run in exponential time. Instead, we use a structural result about low-degree extensions of the zero function, the *combinatorial nullstellensatz* [Alo99].

**Lemma 4** (informal)**.** *If a polynomial P is zero on {*0*,*1*}* *n* *, then there exist polynomials* (*Ri*) *n* *i*=1 *such* *that* X *n* *P* (*X⃗*) *≡ Xi*(*Xi−* 1)*Ri*(*X⃗*)*.* (2) *i*=1

Combining Lemma 4 with a linear-algebraic argument, we show that sampling each *Ri*in Equation 2 uniformly at random subject to constraints implied by *P* being a low-degree extension of *g* yields a uniformly random low-degree extension of *g*. We can then sample each *Ri*via LDSample.

(ii) *The set W.* We do not know of an algorithm that can efficiently compute, given a set *S ⊆* F *n*, the set of all *S*-bad points. As a result, we do not know how to efficiently realize *M*LD. Instead we address this difficulty by leveraging the structure of vo. Specifically, we consider *g* = vo (and thus *n* = *m* + *λ* + *w*).

We observe that vo is sparse: it is nonzero only at points (*x,y,z*) for ro(*x*) = *y* and wo(*x*) = *z*. If the adversary has not queried ro at *x*, then intuitively (since ro(*x*) is random) it will not be able to find any *y,z* such that vo(*x,y,z*) = 1, even given access to vob. In particular, the probability that the set *W* contains any (*x,y,z*) *∈{*0*,*1*}* *m*+*λ*+*w* such that vo(*x,y,z*) = 1, but ro(*x*) was not yet queried, should be negligible. Indeed, we show that this probability is at most *|S|/*2 *λ*.

Observe that Step 1 of the time-inefficient emulator does nothing if *f* (*w*) = 0 for all *w ∈ W*. It follows from the above that to achieve simulation accuracy *O*(*|S|/*2 *λ* ), it suffices to include in *W* only points (*x,y,z*) for which the adversary has already queried ro at *x* and ro(*x*) = *y,* wo(*x*) = *z*. Since we observe the adversary’s queries to ro, this set of points is easy to determine.

To show this formally, we follow an “identical-until-bad-is-set” analysis [BR06].

9 If the RHS is not well-defined, LDSample outputs *⊥*.

## 3 Preliminaries

### 3.1 Notations

We define [*n*] := *{*1*,...,n}*. For a subset *S ⊆* [*n*], we use *S*¯ to denote the complement of *S*. We use F *≤d* [*X₁,...,Xm*] to denote the set of *m*-variate polynomials of individual degree at most *d* with coefficients *⃗d≤d* *⃗*
in F; we write deg(*·*) to denote the individual degree. For = (*d₁,...,dm*), we use F [*X₁,...,Xm*] to
denote the set of *m*-variate polynomials such that the variable *Xi*has individual degree at most *di*for each *i ∈* [*m*]. **Functions.** We use Dom(*f*) to denote the domain and Cod(*f*) to denote the codomain of a function *f*. We use (*X→Y*) to denote the set of all functions *{f* : *X → Y}*, and (*X ⇀ Y*) to denote the set of all partial functions *{f* : *X ⇀ Y}*. For a linear map Φ, we use ker(Φ) to denote the kernel of Φ and im(Φ) to denote the image of Φ. We say that a function is total if it is defined for all elements of its domain, and say that it is not total otherwise. **Low-degree extensions.** For *n,d ∈* N, *S ⊂* n F *n* and *f* : *S →* F we denote the set of extensions of degree at o most *d* of *f* to the field F by LDEF*,d*[*f*] := *f*ˆ *∈* F *≤d* [*X₁,...,Xn*] : *f*ˆ(*x*) = *f* (*x*) *∀x ∈ S*.

**Distributions.** For finite set *X*, we write *x ← X* to denote that *x* is drawn uniformly at random from *X*. We use supp(*D*) to denote the support of the distribution *D*. We write *U* (*X*) to denote the uniform distribution over the set *X*. **Oracle distributions.** An *oracle distribution O* is a distribution over functions *θ* : *X→Y*. We define Dom(*O*) := *X* and Cod(*O*) := *Y*. A *random oracle* is an oracle distribution *U* (*m,n*) given by *θ ←* (*{*0*,*1*}* *m* *→{*0*,*1*}* *n* ) for some *m,n ∈* N. **Oracle algorithms.** *θ*

|||For a function θ : X→Y, we write A||for an algorithm with oracle access to θ.|||||
|---|---|---|---|---|---|---|---|---|
||||ν|i|i|i|(θ ,...,θ|)|
||i|t t|i oid t|||oid|ν||
|i|i||||||||

Further, for a tuple of functions (*θ₁,...,θ*), where *ν ∈* N, with *θ* : *X → Y*, we write *A* (*θ*1*,...,θν*) for an algorithm with oracle access to each *θ* for *i ∈* [*ν*], and *A* *θ* *S*for an algorithm with oracle access to a subset of functions *{θ | i ∈ S}* where *S ⊆* [*ν*]. Often it is useful to view a tuple of oracles (*θ₁,...,θ*) as a single *combined* oracle *θ* such that *θ*(oid*,x*) = *θ* (*x*) for all oid *∈* [*ν*] and *x ∈* Dom(*θ*). **Oracle transcripts.** For *F ⊆* (*X → Y*), an *F*-query-answer transcript is a sequence of tuples tr := ((*x₁,y₁*)*,...,*(*x,y*)) *∈* (*X×Y*) for some *t ∈* N, such that there exists *f ∈ F* where for all *i*, *f* (*x*) = *y*. We denote the query set supp(tr) := *{x* : (*x,y*) *∈* tr*}*. Note that we can view tr as a function supp(tr) *→* F. For an oracle distribution *O*, we define an *O*-query-answer transcript to be a supp(*O*)-query-answer transcript. For *O* supported on *ν*-tuples of oracles, an *O*-query-answer transcript is defined with respect to the combined oracle; i.e., tr = ((oid₁*,x₁,y₁*)*,...,* (oid*t,xt,yt*)) *∈* S *ν t*

|ν oid=1|oid t|oid||
|---|---|---|---|
|||tr θ||

( (*{*oid*}×* Dom(*θ*oid) *×* Cod(*θ*oid))). We also define tr*|*oid:= *{*(*x,y*) : (oid*,x,y*) *∈* tr*}*. *θ* For an oracle algorithm *A* and oracle *θ*, the notation o *←− A* (*z*) denotes that *A* on input *z* outputs o and makes the sequence of oracle queries tr. **Indexed relations.** An *indexed relation R* is a set of triples (✐*,* ①*,*✇) where ✐ is the index, ① is the instance, and ✇ is the witness; the corresponding *indexed language L*(*R*) is the set of index-instance pairs (✐*,*①) for which there exists a witness ✇ such that (✐*,* ①*,*✇) *∈R*. For example, the indexed relation of satisfiable boolean circuits consists of triples where ✐ is the description of a boolean circuit, ① is a partial assignment to its input wires, and ✇ is an assignment to the remaining wires that makes the circuit output 0. **Oracle relations.** For a set of oracle distributions *X*, we write *R* *X* to denote the set of indexed relations *θ* S *{R* : *θ ∈* *O∈X* supp(*O*)*}*. When considering sets of oracle distributions *X* for which each *O∈X* is such
that supp(*O*) contains tuples of oracles (*θ₁,...,θν*), for *ν ∈* N, with oracle identifiers (oid₁*,...* oid*ν*), we

S

|(X,oid)||θ|ν O∈X|
|---|---|---|---|
|(X,oid)|(X,oid) ν O∈X|θ||

write *R* to denote the set of indexed relations *{R*oid: (*θ₁,...,θ*) *∈* supp(*O*)*}*. We define *R ∈* NP if and only if there exists a polynomial-time oracle Turing machine *M* such that, for S *θ* every (*θ₁,...,θ*) *∈* supp(*O*), *R*oid= *{*(✐*,* ①*,*✇) : *M*oid(✐*,* ①*,*✇) = 1*}*. **Security parameters.** We assume for simplicity that all public parameters have a length of at least *λ* so that efficient algorithms that receive such parameters can run in time (at least) polynomial in *λ*. **Adversaries.** An adversary (or extractor) is *polynomial-size* if it can be expressed as a circuit of polynomial size. We also consider a relaxed definition: an adversary (or extractor) running in *(non-uniform) expected* *polynomial-time* is a Turing machine provided with a *polynomial-size* non-uniform advice string and access to an infinite random tape, whose expected running time for all choices of advice is polynomial. An adversary *A* with expected running time *t* and success probability *p* can be converted into a circuit of size *O*(*t/ϵ*) with success probability *p − ϵ* as follows: first truncate the execution of *A* at running time *t/ϵ*; then choose as advice the randomness that maximizes the success probability of the truncated *A*. For *ν ∈* N and a distribution *O*, whose support contains tuples of oracles (*θ₁,...,θν*), we refer to an adversary with access to (*θ₁,...,θν*) *←O* as an *O*-adversary.

### 3.2 Linear algebra and the combinatorial nullstellensatz

**Definition 3.1.** *An affine subspace S of a vector space V is a set a* + *S₀* = *{a* + *s₀* : *s₀ ∈ S₀} where a ∈ V* *and S₀ is a subspace of V.*

**Claim 3.2.** *Let* Φ : *V → W be a linear map, and let S be a finite affine subspace of V. If s ∼U*(*S*) *then* Φ(*s*) *∼U*(Φ(*S*))*.*

*Proof.* Since *S* is a finite affine subspace of *V*, there is a vector *a ∈ V* and a finite subspace *S₀ ⊆ V* such that *S₀* := *{s − a* : *s ∈ S}*. Fix *w ∈* Φ(*S*) and *s* *′* 0*∈ S₀* such that Φ(*s* *′* 0 ) = *w −* Φ(*a*); then

Pr [Φ(*s*) = *w*] = Pr [Φ(*s₀*) = *w −* Φ(*a*)] = Pr [*s₀ ∈* ker(Φ) + *s* *′* 0] *s←S s*0*←S*0*s*0*←S*0 = *|*ker(Φ)*|/|S₀|* = 1*/|*Φ(*S₀*)*|* = 1*/|*Φ(*S*)*| .*

**Lemma 3.3** (Combinatorial nullstellensatz [Alo99])**.** *Let* F *be an arbitrary field, and let f be a polynomial* Q
*in* F[*X₁,...,Xn*]*. Let S₁,...,Snbe nonempty subsets of* F *and define g*

|||(x ) =||(x − s).|
|---|---|---|---|---|
|||i i|s∈S|i|
|n n|i|i|i i||
||i i||||
|i=1|||||

*i* *If f*
*vanishes over all the common zeros of g₁,...,g (that is, if f*(*s₁,...,sn*) = 0 *for all s ∈ S), then there are*
*polynomials h₁,...,hn∈* F[*X₁,...,Xn*] *so that* deg(*h*) *≤* deg(*f*) *−* deg(*g*) *so that*

X *f* = *h g.*

### 3.3 Non-interactive arguments in oracle models

Given a set of oracle distributions *X*, a (preprocessing) *non-interactive argument* relative for an indexed oracle relation *R* *X* is a tuple of algorithms ARG = (*G, I, P, V*) that works as follows. Below we denote by S *θ* an oracle (or tuple of oracles) in the set *O∈X* supp(*O*).

- *G*(1 *λ* ) *→* pp. On input a security parameter *λ* (in unary), the generator *G* samples public parameters pp.
- *I* *θ* (pp*,*✐) *→* (ipk*,*ivk). On input public parameters pp and an index ✐ for the relation *R*, the indexer *I* deterministically computes index-specific proving and verification keys (ipk*,*ivk).

- *P* *θ* (ipk*,* ①*,*✇) *→ π*. On input an index-specific proving key ipk, an instance ①, and a corresponding witness ✇, the prover *P* computes a proof *π* that attests to the claim that (✐*,* ①*,*✇) *∈R*
*θ*.

- *V* *θ* (ivk*,* ①*,π*) *→ b*. On input an index-specific verification key ivk, an instance ①, and a corresponding proof *π*, the verifier *V* computes a bit indicating whether *π* is a valid proof. We require ARG to satisfy the following completeness and soundness properties.
- *Completeness.* For every oracle distribution *O∈X* and adversary *A*,
  *θ ←O*(*λ*)  (✐*,* ①*,*✇) *∈Rθ*pp *←G*(1*λ*)    Pr   *⇓* (✐*,* ①*,*✇) *←A* *θ* (pp)   = 1 *.*  *Vθ*(ivk*,* ①*,π*) = 1 (ipk*,*ivk) *←Iθ*(pp*,*✐)  *π ←P* *θ* (ipk*,* ①*,*✇)

The above formulation of completeness allows (✐*,* ①*,*✇) to depend on the oracle *θ* and public parameters pp.

- *Soundness.* For every oracle distribution *O∈X* and polynomial-size adversary *P*˜,
  *V* *θ* (ivk*,* ①*,π*) = 1 *θ ←O*(*λ*)  pp *←G*(1*λ*)  Pr   *∧* ˜*θ*   *≤* negl(*λ*)*.* *θ*(✐*,* ①*,π*) *← P* (pp) (✐*,*①) *̸∈L*(*R*) *θ* (ipk*,*ivk) *←I* (pp*,*✐)

The above formulation of soundness allows (✐*,*①) to depend on the oracle *θ* and public parameters pp. We also consider straightline knowledge soundness properties and zero knowledge for ARG. **Straightline knowledge soundness.** ARG has *straightline knowledge soundness* (with respect to auxiliary input distribution *D*) if there exists a deterministic polynomial-time extractor *E* such that for every oracle distribution *O∈X* and (non-uniform) polynomial-time adversary *P*˜,   *θ ←O*(*λ*)  pp *←G*(1 *λ* )  *θ*  *V* (ivk*,* ①*,π*) = 1 ai *←D*(pp)    Pr  *∧*tr *θ*  *≤* negl(*λ*)*.* *θ*(✐*,* ①*,π*) *←− P*˜ (pp*,*ai)   (✐*,* ①*,*✇) *̸∈R* *θ*   (ipk*,*ivk) *←I* (pp*,*✐)  ✇ *←E*(pp*,* ✐*,* ①*,π,* tr)

**Zero knowledge.** ARG has statistical zero knowledge if there exists a probabilistic polynomial-time stateful simulator *S* such that for every oracle distribution *O∈X* and polynomial-size honest stateful adversary *A*, the following distributions are negl(*λ*)-close in statistical distance:     *θ ←O*(*λ*)    *θ ←O*(*λ*)   *λ*        pp *←G*(1 )   pp *←S*(1 *λ* )  *θ θ Sθ* *A* (*π*) (✐*,* ①*,*✇) *←A* (pp) and *A* (*π*)tr *θ*

*.* (3)
  *θ*     (✐*,* ①*,*✇) *←−A* (pp)    (ipk*,*ivk) *←I* (pp*,*✐)    *θ*  *θ* *π ←S* (✐*,* ①*,*tr) *π ←P* (ipk*,* ①*,*✇)

An adversary *A* is *honest* if it outputs (✐*,* ①*,*✇) *∈R* *θ* with probability *≥* 1 *−* negl(*λ*). Above, the notation *Sθ* *A* indicates that the simulator *S* (with oracle access to *θ*) answers the oracle queries of *A*. **Succinctness.** In this work, we say that a non-interactive argument system ARG for *R* *X* is *succinct* if there is a fixed polynomial *p* such that *both* the length of the proof and the running time of the argument verifier are bounded by *p*(*λ, |*①*|*). In this case, we refer to ARG as a SNARG; if ARG also has knowledge soundness, it is a SNARK.

### 3.4 Proof-carrying data

A triple of algorithms PCD = (G*,* I*,* P*,*V) is a (preprocessing) *proof-carrying data scheme* (PCD scheme) for a class of compliance predicates F relative to a set of oracle distributions *X* if the properties below hold.

**Definition 3.4.** *A* **transcript** T *is a directed acyclic graph where each vertex u ∈ V* (T) *is labeled by local*

(*u*) (*e*)
*data z* loc *and each edge e ∈ E*(T) *is labeled by a message z ̸*= *⊥. The* **output** *of a transcript* T*, denoted* o(T)*, is z*

(*e*) *where e* = (*u,v*) *is the lexicographically-first edge such that v is a sink.*
**Definition 3.5.** *A vertex u ∈ V* (T) *is* Φ**-compliant** *for* Φ *∈* F *if for all outgoing edges e* = (*u,v*) *∈ E*(T) S *and for all θ ∈* *O∈X* supp(*O*)*:* *θ* (*e*) (*u*)

- *(base case) if u has no incoming edges,* Φ (*z,z*
loc *, ⊥,..., ⊥*) = 1*;* *θ* (*e*) (*u*) (*e*1) (*em*)

- *(recursive case) if u has incoming edges e₁,...,em,* Φ (*z,z*
loc *,z,...,z*) = 1*.* *We say that* T *is* Φ**-compliant** *if E*(T) *is non-empty and all vertices incident to an edge are* Φ*-compliant.*

**Completeness.** For every oracle distribution *O∈X* and adversary *A*,     Φ *∈* F *θ ←O*(*λ*)  *m m θ**λ*  *∧* (*∧i*=1*zi*= *⊥*) *∨* (*∧i*=1V (✐✈❦*,zi,πi*) = 1)  ♣♣ *←* G(1 )  *m θ*

||||||, [z ,π|] ) ←A (♣♣)  = 1||
|---|---|---|---|---|---|---|---|
||θ loc||m||loc i|i m i=1|θ|
||θ||||θ|loc|θ i i m i=1|

Pr  *∧* Φ *θ* (*z,z,z₁,...,z*) = 1 (Φ*,z,z.*    *⇓* (✐♣❦*,*✐✈❦) *←* I (♣♣*,*Φ)  *π ←* P (✐♣❦*,z,z,* [*z,π*]) V (✐✈❦*,z,π*) = 1

**Straightline knowledge soundness.** PCD = (G*,* I*,* P*,*V) has straightline knowledge soundness (with respect to auxiliary input distribution *D*) if there exists a deterministic polynomial-time extractor E such that for every oracle distribution *O∈X* and (non-uniform) polynomial-time adversary P˜,   *θ ←O*(*λ*)  ♣♣ *←* G(1 *λ* )   Φ *∈* F   ai *←D*(♣♣)   *∧*V(✐✈❦*,* o*,π*) = 1  Pr tr *θ*  *≤* negl(*λ*)*.*  (Φ*,* o*,π*) *←−* P˜ (♣♣*,*ai)   *∧* T is not Φ-compliant *∨* o(T) *̸*= o *θ*   (✐♣❦*,*✐✈❦) *←* I (♣♣*,*Φ)  T *←* E(♣♣*,* Φ*,* o*,π,* tr)

**Zero knowledge.** PCD has statistical zero knowledge if there exists a probabilistic polynomial-time stateful simulator S such that for every oracle distribution *O∈X* and polynomial-size honest (stateful) adversary *A*,

the following distributions are negl(*λ*)-close in statistical distance:     *θ ←O*(*λ*)    *θ ←O*(*λ*)   *λ*        ♣♣ *←* G(1 )   *λ*

||||||♣♣ ← S(1|) |
|---|---|---|---|---|---|---|
|loc|i i i=1 m|θ θ|loc i|m i i=1|tr θ||
|θ|loc|m i i i=1|||θ||

*θ m θ* S*θ* *A* (*π*) (Φ*,z,z,* [*z,π*]) *←A* (♣♣) and *A* (*π*)*.*       (Φ*,z,z,* [*z,π*]) *←−A* (♣♣)    (✐♣❦*,*✐✈❦) *←* I (♣♣*,*Φ)       *π ←* S (Φ*,z,* tr) *π ←* P (✐♣❦*,* Φ*,z,z,* [*z,π*])

An adversary *A* is *honest* if its output satisfies the implicant of the completeness condition with proba- bility *≥* 1 *−* negl(*λ*) (i.e., Φ *∈* F, Φ *θ* (*z,z*loc*,z₁,...,zm*) = 1, and either for all *i*, *zi*= *⊥*, or for all *i*, V *θ* (✐✈❦*,zi,πi*) = 1). Above, the notation *A* S indicates that the simulator S answers oracle queries of *A*. **Efficiency.** The generator G, prover P, indexer I and verifier V run in polynomial time. A proof *π* has size poly(*λ, |*Φ*|*); in particular, it does not grow with each application of P.

### 3.5 Accumulation schemes

We recall the definition of an accumulation scheme from [BCMS20], extended to any set of oracle distribu- tions; then, in Definition 3.6 below, we describe how to specialize that notion to the case of accumulating oracle queries. S

|O∈X|∗ 3|θ Φ Φ|
|---|---|---|
|Φ Φ|||
|Φ|||

Let Φ : supp(*O*(*∗*))*×* (*{*0*,*1*}*) *→{*0*,*1*}* be a predicate (for clarity we write Φ (pp*,* i*,*q) for Φ(*θ,* pp*,* i*,*q)). Let *H* be a probabilistic algorithm with access to *θ*, which outputs predicate parameters pp. An **accumulation scheme for** (Φ*, H*) is a tuple of algorithms AS = (G*,* I*,* P*,* V*,*D) that have access to the same oracle *θ* (except for G). These algorithms satisfy *completeness* and *soundness*, and optionally also *zero knowledge*, as specified below. **Completeness.** For every oracle distribution *O∈X* and (unbounded) adversary *A*,  

||(dk, acc ) = 1||||θ ←O(λ|)|
|---|---|---|---|---|---|---|
|θ|j|||||λ|
|θ|Φ Φ|i||||θ λ|
||||||Φ||
|n|ℓ||Φ i n i=1|j ℓ j=1|θ|Φ|
|i i=1|j j=1|V|||θ|Φ Φ|
|θ|||V|θ|n i i=1|ℓ j j=1|

*∀ j ∈* [*ℓ*]*,* D  pp *←* G(1)   *∀ i ∈* [*n*]*,* Φ (pp*,* i*,* q) = 1   pp *←H* (1)  Pr   *⇓*   = 1 *.*  V *θ* (avk*,*[q]*,*[acc]*,*acc*,π*) = 1 (i*,*[q]*,*[acc]) *←A* (pp*,*pp)   (apk*,*avk*,*dk) *←* I (pp*,*pp*,* i)  D (dk*,*acc) = 1 (acc*,π*) *←* P (apk*,*[q]*,*[acc])

Note that for *ℓ* = *n* = 0, the precondition on the left-hand side holds vacuously; this is required for the completeness condition to be non-trivial. **Soundness.** For every oracle distribution *O∈X* and polynomial-size adversary *A*,  

|, [acc]|, acc,π ) = 1|||θ ←O(λ|)|
|---|---|---|---|---|---|
|j ℓj=1 θ|V||||λ|
||||||θ λ|
|||||Φ||
|θ|j|Φ i n i=1|j ℓ j=1 V|θ|Φ|
|θ Φ|Φ i|||θ|Φ Φ|

V *θ* (avk*,*[q]*i i* *n* =1  pp *←* G(1)   D (dk*,*acc) = 1   pp *←H* (1)  Pr   *⇓*   *≥* 1 *−* negl(*λ*)*.*  *∀ j ∈* [*ℓ*]*,* D (dk*,*acc ) = 1 i [q] [acc] *←A* (pp*,*pp)   acc *π*  *∀ i ∈* [*n*]*,* Φ (pp*,* i*,* q) = 1 (apk*,*avk*,*dk) *←* I (pp*,*pp*,* i)

**Zero knowledge.** There exists a polynomial-time stateful simulator S such that for every oracle distribution *O ∈ X* and polynomial-size stateful “honest” adversary *A* (see below), the following distributions are

(statistically/computationally) indistinguishable:     *θ ←O*(*λ*)     pp *←* G(1*λ*)      *θ λ* *θ*ppΦ*←H* (1 ) *A* (acc)*n ℓj θ*

|Φ i i=1 n|j ℓj =1|θ|Φ|
|---|---|---|---|
|||θ|Φ Φ|
|V|θ|i i=1 n|j ℓ j=1|

  (iΦ*,*[q*i*] *i*=1 *,*[acc*j*] =1 ) *←A* (pp*,*ppΦ)         (apk*,*avk*,*dk) *←* I (pp*,*pp*,* i)     (acc*,π*) *←* P (apk*,*[q]*,*[acc])

and     *θ ←O*(*λ*)    *λ*  

| |||pp ← S(1 ) ||||
|---|---|---|---|---|---|---|
|θ|||Φ|θ λ|||
|V|Φ i n i=1|j ℓ j=1 tr Φ i n i=1|θ θ Φ j ℓj=1|Φ Φ|θ Φ Φ|i|

*θ* pp *←H* *θ* (1 ) *λ* *A* (acc)*.*       (i*,*[q]*,*[acc]) *←−A* (pp*,*pp)      acc *←* S (pp*,* i*,*tr)

Here *A* is *honest* if it outputs, with probability 1, a tuple (i*,*[q]*,*[acc]) such that Φ (pp*,* i*,* q) = 1 and D *θ* (dk*,*acc*j*) = 1 for every *i ∈* [*n*] and *j ∈* [*ℓ*]. Note that the simulator S is *not* required to simulate the accumulation verifier proof *π*. **Accumulation scheme for oracle queries.** We explain how to specialize the general notion of an accumula- tion scheme above to the particular case of accumulating queries to a tuple of oracles.

**Definition 3.6.** *Let X be a set of oracle distributions. An* **accumulation scheme for** *X***-queries** *is an* *accumulation scheme where: (i) the accumulation verifier* V *does not access the oracle; (ii) H* = *⊥ (and* *so* ppΦ= *⊥); (iii) predicate inputs* q *are of the form* (*x,y*)*;* 10 *(iv) the predicate* Φ *is defined such that* Φ *θ* (ppΦ*,* iΦ*,x,y*) = 1 *if and only if θ*(*x*) = *y (in particular,* ppΦ*and* iΦ*are ignored).*

### 3.6 Commitment schemes

Let *ν ∈* N and let *X* be a set of oracle distributions, such that each *O ∈X* is a distribution over tuples of oracles (*θ₁,...,θν*). A *commitment scheme in X* is a tuple CM = (CM*.*Setup*,*CM*.*Commit) with the following syntax.

- CM*.*Setup, on input a security parameter 1
*λ*, outputs a commitment key ck.

- CM*.*Commit, on input a commitment key ck, a message *m ∈ {*0*,*1*}*
*∗*, and randomness *ω*, outputs a commitment cm. The tuple CM satisfies a binding property and, optionally, a hiding property.

- **Binding.** For every *O∈X* and efficient adversary *A*,  
*m₀ ̸*= *m₁* (*θ₁,...,θν*) *←O*(*λ*) Pr  *∧* ck *←* CM*.*Setup(1 *λ* )  CM*.*Commit(ck*,m₀*;*ω₀*) = CM*.*Commit(ck*,m₁*;*ω₁*) ((*m₀,ω₀*)*,* (*m₁,ω₁*)) *←A* (*θ*1*,...,θν*) (ck) <u>≤ negl(λ).</u> 10 If *X* is a set of oracle distributions whose support contains tuples of oracles, then *x* is assumed to start with the oracle identifier corresponding to the oracle being queried.

- **Hiding.** For every *O∈X* and efficient stateful adversary *A* that outputs two messages of the same length, the following distributions are (statistically or computationally) indistinguishable:
    (*θ₁,...,θν*) *←O*(*λ*)    *λ*    ck *←* CM*.*Setup(1 )  *D₀*(*λ*) := (pp*,*cm*,*aux) (*m₀,m₁,*aux) *←A* (*θ*1*,...,θν*) (ck)   poly(*λ*)     *ω ←{*0*,*1*}*     cm := CM*.*Commit(ck*,m₀*; *ω*)     (*θ₁,...,θν*) *←O*(*λ*)    *λ*    ck *←* CM*.*Setup(1 )  and *D₁*(*λ*) := (pp*,*cm*,*aux) (*m₀,m₁,*aux) *←A* (*θ*1*,...,θν*) (ck)*.*   poly(*λ*)     *ω ←{*0*,*1*}*     cm := CM*.*Commit(ck*,m₁*; *ω*)

Note that in this definition CM does not have access to (*θ₁,...,θν*). The above generalizes the notion of a commitment scheme, which is recovered from the above by setting the oracles to be empty. Moreover, we say that CM is *s***-succinct** if for every commitment key ck *∈* CM*.*Setup(1 *λ* ), message *m ∈{*0*,*1*}* *∗*, and randomness *ω*, it holds that CM*.*Commit(ck*,m*; *ω*) *∈{*0*,*1*}* *s*(*λ*). We have the following simple claim about any binding and hiding commitment scheme.

**Claim 3.7.** *Let* CM *be a binding and hiding commitment scheme. Then for every message m,* h i Pr CM*.*Commit(ck*,m,ω*) = CM*.*Commit(ck*,m,ω* *′* ) = negl(*λ*)*.* *ω,ω′*

A proof of the above claim appears in Claim 3.4 of [CCS22].

### 3.7 Constraint detection for low-degree polynomials

**Definition 3.8.** *Let ⃗d* = (*d₁,...,dm*) *∈* N *m* *. The low-degree polynomial evaluation code is defined as* *follows:* n o *m ≤d⃗ m* LD[F*,m,⃗d*] := *c ∈* (F *→* F) : *∃ p ∈* F [*X₁,...,Xm*] *s.t. ∀ x ∈* F*,c*(*x*) = *p*(*x*)*.*

*Further, let F* = *{*F*λ}λ∈*N*be a family of fields, m*: N *→* N *an arity function, and ⃗d*: N *→* N *m* *a degree* *function. We define* n o LD[*F,m,⃗d*] := LD[F*λ,m*(*λ*)*,⃗d*(*λ*)]*.* *λ∈*N

We recall the notion of constraints for linear codes.

**Definition 3.9.** *Let C⊆* (*D →* F) *be a linear code. A subset Q ⊆ D is* **constrained** *if there exists a nonzero* P *⊥* *z* : *Q →* F *such that, for every c ∈C,* *x∈Q* *z*(*x*)*c*(*x*) = 0 *(equivalently, if there exists z ̸*= 0 *∈C with* supp(*z*) *⊆ Q); we refer to z as a* **constraint** *on Q. We say that Q is* **unconstrained** *if it is not constrained.* *We say that Q ⊆ D* **determines** *x ∈ D if x ∈ Q or there exists a constraint z on Q ∪{x} such that z*(*x*) *̸*= 0*.*

We recall the definition of a constraint detector [BCFGRS17], which is an algorithm that determines whether a set of queries *Q* is constrained and, if so, outputs a constraint.

**Definition 3.10.** *Let C ⊆* (*D →* F) *be a linear code. An algorithm* CD *is a* **constraint detector** *for C* *if, given as input a set Q ⊆ D, outputs: (i) a basis for the space of constraints {z*: *Q →* F : *∀ c ∈* P *C,* *x∈Q* *z*(*x*)*c*(*x*) = 0*} on Q if Q is constrained; (ii) ⊥ if Q is unconstrained; A code family {Cλ}λ∈*N*has* **efficient constraint detection** *if there exists a polynomial-time algorithm* CD *such that, for every λ ∈* N*,* CD(1 *λ* *, ·*) *is a constraint detector for Cλ.*

The following theorem is proved in [BCFGRS17]:

**Theorem 3.11.** *The code family* LD[*F,m,⃗d*]*has a constraint detector* CD(1 *λ* *, ·*)*that runs in time* poly(*m*(*λ*)*,d*(*λ*)*,*log*|*F*λ|*)*,* *where d*(*λ*) := max*i∈*[*m*]*d*(*λ*)*i. In particular, it has efficient constraint detection.*

### 3.8 Forking lemmas

We state a general forking lemma proved in [BN06].

**Lemma 3.12.** *Fix t,λ ∈* N*. Let A be a probabilistic algorithm that on input x,y₁,...,ytreturns a pair* (*I,σ*)*, where I ∈* [*t*] *and σ is referred to as a side output. Let* IG *be a probabilistic algorithm that we call the* *input generator. The accepting probability of A, denoted* acc*, is defined as follows:*   *x ←* IG acc := Pr  *I ≥* 1 *y₁,...,yt←U*(*{*0*,*1*}* *λ* ) *.* (*I,σ*) *←A*(*x,y₁,...,yt*)

*The forking algorithm* Fork*Aassociated to A is the probabilistic algorithm that takes input x and proceeds* *as follows:*

*(i)Pick coins ρ for A at random.*

||t|λ|||
|---|---|---|---|---|
|′ ′|I′|t′|λ|I−1 I′|
|′|I I′||′||

*(ii)Sample y₁,...,y ←U*(*{*0*,*1*}*)*, and run A*(*x,y₁,...,yt*; *ρ*) *to obtain* (*I,σ*)*.*
*(iii)If I* = 0 *then return* (0*,ε,ε*)*.*
*(iv) Otherwise, sample y,...,y ← U*(*{*0*,*1*}*) *and run A*(*x,y₁,...,y,y,...,yt′*; *ρ*) *to obtain*
(*I,σ*)*.*

*(v)If* (*I* = *I and y ̸*= *y*) *then return* (1*,σ,σ*)*.* *(vi)Otherwise return* (0*,ε,ε*)*.*
*Let* *x ←* IG frk := Pr *b* = 1*′.* (*b,σ,σ*) *←* Fork*A*(*x*)

*Then* <u>acc 1</u> frk *≥* acc *· −* *λ* *,* *t* 2

*alternatively,* <u>t</u> *√* acc *≤* *λ* + *t ·* frk*.* 2

### 3.9 Identical-until-bad

We consider two programs, *G* and *H*, which are written in some pseudocode. We say that *G* and *H* are *identical-until-bad* if they are syntactically identical except for statements that follow the setting of a bad flag to true. Somewhat more formally, let *G* and *H* be programs written in some pseudocode and let bad be a flag that occurs in both of them. We say that *G* and *H* are *identical-until-bad* if their code is the same except

possibly places where *G* has a statement “set the bad flag” followed by some statements *SG*while *H* has a corresponding statement “set the bad flag” followed by some statements *SH*, different from *SG*. We refer the reader to [BR06] for further details and a full formal treatment of the notion of identical- until-bad, which requires specification of the programming language in question to fully formalize. We stress that that identical-until-bad is a purely syntactic requirement. We state the fundamental lemma of game-playing, which is proved in [BR06].

**Lemma 3.13.** *Let G and H be identical-until-bad programs and let A be an adversary. Then*

Pr[*A* *G* = 1] *−* Pr[*A* *H* = 1] *≤* Pr[*A* *G* *sets* bad]*.*

## 4 Arithmetized random oracle model

We define the arithmetized random oracle model. As a first step, we define the arithmetized random oracle *distribution*, which is defined over tuples (ro*,*wo*,*vob), and explain how the oracles (ro*,*wo*,*vob) are sampled.

**Definition 4.1.** *Let m ∈* N *be an arity parameter, λ ∈* N *be a security parameter, r ∈* N *be a randomness-size* *parameter, w ∈* N *be a witness-size parameter, and d ∈* N *be a degree parameter. For all oracle circuits* *B* : *{*0*,*1*}* *m*+*r* *→{*0*,*1*}* *w* *, we define an* **arithmetized random oracle distribution** ARO[F*,m,λ,d,B*]*,* 11 *where* F *is a finite field and the support of* ARO[F*,m,λ,d,B*] *contains triples* (ro*,*wo*,*vob) *that are sampled* *as follows:*

|||m|
|---|---|---|
|m||r|
|w|ro x m+λ+w||

*1.Sample the* **random oracle** ro *uniformly at random from* (*{*0*,*1*} →{*0*,*1*}*
*λ* )*.*

*2. For every x ∈ {*0*,*1*}, sample a random string µx∈ {*0*,*1*}. Then define the* **witness oracle** wo : *{*0*,*1*}*
*m* *→{*0*,*1*} as* wo(*x*) := *B* (*x,µ*)*.*

*3.Define the* **verification function** vo : *{*0*,*1*} →{*0*,*1*} as*
( 1 *if* ro(*x*) = *y ∧* wo(*x*) = *z* vo(*x,y,z*) :=*.* 0 *o.w.*

*4.Sample the* **(extended) verification oracle** vob : F
*m*+*λ*+*w* *→* F *uniformly at random from the set* n o *p ∈* F *≤d* [*X₁,...,Xm*+*λ*+*w*] : *p equals* vo *on {*0*,*1*}* *m*+*λ*+*w* *.*

*5.Output* (ro*,*wo*,*vob)*.* Next, we define a *family* of ARO distributions, which is parameterized by a family of finite fields
(*·*) *m*(*λ*) *w*(*λ*)
*F* = *{*F*λ}λ∈*Nand a family of oracle circuits *B* = *{B* *λ* : *{*0*,*1*} →{*0*,*1*}}λ∈*N. Here, *B* can be interpreted as the set of all possible adversarial strategies for learning information about the random oracle, and *λ* is the security parameter.

**Definition 4.2.** *Let F* = *{*F*λ}λ∈*N*be a family of fields, m*: N *→* N *be an arity function, w*: N *→* N

(*·*) *m*(*λ*) *w*(*λ*)
*be a witness-size function, B* = *{B* *λ* : *{*0*,*1*} →{*0*,*1*}}λ∈*N*be a family of oracle circuits, and* *d*: N *→* N *be a degree function. We define the* **arithmetized random oracle family** *as*

(*·*)
ARO[*F,m,d, B*] := *{* ARO[F*λ,m*(*λ*)*,λ,d*(*λ*)*,B* *λ*]*}λ∈*N*.*

The “arithmetized random oracle” is the set of all ARO distributions for polynomial-sized circuit families *B*.

**Definition 4.3.** *Let F* = *{*F*λ}λ∈*N*be a family of fields, m*: N *→* N *be an arity function, w*: N *→* N *be a* *witness-size function, and d*: N *→* N *be a degree function. Then, we define a* **set of arithmetized random** **oracle families** *as*

ARO[*F,m,d*] := *{*ARO[*F,m,d, B*] : *B is a family of* poly(*λ*)*-size oracle circuits},*

*m*(*λ*)

||(·)|w(λ)|
|---|---|---|
|Given m ∈ N and the oracle circuit B, the randomness length r and witness size w parameters are determined. Thus r,w do not appear in the parameterization of ARO.|λ|λ∈N|

*where above B* = *{B* : *{*0*,*1*} →{*0*,*1*}}.*

## 5 Stateful emulation of the ARO

We define the notion of a stateful emulator for the ARO, present our stateful emulator construction, and then prove its correctness. We start by giving a general definition of stateful emulators for distributions over tuples of oracles, and stating the main result of this section.

**Definition 5.1** (Stateful oracle algorithms)**.** *For a randomized algorithm M*: ((*X ⇀ Y*) *× X*) *→ Y and* *oracle algorithm A, we denote by A* *M*

(*z*) *the following procedure:*
*1.Initialize* tr : *X ⇀ Y to be undefined everywhere.*
*2. (Continue to) run A (on input z) until it makes an oracle query x or terminates. If A terminates, then stop* *and return A’s output.*
*3. If A has not terminated, first check if x ∈* supp(tr)*; if so, then set y* := tr(*x*)*. Otherwise, compute* *y ←M*(tr*,x*) *and add the mapping x 7→ y to* tr*.*
*4.Answer A’s query with y and go to Step 2.* *We refer to M as a* **stateful oracle algorithm***.* Note that *M* is not *itself* stateful, but oracle answers are sampled in a stateful way (i.e., by storing prior queries and answers in tr). **Definition 5.2.** *Let O be an oracle distribution supported on tuples of oracles* (*θ₁,...,θν*) *for some ν ∈* N*,* *let S ⊆* [*ν*] *and let ε*: N *→* [0*,*1]*. Then, a* **stateful** (*O,S*)**-emulator with error** *ε is a stateful oracle* *algorithm M such that for every t ∈* N *and probabilistic t-query adversary A:*
h i h *θ* i *θ M S*¯ Pr *A* = 1 *θ ←O −* Pr *A* = 1 *θ ←O ≤ ε*(*t*)*.*

*Moreover, we say that M is* **pass-through** *if it answers queries to θifor any i ∈ S*¯ *by querying θiand* *returning the answer. A* **stateful** *O***-emulator** *is a stateful* (*O,*[*ν*])*-emulator.*

Prior to stating our main theorem, we first introduce the definition of votr, which is a function encoding the view of vob that is known, given only the ro queries in an ARO query-answer transcript.

**Definition 5.3.** *Let X* := ARO[*F,m,d*]*, let O∈X, let* (ro*,*wo*,*vob) *←O*(*λ*) *and let* tr *be an O*(*λ*)*-query-* *answer transcript. We define* votr: *{*0*,*1*}* *m*+*λ*+*w* *→{*0*,*1*} as follows:* ( 1 *if* tr*|*ro(*x*) = *y and* wo(*x*) = *z* votr(*x,y,z*) :=*.* 0 *otherwise*

Now, we state the main theorem of this section.

**Theorem 5.4.** *Let* F *be a finite field, m ∈* N *be an arity parameter, λ ∈* N *be a security parameter,* *d ∈* N *be a degree parameter with d ≥* 2*, and B*: *{*0*,*1*}* *m*+*r* *→ {*0*,*1*}* *w* *be an oracle circuit. Let* (ro*,*wo) *O*(*λ*) := ARO[F*,m,λ,d,B*]*. Then M* ARO *in Construction 5.11 is a pass-through stateful* (*O*(*λ*)*, {*vob*}*)*-* *emulator with error* 2 <u>t</u> *λ. In fact, for every t*vob*∈* N *and probabilistic adversary A that makes at most t*vob *queries to* vob*,* h i h (ro*,*wo) i <u>t</u> (ro*,*wo*,*vob) *M*ARO<u>vob</u> Pr *A* = 1 (ro*,*wo*,*vob) *←O*(*λ*) *−* Pr *A* = 1 (ro*,*wo*,*vob) *←O*(*λ*) *≤* *λ* *.* 2

(ro*,*wo) *M* ARO *additionally satisfies the following properties:*

- ***Output distribution.** For every O-query-answer transcript* tr*, x ∈{*0*,*1*}*
*m*+*λ*+*w* *and y ∈* F *we have that* h i (ro*,*wo) *′*

|Pr|M|b ,x)) = (tr ,y)|[vo ∪ tr||])],|
|---|---|---|---|---|
|(ro,wo,vo b)←O|ARO||tr|vo b|
|′|(ro,wo)|tr|(ro,wo)||
|(ro,wo) ARO|ARO ARO|2t|ARO|(ro,wo)|
|||||ARO|
||2t||||

ARO (tr*,*(vo = Pr [*P* (*x*) = *y | P ←U* (LDEF*,d* tr vob (ro*,*wo*,*vob)*←O*

*where* tr := tr *∪{*(vob*,x,y*)*} and* vo *is defined as in Definition 5.3.*

- ***Efficiency.** M runs in time* poly(*m,λ,w,d,t,* log*|*F*|*)*. For each oracle query M emulates,* *M makes at most 1 oracle query.* We often write *ε* (*t,λ*) :=*λ*to refer to the above error. We will abuse notation and refer to such an emulator as a pass-through stateful (ARO, vob)-emulator. Throughout this section, we assume without loss of generality that any adversary that queries ro on input *x* also queries wo with *x*. The proof that *M* has *emulation error* at most*λ*proceeds via a sequence of hybrids. The remainder of this section is broken up as follows.
- In Section 5.1, we construct an inefficient perfect emulator *M*LDfor low-degree extensions of any function defined over the boolean hypercube.
(ro*,*wo) •In Section 5.2, we construct an *efficient* pass-through stateful (ARO*,*vob)-emulator *M* ARO.

- In Section 5.3 we prove Theorem 5.4. In order to do so, we use *M*LDto obtain an inefficient perfect
(ro*,*wo) (ro*,*wo) emulator for the ARO, *M* ARO*∗*, and prove it is statistically close to *M* ARO. (ro*,*wo) •In Section 5.4, we give efficient implementations of certain subroutines used by *M* ARO.

### 5.1 Inefficient stateful emulator for low-degree extensions

We describe a stateful emulator algorithm for low-degree extensions and prove that the emulation is perfect. Our analysis uses tools from algebraic query complexity; specifically the proof of [AW09, Lemma 4.5] inspired the “shift” polynomial used in our analysis.

**Lemma 5.5.** *Let n,d ∈* N *with d ≥* 2*. Let M*LD*be the stateful oracle algorithm in Construction 5.9. Then* *for every f* : *{*0*,*1*}* *n* *→* F *and adversary A:* h i h *f* i ˆ*M*LD

||fˆ|F,d|
|---|---|---|
|f|||
|LD|F,d||

Pr *A* = 1 *f ←U* (LDE [*f*]) = Pr *A* = 1;

*i.e., M is a stateful U* (LDE [*f*])*-emulator.* Before giving our construction of a stateful emulator for low-degree extensions, we define some notions required for its description.

|n|n t|F,d|
|---|---|---|
|n|||
|||n|
 **Definition 5.6.** *Let f* : *{*0*,*1*} →* F *and let* tr *∈* (F *×* F) *be an* LDE [*f*]*-query-answer transcript. Then* *we define* (*f ∪* tr) : *{*0*,*1*} ∪* supp(tr) *→* F *by*
( *f* (*x*) *if x ∈{*0*,*1*}* (*f ∪* tr)(*x*) :=*.* tr(*x*) *otherwise*

|||n|n t|
|---|---|---|---|
|w,X ≤2|n||w,X|
||w,X|||

**Definition 5.7.** *Given a point w ∈ {*0*,*1*} and a query set* X *∈* (F)*, let* Q*w,*X*be the set containing* *polynomials Q ∈* F [*X₁,...,X*] *such that: (i) Qw,*X(*w*) = 1*; (ii) Q* (*x*) = 0 *for every x ∈{*0*,*1*}* *n* *such that x ̸*= *w; and (iii) Q* (*x*) = 0 *if x ∈* X*.*

**Definition 5.8.** *Given a query set* X *∈* (F *n* ) *t* *, define the set*

BADX:= *{w ∈{*0*,*1*}* *n* *|* Q*w,*X*is empty}.*

*n f* **Construction 5.9.** For a given *f* : *{*0*,*1*} →{*0*,*1*}*, the emulator *M* LD takes input (*n,d,* tr*,x*) and works as follows. P

1.Set *P* (*X⃗*) :=
*b∈*BADsupp(tr)*∪{x}* *f* (*b*) *· δb*(*X⃗*).

2.Define tr*s*:= *{*(*x,y − P*(*x*)) : (*x,y*) *∈* tr*}*.
3.Sample *Z*ˆ *←* LDEF*,d*[*Z ∪* tr*s*], where *Z* : *{*0*,*1*}*
*n* *→{*0*,*1*}* is the zero function.

4.Output *y* := *Z*ˆ(*x*) + *P* (*x*). Before proving Lemma 5.5, we first prove a useful claim.
**Claim 5.10.** *Let Z*: *{*0*,*1*}* *n* *→{*0*,*1*} be the zero function and let h*: *{*0*,*1*}* *n* *→* F*be arbitrary. Let* tr *Z* ˆ*,*tr*h*ˆ*∈* (F *n* *×* F) *t* *be a* LDEF*,d*[*Z*]*-query-answer transcript and a* LDEF*,d*[*h*]*-query-answer transcript respectively,* *such that* supp(tr *Z* ˆ) = supp(tr*h*ˆ)*. Let Z* ˆ *←U* LDE F*,d*[*Z ∪* tr*Z*ˆ]*, and let h* ˆ *∈* LDE F*,d*[*h ∪* tr*h*ˆ]*. Then Z* ˆ +*h*ˆ

*is distributed as U* LDEF*,d*[*h ∪* tr *Z* ˆ+*h*ˆ]*, where* tr*Z*ˆ+*h*ˆ:= *{*(*x,yZ*ˆ+ *yh*ˆ) : (*x,yZ*ˆ) *∈* tr*Z*ˆ*,* (*x,yh*ˆ) *∈* tr*h*ˆ*}.*

*Proof.* Consider the bijective affine map *T* *h* ˆon F *≤d* [*X₁,...,Xn*] defined by *T* *h* ˆ(*Z* ˆ) := *Z*ˆ + *h*ˆ. We show that

*T* *h* ˆ(LDEF*,d*[*Z ∪*tr*Z*ˆ]) = LDEF*,d*[*h∪*tr*Z*ˆ+*h*ˆ]. For any *x ∈* supp(tr*Z*ˆ) we have that (*Z* ˆ+*h*ˆ)(*x*) = *y* *Z* ˆ+*yh*ˆ, where (*x,y* *Z* ˆ) *∈* tr*Z*ˆand (*x,yh*ˆ) *∈* tr*h*ˆ. Thus, for (*x,yZ*ˆ+*h*ˆ) *∈* tr*Z*ˆ+*h*ˆ, we have (*Z* ˆ + *h*ˆ)(*x*) = *y*. Further, for any

*x ∈{*0*,*1*}* *n*, (*Z*ˆ +*h*ˆ)(*x*) = *h*ˆ(*x*) = *h*(*x*). Hence, for any *Z*ˆ *∈* LDEF*,d*[*Z ∪*tr *Z* ˆ], *Th*ˆ(*Z* ˆ) *∈* LDE F*,d*[*h ∪*tr*Z*ˆ+*h*ˆ]. As *Z* is uniformly random in LDEF*,d*[*Z ∪* tr *Z* ˆ] and *Th*ˆis a bijection between LDEF*,d*[*Z ∪* tr*Z*ˆ] and

|LDE [h ∪ tr|], we have that T||(Zˆ) = Zˆ + h|ˆ is uniformly random in LDE||[h ∪ tr|].||
|---|---|---|---|---|---|---|---|---|
|F,d n|Z ˆ+h ˆ||h ˆ|F,d||F,d|Z ˆ+h ˆ i i ti=1|n t|
|||||F,d||f LD|||

F*,d* ˆ+*h*ˆ ˆ F*,d* ˆ+*h*ˆ

*Proof of Lemma 5.5.* We show that for all LDE [*f*]-query-answer transcripts, tr = [(*x,y*)] *∈* (F *×*F), *x ∈* F and *y ∈* F, we have that h i h i ˆ( ˆ Pr *f x*) = *y f ←U* (LDE [*f ∪* tr]) = Pr *M* (tr*,x*) = *y.* (4)

We will obtain Eq. 4 in three steps.

1. We show that the set LDEF*,d*[*Z ∪* tr*s*] is non-empty provided that LDEF*,d*[*f ∪* tr] is non-empty, which ensures that Step 3 of Construction 5.9 does not fail.
2. Note that the output of *M*LDis determined by the polynomial *M* (*X⃗*) := *Z*ˆ(*X⃗*) + *P* (*X⃗*), which is computed in Step 4 of Construction 5.9. We show that *M* (*X⃗*) is distributed like *U* (LDEF*,d*[*g ∪* tr]), for a function *g* : *{*0*,*1*}*
*n* *→* F defined below.

3. We demonstrate that evaluations of polynomials distributed like *U* (LDEF*,d*[*g ∪* tr]) are perfectly indistin- guishable from evaluations of polynomials distributed like *U* (LDEF*,d*[*f ∪* tr]). **Step 1.** We show that LDEF*,d*[*Z ∪* tr*s*] is non-empty if LDEF*,d*[*f ∪* tr] is non-empty. As in Step 1 of
P Construction 5.9, let *P* (*X⃗*) := *b∈*BADsupp(tr)*∪{x}* *f* (*b*) *· δb*(*X⃗*). Then we have that *f*ˆ(*X⃗*) *− P*(*X⃗*) *∈* LDEF*,d*[*h ∪* tr*s*], where *h* : *{*0*,*1*}* *n* *→* F is defined by ( 0 if *x ∈* BADsupp(tr)*∪{x}* *h*(*x*) =*,* *f* (*x*) otherwise

and tr is as defined in Step 2 of Construction 5.9. By definition of BAD, for each *w ∈*

|s||||supp(tr)∪{x}|
|---|---|---|---|---|
|n|supp(tr)∪{x}|w,supp(tr)∪{x}|||
|w|supp(tr)∪{x}||w∈{0,1}|w|
||n|F,d|s||

*{*0*,*1*} \* BAD, the set Q is non-empty; for each *w*, choose an arbitrary element P *Q ∈* BAD. Let *S₁*(*X⃗*) := *n* *\*BADsupp(tr)*∪{x}* *f* (*w*) *· Q* (*X⃗*). It is easily verified that *S₁* has the following properties: (i) *S₁*(*x*) = 0 for all *x ∈* supp(tr); (ii) *S₁*(*w*) = *f* (*w*) for all *w ∈ {*0*,*1*} \* BADsupp(tr)*∪{x}*, and (iii) *S₁*(*b*) = 0 for all *b ∈* BADsupp(tr)*∪{x}*. Thus, the polynomial *f* ˆ(*X⃗*) *− P*(*X⃗*) *− S₁*(*X⃗*) *∈* LDE [*Z ∪* tr], as desired.

**Step 2.** Define ( *f* (*x*) if *x ∈* BADsupp(tr)*∪{x}* *g*(*x*) = 0 otherwise.

|⃗ ) is U (LDE|[g ∪ tr]).||
|---|---|---|
||F,d||
|F,1 P|P|P|
|||F,d s|
|s+P||F,d|

We show that the distribution of *M* (*X* By definition, *P* (*X⃗*) *∈* LDE [*g ∪* tr], where tr is defined by tr = *{*(*x,P*(*x*)) : *x ∈* supp(tr)*}*. Thus, by Claim 5.10, as *M* (*X⃗*) = *Z*ˆ(*X⃗*) + *P* (*X⃗*) and *Z*ˆ(*X⃗*) *←* LDE [*Z ∪* tr], we have that *M* (*X⃗*) *←* LDEF*,d*[*g ∪* tr*s*+*P*]. However, tr = tr, so *M* (*X⃗*) is distributed like *U* (LDE [*g ∪* tr]). In particular, h i *f* Pr *M* LD (tr*,x*) = *y* = Pr [ˆ*g*(*x*) = *y | g*ˆ *←U* (LDEF*,d*[*g ∪* tr])]*.*

P **Step 3.** Consider another “shift” polynomial *S₂*(*X⃗*) = *w∈{*0*,*1*}n\*BADsupp(tr)*∪{x}* (*f* (*w*) *− g*(*w*))*Qw*(*X⃗*). *S₂* has the property that if *g*ˆ *∈* LDEF*,d*[*g ∪* tr], then *g*ˆ + *S₂ ∈* LDEF*,d*[*f ∪* tr]. Further, *S₂*(*x*) = 0. Hence the map *g*ˆ *→ g*ˆ + *S₂* is a bijection between the sets n o *f* ˆ *∈* LDE F*,d*[*f ∪* tr] : *f* ˆ(*x*) = *y*

and *{g*ˆ *∈* LDEF*,d*[*g ∪* tr] : ˆ*g*(*x*) = *y}.*

Thus, we have that h i Pr *f*ˆ(*x*) = *y f*ˆ*←U* (LDEF*,d*[*f ∪* tr]) = Pr [ˆ*g*(*x*) = *y | g*ˆ *←U* (LDEF*,d*[*g ∪* tr])]*,*

### which yields the result.

### 5.2 Stateful emulator for the ARO

We present the stateful emulator algorithm for the ARO. For the purpose of making an identical-until-bad argument (see Section 3.9) in our analysis, we include the setting of a bad flag in this construction. This is not required for the emulator to function.

**Construction 5.11.** We define a pass-through stateful (ARO[F*,m,λ,d,B*]*, {*vob*}*)-emulator as follows:

(ro*,*wo)

- *Query M*
ARO *with parameters* (F*,m,λ,w,d*) *and with input* (tr*,*(oid*,x*)).

**–** If oid = ro, output *y* := ro(*x*). **–** If oid = wo, output *y* := wo(*x*). **–** If oid = vob :

1.Compute the set *V* := *{*(*x,y,z*) : (*x,y*) *∈* tr*|*ro*∧* (*x,z*) *∈* tr*|*wo*}*.
P

2.Set *P* (*X⃗*) := *δb*(*X⃗*).
*b∈V*

3.If the set *B* := *{b ∈* BADsupp(tr*|\ V* : vo(*b*) *̸*= 0*}* is non-empty, set the bad flag.

|supp(tr||)∪{x}|||
|---|---|---|---|
|vo b||s|vo b|
|F,d|s|m+λ+w||

vob)*∪{x}*

4.For each *x ∈* supp(tr*|*), compute *P* (*x*) and set tr := *{*(*x,y − P*(*x*)) : (*x,y*) *∈* tr*|}*.
5.Sample *Z*ˆ *←* LDE [*Z ∪* tr], where *Z* : *{*0*,*1*} →{*0*,*1*}* is the zero function.
6.Output *y* := *Z*ˆ(*x*) + *P* (*x*).
**Remark 5.12.** We obtain an efficient implementation of Construction 5.11 by using the ZSampleF*,m*+*λ*+*w,d* algorithm (Construction 5.20) in Step 5 and Step 6.

### 5.3 Proof of Theorem 5.4

It is clear that the answers to ro and wo queries are indistinguishable. Hence, we focus on proving the indistinguishability of answers to vob queries. We use a hybrid argument with the following hybrids.

- **H₀**: *A* queries (ro*,*wo*,*vob).
vo

- **H₁**: *A* queries (ro*,*wo*, M*), the emulator described in Construction 5.9.
LD (ro*,*wo)

- **H₂**: *A* queries *M*, the emulator described in Construction 5.13, below.
ARO*∗* (ro*,*wo)

- **H₃**: *A* queries *M*, the emulator described in Construction 5.11.
ARO

For every *O*-query-answer transcript tr, let tr*<ℓ*denote the queries in tr up to and *excluding* the *ℓ*-th *ℓi−*1 query, i.e. tr*<ℓ*:= [(oid*i,xi,yi*)]. =1

**Construction 5.13.** We specify an inefficient hybrid stateful emulator for the ARO, which runs based on the stateful emulator for random low-degree extension (Construction 5.9).

(ro*,*wo)

- *Query M with parameters* (F*,m,λ,w,d*) *and with input* (tr*,*(oid*,x*)).
ARO*∗*

**–** If oid = ro, output *y* := ro(*x*). **–** If oid = wo, output *y* := wo(*x*). **–** If oid = vob :

1.Compute the set *V* := *{*(*x,y,z*) : (*x,y*) *∈* tr*|*ro*∧* (*x,z*) *∈* tr*|*wo*}*.
P

2.Set *P* (*X⃗*) := *δb*(*X⃗*).
*b∈V*

3. If the set *B* := *{b ∈* BADsupp(tr*|\ V* : vo(*b*) *̸*= 0*}* is non-empty, set the bad flag and
vob)*∪{x}* update: X

|⃗ ) := P (X P (X|⃗ ) + vo(b) · δ||
|---|---|---|
||b∈B||
|vo b|s|vo b|
|F,d s|m+λ+w||

*b*(*X⃗*)*.* *b∈B*

4.For each *x ∈* supp(tr*|*), compute *P* (*x*) and set tr := *{*(*x,y − P*(*x*)) : (*x,y*) *∈* tr*|}*.
5.Sample *Z*ˆ *←* LDE [*Z ∪* tr], where *Z* : *{*0*,*1*} →{*0*,*1*}* is the zero function.
6.Output *y* := *Z*ˆ(*x*) + *P* (*x*).
**H₀ vs. H₁. H₀** and **H₁** are perfectly indistinguishable by Lemma 5.5.

**H₁ vs. H₂.** We show that **H₁** and **H₂** are perfectly indistinguishable. We do this by showing that for all *O*-query-answer transcripts tr, *x ∈* F *m* and *y ∈* F we have h i vo (ro*,*wo) Pr [*M*LD(tr*|*vob*,x*) = *y*] = Pr *M* ARO*∗* (tr*,x*) = *y.*

In both experiments *y* is sampled as *Z*ˆ(*x*)+*P* (*x*) where *Z*ˆ *←* LDEF*,d*[*Z ∪*tr*s*], but where *P* is constructed differently in each experiment. We show that *P* is in fact the same polynomial in both experiments, from P P which the claim follows. In Construction 5.13, we have *P* (*X⃗*) := *b∈V* *δ* *b* (*X⃗*) + *b∈B* vo(*b*)*δb*(*X⃗*). But P P vo(*b*) = 1 for all *b ∈ V*. Thus *P* (*X⃗*) = *b∈B∪V* vo(*b*)*δb*= *b∈*BADsupp(tr*|*)*∪{x}* vo(*b*)*δb*(*X⃗*), which is vob precisely how *P* (*X⃗*) is constructed by *M* vo LD. (Note that tr in *M* vo LD is an LDEF*,d*[vo]-query-answer transcript.) **H₂ vs. H₃.** We show that *t*-query adversary *A* distinguishes between **H₂** and **H₃** with probability *ε ≤* 2 *t* *λ*. (ro*,*wo) (ro*,*wo) We do this by showing that *M* ARO*∗* and *M* ARO are identical-until-bad (Section 3.9). Then we argue that <u>t</u> <u>vob</u> the probability that the bad flag is set in either construction is at most 2 *λ*, where *t*vob*≤ t* is the total number of queries made to the verification oracle. (ro*,*wo) (ro*,*wo) **Claim 5.14.** *M* ARO*∗* *and M* ARO *are identical-until-bad.*

(ro*,*wo) (ro*,*wo) *Proof. M* ARO*∗* and *M* ARO are syntactically identical until the bad flag is set.

(ro*,*wo) (ro*,*wo) Since*M* ARO*∗* and*M* ARO are identical-until-bad, the fundamental lemma of game playing (Lemma 3.13) states that h (ro*,*wo) i h (ro*,*wo) i Pr *A* *M*ARO = 1 *−* Pr *A* *M* ARO*∗*= 1 h i (ro*,*wo) *≤* Pr the bad flag is raised by *M* ARO *.*

Next we bound the probability that the bad flag is raised within *t* queries. First observe that the bad flag is only ever raised when oid = vob. Let *Ei*be the event that the bad flag is raised on the *i*-th query to the verification oracle, and let *Bi* be the set defined in Step 3 of Construction 5.13, on the *i*-th query. Further, define BAD₁ := *B₁* and BAD*i*:= *Bi\ Bi−*1for *i ∈{*2*,...t*vob*}*. Then by a union bound over the points in BAD*i*we have

X Pr[*Ei*] *≤ /* tr*<i*]

||Pr [ro(x|) = y|| (ro,x|, ro(x )) ∈|
|---|---|---|---|---|
|(x ,y ,z)∈BAD i λ|b b|b b|b i|b b|
|b|b|b|<i|λ|
||||vo b||

*b b b i* <u>|BAD |</u> *≤,* 2

where we use the fact that for every *b* := (*x,y,z*) *∈* BAD, we have that

<u>1</u> Pr [ro(*x*) = *y |* (ro*,x*) *∈/* supp(tr)] =*.* 2

To conclude, we upper bound *A*’s overall advantage over *t* queries to vob.

    [ X [ Pr  *Ei* = Pr  *Ei|*BAD*j|* = *sj∀j ∈* [*t*vob] Pr [*|*BAD*j|* = *sj∀j ∈* [*t*vob]] *i∈*[*t*vob] *s,...,st*vob*∈*N *i∈*[*t*vob]

  X [

|=|Pr |E|] Pr [|BAD|]]|
|---|---|---|---|---|
|Ps ,...,s|∈N s ≤t|i∈[t]|||

*i|*BAD*j|* = *sj∀j ∈* [*t*vob *j|* = *sj∀j ∈* [*t*vob 1 *,...,st* vob *∈*N *i∈*[*t*vob] *k∈*[*t*vob] *k* vob   X X

|≤||Pr [E|||BAD|| = s|∀j ∈ [t|]] Pr [|BAD||| = s ∀j ∈ [t|]]|
|---|---|---|---|---|---|---|---|---|---|
||||i|j|j|vo b||j j|vo b|
|Ps ,...,s|∈N s ≤t|i∈[t] i λ||j|j|vo b|vo b λ|||
|Ps ,...,s vo b|∈N s ≤t|i∈[t]||||||i∈[t] m+λ+w|i|

1 *t*vob vob *k∈*[*t*vob] *k* vob   X X <u>s t</u>   Pr [ *≤ |*BAD *|* = *s ∀j ∈* [*t*]] *≤.* 2 2 1 *t*vob vob *k∈*[*t*vob] *k* vob P The equality in the second line follows from [AW09, Lemma 4.3], which states that vob *|*BAD *|* = *|*BADsupp(tr*|* vob) *|≤ t*. **Output distribution.** Finally, we show that for every *O*-query-answer transcript tr, *x ∈{*0*,*1*}* and *y ∈* F we have that h i (ro*,*wo) *′* Pr [*P* (*x*) = *y | P ←U* (LDEF*,d*[votr*∪* tr*|*vob])] = Pr *M* ARO (tr*,*(vob*,x*)) = (tr*,y*)*.* (ro*,*wo*,*vob)*←O*

The output of Construction 5.11 is determined by the polynomial *M* (*X⃗*) := *Z*ˆ(*X⃗*) + *P* (*X⃗*). We show that the distribution of *M* (*X⃗*) is *U*(LDEF*,d*[votr*∪* tr*|*vob]). By definition, *P* (*X⃗*) *∈* LDEF*,*1[votr*∪* tr*P*], where tr*P*:= *{*(*x,P*(*x*) : *x ∈* supp(tr)*}*. Also, *Z*ˆ(*X⃗*) *←*

|[Z ∪ tr|], where tr|:= {(x,y − P (x)) : (x,y) ∈ tr}. Thus by Claim 5.10, M (X||||[vo|∪|
|---|---|---|---|---|---|---|---|
|F,d|s|s||||F,d|tr|
|P +S|P +S|(ro,wo) ARO||||vo b||
||||F,d|||||
|(ro,wo)|||||(ro,wo)|||
|ARO|||||ARO|||

LDEF*,d s s⃗*) *←* LDEF*,d* tr tr]. But tr = tr, which yields the result. *⃗* **Efficiency.** Running *M ∗* requires computing *P* (*X*) at all of the points in the set supp(tr*|*) which takes time *O*(*t*) and running ZSample which takes time poly(*m,λ,w,d,* log(*|*F*|*)*,t*) by Lemma 5.21. Thus *M* runs in time poly(*m,λ,w,d,* log(*|*F*|*)*,t*). Finally, *M* makes at most one query to (ro*,*wo) for every query it receives, so its query complexity is *O*(*t*).

### 5.4 Efficiently implementing Construction 5.11

We describe the subroutines used to efficiently implement the ARO stateful emulator in Construction 5.11.

### 5.4.1 Efficiently sampling a random low-degree polynomial

We describe LDSample F*,m,⃗d*, a stateful oracle that samples evaluations of a random low-degree polynomial *≤d⃗* in F [*X₁,...,Xm*].

**Lemma 5.15.** *Let* F *be a field, let m,t ∈* N*,⃗d ∈* N *m* *and let* LDSample F*,m,⃗d* *be the algorithm described in* *Construction 5.16. Then for all* tr *∈* (F *m* *×* F) *t* *, for which* LDE F*,⃗d* [tr] *̸*= *∅, and for all x ∈* F *m* *,y ∈* F*:* h i h i Pr LDSample F*,m,⃗d* (tr*,x*) = (tr *′* *,y*) = Pr *P* (*x*) = *y P* (*X⃗*) *←* LDE F*,⃗d* [tr]*,*

*where* tr *′* := tr *∪{*(*x,y*)*}. Moreover,* LDSample F*,m,⃗d* *runs in time* poly(*m,d,* log*|*F*|,t*)*, where t* = *|*tr*|.*

**Construction 5.16.** Given a constraint detector CD F*,m,⃗d* for LD[F*,m,⃗d*] (Definition 3.10) the algorithm LDSample F*,m,⃗d* operates as follows.

- *Evaluate polynomial:* LDSample
F*,m,⃗d* (tr*,x*) *→ y*.

1.Run CD F*,m,⃗d*
(supp(tr) *∪{x}*):

(a) If CD F*,m,⃗d*
outputs a constraint *z* for which *z*(*x*) *̸*= 0, compute *y* such that (*x,y*) that is <u>1</u> P

||1||′ ′|
|---|---|---|---|
||z(x)|(x ,y)∈tr||
|F,m,⃗d||k||

*′ ′* consistent with *z*; i.e., *y* := *− ′ ′ z*(*x*)*y*.

(b)If CD outputs *⊥* or a basis *z₁,...,z* where *z*(*x*) = 0 for all *i ∈* [*k*], sample *y ←* F.
2.Output *y*.
*Proof of Lemma 5.15.* Follows from Lemma 4.3 of [BCFGRS17].

*Proof.* This algorithm appears in appendix B of [BCFGRS17], and its correctness and efficiency are argued in Lemma 4.3 of [BCGRS17].

### 5.4.2 Efficiently sampling a RLDE of the boolean zero function

We first give an inefficient subroutine (Construction 5.18) that samples evaluations of a uniformly random low- degree extension of the boolean zero function conditioned on a set of preprogrammed points in Lemma 5.17 and prove its correctness. Subsequently, in Construction 5.20 we give an efficient stateful algorithm that realizes Lemma 5.17 in polynomial time, based on succinct constraint detection. Throughout the following, given an arity *m ∈* N and a degree parameter *d ≥* 2 *∈* N we denote
*d⃗i*:= (*d,...,d −* 2*,...,d*) *∈* N
*m* to be the vector which takes the value *d −* 2 at its *i*-th entry, and the value *d* everywhere else.

**Lemma 5.17.** *Let* F *be a field, let m,d,t ∈* N*, let* ZSampleF*,m,dbe the algorithm described in Construc-* *tion 5.18 and let Z*: *{*0*,*1*}* *m* *→{*0*,*1*} denote the zero function. Then for all* tr *∈* (F *m* *×* F) *t* *which agree* *with Z and are such that* LDEF*,d*[*Z ∪* tr] *̸*= *∅, and for all x ∈* F *m* *,y ∈* F*:* h i h i Pr ZSample F*,m,⃗d* (tr*,x*) = (tr *′* *,y*) = Pr *P* (*x*) = *y P* (*X⃗*) *←* LDE F*,⃗d* [*Z ∪* tr]*,*

*where* tr *′* := tr *∪{*(*x,y*)*}.*

**Construction 5.18.** ZSampleF*,m,d*(tr*,x* *∗* ).

1.Define the set
n *S*tr:= (tr₁*,...,* tr*m*) *∈* (supp(tr) *→* F) *m* : *∀i ∈* [*m*]*,* LDE F*,d⃗* [tr*i*] *̸*= *∅* *i* X *m*o *∧ ∀*(*x,y*) *∈* tr*,.*

||||x (x − 1)tr|(x) = y|
|---|---|---|---|---|
||||i i|i|
|||i=1|||
|m|tr||||
||i||||

2.Sample (tr₁*,...,* tr) *←U*(*S*).
3.For each *i ∈* [*m*] sample *R* (*X⃗*) *←* LDE
F*,d⃗* [tr*i*]. *i*

P *m ∗ ∗ ∗*

4.Output *y* :=
<u>i=1</u> *x* *i* (*x* *i* *−* 1)*Ri*(*x*).

We will require the following simple, but useful claim.

**Claim 5.19.** *Let* F *be a field, m ∈* N*, ⃗d* := (*d₁,...,dm*) *∈* N *m* *and S ⊆* F *m* *. Let f* : *S →* F *and g*: *S →* F *be such that* LDE F*,⃗d* [*f*] *and* LDE F*,⃗d* [*g*] *are non-empty. Then |*LDE F*,⃗d* [*f*]*|* = *|*LDE F*,⃗d* [*g*]*|.*

*Proof.* Fix some *f*ˆ *∈* LDE F*,⃗d* [*f*], *g*ˆ *∈* LDE F*,⃗d* [*g*]. Let *T* (*P*) := *P − f*ˆ + ˆ*g*, and observe that *T* is a bijection between LDE F*,⃗d* [*f*] and LDE F*,⃗d* [*g*].

*Proof of Lemma 5.17.* Denote *D₀* := *U*(LDEF*,d*[*Z ∪* tr]). Define () (tr₁*,...,* tr*m*) *←U*(*S*tr) *DZ*:= (*R₁*(*X⃗*)*,...,Rm*(*X⃗*)) *⃗* *.* *Ri*(*X*) *←* LDE F*,d⃗* [tr*i*] *∀i ∈* [*m*] *i*

Observe that the distribution of polynomials sampled by Step 3 of ZSampleF*,m,d*(tr) is *DZ*. P *m* Let Φ(*R₁*(*X⃗*)*,...,Rm*(*X⃗*)) := *i*=1 *Xi*(*Xi−* 1)*Ri*. We introduce a hybrid distribution, as follows

n Y*m*o *⃗≤d* *⃗* *i ⃗* *R*tr:= *R ∈* F [*X₁,...,Xm*] : (Φ(*R*))(*x*) = *y ∀* (*x,y*) *∈* tr*,* *i*=1

and define the hybrid *DCN*to be the uniform distribution over the set *R*tr. The proof proceeds in two steps: first we show that *DZ*is identical to *DCN*. Second, we use the combinatorial nullstellensatz [Alo99] to show that if *R⃗ ∼U*(*R*tr) then Φ(*R⃗*) *∼U*(LDEF*,d*[*Z ∪* tr]).

*DZ***vs.** *DCN***:** The distribution *DCN*is defined as the uniform distribution over *R*trso Pr[*R⃗ ←DCN*] = <u>1</u>. We show that Pr[*R⃗ ←D*] = <u>1</u>. *|R*tr*| Z |R*tr*|* The set *S*trpartitions *R*trinto a disjoint union of sets, each of the same cardinality. In particular, for tr *⃗ ∈ S* trdenote n o *T* tr *⃗*:= (*R₁*(*X* *⃗*)*,...,R* *m*(*X* *⃗*)) : *R* *i* (*X⃗*) *∈* LDE F*,d⃗* [tr*i*] *∀i ∈* [*m*]*,* *i*

then we have that [ *T* tr *⃗*= supp(*DZ*) = *R*tr*.* tr *⃗ ∈S*tr

|⃗ ̸= tr|⃗, T ∩ T|= ∅. Moreover, by definition of S||, LDE|[tr] ̸= ∅ for each i ∈ [m],||||
|---|---|---|---|---|---|---|---|---|
||′ tr ⃗ tr ⃗|tr ⃗||tr tr|F,d⃗ i |R tr ⃗ |S|| |||tr|
|tr|Z||⃗r∗ tr||||tr ⃗||
|tr ⃗ tr ⃗|||tr ⃗|Z|tr ⃗||S1 |||tr|

### Observe that for tr ′

*i* *⃗ ∈ S*<u>tr</u>*⃗ ∈ S* so by Claim 5.19, every *T* is of the same cardinality for any tr. Thus *|T |* = tr for all tr. Let *⃗r ∈ R*, let *R⃗ ←D*, and let tr*⃗ ∈ S* be uniquely defined to be such that *⃗r ∈ T ∗*. For each *⃗r* tr *⃗ ∈ S* tr, let *E* be the event that *R* *⃗ ∈ T*. Note that by definition of *D*, Pr[*E*] = tr for all tr*⃗ ∈ S*. Conditioning on *E*, we have

h i X h i

|= Pr|= ⃗r E|Pr [E]|
|---|---|---|
|tr ⃗ ∈S|tr ⃗|tr ⃗|

Pr *R⃗* =*⃗r R⃗* tr *⃗* tr*⃗* tr *⃗ ∈S*tr h i h i = Pr *R⃗* =*⃗r E ∗* Pr *E ∗* *⃗r ⃗r*

<u>1</u> = *|T* tr *⃗∗||S*tr*|* *⃗r* <u>1</u> =*,* *|R*tr*|* h i where the second and third equalities follow from the fact that Pr *R⃗* =*⃗r E* tr *⃗*=*|T* <u>1</u> *|* if tr*⃗* = tr*⃗* *⃗r∗* and is 0 *⃗* tr otherwise. *DCN***vs.** *D₀***.** We show that Φ(*R⃗*) for *R ←DCN*is distributed as *D₀* = *U*(LDEF*,d*[*Z ∪* tr]). Note that Φ is a linear map, and *R*tris an affine space, so by Claim 3.2, if *R⃗ ∼DCN*then Φ(*R⃗*) *∼* *U*(Φ(*R*tr)). It remains to show that Φ(*R*tr) = LDEF*,d*[*Z ∪* tr]. First, we show that Φ(*R*tr) *⊆* LDEF*,d*[*Z ∪* tr]: fix *R⃗ ∈ R*tr; then since im(Φ) *⊆* LDEF*,d*[*Z*] and (Φ(*R⃗*))(*x*) = *y ∀* (*x,y*) *∈* tr, Φ(*R⃗*) *∈* LDEF*,d*[*Z ∪* tr]. Finally we show that LDEF*,d*[*Z ∪*tr] *⊆* Φ(*R*tr), which completes the proof. Fix some *Z*ˆ *∈* LDEF*,d*[*Z ∪*tr]. Since LDEF*,d*[*Z ∪* tr] *⊆* LDEF*,d*[*Z*], by Lemma 3.3, there exist polynomials *R₁,...,Rm*where *Ri∈* *≤d⃗i*

|F [X₁,...,X|] such that Zˆ = Φ(R₁,...,R|||). Then for all (x,y) ∈ tr, Φ(R₁,...,R||)(x) = Zˆ(x) =|
|---|---|---|---|---|---|---|
|≤d⃗|m tr||tr|m||m|

*y*. Hence *R⃗ ∈ R*, and so *Z*ˆ *∈* Φ(*R*). **Construction 5.20.** Given a constraint detector CD
F*,m,⃗d* for LD[F*,m,⃗d*] (Definition 3.10), we efficiently implement ZSampleF*,m,d*as a stateful oracle for *d ≥* 2 as follows:

- *Evaluate polynomial:* ZSampleF*,m,d*(tr*,x*
*∗* ) *→ y*.

1.If tr = *∅*:
(a)For each *i ∈* [*m*], set tr*i*:= *∅*.
2.If tr *̸*= *∅*:
(a)For each *i ∈* [*m*], run CD
F*,m,d⃗* (supp(tr)) to obtain constraints *zi,j*for *j ∈* [*k*]. *i*

(b)Using Gaussian elimination, solve the following linear system of constraints
X *,*

||z|(x)tr (x) = 0|∀j ∈ [k], ∀i ∈ [m]|
|---|---|---|---|
|x∈supp(tr)|i,j|i||
||m i|i i||
||i=1|||
|i||||
|m|tr|||
|i||F,m,d⃗|i ∗|
|∗ i ∗ i|i|||

X *x* (1 *− x*)tr (*x*) = *y ∀*(*x,y*) *∈* tr*,*

for the variables tr (*x*), to obtain a description of the solution space *S*tr*⊆* F *m×|*supp(tr)*|* of vectors satisfying the constraints.

(c)Sample (tr₁*,...,* tr) *← S* uniformly.
3.For each *i ∈* [*m*], sample *y ←* LDSample (tr*,x*).
P *m* *i*

4.Output *y* :=
<u>i=1</u> *x* (*x −* 1)*y*.

**Lemma 5.21.** *The outputs of Construction 5.18 and Construction 5.20 are identical. Moreover, Construc-* *tion 5.20 runs in time* poly(*m,d,* log*|*F*|,t*)*, where t* = *|*tr*|.*

*Proof.* **Correctness.** By definition, for each *i ∈* [*m*], CD F*,m,d⃗* (supp(tr)) will output a basis *zi,j*for the *i* P *m ≤d⃗i* space of constraints *{z* : F *→* F : *∀ p ∈* F [*X₁,...,Xm*]*,* *x∈*supp(tr) *z*(*x*)*p*(*x*) = 0*}* on supp(tr).

Therefore for any given *i ∈* [*m*], we have that tr*i*satisfies X *zi,j*(*x*)tr*i*(*x*) = 0 *∀j ∈* [*k*]*,* *x∈*supp(tr)

if and only if LDE F*,d⃗* [tr*i*] *̸*= *∅*. Therefore, the query-answer transcripts which are sampled in Step 2c of *i* Construction 5.20 are distributed identically to those sampled in Step 2 of Construction 5.18. By Lemma 5.15 for each *i ∈* [*m*] we have that h i h i Pr LDSample F*,m,⃗d* (tr*i,x*) = (tr *′i* *,y*) = Pr *Ri*(*x*) = *y Ri*(*X⃗*) *←* LDE F*,⃗d* [tr*i*]*,*

meaning that the output distribution of Construction 5.20 is identical to Construction 5.18. **Efficiency.** Running ZSampleF*,m,d*requires running CD F*,m,d⃗* *m* times, which requires poly(*m,d,* log(*|*F*|*)) *i* time. It further requires using Gaussian elimination to solve a system of at most *mt* equations for *mt* unknowns, which requires time *O*(*m³t³*). Finally, it requires running LDSample F*,m,d⃗* which also requires *i* time poly(*m,d,* log(*|*F*|*)), by Lemma 5.15. Thus ZSampleF*,m,d*runs in time poly(*m,d,* log(*|*F*|*)*,t*).

## 6 From ROM to AROM security

We prove that security properties in the ROM also hold in the AROM.

•In Section 6.1 we prove that the witness oracle in the AROM can be emulated.

- In Section 6.2 we show that any pass-through stateful (ARO, vob)-emulator can be transformed into a pass-through stateful (ARO*, {*wo*,*vob*}*)-emulator that only accesses ro, while preserving the emulation error. This is done using the witness oracle emulator from Section 6.1.
- In Section 6.3 we build on the above result to prove that security in the ROM implies security in the AROM. •In Section 6.4 we prove that commitment schemes in the ROM remain secure in the AROM.
### 6.1 Emulating access to the witness oracle

We transform any adversary that queries the witness oracle wo of the ARO to an adversary that does not query wo. In Section 6.3 we use this result to prove Theorem 6.5.

**Lemma 6.1.** *Let O* := ARO[F*,m,λ,d,B*]*, where* F *is a finite field, the parameters m,λ,d ∈* N*, and* *B* : *{*0*,*1*}* *m*+*r* *→{*0*,*1*}* *w* *is an oracle circuit. Define the distribution O* *′* := *{*(ro*,*wo) : (ro*,*wo*,*vob) *←O}.* *The algorithm W*[*B*] *(Construction 6.2) is a pass-through stateful* (*O* *′* *, {*wo*}*)*-emulator with zero error. W* *answers each query in time O*(*|B|*)*.*

### Construction 6.2. Define W[B] as follows:

- *W* ro [*B*](tr*,*oid*,x*) *→ y*.
1.If oid = ro, return oid(*x*).
2.If tr(*x*) *̸*= *⊥*, return tr(*x*).
3.Otherwise, sample uniform *µ ←{*0*,*1*}*
*r* and set *y* := *B* ro (*x,µ*). Output *y*.

### 6.2 Stateful emulator for the ARO w.r.t. the random oracle

As a consequence of Lemma 6.1, there exists an emulator for the ARO that only accesses the random oracle.

**Lemma 6.3.** *Let O* := ARO[F*,m,λ,d,B*]*, where* F *is a finite field, m,λ,d ∈* N *respectively are arity,* *m*+*r w* (ro*,*wo) *security, and degree parameters, and B*: *{*0*,*1*} →{*0*,*1*} is a tB-query oracle circuit. Let M* ARO *be* *a pass-through stateful* (*O, {*vob*}*)*-emulator with error ε*ARO(*t,λ*)*. Then, there exists a pass-through stateful* (*O, {*wo*,*vob*}*)*-emulator M* ro ARO *with error ε*ARO(*t,λ*)*.* (ro*,*wo) *Further, if M* ARO *makes tMoracle queries and runs in time TMfor emulating a single query, then for* *emulating t queries, M* ro

|||has a runtime of t · (T||+ t|· O(|B|)) and a query complexity of t · t||||· t.|
|---|---|---|---|---|---|---|---|---|---|
||ro ARO|ro ARO|(ro,W [B]) ARO|M M|ro ARO||(ro,wo) ARO|M|B|

ARO *M M M B*

*Proof.* Define the emulator *M* := *M*, i.e. *M* works exactly like *M* except that wo-queries are answered using *W*[*B*] (Construction 6.2). We show that for any *t*-query adversary *A*, h i ro Pr *A* (ro*,*wo*,*vob) = 1 (ro*,*wo*,*vob) *←O*(*λ*) *−* Pr *A* *M*ARO = 1 (ro*,*wo*,*vob) *←O*(*λ*) *≤ ε*ARO(*t,λ*)*.*

*M*

(*·*)
By Lemma 6.1, in which the adversary *A* is the composed adversary *A*ARO, we have h (ro*,*wo) i ro Pr *A* *M*ARO = 1 (ro*,*wo*,*vob) *←O*(*λ*) = Pr *A* *M*ARO = 1 (ro*,*wo*,*vob) *←O*(*λ*)*.* (5)

(ro*,*wo) Since *M* ARO is a pass-through stateful (*O, {*vob*}*)-emulator, by Definition 5.2, we have h i h (ro*,*wo) i Pr *A* (ro*,*wo*,*vob) = 1 (ro*,*wo*,*vob) *←O −* Pr *A* *M*ARO = 1 (ro*,*wo*,*vob) *←O*(*λ*) *≤ ε*ARO(*t,λ*)*.*

(6)
Substituting the probability on the right side of Equation 6 with Equation 5 yields the claim. Finally, we consider the efficiency of *M* ro ARO. Let *tM,TM*respectively denote the number of queries (ro*,*wo) ro and runtime of *M*

||for emulating a single query. Then, M||||has a runtime of T|+ t|· O(|B|)|
|---|---|---|---|---|---|---|---|
|ro ARO|ARO M|M M B|||ARO|M B|M|
||||||||2t|
||B||(ro,wo)|||||
||||ARO|||||

ARO ARO *M M* per emulated query, since *W*[*B*] answers each query in time *O*(*|B|*) (Lemma 6.1). Hence the runtime for emulating *t* queries is *t ·* (*T* + *t · O*(*|B|*)). Moreover, if a single execution of *B* makes *t* queries to ro, then *M* makes *t · t · t* oracle queries when emulating *t* queries.

**Corollary 6.4.** *There exists an efficient pass-through stateful* (*O, {*wo*,*vob*}*)*-emulator with errorλand a* *query complexity of t · t.*

*Proof.* This is a consequence using the *M* of Theorem 5.4 in Lemma 6.3.

### 6.3 Security in the ROM is preserved in the AROM

We prove that security properties in the ROM are preserved in the AROM; this is a straightforward application of Corollary 6.4.

**Theorem 6.5.** *Let O* := ARO[F*,m,λ,d,B*]*, where* F *is a finite field, m,λ,d ∈* N *respectively are arity,* *security, and degree parameters, and B*: *{*0*,*1*}* *m*+*r* *→{*0*,*1*}* *w* *is a tB-query polynomial-size oracle circuit.* *There exists a polynomial-size circuit C such that for all tA-query adversaries A and all t*p*-query* ro*-oracle* *predicates* p *where* ro(ro*,*wo*,*vob) *←O* Pr p (*x*) = 1 (ro*,*wo*,*vob) *≥ δ ,* (7) *x ←A*

*we have* ro *←U*(*m,λ*) <u>t + t</u>

|||ro|A|p|
|---|---|---|---|---|
|||||λ|
|A ro|B||||
|ARO (ro,A) ro|M||||
|b) ARO||ro|||
||||A p||

Pr p (*x*) = 1 (ro*,A*) *≥ δ −.* *x ←C* 2

*C makes at most t · t queries to* ro *and accesses A in a straightline fashion.*

*Proof.* Let *M* be the pass-through stateful (*O, {*wo*,*vob*}*)-emulator guranteed by Corollary 6.4. Define ro(ro*,A*) the adversary *C* := *A*ARO. Note that *C* runs *A* in a straightline fashion and answers *A*’s oracle queries using *M*; the efficiency of *C* is straightforward. Define the algorithm *A*¯ (ro*,*wo*,*vob), which runs *x ←A* (ro*,*wo*,*vo and outputs p (*x*); the query complexity of *A*¯ is *t* + *t*. The theorem follows immediately from the definition of pass-through stateful emulator (Definition 5.2) applied to *A*¯.

### 6.4 Commitment schemes in the AROM

A corollary of Theorem 6.5 is that any commitment scheme secure in the ROM is also secure in the AROM. The weaker statement that any commitment scheme in the standard model is secure in the AROM also holds, since any standard-model commitment scheme is secure in the ROM. (Because any adversary in the ROM that breaks the commitment scheme can also break it in the standard model by simulating the random oracle.)

**Lemma 6.6.** *Denote X* := ARO[*F,m,d*]*, in which F* = *{*F*λ}λ∈*N*is a family of fields, m*: N *→* N *be an* *arity function and d*: N *→* N *be a degree function. If* CM *is a binding (resp. hiding) commitment scheme* *in the ROM with binding error ε*bind(*λ*) *(resp. hiding error ε*hide(*λ*)*), then* CM *is a commitment scheme in* *X with binding error ε*bind(*λ*) + *ε*ARO(*t,λ*) *(resp. hiding error ε*hide(*λ*) + *ε*ARO(*t,λ*)*), in which t is the* *adversary’s query bound.*

*Proof.* Let *O ∈ X* and *λ ∈* N. Let *δ* be the binding error of a commitment scheme CM in the AROM. Suppose *A* is a *t*-query efficient adversary such that   *m₀ ̸*= *m₁* (ro*,*wo*,*vob) *←O*(*λ*) Pr  *∧* ck *←* CM*.*Setup(1 *λ* )  *> δ .* CM*.*Commit(ck*,m₀*;*ω₀*) = CM*.*Commit(ck*,m₁*;*ω₁*) ((*m₀,ω₀*)*,* (*m₁,ω₁*)) *←A* (ro*,*wo*,*vob) (ck)

By Theorem 6.5, there exists an adversary *C* so that   *m₀ ̸*= *m₁* ro *←U*(*m*(*λ*)*,λ*) Pr  *∧* ck *←* CM*.*Setup(1 *λ* )  CM*.*Commit(ck*,m₀*;*ω₀*) = CM*.*Commit(ck*,m₁*;*ω₁*) ((*m₀,ω₀*)*,* (*m₁,ω₁*)) *←C* (ro*,A*) (ck) *≥ δ − ε*ARO(*t,λ*)*.*

By CM’s binding property in the ROM, we have that *δ −ε*ARO(*t,λ*) *≤ ε*bind(*λ*), so *δ ≤ ε*bind(*λ*)+*ε*ARO(*t,λ*). Note that when *ε*ARO(*t,λ*) is the error from Theorem 5.4, we get *δ ≤* negl(*λ*) since CM is binding in the ROM; hence CM is binding in the AROM. A similar argument shows that CM is hiding in the AROM.

## 7 Zero-finding game in the AROM

We state and prove our lemma for zero-finding games in the AROM.

**Lemma 7.1.** *Let X* := ARO[*F,m,d*]*, let ℓ ∈* N *be a degree bound, and let* CM *be a commitment scheme* *that has binding error ε*CM(*λ*) *(and is not necessarily hiding). For every efficient probabilistic t-query oracle* *algorithm A that outputs tuples of the form* (*f ∈* F *≤dℓ*(*m*+*λ*+*w*) [*X*]*,g ∈* (F *≤ℓ* [*X*]) *m*+*λ*+*w* *,ω*) *and every* *O∈X, the following holds:*

  (ro*,*wo*,*vob) *←O*(*λ*)  ck *←* CM*.*Setup(1*λ*)   *f* (*X*) *̸≡* vob (*g*(*X*))  Pr   (*f,g,ω*) *←A* (ro*,*wo*,*vob) (ck)    *∧ f*(*β*) = vob (*g*(*β*)) cm := CM*.*Commit(ck*,* (*g,f*);*ω*)  *β ∈{*0*,*1*}* *λ* := ro(cm) s! <u>dℓ(m + λ + w)</u> *≤ O t ·* + *ε*CM(*λ*) + *ε*ARO(*t* + *dℓ*(*m* + *λ* + *w*)*,λ*)*.* *|*F*|*

*Above, ε*ARO(*t* + *dℓ*(*m* + *λ* + *w*)*,λ*) *is the emulation error of a stateful emulator for the ARO.*

### 7.1 Partial oracles

We introduce partial oracles for the stateful emulator for the ARO, which extend an ARO-query-answer transcript to include evaluations which are determined by the structure of the emulator. First, we define a partial oracle for vob queries as follows.

**Definition 7.2.** *Let* <u>X</u> := ARO[*F,m,d*]*, let O∈X, and let* tr *be an O-query-answer transcript. We define* *the partial function* trvob: *{*0*,*1*}* *m*+*λ*+*w* *⇀* F *to be:* ( *y if P*(*x*) = *y for all P ∈* LDEF*,d*[votr*∪* tr*|*vob] trvob(*x*) :=*.* *⊥ otherwise* (ro*,*wo) Second, we relate trvobto the output distribution of *M* ARO for vob queries.

**Claim 7.3.** *Let X* := ARO[*F,m,d*]*. For every O ∈ X, every O-query-answer transcript* tr*, every* *x ∈* F *m*+*λ*+*w* *and every y ∈* F*, we have that*    *|*F <u>1</u> *|* *if* trvob(*x*) = *⊥* Pr [*P* (*x*) = *y*] = 1 *if* tr vob(*x*) = *y* *.* *P ←*LDEF*,d*[votr*∪*tr*|*vob]  0 *otherwise*

*Proof.* Let *x ∈* F *m*+*λ*+*w*. The cases when trvob(*x*) *̸*= *⊥* are clear, and so we consider the case when trvob(*x*) = *⊥*. Let FIXED = *x ∈* F *m*+*λ*+*w* trvob(*x*) *̸*= *⊥*. In this case, there exist *P₁,P₂ ∈* supp(LDEF*,d*[votr*∪* tr*|*vob]) such that *P₁*(*x* *′* ) = *P₂*(*x* *′* ) for every *x* *′* *∈* FIXED, but *P₁*(*x*) *̸*= *P₂*(*x*). Since supp(LDEF*,d*[votr*∪* tr*|*vob]) is an affine space, there exists *P* *∗* = *P₁ − P₂ ∈* LDEF*,d*[*Z ∪* tr₀], where *Z* : *{*0*,*1*}* *m* *→{*0*,*1*}* is the zero function and tr₀ := *{*(*x,*0) : *x ∈* supp(tr)*}*, such that *P* *∗* (*x* *′*

) = 0 for every *x ∈* FIXED and
*P* *∗*

(*x*) *̸*= 0. Thus, we can sample from the conditional distribution in the claim by uniformly sampling
*P* *′′* *∈* supp(LDEF*,d*[votr*∪* tr*|*vob]) such that *P* *′′* (*x* *′* ) = trvob(*x* *′* ) for every *x* *′* *∈* FIXED, uniformly sampling *α ∈* F, and returning *P* *′′* + *αP* *∗* *∈* supp(LDEF*,d*[votr*∪* tr*|*vob]). The claim follows since *P* *′′*

(*x*) + *αP* *∗*
(*x*) <u>is</u>
uniformly random in F.

### 7.2 Proof of Lemma 7.1

We will prove Lemma 7.1 by first introducing an emulated hybrid world, in which the adversary plays the zero-finding game against the emulator, which we show is statistically close to the zero-finding game in the lemma statement. We then invoke a forking lemma (Lemma 3.12) to obtain a lower bound on the probability that a forking adversary wins both forks in this hybrid world. Finally, we invoke Schwartz–Zippel and the binding property of CM to obtain an upper bound on the same quantity, and combine the two bounds to obtain the result. **Emulated hybrid world.** Let *O∈X* and let *A* be an adversary that wins the zero-finding game above (ro*,*wo) with probability *δ*. Let *M* ARO be a pass-through stateful (*O, {*vob*}*)-emulator with error *ε*ARO(*t,λ*), as constructed in Theorem 5.4. Then *A* wins the following game, which we refer to as the *emulated zero finding* *game*, with probability at least *δ − ε*ARO(*t* + *dℓ*(*m* + *λ* + *w*)*,λ*):   (ro*,*wo*,*vob) *←O*(*λ*)  ck *←* CM*.*Setup(1 *λ* )    tr *M* (ro*,*wo)   *f* (*X*) *̸≡ P*(*g*(*X*)) (*f,g,ω*) *←−A*ARO(ck)  Pr   *≥ δ − ε*ARO(*t* + *dℓ*(*m* + *λ* + *w*)*,λ*)*,*  *∧ f*(*β*) = *P* (*g*(*β*)) *P ←* LDE

||[vo|]  ∪ tr||
|---|---|---|
||F,d tr|vo b|
||λ||

F*,d* tr vob    cm := CM*.*Commit(ck*,* (*g,f*);*ω*)  *β ∈{*0*,*1*}* := ro(cm)

To see this, consider the following. First, an efficient adversary can compute vob (*g*(*X*)) with *dℓ*(*m*+*λ*+*w*) (ro*,*wo) queries to vob. Second, by Theorem 5.4, provided it is only receiving queries to vob, *M* ARO answers each query by freshly sampling *P ←* LDEF*,d* tr vob

|||[vo|∪ tr|] and outputting P (x). This is equivalent to sampling||
|---|---|---|---|---|
|||F,d tr|vo b||
|F,d tr|vo b||||

*P ←* LDE [vo *∪* tr*|*] once and then outputting *P* (*x*), as is done in the above experiment. Thus if the above inequality were not true, an efficient distinguishing adversary can use the zero-finding game to distinguish between the ARO and the emulator, contradicting Theorem 5.4. **Lower bound on winning probability for forked executions.** We conclude the proof via the general forking lemma (Lemma 3.12). We define a forking predicate p that, on input (*x* := cm*,*o := (ck*,f,g,ω*)*,*tr), checks the following conditions: **Condition 1.** cm = CM*.*Commit(ck*,* (*f,g*);*ω*); **Condition 2.** either tr<u>vob</u>*◦ g*: F *→* F is not total or *f* (*X*) *̸≡* trvob(*g*(*X*)); and **Condition 3.** *f* (*β*) = trvob(*g*(*β*)), where *β* := tr*|*ro(cm). Consider the following (forking lemma) adversary *B*, which we introduce in order to invoke Lemma 3.12.

*B* *A,*p (ck*,y₁,...,yt*; *r*):

1.Run o := (ck*,f,g,ω*) *←A* using *r* as its random tape and simulating its oracle queries as follows:
(a)answer the *i*-th fresh ro-query with *yi*.
(b)answer wo-queries using Construction 6.2, and simulating its ro queries as above;
(ro*,*wo)

(c)answer vob -queries using *M*
ARO, simulating its ro*,*wo queries as above. Let tr be the query-answer transcript in this simulation.

2.Compute cm *←* CM*.*Commit(ck*,*o).
3. If p(cm*,* o*,*tr) = 0, output (0*, ⊥*). Otherwise, define FP(tr*,*cm) to be the index of the query *A* made to ro at cm and output (FP(tr*,*cm)*,*(cm*,* o*,*tr)). Recall from the assumption that *A* wins the zero-finding game with probability *δ*, which implies that *A*
wins the emulated zero-finding game with probability *δ − ε*ARO(*t* + *dℓ*(*m* + *λ* + *w*)*,λ*). We show that *B* is

accepting (i.e. outputs (*i, ·*) such that *i ≥* 1) with probability at least *δ − ε*ARO(*t* +*dℓ*(*m* + *λ* + *w*)*,λ*) *−* *|*F <u>1</u> *|*. *B* is accepting when the output of *A* satisfies p. First, any *A* winning the emulated zero-finding game directly satisfies Condition 1. Second, we show that whenever *A* wins the emulated zero-finding game, then Condition 2 is satisfied. We argue this via the contrapositive: if *f* (*X*<u>)</u> *≡* tr (*g*(*X*)), then *A* does not win the emulated zero-finding

|||vo b|
|---|---|---|
||m+λ+w|vo b|
|vo b|vo b||

game. For any input (*x,y,z*) <u>∈</u> F, if tr (*x,y,z*) is defined, then it is equal to *P* (*x,y,z*) by definition. Thus if *f* (*X*) *≡* tr (*g*(*X*)), tr must be defined over the image of *g*, so *f* (*X*) *≡ P*(*g*(*X*)); hence *A* cannot win the emulated zero-finding game by definition. Third, we argue that the probability that *A* wins the emulated zero-finding game but fails to satisfy Condition 3 is at most

||. There are two cases: either tr||(g(β)) is defined, or not. If tr|(g(β)) is defined|
|---|---|---|---|---|
|vo b||F 1|||vo b|vo b|
|||vo b|||
||1|||||
|||F||ARO||F 1||

then tr (*g*(*β*)) = *P* (*g*(*β*)), and if *A* wins the emulated zero-finding game then *P* (*g*(*β*)) = *f* (*β*); hence Condition 3 is satisfied in this case. If tr (*g*(*β*)) = *⊥*, then the probability that *A* wins the emulated zero-finding game is, by Claim 7.3, since it must guess the value of *P* (*g*(*β*)). Thus, *B* accepts with probability at least *δ − ε* (*t* + *dℓ*(*m* + *λ* + *w*)*,λ*) *−*. We deduce via Lemma 3.12 that

<u>1 t</u> *√* *δ − ε*ARO(*t* + *dℓ*(*m* + *λ* + *w*)*,λ*) *− ≤* *λ* + *t · µ ,* *|*F*|* 2

where

ck *←* CM*.*Setup(1 *λ* ) *µ* := Pr *b* = 1*′ ′ ′.* (*b,* (cm*,* o*,*tr)*,*(cm*,* o*,*tr )) *←* Fork*BA,*p(ck)

We argue that cm = cm *′* in Fork*BA,*p(ck)’s output. Note that if *b* = 1, then we have FP(tr*,*cm) = FP(tr *′* *,*cm *′* ). Let *i* := FP(tr*,*cm). Then by the definition of the forking algorithm, we have that tr*<i*= tr *′<i* (recall that the notation tr*<ℓ*refers to the query-answer pairs in tr up to and excluding the *ℓ*-th query). The *i*-th query made by *A* only depends on its internal randomness *r* and tr*<i*. Since these are the same in both executions, *A*’s *i*-th query must be the same in both executions. Thus, we have

ck *←* CM*.*Setup(1 *λ* ) *µ* = Pr *b* = 1*′ ′.* (*b,* (cm*,* o*,*tr)*,*(cm*,* o*,*tr )) *←* Fork*BA,*p(ck)

**Upper bound on winning probability for forked executions.** To conclude the proof, we upper bound *µ*. We can write *µ* as   cm *̸*= *⊥λ* ck *←* CM*.*Setup(1 )  *µ* = Pr  *∧* p(cm*,* o*,*tr) = 1*′ ′.* (8)

||′ ′||
|---|---|---|
|′ ′||B|

(*b,* (cm*,* o*,*tr)*,*(cm*,* o*,*tr )) *←* Fork *A,*p(ck) *∧* p(cm*,* o*,*tr) = 1

This is because if *b* = 1, then Step 3 of the forking adversary *B* implies that cm *̸*= *⊥* and p(cm*,* o*,*tr) = 1 = p(cm*,* o *′* *,*tr *′* ). Denote by *E₁* the event on the left of Equation 8. By the law of total probability, we have

Pr[*E₁*] = Pr[*E₁ ∧* (o = o *′* )] + Pr[*E₁ ∧* (o *̸*= o *′* )]*.*

We compute the value of Pr[*E₁∧*(o *̸*= o *′* )]. By the definition of p, if *E₁* holds then CM*.*Commit(ck*,*o) = cm = CM*.*Commit(ck*,* o *′* ). However, by the binding property of the commitment scheme CM, the probability that this happens and o *̸*= o *′* occurs is at most *ε*CM(*λ*). Let *E₂* := *E₁ ∧* (o = o *′* ). From the above, it holds that

*µ − ε*CM(*λ*) *≤* Pr[*E₂*]*.* (9)

Let *i* := <u>FP(tr,</u>cm), and let tr*|i−*1denote the truncation of tr to the first *i −* 1 queries. Define *E₃* as the event that tr*|i−*1vo b

- *g* is total. By the law of total probability, we have
Pr[*E₂*] = Pr[*E₂ ∧ E₃*] + Pr[*E₂ ∧ E₃*]*.* (10)

We show that *E₂ ∧ E₃* occurs with low probability. Define the point *β* *′* := tr *′* *|* ro(cm *′* ).

**Claim 7.4.** *The probability that E₂ occurs and* tr*|i−*1vo b

- *g is not total is at most* (*dℓ*(*m* + *λ* + *w*) + 1)*/|*F*|.*

|Proof. Since P ∈ supp(LDE||[vo ∪ tr||]), we have deg(P ◦ g) ≤ d · ℓ. Hence, if tr||||||◦ g is not total,|
|---|---|---|---|---|---|---|---|---|
||i−1|F,d tr|vo b|i−1vo b|||i−1vo i−1 ro|b|
|′|||i−1||i−1vo b|′|dℓ(m+λ+w)||F||
|i−1vo b i−1|′|i−1vo b|′|′||F 1||′|||
||||i−1vo b||i−1vo|b ′|CM ′||

then there are at most *d · ℓ* points *x ∈* F such that tr*|* (*g*(*x*)) *̸*= *⊥*. Since tr*|* contains only queries before the *i*-th query cm, we have (tr*|*)*|* (cm) = *⊥*. Hence <u>β</u> is uniformly random conditioned on tr*|*. Thus Pr[tr*|* (*g*(*β*)) *̸*= *⊥*] *≤*. Finally, if tr*|* (*g*(*β*)) = *⊥* then Pr[tr*|* (*g*(*β*)) = *f* (*β*)] *≤*, as *f* and tr are independent conditioned on tr*|*.

Combining Equations 9 and 10 and Claim 7.4, we get *µ−*(*dℓ*<u>(m+</u>*λ*+*w*)+1)*/|*F*|−ε* (*λ*) *≤* Pr[*E₂∧E₃*]. In the event that *E₂ ∧ E₃*, it holds that tr*| ◦ g ̸≡ f*, but tr*|* (*g*(*β*)) = *f* (*β*). Since *β* *′* is drawn independently of tr*|i−*1, *g*, and *f*, this equality holds with probability at most (*dℓ*(*m* + *λ* + *w*))*/|*F*|*. Rearranging, we conclude that

<u>2dℓ(m + λ + w) + 1</u> *µ ≤* + *ε*CM(*λ*)*.* *|*F*|*

<u>1 t</u> *√* Since *δ − ε*ARO(*t* + *dℓ*(*m* + *λ* + *w*)*,λ*) *−* *|*F*|* *≤* 2 *λ*+ *t · µ*, we deduce that

s 2*dℓ*(*m* + *λ* + *w*) + 1 1 *t* *δ ≤ t ·* + *ε*CM(*λ*) + + *ε*ARO(*t* + *dℓ*(*m* + *λ* + *w*)*,λ*) + *λ* *,* *|*F*| |*F*|* 2

### which implies the statement.

## 8 Accumulation scheme

We construct an accumulation scheme for ARO queries. See Definition 3.6 for the definition of an accumula- tion scheme for oracle queries.

**Theorem 8.1.** *Let F* = *{*F*λ}λ∈*N*be a family of fields, m*: N *→* N *an arity function, and d*: N *→* N *a* *degree function. Let* CM = (CM*.*Setup*,*CM*.*Commit) *be a standard-model commitment scheme that is* *hiding, m-succinct (see Section 3.6), and binding with error ε*CM(*λ*)*. Then,* AS *described in Construction 8.2* *is a zero-knowledge accumulation scheme for* ARO[*F,m,d*]*-queries with the following properties.*

•Soundness error. *When accumulating n queries and ℓ old accumulators, the soundness error is* s! <u>t · d(λ) · (n + ℓ) · (m(λ) + λ + w(λ))</u> *O* + *ε*CM(*λ*) + *ε*ARO(*t,λ*) *|*F*λ|*

*against any t-query adversary, in which ε*ARO(*t,λ*)*is the error for the pass-through stateful* (ARO[F*,m,λ,d,B*]*, {*vob*}*)*-* *emulator for ARO queries from Theorem 5.4.*

- Accumulator size. *The accumulator contains 2* vob *query-answer pairs (i.e.,*2(*m*(*λ*) + *λ* + *w*(*λ*) + 1) *field* *elements).* •Decider efficiency. *The decider consists of checking 2* vob *query-answer pairs.*
### 8.1 Construction

We assume a global ordering of the field F, so that F = *{b₁,...,b|*F*|}*. For every *O∈* ARO[*F,m,d*], we define *w* := *w*(*λ*) to be the size of the output of *Bλ*, that is, the witness size function.

**Construction 8.2.** Denote *X* := ARO[*F,m,d*]. The accumulation scheme AS = (G*,* I*,* P*,* V*,*D) for *X*-queries is specified below. An accumulator acc is a tuple (((*x₁,y₁,z₁*)*,γ₁*)*,*((*x₂,y₂,z₂*)*,γ₂*)) where *m*+*λ*+*w* each ((*xi,yi,zi*)*,γi*) is a vob query-answer pair in F *×* F. Note that a predicate input q is a triple (oid*,x,y*) *∈X*oid*×*Dom(oid)*×*Cod(oid), where *X*oid= *{*ro*,*wo*,*vob*}*, is the set of possible oracle identifiers 12 for *X* by abuse of notation.

*λ λ*

- G(1): Sample a commitment key ck *←* CM*.*Setup(1), and output the public parameters pp := ck. (ro*,*wo*,*vob) *λ*
- I

|(pp = ck): Output (apk, avk, dk) := (ck, ck, 1||||).||||||
|---|---|---|---|---|---|---|---|---|---|
|b) i|i n i=1 n+2ℓ+1|j ℓj=1 n+2ℓ+1 i n i=1|n+2ℓ+1 k|m+λ+w k k n k=1||n+2ℓ+1||n+2ℓ+1|n+2ℓ+1|
|i|i i|i|i|i|i i i|||||
|i|i i|i|i|i|i i i|||||
|i|i i i k k k j ℓj=1|i n k=1 +2ℓ+1|i|i|i i n+2ℓ+1|i i n+2ℓ+1|n+2ℓ+1|n+2ℓ+1|i n i=1|
 (ro*,*wo*,*vo
- P (apk = ck*,*[q]*,*[acc]):
1. Sample a vob query (*x,y,z*) *←* F, and set*ζ* := vob (*x,y,zn*+2*ℓ*+1).
2. Transform the predicate inputs [q] = [(oid*,x,y*)] into the corresponding vob query-answer pairs qˆ as follows. For every *i ∈* [*n*]:
(a)If q = (ro*,x,y*), then set *a* := wo(*x*) and qˆ := ((*x,y,a*)*,*1).
(b)If q = (wo*,x,z*), then set *a* := ro(*x*) and qˆ := ((*x,a,z*)*,*1).
(c)If q = (vob*,* (*x,y,z*)*,ζ*), then set *a* := *⊥* and qˆ := ((*x,y,z*)*,ζ*).
3. Let *Q* = [((*xk,y,z*)*,ζ*)] be the concatenation of the transformed predicate inputs [qˆ], old accumulators [acc], and the vob query-answer pair ((*x,y,z*)*,ζ*) from Step 1. 12 Earlier we defined oracle identifiers as integers, while here we use the names of the oracles.

4. Compute the polynomial *g ∈* (F[*X*])
*m*+*λ*+*w* of degree less than *n*+2*ℓ*+1 that interpolates the vob queries in *Q* over the fixed domain *{bk}* *n* *k*=1 +2*ℓ*+1 (i.e., such that *g*(*bk*) = (*xk,yk,zk*) for every *k ∈* [*n* + 2*ℓ* + 1]). Note that *g* is a vector of *m* + *λ* + *w* univariate polynomials from F to F, where the *i*-th polynomial operates on coordinate *i ∈* [*m* + *λ* + *w*].

5.Compute the polynomial *f ∈* F[*X*] such that *f* (*X*) *≡* vob (*g*(*X*)).
13

6.Sample commitment randomness *ω* and then compute the commitment
cm := CM*.*Commit(ck*,*((*x₁,...,xn*+2*ℓ*+1)*,f*);*ω*) *∈{*0*,*1*}* *m* *.*

7. Compute *β₀* := ro(cm) *∈{*0*,*1*}*
*λ* and *β₁* := wo(cm) *∈{*0*,*1*}* *w*; *β₀* is the Fiat–Shamir challenge. 14 Interpret *β₀* as an element of F. If *β₀ ∈{b₁,...,bn*+2*ℓ*+1*}*, go to Step 6; except if this has happened *λ* times, in which case we proceed.

8.Compute (*x,y,z*) := *g*(*β₀*).
9.Output the new accumulator acc and accumulation proof *π*Vdefined as follows:
acc := ((cm*,β₀,β₁*)*,*1)*,*((*x,y,z*)*,f*(*β₀*))*,* *π*V:= ((*xn*+2*ℓ*+1*,yn*+2*ℓ*+1*,zn*+2*ℓ*+1)*,ζn*+2*ℓ*+1)*,* (*a₁,...,an*)*,f,ω.*

- V avk = ck*,*[q*i*]
*n* *i*=1 *,*[acc*j*] *ℓj* =1 *,*acc = ((cm*,β₀,β₁*)*,*1)*,*((*x,y,z*)*,γ*)*,*

|π = ((x|,y|,z|),ζ|), (a₁,...,a|),f,ω|:|||
|---|---|---|---|---|---|---|---|---|
|n+2ℓ+1|n+2ℓ+1|k k n+2ℓ+1|k k n k=1 +2ℓ+1||||i n i=1|j ℓj=1|
||||i n+2ℓ+1|n i=1||n|V V||

V *n*+2*ℓ*+1 *n*+2*ℓ*+1 *n*+2*ℓ*+1 *n*+2*ℓ*+1 *n*

1.Compute the list *Q* = [((*x,y,z*)*,ζ*)]
and the polynomial *g* from [q], [acc], and ((*x,y,z*)*,ζn*+2*ℓ*+1) as P does, apart from the following: rather than sampling the (*n* + 2*ℓ* + 1)-th entry of *Q*, use the vob query-answer pair received in *π*; and rather than querying ro and wo to transform the input predicate [q], use (*a₁,...,a*) received in *π*.

2.Check that: **–** cm = CM*.*Commit(ck*,*((*x₁,...,x*)*,f*);*ω*); **–** (*x,y,z*) = *g*(*β₀*); and **–** *γ* = *f* (*β₀*).
3.For every *k ∈* [*n* + 2*ℓ* + 1], check that *f* (*bk*) = *ζk*.
- D (ro*,*wo*,*vob)
dk = 1 *λ* *,*acc = ((*x₁,y₁,z₁*)*,*1)*,*((*x₂,y₂,z₂*)*,γ*) :

1.Check that vob (*x₁,y₁,z₁*) = 1 and vob (*x₂,y₂,z₂*) = *γ*. In the next subsections, we prove Theorem 8.1 by analyzing the completeness, soundness, zero knowledge,
and efficiency of the construction.

### 8.2 Completeness

|The accumulation prover P receives as input a list of predicate inputs [q|||]|and a list of old accumulators|
|---|---|---|---|---|
|j ℓj=1|b) i (ro,wo,vo|b)|(ro,wo,vo b)|j|

*i* *n* *i*=1 [acc*j*] *ℓj* =1. Suppose that Φ (ro*,*wo*,*vob) (q*i*) = 1 for every *i ∈* [*n*] and D (ro*,*wo*,*vob) (acc*j*) = 1 for every *j ∈* [*ℓ*]. Completeness requires showing that P outputs a new accumulator acc and accumulation proof *π*V that satisfy the following two conditions. 13 Note that the degree of *f* is less than (*m* + *λ* + *w*) *· d ·* (*n* + 2*ℓ* + 1), and so *f* can be computed by interpolation by evaluating the expression vob (*g*(*X*)) at (*m* + *λ* + *w*) *· d ·* (*n* + 2*ℓ* + 1) points (which involves a corresponding number of queries to vob). 14 While *β₁* is not used for Fiat–Shamir, the *β₁* value is needed for completeness.

•Condition 1: V(avk*,*[acc*j*] *ℓj* =1 *,*acc*,*[q*i*] *n* *i*=1 *,π*V) = 1.

By the construction of V, this holds if the accumulator acc = ((cm*,β₀,β₁*)*,*1)*,*((*x,y,z*)*,γ*) and the accumulation proof *π*V= ((*xn*+2*ℓ*+1*,yn*+2*ℓ*+1*,zn*+2*ℓ*+1)*,ζn*+2*ℓ*+1)*,* (*a₁,...,an*)*,f,ω* are such that (i) cm = CM*.*Commit(ck*,*((*x₁,...,xn*+2*ℓ*+1)*,f*);*ω*); (ii) (*x,y,z*) = *g*(*β₀*) (where V computes *g* exactly as P does); (iii) *γ* = *f* (*β₀*); and (iv) *f* (*bk*) = *ζk*for every *k ∈* [*n* + 2*ℓ* + 1]. Condition i is satisfied because V computes cm using the same inputs and commmitment key (since apk = avk = ck) as P (ro*,*wo*,*vob). Conditions ii and iii are satisfied directly. For Condition iv: *g*(*b*

||||) = (x|,y ,z ) for all k ∈ [n + 2ℓ + 1]|
|---|---|---|---|---|
|b)|k|k k|k k k k|k k k|

by the definition of *g*. Thus, we have vob (*g*(*b*)) = vob (*x,y,z*) for every *k ∈* [*n* + 2*ℓ* + 1]. Since we defined *f* := vob *◦ g*, we get that *f* (*b*) = *ζ* for every *k ∈* [*n* + 2*ℓ* + 1].

•Condition 2: D (ro*,*wo*,*vo (acc) = 1.

This occurs when both elements in acc are valid query-answer pairs for vob. In the first pair, the honest P (ro*,*wo*,*vob) sets *β₀* = ro(cm) and *β₁* = wo(cm), which means vob (cm*,β₀,β₁*) = 1 by the definition of vob. For the second pair, the honest prover outputs ((*x,y,z*)*,f*(*β₀*)), where *g*(*β₀*) = (*x,y,z*). This satisfies vob (*g*(*β₀*)) = *f* (*β₀*) because *f ≡* vob *◦ g*.

### 8.3 Soundness

Since AS is an accumulation scheme for ARO[*F,m,d*]-queries, we show that the probability below is bounded from above by the expression in the theorem statement:  *n ℓ*  V(avk*,*[q*i*] *i*=1 *,*[acc*j*] *j*=1 *,*acc*,π*V) = 1 (ro*,*wo*,*vob) *←O*  D(ro*,*wo*,*vob)(dk*,*acc) = 1*λ*  pp *←* G(1)  *n ℓj* [acc *.* (11)

|Pr ||∧||[q]|]|||
|---|---|---|---|---|---|---|---|
||(ro,wo,vo|b) (ro,wo,vo b)|j|i n i=1|j ℓj =1 V|(ro,wo,vo b) (ro,wo,vo b)||
||||i|||||
|Φ n|Φ||||V|n+2ℓ+1|n+2ℓ+1|

 *←A* (pp)   *∃ j ∈* [*ℓ*]*,* D (dk*,*acc) = 0 *∨* acc *π*  (apk*,*avk*,*dk) *←* I (pp) *∃ i ∈* [*n*]*,* Φ (q) = 0

Since i = *⊥* and pp = *⊥* in oracle query accumulation schemes, we omit them from the above equation. In the above equation, let acc = ((cm*,β₀,β₁*)*,*1)*,*((*x,y,z*)*,γ*) and*π* = ((*x,y,zn*+2*ℓ*+1)*,ζn*+2*ℓ*+1)*,* (*a₁,...,a*)*,f,ω*. We argue that the event in the left side of Equation 11, which we denote by *E*, is equiva- lent to the condition “*f* (*X*) *̸≡* vob (*g*(*X*)) and *f* (*β₀*) = vob (*g*(*β₀*))”.

•First, we show that *f* (*β₀*) = vob (*g*(*β₀*)). Note that

**–** D (ro*,*wo*,*vob) (dk*,*acc) = 1 implies that vob (*x,y,z*) = *γ*; and **–** V(avk*,*[q*i*] *n* *i*=1 *,*[acc*j*] *ℓj* =1 *,*acc*,π*V) = 1 implies that (*x,y,z*) = *g*(*β₀*) and *γ* = *f* (*β₀*).

Then substitution gives vob (*g*(*β₀*)) = *f* (*β₀*).

•Second, we show that *f* (*X*) *̸≡* vob (*g*(*X*)). Consider the expression

||b)|j||(ro,wo,vo b)|Φ Φ|i|||
|---|---|---|---|---|---|---|---|---|
|||k k|k k|||k k|k|k|
|∗|||k k|k|k||||
|k|k|i n i=1 k|j ℓj=1|V||k|k||

*∃ j ∈* [*ℓ*]*,* D (ro*,*wo*,*vo (dk*,*acc) = 0 *∨∃ i ∈* [*n*]*,* Φ (pp*,* i*,* q) = 0*.*

This means there is a query-answer pair ((*x ∗,y ∗,z ∗*)*,ζ ∗*) *∈ Q* such that vob (*x ∗,y ∗,z ∗*) *̸*= *ζ ∗*, for some *k ∈* [*n* + 2*ℓ* + 1]. By *g*’s definition, we have (*x,y,z*) = *g*(*b*) for every *k ∈* [*n* + 2*ℓ* + 1], so vob (*g*(*b ∗*)) *̸*= *ζk∗*. Also since V(avk*,*[q]*,*[acc]*,*acc*,π*) = 1, we have *f* (*b*) = *ζ* for every *k ∈* [*n* + 2*ℓ* + 1]. Hence, we get *f* (*b ∗*) *̸*= vob (*g*(*b ∗*)), and thus conclude that *f* (*X*) *̸≡* vob (*g*(*X*)).

Next, we wish to invoke our oracle zero-finding game lemma (Lemma 7.1) to bound the probability in Equation 11. We apply Lemma 7.1 with respect to the commitment scheme CM *′* obtained by modifying CM as follows:

CM *′* *.*Commit(ck*,* (*g,f*);*ω*) := CM*.*Commit(ck*,*((*g*(*b₁*)*,...,g*(*bn*+2*ℓ*+1))*,f*);*ω*)*.*

Note that CM *′* is binding to *g* since *g* has degree less than *n* + 2*ℓ*. Further, since CM has binding error *ε*CM(*λ*) in the standard model (and hence also in the ROM¹⁵), Lemma 6.6 states that CM has binding error *ε*CM(*λ*) + *ε*ARO(*t,λ*) in the AROM. The winning event in the zero-finding game is that

cm = CM *′* *.*Commit(ck*,* (*g,f*);*ω*) = CM*.*Commit(ck*,*((*x₁,...,xn*+2*ℓ*+1)*,f*);*ω*)*,*

*f* (*X*) *̸≡* vob (*g*(*X*)), and *f* (*β₀*) = vob (*g*(*β₀*)) for *β₀* := ro(cm). Since V(avk*,*[q*i*] *n* *i*=1 *,*[acc*j*] *ℓj* =1 *,*acc*,π*V) = 1, we get that cm = CM*.*Commit(ck*,*((*x₁,...,xn*+2*ℓ*+1)*,f*);*ω*). Also note that deg(*g*) *≤ n* + 2*ℓ*. Thus, by applying our oracle zero-finding game lemma, the probability that *f* (*X*) *̸≡* vob (*g*(*X*)) and *f* (*β₀*) = vob (*g*(*β₀*)) is at most s 2*d*(*n* + 2*ℓ*)(*m* + *λ* + *w*) + 1 1 *t* *t ·* + *ε*CM(*λ*) + *ε*ARO(*t,λ*) + + *ε*ARO(*t,λ*) + *λ* *.* *|*F*| |*F*|* 2

Since the event *E* is equivalent to *f* (*X*) *̸≡* vob (*g*(*X*)) and *f* (*β₀*) = vob (*g*(*β₀*)), the above probability is an upper bound on the probability in Equation 11, as desired.

### 8.4 Zero knowledge

We describe a zero-knowledge simulator S that has access to (ro*,*wo*,*vob) and simulates: (i) the scheme’s public parameters pp; and (ii) the distribution of P’s accumulator acc without access to P’s inputs (the predicate inputs [q*i*] *n* *i*=1 and old accumulators [acc*j*] *ℓj* =1 ). Then we show that if the commitment CM is statistically (resp. computationally) hiding, then the simulated joint distribution ((ro*,*wo*,*vob)*,*pp*,*acc) is statistically (resp. computationally) indistinguishable from ((ro*,*wo*,*vob)*,*pp*,*acc) produced in the real protocol.

- *Parameter generation:* S(1
*λ* ) *→* pp*.*

1.Sample ck *←* CM*.*Setup(1
*λ* ).

2.Output pp := ck (and store ck in the internal state).
- *Proving:* S
(ro*,*wo*,*vob) (ppΦ= *⊥,*iΦ= *⊥*) *→* acc*.*

1. Sample commitment randomness*ω* and compute a commitment cm := CM*.*Commit(ck*,*((0*,...,*0)*,f*
*′* );*ω*) where *f* *′* *∈* F[*X*] is the zero polynomial (appropriately padded).

2. Query ro and wo to compute *β₀* := ro(cm) and *β₁* := wo(cm). If *β₀ ∈{b₁,...,bn*+2*ℓ}*, resample *ω* and recompute cm until this is not the case. Abort if we resample more than *κ* := *λ/*(log*|*F*|−* log(*n* + 2*ℓ*)) times. 16
3.Sample a random vob query (*x,y,z*) *←* F
*m*+*λ*+*w*.

4.Query the oracle vob to compute *γ* := vob (*x,y,z*). 15 Otherwise, we can construct a standard-model adversary for CM via running the adversary for CM in the ROM and answering
ro-queries using a “lazily sampled” evaluation table for ro. 16 If the field F is of superpolynomial size (and *n,ℓ* are polynomially bounded) then resampling is not necessary.

5.Output the accumulator acc := ((cm*,β₀,β₁*)*,*1)*,*((*x,y,z*)*,γ*).
Observe that the probability that the simulator aborts in Step 2 is at most negl(*λ*). By Claim 3.7, with all but negligible probability, all of the sampled cm are distinct; hence the probability that ro(cm) *∈{b₁,...,bn*+2*ℓ}* <u>n+2ℓ</u> *κ* for all sampled cm is at most *|*F*|* + negl(*λ*) = negl(*λ*). We argue that ((ro*,*wo*,*vob)*,*pp*,*acc) above is indistinguishable from that produced by the accumulation prover. Since S does not program the oracle, we fix an oracle (ro*,*wo*,*vob) *←O*, then argue that pp and acc output by S are distributed correctly, given (ro*,*wo*,*vob). First, the real and simulated pp have the same distribution: they are both commitment keys ck *←* CM*.*Setup(1 *λ* ). Next, we show that the real and simulated acc = ((cm*,β₀,β₁*)*,*1)*,*((*x,y,z*)*,γ*) are indistinguishable. It suffices to argue the indistinguishability of cm and (*x,y,z*) (between the real protocol and the simulation), because *β₀* = ro(cm)*,β₁* = wo(cm) and *γ* = vob (*x,y,z*) in both the real protocol and the simulation.

- cm: Since CM is (statistically/computationally) hiding, cm is (statistically/computationally) indistinguish- able from a commitment to any other message of the same length. This is true even if the adversary is given many independent commitments to the same message. Note that apart from the choice of message, the prover and simulator sample cm in the same way.

|• (x,y,z): Since β₀ ̸∈{b₁,...,b|} (else the simulator aborts), in the real protocol, as in the simulation,||
|---|---|---|
||m+λ+w||
||N +1|N t|
|N +1 t||N +1 N +1|
|t||t|

*n*+2*ℓ* *g*(*β₀*) is uniformly random in F *m*+*λ*+*w*. This follows from a standard algebraic fact stated below.

*Fact* 8.3*.* Let *t ∈* N and let *b₁,...,b ∈* F be distinct field elements, and let *x₁,...,x ∈* F. Sample
*x ←* F uniformly and construct*g* to be the (unique) interpolation of the points (*b₁,x₁*)*,...,*(*b,x*) *∈* F *×* F of minimal degree. Then for any point *β ←* F *\{b₁,...,bN}*, *g*(*β*) is uniformly random in F.

### 8.5 Efficiency

We discuss the efficiency of Construction 8.2.

- *Generator.* Efficiency follows from the efficiency of CM*.*Setup, which takes poly(*λ*) time.
- *Indexer.* This takes poly(*λ*) time.
- *Accumulation prover.* Running P
(ro*,*wo*,*vob) involves making at most *n* queries (where each query is either to ro or wo), computing the polynomial *g* via polynomial interpolation, committing to (*f,g*), and computing the polynomial *f* via evaluating *g* at (((*m* + *λ* + *w*) *· d*) *−* 1) *·* (*n* + 2*ℓ* + 1) query points, 17 making (*m* + *λ* + *w*) *· d ·* (*n* + 2*ℓ* + 1) queries to ro, then interpolating. These operations can be accomplished in polynomial time in *λ*.

- *Accumulator size.* Consider the first query-answer pair ((cm*,*ro(cm)*,*wo(cm))*,*1) in acc. Since the commitment scheme CM has commitment size *m*, we know that cm *∈ {*0*,*1*}*
*m* *⊆* F *m*. Then, the query-answer pair ((cm*,*ro(cm)*,*wo(cm))*,*1) is in F *m*+*λ*+*w* *×* F. The second query-answer pair in acc is ((*x,y,z*)*,f*(*β₀*)), which is in F *m*+*λ*+*w* *×* F due to the domain of vob and the definition of *f*.

|includes (i) a vo|,y|,z|
|---|---|---|
|V|n+2ℓ+1|n+2ℓ+1 n+2ℓ+1|
|||n|

- *Accumulation proof size.* The accumulation proof*π*
b query-answer pair ((*x*)*,* *ζ* *n*+2*ℓ*+1), which can be represented with *m* + *λ* + *w* + 1 elements of F; (ii) advice values (*a₁,...,a*), which can be represented with *≤ n ·*max*{λ,w}* elements of F; (iii) a single-variate polynomial *f* of degree 17 This assumes that we reuse the *g* query-answer pairs (*bi,* (*xi,yi,zi*)) from the prover’s Step 4.

at most (*m* + *λ* + *w*) *· d ·* (*n*+ 2*ℓ* + 1), which can be represented with (*m* + *λ* + *w*) *· d ·* (*n*+ 2*ℓ* + 1) + 1 elements of F; and (iv) commitment randomness *ω*, which is a bitstring of poly(*λ*) length.

- *Accumulation verifier.* The accumulation verifier V computes the polynomial *g* via interpolation, the com- mitment CM*.*Commit(ck*,*((*x₁,...,xn*+2*ℓ*+1)*,f*);*ω*), a single evaluation of *g*, and *n* + 2*ℓ* + 2 evaluations of *f*. Note that V makes no oracle queries.
- *Decider.* D
(ro*,*wo*,*vob) makes 2 queries to vob.

## 9 PCD in the AROM

We describe how to combine our results to construct PCD in the AROM, proving our main theorem.

### 9.1 SNARKs in the AROM

We argue that a (zk)SNARK in the ROM is also a (zk)SNARK (where honest parties only query the random oracle) in the AROM. In Lemma 9.1 we prove that straightline knowledge soundness is preserved in the AROM. Afterwards, in Lemma 9.2 we prove that zero knowledge of a SNARK in the ROM is preserved in the AROM.

### 9.1.1 Knowledge soundness

**Lemma 9.1.** *Let F* = *{*F*λ}λ∈*N*be a family of fields, m*: N *→* N *an arity function, d*: N *→* N *a degree* *function such that d*(*λ*) *≥* 2 *for a security parameter λ ∈* N*, and X* := ARO[*F,m,d*]*.* *Let* ARG = (*G, I, P, V*) *be a SNARK in the ROM for a relation R, where the random oracle has arity* *≤ m*(*λ*)*. Suppose* ARG *has straightline knowledge extraction error κ*(*λ,t*)*, in which t ∈* N*.* *Then,* ARG *is a SNARK relative to X for R (unconditionally) with straightline knowledge extraction* <u>t+poly(λ,|①|)</u> *error at most κ*(*λ,t ·* poly(*λ*)) + 2 *λ, where t is the number of queries made by the adversary in the* *AROM and |*①*| is the size of an instance in L*(*R*)*.*

*Proof.* Let ARG = (*G, I, P, V*) be a SNARK in the ROM for *R* with straightline knowledge extraction error *κ*(*λ,t*). We argue that ARG, with access to *O∈* ARO[*F,m,d*], has straightline knowledge extraction error at most *κ*(*λ,O*(*t²*) *·* poly(*λ*)) + 2 <u>t</u> *λ*. By the definition of straightline knowledge soundness for ARG, there exists a knowledge extractor *E* such that for every malicious prover *P*˜:   ro *←U*(*m*(*λ*)*,λ*)  pp *←G*(1 *λ* )  ro  *V* (ivk*,* ①*,π*) = 1 ai *←D*(pp)    Pr  *∧*tr ro  *≤ κ*(*λ,t* *P* ˜)*,* (12)  (✐*,* ①*,π*) *←− P*˜ (pp*,*ai)   (✐*,* ①*,*✇) *̸∈R* ro   (ipk*,*ivk) *←I* (pp*,*✐)  ✇ *←E*(pp*,* ✐*,* ①*,π,* tr)

in which *t* *P* ˜= *|*tr*|*. Define a predicate p ro

(*x*) corresponding to the game that *P*˜ attempts to win in Equation 12:
1.Parse *x* as (pp*,* ✐*,* ①*,π,* tr).
2.Run (ipk*,*ivk) *←I*
ro (pp*,*✐).

3.Run *E*(pp*,* ✐*,* ①*,π,* tr*|*ro), in which tr*|*rodenotes tr restricted to ro queries.
4.Output 1 if *V*
ro (ivk*,* ①*,π*) = 1 and (✐*,* ①*,*✇) *̸∈R*. Otherwise, output 0.

Let *t*pdenote the query complexity of p ro. By the succinctness of ARG (Section 3.3) and the efficiency of *I*, we have *t*p= poly(*λ, |*①*|*).

Next, let *P*˜ARObe any *t*-query malicious prover in the AROM. For some *δ ∈* [0*,*1), we have   (ro*,*wo*,*vob) *←O*  pp *←G*(1*λ*)  Pr   p ro (pp*,* ✐*,* ①*,π,* tr) = 1   *> δ .* (13) ai *←D*(pp) tr ˜(ro*,*wo*,*vo

b)
(✐*,* ①*,π*) *←− P* ARO (pp*,*ai)

Note that the probability in Equation 13 is equivalent to the straightline knowledge soundness property for ARG in the AROM. Now, we invoke Theorem 6.5 and the knowledge soundness property of ARG to upper bound *δ*. De- fine an adversary *A* (ro*,*wo*,*vob) that runs the right side of Equation 13, excluding the first line, and outputs (pp*,* ✐*,* ①*,π,* tr). Note that *A* (ro*,*wo*,*vob) makes *tA*= *t* oracle queries because only *P*˜AROmakes oracle queries. By Theorem 6.5, there exists an adversary *C*, with access to ro and straightline access to *A*, so that

ro *←U*(*m*(*λ*)*,λ*) (*t* + *t,λ*)

|||Pr p (x) = 1|||≥ δ − ε|,||
|---|---|---|---|---|---|---|---|
|||ro||(ro,A)|ARO|p||
|ARO|(ro,A)|p M|(ro,A)||M|M|ro ARO|
|||ro ARO|ro|λ|||M|
|ARO|p|||M|p|||

*x ←C*

in which *ε* (*t* + *t,λ*) is the emulation error of a pass-through stateful (*O, {*wo*,*vob*}*)-emulator *M*. ro Specifically, *C* := *A*ARO, and *C* makes at most *t · t* queries, in which *t* denotes the per-query query complexity of *M*. Observe that both *A* and *C* run pp *← G*(1) and ai *← D*(pp), then differ afterwards; interpret the differing code in *C* as a malicious prover *P*˜ (which is in the ROM). Then, Equation 12 implies *κ*(*λ,t · t*) *≥* *δ − ε* (*t* + *t,λ*). Rearranging gives

*δ ≤ κ*(*λ,t · t*) + *ε*ARO(*t* + *t,λ*)*.* (14)

By Theorem 5.4, there exists a pass-through stateful (*O, {*vob*}*)-emulator with query complexity *O*(1)

||t+t|ro||
|---|---|---|---|
|ARO p|2|ARO|M B|

<u>p</u> and with emulation error *ε* (*t* + *t,λ*) =*λ*. Thus by Lemma 6.3, *M* makes *t* := *O*(*t*) = poly(*λ*) oracle queries per emulated query, where the equality is due to the definition of ARO[*F,m,d*<u>]</u> (Definition 4.3). Plugging these values into Equation 14 yields the desired result.

### 9.1.2 Zero-knowledge

We show that zero-knowledge SNARKs in the ROM remain zero-knowledge in the AROM.

**Lemma 9.2.** *Let F* = *{*F*λ}λ∈*N*be a family of fields, m*: N *→* N *an arity function, and d*: N *→* N *a degree* *function such that d*(*λ*) *≥* 2 *for a security parameter λ ∈* N*.* *Let* ARG = (*G, I, P, V*) *be a zero-knowledge SNARK in the ROM for a relation R, where the random* *oracle has arity ≤ m*(*λ*)*, with zero-knowledge simulation error at most ε*ZK(*λ*)*. Then,* ARG *is a SNARK* *relative to X* := ARO[*F,m,d*] *for R with zero-knowledge simulation error at most ε*ZK(*λ*) + 2 *λ* <u>t</u> *−*1*, where* *t is the number of oracle queries made by a stateful adversary in the AROM.*

*Proof.* Let ARG = (*G, I, P, V*) be a zero-knowledge SNARK in the ROM. We argue that ARG maintains zero-knowledge in the AROM; for *O* = ARO[F*,m,λ,d,B*] *∈X*, we show that there exists an efficient (ro*,*wo*,*vob) simulator *S* ARO such that for all stateful honest *t*-query adversaries *A*, the following distributions are

*ε*ZK(*λ*) + 2 *· ε*ARO(*t,λ*)-close, where *ε*ARO(*t,λ*) is the *O*-emulation error:     (ro*,*wo*,*vob) *←O*(*λ*)   

|||pp ←G(1 ) ||
|---|---|---|---|
|ARO|(ro,wo,vo b)|(ro,wo,vo b)||
|||ro||
|||ro||

*λ*   *D* := *A* (ro*,*wo*,*vob)

(*π*) (✐*,* ①*,*✇) *←A*
(ro*,*wo*,*vob) (pp)       (ipk*,*ivk) *←I* (pp*,*✐)     *π ←P* (ipk*,* ①*,*✇)     (ro*,*wo*,*vob) *←O*(*λ*)    (ro*,*wo*,*vob) *λ*   *S* (ro*,*wo*,*vob) pp *←S* ARO (1 ) and *D*ZK:= *A*ARO(*π*)tr (ro*,*wo*,*vob) *.*   (✐*,* ①*,*✇) *←−A* (pp)   (ro*,*wo*,*vob)   *π ←S* ARO (✐*,* ①*,*tr)

We may assume without loss of generality that the second stage of *A* outputs a single bit. Note that in *D*ARO, the indexer *I* and prover *P* only access ro because we want to argue that ARG, which is defined in the ROM, remains zero-knowledge in the AROM. Further, since *A* is honest, we have (✐*,* ①*,*✇) *∈R* in both *D*AROand *D*ZK. Let *S* be the zero-knowledge simulator for ARG. Further, let *M* ro ARO be a pass-through stateful (*O, {*wo*,*vob*}*)-emulator with error *ε*ARO(*t,λ*), which exists due to Lemma 6.3. Define the (stateful) zero- (ro*,*wo*,*vob) knowledge simulator *S* ARO for ARG in the AROM as follows: (ro*,*wo*,*vob) *λ*

- *Parameter generation: S*
ARO

(1) *→* pp*.*
1.Output pp *←S*(1
*λ* ). (ro*,*wo*,*vob)

- *Proving: S*
ARO (✐*,* ①*,*tr) *→ π.*

1.Run *π ←S*
ro (✐*,* ①*,*tr*|*ro), in which tr*|*rodenotes the restriction of tr to ro query-answer pairs.

2.Output *π*.
(ro*,*wo*,*vob)

- *Query responses: S*
ARO (tr*i,*(oid*,x*)) *→ y.* *S*ro(tr*i|*ro) ro

1. Run (tr*i*+1*,y*) *← M*
ARO (tr*i,*(oid*,x*)). Note that *S* simulates responses to the ro queries of *M*ARO, conditioned on tr*i|*ro, which is tr*i*restricted to ro queries.

2.Output *y*. (ro*,*wo*,*vob) ro (ro*,*wo*,*vob)
Note that *S* ARO never queries wo or vob, so below we write *S* ARO := *S* ARO. Below, we write *M*ro(tr) ro *A*AROto mean that *A* has query access to an emulator *M* ARO (tr) that is initialized with tr; if *A* makes more than one query, then subsequent runs of the emulator are initialized with a transcript containing all query-answer pairs that *A* has seen. Next, we use a hybrid argument to argue the indistinguishability of *D*AROand *D*ZK. The hybrids are as follows. Below, we usebluetext to denote changes from the previous hybrid (i.e.blue text in hybrid Hyb*i*+1are the changes from hybrid Hyb*i*. Further, we write tr to denote the *O*-query-answer transcript of *A*.

- **H₀**: *A*’s view is defined as in *D*ARO.
    (ro*,*wo*,*vob) *←O*(*λ*)   *λ*

| ||pp ←G(1 ) ||
|---|---|---|---|
|(ro,wo,vo|b)|(ro,wo,vo b)||
|||ro||
|||ro||

*D*ARO:= *A* (ro*,*wo*,*vob)

(*π*) (✐*,* ①*,*✇) *←A*
(ro*,*wo*,*vob) (pp)*.*       (ipk*,*ivk) *←I* (pp*,*✐)     *π ←P* (ipk*,* ①*,*✇)

(ro*,*wo*,*vob) *M*ro(*⊥*)

- **H₁**: *A*’s view is defined as in *D*ARO, except that *A* is replaced by *A*ARO. That is, the distribution is:
   ro *←U*(*m*(*λ*)*,λ*)      pp *←G*(1*λ*)    *M*ro(tr) tr *M*ro(*⊥*) *D₁* := *A*ARO(*π*) (✐*,* ①*,*✇) *←−A*ARO(pp)*.*    ro    (ipk*,*ivk) *←I* (pp*,*✐)    ro *π ←P* (ipk*,* ①*,*✇)

- **H₂**: *A*’s view is defined as:
   ro *←U*(*m*(*λ*)*,λ*)    ro (tr*|λ* *S* ro) pp *←S*(1)  *M*ARO(tr) *D₂* := *A* (*π*)tr*,* *M*roARO(*⊥*)(pp) 

||tr M|(⊥)||
|---|---|---|---|
||ro||ro|
|||ro||
|M (⊥)||||

  (✐*,* ①*,*✇) *←−A*    *π ←S* (✐*,* ①*,*tr*|*)

ro in which *S* is the zero-knowledge simulator for ARG. Observe that tr*|* is the query-answer transcript of ro the composed adversary *A*ARO.

- **H₃**: *A*’s view is:
   ro *←U*(*m*(*λ*)*,λ*)    

||||pp ←S|(1 ) |
|---|---|---|---|---|
|S|(tr)||ARO M (⊥)|λ|
||||ro||
||||ARO||
|ZK||ARO ro|||

ro *D₃* := *A*ARO(*π*)tr ro*.*  ARO(pp)   (✐*,* ①*,*✇) *←−A*    *π ←S* (✐*,* ①*,*tr)

- **H₄**: *A*’s view is defined as in *D* running with *S*.
   (ro*,*wo*,*vob) *←O*(*λ*)    

||pp ←S|(1 ) |
|---|---|---|
|S (tr)|ARO tr (ro,wo,vo|λ b)|
||ro||
||ARO||

ro *D*ZK:= *A*ARO(*π*)*.*   (✐*,* ①*,*✇) *←−A* (pp)    *π ←S* (✐*,* ①*,*tr)

Next, we bound the statistical distance between the hybrids. **H₀ vs. H₁.** We argue that **H₀** and **H₁** have distance at most *ε*ARO(*t,λ*). Given (ro*,*wo*,*vob) *←O*(*λ*), define a stateful adversary *A*Thm, as follows:

*λ*

1.Run pp *←G*(1).

|(ro,wo,vo|b)|||
|---|---|---|---|
|ro||||
|ro||||
|(ro,wo,vo b)||||
|(ro,wo,vo b)||M||
|Thm||Thm||
|(ro,wo,vo b)|||M|
|Thm|||Thm|
||||ARO|

(ro*,*wo*,*vob)

2.Run (✐*,* ①*,*✇) *←A*.
3.Run (ipk*,*ivk) *←I* (pp*,*✐).
4.Run *π ←P* (ipk*,* ①*,*✇).
5.Output *b ←A* (*π*).
ro ARO Observe that *A* is exactly *D*AROand *A* is exactly *D₁*. Hence the statistical distance between **H₀** and **H₁** is at most h i hroi ARO Pr *A* = 1 (ro*,*wo*,*vob) *←O*(*λ*) *−* Pr *A* = 1 ro *←U*(*m,λ*)*.* (15)

Invoking Corollary 6.4, Equation 15 is upper bounded by *ε* (*t,λ*).

**H₁ vs. H₂.** We argue that **H₁** and **H₂** have statistical distance at most *ε*ZK(*λ*). Observe that the composed *M*ro(*⊥*) adversary *A*AROonly queries ro. *M*ro(*⊥*) Next, we argue that, in **H₁**, *A*ARO(pp) is honest, i.e. outputs (✐*,* ①*,*✇) *∈ R* with probability *≥* 1*−*negl(*λ*). Since *A* (ro*,*wo*,*vob) (pp) is honest, it outputs *x* = (✐*,* ①*,*✇) *∈R* with probability *δ ≥* 1*−*negl(*λ*). Next, we invoke Theorem 6.5, with a predicate p(*x*) checking that *x ∈R*, on *A* (ro*,*wo*,*vob) (pp) to get the (ro*,A*) *M*ro(*⊥*) *M*ro(*⊥*) transformed adversary *C* := *A*ARO(pp); the output *x* of *A*ARO(pp) satisfies *x ∈ R* with probability *≥ δ − ε*ARO(*t,λ*) *≥* (1 *−* negl(*λ*)) *− ε*ARO(*t,λ*). Setting the emulation error *ε*ARO(*t,λ*) := 2 <u>t</u> *λ*, as computed in Theorem 5.4, implies that *C* (ro*,A*) outputs a valid *x ∈R* with probability *≥* 1 *−* negl(*λ*). *M*ro(*⊥*) Thus, we can invoke ARG’s zero-knowledge property with respect to *A*ARO; given the zero- knowledge simulator *S* ro for ARG, we can syntactically update distribution *D₁* to (a) replace *P* ro with *S* ro; and (b) after *π* is produced, have *S* ro (tr*|*ro) answer the composed adversary’s ro queries. This updated distribution is exactly the distribution *D₂* in **H₂**, which proves the claim. **H₂ vs. H₃. H₂** is obtained from **H₃** by expanding the definition of *S* ARO ro, so the two hybrids are identical. **H₃ vs. H₄.** The difference between the hybrids is that, in **H₄**, *A* accesses the real (ro*,*wo*,*vob) when outputting (✐*,* ①*,*✇) versus, in **H₃**, *A* accesses the emulator *M* ro ARO

(*⊥*). We bound the statistical distance
between **H₃** and **H₄**. Given (ro*,*wo*,*vob) *←O*(*λ*), define a stateful adversary *A*Thmthat does the following:

1.Run pp *←S*
ARO ro (1 *λ* ). tr (ro*,*wo*,*vob)

2.Run (✐*,* ①*,*✇) *←−A* (pp).
3.Run *π ←S*
ARO ro (✐*,* ①*,*tr). *S*ro(tr)

4.Output *b ←A*ARO(*π*).
(ro*,*wo*,*vob) *M* ro ARO Observe that *A* Thm is exactly *D*ZKand *A* Thm is exactly *D₃*. Hence the statistical distance between **H₃** and **H₄** is at most h i hroi (ro*,*wo*,*vob) *M*ARO(*⊥*) Pr *A* Thm = 1 (ro*,*wo*,*vob) *←O*(*λ*) *−* Pr *A* Thm = 1 ro *←U*(*m,λ*)*.* (16)

By Corollary 6.4, Equation 16 is upper bounded by *ε*ARO(*t,λ*). **Overall bound.** By the triangle inequality, we conclude that the statistical distance between **H₀** and **H₄** is at most *ε*ZK(*λ*) + 2 *· ε*ARO(*t,λ*). Further, setting the emulation error *ε*ARO(*t,λ*) := 2 <u>t</u> *λ*, as computed in Theorem 5.4, yields the statement.

As a consequence of Lemmas 9.1 and 9.2, the Micali SNARK [Mic00] is secure in the AROM.

**Corollary 9.3.** *Let F* = *{*F*λ}λ∈*N*be a family of fields, m*: N *→* N *be an arity function, d*: N *→* N *be a* *degree function, and λ ∈* N *be the security parameter.* *If m*(*λ*) *≥* 2*λ and d*(*λ*) *≥* 2*, then the Micali SNARK [Mic00], instantiated with a (holographic) PCP that* *is honest-verifier zero knowledge and has knowledge soundness, is a zero-knowledge SNARK with straightline* *knowledge extraction relative to* ARO[*F,m,d*]*.*

The requirement *m*(*λ*) *≥* 2*λ* comes from the Micali SNARK construction, which uses the random oracle ro to compute the Merkle tree. Thus, setting *m*(*λ*) *≥* 2*λ* ensures that ro can parse inputs containing two ro outputs.

### 9.2 PCD from SNARKs in the AROM

**Theorem 9.4** (formal restatement of Theorem 1)**.** *Let F* = *{*F*λ}λ∈*N*be a family of fields, m*: N *→* N *an* *arity function, and d*: N *→* N *a degree function such that d*(*λ*) *≥* 2*, m*(*λ*) *≥* 2*λ, and |*F*λ|* = *λ* *ω*(1) *.* *There exists a zero-knowledge PCD scheme relative to* ARO[*F,m,d*]*(see Definition 4.2) for polynomial-* *time compliance predicates (of unbounded depth) with access to the sampled oracle, assuming the existence* *of (standard-model) collision-resistant hash functions.*

*Proof.* We recall a lemma from [CCS22] on SNARKs for oracle computations, with the following minor strengthening: if the given SNARK ARGinhas straightline knowledge extraction, then so does the resulting SNARK ARGout. This is straightforward from the construction of the extractor for ARGoutin [CCS22].

**Lemma 9.5** ([CCS22, Lemma 8.2])**.** *Let O be an oracle distribution. Suppose that we are given:*

*(i)a SNARK* ARGin*in the O-oracle model for an (oracle-free) relation R; and* *(ii) an accumulation scheme* AS = (G*,* I*,* P*,* V*,*D) *for O-queries (in particular,* V *makes no oracle query).*
*Then we can construct a SNARK* ARGout*relative to O for R* *O* *.* *Moreover: (i) if* ARGin*is zero-knowledge and* AS *is zero-knowledge, then* ARGout*is zero-knowledge;* *and (ii) if* ARGin*has straightline knowledge extraction then* ARGout*has straightline knowledge extraction.*

We invoke Lemma 9.5 with *O ∈* ARO[*F,m,d*], in which ARGinis the Micali SNARK run in the AROM (Corollary 9.3) and AS is the accumulation scheme for AROM queries from Theorem 8.1. This gives a SNARK ARGoutin the AROM for AROM computations. At this point, we could invoke [CCS22, Theorem 9.2] to obtain PCD for constant-depth compliance predicates. However, since ARGouthas straightline knowledge extraction, we can obtain a stronger result: PCD for arbitrary-depth compliance predicates. Given the output of a (cheating) prover P˜, the PCD knowledge extractor receives P˜’s oracle transcript tr, applies ARGout’s straightline knowledge extractor to get the witness ✇, then reconstructs a transcript of the computation based on ✇. Since ARGout’s extractor is straightline, each extraction step has incurs an additive cost. It follows that we obtain PCD in the AROM for all arbitrary-depth polynomial-time compliance predicates. We omit further details about the knowledge extractor as this essentially follows from [CT10]; the main difference is that the SNARK in [CT10] satisfies a stronger knowledge extraction property called “list extraction”. However, our notion of straightline extraction suffices for the [CT10] analysis.

## Acknowledgments

We thank Giacomo Fenzi for pointing out some inaccuracies in an earlier draft of this paper. Tom Gur is supported by the UKRI Future Leaders Fellowship MR/S031545/1 and EPRSC New Horizons Grant EP/X018180/1. Jack O’Connor is supported by the Engineering and Physical Sciences Research Council through the Mathematics of Systems Centre for Doctoral Training at the University of Warwick (reference EP/S022244/1). Megan Chen is supported by DARPA under Agreement No. HR00112020023.

## References

[Alo99] N. Alon. “Combinatorial Nullstellensatz”. In: *Combinatorics, Probability and Computing* 8 (1999), pp. 7–29. [AW09] S. Aaronson and A. Wigderson. “Algebrization: A New Barrier in Complexity Theory”. In: *ACM* *Transactions on Computation Theory* 1.1 (2009), 2:1–2:54. [BCCT13] N. Bitansky, R. Canetti, A. Chiesa, and E. Tromer. “Recursive Composition and Bootstrapping for SNARKs and Proof-Carrying Data”. In: *Proceedings of the 45th ACM Symposium on the Theory of* *Computing*. STOC ’13. 2013, pp. 111–120. [BCFGRS17] E. Ben-Sasson, A. Chiesa, M. A. Forbes, A. Gabizon, M. Riabzev, and N. Spooner. “Zero Knowledge Protocols from Succinct Constraint Detection”. In: *Proceedings of the 15th Theory of Cryptography* *Conference*. TCC ’17. 2017, pp. 172–206. [BCGRS17] E. Ben-Sasson, A. Chiesa, A. Gabizon, M. Riabzev, and N. Spooner. “Interactive Oracle Proofs with Constant Rate and Query Complexity”. In: *Proceedings of the 44th International Colloquium on* *Automata, Languages and Programming*. ICALP ’17. 2017, 40:1–40:15. [BCLMS21] B. Bunz, A. Chiesa, W. Lin, P. Mishra, and N. Spooner. “Proof-Carrying Data Without Succinct ¨ Arguments”. In: *Proceedings of the 41st Annual International Cryptology Conference*. CRYPTO ’21. 2021, pp. 681–710. [BCMS20]B. B unz, A. Chiesa, P. Mishra, and N. Spooner. “Proof-Carrying Data from Accumulation Schemes”. ¨ In: *Proceedings of the 18th Theory of Cryptography Conference*. TCC ’20. 2020, pp. 1–18. [BCTV14] E. Ben-Sasson, A. Chiesa, E. Tromer, and M. Virza. “Scalable Zero Knowledge via Cycles of Elliptic Curves”. In: *Proceedings of the 34th Annual International Cryptology Conference*. CRYPTO ’14. 2014, pp. 276–294. [BDFG21] D. Boneh, J. Drake, B. Fisch, and A. Gabizon. “Halo Infinite: Proof-Carrying Data from Additive Polynomial Commitments”. In: *Proceedings of the 41st Annual International Cryptology Conference*. CRYPTO ’21. 2021, pp. 649–680. [BGH19] S. Bowe, J. Grigg, and D. Hopwood. *Halo: Recursive Proof Composition without a Trusted Setup*. Cryptology ePrint Archive, Report 2019/1021. 2019. [BGV11] S. Benabbas, R. Gennaro, and Y. Vahlis. “Verifiable Delegation of Computation over Large Datasets”. In: *Proceedings of the 31st Annual International Cryptology Conference*. CRYPTO ’11. 2011, pp. 111–

131.
[BMRS20] J. Bonneau, I. Meckler, V. Rao, and E. Shapiro. *Coda: Decentralized Cryptocurrency at Scale*. Cryptol- ogy ePrint Archive, Report 2020/352. 2020. [BN06] M. Bellare and G. Neven. “Multi-signatures in the plain public-Key model and a general forking lemma”. In: *Proceedings of the 13th ACM Conference on Computer and Communications Security*. CCS ’06. 2006, pp. 390–399.

[BR06]

[BR93]

[CCDW20]

[CCS22]

[CFS17]

[CL20]

[COS20]

[CT10]

[CTV13]

[CTV15]

[GK03]

[Gro16]

[GW11]

[HN23]

[JKRS09]

[JLLW22]

[KB23]

[KR08]

M. Bellare and P. Rogaway. “The Security of Triple Encryption and a Framework for Code-Based Game-Playing Proofs”. In: *Proceedings of the 25th Annual International Conference on the Theory* *and Applications of Cryptographic Techniques*. EUROCRYPT ’06. 2006, pp. 409–426.
M. Bellare and P. Rogaway. “Random Oracles Are Practical: A Paradigm for Designing Efficient Protocols”. In: *Proceedings of the 1st ACM Conference on Computer and Communications Security*. CCS ’93. 1993, pp. 62–73.
W. Chen, A. Chiesa, E. Dauterman, and N. P. Ward. *Reducing Participation Costs via Incremental* *Verification for Ledger Systems*. Cryptology ePrint Archive, Report 2020/1522. 2020.
M. Chen, A. Chiesa, and N. Spooner. “On Succinct Non-interactive Arguments in Relativized Worlds”. In: *Proceedings of the 41st Annual International Conference on the Theory and Applications of* *Cryptographic Techniques*. EUROCRYPT ’22. 2022, pp. 336–366.
A. Chiesa, M. A. Forbes, and N. Spooner. *A Zero Knowledge Sumcheck and its Applications*. Cryptology ePrint Archive, Report 2017/305. 2017.
A. Chiesa and S. Liu. “On the Impossibility of Probabilistic Proofs in Relativized Worlds”. In: *Proceedings of the 11th Innovations in Theoretical Computer Science Conference*. ITCS ’20. 2020, 57:1–57:30.
A. Chiesa, D. Ojha, and N. Spooner. “Fractal: Post-Quantum and Transparent Recursive Proofs from Holography”. In: *Proceedings of the 39th Annual International Conference on the Theory and* *Applications of Cryptographic Techniques*. EUROCRYPT ’20. 2020, pp. 769–793.
A. Chiesa and E. Tromer. “Proof-Carrying Data and Hearsay Arguments from Signature Cards”. In: *Proceedings of the 1st Symposium on Innovations in Computer Science*. ICS ’10. 2010, pp. 310–331.
S. Chong, E. Tromer, and J. A. Vaughan. *Enforcing Language Semantics Using Proof-Carrying Data*. Cryptology ePrint Archive, Report 2013/513. 2013.
A. Chiesa, E. Tromer, and M. Virza. “Cluster Computing in Zero Knowledge”. In: *Proceedings of* *the 34th Annual International Conference on Theory and Application of Cryptographic Techniques*. EUROCRYPT ’15. 2015, pp. 371–403.
S. Goldwasser and Y. T. Kalai. “On the (In)security of the Fiat-Shamir Paradigm”. In: *Proceedings of* *the 44th Annual IEEE Symposium on Foundations of Computer Science*. FOCS ’03. 2003, pp. 102–113.
J. Groth. “On the Size of Pairing-Based Non-interactive Arguments”. In: *Proceedings of the 35th Annual* *International Conference on Theory and Applications of Cryptographic Techniques*. EUROCRYPT ’16. 2016, pp. 305–326.
C. Gentry and D. Wichs. “Separating Succinct Non-Interactive Arguments From All Falsifiable As- sumptions”. In: *Proceedings of the 43rd Annual ACM Symposium on Theory of Computing*. STOC ’11. 2011, pp. 99–108.
M. Hall-Andersen and J. B. Nielsen. “On Valiant’s Conjecture: Impossibility of Incrementally Verifiable Computation from Random Oracles”. In: *Proceedings of the 42nd Annual International Conference on* *the Theory and Applications of Cryptographic Techniques*. EUROCRYPT ’23. 2023, pp. 438–469.
A. Juma, V. Kabanets, C. Rackoff, and A. Shpilka. “The Black-Box Query Complexity of Polynomial Summation”. In: *Computational Complexity* 18.1 (2009), pp. 59–79.
A. Jain, H. Lin, J. Luo, and D. Wichs. *The Pseudorandom Oracle Model and Ideal Obfuscation*. Cryptology ePrint Archive, Paper 2022/1204. 2022.
A. Kattis and J. Bonneau. “Proof of Necessary Work: Succinct State Verification with Fairness Guarantees”. In: *Proceedings of the 27th Financial Cryptography and Data Security*. FC ’23. 2023.
Y. Kalai and R. Raz. “Interactive PCP”. In: *Proceedings of the 35th International Colloquium on* *Automata, Languages and Programming*. ICALP ’08. 2008, pp. 536–547.

[KST22] A. Kothapalli, S. Setty, and I. Tzialla. “Nova: Recursive Zero-Knowledge Arguments from Folding Schemes”. In: *Proceedings of the 42nd Annual International Cryptology Conference*. CRYPTO ’22. 2022, pp. 359–388. [Mic00] S. Micali. “Computationally Sound Proofs”. In: *SIAM Journal on Computing* 30.4 (2000). Preliminary version appeared in FOCS ’94., pp. 1253–1298. [Mina]O(1) Labs. *Mina Cryptocurrency*. https://minaprotocol.com/. 2017. [NT16] A. Naveh and E. Tromer. “PhotoProof: Cryptographic Image Authentication for Any Set of Permissible Transformations”. In: *Proceedings of the 37th IEEE Symposium on Security and Privacy*. S&P ’16. 2016, pp. 255–271. [TFZBT22] N. Tyagi, B. Fisch, A. Zitek, J. Bonneau, and S. Tessaro. “VeRSA: Verifiable Registries with Efficient Client Audits from RSA Authenticated Dictionaries”. In: *Proceedings of the 29th ACM Conference on* *Computer and Communications Security*. CCS ’22. 2022, pp. 2793–2807. [Val08] P. Valiant. “Incrementally Verifiable Computation or Proofs of Knowledge Imply Time/Space Ef- ficiency”. In: *Proceedings of the 5th Theory of Cryptography Conference*. TCC ’08. 2008, pp. 1–

18.
[Zha22] M. Zhandry. “Augmented Random Oracles”. In: *Proceedings of the 42nd Annual International Cryp-* *tology Conference*. CRYPTO ’22. 2022, pp. 35–65.
