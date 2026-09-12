∗

# Speeding Up Sum-Check Proving (Extended Version)

### Quang Dao

†

### Zachary DeStefano

‡

### Suyash Bagad

§

### qvd@andrew.cmu.edu zd2131@nyu.edu suyash@ingonyama.com Yuval Domb

§

### Justin Thaler

¶

### yuval.domb@gmail.com justin.r.thaler@gmail.com March 24, 2026

Abstract

The sum-check protocol is a foundational primitive in modern cryptographic proof systems, but its prover-side cost has emerged as a concrete bottleneck. This paper introduces three complementary techniques that significantly reduce sum-check proving time and memory, especially in the context of zero-knowledge virtual machines (zkVMs). First, for applications involving products of many multilinear polynomials, we develop a new algorithm that significantly reduces the number of field multiplications required for proving. Second, we develop a “small-value sum-check prover” algorithm. This significantly speeds up the prover in the common setting where the polynomials being summed evaluate to 64 or 32-bit integers, or to elements of a small sub-field within a larger extension field. Even outside of the small-value setting, this algorithm yields a faster “streaming prover”, by which we mean a small-space algorithm that applies whenever the terms being summed can be enumerated in small space (as arises, for example, in zkVM applications). Third, we nearly eliminate prover overhead in the ubiquitous case where one factor is an equality polynomial by exploiting its decomposable tensor structure. We implement these techniques in Jolt, a state-of-the-art zkVM, and evaluate their performance. In Jolt, we observe over an order of magnitude runtime speedup and memory reduction on the Spartan sub-protocol, and 1*.*7*×*–2*.*2*×*speedups for a key high-degree sum-check sub-protocol in the Shout batch- evaluation argument.

## 1 Introduction

The sum-check protocol [41] is a fundamental tool in the design of succinct proof systems. When run inter- actively, it is an information-theoretically sound method for verifying claims of the form X *g*(*x*) =*t,* *x∈{*0*,*1*}ℓ*

where*g*is a multivariate polynomial of individual degree*d*over a finite fieldF. From the verifier’s perspective, the protocol reduces the expensive task of summing 2 *ℓ* evaluations of*g*to the much cheaper task of evaluating *g*at a single random point inF *ℓ*. In many applications*g*factors as a product of*dmultilinear*polynomials; this is the case we consider throughout. When used in succinct non-interactive arguments of knowledge (SNARKs), the sum-check protocol gener- ally*minimizes*the amount of data the SNARK prover must commit to cryptographically, and*also*minimizes the time required to prove that this committed data is well-formed. Because of these features, the sum-check ∗ This manuscript directly combines and improves upon results from prior work [8, 23]. † Carnegie Mellon University ‡ New York University § Ingonyama ¶ a16z crypto research and Georgetown University

protocol now underpins SNARKs for arithmetic circuit satisfiability [30, 63, 65], R1CS [49], Plonkish and CCS [14, 52], the fastest lookup arguments [51, 53], polynomial commitment schemes [4, 25, 26, 45], folding schemes [11, 37, 38, 12, 44], and zero-knowledge virtual machines (zkVMs) like Jolt [5], SP1 Hypercube [55], and Ceno [40]. The sum-check protocol is so effective at reducing cryptographic costs that its own proving time and memory have become a major bottleneck in many proof systems.

Overhead of large-field arithmetic.The security of the sum-check protocol is directly related to the size of the finite fieldFover which it operates. For non-interactive security, the sum-check protocol needs to operate over fields of at least*λ*= 128 bits, with many systems (such as Jolt) requiring 256-bit fields to support elliptic curve-based polynomial commitments. This leads to a large overhead: a single 256-bit field multiplication requires 40-100 CPU cycles [66]. For additional details on the necessity of large fields, see Appendix F.

*ℓ* Time-space tradeoffs for sum-check algorithms.Let*M*= 2 be the size of the sum being proved. The fastest proving algorithms for products of multilinear polynomials [61, 58] perform a number of field operations that scales linearly with*M*; however, these algorithms also require linear space (i.e., storing Θ(*M*) field elements). In practice, when*M*can be on the order of billions, the memory requirements of these algorithms can be prohibitive. There are low-memory alternatives, called streaming algorithms, which use significantly less space at the cost of superlinear time. The best streaming algorithm, recently introduced by Baweja et al. [10], uses */k* *O*(*M¹*) space and*O*(*M*log log*M*) time for any constant*k*whenever*d*is a small constant (i.e., 3 or smaller). However, as*d*increases, this algorithm rapidly approaches the performance of a prior streaming algorithm [21] that costs*O*(*d²M*log*M*) time and*O*(*d*+ log*M*) space. For realistic values of*M*, this is more than an order of magnitude slower than the linear-time algorithm. To summarize, recall that we are considering applications of the sum-check protocol to a product of*d* multilinear polynomials over a*λ*-bit fieldF. In a crude model where a field multiplication costs one unit and linear space is allowed, the “linear-time” sum-check proving algorithm [61, 58] is essentially optimal for small*d*like*d*= 2 or*d*= 3. In practice, however, field multiplications dominate proving time (and, even asymptotically, a*λ*-bit field multiplication should not be regarded as a unit-cost operation). On top of this, moving to a sublinear-space proving algorithm results in a time penalty. Moreover, handling high*d*is important in some modern proof systems. For example, the Shout [51] batch-evaluation argument used in Jolt [5, 2], as currently configured, invokes a sum-check protocol with a configurable degree*d*that can be up to 32. This makes efficient prover support for high-degree sum-checks important in practice. A major goal and focus of our work is to speed up the Jolt zkVM prover [5, 2] as much as possible. Jolt is a state-of-the-art zkVM that is simple and fast, relying entirely on various sum-check instances for its information-theoretic core (the PIOP), together with a polynomial-commitment layer. When proving programs with large trace lengths (say 1 billion cycles), the Jolt prover spends about 65*−*70% of its time on sum-checks, making it a major bottleneck. While this is the main motivation, we also stress that our techniques apply to a broad range of applications of the sum-check protocol in SNARK design, including the fastest SNARKs for circuit- and constraint- satisfaction, such as Spartan [49, 1] and its variants like Binius64 [57] (which applies SuperSpartan, a SNARK for Customizable Constraint Systems [52], over binary fields using (FRI-)Binius [25, 26] as the polynomial commitment scheme). An earlier version of this manuscript appeared in prior work [7]. The present extended version reorganizes and expands that presentation, and directly combines and improves upon results from prior work [8, 23].

### 1.1 Our results

This work presents a variety of prover-side optimizations for sum-check that, except for one (univariate skip 1 (Section 7)), leave the protocol, verifier, and soundness unchanged. The techniques we introduce are com-

Univariate skip, first introduced by Gruen [33], modifies the protocol but still remains sound.

Algorithm Time Space

LinearTime[61, 58]*d²M dM* OptLinearTime (*d*log*d*)*M dM*

LogSpace[21]*d²M*log*M d*+ log*M* CrossProduct*k*[10]*d²M*(*k*+ log log*M*)*M¹* */k* EvalProductStream*k*(*d*log*d*)*M*(*k*+ log log*M*) *M¹* */k*

Table 1: Generic-setting prover asymptotic costs (*M*=2

*ℓ* ), counted in terms ofbb(i.e., big-big) field multi- plications. In all cases, the constants hidden by the asymptotics are concretely small.

plementary to each other, and exploit structural properties common in sum-check applications, such as small polynomial evaluations, long-running sums of products, high-degree products, and equality polynomials.

Faster field arithmetic via small-value specialization and delayed reduction.In Section 3, we observe that while computing the product of two arbitrary finite field elements is expensive, when one or both elements are small interpreted as integers (e.g., storable in a single 64-bit or 32-bit machine word), it is possible to compute their product significantly faster. We then generalize these techniques to the efficient computation of linear combinations (and, more generally, low multiplicative depth circuits) over the appropriate finite field. Our techniques improve efficiency by allowing intermediate values to exceed the field size, deferring modular reduction until the end of the operation sequence. 2

We provide explicit procedures for small-small, small-big, and big-big multiplications, where the latter refers to standard finite field multiplication.

High-degree sum-check speedups.In Section 4, we apply this observation to the problem of efficiently computing the product of*d*multilinear polynomials, each in*v*variables. This computation is a core subroutine in all known sum-check proving algorithms and dominates their runtimes. The most concretely efficient prior baseline is the naive algorithm that performs*O*(*d* *v*+1 ) (big-big) mul- tiplications to compute this product by directly evaluating the product at (*d*+ 1) *v* points. We lower this cost to*O*(*d* *v* +*d*log*d*) (big-big) multiplications with a concretely small constant. In the univariate case of*v*= 1, this is an improvement from*O*(*d²*) to*O*(*d*log*d*) multiplications, while for*v >*1, this is an improvement by a factor of*d*over the naive algorithm. 3 For large*d*used in practice, such as*d*= 16 or*d*= 32, this yields substantial concrete speedups: up to about 2*.*5*×*in our high-degree kernel microbenchmarks, and about

1*.*7*×*–2*.*2*×*in Jolt’s read-access (RA) virtualization sum-check benchmark (see§9). This approach is inspired by a suggestion of Ben Diamond [24]; however, making the idea concretely efficient requires a routine to efficiently extrapolate from a small set of evaluation points to a larger set. Our contributions here consist of generalizing the approach to the multivariate setting and making it concretely efficient, by optimizing the extrapolation step with a mix of specialized field operations and optimal multi- addition chains. Improved speed/memory tradeoffs.In Section 5, we work at the granularity of full sum-check prover algorithms, combining the techniques above with additional algorithmic insights to improve prover perfor- mance across the time-space tradeoff spectrum. Table 1 summarizes our results against prior work. Streaming algorithms typically group the rounds of the sum-check protocol into epochs called windows and amortize the cost of computing the prover’s messages over all rounds within a window [21, 10]. When using a window size of*k*rounds, our improvement over prior work [10] comes from working with (*d*+ 1)
*k*

evaluations, rather than*O*((2 *d* ) *k* ) terms used to compute the coefficients of intermediate polynomials. We show that computing these evaluation points can be structured as a recursive polynomial multiplication problem, similar to the high-degree optimization above, allowing speedups using techniques similar to the Toom-Cook multiplication algorithm [18, 60].

While the delayed reduction technique is not new and has been used in other contexts, our work is the first time it has applied to speed up sum-check proving, yielding a substantial speedup for all existing sum-check algorithms ( Section 3). The lower-order (sb/addition) work is*O*(*dv*+1), which is dominated by thebbsavings for all practical values of*d*.

Small-value sum-check optimizations.When the underlying multilinear polynomials in the sum-check protocol have small evaluations (as is common in zkVMs), we further reduce the number of expensive big-big multiplications in this algorithm. Here, we say informally that an*ℓ*-variate multilinear polynomial*p*has small evaluations if, for all*x∈{*0*,*1*}* *ℓ* ,*p*(*x*) can be specified with significantly fewer bits than arbitrary elements ofF. This includes, for example, values in*{*0*,*1*,...,*2 64 *−*1*}*when working over a 128- or 256-bit prime field, or values in a 32- or 64-bit subfield of a larger extension field. The key insight is that the first few rounds of the sum-check prover make up the vast majority of the prover’s work, and in these rounds only a handful of random field elements arise—all other values in the prover’s computation within these rounds are small. By working with evaluation points, rather than coefficients, it is possible to replace a significant fraction of big-big multiplications with much cheaper small- small and small-big multiplications. The resulting prover time improvements are substantial*for alld, even* *d*= 2, and even in non-streaming (i.e., linear-space) contexts.

Handling decomposable polynomials for free.In practice, some of the multilinear polynomials in the sum-check protocol have a specific*decomposable*structure. That is they can be expressed as a product of univariate polynomials. One common example is the equality polynomial

Y *ℓ* eqe (*W,X*) = (*Wi·Xi*+ (1*−Wi*)*·*(1*−Xi*))*,* *i*=1

with randomly chosen*W∈*F *ℓ*, which is nearly ubiquitous in sum-check applications. In Section 6, we show how to leverage this structure in the streaming setting, to nearly eliminate all overheads from this polynomial factor. This decomposability allows for unique amortization strategies. This structure was previously exploited by Gruen [33]; however, our techniques are distinct and complementary. 4 The key insight involves rewriting the sum-check messages as iterated sums, which allows the prover to compute small tables of values that can be reused across rounds of the protocol.

Implementation and evaluation.We have implemented these techniques and integrated them into the Jolt zkVM (§8). 5 Our experimental evaluation (§9) shows substantial microbenchmark speedups that carry over to end-to-end prover performance. In Jolt’s Spartan outer benchmarks, our most optimized variant (using univariate skip, which trades faster proving for a higher-degree verifier interpolation step) reaches

10*.*9*×*runtime speedup over an unoptimized baseline (with none of our optimizations in this paper), and up to 17*.*5*×*lower isolated peak memory; at memory-bottleneck scales, runtime speedup grows up to 57*.*9*×*. In Shout’s read-access virtualization sum-check, we observe 1*.*7*×*–2*.*2*×*speedups across various configurable degree settings.
### 1.2 Related work

Sum-check’s central role in modern SNARKs has spurred extensive prover-side optimizations. We review prior work, spanning general techniques and setting-specific variants.

Sum-check origins.The sum-check protocol was introduced by Lund, Fortnow, Karloff, and Nisan [41] as a key component in an interactive proof for #Pand laterPSPACE[54]. The provers in these protocols took superpolynomial time even when applied to very simple problems (e.g., those solvable in logarithmic space). The sum-check protocol was later harnessed by Goldwasser, Kalai, and Rothblum (GKR) [30], who used it to construct an interactive proof for any arithmetic circuit of polylogarithmic depth and polynomial size, with a prover that runs in polynomial time. 4 See also a small variation proposed by Setty and Thaler [51] that avoids altering the prover’s message in each round of sum-check. 5 See[https://github.com/quangvdao/jolt/tree/zkproof-submission](https://github.com/quangvdao/jolt/tree/zkproof-submission).

Linear time proving.The linear-space implementations of Vu et al. [61] and Thaler [58] are what is colloquially called the “linear-time” sum-check prover when applied to a product of multilinear polynomials. Cormode, Thaler, and Yi [21] gave a space-efficient variation that runs in quasilinear time using only loga- rithmic space. The name “linear-time” stems from the fact that, for fixed*d*, the prover performs*O*(*M*) field operations, where*M*= 2 *ℓ* is the size of the summation domain. We follow the conventional name “linear- time”, though the dependence on*d*is crucial in practice and is a focus of our work, as is the difference between big-by-big field multiplications compared to big-by-small or small-by-small. These algorithms have since been refined and deployed in a variety of systems. For example, they were used in a long line of works to implement linear-time variants of the GKR protocol [20, 61, 58, 62, 63, 68, 65, 67]. They also form the prover backbone in Spartan [49], which is itself a major component of the Jolt zkVM [5]. A line of works has also applied the sum-check protocol to obtain efficient memory-checking arguments, meaning a way of forcing an untrusted prover to correctly process reads and writes to a large memory (or just reads, in the case of read-only memories) [69, 50, 53]. Most recent in this line of work is Twist and Shout [51].

Low-memory proving.Baweja et al. [10] implement the sum-check prover (applied to a product of a constant number of multilinear polynomials) in sublinear space and slightly superlinear time (i.e., in *O*(*M·*log log*M*) field operations and using space*M¹* */k* for any constant integer*k >*1, where*M*= 2 *ℓ* is the size of the sum being computed). Assuming natural conjectures, Baweja et al. also prove a matching lower bound of Ω(*M*log log*M*) field multiplications for the sum-check prover applied to a product of two multilinear polynomials when using sublinear space. This lower bound in terms of*M*also applies to our improvement of their streaming algorithm; we improve upon the asymptotic dependence on the degree instead.

Delayed reduction.The idea of postponing modular reduction to a canonical field representation when performing many operations sequentially (often referred to as “lazy reduction”) is a well-known optimization in pairing-based cryptography [47, 3, 48], and is used in practice in many high-performance elliptic curve and SNARK implementations (e.g.,blst[56] andgnark-crypto[16]) to optimize extension field arithmetic and multi-scalar multiplications. Our contribution is to systematically apply this insight to the core linear combinations and low-degree polynomial evaluations of the sum-check protocol, where it combines with small-value arithmetic to yield substantial speedups. We describe the delayed reduction principle and its applications in detail in§3.

Gruen’s optimizations.A recent work of Gruen [33] also seeks to optimize the sum-check prover and focuses on the case where the protocol is performed over fields of small characteristic. Two of the optimizations in that work are relevant to us. The first is useful when summing a product of multilinear polynomials one of which is decomposable. Gruen’s optimization in this setting is complementary to our own, and is discussed in more detail in Section 6. The second is the univariate-skip technique itself, which targets the same small- value regime as ours but modifies the protocol and increases the degree of the first-round prover polynomial; we revisit this tradeoff in Section 7. Our small-value optimizations do not have any of the above limitations, instead applying “as is” to existing sum-check-based SNARKs, yielding functionally equivalent implementations (i.e., the SNARK verifier is unchanged).

Structured sum-check protocols.The*sparse-dense sum-check*prover algorithm [53] achieves a gen- eral time-space tradeoff, running in*O*(*cM*) time and*O*(*M¹* */c* ) space for any integer*c >*0, but applies only to structured sum-check instances, involving the product of an arbitrary multilinear polynomial and a structured multilinear polynomial. Its refinement, the*prefix-suffix inner product*algorithm [43], further generalizes applicability and improves efficiency for these structured scenarios. Jolt employs these protocols where possible for efficiency; however, their applicability is limited to specific structured sum-check instances (they do not apply to many sum-check instances in Jolt, including those in Spartan).

Concurrent work.As mentioned above, after the release of an initial version of our results [8, 23], Nair, Thaler, and Zhu [43] described an efficient small-space implementation of the Jolt prover (without invoking

SNARK composition or recursion), whose concrete efficiency benefits substantially from our optimizations. Two recent works also focus on the sum-check protocol applied in the small-characteristic setting. Liu and Zhang [39] focus on the setting of binary tower fields, building on a technique of Dao and Thaler [22] to give a sum-check prover algorithm for products of*d*Boolean-valued multilinear polynomials. However, for the most common settings of*d*, namely*d∈{*2*,*3*}*, their algorithm is asymptotically slower than ours, and no implementation is provided. Wei et al. [64] obtain a fast sum-check prover implementation by combining parallel repetition with NeutronNova’s [38] “sumfold” scheme that reduces many independent instances of the sum-check protocol to a single one.

## 2 Preliminaries

Notation.We index vectors from 1, and denote ranges using bracket notation as: [*a,b*] :=*{a,...,b}*,
[*n*] :=*{*1*,...,n}*, [*< i*] :=*{*1*,...,i−*1*}*, and [*> i*] :=*{i*+ 1*,...,n}*(where*n*is assumed to be clear from
context).*Ud*is shorthand for the set*{∞,*0*,*1*,...d−*1*}*and *U*c*d*:=*Ud\{*0*}*is the set*{∞,*1*,...d−*1*}*. We write
P*ℓ* *i−*1 *ℓ* nat*b*(*x*) :=*i*=1*xi·b* to refer to the natural number in base*b*corresponding to the vector*x∈*[0*,b−*1], abbreviatingnat(*x*) when*b*= 2.

### 2.1 Finite fields

SNARKs that use elliptic curve-based polynomial commitments need to operate over large prime fieldsF*p* of roughly 256 bits; examples include the scalar fields of the BN254, secp256k1, or BLS12-381 curves. On 64-bit architectures, elements of such fields are represented as*N*= 4*limbs*of 64-bit unsigned integers. To accelerate multiplication, field elements are typically stored in*Montgomery form*[42]. An element*a∈*F*p*is represented as*a* *′* =*aR*(mod*p*), where*R*= 2 64*N* is a power of two, chosen so that multiplication or division by*R*amounts to very cheap bit shifts. Multiplying two elements*a* *′* *,b* *′* in Montgomery form involves two steps. First, a large-integer multiplica- tion computes*c*=*a* *′* *·b* *′*, a 2*N*-limb integer, at a cost of*N²* native multiplications. Second, a Montgomery reduction computes*cR* *−*1 (mod*p*) to return the product to Montgomery form, costing an additional*N²*+*N* native multiplications. 6 The total cost for a field multiplication is thus approximately 2*N²* +*N*native mul- tiplications and a similar amount of additions, translating to around 50-100 CPU cycles when*N*= 4 [66] (see Appendix G for further details). *Barrett reduction*[9] is another common technique for modular reduction which does*not*perform the division by*R*. An optimized implementation gives the same number of multiplications as Montgomery reduction, but with a larger number of conditional subtractions, and thus is slower in practice. Because of this, most field arithmetic libraries use Montgomery representation for large prime fields Hash-based SNARKs often use*∼*128-bit*extension fields*F*pk*, which are*k*-dimensional vector spaces over a base fieldF*p*. Extension field elements can be represented as vectors over the base field, relative to a chosen basis. A standard*monomial basis*represents elements as polynomials of degree less than*k*, with multiplication performed modulo a degree-*k*irreducible polynomial. When*k*= 2 *τ* is a power of two, a*tower* *basis*can be used, constructed from a sequence of iterated quadratic extensions. For both bases, multipli- cation in the extension field costs*O*(*k* log23 )*≈O*(*k¹*

*.*585 ) multiplications in the base field via Karatsuba’s
algorithm [36]. Prominent examples include the degree-4 tower extension of the 31-bit BabyBear prime field and the degree-128 tower extensionGF(2 128 ) of the binary fieldGF(2), used in systems like Binius [25].

### 2.2 Multilinear polynomials

We state some facts about multilinear polynomials needed in our paper. See standard references, e.g. [59], <u>for derivations.</u> 6 It is possible to reduce the multiplication count to*N*2+ 1 [27], but this may not always yield a practical speedup due to an increased number of conditional branches.

Multilinear extension.An*ℓ*-variate polynomial*p*is*multilinear*if it has degree at most 1 in each variable. The*multilinear extension*of a function*f*:*{*0*,*1*}* *ℓ* *→*Fis the*unique*multilinear polynomial*p*such that *p*(*x*) =*f*(*x*) for all*x∈{*0*,*1*}* *ℓ*. In particular, the*equality polynomial* eqe defined as

Y *ℓ* eqe (*X,Y*) = (*Xi·Yi*+ (1*−Xi*)*·*(1*−Yi*)) (1) *i*=1

? *ℓ ℓ* is the multilinear extension of the*equality function*(*·* =*·*) :*{*0*,*1*} ×{*0*,*1*} →{*0*,*1*}*, as we can verify that ( 1 if*x*=*yℓ* eqe (*x,y*) =*,*for all*x,y∈{*0*,*1*}.* 0 otherwise

Lemma 1.*Letp*:F *ℓ* *→*F*be a multilinear polynomial. Then for any*0*≤i≤ℓ, any*(*r₁,...,ri*)*∈*F *i* *, and* *anyx* *′* *∈{*0*,*1*}* *ℓ−i* *,* X *p*(*r₁,...,ri,x* *′* ) = eqe ((*r₁,...,ri*)*,y*)*·p*(*y,x* *′*

)*.*(2)
*y∈{*0*,*1*}i*

Setting*i*= 1, Equation (2) simplifies to

*p*(*r₁,x* *′* ) = (1*−r₁*)*·p*(0*,x* *′* ) +*r₁ ·p*(1*,x* *′*

)*.*(3)
Setting*i*=*ℓ*, we get the*multilinear extension*formula X
*p*(*r₁,...,rℓ*) = eqe (*r₁,...,rℓ,y*)*·p*(*y*)*.*(4)
*y∈{*0*,*1*}ℓ*

Lagrange interpolation.A (univariate) polynomial*s*(*X*) of degree*d*is uniquely determined by its values at*d*+ 1 distinct evaluation points*U*=*{x₀,...,xd}⊂*Fvia the*Lagrange interpolation*formula:

X*d*Y <u>X−x</u> <u>j</u> *s*(*X*) = *s*(*xi*)*·LU,i*(*X*)*,*where*LU,i*(*X*) =*.*(5) *i*=0 *j̸*=*i* *xi−xj*

In our algorithms, we use a standard variant of Lagrange interpolation that takes into account the “evaluation at infinity” of a polynomial, defined as*s*(*∞*) := the highest-degree coefficient of*s*(*X*).

Lemma 2.*Lets*(*X*) =*a·X* *d* +*···∈*F[*X*]*be a polynomial of degreed. Then for any distinct evaluation*
*pointsx₁,...,xd∈*F*, settingU*=*{∞}∪{x₁,...,xd}, we have the identity:*

Y *d*X*d* *s*(*X*) =*a·* (*X−xk*) + *s*(*xk*)*·L{xi},k*(*X*)*.*(6) *k*=1 *k*=1 Q*d* *Thus, we can defineLU,*0 *k*=1 *k U,k {xi},k*

||(X) :=||(X−x )andL|(X) :=L|(X)fork∈[d].|
|---|---|---|---|---|---|
|ℓ|U,0 ℓ|k=1 ℓ d|k ℓ|U,k|{x},k|

Streaming model.For all streaming algorithms, we assume that the evaluations*p₁*(*x*)*,...,pd*(*x*) for *x∈{*0*,*1*}* can be enumerated in linear time and small space, in lexicographic order (either little- or big- endian) from*x*= 0 to*x*= 1. This holds in many applications, since*p₁,...,pd*are typically the multilinear extensions of functions*f₁,...,f* :*{*0*,*1*} →*F, whose evaluations over the Boolean hypercube can themselves be enumerated in linear time and small space (for example, when they are derived from the execution trace of a virtual machine).

Setup:Assume that the verifier has oracle access to the polynomial*g*, and knows the value*C₀* claimed to equal X *g*(*x*) =*C₀.* *x∈{*0*,*1*}ℓ*

#### For each roundi= 1,...,ℓ:

1.*P*sends the univariate polynomial*si*(*X*) claimed to equal
X

|||g(r₁,...,r|,X,x|
|---|---|---|---|
|(x ,...,x i|)∈{0,1} i|d||
|i||i i|i|

*i−*1 *i*+1*,...,xℓ*)*.* (*xi*+1*,...,xℓ*)*∈{*0*,*1*}ℓ−i*

*P*does so by sending the evaluations*{s* (*u*) : *u∈ U*b*}*to*V*.

2.*V*sends a random challenge*r ←*Fto*P*.
3.*V*derives*si*(0) :=*Ci−*1*−s* (1), then sets*C* :=*s* (*r*). After*ℓ*rounds, we reduce to the claim that
*g*(*r₁,...,rℓ*) =*Cℓ.*

<u>Vchecks this claim by making a single oracle query tog.</u>

Figure 1: The sum-check protocol

### 2.3 The sum-check protocol

In Figure 1, we describe the sum-check protocol that reduces checking a claim of the form X *g*(*x*) =*C,* *x∈{*0*,*1*}ℓ*

for a polynomial*g*of degree at most*d*in each variable over fieldF, to checking the evaluation of*g*at a random point*r∈*F *ℓ* : *g*(*r*) =*v*. We assume that*g*is a product of*d*multilinear polynomials*p₁,...,pd*; by linearity, existing algorithms can be straightforwardly extended if*g*is any degree-*d*function of multilinears. In each round*j*, the honest prover sends a univariate polynomial*sj*of degree*d*. As any degree-*d*univariate polynomial is specified by its evaluations on any set of*d*+ 1 points, computing*sj*(*c*) for all*c∈ {∞}∪*

|j 7|||j|
|---|---|---|---|
||j|j−1 j||

*{*0*,*1*,...,d−*1*}*suffices to uniquely specify*sj*. 7 In fact, the prover can omit the evaluation*sj*(0), and instead let the verifier derive it from the previous round using the equation*s* (0) =*C −s* (1), which holds for an honest protocol execution.

Theorem 3.*The sum-check protocol applied to a polynomialgof individual degree at mostdis perfectly* *complete and has soundness error ofdℓ/|*F*|.*

See, e.g., [59] for a proof of this standard result, attributed to Lund, Fortnow, Karloff, and Nisan [41]. 8

Linear-time algorithm for sum-check proving.We recall the linear-time algorithm from prior work [21, 61, 58], which runs in time linear in the instance size*M*= 2 *ℓ*. The key idea is that we “bind” the polynomial after each round to this round’s verifier challenge*ri*. After each round*i*, it uses the verifier’s challenge*ri* to compute and cache the partial evaluations*pk*(*r₁,...,ri,x* *′* ) for all*k∈*[*d*] and*x* *′* *∈{*0*,*1*}* *ℓ−i*. This cache, 7 We assume a mapping from*{*0*,*1*,...,d−*1*}*to distinct field elements. For large enough prime fields, these integers are naturally identified with their corresponding field elements. For binary extension fields, a natural choice is to use those whose binary representation (in the chosen basis) matches that of each integer. Not only does the sum-check protocol have soundness error at most*dℓ/|*F*|*, it satisfies a stronger property: it has*round-* *by-round soundness*at most*d/|*F*|*in each round. This ensures that the protocol remains secure (in the random oracle model) even after it is rendered non-interactive via the Fiat-Shamir transformation. See [13] for details.

which halves in size each round, allows for efficient computation of the next round’s polynomial in only *O*(*d² ·*2 *ℓ−i* ) time. The total runtime is*O*(*d² ·*2 *ℓ* ). See Section C for a full description and cost analysis of LinearTimeSC, along with full descriptions of two prior streaming algorithms [21, 10].

## 3 Non-black-box field arithmetic

The implementation of arithmetic operations in a finite field is typically treated as a black-box: given two field elements, one can add, subtract, multiply, or divide them. These operations can broadly be decomposed into two discrete steps. First, the field elements are treated as integers (or polynomials) and the corresponding integer (or polynomial) operation is performed. This results in a*non-reduced*integer (or polynomial). Second, the result is*reduced*to obtain a valid canonical representation of the resulting field element. By opening up this black box, we identify a variety of techniques that involve modifying, deferring, or batching reductions across multiple operations. The first of these is a more efficient algorithm for multiplying two field elements when one of them is “small” when interpreted as an integer (i.e., fits into a single machine word). The second of these is a*delayed*(also known as*deferred*, or*lazy*) reduction technique, where we minimize the number of (Barrett or Montgomery) reductions in a long-running sequence of field operations. As mentioned in Section 1.2, we stress that this technique is not new, but to the best of our knowledge ours is the first time this technique is systematically applied to sum-check.

### 3.1 Multiplying with small integers

As discussed in§2.1, multiplying two*N*-limb field elements in Montgomery form involves 2*N²* +*N*native multiplications. However, when one of the operands is a small integer that fits into a single limb (e.g., a 64-bit integer), we can employ a more direct and efficient method. Instead of converting the small integer to Montgomery form, we can:

1.Multiply the multi-limb integer representation of the field element by the small integer directly. This large integer (bignum) multiplication costs only*N*native multiplications.
2.Apply a single, optimized pass of Barrett reduction to the (*N*+ 1)-limb result to perform the modular reduction. This costs an additional*N*+ 1 native multiplications.
This optimized approach reduces the total cost from 2*N²* +*N*to 2*N*+ 1 native multiplications, which in practice is about a 2-3*×*speedup for a*∼*256-bit field. We give details in Appendix B.1. To distinguish types of multiplications, we use the following notation. A multiplication of two (big) field elements is denoted as a*big-big multiplication*(bb). A multiplication of a small field element (i.e., a machine integer) with a big field element is denoted as a*small-big multiplication*(sb). Finally, a multiplication of two small field elements (i.e., two machine integers) is denoted as a*small-small multiplication*(ss). When we discuss the complexity of various algorithms, we will focus on the number ofbboperations as the dominant cost, while also accounting forsbandssoperations as secondary costs when relevant.

### 3.2 Small value arithmetic over tower fields

An analogue of small-value arithmetic is also available for tower fields. Recall from§2.1 that a tower field Fis constructed as a series of quadratic extensions over a base fieldB, denotedB*⊂*B

(1) *⊂···⊂*B
(*ℓ*) =F,
where eachB

(*j*) is a degree-2 extension ofB
(*j−*1). This recursive structure allows for two benefits (already exploited in prior work [25, 26]):

1.Compressed subfield representation:An element*x∈*B
(*j*) is, by construction, a linear combination
of the first 2 *j* basis vectors ofFoverB. Thus, it can be represented using only 2 *j* elements fromB.

(*j*) (*j*
*′* )

2.Fast subfield multiplication:To multiply an element*x∈*B by an element*y∈*B (with *′* (*j −*
*′*

1)
*j < j*), we can leverage the recursive structure. We view*y*as*y₀* +*y₁α*, where*y₀,y₁ ∈*B. The product*x·y*= (*x·y₀*) + (*x·y₁*)*α*becomes two recursive multiplications of an element inB

(*j*) by
(*j −* *′*

1) *j −j*
*′* elements inB. This recursive definition leads to a multiplication algorithm that costs only 2 multiplications in the subfieldB

(*j*).

These properties allow operations on subfield elements to be treated as a form of small-value arithmetic, yielding significant performance gains. Further details are in Appendix B.

### 3.3 Delayed reduction

Instead of focusing on a single field multiplication, we turn to computing a linear combination of field elements, specifically a dot product between a vector of small integers and a vector of large field elements. An efficient primitive of this form is particularly useful when applied to the sum-check protocol, as described in Sections 4 and 5. P*k* Formally, consider computing the linear combination*S*=*i*=1*ci·ai*(mod*p*), where each*ci*is a 64-bit unsigned integer and each*ai*is a large field element in Montgomery form. A black-box approach would involve*k*bbmultiplications. Using our newsbmultiplication primitive, this can be improved to*k*sbmultiplications. However, in the spirit of opening the black-box further, the modular reduction in each of thesesbmultiplications can be deferred to the end as a single modular reduction operation. The full procedure is the following. First, compute the integer product*T* where each

|||=c ·a|T is an|
|---|---|---|---|
|||i i i|k i|
||||i=1 i|
|k i=1 i|64|||

P integer of at most*N*+ 1 limbs. Then, sum these integer products to get an integer total*T*= *T*. If the P coefficient sum satisfies *c <*2, then*T*still has at most*N*+ 1 limbs and the specialized single-pass Barrett reduction from Appendix B applies directly. More generally, if the accumulated coefficient growth needs one extra limb, then*T*has at most*N*+ 2 limbs and one should either widen the final reduction routine or reduce in batches. Finally, perform a single Barrett reduction on*T*to compute*S*=*T*mod*p*. This approach amortizes the cost of modular reduction, requiring only*k*small-big (integer) multiplications (at*N*native multiplications each) plus one final reduction (at*N*+ 1 native multiplications), for a total of *k·N*+ (*N*+ 1) native multiplications. This is nearly a 2*×*improvement over an approach that uses rawsb multiplications, and a far larger improvement over an approach which treats field multiplication as a black box. This primitive can be further adapted to support cases where*ci*can be: (i) larger (say 128-bit unsigned integers), or (ii) negative. The first case is handled straightforwardly by adapting the number of limbs used in the intermediate integer representation. The second involves splitting the sum into positive and negative terms, computing the positive and negative integer linear combinations, taking the difference of the result, and finally performing a Barrett reduction.

Delayed reduction in field extensions.This technique of delaying reductions also applies to field extensions with some modifications, though we do not specifically implement or benchmark this extension in this work. In this setting, say one has an extensionF*p*[*X*]*/*(*f*(*X*)) for a degree-*κ*irreducible polynomial*f*. The multiplication of two extension field elements begins with a multiplication of two degree-(*κ−*1) polynomials to produce a polynomial of degree at most 2*κ−*2. This step typically involves*κ²* base-field multiplications. Then polynomial division by*f*is performed to produce an extension field element. There are two types of reductions happening here: (i) reductions on the base field elements themselves (in the base field multiplications) and (ii) a final polynomial reduction (taking remainder when divided by

*f*). It is possible to delay both types of reductions by working with a “long” representation. In this setting, a linear combination will consist of up to 2*κ−*1 coefficients, each one having bit-width more than twice the bit-width of a base field element. If base field reduction is fast, one could apply the base field reduction right away, delaying only the polynomial reduction. If not, it is possible to delay both types of reductions. We leave the implementation and optimization of this technique to future work. Application to sum-check.Recall that in every round, the prover must evaluate expressions of the form
X Y*d* *s*

||p|(r ,u,x|
|---|---|---|
||i|[<j]|
|x ∈{0,1}|i=1||

*j*

(*u*) =*i* [*<j*]
*′* )*,* *′ ℓ−j*

which are long-running accumulations of products. For each summand, one can first compute*h*(*x* *′* ) := Q*d−*1 *′ ′ ′* *i*=1*pi*(*r*[*<j*]*,u,x*), then form the final product*h*(*x*)*·pd*(*r*[*<j*]*,u,x*) in an unreduced representation, and defer reduction until after many summands have been accumulated (or at the end of the accumulator update). This replaces many per-term reductions by one batched reduction per accumulator, and therefore reduces prover cost without changing the protocol. The effect is most pronounced for low degrees, especially*d∈{*2*,*3*}*, where this final multiplication accounts for a large fraction of per-summand work; we measure this effect empirically in Section 9.

Rough cost model.In subsequent sections, we often refer to trading off one operation for a handful of another operation, so it is useful to have a heuristic model of the relative costs of these operations for 256-bit fields. Following the notation established earlier in this section, sayssoperations have unit cost, then it is helpful to think ofbbadditions,sbmultiplications,bbmultiplications, andsblinear combinations of*n* variables as having costs of roughly 5, 8, 32, and 5*n*+ 3 respectively. This model is crude, using simple round numbers to provide intuition. Although the actual costs of these operations in practice are hardware- dependent and field-dependent, this model can be justified empirically using the results in Section 9.

## 4 Handling high-degree polynomials

Almost all sum-check prover algorithms require, as a subroutine, the ability to compute the product of*d* linear (or multilinear) polynomials, where*d*can be as large as 32 in practice. While adding two*v*-variate degree-*d*polynomials can be performed with (*d*+1) *v* additions and no multiplications, computing the product of*d*linear polynomials is typically much more expensive. This section provides a general algorithm for computing this product, which is concretely faster than all prior approaches for the values of*d*and*v*arising in practical applications of the sum-check protocol. We focus first on the univariate case for simplicity in exposition, and then show how to generalize from univariate to multivariate.

### 4.1 Product of univariate polynomials

For the univariate case, let Q *p₁,...,pd*be*d*linear polynomials. The most common approach to compute the product*ipi*(*x*) is to directly evaluate this product at*d*+ 1 points. Each linear polynomial, Q *pi*, can be extrapolated to evaluations at*Ud*using*d−*1 additions. Given these evaluations,*ipi*(*x*) can be computed for each*x∈Ud*using*d−*1bbmultiplications. This results in a total of (*d−*1)*·*(*d*+ 1)bbmultiplications and*d·*(*d−*1) additions. This algorithm is simple to implement, optimal for*d*= 2, and commonly used in practice. Hyperplonk [14] describes an asymptotically more efficient divide-and-conquer approach. Split the list of polynomials in half, make recursive calls to compute the product of the first*⌊d/*2*⌋*polynomials and the product of the last*⌈d/*2*⌉*polynomials, and then multiply the two resulting polynomials. When using FFT- based polynomial multiplication, this algorithm requires*O*(*d*log² *d*)bbmultiplications; however, in practice, there are large constants hidden in the*O*-notation which make this algorithm significantly slower than the naive approach for common values of*d*(also, not all finite fields support efficient FFTs). For this reason, we consider the common approach to be the baseline for comparison.

An alternative algorithm.Here we introduce an alternative algorithm whose expensivebbwork is *O*(*d*log*d*). The lower-order (sb/addition) cost is*O*(*d²*), which is concretely acceptable sincesboperations and additions are significantly cheaper thanbbmultiplications. This is concretely more efficient for the values of*d*used in practice. Additionally, we significantly optimize the concrete number of operations over a naive specification of our new algorithm. Consider a recursive algorithm that takes in the evaluations of*d*linear polynomials at*{*0*,*1*}*and outputs the evaluations of their product at*Ud*. To compute this, it first divides the list of*d*polynomials in half and recursively computes the product of each half. This yields two polynomials of degree*⌈d/*2*⌉*and*⌊d/*2*⌋*, specified by their evaluations over*U⌈d/ ⌉*and*U⌊d/ ⌋*respectively. Next, it extrapolates these polynomials

|Procedure 1MultiProductEval|v, d|: Efficient product of multilinear polynomials in evaluation form using|
|---|---|---|
|extrapolation.|||
|||v|
|Input: d multilinear polynomials|p₁|,...,p d in v variables, specified by their evaluations over { 0, 1 }|
|||Q d|
|Output:The product polynomial 1: if d = 1then||g ( x ) = p i ( x ), specified by its evaluations over U i =1 dv|
|2: g ( x ) ←p₁ 3: return g 4: else|( x ) ▷|Identify the input two-point domain with U₁ via a fixed bijection|
|5: m←⌊d/|2 ⌋||
|6: q L ← MultiProductEval|v, m ( p₁|,...,p m )|
|7: q R ← MultiProductEval ′|v, d −|m ( p m +1 ,...,p d )|
|8: q ← MultiExtrapolate L ′|v,m,d|( q L )|
|9: q ← MultiExtrapolate R|v,d−m,d|( q R )|
|′|′||
|10: g←q ◦q||▷ Pointwise product of evaluations|
|L 11: return g 12: end if|R||

to their evaluations over*Ud*and then multiplies these evaluations point-wise to get the evaluations of their product over*Ud*. A precise accounting of the number ofbbmultiplications gives the recurrence*a*(*d*) =*a*(*⌊d/*2*⌋*)+*a*(*⌈d/*2*⌉*)+ (*d*+ 1) with base case*a*(1) = 0, whose closed form is

*a*(*d*) =*d⌈*log₂ *d⌉*+ 2*d−*2 *⌈*log2*d⌉* *−*1*.*

In particular,*a*(*d*)*≤d⌈*log₂ *d⌉*+*d−*1, with equality when*d*is a power of two. A naive realization of the extrapolation step uses Θ(*d²*)sbmultiplications and a similar number of additions. These additions andsb multiplications can be optimized using the techniques in Section 3.3; moreover, nearly all thesboperations can be eliminated entirely using a few more technical insights about Vandermonde matrices and optimal multi-addition chains. See Appendix D for details. When this algorithm is applied as a subroutine in the linear-time sum-check proverLinearTimeSC, the number ofbbmultiplications is reduced from Θ(*d²M*) to Θ((*d*log*d*)*M*). Note that a slight refinement of this algorithm can be used here, as the evaluation point at 0 can be omitted and a singlebbmultiplication can be saved. When this optimization is applied, this algorithm yields a concrete improvement for all*d≥*4. At*d*= 4, the number ofbbmultiplications is reduced from 12*M*to 10*M*. By*d*= 32, the number ofbbmultiplications is reduced from 992*M*to 190*M*, a*>*5*×*improvement.

### 4.2 Product of multilinear polynomials

The univariate algorithm is a special case of a more general algorithm (Procedure 1) for computing the product of*d*multivariate polynomials using a minimal number ofbbmultiplications, used later in Section 5. The algorithm is given the multilinear polynomials Q *p₁,...,pd*by their evaluations on the Boolean hypercube *v d* *{*0*,*1*}*, and needs to return their product*g*=*k*=1*pkalso in evaluation form*; namely, by returning the evaluations of*g*on the extended grid*Udv*:=*{*0*,*1*,...,d−*1*,∞}* *v*. Whereas the univariate algorithm worked with evaluations over*Ud*, the multivariate algorithm works with evaluations over*Udv*. This means that univariate extrapolations from*Uk*to*Ud*become multivariate extrapolations from*Ukv*to*Udv*. Multivariate extrapolation reduces to repeated univariate extrapolation along each dimension, and is described in Procedure 2. To begin, for each*S∈U* *kv−* 1, the evaluations at*Uk×S*can be extrapolated to evaluations at*Ud×S*using the univariate extrapolation algorithm. This process is repeated*v*times to extrapolate along each dimension. In the*j*’th step, the evaluations at*U* *dj−* 1 *×U* *kv−j* +1 can be extrapolated to evaluations at*U* *dj* *×U* *kv−j* using repeated univariate extrapolation. In the*j*’th step, (*d*+ 1) *j−*1 *·*(*k*+ 1) *v−j*

|Procedure 2MultiExtrapolate|v,k,d|: Multivariate polynomial extrapolation from evaluations at|U|to|U|
|---|---|---|---|---|---|
|using a univariate extrapolation subroutine as a black-box.||||kv|dv|
|Input:A v -variate polynomial|p with per-variable degree at most||k, specified as evaluations over U|||
|||||kv||
|Output: q, the evaluations of|p over|U||||
|||dv||||
|Initialize q with known evaluations over||U||||
|||kv||||
|1: q←p||||||
|2: for j = 1to|v do|||||
|For each slice orthogonal to dimension||j||||
||1|||||
|3: foreach ( Apply univariate extrapolation on the|x l ,x r ) ∈U ×U dj−|do kv−j j th axis||||
|4: q ( x l ,U 5: end for 6: end for 7: return q|d ,x r ) ← Extrapolate|k,d ( q ( x l ,U k ,x r ))||||

univariate extrapolations are required (one for each setting of the other coordinates), resulting in a total of

X*v* (*d*+ 1) *j−*1 (*k*+ 1) *v−j*

*j*=1

univariate extrapolations to extrapolate from*Ukv*to*Udv*. A general accounting of the number ofbbmultiplications in this multivariate algorithm gives the recur- rence*a*(*d*) =*a*(*⌊d/*2*⌋*) +*a*(*⌈d/*2*⌉*) + (*d*+ 1) *v* with base case*a*(1) = 0. Using the extrapolation analysis from Appendix D, we obtain the following summary.

Lemma 4.*Forv*= 1*, the algorithm*MultiProductEval₁*,drequiresO*(*d*log*d*)bb*multiplications andO*(*d²*)sb *multiplications plus additions. For every fixedv≥*2*,*MultiProductEval*v,drequiresO*(*d* *v* )bb*multiplications* *andO*(*d* *v*+1 )sb*multiplications plus additions.*

Thebbcost is*d*log*d*for*v*= 1 and Θ(*d* *v* ) for*v≥*2. The lower-order (sb/addition) cost is Θ(*d* *v*+1 ) uniformly, because each univariate extrapolation from degree*k*to 2*k*costs Θ(*k²*) operations, and the resulting per-level sums form a convergent geometric series dominated by the root. Using the optimizations to extrapolation described in Appendix D, the ratio ofbboperations for the naive algorithm to this algorithm for various values of*d*and*v*is summarized in Table 2. In the sum-check protocol, it is possible to save a small part of a single univariate extrapolation and a singlebbmultiplication by omitting an evaluation at 0, though for large*d*and*v*this offers only a marginal improvement.

## 5 Small-value and streaming proving

Small-value operations and fast multilinear products set the stage for an optimized round-batching algorithm that allows the prover to compute messages for a contiguous window of rounds in a single pass. This technique leads to two simultaneous improvements: (i) an efficient prover in the*small-value*setting, whose speedup over LinearTimeSCscales as Θ (*d²κ*) 1*/δ* for fixed*d*, where*κ*is the cost ratio betweenbbandssmultiplications and*δ*= log₂(*d*+ 1); and (ii) a streaming prover, improving the dependence on*d*from Θ(*d²*) to Θ(*d*log*d*) over the prior algorithm of Baweja et al. [10].

### 5.1 Small-value setting

We first motivate the idea of round-batching in the context of small-value proving, then show how it gener- alizes to the streaming setting.

|d v|1|2|3|4|5|
|---|---|---|---|---|---|
|3|⁄|⁄|⁄|⁄|⁄|
|4|⁄|⁄|⁄|⁄|⁄|
|5|⁄|⁄|⁄|⁄|⁄|
|6|⁄|⁄|⁄|⁄|⁄|
|7|⁄|⁄|⁄|⁄|⁄|
|8|⁄|⁄|⁄|⁄|⁄|
|9|⁄|⁄|⁄|⁄|⁄|
|10|⁄|⁄|⁄|⁄|*|
|16|⁄|⁄|⁄|*|*|
|32|⁄|⁄|*|*|*|

87 3225 12891 512337 20481267 1511 7543 375179 1875787 93753611 2416 14470 864334 51841714 311049286 3521 24599 1715525 120053075 8403519341 4826 384132 3072782 245765220 19660837646 6331 567167 51031087 459278135 41334366271 8037 800213 80001513 8000012501 800000112897 9943 1089261 119791999 13176918069

25579 4335623 736957087 1023191 337592335

Table 2: Ratio of the number ofbbmultiplications between a baseline multilinear polynomial product al-

gorithm and our optimized algorithm (Algorithm 1), for various numbers of variables*v*and polynomials*d*. These operations dominate the cost of the algorithm, so they can be treated as a proxy for overall speedup. *∗*indicates entries where either the numerator or denominator exceeds 10 6 (the display cutoff used to keep the table readable). Our algorithm is significantly faster for all parameters listed and this speedup increases sharply as one moves down or right in the table.

Taking advantage of small evaluations.Consider the linear-time algorithmLinearTimeSCin the small- value setting applied to the polynomial

Y *d*
*g*(*X₁,...,Xℓ*) = *pk*(*X₁,...,Xℓ*)*.*
*k*=1

In the first round, it is possible to performssandsbmultiplications, as, by definition, the evaluations of*g* required for computing the first prover message are all small. However, from the second round onwards, the prover exclusively performsbbmultiplications, since the bound evaluations*pk*(*r₁,...,ri−*1*,x* *′* ) are no longer small, due to the presence of the large random challenges*r₁,...,ri−*1*←*F. In each round, the number of evaluations required to compute the sum is halved, so this approach makes the most expensive round far cheaper. Extending this benefit to the first few rounds, by computing the first few messages with onlyssandsbmultiplications, would significantly reduce prover work. The presence of the random values*r₁,...,ri−*1eliminates the possibility of exclusively usingssandsb multiplications; however, the effect of their contributions can be delayed.
We consider a prover which delays binding the variables*X₁...,Xi−*1to the values*r₁,...,ri−*1, opting
to treat them*symbolically*instead. This approach has a clear tradeoff: it eliminates a large number ofbb multiplications, but it also increases the number ofssmultiplications and additions required. If the prover takes this approach and wants to bind the polynomial only after the first*v*rounds, then it first needs to compute the*v*-variate polynomial that suffices to answer the first*v*rounds:

X Y*d*
*q*(*X₁,...,Xv*) := *pk*(*X₁,...,Xv,x*
*′* )*,* *x* *′* *∈{*0*,*1*}ℓ−vk*=1

purely from the evaluations of*p₁,...,pd*on*{*0*,*1*}* *v*. For all*x* *′*, computing the product in the summand is *exactly*the multilinear product evaluation problem, which we have an efficient algorithm for in Procedure 1. 9

Moreover, when the evaluations of*p₁,...,pd*over the Boolean hypercube*{*0*,*1*}* *ℓ* are small (and*d*is not significantly larger than what is seen in practice), mostbbandsbmultiplications inMultiProductEvalcan 9 To be precise, it is possible to skip one out of (*d*+ 1)*v*evaluations of*q*, for instance the evaluation at the all-zero point. This is a simple generalization of the trick in the*v*= 1 case, described in Section 2.3. The impact of this quickly becomes negligible as*v*grows.

be replaced withssmultiplications. 10 This is because extrapolations of small values remain small, and the growth rate of the products of these extended evaluations is similarly controlled. For typical values of*d* and*v*, in this setting, this primitive requires Θ(*d* *v* )ssmultiplications and not a singlebbmultiplication. More generally, the small-value specialization is valid whenever the chosen window satisfies the bit-width preconditions of the underlying arithmetic routines: extrapolated values must remain within the machine- word budget used by thess/sbkernels, and every delayed-reduction accumulator must stay within the limb bounds discussed in Sections B and 3.3. Given this modified cost structure, the prover can tune*v*, the number of initial rounds to batch together before binding, to balance the savings from avoidingbbmultiplications against the increased number ofss multiplications and additions.

Comparison with an earlier version of the paper.In prior work [7], we described essentially the same small-value proving algorithm (called Algorithm 4 and Algorithm 6 in that paper). In this version, we opt for an alternative explanation that we think clarifies the underlying algebra: the pre-computation is specifically to form evaluations of the*v*-variate prefix polynomial*q*(*X₁,...,Xv*) over the full grid*Udv*. This algebraic framing abstracts away the complex, round-by-round “accumulator” state machines and Toom-Cook index mappings (e.g., theidx4function) used in that prior work [7]. Instead, we show that evaluating*q*on this grid yields exactly the information needed to answer the verifier dynamically during the first*v*rounds via simple challenge-weighted combinations.

### 5.2 Streaming setting

In the linear time small-value setting we focused strictly on reducing runtime; however, the streaming setting imposes a space budget of*O*(*M¹* */k* ) for a tunable*k≥*2. As it turns out, an extension of the round-batching idea is also well-suited to this setting when applied repeatedly, rather than just once. Recall, as the sum-check progresses, the number of summands decreases by a factor of 2 each round. The LinearTimeSCalgorithm uses standard caching techniques to exploit this halving; however, these techniques require far more space than is available to the prover in the streaming setting. Instead of caching, our prover algorithm takes advantage of iterative batching of rounds. If the prover batches rounds [*j,j*+*ω−*1] together, then this incurs a*normalized*overhead of*≈*(*d*+ 1) *ω* */*2 *j*+*ω* relative to the linear-time baseline. The exponential decrease of the overhead in*j*means that this overhead becomes more tolerable as the protocol progresses and fewer variables remain, allowing us to start with small windows and gradually increase them as total work decreases. Mechanically, the high-level design of our prover algorithm is similar to that of Baweja et al. [10] as they both consist broadly of three phases:

1.A time-constrained precomputation phase with geometrically growing window sizes.
2.A space-constrained precomputation phase with a fixed integer window chosen to meet the*O*(*M¹*
*/k* ) memory target.

3.A final phase identical toLinearTimeSConce the remaining variable count is small enough.
However, at a low level, the implementation of each phase, as well as the points at which the prover transitions between phases differ significantly. Appendix C contains additional details, particularly on the schedule for phases.

Algorithm and cost summary.Figure 2 describes the complete algorithm with the option to specialize to the small-value or streaming setting (or both). The window schedule Ω determines the behavior: for streaming, Ω uses the progressive integer schedule from Figure 2 (with floor/clip operations and a final- phase cutoff at*ℓ−ST*+1*≤ℓ/k*), rather than the single early window used in the small-value setting.
10For exceptionally large*d*, it may also be better to use the evaluation points at 0*,*1*,...,d*rather than 0*,*1*,...,d−*1*,∞*as
this results in a smaller largest entry of the extrapolation matrix.

### EvalProductSV Streamk,SC

Inputs: PStreams of evaluations for *p₁,...,pd*over*{*0*,*1*}* *ℓ*. Let*M*= 2 *ℓ* ,*δ*= log₂(*d*+ 1),*α*=*δ/*(*δ−*1). Let *St*:=*i<tωi*be the partial window sum (with*S₁* := 0). Window scheduleΩ = (*ω₁,...,ωT*):

•SV: Ω = (*ω₁*), single early window to minimize time, then linear-time for remaining rounds.

•Stream*k*: Two precomputation phases with integer windows, then a final linear-time phase: (

|||t|′|
|---|---|---|---|
||t||′|
|||t||
|′|||t−1|
||T+1|||
|[1:0]||||

min max 1*, α* *t−*1 */*(*δ−*1)*, ℓ−S t≤T,* *ω* = min(max(1*,⌊ℓ/*(*kδ*)*⌋*)*, ℓ−S*)*t > T.*

Here*T* is the largest index in the time-constrained phase, i.e., the last*t*for which *α /*(*δ−*1) *≤⌊ℓ/*(*kδ*)*⌋*. Choose*T*so that*ℓ−S ≤ℓ/k*.

#### Interpretr as the empty tuple.

1.For*t*= 1*,...,T*:
(a)For each*x*
*′* *∈{*0*,*1*}* *ℓ−St−ωt*, compute usingMultiProductEval:

Y *d*
*Px′* (*X₁,...,Xωt*) := *pkr*[1: *St*]*, X₁,...,Xωt, x*
*′* *,* *k*=1 P

|(X₁,...,X|) =|(X₁,...,X P|).||||
|---|---|---|---|---|---|---|
|t|ω x t t|x k t|ω [1:S]||t|[1:S]|

and thus*qt ′ ′ t*

If*t >*1, emulate streaming access to*p* (*rt,·*) via on-the-fly Lagrange weights eqe (*rt,·*).

(b)Emulate rounds [*S* +1*, S* +*ω*] directly on the evaluation grid of*q* (grid-based linear-time emulation; see Appendix C).
2.Final phase: for remaining rounds*i > ST*+1, stream and store
*pk*(*r*[1: *ST*+1]*,x* *′* ) : *k∈*[*d*]*, x* *′* *∈{*0*,*1*}* *ℓ−ST*+1 *,*

*d* then runLinearTimeSCon *pk*(*r*[1: *ST*+1]*,X*) *k*=1.

Figure 2: Combined small-value and streaming prover, parameterized by an integer window schedule Ω =

(*ω₁,...,ωT*) and a final linear-time phase.

In the small-value setting, with the cost analysis in Section C.4.1, we get the following result. Let*κ* denote the ratio of costs betweenbbandssmultiplications. 11

Lemma 5.*For fixed degree parameterd, at the optimal early-window sizev* *∗* = log*d*+1(*d²κ*)*(clipped/rounded* *to valid rounds),*EvalProductSVSC*has big-multiplication-equivalent runtime*

Θ *M·d²* *−*2*/δ* *·κ* *−*1*/δ* *,*

*and space usage* *v* *∗* 2 Θ (*d*+ 1) = Θ *d κ,*

For large prime fields with Montgomery multiplication,*κ≈ N* +*N*, where*N*is the number of limbs, so*κ*= Θ(*N*); for tower extension fields with Karatsuba,*κ≈N*log2 (3), where*N*is the extension degree.

*whereδ*= log₂(*d*+ 1)*. Compared with*LinearTimeSC*(runtime*Θ(*d²M*)*), this gives speedup*Θ((*d²κ*) 1*/δ* )*.*

For the streaming setting, we have the following result.

Lemma 6.*For products ofdmultilinear polynomials, the evaluation-basis round-batched prover algorithm* EvalProductStream*k,*SC*usesO*(*M¹* */k* )*space and runs in time*

#### Θ (dlogd)M(k+ log logM).

This improves over the prior work of Baweja et al. [10] which has complexity

#### Θ(d²M(k+ log logM)).

Hidden in these asymptotics are small constants which we also improve on for parameters seen in practice. Roughly speaking, their algorithm computes the*coefficients*rather than the evaluations of the product polynomials, which is more expensive. A full analysis is provided in Section C.4.2. The improvement stems from a better growth base*α*=*δ/*(*δ−*1) compared to*α*old=*d/*(*d−*1) that reduces the number of time-constrained passes, and more efficient evaluation-form storage that increases the allowable space-constrained window size from*ℓ/*(*dk*) to*ℓ/*(*kδ*) with*δ*= log₂(*d*+ 1). However, each pass still requires Θ(*d·M*) work for prefix adaptation to handle intermediate challenges.

## 6 Decomposable multilinear polynomial optimization

Many applications of the sum-check protocol involve a polynomial which has as one of its factors, a multilinear polynomial which is decomposable into a product of univariate linear polynomials. The canonical example, and most common one, is the*equality polynomial* eqe (*w,X*) in*X*with randomly chosen constant*w*. Many applications of sum-check involve an equality polynomial term when batching multiple constraints into a single protocol instance. For example, the Spartan protocol [49] verifies R1CS satisfiability by checking that X eqe (*w,X*)*·*(*Az* f (*X*)*· Bz* f (*X*)*− Cz* f (*X*)) = 0*,*(7) *X∈{*0*,*1*}ℓ*

where eqe is the equality polynomial and *Az,* f *Bz,* f *Cz* fare multilinear extensions derived from the product of constraint matrices*A,B,C*and a witness vector*z*. For clarity, in the remainder of this section, we focus on the equality polynomial, but our techniques apply more generally to any decomposable multilinear polynomial. Suppose it was possible to remove this polynomial entirely from the prover’s algorithm. Then, using our multiproduct evaluation from Section 4, the prover’s dominant cost per window of size*v*would be Θ(*d* *v* )bb field multiplications instead of Θ((*d*+1) *v* ). Even for small values of*d*and*v*, the savings would be substantial: for*d*= 3 and*v*= 4, this represents a*>*2*.*3*×*decrease in the number ofbbmultiplications. While it may not be possible to remove this factor entirely, it is possible to remove it from the multiproduct evaluation step, nearly achieving the same savings.

Exploiting decomposability.The equality polynomial’s decomposable structure allows much more ef- ficient handling. Observe that, for a variable*X*, eqe (*w,X*) decomposes as a product of linear factors as Q*ℓi* eqe (*w,X*) ==1eqe (*wi,Xi*). Consider the window of rounds [*i,i*+*v−*1]. This decomposability allows the equality polynomial to be written as the product of three parts.

•The first part is a constant factor*α*= eqe (*w*[*<i*]*,r*[*<i*]) contributed by past rounds. Q*v*

||e (w eq||,X ).|
|---|---|---|---|
||j=1 ′|i+j−1 ′|j ℓ−i−v+1|

•The second part is a product of linear factors in the current window:*j*=1 *i*+*j−*1 *j*

•The third part is the weights contributed by future rounds: eqe (*w*[*>i*+*v−*1]*,x*) for*x ∈{*0*,*1*}*.

Splitting the polynomial in this way immediately leads to the following more efficient prover algorithm.

Algorithm overview.Suppose, concretely, that the sum-check polynomial is of the form

Y *d* *g*(*X₁,...,Xℓ*) = eqe (*w,X*)*· pi*(*X*)*,* *i*=1

where*p₁,...,pd*are multilinear polynomials. For the window of rounds [*i,i*+*v−*1], the prover is tasked with computing the*v*-variate polynomial X
*g*(*r₁,...,ri−*1*,X₁,...,Xv,x*
*′* )*.* *x* *′* *∈{*0*,*1*}ℓ−i−v*+1

By the decomposition into past rounds, the current window, and the remaining suffix, this can be rewritten as

|i −1||v|||
|---|---|---|---|---|
||j j|i+j−1|j|v|
|j=1||j=1|||
||[>i+v−1]|d ′|k [<i]|′ v|
|x||k=1|||

Y Y eqe (*w,r*)*·* eqe (*w,X*)*·T*(*X₁,...,X*)*,*

where*T*(*X₁,...,Xv*) is defined as

X Y eqe (*w,x*) *p* (*r,X₁,...,X,x*)*.* *′*

While the first two parts are straightforward to compute, the challenge is to efficiently compute the third part

*T*. We give a sketch of the technique here for evaluating*T*on the grid*Udv*efficiently. Figure 8 summarizes the main-body algorithm; full details and proofs are provided in Section C.5. First, the prover partitions eqe (*w*[*>i*+*v−*1]*,x*
*′* ) into a product of*k*polynomials and computes a table of evaluations for each part using*k*-way decomposition, requiring only*O*(*M¹* */k* ) space while maintaining *O*(2 *ℓ−i−v*+1 ) time complexity. Next, the prover iterates over all*x* *′* *∈{*0*,*1*}* *ℓ−i−v*+1 in lexicographic order, and uses these evaluations in combination with multiproduct evaluation from Section 4 to compute Q *T*on *v* *Udv*. Finally, this*T*can be easily combined with*α·* e ( *j*=1eq *wi*+*j−*1*,Xj*) to form the sum-check polynomials for rounds*i*through*i*+*v−*1.

Lemma 7.*Appending an equality polynomial factor* eqe (*w,X*)*to a product ofdmultilinear polynomials leads* *to the following additional sum-check prover work:*

•*Time:O*(2 *ℓ−i−v*+1 )*field operations for suffix weights, while preserving the same dominant multiproduct* *term as the non-equality case.*

•*Space:O*(*M¹* */k* )*withk-way decomposition.*

*When combined with small-value proving, the optimization preserves the use of cheap small-value arithmetic,* *requiring only small-by-big multiplications for the linear factors.*

The detailed proof and constants appear in Appendix C.5, Theorem 14. We note that in practice, a two- way decomposition of eqe (*w,X*) often yields the best performance tradeoff; this variant is the one described in the original note of the first and last author [23].

## 7 Univariate Skip over Large Prime Fields

Univariate skip, introduced by Gruen [33], is a generic way to reduce prover work by “fusing” several Boolean variables into a single higher-degree variable, in a setting where we start out with base field values but sumcheck is over the extension field. In this section, we show that univariate skip can also apply in the setting of small values inside a large prime field, which allows us to apply the technique to applications such as Spartan-in-Jolt.

General idea.Let*f*:F *n* *→*Fbe the polynomial being summed. Univariate skip chooses a set of*m* components to pack into one variable*Y*(here*m*is a design parameter, not necessarily a power of two), and an interpolation domain*D*=*{u₀,...,um−*1 *j* *m*

|}⊂Fof the same size. Let{L|||(Y)}|be the Lagrange basis|
|---|---|---|---|---|
|m−1|m −1||j|j=0|
|pack|j|j|||
||j=0 pack|j k|j j||

*j*=0 *−*1

#### forD. Define the packed polynomial

X *f* (*Y,·*) := *L* (*Y*)*·f* (*·*)*,*

where*f₀,...,fm−*1are the objects being packed (for example, slices indexed by Boolean prefixes, or batched constraint components in zerocheck). By construction,*f* (*u,·*) =*f* (*·*) for all*j*. Operationally, this re- places several rounds/components by one higher-degree univariate step. The familiar Boolean-block version is the special case*m*= 2, with*f* (*·*) =*f*(bin(*j*)*,·*) for a*k*-bit prefix. But in batched zerocheck settings, one often wants*m*to match the number of packed constraints or terms; this can be any convenient size.

What Gruen uses.Gruen’s zerocheck setting is over a small base field with a large extension field [33]. The univariate-skip instantiation there chooses domains compatible with that base/extension-field structure, specifically a*m*-sized subgroup of the base field’s multiplicative group, to enable*O*(*m*log*m*) extrapolation cost over the base field.

Adapting to large-prime fields.For our setting (small values inside a large prime field), we use the same packing principle but with a different domain choice. Instead of a multiplicative subgroup, we take a small symmetric integer domain around 0 with the required cardinality*m*:

#### Dm:={−⌊m/2⌋,−⌊m/2⌋+ 1, ...,−⌊m/2⌋+m−1}⊂F.

This choice has two practical benefits. First, the interpolation points stay numerically small, which con- trols the growth of intermediate Lagrange terms (compared with one-sided domains like*{*0*,...,m−*1*}*). Second, symmetry around 0 improves conditioning of integer-lifted intermediate expressions used in our implementation, reducing delayed-reduction pressure.

Why quadratic interpolation is acceptable.With this domain, we use the straightforward*O*(*|Dm|* 2 ) interpolation/evaluation routine. This is practical because*|Dm|*=*m*is chosen to be small in our target regime and the arithmetic in the interpolation loop is dominated by multiplying large field elements by small coefficients. Hence, the fast small-by-big multiplications (§3.3) and delayed reductions (§3) apply directly. As a result, even a quadratic-in-*m*interpolation step has low concrete cost.

Practical bound on packed width.For symmetric domains, the shifted Lagrange coefficients are integers

*m−*1*−is s−i−*1 *αi*(*s*) = (*−*1)*,* *i m−*1*−i*

where*s*is the integer shift from the left endpoint of the base window. Define *m* X*−*1 Λ := max *|αi*(*s*)*|.* *s∈*target shifts *i*=0 P If the packed values satisfy*|vi|≤B*, then the interpolation sum obeys*|iαi*(*s*)*vi|≤B*Λ. Hence, with a one-extra-limb budget (signed 128-bit accumulation for 64-bit inputs), we need*B*Λ*<*2 127. For the common odd symmetric case*D*=*{−K,...,K}*(so*m*= 2*K*+ 1), a natural degree-2 target window is*{−*2*K,...,*2*K}*, which corresponds to shifts*s∈*[0*,*3*K*] from the left endpoint of*D*. In this specific regime, exact integer evaluation of*αi*(*s*) gives:

Λ₁₄ *≈*7*.*16*·*10 18 (*≈*2

62*.*6 )*,*Λ₁₅ *≈*1*.*87*·*10
20 (*≈*2

67*.*3 )*,*Λ₁₆ *≈*4*.*88*·*10
21 (*≈*2

72*.*0 )*.*
So under worst-case full-width 64-bit values in this degree-2 symmetric setting,*K≤*14 is the conservative safe choice. For higher packed degrees, the target window is larger and the corresponding value of Λ must be recomputed.

Applicability.Univariate skip is most useful when the prover can choose a block of variables to pack and then reuse this structure across many evaluations. As in Gruen’s analysis [33], the parameter*k*gives a prover-verifier tradeoff: larger*k*decreases prover-side repeated work but increases the degree of the packed univariate and therefore the verifier-side interpolation burden. In the more general*m*-ary formulation above, the same tradeoff is controlled directly by*m*: larger*m*gives more prover amortization but increases univariate degree and interpolation cost.

## 8 Implementation

For field arithmetic, we extended thearkworks[17] library to support the delayed reduction technique in Section 3. Our Jolt integration includes several key components. First, we apply delayed reduction (Section 3) across sum-check-heavy components. Second, we implement various iterations of the Spartan outer sum- check prover. This spans from a baseline variant with no optimizations to successive variants incorporating split-eq (Section 6) and delayed reduction (Section 3), followed by round-batching (Section 5.1) and univariate skip (Section 7). We also include streaming variants of both our approach (Section 5) and that of Baweja et al. [10]. Finally, we apply our high-degree optimization to the instruction RA virtualization sum-check prover. In this context, the effective degree is configurable in the range*{*4*,*8*,*16*,*32*}*and involves an equality polynomial term optimized using our split-eq technique (Section 6).

## 9 Evaluation

Our evaluation aims to answer the following questions:

1.How do our new white-box finite field techniques compare to black-box alternatives?
2.How do our techniques improve the prover time and space of various sum-check primitives over prior work?
3.What is the end-to-end impact of our techniques on real-world systems?
Experimental setup.All experiments are run over the BN254 scalar field (the field currently used in Jolt). We run benchmarks on a MacBook Pro with Apple M4 Max (12 performance cores, 64 GB RAM). We use the Criterion [34] benchmark tool to derive statistically significant microbenchmarks and Chrome-trace [31] span analysis for RA virtualization measurements in Jolt. All microbenchmarks are run single threaded, and the multithreaded benchmarks are specified as such. For memory, we use three complementary metrics: isolated process peak RSS (Resident Set Size), which measures the maximum amount of physical RAM a process consumes over its lifetime, for Spartan outer runs, setup-normalized ∆peak RSS for streaming comparisons (∆peak RSS = peak RSS*−*RSS immediately after trace/setup), and allocative object-level heap snapshots for retained-state accounting. This allows us to measure the additional memory overhead of components when compared to the rest of Jolt.

### 9.1 The cost of finite field operations

We first benchmark primitive finite-field operations, includingss,sb, andbbmultiplication costs and their internal breakdowns. Next, we benchmark linear combinations with small coefficients using: (i) naivebbmultiplication, (ii)sb multiplication, and (iii) delayed reduction across the whole combination. Finally, we benchmark the product of*d*multilinear polynomials in*v*variables (the core high-degree kernel from Section 4). Table 5 reports speedups of our optimized method over the naive baseline. Speedups grow with*d*and*v*, reaching about 2*.*5*×*at (*d,v*) = (32*,*18) and (32*,*20).

|Operation||Time (ns)|
|---|---|---|
|ssmultiply||0.36|
|bbadd||1.99|
|sbmultiply|Bigint multiply by u642.02 Barrett reduce3.67|4.65|
|bbmultiply||10.50|

Bigint multiply*4.48* Montgomery reduce*6.67*

Table 3: Microbenchmarks for various field operations. Forsbandbbmultiplications, we break down the

time into its constituent parts: raw big-integer multiplication and modular reduction and benchmark each of these separately. Note that the sum of the time for the constituent parts exceeds the time for the full operation because the compiler is able to optimize the combined operation better than the individual parts.

|Size (n)|2|4|8|16|32|
|---|---|---|---|---|---|
|Baseline (ns)|55.10|107.27|212.85|438.95|873.31|
|sb(ns)|11.49|23.070|42.57|81.71|167.60|
|Fast (ns)|5.26|9.32|12.08|26.00|36.84|
|Speedup (×)|10.48|11.51|17.62|16.88|23.71|

Table 4: Microbenchmark results of linear combinations of*n*variables with small-value coefficients. Baseline

indicates the approach of decomposing the linear combination into a series ofbbadditions and multiplications. sbindicates the approach of using our newsbops. Fast indicates delaying the reduction step across allsb operations until the end of the linear combination. The speedup row indicates the difference in time between the baseline approach and our one-reduction approach.

### 9.2 Delayed reduction in degree-2 sum-check

To isolate the effect of delayed reduction inside actual sum-check prover loops (see Section 3), we run two P single-threaded sum-check prover microbenchmarks: one on a clean degree-2 instance P*x* *p*(*x*)*·q*(*x*), and a degree-2 plus eq-poly instance*x*eqe (*τ,x*)*·p*(*x*)*·q*(*x*) with split-eq optimization (see Section 6).

Table 6 shows that delayed reduction yields a stable*≈*1*.*37*×*speedup across variable sizes 14–26 in the

clean degree-2 setting. In the eq-poly setting (Table 7), the gain is smaller but still consistent at*≈*1*.*09*×*. This reduction in speedup is expected: after split-eq, fewer multiplications are on the critical path where reductions can be deferred.

### 9.3 Jolt integration benchmarks

#### We evaluate two integrations in Jolt:

1.Spartan outer sum-check (small-value + equality-polynomial optimizations);
2.Shout instruction lookup RA virtualization (high-degree optimization). See Section E for full details on these sum-checks as they appear in Jolt. For Spartan ablations, we report
SHA2-chain-*N*, where*N*is the number of SHA-256 iterations. In Jolt’s SHA2 benchmark, one iteration corresponds to roughly 3*.*4*×*10 3 RISC-V cycles, so the workload has approximately 3*.*4*×*10 3 *·N*cycles (e.g., *N*= 8192 is about 2*.*8*×*10 7 cycles). For end-to-end results, we use a*scale*parameter: scale*s*means the trace is padded to roughly 2 *s* cycles (for example, at scale 22 the unpadded trace is about 3*.*8M cycles and the padded trace is about 4*.*2M cycles in our setup).

<u>Speedup (baseline / optimized) v= 12v= 14v= 16v= 18v= 20</u>

*d*= 2 1.12*×*1.87*×*2.07*×*2.20*×*2.92*×* *d*= 4 1.17*×*1.54*×*2.04*×*1.93*×*2.07*×* *d*= 8 1.27*×*1.58*×*1.83*×*1.94*×*2.01*×* *d*= 16 1.33*×*1.67*×*1.91*×*2.02*×*2.04*×* *d*= 32 1.48*×*1.93*×*2.31*×*2.48*×*2.47*×*

#### Optimized runtime (µs)

|d= 2|88|121|246|709|2,235|
|---|---|---|---|---|---|
|d= 4|145|238|606|1,882|7,038|
|d= 8|351|641|1,640|5,329|21,262|
|d= 16|949|1,903|5,648|19,214|76,196|
|d= 32 Baseline runtime (µs)|3,054|6,026|17,120|58,397|237,080|
|d= 2|98|226|509|1,561|6,521|
|d= 4|170|367|1,235|3,628|14,568|
|d= 8|446|1,012|2,997|10,324|42,677|
|d= 16|1,263|3,179|10,786|38,747|155,200|
|d= 32|4,511|11,651|39,618|144,980|585,530|

Table 5: High-degree product benchmark for computing the product of*d*multilinear polynomials in*v*vari-

ables. Values are Criterion mean estimates from a dedicated microbenchmark.

|Variables|Baseline (ms)|Unreduced (ms)|Speedup|
|---|---|---|---|
|14||1.15|0.87 1.31 ×|
|16||5.42|3.98 1.36 ×|
|18||21.0|15.2 1.38 ×|
|20||82.6|59.4 1.39 ×|
|22||331.5|235.2 1.41 ×|
|24||1,324|965 1.37 ×|
|26||5,316|3,819 1.39 ×|

P

Table 6: Degree-2 sum-check prover microbenchmark applied to the sum:*xp*(*x*)*·q*(*x*), comparing baseline

multiplication against delayed reduction.

Spartan ablation (linear-space).Figure 3 shows a cumulative ablation¹² over variants of the outer sum- check protocol in Spartan (hereafter referred to as “Spartan outer”): baseline, split-eq, delayed reduction, round batching, and univariate skip. The variants are defined as follows.

•Baseline:textbook Spartan outer prover implemented with the linear-time sum-check algorithm, without the optimizations introduced in this paper.

#### •Split-eq:applies equality-polynomial factorization (Section 6).

#### •Delayed reduction:adds delayed reduction (Section 3).

•Round batching:adds our multi-round small-value precomputation strategy (Section 5.1) to reduce big-field multiplications in early rounds.

•Univariate skip:adds univariate skip (Section 7) replacing round batching, yielding our fastest linear- space Spartan outer variant (and is the current default in Jolt).

|Byablation,|we mean|starting|from a baseline|and adding|one optimization|at a time|to isolate|each optimization’s|
|---|---|---|---|---|---|---|---|---|
|contribution.|||||||||

|Variables|Baseline (ms)|Unreduced (ms)|Speedup|
|---|---|---|---|
|14||2.63|2.49 1.06 ×|
|16||9.51|8.57 1.11 ×|
|18||35.0|32.2 1.09 ×|
|20||136.4|124.3 1.10 ×|
|22||538.9|494.9 1.09 ×|

P

Table 7: Degree-2 plus eq-poly sum-check prover microbenchmark. e (*τ,x*)*·p*(*x*)*·q*(*x*) with split-eq,

*x*eq comparing baseline multiplication against delayed reduction.

(a) Runtime (b) Peak Memory
baseline

|5||
|---|---|
|4|1|
|3||
|2|0|
|1||
|3 5|7|

10split-eq delayed red. round batch. 10 univariate skip 10

Time (ms) 10 10 Peak RSS (GB)

7 9 11 13 9 11 13 2 2 2 2 2 2 2 2 2 2 SHA-2 iterations SHA-2 iterations

Figure 3: Performance of Spartan’s outer sum-check (linear-space) in Jolt. (a) Runtime in milliseconds (log-

log scale); (b) Peak process RSS in GB (log-log scale). Our optimized variants (round batching and univariate skip) maintain near-linear scaling in both time and memory, while baselines hit severe memory pressure at large scales.

We see a monotonic improvement in performance as we add more optimizations. The largest incremental gain comes from round batching, while univariate skip yields the fastest overall linear-space variant. This ablation focuses on prover-side runtime and memory; univariate skip changes the prover/verifier tradeoff and 5 is discussed separately in Section 7. In a*steady-state compute regime*(*N*= 128—2048, about 4*.*4*×*10 — 6

7*.*0*×*10 RV64 cycles), the multiplicative gains across successive variants are as follows. •baseline*→*split-eq: 1*.*26—1*.*47*×*.
#### •split-eq→delayed reduction: 1.09—1.31×.

#### •delayed reduction→round batching: 4.10—6.01×.

#### •round batching→univariate skip: 1.11—1.24×.

These values capture pure algorithmic throughput before dense variants hit severe memory pressure. 7 In a*memory-bottleneck regime*(*N≥*4096, about 1*.*4*×*10 RV64 cycles and above), dense variants become memory-bound: the incremental performance gains are:

•baseline*→*split-eq: 1*.*76—3*.*01*×*,

•split-eq*→*delayed reduction: 1*.*02—1*.*12*×*,

•delayed reduction*→*round batching: 8*.*81—14*.*95*×*,

#### •round batching→univariate skip: 1.23—1. ×.

This is consistent with the runtime scaling under input doubling: the proving times for baseline/split- eq/delayed grow super-linearly (e.g., doubling the input from 2048*→*4096 iterations yields runtime slow- downs of 3*.*85*×/*2*.*86*×/*2*.*84*×*respectively; 4096*→*8192: 5*.*32*×/*3*.*11*×/*3*.*43*×*), while round batching and univariate skip proving times remain near-linear (about 1*.*94*×*–2*.*02*×*per doubling). Consequently, the cumulative headline at 8192 iterations is much larger: univariate skip is 57*.*9*×*faster than baseline (about

2.1s vs. 121s), and round batching is 45*.*9*×*faster. This is consistent with the memory data in Table 9: at 512 iterations, dense variants already use 8.8–13.1 GB peak RSS, versus 0.75–1.29 GB for univariate skip/round batching; by 8192 iterations, dense variants rise to 46.6–50.1 GB while univariate skip/round batching stay at 11.5–15.0 GB. Tables 8 and 9 provide the full datapoints used in these plots, including both runtime and isolated peak memory during sum-check.

|SHA2 iterations|8|16|32|64|128|256|512|1024|2048|4096|8192|
|---|---|---|---|---|---|---|---|---|---|---|---|
|Baseline|32.1|53.2|95.3|168.4|306.9|625.6|1262.0|2679.7|5929.3|22814.6|121432.5|
|Split EqPoly|25.9|35.4|61.9|107.1|208.4|483.5|925.1|2129.2|4538.9|12980.0|40305.6|
|Delayed reduction|20.7|32.4|58.6|98.9|186.0|369.6|815.3|1954.4|4068.1|11552.3|39566.8|
|Round batching|7.1|12.7|17.7|26.5|45.4|86.8|171.7|330.6|677.0|1311.3|2645.9|
|Univariate skip Table 8: Numeric runtime data in milliseconds for the linear-space Spartan outer ablation in Figure 3.|6.6|11.2|16.3|25.5|40.1|78.1|151.4|273.6|545.7|1064.1|2098.7|
||SHA2 iterations||128|256||512|1024|2048|4096|8192||
||Baseline||3.280|6.552|13.094|14.387|28.202||28.005 50.054|||
||Split-eq||2.207|4.405|8.802|12.386|24.762||46.102 46.610|||
||Delayed reduction||2.207|4.406|8.799|12.386|24.761||46.155 46.998|||
||Round batching||0.329|0.649|1.286||2.389|4.763|9.518 15.014|||
||Univariate skip||0.195|0.380|0.749||1.386|2.760|5.761 11.511|||

Table 9: Peak process resident set size, measured in GB, when running Spartan’s outer sum-check in isolation
 for proving various numbers of SHA2 executions. Streaming *√*
regime (low-space).Tables 10 and 11 compare linear-space univariate skip against two *N*-space streaming variants: our*evaluation-basis streaming*prover and a*cross-product streaming*baseline (implemented in coefficient form, following Baweja et al.). Our evaluation-basis streaming implementation is consistently faster than cross-product streaming. Relative to linear-space univariate skip, evaluation-basis streaming is typically in the 1*.*62*×*–2*.*70*×*slowdown range overall (and 2*.*3*×*–2*.*7*×*on larger instances), versus 1*.*88*×*–2*.*97*×*overall (and 2*.*6*×*–3*.*0*×*on larger instances) for cross-product streaming. Using setup- normalized peak RSS (Table 11), where we subtract RSS immediately after trace/setup to mask shared allocations, both streaming variants require much less additional memory at moderate and large sizes. At the very smallest instances this normalized metric is close to the allocator/setup noise floor, so we interpret it only qualitatively there. At 8192 iterations, the masked ∆peak RSS is 8.593 GB for univariate skip versus

0.018 GB (17.7 MB, evaluation-basis) and 0.036 GB (35.8 MB, cross-product), i.e., about
*√* two orders of magnitude lower for streaming. This MB-scale overhead is consistent with the intended *N*working set once dense trace/setup allocations are removed.

RA virtualization in Shout.Table 12 reports scale*s*= 22 (i.e., padded to*≈*2 22 cycles) trace mea- surements for RA virtualization with the number of virtual polynomials set to*N∈ {*8*,*4*,*2*,*1*}*(degrees 5*,*9*,*17*,*33), comparing optimized and baseline kernels. Total RA time improves by 1*.*70—2*.*18*×*, and the RA share of total proving time is substantially reduced across all configurations.

End-to-end sweep.Table 13 reports a consolidated SHA2-chain sweep for scale parameters*s*= 22 to 25 (3 runs per scale) under the default optimized configuration. Proving time grows from 9*. ±.*12s (scale 22)

|SHA2 iterations|8|16|32|64|128|256|512|1024|2048|4096|8192|
|---|---|---|---|---|---|---|---|---|---|---|---|
|linear-space, univariate skip|6.6|11.2|16.3|25.5|40.1|78.1|151.4|273.6|545.7|1064.1|2098.7|
|streaming, evaluation-basis|10.7|18.8|32.1|59.4|96.4|181.2|381.9|718.3|1261.9|2871.0|5647.1|
|streaming, cross-product|13.9|21.1|39.1|62.5|103.8|213.8|418.8|784.7|1411.4|3165.7|6121.9|
|evaluation-basis slowdown|1.62 ×|1.68 ×|1.97 ×|2.33 ×|2.40 ×|2.32 ×|2.52 ×|2.63 ×|2.31 ×|2.70 ×|2.69 ×|
|cross-product slowdown Table 10: Streaming versus linear-space Spartan outer sum-check in Jolt. All runtimes are in milliseconds (ms). The evaluation-basis streaming variant is consistently faster than the cross-product baseline at the √ same N -space regime.|2.10 ×|1.88 ×|2.40 ×|2.45 ×|2.59 ×|2.74 ×|2.77 ×|2.87 ×|2.59 ×|2.97 ×|2.92 ×|
|SHA2 iterations||8 16|32|64|128|256|512|1024|2048|4096|8192|
|univariate skip|0.105|0.100|0.095|0.082|0.136|0.272|0.539|1.078|2.152|4.300|8.593|
|evaluation-basis streaming|0.105|0.101|0.094|0.082|0.057|0.011|0.015|0.013|0.015|0.017|0.018|
|cross-product streaming|0.105|0.101|0.095|0.082|0.057|0.016|0.020|0.021|0.028|0.032|0.036|

Table 11: Masked memory using setup-normalized peak RSS for streaming versus linear-space Spartan outer

variants across SHA2-chain 8–8192. We report ∆peak RSS = (run peak RSS) - (RSS immediately after trace/setup) obtained from a dedicated memory microbenchmark, in GBs, which removes shared allocations such as trace storage.

to 51*.*09*±*1*.*11s (scale 25), while the RA virtualization share increases from 8.0% to 11.8% and the Spartan outer sum-check share remains a smaller component (3.0% to 4.2%).

Memory measurements.We report memory using the metric that best matches each question. For variant-level outer sum-check comparison, we use isolated process peak RSS obtained from a dedicated memory microbenchmark. For streaming versus linear-space comparison, we report setup-normalized ∆peak RSS to remove shared trace/setup allocations. For retained-state accounting, we use allocative object-level heap snapshots. Under this methodology, isolated allocative object-level runs at 16k and 32k SHA2 iterations show a stable*≈*4*.*00*×*reduction for streaming versus linear-space univariate skip. For linear-space variant ablations at SHA2-chain 128–8192 (Table 9), peak RSS in isolated runs drops from 3.28–50.05 GB (baseline) to 0.19–11.51 GB for univariate skip (*≈*4*.*35*×*–17*.*5*×*lower) and to 0.33–15.01 GB for round batching (*≈*2*.*94*×*–10*.*2*×*lower), with round batching using about 1*.*30*×*–1*.*73*×*higher peak RSS than univariate skip. For end-to-end process peak memory (monitor/perfetto, single run per scale), we measure 4.98 GB (scale 22), 9.91 GB (scale 23), 14.12 GB (scale 24), and 27.67 GB (scale 25).

## 10 Discussion

The techniques in this paper represent substantial progress toward practical SNARK-based proof systems, especially in the setting of zero-knowledge virtual machines. We develop a suite of prover-side optimizations for the sum-check protocol that significantly reduce proving time and memory usage. All of the optimizations except univariate skip leave the protocol and verifier costs unchanged; univariate skip instead trades a faster prover for a higher-degree verifier interpolation step. A primary beneficiary of these techniques is Jolt, which already had state-of-the-art proving performance among zkVMs. Our improvements further strengthen its position, yielding even faster and more memory- efficient proving. More broadly, these results help close the performance gap traditionally associated with operating over large prime fields. Our techniques substantially mitigate the cost of these large fields, allowing systems like Jolt to enjoy the benefits of elliptic curves without incurring prohibitive overhead from the 256-bit fields that they impose. At the same time, our techniques remain applicable to future versions of Jolt and other zkVMs that avoid elliptic curves and hence use 128-bit fields.

|Degree|Baseline (ms)|Optimized (ms)|Speedup|% prove (base)|% prove (opt)|
|---|---|---|---|---|---|
|5|1,602|921|1.74 ×|13.0%|8.4%|
|9|2,135|1,247|1.71 ×|17.5%|11.2%|
|17|3,837|2,254|1.70 ×|26.0%|17.1%|
|33|6,501|2,979|2.18 ×|39.7%|22.8%|

Table 12: RA virtualization benchmark inside Jolt’s Shout lookup argument (scale parameter*s*= 22, multi-

threaded).

|Scale|Prove time (s)|RA virtualization share|Spartan outer share|
|---|---|---|---|
|22|9. 76 ± 0|. 12 8.0%|3.0%|
|23|15. 72 ±|0. 18 9.6%|3.4%|
|24|29. 79 ±|0. 38 10.2%|3.6%|
|25|51. 09 ±|1. 11 11.8%|4.2%|

Table 13: End-to-end SHA2-chain proving sweep in Jolt (default optimized configuration, BN254, 3 runs

per scale, mean*±*standard deviation). Component shares are extracted from Chrome-trace spans. These include optimized implementations of both the RA virtualization and Spartan outer sum-check instances.

The goal of this line of work is to put SNARKs on the same footing as digital signatures and en- cryption—namely, as standard cryptographic building blocks that developers reach for without hesitation, confident in their performance and reliability. In our view, SNARKs should be as pervasive in digital in- frastructure as signatures and encryption already are. This work moves the field closer to realizing that vision.

## Acknowledgments

The first author thanks Riad Wahby for fruitful discussion, especially on the delayed reduction technique.

## Disclosures

Justin Thaler is a Research Partner at a16z crypto and is an investor in various blockchain-based platforms, as well as in the crypto ecosystem more broadly (for general a16z disclosures, see[https://www.a16z.com](https://www.a16z.com) /disclosures/).

## AI Usage

GPT, Claude, and Gemini were used to assist with implementation, benchmark setup, data extraction, LATEX formatting, and parts of the writing in the technical sections. The authors have carefully reviewed every word and every experimental result, and take full responsibility for all writing and results reported in this paper.

## References

[1]Spartan: High-speed zkSNARKs without trusted setup.[https://github.com/Microsoft/Spartan](https://github.com/Microsoft/Spartan) (2020)

#### [2]Jolt codebase.[https://github.com/a16z/jolt(2025](https://github.com/a16z/jolt(2025))

[3]Aranha, D.F., Karabina, K., Longa, P., Gebotys, C.H., L´opez, J.: Faster software for sparse isogenies and pairings. Cryptology ePrint Archive (2011)

[4]Arnon, G., Chiesa, A., Fenzi, G., Yogev, E.: WHIR: Reed–solomon proximity testing with super-fast verification. Cryptology ePrint Archive, Paper 2024/1586 (2024),[https://eprint.iacr.org/2024/1](https://eprint.iacr.org/2024/1) 586

[5]Arun, A., Setty, S., Thaler, J.: Jolt: Snarks for virtual machines via lookups. In: Annual International Conference on the Theory and Applications of Cryptographic Techniques. pp. 3–33. Springer (2024)

[6]Attema, T., Fehr, S., Klooß, M.: Fiat-shamir transformation of multi-round interactive proofs. In: Theory of Cryptography Conference. pp. 113–142. Springer (2022)

[7]Bagad, S., Dao, Q., Domb, Y., Thaler, J.: Speeding up sum-check proving. Cryptology ePrint Archive, Paper 2025/1117 (2025),[https://eprint.iacr.org/2025/1117](https://eprint.iacr.org/2025/1117)

[8]Bagad, S., Domb, Y., Thaler, J.: The sum-check protocol over fields of small characteristic. Cryptology ePrint Archive, Paper 2024/1046 (2024),[https://eprint.iacr.org/2024/1046](https://eprint.iacr.org/2024/1046)

[9]Barrett, P.: Implementing the rivest shamir and adleman public key encryption algorithm on a standard digital signal processor. In: Conference on the Theory and Application of Cryptographic Techniques. pp. 311–323. Springer (1986)

[10]Baweja, A., Chiesa, A., Fedele, E., Fenzi, G., Mishra, P., Mopuri, T., Zitek-Estrada, A.: Time-space trade-offs for sumcheck. Cryptology ePrint Archive, Paper 2025/1473 (2025),[https://eprint.iacr](https://eprint.iacr). org/2025/1473

[11]Boneh, D., Chen, B.: LatticeFold: A lattice-based folding scheme and its applications to succinct proof systems. Cryptology ePrint Archive, Paper 2024/257 (2024),[https://eprint.iacr.org/2024/257](https://eprint.iacr.org/2024/257)

[12]Boneh, D., Chen, B.: Latticefold+: Faster, simpler, shorter lattice-based folding for succinct proof sys- tems. Cryptology ePrint Archive (2025)

[13]Canetti, R., Chen, Y., Holmgren, J., Lombardi, A., Rothblum, G.N., Rothblum, R.D.: Fiat-shamir from simpler assumptions. Cryptology ePrint Archive (2018)

[14]Chen, B., B¨unz, B., Boneh, D., Zhang, Z.: HyperPlonk: Plonk with linear-time prover and high-degree custom gates (2023)

[15]Cloutier, F.: MULX — Unsigned Multiply Without Affecting Flags (nd), url:[https://www.felixclo](https://www.felixclo) utier.com/x86/mulx

[16]Consensys: gnark-crypto: High-performance cryptographic and elliptic curve library in go.[https://gi](https://gi) thub.com/Consensys/gnark-crypto(2024)

#### [17]arkworks contributors: arkworks zksnark ecosystem.[https://arkworks.rs(2022](https://arkworks.rs(2022))

[18]Cook, S.A.: On the minimum computation time of functions. In: Proceedings of the first annual ACM symposium on Theory of computing. pp. 187–192. ACM (1969)

[19]Cordes, P., et al.: What is the difference between the adc and adcx instructions on x86?https: //stackoverflow.com/questions/29747508/what-is-the-difference-between-the-adc-and-a dcx-instructions-on-x86(2015)

[20]Cormode, G., Mitzenmacher, M., Thaler, J.: Practical verified computation with streaming interactive proofs. In: ITCS (2012)

[21]Cormode, G., Thaler, J., Yi, K.: Verifying computations with streaming interactive proofs. Proc. VLDB Endow.5(1), 25–36 (2011). [https://doi.org/10.14778/2047485.2047488,http://www.vldb.org/pvldb](https://doi.org/10.14778/2047485.2047488,http://www.vldb.org/pvldb) /vol5/p025_grahamcormode_vldb2012.pdf

[22]Dao, Q., Thaler, J.: Constraint-packing and the sum-check protocol over binary tower fields. Cryptology ePrint Archive, Paper 2024/1038 (2024),[https://eprint.iacr.org/2024/1038](https://eprint.iacr.org/2024/1038)

[23]Dao, Q., Thaler, J.: More optimizations to sum-check proving. Cryptology ePrint Archive, Paper 2024/1210 (2024),[https://eprint.iacr.org/2024/1210](https://eprint.iacr.org/2024/1210)

[24]Diamond, B.: Sumchecks of medium degree.[https://hackmd.io/@benediamond/Sye_bB1wJl(2025](https://hackmd.io/@benediamond/Sye_bB1wJl(2025)), accessed 2026-03-24

[25]Diamond, B.E., Posen, J.: Succinct arguments over towers of binary fields. Cryptology ePrint Archive, Paper 2023/1784 (2023),[https://eprint.iacr.org/2023/1784,https://eprint.iacr.org/2023/1](https://eprint.iacr.org/2023/1784,https://eprint.iacr.org/2023/1) 784

[26]Diamond, B.E., Posen, J.: Polylogarithmic proofs for multilinears over binary towers. Cryptology ePrint Archive, Paper 2024/504 (2024),[https://eprint.iacr.org/2024/504,https://eprint.iacr.org/](https://eprint.iacr.org/2024/504,https://eprint.iacr.org/) 2024/504

[27]Domb, Y.: The Barrett-Montgomery duality and a new multi-precision modular reduction scheme with only*n² −*1 operations.[https://medium.com/@ingonyama/the-barrett-montgomery-duality-and](https://medium.com/@ingonyama/the-barrett-montgomery-duality-and) -a-new-multi-precision-modular-reduction-scheme-with-only-n2-1-b40ede4792da(2024), accessed: 2025-04-09

[28]Fiat, A., Shamir, A.: How to prove yourself: Practical solutions to identification and signature problems. pp. 186–194 (1986)

[29]Fog, A.: Instruction Tables: Lists of instruction latencies, throughputs and micro-operation breakdowns for Intel, AMD and VIA CPUs. Technical University of Denmark (2025),[https://www.agner.org/op](https://www.agner.org/op) timize/instruction_tables.pdf

[30]Goldwasser, S., Kalai, Y.T., Rothblum, G.N.: Delegating computation: interactive proofs for muggles. Journal of the ACM (JACM)62(4), 1–64 (2015)

[31]Google: Trace event format.[https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQt](https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQt) YMH4h6I0nSsKchNAySU/preview(2024)

[32]Gouvˆea, C.P., L´opez, J.: Implementing gcm on armv8. In: Topics in Cryptology—CT-RSA 2015: The Cryptographer’s Track at the RSA Conference 2015, San Francisco, CA, USA, April 20-24, 2015. Pro- ceedings. pp. 167–180. Springer (2015)

[33]Gruen, A.: Some improvements for the piop for zerocheck. Cryptology ePrint Archive (2024)

[34]Heisler, B.: Criterion.rs: Statistics-driven micro-benchmarking in rust.[https://github.com/criteri](https://github.com/criteri) on-rs/criterion.rs(2024)

[35]Intel Corporation: New instructions supporting large integer arithmetic on intel®architecture proces- sors. Technical whitepaper (PDF) (2013),[https://raw.githubusercontent.com/wiki/intel/intel](https://raw.githubusercontent.com/wiki/intel/intel) -ipsec-mb/doc/ia-large-integer-arithmetic-paper.pdf

[36]Karatsuba, A.A.: The complexity of computations. Proceedings of the Steklov Institute of Mathematics- Interperiodica Translation211, 169–183 (1995)

[37]Kothapalli, A., Setty, S.: Hypernova: Recursive arguments for customizable constraint systems. In: Annual International Cryptology Conference. pp. 345–379. Springer (2024)

[38]Kothapalli, A., Setty, S.: NeutronNova: Folding everything that reduces to zero-check. Cryptology ePrint Archive, Paper 2024/1606 (2024),[https://eprint.iacr.org/2024/1606](https://eprint.iacr.org/2024/1606)

[39]Liu, T., Zhang, Y.: Efficient SNARKs for boolean circuits via sumcheck over tower fields. Cryptology ePrint Archive, Paper 2025/594 (2025),[https://eprint.iacr.org/2025/594](https://eprint.iacr.org/2025/594)

[40]Liu, T., Zhang, Z., Zhang, Y., Hu, W., Zhang, Y.: Ceno: Non-uniform, segment and parallel zero- knowledge virtual machine. Journal of Cryptology38(2), 17 (2025)

[41]Lund, C., Fortnow, L., Karloff, H., Nisan, N.: Algebraic methods for interactive proof systems. In: FOCS (Oct 1990)

[42]Montgomery, P.L.: Modular multiplication without trial division. Mathematics of Computation44(170), 519–521 (1985). [https://doi.org/10.2307/2007970,https://doi.org/10.2307/2007970](https://doi.org/10.2307/2007970,https://doi.org/10.2307/2007970)

[43]Nair, V., Thaler, J., Zhu, M.: Proving CPU executions in small space. Cryptology ePrint Archive, Paper 2025/611 (2025),[https://eprint.iacr.org/2025/611](https://eprint.iacr.org/2025/611)

[44]Nguyen, W., Setty, S.: Neo: Lattice-based folding scheme for ccs over small fields and pay-per-bit commitments. Cryptology ePrint Archive (2025)

[45]Novakovic, A., Angeris, G.: Ligerito: A small and concretely fast polynomial commitment scheme (2025)

[46]Schorn, E.: Optimizing pairing-based cryptography: Montgomery multiplication in assembly.https: //www.nccgroup.com/research-blog/optimizing-pairing-based-cryptography-montgomery-m ultiplication-in-assembly/(2021)

[47]Scott, M.: Implementing cryptographic pairings. In: Pairing-Based Cryptography–Pairing 2007: First International Conference, Tokyo, Japan, July 2-4, 2007. Proceedings 1. pp. 177–196. Springer (2007)

[48]Scott, M.: Slothful reduction. Cryptology ePrint Archive, Paper 2017/437 (2017),[https://eprint.i](https://eprint.i) acr.org/2017/437

[49]Setty, S.: Spartan: Efficient and general-purpose zksnarks without trusted setup. In: Annual Interna- tional Cryptology Conference. pp. 704–737. Springer (2020)

[50]Setty, S., Angel, S., Gupta, T., Lee, J.: Proving the correct execution of concurrent services in zero- knowledge (Oct 2018)

[51]Setty, S., Thaler, J.: Twist and shout: Faster memory checking arguments via one-hot addressing and increments. Cryptology ePrint Archive, Paper 2025/105 (2025),[https://eprint.iacr.org/2025/105](https://eprint.iacr.org/2025/105)

[52]Setty, S., Thaler, J., Wahby, R.: Customizable constraint systems for succinct arguments. Cryptology ePrint Archive, Paper 2023/552 (2023),[https://eprint.iacr.org/2023/552](https://eprint.iacr.org/2023/552)

[53]Setty, S., Thaler, J., Wahby, R.: Unlocking the lookup singularity with lasso. In: Annual International Conference on the Theory and Applications of Cryptographic Techniques. pp. 180–209. Springer (2024)

[54]Shamir, A.: Ip= pspace. Journal of the ACM (JACM)39(4), 869–877 (1992)

[55]Succinct: Sp1 hypercube: Proving ethereum in real-time.[https://blog.succinct.xyz/sp1-hypercu](https://blog.succinct.xyz/sp1-hypercu) be/(2025)

[56]Supranational: blst: Multilingual rsa-and ecdsa-capable bls12-381 signature library.[https://github.c](https://github.c) om/supranational/blst(2024)

[57]team, T.I.: Binius: Rust implementation of Snark over towers of binary fields (2023),[https://gitlab](https://gitlab) .com/IrreducibleOSS/binius

[58]Thaler, J.: Time-optimal interactive proofs for circuit evaluation. In: CRYPTO (2013)

[59]Thaler, J.: Proofs, arguments, and zero-knowledge. Foundations and Trends in Privacy and Security 4(2–4), 117–660 (2022)

[60]Toom, A.: The complexity of a scheme of functional elements realizing the multiplication of integers. In: Soviet Mathematics Doklady, No 3. pp. 714–716 (1963)

[61]Vu, V., Setty, S., Blumberg, A.J., Walfish, M.: A hybrid architecture for verifiable computation (2013)

[62]Wahby, R.S., Ji, Y., Blumberg, A.J., Shelat, A., Thaler, J., Walfish, M., Wies, T.: Full accounting for verifiable outsourcing (2017)

[63]Wahby, R.S., Tzialla, I., Shelat, A., Thaler, J., Walfish, M.: Doubly-efficient zkSNARKs without trusted setup (2018)

[64]Wei, Y., Wang, K., Xiang, B., Zhang, X., Wang, H., Deng, Y., Zhu, X., Lin, L.: Packed sumcheck over fields of small characteristic with application to verifiable FHE. Cryptology ePrint Archive, Paper 2025/719 (2025),[https://eprint.iacr.org/2025/719](https://eprint.iacr.org/2025/719)

[65]Xie, T., Zhang, J., Zhang, Y., Papamanthou, C., Song, D.: Libra: Succinct zero-knowledge proofs with optimal prover computation (2019)

[66]XopMC: secp256k1-x64-avx: very fast (not secure) implementation of arithmetic on curve secp256k1 on x86 64.[https://github.com/XopMC/secp256k1-x64-avx](https://github.com/XopMC/secp256k1-x64-avx), rEADME benchmark: Montgomery mul = 49 cycles/op on Intel Core i7-6700 (Skylake); 93 cycles/op on Intel Core i3-2328M (Sandy Bridge)

[67]Zhang, J., Xie, T., Zhang, Y., Song, D.: Transparent polynomial delegation and its applications to zero knowledge proof. In: 2020 IEEE Symposium on Security and Privacy (SP). pp. 859–876. IEEE (2020)

[68]Zhang, Y., Genkin, D., Katz, J., Papadopoulos, D., Papamanthou, C.: vSQL: Verifying arbitrary SQL queries over dynamic outsourced databases (2017)

[69]Zhang, Y., Genkin, D., Katz, J., Papadopoulos, D., Papamanthou, C.: vRAM: Faster verifiable RAM with program-independent preprocessing (2018)

## A Auxiliary procedures

In this section, we list the procedures that are called by the algorithms in the paper.

### A.1 Equality polynomial evaluations

Procedure 3 computes the equality polynomial evaluations eqe (*w,x*) for*w∈*F *ℓ* and*x∈{*0*,*1*}* *ℓ* using 2 *ℓ* bb multiplications. Procedure 4 is a memoized version of Procedure 3 that additionally stores the intermediate result*{e*(*w*[1: *i*]*,x*)*}* *ℓi* =1at each step*i*.

Procedure 3Compute eqe (*w,x*) for all*x∈{*0*,*1*}* *ℓ*

Input: *w∈*F *ℓ*

Output:vsuch thatv[nat(*x*)] = eqe (*w,x*) for all*x∈{*0*,*1*}* *ℓ* 2 *ℓ* 1: Initialize:an all-one vectorv:= (1*,*1*,...,*1)*∈*F 2: Initialize: *s*:= 1 3: for*i*= 0*,...,ℓ−*1do 4: for*j*=*s−*1*,...,*0do 5: v[*j*+*s*] :=v[*j*]*·wi* 6: v[*j*] :=v[*j*]*−*v[*j*+*s*] 7: end for 8: *s*:=*s·*2 9: end for 10: return v

*i* Procedure 4Compute*{*eqe (*w*[1: *i*]*,x*) : *x∈{*0*,*1*}}*for all*i∈*[*ℓ*] *ℓ* Input: *w∈*F *i*
Output:v₁*,...,*v*ℓ*such thatv*i*[nat(*x*)] = eqe (*w*[1: *i*]*,x*) for all*i*= 1*,...,ℓ*and*x∈{*0*,*1*}*
*i* 1: Initialize:empty vectorsv*i*of size 2 for all*i*= 1*,...,ℓ*. 2: Initialize: v₀ := (1) and*s*:= 1 3: for*i*= 0*,...,ℓ−*1do 4: for*j*=*s−*1*,...,*0do 5: v*i*+1[*j*+*s*] :=v*i*[*j*]*·wi* 6: v*i*+1[*j*] :=v*i*[*j*]*−*v*i*+1[*j*+*s*] 7: end for 8: *s*:=*s·*2 9: end for 10: return v₁*,...,*v*ℓ*

||(X) = eq|e (w ,(r|
|---|---|---|
||i|[:i] [<i]|
|i c∈U b|i|i|

We also derive a procedure to compute the round polynomial*s,X*))*·ti*(*X*) given evaluations*{t* (*c*)*}* and the claimed equality*si*(0) +*si*(1) =*T*, where*T* is the claimed value of the *d* round. This is given in Procedure 5, and can easily be seen to be correct.

<u>Procedure 5Computes(X) =ℓ(X)·t(X) given evaluations{t(c)} and the conditions(0) +s(1) =T</u> <u>c∈Ubd</u> Input:Evaluations*{t*(*c*)*}* for a polynomial*t*(*X*) of degree*d*, a linear polynomial*ℓ*(*X*) with*ℓ*(0)*̸*= 0, *c∈U*b*d* and a target sum*T∈*F Output:Polynomial*s*(*X*) of degree*d*+ 1 such that*s*(0) +*s*(1) =*T*and*s*(*X*) =*ℓ*(*X*)*·t*(*X*) *−*1 1: Compute*t*(0) =*ℓ*(0) *·*(*T−ℓ*(1)*·t*(1)). 2: Interpolate*t*(*X*) from*{t*(*c*)*}c∈Ud*. 3: return*s*(*X*) =*ℓ*(*X*)*·t*(*X*).

Exact cost of the memoized equality-polynomial procedures.For Procedure 3, across rounds*i*= *i i ℓ* 0*,...,ℓ−*1, each round performs exactly 2 bbmultiplications and 2 additions; summing gives (2 *−*1)bb *ℓ* multiplications and (2 *−*1) additions. For Procedure 4, the arithmetic counts are identical, and it additionally P*ℓ* *i ℓ*+1 materializes vectors of total size*i*=12 = 2 *−*2.

## B Implementation details for field arithmetic

### B.1 Optimized multiplication by small integers

We present a two-stage algorithm for multiplying a large field element in Montgomery form with a 64- bit unsigned integer. The key idea is to separate the initial integer multiplication from the final modular reduction.

B.1.1 Bignum multiplication Given a field element*a*
*′* =*aR*(mod*p*) represented by*N*64-bit limbs and a 64-bit integer*b*, we first compute the integer product*c*=*a* *′* *·b*. This is a standard multi-precision multiplication of an*N*-limb number by a single-limb number, which costs*N*native 64-bit multiplications and results in an (*N*+ 1)-limb integer*c*.

B.1.2 Barrett reduction for(*N*+ 1)-limb integers After obtaining the integer product*c*, we apply a specialized Barrett reduction to compute*c*(mod*p*). This reduction is optimized for inputs that are only slightly larger than the modulus (i.e., (*N*+ 1) limbs). The algorithm is presented in Procedure 6.

|Procedure 6Optimized Barrett reduction for an (|N|+ 1)-limb integer|
|---|---|---|
|Input:|||
|• An ( N + 1)-limb integer|c = ( c N ,...,c₀ ). 64 n p||
|• Precomputed constant|µ = ⌊ 2 · 2 / (2 p ) ⌋.||
|Output: c mod p as a N n p|-limb integer.||
|1: Let ˜= c ⌈c/ 2 ⌉. ▷||Round up the high part of c|
||64||
|2: Compute m := ⌊ (˜ ·c µ )|/ 2 ⌋. ▷|Estimate quotient c/ (2 p )|
|3: Compute r := c−m· 2|p. ▷|Signed result − 2 p < r < 4 p|
|4: If r < 0, set r←r + 2|p. ▷|Correct underflow|
|||′|
|5: Find k∈{ 0, 1, 2, 3 } such that ′ 6: return c|kp≤r < ( k + 1) p, and compute|c = r−kp.|

Lemma 8.*Assume*2 *n* *p* *−*1 *< p <*2 *n* *pand inputcsatisfies*0*≤c < p·*264*. Then the Barrett reduction* *in Procedure 6 is correct.*

*Proof.*Let*q*=*⌊c/*(2*p*)*⌋*, and write*c*= ˆ*·c* 2 *n* *p−δ*where ˆ=*c ⌈c/*2*np⌉*and 0*≤δ <*2*np*. The key claim is that *m*:=*⌊*(ˆ*·c µ*)*/*2 64 *⌋*satisfies*q−*1*≤m≤q*+ 1.

|||n +64|n||n|
|---|---|---|---|---|---|
|||n|n|||
||64|n −1||||
|||n +64||||
|||n||||
|||||64||
|64|64−n|64|n|64||
|64||64||||

*Upper bound (m≤q*+ 1*).*Since*µ≤*2 *n* *p* +64 */*(2*p*) and*c*= ˆ*·c* 2 *n* *p−δ≥*(ˆ*−c* 1)*·*2*np*:

ˆ*·c µ* ˆ*·c* 2*pc*+*δ c* 2*p* *m≤ ≤* = *≤* + *< q*+ 1 + 1 =*q*+ 2*.* 2 2*p* 2*p* 2*p* 2*p*

The last step uses*δ <*2 *n* *p<*2*p*(since*p >*2*p*). Since*m*and*q*are integers,*m≤q*+ 1. *Lower bound (q−*1*≤m).*Write*µ*= 2*p/*(2*p*)*−ε*where 0*≤ε <*1. Then:

ˆ*·c µ* ˆ*·c* 2*p*ˆ*·c ε c*+*δ* ˆ*·c ε* 64 = *−* 64 = *−.* 2 2*p* 2 2*p* 2

Since*c < p·*2 we have ˆ*≤c p·*2*p*+ 1*<*2 (using*p <*2*p*), so ˆ*·c ε/*2 *<*1. Also*δ/*(2*p*)*<*2 *n* *p* */*(2*p*)*<*1. Thus ˆ*·c µ/*2 *> c/*(2*p*)*−*1, giving*m*=*⌊*ˆ*·c µ/*2 *⌋> q−*2, i.e.,*m≥q−*1. Combining: *m∈{q−*1*,q,q*+ 1*}*, so*r*=*c−m·*2*p*satisfies*−*2*p < r <*4*p*. After correcting underflow (*r <*0 =*⇒r←r*+ 2*p*), we have 0*≤r <*4*p*, and*r≡c*(mod*p*). The final conditional subtraction of*kp* for*k∈{,,,}*then yields*c*mod*p*.

B.1.3 Alternative: Montgomery reduction For the linear combination optimization described in the main body, it is also possible to use Montgomery reduction on the final sum*T*, instead of Barrett reduction. A Montgomery reduction would compute
P *T·R* *−*1

(mod*p*). The result would be (*iciai*) (mod*p*), which is the correct value but is no longer in Montgomery form. If the surrounding protocol can accommodate a value in standard form, this is a valid alternative. However, a generic Montgomery reduction is typically more costly than the specialized single-pass Barrett reduction we employ, so Barrett reduction is generally preferred for this optimization.

### B.2 Extension field multiplication

In both monomial and tower bases, multiplication of extension field elements can be accelerated using variants of Karatsuba’s algorithm [36]. For an extension of degree*k*, this reduces the number of base field multiplications from*k²* to*O*(*k* log23 )*≈O*(*k¹*

*.*585 ). For the monomial basis, Karatsuba’s algorithm is used
for polynomial multiplication. For the tower basis, it is applied recursively to multiply elements in smaller subfields.

### B.3 Hardware considerations

In FPGAs and ASICs, multiplication in binary fields is highly efficient when field elements are represented us- ing a tower basis. Current CPUs, however, do not natively support efficient multiplication in the tower basis, but they do support fast multiplication in a different (monomial) basis forGF(2 128 ), known as POLYVAL. For instance, ARMv8 provides the PMULL instruction, which efficiently multiplies two 64-bit inputs. To extend multiplication to 128-bit inputs, one can apply the techniques described in [32, Algorithms 2 and 3], which invoke PMULL multiple times. Indeed, BearSSL¹³ contains optimized implementations ofGF(2 128 ) multipli- cation in the POLYVAL basis for both x86 64 and ARM64 architectures, utilizing the PMULL instruction for ARM64 and the PCLMULQDQ instruction for x86 64 [25]. Additionally, Intel’s Galois Field instruction set (GFNI), originally targetingGF(2 8 ) multiplications for AES computations, can be leveraged—together with Karatsuba’s algorithm—to achieve reasonably efficientGF(2 128 ) multiplications by decomposing bigger operations into sequences of smaller ones.

## C Details of sum-check prover algorithms

In this section, we give full details of the three existing algorithms for the sum-check prover (spanning the time-space trade-off spectrum) with a fine-grained analysis of their cost in each round. We also give missing details of the combined small-value and streaming algorithm in Section 5, along with the equality polynomial handling in Section 6. As with the main body, we focus on the product of multilinear polynomials case, where the polynomial*g*(*x*) is given as *g*(*X*) =*p₁*(*X*)*·p₂*(*X*)*···pd*(*X*)*,*(8)

with*p₁,...,pd*being multilinear polynomials in*ℓ*variables. Recall that we denote*M*= 2 *ℓ* to be the instance size.

### C.1 Linear time and linear space

The first algorithm we consider is the linear-time, linear-space algorithm from prior work [61, 58]. The key idea ofLinearTimeSCis that, by maintaining a cache of the partial evaluations of the polynomials*p₁,...,pd* at (*r₁,...,ri−*1) in each round*i*, the prover can compute the round polynomial*si*(*u*) and update the cache

|ℓ−i||ℓ|||
|---|---|---|---|---|
||ℓ||||
||SC||||
|d|ℓ|k|k k∈[d]|ℓ i|

for the next round in*O*(*d² ·*2 *ℓ−i* ) time, leading to*O*(*d² ·*2 *ℓ* ) time in total. Unfortunately, storing the cache, especially after the first round, requires*O*(*d·*2) space as well.

Figure 4 gives the full details ofLinearTime. The prover maintains*d*arrays*P₁,...,Pd*, which initially

store all evaluations of*p₁,...,p* over*{*0*,*1*}*, e.g., we have*P* [*x*] =*pk*(*x*) for all*k∈*[*d*] and*x∈{*0*,*1*}*. The prover halves the size of the arrays after each round*i*, via “binding” the arrays*{P}* to the challenge*r* <u>received from the verifier.</u> [https://bearssl.org/](https://bearssl.org/)

### LinearTimeSC

*ℓ* (0) (0) Initialize:Length-2 arrays*P₁,...,P* *d* such that

(0) *ℓ*
*P* *k* [*x*] =*pk*(*x*) for all*k*= 1*,...,d*and*x∈{*0*,*1*}.*

#### For each roundi= 1,...,ℓ:

1.For*u∈ U*b*d*, compute*si*(*u*) using the formula
X Y*d* (*i−*1) (*i−*1) (*i−*1) *P* *k* [1*,x* *′*]*−P* *k* [0*,x* *′*] *·u*+*P* *k* [0*,x* *′*]*.* *x* *′* *∈{*0*,*1*}ℓ−ik*=1

n o

2.Send *si*(*u*) : *u∈ U*b*d*to the verifier.
3.Receive challenge*ri∈*Ffrom the verifier.

||′|ℓ−i||||
|---|---|---|---|---|---|
||(i) k|′ (i−1) k|′ (i−1) k|′|(i−1) i k|
|k (i) ′|k [1:i] ′||′|ℓ−i||

4.For*k*= 1*,...,d*and*x*
*′* *∈{*0*,*1*}* *ℓ−i*, update arrays:

*′* *P* [*x*] := *P* [1*,x*]*−P* [0*,x*] *·r* +*P* [0*,x*]*.*

<u>Note: P [x] =p (r,x)∀k∈[d],i∈[0,ℓ],x ∈{0,1}.</u>

Figure 4: Linear time, linear space prover [61, 58]

C.1.1 Cost analysis ofLinearTimeSC. We now give a fine-grained analysis of the cost ofLinearTimeSC. •Per-round operations:In each round*i∈*[*ℓ*], the prover first computes the evaluations of the round polynomial*si*(*u*) for all*u∈ U*c*d*, then updates an auxiliary array for the subsequent round. •Cost of evaluations:The computation of each of the*d*evaluations for*si*involves a sum over 2
*ℓ−i*

terms. Each term is a product of*d*values, requiring*d−*1 multiplications. Note that we may compute the evaluations of each*pk*at 0*,∞,*2*,...*purely by additions and subtractions, requiring no multiplications.

–Cost: *d×*(*d−*1)*×*2 *ℓ−i* multiplications.

•Cost of array updates:The prover updates an array of size*d·*2 *ℓ−i*. This requires one multiplication per entry.

–Cost: *d·*2 *ℓ−i* multiplications.

•Total cost for round*i*:The total number of multiplications in round*i*is the sum of these two steps:

*d*(*d−*1)*·*2 *ℓ−i* +*d·*2 *ℓ−i* =*d² ·*2 *ℓ−i* *.*

•Total cost across all rounds:Summing over all*ℓ*rounds, the total number of multiplications is:

X*ℓ*X*ℓ−*1 *d² ·*2 *ℓ−i* =*d²* 2 *j* =*d²*(2 *ℓ* *−*1)*≈d² ·M.* *i*=1 *j*=0

The additions / subtractions are of the same order: generating the*d*evaluations of each linear factor already costs*d*(*d−*1)2 *ℓ−i* additions per round, so the total is Θ(*d² ·M*).

### LogSpaceSC

#### For each roundi= 1,...,ℓ:

1.For*u∈ U*b*d*, compute*si*(*u*) by streaming through the inputs:
  X Y*d*X *s* *i*

(*u*) =  eqe (*r*[*<i*]*,b*)*·pk*(*b,u,x*
*′*

)*,*(9)
*x* *′* *∈{*0*,*1*}ℓ−ik*=1 *b∈{*0*,*1*}i−*1

where the values eqe (*r*[*<i*]*,b*) are computed on-the-fly for each*b*.

2.Send*{si*(*u*) : *u∈ U*b*d}*to the verifier.
3.Receive challenge*ri∈*Ffrom the verifier.
Figure 5: Quasilinear time, logarithmic space prover [21]
 Thus, in the general case, where none of*pk*have small evaluations, we have the following cost summary. Lemma 9.*For general multilinear polynomialsp₁,...,pdover the finite field*F*,*LinearTimeSC*performs* *exactlyd²*(*M−*1)*field multiplications and*Θ(*d² ·M*)*field additions/subtractions.* When the evaluations of*p₁,...,pd*are small.In this case, we have that the computation of*s₁*(*u*) in round 1 are entirelyssmultiplications. The binding of the arrays in round 1 now usesbmultiplications. When all but one of the polynomials*p₁,...,pd*have small evaluations.In this case (which happens for instance when one of the*pi*terms is the equality polynomial eqe (*w,x*) for some*w∈*F
*ℓ* chosen prior by the verifier), we must convert*d·M/*2 multiplications in the computation of*s₁*(*u*) fromss(in the case where all of*p₁,...,pd*have small evaluations) tosbmultiplications.

### C.2 Quasilinear time and logarithmic space

Next, we describeLogSpaceSC, a sum-check prover implementation with*O*(*ℓ·*2 *ℓ* ) time and*O*(*ℓ*) space [21]. This algorithm avoids storing large tables of partially evaluated polynomials by recomputing the necessary values from the initial streams in each round. The core idea is that for each round*i*, the prover can compute the partial evaluations*pk*(*r₁,...,ri−*1*,u,x* *′* ) directly from the initial inputs by applying the multilinear extension formula (Equation (2)). This involves summing over the Boolean hypercube of dimension*i−*1. The Lagrange coefficients eqe (*r*[*<i*]*,b*) needed for this expansion can be generated in a streaming fashion, requiring only*O*(*i*) space. As the prover iterates through all inputs for each round, no large state needs to be maintained between rounds.

C.2.1 Cost analysis ofLogSpaceSC. We first analyze the*general case*(no small-evaluation assumption), then state the changes in the small- evaluation setting. •Per-round operations:In round*i∈*[*ℓ*] and for each*u∈ U*c*d*(there are*d*such points), we stream over all*x* *′* *∈{*0*,*1*}*
*ℓ−i*. For each*x* *′* and each*k∈*[*d*] we compute the inner sum X *Sk*(*u,x* *′* ) := eqe (*r*[*<i*]*,b*)*·pk*(*b,u,x* *′* )*.* *b∈{,}i−*

We then multiply the*d*values*{Sk*(*u,x* *′* )*}* *d* *k*=1and add the product into*si*(*u*).

•Cost of inner sums*Sk*:For fixed (*u,x* *′* *,k*), the sum has 2 *i−*1 terms. Each term multiplies a big coefficient eqe (*r*[*<i*]*,b*) by a big value*pk*(*b,u,x* *′* ), so each such multiply is abbmultiply. The additions to accumulate the sum are over field elements.

–Multiplies per(*u,x* *′* *,k*):2 *i−*1 bb. –Adds per(*u,x* *′* *,k*):2 *i−*1 *−*1.

|||′||ℓ−i||′|i−1|
|---|---|---|---|---|---|---|---|
|ℓ−1||′ ′|ℓ−1|ℓ−i ℓ−i|′|′|d ℓ−i|

–Per round*i*across all*u,x,k*: *d*(choices of*u*)*×*2 (choices of*x*)*×d*(choices of*k*)*×*2 =*d² ·*2 bbmultiplies. –Adds per round*i*across all*u,x,k*: *d² ·*(2 *−*2).

•Cost of forming the product across*k*:For each (*u,x*), we multiply*d*big values*S₁,...,S* to produce their product, which requires*d−*1bbmultiplies.

–Per round*i*across all*u,x* : *d*(choices of*u*)*×*2 (choices of*x*)*×*(*d−*1) =*d*(*d−*1)*·*2 bb multiplies.

|i−1|||
|---|---|---|
|j|i−1 j=1 j|i|
|||′|

•Cost to generate eqe (*r*[*<i*]*,·*)coefficients:The 2 coefficients can be generated once per round via P the standard doubling recurrence*C7→*((1*−rj*)*·C, r ·C*) for*j*= 1*,...,i−*1. This costs 2 = 2 *−*2 multiplications; these arebb. This table (or an equivalent on-the-fly generator) is shared by all*u,x,k*in round*i*.

–Per round*i*: *O*(2 *i* ) multiplications (predominantlybb), plus*O*(2 *i* ) additions.

#### •Total cost for roundi(general case):

||2 ℓ− 1||ℓ−i|i|
|---|---|---|---|---|
|bbfrom inner sums||bbfrom products||bbfrom coeffs|
|ℓ−i||i|||

*d* | *·* {z 2 } +*d*<u>(d−</u>1)<u>·2</u> + (2 *−*2)*.* | {z} | {z}

Additions: *d² ·*(2 *ℓ−*1 *−*2) from inner sums and*O*(2) from coefficient generation.

#### •Totals across all rounds (general case):

bbmultiplications:

X*ℓ*

||||ℓ−1|ℓ−i|i|
|---|---|---|---|---|---|
|||i=1|ℓ−1|ℓ|ℓ+1|
||||ℓ|||
|ℓ i=1|2 ℓ−1|ℓ−i|ℓ+1|2 ℓ−1|ℓ|

*d²*2 *ℓ−*1 +*d*(*d−*1)2 *ℓ−i* + (2 *i* *−*2)

=*d² ℓ*2 +*d*(*d−*1)(2 *−*1) + (2 *−*2*ℓ−*2)*.*

#### = Θ(d² ℓ2).

P *ℓ*+1 Additions: *d* (2 *−*2) + (2 *−*2) =*d* (*ℓ*2 *−*2 + 1) + 2 *−*2.

•Space Complexity:We maintain*O*(1) accumulators per*u*and per*k*, plus an*O*(*i*)-state generator for eqe (*r*[*<i*]*,·*). Hence*O*(*d*+*i*) words in round*i*, i.e.,*O*(*d*+*ℓ*) overall.

Small-evaluation setting.When all*pk*(*b,u,x* *′* ) are small at Boolean points, the inner-sum multiplies becomesb(counts unchanged): *d²*2 *ℓ−*1 sbmultiplications per round (and*d²*(2 *ℓ−*1 *−*2 *ℓ−i* ) additions). The product-across-*k*and coefficient-generation costs remainbbwith exact totals as above, i.e.,*d*(*d−*1)(2 *ℓ* *−*

1) + (2 *ℓ*+1 *−*2*ℓ−*2)bbmultiplications across all rounds. Recalling that*M*= 2
*ℓ* is the instance size, and rewriting in terms of*M*, we have the following cost summary (in the general case).

<u>d²</u> Lemma 10.*In the general case,*LogSpaceSC*performs M*log*M*+*d*(*d−*1)(*M−*1) + (2*M−*2 log*M−*2) 2 <u>d²</u> bb*multiplications and* (*M*log*M− M*+ 2) + (2*M−*2)*additions in total, and usesO*(*d*+ log*M*)*space.*

<u>d²</u> *In the small-evaluation setting, the M*log*Minner-sum*bb*multiplications become*sb*.*

### CrossProductk,SC

Inputs:Streams of evaluations for*p₁,...,pd*over*{*0*,*1*}* *ℓ*; parameter*k≥*2. Setup:Let*ℓ*be the number of variables,*M*:= 2 *ℓ* the instance size,*η*:=*d/*(*d−*1), and*ℓ₀* :=*⌊ℓ/*(*kd*)*⌋*.

#### For every roundj∈[ℓ]:

1.Initialize*P←*0.indicates whether a pass is executed.
2.Time-constrained phase (*j <*(*d−*1)*ℓ₀*):
(a)If*j*=*⌈η*
*t* *⌉*for some*t∈*N, set*P←*1 and*j* *′* :=*⌈η* *t* *⌉*.

(b)Define*w*(*j*
*′* ) := min(max(1*,⌈η* *t*+1 *⌉−⌈η* *t* *⌉*)*, ℓ−j* *′* + 1).rounds handled by the pass

3.Space-constrained phase (*j≥*(*d−*1)*ℓ₀*):
(a)If*ℓ₀ |j*, set*P←*1 and*j*
*′* :=*ℓ₀ ·⌈j/ℓ₀⌉*.

(b)Define*w*(*j*
*′* ) := min(*ℓ₀, ℓ−j* *′* + 1).

*′ j −* *′* 1

4.If*P*= 1(necessarily*j*=*j*):Let the received challenges be*r*[*<j′*]*∈*F. For all*x₁,...,xd∈* *w*(*j* *′* ) *{*0*,*1*}*, compute and store
X Y*d* *Mj′* [*x₁,...,xd*] := *pt*(*r*[*<j′*]*,xt,b*)*.* *b∈{*0*,*1*}ℓ−j′ −w*(*j′*)+1 *t*=1

5.At the current round*j*(necessarily*j∈{j*
*′* *, j* *′* + 1*, ..., j* *′* +*w*(*j* *′*

)*−*1*}*):
(a)Let ∆ :=*j−j*
*′* and let*r* *′* *∈*F ∆ denote the suffix of*r*[*<j*]after*r*[*<j′*](i.e., the challenges received so far in this stage).

(b)For all*z∈ U*b*d*,
*d* ! X Y X X*∗ ∗* *f* *j*

(*z*) = eqe (*r*
*′* *,βt*) *· z* *|b |* (1*−z*) *d−|b |* *Mj′ β₁∥b* *∗* 1 *∥b, ..., βd∥b* *∗* *d* *∥b.* *β₁,...,βd∈{*0*,*1*}*∆*t*=1 *b∈{*0*,*1*}w*(*j′*)*−*∆*−*1*b∗∈{*0*,*1*}d*

(c)Send*{fj*(*z*) : *z∈ U*b*d}*to*V*.
(d)Receive*rj*from*V*.
Figure 6: Cross-product-based streaming prover for products of*d*multilinear polynomials with parameter

*k*[10].

### C.3 Streaming via cross products

C.3.1 Cost analysis ofCrossProduct*k,*SC. We give a fine-grained accounting for the general*d*-polynomial setting. We default to the general (no small- evaluation) case (all multiplications arebbunless stated otherwise). Costs are split between: (i) passes that build the tables*Mj′* at stage starts*j*
*′*; and (ii) the per-round message computations within a stage.

Per-pass cost at stage start*j* *′* .Let the stage window be*w*:=*w*(*j* *′* )*∈*N(defined in Figure 6). There *ℓ−j −w* *′* +1 are*B*:= 2 values of*b*.

•Compute*X*

|[β]for eacht∈[d]:For a fixedbandβ|||∈{0,1}|,|||
|---|---|---|---|---|---|---|
|t t|t t j − w j − 1 w j − 1|x∈{0,1} 1 ℓ|t] j − w j − 1|w t t 1|w j − 1|w|

X *X* [*β*] := eqe (*r*[*<j′,x*)*·p* (*x,β,b*)*.* *j′ −*1 *′ ′* Exact operations (per*b*): for each*t*, 2 multiplications and 2 *−*1 additions; across 2 choices of*βt* and all*d*polynomials this is *′ ′* *d*2 (2) mults and*d*2 (2 *−*1) adds*.* *′ ′* *ℓ* Aggregated across all*b*’s: *dB*2 (2) =*d*2 =*dM*multiplications and*dB*2 (2 *−*1)*≤d*2 =*dM* additions.

|||||j|d|w d|
|---|---|---|---|---|---|---|
|d|||||||
|t=1|t t|j ′|dw dw|dw dw dw ℓ−j −w|ℓ+1||

•Form the*d*-wise product and accumulate into*M ′*:For each *β⃗*= (*β₁,...,β*)*∈*(*{*0*,*1*}*), Q compute *X* [*β*] and add into*M ′* [*β⃗*]. This takes (*d−*1) multiplications and 1 addition per entry. There are 2 *dw* entries, hence per*b*we use (*d−*1) 2 multiplications and 2 additions. Across all*b*’s this is

(*d−*1)*B*2 mults and*B*2 adds*.* *′* +1+*dw* Our scheduling ensures (*d−*1)*w≤j* (both phases), so*B*2 = 2 *≤*2 = 2*M*. Thus this product-and-accumulate step is bounded by at most 2(*d−*1)*M*multiplications and 2*M*additions per pass.

#### Per-pass total (exact upper bound):

|{z} *dM* + 2( | <u>d</u>*−* {z

<u>1)M</u> } = (3*d−*2)*M*multiplications,
*Xt* sums products

#### and at most (d+ 2)Madditions.

Per-round cost within a stage[*j* *′* *, j* *′* +*w−*1].Write ∆ :=*j−j* *′* *∈{*0*,...,w−*1*}*.

•Generate Lagrange coefficients for the recent challenges*r* *′* *∈*F ∆ :Generate*{*eqe (*r* *′* *,b*) : *b∈* *{*0*,*1*}* ∆ *}*once and reuse it across all*t∈*[*d*]. Exact per round: (2 ∆+1 *−*2) multiplications and (2 ∆+1 *−*2) additions (shared across*fj*(0)*,fj*(1)*,fj*(*z*)).

•Form inner partial sums over*Mj′*:For each (*b₁,...,bd*)*∈{*0*,*1*}* ∆*d* and each pattern*b* *∗* *∈{*0*,*1*}* *d*, take the sum over*b∈{*0*,*1*}* *w−*∆*−*1 of the relevant*Mj′* entries. This is additions-only: exactly 2 *w−*∆*−*1 *−*1 additions per pair, giving [2 *w−*∆*−*1 *−*1]*·*2 *d*(∆+1) additions.

•Scale by coefficient products and assemble*fj*: Q*d* *′ d*∆ –Compute the coefficient products*t*=1eqe (*r,bt*) once per tuple (*b₁,...,bd*), costing (*d−*1) 2 multi- plications. –For*u∈ {*0*,*1*}*: apply the cached coefficient product to the two relevant partial sums, costing 2 2 *d*∆

multiplications. *d ∗ d |b* *∗* *| d−|b* *∗* *| d d*∆ –For*fj*(*z*): combine the 2 patterns*b ∈{*0*,*1*}* with weights*z* (1*−z*). This costs 2 2 multipli- cations for the weights, (2 *d* *−*1) 2 *d*∆ additions to sum the weighted terms, and a final 2 *d*∆ multiplications to scale by the cached coefficient product.

*Per-round totals:*

|∆+1|d d∆|
|---|---|
|∆+1|w−∆−1 d(∆+1)|

mults = (2 *−*2) + *d*+ 2 + 2 2*,*

adds = (2 *−*2) + 2 *−*1 2 + (2 *d* *−*1) 2 *d*∆ *.*

Summing ∆ = 0 to*w−*1 within the stage gives *w* X *−*1 (2 ∆+1 *−*2) = 2 (2 *w* *−*1)*−*2*w,* ∆=0 *w* X *− dw* *d d*∆ *d*<u>−</u> *d*+ 2 + 2 = *d*+ 2 + 2 *d* *.* *−* ∆=0

### CrossProductSC

#### Letℓ₀ =⌊ℓ/(2d)⌋.

#### Time-constrained phase (1≤j <(d−1)ℓ₀):

•Passes are made in rounds*j* *′ t*

||=⌈η|⌉fort∈Nwhereη=d/(d−1). Letw|||= max(1,⌈η||⌉−⌈η|⌉).|
|---|---|---|---|---|---|---|---|---|
|′ w|j||i d||i|i i|i|j − 1|
||j|d|b∈{0,1}|d i [<j i=1|] i||||

*j* *′* *t*+1 *t*

*′* •In round*j*, for each of the*d*polynomials*p*, compute and store tables*P* [*b,x*] for*b ∈{*0*,*1*}* and *xi∈{*0*,*1*}j′*.

•Compute and store table*M ′* for*x₁,...,x ∈{*0*,*1*}* *wj′*

X Y *M ′* [*x₁,...,x*] := *p* (*r ′,x,b*)*.* *ℓ−j′−wj′* +1

#### Space-constrained phase ((d−1)ℓ₀ ≤j≤ℓ):

#### •Passes are made everyℓ₀ rounds.

|j|d|ℓ||
|---|---|---|---|
||d|||
|d||i [<j|] i|
|b∈{0,1}|i=1|||

•In round*j* *′*, compute and store table*M ′* for*x₁,...,x ∈{*0*,*1*}*0

X Y *Mj′* [*x₁,...,x*] := *p* (*r ′,x,b*)*.* *ℓ−j′ −ℓ*0 +1

Figure 7: Cross-product-based streaming prover following prior work [10]

*dw dw*

|Hence, within a stage the round-message work isO(2||) multiplications andO(2|) additions. Since our|
|---|---|---|---|
|d d|dw /k|d /k|d|

schedule ensures 2 *dw* *≤M¹* */k*, each stage contributes at most*c M¹* */k* multiplications for*c* := (*d*+ 2 +

2)*/*(2 *−*1) + 2. Number of stages and overall time.The number of passes (stages) is Θ log*η*(*ℓ₀*) +*dk* with*η*= *d/*(*d−*1) and*ℓ₀* =*⌊ℓ/*(*kd*)*⌋*. Combining with the per-pass bound, the total multiplication count is
(3<u>d</u>*−*<u>2)M</u> *× ⌈*log*η*(*ℓ₀*)*⌉*+*dk* +*O* (log*η*(*ℓ₀*) +*dk*)*M¹* */k* *,* | {z} | {z} per pass num. passes

which, using log*η*(*x*) = ln(*x*)*/*ln(*d/*(*d−*1)) = Θ(*d*log*x*), simplifies to Θ *d² ·M·*(log log*M*+*k*) big-field multiplications, plus a lower-order*O d*(log log*M*+*k*)*M¹* */k* tail.

Small-evaluation variant.If each*pt*(*x*) is small on Boolean inputs, then multiplications inside the*Xt* sums aresb(counts unchanged). All other multiplications (coefficient generation,*d*-wise products, and the *z*-weights) remainbb.

Switch to folding-based sum-check in the final*ℓ/k*rounds.As suggested in prior work [10] (see discussion after Fig. 2 therein), one can switch fromCrossProduct*k,*SCto the folding-based prover from prior work [21, 58] for the final*ℓ/k*rounds. This preserves the*O*(*M¹* */k* ) space and reduces the tail cost; we defer a detailed cost derivation for this switch to a later subsection. Next, we describe the cross-product algorithm in its*k*= 2 specialization (the familiar*O*(*M¹* */* )-space setting from Baweja et al. [10]). Let*ℓ₀* =*⌊ℓ/*(2*d*)*⌋*.

The protocol is split into two phases. The space-constrained phase begins at round (*d−*1)*ℓ₀*. In this phase, a pass is made over the input streams every*ℓ₀* rounds. The time-constrained phase covers rounds *j <*(*d−*1)*ℓ₀*. In this phase, passes are made in rounds*j* *′* =*⌈η* *t* *⌉*for*t∈*N, where*η*=*d/*(*d−*1). The computation of the round polynomial*si*(*u*) for a round*i*within a stage (that started at round*j* *′* ) can be expressed as an inner product. Let*r<i* *′* *−j′* be the challenges received between round*j* *′* and*i−*1. The value*si*(*u*) is a sum over the remaining variables*x* *′* of a product of polynomials evaluated at the full challenge vector (*r*[*<j′*]*,r<i* *′* *−j′*). By expanding this expression similarly to the derivation in Section C.1, we can separate the challenge-dependent parts from the precomputed parts:

X Y*d* *s* *i*

(*u*) = *pk*(*r*[*<j′*]*,r<i*
*′* *−j′,u,x* *′* ) *x* *′k*=1 *d* ! X Y = *χbk*(*r<i* *′* *−j′*) *·* *b₁,...,bd∈{*0*,*1*}i−j′ k*=1 *d* ! X Y *pk*(*r*[*<j′*]*,bk,u,x* *′* )*.* *x* *′k*=1 P Q *′* The second term,*x′kpk*(*r*[*<j′*]*,bk,u,x*), can be computed from the precomputed table*Mj′*. The first term consists of products of Lagrange basis polynomial evaluations, which depend only on the recent chal- lenges*r<i* *′* *−j′*. This structure allows the prover to compute*si*(*u*) efficiently without new passes over the full dataset.

Lemma 11.*For anyk≥*2*, the cross-product-based streaming prover runs in time*Θ *d² ·M·*(log log*M*+*k*) *and usesO*(*M¹* */k* )*space.*

### C.4 Combined small value and streaming via evaluation-basis products

C.4.1 Analysis of the small value algorithm We analyze the early-window variant ofEvalProductSVSC(Figure 2) for the small-value setting where all input polynomials*p₁,...,pd*have small evaluations on*{*0*,*1*}*
*ℓ*. The algorithm defers binding by*v*rounds, computing the window polynomial *d*

|X|Y||
|---|---|---|
|||′|
|v|k|v|
|x ∈{0,1}|k=1||

*q*(*X₁,...,Xv*) = *pk*(*X₁,...,Xv,x*
*′* ) *′ ℓ−v*

on the (*d*+ 1) *v* evaluation grid using the multivariate product engine (Procedure 1), then answering*v*rounds from this grid. The cost has two components:

•Big-multiplication tail: The remaining*ℓ−v*rounds cost Θ(*d²M/*2 *v* ) big multiplications.

•Window computation: For each of the*M/*2 *v* suffix assignments, we compute one (*d*+ 1) *v* grid via multivariate products. For*v*= 1 this costs Θ((*d*+ 1) log*d*) per suffix, while for every fixed*v≥*2 it costs Θ(*d* *v* ) = Θ((*d*+ 1) *v* ) per suffix. In the early-window regime of interest we therefore summarize the total as <u>d+1</u> *v* Θ *M·* 2 small multiplications, up to*d*-independent constants.

Let*κ*be the big-to-small multiplication cost ratio (typically*κ≈*2*N²* +*N*where*N*is the limb count). We optimize in big-multiplication-equivalent units: 2 *v* *d M M d*+ 1 Costbig-eqv(*v*) = *v* + *·.* 2 *κ* 2

Ignoring integrality and clipping, the minimizer satisfies equality of the two terms: *v* *∗* *d M M d*+ 1 *∗* *v* *v* *∗*= *· ⇐⇒*(*d*+ 1) =*d κ.* *κ*

Thus the unconstrained optimum is

*∗* 2<u>2 logd+ logκ</u> *v* = log*d*+1*d κ* =*,* log(*d*+ 1)

then clipped to [0*,ℓ*] and rounded to an integer. At*v* *∗*, both terms contribute equally, giving big-multiplication-equivalent runtime

(big eqv) 2*−*2*/δ −*1*/δ* *T* SV (*M,d,κ*) = Θ *M·d ·κ,*

where*δ*= log₂(*d*+ 1); equivalently,

(big eqv) 2 2 *−*1*/δ* *T* SV (*M,d,κ*) = Θ *Md d κ.*

*∗ v* *∗* 2 The dominant space term is the stored window grid, so Space(*v*) = Θ((*d*+ 1)) = Θ(*d κ*) (up to constant factors).

Lemma 12(Small-value early window: optimal cost and space).*For cost ratioκbetween big and small* *multiplications, the unconstrained minimizer isv* *∗* = log*d*+1(*d²κ*)*, then clipped/rounded to a valid round* *∗ v* *∗* 2 *count. At thisv,*(*d*+ 1) *≍d κ, yielding:*

•*Big-multiplication-equivalent runtime:* Θ *M·d²* *−*2*/δ* *·κ* *−*1*/δ*

*v* *∗* 2 •*Space usage:* Θ((*d*+ 1)) = Θ(*d κ*)*(vsO*(*d·M*)*for*LinearTimeSC*)*

#### withδ= log₂(d+ 1).

C.4.2 Analysis of the streaming algorithm We analyze the evaluation-basis (round-batched) variant from Section 5. The algorithm materializes, per pass, an evaluation grid for a window polynomial and answers all rounds within the window from this grid. We compare with Baweja et al. [10]. Per-pass time bound.Fix a pass at*j*
*′* with window size*ω*. Each pass has two main cost components:

(i)prefix adaptation, where we must stream through all inputs to form the partial evaluations*pk*(*r*[*<j′*]*,·*) by applying Lagrange weights eqe (*r*[*<j′*]*,·*), costing Θ(*d·M*) big-field multiplications; and (ii)window grid computation, where we materialize the (*d*+ 1)
*ω* evaluation grid. With the multivariate product engine (Section 4), the grid computation costs ( Θ((*d*+ 1) log*d*)*ω*= 1*,* *T*(*d,ω*) = *ω* Θ((*d*+ 1))*ω≥*2 (*d*-independent constant)*.*

Under the constraint (*δ−*1)*ω≤j* *′*, we have*T*(*d,ω*) =*O*(*M*), so the grid work is absorbed by the Θ(*d·M*) prefix adaptation cost. Hence the total per-pass cost is Θ(*d·M*) big-field multiplications.

Number of passes.With*ωt≈jt′/*(*δ−*1), the starts satisfy*jt′*+1*≈jt′*+*ωt≈αjt′*, so the time-constrained phase takes Θ(log*αℓ*) = Θ(log*d·*log log*M*) passes. The space-constrained phase uses fixed*ω*=*ℓ/*(*kδ*) and requires Θ(*kδ*) = Θ(*k*log*d*) passes. Total passes are therefore Θ(log*d·*log log*M*+*k*log*d*) = Θ(log*d·* (log log*M*+*k*)).

Overall time and space.The number of time-constrained passes is*⌈*log*αℓ⌉*with*α*=*δ/*(*δ−*1), and Θ(*kδ*) = Θ(*k*log*d*) space-constrained passes. Each pass costs Θ(*d·M*) big-field multiplications due to prefix adaptation. Therefore

#### T(M,d,k) = Θ d·M·(logαℓ+kδ)

= Θ *d·M·*(log*d·*log log*M*+*k*log*d*)*,*

where we used log*αℓ*= ln*ℓ/*ln*α*and ln*α*= ln(*δ/*(*δ−*1))*≈ /*(*δ−*1) = Θ(1*/*log*d*). Factoring out log*d*, this becomes Θ *d·M·*log*d·*(log log*M*+*k*). The space usage is*O*(*M¹* */k* ) by construction.

Comparison with Baweja et al.Their coefficient-based streaming yields Θ(*d² ·M·*(log log*M*+*k*)) (up to growth-base constants). Our evaluation-basis streaming achieves Θ(*d·M·*log*d·*(log log*M*+*k*)), improving by roughly a factor of*d/*log*d*over the prior approach, while preserving*O*(*M¹* */k* ) space.

Lower-order terms.If one multiplies*d*factors pointwise without reuse, the exact big-multiplication count is (*d−*1)(*d*+ 1) *ω*. The recursive product replaces this with*O*((*d*+ 1) log*d*) when*ω*= 1 and with*O*((*d*+ 1) *ω* ) for every fixed*ω≥*2. Additions and small-by-big operations contribute lower-order terms that do not change the asymptotic in*M*.

Dependence on*d*: old vs. new.For the existing algorithm of Baweja et al. [10], the*d*-dependence per phase is:

•Time-constrained phase: log*η*(*ℓ*) passes with*η*=*d/*(*d−*1), so*≈*(*d−*1) ln*ℓ*= Θ(*d*log log*M*). Per-pass *d*-dependence Θ(*d*), yielding Θ(*d² ·M·*log log*M*).

•Space-constrained phase: Θ(*dk*) passes (window size*ℓ/*(*dk*)), each Θ(*d·M*), for Θ(*d² ·M·k*).

For the new algorithm, the*d*-dependence per phase is:

•Time-constrained phase: log*α*(*ℓ*) passes with*α*=*δ/*(*δ−*1), so*≈*(*δ−*1) ln*ℓ*= Θ(log*d·*log log*M*). Per-pass cost Θ(*d·M*) due to prefix adaptation, yielding overall Θ(*d·M·*log*d·*log log*M*).

•Space-constrained phase: Θ(*kδ*) = Θ(*k*log*d*) passes (window size*ℓ/*(*kδ*)), each Θ(*d·M*) for prefix adaptation, totaling Θ(*d·M·k*log*d*).

### C.5 Equality Polynomial Optimization: Full Algorithm and Analysis

This appendix provides the complete algorithm and analysis for handling equality polynomials in windowed sum-check, as summarized in Section 6.

C.5.1 Detailed algorithm for windowed equality handling
Q*d* Consider computing sum-check for*g*(*X*) = eqe (*w,X*)*·k*=1*pk*(*X*) using a window of*v*rounds starting at position*i*. The polynomial we need to evaluate is: X
*q*(*X₁,...,Xv*) = eqe (*w,*(*r*[*<i*]*,X₁,...,Xv,x*
*′* )) *x* *′* *∈{*0*,*1*}ℓ−i−v*+1

Y *d* *· pk*(*r*[*<i*]*,X₁,...,Xv,x* *′* )*.* *k*=1

Using the decomposability of eqe, we rewrite this as:

Y *v*
*q*(*X₁,...,Xv*) =*α· ℓj*(*Xj*)*·T*(*X₁,...,Xv*)*,*
*j*=1

where:

•*α*= eqe (*w*[*<i*]*,r*[*<i*]) is a scalar constant

•*ℓj*(*Xj*) = eqe (*wi*+*j−*1*,Xj*) =*wi*+*j−*1*·Xj*+ (1*−wi*+*j−*1)(1*−Xj*) are linear polynomials P *′* Q *′*
•*T*(*X₁,...,Xv*) =*x′* eqe (*w*[*>i*+*v−*1]*,x*)*·kpk*(*r*[*<i*]*,X₁,...,Xv,x*)

C.5.2 Space-efficient computation via k-way decomposition Let*s*=*ℓ−i−v*+ 1 be the suffix length. We partition the suffix bits into
P *k*parts of roughly equal length *k* *s* *j≈s/k*for*j∈*[*k*], with*j*=1*sj*=*s*. This allows us to rewrite*T*as a*k*-fold iterated sum: X *T*(*X₁,...,Xv*) = eqe (*w*range 1 *,x* *′* 1 ) *x* *′* 1 *∈{*0*,*1*}s*1 X eqe (*w*range 2 *,x* *′* 2 ) *x* *′* 2 *∈{*0*,*1*}s*2 ... X eqe (*w*range *k* *,x* *′k* ) *x* *′k* *∈{*0*,*1*}sk*

Y *d* *· pj*(*r*[*<i*]*,X₁,...,Xv,x* *′* 1 *,...,x* *′k* )*,* *j*=1

where range*j*denotes the*j*-th partition of suffix bits. The crucial insight is that we can evaluate this nested sum in a streaming fashion that uses only*O*(2 *s/k* ) space. We iterate through all tuples (*x* *′* 1 *,...,x* *′k* ) in lexicographic order (with*x* *′k* changing most frequently), maintaining only the necessary partial sums.

#### Algorithm: Streaming k-way evaluation.

1.Precompute equality tables:For each of the*k*ranges, compute and store:

||e (w {eq||∈{0,1} ) :x ,x|
|---|---|---|---|
|s|s/k|||
|s/k|s/k|||

range*j* *′j ′j sj* *}*for*j∈*[*k*]

Each table requires 2*j≈*2 space and can be computed using the standard streaming recurrence. Total space: *O*(*k·*2) =*O*(2).

2.Streaming accumulation:Process the nested sum from innermost to outermost. For each partial tuple (*x* *′* 1
*,...,x* *′j−* 1 ), we maintain a running sum over (*x* *′j* *,...,x* *′k* ). By processing in lexicographic order and immediately consuming each partial sum, we never store more than one partial sum per level simultaneously.

C.5.3 Proof of grid sufficiency
Q*v*
Lemma 13(Grid sufficiency).*Letq*(*X₁,...,Xv*) =*α·j*=1*ℓj*(*Xj*)*·T*(*X₁,...,Xv*)*whereα∈*F*, eachℓjis*
*linear, andThas degree at mostdin each variable. Then knowingTon the gridUdvsuffices to compute all* *round polynomialssi,...,si*+*v−*1*for the sum-check protocol.*

*Proof.*In round*i*+*j−*1 for*j∈*[1*,v*], the sum-check polynomial is: X *s* *i*+*j−*1(*Xj*) = *q*(*ri,...,ri*+*j−*2*,Xj,x* *′′* )*.* *x* *′′* *∈{*0*,*1*}v−j* Q*j−*1 This can be expressed as*si*+*j−*1 *j t*=1 *t i*+*t−*1 *j j j j j*is obtained by:

|(X|) =α·|ℓ (r|)·ℓ|(X )·t|(X ), wheret|
|---|---|---|---|---|---|
|i+j−1|j|t=1 t i|i+t−1 j i+j−2|j j|j|

1.Binding the first*j−*1 coordinates of*T*to (*r,...,r*) using Lagrange interpolation
2.Summing the remaining*v−j*coordinates over Boolean values (i.e., summing evaluations at 0 and 1 along each free coordinate)
Both operations preserve the property that*tj*is a degree-*d*univariate polynomial, which can be recovered from its evaluations on*Ud j j*

||. Multiplying by the linear polynomialℓ|(X ) gives the full round polynomial|
|---|---|---|
||d|j j|
|i+j−1 d i+j−2 i+j−1||d|

*s* on*U*; the protocol message is then its restriction to *U*c, with the verifier reconstructing*si*+*j−*(0) from*C −s* (1).

#### Equality-polynomial window handling

||={∞,0,1,...,d−1}, U|||c =U \{0}.|
|---|---|---|---|---|
||d|||d d|
||d k=1 [>i+v−1]|k ′ x|||
|′|ℓ−i−v+1|d k=1|k [<i]|′|
|[>i+v−1]|′ k|k [<i]|′||

Inputs:Window size*v*, degree bound*d*, grid*U* Q Goal:Compute sum-check for*g*(*X*) = eqe (*w,X*)*· p* (*X*) over rounds [*i,i*+*v−*1].

1.Precompute suffix weights:Compute*{*eqe (*w,x*)*} ′* via*k*-way streaming.
2.Compute*T*on*Udv*:For each*x ∈{*0*,*1*}* :
Q

(a)Use multiproduct evaluation (Section 4) to compute *p* (*r,β,x*) for all*β∈Udv*.
Q

(b)Accumulate: *T*(*β*)*←T*(*β*) + eqe (*w,x*)*· p* (*r,β,x*).
3.Extract round polynomials:For round*j∈*[1*,v*]:
(a)Contract bound variables (*X₁,...,X*

||||) to (r|,...,r|) via Lagrange.|
|---|---|---|---|---|---|
||j+1|v|j−1|i|i+j−2|
||j−1|||||
|j j|t=1 t|i+t−1|j j|j j||
|j j|d|||||

(b)Sum free variables (*X,...,X*) over Boolean values (equivalently, evaluate each free coordinate at 0 and 1 and add).
Q

(c)Form*s* (*X*) =*α· ℓ* (*r*)*·ℓ* (*X*)*·t* (*X*).
(d)Restrict*s* to *U*c for the transmitted message; the verifier reconstructs the omitted value*sj*(0) from *Ci*+*j−*2*−s* (1).
Figure 8: Complete algorithm for handling equality polynomials in windowed sum-check.

C.5.4 Detailed cost analysis
Q*d* Lemma 14(Detailed marginal cost).*When computing sum-check forg*(*X*) = eqe (*w,X* Q

)*·k*=1*pk*(*X*)*using*
*windows of sizevwithk-way decomposition, the additional cost beyond computingkpk*(*X*)*is:*

•*Time:*

–*Suffix weight computation:O*(2 *s* )*field operations wheres*=*ℓ−i−v*+ 1 –*k-way table/setup overhead:O*(*k*2 *s/k* )*operations* –*Window linear factors:*(*d*+ 1) *v* *small-by-big multiplications per window*

•*Space:O*(2 *s/k* ) =*O*(*M¹* */k* )*for suffix weight storage*

*The dominant multiproduct evaluation cost remains*Θ((*d*+ 1) *v* )*rather than increasing to*Θ((*d*+ 2) *v* )*.*

*Proof.*The suffix weight computation uses standard equality-evaluation recurrences and costs P *O*(2 *s* ) field operations. With*k*-way decomposition, we store*k*tables of size 2 *s* *j*each, where *jsj*=*s*and*sj≈s/k*. P *s* *j s/k s/k* Thus total space is*j*2 *≈k·*2 =*O*(2). Generating the*k*equality tables contributes at most   *k k*

||X||X|||||
|---|---|---|---|---|---|---|---|
||s j=1|+1|s j=1||s/k|||
||||||v|||

(2 *s* *j* +1 *−*2) =*O* 2 *s* *j*  =*O*(*k*2*s/k*)*,*

which is lower order than the dominant suffix-streaming work. The multiproduct evaluation for each suffix tuple uses the same (*d*+ 1) grid as without equality factors. The only additional per-window multiplications are: (1) scaling accumulated sums by precomputed equality weights (precomputation avoids recomputing weights but does not eliminate these multiplications), and (2) multiplying by linear factors*ℓj*when extracting round polynomials, which requires (*d*+ 1) *v* small-by-big multiplications.

C.5.5 Intra-window prover algorithm The statement in Figure 2 to “RunLinearTimeSCwith*qt*” is a conceptual simplification. In practice, the prover does not materialize the coefficients of*qt*. Instead, it performs an equivalent set of operations directly on the evaluation grid computed byMultiProductEval. This subsection details this process. Representation.The window polynomial*qt*(*X₁,...,Xωt*) is stored as a grid of (*d*+ 1)
*ωt* field elements, representing its evaluations on the grid*U* *dω* *t*, where we define*Ud*:=*{∞,*0*,*1*,...,d−*1*}*. All intra-window operations are performed on this grid, typically stored as a flat array in row-major order.

Sum-check on the Grid.Emulating the sum-check protocol on*qt*for rounds*j*= 1*,...,ωt*involves two main steps per round, mirroring the logic ofLinearTimeSCbut adapted for the evaluation representation.

Round Polynomial Computation.For the current round*j*, the prover must compute the univariate polynomial*sj*(*Xj*) by summing*qt*over the Boolean hypercube of the remaining free variables*Xj*+1*,...,Xωt*. This is implemented as a series of grid reductions. To sum out a variable*Xk*(for*k > j*), the prover collapses the corresponding axis of the grid. This operation proceeds slice-by-slice: for each univariate slice P *f*(*Xk*) along that axis (represented by its*d*+ 1 evaluations on*Ud*), the prover computes the sum*b∈{*0*,*1*}f*(*b*) = *f*(0)+*f*(1). Since the values*f*(0) and*f*(1) are directly available in the evaluation grid for*Ud*, this summation is a simple addition. This process is repeated for each free variable until only the axis corresponding to*Xj* remains, which now holds the evaluations of*sj*(*Xj*) on*Ud*.

Challenge Binding.After the verifier sends the challenge*rj∈*F, the prover binds the variable*Xj*to this value. This corresponds to collapsing the current axis of the grid. For each slice along this axis (which now represents a univariate restriction of the currently bound window polynomial), the prover evaluates it at the point*r* using Lagrange interpolation from the known values on*Ud*. The result is a new, smaller grid for

|j|||
|---|---|---|
|t|j j+1|ω|

the polynomial*q* (*r₁,...,r,X,...,Xt*), whose dimensionality is one less than the previous grid. This
prepares the state for the next round within the window.

C.5.6 Transition to the Final Prover When the windowing schedule dictates a switch to the final, non-windowed prover (conceptually,LinearTimeSC), it is crucial to initialize this prover in the correct state. The new prover must behave as if it had been running from the start, having already processed challenges*r₁,...,rj′−*1, where*j*
*′* is the round of the switch. A naive start would be incorrect. An effective implementation strategy to correctly transfer state is to “fast-forward” a fresh instance of the linear-time prover, via a final streaming pass. The process is as follows:

1.Instantiate:A fresh instance of theLinearTimeSCprover is created, initialized with the original streams over the full*{*0*,*1*}*
*ℓ* hypercube.

2.Populate Caches:The prover’s first step is run, which populates its internal evaluation tables (the
(0)
arrays*P* *k* in Figure 4).

3.Replay History:The prover then iteratively applies every historical challenge, from*r₁* up to*rj′−*1.
*′* (*t*) (*t−*1) For each*t*= 1*,...,j −*1, it uses its update procedure to compute the tables*P* *k* from*P* *k* and the challenge*rt*.

*′* (*j* *′* *−*1)

4.State Transfer:After all*j −*1 challenges have been processed, the resulting evaluation tables*P*
*k* represent the correct state. These tables are transferred to the main prover, which will use them to continue the protocol for rounds*j* *′* *,...,ℓ*.

This fast-forwarding procedure ensures that the final phase of the protocol begins with the correct partial evaluations.

## D Details of the high-degree polynomial product

This appendix provides additional details for the univariate extrapolation routine used insideMultiProductEvalv*,*d, which were too technical for the main body.

### D.1 Univariate extrapolation

We first provide the technical details for the optimized univariate extrapolation procedure,UniExtrap, which is central to the performance of our high-degree polynomial product algorithm. The goal is to compute the evaluations of a degree-*k*polynomial*p*(*x*) at points in*Uh*given its evaluations at*Uk*, for*h > k*. Let*ek*be the vector of evaluations of*p*(*x*) on*Uk*. Each extrapolated value in*eh*can be computed as a linear combination of the values in*ek*.

Vandermonde matrix formulation.We consider first a naive solution. Let the coefficients of this linear combination be computed using Vandermonde matrices in the following manner. Let*Vn*be the Vandermonde matrix of size (*n*+ 1)*×*(*n*+ 1) over*Un*=*{∞,*0*,*1*,...,n−*1*}*:   0 0 0 0*···*1 1 0 0 0*···*0   

|2|3|n|
|---|---|---|
|2|3|n|
|2|3|n|

1 1 1 1 *···*1     2 2 2 *···*2  *Vn*= 1  1 3 3 3 *···*3   
............ 

||.|.||||
|---|---|---|---|---|---|
||2|3|n n||n−1|
|||||h||
|k|h h,k|k−1 k||||
|h,k||||h||
|k−1|||||h,k|
||h|||||
|h,k k−1||||||
||k|||||

....
1*n−*1 (*n−*1) (*n−*1) *···*(*n−*1)

which maps a vector of coefficients of a degree-*n*polynomial to its evaluations at*U*. Its inverse*V* maps the evaluations of a degree-*n*polynomial to its coefficients. The extrapolated evaluations*e* can be computed from*e* using the formula *e* =*V V e,*

where*V* is the (*h*+ 1)*×*(*k*+ 1) matrix formed by taking the first*k*+ 1 columns of*V*. The right matrix *V* maps the evaluations of the degree-*k*polynomial to its coefficients, and the left matrix*V* maps these coefficients to evaluations at points in*U*. Together, these can be preprocessed to a single matrix *M*=*V V* of size (*h*+ 1)*×*(*k*+ 1). The first*k*+ 1 rows of this matrix are the identity matrix, as the first*k*+ 1 values of*eh*are the same as those of*e*.

Coefficient growth and cost of the naive approach.In the subsequent rows of*M*, all of the entries are non-zero and the entries grow in magnitude further down the rows. As an example of how these entries grow, row*k*+ 2 of*V₁₆V₈* *−*1 is [40320*,−*1*,*8*,−*28*,*56*,−*70*,*56*,−*28*,*8]

while row 2*k*is [259459200*,−*3432*,*25740*,−*83160*,*150150*,−*163800*,...*]

Naively, this extrapolation requires (*k*+ 1)sbmultiplications and*k*additions per extrapolated value. For the recursive structure ofMultiProductEval, this would imply*O*(*d²* log*d*)sboperations in total to compute the product of*d*linear polynomials, which is concretely worse than the naive approach unlesssboperations were cheaper thanbbby a factor of at least log*d*.

Reusing computations via shifted evaluations.However, we observe that it is possible to do signif- icantly better by reusing work across the*k*extrapolated values, after which it is even possible to optimize

away many of thesbmultiplications in favor of additions. Consider the more manageable example of*V₈V₄* *−*1.  

| 1|0 0|0 0 |
|---|---|---|
|  0|1 0|0 0  |
|  0|0 1|0 0  |
|  0|0 0|1 0  .|
|=   0|0 0|0 1  |
| 24−1 |4−6|4  |
|120−4 |15−20|10 |
|360−10|36−45|20|
|840−20|70−84|35|

*−*1 *M*:=*V₈V₄*

Ignoring the contribution of the evaluation at*∞*, the linear combination in the first row can be computed using just 6 additions. If every row had values this small, they would be similarly easy to compute, and it would be possible to potentially share work across the rows. However, the later rows require significantly more work. Put differently, computing*p*(*k*) from evaluations of*p*(*x*) for all*x∈Uk*is easy while computing*p*(*k*+*c*) from evaluations of*p*(*x*) at these points is more expensive, and rapidly gets more expensive, to a point, as *c*increases. Our key insight is that computing*p*(*k*+*c*) can be expressed as the problem of computing*qc*(*k*) where*qc*(*k*) :=*p*(*k*+*c*). This means that it is possible to compute*p*(*k*+*c*) from evaluations of*p*(*x*) at the points (*∞,c,c*+ 1*,...,c*+*k−*1) efficiently. Additionally, if we have already extended*p*from*Uk*to*Uc*+*k*, then we have the evaluations required to compute*qc*(*k*). This is best illustrated with the example of*k*= 4. To extrapolate from*U₄* to*U₈*, we can compute the new evaluations one by one. In the lower-triangular matrix below, the*j*th entry of*e₈* can be computed by multiplying the*j*th row of this matrix by the partially filled vector of evaluations,*e₈*.   1 0 0 0 0 0 0 0 0  0 1 0 0 0 0 0 0 0    0 0 1 0 0 0 0 0 0    0 0 0 1 0 0 0 0 0    0 0 0 0 1 0 0 0 0*.*   24*−*1 4*−*6 4 0 0 0 0

|24−1 |4−6|4|0 0|0 0 |
|---|---|---|---|---|
|24 |0−1|4−6|4 0|0 0 |
|24|0 0−1|4−6|4|0 0|
|24|0 0|0−1|4−6|4 0|

From this structure, it is immediately clear that it is possible to reuse work across rows and that the number of additions required to compute each row is small. The low-level optimizations here require finding minimal multi-addition chains for the small integer coefficients. We provide explicit, optimized procedures for this computation in our implementation.

### D.2 Multivariate extrapolation

We first recall the content of the multivariate extrapolation algorithm from the main body (Procedure 2). Given evaluations on the Boolean grid*Ukv*of a*v*-variate polynomial*p*with per-variable degree at most*k*, the task is to extend these evaluations to the larger grid*Uh* *v* for some*h > k*. The algorithm uses the standard “passes” view that reduces multivariate extrapolation to a sequence of univariate extrapolations applied to axis-aligned slices. In pass*j∈*[*v*], we extrapolate along the*j*-th coordinate for all (*v−*1)-dimensional slices defined by the remaining coordinates. At the start of pass*j*, the grid is*U* *hj−* 1 *×U* *kv−j* +1. Extrapolating along the*j*-th coordinate requires *Nj*= (*h*+1) *j−*1 (*k*+1) *v−j*

independent univariate calls. After completing pass*j*the grid becomes*U* *hj* *×U* *kv−j*. Summing over all passes,

the total number of univariate extrapolations is

X*v*<u>(h+1)</u>*v*<u>−(k+1)</u>*v* *N*tot(*k,v,h*) = (*h*+1) *j−*1 (*k*+1) *v−j* =*.*(10) *j*=1 *h−k*

Let*C*uni(*k,h*) denote the online cost of one univariate extrapolation from degree*k*to*h*using the shifted- evaluation recurrence described above, countingsboperations and field additions. In the doubling regime used in the product recursion (*h∈{*2*k,*2*k*+ 1*}*), the recurrence has*k*terms applied to each of*h−k*= Θ(*k*) new values, giving *C*uni(*k,h*) = Θ(*k²*)*.*(11)

Therefore, the online cost of multivariate extrapolation is

#### Cextrap(k,v,h) =Ntot(k,v,h)·Cuni(k,h),(12)

entirely insboperations and field additions, with zerobbmultiplications. For the doubling regime that arises inside our product recursion (set*k*=*⌊d/*2*⌋*,*h*=*d*), we have *N*tot(*k,v,h*) = Θ*v*(*k* *v−*1 ) (with a constant depending on*v*), and*C*uni(*k,h*) = Θ(*k²*). Hence one multivariate extrapolation costs Θ*v*(*k* *v*+1 ), and the pair of extrapolations at a product node costs Θ*v*(*d* *v*+1 ) insb/a.

### D.3 Multivariate product costs

Q*d* We now analyze the cost ofMultiProductEval*v,d*which computes, in evaluation form, the product*g*=*i*=1*pi* of*d*multilinear polynomials given by their values on*U₁* *v* =*{*0*,*1*}* *v*. Each internal node of the divide-and- conquer recursion multiplies two degree-*⌊d/*2*⌋*and degree-*⌈d/*2*⌉*partial products after extrapolating them to the common grid*Udv*.

Big-by-big multiplications.Counting only pointwise products on*U·v*, the cost obeys the recurrence

*Av*(1) = 0*, Av*(*d*) =*Av*(*⌊d/*2*⌋*) +*Av*(*⌈d/*2*⌉*) + (*d*+1) *v* *.*

Unrolling by recursion depth yields the bounds

*⌈*log X 2*d⌉−*1 *⌈*logX2*d⌉−*1 2 *t* (*⌊d/*2 *t* *⌋*+1) *v* *≤Av*(*d*)*≤* 2 *t* (*⌈d/*2 *t* *⌉*+1) *v* *.* *t*=0 *t*=0

Hence*Av*(*d*) = Θ(*d* *v* ) for all fixed*v≥*2. When*d*= 2 *m* the exact expression is

*m* X*−*1 *Av*(2 *m*

) = 2 *t*
(2 *m−t* +1) *v* (13) *t*=0 *m* X*−*1 = 2 *mv* 2 *t*(1*−v*) *·* 1 +*O*(2 *−*(*m−t*)

)*,*(14)
*t*=0

which converges to a constant factor*cv*:= 1*/*(1*−*2 1*−v* ) as*m→ ∞*. For*v*= 1 one recovers the exact univariate form*A₁*(*d*) =*d⌈*log₂ *d⌉*+ 2*d−*2 *⌈*log2*d⌉* *−*1.

Small-by-big multiplications and additions.Let*Sv*(*d*) denote the total cost insboperations and additions. At a node with degree*d*, we perform two extrapolations to*Udv*from*k*=*⌊d/*2*⌋*and*k* *′* =*⌈d/*2*⌉*. Using (12), each extrapolation costs Θ*v*(*d* *v*+1 ) in the doubling regime, so the per-node lower-order work is Θ*v*(*d* *v*+1 ). The resulting recurrence

|||S (1) = 0,|S (d) =S|(⌊d/2⌋)|+S (⌈d/2⌉)|
|---|---|---|---|---|---|
||v|v v+1|v|v|v|
|||||v,d||

*v v v v*+ Θ(*d* *v*+1 )

solves to*S* (*d*) = Θ(*d*) for all fixed*v≥*1. All these costs are insband additions; no newbbare introduced by extrapolation. We thus summarize the cost ofMultiProductEval as follows. This gives more details than the same statements in the main body.

Lemma 15(Product cost summary).*For fixedv≥*2*and alld≥*1*, the algorithm*MultiProductEval*v,duses* *Av*(*d*) = Θ(*d* *v* )*big-by-big multiplications andSv*(*d*) = Θ(*d* *v*+1 )*small-by-big operations plus additions. For* *v*= 1*, the big-by-big count isA₁*(*d*) =*d⌈*log₂ *d⌉*+2*d−*2 *⌈*log2*d⌉* *−*1*and the lower-order work isS₁*(*d*) = Θ(*d²*)*.*

These results follow from the fact that at each level of the recursion, the per-node extrapolation cost is Θ(*d* *v*+1 ) (because each univariate extrapolation from degree*k*to 2*k*costs Θ(*k²*) operations), and the level-sum decays geometrically (ratio 1*/*2 *v* ), so the root level dominates.

## E Integration with Jolt

This appendix explains how the techniques in this paper instantiate inside the current Jolt prover [2]. We focus on the two integration points used in our evaluation: (i) Spartan outer sum-check, and (ii) instruction RA (read-access) virtualization in Shout.

### E.1 Spartan outer sum-check

In the standard Spartan formulation [49], one proves the R1CS relation

(*A·Z*)*◦*(*B·Z*) =*C·Z,*

where*A,B,C∈*F *n×m* are public matrices,*x∈*F *k* is the public input,*v∈*F *m−k−*1 is the private witness, and*Z*= (1*,x,v*). The first Spartan sum-check is applied to

*G*(*X*) := eqe (*w,X*)*· A*(*X*)*· B*(*X*)*− C*(*X*)*,*

and proves X *G*(*x*) = 0*.* *x∈{*0*,*1*}ℓ*

Here*w∈*F *ℓ* is a random verifier challenge vector, and *A, B, C*are multilinear extensions of*A·Z*,*B·Z*, and *C·Z*, respectively. In Jolt,*Z*encodes the execution trace, while*A,B,C*encode the VM constraints (together with lookup and read-write checking subprotocols). Operationally, the prover computes*A·Z*,*B·Z*, and*C·Z*from the trace; many coordinates are zero/one and, more generally, small signed integers. This is exactly the structure we exploit. Round-by-round, the prover message has the standard form

*s* *i*

(*X*) =eq(*w*[*≤i*]*,*(*r*[*<i*]*,X*))*·ti*(*X*)*,*
X *t*

||eq(w|,x ) A(r|,X,x|)B(r|,X,x|
|---|---|---|---|---|---|
|x ∈{0,1}|[>i]||[<i]||[<i]|

*i*

(*X*) =[*>i*]
*′* [*<i*] *′* [*<i*] *′* )*− C*(*r*[*<i*]*,X,x* *′* )*.* *′ ℓ−i*

This is the standard outer sum-check equation used by the baseline ablation.

Univariate-skip variant in Jolt.In the current Jolt outer instance, the uniform constraint table has 19 constraints. Applying univariate skip, we partition these constraints as*C*=*C*small*⊔C*rem, with*|C*small*|*= 10 and*|C*rem*|*= 9. The first set is proved via one univariate-skip round over a size-10 domain, followed by ordinary low-degree remainder rounds for the residual variables. Write*d*=*|C*small*|−*1 = 9, and let*z*be the univariate first-round variable. The first-round message is built from X *q*(*z*) =*ω*pack(*z*)*· ω*(*x* *′*

||) A|) B|(z,x|),||
|---|---|---|---|---|---|
||small|small|small|||
|pack|||||′|

small(*z,x* *′* small(*z,x* *′* )*− C*small *′*

*x* *′*

where*ω* (*z*) is the packed equality factor on the skipped constraint coordinate and*ω*(*x*) is the folded equality weight on the remaining variables; under this parameterization, deg*q≤ d*= 27. After the verifier samples the first-round challenge, the protocol continues with standard low-degree rounds (including the *|C*rem*|*= 9 constraint remainder).

Why this split helps.The split is not arbitrary: we place in*C*smallthe constraints whose arithmetic profile is most “small-value friendly” (many Boolean/near-Boolean factors and low absolute value (*∼*64-bit integers) in the linear forms). This maximizes the work that benefits from our small-value multiplication and delayed reduction optimizations. Constraints with wider intermediate magnitudes are left in*C*rem, where they are handled in the regular remainder rounds.

Why this matters for the benchmarks.This stage is exactly what is measured in Figure 3 and tables 8 to 10. The linear-space variants materialize large bound buffers in the remainder, while streaming variants trade runtime for lower peak memory.

### E.2 Instruction RA virtualization in Shout

For proving correctness of instruction execution, Jolt uses the Shout lookup argument to perform one lookup per cycle into a structured table of size 2 128. In this lookup argument, the prover needs a read-address selectorera(*k,j*): for each cycle*j*, it indicates which lookup-table row*k*was accessed. Since the instruction lookup address space is very large (*K*= 2 128 in our setting), committing to a monolithicera is expensive. The protocol therefore virtualizes this selector and commits only to smaller one-hot components. Concretely, the prover splits the address into*N*blocks,*k*= (*k*

(0) *,...,k* (*N−*1)
), and writes

*N* Y *−*1 era(*k,j*) = era

(*i*) (*k*
(*i*) *,j*)*.*
*i*=0

The instruction read-checking and RAF-evaluation identities (see [51]) consumeera

(*i*) as*virtual*polynomials
and output claims *αi*=era

(*i*) (*r*
(*i*) *,r*cyc) for*i*= 0*,...,N−*1*.*
The RA virtualization sum-check is the bridge that proves these claims from committed data. Each virtual factorera

(*i*) is itself represented as a product of*d*committed one-hot chunk polynomials,
era*i,*1*,...,*era*i,d*, so the identity proved is

X Y*d* *αi*= eqe (*r*cyc*,j*)*·* era*i,t*(*ri,t,j*)*.* *j∈{*0*,*1*}*log*Tt*=1

To prove all*N*claims in one shot, Jolt batches them with a random challenge*γ*:

|N −1||N −1 d||
|---|---|---|---|
|i|i|i|i,t i,t|
|i=0|j∈{0,1}|i=0 t=1||

X X X Y *γ α* = eqe (*r*cyc*,j*)*· γ* era (*r,j*)*.* log*T*

At a high level, this certifies that the virtual address selectors used by the instruction-lookup argument are exactly the tensor/product composition of the committed one-hot chunks.

Tunable parameters.Let*κ*= log₂ *K*be the address bit-width and let*b*be the bit-width per committed chunk. Then <u>κ/N</u> *d*=*,*degsumcheck=*d*+ 1*.* *b* Thus*N*and*d*are coupled tuning knobs: increasing*N*by a factor of 2 decreases*d*(and the degree) by a factor of 2, and vice versa, while the total number of committed chunk polynomials*N·d*=*κ/b*stays fixed. In our benchmarks (*κ*= 128*,b*= 4), this gives

*N*= 8 : *d*= 4*,*deg = 5*, N*= 4 : *d*= 8*,*deg = 9*,* *N*= 2 : *d*= 16*,*deg = 17*, N*= 1 : *d*= 32*,*deg = 33*.*

Optimized vs naive kernels.The RA prover can evaluate this product either with a naive*O*(*d²*) inter- polation/extrapolation path or with the optimized high-degree product kernel used in our implementation from Section 4. This is exactly the comparison reported in Table 12.

On the scope of our optimizations.Jolt contains additional sum-check instances beyond these two integration points. This appendix intentionally documents only the two instances used in the paper’s main benchmark claims, and matches the current Jolt implementation.

## F Why large fields?

In this section, we discuss why the sum-check protocol needs to operate over large fields (with cardinality at least 2 128 ) for non-interactive security (after applying the Fiat-Shamir transformation). More precisely, this means that the sum-check challenges*r₁,...,rℓ*from the verifier need to be chosen over this large field, even if the initial polynomial evaluations may be small. This applies especially to the extension field setting, where one might be tempted to work fully over the small base field. Indeed, the core of the problem is that in the non-interactive setting, one*cannot*apply either sequential or parallel repetition to boost soundness. Although such techniques can boost soundness in the*interactive* setting, for sum-check-based SNARKs they fail to do so when combined with the Fiat-Shamir transforma- tion [28] to render the protocol non-interactive (at least, not without major performance overheads). The case of sequential repetition is widely known. In particular, given a protocol with one or more rounds and 1*/*poly(*λ*) soundness, repeating the protocol for any*k*=poly(*λ*) times and applying Fiat-Shamir results in a*completely insecure*non-interactive argument. This is because an adversary against the Fiat-Shamired version can simply guess the “bad” challenge for the first repetition via varying the first message, then do the same for the second repetition via varying the first message of the second repetition, and so on. This is referred to as a “grinding attack” on the Fiat-Shamired protocol. Grinding attacks are also effective when the Fiat-Shamir transformation is applied to the parallel (rather than sequential) repetition of a multi-round protocol, unless the number of repetitions is very big. Specifically, when applying parallel repetition followed by Fiat-Shamir to an*ℓ*-round interactive protocol,*ℓ·k*repetitions are necessary to amplify*λ/k*bits of security to*λ*bits of security (i.e., there is an attack demonstrating that this security bound is tight [6]. 14 ). In the context of the sum-check protocol, this results in*O*(*nk*log*n*) base field operations for the prover, which is typically worse than the linear-time algorithm (Procedure 4) that achieves*O*(*nk²*) base field opera- tions. Indeed, in practice, we have*k≤*4 (i.e. 64-bit inside BN254, or 32-bit subfield inside 128-bit extension fields) while log*n≥*20.

## G Cycle counts for Montgomery multiplication

An informal but concrete anchor for the claim that a 256-bit field multiplication costs on the order of 50– 100 cycles on modern x86 64 comes from a public benchmark: a hand-tuned (non-constant-time) secp256k1 implementation reports a 256-bit Montgomery multiplication in 49 cycles/op on an Intel i7-6700 (Skylake) and 93 cycles/op on an Intel i3-2328M (Sandy Bridge) [66]. At 4 GHz, 50–100 cycles corresponds to roughly

12*.*5–25 ns. The architectural reason these numbers are plausible is that modern x86 cores provide instructions intended for multi-precision arithmetic. In particular,MULX(BMI2) performs a 64*×*64*→*128 multiply without touching flags, and the ADX extension providesADCXandADOX, which maintain independent carry chains. This permits overlap of partial products and reductions in 4*×*64-bit (256-bit) Montgomery kernels, shortening dependency chains compared to classicMUL/ADC-based code [35, 15, 19, 29]. As an additional data point, a 384-bit Montgomery multiplication implemented in x86 64 assembly and using these instructions is reported at about 29*.*576 ns on an Intel i7-7700K, i.e., about 124–133 cycles at 4*.*2–4*.*5 GHz, which is consistent with a well-optimized 256-bit kernel being cheaper [46].
See[https://a16zcrypto.com/posts/article/17-misconceptions-about-snarks/#section-13for](https://a16zcrypto.com/posts/article/17-misconceptions-about-snarks/#section-13for) an exposition of this attack.
