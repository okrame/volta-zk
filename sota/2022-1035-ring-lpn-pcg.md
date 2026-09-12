∗

# Efficient Pseudorandom Correlation Generators from Ring-LPN

† ‡ § ¶ ‖ Elette Boyle Geoffroy Couteau Niv Gilboa Yuval Ishai Lisa Kohl ∗∗ Peter Scholl

### August 10, 2022

Abstract

Secure multiparty computation can often utilize a trusted source of correlated random- ness to achieve better efficiency. A recent line of work, initiated by Boyle et al. (CCS 2018, Crypto 2019), showed how useful forms of correlated randomness can be generated using a cheap, one-time interaction, followed by only “silent” local computation. This is achieved via a *pseudorandom correlation generator* (PCG), a deterministic function that stretches short correlated seeds into long instances of a target correlation. Previous works constructed con- cretely efficient PCGs for simple but useful correlations, including random oblivious transfer and vector-OLE, together with efficient protocols to distribute the PCG seed generation. Most of these constructions were based on variants of the Learning Parity with Noise (LPN) assumption. PCGs for other useful correlations had poor asymptotic and concrete efficiency. In this work, we design a new class of efficient PCGs based on different flavors of the *ring-LPN* assumption. Our new PCGs can generate OLE correlations, authenticated multi- plication triples, matrix product correlations, and other types of useful correlations over large fields. These PCGs are more efficient by orders of magnitude than the previous constructions and can be used to improve the preprocessing phase of many existing MPC protocols.

∗ Full version of a paper published at CRYPTO 2020, [https://doi.org/10.1007/978-3-030-56880-1_14](https://doi.org/10.1007/978-3-030-56880-1_14). For a list of changes, see Section 1.2. † IDC Herzliya and NTT Research, eboyle@alum.mit.edu ‡ IRIF, couteau@irif.fr § Ben-Gurion University, niv.gilboa@gmail.com ¶ Technion, yuvali@cs.technion.ac.il ‖ Cryptology Group, CWI Amsterdam, lisa.kohl@cwi.nl ∗∗ Aarhus University, peter.scholl@cs.au.dk

## Contents

Introduction

1.1 Our contributions................................... .5
1.2 Changes Since Publication at CRYPTO 2020................... .7
1.3 Technical Overview.................................. .7
2 Preliminaries 11

2.1 Notation........................................ .11
2.2 Function Secret Sharing............................... .11
2.3 Pseudorandom Correlation Generators....................... .12
3 The Ring-LPN Assumption 13

3.1 Ring-LPN....................................... .14
3.2 Choice of the Polynomial *F*............................. .16
4 PCGs for OLE and Authenticated Multiplication Triples 17

4.1 PCG for OLE over *Rp*................................ .17
4.2 Authenticated Multiplication Triples........................ .21
5 DPF Key Generation Protocols 24

5.1 Reactive 2-PC..................................... .24
5.2 Semi-honest DPF Key Generation......................... .24
5.3 Malicious DPF Key Generation........................... .27
6 PCG Setup Protocols 38

6.1 Semi-Honest Distributed Setup for OLE...................... .39
6.2 PCG Setup Protocols with Malicious Security................... .39
6.3 Efficiency Analysis.................................. .46
7 Extensions and Applications 49

7.1 Bilinear Correlations................................. .50
7.2 Inner Product Correlations............................. .50
7.3 Bilinear Correlations from Programmable PCG for OLE............. .51
7.4 Application: Matrix Multiplication Triples..................... .56
7.5 Application: Circuit-Dependent MPC Preprocessing............... .57
7.6 Application: Multi-Party PCGs for Bilinear Correlations............. .57
8 Security Analysis 58

8.1 Generic Attacks on LPN............................... .58
8.2 Taking Advantage of Reducible *F*.......................... .61
8.3 Algebraic Attacks on Fully-Reducible *F*...................... .63
8.4 Attacks Using the Quasi-Cyclic Structure of the Code.............. .63
8.5 Attacks over Small Fields.............................. .63
8.6 Attacks on *R*-LPN with Static Leakage....................... .64
9 Efficiency Analysis 65

9.1 Comparing Reducible and Irreducible Ring-LPN................. .65
9.2 Estimated Costs and Runtimes for OLE and Triple Generation......... .67
9.3 Comparison with OLE From Ring-LWE...................... .68

10 PCG for OLE from Standard LPN

10.1 The Construction of [BCG
+ 19b].......................... .70

10.2 Optimized Construction............................... .70
10.3 LPN-Based PCG for Matrix Multiplication.................... .71
### 11 Acknowledgements 73

## Introduction

Correlated secret randomness is a commonly used resource for secure multi-party computation (MPC) protocols. Indeed, simple kinds of correlations enable lightweight MPC protocols even when there is no honest majority. For instance, an *oblivious transfer* (OT) correlation supports MPC for Boolean circuits [GMW87,Kil88,IPS08,NNOB12], while oblivious linear-function eval- uation¹ (OLE), an arithmetic variant of OT, supports MPC for arithmetic circuits [NP99,IPS09]. Other useful types of correlations include multiplication triples [Bea91] and truth-table correla- tions [IKM + 13,DNNR17,Cou19]. Finally, *authenticated* multiplication triples serve as a powerful resource for achieving security against malicious parties [BDOZ11,DPSZ12]. A common paradigm in modern MPC protocols is to utilize the above kinds of correlations in the following way. In a preprocessing phase, before the inputs are known, the parties use an *offline protocol* to generate many instances of the correlation. These instances are then consumed by an *online protocol* to securely compute a function of the secret inputs. This approach is appealing because of the high efficiency of the online protocol. Indeed, with the above simple correlations, the online communication and computation costs are comparable to the size of the circuit being evaluated. The price one pays for the fast online protocol is a much slower and higher-bandwidth offline protocol. Even simple types of correlated randomness are expensive to generate in a secure way. This high cost becomes even higher when aiming for security against malicious parties. Recently, a promising approach for instantiating the preprocessing phase of MPC protocols was suggested in [BCGI18,BCG + 19b], relying on a new primitive called a *pseudorandom corre-* *lation generator* (PCG). Consider a target two-party correlation *C*, typically consisting of many independent instances of a simple correlation as above. A PCG for *C* consists of two algorithms: Gen(1 ), which given a security parameter generates a pair of short, correlated seeds (k₀*;*k₁), and Expand(k), which deterministically stretches a seed k to a long output *R*. The intuitive security requirement is that the joint outputs (*R₀;R₁*) of the above process cannot be distin- guished from *C* not only by an outsider, but also by an insider who learns one of the two seeds. PCGs naturally lead to protocols with an appealing *silent preprocessing* feature, by breaking the offline phase into two parts:

1. Setup. The parties run a secure protocol to distribute the seed generation of Gen. Since Gen has low computational cost and short outputs, this protocol only involves a small amount of communication, much smaller than the output of *C*. Each party stores its own short seed k for later use.
2. Silent expansion. Shortly before the online phase, the parties use Expand to generate long pseudorandom correlated strings (*R₀;R₁*) to be consumed by the online protocol. This part is referred to as *silent*, since it involves no communication. Beyond the potential improvement in the total offline communication and computation, this
blueprint has two additional advantages. First, it can substantially reduce the *storage* cost of correlated randomness by enabling efficient compression. Indeed, the parties can afford to generate and store many correlated seeds, possibly with different sets of parties, and expand them just before they are needed. Second, the cost of protecting the offline protocol against malicious parties is “amortized away,” since it is only the small setup part that needs to be protected. A malicious execution of Expand is harmless. The work of Boyle et al. [BCG + 19b] constructed efficient PCGs for several kinds of useful correlations based on different assumptions that include variants of Learning Parity with Noise (LPN) [BFKL94] and Learning With Errors (LWE) [Reg05]. While the LPN-based PCG for OT

An OLE correlation over a finite field F is a two-party correlation (*r₀;r₁*) where *r₀* = (*a;b*) is uniform over F² and *r₁* = (*x;ax* + *b*) for *x 2R* F.

from [BCG + 19b] has very good concrete efficiency, making it a practically appealing approach for generating many OTs [BCG + 19a], this is not the case for other useful correlations such as OLE or authenticated multiplication triples. For these correlations, two different constructions were proposed in [BCG + 19a]. Both are “practically feasible” but quite inefficient. In the first construction, based on homomorphic secret sharing from ring-LWE [BGI16a,BGI17,BCG + 17, BKS19], the seed expansion can be at most quadratic due to the use of a pseudorandom generator with algebraic degree 2. In concrete terms, the seeds are several GBs long and can only be expanded by around 6x, giving far too much overhead for most applications. Their second construction is based directly on LPN, and has computational cost of at least (*N²*) for output length *N*, which is impractical for large *N*.

### 1.1 Our contributions

In this work, we present efficient new PCG constructions for several widely used correlations for which previous techniques had poor concrete efficiency.

Silent OLE and multiplication triple generation. Our main construction gives the first concretely efficient PCG for OLE over big finite fields F. This PCG is based on a variant of the *ring-LPN* assumption over F, makes a black-box use of F, and has poly() log*N* seed size and poly() *O*~(*N*) computational cost for expanding the seeds into *N* instances of OLE. This PCG gives both an asymptotic and concrete improvement over the LPN-based construction from [BCG + 19b]. We also show how to modify our PCG for OLE to produce multiplication triples and authen- ticated triples, used in maliciously secure MPC protocols like SPDZ [DPSZ12]. This incurs an extra overhead of only around a factor of two in seed size, seed generation, and silent expansion time. Finally, we extend the main construction to other types of useful correlations, including matrix products and circuit-dependent correlations. Technically, one of our main innovations here is showing how to avoid the (*N²*) blowup from the previous LPN-based PCG for OLE from [BCG + 19b]. Our method of doing this requires switching from unstructured LPN to ring-LPN over a certain kind of polynomial rings. This is analogous to early fully homomorphic encryption schemes, where switching from a construction based on LWE [BV11a] to one based on ring-LWE [BV11b] reduced the ciphertext expansion in multiplication from quadratic to linear. A key difference between LWE-based constructions and LPN-based constructions over a big field F is the noise distribution: Gaussian in the former and low Hamming weight noise in the latter. With LPN-style noise distribution more care is needed, and some natural PCG candidates based on Reed-Solomon codes can indeed be broken.

Concrete efficiency. Our PCGs have attractive concrete efficiency features. To give a couple of data points, in the case of OLE the parties can store a pair of seeds of size 1.25MB each, and expand them on demand to produce over a million OLEs (of size 32MB, 26x larger than the seeds) in Z*q*, where *q* is the product of two 62-bit primes, 2 with 128-bit security. When running on a single core of a modern laptop, we estimate this takes under 10 seconds, resulting in a throughput of over 100 thousand OLEs per second. To produce authenticated triples instead of OLE, the expansion cost roughly doubles, giving 50 thousand triples per second, while the seed size increases to 2.6MB. For comparison, estimates from [BCG + 19b] for their PCG for producing authenticated triples gave a throughput of up to 7 thousand per second, but this was only possible when generating an enormous batch of 17GB worth of triples, with 3GB seeds. See below for comparison with non-silent correlation generation techniques. 2 Our construction works in any sufficiently large finite field, or modulus that is a product of primes via the CRT. We estimated costs with a product of two primes due to better software support.

Efficient setup protocols. Recall that to avoid a trusted setup, one typically needs a setup protocol to securely distribute the PCG seed generation. We present concretely efficient setup protocols for OLE and authenticated triples, with both semi-honest and malicious security. The protocols make black-box use of lightweight cryptographic primitives, as well as of generic MPC protocols for performing binary and arithmetic computations on secret-shared values. In practice, our PCGs and setup protocols can be used in a *bootstrapping mode*, where a portion of the PCG outputs are reserved to be used as correlated randomness for the setup procedure of the next PCG seeds. This means that the vast majority of the setup cost is amortized away over multiple instances. Concretely, we estimate that when bootstrapped in this way, the setup phase for a PCG of one million authenticated triples requires only around 4.2MB of communication per party, to produce 32MB worth of triples. The initial setup protocol for the first PCG (before bootstrapping can take place) requires around 25000 authenticated triples, plus some additional correlated randomness (OT and VOLE). This should be feasible to produce in under a minute (although with high communication cost) using standard protocols such as MASCOT [KOS16] or Overdrive [KPR18], and previous PCG protocols for OT and VOLE with + malicious security [BCG 19a]. Compared with non-silent secure correlation generation protocols, we expect the overall *computational* cost of our approach to be comparable with state-of-the-art protocols based on homomorphic encryption [KPR18,JVC18,HIMV19], but with much lower *communication* costs. For instance, in the case of authenticated multiplication triples, the Overdrive protocol [KPR18] can produce around 30 thousand triples per second with malicious security. This is similar to our PCG expansion phase (modulo different hardware, environment, and so on), with the significant difference that Overdrive requires almost 2GB of communication to produce the triples. In comparison, our amortized 4.2MB communication complexity is over two orders of magnitude smaller, with the additional benefit that our short correlated seeds can be easily stored for on-demand silent expansion.

Extension to other correlations and multiple parties. Beyond multiplication triples, it can be useful to have more general “degree-two” correlations, such as inner-product triples, matrix-multiplication triples, or circuit-dependent multiplication triples [Cou19,BNO19,BGI19]. We use our PCG for OLE to obtain PCGs for these kinds of correlations, by exploiting a special “programmability” feature that enables reusing the same PCG output in multiple in- + stances [BCG 19b]. This gives us a way to produce many independent instances of any degree- two correlation (a vast generalization of OLE and multiplication triples), with seed size that grows sublinearly with the total number of instances. Useful special cases include the types of correlations mentioned above. This construction has a bigger overhead than our PCG for OLE, and in practice seems mainly suited for small correlations such as low-dimensional matrix products. However, these can still be useful in larger computations which involve a lot of linear algebra or other repeated sub-computations. We can also use same programmability feature of our 2-party PCGs to extend them to the *multi-party setting*. This yields practical multi-party PCGs for multiplication triples that enable an online passively-secure MPC protocol for arithmetic circuits whose cost scales linearly (rather than quadratically) with the number of parties. This transformation to the multi-party + case, which originates from [BCG 19b], does not scale well to correlations with degree higher than 2. As a result, we do not get a multi-party PCG for authenticated triples (a degree-three correlation) with the same level of efficiency.

Security of ring-LPN. Our constructions rely on variants of the ring-LPN assumption over + non-binary fields. Binary ring-LPN [HKL 12] is a fairly standard assumption that withstood a significant amount of cryptanalysis. However, since we also use relatively unexplored variants over different rings, we give a thorough survey of known attacks, and analyze the best strategies

that apply to our setting. We find that there are only one or two additional attack possibilities from the additional structure we introduce, and these are easily countered with a small increase in the number of errors. More precisely, settling for a PCG that generates a single OLE instance over a large ring of degree-*N* polynomials, our construction can be based on a conservative variant of ring-LPN where the modulus is irreducible. A big ring-OLE correlation can then be converted into *N* independent instances of standard OLE by communicating *O*(*N*) field elements. For generating *silent* OLE over F*p*, we instead rely on a variant of ring-LPN where the modulus splits completely into *N* linear factors. In practice, this requires using larger parameters and increases the cost of our protocols by around a factor of two, compared with irreducible ring-LPN.

### 1.2 Changes Since Publication at CRYPTO 2020

This article has undergone a major revision since its original publication. As well as various minor improvements and clarifications, there are the following major changes.

- The maliciously secure DPF setup protocol in Section 5.3 has changed, since the original security proof was flawed, as pointed out by Damiano Abram. The protocol now uses a different consistency check to fix the issue.
- The DPF setup protocol has also been generalized to work over any (sufficiently large) finite field, it no longer uses the random oracle model, and the *F*c-SUVfunctionality it realizes no longer allows the adversary to guess.
- The cost analysis has been updated to reflect the new protocol. The resulting efficiency estimates have not changed significantly.
- Some of the security analysis of the ring-LPN assumption has been revised due to minor bugs. We point out that much of this analysis is based on cost estimates for attacks that were recently shown in [LWYY22] to be overly conservative. We did not adjust our parameters to reflect [LWYY22], however, according to their cost models (combined with our optimizations for exploiting the structure of cyclotomic ring-LPN), our parameter sets for 80-bit security have between 92–112 bits of security, while our 128-bit parameter sets have 133–171 bits of security. It therefore seems that our parameters have a comfortable security margin.
### 1.3 Technical Overview

Construction from [BCG + 19b]. Before describing our PCG for OLE, it is instructive to recall the PCG for general degree-two correlations by Boyle et al. [BCG + 19b], based on LPN. The goal is to build a PCG for the correlation which gives each party a random vector *~xi*, together with an additive secret share of the tensor product *~x₀ ~x₁*. They used the dual form of LPN over a ring Z, which states that the distribution

|p|||
|---|---|---|
||m n p|n p|

n o $ $ *H;H ~e H* Z*;~e* Z s.t. wt(*~e*) = *t*

is computationally indistinguishable from uniform, where *~e* is a sparse random vector with only *t* non-zero coordinates, for some *t n*, and *m < n*. The idea of the construction is that the setup algorithm gives each party a random sparse *~e₀* or *~e₁*, and computes the tensor product *~e₀ ~e₁*, which has at most *t²* non-zero coordinates. This product is then distributed to the parties via function secret sharing (FSS), by generating a pair of FSS keys for the function that outputs each entry of the product on its respective inputs from 1 to *n²*. This function can be written as a sum of *t²* point functions, allowing practical FSS schemes based on distributed point functions [GI14,BGI15,BGI16b]. Note that unlike the

case of PCGs for OT or Vector-OLE [BCG + 19a,SGRR19], here we cannot replace FSS by the simpler punctured PRF primitive. Given shares of *~e₀ ~e₁* and either *~e₀* or *~e₁*, the parties expand these using LPN, computing:

*~x₀* = *H ~e₀; ~x₁* = *H ~e₁; ~z* = (*H ~e₀*) (*H ~e₁*) = (*H H*) (*~e₀ ~e₁*)

where *~xi*is computed by party *Pi*, while *~z* is computed in secret-shared form, using the shares of *~e₀ ~e₁* and the formula on the right-hand side. Notice that both *~x₀* and *~x₁* are pseudorandom under LPN, which gives the desired correlation.

Optimizations and additional applications. Boyle et al. state the computational com- plexity of the above as *O*(*n⁴*) operations, due to the tensor product of *H* with itself. We observe | | that the value of (*H ~e₀*) (*H ~e₁*) can be read directly from *H* (*~e₀ ~e₁*) *H*, which requires much less computation and can be made even more efficient if *H* is a structured matrix, reducing the computational complexity to *O*~(*n²*). We also describe two variants of the PCG which allow pro- ducing large matrix multiplication correlations with different parameter tradeoffs. While much less practical than our main constructions, we present these in Section 10 for completeness.

A first attempt. The problem with the above construction is that it produces an entire tensor product correlation, which inherently requires (*n²*) computation. Even if we only want to compute the diagonal entries of the tensor product output (that is, *n* OLEs), we do not see a way to do this any more efficiently. The bottleneck is computing the *n²* entries of *~e₀ ~e₁* to obtain *~z*. A natural idea to reduce the computational complexity is to replace *~e₀* and *~e₁* by degree-*n* sparse polynomials *e₀* and *e₁*, and *~x₀* and *~x₁* by, say, *n=*2 evaluations of *e₀* and *e₁* respectively. Then, *~z* is computable in quasilinear time as evaluations of the polynomial product *e₀ e₁* of degree 2*n*. This approach does not give a secure PCG candidate, though, because *~x₀* and *~x₁* can be efficiently distinguished from random using algebraic decoding techniques.

An efficient PCG for OLE. Our actual approach follows the same idea, but with the under- lying code chosen more carefully. Namely, let *Rp*= Z*p*[*X*]*=F*(*X*) for some degree *N* polynomial *F* (*X*), and let *e;f* be two sparse polynomials in *Rp*. For a random polynomial *a 2 Rp*, the pair

(*a;a e* + *f* mod *F* (*X*))

is pseudorandom under the *ring-LPN* assumption [HKL + 12]. Now, given two pairs of sparse polynomials (*e₀;e₁*) and (*f₀;f₁*), each product *eifj*(without reduction modulo *F*) has degree *<* 2*N* and only *t²* non-zero coefficients. These can again be distributed to two parties using FSS, but this time the expanded FSS outputs can be computed in *linear time* in *N*, instead of quadratic, since the domain size of the function being shared is only 2*N*. Given shares of *eifj*, similarly to the LPN case, the parties compute expanded outputs by defining

*x₀* = *a e₀* + *f₀; x₁* = *a e₁* + *f₁; z* = ((1*;a*) (1*;a*)) ((*e₀;f₀*) (*e₁;f₁*))

The main difference here is that each tensor product is only of length 2, and can be computed in *O*~(*N*) time using fast polynomial multiplication algorithms. This gives a PCG that compresses a single OLE over the ring *Rp*. To obtain a PCG for OLE over Z*p*, we again take inspiration from the fully homomorphic encryption literature, by using ciphertext-packing techniques [SV14]. We can carefully choose *p* and *F* (*X*) such that *F* (*X*) splits into *N* distinct, linear factors modulo *p*. Then *Rp*is isomorphic to *N* copies of Z*p*, and we can immediately convert a random OLE over *Rp*into *N* random OLEs over Z*p*. This works

particularly well with cyclotomic rings as used in ring-LWE [LPR13], where we can e.g. use *N* a power of two and easily exploit FFTs for polynomial arithmetic.

Extending to authenticated multiplication triples. We show that our construction ex- tends from OLE to authenticated multiplication triples, as used in the SPDZ protocol for ma- liciously secure MPC [DPSZ12,DKL + 13]. This follows from a simple trick, where we modify the FSS scheme to additionally multiply its outputs by a random MAC key *2* Z*p*. Since this preserves sparsity of the underlying shared vector, it adds only at most a factor of two overhead on top of the basic scheme.

Distributed setup. We focus on the case of OLE correlations over *Rp*(the setup for authen- ticated triples is very similar). Recall that the seed of the PCG for OLE consists of *t*-sparse degree-*N* “error” polynomials *e₀;e₁* and *f₀;f₁*, and FSS keys for secret-shares of the products

|e f, each represented as a coefficient vector via the sum of t² point functions f||: [2N] ! Z|
|---|---|---|
|i j|i|; j|
||i j||

*p*. Each point function corresponds to a single monomial product from *e* and *f*. The index *2* [2*N*] of the nonzero position is the *sum* of the corresponding nonzero indices, and the payload *2* Z*p*is the *product* of the corresponding payloads in *e* and *f*. In the semi-honest setting, secure computation of this PCG generation procedure can be attained directly, using generic 2-PC for simple operations on the and values, as well as black-box use of a protocol for secure computation of FSS key generation, such as the efficient protocol of Doerner and shelat [Ds17]. For the malicious setting, we would wish to mimic the same protocol structure with underly- ing 2-PC components replaced with maliciously secure counterparts. The simple 2-PCs on*;* can be converted to malicious security with relatively minor overhead. The problem is the FSS key generation, for which efficient maliciously secure protocols currently do not exist. Generic 2-PC of the FSS key generation functionality would require expensive secure evaluations of cry- tographic pseudorandom generators (PRG). The semi-honest protocol of [Ds17] is black-box in a PRG; but, precisely this fact makes it difficult to ensure consistency between different steps in the face of a malicious party. Note that this is similar to the problem that Boyle et al. faced in [BCG + 19a] for silent OT generation, but their setting was conceptually simpler: There, one party always knew the position of the non-zero value of the distributed point function (indeed, for their purpose the simpler building block of a puncturable pseudorandom function sufficed). Further, they did not have to assume any correlation between path values, whereas in our setting we require that the parties behave consistently regarding the path positions *and* payloads across several instances. In this work we show how to extend the approach of [BCG + 19a] to the context of distributed point functions, further addressing the mentioned issues. Our protocol realizes a PCG-type functionality for a scaled unit vector³ with leakage: Given authenticated values for the location of the non-zero position *2* [0*::N*) and the non-zero payload *2* Z*p*, the functionality allows a corrupt party to choose its output vector *~y 2* Z *N* *p*and delivers to the honest party the correct corresponding output *~y* (0*;:::;;:::;* 0), where is in the-th position. The leakage on can be captured by allowing the adversary a predicate guess on. 4 In the setting of noise generation for (ring-)LPN, as is the case for our PCG constructions (and likely future constructions), such leakage is tolerable as, intuitively, this can be accounted for by slightly increasing the noise rate. Indeed, we prove that this functionality suffices to implement a protocol securely realizing PCG functionalities, such as the corruptible functionality for OLE 3 Note that this corresponds to a distributed point function where we do not require the key setup on its own to be secure, but only require the protocol to securely implement the FSS functionality including expansion, as this suffices for using PCGs in the context of secure computation (see also [BCG + 19a]). In fact, the leakage can be characterized by predicates corresponding to bit-matching with wildcards.

and authenticated multiplication triples, based on a variant of the ring-LPN assumption that allows small amount of leakage (only 1 bit on average).

Extensions. A downside of the above construction, compared with the one from LPN, is that it is restricted to multiplication triples or OLE. It can be useful to obtain other degree-two correlations such as matrix multiplication triples, which allow multiplying two secret matrices with only *O*(*n²*) communication, instead of *O*(*n³*) from naively using individual triples. Another technique is preprocessing multiplications in a way that depends on the structure of the circuit, which allows reducing the online cost of 2-PC down to communicating just one field element per party, instead of two from multiplication triples [Bea92,DNNR17,Cou19,BNO19,BGI19]. This type of circuit-dependent preprocessing can also be expressed as a degree two correlation. Our PCG for OLE satisfies a useful “programmability” feature, introduced by Boyle et al. [BCG + 19b], allowing certain parts of the PCG output to be reused across multiple instances. This is simply due to the fact that we can reuse the polynomials *e₀;e₁* or *f₀;f₁* in the PCG, without harming security. This allows us to extend the PCG to build more general correla- tions, by using multiple programmed instances to perform every multiplication in the general correlation. We in fact present a more general construction, which, loosely speaking, achieves the fol- lowing. Given a programmable PCG for some bilinear correlation *g*, let *f* be another bilinear correlation that is computable using linear combinations of outputs of *g* applied to its input. Then, we can construct a PCG for *f* using several copies of the PCG for *g*, where the number of instances is given by the complexity of *f* written as a function of *g*. This gives a general way of combining PCGs to obtain correlations of increasing complexity, while allowing for different complexity tradeoffs by varying the “base” bilinear correlation *f*.

Multi-party PCGs. As discussed earlier, the programmability feature also immediately al- lows us to extend our PCGs for OLE and degree-two correlations to the multi-party setting, using the construction from [BCG + 19b]. This does not apply to the PCG for authenticated multi- plication triples; in Section 7.6, we sketch a possible alternative solution based on three-party distributed point functions, but these are much less efficient than the two-party setting.

Security analysis of ring-LPN. We use the ring *Rp*= Z*p*[*X*]*=F*(*X*), for some degree *N* polynomial *F* (*X*). There are two main ring-LPN variants we consider, depending on how the parameters are instantiated. The more conservative is when *F* (*X*) is either *irreducible* in *Rp* (hence, *Rp*is isomorphic to a finite field), or at least when *F* (*X*) has only very few low-degree factors, so *Rp*has a large subring that is a field. This type of instantiation is similar to previous recommendations for ring-LPN [HKL + 12,GJL15] and post-quantum encryption schemes from quasi-cyclic codes [MBD + 18]. The best known attacks are to solve the underlying syndrome decoding problem, and the additional ring structure does not seem to give much advantage. One exception is when a very large number of samples are available, when the ring structure can in some cases be exploited [BL12]. This does not apply to our setting, however, since our constructions only rely on ring-LPN with one sample⁵. The second variant, which is needed for silent OLE in F*p*, is when *F* (*X*) splits modulo *p* into many distinct factors of low degree. Here, the main attack vector that needs to be considered is that if *fi*is some degree-*d* factor of *F* (*X*), then reducing a ring-LPN instance modulo *fi*gives a new instance in smaller dimension *d*, albeit with a different noise distribution. The best case for the adversary is when *fi*is of the form *X* *d* + *ci*, when this reduction does not increase the Hamming weight of the noise (although, the corresponding error rate goes up). If such sparse factors exist, then, we must also ensure that the underlying ring-LPN instance in dimension *d*, with new noise weight, is hard to solve.

Or, two samples if security is based on ring-LPN with a uniform (not sparse) secret.

One way to counter this attack is to choose *F* (*X*) to be a product of *N* random linear factors, ensuring that any factors of *F* an adversary can find are likely to be very dense. However, to improve computational efficiency, it is better to use a cyclotomic polynomial such as *F* (*X*) = *X* *N* + 1 with *N* a power of two, as is common in the ring-LWE setting. In this case, there are 2 *i* many sparse factors of the form *X* + *ci*which can be exploited, and we must take these into account when choosing parameters. The main advantage of performing this reduction is the vector operations in attacks such as information-set decoding become cheaper, since they are all in a smaller dimension. This only has a small overall effect on attack complexity, though, since these algorithms are all exponential in the noise weight. Therefore, to counter the attack, it suffices to ensure there are enough noisy coordinates in a reduced instance, which requires only a small increase in noise weight. Note that for *p* = 2, this strategy was also considered in Lapin [HKL + 12], and it was later shown that an optimized version of this over F₂ reduces security of some Lapin parameter sets by 10 bits [GJL15]. Our analysis over F*p*is roughly consistent with this.

## 2 Preliminaries

### 2.1 Notation

We let denote a security parameter, and use the standard definitions of negligible functions, computational indistinguishability (with respect to nonuniform distinguishers), and pseudoran- dom generators. We use [0*::n*) to denote the index set *f*0*;;n* 1*g*, as well as [0*::n*] = *f*0*;:::;ng* and [*n*] = *f*1*;:::;ng*.

Vectors, outer sum and outer product. We use column vectors by default. For two vectors *~u* = (*u₁;:::;ut*)*;~v* = (*v₁;:::;vt*) *2 R* *t*, for some ring *R*, we write *~u ~v* to mean the *outer sum* given by the length *t²* vector (*ui*+ *vj*) *i2*[*t*]*;j2*[*t*]. Similarly, we define the flattened outer product (or tensor product) to be *~u ~v* = (*uivj*) *i2*[*t*]*;j2*[*t*], that is, the vector (*v₁ ~u;:::;vn~u*). We denote the inner product of two vectors by *h~u;~vi*.

### 2.2 Function Secret Sharing

Function secret sharing [BGI15,BGI16b] (FSS) is a succinct secret sharing of functions. More concretely, an FSS scheme randomly splits a secret function *f* : *I !* G, where G is some Abelian group, into two or more functions *fi*, each represented by a key *Ki*, such that: (1) the sum of all P function shares *fi*is equal to *f* (namely, *i* *fi*(*x*) = *f* (*x*) for every input *x 2 I*), and (2) each subset of the keys *Ki*hides *f*. In this work we will use 2-party FSS that we formalize below.

Definition 2.1 (Function Secret Sharing) *Let C* = *ff* : *I!* G*g be a class of function* *descriptions, where the description of each f specifies the input domain I and an Abelian group* (G*;*+) *as the output domain. A (2-party)* function secret sharing *(FSS) scheme for C is a pair* *of algorithms* FSS = (FSS*:* Gen*;*FSS*:* Eval) *with the following syntax:*

- FSS*:* Gen(1*;f*) *is a PPT algorithm that given security parameter and description of* *f 2C outputs a pair of keys* (*K₀;K₁*)*. We assume that the keys specify I and* G*.*
- FSS*:* Eval(*b;Kb;x*) *is a polynomial-time algorithm that, given a key Kbfor party b 2f*0*;* 1*g,* *and an input x 2 I, outputs a group element yb2* G*.*
*The scheme should satisfy the following requirements:* $

- Correctness: *For any f 2 C and x I, we have* Pr[(*K₀;K₁*) FSS*:* Gen(1*;f*) : P *b2f; g*
FSS*:* Eval(*b;Kb;x*) = *f* (*x*)] = 1*.*

- Security: *For any b 2 f; g, there exists a PPT simulator* Sim *such that for any*
$ *polynomial-size function sequence f 2C, the distributions f*(*K₀;K₁*) FSS*:* Gen(1*;f*) : $ *Kbg and fKb*Sim(1*;*Leak(*f*))*g are computationally indistinguishable.*

*In the constructions we use, the leakage function* Leak : *f*0*;* 1*g!f*0*;* 1*g is given by* Leak(*f*) = (*I;* G)*, namely it outputs a description of the input and output domains of f.*

We also define a full-domain evaluation algorithm, FSS*:* FullEval(*b;Kb*), which outputs a vec- tor of *jIj* group elements, corresponding to running Eval on every element *x* in the domain *I*. For the type of FSS we consider, FSS*:* FullEval is significantly faster than the generic solution of running *jI* instances of Eval. We will use FSS for point functions and sums of point functions, as defined below.

Definition 2.2 (Distributed Point Function (DPF) [GI14,BGI15]) *For an Abelian group* G*, 2* [*n*]*, and 2* G*, the* point function *f;is the function f;*: [*n*]*!* G *defined by* *f;*(*x*) = 0 *whenever x 6*=*, and f;*(*x*) = *if x* =*. A* distributed point function *(DPF) is* *an FSS scheme for the class of point functions ff;*: [*n*]*!* G *j 2* [*n*]*; 2* G*g.*

The best known DPF construction [BGI16b] can use any pseudorandom generator (PRG) 2 +2 <u>logjGj</u> *G* : *f*0*;* 1*g! f*0*;* 1*g* and has the following efficiency features. For *m* = *d* +2 *e*, the key generation algorithm Gen invokes *G* at most 2(*d*log *ne*+ *m*) times, the evaluation algorithm Eval invokes *G* at most *d*log *ne* + *m* times, and the full-domain evaluation algorithm FullEval invokes *G* at most *n* (1 +*m*) times. The size of each key is at most *d*log *ne*( + 2) + + *d*log₂ *j*G*je* bits. We will use a simple and generic extension of DPF to sums of point functions.

Definition 2.3 (FSS for sum of point functions (SPFSS)) *For S* = (*s₁;:::;st*) *2* [*n*] *t* *and ~y* = (*y₁;:::;yt*) *2* G *t* *, define the* sum of point functions *fS;~y*: [*n*]*!* G *by*

X *t* *fS;~y*(*x*) = *fsi;yi*(*x*)*:* *i*=1

*An* SPFSS *scheme is an FSS scheme for the class of sums of point functions fS;~y.*

Note that for *S* = (*s₁;:::;st*), the function *fS;~y*non-zero on *at most t* points. If the ele- ments of *S* are distinct, *fS;~y*coincides with a *multi-point function* for the set of points in *S*; however, in our usage we can have repeated elements in *S*. A simple realization of SPFSS is by summing *t* independent instances of DPF. This will typically be good enough for our purposes. Alternatively, asymptotically better constructions for full-domain evaluation can be obtained using hash functions or (probabilistic) batch codes [IKOS04,BCGI18,ACLS18,SGRR19]. To simplify notation, when generating keys for a scheme SPFSS = (SPFSS*:* Gen*;*SPFSS*:* Eval), we write SPFSS*:* Gen(1*;S;~y*), instead of explicitly writing *fS;~y*.

### 2.3 Pseudorandom Correlation Generators

A pseudorandom correlation generator (PCG) [BCGI18,BCG + 19b] is a primitive with a setup algorithm that generates a pair of seeds, which can then be locally expanded to produce *correlated* pseudorandomness. To define security, we use the notions of correlation generators, and reverse- sampleable correlation generators, from [BCG + 19b].

Definition 2.4 (Correlation generator) *A PPT algorithm C is called a* correlation genera- tor*, if C on input outputs a pair of elements in f; g* *n* *f; g* *n* *for n 2* poly()*.*

Definition 2.5 (Reverse-sampleable correlation generator) *Let C be a correlation gener-* *ator. We say C is* reverse sampleable *if there exists a PPT algorithm* RSample *such that for* *2f; g the correlation obtained via:*

*0 0*$*0 0*$ *f*(*R₀;R₁*) *j*(*R₀;R₁*) *C* (1 )*;R* := *R;R₁* RSample(*;R*)*g*

### is computationally indistinguishable from C(1 ).

The following definition of pseudorandom correlation generators can be viewed as a general- ization of the definition of the pseudorandom VOLE generator in [BCGI18].

Definition 2.6 (Pseudorandom Correlation Generator (PCG)) *Let C be a reverse-sam-* *pleable correlation generator. A* pseudorandom correlation generator (PCG) for *C is a pair of* *algorithms* (PCG*:* Gen*;*PCG*:* Expand) *with the following syntax:*

- PCG*:* Gen(1 ) *is a PPT algorithm that given a security parameter, outputs a pair of seeds* (k₀*;*k₁)*;*
- PCG*:* Expand(*;* k) *is a polynomial-time algorithm that given a party index 2f*0*;* 1*g and* *a seed* k*, outputs a bit string R 2f*0*;* 1*g*
*n* *.*

*The algorithms* (PCG*:* Gen*;*PCG*:* Expand) *should satisfy the following:*

- Correctness. *The correlation obtained via:*
$ *f*(*R₀;R₁*) *j* (k₀*;*k₁) PCG*:* Gen(1 )*;R* PCG*:* Expand(*;* k) *for 2f*0*;* 1*gg*

### is computationally indistinguishable from C(1 ).

- Security. *For any 2f*0*;* 1*g, the following two distributions are computationally indis-* *tinguishable:*
$ *f*(k₁*;R*) *j* (k₀*;*k₁) PCG*:* Gen(1 )*;R* PCG*:* Expand(*;* k)*g and* $ *f*(k₁*;R*) *j* (k₀*;*k₁) PCG*:* Gen(1 )*;R₁* PCG*:* Expand(*;*k₁)*;* $ *R* RSample(*;R₁*)*g*

*where* RSample *is the reverse sampling algorithm for correlation C.*

Note that to avoid the trivial solution where PCG*:* Gen simply outputs a sample from *C*, we are only interested in constructions where the seed size is significantly shorter than the output size.

## 3 The Ring-LPN Assumption

In this section, we recall the ring-LPN assumption, which was first introduced (over Z₂) in [HKL + 12] to build efficient authentication protocols. Since then, it has received some attention from the cryptography community [BL12,DP12,LP15,GJL15], due to its appealing combination of LPN- like structure, compact parameters, and short runtimes. Below, we provide a definition of module-LPN, which generalizes ring-LPN in the same way that the more well-known module- LWE generalizes ring-LWE. We also discuss several variants depending on the choice of ring, including cyclotomic rings over Z*p*, which have previously been used for ring-LWE.

### 3.1 Ring-LPN

Definition 3.1 (Ring-LPN) *Let R* = Z*p*[*X*]*=F*(*X*) *for a prime p and degree-N polynomial* *F* (*X*) Z*p*[*X*]*. (We will write Rpwhen we want to highlight the modulus p.) For t 2* N*,* *let HWR;tdenote the distribution of “sparse polynomials” over R obtained by sampling t noise* *positions A* [0*::N*) *t* *and t payloads ~b* (Z*p*) *t* *uniformly at random, and outputting e*(*X*) := P *t* 1 *A*[*j*] *~* *b*[*j*] *X : (We write HWtwhen R is clear from the context.) For R* = *R*()*;m* = *j*=0 *m*()*;t* = *t*()*, we say that the* ring-LPN problem *R*-LPN*R;m;tis hard if for every nonuniform* *polynomial-time distinguishher A, it holds that*

Pr[*A*((*a*

(*i*) *;a*
(*i*) *e* + *f*
(*i*) ) *m* *i*=1) = 1] Pr[*A*((*a*
(*i*) *;u*
(*i*) ) *m* *i*=1) = 1] negl()
*where the probabilities are taken over a*

(1) *;:::;a*
(*m*) *;u*
(1) *;:::;u*
(*m*) *R*() *and e;f*
(1) *;:::;f*
(*m*)
*HWR;t.* *We will also use the* regular *variant of R-*LPN*R;m;t, which is defined in the same way as above* *except that HWR;tis obtained by letting A include a single random position from each block of* *size N=t (where here we assume that tjN).*

Remark 3.1 (Useful parameters) *Our constructions will only use Definition 3.1 with m* = 1*,* *namely one sample. Bigger values of m will be used for reducing security in this case to a variant* *where the secret e is uniform (see Lemma 3.4 below). The sparsity parameter t will roughly* *correspond to a concrete security parameter, the degree N to the length of the target correlation* *(or number of instances of an atomic correlation), and p to a modulus over which this correlation* *is defined. Useful choices of the polynomial F*(*X*) *will be discussed in Section 3.2 below.*

Remark 3.2 (Noise distribution) *Note that in the default variant of our definition, the dis-* *tribution over sparse polynomials is obtained by picking the t noise positions* with *replacement.* *This can result in collisions, and thus negatively affect the entropy introduced by the payloads.* *The reason for this choice is that it helps simplify some of our constructions and their analysis.* *The entropy loss is minor in the regime of parameters we care about, as for t N the proba-* *bility of collisions is very small. The collisions are entirely avoided in the regular variant of the* *definition, which also leads to better concrete efficiency in our constructions.*

Remark 3.3 (Extension to other rings.) *Note that our restriction to prime-order fields* Z*p* *is only for simplicity; R-*LPN *can be defined similarly over other rings (such as extension fields* F*pd or rings* Z₂*k or* Z*pqfor primes p;q). These alternative choices are not known to introduce* *any significant weakness or structural difference compared to the version over prime-order fields.* *In fact, we obtain PCGs for OLEs and multiplication triples over extension fields* F*pd by using* *rings Rpdefined over the base field.*

Module LPN. We will also use a natural generalization of *R*-LPN, where we replace *a*

(*i*) *e*
by the inner product *h~a*

(*i*) *;~ei* between length-(*c* 1) vectors over *R*, for some constant *c* 2.
(The parameter *c* can be viewed as a *compression factor* in our construction – see more below.) We call this *module-LPN*, analogously to module-LWE. This will allow for useful efficiency tradeoffs, as according to our security analysis it will be enough to choose the total number of noise positions *w* such that *w* = *ct*, and therefore increasing *c* allows to choose a smaller *t*. For the parameter regime in our constructions, increasing *c* will result in shorter PCG seeds at the expanse of higher running time of Expand.

Definition 3.2 (Module-LPN) *Let c* 2 *be an integer and R; HWR;tbe as in Definition 3.1.* *Then, for R* = *R*()*;m* = *m*()*;t* = *t*()*, we say that the R* *c* *-*LPN*R;m;tproblem is hard if for* *every nonuniform polynomial-time distinguisher A, it holds that*

|(i) (i)|(i) m|(i) (i) m||
|---|---|---|---|
||i=1 (1)|i=1 c 1 (1)|cR;t1|
|R;t|||R;t|

Pr[*A*((*~a; h~a;~ei* + *f*)) = 1] Pr[*A*((*~a;u*)) = 1] negl()

*where the probabilities are taken over ~a;:::;~a*

(*m*) *R, u;;u*
(*m*) *R, ~e HW,*
*f*

(1) *;:::;f*
(*m*) *HW. We similarly define the regular variant by modifying HW as in*
*Definition 3.1.*

Equivalence to module-LPN with uniform secret. We observe that, by the same argu- ment as for standard LWE [ACPS09], the *R*-LPN (resp. module-LPN) problem with a secret chosen from the error distribution is at least as hard as the corresponding *R*-LPN (resp. module- LPN) problem where the secret is chosen uniformly at random, if the adversary is given one additional sample (resp., *c* 1 additional samples).

Lemma 3.4 *For any c* 2*, let R* *c* *-*uLPN *denote the variant of R* *c* *-*LPN *where the secret e is sam-* *pled uniformly at random. Then, for any R* = *R*()*;m* = *m*()*;t* = *t*()*, if R* *c* *-*uLPN*R;m*+(*c* 1)*;t* *is hard then R* *c* *-*LPN*R;m;tis hard.*

*Proof.* Let *m > c*. We show how a distinguisher for *R* *c* -LPN*R;m* (*c* 1)*;t*can be used to solve an in- stance of *R* *c*

|-uLPN|, which implies the statement in the theorem. Let (~a||||;u;|;~a ;u|
|---|---|---|---|---|---|---|
|c||(i) c 1|||(1)|(c 1)|
|||||(i)|||
|(c 1) (c|1)||(c)|(m)|||

(1) (c 1) (c) (m)

*R;m;t*

(1) (1) (*m*) (*m*)
) be *R* *c* -uLPN samples, where *~a*

(*i*) *2 R* *c* 1 and *u*
(*i*) *2 R* for *i* = 1 to *m*. Assume that (*~a*
(1) *;;~a* (*c* 1)
), viewed as a matrix *A* of dimensions (*c* 1) (*c* 1) over *R*, is invertible; this happens with high probability (at least constant) over a random choice of the *~a*. Denote by *A⁰ 2* *R* *m* the matrix whose rows are the remaining (*~a;;~a*), by *~u* the (vertical) vector (*u;;u*), and by *~u⁰* the (vertical) vector (*u;;u*). With these, the dis- tinguishing game can be rewritten as follows: the adversary must distinguish between the case where

- *A~e* + *f~* = *~u* for some *~e 2 R*
*c* 1 *cR;t*1

|||and sparse f~ 2HW||, and|||
|---|---|---|---|---|---|---|
|0||0|m R;t c+1||||
||1||||||
||||0|c R;m|(c 1);t||
|c|R;m (c 1);t|||||c|

- *A⁰~e* + *f~* = *~u⁰* for some sparse *f~ 2HW*,
from the case where (*~u;~u⁰*) are random. But since *A* is invertible, by multiplying the first equation with *B A⁰A* and denoting *~v B~u ~u⁰*, the first case can be rewritten as

### Bf~ f~ = ~v

which is distributed exactly as an instance of the *R*-LPN problem; hence, a distin- guisher for *R*-LPN can be used to get a distinguisher for *R*-uLPN*R;m;t*.

Relation to syndrome decoding. Our constructions will use module-LPN with a single sample (*m* = 1). To simplify notation and emphasize that the secret comes from the error dis- tribution, we often combine the secret and noise value (*~e* and *f* in the notation of Definition 3.2) into a single vector *~e*, replacing the previous (*~a; h~a;~ei* + *f*) by writing (*~a; h~a;~ei*), where

*0 0*$*c* 1$*cR;t* *~a* = (1*;~a*)*;~a R;~e HW :*

This formulation of module-LPN is equivalent to a variant of the syndrome decoding problem in random polynomial codes. To see this, let *Mi*be the *N N* matrix over Z*p*representing multiplication with the fixed element *a* *0i* *2 Rp*, for *i* = 1 to *c* 1. Define the matrix

### H = [IdNjjM₁jjjjMc 1]:

*H* is a parity-check matrix in systematic form for a polynomial code defined by the random elements *a* *0i* *2 Rp*. Module-LPN can be seen as a decisional version of syndrome decoding for

this code, where we assume that (*H;H ~e*) is pseudorandom for an error vector *~e* = (*e₁;:::;ec*) with a regular structure, namely where each of the length-*N* blocks *ei*have *t* non-zero entries. The code has length *N c* and dimension *N* (*c* 1); the rate of the code is therefore (*c* 1)*=c*. With this formulation, *c* can be viewed as the compression factor of the linear map *~e ! H ~e*. Therefore, we generally refer to *c* as the *syndrome compression factor*.

### 3.2 Choice of the Polynomial F

The ring-LPN assumption (and more generally, the module-LPN assumption) is dependent of the choice of the underlying polynomial *F*. We discuss possible choices for the polynomial *F*, and their implications for the security of ring-LPN/module-LPN over the corresponding ring *Rp*= Z*p*[*X*]*=F*(*X*).

Irreducible *F* (*X*). The most conservative instantiation is when *F* (*X*) is irreducible over Z*p*, and so *Rp*is a field. In this setting, no attacks are known that perform significantly better than for standard LPN.

Reducible *F* (*X*). We also consider when *F* (*X*) is reducible over Z*p*, and splits into several distinct factors. Here we have a few different useful instantiations.

1. *Cyclotomic F*(*X*)*.* Let *F* (*X*) be the *M*-th cyclotomic polynomial, whose degree is *N* =
(*M*) (Euler’s totient function). Then, *F* (*X*) splits modulo *p* into *N=d* distinct factors
*fi*, where each *fi*is of degree *d*, and *d* is the smallest integer satisfying *p* *d* 1 mod *M*. The advantage of using a cyclotomic *F* is that it allows for fast multiplication in *Rp*using FFT. We are particularly interested in the following cases.

- *Two-power N, prime p >* 2*N.* Let *N* be a power of two and *p* a large prime such that *p* 1 mod (2*N*) (here, *M* = 2*N*). Then *F* (*X*) splits completely into *N* linear factors modulo *p*, so *Rp*is isomorphic to Z
*N*

*p*.
- *p* = 2*.* Here, each degree-*d* subring Z*p*[*X*]*=*(*fi*(*X*)) is isomorphic to the finite field
*N=d* F₂*d*, hence *Rp*= F₂*d*.

Regarding security, we observe that cyclotomic polynomials can introduce an additional weakness, due to sparse factors of *F* (*X*). In Section 8.2, we analyze this further and discuss how to adjust parameters accordingly.

2. *Random factors.* A more conservative option may be to choose an *F* (*X*) that splits com- pletely into *d* distinct, *random* factors. For instance, for a large prime *p* we can pick (distinct) random elements1*;:::;N*Z*p*and let
Y *N* *F* (*X*) = (*Xi*) *i*=1

Just as with the two-power cyclotomic case, *Rp*is isomorphic to Z *N*

*p*. Now, however, the
problem may be harder since we are avoiding the structure given by roots of unity. On the other hand, the isomorphism is more expensive to compute as we can no longer make a direct use of FFT, and polynomial interpolation algorithms cost *O*(*N* log² *N*) instead of *O*(*N* log*N*).

## PCGs for OLE and Authenticated Multiplication Triples

In this section, we construct PCGs for OLE and authenticated multiplication triples, based on the *R* *c* -LPN assumption. The constructions in this section can achieve an arbitrary (a priori bounded) polynomial stretch, where the seed size scales logarithmically with the output length *N* and the running time of Expand scales nearly linearly with *N*.

### 4.1 PCG for OLE over Rp

We build a PCG for producing a single OLE over the ring *Rp*. When *Rp*splits appropriately, as described in Section 3.2, this can be locally transformed into a PCG for a large batch of OLEs or (authenticated) multiplication triples over a finite field F*pd* or F*p*. The OLE correlation over *Rp*outputs a single sample from the distribution n o $ ((*x₀;z₀*)*;* (*x₁;z₁*)) *x₀;x₁;z₀ Rp;z₁* = *x₀ x₁ z₀*

This can be viewed as giving the two parties additive shares of a product of two random elements *x₀;x₁* of *Rp*, where *x* is known to party *P*. Below is an informal presentation of the construction, which is described formally in Fig. 1. The high-level idea is to first give each of the two parties a random vector *~e₀* or *~e₁ 2 Rp* *c*, consisting of sparse polynomials, together with a random, additive secret sharing of the tensor product *~e₀ ~e₁* over *Rp*. We view *~e₀;~e₁* as *R* *c* -LPN error vectors (whose first entry is implicitly the *R* *c* -LPN secret), which will be expanded to produce outputs *x* = *h~a;~e i* by each party *P* for a random, public *~a* = (1*; ~a* ^). This defines two *R* *c* -LPN instances with independent secrets but the same *~a* value, which are pseudorandom by a standard reduction to *R* *c* -LPN with a single sample. To obtain shares of *x₀ x₁*, observe that when *~a* is fixed, this is a degree 2 function in (*~e₀;~e₁*), so can be computed locally by the parties given their shares of *~e₀ ~e₁*. The only part that remains, then, is to distribute shares of this tensor product. Recall that each entry of *~e* is a polynomial of degree less than *N* with at most *t* non-zero coordinates. We write these coefficients as a set of indices *A 2* [0*::N*) *t* and corresponding non-zero values *~b 2* Z*t*. Taking two such sparse polynomials (*A;~b*) and (*A⁰;~b⁰*), notice that the product of the *p* two polynomials is given by 0 1 0 1 X X *0* X *0* @ *~b*[*i*] *XA*[*i*]A @ *~b⁰*[*j*] *XA* [*j*]A = *~b*[*i*] *~b⁰*[*j*] *XA*[*i*]+*A* [*j*] *i2*[0*::t*) *j2*[0*::t*) *i;j2*[0*::t*)

We can therefore express the coefficient vector of the product as a *sum of t² point functions*, where the (*i;j*)-th point function evaluates to *~b*[*i*] *~b₀*[*j*] at input *A*[*i*] + *A⁰*[*j*], and zero elsewhere. This means the parties can distribute this product using a function secret sharing scheme SPFSS for sums of point functions, as defined in Definition 2.3. Recall that an SPFSS takes a sequence of points and associated vector of values, and produces two keys that represent shares of the underlying sum of point functions. If each party locally evaluates its key at every point in the domain, then it obtains a pseudorandom secret-sharing of the coefficients of the entire sparse polynomial. There are *c²* polynomials in the tensor product, so overall we need *c²* instances of SPFSS, where each SPFSS uses *t²* point functions. Instantiating this naively using *t²* distributed point functions, we get a seed size of *O*~( (*ct*) 2 log*N*) bits. Note that to achieve exponential security against the best known attacks on *R* *c* -LPN, it is enough to choose *ct* = *O*(). By increasing *N*, we can therefore obtain an arbitrary polynomial stretch for the PCG, where the stretch is defined as the ratio of its output length to the seed size.

More concretely, we have the following theorem.

### Construction GOLE

Parameters: Security parameter, noise weight *t* = *t*(), compression factor *c* 2, modulus *p* = *p*(), degree *N* = *N* (), and the ring *Rp*= Z*p*[*X*]*=F*(*X*) for degree-*N F*(*X*) *2* Z*p*[*X*]. An FSS scheme (SPFSS*:* Gen*;*SPFSS*:* FullEval) for sums of *t²* point functions, with domain [0*::* 2*N* 1) and range Z*p*. Public input: random polynomials *a₁;:::;ac* 1 *p* *c*

|2 R|, used for R|-LPN.|
|---|---|---|
|c 1|p|c|
||2 p|2 p|

Correlation: After expansion, outputs (*x₀;z₀*) *2 R* and (*x₁;z₁*) *2 R*, where *z₀*+*z₁* = *x₀ x₁*.

### Gen: On input 1 :

||||t i|t|
|---|---|---|---|---|
|||i;j i;j|i|p j i j|
|||||1|
|i;j|i i||||
|i;j2[0::c)|i2[0::c)||||

1.For *2f*0*;* 1*g* and *i 2* [0*::c*), sample random vectors *A*
*i* [0*::N*) and *~b* (Z).

$*~b*

2.For each *i;j 2* [0*::c*), sample FSS keys (*K₀;K₁*) SPFSS*:* Gen(1*;A₀ A₁;~b₀*).
3.Let k = (*K*)*;* (*A;~b*).
4.Output (k₀*;*k₁).
### Expand: On input (; k):

|i;j|i i||||
|---|---|---|---|---|
|i;j2[0::c) p|i2[0::c) i|j2[0::t)|A [j] c 1|c 1|
||||i;j||
||;i+cj||||

1.Parse k as (*K*)*;* (*A;~b*).
2.Define (over Z) the degree *< N* polynomials, for *i 2* [0*::c*)
X *i* *e* (*X*) = *~b* *i* [*j*] *X*

3.Compute *x* = *h~a;~e i* mod *F* (*X*), where *~a* = (1*;a₁;:::;a*), *~e* = (*e⁰;:::;e*).
4.For *i;j 2* [0*::c*), compute *u* SPFSS*:* FullEval(*;K*) and view this as a degree *<* 2*N* polynomial, defining the length-*c²* vector *~u* mod *F* (*X*).
5.Compute *z* = *h~a ~a;~u i* mod *F* (*X*).
<u>6.Output (x;z)</u>
Figure 1: PCG for OLE over the ring *Rp*, based on ring-LPN

Theorem 4.1 *Suppose that* SPFSS *is a secure FSS scheme for sums of point functions (Defi-* *nition 2.3), and the R* *c* *-*LPN*Rp;;tassumption (Definition 3.2) holds. Then the construction in*

*Fig. 1 is a secure PCG for OLE over Rp.*

When instantiating SPFSS using from PRG : *f*0*;* 1*g! f*0*;* 1*g²* +2 via the PRG-based DPF construction from [BGI16b], we have:

- Each party’s seed has size at most (*ct*)
2 ((*d*log *N e*+ 1) ( + 2) + + *d*log *pe*) +*ct*(*d*log *N e*+ *d*log *pe*) bits.

- The computation of Expand can be done with at most (4 + 2*b*log *p=c*)*N* (*ct*)
2 PRG oper- ations, and *O*(*c²N* log*N*) operations in Z*p*.

Under standard ring-LPN parameters the above can be instantiated with seed size poly() log*N* and with Expand running in time *O*(*N* 1+ ). This running time can be improved to *O*~(*N*) using batch codes, as discussed below. Increasing the syndrome compression parameter *c* allows choosing a smaller noise parameter *t*, which results in smaller seed side at the expense of increased running time. *Proof.* We first argue correctness. *i j* Let *i;j 2* [0*::c*) and consider the polynomials *e₀;e₁* defined in Expand. We have, X *i j* *i j~bi~bj A*0[*k*]+*A*1[*‘*] *e₀*(*X*) *e₁*(*X*) =0[*k*] 1 [*‘*] *X* *k;‘2*[0*::t*) Therefore, the coefficients of this product can be obtained by evaluating the sum of point functions used in the (*i;j*)-th instance of SPFSS. This means that *u₀;i*+*cj*+*u₁;i*+*cj*equals *e* *i* 0

(*X*)
*j* *e₁*(*X*), and hence, *~u* = *~e₀ ~e₁*. Looking at the outputs of expand, we then have

*z₀* + *z₁* = *h~a ~a;~u₀* + *~u₁i* = *h~a ~a;~e₀ ~e₁i* = *h~a;~e₀ih~a;~e₁i* = *x₀ x₁* where the penultimate equality can be seen by inspection of the tensor products. Each *h~a;~e i* can be seen as a sample from the *R* *c* -LPN distribution with a fixed random *~a* and independent secret *~e*. It follows from a standard hybrid argument that (*x₀;x₁*) is computation- ally indistinguishable from a random pair in *Rp* 2, under *R* *c* -LPN. Furthermore, by the security of SPFSS, each *z* is individually pseudorandom, so the outputs (*x₀;z₀;x₁;z₁*) are indistinguishable from a random OLE over *R*. To show the security property, fix = 1 (the case = 0 is symmetric). For two keys $ (k₀*;*k₁) PCG*:* Gen(1 ) with associated expanded outputs (*x₀;z₀*) and (*x₁;z₁*), we need to show that n o $

|~; z~|)jx ~|R; z~ = ~|
|---|---|---|
|0 0 i;j|0|p 0|

*f*(k₁*;x₀;z₀*)*g* (k₁*; x x₀ x₁ z₁*

We use a sequence of hybrids, where first we change *z₀* to be computed as *x₀ x₁ z₁*, and successively replace each FSS key *K₁* in k₁ with a *simulated* key, generated with only the range and domain of the function. This is indistinguishable from the first distribution, by the correctness and security properties of the FSS scheme. Then, since *K₁* and *z₀* are independent of the *R* *c* -LPN secret producing *x₀*, we can rely on *R* *c* -LPN to sample *x₀* at random instead of from the seed k₀. Finally, we can now switch the FSS keys back to ones generated from SPFSS*:* Gen, again using the FSS security property. This gives the distribution on the right. We remark that assuming *R* *c* -LPN holds for *regular error distributions*, the seed size can be reduced to roughly (*ct*) 2 ((log*N* log*t* + 1) ( + 2) + + log*p*) + *ct*(log*N* + log*p*) bits, and the number of PRG calls in Expand down to (4 + 2*b*(log*p*)*=c*)*Nc²t*. See details below. This eliminates a factor of *t* from the asymptotic computational cost. Furthermore, implementing SPFSS using batch codes reduces the number of PRG calls to *O*(*Nc²*). This eliminates another factor of *t*, making the overall computational overhead logarithmic in *N*, but comes at a cost of making distributed seed generation more complex.

Obtaining OLEs over F*p*. As discussed in Section 3.2, when *R* and *p* are chosen appro- priately, an OLE over *Rp*is locally equivalent to *N* OLEs over F*p*or F*pd*. Hence, this PCG immediately implies PCGs over F*pd*, with the same seed size and complexity. If we want to rely on the (apparently) more conservative version of *R* *c* -LPN, where *F* (*X*) is *irreducible* in Z*p*[*X*], the parties can still use our PCG over *Rp*to obtain OLEs over Z*p*, but this requires *O*(*N*) interaction. To do this, the parties each sample random polynomials *a;b 2* Z*p*[*X*], each of degree *< N=*2. They then use the OLE over *Rp*to multiply *a* and *b*, which can be done by sending *N* elements of Z*p*. 6 This gives shares of *c* = *ab* in *Rp*, which equals *ab* over Z*p*[*X*], since no overflow occurs modulo *F* (*X*) (which has degree *N*). Each party then locally computes evaluations of its shares of *a;b* and *c* at *N=*2 fixed, distinct, non-zero points, which gives *N=*2 secret-shared products over Z*p*(this can be done as long as *p > N=*2).

Optimizations. We now discuss a few optimizations which apply to the basic scheme.

Optimizing the MPFSS evaluation. Naively, the computational cost of the FSS full- domain evaluation is *O*((*ct*) 2

*N*) PRG operations. Using a regular error distribution, we can
bring this down to *O*(*c²tN*) (see below). With batch codes [IKOS04,BCGI18] or probabilistic batch codes [ACLS18,SGRR19], the full evaluation cost can be brought down to *O*(*c²N*) opera- tions. However, if the seed generation phase has to be created by a secure distributed protocol, setting up the seeds that support better Expand time can hurt the concrete cost of distributed seed generation.

Using regular errors. Suppose two sparse polynomials *e₀;e₁ 2 ZpN*are regular, that is *N=t*

|||N=t|
|---|---|---|
|b b;1|b;t|p|
|||;i|

*e* = (*e;:::;e*), where each *eb;j2* Z has weight 1, and defines a coefficient in the range [(*j* 1) (*N=t*)*;j* (*N=t*) 1]. Each pair (*e₀;e₁;j*) gives rise to an index in [(*i* + *j* 2) (*N=t*)*;* (*i* +

*j*) (*N=t*) 2], so the product of two regular error polynomials can be represented by a *t²*-point SPFSS of domain size 2*N=t*. This leads to a total expansion cost of *O*(*c²tN*) PRG operations. Extension to multiplication triples. Recall that in an instance of an OLE correlation over Z*p*, parties *P₀* and *P₁* each hold a secret random Z*p*element, and they jointly hold an additive secret-sharing of the product of the two secrets. While OLE correlations can be directly useful for some applications of secure computation [NP99,IPS09,DGN
+ 17,GN19,CDI + 19,HIMV19], it is often more convenient to use a slightly more complicated variant known as a *multiplication* *triple* correlation [Bea91]. In a (2-party) multiplication triple, the two parties hold *shares* of random Z*p*elements *a* and *b* (which are known to neither party), and moreover they hold shares of the product *c* = *a b*. Multiplication triples are useful for 2-PC of arithmetic circuits over Z*p*with security against semi-honest parties: each multiplication gate can be evaluated by consuming a single multiplication triple and communicating two Z*p*elements per party. (Addition gates are “for free.”) An instance of a multiplication triple correlation can be obtained in a black-box way using two instances of an OLE correlation. Concretely, writing *a* = *a₀* + *a₁*, *b* = *b₀* + *b₁*, and *c* = *a₀b₀* + *a₁b₁* + *a₀b₁* + *a₁b₀*, one can distribute (*a;b*) to party *P* and secret-share the cross-terms *a₀b₁* and *a₁b₀* via two independent OLE instances (the terms *a₀b₀* and *a₁b₁* can be computed locally by *P₀* and *P₁* respectively and added to the OLE outputs). As a result, a PCG generating *N* instances of multiplication triples can be obtained from a PCG generating 2*N* instances of OLE. In the next section we will see how to extend this to *authenticated* multiplication triples, which serve as a useful resource for 2-PC with security against *malicious* parties, at a slightly higher cost. 6 This can be reduced to *N=*2, by defining *a;b* to be the first *N=*2 coefficients of the polynomials *x₀;x₁* produced by the OLE, so that only the second half of the coefficients need to be sent in the multiplication protocol.

|Extension to higher degree correlations.||We can naturally extend this construction from|
|---|---|---|
|OLE over R way products of sparse polynomials instead of just pairwise products. However, this comes at|to general degree-D correlations (over R||
|a high cost: the seed size increases to O((ct)||log N), and the computational cost becomes|
|O ~((ct)|N ).||

*p p*), for any constant *D*, by sharing *D*-

*D* *D*

### 4.2 Authenticated Multiplication Triples

We now show how to modify the PCG for OLE to produce *authenticated multiplication triples*, which are often used in maliciously secure MPC protocols such as the BDOZ [BDOZ11] and SPDZ [DPSZ12,DKL + 13] line of work. Note that although OLE can be used to build authen- ticated triples in a black-box way, doing this requires several OLEs and some interaction, for every triple. This is contrasted with the case of standard multiplication triples, discussed above, that can be reduced to OLE without any interaction. Our PCG avoids this interaction, with only a small overhead on top of the previous construction: the seeds are less than 2x larger, while the expansion phase has around twice the computational cost.

Secret-sharing with MACs. We use authenticated secret-sharing based on SPDZ MACs between *n* parties, where a secret-sharing of *x 2* Z*p*is defined as: X X X J*x*K = (*i i x;i* *n*

|;x ;m|)|x = x;|m = x|||
|---|---|---|---|---|---|
||i|i|i|i|x;i|

*i*=1such that*i x;i i* *i i i* Note that the MAC key shares are fixed for every shared *x*. The MAC shares *m* are used to prevent a sharing from being opened incorrectly, via a MAC check procedure from [DKL + 13]. $ An *authenticated multiplication triple* is a tuple of random sharings (J*x*K*;* J*y*K*;* J*z*K), where *x;y* Z*p*and *z* = *x y*. Our PCG outputs a single multiplication triple over the ring *Rp*, for *n* = 2 parties, together with additive shares of the MAC key *2* Z*p*. When using the fully-reducible variant of ring-LPN, this is equivalent to *N* triples over F*pd* (where for suitably chosen *p* we can have *d* = 1).

PCG construction. The construction, given in Fig. 2, is remarkably simple. Recall that our previous construction for OLE uses FSS keys which are expanded into shares of sparse polynomials *u*

|= e|e 2 Z [X]. The FSS payload was defined by some (column) vector||
|---|---|---|
|i;j i|j p 2|i;j|
|||p p|
|p 2N 2|||

*tp* 2 *~v 2* Z, which defines the *t* values of the non-zero coefficients in *u*. We can modify this to produce *authenticated OLE* by extending the FSS range from Z to Z², and letting the payload be *~v* (1*;*) *2* Z, for a random *2* Z*p*. Evaluating the FSS keys at some input *k* now produces shares of (*~v*[*k*]*; ~v*[*k*]). Hence, these can be used to obtain authenticated shares of *x₀ x₁*, as well as the OLE. To extend the above to authenticated triples, the seed generation phase will now produce three sets of FSS keys. The first two sets, (*Kx;* *i* 0 *;Kx;* *i* 1 ) and (*Ky;* *i* 0 *;Ky;* *i* 1 ), are used to compress shares of the 2*c* sparse polynomials defined by (*A* *i* 0 *;~b* *i* 0 ) and (*A* *i* 1 *;~b* *i* 1 ). These have sparsity *t*, so can be compressed using *t*-point SPFSS, and are later expanded to produce shares and MAC shares for *Rp*elements *x* and *y*. The third set, (*Kz;* *i* 0 *;Kz;* *i* 1 ), compresses pairwise products of the previous sparse polynomials, so each of these can be defined using *t²*-point SPFSS, as in the previous construction. This gives the shares and MAC shares for the product term *z* = *x y*. We omit the proof of the following theorem, which is very similar to that of Theorem 4.1. Recall that to achieve exponential security against the best known attacks on *R* *c* -LPN, it is enough to choose *ct* = *O*(), therefore choosing a larger *c* allows to decrease the size of *t*. For more details on concrete parameter choices we refer to Section 9.

### Construction Gtriple

Parameters: Security parameter, noise weight *t* = *t*(), compression factor *c* 2, modulus *p* = *p*(), degree *N* = *N* (), and the ring *Rp*= Z*p*[*X*]*=F*(*X*) for degree-*N F*(*X*) *2* Z*p*[*X*]. An FSS scheme (SPFSS*:* Gen*;*SPFSS*:* FullEval) for sums of *t²* point functions, with domain [0*::* 2*N* 1) and range Z²*p*. Public input: random polynomials *a₁;:::;ac* 1*2 Rp*, used for *R* *c* -LPN. Correlation: Authenticated triples (J*x*K*;* J*y*K*;* J*z*K), satisfying *z* = *x y 2 Rp*, and MAC key shares0*;*1*2* Z*p*.

Gen: On input 1 : $

1.Sample and let =

|; Z|+.|||
|---|---|---|---|
|0 1 p|0 1|t i|t|
||||p|

2.For *2f*0*;* 1*g* and *i 2* [0*::c*), sample random vectors *A*
*i* [0*::N*) and *~b* (Z).

3.Sample the following FSS keys:
*i i*$*i i*

|;K • (K|)|SPFSS:Gen(1 ;A₀|(1;)), for i 2 [0::c) ;~b₀||
|---|---|---|---|---|
|x;0|x;1||||
|i|i||i i||
|y;0|y;1||||
|i;j z;0|i;j z;1 x; i|y; i i2[0::c)|i j z; i;j i;j2[0::c)|i j 0 1|

*x;*0 *x;*1 $

- (*K;K*) SPFSS*:* Gen(1*;A₁;~b₁* (1*;*)), for *i 2* [0*::c*)
$*~b ~b*

- (*K;K*) SPFSS*:* Gen(1*;A₀ A₁;* () (1*;*)), for *i;j 2* [0*::c*)
4.Let k =*;* (*K;K*)*;* (*K*).
5.Output (k₀*;*k₁).
*i i i;j* Expand: On input (*;* k), where k =*;* (*Kx;;Ky;*)*i2*[0*::c*)*;* (*Kz;*)*i;j2*[0*::c*):

1.Compute the vectors *~u;~v; ~w*

||||and ~u⁰ ;~v⁰; ~w⁰|as follows:|
|---|---|---|---|---|
|;i|0;i||x; i||
|;i|;i 0||y; i||
|;i+cj||;i+cj 0||z; i;j|

- *u;u* SPFSS*:* FullEval(*;K*), for *i 2* [0*::c*)
- *v;v* SPFSS*:* FullEval(*;K*), for *i 2* [0*::c*)
- *w;w* SPFSS*:* FullEval(*;K*), for *i;j 2* [0*::c*)
viewing each FullEval output as a pair of degree *<* 2*N* polynomials over Z*p*.

2.Compute
*x* = *h~a;~u i;y* = *h~a;~v i;z* = *h~a ~a; ~w i* and *mx;*= *~a;~u⁰;my;*= *~a;~v⁰;mz;*= *~a ~a; ~w⁰*

### all modulo F (X).

<u>3.Output (;x;y;z;mx;;my;;mz;)</u>
Figure 2: PCG for authenticated triples over the ring *Rp*, based on Ring-LPN

Theorem 4.2 *Suppose that* SPFSS *is a secure FSS scheme for sums of point functions (Defi-* *nition 2.3), and the R* *c* *-*LPN*Rp;;tassumption (Definition 3.2) holds. Then the construction in*

*Fig. 2 is a secure PCG for two-party authenticated multiplication triples over Rp.*

When instantiating SPFSS using from PRG : *f*0*;* 1*g! f*0*;* 1*g²* +2 via the PRG-based DPF construction from [BGI16b], we have a secure PCG for two-party authenticated multiplication triples over *Rp*with the following complexities:

- Each party’s seed has size at most 2(2*ct*+(*ct*)
2 ) ((*d*log *N e*+1) ( +2)+ +*d*log *pe*)+*d*log *pe* bits.

- The computation of Expand can be done with at most (8 + 4*b*(log*p*)*=c*)*N*(2*ct* + (*ct*)
2 ) PRG operations, and *O*(*c²N* log*N*) operations in Z*p*.

As with the PCG for OLE, when using ring-LPN with regular errors the seed size can be reduced, replacing *d*log *N e* + 1 in the formula with log(2*N=t*), while also reducing the number of PRG operations by a factor *t*.

## 5 DPF Key Generation Protocols

Up to this point, the exposition has focused on how to obtain and use pseudorandom correlation generators (PCG), abstracted in an idealized model where the short PCG seeds are sampled by a third-party trusted dealer. In this section, we give the preliminaries that will be necessary to securely set up these seeds. In particular, we present a protocol for setting up keys for distributed point functions with malicious security (allowing some leakage on the path value). Since these protocol works over any finite field, we will present it over F*q*for arbitrary *q 2* N.

### 5.1 Reactive 2-PC

In the following, we assume secure computation of simple operations over F *‘* 2and F*q*, which are depicted in Functionality *F*2-PCand-for the malicious setting-in Functionality *F*ext-2-PCin

Figure 3. Note that the arithmetic addition BitAdd is nontrivial, as the parties must hold

*bitwise* additive secret shares, but the sum itself is over Z. This “grade school addition” over bits can be implemented via a binary circuit for integer addition with log*N* AND gates, similar to previous (e.g., garbled circuit based [KSS09]) protocols. For details on implementation and efficiency considerations we refer to Section 6.3.

### 5.2 Semi-honest DPF Key Generation

Recall that a distributed point function (DPF) allows to generate succinct shares of the point function *f* : [0*::D*)*!* F*q;* ( if *x* = *f;*(*x*) = *:* 0 else

We give the functionality for setting up this succinct shares securely in Figure 4. We use the DPF construction of [BGI16b] and implement the functionality *F*DPFusing the protocol of [Ds17] (note that the optimized DPF construction used in [Ds17] is not secure, see Remark 5.1 for details). In the following we give an overview of the underlying DPF construction and the distributed setup protocol.

The DPF construction [BGI16b]: We start by outlining the underlying DPF construction.

Parameters: Security parameter 1, a natural number *D* specifying the domain size, and a pseudorandom generator PRG : *f; g!f; g²* +2.

### Functionality F2-PC

The functionality operates on elements of F*q*for *q 2* N and bit-strings F *‘* 2for *‘ 2* N. Each value stored by the functionality is associated with a unique identifier that is given to all parties. Let J*y*KF*q*denote the identifier for a value *x 2* F*q*and J*x*K F *‘* denote the identifier for a bit-string 2 *x 2* F *‘* 2that is stored by the functionality. Note that for stored bit-strings J*x*KF*‘*2we assume individual access to the *i*-th bit J*xi*KF2for all *i 2* [0*::‘*).

Input(*P;x*): Receive a value *x 2* F*q*or *x 2* F *‘* 2or from party *P* and store J*x*KF*q*or J*x*KF*‘*2.

Add(J*x*KF*q;* J*y*KF*q*): Compute *z* = *x* + *y 2* F*q*and store J*z*KF*q*.

Add(J*x*K F *‘;* J*y*KF*‘*): (for *x;y 2* F *‘* 2 ) Compute *z* = *x y 2* F *‘* 2and store J*z*KF*‘*. 2 2 2

BitAdd(J*x*K F *‘;* J*y*KF*‘*): (for *x;y 2* F *‘* 2 ) Compute *z* = *x* + *y 2f*0*;* 1*g* *‘*+1 via arithmetic addition 2 2 and store J*z*K F *‘*+1. 2

Mult(J*x*KF*q;* J*y*KF*q*): Compute *z* = *x y 2* F*q*and store J*z*KF*q*.

Output(J*x*KF*q*): Send the value *x 2* F*q*to all parties.

Output(J*x*K F *‘*): Send the value *x 2* F *‘* 2to all parties. 2 Functionality *F*ext-2-PC

The functionality contains all the same commands as *F*2-PC, as well as the additional commands below. In the following, *x* is always the input of party *P*.

Inv(J*x*KF*q*): Compute *z* = *x* 1 *2* F*q*and store J*z*KF*q*.

MixedMult(*x₀;x₁;* J KF2): (for *x₀;x₁ 2* F *‘* 2, *2* F₂) Compute *z* = (*x₀ x₁*) *2* F *‘* 2.

$*‘*

1. *If both parties are honest:* Choose *z₀* F₂ at random and set *z₁* = *z z₀*. Output *z* to *P* for *2f*0*;* 1*g*.
2. *If P is corrupt:* Wait for input *z* by *P*, set *z₁* = *z z* and output *z₁* to *P₁*.
PassiveOutput(*x₀;x₁*): (for *x₀;x₁ 2* F *‘* 2 )

1. *If both parties are honest:* Wait for input *x₀;x₁ 2* F
*‘* 2. Output *z* = *x₀ x₁ 2* F *‘* 2to both parties.

2. *If P is corrupt:* Send *x₁* to *P* and wait for input *x 2* F₂*‘* by *P*. Send *z* = *x₀ x₁ 2* F
*‘* 2to *P₁*.

Figure 3: Functionality *F*2-PCand extended functionality *F*ext-2-PCfor reactive 2-PC over F*q* and F₂

### Functionality FDPF

Parameters: Security parameter 1, distributed point function DPF = (DPF*:* Gen*;*DPF*:* Eval) with domain [0*::D*) and range F*q*, where *D;q 2* N. Functionality: The functionality contains the same Input, Add, Mult and Output com- mands as *F*2-PC, as well as the following command. DPF: On input J K F *‘*, and J KF*q*: 2 dpf dpf

1.Sample keys (*K₀;K₁*) DPF*:* Gen(1*;;*).
dpf

<u>2.For 2f0; 1g output K to P.</u>
Figure 4: Functionality for semi-honest setup of a distributed point function. Here, we parse *2* [0*::D*) as

bit-string *2f*0*;* 1*g* log2 *D*, and assume to be given a secret sharing of over F log 2 2*D* as explained in Figure 3.

Input: A “path” *2* [0*::D*) (in the following usually interpreted as a bit-string *2f*0*;* 1*g* log*D* ) and a “payload” *2* F*q*.

Goal: The parties hold a compact representation of (pseudorandom) shares *~y₀;~y₁ 2* F *D* *q*, such that *~y₀* + *~y₁* = (0*;:::;;:::;* 0), where is in the-th position. In other words, parties *P₀*, *P₁* hold an additive secret sharing modulo *p* of the-th unit vector scaled by payload. 0*;*0 0*;*1 Strategy: 1.Each party *P* holds seeds *~s;~s 2f*0*;* 1*g*. These values define a log*D*-depth tree following the GGM paradigm: To get from the *i*-th to *i* + 1-st level, for all *j 2* [0*::* 2 *i* ), *P* computes

*i*+1*;*2*j i*+1*;*2*j*+1 *i*+1*;*2*j i*+1*;*2*j*+1$*i;j* *~s k~s kt kt* PRG(*~s*)*:*

0*;*0 0*;*1

|||;~s|can be viewed as a compact repre-|
|---|---|---|---|
||log D;0|log D;D|1|
|log D;j|log D;j|||

Ignoring the *t*-values for now, the seeds *~s* log *D;*0 log *D;D* 1 sentation of a length-*D* vector (*~s;:::;~s*).

2.In order to achieve *~s₀* = *~s₁* for all *j 2* [0*::D*)*nf g* (i.e. shares of a scaled unit vector), the idea is to *correct* the nodes leaving the position defined by. If was known to one party (say <u>P₀</u>), this could be achieved by giving a correction
*i i;*0 1*:::ii;*0 1*:::i* word CW := *~s₀ ~s₁* (i.e. the node leaving the path corresponding to in the *i*-th level) to party *P₀* in every level. In the last level the party additionally log *D;* log *D;* 1 log *D;* log *D;* receives CW := (*s₀ s₁*), where *s* corresponds to the value *~s* interpreted as a bit string. (Note that this hides, as party *P₀* as no information on log *D;* any of the preceding nodes of *~s₁*). Adding CW

|at position||:::|in the i-th level and interpreting the last values|
|---|---|---|---|
|i||0 1|i|
||||q|

in the last level of the GGM tree as F elements, where *P₁* multiplies its shares by 1 and *P₀* multiplies the value at the ’s position by CW, the parties indeed obtain output shares of the-th unit vector scaled by.

3.In the general setting, neither party has knowledge of. This is, when the *t*-values
*i;j* come into play. The idea is as follows: For each node *~s* at level *i*, the parties will *i;j i;*0 *i;*1 hold a value *T* (derived from their *t*-values together with correction bits*;* hold by both parties) determining whether party *P* adds the correction word or not, such that

(a)for children of nodes *outside the path corresponding to*, either none or both of the parties add the correction word

(b)for children of nodes *on the path corresponding to*, exactly one of the parties adds the correction word.
*i;j* As the parties do not know about the others party’s *T* value, is not leaked by the correction words or bits.

Remark 5.1 (Difference compared with [Ds17]) *[Ds17] actually use a modification of the* *i;j*

||i;j|||||
|---|---|---|---|---|---|
||||i|||
|i; :::|0|i; :::|i; :::|1 i;|:::|

*above description, since they choose each bit t as the LSB of ~s, instead of as a fresh output* *from the PRG. We observe that unfortunately, this tweak renders their construction insecure,* *since the same bits are then used in computation of the correction words* CW*. This has the effect* 0 *i* 1 0 *i* 100 *i* 1 0 *i* 11 *of leaking the bitiwhenever* LSB(*~s₀ ~s₁*) *6*= LSB(*~s₀ ~s₁*)*.* *This occurs with probability* 1*=*2*, so on average leaks half of the bits of, given just one of the* *two seeds.* 7 *To avoid this issue, we instead apply the setup protocol of [Ds17] to the original DPF* *of [BGI16b].*

The protocol of Doerner and shelat. The setup protocol of Doerner and shelat [Ds17] is based on the observation that the correction words in the *i*-th level can be derived from the *sums* of the values of all left (resp. right) leaves in level *i*, if*i*= 1 (resp.*i*= 0). This is due to the fact that all left (resp. right) leaves that are not a child of node *ji* 1in level *i* 1 already agree due to previous corrections. Their protocol can be described as follows:

Input: The position *2* [0*::D*) (in bit-representation) and the payload *2* F*q*.

0*;*0 0*;*1 Setup: Each party (locally) chooses random seeds *~s;~s 2f*0*;* 1*g*

Key generation: For each *i 2* [0*::D*) the parties input the sums of their right leaves and the sums of their left leaves (as well as the sums of their right *t*-values and their left *t*-values) into a secure computation. The secure computation outputs a correction word *CW* *i* (computed as the sum of either all left leaves or all right leaves, depending on the *i*-th bit of alpha) and correction bits *i;*0 *i;*1

|||;|. The parties correct the nodes of the i-th|
|---|---|---|---|
||i||i;j|
|i+1;2j|i+1;2j+1|||

*i i;j* level by adding *CW* to the *j*-th word whenever *T* = 1. Further, both parties derive the values *T;T* for the next level using the correction bits. In the last level, each party additionally inputs the sum of all nodes, from which the final correction word CW can be derived.

Working Over a Ring Instead of a Field. Although we described the above protocol only over finite fields, note that it can in fact be adapted to work over Z*q*for any *q 2* N.

### 5.3 Malicious DPF Key Generation

We now turn focus to malicious adversaries. When transferring the protocol of Doerner and shelat to the malicious setting, one runs into the following problem: In order to achieve a practically efficient protocol, the evaluation of the PRG has to take place locally, i.e. outside any secure evaluation. But this would allow a malicious adversary to provide inconsistent key shares during key generation. Previous works [BCG + 19a,YWL + 20] solve this issue at very low cost for the simpler setting of puncturable pseudorandom functions, where one party is in knowledge of the position (say *P₀*) and the other party in charge of setting up the key (say *P₁*). The idea is to introduce a consistency check that ensures that *P₁* behaved consistently *with respect to* the input value. As the check depends on the input value if *P₁* deviates from the protocol, party *P₁* can attempt guess partial information on. If *P₁* guesses correctly, it obtains (partial) leakage on. Otherwise, the protocol aborts.

In the notation of [Ds17, Fig. 1], whenever *j;* = *j;* 1, you can read off *j* by XORing *j;* with LSB( *j* ).

### Functionality Fc-SUV

Parameters: Length *D 2* N, and a prime modulus *p* Functionality: The functionality contains the same Input, Add, Mult and Output commands as *F*2-PC, as well as the following command.

SUV: On input J K F log *D* and J KF*q*: 2 If both parties are honest:

1.If = 0 output “ = 0” to both parties and abort.
$*D*

2.Sample *~y₀* F*q*, and let *~y₁* (0*;:::;*0*;;:::;* 0) *~y₀*, where is in position (parsed as integer).
3.Output *~y* to party *P*, for *2f*0*;* 1*g*
### If party P is corrupted:

1. Allow the adversary to determine its output shares. Wait for input *~y 2* F
*D* *q*from the adversary. log*D*

2. Allow the adversary an arbitrary guess on. Wait for input *P* : F₂*!f*0*;* 1*g*. If *P* () = 0, abort.
3.If = 0 output “ = 0” to both parties and abort.
4.Set *~y₁* (0*;:::;*0*;;:::;* 0) *~y 2* F
*D* *q*, where is in position (parsed as integer).

<u>5.Output (success) to the adversary and ~y₁ to the honest party.</u>
Figure 5: Functionality for the malicious distributed setup of a scaled unit vector
 We show how to achieve the same in the more general setting of distributed point functions.
We do this using a new consistency check for verifying the DPF keys were computed correctly. This check, which is inspired by [YWL + 20], has a similar leakage profile to previous approaches for puncturable PRFs. 8 Compared with the semi-honest protocol, we need a small extra over- head, dominated by two maliciously secure 2-PC multiplications and one inversion in F*q*, as well as around twice as many PRG evaluations as in the semi-honest case. In Figure 5 we outline the achieved functionality. Note that this is weaker than the func- tionality for securely generating keys of a distributed point function for two reasons:

- For the reason elaborated on above, it allows some leakage on the noise. In the setting of noise generation for LPN, this leakage is tolerable for the following reason: The more the adversary attempts to guess, the higher the probability the protocol aborts, resulting in a leakage of only 1 bit on average. Intuitively, this can be accounted for by slightly increasing the noise rate.
- It gives out additive secret shares of the output (instead of the DPF keys), where the adversary is given full control over its share of the input. To make the resulting restriction to polynomial-size output explicit, we refer to the functionality as a setup functionality for a *shared unit vector*. Note that combined with our PCGs, this allows implementing the corruptible OLE functionality (Fig. 9) and the corruptible functionality for generating The original version of this paper used a hash-based consistency check similar to [BCG
+ 19a], however, as observed by Damiano Abram, that check was not sufficient in this setting.

authenticated multiplication triples (Fig. 11), where the adversary is also given control over its share of the output.

Intuition for the Protocol (Fig. 6). The protocol uses the malicious 2-PC functionality *F*ext-2-PC(Fig. 3), and requires that is stored in *F*ext-2-PCbitwise, while is stored as an element of F*q*. Next, it starts by running the semi-honest setup protocol, with the difference that in the secure computation used to compute the correction words CW *i*, we rely on *F*ext-2-PC to ensure that the correct bits of are being used. Apart from this, the secure computation stage is only semi-honest: the PassiveOutput command of *F*ext-2-PCallows corrupt parties to incorrectly open a shared value, while MixedMult only enforces that the bit*i*is correct, and not the string it is multiplied with. The correction words computed in this first stage correspond to a random payload *0*. Before switching this to, we perform a consistency check. The parties sample (via coin-tossing) random values *r⁰;:::;r* *D* 1 *2* F*q*, and use these to compute a linear combination of the DPF outputs. The result (which is secret-shared) should equal *r* *0*. To check this, the parties take an additional *D* outputs of the DPF (by extending the depth of the tree by one), with associated random payload CW *R*, and take the same linear combination, scaled by (CW *R* ) 1, and multiply the result with *0* (which has been stored in *F*2-PC). The parties then use *F*2-PCto verify that these two values are equal. The idea of the check is that the only way a corrupt party can cheat is by guessing *0*, which is random in a large field F*q*, or by guessing (a few bits of), which is allowed by the leakage in the functionality. If the check goes through, the parties finally correct the DPF payload to instead of *0*, by outputting the relevant correction value CW *L* = *=* *0*.

Remark 5.2 *Note that one can use the functionality F*c-SUV*with larger output spaces* F *‘q* *, by* *running the same functionality over* F*q‘ and embedding* F *‘q* *vectors into that field. Alternatively,* *if q is already large enough for security, a slightly more efficient solution can be obtained by* *tweaking the protocol as follows. Choose a PRG with larger output length* (*f*0*;* 1*g*) *‘*+1 *on the last* *level, compute a correction word* CW *L* *ifor each i 2* [*‘*]*, and check consistency for each component* *L;i L* *individually. More precisely, for each i 2* [*‘*]*, compute S similarly to S in Fig. 6, using the* *additional PRG outputs, and check that* *0* *S* *R* *S* *L;i* = 0 *as required.*

In the following, we prove that our protocolc-SUV(see Fig. 6) realizes the functionality *F*c-SUV(Fig. 5) for generating additive secret shares of a scaled unit vector with security against malicious adversaries.

Theorem 5.1 *If* PRG : *f*0*;* 1*g!f*0*;* 1*g²* +2 *is a secure PRG, then the protocol*c-SUV*(Fig.*

*6) implements the functionality F*c-SUV*(Fig. 5) with security against malicious adversaries in* *the* (*F*ext-2-PC*; F*coin)*-hybrid model.* *Proof.* We first consider the case that both parties are honest, before giving a simulator for the case that one party is corrupt. Both parties are honest. We have to show that the outputs in a real execution of the
$*D* protocol are indistinguishable from the outputs of the ideal functionality (i.e. *~y₀* F*q*, *~y₁* (0*;:::;;:::;* 0) *~y₀*, where is in position), even to an adversary seeing all communication over the network. *j j* *Correctness.* We have to prove that indeed *y₀* + *y₁* = 0 for all *j 6*= and *y₀* + *y₁* =. In particular, we have to show that in an honest execution the protocol does not abort. We proceed in a number of steps.

### Protocolc-SUV(Part I)

Parameters:

- Security parameter 1; output length *D* = 2
*k*; finite field F*q*(where log*q* is a statistical security parameter)

- PRG : *f*0*;* 1*g!f*0*;* 1*g²*
+2, a pseudorandom generator

- ConvertF*q*: *f*0*;* 1*g!* F*q*, maps a pseudorandom bit string into an F*q*element
- Functionalities *F*ext-2-PC(Fig. 3) and *F*coin(coin-tossing)
Protocol: <u>The framed</u> parts are run in malicious 2-PC (using commands from *F*ext-2-PC).

Inputs:

- The parties holds a position J K
F log *D* and a payload J KF*q*stored in *F*ext-2-PC. We 2 assume is shared bitwise, so for each bit*j*, for *j 2* [0*::* log*D*), party *P* holds*j;* with*j;*0+*j;*1=*j*.

Key Generation Phase: 0*;*0

1.For *2 f*0*;* 1*g* party *P* chooses a PRG seed *~s 2 f*0*;* 1*g* and computes 1*;*0 1*;*1 1*;*0 1*;*1 0*;*0 1*;*0 1*;*1 *~s k~s kt kt* := PRG(*~s*). Party *P* locally sets *T* := *T* :=, and 1*;*0 1*;*0 1*;*1 1*;*1 1*;*0 1*;*0 1*;*1 1*;*1 *~z* := *~s;~z* := *~s;u* := *t;u* := *t*.
2.For *i* = 1 to log*D*:
*i;b i;b i;b*

- For *b 2f*0*;* 1*g*: PassiveOutput(*u₀i;*0*;u₁i;*11 *b*) *i i i;*0 *i;*1 *i;*0 *i;*1 *i;*0 *i;*1

|) ;~y₁ (~y₀||~z₀ ;~z₁|~z₁; J|K )|(~z|+ ~z )|
|---|---|---|---|---|---|---|
|i||i;1 i|i;1||i|i;1|
||i||||||

- MixedMult(*~z₀i* F2// =*i*
*i*

- CW PassiveOutput(*~y₀ ~z₀;~y₁ ~z₁*) // CW = *~z*
- For *2f*0*;* 1*g*, *j 2* [0*::* 2), party *P* computes: – The next level of the GGM tree:
*~s* *i*+1*;*2*j* *k~s* *i*+1*;*2*j*+1 *kt* *i*+1*;*2*j* *kt* *i*+1*;*2*j*+1 := PRG(*~s* *i;j* *T* *i;j* CW *i* )

– If *i <* log*D*, the sums of the left/right leaves and left/right correction bits, for *b 2f*0*;* 1*g*:

2 M *i*1 2 M *i*1 *~z* *i*+1*;b* := *~s* *i*+1*;*2*j*+*b* *; u* *i*+1*;b* := *t* *i*+1*;*2*j*+*b* *;* *j*=0 *j*=0

– If *i <* log*D*, the next level of choice bits:

*T* *i*+1*;*2*j* := *t* *i*+1*;*2*j* *T* *i;j i;*Parity(j) *; T* *i*+1*;*2*j*+1 := *t* *i*+1*;*2*j*+1 *T* *i;j i;*Parity(j)

3.Convert the output shares to F*q*: *P* computes:
*D D*

|||X¹||X¹|||
|---|---|---|---|---|---|---|
|||L j=0|j;L|R j=0|j;R||
|j;L|log D+1;2j F||j;R||log D+1;2j+1 F||

*z* *L* := *s* *j;L* *; z* *R* := *s* *j;R*

where *s* = Convert*q*(*~s*) and *s* = Convert*q*(*~s*). *(to be continued)*

Figure 6: Protocol for the malicious distributed setup of scaled unit vectors (Part I)

### Protocolc-SUV(Part II)

Key Generation Phase: *(continued)*

4.Correct the offset of the left leaves to and the offset of the right leaves to 0:

||L|F||L R F||
|---|---|---|---|---|---|
|0 p|L F|L F||||
|L F|0 F 1 R|F|R F R F|R F|R F|

- For *2f*0*;* 1*g*: J*z* K*q*Input(*P;z*)*;* J*z* K*q*Input(*P;z*
*R* )

- J K J*z₀* K*q*J*z₁* K*q*
- JCW K*q*J K
*q* J K*q*, JCW K*q*J*z₀* K*q*J*z₁* K*q*

- Output CW Output(JCW K*q*) to both parties.
Verification Phase:

6.To verify that the sender behaved consistently and the output unit vector has the correct payload, the parties proceed as follows:
- The parties call *F*cointo obtain public random values *r⁰;:::;r*
*D* 1 *2* F*q*.

- Each *P* computes
*D D*

|X¹||X¹||
|---|---|---|---|
|j|j;L|R 1|j j;R|
|j=0||j=0||

*S* *L* = ( 1) *r* *j* *s* *j;L* *; S* *R* = ( 1) (CW *R* ) 1 *r* *j* *s* *j;R*

7.The parties check if the check values where computed correctly:

||L F||L R|F||R|
|---|---|---|---|---|---|---|
|F|0 F|R F|R F|L F|L F||
||F||||||
|L||L F|||L||
|||j|j;L|L|D||

- For *2f*0*;* 1*g*: J*S* K*q*Input(*P;S*), J*S* K*q*Input(*P;S*)
- Compute J*Z*K*q*= J K*q*(J*S₀* K*q*+ J*S₁* K*q*) J*S₀* K*q*J*S₁* K*q*.
- If *Z* Output(J*Z*K*q*) does not equal 0, abort.
Output Phase:

1.Output CW Output(JCW K*q*) to both parties. If CW = 0, abort.
8.Finally, if all checks passed, party *P* outputs *~y* = (*y⁰;:::;y* 1), where
*y* := ( 1) *s* CW *:*

Figure 6: Protocol for the malicious distributed setup of scaled unit vectors (Part II)

Claim 5.3 *If the parties follow the protocol description honestly, then all i 2* [0*::* log*D*) *and*

||i|i;j|||
|---|---|---|---|---|
|i|||||
|i+1;2j+b|i||j +b|j +b|
|||i|||

*i i;j i;j i;j i* *j 2* [0*::*)*nf j g we have ~s₀ T₀* CW = *~s₁ T₁* CW*. Further, for the correction bits we have* *i*+1*; j*+*b i*+1*;ii*+1*;i* *T₀* = *T₁ for all j 2* [0*::*)*nf j g;b 2f; g, as well as T₀* = *T₁* *for b 2f*0*;* 1*g.*

We omit the proof of this claim, which closely follows from [BGI16b].

Claim 5.4 *After an honest execution of the protocol party P holds output* (*y⁰;:::;y* *D* 1 )*, such* *j j* *that y₀* + *y₁* = 0 *for all j 6*=*, and y₀* + *y₁* =*.*

*Proof.* For all *j 6*=, by Claim 5.3 we have log*D* 1*;j* log*D* 1*;j D* 1 log*D* 1*;j* log*D* 1*;j D* 1 *~s T* CW = *~s₁ T₁* CW*;*

log *D;*2*j* log *D;*2*j j;L j;L j j j L j* and thus *~s₀* = *~s₁*. This implies *s₀* = *s₁*, and thus *y₀* + *y₁* = *s₀;L* CW *s₁;L* CW *L* = 0 Further, we have *D* X¹ *D* X¹ *L L j;L j;L;L;L* *z₀ z₁* = *s₀ s₁* = *s₀ s₁* *j*=0 *j*=1 *;L L;L L;L;L;L;L* 1 and thus *y₀* + *y₁* = *s₀* CW *s₁* CW = (*s₀ s₁*) (*s₀ s₁*) =.

Claim 5.5 *If 6*= 0*, then in an honest execution the protocol does not abort with overwhelming* *probability.*

*Proof.* First, note that *6*= 0 implies that CW *L* *6*= 0. Further, by the same reasoning as above, log *D;*2*j*+1 log *D;*2*j*+1 *j;R j;R*

5.3 yields *~s₀* = *~s₁*, and thus *s₀* = *s₁*, for all *j 2* [0*::D*)*nf g*. This implies *R R R;R;R* CW = *z₀ z₁* = *s₀ s₁*. This implies
*D* X¹ *R R R* 1 *j j;R j;R* *S₀* + *S₁* = (CW) *r* (*s₀ s₁*) *j*=0 *;R;R* 1*;R;R* = (*s₀ s₁*) *r* (*s₀ s₁*) = *r :*

Further, we have

*D* X¹ *L L j j;L j;L* *S₀* + *S₁* = *r* (*s₀ s₁*) *j*=0 *;L;L* = *r* (*s₀ s₁*) = *r* *0*

which yields *Z* = 0 as required.

*Security.* It is left to show that *~y* is distributed uniformly for each *2f*0*;* 1*g* individually, even given access to all communication between *P₀* and *P₁*. As an honest execution of our pro- tocol is very similar to an execution of the original protocol of Doerner and shelat (instantiated with the DPF of [BGI16b]), in the following we only give a proof sketch. Note that even condi- tioned on all correction words and correction bits revealed during the protocol, i.e. CW *i* *;* *i;*0 *;* *i;*1 for all *i 2* [0*::D*) and CW *R*, it holds that *~y* is distributed uniformly at random, because each of the correction values is blinded by an output of the PRG, where the input is known only to *P₁* (and in particular not revealed during the protocol execution). Further, if = 0, the same holds true conditioned on CW *L*. Finally, note that the only value that an adversary sees in the verification step of an honest execution is a 0, therefore security follows.

Party *P* is corrupted. We now proceed to the case that one party is corrupted. We start by giving an intuition for the proof. In the simulation, all the correction values *i;b* *;*CW *i*, and the right correction word CW *R*, will be simulated using random values. In the consistency check, the simulator needs to extract a guess on *2* [*D*] made by the potentially cheating adversary. Since the simulator does not know, it will define, for each *2* [*D*], a simulated “honest view” that is consistent with = and the adversary’s view so far. Using the *S* *L* *;S* *R* values provided by the adversary, the simulator then defines the predicate *P* (), which is 1 if the adversary’s behaviour is consistent with the simulated honest view based on. It queries this guess to the functionality, if the guess is successful, the consistency check passes. The simulator can then use a consistent value of to extract a valid output vector that is known by the adversary. In the proof, we show that due to the random linear combination, every that satisfies *P* () = 1 will lead to the same extracted output, so the simulation is consistent with the real protocol. The simulator proceeds as follows.

Key generation phase: • For *i 2* [1*::* log*D*] : *i;b i;b* – The simulator sends a random 1 *2f*0*;* 1*g* to *P*, and waits to receive, then *i;b i;b i;b*

|defines|=|.|||||
|---|---|---|---|---|---|---|
||0|1|||||
||||i||||
||||||i||
||||||i|i1 i|
|i0|i1||L R|q|||
|R q||||L|||

0 1 – Next, the simulator awaits input *~v 2f*0*;* 1*g* to MixedMult from the adversary, as well as the adversary to input *P* ’s output share *~y 2f*0*;* 1*g*. – Next, to simulate PassiveOutput the simulator sends a random CW *2* *f*0*;* 1*g* to the adversary, then waits to receive CW *2f*0*;* 1*g*, and sets CW := CW CW.

- Now, the simulator awaits input *z;z 2* F from the adversary and returns a random CW F. It also samples a random CW F*q*.
- Finally, for each *2* [0*::D*) (corresponding to all possible values of) the simulator computes the output of the honest party *P₁* that is compatible with the correction values and correction bits as sampled above.
1*;*11 – The simulator sets *T₁* *;* := 1. – For *i 2* [1*::* log*D*]: *i;b i;b* ∗ For *b 2f*0*;* 1*g*, the simulator sets *u₁*

|||;|1|i i;|
|---|---|---|---|---|
|i|i;1;|i 1;1;|i i 1;1;|i|

*;* := 1 *i i;*

(1) (1 *b*).
∗ The simulator sets *i* *~z₁* := CW₁ *~y ~v :*

1 1 – For the first level, the simulator sets *~s₁* := *~z₁*. – For *i 2* [1*::* log*D*] : ∗ For *j 2* [0*::* 2), the simulator computes: · The next level of the GGM tree:

*i*+1*;*2*j i*+1*;*2*j*+1 *i*+1*;*2*j i*+1*;*2*j*+1 *i;j i;j i*

|~s₁|k~s₁|kt₁ kt₁||:= PRG(~s₁||T₁ CW ) if j 6=||:|
|---|---|---|---|---|---|---|---|---|
|;|;|;|;||;|;||i|
||||||||i+1;1||
||||||||;||
|i+1;0|i+1;1||||||||
|;|;||i+1;j|+;||i|i 1 j=0 j|j|

*;;;;;; i* *i*+1 · Next, if *i <* log*D* the simulator uses the pre-computed values *~z₁*, *u₁;u₁* to compute the missing part of the GGM tree – except for *i i*+1 P the seed value *on the-path*, *~s₁* (where by *j* = 2 we denote the *i*-bit prefix of parsed as a natural number), since we do not need this value to continue. Instead, the already chosen correction word of the next level (together with the other leave values) will implicitly define it. M *i* *i*+1*; ji*+1*i*+1*i*+1*;i*+1*i*+1*; j*+1*i*+1

|i+1;2 j +1|i+1;1||i+1;2j+1|
|---|---|---|---|
|;|;|j=0;j6= j|;|

*~s₁* := *~z₁ ~s₁;* *i*

as well as M *i* *i*+1*; ji*+*b i*+1*;b i*+1*; j*+*b*

|i+1;2 j +b|i+1;b||i+1;2j+b|
|---|---|---|---|
|;|;|j=0;j6= j|;|

*t₁* := *u₁ t₁ :* *i* · Further, if *i <* log*D*, the simulator computes the next level of choice bits:

*i*+1*;*2*j i*+1*;*2*j i;j i;*Parity(j) *i*+1*;*2*j*+1 *i*+1*;*2*j*+1 *i;j i;*Parity(j) *T₁* *;* := *t₁* *;* *T₁* *;* *; T₁* *;* := *t₁* *;* *T₁* *;*

- Note that the simulator cannot compute the honest party’s output shares at position, since this would require knowledge of. However, the simulator can compute the output share of the dishonest party *P*, such that it is consistent with the shares of *P₁* (conditioned on =).
*D D*

|||X¹|||X¹||||
|---|---|---|---|---|---|---|---|---|
||;L;|L j=0;j6=|j;L;|;R;|R j=0;j6=|j;R;|||
|j;L||log D+1;2j|j;R||log D+1;2j+1||||
|;|F|; coin|;|L|F; R||D 1|q|

*s* *;L* := *z* *L* *s* *j;L* *; s* *;R* := *z* *R* *s* *j;R*

where *s* = Convert*q*(*~s₁*) and *s* = Convert*q*(*~s₁*) for *j 6*=.

Verification phase: • To simulate *F*, the simulator sends random *r⁰;:::;r 2* F.

- Further, the simulator receives the “real” inputs *S;S* by the adversary.
- Next, for each *2* [0*::D*) the simulator computes
*D D*

||X¹|||X¹||
|---|---|---|---|---|---|
|L|j|j;L|R|R 1|j j;R|
|;|j=0|;|;|j=0|;|

*S* *L* = ( 1) *r* *j* *s* *j;L* *; S* *R* = ( 1) (CW *R* ) 1 *r* *j* *s* *j;R*

- For all *j 2* [0*::D*) the simulator further computes the (potential) output as
*y;* *j* := ( 1) *s* *j;* *;L* CW *L* *:*

- To extract the adversary’s potential guess on, the simulator defines the predicate

|log D|L|L R|
|---|---|---|
||;|;|
|? ?|; 0|; D 1|

*R* *P* : F₂ :*!f*0*;* 1*g;P*() = 1*, S* = *S ^ S* = *S;*

picks a *?* with *P* () = 1 and inputs *~y;?* = (*y?;:::;y?*) and *P* to the func- tionality. If such a does not exist, the simulator sends *~y* = 0 and *P* = 0 to the functionality. – If the functionality aborts, then the simulator receives and sends to the adver- sary a random *Z 2* F*q*and aborts. – Else, the simulator outputs *Z* = 0 to the adversary. It also learns from the functionality whether or not = 0.

Output phase. Finally, we simulate the opening of the correction word CW *L*. If = 0, the simulator outputs 0 and aborts. Else, it sends CW *L* as sampled before.

It is left to show that the simulation is indistinguishable from a real protocol execution. To this end, we first switch the real protocol distribution to a randomized distribution (Lemma 5.6), and then show that the simulation is statistically indistinguishable from the randomized distri- bution (Lemma 5.7).

Hybrid 1: Real behaviour of the honest party: We start by describing the honest party’s behavior in a real execution, when the protocol is run with input.

*;* Key generation phase:

|• Party P₁||chooses a PRG seed ~s₁||2f0; 1g|and com-|
|---|---|---|---|---|---|
|1;1 1;0|1;1|0;0|||1;0|
|1;0|1;0|1;1|1;1|1;0|1;1|

*;* putes *~s₁ k~s₁ kt₁ kt₁* := PRG(*~s₁*). Party *P₁* locally sets *T₁* := *;;;* *T₁* := 1, and *~z₁* := *~s₁;~z₁* := *~s₁;u₁* := *t₁;u₁* := *t₁*.

- For *i* = [1*::* log*D*] :
*i;b i;b* – For *b 2 f*0*;* 1*g*,

||P₁ sends|:=|
|---|---|---|
|||i;b|
|i;0|i;1||
|i i|i;1||

1 *u₁i;*1(1) (1 *b*) to PassiveOutput and receives *i;b*. *i* – *P₁* sends *~z₁ ~z₁* to MixedMult and receives *~y₁*. *i* – *P₁* sends *~y₁ ~z₁* to PassiveOutput and receives CW. – For *j 2* [0*::* 2), party *P₁* computes: ∗ The next level of the GGM tree:

*i*+1*;*2*j i*+1*;*2*j*+1 *i*+1*;*2*j i*+1*;*2*j*+1 *i;j i;j i* *~s₁ k~s₁ kt₁ kt₁* := PRG(*~s₁ T₁* CW)

∗ The sums of the left/right leaves and left/right correction bits, for *b 2* *f*0*;* 1*g*:

2 M *i*1 2 M *i*1 *i*+1*;b i*+1*;*2*j*+*b i*+1*;b i*+1*;*2*j*+*b* *~z₁* := *~s₁; u₁* := *t₁;* *j*=0 *j*=0

∗ The next level of choice bits:

*i*+1*;*2*j i*+1*;*2*j i;j i;*Parity(j) *i*+1*;*2*j*+1 *i*+1*;*2*j*+1 *i;j i;*Parity(j) *T₁* := *t₁ T₁; T₁* := *t₁ T₁*

- Convert the output shares to F*q*: *P₁* computes:
*D D*

||X¹|||X¹|||
|---|---|---|---|---|---|---|
|L|j=0|j;L|R|j=0|j;R||
|log D+1;2j|||j;R|||log D+1;2j+1|
|F|||||F||
|L||R|||||
||R|coin|||D|1|

*L j;L R j;R* *z₁* := *s₁; z₁* := *s₁*

*j;L* where *s₁* = Convert*q*(*~s₁*) and *s₁* = Convert*q*(*~s₁*).

- Correct the offset of the left leaves to and the offset of the right leaves to 0: – Party *P₁* sends *~z₁* and *~z₁* to Input. – Party *P₁* receives CW.
Verification Phase: • The parties call *F* to obtain *r⁰;:::;r 2* F*q*.

- Party *P₁* computes
*D D*

|X¹||X¹||
|---|---|---|---|
|1|j j;L|R 1|j j;R|
|j=0||j=0||
|L|R|||

*L* 1 *j j;L R* 1 *R* 1 *j j;R* *S₁* = ( 1) *r s₁; S₁* = ( 1) (CW) *r s₁*

- Party *P₁* inputs *S₁;S₁* to Input. It receives *Z*. If *Z 6*= 0, party *P₁* aborts.
Output Phase: • Party *P₁* receives CW *L*. If CW *L* = 0, the party aborts.

- Finally, if all checks passed, party *P₁* outputs *~y₁* = (*y₁₀;:::;y₁*
*D*

1),
where *j* 1 *j;L L* *y₁* := ( 1) *s₁* CW *:*

Hybrid 2: Randomized behaviour of the honest party. We now describe the honest party’s behaviour, where we replace calls to PRG by random values whenever the seed is not known by the adversarial party *P*. Changes to the first hybrid are framed.

$

||1;0|1;1 1;0|1;1|2 +2|
|---|---|---|---|---|
|1;0 1;1|1;1||1;0|1;0 1;1|

Key generation phase: • Party *P₁* <u>chooses ~s₁ k~s₁ kt₁ kt₁ f; g</u> at

random. Party *P₁* locally sets *T₁* := *T₁* := 1, and *~z₁* := *~s₁;~z₁* := *;;;;* *~s₁;u₁* := *t₁;u₁* := *t₁*.

- For *i* = [1*::* log*D*] :
*i;b i;b* – For *b 2 f*0*;* 1*g*,

||P₁ sends|:=|
|---|---|---|
|||i;b|
|i;0|i;1||
|i i|i;1||

1 *u₁i;*1(1) (1 *b*) to PassiveOutput and receives *i;b*. *i* – *P₁* sends *~z₁ ~z₁* to MixedMult and receives *~y₁*. *i* – *P₁* sends *~y₁ ~z₁* to PassiveOutput and receives CW. – For *j 2* [0*::* 2), party *P₁* computes: ∗ The next level of the GGM tree:

8 < $

|2 +2||
|---|---|
|i;j|i;j|
|1|1|

*i*+1*;*2*j i*+1*;*2*j*+1 *i*+1*;*2*j i*+1*;*2*j*+1 <u>f 0; 1g if j = ji</u> *~s₁ k~s₁ kt₁ kt₁* ::= PRG( *~s T* CW *i* ) else

∗ The sums of the left/right leaves and left/right correction bits, for *b 2* *f*0*;* 1*g*:

2 M *i*1 2 M *i*1 *i*+1*;b i*+1*;*2*j*+*b i*+1*;b i*+1*;*2*j*+*b* *~z₁* := *~s₁; u₁* := *t₁;* *j*=0 *j*=0 ∗ The next level of choice bits:

*i*+1*;*2*j i*+1*;*2*j i;j i;*Parity(j) *i*+1*;*2*j*+1 *i*+1*;*2*j*+1 *i;j i;*Parity(j) *T₁* := *t₁ T₁; T₁* := *t₁ T₁*

- Convert the output shares to F*q*: *P₁* computes:
*D D*

|||X¹||X¹||||
|---|---|---|---|---|---|---|---|
||L|j;L j=0|R|j;R j=0||||
|j;L|log D+1;2j F L|R|j;R|F|log D+1;2j+1|||
||R|coin|||D 1|q||

*L j;L R j;R* *z₁* := *s₁; z₁* := *s₁*

where *s₁* = Convert*q*(*~s₁*) and *s₁* = Convert*q*(*~s₁*).

- Correct the offset of the left leaves to and the offset of the right leaves to 0: – Party *P₁* sends *~z₁* and *~z₁* to Input. – Party *P₁* receives CW.
Verification Phase: • The parties call *F* to obtain *r⁰;:::;r 2* F.

- Party *P₁* computes
*D D*

|X¹|||||X¹||
|---|---|---|---|---|---|---|
|1|j j;L|R|1||R 1|j j;R|
|j=0|||||j=0||
|L|R|L|L||||
||j|1|j;L|L||D|

*L* 1 *j j;L R* 1 *R* 1 *j j;R* *S₁* = ( 1) *r s₁; S₁* = ( 1) (CW) *r s₁*

- Party *P₁* inputs *S₁;S₁* to Input. It receives *Z*. If *Z 6*= 0, party *P₁* aborts.
Output Phase: • Party *P₁* receives CW. If CW = 0, the party aborts.

- Finally, if all checks passed, party *P₁* outputs *~y₁* = (*y₁₀;:::;y₁* 1), where
*y₁* := ( 1) *s₁* CW *:*

We omit the proof of the following lemma here and refer to [BGI16b], since the changes only concern the underlying DPF protocol.

Lemma 5.6 *If* PRG : *f; g! f; g²* +2 *is a secure PRG, then the real behaviour and the* *randomized behaviour of P₁ are indistinguishable to an adversary controlling P.*

Lemma 5.7 *Assume q* = *q*() = *!*(1) *. Then, the distribution generated by the simulator is* *statistically indistinguishable from the randomized protocol execution as described in Hybrid 2.*

*Proof.* Assume to be given the real *2* [0*::D*)*; 2* F*q*. First, note that we can assume that for CW *L* as sampled by the simulator it holds that CW *L* *6*= 0, since this holds except with probability 1*=q*. Further, we assume that for *0* as generated in the randomized protocol execution, it holds *0* *6*= 0, which is also true except with probability 1*=q*. log*D*+1*;*2*j* log*D*+1*;*2*j*+1 We begin the proof by showing that the values *~s₁* *;* and *~s₁* *;* for *j 6*= are *perfectly* indistinguishable from those generated in a real protocol execution with randomized behaviour of *P₁*. 1*;*111*;*1

- First, we have *T₁*
*;* = 1 = *T₁*.

1*;b* 1*;b*

- Next, recall that for *b 2f*0*;* 1*g* the simulator sets *u₁*

||||;|1|1 1;|
|---|---|---|---|---|---|
|1;b||||||
|1||||||
|||i;b 1|1;1|||

*;* := 1 1 1*;*

(1) (1 *b*),
1*;b* where is chosen uniformly at random from *f*0*;* 1*g*. This is equivalent to choosing *u₁* *i;b* uniformly at random and setting := *u₁* (1) (1 *b*), as done in the randomized protocol execution.

- Further, recall that the simulator sets
*i* 1

|1;1|1|1|
|---|---|---|
|;|1||

*~z₁* := CW₁ *~y ~v;*

where *~v¹ 2 f*0*;* 1*g* is the adversary’s input to MixedMult and *~y¹ 2 f*0*;* 1*g* is the adversary’s output share for *P*. Note that in a randomized execution of the protocol, it 1*;*1 1*;*1

|1|1|1|1 1;0|
|---|---|---|---|
|1;1|1 1|1 1|1;1|

holds CW₁ = *~y₁₁ ~z₁;* where *~y ~y₁₁* = (*~v ~z₁ ~z₁*). This yields

1 CW₁ = *~y ~v ~z₁;*

1 where *~z₁* is sampled uniformly at random. Thus, as above we obtain that the simu- lation is perfectly indistinguishable from the randomized protocol execution.

||i+1|i+1;0 i+1;1||i+1;1|
|---|---|---|---|---|
|||||;|
|i+1;b|i+1;2 j +1|i+1;2 j|i+1;2 j +1||
|;|; log D+1;2j;|; log D+1;2j+1;|;||

*i*

- For *i 2* [1*::* log*D*], observe that again sampling CW*;;* (and thus *~z₁*
*i i*+1 *i i* and *u₁*) and then defining the missing *~s₁*, *t₁*, *t₁* is indistin- guishable to the randomized protocol execution, where *P₁* proceeds vice versa.

With the above considerations, we obtain that *~s₁* and *~s₁* for *j 6*= are indistinguishable from those generated in a randomized protocol execution as required. *;L;R* Next, we compute the values *s₁;s₁*, as would be computed in a randomized protocol execution (conditioned on *6*= 0), and show that the simulator outputs *Z* = 0 if and only if the randomized execution outputs *Z* = 0, except with negligible probability (corresponding to the event that the adversary successfully guessed *0* ).

- Recall that *z*
*L* *;z* *R* are the values sent to Input by the adversary. In a randomized protocol execution we would have

( 1) *z* *L* + ( 1) 1 *z₁* *L* = *0* *;*

and thus *z₁* *L* = ( 1) 1 *0* + *z* *L* *;*

as well as *z₁* *R* = ( 1) CW *R* + *z* *R* *:*

### This yields

*D D*

|||X¹||X¹|
|---|---|---|---|---|
||;L L|j=0;j6=|j;L ;R|R j=0;j6=|
|j;L|log D+1;2j F||j;R|log D+1;2j+1 F|
|L|R L;|R;|||
|L|L;|1 1|;L L|;L; L|
|||1|1|L|
|||0|||

*;L L j;L;R R j;R* *s₁* = *z₁ s₁; s₁* = *z₁ s₁*

where *s₁* = Convert*q*(*~s₁*) and *s₁* = Convert*q*(*~s₁*) for *j 6*=.

- Let now *S₁*, *S₁* be the values as computed by the honest party in a randomized protocol execution, and *S*, *S* the values computed by the simulator. Then, we have
*S₁* + *S* = ( 1) *r s₁* + ( 1) *r s*

= ( 1) *r z₁* + ( 1) *r z*

= ( 1) *r* (( 1) *0* + *z*) + ( 1) *r z* *L*

= *r*

and *R R* 1 *R* 1*;R R* 1*;R* *S₁* + *S;*= ( 1) (CW) *r s₁* + ( 1) (CW) *r s;*

### = r :

We thus have that the randomized protocol execution outputs *Z* = 0 if and only if

|L; L|R;|0|
|---|---|---|
|0||0|

*S* = *S* and *S* = *S*, unless the adversary successfully guessed. Since *0* is distributed perfectly uniformly at random from the adversary’s point of view in the ran- domized protocol execution at this point (since it didn’t yet learn CW *L* ), this only happens with probability 1*=q*. Further, if the simulator aborts and the adversary did not success- fully guess, it perfectly simulates the distribution of *Z*, since again is distributed uniformly at random.

It is left to show that the output of the honest party induced by the simulation is indistin- guishable from the output of the honest party in the randomized protocol execution. To that end, we have to show that

1. *~y;*+ *~y₁* = (0*;:::;*0*;;:::;* 0), where *~y;*is as computed by the simulator and *~y₁* is the value computed in the randomized protocol execution, and
2. *~y;*= *~y;*for all with *P* (
*?*

) = 1.
### This can be proven as follows.

1.By the above considerations we have

|j j|j;L L|1 j;L|
|---|---|---|
|;|;||

*L* *y* + *y₁* = ( 1) *s* CW + ( 1) *s₁* CW = 0

for all *j 6*=. Further, we have *;L L* 1*;L L*

|s|CW + (|1)|s₁|CW|
|---|---|---|---|---|
|L L|L|1|L|L|

*y;*+ *y₁* = ( 1)*;*

= ( 1) *z* *L* CW *L* + ( 1) 1 *z₁* *L* CW *L*

= *0* CW =*;*

### which yields the required.

2.Since *r⁰;:::;r*
*D* 1 are sampled at random over F*q*, independently of the rest of the protocol *L L L L j;L j;L* execution, we have that if *S₁;?* = *S₁;*and *S₁;?* = *S₁;*, then *s;*= *s;*for all *j 2* [0*::D*), except with negligible probability. This concludes the proof.

### Functionality FOLE-Setup

Parameters: Security parameter 1, PCGOLE= (PCGOLE*:* Gen*;*PCGOLE*:* Expand) as per Fig- ure 1. Functionality:

1.Sample (k₀*;*k₁) PCGOLE*:* Gen(1 )*:*
<u>2.Output k to party P, for 2f0; 1g</u>
Figure 7: Generic functionality for the distributed setup of OLE PCG seeds

## 6 PCG Setup Protocols

In this section, we present the complete secure two-party setup protocols for our PCGs based on module-LPN, using the protocols from the previous section as building blocks. In Section 6.1, we show how to securely realize (against a semi-honest adversary) the randomized functionality *F*OLE-Setupthat executes the seed generation for our PCG construction PCGOLEfrom Section 4, and outputs the corresponding PCG seeds to each party. This can in turn be used to realize a functionality for the secure generation of OLE correlations, by having the parties simply expand their received PCG seeds locally. For the malicious case, we do not directly realize the PCG seed generation functionality, which would be much more challenging. Instead, we realize the random OLE generation func- tionality *F*mal-OLE, in which a corrupt adversary can choose his output (*x;z*) *2 Rp* 2 and the honest party receives a random consistent value (*x₁;z₁*), i.e. for which *z₀* +*z₁* = *x₀ x₁* (or the parties receive a random sample from the correlation given honest behavior; see Figure 9 for full description). As discussed in [BCG + 19b], such a protocol can *directly* serve as a substitute for ideal OLE correlations in a wide range of higher-level applications, already proven to remain secure given this functionality. More precisely, in Section 5.3, we address both the secure gen- eration of OLEs and authenticated multiplication triples in the presence of active adversaries, securely realizing the functionality *F*mal-tripleat little extra cost. Finally, in Section 6.3 we analyze the efficiency of our protocols. For concrete numbers, we refer to Table 3 in Section 9.2.

### 6.1 Semi-Honest Distributed Setup for OLE

We present a protocol for securely executing the seed-generation functionality *F*OLE-Setup(Fig- PCGOLERecall that in the

|ure 7) with respect to our PCG construction||from Section 4.|||
|---|---|---|---|---|
|OLE|c 1||i i 2|i2[0::c)|
|DPF|OLE-Setup|p|i j|q|
|OLE-Setup|||DPF||

PCGOLE*:* Gen procedure (see Figure 1), each party receives a succinct description (*A* *i* *;~b* *i* ) *i2*[0*::c*)of *t*-sparse “noise vectors” *e⁰;:::;e* each of length *N*, as well as a collection of (*ct*) distributed point function (DPF) keys as a compact representation of all possible products *e₀ e₁*. Note that the protocols works over the prime field F, rather than an extension field F (as in *F*). This is because the PCGs we use need to run over *Rp*for a prime *p*, to be useful for the case where *Rp*fully splits into linear factors (cf. Section 3.2).

Theorem 6.1 *The protocol (Fig. 8) securely realizes the OLE PCG seed functionality* *F (Fig. 7) with security against semi-honest adversaries in the* (*F*2-PC*; F*)*-hybrid* *model.*

*Proof.* Observe that the protocolOLE-Setupis directly a secure evaluation of the computation steps of *F*OLE-Setup(see description of PCGOLE*:* Gen as given in Figure 1 within Section 4), with the exception that the FSS key generation for the sum of point functions SPFSS*:* Gen(1*;A* *i*

ProtocolOLE-Setup

Parameters: Security parameter 1, natural number *N* = *k*, prime *p*, distributed point function DPF = (DPF*:* Gen*;*DPF*:* Eval) with domain [0*::* 2*N*) and range F*p*. Further, we assume access to the functionalities *F*2-PC(Fig. 3) and *F*DPF(Fig. 4). Protocol:

1.For *2 f*0*;* 1*g;i 2* [0*::c*), party *P* samples random vectors *A*
*i* [0*::N*) *t* (where each entry of *A* *i* is viewed as a length-log*N* bit-string) and *~b* *i* (F*p*) *t*. Note that as outlined in Figure 1, each pair *A* *i* *;~b* *i* defines a *t*-sparse polynomial *e* *i* *2 Rp*.

2.For *2f*0*;* 1*g;i 2* [0*::c*) and *k 2* [0*::t*):

|||i|
|---|---|---|
|i|i|i|
|F|p||
 //*P* inputs the *k*-th non-zero position and corresponding payload of *e*.
J*A* [*k*]K *‘* Input(*P;A* *i* [*k*]) and J*~b* [*k*]K Input(*P;~b* [*k*]) 2

3.For every *i;j 2* [0*::c*) and *k;l 2* [0*::t*) (in parallel) the parties do the following: *i;j i j i j*
(a) J *k;l* K F
*‘*+1 BitAdd(J*A₀*[*k*]KF*‘;* J*A₁*[*l*]KF*‘*) //Compute the *k* +*tl*-th position of *e₀ e₁*. 2 2 2 *i;j~bi~bj i j*

(b) J *k;l* K *p*Mult(J0[*k*]K*p;* J1[*l*]K*p*) //Compute the *k* + *tl*-th payload of *e₀ e₁*.
(c)For each *i;j 2* [0*::c*) and *k;l 2* [0*::t*), call *F*DPFwith domain size [0*::* 2*N*) on input *i;j i;j i;j* J *k;l* K F *‘*+1 and J
*k;l* K *p*, and let *K* *;k;l* denote the output to party *P*. 2 *i j* //Compute compressed additive secret shares of *e₀ e₁*.

*i;j i i*

4.Party *P* outputs k = (*K*
*;k;l* ) *i;j2*[0*::c*)*;k;l2*[0*::t*)*;* (*A;~b*)*i2*[0*::c*).

Figure 8: Distributed setup of PCG seeds for OLE in the (*F*2-PC*; F*DPF)-hybrid model, against semi-honest adver-

saries. J*x*KF*‘* 2 *;* J*x*K*p* denote additive shares of bit-strings or F*p* elements.

*j i~bj* *A₁;~b₀* 1 ) is instantiated directly by the DPF key generation for every individual nonzero component. As discussed in Section 2.2, this is a valid instantiation of SPFSS, and hence the claim holds.

### 6.2 PCG Setup Protocols with Malicious Security

Module-LPN with static leakage. The protocols in this section rely on a stronger variant of module-LPN, where the adversary is allowed to query (on average) one bit of information on the secret error vectors. We need to allow this, because of the leakage in the functionality *F*c-SUVused to generate DPF keys with malicious security. Note that this style of assumption with leakage is very similar to the assumption of standard LPN with static leakage as used in [HOSS18a,BCG + 19a].

Definition 6.2 (Module-LPN with static leakage) *Let Rp*= Z*p*[*X*]*=F*(*X*) *for some prime* *p and degree-N polynomial F*(*X*) *2* Z[*X*]*, and let c;t 2* N *with c* 2*. Let HWtbe the distribution* *over Rpthat is obtained via sampling t noise positions A* [0*::N*) *t* *as well as t payloads ~b* Z *tp* P *t* 1 *A*[*j*]

||t 1|A[j]||
|---|---|---|---|
||j=0|||
|c 1|c 1|t||

*uniformly at random, and outputting e*(*X*) := *~b*[*j*] *X. For b 2f*0*;* 1*g let Gb*() *be the* *following game:*

- *Let e₀;:::;e HWtand let A⁰;:::;A* [0*::N*) *be the corresponding positions of* *non-zero coefficients.*

- *Allow the adversary arbitrary guesses on the noise positions* before *seeing the* *module-LPN sample. The adversary A can make an arbitrary number of (adaptive)* *queries, each consisting of indices i 2* [0*::c*)*, k 2* [0*::c*) *and a predicate P* : [0*::N*)*!f; g.* *For each query, if P*(*A*
*i* [*k*]) = 0 *then abort, otherwise, send* (success) *to the adversary* *and continue.*

- *Set u₀* = *h~a;~ei* mod *F* (*X*)*, where ~e* = (*e₀;:::;ec* 1) *and draw u₁ Rpat random.*
- *Return ubto the adversary.*
*The R* *c* -LPN*p;t*problem with static leakage *for ~a 2 Rp* *c* *is hard if for any PPT adversary A, it* *holds that*

Pr[*A* *G*0() = 1] Pr[*A* *G*1() = 1] negl()

*where the probabilities are taken over e₀;:::;ec* 1 *HWtand the randomness of A.*

In the above, if the adversary was restricted to querying predicates that either take 1 on all values or 0 on at least half of the values (in other words: if the adversary attempts to guess some noise coordinate, the protocol will abort with probability at least 1*=*2), then we can reduce the ring LPN with static leakage and noise parameter *t* + to our basic ring LPN assumption with noise parameter *t*. The idea is that the adversary can attempt a guess on at most noise coordinates, where is a statistical security parameter, as otherwise the protocol will abort with probability *>* 1 2. This observation would allow to reduce security of a slight tweak of the protocolmal-OLE(Figure 10), where our protocolc-SUVis used to generate *random* instances of scaled unit vectors (which are derandomized subsequently), to the standard module-LPN assumption. This is due to the fact that if is random from the point of the view of the adversary, one can show that in the protocolc-SUVan adversary actually can only give a wildcard guess on, i.e. guess a subset of the bits, which corresponds to giving a predicate which takes 0 on at least half of the inputs. This said, we want to stress that the described reduction is very loose in the sense that even if the adversary only attempts to guess a single bit on the noise position, the reduction “gives up” the correspoding noise position completely. Indeed, for our concrete protocol, we conjecture that it’s not necessary to increase the noise rate in the presence of this limited leakage. For a more detailed discussion regarding attacks on ring LPN with static leakage, see Section 8.6.

Distributed generation of OLEs in the malicious setting. Building on the previous protocols, we now present our PCG protocol for generating OLE correlations with distributed setup (Fig. 10) and show that it securely implements the corruptible OLE functionality (Fig.

9) with security against malicious adversaries. Theorem 6.3 *Let Rp*= Z*p*[*X*]*=F*(*X*) *for some prime p and degree-N polynomial F* (*X*) *2* Z[*X*]*, and let c;t 2* N*. If the R*
*c* *-*LPN*p;tproblem with static leakage is hard, then the protocol* mal-OLE*(Fig. 10) implements the functionality F*mal*-*OLE*(Fig. 9) with security against malicious* *adversaries in the F*2-PC*; F*c-SUV*-hybrid model.*

*Proof.* We start with considering the case that both parties are honest.

Both parties are honest. Note that all communication of the parties is via ideal functionali- ties, so we only need to prove that the final output of a real protocol execution is indistinguishable from the output of the ideal functionality. P*i* *i*

||i|t 1 i|A [k]|p||
|---|---|---|---|---|---|
|i j||k=0||i|j|
|||||0|1|

For *2f; g*, let *e* (*X*) = *~b* [*k*] *X 2 R* be the noise polynomial defined by *A* *~bi~b ~bi j* and. Then, *e₀ e₁* is the polynomial with coefficient [*k*] [*l*] at position *A₀*[*k*] +*A₁*[*l*] for all

### Functionality Fmal-OLE

Parameters: Security parameter 1, modulus *p*, and the ring *Rp*= Z*p*[*X*]*=F*(*X*), where *F* (*X*) has degree *N*. Functionality: If both parties are honest:

1.Sample *x₀;x₁ Rp:*
$

2.Sample *z₀ Rp*, and let *z₁ x₀ x₁ z₀*.
3.Output (*x;z*) to party *P*, for *2f*0*;* 1*g*
### If party P is corrupted:

1.Wait for input (*x;z*) *2 Rp*
2 from the adversary.

2.Sample *x₁ Rp*and set *z₁ x₀ x₁ z*.
<u>3.Output (x₁;z₁) to the honest party.</u>
Figure 9: Corruptible OLE Functionality

||;i+cj ;i+cj|i j|
|---|---|---|
|c p;t|||

*i;j 2* [0*::c*) and *k;l 2* [0*::t*). Thus, by the properties of *F*c-SUV, it holds *g₀* +*g₁* = *e₀ e₁*, and therefore *x₀ x₁* = *z₀* + *z₁* as required. Finally, *R*-LPN implies the indistinguishability of (*x₀;x₁*)*;* (*z₀;z₁*) from an OLE triple generated at random similarly to the proof of Theorem 4.1.

Party *P* is corrupted. For the notation in the following we assume = 1, the case = 0 is obtained by switching (*i;k*) with (*j;l*). The simulator proceeds as follows. For *j 2* [0*::c*) *j j t~bj tp* and *l 2* [0*::t*) it waits for input *A;:::;A 2* [0*::N*) and *2* Z of the adversary. Otherwise, *j j j* the simulator sets *e 2 Rp*to be degree *< N* polynomial defined by *A;~b*, and saves *~e* := (*e⁰;:::e* *c* 1

) *2 Rp* *c*.
The simulator proceeds to simulate the calls to *F*c-SUVas follows. For each *j 2* [0*::c*), *l 2* [0*::t*) for which *~b* *i* [*k*] = 0 it outputs “ = 0” to the adversary and aborts on this instance. Next, for all other instances it awaits a guess *B* of size at most 2*N* of the adversary. The simulator replies with “*?*” (regardless of the set *B*) and continues. Subsequently, for *i;j 2* [0*::c*) *i;j* and *k;l 2* [0*::t*) corresponding to a non-aborting instance the simulator waits for input *~g* *;k;l* *i;j* and predicate *P* *k;l* : [0*::* 2*N*)*! f*0*;* 1*g* by the adversary. Now, the simulator chooses random 0 *c* 1$*t* 0 *c* 1$*tp* *A;:::;A* [0*::N*)*;~b;:::;~b* Z *nf*0*g* and proceeds as follows: For each *i;j 2* [0*::c*), *i;j i j* *k;l 2* [0*::t*), in the (*i;j;k;l*)-th invocation of *F*c-SUV, if *P* *k;l* (*A* [*k*] + *A* [*l*]) = 0, the simulator *i j i~bj* aborts on all instances and outputs (*A* [*k*] +*A* [*l*]*;~b* [*k*] [*l*]). Otherwise, it outputs (success) and continues. Next, if the simulator did not abort on any instance, for each *i;j 2* [0*::c*), *k;l 2* [0*::t*) the simulator defines the vector

X *t* *i;j i;j* *~g* = *~g* *;k;l* *:* *j;k*=1

*i;j* The simulator interprets each *~g* as a degree *<* 2*N* polynomial *g;i*+*cj*over *Zp*, and sets *~g* := *c* (*g;:::;g*).

Protocolmal-OLE

Parameters: Security parameter 1, natural number *N* = 2 *k*, prime *p*, access to functionality *F*c-SUVwith length 2*N*, prime modulus *p*, polynomial *F* (*X*) *2* Z[*X*] of degree *N*, ring *R* = Z*p*[*X*]*=F*(*X*), and parameters *c;t 2* N (corresponding to the syndrome compression factor and noise rate of the LPN assumption, respectively). Public input: random polynomials *a₁;:::;ac* 1*2 Rp*, used for *R* *c* -LPN Correlation: After expansion, outputs (*x₀;z₀*) *2 Rp* 2 and (*x₁;z₁*) *2 Rp* 2, where *z₀*+*z₁* = *x₀ x₁*. Protocol:

1.For *2 f*0*;* 1*g;i 2* [0*::c*), party *P* samples random vectors *A*
*i* [0*::N*) *t* (where each entry of *A* *i* is viewed as a length-log*N* bit-string) and *~b* *i* (Z*p*) *t*. Note that each pair *i i i* P *t* 1 *i Ai*[*k*] *A;~b* defines a *t*-sparse polynomials *e* (*X*) = *k*=0 *~b* [*k*] *X 2 R* *p*.

2.For *2f*0*;* 1*g;i 2* [0*::c*) and *k 2* [0*::t*):
J*A* *i* [*k*]K₂ Input(*P;A* *i* [*k*]) and J*~b* *i* [*k*]K*p*Input(*P;~b* *i* [*k*])*:*

3.For every *i;j 2* [0*::c*) and *k;l 2* [0*::t*) (in parallel) the parties do the following:

|i;j||j|||
|---|---|---|---|---|
|k;l|i;j k;l p|i 0 p|j 1 p||
||||c-SUV|i;j k;l|
|i;j|i;j||||
|k;l p|;k;l||||

*i*

(a) J K₂ BitAdd(J*A₀*[*k*]K₂*;* J*A₁*[*l*]K₂).
*~b ~b*

(b)Compute J K Mult(J [*k*]K*;* J [*l*]K).
(c)For each *i;j 2* [0*::c*) and *k;l 2* [0*::t*), call *F* with length 2*N* on input J K₂ and J K, and let *~g* denote the output to party *P*.
4.For each *i;j 2* [0*::c*), *P* defines the vector
X *t* 1 *i;j i;j* *~g* = *~g* *;k;l* *:* *j;k*=0

5.Party *P* computes *x* = *h~a;~e i* mod *F* (*X*), where *~a* = (1*;a₁;:::;ac* 1), *~e* = (*e⁰;:::;e*
*c* 1 ). *i;j* And, interpreting each *~g* as a degree *<* 2*N* polynomial *g;i*+*cj*over *Zp*, and setting *~g* := (*g₀;:::;gc*21), party *P* computes

*z* = *h~a ~a;~g i* mod *F* (*X*)*:*

<u>6.Party P outputs (x;z)</u>
Figure 10: PCG protocol securely implementing the corruptible OLE functionality

### Finally, the simulator forwards

*x* := *h~a;~e i* mod *F* (*X*)

and *z* := *h~a ~a;~g i* mod *F* (*X*)

to the functionality. We conclude the proof by showing that an adversary *A* distinguishing the simulated pro- tocol execution from a real execution can be turned into an adversary *B* on the module-LPN assumption with static leakage. Adversary *B* proceeds exactly as the simulation until the point, *i;j* where it receives the predicate guesses *P* *k;l* from the adversary within the call of *F*c-SUV. Instead 0 *c* 1$*t* 0 *c* 1$*tp*

|of choosing A|;:::;A||[0::N ) ;~b|;:::;~b|Z nf0g, for each i;j 2 [0::c), k;l 2 [0::t) the|||||
|---|---|---|---|---|---|---|---|---|---|
||||i;j k;l|||i;j k;l||i;j k;l|j|
|||||i;j||||||
|||? ?|? ?|k;l||0|c 1||t|
|i ;j|i ?||i;j i|||||||
|k ;l||c 1 0|k;l tp c 1|i|? j|? i|j 0|c 1||

*i;j i;j i;j j* simulator defines the predicate *Q* : [0*::N*)*!f*0*;* 1*g* via *Q* (*A*) = 0, iff *P* (*A* + *A* [*l*]) = 0 and forwards indices *i;k* and predicate *Q* to the module-LPN game. If the game aborts $ on some index *i;j 2* [0*::c*), *k;l 2* [0*::t*), *B* samples *A;:::;A* [0*::N*) such that *???* *Q??*(*A* [*k*]) = 0 and *Q* (*A* [*k*]) = 1 for all previously queried tuples (*i;j;k;l*). Further, *~b₀*$ *??* *~b* *B* samples*;:::;~b* Z *nf*0*g*, returns (*A* [*k*] + *A* [*l*]*;~b* [*k*] [*l*]) to *A* and aborts. Note $*t* that *B* can sample *A;:::;A* as required by sampling fresh tuples *A;:::;A* [0*::N*) until the predicates take the values as required. For all events that happen with noticeable probability, this yields an adversary in expected polynomial time. If the module LPN game does not abort, *B* receives *u 2 Rp*from the experiment and sets *x₁* := *u*. The adversary *B* computes *z₁* = *x₀ x₁ z* (where *x* and *z* are computed as in the simulation). Finally, *B* outputs 0 if and only if the adversary *A* returns “real”. Note that in case *b* = 0 (i.e. the module-LPN game returns a real module-LPN sample), adversary *B* simulates the real protocol execution except with negligible probability: First, note that the probability that the adversary gets any of the guesses *B* to the functionality *F*c-SUV right is negligible, since *p* is superpolynomial and *jBj* 2*N*. Next, observe that the output distribution simulated by *B* corresponds to the real output distribution, and the module-LPN game aborts if and only if the functionality *F*c-SUVwould have aborted on at least one of its calls. Therefore, *B* simulates the real protocol execution except with negligible probability. In case *b* = 1, *B* perfectly simulates the simulation, since the probability that the module-LPN game aborts equals the probability that the simulation aborts in an ideal execution. This concludes the proof.

Distributed generation of authenticated multiplication triples in the malicious set- ting. We finally present the distributed setup for our PCG protocol to generate authenticated multiplication triplesmal-triple(Fig. 12). To additionally generate shares of the MACs, the protocol uses *F*DPFwith outputs in F²*p*; this can be done using the modification in Remark 5.2. Note that the corruptible functionality *F*mal-triple(similar to *F*c-SUV) gives the adversary full control over its share of the output. Recall that this is sufficient to use our PCG construction as a “plug-in” replacement in a wide range of natural MPC protocols that use correlated randomness, such as [DPSZ12]. As the proof of the following is very similar to the proof of Theorem 6.3, we omit it here.

Theorem 6.4 *Let R* = Z*p*[*X*]*=F*(*X*) *for some prime p and degree-N polynomial F*(*X*) *2* Z[*X*]*,* *and let c;t 2* N*. If the R* *c* *-*LPN*p;tproblem with static leakage is hard, then the protocol*mal-triple *(Fig. 12) implements the functionality F*mal-triple*(Fig. 11) with security against malicious ad-* *versaries in the F*2-PC*; F*c-SUV*-hybrid model.*

### Functionality Fmal-triple

Parameters: Security parameter 1, modulus *p*, and the ring *R* = Z[*X*]*=F*(*X*), where *F* (*X*) has degree *N*. Functionality: If both parties are honest:

1.Sample0*;*1Z*p*and let =0+1.
2.Sample *x₀;x₁;y₀;y₁ Rp*and let *x* = *x₀* + *x₁*, *y* = *y₀* + *y₁*.
3.Compute *z* = *x y*.
4.Choose *mx;*1:= *x* := *y my;*0and

|;m ;m|R and define m||m, m|
|---|---|---|---|
|x;0 y;0 z;0|z;0 p x; y;|z;|x;0 y;1|
 *mz;*1:= *z m*.
5.Output (*;x;y;z;m;m;m*) to party *P*, for *2f*0*;* 1*g*
### If party P is corrupted:

1.Wait for input (*;y;z;m*

||;x|;m|;m ) 2 Z||R from the adversary.|
|---|---|---|---|---|---|
|||x; y;|z;|p|p 6|
|1|p||p|0|1|
|||||x;1||
|z;1||||||
|1|Figure 11: Corruptible functionality for authenticated triples|x;1|y;1|z;1||

2.Sample Z and *x₁;y₁ R*. Set := +, *x* := *x₀* +*x₁*, *y* := *y₀* +*y₁* and *z* := *x y*. Compute *z₁ z z*, as well as *m x mx;;my;*1*y my;* and *m z mz;*.
<u>3.Output (;x₁;y₁;z₁;m;m;m) to the honest party.</u>
### 6.3 Efficiency Analysis

In this section we analyze the efficiency of the presented protocols for distributed setup. For an overview of concrete efficiency for the generation of OLEs in the semi-honest and malicious setting, we refer to Table 3 in Section 9. We start this section by providing the costs for implementing the secure functionalities *F*2-PCand *F*ext-2-PCfrom Section 5. We assume that secret values in these functionalities are additively secret-shared between the two parties. In the case of malicious security, the shares are also authenticated with information-theoretic MACs as in [BDOZ11,NNOB12], which ensures correct opening of shares.

Input(*P;x*): For semi-honest security, this has no communication cost as the parties define their respective shares to be *x* and zero. For malicious security, *P* needs to have an authenticated random value, which can be preprocessed, and then sends *‘* bits for *x 2* *f*0*;* 1*g* *‘* or log*p* bits for *x 2* Z*p*, to use the random value to authenticate *x*.

### Add: This is a local operation.

Mult(J*x*K*M;* J*y*K*M*): Uses one multiplication triple over Z*M*, with an online communication cost of 2 log*M* bits per party (from two calls to Output).

BitAdd: Evaluates a binary circuit on inputs of length *‘* bits, using *‘* AND gates. This consumes *‘* multiplication triples over Z₂, giving an online communication cost of 2*‘* bits per party.

Output(J*x*K*M*): This requires sending log*M* bits per party. With malicious security, the parties

### Protocolmal-triple(Part I)

Parameters: Security parameter 1, natural number *N* = 2 *k*, prime *p*, access to functionality *F*c-SUVwith length 2*N*, prime modulus *p*, polynomial *F* (*X*) *2* Z[*X*] of degree *N*, ring *R* = Z*p*[*X*]*=F*(*X*), and parameters *c;t 2* N (corresponding to the syndrome compression factor and noise rate of the LPN assumption, respectively). Public input: random polynomials *a₁;:::;ac* 1*2 Rp*, used for *R* *c* -LPN Protocol:

1.The parties jointly setup *2* Z*p*and *t*-sparse polynomials *e⁰;:::;e*
*c* 1 and *f⁰;:::;f* *c* 1, which will be used to generate *x* and *y*, respectively.

(a)For *2f*0*;* 1*g*, party *P* chooses *2* Z*p*, and inputs J K*p*Input(*P;*). The parties compute J K*p*J0K*p*+ J1K*p*.
(b)For *2f*0*;* 1*g;i 2* [0*::c*), party *P* chooses *A*
*ie;* [0*::N*) *t*, *~bie;*(Z *p* ) *t*. For *k 2* [0*::t*):

i. *ie; ie; i*

|JA [k]K₂|Input(P|;A [k]) //P|inputs k-th non-zero position of e|||||
|---|---|---|---|---|---|---|---|
|ie; p||ie;||||i||
|ie|ie;0|ie;1||||i|i0 i1|
|ie p|ie;0 p|ie;1 p||||i i0|i1|
|ie p|ie|p p||||i||
|c-SUV|i;k|i;k|ie N N||ie ie|p||
||||p p|||||
|||c 1|i i|i i ;k ;k|N p|N p||
 ii. J*~b* [*k*]K Input(*P;~b* [*k*]) //*P* inputs the *k*-th payload of *e*
iii. J*A* [*k*]K₂ J*A* [*k*]K₂ J*A* [*k*]K₂ //compute *k*-th position of *e* = *e* + *e*

iv. J*~b* [*k*]K J*~b* [*k*]K + J*~b* [*k*]K //compute *k*-th payload of *e* = *e* + *e*

v. J*~m* [*k*]K Mult(J*~b* [*k*]K*;* J K) //multiply *k*-th payload of *e* by MAC key vi.Call *F* with length *N* on input J*A* [*k*]K₂ and J*~b* [*k*]*; ~m* [*k*]K such that party *P* receives output (*~e;~u*) *2* Z Z. //convert to additive shares of *e; e*
(c)Repeat step (b) for *f⁰;:::;f* with result (*f~;~v*) *2* Z Z.
2.For every *i;j 2* [0*::c*) and *k;l 2* [0*::t*) (in parallel) the parties do the following:

|i;j||ie|j|||||i j|
|---|---|---|---|---|---|---|---|---|
|k;l|||f||||||
|k;l i;j p||ie p|j f p|||i|j||
|i;j k;l p||k;l i;j p|p|||i j|||
||||||c-SUV||i;j k;l||
|i;j|i;j|i;j|i;j||||||
|k;l|k;l p|;k;l|;k;l i|j|i j||||

(a) J K₂ BitAdd(J*A* [*k*]K₂*;* J*A* [*l*]K₂) //compute (*k*+*tl*)-th non-zero position of *e f*
*~b ~b*

(b) J K Mult(J [*k*]K*;* J [*k*]K) //compute (*k* + *tl*)-th payload of *e f*
(c) J*m* K Mult(J K*;* J K) //multiply (*k* +*tl*)-th payload of *e f* by MAC key
(d)For each *i;j 2* [0*::c*) and *k;l 2* [0*::t*), call *F* with length 2*N* on input J K₂ and J*;m* K, and let (*~g; ~w*) denote the output to party *P*. //convert to additive shares of *e f*, *e f*
3.For each *i 2* [0*::c*), *P* defines the vectors
X *t* 1 X *t* 1 X *t* 1 X *t* 1 *~e* *i* = *~e* *i;k* *; ~u* *i* = *~u* *i;k* *; f~* *i* = *f~;k* *i* and *~v* *i* = *~v;k* *i* *:* *k*=0 *k*=0 *k*=0 *k*=0

4.For each *i;j 2* [0*::c*), *P* defines the vectors
X *t* 1 X *t* 1 *i;j i;j i;j i;j* *~g* = *~g* *;k;l* and *~w* = *~w* *;k;l* *:* *j;k*=0 *j;k*=0

Figure 12: PCG protocol implementing the corruptible functionality for authenticated triples (Part I)

### Protocolmal-triple(Part II)

### Protocol: (continued)

5.Interpret each *~e;i*over Z := (*e₀;:::;e*

||as a degree < N|polynomial e|, and set ~e|)|
|---|---|---|---|---|
|i|||p|c 1|
|i i;j|i|i|||
||||;i+cj||
|||i;j|||
|1|||||
 (accordingly for *~u; f~* and *~v*).
6.Interpret each *~g* as a degree *<* 2*N* polynomial *g* over Z*p*, and set *~g* := (*g₀;:::;gc*2) (accordingly for *~w*).
7.Compute
D E *x* = *h~a;~e i;y* = *~a; f~;z* = *h~a ~a;~g i* and

*mx;*= *h~a;~u i;my;*= *h~a;~v i;mz;*= *h~a ~a; ~w i*

### all modulo F (X).

<u>8.Output (;x;y;z;mx;;my;;mz;)</u>
Figure 12: PCG protocol implementing the corruptible functionality for authenticated triples (Part II)
 also need to send and check the MACs on shares, however, this can be amortized for a large batch of openings by checking a random linear combination, so we ignore this.
Inv(J*x*K*p*): This can be done using one multiplication triple, and two openings. 9

MixedMult(*x₀;x₁;* J K₂): With semi-honest security, this uses two string-OTs of length *‘*, plus *‘* + 1 bits of communication from each party. With malicious security, when is already authenticated with MACs, this can be done with *‘* bits of communication from each party without any additional preprocessing. To see this, recall that a share is authenticated by giving *P* a MAC *M* = *K* +*K⁰*, where *K;K⁰ 2f*0*;* 1*g* are random MAC keys known to *P₁*. By hashing *M* and *K⁰* respectively, the parties obtain secret shares of *z*, where *z* = *H*(*K⁰*) *H*(*K⁰ K*) is known to *P₁*. These can be converted into shares of *x₁* with *‘* bits of communication; the complete multiplication is then obtained symmetrically.

PassiveOutput(*x₀;x₁*): (*x₀;x₁ 2 f*0*;* 1*g* log*M* ) Here, the parties exchange shares by sending log*M* bits each.

Cost of Preprocessing. We assume that multiplication triples over Z*p*can be obtained by bootstrapping from a previous PCG instance, so essentially obtained at no cost. Similarly, for the Input phase we can obtain authenticated random values with vector-OLE (over Z*p*) or correlated OT (over Z₂), using the efficient PCGs from previous works [BCGI18,BCG + 19b,BCG + 19a]. With semi-honest security, we can also obtain multiplication triples over Z₂ using a PCG for OT. However, we cannot do this for malicious security, since we do not have an efficient PCG for authenticated triples over Z₂. Therefore, we build these from correlated OT using the TinyOT protocol from [FKOS15,HSS17], for a cost of 32 bits of communication per party and 54 correlated OTs, for each triple.

Main Subprotocols. Before stating the complexities of distributed key generation, we give an overview of the complexity of the subprotocolsDPF(based on [Ds17])/c-SUV(see Figure 6) for

Given a triple J*a*K*;* J*b*K*;* J*c*K with *c* = *ab*, first open *x* + *a*, then compute J*xb*K = (*x* + *a*)J*b*K J*c*K, open *xb* and finally compute J*z*K=J*b*K(*xb*).

implementing *F*DPF(semi-honest)/ *F*c-SUV(malicious) with domain size *D* and output shares in Z *‘p* (see Remark 5.2 for obtaining outputs in Z *‘p* ). Note that for the following we assume *>* log*p*, otherwise the parties have to perform an additional *D b*(log*p*) *c* PRG operations.

Basic protocol: the basic protocol has the following complexity:

- 2*D* evaluations of PRG //Step 2
- log*D* Mult/MixedMult over *f*0*;* 1*g f*0*;* 1*g* //Step 2
- log*D* Output/PassiveOutput over *f*0*;* 1*g*
+2 //Step 2

- *‘* + 1 Input (per party) + *‘* + 1 Output over Z*p*//Step 4
- *‘* Inv + *‘* Mult over Z*p*//Step 4
Consistency check: (only required for malicious security)

- *‘* Mult over Z*p*//Step 7
- *‘* + 1 Input (per party) + *‘* Output over Z*p*//Step 7
With implementing the functionalities for secure 2-party computation as described, this adds up to the following complexity:

Correlated randomness: Consuming correlated randomness in the form of:

- semi-honest: 2*‘* multiplication triples + 2 log*D*-string-OTs
- malicious: 3*‘* multiplication triples + 2 length-(2*‘* + 2) vector-OLE (both over Z*p*)
Computation: Computation is dominated by 2*D* PRG evaluations.

Communication: Communication (per party) is dominated by:

- (2 + 3) log*D* + 5*‘*log*p* bits
- malicious: extra (4*‘* + 2) log*p* bits
Cost of distributed setup. The complexities of our protocolOLE-Setup(Fig. 8/mal-OLE (Fig. 10 implementing *F*OLE-Setup(semi-honest)/ *F*mal-OLE(malicious) to produce *N* OLEs are as follows:

||log N|p||i0 i1||
|---|---|---|---|---|---|
|2|log N||2||i j|
|2 i j|DPF|c-SUV||||

1. *ct* Input over *f*0*;* 1*g* and Z (per party)//positions + payloads of *e;e*
2. (*ct*) BitAdd over *f*0*;* 1*g* + (*ct*) Mult over Z*p*//positions + payloads of *e₀ e₁*
3. (*ct*) invocations of *F* / *F* with length 2*N* over Z*p*(*‘* = 1)//convert to shares of *e₀ e₁*
For protocolmal-triple(Fig. 12) implementing *F*mal-triple(malicious)the costs are as follows:

|||log N|p||||i0 i1|i i|
|---|---|---|---|---|---|---|---|---|
||2|p|||i0 i1 i|i|||
|c-SUV||||p||i0|i1 i|i|
|2||log N||2|p|||i j|
|2 i j||DPF|c-SUV||p||||

1. 2*ct* Input over *f*0*;* 1*g* and Z (per party)//positions + payloads of *e;e;f₀;f₁*
2. 2*ct* + (*ct*) Mult over Z //multiply payloads of *e;e;f₀;f₁* by MAC
3. 2*ct F* with length *N* and output Z² //convert to shares of *e* + *e*, *f₀* + *f₁*
4. (*ct*) BitAdd over *f*0*;* 1*g* + (*ct*) Mult over Z //positions + payloads of *e f*
5. (*ct*) invocations of *F* / *F* with length 2*N* over Z² (*‘* = 2)//convert to shares of *e f*

### Altogether, we obtain the following theorems:

Theorem 6.5 (OLE Distributed Generation) *Assuming hardness of R* *c* *-*LPN*p;;t(Def. 3.2),* *there exists a protocol securely realizing functionality F*OLE*-*Setup*/ F*mal*-*OLE*to produce N OLEs* *against semi-honest adversaries/ malicious adversaries with the following complexity (note that* *costs not specified in the following apply to both):*

Correlated randomness: *Consuming correlated randomness in the form of:*

*1.malicious:* 2*ct*log *N correlated OTs +* 2 *length-ct vector-OLE (in* Z*p)*

|2|2||p||
|---|---|---|---|---|
|2 2||2||p|
|2|||2|p|
||2||||

*2.* • *semi-honest:* 2(*ct*)
2 log *N bit-OTs +* (*ct*) 2 *OLEs over* Z

- *malicious:* 54(*ct*) log *N correlated OTs +* (*ct*) *authenticated triples over* Z
*3.* • 4(*ct*)
2 *OLEs +* 2(*ct*) log(2*N*)*-string-OTs*

- *malicious:* 3(*ct*) *authenticated triples +* 2 *length-*4(*ct*) *vector-OLE over* Z
Computation: *Computation is dominated by* 2(*ct*) *N PRG evaluations.*

Communication: *Communication (per party) is dominated by:*

*1.malicious: ct*(log*N* + log*p*) *bits*
*2.* • *semi-honest:* 2(*ct*)
2 log *N +* 2(*ct*) 2 log *p bits*

- *malicious:* 34(*ct*)
2 log *N +* 2(*ct*) 2 log *p bits*

*3.* • (*ct*)
2 ((2 + 3) log(2*N*) + 5 log*p*) *bits*

- *malicious: additional* (*ct*)
2 6 log*p*) *bits*

Theorem 6.6 (Authenticated Triples Distributed Generation) *Assuming hardness of the* *R* *c* *-*LPN*p;*1*;tassumption (Def. 3.2), there exists a protocol securely realizing functionality F*mal-triple *to produce N authenticated triples against malicious adversaries with the following complexity:*

Correlated randomness: *Consuming correlated randomness in the form of:*

*1.* 4*ct*log *N correlated OTs +* 2 *length-*2*ct vector-OLE (in* Z*p)*

|2||p||
|---|---|---|---|
|2 p|p||2|
||2|||

*2. & 4.* 54(*ct*)
2 log *N bit OTs +* 2(*ct* + (*ct*) 2 ) *authenticated triples over* Z

*3. & 5.* 6(2*ct* + (*ct*)) *authenticated triples over* Z *+* 2 *length-*6(2*ct* + (*ct*)) *vector-OLE* *over* Z
Computation: *Computation is dominated by* 2(2*ct* + (*ct*))*N PRG evaluations.*

Communication: *Communication (per party) is dominated by:*

*1.* 2*ct*(log*N* + log*p*) *bits*
*2. & 4.* 34(*ct*)
2 log *N +* 4(*ct* + (*ct*) 2 ) log *p bits*

*3. & 5.* (2*ct* + (*ct*)
2

) ((2 + 3) log(2*N*) + 10 log*p*) *bits*
Remark 6.1 (Optimizing efficiency) *If N is a power of* 2*, the above protocols can be opti-* *mized by taking the noise positions mod N and therefore reducing the input length to F*DPF*/F*c-SUV *from* 2*N to N.* *Alternatively, by relying on the hardness of R* *c* *-*LPN *with a* regular *error distribution (where* *each noisy coordinate lies in a fixed interval of size N=t), one can replace all occurrences of N* *in the efficiency estimates above by N=t.*

Recall that except for a one-time setup cost the generation of correlated randomness is *almost* *for free* in terms of communication: For the generation of OT and vector-OLE with semi-honest and even malicious security, we can build on the silent OT and vector-OLE extensions from [BCG + 19b,BCG + 19a]. Further, for the generation of OLE and authenticated multiplication triples we can bootstrap and therefore only need to generate these correlations from scratch once. For generating OLEs with malicious security one can bootstrap using the PCG for authenticated multiplication triples (at comparatively little extra cost).

## 7 Extensions and Applications

In this section we extend our PCG for OLE in several directions. First, we build PCGs for inner product correlations from OLE over *Rp*, with the advantage that we do not need to rely on the full reducibility of *F* (*X*), and can also obtain correlations over F₂. Secondly, we present a method for building PCGs for general bilinear correlations, such as matrix multiplication, in a black-box way from our previous PCG. Finally, we show that all of these PCGs for degree two correlations can be extended in a natural way to the multi-party setting.

### 7.1 Bilinear Correlations

The class of bilinear correlations we consider is as follows.

Definition 7.1 (Simple Bilinear Correlation) *Let* G₁*;*G₂*;* G*Tbe Abelian groups and e*: G₁ G₂*!* G*Tbe a bilinear map. We define the* simple bilinear correlation *for e by the distribution* *Ceover* (G₁ G*T*) (G₂ G*T*) *of the form* n o $ $ $

|C =|((r₀;s₀); (r₁;s₁)) j r₀|||G ;s₁ = e(r₀;r₁)|
|---|---|---|---|---|
|e||||T|
||en||||
|||||n|
|en|n|n|n|T|
||1|2|T||

G₁*;r₁* G₂*;s₀ s₀ :*

*We denote by C the correlation that outputs n independent samples from Ce, i.e.* n o $*n*$*n*$ *C* = ((*R₀;S₀*)*;* (*R₁;S₁*)) *j R₀* G₁*;R₁* G₂*;S₀* G*;S₁* = *e*(*R₀;R₁*) *S₀;*

*where we define e*: G G*!* G *as the bilinear map obtained by applying e componentwise.*

This covers several common correlations like OT and OLE, for example, OLE over a ring *R* can be obtained with G₁ = G₂ = G*T*= (*R;* +) and *e*(*x;y*) = *x y*. Also, note that two independent bilinear correlations can be locally converted to produce an additively secret-shared instance of the correlation — for example, two OLEs are locally equivalent to one multiplication triple.

### 7.2 Inner Product Correlations

An inner product correlation is a simple bilinear correlation with the inner product map over Z*p*. These can be used to compute inner products in an MPC online phase, in a similar way to using multiplication triples. Inner products are common in tasks involving linear algebra, like privately evaluating or training machine learning models such as SVMs and neural networks, and a single inner product can also be used to measure the similarity between two input vectors. We remark that given *n* random OLEs in F*p*, it is easy to locally convert these into a length-*n* inner product correlation, so we can build a PCG for inner products of any length using a PCG for OLE. However, the constructions in this section *do not* rely on the fully-reducible ring-LPN assumption that is needed for OLE in F*p*; instead, we use the ring-OLE construction from Fig. 1 over more conservative rings, which do not split completely into linear factors. Further, the constructions in this section generalize to rings Z*p*for arbitrary *p 2* N (including *p* = 2).

Lemma 7.1 *Let Rp*= Z*p*[*X*]*=F*(*X*)*, where F*(*X*) *is a degree-N polynomial with non-zero con-* *stant coefficient. Then, a single OLE over Rpcan be locally converted into an inner product* *correlation over* Z *N*

*p.*
*Proof.* For *a 2 Rp*, define the matrix over Z*p*that corresponds to multiplication by *a*, as 0 1

*Ma*= @ *a aX aX* *N* 1A

where each *aX* *i* is reduced modulo *F* (*X*) and represented as a vector of coefficients in Z *N*

*p*.
We have that for any *b 2 Rp*represented as a vector of coefficients, the coefficient vector of *ab* is *Mab*. Also, it is easy to see that if *a* is uniformly distributed in *Rp*then the first row of *Ma*, denoted *Ma*[0], is uniform over Z *N* *p*, since *aX* *i* has *aN i*appearing in its constant term. So given an OLE (*a;c*)*;* (*b;d*) over *Rp*, where *c d* = *ab*, the parties can define an inner product correlation (*Ma*[0]*;c₀*)*;* (*b; d₀*), where *c₀ d₀* = *hMa*[0]*;bi*. Note that, for the special case of *F* (*X*) = *X* *n* + 1, the vector *Ma*[0] can be computed as (*a₀; an* 1*;:::; a₁*), without any modular reductions.

Corollary 7.2 (Large inner product from irreducible ring-LPN) *Suppose the R-*LPN*p;*1*;t* *assumption holds for R* = Z*p*[*X*]*=F*(*X*)*, where F*(*X*) *is degree N and irreducible over* Z*p. Then* *there is a PCG for the length-N inner product correlation over* Z*p, where the seeds have size* *O*(*t²* log*N*) *bits, and the computational complexity of the* Expand *operation is O*~(*N*) *operations* *in* Z*p, plus O*(*t²N*) *PRG operations.*

Corollary 7.3 (Small inner products from reducible ring-LPN) *Suppose the R-*LPN*p;*1*;t* *assumption holds for R* = Z*p*[*X*]*=F*(*X*)*, where F*(*X*) *is degree N and splits into N=d distinct* *factors of degree d. Then there is a PCG for producing N=d instances of length-d inner product* *correlation over* Z*p, with the same seed size and complexity as above.*

The latter construction has two benefits over naively using OLE over F*p*to generate an inner product. Firstly, OLE in F*p*requires that *R* splits fully into *linear factors*, whereas for inner products the factors can be degree-*d* (and irreducible), which is a much more conservative as- sumption; in particular, the dimension-reduction attack we consider in Section 8 is less effective. Secondly, we can also use this to generate inner products over small fields such as F₂, whereas we cannot efficiently obtain OLEs over F₂ with our present constructions.

### 7.3 Bilinear Correlations from Programmable PCG for OLE

We can build a PCG to create a large batch of samples from *any* simple bilinear correlation, using the PCG for OLE from Section 4. To do this, we exploit the fact that this PCG is *programmable*, which, roughly speaking, means that one party can “reuse” its input *a* or *b* in several instances of the PCG, while maintaining security. Boyle et al. [BCG + 19b] previously used this property to construct multi-party PCGs from several instances of programmable two-party PCGs; unlike their work, we exploit the property for a different purpose in the two-party setting. In the following, we recall the definition of programmability, and show that our PCG for OLE satisfies this definition.

Definition 7.2 (Programmable PCG) *A tuple of algorithms* PCG = (PCG*:* Gen*;*PCG*:* Expand) *following the syntax of a standard PCG, but where* PCG*:* Gen(1 ) *takes additional random inputs* *; 2f*0*;* 1*g, is a* *?* programmable PCG *for a simple bilinear* 2*-party correlation C* *n* *(specified* *e* *by e*: G₁ G₂*!* G*T) if the following holds:*

- Correctness. *The correlation obtained via:*
$ $ *;* $*;*(k₀*;*k ) PCG*:* Gen(1*; ;*)*;* ((*R₀;S₀*)*;* (*R₁;S₁*)) (*R;S*) PCG*:* Expand(*;* k) *for 2f; g*

### is computationally indistinguishable from Cen(1 ).

- *Programmability. There exist public efficiently computable functions*0: *f*0*;* 1*g*
*?* *!* G *n* 1*,* : *f*0*;* 1*g* *?* *!* G *n* *such that* 1 2 2 $ 3 0 *;*1$*;*(k₀*;*k₁) PCG*:* Gen(1*;*0*;*1) *R* = () 0 0 05 Pr 4 (*R₀;S₀*) PCG*:* Expand(0*;*k₀)*;* : 1 negl()*;* *R₁* =1(1) (*R₁;S₁*) PCG*:* Expand(1*;*k₁)

|n n|n||||
|---|---|---|---|---|
|1 2|T||||

*where e*: G G*!* G *is the bilinear map obtained by applying e componentwise.*

- *Programmable security. The distributions*
(k₁*;* (0*;*1))0*;*1$*;*(k₀*;*k₁) $ PCG*:* Gen(1*;*0*;*1) *and*

(k₁*;* (0*;*1))0*;*1*;* ~0$*;*(k₀*;*k₁) $ PCG*:* Gen(1*;* ~0*;*1)

*as well as*

(k₀*;* (0*;*1))0*;*1$*;*(k₀*;*k₁) $ PCG*:* Gen(1*;*0*;*1) *and*

(k₀*;* (0*;*1))0*;*1*;* ~1$*;*(k₀*;*k₁) $ PCG*:* Gen(1*;*0*;* ~1)

### are computationally indistinguishable.

We start by showing that a programmable PCG is a PCG in the standard sense.

Lemma 7.4 *Let e*: G₁ G₂*!* G*Tbe a bilinear map. Then, a programmable PCG* PCG = (PCG*:* Gen*;*PCG*:* Expand) *for the bilinear* 2*-party correlation Cenis also a PCG for Cenin the sense* *of Definition 2.6 (where the sampling of*0*;*1*happens inside* PCG*:* Gen*).*

*Proof.* We have to show that the PCG satisfies standard security. More precisely, we have to prove that if PCG = (Gen*;*Expand) satisfies correctness, programmability and programmable security, then the distributions $ real 0*;*1$*;*(k₀*;*k )1PCG*:* Gen(1*; ;*0 1) *D* := (k₁*;* (*R₀;S₀*)) and (*R₀;S₀*) PCG*:* Expand(0*;*k₀) 8 9 > < 0*;*1$*;*(k₀*;*k₁) $ PCG*:* Gen(1*;*0*;*1) >= *D* sim := (k₁*;* (*R₀;S₀*)) (*R₁;S₁*) PCG*:* Expand(1*;*k₁) > : $ >; *R₀* G₁*;S₀* = *e*(*R₀;R₁*) *S₁*

are computationally indistinguishable (the case *k₀* is symmetric). We proceed the proof via a sequence of hybrid distributions: 8 $ 9 > <0 *;*1$*;*(k₀*;*k₁) PCG*:* Gen(1*;*0*;*1) > = *D₁* := (k₁*;* (*R₀;S₀*)) (*R₁;S₁*) PCG*:* Expand(1*;*k₁) > : >; *R₀* =0(0)*;S₀* = *e*(*R₀;R₁*) *S₁* 8 9 > < 0*;*1$*;*(k₀*;*k₁) $ PCG*:* Gen(1*;*0*;*1) >= *D₂* := (k₁*;* (*R₀;S₀*)) (*R₁;S₁*) PCG*:* Expand(1*;*k₁) > : >; ~ $*;R₀* = (~)*;S₀* = *e*(*R₀;R₁*) *S₁*

The distribution *D* real and *D₁* are computationally close by the programmability and correctness of the PCG. Next, let *A* be a distinguisher between the distribution *D₁* and *D₂*. Then, we can construct an adversary *B* on the programmable security of PCG as follows. The adversary *B* obtains (k₁*;* (0*;*1)) from its experiment. It computes (*R₁;S₁*) PCG*:* Expand(1*;*k₁), *R₀* =0(0) and *S₀* = *e*(*R₀;R₁*) *S₁* and forwards (k₁*;* (*R₀;S₀*)) to *A*. Finally, *B* forwards the reply of *A* to its own experiment. If *B* obtained the real0from its own experiment, then the resulting distribution is identically to *D₁*, whereas if *B* obtained a simulated0, *B* simulates *D₂*. Therefore, *B* successfully breaks the programmable security, whenever *A* successfully distinguishes *D₁* and *D₂*. Finally, *D₂* and *D* sim are computationally indistinguishable by the correctness of the PCG.

Lemma 7.5 *The PCG construction for ring-OLE from Fig. 1 is programmable.*

*Proof.* To allow programmability, we tweak the Gen algorithm as follows. For *2f*0*;* 1*g* the additional input can be sampled as *fA* *i* *;~b* *i* *gi2*[0*::c*)in Fig. 1, representing a vector of sparse polynomials *~e* = (*e⁰;:::;e* *c* 1 ). Notice that the first part (i.e. *x*) of both expanded outputs can now be obtained from just, by first expanding *fA* *i* *;~b* *i* *gi2*[0*::c*)to *~e* and then computing *x* = *h~a;~e i* mod *F* (*X*). This defines the functions0and1, and the correctness property follows in the same way as the proof of correctness in Theorem 4.1. The programmable security property can also be proven similarly to the proof of Theorem 4.1, with a reduction to the FSS scheme and ring-LPN assumption. Below we describe the main result, and some applications.

|||T|u 1|v 2|w T|
|---|---|---|---|---|---|
|T||||||
||T|||||
|u 1 v 2 u 1|w T|w v|v 2|i|i|

Decomposition of bilinear maps. Let *f* : G₁ G₂*!* G and *g* : G G*!* G be bilinear maps over the additive groups G₁*;*G₂*;* G. We will consider ways of computing *g* that are restricted to a fixed number of calls to *f* on the components of the inputs to *g*, followed by linear combinations in G*T*of the results of the *f* evaluations.

Definition 7.3 (Simple *f*-decomposition) *Let* G₁*;*G₂*;* G *be additive abelian groups, viewed* *as* Z*-modules. Let f* : G₁ G₂*!* G*Tand g* : G G*!* G *be non-degenerate bilinear maps. We* *say that g has a* simple *f*-decomposition *if there exist 2* N*,W2* Z *and 2* [*u*]*; 2* [*v*]*,* *for i 2* []*, such that for all a* = (*a₁;:::;au*) *2* G *and b* = (*b₁;:::;b*) *2* G*, it holds that* 0 1 *f* (*a*1*;b*1) B *:* C *g*(*x₀;x₁*) = *W* @ *::* A *f* (*a;b*)

*We say that the f*-complexity *of this decomposition of g is given by nf*(*g*) :=*.*

Note that if G₁*;*G₂*;* G*T*are all a (commutative) ring *R* and *f* is multiplication in *R*, then any *g* has a simple *f*-decomposition of complexity *u v*. However, it can still be useful to find a different *f* that achieves lower complexity. We now show that any map *g* with a simple *f*-decomposition can be used to construct a PCG for the simple bilinear correlation *Cg*, given a programmable PCG for *Cf*. The construction is given in Fig. 13. The idea is that for each invocation of *f* used in an evaluation of *g*, we will use a separate instance of the PCG for *f*, programmed to use the correct portions of the input to *g*. Then, we can obtain the expanded *g* output by applying the linear map *W* to all the expanded outputs of *f*. We also use a PRG to randomize the final output shares, to ensure that there are no correlations introduced when multiplying by *W*. For the security proof, we use an extension of the programmable security property, which considers several PCG instances, given in the following lemma.

prog Construction *G* bil

|Parameters: Security parameter 1, a programmable PCG (PCG|||||||:Gen; PCG|:Expand) for the||
|---|---|---|---|---|---|---|---|---|---|
||||fn|||0|?|n 1 1|n 2|
||||u|v|n w w T|||||
||||1|2|T|||||
|1|1|||||||||
||gn|||||||||
|gn||||||||||
|n u|n v|n w||||||||
|1|2|T||||||||

*f f* simple bilinear correlation *C* with programmibiliy maps0: *f*0*;* 1*g* *?* *!* G *n* 1,1: *f*0*;* 1*g* *?* *!* G *n* 2, and a pseudorandom generator PRG : *f*0*;* 1*g!* G. The bilinear map *g* : G G*!* G has an *f*-decomposition with parameters (*;;:::; ;;:::; ;W*). Correlation: *C* produces *n* instances of the simple bilinear correlation for *g*. That is, *C* outputs tuples ((*X₀;Y₀*)*;* (*X₁;Y₁*)) such that it holds *Y₀* + *Y₁* = *g*(*X₀;X₁*), where by *g*: G G*!* G we denote the transpose of the map *g* applied to *X₀* and *X₁* row-wise.

### Gen: On input 1 :

|1 u|1|v|||
|---|---|---|---|---|
|0 0|1|1||j|
|||||0 0|
|1 k 1|||||
|prg|i0 i1|f||0 1|
|i0 i2[]||prg i1|i2[]||

1.Sample random*;:::;* and*;:::;* according to the programmability property of PCG*f*.// This choice will define the *j*-th column of *X₀* as () for all *j 2* [*u*], and the *k*-th column of *X₁* as () for all *k 2* [*v*].
2.Sample a PRG seed k *f* 0*;* 1*g*.
3.For *i* = 1*;:::;*, sample seeds (k*;* k) PCG *:* Gen(1*;*
*i* *;* *i* ).

4.Output k₀ = (kprg*; f*k *g*) and k₁ = (k*; f*k *g*)
### Expand: On input (; k):

||i i|f|i||||
|---|---|---|---|---|---|---|
||||u|n 1 u|j i||
|i i||i|v >|a n 2 v prg|j i n T w||
|Note that such an|always exists, otherwise g would be degenerate. Further, if||||=|= j, then ~k|
|~k were sampled using the same seed|Figure 13: PCG for general bilinear correlations defined by the map g|, and thus R₀|= R₀ =|() by programmability of PCG||.|

1.Compute (*R;S*) PCG *:* Expand(*;* k), for *i 2* []
2.If = 0, define the matrix *X₀* = (*A₁k ::: kA*) *2* G, where *A* = *R₀* for some *i* where = *j* (if more than one matches, pick arbitrarily)
3.If = 1, define the matrix *X₁* = (*B₁k ::: kB*) *2* G, where *B* = *R₁* for some *i* where = *j*
4.Output *X* and *Y* = (*S¹k ::: kS*) *W* + ( 1) PRG(k) *2* G *a*
*i i0* *i* and *i* *0j i i0j* *i* 0 0 <u>0</u> 0 <u>0</u> *f*

Lemma 7.6 (Multi-instance programmability) *Let* PCG = (PCG*:* Gen*;*PCG*:* Expand) *be a* *programmable PCG as in Definition 7.2. Then, for any d* = poly()*, the distributions*

*i i d i i i*$*i*

|; (;|)|; $; (k₀; k₁)||; )|
|---|---|---|---|---|
|i 0 i 1|d i=1|0 i 1 i 0|i i|i 0 i 1|
|||||i0|

k₁0 1 *i*=1 0 1 PCG*:* Gen(1*;*0 1*and*

$ k₁*;* (*;*)*;;* ~ $*;*(k₀*;*k₁) PCG*:* Gen(1*;* ~*;*)*;*

*are computationally indistinguishable. A symmetric property holds for* k*.*

*Proof.* This follows a standard hybrid argument, where the reduction loses a factor of *d* in advantage. In the *j*-th hybrid, pick randomness0*;* *i* 1$ and for *i j* also ~ *i* 0$, for *i i*$*i i* *i j* compute the key as (*k₀;k₁*) PCG*:* Gen(1*;* ~0*;*1), and for *i > j* compute the key as *i i*$*i i i d* (*k₀;k₁*) PCG*:* Gen(1*;*0*;*1). Then give out k₁*;* (0*;*1) *i*=1. Given a distinguisher for any two hybrids *j* and *j* + 1, it is straightforward to construct a distinguisher for the programmable security property of PCG, with the same advantage.

Theorem 7.4 *Let f and g be bilinear maps as above, and suppose that g has a simple f -* *decomposition with f -complexity nf*(*g*)*. Furthermore, let* PCG*f*= (PCG*f:* Gen*;*PCG*f:* Expand) *be a programmable PCG for C* *fn* *. Then there exists a programmable PCG* PCG*g*= (PCG*g:* Gen*;* PCG*g:* Expand) *for Cgn, with the following properties:*

- PCG*g:* Gen *runs nf*(*g*) *executions of* PCG*f:* Gen*, and its key sizes are nf*(*g*) *times that of* PCG*f.*
- PCG*g:* Expand *runs nf*(*g*) *executions of* PCG*f:* Expand*, and n evaluations of the linear map* *W from the f -decomposition of g.*
*Proof.* We give an explicit consturction of PCG*g*in Figure 13. We consider separately the correctness and security properties of the PCG definition.

|Correctness.||Let (X₀;Y₀) and (X₁;Y₁) be a pair of outputs from PCG|||||:Expand. Let|; be|
|---|---|---|---|---|---|---|---|---|
||||1 0|u 0|1 1|v 1||j|
|0 j 0|n|k|k 1 n||||||
||f||1||||1||
|||v|||f|||u|

*g* 0 1 the programmibility maps, and 1 0 *;:::;* *u* 0and 1 1 *;:::;* *v* 1as chosen by Gen on input 1. Let *Aj*= () *2* G₁ and *B* =1() *2* G₂ for all *j 2* [*u*]*;k 2* [*v*]. Then, by the programmibility prop- erty of PCG it holds that (*R₀;:::;R₀*) = (*A*1*;:::;A*) and (*R₁;:::;R₁*) = (*B*1*;:::;B*) with overwhelming probability. Also, by construction in PCG*g*, we have *X₀* = (*A₁k ::: kA*) and *X₁* = (*B₁k ::: kB*). From the correctness of PCG, with overwhelming probability

*Y₀* + *Y₁* = (*S₀₁* + *S₁₁k ::: kS₀* + *S₁*) *W* *>* = (*f* (*A*1*;B*1)*k ::: kf*(*A;B*)) *W* *>* = *g*(*X₀;X₁*)*;*

where *f* is considered to be applied entry-wise to the inputs. Furthermore, *X₀* and *X₁* are both pseudorandom by the correctness property of PCG*f*, and any individual *Y* is pseudorandom due to the security of PRG; hence, the outputs of PCG*g*are computationally indistinguishable from random outputs of the correlation *Cgn*.

||||0|1 0|u 0|
|---|---|---|---|---|---|
|1 1 1 f|v 1||0|1|f|

Programmability. The programable randomness can be defined as = (*;:::;*) and = (*;:::;*). The programmability maps are defined by applying and for PCG componentwise. The programmability property then follows directly from the programmability of PCG.

Programmable Security. We first consider the case = 1. Recall that by Lemma 7.4 programmable security together with correctness and programmability automatically implies standard PCG security. We need to show indistinguishability of the two distributions

real$ $ *D* := (k₁*;* (0*;*1))0*;*1$*;*(k₀*;*k₁) PCG*g:* Gen(1*;*0*;*1) and

sim$ $ *D* := (k₁*;* (0*;*1))0*;*1*;* ~0$*;*(k₀*;*k₁) PCG*g:* Gen(1*;* ~0*;*1)

Recall that k₁ = (kprg*; f*k *i* 1 *gi2*[]), where (k *i* 0 *;* k *i* 1 ) PCG*f:* Gen( 0 *i* *;* 1 *i* ), and0= *f* *i* 0 *gi2*[*u*]*;*1= *f* *i* 1 *gi2*[*v*]. We use a hybrid argument, where the *j*-th experiment is as follows. Hybrid distribution *D₀*. Give out (k₁*;* (0*;*1)) as computed in the actual construction.

Hybrid distribution *Dj*, for *j* = 1*;:::;u*.Sample randomness 1 0 *;:::;* *u* 0*;* 1 1 *;:::;* *v* 1as in the construction, as well as random ~ 1 0 *;:::;* ~ 0 .For each *i 2* [],if*ij* then sample *i i*$*i i i i i i* (k₀*;*k₁) PCG*f:* Gen(1*;* ~0*;* 1 ). Otherwise, if*i> j*,sample (k₀*;*k₁) using ( 0 *;* 1 ) as in the construction. Output k₁ = *f*k *i* 1 *gi2*[]and the randomness0= *f* *i* 0 *gi2*[*u*]*;*1= *f* *i* 1 *gi2*[*v*].

Note that *D₀* is identical to *D* real and *Du*is identical to *D* sim. It is left to consider the difference between hybrids *Dj*and *Dj*+1. For any *i 2* [] such that*i*= *j* + 1, in hybrid distribution *Dj*+1we use fresh randomness ~ *i* 0to sample k *i* 1, whereas in *Dj*we use the real randomness 0 *i*. However, any adversary who distinguishes these can be used to break the multi-instance security property (Lemma 7.6) of the programmable PCG, where the *d* keys are defined to be those of the indices where*i*= *j* + 1. Finally, notice that the case of = 0 proceeds symmetrically, with a sequence of *v* hybrids argued in the same way.

### 7.4 Application: Matrix Multiplication Triples

We can use the general bilinear construction to build a PCG for generating a large batch of matrix multiplication triples. For matrices of dimensions *n₁ n₂* and *n₂ n₃*, the PCG seed size is around *n₁ n₃* times larger than the PCG for OLE. This means it will likely be practical for small-to-medium matrices. Let *g* : Z *n* *p* 1*n*2Z*n* *p* 2*n*3*!* Z*n* *p* 1*n*3be the matrix multiplication map, and let *f* : Z*n* *p* 2Z*n* *p* 2*!* Z*p*be the inner product map over Z*p*. These maps fit the requirements of Theorem 7.4, by using G₁ = G₂ = Z *n* *p* 2, G*T*= Z*p*, *u* = *n₁;v* = *n₃;w* = *n₁ n₃* and appropriately flattening matrices into one-dimensional vectors. Multiplication of *n₁ n₂* and *n₂ n₃* matrices is easily decomposed as a sequence of *n₁ n₃* inner products of length *n₂*, where each inner product is taken from a consecutive portion of the two inputs. This shows that the matrix multiplication map *g* has a linear *f*-decomposition with *f*-complexity *n₁ n₃*. To obtain a PCG for *g*, we use the PCG for the length-*n₂* inner product correlation *f*, which can be based on *R*-LPN when *F* (*X*) splits into degree-*n₂* factors (Corollary 7.3).

Corollary 7.7 *Suppose R-*LPN*p;*1*;tholds for R* = Z*p*[*X*]*=F*(*X*)*, where F*(*X*) *is degree N and* *splits into N=n₂ distinct factors of degree n₂. Then there is a PCG for producing n* = *N=n₂* *correlations for* (*n₁ n₂*) (*n₂ n₃*) *matrix multiplication over* Z*p. The PCG requires n₁ n₃* *copies of the PCG for n inner products of length n₂, and has seed size and computational cost* *around n₁ n₃ times that of the PCG for inner product.*

Example parameters. We now give some example parameters for generating matrix triples, based on the analysis in Section 9. For instance, when producing 8-dimensional square matrix triples in a batch of size 130000, over a 128-bit field, the PCG seeds have size around 83MB. These can be expanded to produce matrix correlations of around 400MB, giving a 5-fold ex- pansion factor. Increasing the dimension to 16, the seed size grows to 330MB, while the PCG output has size 810MB. Going to dimension 32 and beyond, the seeds start to become much larger, although better expansion rates could be obtained when producing a much larger batch of triples. In general, this shows that in practice, the construction is only likely to be useful for small matrix dimensions; however, these could still be used as a building block in performing larger matrix multiplications in applications. For larger matrices, more interactive approaches such as recent work based on homomorphic encryption [CKR + 20] appear to be more practical.

Remark 7.8 *Instead of using a PCG for inner product, we could instead directly use a pro-* *grammable PCG for OLE to build matrix multiplications, by applying Theorem 7.4 with f as* Z*p* *multiplication. However, this would require n₁ n₂ n₃ instances of the base PCG, giving a much* *worse expansion factor. This shows the advantage of finding a suitable f such that the desired* *correlation g has low f -complexity, compared with the naive approach.*

### 7.5 Application: Circuit-Dependent MPC Preprocessing

Circuit-dependent preprocessing is a variation on the standard multiplication triples technique, which is based on Beaver’s circuit randomization technique [Bea92] and extended in more recent works [DNNR17,KKW18,BNO19,BGI19]. The idea is to preprocess multiplications in a way that depends on the structure of the circuit, and leads to an online phase that requires just *one* *opening per multiplication gate*, instead of two when using multiplication triples. With the PCG for general bilinear correlations, we can generate circuit-dependent prepro- cessing for a large batch of identical circuits. This can be useful, for instance, when executing the same function many times on different inputs, or when a larger computation contains many small, repeated instances of a particular sub-circuit. Let *C* be an arithmetic circuit over F consisting of fan-in two addition and multiplication gates. In the offline phase each wire *w* in the circuit is assigned a value *rw*such that: $

- if *w* is an input wire, *rw*F is chosen at random
$

- if *w* is the output wire of a multiplication gate, *rw*F is chosen at random
- if *w* is the output wire of an addition gate with input wires *u* and *v*, then *r*

||||= r|+ r.|
|---|---|---|---|---|
|u;v|u;v|u v|w|u v|
|||||w|
||u;v||||
|i j2R|j|g|g||
||C||||

Further, each multiplication gate is assigned a value *s* as follows:

- if the multiplication gate has input wires *u* and *v*, then *s* = *r r*.
The goal of the offline phase is for the parties to obtain random additive shares of *r* for all input wires and output wires of multiplication gates, as well as *s* for all multiplication gates. Let *G* denote the set of multiplication gates. Then, for a multiplication gate *g 2 G* with P P input wires *u* and *v*, we can write *su;v*as *i2Lg* *r* *g* *r*, where *L* and *R* are the sets of output wires of multiplication gates that pass only through addition gates before reaching *g*. All *su;v*values can therefore be computed as a bilinear function *f* of *~r*, where *~r* consist of the random values assigned to the input wires and the output wires of multiplication gates. Plugging in the previous construction for general bilinear correlations, we obtain a PCG for *fC*out of several instances of a PCG for OLE, where the total number of instances is P *g2G* *jLgjjRgj*.

### 7.6 Application: Multi-Party PCGs for Bilinear Correlations

In [BCG + 19b][Theorem 41], Boyle et al. showed that any two-party, programmable PCG for a simple bilinear correlation can be used to build a multi-party PCG for an additively secret-shared version of the same correlation. Plugging in Lemma 7.5 and the results of the previous section, we obtain *N*-party PCGs for (unauthenticated) multiplication triples, matrix triples and circuit-dependent preprocessing over Z*p*based on ring-LPN, for any polynomial number of parties *N*. Each party’s seed contains 2(*N* 1) seeds of the underlying two-party PCG, plus *N* 1 seeds for a PRG. The expansion procedure of the PCG consists of expanding the 2(*N* 1) PCG seeds, as well as the PRG seeds.

Authenticated triples in the multi-party setting. Unfortunately, the transformation of Boyle et al. only applies to degree-2 correlations, and we do not see a way to directly apply it to our PCG for *authenticated* multiplication triples, which is a degree-3 correlation. To see the challenge in extending their construction, consider the case of *n* parties who wish to obtain additive shares of (*x y*), where*;x;y* are additively shared. To do this using pairwise correlations, it seems we need a way to obtain shares of *x*

||||y|, for every i;j;k 2 [n], where|
|---|---|---|---|---|
||||i j|k|
|i j|j|k|||
|i|j|k|k||

*Pi*holds *x*, *P* holds *y* and *P* holds*k*. We cannot do this with just a pairwise correlation between *P* and *P*, since must be known only to *P*. On the other hand, given a function secret sharing scheme for *3 parties*, one could modify our authenticated triples construction from

Fig. 2 to make this work. However, known constructions of 3-party distributed point functions

*p* are much more expensive, with a seed size of *O*( *N*) rather than *O*( log*N*) [BGI15].

## 8 Security Analysis

We analyze the security of module-LPN against various attacks. In the following, we consider a *R* *c* -uLPN instance over a ring *R* = F[*X*]*=F*(*X*) (where *F* (*X*) is a degree-*N* polynomial) with *c* samples, and a regular noise of total weight *w* (that is, *w* = *t c*, where *t* is the number of nonzero coordinates of each noise *ei2 R*); therefore, the adversary gets (*~ai; h~ai;~si* + *ei*) *ci* =1, where *~s* and each *~ai*are random over *R* *c* 1, and each *~ei*is sampled from *HWw=c*, and must distinguish (*h~ai;~si* + *ei*)*i c*from a random element of *R* *c*. The corresponding code is a linear code with dimension (*c* 1) *N* and length *c N*, whose parity-check matrix *H 2* F *N c N* is *c*-compressing. Note that by our reduction from *R*-LPN to *R*-uLPN (Lemma 3.4), this effectively *0 0 0 0 0*$*c* 1 *0*$ *cw=c*1 reduces to distinguishing (*~a; h~a;~s i* + *e*) from random, where *~a R* and *~s* (*HW*) is (*c* 1)*w=c*-sparse. We will consider two alternatives for the underlying field: either F is a very small field (e.g. F=F₂), or F is a large field (e.g. F=Z*p*where *p* is a large prime, for example *p* 2 128 ). Eventually, we will consider both the cases where *F* (*X*) is an irreducible polynomial over F[*X*], and the case where *F* (*X*) is fully reducible over F[*X*] (typically, this will be the case when *F* is a two-power cyclotomic polynomial and F = Z*p*where *p* is a large prime). We can also consider two error distributions: the *ei*can be either random weight-*t* errors, or regular weight-*t* errors (where *N* coordinates of *ei*are divided into *t* blocks of length *N=t*, and a single random noise is added to a random coordinate of each block). Below, we analyze various attacks with respect to the uniform noise distribution. However, none of the attacks we describe in the following sections performs better when using a regular noise distribution.

Bottom Line. To provide a short, high-level summary of the conclusion of this section: when *F* is irreducible over a large field F, no known attacks perform significantly better than those on standard LPN, with a very limited number of samples *O*(*n*), where *n* is the dimension. In this setting, attacks such as BKW do not apply, but information set decoding (ISD) and statistical decoding (SD) do. Both have complexity exponential in the number of noisy coordinates. When

*F* is reducible, however, the adversary can reduce the instance modulo some factor and get a new LPN instance, which might be easier to solve if the factor is sparse (as it reduces the dimension without increasing the noise). Hence, the cost of ISD and SD must be evaluated for each reduction modulo a sparse factor, and the cost of the attack is the smallest cost accross all factors. Our use of structured matrices means that the DOOM attack might apply, but it only reduces security by about (log*N*)*=*2 bits. Eventually, over types of structural attacks, like algebraic decoding attacks, do not seem to apply to our setting.

### 8.1 Generic Attacks on LPN

|||||| ||
|---|---|---|---|
||||c 1|
|c 1 i|N|i||

We denote by *G* = [Id*Njj A₁jj A*] the generating matrix of the linear code associated to our *R*-LPN instance, which generates a code with a *c*-compressing parity-check matrix *H* = [*A₁jj A jj*Id] where the *A* are the multiplication matrices of *ai*mod *F* (*X*) for independent random *a 2 R*.

Existing Generic Attacks. In spite of its extensive use in cryptography, few cryptanalytic results are known for the general LPN assumption. We outline below the main known attacks.

Attacks on Syndrome Decoding. The problem we consider is best seen as an instance of the syndrome decoding problem, where the goal is to recover *~s* given *H ~s* (where, in our case, *H* = [*A₁jj Ac* 1*jj*Id*N*] is the parity-check matrix of *G*). Existing attacks on syndrome decoding rely either on improvements over a natural Gaussian elimination attack, called information set decoding (ISD), or on a parity-check attack exploiting low-weight codewords in the dual code, known as statistical decoding attacks [AJ01,Ove06,FKI06,DAT17], or low-weight parity-check attacks [Zic17].

- Gaussian Elimination. For the standard LPN assumption with *w* noisy coordinates, the Gaussian elimination attack requires on average (1*=*(1 *w=*(*cN*)))
(*c* 1)*N* iterations, where the adversary must invert a (*c* 1)*N* (*c* 1)*N* submatrix of *G*, which takes time *O*(((*c* 1)*N*) 2*:* 8 ) using Strassen’s matrix multiplication algorithm. However, since the special structure of *G* allows for fast (quasilinear) matrix-vector multiplication, standard techniques allow for solving a linear system of equations defined by a random submatrix of *G* in time *O*(((*c* 1) 2 *N²* log((*c* 1)*N*)). Hence, the cost (counted as a number of arithmetic operations over F) of the generic Gaussian elimination attack on *R*-LPN is (assuming for simplicity that *c* is a constant, as it will be in all our instantiations): ! (*c* 1)*N* <u>(c 1)w</u> <u>1</u>2 2 *O* <u>w</u> ((*c* 1)*N*) log*N* = *O*(*ec*((*c* 1)*N*) log*N*)*;* 1 *cN*

where the equality holds when *N w*. Note that the above attack assumes a standard noise distribution. However, using a regular noise distribution does not change the effi- ciency of the attack: if the noise vector is divided into *w* blocks of length *cN=w* with a single noise in each block, the natural adaptation of the above Gaussian elimination attack to this setting works by trying to find (*c* 1)*N=w* non-noisy coordinate in each of the *w* blocks (finding more non-noisy coordinates in a given block can only decrease the success probability of the attack). This means that the success probability of the attack is given by ! (*c* 1)*N=w* *w* (*c* 1)*N* <u>1 w</u> 1 = 1 *cN=w cN*

which leads exactly to the same cost for the attacker. We note that the same observation applies to all variants of ISD we are aware of.

- Information Set Decoding. Among the best algorithms for syndrome decoding are improvements of Prange’s ISD algorithm (which is itself an improvement over the Gaussian elimination attack given above), which attempts to find a size-*w* subset of the rows of *H* that spans *H ~e*. When the LPN instance has high dimension (*c* 1)*N*, *cN* samples, and very low error rate (which is the case in our scenario, since we consider a fixed amount *w* of noisy coordinates and *N w*), according to the analysis of [TS16], all known variants of ISD (e.g. [Pra62,Ste88,FS09,BLP11,MMT11,BJMM12,MO15]) have essentially the same asymptotic complexity *c*
*w*(1+*o*(1)) (ignoring the *O*((*c* 1) 2 *N²* log*N*) polynomial cost of solving a linear system). Therefore, their gain compared to the initial algorithm of Prange vanishes in our setting and the cost of these attacks is well approximated by

*O c* *w* (1+*o*(1)) (*c* 1) 2 *N²* log*N :*

- Statistical Decoding. Eventually, all the previous attacks recover the secret *~s*. If one simply wants to distinguish *~b* = *A ~s*+*~e* from random, there exists an alternative, incom- parable line of attacks, known as *statistical decoding* attacks [AJ01]. These attacks are based on the following observation: by the singleton bound, the minimal distance of the code generated by *H* is at most (*c* 1) *N* + 1, hence there must be a parity-check equation for *G* of weight (*c* 1) *N* + 1. Then, if *~b* is random, it passes the check with probability at most 1*=j*F*j*, whereas if *~b* is a noisy encoding, it passes the check with probability at least 1*=j*F*j* + ((*N* 1)*=cN*)
*w*. Note that this attack works especially well when F is very large, since then a random *~b* has negligible probability to pass the check. Improved variants of the algorithm describe optimized methods to quickly find a relatively large number of parity-check equations with a sufficiently small weight. For the sake of providing conser- vative estimates, however, we will assume in our analysis that the adversary has already pre-computed an arbitrary number of parity-check equations (since these equations depend solely on *H*), and that all such equations have minimal weight *N* + 1. Under these conser- vative assumptions, the cost (counted as a number of arithmetic operation) of statistical decoding is lower-bounded by *w* <u>cN</u>*w* *O N O* (*c N*) *:* *N* 1

Here again, the estimations are made using the standard noise distribution. However, it does not seem feasible for an attacker to exploit a regular noise distribution: intuitively, the best the attacker can do to exploit this structure requires finding low-weight codewords in the dual code whose nonzero coordinates are ‘equally well-spread’ accross all coordinates. But at quick calculation similar to the one we did for Gaussian elimination shows that, even if finding many such optimally low-weight well-spread codewords was feasible (which is not clear), the running time of the attack would still remain identital to our estimate above.

Attacks on LPN (Using Many Samples). When the number of samples can be very large, as is generally the case in the LPN literature, there exist improved attacks based on time-space tradeoffs. Below, we briefly recall existing attacks. However, as our overview below illustrates, all these attacks require a *superlinear* number of samples*!*(*D*) in the dimension *D* (even the sample- optimized variant of BKW of [Lyu05]), while the variant we consider has *cN* = *c* <u>c</u> 1 *D* samples. Hence, none of the attacks below does apply in our scenario. We refer the reader to [EKM17] for a more comprehensive overview. Given an LPN instance with dimension (*c* 1)*N*, *w* noisy coordinates, and *q* = *cN* samples, we let *r w=q* denote the *noise rate* of the instance.

- The BKW algorithm [BKW00]. This algorithm is a variant of Gaussian elimination which achieves subexponential complexity even for high-noise LPN (e.g. constant noise

rate), but requires a subexponential number of samples: the attack solves LPN over F₂ in time 2 *O*((*c* 1)*N=* log((*c* 1)*N=r*)) using 2 *O*((*c* 1)*N=* log(*c* 1)(*N=r*)) samples.

- Hybrid attacks [EKM17]. The authors of [EKM17] conducted an extended study of the security of LPN, and described combinations and refinements of the previous three attacks (called the *well-pooled Gauss attack*, the *hybrid attack*, and the *well-pooled MMT* *attack*). All these attacks achieve subexponential time complexity, but require as many sample as their time complexity.
- Scaled-down BKW [Lyu05]. This algorithm is a variant of the BKW algorithm, tailored to LPN with polynomially-many samples. It solves LPN in time
2 *O*((*c* 1)*N=* log log((*c* 1)*N=r*)) *;*

using ((*c* 1)*N*) 1+*"* samples (for any constant *" >* 0) and has worse performance in time and number of samples for larger fields.

### 8.2 Taking Advantage of Reducible F

When *F* (*X*) is reducible, the above attacks can be improved if the adversary finds sufficiently sparse polynomial factors *fi*of *F*. Indeed, when this is the case, the adversary obtains new LPN instances by computing *~a s* + *~e* mod *fi*, where the new noise *~e* mod *fi*remains sparse since *fi* is sparse. This reduces the problem to an LPN instance in smaller dimension, which can also be solved by any of the above attacks. Below, we consider the best case (for the adversary), when there is a factor *fi*of degree *n* = *N=k*, for some *k*, which has sparsity 1. This happens, for example, when *F* (*X*) is the *m*-th cyclotomic polynomial, of degree *N* = (*m*), *p* = 1 mod 2*N*, and *N* is a power of two. In this case, *F* (*X*) = *X* *N* + 1 splits completely into *N* linear factors 2 *i*10 modulo *p*, but also has sparse factors of the form *X* + *ci*due to properties of roots of unity. Reducing a *R*-LPN sample mod *fi*brings the dimension down to *N=k*, while the total number of noisy coordinates now lies between *w=k* and *w* (depending on how many errors are added together). To study the effectiveness of this attack, we need to first analyze the new noise rate, and then the performance of the best known *R*-LPN attacks for the new set of parameters.

Estimating the reduced error rate. Suppose each of the *t* = *w=c* errors in one entry of *~e* = (*e₁;;ec*) is chosen independently and uniformly from [*N*] (this is only a small change from the original distribution. Then, reducing an error polynomial modulo some 1-sparse *fi*of degree *n* = *N=k* just means each error ends up in a random position in the reduced length-*n* vector. For each *j 2* [*n*], define the random variable *Ej*to be 1 if position *j* in the reduced polynomial has zero errors, and 0 otherwise. It follows that the expected the number of error- P *t* free positions is *j* E[*Ej*] = *n* Pr[*Ej*= 1] = *n* (1 1*=n*). Therefore, summing up across the *c* error polynomials, we get a total of

<u>1</u>*t* *cn*(1 (1)) *n* expected errors in the reduced LPN instance.

Analysis for Two-Power Cyclotomics. In our estimations below, we will focus on the important case where *F* (*X*) is a two-power cyclotomic, which is one of our main candidates for building a pseudorandom correlation generator for OLE correlations over F = Z*p*, and which is also the best-case scenario for the attacker: for *i* = 1 to log*N*, there exists 1-sparse factors of *F* (*X*) of degree 2 *i*, and each of them gives rise to an LPN instance of dimension *ni*= (*c* 1) 2 *i*,

|with q = c|2 samples, and with an expected number of errors w||(1 )|).|
|---|---|---|---|---|
|For example, if c is a square root of||1 modulo p (which exists, since with two-power cyclotomics,||p|
|1 mod 4) then X|+ 1 = (X|c).|||

*i* *i* *i*= *cni*(1*n* <u>1</u> *i* *w=c*

*N N=* + *c*)(*X* *N=*

Gaussian Elimination. By picking an optimal choice of *i*, this *R*-LPN instance can be solved in time!!

||n||
|---|---|---|
||w|2 i|
|1 i log N|q||

*i* *O* min <u>i</u> *n* log*ni:* 1 *i*

Information Set Decoding. When *F* (*X*) is reducible, we cannot generally assume that the dimension is much larger than the number of noisy coordinates, since the adversary can reduce the dimension. By picking an appropriate *i*, the adversary can therefore find an LPN instance where some of the improved ISD algorithm perform better than Prange’s original algorithm. Due to the extended literature on ISD, it is difficult to evaluate precisely all existing attacks on a given instance. However, a simplified and general estimation of the efficiency of ISD algorithms was given in [HOSS18b], based on similar analysis given in [FS09,Sen11a,HS13,TS16]. This general analysis builds upon the fact that most state-of-the-art ISD algorithms share a common structure, from which a general lower bound on the cost of the attack can be derived. Here, we simply reproduce the conclusions of [HOSS18b], restricted to our specific setting, and refer the reader to [HOSS18b] for details on the analysis. We note that [HOSS18b] does not aim at precisely estimating the cost of the attacks, but at providing a reasonably sharp and general lower bound on their costs. In general, the cost of modern ISD algorithms for a parity-check matrix *Hi*, with dimension *ni*= (*c* 1) 2 *i*, *qi*= *c* 2 *i* samples, and *wi*noisy coordinates, is lower bounded by 8 n o 9 *niqi* ! < min 2*;* *w* =

|||K₁ + K₂||(n q)|
|---|---|---|---|---|
||w|||i i|
|p;q|n q w p|i i|n +q p i i|q|
|i 2|i||||
|||i|||

*iwi i* min *i i* +*;* : 2; *i*

where the values (*p;q*) satisfy 0 *q* 2 and 0 *p n* +*q*, *K₁* denotes the cost of performing a Gaussian elimination on a submatrix of *H* with *n q* columns, and *K₂* denotes the running time of a specific sub-algorithm, which varies accross different attacks. Since *H* is well structured, we assume to be conservative that performing Gaussian elimination on the submatrix of *Hi*can be done in time (*n q*) log(*n q*). Regarding *K₂*, according to the analysis of [HOSS18b], it can be lower bounded by (*n* + *q*)*=*2 *p=*8

when using the algorithm of [BJMM12], which seems to provide the best efficiency on the instances we consider (more recent algorithms improve over [BJMM12], but at the cost of large hidden constants that render them less practical, or only for very high noise rates). Putting everything together, a lower bound on the cost of ISD algorithm for a two-power cyclotomic *F* is given by 8 n o 0 19

||n q||(n +q)=2||
|---|---|---|---|---|
||w|i|p=8|i i|
|1 i log N|n q|n +q||q|
|0 q n 0 p n +q|w p|p|||

< min 2*i;i*(*n* *iq*) 2 log(*n q*) + *i*= *i* @ *w* (*n q*) A min *i i* + *:* : 2; *i* *i* *i*

Statistical Decoding. By picking an optimal choice of *i*, a reducible *R*-LPN instance can be solved with a statistical decoding algorithm in time *wi* <u>q</u> <u>i</u> *i* *O* min 2 *:* 1 *i* log*N ni*1

Changing the Structure of the Noise. In our analysis above, we rely on an estimation of the expected amount of noise after reduction modulo a 1-sparse factor *fi*of *F*. However, this ignores the possibility that, in some rare cases, the reduction modulo *fi*might lead to an

instance with a much smaller amount of noise than the expected number, in which case the attacks above will work much more efficiently. We note that there is a natural approach to avoid these “weak parameters”, by sampling the noise such that its reduction modulo *any* 1-sparse factor *fi*has weight at least the expected quantity *ti*. Typically, when *F* = *X* *N* + 1, the 1-sparse 2 *i* factors are all of the form *X* + *ci*, and sampling the noise in this way is very easy; one can for example use a simple rejection sampling approach. Note that it is sufficient to consider a 2 *i* single factor *X* + *ci*for the smallest *i* which the adversary can consider (typically, *i* = 6 or 7 2 *i* in our instances), because reducing the noise modulo *X* + *ci*amounts to computing a linear combination of the consecutive length-2 *i* subvectors of the noise vector. Hence, reducing modulo *0 i0i* any factor with a larger *i* amounts to computing a linear combination of concatenations of 2 of these subvectors, which implies that the total noise cannot decrease more than when reducing 2 *i* modulo *X* + *ci*. Since a random noise vector will have more than *ti*noisy coordinates after reduction modulo *fi*with probability 1*=*2, this rejection sampling approach reduces by a single bit the total entropy of the noise vector. We note that there might possibly be other, less sparse factors, which the adversary could use. For such factors, the sampled noise vector is not guaranteed to maintain a target expected number of nonzero coordinates after modular reduction. However, the noise reduction achieved by modular reduction comes from collisions between the noisy coordinates in the reduced in- stance, but this number of collision (as shown in our computation of the expected number *ti* of collisions) is typically quite small. On the other hand, reducing modulo a *d*-sparse factor increases the amount of noise by a factor *d*; when *d >* 1, we expect that this will systematically lead to an increased total amount of noise, and is not a viable adversarial strategy. Therefore, reductions modulo 1-sparse factors seems to be the main concern, and sampling the noise vector as we suggest eliminates the unlikely event of a weak noise with respect to one of these factors.

### 8.3 Algebraic Attacks on Fully-Reducible F

Another type of attacks are the algebraic attacks that exploit the structure of the underlying code. Many such algebraic decoding attacks have been devised in the literature, and fall in a unified framework developed in [Pel92,Kot92] of distinguishing attacks based on componentwise product of codes. Examples of such attacks include [PMCMM11,MCP12,FGUO + 13,CGGU + 13, MCMMP14] (and many more), and were often used to break some variants of the McEliece cryptosystem. Assume again that *F* (*X*) = *X* *N* + 1 is a 2-power cyclotomic polynomial, with *N* linear factors *fi*(*X*) = *X* + *ci*. In this setting, the generating matrix associated to (*~s 7!* | | |

|||||| |||
|---|---|---|---|---|
|i i N|N i||c 1|i|

*h~a;~si* mod *fi*)*i N*is of the form *G* = *V* [Id*Njj A₁jj A*], where *V* is a Vandermonde matrix (since Vandermonde matrices capture polynomial evaluation, and reducing a polynomial modulo a linear factor of the form *X* + *c* is equivalent to evaluating the polynomial at *c*). Algebraic decoding attacks would allow to break the reducible *R*-LPN assumption if *G* is strongly multiplicative (roughly, *G* generates a strongly multiplicative code if the entry-wise product of each pairs of columns of *G* spans a vector space of dimension *d <* (*cN*) 2 ). However, with *G* as above, it is easily seen that the pointwise products of pairs of columns of *G* span the whole (*cN*)2 F with overwhelming probability over the choice of *A₁;;Ac* 1, because the pointwise products of two columns in each *Ai*are distinct to each other with overwhelming probability. Therefore, algebraic decoding attacks do not seem to apply to our LPN variant.

8.4 Attacks Using the Quasi-Cyclic Structure of the Code When the underlying code has a quasi-cyclic structure, there is an additional attack which must
p be accounted for, which enhances the ISD family of attacks with a (*c* 1)*N* computational speedup: the DOOM (Decoding One Out of Many) attack [Sen11b]. We note that the structure of our codes is not exactly a quasi-cyclic structure; however, they have a structure that closely resemble the structure of quasi-cyclic codes (e.g. when *F* = *X* *N* + 1, our code matrix is quasi-

cyclic up to the fact that the odd-numbered blocks are multiplied by a factor 1). Therefore, even though we are not aware of an extension of the DOOM attack to the kind of structured codes we consider, we assume to be conservative that the DOOM attack can be extended to work in our setting, and take into account the corresponding speedup for the ISD attacks in our estimations. Similarly, when *F* is reducible, we assume that the DOOM attack speeds up the *p* ISD attacks by a *ni*factor over the reducted instance of dimension *ni*.

### 8.5 Attacks over Small Fields

In this section, we assume the F = F₂, which is the setting we consider in our applications that rely on *R*-LPN small fields. The attack we describe works also over larger fields, but performs more poorly, since it requires to brute-force over all possible secrets. A natural approach to attack *R*-LPN over a small field is to brute-force over all possible choices of *~s 2HW* *cw=c*1. For each candidate vector *~s*, the attacker checks whether *h~a;~si* +*~b* is a regular *w=c*-sparse vector. The number of sparse secrets from *HW* *cw=c*1 over F₂ is

(*c* 1) *N* <u>w</u> *;* (*c* 1) *c*

|||c|
|---|---|---|
|((c|1) N )||
|((c|1))||

*j*F*j*1 and grows to<u>w</u> *j*F*j*1over arbitrary fields. Each *h~a;~si* for some candidate secret *~s* requires *c* *O*((*c* 1) *N* log*N*) multiplications over F, hence the running time of the attack is lower bounded by (*c* 1) *N* *O* <u>w</u> (*c* 1) *N* log*N :* (*c* 1) *c* Note that when F = F₂, the smallest integer *d* such that 2 *d* = 1 mod *m* (where *m* is such that

(*m*) = *N*, *i.e.*, *F* is the *m*-th cyclotomic polynomial) is at least log*N*, hence *F* splits into
*N=d* at most *N=d* factors and when this is the case, F₂[*X*]*=F*(*x*) = *R* = F₂*d*. When applying the brute-force attack to a reduced instance, the cost grows as

((*c* 1) *d*) *j*F 2 *d* *j*1 ((*c* 1) *d*) *N* 1 <u>w</u> *j*F *j*1 (*c* 1) *N* log*N* <u>w</u> *N* 1 (*c* 1) *N* log *N:* ((*c* 1) *c*

)2*d*((*c* 1)
*c* )

Since *N* will be very large (e.g. about 2 20 ) in our instantiations, this attack is never feasible.

Improved Small Field Attacks. We note, however, that when F = F₂ and *F* is reducible, one can significantly refine the naive brute-force attack which we described above. Since this setting is exactly the setting of the Lapin authentication protocol [HKL + 12], which is perhaps the flagship application of *R*-LPN, it has been the subject of extensive cryptanalysis in [BL12,GJL15], which managed to break some candidate parameters of the original proposal. We will not cover their attacks in detail, but note that parameters which were conjectured to provide 80 bits of security in the original proposal (where the estimation was based on standard attacks on LPN, ignoring the ring structure), were shown to provide only 70 bits of security in [GJL15]. Therefore, when using F = F₂ and a reducible *F*, the state-of-the-art attack of [GJL15] should be taken into account and the security margin must be increased by at least a comparable factor.

### 8.6 Attacks on R-LPN with Static Leakage

Eventually, our malicious distributed setup protocol in Section 5.3 relies on the *R*-LPN assump- tion *with static leakage* (Definition 6.2). In this variant, security is based on the following game: after the *c* noise vectors *~e₀; ~ec*sampled, the adversary is allowed to submit *c t* arbitrary predicates *P* *ki* : [0*;N*) *7!f; g*, where *P* *ki* takes as input the position of the *k*-th nonzero entry

of *~ei*. If any *P* *ki* returns 0, we abort and the adversary looses the game. Otherwise, we sens “success” to the adversary, and he can now attempt to distinguish whether he got a random vector or a noisy codeword. As outlined in 5.3, *R*-LPN with static leakage can be reduced to *R*-LPN without leakage. However, this comes at a strong loss in the reduction, and updating parameters to reflect this reduction would decrease the efficiency of our schemes. While the resulting efficiency would still be acceptable, we observe that all the attacks described in this section do not perform signifi- cantly better against the *R*-LPN with static leakage assumption. The reason is that in all the attacks mentioned in this section, the choices made by the adversary when trying to distinguish *~b* = *A~s*+*~e* from random (e.g. picking candidate non-noisy coordinates in the Gaussian elimina- tion attack, or choosing low-weight parity-check vectors in the statistical decoding attack) are made *independently of ~b*. Therefore, in all these attacks, the success probability of the adversary can be computed by sampling the noise vector *~e after the adversary made his choices*; indeed, this is exactly how we estimate the complexity of the attack in our asymptotic estimations. This implies that, for all the above attacks, the success probability of the adversary can be obtained by fixing his choice of predicates *P* *ki*, his choice of attack parameters (e.g. candidate non-noisy coordinates in the Gaussian elimination attack, low-weight parity-check vectors in the statistical decoding attack) and computing *p₀p₁* with

- the probability *p₀* that all *P*
*ki* return 1, over a random choice of *~e*;

- the probability *p₁* that the attack succeeds when *~e* is sampled *conditioned on all P*
*ki* *re-* *turning 1*.

However, the above probability is upper bounded by the probability that the attack succeeds for a random noise vector not conditioned on the output of the predicates. The takeway message is that any attack that selects its attack parameters without using *~b* (but possibly using *A* and all other parameters of the system) cannot succeed better at breaking *R*-LPN with static leakage than at breaking the standard non-leaky *R*-LPN. In light of the fact that all known attacks that apply to our setting have this feature, it seems that, for the same parameters, *R*-LPN with static leakage offers the same concrete level of security as *R*-LPN without leakage.

## 9 Efficiency Analysis

In this section, based on our security analysis from Section 8, we discuss concrete choices of parameters for which the corresponding ring-LPN problems are secure against the attacks we considered. We then analyse the concrete efficiency of our PCGs in terms of seed size, commu- nication complexity of the setup protocol, and estimated computational costs of seed expansion. We focus on the case of a large finite field F = Z*p*, for a prime *p* with log*p* 128, as is commonly used in MPC implementations [KOS16,KPR18]. Further, for improved efficiency, we always choose the ring-LPN noise vectors to have a regular structure (as was done e.g. in [BCGI18,BCG + 19b,BCG + 19a]), which does not introduce any known weaknesses.

Estimating Attack Costs. For large fields, we focus on the statistical decoding and infor- mation set decoding (ISD) families of attacks (the latter being always at least as efficient as the Gaussian elimination attack), combined with the speedup obtained with the DOOM attack against quasi-cyclic codes. For statistical decoding, we compute our estimations with a conser- vative lower bound of *n* (*cN=*(*N* 1)) *w* arithmetic operations. For ISD, we used the parameter estimation tool developed for the LEDA candidate [BBC + 19] in the NIST post-quantum com- petition¹¹. This software takes as input the parameters (dimension, number of sample, number of noisy coordinates, block-size of the quasi-cyclic matrices) of the instance, and outputs the

https://github.com/LEDAcrypt/LEDAtools

complexity of attacking the instance with several ISD variants, namely those of Prange [Pra62], Lee and Brickell [LB88], Leon [Leo88], Stern [Ste88], Finiasz and Sendrier [FS09], May, Meurer, and Thomae [MMT11], and Becker, Joux, May, and Meyer [BJMM12], while taking into account the speedup of the DOOM attack when the code is quasi-cyclic. Furthermore, observing that the C++ code of the software implements matrix inversion using standard (cubic time) Gaus- sian elimination, we modified the matrix inversion used in the code to account for polynomial speedups obtained by using fast (quasi-quadratic time) algorithms for inversion of structured matrices.

### 9.1 Comparing Reducible and Irreducible Ring-LPN

We start by comparing parameters for the PCGs based on the reducible and irreducible variants of ring-LPN. Recall that in the reducible case, *F* (*X*) splits completely into linear factors modulo *p*, so we can obtain OLEs or triples over Z*p*(or an extension field F*pd*). To improve computational efficiency, we use the cyclotomic polynomial *F* (*X*) = *X* *N* + 1, for *N* a power of two. In the case where *F* (*X*) is irreducible, we only produce a single, large OLE/triple over Z*p*[*X*]*=F*(*X*).

Reducible Ring-LPN Parameters. We consider a field F = Z*p*of size *j*F*j* 2 128. As in our applications, we focus on the case where there is a factor *fi*of degree *n* = *N=k*, for some *k*, which has sparsity 1, such as when *N* is a power of two and *F* (*X*) = *X* *N* + 1 splits completely into *N* linear factors modulo *p*. From the analysis in Section 8.2, we can reduce an instance modulo a 1-sparse factor *fi*of degree *n* = 2 *i*, reducing the expected number of noisy coordinates to *w=c* 1 <u>1</u> *wi*= *w cn* + (*c*(*n* 1) + *w*) 1*;* *n*

the dimension to *ni*= (*c* 1) 2 *i*, and the number of samples to *qi*= *c* 2 *i*. In our experiments, we found that the optimal behavior for the adversary was always to pick the smallest *i* such that the new weight *wi*of the noise is not higher than the dimension *ni*(such that the reduced instance is still uniquely decodable and is not statistically close to random). For security parameter = 80 (resp. = 128), the smallest such *i* is *i* = 6 (resp. *i* = 7). In Table 1, we provide various choices of parameters (*;N;c;w*) such that the best attack on any reduced instance requires at least 2 multiplications over a field F of size *j*F*j* 2 128. Observe that increasing *N* does not allow increasing the noise weight, since the best attack always exploits the structure of *F* (*X*) by reducing to a much smaller dimension. The table also presents the concrete seed sizes and computational requirements for our PCG for OLE, based on Theorem 4.1 (and with optimizations due to the regular error distribution). Our conservative estimates of the running time of the statistical decoding attack have better asymptotic complexity than the ISD attacks, according to our analysis in Section 8; and indeed, we found statistical decoding to always give the best available attack. Given that statistical de- coding should not generally perform better than ISD [DAT17], this suggests that our estimation of the cost of statistical decoding might be overly conservative, meaning that our parameters might be slightly pessimistic. When using a smaller field F⁰, the parameters in Table 1 change as follows: the size of the seed, as it is counted as a number of group elements, grows roughly by a factor log₂ *j*F*j=* log₂ *j*F⁰*j*, the stretch and the number of PRG calls decrease by the same factor (e.g. about a factor 2 when using F with log₂ *j*F⁰*j* 64, meaning that the running time for generating *N* OLEs over F⁰ decrease by a factor 2 compared to OLEs over F). The reduction in the number of PRG calls requires encoding multiple field elements into a PRG output; for example, using AES, a single PRG call produces 128 pseudorandom bits, which suffices to “pack” two elements over a 64-bit field using an appropriate encoding.

Table 1: Concrete parameters and seed size (per party, counted as equivalent number of field elements) for our

PCG for OLE over Z*p* from reducible ring-LPN, where *p* = 1 mod 2*N*, log*p* 128, for various, *N*, syndrome

|PCG for OLE over Z|from reducible ring-LPN, where p = 1 mod 2N, log p||128, for various, N, syndrome|
|---|---|---|---|
|compression factor c, and number of noisy coordinates w. ‘Stretch’, computed as 2N=(seed size), is the ratio||||
|between storing a full random OLE (i.e., 2N field elements) and the smaller PCG seed. #PRG calls is computed||||
|as 4 Ncw. Parameters are chosen to achieve details on how the bit-security is estimated). This setting is useful for generating batches of N OLE correlations||-bits of security against known attacks (see Section 9.1 for the||
|or authenticated triples over Z of how to update the table for smaller field sizes.|, or small inner-product correlations (Section 7.2). See Section 9.1 for estimations|||
||20 20 20 20 20 20 25 25 25 25 25 25|i 17:4 15:0 13:9 18:6 16:3 15:1 17:7 15:3 14:2 19:0 16:6 15:4|29:6 29:3 29:7 30:2 30:0 30:4 34:6 34:3 34:7 35:2 35:0 35:4|

*p*

<u>N c w (i;w) Seed size Stretch # R-mults #PRG calls</u>

80 2 2 97 (6*;*74) 2 12 4 2 80 2 4 40 (6*;*37) 2 65 16 2 80 2 8 26 (6*;*25) 2 139 64 2

128 2 2 152 (7*;*121) 2 5 4 2 128 2 4 64 (7*;*60) 2 27 16 2 128 2 8 41 (7*;*40) 2 59 64 2

80 2 2 97 (6*;*74) 2 306 4 2 80 2 4 40 (6*;*37) 2 1654 16 2 80 2 8 26 (6*;*25) 2 3623 64 2

128 2 2 152 (7*;*121) 2 130 4 2 128 2 4 64 (7*;*60) 2 673 16 2 128 2 8 41 (7*;*40) 2 1513 64 2

Irreducible Case. We consider a field F = Z*p*of size *j*F*j* 2 128. We consider various choices of parameters (*N;c;w*), such that the time complexity of the best attack, with statistical decoding or any attack from the ISD family, takes time at least 2 (using all the optimizations discussed previously). As with the reducible case, our analysis in Section 8 (which may be too pessimistic) shows the statistical decoding attack to have the best complexity. Given parameters (*;N;c;w*), our PCG for generating one pseudorandom OLE correlation over *R* has seeds of size equivalent to *w* (1 + log *N=* log*j*F*j*) + *w²* ((log*N* + 1)( + 2) + + log*j*F*j*)*=*log*j*F*j*

elements of F. When the error distribution is regular, the seed size can be reduced to

*w* (1 + log *N=* log*j*F*j*) + *w²* (log(2*Nc=w*) ( + 2) + + log*j*F*j*)*=*log*j*F*j:*

The computational complexity of the expansion algorithm is dominated by *c²* multiplications over *R*, and 4*Ncw* calls to a PRG for evaluating FullEval in the underlying SPFSS. The results are represented on Table 2. When using a smaller field F⁰, the size of the seed, as it is counted as a number of group elements, grows roughly by a factor log₂ *j*F*j=* log₂ *j*F⁰*j*, the stretch and the number of PRG calls decrease by the same factor (e.g. about a factor 2 when using F with log₂ *j*F⁰*j* 64, meaning that the running time for generating *N* OLEs over F⁰ decrease by a factor 2 compared to OLEs over F). The reduction in the number of PRG calls requires encoding multiple field elements into a PRG output; for example, using AES, a single PRG call produces 128 pseudorandom bits, which suffices to “pack” two elements over a 64-bit field using an appropriate encoding. Compared with the reducible case in Table 1, notice that when *N* = 2 20, using an irreducible *F* (*X*) allows the noise weight *w* to be around 10–40% smaller, for the same level of security. This saving is slightly more pronounced for larger *N*, since in the reducible version, an increase in *N* does not allow any reduction in the noise weight.

Table 2: Size of the seed (per party, counted as an equivalent number of field elements) for generating an OLE

correlation over *R* = F[*X*]*=F*(*X*), where *F* is irreducible, *d*log₂ *j*F*je* = 128 and deg*F* = *N* for various, *N*, syndrome compression factor *c*, and number of noisy coordinates *w*. ‘Stretch’ is computed as 2*N=*(seed size), and refers to the ratio between storing a full random OLE (i.e., 2*N* field elements) and storing the smaller seed. #PRG calls is computed as 4 *Ncw*. Parameters are chosen to achieve-bits of security against known attacks (see Section 9.1 for the details on how the bit-security is estimated). Note that increasing *c* always decreases the seed size, but increases the running time of the expansion algorithm. This setting is useful for generating large OLE correlations or authenticated triples over *R*, inner-product correlations (Section 7.2), or batch matrix product correlations (Section 7.4). See Section 9.1 for estimations of how to update the table for smaller field sizes.

### stretch # R-mults

|N c|w seed size|#PRG calls|
|---|---|---|
|20|16:0|28:9|
|20|14:2|28:9|
|20|13:1|29:3|
|20|17:6|29:8|
|20|15:8|29:8|
|20|14:7|30:2|
|25|16:1|33:8|
|25|14:3|33:8|
|25|13:3|34:2|
|25|17:9|34:7|
|25|16:0|34:7|
|25|15:0|35:1|

|80|2|2|60|2|32|4|2|
|---|---|---|---|---|---|---|---|
|80|2|4|30|2|114|16|2|
|80|2|8|20|2|238|64|2|
|128|2|2|108|2|10|4|2|
|128|2|4|54|2|37|16|2|
|128|2|8|36|2|76|64|2|
|80|2|2|55|2|941|4|2|
|80|2|4|28|2|3344|16|2|
|80|2|8|19|2|6834|64|2|
|128|2|2|103|2|279|4|2|
|128|2|4|52|2|1006|16|2|
|128|2|8|35|2|2085|64|2|

9.2 Estimated Costs and Runtimes for OLE and Triple Generation We now look more closely at the concrete costs of setting up and expanding the PCG seeds. Here, we consider the task of producing *N* = 2
20 OLEs or triples over Z*p*, using reducible ring-LPN. (For smaller numbers of outputs, see the discussion in Section 9.3.)

Methodology. We estimate both the computational cost of expanding a PCG seed, as well as the communication cost required to distribute the PCG seeds with either passive or active security. When measuring communication, we do not include the one-time setup phase for bootstrapping the protocol with an initial batch of OLEs or multiplication triples (in practice, these can be created with a non-PCG based protocol such as ring-LWE). For computation, the main costs in the expansion step are the DPF full-domain evaluations, and polynomial operations over *Rp*. We separately benchmarked these using the DPF code from [BCG + 19a], and NFLLib [ABG + 16] for polynomial arithmetic with a 124-bit modulus *p*, which is a product of two 62-bit primes (such that *Rp*splits completely into linear factors, by the CRT). The benchmarks were run on a single core of an Intel i7-7600U 2.8GHz processor. To estimate the communication complexity of setting up the seeds, we first assume that as a one-time setup, the parties already have access to a single pair of PCG seeds (for multiplication triples). We then measure the cost of bootstrapping this to produce another seed, based on the analysis from Section 6.3.

Cost Estimates for *N* = 2 20 Correlations. The results are in Table 3 for OLE, and Table 4 for authenticated triples. Note that compared with Table 1, the noise weight *w* has been rounded so it is divisible by *c*, so that *t* = *w=c* is an integer. We see that as the module-LPN compression factor *c* increases, the polynomial arithmetic gets more expensive, while the DPF cost first decreases at *c* = 4, and then goes back up at *c* = 8. This is because the DPF complexity scales

Table 3: Estimated costs for our PCG for producing *N* = 2 OLEs in Z*p*, with log*p* 124. Seed size is the

size of one party’s seed, setup comm. measures the per-party communication required to setup the PCG seeds (ignoring costs for correlated randomness that can come from a previous PCG).

|||||Setup comm. (MB)||Runtimes for Expand (s)|||
|---|---|---|---|---|---|---|---|---|
|c||w|Seed size (MB)|passive|active|R -mult (s)|DPF eval. (s)|Total (s)|
|80|2|96|2.69|6.14|6.69|0.4|9.8|10.2|
|80|4|40|0.52|1.17|1.28|1.4|7.5|8.9|
|80|8|32|0.35|0.78|0.86|5.3|9.3|14.6|
|128|2|152|6.37|14.63|15.92|0.4|12.6|13.0|
|128|4|64|1.26|2.86|3.12|1.4|8.6|10.0|
|128|8|40|0.55|1.22|1.34|5.3|14.4|19.7|
||||||20||||
|Table 4: Estimated costs for our PCG for producing size is the size of one party’s seed, setup comm. measures the per-party communication required to setup the PCG seeds (ignoring costs for correlated randomness that can come from a previous PCG).|||||N = 2 authenticated triples in Z|Runtimes for Expand (s)|p, with log|p 124. Seed|
|c||w|Seed size (MB)|Setup comm. (MB)||R -mult (s)|DPF eval. (s)|Total (s)|
|80|2|96|5.49||8.77|0.8|19.6|20.4|
|80|4|40|1.09||1.68|2.8|15.0|17.8|
|80|8|32|0.74||1.13|10.6|18.6|29.2|
|128|2|152|12.91|20.97||0.8|25.2|26.0|
|128|4|64|2.60||4.09|2.8|17.2|20.0|
|128|8|40|1.14||1.75|10.6|28.8|39.4|

with *c²t*, so doubling *c* only reduces its cost if *t* can be reduced by more than a factor of 4. The best choice for speed seems to be *c* = 4, where we are able to silently expand over 100 thousand OLEs per second at the 128-bit security level, with a seed size of around 1MB. When generating authenticated triples instead of OLEs, the seed size and runtimes increase by roughly a factor of two, while the setup communication cost is only slightly larger.

### 9.3 Comparison with OLE From Ring-LWE

In Table 5, we compare the cost of our OLE protocol from ring-LPN with the passively secure OLE protocol from ring-LWE by Baum et al [BEPU + 20]. For a 120-bit plaintext modulus, the protocol implemented in [BEPU + 20] has an average communication cost of 420 bits per party, for each OLE. Excluding the one-time setup, our ring-LPN based protocol with *c* = 4 improves upon the communication complexity of ring-LWE when producing *N* = 65536 or more OLEs. With *c* = 2, when *N* is 32768 or 65536, the ring-LPN protocol requires more OLEs as preprocessing than it produces as output, so is not beneficial; instead, the asymptotic improvement in communication starts to take effect when *N* is half a million or more.

## 10 PCG for OLE from Standard LPN

In this section, we provide new constructions of PCG for OLE and matrix product correlations. Unlike the other PCG constructed in this work, the PCGs of this section do not rely on the *R*-LPN assumption, but on the standard LPN assumption (or alternatively, some variant of it with a structured parity-check matrix *H* allowing for fast multiplication with *H*). The PCG for OLE we obtain is typically less efficient than those based on *R*-LPN, but rely on more

Table 5: Comparing costs of our passively secure OLE protocol from ring-LPN with ring-LWE. # OTs and #OLEs

measure the amount of correlated randomness required to run one instance of the protocol. Communication is averaged per-party

<u>Ring-LWE costs [BEPU</u> + <u>20]</u>

|N|c w||Ring-LPN costs|||
|---|---|---|---|---|---|
|||# OTs|# OLEs|Comm. (MB)|Comm. (MB)|
|32768|2 152|877952|115520|10.9|1.72|
|65536|2 152|970368|115520|11.6|3.44|
|131072|2 152|1062784|115520|12.4|6.88|
|262144|2 152|1155200|115520|13.1|13.78|
|524288|2 152|1247616|115520|13.9|27.5|
|32768|4 64|188416|20480|2.19|1.72|
|65536|4 64|204800|20480|2.33|3.44|
|131072|4 64|221184|20480|2.46|6.88|
|262144|4 64|237568|20480|2.59|13.8|
|524288 well-studied assumption, hence can be seen as a conservative alternative.|4 64|253952|20480|2.73|27.5 Furthermore, our|

LPN-based PCGs for matrix multiplication correlations is incomparable to our *R*-LPN-based PCG for batch matrix multiplication: while the later generates large batch of small-to-moderate size matrix multiplication triples, the former allows to generate one (potentially very large) matrix multiplication triple. Our starting point is the LPN-based construction of PCGs for bilinear correlations from Boyle et al. [BCG + 19b], over an arbitrary field F, which we recall below. In [BCG + 19b], this construction was estimated to be mainly of theoretical interest: generating *m* = *O*(*n*) OLEs with this PCG requires *O*(*n⁴*) arithmetic operations, and a seed of size *O*(*t²* log*n*). When *n* is large enough for the seed to provide a nontrivial compression factor, the computational overhead is already impractical. In this section, we will give an optimized variant of this construction which requires *O*(*n* *!* ) arithmetic operations, where*!* is the matrix multiplication exponent. This cost can be further reduced to *O*(*n²* log*n*) by relying on any variant of LPN with structured parity-check matrices allowing for fast (*o*(*n²*)) matrix-vector products, such as a Toeplitz or a quasi-cyclic parity-check matrix.

### 10.1 The Construction of [BCG

+ 19b]

Theorem 10.1 (From [BCG + 19b], Section 6) *Suppose the* dual-LPN*m;n;tassumption holds* *relative to H, and that* SPFSS *is a secure sum of point function secret sharing scheme. Then* *the construction G*bil*(Fig. 14) is a secure PCG for general bilinear correlations.*

Efficiency. Instantiating the SPFSS as in [BCGI18], the setup algorithm of *G*biloutputs seeds of size *t²* (*d*log *ne*( + 2) + + log₂ *j*F*j*) bits, which amounts to *O*~(*t²* log*n*) field elements over a large field (log₂ *j*F*j* = *O*()). Expanding the seed involves (*tn*) 2 PRG evaluations and *O*(*m n*) 2 = *O*(*n⁴*) arithmetic operations.

### 10.2 Optimized Construction

The main source of inefficiency in the above construction stems from the fact that to compute a bilinear function of two (pseudo)random strings, the expansion algorithm must obtain the tensor product between the pseudorandom strings (*~x₀;~x₁*). In the construction, it holds that

*~x* = *H ~e* for = 0*;*

### Construction Gbil

Parameters:*;m;n;t; 2* N, where *n > m*; a field F. A parity-check matrix *H 2* F *m n* for a code of dimension *n m* and number of samples *m* over F. A bilinear function *B~c*: F *n* F *n* *!* F*;* (*~; ~*) *7!h~c;*(*~ ~*)*i*.

Gen: On input 1 : $*n*

1.Pick two random sparse vectors *~e₀;~e₁* F with wt(*~e₀*) = wt(*~e₁*) = *t*. Define *f* to be the sum of *t²* point functions whose evaluation on its entire domain is *~e₀ ~e₁*.
$

2.Compute (*K₀;K₁*) SPFSS*:* Gen(1*;f*).
3.Let k₀ (*K₀;~e₀*) and k₁ (*K₁;~e₁*).
4.Output (k₀*;*k₁).
Expand: On input (*;* k), parse k as (*K;~e*). Set *~x H ~e*. Compute *~u* *n*2 <u>SPFSS: FullEval(;K) in Fp, and set ~z h~c;(H H) ~u i. Output (~x;~z).</u>

Figure 14: PCG for Bilinear Correlations

hence

*~x₀ ~x₁* = (*H ~e₀*) (*H ~e₁*) = (*H H*) (*~e₀ ~e₁*)*:*

The tensor product between noise vectors *~e₀ ~e₁* is compressed using SPFSS. Then, the *O*(*n⁴*) overhead comes from multiplying this length-*n²* vector with an *m² n²* matrix. However, computing the above can be done much more efficiently by observing that the *n n* square | matrix *~x₀ ~x₁* contains exactly the same entries as the tensor product between *~x₀* and *~x₁*. Hence, any bilinear function of (*~x₀;~x₁*) can be trivially computed as a linear combination between the | | components of *~x₀ ~x₁*. Furthermore, we can compute *~x₀ ~x₁* much more efficiently using the following identity:

|

|||||
|---|---|---|
||||||
|||2||
|||||

*~x₀ ~x₁* = (*H ~e₀*) (*H ~e₁*) = *H* (*~e₀ ~e₁*) *H :*

As before, *~e₀ ~e₁* can be generated from an *O*(*t* log*n*)-long seed using SPFSS. But now, |*!* computing *H* (*~e₀ ~e₁*) *H* requires only *O*(*n*) operations, where*!* is the matrix multiplication exponent. Furthermore, if *H* is a structured matrix, this can be computed even more efficiently; for example, taking *H* to be a Toeplitz matrix or a quasi-cyclic matrix leads to a computation cost of *O*(*n²* log*n*) for generating *m* = *O*(*n*) OLEs, under well-established variants of the LPN assumption. This provides a less efficient, but still feasible more conservative alternative to our construction based on the splittable variant of *R*-LPN. Hence, we directly get:

Theorem 10.2 *Suppose the* dual-LPN*m;n;tassumption holds relative to random Toeplitz matri-* *ces, and that* SPFSS *is a secure SPFSS scheme. Then the construction described in this section* *is a secure PCG for general bilinear correlations with seeds of size O*~(*t²* log*n*) *field elements* *over a large field (*log₂ *j*F*j* = *O*()*). Expanding the seed involves O*((*tn*)) *PRG evaluations and* *O*(*n²* log*n*) *arithmetic operations.*

### 10.3 LPN-Based PCG for Matrix Multiplication

In this section, we describe two new variants of the PCG described in the previous section, which allow to generate large matrix multiplication triples over F (with different parameters tradeoffs across the two constructions).

First Construction. The first construction directly generalizes the construction above to generating pseudorandom correlations (*X₀;Z₀*) *2* F *m m* F *m m* and (*X₁;Z₁*) *2* F *m m* F *m m* | such that *X₀ X₁* = *Z₀* + *Z₁*.

Parameters: 1*;m;n;t;p 2* N, where *n > m*. A parity-check matrix *H 2* F *m n* for a code of dimension *n m* and number of samples *m* over F.

### Gen: On input 1 :

1.Pick two random matrices *E₀;E₁ 2* F
*n m* such that each column of *E₀;E₁* contains exactly *t* nonzero entries. |

2.Compute SPFSS keys (*K₀;K₁*) which generate shares of *E₀ E₁*.
3.Let k₀ (*K₀;E₀*) and k₁ (*K₁;E₁*).
4.Output (k₀*;*k₁).
Expand: On input (*;* k), parse k as (*K;E*). Set *X H E*. Compute *U* SPFSS*:* FullEval(*;K*) in F *n n* and set *Z H U H* |. Output (*X;Z*).

The correctness and security of the construction follows by the same argument as for *G*bil (Section 10.2). Regarding efficiency, the expansion cost is optimal, *O*(*n* *!* ) using random parity- check matrices, or *O*(*n²* log*n*) using Toeplitz or quasi-cyclic matrices. Note that this means that generating a pseudorandom *m m* matrix multiplication triples via this method is even faster than computing the product of random *m m* matrices in the clear (for *m* = *O*(*n*)). On the downside, the size of the seed grows now as *O*(*t²n²* log*n*); i.e., the expansion is limited to subquadratic in the seed size. The next construction allows to achieve much better seed size (logarithmic in *n*), but has a higher computational complexity.

Second Construction. The second construction is similar in spirit to the previous one; it achieves a much smaller seed size, albeit with a larger computational cost *O*(*n⁴* log*n*). The high level idea is to generate each *m m* matrix *X* by constructing a length-*m²* vector *~x* = *H ~e*, where *H* is an *m² n²* parity-check matrix (e.g. a Toeplitz or quasi-cyclic matrix), and *~e* is a 2 *m n*2 length-*n t*-sparse vector. Let *Hi2* F the matrix comprising the rows (*i* 1) *m*+ 1 to *i m* *m n*2 of the matrix *H*, i.e. *H* is horizontally parsed as (very flat) matrices *H₁;:::Hm2 F*. Then, we define *X* to be the *m m* matrix whose *i*-th column is equal two *Hi~e*. In other words, the *m*2*m m* *i*-th column of *X* contains the entries (*i* 1) *m* + 1 to *i m* of *~x*. We let mat : F *7!* F denote the operator mapping an *m²*-vector to an *m m* matrix.

*m*2*n*2 Parameters: 1*;m;n;t;p 2* N, where *n > m*. A parity-check matrix *H 2* F for a code of dimension *n² m²* and number of samples *m²* over F.

### Gen: On input 1 :

*n*2

1.Pick two random vectors *~e₀;~e₁* F with exactly *t* nonzero entries.
|

2.Compute SPFSS keys (*K₀;K₁*) which generate shares of *~e₀ ~e₁*.

3.Let k₀ (*K₀;~e₀*) and k₁ (*K₁;~e₁*).
4.Output (k₀*;*k₁).
Expand: On input (*;* k), parse k as (*K;~e*). Set *X* mat(*H ~e*). Compute *U* *n*2*n*2 SPFSS*:* FullEval(*;K*) in F and set

X *m* | *Z HiU H* *i* *:* *i*=1

### Output (X;Z).

Security follows from the same argument as previously. For correctness, note that by defini- P

|||> m i=1|i|i >|
|---|---|---|---|---|
|m i=1 i|> i >||||

tion we can write *X* = [*H₁ ~e jj Hm~e*], which implies *X₀ X₁* = *H ~e₀* (*H ~e₁*) = P *H* (*~e₀ ~e₁*) *H* and thus correctness follows. The seed size is now much smaller, *O*(*t²* log*n*); however, the computational complexity is dominated by the matrix product *H U*, which takes time *O*(*n⁴* log*n*) if *H* is a structured ma- trix. This provides a much better tradeoff than when generating OLEs: the cost of generating *m* = *O*(*n*) OLEs with (our improved version of) *G*bilis *O*~(*n²*), quadratically larger than the cost of generating them in the clear. However, the cost of generating a large random matrix multipli- *p* cation correlation is *M* (*n*) = *O*(*n* *!* ), meaning that the cost of our algorithm is below *O*(*M M*) when the matrix multiplication algorithm is implemented with e.g. Strassen’s algorithm.

## 11 Acknowledgements

We would like to thank Vadim Lyubashevsky, Chris Peikert, Ronny Roth and Jean-Pierre Tillich for helpful discussions and pointers. We also thank Damiano Abram for various corrections, including pointing out a security flaw in a previous version of the malicious DPF protocol.

E. Boyle, N. Gilboa, and Y. Ishai supported by ERC Project NTSC (742754). E. Boyle
additionally supported by ISF grant 1861/16, AFOSR Award FA9550-17-1-0069, ERC Project HSS (852952), and a Google Research Award. G. Couteau supported by ERC Project PREP- CRYPTO (724307) and ANR SCENE. N. Gilboa additionally supported by ISF grant 1638/15, ISF 2951/20, ERC grant 876110, and a grant by the BGU Cyber Center. Y. Ishai additionally supported by NSF-BSF grant 2015782, BSF grant 2018393, ISF grant 2774/20, and a grant from the Ministry of Science and Technology, Israel and Department of Science and Technology, Government of India. L. Kohl is funded by NWO Gravitation project QSC. Most research of L. Kohl was done while at Technion, supported by ERC Project NTSC (742754). Research of L. Kohl was done in part while at Karlsruhe Institute of Technology, supported by ERC Project PREP-CRYPTO (724307) and DFG grant HO 4534/2-2. P. Scholl supported by the Danish Independent Research Council under Grant-IDs 6108-00169 (FoCC) and 0165-00107B (C3PO), and an Aarhus University Research Foundation starting grant.

## References

[ABG + 16]Carlos Aguilar Melchor, Joris Barrier, Serge Guelton, Adrien Guinet, Marc-Olivier Killijian, and Tancrède Lepoint. NFLlib: NTT-based fast lattice library. In Kazue Sako, editor, *CT-RSA 2016*, volume 9610 of *LNCS*, pages 341–356. Springer, Heidelberg, February / March 2016.

[ACLS18]Sebastian Angel, Hao Chen, Kim Laine, and Srinath T. V. Setty. PIR with compressed queries and amortized query processing. In *2018 IEEE Symposium* *on Security and Privacy*, pages 962–979. IEEE Computer Society Press, May 2018.

[ACPS09]Benny Applebaum, David Cash, Chris Peikert, and Amit Sahai. Fast crypto- graphic primitives and circular-secure encryption based on hard learning problems. In Shai Halevi, editor, *CRYPTO 2009*, volume 5677 of *LNCS*, pages 595–618. Springer, Heidelberg, August 2009.

[AJ01]Abdulrahman Al Jabri. A statistical decoding algorithm for general linear block codes. In *IMA International Conference on Cryptography and Coding*, pages 1–8. Springer, 2001.

+ [BBC 19]Marco Baldi, Alessandro Barenghi, Franco Chiaraluce, Gerardo Pelosi, and Paolo Santini. Design of LEDAkem and LEDApkc instances with tight parameters and bounded decryption failure rate. 2019. https://www.ledacrypt.org/archives/ official_comment.pdf.

+ [BCG 17]Elette Boyle, Geoffroy Couteau, Niv Gilboa, Yuval Ishai, and Michele Orrù. Ho- momorphic secret sharing: Optimizations and applications. In Bhavani M. Thu- raisingham, David Evans, Tal Malkin, and Dongyan Xu, editors, *ACM CCS 2017*, pages 2105–2122. ACM Press, October / November 2017.

+ [BCG 19a]Elette Boyle, Geoffroy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, Peter Rindal, and Peter Scholl. Efficient two-round OT extension and silent non-interactive secure computation. In Lorenzo Cavallaro, Johannes Kinder, XiaoFeng Wang, and Jonathan Katz, editors, *ACM CCS 2019*, pages 291–308. ACM Press, November

2019.
+ [BCG 19b]Elette Boyle, Geoffroy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, and Peter Scholl. Efficient pseudorandom correlation generators: Silent OT extension and more. In Alexandra Boldyreva and Daniele Micciancio, editors, *CRYPTO 2019,* *Part III*, volume 11694 of *LNCS*, pages 489–518. Springer, Heidelberg, August

2019.
[BCGI18]Elette Boyle, Geoffroy Couteau, Niv Gilboa, and Yuval Ishai. Compressing vector OLE. In David Lie, Mohammad Mannan, Michael Backes, and XiaoFeng Wang, editors, *ACM CCS 2018*, pages 896–912. ACM Press, October 2018.

[BDOZ11]Rikke Bendlin, Ivan Damgård, Claudio Orlandi, and Sarah Zakarias. Semi- homomorphic encryption and multiparty computation. In Kenneth G. Paterson, editor, *EUROCRYPT 2011*, volume 6632 of *LNCS*, pages 169–188. Springer, Hei- delberg, May 2011.

[Bea91]Donald Beaver. Efficient multiparty protocols using circuit randomization. In *CRYPTO ’91*, pages 420–432, 1991.

[Bea92]Donald Beaver. Efficient multiparty protocols using circuit randomization. In Joan Feigenbaum, editor, *CRYPTO’91*, volume 576 of *LNCS*, pages 420–432. Springer, Heidelberg, August 1992.

+ [BEPU 20]Carsten Baum, Daniel Escudero, Alberto Pedrouzo-Ulloa, Peter Scholl, and Juan Ramón Troncoso-Pastoriza. Efficient protocols for oblivious linear function evaluation from ring-LWE. In Clemente Galdi and Vladimir Kolesnikov, editors, *SCN 20*, volume 12238 of *LNCS*, pages 130–149. Springer, Heidelberg, September

2020.
[BFKL94]Avrim Blum, Merrick L. Furst, Michael J. Kearns, and Richard J. Lipton. Cryp- tographic primitives based on hard learning problems. In Douglas R. Stinson,

editor, *CRYPTO’93*, volume 773 of *LNCS*, pages 278–291. Springer, Heidelberg, August 1994.

[BGI15]Elette Boyle, Niv Gilboa, and Yuval Ishai. Function secret sharing. In Elisabeth Oswald and Marc Fischlin, editors, *EUROCRYPT 2015, Part II*, volume 9057 of *LNCS*, pages 337–367. Springer, Heidelberg, April 2015.

[BGI16a]Elette Boyle, Niv Gilboa, and Yuval Ishai. Breaking the circuit size barrier for secure computation under DDH. In Matthew Robshaw and Jonathan Katz, ed- itors, *CRYPTO 2016, Part I*, volume 9814 of *LNCS*, pages 509–539. Springer, Heidelberg, August 2016.

[BGI16b]Elette Boyle, Niv Gilboa, and Yuval Ishai. Function secret sharing: Improvements and extensions. In Edgar R. Weippl, Stefan Katzenbeisser, Christopher Kruegel, Andrew C. Myers, and Shai Halevi, editors, *ACM CCS 2016*, pages 1292–1303. ACM Press, October 2016.

[BGI17]Elette Boyle, Niv Gilboa, and Yuval Ishai. Group-based secure computation: Optimizing rounds, communication, and computation. In Jean-Sébastien Coron and Jesper Buus Nielsen, editors, *EUROCRYPT 2017, Part II*, volume 10211 of *LNCS*, pages 163–193. Springer, Heidelberg, April / May 2017.

[BGI19]Elette Boyle, Niv Gilboa, and Yuval Ishai. Secure computation with preprocess- ing via function secret sharing. In Dennis Hofheinz and Alon Rosen, editors, *TCC 2019, Part I*, volume 11891 of *LNCS*, pages 341–371. Springer, Heidelberg, December 2019.

[BJMM12]Anja Becker, Antoine Joux, Alexander May, and Alexander Meurer. Decoding ran- dom binary linear codes in 2 *n=*20 : How 1 + 1 = 0 improves information set decod- ing. In David Pointcheval and Thomas Johansson, editors, *EUROCRYPT 2012*, volume 7237 of *LNCS*, pages 520–536. Springer, Heidelberg, April 2012.

[BKS19]Elette Boyle, Lisa Kohl, and Peter Scholl. Homomorphic secret sharing from lattices without FHE. In Yuval Ishai and Vincent Rijmen, editors, *EURO-* *CRYPT 2019, Part II*, volume 11477 of *LNCS*, pages 3–33. Springer, Heidelberg, May 2019.

[BKW00]Avrim Blum, Adam Kalai, and Hal Wasserman. Noise-tolerant learning, the parity problem, and the statistical query model. In *32nd ACM STOC*, pages 435–440. ACM Press, May 2000.

[BL12]Daniel J Bernstein and Tanja Lange. Never trust a bunny. In *International* *Workshop on Radio Frequency Identification: Security and Privacy Issues*, pages 137–148. Springer, 2012.

[BLP11]Daniel J. Bernstein, Tanja Lange, and Christiane Peters. Smaller decoding expo- nents: Ball-collision decoding. In Phillip Rogaway, editor, *CRYPTO 2011*, volume 6841 of *LNCS*, pages 743–760. Springer, Heidelberg, August 2011.

[BNO19]Aner Ben-Efraim, Michael Nielsen, and Eran Omri. Turbospeedz: Double your on- line SPDZ! Improving SPDZ using function dependent preprocessing. In Robert H. Deng, Valérie Gauthier-Umaña, Martín Ochoa, and Moti Yung, editors, *ACNS 19*, volume 11464 of *LNCS*, pages 530–549. Springer, Heidelberg, June 2019.

[BV11a]Zvika Brakerski and Vinod Vaikuntanathan. Efficient fully homomorphic encryp- tion from (standard) LWE. In Rafail Ostrovsky, editor,*52nd FOCS*, pages 97–106. IEEE Computer Society Press, October 2011.

[BV11b]Zvika Brakerski and Vinod Vaikuntanathan. Fully homomorphic encryption from ring-LWE and security for key dependent messages. In Phillip Rogaway, editor, *CRYPTO 2011*, volume 6841 of *LNCS*, pages 505–524. Springer, Heidelberg, Au- gust 2011.

+ [CDI 19]Melissa Chase, Yevgeniy Dodis, Yuval Ishai, Daniel Kraschewski, Tianren Liu, Rafail Ostrovsky, and Vinod Vaikuntanathan. Reusable non-interactive se- cure computation. In Alexandra Boldyreva and Daniele Micciancio, editors, *CRYPTO 2019, Part III*, volume 11694 of *LNCS*, pages 462–488. Springer, Hei- delberg, August 2019.

+ [CGGU 13]Alain Couvreur, Philippe Gaborit, Valérie Gauthier-Umana, Ayoub Otmani, and Jean-Pierre Tillich. Distinguisher-based attacks on public-key cryptosystems using reed-solomon codes. *arXiv preprint arXiv:1307.6458*, 2013.

+ [CKR 20]Hao Chen, Miran Kim, Ilya P. Razenshteyn, Dragos Rotaru, Yongsoo Song, and Sameer Wagh. Maliciously secure matrix multiplication with applications to private deep learning. In Shiho Moriai and Huaxiong Wang, editors, *ASI-* *ACRYPT 2020, Part III*, volume 12493 of *LNCS*, pages 31–59. Springer, Heidel- berg, December 2020.

[Cou19]Geoffroy Couteau. A note on the communication complexity of multiparty com- putation in the correlated randomness model. In Yuval Ishai and Vincent Rijmen, editors, *EUROCRYPT 2019, Part II*, volume 11477 of *LNCS*, pages 473–503. Springer, Heidelberg, May 2019.

[DAT17]Thomas Debris-Alazard and Jean-Pierre Tillich. Statistical decoding. In *2017* *IEEE International Symposium on Information Theory (ISIT)*, pages 1798–1802. IEEE, 2017.

+ [DGN 17]Nico Döttling, Satrajit Ghosh, Jesper Buus Nielsen, Tobias Nilges, and Roberto Trifiletti. TinyOLE: Efficient actively secure two-party computation from oblivi- ous linear function evaluation. In Bhavani M. Thuraisingham, David Evans, Tal Malkin, and Dongyan Xu, editors, *ACM CCS 2017*, pages 2263–2276. ACM Press, October / November 2017.

+ [DKL 13]Ivan Damgård, Marcel Keller, Enrique Larraia, Valerio Pastro, Peter Scholl, and Nigel P. Smart. Practical covertly secure MPC for dishonest majority-or: Break- ing the SPDZ limits. In Jason Crampton, Sushil Jajodia, and Keith Mayes, ed- itors, *ESORICS 2013*, volume 8134 of *LNCS*, pages 1–18. Springer, Heidelberg, September 2013.

[DNNR17]Ivan Damgård, Jesper Buus Nielsen, Michael Nielsen, and Samuel Ranellucci. The TinyTable protocol for 2-party secure computation, or: Gate-scrambling revisited. In Jonathan Katz and Hovav Shacham, editors, *CRYPTO 2017, Part I*, volume 10401 of *LNCS*, pages 167–187. Springer, Heidelberg, August 2017.

[DP12]Ivan Damgård and Sunoo Park. How practical is public-key encryption based on LPN and ring-LPN? Cryptology ePrint Archive, Report 2012/699, 2012. https: //eprint.iacr.org/2012/699.

[DPSZ12]Ivan Damgård, Valerio Pastro, Nigel P. Smart, and Sarah Zakarias. Multiparty computation from somewhat homomorphic encryption. In Reihaneh Safavi-Naini and Ran Canetti, editors, *CRYPTO 2012*, volume 7417 of *LNCS*, pages 643–662. Springer, Heidelberg, August 2012.

[Ds17]Jack Doerner and abhi shelat. Scaling ORAM for secure computation. In Bha- vani M. Thuraisingham, David Evans, Tal Malkin, and Dongyan Xu, editors, *ACM* *CCS 2017*, pages 523–535. ACM Press, October / November 2017.

[EKM17]Andre Esser, Robert Kübler, and Alexander May. LPN decoded. In Jonathan Katz and Hovav Shacham, editors, *CRYPTO 2017, Part II*, volume 10402 of *LNCS*, pages 486–514. Springer, Heidelberg, August 2017. + [FGUO 13]Jean-Charles Faugere, Valérie Gauthier-Umana, Ayoub Otmani, Ludovic Perret, and Jean-Pierre Tillich. A distinguisher for high-rate mceliece cryptosystems. *IEEE Transactions on Information Theory*, 59(10):6830–6844, 2013.

[FKI06]Marc PC Fossorier, Kazukuni Kobara, and Hideki Imai. Modeling bit flipping decoding based on nonorthogonal check sums with application to iterative decod- ing attack of mceliece cryptosystem. *IEEE Transactions on Information Theory*, 53(1):402–411, 2006.

[FKOS15]Tore Kasper Frederiksen, Marcel Keller, Emmanuela Orsini, and Peter Scholl. A unified approach to MPC with preprocessing using OT. In Tetsu Iwata and Jung Hee Cheon, editors, *ASIACRYPT 2015, Part I*, volume 9452 of *LNCS*, pages 711–735. Springer, Heidelberg, November / December 2015.

[FS09]Matthieu Finiasz and Nicolas Sendrier. Security bounds for the design of code- based cryptosystems. In Mitsuru Matsui, editor, *ASIACRYPT 2009*, volume 5912 of *LNCS*, pages 88–105. Springer, Heidelberg, December 2009.

[GI14]Niv Gilboa and Yuval Ishai. Distributed point functions and their applications. In Phong Q. Nguyen and Elisabeth Oswald, editors, *EUROCRYPT 2014*, volume 8441 of *LNCS*, pages 640–658. Springer, Heidelberg, May 2014.

[GJL15]Qian Guo, Thomas Johansson, and Carl Löndahl. A new algorithm for solving ring-lpn with a reducible polynomial. *IEEE Transactions on Information Theory*, 61(11):6204–6212, 2015.

[GMW87]Oded Goldreich, Silvio Micali, and Avi Wigderson. How to play any mental game or A completeness theorem for protocols with honest majority. In Alfred Aho, editor, *19th ACM STOC*, pages 218–229. ACM Press, May 1987.

[GN19]Satrajit Ghosh and Tobias Nilges. An algebraic approach to maliciously secure private set intersection. In Yuval Ishai and Vincent Rijmen, editors, *EURO-* *CRYPT 2019, Part III*, volume 11478 of *LNCS*, pages 154–185. Springer, Heidel- berg, May 2019.

[HIMV19]Carmit Hazay, Yuval Ishai, Antonio Marcedone, and Muthuramakrishnan Venki- tasubramaniam. LevioSA: Lightweight secure arithmetic computation. In Lorenzo Cavallaro, Johannes Kinder, XiaoFeng Wang, and Jonathan Katz, editors, *ACM* *CCS 2019*, pages 327–344. ACM Press, November 2019. + [HKL 12]Stefan Heyse, Eike Kiltz, Vadim Lyubashevsky, Christof Paar, and Krzysztof Pietrzak. Lapin: An efficient authentication protocol based on ring-LPN. In Anne Canteaut, editor, *FSE 2012*, volume 7549 of *LNCS*, pages 346–365. Springer, Heidelberg, March 2012.

[HOSS18a]Carmit Hazay, Emmanuela Orsini, Peter Scholl, and Eduardo Soria-Vazquez. Con- cretely efficient large-scale MPC with active security (or, TinyKeys for TinyOT). In Thomas Peyrin and Steven Galbraith, editors, *ASIACRYPT 2018, Part III*, volume 11274 of *LNCS*, pages 86–117. Springer, Heidelberg, December 2018.

[HOSS18b]Carmit Hazay, Emmanuela Orsini, Peter Scholl, and Eduardo Soria-Vazquez. TinyKeys: A new approach to efficient multi-party computation. In Hovav Shacham and Alexandra Boldyreva, editors, *CRYPTO 2018, Part III*, volume 10993 of *LNCS*, pages 3–33. Springer, Heidelberg, August 2018.

[HS13]Yann Hamdaoui and Nicolas Sendrier. A non asymptotic analysis of information set decoding. *IACR Cryptology ePrint Archive*, 2013:162, 2013.

[HSS17]Carmit Hazay, Peter Scholl, and Eduardo Soria-Vazquez. Low cost constant round MPC combining BMR and oblivious transfer. In Tsuyoshi Takagi and Thomas Peyrin, editors, *ASIACRYPT 2017, Part I*, volume 10624 of *LNCS*, pages 598–

628. Springer, Heidelberg, December 2017.
[IKM + 13]Yuval Ishai, Eyal Kushilevitz, Sigurd Meldgaard, Claudio Orlandi, and Anat Paskin-Cherniavsky. On the power of correlated randomness in secure compu- tation. In Amit Sahai, editor, *TCC 2013*, volume 7785 of *LNCS*, pages 600–620. Springer, Heidelberg, March 2013.

[IKOS04]Yuval Ishai, Eyal Kushilevitz, Rafail Ostrovsky, and Amit Sahai. Batch codes and their applications. In László Babai, editor, *36th ACM STOC*, pages 262–271. ACM Press, June 2004.

[IPS08]Yuval Ishai, Manoj Prabhakaran, and Amit Sahai. Founding cryptography on oblivious transfer-efficiently. In David Wagner, editor, *CRYPTO 2008*, volume 5157 of *LNCS*, pages 572–591. Springer, Heidelberg, August 2008.

[IPS09]Yuval Ishai, Manoj Prabhakaran, and Amit Sahai. Secure arithmetic computation with no honest majority. In *TCC’09*, pages 294–314, 2009.

[JVC18]Chiraag Juvekar, Vinod Vaikuntanathan, and Anantha Chandrakasan. GAZELLE: A low latency framework for secure neural network inference. In *USENIX 2018*, pages 1651–1669, 2018.

[Kil88]Joe Kilian. Founding cryptography on oblivious transfer. In *20th ACM STOC*, pages 20–31. ACM Press, May 1988.

[KKW18]Jonathan Katz, Vladimir Kolesnikov, and Xiao Wang. Improved non-interactive zero knowledge with applications to post-quantum signatures. In David Lie, Mo- hammad Mannan, Michael Backes, and XiaoFeng Wang, editors, *ACM CCS 2018*, pages 525–537. ACM Press, October 2018.

[KOS16]Marcel Keller, Emmanuela Orsini, and Peter Scholl. MASCOT: Faster malicious arithmetic secure computation with oblivious transfer. In Edgar R. Weippl, Stefan Katzenbeisser, Christopher Kruegel, Andrew C. Myers, and Shai Halevi, editors, *ACM CCS 2016*, pages 830–842. ACM Press, October 2016.

[Kot92]Ralf Kotter. An unified description of an error locating procedure for linear codes. *Proc. IAACCT, Voneshta Voda, Bulgaria*, 1992.

[KPR18]Marcel Keller, Valerio Pastro, and Dragos Rotaru. Overdrive: Making SPDZ great again. In Jesper Buus Nielsen and Vincent Rijmen, editors, *EUROCRYPT 2018,* *Part III*, volume 10822 of *LNCS*, pages 158–189. Springer, Heidelberg, April / May

2018.

[KSS09]Vladimir Kolesnikov, Ahmad-Reza Sadeghi, and Thomas Schneider. Improved garbled circuit building blocks and applications to auctions and computing min- ima. In Juan A. Garay, Atsuko Miyaji, and Akira Otsuka, editors, *CANS 09*, volume 5888 of *LNCS*, pages 1–20. Springer, Heidelberg, December 2009.

[LB88]Pil Joong Lee and Ernest F Brickell. An observation on the security of mceliece’s public-key cryptosystem. In *Workshop on the Theory and Application of of Cryp-* *tographic Techniques*, pages 275–280. Springer, 1988.

[Leo88]Jeffrey S Leon. A probabilistic algorithm for computing minimum weights of large error-correcting codes. *IEEE Transactions on Information Theory*, 34(5):1354– 1359, 1988.

[LP15]Helger Lipmaa and Kateryna Pavlyk. Analysis and implementation of an efficient ring-LPN based commitment scheme. In Michael Reiter and David Naccache, editors, *CANS 15*, LNCS, pages 160–175. Springer, Heidelberg, December 2015.

[LPR13]Vadim Lyubashevsky, Chris Peikert, and Oded Regev. A toolkit for ring-LWE cryptography. In Thomas Johansson and Phong Q. Nguyen, editors, *EURO-* *CRYPT 2013*, volume 7881 of *LNCS*, pages 35–54. Springer, Heidelberg, May

2013.
[LWYY22]Hanlin Liu, Xiao Wang, Kang Yang, and Yu Yu. The hardness of LPN over any integer ring and field for PCG applications. Cryptology ePrint Archive, Paper 2022/712, 2022.

[Lyu05]Vadim Lyubashevsky. The parity problem in the presence of noise, decoding random linear codes, and the subset sum problem. In *Approximation, randomiza-* *tion and combinatorial optimization. Algorithms and techniques*, pages 378–389. Springer, 2005.

[MBD + 18]Carlos Aguilar Melchor, Olivier Blazy, Jean-Christophe Deneuville, Philippe Ga- borit, and Gilles Zémor. Efficient encryption from random quasi-cyclic codes. *IEEE Trans. Information Theory*, 64(5):3927–3943, 2018.

[MCMMP14]Irene Márquez-Corbella, Edgar Martínez-Moro, and Ruud Pellikaan. On the unique representation of very strong algebraic geometry codes. *Designs, Codes* *and Cryptography*, 70(1-2):215–230, 2014.

[MCP12]Irene Márquez-Corbella and Ruud Pellikaan. Error-correcting pairs for a public- key cryptosystem. *arXiv preprint arXiv:1205.3647*, 2012.

[MMT11]Alexander May, Alexander Meurer, and Enrico Thomae. Decoding random lin- ear codes in *O*~(2 0*:* 054*n* ). In Dong Hoon Lee and Xiaoyun Wang, editors, *ASI-* *ACRYPT 2011*, volume 7073 of *LNCS*, pages 107–124. Springer, Heidelberg, De- cember 2011.

[MO15]Alexander May and Ilya Ozerov. On computing nearest neighbors with appli- cations to decoding of binary linear codes. In Elisabeth Oswald and Marc Fis- chlin, editors, *EUROCRYPT 2015, Part I*, volume 9056 of *LNCS*, pages 203–228. Springer, Heidelberg, April 2015.

[NNOB12]Jesper Buus Nielsen, Peter Sebastian Nordholt, Claudio Orlandi, and Sai She- shank Burra. A new approach to practical active-secure two-party computation. In Reihaneh Safavi-Naini and Ran Canetti, editors, *CRYPTO 2012*, volume 7417 of *LNCS*, pages 681–700. Springer, Heidelberg, August 2012.

[NP99]Moni Naor and Benny Pinkas. Oblivious transfer and polynomial evaluation. In *31st ACM STOC*, pages 245–254. ACM Press, May 1999.

[Ove06]Raphael Overbeck. Statistical decoding revisited. In Lynn Margaret Batten and Reihaneh Safavi-Naini, editors, *ACISP 06*, volume 4058 of *LNCS*, pages 283–294. Springer, Heidelberg, July 2006.

[Pel92]Ruud Pellikaan. On decoding by error location and dependent sets of error posi- tions. *Discrete Mathematics*, 106:369–381, 1992.

[PMCMM11]Ruud Pellikaan, Irene Márquez-Corbella, and Edgar Martínez-Moro. Evaluation of public-key cryptosystems based on algebraic geometry codes. In *Third Inter-* *national Castle Meeting on Coding Theory and Applications (3ICMTA, Cardona* *Castle, Barcelona, Spain, pages 199–204*, 2011.

[Pra62]Eugene Prange. The use of information sets in decoding cyclic codes. *IRE Trans-* *actions on Information Theory*, 8(5):5–9, 1962.

[Reg05]Oded Regev. On lattices, learning with errors, random linear codes, and cryptog- raphy. In Harold N. Gabow and Ronald Fagin, editors, *37th ACM STOC*, pages 84–93. ACM Press, May 2005.

[Sen11a]Nicolas Sendrier. Decoding one out of many. In *International Workshop on Post-* *Quantum Cryptography*, pages 51–67. Springer, 2011.

[Sen11b]Nicolas Sendrier. Decoding one out of many. In Bo-Yin Yang, editor, *Post-* *Quantum Cryptography - 4th International Workshop, PQCrypto 2011*, pages 51–

67. Springer, Heidelberg, November / December 2011.
[SGRR19]Phillipp Schoppmann, Adrià Gascón, Leonie Reichert, and Mariana Raykova. Dis- tributed vector-OLE: Improved constructions and implementation. In Lorenzo Cavallaro, Johannes Kinder, XiaoFeng Wang, and Jonathan Katz, editors, *ACM* *CCS 2019*, pages 1055–1072. ACM Press, November 2019.

[Ste88]Jacques Stern. A method for finding codewords of small weight. In *International* *Colloquium on Coding Theory and Applications*, pages 106–113. Springer, 1988.

[SV14]N. P. Smart and F. Vercauteren. Fully homomorphic simd operations. *Des. Codes* *Cryptography*, 71(1):57–81, April 2014.

[TS16]Rodolfo Canto Torres and Nicolas Sendrier. Analysis of information set decod- ing for a sub-linear error weight. In *International Workshop on Post-Quantum* *Cryptography*, pages 144–161. Springer, 2016.

[YWL + 20]Kang Yang, Chenkai Weng, Xiao Lan, Jiang Zhang, and Xiao Wang. Ferret: Fast extension for correlated OT with small communication. In Jay Ligatti, Xinming Ou, Jonathan Katz, and Giovanni Vigna, editors, *ACM CCS 2020*, pages 1607–

1626. ACM Press, November 2020.
[Zic17]Lior Zichron. Locally computable arithmetic pseudorandom generators. Master’s thesis, School of Electrical Engineering, Tel Aviv University, 2017.
