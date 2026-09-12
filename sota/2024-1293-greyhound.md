# Greyhound: Fast Polynomial Commitments from Lattices

### Ngoc Khanh Nguyen² and Gregor Seiler¹

1 IBM Research Europe, Zurich 2 King’s College London, London

Abstract. In this paper, we propose Greyhound, the first concretely effi- cient polynomial commitment scheme from standard lattice assumptions. At the core of our construction lies a simple three-round protocol for proving evaluations for polynomials of bounded degree ? *N* with verifier time complexity *O*p *N*q. By composing it with the LaBRADOR proof system (CRYPTO 2023), we obtain a succinct proof of polynomial evalu- ation (i.e. polylogarithmic in *N*) that admits a sublinear verifier runtime.

To highlight practicality of Greyhound, we provide implementation details including concrete sizes and runtimes. Notably, for large polynomials of degree at most *N* “ 2 30, the scheme produces evaluation proofs of size 53KB, which is more than 10 4 times smaller than the recent lattice-based framework, called SLAP (EUROCRYPT 2024), and around three orders of magnitude smaller than Ligero (CCS 2017) and Brakedown (CRYPTO

2023). Keywords: lattices, polynomial commitment scheme, SNARK, imple- mentation, NTT, AVX-512
## 1 Introduction

A polynomial commitment scheme [KZG10] is a cryptographic primitive that allows one to commit to a degree-bounded polynomial *f* P *R* ă*N* rXs over a ring *R*, and later prove evaluation statements, such as *f* p*x*q “ *y* for public *x,y* P *R*. It is crucial for real-world applications that the size of the evaluation proof is succinct and can be efficiently verified (i.e. sublinear in *N*). Polynomial commit- ments, and variations thereof, have found numerous applications in constructing succinct non-interactive arguments of knowledge (SNARKs) [BFS20, BHR ` 21, CHM ` 20, GWC19, MBKM19], look-up arguments [STW23], verifiable secret sharing [BDK13], and multi-party computation [BHV ` 23]. Due to fast development in building quantum computers, there is currently a strong need in designing quantum-safe polynomial commitments. This is ev- idenced by the NIST Post-Quantum Competition for standardizing quantum- safe key encapsulation mechanisms and digital signatures, where three out of four schemes, that were recently selected for standardization, rely on lattice- based assumptions. Not only does it imply that algebraic lattices are a suitable

candidate for building more advanced quantum-safe applications in general, but also that lattice-based SNARKs are the most natural choice for upgrading the newly-standardized encryption and signature schemes with privacy-preserving properties, e.g. verifiable encryption or anonymous credentials. Prior works on lattice-based polynomial commitments have been mainly of theoretical interest. Starting with the construction by Libert et al. [LRY16], poly- nomial commitments were treated as a direct application of (inner-product) func- tional commitments from lattices [ACL ` 22, BCFL23, dCP23, FLV23, WW23b]. Even though the constructions offer succinct proofs, their verification runtime is sublinear in the degree *N* of the committed polynomial (via preprocessing) only if the evaluation point *x* is known in advance³. This is unfortunately not the case in SNARK-related applications, where the evaluation points are chosen uniformly at random. Moreover, only the works of [ACL ` 22, BCFL23, FLV23] provide extractability, although under a *knowledge* assumption that has indepen- dently been broken in both classical [WW23a] and quantum setting [DAFS24]. A different (yet still intuitive) approach for building polynomial commitments can be described as simply combining a standard commitment scheme with an interactive proof of polynomial evaluation. The latter can then be turned non- interactive using Fiat-Shamir transformation [FS86]. For instance, Bootle et al. [BCS23] recently proposed a “Bulletproofs-type” polynomial evaluation proof, which achieves succinct verification via a delegation protocol [Lee21]. The result- ing polynomial commitment relies only on a standard Module-SIS problem and requires no trusted setup. Unfortunately, as inherited from the original lattice- Bulletproofs [BLNS20], soundness error of the core evaluation protocol is non- negligible. Even though parallel repetition can be used to amplify soundness in the interactive setting [AF22], the Fiat-Shamir transformed protocol would suffer a super-polynomial reduction loss in the random oracle model (ROM) [AFK22]. Similar limitation can be found in the polynomial commitment scheme by Cini et al. [CLM23], whose security relies on a new Vanishing-SIS problem. More recent constructions depart from the Bulletproofs paradigm and focus on the “split-and-fold” approach used in FRI low-degree test [BBHR18]. Notably, Fenzi et al. [FMN23] proposed a non-interactive polynomial commitment secure in the ROM under a new assumption called Power-BASIS – a more structured variant of the BASIS assumption introduced in [WW23b]. Unfortunately, the scheme requires a trusted setup, and what is worse, both the common reference string (CRS) size and committing runtime are quadratic in the degree bound

*N*. A follow-up work by Albrecht et al. [AFLN24], called SLAP, removed the need of a new assumption, thus relying only on Module-SIS, while making the prover runtime quasi-linear. However, the remaining requirement on a trusted setup, together with concrete proof sizes reaching tens of megabytes make the scheme very unlikely to be practical. Some issues have been circumvented by the recent work by Cini et al. [CMNW24] who built an elegant SIS-based polynomial commitment with transparent setup and polylogarithmic verifier runtime. The 3 It is worth noting that Orbweaver [FLV23] explicitly circumvents this issue.

concrete instantiation of the scheme, however, provides proof sizes in the order of single-digit megabytes for *N* ą 2 25. Even though none of the currently state-of-the-art lattice-based polynomial commitments have shown any significant sign of practicality, concretely efficient proof of knowledge for NP can be constructed from standard lattice assumptions. Notably, Beullens and Seiler [BS23] proposed a succinct proof system called LaBRADOR that achieves impressive proofs of size « 50KB for large *N*. As a drawback, the protocol suffers from having linear verifier runtime, which limits the range of applications where the proof system could be used. Based on the discussion above, we focus on the following research question:

*Can we build a concretely efficient polynomial commitment scheme with* *transparent setup, sublinear verification complexity, and secure under standard* *lattice assumptions?*

1.1 Our Contributions *Polynomial commitment scheme.* In this work we propose Greyhound, the first practical lattice-based polynomial commitment scheme in the random oracle model. The construction requires no trusted setup and relies on the well-studied Module-SIS assumption. Asymptotically, our scheme produces
? evaluation proofs of size polylogp*N* q which can be verified in time *O*p *N*q. As for concrete efficiency, we provide more details, as well as comparison with prior (plausibly) post-quantum poly- nomial commitments, in Tables 1 and 2. Notably, for large degrees *N* Grey- hound provides 10 4 smaller evaluation proofs than SLAP [AFLN24], and around three orders of magnitude smaller proofs than the hash-based constructions [AHIV17, BBHR18, GLS ` 21]. Our construction also produces much smaller proof sizes compared to the more recent lattice-based polynomial commitments [CMNW24, HSS24] by a factor of at least 30. As for the commit and prover running time, Greyhound performs around 5 ´ 10X faster than Brakedown and Ligero. As a drawback, our verification time seems comparable with Brakedown and two times slower than Ligero.

*Library for fast ring operations.* We have implemented an AVX-512 optimized library for polynomial arithmetic over small-degree power-of-two cyclotomic ring modulo multi-precision primes of the form *q* ” 5 pmod 8q. This library includes functions for sampling polynomials from several standard distributions as well as computing ring automorphisms directly in several different polynomial rep- resentations such as coefficient representations and multi-modular NTT repre- sentations. Moreover, our library contains a very fast implementation of the Johnson-Lindenstrauss projection [GHL22] needed in recent lattice-based zero- knowledge protocols [BS23, LNP22]. The implementation uses the Four Russian algorithm and vector shuffle instructions for in-register lookups. See Section 6 for more details.

Transparent Proof sizes for Scheme Structure setup *N* “ 2 26 *N* “ 2 28 *N* “ 2 30

Brakedown-PC Hashes ✓ 49157 93767 181948 Ligero-PC Hashes ✓ 7256 14383 28631 FRI-PC Hashes ✓ 740 – – FMN23-PC Lattices ✗ – – 8499 SLAP-PC Lattices ✗ – – 785408 CMNW24-PC Lattices ✓ 1546 – 5294 HSS24-PC Lattices ✓ 48640 – – Greyhound Lattices ✓ 46 53 53

Table 1: Concrete evaluation proof sizes (in KB) of Greyhound and comparison with

prior plausibly post-quantum extractable polynomial commitments. Here, *N* is the degree bound on the committed polynomial over a suitably chosen finite field **F***q*. Con- crete sizes are set to reach *λ*-bit security level, where *λ* « 128. Sizes for Brakedown-PC [GLS ` 21], Ligero-PC [AHIV17] (Reed-Solomon rate of *ρ* “ 1{4) and FRI-PC [BBHR18] are taken directly from [GLS ` 21, Figure 8], where for simplicity we assume that sizes for degree 2 25 and 2 26 are the same (and identically for *N* “ 2 28 *,*2 30 ). As stated in the aforementioned figure, for *N* ą 2 25 no sizes are provided for FRI-PC since the prover ran out of memory. Similarly for CMNW24-PC [CMNW24] and HSS24-PC [HSS24], the reported sizes (taken from the respective works) correspond to the degree 2 25 instead of 2 26, where the instantiation of the latter scheme additionally provides zero-knowledge. Proof sizes for SLAP-PC [AFLN24] and FMN23-PC [FMN23] are taken from the re- spective works.

1.2 Technical Overview Denote *λ* as a security parameter. Let *d* be a power-of-two and *R* :“ **Z**r*X*s{p*X*
*d* ` 1q be the ring of integers of the 2*d*-th cyclotomic field. Take an odd prime *q* and

|define R :“ R{pqq and δ :“ tlog qu. For the sake of the overview, we consider|“|‰||
|---|---|---|---|
||n n ´ n 1|δ n nδ q q|n q ˆnδ|
|||n ´||
|||q n 1||
|n ´ n 1||||

*q* base-two gadget matrices G*n*:“ I*n*b 1 2 4 ¨¨¨ 2 *δ* P *R* *n* *q* ˆ*nδ* for *n* ě 1. We define the standard inverse function G : *R* Ñ *R*, which decomposes each entry

w.r.t. base 2. In particular, for any t P *R*, G ptq has binary coefficients and G G ptq“ t. Inner and outer commitments. The starting point of our construction is the basic commitment scheme from LaBRADOR [BS23]. Let *n,m,r* P **N** and define the commitment key as a pair of uniformly random matrices A P *Rq*
*n*ˆ*mδ* and

|n q ˆrnδ||r|m q|
|---|---|---|---|
||´ n 1 i|´ m1 i|n q|

B P *R* *n* *q* ˆ*rnδ*. Suppose we want to commit to arbitrary *r* vectors f₁*,...,*f*r*P *R* *m* *q*of length *m*. The first step is to compute inner commitments t*i*:“ AG pf qP *R* and their binary decomposition ˆt*i*:“ G pt q for *i* P r*r*s. Then, the final outer commitment is » fi ˆt₁ — ffi*n* u :“ B – ... fl P *Rq.* (1) ˆt *r*

*N* “ 2 26 *N* “ 2 28 *N* “ 2 30 <u>Scheme Commit Prove Verify Commit Prove Verify Commit Prove Verify</u> Brakedown-PC 36 3.21 0.703 150 13 2.56 605 48.6 2.96 Ligero-PC 39.9 3.11 0.196 169 12.4 0.402 717 50 0.846 FRI-PC 168 185 0.041 – – – – – – HSS24-PC 188 1.07 – – – – – – Greyhound 4*.*37 2*.*03 0*.*492 21*.*2 8*.*21 1*.*15 132 41*.*2 2*.*80

Table 2: Concrete running time (in seconds) of the Greyhound polynomial commit-

ment scheme and comparison with Brakedown-PC [GLS ` 21], Ligero-PC [AHIV17] (Reed-Solomon rate of *ρ* “ 1{2) and FRI-PC [BBHR18]. The Greyhound runtimes were obtained by running the code on a single Intel Xeon Sapphire Rapids core at 3*.*2 GHz. The values for the related works are taken directly from [GLS ` 21, Figure 8] and [HSS24, Table 3], where for simplicity we assume that running times for degree 2 25 and 2 26 are the same (and identically for *N* “ 2 28 *,*2 30 ).

Commitment opening for the message pf

||q|consists of short vectors ps|, ˆt q|
|---|---|---|---|
||i iPrrs||i i iPrrs|
|m i|i|n i||

which satisfy (i) f*i*“ G s, (ii) As “ G ˆt for *i* P r*r*s and (iii) Equation (1). Computational binding property follows directly from the Module-SIS assump- tion.

Simple proof of quadratic relations. Our base for constructing proofs of polynomial evaluation is the following three-round proof of knowledge of a com- mitment opening ps*i,*ˆt*i*q*i*Pr*r*sfor the message pf*i*q*i*Pr*r*swhich satisfies

⊺ “ ‰ a f₁|¨¨¨|f*r*b “ *y.*

The protocol can be described as follows. The prover starts by sending

⊺ ⊺ “ ‰ ⊺ “ ‰ *r* w :“ a f₁|¨¨¨|f*r*“ a G*m*s₁|¨¨¨|s*r*P *Rq*

to the verifier. Then, given a short challenge vector c P *R* *r* *q*, the prover outputs

“ ‰ pˆt*i*q*i*Pr*r*sand z :“ s₁|¨¨¨|s*r*c*.*

Finally, verifier checks whether pˆt*i*q*i*Pr*r*s*,*z are short and if the following hold:

» fi ˆ t₁ ÿ *r* ⊺? ⊺? ⊺?ˆt? — ffi w b “ *y,* w c “ a G*m*z*,* Az “ *ci*G*n i*and u “ B – ... fl*.* (2) *i*“1ˆt *r*

Communication complexity of thethree-round protocolis *O*p*rn*`*mδ*q elements over *Rq*, which is sublinear in the witness size *N* “ *r* ¨ *m*.

Reducing the proof size. We propose two substantial changes to the protocol above. The first one is that instead of sending w in the clear, we commit to it by computing wˆ :“ G ´ *r* 1 pwq and outputting v :“ Dwˆ, where D P *R* *n* *q* ˆ*r* is a uniformly random matrix. Then, in the final round, the prover reveals wˆ, ? together with pˆt*i*q*i*Pr*r*s*,*z. The verifer checks whether wˆ is short, Dwˆ “ v, and if conditions in (2) hold for the reconstructed w :“ G*r*wˆ. The modifiedthree- round protocolis summarized in Figure 1. At a first sight, this modification gives no advantage, or even worse, makes the protocol less efficient. Indeed, instead of sending w, the prover outputs the commitment v, together with opening wˆ which has the same bit-length as w. The key observation here is that the verification conditions can be described as a standard lattice-type statement, i.e. checking whether wˆ*,*ˆt :“pˆt*i*q*i*Pr*r*s*,*z have small norm and they satisfy the following linear relation over *Rq*:

» fi » fi D 0 0 » fi v — 0 B 0 ffi wˆ —uffi — ⊺ ffi — ffi —b G *r*0 0 ffi – ˆt fl “ —*y*ffi*.* (3) — ⊺ ⊺ ffi — ffi –c G *r*0 ´a G*m* fl z –0fl 0 c ⊺ b G*n*´A 0

Therefore, instead of sending wˆ*,*ˆt*,*z in the clear, we apply the LaBRADOR [BS23] proof system to prove knowledge of short wˆ*,*ˆt*,*z which satisfy (3). This results in succinct proof sizes comparable with LaBRADOR, i.e. asymptotically polyp*λ,* log*N*q bits. More importantly, we notice that by running the LaBRADOR ? sub-protocol on an instance and witness of size *Oλ*p*r* ` *m*q“ *Oλ*p *N*q for a suit- able choice of *r* and *m*, our verifier for the polynomial evaluation protocol has sublinear time complexity.

Polynomial evaluation proof. To transform the protocol above into a poly- nomial evaluation proof⁴ over *Rq*we use the following (standard) observation. ř*N*´1 *i* ă

||||N ´1 i“0|i i|ă q N|
|---|---|---|---|---|---|
|q||||||
|⊺|2|m´1||||
|⊺ ⊺|m|m 2|m r´1|||
|i|pi´1qm|pi´1qm`1|im´1|||

Suppose *N* “ *m* ¨ *r* for some *m,r* ě 1. Then, for any *f* “ *fi*X P *Rq N*rXs, and any evaluation point *x* P *R* we have:

“ ‰ a :“ 1 *x x* ¨¨¨ *x* ⊺ “ ‰ “ ‰ *f* p*x*q“ a f₁|¨¨¨|f*r*b where b :“ 1 *x* p*x* q ¨¨¨ p*x* q*.* “ ‰ f :“ *f f* ¨¨¨ *f* for *i* Pr*r*s

Hence, we can invoke the protocol described above to prove statements of the form *f* p*x*q “ *y* over *Rq*. Finally, we apply the generic transformation from [AFLN24] to convert our construction into a polynomial commitment scheme over a finite field **F***q*.

4 In a similar fashion we can also construct bivariate polynomial commitments, which are used in, e.g. Sonic [MBKM19].

## 2 Preliminaries

2.1 Notation Let *q* be an odd prime. Denote **Z***q*to be the ring of integers modulo *q*. For *n* P **N**, we define r*n*s :“ t1*,*2*,...,n*u. Let *λ* to be the security parameter. We write *Oλ*p*T*q to denote *T* ¨ polyp*λ*q. For a probability distribution *X* (resp. finite set *X*), *x* Ð *X* means that *x* is sampled from *X* (resp. *x* is chosen uniformly at random from the set *X*). We write neglp*λ*q to denote an unspecified negligible function. For a power of two *d* and a positive integer *q*, denote *R* and *Rq*respectively to be the rings **Z**r*X*s{p*X*
*d* ` 1q and **Z***q*r*X*s{p*X* *d* ` 1q. Lower-case letters denote elements in *R* or *Rq*and bold lower-case (resp. upper-case) letters represent ř*d*´1 column vectors (resp. matrices) with coefficients in *R* or *Rq*.For *y* “*i*“0*yi*¨ *X* *i* P *R*, we write ctp*y*q :“ *y₀* P **Z** to denote the constant term of *y*. We define *r¹* “ *r* mod ˘ *q* to be the unique element *r¹* in the range ´ <u>q´</u> 2 <u>1</u> ď *r¹* ď <u>q´</u> 2 <u>1</u> such that *r¹* “ *r* mod *q*. We also denote *r¹* “ *r* mod ` *q* to be the unique element *r¹* in the range 0 ď *r¹* ă *q* such that *r¹* “ *r* mod *q*. When the exact representation is not important, we simply write *r* mod *q*. For an element *w* P **Z***q*, we write }*w*}8to mean |*w* mod ˘ *q*|. Define the *ℓ₈* and *ℓp*norms for *w* “ *w₀* ` *w₁X* `*...* ` *wd*´1*X* *d*´1 P *R* as follows: b }*w*}8“ max}*wj*}8*,*}*w*}*p*“ *p* }*w₀*} *p* 8`*...* `}*wd*´1} *p*

8*.*
*j*

If w “p*w₁,...,wm*qP *R* *k*, then a *p* }w}8“ max}*wj*}8*,*}w}*p*“}*w₁*}*p*`*...* `}*wk*}*p.* *j*

By default, }w} :“}w}2. Similarly, we define the norms for vectors over **Z***q*. We recall the main result by Lyubashevsky and Seiler [LS18] which says that short polynomials over *Rq*are invertible.

Lemma 2.1([LS18]). *Let q* ” 5 pmod 8q *be a prime. Then, any f* P *Rqwhich* *satisfies either* 0 ă}*f*}8ă? <u>1</u> 2 *q* 1{2 *or* 0 ă}*f*}ă *q* 1{2 *has an inverse in Rq.*

The set of invertible elements of *Rq*is denoted by *R* ˆ

*q*.
⊺ “ 2 *δ* ‰ Let *b,n* P **N**. We define the gadget vector g *b* :“ 1 *b b* ¨¨¨ *b*, where *δ* “ tlog*bq*u. Then, the matrix matrix G*b,n*is defined as G*b,n*:“ I*n*b g *b* ⊺. Conversely, we define G ´ *b,n* 1 : *R* *n* *q* ˆ*m* Ñ *R* *δn* *q* ˆ*m* to be the inverse function which decomposes each entry w.r.t. base *b* ě 2. Clearly, for any t P *R* *n* *q*, we have

´1 ´1<u>b</u> GG *b,n* ptq“ t and}G *b,n* ptq}8ď*.* 2

Next, we recall the standard Module-SIS (MSIS) problem [LS15].

Definition 2.2(Module-SIS). *Let q* “ *q*p*λ*q*, n* “ *n*p*λ*q*, m* “ *m*p*λ*q*, β* “ *β*p*λ*q *and d* “ *d*p*λ*q*. We say that the* MSIS*n,m,q,βassumption holds if for any PPT* *adversary A, the following holds:* „ ˇ *n*ˆ*m* ȷ ˇ A Ð *R* *q* Pr Az “ 0 ^ 0 ă *∥*z*∥* ď *β* ˇˇ “ neglp*λ*q*.* z Ð *A*pAq

2.2 Interactive Proofs Let R Ďt0*,*1u
˚ ˆt0*,*1u ˚ ˆt0*,*1u ˚ be a ternary relation. For a triple ppp*,* ①*,* **w**qP R, we call pp the public parameters, ① is a statement and **w** is a witness for ① w.r.t. pp. We denote Rppp*,*①q “ t**w** : Rppp*,* ①*,* **w**q “ 1u. In this work, we only consider NP relations R for which a witness *w* can be verified in time polyp|pp|*,*|①|q for all ppp*,* ①*,* **w**qP R. An interactive proof system *Π* “ p*S, P, V*q for relation R consists of three PPT algorithms: the setup algorithm *S*, prover *P*, and verifier *V*. The latter two are interactive and stateful. We write p*tr,b*qÐx*P*ppp*,* ①*,* **w**q*, V*ppp*,*①qy for running *P* and *V* on inputs pp*,* ①*,* **w** and pp*,*① respectively and getting communication transcript *tr* and the verifier’s decision bit *b*. We use the convention that *b* “ 0 means reject and *b* “ 1 means accept the prover’s claim of knowing **w** such that p①*,* **w**q P *R*. Unless stated otherwise, we will assume that the first and the last message are sent from a prover. Hence, the protocol between *P* and *V* has an odd number of rounds. Further, we say a protocol is *public coin* if the verifier’s challenges are chosen uniformly at random independently of the prover’s messages.

Definition 2.3(Completeness). *A proof system Π* “p*S, P, V*q *for the rela-* *tion* R *satisfies completeness with completeness error ϵ*p¨q *if for all adversaries* *A,* » ˇ *λ* fi ˇ pp Ð *S*p1 q ˇ Pr –*b* “ 0 ^ppp*,* ①*,* **w**qP Rˇˇ p①*,* **w**qÐ *A*pppq fl “ *ϵ*p*λ*q` neglp*λ*q*.* ˇ p*tr,b*qÐx*P*ppp*,* ①*,* **w**q*, V*ppp*,*①qy

*If ϵ*p¨q *is a zero-function then we say Π satisfies perfect completeness.*

Definition 2.4(Knowledge Soundness). *A proof system Π* “p*S, P, V*q *for* *the relation* R *is knowledge sound with knowledge error ε*p*λ*q *if there exists an* *expected PPT extractor E such that for any stateful PPT adversary P* ˚ *:* » ˇ *λ* fi ˇ pp Ð *S*p1 q ˇ ˚ ˚ — ˇ p①*,*st qÐ *P* pppq ffi Pr — – *b* “ 1 ^ppp*,* ①*,* **w**qR Rˇˇ˚ ˚ffi fl “ *ε*p*λ*q`neglp*λ*q*.* ˇ p *tr,b*qÐx*P* ppp*,* ①*,*st q*, V* ˚ ppp*,*①qy ˇ **w** Ð *E* *P* ppp*,*①q

*Here, the extractor E has a black-box oracle access to the (malicious) prover P* ˚

*and can rewind it to any point in the interaction.*

To prove knowledge soundness, we will show that our protocols satisfy coordinate- wise special soundness (CWSS) defined in [FMN23]. Namely, let *C* be a finite

|||ℓ||ℓ ℓ|
|---|---|---|---|---|
|i|||||
|i|i i|j|j||

set and *ℓ* P **N**. For any two vectors *⃗x* :“p*x₁,...,x* q*,⃗y* :“p*y₁,...,y* qP *C*, define
the following relation “” ” for fixed *i* Pr*ℓ*s as:

*⃗x* ” *⃗y* ðñ *x* ‰ *y* ^@ *j* Pr*ℓ*szt*i*u*,x* “ *y.*

That is, vectors *⃗x* and *⃗y* have the same values in all coordinates apart from the *i*-th one. Next, we define the set " * *ℓ*`1D *k* Pr*ℓ* ` 1s*,* @ *i* Pr*ℓ*s*,* SSp*C,ℓ*q :“ p*⃗x₁,...,⃗xℓ*`1qP *C* :*.* D *j* Pr*ℓ* ` 1szt*k*u*, ⃗xk*”*i⃗xj*

We are ready to define the notion of coordinate-wise special soundness forthree- round protocols(the general definition for multi-round protocols is not needed here).

Definition 2.5(CWSS forthree-round protocols). *Let Π* “p*S, P, V*q *be* *a public-coin three-round interactive proof system for relation* R*, and suppose* *the challenge space of V is C* *ℓ* *. We say that Π is ℓ-coordinate-wise special sound* *if there exists a polynomial time algorithm that on input public parameters* pp*,* *statement* ① *and ℓ*` 1 *accepting transcripts* p*a,⃗ci,zi*q*i*Pr*ℓ*`1s*, with* t*⃗c₁,...,⃗cℓ*`1uP SSp*C,ℓ*q *and common first message a, outputs a witness* **w** P Rppp*,*①q*.*

It was shown in [FMN23] that coordinate-wise special sound protocols are knowl- edge sound 5.

Lemma 2.6(Lemma 2.31 of [FMN23]). *Let Π* “ p*S, P, V*q *be public-coin* *three-round protocolfor relation* R *with the challenge space of C. If Π is ℓ-* *coordinate-wise special sound, then it is knowledge sound with knowledge error* *ℓ*{|*C*|*.*

2.3 Polynomial Commitment Scheme Polynomial commitment schemes can be seen as standard commitments to poly- nomials *f* (e.g. by committing to the coefficients of *f*) equipped with the ability to prove evaluations of *f*. We define polynomial commitments in the interactive setting. Due to the slack occurring in the lattice setting, we define the slack space SL and fix a (public) identity element e P SL. Definition 2.7. *Let* PCS “pSetup*,*Commit*,*Open*,*Evalq *be a tuple of algorithms.* PCS *is a polynomial commitment scheme over a ring R with degree bound N if:* – Setupp1 *λ*
qÑ pp *takes a security parameter λ (specified in unary) and outputs* *public parameters* pp*.* – Commitppp*,f*q Ñ p*C,* stq *takes public parameters* pp *a message f* P *R* ă*N* rXs *and outputs a commitment C and decommitment state* st*.* 5 See [FMN23, Lemma 2.32] for the non-interactive version in the random oracle model.

– Openppp*,C,f,* st*,c*q Ñ 0{1 *takes public parameters* pp*, a commitment C, a* *message f* P *R* ă*N* rXs*, a decommitment state* st *and a relaxation factor c* P SL *and outputs a bit indicating whether C is a valid commitment to f under* pp*.* *We implicitly assume that if c* R SL *then* Open *outputs* 0*.* – Eval :“pEval*.P,* Eval*.V*q *is a pair of probabilistic polynomial-time algorithms.* *Here* Eval*.P*ppp*,* p*C,x,y*q*,* p*f,* stqq *is the evaluation prover,* Eval*.V*ppp*,* p*C,x,y*qq *is the evaluation verifier.*

An interactive polynomial commitment scheme can be transformed into a non- interactive one using the Fiat-Shamir transformation [FS86]. We require that the polynomial commitment scheme satisfies evaluation com- pleteness, weak binding and knowledge soundness.

Definition 2.8(Evaluation Completeness). *We say that a polynomial com-* *mitment scheme* PCS “ pSetup*,*Commit*,*Open*,*Evalq *satisfies evaluation com-* *pleteness with completeness error ϵ*p¨q *if for every polynomial f* P *R* ă*N* rXs *and* *any evaluation point x* P *R:* » ˇ *λ* fi ˇ pp Ð Setupp1 q ˇ — Openppp*,C,f,* st*,*eq“ 0 ˇ *C,* st Ð Commitppp*,f*q ffi Pr — – ˇˇ ffi fl “ *ϵ*p*λ*q` neglp*λ*q*.* _*b* “ 0 ˇ ① :“p*C,x,f*p*x*qq*,* **w** :“p*f,* stq ˇ p*tr,b*qÐxEval*.P*ppp*,* ①*,* **w**q*,*Eval*.V*ppp*,*①qy

Definition 2.9(Weak Binding). *A polynomial commitment scheme* PCS “ pSetup*,*Commit*,*Open*,*Evalq *satisfies weak binding if for every PPT adversary A:*

» 1 1 ă*N* ˇ fi *f* ‰ *f* ^ *f,f* P *R* rXs^ ˇˇ*λ* ˇˇ pp Ð Setupp1 q fl “ neglp Pr – Openppp*,C,f,* st*,c*q1 1 1*λ*q*.*

|||1 1 1|
|---|---|---|
|1|1 1||

### pC,pf, st,cq, pf, st,c qqÐ Apppq

### “ Openppp,C,f,st,c q“ 1 ˇ

Definition 2.10(Knowledge Soundness). *We say that a polynomial com-* *mitment scheme* PCS “ pSetup*,*Commit*,*Open*,*Evalq *is knowledge sound with* *knowledge error ε if for all stateful PPT adversaries P* ˚ *, there exists an expected* *PPT extractor E such that*

|»|ˇˇ|pp Ð Setupp1||q fi|
|---|---|---|---|---|
|— pOpenppp,C,f, st,cq‰ 1 _ f pxq‰ yq ˇˇˇˇ p|① :“pC,x,yq, st||Ð P|pppq ffi|
|Pr — – ^b “ 1|ˇˇ tr,bqÐxP|ppp, ①, st pf, st,cqÐ E|q, V ppp, ①qy ffi ppp, ①q|fl “ εpλq` neglpλq.|

*λ* ˚ ˚ ˚ ˚ *P*˚

*Here, the extractor E has a black-box oracle access to the (malicious) prover P* ˚

*and can rewind it to any point in the interaction.*

2.4 Principal Relation We recall the principal relation (alternatively called a dot-product relation) de- fined in [BS23]. The relation is characterised by the rank *n* ě 1, multiplicity

*r* ě 1 and the norm bound *β* ą 0. The statement is a triple p*F, F¹,β*q, where *F* and *F¹* are families of functions *f* : *R* *n* *q*ˆ*...* ˆ *R* *n* *q*Ñ *Rq*of the form

ÿ *r*ÿ*r*

||f ps₁,..., s|q“|a xs|, s y`|xϕ, s y´ b|
|---|---|---|---|---|---|
|||r|i,j i,j“1|i j i“1|i i|
|i,j|q i|n q||||
|r|n q|||||
||||r|||
||||r|||
|||r||||
||||2|||
||||i|||
|||i“1||||

*r i,j i j i i*

for *a,b* P *R,ϕ* P *R*, and *β* ě 0. Then, a valid witness is a sequence of vectors s₁*,...,*s P *R* which satisfy:

### fps₁,...,s q“ 0 @f P F

ctp*f¹*ps₁*,...,*s qq“ 0 @*f¹* P *F¹* ÿ }s} ď *β.*

It was shown in [BS23, Section 7] that the Rank-1 Constraint System (R1CS) can be reduced to the principal relation.

2.5 Inner and Outer Commitments We recall the inner and outer commitments from [BS23], which will be the base of our polynomial commitment. Let *n,m,r,b,q* P **N** and set *δ* :“ tlog*bq*u. Denote *β,* ¯ *γ,*¯ *κ*¯ ą 0 as the security-related norm bounds. Let pA P *Rn*
*q* ˆ*m* *,*B P *R* *n* *q* ˆ*nδr* q be the public parameters. Suppose we want to commit to a matrix S P *R* *m* *q* ˆ*r*, which can be represented as *r* column vectors s₁*,...,*s*r*P *R* *m*

*q*. The *inner commitments* are the *r* vectors
t *i*:“ As*i*P *R* *n*

*q*. Then, the *outer commitment* u is generated by computing » fi ˆt₁ — ffi*n*
ˆt´1 u :“ B – ... fl P *Rq,* where*i*:“ G *b,n* pt*i*q for *i* Pr*r*s*.* (4) ˆt *r*

The decommitment state consists of pˆt*i*q*i*Pr*r*s. A *weak* opening for the commit- ment u is a tuple ps*i,*ˆt*i,ci*q*i*Pr*r*s, which satisfies all the following conditions

@*i* Pr*r*s :}*ci*¨ s*i*}ď *β,*¯}*ci*}1ď *κ,*¯ *ci*P *R* ˆ *q,* As*i*“ G*b,n* ˆt *i* » fi ›» fi› ˆt₁ › ˆt₁ › › › — ffi ›— ffi›
B – ... fl “ u and ›– ... fl› ď *γ.*¯
› › ˆt *r* › ˆt *r* ›

Next, we show that the commitment scheme described above satisfies binding with respect to weak openings under Module-SIS assumption [ALS20].

Lemma 2.11(Weak Binding). *There is a deterministic algorithm, that given* *two weak openings* ps *for the commitment* u P *R*

|, ˆt|,c q and ps¹|, ˆt¹ ,c¹ q|||
|---|---|---|---|---|
|i i j|i iPrrs|i i i iPrrs|m q `nδr|n q|

*such that* s*j*‰ s¹ *for some j* P r*r*s*, outputs a vector* z P *R such that* rA | Bsz “ 0 *and* 0 ă}z}ď maxp4¯*κβ,*¯ 2¯*γ*q*.*

*Proof.* Note that if ˆt*i*‰ ˆt¹*i*for some *i* Pr*r*s, then we have automatically found a short, non-zero solution z*B*for the matrix B of norm at most 2¯*γ*. Suppose this is not the case. In particular, we have

||“ G|ˆt “ G|ˆt¹ “ As¹|
|---|---|---|---|
|j j|j b,n|j b,n|j|

As*j.*

Although s ´ s¹ ‰ 0 is not short, we know that

### }cjc¹jpsj´ s¹jq}ď}c¹jpcjsjq}`}cjpc¹js¹jq}ď 2¯κβ.¯

Finally, since both *cj,c¹j*are invertible over *Rq*, we deduce that z*A*:“ *cjc¹j*ps*j*´s¹*j*q is a short non-zero solution for A. We conclude the proof by combining the two cases. [\

## 3 Proofs of Quadratic Relations with Sublinear Verification

In this section, we propose a simple proof of knowledge of a commitment opening which satisfies certain quadratic relations. More concretely, using the notation from Section 2.5 we consider a relation:

$˜ ¸ˇ,

||pA, B, Dq,||“ G|;|.|
|---|---|---|---|---|---|
||||i|b ,n i||
|b ,b|i iPrrs|i iPrrs b ,n|⊺ i 8 b 2 b|r 8|b 2 q nˆδr|

& ˇˇ @*i* Pr*r*s*,*As “1‰ ˆt R0 1:“ pa*,* b*,* u*,y*q*,* ˇˇ Bˆt “ u; a s₁|¨¨¨|s b “ *y*;*.* (5) % ˆ ˆ ˇ <u>0</u>ˆ<u>1</u> - pps q*,*t “pt q q @*i* Pr*r*s*,*}s} ď;}t} ď

Here, width of the matrix G1is *δ* ¨ *n*, where *δ* :“ tlog 1 *q*u. Matrix D P *R* has a role of an additional commitment key, used to commit to various prover messages in order to preserve succinctness.

3.1 Simple Protocol The three-round protocol is presented in Figure 1. As for the security analysis, we focus on completeness and coordinate-wise special soundness.

*n*

|Public parameters:|A P R|, B P R|, D P R|
|---|---|---|---|
|Witness: ps|P R q, ˆt “pˆt|q P R||
|Statement: a P R|, b P R|, u P R ,y P R|,|

*q* ˆ*m n* *q* ˆ*nδr n* *q* ˆ*δr*

*i* *m* *q i*Pr*r*s *i i*Pr*r*s *nδr* *q* *m* *q* *r* *q* *n* *q q*

<u>Prover Verifier</u>

⊺ ⊺ “ ‰ *r* w :“ a s₁|¨¨¨|s*r* P *Rq* wˆ :“ G ´ *b* 1 1 *,r*pwqP *R* *δr* *q* v :“ Dwˆ P *R* *n* *q* v- c “p*c₁,...,cr*qÐ *C* *r* c “ ‰ z :“ s₁|¨¨¨|s*r* c wˆ*,*ˆt*,* z-Accept iff: ›» fi› › wˆ › › › a <u>1</u> 2 2

1. ››– ˆt fl›› ď2*b₁*p*n* ` 1q*δrd* `p*rκb₀*q *md* › z › » fi » fi D 0 0 v — 0 B 0 ffi »wˆ fi —uffi — ⊺
ffi — ffi

2. ——b G*b*1*,r* 0 0 ffiffi – ˆt fl “ ——*y*ffiffi –c⊺G*b* 1 *,r* 0 ´a
⊺ fl z –0fl 0 c ⊺ b G*b*1*,n* ´A 0

Fig. 1: Proof of knowledge for the relation R*b*0*,b*1in (5). Here, *δ* :“ tlog*b*

1 *q*u.

Lemma 3.1(Completeness). *The protocol in Figure 1 for relation* R*b*0*,b*1*sat-* *isfies perfect completeness.*

*Proof.* We start with the norm check. Since all coefficients of ? ˆt and wˆ are at ? most *b* in the absolute řvalue, we have}ˆt} ď <u>b</u> 2 <u>1</u> *nδrd* and }wˆ} ď <u>b</u> 2 <u>1</u> *δrd*. *r* Combining with }z}8ď*i*“1}*ci*¨ s*i*}8ď *rκb₀*{2, this yields the first verification check. As for the algebraic equations, directly from the relation R*β,b*we have the outer-commitment equation Bˆt “ u. Also, by construction Dwˆ “ v. Next, we obtain “ ‰

|⊺ b,r|⊺|⊺ ⊺|r|
|---|---|---|---|
|⊺ b,r ⊺|⊺ r b,r i“1|⊺ ⊺ i b,r i|r r i i i“1|

b G wˆ “ b w “ w b “ a s₁|¨¨¨|s b “ *y*

and “ ‰ ⊺ c G wˆ “ c w “ w c “ a s₁|¨¨¨|s c “ a z*.*

Finally, ÿ ÿ pc b G qˆt “ *c* G ˆt “ *c* As “ Az

### which concludes the proof. [\

As standard in lattice-based proof systems, we only manage to extract a relaxed ˚ openings (cf. Section 2.5). This corresponds to the following relaxed relation R :

@*i* Pr*r*s*,*As*i b*1*,n i*

|$ ’ ’˜ &|pA, B, Dq,|¸ˇˇ ˇ|“ “ G|‰ ˆt;|, / /.|
|---|---|---|---|---|---|
|:“|pa, b, u,yq,|ˇ ˇˇ Bˆt “ u;|a s |¨¨¨|s|b “ y;|.|
|’ ’ % pps q|, ˆt “pˆt q|q ˇ @i Prrs, }c ˇ|¨ s}ď β;}c ¯ }t}ď γ¯ ˆ|} ď κ ¯; c P R|; / /-|

⊺ ˚ 1 *r* R¯ *γ,*¯ *κ*¯ ˆ *b*1*,β,* *i i i* 1 *i q* *i i*Pr*r*s *i i*Pr*r*s*,* p*ci*q*i*Pr*r*s

(6)
Recall that, as shown in Lemma 2.11, the commitment scheme satisfies weak binding under the Module-SIS assumption. Next, we show that thethree-round protocolsatisfies coordinate-wise special soundness under the Module-SIS assumption.

|a 1 Let γ ¯ :“ 2 ? 1 ? 2 pp :“pA ˆt ˆ, c, pw,, z i i i i q p n `1q δr so that R q Assume without loss of generality that c₀ P r r ¯. Similarly we argue for all w “ ˆt and w r ˆ. w ,r :“p c₁ ,...,c norm of ¯ c :“ c ´ i i by Lemma 2.1. Now, define ¯s ⊺ ⊺ qw ´ c pc 0 i|b² p n ` 1q δrd `p rκb₀ q² 1 q. Then, there exists a polynomial time algorithm, B, Dq, statement ① :“pa qq for i “ 0, 1 ,...,r and common first message v rB | Dsz “ 0 and differs from each c s. First, if for some distinct i,j P t0, then we immediately yield a non-zero solution z :“ ˆt ˆ i ˆ :“ w ˆ₀ ˆ “ ... “ w r q and c :“p c₁ ,...,c r i i ´1 c¹ is at most ¯ κ “ 2 κ i :“pz₀ ´ z q{c ¯. Clearly,} i i i and tr we have i ⊺ a pz₀ ´ z₁ q ⊺|
|---|---|
|“ c ¯ i ⊺ w “ y “ ⊺ ¯s₁ |¨¨¨|¯s a p1q p r q ˆt ,..., ˙ ˆ ⊺ i ˆt “|¯s “ a. i c ¯ i, we obtain ‰ b “ y. r p j q nδ q, where each ˆt P R q ˙ ˆ ⊺ ⊺ c₀ ´ c i ˆt “ A|

Lemma 3.2(CWSS). *md, β*¯ :“ 2¯*γ and* *κ*¯ :“ 2*κ. Suppose that κ*¯ ă *that on input public parameters,* b*,* u*,y*q *and* *r* ` 1 *accepting transcripts*

tr*i*:“pv

*with* pc₀*,...,*c*r*qP SSp*C,r, either outputs a witness* ˚¯

|˚|||
|---|---|---|
|b ,β, ¯ γ, ¯ κ|¯||
|||i|
|i|j|i j|

**w** P R¯ppp*,*①q*, or* z P 0 ă}z}ď *β.* 1 *γ,*

*Proof.* exactly in the *i* coordinate for *i,*1*,...,r*u we have ˆt ‰ ˆt ´ ˆt to B of norm at most *β*. Thus, from now on we
assume that ˆt :“ ˆt₀ “*...*. For presentation, set
w :“p*w₁,...,w* q“ G1

|r|b|||
|---|---|---|---|
|i i||i i`1|r|
|q||i i||

Fix *i* Pr*r*s and denote c₀*,c¹,c,...,c* q where *c* ‰ *c¹*. The *L₁* and thus it is invert- ible over *R c*¯ ¨ ¯s}ď *β*¯. Next, from the verification equations for tr₀

*wi*“

### In particular, combined with b

Moreover, by parsing ˆt :“pˆt, we have ˆ⊺˙

|||c₀ ´ c||z₀ ´ z|
|---|---|---|---|---|
|piq||||i|
|b ,n|b ,n|i|b ,n|i|

p*i*q *i* G*b*1*,n*ˆt “ G*b*1*,n*b I*nδ*b G*b*1*,n*“ A¯s*i.* *c*¯ *c*¯*ic*¯

Therefore, we conclude that ´ ¯ p*i*q **w** :“*i i*Pr*r*s *i*Pr*r*s *i i*Pr*r*s

||p¯s q|, pˆt q|, pc¯ q|
|---|---|---|---|
|˚ b ,β, ¯ γ, ¯ κ ¯|i iPrrs|iPrrs|i iPrrs|

belongs to R ppp*,*①q. [\ 1

*Efficiency.* The communication complexity from the prover’s side can be bounded by *nd*rlog*q*s `p*n* ` 1q*δrd*rlogp2*b₁*qs ` *md*rlogp2*rκb₀*qs*.*

The prover’s running time is *O*p*r*p*m* ` *n* ` *δ*qq operations over *Rq*. On the other hand, the verifier’s time complexity is *O*p*n*¨p*nδr*` *m*qq operations over *Rq*. Since the witness size is *m* ¨ *r* elements in *Rq*, we deduce that the verifier runtime is sublinear.

3.2 Batching In this section we consider a full generalisation of the relation in Equation (5). Namely, let *k* ě 1 and fix a*j*P *R*
*m* *q,* b*j*P *R* *r* *q*for *j* P r*k*s. Next, consider any *k* positive integers *L₁,...,Lk*. In the context of polynomial commitments, *k* is the number of *distinct* evaluation points, and for the *j*-th point, we will prove *Lj* polynomial evaluations. Clearly, the previous protocol corresponds to the case *k* “ 1 and *L₁* “ 1. We focus on proving knowledge of short vectors ps*j,ι,i*q*j*Pr*k*s*,ι*Pr*Lj* s*,i*Pr*r*s, such that

|“s|‰ b||
|---|---|---|
|⊺|||
|j j,ι,1 j,ι|j,ι,r j j,ι|j|
|||j|

a |¨¨¨|s “ *y* @*j* Pr*k*s*,ι* Pr*L* s*,*

where all *y* are public. By including the commitment opening relation, we define (for presentation we fix the indices *j* Pr*k*s*,ι* Pr*L* s and *i* Pr*r*s):

### $ ˇ

ˆ, ’ ’˜ pA*,*pB*,*D q q*,* ¸ˇˇ @*j,ι,i,* řAs *j,ι,i*“ G*b*1*,n*t*j,ι,i*; / / & *j j j*ˇ*k* ˆ. ˇˇ “*j*“1 B t*j j*“ u; ‰ BR*b*0*,b*1:“ ppa*j,* b*j*q*j,* u*,* p*yj,ι*q*j,ι*q*,*⊺*.* ’ ’ ˆ ˆ ˇ @*j,ι,*a*j*s*j,ι,*1|¨¨¨|s*j,ι,r*b*j*“ *yj,ι*; // % pps*j,ι,i*q*j,ι,i,*pt*j*“pt*j,ι,i*q*ι,i*q*j*q ˇ- @*j,ι,i,*}s*j,ι,i*}8ď *b₀*;}ˆt*j*}8ď *b₁*

(7)
As before, width of the matrix G*b*1*,n*is *δ* ¨ *n* for *δ* :“ tlog*b* 1 *q*u. We present athree-round protocolfor BR*b*0*,b*1in Figure 2 and provide an informal description below due to more involved notation. The prover starts by computing for all *j* Pr*k*s*,ι* Pr*Lj*s:

´1 *δr* ⊺ ⊺ “ ‰ *r* wˆ*j,ι*:“ G *b* 1 *,r* pw*j,ι*qP *Rq,* where w*j,ι*:“ a*j*s*j,ι,*1|¨¨¨|s*j,ι,r*P *Rq*

⊺ “⊺ ⊺‰ and sets wˆ*j*:“ wˆ*j,*1|¨¨¨|wˆ*j,L* *j* for *j* Pr*k*s. Finally, it commits to all wˆ₁*,...,*wˆ*k* by sending v :“ D₁wˆ₁ `*...* ` D*k*wˆ*k*

to the verifier. Then, *L₁* `*...* ` *Lk*vectors c₁*,*1*,...,*c*k,Lk*generated uniformly
at random from *C* *r* are sent by the verifier. The prover responds by computing

ÿ *Lj* “ ‰ z*j*:“ s*j,ι,*1|¨¨¨|s*j,ι,r*c*j,ι*for *j* “ 1*,...,k* *ι*“1

and outputting pwˆ₁*,...,*wˆ*k*q*,*ˆt*,*pz₁*,...,*z*k*q. The verifier then checks whether
›» fi› g ˜ ¸ ˜ ¸ › pwˆ *j* q *j*Pr*k*s › f ÿ *k*ÿ*k* › › <u>1</u> f ›– pˆt *j* q *j*Pr*k*s fl› ď e*b²*p*n* ` 1q*δr L* *jd* `p*rκb₀*q² *ℓ² md* (8) › › 2 1 *j* › pz *j* q *j*Pr*k*s ›*j*“1 *j*“1

and ÿ *k* D*j*wˆ*j*“ v *j*“1 ÿ *k* B*j*ˆt*j*“ u *j*“1 »⊺fi » fi

(9)
b*j*G*b*1*,r yj,*1
—... ffi —... ffi
@*j* Pr*k*s*,* – fl wˆ*j*“ – fl

b ⊺ *j*G*b*1*,ryj,Lj* “⊺ ⊺‰ ⊺ @*j* Pr*k*s*,* c*j,*1G*b*1*,r*¨¨¨ c*j,L* *j* G*b*1*,r* wˆ*j*“ a *j*z*j* “⊺ ⊺‰ @*j* Pr*k*s*,* c*j,*1b G*b*1*,n*¨¨¨ c*j,L* *j* b G*b*1*,n*ˆt*j*“ Az*j.*

*n*ˆ*m n*ˆ*nδrLjn*ˆ*δrLj*

|Public parameters:|A P R|, pB|P R|, D P R|q|
|---|---|---|---|---|---|
|Witness: ps|P R q||, pˆt P R|q||
|Statement: pa|P R, b|P R q|, u P R, py|P R q|,|

*q j q j q j*Pr*k*s *m nδrLj* *j,ι,i q j*Pr*k*s*,ι*Pr*Lj*s*,i*Pr*r*s *j q j*Pr*k*s *j* *m* *q j* *r* *q j*Pr*k*s *n* *q j,ι q j*Pr*k*s*,ι*Pr*Lj*s

<u>Prover Verifier</u>

For *j* Pr*k*s : For *ι* Pr*Lj*s :“ ‰ w*j,ι* ⊺ :“ a ⊺ *j*s*j,ι,*1|¨¨¨|s*j,ι,r* P *R* *r* *q* wˆ*j,ι* ”:“ G ´ *b* 1 1 *,r*pw*j,ι*qPı*R* *δr* *q* wˆ*j* ⊺ :“ wˆ*j,* ⊺ 1 |¨¨¨|wˆ*j,L* ⊺ *j* ř*k n* v :“*j*“1D*j* wˆ*j* P *Rq* v- c₁*,*1*,...,*c*k,Lk* Ð *C* *r* <u>c₁,1,...,ck,Lk</u> For *j* Pr*k*s : “ ‰ ř*Lj* z *j* :“*ι*“1s*j,ι,*1|¨¨¨|s*j,ι,r* c*j,ι* <u>pwˆj,ˆtj, zj qjPr</u> <u>-</u> <u>ks</u> Accept iff (8) and (9) hold

Fig. 2: Proof of knowledge for the relation BR*b*0*,b*1in (7).

*Security analysis.* We prove completeness and coordinate-wise special soundness.

Lemma 3.3. *The protocol in Figure 2 for relation* BR*b*0*,b*1*satisfies perfect com-* *pleteness.*

*Proof.* We start with the norm checks. We know that for *j* P r*k*s, }wˆ*j*}8ď <u>b</u> 2 <u>1</u>

and }ˆt*j*}8ď <u>b</u> 2 <u>1</u>. Also, }z*j*}8ď *rκb₀Lj*{2. Hence, (8) holds by applying the naive *ℓ₈*-to-*ℓ₂* inequality. Now, we move on to (9). The first two equations hold trivially. As for the third one, we note that for any *j* Pr*k*s and *ι* Pr*Lj*s:

⊺ ⊺ ⊺ ⊺ “ ‰ b*j*G*b*1*,r*wˆ*j,ι*“ b*j*w*j,ι*“ w*j,ι*b*j*“ a*j*s*j,ι,*1|¨¨¨|s*j,ι,r*b*j*“ *yj,ι.*

### As for the fourth item:

“⊺ ⊺‰ ÿ *Lj* ⊺ c*j,*1G*b*1*,r*¨¨¨ c*j,L* *j* G*b*1*,r* wˆ*j*“ c *j,ι*G*b*1*,r*wˆ*j,ι* *ι*“1 ÿ *Lj* ⊺ “ w*j,ι*c*j,ι* *ι*“1 ÿ *Lj* ⊺ “ ‰ “ a*j*s*j,ι,*1|¨¨¨|s*j,ι,r*c*j,ι* *ι*“1 “ a ⊺ *j*z*j.*

For the last equation, we know that:

“⊺ ⊺‰ ÿ *Lj* ÿ *r* c*j,*1b G*b*1*,n*¨¨¨ c*j,L* *j* b G*b*1*,n*ˆt*j*“ *cj,ι,i*G*b* 1 *,n* ˆt *j,ι,i* *ι i*“1 ˜ *L* ¸ ÿ*j*ÿ*r* “ A *cj,ι,i*s*j,ι,i* *ι i*“1 “ Az*j.*

### This concludes the proof. [\

Similarly as before, we consider a relaxed relation for proving coordinate-wise special soundness:

|$ ’ ’|||ˇˇ ˇ|“ G|ˆ t;|, / /|
|---|---|---|---|---|---|---|
|’ ’ &˜|pA, pB|, D q q,|¸ˇˇ|“s B ˆt|“ u; ‰ b|/ /.|
|:“ ’|ppa, b q, u, py|q q,|ˇˇ @j,ι, a||¨¨¨|s|“ y|; /.|
|’ ’ ’ % pps|q, pˆt “pˆt|q q, pc|q q ˇˇˇ @j,ι,i, }c|¨ s}ď β¯;}c c P R, }ˆt|} }ď γ¯|ď κ ¯; / / /-|

@*j,ι,i,* řAs *j,ι,i b*1*,n j,ι,i* *j j j* *k* *j*“1 *j j* ˚ ⊺ BR*b* 1 *,β,* ¯ *γ,*¯ *κ*¯ *j j j j,ι j,ι j j,ι,*1 *j,ι,r j j,ι* *j,ι,i j,ι,i j j,ι,i ι,i j j,ι,i j,ι,i j,ι,i j,ι,i j,ι,i* 1 *j,ι,i* ˆ *q j* (10)

c ´ ¯ ´ ¯

||ř||ř||
|---|---|---|---|---|
|1 2|k||2 k|2|
|2|j“1|j|j“1|j|
||?12||||

Lemma 3.4. *Define γ*¯ :“ *b₁*p*n* ` 1q*δr L d* `p*rκb₀*q *ℓ md,*

*β* ¯ :“ 2¯*γ and κ*¯ :“ 2*κ. Suppose that κ*¯ ă *q. Then, there exists a polynomial* ?

*time algorithm that on input public parameters* pp :“pA*,*pB*j,* D*j*q*j*q*, statement* ř*k* ① :“ppa*j,* b*j*q*j,* u*,* p*yj,ι*q*j,ι*q *and* p*j*“1*Lj*q*r* ` 1 *accepting transcripts*

˜ ¸ ÿ *k* p*e*q p*e*qˆtp*e*q p*e*q tr*i*:“pv*,* c*,*pwˆ*j,j,* z*j*q*j*Pr*k*sq *for e* “ 0*,*1*,..., Ljr* *j*“1

p*e*q ř*k* *with* pc q*e*P SSp*C,*p*j*“1*Lj*q*r*q *and common first message* v*, either outputs a* ř*k* ˚ p*n*`1q*δr*p*j*“1*Lj* q *witness* **w** P BR *b* 1 *,β,* ¯ *γ,*¯ *κ*¯ppp*,*①q*, or* z P *Rqso that* “ ‰ B₁|¨¨¨|B*k*|D₁|¨¨¨|D*k*z “ 0 *and* 0 ă}z}ď *β.*¯

The proof follows almost identically as for Lemma 3.2. That is, we first claim that p*e*qř*k* unless we found a short Module-SIS solution, all wˆ*j*, for *e* “ 0*,*1*,...,*p*j*“1*Lj*q*r*, p*e*q must be the same (and similarly for ˆt*j*). Then, using the coordinate-wise special soundness property, we extract each vector s*j,ι,i*.

*Efficiency.* Communication complexity from the prover’s side can be bounded by ˜ ¸ ÿ *k*ÿ*k* *nd*rlog*q*s `p*n* ` 1q*δr Ljd*rlogp2*b₁*qs ` *md*rlogp2*rκb₀Lj*qs*.* *j*“1 *j*“1 ř*k* The prover’s running time is *O*pp*j*“1 *j q*

||L qrpm ` n ` δqq operations over R||. On|
|---|---|---|---|
|j“1 k|j||q|
|j“1 j|||j|

the other hand, the verifier’s time complexity is dominated by the last equation ř 2 of (9), which takes *O*p*n δr*p *L* q`*knm*q ring operations. Thus, if each *L* “ *O*p1q then the verifier runtime becomes asymptotically linear in *k*.

*Remark 3.5.* Note that trivially concatenating proofs would result in the verifi- cation time ˜ ˜ ¸¸ ÿ *k* *O* p*n²* ¨ *δ* ¨ *r* ` *n* ¨ *m*q¨ *Lj.* *j*“1

When *L₁* “*...* “ *Lk*“ 1 (i.e. we prove k polynomial evaluations at *k* different points) then our proposed batching method does not differ from trivially con- catenating proofs. The main advantage of our approach comes when one wants prove multiple polynomial evaluations at the *same evaluation point*.

## 4 Efficient Polynomial Commitments over Zq

In this section we show how to utilise the proofs of quadratic relations from Section 3 to efficiently prove polynomial evaluations. The key idea is that for a bivariate polynomial *m* ÿ ´1 *r*ÿ´1 *f*pX*,*Yq“ *fi,j*X *i* Y *j* *,* *i*“0 *j*“0

where the individual degrees of X and Y are *m* ´ 1 and *r* ´ 1 respectively, we can write » fi » fi 1

|||f₀ ¨¨¨|f₀|
|---|---|---|---|
|||,0|,r´1|
||2|,0 m´1,0|,r´1 m´1,r´1|
|q i i|⊺|i m´1|⊺|
||q|||

— ffi ffi Y ffi “ *m*´1 ‰ —— *f₁* ¨¨¨ *f₁* ffi —— Y² ffi *f*pX*,*Yq“ 1 X X ¨¨¨ X —... ffi — ffi (11)
–...... fl —.. ffi
–. fl *f* ¨¨¨ *fr*´1 Y

which is of the same form as in (5) by setting “ s‰ to be the *i* “-th column of the‰ middle matrix for *i* Pr*r*s, a :“ 1 X X² ¨¨¨ X and b :“ 1 Y Y² ¨¨¨ Y *r*´1. Therefore, the protocols in Section 3 can intuitively prove polynomial evalua- tions over *R*. However, there are two caveats. First, the protocols only support witnesses ps q with short coefficients. Additionally, to achieve compatibility with Polynomial IOPs, the polynomial commitments should be over finite fields, which is not the case for *R*. We deal with these issues as follows.

4.1 Adapting the Protocols from Section 3 *Short coefficients.* If we denote the *i*-th row of the middle matrix in (11) as f *i*P *R* *m* *q*for *i* Pr*r*s, then we can define s*i*:“ G
´ *b* 0 1 *,m* pf*i*qP *R* *δ* *q* 0 *m* for *δ₀* :“ tlog*b* 0 *q*u. Then, the coefficients of all s*i*are indeed short and

⊺ “ 2 *m*´1 ‰ *δ m* ⊺ “ ‰ a :“ 1 X X ¨¨¨ X G*b*0*,m*P *Rq* 0 *f*pX*,*Yq“ a s₁|¨¨¨|s*r*b where ⊺ “ 2 *r*´1 ‰ *r* *.* b :“ 1 Y Y ¨¨¨ Y P *Rq*

Hence, by setting Y :“ X *m* and using the protocols in Section 3 we can prove arbitrary polynomial evaluations of degree strictly less than *m* ¨ *r* over *Rq*.

*Working over* **Z***q.* We recall how one translates proving polynomial evaluations over **Z***q*to *Rq*as shown in [AFLN24]. Suppose *f* p*x*q “ *y* over **Z***q*and *f* has degree at most *N* ´ 1, where *N* is divisible by the ring dimension *d*. Then

*N* {*d*´1 *N* {*d*´1 ˜ ¸ *N* ÿ ´1ÿ*d*ÿ´1ÿ*d*ÿ´1 ` ˘ *i id*`*j j d i* *y* “ *fix* “ *fid*`*jx* “ *fid*`*jx* ¨ *x.* *i*“0 *i*“0 *j*“0 *i*“0 *j*“0

Let *σ*´1: *R* Ñ *R* be the Galois automorphism, which maps *X* ÞÑ *X* ´1. Thus, if we define the following *Rq*-elements:

*d* ÿ ´1 *d*ÿ´1 x :“ *x* *j* ¨ *X* *j* *,* f*i*:“ *fid*`*j*¨ *X* *j* for *i* “ 0*,*1*,...,N*{*d* ´ 1*,* *j*“0 *j*“0

then the constant term (as defined in Section 2) of

*N* ÿ {*d*´1 ` ˘ *d i* y :“ *σ*´1pxq¨ f*i*¨ *x* *i*“0

variable description instantiation *q* prime modulus, *q* ” 5 pmod 8q *N* degree bound on the polynomials *d* ring dimension, power-of-two poly a <u>pλq</u> *m* folding parameter *O*pa<u>N {d</u>q *r* folding parameter *O*p *N* {*d*q *n* height of matrices A*,* B*,* D *O*p1q *b₀ ℓ₈* norm of s₁*,...,*s*r q* 1{*O*p1q

*b₁ ℓ₈* norm of ˆt₁*,...,*ˆt*r q* 1{*O*p1q *δ₀* tlog*b* 0 *q*u *O*p1q *δ₁* tlog*b* 1 *q*u *O*p1q *κ ℓ₁* norm of a challenge a *ω*p1q *κ*¯ slack parameter a <u>q{2 ą κ¯ ě 2κ</u> *γ*¯ *ℓ₂* norm of z *γ*¯ :“ *b²*1p*n* ` 1q*δ₁rd* `p*rκb₀*q²*δ₀md* *β* ¯ *ℓ₂* norm bound on extracted witness 2¯*γ* *C C* *r* is the challenge space t*c* P *R* : }*c*}1 ď *κ*u SL slack space t*c* P *R* : }*c*}1 ď *κ*¯u *r* e identity element in SL p1*,...,*1q

Fig. 3: Overview of the notation.

is equal to *y* [LNP22]. Also, the equation above is a polynomial evaluation state-

|d|q|||ă q N {d|
|---|---|---|---|---|
|||N {d´1|N {d q||
||d q||||
||q||||
|d|´1 ´1||||

ment *σ*´1pxq¨ fp*x* q“ y over *R*, where the polynomial f P *R* rXs has coeffi- cients pf₀*,...,*f qP *R,*

the evaluation point is *x* P *R* and the image is y defined above. Therefore, the prover can first send y P *R* in the clear and proceed with proving knowledge of f such that fp*x* q “ *σ* pxq ¨ y. Note that now we prove evaluations for polynomials of degree less than *N* {*d* rather than *N*. We refer to [AFLN24, Section

5.5] for more details.
4.2 Construction We present our basic construction PCS “pSetup*,*Commit*,*Open*,*Eval*,*Verifyq for- polynomials over **Z***q*rXs of degree less than *N* :“ *m* ¨ *r* ¨ *d* in Figure 4. Basic notation is summarized in Figure 3. The slack space is defined as SL :“ t*c* P *R* : }*c*}1ď *κ*¯u
*r* for ¯*κ* ě 1. We set the identity e :“ p1*,...,*1q P SL. As before, we define *C* :“ t*c* P *R* : }*c*}1ď *κ*u. As a building block, we need a proof system *Π¹* “p*S¹, P¹, V¹*q for the relation R¹ defined as follows:

R¹ :“tppp*,*pP*,* h*, γ*¯q*,*zq : Pz “ h ^}z}ď *γ*¯u*.* (12)

We are ready to summarise the security properties of our polynomial commit- ment.

*λ*

|Setupp1 q:||||Openppp, u,f, st :“ps|, ˆt|q, pc q|
|---|---|---|---|---|---|---|
|1: A Ð R||||1: f pXq :“ ř|f X||
|2: B Ð R||||2: for i “ř|0, 1,...,N {d ´ 1 :||
|3: D Ð R 4: pp¹ Ð S¹p1|q|||3: f :“ 4: for i “ 1,...,r:|f X|P R|
|5: return pp :“pA, B, D, pp¹q||||5: f :“pf|,..., f|qP R|
|Commitppp,f P Z|rXsq:|||6: if G|s ‰ f _ As|‰ G|
|1: f pXq :“|ř f X|||7: return 0|||
|2: for i “ř|0, 1,...,N {d ´ 1 :|||8: if }c|¨ s }ą β¯ _}c }|ą κ ¯ _ c|
|3: f :“|f|X P R||10: ˆt 9: :“rˆt return||¨¨¨|ˆt 0 s||
|4: for i “ 1,...,r:||||11: if }ˆt}ą¹γ¯ _ Bˆt|‰ u||
|5: f :“pf|,..., f|qP R||12: return 0|||
|6: s :“ G 7: t :“ As|pf q|||13: return 1|||
|8: ˆt :“ G|pt q||||||
|9: ˆt :“pˆt 10: u :“ Bˆt|q P R||||||
|11: st :“ps 12: return pu, stq|, ˆt q||||||
|Eval.P ppp, pu,x,yq, pf, st :“ps||, ˆt|qqq:|Eval.V ppp, pu,x,yqq:|||
|1: f pXq :“|ř f X|||1: x :“ ř|x ¨ X|‰ G|
|2: for i “ř|0, 1,...,N {d ´ 1 :|||2: a :“ “1 x|x² ¨¨¨ x||
|3: f :“ ř|f|X P R||3: b :“ “1 x|x² ¨¨¨ x|‰|
|4: x :“ ř|x ¨ X|` ˘||4: receive py, vq from Eval.P|||
|5: y :“ “|σ pxq¨ f|¨ x ‰||5: send c Ð C|to Eval.P||
|6: a :“ “1 x|x² ¨¨¨ x||G ‰|6:compute P, h, γ¯ as in Lines 14 to 16 of|||
|7: b :“|1 x“ x²|‰¨¨¨ x||Eval.P|||
|8: w :“ a 9: w ˆ :“ G 10: v :“ Dw 11: send py, vq to Eval.V|s₁|¨¨¨|s pwqP R ˆ P R|P R||7: if ctpyq‰ y 8: 9: else run V¹ppp¹, pP, h, γ¯qq return 0|||
|12: receive c “|P C ‰from Eval.V||||||
|13: z :“ » s₁|¨¨¨|s|c||fi||||
||D|0|0||||
|— — 14: P :“ — —b G|0|B 0|0 ffi ffi 0 ffi ffi||||
|–c|G 0 c|0 ´a b » G ´A|fl fi||||
|»|w ˆ fi|— — u v|ffi ffi||||
|15: z :“ – ˆt fl,|h :“ — z|—σ pxq – 0|¨ yffi ffi fl||||
|a||0|||||
|16:¯ γ :“ 17: run P¹ppp¹, pP, h, γ¯q, zq|b₁pn ` 1qδrd `prκb₀q δ₀md||||||

<u>i i iPrrs i iPrrsq</u> *n*ˆ*δ*0*m i* *q iN*“´01 *i* *n*ˆ*nδr* *q* *n*ˆ*δr d*´01 *j* *q i j*“ *id*`*j q* *λ* ⊺ *m* *i* p*i*´1q*m im*´1 *q* ă*N* <u>q</u> *b*0*,m i i i b*1*,n*ˆt*i* *i* *iN*“´01 *i* ˆ *i i i* 1 *i* R *Rq* *d*´01 *j* *i j*“ *id*`*j q* ⊺ ⊺ ⊺ *r* ⊺ *m* *i* p*i*´1q*m im*´1 *q* ´1 *i b*0*,m i* *i i* ´1 *i b*1*,n i* *nδr* *i i*Pr*r*s *q*

*i i i*Pr*r*s

*i i* *i d*´01 *j j* *iN*“´01 *i j*“ ⊺ *d d* p*m*´1q*d* *d*´01 *j b*0*,m* *i j*“ *id*`*j q* ⊺ *md md* p*r*´1q*md* *d*´01 *j j* *j*“ *N d*´1 *d i r* *i*“{0 ´1 *i* ⊺ *d d* p*m*´1q*d* *b*0*,m* ⊺ *md md* p*r*´1q*md* ⊺ ⊺ *r* *r q* ´1 *δr* *b*1*,r q* *n* *q*

*r*

*r*

⊺ *b*1*,r* ⊺ ⊺ *b*1*,r* ⊺ *b*1*,n*

´1 ´1

2 2

Fig. 4: Description of the Setup*,*Commit*,*Open and Eval “pEval*.P,* Eval*.V*q algorithms.

Theorem 4.1. *The polynomial commitment* PCS *defined in Figure 4 satisfies* *evaluation completeness, weak binding, and knowledge soundness under the Module-* *SIS assumption. Namely, let Π¹* “p*S¹, P¹, V¹*q *be a proof system for the relation* R¹*. Then, the following hold.*

*1.For evaluation completeness,* PCS *satisfies evaluation completeness with com-* *pleteness error ϵ¹, where ϵ¹ is the completeness error for Π¹.*
*2.For weak binding, there is a deterministic algorithm, that given public param-* *eters* pA*,* B*,* D*,*pp¹q Ð Setupp1
*λ* q*, and two weak openings* p*f,* ps*i,*ˆt*i,ci*q*i*Pr*r*sq *and* p*f¹,*ps¹*i,*ˆt¹*i,c¹i*q*i*Pr*r*sq *for the commitment* u P *R* *n* *qsuch that f* ‰ *f¹, outputs* *a vector* z P *R* *δ* *q* 0 *m*`*nδ*1 *r* *such that* rA | Bsz “ 0 *and* 0 ă}z}ď maxp4¯*κβ,*¯ 2¯*γ*q*.*

*3.As for knowledge soundness, there is an expected PPT extractor E with the* *folowing properties. Given rewindable black-box access to a PPT prover P*
˚

*that convinces* Eval*.V*ppp*,*pu*,x,y*qq*, where* pp :“pA*,* B*,* D*,*pp¹qÐ Setupp1 *λ* q*,* *with probability ε, extractor E with probability at least*

1<u>r</u> *ε* ´ *ε* ´ |*C*|

*either outputs f,* st*,* p*ci i*Pr*r*s*such that* Openppp*,* u*,f,* st*,* p*ci i*Pr*r*s

||q|q q “ 1, or a|
|---|---|---|
|pn`1qδ q|r||

p*n*`1q*δ*1 *r*¯ 1 *vector* z P *Rqsuch that* rB|Dsz “ 0 *and* 0 ă}z}ď *β, where ε is the* *knowledge error of Π¹.*

*Proof.* We first show that a modified scheme, where instead of running *Π¹* the prover outputs z in the clear, satisfies perfect evaluation completeness. The state- ment then follows by composition. Take any polynomial *f* P **Z** ă *q N*rXs. Then, for pp :“pA*,* B*,* D*,*pp¹qÐ Setupp1 *λ*

|||q and pu, st :“ps|, ˆt q|qÐ Commitppp,f q we|
|---|---|---|---|---|
||´ 1,m|λ|i i iPrrs||
|b ,m i i|b ,m b|i i|i i|b ,n i|

*i i i*Pr*r*s have

G0s “ G0G 0 pf q“ f and As “ t “ G1pˆt q for *i* Pr*r*s*.*

? Moreover, }s} ď *b₀ δ₀md* ď *β*¯ for all *i*. Therefore, Openppp*,* u*,f,* st*,*eq “ 1. Finally, by applying the methodology described in Section 4.1 together with Lemma 3.3, we conclude that the underlying evaluation protocol satisfies perfect completeness, and thus the claim holds. We move on to weak binding. From Lemma 2.11 we deduce that either all s “ s¹ for all *i*, or there is an efficient algorithm which finds a short solution

|i i|||
|---|---|---|
||i b ,m i|b ,m i i1|

to rA|Bs. Suppose the former case. Since f “ G0s “ G0s¹ “ f for all *i*, and therefore we conclude that *f* “ *f¹*, which leads to a contradiction. As for knowledge soundness, we first consider the modified evaluation proto- col, where instead of running *Π¹*, the prover outputs z in the clear. The state- ment then follows by the composition result [BS23, Lemma 3.7]. To begin with, we use Lemmas 3.2 and 2.6 to deduce that the knowledge error of the evalua- tion protocol is at least *r*{|*C*|. This means that we can define an extractor that with probability at least *ε* ´ *r*{|*C*| either outputs a short solution to rB|Ds, or st :“ p¯s*i,*ˆt*i*q*i*Pr*r*sand p*c*¯*i*q*i*Pr*r*sP SL such that for }pˆt*i*q*i*Pr*r*s} ď *γ*¯ and }*c*¯*i*¨ ¯s*i*} ď *β*¯

<u>size runtime</u> commitment eval. proof prover verifier ? *Oλ*p1q *Oλ*plog log*N* q *Oλ*p*N* q *Oλ*p *N* q

Table 3: Asymptotic efficiency in terms of **Z***q* elements and operations.

for all *i* Pr*r*s and

|||||» 1|fi|
|---|---|---|---|---|---|
|“||‰|“|‰ — — — x|ffi ffi ffi|
|1 x x|¨¨¨ x|G|¯s₁|¨¨¨|¯s|— — x² .. –.|ffi “ σ ffi fl|

*md* *md*

|d 2d|pm´1qd||md|´1|
|---|---|---|---|---|
||i|b ,m b ,m i ă q N|r pr´1qmd|´1 q|

0pxq ¨ y*.*

*x*

Then, by defining f :“ G0¯s for *i* P r*r*s and following the strategy from Section 4.1, one can extract *f* P **Z** rXs so that *f* p*x*q“ *y* over **Z**. This concludes the proof. [\

*Remark 4.2.* We highlight that matrices A*,* B*,*D can be generated uniformly at random from a seed. Thus, by embedding a Module-SIS challenge inside the aforementioned matrices yields weak binding and knowledge soundness under the Module-SIS assumption.

4.3 Instantiation and Asymptotic Efficiency We set asymptotic parameters for our polynomial commitment scheme as de- scribed in Figure 3. We instantiate our evaluation protocol with LaBRADOR [BS23] as the underlying proof system *Π¹*. We first show that R¹ is a folklore lattice-type relation that is a special case of *principal relations* (cf. Section 2.4). Thus, we can directly apply the LaBRADOR proof system [BS23] to produce a succinct proof.
a The length of the vector z is p*n* ` 1q*δ₁r* ` *m* “ *O*p *N* {*d*q elements in *Rq*, while the height of the matrix P is 3*n* `2“ *O*p1q. Denote by p ⊺ *i*the *i*-th row of P. We can then split the vector z into *r¹* subvectors z₁*,...,*z*r*1 of length *n¹* each, where *r¹* ¨ *n¹* “ p*n* ` 1q*δ₁r* ` *m*. We proceed similarly for all row vectors ⊺

|p :“rp||¨¨¨|p|s. Then, the linear equation of (12) can be rewritten as 3n`2||||
|---|---|---|---|---|---|
|i|i,1|i,r||||
|||i|r i,j|j||
||||j“1|||
|||n`2||||

*i* ⊺ *i,*1 ⊺ *i,r*1 constraints of the form:

ÿ 1

*f* pzq :“ xp*,* z y´ *hi*“ 0 for *i* Pr3*n* ` 2s

where h :“p*h₁,...,h₃* q. Hence, we formulated the relation in (12) using the native language of LaBRADOR. We apply the LaBRADOR proof system as an underlying building block and pick the most asymptotically optimal parameters

as described in [BS23, Section 1.1]. In particular, we set the multiplicity *r¹* and rank *n¹* as follows: ´ <u>1</u> ¯ ´ <u>1</u> ¯ *r¹* “ *OλN*6and *n¹* “ *OλN*3*.*

Then, the LaBRADOR sub-protocol has *O*plog log*N*q rounds and the total size of prover’s messages in our evaluation protocol, in terms of the number of *Rq*- elements, is *Oλ*plog log*N*q. The prover runtime (in terms of the number of *Rq*-operations) of our evalu- ation protocol can be split the two parts. The first one is running the protocol in Figure 1, which takes *Oλ*p*r* ¨ *m*q “ *Oλ*p*N*q operations. As for running the LaBRADOR building block, the main bottleneck is computing the so-called 1 2 1 2{3 garbage cross-terms, which takes at most *Oλ*p*r* ¨ *n* q “ *Oλ*p*N* q operations over **Z***q*. Hence, the naive upper-bound on the prover time for this sub-protocol is *Oλ*p*N* 2{3 log log*N*q. By combining the two parts, we conclude that the total prover runtime is *Oλ*p*N*q. Similarly as above, the verifier runtime can be analysed in two parts. The first is receiving the vector ? v and generating the challenge c, which takes *Oλ*p*r*q “ *Oλ*p *N*q time. Further, the verifier runs the verification algorithm ?from the LaBRADOR protocol, where the statement size is *Oλ*p*r* ` *m*q “ *Oλ*p *N*q ele- ments over *Rq*. Since the verifier time for LaBRADOR is linear in the size of ? the statement, we conclude that the total verifier runtime is *Oλ*p *N*q.

4.4 Batching Evaluation Proofs Suppose we want to prove knowledge of *L* polynomials p*f* q*j* sover **Z***q*

|||j,ι jPrks,ιPrℓ|
|---|---|---|
|j,ι j|j,ι|j|
 such that
*f* p*x* q“ *y* for *j* Pr*k*s*,ι* Pr*ℓ* s*.*

We can do this similarly as before by adapting the protocol in Figure 2, where *k* is now the number of distinct evaluation points, and for the *j*-th point, we want to prove *ℓj*ě 1 polynomial evaluations. Then, by following the strategy from ř*k* Section 4.1, the prover needs to send *L* :“*j*“1*ℓj*ring elements py*j,ι*q*j*Pr*k*s*,ι*Pr*ℓj* s in the clear. Even though in many Polynomial IOPs we have *L* “ *O*p1q, and thus suc- cinctness is asymptotically preserved, sending all *L* full-sized elements in *Rq*can be costly in practice. To circumvent this problem, one can instead commit to the vector y :“ py*j,ι*q*j*Pr*k*s*,ι*Pr*ℓj* sP *R* *L* *q*and later prove its well-formedness, as well as that the constant term of each y*j,ι*equals *yj,ι*. The key observation here is that these “constant term”-type statements are also natively supported by principal relations, and therefore we can still apply LaBRADOR in a black-box manner.

4.5 Hiding Our current construction of the polynomial commitment scheme does not na- tively satisfy the hiding property. Namely, both the commitment and the evalu- ation protocol may reveal information about the committed values. To remedy this, we introduce the following simple changes.

*Computationally hiding commitment scheme.* First, we use the hiding version of the outer commitment scheme by sampling a randomness vector r Ð *χ* *µ* and computing the commitment u :“ Bˆt ` Er (instead of u “ Bˆt), where E P *R* *n* *q* ˆ*µ*

is an additional uniformly random matrix. By the (knapsack) Module-LWE as- sumption, the commitment u looks pseudorandom. Hence, one needs to choose the parameter *µ* big enough to ensure that u does not leak any information about ˆt, while not too big since it directly affects efficiency of the underlying scheme.

*Defining weak binding.* In the hiding version of the commitment, we define a weak opening to additionally contain a short randomness vector r, such that u “ Bˆt ` Er. More concretely, a weak opening for the commitment u is a tuple pps*i,*ˆt*i,ci*q*i*Pr*r*s*,*rq, which satisfies all the following conditions

@*i* Pr*r*s :}*ci*¨ s*i*}ď *β,*¯}*ci*}1ď *κ,*¯ *ci*P *R* ˆ *q,* As*i*“ G*b,n* ˆt *i* ›» fi› » fi › ˆt₁ › ˆt₁ › › ›—. ffi› — ffi ›—. ffi› B – ... fl ` Er “ u and ›—. ffi› ď *γ.*¯ ›–ˆ fl› t *r* ˆt *r* ›› ›› r

Suppose we have two weak openings pps*i,*ˆt*i,ci*q*i*Pr*r*s*,*rq and pps¹*i,*ˆt¹*i,c¹i*q*i*Pr*r*s*,*r¹q for the same commitment u. Note that if ˆt*i*‰ ˆt¹*i*for some *i*, then we immediately yield a short solution for the uniformly random concatenated matrix rB | Es. We argue analogously for the case r ‰ r¹. The rest of the proof follows similarly as in Lemma 2.11. Finally, we highlight that in the knowledge soundness argument, we will be able to extract such a weak opening, since the additional randomness vector r is a part of the witness for the LaBRADOR subroutine (see (14)).

*HVZK Evaluation Proof.* We modify the evaluation protocol to achieve honest- verifier zero-knowledge (HVZK) as follows. To begin with, note that sending y P *Rq*in the clear, and in particular the non-constant terms of y, may naturally reveal some information about the secret polynomial *f*. To circumvent this issue, we follow the strategy from [ENS20, LNP22]. Let *L* ě 1 be the soundness pa- rameter. The prover at the beginning samples masking terms l :“p*l₁,...,lL*qÐ t*l* P *Rq*: ctp*l*q“ 0u *L*. Then, it computes ˆl :“ G ´ *b* 1 1 *,L* plq. Next, it commits to both

wˆ*,*ˆl by sampling r*v*Ð *χ* *µ* and computing

v :“ D₀wˆ ` D₁ˆl ` Er*v*

where D₀*,*D₁*,*E are part of public parameters. Similarly as before, v is compu- tationally indistinguishable from random. The first prover message is v. In the second round, the verifier provides *L* challenges *α₁,...,αL*Ð **Z***q*. The prover replies with j :“p*j₁,...,jL*q where

*j* *i*:“ *li*` *αi*¨ y for *i* “ 1*,...,L.* (13)

Note that ctp*ji*q “ ctp*li*` *αi*¨ yq “ *αi*¨ ctpyq “ *αi*¨ *y* by definition of *l₁,...,lL*. In particular, the verifier can manually check whether constant terms of each *j* *i*are exactly *αi*¨ *y*. Moreover, sending all *ji*reveals no information about the coefficients of y apart from the constant term. Finally, we have to prove well-formedness of polynomials *j₁,...,jL*in Equa- tion (13). That is, “ ‰ ¨ *σ* s₁|¨¨¨|s b

||j|“ l ` α|pxq¨ a|||
|---|---|---|---|---|---|
|||i i i|´1 ⊺|r||
|||i b ,L|i ´1|⊺ b ,r||
|||i L q||||
||||||r|
|v||||||

“ e G1ˆl ` *α* ¨ *σ* pxq¨ b G1wˆ

for *i* P r*L*s, where e P *R* is the binary vector with 1-entry in exactly *i*-th position and a*,* b*,* wˆ are constructed as before. Then, given a challenge c Ð *C*, the prover now runs the proof system *Π¹* to prove knowledge of short vectors wˆ*,*ˆl*,* r*,*ˆt*,* r*,*z which satisfy » fi » fi D₀ D₁ E 0 0 0 » fi v — 0 0 0 B E 0 ffi wˆ — u ffi — ffi — ˆ ffi — ffi

|pxq¨ b|G|e₁G 0|0 0|
|---|---|---|---|
|´1|⊺ b ,r|b ,L||
|L ´1|⊺ b ,r|L b ,L||
|⊺|b ,r|||
||||b ,n|

—*α₁* ¨ *σ* 1 10 ffi — l ffi —*j₁*ffi — ffi — ffi — ffi
—............ ffi —r*v*ffi — .. ffi
—...... ffi — ˆ ffi “ —. ffi*.* (14)
— ffi — t ffi — ffi —*α* ¨ *σ* pxq¨ b G e G 0 0 0 0 ffi – fl —*j* *L* ffi — 1 1 ffi r — ffi – c G 10 0 0 0 ´a ⊺fl – 0 fl ⊺ z 0 0 0 c b G10 ´A 0

Finally, we require *Π¹* to satisfy HVZK. As demonstrated in [BS23, Section 6], we can still apply LaBRADOR to achieve a hiding polynomial commitment scheme. The intuition for knowledge soundness comes from the following observation, which is used to formally argue (coordinate-wise) special soundness. Suppose we are given two distinct tuples p*α₀*

|||,...,α₀|q ‰ pα₁|,...,α₁|q, along with 2L|||
|---|---|---|---|---|---|---|---|
|b,i|bPt0,1u,iPrLs|,1|,L|,1|,L|||
|b,i i|b,i|b,i|b,i ,i|,i||,i|,i|
|q ´L|||,i|,i|,i|,i|,i|

polynomials p*j* q such that

*j* “ *l* ` *α* y and ctp*j* q“ *α* ¨ *y* for *b* Pt0*,*1u*,i* Pr*L*s*.*

First, there exists some index *i* for which *α₀* ‰ *α₁*, and thus *α₀* ´ *α₁* is invertible over **Z**. Also, the constant term of *j₀* ´*j₁* “p*α₀* ´*α₁* qy is p*α₀* ´ *α₁,i*q*y*. Therefore, we conclude that the ctpyq “ *y*, which is what we wanted. Hence, the soundness error of our HVZK protocol is increased by an additive factor of *q*.

*Remark 4.3.* We note that the prover actually does not need to reveal all the *L* ring elements *j₁,...,jL*defined in (13). The reason is that LaBRADOR na- tively also allows to prove statements related to constant terms (see Section 2.4) by applying the same “masking non-constant term” technique as shown above. Thus, we can directly use the framework to prove that ctpyq“ *y*.

## 5 Concrete Parameters

We now discuss how to set the various parameters in Greyhound. Similar strate- gies as in LaBRADOR are employed. We use the standard power-of-two cyclo- tomic ring of dimension *d* “ 64 and modulus *q* « 2 32, and challenges with *τ₁* “ 32

non-zero coefficients that are ˘1 and *τ₂* “ 8 non-zero coefficients that are ˘2. For simplicity, in the above presentation of the protocol we have used the same SIS rank *n* for the inner and outer commitments (i.e. height of the matrices A and B). However, it is indeed more efficient to allow for different ranks and we denote them by *n* and *n₁* for the inner and outer commitments, respectively. They need to be chosen large enough to achieve (weak) binding. We do this in the standard way with respect to the relevant norm bounds, c.f. [MR08]. The *N* {*d* witness polynomials that make up the polynomial *f* P **Z***q*r*X*s are distributed over *r* vectors of length *m*. So we need to have *rm* ě *N* {*d*. Then the vectors are decomposed into *δ₀* parts with respect to the small integer basis *b₀* in order to commit to them. So here we want to have *δ₀* logp*b₀*q« logp*q*q. In the protocol the last prover message, i.e. the witness for the LaBRADOR statement, consists of *r* commitments that are each decomposed into *δ* parts of length *n*, the decomposed *w*ˆ vector of length *δr*, and the amortized opening *z* of length *δ₀m*, which is decomposed into two parts with respect to the basis *b* before handing it over to LaBRADOR. Our goal is thus to minimize *rδ*p*n* ` 1q` 2*δ₀m* under the constraint *rm* ě *N* {*d*. We approximate *b₀* “ *b* and hence *δ₀* “ *δ*. Then we find Sc _ R V <u>N pn ` 1q N</u> *m* “ and *r* “*.* 2*d md*

<u>b²</u> We predict the variance of the decomposed *z* vectors to be *vz*“ 12 *r*p*τ₁* ` 4*τ₂*q, where we have used *b²*{12 for the variance of the discrete uniform distribution Q U on t´*b*{2*,...,b*{2 ´ 1u. Then we use logp*b*q “ <u>logp12</u> 4 <u>v</u> <u>z</u> <u>q</u> as the decomposition

basis for *z*, and *δ* “ rlogp*q*q{ logp*b*qu. Finally, the square of the predicted total norm for the LaBRADOR statement turns out to be

|ˆ ˙|˙|
|---|---|
|2 v|2 2|
|2|2pδ´1q|

ˆ *b z b q* ` *mδ₀d* ` p*δ* ´ 1q ` p*n* ` 1q*rd.* 12 *b* 12 12*b*

We summarize the concrete parameters that we have used in our implemen- tation in Table 4. For the parameters inside LaBRADOR and how to optimize them see the Labrador paper. The concrete contributions from the Greyhound protocol to the proof sizes for *N* “ 2 26, *N* “ 2 28 and *N* “ 2 30 due to the parameter choices in Table 4 are 3*.*75 KB, 3*.*75 KB and 4*.*25 KB, respectively.

*Making the protocol zero-knowledge.* As explained in Section 4.5 for adding zero-knowledge it suffices to add LWE randomness to the outer commitments and mask the polynomial *y* where the uniformly random masks need to be put into the first outer commitment. This is similar to LaBRADOR. Unlike in LaBRADOR there is no Johnson-Lindenstrauss projection in Greyhound which would be more complicated to mask since it would need a short mask and rejec- tion sampling. We refer to [BS23] for the details. The relatively low-dimensional randomness vectors and masks do not increase the total norm of the output wit- ness much and hence the SIS ranks for the outer commitments can stay the same. Since *q* « 2 32 we need *L* “ 4 masking terms for *y* so the proof size of Greyhound

*N* “ 2 26 *N* “ 2 28 *N* “ 2 30

*m* 3156 6312 12625 *r* 333 665 1329 *n* 18 18 18 *n₁* 7 7 7 *b₀* 6 5 4 *δ₀* 5 6 8 *b* 7 6 6 *δ* 5 5 5

Table 4: Concrete parameter choices for Greyhound for three different polynomial

lengths *N*.

goes up by three additional polynomials, or 0*.*75KB. For the LWE randomness we use the uniform distribution modulo *b*. Then the required LWE rank to achieve the hiding property can be computed in the usual way, c.f. [ADPS15].

## 6 Implementation

We have implemented Greyhound and LaBRADOR in C with intrinsics for vec- torization using the AVX-512 instruction set. The source can be found here:

https://github.com/lattice-dogs/labrador*.*

Our code is single-threaded and so we do not make use of parallization beyond SIMD. We have deviated from the LaBRADOR paper in a few ways. Most im- portantly we only use power-of-two bases for decomposing vectors, and sample the matrices for the Johnson-Lindenstrauss projections to have coefficients that are ˘1 instead of ´1*,*0*,*1. The heuristic from [GHL22, BS23] regarding the tail of the distribution of the projected vectors still applies. The power-of-two decom- position bases mean that we do not achieve the best possible proof sizes. Also we have not yet implemented the most elaborated parameter selection strategy and optimize the parameters for each LaBRADOR layer locally instead of globally optimizing over all layers. The focus of this paper is on runtime and we leave the proof size optimization to later work. The proof sizes are determined by the later LaBRADOR layers where the instance sizes are already so small that those layers do not contribute significantly to the runtime. Therefore we believe that one can improve our proof sizes without influencing the runtime. Since vectorized code on the Intel architecture often bottlenecks on the front- end of the CPU pipeline we tried to structure our code in a way that is friendly to the *µ*op cache. Concretely, this means that we try to compute on chunks of polynomial vectors that are short enough to fit into the data caches but long enough that the same small code section (for example implementing an NTT) is used on many polynomials and comes from the *µ*op cache rather than the L1 instruction cache and decoding.

For sampling randomness we use the new vectorized AES instructions from the VAES instruction set that compute four (independent) AES-128 rounds si- multaneously. Together with hiding the instruction latencies by computing suffi- ciently many AES blocks in parallel this results in our sampler outputting blocks of 512 bytes of randomness at a time. For the hashing needed in the Fiat-Shamir transform we use SHAKE128.

6.1 Polynomial Arithmetic Library As part of our implementation we provide an optimized library for polynomial arithmetic modulo (low-degree) power-of-two cyclotomics and primes *q* of the form *q* “ 2 *d*
´ *a* for *d* “ 3*,...,*263 and minimal *a* such that *q* ” 5 pmod 8q. The library is fully vectorized and includes functions for sampling polynomials from various distributions and applying ring automorphisms. For theoretical reasons the prime *q* defining the quotient polynomial ring *Rq* for the LaBRADOR proof system needs to have high inertia degree. Therefore we can not use NTT-based multiplication directly for the ring *Rq*. Instead we use a multi-modular algorithm with NTT-based multiplication modulo several small primes *pi*. This is similar to [CHK ` 21]. Unlike [CHK ` 21] where a divided- difference based CRT algorithm is used to lift the results from mod *pi*, followed by reduction modulo *q*, we use the explicit CRT mod *q* from [BS07]. This is advantageous in our case since we compute modulo more small primes primes *pi*. For the *pi*we use primes between 2 12 and 2 14 that are fully splitting in the main ring **Z**r*X*s{p*X⁶⁴* ` 1q in LaBRADOR. Such 16-bit primes allow us to use the fast Montgomery arithmetic from [Sei18] and [LS19] on the x86 instruction set. For the multi-precision arithmetic modulo *q* we use 14-bit limbs. This is not optimal but allows us to always compute on vectors of 16-bit integers. This also includes the fixed-point approximation to the quotient in the explicit CRT. Moreover, the 14-bit limbs enable a fast forward CRT-map using a (modified) Montgomery reduction algorithm. The arithmetic mod *q* is much less relevant for the overall speed of our protocols compared to the arithmetic modulo the *pi* where most of the operations take place. We keep the computation of CRT maps and NTTs to a minimum and com- pute in the multi-modular NTT representation as much as possible. This is the main advantage of NTT-based multiplication in lattice-based protocols with arithmetic in high-rank modules. In the case of Greyhound and LaBRADOR this means that the arithmetic becomes effectively linear. Instead of the usual sign-and-magnitude representation for the multi-precision arithmetic modulo *q* we use two’s complement and allow for signed limbs in our representation. The main advantage of this is that conversion to and from short polynomials that are stored in signed single-precision representations are very fast. This explains the reason for the 14 bits: positive limbs can go up to 2 15 ´ 1 to not overflow into negative values and we need one nail bit to handle the carries in our vectorized algorithms.

For computing commitments we compute over extension rings by viewing them as vector spaces over our base ring. This reduces the randomness that has to be sampled for the commitment matrices. The computational cost stays quadratic in the extension degree (resp. the SIS rank).

6.2 Johnson-Lindenstrauss Projection For fast computation of the Johnson-Lindenstrauss reductions in LaBRADOR which essentially entails a matrix-vector product where the matrix has coeffi- cients that are ˘1, we use the Four Russians algorithm on blocks of 4 integers. We precompute 16 vector registers at a time, each containing the 16 possible signed summations of 4 vector coefficients. Then, for every matrix row and four times four columns we lookup the correct summations from the precomputed vectors using vector shuffle instructions.
6.3 Future Work Unlike AVX2, AVX-512 has 52-bit integer instructions that include fused low and high half multiply and add instructions. These instructions enable fast vectorized NTTs modulo 52-bit primes *pi*, c.f. [BKS
` 21]. The advantage of this approach would be that one could compute the commitments directly with NTTs for the extension rings instead of implementing the extension ring arithmetic using quadratic linear algebra over the 64 dimensional base ring. Concretely we often compute commitments in extension rings of rank 16 over *Rq*“ **Z***q*r*X*s{p*X⁶⁴* ` 1q with a cost of 16 2 pointwise multiplications of length 64 (note that the NTTs don’t matter as they can be precomputed in case of the commitment matrices and reused many times in case of the matrices and the vectors). By directly computing length-1024 pointwise products when the *pi*are fully splitting in **Z***q*r*X*s{p*X¹⁰²⁴* ` 1q one can reduce the computational cost to only one pointwise product of length 1024 and hence reduce the cost by a factor of 16.

## Acknowledgements

We would like to thank the reviewers for their useful comments. Ngoc Khanh Nguyen was supported by the Protocol Labs RFP-013: Cryptonet network grant. Gregor Seiler was supported by the EU H2020 ERC Project 101002845 PLAZA.

## References

ACL `

22.Martin R. Albrecht, Valerio Cini, Russell W. F. Lai, Giulio Malavolta, and Sri Aravinda Krishnan Thyagarajan. Lattice-based snarks: Publicly verifiable, preprocessing, and recursively composable - (extended abstract). In *CRYPTO (2)*, volume 13508 of *Lecture Notes in Computer Science*, pages 102–132. Springer, 2022.

ADPS15.Erdem Alkim, L´eo Ducas, Thomas P¨oppelmann, and Peter Schwabe. Post-quantum key exchange-a new hope. *IACR Cryptol. ePrint Arch.*, 2015:1092, 2015. AF22.Thomas Attema and Serge Fehr. Parallel repetition of p*k₁,...,kµ*q-special- sound multi-round interactive proofs. In *CRYPTO (1)*, volume 13507 of *Lecture Notes in Computer Science*, pages 415–443. Springer, 2022. AFK22.Thomas Attema, Serge Fehr, and Michael Klooß. Fiat-shamir transfor- mation of multi-round interactive proofs. In *TCC (1)*, volume 13747 of *Lecture Notes in Computer Science*, pages 113–142. Springer, 2022. AFLN24.Martin R. Albrecht, Giacomo Fenzi, Oleksandra Lapiha, and Ngoc Khanh Nguyen. Slap: Succinct lattice-based polynomial commitments from stan- dard assumptions. To appear at EUROCRYPT 2024, 2024. https: //eprint.iacr.org/2023/1469. AHIV17.Scott Ames, Carmit Hazay, Yuval Ishai, and Muthuramakrishnan Venkita- subramaniam. Ligero: Lightweight sublinear arguments without a trusted setup. In *ACM Conference on Computer and Communications Security*, pages 2087–2104. ACM, 2017. ALS20.Thomas Attema, Vadim Lyubashevsky, and Gregor Seiler. Practical prod- uct proofs for lattice commitments. In *CRYPTO (2)*, volume 12171 of *Lecture Notes in Computer Science*, pages 470–499. Springer, 2020. BBHR18.Eli Ben-Sasson, Iddo Bentov, Yinon Horesh, and Michael Riabzev. Fast reed-solomon interactive oracle proofs of proximity. In *ICALP*, volume 107 of *LIPIcs*, pages 14:1–14:17. Schloss Dagstuhl-Leibniz-Zentrum fuer Informatik, 2018. BCFL23.David Balb´as, Dario Catalano, Dario Fiore, and Russell W. F. Lai. Chain- able functional commitments for unbounded-depth circuits. In *TCC (3)*, volume 14371 of *Lecture Notes in Computer Science*, pages 363–393. Springer, 2023. BCS23.Jonathan Bootle, Alessandro Chiesa, and Katerina Sotiraki. Lattice-based succinct arguments for NP with polylogarithmic-time verification. In He- lena Handschuh and Anna Lysyanskaya, editors, *Advances in Cryptology -* *CRYPTO 2023*, volume 14082 of *Lecture Notes in Computer Science*, pages 227–251. Springer, 2023. BDK13.Michael Backes, Amit Datta, and Aniket Kate. Asynchronous computa- tional VSS with reduced communication complexity. In *CT-RSA*, volume 7779 of *Lecture Notes in Computer Science*, pages 259–276. Springer, 2013. BFS20.Benedikt B¨unz, Ben Fisch, and Alan Szepieniec. Transparent snarks from DARK compilers. In *EUROCRYPT (1)*, volume 12105 of *Lecture Notes in* *Computer Science*, pages 677–706. Springer, 2020. BHR `

21.Alexander R. Block, Justin Holmgren, Alon Rosen, Ron D. Rothblum, and Pratik Soni. Time- and space-efficient arguments from groups of unknown order. In *CRYPTO (4)*, volume 12828 of *Lecture Notes in Computer Sci-* *ence*, pages 123–152. Springer, 2021.
BHV `

23.Rishabh Bhadauria, Carmit Hazay, Muthuramakrishnan Venkitasubrama- niam, Wenxuan Wu, and Yupeng Zhang. Private polynomial commitments and applications to MPC. In *Public Key Cryptography (2)*, volume 13941 of *Lecture Notes in Computer Science*, pages 127–158. Springer, 2023.
BKS `

21.Fabian Boemer, Sejun Kim, Gelila Seifu, Fillipe D. M. de Souza, and Vin- odh Gopal. Intel HEXL: accelerating homomorphic encryption with intel AVX512-IFMA52. In *WAHC@CCS*, pages 57–62. WAHC@ACM, 2021.

BLNS20.Jonathan Bootle, Vadim Lyubashevsky, Ngoc Khanh Nguyen, and Gregor Seiler. A non-pcp approach to succinct quantum-safe zero-knowledge. In *CRYPTO (2)*, volume 12171 of *Lecture Notes in Computer Science*, pages 441–469. Springer, 2020. BS07.Daniel J. Bernstein and Jonathan P. Sorenson. Modular exponentiation via the explicit chinese remainder theorem. *Math. Comput.*, 76(257):443–454,

2007.
BS23.Ward Beullens and Gregor Seiler. Labrador: Compact proofs for R1CS from module-sis. In *CRYPTO (5)*, volume 14085 of *Lecture Notes in Computer* *Science*, pages 518–548. Springer, 2023. CHK `

21.Chi-Ming Marvin Chung, Vincent Hwang, Matthias J. Kannwischer, Gre- gor Seiler, Cheng-Jhih Shih, and Bo-Yin Yang. NTT multiplication for ntt-unfriendly rings new speed records for saber and NTRU on cortex-m4 and AVX2. *IACR Trans. Cryptogr. Hardw. Embed. Syst.*, 2021(2):159–188,
2021.
CHM `

20.Alessandro Chiesa, Yuncong Hu, Mary Maller, Pratyush Mishra, Noah Vesely, and Nicholas Ward. Marlin: Preprocessing zkSNARKs with uni- versal and updatable SRS. In *Proceedings of the 39th Annual International* *Conference on the Theory and Applications of Cryptographic Techniques*, EUROCRYPT ’20, pages 738–768, 2020.
CLM23.Valerio Cini, Russell W. F. Lai, and Giulio Malavolta. Lattice-based suc- cinct arguments from vanishing polynomials. In Helena Handschuh and Anna Lysyanskaya, editors, *Advances in Cryptology – CRYPTO 2023*, pages 72–105, Cham, 2023. Springer Nature Switzerland. CMNW24.Valerio Cini, Giulio Malavolta, Ngoc Khanh Nguyen, and Hoeteck Wee. Polynomial commitments from lattices: Post-quantum security, fast verifi- cation and transparent setup. Cryptology ePrint Archive, Paper 2024/281,

2024.
DAFS24.Thomas Debris-Alazard, Pouria Fallahpour, and Damien Stehl´e. Quan- tum oblivious lwe sampling and insecurity of standard model lattice- based snarks. Cryptology ePrint Archive, Paper 2024/030, 2024. https: //eprint.iacr.org/2024/030. dCP23.Leo de Castro and Chris Peikert. Functional commitments for all functions, with transparent setup and from SIS. In *EUROCRYPT (3)*, volume 14006 of *Lecture Notes in Computer Science*, pages 287–320. Springer, 2023. ENS20.Muhammed F. Esgin, Ngoc Khanh Nguyen, and Gregor Seiler. Practical exact proofs from lattices: New techniques to exploit fully-splitting rings. In *ASIACRYPT (2)*, pages 259–288, 2020. FLV23.Ben Fisch, Zeyu Liu, and Psi Vesely. Orbweaver: Succinct linear functional commitments from lattices. In Helena Handschuh and Anna Lysyanskaya, editors, *Advances in Cryptology – CRYPTO 2023*, pages 106–131, Cham,

2023. Springer Nature Switzerland.
FMN23.Giacomo Fenzi, Hossein Moghaddas, and Ngoc Khanh Nguyen. Lattice- based polynomial commitments: Towards asymptotic and concrete ef- ficiency. Cryptology ePrint Archive, Paper 2023/846, 2023. https: //eprint.iacr.org/2023/846. FS86.Amos Fiat and Adi Shamir. How to prove yourself: Practical solutions to identification and signature problems. In *CRYPTO*, pages 186–194, 1986. GHL22.Craig Gentry, Shai Halevi, and Vadim Lyubashevsky. Practical non- interactive publicly verifiable secret sharing with thousands of parties. In

*EUROCRYPT (1)*, volume 13275 of *Lecture Notes in Computer Science*, pages 458–487. Springer, 2022. GLS `

21.Alexander Golovnev, Jonathan Lee, Srinath Setty, Justin Thaler, and Riad S. Wahby. Brakedown: Linear-time and field-agnostic SNARKs for R1CS. Cryptology ePrint Archive, Paper 2021/1043, 2021. https: //eprint.iacr.org/2021/1043.
GWC19.Ariel Gabizon, Zachary J. Williamson, and Oana Ciobotaru. PLONK: Per- mutations over lagrange-bases for oecumenical noninteractive arguments of knowledge. Cryptology ePrint Archive, Report 2019/953, 2019. HSS24.Intak Hwang, Jinyeong Seo, and Yongsoo Song. Concretely efficient lattice- based polynomial commitment from standard assumptions. Cryptology ePrint Archive, Paper 2024/306, 2024. KZG10.Aniket Kate, Gregory M. Zaverucha, and Ian Goldberg. Constant-size com- mitments to polynomials and their applications. In *ASIACRYPT*, volume 6477 of *Lecture Notes in Computer Science*, pages 177–194. Springer, 2010. Lee21.Jonathan Lee. Dory: Efficient, transparent arguments for generalised inner products and polynomial commitments. In *TCC (2)*, volume 13043 of *Lecture Notes in Computer Science*, pages 1–34. Springer, 2021. LNP22.Vadim Lyubashevsky, Ngoc Khanh Nguyen, and Maxime Plan¸con. Lattice- based zero-knowledge proofs and applications: Shorter, simpler, and more general. In *CRYPTO (2)*, volume 13508 of *Lecture Notes in Computer* *Science*, pages 71–101. Springer, 2022. LRY16.Benoˆıt Libert, Somindu C. Ramanna, and Moti Yung. Functional com- mitment schemes: From polynomial commitments to pairing-based accu- mulators from simple assumptions. In *ICALP*, volume 55 of *LIPIcs*, pages 30:1–30:14. Schloss Dagstuhl-Leibniz-Zentrum f¨ur Informatik, 2016. LS15.Adeline Langlois and Damien Stehl´e. Worst-case to average-case reductions for module lattices. *Designs, Codes and Cryptography*, 75(3):565–599, 2015. LS18.Vadim Lyubashevsky and Gregor Seiler. Short, invertible elements in partially splitting cyclotomic rings and applications to lattice-based zero- knowledge proofs. In *EUROCRYPT (1)*, pages 204–224. Springer, 2018. LS19.Vadim Lyubashevsky and Gregor Seiler. NTTRU: truly fast NTRU using NTT. *IACR Trans. Cryptogr. Hardw. Embed. Syst.*, 2019(3):180–201, 2019. MBKM19.Mary Maller, Sean Bowe, Markulf Kohlweiss, and Sarah Meiklejohn. Sonic: Zero-knowledge SNARKs from linear-size universal and updateable struc- tured reference strings. Cryptology ePrint Archive, Report 2019/099, 2019. MR08.Daniele Micciancio and Oded Regev. Lattice-based cryptography. In Daniel J. Bernstein, Johannes Buchmann, and Erik Dahmen, editors, *Chap-* *ter in Post-quantum Cryptography*, pages 147–191. Springer, 2008. Sei18.Gregor Seiler. Faster AVX2 optimized NTT multiplication for ring-lwe lattice cryptography. *IACR Cryptol. ePrint Arch.*, page 39, 2018. STW23.Srinath Setty, Justin Thaler, and Riad Wahby. Unlocking the lookup sin- gularity with lasso. Cryptology ePrint Archive, Paper 2023/1216, 2023. https://eprint.iacr.org/2023/1216. WW23a.Hoeteck Wee and David J. Wu. Lattice-based functional commitments: Fast verification and cryptanalysis. In *ASIACRYPT (5)*, volume 14442 of *Lecture Notes in Computer Science*, pages 201–235. Springer, 2023. WW23b.Hoeteck Wee and David J. Wu. Succinct vector, polynomial, and functional commitments from lattices. In *EUROCRYPT (3)*, volume 14006 of *Lecture* *Notes in Computer Science*, pages 385–416. Springer, 2023. Full version: https://eprint.iacr.org/2022/1515.
