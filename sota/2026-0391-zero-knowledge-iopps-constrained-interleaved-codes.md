# Zero-Knowledge IOPPs for Constrained Interleaved Codes

### Alessandro Chiesa Giacomo Fenzi Guy Weissenberg

alessandro.chiesa@epfl.ch giacomo.fenzi@epfl.ch guy.weissenberg@epfl.ch EPFL EPFL EPFL

### February 25, 2026

**Abstract**

Succinct arguments based on interactive oracle proofs (IOPs) have achieved remarkable effi- ciency improvements and are now widely adopted in applications. State-of-the-art IOPs involve protocols for testing proximity to constrained interleaved linear codes, and enjoy essentially optimal parameters. However, recent IOP constructions provide no privacy guarantees, which remain a must for many applications. We present an IOP of proximity for testing constrained interleaved linear codes that achieves (honest-verifier) zero-knowledge, while incurring a negligible overhead compared to the (non- zero-knowledge) state of the art. In line with recent constructions, our construction satisfies round-by-round knowledge soundness with a straightline extractor and negligible error. We propose a definition of (honest-verifier) zero-knowledge for interactive oracle reductions (IORs) that we prove is compatible with composition, and then obtain our result by constructing and modularly composing several lightweight zero-knowledge IORs. Our key technical contribu- tions are a zero-knowledge sumcheck IOR and a zero-knowledge code-switching IOR that fit the strict efficiency requirements of our setting; these contributions and other technical complica- tions entailed overcoming several challenges with new notions and protocols. Finally, along the way, we highlight the efficiency benefits of high-distance codes obtained from dispersers, which may be of independent interest.

**Keywords**: interactive oracle reductions; zero-knowledge; linear codes; dispersers

## Contents

**1 Introduction**

1.1 Our results............................................. .4
**2 Technical overview**

2.1 Basic notions............................................ .8
2.2 Warmup: a simple zero-knowledge IOPP for constrained codes
2.3 Composition for honest-verifier zero-knowledge IORs...................... .11
2.4 A “committed” relation for zero-knowledge........................... .12
2.5 An honest-verifier zero-knowledge sumcheck reduction..................... .13
2.6 HVZK code switching....................................... .18
2.7 From building blocks to our main results............................. .22
2.8 Bonus: distance-amplified codes.................................. .24
**3 Preliminaries**

**4 Zero-knowledge for IORs and composition**

**5 Succinct linear forms**

**6 Zero-knowledge sumcheck IOR**

**7 A non-succinct zero-knowledge protocol for constrained codes**

**8 A sublinear zero-knowledge IOP for constrained codes**

**9 Zero-knowledge code-switching**

**3**

**8**

................ .9

**26**

**32**

**35**

**37**

**43**

**49**

**51**

**10 Zero-knowledge IOPP for constrained codes**

**11 Zero-knowledge reduction from R1CS**

**12 High-distance codes from dispersers**

**Acknowledgments**

**References**

**62**

**66**

**72**

**77**

**77**

3.1 Interactive oracle reductions.................................... .26
3.2 Coding theory............................................ .27
6.1 Zero-knowledge........................................... .38
6.2 Round-by-round security...................................... .40
7.1 Zero-knowledge........................................... .44
7.2 Round-by-round knowledge soundness.............................. .45
9.1 Out-of-domain samples....................................... .51
9.2 Private zero-evaders........................................ .51
9.3 Code-switching complexity.................................... .53
9.4 Code-switching IOR........................................ .54
9.5 Zero-knowledge........................................... .56
9.6 Round-by-round knowledge soundness.............................. .57
9.7 Proof of Theorem 2......................................... .60
12.1 Preliminaries............................................ .72
12.2 Amplified Reed–Solomon code................................... .73
12.3 Distance amplification and Merkle-compiled argument size................... .75

## 1 Introduction

Succinct non-interactive arguments (SNARGs) are short cryptographic proofs that admit a fast- verification procedure. They are widely deployed across applications in decentralized systems and cloud computing. We study*hash-based SNARGs*, a class of constructions notable for their trans- parent setup (the choice of hash function), post-quantum security (in the quantum random oracle model), fast provers (they avoid public-key cryptography), and more. Such SNARGs are, e.g., used for scaling distributed systems (e.g. [Sta; Pol; Ris; Suc]) and for anonymous credentials [Fs24]. Hash-based SNARGs are constructed via the BCS transformation [BCS16] from an interactive oracle proof (IOP), and a beautiful line of research investigates efficient IOP constructions. In this paper we investigate efficient constructions of (honest-verifier)*zero-knowledge*IOPs with the goal of obtaining efficient constructions of (malicious-verifier)*zero-knowledge*hash-based SNARGs. **The efficiency of code-agnostic IOPs.**Many constructions of efficient IOPs rely on polynomial codes [AHIV17; BBHR19; BCRSVW19; COS20; ACFY24; HK24; Dia25; MZ25]. The limitations of constructions based on polynomial codes (e.g., superlinear encoding time) have motivated the study of IOPs based only on combinatorial transformations of general linear codes (e.g., tensoring, interleaving), which has achieved “code-agnostic” IOPs [BCGGHJ17; BCG20; RR20; RR22; NA25; BMMS25a; DMR25; DL25; ARR25; BFRW25; BMMS25b]. This is reminiscent of similar efforts for PCPs (the non-interactive counterparts of IOPs) where researchers have sought to decouple PCPs from the properties of the underlying codes in order to understand the minimal structure that enables PCPs and related tools [GS00; DR04; Din07; IKW09; DM11; Mei13; Mei12]. Recent works have shown that general linear codes and their interleaving are sufficient to con- struct state-of-the-art IOPs in terms of efficiency [BCGGHJ17; BCFW25; ACFY25; BCFRRZ25; NA25; BMMS25a],*even outperforming*constructions tailored to an error-correcting code (such as

e.g. [ACFY24]). This has provided a class of highly configurable and efficient IOP constructions. **The cost of zero-knowledge.**Zero-knowledge for hash-based SNARGs is increasingly in de- mand [Fs24; Mid; Goo; Lig], which requires the underlying IOP to satisfy (honest-verifier) zero- knowledge. Such an IOP is usually obtained by modifying an underlying (non-private) IOP. A key goal is minimizing the “zero-knowledge overhead”, i.e., the cost incurred by the prover and verifier in using the zero-knowledge version of the protocol compared to its non-private equivalent. The zero-knowledge overhead of concretely efficient IOPs is*≥*2*×*(in prover and verifier times), and they are specific to Reed–Solomon codes [RS60] (or other polynomial codes). This overhead deters developers and engineers from using the zero-knowledge version. Moreover,*none of the* *state-of-the-art code-agnostic IOPs in the literature provide zero-knowledge*. Two notable works study zero-knowledge IOPs based on any “zero-knowledge” code (we define these shortly). [BCL22] obtains a tensor-code-based IOP with*≥*2*×*overhead; the IOP is not con- cretely efficient partly due to heavy PCP machinery. [RW24] obtains a tensor-code-based IOP that reduces the overhead to1 +*o*(1)relative to witness size, however only targets constant soundness. Both works achieve malicious-verifier zero-knowledge, while honest-verifier zero-knowledge suffices for achieving (malicious-verifier) zero-knowledge via the Fiat–Shamir transformation. **Tensoring vs. interleaving.**There are two fundamental operations on codes that are used to create a modicum of structure for designing “code-agnostic” protocols. •*Code tensoring.*The tensor product of codes*C₁ ⊆*Σ
*m*1 and*C₂ ⊆*Σ *m*2 is the code*C₁ ⊗C₂ ⊆* Σ *m*1*×m*2 of matrices*u∈*Σ *m*1*×m*2 such that each column of*u*is in*C₁* and each row of*u*is in*C₂*. The code*C₁ ⊗C₂* is a “nice” code if*C₁* and*C₂* both have (even general forms of) linear structure.

|m|≡K|K m|
|---|---|---|
|K m|≡K||
|K|K||

•*Code interleaving.*The*K*-interleaving of a code*C⊆*Σ is the code*C ⊆*(Σ) obtained by “stacking”*K*codewords from*C*, that is, a word*u∈*(Σ) is in*C* if and only if there exist words*v₁,...,vK∈*Σ *m* in*C*such that*u*(*z*) = (*v₁*(*z*)*,...,v* (*z*))*∈*Σ for every*z∈*[*m*].

Both operations lead to linear-time IOP provers by way of linear-time encodable codes, but they offer different tradeoffs. Tensoring creates key structures for local testability and tensor sumchecks [Mei13; RR20; BCG20; RR22; BCL22; RW24; BFRW25; BMMS25b], enabling for example query- optimal IOPs; this comes with the cost of worse rate and distance compared to the original code as well as a less efficient encoding. Interleaving also enables key structures for alternative sumchecks and code-switching [AHIV17; BBHV22; ACFY25; NA25; BMMS25a], while preserving rate and distance at the cost of increasing the alphabet size (which precludes query-optimal IOPs); on the other hand, interleaving leads to better encoding efficiency (including with small space [BBHV22]) and also works for*every*code, enabling the most freedom in code choice for a protocol.

### 1.1 Our results

We present a concretely-efficient HVZK IOPP for constrained interleaved codes, as well as a cor- responding HVZK IOP for R1CS. We match the efficiency of state-of-the-art (non-private) IOPs up to low-order factors, obtaining a zero-knowledge overhead of1 +*o*(1); moreover, we achieve round-by-round straightline extraction for every code by relying on mutual correlated agreement. We elaborate on our results below. We begin by recalling the notions of zero-knowledge encod- ings and constrained interleaved codes, which we need to state our results.

**ZK encodings.**We use*zero-knowledge encodings*for codes, also known as zero-knowledge codes [ISVW13; BCGV16; BBHR19; BCL22; RW24]. For a finite fieldF, we say that a code*C⊆*Σ *m* is

|||ι|
|---|---|---|
|ℓ r|m||
|C ℓ r||ℓ|
||C||

F*-additive*if the alphabetΣis anF-linear vector space (e.g.,Σ =F *ι* for some*ι∈*N); whenΣ =F this becomes anF-linear code in the common sense. For message length*ℓ*and randomness length *r*, we say thatEnc*C*:F *×*F *→*Σ is a*t*-query zero-knowledge encoding for*C*if: (i) the image of Enc*C*is in*C*(i.e.,Enc (F*,*F)*⊆C*); and (ii) for every messagemsg*∈*F and index subset*S⊆*[*m*] with*|S|≤t*, the distributionEnc (msg*,**r**←*F *r* )[*S*]can be simulated efficiently, up to some error *ζ*, given only*S*(but notmsg). Intuitively, a*randomized*encoding of a message yields multiple possible encodings and the view of a certain number of locations is independent of the message.

**Our target: constrained interleaved codes with ZK encodings.**We seek to construct concretely-efficient HVZK IOPPs for relations that involve interleaved codes whose underlying messages are subject to succinct linear constraints. This is in line with state-of-the-art protocols that consider proximity testing to codes with linear constraints [ACFY25; BMNW25; BCFW25], which enables significantly more efficient (and simpler) reductions from NP compared to merely relying on proximity tests to unconstrained codes. Informally, given a zero-knowledge encoding Enc*C*for a code*C*we consider the relation of linear constraints defined as follows:   ∣    **x**= (*µ,⟨**v**⟩*)*∈*F*×*F log*ℓ* *,* ∣∣   lin*m* ∣ *f*=Enc*C*(***f**,**r***) *RC,T*:= **y**=*f∈*Σ*,*  ∣*.*(1)   *ℓ r*∣ *∧⟨**f**,**v**⟩*=*µ*  **w**= (***f**,**r***)*∈*F *×*F ∣

Above*⟨**v**⟩*is some “succinct” description of the vector***v**∈*F *ℓ* from which***v***can be computed in time*T*and “*k*-folds of***v***” (which we define later) can be computed in time*T*

(*k*). (In fact*R*
lin *C,T* is a simplification of the relation we use; in Section 2.4 we discuss and motivate a refined variant of it.)

**HVZK IOPP for constrained interleaved codes.**Our first result is an honest-verifier zero- knowledge IOP of proximity for the linear constraint relation*R* lin *≡*2*k* (Equation 1) for a given *C,T* interleaving parameter*k*. This IOPP is in the “sublinear regime” and is the result of a single reduction step of a more general*HVZK code-switching*technique that we discuss further below.

**Theorem 1**(informal)**.***LetC⊆*Σ *mC* *be an*F*-additive code with atC-query zero-knowledge encoding* Enc*C*:F *ℓ* *C×*F*rC→*Σ*mCwith errorζ* *Cand encoding timeτC. Fix an interleaving parameterk∈*N*,* *security parameterλ∈*N*, and proximity parameterδ∈*(0*,*1)*; lett* :=*O*( *−*log(1 <u>λ</u> *−δ*) )*. We construct* *aO*(*k*)*-round IOPP forR* lin *≡*2*k* *with the following features.* *C,T* •*The prover sendsO*(*mC*) + *O* ˜( *k·λ*)*alphabet symbols, and the verifier makestqueries over the* 2 *k* *alphabet*Σ*.* •*The prover time isO*(*T*+ 2 *k* *·ℓC*+*τC*) +*O* ˜( *k·λ*)*and verifier time isO*(*T*

(*k*) + 2 *k* *·t*+*τC*) +*O*
˜( *k·λ*)*.* •*The protocol has round-by-round knowledge soundness error at most*2 *−λ* *assuming*F*is large* *enough with respect toC’s mutual correlated agreement radius at distanceδ.* •*IftC≥tthe protocol is honest-verifier zero-knowledge with errorζC.* *The notation O* ˜( *·*)*hides*poly(log*λ*)*factors (here and elsewhere in this introduction).*

˜( *≡*2 *kk* The prover sends*O*(*mC*)+*O k·λ*)alphabet symbols, while the block length of*C* is*N*= 2 *·mC* alphabet symbols. For common settings of the interleaving parameter*k*(say <u>log</u> 2 <u>N</u> orlog log*N*), the prover sends*O*( <u>m</u> *N* <u>C</u> )*·N*+ *O* ˜(<u>k</u> *N* <u>·λ</u> )*·N*=*o*(1)*·N*alphabet symbols. As this includes the costs arising from the addition of HVZK, the zero-knowledge overhead is*o*(1). A notable setting of parameters for Theorem 1 is the *√* *sublinear regime*, achieved when2 *k* *≈mC*. In this setting, the proof length is *≈O*( *N*)alphabet symbols, and verifier time is sublinear. Theorem 1 gives the first IOPP for constrained interleaved general codes with list-decoding soundness and1+*o*(1)zero-knowledge overhead in the*sublinear verifier*regime. Prior works either show HVZK IOPPs for interleaved Reed–Solomon codes in the unique decoding regime [AHIV17], or give IOPPs for interleaved general codes in the unique decoding regime [BCG20; GLSTW23] without providing zero-knowledge. None of these prior works consider constrained code testing relations. Theorem 1 improves upon these works, simultaneously achieving the desirable properties.

**HVZK code switching.**We obtain honest-verifier zero-knowledge IOPPs beyond the sublinear- verifier regime by providing an*HVZK code-switching*IOR from an interleaved code to another code (that, in particular, can itself be interleaved). Code-switching loosely refers to techniques for reducing a testing problem for a code to a testing problem for another*smaller*code, first introduced in the setting of tensor codes [RR20; RR22].

|Theorem 2(informal, code switching with HVZK).Forb∈{1,2}, letC|||||⊆Σ|
|---|---|---|---|---|---|
||C|||C ℓ|m|
||C||λ−δ)|||
||||log(1|||
|lin|lin|||||
|C ,T|C ,T|||||
|||C||||
||2|k C|C|||

*b* *mCb* *be an*F*-additive* *code that has atC* *b* *-query zero-knowledge encoding*Enc*C* *b* :F *ℓ* *Cb* *×*F *r* *Cb* *→*Σ *mCb* *with errorζC* *b* *and* *encoding timeτ* *b* *. Fix an interleaving parameterk∈*N*, security parameterλ∈*N*, and proximity* *parameterδ∈*(0*,*1)*; lett* :=*O*(*−*)*. We construct aO*(*k*)*-round IOR of proximity from* *R* *≡*2*k* *toR* 2 2 *, whereT₂* =*O*(*T₁* +*TC* 2 )*andTC* 2 *is a quantity determined byC₂’s generator* 1 1 *matrix, with the following features.* •*The prover sendsO*(*m*2) + *O* ˜( *k·λ*)*alphabet symbols, and the verifier makestqueries over* *k* *alphabet*Σ*.* •*The prover time isO*(2 *·ℓ*1+*τ*2) + *O* ˜( *k·λ*)*and the verifier time isO*(2 *k* *·t*) + *O* ˜( *k·λ*)*.*

•*The protocol has round-by-round knowledge soundness error at most*2 *−λ* *assuming*F*is large* *enough with respect toC₁’s andC₂’s mutual correlated agreement errors at distanceδ.* •*The protocol is honest-verifier zero-knowledge with errorζC*2*against distinguishers that perform* *at mosttC*2*queries.*

We consider a stronger notion of HVZK for IORs in Theorem 1, as we require an HVZK notion that is compatible with composition of IOR (accounting for later queries by algorithms we refer to as*distinguishers*on the output implicit instance). We elaborate on the “correct” HVZK notion for IORs in Section 2.3. Additionally, the fixed quantity*TC* 2 refers to the*code-switching friendliness* of the code, and we elaborate on this property in Section 2.6. Finally, similarly to Theorem 1, for common settings of the interleaving parameter*k*the zero-knowledge overhead is*o*(1). **Polylogarithmic HVZK IOPP for constrained interleaved codes.**Theorem 2 and the building blocks of Theorem 1 directly yield HVZK variants of WHIR [ACFY25] and Ligerito [NA25], as follows. Use the parameter settings in [NA25] (implicit in [ACFY25]) to apply Theorem 2 in sequence and conclude with Theorem 1. Moreover, Theorem 2 also improves upon [BCL22], who achieve HVZK IOPP for general linear codes but with*O*(1)overhead and unique decoding soundness, while our result achieves*o*(1)overhead and list decoding soundness. In particular, instantiating this recipe with Reed–Solomon code yields the following corollary.

*≡*2*k* **Corollary 3.***LetC be an interleaved Reed–Solomon code with message lengthℓ, evaluation* *domain sizem, and with anO*(*λ*)*-query zero-knowledge encoding, wherek*=*O*(log log*ℓ*)*. There* *exists an IOPP forR* lin *≡*2*k* *with the following features.* *C,T* •*The prover sendsO*(*m*) + *O* ˜( *λ*)*alphabet symbols, and the verifier makesO*(*λ*)*queries over* *alphabet*F log*ℓ* *.* •*The prover time isO*(*T*+*m·*log*m*+ log <u>λ·ℓ</u> *ℓ* )+*O* ˜( *λ*)*and the verifier time isO*(*T* (log*ℓ*) +*λ·*log*ℓ*)+*O* ˜( *λ*)*.* •*The protocol has round-by-round knowledge soundness error at most*2 *−λ* *.* •*The protocol is perfect honest-verifier zero-knowledge.*

**HVZK IOR from NP to constrained code testing.**As an additional contribution, we provide a reduction from the NP-complete Rank-1-Constraint-Satisfaction (R1CS) problem to proximity testing of*R* lin *≡*2*k*. The reduction incurs*o*(1)overhead over sending a single (interleaved) code- *C,T* word, illustrating that the efficiency characteristics of the proximity test are also achievable in the reduction from an NP problem. The reduction is based on the same zero-knowledge sumcheck (see Section 2.5), which is an essential ingredient in the proofs of Theorem 1 and Theorem 2, and adapts theΣ-IOP for R1CS in [ACFY25]. In addition, we use a sublinear masking technique (similar to the one we use in our zero-knowledge sumcheck) to mask the R1CS matrix-vector product. Prior reductions from R1CS [BCL22] incur*O*(1)overhead by sending full masking oracles. Our reduction can, in particular, be instantiated with the interleaving of a linear-time-encodable code (with zero-knowledge encodings, as shown in [BCL22]) and, together with our proximity test, leads to an HVZK IOR from R1CS to testing proximity to a code, with a linear-time prover, list-decoding soundness, and*o*(1)overhead. We note that our size comparison is against*non-zero-* *knowledge*protocols that use this style of reduction (“reduce R1CS to constraint code-testing”),

e.g. [ACFY24; ACFY25; MZ25]. This improves upon the state-of-the-art for linear-time provers from [BCL22], which only achieves unique decoding soundness and constant overhead. Composing the IOR from NP with Theorem 1 (or its polylogarithmic-verifier version that we provide in Theorem 4 in Section 2.7) achieves an HVZK IOP for NP with desirable efficiency

properties. We consider an example application of such efficiency improvements: [Fs24] develop an anonymous credential solution using the sublinear hash-based zkSNARK in [AHIV17], which is based on zero-knowledge IOPs with zero-knowledge overhead*≥*2*×*(and the corresponding non- private IOPs are no longer state of the art); our protocols can be used as a drop-in replacement to avoid this overhead. The effect is further amplified by the fact that we measure our overhead against*state-of-the-art*non-private IOPs.

**Memory efficiency.**While not an explicit focus of our work, Theorem 1 is plausibly amenable to space efficient streaming proving. The memory efficiency of the prover is concretely dominated by the space-efficiency of the encoding of the interleaved code and by the sumcheck. Crucially, an encoding of an interleaved code*C* *≡K* can be performed in space equivalent to that required for the encoding of a message via the*base codeC*, which can be significantly smaller. This fact was already leveraged in [BBHV22] to achieve efficient streaming provers, for the specific case when *C*is a Reed–Solomon code. The sumcheck protocol can also be implemented in a time and space efficient manner (see e.g. [CTY11; VSBW13; BCFFMMZ25; NTZ25]), and plausibly the techniques can be adapted to achieve memory efficiency for our protocol.

**On the choice of codes.**AnyF-additive code with an appropriate zero-knowledge encoding can be used in Theorem 1 and Theorem 2. These theorems use auxiliary*internal*smaller codes with zero-knowledge encoding, distinct from the*main*code being tested (exposed in the informal theorem statements). When setting the parameters for these theorems, we set the internal codes to be Reed–Solomon codes. Yet, the generality of our constructions (and full theorem statements) allows us to consider*other*codes for the codes being tested and for the internal codes. We identify a class of codes that represents a midpoint between two popular choices of codes:

(i) Reed–Solomon codes (an MDS code that is not linear-time encodable), and (ii) practical linear- time encodable codes. Specifically, we describe a class of codes obtained via*distance amplification* *based on dispersers*, and we argue that these codes achieve encoding time that approaches that of linear-time encodable MDS codes, but over a larger alphabet. We elaborate on this in Section 2.8.

## 2 Technical overview

We summarize the main ideas behind our results via an extended technical overview; the technical sections are long as we invested much effort to provide formal statements, constructions, and proofs.

•In Section 2.1 we review basic notions used in the technical overview: zero-knowledge codes, interactive oracle reductions, and round-by-round knowledge soundness. •In Section 2.2 we describe a*non-succinct*HVZK IOPP for linear constraints, serving as a warmup to the techniques we use and as a baseline for our constructions (details are in Section 7). •In Section 2.3 we present a new definition of HVZK for IORs that is compatible with sequential composition of IORs (details are in Section 4). •In Section 2.4 we discuss a new*committed sumcheck relation*, which allows us to ensure zero- knowledge and efficient verifiers in our protocols. •In Section 2.5 we present an**HVZK sumcheck reduction**from testing the interleaving of a base code to testing the base code itself (details are in Section 6), expressed via the aforemen- tioned committed sumcheck relation. This is a key technical ingredient of our paper. •In Section 2.6 we present an**HVZK code switching protocol**(details are in Section 10). This is the other key technical ingredient of our paper. •In Section 2.7 we sketch how we prove our main theorems, by combining the basic HVZK IOPP, the sumcheck reduction, and code switching (via our HVZK IOR composition theorem). •In Section 2.8 we propose the use of high-distance codes constructed via distance amplification for improved efficiency, in encoding time and in argument size. These codes are compatible with our constructions, and we deem them of independent interest for other probabilistic proofs.

### 2.1 Basic notions

We review basic notions used in this extended technical overview; full definitions appear in Section 3. BelowF*-additive codes*refers to codes*C⊆*Σ *m* whose alphabetΣis anF-linear vector space (e.g., Σ =F *ι* for some*ι∈*N); when the alphabetΣ =Fthis becomes a linear code in the usual sense.

||m|||C ℓ|r|
|---|---|---|---|---|---|
|C|C ℓ|r C|r|ℓ||

**ZK codes.**A code*C⊆*Σ has a*t-query zero-knowledge encoding*Enc :F *×*F *→*Σ *m* if the image ofEnc is in*C*(i.e.,Enc (F*,*F)*⊆C*) and, for every messagemsg*∈*F and index subset*S⊆*[*m*] with*|S|≤t*, the distributionEnc (msg*,**r**←*F)[*S*]can be simulated efficiently, up to some error, given only*S*. Zero-knowledge codes are key ingredients in prior work on zero-knowledge IOPs (e.g. [ISVW13; BCL22; RW24]), and all codes in this work have zero-knowledge encodings. A concrete example one can keep in mind is the Reed–Solomon code, where encoding a message extended with randomness in***r**∈*F *t* achieves perfect*t*-query zero-knowledge (see Proposition 3.19). Many other zero-knowledge codes are known, including some with linear-time encoding algorithms [BCL22].

**IORs.**Recent constructions of hash-based succinct arguments and accumulation schemes are obtained via a modular approach based on*interactive oracle reductions*(IORs) [BCGGRS19; BMNW25]. Informally, an IOR is an interactive oracle protocol in which the verifier, rather than outputting a decision bit, either rejects or outputs an instance for a target relation; in addition, instances are split into two parts, an*explicit instance*part that the verifier receives as input and an*implicit instance*part that the verifier receives as an oracle to query. In more detail, an IOR (of proximity) from relation*R*to*R* *′* works as follows. The prover**P** receives as input(**x***,***y***,***w**)*∈R*, whereas the verifier**V**receives as (explicit) input**x**and query access to**y**. After interacting,**V**either rejects or outputs a new explicit instance**x** *′* and implicit instance

**y** *′*, and (in the honest case)**P**outputs a new witness**w** *′* such that(**x** *′* *,***y** *′* *,***w** *′* )*∈R* *′*. We say thatIOR has (perfect) completeness if for every(**x***,***y***,***w**)*∈R*it always holds that(**x** *′* *,***y** *′* *,***w** *′* )*∈R* *′*. **RBR security.**We target the strong notion of round-by-round security [CCHLRR18; CMS19; CY24; BMNW25; BCFW25] to ensure that our protocols are suitable to construct*non-interactive* succinct arguments (in the random oracle model). Informally, this amounts to establishing, for each round, a*round error*that upper bounds the probability of transitioning, in that round, from a*bad* state for the attacker (“the statement is false”) into a*good*state (“the next statement is true”). Specifically, we target the*straightline RBR knowledge soundness*notion for IORs in [BCFW25], which is suitable for code-agnostic protocols such as ours. The notion essentially states that an IOR from*R*to*R* *′* can be viewed as a sequence of one-round reductions each satisfying straightline knowledge soundness, which requires providing for each round a knowledge extractor and bounding its extraction error. Finally, since both*R*and*R* *′* involve implicit instances (**V**receives query access to an implicit instance**y**and outputs an implicit instance**y** *′* ) the extraction errors are a function of proximity parameters*δ*for*R*(“**y**is*δ*-far from*R*”) and*δ* *′* for*R* *′* (“**y** *′* is*δ* *′* -close to*R* *′* ”). **List decoding and mutual correlated agreement.**The RBR knowledge soundness errors that we achieve for our protocols depend, as in prior work, on several properties of the given code *C*: distance, list-decoding size, and mutual correlated agreement error. We review the latter two. •We denote the worst-case list size of a code*C*at distance*δ∈*(0*,*1)as*|*Λ(*C,δ*)*|* := max*f|*Λ(*C,f,δ*)*|* whereΛ(*C,f,δ*) :=*{u∈C*: ∆(*u,f*)*≤δ}*is the set of codewords in*C*at relative distance*≤δ* from*f*. Hence*C*’s list decoding size captures the maximum number of codewords in the Ham- ming ball of a certain radius centered at any codeword in*C*. •Mutual correlated agreement (MCA) [ACFY25] is a strong notion of distance preservation. Informally, it bounds the probability that the random combination*f₁* +*γ·f₂* is close to*C*when *f₁,f₂* are not individually close to*C*. We let*ϵ*mca(*C,δ*)be the mutual correlated agreement error of*C*at distance*δ∈*(0*,*1)(see Definition 3.14). In this overview we also consider the random combination(1*−γ*)*·f₁* +*γ·f₂*, and use the same notation because the error is the same.

### 2.2 Warmup: a simple zero-knowledge IOPP for constrained codes

We describe a simple honest-verifier zero-knowledge IOPP for linear constraints that works for any given zero-knowledgeF-additive code. The protocol illustrates IOP-native ideas commonly used to achieve zero-knowledge, incurring a2*×*overhead. This serves as a simple concrete example to understand before we describe more efficient protocols; moreover, variants of this protocol will serve as a “base case” on small instances in our protocols. **An initial relation.**Let*C⊆*Σ *m* be anF-additive code with a zero-knowledge encodingEnc*C*:F *ℓ* *×* F *r* *→*Σ *m*. We define a linear constraint relation *R*¯*C*: (a) the explicit instance**x**contains a target *µ∈*Fand a coefficient vector***v**∈*F *ℓ*, (b) the implicit instance**y**is an oracle*f∈*Σ *m*, and (c) the witness is a message***f**∈*F *ℓ* and randomness***r**∈*F *r* such that*f*=Enc*C*(***f**,**r***)and*⟨**f**,**v**⟩*=*µ*. Namely:   ∣    **x**= (*µ,**v***)*∈*F*×*F *ℓ* *,* ∣∣   *R* ¯ *C*:= **y**=*f∈*Σ *m* *,*  ∣∣*.*(2)   *f*=Enc*C*(***f**,**r***)   *ℓ r*∣ *∧⟨**f**,**v**⟩*=*µ*  **w**= (***f**,**r***)*∈*F *×*F ∣

As explained in Section 2.4, *R*¯*C*is a simplification of the linear constraints relation that we use. **Recall: HVZK for IOPPs.**We recall the standard definition of HVZK for interactive oracle proofs of proximity [BCFGRS17], which are for ternary relations*R*consisting of tuples(**x***,***y***,***w**)

where**x**is the explicit instance,**y**is the implicit instance, and**w**is the witness. The key feature of the definition is that the simulator has oracle access to the implicit instance**y**since the honest verifier also does, and we account for the query complexity of the simulator to**y**.

**Definition 2.1**(informal)**.***Let*IOP= (**P***,***V**)*be an IOPP for a ternary relationR. The***view** *of*(**P***,***V**)*on*(**x***,***y***,***w**)*∈ R is the random variable*View(**P***,***V***,***x***,***y***,***w**)*that consists of***V***’s ran-* *domness and the answers to***V***’s queries in an interaction between***P**(**x***,***y***,***w**)*and***V** **y**

(**x**)*.*IOP
*has***honest-verifier zero-knowledge with error***ζ***and query complexity**b*if there exists* *a polynomial-time simulator***S***such that the random variables*View(**P***,***V***,***x***,***y***,***w**)*and***S** **y**

(**x**)*are*
*ζ-close (in statistical distance) and***S** **y**

(**x**)*makes at most*b*queries to***y***.*
**A simple protocol for linear constraints.**We sketch a*non-succinct*HVZK IOPP for *R*¯*C*.

**Construction 2.2.**The verifier receives as explicit input**x**= (*µ,**v***)*∈*F*×*F *ℓ* and as implicit input **y**=*f∈*Σ *m*. The prover receives as input a message***f**∈*F *ℓ* and randomness***r**∈*F *r* such that *f*=Enc*C*(***f**,**r***)and*⟨**f**,**v**⟩*=*µ*.

||||ℓ ′|r|C ′|m||
|---|---|---|---|---|---|---|---|
|i|i|i i|t i|ℓ ∗ i|r C ∗|m|t|
||||||C|||

1.The prover samples***g**∈*F
*ℓ* and***r*** *′* *∈*F *r*, and sends*g* :=Enc*C*(***g**,**r*** *′* )*∈*Σ *m* and˜*µ* :=*⟨**g**,**v**⟩∈*F.

2.The verifier samples and sends*ε←*F.
3.The prover sends***h*** :=***g***+*ε·**f**∈*F and***r*** :=***r***
*′* +*ε·**r**∈*F.

4.The verifier samples*x₁,...,x ←*[*m*], computes*h* :=Enc (***h**,**r***)*∈*Σ, and checks that: •*⟨**h**,**v**⟩*= ˜*µ*+*ε·µ*. •for*i∈*[*t*],*h*(*x*) =*g*(*x*) +*ε·f*(*x*)(by querying*f*and*g*at*x₁,...,x*). Recall that *h*(*x*)*,g*(*x*)*,f*(*x*)*∈*Σand they are compared as alphabet symbols. Completeness of Construction 2.2 follows by linearity ofEnc, and its (straightline) round-by- round knowledge soundness follows via an analysis similar to prior work (e.g., [BCFW25]). **Lemma 2.3.***For everyδ∈*(0*,*1)*, Construction 7.2 has round-by-round knowledge soundness with*
<u>|Λ(C</u>*≡*2<u>,δ)|</u> *t* *errors*(*ϵ*mca(*C,δ*) + *|*F*|* *,*(1*−δ*))*.*

We wish to highlight the privacy properties of Construction 2.2, per the following lemma.

**Lemma 2.4.***If*Enc*Cis at-query zero-knowledge encoding forCwith errorζ, then Construction 2.2* *is an honest-verifier zero-knowledge IOPP for R*¯*Cwith errorζand query complexity*b=*t.*

The intuition for the lemma is that if the encodingEnc*C*is*t*-query zero-knowledge then the queries of the verifier can be simulated efficiently, so they do not leak any information about the underlying message. The remaining information sent by the prover can also be efficiently simulated.

**Takeaway.**Informally, the overhead to achieve HVZK in Construction 2.2 is2*×*(the prover sends *g*of the same size as*f*), and we will see how to achieve IOPPs for the same task with less overhead. Even so, Construction 2.2 will play the role of a “base case” on small instances in our protocols, so we describe and analyze (a generalization of) it in Section 7. Note also that Construction 2.2 is a “minimal example” of an IOP-native HVZK protocol, as it relies on both interaction and the verifier’s ability to query oracles; more restricted models such as IPs and PCPs typically require other techniques to achieve HVZK (or have significant limitations in their HVZK capabilities).

### 2.3 Composition for honest-verifier zero-knowledge IORs

We explain how prior (honest-verifier) zero-knowledge definitions of IOPs (and IOPPs), when naively adapted to IORs, do*not*preserve zero knowledge,*precluding a modular treatment of zero* *knowledge*. We address this via a**new definition (and composition theorem) for IORs**. This enables constructing zero-knowledge IOPs by modularly composing simple zero-knowledge IORs.

**Definition 2.1 is insufficient for IORs.**The notion of HVZK for IOPPs in Definition 2.1 can be straightforwardly adapted to IORs. However, this notion is insufficient for composing IORs, as we now explain via an (artificial) example. Let*R*be a binary relation of instance-witness pairs (**x***,***w**), and let*R* *′* be the ternary relation*{*(**x** *′* *,***y** *′* *,***w** *′* =*⊥*) : (**x** *′* *,***y** *′* )*∈R}*. Consider two IORs.

•InIOR₁, the prover sends**w**as an oracle to the verifier; the verifier makes no queries and then outputs the new instance(**x** *′* *,***y** *′* ) := (**x***,***w**)for*R* *′*. This IOR from*R*to*R* *′* has perfect completeness and soundness, and it is honest verifier zero-knowledge: the view of the verifier is empty (the verifier performs no queries), so it can be efficiently (and perfectly) simulated.

•InIOR₂, the prover does nothing; the verifier queries the implicit instance**y** *′* entirely and then checks that(**x** *′* *,***y** *′* )*∈R*. This is an IOPP for*R* *′* with perfect completeness and soundness, and it is honest verifier zero-knowledge: the simulator in Definition 2.1 can query the entire implicit instance, so it can simulate the view of the honest verifier.

The composition ofIOR₁ andIOR₂ yields a trivial IOP for*R*. Note thatIOR₁ andIOR₂ each satisfy Definition 2.1, yet the prover in their composition sends the witness to the verifier, which is not honest-verifier zero-knowledge (unless*R*is trivial). We conclude that Definition 2.1 is not strong enough to capture the notion of HVZK necessary for composing IORs (while preserving HVZK). Variants ofIOR₁ where the prover sends**w**encoded with a zero-knowledge code will be central to our constructions. The problem with Definition 2.1 is that it*does not account for the way in* *which the implicit instance***y** *′* *output by*IOR₁ *is queried in*IOR₂.

**Defining HVZK for IORs.**We strengthen Definition 2.1 by requiring the simulator to addi- tionally be responsible for simulating all future queries to the implicit instance**y** *′* output by the verifier. We model these queries via an oracle algorithm*D*that we call a*distinguisher*, because*D* captures the additional distinguishing opportunities arising from querying**y** *′*.

**Definition 2.5**(informal)**.***Let*IOR= (**P***,***V**)*be an IOR fromRtoR* *′* *. The***view***of*IOR*on* (**x***,***y***,***w**)*∈ Rwith respect to an oracle algorithmDis the random variable*View(**P***,***V***,D,***x***,***y***,***w**) *that consists of***V***’s andD’s randomnesses, the answers to***V***’s andD’s queries, andD’s output* **y** *′ ′ ′* **y***′′* out*in this experiment:* **P**(**x***,***y***,***w**)*and***V** (**x**)*interact yielding output*(**x***,***y***,***w**)*, and thenD* (**x**) *is run to produce*out*.*IOR*has***honest-verifier zero-knowledge with error***ζ***and query** **complexity**b**with respect to***Dif there exists a polynomial time simulator***S***such that the* *random variables*View(**P***,***V***,D,***x***,***y***,***w**)*and***S** **y***,D*

(**x**)*areζ-close (in statistical distance) and***S**
**y***,D*

(**x**)
*makes at most*b*queries to***y***.*

Above, the simulator**S**has black-box access to*D*so, in particular, can run*D*(**x** *′* )to deduce simulated answers for its queries to**y** *′*. Note that Definition 2.5 collapses to Definition 2.1 when*D* makes no queries to**y** *′* (i.e.,*D*is trivial). **y** *′′* IOR₁ is honest-verifier zero-knowledge with respect to the trivial distinguisher*D* (**x**) =*⊥*, **y** *′′* but does not satisfy Definition 2.5 for any non-trivial distinguisher*D* (**x**)that queries its implicit

instance**y** *′*, and in particular does not satisfy honest-verifier zero-knowledge with respect to the simulator forIOR₂ (unless the relation*R*is trivial). The oracle algorithm*D*enables us to formulate a composition theorem, which we discuss next.

**HVZK composition theorem.**We informally state a composition theorem for HVZK IORs.

**Lemma 2.6**(informal)**.***Let*IOR₁ *be an IOR fromR₁ toR₂ and*IOR₂ *be an IOR fromR₂ toR₃,* *and let*IOR :=IOR₁ *◦*IOR₂ *be the IOR fromR₁ toR₃ obtained by composing these. Suppose that:* •IOR₂ *is HVZK with errorζ₂ and query complexity*b₂ *with respect toD₂, with simulator***S₂***;* **y y***,D*2 •IOR₁ *is HVZK with errorζ₁ and query complexity*b₁ *with respect toD₁*(**x**) :=**S₂** (**x**)*.* *Then*IOR*is HVZK with errorζ₁* +*ζ₂ and query complexity*b₁ *with respect toD₂.*

**y** 1**y**1*,D*1 *Proof sketch.*Let**S₁** be the simulator forIOR₁ and define**S** (**x₁**) :=**S₁** (**x₁**). By the honest- verifier zero-knowledge ofIOR₁ with respect to*D₁*, the distribution of**S** **y** 1 (**x₁**)has statistical distance at most*ζ₁* from the experiment in which(**P₁***,***V₁**)interact on(**x₁***,***y₁***,***w₁**), outputting(**x₂***,***y₂***,***w₂**), **y** 2**y**2**y**2*,D*2 and then*D₁* (**x₂**)is run. Since*D₁* (**x₂**) =**S₂** (**x₂**), by honest-verifier zero-knowledge ofIOR₂ with respect to*D₂*, this latter part has statistical distance at most*ζ₂* from running(**P₂***,***V₂**)on **y** 3 **y**1 (**x₂***,***y₂***,***w₂**)to obtain(**x₃***,***y₃***,***w₃**)and then running*D₂* (**x₃**). Thus, the distribution of**S** (**x₁**)has statistical distance at most*ζ₁* +*ζ₂* from an honest execution ofIORfollowed by*D₂*.

**Distinguisher classes in our constructions.**Lemma 2.6 spells out the minimal condition for HVZK composition by relying on Definition 2.5 with*D*set to a specific algorithm. More generally we consider an extension of Definition 2.5 that requires the simulator to work for every algorithm*D* in a given classD. This strengthening enables preserving HVZK in a more flexible way: for HVZK composition, it suffices that the algorithm*D*arising from the second IOR’s simulator belongs to the classD. We typically construct IORs that satisfy this notion for a specific class of algorithms that is both general and restricted enough for our purposes: the class of*t-restricted distinguishers*, denotedD *≤t*, consisting of algorithms that make at most*t*queries to the implicit instance.

See Section 4 for the formal definition of HVZK for IORs and the associated composition theorem.

### 2.4 A “committed” relation for zero-knowledge

We describe and motivate the main relation that we use in this work. The relation is similar to constrained relations in prior work [ACFY25; BCFW25] but with differences that we motivate below: (1) succinct linear constraints to allow for a polylogarithmic verifier, and (2) a “committed” version of the relation to allow for zero-knowledge.

**The relation in Equation 2 is insufficient.**The linear constraint relation *R*¯*C*in Equation 2 has two limitations from the perspective of our work. First, linear constraints are expressed via an*explicit*coefficient vector***v**∈*F *ℓ* in the explicit instance**x**, which rules out verifiers that run in time*o*(*ℓ*); instead, we seek a*succinct*representation of linear constraints. Second, the target *µ∈*Fin the explicit instance**x**contains information about the secret message***f***(even ifEnc*C*is a zero-knowledge encoding), whereas we seek to avoid revealing even a single linear constraint about the message***f***. We modify *R*¯*C*to address these two limitations.

**Modification 1: succinct linear constraints.**We replace***v***in**x**with a succinct statestthat implicitly represents such a vector. We hardcode in the relation a*succinct linear form*slthat, given as input a “small” statest(from some space determined bysl), outputs an explicit vector ***v**∈*F *ℓ*. A simple example to keep in mind is the succinct constraintslmappingst=*α∈*Fto the

vectorsl(st) := (*α* *i−*1 ) *i∈*[*ℓ*]. These succinct linear forms are similar to sumcheck-based constraints in [ACFY25]. While the two constraint classes are formally incomparable, both would suffice for our protocols; we opt to use succinct linear constraints as they are a better notational fit in this paper.

**Modification 2: masks in the constraint.**The target*µ∈*Fleaks the linear constraint*⟨**f**,**v**⟩* about the secret message***f***. We further modify the relation to incorporate sumcheck-friendly masks *m* intended to eliminate the leakage in*µ*. We introduce an additional linear code*C*zk*⊆*Σzk zkwith zero- *ℓ* zk*r*zk*m ℓ*zk

|ℓ|m|n|ℓ|
|---|---|---|---|
|||n ℓ||

knowledge encodingEnc*C* zk :F *×*F *→*Σzk zkthat we use to encode small masks***ξ₁**,...,**ξ** ∈*F (as many masks as there are variables). We associate linear constraints***u₁**,...,**u** ∈*Fzkto these masks, which need not be succinct (as the masks are in fact small).

**Committed sumcheck relation.**The above considerations lead to the relation*RC,C* zk*,*sl where:

(a) the explicit instance**x**= ((*µ,*st*,*(***u**i*)*i∈*[*n*]))contains the target, succinct linear constraint, and explicit linear constraints; (b) the implicit instance**y**= (*f,*(*ξi*)*i∈*[*n*])contains the main encoding and the encoded masks; and (c) the witness**w**= (***f**,**r**,*(***ξ**i,**r**i*)*i∈*[*n*])contains the underlying secret messages and secret masks and their corresponding secret randomnesses. Namely:
  ∣    **x**= ((*µ,*st*,*(***u**i*)*i∈*[*n*]))*,* ∣∣ *f*=Enc*C*(***f**,**r***)    ∣ *RC,C* zk*,*sl := **y**= (*f,*(*ξi*)*i∈*[*n*])*,*  ∣ *∧∀i∈*[*n*] : *ξi*=Enc*C* zk (***ξ**i,**r**i*)*.*(3)   ∣ ∑  

||,r )||⟨ξ ,u ⟩=µ||
|---|---|---|---|---|
|i i∈[n]|i i i∈[n]|i∈[n]|i i i i∈[n]|i i∈[n]|

**w**= (***f**,**r**,*(***ξ**i i i∈*[*n*]) ∣ *∧⟨**f**,*sl(st)*⟩*+*i∈*[*n*] *i i*

We call this a**committed sumcheck relation**: the implicit instance**y**= (*f,*(*ξ*))can infor- mally be viewed as a commitment to the secret message***f***and masks(***ξ***), which are jointly constrained via a sumcheck-friendly linear constraint. The encoding*f*is the “main” oracle, while the encodings(*ξ*) are much smaller encoded “mask” oracles: they appear in the joint con- straint to “hide” the value of a linear constraint on***f***. We refer to the last constraint as the*joint* constraint, which combines the masks as well as the main oracle. Verifier succinctness in our protocols will come from the succinct statest: in our sumcheck reduction, the verifier will only need to evaluate a “fold” ofst, which is in polylogarithmic time for the succinct linear forms that we consider.

### 2.5 An honest-verifier zero-knowledge sumcheck reduction

We present an HVZK sumcheck*reduction*from testing the (constrained) interleaving of a code to testing the (constrained) code itself plus several small testing problems for another code (with a zero-knowledge encoding); the reduction is based on an extension to zero-knowledge codes of the notion of interleaved folding in [ACFY25; NA25; BCFW25]. Later in Section 2.7 we discuss how we use this HVZK sumcheck reduction multiple times to obtain our results: we use it to establish Theorem 1 and Theorem 2, and we use it for an HVZK variant of [ACFY25]’s sumcheck-query IOP reduction from R1CS to testing interleaved codes. *m*

|Code interleaving and its folding.Recall that theK-interleaving of a codeC ⊆Σ|||||is the|
|---|---|---|---|---|---|
|≡K|K m|K|K|K m|K m|
||k|||||
||||k|||
|C||||||

code*C* *≡K* *⊆*(Σ *K* ) *m* consisting of words*u∈*(Σ *K* ) *m* such that there exist words*v₁,...,v ∈*Σ *m* in *C*with*u*(*z*) = (*v₁*(*z*)*,...,v* (*z*))*∈*Σ for every*z∈*[*m*]. In this paper we consider the interleaving operation for*K*= 2 and we define interleaving directly in terms of a zero-knowledge encoding Enc*≡*2*k* that separately encodes2 pieces of the given message, chosen in a special way based on multilinear polynomials, via the given zero-knowledge encodingEnc*C*for*C*. Beloweqis the

### k-variable equality polynomial

∏ *k*
eq(X₁*,...,*X*k,*Y₁*,...,*Y*k*) := (X*i·*Y*i*+ (1*−*X*i*)*·*(1*−*Y*i*))*.*
*i*=1

||m|||||C|ℓ|r m|
|---|---|---|---|---|---|---|---|---|
|k|||≡2|2|m||||
|2 ℓ|2 r|2 m||||||2 ℓ|
|2 r|k|b b∈{0,1}||b b∈{0,1}|||||
|<2|k+logℓ k+logℓ k+logr|b∈{0,1} b∈{0,1}|<2|k+logr k k|b k+1 b k+1|k+logℓ k+logr|||

**Definition 2.7.***LetC ⊆*Σ *be a code with a zero-knowledge encoding*Enc :F *×*F *→*Σ*.* *k k* *Fork∈*N*, the*2**-interleaving***ofCis the codeC ⊆*(Σ) *obtained via the zero-knowledge* *k k k k* *encoding*Enc *C* *≡*2*k* :F *×*F *→*(Σ) *defined as follows. We split a message**f**∈*F *and* *k* *randomness**r**∈*F *into*2 *pieces*(***f***) *k and*(***r***) *k by viewing both as multilinear*
*polynomials **f***ˆ*∈*F [X₁*,...,*X]*and **r***ˆ*∈*F [X₁*,...,*X]*and writing*
∑ ***f***
ˆ(X₁*,...,*X) = eq(***b**,*(X₁*,...,*X))*·**f*** (X*,...,*X)*,*(4)
*k* ∑
***r***ˆ(X₁*,...,*X) = eq(***b**,*(X₁*,...,*X))*·**r*** (X*,...,*X)*.*(5)
*k*

*Then we define* () 2 *k* *∀z∈*[*m*]*,*Enc *C* *≡*2*k* (***f**,**r***) (*z*) := Enc*C*(***fb**,**rb***)(*z*)***b**∈{*0*,*1*}k∈*Σ*.*

Next, we define the notion of*interleaved folding*. *k*

||||2||i|
|---|---|---|---|---|---|
|2 2|(b,c)|b∈{0,1}||k (b,c)|i|
||k−i||c b∈{0,1}||(b,c)|
|||||ι||

**Definition 2.8.***The***interleaved fold***of a functionf*: [*m*]*→*Σ *at the point**γ**∈*F *withi∈*[*k*] *k−i* *∼ k−i* *is the function*Fold(*f,**γ***) : [*m*]*→*Σ *defined as follows. We identify{*0*,*1*}* = *{*0*,*1*} ×{*0*,*1*},* () *and for everyz∈*[*m*]*we writef*(*z*) = *f* (*z*)*i* *,**c**∈{*0*,*1*}k−i* *, meaning thatf* (*z*)*∈*Σ*is the* *k* *coordinate of the vectorf*(*z*)*∈*Σ *indexed by*(***b**,**c***)*. Then, for everyz∈*[*m*]*we define*

2 *k−i* () ∑ Fold(*f,**γ***)(*z*)*∈*F *s.t.∀**c**∈{*0*,*1*},* Fold(*f,**γ***)(*z*) := eq(***b**,**γ***)*·f* (*z*)*.* *i*

*The expressions are well-defined because*Σ*is an*F*-linear vector space (e.g.,*Σ =F *for someι∈*N*).*

The key feature of the above definitions is that “encode then fold” equals “fold then encode”.

2 *k* *ℓ* 2*kr i* **Claim 2.9**(informal)**.***For every**f**∈*F*,**r**∈*F*,i∈*[*k*]*, and**γ**∈*F*,* () Fold Enc *C* *≡*2*k* (***f**,**r***)*,**γ*** =Enc*C≡*2*k−i* (Fold(***f**,**γ***)*,*Fold(***r**,**γ***))*.*

The above definitions and identity are a direct extension to zero-knowledge codes of the notions of folding for arbitrary linear codes that appear in [ACFY25; NA25; BCFW25]. These folding notions are similar to, but distinct from, other notions of folding that apply to several classes of codes in [AHIV17; BCG20; BBHR18; BGKS20; GLSTW23; ZCF24; DP24; ACFY24]. **An HVZK committed-sumcheck IOR.**Armed with these definitions, we can*fold*an initial interleaved codeword and then claim that the resulting codeword is an interleaved codeword with a *smaller*interleaving factor, while keeping track of the succinct linear constraints. This intuition is what underlies the HVZK committed-sumcheck IOR that we now describe. Specifically, we outline a queryless IOR from*R* *C* *≡*2*k,C,*slto*RC,C*zk*,*sl*′* where(*n,C*zk*,*sl)are as in the definition of the relation zk in Equation 3,*C*is anF-additive code with a zero-knowledge encodingEnc*C*, and*k∈*N.

() **Construction 2.10.**The verifier receives as explicit input**x** := *µ,*st*,*(***u**i*)*i∈*[*n*]and oracle access to the implicit input**y** := (*f,*(*ξi*)*i∈*[*n*]). In the honest case, the prover receives as input a witness **w** := (***f**,**r**,*(***ξ**i i i∈*[*n*])such that(**x***,***y***,***w**)*∈R≡*2*k*

|,r )|||.||||||
|---|---|---|---|---|---|---|---|---|
|i i i∈[n]|k k ′ r|C m|,C ,sl j k <ℓ|C j (b ,...,b|j′ )∈{0,1}|<2|k ℓ l=1 j l k k+logℓ|ℓ l−1 k|

zk zk

1.The prover sends oracles*s₁,...,s ∈*Σzk zk. The honest prover samples masks***s₁**,...,**s** ∈*F and randomnesses***r₁***
*′* *,...,**r** ∈*Fzk, and sets*s* :=Enc zk (***s**,**r***)for*j∈*[*k*]. The masks are ∑ zk interpreted as univariate polynomials ***s***ˆ₁*,...,**s***ˆ *∈*Fzk[X]:*∀j∈*[*k*]*, **s***ˆ*j*(X) := (***s***) *·*X. ∑ ()

2.The prover sends˜*µ∈*F. The honest prover sets˜*µ* :=
1 *k* *k **s***ˆ₁(*b₁*) +*···*+ ***s***ˆ (*b*).

3.The verifier samples and sends*ε←*F.
4.The prover and the verifier interpret***f***as a multilinear polynomial ***f***ˆ*∈*F [X₁*,...,*X](see Equation 4) and they run a*k*-round sumcheck protocol on the claim
∑ () ***s***ˆ₁(*b₁*) +*···*+ ***s***ˆ*k*(*bk*) +*ε· G*ˆ(*b₁,...,bk*) = ˜*µ*+*ε·µ* (*b*1*,...,bk*)*∈{*0*,*1*}k*

where   ∑ ***f*** ˆ (X*,...,*X*,**a***) ∑ *G* ̂(X1 *,...,*X*k*) :=  1 *k* + *⟨**ξ**i,**u**i⟩* log*ℓ* *·*Fold(sl(st)*,*X₁*,...,*X )[*k**a***] ***a**∈{*0*,*1*} i∈*[*n*]

andFoldis defined to mirror Definition 2.8:   ∑
Fold(sl(st)*,*X₁*,...,*X*k*) :=  eq(X₁*,...,*X*k,**b***)*·*sl(st)[***a**,**b***]*.*
***b**∈{*0*,*1*}k* ***a**∈{*0*,*1*}*log*ℓ*

In each round*j∈*[*k*]the prover sends a univariate polynomial *h*ˆ*j∈*F *<ℓ*zk [X]and the verifier replies with a random*γj←*F. Define***γ**j*:= (*γ₁,...,γj*)*∈*F *j* for every*j∈*[*k*], and set***γ*** :=***γ**k*.

5.The verifier sets*µ*
*′* := *h*ˆ*k*(*γk*)and outputs a new instance for the target relation*R* *C,C*zk*,*sl *′* with the joint constraint: ∑

||sˆ₁(γ₁) +···+ sˆ|(γ ) +⟨Fold(f,γ),ε·Fold(sl(st),γ)⟩+|||||⟨ξ ,ε·u ⟩=µ.|||
|---|---|---|---|---|---|---|---|---|---|
|||k k||||i∈[n]|i i|′||
||′|||||||||
|′|′|i i∈[n]|jl− 1 ℓ jl− l=1|1 ℓ l=1 j∈[k]|j|1 ℓ jl− l=1|j j||′|
|′||i i∈[n] ′|j j∈[k]||i i i∈[n]|j j′ j∈[k] logℓ||||

That is,sl is defined to express the succinct linear constraint(st*,**γ**,ε*)*7→ε·*Fold(sl(st)*,**γ***)and the outputs are: := ( zk •**x** *µ,*(st*,**γ**,ε*)*,*(*ε·**u***)*,*((*γ*)))where(st*,**γ**,ε*)is a succinct state forsl and zk zk for each*j∈*[*k*]the vector(*γ*) is chosen so that*⟨**s**,*(*γ*) *⟩*= ***s***ˆ (*γ*); •**y** := (Fold(*f,**γ***)*,*(*ξ*)*,*(*s*)); and •in the honest case**w** := (Fold(***f**,**γ***)*,*Fold(***r**,**γ***)*,*(***ξ**,**r***)*,*(***s**,**r***)).

**Completeness.**The completeness of the construction follows by Claim 2.9 after observing that Fold(***f**,**γ***)[*a*] = ***f***ˆ(***γ**,*binary(*a*))where*a∈*[*ℓ*]andbinary(*a*)*∈{*0*,*1*}* is the binary representation of*a*(the same holds also for the folding ofsl(st)). This follows by Definition 2.8: ∑ ∑ Fold(***f**,**γ***)[*a*] = eq(***b**,**γ***)*·**f***(***b***)[*a*] = eq(***b**,**γ***)*·**fb***[*a*] ***b**∈{*0*,*1*}k**b**∈{*0*,*1*}k* ∑ () = eq(***b**,**γ***)*·**fb***(binary(*a*)) = ***f***ˆ ***γ**,*binary(*a*)*.* ***b**∈{*0*,*1*}k*

**Honest-verifier zero-knowledge.**We sketch why Construction 2.10 is HVZK.

*ℓ r*zk*m* **Lemma 2.11.***Lett∈*N*and assume*char(F)*̸*= 2*. If*Enc*C* zk :Fzk*×*F *→*Σzk zk*is at*zk*-query* *zero-knowledge encoding forC*zk*with errorζC* zk *andℓ*zk*≥*2*, then Construction 6.3 is honest-verifier* *zero-knowledge with errork·ζC* zk *with respect to the family of distinguishers*D*makingtqueries* *to***y** *′* *andt*zk*queries to each of the other oracles in***y** *′* *. The simulator makestqueries tofandt*zk *queries to each oracle*(*ξi*)*i∈*[*n*]*in***y***.*

*Proof sketch.*We outline the zero-knowledge simulator. First, since the distinguisher class is re- stricted to make at most*t*zkqueries to the oracles(*sj*)*j∈*[*k*]in**y** *′*, the simulator uses the simulator for the code*C*zkto sample answers for these queries. Taking a union bound gives the simulation error *k·ζC* zk. Second, for the sumcheck part, the simulator samples˜*µ,ε,*(*γj*)*j∈*[*k*]uniformly at random, and then samples(*h*ˆ*j*)*j∈*[*k*]uniformly at random*conditioned*on satisfying all consistency checks in the sumcheck protocol. This matches the distribution of the sumcheck protocol, as we show via a linear-algebraic argument by counting the degrees of freedom provided by the random masks (this part is similar to the analysis of the zero-knowledge sumcheck in [XZZPS19]). The assumption char(F)*̸*= 2ensures that the mask contribution in the sumcheck claim does not cancel.

**Round-by-round knowledge soundness.**We sketch why Construction 2.10 satisfies straightline RBR knowledge soundness [BCFW25]. The construction is an IOR*of proximity*from*R* *C* *≡*2*k,C,*slto zk *RC,C* zk*,*sl *′*, so the knowledge soundness error depends on proximity parameters for the first relation and for the second relation. Moreover, implicit instances involve multiple oracles of different sizes so we use multiple proximity parameters: a proximity parameter*δ*for the main oracle, and a proximity parameter*δ*zkfor all mask oracles. One way to express this, similarly to [BMNW25; BCFW25], is via the “relaxed” relation corresponding to*RC,C* zk*,*sl (Equation 3) defined as follows:   ∣    **x***,* ∣∣ ∆(*f, f*¯)*≤δ*  *R* ˜ *C,C* zk zk*,*sl := **y**= (*f,*(*ξi*)*i∈*[*n*])*,*  ∣∣ *∧∀i∈*[*n*]*,*∆(*ξi, ξ*¯*i*)*≤δ*zk*.* *δ,δ*     ¯ ¯ ¯ )) ∣  (**w***,*¯**y** := (*f, ξ₁,..., ξn*∣ *∧*(**x***,*¯*,***y w**)*∈RC,C* zk*,*sl

Finally, we target distance preservation, so we use the*same*proximity parameters*δ,δ*zkto relax the initial and target relations. In light of all this, the round-by-round knowledge soundness of the construction can be stated as follows.

**Lemma 2.12**(informal)**.***For everyδ,δ*zk*∈*(0*,*1)*, Construction 2.10 has round-by-round knowledge* ˜*δ,δ*zk˜*δ,δ*zk *soundness with relaxation*(*R* *≡*2*k* *, R* *C,C,*sl *′* )*with the following round errors:* *C,C*zk*,*sl zk  *k*  <u>|Λ(C</u> *≡*2 <u>,δ)|·|Λ(Czk</u> *≡n*+*k* <u>,δzk)|</u> *,*   *|*F*|*   ( )   *≡*2*k−*(*j−*1)*≡n*+*k* *.*  *≡*2*k−j* <u>ℓzk·|Λ(C,δ)|·|Λ(Czk,δzk)|</u>   *ϵ* mca(*C,δ*) +  *|*F*|* *j∈*[*k*]

*Proof sketch.*The proof is similar in spirit to analyses in [ACFY25; BCFW25], but is more challeng- ing due to the fact that multiple codewords participate in the constraint being checked. Typically, (knowledge) soundness analyses for IORs involve two types of errors: proximity preservation errors and list size errors. Proximity preservation errors are captured, as in prior work, via a quantity *ϵ* mca(*C,δ*)that equals the MCA (mutual correlated agreement) error of a given code*C*at distance *δ*. List size errors require some care in our setting, as we now explain.

In each round we upper bound the probability that*any*codeword at distance*δ*from the sent oracles causes that round’s “claim” to flip from false to true. This leads to taking a union bound over the list size of the code at distance*δ*. However, “breaking” the interleaved word*f*into its2 *k*

parts and then naively applying a union bound over*each*one would lead to a union bound over 2 *k* *|*Λ(*C,δ*)*|* many events. Similarly, for the*n*+*k*masks allegedly in the code*C*zk, we may end up with a union bound over*|*Λ(*C*zk*,δ*zk)*|* *n*+*k* many events. Such an approach would ultimately require selecting an extremely large fieldF. *≡*2*k≡n*+*k* Instead, in our analysis we analyze codewords relative to the interleaved codes*C* and*C*zk. As interleaving*does not*increase a code’s list-size by more than a constant factor [GGR11], this yields a significantly improved soundness error. This crucially relies on the fact that our protocol *correlates the queries*(over a larger alphabet) to these oracles (which also reduces the argument size of the resulting argument after compilation).

**Comparisons.**We compare our zero-knowledge sumcheck with prior variants. While all known zero-knowledge sumchecks are similar at a high level in their masking of sumcheck polynomials, our specific construction differs from other variants in crucial aspects motivated by our context.

•[CFS17; BCL22; Dia25] considers a “full mask” in the form of a random polynomial added to the original one via a random linear combination; this incurs an overhead of at least 2, which is too expensive for us. Moreover, [BCL22] does not employ out-of-domain techniques to achieve list-decoding soundness and, in particular, only targets constant soundness error.

•[XZZPS19] describes a zero-knowledge sumcheck, based on polynomial commitment schemes, that uses a small mask for each round rather than a full mask at the start. Our protocol also uses small masks but the different setting of IOPs/IORs demands different techniques: the small masks are*oracles*that we carry throughout the reduction (as opposed to them being committed and opened once). Moreover, the protocol in [XZZPS19] reveals an evaluation of the masks and thus an evaluation of the main oracle; but we cannot afford this in our setting, which is why we define the relation to accumulate claims about the masks. Finally, our sumcheck is a reduction from an interleaved code to the base code, while the sumcheck in [XZZPS19] serves as an ingredient in the GKR protocol, and hence it is used in a different context.

•[RW24] uses zero-knowledge codes for masks tailored to the tensor-code sumcheck. Their context is similar to ours: they reduce the testing of a tensor code to the testing of the base code, and they similarly use small masks to achieve zero-knowledge (in their case they achieve*malicious*-verifier zero-knowledge while we achieve honest-verifier zero-knowledge). The main difference between their approach and ours is that they use tensor codes while we use interleaved codes. Moreover, we achieve list-decoding soundness, while [RW24] targets constant soundness, and additionally, our work emphasizes the efficiency of the prover and the verifier, whereas the prover in [RW24] runs in polynomial time.

There are other variants of zero-knowledge sumchecks in the PCP setting [GOS24; GOS25], though these are less relevant to this work as they are closely related to the “full mask” approach in [CFS17] (which has an overhead of at least 2) and are adapted to the unique challenges of PCPs.

### 2.6 HVZK code switching

We describe our HVZK code-switching reduction: a HVZK IOR that reduces a claim in*RC,C* zk*,*sl *m ι m ′ ′ m′ι′m′*

|ι m||′ ′ m|ι m||
|---|---|---|---|---|
||C ,C ,sl||||

for the code*C⊆*Σ *≡*(F) to*RC′,C* zk*,*sl *′* for an*arbitrary codeC ⊆*(Σ) *≡*(F). The setting that we consider presents two significant challenges compared to previous codeswitches (e.g. [RR20; RW24; ACFY24; ACFY25; BCFRRZ25; BMMS25a; BCFW25; BFRW25]).

**Code-switching without ZK.**Known code-switching methods follow a template.

1.The verifier has access to an oracle*f∈*Σ
*m*. In the honest case,*f*=*C*(***f***)*∧*Φ(***f***) = 1, i.e.,*f*is the encoding under the code*C*of a message***f***that satisfies a given predicateΦ. *′ m′′*

2.The prover sends*g∈*(Σ). In the honest case,*g*=*C* (***f***), i.e.,*g*is the encoding of***f***under the code*C*
*′*.

3.The verifier samples challenges*x₁,...,xt∈*[*m*]and queries*f*(*x₁*)*,...,f*(*xt*).
4.The prover and verifier engage in a proximity protocol for the claim “***g***=*C*
*−*1

(*g*)*∧*Φ *′*
(*g*) = 1”
*′* whereΦ

|(g) := Φ(g)∧ ∧|C(g)[x] =f(x ).|||
|---|---|---|---|
|′|i∈[t]|i i||
|i∈[t]|i i|||

∧ The checks (*C*(***g***)[*x*] =*f*(*x*))are a “consistency check” that the new oracle*g*indeed encodes the same message as the original oracle*f*. This template has not been applied to zero-knowledge codes, with the notable exception of [RW24], whose code-switching relies on specific properties of (zero-knowledge) tensor codes.

**Code-switching with ZK encodings.**When using a zero-knowledge encodingEnc*C*for a code*C*, the codeword*f*=Enc*C*(***f**,**r***)depends on both the message***f***and the randomness***r***. Hence, in order to be complete, a consistency check must also take into account***r***. One option to address this would be for the new oracle*g*to encode, under*C* *′* both the message and the randomness. Unfortunately, since later rounds will require to invoke the sumcheck protocol, that would require introducing padding that would involve at least a2*×*overhead. Instead, we leverage the committed sumcheck relation introduced in Section 2.4 to introduce an*additional mask*encoding the randomness using *C*zk. Then, supposing that*g*=Enc*C′* (***f**,**r*** *′* )and*s*=Enc*C* zk (***r**,**r*** *′′* )(where***r*** *′* *,**r*** *′′* are freshly sampled pieces of randomness), for*x∈*[*m·ι*]one can write the following claim ( []) ***f***# $ *f*(*x*) =Enc*C*(***f**,**r***)[*x*] = ***G**C·* [*x*] =*⟨**f**,**G*** *C* [*x*]*⟩*+*⟨**r**,**G**C*[*x*]*⟩,* ***r***

|,G = [G|]∈F|is the linear map associated withEnc|(recall that we interpret|
|---|---|---|---|
|C C|(ι·m)×(ℓ+r)||C|
|||ι||
|ι||||

where***G**C* # $

alphabet symbols inΣas vectors inF and then again reinterpret the output of the encoding map as *m*symbols ofF). This claim can be written as a succinct linear form via our committed sumcheck relation.

**OOD sampling.**Efficient support for proximity parameters in the list-decoding regime typically relies on some form of out-of-domain (OOD) sampling [BGKS20]; without it, the above ideas would lead to inefficient protocols (regardless of zero knowledge considerations). Informally, OOD sampling refers to methods that force the prover, after sending an oracle*f*, to “choose” a single codeword inΛ(*C,f,δ*)(if*δ > δ*(*C*)*/*2then it can be that*|*Λ(*C,f,δ*)*|>*1). Several methods for this task are used in the literature [BGKS20; ACY23; ACFY24; ACFY25; BMNW25; BCFW25; BFRW25; MZ25]; here we follow the presentation of [BCFW25]. Let*C ⊆*Σ *m* be a code with message spaceF *ℓ*, and fix a functionze: *D*ze*→*F *t* ood*×ℓ*. OOD sampling roughly works as follows.

1.The prover sends*f∈*Σ
*m*. In the honest case,*f*=*C*(***f***).

|2.The verifier samplesρ←D|.|
|---|---|
|3.The prover sendsy∈F 4.The prover and verifier proceed, with the additional constraint “ze(ρ)·C|. In the honest casey :=ze(ρ)·f.|

ze *t* ood *−*1

(*f*) =***y***”.
[BCFW25] shows that, for appropriate choices ofze, with high probability over*ρ*a*single*codeword inΛ(*C,f,δ*)satisfies the aforementioned additional constraint, and this property enables building efficient protocols in the list-decoding regime. However, the above protocol is*not compatible*with zero-knowledge. The vector***y***leaks infor- mation about***f***(which encodes information about the private witness). The tension is inherent, in that the OOD protocol is supposed to uniquely identify a single codeword (and thus witness), while the zero-knowledge guarantee mandates that no information is revealed about this witness.

**OOD sampling with ZK.**We resolve this tension by extending the functionzeto allow for additional randomization. Letze: *D*ze*→*F *t* ood*×*(*ℓ*+*r*)be a function. The revised OOD sample is set as [] ***f*** ***y*** :=ze(*ρ*)*·,*(6) ***r***

where*ρ←D*zeand***r**←*F *r* are freshly sampled randomness. We requirezeto satisfy two conditions:

(i)zemust be suitable as an OOD sample, and (ii)zemust guarantee that***y***leaks no information on***f***. The first condition, as shown in [BCFW25], is equivalent tozebeing a zero-evader (a widely studied notion): for every***v**̸*=**0**it holds thatPr*ρ*[ze(*ρ*)*·**v***=**0**]*≤ε*zero. For the second condition, we introduce the notion of a(*r,ζ*ze)**-private zero-evader**which is a zero-evader where(***y**,ρ*)in Equation 6 can be efficiently simulated (with statistical error at most*ζ*ze). We show that zero- evaders satisfying the two conditions are plentiful (and in fact with perfect privacy error*ζ*ze= 0).

||t|×ℓ|
|---|---|---|
|′ ′|t ×(ℓ+r)||
 **Lemma 2.13.***Let*ze: *D*ze*→*Food*be a zero-evader with errorε*zero*. For everyr∈*N*there exists* *a zero-evader*ze : *D*ze*→*Food*with error≈ε*zero*that is*(*r,*0)*-private.* One last challenge must be solved. The newly sampled randomness***r***must somehow be included in the code switching claim. Including***r***in the message encoded with*C*
*′* involves the same padding complication that we encountered in the zero-knowledge code-switching. Instead, we again make use of the flexibility of the committed sumcheck relation, and perform a*joint OOD sample*of both *g*and*s*. To do so, we rely on the following lemma, which generalizes [BCFW25]. In particular, compatibly with zero-knowledge encodings, we allow*many codewords close to the original words* to satisfy the same constraint, but we enforce that the “message” parts must indeed be equal.

**Lemma 2.14.***Let*ze: *D*ze*→*F *t* ood*×*(*ℓ*+*ℓ*zk)*be a zero-evader with errorε* zero*. LetC ⊆*Σ *m* *≡*(F *ι* ) *m* *,* *m ι*zk*m*zk*ℓ r ι·m* *C*zk*⊆*Σzk zk*≡*(F) *be*F*-additive codes with zero-knowledge encodings*Enc*C*:F *×*F *→*F *and* *ℓ r*zk*ι ·m′* zk Enc*C* zk :Fzk*×*F *→*F*. For everyf,s,*

 ¯ ¯  *∃*(*f₁, f₂*)*∈*Λ(*C,f,δ*)*,*(¯1*s ,*¯2*s*)*∈*Λ(*C*zk*,s,δ*zk)  (***f₁**,**s₁***)*̸*= (***f₂**,**s₂***)*∧*ze(*ρ*)*·*(***f₁**,**s₁***) T =ze(*ρ*)*·*(***f₂**,**s₂***) T     *where:* 2 2 Pr   *≤|*Λ(*C,δ*)*| ·|*Λ(*C*zk*,δ*zk)*| ·ε*zero *ρ* *−*1 ¯*′ −*1   (***f₁**,**r₁***) :=Enc *C* (*f₁*)*,*(***s₁**,**r₁***) :=Enc *C* (¯1*s*)*,*  zk (***f₂**,**r₂***) :=Enc *−* *C* 1 (*f*¯2)*,*(***s₂**,**r₂*** *′* ) :=Enc *−* *C* zk 1 (¯2*s*)

*Proof sketch.*Fix distinct(*f*¯1*,*¯1*s*)*,*(*f*¯2*,*¯2*s*)*∈*Λ(*C,f,δ*)*×*Λ(*C*zk*,s,δ*zk). Write(***f₁**,**r₁***) :=Enc *−* *C* 1 (*f*¯1), (***s₁**,**r₁*** *′* ) :=Enc *−* *C* zk 1 (¯1*s*)and(***f₂**,**r₂***) :=Enc *−* *C* 1 (*f*¯2),(***s₂**,**r₂*** *′* ) :=Enc *−* *C* zk 1 (¯2*s*). If(***f₁**,**s₁***) = (***f₂**,**s₂***)we are

done. Else, sincezeis a zero-evader, it must be that except with probability*ε*zero, [] ***f₁** −**f₂*** ze(*ρ*)*· ̸*=**0***.* ***s₁** −**s₂***

( *|*Λ(*C,δ*)*|·|*Λ(*C*zk zk )

|,δ|)|||
|---|---|---|
|2|||
|C|′|′ ′′|

Taking a union bound over the many such words concludes the proof.

In particular, supposing that*g*=Enc *′* (***f**,**r***)and*s*=Enc*C* zk (***r**,**r*** *′′* )(where***r**,**r*** are freshly sampled choices of randomness), Equation 6 can be rewritten as the claims that ( []) ***f***# $ *∀i∈*[*t*ood] : ***y**i*= ze(*ρ*)*·* [*i*] =*⟨**f**,*ze *i*

(*ρ*)*⟩*+*⟨**r**,*ze*i*(*ρ*)*⟩,*
***r***

whereze # *i*

(*ρ*)(resp.ze
$ *i*

(*ρ*)) denote the first*ℓ*(resp. last*r*) elements of the*i*-th row ofze(*ρ*). Again,
these are claims compatible with our committed sumcheck relation.

**Codeswitch construction.**We incorporate the ideas so far into the following construction.

**Construction 2.15.**The verifier receives explicit input**x**= (*µ,*st*,**u₁**,...,**u**n*)and implicit input **y**= (*f,ξ₁,...,ξn*). The prover receives witness**w**= (***f**,**r**,*(***ξ**i,**r**i*)*i∈*[*n*])such that(**x***,***y***,***w**)*∈RC,C* zk*,*sl.

*′ m′m*

1.The prover sends oracles*g∈*(Σ) and*s∈*Σzk zk. In the honest case, the prover samples *′ r′ℓ*zk*−r ′′ r*zk*′ ′′* ***r** ∈*F,***s**∈*F,***r** ←*F, and sets*g* :=Enc*C′* (***f**,**r***)and*s* :=Enc*C*
zk ((***s**,**r***)*,**r***).

2.The verifier samples and sends out-of-domain randomness*ρ←D*ze.
3.The prover replies with***y**∈*F
*t* ood. In the honest case the prover sets***y*** :=ze(*ρ*)*·*(***f**,**r**,**s***)T.

4.The verifier samples and sends in-domain query randomness*x₁,...,xt←*[*m*]and batching randomness***ε**←*F
*t* ood+*t·ι*.

5.The verifier queries*f*(*x₁*)*,...,f*(*xt*)*∈*Σ*≡*F
*ι* and sets ∑ ∑ ∑ *µ* *′* :=*µ*+ ***ε**i·**y**i*+ ***ε**t* ood+*i·ι*+*l* *·f*(*xi*)*l.* *i∈*[*t*ood] *i∈*[*t*] *l∈*[*ι*]

The verifier outputs a new instance for the target relation*RC′,C* zk*,*sl *′* with the joint constraint

∑ *⟨**f**,*sl(st)*⟩*+ *⟨**ξ**i,**u**i⟩* *i∈*[*n*] ∑ + ***ε**i·⟨*(***f**,**s**,**r***)*,*ze*i*(*ρ*)*⟩*

(7)
*i∈*[*t*ood] ∑ ∑ + ***ε**t* ood+*i·ι*+*l* *·⟨*(***f**,**r***)*,**G**C*[*xi,l*]*⟩*=*µ* *′* *,* *i∈*[*t*] *l∈*[*ι*]

where***G**C*[*xi,l*]*∈*F *ℓ*+*r* denotes the row ofEnc*C*’s generator matrix corresponding to the*l*-th symbol of the*xi*-th position andze*i*denotes the restriction ofzeto the*i*-th row. The output consists of: •**x** *′* := (*µ* *′* *,*st *′* *,*(***u**i*)*i∈*[*n*]*,**u**n*+1)wherest *′* := (st*,**ε**,ρ,x₁,...,xt*)denotes the state for the linear form associated with***f***and***u**n*+1denotes the vector associated with(***s**,**r***)(both the linear form and the vector are obtained by appropriately grouping terms in Equation 7), •**y** *′* := (*g,*(*ξi*)*i∈*[*n*]*,s*), and

•in the honest case**w** *′* := (***f**,**r*** *′* *,*(***ξ**i,**r**i*)*i∈*[*n*]*,*((***r**,**s***)*,**r*** *′′* )).

**Analysis of Construction 2.15.**We outline how we analyze the construction above.

**Lemma 2.16.***Assume that*ze*is a*(*ℓ*zk ze *C′ is at* *′*

|−r,ζ|)-private zero-evader,Enc|-zero-knowledge|
|---|---|---|
||C||
|C|C||
|′||′|

*encoding forC* *′* *with errorζC′, and that*Enc zk *ist*zk*-zero-knowledge encoding forC*zk*. Then, Con-* *struction 2.15 is HVZK with errorζ ′* +*ζ* zk +*ζ*ze*with respect to the family of distinguishers*D *makingt* *′* *queries to the first oracle of***y** *andt*zk*queries to the other oracles in***y***. The simulator* *performstqueries to the first oracle of***y***andt*zk*queries to the remaining oracles.*

*Proof sketch.*Sincezeis a(*ℓ*zk*−r,ζ*ze)-private zero-evader, there exists an efficient algorithm that simulates the distribution of(***y**,ρ*). SinceEnc*C′* andEnc*C* zk are zero-knowledge encodings, there are also efficient simulators for the distribution of queries to their encodings. The simulator for Construction 2.15 samples*x₁,...,xt*uniformly at random, queries*f*at the corresponding positions, and then runs the three simulators described above (answering queries to*ξ₁,...,ξn*by querying the corresponding oracle).

**Lemma 2.17**(informal)**.***For everyδ,δ* *′*

||,δ|∈(0,1), Construction 2.15 has round-by-round knowl-||
|---|---|---|---|
||δ,δ|δ ,δ||
||C,C ,sl|C ,C ,sl|′ ′|
|′ ′ 2|2|||

zk ˜*δ,δ*zk˜*δ* *′* *,δ*zk *edge soundness with relaxation*(*R* zk *, R′ ′*)*with errors* zk () <u>|Λ(C,δ)|·|Λ(Czk</u> *≡n*+1 <u>,δzk)|</u>*t* *|*Λ(*C,δ*)*| ·|*Λ(*C*zk*,δ*zk)*| ·ε*zero*,* + (1*−δ*)*.* *|*F*|*

*Proof sketch.*We only sketch soundness; the round-by-round knowledge soundness proof is given in Lemma 9.9. Fix an arbitrary(¯*g,*¯)*s ∈*Λ(*C* *′* *,g,δ* *′* )*×*Λ(*C*zk*,s,δ*zk)and let(***f**,**r***) :=Enc *−* *C* *′* 1

(¯)*g*,(***s**,**r*** *′* ) :=Enc
*−* *C* zk 1

(¯)*s*.
By Lemma 2.14 there is at most a single pair(***f**,**s***)such thatze(*ρ*)*·*(***f**,**s***) T =***y***. Write***s***= (***r*** *∗* *,**s*** *′* ) and *f*¯=Enc*C*(***f**,**r*** *∗* ). Note that∆(*f, f*¯)*> δ*, or else***f**,**r*** *∗* constitute (together with a valid witness for the other masks) a valid witness for the relation, a contradiction to soundness. In this case, except with probability(1*−δ*) *t*, one of the consistency claims is not satisfied. Thus, for arbitrary (¯*g,*¯)*s ∈*Λ(*C* *′* *,g,δ* *′* )*×*Λ(*C*zk*,s,δ*zk)it must either be that: (i) the OOD condition is not satisfied; (ii) the associated joint constraint is not satisfied; or (iii) one of the consistency claims is not satisfied. Taking a final union bound over the batch yields the final bound.

**Efficiency of Construction 2.15.**The prover time in Construction 2.15 is dominated by the time to compute the encodingEnc*C′*. The verifier time is dominated by the time to compute*µ* *′*. Both of these quantities are*independent*of the starting code*C*, which is counterintuitive. The resolution ˜*δ,δ*zk *′* is that*C*affects future protocols used to test claims for *R* *C* *′* *,C,***sl** *′*, since**sl** *does*depend*C*. This zk added complexity of**sl** *′* was informally reflected in the quantity*TC*introduced in Theorem 2. More ˜*δ,δ*zk formally, in protocols for *R* *C* *′* *,C,***sl** *′*(such as Constructions 2.2 and 2.10) the prover time depends zk on*t***sl***′* and the verifier time depends on the cost of evaluating “folds” of the vectors specified in**sl** *′*.

•The prover time will depend on the time required to compute*t·ι*rows of***G*** # *C* and*t·ι*rows of ***G*** $ *C*. We refer to this quantity ast **P**

*C*.
•The verifier time will depend on the time required to evaluate*t·ι*folded rows of***G*** # *C* according to Definition 2.8), and*t·ι*(non-folded) rows of***G*** $ *C*. We refer to this quantity ast **V**

*C*.

### 2.7 From building blocks to our main results

Theorem 1 follows by composing the zero-knowledge sumcheck IOR from Section 2.5 with the non-succinct IOPP from Section 2.2. Theorem 2 further uses the code-switching protocol from Section 2.6. This sequential composition satisfies HVZK because we establish the composable notion of HVZK for IORs described in Section 2.3: in each IOR we explicitly address a “future distinguisher” that is going to query that IOR’s output implicit instance, capturing as a special case the subsequent IOR invoked on that implicit instance. Making these dependencies explicit and instantiating the distinguishers based on the “next” IORs allows us to safely compose the sub-protocols while maintaining honest-verifier zero-knowledge throughout.

**On the code for the small masks.**The relation*RC,C* zk*,*sl (Equation 3) is defined with respect to the two zero-knowledge codes*C*and*C*zk. Extending the non-succinct “base case” protocol from Section 2.2 from the initial relation *R*¯*C*(Equation 2) to the relation*RC,C* zk*,*sl requires additional care, incurring an additional term of(1*−δ*zk) *t* zkto the soundness error, where*δ* zkis*C*zk’s distance and*t*zkis the number of queries to each mask oracle. In our constructions*C*and*C*zkcan be any F-additive code (with a zero-knowledge simulator supporting the appropriate number of queries). To state Theorem 1 we*fixC*zkto a Reed–Solomon code with message length*O*(*λ/*log log*λ*)and rate1*/*log*λ*. Then each mask has size*O*(*λ·*log*λ/*log log*λ*) = *O* ˜( *λ*)and the distance*δ*zk*≈*1*−*1*/*log*λ* is such that the number of queries*t*zkrequired for(1*−δ*zk) *t* zk*≈*2*−λ*is*t* zk=*O*(*λ/*log log*λ*) =*o*(*λ*). To state Theorem 2 (as well as Theorem 4 below), instead*C*zkmust encode messages with size *O*(*λ*). Again choosing rate1*/*log*λ*, each mask has size*O*(*λ·*log*λ*) = *O* ˜( *λ*), and the number of queries*t*zkrequired is*t*zk=*O*(*λ/*log log*λ*) =*o*(*λ*). Other choices of*C*zkare possible; the above choices achieve*o*(1)overhead in the query complexity of the protocol over the non-private protocols (and in fact over any such IOPP, which requires at least*O*(*λ*)queries [BMMS25b]).

**Theorem 1: sublinear HVZK IOPP for constrained interleaved codes.**First we run the zero-knowledge sumcheck from Section 2.5 to reduce from*R* *C* *≡*2*k,C,*slto*RC,C*zk*,*sl*′*, reducing a zk *≡*2*k* committed sum over the interleaved code*C* to a committed sum over the base code*C*. Then, we use a*variant*of the non-succinct IOPP from Section 2.2 for the relation*RC,C* zk*,*sl *′*. The sumcheck IOR reduces the tested object size from2 *k* *·m*alphabet symbols to*m*alphabet symbols, the size of the base code. The verifier’s runtime is dominated by the queries made by the non-succinct IOPP to the*folded*oracle, with each query mapping to a single query to the original oracle over 2 *k* the alphabetΣ. *≡*2*k* One parameter regime of interest is the following. Assume the encoded message in *√* *C ⊆* 2 *km k ′ ′ ′* 1 *m*

(Σ) has size*ℓ* := 2 *·ℓ* for*ℓ* := *ℓ*and that*k* := log*ℓ*. This implies that*C ⊆*Σ encodes messages of size*ℓ*
*′*. After running the sumcheck IOR, the queries made by the non-succinct IOPP to the tested codeword, i.e., the virtual oracle that the sumcheck IOR reduction outputs, amount 2 *k*2*kℓ′* to a query of the original oracle over alphabetΣ, whose size is*|*Σ*|* =*|*Σ*|*. Since the problem size has been reduced by a square-root factor, the full-mask strategy in the non-succinct protocol over messages of sublinear size compared to the original oracle yields an*o*(1)overhead, as desired.

**Theorem 2: HVZK code-switching.**We combine components developed in prior subsections to obtain a protocol for reducing proximity testing for*R* *C* *≡*2*k,C,*slto proximity testing for*RC′,C*zk*,*sl*′*. zk The construction first runs the zero-knowledge sumcheck from Section 2.5 to reduce from testing 1 A more concretely efficient version can be obtained by balancing the interleaving factor with the message size to minimize the overall argument size (see e.g. [AHIV17; GLSTW23; BFRW25]).

*≡*2*k* the interleaved code*C* to testing the base code*C*. Then, we apply the code-switching from Section 2.6 to reduce to the relation*RC′,C* zk*,*sl *′*. As before, the queries by the verifier in the code- switching sub-protocol are made to the “virtual” oracle in the output of the sumcheck IOR, and are simulated by queries to the initial interleaved codeword (this dominates the verifier’s runtime).

**HVZK polylogarithmic-verifier protocol.**To achieve much improved verifier complexity we

||n|k||
|---|---|---|---|
|i+1 C ,C ,sl|i|C|,C ,sl|

fix a folding parameter*k∈*Nand a sequence of codes*C₁,...,C*, selected so that the2 interleaving of*C* has the same message size as (the non-interleaved)*C*. The input relation is*R≡*2*k*, 1 zk which we apply Construction 2.10 and Construction 2.15 (i.e. Theorem 2) to reduce to an instance of*R≡*2*k*. The size of the problem has been reduced by a factor of2 *k*, and we iterate this process 2 zk multiple times, concluding with the same variant of Section 2.2 used in the proof of Theorem 1. Similar to [ACFY24; ACFY25; NA25; BFRW25], the theorem is then instantiated with codes whose distances increase progressively across the reduction, which yields improved query complexity (an example instantiation yielding Corollary 3 follows). We give a generic formulation of the theorem, for any sequence of codes*C₁,...,C*nsatisfying the conditions previously specified.

**Theorem 4**(informal, polylogarithmic HVZK)**.***LetC₁ ⊆*Σ *mC* 1*,...,C*n*⊆*Σ*mC*n*be*F*-additive codes,* *and fix a folding parameterk∈*N*such that for eachi∈*[n]*,Cihas atCi-query zero-knowledge* *encoding*Enc*Ci*:F *ℓ* *Ci* *×*F *r* *Ci* *→*Σ *mCi* *with errorζCiand encoding timeτCi. For eachi∈*[n*−*1]*, let* *ℓ* *C* *i* := 2 *k* *·ℓCi*+1*. For a security parameterλ∈*N*, proximity parametersδ₁,...,δ*n*∈*(0*,*1)*, letting* *t* *i*=*O*(*−*log(1 <u>λ</u> *−δ*) )*, we construct aO*(*k·*n)*-round IOPP forR* lin *≡*2*k* *, with the following features.* *iC* 1*,T*

(∑)
∑ •*The prover sendsOi∈*[2*,*n]*mCi*+ *O* ˜(n *·k·λ*)*alphabet symbols, and the verifier makesi∈*[n]*ti* 2 *k* *queries over alphabet*Σ(*.* ) *k* ∑ ∑ **P** ˜(n •*The prover time isO T*+ 2 *·ℓC*1+*i∈*[2*,*n]*τCi*+*i∈*[2*,*n]t*Ci−* 1 + *O ·k·λ*)*and the verifier* ( ∑

())
*time isO T* (*k·*n) +*mC*n+*i∈*[n]2 *k* *·ti*+t **V** *Ci*+ *O* ˜(n *·k·λ*)*.*

•*The protocol has round-by-round knowledge soundness error at most*2 *−λ* *assuming that, for every* *i∈*[n]*,*F*is large enough with respect toCi’s mutual correlated agreement radius and list-size at* *distanceδi.* ∑ *k* •*If, fori∈*[2*,*n]*,tCi≥ti, the protocol is honest-verifier zero-knowledge with errori∈*[2*,*n]2 *·ζCi.*

To achieve the parameters of Corollary 3, we consider an instantiation of Theorem 4 with Reed– Solomon codes, resembling [ACFY25]. Fix an initial message size*ℓ∈*Nand an initial evaluation domain of size*m∈*N, set*k* :=*O*(log log*ℓ*)andn :=*O*(log*ℓ/*log log*ℓ*).

||i||C|
|---|---|---|---|
|C ℓ|r m|||
||k C|C k|C|

•For*i∈*[n], let*C* be a Reed–Solomon code with evaluation domain size*mi*:= 2 *−i* *·m*and let Enc*i*:F *Ci* *×*F *Ci* *→*F *Ci* be the corresponding*rCi*-query zero-knowledge encoding. •Enforce that*ℓ*= 2 *·ℓ*1and, for every*i∈*[n*−*1], enforce that*ℓi*= 2 *·ℓi*+1.

The rest of Corollary 3 follows by accounting, and noticing that if*C*is the Reed–Solomon code encoding messages of size*ℓ*with randomness size*r*into codewords of size*m*,t **P** *C*=*O*(*ℓ*+*r*)and t **V** *C*=*O*(log*m*+*r*). (Both are implicit in [ACFY25; NA25] and made explicit in [BFRW25].) **A zero-knowledge reduction from R1CS to proximity-testing.**We additionally provide a (1+*o*(1))-overhead reduction from R1CS to*RC,C* zk*,*sl (in particular,*C*can be an interleaved code, for use with our testing protocols). Using our masking technique as in Section 2.5, we achieve sublinear zero-knowledge overhead in the encoded codeword, whereas [BCL22] obtains overhead*O*(1)due to

full masking. We note that since, for simplicity, we do not employ a holographic/pre-processing step (as done in [BCL22; RW24]) the verifier in this protocol is non-succinct. On a high level, our R1CS reduction is similar to the construction in [ACFY25] (generalized to work with interleaved codes). To add zero-knowledge, instead of padding the R1CS instance with randomness (as done in [BCL22]), we use a similar masking technique to mask the matrix-vector multiplications for each of the R1CS matrices. Then, the reduction uses sumcheck as its main building block, but now with two types of sublinear masks: the first are masks “protecting” the R1CS witness, and the second are the sumcheck masks as in Section 2.4. We can propagate the constraints for both mask types (which are syntactically the same) into an instance of the relation *RC,C* zk*,*sl (which our protocols can test in zero knowledge).

### 2.8 Bonus: distance-amplified codes

The HVZK protocols in this work are*code-agnostic*: they can be instantiated with anyF-additive zero-knowledge code. The concrete efficiency of our protocols, like that of other recent code-agnostic IOPs/IORs based on interleaving, depends on the code’s parameters; for example, the*encoding time* impacts the IOP prover time, the*distance*impacts the query complexity of the IOP verifier, and the*alphabet size*impacts how many bits each query reads. In this section, we propose**distance** **amplification via dispersers**(i.e., the ABNNR construction [ABNNR92]) as a way to achieve concrete improvements in the prover time and argument size for the resulting succinct arguments. This provides further opportunities for optimizations of zero-knowledge succinct arguments based on our techniques.

**The code-design tension.**In typical IOPs, a larger code distance enables fewer verifier queries for a fixed soundness target, which reduces the number of Merkle commitment openings in the resulting succinct argument. At the same time, the argument prover must (i)*encode*to obtain a codeword and (ii)*commit*to the codeword via a Merkle commitment; so it is desirable for the code to have a fast encoding and a small alphabet. Ideally, one would like a*linear-time encodable*code that is also*nearly MDS*(approaching the Singleton bound) over a small alphabet. Unfortunately, known families with near-MDS distance and linear-time encoding [GI05] are not known to be competitive in the parameter regimes relevant for implementations, whereas Reed–Solomon codes are MDS (meet the Singleton bound) but they have quasilinear-time encoding (via FFT-style multipoint evaluation) and their alphabet grows with block length.

**ABNNR distance–amplification.**High-distance linear-time encodable codes rely on distance amplification, and here we discuss one such procedure from [ABNNR92]. A bipartite graph*G*= (*L∪R,E*)with*|L|*=*|R|*=*m*is a(*ϵ,γ*)*-disperser*if every left set*S⊆L*with*|S|≥ϵ*has neighbors *N*(*S*) :=*{j∈R*:*∃i∈S*with(*i,j*)*∈E}*covering at least a(1*−γ*)-fraction of the right set*R*, and also (within this paper)*G*is right-regular of some degree*d*. Given a base code*C⊆*F *m* with distance *δ*(*C*)*≥*1*−ε*, the ABNNR amplification map*AG*:F *m* *→*(F *d* ) *m* is defined by fixing, for each right vertex*j∈R*, an arbitrary ordering of its left neighbors*N*(*j*) =*{i₁,...,id}*and setting(*AG*(*c*))*j*:= (*ci*1*,...,ci* *d* )*∈*F *d*. This leads to a new code*G*(*C*) :=*{AG*(*c*) : *c∈ C} ⊆*(F *d* ) *m* with distance *δ*(*G*(*C*))*≥*1*−γ*. In the parameters achieved by probabilistic constructions, with all but negligible probability, a random right-regular*G*of degree*d*=*O*(1*/γ*)is such a disperser; the transformation then increases any constant base code distance1*−ε*to distance1*−γ*while keeping blocklength *|R|*=*m*and incurring an alphabet blow-up fromFtoF *O*(1*/γ*). Explicit constructions of dispersers with these parameters achieve only a larger degree*d*= poly(1*/γ*)*·*poly(log*m*)[GUV09; TUZ07],

and reducing the gap between explicit and probabilistic constructions can further accentuate the efficiency benefits that we discuss below.

**Efficiency benefits.**We illustrate the efficiency benefits of distance amplification via the features of recent IOP-based succinct arguments [ACFY24; ACFY25; BCFW25], where the dominant error term in the soundness error is*≈*(1*−δ*) *t* where*δ*is the distance of the code and*t*is the number of spot checks by the verifier. In such protocols, the prover encodes a message via the given code and then commits to the resulting codeword via a Merkle commitment, and then (in a later round) sends the requested*t*random locations of the codeword along with the corresponding Merkle openings. We consider two efficiency metrics in this setting: encoding time and argument size.

•**Improved encoding time via amplified Reed–Solomon.**We instantiate the distance amplification transformation with a Reed–Solomon code as the base code, yielding an*amplified* *Reed–Solomon code*(ARS code). Fix a constant*c >*1and encode a message of length*ℓ*as a Reed–Solomon codeword on an evaluation domain of size*m*=*⌈cℓ⌉*, achieving a relative distance *≈*1*−* <u>1</u> *c*; then amplify to a target distance1*−γ*using a disperser. (See Definition 12.5.)

The encoding procedure in an ARS code separates the*expensive*FFT-based evaluation step per- formed at sizeΘ(*ℓ*)and the*fast*distance-boosting step performed by simply gathering neighbors; this yields an improved encoding time precisely in the regime where plain RS would require eval- uation atΘ(*ℓ/γ*)points. Overall, encoding for plain RS takes time*O*( *γ* <u>ℓ</u> *·*log *γ* <u>ℓ</u> )while encoding for ARS takes the (improved) time*O*( *γ* <u>ℓ</u> +*ℓ·*log*ℓ*).

While improving encoding time, using ARS*increases*argument size. The number of spot checks by the verifier depends on the code’s distance alone and each is answered via the requested symbol plus the corresponding Merkle opening. Plain RS and ARS with the same distance yield the same number of spot checks but have different argument sizes: for plain RS the requested symbol is one field element and for ARS the requested symbol is*d*=*O*(1*/γ*)field elements.

•**Reducing argument size (with an increase in prover time).**Increasing distance by amplification reduces the number of spot checks for a fixed soundness target while increasing alphabet size, as each opened leaf now contains*d*field symbols. This leads to a parameter regime in which one benefits from the reduction in the number of queries, while the cost of the increase in the alphabet size is not too big. Under reasonable parameters, which we give in Section 12, one can obtain an improvement of*≈*30%in argument size.

This comes at a cost: the prover has to perform an additional distance amplification, making *O*(1*/γ*)copies of each symbol in the original codeword, increasing its runtime.

**Compatibility with our protocols.**While the amplified symbols have large alphabetF *d*, the resulting code remainsF-additive (by viewing each alphabet symbol as a*d*-tuple overF). Moreover, if a base code admits a*t*-query zero-knowledge encoding, then placing*d*base symbols per amplified symbol yields a corresponding encoding for the amplified code that is(*t/d*)-query zero-knowledge. Thus, amplified codes can be used in all of our main theorems.

## 3 Preliminaries

We define objects and state results that we use in this paper. We use the following notation.

•For two functions*f,g*: [*m*]*→*Σand a set*S⊆*[*m*], we write*f*(*S*) =*g*(*S*)to mean*f*(*x*) =*g*(*x*) for every*x∈S*. Conversely,*f*(*S*)*̸*=*g*(*S*)means there exists*x∈S*with*f*(*x*)*̸*=*g*(*x*). •For two functions*f,g*: [*m*]*→*Σ,∆(*f,g*)is the fractional Hamming distance between*f*and*g* (the fraction of points in which they disagree). For a set*S⊆*Σ [*m*] ,∆(*f,S*) := min*h∈S*∆(*f,h*) (or if*S*is empty,∆(*f,S*) := 1). ∏ *n* •The equality polynomialeqfor*n*variables iseq(**X***,***Y**) :=*i*=1(X*i·*Y*i*+ (1*−*X*i*)*·*(1*−*Y*i*)). •F *<d*
[X₁*,...,*X*n*]is the ring of polynomials overFwith variablesX₁*,...,*X*n*of total degree*< d*.

ˆ*<*2 *n* **Claim 3.1.***For every f∈*F*n **b**∈{*0*,*1*}n*

|[X₁,...,X|]andτ∈F|, fˆ(τ) = ∑||fˆ(b)·eq(τ,b).|||
|---|---|---|---|---|---|---|
|ℓ|ℓ ρ←D|<d|n τ←F t||t×ℓ|n·(d−1) |F||

*n* **Lemma 3.2.***For every non-zero polynomial*ˆ*∈p* F [X₁*,...,*X]*,*Pr [ˆ(*p **τ***) = 0]*≤.*

**Definition 3.3.***A***zero-evader***over*F*with errorε*zero*is a function*ze: *D*ze*→*F *such that* [] *∀**v**∈*F *\{*0*},*Pr ze(*ρ*)*·**v***= 0 *≤ε*zero*.* ze

**Relations.**A*relationR*consists of triples(**x***,***y***,***w**)where**x**is the explicit instance,**y**the implicit instance, and**w**the witness. The corresponding language is*L*(*R*) :=*{*(**x***,***y**) :*∃***w***,*(**x***,***y***,***w**)*∈R}*.

### 3.1 Interactive oracle reductions

*Interactive Oracle Reductions*(IORs) [BCGGRS19; BMNW25] are a generalization of Interactive Oracle Proofs (IOPs) [BCS16; RRR16]. Below we describe the flavor of IOR relevant to this paper. A public-coin IOR of proximity from relation*R*to relation*R* *′* is a tupleIOR= (**P***,***V**)that works as follows. The prover**P**is an interactive algorithm that receives as input(**x***,***y***,***w**)*∈ R*, and the verifier**V**is an interactive oracle algorithm that receives input**x**and query access to**y** (consisting ofl₀ symbols over some alphabetΣ₀). They interact overkrounds: in each round*i∈*[k], **P**sends a proof stringΠ*i i i*, and**V**sends a uniformly

||consisting ofl|symbols over some alphabetΣ|||
|---|---|---|---|---|
|i|r|||k|
|||||′|
|′||′|′ ′ ′|k|

random message*ρi∈ {*0*,*1*}* r *i*. Afterkrounds of interaction,**V**makes queries to**y***,*Π₁*,...,*Πk (each query to a symbol). After that: (i)**V**either rejects or outputs a new explicit instance**x** and implicit instance**y** (which is implicitly specified in terms of the oracles**y**andΠ₁*,...,*Π), and (ii)**P**outputs a new witness**w** such that(**x***,***y***,***w**)*∈ R* *′*. We write*⟨***P***,***V***⟩*(**x***,***y***,***w**)for the interaction of**P***,***V**above.

**Definition 3.4.**IOR= (**P***,***V**)*has***(perfect) completeness***if, for every*(**x***,***y***,***w**)*∈R,* [ ∣] *′ ′ ′ ′*∣*′ ′ ′* Pr (**x***,***y***,***w**)*∈R* ∣ (**x***,***y***,***w**)*←⟨***P***,***V***⟩*(**x***,***y***,***w**) = 1*.*

**Efficiency measures.**Efficiency measures are implicitly functions of**V**’s inputs.

•*Rounds:* there arekrounds of interaction (a round is a prover message and verifier message). •*Prover communication:* for each*i∈*[k],Π*i*consists ofl*i*symbols over alphabetΣ*i*; in this paper the alphabetsΣ₁*,...,*ΣkareF-additive spaces, so we simply count the total number of elements ofFinΠ₁*,...,*Πk, and we refer to this quantity as*prover communication*.

•*Input queries:* q**y**is the number of alphabet symbols read by the verifier from**y**. •*Proof queries:* qΠis the number of alphabet symbols read by the verifier fromΠ₁*,...,*Πk. •*Input query blowup:m***y***′ →***y**is the number of queries that a query to**y** *′* induces to**y**. •*Proof query blowup:m***y***′ →*Πis the number of queries that a query to**y** *′* induces toΠ₁*,...,*Πk. ∑ •*Randomness:* r :=*i∈*[k]r*i*is the total number of random bits sent by the verifier. •*Prover time:* ptis**P**’ time measured in algebraic field operations. •*Verifier time:* vtis**V**’s time measured in algebraic field operations.

**Remark 3.5.**An IOP for a relation*R*is an IOR from the relation*R*to the trivial relation *R*triv:=*{*(**x**=*⊥,***y**=*⊥,***w**=*⊥*)*}*.

The IORs that we consider in this paper satisfy a strong notion of knowledge soundness, namely round-by-round knowledge soundness [BCFW25], extended to handle relaxed relations.

**Definition 3.6.***Let*IOR= (**P***,***V**)*be an IOR from a relationRtoR* *′* *. A***knowledge state** **function with relaxation**(*R*˜*, R*˜ *′* )*for*IOR*is a (possibly inefficient) function*KState*that, on* *input a statement*(**x***,***y**)*, interaction transcript*tr*, and***knowledge state witness**w*, outputs a bit* *and has the following properties.*

•*Empty transcript: if*tr=*∅is the empty transcript, then*KState(**x***,***y***,*tr*,*w) = 1*if and only* (**x***,***y***,*w)*∈ R*˜*.*

•*Prover moves: if*tr*is a transcript where the prover is about to move and*KState(**x***,***y***,*tr*,*w) = 0*,* *then*KState(**x***,***y***,*tr*∥*Π*,*w) = 0*for every prover message*Π*.*

•*Full transcript: if*tr= (Π₁*,ρ₁,...,*Πk*,ρ*k)*is a full transcript, then*KState(**x***,***y***,*tr*,*w) = 1*if and*

||y,Π ,...,Π||k|′ ′||′ ′|′|
|---|---|---|---|---|---|---|---|
||||′||′ k|||
|||||||′||
|rbr i||ρ|i−1 i−1 i∈[k]|i rbr i i|i||i|

*only if***V** **y***,*Π1*,...,*Πk (**x***,ρ₁,...,ρ*k)*outputs*(**x** *′* *,***y** *′* )*such that*(**x** *′* *,***y** *′* *,*w)*∈ R*˜ *′* *.*

**Definition 3.7.**IOR= (**P***,***V**)*from a relationRtoR has***round-by-round knowledge sound-**
**ness with relaxation**(*R*˜*, R*˜)**, errors**(*ε₁,...,ε*)**, and extraction times**(et₁*,...,*etk)*if there*
*exist a knowledge state function*KState*with relaxation R*˜*to R*˜ *for*IOR*and a deterministic extrac-* *tor***E** *with the following property: for every statement*(**x***,***y**)*, round indexi∈*[k]*, and interaction* *transcript*tr= (Π₁*,ρ₁,...,*Π*,ρ,*Π)*where the verifier is about to move,***E**rbr*runs in time at* *most*et *and* [] () KState **x***,***y***,*tr*,***E** (**x***,***y***,*tr*∥ρ,*w) = 0 Pr *∃*w: *≤ε* (**x***,***y**)*.* *i ∧*KState(**x***,***y***,*tr*∥ρ,*w) = 1 ∑ *The***total extraction time***is* et*.*

### 3.2 Coding theory

We provide definitions for (error-correcting) codes and associated notions.

**Definition 3.8.***Let*F*be a finite field. A***code***C***over an alphabet**Σ**with message size***ℓ* **and block length***mis an injective mapC*:F *ℓ* *→*Σ *m* *. The***minimum distance of***Cis*

*δ*(*C*) := min ∆(*f,g*)*.* *f,g∈C* *f̸*=*g*

*We say thatCis*F**-additive***if*Σ =F *ι* *, where*F*is a finite field, andCis a linear subspace of*F *ι·m* *.* *Whenι*= 1*we say thatCis*F**-linear***(or just linear when*F*is clear from context).*

We sometimes highlight the alphabet structureΣ =F *ι* when we explicitly think of an alphabet symbol as a vector of field elements. We often identify a code with its image*C*(F *ℓ* )*⊆*Σ *m*. We consider several algorithmic measures associated to a code*C*:

•tenc(*C*)is the number of field operations required to encode a message*x∈*F *ℓ* into its corre- sponding codeword*u* :=*C*(*x*); •tcor(*C*)is the number of field operations required to*erasure correct*a codeword (Definition 3.9); every linear code has efficient erasure correction (Lemma 3.10, see [GRS12]).

**Definition 3.9.***A codeC ⊆*Σ *m* *has***erasure correction with time**tcor(*C*)*if there exists a* *deterministic algorithm***E***Cthat on inputf∈*Σ *m* *andS⊆*[*m*]*: (i) if|S|≥*(1*−δ*(*C*))*·mand there* *exists a codewordu∈Csuch thatf*(*i*) =*u*(*i*)*for alli∈S, then***E***C*(*f,S*) =*u(the codeworduis* *unique); and (ii) otherwise,***E***C*(*f,S*) =*⊥. Moreover,***E***Cperforms at most*tcor(*C*)*field operations.*

**Lemma 3.10.***Every additive codeC⊆*Σ *m* *has erasure correction with time*tcor(*C*) =*O*((*ι·m*) 3 )

**Interleaving.**An interleaved code is obtained by “stacking” a code’s codewords.

**Definition 3.11.***LetC ⊆*Σ *m* *be a code and letK∈*N*. TheK***-interleaved code***C* *≡K* *is the* *code over alphabet*Σ *K* *with block lengthmdefined as*

|≡K||K m||
|---|---|---|---|
|≡K ≡K|||K|

### C :={(u₁,...,uK)|∀i∈[K] : ui∈C}⊆(Σ).

*A codewordu∈C consists ofK·msymbols in*Σ*viewed asmsymbols in*Σ*.*

If*C*isF-additive then*C* isF-additive. **Lists.**We recall the combinatorial list-decoding of a code.

**Definition 3.12.***LetC⊆*Σ *m* *be a code. The***list around***f∈*Σ *m* **at distance***δ∈*[0*,*1]*is*

### Λ(C,f,δ) :={g∈C|∆(f,g)≤δ}.

### Moreover we define|Λ(C,δ)| := maxf∈Σm |Λ(C,f,δ)|.

For every*K∈*Nand*δ∈*(0*,*1)it holds that*|*Λ(*C,δ*)*|≤|*Λ(*C* *≡K* *,δ*)*|≤|*Λ(*C,δ*)*|* *K*. In fact the list size of an interleaved code at some distance is larger than the list size of the base code by a factor*independent of the interleaving factorK*(but which depends on the distance*δ*considered). ⌈ ⌉ **Lemma 3.13**([GGR11])**.***LetC ⊆*Σ *m* *be a code and letδ∈*[0*,δ*(*C*))*. Letb* := *δ*(*C* <u>δ</u> )*−δ* *and*

|⌉||( )|
|---|---|---|
|)|≡K|b+|
|δ(δC()C−δ||r r|

⌈ := <u>)</u> *≡K b*+ *r* *r* log*. For everyK≥*1*,|*Λ(*C,δ*)*|≤ ·|*Λ(*C,δ*)*|.*

**MCA.**We recall the notion of mutual correlated agreement [ACFY25]. WhenΣis anF-additive alphabet, scalar multiplication and sums in the definition below are interpreted componentwise in the fixedF-vector-space structure ofΣ.

**Definition 3.14.***LetC ⊆*Σ *m* *be an*F*-additive code. The***mutual correlated agreement** **(MCA)***error of a function*PG: *D→*F *n* *forCat distanceδ∈*[0*,*1]*is*   *|S|≥*(1*−δ*)*·m*  ∑ 

|max|Pr|γ ·f (S) =u(S)|
|---|---|---|
|f ,...,f ∈Σ|α←D γ:=PG(α)|i i i i|

*ϵ* mca(*C,δ*) := *m* *∃S⊆*[*m*] : *∃u∈C*:  1 *n* *∃i∈*[*n*]*,∀u∈C*: *f* (*S*)*̸*=*u*(*S*)

Upper bounds on*ϵ*mca(*C,δ*)are known for everyF-additive code (see e.g. [AHIV17; BCIKS20; ACFY25; Zei24; GKL24; BCGM25]). In this work we only consider functionsPG:F*→*F² where *γ7→*(1*−γ,γ*)or*γ7→*(1*,γ*); these two have the same error, as can be seen by considering the identity(1*−γ*)*·f₁* +*γ·f₂* =*f₁* +*γ·*(*f₂ −f₁*).

**Lemma 3.15.***LetC⊆*Σ *m* *≡*(F *ι* ) *m* *be an*F*-additive code and let*PG: *D→*F *n* *have MCA error* *ϵ* mca*. For everyK∈*N*,ϵ*mca(*C* *≡K* *,δ*)*≤K·ϵ*mca(*C,δ*)*.*

*Proof.*For*f∈*(Σ *K* ) *m* and*j∈*[*K*], we denote by*f*[*j*]*∈*Σ *m* the*j*-th row of*f*. We write

*ϵ* mca(*C* *≡K* *,δ*)   *|S|≥*(1*−δ*)*·m* *≡K*∑ 

|= max|Pr|γ ·f (S) =u(S)|
|---|---|---|
|||i i i|
|f ,...,f ∈(Σ|) γ:=PG(n;α) α←D|≡K i|

*∃S⊆*[*m*] : *∃u∈C* :  1 *n* *K m* *∃i∈*[*n*]*,∀u∈C* : *f* (*S*)*̸*=*u*(*S*)   *|S|≥*(1*−δ*)*·m*  ∑ 

|= max|Pr|γ ·f [j](S) =u|(S)|
|---|---|---|---|
|f ,...,f ∈(Σ|) α←D γ:=PG(n;α)|i i i i|j j|

*∃S⊆*[*m*] : *∃*(*u₁,...,uK*)*∈C,∀j∈*[*K*] :  1 *n* *K m* *∃i∈*[*n*]*,∀*(*u₁,...,uK*)*∈C,∃j∈*[*K*] : *f* [*j*](*S*)*̸*=*u* (*S*)

*≤K·ϵ*mca(*C,δ*)*.*

where the last inequality follows from a union bound over the*K*events.

### 3.2.1 Zero-knowledge codes

**Definition 3.16.***LetC⊆*Σ *m* *be a code. For message lengthℓand randomness lengthr, at***-query** **zero-knowledge encoding for***C***with error***ζCis a function*Enc*C*:F *ℓ* *×*F *r* *→*Σ *m* *such that there* *exists a polynomial-time probabilistic simulator*Sim*Csuch that, for every*msg*∈*F *ℓ* *andS⊆*[*m*] *with|S|≤t, the following two random variables have statistical distance at mostζC:*

•*The random variable*Enc*C*(msg*,**r***)[*S*]*consisting of*Enc*C*(msg*,**r***)*restricted to locations inS,* *where the randomness is over**r**←*F *r* *.*

•*The random variable*Sim*C*(*S*)*, where the randomness is over*Sim*C’s randomness.*

**Definition 3.17.***LetC⊆*(F *ι* ) *m* *be an*F*-additive code with a zero-knowledge encoding* [] Enc*C*:F *ℓ* *×* F *r* *→*(F *ι* ) *m* *. A***generating matrix for**Enc*Cis**G**C*= ***G*** # *C* ***G*** $ *C* *∈*F (*ι·m*)*×ℓ* *×*F (*ι·m*)*×r* *such that*

[] ***f***# $ *∀**f**∈*F

||,∀r∈F|,Enc (f,r) =G||·|=G|·f+G|·r,||
|---|---|---|---|---|---|---|---|---|
||ℓ|r C ι||C|C C||C|C|

***r***

*viewing a vector*F *ι·m* *asmsymbols of*(F)*. Fori∈*[*ι·m*]*,**G*** [*i,·*]*denotes thei-th row of**G**.*

We recall the definition of the Reed–Solomon code and its zero-knowledge encodings, and a linear-time encodable code with a zero-knowledge encoding.

**Definition 3.18.***Let*F*be a finite field,L⊆*F*, andℓ∈*N*. We define* {} RS[F*,L,ℓ*] := *f*: *L→*F:*∃ f*ˆ*∈*F *<ℓ* [X]*s.t.∀x∈L f*ˆ(*x*) =*f*(*x*)*.*

**Proposition 3.19.***For everyt∈*N*,C* :=RS[F*,L,ℓ*]*has at-query zero-knowledge encoding with* *message lengthℓ−t, randomness lengtht, and errorζC*= 0*.*

**Theorem 3.20**([BCL22, Theorem 6], informal)**.***For everyε∈*(0*,*1)*,ℓ,t∈*N*, there exists a* *randomized linear time encoding algorithm that maps messages in*F *ℓ* *to a codeC⊆*F *Oε*(*ℓ*+*t*) *such* *that this encoding ist-query zero-knowledge with errorε.*

### 3.2.2 Interleaving and folding for zero-knowledge encodings

We define interleaving and folding for zero-knowledge codes. These operations are designed to be compatible with the*multilinear polynomials*we use later in the paper.

**Definition 3.21.***For a functionf*:F *n*+*m* *→*F*and**b**∈*F *n* *we writef**b***:F *m* *→*F*asf**b***(*x*) :=*f*(***b**,x*)*.*

**Definition 3.22.***LetC⊆*Σ *m* *be a code with a zero-knowledge encoding*Enc*C*:F *ℓ* *×*F *r* *→*Σ *m* *. For a* *k* 2*kℓ* 2*kr* *folding parameterk∈*N*, the*2**-interleaved zero-knowledge encoding**Enc *C* *≡*2*k* :F *×*F *→* 2 *km* 2*kℓ* 2*kr k*

(Σ) *is defined as follows. We split a message**f**∈*F *and randomness**r**∈*F *into*2 *pieces* (***fb***)***b**∈{*0*,*1*}k and*(***rb***)***b**∈{*0*,*1*}k by viewing both as multilinear polynomials **f***ˆ*∈*F
*<*2 [X₁*,...,*X*k*+log*ℓ*]*and* ***r***ˆ*∈*F *<*2 [X₁*,...,*X*k*+log*r*]*and writing* ∑ ***f*** ˆ(X₁*,...,*X
*k*+log*ℓ*) = eq(***b**,*(X₁*,...,*X*k*))*·**fb***(X*k*+1*,...,*X*k*+log*ℓ*)*,*
***b**∈{*0*,*1*}k* ∑
***r***ˆ(X₁*,...,*X*k*+log*r*) = eq(***b**,*(X₁*,...,*X*k*))*·**rb***(X*k*+1*,...,*X*k*+log*r*)*.*
***b**∈{*0*,*1*}k*

*Then we define* () 2 *km* Enc *C* *≡*2*k* (***f**,**r***) := Enc*C*(***fb**,**rb***)***b**∈{*0*,*1*}k∈*(Σ)*.*

**Claim 3.23.***LetC ⊆*Σ *m* *be a code and let*Enc*C*:F *ℓ* *×*F *r* *→*Σ *m* *be at-query zero-knowledge* 2 *k* *·ℓ* 2*k·r* 2*km* *encoding forC. For everyk∈*N*,*Enc *C* *≡*2*k* :F *×*F *→*(Σ) *from Definition 3.22 is at-query* *≡*2*k*2*km k* *zero-knowledge encoding forC ⊆*(Σ) *with error*2 *·ζ.*

*Proof.*LetSim*C*be the simulator forEnc*C*. We define a simulatorSim *C* *≡*2*k* forEnc*C≡*2*k*. For a query set*S*, let*S**b***be the projection of queries in*S*of the block***b**∈{*0*,*1*}* *k*. We defineSim *C* *≡*2*k* (*S*) := *{*Sim*C*(*S**b***)*}**b**∈{*0*,*1*}k*. Let*S*be any query set where*|S| ≤t*, which implies*|S**b**| ≤t*for every***b***. For every message***f***and randomness***r***,Enc *C* *≡*2*k* (***f**,**r***)[*S*] =*{*Enc*C*(***fb**,**rb***)[*S**b***]*}**b**∈{*0*,*1*}k*. For each ***b**∈{*0*,*1*}* *k*, by the zero-knowledge property of ( Enc*C*,*δ*(Enc )*C* (***fb**,**rb***)[*S**b***]*,*Sim*C*(*S**b***))*≤ζ*. By union *k* ∑ *k* bound over all2 blocks,∆ Enc *C* *≡*2*k* (***f**,**r***)[*S*]*,*Sim*C≡*2*k* (*S*) *≤**b**∈{*0*,*1*}k ζ*= 2 *·ζ*.

2 *km* **Definition 3.24.***Let*Σ*be*F*-additive, and letf∈*(Σ)*. Fori∈*[*k*]*, the***interleaved fold** *i* 2*k−im k ∼* *offat**γ**∈*F *is the function*Fold(*f,**γ***)*∈*(Σ) *defined as follows. We identify{*0*,*1*}* = *i k−i* () *{*0*,*1*} ×{*0*,*1*}, and for everyz∈*[*m*]*we writef*(*z*) = *f*(***b**,**c***)(*z*) ***b**∈{*0*,*1*}i,**c**∈{*0*,*1*}k−i* *to mean that* 2 *k* *f*(***b**,**c***)(*z*)*∈*Σ*is the*(***b**,**c***)*-th coordinate off*(*z*)*∈*Σ*. Then we define*   ∑ *∀z∈*[*m*]*,*Fold(*f,**γ***)(*z*) :=  eq(***b**,**γ***)*·f*(***b**,**c***)(*z*) ***b**∈{*0*,*1*}i* ***c**∈{*0*,*1*}k−i*

*where the product*eq(***b**,**γ***)*·f*(***b**,**c***)(*z*)*and the sum are computed after identifying*Σ*with*F *ι* *.*

**Remark 3.25.**LetΣ,*f*,*i*be as in Definition 3.24. The interleaved fold of*f*is well-defined when ***γ**∈*F *i* is replaced with indeterminates(**X₁***,...,***X***i*). Indeed, for every*z∈*[*m*],   ∑*k−i*
Fold(*f,*(**X₁***,...,***X***i*))(*z*) :=  eq(***b**,***X₁***,...,***X***i*)*·f*(***b**,**c***)(*z*) *∈*(Σ
*<*2 [**X₁***,...,***X***i*]) 2 *.* ***b**∈{*0*,*1*}i* ***c**∈{*0*,*1*}k−i*

|||m|ι m||||||C|ℓ|
|---|---|---|---|---|---|---|---|---|---|---|
|r|m||C|||||2 ℓ|2 r||
||j|k|C j|k−j|C||||||
|||C||C (b,c)|(b,c)|(b,c)∈{0,1}|C ×{0,1}||||

**Lemma 3.26.***LetC⊆*Σ *≡*(F) *be an*F*-additive code with a zero-knowledge encoding*Enc :F *×* *k k* F *→*Σ *and generating matrix**G** (as in Definition 3.17). For every**f**∈*F*,**r**∈*F*,j∈*[*k*]*,* *and**γ**∈*F*,* () Fold Enc*≡*2*k* (***f**,**r***)*,**γ*** =Enc*≡*2*k−j* (Fold(***f**,**γ***)*,*Fold(***r**,**γ***))*.*

*Proof.*Identify*{*0*,*1*}* *∼* = *{*0*,*1*} ×{*0*,*1*}*. By the definition ofEnc*≡*2*k* (Definition 3.22),

() Enc*≡*2*k* (***f**,**r***) = Enc (***f**,**r***)*j k−j.*

By the definition ofFoldoverΣ(Definition 3.24) and the above equality,   () ∑ Fold Enc *C* *≡*2*k* (***f**,**r***)*,**γ*** =  eq(***b**,**γ***)*·*Enc*C*(***f***(***b**,**c***)*,**r***(***b**,**c***))*.* ***b**∈{*0*,*1*}j* ***c**∈{*0*,*1*}k−j*

Using Definition 3.17 for each summand, for every***b**∈{*0*,*1*}* *j* and***c**∈{*0*,*1*}* *k−j*, [] ***f***(***b**,**c***) # $

|Enc (f ,r|·|·f|+G ·r.|
|---|---|---|---|
|C (b,c)|C|C (b,c)|C (b,c)|
||(b,c)|||

*C* (***b**,**c***) (***b**,**c***)) =***G**C*=***G**C* (***b**,**c***) *C* (***b**,**c***) ***r***(***b**,**c***)

Therefore,   ∑

||eq(b,γ)·Enc|(f ,r|)|||
|---|---|---|---|---|---|
|b∈{0,1}|||c∈{0,1}|||
|C|b∈{0,1}|(b,c)|c∈{0,1}|C b∈{0,1}|(b,c) c∈{0,1}|

*C* (***b**,**c***) (***b**,**c***) ***b**∈{*0*,*1*}j* ***c**∈{*0*,*1*}k−j*     # ∑ ∑ =***G** ·*  eq(***b**,**γ***)*·**f***  +***G*** $ *·*  eq(***b**,**γ***)*·**r***  *j* *k−j* *j* *k−j* (by linearity)

=***G*** # *C* *·*Fold(***f**,**γ***) +***G*** $ *C·*Fold(***r**,**γ***)(by definition of FoldoverF) =Enc *C* *≡*2*k−j* (Fold(***f**,**γ***)*,*Fold(***r**,**γ***))*.*

## 4 Zero-knowledge for IORs and composition

**Definition 4.1.***Let*IOR= (**P***,***V**)*be an IOR fromRtoR* *′* *and letDbe an algorithm. The* *D***-extended view for**IOR*on input*(**x***,***y***,***w**)*∈Ris the random variable*

### View(P,V,D,x,y,w) = ((ρ₁,...,ρk),(Qy,Q₁,...,Qk),(ay,a₁,...,ak),out)

*obtained by running the experiment* [] (**x** *′* *,***y** *′* *,***w** *′* )*←⟨***P***,***V***⟩*(**x***,***y***,***w**) **y** *′′* out*←D* (**x**)

*where*out*may be any output string ofD, and making the following definitions for everyi∈*[k]*:*

|i|r|||
|---|---|---|---|
|y|y|y|Q|
|i|i|i|Q|

•*ρ ∈{*0*,*1*}iis the verifier randomness in roundi;* •*Q ⊆*[l]*and**a** ∈*Σ**y***are the queries of***V***andDto***y***along with their answers; and* •*Q ⊆*[l]*and**a** ∈*Σ*iare the queries of***V***andDto the proof oracle*Π*isent in roundialong* *with their answers.*

**Definition 4.2.***Let*IOR*be an IOR fromRtoR* *′* *and let*D*be a set of algorithms.*IOR*is***honest-** **verifier zero-knowledge for**D**with error***ζ***and query complexity**b*if and only if there* *exists a polynomial-time probabilistic simulator***S***such that for everyD ∈*D*and*(**x***,***y***,***w**)*∈ R* *the two distributions*View(**P***,***V***,D,***x***,***y***,***w**)*and***S** **y***,D*

(**x**)*have statistical distance at mostζ*(*D*)*, and*
**S** **y***,D*

(**x**)*makes at most*b(*D*)*queries to***y***. We letζ* := max*D∈*D*ζ*(*D*)*and*b := max*D∈*Db(*D*)*.*
**Remark 4.3.**When the IOR is from*R*to the trivial relation*R*triv(i.e., the IOR is an IOP) one can verify that Definition 4.2 coincides with honest-verifier zero-knowledge for the IOP.

**y y***,D* **Definition 4.4.***Given algorithms***S***andD, we letD***S***be the algorithm such thatD* **S**

(**x**) :=**S** (**x**)*.*
*For a set of algorithms*D*we define the***S-wise distinguisher class**D**S**:=*{D***S**: *D∈*D*}.*

**Theorem 4.5.***Let*IOR₁ *be an IOR fromR*start*toR*int*and let*IOR₂ *be an IOR fromR*int*toR*fin*that* *have the following parameters (respectively).* •*Round complexities*k₁ *and*k₂*.* •*Prover communication*l₁ *and*l₂*.* •*Input query complexities*q**y***,*1*and*q**y***,*2*.* •*Proof query complexities*q₁ *and*q₂*.* •*Prover times*pt₁ *and*pt₂*.* •*Verifier times*vt₁ *and*vt₂*.* •IOR₁ *has input query blow upm***y***′ →***y***and proof query blowupm***y***′ →*Π*.* *Construction 4.6 is an IOR*IOR*fromR*start*toR*fin*with the following parameters.* •*Round complexity*k₁ +k₂*.* •*Prover communication*l₁ +l₂*.* •*Input query complexity*q**y***,*1+*m***y***′ →***y***·*q**y***,*2*.* •*Proof query complexity*q₁ +q₂ +*m***y***′ →*Π*·*q**y***,*2*.* •*Prover time*pt₁ +pt₂*.* •*Verifier time*vt₁ +vt₂*.* *Moreover:*

•***RBR security.**If*IOR₁ *has RBR knowledge soundness with relaxation*(*R*˜start*, R*˜int)*and errors*

(1) (1)˜ ˜

|(ε₁ ,...,ε|)andIOR₂|has RBR knowledge soundness with relaxation(R|
|---|---|---|
||k||
||k k|k|

(2) (2)
(1) (1) (2) (2)
 k 1 int
*, R*fin)*and errors* ˜ ˜ (*ε₁,...,ε* 2 )*, then*IOR*has RBR knowledge soundness with relaxation*(*R*start*, R*fin)*and errors*

(*ε₁,...,ε* 1 *,ε₁,...,ε* 2 )*.*

•***Zero-knowledge.**If*IOR₂ *is HVZK for*D*with errorζ₂ via the simulator***S₂***, and*IOR₁ *is* *HVZK for*D**S**2*with errorζ₁ and query complexity*b*, then*IOR*is HVZK for*D*with errorζ₁*+*ζ₂* *and query complexity*b*.*

**Construction 4.6.**The IOR consists of the concatenation ofIOR₁ andIOR₂.

•**Inputs.**The verifier receives as explicit input**x₁** and query access to**y₁**. The honest prover receives as input**w₁** such that(**x₁***,***y₁***,***w₁**)*∈R*start.

•**Protocol.**

1.**First IOR.**The prover and verifier runIOR₁ for(**x₁***,***y₁***,***w₁**). After the interaction, the verifier outputs an explicit instance**x₂** and implicit instance**y₂** (defined via**y₁** and proof oracles sent in the execution ofIOR₁). The honest prover outputs a witness**w₂** such that(**x₂***,***y₂***,***w₂**)*∈R*int.
2.**Second IOR.**The prover and verifier runIOR₂ for(**x₂***,***y₂***,***w₂**). After the interaction, the verifier outputs an explicit instance**x₃** and implicit instance**y₃**. The honest prover outputs a witness**w₃** such that(**x₃***,***y₃***,***w₃**)*∈R*fin.
•**Output.**The verifier outputs explicit instance**x₃** and implicit instance**y₃**. The honest prover outputs a witness**w₃**.

*Proof.*The efficiency parameters follow via inspection and the RBR knowledge soundness errors follow similarly to prior work. Here we focus on establishing HVZK of the composed IOR, demon- strating how to use Definition 4.2. Consider the following simulator.

**S** **y** 1 *,D*2 (**x₁**): **y** 2**y**2*,D*2

1.Define the algorithm*D₁* (**x₂**) :=**S₂** (**x₂**).
**y** 1 *,D*1

2.Run and output**S₁** (**x₁**).
We argue that, for every(**x₁***,***y₁***,***w₁**)*∈ R*startand*D₂ ∈*D, the following two distributions are (*ζ₁* +*ζ₂*)-close in statistical distance:

View(**P***,***V***,D₂,***x₁***,***y₁***,***w₁**)and**S** **y** 1 *,D*2 (**x₁**)*,*

Note thatView(**P***,***V***,D₂,***x₁***,***y₁***,***w₁**)is equivalent to the following experiment.

View(**P***,***V***,D₂,***x₁***,***y₁***,***w₁**): view1

1.Compute(**x₂***,***y₂***,***w₂**) *←−−−⟨***P₁***,***V₁***⟩*(**x₁***,***y₁***,***w₁**)whereview₁ is**V₁**’s view in the interaction.
view2

2.Compute(**x₃***,***y₃***,***w₃**) *←−−−⟨***P₂***,***V₂***⟩*(**x₂***,***y₂***,***w₂**)whereview₂ is**V₂**’s view in the interaction.
**y** 3

3.Computeout₂ *←D₂* (**x₃**).
4.Letviewbe**V**’s view obtained by combiningview₁ andview₂.
5.Output(view*,*out₂).
We rely on a two-step hybrid argument. For that, we define a hybrid simulator **S** ˜.

**S** ˜**y**1*,D*2 (**x₁***,***w₁**): **y** 2**y**2*,D*2

1.Define the algorithm*D₁* (**x₂**) :=**S₂** (**x₂**).
2.Compute and outputView(**P₁***,***V₁***,D₁,***x₁***,***y₁***,***w₁**).
We consider the two steps of the hybrid argument.

•∆(View(**P***,***V***,D₂,***x₁***,***y₁***,***w₁**)*,* **S** ˜**y**1*,D*2 (**x₁***,***w₁**))*≤ζ₂*. ByIOR₂’s HVZK property, since*D₂ ∈*D, **y** 2 *,D*2 the statistical distance ofView(**P₂***,***V₂***,D₂,***x₂***,***y₂***,***w₂**)and**S₂** (**x₂**)is at most*ζ₂*. Moreover, **y** 2 *,D*2 first running*⟨***P₁***,***V₁***⟩*(**x₁***,***y₁***,***w₁**)and then**S₂** (**x₂**)is equivalent toView(**P₁***,***V₁***,D₁,***x₁***,***y₁***,***w₁**), which is the experiment in **S** ˜**y**1*,D*2 (**x₁***,***w₁**).

•∆(**S** ˜**y**1*,D*2 (**x₁***,***w₁**)*,***S** **y** 1 *,D*2 (**x₁**))*≤ζ₁*. Since*D₂ ∈*Dwe know that*D₁ ∈*D**S**2(by definition of*D₁*). **y** 1 *,D*1 ByIOR₁’s HVZK property, the statistical distance ofView(**P₁***,***V₁***,D₁,***x₁***,***y₁***,***w₁**)and**S₁** (**x₁**) is at most*ζ₁*.

We conclude that

∆(View(**P***,***V***,D₂,***x₁***,***y₁***,***w₁**)*,***S** **y** 1 *,D*2 (**x₁**))

*≤*∆(View(**P***,***V***,D₂,***x₁***,***y₁***,***w₁**)*,* **S** ˜**y**1*,D*2 (**x₁***,***w₁**)) + ∆(**S** ˜**y**1*,D*2 (**x₁***,***w₁**)*,***S** **y** 1 *,D*2 (**x₁**))

*≤ζ₁* +*ζ₂.*

The simulator is polynomial-time as a composition of polynomial-time algorithms, and its number of queries to**y₁** is exactly that of**S₁**, i.e., at mostb.

We introduce the class of query-bounded distinguishers, which are distinguishers that make a bounded number of queries to the implicit instance (and are otherwise unbounded). We only consider distinguishers*D*that are*non-adaptive*, i.e.,*D*is specified by a pair(*D₀,D₁*)such that [] **y**(st*,S*)*←D₀*(**x**) *∀***x***,***y**: *D* (**x**) =*.* *D₁*(st*,***y**[*S*])

**Definition 4.7.***Lett∈*N*. We define the class of***query-bounded distinguishers**D *≤t* *as the* *set of algorithms that perform at mostt(non-adaptive) queries to their implicit input.*

**Multiple implicit instances.**Many IORs that we consider in this work have as target relations where the implicit instance can be decomposed in a number of oracles. When considering honest- verifier zero-knowledge against query-bounded adversaries, we writeD *≤t*1 *×···×*D *≤tn* for the class of query-bounded distinguishers that query the*i*-th oracle in the implicit instance at most*ti*times. Alternatively, we let***t***= (*t₁,...,tn*)and writeD *≤**t*** for conciseness. For the notions of honest- verifier zero-knowledge that we consider this suffices and we abuse notation by simulating the view of each distinguisher individually.

## 5 Succinct linear forms

We define a notion of succinct linear forms. These capture the fact that some linear claims can be succinctly described and efficiently computed from such succinct descriptions.

**Definition 5.1.***A***succinct linear form**sl*is a map that takes as input a state*st*and outputs a* *matrix*sl(st)*∈*F *t×n* *; we use the notation*sl*∈⟨*F *t×n* *|to indicate the dimensions of the matrix. We* *writet*sl*for the maximum number (over the choice of*st*) of field operations for computing*sl(st)*.*

We define a few succinct linear form that we use.

**Definition 5.2.***The***identity linear form***is the linear form*slid*∈⟨*F *t×n* *|that takes as input a* *state**V**∈*F *t×n* *and outputs**V**(i.e.,*slid*is the identity map). Note thatt*slid= 0*.*

**Definition 5.3.***Let*ze: *D*ze*→*F *t×n* *be a zero-evader. The*ze**-linear form***is the linear form* slze*∈⟨*F *t×n* *|that takes as input a stateρ∈D*ze*and outputs*ze(*ρ*)*. Note thatt*slze=teval(ze)*.*

Succinct linear forms can be combined and operated on.

**Definition 5.4.***The***scalar multiplied linear form for**sl*∈⟨*F *t×n* *|is the linear form×*(sl)*∈* *⟨*F *t×n* *|mapping*(st*,ε∈*F)*toε·*sl(st)*. Note thatt×*(sl)*≤t*sl+*O*(*t·n*)*.*

**Definition 5.5.***Fork∈*N*, thek***-zero-padded linear form for**sl*∈⟨*F *t×n* *|is the linear form* 0 *k* (sl)*∈⟨*F *t×*(*n*+*k*) *|mapping*st*to*[sl(st)*,*0 *t×k*]*. Note thatt₀k*(sl)*≤t*sl*.*

**Definition 5.6.***Let*sl₁*,...,*sl*k∈⟨*F *t×n* *|and let*ze: *D*ze*→*F *k* *be a zero-evader. The*ze**-batched** *t×n* ∑
**linear form**sl[ze*,*(sl₁*,...,*sl*k*)]*∈⟨*F *|maps*(st₁*,...,*st*k,ρ*)*toi∈*[*k*]ze(*ρ*)*i·*sl*i*(st*i*)*. Note that*
∑ *t* sl[ze*,*(sl1*,...,*sl*k*)]*≤*teval(ze) +*i∈*[*k*]*t*sl*i*+*O*(*k·t·n*)*.*

The most important operation that we apply on succinct linear form is that of “fixing variables”. This operation takes a succinct linear form (say of size2 *n* ) and a vector of field elements***α**∈*F *i*

(where*i≤n*), and outputs a succinct linear form of size2 *n−i*, in a way that is compatible with the folding operation in Definition 3.24.

*t×*2*n* **Definition 5.7.***Leti∈*N*and*sl*∈⟨*F *|. Thei***-fixing linear form associated to**sl*is the* *t×*2*n−ii ′ t×*2*n−i*

||t×2||i|′ t×2|
|---|---|---|---|---|
|′ t×2|t×2 j 2|j′ n−i|j j′ b∈{0,1}|2|
|||||j′|

*linear form⊙i*sl*∈⟨*F *|that maps*(st*,**γ**∈*F)*to**V** ∈*F *defined as follows:* *n*

*1.Let**V***=sl(st)*∈*F*.*
*n n−i*

*2.For each row**v** ∈*F *of**V**, set**v*** :=Fold(***v**,**γ***)*∈*F *as in Definition 3.24 i.e.*
∑ *∀**c**∈{*0*,*1*},**v*** [***c***] := eq(***b**,**γ***)*·**v**j*[***b**,**c***]*.* *i*

*n−i*

*3.let**V** ∈*F *to be the matrix whose rows are**v**.* *Note thatt⊙i*sl*≤t*sl+*O*(*t·n*)*.* The fixing operation is used to reduce the instance size, and we illustrate this via an example. Consider the linear formslzeeqassociated to the zero evaderzeeqmapping***α**7→*(eq(***α**,**b***))***b**∈{*0*,*1*}n*. By [VSBW13],*t*slzeeq=*O*(2
*n* ). Consider now*⊙n*slzeeq, which (by definition) is the map that maps (***α**,**γ***)*7→*eq(***α**,**γ***). Note that*t⊙n*slzeeq*≤n*, which is succinct in the original linear form size.

Following Remark 3.25, the fixing linear form is well-defined when part of the input state consists 2*n* of indeterminates. Forsl*∈⟨*F *|*,   ∑
(*⊙i*sl)(st*,*(**X₁***,...,***X***i*)) =  eq(***b**,***X₁***,...,***X***i*)*·*sl(st)[***b**,**c***];(8)
***b**∈{*0*,*1*}i* ***c**∈{*0*,*1*}n−i*

*t×*2*n* and this extends naturally tosl*∈⟨*F *|*. We introduce the main relation that we use in this work.

**Definition 5.8.***Let:* •*n∈*N*;*

|m||C ℓ|r m||
|---|---|---|---|---|
|m||C|ℓ r|m|
|i i∈[n]|◦,i i∈[n]|ℓ i|ℓ ◦,i|t ×ℓ|

•*C⊆*Σ *with a zero-knowledge encoding*Enc :F *×*F *→*Σ*;* •*C*zk*⊆*Σzk zk*with a zero-knowledge encoding*Enc :Fzk*×*Fzk*→*Σzk zk*;* zk •**sl**= (sl*,*(sl)*,*(sl))*where*sl*∈⟨*F *|,*sl *∈⟨*Fzk*|,*sl *∈⟨*F*i* zk*|.* *Define:*  ∣    ∣∣ *f*=Enc  *C*(***f**,**r***) 

||) ),((µ|,st )|||
|---|---|---|---|---|
||i i∈[n]|i ◦,i i∈[n]|i|C i i|
|C,C ,sl|i i i∈[n]||◦,i ◦,i i∈[n]|i i i i i|

 **x**= ((*µ,*st*,*(st*i i∈*[*n*] *i ◦,i i∈*[*n*]))*,* ∣    ∣ *∀i∈*[*n*] : *ξi*=Enc*C*zk(***ξ**i,**r**i*) *R* := **y**= (*f,*(*ξi*)*i∈*[*n*])*,*  ∣*.* zk  ∣ *∀i∈*[*n*] :sl (st)*·**ξ*** =***µ***   **w**= (***f**,**r**,*(***ξ**,**r***)) ∣ ∑  ∣ *⟨**f**,*sl(st)*⟩*+ *⟨**ξ**,*sl (st)*⟩*=*µ*

*For everyδ,δ*zk*∈*(0*,*1)*we define a corresponding relaxed relation for proximity testing:* { ∣} ˜*δ,δ*zk∣∣ *R* := (**x***,***y***,*(**w***,*¯))**y** ∆(**y***,*¯)**y** *≤*(*δ,δ*zk*,...,δ*zk)*∧*(**x***,*¯*,***y w**)*∈RC,C.* *C,C*zk*,***sl** zk*,***sl**

## 6 Zero-knowledge sumcheck IOR

We formally describe and analyze our zero-knowledge sumcheck IOR. First, we introduce some notation for the univariate evaluation zero-evader.

**Definition 6.1.***Forn∈*N*,*ze *⋆* *n*:F*→*F *n* *is the zero-evader mappingρ7→*(1*,ρ,...,ρ* *n−*1 )*, which* *has error* <u>n</u> *|* <u>−</u> F*|* <u>1</u> *.*

**Theorem 6.2.***Consider the following ingredients:* •*n∈*N*be a number of functions;* •*k∈*N*be a folding parameter;*

|m|||C ℓ|r m|||
|---|---|---|---|---|---|---|
|m|ι m|||C|ℓ|r|
|i i∈[n]|◦,i i∈[n] ′|ℓ i i∈[n] ,C ,sl|i ℓ j∈[k] C,C ,sl|◦,i ◦,i i∈[n]|t ×ℓ|j∈[k]|

•*C⊆*Σ *with a zero-knowledge encoding*Enc :F *×*F *→*Σ*;* zk zk zk zk*m* •*C*zk*⊆*Σzk zk*≡*(F) *with a zero-knowledge encoding*Enc zk :F *×*F *→*Σzk zk*;* •**sl**= (sl*,*(sl)*,*(sl))*where*sl*∈⟨*F *|,*sl *∈⟨*Fzk*|,*sl *∈⟨*F*i* zk*|.* *Define* **sl** := (*×*(*⊙k*sl)*,*(*×*(sl))*,*(slze*⋆* *ℓ* )*,*(sl)*,*(slid))*.* zk *Construction 6.3 is a IOR fromR* *C* *≡*2*k toR*zk *′ with the following properties.* zk •*Round complexity:k*+ 1*.* •*Prover communication (in field elements):k·*(*ℓ*zk+*ι*zk*·m*zk) + 1*. Of these,k·ι*zk*·m*zk*are sent* *as a single oracle message over alphabet*Σ *k* zk*andk·ℓ*zk+ 1*are sent as non-oracle messages.* •*Verifier queries: none (a queryless IOR).* *k* ∑ •*Prover time (in field operations):O*(2 *·ℓ*+*t*sl+*i∈*[*n*]*t*sl *i* +*k·*tenc(*C*zk))*.* •*Verifier time (in field operations):O*(*k·ℓ*zk)*.* •**Round-by-round security:** *For everyδ,δ*zk*∈*(0*,*1)*, Construction 6.3 has RBR knowledge* *δ,δ*zk*δ,δ*zk

|soundness with relaxation(R|˜|˜, R )and errors||||
|---|---|---|---|---|---|
||C ,C ,sl|C,C ,sl||||
|≡2|||≡2|≡n+k||
|||≡2|||j∈[k]|
||j∈[k]|≡2||||
|C|1+n||C|≤(t,t ,...,t|)|

*≡*2*kC,C,***sl***′* *C,C*zk*,***sl** zk  ()  *k≡n*+*kk−*(*j−*1) <u>|Λ(C,δ)|·|Λ(Czk,δzk)|</u> *k−j* <u>ℓzk·|Λ(C,δ)|·|Λ(Czk,δzk)|</u> *, ϵ* mca(*C,δ*) + *.* *|*F*| |*F*|*

∑ *k−j* *The total extraction time isO*( tcor(*C*))*.* •**Zero-knowledge:** *If*char(F)*̸*= 2*,ℓ*zk*≥*2*, and*Enc zk *is at*zk*-query zero-knowledge encoding* *with errorζC* zk *then, for every**t**∈*N*, Construction 6.3 is HVZK for*Dzk zk*with error* *k·ζ* zk *and query complexity**t**.*

### Construction 6.3.

•**Inputs and notation.**The verifier receives explicit input**x**= ((*µ,*st*,*(st*i*)*i∈*[*n*])*,*((***µ**i*)*i∈*[*n*]*,*(st*◦,i*)*i∈*[*n*])) and oracle access to implicit input**y**= (*f,*(*ξi*)*i∈*[*n*]). In the honest case, the prover receives as input**x**and**y**as well as witness**w**= (***f**,**r**,*(***ξ**i,**r**i*)*i∈*[*n*])such that(**x***,***y***,***w**)*∈R* *C* *≡*2*k,C,***sl**. zk

### •Interaction phase.

1.**Sending masks.**The prover sends*s₁,...,sk∈*F
*m*zk. In the honest case the prover samples ***s₁**,...,**s**k∈*F *<ℓ*zk [X],***r₁*** *′* *,...,**r*** *k* *′* *←*F *r* zkand sets*s* *j*:=Enc*C*zk(***s**j,**r**j′*)for each*j∈*[*k*].

2.**New target.**The prover sends˜*µ∈*F. In the honest case the prover sets
∑ ˜*µ* := ***s₁***(*b₁*) +*···*+***s**k*(*bk*)*.* ***b**∈{,}k*

3.**Combination randomness.**The verifier samples and sends*ε←*F.
4.**Sumcheck.**Set***γ*** :=*∅*. For*j∈*[*k*]:

|j|<max{2,ℓ|}||||
|---|---|---|---|---|---|
|(b k−j+logℓ|)∈{0,1}|k−j+logℓ j|j j|k k i∈[n] j|i i i|

(a)The prover sends *h*ˆ *∈*Fzk[X]. In the honest case
∑ *j*+1*,...,bk* ***s₁***(*γ₁*) +*···*+***s*** (X) +*···*+***s*** (*b*) *h* ˆ *j*

(X) :=
( ∑ ) +*ε· ⟨**f***(***γ**,*X*,{*0*,*1*}*)*,⊙j*sl(st*,*(***γ**,*X))*⟩*+ *⟨**ξ**,*sl (st)*⟩*

where***f***(***γ**,*X*,{*0*,*1*}*)denotes the linear polynomial (inX) obtained by performing a partial evaluation of***f***on(***γ**,*X)and(*⊙j*sl)(st*,*(***γ**,*X))is well-defined by Equation 8.

(b)The verifier samples and sends*γ ←*F. Set***γ*** :=***γ**∥γ ∈*F.
### •Decision phase.

1.The verifier checks that *h*ˆ₁(0) + *h*ˆ₁(1) =*ε·µ*+ ˜*µ*.
2.For every*j∈{*2*,...,k}*the verifier checks that *h*ˆ*j*(0) + *h*ˆ*j*(1) = *h*ˆ*j−*1(*γj−*1).
•**Output claims.**The verifier sets new targets and states:

|′|k k|||
|---|---|---|---|
|′|′i ′◦,i ′◦,n+j|i ◦,i|′i ′n+j|

**–***µ* := *h*ˆ (*γ*); **–**st := ((st*,**γ***)*,ε*); **–***∀i∈*[*n*]*,*st := (st*,ε*)and*∀j∈*[*k*]*,*st *′n* +*j* :=*γj*; **–***∀i∈*[*n*]*,*st :=st*,**µ*** :=***µ**i*; **–***∀j∈*[*k*]*,*st :=**0***,**µ*** :=**0**.

The verifier outputs the following new explicit instance and implicit instance and in the honest case the prover outputs the following new witness:

|′|′ ′|′i|′i ′◦,i||
|---|---|---|---|---|
|||i∈[n+k]|i∈[n+k]||
|′||i i∈[n]|j j∈[k]||
|′|||i i i∈[n]|j j′ j∈[k]|

**x** := ((*µ,*st*,*(st))*,*(***µ**,*st))*,*

**y** := (Fold(*f,**γ***)*,*(*ξ*)*,*(*s*))*,*

### w := (Fold(f,γ),Fold(r,γ),(ξ,r),(s,r)).

Completeness of Construction 6.3 follows by completeness of the sumcheck protocol and by Lemma 3.26.

### 6.1 Zero-knowledge

**Lemma 6.4.***If*char(F)*̸*= 2*,ℓ*zk*≥*2*, and*Enc*C* zk *is at*zk*-query zero-knowledge encoding with error* *ζ* *C* zk *then, for every**t**∈*N 1+*n* *, Construction 6.3 is HVZK for*D *≤*(***t**,t*zk*,...,t*zk) *with errork·ζC* zk *and* *query complexity**t**.*

*Proof.*LetSim*C* zk denote the simulator forEnc*C* zk. We define the simulator**S**for the protocol.

**S** **y***,D*

(**x**):

|||j j∈[k]|k||
|---|---|---|---|---|
|j j∈[k]|j|j|<max{2,ℓ j−1|} j−1|
|′|′||j j∈[k]||

1.Sample*ε,*˜*µ←*Fand(*γ*) *←*F
*k*.

2.Sample(*h*ˆ) uniformly fromFzk[X]conditioned on *h*ˆ₁(0) + *h*ˆ₁(1) =*ε·µ*+ ˜*µ*and *∀j∈{*2*,...,k}, h*ˆ (0) + *h*ˆ (1) = *h*ˆ (*γ*).
3.Define**x** and**y** from(**x***,ε,**γ**,*˜*µ,*(*h*ˆ))as in the output-claims phase of Construction 6.3.

4.Since*D*is non-adaptive (see Definition 4.7) there exists(*D₀,D₁*)such that
[] **y** *′′*(st*,Q***y***,*(*Qs* *j* ) *j∈*[*k*])*←D₀*(**x** *′* ) *D* (**x**) =*.* *D₁*(st*,**a*y***,*(***a**sj*)*j∈*[*k*])

5.Answer all queries in*Q***y**by forwarding to**y**(for queries toFold(*f,**γ***)use the folding map), and denote the resulting answers by***a*y** *sjC*

|||. For everyj∈[k], seta||←Sim|(Q ).|
|---|---|---|---|---|---|
|s j∈[k]||y||s|C s|
|y|s j∈[k]||k|y s j∈[k]||
||y C ,C|,sl|y,D|C||

zk*sj*

6.Setout :=*D₁*(st*,**a*y***,*(***a**j*))and output
() (*ε,**γ***)*,*(*Q,*(*Qj*))*,*((˜*µ, h*ˆ₁*,..., h*ˆ)*,**a**,*(***a**j*))*,*out*.*

The simulator queries**y**exactly on*Q*, and by the distinguisher class bound this is at most***t***. We must show that for every(**x***,***y***,***w**)*∈R≡*2*k* and every distinguisher*D*in the stated class, zk () ∆ View(**P***,***V***,D,***x***,***y***,***w**)*,***S** (**x**) *≤k·ζ* zk *.*

We prove this in two parts: first we show that the sumcheck-transcript component has the correct distribution, then we bound the oracle-answer simulation error.

•*Sumcheck transcript.*Fix verifier randomness(*ε,**γ***). Let*T ⊆*F 1+*k·ℓ*zk be the affine subspace of tuples(˜*µ, h*ˆ₁*,..., h*ˆ*k*)satisfying the*k*verifier checks in Construction 6.3 (where we think of each *h*ˆ*j*as a list of*ℓ*zkevaluations). Since each check imposes one independent linear constraint on the polynomial *h*ˆ*j*, the subspace*T*has dimension1 +*k·*(*ℓ*zk*−*1). The simulator samples uniformly from*T*by construction. ( *<ℓ* ) *k* In the honest execution, the masks(***s**j*)*j∈*[*k*]are uniform in Fzk[X]. The honest-prover ( *<ℓ* ) *k* 1+*k·ℓ* formulas in Construction 6.3 define an affine functionA: Fzk[X] *→*Fzkthat maps ( *<ℓ* ) *k*

||)7→(˜µ, h|ˆ₁,..., h|ˆ ). Forz∈|F|[X], letL(z) :=A(z)−A(0)be its linear part, so||||||
|---|---|---|---|---|---|---|---|---|---|---|
||′||′|′|<ℓ|k|j||k|j ′|
|′1 ′k|||′||′||||||
|j k−j|j j|k|j k j <ℓ|j|j|k−j l=1 j|j l|′j k l=1|l||

(***s₁**,...,**s**k k*zk *′ ′ ′* ( *<ℓ* ) *k* thatA(**z**)*−*A(**z**) =L(**z***−***z**)for all**z***,***z** *∈* Fzk[X]. Expanding the sumcheck formula,***s*** is the only mask contributing non-constant (inX) terms to *h*ˆ. Suppose**z** := (***s₁**,...,**s***)*,***z** := (***s**,...,**s***)satisfyA(**z**) =A(**z**), i.e.,**z***−***z** *∈*ker(L). Since the non-constant coefficients of *h* ˆ are2 times those of***s*** andchar(F)*̸*= 2, each difference***s** −**s*** is some constant we ˆ ∑ *k* ∑ *k* denote by*c ∈*F. Such constants shift each *h* by2 *c* and˜*µ*by2 *c*. Therefore ∑ ker(L) =*{*(*c₁,...,c*)*∈*F : *c* = 0*}*(formally,*c* is identified with the constant poly- ()*k* nomialX*7→c*). Sincedim( Fzk[X]) =*k·ℓ*zkanddim ker(L) =*k−*1, rank–nullity gives dim im(L) = 1 +*k·*(*ℓ*zk*−*1) = dim(*T*). Also,im(A) =A(0) + im(L), soim(A)is an affine subspace with the same dimension asim(L). Becauseim(A)*⊆T*and both affine subspaces have dimension1 +*k·*(*ℓ*zk*−*1), we getim(A) =*T*. Fix*t∈T*and choose any**z₀** *∈*A *−*1

(*t*). For any
( *<ℓ* ) *k* **z***∈* Fzk[X],

A(**z**) =*t⇐⇒*A(**z**)*−*A(**z₀**) = 0*⇐⇒*L(**z***−***z₀**) = 0*⇐⇒***z***−***z₀** *∈*ker(L)*.*

HenceA *−*1

(*t*) =**z₀** + ker(L), so*|*A
*−*1

(*t*)*|*=*|*ker(L)*|*=*|*F*|*
*k−*1. Therefore uniform masks induce the uniform distribution over*T*.

•*Oracle answers.*Let*Q***y**and(*Qj*) be the query sets output by*D₀* in the simulator above.

|s j∈[k]||
|---|---|
|(j)|C s|

(0) (k)

For*j∈{*0*,...,k}*, define a hybrid*H* that answers*Q***y**from**y**, usesSim zk for*Q* *l* with*l≤j*, and uses honest values for*l > j*. Then*H* is the real experiment and*H* is the simulated one.

|(j)||j|s|
|---|---|---|---|
|j s|C s|||
|||C||

For each*j∈*[*k*], hybrids*H* (*j−*1) and*H* differ only in the oracle*s*. Since*|Qj| ≤t*zk, by Definition 3.16 replacing honest answers*s* [*Qj*]withSim zk (*Qj*)changes statistical distance by at most*ζC* zk. Summing over*j*gives a total simulation error of at most*k·ζ* zk.

By the first part, the simulator samples the sumcheck transcript with exactly the same distribution as in the real execution, hence the induced distribution of**x** *′* and of the query sets output by *D₀* is also the same. Therefore the differences in the simulation stem from the oracle-answer simulation which is bounded above (and applying () *D₁* to these answers to produceout). Thus ∆ View(**P***,***V***,D,***x***,***y***,***w**)*,***S** **y***,D*

(**x**) *≤k·ζC*
zk.

### 6.2 Round-by-round security

**Lemma 6.5.***For everyδ,δ*zk*∈*(0*,*1)*, Construction 6.3 has RBR knowledge soundness with relax-* ˜*δ,δ*zk˜*δ,δ*zk *ation*(*R* *≡*2*k* *, R* *C,C,***sl** *′* )*and errors* *C,C*zk*,***sl** zk  ()  *≡*2*k≡n*+*k ≡*2*k−*(*j−*1)*≡n*+*k* <u>|Λ(C,δ)|·|Λ(Czk,δzk)|</u>*≡*2*k−j* <u>ℓzk·|Λ(C,δ)|·|Λ(Czk,δzk)|</u> *, ϵ* mca(*C,δ*) + *.* *|*F*| |*F*|* *j∈*[*k*]

∑ *≡*2*k−j* *The total extraction time isO*(*j∈*[*k*]tcor(*C*))*.*

*Proof.*We give notation, describe the extractors, describe a state function, and finally we establish the RBR knowledge soundness errors (based on the extractor and state function).

**Notation.**Let**x**= ((*µ,*st*,*(st*i*)*i∈*[*n*])*,*(***µ**i,*st*◦,i*)*i∈*[*n*])and**y**= (*f,*(*ξi*)*i∈*[*n*]). A complete transcript of () the protocol has the formtr= (*sj*)*j∈*[*k*]*,*˜*µ,ε,*((*h*ˆ*j,γj*))*j∈*[*k*]. Given a partial transcript, we define the following symbols (these are defined whenever they can be derived from the partial transcript): •***γ***

(*j*) = (*γ₁,...,γj*);
•*f*

(*j*) =Fold(*f,**γ***
(*j*) ); and
•*µ*

(*j*) = *h*ˆ*j*(*γj*)for*j >*0and*µ*
(0) =*ε·µ*+ ˜*µ*.
**Extractors.**We describe the round-by-round extractors from the last round to the first.

1.**Final round.E**rbr(**x***,***y***,*tr*∥γk,*w):
()

(a)Parsewas (***f**,**r***)*,*(***ξ**i,**r**i*)*i∈*[*n*]*,*(***s**j,**r**j′*)*j∈*[*k*].
(b)Compute *f*¯=Enc*C*(***f**,**r***)and for every*i∈*[*n*]compute *ξ*¯*i*:=Enc*C*
zk (***ξ**i,**r**i*)and for every

|:=Enc s|(s|,r ).|||||
|---|---|---|---|---|---|---|
|j|C ′ rbr|j j′ j|i i i i∈[n]|j j|j′ j∈[k]||
|(j) (j) (j−1)|(j)|i i i i∈[n]|j j j′|j ∈[k]|||

*j∈*[*k*]compute¯*j C* zk*j*(*j′*)

(c)Output the round witnessw := (*f,*¯ ***f**,**r***)*,*(*ξ*¯*,**ξ**,**r***)*,*(¯*s ,**s**,**r***).
2.**Sumcheck round***j∈*[*k*]**.E** (**x***,***y***,*tr*∥γ,*w):
()

(a)Parsewas (*f*¯*,**f**,**r***)*,*(*ξ*¯*,**ξ**,**r***)*,*(¯*s ′,**s** ′,**r** ′*) *′*.
(b)Parse*f*
(*j*) and*f* fromtr.

(c)Computes the largest set*S⊆*[*m*]such that *f*¯
(*j*) agrees with*f*
(*j*) and computes the erasure
correction *f*¯ (*j−*1) :=**E** *C* *≡*2*k−j* (*f* (*j−*1) *,S*)(see Definition 3.9).

(d)Compute(***f***
(*j−*1) *,**r*** (*j−*1) ) :=Enc *−* *≡* 1 2 *k−j*(*f* ¯ (*j−*1) ). *C* ()

|||:= (f¯|,f|,r|,ξ ,r )|,(¯ s ,s ,r|)|
|---|---|---|---|---|---|---|---|
|||′|(j−1) (j−1)|(j−1)|i i i i∈[n]|j j|j′ j ∈[k]|
|||rbr||||||

(e)Output the round witness**w**
*′* (*j−*1) (*j−*1) (*j−*1) )*,*(*ξ*¯*i i i i∈*[*n*] *j′j′ ′j′∈*[*k*].

3.**Combination randomness.E** (**x***,***y***,*tr*∥ε,*w)outputsw. **The state function.**We define a state functionKState.
˜*δ,δ*zk

0.**Initial transcript:** We setKState(**x***,***y***,∅,*w) = 1if and only if(**x***,***y***,*w)*∈ R*
*≡*2*k*. *C,C*zk*,***sl** ()

1.**Combination randomness:** The transcript has the formtr= (*sj*)*j∈*[*k*]*,*˜*µ* and the verifier samples*ε←*F. We setKState(**x***,***y***,*tr*∥ε,*w) = 1if and only if
() w= (*f,*¯ ***f**,**r***)*,*(*ξ*¯*i,**ξ**i,**r**i*)*i∈*[*n*]*,*(¯*js ,**s**j,**r**j′*)*j∈*[*k*]

is such that

•∆((*f,ξ₁,...,ξn,s₁,...,sk*)*,*(*f,*¯ *ξ*¯1*,..., ξ*¯*n,*¯1*s ,...,*¯*ks*))*≤*(*δ,δ*zk*,...,δ*zk);

- *f*¯=Enc
*C* *≡*2*k* (***f**,**r***),*∀i∈*[*n*] *ξ* ¯ *i*=Enc*C*zk(***ξ**i,**r**i*),*∀j∈*[*k*] ¯*js* =Enc*C*zk(***s**j,**r**j′*); •*∀i∈*[*n*]*,*sl*◦,i*(st*◦,i*)*·**ξ**i*=***µ**i*; ∑ ( ∑ ) •***b**∈{*0*,*1*}k* (***s₁***(*b₁*) +*···*+***s**k*(*bk*)) +*ε· ⟨**f**,*sl(st)*⟩*+*i∈*[*n*]*⟨**ξ**i,*sl*i*(st*i*)*⟩* = ˜*µ*+*ε·µ*.

()

2.**Sumcheck, round***j∈*[*k*]**:** The transcript has the formtr= (*sj′*)*j′∈*[*k*]*,*˜*µ,ε,*(*h*ˆ*j′,γj′*)*j′<j, h*ˆ*j*. The verifier samples*γj←*F. We setKState(**x***,***y***,*tr*∥γj,*w) = 1if and only if
() w= (*f*¯

(*j*) *,**f***
(*j*) *,**r***
(*j*) )*,*(*ξ*¯*i,**ξ**i,**r**i*)*i∈*[*n*]*,*(¯*js ′,**s**j′,**r**j′′*)*j′∈*[*k*]
is such that

•∆((*f*

(*j*)
*,ξ₁,...,ξn,s₁,...,sk*)*,*(*f*¯

(*j*)
*, ξ*¯1*,..., ξ*¯*n,*¯1*s ,...,*¯*ks*))*≤*(*δ,δ*zk*,...,δ*zk);

- *f*¯
(*j*) =Enc *C* *≡*2*k−j* (***f***
(*j*) *,**r***
(*j*) ),*∀i∈*[*n*] *ξ*¯*i*=Enc*C*
zk (***ξ**i,**r**i*),*∀j* *′* *∈*[*k*] ¯*js ′* =Enc*C* zk (***s**j′,**r*** *j′* *′* );

- *h*ˆ₁(0) + *h*ˆ₁(1) = ˜*µ*+*ε·µ*and*∀j*
*′* *∈*[*j−*1] *h*ˆ*j′*+1(0) + *h*ˆ*j′*+1(1) = *h*ˆ*j′* (*γj′*);

•*∀i∈*[*n*]*,*sl*◦,i*(st*◦,i*)*·**ξ**i*=***µ**i*; ∑ (

(*j*)
∑ ) ˆ •(*b* *j* *,...,bk*)*∈{*0*,*1*}k−j* (***s₁***(*γ₁*) +*···*+***s**k*(*bk*))+*ε· ⟨**f**,⊙j*sl(st*,**γ***)*⟩*+*i∈*[*n*]*⟨**ξ**i,*sl*i*(st*i*)*⟩* = *hj*(*γj*).

**Bounding the errors.**We bound the RBR errors for the protocol. ()

1.**Combination randomness.**Lettr= (*sj*)*j∈*[*k*]*,*˜*µ*. We show that:
[] *k* KState(**x***,***y***,*tr*,***E**rbr(**x***,***y***,*tr*,*w)) = 0 <u>|Λ(C</u> *≡*2 <u>,δ)|·|Λ(Czk</u> *≡n*+*k* <u>,δzk)|</u> Pr *∃*w: *≤.* *∧*KState(**x***,***y***,*tr*∥ε,*w) = 1 *|*F*|*

*≡*2*k≡n*+*k* Fixwsuch thatKState(**x***,***y***,*tr*∥ε,*w) = 1. There are at most*|*Λ(*C,δ*)*|·|*Λ(*C*zk*,δ*zk)*|*choices of wsuch that the conditions in Item 1 hold. SinceKState(**x***,***y***,*tr*,*w) = 0andKState(**x***,***y***,*tr*∥ε,*w) = 1(and most of the items in state function are independent of*ε*), it must be that either ∑ (***s₁***(*b₁*) +*···*+***s**k*(*bk*))*̸*= ˜*µ*or ***b**∈{*0*,*1*}k* ∑ *⟨**f**,*sl(st)*⟩*+ *⟨**ξ**i,*sl*i*(st*i*)*⟩̸*=*µ.* *i∈*[*n*]

By the polynomial identity lemma, Item 1 holds with probability *|*F <u>1</u> *|*. Taking a union bound concludes this part. ()

2.**Sumcheck randomness.**Lettr= (*sj′*)*j′∈*[*k*]*,*˜*µ,ε,*(*h*ˆ*j′,γj′*)*j′<j, h*ˆ*j*. We show that:
[] KState(**x***,***y***,*tr*,***E**rbr(**x***,***y***,*tr*,*w)) = 0 Pr *∃*w: *∧*KState(**x***,***y***,*tr*∥γj,*w) = 1

*≡*2*k−j*+1*≡n*+*k* *≡*2*k−j* <u>ℓzk·|Λ(C,δ)|·|Λ(Czk,δzk)|</u> *≤ϵ*mca(*C,δ*) +*.* *|*F*|*

*≡*2*k−j* Consider the event*E₁* that for every*S⊆*[*m*]with*|S|≥*(1*−δ*)*·m*if there exists*u∈C*

(*j*) *≡*2*k−j*(*j−*1)
such*u*(*S*) =*f* (*S*)then there exist*v₀,v₁ ∈C* such that(*v₀,v₁*)(*S*) =*f* (*S*). Note that *≡*2*k−j* by Definition 3.14 we have thatPr[*¬E₁*]*≤ϵ*mca(*C,δ*). The rest of the analysis is assuming that*E₁* holds.

Fixwsuch thatKState(**x***,***y***,*tr*∥γj,*w) = 1. SinceKState(**x***,***y***,*tr*,***E**rbr(**x***,***y***,*tr*,*w)) = 0, it must be that the conditions in Item 2 hold and thus∆(*f*

(*j*) *, f*¯
(*j*) )*≤δ*. Therefore (since*E₁* holds) there
*≡*2*k−j*(*j−*1)¯) are*v₀,v₁ ∈C* such that(*v₀,v₁*)(*S*) =*f* (*S*). Since∆((1*−γj*)*·v₀*+*γj·v₁, f ≤δ*it must be that *f*¯

(*j*) = (1*−γj*)*·v₀* +*γj·v₁* and that*v₀,v₁* are the words that**E**rbroutputs. Let***f₀**,**f₁***
*≡*2*k−j*+1 be the message (ignoring the randomness) underlying*v₀,v₁*. There are at most*|*Λ(*C,δ*)*|* such choices of***f₀**,**f₁***, and at most*|*Λ(*C*zk *≡n*+*k* *,δ*zk)*|*choices for the mask-related messages inw.

|It must be that h|ˆ (0) + h|ˆ (1) = h|ˆ|(γ ), and thus it must be that||||
|---|---|---|---|---|---|---|---|
|ℓ |F||j j|j (b ,...,b|j−1 )∈{0,1} j−1 j−1|j−1||i i∈[n]|k k i i|

∑ *h* ˆ (X)*̸*= (***s₁***(*γ₁*) +*···*+***s*** *j*

(X) +*···*+***s*** (*b*)) +
*j*+1 *k* *k−j−*1   ∑ *ε·* *⟨*X*·**f₀*** + (1*−*X)*·**f₁**,⊙j*sl(st*,*(***γ**,*X))*⟩*+ *⟨**ξ**,*sl (st)*⟩*

as the right hand side sums to *h*ˆ (*γ*), and if the left hand side did thenKState(**x***,***y***,*tr*,*w) = 0, a contradiction. By the polynomial identity lemma, the probability this happens is bounded by <u>zk</u>. A union bound over the possible choices ofwconcludes the lemma.

## 7 A non-succinct zero-knowledge protocol for constrained codes

We describe a zero-knowledge IOP for the relation*RC,C* zk*,***sl** (Definition 5.8). The IOP is*non-* *succinct*, and is used on small instances as a base case.

**Theorem 7.1.***Fix the following:* •*n∈*N*;*

|m ι m|||C ℓ|r m|
|---|---|---|---|---|
|m|ι m||C|ℓ r|
|i i∈[n]|◦,i i∈[n]|ℓ i C,C ,sl|ℓ ◦,i|t ×ℓ|

•*C⊆*Σ *≡*(F) *has a zero-knowledge encoding*Enc :F *×*F *→*Σ*;* zk zk zk zk*m* •*C*zk*⊆*Σzk zk*≡*(F) *has a zero-knowledge encoding*Enc zk :F *×*F *→*Σzk zk*;* •**sl**= (sl*,*(sl)*,*(sl))*where*sl*∈⟨*F *|,*sl *∈⟨*Fzk*|,*sl *∈⟨*F*i* zk*|;* •*t,t*zk*∈*N*are repetition parameters.* *Construction 7.2 is a*2*-round IOPP forR* zk *with the following properties:* •*Prover communication (in field elements):m·ι*+*n·m*zk*·ι*zk+*ℓ*+*r*+*n·*(*ℓ*zk+*r*zk)*. Of these,* **–***m·ιare sent as an oracle over*Σ*,* **–***n·m*zk*·ι*zk*are sent as an oracle over*Σ *n* zk*, and* **–***ℓ*+*r*+*n·*(*ℓ*zk+*r*zk)*are sent as non-oracle messages.* •*Query complexity:tqueries to the first input oracle,t*zk*queries to the remaining oracles.* ∑ ∑ •*Prover time (in field operations):O*(tenc(*C*) +*n·*tenc(*C*zk) +*t*sl+*i∈*[*n*]*t*sl *i* +*i∈*[*n*]*t*sl *◦,i* )*.* ∑ ∑ •*Verifier time (in field operations):O*(tenc(*C*) +*n·*tenc(*C*zk) +*t*sl+*i∈*[*n*]*t*sl *i* +*i∈*[*n*]*t*sl *◦,i* )*.* •**Round-by-round security:** *For everyδ,δ*zk*∈*(0*,*1)*, Construction 7.2 has RBR knowledge* ˜*δ,δ*zk *soundness with relaxation R* *C,C*zk*,***sl** *and errors*

() *≡n*<u>|Λ(C</u> *≡*2 <u>,δ)|·|Λ(Czk</u> *≡*2*·n* <u>,δzk)|</u> { *t t*zk } *ϵ* mca(*C,δ*) +*ϵ*mca(*C*zk*,δ*zk) +*,*max (1*−δ*)*,*(1*−δ*zk)*.* *|*F*|*

*The total extraction time isO*(tcor(*C*) +*n·*tcor(*C*zk))*.* •**Zero-knowledge:** *If*Enc*Cis at-query zero-knowledge encoding with errorζCand*Enc*C* zk *is*

|at -query zero-knowledge encoding with errorζ|, then Construction 7.2 is HVZK with error||
|---|---|---|
||C||
|C C|i∈[n]||

zk *C*zk *ζ* +*n·ζ* zk *and query complexity*(*t,*(*t*zk))*.*

### Construction 7.2.

•**Inputs and notation.**The verifier receives explicit input**x**= ((*µ,*st*,*(st

|||) ),(µ|,st )|)|
|---|---|---|---|---|
|C,C ,sl|i i∈[n]|i i∈[n] i|i ◦,i i i i∈[n]|i∈[n] t|

and oracle access to implicit input**y**= (*f,*(*ξ*)). Here*µ∈*Fand, for each*i∈*[*n*],***µ** ∈*F*i*. In the honest case, the prover receives**x**and**y**as well as witness**w**= (***f**,**r**,*(***ξ**,**r***))such that(**x***,***y***,***w**)*∈R* zk.

### •Interaction phase.

*m m ′*

|1.New masks.The prover sendsg∈Σ|||||,s₁,...,s|∈Σ|,µ ∈F, and for eachi∈[n]sends||||
|---|---|---|---|---|---|---|---|---|---|---|
|′i i∗|t i i′|ℓ i|i′ i ∗|r C i ∗|i′ ℓ ∗ ∗|C ′i ◦,i r ′|ℓ ′ ′ ′ ◦,i i|r i∗|i∈[n] ℓ i∗ i|i i i r i∗ i|

*n* zk zk ***µ*** *′i* *∈*F *t* *i*. In the honest case, the prover samples***g**∈*F *ℓ* ,***r*** *′* *∈*F *r* and for*i∈*[*n*]the prover ∑ samples***s** ∈*Fzkand***r** ∈*Fzkand sets*g* :=Enc (***g**,**r***),*µ* :=*⟨**g**,*sl(st)*⟩*+ *⟨**s**,*sl (st)*⟩* and for*i∈*[*n*]sets*s* :=Enc zk (***s**,**r***)and***µ*** :=sl (st)*·**s***.

2.**Combination randomness.**The verifier samples and sends*γ←*F.
3.**Answer.**The prover sends***f** ∈*F,***r** ∈*F and for*i∈*[*n*]sends***ξ** ∈*Fzkand***r** ∈*Fzk. In the honest case,***f*** :=***g***+*γ·**f***and***r*** :=***r*** +*γ·**r***and, for*i∈*[*n*],***ξ*** :=***s*** +*γ·**ξ*** and ***r*** :=***r*** +*γ·**r***.

4.**Spotcheck randomness.**The verifier samples and sends*x₁,...,xt←*[*m*]and*y₁,...,yt*
zk *←* [*m*zk].

|||||∗|C|∗ ∗|
|---|---|---|---|---|---|---|
|C i∗|i∗|∗ ∗|◦,i ◦,i i∈[n] j|∗ i ∗i i j i∗ j|′i i j i j|i ′ i j|

•**Decision phase.**The verifier computes*f* :=Enc (***f**,**r***)and, for each*i∈*[*n*], computes *ξ* *i∗* :=Enc zk (***ξ**,**r***); then it performs the following checks.

*•∀i∈*[*n*]*,*sl (st)*·**ξ*** =***µ*** +*γ·**µ*** **–**Target checks: ∑. *•⟨**f**,*sl(st)*⟩*+ *⟨**ξ**,*sl (st)*⟩*=*µ* +*γ·µ*

### –Cspot checks:∀j∈[t], f (x) =g(x) +γ·f(x).

**–***C*zkspot checks:*∀i∈*[*n*]*,∀j∈*[*t*zk]*, ξ* (*y*) =*s* (*y*) +*γ·ξ* (*y*).

### 7.1 Zero-knowledge

**Lemma 7.3.***If*Enc*Cis at-query zero-knowledge encoding with errorζCand*Enc*C* zk *is at*zk*-query* *zero-knowledge encoding with errorζC* zk *, then Construction 7.2 is HVZK with errorζC*+*n·ζC* zk *and* *query complexity*(*t,*(*t*zk)*i∈*[*n*])*.*

### Proof.We define the simulator.

**S** **y**

(**x**):
1.Parse**x**as((*µ,*st*,*(st*i*)*i∈*[*n*])*,*(***µ**i,*st*◦,i*)*i∈*[*n*]), and recall that**y**has the form(*f,*(*ξi*)*i∈*[*n*]).
2.Sample*γ←*F,*x₁,...,xt←*[*m*], and*y₁,...,yt*
zk *←*[*m*zk].

3.Set*S* := (*x₁,...,xt*)and*S*
*′* := (*y₁,...,yt* zk ).

4.Query*f*[*S*]and, for every*i∈*[*n*], query*ξi*[*S*
*′*].

5.Sample*g*[*S*]*←*Sim*C*(*S*)and, for every*i∈*[*n*], sample*si*[*S*
*′*]*←*Sim*C* zk (*S* *′* ).

6.Sample***f***
*∗* *←*F *ℓ* and***r*** *∗* *←*F *r* such thatEnc*C*(***f*** *∗* *,**r*** *∗* )satisfiesEnc*C*(***f*** *∗* *,**r*** *∗* )(*S*) =*g*[*S*]+*γ·f*[*S*]. (If no solution exists, abort.)

7.For every*i∈*[*n*], sample***ξ**i∗←*F
*ℓ* zkand***r*** *i∗←*F *r* zksuch thatEnc *C* zk (***ξ**i∗,**r**i∗*)(*S* *′* ) =*si*[*S* *′*] +*γ·* *ξ* *i* [*S* *′*]. (If no solution exists, abort.) *′ ∗* ∑

8.Set*µ* :=*⟨**f**,*sl(st)*⟩*+*i∈*[*n*]*⟨**ξ**i∗,*sl*i*(st*i*)*⟩−γ·µ*.
9.For every*i∈*[*n*], set***µ***
*′i* :=sl*◦,i*(st*◦,i*)*·**ξ*** *i∗−γ·**µ**i*.

10.Output
 
*γ,*(*x₁,...,xt*)*,*(*y₁,...,yt*
zk )*,*  *µ* *′* *,*(***µ*** *′* *,...,**µ*** *′* )*,g*[*S*]*,*(*s* [*S* *′*]*,...,s* [*S* *′*])*,*  1 *n* 1 *n*  *∗ ∗ ∗ ∗ ∗ ∗**.*
 ***f**,**r**,*(***ξ₁**,...,**ξ**n*)*,*(***r₁**,...,**r**n*)*,* 
*f*[*S*]*,*(*ξ₁*[*S* *′*]*,...,ξn*[*S* *′*])

The simulator runs in polynomial time. This is straightforward except for Items 6 and 7. SinceEnc*C* andEnc*C* zk are injective linear maps, there exist matrices***G**∈*F *m×*(*ℓ*+*r*) and***G**C* zk *∈*F *m*zk*×*(*ℓ*zk+*r*zk)

such thatEnc*C*(***u***) =***G**·**u***andEnc*C* zk

(***u***) =***G**C* zk
*·**u***. Sampling***f*** *∗* and***r*** *∗* such thatEnc*C*(***f*** *∗* *,**r*** *∗* )(*S*) = *g*[*S*] +*γ·f*[*S*]is equivalent to sampling a solution to(***G**·**u***) [*S*] =***t***, and similarly for each***ξ**i∗,**r**i∗* with***G**C* zk; both can be done in polynomial time. **y** Next we analyze the simulation error. We introduce an intermediate simulator**S₀**(**x***,***w**)that has access to the witness to the relation.

**y**

|,r )|)).||
|---|---|---|
|i i i∈[n]|t|t|
|t|′|t|

**S₀**(**x***,***w**= (***f**,**r**,*(***ξ**i i i∈*[*n*]

1.Sample*γ←*F,*x₁,...,x ←*[*m*], and*y₁,...,y*
zk *←*[*m*zk].

2.Set*S* := (*x₁,...,x*)and*S* := (*y₁,...,y*
zk ).

|ℓ ′|i|ℓ|
|---|---|---|
|C ′|C i|i′|

3.Sample***g**←*F,***r** ←*F
*r*, and for every*i∈*[*n*]sample***s** ←*Fzkand***r**i′←*F *r* zk.

4.Set*g* :=Enc (***g**,**r***)and, for every*i∈*[*n*],*si*:=Enc
zk (***s**,**r***).

5.Set
***f*** *∗* :=***g***+*γ·**f**,**r*** *∗* :=***r*** *′* +*γ·**r**,*

### ∀i∈[n] : ξi∗:=si+γ·ξi,ri∗:=ri′+γ·ri.

6.Set
∑

|:=⟨g,sl(st)⟩+ µ||⟨s|,sl (st )⟩,|
|---|---|---|---|
|′||i∈[n]|i i i|
|′i|◦,i ◦,i|i||

### ∀i∈[n] : µ :=sl (st)·s.

7.Output
 
*γ,*(*x₁,...,xt*)*,*(*y₁,...,yt*
zk )*,*  *µ* *′* *,*(***µ*** *′* *,...,**µ*** *′* )*,g*[*S*]*,*(*s* [*S* *′*]*,...,s* [*S* *′*])*,*  1 *n* 1 *n*  *∗ ∗ ∗ ∗ ∗ ∗**.*

| f ,r ,(ξ₁,...,ξ||),(r₁,...,r|),||
|---|---|---|---|---|
||′|n ′|||
|′ i∈[n] i ′|i∈[n]||∗ ∗|i∗ i∗|
|C|C||||
|C|C||||

*n n* *f*[*S*]*,*(*ξ₁*[*S* *′*]*,...,ξn*[*S* *′*])

Conditioned on*g*[*S*]and(*si*[*S*]), the sampling of(***f**,**r***)and(***ξ**,**r***)in**S₀** is uniform over the solution sets of the linear systems in Item 6. Therefore the only statistical gap between**S**and**S₀** comes from simulating*g*[*S*]and(*s* [*S*]) : by Definition 3.16 and a union bound over these*n*+ 1 codewords, this gap is at most*ζ* +*n·ζ* zk. The distribution of**S₀** is identical to the real view, so the simulation error is at most*ζ* +*n·ζ* zk.

### 7.2 Round-by-round knowledge soundness

**Lemma 7.4.***For everyδ,δ*zk*∈*(0*,*1)*, Construction 7.2 has RBR knowledge soundness with relax-* ˜*δ,δ*zk *ation R* *C,C*zk*,***sl** *and errors*

() *≡n*<u>|Λ(C</u> *≡*2 <u>,δ)|·|Λ(Czk</u> *≡*2*·n* <u>,δzk)|</u> { *t t*zk } *ϵ* mca(*C,δ*) +*ϵ*mca(*C*zk*,δ*zk) +*,*max (1*−δ*)*,*(1*−δ*zk)*.* *|*F*|*

### The total extraction time isO(tcor(C) +n·tcor(Czk)).

*Proof.*We give notation, describe the extractors, describe a state function, and finally we establish the RBR knowledge soundness errors (based on the extractor and state function).

**Notation.**Let**x**= ((*µ,*st*,*st₁*,...,*st*n*)*,*(***µ**i,*st*◦,i*)*i∈*[*n*])and**y**= (*f,*(*ξi*)*i∈*[*n*]). A complete transcript of the protocol has the form () tr= *g,s₁,...,sn,µ* *′* *,**µ*** *′* 1 *,...,**µ*** *′n* *,γ,**f*** *∗* *,**r*** *∗*
*,*(***ξ**i∗,**r**i∗*)*i∈*[*n*]*,x₁,...,xt,y₁,...,yt*
zk *.*

**Extractor.**We describe the round-by-round extractors from the last round to the first.

1.**Spotcheck randomness.**
(a)Parse the transcript to obtain***f***

|||,r, and(ξ|,r|).|
|---|---|---|---|---|
|||∗ ∗|i∗|i∗ i∈[n]|
|C ∗|∗|1 ∗|n ∗|C|

*∗* ( *∗ ∗ ∗ ∗* )

(b)Compute *f*¯ :=Enc (***f**,**r***)and(*ξ*¯*,..., ξ*¯) :=Enc *≡n* (***ξ₁**,...,**ξ**n*)*,*(***r₁**,...,**r**n*).
zk

(c)Outputs the round witnessw := (*f*¯
*∗* *,**f*** *∗* *,**r*** *∗* *,*(*ξ*¯*i∗,**ξ**i∗,**r**i∗*)*i∈*[*n*]).

2.**Combination randomness.**
(a)Parsewas(*f*¯
*∗* *,**f*** *∗* *,**r*** *∗* *,*(*ξ*¯*i∗,**ξ**i∗,**r**i∗*)*i∈*[*n*]).

(b)Let*S⊆*[*m*]be the largest set on which *f*¯
*∗* agrees with*g*+*γ·f*.

(c)Use the erasure corrector**E***C*for*C*to obtain codewords *f,*¯ ¯from *g f*(*S*)*,g*(*S*)and decode them to(***f**,**r***),(***g**,**r***
*′* ).

(d)Let*S* *′*
*⊆*[*m*zk]be the largest set on which(*ξ*¯1 *∗* *,..., ξ*¯*n* *∗* )agrees with(*s₁*+*γ·ξ₁,...,sn*+*γ·ξn*).

(e)For every*i∈*[*n*], use the erasure corrector**E***C*
zk for*C*zkto obtain codewords *ξ*¯*i,*¯*is* from

|ξ (S ),s (S|)and decode them to(ξ|||,r ),(s ,r|).||||
|---|---|---|---|---|---|---|---|---|
|i ′ i|′|||i i ′ i|i′ i i|i′ i∈[n]|||

*i* *′* *i* *′* *i i i i′*

(f)Output the round witnessw := (***f**,**r**,**g**,**r**,*(***ξ**,**r**,**s**,**r***)).
3.**Final extraction.**
(a)Parsewas(***f**,**r**,**g**,**r***

|,(ξ ,r|,s ,r )|).|||
|---|---|---|---|---|
|′ i|i i i′ i∈[n]||||
|C|i|i i∈[n]|i i i∈[n]|C i i|

(b)Compute *f*¯ :=Enc (***f**,**r***)and for every*i∈*[*n*]compute *ξ*¯ :=Enc
zk (***ξ**,**r***).

(c)Output(**w***,***y**
*∗* )where**w** := (***f**,**r**,*(***ξ**,**r***))and**y** *∗* := (*f,*¯ (*ξ*¯)).

**The state function.**We define a state functionKState.

˜*δ,δ*zk

0.**Initial transcript:** We setKState(**x***,***y***,∅,*w) = 1if and only if(**x***,***y***,*w)*∈ R*
*C,C*zk*,***sl**.

||||n|′ ′1|′n||
|---|---|---|---|---|---|---|
|||||∗ ∗|∗ i∗|i∗ i∗|
|C ∗ ∗|n ∗|C ∗|n ∗ ∗|n ∗|||
|∗||n|n 1∗|n ∗|||

1.**Combination randomness:** The transcript istr= (*g,s₁,...,s,µ,**µ**,...,**µ***)and the verifier samples*γ←*F. We setKState(**x***,***y***,*tr*∥γ,*w) = 1if and only ifw= (*f*¯*,**f**,**r**,*(*ξ*¯*,**ξ**,**r***))such that all of following hold:
(a) *f*¯ *∗* =Enc (***f**,**r***)and(*ξ*¯1
*∗*
*,..., ξ*¯) =Enc *≡n* ((***ξ₁**,...,**ξ***)*,*(***r₁**,...,**r***));
zk

(b)∆(*g*+*γ·f, f*¯)*≤δ*and∆((*s₁* +*γ·ξ₁,...,s* +*γ·ξ*)*,*(*ξ*¯*,..., ξ*¯))*≤δ*zk;
(c)the following both hold
∑

|∗|i∗|i i|′||||
|---|---|---|---|---|---|---|
||i∈[n] ◦,i ◦,i|i∗ i i∈[n]|′i ′|i ′i i∈[n]|∗ ∗|i∗ i∗ i∈[n]|
|t|t||||t|t|

*⟨**f**,*sl(st)*⟩*+ *⟨**ξ**,*sl (st)*⟩*=*µ* +*γ·µ,*

### ∀i∈[n] :sl (st)·ξ =µ +γ·µ.

2.**Spotcheck randomness:** The transcript istr= (*g,*(*s*)*,µ,*(***µ***)*,γ,**f**,**r**,*(***ξ**,**r***))
and the verifier samples*x₁,...,x* and*y₁,...,y*
zk
. We setKState(**x***,***y***,*tr*∥*(*x₁,...,x,y₁,...,y*
zk )*,*w) = 1if and only ifw=*∅*and the verifier accepts.

**Bounding the errors.**We bound the RBR errors for the protocol.

1.**Combination randomness.**We show that
[] KState(**x***,***y***,*tr*,***E**rbr(**x***,***y***,*tr*,*w)) = 0 Pr *∃*w: *γ ∧*KState(**x***,***y***,*tr*∥γ,*w) = 1

*≡n*<u>|Λ(C</u> *≡*2 <u>,δ)|·|Λ(Czk</u> *≡*2*·n* <u>,δzk)|</u> *≤ϵ*mca(*C,δ*) +*ϵ*mca(*C*zk*,δ*zk) +*, .* *|*F*|*

Let*E₁* be the event that for every*S⊆*[*m*]with*|S|≥*(1*−δ*)*·m*if there exists a codeword *u∈C*such that*u*(*S*) = (*g*+*γ·f*)(*S*)then there exist*ug,uf∈C*such that*ug*(*S*) =*g*(*S*)and

*uf*(*S*) =*f*(*S*). Similarly, let*E₂* be the event that for every*S* *′*

||||⊆[m||≥(1−δ|
|---|---|---|---|---|
|′|≡n|′ ′||n ′|
|ξ,n|≡n|ξ,i ′|i ′||
|||≡n|||

zk]with*|S* *′* zk)*·m*zkif there exists a codeword*u* *′* *∈C*zk *≡n* such that*u* *′* (*S* *′* ) = (*s₁*+*γ·ξ₁,...,sn*+*γ·ξ*)(*S* *′* )then there exist codewords(*uξ,*1*,...,u*)in*C*zksuch that*u* (*S*) =*ξ* (*S*)for all*i∈*[*n*]. By Definition 3.14, Pr[*¬E₁*]*≤ϵ*mca(*C,δ*)andPr[*¬E₂*]*≤ϵ*mca(*C*zk*,δ*zk). We condition on*E₁ ∧E₂* in the rest of the analysis.

|∗ ∗ ∗|i∗ i∗ i∗ i∈[n]|||
|---|---|---|---|
|||′ i i|i i′ i∈[n]|

### Fixw= (f¯,f,r,(ξ¯,ξ,r))such thatKState(x,y,tr∥γ,w) = 1and let

(***f**,**r**,**g**,**r**,*(***ξ**,**r**,**s**,**r***)) =**E**rbr(**x***,***y***,*tr*,*w)

denote the output of the extractor onw.

By*E₁* and*E₂* and the definition of the extractor**E**rbrthere are at most*|*Λ(*C* *≡*2 *,δ*)*|·|*Λ(*C*zk *≡*2*·n* *,δ*zk)*|* possible choices forw. This is because:

•SinceKState(**x***,***y***,*tr*∥γ,*w) = 1it must be that∆(*g*+*γ·f, f*¯ *∗* )*≤δ*and similarly for*i∈*[*n*]it must be that∆(*si*+*γ·ξi, ξ*¯*i∗*)*≤δ*zk. Thus, by*E₁,E₂* there must exists sets*S*and*S* *′* with *|S|≥*(1*−δ*)*·m*and*|S* *′* *|≥*(1*−δ*zk)*·m*zksuch that(*f,g*)agrees with the interleaved code *C* *≡*2
on*S*and(*ξ₁,...,ξn,s₁,...,sn*)agrees with the interleaved code*C*zk
*≡*2*·n*. •The extractor by definition outputs the messages underlying the interleaved code, and thus there can be at most*|*Λ(*C* *≡*2 *,δ*)*|·|*Λ(*C*zk *≡*2*·n* *,δ*zk)*|*such choices. *∗*

|•Further, it must be thatf||=g+γ·f. For anyx∈Sit holds thatEnc|||||(f ,r|)(x) =|
|---|---|---|---|---|---|---|---|---|
|∗||C|′|C||C|′||
||||||||∗||
|∗|′|||i i|||||
|||rbr|||||||
||||i∈[n]|i i i ◦,i i|i||||

*C* *∗ ∗*

*f* ¯ *∗*

(*x*) =*g*(*x*) +*γ·f*(*x*) =Enc (***g**,**r***
*′* )(*x*) +*γ·*Enc (***f**,**r***)(*x*) =Enc (***g***+*γ·**f**,**r*** *′* +*γ·**r***)(*x*). Since the two codewords agrees on a set of size(1*−δ*)*·m≥*(1*−δ*(*C*))*·m*they must be the same codeword, and since the encoding is injective it must in fact be that***f*** =***g***+*γ·**f***and ***r*** =***r*** +*γ·**r***. A similar fact also holds for the*ξ,s*.

Suppose thatKState(**x***,***y***,*tr*,***E** (**x***,***y***,*tr*,*w)) = 0, it must then be that either ∑ *⟨**f**,*sl(st)*⟩*+ *⟨**ξ**,*sl (st)*⟩̸*=*µ*or

### ∃i∈[n] :sl◦,i(st)·ξ ̸=µ.

In either case, the probability over a choice of*γ*that ∑ *⟨g*+*γ·**f**,*sl(st)*⟩*+ *⟨**s**i*+*γ·**ξ**i,*sl*i*(st*i*)*⟩*=*µ* *′* +*γ·µ*and *i∈*[*n*]

*∀i∈*[*n*] :sl*◦,i*(st*◦,i*)*·*(***s**i*+*γ·**ξ**i*) =***µ*** *′i* +*γ·**µ**i.*

is at most *|*F <u>1</u> *|*. Since, as noted before,***f*** *∗* =***g***+*γ·**f***and for*i∈*[*n*]it holds that***ξ**i∗*=***s**i*+*γ·**ξ**i*, this implies thatKState(**x***,***y***,*tr*,*w) = 0. Taking a union bound over all possible witnesses yields the bound above.

2.**Spotcheck randomness.**We show that
[] {

|||KState(x,y,tr,E||(x,y,tr,∅)) = 0|}|
|---|---|---|---|---|---|
|||||rbr|t|
|(x ,...,x|,y ,...,y ∗ ∗|) ∗ i∗|i∗ i∗ i∈[n]|rbr||
||||||∗|

*t*zk Pr *≤*max (1*−δ*)*,*(1*−δ*zk)*.*
1 *t* 1 *t*zk*∧*KState(**x***,***y***,*tr*∥*(*x₁,...,xt,y₁,...,yt*zk)*,∅*) = 1

Write(*f*¯*,**f**,**r**,*(*ξ*¯*,**ξ**,**r***))for**E** (**x***,***y***,*tr*,∅*). If the linear constraints in the decision phase fail, the verifier rejects regardless of the sampled points. Otherwise, either∆(*g*+*γ·f, f*¯)*> δ*

or∆((*s₁* +*γ·ξ₁,...,sn*+*γ·ξ*zk *∗* )*> δ*, then

|),(ξ¯ ,..., ξ¯|))> δ|. In the first case,∆(g+γ·f, f¯|
|---|---|---|
|n 1∗|n ∗||
|t|j||
|n|n 1∗|n ∗|

with probability at most(1*−δ*) all*x* fall in the agreement set, and the*C*-local checks pass.
Similarly, if∆((*s₁* +*γ·ξ₁,...,s* +*γ·ξ*)*,*(*ξ*¯*,..., ξ*¯))*> δ*zk, then with probability at most
(1*−δ*zk) *t* zkall*y* *j*avoid disagreement positions and the*C*zk-local checks pass.

## 8 A sublinear zero-knowledge IOP for constrained codes

We prove Theorem 1 by composing the IOR of Theorem 6.2 and the2-round IOPP of Theorem 7.1.

**Theorem 8.1.***Consider the following ingredients:* •*n,k∈*N*;*

|m ι m||||C ℓ|r m|
|---|---|---|---|---|---|
|m|ι m|||C|ℓ r|
|i i∈[n]|◦,i i∈[n]|ℓ C ,C ,sl|i|ℓ ◦,i|t ×ℓ|

•*C⊆*Σ *≡*(F) *with a zero-knowledge encoding*Enc :F *×*F *→*Σ*;* zk zk zk zk*m* •*C*zk*⊆*Σzk zk*≡*(F) *with a zero-knowledge encoding*Enc zk :F *×*F *→*Σzk zk*;* •**sl**= (sl*,*(sl)*,*(sl))*where*sl*∈⟨*F *|,*sl *∈⟨*Fzk*|,*sl *∈⟨*F*i* zk*|;* •*t,t*zk*∈*N*are repetition parameters.* *Construction 8.2 is an IOPP forR≡*2*k with the following parameters.* zk

•*Round complexity:k*+ 3*.* •*Prover communication (in field elements):O*(*k·*(*ℓ*zk+*m*zk*·ι*zk) +*m·ι*+ (*n*+*k*)*·m*zk*·ι*zk+*ℓ*+ *r*+ (*n*+*k*)*·*(*ℓ*zk+*r*zk))*. Of thesem·ιare sent as an oracle with alphabet*Σ*,*(*n*+ 2*·k*)*·m*zk*·ι*zk *are sent as an oracle with alphabet*Σ *n* zk +2*·k* *, andk·ℓ*zk+*ℓ*+*r*+ (*n*+*k*)*·*(*ℓ*zk+*r*zk)*are sent as* *non-oracle messages.* 2 *k* •*Verifier queries: the verifier makestoracle queries tofover alphabet*Σ *and, for each mask* *oracle in the protocol (namely thenmasks from the instance together with thekmasks introduced* *by the sumcheck IOR), it makes at mostt*zk*oracle queries over alphabet*Σzk*.* •*Prover time (in field operations):O*(2 *k* *·ℓ*+*t*sl+*k·*tenc(*C*zk) +*k·ℓ*zk+tenc(*C*) + (*n*+*k*)*·*tenc(*C*zk) + ∑ ∑ *i∈*[*n*]*t*sl*i*+*i∈*[*n*]*t*sl*◦,i*+*k·t*slze*⋆*+*k·t*slid)*.* *ℓ* zk∑ •*Verifier time (in field operations):O*(2 *k* *·t*+*k·ℓ*zk+tenc(*C*)+(*n*+*k*)*·*tenc(*C*zk)+*t⊙k*sl+*i∈*[*n*]*t*sl *i* + ∑ *i∈*[*n*]*t*sl*◦,i*+*k·t*slze*⋆*+*k·t*slid)*.* *ℓ* zk •**Round-by-round security:** *For everyδ,δ*zk*∈*(0*,*1)*, Construction 8.2 has RBR knowledge* ˜*δ,δ*zk *soundness with relaxation R* *≡*2*k* *and errors:* *C,C*zk*,***sl** ( *k* ( *k−*(*j−*1) ) <u>|Λ(C</u> *≡*2 <u>,δ)|·|Λ(Czk</u> *≡n*+*k* <u>,δzk)|</u>*≡*2*k−j* <u>ℓzk·|Λ(C</u> *≡*2 <u>,δ)|·|Λ(Czk</u> *≡n*+*k* <u>,δzk)|</u> *, ϵ*mca(*C,δ*) +*,* *|*F*| |*F*|* *j∈*[*k*] *≡*2 *≡*2(*n*+*k*){} ) *≡n*+*k*<u>|Λ(C,δ)|·|Λ(Czk,δzk)|</u>*t t*zk *ϵ* mca(*C,δ*) +*ϵ*mca(*C*zk*,δ*zk) +*,*max (1*−δ*)*,*(1*−δ*zk)*.* *|*F*|*

(∑ *k−j* ) *The total extraction time isOj∈*[*k*]tcor(*C* *≡*2 ) + (*n*+*k*)*·*tcor(*C*zk)*.* •**Zero-knowledge:** *If*char(F)*̸*= 2*,ℓ*zk*≥*2*,*Enc*Cis at-query zero-knowledge encoding with error* *ζ* *C* *, and*Enc*C*

|||C|
|---|---|---|
|C||i∈[n]|

zk *is at*zk*-query zero-knowledge encoding with errorζC* zk *, then Construction 8.2 is* *HVZK with error*2 *k* *·ζC*+ (*n*+ 2*k*)*·ζ* zk *and query complexity*(*t,*(*t*zk))*.*

### Construction 8.2.

( ()) •**Inputs.**The verifier receives explicit input**x**= (*µ,*st*,*(st*i*)*i∈*[*n*])*,* (***µ**i*)*i∈*[*n*]*,*(st*◦,i*)*i∈*[*n*]and oracle access to implicit input**y**= (*f,*(*ξi*)*i∈*[*n*]). In the honest case, the prover receives as input **x**and**y**as well as witness**w**= (***f**,**r**,*(***ξ**i,**r**i*)*i∈*[*n*])such that(**x***,***y***,***w**)*∈R* *C* *≡*2*k,C,***sl**. zk

### •Interaction phase.

**–Sumcheck IOR.**The prover and verifier run the zero-knowledge sumcheck IOR from*R* *C* *≡*2*k,C,***sl** zk to*RC,C* zk*,***sl** *′* in Construction 6.3, leading to:

() **x** *′* := (*µ* *′* *,*st *′* *,*(st *′i* ) *i∈*[*n*+*k*])*,*(***µ*** *′i* *,*st *′◦,i* ) *i∈*[*n*+*k*]*,*

**y** *′* := (Fold(*f,**γ***)*,*(*ξi*)*i∈*[*n*]*,*(*sj*)*j∈*[*k*])*,*

(in the honest case)**w** *′* := (Fold(***f**,**γ***)*,*Fold(***r**,**γ***)*,*(***ξ**i,**r**i*)*i∈*[*n*]*,*(***s**j,**r*** *j′* ) *j∈*[*k*])*,* **sl** *′* := (*×*(*⊙k*sl)*,*(*×*(sl*i*))*i∈*[*n*]*,*(slze*⋆* *ℓ* ) *j∈*[*k*]*,*(sl*◦,i*)*i∈*[*n*]*,*(slid)*j∈*[*k*])*.* zk

Above***γ**∈*F *k* is the randomness sampled during the sumcheck protocol. **–Non-succinct IOPP.**The prover and verifier run the IOPP for the relation*RC,C* zk*,***sl** *′* in Construction 7.2 on(**x** *′* *,***y** *′* *,***w** *′* ), with repetition parameters(*t,t*zk).

*Proof of Theorem 8.1.*LetIOR₁ be Construction 6.3 and letIOR₂ be Construction 7.2 instantiated on*RC,C* zk*,***sl** *′* with*n*+*k*mask oracles. Construction 8.2 is the concatenationIOR₂ *◦*IOR₁. The stated round complexity, prover communication, verifier queries, prover/verifier time, and round-by-round errors are obtained by combining the corresponding bounds from Theorems 6.2 and 7.1. We now establish HVZK:

•By Theorem 7.1,IOR₂ has a simulator**S₂** with error*ϵ₂* :=*ζ* *C* *≡*2*k* + (*n*+*k*)*·ζC*zkand query complexity(*t,*(*t*zk)*i∈*[*n*+*k*]). In the concatenated protocol, the first-oracle queries handled through *≡*2*k* **S₂** are induced by queries to the original oracle*f*, which is a codeword of*C*.

:= ( **y y** •Let***t** t,*(*t*zk)*i∈*[*n*]), and define*D***S**2as in Definition 4.4, i.e.,*D* **S**2

(*·*) :=**S₂**(*·*). By the query
bound of**S₂**,*D***S**2makes at most*t*queries to the first oracle of**y** *′*, at most*t*zkqueries to each of the next*n*mask oracles, and at most*t*zkqueries to each of the*k*new mask oracles. Hence *D***S**2*∈*D *≤*(***t**,*(*t*zk)*j∈*[*k*]). By Theorem 6.2,IOR₁ is HVZK for this distinguisher via a simulator**S₁** with error*ϵ₁* :=*k·ζC* zk and query complexity(*t,*(*t*zk)*i∈*[*n*]).

•Apply Theorem 4.5 with*R*start:=*R* *C* *≡*2*k,C,***sl***,R*int:=*RC,C*zk*,***sl***′,R*fin:=*R*triv. The composed proto- zk col is HVZK with query complexity(*t,*(*t*zk)*i∈*[*n*])and error at most*ϵ₁*+*ϵ₂* =*ζ* *C* *≡*2*k* +(*n*+2*k*)*·ζC*zk. By Claim 3.23,*ζ* *C* *≡*2*k ≤*2 *k* *·ζC*, and therefore

*ϵ₁* +*ϵ₂ ≤*2 *k* *·ζC*+ (*n*+ 2*k*)*·ζC* zk *.*

In sum Construction 8.2 is an IOPP with HVZK simulation error2 *k* *·ζC*+ (*n*+ 2*k*)*·ζC* zk.

## 9 Zero-knowledge code-switching

We introduce an honest-verifier zero-knowledge code-switching protocol. To do so, we first introduce the variant of out-of-domain samples that we use in Section 9.1, the notion of private zero-evaders in Section 9.2, and a measure of the code-switching efficiency in Section 9.3.

### 9.1 Out-of-domain samples

We refine the notion of out-of-domain samples for a linear code (see [BGKS20] and their later uses in [ACFY24; ACFY25; BCFW25]) to account for zero-knowledge encodings. Specifically, in this paper we need to ensure that the “disagreement” is on the message part of the zero-knowledge code and not (only) the randomness part.

**Lemma 9.1.***LetC⊆*Σ *m* *be an*F*-additive code with zero-knowledge encoding*Enc*C*:F *ℓ* *×*F *r* *→*Σ *m* *,* *f∈*Σ *m* *be a word, andδ∈*[0*,*1]*be a distance parameter. Let*ze: *D*ze*→*F *t×ℓ* *be a zero-evader with* *errorε*zero*(Definition 3.3). Then,*   *∃u,v∈*Λ(*C,f,δ*)*s.t.*2   <u>|Λ(C,δ)|</u> Pr  ***u**̸*=***v**∧*ze(*ρ*)*·**u***=ze(*ρ*)*·**v***  *≤ ·ε*zero*.* *ρ←D*ze *−*1 *′ −*12 *where*(***u**,**r***) :=Enc *C*

(*u*)*,*(***v**,**r***) :=Enc
*C*

(*v*)
*Proof.*Let*u,v∈*Λ(*C,f,δ*)be distinct codewords and(***u**,**r***) :=Enc *−* *C* 1

(*u*)and(***v**,**r***
*′* ) :=Enc *−* *C* 1

(*v*).
We consider two cases: (i) if***u***=***v***, we are done; (ii) if***u**̸*=***v***, sincezeis a zero-evaderze(*ρ*)*·**u***= ze(*ρ*)*·**v***with probability at most*ε*zero. The bound follows by taking a union bound over the at most ( *|*Λ(*C,δ*)*|* ) 2 distinct pairs of codewords inΛ(*C,f,δ*).

### 9.2 Private zero-evaders

We consider zero-evaders with a*privacy guarantee*: the inner product with a vector consisting of a private portion and a random portion reveals little or no information about the private portion.

**Definition 9.2.***A zero-evader*ze: *D*ze*→*F *t×ℓ* *is*(*r,ζ*ze)**-private***if there exists a simulator***S**ze *such that for every**f**∈*F *ℓ−r* *the following two distributions have statistical distance at mostζ*ze*:*  ∣ *r*    ∣∣ *ρ←D* ze*,**r**←*[ F]  ∣ (*ρ,**y***) ∣ ***f** and***S**ze*.*   ∣ ***y***=ze(*ρ*)*·*  ∣ ***r***

By considering the all-zero zero-evader, one can see that there are zero-evaders with good privacy guarantees but trivial zero-evading error. In fact any zero-evader can be modified to have*perfect* privacy guarantees while essentially preserving the zero-evading error.

**Lemma 9.3.***Let*ze: *D*ze*→*F *t×ℓ* *be a zero-evader with errorε*zero*. For everyr∈*N*withr≥t,* *there exists a zero-evader*ze *′* : *D*ze *′* *→*F *t×*(*ℓ*+*r*) *with error*max*{ε*zero*,* *|*F*|t* <u>1</u> *−*1 *}that is*(*r,*0)*-private.*

*Proof.*Let

||{||}|
|---|---|---|---|
|t,r t,r||t×r|t|
|||′||

*M* := ***M**∈*F :the columns of***M***spanF*.*

Define*D*ze *′* :=*D*ze*×M* and ze (*ρ,**M***) := [ze(*ρ*)*,**M***]*.*

||ze|′|r|
|---|---|---|---|
|t|t|t||
|r|||t|

**Privacy error.**Fix any***f**∈*F *ℓ*. Let**S** *′* be the simulator that samples(*ρ,**M***)*←D*zeand***r**←*F. Let***t**ρ*:=ze(*ρ*)*·**f**∈*F. The sample from the real distribution is [] *′**f*** ((*ρ,**M***)*,**y***)where***y***=ze (*ρ,**M***)*·* =***t**ρ*+***Mr**.* ***r***

Since***M**∈Mt,r*has columns spanningF, the linear map***r**7→**Mr***is surjective ontoF. Therefore, when***r***is uniform inF, the value***Mr***is uniform inF *t*, and hence***y***=***t**ρ*+***Mr***is uniform inF, even conditioned on(*ρ,**M***). Thus the joint distribution of((*ρ,**M***)*,**y***)is identical to the distribution produced by the simulator. **Zero-evader error.**Let***v**̸*= 0and write***v***= (***s**,**r***) T for***s**∈*F *ℓ* and***r**∈*F *r*. Note that ze *′* (*ρ,**M***)*·**v***=ze(*ρ*)*·**s***+***M**·**r***. We consider two cases.

### •Ifr=0thens̸=0and then

Pr[ze *′* (*ρ,**M***)*·**v***=**0**] = Pr[ze(*ρ*)*·**s***=**0**]*≤ε*zero*.*

### •Ifr̸=0, writetρ=ze(ρ)·s, in which case

Pr[ze *′* (*ρ,**M***)*·**v***=**0**] = Pr[***M**·**r***=***t**ρ*]*.*

Since***r**̸*=**0**, there exists an invertible matrix***R**∈*F *r×r* such that***R**·**r***=***e₁***. Right-multiplication by***R***preserves the property that the columns spanF *t*, hence the map***M**7→**MR***is a bijection on*Mt,r*and therefore Pr[***Mr***=***t**ρ*] = Pr[***Me₁*** =***t**ρ*]*.*

Denote by***m₁*** the first column of***M***, so***Me₁*** =***m₁***. We upper boundPr[***m₁*** =***t**ρ*].

If***t**ρ̸*=**0**, then for every***u**∈*F *t* *\{***0***}*the probabilityPr[***m₁*** =***u***]is the same by left-invariance: for any invertible***L**∈*F *t×t*, the map***M**7→**LM***is a bijection on*Mt,r*and sends***m₁*** to***L**·**m₁***. HencePr[***m₁*** =***u***]is constant over all nonzero***u***, and therefore

<u>1</u> Pr[***m₁*** =***t**ρ*]*≤* *t* *.* *|*F*| −*1

If***t**ρ*=**0**, then *t−* ∏1 *r−*1 *i*

||||t,r−1|t−|r−1|i|−t||
|---|---|---|---|---|---|---|---|---|
||M←M||t,r|i=0|r|i|||
|t×(r−1) −1|M←M|t ρ ρ|t|t|−t|t||F| −|F| |F| −|F|||F| |F||

<u>|M | |F| −|F|</u> Pr [***m₁*** =**0**] = = *≤|*F*|,* *t,r |M | |*F*| −|*F*|*

where the equality follows by observing that fixing***m₁*** =**0**leaves a uniformly random matrix *r−*1 *i r−*1 inF whose columns spanF, and the inequality holds since for all*i*,*r i≤r*= *|*F*|*.

Combining the two subcases, for all***t** ∈*F we obtain {} <u>1 1</u> Pr [***Mr***=***t***]*≤*max*,|*F*|* =*,* *t,r |*F*| −*1 *|*F*| −*1

and hence, for***r**̸*=**0**, *′*<u>1</u> Pr[ze (*ρ,**M***)*·**v***=**0**]*≤* *t* *.* *|*F*| −*1

### 9.3 Code-switching complexity

We define succinct linear forms induced by the generating matrices of (the encoding map of) the code. The complexity of computing such succinct linear forms will directly impact the prover and verifier time of the code-switch protocol that we design.

**Definition 9.4.***LetC ⊆*Σ *m* *≡*(F *ι* ) *m* *be an*F[*-additive code with a zero-knowledge encoding*] Enc*C*:F *ℓ* *×*F *r* *→*Σ *m* *and generating matrix**G**C*= ***G*** # *C* ***G*** $ *C* *. We define two linear forms:*

•sl # *Ctakes as input a statex∈*[*m·ι*]*and outputs**G*** # *C* [*x,·*]*∈*F *ℓ* *(**G*** # *C* *’sx-th row);* •sl $ *Ctakes as input a statex∈*[*m·ι*]*and outputs**G*** $ *C* [*x,·*]*∈*F *r* *(**G*** $ *C* *’sx-th row).* *(A minor abuse of notation for simplicity:* sl # *C,*sl $ *Cactually depend on*Enc*Crather thanC.)*

In our protocols the prover time will depend on*t* sl# and*t* sl$, and the verifier time will depend *C C* on*t* *⊙* (sl#) and*t* sl$ for some*k∈*N. *k C C* For some linear codes such as Reed–Solomon codes over explicit domains, the prover costs can be linear*O*(*ℓ*+ log*m*+*r*)while the verifier costs can be logarithmic*O*(log*m*+*r*)(this fact is implicit in [ACFY25; NA25] and explicit in [BFRW25]).

**Lemma 9.5.***LetC* :=RS[F*,L,ℓ*+*r*]*be a Reed–Solomon code with|L|*=*mand such that there* *exists a bijectionφ*: [*m*]*→ L computable inO*(log*m*)*field operations.* 2 *There exists ar-query* *perfect zero-knowledge encoding forCsuch that: (i) ifℓis a power-of-two, for everyi∈*[log*ℓ*]*,* *t* *⊙* (sl#) =*O*(*ℓ/*2 *i* +*i*+ log*m*)*; (ii)t* sl$ =*O*(*r*+ log*m*)*.* *i C C*

*Proof.*Consider the encoding mapEnc*C*:F *ℓ* *×*F *r* *→C*that takes as input(***f**,**r***), interprets them as coefficients of polynomials ***f***ˆ, ***r***ˆand outputs(***f***ˆ+*X* *ℓ* *· **r***ˆ)(*L*). From prior work (e.g. [BCL22]), Enc*C*is a*r*-query perfect zero-knowledge encoding for*C*. The encoding matrix ofEnc*C*is***G**C*= [***G*** # *C* *,**G*** $ *C*] = [*φ*(*x*) *j−*1] *x∈*[*m*]*,j∈*[*ℓ*+*r*]. Assume that*ℓ*is a power of two,*x∈*[*m*],***γ**∈*F *i*, and consider*⊙i*sl # *C*(*x,**γ***). By definition, for every***c**∈{*0*,*1*}* log*ℓ−i*, ∑ # (*⊙i*sl # *C*(*x,**γ***))[***c***] = eq(***b**,**γ***)*·**G**C*[*x,**b**,**c***] ***b**∈{*0*,*1*}i* ∑ ∑ *b* *t* *·*2*t−*1+ ∑ *c* *t* *·*2*i*+*t−*1 = eq(***b**,**γ***)*·φ*(*x*)*t∈*[*i*] *t∈*[log*ℓ−i*] ***b**∈{*0*,*1*}i* ∑ ∏*t−*1∏*i*+*t−*1 = eq(***b**,**γ***)*· φ*(*x*) *b* *t* *·*2 *· φ*(*x*) *c* *t* *·*2

***b**∈{*0*,*1*}it∈*[*i*] *t∈*[log*ℓ−i*]     ∏*i*+*t−*1∑ ∏*t−*1 =  *φ*(*x*) *c* *t* *·*2 *·*  eq(***b**,**γ***)*·* ((1*−bt*)*·*1 +*bt·φ*(*x*) 2 ) *t∈*[log*ℓ−i*] ***b**∈{*0*,*1*}it∈*[*i*]   ∏*i*+*t−*1∏*t−*1 =  *φ*(*x*) *c* *t* *·*2 *·* (1*−γt*+*γt·φ*(*x*) 2 )*.* *t∈*[log*ℓ−i*] *t∈*[*i*] ∑ Where we have used the fact that one of the quantities was multilinear in***b***and***b***eq(***b**,**γ***)*·*ˆ(*p **b***) = ˆ(*p **γ***)for any multilinear polynomialˆ. This yields an algorithm to compute *p ⊙i*sl # *C*(*x,**γ***): 2 This class includes many commonly used Reed–Solomon codes over finite field, but excludes (for example) Reed– Solomon codes where*L*is a random subset of the field.

1.Compute*φ*(*x*)in*O*(log*m*)field operations.
∏ *t−*1

2.Compute

|(1−γ|+γ ·φ(x)|)inO(i)field operations.||
|---|---|---|---|
|t∈[i]|t t|2||
||c ·2|||
|t∈[logℓ−i]||c∈{0,1}||
|||i|ℓ+i−1 j∈[r]|

(∏ *i*+*t−*1 )

3.Compute *φ*(*x*)*t*
log*ℓ−i* in*O*(*ℓ/*2 *i* )field operations using a dynamic pro-

gramming algorithm (e.g., [VSBW13; BCFFMMZ25]).

4.Compute the final expression in*O*(*ℓ/*2)field operations. To conclude the lemma, one can see that for every*x∈*[*m*],***G***
$ *C* [*x,·*]=[*φ*(*x*)] can be computed in*O*(log*m*+*r*)field operations.

### 9.4 Code-switching IOR

We describe an IOR from*RC,C* zk*,***sl** to*RC′,C* zk*,***sl** *′*.

**Theorem 9.6.***Let:* •*n∈*N*be a number of functions.* •*t,t*ood*∈*N*be repetition parameters.* •*C⊆*Σ *m ι m*

|≡(F|) be anF-additive code with zero-knowledge encodingEnc||||×F|→Σ.|
|---|---|---|---|---|---|---|
|′ ′ ′ m|ι m||||C|ℓ r|
|m m|ι m i∈[n] ◦,i 1+t t|i∈[n] +t·ι ×(ℓ+ℓ)|ℓ i|t ×ℓ|C t ←|ℓ r →|
|← →|t ×ℓ|→ ←,|t ×ℓ →,|||←|

*C*:F *ℓ r m* *′ ′ m′ι′m′ℓ r′* •*C ⊆*(Σ) *≡*(F) *be a*F*-additive code with a zero-knowledge encoding*Enc *′* :F *×*Fzk*→* *′*

(Σ)*.*
zk zk zk zk •*C*zk*⊆*Σzk zk*≡*(F) *be a*F*-additive code with a zero-knowledge encoding*Enc zk :F *×*F *→* Σzk zk*.* •**sl**= (sl*,*(sl*i*)*,*(sl))*where*sl*∈⟨*F *|,*sl *∈⟨*F *ℓ* zk*|,*sl *◦,i∈⟨*F *i* zk*|.* •*Let*ze: *D*ze*→*Food*be a zero-evader with errorε*zero*and let*ze*↔*: *D*ze*→*Food*denote the* *firstt*ood*coefficients of*ze*(skipping the first one).* •*Let*zeood: *D*ood*→*Food zk*be a zero-evader with errorε*ood*. Write*zeood= (zeood*,*zeood)*where* zeood: *D*ood*→*Food*and*zeood: *D*ood*→*Food zk*denote the first and last components of*zeood*. For* *i i* *everyi∈*[*t*ood]*denote by*zeood*(resp.*zeood*) the zero-evader obtained by restricting*zeood*(resp.* zeood*) to thei-th row.* *Define*

*′* :=ze[ *←,i* # sl *×*(sl)*,*(zeood)*i∈*[*t* ood] *,*(sl*C*)*i∈*[*t*]*,l∈*[*ι*]] *′n*

||:=ze sl|[(sl|) ,(0|(sl|))|
|---|---|---|---|---|---|
||′|′ C,C ,sl|i∈[t] i i∈[n] ′n+1 C ,C ,sl ′ ′|◦,i|i∈[t],l∈[ι] i∈[n]|
|′ ′||′||||

+1*↔* ze*→,ii∈*[*t*ood] *ℓ* zk*−r* $ *C i∈*[*t*]*,l∈*[*ι*]] ( ood ) **sl** := sl*,*(*×*(sl))*,*sl*,*(sl)*,*slid*.*

*Construction 9.7 is an IOR fromR* zk *toR ′* zk *′ with the following properties.*

•*Round complexity:* 2*.* •*Prover communication (in field elements):m ·ι* +*m*zk*·ι*zk+*t*ood*. Of these,* **–***m ·ι are sent as an oracle over*Σ*,* **–***m*zk*·ι*zk*are sent as an oracle over*Σzk*, and* **–***t*ood*are sent as a non-oracle message.* •*Query complexity:tqueries to the first input oracle.* *′* ∑ •*Prover time (in field operations):O*(tenc(*C*) +tenc(*C*zk) +teval(ze) +teval(zeood) +*i∈*[*n*]*t*sl *i* )*.* •*Verifier time (in field operations):O*(teval(ze) +*t*ood)*.*

•**Round-by-round security:** *For everyδ,δ* *′* *,δ*zk*∈*(0*,*1)*, Construction 9.7 has RBR knowledge*

||δ,δ|δ ,δ|||
|---|---|---|---|---|
||C,C ,sl|C ,C ,sl|||
|′ ′|2||t|′ ′|

˜*δ,δ*zk˜*δ* *′* *,δ*zk *soundness with relaxation*(*R* zk *, R′ ′*)*and errors* zk () <u>(|Λ(C,δ)|·|Λ(Czk,δzk)|)</u>*≡n*+1 *·ε*ood*,*(1*−δ*)*,|*Λ(*C ,δ*)*|·|*Λ(*C*zk*,δ*zk)*|·ε*zero*.* 2

*The total extraction time isO*(tenc(*C*))*.* •**Zero-knowledge:** *If*zeood*is a*(*ℓ*zk*−r,ζ*ze)*-private zero-evader,C* *′* *has at* *′* *-query zero-knowledge* *encoding with errorζC′, andC*zk*has at*zk*-query zero-knowledge encoding with errorζ*

|||C|
|---|---|---|
|≤(t, t,t)|C|C|

zk *, then,* *n′* zk *for every**t**∈*N*, Construction 9.7 is HVZK for*D *with errorζ ′* +*ζ*ze+*ζ* zk *and query* *complexity*(*t,**t***)*.*

### Construction 9.7.

•**Inputs.**The verifier receives explicit input**x**= ((*µ,*st*,*(st*i*)*i∈*[*n*])*,*((***µ**i*)*i∈*[*n*]*,*(st*◦,i*)*i∈*[*n*]))and oracle access to implicit input**y**= (*f,*(*ξi*)*i∈*[*n*]). In the honest case, the prover receives as input **x**and**y**as well as witness**w**= (***f**,**r**,*(***ξ**i,**r**i*)*i∈*[*n*])such that(**x***,***y***,***w**)*∈RC,C* zk*,***sl**.

### •Interaction phase.

*′ m′m*

1.**Send witness.**The prover sends*g∈*(Σ) and*s∈*Σzk zk. In the honest case, the
*′ r′ℓ*zk*−r ′′ r*zk*′*

|′|r|ℓ −r|′′ r||
|---|---|---|---|---|
|′′|||||
|||||t|

prover samples***r** ←*F,***s**←*F,***r** ←*F and computes*g* :=Enc*C′* (***f**,**r***)and *s* :=Enc*C* zk ((***r**,**s***)*,**r***).

2.**Out-of-domain samples.**The verifier samples and sends*ρ*ood*←D*ood.
3.**Out-of-domain answers.**The prover sends***y**∈*Food. In the honest case the prover computes
  ***f***   ***y*** :=zeood(*ρ*ood)*·* ***r****.* ***s***

4.**In-domain queries and batching.**The verifier samples and sends*x₁,...,xt←*[*m*]and *ρ←D*ze. Set***ν*** :=ze(*ρ*)and for*i∈*[*t*], let***x**i*:=binary(*xi*).
•**Decision phase.**The verifier queries*f*(*x₁*)*,...,f*(*xt*)*∈*Σ, and computes ∑ ∑ ∑

||ν ·y|+|ν|·f(x|).||
|---|---|---|---|---|---|---|
||1+i|i|1+t|+i·ι+l|i l||
|i∈[t|]|i∈[t] l∈[ι]|||||
|′n+1||i∈[t|] ,l|t,l l∈[ι]||j,l|

*µ* *′* :=***ν₁** ·µ*+ ood ood

The verifier further setsst *′* :=st := (*ρ,*st*,*(*ρ*ood) ood *,*(*x₁,...,x*)), where*x* :=*ι·xj*+*l*. The verifier outputs the following new explicit instance and implicit instance and in the honest case the prover outputs the following new witness:

|′|′ ′||n ′n+1|i i∈[n]|◦,i i∈[n]|
|---|---|---|---|---|---|
|′|i i∈[n]|||||
|′|′|i i i∈[n]|′′|||

**x** := ((*µ,*st*,*(***ν₁**,*st₁)*,...,*(***ν₁**,*st)*,*sl)*,*((***µ***)*,*(st))*,*(0*,*0 *ℓ* zk

))*,*(9)
**y** := (*g,*(*ξ*)*,s*)*,*

### w := ((f,r),(ξ,r),((r,s),r)).

**Completeness.**We show that the construction is perfectly complete. In an honest execution ∑ *µ*=*⟨**f**,*sl(st)*⟩*+ *⟨**ξ**i,*sl*i*(st*i*)*⟩* *i∈*[*n*] *←,i →,i* *∀i∈*[*t*ood] : *yi*=*⟨*(***f**,**r**,**s***)*,*zeood(*ρ*ood)[*i*]*⟩*=*⟨**f**,*zeood(*ρ*ood)*⟩*+*⟨*(***r**,**s***)*,*zeood(*ρ*ood)*⟩*

*∀i∈*[*t*]*,∀l∈*[*ι*] : *f*(*xi*)*l*=*⟨**f**,**G*** # *C* [*xi,l,·*]*⟩*+*⟨**r**,**G*** $ *C*[*xi,l,·*]*⟩* =*⟨**f**,**G*** # *C* [*xi,l,·*]*⟩*+*⟨*(***r**,**s***)*,*(***G*** $ *C*[*xi,l,·*]*,***0**)*⟩.*

By linearity then, 〈 〉 ∑ *←,i* ∑ ∑ *′* #

|µ = f,ν₁ ·sl(st) +|||ν|·ze (ρ|) +|ν|·G|[x ,·]|
|---|---|---|---|---|---|---|---|---|
|i∈[n]|i|i∈[t i i|1+i]||i∈[t] l∈[ι]|1+t|+i·ι+l|C i,l|
||i∈[t|1+i]|→,|i∈[t] l∈[ι]|1+t|+i·ι+l|C i,l||

1+*i* ood ood 1+*t*ood+*i·ι*+*l C i,l* ood ∑ + *⟨**ξ**,**ν₁** ·*sl (st)*⟩*

〈 〉 ∑ *i* ∑ ∑ + (***r**,**s***)*, **ν** ·*zeood(*ρ*ood) + ***ν*** ood *·*(***G*** $ [*x,·*]*,***0**)*.* ood

### 9.5 Zero-knowledge

**Lemma 9.8.***If*zeood*is a*(*ℓ*zk*−r,ζ*ze *′ ′*

|)-private zero-evader,C|has at|-query zero-knowledge encoding|
|---|---|---|
|||C|
|≤(t, t,t)|C||

*with errorζC′, andC*zk*has at*zk*-query zero-knowledge encoding with errorζ* zk *, then, for every**t**∈*N *n* *,* *′* zk *Construction 9.7 is HVZK for*D *with errorζC′* +*ζ*ze+*ζ* zk *and query complexity*(*t,**t***)*.*

### Proof.We describe the simulatorSfor Construction 9.7.

**S** **y***,D*

(**x**):
1.Parse**y**as**y**= (*f,*(*ξi*)*i∈*[*n*]).
2.Sample*x₁,...,xt←*[*m*]and*ρ←D*ze.
3.Sample(*ρ*ood*,**y***)*←***S**ze
ood.

4.Query*f*(*x₁*)*,...,f*(*xt*)and derive**x**
*′* as in Equation 9.

5.Run*D*on**x**
*′*, answering queries to**y** *′* as follows:

**–**When*D*queries one of(*ξi*)*i∈*[*n*], query the corresponding oracle accordingly (denote these answers as*Q**ξ***). **–**When*D*queries*g*, answer according toSim*C′* (denote these answers as*Qg*). **–**When*D*queries*s*, answer according toSim*C* zk (denote these answers as*Qs*).

6.Letoutdenote*D*’s output.
7.Output(*ρ,*(*x₁,...,xt*)*,*(*f*(*x₁*)*,...,f*(*xt*))*,Q**ξ**,Qg,Qs,**y**,*out). The proof follows by a sequence of hybrids*H₀,...,H₃*. The first hybrid*H₀* is the real experi-
ment. In the second hybrid*H₁*, the distribution of(*ρ*ood*,**y***)is replaced to be sampled by**S**ze ood; the statistical distance between*H₀* and*H₁* is then bounded by*ζ*ze. In the third hybrid*H₂*, the queries to*g*are replaced by answers according toSim*C′*; the statistical distance between*H₁* and*H₂* is then bounded by*ζC′*. In the fourth hybrid*H₃*, the queries to*s*are replaced by answers according to Sim*C* zk, and thus the experiment is simulated experiment; the statistical distance between*H₂* and *H₃* is then bounded by*ζC* zk.

### 9.6 Round-by-round knowledge soundness

**Lemma 9.9.***For everyδ,δ* *′* *,δ*zk*∈*(0*,*1)*, Construction 9.7 has RBR knowledge soundness with*

|δ,δ|δ ,δ|||
|---|---|---|---|
|C,C ,sl|C ,C|,sl||
|′|′||′ ′|

˜*δ,δ*zk˜*δ* *′* *,δ*zk *relaxation*(*R* zk *, R′ ′*)*and errors* zk () <u>(|Λ(C,δ)|·|Λ(Czk,δzk)|)</u> 2 *t ≡n*+1 *·ε*ood*,*(1*−δ*)*,|*Λ(*C ,δ*)*|·|*Λ(*C*zk*,δ*zk)*|·ε*zero*.* 2

### The total extraction time isO(tenc(C)).

*Proof.*We give notation, describe the extractors, describe a state function, and finally we establish the RBR knowledge soundness errors (based on the extractor and state function).

**Notation.**Let**x**= ((*µ,*st₀*,*(st*i*)*i∈*[*n*])*,*(***µ**i,*st*◦,i*)*i∈*[*n*])and**y**= (*f,*(*ξi*)*i∈*[*n*]). A complete transcript of the protocol has the formtr= ((*g,s*)*,ρ*ood*,**y**,*(*x₁,...,xt,ρ*)).

**Extractors.**We describe the round-by-round extractors from the last round to the first.

1.**Final round.E**rbr(**x***,***y***,*tr*∥*(*x₁,...,xt,ρ*)*,*w)outputs the witnessw.
2.**Out-of-domain samples.E**rbr(**x***,***y***,*tr*∥ρ*ood*,*w):
()

(a)Parsewas (¯*g,**g**,**r***
*′* )*,*(*ξ*¯*i,**ξ**i,**r**i*)*i∈*[*n*]*,*(¯*s,**s**,**r*** *′′* ).

(b)Parse***s***as(***r**,**s***
*′* )*∈*F *r* *×*F *ℓ* zk*−r*.

(c)Compute( *f*¯ :=Enc*C*(***g**,**r***).
)

(d)Output (*f,*¯ ***g**,**r***)*,*(*ξ*¯*i,**ξ**i,**r**i*)*i∈*[*n*].
3.**Initial round.**
()

|¯ f,r),(ξ¯ (f,|,ξ|,r )|
|---|---|---|
||i i|i i∈[n]|
|i i i∈[n] ∗|i i∈[n]||

(a)Parsewas.
()

(b)Set**w** := (***f**,**r***)*,*(***ξ**,**r***).
(c)Set**y** *∗*
:= (*f,*¯ (*ξ*¯)).

(d)Output(**w***,***y**).
**The state function.**We define a state functionKState.

˜*δ,δ*zk

0.**Initial transcript:** We setKState(**x***,***y***,∅,*w) = 1if and only if(**x***,***y***,*w)*∈ R*
*C,C*zk*,***sl**, that is

() w= (*f,*¯ ***f**,**r***)*,*(*ξ*¯*i,**ξ**i,**r**i*)*i∈*[*n*]

### is such that:

|),(f,|¯ ξ¯ ,..., ξ¯ ))≤(δ,δ|,...,δ|
|---|---|---|
|n|1 n||
|C|i|C i i|
|◦,i ◦,i|i i||
|i∈[n]|i i i||

•∆((*f,ξ₁,...,ξ*zk zk);

- *f*¯=Enc (***f**,**r***),*∀i∈*[*n*] *ξ*¯ =Enc
zk (***ξ**,**r***);

•*∀i∈*[*n*]sl (st)*·**ξ*** =***µ***; ∑ •*⟨**f**,*sl(st)*⟩*+ *⟨**ξ**,*sl (st)*⟩*=*µ*.

1.**Out-of-domain samples:** The transcript has the formtr= ((*g,s*)). The verifier samples *ρ*ood*←D*ood. We setKState(**x***,***y***,*tr*∥ρ*ood*,*w) = 1if and only if either of the following hold:

()

(a)w= (*f,*¯ ***f**,**r***)*,*(*ξ*¯*i,**ξ**i,**r**i*)*i∈*[*n*]is such that:

|),(f,|¯ ξ¯ ,..., ξ¯|))≤(δ,δ|,...,δ|);||
|---|---|---|---|---|---|
|n|1 i|C i|i|||
|◦,i ◦,i|i i|||||
|i∈[n]|i i i||′ ′′|′ ′′|C|
|C ′′||C|′|′|′′|
 •∆((*f,ξ₁,...,ξn* zk zk
- *f*¯=Enc*C*(***f**,**r***),*∀i∈*[*n*] *ξ*¯ =Enc
zk (***ξ**,**r***); •*∀i∈*[*n*]sl (st)*·**ξ*** =***µ***; ∑ •*⟨**f**,*sl(st)*⟩*+ *⟨**ξ**,*sl (st)*⟩*=*µ*.

(b)there exist distinct(***g₀**,**s₀***)*̸*= (***g₁**,**s₁***)and(***r₀**,**r₀**,**r₁**,**r₁***)such that∆(*g,*Enc *′* (***g₀**,**r₀***
*′* ))*≤δ* *′*

and∆(*s,*Enc zk (***s₀**,**r₀***))*≤δ*zk,∆(*g,*Enc *′* (***g₁**,**r₁***))*≤δ* and∆(*s,*Enc*C* zk (***s₁**,**r₁***))*≤δ*zkand [] [] ***g₀ g₁*** zeood(*ρ*ood)*·* =zeood(*ρ*ood)*·.* ***s₀ s₁***

2.**In-domain samples:** The transcript has the formtr= ((*g,s*)*,ρ*ood*,**y***). The verifier samples
*x₁,...,xt←*[*m*]. We setKState(**x***,***y***,*tr*∥*(*x₁,...,xt*)*,*w) = 1if and only if
() w= (¯*g,**g**,**r*** *′* )*,*(*ξ*¯*i,**ξ**i,**r**i*)*i∈*[*n*]*,*(¯*s,**s**,**r*** *′′* )

### is such that:

•∆((*g,ξ₁,...,ξn,s*)*,*(¯*g, ξ*¯1*,..., ξ*¯*n,*¯))*s ≤*(*δ*
*′* *,δ*zk*,...,δ*zk);

•¯= *g* Enc *′* *′*

|(g,r ),∀i∈[n] ξ¯|=Enc|(ξ|,r ),¯= s|(s,r );|
|---|---|---|---|---|
|C ′|i|C|i i|C ′′|
|i∈[n]|i i i||||
|◦,i ◦,i|i i||||
|||i|||
||C i,l|C|i,l|i l|

zk Enc zk *′′* ∑ •***g**,*sl(st)*⟩*+ *⟨**ξ**,*sl (st)*⟩*=*µ*;

•*∀i∈*[*n*],sl (st)*·**ξ*** =***µ***;

•*∀i∈*[*t*ood],*⟨*(***g**,**s***)*,*zeood(*ρ*ood)[*i*]*⟩*=*y*;

•*∀i∈*[*t*]*,l∈*[*ι*],*⟨**g**,**G*** # [*x,·*]*⟩*+*⟨**s**,*(***G*** $ [*x,·*]*,***0**)*⟩*=*f*(*x*).

3.**Combination randomness:** The transcript has the formtr= ((*g,s*)*,ρ*ood*,**y**,*(*x₁,...,xt*)). The verifier samples*ρ←D*ze. We setKState(**x***,***y***,*tr*∥ρ,*w) = 1if and only if
() w= (¯*g,**g**,**r*** *′* )*,*(*ξ*¯*i,**ξ**i,**r**i*)*i∈*[*n*]*,*(¯*s,**s**,**r*** *′′* )

### is such that:

•∆((*g,ξ₁,...,ξn,s*)*,*(¯*g, ξ*¯1*,..., ξ*¯*n,*¯))*s ≤*(*δ*
*′* *,δ*zk*,...,δ*zk);

|(g,r ),∀i∈[n] ξ¯|=Enc||(ξ ,r ),¯=|
|---|---|---|---|
|C ′|i|C|i i|
|◦,i ◦,i|i i|||

•¯= *g* Enc *′* *′* zk *s* Enc*C* zk (***s**,**r*** *′′* );

•*∀i∈*[*n*]sl (st)*·**ξ*** =***µ***;

•the following holds 〈 〉 ∑ *←,i* ∑ ∑ #

|||ν|(ρ ·ze|) +|ν|·G [x ,·]|
|---|---|---|---|---|---|---|
||i∈[t|1+i]||i∈[t] l∈[ι]|1+t +i·ι+l|C i,l|
|i i∈[n]|i i||||||
||→,||||||
|1+i i∈[t]|||i∈[t] l∈[ι]|1+t +i·ι+l|C i,l||

*µ* *′* = ***g**,**ν₁** ·*sl(st) +1+*i* ood ood 1+*t* ood+*i·ι*+*l C i,l* ood ∑ +***ν₁** · ⟨**ξ**,*sl (st)*⟩*

〈 〉 ∑ *i* ∑ ∑ + ***s**, **ν** ·*zeood(*ρ*ood) + ***ν*** ood *·*(***G*** $ [*x,·*]*,***0**)*.* ood

**Bounding the errors.**We bound the RBR errors for the protocol.

1.**Out-of-domain samples.**We show that
[] KState(**x***,***y***,*tr*,***E**rbr(**x***,***y***,*tr*,*w)) = 0 <u>(|Λ(C</u> *′* <u>,δ</u> *′* <u>)|·|Λ(Czk,δzk)|)</u> 2 Pr *∃*w: *≤ ·ε*ood*.* *∧*KState(**x***,***y***,*tr*∥ρ*ood*,*w) = 1 2

Note that Item 1a is independent of*ρ*ood, and so it cannot hold. It must then be that Item 1b holds, but the probability of this holding is bound by Lemma 9.1.

2.**In-domain samples.**We show that
[]

|KState(x,y,tr,E||(x,y,tr,w)) = 0|||
|---|---|---|---|---|
|||rbr||t|
|′|t ◦,i|◦,i|t i i|rbr|
|||||i|
|t|||||
|′|∗||||

Pr *∃*w: *≤*(1*−δ*)*.* *∧*KState(**x***,***y***,*tr*∥*(*x₁,...,x*)*,*w) = 1

Fixwsuch thatKState(**x***,***y***,*tr*∥*(*x₁,...,x*)*,*w) = 1andKState(**x***,***y***,*tr*,***E** (**x***,***y***,*tr*,*w)) = 0. Then, it must be that for*i∈*[*n*]we have thatsl (st)*·**ξ*** =***µ*** and this must also hold in Item 1a.

Note that∆((*g,s*)*,*(¯*g,*¯))*s ≤*(*δ,δ*zk), and so by Item 1b there must be a unique choice of(***g**,**s***) inwsuch that for every*i∈*[*t*ood]it holds that*⟨*(***g**,**s***)*,*zeood(*ρ*ood)[*i*]*⟩*=*y* (note also that every condition involving*x₁,...,x* only depends on the(***g**,**s***)portion of the witness).

Now, suppose that for this(***g**,**r**,**s**,**r***)it held that ∑ *⟨**g**,*sl(st)*⟩*+ *⟨**ξ**i,*sl*i*(st*i*)*⟩*=*µ,* *i∈*[*n*]

|∗ ′|C|∗|||
|---|---|---|---|---|
||rbr i l|i l|C i,l|∗ C i,l|

and parse***s***= (***r**,**s***). Let *f*¯=Enc (***g**,**r***). It must be that∆(*f, f*¯)*> δ*, as else it contradicts the assumptionKState(**x***,***y***,*tr*,***E** (**x***,***y***,*tr*,*w)) = 0. But then, the probability that for every *i∈*[*t*]*,l∈*[*ι*]it holds that*f*(*x*) = *f*¯(*x*) =*⟨**g**,**G*** # [*x,·*]*⟩*+*⟨**r**,**G*** $ [*x,·*]*⟩*is at most(1*−δ*) *t*.

3.**Combination randomness.**We show that
[] KState(**x***,***y***,*tr*,***E**rbr(**x***,***y***,*tr*,*w)) = 0*′ ′ ≡n*+1 Pr *∃*w: *≤|*Λ(*C,δ*)*|·|*Λ(*C*zk*,δ*zk)*|·ε*zero*.* *∧*KState(**x***,***y***,*tr*∥ρ,*w) = 1

Fixwsuch thatKState(**x***,***y***,*tr*,***E**rbr(**x***,***y***,*tr*,*w)) = 0. Then, it must be that at least one of the three conditions are not satisfied, namely either: ∑ *⟨**g**,*sl(st)*⟩*+

||⟨ξ ,sl|(st )⟩̸=µ,|||
|---|---|---|---|---|
||i i∈[n]|i i|||
|||i|||
|′ ′|C i,l||C i,l|i l|

### •or for somei∈[tood]it holds that⟨(g,s),zeood(ρood)[i]⟩̸=y.

•or for some*i∈*[*t*]*,l∈*[*ι*]it holds that*⟨**g**,**G*** # [*x,·*]*⟩*+*⟨**s**,*(***G*** $ [*x,·*]*,***0**)*⟩̸*=*f*(*x*).

Then, the probability thatKState(**x***,***y***,*tr*∥ρ,*w) = 1is at most*ε*zero. Taking a union bound over the *|*Λ(*C,δ*)*|·|*Λ(*C*zk *≡n*+1 *,δ*zk)*|*possible choices ofwconcludes the proof.

### 9.7 Proof of Theorem 2

We combine Construction 6.3 and Construction 9.7 to give a formal statement and proof of Theo- rem 2.

**Theorem 9.10.***Let:* •*n∈*N*;* •*k,t,t*ood*∈*N*;*

|m|ι m|||||C ℓ|r m|
|---|---|---|---|---|---|---|---|
|m m|ι|m||||C|ℓ r|
|′ ′ m|′ m i i∈[n] 1+t t|ι m ◦,i i∈[n] +t·ι ×(ℓ+ℓ|)|ℓ i|t ×ℓ|C t ←|ℓ r →|
|←|t|×ℓ|→|t ×ℓ||←,|→,|

•*C⊆*Σ *≡*(F) *be an*F*-additive code with a zero-knowledge encoding*Enc :F *×*F *→*Σ*;* zk zk zk zk •*C*zk*⊆*Σzk zk*≡*(F) *be a*F*-additive code with a zero-knowledge encoding*Enc zk :F *×*F *→* Σzk zk*;* *′ ′ ′ ′* •*C ⊆*(Σ) *≡*(F) *be a*F*-additive code with zero-knowledge encoding*Enc *′* :F *×*Fzk*→* *′*

(Σ)*;*
•**sl**= (sl*,*(sl)*,*(sl))*where*sl*∈⟨*F *|,*sl *∈⟨*F *ℓ* zk*|,*sl *◦,i∈⟨*F *i* zk*|;* •ze: *D*ze*→*Food*be a zero-evader with errorε*zero*, and let*ze*↔*: *D*ze*→*Food*denote the first* *t* ood*coefficients of*ze*(skipping the first one);* •zeood: *D*ood*→*Food zk*be a zero-evader with errorε*ood*, and write*zeood= (zeood*,*zeood)*with* ood ood zk *i i* zeood: *D*ood*→*F *and*zeood: *D*ood*→*F*. Fori∈*[*t*ood]*, denote by*zeood*and*zeood*the* *corresponding row-restricted zero-evaders.* *Define*

*′* :=ze[ *←,i* # sl *×*(*⊙k*sl)*,*(zeood)*i∈*[*t* ood] *,*(sl*C*)*i∈*[*t*]*,l∈*[*ι*]]*,* *′n*

|sl|:=ze|)|,(0 (sl|))||||
|---|---|---|---|---|---|---|---|
||′|i∈[t i i∈[n] C ,C ,sl|] C ,C ,sl|i∈[t],l∈[ι] j∈[k] ′n+k+1|◦,i i∈[n]|j∈[k+1] ′ ′||
|′ ′|||′||||k +1|

+*k*+1*↔*[(slze*→,ii∈*[*t*ood] *ℓ* zk*−r* $ *C i∈*[*t*]*,l∈*[*ι*]] ( ood ) **sl** := sl *′* *,*(*×*(sl))*,*(*×*(slze*⋆* *ℓ* ))*,*sl*,*(sl)*,*(slid)*.* zk

*There exists an IOR fromR≡*2*k toR ′* zk *′ with the following properties:* zk

•*Round complexity:k*+ 3*.* •*Prover communication (in field elements):k·*(*ℓ*zk+*m*zk*·ι*zk) + 1 +*m ·ι* +*m*zk*·ι*zk+*t*ood*. Of* *these,m ·ι are sent as an oracle over*Σ*,*(*k*+ 1)*·m*zk*·ι*zk*are sent as an oracle over*Σzk*and* *k·ℓ*zk+*t*ood+ 1*are sent as non-oracle messages.* •*Query complexity:tqueries to the first input oracle.* *k* ∑ *′* •*Prover time (in field operations):O*(*ℓ·*2 +*t*sl+*i∈*[*n*]*t*sl *i* +tenc(*C*) +*k·*tenc(*C*zk) +teval(ze) + teval(zeood))*.* •*Verifier time (in field operations):O*(*k·ℓ*zk+teval(ze))*.* •**Round-by-round security:** *Forδ,δ* *′* *,δ*zk*∈*(0*,*1)*, the protocol has RBR knowledge soundness*

|δ,δ|δ ,δ|||||
|---|---|---|---|---|---|
|C|,C ,sl C ,C|,sl||||
|,δ)|·|Λ(C|,δ)||≡2|ℓ ·|Λ(C|,δ)|·|Λ(C|,δ)||
||F||||||F||j∈[k]|
|,δ)|·|Λ(C 2|,δ)|)|t|′ ′|||
||j∈[k]|≡2||||

˜*δ,δ*zk˜*δ* *′* *,δ*zk *with relaxation*(*R* *≡*2*k* *, R′ ′*)*with errors* zk zk  ()  *≡*2*k ≡n*+*k k−j ≡*2*k−*(*j−*1) *≡n*+*k* <u>|Λ(C</u> <u>zk zk zk zk zk</u> *, ϵ*mca(*C,δ*) +*,*      <u>(|Λ(C</u>*′ ′* <u>zk zk</u> 2*≡n*+*k*+1 *·ε*ood*,*(1*−δ*)*,|*Λ(*C ,δ*)*|·|*Λ(*C*zk*,δ*zk)*|·ε*zero

(∑ *k−j* ) *and extraction timeO* tcor(*C*) +tenc(*C*)*.* •**Zero-knowledge:** *Suppose that*char(F)*̸*= 2*,ℓ*zk*≥*2*, and:* **–**zeood*is a*(*ℓ*zk*−r,ζ*ze)*-private zero-evader;*

|C ′||C||
|---|---|---|---|
|C|n|C t,(t)|)|

**–**Enc *′ is at-query zero-knowledge encoding with errorζ ′;* **–**Enc zk *is at*zk*-query zero-knowledge encoding with errorζ* zk *.* *≤*(*t ,′* zk *j∈*[*k*+1] *Then, for every**t**∈*N*, the protocol is HVZK for*D *with errorζC′* +*ζ*ze+(*k*+1)*·ζC* zk *and simulator query complexity*(*t,**t***)*.*

*Proof.*LetIORsc: *R* *C* *≡*2*k,C,***sl***→RC,C*zk*,***sl**scbe the IOR from Theorem 6.2 and letIORcs: *RC,C*zk*,***sl**sc*→* zk *RC′,C* zk*,***sl** *′* be the IOR from Theorem 9.6 (with*n*+*k*mask oracles). DefineIOR :=IORcs*◦*IORsc. The round, communication, and time bounds follow by adding the corresponding bounds of the two theorems. The round-by-round knowledge soundness statement (including the error vector and extraction time) follows from Theorem 4.5 together with the two constituent RBR guarantees. *′*

||≤(t,|t,(t)|)|cs||
|---|---|---|---|---|---|
|∗ S||||cs ∗||
||i|||||
||∗|||||
|sc||C||||
|sc|cs|||||
|C|C|C|C||C|

zk *j∈*[*k*+1] For zero-knowledge, fix any*D∈*D, and let**S** be the simulator from the HVZK guarantee ofIORcs. Set*D* :=*D*cs. By the query bounds of**S**,*D* queries (i)*f*at most*t*times; (ii) the*i*-th original mask at most*t* times for*i∈*[*n*]; and (iii) each of the*k*masks introduced by sumcheck at most*t*zktimes. Hence*D* is in the query class required by Theorem 6.2. Applying that theorem gives a simulator**S** with error*k·ζ* zk and with exactly the claimed query complexity to the original implicit instance. Apply Theorem 4.5 toIOR andIOR. The composed simulator error is

(*k·ζ* zk ) + (*ζ ′* +*ζ*ze+*ζ* zk ) =*ζ ′* +*ζ*ze+ (*k*+ 1)*·ζ* zk *.*

## 10 Zero-knowledge IOPP for constrained codes

We construct a zero-knowledge IOPP for constrained codes. This yields a formal statement and proof of Theorem 4, and can be seen as a zero-knowledge variant (and generalization) of both WHIR [ACFY25] and Ligerito [NA25]. **Batched linear forms.**We are going to iteratively use the IOR from*R* *C* *≡*2*k,C,***sl**to*RC′,C*zk*,***sl***′* in ∑zk Theorem 9.10; in this IOR the prover incurs (among others) the cost*t*sl+*i∈*[*n*]*t*sl *i* associated to **sl**= (sl*,*sl₁*,...,*sl*n*). In particular, the second invocation after the first incurs this cost relative to the*new linear form***sl** *′* (defined in Theorem 9.10). A similar cost is also incurred by the verifier. In both cases, the prover and verifier costs associated tosl *′* involve*batch of linear forms*.

**Definition 10.1.***Let*sl*∈⟨*F *t×n* *|and letb∈*N*. We let*b(sl*,b*)*denote the number of field operation* ∑ *t×n b*

||i∈[b] i|i|t×n|b|b||||
|---|---|---|---|---|---|---|---|---|
|||ℓ||M|ℓ|m×ℓ M|b||
|i i∈[b]|i|T|i∈[b]|x|||i m||
|||||||||T|

*to compute **ν** ·*sl(st)*∈*F *given*(st₁*,...,*st)*and**ν**∈*F*. Note that*b(sl*,b*)*≤b·t*sl+*O*(*b·t·n*)*.*

For many linear forms (e.g., the one in Section 9.3) the cost to compute such batches can be much smaller than*O*(*b·t·n*). To see this, fix a matrix***M**∈*F and let*|**M**|*denote the number of field operations to compute***M**·**v***for any***v**∈*F. Letsl be linear form mapping *x∈*[*m*]to***M***[*x,·*]*∈*F. We argue that ( b()sl*,b*) =*O*(*b*+*|**M**|*). Fix*x₁,...,x* and***ν***. Then ∑ ∑ ***ν** ·**M***[*x,·*] =***M** · **ν**i∈*[*b*]*·**e**i*where for*i∈*[*m*], the vector***e** ∈*F is the unit

vector with1in position*i*and0everywhere else. This quantity can be computed in*O*(*b*+*|**M** |*) field operations, which is*O*(*b*+*|**M**|*)operations by the transposition principle [Bor57; Ber]. **Main theorem.**The main theorem in this section follows by iteratively applying the zero- knowledge sumcheck IOR in Section 6 and the zero-knowledge code-switching IOR in Section 9.

**Theorem 10.2.***Fix the following:* •*n∈*N*and*n*∈*N*with*n*≥*2*;* *m*i *ι*i*m*i*ℓ*i*r*i*m*i •*∀*i*∈*[n]*,C*i*⊆*Σ i *≡*(F) *with a zero-knowledge encoding*Enc*C* i :F *×*F *→*Σ i *;* *m ι*zk*m*zk*ℓ*zk*r*zk*m* •*C*zk*⊆*Σzk zk*≡*(F) *with a zero-knowledge encoding*Enc*C* zk :F *×*F *→*Σzk zk*withℓ*zk*≥* maxi*∈*[n]*r*i*;*

|i|i∈[n] ◦,i|i∈[n]||ℓ|i ℓ|◦,i t ×ℓ|||
|---|---|---|---|---|---|---|---|---|
|i i,|||||||||
|i|1+t|+t|||||||
|,|, t|×(ℓ +ℓ|)|||,|||
|n||k|i+1|i|||||
|j|i≤j i i|C|i ,C ,sl||n−1||||

•**sl₀** = (sl*,*(sl*i*)*i∈*[*n*]*,*(sl*◦,i*)*i∈*[*n*])*where*sl*∈⟨*F *ℓ* *|,*sl*i∈⟨*F *ℓ* zk*|,*sl *◦,i∈⟨*F *t* *i* *×ℓ*zk *|;* •*∀*i*∈*[n*−*1]*:* **–***k,t,t*ood i*∈*N*;* **–**ze : *D*ze*,*i*→*Food*,*i i*is a zero-evader with errorε*zero*,*i*;* **–**zeood i: *D*ood i*→*Food*,*i i zk*is a zero-evader with errorε*ood i*;* •*t*n*,t*zk*∈*N*;* •*setk* := 0*, and assume*2i+1*·ℓ ≥ℓ for every*i*∈*[n*−*1]*;* ∑ •*setK* := *k,N* :=*n*+*K and*(*K,N*) := (*K,N*n*−*1)*.* *There exists an IOPP forR≡*2*k*1*with the following properties.* 1 zk 0

•*Round complexity:K*+ 3*·*(n*−*1) + 2*rounds.* •*Prover communication (in field elements):* ∑ () *k*i*·*(*ℓ*zk+*m*zk*·ι*zk) + 1 + 2 *k* i+1 *·m*i+1*·ι*i+1+*m*zk*·ι*zk+*t*ood*,*i i*∈*[n*−*1]

+*m*n*·ι*n+*N·m*zk*·ι*zk+*ℓ*n+*r*n+*N·*(*ℓ*zk+*r*zk)*.*

### Of these:

∑ ∑ *N*+ i*∈*[n*−*1]*k*i **–**(*N*+i*∈*[n*−*1]*k*i)*·m*zk*·ι*zk*are sent as an oracle over alphabet*Σzk*,* *k* 2 *k* i+1 **–***∀*i*∈*[n*−*1]*,*2i+1*·m*i+1*·ι*i+1*are sent as oracles over alphabet*(Σi+1)*,* **–***m*n*·ι*n*are sent as an oracle over alphabet*Σn*,* ∑ **–**i*∈*[n*−*1] i zk ood*,*i n n zk zk)*are sent as non-oracle messages.*

|(k|·ℓ +t|+ 1) +ℓ|+r +N·(ℓ|+r||||
|---|---|---|---|---|---|---|---|
|i∈[n−1]|i i∈[n]|, i|n n|||||
|||||≡2||||
|k₁|i∈[n]|i∈[n−1]||i i|, i i||n|

∑ •*Query complexity: t* +*N·t*zk*oracle queries in total.* •*Prover time (in field operations):*  *k* i+1   ∑ ∑ tenc(*C* i+1 ) +*k*i*·*tenc(*C*zk)     *O* *ℓ₁ ·*2 +*t*sl+ *t*sl *i* +  +teval(zei) +teval(zeood i)  +tenc(*C*) +*N·*tenc(*C*zk)*.* +b(sl # *C,t ·ι*) +b(sl $ *C,t ·ι*) i i •*Verifier time (in field operations):*     *k*i*·ℓ*zk+teval(zei)  ∑ ∑  *⊙* sl # *,t ·ι*) +b(sl $ *,t ·ι*)   *O* *t⊙K* sl+ *t*sl *i* +  +b( *K−K*i *C* i i i *C* i i i  +tenc(*C*n) +*N·*tenc(*C*zk)*.* *i∈*[*n*] i*∈*[n*−*1] +b(*⊙K−K* i slze*←* ood*,*i *,t*ood*,*i) +b(slze*→* ood*,*i *,t*ood*,*i)

•**Round-by-round security:** *For everyδ*zk

|∈(0,1)and(δ||)|∈(0,1), the protocol has RBR|
|---|---|---|---|
|δ ,δ||i i∈[n]|n|
|C ,C|,sl||cs,1|

˜1 *knowledge soundness with relaxation R* *≡*2zk*k*1 *with the errors**ϵ** ∥···∥**ϵ***cs*,*n*−*1*∥**ϵ***base*defined* 1 zk 0 *below and total extraction time*     ∑ ∑*k* i *−h*

||tcor(C|) +N|
|---|---|---|
|h∈[k]|i≡2|n n−1|

*O* ) +tenc(*C*i) +tcor(*C ·*tcor(*C*zk)*.* i*∈*[n*−*1]i

**–***For every*i*∈*[n*−*1]*, define* *k* i *≡N*  <u>|Λ(Ci</u>*≡*2<u>,δi)|·|Λ(C</u> <u>zk</u> i <u>,δzk)|</u>  ( *|*F*|* *,* )  *k* i *−*(*h−*1) *≡N*  *≡*2*k*i*−h* <u>ℓzk·|Λ(Ci</u> *≡*2<u>,δ</u> <u>i</u> <u>)|·|Λ(Czk</u> i<u>,δzk)|</u>  *ϵ* mca(*C,δ*i) +*,*   i *|*F*|*  *h∈*[*k* i] ***ϵ***cs*,*i:=   ( *k* i+1

)2
 *,*  *|*Λ(*C*i *≡* +1 2*,δ* i+1)*|·|*Λ(*C*zk*,δ*zk)*|*   *·ε,*  2ood*,*i  *t*i  (1*−δ*i)*,*  *≡*2 *k* i+1 *≡N*i+1 *|*Λ(*C* i+1 *,δ*i+1)*|·|*Λ(*C*zk*,δ*zk)*|·ε*zero*,*i

**–***Define*   <u>|Λ(Cn</u>*≡*2<u>,δn)|·|Λ(C</u> *≡*2*·N*n*−*1 <u>,δzk)|</u> *ϵ* (*C,δ*) +*ϵ* (*C* *≡N* *,δ*) + <u>zk</u> *,* ***ϵ***base:= mca{nn mca zk zk}*|*F*|**.* max (1*−δ*n) *t* n *,*(1*−δ*zk) *t* zk

•**Zero-knowledge:** *Suppose that*char(F)*̸*= 2*,ℓ*zk*≥*2*, and:* **–***for every*i*∈*[n*−*1]*,*zeood*,*i*is a*(*ℓ*zk*−r*i*,ζ*ze*,*i)*-private zero-evader;* **–***for every*i*∈*[2*,*n]*,C*i*has at*i*-query zero-knowledge encoding with errorζC* i *;* **–***C*zk*has at*zk*-query zero-knowledge encoding with errorζC* zk *.* *Then the protocol is honest-verifier zero-knowledge with error* ∑ () *ζ* *≡*2 *k* i+1+*ζ*ze*,*i+ (*k*i+ 1)*·ζC*zk+*ζC*n+*N·ζC*zk *C* i+1 i*∈*[n*−*1]

### and simulator query complexity(t₁,(tzk)i∈[n]).

*Proof.*Let**sl₀** be the initial tuple from the theorem statement and for eachi*∈*[n*−*1]let**sl**ibe the output tuple after stagei. For eachi*∈*[n*−*1], apply Theorem 9.10 with ( *k* ) i+1 (*C,C*ood*C,C*ood i

|,n,k,t,t|) =||,N ,k ,t ,t|||||
|---|---|---|---|---|---|---|---|
|′||i i+1 ≡2|i−1|i i,||||
|,|||i|C ,N|,C ,sl|C ,N|,C ,sl|
|n−1||C C ,C|,C ,sl ,sl|C ,C|,sl n|||
|C|,C ,sl|cs||||||

and with zero-evaderszeiandzeood i, obtaining an IORIOR from*R* *≡*2*k*i to*R* *≡*2 *k* i+1. i i*−*1 zk i*−*1 i+1 i*−*1 zk i ThenIORcs:=IOR₁ *◦···◦*IOR is an IOR from*R≡*2*k*1to*R*n zk n*−*1. 1 zk 0 Apply the IOPPIORbasefrom Theorem 7.1 to*R*n zk n*−*1 with*n* :=*N*,*t* :=*t*, and*t*zkas in the statement. The final IOPP for*R≡*2*k*1isIOR *◦*IORbase. 1 zk 0 The stated round/query/communication/time bounds and the round-by-round error vector (in- cluding extraction time) follow by careful accounting. We focus on establishing zero knowledge. **Zero-knowledge.**We establish HVZK for all distinguishers by building simulators**S**n*,***S**n*−*1*,...,***S₁**, and applying Theorem 4.5 at each step. For each stagei*∈*[n*−*1], define

|||:=ζ ϵ|+ (k + 1)·ζ|.|
|---|---|---|---|---|
|||i C s|i i= i C|C C|
|n C|C||||
||n||||
|||n|||

*≡*2 *k* i+1+*ζ*ze*,*i zk i+1 ∑ n*−s*1 Also define tail-error terms: for*s∈*[n],*E* := ( *ϵ*) +*ζ*n+*N·ζ* zk; for*s*=nthe sum is empty, so*E* =*ζ*n+*N·ζ* zk.

•*Base case.*Let**S** be the simulator forIORbasefrom Theorem 7.1; the simulator has error*E*nand queries the main oracle at most*t* times and each of the*N*mask oracles at most*t*zktimes. As IORbaseis an IOPP, simulation works (trivially) for all distinguishers.

•*Inductive step (*i=n*−*1*down to*1*).*Suppose we have already constructed a simulator**S**i+1 for the IOPPIORi+1*◦···◦*IORn*−*1*◦*IORbasethat has simulation error*E*i+1and that queries the *≡*2 *k* i+1 *C* i+1 -oracle at most*t*i+1times and each of the*N*imask oracles at most*t*zktimes. **y y***,D* Fix any distinguisher*D*and let*D***S** i+1 be as in Definition 4.4, i.e.,*D* **S**i+1

(*·*) :=**S** i+1
(*·*). By the
*≡*2 *k* i+1 query bounds of**S**i+1,*D***S** i+1 queries the*C* i+1 -oracle at most*t*i+1times and each of the*N*iout- put mask oracles at most*t*zktimes; so*D***S** i+1 *∈*D *≤*(*t*i+1*,*(*t*zk)*j∈*[*N* i] ). ThusD**S** i+1 *⊆*D *≤*(*t*i+1*,*(*t*zk)*j∈*[*N* i] ).

The IORIORifrom Theorem 9.10 (instantiated with*n*=*N*i*−*1input masks) is HVZK with respect toD *≤*(*t*i+1*,*(*t*zk)*j∈*[*N* i] ) : the*k*imask oracles introduced during the sumcheck phase are each queried by*D***S** i+1 at most*t*zktimes (since they belong to the*N*ioutput masks), satisfying *t* *N*i*−*1+*j≤t*zkfor every*j∈*[*k*i]as required. SinceD**S**i+1*⊆*D *≤*(*t*i+1*,*(*t*zk)*j∈*[*N* i] ) ,IORiis in particular HVZK with respect toD**S** i+1.

Let**S**ibe simulator from Theorem 9.10, with error*ϵ*iand query complexity at most*t*ito the *≡*2*k*i *C* i -oracle and at most*t*zkto each of the*N*i*−*1input mask oracles. Applying Theorem 4.5 with IOR₁ :=IORi(simulator**S**i) andIOR₂ :=IORi+1*◦···◦*IORn*−*1*◦*IORbase(simulator**S**i+1) yields a simulator for the IOPPIORi*◦*(IORi+1*◦···◦*IORn*−*1*◦*IORbase)that is HVZK with ZK error *ϵ* i+*E*i+1=*E*i.

•*Conclusion.*Unrolling the induction toi= 1gives a simulator**S** :=**S₁** for the full protocol.**S** queries the original implicit instance(*f,*(*ξi*)*i∈*[*n*])at most*t₁* times for*f*and at most*t*zktimes for each*ξi*, as guaranteed by Theorem 9.10 for stage1. The total ZK error is*E₁*, which equals ∑ () *ζ* *≡*2 *k* i+1+*ζ*ze*,*i+ (*k*i+ 1)*·ζC*zk+*ζC*n+*N·ζC*zk*.* *C* i+1 i*∈*[n*−*1]

**Efficiency.**The efficiency of the construction follows by accumulating the costs of the building blocks throughout, and computing the cost of succinct linear form at each step (in particular, the codeswitches costs in see Section 9.3). The latter add the following terms to the prover/verifier time — the prover needs to compute a batch of size*t*i*·ι*iof the linear formssl # *C* i *,*sl $ *C* i for alli*∈*[n*−*1], as this must be proved by subsequent reductions. Similarly, the verifier must compute the (folded) succinct linear forms associated with those codeswitches, which entailsb(*⊙K−K* i sl # *C* i *,t*i) +b(sl $ *C* i *,t*<u>i)</u> field operations (as these are also computable in a batch).

## 11 Zero-knowledge reduction from R1CS

We describe a reduction from*R*R1CSto testing proximity to a constrained code relation, similar to the one in Definition 5.8. The reduction is similar to theΣ-IOP from [ACFY25], combined with a masking technique similar to the one used for the zero-knowledge sumcheck in Section 6.

**Definition 11.1.***Let:* •*n*in*,n*out*∈*N*;*

|m||||C ℓ|r m|||
|---|---|---|---|---|---|---|---|
||m||||ℓ|r|m|
|out||||C||||
|m|||||ℓ r|m||
|in ℓ|i i∈[n|] ◦,i i∈[n|] ◦,i i∈[n|C]|ℓ|i ℓ|◦,i|

•*C⊆*F *with a zero-knowledge encoding*Enc :F *×*F *→*Σ*;* zk zk zk out out zk zk •*C ⊆*Σzk out*with a zero-knowledge encoding*Enc zk :F *×*F *→*Σzk out*;* out zk zk zk zk zk •*C ⊆*Σzk in*with a zero-knowledge encoding*Enc zk :Fin*×*Fin*→*Σzk in*;* in in in out in zk in 2*×ℓ*zk out •**sl**= (sl*,*(sl) in *,*(sl) in *,*(sl) out )*where*sl*∈ ⟨*F *|,*sl *∈ ⟨*Fin*|,*sl *∈ ⟨*Fin*|,*sl*◦,i∈* zk *⟨*Fout*|.* *Define:*  ∣     in  ∣∣ *f*=Enc*C*(***f**,**r***)   

||||||¯ ξ =Enc|¯ (ξ, r¯ )|
|---|---|---|---|---|---|---|
|||i i∈[n i ◦,i i∈[n|]]||i i|i i C i i|
|C,C ,C|,sl|i ◦,i i∈[n i∈[n] i i i i∈[n|] i∈[n]] i|i i∈[n|◦,i ◦,i ◦,i ◦,i i∈[n]|i i i i i i i|

 (*µ,*st*,*(st*i*)*i∈*[*n*in])*,* ∣      ∣ *∀i∈*[*n*in] :*i C*zk*i i*   **x**=  ((***µ*** in *,*st in ))*,* *,* ∣in    in∣ *∀i∈*[*n*] : *ξ* =Enc zk (***ξ**,**r***)  out out∣∣out out *R* zk zk := ((*µ,*st)out) in in in *.* in out   ∣ *∀i∈*[*n*in] :sl (st)*· **ξ*** **¯** =***µ***     **y**= (*f,*(*ξ* ¯ *i* )*,*(*ξ*) out )*,* ∣    in ∣ *∀i∈*[*n*] :sl out (st out )*·**ξ*** =*µ* out     **w**= (***f**,**r**,*(***ξ*¯***, **r***¯)*,*(***ξ**,**r***)) ∣ out ∑   in out]∣ **¯**in in  *⟨**f**,*sl(st)*⟩*+ in *⟨**ξ**,*sl (st)*⟩*=*µ*

*For everyδ,δ*zk*∈*(0*,*1)*we define a corresponding relaxed relation for proximity testing:* { ∣} ∣ ∆(**y***,*¯)**y** *≤*(*δ, δ,...,δ ∧*(**x***,*¯*,***y w**)*∈R*

|δ,δ||C,C ,C ,sl|
|---|---|---|
|C,C ,C ,sl|n +n terms||

*R* ˜zk zk zk:= (**x***,***y***,*(**w***,*¯))**y** ︸ ︷︷ ︸ ) in out*.* ∣∣ zk zk zk zk in out∣in out

This definition is a minor extension of Definition 5.8 that we use to illustrate the different roles each zero-knowledge code plays in the reduction. By padding the shorter mask messages (and the corresponding succinct-evaluation states/targets) with zeros to a common length, both mask codes (the inner and outer codes) can be the same code, returning to the relation in Definition 5.8.

**Definition 11.2.***The relationR*R1CS*is the set of all pairs*((F*,n₀,ℓ,A,B,C,v*)*,w*)*where*F*is a* *finite field,n₀,ℓ∈*N*,A,B,Care*(*ℓ*+*n₀*)*×*(*ℓ*+*n₀*)*matrices over*F*,v∈*F *n*0 *, andw∈*F *ℓ* *, such* *that for alli∈*[(*ℓ*+*n₀*)]*:*       (*ℓ* ∑ +*n₀*) (*ℓ* ∑ +*n₀*) (*ℓ* ∑ +*n₀*)

| A| ·  ·z B ·z|= C ·z|
|---|---|---|
|j=1 (ℓ+n)|j=1|j=1|

*i,j j i,j j i,j j*  *j*=1 *j*=1 *j*=1

### forz := (v,w)∈F0.

**Theorem 11.3.***Assumeℓ*=*n₀ and thatℓis a power of*2*.*

||m ι m||C ℓ|r m|
|---|---|---|---|---|
||m|ι m||ℓ|
|out m||||C|

•*LetC⊆*Σ *≡*(F) *be a code with zero-knowledge encoding*Enc :F *×*F *→*Σ*.* zk zk zk out zk out zk out*r*out zk •*LetC ⊆*Σzk out*≡*(F) *be a code with zero-knowledge encoding*Enc zk :F *×*F *→* out zk Σzk out*.*

zk*m* zk *ι* zk*m*zk*ℓ*zk*r*zk *m*zk •*LetC*in*⊆*Σzk in*≡*(Fin)in*be a code with zero-knowledge encoding*Enc *C* zk :Fin*×*Fin*→*Σzk in*.* in •*Let*ze: *D*ze*→*F³ *be a zero-evader with errorε*zero*.*

*Define:* ( () () ()) in in out

|sl := sl,|sl|, sl|, sl|
|---|---|---|---|
||M,i M∈{A,B,C},i∈[logℓ+1]|◦,M,i M∈{A,B,C},i∈[logℓ+1]|◦,i i∈[logℓ+1]|
||T|||
|◦,M,i||||
|◦,j||||

in *where*sl := (slid*,*slid)*,*

sl out :=slid*,*

sl :=sl[ze*,*(slid*,*slid*,*slid)]*,*

sl in *M,i* :=slid*.*

*There exists an IOR fromR*R1CS*toR* *C,C*zk*,C*zk*,***sl** *with the following properties.* in out •*Round complexity:O*(log*ℓ*)*.* •*Prover communication (in field elements):m·ι*+ 3(log*ℓ*+ 1)*·m* zk in*·ι* zk in+ (log*ℓ*+ 1)*·m* zk out*·ι* zk out+ (log*ℓ*+ 1)*·*(*ℓ* zk out+ 1) + 4*. Of these,* **–***m·ιare sent as an oracle over alphabet*Σ*,* **–**3(log*ℓ*+1)*·m* zk in*·ι* zk in+(log*ℓ*+1)*·m* zk out*·ι* zk out*are sent as mask oracles over alphabet*Σzk*(consisting* *of*3(log*ℓ*+ 1)*inner-mask oracles and*log*ℓ*+ 1*outer-mask oracles), and* **–**(log*ℓ*+ 1)*·*(*ℓ* zk out+ 1) + 4*are sent as non-oracle messages.* •*Verifier queries: none (a queryless IOR).* •*Prover time (in field operations):O*(tenc(*C*) + log*ℓ·*(tenc(*C*out zk ) +tenc(*C*in zk )) +*ℓ*)*.* •*Verifier time (in field operations):O*(log*ℓ·ℓ* zk out+*ℓ*)*.* •**Round-by-round security:** *For everyδ,δ*zk*∈*(0*,*1)*, Construction 11.4 has RBR knowledge* ˜*δ,δ*zk *soundness with relaxation*(*R*R1CS*, R* *C,C*zk*,C*zk*,***sl** )*and errors* in out ( ()) (*ℓ* zk out+ 1)*·|*Λ(*C,δ*)*|·|*Λ*| |*Λ(*C,δ*)*|·|*Λ*|·ℓ* zk out*|*Λ(*C,δ*)*|·|*Λ*|·ℓ* zk out *,,,|*Λ(*C,δ*)*|·|*Λ*|·ε*zero *|*F*| |*F*|* *j∈*[log*ℓ*+1] *|*F*|−*2

*where|*Λ*|* :=*|*Λ((*C*out zk ) *≡*log*ℓ*+1 *,δ*zk)*|·|*Λ((*C*in zk ) *≡*3(log*ℓ*+1) *,δ*zk)*|. The total extraction time isO*(log*ℓ·* (tcor(*C*out zk ) +tcor(*C*in zk )))*.* •**Zero-knowledge:** *If*char(F)*̸*= 2*,ℓ* zk

|||≥2·ℓ||,ℓ ≥4, andEnc|,Enc|,Enc|aret-query||
|---|---|---|---|---|---|---|---|---|
|||out|in|in|C|C|C||
|||||||≤t|||
|||R1CS|||||||

out zk in zk in *C C*zk*C*zk out in *zero-knowledge encodings with errorζ, then the reduction is HVZK for*D *with error*(4log*ℓ*+

5)*·ζ(and no query complexity asR has no implicit instance).*
**Construction 11.4.**LetFbe a field. Consider the following ingredients and notation.

•We assume that*ℓ*is a power of2. Sometimes we refer to elements of*{*0*,*1*}* log*ℓ* as elements in[*ℓ*]. Implicitly, we assume a bijection between the two domains and use it as appropriate to translate between them. We also identify*{*0*,*1*}* log*ℓ*+1 with[(*ℓ*+*n₀*)](recall that we assume(*ℓ*+*n₀*) = 2*ℓ*).

•We let *f*ˆ*v v*(*b*) =*v*(*b*)for

|∈F [X₁,...,X|]be the unique multilinear polynomial satisfying fˆ|||
|---|---|---|---|
|<2 logℓ|logℓ M M|<2|logℓ+1 logℓ+1|

every*b∈{*0*,*1*}*.

•For every*M∈{A,B,C}*let *f*ˆ *∈*F [X₁*,...,*Xlog*ℓ*+1*,*Y₁*,...,*Y]be the unique multilinear
polynomial such that

*f* ˆ (*a,b*) =*M*[*a,b*]for all*a,b∈{*0*,*1*}.*

**Inputs.**The honest prover receives((F*,n₀,ℓ,A,B,C,v*)*,w*)*∈ R*R1CSand the verifier receives *ℓ* zk*−*1 *ℓ*zk*−*2 (F*,n₀,ℓ,A,B,C,v*). Definest₁ := (1*,*0in)andst₂ := (0*,*1*,*0in). **Interaction phase.**

¯ *m*zk

1.**Witness hiding masks.**For each*M∈{A,B,C},i∈*[log*ℓ*+1]send *ξM,i* zk in

||||||∈Σ|. In the honest||
|---|---|---|---|---|---|---|---|
|||M,i|ℓ||||<ℓ|
|M,i||M,i T|r|T|M,i|C|M,i M,i|
||M,i|◦,M,i||||||
||||m|||||
|r|w|C|w logℓ|||||

**¯***ℓ* zk*<ℓ*zk case, the prover samples a coefficient vector ***ξ** ∈*Fin(equivalently, a polynomial inFin[X]), **¯ ¯** zk ¯ **¯** conditioned on ***ξ**M,i*(0) = ***ξ*** (1) = 0, samples ***r***¯ *∈*Fin, and sends *ξ* :=Enc zk(***ξ**, **r***¯). in *Succinct evaluation:* define***µ*** in = (0*,*0) andst in = (st₁*,*st₂).

2.**Send witness encoding.**The prover sends a*f∈*Σ. In the honest case, the prover sets ***f*** :=*w*, samples***r**∈*F, and sends*f* :=Enc (***f**,**r***), where *f*ˆ is the unique multilinear extension of*w*, i.e.
*f* ˆ (*b*) =*w*(*b*)*∀b∈{*0*,*1*}.*

3.**Sumcheck.**The prover and verifier engage in a sumcheck protocol. In the honest case, the prover defines the following polynomials:
### •Boolean extension of the witness/input:

*f* ˆ *z*
(X₁*,...,*Xlog*ℓ*+1) := (1*−*Xlog*ℓ*+1)*· f*ˆ*v*(X₁*,...,*Xlog*ℓ*) +Xlog*ℓ*+1*· f*ˆ*w*(X₁*,...,*Xlog*ℓ*)*.*

•*Constraint polynomial:* Define:       ∑ log ∑ *ℓ*+1 ∑ log ∑ *ℓ*+1 ˆ(*g* X) :=  *f*ˆ*A*(X*,b*)*f*ˆ*z*(*b*) +  ***ξ*¯***A,i*(X*i*) *·*  *f*ˆ*B*(X*,b*)*f*ˆ*z*(*b*) +  ***ξ*¯***B,i*(X*i*) *b∈{*0*,*1*}*log*ℓ*+1*i*=1 *b∈{*0*,*1*}*log*ℓ*+1*i*=1    ∑ log ∑ *ℓ*+1 *−*  *f*ˆ*C*(X*,b*)*f*ˆ*z*(*b*) +  ***ξ*¯***C,i*(X*i*)*.* *b∈{*0*,*1*}*log*ℓ*+1*i*=1

*m*zk

4.**Sumcheck masks.**For each*j∈{*1*,...,*log*ℓ*+ 1*}*send*ξj∈*Σzk out, and send one value˜*µ*. In
*ℓ* zk the honest case, for each*j*the prover samples a coefficient vector***ξ**j∈*Fout(equivalently, a *<ℓ*zk*r*zk polynomial inFout[X]), samples***r**j∈*Fout, and sends*ξj*:=Enc *C* zk (***ξ**j,**r**j*). Then it sends out ∑ ˜*µ* := (***ξ₁***(*a₁*) +*···*+***ξ***log*ℓ*+1(*a*log*ℓ*+1))*.* *a∈{*0*,*1*}*log*ℓ*+1

5.**Sumcheck combining randomness.**The verifier sends*ε←*Fand***r**←*F
log*ℓ*+1.

6.**Sumcheck messages.**The prover and the verifier engage with a sumcheck protocol on the claim
() ∑ ∑log*ℓ*+1

|i=1|i i|||||
|---|---|---|---|---|---|
|j|<ℓ|j −1 i=1|i i|j log ℓ+1 i=j+1|i i|

*a∈{*0*,*1*}*log*ℓ*+1 *ε·*ˆ(*g a*)*·*eq(***r**,a*) + ***ξ*** (*a*) = ˜*µ*. Let*α* :=*∅*. For each*j∈{*1*,...,*log*ℓ*+ 1*}*:

ˆ zk ˆ •The prover sends a polynomial *h ∈*Fout[X]. In the honest case, *h* (X)is equal to the following:     ∑ ∑ ∑ *ε·*ˆ(*g α,*X*,a*)*·*eq(***r**,*(*α,*X*,a*)) +  ***ξ*** (*α*) +***ξ**j*(X) +  ***ξ*** (*a*) *a∈{*0*,*1*}*log*ℓ*+1*−j*

whereˆ(*g α,*X*,a*)is:

ˆ(*g α,*X*,a*)      ∑ *j* ∑ *−*1 log ∑ *ℓ*+1 :=  *f*ˆ*A*((*α,*X*,a*)*,b*)*f*ˆ*z*(*b*) +  ***ξ*¯***A,i*(*αi*) + ***ξ*¯***A,j*(X) +  ***ξ*¯***A,i*(*ai*) *b∈{*0*,*1*}*log*ℓ*+1*i*=1 *i*=*j*+1      ∑ *j* ∑ *−*1 log ∑ *ℓ*+1 *·*  *f*ˆ*B*((*α,*X*,a*)*,b*)*f*ˆ*z*(*b*) +  ***ξ*¯***B,i*(*αi*) + ***ξ*¯***B,j*(X) +  ***ξ*¯***B,i*(*ai*) *b∈{*0*,*1*}*log*ℓ*+1*i*=1 *i*=*j*+1      ∑ *j* ∑ *−*1 log ∑ *ℓ*+1 *−*  *f*ˆ*C*((*α,*X*,a*)*,b*)*f*ˆ*z*(*b*) +  ***ξ*¯***C,i*(*αi*) + ***ξ*¯***C,j*(X) +  ***ξ*¯***C,i*(*ai*) *b∈{*0*,*1*}*log*ℓ*+1*i*=1 *i*=*j*+1 ∑ ˆ ˆ •The verifier checks that*a∈{*0*,*1*}hj*(*a*) = *hj−*1(*αj−*1)(for*j*= 1, the verifier compares to˜*µ*).

•The verifier samples*αj←*F(except for the last round where*α*log*ℓ*+1*←*F*\{*0*,*1*}*) and updates*α* := (*α∥αj*).

7.**Reveal outer masks evaluations.**The prover sends*∀j∈{*1*,...,*log*ℓ*+1*},*˜*µj*. In the honest case,˜*µj*=***ξ**j*(*αj*). *Succinct evaluation:* define*µ*
out *j*= ˜*µj*andst out *◦,j*=pow(*αj*).

8.**Sumcheck’s final check.**The prover sends*vM*for every*M∈{A,B,C}*. In the honest case:
  ∑ log ∑ *ℓ*+1 *vM*:= *f*ˆ*M*(*α,b*)*· f*ˆ*z*(*b*) +  ***ξ*¯***M,i*(*αi*) *b∈{*0*,*1*}*log*ℓ*+1*i*=1   ∑ () log ∑ *ℓ*+1 = *f*ˆ*M*(*α,b,*0)*· f*ˆ*v*(*b*) + *f*ˆ*M*(*α,b,*1)*· f*ˆ*w*(*b*) + 2*·*  ***ξ*¯***M,i*(*αi*) *b∈{*0*,*1*}*log*ℓi*=1

The verifier checks that: log ∑ *ℓ*+1

|·v|−v )·eq(r,α) +||ˆ ˜µ = h|
|---|---|---|---|
|A B|C||j logℓ+1|
|||j=1||

*ε·*(*vj*(*α*log*ℓ*+1)

Finally, the verifier computes: ∑ () *uM*= *f*ˆ*M*(*α,b,*0)*· f*ˆ*v*(*b*)*.* *b∈{*0*,*1*}*log*ℓ*

9.**Joint constraint.**The verifier samples and sends*ρ←*F. *Succinct evaluation:* Letst*M*=*M*for all*M∈ {A,B,C}*(note that we abuse the notation but we mean that the state is the succinct description of the matrix) andsl*M*=slid
3. Set: sl=sl[ze*,*(sl*A,*sl*B,*sl*C*)]andst= (st*A,*st*B,*st*C,ρ*). Define also, for each*M∈{A,B,C}*and*i∈* in in

|[logℓ+1],sl|=sl|andst|= (pow(α ),ze(ρ)||), and setµ= ∑|ze(ρ) ·(v|−u )|
|---|---|---|---|---|---|---|---|
||M,i||M,i|i|M|M|M M|
||M|||||||
|Note the slight abuse of notation where we treat the entire description of the matrix as the succinct description||||||||
|from which we compute the MLE as in the beginning of the construction.||||||||

*M,i*id*M,i i M M∈{A,B,C} M M M* (whereze(*ρ*) *∈*Fdenotes the coordinate associated with*M∈{A,B,C}*). 3

10.**Output claim:** The prover and the verifier both implicitly define the output instance for *R* *C,C*zk*,C*zk*,***sl**
: in out

in in

|x= ((µ,st,(st|)|),(µ|)|) ,st|
|---|---|---|---|---|
||M,i M∈{A,B,C},i∈[logℓ+1]|M,i|◦,M,i M∈{A,B,C},i∈[logℓ+1]|i ◦,i i∈[logℓ+1]|
|M,i|M∈{A,B,C},i∈[logℓ+1]|i i∈[logℓ+1]|||

*,*st in *,*(*µ* out out )

**y**= (*f,*(*ξ*¯)*,*(*ξ*))*.*

In the honest case, the prover also defines the witness:

### w= (f,r,(ξ¯M,i, r¯M,i)M∈{A,B,C},i∈[logℓ+1],(ξi,ri)i∈[logℓ+1]).

*Proof sketch of Theorem 11.3.*We sketch the proof for round-by-round knowledge soundness, and honest-verifier zero-knowledge.

**Round-by-round knowledge soundness.**Ignoring masks, the protocol follows theΣ-IOP analysis for*R*R1CSin [ACFY25]. The differences are the added inner/outer masking layers and the finalze-based joint constraint, and these are handled with the same tools as in Section 6. Writing

*|*Λ*|* :=*|*Λ((*C*out zk ) *≡*log*ℓ*+1 *,δ*zk)*|·|*Λ((*C*in zk ) *≡*3(log*ℓ*+1) *,δ*zk)*|*

as in the theorem statement, the round-by-round error vector is ( ()) (*ℓ* zk out+ 1)*·|*Λ(*C,δ*)*|·|*Λ*| |*Λ(*C,δ*)*|·|*Λ*|·ℓ* zk out*|*Λ(*C,δ*)*|·|*Λ*|·ℓ* zk out *,,,|*Λ(*C,δ*)*|·|*Λ*|·ε*zero*.* *|*F*| |*F*|* *j∈*[log*ℓ*+1] *|*F*|−*2

The first coordinate corresponds to the initial masked-sumcheck consistency check, the vector coordinates correspond to the per-round sumcheck checks for rounds*j∈*[log*ℓ*+ 1], the third coordinate corresponds to the final check at*α*log*ℓ*+1*∈*F*\{*0*,*1*}*(hence denominator*|*F*|−*2), and the fourth coordinate comes from the final random linear combination withzein the joint constraint. Extraction time is*O*(log*ℓ·*(tcor(*C*out zk ) +tcor(*C*in zk ))).

**Honest-verifier zero-knowledge.**Fix any*D ∈*D *≤t* and define a simulator for its view. Let **S** *C* zk and**S***C*zk denote the simulators for the*t*-query zero-knowledge encodings of*C*out zk and*C*in zk (with out in error*ζ*). If*D*also queries*f*, we use the analogous simulator**S***C*forEnc*C*.

**S** *D* (F*,ℓ,A,B,C,v*):

1.Sample verifier randomness exactly as in the protocol: *ε←*F,***r**←*F
log*ℓ*+1 ,(*α₁,...,α*log*ℓ*)*←* F log*ℓ* ,*α*log*ℓ*+1*←*F*\{*0*,*1*}*,*ρ←*F.

2.Sample(*vA,vB,vC*)*←*F³.

|3.Sample(˜µ,(h||ˆ )|)|)uniformly fromT(v||,v|,v )(defined below).||
|---|---|---|---|---|---|---|---|---|
|||j j∈[logℓ+1]|j j∈[logℓ+1]|||A B|C||
|A|B C||M∈{A,B,C}|M M∈{A,B,C}|M M|M|||

*j j∈*[log*ℓ*+1]*,*(˜*µj j∈*[log*ℓ*+1] *A B C*

4.Compute the explicit output instance**x**exactly as in Items 9 and 10, using the sampled values (*v,v,v*)and the public quantities(*u*) computed from(*A,B,C,v*)and*α*, and setting
∑ *µ* := ze(*ρ*) *·*(*v −u*)*.*

(Also set all inner and outer targets/states as in the construction.)

5.Run*D*on**x**, giving it oracle access to**y**= (*f,*(*ξ*¯*M,i*)*M,i,*(*ξj*)*j*), and answer its (adaptive) oracle queries as follows:
(a)for each(*M,i*), answer queries to *ξ*¯*M,i*using**S**
*C* zk; in

(b)for each*j*, answer queries to*ξj*using**S**
*C* zk; out

(c)answer queries to*f*using**S***C*.
6.Output the simulated view (including*D*’s query/answer transcript). Fix verifier randomness(*ε,**r**,α,ρ*). For any fixed triple(*vA,vB,vC*)*∈*F³, define*T*(*vA,vB,vC*)
to be the set of all tuples(˜*µ,*(*h*ˆ*j*)*j∈*[log*ℓ*+1]*,*(˜*µj*)*j∈*[log*ℓ*+1])that satisfy

*h* ˆ₁(0) + *h*ˆ₁(1) = ˜*µ,*

*∀j∈{*2*,...,*log*ℓ*+ 1*}*: *h*ˆ*j*(0) + *h*ˆ*j*(1) = *h*ˆ*j−*1(*αj−*1)*,*

and log ∑ *ℓ*+1

||ε·(v|·v −v|)·eq(r,α) +||ˆ ˜µ = h|(α|||
|---|---|---|---|---|---|---|---|---|
||A|B|C||j logℓ+1|logℓ+1|||
|||||j=1|||||
|A B C||||||j j|logℓ+1||
|A B C|||||||A B|C|
|A B|C||logℓ+1 logℓ||logℓ+1|j j|j−1||

*j*)*.*
For fixed(*v,v,v*), these are linear constraints in the coefficients of(*h*ˆ) and in(˜*µ,*˜*µ₁,...,*˜*µ*), hence*T*(*v,v,v*)is the solution set of a linear system (i.e., an affine subspace). Also,*T*(*v,v,v*)*̸*= *∅*for every(*v,v,v*): choose *h*ˆ₁*,..., h*ˆ recursively so that *h*ˆ (0) +*h*ˆ (1) = *h*ˆ*j−*1(*α*)(with *h* ˆ₁(0) + *h*ˆ₁(1) = ˜*µ*), set˜*µ₁* =*···*= ˜*µ* = 0, and then define˜*µ* to satisfy the final equation.

Hence the simulator’s sampling in Item 3 is well-defined. We compare distributions in two claims, conditioning on verifier randomness. *Outer transcript claim.*Fix the prover’s inner-layer randomness (thus fixingˆand the values *g*

|,v ,v|)from Item 8). In the honest execution, the tuple(˜µ,(h||||ˆ|) ,(˜µ )|)is an affine func-||
|---|---|---|---|---|---|---|---|---|
|A B|C|||||j j j j|||
|A B|C|out A B|in C|A B|C||A B|C|

(*v* tion of the outer-mask coefficients, and the verifier’s checks are exactly the constraints defining *T*(*v,v,v*). Under*ℓ* zk *≥*2*·ℓ* zk and*ℓ* zk in*≥*4, the same linear-algebra argument as in Lemma 6.4 gives: the image is*T*(*v,v,v*), and every point in*T*(*v,v,v*)has the same number of preim- ages. Therefore uniform outer masks induce the uniform distribution on*T*(*v,v,v*), which matches the simulator’s choice in Item 3. *Value claim.*Using the decomposition in Item 8, in the honest execution

∑ () log ∑ *ℓ*+1

||fˆ|(α,b,0)· fˆ|(b) + fˆ|(α,b,1)· fˆ|(b)||ξ¯ (α|
|---|---|---|---|---|---|---|---|
||M||v|M|w||M,i|
|b∈{0,1}||||||i=1||
|M,i||M,logℓ+1|M|M|M,i M,logℓ+1|M,i logℓ+1||
|logℓ+1|||in||M,logℓ+1|logℓ+1||
||||||||M|
|A B|C|||||||

*vM*=*v w*+ 2*·i*) (*M∈{A,B,C}*)*,* log*ℓ*

where each ***ξ*¯** is sampled uniformly subject to ***ξ*¯** (0) = ***ξ*¯** (1) = 0. For each*M*, condition on all inner masks except ***ξ*¯**, and rewrite

*v* = const + 2*· **ξ*¯** (*α*)*.*

Because*α ∈*F*\{*0*,*1*}*and*ℓ* zk *≥*4, the value ***ξ*¯** (*α*)is uniform overF; and because char(F)*̸*= 2, multiplication by2is a bijection onF. Hence each*v* is uniform overFconditioned on public randomness and witness, and by independence of the three masks at indexlog*ℓ*+ 1, the triple(*v,v,v*)is jointly uniform overF³ and independent of witness/input. This matches the simulator’s choice in Item 2. Combining the two claims, the sumcheck part is perfectly simulated. Finally, we replace the honest encodings of the oracles(*ξ*¯*M,i*)*M,i*,(*ξj*)*j*, and*f*, one oracle at a time, by**S** *C* zk*,***S***C*zk, and**S***C*respectively (similarly to the hybrid argument in Lemma 6.4). Each in out replacement changes*D*’s view by at most*ζ*in statistical distance, because each encoding is*t*-query zero-knowledge and*D ∈*D *≤t*. There are exactly3(log*ℓ*+ 1) + (log*ℓ*+ 1) + 1 = 4log*ℓ*+ 5such oracles, so by a union bound the simulation error is at most(4log*ℓ*+ 5)*·ζ*=*O*(log*ℓ·ζ*).

## 12 High-distance codes from dispersers

We discuss the use of distance amplification via disperser graphs [ABNNR92; GRS12], and its use for certain efficiency gains.

### 12.1 Preliminaries

The following two definitions and subsequent proposition are from [GRS12].

**Definition 12.1.***LetG*= (*L∪R,E*)*be a bipartite graph with|L|*=*|R|*=*m. We say thatGis a* () *ε,γ***-disperser***if for everyS⊆Lwith|S|≥*(1*−ε*)*mthe neighborhoodN*(*S*) :=*{j∈R|∃i∈* *S*: (*i,j*)*∈E}satisfies|N*(*S*)*|≥*(1*−γ*)*|R|*= (1*−γ*)*m.*

**Definition 12.2.***LetC⊆*F *m* *be a code with minimum distanceδ*(*C*)*≥*1*−ε. LetG*= (*L∪R,E*)*be* () *a ε,γ -disperser with|L|*=*|R|*=*m, and assumeGis right-regular of degreed. For everyj∈R,* *fix an ordered list*(*i* *d* *of itsdleft incidences (allowing repetitions when*

|,i ,...,i|)∈L||||
|---|---|---|---|---|
|j,1 j,2|j,d|G m|d m|G j|

( *G* ) *has* *multi-edges). Define the***amplification map***A* :F *→*(F) *by*(*A* (*c*)) := *cij,*1*,...,ci* *j,d* *for* *eachj∈R.*

**Proposition 12.3**(Code–amplification lemma)**.***Under the hypotheses of Definition 12.2, the am-*

|G|d m||||
|---|---|---|---|---|
|′||i|′i||
|j,k||G|G|′|

*plified codeG*(*C*) :=*{A* (*c*)*|c∈C}⊆*(F) *has minimum distanceδ*(*G*(*C*))*≥*1*−γ.*

*Proof.*Take distinct*c,c ∈ C*and let*S* :=*{i∈L|c ̸*=*c}*. Since*δ*(*C*)*≥*1*−ε*, we have *|S|≥*(1*−ε*)*m*and hence*|N*(*S*)*|≥*(1*−γ*)*m*by Definition 12.1. For any*j∈N*(*S*)there exists *k∈ {*1*,...,d}*with*i ∈S*, so the*j*-th symbols of*A* (*c*)and*A* (*c*)differ in coordinate*k*of the*d*-tuple. Therefore the number of right indices where the amplified codewords differ is at least *|N*(*S*)*|≥*(1*−γ*)*m*.

Below we show via a standard probabilistic method argument that random graphs are good dispersers (similar lemmas can be found in [Coh91; TUZ07]). The edges of the graph are sampled at random such that each right vertex has*d*left-neighbors. The following gives a lower bound on the required degree to guarantee the parameters of the disperser.

**Proposition 12.4**(Probabilistic sampling of dispersers)**.***LetL,Rbe vertex sets with|L|*=*|R|*=

*m. Construct a random bipartite graphG*= (*L∪R,E*)*(with multi-edges) by choosing, for each* *j∈R, a multiset ofdneighbors inLuniformly at random with replacement (right-degreed). If*
<u>⌈(1−ε)m⌉ln</u> <u>⌈(1−</u> <u>me</u> <u>ε)m⌉</u> <u>+⌈γm⌉ln</u> <u>⌈γm</u> <u>me⌉</u> <u>−lnα</u> *d >* ()*,* *⌈γm⌉· −*ln*ε*

() *then, with probability at least*1*−α, the graphGis a ε,γ -disperser.* () *Proof.G*fails to be a *ε,γ*-disperser iff there exist*S⊆L*and*T⊆R*with*|S|≥⌈*(1*−ε*)*m⌉*and *|T|≥⌈γm⌉*such that every neighbor of each*j∈T*lies in*L\S*, i.e.,*N*(*S*)*⊆R\T*(equivalently, *|N*(*S*)*|≤*(1*−γ*)*m*). We may assume*|S|*=*⌈*(1*−ε*)*m⌉*and*|T|*=*⌈γm⌉*. := <u>m−|S|</u> Fix*S,T*of sizes*|S|*=*⌈*(1*−ε*)*m⌉*and*|T|*=*⌈γm⌉*. Let*p* *m* *≤ε*be the probability that a single random neighbor (one draw into*L*) lands in*L\S*. For a fixed*j∈T*, the probability that all*d*independently sampled neighbors (with replacement) lie in*L\S*is at most*p* *d* *≤ε* *d*.

]

|[||( )|T|||
|---|---|---|---|
|||d m ⌉ ε)m⌉ ⌈γm|d⌈γm⌉ d⌈γm⌉|
|me|me|||
|⌈(1−ε)m⌉|⌈γm⌉|||

Independence across*j∈T*yieldsPr all neighbors of all*j∈T*avoid*S ≤ ε* =*ε*. By a ()() union bound over all choices of*S*and*T*of these sizes,Pr[failure]*≤* *⌈*(1*−m* *ε*. Using ( *N* ) ( *Ne* ) *k* ()*⌈*(1*−ε*)*m⌉*()*⌈γm⌉* *d⌈γm⌉* *k* *≤* *k* givesPr[failure]*≤ ε*. We conclude by making the right-hand side at most*α*.

**Use in our protocols.**Our protocols can be instantiated with anyF-additive code with a zero- knowledge encoding, including distance-amplified codes. Although amplified codewords are over a

||d m||d·m|
|---|---|---|---|
|m G||ℓ r|m|

larger alphabet, they remainF-additive: a vector in(F) is equivalently a vector inF. There are generic results on mutual correlated agreement for everyF-additive code [GKL24; GCXK25; BCGM25]. Moreover, if*C⊆*F has a*t*-query zero-knowledge encodingEnc*C*:F *×*F *→*F, then the amplified code*G*(*C*) =*{A* (*c*) : *c∈C}*has a*⌊t/d⌋*-query zero-knowledge encoding: each query to one amplified symbol reveals*d*base-code symbols. In sum, distance-amplified codes can be used in our constructions both as the zero-knowledge masking code*C*zkand as the main code*C*(for example in Theorem 8.1).

### 12.2 Amplified Reed–Solomon code

We describe how distance amplification can be used to improve the encoding time of codes, in particular Reed–Solomon codes, given any target distance. The distance of the codes used in the protocols plays a crucial role in the number of queries made (and hence the resulting argument size after compilation via Merkle commitments), and it is beneficial to have large distance (that is, to have a code with distance1*−γ*with small*γ*). In general, distance amplification allows one to take any code, and obtain any distance using graphs with sufficiently large degrees (which correspond to sufficiently large alphabet for the output code). In the following, we highlight the resulting code from distance amplification on the Reed– Solomon code, which allows for faster encoding for a target distance.

**Definition 12.5**(Amplified Reed–Solomon code)**.***Fixc >*1*and a message lengthℓ∈*N*. Set* *m* :=*⌈cℓ⌉, choose a field*F*with|*F*|≥m, and fix an evaluation domain*[*m*]*⊆*F*of sizem. Let* () *L* := [*m*]*and letG*= (*L∪R,E*)*be a right-regular bipartite graph of degreedthat is a ε,γ -disperser* *withε* := <u>ℓ</u> *m* <u>−1</u> *. The code*ARS[F*,m,ℓ,G*]*is defined via this encoding: for a message*msg*∈*F *ℓ* *, set* *u* :=EncRS(msg)*∈*RS[F*,m,ℓ*]*and outputAG*(*u*)*∈*(F *d* ) *|R|* *(following Definition 12.2).*

The following claim follows by Definition 12.2 and Proposition 12.3.

**Claim 12.6**(Parameters of the amplified RS code)**.***The code in Definition 12.5 has alphabet*F *d* *,* *block length|R|(in alphabet symbols), and minimum distance at least*1*−γ.*

**Encoding time for two ways to reach relative distance1*−γ*.**We want to encode a message msg*∈*F *ℓ* into a codeword with minimum distance at least1*−γ*. We compare two methods.

1.Plain Reed–Solomon: Choose an evaluation domain of size
<u>ℓ−</u> *γ* <u>1</u> (and a fieldFlarge enough) so that*δ*(RS[F*,* <u>ℓ−</u> *γ* <u>1</u> *, ℓ*])*≥*1*−γ*. Encodingmsgconsists of (i) interpolating the degree-(*ℓ−*1) polynomial from the*ℓ*message symbols, and (ii) evaluating it at all points of the chosen domain. Assuming FFT-style algorithms on[*m*], this requires at most () () <u>ℓ−1 ℓ−1</u> *c* FFT*·ℓ·*log₂ *ℓ*+*c*FFT*· ·*log₂ *γ γ*

field operations. (IfEncRStreats the message as polynomial coefficients, omit the interpolation term and keep only the evaluation term.)

2.Amplified Reed–Solomon (with factor*c* :=*m/ℓ*and a right-regular disperser of degree*d*from the main bound): First encodemsg*∈*F
*ℓ* as a Reed–Solomon codeword on an evaluation domain of size*c·ℓ*; this takes at most*c*FFT*·ℓ·*log₂ *ℓ*+*c*FFT*·*(*c·ℓ*)*·*log₂ (*c·ℓ*)field operations (again, drop the interpolation term if the message is given as coefficients). Then apply the amplification map *AG*using the disperser graph; this step performs*d·|R|*copy operations. If, as in Definition 12.5, one sets*|R|*=*c·ℓ*, this amplification step costs*d·c·ℓ*symbols. Overall, the encoding time amounts to: *c* FFT*·ℓ·*log₂ *ℓ*+*c*FFT*·*(*c·ℓ*)*·*log₂ (*c·ℓ*) +*d·c·ℓ.*

For the amplified option, we instantiate the disperser degree at the smallest integer strictly larger than the lower bound in Proposition 12.4 with*n* :=*c·ℓ*,*ε* := <u>ℓ</u> *c* <u>−</u> *·ℓ* <u>1</u> ,*γ*as in the target distance, and any fixed*α∈*(0*,*1)for the construction’s failure probability. Concretely, take*d*to be the least integer bigger than

<u>(1−ε)n·ln</u> <u>(1−</u> <u>neε</u> <u>)n</u> <u>+γn·ln</u> <u>γn</u> <u>ne</u> <u>−lnα ℓ−1</u> with*n*=*c·ℓ, ε*=*.* *γn·*(*−*ln*ε*) *c·ℓ*

With this choice, the amplified variant is faster than plain RS exactly when () () <u>ℓ−1 ℓ−1</u> *c* <u>FFT·(c·ℓ</u>)*·*<u>log₂(c·ℓ</u>) +*d*︸ <u>·</u>︷︷*c*<u>·</u>*ℓ*︸ *≤c*FFT*· ·*log₂*.* ︸ ︷︷ ︸ <u>γ γ</u> RS on size*c·ℓ* amplification copies ︸ ︷︷ ︸ RS on size(*ℓ−*1)*/γ*

Intuitively, when*γ*is small (demanding very large plain-RS block length), the right-hand side grows like *γℓ* log₂ *γℓ*, while the extra cost of amplification grows only linearly in *γℓ* through*d·c·ℓ*(since (1*−* 1 *c* ) ln <u>1−</u> *e* <u>1</u>+*γ*ln*γ* *e* *d*from the lemma scales like *γ*ln*c* <u>c</u> with*n*=*c·ℓ*). Thus, for small*γ*and fixed*c*, the amplified RS method is cheaper.

**Benefits of amplified RS.**Amplified Reed–Solomon codes offer benefits in time and rate.

•*No large FFTs.*The FFT is for sizeΘ(*ℓ*)rather thanΘ(*ℓ/γ*). This improves encoding time, by trading aΘ(*ℓ/γ*)-size FFT for aΘ(*cℓ*)-size FFT plus aΘ (*ℓ/γ*)-time pass to gather neighbors.

•*Space complexity.*The*encoding space*required forARSis also decreased, if one has efficient access to the graph*G*. Even if one were to use in-place FFTs, the encoding space of the Reed– Solomon code at that distance is*ℓ/γ*, while we can afford smaller FFTs requiring only*O*(*ℓ*)size. Storing*G*in memory takes*O*( *γ* <u>ℓ</u> log*ℓ*), making the space complexity slightly*worse*than in-place FFT implementations. Since strongly-explicit dispersers (where the neighborhood of a vertex could be computed in polylogarithmic time) with*d*=*O*(1*/γ*)are not known, one would have to store the sampled*G*in memory. An alternative approach would be to*streamG*, performing the alphabet aggregation for the neighbors of each vertex when their neighborhoods are streamed. This streaming option is much less clear for FFTs. Furthermore, in practice, one could use a PRG that, in principle, replaces the notion of a strongly explicit construction, as the neighbor set of each vertex could be sampled “on the fly” in a reproducible way.

### 12.3 Distance amplification and Merkle-compiled argument size

We discuss potential efficiency gains from distance amplification for argument size. While the proposed application here increases the encoding time (as opposed to the decrease in encoding time mentioned in the previous section), we show that it decreases overall argument size.

**A case study.**To investigate this point, we consider an example, which is based on the codeword batching protocol from [BCFW25]. In this protocol, the prover sends as an oracle a purported codeword, and the verifier makes*t*independent spot-checks to an oracle. When the protocol’s soundness relies on the fact that two distinct codewords disagree on a1*−ε*fraction of coordinates (i.e., the underlying code has relative distance at least1*−ε*), then each independent check catches a cheating strategy with probability at least1*−ε*, and hence the overall soundness error is at most *ε* *t*. Thus, to drive the soundness error below2 *−λ*, it suffices to take*t≥* *−*log <u>λ</u> *ε*. 2 **The cost of a Merkle commitment.**Consider compiling such a protocol into an argument by committing to the codeword via a Merkle commitment whose leaves are the codeword symbols. Each verifier query is then answered by the leaf value and the authentication path, i.e., the sibling hashes along the root-to-leaf path. For a codeword of block length*m*(in symbols), the path has length*⌈*log₂ *m⌉*. Hence, measured as “one field symbol plus one hash digest” units, the total proof () communication contributed by these*t*oracle queries is*t·* 1 +*⌈*log₂ *m⌉*, up to constant factors that depend only on the fixed hash function.

**Merkle compilation cost for an amplified code.**Now replace the underlying code*C⊆*F *m* by *d m* () its amplified version*G*(*C*)*⊆*(F) from Definition 12.2, where*G*is a right-regular *ε,γ*-disperser of degree*d*and*|R|*=*m*. By Proposition 12.3, the amplified code has relative distance at least1*−γ*, so the same “independent spot-check” reasoning yields soundness error at most*γ* *t*, and to achieve soundness error below2 *−λ* it suffices to take*t≥* *−*log <u>λ</u> *γ*. After compilation, each query now opens 2 a*single amplified symbol*, i.e., an element ofF *d*, together with an authentication path of length () *⌈*log₂ *m⌉*. Hence the argument size contributed by the*t*oracle queries becomes*t· d*+*⌈*log₂ *m⌉*. In the disperser-based setting of Definitions 12.1 and 12.2, the Merkle depth terms coincide and amplification yields an improvement for this part of the argument when

() <u>−log γ</u> *d <* 1 +*⌈*log₂ *m⌉ ·* <u>2</u> *−⌈*log₂ *m⌉.*(10) *−*log₂ *ε*

**Instantiating*d*via Proposition 12.4.**Fix any target*γ∈*(0*,*1)and any*α∈*(0*,*1). Let*d* be the least integer strictly larger than the lower bound from Proposition 12.4. To assess whether Equation 10 can hold for the*best*(i.e., smallest) degree guaranteed by Proposition 12.4, take*d*to be the least integer strictly larger than the bound of Proposition 12.4. Ignoring ceiling effects and the additive*−*ln*α*term (which is divided by*γm*and is negligible once*m*is large), the bound has the following dominant form: <u>e</u> <u>ln</u> <u>e</u> <u>(1−ε) ln₁</u> <u>−ε γ</u> *d≈* () +*.* *γ· −*ln*ε −*ln*ε*

In particular, for fixed*ε*this degree grows proportionally to1*/γ*as*γ→*0. Since the required number of openings decreases only as1*/*(*−*log₂ *γ*), very small*γ*forces*d*so large that Equation 10 eventually fails: in this regime, amplifying to extremely high relative distance makes each Merkle leaf so large that the reduction in the number of openings cannot compensate.

**Concrete parameters.**The condition in Equation 10*can*hold for moderate target distances.

|20 −40|1|||
|---|---|---|---|
||3|3||
||||3|
|||3||

For instance, take*m*= 2*,α*= 2*,λ*= 128*,ε*=. Then the plain compilation needs*t≈*81 openings and the query/opening contribution is approximately81*·*(1 + 20)*≈*1*.*70*·*10 units. If we target*γ*= 0*.*1(relative distance0*.*9), the smallest*d*certified by Proposition 12.4 is*d*= 12, and the amplified compilation needs*t≈*39openings, contributing about39*·*(12 + 20)*≈*1*.*23*·*10 units, a reduction of roughly27%. In contrast, if we target*γ*= 0*.*01(relative distance0*.*99), the same calculation yields*d*= 91and*t≈*19, giving about19*·*(91 + 20)*≈*2*.*14*·*10 units, which is*larger* than plain. These examples illustrate that, under Proposition 12.4, the Merkle-query part improves only when the requested distance increase is substantial but not so extreme that the required*d* becomes the dominant term in each opening. We compare the prover’s slowdown when using distance amplification. To compare*prover* runtime, we separate (a) committing to the oracle (encoding, plus building the Merkle commitment) from (b) answering the*t*openings. In the comparison we ignore the base encoding time of*C*(it is the same in both variants) and we count the total number of field-symbol copies/hashes.

||20|
|---|---|
|m|20|
|20|20|

As before, we assume that*m*= 2 20 so the Merkle commitment has2 leaves and2 20 *−*1internal nodes. In the*plain*case, committing to*C⊆*F requires hashing2 leaves (each containing one field symbol) and2 20 *−*1internal nodes, i.e., about(2)+(2 *−*1) = 2*,*097*,*151hash computations. Answering*t≈*81openings transmits81field symbols and81*·*20sibling hashes, i.e.,81*·*(1 + 20) = 1*,*701units in the same model. Overall, the plain prover’s Merkle-related work is*≈*2*,*098*,*852units. For*γ*= 0*.*1, the probabilistic-method bound yields*d*= 12and*t≈*39. In the*amplified*case, beyond the same base encoding, the prover must (i) compute*AG*(about*dm*= 12*·*2 20 = 12*,*582*,*912 symbol copies), and (ii) hash2 20 leaves each containing*d*= 12field symbols (about another 12*,*582*,*912symbol-hash units), plus the same2 20 *−*1internal-node hashes. Answering the openings transmits39leaves of size12plus39*·*20sibling hashes, i.e.,39*·*(12 + 20) = 1*,*248units. Altogether, this totals roughly12*,*582*,*912 + 12*,*582*,*912 + (2 20 *−*1) + 1*,*248 = 26*,*215*,*647units, i.e., about a12*.*5*×*increase over the plain prover time in this model. In other words, even though the *communication*in openings improves (roughly27%above), the*prover*becomes slower because it must materialize and commit to*d*-times larger leaves.

## Acknowledgments

The authors are supported in part by the Ethereum Foundation, the Sui Foundation, and Polygon Labs.

## References

[ABNNR92]N. Alon, J. Bruck, J. Naor, M. Naor, and R.M. Roth. “Construction of asymptotically good low-rate error-correcting codes through pseudo-random graphs”. In: *IEEE Transactions on* *Information Theory*38.2 (1992), pp. 509–516.doi:10.1109/18.119713.

[ACFY24]Gal Arnon, Alessandro Chiesa, Giacomo Fenzi, and Eylon Yogev. “STIR: Reed–Solomon Proximity Testing with Fewer Queries”. In: *Proceedings of the 44th Annual International* *Cryptology Conference*. CRYPTO ’24. 2024, pp. 380–413.

[ACFY25]Gal Arnon, Alessandro Chiesa, Giacomo Fenzi, and Eylon Yogev. “WHIR: Reed–Solomon Proximity Testing with Super-Fast Verification”. In: *Proceedings of the 44th Annual In-* *ternational Conference on Theory and Application of Cryptographic Techniques*. EURO- CRYPT ’25. 2025.

[ACY23]Gal Arnon, Alessandro Chiesa, and Eylon Yogev. “IOPs with Inverse Polynomial Sound- ness Error”. In: *64th IEEE Annual Symposium on Foundations of Computer Science ,* *FOCS 2023, Santa Cruz, CA, USA, November 6-9, 2023*. IEEE, 2023, pp. 752–761.

[AHIV17]Scott Ames, Carmit Hazay, Yuval Ishai, and Muthuramakrishnan Venkitasubramaniam. “Ligero: Lightweight Sublinear Arguments Without a Trusted Setup”. In: *Proceedings of* *the 24th ACM Conference on Computer and Communications Security*. CCS ’17. 2017, pp. 2087–2104.

[ARR25]Noor Athamnah, Noga Ron-Zewi, and Ron D. Rothblum. “Linear Prover IOPs in Log Star Rounds”. In: *Proceedings of the 23rd Theory of Cryptography Conference*. TCC ’25. 2025, pp. 335–368.

[BBHR18]Eli Ben-Sasson, Iddo Bentov, Yinon Horesh, and Michael Riabzev. “Fast Reed–Solomon Interactive Oracle Proofs of Proximity”. In: *Proceedings of the 45th International Collo-* *quium on Automata, Languages and Programming*. ICALP ’18. 2018, 14:1–14:17.

[BBHR19]Eli Ben-Sasson, Iddo Bentov, Yinon Horesh, and Michael Riabzev. “Scalable Zero Knowl- edge with No Trusted Setup”. In: *Proceedings of the 39th Annual International Cryptology* *Conference*. CRYPTO ’19. 2019, pp. 733–764.

[BBHV22]Laasya Bangalore, Rishabh Bhadauria, Carmit Hazay, and Muthuramakrishnan Venkita- subramaniam. “On Black-Box Constructions of Time and Space Efficient Sublinear Argu- ments from Symmetric-Key Primitives”. In: *Proceedings of the 20th Theory of Cryptography* *Conference*. TCC ’22. 2022, pp. 417–446.

[BCFFMMZ25]Anubhav Baweja, Alessandro Chiesa, Elisabetta Fedele, Giacomo Fenzi, Pratyush Mishra, Tushar Mopuri, and Andrew Zitek-Estrada. “Time-Space Tradeoffs for Sumcheck”. In: *Proceedings of the 23rd Theory of Cryptography Conference*. TCC ’25. 2025, pp. 37–70.

[BCFGRS17]Eli Ben-Sasson, Alessandro Chiesa, Michael A. Forbes, Ariel Gabizon, Michael Riabzev, and Nicholas Spooner. “Zero Knowledge Protocols from Succinct Constraint Detection”. In: *Proceedings of the 15th Theory of Cryptography Conference*. TCC ’17. 2017, pp. 172–

206.

[BCFRRZ25]Martijn Brehm, Binyi Chen, Ben Fisch, Nicolas Resch, Ron D. Rothblum, and Hadas Zeilberger. “Blaze: Fast SNARKs from Interleaved RAA Codes”. In: *Proceedings of the 44th* *Annual International Conference on Theory and Application of Cryptographic Techniques*. EUROCRYPT ’25. 2025.

[BCFW25]Benedikt Bünz, Alessandro Chiesa, Giacomo Fenzi, and William Wang. “Linear-Time Ac- cumulation Schemes”. In: *Proceedings of the 23rd Theory of Cryptography Conference*. TCC ’25. 2025, pp. 369–399.

[BCG20]Jonathan Bootle, Alessandro Chiesa, and Jens Groth. “Linear-Time Arguments with Sub- linear Verification from Tensor Codes”. In: *Proceedings of the 18th Theory of Cryptography* *Conference*. TCC ’20. 2020, pp. 19–46.

[BCGGHJ17]Jonathan Bootle, Andrea Cerulli, Essam Ghadafi, Jens Groth, Mohammad Hajiabadi, and Sune K. Jakobsen. “Linear-Time Zero-Knowledge Proofs for Arithmetic Circuit Satisfiabil- ity”. In: *Proceedings of the 23rd International Conference on the Theory and Applications* *of Cryptology and Information Security*. ASIACRYPT ’17. 2017, pp. 336–365.

[BCGGRS19]Eli Ben-Sasson, Alessandro Chiesa, Lior Goldberg, Tom Gur, Michael Riabzev, and Nicholas Spooner. “Linear-Size Constant-Query IOPs for Delegating Computation”. In: *Proceedings* *of the 17th Theory of Cryptography Conference*. TCC ’19. 2019, pp. 494–521.

[BCGM25]Sarah Bordage, Alessandro Chiesa, Ziyi Guan, and Ignacio Manzur.*All Polynomial Gen-* *erators Preserve Distance with Mutual Correlated Agreement*. Cryptology ePrint Archive, Paper 2025/2051. 2025.

[BCGV16]Eli Ben-Sasson, Alessandro Chiesa, Ariel Gabizon, and Madars Virza. “Quasilinear-Size Zero Knowledge from Linear-Algebraic PCPs”. In: *Proceedings of the 13th Theory of Cryp-* *tography Conference*. TCC ’16-A. 2016, pp. 33–64.

[BCIKS20]Eli Ben-Sasson, Dan Carmon, Yuval Ishai, Swastik Kopparty, and Shubhangi Saraf. “Prox- imity Gaps for Reed–Solomon Codes”. In: *Proceedings of the 61st Annual IEEE Symposium* *on Foundations of Computer Science*. FOCS ’20. 2020, pp. 900–909.

[BCL22]Jonathan Bootle, Alessandro Chiesa, and Siqi Liu. “Zero-Knowledge IOPs with Linear- Time Prover and Polylogarithmic-Time Verifier”. In: *Proceedings of the 41st Annual In-* *ternational Conference on Theory and Application of Cryptographic Techniques*. EURO- CRYPT ’22. 2022, pp. 275–304.

[BCRSVW19]Eli Ben-Sasson, Alessandro Chiesa, Michael Riabzev, Nicholas Spooner, Madars Virza, and Nicholas P. Ward. “Aurora: Transparent Succinct Arguments for R1CS”. In: *Proceedings of* *the 38th Annual International Conference on the Theory and Applications of Cryptographic* *Techniques*. EUROCRYPT ’19. 2019, pp. 103–128.

[BCS16]Eli Ben-Sasson, Alessandro Chiesa, and Nicholas Spooner. “Interactive Oracle Proofs”. In: *Proceedings of the 14th Theory of Cryptography Conference*. TCC ’16-B. 2016, pp. 31–60.

[BFRW25]Benedikt Bünz, Giacomo Fenzi, Ron D. Rothblum, and William Wang.*TensorSwitch:* *Nearly Optimal Polynomial Commitments from Tensor Codes*. Cryptology ePrint Archive, Report 2025/2065. 2025.

[BGKS20]Eli Ben-Sasson, Lior Goldberg, Swastik Kopparty, and Shubhangi Saraf. “DEEP-FRI: Sampling Outside the Box Improves Soundness”. In: *Proceedings of the 11th Innovations* *in Theoretical Computer Science Conference*. ITCS ’20. 2020, 5:1–5:32.

[BMMS25a]Anubhav Baweja, Pratyush Mishra, Tushar Mopuri, and Matan Shtepel.*FICS and FACS:* *Fast IOPPs and Accumulation via Code-Switching*. Cryptology ePrint Archive, Report 2025/737. 2025.

[BMMS25b]Anubhav Baweja, Pratyush Mishra, Tushar Mopuri, and Matan Shtepel.*Query-Optimal* *IOPPs for Linear-Time Encodable Codes*. Cryptology ePrint Archive, Report 2025/1588.

2025.
[BMNW25]Benedikt Bünz, Pratyush Mishra, Wilson Nguyen, and William Wang. “Arc: Accumulation for Reed–Solomon Codes”. In: *Proceedings of the 45th Annual International Cryptology* *Conference*. CRYPTO ’25. 2025.

[Ber]Daniel J. Bernstein.*The transposition principle*.url:https://cr.yp.to/transposition. html.

[Bor57]Jan L. Bordewijk. “Inter-reciprocity applied to electrical networks”. In: *Applied Scientific* *Research, Section B*6.1 (1957), pp. 1–74.

[CCHLRR18]Ran Canetti, Yilei Chen, Justin Holmgren, Alex Lombardi, Guy N. Rothblum, and Ron

D. Rothblum.*Fiat–Shamir From Simpler Assumptions*. Cryptology ePrint Archive, Report 2018/1004. 2018.
[CFS17]Alessandro Chiesa, Michael A. Forbes, and Nicholas Spooner.*A Zero Knowledge Sumcheck* *and its Applications*.https://arxiv.org/abs/1704.02086. arXiv:1704.02086 [cs.CC].

2017.doi:10.48550/arXiv.1704.02086.
[CMS19]Alessandro Chiesa, Peter Manohar, and Nicholas Spooner. “Succinct Arguments in the Quantum Random Oracle Model”. In: *Proceedings of the 17th Theory of Cryptography* *Conference*. TCC ’19. 2019, pp. 1–29.

[COS20]Alessandro Chiesa, Dev Ojha, and Nicholas Spooner. “Fractal: Post-Quantum and Trans- parent Recursive Proofs from Holography”. In: *Proceedings of the 39th Annual Interna-* *tional Conference on the Theory and Applications of Cryptographic Techniques*. EURO- CRYPT ’20. 2020, pp. 769–793.

[CTY11]Graham Cormode, Justin Thaler, and Ke Yi. “Verifying computations with streaming interactive proofs”. In: *Proceedings of the VLDB Endowment*5.1 (2011), pp. 25–36.

[CY24]Alessandro Chiesa and Eylon Yogev.*Building Cryptographic Proofs from Hash Functions*.

2024.url:https://github.com/hash-based-snargs-book.
[Coh91]Aviad Cohen. “Disperser Graphs, Deterministic Amplification and Imperfect Random Sources”. PhD Thesis, PDF available online athttps : / / www. math. ias. edu / ~avi / STUDENTS/acthesis.pdf. PhD thesis. Hebrew University of Jerusalem, 1991.

[DL25]Hugo Delavenne and Louise Lallemand.*Codes on any Cayley Graph have an Interactive* *Oracle Proof of Proximity*. arXiv preprint. 2025. arXiv:2508.10510 [cs.CC].

[DM11]Irit Dinur and Or Meir. “Derandomized Parallel Repetition via Structured PCPs”. In: *Computational Complexity*20.2 (2011), pp. 207–327.doi:10.1007/s00037-011-0013-5. url:https://link.springer.com/article/10.1007/s00037-011-0013-5.

[DMR25]Hugo Delavenne, Tanguy Medevielle, and Élina Roussel. “Interactive Oracle Proofs of Proximity to Codes on Graphs”. In: *2025 IEEE International Symposium on Information* *Theory*. ISIT ’25. 2025, pp. 1–6.

[DP24]Benjamin E. Diamond and Jim Posen.*Proximity Testing with Logarithmic Randomness*. Cryptology ePrint Archive, Report 2023/630. 2024.

[DR04]Irit Dinur and Omer Reingold. “Assignment Testers: Towards a Combinatorial Proof of the PCP Theorem”. In: *Proceedings of the 45th Annual IEEE Symposium on Foundations* *of Computer Science*. FOCS ’04. 2004, pp. 155–164.

[Dia25]Benjamin Diamond.*Zero-Knowledge Polynomial Commitment in Binary Fields*. Cryptol- ogy ePrint Archive, Report 2025/1015. 2025.

[Din07]Irit Dinur. “The PCP theorem by gap amplification”. In: *Journal of the ACM*54.3 (2007),

p. 12.
[Fs24]Matteo Frigo and abhi shelat.*Anonymous credentials from ECDSA*. Cryptology ePrint Archive, Report 2024/2010. 2024.

[GCXK25]Yiwen Gao, Dongliang Cai, Yang Xu, and Haibin Kan.*From List-Decodability to Proximity* *Gaps*. Tech. rep. 2025/870. Cryptology ePrint Archive, 2025.url:https://eprint.iacr. org/2025/870.

[GGR11]Parikshit Gopalan, Venkatesan Guruswami, and Prasad Raghavendra. “List Decoding Tensor Products and Interleaved Codes”. In: *SIAM Journal on Computing*40.5 (2011), pp. 1432–1462.

[GI05]Venkatesan Guruswami and Piotr Indyk. “Linear-time encodable/decodable codes with near-optimal rate”. In: *IEEE Transactions on Information Theory*51.10 (2005). Prelimi- nary version appeared in STOC ’03., pp. 3393–3400.

[GKL24]Yiwen Gao, Haibin Kan, and Yuan Li.*Linear Proximity Gap for Linear Codes within the*

*1.5 Johnson Bound*. Cryptology ePrint Archive, Report 2024/1810. 2024.
[GLSTW23]Alexander Golovnev, Jonathan Lee, Srinath T. V. Setty, Justin Thaler, and Riad S. Wahby. “Brakedown: Linear-time and field-agnostic SNARKs for R1CS”. In: *Proceedings of the* *43rd Annual International Cryptology Conference*. CRYPTO ’23. 2023.

[GOS24]Tom Gur, Jack O’Connor, and Nicholas Spooner. “Perfect Zero-Knowledge PCPs for #P”. In: *Proceedings of the 56th Annual ACM Symposium on Theory of Computing*. STOC ’24. 2024, pp. 1724–1730.

[GOS25]Tom Gur, Jack O’Connor, and Nicholas Spooner. “A Zero-Knowledge PCP Theorem”. In: *Proceedings of the 57th Annual ACM Symposium on Theory of Computing*. STOC ’25. 2025, pp. 986–994.

[GRS12]Venkatesan Guruswami, Atri Rudra, and Madhu Sudan.*Essential coding theory*. Vol. 2. 1.

2012.
[GS00]Oded Goldreich and Shmuel Safra. “A Combinatorial Consistency Lemma with Application to Proving the PCP Theorem”. In: *SIAM Journal on Computing*29.4 (2000). Earlier version: FOCS 1997, pp. 1132–1154.doi:10.1137/S0097539797315744.

[GUV09]Venkatesan Guruswami, Christopher Umans, and Salil P. Vadhan. “Unbalanced expanders and randomness extractors from Parvaresh–Vardy codes”. In: *Journal of the ACM*56.4 (2009), 20:1–20:34.

[Goo]*Opening up ‘Zero-Knowledge Proof’ technology to promote privacy in age assurance*.https: //blog.google/technology/safety-security/opening-up-zero-knowledge-proof- technology-to-promote-privacy-in-age-assurance/. 2025.

[HK24]Ulrich Haböck and Al Kindi.*A note on adding zero-knowledge to STARK*. Cryptology ePrint Archive, Report 2024/1037. 2024.

[IKW09]Russell Impagliazzo, Valentine Kabanets, and Avi Wigderson. “New Direct-Product Testers and 2-Query PCPs”. In: *Proceedings of the 41st Annual ACM Symposium on Theory of* *Computing (STOC)*. Preliminary version appeared as ECCC TR08-016. 2009, pp. 131–140. doi:10.1145/1536414.1536436.

[ISVW13]Yuval Ishai, Amit Sahai, Michael Viderman, and Mor Weiss. “Zero Knowledge LTCs and Their Applications”. In: *Proceedings of the 16th International Workshop on Approxima-* *tion Algorithms for Combinatorial Optimization Problems, and of the 17th International* *Workshop on Randomization and Computation*. APPROX-RANDOM ’13. 2013, pp. 607–

622.

[Lig]*Reshaping KYC/AML in Web3*.https://ligero-inc.com/kyc-aml. 2025. [MZ25]Dor Minzer and Kai Zhe Zheng. “Improved Round-by-round Soundness IOPs via Reed– Muller Codes”. In: *Proceedings of the 66th Annual IEEE Symposium on Foundations of* *Computer Science*. FOCS ’25. 2025, pp. 1286–1294. [Mei12]Or Meir. “Combinatorial PCPs with Short Proofs”. In: *Proceedings of the 26th Annual* *IEEE Conference on Computational Complexity*. CCC ’12. 2012. [Mei13]Or Meir. “IP = PSPACE Using Error-Correcting Codes”. In: *SIAM Journal on Computing*

42.1 (2013), pp. 380–403.
[Mid]*Miden*.https://github.com/0xPolygonMiden. [NA25]Andrija Novakovic and Guillermo Angeris.*Ligerito: A Small and Concretely Fast Polyno-* *mial Commitment Scheme*. Cryptology ePrint Archive, Report 2025/1187. 2025. [NTZ25]Vineet Nair, Justin Thaler, and Michael Zhu.*Proving CPU Executions in Small Space*. Cryptology ePrint Archive, Report 2025/611. 2025. [Pol]*Polygon*.https://polygon.technology. [RR20]Noga Ron-Zewi and Ron Rothblum. “Local Proofs Approaching the Witness Length”. In: *Proceedings of the 61st Annual IEEE Symposium on Foundations of Computer Science*. FOCS ’20. 2020, pp. 846–857. [RR22]Noga Ron-Zewi and Ron D. Rothblum. “Proving as Fast as Computing: Succinct Argu- ments with Constant Prover Overhead”. In: *Proceedings of the 54th ACM Symposium on* *the Theory of Computing*. STOC ’22. 2022, pp. 1353–1363. [RRR16]Omer Reingold, Ron Rothblum, and Guy Rothblum. “Constant-Round Interactive Proofs for Delegating Computation”. In: *Proceedings of the 48th ACM Symposium on the Theory* *of Computing*. STOC ’16. 2016, pp. 49–62. [RS60]I. S. Reed and G. Solomon. “Polynomial Codes Over Certain Finite Fields”. In: *Journal* *of the Society for Industrial and Applied Mathematics*8.2 (1960), pp. 300–304. [RW24]Noga Ron-Zewi and Mor Weiss. “Zero-knowledge IOPs Approaching Witness Length”. In: *Proceedings of the 44th Annual International Cryptology Conference*. CRYPTO ’24. 2024, pp. 105–137. [Ris]*Risc0*.https://risc0.com. [Sta]*StarkNet*.https://www.starknet.io/. [Suc]*Succinct*.https://succinct.xyz. [TUZ07]Amnon Ta-Shma, Christopher Umans, and David Zuckerman. “Lossless Condensers, Un- balanced Expanders, and Extractors”. In: *Combinatorica*27.2 (2007), pp. 213–240.doi: 10. 1007 / s00493 - 007 - 0053 - 2.url:https : / / www. cs. utexas. edu / ~diz / pubs / condenser.pdf. [VSBW13]Victor Vu, Srinath Setty, Andrew J. Blumberg, and Michael Walfish. “A hybrid architec- ture for interactive verifiable computation”. In: *Proceedings of the 34th IEEE Symposium* *on Security and Privacy*. Oakland ’13. 2013, pp. 223–237. [XZZPS19]Tiancheng Xie, Jiaheng Zhang, Yupeng Zhang, Charalampos Papamanthou, and Dawn Song. “Libra: Succinct Zero-Knowledge Proofs with Optimal Prover Computation”. In: *Proceedings of the 39th Annual International Cryptology Conference*. CRYPTO ’19. 2019, pp. 733–764. [ZCF24]Hadas Zeilberger, Binyi Chen, and Ben Fisch. “BaseFold: Efficient Field-Agnostic Poly- nomial Commitment Schemes from Foldable Codes”. In: *Proceedings of the 44th Annual* *International Cryptology Conference*. Vol. 14929. CRYPTO ’24. 2024, pp. 138–169.

[Zei24]Hadas Zeilberger.*Khatam: Reducing the Communication Complexity of Code-Based SNARKs*. Cryptology ePrint Archive, Report 2024/1843. 2024.
