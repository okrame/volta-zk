# A Unified Framework for Succinct Garbling from Homomorphic Secret Sharing

Yuval Ishai¹ *⋆*, Hanjun Li², and Huijia Lin² 1 Technion, Haifa, Israel yuvali@cs.technion.ac.il 2 University of Washington, Seattle, WA, USA *{*hanjul,rachel*}*@cs.washington.edu

Abstract. A major challenge in cryptography is the construction of *succinct garbling schemes* that have asymptotically smaller size than Yao’s garbled circuit construction. We present a new framework for succinct garbling that replaces the heavy machinery of most previous constructions by lighter-weight *homomorphic secret sharing* techniques. Concretely, we achieve *1-bit-per-gate* (amortized) garbling size for Boolean circuits under circular variants of standard assumptions in composite-order or prime-order groups, as well as a lattice- based instantiation. We further extend these ideas to *layered* circuits, improving the per-gate cost below 1 bit, and to *arithmetic* circuits, eliminating the typical *Ω*(*λ*)-factor overhead for garbling mod-*p* computations. Our constructions also feature “leveled” variants that remove circular-security requirements at the cost of adding a depth-dependent term to the garbling size. Our framework significantly extends a recent technique of Liu, Wang, Yang, and Yu (Eurocrypt 2025) for lattice-based succinct garbling, and opens new avenues toward practical succinct garbling. For moderately large circuits with a few million gates, our garbled circuits can be *two orders of mag-* *nitude smaller* than Yao-style garbling. While our garbling and evaluation algorithms are much slower, they are still *practically feasible*, unlike previous fully succinct garbling schemes that rely on expensive tools such as iO or a non-black-box combination of FHE and ABE. This trade-off can make our framework appealing when a garbled circuit is used as a functional ciphertext that is broadcast or stored in multiple locations (e.g., on a blockchain), in which case communication and storage may dominate computational cost.

*⋆* This paper describes work performed at the Technion and is not associated with Amazon.

# Table of Contents

1 Introduction................................................................ .3

1.1 Our Results in a Nutshell................................................ .4
1.2 Related Works.......................................................... .8
2 Technical Overview.......................................................... .11 3 Preliminaries............................................................... .16

3.1 Definition of Garbling................................................... .17
3.2 Hardness Assumptions in Paillier Groups.................................. .18
3.3 Lattice Hardness Assumptions............................................ .21
4 aHMAC and HSS as Evaluation Procedures.................................... .22

4.1 aHMAC and HSS under Paillier Groups................................... .22
4.2 aHMAC and HSS under Prime-Order Groups............................... .25
4.3 aHMAC and HSS under Lattices.......................................... .27
4.4 aHMAC Constructions under Lattices..................................... .29
5 Succinct Boolean Garbling Schemes........................................... .30

5.1 Sub-protocol for Garbling *O*(log*λ*)-ary Boolean Gates....................... .33
5.2 A Leveled Variant under Paillier Groups................................... .38
5.3 Instantiations under Lattices............................................. .44
5.4 Instantiations under Prime-Order Groups.................................. .50
5.5 Security Amplification for Prime-Order Group Instantiations.................. .56
6 Efficient Arithmetic Garbling Schemes......................................... .61

6.1 Handling Large *R* using Chinese Remainder Theorem........................ .63
7 Concrete Efficiency Analysis.................................................. .65

## 1 Introduction

Introduced by Yao in the 1980s, a garbling scheme [Yao82,BHR12] allows a “garbler” to trans-

||n|m|
|---|---|---|
|i,0 i,1|i x|i,x i∈[n]|

form a Boolean circuit *C* : *{*0*,*1*} →{*0*,*1*}* into a *garbled circuit C*ˆ along with a pair of short keys k*,* k for each input bit *x*. Given the circuit *C*, the garbled circuit *C*ˆ, and an *encoded* *input* consisting of the input labels k = *{*k*i}* for an unknown input *x*, an efficient “eval- uator” can compute *C*(*x*) while learning nothing else about *x*. An important feature of garbled circuits is that the input keys are short, growing only with the security parameter *λ* and not with the size of the circuit *C*. Garbling schemes serve as fundamental building blocks in cryptography and have found a variety of applications, including constant-round secure computation [Yao82,BMR90,FKN94, GS18,BL18,HIKR23], low-complexity cryptography [AIK05], proof systems [GGP10], single- key functional encryption [SS10], offline-online secure computation [CEMY09,AIKW13], and many more. See [App17] for a survey. A central research direction is to minimize the size of garbled circuits. This is motivated by the fact that in typical applications, the garbler needs to communicate the garbled circuit to the evaluator. Minimizing size has a compounded impact when the same garbled circuit is distributed to multiple parties, translating into proportional bandwidth and storage savings across all recipients. For example, a garbled circuit implementing a complex algorithm can be generated and broadcasted to many receivers during an offline phase, or even stored on a blockchain, allowing fast online computation once the inputs are known. Succinct Garbling. In this work, we focus on the task of obtaining *succinct* garbled circuits. Our default notion of succinctness requires that the bit-length of the garbled circuit be smaller than the description size of the original circuit. Concretely, we say that a garbling scheme (for Boolean circuits) is succinct, if for sufficiently large *C* we have *|C*ˆ*| < |C |* log *|C|*, where *|C|* denotes the size of a Boolean circuit *C* (number of gates, with fan-in 2 3 ) and *|C*ˆ*|* denotes the bit length of the string *C*ˆ; 4 note that describing a general circuit *C* requires at least *|C|* log *|C|* bits. This is a natural threshold, since it implies that a succinct garbled circuit is less expensive to communicate than the original circuit. Once this minimal threshold of succinctness is crossed, we can aim for a full spectrum of better levels of succinctness. Concrete succinctness goals we consider in this work include garbling with 1-bit-per-gate, or even *O*(1*/*log log*λ*)-bits-per-gate, where *λ* is the security parameter. (These are all amortized costs, assuming *|C|≫ n,m,λ*.) The ultimate goal is achieving *full succinctness*, where the garbled circuit size is independent of the size of the original circuit. Over the past four decades, tremendous progress has been made on reducing the garbled circuit size, even reaching the ultimate goal of full succinctness. However, significant gaps remain, especially when requiring the constructions to be efficient enough to be implemented.

– *Fast Non-Succinct Garbling Schemes.* Yao’s original garbled circuit construction [Yao82] and its optimizations [BMR90,NPS99,KS08,PSSW09,KMR14,GLNP15,ZRE15,RR21] remain the most practical general-purpose garbling schemes, as they only rely on fast symmetric- key cryptography. The current state-of-the-art, due to Rosulek and Roy [RR21], garbles an

3 By default, the number of gates counts all fan-in 2 gates, including XOR, AND, OR. But in fact, our results apply also to circuits with a much richer set of gates that include all possible fan-in-*O*(log*λ*) gates; see below. 4 Note that *C* and *C*ˆ are syntactically different objects. *C* is a circuit, while *C*ˆ is a binary string. Adopting standard notation, *|C|* denotes the number of *gates* in the original circuit *C*, while *|C*ˆ*|* denotes the bit-length of the garbled circuit.

AND gate using 1*.*5*λ* + 5 bits, while XOR and NOT gates are free, using a random oracle. Note that this does not meet our succinctness criterion, since security against poly(*|C|*)-time adversaries implies that *λ >* log *|C|*. Indeed, high communication cost is typically the main practical bottleneck in applications that rely on Yao-style garbling. – *Fully Succinct Garbling Schemes.* On the other extreme, fully succinct garbled circuits have been shown feasible under standard assumptions. Though theoretically optimal, the con- crete garbling size is astronomically large, making these constructions practically infeasible. In addition, existing schemes rely either on indistinguishability obfuscation (iO) [KLW15, BCG + 18] or on a non-black-box combination of fully homomorphic encryption (FHE) and attribute-based encryption (ABE) [GKP + 13,BGG + 14,HLL23]. These do not only incur a high computational overhead but also rely on a limited class of assumptions, such as circular- secure LWE (e.g., [Gen09,BV11,GSW13]) or combinations of multiple assumptions (e.g., LPN over large fields, local PRG, and DLin over bilinear groups).

As is often the case in cryptography, diversifying assumptions may also lead to efficiency benefits. This motivates the following question:

*Can succinct garbling schemes be based on a broader set of assumptions,* *with improved efficiency?*

Two recent works have made major progress on succinct garbling without the heavy machin- ery of iO, FHE, or ABE. The work of [LWYY24] presented garbled circuits with 1-bit-per-gate based on variants of RLWE or NTRU, while [ILL24] achieved *fully succinct* garbling for weak classes of programs, including truth-tables and DFAs, from a variety of group-based assump- tions. The latter results build on a fully succinct *partial* garbling scheme for general circuits, applying a computation on a secret input on top of a computation on a public input. Here full succinctness requires the garbled circuit size to be independent of the complexity of the public part of the computation.

1.1 Our Results in a Nutshell Following the recent momentum, we present a unified framework for constructing succinct gar- bled circuits with 1-bit-per-gate using techniques for *homomorphic secret sharing* (HSS) [BGI16, BGI + 18,BKS19,OSY21,RS21,MORS24]. Our unified framework can be instantiated using pirme order groups or Paillier groups or lattices, relying on circular-security variants of the power-DDH assumption or a circular power-RLWE assumption. (See discussion of these as- sumptions below.) We further show how to avoid circular security altogether in a “leveled” variant of our unified framework, where the garbled circuits contain additional components of size *D ·*poly(*λ*) that depend the circuit depth *D* but not on the circuit size. Note that the leveled version already gives 1-bit-per-gate garbling for low-depth circuits, including NC¹ or depth-*λ* cir- cuits, that arise in many applications. We summarize our results on succinct Boolean garbling in the following theorem, and compare it with prior schemes in Table1. Theorem (Succinct Boolean Garbling, Informal). *Assuming either: (1) circular Power-DDH* *in Paillier groups (Definition7), or (2) a variant of circular Power-DDH in prime-order groups* *(Definition11), or (3) circular Power-RLWE (Definition9), there is a garbling scheme for* *Boolean circuits C with garbled circuit size |C*b*|* = *|C|* + poly(*λ*)*.* *Assuming Power-DDH (Definition6) in Paillier or prime-order groups, or Power-RLWE* *(Definition8), there is a leveled variant with garbled circuit size |C*b*|* = *|C|* + *D ·* poly(*λ*) *for* *circuits of depth D.*

See Theorem2and Corollary1for the formal statements on instantiations from Paillier groups and lattices. The instantiation using prime order groups is slightly more complex and proceeds in two steps. In the first step, we obtain a 1-bit-per-gate Boolean garbling with inverse polynomial correctness and privacy errors assuming the circular Power-DDH assumption, as formally stated in Theorem2and Corollary1. Then in the second step, we make the errors negligible, using correctness and privacy amplification, assuming a variant of the circular Power- DDH assumption (Definition11). Importantly, it turns out that the amplification does not increase the (amortized) per-gate garbling size, keeping 1-bit-per-gate. See Section5.5.

|Class|ˆ |C | + |x ˆ ||Tool|
|---|---|---|
|general|O (λ) ·|C||Symmetric|
|general|poly(λ) · (n + m)|iO FHE+ABE Lattice|
|weak classes e.g. DFA|poly(λ) · (n + m)|HSS|
|general||C| + poly(λ) · n|SHE|
|general layered general layered||C| + poly(λ) · n |C| + poly(λ) · n log log λ |C| + poly(λ) · (n + D) |C| + poly(λ) · (n + D) log log λ|HSS|

Assumption Yao [Yao82] OWF Fully Succinct +

e.g.,[BGG 14] cir-LWE Fully Succinct
Group cir-P-DDH ILL24 [ILL24] cir-RLWE LWYY24 [LWYY24] Lattice cir-NTRU Group cir-P-DDH This Work Lattice cir-P-RLWE

P-DDH P-RLWE

Table 1. Comparison between Boolean garbling schemes, in terms of *the class of Boolean circuits handled*, *garbled*

*circuit size*, *the cryptographic tool used*, and *assumptions*. For assumptions, we list both the mathematical structure and the concrete assumption. *λ* denotes the security parameter, *|C|* the number of gates in *C*, *n* the input length, *m* the output length, and *D* the depth. OWF stands for one-way function and SHE for somewhat homomorphic encryption.

Extension 1: Beating 1-bit-per-gate. Our framework can be further extended in two inter- esting ways. First, for *layered* circuits, we can improve the garbling size to *O*(1*/*log log*λ*)-bits- per-gate. This gives the first garbling scheme for a natural and general class of circuits that goes below the bar of 1-bit-per-gate, without relying on iO or FHE plus ABE. Previously, this was only achieved for simple programs such as DFAs [ILL24]. In fact, this follows as a corollary of a more general construction of a garbling scheme for circuits built from “supergates”, including all gates with *O*(log*λ*)-fan-in, and the garbling size is 1 bit per “supergate.” Extension 2: Succinct arithmetic garbling. We extend our unified framework to garble *arithmetic* circuits, whose gates perform additions and multiplications modulo *p* or over the integers. Under the above assumptions, we garble arithmetic circuits modulo *p* with *O*(log*p*)- bits-per-gate for general moduli *p* (for small modulus *p* = poly(*λ*), the constant behind the big-O is 1). Note that garbling schemes for mod-*p* computations automatically imply garbling schemes for bounded integer computations where the wire values are guaranteed to be smaller than *p*. This represents significant progress on the front of succinct arithmetic garbling, without relying on iO or FHE plus ABE. As summarized in Table2, the state-of-the-art arithmetic garbling schemes require *Ω*˜(log *p · λ*)-bits-per-gate for Z*p*computation [BLLL23,LL24,Hea24]. We eliminate the *λ*-multiplicative overhead.

For the simpler task of bounded integer garbling, prior works [BLLL23,MORS24] have shown how to trade the *Ω*(*λ*)-multiplicative overhead for an additive poly(*λ*)-overhead, achieving (log*p*+poly(*λ*))-bits-per-gate, based on DCR. We improve the state-of-the-art by diversifying the assumptions, adding prime-order groups and lattices, and removing the large additive poly(*λ*) overhead.

Ring *|C*ˆ*|* + *|x*ˆ*|* Tool Assumption [BLLL23] Z *|C|·* (*O*(*ℓ*) + poly(*λ*)) LHE Paillier DCR [MORS24] Z *|C|·* (*ℓ* + poly(*λ*)) HSS Paillier cir-DCR [BLLL23] Z*p |C|· λ ·* (*O*(log*p*) + poly(*λ*)) LHE Paillier strong DCR [LL24,Hea24] Z*p |C|· λ · O*e(log*p*) Symmetric CRH ⋆cir-P-DDH *|C|· O*(log*p*) + poly(*λ*) *· n* Paillier <u>cir-P-RLWE</u> This Work Z*p* HSS Prime Group ⋆ P-DDH *|C|· O*(log*p*) + poly(*λ*) *·* (*n* + *D*) Lattice P-RLWE

Table 2. Comparison between *arithmetic* garbling schemes, in terms of *ring supported*, *garbled circuit size*, *the*

*cryptographic tool used*, and *assumptions*. For integer computations, the wire values must be smaller than an a priori upper bound 2 *ℓ*. For assumptions, we list both the mathematical object it relies on and the concrete assumption. *λ* denotes the security parameter, *|C|* the number of gates in *C*, *n* the input length, and *D* the depth. CRH stands for Correlation Robust Hash, LHE for linearly homomorphic encryption. Strong DCR refers to DCR where the secret exponent of the hard subgroup is chosen to be a random *λ*-bit number, instead of *O*(log*N*)-bit number. ⋆ indicates that when the prime is *O*(log(*λ*))-bit long, the size of garbling is *|C|·* log*p*+ poly(*λ*)*· n* and *|C|·* log*p* + poly(*λ*) *·* (*n* + *D*) respectively, eliminating the hidden constant factor multiplied with log *p*.

Concrete Succinctness. Our 1-bit-per-gate Boolean garbling scheme improves the concrete garbling size even with just a moderately large number of gates. Recall that asymptotically the garbling size is *|C*ˆ*|* = *|C|* + poly(*λ*). Here the poly(*λ*) additive term represents the size of some global public data pd. The concrete size of this global data determines when using our schemes yields smaller garbled circuits compared with Yao-style garbled circuits. The break-even point depends on the instantiation, as well as the choice of a PRG seed length. For our estimation below and in Section7, we optimistically assume an “HSS-friendly” PRG with 128-bit seed and output length *≈|C|*. Designing MPC/FHE/HSS-friendly PRGs is an active research direction; see, e.g., [ARS + 15,GRR + 16,BCG + 17,CCKK21,ABG + 24,FLLL24,CCH + 24] and references therein. For such PRGs, there is typically a tradeoff between computational cost and seed length; the size of the global data pd in our constructions scales linearly with the seed length. On the other hand, the number of restricted multiplications (between an intermediate value and an input bit) needed for evaluating each output bit of the PRG, which is upper bounded by the branching program size, directly influences the computational cost. While research on HSS-friendly PRGs is still in its infancy, there is a large space of possible designs to explore. We hope that the goal of practical succinct garbling will further motivate research on the concrete efficiency of HSS-friendly PRGs. Table3in Section7summarizes the concrete sizes of the global data. The Paillier instantia- tion has just 0.38MB global data, the simple instantiation using Prime-order groups *with inverse* *polynomial errors⁵* has 5.1MB global data which can be optimized down to just 0.13MB, and

As mentioned above, these errors can be made negligible via correctness and security amplification. The am- plification step increases the size of the global data and computational efficiency by a factor of *ω*(1) factor

our lattice instantiation has 71MB global data. Comparing with using optimized Yao’s garbled circuits with estimated size⁶ of *λ|C|*, our 1-bit-per-gate garbling is smaller when the original circuit satisfies *|C | > |*pd*|/*(*λ −* 1). Concretely, the break-even point is *|C|* = 24*K* for Paillier instantiation, 8*K* for optimized prime order groups, and 4*.*5*M* for lattices. For moderately large circuits, e.g., of size 10 7 gates, our optimized prime order group instantiation is smaller than Yao-style garbling by a factor of 116 (from 160MB to 1.38MB), while our Paillier group instan- tiation is smaller by a factor of 98 with size 1.63MB. For reference, the plain circuit description size is at least 29MB. Compared with the recent work of Liu et al. [LWYY24] that constructed 1-bit-per-gate garbled circuits based on circular RLWE, the public data in the latter has a much larger size of 10*GB*. This results from the use of the Gentry-Sahai-Water fully homomorphic encryption scheme [GSW13], which has much larger ciphertexts than the HSS encodings used in this work. Finally, we compare with fully succinct garbling schemes. The iO-based constructions are not currently implementable, while the FHE+ABE-based constructions [GKP + 13,BGG + 14, HLL23] have astronomically large input labels and/or computational costs, and hence are also impractical. The label size for each input bit of the RLWE instantiation of the succinct garbling scheme of [GKP + 13,BGG + 14] is *Ω*(*n²* log *q⁴*), where *n* and *q* are RLWE degree and modulus satisfying *n¹* *−ϵ* *>* log *q > D* for some *ϵ ∈* (0*,*1) and *D* is the circuit depth. This means each input label has size *ω*(*D⁶*), which is prohibitive even for small depth such as 100. The recent work [HLL23] removes the constraint of log *q > D*, allowing for smaller modulus and degree. However, this requires performing “boostrapping” inside ABE, which is very computationally expensive. In summary, for circuits of moderate size around 10 5 to 10 6 gates, the garbled circuits of our schemes are concretely smaller than all prior constructions.

Towards Practical Succinct Garbling. Concretely, our garbling schemes require evaluating a PRG using HSS, in addition to a few other HSS operations per gate. Assuming each output bit of the PRG can be evaluated using a restricted multiplication straightline (RMS) program of size *S*, or alternatively a branching program of size *S*, then garbling and evaluating a general Boolean circuit require *|C|·* (4*S* + *O*(1)) homomorphic RMS operations. In particular, since the HSS restricted multiplication operation is much more expensive than the HSS addition operation, if the PRG requires *S×*restricted multiplications, the per-gate cost of garbling is dominated by 4*S×*+ *O*(1) homomorphic restricted multiplication. As discussed above, we optimistically conjecture an HSS-friendly PRG with a large stretch (as our garbling size scales linearly with the seed length), and where each output bit can be evaluated using a reasonably small number of restricted multiplication operations. Then in the lattice instantiation, the per-gate compu- tation boils down to computing a small number of multiplication/addition of *Rq*elements and rounding.

Our Assumptions. The leveled version of our unified framework can be based on natural flavors of the Power Decisional Diffie Hellman (P-DDH) assumption (Definition6), introduced in [GJM03,CNs07,AHI11] and further used in [GHKW17,KY18,AMN + 18,BMZ19,ILL24], in Paillier or prime-order groups. P-DDH postulates that for appropriately sampled group el-

asymptotically, but does not increase the per-gate communication cost. For concrete efficiency, we consider the simpler instantiation without amplification. The state-of-the-art optimization over Yao’s garbled circuit is by [RR21], which contains 1*. λ* bits per AND gate, and garbling XOR is free. We use *λ|C|* as a rough estimation of the garbled circuit size.

*s s*2 ement *g* and exponents *s* and *a,b* sampled randomly from a range [*ℓ*], the triple (*g,g,g*) is indistinguishable from (*g,g* *a* *,g* *b* ). To remove the *D ·*poly(*λ*) additive term in the size of “leveled” garbled circuits, we need the following circular-security variant of this assumptions. The Circular Power Decisional Diffie Hell- man (CP-DDH) assumption (Definition7) asserts that a circular encryption of bits of the secret key *s* using powers of the secret key is pseudorandom. More precisely, for appropriately sam- pled group elements *g,f* and random exponents *s* and *{ai,bi,ci}i*, the following computational indistinguishability holds:

*s s*2*aisais*2*ais*[*i*] *s d aibici* 7 CP-DDH: *g,g,g,* (*g,g,g · f*)*i∈*[log*s*]*≈cg,g,g,* (*g,g,g*)*i∈*[log*s*]*.*

The P-DDH and CP-DDH assumptions can be postulated over Paillier or prime order groups. For the Paillier group, the assumption can be further simplified (still sufficient for succinct garbling) *r rs rs*2*s* to (*g,g,g* (1 + *N*)) being pseudorandom, where *g* is a generator of the hard subgroup and the exponents *r,s* are randomly sampled. This optimization is introduced for concrete efficiency; see Section7. For prime-order groups, Power-DDH and Circular Power-DDH hold in the standard generic group model (GGM) [Sho97], as shown in [ILL24]. In particular, our succinct garbling scheme can be instantiated in the (prime-order) GGM, under the mild assumption of a PRF in NC¹. Furthermore, under the CP-DDH assumption in prime order groups, we only obtain succinct garbling with inverse polynomial errors. As mentioned above, we can amplify correctness and privacy to make the errors negligible without hurting the amortized per-gate garbling size. This requires a variant of the CP-DDH assumption, which instead of hiding the bits of the secret *s*, hides bits of the secret shifted by a public constant *s* *′*, *t* = *s* + *s* *′*.

*s s*2*′ aisais*2*ait*[*i*] *s d aibici* CP-DDH*: *g,g,g,s,* (*g,g,g · f*)*i∈*[log*s*]*≈cg,g,g,* (*g,g,g*)*i∈*[log*s*]*,*

where *t* = *s* + *s* *′*

Alternatively, our garbling schemes can be based on the Power-RLWE assumption (Defi- nition8) for the leveled version and circular Power-RLWE assumption (Definition9) for the full-fledged version. Introduced in [ARS24], Power-RLWE postulates that RLWE samples with *small* secrets *s* and *s²*, and the same public vector a in a polynomial ring *Rq*, (a*,s*a+e₁*,s²*a+e₂) is pseudorandom. The circular variant further uses the last sample to hide the secret *s*, assuming the pseudorandomness of (a*,s*a + e₁*,s²*a + e₂ + *s∆*), where *∆* is a constant.

1.2 Related Works In this section we provide a detailed comparison between our results and prior or concurrent related works. Comparison with [ILL24]. The work of [ILL24] constructed fully succinct garbling schemes for weak classes of programs, including truth tables, DFA, and decision trees, based on different group-based assumptions. This builds on a fully succinct *partial garbling schemes* (equivalently, conditional disclosure of secrets), where most of the input is public. cIn comparison, our garbling schemes achieve a weaker level of succinctness, but apply to all circuits while fully hiding the input. Our work provides a lattice-based instantiation of the succinct partial garbling scheme from [ILL24] and the underling homomorphic MAC primitive. Compared to [ILL24], our formulation here includes *g*
*s* in the indistinguishability, which we believe is more natural and easier to use. See also the remark under Definition7.

Comparison with [LWYY24]. Another recent work [LWYY24] constructed 1-bit-per-gate garbled circuits using special somewhat homomorphic encryption schemes, namely the GSW scheme instantiated using circular variants of RLWE or NTRU. In comparison, our unified framework presents a more general design principle using HSS. It yields instantiations based on more diverse assumptions that include different group-based assumptions. Our garbled circuits have smaller concrete sizes as discussed in the introduction (also see Table3), owing to the fact that HSS encoding is smaller than GSW ciphertexts. In addition, we show how to go below 1-bit-per-gate for layered circuits as well as an extension to arithmetic garbling. Comparison with [MORS25]. The concurrent and independent work of [MORS25] achieves a similar set of results to this work based on similar techniques. We note the following differences. For Boolean garbling, both [MORS25] and this work achieve (amortized) 1 bit per gate for general circuits, and *O*(1*/*log log*λ*) bits per gate for layered circuits under circular assumptions. Both works have leveled variants that avoid circular assumptions at the price of an additive Depth(*C*) *·* poly(*λ*) size overhead. The differences are in the underlying assumptions: the work of [MORS25] focuses on constructions in Paillier groups based on a circular DCR assumption (resp., standard DCR for the leveled variant), while our work presents a unified framework with instantiations in Paillier groups, prime-order groups, or lattices, based on the CP-DDH or CP-RLWE assumptions (resp. P-DDH or P-RLWE for the leveled variants). The difference in assumptions stems from the fact that [MORS25] use a more sophisticated variant of the basic technique to base their construction (in the leveled case) on the standard DCR assumption. While DCR is more widely used than P-DDH in Paillier groups used in our work, these assumptions seem technically incomparable. We believe that adapting the technique from [MORS25] to our constructions will give leveled variants under Paillier groups, prime- order groups, or lattices based on the standard DDH or RLWE with small secret assumptions. However, this seems to come at the price of a higher concrete overhead. The current work initiates a study of the concrete efficiency of group-based and lattice-based garbling, including an effort to optimize the additive terms. For arithmetic garbling, the work of [MORS25] constructs a scheme over *bounded integers* by 2 *ℓ*, with (amortized) (*ℓ* + *λ*) bits per gate for general circuits, and *O*((*ℓ* + *λ*)*/*log log*λ*) bits per gate for layered circuits. In contrast, our work constructs schemes for computation over Z*R*computation for *any modulus R* of *ℓ* bits, with (amortized) *O*(*ℓ*) bits per gate for general circuits. We believe that we can also obtain additional savings in cost for layered arithmetic circuits. Besides the distinction between supporting bounded integers vs. Z*R*computation, the above differences in assumptions also hold for the arithmetic garbling results. Comparison with [CHHK25]. The concurrent and independent work of [CHHK25] con- structed Boolean garbling schemes with amortized per-gate garbling size below *λ*. Their first *√* scheme is proven in the Generic Group model (GGM), achieving *λ/* log*λ*-bit-per-gate garbling size. Their second scheme is proven in the plain model under the Power-DDH assumption to- gether with the existence of a tweakable correlation robust hash, attaining a garbled circuit *√* size of *λ ·|C|/* log*λ* + poly(*λ*) *· D*, where *D* is the depth of the circuit for *layered* circuits. In comparison, our Boolean garbling schemes achieve 1-bit-per-gate for general circuits, and *O*(1*/*log log*λ*)-bit-per-gate for layered circuits, again, removing the *Ω*˜(*λ*) multiplicative over- head. On the other hand, our schemes make a non-black-box use of a PRF (or high-stretch PRG), whereas their constructions can be cast unconditionally in the GGM. Other Use of HSS in Garbling by [GN25]. The recent work of [GN25] constructed a garbling scheme that supports mixed circuits with both Boolean and bounded integer arithmetics using

HSS techniques. The core innovation is using HSS techniques to implement an efficient garbling gadget for bit-decomposition that is compatible with the state-of-art arithmetic garbling scheme of [MORS24]. Overall, their scheme has a garbling size of (amortized) *O*(*λ*) bits per Boolean gate, (*ℓ* + *λ*DCR) bits per arithmetic gate (over integers bounded by 2 *ℓ* ), and *O*(*ℓ · λ*DCR*/*log(*λ*)) bits per bit-decomposition gate. In comparison, we apply HSS techniques to construct significantly more succinct Boolean and arithmetic garbling with (amortized) 1 bit per Boolean gate, and *O*(*ℓ*) bits per arithmetic gate (over an *ℓ*-bit modulus).

Updated Version of [ILL24]. As explained in the technical overview below, our results use the aHMAC constructions from [ILL24] as one of the main building blocks. The updated version of [ILL24] presents new constructions of leveled aHMAC that improve the assumptions from P- DDH (in Paillier and prime-order groups) or P-RLWE respectively to standard DDH or RLWE. Applying the new constructions of leveled aHMAC, we can obtain all of our leveled garbled circuit results from DDH (in Paillier and prime-order groups) or RLWE.

Inspiration from Arithmetic Garbling. Our work builds upon a recent line of research [BLLL23, LL24,Hea24,MORS24] for improving the garbling size of *arithmetic* circuits. These circuits consist of addition and multiplication gates, evaluated over a ring, typically Z*p*or Z, and an input *x* consists of ring elements. Because there is a simple baseline solution that uses a Boolean garbling scheme to garble a Boolean circuit implementing the arithmetic circuit of interest, re- search naturally focuses on what can be done differently. The first work on arithmetic garbling by Applebaum et al. [AIK11] proposed an aritsshmetic generalization of input keys and labels – the keys of an input wire describes an affine functions K*i*and the label for *xi*is the output K*i*(*xi*). They then constructed an garbling scheme for bounded integer computation with such arithmetic input labels, based on LWE, which sends *ℓ ·* poly(*λ*) bits per gate when the wire val- ues are bounded by 2 *ℓ*. Building upon [AIK11] and a subsequent work by Ball et al. [BMR16], recent works [BLLL23,LL24,Hea24,MORS24] have renewed research on arithmetic garbling on several different fronts: 1) diversifying assumptions, 2) supporting more models of computing, such as, Z*p*computation, and mixed circuits with both arithmetic and Boolean gates, and 3) optimizing succinctness. We focus on the succinctness aspect. The baseline solution using Yao’s garbled circuits requires *Ω*(*λℓ*log*ℓ*)-bits-per-gate. Interestingly, the work of Ball et. al. [BLLL23] showed that bounded integer computations can be garbled with *O*(*ℓ* + poly(*λ*))-bits-per-gates, trading the *O*(*λ*log*ℓ*) multiplicative factor for an additive poly(*λ*) term, assuming the DCR assumption over Paillier/Damg˚ard-Jurik groups. Their technique relies on simple additive homomorphism supported by DCR, rather than iO or FHE plus ABE underlying fully succinct garbling. The work of [MORS24] further improved size to exactly *ℓ* + poly(*λ*)-bits-per-gate, by applying HSS techniques, assuming the circular security of Damg˚ard-Jurik encryption. These works shed new light on how to avoid the *O*(*λ*)-multiplicative factor overhead associ- ated with Yao’s garbled circuits, using lightweight tools. But their techniques are limited in two ways. First, the additive poly(*λ*) is large, proportional to log*N* where *N* is the Paillier modulus, and dominates when wire values are relatively small *ℓ* = *o*(log*N*). In particular, when used to garble Boolean computation *ℓ* = 1, the size is *O*(log*N*)-bits-per-gate, worse than Yao’s garbled circuits. Second, their methods do not extend to garbling Z*p*-arithmetic circuits. Despite past efforts [AIK11,BMR16,BLLL23,LL24,Hea24], the most succinct garbled Z*p*-circuits have size *Ω*(*λ*log*p*)-bit-per-gate, carrying the *Ω*(*λ*)-multiplicative factor overhead. As discussed before, the current work overcomes the above two limitations. Our unified framework also gives a Z*p*-garbling scheme with *O*(log*p*)-bits-per-gate for general *p*, based on

various group and lattice assumptions. Our technique is inspired by techniques developed in the context of arithmetic garbling, particularly the HSS-based technique from [MORS24].

## 2 Technical Overview

Starting Point: Succinct Garbling of [ILL24]. Our starting point is the recent new ap- proach to succinct garbling from [ILL24], which combines a new primitive called fully succinct *partial* garbling and fully homomorphic encryption (FHE) to obtain fully succinct standard gar- bling. This follows the FHE+ABE blueprint of [GKP + 13,BGG + 14], replacing succinct ABE by succinct partial garbling. In more detail, a partial garbling scheme generalizes standard garbling to consider com- putations with public and private parts, *C*(x*,*y) = *C*Priv(y*,C*Pub(x)). A partial garbling of *C* computes a garbling *C*b and a pair of short keys k*x,i,*0*,* k*x,i,*0for every bit in x, as well as k*y,i,*0*,* k*y,i,*1for every bit in y. The garbling *C*b, the keys *{*k*x,i}*, *{*k*y,i}* selected corresponding to inputs x*,*y, together with x in the clear reveals the computation result z = *C*(x*,*y), and nothing else about the private input y. The scheme of [ILL24] achieves a fully succinct garbling size *|C*b*|≤|C*Priv*|·* poly(*λ*), independent of the complexity of *C*Pub. The observation from [ILL24] then is to apply partial garbling to the computation

|C(ct, sk) = Dec(sk, HEval||(ct|)),||
|---|---|---|---|---|
|x|f x x|∗ z|Priv|∗ z|

x *f* x

i.e. with a public part *C*Pub(ct) = HEval
*f* (ct) = ct computing homomorphic evaluation of some function *f* over FHE ciphertexts ct, and a private part *C* (sk*,*ct) decrypting evaluated ciphertexts using the secret key sk as the private input. A partial garbling of *C* reveals the evaluation result z = *f*(x), and guarantees privacy of the secret key sk, which further guarantees privacy of x by FHE security. Therefore, a partial garbling of *C* can be viewed as a standard garbling of the function *f*. Furthermore, the size of *C*b only depends on the complexity of private computation, i.e. FHE decryption, *|C*b*|≤|*z*|·|*Dec*|·* poly(*λ*) = *|*z*|·* poly(*λ*), and does not depend on the complexity of *f*. Hence the partial garbling of *C* is a fully succinct standard garbling of

*f*. While conceptually simple, this solution is far from practically useful due to the heavy computation complexity of FHE. A natural attempt is to use a less powerful, but much lighter- weight, homomorphic encryption (HE) scheme to obtain fully succinct garbling for many low- depth computations *{f*
*i* *}*, and composing them into a high-depth one: *f* := *f* *T*

- *f* *T −*1 *◦... ◦ f₁*.
However, some calculation shows a difficulty. Suppose each *f* *i* is a Boolean circuit of depth *D* with width *W*. The succinct garbling of *f* *i* costs *|f*b *i* *|* = *W ·* poly(*λ*), while our target size is *≤ WD ·* log(*WD*) to achieve succinctness. Without new ideas, we would need a powerful HE supporting *D* = poly(*λ*) depth computation to achieve succinctness. Indeed, our new ideas require looking into the construction of [ILL24], and finding new ways to garble the private computation *C*Privmore efficiently, at the cost of supporting only a restricted form of computation. The Construction of [ILL24] in More Detail. The partial garbling construction of [ILL24] relies on a new primitive, algebraic homomorphic MAC (aHMAC), and the standard Yao’s Boolean garbling to handle the public and private computations respectively. We give a simplified review here, assuming the the free-XOR [KS08] key format in Yao’s garbling. <u>The aHMAC Scheme.</u> An aHMAC scheme is run between an authenticator and an evaluator. They both hold an evaluation key evk. The authenticator additionally holds a PRF key k, and a global secret *s ∈* Z.

– The authenticator when given a bounded integer *xi∈* [*B*] as input, and an associated id,

(*i*) (*i*)
computes its tag as *σxi*:= *s · xi*+ *kx*over Z, where *kx*= PRF(k*,*id) is derived from the id. – The evaluator when given inputs x and tags *σ*x= *{σxi}* can evaluate any arithmetic circuit *C* (with bounded intermediate values by *B*) using the evaluation key: *σ*z*←* EvalTag(evk*,C,σ*x*,*x).

(*i*)
– The authenticator when given only the ids, hence the derived keys k*x*= *{kx}*, can evaluate the same circuit: k*z←* EvalKey(evk*,C,*k*x*).

The scheme guarantees the evaluated tags and keys are consistent: *σ*z= *s ·* z + k*z*over Z, and also that the evaluation key evk and tags *σ*xdon’t leak anything about the global secret *s*.

(*i*)
In this work, we view a pair of tag and key *σxi*, *kx*as an additive share of *sxi*over Z, written

(*i*)
as *⟨sxi⟩* 0 = *kx*, and *⟨sxi⟩* 1 = *σxi*. We view the algorithms EvalKey*,*EvalTag as homomorphically evaluating additive shares of *s*x between a garbler *PG*and an evaluator *PE*, who both hold an evaluation key evk with respect to the global secret *s*. Note that the EvalTag algorithm by the evaluator also needs x in the clear.

|P (evk)|P (evk, x)|
|---|---|
|G|E|
|0|0 1|

*⟨s*z*⟩ ←* EvalKey(evk*,C, ⟨s*x*⟩*)*, ⟨s*z*⟩ ←* EvalTag(evk*,C, ⟨s*x*⟩* 1 *,*x)*.*

The construction of [ILL24] guarantees that given any additive shares of *s*x, as long as all intermediate values of *C*(x) are bounded by *B*, the results of EvalKey*,*EvalTag also form additive shares of *s*z, where z = *C*(x). <u>Yao’s Garbling.</u> In Yao’s garbling of a Boolean circuit *C* (assuming the free-XOR [KS08] key format), the garbler *PG*samples a random key *kj*for every wire *j* in *C*, and a global secret *s*. We view the keys *{kj}* and the global secret *s* as *O*(*λ*)-bit integers in this overview. *PG*provides a garbled table for each gate to the evaluator *PE*, such that if *PE*obtains a set of labels *{li*= *s · xi*+ *ki}* according to an input x = *{xi}*, then she can use the garbled tables to recover a label *lj*= *s · vj*+ *kj*for every wire *j* corresponding to the correct wire value *vj*. In order for *PE*to recover the values *zo*on the output wires *o* in C, a usual trick is to assume the least significant bit (LSB) of *s* is 1, so that LSB(*lo*) = *zo⊕* LSB(*ko*). It suffices for *PG*to send *PE*LSB(*ko*) for every output wire *o*. We take an alternative view of Yao’s garbling not as a static scheme, but as a protocol between a garbler *PG*and an evaluator *PE*.

– Initially *PG*and *PE*jointly hold additive shares of *s*x for some input x = *{xi}*: the garbler holds *⟨sxi⟩* 0 = *ki*, and the evaluator holds *⟨sxi⟩* 1 = *li*. – Then *PG*sends garbled tables to *PE*so that they jointly hold additive shares of *svj*for every wire value *vj*in *C*. – In the end, *PG*and *PE*jointly hold additive shares of *s*z for the output z = *{zo}*: the garbler holds *⟨szo⟩* 0 = *ko*, and the evaluator holds *⟨szo⟩* 1 = *lo*. *PG*then sends *{*LSB(*ko*)*}* to *PE*to reveal z.

The security of Yao’s garbling guarantees that if the global secret *s* is not leaked by the initial additive shares *⟨s*x*⟩* 1 to *PE*, then all communication from *PG*to *PE*can be simulated by *PE*, given only the output z. To summarize the protocol between *PG E*

||||and P||, we write|
|---|---|---|---|---|---|
||||G|E||
|G|0 E|C G|0|E|1|

(*P* : *⟨s*z*⟩*)*,* (*P* : *⟨s*z*⟩* 1 *,*z) *←* Yao (*P* : *⟨s*x*⟩*)*,* (*P* : *⟨s*x*⟩*)*.*

<u>Succinct Partial Garbling from aHMAC and Yao.</u> We again describe the partial garbling scheme

for evaluating *C*(x*,*y) = *C*Priv(y*,C*Pub(x)) as a protocol between the garbler *PG*and the eval- uator *PE*, which we believe is more intuitive. (See Section5for viewing garbling as a 2PC protocol.) It represents a valid garbling scheme as long as *PG*’s communication is independent of the inputs x*,*y except in an initialization phase.

1.In the initialization phase, *PG*sets up the aHMAC scheme with a global secret *s*, and evaluation key evk. He then samples random additive shares *⟨s*x*⟩*
0, *⟨s*x*⟩* 1, for the public input x, and *⟨s*y*⟩* 0, *⟨s*y*⟩* 1 for the private input y. In the end, *PG*sends evk, x, *⟨s*x*⟩* 1 and *⟨s*y*⟩* 1 to *PE*.

2.To evaluate the public computation *C*Pub,
8 *PG*and *PE*locally run EvalKey and EvalTag respectively on their shares *⟨s*x*⟩* 0 and *⟨s*x*⟩* 1.

*PG*: *⟨s*w*⟩* 0 *←* EvalKey(evk*,C*Pub*, ⟨s*x*⟩* 0 )*,*

(1)
*PE*: *⟨s*w*⟩* 1 *←* EvalTag(evk*,C*Pub*, ⟨s*x*⟩* 1 *,*x)*.*

3.To evaluate the private computation *C*Priv, *PG*and *PE*jointly run Yao’s garbling.
(*PG*: *⟨s*z*⟩* 0 )*,* (*PE*: *⟨s*z*⟩* 1 *,*z) *C*

(2)
*←* Yao Priv (*PG*: *⟨s*y*⟩* 0 *, ⟨s*w*⟩* 0 )*,* (*PE*: *⟨s*y*⟩* 1 *, ⟨s*w*⟩* 1 )*.*

The evaluator *PE*outputs z in the end.

In the above protocol, communication from *PG*to *PE*after the initialization phase corresponds to the garbling material *C*b in the garbling scheme. We note since the public computation *C*Pubis evaluated by local procedures, with no communication, we indeed obtain a fully succinct partial garbling scheme. Recall that in this work, we intend to perform homomorphic evaluation of some low-depth computation *f* *i* over HE ciphertexts ctx*i* using the public computation, and then HE decryption using the private computation. Furthermore, in order to compose multiple such evaluations, *...f* *i*+1

- *f* *i* *◦...*, we need to also implement HE re-encryption using the private computation.
We illustrate the modified steps 2 and 3 below. *f* *i* 2’To evaluate the public computation *C*Pub:= HEval, *PG*and *PE*locally run EvalKey and EvalTag respectively on their shares *⟨s ·* ctx*i ⟩* 0, *⟨s ·* ctx*i ⟩* 1. 9

*∗ fi* *PG*: *⟨s ·* ct x*i*+1 *⟩* 0 *←* EvalKey(evk*,*HEval*, ⟨s ·* ctx*i ⟩* 0 )*,* *∗ fi* *PE*: *⟨s ·* ct x*i*+1 *⟩* 1 *←* EvalTag(evk*,*HEval*, ⟨s ·* ctx*i ⟩* 1 *,*ctx*i*)*,*

where ct *∗* denotes homomorphically evaluated ciphertexts. 3’To evaluate the private computation *C*Priv:= Enc*◦*Dec, *PG*and *PE*jointly run Yao’s garbling.

(*PG*: *⟨s ·* ctx*i*+1*⟩* 0 )*,* (*PE*: *⟨s ·* ctx*i*+1*⟩* 1 *,*ctx*i*+1)

*←* Yao Enc*◦*Dec (*PG*: *⟨s ·* sk*⟩* 0 *, ⟨s ·* ct *∗* x*i*+1 *⟩* 0 )*,* (*PE*: *⟨s ·* sk*⟩* 1 *, ⟨s ·* ct *∗* x*i*+1 *⟩* 1 )*.*

Note that the results are shares of fresh HE ciphertexts ctx*i*+1, so the parties can then repeat Step 2’ and 3’ for the next evaluation of *f* *i*+1. 8 A Boolean circuit *C*Pubcan be implemented by an arithmetic circuit over integers bounded by 2. Technically, we mean shares of *s ·* Bits(ct *i*) here, and shares of *s ·* Bits(sk) in step 3’. But we choose to abuse x notations to avoid cluttering.

As explained, the communication by Yao’s garbling to implement Enc*◦*Dec is too much for our purpose. Instead, our idea is to use homomorphic secret sharing (HSS) to replace Yao’s garbling in the above protocol. It may first seem a bit odd to consider HSS as a replacement for garbling. Indeed, in the setting of HSS, both parties *depend* on the input, while in the setting of garbling, *PG*needs to be independent of the input. Our observation is that in the private computation implemented by Yao, Enc*◦*Dec(sk*,*ctx), the most complicated computations, e.g. evaluating a PRG, involve only the secret key sk, which is indeed independent of the actual input x! One can therefore hope to rely on HSS for the complicated computations involving only sk, and in the end incorporate ctx in the remaining simpler steps. Replacing Yao with HSS. An HSS scheme runs between two parties *P₀*, *P₁*. In common constructions, such as [ADOS22,BGI16,BKS19], they both hold encryptions of an input y, denoted *I*y, and jointly an additive share of a global secret *s* over Z consistent with the encryp- tions. Each party *Pb*can locally evaluate any NC1 Boolean circuits *C* over the encrypted inputs via HSS*.*Eval*b*such that the two outputs form additive shares of *s ·* z and z, where z = *C*(y) is the evaluation result.

|P₀(I, ⟨s⟩|)|P₁(I, ⟨s⟩|)|
|---|---|---|---|
|y|0|y|1|
|0|0|1|1|
||||0|

*⟨s*z*⟩, ⟨*z*⟩ ←* HSS*.*Eval₀(*I*y*,C, ⟨s⟩* 0 )*, ⟨s*z*⟩, ⟨*z*⟩ ←* HSS*.*Eval₁(*I*y*,C, ⟨s⟩* 1 )*.*

In an additional step, the party *P₀* may send its share *⟨*z*⟩* (mod 2) to *P₁* to reveal the Boolean evaluation result z. It was observed in [CMPR23] that the above HSS schemes allow for an extended evaluation procedure, where if replacing the additive share of *s* with shares of *s · w* and *w* for some integer *w*, then the extended evaluation results form additive shares of *s · w ·* z and *w ·* z. In other words, the HSS evaluation results over encrypted inputs y can be additionally multiplied with an integer *w*, when the two parties hold additive shares of *sw* and *w*.

<u>P₀(Iy, ⟨s⟩</u> <u>0</u> <u>) P₁(Iy, ⟨s⟩</u> <u>1</u> <u>)</u>

*⟨sw*z*⟩ ⟨sw*z*⟩*

|, ⟨wz⟩|||, ⟨wz⟩|||||
|---|---|---|---|---|---|---|---|
|0 0|||1|1||||
|′|y ′|0 0|′|y||1|1|
|||C||||||
|G ′|0 E|′ 1 ′||||||
||C G|y 0|0 E|y|1|1||

*←* ExtEval(*I,C, ⟨sw⟩, ⟨w⟩*)*, ←* ExtEval(*I,C, ⟨sw⟩, ⟨w⟩*)*.*

Taking the extended evaluation one step further, we can consider a matrix W as the additional input, and compute z = W *· C*(y) (over Z) as the final output. Including the additional step where *P₀* sends its share of z (mod 2) to *P₁* to reveal z, we obtain an HSS evaluation “protocol” for NC1 Boolean circuits *C*, denoted HSS :

(*P* : *⟨s*z *⟩*)*,* (*P* : *⟨s*z *⟩,* z)

*←* HSS (*P* : *I, ⟨s*W*⟩, ⟨*W*⟩*)*,* (*P* : *I, ⟨s*W*⟩, ⟨*W*⟩*)*,*

which we replace Yao’s garbling with in step 3 (Equation2) and 3’ from the previous paragraph. 10 The communication cost from HSS is only *|*z *′* *|* bits, much smaller than that of Yao. One detail to note is that in Yao’s garbling we are free to use the global secret *s* from aHMAC also as the secret in Yao, but now with HSS, we need compatible instantiations with 10 Readers may notice a mismatch, where from step 2 (Equation1), the parties hold shares of *s*w, but not of w. This is not an issue, as *PE* can compute w in the clear from the public input x. The parties now hold a trivial share: *⟨*w*⟩* = 0, *⟨*w*⟩* = w.

aHMAC, (see Section4) so that they can share a common secret *s*. This usage of aHMAC and HSS requires us to prove security of the overall garbling scheme in a non-black-box way. As anticipated, the computation implemented by this protocol is restricted: z *′* = W *· C*(y) over Z, for an NC1 circuit *C*. In order to use HSS Enc*◦*Dec in place of Yao Enc*◦*Dec in Step 3’, we need to find a suitable HE scheme where the Enc *◦* Dec circuit can be implemented in this restricted way: ctx= Enc *◦* Dec(sk*,*ct *∗*

x) = Bits(<u>ct</u>
*∗*

<u>x</u>)*· C*(sk) over Z*.*
|{z} | {z} | {z } z *′* W *C*(y)

While such an HE scheme may seem hard to find, our observation is that the size of evaluated ciphertexts *|*ct *∗* x*|* don’t matter in our scheme, as the communication cost from HSS is exactly the size of a fresh ciphertext *|*ctx*|*. In fact, viewing one-time-pad as a trivial HE scheme suffices! We illustrate a simple case of homomorphically multiplying one-time-pad ciphertexts, and the Enc *◦* Dec computation.

ct*x*:= *x ⊕ rx,* ct*y*:= *y ⊕ ry,* where *rx*= PRF(sk*,*1)*,ry*= PRF(sk*,*2)*.* ct *∗* *z*= HMult(ct*x,*ct*y*) = (ct*x,*ct*y,*ct*x·* ct*y*)*.* Enc *◦* Dec(sk*,*ct *∗* *z* ) = (ct*x⊕ rx*) *·* (ct*y⊕ p₂*) *⊕ rz,* where *rz*= PRF(sk*,*3)

||= C₁(sk)ct|+ C₂(sk)ct||+ C₃(sk)ct|· ct + C₄(sk) over Z.|
|---|---|---|---|---|---|
|||x|y||x y|
|||∗||||
|||z||||

= Bits(ct) *· C*(sk) over Z where *C* := (*C₁,C₂,C₃,C₄*)*.*

The final equality, writing Boolean operations as a polynomial over <u>Z</u>, uses the fact that *x ⊕ y* = *x*+*y−*2*xy* over Z for *x,y ∈{*0*,*1*}*. In the following, we directly write x to denote one-time-padded x, instead of ctx. In summary, our final Boolean garbling scheme for a circuit *C* starts with two parties *PG,PE* holding additive shares *⟨s*x*⟩* and *PE*holding x in the clear, where x represents one-time-padded inputs. For every gate in *C*, in a topological order, both parties applie aHMAC evaluations to “homomorphically” add or multiply two one-time-padded inputs, and then run HSS to decrypt and re-encrypt the resulting bit. The communication cost per gate is excatly 1-bit from the HSS protocol. Generalization: Evaluating *O*(log*λ*)-ary Gates. Observe that the technique of combining aHMAC and HSS from the previous paragraph can be viewed as a more general protocol for computation over some public masked input x and a private secret key sk for deriving the masks. Using aHMAC we can evaluate any arithmetic circuit *C*Pub(with bounded intermediate values) on x, and with HSS we can evaluate any NC1 Boolean circuit *C*Privon sk. The two results are then multiplied as an inner product over Z. We summarize it as a protocol aHMAC-HSS *C*Pub*,C*Priv :

|G|′ 0|′ 1|′||||||
|---|---|---|---|---|---|---|---|---|
|′|Pub|C Priv|,C|G sk|0|E sk|1||
||||||||′||
|E||||||C|,C||

(*P* : *⟨sz ⟩*)*,* (*PE*: *⟨sz ⟩,z*)

*←* aHMAC-HSS Pub Priv (*P* : *I, ⟨s*x*⟩*)*,* (*P* : *I, ⟨s*x*⟩,*x)*,* // *z* = *⟨C* (x)*,C* (sk)*⟩.*

The communication cost of this protocol is 1 bit. Note that the result *z* is revealed to the evaluator *P*, hence should always be masked by a pseudo-random pad derived from sk. Given this more general view, we can in fact use aHMAC-HSS Pub Priv to compute any function *g* over <u>O</u>(log*λ*) masked input bits, and re-mask the resulting value. In particular,
we choose *C*Pub(x) to compute a one-hot vector (0*,...,,,,...,*0), where all but the x-th

component are 0. (See Fact1.) And we choose *C*Priv(sk) = (*...,C*Priv*,*v(sk)*,...*)<u>v</u>to compute a
vector listing evaluated values *g*(x) (and then masked) for all possible values of x.

*∀*v *∈{*0*,*1*}* *|*x*|* *, C*Pub*,*v(x) = 1 iff x = v *C*Priv*,*v(sk) = *g*(v *⊕* PRF(sk*,*id)) *⊕* PRF(sk*,*id *′* )*.* // *z* *′* = *⟨C*Pub(x)*,C*Priv(sk)*⟩* = *g*(x) *⊕* PRF(sk*,*id *′* )*.*

The id*,*id *′* from the above means some distinct ids assigned to every wire of the overall circuit consisting of these *O*(log*λ*)-ary gates. In summary, our generalized technique can garble Boolean circuits consisting of arbitrary *O*(log*λ*)-ary gates, costing 1 bit per such gate. As applications, we show how to obtain a scheme for *layered* circuits *C* Layer with garbling size *|C* \ Layer *|≤ O*(*|C* Layer *|/* log log*λ*)+poly(*λ*) in Section5, and a scheme for arithmetic circuits *C* over Z*R*with garbling size *|C*b*|≤ O*(*|C|* log*R*) + poly(*λ*) in Section6. Other Extensions. Our techniques rely on two primitives:

– aHMAC which has been instantiated under the circular power-DDH (CP-DDH) assumptions in Paillier groups or prime-order groups in [ILL24]; – HSS which has been instantiated under the DDH assumption in Paillier groups [ADOS22], prime-order groups [BGI16], and the RLWE assumption [BKS19].

We introduce a new lattice assumption, CP-RLWE, analogous to the CP-DDH assumption in groups, and show three instantiations of our technique of combining aHMAC and HSS under either CP-DDH in Paillier groups, in prime-order groups, or CP-RLWE. As noted earlier, since we require using a common secret in both aHMAC and HSS, we have to prove the security of our garbling schemes in a non-black-box way. The work of [ILL24] also constructed leveled variants of aHMAC that avoids the circular assumptions at the cost of a larger evaluation key evk with size linear in the supported evaluation depth. We also construct leveled garbling schemes using leveled aHMAC and (normal) HSS at the cost of increasing the garbling size by Depth(*C*) *·* poly(*λ*) bits. They can be instantiated under P-DDH plus DDH in Paillier groups, P-DDH in prime-order groups, or P-RLWE. (See Section5.2for details.) Finally, we note that existing aHMAC and HSS instantiations under prime-order groups suffer a 1*/*poly(*λ*) correctness error. This causes a 1*/*poly(*λ*) error for both correctness and *privacy* in our garbling scheme under prime-order groups. We show in Section5.5how to adapt existing HSS amplification techniques [BGI17] to our setting to remove the 1*/*poly(*λ*) error at the price of increased computation cost and, in the non-leveled variant, assuming a variant of CP-DDH (Definition11).

## 3 Preliminaries

Notations. We use bold letters x to denote a vector, and write x[*i*] to denote its *i*-th component. We write x *⊗* y to denote the tensor product between two vectors. For an integer value within some range *x ∈* [*B*], we write Bits(*x*) to denote its bit-representation as a Boolean vector of dimension *⌈*log *B⌉*, and BitComp(x *∈{,}* *⌈*log *B⌉* ) to denote the linear function that recovers *x* from its bit-representation.

We write *⟨x⟩* 0 *, ⟨x⟩* 1 to denote a pair of additive shares (over a ring *R*) of the value *x*, i.e. the notation represents two arbitrary values *v₀,v₁ ∈R* such that *v₁* = *v₀* + *x* over *R*. In this work we will consider additive shares over the integers *R* = Z and over the polynomial ring *R* = Z[*X*]*/*(*X* *n* + 1) where *n* is a power-of-two. When describing invocations of (sub-)protocols between two parties *PG,PE*, we write

||(P : O ), (P|: O ) ← Protocol ((P||: I ), (P|: I ))||
|---|---|---|---|---|---|---|
||G G|E E||G G|E E||
||||G E||||
|G E|||||||

to mean the parties respectively hold inputs *I,I* when entering the protocol, and obtain outputs *O,O* after the protocol. We assume all gates and wires in a circuit are labeled by distinct ids in *{*0*,*1*}* *λ*. We write InWires(*C*) to denote the ids of all input wires to *C*, and InWires(g)*,*OutWire(g) to respectively denote the ids of input wires to, and output wire from a gate g *∈ C*. When writing invocations of a function *f* : *X →Y*, we use the short-hand *f*(x *∈X* *ℓ* ) *∈Y* *ℓ* to mean parallel invocations of *f* on every component of the vector x. For example, given a PRF : *{*0*,*1*}* *λ* *×{*0*,*1*}* *λ* *→{*0*,*1*}*, we write

## x = x ⊕ PRF(sk,InWires(g))

to mean computing masked inputs x to some gate g using parallel invocations of a PRF (w.r.t. different wire ids) under a secret key sk.

3.1 Definition of Garbling Definition 1(Garbling). *A garbling scheme consists of two efficient algorithms:* – Garb(1 *λ*
*,C*) *takes a circuit C* : *R* *ℓ* *x→ Rℓz, over some ring R, and outputs a garbling C*b*,* *and input key functions {K*

(*i*) *}i∈*[*ℓ* *x*] *, where each key function K*
(*i*) *maps an input* x[*i*] *∈R*
*to a label L*

(*i*) *∈{*0*,*1*}* *ℓ*
*, where the label length is bounded by a fixed polynomial in λ and the* *bit-length of R, independent of the circuit size |C|: ℓ ≤* poly(*λ, |R|*) – Eval(*C, C,*b *{L*

(*i*) *}i∈*[*ℓ* *x*] ) *takes a circuit C, a garbling C*b*, and input labels L*
(*i*) *(corresponding*
*to some input* x *∈R* *ℓ*

*x). It outputs the evaluation result* z *∈Rℓz.*
Correctness: *For every polynomials p*(*λ*)*,p* *′*

(*λ*)*, there exists a negligible function* negl(*λ*) *such*
*that for all λ ∈* N*, circuits C with size |C|≤ p*(*λ*)*, over rings R with bit-length |R|≤ p* *′*

(*λ*)*, and*
*inputs* x *∈R* *ℓ* *x, the following holds:* " # b(*i*)(*C,*b *{K*(*i*)*}*) *←* Garb(1*λ,C*)*,* Eval(*C, C, {L}*) Pr *≥* 1 *−* negl(*λ*)*.* = *C*(x) *L*

(*i*) = *K*
(*i*) (x[*i*])*.*
Security: *There exists an efficient simulator* Sim *such that for every polynomials p*(*λ*)*,p* *′*

(*λ*)*,*
*sequence of circuits {Cλ} where |Cλ|≤ p*(*λ*)*, over rings Rλwith bit-lengths |Rλ|≤ p* *′*

(*λ*) *and*
*sequence of inputs {*x*λ∈R* *ℓλ* *x* *}, the following holds (suppressing the subscript λ for brevity):* () n o (*C,*b *{K*

(*i*) *}*) *←* Garb(1
*λ* *,C*)*,* Sim(1 *λ* *,C,C*(x)) *≈cC,*b *{L*

(*i*) *},*
*λL*(*i*)= *K*(*i*)(x[*i*])*.* *λ* Definition 2(Succinct Garbling Schemes). *We say a garbling scheme is* succinct *if there* *exists a polynomial p*(*λ*) *such that for every supported ring R and every λ ∈* N*, sufficiently large* *circuits C (over R) with |C| > p*(*λ*) *have garbling sizes |C*b*|≤|C|·* log *|C|.*

3.2 Hardness Assumptions in Paillier Groups We consider two types of groups, Paillier groups (of composite orders) and prime-order groups in this work. We first provide a quick review of these groups and the standard DDH assumption in them. We next introduce two variants of the standard DDH assumption in those groups. Definition 3(Paillier Groups). *Paillier groups are defined by the following instance gener-* *ation algorithm* Gen*.* – Gen(1 *λ* *,*1
*ζ* ) *uniformly samples two λ-bit primes p,q such that p* = 2*p* *′* + 1*, q* = 2*q* *′* + 1 *where* *p* *′* *,q* *′* *are also primes. It outputs* (*N* = *pq,ζ*) *as the group description of G* = Z *∗* *Nζ*+1 *.*

Lemma 1(Facts about Paillier Groups [Pai99,DJ01]). *Let G* = Z *∗* *Nζ*+1 *be a Paillier* *group sampled by* Gen(1 *λ* *,*1 *ζ* ) *for a polynomial ζ*(*λ*)*.*

– *G has a subgroup F* = *{*(1 + *N*) *x* : *x ∈ N* *ζ* *} where discrete log (i.e., finding x) can be* *efficiently solved.* – *G has a subgroup H that’s isomorphic to* Z *∗* *N* *, and G* = *F × H.* – *Consider a random element g ∈ G such that the Jacobi symbol of g mod N is 1. Then ⟨g⟩* *contains F except with negligible probability. We write g ←* Samp(*N,ζ*) *to mean sampling* *such elements g with Jacobi symbol 1.*

Definition 4(Prime-order Groups). *We consider prime-order groups defined by an instance* *generation algorithm* Gen *with the following syntax.*

– Gen(1 *λ* ) *outputs* (*G,p,g*) *where G is a group description of prime order p >* 2 *λ* *, and g is a* *generator of G.*

The following DDH assumption in Paillier groups is adapted from the formulation by [ADOS22], where the authors formulate a separate “small exponent” assumption stating it’s secure to sam- ple the secret exponents in DDH from a smaller, but still sufficiently large, range than the order of *g*. We directly state the small-exponent variant of DDH in Paillier groups here, as it’s required to obtain the HSS construction from [ADOS22] (Lemma6).

Definition 5(DDH Assumption). *We say DDH holds in Paillier groups if the following* *holds for every polynomial ζ*(*λ*)*:* () *a b ab* pp = (*N,ζ*) *←* Pai*.*Gen(1 *λ* *,*1 *ζ* )*,* pp*,g,g,g,g* *g ←* Pai*.*Samp(pp)*, a,b ←* [*N*]*.* ( *λ* ) *a b c* pp = (*N,ζ*) *←* Pai*.*Gen(1 *λ* *,*1 *ζ* )*,* *≈c*pp*,g,g,g,g* *ζ*+2 *.* *g ←* Pai*.*Samp(pp)*, a,b,c ←* [*N*]*.* *λ*

*We say DDH holds in prime-order groups if the following holds:* () *a b ab* pp = (*G,p,g*) *←* Pri*.*Gen(1 *λ* )*,* pp*,g,g,g,g* *a,b ←* Z*p.* () *λ*

*a b c* pp = (*G,p,g*) *←* Pri*.*Gen(1 *λ* )*,* *≈c*pp*,g,g,g,g.* *a,b,c ←* Z*p.* *λ*

Our first variant, power-DDH, was first introduced by [CNs07,AHI11] in prime-order groups, and formulated in Paillier groups (as an instance of the NIDLS framework) by [ARS24]. Roughly, the assumption states that a group element *g* raised to the powers of a random secret exponent *s,s²,s³,...* still “look random”. In this work we only need the weaker version that consider the first and second powers *s,s²*. Definition 6(Power-DDH Assumption [CNs07,AHI11,ARS24]). *We say the power-* *DDH assumption (P-DDH) holds in Paillier groups if the following holds for every polynomial* *ζ*(*λ*)*:* () pp = (*N,ζ*) *←* Pai*.*Gen(1 *λ* *,*1 ) *ζ* *,* *s s*2 pp*,g,g,g* *g ←* Pai*.*Samp(pp)*, s ←* [*N*]*.* ( *λ* ) *a b* pp = (*N,ζ*) *←* Pai*.*Gen(1 *λ* *,*1 *ζ* )*,* *≈c*pp*,g,g,g* *ζ*+2 *.* *g ←* Pai*.*Samp(pp)*, a,b ←* [*N*]*.* *λ* *We say P-DDH holds in prime-order groups if the following holds:* () pp = (*G,p,g*) *←* Pri*.*Gen(1 ) *λ* *,* *s s*2 pp*,g,g,g* *s ←* Z*p.* () *λ*

*a b* pp = (*G,p,g*) *←* Pri*.*Gen(1 *λ* )*,* *≈c*pp*,g,g,g.* *a,b ←* Z*p.* *λ* *Remark 1.* As remarked in [ILL24], in prime-order groups, power-DDH implies DDH: the re- *s s*2 duction given a power-DDH tuple (*g,g,g*) samples *a,b ←* Z*p*to re-randomize the tuple as *s·a s·b s*2*·ab* (*g,g,g,g*), which becomes a valid DDH tuple. If the reduction is given a random tuple (*g,g* *s* *,g* *r* ), the re-randomized is also random. We show below that power-DDH also implies DDH in Paillier groups, via a slightly different reduction suggested by Lawrence Roy.

Lemma 2. *Power-DDH implies DDH in in prime-order or Paillier groups.*

*Proof.* The implication in prime-order groups is sketched in the remark above. We focus on proving the implication in Paillier groups via a series of hybrid distributions that transitions from the left-hand side to the right-hand side in the DDH assumption (Definition5).

Hyb₀: This is the left-hand side in the DDH assumption: () *a b ab* pp = (*N,ζ*) *←* Pai*.*Gen(1 *λ* *,*1 *ζ* )*,* pp*,g,g,g,g.* *g ←* Pai*.*Samp(pp)*, a,b ←* [*N*]*.* *λ* Hyb₁: In this hybrid, we sample the random exponents *a,b* from a much larger range [*N* *ζ*+2]. () *a b ab* pp = (*N,ζ*) *←* Pai*.*Gen(1 *λ* *,*1 *ζ* )*,* pp*,g,g,g,g* *ζ*+2 *.* *g ←* Pai*.*Samp(pp)*, a,b ←* [*N*]*.* *λ* By P-DDH in Paillier groups (looking only at the first three terms), we have Hyb₀ *≈c*Hyb₁. Hyb₂: In this hybrid, we shift the random components *a,b* by a common random factor *r ←* [*N*]. () (*a*+*r*) (*b*+*r*) (*a*+*r*)(*b*+*r*) pp = (*N,ζ*) *←* Pai*.*Gen(1 *λ* *,*1 *ζ* )*,* pp*,g,g,g,g* *ζ*+2 *.* *g ←* Pai*.*Samp(pp)*, a,b ←* [*N*]*,r ←* [*N*]*.* *λ* Since *a,b* are sampled at random from a much larger range than *r*, they statistically “smudges” the term *r*. We have Hyb₁ *≈* Hyb₂.

Hyb₃: In this hybrid, we replace the square term *r²* in the exponent (*a* + *r*)(*b* + *r*). () (*a*+*r*) (*b*+*r*) *ab*+(*a*+*b*)*r*+*c* pp = (*N,ζ*) *←* Pai*.*Gen(1 *λ* *,*1 *ζ* )*,* pp*,g,g,g,g* *ζ*+2 *.* *g ←* Pai*.*Samp(pp)*, a,b,c ←* [*N*]*,r ←* [*N*]*.* *λ*

By P-DDH in Paillier groups, we have Hyb₂ *≈c*Hyb₃. Hyb₄: In this hybrid, we combine two steps: first artificially add a square term *r²* to the exponent *ab* + (*a* + *b*)*r* + *c*, and then replace the terms (*a* + *r*)*,* (*b* + *r*) with *a,b*. () *a b ab*+*c* pp = (*N,ζ*) *←* Pai*.*Gen(1 *λ* *,*1 *ζ* )*,* pp*,g,g,g,g* *ζ*+2 *.* *g ←* Pai*.*Samp(pp)*, a,b,c ←* [*N*]*.* *λ*

The first step is statistically indistinguishable because *c* is sampled at random from a much larger range than *r²*, hence smudges the term *r²*. The second step is also statistically indis- tinguishable because *a,b* are sampled from much larger ranges than *r*, hence smudges the term *r*. We have Hyb₃ *≈* Hyb₄. Hyb₅: In this hybrid, we sample the random exponents *a,b* from a much smaller range [*N*]. () *a b ab*+*c* pp = (*N,ζ*) *←* Pai*.*Gen(1 *λ* *,*1 *ζ* )*,* pp*,g,g,g,g* *ζ*+2 *.* *g ←* Pai*.*Samp(pp)*, a,b ←* [*N*]*,c ←* [*N*]*.* *λ*

By P-DDH in Paillier groups, we have Hyb₄ *≈c*Hyb₅. *hyb₆*: In this hybrid, we remove the term *ab* from the exponent *ab* + *c*. () *a b c* pp = (*N,ζ*) *←* Pai*.*Gen(1 *λ* *,*1 *ζ* )*,* pp*,g,g,g,g* *ζ*+2 *.* *g ←* Pai*.*Samp(pp)*, a,b ←* [*N*]*,c ←* [*N*]*.* *λ*

Since *c* is sampled at random from a much larger range than *a,b* now, it statistically smudges the term *ab*. We have Hyb₅ *≈* Hyb₆. Hyb₇: This is the right-hand side in the DDH assumption: () *a b c* pp = (*N,ζ*) *←* Pai*.*Gen(1 *λ* *,*1 *ζ* )*,* pp*,g,g,g,g* *ζ*+2 *.* *g ←* Pai*.*Samp(pp)*, a,b,c ←* [*N*]*.* *λ*

By P-DDH, we have Hyb₇ *≈* Hyb₈.

The next circular variant was first introduced by [ILL24] both over Paillier groups and prime-order groups. It further assumes that the DDH sample using *s²* as the secret exponent can securely hide (bits of) the secret *s* itself, after proper re-randomization.

Definition 7(Circular-Power-DDH [ILL24]). *We say the circular-power-DDH assumption* *(CP-DDH) holds in Paillier groups if the following holds for every polynomial ζ*(*λ*)*:* ( 2 2 )

|s s a|sa s a|||λ ζ||
|---|---|---|---|---|---|
|||||i|λ|
|s d a|b c|λ ζ||||
|||i i|i|ζ+2|λ|

*i i is*[*i*]pp = (*N,ζ*) *←* Pai*.*Gen(1*,*1 )*,* pp*,g,g,g,g,g,g* (1 + *N*) (for *i ∈⌈*log *N ⌉*) *g ←* Pai*.*Samp(pp)*, s, {a}←* [*N*]*.* () *i i i*pp = (*N,ζ*) *←* Pai*.*Gen(1*,*1 )*,* pp*,g,g,g,g,g,g* *≈c.* (for *i ∈⌈*log *N ⌉*) *g ←* Pai*.*Samp(pp)*, s,d, {a,b,c}←* [*N*]*.*

*We say CP-DDH holds in prime-order groups if the following holds:* ( 2 2 )

|s s a|sa s a|+s[i]||||λ||
|---|---|---|---|---|---|---|---|
|||||i|p||λ|
|s d a|b c|i|i i|p|λ|λ||
||||||s|||

*i i i*pp = (*G,p,g*) *←* Pri*.*Gen(1 )*,* pp*,g,g,g,g,g,g* (for *i ∈⌈*log *p⌉*) *s, {a}←* Z*.* () pp*,g,g,g,g* *i* *,g* *i* *,g* *i* pp = (*G,p,g*) *←* Pri*.*Gen(1)*,* *≈c.* (for *i ∈⌈*log *p⌉*) *s,d, {a,b,c}←* Z*.*

2 *Remark 2.* We modify the formulation from [ILL24] to include the *g* term in the indistinguisha- bility, so that it implies both DDH and P-DDH and looks more natural. The proof (Theorem 4 in [ILL24]) that CP-DDH in prime-order groups holds in the generic group model (GGM) still goes through for our variant.

3.3 Lattice Hardness Assumptions In this work, we consider two variants to the standard RingLWE assumption over polynomial rings of the form *R* = Z[*X*]*/*(*X*
*n* + 1), where *n*(*λ*) is a power-of-2. Let *q*(*λ*) *>* 2 be a modu- lus, *D*err(*λ*)*, D*sk(*λ*) *⊆R* be error and secret distributions. The standard RingLWE assumption (w.r.t. *R,q, D*sk*, D*err) states that for every polynomial *m*(*λ*), the following computational indis- tinguishability holds: ()

|, e ←D|,|||
|---|---|---|---|
|sk|err m||m|
|m||c|q λ|
|q|λ|||

a*, s ·* a + e *s ←D* *≈* a*,* b *←R,* (over *Rq*) a *←R*

where *Rq*= *R/*(*qR*). The first variant considers the case where two vectors of RingLWE samples are computed using the same public vector a, correlated secrets *s*, *s²*, and fresh errors e₁*,*e₂. This is a weaker version of the power RingLWE assumption first introduced in [ARS24], which considers multiple powers of *s* instead of just 2.

Definition 8(Power RingLWE[ARS24]). *We say the power RingLWE (P-RLWE) assump-* *tion holds with respect to the ring R*(*λ*)*, a modulus q*(*λ*)*, error and secret distributions D*err(*λ*)*, D*sk(*λ*) *if the following holds for every polynomial m*(*λ*)*:* ()

|, e₁, e₂ ←D|,|||
|---|---|---|---|
|sk|err m||m|
|m||c|q λ|
|q|λ|||

a*, s ·* a + e₁*, s² ·* a + e₂ *s ←D* *≈* a*,* b*,* c *←R* (over *R*q) a *←R*

*Remark 3.* P-RLWE implies the standard RLWE, which just requires indistinguishability of the first 2 terms in the above.

Our next circular variant further assumes that the RingLWE sample using *s²* as the secret can securely hide the secret *s* itself.

Definition 9(Circular Power RingLWE). *We say the circular power RingLWE (CP-RLWE)* *assumption holds with respect to the ring R*(*λ*)*, two modulus p*(*λ*)*,q*(*λ*) *such that q* = *p · ∆, error* *and secret distributions D*err(*λ*)*, D*sk(*λ*) *if the following holds for every polynomial m*(*λ*)*:* ()

|, e₁, e₂ ←D|,|||
|---|---|---|---|
|sk|err m||m|
|m||c|q λ|
|q|λ|||

a*, s ·* a + e₁*, s² ·* a + e₂ + *s · ∆ s ←D* *≈* a*,* b*,* c *←R* (over *R*q) a *←R*

## 4 aHMAC and HSS as Evaluation Procedures

In this work, we make use of two tools from prior works, an algebraic homomorphic MAC scheme (aHMAC) [ILL24], and a homomorphic secret sharing scheme (HSS) with extended evaluations [CMPR23,ARS24]. At a highlevel, both schemes are run between a pair of parties, which we call the garbler and the evaluator, who jointly hold (not neccessarily additive) secret shares with respect to some input values x.

– An aHMAC scheme allows the parties to locally evaluate arithmetic circuits (over bounded integers) on their input shares, if the evaluator additionally knows the inputs x in the clear. – An HSS scheme allows the parties to locally evaluate a weaker program class (including NC1 Boolean circuits), but without requiring the evaluator to learn x.

When garbling and evaluating a circuit, our techniques require interleaving aHMAC and HSS evaluations on secret shares of intermediate wire values. In particular, they require conversions between the two schemes’ share formats. For this reason, (except in the leveled variants of our grabling constructions,) we need to setup the two schemes using correlated secret randomness, and hence cannot directly invoke their standard security definitions. In the following lemmas we focus only on their correctness prop- erties, and expose the underlying construction detail of their “setup” algorithm (for generating public data pd). We stress that our garbling schemes will use the evaluation procedures of HSS and aHMAC as subroutines, and we will directly prove the security of our garbling schemes without relying on the security aHMAC and HSS in a black-box way.

4.1 aHMAC and HSS under Paillier Groups The following lemmas summarize the aHMAC constructions under Paillier groups from [ILL24], including both the non-leveled and leveled variants. We refer readers to [ILL24] for more details. We note that [ILL24] presents the constructions in the language of NIDLS framework [ADOS22], which covers Paillier groups, class groups, and a variant of Joye-Libert encryption as known instantiations. In this work, we chose to focus on Paillier groups for clarity. Our results can be generalized to fit NIDLS framework, and enjoy other instantiations covered by it. Lemma 3(aHMAC Gate Evaluation under Paillier Groups). *Let B <* 2
poly(*λ*) *be a* *bound on input values, and ζ* = *⌈*log *B/*(2*λ*)*⌉* + 1*. There exist two pairs of efficient algorithms:* *x y x y* – MultKey(pd*,w₀,w₀*) *takes as inputs public data* pd *and two integer values w₀,w₀ ∈* Z*. It* *outputs an integer w₀* *z* *∈* Z*.* *x y x y* – MultTag(pd*,w₁,w₁,x,y*) *takes as input public data* pd *and four integer values w₁,w₁,x,y ∈*

Z*. It outputs an integer w₁*
*z* *∈* Z*.* – AddKey*,*AddTag *have the same syntax as* MultKey*,*MultTag*, respectively.*

||||λ|ζ|′|
|---|---|---|---|---|---|
|||||0|0 1|
|z|z ′|z||||
||||0 0|||
|||z||||
||||1 1|||
|z|z|z||||
||||0|0||
|||z||||
||||1|1||

*For every λ ∈* N*,* pp = (*N,ζ*) *in the support of* Pai*.*Gen(1*,*1)*, secret exponents, s,s ∈* [*N*]*,* *inputs x,y ∈* [*B*] *such that xy < B, and additive shares (over* Z*) ⟨sx⟩, ⟨sx⟩* 1 *, ⟨sy⟩, ⟨sy⟩, the* *following holds:* " # *w₁* = *w₀* + *s · xy w₀* = MultKey(pd*, ⟨sx⟩, ⟨sy⟩*) Pr *>* 1 *−* negl(*λ*)*,* (over Z) *w₁* = MultTag(pd*, ⟨sx⟩, ⟨sy⟩,x,y*) " # *w₁* = *w₀* + *s ·* (*x* + *y*) *w₀* = AddKey(pd*, ⟨sx⟩, ⟨sy⟩*) Pr *> −* negl(*λ*)*,* (over Z) *w₁* = AddTag(pd*, ⟨sx⟩, ⟨sy⟩,x,y*)

*over the randomness of* pd*, which is computed as follows:*

||⌈log N ⌉||λ|
|---|---|---|---|
|r rs|r[i]s|Bits(s)[i]||

*g ←* Pai*.*Samp(pp)*,* r *←* [*N*]*,* seed *←{*0*,*1*}* 2 *′* pd := (pp*,*seed*,g,g, {g ·* (1 + *N*)*}*)*.*

*We write* aHMAC Pai *.*pd(pp*,s,s* *′* ) *to denote public data* pd *computed as above with freshly sampled* *g,* r*, and* seed*.*

In the above, if we choose the secret exponents *s* *′* = *s*, then we can compose MultKey, MultTag, MultKey, MultTag to obtain algorithms EvalKey*,*EvalTag that respectively evaluates an arithmetic *C* over additive shares. Note that each invocation of those algorithms imposes a bound *B* on the underlying wire values. We therefore only consider bounded integer evaluations.

Definition 10(Admissible Input w.r.t. *B*). *Let C be an arithmetic circuit (with ℓxinputs)* *over* Z*. We say an input* x *∈* Z *ℓ* *xis admissible w.r.t. some positive integer B if all intermediate* *wire values of C*(x) *are bounded by B.*

Lemma 4(aHMAC Circuit Evaluation under Paillier Groups). *Under the same setting* *as Lemma3, and assume the existence of a PRG, there exists a pair of efficient algorithms:*

||x|||ℓ ℓ||
|---|---|---|---|---|---|
|x ℓ|x z|z ℓ|ℓ||x ℓ|

– EvalKey(pd*,C,* w₀) *takes public data* pd*, an arithmetic circuit C* : Z*x→* Z*z, and a vector* w₀ *∈* Z*x. It outputs a vector* w₀ *∈* Z*z.* – EvalTag(pd*,C,* w₁*,*x) *takes public data* pd*, an arithmetic circuit C, two vectors* w₀*,* x *∈* Z*x.* *It outputs a vector* w₁ *∈* Z*z.*

*For every polynomial p*(*λ*)*, there exists a negligible function* negl(*λ*) *such that for every λ ∈* N*,* pp = (*N,ζ*) *in the support of* Pai*.*Gen(1 *λ* *,*1 *ζ* )*, secret exponents, s ∈* [*N*]*, arithmetic circuit C with* *|C|≤ p*(*λ*)*, admissible inputs* x *w.r.t B, and additive shares (over* Z*) ⟨s*x*⟩* 0 *, ⟨s*x*⟩* 1 *, the following* *holds:* " # w₁ *z* = w₀ *z* + *s · C*(x) w₀ *z* = EvalKey(pd*,C, ⟨s*x*⟩* 0 ) Pr *z* *>* 1 *−* negl(*λ*)*,* (over Z) w₁ = EvalTag(pd*,C, ⟨s*x*⟩* 1 *,*x)

*over the randomness of* pd*, which is computed as* pd *←* aHMAC Pai *.*pd(pp*,s,s*)*.*

Alternatively, by using a vector of different secret exponents s *∈* Z *d*+1 we can compose MultKey, MultTag, MultKey, MultTag to obtain *leveled* variants of algorithms EvalKey *d* *,*EvalTag *d*

that respectively evaluates an arithmetic *C* of depth bounded by *d*. 11

Lemma 5(aHMAC Leveled Circuit Evaluation under Paillier Groups). *Under the* *same setting as Lemma3, assuming the existence of a PRG, for every polynomial depth bound* *d*(*λ*)*, there exists a pair of efficient deterministic algorithms:*

– EvalKey *d* (pd*,C,* w₀ *x* ) *takes public data* pd*, an arithmetic circuit C* : Z *ℓ* *x→* Z*ℓzof depth at* *most d, and a vector* w₀ *x* *∈* Z *ℓ*

*x. It outputs a vector* w₀*z∈* Z*ℓz.*
11 In the leveled variant, shares of two intermediate wires to a gate can have different secret “levels”. We can artificially increase the lower wire by multiplying with a constant wire of value 1. In this work, we assume the inputs to a computation contains a constant wire 1 (with secret level 0). Multiplying 1 with itself then provides constant wires with any secret level as needed. This assumption does not affect the asymptotic size of our garbling schemes.

– EvalTag *d* (pd*,C,* w₁ *x* *,*x) *takes public data* pd*, an arithmetic circuit C of depth at most d, two* *vectors* w₀ *x* *,* x *∈* Z *ℓ*

*x. It outputs a vector* w₁*z∈* Z*ℓz.*
*For every polynomial p*(*λ*)*, there exists a negligible function* negl(*λ*) *such that for every λ ∈* N*,* pp = (*N,ζ*) *in the support of* Pai*.*Gen(1 *λ* *,*1 *ζ* )*, secret exponents,* s *∈* [*N*] *d*+1 *, arithmetic circuit C* *with |C|≤ p*(*λ*) *and* Depth(*C*) *< d*(*λ*)*, admissible inputs* x *w.r.t B, and additive shares (over*

Z*) ⟨*s[0] *·* x*⟩*

|, ⟨s[0] · x⟩|, the following holds:|||||
|---|---|---|---|---|---|
|0|1|||||
|z|z||z|d||
||||0 z|d|0|
||||||1|
|||(j)||||
||||[d]|||
|||(j)||||

" # w₁ = w₀ + s[*d*] *· C*(x) w = EvalKey (pd*,C, ⟨*s[0] *·* x*⟩*) Pr *>* 1 *−* negl(*λ*)*,* (over Z) w₁ = EvalTag (pd*,C, ⟨*s[0] *·* x*⟩,*x)

*over the randomness of* pd = *{*pd*}, computed as*

pd *←* aHMAC Pai *.*pd(pp*,*s[*j*]*,*s[*j* + 1])*.*

The following lemma summarizes the HSS construction under Paillier groups from [ADOS22]. Again, the results in [ADOS22] are presented in the language of NIDLS framework, which covers Paillier groups as a particular instantiation.

Lemma 6(HSS Extended Evaluation under DCR Groups [ADOS22]). *Under the same* *setting as Lemma3, and assume the existence of a PRG, there exists a pair of efficient algo-* *rithms,* ExtEval₀*,* ExtEval₁*, where*

|(pd ,C, w|): takes public data pd, v||(with respect to some vector y ∈{0, 1}||||), an|
|---|---|---|---|---|---|---|---|
|b y|bx bx|ℓ|y ℓ||ℓ|ℓ||
|||||bx bx||||
|bz|bz ℓ ℓ|ℓ ℓ||||λ|ζ|
||||||0|1 0|1|

– ExtEval*y* *NC1 Boolean circuit C* : *{*0*,*1*}y→{*0*,*1*}x, and two vectors* w*,* v *∈* Z*x. It outputs a pair* *of integers w,v ∈* Z*.*

*For every logarithmic function d*(*λ*) *≤ O*(log*λ*)*, and every polynomial p*(*λ*)*, there exists a negli-* *gible function* negl(*λ*) *such that for every λ ∈* N*,* pp = (*N,ζ*) *in the support of* Pai*.*Gen(1*,*1)*,* *Boolean circuit C* : *{*0*,*1*}y→{*0*,*1*}xwith |C| < p*(*λ*) *and* Depth(*C*) *< d*(*λ*)*, secret exponents* *s ∈* [*N*]*, inputs* x *∈* [*B*]*xand* y *∈{*0*,*1*}y, and additive shares (over* Z*) ⟨s*x*⟩, ⟨s*x*⟩, ⟨*x*⟩, ⟨*x*⟩,* *the following holds:*  *z z*  *w₁* = *w₀* + *sz* *z z* *z zwb,vb*= ExtEval*b*(pdy*,C, ⟨s*x*⟩b, ⟨*x*⟩b*)  Pr *v₁* = *v₀* + *z*  *>* 1 *−* negl(*λ*)*,* *z* := InnerPord(x*,C*(y)) (over Z)*.* (over Z)

*over the randomness of* pdy*, which is computed as follows.*

*g ←* Pai*.*Samp(pp)*,* r*,* r *′* *←* [*N*] *ℓ* *y* *,* seed *←{*0*,*1*}* *λ* !

||r[i]|r[i]s|y[i]|
|---|---|---|---|
|(i)||||
|y|r [i]s|r [i]|y[i]|
|||(i)||
|y||y||
||||y|

*g, g ·* (1 + *N*)*,* pd :=*′ ′∀i ∈* [*ℓy*]*,* *g, g ·* (1 + *N*)

## pd := (pp,seed, {pd}).

*We write* HSS Pai *.*pd(pp*,s,* y) *to denote public data* pd *computed as above with freshly sampled* *g,* r*,* r *′* *, and* seed*.*

4.2 aHMAC and HSS under Prime-Order Groups The following lemmas summarize the aHMAC constructions under prime-order groups from [ILL24], including both the non-leveled and leveled variants. The main difference between these construc- tions and those under Paillier groups is that these only achieve
p *δ* = 1*/*poly(*λ*) correctness, and have computation costs scaling with 1*/δ*. We refer readers to [ILL24], for more details.

Lemma 7(aHMAC Gate Evaluation under Prime-Order Groups). *Let B <* poly(*λ*) *be* *a bound on input values, δ* = 1*/*poly(*λ*) *be an error bound, and* Pri*.*Gen *be an instance generation* *algorithm for prime-order groups. There exists two pairs of efficient deterministic algorithms:* MultKey*,*MultTag*,*AddKey*,*AddTag *with analogous syntax to Lemma3.* *For every λ ∈* N*,* pp = (*G,p,g*) *in the support of* Pri*.*Gen(1 *λ* )*, secret exponents,* s*,* s *′* *∈* *{*0*,*1*}* *⌈*log *p⌉* *, inputs x,y ∈* [*B*] *such that xy < B, and additive shares (over* Z*) ⟨*s*x⟩* 0 *, ⟨*s*x⟩* 1 *, ⟨*s*y⟩* 0 *, ⟨*s*y⟩* 1 *,* *the following holds:* " # *z z ′* *· xy* *z*

|= w₀ w₁|+ s|= MultKey(pd, ⟨sx⟩ w₀||, ⟨sy⟩||)||
|---|---|---|---|---|---|---|---|
|||||0||0||
|||z||||||
|||||1||1||
|z|z||z|||||
||||||0||0|
||||z|||||
||||||1||1|

0 0 Pr *>* 1 *− δ*(*λ*) *−* negl(*λ*)*,* (over Z) *w₁* = MultTag(pd*, ⟨*s*x⟩, ⟨*s*y⟩,x,y*) " # w₁ = w₀ + s *·* (*x* + *y*) *w₀* = AddKey(pd*, ⟨*s*x⟩, ⟨*s*y⟩*) Pr *>* 1 *− δ*(*λ*) *−* negl(*λ*)*,* (over Z) *w₁* = AddTag(pd*, ⟨*s*x⟩, ⟨*s*y⟩,x,y*)

*over the randomness of* pd*, which is computed as follows:*

|⌈plog p⌉||λ|
|---|---|---|
|′|r rs|rs +s|

r *←* Z*,* seed *←{*0*,*1*}, s* := BitComp(s)*,* 2 *′* pd := (pp*,*seed*,g,g,g*)*.*

*We write* aHMAC Pri *.*pd(pp*,* s*,* s) *to denote public data* pd *computed as above with freshly sampled* r*, and* seed*.*

*Remark 4.* The lemma also holds when the secret exponent s *′* has a different dimention *ℓ ≥* *⌈*log *p⌉* than s. In this case, the public data are computed with r *←* Z *ℓp* to match the dimension of s *′*. We need to support this edge case when using aHMAC together with the HSS scheme based on BHHO encryption (Lemma11), whose secret exponents has a dimension of *⌈*3 log *p⌉*.

Lemma 8(aHMAC Circuit Evaluation under Prime-Order Groups). *Under the same* *setting as Lemma7, assuming the existence of a PRG, there exists a pair of efficient deterministic* *algorithms:* EvalKey*,*EvalTag *with analogous syntax to Lemma4.* *For every polynomial p*(*λ*)*, there exists a negligible function* negl(*λ*) *such that for every λ ∈* N*,* pp = (*G,p,g*) *in the support of* Pri*.*Gen(1 *λ* )*, secret exponents,* s *∈{*0*,*1*}* *⌈*3 log *p⌉* *, arithmetic circuit* *C with |C|≤ p*(*λ*)*, admissible inputs* x *w.r.t B, and additive shares (over* Z*) ⟨*s *⊗* x*⟩* 0 *, ⟨*s *⊗* x*⟩* 1 *,* *the following holds:* " # W₁ *z* = W₀ *z* + s *⊗ C*(x) W₀ *z* = EvalKey(pd*,C, ⟨*s *⊗* x*⟩* 0 ) Pr *z* *>* 1 *− δ*(*λ*) *−* negl(*λ*)*,* (over Z) W₁ = EvalTag(pd*,C, ⟨*s *⊗* x*⟩* 1 *,*x)

*over the randomness of* pd*, which is computed as* pd *←* aHMAC Pri *.*pd(pp*,* s*,*s)*.*

Lemma 9(aHMAC Leveled Circuit Evaluation under Prime-Order Groups). *Under* *the same setting as Lemma7, assuming the existence of a PRG, for every polynomial depth bound*

*d*(*λ*)*, there exists a pair of efficient deterministic algorithms:* EvalKey *d* *,*EvalTag *d* *with analogous* *syntax to Lemma5.* *For every polynomial p*(*λ*)*, there exists a negligible function* negl(*λ*) *such that for every λ ∈* N*,* pp = (*G,p,g*) *in the support of* Pri*.*Gen(1 *λ* )*, secret exponents* S *∈{*0*,*1*}* (*d*+1)*×⌈*3 log *p⌉* *, arithmetic* *circuit C with |C|≤ p*(*λ*) *and* Depth(*C*) *< d*(*λ*)*, admissible inputs* x *w.r.t B, and additive shares* *(over* Z*) ⟨*S[0] *⊗* x*⟩*

|, ⟨S[0] ⊗ x⟩|, the following holds:||||
|---|---|---|---|---|
|0|1||||
|z|z|z|d||
|||0 z|d|0|
|||||1|

" # W₁ = W₀ + S[*d*] *⊗ C*(x) W = EvalKey (pd*,C, ⟨*S[0] *⊗* x*⟩*) Pr (over Z) W₁ = EvalTag (pd*,C, ⟨*S[0] *⊗* x*⟩,*x)

*>* 1 *− δ*(*λ*) *−* negl(*λ*)*,*

*over the randomness of* pd = *{*pd

(*j*) *}*[*d*]*, computed as*
pd

(*j*) *←* aHMAC
Pri *.*pd(pp*,*S[*j*]*,*S[*j* + 1])*.*

The following two lemmas summarize the HSS constructions under prime-order groups from [BGI16]. The first variant was proven secure assuming circular security of ElGamal en- cryption. We modify it slightly:

ElGamal CT of y under s : *g* r *,g* r*·s*+y

r*·s* r*·s*2+y modified : *g,g.*

The modified ciphertext can be decrypted in the same way using *s*, but we can now use CP-DDH to replace circular security assumption of ElGamal when proving security of the joint usage of aHMAC and this variant is secure.

Lemma 10(HSS Extended Evaluation Based on ElGamal [BGI16]). *Under the same* *setting as Lemma7, assuming the existence of a PRG, there exists a pair of efficient deterministic* *algorithms,* ExtEval₀*,* ExtEval₁*, with analogous syntax to Lemma6.* *For every logarithmic function d*(*λ*) *≤ O*(log*λ*)*, polynomial p*(*λ*)*, there exists a negligible* *function* negl(*λ*) *such that for every λ ∈* N*,* pp = (*G,p,g*) *in the support of* Pri*.*Gen(1 *λ* )*, circuit* *C* : *{*0*,*1*}* *ℓ* *y→{*0*,*1*}ℓxwith |C| < p*(*λ*)*,* Depth(*C*) *< d*(*λ*)*, secret exponents* s *∈⌈*log *p⌉, inputs* x *∈* [*B*] *ℓ* *x ℓy*

|, y ∈{0, 1}|, and additive shares (over Z) ⟨x ⊗ s⟩|||, ⟨x ⊗ s⟩|, ⟨x⟩, ⟨x⟩|, the following|
|---|---|---|---|---|---|---|
|||||0|1 0|1|
|z|z||||||
|z|z|b z b z|b y|b b|||

0 1 0 1 *holds:*   w₁ = w₀ + s *· z*  *w,v* = ExtEval (pd*,C, ⟨*x *⊗* s*⟩, ⟨*x*⟩*) Pr *v₁* = *v₀* + *z*  *>* 1 *− δ*(*λ*) *−* negl(*λ*)*,* *z* := InnerPord(x*,C*(y)) (over Z)*.* (over Z)

*over the randomness of* pdy*, which is computed as follows.*

|ℓ|ℓ ×⌈log p⌉||λ|
|---|---|---|---|
|p|p r·s r·s|+y R·s|R·s +y⊗s|
||||y|

*y y* r *←* Z*,* R *←* Z*,* seed *←{*0*,*1*}, s* := BitComp(s) 2 2 pdy:= (pp*,*seed*,g, g, g, g*)*.*

*We write* HSS EG *.*pd(pp*,* s*,*y) *to denote public data* pd *computed as above with freshly sampled* r*,* R*, and* seed*.*

The second variant was proven secure assuming only DDH, without assuming circular se- curity, by using BHHO [BHHO08] encryption instead of ElGamal. We use this variant in our leveled garbling scheme, together with leveled aHMAC, so that we can use P-DDH instead of CP-DDH when proving security of garbling scheme. Lemma 11(HSS Extended Evaluation under BHHO [BGI16]). *Under the same setting* *as Lemma7, assuming the existence of a PRG, there exists a pair of efficient deterministic* *algorithms,* ExtEval₀*,* ExtEval₁*, with analogous syntax to Lemma6.* *For every logarithmic function d*(*λ*) *≤ O*(log*λ*)*, polynomial p*(*λ*)*, there exists a negligi-* *ble function* negl(*λ*) *such that for every λ ∈* N*,* pp = (*G,p,g*) *in the support of* Pri*.*Gen(1 *λ* )*,* *Boolean circuit C* *ℓ* *y ℓx*

||: {0, 1}|→ {0, 1}|with |C| < p(λ), Depth(C) < d(λ), secret exponents|||
|---|---|---|---|---|---|
|⌈3 log p⌉||ℓ|ℓ|||
||||||1|
|1||||||
|z|z|||||
|z|z|b z b z|b y|b b||

s *∈{*0*,*1*}* *⌈*3 log *p⌉* *, inputs* x *∈* [*B*] *ℓ* *x,* y *∈{*0*,*1*}ℓy, and additive shares (over* Z*) ⟨*x *⊗* s*⟩* 0 *, ⟨*x *⊗* s*⟩,* *⟨*x*⟩* 0 *, ⟨*x*⟩, the following holds:*   w₁ = w₀ + s *· z*  *w,v* = ExtEval (pd*,C, ⟨*x *⊗* s*⟩, ⟨*x*⟩*) Pr *v₁* = *v₀* + *z*  *>* 1 *− δ*(*λ*) *−* negl(*λ*)*,* *z* := InnerPord(x*,C*(y)) (over Z)*.* (over Z)

*over the randomness of* pdy*, which is computed as follows.* *ℓ*

||⌈p3 log p⌉|ℓ|ℓ ×⌈3 log p⌉|
|---|---|---|---|
|y BHHO||p c⊗r c⊗R|p InnerPord(c,s)·r+y|

*y ℓy×⌈*3 log *p⌉ λ* c *←* Z*,* r *←* Z*,* R *←* Z*,* seed *←{*0*,*1*},*

pd := (pp*,*seed*,g, g, g, g* InnerPord(c*,*s)*·*R+y*⊗*s )*.*

*We write* HSS*.*pd(pp*,* s*,*y) *to denote public data* pdy*computed as above with freshly sampled* c*,* r*,* R*, and* seed*.*

4.3 aHMAC and HSS under Lattices The following lemmas summarize analgous aHMAC constructions to Lemma3,4, and5under lattices. We present details of these constructions (hence prove the lemmas) in Section4.4. Lemma 12(aHMAC Gate Evaluation under Lattices). *Let B <* 2
poly(*λ*) *be a bound* *on input values, R be the polynomial ring R* = Z[*X*]*/*(*X* *n* + 1) *where n*(*λ*) *is a power-of-two,* *p ≥ B ·λ* *ω*(1) *, q* = *p·∆ be two moduli, where ∆* = *B ·p·λ* *ω*(1) *is a scaling factor, and D*sk(*λ*)*, D*err(*λ*) *be error and secret distributions with coefficients bounded by* poly(*λ*)*. There exists two pairs of* *efficient deterministic algorithms,* MultKey*,*MultTag*,*AddKey*,*AddTag*, with analogous syntax to* *Lemma3.* *For every λ ∈* N*, secret elements s,s* *′* *∈D*sk*, inputs x,y ∈* [*B*] *such that xy < B, and additive* *shares (over R) ⟨sx⟩* 0 *, ⟨sx⟩* 1 *, ⟨sy⟩* 0 *, ⟨sy⟩* 1 *, the following holds:* " # *w₁* *z* = *w₀* *z* + *s* *′* *· xy w₀* *z* = MultKey(pd*, ⟨sx⟩* 0 *, ⟨sy⟩* 0 ) Pr *z* *>* 1 *−* negl(*λ*)*,* (over *R*) *w₁* = MultTag(pd*, ⟨sx⟩* 1 *, ⟨sy⟩* 1 *,x,y*) " # *w₁* *z* = *w₀* *z* + *s ·* (*x* + *y*) *w₀* *z* = AddKey(pd*, ⟨sx⟩* 0 *, ⟨sy⟩* 0 ) Pr *z* *>* 1 *−* negl(*λ*)*,* (over *R*) *w₁* = AddTag(pd*, ⟨sx⟩* 1 *, ⟨sy⟩* 1 *,x,y*)

*over the randomness of* pd*, which is computed (over Rq) as follows:*

## pp := (R,p,q, Derr, Dsk)

*a ←Rq, e₁,e₂ ←D*err*,* seed *←{,}* *λ* *,*

pd := (pp*,*seed*,a, s · a* + *e₁, s² · a* + *e₂ − s* *′* *· ∆*)*.*

*We write* aHMAC Lat *.*pd(pp*,s,s* *′* ) *to denote public data* pd *computed as above with freshly sampled* *a, e₁,e₂, and* seed*.*

Lemma 13(aHMAC Circuit Evaluation under Lattices). *Under the same setting as* *Lemma12, assuming the existence of a PRG, there exists a pair of efficient deterministic algo-* *rithms:* EvalKey*,*EvalTag *with analogous syntax as Lemma4.* *For every polynomial p*(*λ*)*, there exists a negligible function* negl(*λ*) *such that for every λ ∈* N*,* *secret elements s ∈D*sk*, arithmetic circuit C with |C|≤ p*(*λ*)*, admissible inputs* x *w.r.t B, and* *additive shares (over R) ⟨s*x*⟩* 0 *, ⟨s*x*⟩* 1 *, the following holds:* " # w₁ *z* = w₀ *z* + *s · C*(x) w₀ *z* = EvalKey(pd*,C, ⟨s*x*⟩* 0 ) Pr *z* *>* 1 *−* negl(*λ*)*,* (over *R*) w₁ = EvalTag(pd*,C, ⟨s*x*⟩* 1 *,*x)

*over the randomness of* pd*, which is computed as* pd *←* aHMAC Lat *.*pd(pp*,s,s*)*.*

Lemma 14(aHMAC Leveled Circuit Evaluation under Lattices). *Under the same set-* *ting as Lemma12, assuming the existence of a PRG, for every polynomial depth bound d*(*λ*)*,* *there exists a pair of efficient deterministic algorithms:* EvalKey *d* *,*EvalTag *d* *with analogous syntax* *as Lemma5.* *For every polynomial p*(*λ*)*, there exists a negligible function* negl(*λ*) *such that for every λ ∈* N*,* *secret elements* s *∈D* sk *d*+1 *, arithmetic circuit C with |C|≤ p*(*λ*) *and* Depth(*C*) *< d*(*λ*)*, admissible* *inputs* x *w.r.t B, and additive shares (over R) ⟨*s[0] *·* x*⟩* 0 *, ⟨*s[0] *·* x*⟩* 1 *, the following holds:* " # *z z* w *z* = EvalKey (pd *d* w₁ = w₀ + s[*d*] *· C*(x)0*,C, ⟨*s[0] *·* x*⟩*) 0 Pr *z d* *>* 1 *−* negl(*λ*)*,* (over *R*) w₁ = EvalTag (pd*,C, ⟨*s[0] *·* x*⟩* 1 *,*x)

*over the randomness of* pd = *{*pd

(*j*) *}*[*d*]*, computed as*
pd

(*j*) *←* aHMAC
Lat *.*pd(pp*,*s[*j*]*,*s[*j* + 1])*.*

The following lemma summarizes the HSS construction under lattices from [BKS19]. We refer readers to [BKS19] for more details. Lemma 15(HSS Extended Evaluation under Lattices [BKS19]). *Under the same set-* *ting as Lemma12, assuming the existence of a PRG, there exists a pair of efficient deterministic* *algorithms,* ExtEval₀*,* ExtEval₁*, with analogous syntax to Lemma6.* *For every logarithmic function d*(*λ*)*, every polynomial p*(*λ*)*, there exists a negligible function* negl(*λ*) *such that for every λ ∈* N*, Boolean circuit C* : *{*0*,*1*}* *ℓ* *y→ {*0*,*1*}ℓxwith |C| < p*(*λ*)*,* Depth(*C*) *< d*(*λ*)*, secret elements s ∈ D*sk*, inputs* x *∈* [*B*] *ℓ* *xand* y *∈ {*0*,*1*}ℓy, and additive* *shares (over R) ⟨s*x*⟩* 0 *, ⟨s*x*⟩* 1 *, ⟨*x*⟩* 0 *, ⟨*x*⟩* 1 *, the following holds:*  *z z*  *w₁* = *w₀* + *sz* *z z* *z zwb,vb*= ExtEval*b*(pdy*,C, ⟨s*x*⟩b, ⟨*x*⟩b*)  Pr *v₁* = *v₀* + *z*  *>* 1 *−* negl(*λ*)*,* *z* := InnerPord(x*,C*(y)) (over Z)*.* (over *R*)

*over the randomness of* pdy*, which is computed (over Rq) as follows.* *ℓ* *y ′ ′ ℓy*

|, r₁,r₂ ←D|, e, e₁, e₂, e₁, e₂ ←D|||||
|---|---|---|---|---|---|
|q|sk ′1|′2||err ′1 ′2|′1 ′2|

a *←Rq* sk err b := *s ·* a + e*,* c₁ := *r₁ ·* a + e₁ + y *· ∆,* c := *r₁ ·* b + e*,* c₂ := *r₂ ·* a + e₂*,* c := *r₂ ·* b + e + y *· ∆.* pdy:= (pp*,*seed*,*c₁*,* c*,*c₂*,* c)*.*

*We write* HSS Lat *.*pd(pp*,s,* y) *to denote public data* pdy*computed as above with freshly sampled* a*, r₁,r₂, the errors, and* seed*.*

4.4 aHMAC Constructions under Lattices We show a construction of MultKey, MultTag, AddKey and AddTag, which proves Lemma3. Construction 1(aHMAC Gate Evaluation under Lattices). The construction is with respect to the following public parameters pp = (*R,p,q, D*err*, D*sk): – a polynomial ring *R* = Z[*X*]*/*(*X*
*n* + 1) where *n* is a power-of-two; – two modulus *p > B · λ* *ω*(1), and *q* = *p · ∆*, where *∆ > B²λ* *ω*(1), for some input bound *B*. – error and secret distributions *D*err*, D*sk*⊆R* with coefficients bounded by poly(*λ*).

As described in Lemma3, the public data with respect to two secrets *s,s* *′* *∈D*skare sampled as follows *a ←Rq, e₁,e₂ ←D*err*,* seed *←{*0*,*1*}* *λ* *,*

pd := (pp*,*seed*,a, s* <u>·</u> *a* + <u>e₁</u>*, s²* <u>· a +</u> *e₂* <u>− s</u> *′* <u>·</u> *∆*)*.* | {z} | {z} *b c* *z x y* *w₀ ←* MultKey(pd*,w₀ ∈R,w₀ ∈R*) :Read seed from pd, and expand from it pseudo-random “shifting factors” *r* *x* *,r* *y* *,r* *z* *∈Rp*. *x y x y*

1.Shift the coefficients of *w₀*, *w₀* by the random factors *r,r ∈Rp*, and then reduce them mod *p*.
*x x x y y y* *w₀ ←* (*w₀* + *r* mod *p*)*, w₀ ←* (*w₀* + *r* mod *p*)*.*

2.Read *a* from pd, and compute the output *w₀*
*z* as follows.

*z x y z* *w₀ ←* (*⌊aw₀w₀/∆⌋* + *r*) mod *p.*

*z x y* *w₁ ←* MultTag(pd*,w₁ ∈R,w₁ ∈R,x ∈* Z*B,y ∈* Z*B*) :Read seed from pd, and expand from it pseudo-random “shifting factors” *r* *x* *,r* *y* *,r* *z* *∈Rp*. *x y x y*

1.Shift the coefficients of *w₁*, *w₁* by the random factors *r,r ∈Rp*, and then reduce them
*x y* mod *p*. As a result, we have *∥w₁∥∞, ∥w₁∥∞< p*.

*x x x y y y* *w₁ ←* (*w₁* + *r* mod *p*)*, w₁ ←* (*w₁* + *r* mod *p*)*.*

*Note that if the input satsify w₁* *x* = *sx* + *w₀* *x* *over R, where x ∈* [*B*]*, then it also holds,* *except with negligible probability, that* (*w₁* *x* + *r* *x* mod *p*) = *sx* + (*w₀* *x* + *r* *x* mod *p*) *over R,* *y* *as long as ∥sx∥∞≪ p. (See Lemma 2 in [BKS19].) The same holds for w₁.*

2.Read *a,b,c ∈Rq*from pd, and compute the following over *Rq*:
*x y y x* *d* = *−a · w₁ · w₁* + *b ·* (*x · w₁* + *y · w₁*) *− c · x · y.*

*x x y y* *Assuming w₁* = *sx*+*w₀, and w₁* = *sy*+*w₀, where x,y ∈* [*B*] *and xy < B, then the above* *computation equals*

|2|y|x|x y||
|---|---|---|---|---|
|||y|x|2|
|x y||y|x||
||1 ∥error∥|≤B·p·poly(λ)≪∆|1||

*d* = *− a ·* (*s xy* + *sxw₀* + *syw₀* + *w₀w₀*) *′* + (*sa* + *e₁*) *·* (2*sxy* + *xw₀* + *yw₀*) *−* (*s a* + *e₂ − s ∆*) *· xy* *′* =*s xy∆ − aw₀w₀* + *e* <u>(xw₁ +</u> *yw*<u>) + e₂xy</u> | {z} *∞*

3.Round the coefficients of *d* by *∆*, and shift resulting coefficients again by the random factor *r*
*z* *∈Rp*. *w₁* *z* *←* (*⌊d/∆⌋* + *r* *z* mod *p*)*.*

*We have shown that the error term from d is much smaller than ∆. Hence the rounding* *step removes it, except with negligible probability. (See Lemma 1 in [BKS19].)*

*z z ′ x y z* *w₁* = *⌊d/∆⌋* + *r* = *s xy* + *⌊*<u>aw₀w₀</u>*/∆*<u>⌋ + r</u> mod*p.* | {z} *w*0*z*

*Shifting by the random factor r* *z z ′ z*

|||ensures that w₁||= s xy + w₀|over R holds except with|
|---|---|---|---|---|---|
|||′|∞|||
|z|x y|z x|y|||
|z|x y x|z x z|x y|y y x y||
|||||0||
|||||w||

*negligible probability, as long as ∥s* *′* *xy∥ ≪ p.* *w₀ ←* AddKey(pd*,w₀,w₀*) :output *w₀* = *w₀* + *w₀* over *R*. *w₁ ←* AddTag(pd*,w₀,w₀,x,y*) :output *w₁* = *w₁* + *w₁* over *R*. *Note that assuming w₁* = *sx* + *w₀, and w₁* = *sy* + *w₀, then we have*

*w₁* = *s*(*x* + *y*) + *w* + <u>w₀</u>*.* | {z} 0 *z*

We have directly analyzed the correctness in the construction, and have proven Lemma3. By composing the algorithms MultKey, MultTag, AddKey and AddTag in an analogous way to the instantiations under Paillier groups (see Section4.1), we derive Lemma12and13as corollaries. Additionally, we note that our new lattice construction implies an aHMAC scheme (and a leveled variant) as originally defined in [ILL24]. We refer readers to [ILL24] for the definition of an aHMAC scheme.

Theorem 1(aHMAC Under Lattices). *Assuming CP-RLWE (Definition9) with respect to* *the public parameters* pp Lat *specified in Section5.3, there exists an aHMAC scheme achieving* negl*-correctness, with an* evk *of size ℓz·* poly(*λ*) *bits.* *Alternatively, assuming P-RLWE (Definition8, with respect to* pp Lat *), there exists a leveled* *aHMAC scheme achieving* negl*-correctness, with an* evk *of size* (*ℓz*+ *D*) *·* poly(*λ*) *bits.*

## 5 Succinct Boolean Garbling Schemes

For a more intuitive presentation, we first show a 2PC protocol BoolCircEval *C,*Pai (Figure1,2, under Paillier groups) for evaluating Boolean circuits between a garbler *PG*and an evaluator *PE*:

– In an Init phase, the garbler *PG*sends public data and input shares w.r.t. a Boolean vector x *∈{*0*,*1*}* *ℓ* *x*to the evaluator *P* *E*; – In an Eval phase, the two parties jointly evaluate gates of a Boolean circuit *C* : *{*0*,*1*}* *ℓ* *x→* *{*0*,*1*}* *ℓ* *z*in topological order; – In a Final phase, the garbler *PG*sends some decryption data to reveal the final output z *∈{*0*,*1*}* *ℓ* *z*to the evaluator *P*

*E*.
We note that all messages in this protocol are from the garbler *PG*to the evaluator *PE*. We further divide them into two parts, each satisfying a special property. 12

Without the special properties, a trivial protocol is letting the garbler *PG* directly send z := *C*(x) to the evaluator *PE*.

1. *Input shares w.r.t. to the vector* x*.* We ensure they are decomposable, i.e., each bit in this communication depends only on a single bit of x.
2. *Garbling materials.* These include the public data during Init, the decryption data during Final, and all communication during Eval. We ensure they are independent of the input x. Therefore, we can directly “compile” the above 2PC protocol into a garbling scheme as follows.
(*i*) (*i*) (*i*)
– The Garb algorithm outputs (1) key functions *{Kx}* such that labels *{Lx*:= *Kx*(x[*i*])*}* exactly equal to the input shares w.r.t. x, and (2) a garbling *C*b that contains the garbling materials. – The Eval algorithm performs all steps of *PE*in the 2PC protocol to recover the final output.

Protocol BoolCircEval *C,*Pai The protocol runs between a garbler *PG* and an evaluator *PE*, to evaluate a Boolean circuit *C* : *{*0*,*1*}* *ℓx* *→* *{*0*,*1*}* *ℓz*. It uses the following ingradients:

– aHMAC evaluation procedures EvalKey*,*EvalTag over bounded integers by *B* = 2, and public data generation procedure aHMAC Pai *.*pd under Paillier groups; (See Lemma4;) – HSS evaluation procedures ExtEval₀*,*ExtEval₁ and public data generation procedure HSS Pai *.*pd under paillier groups; (See Lemma6;) – a PRF : *{*0*,*1*}* *λ* *×{*0*,*1*}* *λ* *→{*0*,*1*}* in NC1. *a*

Inputs: *PG* holds a vector x *∈{*0*,*1*}* *ℓx*, while *PE* holds notinog. Outputs: *PG* outputs nothing, while *PE* outputs a vector z *∈{*0*,*1*}* *ℓz*.

– Init :

1. *PG* sends public data pd to the evaluator *PE*.
*ζ* := 2*,* pp = (*N,ζ*) *←* Pai*.*Gen(1 *λ* *,*1 *ζ* )*,* *s ←* [*N*]*,* sk *←{*0*,*1*}* *λ*

pd := aHMAC Pai *.*pd(pp*,s,s*)*,*HSS Pai *.*pd(pp*,s,* sk)*.* (3)

2. *PG* sends masked inputs x and additive shares *⟨s*x*⟩*1to *PE*.
*b*

x = x *⊕* PRF(sk*,*InWires(*C*))*,* *⟨s*x*⟩*1:= *s*x + *⟨s*x*⟩*0(over Z), where *⟨s*x*⟩*0*←* [*N · λ* *ω*(1)] *ℓx* *.* *a* With a bound on *|C|*, the PRF can be replaced with a PRG where each bit can be evaluated in NC1. *b* (x*, ⟨s*x*⟩*<u>1</u>) jointly is what we call input shares in the overview text.

Fig. 1. The Init phase of our 2PC protocol for Boolean circuits under Paillier groups.

The core of our construction is a sub-protocol BoolGateEval (Figure3, and Section5.1) for evaluating an arbitrary Boolean gate with up to *O*(log*λ*) input wires, and a single output, costing 1 bit per gate. The sub-protocol itself stays unchanged when we instantiate the underlying primitives aHMAC and HSS under Paillier groups, prime-order groups, or lattices. The only changes under different instantiations lie in the Init phases of the main protocol, during which *PG*computes public data pd differently. We describe the Init phase under Paillier groups in Figure1, under lattices in Section5.3, and under prime-order groups in Section5.4. In summary, we obtain the following theorem.

Protocol BoolCircEval *C,*Pai Continued

– Eval : *PG,PE* evaluate gates g *∈ C* in the topological order while maintaining the following invariant:

1. *PG,PE* jointly hold additive shares *⟨s*xg*⟩*, where xg are masked input wire values to the gate g
xg = xg *⊕* PRF(sk*,*InWires(g))*.* (4)

2. *PE* holds the masked wire values xg. To evaluate the gate g, *PG,PE* jointly call the sub-protocol BoolGateEval.
(*PG* : *⟨sz*g*⟩*0)*,* (*PE* : *⟨sz*g*⟩*1*, z*g) *←* BoolGateEval *C,*g (*PG* : pd*, ⟨s*xg*⟩*0)*,* (*PE* : pd*, ⟨s*xg*⟩*1*,* xg)

– Final : *PG* sends masks PRF(sk*,*OutWires(*C*)) mod 2 on all output wires to *PE*, who then recovers the output z by removing the masks mod2. *a*

*a* The final message from *PG* to *PE* can be avoided via an optimization: let BoolGateEval compute *z*, instead of masked *z*, for values on the output wires.

Fig. 2. The Eval*,*Final phases of our 2PC protocol for Boolean circuits.

Theorem 2(Garbling *O*(log*λ*)-ary Gates). *Let C* Arb = *{C* *λ* Arb *} be the class of circuits (of* *unbounded size) consisting of arbitrary gates with O*(log*λ*) *input wires and* 1 *output wires.* *Assuming CP-DDH in Paillier groups or CP-RLWE with respect to the public parameters* pp Lat *specified in Section5.3, there exists a garbling scheme for C* Arb *over* Z₂*, where the garbling* *size C*b *for a circuit C ∈C* *λ* Arb *is |C*b*|≤|C|* + poly(*λ*)*.* *Assuming CP-DDH in prime-order groups, there exists a garbling scheme for C* Arb *over* Z₂ *achieving the same garbling size as above, but* with 1*/*poly correctness and privacy errors*. The* *errors can be made negligible assuming a variant of CP-DDH (Definition11).*

The proof of Theorem2follows from Proposition1,3, and5, which are proven in Sec- tion5.1,5.3, and5.4respectively. We show amplification techniques in Section5.5for removing correctness and privacy errors from prime-order group instantiations. Applying Theorem2to garbling standard Boolean circuits with binary gates gives a scheme costing 1 bit per gate.

Corollary 1(Boolean Garbling). *Assuming any of the assumptions in Theorem2, there* *exists a garbling scheme for all Boolean circuits C (with binary gates) with garbling size |C*b*|≤* *|C|* + poly(*λ*)*.* *The scheme assuming CP-DDH in prime-order groups has* 1*/*poly correctness and privacy errors*, which can be made negligible assuming a variant of CP-DDH (Definition11).*

In the special case of layered circuits *C* Layer, we can re-write *C* Layer into another circuit *C* *′* in terms of general gates for log log*λ*-depth computations, with the guarantee that *|C* *′* *| <* *O*(*|C* Layer *|/* log log*λ*). (See Lemma 4.12 in [BGI16].) Since each general gate depends on at most log*λ* input values, we can apply Theorem2to garble *C* *′* which yields a scheme costing *O*(1*/*log log*λ*) bits per gate.

Corollary 2(Boolean Garbling for Layered Circuits). *Assuming any of the assumptions* *in Theorem2, there exists a garbling scheme for all layered Boolean circuits C* Layer *(with binary* *gates) with garbling size |C*b Layer *|≤ O*(*|C* Layer *|/* log log*λ*) + poly(*λ*)*.* *The scheme assuming CP-DDH in prime-order groups has /*poly correctness and privacy errors*, which can be made negligible assuming a variant of CP-DDH (Definition11).*

In Section5.2, we describe a leveled variant of the 2PC protocol LBoolCircEval (Figure4 ,5, under Paillier groups), based on a leveled variant of the core sub-protocol LBoolGateEval (Figure6). We describe the Init phases of this variant under lattices and prime-order groups in Section5.3and5.4respectively. In summary, we obtain the following theorem.

Theorem 3(Leveled Garbling of *O*(log*λ*)-ary Gates). *Let C* Arb = *{C* *λ* Arb *} be the class of* *circuits (of unbounded size) consisting of arbitrary gates with O*(log*λ*) *input wires and* 1 *output* *wires.* *Assuming P-DDH and DDH in Paillier groups, or P-RLWE with respect to the public pa-* *rameters* pp Lat *specified in Section5.3, there exists a garbling scheme for C* Arb *over* Z₂*, where* *the garbling size C*b *for a circuit C ∈C* *λ* Arb *is |C*b*|≤|C|* + Depth(*C*) *·* poly(*λ*)*.*

The proof of Theorem3follows from Proposition2,4, and6, which are proven in Sec- tion5.1,5.3, and5.4respectively. Security amplification for the leveled variant under prime- order groups is analogous to the non-leveled variant as described in Section5.5. We obtain two corollaries analogous to the non-leveled case.

Corollary 3(Leveled Boolean Garbling). *Assuming any of the assumptions in Theorem3,* *there exists a garbling scheme for all Boolean circuits C (with binary gates) with garbling size* *|C*b*|≤|C|* + Depth(*C*) *·* poly(*λ*)*.*

Corollary 4(Leveled Boolean Garbling for Layered Circuits). *Assuming any of the* *assumptions in Theorem2, there exists a garbling scheme for all layered Boolean circuits C* Layer *(with binary gates) with garbling size |C*b Layer *|≤ O*(*|C* Layer *|/* log log*λ*) + Depth(*C*) *·* poly(*λ*)*.*

5.1 Sub-protocol for Garbling *O*(log *λ*)-ary Boolean Gates In the sub-protocol BoolGateEval
*C,*g, both parties *PG,PE*hold public data pd = (aHMAC*.*pd*,* HSS*.*pdsk) prepared in the Init phase of the main protocol (Figure1), and jointly hold additive shares *⟨s*x*⟩*, where *s* is a global secret exponent sampled during Init, and x represent masked input values to the gate g *∈ C* (with masks derived from sk). Additionally, *PE*holds x in the clear. Inputs: (*PG*: pd*, ⟨s*x*⟩* 0 )*,* (*PE*: pd*, ⟨s*x*⟩* 1 *,*x)*.*

Their goal is to jointly obtain shares of *⟨s · z⟩*, where *z* is the masked output of g. Additionally, *PE*should hold *z* in the clear.

Outputs: (*PG*: *⟨sz⟩* 0 )*,* (*PE*: *⟨sz⟩* 1 *, z*)*.*

Their first steps are local aHMAC and HSS evaluations by both parties over the input shares *⟨s*x*⟩*. For now, assume there are arithmetic circuits *C*v(Fact1) and Boolean circuits *C*g*,*v(Equation6) which satsify X *z* = *C*v(x) *· C*g*,*v(sk) over Z*.* (5) v*∈{*0*,*1*}ℓx*

The parties apply aHMAC to locally evaluate *C*vover *⟨s*x*⟩* to obtain shares *⟨s · C*(x)*⟩*. They also locally hold additive shares of *⟨C*(x)*⟩* as *PE*can compute *C*(x) on its own.

|P :⟨s · C|(x)⟩ ← EvalKey(aHMAC.pd,C|||, ⟨sx⟩|),|
|---|---|---|---|---|---|
|G|v 0|||v|0|
|E|v 1|||v|1|

*P* :*⟨s · C* (x)*⟩ ←* EvalTag(aHMAC*.*pd*,C, ⟨s*x*⟩,*x)*.*

The parties next apply HSS to locally evaluate *C*g*,*vover the public data HSS*.*pdskand addition- ally “multiply” the results with *C*(x) to obtain shares *⟨sz⟩* and *⟨z⟩*.

*PG*:(*⟨sz⟩* 0 *, ⟨z⟩* 0
) *←* ExtEval₀(HSS*.*pdsk*,* (*...,C*g*,*v*,...*)*, ⟨s · C*v(x)*⟩*
0 *, ⟨C*v(x)*⟩* 0 v )

*PE*:(*⟨sz⟩* 1 *, ⟨z⟩* 1
) *←* ExtEval₁(HSS*.*pdsk*,* (*...,C*g*,*v*,...*)*, ⟨s · C*v(x)*⟩*
1 *, ⟨C*v(x)*⟩* 1 v )*.*

In summary, the parties now hold shares *⟨sz⟩*, *⟨z⟩* through local computations. In the last step, *PG*sends its share *⟨z⟩* mod 2 to *PE*, who then recovers *z*. It remains to specify the arithmetic circuits *C*vand Boolean circuits *C*g*,*vsatisfying Equa- tion5. For this, we let *C*vimplement the indicator polynomial *p*vspecified as follows.

Fact 1(Indicator Polynomial). For every positive integer *ℓx∈* N, every vector v *∈{*0*,*1*}* *ℓ* *x*, there exists a polynomial *p*v(over Z) such that ( 1 for x = v *p*v(x) = *ℓ* 0 for x *∈{*0*,*1*}x,* x *̸*= v*.*

Furthermore, *px*

|can be implemented by an arithmetic circuit C||: Z → Z of size |C||≤ O(ℓ ),|
|---|---|---|---|
|v||v ℓ|v x|
|v|x|ℓ||

Depth(*C*) *≤ O*(log*ℓ*) and such that all Boolean inputs x *∈{*0*,*1*}x*are admissible w.r.t. the bound *B* = 2.

We define *C*g*,*v(sk) to compute a masked output *z* pretending x = v.

*C*g*,*v(sk) = PRF(sk*,*OutWire(*g*)) *⊕* g v *⊕* PRF(sk*,*InWires(g))*.* (6)

Effectively, Equation5computes all possible evaluation results of *z* via *C*g*,*v(sk), and selects the correct one via *C*v(x), which only equals 1 when v = x. Assuming PRF is in NC1 and *ℓ* *x*= *O*(log*λ*), *C*g*,*vcan indeed be evaluated using HSS. We summarize the sub-protocol BoolGateEval *C,*g in Figure3. Note that in each invocation, the only communication is *one bit b* := *⟨z⟩* 0 sent from the garbler *PG*to the evaluator *PE*. We summarize its correctness and security in the following lemmas.

Lemma 16(Correctness of BoolGateEval *C,*g under Paillier Groups). *Let ℓ*(*λ*) *≤ O*(log*λ*) *be a bound on input length. There exists a negligible function* negl(*λ*) *such that for every λ ∈* N*,* *every Boolean circuit C with a gate* g *of ℓx≤ ℓ*(*λ*) *inputs, every masked input* x *∈ {*0*,*1*}* *ℓ* *x,* pp = (*N,ζ*) *in the support of* Pai*.*Gen(1 *λ* *,*1 2 )*, secret exponent s ∈* [*N*]*, additive shares (over* Z*)* *⟨s*x*⟩* 0 *, ⟨s*x*⟩* 1 *, and PRF key* sk *∈{*0*,*1*}* *λ* *, the following holds:*

  pd *sampled per Equation3,*  

|z z|G z|E z|||
|---|---|---|---|---|
|||C,g|G|0 E|

*w₁* = *w₀* + *sz,* (*P* : *w₀*)*,* (*P* : *w₁, z*)  Pr      *z* = g(x) *←* BoolGateEval (*P* : pd*, ⟨s*x*⟩*)*,* (*P* : pd*, ⟨s*x*⟩*1*,*x)  *z* := *z ⊕* PRF(sk*,*OutWire(*g*))*,* x := x *⊕* PRF(sk*,*InWires(*g*))

## ≥ 1 − negl(λ).

*Proof.* The correctness of BoolGateEval *C,*g follows from that of EvalKey, EvalTag and that <u>of</u> ExtEval*b*.

Sub-protocol BoolGateEval *C,*g The protocol runs between a garbler *PG* and an evaluator *PE*, to evaluate a Boolean gate g *∈ C*. Inputs: *PG,PE* both hold public data pd = (aHMAC*.*pd*,*HSS*.*pdsk) (as defined in Equation3), and jointly hold additive shares *⟨s*x*⟩*, where x *∈{*0*,*1*}* *ℓx* is a masked input vector. *PE* additionally holds the vector x. Outputs: *PG,PE* jointly output additive shares *⟨sz⟩*, where *z ∈{*0*,*1*}* is the masked output. *PE* addition- ally holds the bit *z*.

– *PG,PE* obtain additive shares *⟨sz⟩* and *⟨z⟩* through local computations, where

*z* := *z ⊕* PRF(sk*,*OutWire(*g*))*, z* := g(x)*,* x := x *⊕* PRF(sk*,*InWires(*g*))*.* (7)

Let *C*v and *C*g*,*v be arithmetic and Boolean circuits specified in Fact1and Equation6, respectively.
Further define *C*g := (*...,C*g*,*v*,...*).

1. *PG,PE* locally runs EvalKey*,*EvalTag, respectively, to obtain additive shares *⟨s · C*v(x)*⟩* and *⟨C*v(x)*⟩* for all v *∈{*0*,*1*}*
*ℓx*.

*PG* :*⟨s · C*v(x)*⟩*0*←* EvalKey(aHMAC*.*pd*,C*v*, ⟨s*x*⟩*0)*, ⟨C*v(x)*⟩*0*←* 0 *PE* :*⟨s · C*v(x)*⟩*1*←* EvalTag(aHMAC*.*pd*,C*v*, ⟨s*x*⟩*1*,*x)*, ⟨C*v(x)*⟩*1*← C*v(x)*.*

2. *PG,PE* locally runs ExtEval₀*,*ExtEval₁, respectively, to obtain additive shares *⟨sz⟩* and *⟨z⟩*.
*PG* :(*⟨sz⟩*0*, ⟨z⟩*0) *←* ExtEval₀(HSS*.*pdsk*,C*g*, ⟨s · C*v(x)*⟩*0*, ⟨C*v(x)*⟩*0 v ) *PE* :(*⟨sz⟩*1*, ⟨z⟩*1) *←* ExtEval₁(HSS*.*pdsk*,C*g*, ⟨s · C*v(x)*⟩*1*, ⟨C*v(x)*⟩*1 v )*.*

– *PG* sends a bit *b* := *⟨z⟩*0mod 2 to *PE*, who can then locally recover *z*.

<u>z := ⟨z⟩1− b mod 2.</u>

Fig. 3. Our 2PC subprotocol for *O*(log*λ*)-ary Boolean gates.

Lemma 17(Security of BoolGateEval *C,*g under Paillier Groups). *Under the same setting* *as Lemma16, there exists an efficient simulator* Sim *that, given the masked output z,* statistically *simulates PG’s message in the sub-protocol* BoolGateEval *C,*g *.* *More precisely, there exists a negligible function* negl(*λ*) *such that for every λ ∈* N*, every* *Boolean circuit C with a gate* g *of ℓx≤ ℓ*(*λ*) *inputs, every masked input* x *∈{*0*,*1*}* *ℓ* *x,* pp = (*N,ζ*) *in the support of* Pai*.*Gen(1 *λ* *,*1 2 )*, secret exponent s ∈* [*N*]*, additive shares (over* Z*) ⟨s*x*⟩* 0 *, ⟨s*x*⟩* 1 *,* *and PRF key* sk *∈{*0*,*1*}* *λ* *, the following holds.*

pd *sampled per Equation3,* SD msg*G*(pd*, ⟨s*x*⟩* 0 )*,* x := x *⊕* PRF(sk*,*InWires(*g*))*,* Sim(pd*, ⟨s*x*⟩* 1 *,* x*, z*) *≤* negl(*λ*)*,* *z* := g(x) *⊕* PRF(sk*,*OutWire(*g*))

*where* msg*G*(pd*, ⟨s*x*⟩* 0 ) *denotes PG’s message to PEin* BoolGateEval *C,*g *.*

*Proof.* The simulator computes *⟨z⟩* 1 following exactly *PE*’s steps, and then simulates *⟨z⟩* 0 mod 2 (which is the message from *PG*) as *z −⟨z⟩* 1 mod 2.

Using the correctness and security of the core sub-protocol, BoolGateEval under Paillier groups, we can now prove those of our garbling scheme under Paillier groups (compiled from the 2PC protocol BoolCircEval).

Proposition 1(Garbling of *O*(log*λ*)-ary Gates under Paillier Groups). *Assuming CP-* *DDH in Paillier groups, the garbling scheme compiled from the protocol* BoolCircEval *C,*Pai *(Fig-* *ure1,2) is correct and secure.*

*Proof of Proposition1.* The correctness of the protocol follows from that of BoolGateEval (Lemma16). Hence the correctness of the compiled garbling scheme follows. We focus now on proving security. First, we recap the compiled garbling scheme. Given a circuit *C*, the garbler proceeds as follows.

– Sample Paillier public parameters pp = (*N,ζ*), a secret exponent *s ←* [*N*], a PRF key sk *←{*0*,*1*}* *λ*, and compute public data pd per Equation3:

||λ|2||
|---|---|---|---|
||⌈log N ⌉ r rs rs|′ ′′|λ Bits(s)|
|r r s|Bits(sk)|r s r||

pp = (*N,*2) *←* Pai*.*Gen(1*,*1) *g ←* Pai*.*Samp(pp)*,* seed *←{*0*,*1*}* *λ* *,*

*s ←* [*N*]*,* r *←* [*N*]*,* r*,* r *←* [*N*]*,* 2(8) pd = (pp*,*seed*,g,g,g ⊙* (1 + *N*)*,* *′ ′ ′′ ′′*Bits(sk) *g,g ⊙* (1 + *N*)*,g,g ⊙* (1 + *N*))*.*

where *⊙* denotes component-wise multiplication between two vectors. – For every input wire *i*, sample a pad *k*

(*i*) *←* [*N · λ*
*ω*(1)], and define the key function *K*

(*i*) as
follows: *K*

(*i*)
(*b*) := (*b,s · b* + *k*
(*i*) )*,* where *b* := *b ⊕* PRF(sk*,*InWires(*C*)[*i*])*.*
– For every gate g *∈ C*, in the topological order, where a pad *k*

(*i*) is defined for all *i ∈*
InWires(*g*), follow the subprotocol BoolGateEval as *PG*with (pd*, {k*

(*i*) *}*InWires(*g*)) as inputs,
and compute its message *b*g. The output of the subprotocol defines a pad *k*

(*j*) for the output
wire *j* = OutWire(g). – Compute the masks on output wires o = PRF(sk*,*OutWires(*C*)). – Output the garbling *C*b = (pd*, {b*g*}C,*o) consisting of the public data, the bit *b*gfor every g *∈ C*, and the masks on the output wires. Output the key functions *{K*

(*i*) *}* as defined above.
Next, we describe the simulator Sim required by Definition1. It takes the circuit *C* and the evaluation results z as input, and simulates the garbling *C*b and input labels *{L*

(*i*) *}* as follows.
– Sample Paillier public parameter pp = (*N,ζ*) honestly, and sample random elements as public data pd f:

||λ 2||||λ|
|---|---|---|---|---|---|
||⌈log N ⌉|′ ′ ′′|′′|λ||
|a b|c a b (i)|a b ω|||(i)|
|(i)|(i) (i)||||(j)|
|||||(i)||
||||||E|
|(i)|(i)|||||
||(j)|||||

pp = (*N,*2) *←* Pai*.*Gen(1*,*1) *g ←* Pai*.*Samp(pp)*,* seed *←{*0*,*1*},*

*s ←* [*N*]*,* a*,* b*,* c *←* [*N³*]*,* a*,* b*,* a*,* b *←* [*N³*]*,* (9)

pd f = (pp*,*seed*,g,g,g,g,g,g,g*)*.* *′ ′ ′′ ′′*

– For every input wire *i*, sample a label ˜*l ←* [*N · λ*], and a masked bit ˜*x ←{*0*,*1*}*. The simulated input labels are *L*e = (˜*x,* ˜*l*). Further sample a masked bit *x*˜ *←{*0*,*1*}* for every wires *j* in *C*, including the output wires. – For every gate *g ∈ C*, in the topological order, where a label ˜*l* and a masked bit ˜*x*

(*i*) are
defined for all *i ∈* InWires(g), follow the the subprotocol BoolGateEval as *P* except the last step (See Figure3) with (pd f*, {*˜*l, x*˜*}*) as inputs. The computation results (corresponding to *⟨sz⟩* 1 in Figure3) define a label ˜*l* for the output wire *j* = OutWire(g). Then run the simulator guaranteed by the security of the subprotocol (Lemma17):

˜ *b* g*←* Sim *′* (pd f*, {*˜*l*(*i*)*, x*˜(*i*)*}, z*˜(*j*))*,* InWires(g)

where ˜*z*

(*i*) is the masked bit assigned to wire *j* = OutWire(g).

– Let ez be the masked bits assigned to output wires OutWires(*C*), simulate the masks on output wires as o˜ = ez *⊕* z. – Output the simulated garbling *C*e = (pd f*, {*˜*b*g*},*o˜), and the simulated input labels *{L*e

(*i*) *}*.
We now show a series of hybrid experiments, where Hyb₀ describe the honest distribution of *C*b and *{L*

(*i*) = *K*
(*i*) (x[*i*])*}* for some input x, and Hyb₅ describe the simulated distribution *C*e and
*{L*e

(*i*) *}*.
Hyb₀ The real distribution of *C*b and *{L*

(*i*) = *K*
(*i*) (x[*i*])*}* computed according to the garbling
scheme. (See the recap earlier.) Hyb₁ In this hybrid, instead of computing the bits *{b*g*}* as the garbler’s message following the subprotocol BoolGateEval, simulate them using the simulator Sim *′* guaranteed by the security of the subprotocol: – First compute the correct wire value *x*

(*j*) on each wire *j* in *C*, and then the masked bit
*x*

(*j*) = *x*
(*j*) *⊕* PRF<u>(</u>sk*,j*).
– Let *l*

(*i*) = *k*
(*i*) + *sx*
(*i*) be the labels on input wires. For every gate g *∈ C*, in topological
order, follow the subprotocol as *PE*(except the last step) with (pd*, {l*

(*i*) *, x*
(*i*) *}*InWires(g)) as
(*j*)

|inputs to compute a label l|||for the output wire j = OutWire(g). Then run the simulator|||||||
|---|---|---|---|---|---|---|---|---|---|
||||g|′|(i) (i)|(j)||||
||(j)|||||||||
||||(i)|||||||
|g||||||(i)|(i)|(i)||
|(i)|ω(1)|(i)|(i)|||||||
 ˜ *b ←* Sim (pd*, {*˜*l, x*˜*}, z*)*,*
where *z* is the masked bit on wire *j*. By the correctness and security of BoolGateEval (Lemma16and17), the simulated bits *b*g are statistically close to the correctly computed ones in Hyb₀. Hence we have Hyb₀ *≈* Hyb₁. Note that in Hyb₁, the pads *k* sampled for the input wires are not used for computing the bits *b* anymore. Hyb₂ In this hybrid, instead of computing the input labels as *l* = *x s* + *k*, directly sample ˜ *l ←* [*N · λ*]. The two ways of sample *l* and ˜*l* are statistically close, hence we have Hyb₂ *≈* Hyb₁. Note that in Hyb₂, the secret exponent *s* within pd is not used for computing the input labels or anywhere else. Hyb₃ In this hybrid, instead of computing the masks on the output wires directly using the PRF, o = PRF(sk*,*OutWires(*C*)), compute it as oe = z *⊕* z, where z are the masked wire values on the output wires. As the two ways of computing o and oe are equivalent, we have Hyb₃ *≡* Hyb₂. Hyb₄ In this hybrid, instead of computing the public data pd as in Equation8, simulate it with random elements as in Equation9. We claim the two ways of sampling pd are computationally indistinguishable (Claim1). Hence we have Hyb₄ *≈c*Hyb₃. Note that in Hyb₄, the PRF key sk are only used for computing masked wire values *x*

(*i*) = *x*
(*i*) *⊕* PRF(sk*,i*), and in particular not the public data anymore.
Hyb₅ In this hybrid, instead of computing the masked wire values *x*

(*i*) using a PRF, directly
sample them at random ˜*x*

(*i*) *←{*0*,*1*}*.
By the security of PRF, we have Hyb₅ *≈c*Hyb₄. Note that Hyb₅ computes exactly the simulated distribution of *C*e and *{L*e

(*i*) *}*.
By a hybrid argument, we conclude Hyb₀ *≈c*Hyb₅. It remains to prove the following claim.

Claim 1. *For all* sk *∈{,}* *λ* *, the distribution of* pd *defined by Equation8and* pd f *by Equation9* *are computationally indistinguishable.*

*Proof.* We show a series of hybrid that transitions from the distribution of Equation8to Equa- tion9.

Hyb *′* 0This is the distribution of Equation8. Hyb *′* 1In this hybrid, instead of computing the aHMAC public data as

r r*s* r*s*2Bits(*s*) *g,g,g ⊙* (1 + *N*)

where r*,s* are random exponents from [*N*], simulate them as random elements

*g* a *,g* b *,g* c *,*

where a*,* b*,*c are random exponents from [*N³*]. By CP-DDH in Paillier groups (Definition7), we have Hyb *′* 1*≈c*Hyb *′* 0. Hyb *′* 2In this hybrid, instead of computing the HSS public data as r *′*r*′s* Bits(sk) r*′′s* r*′′*Bits(sk) *g,g ⊙* (1 + *N*)*,g,g ⊙* (1 + *N*)*,*

*′ ′′*

|where r|, r ,s are random exponents from [N], simulate them as|||||||
|---|---|---|---|---|---|---|---|
||′ ′ ′′|a ′′|b|Bits(sk)|a b ′2 c|′1|Bits(sk)|
|′ b||||a b|a b|Bits(sk)||

*′ ′ ′′ ′′* *g,g ⊙* (1 + *N*)*,g,g ⊙* (1 + *N*)*,*

where a*,* b*,* a*,* b are random exponents from [*N³*]. By DDH (Definition5, which is implied by CP-DDH) in Paillier groups, we have Hyb *≈* Hyb. b*′* Hyb₃ In this hybrid, instead of multiplying the term (1 + *N*) to random elements *g* and *′′* *g* as above, directly compute HSS public data at random *′ ′ ′′ ′′* *g,g,g,g.*

By Lemma1, the element *g* sampled by Pai*.*Samp(pp) has the guarantee that *⟨g⟩* contains b*′′* 3 the subgroup generated by (1 + *N*). Therefore, *g* with a random exponent b from [*N*] perfectly hides the multiplicative factor (1 + *N*) Bits(sk). We have Hyb *′* 3*≡* Hyb *′* 2. Note that Hyb *′* 3computes exactly the distribution of Equation9.

By a hybrid argument, we conclude that Hyb *′* 0*≈c*Hyb *′* 3, which proves the claim.

5.2 A Leveled Variant under Paillier Groups Compared to the non-leveled protocol, the main changes in the leveled variant are (1) in the core sub-protocol LBoolGateEval both parties now run *leveled* aHMAC local evaluations, and (2) the leveled aHMAC and (normal) HSS instances no longer rely on common secret exponents. The two differences together allow us to avoid circular security arguments in this variant. On the other hand, they require much larger public data, of size linear in the circuit depth. We now explain the differences in more detail. – During Init, the garbler prepares appropriate public data (Equation10) for Depth(*C*) in- stances of leveled aHMAC and HSS to support the following two types of local evaluations. Assume *P*

|,P jointly holds additive shares ⟨s||· x⟩, and P|additionally holds x.|
|---|---|---|---|
|G E|(t) (t) 0|E|E (t) 1|

Inputs: (*PG*: pd*, ⟨s ·* x*⟩*)*,* (*P* : pd*, ⟨s ·* x*⟩,*x)*.*

1.In the first type, they locally run leveled aHMAC evaluations on the input shares *⟨s*
(*t*) <u>·</u> x*⟩*
over arithmetic circuits *C*v(of depth *d*Ind; Fact1) to obtain additive shares *⟨*k[*t*] *· C*v(x)*⟩*, where k[*t*] is an independent secret exponent in the *t*-th HSS instance.

Via aHMAC Eval: (*PG*: *⟨*k[*t*] *· C*v(x)*⟩* 0 )*,* (*PE*: *⟨*k[*t*] *· C*v(x)*⟩* 1 )*.*

(*i*) (*t*+1)
They then locally run HSS to evaluate *C*g*,*vover public data HSS*.*pd sk*,s*(*t*+1) where *s* is

(*i*) (*t*+1)
an independent secret exponent in the (*t*+1)-th leveled aHMAC instance, and *C*g*,*v(sk*,s*) is defined to compute *C*g*,*v(<u>sk</u>) *·* Bits(*s* (*t*+1) )[*i*] (see Equation6). The result can be addi- tionally “multiplied” by *C*v(x) via HSS extended evaluation. In the end, they jointly hold additive shares of *⟨*Bits(*s* (*t*+1) )[*i*] *· z⟩* and *⟨z⟩*.

Via HSS Eval: (*PG*: *⟨*Bits(*s* (*t*+1) )[*i*] *· z⟩* 0 *, ⟨z⟩* 0 )*,*

(*PE*: *⟨*Bits(*s* (*t*+1) )[*i*] *· z⟩* 1 *, ⟨z⟩* 1 )*.*

Finally, they locally linearly combine the shares *⟨*Bits(*s* (*t*+1) )[*i*] *· z⟩* into shares *⟨s* (*t*+1) *· z⟩*.

Via Linear Comb.: (*PG*: *⟨s* (*t*+1) *· z⟩* 0 )*,* (*PE*: *⟨s* (*t*+1) *· z⟩* 1 )*.*

2.In the second type, they locally run leveled aHMAC evaluations on the input shares *⟨s*
(*t*) *·* x*⟩* over the identity arithmetic circuit *C*id(of appropriate depth) to obtain additive (*t′*) *′* (*t′*) *′*
shares *⟨s ·* x*⟩*, where *t > t*, and *s* is an independent secret exponent in the *t*-th leveled aHMAC instance.

(*t′*) (*t′*) Via aHMAC Eval: (*PG*: *⟨s ·* x*⟩* 0 )*,* (*PE*: *⟨s ·* x*⟩* 1 *,*x)*.*

– During Eval, for every gate g *∈ C* of depth *t*, assume *PG,PE*jointly holds additive shares *⟨s*

(*t*) *·* x*⟩*, and *PE*additionally holds x.
First, they apply type-1 local evaluations to obtain additive shares of *⟨s* (*t*+1) *z⟩, ⟨z⟩*. Next, *PG* sends his share *⟨z⟩* mod 2 to *PE*who then recovers *z* mod 2. Finally, for every gate g *′* *∈ C* of depth *t* *′* *> t* that uses *z* as an input, they apply type-2 local evaluations to obtain additive (*t′*) shares of *⟨s z⟩*.

Implementing the leveled variant requires careful book-keeping of the public data. We give full details of the leveled variant of our 2PC protocol under Paillier groups in Figure4,5, and the leveled variant of the core sub-protocol in Figure6. Note that the total communication from *PG*to *PE*consists of *one bit* per invocation of the sub-protocol LBoolGateEval, plus public data of size Depth(*C*) *·* poly(*λ*), assuming all gates in *C* has fan-in *O*(log(*λ*)). We summarize the correctness and security of the sub-protocol LBoolGateEval in the following lemmas.

Lemma 18(Correctness of LBoolGateEval *C,*g under Paillier Groups). *Let ℓ*(*λ*) *≤ O*(log*λ*) *be a bound on input length, and d*Ind= *O*(log log*λ*) *be the depth of the indicator arithmetic circuit* *over ℓ inputs (Fact1).* *There exists a negligible function* negl(*λ*) *such that for every λ ∈* N*, every Boolean circuit C* *(of depth dC) with a gate* g *of ℓx≤ ℓ*(*λ*) *inputs, every masked input* x *∈{,}* *ℓ* *x,* pp = (*N,ζ*) *in the support of* Pai*.*Gen(1 *λ* *,*)*, secret exponent* s *∈* [*N*] *d* *C·d*Ind+1*, additive shares (over* Z*)*

Protocol LBoolCircEval *C,*Pai The protocol runs between a garbler *PG* and an evaluator *PE*, to evaluate a Boolean circuit *C* : *{*0*,*1*}* *ℓx* *→* *{*0*,*1*}* *ℓz*. It uses the following ingradients:

– aHMAC *leveled* evaluation procedures EvalKey *d* Ind*,*EvalTag*d*Indfor bounded depth computations by *d* Ind= *O*(log log*λ*) *a* over bounded integers by *B* = 2, and public data generation procedure aHMAC Pai *.*pd under Paillier groups; (See Lemma5;) – HSS evaluation procedures ExtEval₀*,*ExtEval₁ and public data generation procedure HSS Pai *.*pd under paillier groups; (See Lemma6;) – a PRF : *{*0*,*1*}* *λ* *×{*0*,*1*}* *λ* *→{*0*,*1*}* in NC1.

Inputs: *PG* holds a vector x *∈{*0*,*1*}* *ℓx*, while *PE* holds notinog. Outputs: *PG* outputs nothing, while *PE* outputs a vector z *∈{*0*,*1*}* *ℓz*.

– Init : Let *dC* = Depth(*C*), and *d* = *dC · d*Ind.

1. *PG* sends public data pd to the evaluator *PE*.
*ζ* := 2*,* pp = (*N,ζ*) *←* Pai*.*Gen(1 *λ* *,*1 *ζ* )*,* s *←* [*N*] *d*+1 *,* k *←* [*N*] *dC* *,* sk *←{*0*,*1*}* *λ*

// For short, write *s*

(*t*) = s[*t · d*Ind]*, s*
(end *t*) = s[(*t* + 1) *· d*Ind*−* 1]*.* *∀j ∈* [*d*]*,* aHMAC*.*pd

(*j*) *←* aHMAC
Pai *.*pd(pp*,*s[*j*]*,*s[*j* + 1])*,* *∀t ∈* [*dC*]*,* aHMAC*.*pd (k*t*) *←* aHMAC Pai *.*pd(pp*,s* (end *t*) *,*k[*t*])*,* (10) *∀t ∈* [*dC*]*,* HSS*.*pd (sk*t,*)s *←* HSS Pai *.*pd(pp*,*k[*t*]*,*sk*∥*Bits(*s* (*t*+1) ))*,* pd := *{*aHMAC*.*pd

(*j*) *}* *j∈*[*d*]*, {*aHMAC*.*pd
(k*t*) *,*HSS*.*pd (sk*t,*)s *}* *t∈*[*dC*]*.*

2.Let *s* = s[0]. *PG* sends masked inputs x and additive shares *⟨s*x*⟩*1to *PE* as in BoolCircEval
*C,*Pai (Figure1). *a* *d* Indis the depth of the indicator arithmetic circuit over *O*(log*λ*) inputs (Fact1).

Fig. 4. The Init phase of leveled 2PC for Boolean circuits under Paillier groups.

*⟨s*

(*t*) x*⟩* 0 *, ⟨s*
(*t*) x*⟩* 1 *, and PRF key* sk *∈{*0*,*1*}*
*λ* *, the following holds: (where we use the shorthand* *s*

(*t*) = s[*t · d*Ind]*)*
  pd *sampled per Equation10,* *z z C,*g

||(P : w₀), (P|: w₁, z) ← LBoolGateEval||
|---|---|---|---|
|z (t+1)|G G|E (t) 0|(t) 1|

 *z z* (*t*+1) *G E*  *w₁* = *w₀* + *s z,*  Pr   (*P* : pd*, ⟨s* x*⟩*)*,* (*PE*: pd*, ⟨s* x*⟩,*x)    *z* = g(x)   *z* := *z ⊕* PRF(sk*,*OutWire(*g*))*,*  x := x *⊕* PRF(sk*,*InWires(*g*)) *≥* 1 *−* negl(*λ*)*.*

*Proof.* The correctness of LBoolGateEval *C,*g follows from that of the leveled variants of EvalKey<u>,</u> EvalTag (Lemma5) and that of ExtEval*b*(Lemma6).

Lemma 19(Security of LBoolGateEval *C,*g under Pailler Groups). *Under the same setting* *as Lemma18, there exists an efficient simulator* Sim *that, given the masked output z,* statistically *simulates PG’s message in the sub-protocol* LBoolGateEval *C,*g *.* *More precisely, there exists a negligible function* negl(*λ*) *such that for every λ ∈* N*, every* *Boolean circuit C with a gate* g *of ℓx≤ ℓ*(*λ*) *inputs, every masked input* x *∈{,}* *ℓ* *x,* pp = (*N,ζ*)

Protocol LBoolCircEval *C,*Pai Continued

– Eval : *PG,PE* evaluate gates g *∈ C* (at depth *t*) in the topological order while maintaining the following invariant. (We write *s*

(*t*) = s[*t · d*Ind] for short.)
1. *PG,PE* jointly hold additive shares *⟨s*
(*t*) xg*⟩*, where xg are masked input wire values to the gate g
as in BoolCircEval *C* (Equation4).

2. *PE* holds the masked wire values xg. To evaluate the gate g, *PG,PE* call the sub-protocol LBoolGateEval.
(*PG* : *⟨s* (*t*+1) *z* g *⟩* 0 )*,* (*PE* : *⟨s* (*t*+1) *z* g *⟩* 1 *, z*g) *←* LBoolGateEval *C,*g (*PG* : pd*, ⟨s*

(*t*) xg*⟩*0)*,* (*PE* : pd*, ⟨s*
(*t*) xg*⟩*1*,* xg)*.*
*′ ′* (*t′*) Then, for every gate g (at depth *t > t*+ 1) taking *z* as an input, *PG,PE* obtain shares *⟨s z⟩* through local computations.

diff := (*t* *′* *− t −* 1) *· d*Ind*,* pddiff:= *{*aHMAC*.*pd ((*t*+1)*·d*Ind+*j*) *}* *j∈*[diff+1] (*t′*) diff (*t*+1) *PG* :*⟨s z⟩*0*←* EvalKey₀ (pddiff*,C*id*, ⟨s · z⟩*0)*,* (*t′*) diff (*t*+1) *PE* :*⟨s z⟩*1*←* EvalTag₁ (pddiff*,C*id*, ⟨s · z⟩*1*, z*)*,*

where *C*id(with depth = diff) computes the identity function. <u>– Final : The same as BoolCircEval</u> *C,*Pai <u>(Figure2).</u>

Fig. 5. The Eval*,*Final phases of the leveled 2PC protocol for Boolean circuits under Paillier groups.

*in the support of* Pai*.*Gen(1 *λ* *,*1 2 )*, secret exponents* s *∈* [*N*] *d* *C·d*Ind+1*, additive shares (over* Z*)*

(*t*)

|⟨s x⟩, ⟨s|x⟩, and PRF key sk ∈{0, 1}|||, the following holds.|||
|---|---|---|---|---|---|---|
|0|1||||||
|||G|(t) 0||||
||||(t)||||
||G|(t) 0|1|G||C,g|
 0
(*t*) 1
*λ*

pd *sampled per Equation10,* SD msg (pd*, ⟨s* x*⟩*)*,* x := x *⊕* PRF(sk*,*InWires(*g*))*,* Sim(pd*, ⟨s* x*⟩,* x*, z*) *≤* negl(*λ*)*,* *z* := g(x) *⊕* PRF(sk*,*OutWire(*g*))

*where* msg (pd*, ⟨s* x*⟩*) *denotes P ’s message to PEin* LBoolGateEval*.*

*Proof.* Analogous to the proof of Lemma17.

Using the correctness and security of LBoolGateEval under Paillier groups, we can now prove those of our leveled garbling scheme under Paillier groups (compiled from the 2PC protocol LBoolCircEval).

Proposition 2(Leveled Garbling of *O*(log*λ*)-ary Gates under Paillier Groups). *As-* *suming P-DDH and DDH in Paillier groups, the garbling scheme compiled from the protocol* LBoolCircEval *C,*Pai *(Figure4,5) is correct and secure.*

*Proof of Proposition2.* The correctness of the protocol follows from that of LBoolGateEval (Lemma18). Hence the correctness of the compiled garbling scheme follows. The security proof follows the same arguments as those for Proposition1, except the public data pd are computed and simulated differently. In the honest protocol, they are computed as

Sub-protocol LBoolGateEval *C,*g The protocol runs between a garbler *PG* and an evaluator *PE*, to evaluate a Boolean gate g *∈ C*. Inputs: *PG,PE* both hold public data pd = *{*aHMAC*.*pd

(*j*) *}, {*aHMAC*.*pd
(k*t*) *,*HSS*.*pd (sk*t,*)s *}* (as defined in Equation10), and jointly hold additive shares *⟨s*

(*t*) x*⟩*, where x *∈ {*0*,*1*}*
*ℓx* is a masked input vector. *PE* additionally holds the vector x. Outputs: *PG,PE* jointly output additive shares *⟨s* (*t*+1) *z⟩*, where *z ∈ {*0*,*1*}* is the masked output. *PE* additionally outputs the bit *z*.

– *PG,PE* obtain additive shares *⟨s*

(*t*) *z⟩* and *⟨z⟩* through local computations, where *z* is defined as in
BoolGateEval (Equation7). Let *C*v and *C*g*,*v be arithmetic and Boolean circuits specified in Fact1
and Equation6, respectively. Further define *C*g := (*...,C*g*,*v*,...*), and *C*g(

*i*) : *{*0*,*1*}* *ℓx* *×{*0*,*1*}*
*⌈*log *ℓx ⌉* *→* 2 *ℓx·⌈*log *ℓ⌉* *{*0*,*1*}*. *C*g(

*i*) (sk*,s* (*t*+1) ) = (*...,C*g*,*v(sk) *·* Bits(*s*
(*t*+1) )[*i*]*,...*)v*∈{*0*,*1*}ℓx.*

1. *PG,PE* locally runs EvalKey
*d* Ind*,*EvalTag*d*Ind, respectively, to obtain additive shares *⟨*k[*t*] *· C* v

(x)*⟩*
and *⟨C*v(x)*⟩* for all v *∈{*0*,*1*}* *ℓx*.

pdInd:= *{*aHMAC*.*pd (*t·d*Ind+*j*) *}* *j∈*[*d*Ind]*∪{*aHMAC*.*pd (k*t*) *}* *PG* :*⟨*k[*t*]*C*v(x)*⟩*0*←* EvalKey *d* Ind(pd Ind*,C*v*, ⟨s*

(*t*) x*⟩*0)*, ⟨C*v(x)*⟩*0*←* 0
*PE* :*⟨*k[*t*]*C*v(x)*⟩*1*←* EvalTag *d* Ind(pd Ind*,C*v*, ⟨s*

(*t*) x*⟩*1*,*x)*, ⟨C*v(x)*⟩*1*← C*v(x)*.*
2. *PG,PE* locally runs ExtEval₀*,*ExtEval₁, respectively, to obtain additive shares *⟨s*
(*t*+1) *z⟩* and *⟨z⟩*. (*PE*’s computation is analogous *PG*’s.)

*PG* :(*, ⟨z⟩*0) *←* ExtEval₀(HSS*.*pd (sk*t,*)s *,C*g*, ⟨*k[*t*]*C*v(x)*⟩*0*, ⟨C*v(x)*⟩*0 v )*,* (*, ⟨z ·* Bits(*s* (*t*+1) )[*i*]*⟩*0) *←* ExtEval₀(HSSpd (sk*t,*)s *,C*g(

*i*) *, ⟨*k[*t*]*C*v(x)*⟩*0*, ⟨C*v(x)*⟩*0
v )*,*

*⟨s* (*t*+1) *z⟩*0*←* BitComp *⟨z ·* Bits(*s* (*t*+1) )[*i*]*⟩*0over Z*.*

– *PG* sends a bit *b* := *⟨z⟩*0mod 2 to *PE*, who can then locally recover *z*.

<u>z := ⟨z⟩1− b mod 2.</u>

Fig. 6. Leveled 2PC protocol for Boolean gates.

follows according to Equation10, with respect to a PRF key sk *∈{*0*,*1*}* *λ* :

||λ 2|d+1|d||
|---|---|---|---|---|
||(t) (j) (t)|(t) Ind end Pai Pai|(t)|Ind|
|C|k (t)|Pai|end|(t+1)|
|C|sk,s (j) j∈[d]|(t) k|(t) sk,s t∈[d|]|

pp = (*N,*2) *←* Pai*.*Gen(1*,*1)*,* s *←* [*N*]*,* k *←* [*N*] *C* *,*

// For short, write *s* = s[*t · d*]*, s* = s[(*t* + 1) *· d −* 1]*.*

*∀j ∈* [*d*]*,* aHMAC*.*pd *←* aHMAC*.*pd(pp*,*s[*j*]*,*s[*j* + 1])*,* (11) *∀t ∈* [*d*]*,* aHMAC*.*pd *←* aHMAC*.*pd(pp*,s,*k[*t*])*,*

*∀t ∈* [*d*]*,* HSS*.*pd *←* HSS*.*pd(pp*,*k[*t*]*,*sk*∥*Bits(*s*))*,*

pd := *{*aHMAC*.*pd*}, {*aHMAC*.*pd*,*HSS*.*pd*}* *C* *.*

In the simulation, the are computed as follows:

pp = (*N,*2) *←* Pai*.*Gen(1 *λ* *,*1 2 )*,*

(*j*)
Pai *⌈*log *N ⌉* *∀j ∈* [*d*]*,* aHMAC*.*pd f *←* aHMAC*.*Sim(pp*,*1)*,*

*′*

(*t*)
Pai *⌈*log *N ⌉* *∀t ∈* [*dC*]*,* aHMAC*.*pd f *, ←* aHMAC*.*Sim(pp*,*1)*,* (12)

(*t*) Pai *⌈*log *N ⌉*+*λ*
*∀t ∈* [*dC*]*,* HSS*.*pd f *←* HSS*.*Sim(pp*,*1)*,*

(*j*)
f*′*

(*t*) (*t*)
pd f := *{*aHMAC*.*pd f*}* *j∈*[*d*]*, {*aHMAC*.*pd*,*HSS*.*pd f*}* *t∈*[*dC*]*,*

where aHMAC Pai *.*Sim(pp*,*1 *ℓ* ) is as follows

*g ←* Pai*.*Samp(pp)*,* a*,* b*,* c *←* [*N³*] *ℓ* *,* seed *←{*0*,*1*}* *λ* (13) aHMAC Pai *.*pd f = (pp*,*seed*,g*a*,g*b*,g*c)*,*

and HSS Pai *.*Sim(pp*,*1 *ℓ* ) as as follows

*g ←* Pai*.*Samp(pp)*,* a*,* b*,* c*,* d *←* [*N³*] *ℓ* *,* seed *←{*0*,*1*}* *λ* (14) HSS Pai *.*pd f = (pp*,*seed*,g*a*,g*b*,g*c*,g*d)*.*

We show an analogous claim (to Claim1) which completes the proof.

Claim 2. *For all* sk *∈{*0*,*1*}* *λ* *, the distribution of* pd *defined by Equation11and* pd f *by Equa-* *tion12are computationally indistinguishable.*

*Proof.* We show a series of hybrid that transitions from the distribution of Equation11to Equation12.

Hyb *′* 0This is the distribution of Equation11. Hyb *′* 0*,*1Instead of computing the first instance of aHMAC public data aHMAC*.*pd

(0) as aHMAC
Pai *.*pd (pp*,*s[0]*,*s[1]), simulate it as aHMAC Pai *.*Sim(pp*,*1 *⌈*log *N ⌉* ). We claim (Claim3) the two ways of generating aHMAC*.*pd

(0) are computationally indistinguishable. Hence we have Hyb
*′* 0*,*1*≈c* Hyb *′* 0. Hyb *′* 0*,j*for 1 *< j < d*Ind*−*1, instead of computing the *j*-th instance of aHMAC public data from

aHMAC Pai *.*pd(pp*,*s[*j*]*,*s[*j* + 1])*,*

simulate is as aHMAC Pai *.*Sim(pp*,*1 *⌈*log *N ⌉* )*.* *′*

|By Claim3again, we have Hyb|||≈|Hyb|||
|---|---|---|---|---|---|---|
|′ ,j|Ind|||||Pai|
||(0) end|Ind Pai|(0) end|Ind|Pai|(0) end|

0*,j c* *′* 0*,j−*1. *′* Pai (*j*) Pai *′*(0) Hyb₀ for *j* = *d −*1, instead of computing the aHMAC public data aHMAC*.*pd, aHMAC*.*pd from (where *s* := s[*d −* 1])

aHMAC*.*pd(pp*,*s[*s,*s[*d*])*,* aHMAC*.*pd(pp*,*s[*s*]*,*k[0])*,*

simulate them as

aHMAC Pai *.*Sim(pp*,*1 *⌈*log *N ⌉* )*,* aHMAC Pai *.*Sim(pp*,*1 *⌈*log *N ⌉* )*.*

By Claim3again, we have Hyb *′* *,j≈c*Hyb *′* *,j−*.

Hyb *′* 0*,j*for *j* = *d*Ind, instead of computing the HSS public data HSS Pai *.*pd

(0) from
HSS Pai *.*pd(pp*,*k[0]*,*sk*∥*Bits(*s*

(1) ))*,*
simulate it as HSS Pai *.*Sim(pp*,*1 *⌈*log *N ⌉*+*λ* )*.*

We claim (Claim4) the two ways of generating HSS*.*pd

(0) are computationally indistinguish-

||≈ Hyb|.|||||
|---|---|---|---|---|---|---|
|C|Ind||||′0,j||
|′t,1 c ′|′t−1,d|′t,j Pai|c ′t,j−1 c ′|′d −1,d||′d −1,d|
||c|Pai|ℓ||λ||
|||||λ|||
||||||λ 2||

able. Hence we have Hyb *′* 0*,j c* *′* 0*,j−*1 Hyb *′t,j* for 1 *< t < d*, 1 *≤ j ≤ d* is analogous to the case of Hyb *′* 0*,j*, except replacing the 0 in its description with *t*. We have Hyb *≈* Hyb Ind, and Hyb *≈* Hyb. Note that Hyb *C* Ind computes exactly the distribution of Equation12.

By a hybrid argument, we conclude that Hyb *′* 0*≈* Hyb*C* Ind, which proves the claim. It remains to prove the following sub-claims.

Claim 3. *For all s ∈* Z*, with bit-length ℓ ≤* poly(*λ*) *the following computational indistinguisha-* *bility holds* pp*,*aHMAC*.*pd(pp*,s,s*) *s ←* [*N*] n o *≈* pp*,*aHMAC*.*Sim(pp*,*1)

*where the public parameter* pp *is sampled as* pp = (*N,*2) *←* Pai*.*Gen(1*,*1) *in both sides.*

*Proof.* This follows directly from P-DDH and DDH (Definition7and6) in Paillier groups.

Claim 4. *For all s* *′* *∈* Z*, with bit-length ℓ ≤* poly(*λ*)*, and* sk *∈{*0*,*1*}* *λ* *the following computa-* *tional indistinguishability holds*

pp*,*HSS Pai *.*pd(pp*,s,* sk*∥*Bits(*s* *′* )) *s ←* [*N*] *λ* n o *≈c*pp*,*HSS Pai *.*Sim(pp*,*1 *ℓ* ) *λ*

*where the public parameter* pp *is sampled as* pp = (*N,*2) *←* Pai*.*Gen(1 *λ* *,*1 2 ) *in both sides.*

*Proof.* This follows directly from DDH (Definition5) in Paillier groups.

5.3 Instantiations under Lattices In this section, we instantiate the non-leveled and leveled variants of our 2PC protocols under lattices, BoolCircEval
*C,*Lat, LBoolCircEval *C,*Lat. As explained in the begining of Section5, the protocols stay mostly unchanged, except for the Init phases, during which *PG*computes public data pd differently. We show them in Figure7and8respectively. Parameter Settings. Our instantiations under lattices uses the following public parameter settings: A polynomial ring *R*(*λ*) = Z[*X*]*/*(*X* *n*(*λ*) + 1), two moduli *p*(*λ*)*,q*(*λ*), and error and secret distributions *D*err(*λ*)*, D*sk(*λ*) where

– *n ≤* poly(*λ*) is a power-of-two, – *p ≥ λ* *ω*(1), *q* = *p · ∆*, and *∆ ≥ p · λ* *ω*(1); – *D*err(*λ*), *D*sk(*λ*) have coefficients bounded by poly(*λ*).

We write pp Lat = (*R,p,q, D*err*, D*sk). The Non-leveled Variant. The non-leveled 2PC protocol is shown in Figure7. It uses the same core sub-protocol BoolGateEval *C,*g (Figure3) which stays unchanged. We summarize the correctness and security of BoolGateEval *C,*g under lattices in the following lemmas. Their proofs are completely analogous to those of Lemma16and17, hence are omitted.

Protocol BoolCircEval *C,*Lat The protocol runs between a garbler *PG* and an evaluator *PE*, to evaluate a Boolean circuit *C* : *{*0*,*1*}* *ℓx* *→* *{*0*,*1*}* *ℓz*. It uses the following ingradients:

– public parameters pp Lat = (*R,p,q, D*err*, D*sk) specified in Section5.3; – aHMAC evaluation procedures EvalKey*,*EvalTag over bounded integers by *B* = 2, and public data generation procedure aHMAC Lat *.*pd under lattices; (See Lemma13;) – HSS evaluation procedures ExtEval₀*,*ExtEval₁ and public data generation procedure HSS Lat *.*pd under lattices; (See Lemma15;) – a PRF : *{*0*,*1*}* *λ* *×{*0*,*1*}* *λ* *→{*0*,*1*}* in NC1.

Inputs: *PG* holds a vector x *∈{*0*,*1*}* *ℓx*, while *PE* holds notinog. Outputs: *PG* outputs nothing, while *PE* outputs a vector z *∈{*0*,*1*}* *ℓz*.

– Init :

1. *PG* sends public data pd to the evaluator *PE*.
*s ←D*sk*,* sk *←{*0*,*1*}* *λ*

pd := aHMAC Lat *.*pd(pp Lat *,s,s*)*,*HSS Lat *.*pd(pp Lat *,s,* sk)*.* (15)

2. *PG* sends masked inputs x and additive shares *⟨s*x*⟩*1to *PE*.
x = x *⊕* PRF(sk*,*InWires(*C*))*,* *⟨s*x*⟩*1:= *s*x + *⟨s*x*⟩*0(over *R*), where *⟨s*x*⟩*0*←R* *ℓ* *λxω*(1) *.*

<u>– Eval,Final phases are the same as BoolCircEval</u> *C,*Pai <u>(Figure2).</u>

Fig. 7. Our 2PC protocol for Boolean circuits under lattices.

Lemma 20(Correctness of BoolGateEval *C,*g under Lattices). *Let ℓ*(*λ*) *≤ O*(log*λ*) *be a* *bound on input length, and* pp Lat *be the public parameters specified in Section5.3. There exists* *a negligible function* negl(*λ*) *such that for every λ ∈* N*, every Boolean circuit C with a gate* g *of ℓx≤ ℓ*(*λ*<u>)</u> *inputs, every masked input* x *∈{*0*,*1*}* *ℓ* *x, secret exponent s ∈D* sk*, additive shares* *(over R) ⟨s*x*⟩* 0 *, ⟨s*x*⟩* 1 *, and PRF key* sk *∈{*0*,*1*}* *λ* *, the following holds:*   pd *sampled per Equation15,*  

|z z|G z|E z|||
|---|---|---|---|---|
|||C,g|G|0 E|

*w₁* = *w₀* + *sz,* (*P* : *w₀*)*,* (*P* : *w₁, z*)  Pr      *z* = g(x) *←* BoolGateEval (*P* : pd*, ⟨s*x*⟩*)*,* (*P* : pd*, ⟨s*x*⟩*1*,*x)  *z* := *z ⊕* PRF(sk*,*OutWire(*g*))*,* x := x *⊕* PRF(sk*,*InWires(*g*))

## ≥ 1 − negl(λ).

Lemma 21(Security of BoolGateEval *C,*g under Lattices). *Under the same setting as Lemma20,* *there exists an efficient simulator* Sim *that, given the masked output z,* statistically *simulates* *PG’s message in the sub-protocol* BoolGateEval *C,*g *.*

*More precisely, there exists a negligible function* negl(*λ*) *such that for every λ ∈* N*, every*

|x||ℓ|
|---|---|---|
|0|1|λ|

*Boolean circuit C with a gate* g *of ℓ ≤ ℓ*(*λ*<u>)</u> *inputs, every masked input* x *∈ {*0*,*1*}x, secret* *exponent s ∈D*sk*, additive shares (over R) ⟨s*x*⟩, ⟨s*x*⟩, and PRF key* sk *∈{*0*,*1*}, the following* *holds:*

pd *sampled per Equation15,* SD msg

|(pd, ⟨sx⟩|),|
|---|---|
|G|0|
||1|
|0|G|

x := x *⊕* PRF(sk*,*InWires(*g*))*,* Sim(pd*, ⟨s*x*⟩,* x*, z*) *≤* negl(*λ*)*,* *z* := g(x) *⊕* PRF(sk*,*OutWire(*g*))

*where* msg*G*(pd*, ⟨s*x*⟩*) *denotes P ’s message to PEin* BoolGateEval *C,*g *.*

Using the correctness and security of the core sub-protocol, BoolGateEval under lattices, we can now prove those of our garbling scheme under lattices (compiled from the 2PC protocol BoolCircEval).

Proposition 3(Garbling of *O*(log*λ*)-ary Gates under Lattices). *Assuming CP-RLWE* *with respect to the public parameters* pp Lat *specified in Section5.3, the garbling scheme compiled* *from the protocol* BoolCircEval *C,*Lat *(Figure7) is correct and secure.*

*Proof of Proposition3.* The correctness of the protocol follows from that of BoolGateEval (Lemma20). Hence the correctness of the compiled garbling scheme follows. The security proof follows the same arguments as those for Proposition1, except the public data pd are computed and simulated differently. In the honest protocol, they are computed as follows according to Equation15, with respect to a PRF key sk *∈ {*0*,*1*}* *λ*, and the public parameters pp Lat = (*R,p,q, D*err*, D*sk) described in Section5.3.

|λ||sk|q ′|λ q|
|---|---|---|---|---|
|′ err Lat ′|′1 ′2 ′1|′′ ′′ 1 2|λ err ′′|′ ′|
||||1||
|′|′2|′′|||
|||2|||

seed *←{*0*,*1*}, s,r₁,r₂ ←D, a ←R,* a *←R,*

*e₁,e₂ ←D,* e*,* e*,* e*,* e*,* e *←D,* b := *s*a + e

pd = (pp*,*seed*,a,sa* + *e₁,s²a* + *e₂ − s∆* (16) *r₁*a + e + Bits(sk)*∆, r₁*b + e*,* *r₂*a + e*, r₂*b + e + Bits(sk)*∆*)*.*

In the simulation, they are computed as random elements:

|λ|q ′ ′|′′ ′′|λ q|
|---|---|---|---|
|Lat|′ ′ ′′|′′||

seed *←{*0*,*1*}, a,b,c ←R,* b*,* c*,* b*,* c *←R,* (17) pd f = (pp*,*seed*,a, b, c,* b c*,* b*,* c)*.*

We show the analogous claim (to Claim1) which completes the arguments for this proof.

Claim 5. *For all* sk *∈{*0*,*1*}* *λ* *, the distribution of* pd *defined by Equation16and* pd f *by Equa-* *tion17are computationally indistinguishable.*

*Proof.* We show a series of hybrid that transitions from the distribution of Equation16to Equation17.

Hyb *′* This is the distribution of Equation16.

Hyb *′* 1In this hybrid, instead of computing the aHMAC public data, together with the interme- diate value b as *a,sa* + *e₁,s²a* + *e₂ − s∆,* b := *s*a *′* + e *′*

where *a,*a *′* are random elements in *Rq*, *s* is a secret sampled from *D*sk, and *e₁,e₂,* e *′* are errors from *D*err, simulate them as random elements *a,b,c,* b from *Rq*. By CP-RLWE (Definition9), we have Hyb *′* 1*≈c*Hyb *′* 0. Hyb *′* 2In this hybrid, instead of computing the HSS public data as

*r₁*a *′* + e *′* 1+ Bits(sk)*∆, r₁*b + e *′′* 1*, r₂*a *′* + e *′* 2 *, r₂*b + e *′′* 2+ Bits(sk)*∆,*

where a*,* a *′* *,*b are random elements from *Rq*, *r₁,r₂* secrets sampled from *D*sk, and e *′* 1 *,* e *′* 2 *,* e *′′* 1*,* e *′′* 2 are errors from *D*err, simulate them as

b *′* + Bits(sk)*∆,* c *′* *,* b *′′* *,* c *′′* + Bits(sk)*∆,*

where b *′* *,* c *′* *,* b *′′* *,* c *′′* are random elements from *Rq*. By RLWE (which is implied by CP-RLWE) we have Hyb *′* 2*≈c*Hyb *′* 1. Hyb *′* 3In this hybrid, instead of adding the term Bits(*sk*)*∆* to random elements b *′* and c *′′* as above, directly compute HSS public data as random elements b *′* *,* c *′* *,* b *′′* *,* c *′′* from *Rq*. Since b *′* *,* c *′′* are random, they perfectly hide the additive factor Bits(*sk*)*∆*. We have Hyb *′* 3*≡* Hyb *′* 2. Note that Hyb *′* 3computes exactly the distribution of Equation17.

By a hybrid argument, we conclude that Hyb *′* 0*≈c*Hyb *′* 3, which proves the claim.

The Leveled Variant. The leveled 2PC protocol is shown in Figure8. It uses the same core sub- protocol LBoolGateEval *C,*g (Figure6) which stays unchanged. We summarize the correctness and security of LBoolGateEval *C,*g under lattices in the following lemmas. Their proofs are completely analogous to those of Lemma18and19, hence are omitted.

Lemma 22(Correctness of LBoolGateEval *C,*g under Lattices). *Let ℓ*(*λ*) *≤ O*(log*λ*) *be* *a bound on input length,* pp Lat *be the public parameters specified in Section5.3, and d*Ind= *O*(log log*λ*) *be the depth of the indicator arithmetic circuit over ℓ inputs (Fact1).* *There exists a negligible function* negl(*λ*) *such that for every λ ∈* N*, every Boolean circuit*

|C|||
|---|---|---|
|d ·d +1|(t)|(t)|
|sk|(t) 0|1|
|||Ind|

*C (of depth d) with a gate* g *of ℓx≤ ℓ*(*λ*) *inputs, every masked input* x *∈ {*0*,*1*}* *ℓ* *x, secret* *C* Ind *λ* *exponents* s *∈D, additive shares (over R) ⟨s* x*⟩, ⟨s* x*⟩, and PRF key* sk *∈{*0*,*1*},* *the following holds: (where we use the shorthand s* = s[*t · d*]*)*   pd *sampled per Equation18,* *z z C,*g

||(P : w₀), (P|: w₁, z) ← LBoolGateEval||
|---|---|---|---|
|z (t+1)|G G|E (t) 0|(t) 1|

 *z z* (*t*+1) *G E*  *w₁* = *w₀* + *s z,*  Pr   (*P* : pd*, ⟨s* x*⟩*)*,* (*PE*: pd*, ⟨s* x*⟩,*x)    *z* = g(x)   *z* := *z ⊕* PRF(sk*,*OutWire(*g*))*,*  x := x *⊕* PRF(sk*,*InWires(*g*)) *≥* 1 *−* negl(*λ*)*.*

Lemma 23(Security of LBoolGateEval *C,*g under Lattices). *Under the same setting as* *Lemma22, there exists an efficient simulator* Sim *that, given the masked output z,* statistically *simulates PG’s message in the sub-protocol* LBoolGateEval *C,*g *.*

Protocol LBoolCircEval *C,*Lat The protocol runs between a garbler *PG* and an evaluator *PE*, to evaluate a Boolean circuit *C* : *{*0*,*1*}* *ℓx* *→* *{*0*,*1*}* *ℓz*. It uses the following ingradients:

– public parameters pp Lat = (*R,p,q, D*err*, D*sk) specified in Section5.3; – aHMAC *leveled* evaluation procedures EvalKey *d* Ind*,*EvalTag*d*Indfor bounded depth computations by *d* Ind= *O*(log log*λ*) over bounded integers by *B* = 2, and public data generation procedure aHMAC Lat *.*pd under lattices; (See Lemma14;) – HSS evaluation procedures ExtEval₀*,*ExtEval₁ and public data generation procedure HSS Lat *.*pd under lattices; (See Lemma15;) – a PRF : *{*0*,*1*}* *λ* *×{*0*,*1*}* *λ* *→{*0*,*1*}* in NC1.

Inputs: *PG* holds a vector x *∈{*0*,*1*}* *ℓx*, while *PE* holds notinog. Outputs: *PG* outputs nothing, while *PE* outputs a vector z *∈{*0*,*1*}* *ℓz*.

– Init : Let *dC* = Depth(*C*), and *d* = *dC · d*Ind.

1. *PG* sends public data pd to the evaluator *PE*.
s *←D*sk *d*+1 *,* k *←D*sk *dC* *,* sk *←{*0*,*1*}* *λ*

// For short, write *s*

(*t*) = s[*t · d*Ind]*, s*
(end *t*) = s[(*t* + 1) *· d*Ind*−* 1]*.* *∀j ∈* [*d*]*,* aHMAC*.*pd

(*j*) *←* aHMAC
Lat *.*pd(pp Lat *,*s[*j*]*,*s[*j* + 1])*,* *∀t ∈* [*dC*]*,* aHMAC*.*pd (k*t*) *←* aHMAC Lat *.*pd(pp Lat *,s* (end *t*) *,*k[*t*])*,* (18) *∀t ∈* [*dC*]*,* HSS*.*pd (sk*t,*)s *←* HSS Lat *.*pd(pp Lat *,*k[*t*]*,*sk*∥*Bits(*s* (*t*+1) ))*,* pd := *{*aHMAC*.*pd

(*j*) *}* *j∈*[*d*]*, {*aHMAC*.*pd
(k*t*) *,*HSS*.*pd (sk*t,*)s *}* *t∈*[*dC*]*.*

2.Let *s* = s[0]. *PG* sends masked inputs x and additive shares *⟨s*x*⟩*1to *PE* as in BoolCircEval
*C,*Lat (Figure7). <u>– Eval,Final phases are the same as LBoolCircEval</u> *C,*Pai <u>(Figure5).</u>

Fig. 8. Our leveled 2PC protocol for Boolean circuits under lattices.

*More precisely, there exists a negligible function* negl(*λ*) *such that for every λ ∈* N*, every*

|with a gate g of ℓ|||, secret|
|---|---|---|---|
|d ·d +1|(t) (t)||λ|
|sk|0|1||

*Boolean circuit Cx≤ ℓ*(*λ*) *inputs, every masked input* x *∈ {*0*,*1*}* *ℓ* *x* *d* *C·d*Ind+1 (*t*) (*t*) *λ* *exponents* s *∈D, additive shares (over* Z*) ⟨s* x*⟩, ⟨s* x*⟩, and PRF key* sk *∈{*0*,*1*},* *the following holds:*

(*t*)
pd *sampled per Equation18,* SD msg*G*(pd*, ⟨s* x*⟩* 0 )*,* x := x *⊕* PRF(sk*,*InWires(*g*))*,* Sim(pd*, ⟨s*

(*t*) x*⟩* 1 *,* x*, z*) *≤* negl(*λ*)*,*
*z* := g(x) *⊕* PRF(sk*,*OutWire(*g*))

*where* msg*G*(pd*, ⟨s*

(*t*) x*⟩* 0 ) *denotes PG’s message to PEin* LBoolGateEval
*C,*g *.*

Using the correctness and security of LBoolGateEval under lattices, we can now prove those of our leveled garbling scheme under lattices (compiled from the 2PC protocol LBoolCircEval).

Proposition 4(Leveled Garbling of *O*(log*λ*)-ary Gates under Lattices). *Assuming P-* *RLWE with respect to the public parameters* pp Lat *specified in Section5.3, the garbling scheme* *compiled from the protocol* LBoolCircEval *C,*Lat *(Figure8) is correct and secure.*

*Proof of Proposition4.* The correctness of the protocol follows from that of LBoolGateEval (Lemma22). Hence the correctness of the compiled garbling scheme follows.

The security proof follows the same arguments as those for Proposition1, except the public data pd are computed and simulated differently. In the honest protocol, they are computed *λ* as follows according to Equation18, with respect to a PRF key sk *∈ {*0*,*1*}* and the public Lat parameters pp = (*R,p,q, D*err*, D*sk) described in Section5.3:

*d*+1 *dC* s *←D,* k *←D,* sk sk

(*t*) (*t*)
// For short, write *s*Ind

||= s[t · d|], s = s[(t + 1) · d||− 1].||
|---|---|---|---|---|---|
||(j) (t)|Ind end Lat Lat|Lat Lat (t)|Ind||
|C|k (t)|Lat|end|(t+1)||
|C|sk,s (j) j∈[d]|(t) k|(t) sk,s t∈[d|]||

end Ind *∀j ∈* [*d*]*,* aHMAC*.*pd *←* aHMAC*.*pd(pp*,*s[*j*]*,*s[*j* + 1])*,* (19) *∀t ∈* [*d*]*,* aHMAC*.*pd *←* aHMAC*.*pd(pp*,s,*k[*t*])*,* Lat *∀t ∈* [*d*]*,* HSS*.*pd *←* HSS*.*pd(pp*,*k[*t*]*,*sk*∥*Bits(*s*))*,*

pd := *{*aHMAC*.*pd*}, {*aHMAC*.*pd*,*HSS*.*pd*}.* *C*

In the simulation, the are computed as follows:

(*j*)
Lat Lat *∀j ∈* [*d*]*,* aHMAC*.*pd f *←* aHMAC*.*Sim(pp)*,*

(*t*)
f*′* Lat Lat *∀t ∈* [*dC*]*,* aHMAC*.*pd*, ←* aHMAC*.*Sim(pp)*,* (20)

(*t*) Lat Lat
*∀t ∈* [*dC*]*,* HSS*.*pd f *←* HSS*.*Sim(pp)*,*

(*j*) (*t*) (*t*)
f := *{*aHMAC*.*pd f*}* f*′*f*}* pd*j∈*[*d*]*, {*aHMAC*.*pd*,*HSS*.*pd*t∈*[*dC*]*,*

Lat where aHMAC*.*Sim(pp) is as follows

*λ* *a,b,c ←Rq,* seed *←{*0*,*1*}* (21) Paif = (pp*,*seed*,a,b,c*)*,* aHMAC*.*pd

Lat and HSS*.*Sim(pp) as as follows

*n*log*q*+*λ λ* a*,* b*,* c*,* d *←Rq,* seed *←{*0*,*1*}* (22) Paif = (pp*,*seed*,* a*,* b*,* c*,*d)*.* HSS*.*pd

We show an analogous claim (to Claim2) which completes the proof.

*λ*f Claim 6. *For all* sk *∈{*0*,*1*}, the distribution of* pd *defined by Equation19and* pd *by Equa-* *tion20are computationally indistinguishable.*

*Proof.* The proof is again analogous to that of Claim2, based on the following two sub-claims.

*′* Claim 7. *For all s ∈D*sk*, the following computational indistinguishability holds*

Lat Lat Lat *′* pp*,*aHMAC*.*pd(pp*,s,s*) *s ←D*sk *λ*

||n|||o||
|---|---|---|---|---|---|
||c Lat|Lat|Lat|||
|||||λ||

Lat Lat Lat *≈* pp*,*aHMAC*.*Sim(pp)

*Proof.* This follows directly from P-RLWE (Definition8).

|′||λ||||
|---|---|---|---|---|---|
|Lat|Lat|Lat||′||
||||||sk λ|
|c|Lat|Lat|Lat|||
||||λ|||

Claim 8. *For all s ∈* [*N*]*, and* sk *∈ {*0*,*1*} the following computational indistinguishability* *holds* pp*,*HSS*.*pd(pp*,s,* sk*∥*Bits(*s*)) *s ←D* n o *≈* pp*,*HSS*.*Sim(pp)*.*

*Proof.* This follows from RLWE, which is implied by P-RLWE.

5.4 Instantiations under Prime-Order Groups In this section, we instantiate the non-leveled and leveled variants of our 2PC protocols un- der prime-order groups, BoolCircEval
*C,*Pri, LBoolCircEval *C,*Pri. As explained in the begining of Section5, the protocols stay mostly unchanged, except for the Init phases, during which *PG* computes public data pd differently. We show them in Figure9and10respectively. The Non-leveled Variant. The non-leveled 2PC protocol is shown in Figure9. It uses the same core sub-protocol BoolGateEval *C,*g (Figure3) which stays unchanged. We summarize the correctness and security of BoolGateEval *C,*g under prime-order groups in the following lemmas. Their proofs are completely analogous to those of Lemma16and17, hence are omitted.

Protocol BoolCircEval *C,*Pri The protocol runs between a garbler *PG* and an evaluator *PE*, to evaluate a Boolean circuit *C* : *{*0*,*1*}* *ℓx* *→* *{*0*,*1*}* *ℓz*. It uses the following ingradients:

– aHMAC evaluation procedures, with error bound *δ* = 1*/*(poly(*λ*) *·|C|*), EvalKey*,*EvalTag over bounded integers by *B* = 2, and public data generation procedure aHMAC Pri *.*pd under prime-order groups; (See Lemma8;) – HSS evaluation procedures ExtEval₀*,*ExtEval₁ and public data generation procedure HSS EG *.*pd under ElGamal; (See Lemma10;) – a PRF : *{*0*,*1*}* *λ* *×{*0*,*1*}* *λ* *→{*0*,*1*}* in NC1.

Inputs: *PG* holds a vector x *∈{*0*,*1*}* *ℓx*, while *PE* holds notinog. Outputs: *PG* outputs nothing, while *PE* outputs a vector z *∈{*0*,*1*}* *ℓz*.

– Init :

1. *PG* sends public data pd to the evaluator *PE*.
pp = (*G,p,g*) *←* Pri*.*Gen(1 *λ* )*,* *s ←* Z*p,* s := Bits(*s*)*,* sk *←{*0*,*1*}* *λ*

pd := aHMAC Pri *.*pd(pp*,* s*,*s)*,*HSS EG *.*pd(pp*,* s*,*sk)*.* (23)

2. *PG* sends masked inputs x and additive shares *⟨*s *⊗* x*⟩*1to *PE*.
x = x *⊕* PRF(sk*,*InWires(*C*))*,* *⟨*s *⊗* x*⟩*1:= s *⊗* x + *⟨*s *⊗* x*⟩*0(over Z)*,* where *⟨*s *⊗* x*⟩*0*←* [*λ* *ω*(1)] *⌈*3 log *p⌉×ℓx* *.*

– Eval*,*Final phases are the same as BoolCircEval *C,*Pai (Figure2), except for syntactical changes from using dot products *·* when multiplying with a scalar *s* to using tensor products *⊗* when multiplying with a <u>vector s.</u>

Fig. 9. Our 2PC protocol for Boolean circuits under prime-order groups.

Lemma 24(Correctness of BoolGateEval *C,*g under Prime-Order Groups). *Let ℓ*(*λ*) *≤* *O*(log*λ*) *be a bound on input length, and δ* = 1*/*(poly(*λ*)*·|C|*) *be the error bound specified in Fig-* *ure9. There exists a negligible function* negl(*λ*) *such that for every λ ∈* N*, every Boolean circuit* *C with a gate* g *of ℓx≤ ℓ*(*λ*) *inputs, every masked input* x *∈{*0*,*1*}* *ℓ* *x,* pp = (*G,p,g*<u>)</u> *in the sup-* *port of* Pri*.*Gen(1 *λ* )*, secret exponents* s *∈{*0*,*1*}* *⌈*log *p⌉* *, additive shares (over* Z*) ⟨*s *⊗* x*⟩* 0 *, ⟨*s *⊗* x*⟩* 1 *,* *and PRF key* sk *∈{*0*,*1*}* *λ* *, the following holds:*   pd *sampled per Equation23,*  

|z z|G z|E z|||
|---|---|---|---|---|
|||C,g|G|0 E|

*w₁* = *w₀* + s*z,* (*P* : *w₀*)*,* (*P* : *w₁, z*)  Pr      *z* = g(x) *←* BoolGateEval (*P* : pd*, ⟨*s *⊗* x*⟩*)*,* (*P* : pd*, ⟨*s *⊗* x*⟩*1*,*x)  *z* := *z ⊕* PRF(sk*,*OutWire(*g*))*,* x := x *⊕* PRF(sk*,*InWires(*g*))

## ≥ 1 − δ(λ) − negl(λ).

Lemma 25(Security of BoolGateEval *C,*g under Prime-Order Groups). *Under the same* *setting as Lemma24, there exists an efficient simulator* Sim *that, given the masked output z,* statistically *simulates PG’s message in the sub-protocol* BoolGateEval *C,*g *.* *More precisely, there exists a negligible function* negl(*λ*) *such that for every λ ∈* N*, every* *Boolean circuit C with a gate* g *of ℓx≤ ℓ*(*λ*) *inputs, every masked input* x *∈ {*0*,*1*}* *ℓ* *x,* pp = (*G,p,g*) *in the support of* Pri*.*Gen(1 *λ* )*, secret exponents* s *∈{*0*,*1*}* *⌈*log *p⌉* *, additive shares (over* Z*)* *⟨*s *⊗* x*⟩* 0 *, ⟨*s *⊗* x*⟩* 1 *, and PRF key* sk *∈{*0*,*1*}* *λ* *, the following holds:*

pd *sampled per Equation23,*

|SD msg (pd, ⟨s ⊗ x⟩|),|
|---|---|
|G|0|
||1|
|G|0|

x := x *⊕* PRF(sk*,*InWires(*g*))*,* Sim(pd*, ⟨*s *⊗* x*⟩,* x*, z*) *≤* negl(*λ*) + *δ*(*λ*)*,* *z* := g(x) *⊕* PRF(sk*,*OutWire(*g*))

*where* msg (pd*, ⟨*s *⊗* x*⟩*) *denotes PG’s message to PEin* BoolGateEval *C,*g *.*

Using the correctness and security of the core sub-protocol, BoolGateEval under prime-order groups, we can now prove those of our garbling scheme under prime-order groups (compiled from the 2PC protocol BoolCircEval).

Proposition 5(Garbling *O*(log*λ*)-ary Gates under Prime-Order Groups). *Assuming* *CP-DDH in prime-order groups, the garbling scheme compiled from the protocol* BoolCircEval *C,*Pri

*(Figure9) achieves* 1*/*poly *correctness and privacy error.*

*Proof of Proposition5.* The correctness of the protocol, with an error *δ ·|C|* = 1*/*poly(*λ*) follows from that of BoolGateEval (Lemma24), and a union bound on the error probability over all gates in *C*. Hence the correctness of the compiled garbling scheme follows. The security proof follows the same arguments as those for Proposition1, except for two differences.

– In Hyb₁, which changes from following the subprotocol BoolGateEval as *PG*with (pd*, {k*

(*i*) *}*)
as inputs, into following the subprotocol as *PE*with (pd*, {l*

(*i*) *, x*
(*i*) *}*) as inputs, there is an
error probability for every gate in *C*. Therefore, the statistical distance between Hyb₁ and Hyb₀ is bounded by negl(*λ*) + *δ*(*λ*) *·|C|≤* 1*/*poly(*λ*). – The public data pd are computed and simulated differently as explained below. We need to argue the honestly computed pd and the simulated are computationally indistinguishable, which completes the argument for this proof.

In the honest protocol, the public data pd are computed as follows according to Equation23, *λ* with respect to a PRF key sk *∈{*0*,*1*}*.

*λ λ* seed *←{*0*,*1*}*

|, pp = (G,p,g) ← Pri.Gen(1|||),|
|---|---|---|---|
|p ⌈plog p⌉|′|λ p|λ p ×⌈log p⌉|
|r|rs rs +Bits(s)|||
|r s r s +Bits(sk)|Rs|Rs +Bits(sk)⊗Bits(s)||

*s ←* Z*,* r *←* Z*,* r *←* Z*,* R *←* Z*,* 2(24) pd = (pp*,*seed*,g,g,g,* *′ ′* 2 2 *g,g,g,g*)*.*

In the simulation, they are computed as random elements: *λ λ* seed *←{*0*,*1*},* pp = (*G,p,g*) *←* Pri*.*Gen(1)*,* *⌈p*log *p⌉ ′ ′ λ λ* log *p⌉* a*,* b*,* c *←* Z*p p ×⌈*(25)

|, a|, b ← Z|, A, B ← Z||,|
|---|---|---|---|---|
||a b|p c a|p ×⌈log p⌉ b A|B|

*′ ′* pd = (pp*,*seed*,g,g,g,g,g,g,g*)*.*

We show the analogous claim (to Claim1) which completes the arguments for this proof. *λ*f *by Equa-* Claim 9. *For all* sk *∈{*0*,*1*}, the distribution of* pd *defined by Equation24and* pd *tion25are computationally indistinguishable.*

*Proof.* We show a series of hybrid that transitions from the distribution of Equation24to Equation25. *′* Hyb0This is the distribution of Equation16. *′* Hyb1In this hybrid, instead of computing the last two terms of HSS public data as 2

||Rs|Rs +Bits(sk)⊗Bits(s)||
|---|---|---|---|
|′2|′1 r rs|Bits(sk)⊗(rs ′0 rs +Bits(s)|rs rs +Bits(s)|

H₁ = *g,*H₂ = *g,* 2 where R are random exponents, simulate them based on the aHMAC public data *g,g* as follows. 2 2 He₁ = *g*Bits(sk)*⊗*r*s*+R*s,* He₂ = *g*+Bits(*s*))+R*s.*

By the randomness of R, we have Hyb *≡* Hyb. Hyb In this hybrid, instead of computing the aHMAC public data as 2 *g,g,g,*

where r*,s* are random exponents, simulate them as random elements

a b c *g,g,g,*

for random exponents a*,* b*,*c. By CP-DDH in prime-order groups, (Definition7), we have *′ ′* Hyb2*≈c*Hyb1. *′* Hyb3In this hybrid, instead of computing the HSS public data as *′ ′* 2 2

||r s|r s +Bits(sk)|Bits(sk)⊗b+Rs||Bits(sk)⊗c+Rs|
|---|---|---|---|---|---|
|′|a|b +Bits(sk)|Bits(sk)⊗b+A||Bits(sk)⊗c+B|
|′|′||′3 c|′2||

*g,g,* H₁ e = *g,* H₂ e = *g.*

where r*,*R, b*,*c are random exponents, simulate them as *′ ′* *g,g* H₁ e*,* = *g,* H₂ e = *g.*

where a*,* a*,* b*,* b*,* A*,*B are exponents. By P-DDH (Definition6, which is implied by CP-DDH) in prime-order groups, we have Hyb *≈* Hyb.

Hyb *′* 4In this hybrid, remove the additive terms involving Bits(sk) from the exponents. Due to the randomness of b *′* *,* A*,*B, We have Hyb *′* 4*≡* Hyb *′* 3. Note that Hyb *′* 4computes exactly the distribution of Equation25.

By a hybrid argument, we conclude that Hyb *′* 0*≈c*Hyb *′* 4, which proves the claim.

The Leveled Variant. The leveled 2PC protocol is shown in Figure10. It uses the same core sub-protocol LBoolGateEval *C,*g (Figure6) which stays unchanged. We summarize the correctness and security of LBoolGateEval *C,*g under prime-order groups in the following lemmas. Their proofs are completely analogous to those of Lemma18and19, hence are omitted.

Protocol LBoolCircEval *C,*Pri The protocol runs between a garbler *PG* and an evaluator *PE*, to evaluate a Boolean circuit *C* : *{*0*,*1*}* *ℓx* *→* *{*0*,*1*}* *ℓz*. It uses the following ingradients:

– aHMAC *leveled* evaluation procedures, with error bound *δ* = 1*/*(poly(*λ*)*·|C|*), EvalKey *d* Ind*,*EvalTag*d*Ind for bounded depth computations by *d*Ind= *O*(log log*λ*) over bounded integers by *B* = 2, and public data generation procedure aHMAC Pri *.*pd under lattices; (See Lemma9;) – HSS evaluation procedures ExtEval₀*,*ExtEval₁ and public data generation procedure HSS BHHO *.*pd under BHHO; (See Lemma11;) – a PRF : *{*0*,*1*}* *λ* *×{*0*,*1*}* *λ* *→{*0*,*1*}* in NC1. Inputs: *PG* holds a vector x *∈{*0*,*1*}* *ℓx*, while *PE* holds notinog. Outputs: *PG* outputs nothing, while *PE* outputs a vector z *∈{*0*,*1*}* *ℓz*.

– Init : Let *dC* = Depth(*C*), and *d* = *dC · d*Ind.

1. *PG* sends public data pd to the evaluator *PE*.
pp = (*G,p,g*) *←* Pri*.*Gen(1 *λ* )*,* K *←{*0*,*1*}* *dC ×⌈*3 log *p⌉* *,* sk *←{*0*,*1*}* *λ*

S *∈{*0*,*1*}* (*d*+1)*×⌈*log *p⌉* where *sj ←* Z*p,* S[*j*] := Bits(*sj*)*,* // For short, write s

(*t*) = S[*t · d*Ind]*,* s
(end *t*) = S[(*t* + 1) *· d*Ind*−* 1]*.* *∀j ∈* [*d*]*,* aHMAC*.*pd

(*j*) *←* aHMAC
Pri *.*pd(pp*,*S[*j*]*,*S[*j* + 1])*,* *∀t ∈* [*dC*]*,* aHMAC*.*pd (k*t*) *←* aHMAC Pri *.*pd(pp*,* s (end *t*) *,*K[*t*])*,* (26) *∀t ∈* [*dC*]*,* HSS*.*pd (sk*t,*)s *←* HSS BHHO *.*pd(pp*,*K[*t*]*,*sk*∥*Bits(s (*t*+1) ))*,* pd := *{*aHMAC*.*pd

(*j*) *}* *j∈*[*d*]*, {*aHMAC*.*pd
(k*t*) *,*HSS*.*pd (sk*t,*)s *}* *t∈*[*dC*]*.*

2.Let s = S[0]. *PG* sends masked inputs x and additive shares *⟨*s *⊗* x*⟩*1to *PE* as in BoolCircEval
*C,*Pri (Figure9). – Eval*,*Final phases are the same as LBoolCircEval *C,*Pai (Figure5) except for syntactical changes from using dot products *·* when multiplying with a scalar *s* to using tensor products *⊗* when multiplying <u>with a vector s.</u>

Fig. 10. Our leveled 2PC protocol for Boolean circuits under prime-order groups.

Lemma 26(Correctness of LBoolGateEval *C,*g under Prime-Order Groups). *Let ℓ*(*λ*) *≤* *O*(log*λ*) *be a bound on input length, δ* = 1*/*(poly(*λ*)*·|C|*) *be the error bound specified in Figure10,* *and d*Ind= *O*(log log*λ*) *be the depth of the indicator arithmetic circuit over ℓ inputs (Fact1).* *There exists a negligible function* negl(*λ*) *such that for every λ ∈* <u>N</u>*, every Boolean circuit C* *(of depth dC) with a gate* g *of ℓx≤ ℓ*(*λ*) *inputs, every masked input* x *∈{,}* *ℓ* *x,* pp = (*G,p,g*) *in the support of* Pri*.*Gen(1 *λ* )*, secret exponents* S *∈{,}* (*d*+1)*×⌈*log *p⌉* *, additive shares (over* Z*)*

*⟨*s

(*t*) *⊗* x*⟩* 0 *, ⟨*s
(*t*) *⊗* x*⟩* 1 *, and PRF key* sk *∈{*0*,*1*}*
*λ* *, the following holds:*   pd *sampled per Equation26,* *z z C,*g

||(P : w₀), (P|: w₁, z) ← LBoolGateEval||||
|---|---|---|---|---|---|
|z (t+1)|G G|E (t)|0|(t)|1|

 *z z* (*t*+1) *G E*  w₁ = w₀ + s *z,*  Pr   (*P* : pd*, ⟨*s *⊗* x*⟩*)*,* (*PE*: pd*, ⟨*s *⊗* x*⟩,*x)    *z* = g(x)   *z* := *z ⊕* PRF(sk*,*OutWire(*g*))*,*  x := x *⊕* PRF(sk*,*InWires(*g*)) *≥* 1 *− δ*(*λ*) *−* negl(*λ*)*.*

Lemma 27(Security of LBoolGateEval *C,*g under Prime-Order Groups). *Under the same* *setting as Lemma26, there exists an efficient simulator* Sim *that, given the masked output z,* statistically *simulates PG’s message in the sub-protocol* LBoolGateEval *C,*g *.* *More precisely, there exists a negligible function* negl(*λ*) *such that for every λ ∈* N*, every* *Boolean circuit C with a gate* g *of ℓx≤ ℓ*(*λ*) *inputs, every masked input* x *∈ {*0*,*1*}* *ℓ* *x,* pp = (*G,p,g*) *in the support of* Pri*.*Gen(1 *λ* )*, secret exponents* S *∈ {*0*,*1*}* (*d*+1)*×⌈*log *p⌉* *, additive shares* *(over* Z*) ⟨*s

(*t*)

|⊗ x⟩|, ⟨s ⊗ x⟩|, and PRF key sk ∈{0, 1}||, the following holds:|||
|---|---|---|---|---|---|---|
||0|1|||||
||(t)||||||
|G||0|||||
||(t)||||||
|||1|||||
|G|(t)|0|G|E||C,g|
 0
(*t*) 1
*λ*

pd *sampled per Equation26,* SD msg (pd*, ⟨*s *⊗* x*⟩*)*,* x := x *⊕* PRF(sk*,*InWires(*g*))*,* Sim(pd*, ⟨*s *⊗* x*⟩,* x*, z*) *≤* negl(*λ*) + *δ*(*λ*)*,* *z* := g(x) *⊕* PRF(sk*,*OutWire(*g*))

*where* msg (pd*, ⟨*s *⊗* x*⟩*) *denotes P ’s message to P in* LBoolGateEval*.*

Using the correctness and security of LBoolGateEval under prime-order groups, we can now prove those of our leveled garbling scheme under prime-order groups (compiled from the 2PC protocol LBoolCircEval).

Proposition 6(Leveled Garbling of *O*(log*λ*)-ary Gates under Prime-Order Groups). *Assuming P-DDH in prime-order groups, the garbling scheme compiled from the protocol* LBoolCircEval *C,*Pri

*(Figure10) achieves* 1*/*poly *correctness and privacy error.*

*Proof of Proposition6.* The correctness of the protocol follows from that of LBoolGateEval (Lemma26). Hence the correctness of the compiled garbling scheme follows. The security proof follows the same arguments as those for Proposition1, except the public data pd are computed and simulated differently. In the honest protocol, they are computed as follows according to Equation26, with respect to a PRF key sk *∈{*0*,*1*}* *λ* :

pp = (*G,p,g*) *←* Pri*.*Gen(1 *λ* )*,*

## S ∈{0,1}j

||where s|← Z, S[j] := Bits(s|),|||
|---|---|---|---|---|---|
|(d+1)×⌈log p⌉||p|j|||
|d ×⌈3 log p⌉|(t) (j) (t)|λ (t) Ind end Pri Pri|Pri Pri (t)|Ind||
|C|k (t)|BHHO|end Lat||(t+1)|
|C|sk,s (j) j∈[d]|(t) k|(t) sk,s t∈[d|]||

K *←{*0*,*1*}* *C* *,* sk *←{*0*,*1*}*

// For short, write s = S[*t · d*]*,* s = S[(*t* + 1) *· d −* 1]*.* (27) *∀j ∈* [*d*]*,* aHMAC*.*pd *←* aHMAC*.*pd(pp*,*S[*j*]*,*S[*j* + 1])*,*

*∀t ∈* [*d*]*,* aHMAC*.*pd *←* aHMAC*.*pd(pp*,* s*,*K[*t*])*,*

*∀t ∈* [*d*]*,* HSS*.*pd *←* HSS*.*pd(pp*,*K[*t*]*,*sk*∥*Bits(s))*,*

pd := *{*aHMAC*.*pd*}, {*aHMAC*.*pd*,*HSS*.*pd*}* *C* *.*

In the simulation, the are computed as follows:

*λ* pp = (*G,p,g*) *←* Pri*.*Gen(1)*,*

||(j)|Pri|⌈log p⌉||
|---|---|---|---|---|
|C C ℓ|′(t) (t) j∈[d] ℓp Pai|Pri BHHO ′(t) λ a b|⌈3 log p⌉ Lat (t) t∈[d c|]|
|⌈qlog q⌉+λ|(q⌈log q⌉+λ)×⌈3 log p⌉|||λ|
|BHHO|a b|D|||

*∀j ∈* [*d*]*,* aHMAC*.*pd f *←* aHMAC*.*Sim(pp*,*1)*,*

f *∀t ∈* [*d*]*,* aHMAC*.*pd*, ←* aHMAC*.*Sim(pp*,*1)*,* (28)

*∀t ∈* [*d*]*,* HSS*.*pd f *←* HSS*.*Sim(pp)*,*

(*j*)
f := *{*aHMAC*.*pd f*}, {*aHMAC*.*pdf*,*HSS*.*pd f*}* pd*,* *C*

Pri where aHMAC*.*Sim(pp*,*1) is as follows

a*,* b*,* c *←* Z*,* seed *←{*0*,*1*}* (29) aHMAC*.*pd f = (pp*,*seed*,g,g,g*)*,*

BHHO and HSS*.*Sim(pp) as as follows

a*,* b*, ←* Z*,* C*,* D *←* Z*,* seed *←{*0*,*1*}* (30) C HSS*.*pd f = (pp*,*seed*,g,g,g,g*)*.*

We show an analogous claim (to Claim2) which completes the proof.

*λ* Claim 10. *For all* sk *∈{*0*,*1*}, the distribution of* pd *defined by Equation27and* pd f *by Equa-* *tion28are computationally indistinguishable.*

*Proof.* The proof is again analogous to that of Claim2, based on the following two sub-claims. *′ ℓ* Claim 11. *For all* s *∈{*0*,*1*}, with ℓ ≤* poly(*λ*) *the following computational indistinguishability* *holds* Pri *′*

|pp, aHMAC||.pd(pp, s, s|s ← Z )|, s := Bits(s)||
|---|---|---|---|---|---|
|||||p|λ|
|c||Pri|ℓ|||
|||||λ||
||||||λ|

*p* *λ* n o *≈* pp*,*aHMAC*.*Sim(pp*,*1)

*where the public parameter* pp *is sampled as* pp = (*G,p,g*) *←* Pri*.*Gen(1) *in both sides.*

*Proof.* This follows from P-DDH (Definition6) and DDH (Definition5, which is implied by P-DDH) in prime-order groups.

*′ ℓ λ* Claim 12. *For all* s *∈{*0*,*1*}, with ℓ ≤* poly(*λ*) *and* sk *∈{*0*,*1*} the following computational* *indistinguishability holds*

BHHO *′* pp*,*HSS*.*pd(pp*,s,* sk*∥*Bits(*s*)) *s ←D*sk *λ* n o BHHO *ℓ* *≈c*pp*,*HSS*.*Sim(pp*,*1)*.* *λ*

*λ* *where the public parameter* pp *is sampled as* pp = (*G,p,g*) *←* Pri*.*Gen(1) *in both sides.*

*Proof.* This follows from the security of the BHHO [BHHO08] encryption scheme, which is based on DDH (Definition5) in prime-order groups.

5.5 Security Amplification for Prime-Order Group Instantiations. In this section, we show how to adapt the amplification techniques from [BGI17] to remove the 1*/*poly privacy and correctness errors of our garbling scheme under prime-order groups. For simplicity, we focus on the non-leveled variant in this section. The leveled variant can be amplified in the analogous way. The Reason For the Errors. The the 1*/*poly privacy and correctness errors of our garbling scheme both come from the 1*/*poly correctness errors in the aHMAC and HSS constructions under prime-order groups. While it’s clear correctness of our garbling scheme depends on those of aHMAC and HSS, it’s less obvious how privacy depends on those. We briefly review our proof strategy (see the proof of Proposition5) to illustrate the cause of this error. The relevant step in our proof consists the following hybrid experiments for computing the garbled circuits *C*b, and labels *{L*
(*i*) *}*.
Hyb₀ :This is the real world distribution. – First sample a global secret s and a PRF key sk. Compute public data pd w.r.t. seed*,* s*,*sk following Equation23. – Next sample a random pad k

(*i*) for every input wire *i* in *C*, and compute the labels *L*
(*i*)
as *L*

(*i*) = s *·* (x[*i*] *⊕* PRF(sk*,i*)) + k
(*i*), where x is the input.
– For every gate g in *C*, in topological order, run aHMAC and HSS (as *PG*described in Figure3) evaluations over *{*k

(*i*) *}*, for input wires *i* to g. The results are a pad k
(*j*) and
an integer *r*

(*j*). Set *b*
(*j*) = *r*
(*j*) mod 2.
– In the end, compute o = PRF(sk*,*OutWires(*C*)) and set *C*b = (pd*, {b*

(*j*) *},* o).
Hyb₁ :In this hybrid, compute the bits *{b*

(*j*) *}* differently.
– For every output wire *j* of some gate g *∈ C*, compute the correct wire value *x*

(*j*) according
to the input x. Then set *x*

(*j*) = *x*
(*j*) *⊕* PRF(sk*,j*).
– For every gate g in *C*, in topological order, run aHMAC and HSS (as *PE*described in Figure3) evaluations over *{L*

(*i*) *,x*
(*i*) *}*, for the input wires *i* to g. The results are a label
*L*

(*j*) and an integer *u*
(*j*). Set the bit *b*
(*j*) = *x*
(*j*) + *u*
(*j*) mod 2.
If there are no error in the aHMAC and HSS evaluations, then we have *L*

(*j*) = s *· x*
(*j*) + k
(*j*), and
*u*

(*j*) = *x*
(*j*) + *r*
(*j*) for every output wire *j* of some gate g *∈ C*. Hence conditioned on no error
occurs, Hyb₀*,*Hyb₁ compute the same distribution. In our construction (Figure9) we set the error chance of each aHMAC and HSS evaluation to be *≤* 1*/*(poly(*λ*)*|C|*). Hence by a union bound, no error occurs except with 1*/*poly chance, creating a 1*/*poly statistical distance between Hyb₀ and Hyb₁. Removing the Correctness Error. The correctness errors from both aHMAC and HSS evalua- tions stem from the following distributed discrete logarithm (DDLog) technique, which underlies their constructions (Lemma8and10). In particular, the following DDLog evaluation is invoked for every intermediate multiplication within aHMAC and HSS.

Lemma 28(Distributed Discrete Log with Error [BGI16,DKK18]). *For any cyclic* *group G with order p and a generator g, there exists an algorithm* DDLog*G,g:*

– DDLog*G,g*(*δ ∈* (0*,*1]*,B ∈* [*p*]*,ϕ* : *G → {*0*,*1*}* *⌈*log(2*B/δ*)*⌉* *,a ∈ G*) *takes an error bound δ, a* *message bound B, a function ϕ mapping group elements to bit strings, and an element a. It* *outputs a value α ∈* Z*p.*

p *The algorithm requires O*( *B/δ*) *group operations, and has the guarantee that for all* 0 *< δ ≤* 1*,* *B < p, a ∈ G, and m ≤ B:* " # DDLog*G,g*(*δ,B,ϕ,a · g* *m* ) Pr *ϕ ←* $ *≥* 1 *− δ,* =DDLog*G,g*(*δ,B,ϕ,a*) + *m* mod *p*

*where ϕ ←* $ *means sampling at random from all possible mappings.*

The DDLog algorithm is setup with a sufficiently small error bound *δ* such that the overall error probability (through a union bound) of all aHMAC and HSS multiplications is bounded by 1*/*poly. A (pseudo-)random mapping function *ϕ* used for DDLog is specified by the public PRG seed included in the public data pd of aHMAC and HSS. To remove the correctness error, we follow the observation from [BGI17] that when two parties locally run DDLog on two elements *a,a · g* *m*, one of the party, which we call the left party, can actually detect potential errors as long as there is a bound *B* on the value *m*:

– The left party aborts with probability *≤ δ* over the randomness of *ϕ*; – When the left party doesn’t abort, both parties output the correct results except with neg- ligible probability.

Armed with this detection technique, we can remove the correctness error from our grabling scheme: when the garbler – who acts as the left party in DDLog – aborts, it restarts with fresh randomness. By setting the error probability *δ* in each DDLog invocation to be sufficiently small, *≤* 1*/*(poly(*λ*)*·|C|*), the garbler only restarts with 1*/*poly(*λ*) probability. In expectation, it takes a constant number of restarts before the garbler produces a garbled circuit that’s guaranteed to be correct. Removing the Privacy Error. While restarting removes the 1*/*poly correctness error, there is still a 1*/*poly privacy error in the resulting scheme. Looking again at the two hybrids Hyb₀*,*Hyb₁ in our proof strategy, it may seem with restarting we have ensured no error occurs during all aHMAC and HSS evaluations, and have removed the 1*/*poly statistical difference between Hyb₀ and Hyb₁. However, the subtle issue is that in Hyb₀, the experiment runs DDLog as the left party to detect errors and restarts, while in Hyb₁ the experiment runs DDLog as the right party, who does not have the same restarting pattern. To simulate the restarting pattern of Hyb₀, our first step is to use another observation from [BGI17]: the right party running DDLog can actually predict potential abort from the left party with possibly false positives:

– The right party can additionally output a bit pred, which equals 1 with probability *≤* 2*δ* over the randomness of *ϕ*; – When pred = 0, the left party does not abort.

Armed with this prediction technique, in Hyb₁, the experiment can proceed as the right party running DDLog as long as pred = 0. However, when the experiment sees pred = 1 during some DDLog invocation, it then needs to re-run this particular DDLog as the left party to check if there needs to be a restart (as pred = 1 may be a false positive). As we explain next, re-running the DDLog as the left party relies on some leakages on the global secret *s* and the PRF key sk. We then show how to deal with those leakages by adapting techniques from [BGI17].

Leakages in aHMAC and HSS. In order to explain the leakage, we now expose a bit more detail on how the left and right parties, which correspond to *PG*and *PE*respectively in Figure3, run DDLog within aHMAC and HSS evaluations.

– aHMAC evaluations are over input shares *⟨*s *⊗* x*⟩*, where s is the global secret. The results are output shares *⟨*s *· C*v(x)*⟩*, where *C*vis an arithmetic circuit with intermediate values bounded by *B* = 2. The right party additionally holds x in the clear. In each invocation of DDLog, the left and right parties respectively hold inputs of the form *a,a · g* s[*i*]*·v* : Left : DDLog(*δ,ϕ,B,a*)*,*

Right : DDLog(*δ,ϕ,B,a · g* s[*i*]*·v* )*,*

where *v* is an intermediate wire value of *C*v(x). When the right party predicts a potential abort and needs to re-run DDLog as the left party, it needs to know both s[*i*] and *v*. As all intermediate wire values *v* are known to the right party in the clear, the only leakage required is a certain bit s[*i*] from the global secret. – HSS evaluations are over input shares *⟨*s *⊗* x*⟩*, and *⟨*x*⟩*. The results are output shares *{⟨*s *·* InnerPord(x*,C*g(sk))*⟩}*, where *C*gis a Boolean circuit (implementable by an arithmetic circuit with *B* = 2), and sk is the global PRF key. The right party additionally holds x in the clear. In each invocation of DDLog, the left and right parties respectively hold inputs of the form *a,a · g* s[*i*]*·*x[*j*]*·v* : Left : DDLog(*δ,ϕ,B* = 2*,a*)*,*

Right : DDLog(*δ,ϕ,B* = 2*,a · g* s[*i*]*·*x[*j*]*·v* )*,*

where *v* is an intermediate wire value of *C*g(sk). When the right party predicts a potential abort and needs to re-run DDLog as the left party, it needs to know s[*i*], x[*j*], and *v*. As x is known to the right party in the clear, the leakage required is a certain bit s[*i*] from the global secret, and an intermediate wire value *v* from *C*g(sk).

In summary, the Hyb₁ experiment proceeds as the righ party running DDLog in aHMAC and HSS evaluations, as long as pred = 0. In the case pred = 1, it relies on the following leakage to re-run the DDLog as the left party.

– If the DDLog is within an aHMAC evaluation, the leakage is a bit s[*i*] from the global secret

s.
– If the DDLog is within an HSS evaluation, the leakage is a bit s[*i*] and an intermediate wire value *v* in *C*g(sk).

If the re-run as the left party indeed aborts, then Hyb₁ restarts with fresh randomness, and all the leakages have no effect. However if the re-run does not abort, (i.e. pred = 1 is a false positive), then Hyb₁ continues as the right party. This restarting pattern exactly simulates that of Hyb₀, so we have Hyb₀ *≡* Hyb₁. Note that as pred = 1 happens independently in each DDLog invocation with *≤* 2*δ ≤* 1*/*(poly(*λ*)*·|C|*) probability, in an eventual accepting Hyb₁ experiment with no aborts, there are at most some *ω*(1) *≤ λ* instances of leakages except with negligible probability. In conclusion, the overall leakage in Hyb₁ are (1) *≤ λ* bits from the global secret s and (2) *≤ λ* intermediate values in the circuit *C*g(sk).

Removing the Leakages. We explain the solutions to each leakage type in more detail. They are adapted from the techniques introduced in [BGI17] for dealing with similar types leakages.

1.The global secret s *∈{*0*,*1*}*
*⌈*log *p⌉* in our garbling scheme is sampled as follows, per Equa- tion23: *s ←* Z*p,* s := Bits(*s*)*.*

Our security proof (of Proposition5) relies on the *s* being a random exponent and the CP- DDH assumption (Definition7) to argue that the public data pd leaks nothing about the PRF key sk. With *≤ λ* bits of leakage from s, the secret exponent *s* is no longer random. Our solution is to create *λ*+1 additive shares of *s*, and define s to be the bits of all *λ*+1 shares. Any *≤ λ* bits leaked from s are now statistically independent of the secret exponent *s*, which remains random. In more detail, we modify Equation23and correspondingly aHMAC Pri *.*pd, HSS EG *.*pd as follows:

Modified Equation23: X
*∀i ∈* [*λ* + 1]*, si←* Z*p, s* := *si*mod *p,* s := (*... ∥*Bits(*si*)*∥...*)*.*
*i* Modified aHMAC Pri *.*pd*,*HSS EG *.*pd : X
parse s = (*... ∥*s*i∥...*)*, s* := BitComp(s*i*) mod *p.*
*i*

Now our proof argument of pd computed using the modified Equation23goes through, under a slight variant of the CP-DDH assumption that incorporates the extra secret sharing steps. (In the leveled variants, the P-DDH assumption unmodified suffices.)

Definition 11(CP-DDH* Over Prime-Order Groups). *We say CP-DDH* holds in* *prime-order groups if the following holds:*  *λ*    pp = (*G,p,g*) *←* Pri*.*Gen(1 )*,*   2 

| |||||X|
|---|---|---|---|---|---|
||λ|s s|0 1|λ p|i|
|a s·a|s ·a+(...∥Bits(s|)∥...)|⌈plog p⌉·(λ+1)||i|
||λ|s d|||λ|
|c a b|c||λ ⌈plog p⌉|p||
||||||λ|

 pp*,s₁,...,s,g,g ,g,* *s ,s ,...,s ←* Z*, s* := *s* mod *p*  *g,g,g* 2 *i*       a *←* Z *λ*     pp = (*G,p,g*) *←* Pri*.*Gen(1 )*,*   pp*,s₁,...,s,g,g ,g ,* *≈ s,s₁,...,s,d ←* Z*,.*  *g,g,g*   a*,*b*,* c *←* Z*.*

*Remark 5.* This formulation can be further simplified to

|(||||||)|
|---|---|---|---|---|---|---|
|′|s s|||||λ|
|a s·a|s ·a+Bits(s+s|mod p)|′|p|⌈log p⌉ p|λ|
|′|s d|||λ|||
|a b|c|′|p|⌈log p⌉ p|λ||

2 pp*,s,g,g,g,* pp = (*G,p,g*) *←* Pri*.*Gen(1)*,* 2 *′* *g,g,g s,s ←* Z*,* a *←* Z () (31) pp*,s,g,g,g,* pp = (*G,p,g*) *←* Pri*.*Gen(1)*,* *≈c.* *g,g,g s,s ,d ←* Z*,* a*,* b*,* c *←* Z*.*

We sketch this through the following hybrid arguments:

Hyb *′* 0This is the left-hand-side distribution from the CP-DDH* assumption, in a slightly more convenient form:

pp = (*G,p,g*) *←* Pri*.*Gen(1 *λ* )*,* *s s*2X pp*,s₁,...,sλ,g,g,g,* *s ,s ,...,s ←* Z*, s* := *s* mod *p* 0 1 *λ p i* a *is·*a*is* 2 *·*a*i*+Bits(*si*) *{g,g,g}i*=0*,*1*,...,λ.i* a*i←* Z *⌈p*log *p⌉*

*′ ′* P *′* Hyb₁ Equivalently sample *s ←* Z*p*and set *s* := *i>*0 *si*mod *p*, and *s₀* := *s − s* mod *p*. The distribution is:

*s s*2 pp*,s₁,...,sλ,g,g,g,* a 0*s·*a0*s* 2 *·*a0+Bits(*s−s′*mod *p*) a*is·*a*is*2*·*a*i*+Bits(*si*) *g,g,g, {g,g,g}i*=1*,...,λ.*

We have Hyb *′* 0*≡* Hyb *′* 1. *′ s*2*s·*a0*s*2*·*a0+Bits(*s−s′*mod *p*) *d* b0c0 Hyb₂ Replace the terms *g,g*, *g*, with *g,g,g* for random expo- nents *d,* b₀*,*c₀: pp*,s₁,...,sλ,g,g* *s* *,g* *d* *,*

*g* a 0 *,g* b0 *,g* c 0 *, {g* a *i* *,g* *s·*a*i* *,g* *d·*a*i*+Bits(*si*) *}i*=1*,...,λ.*

By the simplied assumption in Equation31, we have Hyb *′* 2*≈c*Hyb *′* 1. Hyb *′* 3Replace the terms *g* *s·*a*i* and *g* *d·*a*i* with *g* b*i* *,g* c *i*for random exponents b *i* *,* c*i*:

pp*,s₁,...,sλ,g,g* *s* *,g* *d* *,*

*g* a 0 *,g* b0 *,g* c 0 *, {g* a *i* *,g* b*i* *,g* c *i* +Bits(*si*) *}i*=1*,...,λ.*

By DDH (which is implied by Equation31), we have Hyb *′* 3*≈c*Hyb *′* 2. Hyb *′* 4Remove the additive terms Bits(*si*) from the exponents. By the randomness of exponents c*i*, we have Hyb *′* 4*≡* Hyb *′* 3. Note that the resulting is exactly the right-hand-side distribution from the CP-DDH* assumption.

2.To deal with the second leakage type, we need to ensure the leaked intermediate values from *C*g(sk), for all gates g *∈ C*, are independent of the PRF key sk<u>.</u> The solution is to replace *C*gwith a leakage resilient circuit *C*gsuch that any set of *≤ λ* intermediate values can be computationally simulated from the evaluation result only. We cite the result from [BGI17] that there exists a compiler from any NC1 Boolean circuit *C*<u>g</u> to a leakage resilient one *C*galso in NC1, together with a compiler for the inputs sk to sk such that *C*g(sk) = *C*g(sk). Lemma 29(Leakage Resilient Circuits for NC1 [BGI17]). *Assuming there is a PRF* *in NC1. There exists a pair of compilers* LR
Circ LR Input *satisfy the following.* *Correctness: For every logarithmic depth bound d ≤ O*(log*λ*)*, there exists another logarith-* *mic bound d* *′* *≤ O*(log*λ*)*, and a polynomial p ≤* poly(*λ*) *such that for every λ ∈* N*, Boolean* *circuit C* : *{*0*,*1*}* *ℓ* *x→{*0*,*1*} of depth ≤ d*(*λ*)*, and inputs* x *∈{*0*,*1*}ℓx:* – <u>C</u> *←* LR Circ

(*C*) *has depth ≤ d*
*′*

(*λ*)*;*
– x *←* LR Input

(x) *has bit-length ≤ ℓx· p*(*λ*)*;*
– *C*(x) = *C*(x)*.*

*Leakage Resilience: There exists a simulator* Sim *such that for every logarithmic depth* *bound d ≤ O*(log*λ*)*, Boolean circuits {Cλ} of depth ≤ d*(*λ*)*, inputs {*x*λ}, and sets of leakage* *wires {Sλ} of size ≤ λ:* ()

|Circ|||
|---|---|---|
|Input|c|λ|
||λ||

*Wire values C ←* LR (*C*)*,* *≈ {*Sim(*C*(x))*}* *in S of C*(x) x *←* LR (x)*,*

Now we just need to modify Equation23to compile the sampled PRF key sk into leakage resilient inputs sk, and correspondingly modify Figure3to use leakage relient circuits in HSS evaluations:

Modified Equation23: sk *←{*0*,*1*}* *λ* *,* sk *←* LR Input (sk)

Modified Figure3Step 2 : run ExtEval*b*with *C*g*←* LR Circ

(*C*)*.*
After applying the two solutions, we can now conclude that in Hyb₁ the leakages (required to simulating restarting patterns of Hyb₀) do not affect the remaining proof arguments. The overhead of our solutions for removing leakages are (1) larger public data pd caused by a larger global secret vector s and a larger leakage resilient version of the PRF key sk and (2) heavier computation in HSS evaluations caused by the leakage resilient circuits *C*g.

## 6 Efficient Arithmetic Garbling Schemes

Our observation is that the Boolean garbling schemes from Theorem2(and their leveled vari- ants), supporting evaluations of arbitrary *O*(log*λ*)-ary gates, can implement arithmetics over small modulus *R*(*λ*) *≤* poly(*λ*) very efficeintly. This is because multiplications and additions between two Z*R*values can be implemented by (2 log*R*)-ary Boolean gates, costing log*R* bits per multiplication or addition. A small issue prevents directly using Theorem2to obtain arithmetic garbling schemes for small modulus. An arithmetic garbling scheme requires arithmetic labels for its inputs x *∈* Z *ℓR* *x*, while the schemes from Theorem2require Boolean labels for the bit representations Bits(x). Therefore, to obtain arithmetic garbling over polynomial modulus *R*(*λ*) *<* poly(*λ*), we need a special garbling scheme in which the evaluation algorithm Eval takes in arithmetic labels for some input x *∈* Z *ℓR* *x*, and outputs Boolean labels for their bit-representations Bits(x), as required by the scheme from Theorem2. Fortunately, such schemes exist based on Chinese Remainder Theorem and the minimal assumption of one-way functions. (See Section 8 in [AIK11], and also [LL24,Hea24] for more efficient constructions based on stronger assumptions.)

Lemma 30(Bit-Decomposition Garbling Scheme [AIK11]). *Assuming one-way func-* *tions exist, there exists a garbling scheme for the class of functions C* : Z*R→{*0*,*1*}* *⌈*log *R⌉×ℓ* 13 *specified by any modulus R, and any set of Boolean key functions K*

(*i*) : *{*0*,*1*} → {*0*,*1*}*
*ℓ* *for* *i ∈* [*⌈*log *R⌉*]*:* *C*(*x*) = *{K*

(*i*) (Bits(*x*)[*i*])*}.*
## The garbling size is poly(log R,ℓ,λ).

Technically we are generalizing Definition1to allow functions with different input and output rings: Z*R* and Z₂.

Composing a bit-decomposition garbling scheme with Theorem2results in an arithmetic garbling scheme satisfying Definition1, and creates only an additive cost of *|*x*|·* poly(*λ*) to the garbling size. We therefore obtain the following corollary.

Corollary 5(Arithmetic Garbling for Small Modulus). *Let R*(*λ*) *≤* poly(*λ*) *be a modulus.* *Assuming any of the assumptions in Theorem2, there exists a garbling scheme for all arithmetic* *circuits C (with binary gates, ℓxinputs) over* Z*Rwith garbling size*

## |Cb|≤|C|· logR + ℓx· poly(λ).

*The scheme assuming CP-DDH in prime-order groups has* 1*/*poly correctness and privacy errors*,* *which can be made negligible assuming a variant of CP-DDH (Definition11).* *Alternatively, assuming any of the assumptions in Theorem3, there exists a garbling scheme* *for all arithmetic circuits C (with binary gates, ℓxinputs) over* Z*Rwith garbling size*

*|C*b*|≤|C|·* log*R* + (*ℓx*+ Depth(*C*)) *·* poly(*λ*)*.*

Using Chinese Remainder Theorem, we can further compose multiple schemes, supporting co- *∗* Q prime polynomial moduli *{Ri}*, into one supporting a large modulus *R* = *i* *Ri*. We additionally show how to emulate an arbitrary modulus *R* using a sufficiently large one *R* *∗* = *O*(*R²*) in Section6.1(protocol ArithCircEval *C*, Figure2). We show its instantiation under Paillier groups to illustrate our techniques. Other instantiations under prime-order groups and lattices differ only by how the public data are generated during the Init phase, analogous to the Boolean case. In summary, we obtain the following result.

Theorem 4(Arithmetic Garbling for Large Modulus). *Assuming any of the assumptions* *in Theorem2, there exists a garbling scheme for all arithmetic circuits C (with binary gates, ℓx* *inputs) over an arbitrary modulus* Z*Rwith garbling size*

*|C*b*|≤ O*(*|C|·* log*R*) + *ℓx·* poly(*λ,* log*R*)*.*

*The scheme assuming CP-DDH in prime-order groups has* 1*/*poly correctness and privacy errors*,* *which can be made negligible assuming a variant of CP-DDH (Definition11).*

We can also obtain leveled variants analogous to the Boolean case to avoid circular assump- tions at the cost of an additive Depth(*C*) *·* poly(*λ,* log*R*) term in the size of the garbling.

Theorem 5(Leveled Arithmetic Garbling for Large Modulus). *Assuming any of the* *assumptions in Theorem3, there exists a garbling scheme for all arithmetic circuits C (with* *binary gates, ℓxinputs) over an arbitrary modulus* Z*Rwith garbling size*

*|C*b*|≤ O*(*|C|·* log*R*) + (*ℓx*+ Depth(*C*)) *·* poly(*λ,* log*R*)*.*

Note that we cannot use the schemes from Theorem2(and their leveled variants) to support general arithmetic gates with *ℓx*= *ω*(1) inputs over polynomial modulus *R*(*λ*) *<* poly(*λ*), as their computation cost would become super-polynomial *R* *ℓ* *x*= *λω*(1). Therefore, we *do not* directly obtain analogous (to Theorem2and4) arithmetic garbling schemes for layered circuits.

Protocol ArithCircEval *C,*Pai The protocol runs between a garbler *PG* and an evaluator *PE*, to evaluate an crithmetic circuit over Z*R*, *C* : Z *ℓ* *Rx→* Z *ℓ* *Rz*. It uses the same ingradients as BoolCircEval *C,*Pai (Figure1), except with a different PRF:

– a PRF : *{*0*,*1*}* *λ* *×{*0*,*1*}* *λ* *→* [*R² · λ* *ω*(1)] in NC1.

Inputs: *PG* holds a vector x *∈* Z *ℓ* *Rx*, while *PE* holds notinog. Outputs: *PG* outputs nothing, while *PE* outputs a vector z *∈* Z *ℓ* *Rz*. – Init : *PG* sends public data pd to *PE* computed in the same way as BoolCircEval *C,*Pai (Figure1). Then *PG* sends masked inputs x and additive shares *⟨s*Bits(x)*⟩*1to *PE*.

x[*i*] = x[*i*] + *r*

(*i*) mod *R, ⟨s*Bits(x)*⟩* := *s*Bits(x) + *⟨s*Bits(x)*⟩*0over Z*,*
where *r*

(*i*) *←* PRF(sk*,*InWires(*C*)[*i*])*, ⟨s*Bits(x)*⟩*0*←* [*Nλ*
*ω*(1)] *ℓx ·⌈*log *R⌉* *.*

– Eval : *PG,PE* evaluate gates g *∈ C* in the topological order while maintaining the following invariant:

1. *PG,PE* jointly hold additive shares *⟨s*Bits(xg)*⟩*, where xg are masked input wire values to the gate g
xg[*i*] = xg[*i*] + *r*

(*i*) mod *R* where *r*
(*i*) *←* PRF(sk*,*InWires(g)[*i*])*.* (32)
2. *PE* holds the masked wire values xg. To evaluate the gate g, *PG,PE* jointly call the sub-protocol ArithGateEval. (*PG* : *⟨s*Bits(*z*g)*⟩*0)*,* (*PE* : *⟨s*Bits(*z*g*⟩*1*, z*g))
*←* ArithGateEval *C,*g (*PG* : pd*, ⟨s*Bits(xg)*⟩*0)*,* (*PE* : pd*, ⟨s*Bits(xg)*⟩*1*,* xg)

– Final : *PG* sends masks PRF(sk*,*OutWire(g)) mod *R* on all output gates g *∈ C* to *PE*, who can then <u>recovers the output z by removing the masks modR.</u>

Fig. 11. 2PC protocol for Arithmetic circuits with large modulus.

6.1 Handling Large *R* using Chinese Remainder Theorem The overall protocol ArithCircEval
*C,*Pai (under Paillier groups) is shown in Figure2. It’s mostly the same as the Boolean protocol BoolCircEval *C,*Pai except how wire values are masked.

– In the Boolean protocol, each wire value (on wire *i*) is masked by a single bit derived by PRF(sk*,i*). – In the arithmetic protocol, each wire value (on wire *i*) is masked by an integer mod *R* derived by PRF(sk*,i*).

The wire values are always represented as bits. In particular, the input shares during the Init phases are defined as additive shares of bit representations of the masked inputs. We can still compile such a protocol to an arithmetic garbling scheme with arithmetic input labels, relying on existing techniques [AIK11,LL24,Hea24] as explained in Section6. As in the Boolean case, we rely on a core sub-protocol ArithGateEval *C,*g (Figure12) to evaluate arithmetic gates (+, *×*). It proceeds in the following steps. Q – First find enough number of *O*(log*λ*)-bit primes *{pi}* such that their product *Q* = *i* *pi*is sufficiently large, *Q > R² · λ* *ω*(1). Let *ℓ* be the number of primes needed. Also define CRT representations with respect to *Q* as

CRT(*x*) = *{xi}* where *xi*:= *x* mod *pi,* CRT *−* (*{xi}*) = *x,* (33)

Sub-protocol ArithGateEval *C,*g The protocol runs between a garbler *PG* and an evaluator *PE*, to evaluate an arithmetic gate (+ or *×*) g *∈ C*. Inputs: *PG,PE* both hold public data pd = (aHMAC*.*pd*,*HSS*.*pdsk) (as defined in Equation3), and jointly hold additive shares *⟨s*Bits(*x*)*⟩*, *⟨s*Bits(*y*)*⟩*, where *x, y ∈* Z*R* are masked inputs. *PE* additionally holds the values *x*, *y*. Outputs: *PG,PE* jointly output additive shares *⟨s*Bits(*z*)*⟩*, where *z ∈* Z*R* is the masked output. *PE* additionally holds the value *z*.

– Let CRT*,*CRT *−*1 be functions defined in Equation33, and *C* CRT, *C* InvCRT be Boolean circuits imple- menting them (Equation34). – *PG,PE* obtain additive shares *⟨s*Bits(CRT(*x*))*⟩* through local computations:

*PG* :*{⟨s*Bits(*xi*)*⟩*0*}, ←* EvalKey(aHMAC*.*pd*,C* CRT *, ⟨s*Bits(*x*)*⟩*0)*,* *PE* :*{⟨s*Bits(*xi*)*⟩*1*}←* EvalTag(aHMAC*.*pd*,C* CRT *, ⟨s*Bits(*x*)*⟩*1*, x*)*,*

where *xi* := *x* mod *pi*. Similarly obtain shares of *⟨s*Bits(CRT(*y*))*⟩*. – *∀i ∈* [*ℓ*], *PG,PE* apply BoolGateEval *′* over the shares *⟨s*Bits(*xi*)*⟩*, *⟨s*Bits(*yi*)*⟩*.

(*PG* : *⟨s*Bits(*zi*)*⟩*0)*,* (*PE* : *⟨s*Bits(*zi*)*⟩*0*, zi*) *←* BoolGateEval *′C,*g (*PG* : pd*, ⟨s*Bits(*xi, yi*)*⟩*0*,* (*PE* : pd*, ⟨s*Bits(*xi, yi*)*⟩*1*, xi, yi*)*,*

where BoolGateEval *′* is a slight variant of BoolGateEval (Figure3) as explained in Section6.1. – *PG*, *PE* obtain additive shares *⟨s*Bits(*z* *′* )*⟩* where *z* *′* := CRT *−*1 (*{zi}*) through local computations.

*PG* :*⟨s*Bits(*z* *′*

)*⟩*0*, ←* EvalKey(aHMAC*.*pd*,C*
InvCRT *, {⟨s*Bits(*zi*)*⟩*0*}*)*,* *PE* :*⟨s*Bits(*z* *′*

)*⟩*1*←* EvalTag(aHMAC*.*pd*,C*
InvCRT *, {⟨s*Bits(*zi*)*⟩*1*}, {zi}*)*,*

Then obtain additive shares *⟨s*Bits(*z*)*⟩* where *z* := *z* *′* mod *R* through local computations.

*PG* :*⟨s*Bits(*z*)*⟩*0*, ←* EvalKey(aHMAC*.*pd*,* mod*R, ⟨s*Bits(*z* *′*

)*⟩*0)*,*
*PE* :*⟨s*Bits(*z*)*⟩*<u>1</u>*←* EvalTag(aHMAC*.*pd*,* mod*R, ⟨s*Bits(*z* *′*

)*⟩*<u>1</u>*, z* *′* )*.*
Fig. 12. 2PC protocol for Arithmetic gates.

## and Boolean circuits computing those conversions.

*C* CRT (Bits(*x*)) := *{*Bits(*x* mod *pi*)*}i*= Bits(CRT(*x*))*,* InvCRT (34) *C* (Bits(CRT(*x*))) := Bits(*x*)*.*

– *PG*, *PE*apply the aHMAC evaluations locally on the shares *⟨s*Bits(*x*)*⟩*, *⟨s*Bits(*y*)*⟩* to obtain shares of their CRT representations:

Input *⟨s*Bits(*x*)*⟩, ⟨s*Bits(*y*)*⟩* via aHMAC *{⟨s*Bits(*xi*)*⟩}, {⟨s*Bits(*yi*)*⟩}.*

– After decomposing the large values *x, y* into small CRT representations, *P*<u>G</u>*,P*<u>E</u>jointly call *′* *C,*g

|′C,g||||i i|
|---|---|---|---|---|
||′|i|||
|′C,g ′ v g,||C,g|||

BoolGateEval to evaluate the gate function *g* on each CRT components *xi*, *yi*:

via BoolGateEval *{⟨s*Bits(*z*)*⟩},*

where BoolGateEval is the same as BoolGateEval (Figure3) except using a different Boolean circuit *C* (sk) defined as follows.

1.Parse v as two values *xi*

||, y ∈ Z|.||
|---|---|---|---|
|′i i′|i i ′i i|p x|i′ i|
|x|||y|

2.Compute *x,y* as
*x* = *x −* (*r* mod *R*)*, y* = *y −* (*r* *y* mod *R*) where *r ←* PRF(sk*,*InWires(*g*)[0])*, r ←* PRF(sk*,*InWires(*g*)[1])*.*

3.Outputs Bits(*zi*) where *zi*is computed as
*zi*= g(*x* *′i* *,yi′*) + *r*

(*z*) mod *pi,* where *r*
*z* *←* PRF(sk*,*OutWire(*g*))*.*

*′* *C,*g We note two facts of the values *zi*computed by BoolGateEval.

CRT *−*1 (*{zi}*) *≡ g*(*x,y*) + PRF(sk*,*OutWire(*g*)) mod *R,* *−*1 2 *ω*(1) (35) *|*CRT (*{zi}*)*|≤ R · λ.*

where *x,y* are the actual wire values to the gate g. – Finally, convert the shares of small CRT components *⟨szi⟩* back into a share of an integer, and then compute the mod *R* circuit on it.

|′|′ −1|i|
|---|---|---|
||′||
|C,g|||

via aHMAC *{⟨s*Bits(*z*)*⟩},* where *z* = CRT (*{z}*) via aHMAC *{⟨s*Bits(*z*)*⟩},* where *z* = *z* mod *R.*

The security of the subprotocol ArithGateEval and of the overall protocol ArithCircEval *C,*Pai

can be proved analogously to the Boolean case. Hence we omit them here.

## 7 Concrete Efficiency Analysis

In this section, we analyze the concrete garbling sizes of our non-leveled schemes, which corre- sponds to the communication sizes in the protocols BoolCircEval *C,*Pai (Figure1,2), BoolCircEval *C,*Pri

(Figure9), and BoolCircEval *C,*Lat (Figure7). They consist of two parts: (1) 1-bit per gate in the circuit (during the Eval phase), and (2) public data pd (during the Init phase). We analyze the size of the public data pd in different instantiations below, and summarize them in Table3.

Concrete Size Asymptotic Ours (Paillier) 0.38 MB 8*λ⌈*log *N ⌉* Ours (Prime-Order) 5.1 MB (4*/β*)*λ²⌈*log *p⌉* size opt. ver. 0.13 MB Ours (Lattice) 71 MB 4*λn⌈*log *q⌉* [LWYY24] (Lattice) 10 GB 4*λn⌈*log *q⌉* 2

||||[LWYY24] (Lattice)||10 GB|4λn⌈log q⌉|||
|---|---|---|---|---|---|---|---|---|
|Table for [LWYY24]. Our scheme under prime-order groups has a 1/poly correctness and privacy error. Here N the Paillier modulus, p is the prime-order group size, β denotes digit-decomposition by 2|3. Concrete|sizes for|the public|data pd|in our non-leveled|schemes,|and|an optimistic (explained below), and|
|n, q are the degree and the modulus of the polynomial ring R||||||= Z [X]/(X|+ 1).||

estimation is *β* *q q* *n*

In the following, we use *λ* = 128 as the computational security parameter, and *κ* = 40 as the statistical security parameter. We also recall the following parameters:

– Under Paillier groups, *N* and *ζ* specify the group Z *∗* *Nζ*+1. – Under prime-order groups, *p* denotes the group size. – Under lattices, *n* and *q* specify the polynomial ring *Rq*= Z*q*[*X*]*/*(*X* *n* + 1), where the degree *n* is a power-of-two.

Paillier Groups Instantiation. The public data for aHMAC evaluations contains a *λ*-bit seed, and 3*⌈*log *N ⌉* elements in Z *∗* *Nζ*+1. (See Lemma3.) The public data for HSS evaluations can share the seed from aHMAC, and additionally contains 4*λ* elements in Z*Nζ*+1. In total:

*|*pd Pai *|* = *λ* + (3*⌈*log *N ⌉* + 4*λ*) *·* (*ζ* + 1) *·⌈*log *N ⌉.*

An optimization to reduce this size is to compress the public data of aHMAC. As long as the order of the sub-group generated by (1 +*N*) is sufficiently larger than the secret exponent *s*, i.e., *N* *ζ* *≫|s|*, we can compress the public data from consisting 3*⌈*log *N ⌉* elements to 3 elements:

*r* *∗r∗s r∗s*2*s ∗* X *⌈*log *N ⌉* *g, g, g ·* (1 + *N*)*,* where *r* = r[*i*]*,* and r *←* [*N*]*.* *i*

Note that the compressed version of pd can be derived from the original, hence is still secure. Furthermore, if aggressively assuming the secret exponent in CP-DDH only needs to have 2*λ* 14 instead of *⌈*log *N ⌉* bits, it suffices to set *ζ* = 1 to guarantee *N* *ζ* = *N ≫* 2*λ*. In total

*|*pd Pai *|* = *λ* + (3 + 4*λ*) *·* 2 *·⌈*log *N ⌉.* // w/ compressed aHMAC pd and small exponents.

Concretely, we set the Paillier modulus *N* to have 3072 bits (which is believed to provides 128 bits of security), which gives *|*pd Pai *|* = 0*.*38MB. Prime-Order Groups Instantiation. The public data for aHMAC evaluations contains a *λ*-bit seed, and 3*⌈*log *p⌉* elements in Z*p*. (See Lemma7.) The public data for HSS evaluations can share the seed from aHMAC, and additionally contains 2*λ* + 2*λ⌈*log *p⌉* elements in Z*p*. (See Lemma10.) In total:

*|*pd Pri *|* = *λ* + (3*⌈*log *p⌉* + 2*λ* + 2*λ⌈*log *p⌉*) *·⌈*log *p⌉.*

We can reduce this size by similarly assuming the secret exponent only needs 2*λ* instead of *⌈*log *p⌉* bits. Furthermore, we can considering digit-decomposition instead of bit-decomposition of the secret *s*. When using a base 2 *β*, the public data for aHMAC now only needs to contain 6*λ/β* elements, and the public data for HSS only needs to contain 2*λ* + (4*/β*)*λ²* elements. 15 A final optimization is to use a random oracle (RO) to obtain the first elements in all ElGamal ciphertexts for free, as suggested in [BGI16], which reduces the public data for HSS by a factor of 2. In total:

*|*pd Pri *|* = *λ* + (6*/β* + 1)*λ* + (2*/β*)*λ² ·⌈*log *p⌉.* // w/ small exponents, digit decomposition, and RO.

14 We estimate a 2*λ*-bit exponent to have *λ*-bit security following the estimation for small-exponent ElGamal in [BGI17]. As a consequence of using digit decomposition, the computation cost of our scheme will increase (by a at least a factor of 2 *β* ).

Concretely, we consider two settings. First, optimizing for computation time, we follow the optimized implementation from [BGI17] to use “conversion friendly” primes for *p*. As noted there, compared to a general prime, such conversion friendly primes needs to have a 50% larger bit-length to provide a similar level of security. Therefore, we estimate *⌈*log *p⌉* = 5000 to provide 128 bits of security. We also follow [BGI17] to set *β* = 4, which gives *|*pd Pri *|* = 5*.*07MB. Second, optimizing for garbling size, we choose elliptic curves of 256-bit as the prime-order group, and more aggressively set *β* = 8, which gives *|*pd Pri *|* = 0*.*13MB. Lattice Instantiation. The public data for aHMAC evaluations contains a *λ*-bit seed, and 3 elements in *Rq*. (See Lemma12.) The public data for HSS evaluations can share the seed from aHMAC, and additionally contains 4*λ* elements in *Rq*. (See Lemma15.) In total:

*|*pd Lat *|* = *λ* + (3 + 4*λ*) *· n ·⌈*log *q⌉.*

Concretely, we follow [BKS19] to use uniform ternary secrets with coefficients from *√* *{*0*, −*1*,*1*}*, and rounded Gaussian error distributions with parameter *σ* = 8*/* 2*π*. We choose a modulus with *⌈*log *q⌉* = 142 bits, and the polynomial ring with degree *n* = 2 13 = 8192. These settings are estimated 16 to achieve 128 bits of security, and a correctness error 2 *−*40. We get *|*pd Lat *|* =

71*.*42MB. Comparing with the Scheme of [LWYY24] Based on FHE. The scheme of [LWYY24] is based on the GSW [GSW13] fully homomorphic encryption (FHE) scheme (and assuming its KDM-security). Under the RLWE version of GSW, the garbling material contains 1 bit per gate, a *λ*-bit seed, public parameters pp, and *λ* FHE ciphertexts. We refer to the seed, pp and the ciphertexts as the public data pd
GSW in this scheme. In more detail, pp consists of 2 + 8*⌈*log *q⌉* elements in *Rq*, and each ciphertext consists of 4*⌈*log *q⌉* elements in *Rq*. In total:

*|*pd GSW *|* = *λ* + (2 + 8*⌈*log *q⌉* + 4*⌈*log *q⌉λ*) *· n ·⌈*log *q⌉.*

Compared to our lattice instantiation, the public data in [LWYY24] is asymptotically greater by a factor of log*q*, assuming the polynomial ring degree *n* and the modulus *q* being equal. In the GSW FHE scheme, the modulus *q* not only needs to satisfy a similar set of constraints to our lattice instantiation, but also needs to support homomorphic evaluations of a low-depth PRG. Therefore, we expect concretely the scheme of [LWYY24] needs a much larger *q* than ours, and consequently also a larger *n*, to achieve 128 bits of estimated security. Optimistically, under the same settings of *⌈*log *q⌉* = 142 and *n* = 2 13 = 8192, we get *|*pd GSW *|* = 10*.*00GB.

Acknowledgments. We thank Lance Roy for the helpful suggestion on proving power-DDH implies DDH in Paillier groups. Y. Ishai was supported by ISF grants 2774/20 and 3527/24, BSF grant 2022370, and ISF-NSFC grant 3127/23. H. Lin and H. Li were supported by NSF grant CNS-2026774, and a Simons Collaboration on the Theory of Algorithmic Fairness.

Using the LWE security estimator: [https://github.com/malb/lattice-estimator](https://github.com/malb/lattice-estimator)

# Bibliography

+ [ABG 24]Amit Agarwal, Elette Boyle, Niv Gilboa, Yuval Ishai, Mahimna Kelkar, and Yiping Ma. Compressing unit-vector correlations via sparse pseudorandom generators. In Leonid Reyzin and Douglas Stebila, editors, *CRYPTO 2024, Part VIII*, volume 14927 of *LNCS*, pages 346–383. Springer, Cham, August 2024. [ADOS22]Damiano Abram, Ivan Damg˚ard, Claudio Orlandi, and Peter Scholl. An algebraic framework for silent preprocessing with trustless setup and active security. In Yev- geniy Dodis and Thomas Shrimpton, editors, *CRYPTO 2022, Part IV*, volume 13510 of *LNCS*, pages 421–452. Springer, Cham, August 2022. [AHI11]Benny Applebaum, Danny Harnik, and Yuval Ishai. Semantic security under related- key attacks and applications. In Bernard Chazelle, editor, *ICS 2011*, pages 45–60. Tsinghua University Press, January 2011. [AIK05]Benny Applebaum, Yuval Ishai, and Eyal Kushilevitz. Computationally private randomizing polynomials and their applications. In *20th Annual IEEE Conference* *on Computational Complexity (CCC 2005), 11-15 June 2005, San Jose, CA, USA*, pages 260–274. IEEE Computer Society, 2005. [AIK11]Benny Applebaum, Yuval Ishai, and Eyal Kushilevitz. How to garble arithmetic circuits. In Rafail Ostrovsky, editor, *52nd FOCS*, pages 120–129. IEEE Computer Society Press, October 2011. [AIKW13]Benny Applebaum, Yuval Ishai, Eyal Kushilevitz, and Brent Waters. Encoding functions with constant online rate or how to compress garbled circuits keys. In Ran Canetti and Juan A. Garay, editors, *CRYPTO 2013, Part II*, volume 8043 of *LNCS*, pages 166–184. Springer, Berlin, Heidelberg, August 2013. + [AMN 18]Nuttapong Attrapadung, Takahiro Matsuda, Ryo Nishimaki, Shota Yamada, and Takashi Yamakawa. Constrained PRFs for NC¹ in traditional groups. In Hovav Shacham and Alexandra Boldyreva, editors, *CRYPTO 2018, Part II*, volume 10992 of *LNCS*, pages 543–574. Springer, Cham, August 2018. [App17]Benny Applebaum. Garbled circuits as randomized encodings of functions: a primer. In Yehuda Lindell, editor, *Tutorials on the Foundations of Cryptography*, pages 1–44. Springer International Publishing, 2017. + [ARS 15]Martin R. Albrecht, Christian Rechberger, Thomas Schneider, Tyge Tiessen, and Michael Zohner. Ciphers for MPC and FHE. In Elisabeth Oswald and Marc Fischlin, editors, *EUROCRYPT 2015, Part I*, volume 9056 of *LNCS*, pages 430–454. Springer, Berlin, Heidelberg, April 2015. [ARS24]Damiano Abram, Lawrence Roy, and Peter Scholl. Succinct homomorphic secret sharing. In Marc Joye and Gregor Leander, editors, *EUROCRYPT 2024, Part VI*, volume 14656 of *LNCS*, pages 301–330. Springer, Cham, May 2024. + [BCG 17]Elette Boyle, Geoffroy Couteau, Niv Gilboa, Yuval Ishai, and Michele Orr`u. Homo- morphic secret sharing: Optimizations and applications. In Bhavani M. Thuraising- ham, David Evans, Tal Malkin, and Dongyan Xu, editors, *ACM CCS 2017*, pages 2105–2122. ACM Press, October / November 2017. + [BCG 18]Nir Bitansky, Ran Canetti, Sanjam Garg, Justin Holmgren, Abhishek Jain, Huijia Lin, Rafael Pass, Sidharth Telang, and Vinod Vaikuntanathan. Indistinguishabil-

ity obfuscation for RAM programs and succinct randomized encodings. *SIAM J.* *Comput.*, 47(3):1123–1210, 2018. + [BGG 14]Dan Boneh, Craig Gentry, Sergey Gorbunov, Shai Halevi, Valeria Nikolaenko, Gil Segev, Vinod Vaikuntanathan, and Dhinakaran Vinayagamurthy. Fully key- homomorphic encryption, arithmetic circuit ABE and compact garbled circuits. In Phong Q. Nguyen and Elisabeth Oswald, editors, *Advances in Cryptology-EU-* *ROCRYPT 2014 - 33rd Annual International Conference on the Theory and Ap-* *plications of Cryptographic Techniques, Copenhagen, Denmark, May 11-15, 2014.* *Proceedings*, volume 8441 of *Lecture Notes in Computer Science*, pages 533–556. Springer, 2014. [BGI16]Elette Boyle, Niv Gilboa, and Yuval Ishai. Breaking the circuit size barrier for secure computation under DDH. In Matthew Robshaw and Jonathan Katz, editors, *CRYPTO 2016, Part I*, volume 9814 of *LNCS*, pages 509–539. Springer, Berlin, Heidelberg, August 2016. [BGI17]Elette Boyle, Niv Gilboa, and Yuval Ishai. Group-based secure computation: Op- timizing rounds, communication, and computation. In Jean-S´ebastien Coron and Jesper Buus Nielsen, editors, *EUROCRYPT 2017, Part II*, volume 10211 of *LNCS*, pages 163–193. Springer, Cham, April / May 2017. + [BGI 18]Elette Boyle, Niv Gilboa, Yuval Ishai, Huijia Lin, and Stefano Tessaro. Foundations of homomorphic secret sharing. In Anna R. Karlin, editor, *ITCS 2018*, volume 94, pages 21:1–21:21. LIPIcs, January 2018. [BHHO08]Dan Boneh, Shai Halevi, Michael Hamburg, and Rafail Ostrovsky. Circular-secure encryption from decision Diffie-Hellman. In David Wagner, editor, *CRYPTO 2008*, volume 5157 of *LNCS*, pages 108–125. Springer, Berlin, Heidelberg, August 2008. [BHR12]Mihir Bellare, Viet Tung Hoang, and Phillip Rogaway. Foundations of garbled circuits. In Ting Yu, George Danezis, and Virgil D. Gligor, editors, *ACM CCS* *2012*, pages 784–796. ACM Press, October 2012. [BKS19]Elette Boyle, Lisa Kohl, and Peter Scholl. Homomorphic secret sharing from lattices without FHE. In Yuval Ishai and Vincent Rijmen, editors, *EUROCRYPT 2019,* *Part II*, volume 11477 of *LNCS*, pages 3–33. Springer, Cham, May 2019. [BL18]Fabrice Benhamouda and Huijia Lin. k-round multiparty computation from k- round oblivious transfer via garbled interactive circuits. In Jesper Buus Nielsen and Vincent Rijmen, editors, *EUROCRYPT 2018, Part II*, volume 10821 of *LNCS*, pages 500–532. Springer, Cham, April / May 2018. [BLLL23]Marshall Ball, Hanjun Li, Huijia Lin, and Tianren Liu. New ways to garble arith- metic circuits. In Carmit Hazay and Martijn Stam, editors, *EUROCRYPT 2023,* *Part II*, volume 14005 of *LNCS*, pages 3–34. Springer, Cham, April 2023. [BMR90]Donald Beaver, Silvio Micali, and Phillip Rogaway. The round complexity of secure protocols (extended abstract). In *22nd ACM STOC*, pages 503–513. ACM Press, May 1990. [BMR16]Marshall Ball, Tal Malkin, and Mike Rosulek. Garbling gadgets for Boolean and arithmetic circuits. In Edgar R. Weippl, Stefan Katzenbeisser, Christopher Kruegel, Andrew C. Myers, and Shai Halevi, editors, *ACM CCS 2016*, pages 565–577. ACM Press, October 2016. [BMZ19]James Bartusek, Fermi Ma, and Mark Zhandry. The distinction between fixed and random generators in group-based assumptions. In Alexandra Boldyreva and

Daniele Micciancio, editors, *CRYPTO 2019, Part II*, volume 11693 of *LNCS*, pages 801–830. Springer, Cham, August 2019. [BV11]Zvika Brakerski and Vinod Vaikuntanathan. Efficient fully homomorphic encryption from (standard) LWE. In Rafail Ostrovsky, editor,*52nd FOCS*, pages 97–106. IEEE Computer Society Press, October 2011. [CCH + 24]Mingyu Cho, Woohyuk Chung, Jincheol Ha, Jooyoung Lee, Eun-Gyeol Oh, and Mincheol Son. FRAST: tfhe-friendly cipher based on random s-boxes. *IACR Trans.* *Symmetric Cryptol.*, 2024(3):1–43, 2024. [CCKK21]Jung Hee Cheon, Wonhee Cho, Jeong Han Kim, and Jiseung Kim. Adventures in crypto dark matter: Attacks and fixes for weak pseudorandom functions. In Juan Garay, editor, *PKC 2021, Part II*, volume 12711 of *LNCS*, pages 739–760. Springer, Cham, May 2021. [CEMY09]Seung Geol Choi, Ariel Elbaz, Tal Malkin, and Moti Yung. Secure multi-party com- putation minimizing online rounds. In Mitsuru Matsui, editor, *ASIACRYPT 2009*, volume 5912 of *LNCS*, pages 268–286. Springer, Berlin, Heidelberg, December 2009. [CHHK25]Geoffroy Couteau, Carmit Hazay, Aditya Hegde, and Naman Kumar. o(1/*λ*)-rate boolean garbling scheme from generic groups. Cryptology ePrint Archive, Paper 2025/268, 2025. [CMPR23]Geoffroy Couteau, Pierre Meyer, Alain Passel`egue, and Mahshid Riahinia. Con- strained pseudorandom functions from homomorphic secret sharing. In Carmit Hazay and Martijn Stam, editors, *EUROCRYPT 2023, Part III*, volume 14006 of *LNCS*, pages 194–224. Springer, Cham, April 2023. [CNs07]Jan Camenisch, Gregory Neven, and abhi shelat. Simulatable adaptive oblivious transfer. In Moni Naor, editor, *EUROCRYPT 2007*, volume 4515 of *LNCS*, pages 573–590. Springer, Berlin, Heidelberg, May 2007. [DJ01]Ivan Damg˚ard and Mats Jurik. A generalisation, a simplification and some ap- plications of Paillier’s probabilistic public-key system. In Kwangjo Kim, editor, *PKC 2001*, volume 1992 of *LNCS*, pages 119–136. Springer, Berlin, Heidelberg, February 2001. [DKK18]Itai Dinur, Nathan Keller, and Ohad Klein. An optimal distributed discrete log protocol with applications to homomorphic secret sharing. In Hovav Shacham and Alexandra Boldyreva, editors, *CRYPTO 2018, Part III*, volume 10993 of *LNCS*, pages 213–242. Springer, Cham, August 2018. [FKN94]Uriel Feige, Joe Kilian, and Moni Naor. A minimal model for secure computation (extended abstract). In Frank Thomson Leighton and Michael T. Goodrich, editors, *Proceedings of the Twenty-Sixth Annual ACM Symposium on Theory of Computing,* *23-25 May 1994, Montr´eal, Qu´ebec, Canada*, pages 554–563. ACM, 1994. [FLLL24]Ximing Fu, Mo Li, Shihan Lyu, and Chuanyi Liu. Bit-fixing correlation attacks on goldreich’s pseudorandom generators. *IACR Cryptol. ePrint Arch.*, page 1594,

2024.
[Gen09]Craig Gentry. Fully homomorphic encryption using ideal lattices. In Michael Mitzen- macher, editor, *41st ACM STOC*, pages 169–178. ACM Press, May / June 2009. [GGP10]Rosario Gennaro, Craig Gentry, and Bryan Parno. Non-interactive verifiable com- puting: Outsourcing computation to untrusted workers. In Tal Rabin, editor, *CRYPTO 2010*, volume 6223 of *LNCS*, pages 465–482. Springer, Berlin, Heidel- berg, August 2010.

[GHKW17]Rishab Goyal, Susan Hohenberger, Venkata Koppula, and Brent Waters. A generic approach to constructing and proving verifiable random functions. In Yael Kalai and Leonid Reyzin, editors, *TCC 2017, Part II*, volume 10678 of *LNCS*, pages 537–566. Springer, Cham, November 2017. [GJM03]Philippe Golle, Stanislaw Jarecki, and Ilya Mironov. Cryptographic primitives en- forcing communication and storage complexity. In Matt Blaze, editor, *FC 2002*, volume 2357 of *LNCS*, pages 120–135. Springer, Berlin, Heidelberg, March 2003. [GKP + 13]Shafi Goldwasser, Yael Tauman Kalai, Raluca A. Popa, Vinod Vaikuntanathan, and Nickolai Zeldovich. Reusable garbled circuits and succinct functional encryption. In Dan Boneh, Tim Roughgarden, and Joan Feigenbaum, editors, *45th ACM STOC*, pages 555–564. ACM Press, June 2013. [GLNP15]Shay Gueron, Yehuda Lindell, Ariel Nof, and Benny Pinkas. Fast garbling of circuits under standard assumptions. In Indrajit Ray, Ninghui Li, and Christopher Kruegel, editors, *ACM CCS 2015*, pages 567–578. ACM Press, October 2015. [GN25]Jian Guo and Wenjie Nan. Efficient mixed garbling from homomorphic secret shar- ing and GGM-tree. Cryptology ePrint Archive, Paper 2025/207, 2025. [GRR + 16]Lorenzo Grassi, Christian Rechberger, Dragos Rotaru, Peter Scholl, and Nigel P. Smart. MPC-friendly symmetric key primitives. In Edgar R. Weippl, Stefan Katzen- beisser, Christopher Kruegel, Andrew C. Myers, and Shai Halevi, editors, *ACM CCS* *2016*, pages 430–443. ACM Press, October 2016. [GS18]Sanjam Garg and Akshayaram Srinivasan. Two-round multiparty secure compu- tation from minimal assumptions. In Jesper Buus Nielsen and Vincent Rijmen, editors, *Advances in Cryptology-EUROCRYPT 2018 - 37th Annual International* *Conference on the Theory and Applications of Cryptographic Techniques, Tel Aviv,* *Israel, April 29 - May 3, 2018 Proceedings, Part II*, volume 10821 of *Lecture Notes* *in Computer Science*, pages 468–499. Springer, 2018. [GSW13]Craig Gentry, Amit Sahai, and Brent Waters. Homomorphic encryption from learn- ing with errors: Conceptually-simpler, asymptotically-faster, attribute-based. In Ran Canetti and Juan A. Garay, editors, *CRYPTO 2013, Part I*, volume 8042 of *LNCS*, pages 75–92. Springer, Berlin, Heidelberg, August 2013. [Hea24]David Heath. Efficient arithmetic in garbled circuits. In Marc Joye and Gregor Leander, editors, *EUROCRYPT 2024, Part V*, volume 14655 of *LNCS*, pages 3–31. Springer, Cham, May 2024. [HIKR23]Shai Halevi, Yuval Ishai, Eyal Kushilevitz, and Tal Rabin. Additive randomized encodings and their applications. In Helena Handschuh and Anna Lysyanskaya, editors, *CRYPTO 2023, Part I*, volume 14081 of *LNCS*, pages 203–235. Springer, Cham, August 2023. [HLL23]Yao-Ching Hsieh, Huijia Lin, and Ji Luo. Attribute-based encryption for circuits of unbounded depth from lattices. In *64th FOCS*, pages 415–434. IEEE Computer Society Press, October 2023. [ILL24]Yuval Ishai, Hanjun Li, and Huijia Lin. Succinct homomorphic MACs from groups and applications. Cryptology ePrint Archive, Paper 2024/2073, 2024. [KLW15]Venkata Koppula, Allison Bishop Lewko, and Brent Waters. Indistinguishability obfuscation for Turing machines with unbounded memory. In Rocco A. Servedio and Ronitt Rubinfeld, editors, *47th ACM STOC*, pages 419–428. ACM Press, June

2015.

[KMR14]Vladimir Kolesnikov, Payman Mohassel, and Mike Rosulek. FleXOR: Flexible gar- bling for XOR gates that beats free-XOR. In Juan A. Garay and Rosario Gennaro, editors, *CRYPTO 2014, Part II*, volume 8617 of *LNCS*, pages 440–457. Springer, Berlin, Heidelberg, August 2014. [KS08]Vladimir Kolesnikov and Thomas Schneider. Improved garbled circuit: Free XOR gates and applications. In Luca Aceto, Ivan Damg˚ard, Leslie Ann Goldberg, Magn´us M. Halld´orsson, Anna Ing´olfsd´ottir, and Igor Walukiewicz, editors, *ICALP* *2008, Part II*, volume 5126 of *LNCS*, pages 486–498. Springer, Berlin, Heidelberg, July 2008. [KY18]Ilan Komargodski and Eylon Yogev. Another step towards realizing random oracles: Non-malleable point obfuscation. In Jesper Buus Nielsen and Vincent Rijmen, edi- tors, *EUROCRYPT 2018, Part I*, volume 10820 of *LNCS*, pages 259–279. Springer, Cham, April / May 2018. [LL24]Hanjun Li and Tianren Liu. How to garble mixed circuits that combine boolean and arithmetic computations. In Marc Joye and Gregor Leander, editors, *EURO-* *CRYPT 2024, Part VI*, volume 14656 of *LNCS*, pages 331–360. Springer, Cham, May 2024. [LWYY24]Hanlin Liu, Xiao Wang, Kang Yang, and Yu Yu. Garbled circuits with 1 bit per gate. Cryptology ePrint Archive, Paper 2024/1988, 2024. [MORS24]Pierre Meyer, Claudio Orlandi, Lawrence Roy, and Peter Scholl. Rate-1 arith- metic garbling from homomorphic secret sharing. In Elette Boyle and Mohammad Mahmoody, editors, *Theory of Cryptography - 22nd International Conference, TCC* *2024, Milan, Italy, December 2-6, 2024, Proceedings, Part IV*, volume 15367 of *Lec-* *ture Notes in Computer Science*, pages 71–97. Springer, 2024. [MORS25]Pierre Meyer, Claudio Orlandi, Lawrence Roy, and Peter Scholl. Silent circuit re- linearisation: Sublinear-size (boolean and arithmetic) garbled circuits from DCR. Cryptology ePrint Archive, Paper 2025/245, 2025. [NPS99]Moni Naor, Benny Pinkas, and Reuban Sumner. Privacy preserving auctions and mechanism design. In Stuart I. Feldman and Michael P. Wellman, editors, *Proceed-* *ings of the First ACM Conference on Electronic Commerce (EC-99), Denver, CO,* *USA, November 3-5, 1999*, pages 129–139. ACM, 1999. [OSY21]Claudio Orlandi, Peter Scholl, and Sophia Yakoubov. The rise of paillier: Homomor- phic secret sharing and public-key silent OT. In Anne Canteaut and Fran¸cois-Xavier Standaert, editors, *EUROCRYPT 2021, Part I*, volume 12696 of *LNCS*, pages 678–

708. Springer, Cham, October 2021.
[Pai99]Pascal Paillier. Public-key cryptosystems based on composite degree residuosity classes. In Jacques Stern, editor, *EUROCRYPT’99*, volume 1592 of *LNCS*, pages 223–238. Springer, Berlin, Heidelberg, May 1999. [PSSW09]Benny Pinkas, Thomas Schneider, Nigel P. Smart, and Stephen C. Williams. Secure two-party computation is practical. In Mitsuru Matsui, editor, *ASIACRYPT 2009*, volume 5912 of *LNCS*, pages 250–267. Springer, Berlin, Heidelberg, December 2009. [RR21]Mike Rosulek and Lawrence Roy. Three halves make a whole? Beating the half- gates lower bound for garbled circuits. In Tal Malkin and Chris Peikert, editors, *CRYPTO 2021, Part I*, volume 12825 of *LNCS*, pages 94–124, Virtual Event, August

2021. Springer, Cham.
[RS21]Lawrence Roy and Jaspal Singh. Large message homomorphic secret sharing from DCR and applications. In Tal Malkin and Chris Peikert, editors, *CRYPTO 2021,*

*Part III*, volume 12827 of *LNCS*, pages 687–717, Virtual Event, August 2021. Springer, Cham. [Sho97]Victor Shoup. Lower bounds for discrete logarithms and related problems. In Walter Fumy, editor, *EUROCRYPT’97*, volume 1233 of *LNCS*, pages 256–266. Springer, Berlin, Heidelberg, May 1997. [SS10]Amit Sahai and Hakan Seyalioglu. Worry-free encryption: functional encryption with public keys. In Ehab Al-Shaer, Angelos D. Keromytis, and Vitaly Shmatikov, editors, *ACM CCS 2010*, pages 463–472. ACM Press, October 2010. [Yao82]Andrew Chi-Chih Yao. Protocols for secure computations (extended abstract). In *23rd FOCS*, pages 160–164. IEEE Computer Society Press, November 1982. [ZRE15]Samee Zahur, Mike Rosulek, and David Evans. Two halves make a whole-reducing data transfer in garbled circuits using half gates. In Elisabeth Oswald and Marc Fischlin, editors, *EUROCRYPT 2015, Part II*, volume 9057 of *LNCS*, pages 220–

250. Springer, Berlin, Heidelberg, April 2015.
