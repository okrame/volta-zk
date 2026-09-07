# Interactive Oracle Proofs

### Eli Ben-Sasson Alessandro Chiesa Nicholas Spooner

eli@cs.technion.ac.il alexch@berkeley.edu spooner@cs.toronto.edu Technion UC Berkeley University of Toronto

### February 10, 2016

**Abstract**

We initiate the study of a proof system model that naturally combines two well-known models: interactive proofs (IPs) and probabilistically-checkable proofs (PCPs). An *interactive oracle proof* (IOP) is an interactive proof in which the verifier is not required to read the prover’s messages in their entirety; rather, the verifier has oracle access to the prover’s messages, and may probabilistically query them. IOPs simultaneously generalize IPs and PCPs. Thus, IOPs retain the expressiveness of PCPs, capturing NEXP rather than only PSPACE, and also the flexibility of IPs, allowing multiple rounds of communication with the prover. These degrees of freedom allow for more efficient “PCP-like” interactive protocols, because the prover does not have to compute the parts of a PCP that are not requested by the verifier. As a first investigation into IOPs, we offer two main technical contributions. First, we give a compiler that maps any public-coin IOP into a non-interactive proof in the random oracle model. We prove that the soundness of the resulting proof is tightly characterized by the soundness of the IOP against *state restoration attacks*, a class of rewinding attacks on the IOP verifier. Our compiler preserves zero knowledge, proof of knowledge, and time complexity of the underlying IOP. As an application, we obtain blackbox unconditional ZK proofs in the random oracle model with quasilinear prover and polylogarithmic verifier, improving on the result of Ishai et al. (2015). Second, we study the notion of state-restoration soundness of an IOP: we prove tight upper and lower bounds in terms of the IOP’s (standard) soundness and round complexity; and describe a simple adversarial strategy that is optimal across all state restoration attacks. Our compiler can be viewed as a generalization of the Fiat–Shamir paradigm for public-coin IPs (CRYPTO ’86), and of the “CS proof” constructions of Micali (FOCS ’94) and Valiant (TCC ’08) for PCPs. Our analysis of the compiler gives, in particular, a unified understanding of all of these constructions, and also motivates the study of state restoration attacks, not only for IOPs, but also for IPs and PCPs.

**Keywords**: probabilistically checkable proofs, interactive proofs, Fiat–Shamir paradigm, computationally-sound proofs

Parts of this paper appear in the third author’s master’s thesis (April 2015) in the Department of Computer Science at ETH Zurich, supervised by Alessandro Chiesa and Thomas Holenstein. Independent of our work, [RRR16] introduce the notion of *Probabilistically Checkable Interactive Proofs*, which is the same as our notion of Interactive Oracle Proofs.

## Contents

**1 Introduction 3**

1.1 Models of proof systems.......................................................3
1.2 Compiling proof systems into argument systems...........................................4
1.3 Results................................................................5
1.4 Techniques..............................................................9
1.5 Roadmap ...............................................................11
**2 Preliminaries 12**

2.1 Basic notations ............................................................12
2.2 Merkle trees.............................................................12
2.3 Non-interactive random-oracle proofs................................................12
**3 Extractability and privacy of Merkle trees 14**

3.1 Extractability .............................................................14
3.2 Privacy................................................................15
**4 Interactive oracle proofs 18**

4.1 Interactive oracle protocols ......................................................18
4.2 Interactive oracle proof systems...................................................18
4.3 Basic complexity-theoretic properties................................................19
**5 State restoration attacks on interactive oracle proofs 20**

5.1 State restoration attacks, and soundness and proof of knowledge against these............................20
5.2 General bounds ............................................................21
5.3 Tightness of general bounds.....................................................22
5.4 Restricted state restoration attacks..................................................23
**6 From interactive oracle proofs to non-interactive random-oracle proofs 25** **7 Analysis of the transformation** *T* **27**

7.1 Upper bound for soundness ......................................................28
7.2 Lower bound for soundness.....................................................30
7.3 Proof of knowledge ..........................................................31
7.4 Zero knowledge...........................................................32
**8 Tree exploration games 34**

8.1 Definition of tree exploration games.................................................34
8.2 A connection between tree exploration and state restoration.....................................34
8.3 The expected value strategy.....................................................37
**Acknowledgments 39** **A Interactive oracle proofs characterize** NEXP **40** **B Soundness error reduction 41**

B.1 Soundness error reduction for IOPs ..................................................41
B.2 Soundness error reduction for NIROPs ................................................41
B.3 Strategies for soundness error reduction...............................................43
**C Zero knowledge with non-programmable random oracles 44** **References 45**

## 1 Introduction

The notion of *proof* is central to modern cryptography and complexity theory. The class NP, for example, is the set of languages whose membership can be decided by a deterministic polynomial-time verifier by reading proof strings of polynomial length; this class captures the traditional notion of a mathematical proof. Over the last three decades, researchers have introduced and studied proof systems that generalize the above traditional notion, and investigations from these points of view have led to breakthroughs in cryptography, hardness of approximation, and other areas. In this work we introduce and study a new model of proof system.

### 1.1 Models of proof systems

We give some context by recalling three of the most well-known among alternative models of proof systems. **Interactive proofs (IPs).** Interactive proofs were introduced by Goldwasser, Micali, and Rackoff [GMR89]: in a *k*-round interactive proof, a probabilistic polynomial-time verifier exchanges *k* messages with an all- powerful prover, and then accepts or rejects; IP[*k*] is the class of languages with a *k*-round interactive proof. Independently, Babai [Bab85] introduced Arthur–Merlin games: a *k*-round Arthur–Merlin game is a *k*-round *public-coin* interactive proof (i.e., the verifier messages are uniformly and independently random); AM[*k*] is the class of languages with a *k*-round Arthur–Merlin game. Goldwasser and Sipser [GS86] showed that the two models are equally powerful: for polynomial *k*, IP[*k*] AM[*k* + 2]. Shamir [Sha92], building on the “sum-check” interactive proof of Lund, Fortnow, Karloff, and Nisan [LFKN92], proved that interactive proofs correspond to languages decidable in polynomial space: IP[poly(*n*)] = PSPACE. (Also see [Bab90].) **Multi-prover interactive proofs (MIPs).** Multi-prover interactive proofs were introduced by Ben-Or, Goldwasser, Kilian, and Wigderson [BGKW88]: in a *k*-round *p*-prover interactive proof, a probabilistic polynomial-time verifier interacts *k* times with *p* non-communicating all-powerful provers, and then accepts or rejects; MIP[*p;k*] is the class of languages that have a *k*-round *p*-prover interactive proof. In [BGKW88], the authors show that two provers always suffice (i.e., MIP[*p;k*] = MIP[2*;k*]), and that all languages in NP have perfect zero knowledge proofs in this model. Fortnow, Rompel, and Sipser [FRS88] show that interaction with two provers is equivalent to interaction with one prover plus oracle access to a proof string, and from there obtain that MIP[poly(*n*)*;*poly(*n*)] NEXP; Babai, Fortnow and Lund [BFL90] show that NEXP has 1-round 2-prover interactive proofs, thus showing that MIP[2*;*1] = NEXP. **Probabilistically checkable proofs (PCPs).** Probabilistically checkable proofs were introduced by [FRS88, BFLS91, AS98, ALM + 98]: in a probabilistically-checkable proof, a probabilistic polynomial-time verifier has oracle access to a proof string; PCP[*r;q*] is the class of languages for which the verifier uses at most *r* bits of randomness, and queries at most *q* locations of the proof (note that the proof length is at most 2 *r* ). The above results on MIPs imply that PCP[poly(*n*)*;*poly(*n*)] = NEXP. Later works “scaled down” this result to NP: Babai, Fortnow, Levin and Szegedy [BFLS91] show that NP = PCP[*O*(log*n*)*;*poly(log*n*)]; Arora and *p* Safra [AS98] show that NP = PCP[*O*(log*n*)*;O*( log*n*)]; and Arora, Lund, Motwani, Sudan, and Szegedy [ALM + 92] show that NP = PCP[*O*(log*n*)*;O*(1)]. This last is known as the *PCP Theorem*. +

|Researchers have studied other models of proof systems, and here we name only a few: linear IPs [BCI||13],|
|---|---|---|
|||+|
|+|+ +||

*no-signaling MIPs* [IKM09, Ito10, KRR13, KRR14], *linear PCPs* [IKO07, Gro10, Lip12, BCI + 13, GGPR13, PGHR13, BCI 13, SBW11, SMBW12, SVP 12, SBV 13], *interactive PCPs* [KR08, KR09, GIMS10]. We introduce **interactive oracle proofs** (IOPs), a model of proof system that combines aspects of IPs and PCPs. (Later, in Section 1.3.1, we describe how interactive PCPs are a special case of IOPs.) Our work focuses on cryptographic applications of this proof system, as we discuss next.

### 1.2 Compiling proof systems into argument systems

The proof systems mentioned so far share a common feature: they make no assumptions on the computational resources of a (malicious) prover trying to convince the verifier. Instead, many proof systems make “structural” assumptions on the prover: MIPs assume that the prover is a collection of non-communicating strategies (each representing a “sub-prover”); PCPs assume that the prover is non-adaptive (the answer to a message does not depend on previous messages); linear IPs assume that the prover is a linear function, and so on. In contrast, in cryptography, one often considers *argument systems* [BC86, BCC88, Kil92, Mic00]: these are proof systems where soundness holds only against provers that have a bound on computational resources (e.g., provers that run in probabilistic polynomial time). The relaxation from statistical soundness to computational soundness allows circumventing various limitations of IPs [BHZ87, GH98, GVW02, PSSV07], while also avoiding “structural” assumptions on the prover, which can be hard to enforce in applications. **Constructing argument systems.** A common methodology to construct argument systems with desirable properties (e.g., sublinear communication complexity) follows these two steps: (1) give a proof system that achieves these properties in a model with structural restrictions on (all-powerful) provers; (2) use cryptographic tools to compile that proof system into an argument system, i.e., one where the only restriction on the prover is that it is an efficient algorithm. In other words, the compilation trades any structural assumptions for computational ones. This methodology has been highly productive; see Figure 1 for some examples that follow this paradigm. (On the flip side, many other argument systems are constructed, without the explicit use of underlying proof systems, using cryptographic tools “directly”; for instance see [BCC88]. A partial list of more recent examples is [PR14, GHRW14, BGL + 15, CHJV15, CH15, CCC + 15, KP15].) **Proofs in the random oracle model.** An idealized model for studying computationally-bounded provers is the random oracle model [FS86, BR93], where every party has access to the same random function. A protocol proved secure in this model can potentially be instantiated in practice by replacing the random function with a concrete “random-looking” efficient function. While this intuition fails in the general case [CGH04, BBP04, GK03, BDG + 13], the random oracle model is nonetheless a useful testbed for cryptographic primitives. In this paper we focus on proof systems in this model for which the proof consists of a single message from the prover to the verifier. A **non-interactive random-oracle proof** (NIROP) for a relation *R* is a pair of probabilistic polynomial-time algorithms, the prover P and verifier V, that satisfy the following.

(1) *Completeness:* for every instance-witness pair (①*;*✇) in the relation *R*, Pr[V (①*;*P (①*;*✇)) = 1] = 1, where the probability is taken over the random oracle as well as any randomness of P and V. (2) *Soundness:* for every instance ① not in the language of *R* and every malicious prover P~ that asks at most a polynomial number of queries to the random oracle, it holds that Pr[V (①*;* P~ ) = 1] is negligible in the security parameter. **Prior NIROPs and our focus.** Prior work uses the above 2-step methodology to obtain NIROPs with desirable properties. For example, the Fiat–Shamir paradigm maps 3-message public-coin IPs to corre- sponding NIROPs [FS86, PS96]; when invoked on suitable IP constructions, this yields very efficient zero knowledge non-interactive proofs. As another example, Micali’s “CS proof” construction, building on [Kil92], transforms PCPs to corresponding NIROPs; Valiant [Val08] revisits Micali’s construction and proves that it is a proof of knowledge; when invoked on suitable PCPs, these yield non-interactive proofs of knowledge that are extremely short and easy to verify. In this work we study the question of how to compile IOPs, which generalize both IPs and PCPs, into NIROPs. As discussed below, our work ultimately leads to formulating and studying a game-theoretic property of IOPs, which in turn motivates similar questions for IPs and PCPs. We now turn to the discussion of our results. (We do not study the question of avoiding assuming random oracles, as this question continues to be open for the aforementioned prior works and, also, our work.)

|proof model|work|crypto tools used|properties of argument system|||
|---|---|---|---|---|---|
|||by transformation|setup|# of messages|verifiability|
|IP (public-coin)|[FS86, PS96]|(explicitly-programmable) RO|RO|1|public|
||[KR09]|PIR|none|2|private|
|NIZK w/ hidden bits|[FLS90, PS05]|OWF|CRS|1|public|
|-protocols|[Lin15]|(non-programmable) RO|CRS + RO|1|public|
|PCP|[Kil92, BG08]|CRF|none|4|public|
||[Mic00, Val08] [BCCT12, DFH12, GLR11]|(explicitly-programmable) RO extractable CRF|RO none|1 2|public private|
|MIP|[BC12]|extractable FHE|none|2|private|
|MIP (no signaling)|[KRR13, KRR14]|PIR|none|2|private|
|IPCP (public-coin)|[KR09]|PIR|none|2|private|

+

|LIP (any)|[BCI 13]|linear-only encryption|CRS|1|private|
|---|---|---|---|---|---|
|LIP (algebraic)|[BCI 13]|linear-only encoding|CRS|1|public|
|IOP (public-coin)|this work|(explicitly-programmable) RO|RO|1|public|

+

Figure 1: Summary of some works (including this work) that obtain transformations from (information-theoretic)

proof systems to corresponding (cryptographic) argument systems. For each, we highlight the main cryptographic tools used by the transformation and properties of the resulting argument system. These properties include: the setup model; the number of messages exchanged by the prover and verifier (non-interactive argument systems are 1 message); and whether the verifier relies on public or private randomness. The abbreviations used in the table are: CRF=“collision resistant functions”, CRS=“common reference string”, FHE=“fully homomorphic encryption”, PIR=“private information retrieval”, RO=“random oracle”.

### 1.3 Results

We present three main contributions: one is definitional and the other two are technical in nature.

### 1.3.1 Interactive oracle proofs

**A new proof system model.** We introduce a new proof system model: *interactive oracle proofs* (IOPs). 1 This model naturally combines aspects of interactive and probabilistically checkable proofs; namely, an IOP generalizes an interactive proof as follows: the verifier is not required to read the prover’s messages in their entirety; rather, the verifier has oracle access to the prover’s messages (viewed as strings), and may probabilistically query these messages. In more detail, a *k*-round IOP comprises *k* rounds of interaction. In the *i*-th round of interaction: the verifier sends a message *mi*to the prover, which he reads in full; then the prover replies with a message *fi*to the verifier, which he can query (via random access) in this and all later rounds. After the *k* rounds of interaction, the verifier either accepts or rejects. See Figure 2 for a diagram. Like the PCP model, two fundamental measures of efficiency in the IOP model are the *proof length p*, which is the total number of bits in all of the prover’s messages, and the *query complexity q*, which is the total number of locations queried by the verifier across all of the prover’s messages. Unlike the PCP model, another fundamental measure of efficiency is the round complexity *k*; the PCP model can then be viewed as a special case where *k* = 1 (and the first verifier message is empty). **Basic complexity-theoretic properties.** We show that IOPs characterize NEXP (like PCPs); both sequential and parallel repetition of IOPs yield (perfect) exponential soundness error reduction (like IPs); and any IOP can be converted into a public-coin one (like IPs). These basic complexity-theoretic properties confirm that our definition of IOP is a natural way to combine aspects of PCPs and IPs. 1 Independent of our work, [RRR16] introduce *Probabilistically Checkable Interactive Proofs*, which are equivalent to our IOPs.

**Motivation: efficiency.** IOPs generalize both IPs, by treating the prover’s messages as oracle strings, and PCPs, by allowing for more than 1 round. These degrees of freedom enable IOPs to retain the expressive power of PCPs (supporting all languages in NEXP, unlike IPs), while also allowing for additional efficiency. For example, [BCGV16] obtain unconditional zero knowledge via a 2-round IOP with quasilinear proof length; in comparison, such a result is not known for PCPs (or even IPCPs [KR08]). Moreover, when com- bined with our compiler (see next contribution) we obtain blackbox unconditional zero-knowledge with quasi- linear prover and polylogarithmic verifier in the random-oracle model, improving on results of [IMSX15]. As another example, [BCG + 16] obtain 3-round IOPs for circuit satisfiability *with linear proof length and* *constant query complexity*, while for PCPs prior work only achieves sublinear query complexity [BKK + 13]. To do so, [BCG + 16] show that *sumcheck* [LFKN92, Sha92] and *proof composition* [AS98] (used in many PCP constructions such as [ALM + 98, HS00, BGH + 04]) have more efficient “IOP analogues”, which in turn imply a number of probabilistic checking results that are more efficient than corresponding ones that only rely on PCPs. We briefly sketch the intuition for why interactive proof composition, via IOPs, is more efficient. In a composed proof, the prover first writes a part0of the proof (e.g., in [ALM + 98]0is an evaluation of a low-degree multivariate polynomial, and in [BS08] it is an evaluation of a low-degree univariate polynomial). Then, to demonstrate that0has certain good properties (e.g., it is low degree), the prover also appends a (long) sequence of sub-proofs, where each sub-proof allegedly demonstrates to the verifier that a subset of entries of0is “good”. Afterwards, in another invocation of the recursion, the prover appends to each sub-proof a sequence of sub-sub-proofs, and so on. A crucial observation is that the verifier typically queries locations of only a small number of such sub-proofs; moreover, once the initial proof0is fixed, soundness is not harmed if the verifier randomly selects the set of sub-proofs he wants to see and tells this to the prover. In sum, in many PCP constructions (including the aforementioned ones), *the proof length can be greatly* *reduced via interaction between the prover and verifier*, via an IOP. As yet another example, [RRR16] use IOPs to obtain doubly-efficient constant-round IPs for polynomial- time bounded-space computations. The result relies on an “amortization theorem” for IOPs that states that, for a so-called *unambiguous* IOPs, batch verification of multiple statements can be more efficient than simply running an independent IOP for each statement.

**Remark 1.1** (comparison with IPCP)**.** Kalai and Raz [KR08] introduce and study *interactive PCPs* (IPCPs), a model of proof system that also combines aspects of IPs and PCPs, but in a different way: an IPCP is an IP in which the verifier additionally has oracle access to a PCP provided before the start of the interactive proof. An IPCP can be viewed as a special case of an IOP, i.e., it is an IOP in which the verifier has oracle access to the first prover message, but must read in full subsequent prover messages. The works of [KR08, GKR08] show that boolean formulas with *n* variables, size *m*, and depth *d* have IPCPs where the PCP’s size is polynomial in *d* and *n* and the communication complexity of the subsequent IP is polynomial in *d* and log*m*. This shows that even IPCPs give efficiency advantages over both IPs and PCPs given separately.

### 1.3.2 From interactive oracle proofs to non-interactive random-oracle proofs

We give a polynomial-time transformation that maps any public-coin interactive oracle proof (IOP) to a corresponding non-interactive random-oracle proof (NIROP). We prove that the soundness of the output proof is tightly characterized by the soundness of the IOP verifier against *state restoration attacks*, a class of rewinding attacks on the verifier that we now describe. At a high level, a state restoration attack against an IOP verifier works as follows: the malicious prover and the verifier start interacting, as they normally would in an IOP; at any moment, however, the prover can choose to set the verifier to any state at which the verifier has previously been, and the verifier then continues

|𝑓 𝑓|… 𝑓�||�|
|---|---|---|---|
|𝑚||||
|||𝑚||
|𝑚||||
|�||𝑚�||
|𝑚||� 𝑚�|Figure 3: A non-interactive random-oracle proof system.|

𝑓 𝑓 … 𝑓 � �

𝑃 𝑉 ℙ 𝕍 � �𝑃 𝑉 ℙ 𝕍

Figure 2: An interactive oracle proof system.

onwards from that point with fresh randomness. Of course, if the prover could restore the verifier’s state an unbounded number of times, the prover would eventually succeed in making the verifier accept. We thus only consider malicious provers that interact with the verifier for at most a certain number of rounds: for *b 2* N, we say a prover is *b-round* if it plays at most *b* rounds during any interaction with any verifier. Then, we say that an IOP has state restoration soundness *s*sr(①*;b*) if every *b*-round state-restoring prover cannot make the IOP verifier accept an instance ① (not in the language) with probability greater than *s*sr(①*;b*). Informally, our result about transforming IOPs into NIROPs can be stated as follows.

**Theorem 1.2** (IOP*!* NIROP)**.** *There exists a polynomial-time transformation T such that, for every relation* *R, if* (*P;V*) *is a public-coin interactive oracle proof system for R with state restoration soundness s*sr(①*;b*)*,* *then* (P*;*V) := *T* (*P;V*) *is a non-interactive random-oracle proof system for R with soundness*

*s*sr(①*;m*) + *O*(*m²*2)*;*

*where m is an upper bound on the number of queries to the random oracle that a malicious prover can* *make, and is a security parameter. The aforementioned soundness is tight up to small factors. (Good state* *restoration soundness can be obtained, e.g., via parallel repetition as in Remark 1.6.)*

Moreover, we prove that the transformation *T* is benign in the sense that it preserves natural properties of the IOP. Namely, (1) the runtimes of the NIROP prover and verifier are linear in those of the IOP prover and verifier (up to a polynomial factor in); (2) the NIROP is a proof of knowledge if the IOP is a proof of knowledge; and (3) the NIROP is (malicious-verifier) statistical zero knowledge if the IOP is honest-verifier statistical zero knowledge. See Theorem 7.1 for the formal statement; the statement employs the notion of *restricted state restoration soundness* (see Section 5.4) as it allows for a tighter lower bound on soundness. An immediate application is obtaining blackbox unconditional ZK in the random oracle model with quasilinear prover and polylogarithmic verifier, improving on results of [IMSX15], by plugging the work of [BCGV16] into our compiler. Our compiler can be viewed as a generalization of the Fiat–Shamir paradigm for public-coin IPs [FS86, PS96], and of the “CS proof” constructions of Micali [Mic00] and Valiant [Val08] for PCPs. Our analysis of the compiler gives, in particular, a unified understanding of all of these constructions, and motivates the study of state restoration attacks, not only for IOPs, but also for IPs and PCPs. (Indeed, we are not aware of works that study the security of the Fiat–Shamir paradigm, in the random oracle model, applied to a public-coin IP with arbitrary number of rounds; the analyses that we are aware of focus on the case of 2 rounds.) Our next contribution is a first set of results about such kinds of attacks, as described in the next section.

**Remark 1.3** (resetting, backtracking)**.** We compare state restoration soundness with other soundness notions:

State restoration attacks generalize resetting attacks [BGGL01], in which the prover invokes multiple verifier incarnations with the *same randomness prefix*. Resettable soundness is thus bounded from above by state restoration soundness (and so bounds on the former do not always imply bounds on the latter). State restoration is closely related to backtracking [BD16]. The two notions differ in that: (1) backtracking “charges” more for restoring verifier states that are further into the past, and (2) backtracking also considers the case of the verifier restoring states of the prover (as part of the completeness property of the protocol); backtracking soundness is thus polynomially related to state restoration soundness. Bishop and Dodis [BD16] give a compiler from a public-coin IP to an error-resilient IP, whose soundness is related to the backtracking soundness of the original IP; essentially, they use hashing techniques to limit a malicious prover impersonating an adversarial channel to choosing when to backtrack the protocol. Their setting is a completely different example in which backtracking, and thus state restoration, plays a role.

**Remark 1.4** (zero knowledge and programmability)**.** There are several notions of zero knowledge in the random oracle model, depending on “how programmable” the random oracle is (see Remark 2.2). The notion that we use is zero knowledge in the explicitly-programmable random oracle (EPRO) model; the stronger notion in the non-programmable random oracle model is not achievable for NIROPs (see Appendix C). (And, as in prior works, soundness and proof of knowledge do not rely on any programming of the random oracle.)

### 1.3.3 State restoration attacks on interactive oracle proofs

The analysis of our transformation from public-coin IOPs to NIROPs highlights state restoration soundness as a notion that merits further study. We provide two results in this direction. First, we prove tight upper and lower bounds on state restoration soundness in terms of the IOP’s (standard) soundness and round complexity.

**Theorem 1.5.** *For any relation R, public-coin k-round IOP for R, and instance* ① *not in the language of R,*

<u>b</u> *b* 2 *8 b k*(①) + 1*, s*(①)(1 *o*(1)) *s*sr(①*;b*) *s*(①)*;* *k*(①) + 1 *k*(①) + 1

*where s*sr(①*;b*) *is the state restoration soundness of IOP and s*(①) *its (standard) soundness for the instance* ①*.* *Also, the bounds are tight: there are IOPs that meet the lower bound and IOPs that meet the upper bound.*

**Remark 1.6** (good state restoration soundness)**.** One way to obtain state restoration soundness 2 in the general case is to apply *r*-fold parallel repetition to the IOP with *r* = ( <u>k</u> log <u>log</u> *s* <u>b</u> ( <u>+</u> ①) ); note that *r* is polynomially bounded for natural choices of *k;b;*. This choice of *r* is pessimistic, because for IOPs that do not meet the upper bound (e.g., they are “robust” against such attacks) a smaller choice of *r* suffices.

Second, we study the structure of optimal state restoration attacks: we prove that, for any public-coin IOP, there is a simple state restoration attack that has optimal expected cost, where cost is the number of rounds until the prover wins. This result relies on a correspondence that we establish between IOP verifiers and certain games, which we call *tree exploration games*, pitting one player against Nature. We go in more detail about this result in later sections (see Section 1.4 and Section 8). 2 We note that [BGGL01] prove an analogous upper bound on the more restrictive notion of resettable soundness (see Remark 1.3), and does not imply our bound. Also, [BD16] prove an analogous, weaker upper bound on the related notion of backtracking soundness (see Remark 1.3). Neither of the two studies lower bounds, or tightness of bounds.

### 1.4 Techniques

We summarize the techniques that we use to prove our technical contributions. **The transformation.** Our transformation maps any public-coin IOP to a corresponding NIROP, and it generalizes two transformations that we now recall. The first transformation is the Fiat–Shamir paradigm [FS86, PS96], which maps any public-coin IP to a corresponding NIROP, and it works as follows. The NIROP prover runs the interaction between the IP prover and the IP verifier “in his head”, by setting the IP verifier’s next message to be the output of the random oracle on the query that equals the transcript of previously exchanged messages. The NIROP prover sends a non-interactive proof that contains the final transcript of interaction; the NIROP verifier checks the proof’s validity by checking that all of the IP verifier’s messages are computed correctly through the random oracle. The second transformation is the “CS proof” construction of Micali [Mic00] and Valiant [Val08], which maps any PCP to a corresponding NIROP, and it works as follows. The NIROP prover first commits to the PCP via a Merkle tree [Mer89a] based on the random oracle, then queries the random oracle with the root of this tree to obtain randomness for the PCP verifier, and finally sends a non-interactive proof that contains the root as well as authentication paths for each query by the PCP verifier to the PCP; the NIROP verifier checks the proof’s validity by checking that the PCP verifier’s randomness is computed correctly through the random oracle, and that all authentication paths are valid. (The transformation can be viewed as a non-interactive variant of Kilian’s protocol [Kil92, BG08] that uses ideas from the aforementioned Fiat–Shamir paradigm.) Our transformation takes as input IOPs, for which both IPs and PCPs are special cases, and hence must support both (i) multiple rounds of interaction between the IOP prover and IOP verifier, as well as (ii) oracle access by the IOP verifier to the IOP prover messages. Given an instance ①, the NIROP prover thus uses the random oracle to run the interaction between the IOP prover and the IOP verifier “in his head” in a way that combines the aforementioned two approaches, as follows. First, the NIROP prover computes an initial value 0:= (①). Then, for *i* = 1*;* 2*;:::*, it simulates the *i*-th round by deriving the IOP verifier’s *i*-th message *mi*as (①*ki* 1), compressing the IOP prover’s *i*-th message *fi*via a Merkle tree to obtain the root rt*i*, and

|computing the new value||:=|k ). The values|; ;::: are related by the Merkle–Damgard||
|---|---|---|---|---|---|
|||i k(①)|i i 1|0 1|k(①)|

*i*(rt*i i* 1 0 1˚ transform [Dam89, Mer89b] that, intuitively, enforces ordering between rounds. If there are *k*(①) rounds of interaction, then (①*k*) is used as randomness for the queries to *f₁;:::;fk*(①). The NIROP prover provides in the non-interactive proof all the roots rt*i*, the final value, the answers to the queries, and an authentication path for each query. This sketch omits several details; see Section 6 and Figure 6. **Soundness analysis of the transformation.** We prove that the soundness of the NIROP produced by the above transformation is tightly characterized by the state restoration soundness of the underlying IOP. This characterization comprises two arguments: an upper bound and a lower bound on the NIROP’s soundness. We only discuss the upper bound here: proving that the soundness (error) of the NIROP is at most the soundness (error) of the IOP against state restoration attacks, up to small additive factors. The upper bound essentially implies that all that a malicious prover P~ can do to attack the NIROP verifier is to conduct a state restoration attack against the underlying IOP verifier “in his own head”: roughly, P~ can provide multiple inputs to the random oracle in order to induce multiple fresh samples of verifier messages for a given round so to find a lucky one, or instead go back to previous rounds and do the same there. In more detail, the proof itself relies on a reduction: given a malicious prover P~ against the NIROP verifier, we show how to construct a corresponding malicious prover *P*~ that conducts a state restoration attack against the underlying IOP verifier. We prove that the winning probability of *P*~ is essentially the same as that of P~; moreover, we also prove that the reduction preserves the resources needed for the attack in the sense that if P~ asks at most *m* queries to the random oracle, then *P*~ plays at most *m* rounds during the attack.

Intuitively, the construction of *P*~ in terms of P~ must use some form of extraction: P~ outputs a non- interactive proof that contains only (i) the roots that (allegedly) are commitments to underlying IOP prover’s messages, and (ii) answers to the IOP verifier’s queries and corresponding authentication paths; in contrast, *P* ~ needs to actually output these IOP prover’s messages. In principle, the malicious prover P~ may not have “in mind” any underlying IOP prover, and we must prove that, nevertheless, there is a way for *P*~ to extract some IOP prover message for each round that convince the verifier with the claimed probability. Our starting point is the extractor algorithm of Valiant [Val08] for the “CS proof” construction of Micali [Mic00]: Valiant proves that Micali’s NIROP construction is a proof of knowledge by exhibiting an algorithm, let us call it *Valiant’s extractor*, that recovers the underlying PCP whenever the NIROP prover convinces the NIROP verifier with sufficient probability. Our setting differs from Valiant’s in that the IOP prover *P*~ obtained from the NIROP prover P~ needs to be able to extract multiple times, “on the fly”, while interacting with the IOP verifier; this more complex setting can potentially cause difficulties in terms of extractor size (e.g., if relying on rewinding the NIROP prover) or correlations (e.g., when extracting multiple times from the same NIROP prover). We tackle the more complex setting in two steps. First, we prove an extractability property of Valiant’s extractor and state it as a property of Merkle trees in the random oracle model (see Section 3.1). Informally, we prove that, except with negligible probability, whenever an algorithm with access to a random oracle outputs multiple Merkle tree roots each accompanied with some number of (valid) authentication paths, it holds that Valiant’s extractor run separately on each of these roots outputs a decommitment that is consistent with each of the values revealed in authentication paths relative to that root. We believe that distilling and proving this extractability property of Valiant’s extractor is of independent interest. Second, we show how the IOP prover *P*~ can interact with an IOP verifier, by successively extracting messages to send, throughout the interaction, by invoking Valiant’s extractor multiple times on P~ relative to different roots. The IOP prover *P*~ does not rely on rewinding P~, and its complexity is essentially that of a single run of P~ plus a small amount of work. **Preserving proof of knowledge.** We prove that the above soundness analysis can be adapted so that, if the underlying IOP is a proof of knowledge, then we can construct an extractor to show that the resulting NIROP is also a proof of knowledge. **Preserving zero knowledge.** We prove that, if the underlying IOP is *honest-verifier* statistical zero knowl- edge, then the resulting NIROP is statistical zero knowledge (i.e., is a non-interactive statistical zero knowl- edge proof in the explicitly-programmable random oracle model). This is because the transformation uses a Merkle tree with suitable privacy guarantees (see Section 3.2) to construct the NIROP. Indeed, the authenti- cation path for a leaf in the Merkle tree reveals the sibling leaf, so one must ensure that the sibling leaf does not leak information about other values; this follows by letting leaves be commitments to the underlying values. A Merkle tree with privacy is similarly used by [IMS12, IMSX15], along with honest-verifier PCPs, to achieve zero knowledge in modifications of Kilian’s [Kil92, BG08] and Micali’s [Mic00] constructions. **Understanding state restoration attacks.** We prove tight upper and lower bounds to state restoration soundness in terms of the IOP’s (standard) soundness and round complexity *k*. The upper bound takes the form of a reduction: given a *b*-round state-restoring malicious prover *P*~srthat makes the IOP verifier accept with probability *s*sr, we construct a (non state-restoring) malicious prover *P*~ that makes the IOP verifier *b* 1~ internally simulates ~ accept with probability at least *k*+1 *s*sr. Informally, *P P*sr, while interacting with the “real” IOP verifier, as follows: *P*~ first selects a random subset *S* of *f*1*;:::;bg* with cardinality *k* + 1, and lets *S*[*i*] be the *i*-th smallest value in *S*; then, *P*~ runs *P*~srand simulates its state restoration attack on a “virtual” IOP verifier, executing round *j* (a) by interacting with the real verifier if *j* = *S*[*i*] for some *i*; (b) by sampling fresh randomness otherwise. While this reduction appears wasteful (since it relies on *S* being a good guess),

we show that there are IOPs for which the upper bound is tight. In other words, the sharp degradation as a function of round complexity (for large *b*, *k*+1 *b* *b* *k*+1 *=*(*k* + 1)!) is inherent for some choices of IOPs; this also gives a concrete answer to the intuition that compiling IOPs with large round complexity to NIROPs is “harder” (i.e., incurs in a greater soundness loss) than for IOPs with small round complexity. As for the lower bound on state restoration soundness, it takes the form of a universal state restoration attack that always achieves the lower bound; this bound is also tight. While state restoration soundness may be far, in the worst case, from (standard) soundness for IOPs with large round complexity, it need not always be far. We thus investigate state restoration soundness for any particular IOP, and derive a simple attack strategy (which depends on the IOP) that we prove has optimal expected cost, where cost is the number of rounds until the prover wins. To do so, we “abstract away” various details of the proof system to obtain a simple game-theoretic notion, which we call *tree exploration games*, that pits a single player against Nature in reaching a node of a tree with label 1. Informally, such a game is specified by a rooted tree *T* and a predicate function that maps *T*’s vertices to *f*0*;* 1*g*. The game proceeds in rounds: in the *i*-th round, a subtree *Si* 1*T* is *accessible* to the player; the player picks a node *v 2 Si* 1, and Nature randomly samples a child *u* of *v*; the next accessible subtree is *Si*:= *Si* 1*[fug*. The initial *S₀* is the set consisting of *T*’s root vertex. The player wins in round *r* if there is *v 2 Sr*with (*v*) = 1. We establish a correspondence between state restoration attacks and strategies for tree exploration games, and then show a simple greedy strategy for such games with optimal expected cost. Via the correspondence, a strategy’s cost determines whether the underlying IOP is strong or weak against sate restoration attacks.

### 1.5 Roadmap

The rest of this paper is organized as follows. In Section 2, we provide basic notations and definitions, including for Merkle trees and non-interactive random-oracle proofs (NIROPs). In Section 3, we state and prove the extractability and privacy properties of Merkle trees that we use in this work. In Section 4, we introduce interactive oracle proofs (IOPs), the new proof system that we study. In Section 5, we define state restoration attacks against IOPs and present our results about them. In Section 6, we describe a transformation for compiling IOPs into NIROPs; after that, in Section 7, we present our tight analysis of this transformation. In Section 8, we define tree exploration games and present our results about them.

## 2 Preliminaries

### 2.1 Basic notations

We denote the security parameter by. We let *f* = *O* (*g*) mean there exists *c >* 0 such that *f* = *O*( *c*

*g*).
For *f* : *f*0*;* 1*g!* R, we define *f*^: N*!* R as *f*^(*n*) := max*x2f*0*;*1*gn f* (*x*). **Languages and relations.** We denote by *R* a relation consisting of pairs (①*;*✇), where ① is the *instance* and ✇ is the *witness*, and by *Rn*the restriction of *R* to instances of size exactly *n*. We denote by *L* (*R*) the language corresponding to *R*. For notational convenience, we define *L* (*Rn*) := *f*① *2f*0*;* 1*g* *n* *j* ① *2=* *L* (*R*)*g*. **Random oracles.** We denote by *U* () the uniform distribution over all functions : *f*0*;* 1*g!f*0*;* 1*g* (implicitly defined by the probabilistic algorithm that assigns, uniformly and independently at random, a -bit string to each new input). If is sampled from *U* (), then we say that is a *random oracle*. Given an oracle algorithm *A*, NumQueries(*A;*) is the number of oracle queries that *A* makes. We say that *A* is *m-query* if NumQueries(*A;*) *m* for any *2U*(). **Statistical distance.** The statistical distance between two discrete random variables *X* and *Y* with support <u>1</u> P *V* is (*X*; *Y*) := 2 *v2V* *j*Pr[*X* = *v*] Pr[*Y* = *v*]*j*. We say that *X* and *Y* are*-close* if (*X*; *Y*).

**Remark 2.1.** An oracle *2U*() outputs bits. Occasionally we need to output more than bits; in such cases (we point out where), we implicitly extend ’s output via a simple strategy, e.g., we set *y* := *y₁ky₂k* where *yi*:= (*ikx*) and prefix 0 to all inputs that do not require an output extension.

### 2.2 Merkle trees

We use Merkle trees [Mer89a] based on random oracles as succinct commitments to long lists of values for which one can cheaply decommit to particular values in the list. Concretely, a *Merkle-tree scheme* is a tuple MERKLE = (MERKLE*:* GetRoot*;*MERKLE*:* GetPath*;*MERKLE*:* CheckPath) that uses a random oracle sampled from *U* () and works as follows. MERKLE*:* GetRoot (v)*!* rt. Given input list v = (*vi*) *n* *i*=1, the *root generator* MERKLE*:* GetRoot computes, in time *O* (*n*), a root rt of the Merkle tree over the list v. MERKLE*:* GetPath (v*;i*)*!* ap. Given input list v and index *i*, the *authentication path generator* MERKLE*:* GetPath computes the authentication path ap for the *i*-th value in v. MERKLE*:* CheckPath (rt*;i;v;* ap)*! b*. Given root rt, index *i*, input value *v*, and authentication path ap, the *path checker* MERKLE*:* CheckPath outputs *b* = 1 if ap is a valid path for *v* as the *i*-th value in a Merkle tree with root rt; the check can be carried out in time *O* (log₂ *n*). We assume that an authentication path ap contains the root rt, position *i*, and value *v*; accordingly, we define Root(ap) := rt, Position(ap) := *i*, and Value(ap) := *v*. Merkle trees are well known, so we do not review their construction. Less known, however, are the hiding and extractability properties of Merkle trees that we rely on in this work; we describe these in Section 3.

### 2.3 Non-interactive random-oracle proofs

A *non-interactive random-oracle proof system* for a relation *R* with soundness *s* : *f*0*;* 1*g!* [0*;*1] is a tuple (P*;*V), where P*;*V are (oracle) probabilistic algorithms, that satisfies the following properties.

1.COMPLETENESS. For every (①*;*✇) *2 R* and *2* N,
*U* () Pr V (①*;*) = 1 = 1 *:* P (①*;*✇)

2.SOUNDNESS. For every ① *2= L*(*R*), *m*-query P~, and *2* N,
*U* () Pr V (①*;*) = 1 ~ *s*(①*;m;*) *:* P

**Complexity measures.** Beyond soundness, we consider other complexity measures. Given *p* : *f*0*;* 1*g!* N, we say that (P*;*V) has proof length *p* if has length *p*(①*;*). Given *t*prv*;t*ver: *f*0*;* 1*g!* N, we say that (P*;*V) has prover time complexity *t*prvand verifier time complexity *t*verif P (①*;*✇) runs in time *t*prv(①*;*) and V (①*;*) runs in time *t*ver(①*;*). In sum, we say that (P*;*V) has complexity (*s;p;t*prv*;t*ver) if (P*;*V) has soundness *s*, proof length *p*, prover time complexity *t*prv, and verifier time complexity *t*ver. **Proof of knowledge.** Given *e* : *f*0*;* 1*g!* [0*;*1], we say that (P*;*V) has proof of knowledge *e* if there exists a probabilistic polynomial-time algorithm E (the *extractor*) such that, for every ①, *m*-query P~, and *2* N, h i P ~ *m U* () Pr (①*;*✇) *2 R* ✇ E (①*;* 1*;*1 ) Pr V (①*;*) = 1 ~ *e*(①*;m;*) *:* P

P ~ *m m* ~ The notation E (①*;* 1*;*1 ) means that E receives as input (①*;* 1*;*1 ) and may obtain an output of P for choices of oracles, as we now describe. At any time, E may send a-bit string *z* to P~; then P~ interprets *z* as the answer to its last query to (if any) and then continues computing until it reaches either its next query or its output; then this query or output is sent to E (distinguishing the two cases in some way); in the latter case, P~ goes back to the start of its computation (with the same randomness and any auxiliary inputs). Throughout, the code, randomness, and any auxiliary inputs of P~ are not available to E. **Zero knowledge.** Given *z* : *f*0*;* 1*g!* [0*;*1], we say that (P*;*V) has *z*-statistical zero knowledge (in the explicitly-programmable random oracle model) if there exists a probabilistic polynomial-time algorithm S (the *simulator*) such that, for every (①*;*✇) *2 R* and unbounded distinguisher *D*, the following two probabilities are *z*(①*;*)-close:

[] *U* () *U* () Pr *D* () = 1 and Pr *D* () = 1 *:*

(*;*) S (①) P (①*;*✇)
Above, [] is the function such that, given an input *x*, equals (*x*) if is defined on *x*, or (*x*) otherwise.

**Remark 2.2.** Zero knowledge in the random oracle model can be defined in several ways. Wee [Wee09] details the following hierarchy. (i) *Fully-programmable random oracle (FPRO):* the simulator has access to the random oracle but the distinguisher does not; (ii) *Explicitly-programmable random oracle (EPRO)* *[BR93]:* the simulator has access to the random oracle and also outputs a function, but the distinguisher has access to the same oracle modified so that a query to an input *x* in the domain of is answered with (*x*); (iii) *Non-programmable random oracle (NPRO) [Nie02, Pas03]:* the simulator and the distinguisher have access to the same random oracle. ZK in the NPRO implies ZK in the EPRO, and the latter implies ZK in the FPRO; there exist protocols that are ZK in the EPRO but not in the NPRO, and ones that are ZK in the FPRO but (assuming one-way permutations exist) not in the EPRO. The above definition that we use for NIROPs follows ZK in the EPRO. We do not use the stronger notion of ZK in the NPRO, since Pass shows that it cannot be achieved for non-trivial relations (see Appendix C). In particular, zero-knowledge NIROPs are not *deniable* in the sense of [Pas03].

## 3 Extractability and privacy of Merkle trees

We describe the specific extractability and privacy properties of Merkle trees that we rely on in this work.

### 3.1 Extractability

We rely on a certain extractability property of Merkle trees: there is an efficient procedure for extracting the committed list in a Merkle-tree scheme. We call the procedure *Valiant’s extractor*, and denote it by VE, because it is described in [Val08]. Our presentation of the extractor and its guarantee differs from [Val08] because our use of it in this work requires “distilling” a more general property; see Lemma 3.2 below. **The extractor.** For any oracle algorithm *A*, integers *‘;i* *?* *;i*max*>* 0 with *i* *?* *2f*1*;:::;i*max*g*, and sampled from *U* (), the procedure VE, given input (*A;‘;i* *?* *;i*max) and with oracle access to, works as follows.

1. Run *A* until it has asked *i*maxunique queries to (and abort if *A* asks fewer than *i*max). Along the way,

||;:::;|and answers||( );:::;(|), in order and omitting duplicates.|||
|---|---|---|---|---|---|---|---|
||1 i i0|i i1|i0|1|i i|i1||
|i|i0|i1||i|j||i|
|i||||j i 1 ? max|i 1|i max|i j|
||||max|||||
 record the queries1 *i*max 1 *i*max
2. Parse each query as *k* where are the first bits of and the second bits. For brevity, we write *z 2* if *z* = or *z* =. (If a query has length not equal to 2, then *z =2* for all *z*.)
3.If there exist indices *i;j* such that *i 6*= *j* and () = (), abort.
4.If there exist indices *i;j* such that *i j* and () *2*, abort.
5. Construct a directed graph *G* with nodes *V* = *f;:::;*max*g* and edges *E* = *f*(*;*) : (*j*) *2ig*. Note that *G* is acyclic, every node has out-degree 2, and*;:::;*maxis a (reverse) topological ordering.
6. Output v, the string obtained by traversing in order the first *‘* leaf nodes of the depth-*d*log₂ *‘e* binary tree rooted at*?* and recording the first bit of each node. If any such node does not exist, set this entry to 0. A sample execution of the extractor is depicted in Figure 4. **Remark 3.1.** The queries to asked by VE (*A;‘;i;i*) equals the first *i* queries to asked by *A* (provided that *A* does not ask fewer than *i* queries). Later on we use this fact. **The extractor’s guarantee.** We interpret *A*’s output as containing a (possibly empty) list of tuples of the form (rt*;i;v;* ap), where rt is a root, *i* an index, *v* a value, and ap an authentication path.
3 We define the following events:

(i) *E₁* is the event that, for each tuple (rt*;i;v;* ap) output by *A*, MERKLE*:* CheckPath(rt*;i;v;* ap) = 1; (ii) *E₂* is the event that, for each rt *2f*0*;* 1*g*, there exists an integer *‘*rtsuch that if *A* outputs a tuple of the form (rt*;;;* ap) then ap is an authentication path for a *‘*rt-leaf Merkle tree; and

||rt||
|---|---|---|
||j|max|
|rt rt max||i|

(iii) *E₃* is the event that, for every rt *2f*0*;* 1*g* such that *A* outputs some tuple of the form (rt*;;;*), there is a unique *j*rt*2 f*0*;:::;* NumQueries(*A;*)*g* such that (rt) = rt and, for every *i 2* *fj*rt*;:::;* NumQueries(*A;*)*g*, v := VE (*A;‘;j;i*) is such that v’s *i*-th entry equals *v* for any tuple of the form (rt*;i;v;* ap) output by *A*. The extractability property that we rely on is the following.

**Lemma 3.2.** *Let A be a m-query algorithm. Then*

Pr [(*:*(*E₁ ^ E₂*)) *_ E₃ j U* ()] 1 (*m²* + 1)2 *:*

*Proof.* Observe the following. By the union bound, the probability that there exist indices *i;j* such that (*i 6*= *j*) *^* ( (*i*) = (*j*)) or (*i j*) *^* ( (*j*) *2i*) is at most *m²*2. If this occurs, we say that *A* has found a *collision*. 3 Note that *A*’s output may contain additional information not of the above form; if so, we simply ignore it for now.

The probability that, for a tuple (rt*;i;v;* ap) output by *A* such that MERKLE*:* CheckPath(rt*;i;v;* ap) = 1, the authentication path ap contains a node with no corresponding query is at most 2, since this would mean that *A* has ‘guessed’ the answer to the query. In other words, no matter what strategy *A* uses to generate the result, if it does not query the oracle on this input then it can perform no better than chance. Now suppose that *E₁ ^ E₂* occurs with probability. Then, with probability at least (*m²* + 1)2 :

(a) for each root rt output by *A* there is a unique query*i?* such that (*i?*) = rt; (b) for each root rt output by *A*, if an authentication path ap claims to have root rt then ap appears in the tree rooted at*i?* in *G*; and
(c) the condition in the VE’s Step 3 or Step 4 does not hold. In such a case we may take *j*rt:= *i*
*?*, and then VE (*A;‘*rt*;j*rt*;i*max) outputs a list v with the desired property. Hence, Pr[*E₁ ^ E₂ ^ E₃*] (*m²* + 1)2. The predicate is also satisfied if *:*(*E₁ ^ E₂*) occurs, which is the case with probability 1 and is disjoint from *E₁ ^ E₂ ^ E₃*. The lemma follows.

𝜌

queries & construct VE 𝜌 𝑎 ∥ 𝑎 root answers graph 𝐴 𝜌 𝑏 ∥ 𝑏 𝜌 𝑏 ∥ 𝑏 𝜃 = 𝑣 ∥ 𝑟 𝜃 𝜃 = 𝜌(𝜃 ) ∥ 𝑥 𝜃 𝜌 𝑣 ∥ 𝑟 𝜌 𝑣 ∥ 𝑟 𝜌 𝑣 ∥ 𝑟 𝜌 𝑣 ∥ 𝑟 leaves 𝜃 = 𝑣 ∥ 𝑟 𝜃 𝑣 𝜃 = 𝜌(𝜃 ) ∥ 𝜌(𝜃 ) 𝜃 𝜃 𝑣 values 𝜃 = 𝑦 𝜃 𝑣 𝑣 𝑣 𝑣 𝜃 = 𝜌(𝜃 ) ∥ 𝜌(𝜃 ) 𝑟 𝑟 𝑟 𝑟 randomness

Figure 4: A diagram of an execution of Valiant’s Figure 5: A diagram of the data structure of a

extractor VE, with input parameters *‘* = 2, *i* *?* = 4, Merkle tree with privacy. An authentication path and *i*max = 6. for *v₂* is shaded; the corresponding truncated au- thentication path is the same minus *r₂* and *v₂*.

### 3.2 Privacy

We rely not only on the fact that the root rt of a Merkle tree is hiding, but also on the fact that an authentication path ap reveals no information about values other than the decommitted one. The latter property can be ensured via a slight tweak of the standard construction of Merkle trees: when committing to a list v = (*vi*) *n* *i*=1,

|the i-th leaf is not v|but, instead, is a hiding commitment to v|||(v kr )|
|---|---|---|---|---|
||i|||i i|
||i||||
|i||i|||
|i i|i i|i|0i 0i 1 i n||
||n||||

*i i*. In our case, we will store the value*i i* in the *i*-th leaf, where *r 2f*0*;* 1*g²* is drawn uniformly at random; see Figure 5. (An authentication path for *v* then additionally includes *r*, and path verification is modified accordingly.) In what follows, we regard (*v kr*) as a *leaf*, rather than *v*; moreover, a *truncated authentication path* ap is identical to ap*i*except that it does not contain *r* or *v*, and the *truncated Merkle tree* for v is *T*v *0* := (ap). Note that the *same* randomness r *2f*0*;* 1*g²* is used by MERKLE*:* GetRoot and MERKLE*:* GetPath (to be “in sync”). We summarize the privacy property of Merkle trees as above via the following definition and lemma.

**Definition 3.3.** *A Merkle-tree scheme has z*(*n;*)*-statistical privacy if there exists a probabilistic polynomial-* *time simulator S such that, for every list* v = (*vi*) *n* *i*=1 *and unbounded distinguisher D, the following two*

*probabilities are z*(*n;*)*-close:* 2 3 *U* () 6 *I f*1*;:::;ng* rt MERKLE*:* GetRoot (v; r) 7 Pr 6 4 7 5 r *D* (rt*;*(ap*i*)*i2I*) = 1 *I D* *8 i 2 I;* ap*i*MERKLE*:* GetPath (v*;i*; r)

*and* 2 3 *U* () *I f*1*;:::;ng* 5 Pr 4 *I D :* *D* (rt*;*(ap*i*)*i2I*) = 1 (rt*;*(ap*i*)*i2I*) *S* (*n;*(*i;vi*)*i2I*)

We make no assumption on the power of the distinguisher *D* in the definition above. In particular, *D* may query the random oracle at every input, and use the information to attempt to learn *vi*for some *i =2 I*. For example, for some, it is the case that Pr*r*[*v* = 1 *j* (*vkr*) = *x*] Pr*r*[*v* = 0 *j* (*vkr*) = *x*] for *x* = (*v₂kr₂*), in which case *D* can determine *v₂* from ap₁ with good accuracy. The next lemma shows that the probability that *D* gains a significant statistical advantage in this way (or otherwise) is negligible in.

**Lemma 3.4.** *There exists a Merkle-tree scheme having z*(*n;*)*-statistical privacy with z*(*n;*) := *n*2 *=*4+2 *.*

*Proof.* Given v = (*vi*) *n* *i*=1 and *I f*1*;:::;ng*, we define a sequence of random variables *W₀;:::;W‘*for which *W₀* = *T*v *0* and *W‘*contains the output of a probabilistic polynomial time simulator *S* (see below) on input (*n;*(*i;vi*)*i2I*) and with access to a random oracle. The random variables are defined as follows:

We obtain *W₁* from *W₀* by (i) replacing each leaf node *j 2* [*n*] *I* with an independently uniformly random string in *f*0*;* 1*g*; (ii) ‘marking’ each such leaf; and (iii) recomputing the rest of the tree.

For *i 2f*2*;:::;‘g*, we obtain *Wi*from *Wi* 1by choosing a node whose children are both marked and replacing its value with a string drawn uniformly at random from *f*0*;* 1*g*, marking that node, and then recomputing the Merkle tree above it. (Note that the authentication paths for the leaves *i 2 I* are still valid with respect to the root and each other.) The last *W‘*is when there are no such nodes remaining.

We now argue that the statistical distance between *W₀* and *W‘*is at most *n*2 *=*4+1. For this, we require the following two facts:

FACT 1. For all but a 2 fraction of *2 U*(), (*r*) is 2 *=*4 -close to *r⁰* where *r* is random in *f*0*;* 1*g²* and *r⁰* is random in *f*0*;* 1*g*. (*Proof:* For *z 2 f*0*;* 1*g* and *2 U*() fixed, define (*z*) := *j*Pr[ (*r*) = *z*] Pr[*X* = *z*]*j* where *r 2f*0*;* 1*g²* and *X 2f*0*;* 1*g* are random. Clearly Pr[*X* = *z*] = 2.

|||5=4|2||
|---|---|---|---|---|
|5=4 n|n|1 2 z2f0;1g|5=4|=4 i|

By a Chernoff bound, for every *z 2f*0*;* 1*g* : Pr [ (*z*) 2 *j U* ()] 2. By a union bound, Pr [*9 z 2f*0*;* 1*g* s.t. (*z*) 2 *j U* ()] 2. Hence, with probability at least 1 2 over P, the statistical distance between (*r*) and *X* is at most*z;*2 2 = 2.)

FACT 2. If *X₁;:::;Xn*and *Y₁;:::;Y* are independent random variables such that, for each *i*, *X* and *Yi* are-close, then (*X₁;:::;X*) and (*Y₁;:::;Yn*) are *n*-close.

First we examine the statistical distance between *W₀* and *W₁*: every node we replace has the form (*akr*) for *a 2f*0*;* 1*g*; since (*r*) and (*akr*) are identically distributed, Fact 1 holds for (*akr*) also; thus, using Fact 2 and the fact that we place at most *n* leaves, we deduce that *W₀* and *W₁* are *n*2 *=*4 -close for almost all. Next we examine the statistical distance between *Wi*and *Wi*+1for *i 2f*1*;:::;k* 1*g*: whenever we replace a node with a random string, it is of the form (*r*) where *r 2f*0*;* 1*g²* is random, since we only replace nodes

whose children we have already replaced; so, using Fact 1, *Wi*and *Wi*+1are *n*2 *=*4 -close for almost all. Thus each step in the sequence marks a non-leaf node and *‘* is bounded by the number of non-leaf nodes in

*n*. By the triangle inequality, the statistical distance between *W₀* and *W*.

|T; so ‘|||||is at most n2||
|---|---|---|---|---|---|---|
|v0|||||‘|=4+1|
|i i i2I|i n i=1|i i i i2I|i ‘|i i2I i i i i2I|i i i2I ‘|=4+1|
||||=4+1||||

We now construct the simulator *S*. On input (*n;*(*i;v*)) and with oracle access to, *S* works as follows: (i) set v~ := (~*v*) where *v*~ := *v* for *i 2 I* and *v*~ := 0 for *i 62 I*; (ii) for every *i 2 I*, compute ap MERKLE*:* GetPath (v~*;i*; r), except whenever we require the value of a node which is marked in *W‘*, use a random string in *f*0*;* 1*g*; (iii) compute rt MERKLE*:* GetRoot (v~; r) in the same way; (iv) output (rt*;*(ap)). Note that *S* runs in probabilistic polynomial time since the number of unmarked nodes is at most *jIj*log*n*, and the only marked nodes we consider are those that are siblings of unmarked nodes. Finally, in one case, all the information given to *D* is contained in *W₀* and (*v;r*); in the other case, all the information given to *D* is contained in *W* and (*v;r*). Moreover, *W* was constructed from *W₀* in a way that is independent of (*v;r*). Thus, since these two sets of random variables are *n*2-close, the corresponding outputs of *D* must also be *n*2-close. Choosing uniformly at random, the result follows by the union bound.

## 4 Interactive oracle proofs

We first define *interactive oracle protocols*, and then use these to define *interactive oracle proof systems*. Afterwards, we make some remarks regarding basic complexity-theoretic properties of such proof systems.

### 4.1 Interactive oracle protocols

A *k*-round interactive oracle protocol between two parties, call them Alice and Bob, comprises *k* rounds of interaction. In the *i*-th round of interaction: Alice sends a message *mi*to Bob, which he reads in full; then Bob replies with a message *fi*to Alice, which she can query (via random access) in this and all later rounds. After the *k* rounds of interaction, Alice either accepts or rejects. More precisely, let *k* be in N and *A;B* be two interactive probabilistic algorithms. A *k*-round interactive oracle protocol between *A* and *B*, denoted *hB;Ai*, works as follows. Let *rA;rB*denote the randomness for *A;B*; set *f₀* :=*?* and state₀ :=*?*. For *i* = 1*;:::;k*, in the *i*-th round:

(i)Alice sends a message *mi2f*0*;* 1*g*
*u* *i*, where (*mi;*state*i*) := *A* *f* 0 *;:::;fi* 1 (state*i* 1; *rA*) and *ui2* N; (ii)Bob sends a message *fi2f*0*;* 1*g* *‘* *i*, where *fi*:= *B*(*m₁;:::;mi*; *rB*) and *‘i2* N. The output of the protocol is *m*n:= *A* *f* 0 *;:::;fk* (state*k*; *rA*), and belongs to *f*0*;* 1*g*. The accepting probability of *hB;Ai* is the probability that *m*n= 1 for a random choice of *rA;rB*; this probability is denoted Pr[*hB;Ai* = 1] (leaving *rA;rB*implicit). The query complexity of *hB;Ai* is the number of queries asked by *A* to any of the oracles during the *k* rounds. The proof complexity of *hB;Ai* P *k* is the number of bits communicated by Bob to Alice (i.e., *i*=1 *‘* *i* ). The view of *A* in *hB;Ai*, denoted View*hB;Ai*(*A*), is the random variable (*a₁;:::;aq;rA*) where *aj*denotes the answer to the *j*-th query. **Public coins.** An interactive oracle protocol is *public-coin* if for every *i 2f*1*;:::;kg*: (i) all queries to *f₀;:::;fi* 1before the *i*-th round depend only on *m₁;:::;mi* 1(in particular, the prover knows these queries); (ii) *mi*is random in *f*0*;* 1*g* *u* *i*. We assume, without loss of generality, that in a public-coin protocol Alice does not maintain state (i.e., state*i*=*;*) and postpones any query to after the *k*-th round (i.e., all queries are asked when running *A* *f* 0 *;:::;fk* (state*k*; *rA*)). We can thus take the randomness *rA*to be of the form (*m₁;:::;mk;r*), where *r* is additional randomness that *A* may use of to compute *m*nafter the last round.

### 4.2 Interactive oracle proof systems

An *interactive oracle proof system* for a relation *R* with round complexity *k* : *f*0*;* 1*g!* N and soundness *s* : *f*0*;* 1*g!* [0*;*1] is a tuple (*P;V*), where *P;V* are probabilistic algorithms, that satisfies the following properties.

1. COMPLETENESS. For every (①*;*✇) *2 R*, *hP*(①*;*✇)*;V* (①)*i* is a *k*(①)-round interactive oracle protocol with accepting probability 1.
2. SOUNDNESS. For every ① *2= L*(*R*) and *P*~, *hP;V* ~ (①)*i* is a *k*(①)-round interactive oracle protocol with accepting probability at most *s*(①). **Message lengths.** We assume the existence of polynomial-time functions that determine the message lengths. Namely, for any instance ① and malicious prover *P*~, when considering the interactive oracle protocol *hP;V* ~ (①)*i*, the *i*-th messages *mi*(from *V* (①)) and *fi*(to *V* (①)) lie in *f*0*;* 1*g*
*u* *i*

(①) and *f*0*;* 1*g*
*‘* *i*

(①) respectively.
**Complexity measures.** Beyond round complexity and soundness, we consider other complexity measures. Given *p;q*: *f*0*;* 1*g!* N, we say that (*P;V*) has proof length *p* and query complexity *q* if the proof length and query complexity of *hP;V* ~ (①)*i* are *p*(①) and *q*(①) respectively. (Note that *q*(①) *p*(①) and

P*k*(①) *p*(①) =

|‘ (①).) Given t|;t|! N, we say that (P;V ) has prover time complexity t|||
|---|---|---|---|---|
|i=1 i|prv ver ver|prv ver prv|prv|ver ver|

*i*=1 *i* prv ver : *f*0*;* 1*g*prvand verifier time complexity *t* if *P*(①*;*✇) runs in time *t* (①) and *V* (①) runs in time *t* (①). In sum, we say that (*P;V*) has complexity (*k;s;p;q;t;t*) if (*P;V*) has round complexity *k*, soundness *s*, proof length *p*, query complexity *q*, prover time complexity *t*, and verifier time complexity *t*. **Proof of knowledge.** Given *e* : *f*0*;* 1*g!* [0*;*1], we say that (*P;V*) has proof of knowledge *e* if there exists a probabilistic polynomial-time oracle algorithm *E* (the *extractor*) such that, for every ① and *P*~, *P* ~ ~4 *P* ~ Pr[(①*;E* (①)) *2 R*] Pr[*hP;V* (①)*i* = 1] *e*(①). The notation *E* (①) means that *E* receives as input ① and may interact with *P*~ via rewinding, as we now describe. At any time, *E* may send a partial prover-verifier transcript to *P*~ and then receive *P*~’s next message (which is empty for invalid transcripts) in the subsequent computation step; the code, randomness, and any auxiliary inputs of *P*~ are not available to *E*. **Honest-verifier zero knowledge.** Given *z* : *f*0*;* 1*g!* [0*;*1], we say that (*P;V*) has *z*-statistical honest- verifier zero knowledge if there exists a probabilistic polynomial-time algorithm *S* (the *simulator*) such that, for every (①*;*✇) *2 R*, *S*(①) is *z*(①)-close to View*hP*(①*;*✇)*;V* (①)*i*(*V* (①)). **Public coins.** We say that (*P;V*) is *public-coin* if the underlying interactive oracle protocol is public-coin.

### 4.3 Basic complexity-theoretic properties

Several basic complexity-theoretic properties are straightforward to show and provide different points of comparison with other proof system models.

*Expressivity.* Interactive oracle proofs characterize NEXP (see Appendix A). This is like probabilistically- checkable proofs and multi-prover interactive proofs (which also characterize NEXP), and unlike interactive proofs (which characterize PSPACE).

*Repetition.* Both sequential and parallel repetition of interactive oracle proofs yield (perfect) exponential soundness error reduction (see Appendix B.1). This is like interactive proofs and probabilistically- checkable proofs (where the same holds), and unlike multi-prover interactive proofs (where parallel repetition decays exponentially but not perfectly [Raz95, Hol07]).

*Private vs. public coins.* Any interactive oracle proof system can be converted into a public-coin one with at most two additional rounds. This is like interactive proofs (where the same holds [GS86]), and unlike probabilistically-checkable proofs and multi-prover interactive proofs (where correlations among queries are crucial for soundness). This is because the Goldwasser–Sipser set lower-bound approach [GS86] continues to apply in our setting (since the approach only relies on the verifier’s possible randomness and corresponding messages, which do not differ from the standard setting of interactive proofs).

4 Proof of knowledge *e* implies soundness *s* := *e*. The definition that we use is equivalent to the one in [BG93, Section 6] except that: (a) we use extractors that run in strict, rather than expected, probabilistic polynomial time; and (b) we extend the condition to hold for all ①, rather than for only those in *L* (*R*), so that proof of knowledge implies soundness.

## 5 State restoration attacks on interactive oracle proofs

We introduce state restoration attacks on interactive oracle proofs and discuss our results for these. First, in Section 5.1, we define the notion of state restoration attacks for interactive oracle proof systems; these induce corresponding notions of soundness (and proof of knowledge). Afterwards, in Section 5.2, we provide upper and lower bounds on state restoration soundness as a function of (standard) soundness and round complexity; in Section 5.3, we prove the tightness of these bounds. In Section 5.4, we define restricted state restoration attacks, a sub-class of state restoration attacks that enables us to state our results of Section 7 in a tighter way.

### 5.1 State restoration attacks, and soundness and proof of knowledge against these

In an interactive oracle proof, a malicious prover *P*~ works as follows: for each round *i*, *P*~ receives the *i*-th verifier message *mi*and then sends to the verifier a message *fi*computed as a function of his own randomness and all the verifier messages received so far, i.e., *m₁;:::;mi*. For the case of public-coin interactive oracle proof systems, we also consider a larger class of malicious provers, called *state-restoring provers*. Informally, a state-restoring prover receives in each round a verifier message as well as a *complete verifier state*, and then sends to the verifier a message and a previously-seen complete verifier state, which sets the verifier to that state; this forms a state restoration attack on the verifier. More precisely, let (*P;V*) be a *k*-round public-coin interactive proof system (see Section 4.2) and ① an instance. A complete verifier state cvs of *V* (①) takes one of three forms: (1) the symbol null, which denotes the “empty” complete verifier state; (2) a tuple of the form (*m₁;f₁;:::;mi*), with *i 2f*1*;:::;k*(①)*g*, where

|j|u (①)|‘ (①)|k(①) k(①)|
|---|---|---|---|
|j|j|||

each *mj*is in *f*0*;* 1*g* *u* *j*

(①) and each *fj*is in *f*0*;* 1*g*
*‘* *j*

(①); (3) a tuple of the form (*m₁;f₁;:::;mk*(①)*;fk*(①)*;r*)
where each *m* and *f* is as in the previous case and *r* is the additional randomness of the verifier *V* (①). The interaction between a state-restoring prover *P*~ and the verifier *V* (①) is mediated through a game:

1.The game initializes the list SeenStates to be (null).
2.Repeat the following until the game halts and outputs:
(a)The prover chooses a complete verifier state cvs in the list SeenStates.
(b)The game sets the verifier to cvs.
(c) If cvs = null: the verifier samples a message *m₁* in *f*0*;* 1*g*
*u* 1

(①) and sends it to the prover; the game
appends cvs⁰ := (*m₁*) to the list SeenStates.

(d) If cvs = (*m₁;f₁;:::;mi* 1) with *i 2f*2*;:::;k*(①)*g*: the prover outputs a message *fi* 1in *f*0*;* 1*g*
*‘* *i* 1(①); the verifier samples a message *mi*in *f*0*;* 1*g* *u* *i*

(①) and sends it to the prover; the game appends cvs⁰ :=
cvs*kfi* 1*kmi*to the list SeenStates.

(e) If cvs = (*m₁;f₁;:::;mk*(①)): the prover outputs a message *fk*(①)in *f*0*;* 1*g*
*‘* *k*(①)(①); the verifier samples additional randomness *r*; the game appends cvs⁰ := cvs*kfk*(①)*kr* to the list SeenStates.

||k(①)|k(①)|||f ;:::;f||k(①) V|
|---|---|---|---|---|---|---|---|
|k(①)|V||k|||||

(f) If cvs = (*m₁;f₁;:::;mk*(①)*;fk*(①)*;r*): the verifier computes his decision*b* := *V*
*f* 0 *;:::;fk*(①) (①*;*state*k*(①); *rV*) where state :=*;* and *r* := (*m₁;:::;m;r*); then the game halts and outputs *b*.

Note that there are two distinct notions of a round. *Verifier rounds* are the rounds played by the verifier within a single execution, as tracked by a complete verifier state cvs; the number of such rounds lies in the set *f*0*;:::;k*(①) + 1*g* (the extra (*k*(①) + 1)-th round represents the verifier *V* sampling *r* after receiving the last prover message). *Prover rounds* are all verifier rounds played by the prover across different verifier executions; the number of such rounds is the number of states in SeenStates above. Accordingly, for *b 2* N, we say a prover is *b-round* if it plays at most *b* prover rounds during any interaction with any verifier. Also note that the prover is not able to set the verifier to arbitrary states but only to previously-seen ones (starting with the empty state null); naturally, setting the verifier multiple times to the same state may yield distinct new states, because the verifier samples his message afresh each time. After being set to a state cvs,

the verifier does one of three things: (i) if the number of verifier rounds in cvs is less than *k*(①) (see Step 2c and Step 2d), the verifier samples a fresh next message; (ii) if the number of verifier rounds in cvs is *k*(①) (see Step 2e), the verifier samples his additional randomness *r*; (iii) if cvs contains a full protocol execution (see Step 2f), the verifier outputs the decision corresponding to this execution. The second case means that the prover can set the verifier even *after* the conclusion of the execution (after *r* is sampled and known to the prover). The game halts only in the third case. The above game between a state-restoring prover and a verifier yields corresponding notions of soundness and proof of knowledge. Below, we denote by Pr[*hP;V* ~ (①)*i* sr = 1] the probability that the state-restoring prover *P*~ makes the verifier *V* accept ① in this game.

**Definition 5.1.** *Given s*sr*;e*sr: *f*0*;* 1*g!* [0*;*1]*, a public-coin interactive oracle proof system* (*P;V*) *has*

STATE RESTORATION SOUNDNESS *s*sr*if, for every* ① *2= L*(*R*) *and b-round state-restoring prover P*~*,* Pr[*hP;V* ~ (①)*i* sr = 1] *s*sr(①*;b*)*.*

STATE RESTORATION PROOF OF KNOWLEDGE *e*sr*if there exists a probabilistic polynomial-time algorithm* ~*P* ~ *E*sr*(the* extractor*) such that, for every* ① *and b-round state-restoring prover P,* Pr[(①*;E* (①)) *2 R*]

|||sr P~|
|---|---|---|
|sr|sr||

Pr[*hP;V* ~ (①)*i* = 1] *e* (①*;b*)*.*

**Remark 5.2** (results about proof of knowledge)**.** The discussions in Section 5.2, Section 5.3, and Section 5.4 below mention only state restoration soundness *s*sr. All of these discussions (as well as theorems) also apply, without change, to state restoration proof of knowledge. (Just substitute *e*srfor *s*sr, and *e* for *s*.)

### 5.2 General bounds

Let (*P;V*) be a *k*-round public-coin interactive proof system with soundness *s* and state restoration soundness *s*sr. We give upper and lower bounds on *s*sras a function of *k* and *s*. First, for every instance ① *2f*0*;* 1*g* and small enough budget *b 2* N there are two “degenerate” cases: if *b k*(①) then *s*sr(①*;b*) = 0; and if *b* = *k*(①) + 1 then *s*sr(①*;b*) = *s*(①). For larger values of *b*, we prove the following bounds:

**Lemma 5.3.** *Let* (*P;V*) *be a k-round public-coin interactive proof system with soundness s and state* *restoration soundness s*sr*. For every instance* ① *2f*0*;* 1*g and budget b 2* N *with b k*(①) + 1*,*

<u>b</u> *b* *s*(①)(1 *o*(1)) *s*sr(①*;b*) *s*(①)*;* *k*(①) + 1 *k*(①) + 1

*where the lower bound holds if b* *k*(① <u>b</u>

)+1 *cs*(①) = *o*(1)*.*
*Proof.* We first prove the lower bound by exhibiting a universal “resetting” attack. Let *P*~ be a prover that attains *s*(①), i.e., makes *V* (①) accept with probability *s*(①). Consider the state-restoring prover *P*~srthat runs *P*~ until it halts, then sets *V* (①) to the empty state null, and repeats this until either *V* (①) accepts or *b* prover rounds have elapsed. Note that *P*~srsucceeds with probability at least *b* *k*(① <u>b</u>

)+1 *cs*(①)(1 *o*(1)) provided
*b* *k*(① <u>b</u>

)+1 *cs*(①) = *o*(1). This establishes the lower bound. We now prove the upper bound. Let *P*~srbe a *b*-round state-restoring prover that makes *V* accept ①
with probability *s*sr(①*;b*). We construct a prover *P*~ that, using *P*~sras a subroutine, makes *V* accept ① with *b* 1~ works as follows. ~ probability *k*(①)+1 *s*sr(①*;b*), without any state restoration. The prover *P* First, *P* chooses a uniformly random subset *S f*1*;:::;bg* of cardinality *k*(①) + 1; we denote by *S*[*i*] the *i*-th

smallest value in *S*. Then *P*~ runs *P*~sr, simulating an interaction between *P*~srand a virtual verifier using internal randomness, except that, in the simulated prover round *S*[*i*] with *i 2f*1*;:::;k*(①)*g*, *P*~ gives to *P*~sr the message *mi*from (the real verifier) *V*, and sends *P*~sr’s response message *fi*back to *V*. Finally, in the simulated prover round *S*[*k*(①) + 1], we set the virtual verifier’s randomness to that of *V*. (More precisely, since this randomness is not visible to *P*~, we *couple* these two random variables for the purpose of this analysis; this coupling does not affect the acceptance probability of the real verifier *V*.) The view of *P*~sris as in a real state restoration attack, so the virtual verifier accepts with probability

||0 [b]||f ;:::;f||
|---|---|---|---|---|
||k(①)+1|||k(①) V|
|V|0i|i0||sr|

*0* [*b*] *f*1 *0* *;:::;f* *k* *0*

(①)
*s*sr(①*;b*). If the virtual verifier accepts, there is *S 2* such that *V* (①*;*state; *r*) = 1 where state*k*(①):=*;*, *r* := (*m⁰*1*;:::;m* *0k*

(①) *;r⁰*), the *m* and *f* are messages received and sent by *P*~ in
prover round *S⁰*[*i*] for *i 2f*1*;:::;k*(①)*g*, and *r⁰* is the additional randomness of the virtual verifier for prover round *S⁰*[*k*(①) + 1]. So if *S* = *S⁰* then (the real verifier) *V* accepts ①; the equality occurs with probability *b* 1. So *P*~ makes *V* accept ① with probability *b* 1 *s* (①*;b*); rearranging yields the claim. *k*(①)+1 *k*(①)+1 sr

### 5.3 Tightness of general bounds

We prove that the bounds of Section 5.2 are essentially tight. First, we show that the lower bound of Lemma 5.3 is tight up to a factor *k*(①).

**Theorem 5.4.** *For every k 2* N *there exists a k-round protocol* (*P;V*) *with soundness s*(①) *and state* *restoration soundness s*sr(①*;b*) *such that s*sr(①*;b*) *bs*(①)*.*

*Proof.* Take any zero-round protocol (*P⁰;V* *0* ) with soundness *s*(①), and add *k* dummy rounds to obtain a *k*-round protocol (*P;V*). This protocol also has soundness *s*(①). Moreover, any *b*-round state-restoring prover *P*~ for (*P;V*) can be converted into a *b*-round state-restoring prover *P*~ *0* for (*P⁰;V* *0* ) by restoring (null) whenever *P*~ restores (*:::;mk*), and simulating dummy rounds for all other messages. One can verify that *P* ~*0*convinces *V0*with the same probability as *P*~ convinces *V*. By Lemma 5.3, (*P⁰;V0*) has state restoration soundness at most *bs*(①), and hence so does (*P;V*).

Next, we show that the upper bound of Lemma 5.3 is tight up to a polynomial factor in *j*①*j*, independent of *b*, when *k*(①) = *O*(log*j*①*j*).

**Theorem 5.5.** *For every R 2 NEXP and k 2* N *there is a k-round public-coin interactive oracle proof* *system* (*P;V*) *for R such that, for every sufficiently large b 2* N*,* (*P;V*) *has state restoration soundness* *s*sr(①*;b*) <u>1</u> 4 4 (*k*(①)+1) *k*(① *b*

)+1 *s*(①)*, where s*(①) *is the soundness of* (*P;V*)*.*
### We first prove the following lemma.

**Lemma 5.6.** *For every k 2* N *there exists u 2* N *for which there is a k-round public-coin interactive oracle* *proof system* (*P;V*) *such that, for every sufficiently large b 2* N*,* (*P;V*) *has state restoration soundness* *s*sr(①*;b*) 2 <u>1 1</u> 2 4 (*k*(①)+1) *k*(① *b*

)+1 *s*(①)*, where s*(①) *is the soundness of* (*P;V*)*. Moreover, each of V ’s*
j k *messages has length u* log *k*+1 <u>b</u> *.*

*Proof.* Let *u 2* N be a parameter to be fixed later. Consider the *k*-round public-coin interactive oracle proof system (*P;V*) defined as follows. Each message *mi*of *V* is sampled uniformly at random from *f*0*;* 1*g* *u*; after *k* interactions with the prover, *V* samples *r* uniformly at random from *f*0*;* 1*g* *u* and accepts if and only if *m₁* = = *mk*= *r* = 1 *u*. Note that no malicious prover can make *V* accept with probability more than 2 (*k*+1)*u* without state restoration. Allowing state restoration, we construct a state-restoring prover *P*~ as follows.

(i)Let cvs₀ := null. (ii) For *i* = 1*;:::;k*, restore cvs*i* 1repeatedly (and sending the verifier empty messages) until *mi*= 1
*u*. Let the state received when this happens be cvs*i*. (iii)Restore cvs*k*(with an empty proof) repeatedly until *V* accepts. We make *P*~ be a *b*-round state-restoring prover by having it abort after playing *b* rounds. The prover *P*~ makes *V* accept if and only if drawing *b* strings uniformly at random from *f*0*;* 1*g* *u* yields at least *k* + 1 copies of 1 *u*. The expected number of strings we need to draw to obtain *k* + 1 copies is (*k* + 1)2 *u*, by linearity of expectation. Thus by Markov’s inequality, the probability that more than 2(*k* + 1)2 *u* strings need to be drawn is at most 1*=*2, that is, with probability at least 1*=*2, *k* + 1 copies of 1 *u* are obtained within 2(*k* + 1)2 *u* draws. (*k*+1)*u* 2(*k*+1) *b* 1 We choose *u* to be the smallest integer such that 2 2 *k*+1. This condition holds for all

*u* log *k*+1 *b* 2 (using the inequality *x* *y* ( *x* *y* ) *y* for *x y* 1). By minimality of *u*, *u* log *k*+1 *b* 1, *u* (*k*+1)*u k*+1 *b* 1 and thus 2(*k* + 1)2 *b*. With this choice of *u*, (*P;V*) has soundness *s*(①) = 2 4 *k*+1, but state restoration soundness *s*sr(①*;b*) <u>1</u> 2 2 <u>1</u> 4 (*k*+1) *k*+1 *b* *s*(①).

We now return to the proof of the theorem.

*Proof of Theorem 5.5.* The relation *R* has a public-coin *k*-round interactive oracle proof system (*P;*^ *V*^), because *R* is in NEXP (see the lemma in Appendix A). Moreover, we may assume that (*P;*^ *V*^) has soundness *k*+1 *b* 1 *O*(*k* log*b*) 4 *k*+1 = 2 (see parallel repetition in Appendix B.1). Construct a *k*-round interactive oracle proof system (*P;V*). Let (*P⁰;V* *0* ) be the *k*-round IOP implied by Lemma 5.6, and *u 2* N the corresponding message length. The verifier *V* works as follows.

(i)Let *m*

|^ k ::: km|^ kr^ denote the randomness for V^.||
|---|---|---|
|1|k||
|||i|
||i||
|0f ;:::;f|1|i|
 (ii) Simulate *V*^ until round *k* (i.e., until before *V*^ makes its first query), forwarding *V*^ ’s messages to the prover with the following adjustment. For each *i*, the *i*-th message *m* equals *m*^*i*padded with min*f*0*;u jm*^ *jg* random bits. The randomness *r* equals *r*^ padded with min*f*0*;u jr*^*jg* random bits.
(iii) If *V*1 *k*(①*;m⁰;:::;m* *0k* ;*r⁰*) = 1, where *m* *0i* and *r⁰* are the first *u* bits of *m* for *i* = 1*;:::;k* and *r* respectively, then halt and accept. (iv)Continue to simulate *V*^ until it halts, and output its decision. The prover *P* equals *P*^ up to the fact that *P* ignores any padding in the messages received from *V*. Clearly (*P;V*) has completeness 1. Also, by the union bound, we see that for all ① *2= L*(*R*) and *P*~ ~*k*+1 *b* 1 without state restoration, Pr[*hP;V* (①)*i* = 1] 2 4 *k*+1. (Any additional random bits generated by *V* do not help a malicious prover make *V*^ accept because they do not affect *V*^ ’s decision.) The malicious prover *P*~ implied by Lemma 5.6 achieves the same soundness (using state restoration) against *V* as it does against *V* *0*. The theorem follows analogously.

### 5.4 Restricted state restoration attacks

We briefly discuss a technical restriction of state restoration attacks that we use for stating bounds in Section 7; these bounds can also be stated relative to (unrestricted) state restoration attacks, but would not be as tight. A *restricted* state restoration attack is one where the prover cannot restore the verifier to the empty state cvs = null (except for in the first iteration of the game in Section 5.1), but can still restore the verifier to any other previously-seen verifier state. In other words, a restricted state restoration attack on a *k*-round protocol is equivalent to playing the first round as normal, and then performing an (unrestricted) state restoration attack on the remaining *k* 1 rounds. The notion of restricted state restoration yields corresponding notions

of *restricted state restoration soundness*, which we denote *s*sr, and *restricted state restoration proof of* *knowledge*, which we denote *e*sr. The above equivalence implies the following lemma, analogous to Lemma 5.3.

**Lemma 5.7.** *Let* (*P;V*) *be a k-round public-coin interactive oracle proof system with soundness s and* *restricted state restoration soundness s*sr*. For every instance* ① *2f*0*;* 1*g and budget b 2* N *with b k*(①)*,*

*b* *s*(①) *s*sr(①*;b*) *s*(①) *:* *k*(①)

Note that the lower bound of Lemma 5.3 no longer holds, because there are interactive oracle proof systems for which restricted state restoration soundness is equal to standard soundness. (E.g., consider a *k*-round proof system where every round but the first does not affect the verifier’s acceptance probability.) This shows that the lower bound of Lemma 5.7 is tight; also, the upper bound of Lemma 5.7 is tight in a similar way to the upper bound of Lemma 5.3, by the following theorem (analogous to Theorem 5.5).

**Theorem 5.8.** *For every R 2 NEXP and k 2* N *there is a k-round public-coin interactive oracle proof* *system* (*P;V*) *for R such that, for every sufficiently large b 2* N*,* (*P;V*) *has restricted state restoration* *soundness s*sr(①*;b*) <u>1</u> 4 4 *k*(①) *kb*(①1) *s*(①)*, where s*(①) *is the soundness of* (*P;V*)*.*

Finally, using a similar technique to the proof of the upper bound in Lemma 5.3, we also obtain the following bounds for *s*srin terms of *s*sr:

**Lemma 5.9.** *For every instance* ① *2f*0*;* 1*g and budget b 2* N *it holds that*

<u>1</u> *s*sr(①*;b*) *s*sr(①*;b*) *s*sr(①*;b*) *:* *b*

## 6 From interactive oracle proofs to non-interactive random-oracle proofs

We describe a transformation*T* such that if (*P;V*) is a public-coin interactive oracle proof system for a relation *R* then (P*;*V) := *T* (*P;V*) is a non-interactive random-oracle proof system for *R*. The transformation *T* runs in polynomial time: given as input code for *P* and *V*, it runs in time polynomial in the size of this code and then outputs code for P and V. Concretely, we proceed as follows: Below, we describe the polynomial-time transformation *T* by giving the construction of P and V. In Section 7, we state and prove *T*’s main properties, relating features of (*P;V*) to those of (P*;*V). **Notation.** For convenience, we split the random oracle into two random oracles, denoted1and2, as follows:1(*x*) := (0*kx*) and2(*x*) := (1*kx*). At a high level, we use1for the verifier’s randomness, and 2for Merkle trees and other hashing purposes. When counting queries, we count queries to both1and2. **Construction of** P**.** The algorithm P, given input (①*;*✇) and oracle access to, works as follows.

1.Set *k* := *k*(①), *q* := *q*(①), *f₀* :=*?*, and

|||:=|(①).|||
|---|---|---|---|---|---|
|||0 i 1|2 i 1|||
|i||i i 2 i|i 1|i||
|k|V|k||k||
|f ;:::;f|k V j k|j q k||j|y j|

2.Start running *P*(①*;*✇) and, for *i* = 1*;:::;k*:
(a)Compute the verifier message *m* := (①*k*) (and Remark 2.1 may apply here).
(b)Give *m* to *P*(①*;*✇) to obtain *f*.
(c)Compute the Merkle-tree root rt := MERKLE*:* GetRoot
2

(*f*).
(d)Compute the “root hash”*i*:= (rt *k*).
3.Set state :=*;* and *r* := (*m₁;:::;m;r*), where *r* :=1(①*k*) (and Remark 2.1 may apply here).
4. Run *V*0 *k*(①*;*state; *r*) and compute an authentication path for each query. Namely, for *j* = 1*;:::;q*: if the *j*-th query is to the *x*-th bit of the *y*-th oracle, then compute ap := MERKLE*:* GetPath
2 (*fj;x*). (If MERKLE*:* GetRoot is probabilistic, then give the same randomness to MERKLE*:* GetPath as well.)

5. Set := (rt₁*;:::;* rt)*;*(ap₁*;:::;* ap)*;*. That is, comprises the Merkle-tree roots, an authentication path for each query, and the final root hash.
6.Output. See Figure 6 for a diagram of the construction above. **Construction of** V**.** The algorithm V, given input (①*;* ~) and oracle access to, works as follows.
1.Set *k* := *k*(①), *q* := *q*(①), *f₀* :=*?*, and

||||:=|(①).|||
|---|---|---|---|---|---|---|
||1 i 1 i 2 i|k i 1 i 1|0 1|2 q k|||
|k|V||k||1||
|n k k j n|f ;:::;f|k|V j||j|j y j|

2.Parse ~ as a tuple (rt~*;:::;* rt~)*;*(ap~*;:::;* ap~)*;* ~.
3.For *i* = 1*;:::;k*:
(a)Compute *m* := (①*k*).
(b)Compute := (rt~ *k*).
4.Set state :=*;* and *r* := (*m₁;:::;m;r*), where *r* := (①*kk*).
5.Compute *m* := *V*0 *k*(①*;*state; *r*), answering the *j*-th query with the answer *aj*in the path ap~.
6.If *6*= ~, halt and output 0.
7. For*j* = 1*;:::;q*: if the*j*-th query is to the*x*-th bit of the*y*-th oracle and MERKLE*:* CheckPath
2 (rt*j;x;* *aj;*ap~) *6*= 1, halt and output 0.

8.Output *m*.

|𝑚||𝜎||…|
|---|---|---|---|---|
|𝜌 (𝑥| ⋅)|||𝑓 𝑓|𝑓 �|
|𝑓|rt||||
|GetRoot||𝜌|||
|||𝜎|||
|𝑚|||||
|𝜌 (𝑥| ⋅)|||||
|𝑓|rt|||�; 𝑟)|
|𝑃 GetRoot||𝜌|||
|||𝜎|||
|⋮ ⋮||⋮|oracle 𝑓 𝑥|ap GetPath|
|𝑚 � 𝜌 (𝑥| ⋅)||𝜎 �|�|ap|
|𝑓 �|rt �||𝑓 � 𝑥|GetPath|
|GetRoot||𝜌 𝜎 �|⋮ ⋮|⋮ ap �|
|𝑟 𝜌 (𝑥| ⋅) that involves running the IOP prover P|||𝑓 �� 𝑥 �|GetPath|
|running the IOP verifier V||||.|

𝑉( 𝑚, …, 𝑚

query

Figure 6: Diagram of how the NIROP prover P works. On the left, the diagram shows the part of P’s computation

; on the right, the diagram shows the part of P’s computation that involves. The highlighted values are those that are eventually included in the output proof

## 7 Analysis of the transformation T

The theorem below specifies guarantees of the transformation *T*, described in Section 6. The statement of the theorem relies on the notions of soundness and proof of knowledge against state restoration attacks, described in Section 5 (more precisely, the statement relies on their restricted variants, described in Section 5.4).

**Theorem 7.1** (IOP*!* NIROP)**.** *For every relation R, if* (*P;V*) *is a public-coin interactive oracle proof* *system for R with*

round complexity *k*(①) restricted state restoration soundness *s*sr(①*;b*) proof length *p*(①) prover time *t*ver(①) verier time *t*prv(①)

*then* (P*;*V) := *T* (*P;V*) *is a non-interactive random-oracle proof system for R with*

soundness *s⁰*(①*;m;*) := *s*sr(①*;m*) + 3(*m²* + 1)2 proof length *p⁰*(①*;*) := *k*(①) + *q*(①) (*d*log₂ *p*(①)*e* + 2) + 1 5

prover time *t⁰*prv(①*;*) := *O* (*k*(①) + *p*(①)) + *t*prv(①) + *t*ver(①)

verier time *t⁰*ver(①*;*) := *O* (*k*(①) + *q*(①)) + *t*ver(①)

*Moreover, the transformation T preserves both proof of knowledge and zero knowledge (if present):*

*If* (*P;V*) *has restricted state restoration proof of knowledge e*sr*then* (P*;*V) *has proof of knowledge e⁰ with*

*e⁰*(①*;m;*) := *e*sr(①*;m*) + 3(*m²* + 1)2 *:*

*If* (*P;V*) *has z-statistical honest-verifier zero knowledge then* (P*;*V) *has z⁰-statistical zero knowledge with*

*z⁰*(①*;*) := *z*(①) + *p*(①)2 *=*4+2 *:*

*Finally, the above soundness s⁰*(①*;m;*) *and proof of knowledge e⁰*(①*;m;*) *are tight up to a multiplicative* *factor O*( + *p*(①) + *u*(①)) *in m, where u*(①) *is the total number of bits sent by V* (①) *(for any choice of its* *randomness).*

By construction, if *hP*(①*;*✇)*;V* (①)*i* has accepting probability, then the probability that V (①*;*P (①*;*✇)) accepts is. The complexities *p⁰;t⁰*prv*;t⁰*verabove also directly follow from the construction. Therefore, we are left to discuss soundness (upper bound in Section 7.1 and lower bound in Section 7.2), proof of knowledge (Section 7.3), and zero knowledge (Section 7.4). 5 This bound can be tightened by using additional notation: the term *q*(①) *d*log *p*(①)*e* can be replaced by P *q*(①) *d*log *jfi je* 2 *j*=1 2 *j* where *fij* is the oracle queried by the *j*-th query.

### 7.1 Upper bound for soundness

Let ① *2= L*(*R*) and let P~ be an *m*-query prover for the non-interactive random-oracle proof system (P*;*V). We construct a prover *P*~ (depending on ① and P~) for the interactive oracle proof system (*P;V*), and show that *P*~’s ability to cheat in a (restricted) state restoration attack is closely related to P~’s ability to cheat. **Construction of** *P*~**.** Given no inputs or oracles, the prover *P*~ works as follows.

1. Let1*;*2be tables mapping *f*0*;* 1*g* to *f*0*;* 1*g*, and let be a table mapping-bit strings to verifier states. The tables are initially empty and are later populated with suitable values, during the simulation of P~. Intuitively,1*;*2are used to simulate P~’s access to a random oracle, while is used to keep track of which verifier states P~ has “seen in his mind”.
2. Draw at random, and define2(①) :=

|2f0; 1g||(i.e., the oracle|replies the query ① with the||
|---|---|---|---|---|
|0||0|2||
|0 i||1|0|0|
|i|1||1 i|i|
|i|2 i i|2|2 i|i|
 answer). After receiving *V* ’s first message *m₁*, also define (①*k*) := *m₁* and () := (*m₁*).
3.Begin simulating P~ and, for *i* = 1*;:::;m*:
(a)Let be the *i*-th query made by P~.
(b) If is a query to a location of that is defined, respond with (). Otherwise (if to an undefined location of1), draw a string in *f*0*;* 1*g* at random and respond with it. Then go to the next iteration of Step 3.
(c) If is a query to a location of that is defined, respond with (); then go to the next iteration of Step 3. Otherwise (if is to an undefined location of), draw a string
*0* *2f*0*;* 1*g* at random and respond with it; then continue as follows.

(d) Let rt be the first bits of, and be the second bits. (If the length of is not 2 bits, go to the next iteration of Step 3.) If () is defined, let cvs := () and let *j* be the number of verifier rounds in the state cvs. If () is not defined, go to the next iteration of Step 3.
(e) Find the query*i?* whose result is rt. If this query is not unique, or there is no such query, then answer the verifier *V* with some dummy message (e.g., an all zero message of the correct length) and skip to Step 3g. Otherwise, note the index *i*
*?* and continue.

(f) Compute *f* := VE
2 (P ~*;‘* *j*

(①)*;i* *?* *;i*); if VE aborts, set *f* := 0
*‘* *j*

(①). Recall that *‘j*(①) is the length of
the prover message in the *j*-th verifier round, and VE is Valiant’s extractor (see Section 3.1). Also note that VE does not query2on any value outside the table, because we have already simulated the first *i* queries of P~ (see Remark 3.1).

(g) Send the message *f* to the verifier and tell the game to set the verifier to the state cvs. (Whether cvs lies in the set SeenStates is a matter of analysis further below.) If the game is not over, the verifier replies with a new message *m⁰*. (If *j* = *k*(①) + 1, for the purposes of the proof, we interpret *m⁰* as the additional randomness *r*.) The game adds cvs⁰ := cvs*kfkm⁰* to SeenStates. The prover defines (①*k*
*0* ) := *m⁰* and ( *0* ) := cvs. *0* 1 **Analysis of** *P*~**.** We now analyze *P*~. We first prove a simple lemma, and then discuss *P*~’s ability to cheat.

**Lemma 7.2.** *Let A be an m-query algorithm. Define:*

*1. E₁ to be the event that A*2*outputs* ① *2f*0*;* 1*gk*(①)*2f*0*;* 1*g that satisfy*

|||, rt₁;:::; rt|2f0; 1g, and||
|---|---|---|---|---|
|||n|k(①)||
|0 2|2 i 2|i 1 0 i i|k(①) 1|k(①) 1|
||2||||
|1|||||
 *the recurrence* = (①) *andi*= (rt *k*) *for all i 2f*1*;:::;k*(①)*g;*
*2. E₂ to be the event that A*2*queries at* ①*;*rt₁*k;:::;* rt *k (in order) and, if any* rt*iis the* *result of a query, this query first occurs before* rt *k.* *Then*
Pr [(*:E₁*) *_ E₂ j U* ()] 1 (*m²* + 1)2 *:*

*Proof.* Let rt₀ be ① and be the empty string. Suppose, by contradiction, that *E₁* occurs and *E₂* does not. Then there exists *i 2f*0*;:::;k*(①)*g* for which at least one of the following holds: (i) *A*2does not query

2before it queries rt

|rt k; (ii) A|queries rt|k||k; (iii) rt||is the result of a query but this query|||
|---|---|---|---|---|---|---|---|---|
|i i 1||i+1 i||i i 1|i||||
||i i 1 2 k(①)|k(①) 1||2|i i 1|||k(①)|
|i+1 i k(①) i i|k(①) k(①)|1|i 2|i 1 i|2 i|i 1|2 k(①)|k(①) 1 2|

first occurs after rt *k*. Consider the largest index *i* for which one of the above holds. In case (i), the behavior of *A*2is independent of (rt *k*~). If *i* = *k*(①), then the output of *A*2equals (rt *k*) with probability 2. If *i < k*(①), then there is a sequence of queries rt *k*~*;:::;* rt *k*~ for which ~ = (rt*ik*~) for *i* = 1*;:::;k*(①) 1 and (rt *k*~) =. If this sequence is not unique, then *A*2has found a collision. Otherwise, the unique sequence has ~ = for each *i*, which occurs with probability at most 2. In cases (ii) and (iii), *A*2has found a collision, since = (rt *k*). The fraction of oracles for which *A*2finds a collision is at most *m²*2. Overall, the probability that *E₂* does not occur and *E₁* does is, by the union bound, at most (*m²* + 1)2.

We now state and prove the lemma that establishes the soundness *s⁰* as stated in Theorem 7.1.

**Lemma 7.3.** *Define* *U* () := Pr V (①*;*) = 1 ~ *:* P

*Then there exists b 2* N *with b m such that P*~ *is a b-round state-restoring prover that makes V accept with* *probability at least* 3(*m²* + 1)2*.*

*Proof.* We first note that *P*~ described plays no more than *m* rounds, because *P*~ sends a message to the verifier *V* only in response to P~ making a query. Next, we define some useful notions, and use them to prove three claims which together imply the lemma.

DEFINITION 1.We say *2U*() is *good* if

1.The verifier accepts relative to, i.e., V (①*;*) = 1 where P~.

|~ as (rt|~ ;:::; rt|~ ); (ap|~ ;:::; ap ); ~|and setting|:= ①, for each i 2f1;:::;k(①)g,|||
|---|---|---|---|---|---|---|---|
|i 2 i|1 k(①) i i 1|1 2 i|q i 1|k(①)|0 k|||
|i|1|i|l i||i i||i|
|2 k(①)|a l|i i|max l|i|i l|i i max||

2. Parsing where := (rt~ *k*), there exist indices 1 *j₁ < < j m* such that:
(a) P~ ’s *j*-th query is to at rt~ *k*;
(b)if rt is the result of a query, this query first occurs before *j*;
(c)if P~ queries at ①*k*, then this query occurs *after* query *j*;
(d) if there exists *l* such that Root(ap~) = rt~, there is a unique (up to duplicate queries) *a 2f*0*;:::;jig* such that (*i*) = rt~ and, for every *i 2fa;:::;j g*, v := VE
2 (*A;‘;a;i*) is such that, for all *l* with Root(ap~) = rt~, Value(ap~) equals the Position(ap~)-th value in v; we say v is *extracted* *at i* if this holds.

3. ~*k*(①)=. DEFINITION 2. We say that P~ *chooses 2U*() if for every query made by P~ to its oracle, *P*~ supplies it with ( ) (ignoring whether this response comes from *P*~ itself or the messages sent by *V*; this choice is fixed for a given). CLAIM 1. (*P;V* ~) chooses *2U*() uniformly at random. Whenever the simulation of P~ makes a query, *P*~ responds consistently, either with a uniformly randomly drawn string of its own, or the uniform randomness provided by *V*. This is equivalent in distribution to drawing uniformly at random at the beginning of the protocol. CLAIM 2. For any choice of randomness such that *P*~ chooses a good, *P*~ makes *V* (①) accept with a state restoration attack.

We begin by defining a property of the map.

DEFINITION 3. For *i* = 0*;:::;k*, we say that is *correct at i* if, immediately before P~’s *ji*+1-th query is simulated (for *i* = *k*, at the end of the simulation), it holds that

*;*

|( ) = (|(①k );f₁;:::;|(①k ))|
|---|---|---|
|i l|1 0|1 i|

where for each *l 2f*1*;:::;ig*, *f* is extracted at *l* (see Condition 2d above), and (*i*) *2* SeenStates.

We show by induction that is correct at *i* for every *i 2 f*0*;:::;kg*. First, is correct at 0 since

|( ) = (|(①k||||is correct at i|1. When P|~|~ k (i.e.,|
|---|---|---|---|---|---|---|---|---|
|0|1|||||||i i 1|
|j||i 1|i|1 0|i 1|i 1|i 1|1 i|
|||i+1 k|1|1|1 k||||

0 )) by construction. Suppose that queries rt query*i*), *P*~ restores () *2* SeenStates. By Condition 2d, *f* is extracted at *i*. In Step 3g, (①*k*) is set to the message (or, similarly, internal randomness) sent by *V* in this round, which is possible by Condition 2c. The newly stored state is then () = ( (①*k*)*;f₁;:::;* (①*k*)*;f;* (①*ki*)) *2* SeenStates. This state is stored before query *j* by Condition 2a, and so is correct at *i*. Hence P~ sends a state () = ( (①*k*)*;f₁;:::;* (①*k*)) *2* SeenStates. Since V’s simulation of *V* accepts with this state, so does the real *V* when interacting with P~.

CLAIM 3.The probability that *2U*() is good is at least 3(*m²* + 1)2.

By assumption, the density of oracles satisfying Condition 1 is. Lemma 7.2 implies that the density of oracles satisfying Condition 1 but not satisfying Condition 2a, Condition 2b, and Condition 3 is at most (*m²* + 1)2. 6 The density of oracles failing to satisfy Condition 2c is at most *m²*2, since this implies a ‘collision’ (in the sense of Lemma 3.2) between1and2. Finally, the density of oracles satisfying Condition 1, Condition 2a, and Condition 2b, but not Condition 2d is at most (*m²* + 1)2, by Lemma 3.2 and Condition 2b (where Condition 2b allows us to restrict the possible values for *ai*to 0 *ai< ji*). By the union bound, the density of good oracles is at least 3(*m²* + 1)2.

Combining the claims, we deduce that *P*~ makes *V* accept with probability at least 3(*m²* + 1)2 with a state restoration attack. Finally, note that this state restoration attack is restricted because *P*~ never requests to set *V* to the empty verifier state null.

### 7.2 Lower bound for soundness

We show that the soundness analysis of Section 7.2 is essentially tight. Let ① *2= L*(*R*) and let *P*~ be a *b*-round state-restoring prover for the interactive oracle proof system (*P;V*). We construct an *m*-query prover P~ for the non-interactive random-oracle proof system (P*;*V), and show that P~’s ability to cheat is closely related to *P* ~’s ability to cheat in a state restoration attack.

**Construction of** P~**.** Given oracle access to, the prover P~ works as follows.

1.Initialize SeenStates to be an empty set and to be an empty mapping from verifier states to *f*0*;* 1*g*.
2.Compute *k* := *k*(①),0:=2(①), and *m₁* :=1(①*k*0).
3.Send the verifier message *m₁* to the simulation of *P*~.
4.Set the verifier state cvs := (*m₁*), add cvs to SeenStates, and set (cvs) :=0.
5.For *j* = 1*;:::;b*:
(a)Simulate *P*~ until it selects cvs
(*j*) = (*m₁;f₁;:::;m*
*i*

(*j*)) *2* SeenStates and outputs a message *f*
(*j*).
(b)Compute the root rt := MERKLE*:* GetRoot
2 (*f*

(*j*) *kj*), where *j* is encoded in *f*0*;* 1*g*.
6 More precisely, we apply Lemma 7.2 to an algorithm P~ that does not itself output ① but this does not affect the lemma’s validity because we can substitute into the definition of the event *E₁* the fixed instance ①.

||j 0|2|(j)|1|f|
|---|---|---|---|---|---|
|(j)|||(j)|||
|||0||||
|(j)|||f ;:::;f||k (j)|
|k||i|i f|||

(c)Set := (cvs), := (rt*k*), *m* := (①*k*
*0* ), and *j* (*j*) := *j*.

(d) If *i < k*, send the verifier message *m* to the simulation of *P*~, add cvs := cvs
(*j*) *k*(*f*
(*j*) *;m*
(*j*) ) to
SeenStates, set (cvs) :=, and continue to the next iteration.

(e) If *i* = *k*, compute the bit *d* := *V*1 *k*(①*;;*; (*m₁;:::;m;m*)). If *d* = 0, continue to the next iteration; else if *d* = 1, compute a proof as in Step 4 and 5 of the construction of P in Section 6, using := and replacing *f* with *f kii*for *i* = 1*;:::;k*, then output.
**Analysis of** P~**.** We now analyze P~.

**Lemma 7.4.** *There exists a constant c such that if P*~ *is a b-round state-restoring prover that makes V accept* ① *with probability, then* P~ *is an m-query prover that makes* V *accept* ① *with probability at least m²*2*,* *where m* := *c* ( + *p*(①) + *u*(①)) *b and u*(①) *is the sum of the lengths of all the verifier’s messages.*

*Proof.* First, we argue that P~ makes no more than *c* ( + *p*(①) + *u*(①)) *b* oracle queries for some universal constant *c*. Whenever *P*~ plays a round, P~ makes: one call to1(chained *dui*(①)*=e u*(①) times where *ui*is the length of the *i*-th verifier message); one call to2; and one call to MERKLE*:* GetRoot 2 on a string of length at most *p*(①)+, which requires at most *c⁰* (*p*(①)+) queries for some universal constant *c⁰*. In Step 5e, P~ does not need to make any new queries. Thus, the number of queries is at most *m*. Next, we argue if (the simulation of) *P*~ convinces (the simulation of) *V*, then P~ convinces V. This is clear because P~ constructs the proof from messages and randomness that cause (the simulation of) *V* to accept. It is also clear that (the simulation of) *P*~ sees a legal restricted state restoration transcript. Finally, we argue that (the simulation of) *P*~ convinces (the simulation of) *V* with the claimed probability. If all the root hashes *0* are distinct, then all the verifier messages are uniformly randomly drawn, because each message is computed as1(①*k* *0* ); hence, by assumption, *P*~ convinces *V* with probability. Every Merkle tree root is computed relative to a distinct string (because we include the prover round index in the string), so that if two root hashes collide then this implies a collision in2, which can occur with probability at most *m²*2. By the union bound, P~ causes V to accept with probability at least *m²*2.

### 7.3 Proof of knowledge

We describe how the transformation *T* preserves proof of knowledge. Suppose that the interactive oracle proof system (*P;V*) has restricted state restoration proof of knowledge *e*sr(①*;m*), and denote by *E*srthe corresponding extractor. The security reduction in Section 7.1, in which we construct *P*~ from ① and P~, suggests a natural strategy for extracting a witness from P~. Indeed, note that *P*~ does not need to know the code, randomness, or auxiliary inputs of P~, but only needs to choose answers for its queries to the random oracle; this means that one can compute *P*~ when only given ① and oracle access to P~. So consider the extractor E that, given input (①*;* 1 *m* *;*1 ) and oracle access to P~, works as follows: ~ from the instance ① and oracle P~; (2) compute ✇*P* ~

(1) construct the oracle *P* := *E*sr(①); (3) output ✇. Note that E runs in probabilistic polynomial time because the oracle *P*~ can be simulated in probabilistic poly(*j*①*j* + *m* +) time when given input (①*;* 1
*m* *;*1 ) and the oracle P~ and, moreover, *E*srruns in probabilistic poly(*j*①*j*) time. The extractor E shows that (P*;*V) := *T* (*P;V*) has proof of knowledge *e⁰*(①*;m;*) := *e*sr(①*;m*)+3(*m²*+

1)2 (as stated in Theorem 7.1), as we now argue. By Lemma 7.3, the state-restoring prover *P*~ makes *V* accept ① with probability that is at least the probability that P~ makes V accept ① minus 3(*m²* + 1)2.

*P* ~ Moreover, (*P;V*) has restricted state restoration proof of knowledge *e*sr, so that Pr[(①*;E*sr(①)) *2 R*] Pr[*hP;V* ~ (①)*i* sr = 1] *e*sr(①*;m*). We conclude that h i

|P ~|m|P~||||
|---|---|---|---|---|---|
|||sr sr|sr|||
|||||2||
|||||0||

Pr (①*;*✇) *2 R* ✇ E (①*;* 1*;*1 ) = Pr[(①*;E* (①)) *2 R*]

Pr[*hP;V* ~ (①)*i* = 1] *e* (①*;m*) *U* () Pr V (①*;*) = 1 ~ 3(*m* + 1)2 *e*sr(①*;m*) P *U* () = Pr V (①*;*) = 1 ~ *e* (①*;m;*)*;* P

as desired. Finally, the tightness argument of Section 7.2 can be extended from applying to (restricted state restoration) soundness to also applying to (restricted state restoration) proof of knowledge.

### 7.4 Zero knowledge

We describe how the transformation *T* preserves zero knowledge, by proving the following lemma.

**Lemma 7.5.** *If* (*P;V*) *has z-statistical honest-verifier zero knowledge, then* (P*;*V) *has z⁰-statistical zero* *knowledge (in the explicitly-programmable random oracle model) with z⁰*(①*;*) := *z*(①) + *p*(①)2 *=*4+2 *.*

*Proof.* Let *S* be the simulator for (*P;V*), and *S*MERKLEthe Merkle-tree simulator (see Section 3.2). We construct a (candidate) simulator S for (P*;*V) := *T* (*P;V*) that uses *S* and *S*MERKLEas subroutines. To account for the split of into the two sub-oracles1and2, we view the function from the definition of zero knowledge (see Section 2.3) as a pair (1*;*2) such that [] splits into the function pair (1[1]*;*2[2]). The simulator S, given instance ① and oracle access to, works as follows:

1.Set *k* := *k*(①)*;q* := *q*(①)*;‘*1:= *‘*1(①)*;:::;‘k*:= *‘k*(①)*;*0:=2(①).
2.Compute the view (*a₁;:::;aq;rV*) := *S*(①).
3. Run *V* with randomness *rV*, recording its messages *m₁;:::;mk*and answering its oracle queries with the answers *a₁;:::;aq*, to determine the oracle index *yj*and bit index *xj*of each query*j*.
4.For *i* = 1*;:::;k*:
(a) Run *S*MERKLEto obtain the requested authentication paths corresponding to the *i*-th oracle by setting (rt*i;*(ap*j*)*j2Ji*) := *S*MERKLE(*‘i;* (*xj;aj*)*j2Ji*) where *Ji*:= *fj 2f*1*;:::;qg* s.t. *yj*= *ig*.
(b)Compute*i*:=2(rt*iki* 1).
(c)Set1(①*ki* 1) := *mi*.
5.Set := (rt₁*;:::;* rt*k*)*;*(ap₁*;:::;* ap*q*)*;* (1*;:::;k*), and output (*;*). Note that S runs in probabilistic polynomial time (as its complexity is dominated by that of *S*MERKLEand *S*). Next, we construct a “hybrid simulator” S⁰ that is identical to S except that: (a) S⁰ is given not only an instance ① but also the corresponding witness ✇; (b) in Step 2, instead of using *S*’s output view, S⁰ generates a uniformly random string *rV*and uses it to simulate (*P*(①*;*✇)*;V* (①;*rV*)) and obtain the answers *a₁;:::;aq*and corresponding oracle and bit indices. We claim that, for any distinguisher *D*, the following two distributions are *p*(①)2
*=*4+2 -close:

*U* ()[*0*] *0 U* () Pr *D* () = 1 and Pr *D* () = 1*0 0 0:* P (①*;*✇) (*;*) S (①*;*✇)

Indeed, note that and [ *0*] are identically distributed (since the values in *0* are uniformly random) and [*0*] *=*4+2 *0* P (①*;*✇) is *p*(①)2-close to (by Lemma 3.4). Finally, we know by hypothesis that, for any distinguisher *D*, the following two distributions are *z*-close:

*0 U* () *U* ()

|[] 0||[]|
|---|---|---|
||0 0||

Pr *D* () = 1*0*and Pr *D* () = 1 *:*

(*;*) S (①*;*✇) (*;*) S (①)
The lemma then follows by the triangle inequality.

## 8 Tree exploration games

We introduce tree exploration games, which are a class of games pitting a single player against Nature. We prove a connection between tree exploration games and state restoration attacks on IOPs: we establish a correspondence between public-coin IOP verifiers and tree exploration games and, similarly, between state-restoring provers and strategies on these games. Finally, we describe a simple universal strategy, and prove that it has optimal expected cost (where cost is the number of rounds until the player wins).

### 8.1 Definition of tree exploration games

A *tree exploration game* is a complete-information game, between a single player and Nature, that is specified by a pair *G* = (*T;*), where *T* is a rooted tree and is a predicate function that maps *T*’s vertices to *f*0*;* 1*g*; we denote by *V* (*T*) the vertices of *T*, and by rt(*T*) the root vertex of *T*. The game proceeds in rounds: for *i* = 1*;* 2*;:::*, in the *i*-th round, a subtree *Si* 1*T* is *accessible* to the player; the player chooses a node *v 2 Si* 1, and Nature samples a child *u* of *v* at random; the next accessible subtree is *Si*:= *Si* 1*[fug*. The initial accessible set *S₀* is *f*rt(*T*)*g*, i.e., the set consisting of *T*’s root vertex. The player wins in round *r* if there is *v 2 Sr*such that (*v*) = 1. A *strategy* for *G* is a probabilistic function *s*: 2 *V* (*T*) *! V* (*T*) such that *s*(*W*) *2 W* for all *W V* (*T*). Note that *s*(*S₀*) always equals rt(*T*), because the root vertex is the only vertex in the initial accessible set; if Nature samples the child *u* of rt(*T*), then *S₁* := *f*rt(*T*)*;ug*, and so *s*(*S₁*) may output rt(*T*) or *u* (or each with some probability). Thus the accessible sets form a sequence of random variables each of which depends on the strategy *s*; we emphasize this by writing *Si*(*s*). Note that we have defined a strategy to be a function only of the current accessible set (and not also of previous choices); we justify this choice later (see Lemma 8.3). The *cost* of a strategy *s* is the random variable*s*that denotes the smallest index *r* such that there is *v 2 Sr*(*s*) for which (*v*) = 1. More generally, given a set *W T* containing rt(*T*),*s*(*W*) denotes the cost of *s* when the initial accessible set equals *W*; thus, in particular,*s*=*s*(*f*rt(*T*)*g*). Note that*s*(*W*) = 0 if

(*v*) = 1 for some *v 2 W* and*s*(*W*) = *1* if (*v*) = 0 for all *v 2 W*. For other cases,*s*(*W*) satisfies the
following recursion: <u>1</u> X E[*s*(*W*)] = 1 + E[*s*(*W [fvg*)] (1) *jCs*(*W*)*j* *v2Cs*(*W*)

where *Cv*for *v 2 T* is the set of children of *v*.

**Remark 8.1.** We do not discuss probabilistic strategies in this paper. One can verify, however, that for every probabilistic strategy *s* there is a deterministic strategy *s⁰* whose expected cost is no higher; the strategy *s⁰* can be obtained by iteratively fixing the random choices of *s* such that E[*s*] is minimized.

### 8.2 A connection between tree exploration and state restoration

We establish a connection between tree exploration and state restoration (discussed in Section 5). **From IOPs to tree exploration games.** First, we describe how to map an interactive oracle proof system to a tree exploration game. Let (*P;V*) be a *k*-round public-coin interactive oracle proof system, and let ① be an instance; we use *V* and ① to construct a tree exploration game *GV;*①= (*T;*) as follows. The vertices of the rooted tree *T* consist of sequences of at most *k*(①) + 1 verifier messages: a vertex *v* looks like (*m₁;:::;mi*) with *i 2f*1*;:::;k*(①)*g* and each *mj*in *f*0*;* 1*g* *u* *j*

(①), or looks like (*m₁;:::;mk*(①)*;r*) with
each *mj*as before and *r* being additional randomness for the verifier; we denote by *v*(*j*) the *j*-prefix of *v*. The edges of *T* correspond to sequences for which one sequence extends the previous one by an additional

message: an edge (*u;v*) is in the edge set if *v* = *ukm* for some message *m*. The predicate function : *V* (*T*)*!f*0*;* 1*g* is such that for every vertex *v*: (a) if *v* is not a leaf node (i.e., contains less than *k*(①) + 1 messages), maps *v* to 0; (b) if *v* is a leaf node (i.e., contains exactly *k*(①) + 1 messages), maps *v* to the bit *V* *f* *v*(1)*;:::;fv*(*k*(①))(①; state *k*(①); *rV*) where state*k*(①):=*;*, *rV*:= *v*, and the *fv*(*j*)are defined as follows. Given a vertex *u* = (*m₁;:::;mi*), let *Xu*= (*m₁;:::;mi;mi*+1*;:::;mk*(①)*;r*) be the random variable obtained by setting the first *i* coordinates according to *u* and choosing the rest uniformly at random. Then !

||||h|||||i||
|---|---|---|---|---|---|---|---|---|---|
|||||f ;:::;f|;f ;f|:::;f||||
|u|f|f ;:::;f j0 k(①) k(①)|X||||u j|i|i+1 u|
||f ;:::;f|j|||f ;:::;f|||||
|X||||X||||||
||||||u|||||

*0 0* *u*(1) *u*(*i* 1) *i i*+1 *k*(①) *f* := arg max max Pr *V* (①*;;*; *X*) = 1*;* *i i0*+1 *k* *0*

(①) *u*
where, for *j* = *i* + 1*;:::;k*(①), *f* ranges over probabilistic functions of the random variables *m;:::;mj*. The following lemma is an easy consequence of this definition.

**Lemma 8.2.** *Let X* := (*m₁;:::;m;r*) *be drawn uniformly at random, with m 2f*0*;* 1*giand r 2* *f*0*;* 1*g sufficiently long. Let f₁;:::;f be such that, for j* = 1*;:::;k*(①)*, f is a probabilistic function of* *the random variables m₁;:::;m. Then* h i h i Pr *V* 1 *k*(①) (①*;;*; *X*) = 1 Pr *VX*(1) *X*(*k*(①))(①*;;*; *X*) = 1 *:*

*Proof.* Follows easily by induction and the definition of *f*.

**Augmented strategies vs. standard strategies.** Next, we extend the notion of a strategy to allow tracking, and depending on, previous choices; we use this notion in establishing a correspondence later on. We say a sequence *H* = (*v₁;:::;vh*) *2 V* (*T*) *h* is a *valid history* if *v₁* = rt(*T*) and, for all *j 2f*2*;:::;hg*, *vj*is adjacent to some vertex *u 2fv₁;:::;vj* 1*g*. Every nonempty prefix of a valid history is also a valid history, and that vertices in the sequence need not be distinct.

|||b|
|---|---|---|
||b|j|

Given a tree exploration game *G* = (*T;*), a function *s* : (*V* (*T*))*! V* (*T*) *[f?g* is a *b-augmented* *strategy* for *G* if, for all valid histories (*v₁;:::;v*), it holds that *s*((*v₁;:::;v*)) *2fv₁;:::;vjg[f?g* for all *j 2f*1*;:::;bg*. (The value of *s*(*H*) when *H* is not a valid history is irrelevant.) To play a *b*-augmented strategy on a tree, we provide it with the history *H* of vertices drawn so far. We prove that, in terms of expected cost, *b*-augmented strategies are no more powerful than (standard) strategies.

**Lemma 8.3.** *Let G* = (*T;*) *be a tree exploration game. For every b-augmented strategy s for G there is a* *(standard) strategy s⁰ for G such that* E[*s0*] E[*s*]*.*

*Proof.* For *W* = *fv₁;:::;v g T*, let

|i|||
|---|---|---|
|0|(1)|(i)|

( *s*((*v;:::;v*)) if *s*((*v*(1)*;:::;v*(*i*))) *6*=*?* *s* (*W*) := rt(*T*) otherwise

where minimizes E[))] across all permutations over [*i*] for which (*v*(*i*)) is a

|((v|;:::;v||||;:::;v|
|---|---|---|---|---|---|
|s (1)|(i)|(1)|(i)||(1) (i)|
||s|i i|s|i||
|s|s|s||s||

valid history. Note that *s⁰*(*W*) *2 W* since if *s*((*v;:::;v*)) *6*=*?* then *s*((*v*(1)*;:::;v*)) *2 W*. The expected cost of *s* for any valid history (*v₁;:::;v*) is thus bounded from below as follows

E[ ((*v₁;:::;v*))] E[ *0* (*fv₁;:::;v g*)] *:*

Hence in particular, E[] = E[ ((rt(*T*)))] E[ *0* (*f*rt(*T*)*g*)] = E[ *0*].

**The correspondence.** Let (*P;V*) be a *k*-round public-coin interactive oracle proof system, and let ① be an instance; let *GV;*①= (*T;*) be the tree exploration game constructed as above. We now describe, for any budget *b 2* N, a correspondence between (deterministic) *b*-round state-restoring provers for (*P;V* (①)) and *b*-augmented strategies for *GV;*①. Given *m₁;:::;mi2 f*0*;* 1*g*, the state corresponding to a vertex *v* = (*m₁;:::;mi*) is cvs(*v*) := (*m₁;fv*(1) *i* 1 *v*(*i* 1) *i i*

|;:::;m|;f|;m ). The vertex corresponding to a state cvs := (m₁;f₁;:::;m||) is v(cvs) :=||
|---|---|---|---|---|---|
|v(1) i|i 1 v(i|1) i|j|i j||
||||j|0j|P|
||||||0j|
||||P|||

(*m₁;:::;m*). A history (*v₁;:::;v*) corresponds to the list of states (cvs(*v₁*)*;:::;* cvs(*v*)) and vice versa.

*From provers to strategies.* Let *P* be a *b*-round state-restoring prover; construct a *b*-augmented strategy *s* as follows. Given a valid history (*v₁;:::;vh*) as input, *sP*works by simulating a state-restoration attack by *P* on *V* (①), as follows. For *i 2f*1*;:::;h* 1*g*, in the *i*-th prover round, when *P* chooses a complete verifier state cvs = (*m₁;f₁;:::;m*), we check whether the vertex *vi*+1=: (*m⁰*1*;:::;m0*) in the history is a child of *v*(cvs). If it is not, or if *P* halts, then *sP*outputs*?*. Otherwise, we respond to *P* with *m0*and continue. In the *h*-th prover round, *s* outputs *v*(cvs).

*From strategies to provers.* Let *s* be a *b*-augmented strategy; construct a *b*-round state-restoring prover *Ps*as follows. In prover round *j*, *Ps*computes *vs*:= *s*((*v₁;:::;vj*)), then restores the state cvs(*vs*), and sends the prover message *fvs s j*+1 *i i*+1 *i*

|. Afterwards, P|sets v := (m₁;:::;m|;m ), where (m₁;:::;m|) are|
|---|---|---|---|
|v|s j+1|i i+1|i|
|s i+1||j+1||

the messages in *v* and *m* is the verifier’s response; if *s*((*v₁;:::;v*)) =*?*, *Ps*halts.

The following lemma justifies the study of tree exploration games in relation to state restoration soundness of interactive oracle proof systems; namely, we prove that *b*-augmented strategies and *b*-round state-restoring provers are equivalent in the following sense.

**Lemma 8.4.** *Let b 2* N*.* *For every b-round state-restoring prover P*~ *for* (*P;V* (①))*,* Pr[*s* *P* ~*wins in GV;*①] Pr[*P* ~ *makes V accept* ①]*.* *For every b-augmented strategy s for GV;*①*,* Pr[*P*~*smakes V accept* ①] = Pr[*s wins in GV;*①]*.*

|Proof. First we prove the first bullet. Note that, by the definition of G|||||||, a b-augmented strategy s wins in|
|---|---|---|---|---|---|---|---|
|V;①||||k(①)||b|f ;:::;f|
|||i||||||
|||||u||||
|0|P~ k(①)|P~ (m|)|(m ;m) f ;:::;f|0 k(①) V;①|(m ;:::;m|) P~|
|||0||||||

*V;*① *GV;*①if and only if there exists *v* = (*m₁;:::;mk*(①)*;r*) *2 Sb*such that *V* *f* *v*(1)*;:::;fv*(*k*(①))(①*;;*; *v*) = 1. Each prover message *f* is a probabilistic function of the messages *m₁;:::;mi*that precede it (‘proba- bilistic’ because *P*~ can obtain independent randomness by restoring some state). Then by Lemma 8.2 we can replace *P*~’s messages with *f*, where *u* is the tuple of verifier messages in the state cvs re- stored at the beginning of the prover round, without reducing its success probability. We call this prover *P* ~; note that *s* *0*= *s*. We observe that *P* ~ succeeds if and only if, after *b* prover rounds, there is some state cvs = (*m₁;f* 1 *;m₂;f* 1 2 *;:::;m;f* 1 *k*(①) *;r*) *2* SeenStates such that for *u* := (*m₁;:::;m;r*) it holds that *Vu*(1) *u*(*k*(①))(①*;;*; *u*) = 1. Suppose that we play the tree exploration game *G* with strategy *s0*. We couple this game to an interaction between *P*~ and *V*, and show that, whenever we add a state cvs to SeenStates, we also add the corresponding vertex *v*(cvs) to *H*, the sequence of vertices drawn during the game. These correspond initially because SeenStates = (null), and *H* = (rt(*T*)) = (*v*(null)). Now suppose that we have played *GV;*① coupled to (*P*~ *0* *;V*) for some number of rounds, and the current history *H* corresponds to SeenStates. Also, *s* *P* ~*0*(*H*) =*?* if and only if *P* ~*0*halts because *H* must be consistent with the choices of *s* *P* ~*0*, and moreover *P* ~*0* is deterministic. Let *v⁰* := *s* *P* ~*0*(*H*); observe that *v⁰ 2 H* since cvs(*v⁰*) is restored by *P* ~*0*and hence must be in SeenStates. Then the new vertex *v* added to *H* is chosen uniformly at random from the children of *v⁰*. This is equivalent in distribution to *V* ’s choice of message after *P*~ *0* restores the state cvs(*v⁰*) and sends its message *fv0*; hence we may couple these random choices so that the vertex *v* := *vskm* is added to *H* if and only if

cvs(*v*) is added to SeenStates. Hence *s* *P* ~*0*(i.e., *sP*~) wins in *GV;*①if and only if *P* ~*0*makes *V* accept ① under this coupling, and since the probability that this happens is at least the probability that *P*~ makes *V* accept ①, this concludes the proof of the first bullet. Next we prove the second bullet. The proof is again via coupling argument: consider an interaction between *P*~*s*and *V*. We couple this interaction to *s* played on *GV;*①, and show that whenever we add a vertex *v* to the history *H*, we also add the corresponding state cvs(*v*) to SeenStates. Again, SeenStates and *H* correspond initially. Suppose that (*P*~*s;V*) have interacted for some number of rounds, coupled to *GV;*①, and that SeenStates and *H* correspond. Then cvs := cvs(*s*(*H*)) *2* SeenStates since *s*(*H*) *2 H*, and *P*~*s*is able to restore cvs. Again we observe that the response of *V* and the choice of child of *s*(*H*) are identically distributed, and we may couple them. Under this coupling, a state cvs⁰ := cvs*k*(*fs*(*H*)*;m*) is added to SeenStates if and only if *v*(cvs⁰) is added to *H*. Hence *P*~*s*makes *V* accept ① if and only if *s* wins in *GV;*<u>①</u> under this coupling, which proves the equality.

### 8.3 The expected value strategy

We show how to construct, for every tree exploration game *G* = (*T;*), a simple strategy *s* *?* that has optimal expected cost with respect to all strategies of that game; we call this strategy the *expected value strategy*, for reasons that will become clear below. We associate to each vertex *v 2 T* a *potential* (*v*). If *v* is a leaf and (*v*) = 0, then we set (*v*) := 1; if *v* is a leaf and (*v*) = 0, we set (*v*) := *1*. If *v* is not a leaf, we set ! <u>1</u> X

(*v*) := min *jCvj* + (*u*) *:* *U Cv jU j*
*u2U*

One can show that the smallest *U* minimizing the right hand side is *C<v*:= *fu 2 Cv*: (*u*) *<* (*v*)*g*. The expected value strategy is defined in terms of potentials: for every *S V* (*T*), *s* *?*

(*S*) := arg min*v2S*(*v*).
We first prove that the expected cost of the expected value strategy equals the potential of the root vertex.

### Claim 8.5. E[s?] = (rt(T)).

|=|(frt(T )g) and s|(frt(T )g) = rt(T ), the statement is equivalent to E[|||(W )] =|
|---|---|---|---|---|---|
|s|s|?||s|s ?|
|s||?|s ?|?|?|

*Proof.* Since*???* (*s* *?*

(*W*)) for *W* = *f*rt(*T*)*g*. We prove this by reverse induction on the subtree *W*. So first suppose that
*W* = *V* (*T*). In this case, if there is *v 2 V* (*T*) such that (*v*) = 1 then E[*?* (*V* (*T*))] = 0 = (*s* (*V* (*T*))); otherwise, E[*?* (*V* (*T*))] = *1* = (*s* (*V* (*T*))). This establishes the base case; next we establish the inductive step. Let *W* be a subtree of *T*, and suppose that E[*?* (*W⁰*)] = (*s* (*W⁰*)) for all *W⁰ T* that contain, but do not equal, *W*; we now argue that E[*s?* (*W*)] = (*s* (*W*)) as well. Letting *u* := *s* (*W*) and invoking Equation 1, we obtain that

1 X E[*s?* (*W*)] = 1 + E[*s?* (*W [fvg*)] *jCuj* *v2Cu* 2 3 1 X X

|4||E[ (W )]5|
|---|---|---|
|||s|
|u v2C|v2C C||

= 1 + E[*s?* (*W [fvg*)] +*?* *jC j* *<u u <u* 2 3 1 X = 1 + 4 (*v*) + *jCuC<uj* E[*s?* (*W*)]5 (by the inductive hypothesis) *jCuj* *v2C<u*

Then since *jCuC<uj* = *jCujjC<uj*, we can rearrange to obtain 2 3 <u>jC<ujE[s</u>*?* <u>(W)] 1</u> X = 4*jCuj* + (*v*)5 *jCuj jCuj* *v2C<u*

so that 2 3 <u>1</u> X E[*s?* (*W*)] = 4*jCuj* + (*v*)5 = (*u*)*;* *jC<uj* *v2C<u*

as claimed.

Next we prove that the expected value strategy has optimal expected cost.

**Claim 8.6.** *For any strategy s,* E[*?*

|]|E[].|||||
|---|---|---|---|---|---|
|s|s|||||
|s|s s|s s s v2W|v2W|s s v2frt(T )g|v2W v2V (T )|

*Proof.* Claim 8.5 states that E[*?*] = (rt(*T*)), so it suffices to show that E[] (rt(*T*)). We do so by proving the following statement: for every subtree *W* of *T*, it holds that E[ (*W*)] min (*v*). (We can then take *W* = *f*rt(*T*)*g* to finish the proof because = (*f*rt(*T*)*g*) and min (*v*) = (rt(*T*)).) We proceed by a reverse induction on the subtree *W*. So first suppose that *W* = *V* (*T*). In this case, if there is *v 2 V* (*T*) such that (*v*)=1 then E[ (*V* (*T*))] = 0 = min (*v*); otherwise, E[*s*(*V* (*T*))] = *1* = min*v2V* (*T*)(*v*). This establishes the base case; next we establish the inductive step. Let *W* be a subtree of *T*, and suppose that E[ (*W⁰*)] = min *0* (*v*) for all *W⁰ T* that contain, but do not equal, *W*; we now argue that E[ (*W*)] = min (*v*) as well. By invoking Equation 1 (and rearranging), we obtain that " # <u>1</u> X

|jC j +|E[ (W [fvg)]|
|---|---|
|u|s|
|v2C|W|

E[*s*(*W*)] = *:* *jCuW j* *u*

By the inductive hypothesis, the above is equal to

" # 2 3 <u>1</u> X <u>1</u> X *jCuj* + min (*x*) = 4*jCuj* + (*v*) + *jCuC<uW j*(*w*)5*;* *jCuW j x2W [fvg u*

|||jC|W j|||||
|---|---|---|---|---|---|---|---|
|v2C v2W|W|u||v2C|W|||
|<u|||||<u|||
|||u||||||
|u|<u|v2C|W||u|||
|<u||<u||||||
|u||u|||<u|u||

*v2Cu W v2C<u W*

where *w* := arg min (*v*). Rearranging, this is equal to 2 3 <u>jC W j 1</u> X <u>jC W j</u> 4*jC j* + (*v*)5 + 1 (*w*) *jC W j jC W j jC W j* *<u* <u>jC W j jC W j</u>

(*u*) + 1 (*w*) (*w*)*;*
*jC W j jC W j*

where the first inequality follows from the construction of (*u*) and that (*C W*) *C*, and the second follows since (*u*) (*w*) by the choice of *w*; this concludes the proof the claim.

## Acknowledgments

The authors thank Allan Borodin and Tyrone Strangway for their input on tree exploration games, and Ran Canetti and Nir Bitansky for helpful discussions. This project was funded in part by the ETH Foundation.

## A Interactive oracle proofs characterize NEXP

We prove that interactive oracle proofs characterize the complexity class NEXP.

**Lemma A.1.** *For every relation R and polynomially-bounded k*: *f*0*;* 1*g!* N*, R is in* NEXP *if and only if* *R has an interactive oracle proof system with round complexity k and constant soundness. Moreover, the* *same is true if we restrict our attention to only interactive oracle proof systems that are public-coin.*

*Proof.* Suppose that *R* is in NEXP. Then *R* has a PCP with polynomially-bounded randomness and query complexity, since NEXP = PCP(poly*;*poly) (see, e.g., [AB09, p. 164]). The PCP immediately gives a public-coin interactive oracle proof with one round and the same soundness: the IOP verifier sends an empty first message, the IOP prover answers with the PCP proof, and the IOP verifier runs the PCP verifier. Conversely, suppose that *R* has an interactive oracle proof system (*P;V*) with round complexity *k* and constant soundness. We argue that *R* has a 2*k*-prover interactive proof system, which implies that *R* is in NEXP (since MIP = NEXP). We think of the 2*k* provers as *k* pairs of provers such that the *i*-th pair is responsible for the *i*-th IOP prover message *fi*. Following a simulation argument in [BFL90], the MIP verifier simulates the IOP verifier *V* as follows. First, run *V* until it halts, forwarding its output messages and answering its oracle queries as follows: when *V* outputs the *i*-th message *mi*, send the message history *m₁;:::;mi*to each prover in the *i*-th pair; when *V* makes a query to the *i*-th oracle, send to the first prover in the *i*-th pair, and answer by returning that prover’s answer. Next, once has *V* halted, pick a query of *V* at random and send it to the second prover of the pair whose first prover had answered. Finally, reject if *V* had rejected or the answer to the randomly-picked query is inconsistent with the previous one. Define *fi*to be the string such that *fi*( ) is the value returned by the second prover of the *i*-th pair when receiving the query (and no other query). If the first prover in the *i*-th pair ever answers a query with a value different from *fi*( ), then the MIP verifier rejects with probability at least 1*=q*; else, if the first prover in the *i*-th pair answers every query consistently with *fi*, then it behaves as the oracle *fi*. Overall, if some pair’s first prover answers inconsistently, then the MIP verifier rejects with probability at least 1*=q*; else, if every pair’s first prover answers consistently with its second prover, then convincing the MIP verifier is equivalent to convincing the IOP verifier *V*. The soundness error is thus 1 (1*=q*). Repeating the protocol polynomially many times (sequential repetition suffices) can reduce the soundness error to, e.g., less than 1*=*3.

## B Soundness error reduction

We discuss approaches for soundness error reduction for IOPs (Appendix B.1) and NIROPs (Appendix B.2), and then discuss how these interact with the transformation that compiles one into the other (Appendix B.3).

### B.1 Soundness error reduction for IOPs

Similarly to the case of interactive proof systems, one can define sequential and parallel repetition of interactive oracle proof systems, and both yield exact exponential decay in the soundness error. Below we provide additional details about each, including how other parameters, in addition to soundness, change.

*Sequential repetition.* Given *r 2* N, the *r*-fold sequential repetition of an interactive oracle proof system (*P;V*) is the interactive oracle proof system (*Pr;Vr*) that is obtained by running *r* independent instances of (*P;V*) in sequence (and where the new verifier *Vr*accepts if and only if all *r* invocations of *V* accept).

||r||
|---|---|---|
|prv ver|r r|prv ver|

If (*P;V*) has complexity (*k;s;p;q;t;t*) then (*P;V*) has complexity (*rk;s* *r* *;rp;rq;rt;rt*).

*Parallel repetition.* Given *r 2* N, the *r*-fold parallel repetition of an interactive oracle proof system (*P;V*) is the interactive oracle proof system (*Pr;Vr*) that is obtained by running *r* independent instances of (*P;*

*V*) in parallel (and where the new verifier *Vr*accepts if and only if all *r* invocations of *V* accept).

|r|||
|---|---|---|
|prv ver|r r|prv ver|
 If (*P;V*) has complexity (*k;s;p;q;t;t*) then (*P;V*) has complexity (*k;s*
*r* *;rp;rq;rt;rt*).

In the case of parallel repetition, the proof of the exact exponential decay of the soundness error is similar to that for interactive proofs. Namely, Goldreich’s game-tree approach [Gol99, pp. 145–149] carries over, because it does not depend on whether the prover’s messages are read in their entirety by the verifier (as in interactive proofs) or are only queried at some locations (as in interactive oracle proofs); in particular, the prover has complete information about the game and may act to maximize *V* ’s acceptance probability.

### B.2 Soundness error reduction for NIROPs

Because non-interactive random-oracle proof systems are not an interactive proof system, the intuitive notions of sequential and parallel repetition coincide; so we talk about *repetition* (without any qualifying adjectives). We now explain what this means, and show that it yields exact exponential decay in the soundness error. We also discuss how other parameters, in addition to soundness, change. **Repeating a NIROP.** Given *r 2* N, the *r*-fold repetition of a non-interactive random-oracle proof system (P*;*V) is the non-interactive random-oracle proof system (P*r;* V*r*) that, letting*i*(*x*) denote (*ikx*) for each *2U*() and *i 2f*1*;:::;rg*, works as follows. P*r*(①*;*✇) independently computes*i*:= P*i*(①*;*✇) for each *i 2f*1*;:::;rg* and outputs := (1*;:::;r*). V*r*(①*;*) runs V1(①*;*1)*;:::;*V*r*(①*;r*) and accepts if and only if all of the verifiers accept. **Changes in parameters.** Repetition of a NIROP affects its parameters as follows.

|If (P; V) has complexity (s;p;t|;t ) then (P|; V ) has complexity (s||;rp;rt|;rt|
|---|---|---|---|---|---|
||prv ver r|r r|r|r r|prv|

*r* ver).

**Lemma B.1.** *If* (P*;*V) *has soundness s*(①*;m;*)*, then* (P*;* V) *has soundness s⁰ satisfying*

### s(①;m=r;) s⁰(①;m;) s(①;m;) :

*Proof.* We prove the first inequality. Let P~ be an *m=r*-query prover that convinces V to accept on ① *2=* *L* (*R*) with probability at least *s*(①*;m=r;*). Consider the *m*-query prover P~

(*r*) that runs *r* copies of P~
independently, with the *i*-th copy querying*i*; the probability that P~

(*r*) convinces V*r*is at least *s*(①*;m=r;*)
*r*, by independence. We now prove the second inequality. Let P~ be an *m*-query prover and ① *2= L* (*R*). We show that *s*(①*;m;*) *r*, where *U* () := Pr V*r*(①*;*) = 1 ~ *:* P

Rewriting the right-hand side, we obtain that 2 3 1 (①*;*1) = 1 1 *;:::;r U* () 6 V ( 1 *; ;:::;*) P~ 1 *;:::;r* 7

6. ..
7 = Pr 6. 7 *:*

4.. 5 V*r*(①*;r*) = 1
~ 1*;:::;r* (*;:::; ;r*) P

The above implies that there exist *m*-query provers P~1*;:::;*P~*r*such that 2 3 1 (①*;*1) = 1 1 *;:::;r U* () 6 V 1P ~17

6. ..
1 7 Pr 6. 7*;*

4.. 5 V*r*(①*;r*) = 1
~*r* *r*P*r*

because, for each *i 2f*1*;:::;rg*, we can hardcode the answers to P~*i*from*j*with *j 6*= *i* in order to maximize the probability that V*i*(①*;i*) accepts. Then, by independence, the above probability is bounded from above by *s*(①*;m;*) *r*, and the lemma follows.

**Lemma B.2.** *If* (P*;*V) *has z-statistical zero knowledge, then* (P*r;* V*r*) *has rz-statistical zero knowledge.*

*Proof.* The proof is by a hybrid argument. We start by defining some useful notation: for functions S *r* S *r* 1 *;:::;r*with disjoint domains *X₁;:::;Xr*, let *i*=1 *i* denote the function *f* with domain *i*=1 *Xi*where *f* (*x*) =*i*(*x*) for every *i 2f*1*;:::;rg* and *x 2 Xi*. Let S*r*be the “repetition” of the simulator S for (P*;*V) that shows its *z*-statistical zero knowledge. Given any distinguisher *Dr*, define

[] *U* () *U* () := Pr *Dr*() = 1 Pr *Dr*() = 1 *:*

(*;*) S*r*(①) P*r*(①*;*✇)
S *i* Let *Ai*be the oracle algorithm that, on input (①*;*✇), outputs ((1*;:::;r*)*;* *j*=1 *j* ) where: (i) for *j* = 1*;:::;i*, (*j;j*) S*r* *j*

(①); and (ii) for *j* = *i* + 1*;:::;r*,*j*P*r*
*j* (①*;*✇). Note that *A₀* is equivalent to P*r* and *Ar*is equivalent to S*r*(when discarding ✇). Then

X *r* *U* () *U* () = Pr *Dr* [] () = 1 Pr *Dr* [] () = 1 *:*

(*;*) *A*
*i* (①*;*✇) (*;*) *A* *i* 1 (①*;*✇) *i*=1

Consider the distinguisher *D* that, on input and with oracle access to, works as follows: (1) choose *i 2 f*1*;:::;rg* uniformly at random; (2) for *j* = 1*;:::;i* 1, compute (*j;j*) S*r* *j*

(①); (3) for *j* =
*j* S *i* 1 *i* + 1*;:::;r*, compute*j*P*r*(①*;*✇), where ✇ may be hard-coded into *D*; (4) setting := *j*=1 *j*,

*0* [] *0* simulate *Dr*((1*;:::;i* 1*;;i*+1*;:::;r*)), where (*ikx*) := (*x*) and other responses are drawn uniformly at random, and return its output. Note that if is produced by P, then the distribution corresponds to *Ai* 1; if is produced by S, then it corresponds to *Ai*instead. Therefore,

[] *U* () *U* () *z*(①*;*) Pr *D* () = 1 Pr *D* () = 1

(*;*) S (①) P (①*;*✇)
X *r* <u>1</u>[] *U* ()[] *U* () = Pr *Dr*() = 1 Pr *Dr*() = 1 *r* (*;*) *Ai*(①*;*✇) (*;*) *Ai* 1(①*;*✇) *i*=1 = *=r :*

Rearranging, we obtain that *rz*(①*;*) and the lemma follows.

### B.3 Strategies for soundness error reduction

Parallel repetition of IOPs is superior to sequential repetition of IOPs because the latter increases the number of rounds but not does not offer advantages in return. A more interesting question is whether it is better to:

(1) first reduce the soundness error of an IOP and then convert it to a NIROP via the transformation *T*, or
(2) first transform the IOP to a NIROP and then reduce the soundness error. The first method yields a soundness error of
*km*(①) *s*(①) *r* + *O*(*m²*2), while the second yields one of ( *km*(①) *s*(①) + *O*(*m²*2)) *r*. The first method is the only one that is effective when *km*(①) *s*(①) 1; indeed, the second method also amplifies the soundness loss incurred by the transformation, and hence is less effective for reducing soundness error. With respect to other complexity measures, both methods perform similarly. In sum, the first method is generally the preferable strategy for soundness error reduction.

## C Zero knowledge with non-programmable random oracles

We provide a lemma showing that, for non-interactive random-oracle proof systems with zero knowledge in the non-programmable random oracle model, “simulation is as hard as decision”. The lemma is a simple adaptation of [Pas03, Theorem 7], and implies that non-trivial languages do not have efficient simulators.

**Lemma C.1.** *Let* (P*;*V) *be a non-interactive random oracle-proof system for a relation R with soundness* *s*(①*;m;*) 1*=*3 *(for all sufficiently large j*①*j;m;). If* (P*;*V) *has z-statistical zero knowledge with* *z*(①*;*) 1*=*3 *(for all sufficiently large j*①*j;) in the non-programmable random oracle model with a* *simulator* S *that runs in time t*(*n*)*, then R 2* BPTIME(poly(*t*(*n*)))*.*

*Proof.* Consider the probabilistic decider algorithm *D* that, given an instance ①, seeks to decide if ① belongs to *L* (*R*) as follows: (i) choose a sufficiently large security parameter; (ii) simulate a random oracle *2U*() in the straightforward way; (iii) compute (*;*) := S (①); (iv) compute and output V (①*;*). Note that [] = (since the random oracle is non-programmable) and that *D* runs in time poly(*t*(*n*)). We claim that *D* shows that *R* lies in BPTIME(poly(*t*(*n*))). Fixing a sufficiently large instance ①, consider the following two cases.

Case 1: ① *2 L*(*R*). We claim that Pr[*D*(①) = 1] 2*=*3. Suppose, by way of contradiction, that Pr[*D*(①) = 1] *<* 2*=*3. By construction of *D*, we deduce that

*U* () := Pr V (①*;*) = 1 *<* 2*=*3 *:*

(*;*) S (①)
On the other hand, by the completeness of (P*;*V), we know that

*U* () Pr V (①*;*) = 1 = 1 *:* P (①*;*✇)

Now let *X* and *Y* be the random variables that denote the output of V in the probability distributions of the above two probability statements, respectively. Then <u>1</u> (*X*; *Y*) = (*j*Pr[*X* = 0] Pr[*Y* = 0]*j* + *j*Pr[*X* = 1] Pr[*Y* = 1]*j*) 2 <u>1</u> = (*j*(1) 0*j* + *j* 1*j*) = 1 *>* 1*=*3 *z*(①*;*)*;* 2 which contradicts the zero knowledge property.

Case 2: ① *62 L*(*R*). We claim that Pr[*D*(①) = 1] 1*=*3. By the soundness of (P*;*V), for every *m*-query P ~, and *2* N, *U* () Pr V (①*;*) = 1 ~ *s*(①*;m;*) *:* P

In particular, for sufficiently large *m*, this holds for the *t*(*j*①*j*)-query prover P~ that computes (*;*) := S (①) and outputs. Thus, by construction of *D*,

*U* () Pr[*D*(①) = 1] = Pr V (①*;*) = 1

(*;*) S (①) *U* ()
= Pr V (①*;*) = 1 ~ *s*(①*;m;*) 1*=*3*:* P

## References

[AB09] Sanjeev Arora and Boaz Barak. *Computational Complexity: A Modern Approach*. Cambridge University Press, New York, NY, USA, 1st edition, 2009. [ALM + 92] Sanjeev Arora, Carsten Lund, Rajeev Motwani, Madhu Sudan, and Mario Szegedy. Proof verification and hardness of approximation problems. In *Proceedings of the 33rd Annual Symposium on Foundations of Computer Science*, pages 14–23, 1992. [ALM + 98] Sanjeev Arora, Carsten Lund, Rajeev Motwani, Madhu Sudan, and Mario Szegedy. Proof verification and the hardness of approximation problems. *Journal of the ACM*, 45(3):501–555, 1998. Preliminary version in FOCS ’92. [AS98] Sanjeev Arora and Shmuel Safra. Probabilistic checking of proofs: a new characterization of NP. *Journal of the ACM*, 45(1):70–122, 1998. Preliminary version in FOCS ’92. [Bab85] Laszl ´ o Babai. Trading group theory for randomness. In ´ *Proceedings of the 17th Annual ACM Symposium on Theory of* *Computing*, STOC ’85, pages 421–429, 1985. [Bab90] Laszlo Babai. E-mail and the Unexpected Power of Interaction. Technical report, University of Chicago, Chicago, IL, USA, 1990. [BBP04] Mihir Bellare, Alexandra Boldyreva, and Adriana Palacio. An uninstantiable random-oracle-model scheme for a hybrid-encryption problem. In *Proceedings of the 23rd Annual International Conference on Theory and Application of* *Cryptographic Techniques*, EUROCRYPT ’04, pages 171–188, 2004. [BC86] G. Brassard and Claude Crepeau. Non-transitive transfer of confidence: A perfect zero-knowledge interactive protocol for SAT and beyond. In *27th Annual Symposium on Foundations of Computer Science, 1986*, pages 188–195, October

1986.
[BC12] Nir Bitansky and Alessandro Chiesa. Succinct arguments from multi-prover interactive proofs and their efficiency benefits. In *Proceedings of the 32nd Annual International Cryptology Conference*, CRYPTO ’12, pages 255–272, 2012. [BCC88] Gilles Brassard, David Chaum, and Claude Crepeau. Minimum disclosure proofs of knowledge. ´ *Journal of Computer* *and System Sciences*, 37(2):156–189, 1988. [BCCT12] Nir Bitansky, Ran Canetti, Alessandro Chiesa, and Eran Tromer. From extractable collision resistance to succinct non-interactive arguments of knowledge, and back again. In *Proceedings of the 3rd Innovations in Theoretical Computer* *Science Conference*, ITCS ’12, pages 326–349, 2012. [BCG + 16] Eli Ben-Sasson, Alessandro Chiesa, Ariel Gabizon, Michael Riabzev, and Nicholas Spooner. Short interactive oracle proofs with constant query complexity, via composition and sumcheck, 2016. Crypto ePrint 2016/324. [BCGV16] Eli Ben-Sasson, Alessandro Chiesa, Ariel Gabizon, and Madars Virza. Quasilinear-size zero knowledge from linear- algebraic PCPs. In *Proceedings of the 13th Theory of Cryptography Conference*, TCC ’16, pages 33–64, 2016. [BCI + 13] Nir Bitansky, Alessandro Chiesa, Yuval Ishai, Rafail Ostrovsky, and Omer Paneth. Succinct non-interactive arguments via linear interactive proofs. In *Proceedings of the 10th Theory of Cryptography Conference*, TCC ’13, pages 315–333,

2013.
[BD16] Allison Bishop and Yevgeniy Dodis. Interactive coding for interactive proofs. In *Proceedings of the 13th Theory of* *Cryptography Conference*, TCC ’16, pages 352–366, 2016. [BDG + 13] Nir Bitansky, Dana Dachman-Soled, Sanjam Garg, Abhishek Jain, Yael Tauman Kalai, Adriana Lopez-Alt, and Daniel ´ Wichs. Why ”Fiat-Shamir for proofs” lacks a proof. In *Proceedings of the 10th Theory of Cryptography Conference*, TCC ’13, pages 182–201, 2013. [BFL90] Laszl ´ o Babai, Lance Fortnow, and Carsten Lund. ´ Nondeterministic exponential time has two-prover interactive protocols. In *Proceedings of the 31st Annual Symposium on Foundations of Computer Science*, SFCS ’90, pages 16–25,

1990.
[BFLS91] Laszl ´ o Babai, Lance Fortnow, Leonid A. Levin, and Mario Szegedy. Checking computations in polylogarithmic time. ´ In *Proceedings of the 23rd Annual ACM Symposium on Theory of Computing*, STOC ’91, pages 21–32, 1991. [BG93] Mihir Bellare and Oded Goldreich. On defining proofs of knowledge. In *Proceedings of the 12th Annual International* *Cryptology Conference on Advances in Cryptology*, CRYPTO ’92, pages 390–420, 1993. [BG08] Boaz Barak and Oded Goldreich. Universal arguments and their applications. *SIAM Journal on Computing*, 38(5):1661– 1694, 2008. Preliminary version appeared in CCC ’02.

[BGGL01] Boaz Barak, Oded Goldreich, Shafi Goldwasser, and Yehuda Lindell. Resettably-sound zero-knowledge and its applications. In *Proceedings of the 42nd Annual IEEE Symposium on Foundations of Computer Science*, FOCS ’01, pages 116–125, 2001. [BGH + 04] Eli Ben-Sasson, Oded Goldreich, Prahladh Harsha, Madhu Sudan, and Salil Vadhan. Robust PCPs of proximity, shorter PCPs and applications to coding. In *Proceedings of the 26th Annual ACM Symposium on Theory of Computing*, STOC ’04, pages 1–10, 2004. [BGKW88] Michael Ben-Or, Shafi Goldwasser, Joe Kilian, and Avi Wigderson. Multi-prover interactive proofs: how to remove intractability assumptions. In *Proceedings of the 20th Annual ACM Symposium on Theory of Computing*, STOC ’88, pages 113–131, 1988. [BGL + 15] Nir Bitansky, Sanjam Garg, Huijia Lin, Rafael Pass, and Sidharth Telang. Succinct randomized encodings and their applications. In *Proceedings of the 47th ACM Symposium on the Theory of Computing*, STOC ’15, pages 439–448,

2015.
[BHZ87] Ravi B. Boppana, Johan Hastad, and Stathis Zachos. Does co-NP have short interactive proofs? ˚ *Information Processing* *Letters*, 25(2):127–132, 1987. [BKK + 13] Eli Ben-Sasson, Yohay Kaplan, Swastik Kopparty, Or Meir, and Henning Stichtenoth. Constant rate PCPs for Circuit- SAT with sublinear query complexity. In *Proceedings of the 54th Annual IEEE Symposium on Foundations of Computer* *Science*, FOCS ’13, pages 320–329, 2013. [BR93] Mihir Bellare and Phillip Rogaway. Random Oracles Are Practical: A Paradigm for Designing Efficient Protocols. In *Proceedings of the 1st ACM Conference on Computer and Communications Security*, CCS ’93, pages 62–73, New York, NY, USA, 1993. ACM. [BS08] Eli Ben-Sasson and Madhu Sudan. Short PCPs with polylog query complexity. *SIAM Journal on Computing*, 38(2):551–607, 2008. Preliminary version appeared in STOC ’05. [CCC + 15] Yu-Chi Chen, Sherman S. M. Chow, Kai-Min Chung, Russell W. F. Lai, Wei-Kai Lin, and Hong-Sheng Zhou. Computation-trace indistinguishability obfuscation and its applications. Cryptology ePrint Archive, Report 2015/406,

2015.
[CGH04] Ran Canetti, Oded Goldreich, and Shai Halevi. The random oracle methodology, revisited. *Journal of the ACM*, 51(4):557–594, 2004. [CH15]Ran Canetti and Justin Holmgren. Succinct garbled RAM. Cryptology ePrint Archive, Report 2015/388, 2015. [CHJV15] Ran Canetti, Justin Holmgren, Abhishek Jain, and Vinod Vaikuntanathan. Succinct garbling and indistinguishability obfuscation for RAM programs. In *Proceedings of the 47th ACM Symposium on the Theory of Computing*, STOC ’15, pages 429–437, 2015. [Dam89] Ivan Damgard. ˚ A design principle for hash functions. In *Proceedings of the 9th Annual International Cryptology* *Conference*, CRYPTO ’89, pages 416–427, 1989. [DFH12] Ivan Damgard, Sebastian Faust, and Carmit Hazay. ˚ Secure two-party computation with low communication. In *Proceedings of the 9th Theory of Cryptography Conference*, TCC ’12, pages 54–74, 2012. [FLS90] Uriel Feige, Dror Lapidot, and Adi Shamir. Multiple non-interactive zero knowledge proofs based on a single random string. In *Proceedings of the 31st Annual Symposium on Foundations of Computer Science*, FOCS ’90, pages 308–317,

1990.
[FRS88] Lance Fortnow, John Rompel, and Michael Sipser. On the power of multi-prover interactive protocols. In *Theoretical* *Computer Science*, pages 156–161, 1988. [FS86] Amos Fiat and Adi Shamir. How to prove yourself: practical solutions to identification and signature problems. In *Proceedings of the 6th Annual International Cryptology Conference*, CRYPTO ’86, pages 186–194, 1986. [GGPR13] Rosario Gennaro, Craig Gentry, Bryan Parno, and Mariana Raykova. Quadratic span programs and succinct NIZKs without PCPs. In *Proceedings of the 32nd Annual International Conference on Theory and Application of Cryptographic* *Techniques*, EUROCRYPT ’13, pages 626–645, 2013. [GH98] Oded Goldreich and Johan Hastad. On the complexity of interactive proofs with bounded communication. ˚ *Information* *Processing Letters*, 67(4):205–214, 1998. [GHRW14] Craig Gentry, Shai Halevi, Mariana Raykova, and Daniel Wichs. Outsourcing private RAM computation. In *Proceedings* *of the 55th Annual IEEE Symposium on Foundations of Computer Science*, FOCS ’14, pages 404–413, 2014.

[GIMS10]

[GK03]

[GKR08]

[GLR11]

[GMR89]

[Gol99]

[Gro10]

[GS86]

[GVW02]

[Hol07]

[HS00]

[IKM09]

[IKO07]

[IMS12]

[IMSX15]

[Ito10]

[Kil92]

[KP15]

[KR08]

[KR09]

[KRR13]

[KRR14]

Vipul Goyal, Yuval Ishai, Mohammad Mahmoody, and Amit Sahai. Interactive locking, zero-knowledge PCPs, and unconditional cryptography. In *Proceedings of the 30th Annual Conference on Advances in Cryptology*, CRYPTO’10, pages 173–190, 2010. Shafi Goldwasser and Yael Tauman Kalai. On the (in)security of the Fiat-Shamir paradigm. In *Proceedings of the 44th* *Annual IEEE Symposium on Foundations of Computer Science*, FOCS ’03, pages 102–113, 2003. Shafi Goldwasser, Yael Tauman Kalai, and Guy N. Rothblum. Delegating computation: Interactive proofs for Muggles. In *Proceedings of the 40th Annual ACM Symposium on Theory of Computing*, STOC ’08, pages 113–122, 2008. Shafi Goldwasser, Huijia Lin, and Aviad Rubinstein. Delegation of computation without rejection problem from designated verifier CS-proofs. Cryptology ePrint Archive, Report 2011/456, 2011. Shafi Goldwasser, Silvio Micali, and Charles Rackoff. The knowledge complexity of interactive proof systems. *SIAM* *Journal on Computing*, 18(1):186–208, 1989. Preliminary version appeared in STOC ’85. Oded Goldreich. *Modern Cryptography, Probabilistic Proofs and Pseudorandomness*, volume 17 of *Algorithms and* *Combinatorics*. Springer Berlin Heidelberg, Berlin, Heidelberg, 1999. Jens Groth. Short pairing-based non-interactive zero-knowledge arguments. In *Proceedings of the 16th International* *Conference on the Theory and Application of Cryptology and Information Security*, ASIACRYPT ’10, pages 321–340,

2010. S Goldwasser and M Sipser. Private Coins Versus Public Coins in Interactive Proof Systems. In *Proceedings of the* *Eighteenth Annual ACM Symposium on Theory of Computing*, STOC ’86, pages 59–68, New York, NY, USA, 1986. ACM. Oded Goldreich, Salil Vadhan, and Avi Wigderson. On interactive proofs with a laconic prover. *Computational* *Complexity*, 11(1/2):1–53, 2002. Thomas Holenstein. Parallel repetition: simplifications and the no-signaling case. In *Proceedings of the 39th Annual* *ACM Symposium on Theory of Computing*, STOC ’07, pages 411–419, 2007. Prahladh Harsha and Madhu Sudan. Small PCPs with low query complexity. *Computational Complexity*, 9(3–4):157– 201, Dec 2000. Preliminary version in STACS ’91. Tsuyoshi Ito, Hirotada Kobayashi, and Keiji Matsumoto. Oracularization and two-prover one-round interactive proofs against nonlocal strategies. In *Proceedings of the 24th IEEE Annual Conference on Computational Complexity*, CCC ’09, pages 217–228, 2009. Yuval Ishai, Eyal Kushilevitz, and Rafail Ostrovsky. Efficient arguments without short PCPs. In *Proceedings of the* *Twenty-Second Annual IEEE Conference on Computational Complexity*, CCC ’07, pages 278–291, 2007. Yuval Ishai, Mohammad Mahmoody, and Amit Sahai. On efficient zero-knowledge PCPs. In *Proceedings of the 9th* *International Conference on Theory of Cryptography*, TCC ’12, pages 151–168, 2012. Yuval Ishai, Mohammad Mahmoody, Amit Sahai, and David Xiao. On zero-knowledge PCPs: Limitations, simplifica- tions, and applications, 2015. Available at http://www.cs.virginia.edu/˜mohammad/files/papers/ ZKPCPs-Full.pdf. Tsuyoshi Ito. Polynomial-space approximation of no-signaling provers. In *Proceedings of the 37th International* *Colloquium on Automata, Languages and Programming*, ICALP ’10, pages 140–151, 2010. Joe Kilian. A note on efficient zero-knowledge proofs and arguments. In *Proceedings of the 24th Annual ACM* *Symposium on Theory of Computing*, STOC ’92, pages 723–732, 1992. Yael Tauman Kalai and Omer Paneth. Delegating RAM computations. Cryptology ePrint Archive, Report 2015/957,
2015. Yael Kalai and Ran Raz. Interactive PCP. In *Proceedings of the 35th International Colloquium on Automata, Languages* *and Programming*, ICALP ’08, pages 536–547, 2008. Yael Tauman Kalai and Ran Raz. Probabilistically checkable arguments. In *Proceedings of the 29th Annual International* *Cryptology Conference*, CRYPTO ’09, pages 143–159, 2009. Yael Kalai, Ran Raz, and Ron Rothblum. Delegation for bounded space. In *Proceedings of the 45th ACM Symposium* *on the Theory of Computing*, STOC ’13, pages 565–574, 2013. Yael Tauman Kalai, Ran Raz, and Ron D. Rothblum. How to delegate computations: the power of no-signaling proofs. In *Proceedings of the 46th Annual ACM Symposium on Theory of Computing*, STOC ’14, pages 485–494, 2014.

[LFKN92]

[Lin15]

[Lip12]

[Mer89a]

[Mer89b]

[Mic00]

[Nie02]

[Pas03]

[PGHR13]

[PR14]

[PS96]

[PS05]

[PSSV07]

[Raz95]

[RRR16]

[SBV + 13]

[SBW11]

[SMBW12]

[SVP + 12]

[Val08]

[Wee09]

Carsten Lund, Lance Fortnow, Howard J. Karloff, and Noam Nisan. Algebraic methods for interactive proof systems. *Journal of the ACM*, 39(4):859–868, 1992. Yehuda Lindell. An efficient transform from sigma protocols to NIZK with a CRS and non-programmable random oracle. In *Proceedings of the 12th Theory of Cryptography Conference*, TCC ’15, pages 93–109, 2015. Helger Lipmaa. Progression-free sets and sublinear pairing-based non-interactive zero-knowledge arguments. In *Proceedings of the 9th Theory of Cryptography Conference on Theory of Cryptography*, TCC ’12, pages 169–189,

2012. Ralph C. Merkle. A certified digital signature. In *Proceedings of the 9th Annual International Cryptology Conference*, CRYPTO ’89, pages 218–238, 1989. Ralph C. Merkle. One way hash functions and DES. In *Proceedings of the 9th Annual International Cryptology* *Conference*, CRYPTO ’89, pages 428–446, 1989. Silvio Micali. Computationally sound proofs. *SIAM Journal on Computing*, 30(4):1253–1298, 2000. Preliminary version appeared in FOCS ’94. Jesper Buus Nielsen. Separating random oracle proofs from complexity theoretic proofs: The non-committing encryption case. In *Proceedings of the 22nd Annual International Cryptology Conference*, CRYPTO ’02, pages 111–126, 2002. Rafael Pass. On deniability in the common reference string and random oracle model. In *Proceedings of the 23rd* *Annual International Cryptology Conference*, CRYPTO ’03, pages 316–337, 2003. Brian Parno, Craig Gentry, Jon Howell, and Mariana Raykova. Pinocchio: Nearly practical verifiable computation. In *Proceedings of the 34th IEEE Symposium on Security and Privacy*, Oakland ’13, pages 238–252, 2013. Omer Paneth and Guy N. Rothblum. Publicly verifiable non-interactive arguments for delegating computation. Cryptology ePrint Archive, Report 2014/981, 2014. David Pointcheval and Jacques Stern. Security proofs for signature schemes. In *Proceedings of the 14th Annual* *International Conference on Theory and Application of Cryptographic Techniques*, EUROCRYPT ’96, pages 387–398,
1996. Rafael Pass and Abhi Shelat. Unconditional characterizations of non-interactive zero-knowledge. In *Proceedings of the* *25th Annual International Cryptology Conference*, CRYPTO ’05, pages 118–134, 2005. Aduri Pavan, Alan L. Selman, Samik Sengupta, and Vinodchandranm N. V. Polylogarithmic-round interactive proofs for coNP collapse the exponential hierarchy. *Theoretical Computer Science*, 385(1-3):167–178, 2007. Ran Raz. A parallel repetition theorem. In *Proceedings of the 27th Annual ACM Symposium on Theory of Computing*, STOC ’95, pages 447–456, 1995. Omer Reingold, Ron Rothblum, and Guy Rothblum. Constant-round interactive proofs for delegating computation. In *Proceedings of the 48th ACM Symposium on the Theory of Computing*, STOC ’16, pages ???–???, 2016. Srinath Setty, Benjamin Braun, Victor Vu, Andrew J. Blumberg, Bryan Parno, and Michael Walfish. Resolving the conflict between generality and plausibility in verified computation. In *Proceedings of the 8th EuoroSys Conference*, EuroSys ’13, pages 71–84, 2013. Srinath Setty, Andrew J. Blumberg, and Michael Walfish. Toward practical and unconditional verification of remote computations. In *Proceedings of the 13th USENIX Conference on Hot Topics in Operating Systems*, HotOS ’11, pages 29–29, 2011.
*Journal of the ACM*, 39(4):869–877, 1992. Srinath Setty, Michael McPherson, Andrew J. Blumberg, and Michael Walfish. Making argument systems for outsourced computation practical (sometimes). In *Proceedings of the 2012 Network and Distributed System Security Symposium*, NDSS ’12, 2012. Srinath Setty, Victor Vu, Nikhil Panpalia, Benjamin Braun, Andrew J. Blumberg, and Michael Walfish. Taking proof- based verified computation a few steps closer to practicality. In *Proceedings of the 21st USENIX Security Symposium*, Security ’12, pages 253–268, 2012. Paul Valiant. Incrementally verifiable computation or proofs of knowledge imply time/space efficiency. In *Proceedings* *of the 5th Theory of Cryptography Conference*, TCC ’08, pages 1–18, 2008. Hoeteck Wee. Zero Knowledge in the Random Oracle Model, Revisited. In Mitsuru Matsui, editor, *Advances in* *Cryptology – ASIACRYPT 2009*, number 5912 in Lecture Notes in Computer Science, pages 417–434. Springer Berlin Heidelberg, 2009.

[Sha92]Adi Shamir. IP = PSPACE.
