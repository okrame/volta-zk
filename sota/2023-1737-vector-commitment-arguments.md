# On the Security of Succinct Interactive Arguments from Vector Commitments

*

### Alessandro Chiesa Marcel Dall’Agnol

alessandro.chiesa@epfl.ch dallagnol@princeton.edu EPFL Princeton University

### Ziyi Guan Nicholas Spooner

ziyi.guan@epfl.ch nicholas.spooner@warwick.ac.uk EPFL University of Warwick & NYU

### September 14, 2024

**Abstract**

We study the security of a fundamental family of succinct interactive arguments in the standard model, stemming from the works of Kilian (1992) and Ben-Sasson, Chiesa, and Spooner (“BCS”, 2016). These constructions achieve succinctness by combining probabilistic proofs and vector commitments. Our first result concerns the succinct interactive argument of Kilian, realized with any probabilistically- checkable proof (PCP) and any vector commitment. We establish the tightest known bounds on the security of this protocol. Prior analyses incur large overheads, or assume restrictive properties of the underlying PCP. Our second result concerns an interactive variant of the BCS succinct non-interactive argument, which here we call IBCS, realized with any public-coin interactive oracle proof (IOP) and any vector commitment. We establish the first security bounds for the IBCS protocol. Prior works rely upon this protocol without proving its security; our result closes this gap. Finally, we study the capabilities and limitations of succinct arguments based on vector commitments. We show that a generalization of the IBCS protocol, which we call the *Finale protocol*, is secure when realized with any *public-query* IOP (a notion that we introduce) that satisfies a natural “random continuation sampling” (RCS) property. We also show a partial converse: if the Finale protocol satisfies the RCS property (which in particular implies its security), then so does the underlying public-query IOP.

**Keywords**: succinct interactive arguments; vector commitment schemes

* A subset of the material in this paper (that concering Kilian’s protocol) has been included and further developed in https: //ia.cr/2024/1434, subsuming some sections. The other sections in this paper (primarily concerning the IBCS protocol and the Finale protocol) remain relevant.

## Contents

**1 Introduction 3**

1.1 Our results. ................................................4
1.2 Discussion. ................................................6
1.3 Related work...............................................8
**2 Techniques 11**

2.1 Succinct arguments based on PCPs ....................................11
2.2 Succinct arguments based on public-coin IOPs.. ............................17
2.3 Why doesn’t the same analysis work for public-query IOPs?......................20
2.4 Succinct interactive arguments with adaptive security..........................24
**3 Preliminaries 26**

3.1 Interactive arguments...........................................26
3.2 Vector commitments. ..........................................27
3.3 Probabilistically checkable proofs. ...................................28
3.4 Interactive oracle proofs.........................................29
**4 Interactive arguments based on PCPs 31**

4.1 Construction ................................................31
4.2 Security reduction .. ...........................................32
4.3 Adaptive soundness. ...........................................36
4.4 Adaptive knowledge soundness... ...................................38
**5 Interactive arguments based on public-coin IOPs 40**

5.1 Construction ................................................40
5.2 Security reduction .. ...........................................41
5.3 Adaptive soundness. ...........................................45
5.4 Adaptive knowledge soundness... ...................................48
**6 Interactive arguments based on public-query IOPs 51**

6.1 Construction ................................................51
6.2 Random continuation samplers......................................52
6.3 Equivalence of IOP-RCS and ARG-RCS... ..............................56
6.4 Security reduction .. ...........................................57
**Acknowledgments 63**

**References 63**

## 1 Introduction

A *succinct argument* for a relation *R* is a computationally-sound interactive proof where, for a given instance ①, an argument prover seeks to convince the argument verifier that there exists a witness ✇ such that (①*,*✇) *∈ R*, while communicating much fewer than *|*✇*|* bits. Succinct arguments are a central cryptographic object, with numerous theoretical and practical applications. In this paper, we study succinct *interactive* arguments for NP constructed in the standard model (i.e., without oracles) from falsifiable assumptions. 1

In this work we investigate the power and limitations of the **VC-based approach**, a fundamental paradigm for constructing succinct arguments from two ingredients: a probabilistic proof and a vector commitment (VC). Specifically, we set out to understand *which* probabilistic proofs are amenable to the VC-based approach, and then to *quantitatively* relate the security of the succinct argument to the security of the underlying ingredients. In short, we ask:

*What is the security of succinct interactive arguments obtained via the VC-based approach?*

Kilian’s protocol [Kil92] is the first known succinct argument, and the most notable example of a succinct interactive argument obtained via the VC-based approach. The argument prover commits to a probabilistically checkable proof (PCP) string via a vector commitment scheme (Kilian’s presentation uses a Merkle tree, a VC built from collision-resistant hash functions), and sends the resulting commitment to the argument verifier; the argument verifier sends PCP verifier randomness to the argument prover; and finally the argument prover reveals the values of the queried locations of the PCP string and accompanies these values with opening information. The argument verifier accepts if the opening information is valid and the PCP verifier accepts. Despite this simple template, the security of Kilian’s protocol is not well understood. Kilian [Kil92] gives only an informal analysis. Barak and Goldreich [BG08] give a detailed analysis, but with limitations. First, their analysis applies only to PCPs that satisfy restrictive properties; second, their analysis incurs overheads; and third, they restrict their attention to Merkle trees rather than general VCs. This state of affairs motivates our first question: *What is the security of Kilian’s protocol, for any given PCP and VC?* While Kilian’s protocol relies on only basic (and efficient) cryptography, its reliance on PCPs means that it is of limited practical value, as known PCP constructions have poor concrete efficiency. To address this, Ben-Sasson, Chiesa, and Spooner [BCS16] introduced a new paradigm for constructing succinct arguments that builds on Kilian’s idea. To construct a succinct argument, it is not necessary to start with a *non-interactive* object such as a PCP; instead, they construct succinct arguments from an *interactive* generalization of a PCP called an *interactive oracle proof* (IOP) [BCS16; RRR16]. Since then, extensive study of IOPs has resulted in highly efficient IOP constructions, which have facilitated numerous applications of succinct arguments. The aforementioned BCS protocol in fact compiles a (public-coin) IOP into a succinct *non-interactive* argument (SNARG) in the random oracle model. That protocol can be straightforwardly relaxed to an “interactive BCS” (IBCS) protocol in the standard model that, analogously to Kilian’s protocol, uses a Merkle tree (more generally, a vector commitment scheme) to compile a public-coin IOP into a corresponding succinct interactive argument. The IBCS protocol is a key ingredient in a line of work on succinct arguments with highly efficient provers [BCG20; RR22; HR22] but its security has never been proved, leaving a gap in those results. This motivates our second question: *What is the security of IBCS, for any given public-coin* *IOP and VC?* Finally, we observe that one can formulate a natural generalization of IBCS that, syntactically, can be realized from *any* IOP (i.e., including private-coin IOPs). This brings us to our final question: *for what class* *of IOPs is this VC-based approach secure?* 1 Succinct *non-interactive* arguments for NP cannot be proved secure via black-box reductions to falsifiable assumptions [GW11].

### 1.1 Our results

Throughout this section, we fix a vector commitment scheme VC and denote by *ϵ*VCits position binding error, an upper bound on the probability that an adversary outputs two openings for the same commitment that disagree in at least one position. In general, *ϵ*VCis a function of the security parameter *λ*, length *ℓ* of the committed vector, number *s* of opened entries of the vector, and bound *t*VCon the adversary size. **Succinct arguments from PCPs.** We provide the tightest known security bounds for Kilian’s protocol [Kil92], a seminal result that combines a PCP system and a vector commitment scheme to obtain a succinct interactive argument. Let PCP be a PCP system for a relation *R* with proof length l, query complexity q, and soundness error *ϵ*PCP(resp. knowledge soundness error *κ*PCP); these parameters can depend on the given instance ①.

**Theorem 1** (informal)**.** *The soundness error ϵ*ARG*of* Kilian[PCP*,*VC] *satisfies the following for every security* *parameter λ, instance* ① *∈/ L*(*R*)*, adversary size bound t*ARG*, and error tolerance ϵ >* 0*:*

<u>l(①)</u> *ϵ* ARG(*λ,*①*,t*ARG) *≤ ϵ*PCP(①) + *ϵ*VC*λ,* l(①)*,*q(①)*,t*VC+ *ϵ, where t*VC= *O · t*ARG*.* *ϵ*

*Similarly, the knowledge soundness error satisfies κ*ARG(*λ,*①*,t*ARG) *≤ κ*PCP(①) + *ϵ*VC*λ,* l(①)*,*q(①)*,t*VC+ *ϵ.* *In particular, if ϵ*VC*is negligible when t*VC= poly(*λ*)*, then ϵ*ARG(*λ,*①*,*poly(*λ*)) *≤ ϵ*PCP(①) + negl(*λ*) *(and* *similarly for κ*ARG*).*

The above bound has an intuitive explanation. An adversary that commits to the PCP string Πe with maxi- mal acceptance probability (and opens accordingly) succeeds with probability at least *ϵ*PCPin Kilian[PCP*,*VC]. Moreover, an adversary that then tries to find a collision when Πe is rejected achieves (under some mild conditions) a success probability of *ϵ*PCP+ (1 *− ϵ*PCP) *· ϵ*VC. The *ϵ* <u>l</u> multiplicative loss in *t*VCcompared to *t*ARG expresses the cost of rewinding: to reconstruct an almost full PCP string from small fragments revealed in each (accepting) execution, we must rewind the malicious argument prover sufficiently many times. We leave it as an open problem to establish whether the security bound in Theorem 1 is tight or can be improved. **Succinct arguments from public-coin IOPs.** Interaction often leads to dramatic gains in efficiency for proof systems. PCPs are no exception: *interactive oracle proofs* (IOPs) enable such gains by communicating oracle proof strings across multiple rounds. (In particular, a PCP system is an IOP with a single round.) Let IOP be an IOP system for a relation *R* with round complexity k and soundness error *ϵ*IOP(resp. knowledge soundness error *κ*IOP). Owing to its multiple proof strings, the proof length and query complexity in an IOP may vary round by round; we let lmaxand qmaxdenote the maximum proof length and query complexity and let l and q denote the total proof length and query complexity. 2

Our second main result provides the first security analysis for the *interactive BCS* protocol (inspired by [BCS16]), which extends Kilian’s from the case of PCPs to that of *public-coin* IOPs. (An IOP is public-coin if verifier messages are independent uniformly random strings.) As discussed in Section 1.3, this closes a gap in prior works, which used the interactive BCS protocol as an ingredient (without proving its security).

**Theorem 2** (informal)**.** *If* IOP *is public-coin, the soundness error ϵ*ARG*of* IBCS[IOP*,*VC] *satisfies the* *following for every security parameter λ, instance* ① *∈/ L*(*R*)*, adversary size bound t*ARG*, and error tolerance* *ϵ >* 0*:*

<u>k(①) · l(①)</u> *ϵ* ARG(*λ,*①*,t*ARG) *≤ ϵ*IOP(①) + *ϵ*VC*λ,*lmax(①)*,* qmax(①)*,t*VC+ *ϵ, where t*VC= *O · t*ARG*.* *ϵ* 2

|If the IOP verifier V makes q P||P|{l}, q|{q},|
|---|---|---|---|---|
|l :=|l and q :=|q.|||

*i* queries to a proof string of length l*i* in round *i*, then lmax:= max*i i* max:= max*i i* *i i i i*

*Similarly, the knowledge soundness error is κ*ARG(*λ,*①*,t*ARG) *≤ κ*IOP(①) + *ϵ*VC*λ,*lmax(①)*,* qmax(①)*,t*VC+ *ϵ.* *In particular, if ϵ*VC*is negligible when t*VC= poly(*λ*)*, then ϵ*ARG(*λ,*①*,*poly(*λ*)) *≤ ϵ*IOP(①) + negl(*λ*) *(and* *similarly for κ*ARG*).*

The above parameters are analogous to those in Theorem 1 for PCPs, except for a dependence on the round complexity k of the IOP. Again, it is an open question if the loss in *t*VCcompared to *t*ARGis tight.

**How general is the VC-based approach?** Kilian’s protocol realizes query access to a PCP string via a vector commitment scheme: the values of positions queried by the PCP verifier are revealed alongside an opening proof attesting consistency with the commitment. In the IBCS protocol, this VC-based approach is applied round by round to a public-coin IOP. In general, however, an IOP may not be public-coin. We ask: *which IOPs can be compiled into a secure interactive argument via the VC-based approach?* It is not hard to see that there exist private-coin IOPs for which the VC-based approach is insecure, i.e., for which the “natural” generalization of IBCS to private-coin IOPs yields insecure interactive arguments. 3

For example, consider a 2-round IOP where the verifier, after receiving the first proof string from the prover, queries the first proof string at a few locations in order to determine its first message to the prover but *must keep the queried locations secret* from the prover in order to ensure soundness. 4 In the VC-based approach, the argument verifier sends the desired queries to the argument prover in order to subsequently obtain corresponding answers and opening proofs. A malicious argument prover would then be able to use this information to break IOP soundness when choosing which second proof string to commit to.

**The case of public-query IOPs.** The above discussion implies that a *necessary* condition for an IOP to be compatible with the VC-based approach is being **public-query** (a notion that we introduce): soundness (or knowledge soundness) of the IOP must hold even if, whenever the verifier makes a query, the prover learns that this particular query has been made. (Of course, the IOP verifier’s own randomness remains secret.) A public-coin IOP is, in particular, public-query. One may conjecture that the VC-based approach works not only for every public-coin IOP, but also for every public-query IOP. Indeed, we describe a natural protocol that we call Finale[IOP*,*VC] that, intuitively, ought to be secure for every public-query IOP. However, challenges arise when attempting to prove security. The “rewinding proof” of Theorem 2 crucially depends on the existence of an efficient algorithm for sampling IOP verifier randomness *conditioned* *on a partial transcript of interaction* (which includes prior verifier messages and queries). We call this algorithm a *random continuation sampler* (RCS). Public-coin IOPs have a (trivial) RCS, but there exist public- query IOPs that do not: for example, consider an IOP where, in the first round, the verifier cryptographically commits (via a statistically hiding commitment) to all of its subsequent messages. 5 Sampling random continuations for this proof system is computationally infeasible. We show that if IOP has an efficient RCS then Finale[IOP*,*VC] is secure (for any VC). We proceed in two steps: first, we show that if IOP has an RCS then Finale[IOP*,*VC] has an RCS; then, we show that if Finale[IOP*,*VC] has an RCS then it is (knowledge) sound. We also show a partial converse: if Finale[IOP*,*VC] has an RCS, then so does IOP. This suggests that known proof approaches (all of which rely on random continuations) do not suffice to show the security of Finale[IOP*,*VC] for general public-query IOPs.

**Theorem 3** (informal)**.** *Let* IOP *be a public-query IOP that admits a RCS with running time t*S*. The soundness* *error ϵ*ARG*of* Finale[IOP*,*VC] *satisfies the following for every security parameter λ, instance* ① *∈/ L*(*R*)*,*

3 Of course, other approaches (e.g., using additional cryptography beyond VC schemes) could in principle work with every IOP. 4 For example, one can modify an IOP so that the IOP verifier always accepts if the IOP prover guesses the query locations. 5 The zero knowledge interactive proof of [GK96] has this form.

*adversary size bound t*ARG*, and error tolerance ϵ >* 0*:*

<u>k(①) · l(①)</u> *ϵ* ARG(*λ,*①*,t*ARG) *≤ ϵ*IOP(①) + *ϵ*VC(*λ,*lmax*,* qmax*,t*VC) + *ϵ, where t*VC= *O ·* (*t*ARG+ *t*S)*.* *ϵ*

*Similarly, the knowledge soundness error is κ*ARG(*λ,*①*,t*ARG) *≤ κ*IOP(①) + *ϵ*VC(*λ,*lmax*,* qmax*,t*VC) + *ϵ.* *Moreover,* Finale[IOP*,*VC] *admits an RCS if and only if* IOP *admits an RCS.*

We actually prove a stronger version of Theorem 3: our analysis works for every public-query IOP that admits a RCS with an arbitrary sampling error *α*, in which case the (knowledge) soundness error bound of Finale[IOP*,*VC] depends on both *ϵ* and *α*. (See Section 6 for the technical details of this case.)

**Remark 1** (simulatable verifiers)**.** The notion of RCS in Theorem 3 is closely related to the notion of a “simulatable verifier” that appears in the literature on parallel repetition for interactive arguments [HPWP10; CL10]. Specifically, an IOP admits an RCS (with negligible sampling error *α*) if and only if the IOP verifier is (1-)simulatable (without verdict). An interesting research direction is to understand whether there is a deeper connection between standard-model succinct arguments and parallel repetition. For example, can counterexamples to parallel repetition [BIN97] lead us to public-query IOPs for which Finale is not sound?

**Remark 2** (adaptive choice of ①)**.** The results of Theorems 1, 2 and 3 are stated, for simplicity, in the plain model (no trusted setups), where the argument verifier is responsible for sampling and sending public parameters pp for VC to the argument prover. However, we actually *prove* these results in the (adaptive) common reference string model, wherein public parameters pp for VC are sampled by a trusted party and *a* *malicious argument prover may adaptively choose the instance* ① *after learning* pp. Since in these stronger theorems there is no pre-set instance ①, the analogous statements (for corresponding security properties) in the common reference model replace ① with a size bound *n* (and hold for all instances such that *|*①*|≤ n*). The plain model variants are straightforwardly implied (see Section 2.4 and Remark 3.6).

### 1.2 Discussion

**On the price of rewinding.** We compare the soundness of Kilian’s protocol when analyzed via: (i) a rewinding extractor based on a collision resistant hash function; or (ii) a straightline extractor based on an ideal hash function (a random oracle). Our results enable, for the first time, an accounting of the “price of rewinding” for succinct arguments: the cost of a more expensive security reduction that works under weaker assumptions on the underlying cryptography.

(i) *Rewinding extractor.* Suppose that the vector commitment scheme VC is obtained from a collision- resistant hash function (via a Merkle tree) with security *ϵ*CRH(*λ,t*CRH). By Remark 3 this means that
*ϵ* VC(*λ,ℓ,s,t*VC) *≤ ϵ*CRH*λ,t*CRH= *t*VC+ *O*(*thλ·* q *·* log l)*.*

Suppose that *ϵ*CRH(*λ,t*CRH) *≤ t²*CRH*/*2 *λ*, which is what would be achieved by an ideal hash function. In this case, Theorem 1 gives the following upper bound on the soundness error for Kilian[PCP*,*VC]: ! 2 <u>1 l</u> *ϵ* ARG(*λ,*①*,t*ARG) *≤ ϵ*PCP(①) + *Oλ· · t*ARG+ *thλ·* q *·* log l + *ϵ .* 2 *ϵ*

|2/3 −λ/3|/3|−λ 1/3 6|
|---|---|---|
|· q · log l.|||

Setting *ϵ* = Θ((l*· t*ARG) *·* 2) minimizes the right-hand side at *ϵ*PCP(①) + Θ(l² *·* (*t²*ARG*·* 2)). 6 Ignoring the lower-order term *thλ*

(ii) *Straightline extractor.* Suppose that we model the collision-resistant hash function as an ideal hash function, and analyze Kilian[PCP*,*VC] in the random oracle model. Prior work analyzing such protocols [BCS16] implies the following upper bound on soundness error:

*ϵ* ARG(*λ,*①*,t*ARG) *≤ ϵ*PCP(①) + *O*(*t²*ARG*·* 2 *−λ* )*.*

This smaller upper bound is achieved thanks to a straightline (i.e., non-rewinding) extractor for the vector commitment scheme (which is a Merkle tree in the random oracle model).

**Setting parameters.** Observe that, neglecting factors in l, the rewinding analysis incurs a cube-root loss in the second soundness term. To understand better how this loss affects security, we work through an example of setting concrete parameters for Kilian’s protocol according to each analysis. Theorem 1 gives that, for every malicious argument prover *P*e of size *t*ARGand instance ① *∈/ L*(*R*), h i Pr *P*e*, V*(1 *λ* *,*①) = 1 *≤ ϵ*PCP(①) + *ϵ*VC(*λ,* l(①)*,*q(①)*,t*VC) + *ϵ,*

where *t*VC*≤* 4 *·* *ϵ* <u>l</u> *· t*ARG. (The constant 4 is obtained in our analysis in the technical sections.) Say that we are targeting a soundness error of 2 *−*40 against adversaries of size *t*ARG= 2 60. Suppose that the PCP underlying Kilian’s protocol, for the chosen instance size, achieves soundness error *ϵ*PCP= 2 *−*42

with a proof consisting of 2 30 symbols. Further suppose that the vector commitment scheme has binding error *ϵ*VC(*λ,ℓ,s,t*VC) *≤ t²*VC*/*2 *λ* (the bound achieved by an ideal Merkle tree). Setting *ϵ* = 2 *−*42 results in a bound of <u>2</u> 30 74 *t* VC*≤* 4 *·−*42*· t*ARG= 2 *· t*ARG 2 so <u>(2</u> 74 <u>· tARG)</u> 2 148*−λ* 2 268*−λ* *ϵ* VC*≤λ*= 2 *· t*ARG= 2*.* 2 Then Theorem 1 indicates that we can set *λ* = 309 to achieve the desired security level (soundness error of 2 *−*40 against adversaries of size 2 60 ). On the other hand, for the same overall security level, and with the same underlying PCP, the straightline analysis indicates that setting *λ ≈* 160 suffices. Hence, if we are willing to make a qualitatively stronger assumption about the cryptography, we can obtain succinct arguments which are roughly a factor 2 more efficient. Note that, for the setting *λ* = 160, our rewinding analysis cannot give *any* nontrivial bound against adversaries of size 2 60. Of course, known PCPs are wildly inefficient; in practice, one would use an IOP instead. The explicit security bound in (the detailed analysis underlying) Theorem 2 for the IBCS protocol enables reasoning similarly to the above for the case of public-coin IOPs.

**Remark 3** (security of underlying components)**.** We derive security bounds for argument systems *as* *a function of the security bounds of the underlying components*. In short, we take *ϵ*VC, *ϵ*PCP, *κ*PCP(and *ϵ* IOP, *κ*IOP) as given. While statistical soundness bounds on PCPs and IOPs can be calculated (they are information-theoretic components), the position binding errors for VC must be derived from some (concrete) computational assumption. For example, if VC is a Merkle tree obtained from a collision-resistant hash function *hλ*: *{*0*,*1*}* 2*λ* *→ {*0*,*1*}* *λ* computable in time *th* *λ* whose collision probability against *t*CRH-size adversaries is bounded by *ϵ*CRH(*λ,t*CRH) then VC has binding error *ϵ*VC(*λ,ℓ,s,t*VC) *≤ ϵ*CRH(*λ,t*CRH) where *t* CRH= *t*VC+ *O*(*thλ·* q *·* log l) for a small hidden constant that can be derived from the security reduction. (The reduction transforms a *t*VC-size adversary *A*VCagainst the Merkle tree into a *t*CRH-size adversary *A*CRH against the collision-resistant hash function. Briefly, *A*CRHruns *A*VCand then looks for a collision among the authentication paths output by *A*VC, resulting in the additive increase of *O*(*th* *λ* *·* q *·* log l) in size.)

**Improved understanding of [BCS16].** Theorem 2 is a step towards a fuller understanding of the (non- interactive) BCS protocol. While [BCS16] gives a detailed security analysis of the BCS protocol as a whole, they crucially consider only the specific setting where the VC is implemented as a Merkle tree *and* the hash function used in the tree is modeled as a random oracle. It is believed that the BCS protocol is secure when realized with any vector commitment (in particular, with VCs in the standard model) but this has not been shown thus far. A natural way to prove this would be to combine (an appropriate strengthening of) Theorem 2 with an analysis of the Fiat–Shamir transformation applied to the resulting argument. 7 Note that, while such an analysis would apply to standard-model VCs, the overall scheme would be proven secure in the random oracle model (under computational assumptions); indeed, there are (contrived) IOPs for which the BCS transformation is provably insecure in the standard model [BBHMR19].

**A reflection on succinct arguments.** Succinct arguments are a rare example of an “advanced” cryptographic primitive that can be achieved from simple cryptography. Indeed, it is remarkable that, based solely on the existence of a collision resistant hash function (even given as a black box), one can achieve cryptographic proof systems with such exceptional efficiency. On the other hand, the security reduction of a succinct argument is tasked with a challenging goal: find a “long” witness when given a malicious argument prover that only outputs “short” messages in any given interaction. This naturally leads to *rewinding*, a fundamental method of analysis in cryptography. In light of this, Kilian’s protocol occupies a central place in cryptography: the simplest succinct argument, and its security analysis is a prominent example of extracting a long witness from sufficiently many short messages obtained via rewinding. This work contributes a long overdue general security analysis of a central cryptographic paradigm.

**The preprocessing case.** We omit discussion of the *preprocessing setting* for succinct arguments, and believe that future work can build on our security analyses to cover this case. Informally, the preprocessing setting is an offline-online model that enables succinct verification even for “non-uniform” computations. The canonical way to construct succinct arguments in the preprocessing setting is to combine a *holographic* probabilistic proof and a vector commitment scheme [CHMMVW20; COS20] — this is a direct generalization of the VC-based approach that we study in this paper. Specifically, each protocol that we study in this paper (Kilian’s protocol, the IBCS protocol, the Finale protocol) has a straightforward extension to the preprocessing setting, where the vector commitment scheme is also used in the offline computation phase to commit to the holographic part of the probabilistic proof. We leave to future work extending our analyses to cover this case.

### 1.3 Related work

The literature on succinct arguments presents a vast landscape of constructions exhibiting complex tradeoffs between efficiency, expressiveness and security. The goal of this work is to study the security of the key family of VC-based constructions. This family occupies a special place in the landscape: it alone demonstrates that succinct arguments are a standard-model “minicrypt” primitive. 8 Moreover, the VC-based approach is the the only known method for obtaining succinct arguments in the standard model with linear-time provers. Below, we summarize only the most relevant prior work: security analyses for VC-based succinct arguments.

**Succinct arguments from collision-resistant functions.** The first construction of a succinct argument is due to Kilian [Kil92], and follows the VC-based approach (the underlying vector commitment is a Merkle 7 The appropriate strengthening refers to showing that IBCS is a succinct interactive argument that satisfies (a suitable computa- tional notion of) state-restoration soundness (which makes the interactive argument compatible with the Fiat–Shamir transformation) if the underlying IOP also satisfies state-restoration soundness. 8 This is known to be true only of succinct *interactive* arguments; indeed, succinct *non-interactive* arguments cannot be proven secure in the standard model via black-box reductions from *any* falsifiable assumption [GW11].

tree constructed from a collision-resistant hash function). The security reduction in [Kil92] is informal, and does not provide any asymptotic (nor explicit) security bounds. Barak and Goldreich [BG08] provide a formal analysis of a variant of Kilian’s construction, towards their goal of constructing zero-knowledge arguments with a non-black-box simulator. Due to their setting, they restrict their result to the case where the PCP is *non-adaptive* and *reverse-samplable*. While the former restriction is mild (many known PCP constructions are non-adaptive, with few exceptions such as [KPT97]), the latter restriction is a non-standard strong property of the query algorithm, which has not been shown to hold for a number of PCP constructions of interest (e.g., the short PCPs in [BS06; BKKMS13]). Under these conditions, they establish that Kilian’s protocol achieves non-adaptive knowledge soundness, with a constant multiplicative factor loss in soundness versus the PCP soundness. In contrast, our analysis applies to *all* PCPs (including adaptive PCPs) and establishes the tightest known bound for adaptive knowledge soundness. 9

Lai and Malavolta [LM19, Appendix C] prove that Kilian’s protocol is secure when realized with any PCP and vector commitment. In fact, they prove a more general result: a variant of Kilian’s protocol is secure when realized with any *linear PCP* and *linear map commitment*. This generality can lead to shorter proofs. However, their proof applies only to PCPs with negligible soundness error and does not quantify the security of the succinct argument in terms of the security of the underlying cryptography. Chiesa, Ma, Spooner, and Zhandry [CMSZ21] prove *post-quantum* security of Kilian’s protocol. As part of their analysis, they give a proof of security for Kilian that also applies to the classical setting. Their analysis differs significantly from ours due to challenges unique to the quantum setting, and incurs a multiplicative soundness loss. In this work we consider soundness against classical adversaries only. Several works [BCG20; RR22; HR22] obtain succinct arguments with very strong efficiency properties by applying the IBCS protocol to their highly-efficient IOP constructions (along with a Merkle tree based on linear-time CRHFs). They do not show soundness of the IBCS protocol itself (their focus is on novel IOPs). This omission has remained a gap in that line of work, and our work closes this gap.

**Succinct arguments from ideal hash functions.** A line of work studies security reductions for succinct *non-interactive* arguments in the random oracle model (ROM) [Mic00; Val08; BCS16; CMS19; CY21a; CY21b; BGTZ23]. These works take advantage of the ROM in two key ways. First, they use the observability of oracle queries to construct a vector commitment with a *straightline* (i.e., non-rewinding) extractor (a Merkle tree in the ROM). As shown in Section 1.2, this leads to tighter security bounds. In fact, since these constructions are *unconditionally* secure in the ROM, it is often possible to compute their *exact* soundness. Second, these constructions use the Fiat–Shamir transformation to convert an underlying *interactive* argument into a *non-interactive* one; the general security of this transformation has been shown only in the ROM.

**Special-sound protocols.** Interactive protocols with *special soundness* are an important and well-studied family of public-coin protocols. In the three-message public-coin (Σ-protocol) setting, *k*-special soundness means that a witness can be efficiently extracted from any *k* accepting protocol transcripts with distinct verifier challenges. A line of works extends this notion to multiple rounds [AC20; ACK22; AF22]. The concrete security of general special sound protocols is relatively well-understood. However, as observed in [CMSZ21], for reasonable choices of PCP, Kilian’s protocol is *not k*-special sound for any polynomial *k* (for example, one can find a set of transcripts that includes only queries to a small fraction of the PCP). 10 We are therefore not able to apply results about special soundness directly.

9 Formally, our result is incomparable with the one of Barak and Goldreich. In more detail, they use the reverse samplability property of the PCP to obtain a collision-finder whose running time does not depend on the PCP length. This is necessary in their setting, as there the size of an extracted PCP is not *a priori* bounded by any polynomial. It is open whether such a reduction is possible for (even polynomial-size) PCPs that are not reverse samplable. 10 Towards a tighter security proof for Kilian in the post-quantum setting, Lombardi, Ma, and Spooner [LMS22] introduce the

In concurrent work, Attema, Fehr, and Resch [AFR23] relax the notion of special soundness further: for an access structure Γ, a protocol is Γ-special sound if there is an efficient procedure to compute a witness from any set of transcripts whose challenges form an authorized set in Γ. They use this framework to show that the IBCS protocol applied to the FRI protocol (an IOP of proximity for Reed–Solomon codes [BBHR18]) is a proof of knowledge of a committed codeword (with a quasipolynomial-time extractor). In contrast, rather than analyzing any specific instantiation, our goal is to give a *general* security guarantee for the Kilian (resp. IBCS) protocol, which applies to any PCP (resp. IOP). It seems that Γ-special soundness may not be the right approach for such generality, as Γ will depend on the underlying PCP/IOP. Our guarantee depends, of course, on the *soundness* of the PCP/IOP, which must be analyzed separately.

notion of *probabilistic special soundness* (PSS), a relaxation of special soundness, and show that Kilian’s protocol is PSS. We do not follow this approach, as we do not expect it to yield tight security bounds in the classical setting.

## 2 Techniques

We overview the main ideas underlying our results. In Section 2.1 we review Kilian’s protocol and sketch our security analysis for it. In Section 2.2 we review the IBCS protocol and discuss our security analysis for it, comparing it to that for Kilian’s protocol. In Section 2.3 we overview the Finale protocol (an extension of the IBCS protocol that is formulated for *public-query* IOPs) and discuss capabilities and limitations of the VC-based approach for succinct interactive arguments. In Section 2.4 we discuss adaptive security.

**Vector commitment schemes.** We fix a vector commitment scheme VC throughout this technical overview, whose interface and properties are sketched below; see Section 3.2 for formal definitions. Here we omit the algorithm that samples public parameters (and suppress these parameters in the interfaces of VC). 11

- VC*.*Commit: On input a message *m*, VC*.*Commit outputs a commitment cm and auxiliary state aux.
- VC*.*Open: On input the auxiliary state aux and a query set *Q*, VC*.*Open outputs an opening proof pf.
- VC*.*Check: On input a commitment cm, query set *Q*, answers ans, and opening proof pf, VC*.*Check determines if pf is valid for ans being the restriction to *Q* of the message committed in cm. The property of *perfect completeness* ensures that VC*.*Check always accepts if pf is output by VC*.*Open given the auxiliary information produced by VC*.*Commit. The security property of VC is *position binding*: VC has *position binding error ϵ*VC(*λ,ℓ,s,t*VC) if, when VC is instantiated with security parameter *λ* for messages of length *ℓ*, every adversary of size *t*VCthat outputs (cm*,*ans*,*ans
*′* *, Q, Q* *′* *,*pf*,*pf *′* ) with *|Q|* = *|Q* *′* *|* = *s* satisfies the following predicate with probability at most *ϵ*VC(*λ,ℓ,s,t*VC) (over VC’s public parameters):

*∃ i ∈Q∩Q* *′* : ans[*i*] *̸*= ans *′* [*i*] *∧* VC*.*Check(cm*, Q,* ans*,*pf) = 1*.* *∧* VC*.*Check(cm*, Q* *′* *,*ans *′* *,*pf *′*

) = 1
In other words, position binding makes it hard to produce two incompatible openings to the same commitment.

**Stateful algorithms.** Throughout this section, the interactive algorithms that participate in protocols are stateful. When it is important to distinguish different computation phases of a stateful algorithm, we make explicit the state passed from one phase to the next.

### 2.1 Succinct arguments based on PCPs

We review Kilian’s protocol and sketch the main ideas behind Theorem 1; see Section 4 for details.

### 2.1.1 Kilian’s protocol

Kilian’s protocol [Kil92] obtains a succinct interactive argument by combining two ingredients: a probabilis- tically checkable proof (PCP) and a vector commitment scheme VC (fixed above). Let PCP = (P*,*V) be a PCP system for a relation *R* with alphabet Σ, proof length l, query complexity q, and verifier randomness complexity r. Kilian[PCP*,*VC] is an interactive argument ARG = (*P, V*) in which the argument prover *P* receives an instance ① and a witness ✇, and the argument verifier *V* receives the instance ①. Then *P* and *V* interact, exchanging 3 messages, as follows.

1. *P* computes the PCP string Π *←* P(①*,*✇), computes the commitment (cm*,*aux) *←* VC*.*Commit(Π), and <u>sends cm to V.</u> 11 For example, if VC is based on a Merkle tree, the public parameters are the (randomly sampled) collision-resistant function to be used for hashing the given message down to the Merkle root.

2. *V* samples PCP verifier randomness *ρ ←{*0*,*1*}*
r and sends it to *P*.

3. *P* deduces the set *Q* of queries that V(①;*ρ*) makes to Π, sets the query answers ans := Π[*Q*], generates an opening proof pf *←* VC*.*Open(aux*, Q*), and sends the tuple (*Q,* ans*,*pf) to *V*.
4. *V* performs the following checks.
(a) VC*.*Check(cm*, Q,* ans*,*pf) = 1 (i.e., ans are valid answers for positions *Q* relative to cm);
(b) V [*Q,*ans]
(①;*ρ*) = 1 (i.e., the PCP verifier V(①;*ρ*) accepts the answers ans on *Q*).

Above, the notation V [*Q,*ans] (①;*ρ*) refers to the decision bit of the PCP verifier V, given instance ① and PCP randomness *ρ*, when each query *j ∈Q* is answered with ans[*j*] *∈* Σ. (If V queries outside the set *Q* then V [*Q,*ans] (①;*ρ*) = 0.)

### 2.1.2 Security reduction

Intuitively, the soundness error of Kilian[PCP*,*VC] should be at most the (statistical) soundness error of PCP plus the position binding error of VC. The key lemma below formalizes this intuition. Consider a malicious argument prover *P*e whose first message is the commitment cm. Intuitively, by the position binding property of VC, *P*e is “bound” to open locations of at most a single underlying PCP string Πe. By *rewinding P*e sufficiently many times to recover the underlying PCP string Πe, we can relate the probability of *P*e convincing the argument verifier *V* to the probability of Πe convincing the PCP verifier V.

**Lemma 1** (informal)**.** *There exists a probabilistic algorithm R (the **reductor**) that, for every instance* ①*,* *error parameter ϵ >* 0*, adversary size bound t*ARG*∈* N*, and t*ARG*-size adversary P*e*, satisfies*   cm *← P*e [*Q,* e eΠ]  V (①;*ρ*) *̸*= 1 e e*P* e   [*Q,*ans] (*Q,* Π) *←R* (cm*,ϵ*)  Pr  *∧* V (①;*ρ*) = 1 r  *≤ ϵ*VC(*λ,*l*,* q*,t*VC) + *ϵ ,*  *ρ ←{*0*,*1*}*  *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 e (*Q,* ans*,*pf) *← P*(*ρ*)

*where t*VC= *O* *ϵ* <u>l</u> *· t*ARG*.*

The reductor *R* handles the aforementioned rewinding process. It constructs a proof string Πe *∈* Σ l whose convincing probability is approximately the same as that of the argument prover (up to the position binding error of VC and an arbitrary error term *ϵ*). Note that *R* requires only black-box access to *P*e. In the lemma above, the PCP verifier and the argument verifier are “coupled” in that they receive the same randomness *ρ*. The lemma states that it is unlikely, for a randomly-chosen *ρ*, that the argument verifier *V* accepts the answers provided by *P*e but the PCP verifier V rejects Πe under the same randomness. Intuitively, this will allow us to approximately equate the probability that *P*e convinces the argument verifier *V* to the probability that Πe convinces the PCP verifier V. First we discuss how to use Lemma 1 to establish soundness and knowledge soundness of Kilian[PCP*,*VC] in Sections 2.1.3 and 2.1.4. Then in Section 2.1.5 we sketch the proof of Lemma 1.

### 2.1.3 Soundness analysis

We wish to upper bound the soundness error of Kilian[PCP*,*VC]. As claimed in Theorem 1, we argue that for every instance ① *∈/ L*(*R*), size bound *t*ARG*∈* N, and *t*ARG-size adversary *P*e, h i Pr *P*e*, V*(①) = 1 *≤ ϵ*PCP(①) + *ϵ*VC(*λ,*l*,* q*,t*VC) + *ϵ .*

By construction of the argument verifier *V*, the above probability is equivalent to the following:

  [*Q,*ans] cm *← P*e V (①;*ρ*) = 1r  Pr  *ρ ←{*0*,*1*}.* *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 e (*Q,* ans*,*pf) *← P*(*ρ*)

Below we fix the following experiment (which is the experiment above augmented with an invocation of *R*):   cm *← P*e  e e*P* e   (*Q,* Π) *←R* (cm*,ϵ*)   r   *ρ ←{*0*,*1*}*  (*Q,* ans*,*pf) *← P*e(*ρ*)

Using the law of total probability,

V [*Q,*ans] (①;*ρ*) = 1 Pr *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1  e e   e e  V [*Q,*Π] (①;*ρ*) = 1 V [*Q,*Π] (①;*ρ*) *̸*= 1 = Pr  *∧* V[*Q,*ans](①;*ρ*) = 1  + Pr  *∧* V[*Q,*ans](①;*ρ*) = 1 *.* *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1

The term on the right is bounded from above by *ϵ*VC(*λ,*l*,* q*,t*VC) + *ϵ*, due to Lemma 1. The term on the left is bounded by *ϵ*PCP(①) (the soundness error of PCP). Indeed, we can view the first message of *P*e (cm in the experiment above) and the reductor *R* as a malicious PCP prover Pe that outputs a PCP string Πe :

P e :

1.Run cm *← P*e. e e*P*
e

2.Run (*Q,*Π) *←R* (cm*,ϵ*).
3.Output Πe.
Since ① *∈/ L*(*R*), by the definition of soundness error of PCP,

 e e  V [*Q,*Π] (①;*ρ*) = 1r [*Q,*ans] Π e *ρ ←{*0*,*1*}* Pr  *∧* V (①;*ρ*) = 1 *≤* Pr V (①;*ρ*) = 1 e e *≤ ϵ*PCP(①)*.* Π *←* P *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1

### 2.1.4 Knowledge soundness analysis

We wish to upper bound the knowledge soundness error of Kilian[PCP*,*VC]. As claimed in Theorem 1, we argue that there exists a polynomial-time probabilistic extractor *E* such that for every instance ①, size bound *t* ARG*∈* N, and *t*ARG-size adversary *P* e,

" # *b* = 1 *b ← P* e*, V*(①) Pr *P* e*≤ κ*PCP(①) + *ϵ*VC(*λ,*l*,* q*,t*VC) + *ϵ .* *∧*(①*,*✇) *∈/ R* ✇ *←E* (①)

By construction of the argument verifier *V*, the above probability is equivalent to the following:   [*Q,*ans] cm *← P*e  V (①;*ρ*) = 1 *ρ ←{*0*,*1*}* r    Pr  *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 e *.*  (*Q,* ans*,*pf) *← P*(*ρ*)  *∧*(①*,*✇) *∈/ R* *P* e ✇ *←E* (①)

We construct *E* using the PCP prover Pe described in Section 2.1.3 and the PCP extractor E (which is given by the underlying PCP system):

*P* e *E* (①):

1.Run Πe *←* Pe.
2.Output ✇ *←* E(①*,*Π) e.
Using the law of total probability,   [*Q,*ans] cm *← P*e  V (①;*ρ*) = 1 *ρ ←{*0*,*1*}* r    Pr  *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 e   (*Q,* ans*,*pf) *← P*(*ρ*)  *∧*(①*,*✇) *∈/ R* *P* e ✇ *←E* (①)  e e   e e  V [*Q,*Π] (①;*ρ*) = 1 V [*Q,*Π] (①;*ρ*) *̸*= 1  *∧* V [*Q,*ans] (①;*ρ*) = 1   *∧* V [*Q,*ans] (①;*ρ*) = 1  = Pr     + Pr    *,* *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 *∧*(①*,*✇) *∈/ R ∧*(①*,*✇) *∈/ R*

where the last two probabilities are with respect to   cm *← P*e  *ρ ←{*0*,*1*}* r     e   (*Q,* ans*,*pf) *← P*(*ρ*) *.*  e e   Π *←* P  ✇ *←* E(①*,*Π) e

The term on the right is bounded by *ϵ*VC(*λ,*l*,* q*,t*VC) + *ϵ* due to Lemma 1. The term on the left is bounded by *κ*PCP(①) (the knowledge soundness error of PCP) as shown below:  e e  V [*Q,*Π] (①;*ρ*) = 1  *ρ ←{*0*,*1*}* r   *∧* V [*Q,*ans] (①;*ρ*) = 1  V Π e (①;*ρ*) = 1 Pr     *≤* Pr  Πe *←* Pe  *≤ κ*PCP(①)*.* *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 *∧*(①*,*✇) *∈/ R* e ✇ *←* E(①*,*Π) *∧*(①*,*✇) *∈/ R*

### 2.1.5 Proof sketch of Lemma 1

We are left to sketch the proof of Lemma 1. To do so, we present a reductor algorithm *R*. The goal of *R* is to piece together a PCP string Πe obtained from the argument prover *P*e. Intuitively, Πe is “fixed” after *P*e outputs a commitment cm, and *R* attempts to obtain information about Πe by *rewinding* the second phase of *P*e, when given freshly sampled choices of PCP randomness *ρ*. Each such execution (if it outputs a valid opening) reveals a fragment of Πe. By repeating this process sufficiently many times, *R* obtains enough locations of the string Πe. Below we denote by N = N(*ϵ*) the number of samples (set later).

*P* e (aux*,·*) *R* (cm*,ϵ*):

1.Initialize a proof string: Πe := (*σ*)
l, where *σ* is an arbitrary element in Σ.

2.Initialize an empty set *Q*e to track which locations of Πe are filled in.
3.Repeat the following N times:
(a)Sample PCP verifier randomness *ρ ←{*0*,*1*}*
r.

(b)Ask *P*e for answers to this randomness: (*Q,* ans*,*pf) *← P*e(aux*,ρ*).
(c)If VC*.*Check(cm*, Q,* ans*,*pf) = 1, set Π[e *Q*] := ans and update *Q*e := *Q∪Q* e.
4.Output (*Q*e*,*Π) e.
We make explicit the two computation phases of the (stateful) malicious argument prover *P*e:

(cm*,*aux) *← P*e and (*Q,* ans*,*pf) *← P*e(aux*,ρ*)*,*

where aux is the auxiliary state passed across the two computation phases of *P*e. The reductor *R* needs to rerun only the second phase of *P*e, so the oracle for *R* is *P*e(aux*, ·*). As stated in Lemma 1, with the above notation we wish to bound the following probability:   (cm*,*aux) *← P*e [*Q,* e eΠ]  V (①;*ρ*) *̸*= 1 e e*P* e(aux*,·*)  [*Q,*ans] (*Q,* Π) *←R* (cm*,ϵ*)  Pr  *∧* V (①;*ρ*) = 1 r *.*  *ρ ←{*0*,*1*}*  *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 e (*Q,* ans*,*pf) *← P*(aux*,ρ*)

Π e [*Q,*ans] Observe that, if VC*.*Check(cm*, Q,* ans*,*pf) = 1 then V (①;*ρ*) *̸*= 1 *∧* V (①;*ρ*) = 1 implies either:

(i) Πe and ans disagree at a position *q ∈Q∩ Q*e; or (ii) there is query *q* in *Q* but not in *Q*e. We analyze the two events separately, which bounds the probability above by a union bound.
**(i) Valid openings with disagreeing answers.** We informally argue that  
(cm*,*aux) *← P*e  e e e e*P*e(aux*,·*)   *∃ q ∈Q∩ Q* : ans[*q*] *̸*= Π[*q*] (*Q,* Π) *←R* (cm*,ϵ*)  Pr  r  *≤ ϵ*VC(*λ,*l*,* q*,t*VC)*.*  *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 *ρ ←{*0*,*1*}*  (*Q,* ans*,*pf) *← P*e(aux*,ρ*)

The reductor *R* checks the validity of the opening for each position it fills into Πe. Therefore, the event above implies that there are valid openings to two different values at the same query position; equivalently, the following adversary *A*VC, which has size *t*VC= *O*(N *· t*ARG), breaks VC’s position binding:

*A*VC:

1.Run (cm*,*aux) *← P*e.
*P* e (aux*,·*)

2. Run the reductor *R* (cm*,ϵ*) and collect the valid query-answer-opening tuples (*Q,* ans*,*pf) it sampled in a set *K*.

||r||′|′ ′|
|---|---|---|---|---|
||||′||
|′|′ ′ 12 outputs (cm, Q|, ans, pf, Q|, ans, pf) if no disagreeing openings are found.||

3.Sample fresh randomness *ρ ←{*0*,*1*}* and obtain another tuple (*Q,*ans*,*pf) *← P*e(aux*,ρ*).
4. For every tuple (*Q,* ans*,*pf) *∈K*, if there exists a query *q ∈Q∩Q* such that ans[*q*] *̸*= ans
*′* [*q*], then output (cm*, Q,* ans*,*pf*, Q,*ans*,*pf).

12 To conform with the algorithm’s syntax, *A*VC *′ ′ ′ ′ ′ ′*

Note that *A*VConly checks inconsistencies between (*Q* *′* *,*ans *′* *,*pf *′* ) and tuples in *K*. In other words, *A*VCdoes not attempt to detect inconsistencies among tuples in *K*. Even so, *A*VCcaptures the bound we wish to prove:   (cm*,*aux) *← P*e  e e e e*P*e(aux*,·*)   *∃ q ∈Q∩ Q* : ans[*q*] *̸*= Π[*q*] (*Q,* Π) *←R* (cm*,ϵ*)  Pr  r   *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 *ρ ←{*0*,*1*}*  (*Q,* ans*,*pf) *← P*e(aux*,ρ*)  *′ ′*  *∃ q ∈Q∩Q* : ans[*q*] *̸*= ans [*q*]

|||′ ′ ′|
|---|---|---|
|′|′ ′||

*≤* Pr  *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 (cm*, Q,* ans*,*pf*, Q* *′* *,*ans *′* *,*pf *′* ) *← A*VC *∧*VC*.*Check(cm*, Q,*ans*,*pf) = 1

### ≤ ϵVC(λ,l, q,tVC).

**(ii) Missing position in** Πe**.** We show that   (cm*,*aux) *← P*e  e e e*P*e(aux*,·*)   *Q\ Q̸*= *∅* (*Q,* Π) *←R* (cm*,ϵ*)  <u>l</u> Pr  r  *≤.*  *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 *ρ ←{*0*,*1*}*  N (*Q,* ans*,*pf) *← P*e(aux*,ρ*)

To upper bound the probability of a query *q ∈Q* not having been filled in by *R*, we use the probability that a given position *q ∈* [l] is queried. The *weight δ*(*q*) of a query *q ∈* [l] is the probability that it is queried by the argument verifier with uniformly sampled randomness. We can write: h i Pr *Q\ Q̸*e = *∅* h i = Pr *∃ q ∈* [l] : *q ∈Q∧ q /∈ Q*e X *≤ δ*(*q*) *·* (1 *− δ*(*q*)) N *,* *q∈*[l]

where the inequality follows from the fact that *Q* and all query sets used to generate *Q*e correspond to independently sampled verifier randomness. Note that, for every *δ ∈* [0*,*1], *δ ·* (1 *− δ*) N *≤* 1*/*N. 13 Hence, the target probability is upper bounded by N <u>l</u>. In fact, the proof for this case is more delicate than sketched above. If a position *q ∈* [l] has weight *δ*(*q*), we cannot conclude that *q /∈ Q*e with probability at most (1 *− δ*(*q*)) N, because *P*e may often output invalid openings for *q* while *R* only includes valid openings. To fix this issue, we use a refined notion: *δ*(*q*) is the probability that during the execution of the interactive argument, the verifier *V* samples randomness that corresponds to a query set containing *q and the prover P outputs a valid VC opening for the query set*.

**Setting parameters.** By an union bound, the desired probability can be upper bounded by

<u>l</u> *ϵ* VC(*λ,*l*,* q*,t*VC) +*.* N

Setting N := *ϵ* l, we get *t*VC= *O*(N *· t*ARG) = *O* *ϵ* l *· t*ARGand N l = *ϵ*, yielding the bound stated in Lemma 1.

13 A simple derivation of the inequality is the following: with *f* (*x*) = *x ·* (1 *− x*) N, we have <u>d</u> *f* (*δ*) = 0 *⇐⇒ δ* = <u>1</u>. As *dx* N+1 *f*(0) = *f*(1) = 0 and *δ* is the only critical point in [0*,*1], it achieves the maximum: max*x∈*[0*,*1]*{f*(*x*)*}* = *f* (*δ*) *≤* 1*/*N.

**Remark 2.1.** Superficially one might hope for an improved analysis showing that one only needs q <u>l</u> *·ϵ* rewindings rather than *ϵ* <u>l</u>. Indeed, each rewinding that leads to an accepting transcript yields a freshly sampled fragment of the PCP containing q locations. However such a bound is unrealistic because, in general, a PCP may have many dummy queries. For example, consider a PCP where only *O*(1) of the q queries are “real”, while all others are dummy queries to fixed locations of the PCP string. That said, there may be other metrics through which the factor *ϵ* <u>l</u> can be slightly improved. We leave this intriguing question to future work.

### 2.2 Succinct arguments based on public-coin IOPs

We review the IBCS protocol and sketch the main ideas behind Theorem 2; see Section 5 for details.

### 2.2.1 IBCS protocol

The IBCS protocol (the interactive variant of [BCS16]) obtains a succinct interactive argument by combining two ingredients: a public-coin interactive oracle proof (IOP) and a vector commitment scheme VC (fixed above). Let IOP = (P*,*V) be a public-coin IOP for a relation *R* with alphabet Σ, round complexity k, proof lengths (l*i*)*i∈*[k]and query complexities (q*i*)*i∈*[k](with maximal values lmax*,* qmaxand total values l*,*q) and verifier randomness complexity r (r*i*per round). IBCS[IOP*,*VC] is an interactive argument ARG = (*P, V*) in which the argument prover *P* receives an instance ① and a witness ✇, and the argument verifier *V* receives the instance ①. Then *P* and *V* interact, across k + 1 rounds (exchanging 2k + 1 messages), as follows.

1.For every round *i ∈* [k] of the IOP system:
(a) *P* computes the IOP string Π*i←* P(①*,* ✇*,ρi−*1), computes the commitment (cm*i,*aux*i*) *←* VC*.*Commit(Π*i*), and sends cm*i*to *V*.
(b) *V* samples the *i*-th IOP verifier randomness *ρi←{*0*,*1*}*
r *i*and sends it to *P*.

2. *P* runs the IOP verifier V
(Π*i*)*i∈*[k] ①*,* (*ρi*)*i∈*[k]to deduce the query sets (*Qi*)*i∈*[k]*⊆* [l₁] *×···×* [lk] of V (where *Qi*is the set of queries to the *i*-th IOP string), computes opening proofs pf*i←* VC*.*Open(aux*i, Qi*),

|:= Π|[Q] for each i ∈ [k], then sends ((Q|||, ans|, pf ))|to V.|||
|---|---|---|---|---|---|---|---|---|
|i|i i i i|i||i|i i i∈[k]||||
|([Q ,ans])|i i∈[k] ([Q|,ans]) i i∈[k]|i i∈[k]||i i∈[k] i|||i|

and sets ans*i i i i i i i∈*[k]

3. *V* performs the following checks.
(a) VC*.*Check(cm*, Q,*ans*,*pf) = 1 for every *i ∈* [k] (i.e., all answers have valid openings);
(b) V *i i i∈*[k]
①; (*ρ*) = 1 (i.e., the IOP verifier V ①; (*ρ*) accepts the answers).

Similarly to Section 2.1.1, V *i i i∈*[k] ①; (*ρ*) refers to the decision bit of the IOP verifier V, given instance ① and IOP randomness (*ρ*), when each query *q ∈Q* to the *i*-th oracle is answered with ans [*q*]. (If V queries an oracle outside the corresponding query set then the decision bit is 0.)

### 2.2.2 Security reduction

The analysis in Section 2.1 extends to the case of public-coin IOPs with a more complicated reductor *R*, which is responsible for producing, for each round, an appropriate IOP string for that round, given a partial transcript of interaction so far. Analogously to Lemma 1, the key step of the security reduction is this lemma.

**Lemma 2** (informal)**.** *There exists a probabilistic algorithm R (the **reductor**) that, for every instance* ①*,*

*error parameter ϵ >* 0*, adversary size bound t*ARG*, and t*ARG*-size adversary P*e*, satisfies*   For *i ∈* [k] :  V([*Q* e *i* *,*Π e *i*])*i∈*[k] ①; (*ρi*) *̸*= 1 (cm*i,*aux*i*) *← P*e(aux*i−*1*,ρi−*1)  *i∈*[k]

||①; (ρ )|= 1||e e|||||
|---|---|---|---|---|---|---|---|---|
|([Q, ans])|i i∈[k]|||i i|P e(aux|,·)|j j≤i|j j<i|
|i∈[k]|i|i i|i|i i i|r i i∈[k]||k k||

 *∧* V ([*Q ,i*ans])*i i∈*[k] *P*e(aux*i,·*) Pr  *i* (*Q,* Π) *←R* (cm)*,* (*ρ*)*,ϵ*   V *i*   *∧* VC*.*Check cm*, Q,*ans*,*pf = 1 *ρ ←{*0*,*1*}*  (*Q,*ans*,*pf) *← P*e(aux*,ρ*)

*≤ ϵ*VC(*λ,*lmax*,* qmax*,t*VC) + *ϵ ,*

*where t*VC= *O* <u>k</u> *ϵ* <u>·l</u> *· t*ARG*.*

Observe that Lemma 2 generalizes Lemma 1, which corresponds to the case k = 1. Similar to the reductor in the PCP case, *R* rewinds the IOP adversary to extract an IOP string for each round. In particular, for each round *i*, the reductor *R* is given oracle access to *P*e(aux*i, ·*) (where aux*i*is the auxiliary state output along with the *i*-th commitment cm*i*) and has the following syntax. For round *i*, *R* receives as input commitments (cm*j*)*j≤i*, (partial) verifier randomness (*ρj*)*j<i∈{*0*,*1*}* r 1*×···×{*0*,*1*}*r*i−*1,

and error tolerance *ϵ >* 0; then *R* outputs an IOP string Πe*i*whose entries in *Q*e*i*are valid openings. With Lemma 2, we can obtain the soundness and knowledge soundness error bounds of Theorem 2 via an analysis analogous to Sections 2.1.3 and 2.1.4. In this overview we omit this straightforward generalization, and only sketch the proof of Lemma 2.

### 2.2.3 Proof sketch of Lemma 2

The reductor *R* is faced with two challenges. On the one hand, for each round *i*, the IOP string Πe*i*to be extracted depends on prior randomness (*ρj*)*j<i*(since the corresponding commitment cm*i*depends on these). On the other hand, for each round *i*, queries to Πe*i*may depend on prior randomness (*ρj*)*j<i*and subsequent randomness (*ρj*)*i≤j≤*k. (Indeed, all queries by the IOP verifier may occur after the interaction because we consider public-coin IOPs.) Therefore, *R* must sample (*ρj*)*i≤j≤*k(i.e., IOP verifier randomness for all rounds *j ≥ i*) to see a fragment of Πe*i*. We use N = N(*ϵ*) to denote the number of samples that we set later. For every *i ∈* [k], the reductor algorithm *R* works as follows.

*P* e (aux*i,·*) *R* (cm*j*)*j≤i,* (*ρj*)*j<i,ϵ* :

1.Initialize an IOP string with an arbitrary symbol *σ ∈* Σ: set Πe*i*:= (*σ*)
l *i*.

2.Initialize an empty set *Q*e*i*to store filled locations of Πe*i*.
3.Repeat the following N times:
(a)Sample IOP verifier randomness from round *i* to round k: (*ρi,...,ρ*k) *←{*0*,*1*}*
r *i* +*···*+rk.

(b) Run the prover *P*e using the sampled randomness (*ρi,...,ρ*k) until the end of interaction, and obtain the query-answer-opening tuple (*Qi,*ans*i,*pf*i*) for the *i*-th IOP string.

|(c)If VC.Check(cm||, Q, ans|, pf ) = 1, set Π|e [Q] := ans|and update Q||e := Q|e ∪Q.|
|---|---|---|---|---|---|---|---|---|
|||i i|i i|i i|i||i|i i|
||i i||||||||

*i i i i i i i i i i*

4.Output (*Q*e*,* Πe).
With the above construction, we can prove Lemma 2 with a similar case analysis as Section 2.1.5: if the IOP verifier V, upon querying the proof strings output by *R*, disagrees with the argument verifier *V*, then either:

(i)for some *i ∈* [k], Πe*i*and ans*i*disagree at a position *q ∈Qi∩ Q*e*i*; or (ii)for some *i ∈* [k], there is query *q* in *Qi*but not in *Q*e*i*.

We bound the probability of the two events separately. We fix this experiment for the rest of the proof:   For *i ∈* [k] :  (cm*i,*aux*i*) *← P*e(aux*i−*1*,ρi−*1)     e e*P* e(aux *i* *,·*)

|i i|P e(aux|,·)|j j≤i|j j<i|
|---|---|---|---|---|
|i|r||||
|i i|i i∈[k]||k k||

 (*Q,* Π) *←R* (cm)*,* (*ρ*)*,ϵ* *.*  *i*   *ρ ←{*0*,*1*}*  (*Q,*ans*,*pf) *← P*e(aux*,ρ*)

**(i) Valid openings with disagreeing answers.** We informally argue that
" # *∃ i ∈* [k]*,q ∈Qi∩ Q*e*i*: ans*i*[*q*] *̸*= Πe*i*[*q*] Pr V *≤ ϵ*VC(*λ,*lmax*,* qmax*,t*VC)*.* *∧* *i∈*[k] VC*.*Check(cm*i, Qi,*ans*i,*pf*i*) = 1

We construct an adversary *A*VCfor VC with *R* and *P*e as in Section 2.1.5.

*A*VC:

1.Sample (*ρi*)*i∈*[k]*←{*0*,*1*}*
r 1 +*···*+rk.

2.For every *i ≤* k:

|, aux|) ← P|e(aux|,ρ ).|||||
|---|---|---|---|---|---|---|---|
|P e(aux ′i ′i|,·) ′i i∈[k]|j j≤i i|j j<i k k i i|i ′i|i|′i|i|
|i i i|i ′i|′i ′i||′1|′1 ′1 ′1|′1 ′1 i i|i i∈[k]|
|||||i||||

(a)Run (cm*i i i−*1 *i−*1 *P* e
(aux*i,·*)

(b) Run *R* ((cm)*,* (*ρ*)*,ϵ*) and collect the valid query-answer-opening tuples in a set *K*.
3.Run ((*Q,*ans*,*pf)) *← P*e(aux*,ρ*).
4. If there exists *i ∈* [k] and (*Q,*ans*,*pf) *∈Ki*such that *q ∈Q ∩Q* and ans [*q*] *̸*= ans [*q*], output (cm*, Q,*ans*,*pf*, Q,*ans*,*pf). (Otherwise, simply output (cm₁*, Q,*ans*,*pf*, Q,*ans*,*pf).)
Once again, the VC adversary *A*VConly needs to check for inconsistent answers between ((*Q,*ans*,*pf)) and (*Ki*)*i∈*[k], rather than also checking inconsistencies within each *K*. The VC adversary *A*VCsimulates round *i* of *P*e for *i ·* (N + 1) times (see construction of *R*), so *A*VC runs at most kN full executions of *P*e. Since one full execution of *P*e has size *t*ARG, the size of *A*VCis at most *O*(kN *· t*ARG). Hence setting *t*VC= *O*(kN *· t*ARG) bounds the probability above by *ϵ*VC(*λ,*lmax*,* qmax*,t*VC).

**(ii) Missing query in** *Q*e*i***.** By extending the approach in Section 2.1.5, we show that, for every *δ ∈* [0*,*1],   *∃ i ∈* [k] : *Qi\ Q*e*i̸*= *∅* <u>l</u> Pr  V  *≤.* *∧* *i∈*[k] VC*.*Check(cm*i, Qi,*ans*i,*pf*i*) = 1 N

For each *i ∈* [k] and a given position *q ∈* [l*i*], *q* has weight *δ*(*q*) with respect to a randomness prefix
*ρ₁,...,ρi−*1if it is queried by the argument verifier *V* with probability *δ*(*q*) (over *ρi*+1*,...,ρ*k).
14 Here we consider the *residual* probability after fixing a randomness prefix; this is necessary as this is the distribution that *R* samples from. Therefore: h i Pr *∃ i ∈* [k] : *Qi\ Q*e*i̸*= *∅* h i = Pr *∃ i ∈* [k]*,q ∈* [l*i*] : *q ∈Qi∧ q /∈ Q*e*i*

14 Similarly to Section 2.1.5, here the definition of weight is simplified. In the full proof, we need to consider the fact that *P*e might output invalid openings.

X kh i *≤* Pr *q ∈* [l*i*] : *q ∈Qi∧ q /∈ Q*e*i* *i*=1 X k X *≤ δ*(*q*) *·* (1 *− δ*(*q*)) N

*i*=1 *q∈*[l*i*] <u>l</u> *≤.* N

**Setting parameters.** Setting N := *ϵ* l, we have that *t*VC= *O*(kN *· t*ARG) = *O* k *ϵ·* l *· t*ARGand N l = *ϵ* as desired.

### 2.3 Why doesn’t the same analysis work for public-query IOPs?

We have discussed how the VC-based approach works for PCPs (in Section 2.1) and for public-coin IOPs (in Section 2.2). Here we discuss the capabilities and limitations of the this approach towards succinct interactive arguments. We begin by giving an informal definition of a general (private-coin) IOP. 15

**Definition 1** (informal)**.** *An* IOP = (P*,*V) *with round complexity* k *and randomness complexity* r *works as* *follows.*

*1.* V *samples its private random string ρ ←{*0*,*1*}*
r *.*

*2.For every round i ∈* [k]*:*
*(a)* P *computes the i-th IOP string* Π*i←* P(①*,* ✇*,mi−*1) *and sends it to* V*.*
*(b)i i,j j≤i* q *j j<i i,jis the set of*

|V computes the i-th query set Q|||= (Q|)|← V ①,ρ, (ans|), where Q|
|---|---|---|---|---|---|---|
||d|i i i∈[k]|i i i m|i,j j≤i|q j j≤i j j≤i|j j<i|
|q m|d||||||
 *queries to the j-th IOP string in round i.*
*(c)* V *obtains the answers* ans *to* Q *by querying* (Π)*.*
*(d)* V *computes the i-th message m ←* V ①*,ρ,* (ans) *and sends it to* P*.*
*3.* V *checks that* V ①*,ρ,* (ans) = 1*.* *We use* V*,* V*,* V *to denote the query, message, and decision functions of the IOP verifier* V*, respectively.* We cannot hope for the VC-based approach to work for *every* IOP. The argument verifier needs the argument prover’s help to obtain the answers to its queries; hence, the argument prover learns each round’s queries as they are made. Unless the underlying IOP remains secure even when queries are revealed to the IOP prover, the VC-based approach is insecure. Therefore, at best we can hope for the approach to work for *public-query IOPs*. These are IOPs in which soundness (and knowledge soundness) holds even if the IOP prover knows the queries made by the IOP verifier, or, equivalently, where the latter sends its *i*-th round query set Q*i*along with the message *mi*. This leads to the following (narrowed) question: *Does the VC-based approach work for every public-query IOP?* In Section 2.3.1, we describe a succinct interactive argument that appears secure provided that the underlying IOP is public-query. In Section 2.3.2, we explain the challenges towards a proof of security for this protocol. In Section 2.3.3, we identify a property of public-query IOPs (which is trivially satisfied by public-coin IOPs) that suffices for security. In Section 2.3.4, we partially characterize the class of public-query IOPs that admit this property. Technical details are in Section 6. 15 For notational simplicity, we assume that, within each round of interaction, the IOP verifier queries non-adaptively. All discussions in this paper directly extend to adaptive queries within each round.

### 2.3.1 The Finale protocol

We describe the *Finale* protocol, a succinct interactive argument obtained from any public-query IOP. It is a generalization of the IBCS protocol in Section 2.2.1 from public-coin IOPs to public-query IOPs. The main difference is that, while in the IBCS protocol the argument prover answers queries by the IOP verifier after the IOP interaction, the argument prover in the Finale protocol answers queries within each round. Let IOP = (P*,*V) be a public-query IOP for a relation *R* with alphabet Σ, round complexity k, maximal proof length lmax, maximal query complexity qmax, and verifier randomness complexity r. Finale[IOP*,*VC] is an interactive argument ARG = (*P, V*) in which the argument prover *P* receives an instance ① and a witness ✇, and the argument verifier *V* receives the instance ①. Then *P* and *V* interact, across 2k rounds (exchanging 4k messages), as follows.

1. *V* samples the verifier randomness *ρ ←{*0*,*1*}*
r for V.

2.For every round *i ∈* [k] of the IOP system:
(a) *P* computes the *i*-th IOP string Π*i←* P(①*,* ✇*,mi−*1), computes the corresponding commitment (cm*i,*aux*i*) *←* VC*.*Commit(Π*i*), and sends cm*i*to *V*.

|||= (Q|)|①,ρ, (ans ← V|)|to P, where Q|
|---|---|---|---|---|---|---|
|||i|i,j j≤i|q|j j<i||
|d|j i i i∈[k]|i i,j j≤i|i i m j|i,j i,j j≤i j i,j i,j|j≤i i,j|j i,j|

(b) *V* sends the *i*-th query set Q*i i,j j≤i* q *j j<i i,j*is the set of queries to Π in round *i*.
(c)For each *j ≤ i*, *P* computes an opening proof pf *←* VC*.*Open(aux*, Q*).
(d) *P* sends ans := (Π [*Q*])*,*pf := (pf) to *V*.
(e)Then *V* sends the *i*-th message *m ←* V ①*,ρ,* (ans) to *P*.
3. *V* checks if the following conditions hold:
(a) V ①*,ρ,* (ans) = 1.
(b)For every *i ∈* [k] and *j ≤ i*, VC*.*Check(cm*, Q,*ans*,*pf) = 1.
### 2.3.2 Is there a security reduction that works for every public-query IOP?

It would be natural to conjecture that the security analysis of the IBCS protocol (for public-coin IOPs) directly extends to a security analysis for the Finale protocol (for public-query IOPs). However, that is not the case. The key object in the security analysis is the reductor: *R* rewinds the malicious argument prover *P*e multiple times, each time simulating a fresh partial interaction between *P*e and the (honest) argument verifier

*V*. Let us attempt to construct such a reductor *R* for the Finale protocol. Consider the goal of the reductor *R* for the first round. The reductor *R* receives oracle access to *P*e and receives as input the first commitment cm₁ (and error parameter *ϵ*); the (first) goal of *R* is to output a (partially filled) IOP string Πe₁ consistent with cm₁. As before, *R* can rewind *P*e for N(*ϵ*) times, each time sampling fresh private randomness for *V* and simulating a full interaction between *P*e and *V*. The problem arises in the second round, where *R* must simulate partial interactions of the interactive argument. Now *R* receives as input the first two commitments (cm₁*,*cm₂), the first round’s verifier queries Q₁, the corresponding query answers ans₁ and opening proofs pf₁, and the first round’s verifier message *m₁* (as well as the error parameter *ϵ*). The new goal of *R* is to output a (partially filled) IOP string Πe₂ consistent with cm₂. To do so, *R* must simulate multiple partial interactions between *P*e and *V starting from the second* *round*. This means that *R* needs to sample “consistent” private randomness *ρ* for the argument verifier *V*: *ρ* such that *V*’s first query set is Q₁ and, given answers ans₁ to these queries, *V*’s first message to the argument prover is *m₁*. More generally, *R* must have the capability of sampling consistent private randomness starting from any round (defined by a partial transcript of the interactive argument). How may we sample from this conditional distribution? For the IBCS protocol, sampling a random continuation for a partial transcript is trivial because it is public coin: given first round randomness *ρ₁*, sample

randomness *ρ₂,...,ρ*kfor the remaining rounds; and similarly if starting from a later round. In contrast, in the Finale protocol, the argument verifier is private-coin: it samples all of its private randomness *ρ* at the beginning of the interaction and then uses *ρ* to deterministically compute queries and messages. An attempt to sample from the conditional distribution would be for *R* to repeatedly sample choices of *ρ* until one is consistent with ((cm₁*,*cm₂)*,*(Q₁*,*ans₁*,m₁*)). However, such a sampling strategy would be inefficient, and would imply (in the resulting reduction) an adversary against VC whose similarly large runtime makes *ϵ*VCtrivial (recall that in Section 2.1.5 the VC adversary *A*VCuses *R* as a subroutine). In sum, the bottleneck of the security reduction approach in Section 2.2.2 is the ability to *efficiently and* *consistently sample argument verifier randomness consistent with a partial interaction transcript*, which in turn reduces to the ability to sample consistent IOP verifier randomness for the underlying public-query IOP (as we discuss soon in Section 2.3.3). We are not aware of alternative approaches, and the problem of proving the Finale protocol secure for every public-query IOP (or proving it insecure for some public-query IOP) **remains open**. In the meantime, to achieve a security reduction, we restrict our attention to public-query IOPs that possess efficient *random continuation samplers*, which we discuss next.

### 2.3.3 IOP random continuation sampler leads to security reduction

We sketch how, as claimed in Theorem 3, if the underlying public-query IOP has an efficient random continuation sampler then the Finale protocol is secure.

**Transcripts for general IOPs.** A complete interaction transcript for an IOP has the following form:

tr := (Q*i,*ans*i,mi*) *i∈*[k] *.*

For every *i ∈* [k], a partial interaction transcript tr*i*for an IOP can have the following forms:

- tr*i*= (Q*j,*ans*j,mj*)
*j<i* *,*(Q*i,*ans*i*), if the IOP verifier is about to send its *i*-th message *mi*;

- tr*i*= (Q*j,*ans*j,mj*)
*j≤i*, if the IOP verifier is about to output its (*i* + 1)-th query set Q*i*+1(*i <* k).

An IOP interaction transcript includes only the values of queried locations, and not entire IOP strings.

**What is an IOP random continuation sampler?** An IOP random continuation sampler (IOP-RCS) receives as input a partial interaction transcript tr*i*for an IOP and samples the next message for tr*i*at random among all next messages consistent with tr*i*. (In the technical sections, we also allow for a sampling error *α*.) Formally, an IOP-RCS S works as follows:

•If tr*i*= (Q*j,*ans*j,mj*) *j<i* *,*(Q*i,*ans*i*), then S(tr*i*) samples the next message *mi*; •If tr*i*= (Q*j,*ans*j,mj*) *j≤i* and *i <* k, then S(tr*i*) samples the next query set Q*i*+1.

**How does IOP-RCS help with proving security?** As discussed in Section 2.3.2, the key step in the security reduction is efficiently sampling “consistent random continuations” of a given partial interaction transcript of the argument system. In other words, we need an *ARG random continuation sampler* (ARG-RCS) for the Finale protocol. The notion of ARG-RCS was implicit in prior settings: the construction of *R* for Kilian’s protocol (in Section 2.1.5) and for the IBCS protocol (in Section 2.2.3) implicitly relies on an ARG-RCS, which is trivial for arguments built from PCPs or public-coin IOPs (it suffices to sample uniform random strings for future rounds). In the Finale protocol, based on public-query IOPs, an efficient ARG-RCS is not trivial. Fortunately, we can show that if IOP admits an IOP-RCS then Finale[IOP*,*VC] admits an ARG-RCS.

**Step 1: IOP-RCS implies ARG-RCS.** An ARG-RCS can be defined analogously to an IOP-RCS. A complete interaction transcript for Finale[IOP*,*VC] can be written as:

tr := (cm*i,* Q*i,*ans*i,*pf*i,mi*) *i∈*[k] *.*

Such an interaction transcript is syntactically identical to an IOP interaction transcript, but for the additional inclusion of commitments cm*i*and openings pf*i*. Moreover, the argument verifier’s behavior in the interaction is independent of the commitments and openings (only after the interaction the argument verifier uses them to check the validity of the answers to the query sets). Hence the transformation from an IOP-RCS S to an ARG-RCS *S* is trivial: given a partial argument transcript tr*i*, discard the commitments and openings and pass the resulting partial IOP transcript to S. More specifically, *S* is obtained from S as follows:

*S*(tr*i*):

1. If tr*i*= (cm*j,* Q*j,*ans*j,*pf*j,mj*)
*j<i* *,*(cm*i,* Q*i,*ans*i,*pf*i*), output S (Q*j,*ans*j,mj*) *j<i* *,*(Q*i,*ans*i*);

2.If tr*i*= (cm*j,* Q*j,*ans*j,*pf*j,mj*)
*j≤i* and *i <* k, output S (Q*j,*ans*j,mj*) *j≤i*.

It is clear that *S* samples valid randomness if S does, and the running time of *S* is *O*(*t*S).

**Step 2: ARG-RCS enables a security reduction.** We can use an ARG-RCS *S* for the Finale protocol to construct an efficient reductor *R* for the Finale protocol. Indeed, we can use *S* to randomly sample the next query set and verifier message in the transcript.

*P* e (aux*i,·*) *R* ((cm*j*)*j≤i,*((Q*j,*ans*j,*pf*j,mj*))*j<i,ϵ*):

1.Initialize an IOP string with an arbitrary symbol *σ ∈* Σ: set Πe*i*:= (*σ*)
l *i*.

2.Initialize an empty set *Q*e*i*to store filled locations of Πe*i*.
3.Compute N := N(*ϵ*).
4.Repeat the following N times: For *i ≤ j ≤* k:

|||, aux ) ← P|e(aux, Q|,m|).|||
|---|---|---|---|---|---|---|---|
||j|j j ℓ ℓ j ℓ|j−1 ℓ ℓ j j ℓ ℓ|j−1 j−1 ℓ ℓ<j j ℓ ℓ ℓ<j|j j|j|j j|
|i j,i|j,i j,i|i j,i|j,i|i||j,i||

(a)If *j ̸*= *i*, compute the *j*-th commitment: (cm
(b)Sample the *j*-th IOP query set: Q *←S* (cm*,* Q*,*ans*,*pf*,m*).
(c)Get the *j*-th answer and VC openings from *P*e: (ans*,*pf*,*aux) *← P*e(aux*,* Q).
(d) Sample the*j*-th IOP verifier message: *mj←S* (cm*,* Q*,*ans*,*pf*,m*)*,*(cm*,* Q*,*ans*,*pf).
(e)If VC*.*Check(cm*, Q,*ans*,*pf) = 1, set Πe [*Q*] := ans and update *Q*e := *Q∪Q* e.
5.Output (*Q*e*,* Πe*i*).
If the ARG-RCS *S* is efficient then the reductor *R* is efficient. We can then prove security by adapting Lemma 2 to this setting; we sketch how the proof changes to account for public queries. As before (Sections 2.1.5 and 2.2.3), the security reduction claim can be split into two parts.

- *Valid openings with disagreeing answers.* We construct an adversary *A*VCfor VC with *R* and *P*e as in Section 2.1.5. The construction is similar, except that the verifier’s messages are now denoted by *m* rather than *ρ* and the running time of *A*VCneeds to take into account the running time of the ARG-RCS *S* (in *R*).
- *Missing query in* Πe*i.* For every *i*-round partial transcript tr*i*, we can define the weight of a position *q ∈* [l*i*] with respect to tr*i*analogously as in Section 2.2.3, and the same analysis follows:
h i <u>l</u>

|||i|
|---|---|---|
||j,i|i|

e Pr *∃ q ∈* [l*i*] : (*∃ j ∈* [*i,* k] : *q ∈Q*) *∧ q /∈ Q ≤.* N

Using a union bound over the rounds, we upper bound the target probability of this case as before by

X k <u>l</u> <u>il</u> =*.* N N *i*=1

We conclude that when the Finale protocol (based on a public-query IOP) has an efficient random continuation sampler, we can show (knowledge) soundness via a similar strategy to Sections 2.1.3 and 2.1.4.

### 2.3.4 ARG-RCS implies IOP-RCS

We show that IOP has an efficient IOP-RCS if Finale[IOP*,*VC] admits an efficient ARG-RCS. Combining this with the discussion from Section 2.3.3, we conclude that the existence of an efficient ARG-RCS for the Finale protocol is equivalent to the existence of an efficient IOP-RCS for the underlying public-query IOP. Let *S* be an ARG-RCS for Finale[IOP*,*VC] with running time *tS*. We wish to construct an IOP-RCS S for IOP. Let tr*i*be a partial interaction transcript for the IOP. To invoke *S*, the IOP sampler S needs to augment the IOP transcript to an argument transcript that includes commitments to each IOP string and openings to the commitments. For example, in order for *S* to output the *i*-th query set, the argument transcript given as input should include cm*j*for every *j ≤ i*. However, S has no information about the *i*-th IOP string. We circumvent this issue by observing that the (honest) verifier in the Finale protocol ignores the VC commitments and openings until the interaction ends. Therefore, the IOP-RCS S can construct from tr*i*an argument transcript to pass to *S* by providing dummy values for the commitments and openings, as follows:

S(tr*i*):

|=|(Q, ans|,m )|, ans, ⊥,m|, (⊥, Q )|
|---|---|---|---|---|
|i|j|j j j<i|j j|j j<i|
|i|j|j j j≤i|j j|j j≤i|

1. If tr*i j j j,*(Q*i,*ans*i*), output*S* (*⊥,*Q*j j j i,*ans*i, ⊥*).
2.If tr = (Q*,*ans*,m*) and *i <* k, output *S* (*⊥,*Q*,*ans*, ⊥,m*).
The correctness of S follows straightforwardly from the correctness of *S*, and the running time of S is *O*(*tS*).

### 2.4 Succinct interactive arguments with adaptive security

For simplicity, all results and discussions in Sections 1 and 2 are in the *plain model*, where there are no public parameters available to all parties (so the argument verifier is responsible to sample and send VC’s public parameters to the argument prover). However, in the technical sections (Sections 4 to 6) we show stronger versions of Theorems 1 to 3 that hold with adaptive security in the common reference string (CRS) model. An interactive argument in the CRS model includes an additional algorithm: a trusted *generator algorithm* that samples public parameters pp for the argument prover and argument verifier (which can be used any number of times across different interactions). After that, based on pp, a malicious argument prover can choose the instance on which to interact with the argument verifier. This setting necessitates appropriate definitions of *adaptive* soundness and knowledge soundness (see Section 3.1), which require error bounds to hold for any instance ① chosen by the malicious argument prover up to an instance size bound *n*. 16 In particular, the (soundness and knowledge soundness) error bounds depend on *n* rather than ①. Our security analyses to achieve adaptive security in the CRS model follow the same structure as the discussions in the sections above, with only syntactic modifications due to the different target definitions.

16 We also rely on formulations of soundness and knowledge soundness for PCPs and IOPs in which the malicious prover chooses the instance (see Sections 3.3 and 3.4). This is only for convenience, because, due to the information-theoretic setting, these definitions are straightforwardly implied by (standard) definitions for fixed instances.

(E.g., modifying the experiments to replace a fixed instance ① with an instance size bound *n*, and letting the malicious argument prover choose the instance.) Overall, the (formal) statements provided in the technical sections (Sections 4 to 6) are stronger than the (informal) statements in Theorems 1 to 3 because we achieve adaptive security in the CRS model. 17

17 Adaptive security in the CRS model directly implies security in the plain model. Since no CRS is allowed, the argument verifier can begin the interaction by running itself the generator algorithm and sending the public parameters for the argument system to the argument prover. See Remark 3.6.

## 3 Preliminaries

**Definition 3.1.** *A* **relation** *R is a set of pairs* (①*,*✇) *where* ① *is an instance and* ✇ *a witness. The corre-* *sponding* **language** *L*(*R*) *is the set of instances* ① *for which there exists a witness* ✇ *such that* (①*,*✇) *∈ R.*

### 3.1 Interactive arguments

An *interactive argument* (in the common reference string model) for a relation *R* is a tuple of polynomial-time algorithms ARG = (*G, P, V*) that satisfies the following properties.

**Definition 3.2** (Perfect completeness)**.** ARG = (*G, P, V*) *for a relation R has* **perfect completeness** *if* *for every security parameter λ ∈* N*, instance size bound n ∈* N*, public parameter* pp *∈ G*(1 *λ* *,n*)*, and* *instance-witness pair* (①*,*✇) *∈ R with |*①*|≤ n,*

Pr *P*(pp*,* ①*,*✇)*, V*(pp*,*①) = 1 = 1*.*

**Definition 3.3** (Adaptive soundness)**.** ARG = (*G, P, V*) *for a relation R has* **(adaptive) soundness error** *ϵ* ARG*if for every security parameter λ ∈* N*, instance size bound n ∈* N*, auxiliary input distribution D, circuit* *size bound t*ARG*∈* N*, and t*ARG*-size circuit P*e*,*  *λ*  pp *←G*(1*,n*)  *|*①*|≤ n* ai *←D*  Pr   *∧* ① *∈/ L*(*R*) e   *≤ ϵ*ARG(*λ,n,t*ARG)*.* (①*,*aux) *← P*(pp*,*ai) *∧ b* = 1 *b ← P*e(aux)*, V*(pp*,*①)

**Definition 3.4** (Adaptive knowledge soundness)**.** ARG = (*G, P, V*) *for a relation R has* **(adaptive) knowl-** **edge soundness error** *κ*ARG**with extraction time** *tEif there exists a probabilistic algorithm E such that for* *every security parameter λ ∈* N*, instance size bound n ∈* N*, auxiliary input distribution D, circuit size bound* *t* ARG*∈* N*, and t*ARG*-size circuit P* e*,*  *λ*  pp *←G*(1*,n*)  ai *←D*   *|*①*|≤ n*   (①*,*aux) *← P*e(pp*,*ai)  Pr  *∧*(①*,*✇) *̸∈ R*  *≤ κ*ARG(*λ,n,t*ARG);  tr e   *∧ b* = 1 *b ←− P*(aux)*, V*(pp*,*①)  *P* e (aux) ✇ *←E* (pp*,* ①*,*tr)

### moreover, E runs in time tE(λ,n,tARG).

tr e(aux) Above, *b ←−⟨P, V*(pp*,*①)*⟩* denotes the fact that tr is the transcript of the interaction (i.e., public e and*P* e parameters and messages exchanged between *P V*). Moreover, *E* means that *E* has black-box access to (each next-message function of) *P*e; in particular *E* can send verifier messages to *P*e in order to obtain the next message of *P*e (for a partial interaction where *V* sent those messages). Moreover, we can assume, without loss of generality, that *P*e is deterministic relative to auxiliary input ai (as the internal coin flips of a probabilistic *P*e can be incorporated into the auxiliary input distribution *D*).

**Remark 3.5.** The argument generator *G* receives two inputs: the security parameter *λ* and an instance size bound *n*. This means that the public parameter sampled by *G* may work only for instances of size at most *n*. However, one could consider the stronger notion where the sampled public parameter works for all instance sizes; in this case *G* receives only *λ* as input. Our analysis works for both cases; see Remark 4.4.

**Remark 3.6** (plain model variant)**.** The above definitions consider interactive arguments in the *common* *reference string model*, where a generator samples a public parameter used by the argument prover and the argument verifier. One could also consider interactive arguments in the *plain model*, where there is no generator. This latter notion is implied, at the cost of an additional verifier message, as we now explain. Suppose that (*G, P, V*) is an interactive argument in the common reference string model. We describe an interactive argument (*P* *′* *, V* *′* ) in the plain model with an additional verifier message. The argument prover *P* *′*

receives as input an instance ① and witness ✇, and the argument verifier *V* *′* receives as input the instance ①; both also receive as input the security parameter *λ* (in unary). They interact as follows:

|′||λ|′|
|---|---|---|---|
|′ ′||′ ′||
||||18|

- *V* samples a public parameter pp *←G*(1*, |*①*|*) and sends pp to *P*;
- *P* and *V* simulate an interaction of *P*(pp*,* ①*,*✇) and *V*(pp*,*①). It is straightforward to see that (*P, V*) satisfies the standard definitions of completeness, soundness, and knowledge soundness for interactive arguments in the plain model. In fact, it would suffice for (*G, P, V*) to satisfy the non-adaptive relaxations of soundness and knowledge soundness.
### 3.2 Vector commitments

A (static) *vector commitment scheme* [CF13] over alphabet Σ is a tuple of algorithms

### VC = (Gen,Commit,Open,Check)

### with the following syntax.

- VC*.*Gen(1
*λ* *,ℓ*) *→* pp: On input a security parameter *λ ∈* N and message size bound *ℓ ∈* N, VC*.*Gen samples public parameter pp.

- VC*.*Commit(pp*,m*) *→* (cm*,*aux): On input a public parameter pp and a message *m ∈* Σ
*ℓ*, VC*.*Commit produces a commitment cm and the corresponding auxiliary state aux.

- VC*.*Open(pp*,*aux*, Q*) *→* pf: On input a public parameter pp, an auxiliary state aux, and a query set *Q⊆* [*ℓ*], VC*.*Open outputs an opening proof string pf attesting that *m*[*Q*] is a restriction of *m* to *Q*.
- VC*.*Check(pp*,*cm*, Q,* ans*,*pf) *→{*0*,*1*}*: On input a public parameter pp, a commitment cm, a query set *Q⊆* [*ℓ*], an answer string ans *∈* Σ
*Q*, and an opening proof string pf, VC*.*Check determines if pf is a valid proof for ans *∈* Σ *Q* being a restriction of the message committed in cm to *Q*.

The vector commitment scheme VC must satisfy perfect completeness and position binding.

**Definition 3.7** (Completeness)**.** VC = (Gen*,*Commit*,*Open*,*Check) *has* **perfect completeness** *if for every* *security parameter λ ∈* N*, message length ℓ ∈* N*, message m ∈* Σ *ℓ* *, and query set Q⊆* [*ℓ*]*,*  *λ*  pp *←* VC*.*Gen(1*,ℓ*) Pr VC*.*Check(pp*,*cm*, Q,m*[*Q*]*,*pf) = 1 (cm*,*aux) *←* VC*.*Commit(pp*,m*)  = 1*.* pf *←* VC*.*Open(pp*,*aux*, Q*)

**Definition 3.8** (Position binding)**.** VC = (Gen*,*Commit*,*Open*,*Check) *has* **position binding error** *ϵ*VC*if for* *every security parameter λ ∈* N*, message length ℓ ∈* N*, query set size s ∈* N *with s ≤ ℓ, auxiliary input* *distribution D, adversary size bound t*VC*∈* N*, and t*VC*-size circuit A*VC*,*  *′ λ*  *|Q|* = *|Q |* = *s* pp *←* VC*.*Gen(1*,ℓ*)  *∧∃ i ∈Q∩Q′*: ans[*i*] *̸*= ans*′*[*i*] ai *←D*  Pr  *′*   *≤ ϵ*VC(*λ,ℓ,s,t*VC)*.* *∧* VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 cm*,*ans*,*ans*,* *′ ′ ′ ′ ′← A*VC(pp*,*ai) <u>∧ VC.Check(pp,cm, Q,ans,pf</u>) = 1 *Q, Q,*pf*,*pf 18 These standard definitions can be derived from Definitions 3.2 to 3.4 by setting pp to be empty.

**Remark 3.9** (Monotonicity of *ϵ*VC)**.** We assume hereafter that the position binding error *ϵ*VCis monotone in each coordinate in the natural direction:

- *ϵ*VC(*·,ℓ,s,t*VC) is non-increasing (larger security parameters decrease an adversary’s success);
- *ϵ*VC(*λ, ·,s,t*VC) is non-decreasing (opening some set in a string is easier than opening in a substring);
- *ϵ*VC(*λ,ℓ, ·,t*VC) is non-decreasing (finding a collision in a set is easier than finding one in a subset); and
- *ϵ*VC(*λ,ℓ,s, ·*) is non-decreasing (the success of an adversary increases with its computational power). The last condition is trivially satisfied, while the first should also hold in any reasonable commitment scheme. The remaining two are natural (and satisfied in the case of Merkle trees); in any case, otherwise one may replace, in our computations, expressions of the type *ϵ*VC VC), when *ℓ*max= max

||(λ,ℓ|,s ,t|{ℓ } and|
|---|---|---|---|
|j j|max|max|i i|
||i j|||
 *s*max= max *{s}*, with
max *{ϵ*VC(*λ,ℓ,s,t*VC)*}.* *i,j*

### 3.3 Probabilistically checkable proofs

A *probabilistically checkable proof* (PCP) is an information-theoretic proof system where a probabilistic verifier has oracle access to a proof string.

**Definition 3.10** (Completeness)**.** PCP = (P*,*V) *for a relation R has* **perfect completeness** *if, for every* *instance-witness pair* (①*,*✇) *∈ R,*

Pr V Π

(①) = 1 Π *←* P(①*,*✇) = 1*.*
**Definition 3.11** (Soundness)**.** PCP = (P*,*V) *for a relation R has* **soundness error** *ϵ*PCP*if, for every* *(unbounded) circuit* Pe *and auxiliary input distribution* D*,*   *|*①*|≤ n* ai *←* D Pr  *∧* ① *̸∈ L*(*R*) e e  *≤ ϵ* PCP(*n*)*.* Π e(①*,*Π) *←* P(ai) *∧* V (①) = 1

**Definition 3.12** (Knowledge soundness)**.** PCP = (P*,*V) *for a relation R has* **knowledge soundness error** *κ*PCP**with extraction time** *t*E*if there exists a probabilistic algorithm* E *such that, for every circuit* Pe *and* *auxiliary input distribution* D*,*   *|*①*|≤ n* ai *←* D Pr  *∧*(①*,*✇) *̸∈ R* (①*,*Π) e *←* Pe (ai)  *≤ κ*PCP(*n*); Π e e *∧* V (①) = 1 ✇ *←* E(①*,*Π)

### moreover, E runs in time tE(n).

We consider several efficiency measures for a PCP:

•the *proof alphabet* Σ is the alphabet over which a PCP string is written; •the *proof length* l is the number of alphabet symbols in the PCP string;

- the *query complexity* q *∈* [l] is the number of queries that the PCP verifier makes to the PCP string (each query is an index in [l] and is answered by the corresponding symbol in Σ in the PCP string); •the *randomness complexity* r is the number of random bits used by the PCP verifier. An efficiency measure may be a function of the instance ① (e.g., of its size *|*①*|*).

### 3.4 Interactive oracle proofs

An *interactive oracle proof* (IOP) system [BCS16; RRR16] is a generalization of PCPs to multiple rounds. An IOP system for a relation *R* is formally defined as follows.

**Definition 3.13** (Completeness)**.** IOP = (P*,*V) *for a relation R has* **perfect completeness** *if for every* *instance-witness pair* (①*,*✇) *∈ R,*

### Pr [⟨P(①,✇),V(①)⟩ = 1] = 1.

**Definition 3.14** (Soundness)**.** IOP = (P*,*V) *for a relation R has* **soundness error** *ϵ*IOP*if for every circuit* Pe*,*

  *|*①*|≤ n* ai *←* D Pr  *∧* ① *̸∈ L*(*R*) (①*,*aux) *←* Pe (ai)  *≤ ϵ*IOP(*n*)*.* *∧ b* = 1 *b ←* Pe (aux)*,*V(①)

**Definition 3.15** (Knowledge soundness)**.** IOP = (P*,*V) *for a relation R has* **knowledge soundness error** *κ*IOP**with extraction time** *t*E*if there exists a probabilistic algorithm* E *such that, for every circuit* Pe*,*   ai *←* D  *|*①*|≤ n* (①*,*aux) *←* Pe (ai)    Pr  *∧*(①*,*✇) *̸∈ R*tr e  *≤ κ*IOP(*n*);  *b ←−* P(aux)*,*V(①)  *∧ b* = 1 e ✇ *←* E P(aux) (①*,*tr)

### moreover, E runs in time tE(n).

We consider several efficiency measures for an IOP:

•the *proof alphabet* Σ is the alphabet over which each IOP string is written;

- the *proof length* l is the total number of alphabet symbols across all IOP strings sent by the IOP prover; moreover, l*i*is the length of the proof sent by P in round *i* and lmax:= max*i{*l*i}*;
- the *query complexity* q *∈* [l] is the total number of queries that the IOP verifier makes to any IOP string (each query specifies a round a location in the IOP string of that round and is answered by the corresponding symbol in the IOP string); •the *randomness complexity* r is the number of random bits used by the IOP verifier;
- the *round complexity* k is the number of interaction rounds (back-and-forth interactions) between the IOP prover and IOP verifier. Any efficiency measure may be a function of the instance ① (e.g., of the instance size *|*①*|*). **Public-coin IOPs.** We focus on IOPs that are *public-coin*, which informally means that the IOP verifier is a public-coin interactive algorithm. In other words, in every round, the verifier sends a uniformly random message, independent of other messages they send, to the prover. We provide the formal definition below. **Definition 3.16.** IOP = (P*,*V) *for a relation R is* **public-coin** *if, for every i ∈* [k]*, the i-th message of the* *IOP verifier* V *is a freshly-sampled uniform random string ρiof a prescribed length* r*i(which may depend on* *the instance). In particular, during an interaction, the IOP prover knows all the randomness sampled by the* *IOP verifier so far (as the messages received by the IOP prover are all that randomness so far).*

*Queries in a public-coin IOP can be postponed until after the interaction. (This is without loss of* *generality as, during the interaction, the IOP verifier simply sends a fresh random message in each round.)* *Hence the IOP can be viewed in two parts: an interaction phase (the prover sends oracles and the verifier* *sends random messages) and then a query phase (the verifier queries the oracles and outputs a decision).* *We denote by b* = V (Π*i*)*i∈*[k] (①; (*ρi*)*i∈*[k]) *the IOP verifier’s decision in the query phase, where* k *is the IOP’s* *round complexity; then the two-step experiment* (①*,*aux) *←* Pe *followed by b ←* Pe (aux)*,*V(①) *can be* *written as*   ai *←* D    (①*,*aux₀) *←* Pe (ai)  ai *←* D    (Πe *,*aux ) *←* Pe (aux )   (① *,*aux ) *←* Pe (ai)   1 1 0   0  r1  :   *ρ₁ ←{*0*,*1*}*   *ρ₀* = *⊥*       For *i ∈* [k *−* 1] *\{*1*}* : = For *i ∈* [k] : *.* (1)  e e   e e   (Π*i,*aux*i*) *←* P(aux*i−*1*,ρi−*1)   (Π*i,*aux*i*) *←* P(aux*i−*1*,ρi−*1)   r *i*   r *i*   *ρi←{*0*,*1*}*   *ρi←{*0*,*1*}*    (Π )

|e (aux e ← P||,ρ )||b := V|(①; (ρ|) )||
|---|---|---|---|---|---|---|---|
|k (Π|k−1 )|k−1 i i∈[k]||(Π )||i i∈[k]||

 Π*i i∈*[k]

*b* := V *i i∈*[k] (①; (*ρ*))

**Remark 3.17.** We often make use of simplifications as in Experiment 1, where the right-hand side sets *ρ₀* to the empty string *⊥*. (And does so, implicitly, for auxkas well.) We shall additionally make use of notation for *partial* (or full) executions of an interactive algorithm: for example, an execution of Pe until its second message is denoted ①*,* Πe₁*,*(Πe₂*,*aux₂) *←* Pe ai*,ρ₁* (we omit auxiliary outputs that are not used in the remainder of the experiment). Therefore, Experiment 1 is also equivalent to   ai *←* D  (*ρi*) *i∈*[k]*←{*0*,*1*}* r 1 +*···*+rk  *.*  (①*,* Πe₁*,...,*Πe k ) *←* Pe ai*,ρ₁,...,ρ*k*−*1 *b* := V (Π*i*)*i∈*[k] (①; (*ρi*)*i∈*[k])

**Public-query IOPs.** In Section 6 we discuss IOPs that are *public-query*, which informally means that security (soundness or knowledge soundness) holds even if the IOP prover can “see” the queries that the IOP verifier makes. In contrast, the general definition of an IOP implicitly assumes that an (honest or malicious) IOP prover has no information about the queries that the IOP verifier makes during the interaction.

**Definition 3.18.** IOP = (P*,*V) *for a relation R is* **public-query** *if the soundness (and knowledge soundness)* *condition holds even if the malicious IOP prover* Pe *receives, during the interaction, the index of each location* *queried by the IOP verifier* V *(the moment it happens). In particular, for each i ∈* [k]*, the IOP string* Πe*isent* *by* Pe *in the i-th round may depend on every query made by the IOP verifier in prior rounds (to prior IOP* *strings), in addition to depending on messages sent by the IOP verifier so far.*

Note that a public-coin IOP is a public-query IOP, but the converse need not hold.

## 4 Interactive arguments based on PCPs

### Theorem 4.1. Consider these two ingredients:

- PCP = (P*,*V)*, a PCP system for a relation R with alphabet* Σ*, proof length* l*, and query complexity* q*;* *and*
- VC = (Gen*,*Commit*,*Open*,*Check)*, a vector commitment scheme over alphabet* Σ*.* *Then* ARG = (*G, P, V*) := Kilian[PCP*,*VC] *(Construction 4.3) is a three-message public-coin interactive* *argument system for R, whose soundness error ϵ*ARG*and knowledge soundness error κ*ARG*satisfy the following* *for every ϵ >* 0 *and t*ARG*≥ t*V+ *t*VC*.*Check+ log*|*Σ*|* + log l*:*
*ϵ* ARG(*λ,n,t*ARG) *≤ ϵ*PCP(*n*) + *ϵ*VC(*λ,*l*,* q*,t*VC) + *ϵ and* *κ*ARG(*λ,n,t*ARG) *≤ κ*PCP(*n*) + *ϵ*VC(*λ,*l*,* q*,t*VC) + *ϵ .*

*Above, ϵ*PCP*and κ*PCP*are the soundness and knowledge soundness errors of* PCP*, and t*VC= *O* *ϵ* <u>l</u> *· t*ARG*.* *Moreover, the knowledge extractor runs in time tE*= *O*(*t*E+ *t*VC)*.*

**Corollary 4.2.** *Let* ARG *be as in Theorem 4.1. Assume that for any n ∈* N*, ϵ*VC(*·, ·, ·,t*VC) = negl(*n*) *if* *t* VC= poly(*n*)*. Then, given that t*ARG= poly(*n*)*, we have*

*ϵ* ARG(*λ,n,t*ARG) *≤ ϵ*PCP(*n*) + negl(*n*) *and* *κ*ARG(*λ,n,t*ARG) *≤ κ*PCP(*n*) + negl(*n*)*.*

*Proof.* Let *p*(*n*) be an arbitrary polynomial. We set *ϵ* to be 2*p* <u>1</u>

(*n*) *>* 0. Hence, *t*VC= *O*
*ϵ* <u>l</u> *· t*ARG= poly(*n*), which implies that *ϵ*VC(*λ,*l*,* q*,t*VC) = negl(*n*). Therefore,

<u>1 1</u> *ϵ* ARG(*λ,n,t*ARG) *≤ ϵ*PCP(*n*) + negl(*n*) + *< ϵ*PCP(*n*) + negl(*n*) +*.* 2*p*(*n*) *p*(*n*)

Since *p* is an arbitrary polynomial, we conclude that

*ϵ* ARG(*λ,n,t*ARG) *≤ ϵ*PCP(*n*) + negl(*n*)*.*

### An analogous argument holds for κARG.

### 4.1 Construction

The construction of (*G, P, V*) := Kilian[PCP*,*VC] is specified below.

**Construction 4.3.** The argument generator *G* receives as input a security parameter *λ ∈* N and an instance size bound *n ∈* N, and works as follows.

*G*(*λ,n*):

1.Sample public parameter for the VC scheme: ppVC*←* VC*.*Gen(1
*λ* *,*l(*n*)).

2.Set public parameter for the interactive argument: pp := ppVC.
3.Output pp.
The argument prover *P* receives as input the public parameter pp, an instance ① and a witness ✇, and the argument verifier *V* receives as input the public parameter pp and the instance ①. Then *P* and *V* interact as follows.

1. *P*’s commitment.
(a)Compute a PCP string: Π *←* P(①*,*✇).
(b)Compute a vector commitment to the PCP string: (cm*,*aux) *←* VC*.*Commit(pp*,*Π).
(c)Send cm to *V*.
2. *V*’s challenge.
(a)Sample PCP verifier randomness: *ρ ←{*0*,*1*}*
r.

(b)Send *ρ* to *P*.
3. *P*’s response.
(a)Run the PCP verifier V
Π (①;*ρ*) to deduce its query set *Q⊆* [l].

(b)Compute a VC opening proof: pf *←* VC*.*Open(pp*,*aux*, Q*).
(c)Set ans := Π[*Q*].
(d)Send (*Q,* ans*,*pf) to *V*.
4. *V*’s decision: check that V
[*Q,*ans] (①;*ρ*) = 1 and VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1.

The interactive argument consists of three messages: a prover message; a verifier message; and a prover message. The interactive argument is public-coin since the verifier’s (only) message is a uniform random string. The efficiency measures of interactive arguments are as follows:

•the generator outputs public parameter of size *|*ppVC*|* bits; •the prover-to-verifier communication consists of *|*cm*|* + q *·* (log l + log*|*Σ*|*) + *|*pf*|* bits; •the verifier-to-prover communication consists of r bits; •the time complexity of the argument generator is *t*VC*.*Gen. •the time complexity of the argument prover is *t*P+ *t*VC*.*Commit+ *t*V+ *t*VC*.*Open; •the time complexity of the argument verifier is *t*V+ *t*VC*.*Check.

**Remark 4.4.** There are vector commitments for which VC*.*Gen needs only the security parameter *λ* as input (i.e., VC*.*Gen works for every message size); for example, vector commitments based on Merkle trees have this property, because the public parameter consist of (the description of) a hash function, which suffices for every message size. In this case, the argument generator *G* in Construction 4.3 also requires only *λ* as input and works for every instance size. This leads the notion of an interactive argument discussed in Remark 3.5.

**Remark 4.5.** In the plain-model variant of Construction 4.3 (see Remark 3.6), the public parameters pp := ppVCare sampled and sent by the argument verifier (resulting in a four-message protocol). Hence the plain-model variant is public-coin if (and only if) VC*.*Gen is a public-coin algorithm (its output includes all of its randomness).

### 4.2 Security reduction

To analyze the soundness and knowledge soundness for the argument system of Construction 4.3, it is important to understand how the argument system is related to the PCP system. The core of the security analysis is the construction of a PCP prover Pe from an argument prover *P*e (which may or may not be malicious). More precisely, given a convincing argument prover *P*e, we want to obtain a convincing PCP prover Pe, which we achieve via the *reductor* algorithm *R* in Construction 4.8. Recall that if *V* accepts if and only if both V and VC*.*Check accept. Hence, Lemma 4.6 shows that PCP strings generated by the reductor *R* are, up to small errors, as convincing to the PCP verifier V as the argument prover *P* is to the argument verifier *V*; in other words, *R* transforms an argument prover *P*e into a

PCP prover Pe. 19 We later use this lemma to prove (adaptive) soundness and knowledge soundness of ARG in Sections 4.3 and 4.4, respectively.

**Lemma 4.6.** *There exists a probabilistic algorithm R which, for every ϵ >* 0*, auxiliary input distribution D,* *size bound t*ARG*≥ t*V+ *t*VC*.*Check+ 2q *·* (log*|*Σ*|* + log l)*, and t*ARG*-size circuit P*e*, satisfies*  *λ*  pp *←G*(1*,n*)  ai *←D*  [*Q*e*,*Π]e   V (①;*ρ*) *̸*= 1 ①*,*(cm*,*aux) *← P*e pp*,*ai   [*Q,*ans]  Pr  *∧* V (①;*ρ*) = 1 *P* e(aux*,·*)  (*Q*e*,*Π) e *←R* (pp*,*cm*,ϵ*)   *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 r   *ρ ←{*0*,*1*}*  (*Q,* ans*,*pf) *← P*e(aux*,ρ*)

*≤ ϵ*VC(*λ,*l*,* q*,t*VC) + *ϵ ,*

*where t*VC= *O* *ϵ* <u>l</u> *· t*ARG*. Moreover, R makes* l*/ϵ queries to P*e *and runs in O*(*t*VC) *time.*

We stress that in the experiment above the reductor *R* is *independent* of *ρ*, since it does not receive the verifier randomness as input. (Otherwise, the lemma would be satisfied trivially with *Q*e := *Q* and Π[ e *Q*e] := ans.) We now construct *R*, which will be convenient to separate into two parts: a sampling subroutine *S* followed by a post-processing layer *R*postthat deterministically pieces together a PCP string Πe from the samples obtained by *S* (and outputs the set *Q*e of “filled-in” coordinates along with Πe).

**Construction 4.7.** We construct the *sampler S* as follows.

*P* e (aux*,·*) *S* (pp*,*cm*,*N):

1.Initialize *K* := *∅*.
2.Repeat the following N times:

|||′|r||
|---|---|---|---|---|
|′ ′|′ ′|′ ′ ′|′ ′|′|

(a)Sample PCP verifier randomness: *ρ ←{*0*,*1*}*.
(b)Obtain (*Q,*ans*,*pf) *← P*e(aux*,ρ*).
(c)If VC*.*Check(pp*,*cm*, Q,*ans*,*pf) = 1, add (*Q,*ans*,*pf) to *K*.
3.Output *K*.
The algorithm *S* makes N queries to *P*e, and runs in time²⁰

*t* *S≤* N *·* (*t*ARG+ *t*V+ *t*VC*.*Check) *≤* 3N *· t*ARG*.*

**Construction 4.8.** The *reductor R* is defined as follows. (Below, *σ* is an arbitrary symbol in the alphabet Σ.)

*P* e (aux*,·*) 21 *R* (pp*,*cm*,ϵ*): <u>l</u> *P*e(aux*,·*)

1.Set N :=
*ϵ* and run *K←S* (pp*,*cm*,*N).

2.Run (*Q*e*,*Π) e *←R*post(*K,* l). 19 Moreover, *R* preserves uniformity: if *P*e is a uniform algorithm, then so is Pe. 20 Note that the 2q(log*|*Σ*|* + log l) overhead incurred by copying (*Q*
*′* *,*ans *′* *,*pf *′* ) into *K* is accounted for in the difference between *t* ARG and the other terms. 21 We also denote by *R* *P* e(aux*,·*) pp*,*cm*,ϵ*; *ρ*, where *ρ* = (*ρ*

(*ℓ*) ) (and similarly for *S*) the deterministic algorithm that uses *ℓ∈*[N]
*ρ*

(*ℓ*) as the randomness for *S*’s *ℓ*-th sample. This allows the PCP and IOP provers of Constructions 4.10 and 5.8 to be deterministic.

3.Output (*Q*e*,*Π) e.
The reductor’s second step is an execution of the following (deterministic) *post-processing* algorithm.

*R*post(*K,* l): l

1.Initialize Πe := *σ* and *Q*e := *∅*.
*′ ′ ′*

2.For every (*Q,*ans*,*pf) *∈K*:
*′*

(a)Set *Q*e := *Q∪Q* e.
*′ ′*

(b)For every *q ∈Q*, set Π[e *q*] := ans [*q*].
3.Output (*Q*e*,*Π) e.
Note that *R* makes N = l*/ϵ* queries to *P*e by construction, whose total N *· t*ARGtime dominates that of *R*.

*Proof.* Throughout this proof, probabilistic expressions are with respect to the following experiment unless explicitly denoted otherwise:     *λ λ* pp *←G*(1*,n*) pp *←G*(1*,n*)  ai   ai  *←D ←D*      e     (①*,*aux₀) *← P*(pp*,*ai)   ①*,*(cm*,*aux) *← P*e pp*,*ai   =e(aux*,·*)*.* (2)  (cm*,*aux₁) *← P*e(aux₀)   (*Q,*e Π) e *←RP*(pp*,*cm*,ϵ*)      r r  *ρ ←{*0*,*1*}*   *ρ ←{*0*,*1*}*  (*Q,* ans*,*pf) *← P*e(aux₁*,ρ*) (*Q,* ans*,*pf) *← P*e aux*,ρ*

Our goal is to upper bound the probability of the following expression:

  [*Q,*e eΠ] V (①;*ρ*) *̸*= 1  [*Q,*ans] *.* (3) *∧* V (①;*ρ*) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

Observe that Eq. 3 implies that either (i) Πe and ans disagree at a position *q ∈Q∩ Q*e; or (ii) there is a query *q* in *Q\ Q*e. We analyze the two cases separately.

**Valid openings with disagreeing answers.** Our goal is to prove the following bound:

*∃ q ∈Q∩ Q*e : ans[*q*] *̸*= Π[e *q*] Pr *≤ ϵ*VC(*λ,*l*,* q*,t*VC)*,* *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

where *t*VC*≤* 4N *· t*ARG. Consider the following adversary *A*VCagainst the vector commitment scheme, which follows Experiment 2 (without executing *R*post) and attempts to find a collision using the output *K* of the sampler *S*.

*A*VC(pp*,*ai):

1.Run ①*,*(cm*,*aux) *← P*e pp*,*ai.
r

2.Sample *ρ ←{*0*,*1*}*.
3.Run (*Q,* ans*,*pf) *← P*e(aux*,ρ*).

|P e(aux,·)||l|||
|---|---|---|---|---|
|′ ′|′|′ ϵ|′ ′|′|

4.Run *K←S* (pp*,*cm*,*N), with N = (as in Construction 4.8).
*′*

5. If there are (*Q,*ans*,*pf) *∈K* and *q ∈Q ∩Q* with ans [*q*] *̸*= ans[*q*], output (cm*,*ans*,*ans*, Q, Q,*pf*,*pf).
6.Otherwise, output (the “dummy” tuple) (cm*,*ans*,*ans*, Q, Q,* pf*,*pf).

The time complexity of the sampler *S* is at most 3N *· t*ARGand the collision-finding check (Step 5) runs in 22 time N *·* 2q(log*|*Σ*|* + log l) *≤* N *· t*ARG, so the time complexity of *A*VCis *t*VC*≤* 4N *· t*ARG. Therefore, according to Definition 3.8,

*∃ q ∈Q∩ Q*e : ans[*q*] *̸*= Π[e *q*] Pr *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1   *′ λ* *|Q|* = *|Q |* = q pp *←* VC*.*Gen(1*,*l)  *∧∃ q ∈Q∩Q′*: ans[*q*] *̸*= ans*′*[*q*] ai *←D*  = Pr    *∧* VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 cm*,*ans*,*ans*′,*  *′ ′ ′ ′ ′← A*VC(pp*,*ai) *∧* VC*.*Check(pp*,*cm*, Q,*ans*,*pf) = 1 *Q, Q,*pf*,*pf

### ≤ ϵVC(λ,l, q,tVC).

**Missing positions in** Πe**.** We now upper bound the probability that there is a missing position in Πe; we claim that *Q\ Q̸*e = *∅* Pr *≤ ϵ .* *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

Fix a public parameter-auxiliary input pair (pp*,*ai) (recall that these are obtained in the first steps of Experiment 2), and define the *weight* of a coordinate *q ∈* [l] with respect to (pp*,*ai) as   (①*,*cm*,*aux) *← P*e(pp*,*ai) *q ∈Q*r *δ*  pp*,*ai(*q*) := Pr  *ρ ←{*0*,*1*}.* *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 (*Q,* ans*,*pf) *← P*e(aux*,ρ*)

Then, by a union bound over *q ∈* [l],

*Q\ Q̸*e = *∅* Pr *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

*∃ q ∈* [l] : *q ∈Q∧ q /∈ Q*e = Pr *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1     (①*,*cm*,*aux) *← P*e(pp*,*ai)  *∃ q ∈* [l] : *q ∈Q∧ q /∈ Q*er *≤* max Pr  *ρ ←{*0*,*1*}*  (pp*,*ai)  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1  (*Q,* ans*,*pf) *← P*e(aux*,ρ*)   X  N = max *δ*pp*,*ai(*q*) *·* 1 *− δ*pp*,*ai(*q*) (pp*,*ai)   *q∈*[l] <u>l</u> *≤,* N N 23 <u>l</u> where the last inequality follows from *δ ·* (1 *− δ*) *≤* 1*/*N for any *δ ∈* [0*,*1]. Finally, plugging in N = *ϵ* bounds Eq. 3 as desired, concluding the proof:   [*Q,*e eΠ] V (①;*ρ*) *̸*= 1 Pr  *∧* V[*Q,*ans](①;*ρ*) = 1  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 22 *′* Searching for an intersection between *Q* and *Q* takes 2q log l time, while each check for a symbol mismatch takes 2 log*|*Σ*|*. We omit the time required to produce the output (which can be accounted for in the runtime of *S*). 23 N <u>d 1</u> A simple derivation of the inequality is the following: with *f* (*x*) = *x ·* (1 *− x*), we have *f* (*δ*) = 0 *⇐⇒ δ* =. As *dx* N+1 *f*(0) = *f*(1) = 0 and *δ* is the only critical point in [0*,*1], it achieves the maximum *f* (*δ*) *≤* 1*/*N.

*∃ q ∈Q∩ Q*e : ans[*q*] *̸*= Π[e *q*] *Q\ Q̸*e = *∅* *≤* Pr + Pr *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

### ≤ ϵVC(λ,l, q,tVC) + ϵ.

### 4.3 Adaptive soundness

**Lemma 4.9.** *For every ϵ >* 0*, security parameter λ ∈* N*, instance size bound n ∈* N*, auxiliary input* *distribution D, circuit size bound t*ARG*≥ t*V+ *t*VC*.*Check+ 2q *·* (log*|*Σ*|* + log l) *and t*ARG*-size circuit P*e*, the* *soundness error of the argument system in Construction 4.3 satisfies*

*ϵ* ARG(*λ,n,t*ARG) *≤ ϵ*PCP(*n*) + *ϵ*VC(*λ,*l*,* q*,t*VC) + *ϵ ,*

*where t*VC= *O* *ϵ* <u>l</u> *· t*ARG*.*

*Proof.* Recall, from Definition 3.3 and Construction 4.3, that our goal is to upper bound

 *λ*  pp *←G*(1*,n*)  *|*①*|≤ n* ai *←D*  Pr   *∧* ① *∈/ L*(*R*) e   (①*,*aux) *← P*(pp*,*ai) *∧ b* = 1 *b ← P*e(aux)*, V*(pp*,*①) *λ* pp *←G*(1*,n*)  *|*①*|≤ n* ai *←D*   *∧* ① *∈/ L*(*R*)  = Pr   [*Q,*ans] ①*,*(cm*,*aux) *← P*e pp*,*ai   *.*  *∧* V (①;*ρ*) = 1 *ρ ←{*0*,*1*}* r *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 e (*Q,* ans*,*pf) *← P*(aux*,ρ*)

(Since *P*e sends cm as the first message in Construction 4.3, the former experiment is equivalent to the latter, where we omit the auxiliary state of the choice of instance and aux denotes that of the first message.) As in Lemma 4.6, we consider the following experiment (a restatement of Experiment 2), which augments the above by executing *R*, and thus leaves the probability unchanged.  *λ*  pp *←G*(1*,n*)  ai *←D*     ①*,*(cm*,*aux) *← P*e pp*,*ai     e e*P* e(aux*,·*)*.*  (*Q,* Π) *←R* (pp*,*cm*,ϵ*)   r   *ρ ←{*0*,*1*}*  (*Q,* ans*,*pf) *← P*e(aux*,ρ*)

By total probability,   *|*①*|≤ n*  *∧* ① *̸∈ L*(*R*)  Pr  [*Q,*ans]   *∧* V (①;*ρ*) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

    *|*①*|≤ n |*①*|≤ n*      *∧* ① *̸∈ L*(*R*)   *∧* ① *̸∈ L*(*R*)  [*Q,*e eΠ] [*Q,*e eΠ] = Pr  *∧* V (①;*ρ*) = 1  + Pr  *∧* V (①;*ρ*) *̸*= 1 *.*     [*Q,*ans] [*Q,*ans]  *∧* V (①;*ρ*) = 1   *∧* V (①;*ρ*) = 1  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

We first bound the probability of the leftmost term by the PCP system’s soundness error (i.e., Defini- tion 3.11 with respect to PCP).

**Construction 4.10.** We define the auxiliary input distribution D of the PCP prover Pe as follows:

D: *λ* (*ℓ*) r N

1.Sample pp *←G*(1*,n*) followed by ai *←D* and *ρ* := (*ρ*)*ℓ∈*[N]*←* (*{*0*,*1*}*).
2.Output ai := pp*,*ai*, ρ*.
The PCP prover is then given by the following next message functions. Pe (ai):

|1.Parse ai as|pp, ai, ρ.|
|---|---|
|2.Run (①, aux) ← P|e(pp, ai).|
|3.Set aux :=|pp, aux₀, ρ.|

4.Output (①*,*aux).
### Pe (aux):

1.Parse aux as pp*,*aux₀*, ρ*.
2.Run (cm*,*aux₁) *← P*e(aux₀).
e(aux1*,·*)

3.Run (*Q*e*,*Π) e *←RP*pp*,*cm*,ϵ*; *ρ*.
4.Output Πe.
24 Using Definition 3.11,   *|*①*|≤ n*      *∧* ① *̸∈ L*(*R*)  *|*①*|≤ n* [*Q,*e eΠ] Pr  *∧* V (①;*ρ*) = 1  *≤* Pr  *∧* ① *̸∈ L*(*R*)   e e [*Q,*ans] [*Q,*Π]  *∧* V (①;*ρ*) = 1  *∧* V (①;*ρ*) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1   *|*①*|≤ n* ai *←* D *≤* Pr  *∧* ① *̸∈ L*(*R*) (①*,*aux) *←* Pe (ai)  Πe *∧* V (①) = 1 Πe *←* Pe (aux)

*≤ ϵ*PCP(*n*)*.*

Lastly, an application of Lemma 4.6 yields   *|*①*|≤ n*   [*Q*e*,*Π]e  *∧*(①*,*✇) *̸∈ R*  V (①;*ρ*) *̸*= 1 [*Q,*e eΠ] Pr  *∧* V (①;*ρ*) *̸*= 1[*Q,*ans]   *≤* Pr  *∧* V (①;*ρ*) = 1   [*Q,*ans]  *∧* V (①;*ρ*) = 1  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

24 Note that the prover in Definition 3.11 corresponds to the sequential execution of both steps in Construction 4.10.

*≤ ϵ*VC(*λ,*l*,* q*,t*VC) + *ϵ ,*

where *t*VC*≤* <u>4</u> *ϵ* <u>l</u> *· t*ARG, which concludes the proof.

### 4.4 Adaptive knowledge soundness

**Lemma 4.11.** *For every ϵ >* 0*, security parameter λ ∈* N*, instance size bound n ∈* N*, auxiliary input* *distribution D, circuit size bound t*ARG*≥ t*V+ *t*VC*.*Check+ 2q *·* (log*|*Σ*|* + log l) *and t*ARG*-size circuit P*e*, the* *knowledge soundness error of the argument system obtained by Construction 4.3 satisfies*

*κ*ARG(*λ,n,t*ARG) *≤ κ*PCP(*n*) + *ϵ*VC(*λ,*l*,* q*,t*VC) + *ϵ ,*

*where t*VC= *O* *ϵ* <u>l</u> *· t*ARG*. If the PCP extractor’s runtime is t*E*, the argument system’s extractor is tE*= *t* E+ *O*(*t*VC)*.*

**Construction 4.12.** Let E be the extractor for PCP. We use Pe (Construction 4.10) and E to construct the knowledge extractor *E* for ARG as follows.

*P* e (aux) *E* (pp*,* ①*,*tr):

1.Sample *ρ ←* (*{*0*,*1*}*
r ) N.

2.Set aux := pp*,*aux*, ρ* and run Πe *←* Pe (aux).
25

3.Run ✇ *←* E(①*,*Π) e.
4.Output ✇. Note that *E* executes E once and *P*e for l*/ϵ* times (as Pe runs the reductor *R*, which in turn sets N = l*/ϵ*
and repeats N executions of *P*e). Therefore, *tE*= *t*E+ *O*(*t*VC).

*Proof.* From Definition 3.4 and Construction 4.3, our goal is to upper bound  *λ*  pp *←G*(1*,n*)  ai *←D*   *|*①*|≤ n*   (①*,*aux) *← P*e(pp*,*ai)  Pr  *∧*(①*,*✇) *̸∈ R*   tr e   *∧ b* = 1 *b ←− P*(aux)*, V*(pp*,*①)  *P* e (aux) ✇ *←E* (pp*,* ①*,*tr)  *λ*  pp *←G*(1*,n*)  ai *←D*     (①*,*aux ) *← P*e(pp*,*ai)   *|*①*|≤ n* 0  e   *∧*(①*,*✇) *̸∈ R* (cm*,*aux₁) *← P*(aux₀)  = Pr  [*Q,*ans] r *.*  *∧* V (①;*ρ*) = 1 *ρ ←{*0*,*1*}*   e   *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 (*Q,* ans*,*pf) *← P*(aux₁*,ρ*)     tr := (cm*,ρ, Q,* ans*,*pf)  *P* e (aux0) ✇ *←E* (pp*,* ①*,*tr)

Now, note that by Constructions 4.10 and 4.12, the experiment above is equivalent to the following.

25 *′*e(aux)).

|Note that, by Construction 4.10, P|e only executes P|e(aux) (calls to P|e(aux ,ρ) are continuations of executions of P|
|---|---|---|---|
|Therefore, an equivalent construction gives P|e oracle access to P|e(aux) (rather than to P|e), excluding aux from aux.|

  *λ* pp *←G*(1*,n*)  ai *←D*      pp *←G*(1*λ,n*)  (①  *,*aux₀) *← P*e(pp*,*ai)    ai *←D*   (cm    *,*aux )1*← P*e(aux )0    r  ①*,*(cm*,*aux) *← P*e pp*,*ai   *ρ ←{*0*,*1*}*   r   = *ρ ←{*0*,*1*}* *.*  (*Q,* ans*,*pf) *← P*e(aux₁*,ρ*)    e    (*Q,* ans*,*pf) *← P*(aux*,ρ*)  r N  *ρ ←* (*{*0*,*1*}*)  e(aux*,·*)    (*Q*e*,*Π) e *←RP*(pp*,*cm*,ϵ*)   aux := pp*,*aux₀*, ρ*    ✇ *←* E(①*,*Π) e  Πe *←* Pe (aux) 

### ✇ ← E(①,Π) e

We thus consider the above experiment, which augments that of Lemma 4.6 by appending an execution of E, for the rest of the proof. Note that, as in Lemma 4.9, the experiment consisting of (①*,*aux₀) *← P*e(pp*,*ai) followed by (cm*,*aux₁) *← P*e(aux₀) can be replaced by ①*,*(cm*,*aux) *← P*e pp*,*ai : since *R* only uses the second auxiliary state (which is obtained deterministically from the first), the former can be omitted. Note, moreover, that the explicit randomness for Pe on the left-hand side is replaced with sampling by *R* on the right-hand side. By total probability,   *|*①*|≤ n*  *∧*(①*,*✇) *̸∈ R*  Pr    *∧* V[*Q,*ans](①;*ρ*) = 1  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1     *|*①*|≤ n |*①*|≤ n*      *∧*(①*,*✇) *̸∈ R*   *∧*(①*,*✇) *̸∈ R*  [*Q,*e eΠ] [*Q,*e eΠ] = Pr  *∧* V (①;*ρ*) = 1  + Pr  *∧* V (①;*ρ*) *̸*= 1 *.*     [*Q,*ans] [*Q,*ans]  *∧* V (①;*ρ*) = 1   *∧* V (①;*ρ*) = 1  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

With the PCP prover Pe in Construction 4.10 and using Definition 3.12, we have   *|*①*|≤ n*      *∧*(①*,*✇) *̸∈ R*  *|*①*|≤ n* ai *←* D [*Q,*e eΠ] Pr  *∧* V (①;*ρ*) = 1  *≤* Pr  *∧*(①*,*✇) *̸∈ R* (①*,*Π) e *←* Pe  *≤ κ*PCP(*n*)*.*  e [*Q,*ans] Πe  *∧* V (①;*ρ*) = 1  *∧* V (①) = 1 ✇ *←* E(①*,*Π) *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

Finally, Lemma 4.6 implies   *|*①*|≤ n*   [*Q,*e eΠ] [*Q*e*,*Π]e V (①;*ρ*) *̸*= 1   *∧* V (①;*ρ*) *̸*= 1 Pr   *≤* Pr  *∧* V[*Q,*ans](①;*ρ*) = 1   [*Q,*ans]  *∧* V (①;*ρ*) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

*≤ ϵ*VC(*λ,*l*,* q*,t*VC) + *ϵ ,*

<u>4l</u> where *t*VC*≤ · t*ARG, which concludes the proof. *ϵ*

## 5 Interactive arguments based on public-coin IOPs

### Theorem 5.1. Consider these two ingredients:

- IOP = (P*,*V)*, a public-coin IOP system for a relation R with round complexity* k*, alphabet* Σ*, proof* *length* l*, and query complexity* q*; and*
- VC = (Gen*,*Commit*,*Open*,*Check)*, a vector commitment scheme over alphabet* Σ*.* *Then* ARG = (*G, P, V*) := IBCS[IOP*,*VC] *(Construction 5.3) is a* (2k + 1)*-message public-coin interactive* *argument system for R whose soundness error ϵ*ARG*and knowledge soundness error κ*ARG*satisfy the following* *for every ϵ >* 0 *and t*ARG*≥ t*V+ *t*VC*.*Check+ log*|*Σ*|* + log lmax*:*
*ϵ* ARG(*λ,n,t*ARG) *≤ ϵ*IOP(*n*) + *ϵ*VC(*λ,*lmax*,* qmax*,t*VC) + *ϵ and* *κ*ARG(*λ,n,t*ARG) *≤ κ*IOP(*n*) + *ϵ*VC(*λ,*lmax*,* qmax*,t*VC) + *ϵ ,*

*where t*VC= *O* <u>k</u> *ϵ* <u>·l</u> *· t*ARG*. Moreover, the knowledge extractor runs in time tE*= *t*E+ *O*(*t*VC)*.*

**Corollary 5.2.** *Let* ARG *be as in Theorem 5.1. Assume that for any n ∈* N*, ϵ*VC(*·, ·, ·,t*VC) = negl(*n*) *if* *t* VC= poly(*n*)*. Then, given that t*ARG= poly(*n*)*, we have*

*ϵ* ARG(*λ,n,t*ARG) *≤ ϵ*IOP(*n*) + negl(*n*) *and* *κ*ARG(*λ,n,t*ARG) *≤ κ*IOP(*n*) + negl(*n*)*.*

### 5.1 Construction

We describe below the construction of the interactive argument, which we denote (*P, V*) := IBCS[IOP*,*VC].

**Construction 5.3.** The argument generator *G* receives as input a security parameter *λ ∈* N and an instance size bound *n ∈* N, and works as follows.

*G*(*λ,n*):

1.Sample public parameters for the VC scheme: ppVC*←* VC*.*Gen 1
*λ* *,* lmax(*n*). 26

2.Set public parameters for the interactive argument: pp := ppVC.
3.Output pp.
The argument prover *P* receives as input the public parameter pp, an instance ① and a witness ✇, and the argument verifier *V* receives as input the public parameter pp and the instance ①. Then *P* and *V* interact as follows.

1. *P*’s commitments. For *i ∈* [k]:
(a) *P*’s *i*-th commitment.
i.Compute the *i*-th IOP string Π*i∈* Σ
l *i*and auxiliary state:27

( P(①*,*✇) if *i* = 1 (Π*i,*aux*i*) *←.* P(aux*i−*1 *i−*1

|||,ρ )|if i > 1||
|---|---|---|---|---|
|Alternatively, VC.Gen could sample one set of public parameters pp||per proof length l|and set pp := (pp|). For|
|simplicity, we consider a single one and assume P|e pads proofs where l|< l with a fixed symbol σ ∈ Σ where appropriate.|||
|Note the implicit setting of aux|||at the end of the interaction.||

26 *i* VC*,i* VC*,i i∈*[k] *i* max 27 k:= *⊥*, since P only outputs the last proof string Πk

ii.Compute a VC commitment to the IOP string: (cm*i,*aux*i*) *←* VC*.*Commit(pp*,* Π*i*). iii.Send cm*i*to *V*.

(b) *V*’s *i*-th challenge.
i.Sample the *i*-th IOP verifier randomness *ρi←{*0*,*1*}*
r *i*. ii.Send *ρi*to *P*.

2. *P*’s response.
(a) Run the IOP verifier V
Π1*,...,*Πk
(①; *ρ₁,...,ρ*k) to deduce *Q₁,..., Q*k, where *Qi⊆* [l*i*] is the query
set of V to Π*i*.

(b)For every *i ∈* [k], compute an opening proof pf*i←* VC*.*Open(pp*,*aux*i, Qi*) and set ans*i*:= Π*i*[*Qi*].
(c)Send (*Qi,*ans*i,*pf*i*)
*i∈*[k] to *V*.

3. *V*’s decision. Check that V
([*Qi,*ans*i*])*i∈*[k] (①; *ρ₁,...,ρ*k) = 1 and VC*.*Check(pp*,*cm*i, Qi,*ans*i,*pf*i*) = 1 for all *i ∈* [k]. 28

The protocol has k + 1 rounds: the first k simulate the IOP, and in the last *P*e sends the query set assignments along with their opening proofs. Moreover, the protocol is public coin because the verifier’s messages consist of random strings. We comment on the protocol’s efficiency measures:

•the generator communication to prover and verifier consists of *|*ppVC*|* bits; P •the prover-to-verifier communication consists of *i∈*[k] (*|*cm*i|* + q *·* (log l*i*+ log*|*Σ*|*) + *|*pf*i|*) bits; P •the verifier-to-prover communication consists of r = *i∈*[k] r *i*bits; •the time complexity of the argument generator is *t*VC*.*Gen. •the time complexity of the argument prover is *t*P+ k *·* (*t*VC*.*Commit+ *t*VC*.*Open) + *t*V; •the time complexity of the argument verifier is *t*V+ k *· t*VC*.*Check.

### 5.2 Security reduction

As in Section 4.2, our analysis relies on the following security reduction lemma that relates the acceptance probability of ARG := IBCS[IOP*,*VC] with that of IOP.

**Lemma 5.4.** *There exists a probabilistic algorithm R which, for every size bound t*ARG*≥ t*V+ *t*VC*.*Check+ log*|*Σ*|* + log lmax*, circuit P*e *of size t*ARG*and ϵ >* 0*, satisfies*   pp *←G*(1 *λ* *,n*)  ai *←D*     e   (①*,*aux₀) *← P*(pp*,*ai)  ([*Q*e *i* *,*Π e *i*])*i∈*[k]  V (①; (*ρi*)*i∈*[k]) *̸*= 1 *ρ₀* := *⊥*   ([*Q ,i*ans])*i*  Pr   *∧* V*i∈*[k]①; (*ρi*)*i∈*[k]= 1 For *i ∈* [k] :    V (cm*i,*aux*i*) *← P*e(aux*i−*1*,ρi−*1)   *∧i∈*[k]VC*.*Check pp*,*cm*i, Qi,*ans*i,*pf*i*= 1 e 

|||||e, Π e ) ←R (Q||pp, (cm )||, (ρ ) ,ϵ|
|---|---|---|---|---|---|---|---|---|
|||||i i i i i|P (aux r i i∈[k]|,·)|j j∈[i] k k|j j<i|

 *P*(aux*i,·*)   *i i j j∈*[*i*] *j j<i*   *ρ ←{*0*,*1*}i*    (*Q,*ans*,*pf) *← P*e(aux*,ρ*)

*≤ ϵ*VC(*λ,*lmax*,* qmax*,t*VC) + *ϵ ,*

*where t*VC*and the total runtime of all executions of R are O* <u>k</u> *ϵ* <u>·l</u> *· t*ARG*.*

28 *V* also implicitly checks for appropriate padding, i.e., that ans*i*[*q*] = *σ* for every *q ∈Qi \* [l*i*].

We first construct the reductor *R*, which, similarly to Construction 4.8, will include a sampling subroutine *S* and a post-processing subroutine *R*post.

**Construction 5.5.** Given a number of iterations N *∈* N, we construct the sampler *S* as follows.

*P*e(aux*i,·*) *S* pp*,*(cm*j*)*j∈*[*i*]*,* (*ρj*)*j<i,*N :

1.Initialize *K* := *∅*.
2.Repeat the following N times:
*′i ′* r*i*rk

(a)Sample IOP verifier randomness: (*ρ*

|||,...,ρ|) ←{0, 1}|×···×{0, 1}||.||
|---|---|---|---|---|---|---|---|
|′i ′i|′i i ′i|′j ′j ′i ′i|′j ′j i<j≤k|′i ′i ′i|i|i−1|′i|

k *′i ′i ′i ′j ′j ′j ′j ′i ′*

(b)Obtain (*Q,*ans*,*pf)*,* (cm*, Q,*ans*,*pf) *← P*e(aux*,ρ₁,...,ρ,ρ,...,ρ*).
k

(c)If VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1, add (*Q,*ans*,*pf) to *K*.
3.Output *K*.
**Construction 5.6.** The reductor *R* is defined below.

*Ri*pp*,*(cm)*,* (*ρ*)*,ϵ* :

|P e(aux ,·)|j j∈[i]|j j<i||
|---|---|---|---|
||P e(aux ,·)|j j∈[i]|j j<i|
|||i 29||

1.Set N := l*/ϵ*.
2.Run *K←Si*pp*,*(cm)*,* (*ρ*)*,*N.
3.Run (*Q*e*,*Π) e *←R*post(*K,*l).
4.Output (*Q*e*,*Π) e.
Note that in each of its N iterations, *S* runs VC*.*Check (once) and makes at most k queries to *P*e. Since *t* e dominate the remaining steps of *R*), the total runtime of *R* across all ARG*≥ t*VC*.*Check(and the executions of *P* <u>k·l</u> k rounds is *O · t*ARG. *ϵ*

*Proof.* Throughout this proof, probabilistic expressions are with respect to the following experiment:   *λ* pp *←G*(1*,n*)  ai   *←D*   e   (①*,*aux₀) *← P*(pp*,*ai)     *ρ₀* := *⊥*     For *i ∈* [k] : *,*    (cm*,*aux*i*) *← P*e(aux*i−*1*,ρi−*1)  *i*    *P*e(aux*i,·*)   (*Q*e*i,* Πe )*i←R* pp*,*(cm )*j j∈*[*i*]*,* (*ρj*)*j<i,ϵ*   r*i*

|i||r||||
|---|---|---|---|---|---|
|i|i i|i∈[k] e from a set of samples K (see Construction 4.8).||k k||

 *ρ ←{*0*,*1*}*  (*Q,*ans*,*pf) *← P*e(aux*,ρ*)

29 Recall that *R*post pieces together a proof string Π

which by Construction 5.6 is equivalent to   *λ* pp *←G*(1*,n*)  ai  *←D*    (①  *,*aux )0*← P*e(pp*,*ai)     *ρ₀* := *⊥*     For *i ∈* [k] :   *.* (4)  (cm*i,*aux*i*) *← P*e(aux*i−*1*,ρi−*1)     *P*e(aux*i,·*) 

|i P (aux e|,·)|j j∈[i]|j j<i|
|---|---|---|---|
|i i||i i||
|i|r|||
|i i|i i∈[k]|k|k|

*K ←S* pp*,*(cm)*,* (*ρ*)*,* N    e e   (*Q,* Π) *←R*post(*K,* l)  *i*  *ρ ←{*0*,*1*}*  (*Q,*ans*,*pf) *← P*e(aux*,ρ*)

The argument is analogous to Lemma 4.6. We first note that

  ([*Q*e*i,*Πe])*i i∈*[k] V (①; (*ρi*)*i∈*[k]) *̸*= 1  ([*Qi,*ans*i*])*i∈*[k]

|([Q ,ans|])|i i∈[k]|||
|---|---|---|---|---|
|i∈[k]|||i i|i i|

 *∧* V ①; (*ρi*)*i∈*[k]= 1  V *∧* VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1

implies, likewise, the existence of valid openings with disagreeing answers or a missing query in one of the IOP strings. We analyze the two cases separately.

**Valid openings with disagreeing answers.** We aim to show that " # *∃ i ∈* [k]*,q ∈Qi∩ Q*e*i*: ans*i*[*q*] *̸*= Πe*i*[*q*] Pr V *≤ ϵ*VC(*λ,*lmax*,* qmax*,t*VC) *∧* VC*.*Check pp*,*cm*i, Qi,*ans*i,*pf*i*= 1 *i∈*[k]

<u>k·l</u> where *t*VC= *O · t*ARG. *ϵ* We consider the following adversary *A*VCagainst the vector commitment scheme, which (essentially) follows Experiment 4:

*A*VC(pp*,*ai):

1.Run (①*,*aux₀) *← P*e(pp*,*ai).

|ϵl||i i∈[k]||r +···+r|
|---|---|---|---|---|
|i|i|i−1 i−1|||
|i|P e(aux ,·)|j j∈[i]|j j<i||
|i i|i i∈[k]|k k ′i ′i|′i|i|
|i ′i|i ′i|′i|||

2.Set N :=, *ρ₀* := *⊥* and sample (*ρ*) *←{*0*,*1*}*1 k.
3.For *i ∈* [k]:
(a)Run (cm*,*aux) *← P*e(aux*,ρ*).
(b)Run *K ←Si*pp*,*(cm)*,* (*ρ*)*,*N.
4.Run (*Q,*ans*,*pf) *← P*e(aux*,ρ*).
*′i ′i*

5. If there exist *i ∈* [k] and (*Q,*ans*,*pf) *∈ K* with *q ∈ Qi∩Q* and ans*i*[*q*] *̸*= ans [*q*], output (cm*i,*ans*,*ans*, Q, Q,*pf*i,*pf).
6.Otherwise, output (the “dummy” tuple) (cm₁*,*ans₁*,*ans₁*, Q₁, Q₁,*pf₁*,*pf₁). The time complexity of k executions of the sampler *S* is *O*(kN *· t*ARG) and the collision-finding check
(Step 5) runs in time *O* kN *·* (log*|*Σ*|* + log l*i*) = *O*(kN *· t*ARG), so the total time complexity of *A*VCis <u>k·l</u> *t*VC= *O*(kN *· t*ARG) = *O · t*ARG. *ϵ*

Therefore, according to Definition 3.8, 30

" # *∃ i ∈* [k]*,q ∈Qi∩ Q*e*i*: ans*i*[*q*] *̸*= Πe*i*[*q*] Pr V *∧* *i∈*[k] VC*.*Check pp*,*cm*i, Qi,*ans*i,*pf*i*= 1

|∃ q ∈Q|e ∩ Q : ans [|q] ̸= Π|e [ q]|||
|---|---|---|---|---|---|
|′|i|i i i|i i i|||
||||||λ|
|′||′||||
||′ ′|′||′|′ ′|

*i* *≤* Pr *∃ i ∈* [k] : *∧*VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1   *|Q|* = *|Q |≤* qmax  *∧∃ q ∈Q∩Q* : ans[*q*] *̸*= ans [*q*] pp *←* VC*.*Gen(1*,* lmax)  *≤* Pr   cm*,*ans*,*ans*,*   *∧* VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 *← A*VC(pp) *Q, Q ,* pf*,*pf *∧* VC*.*Check(pp*,*cm*, Q,*ans*,*pf) = 1

### ≤ ϵVC(λ,lmax, qmax,tVC).

**Missing positions in** Πe*i***.** We are left to show   *∃ i ∈* [k] : *Qi\ Q*e*i̸*= *∅* Pr  V  *≤ ϵ .* *∧*

||VC.Check pp, cm||, Q, ans|, pf|= 1||
|---|---|---|---|---|---|---|
||i∈[k]||i i|i i|||
|||||j j<i|||
|i ))||j j<i|||||
|i||j||j i≤j≤k|1|r +···+r k|
|j∈[k]|j|j j||j|j|j j∈[k]|

To this end, fix a partial sequence of prover inputs (pp*,*ai*,* (*ρ*)) of Eq. 4 and define the *weight* of a coordinate *q ∈* [l] with respect to (pp*,*ai*,* (*ρ*)) as

*δ* (pp*,*ai*,*(*ρj j<i*(*q*)  

(*ρ*) *←{*0*,*1*}i* k
*q ∈Q*!  V ①*,*cm*,...,* cm*,*  := Pr  pp*,*cm*,* e pp*,*ai*,* *.* *∧* VC*.*Check = 1 *← P* *Q,*ans*,*pf (*Q,*ans*,*pf) (*ρ₁,...,ρ*k)

(We perform a partial execution of *P*e as in Lemma 4.6, omiting intermediate auxiliary states.) A union bound over all *q ∈* [l*i*] yields h i Pr *Qi\ Q*e*i̸*= *∅* h i = Pr *∃ q ∈* [l*i*] : *q ∈Qi∧ q /∈ Q*e*i*      (*ρj*)*i≤j≤*k*←{*0*,*1*}* r *i* +*···*+ ! r k    *∃ q ∈* [l*i*] : *q ∈Qi* ①*,*cm*,...,* cm*,*  *≤* max Pr  e 1 k e pp*,*ai*,*  (pp*,*ai*,*(*ρj*)*j<i*)  *∧ q /∈ Qi*

|(pp,ai,(ρ|))||i||j|j j j∈[k]||
|---|---|---|---|---|---|---|---|
|||||||N||
|(pp,ai,(ρ i|)) q∈[l|(pp,ai,(ρ]|))||(pp,ai,(ρ)|)||

(*Q ,* ans*,*pf ) *← P*   (*ρ₁,...,ρ*k)    X  *≤* max *δ* *j j<i*

(*q*) *·* 1 *− δ*
*j j<i*

(*q*)
*j j<i*  *i* <u>l</u> *≤,* <u>N</u> 30

|Note that A|P|. Denoting by E|the event that it is found in K|
|---|---|---|---|
|side of the second inequality may be replaced by Remark 3.9).|Pr [E] · ϵ|(λ, l, q ,t|), and the last follows from monotonicity of ϵ|

VC, if successful, outputs a tuple in one of the *Ki i i*, the right-hand *i i* VC *i i* VC VC (see

|([Q, ans])|i i∈[k]||||
|---|---|---|---|---|
|i∈[k]|i i|i i i|i i i||
|i∈[k]|i|i i i i|i i i i|i|

|i i|||i|
|---|---|---|---|
||i i|i i|i∈[k]|

+ log lmax*,* *, the soundness error of the argument system in*

and another union bound over *i ∈* [k] gives   *∃ i ∈* [k] : *Q \ Q*e *̸*= *∅* X <u>l l</u> Pr  V  *≤* =*.* *∧* *i∈*[k] VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1 N N

Since N = l*/ϵ*, we have

 ([*Q*e*,*Πe])  V *i i i∈*[k] (①; (*ρi*)*i∈*[k]) *̸*= 1  *∧* V ([*Q ,i*ans])*i i∈*[k] ①; (*ρ*) = 1  Pr  *i i∈*[k]  V *∧* VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1 " # *∃ i ∈* [k]*,q ∈Q ∩ Q*e : ans [*q*] *̸*= Πe [*q*] *≤* Pr V *∧* VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1 " # *∃ i ∈* [k]*,q ∈Q* : *q ̸∈ Q*e + Pr V *∧* *i∈*[k] VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1

*≤ ϵ*VC(*λ,*lmax*,* qmax*,t*VC) + *ϵ ,*

### which concludes the proof.

### 5.3 Adaptive soundness

**Lemma 5.7.** *For every security parameter λ ∈* N*, circuit size bound t*ARG*≥ t*V+ *t*VC*.*Check+ log*|*Σ*|* *circuit P*e *of size t*ARG*, instance size bound n ∈* N *and ϵ >* 0 *Construction 5.3 satisfies*

*ϵ* ARG(*λ,n,t*ARG) *≤ ϵ*IOP(*n*) + *ϵ*VC(*λ,*lmax*,* qmax*,t*VC) + *ϵ ,*

*where t*VC= *O*( <u>k</u> *ϵ* <u>·l</u> *· t*ARG)*.*

*Proof.* From Definition 3.3 and Construction 5.3, our goal is to upper bound

 *λ*  pp *←G*(1*,n*)  *|*①*|≤ n* ai *←D*  Pr   *∧* ① *∈/ L*(*R*) e   (①*,*aux) *← P*(pp*,*ai) *∧ b* = 1 *b ← P*e(aux)*, V*(pp*,*①)  *λ* pp *←G*(1*,n*)  ai *←D*   *|*①*|≤ n* (①*,*aux ) *← P*e(pp*,*ai) 0  *∧* ① *∈/ L*(*R*) *ρ* := *⊥*  0 = Pr  *∧* V ([*Qi,*ans*i*])*i∈*[k] ①; (*ρ*) = 1 *i i∈*[k]For *i ∈* [k] :  V e  *∧* *i∈*[k] VC*.*Check pp*,*cm*i, Qi,*ans*i,*pf*i*= 1 (cm*i,*aux*i*) *← P*(aux*i−*1*,ρi−*1) r *i*  *ρi←{*0*,*1*}* (*Qi,*ans*i,*pf*i*) *i∈*[k] *← P*e(auxk*,ρ*k



      *.*      )

As in Lemma 5.4, we consider the following experiment, which augments the above by executing *R* (multiple times) and leaves the probability unchanged.   pp *←G*(1 *λ* *,n*)  ai *←D*     e   (①*,*aux₀) *← P*(pp*,*ai)     *ρ₀* := *⊥*     For *i ∈* [k] : *.*    (cm *i* *,*aux*i*) *← P*e(aux*i−*1*,ρi−*1)   e   (*Q*e*,* Πe ) *←R* *P*(aux*i,·*) pp*,*(cm )*,* (*ρ*)*,ϵ*   *i i j j∈*[*i*] *j j<i*  

|i||r||||
|---|---|---|---|---|---|
|i|i i|i∈[k]||k k||

*ρ ←{*0*,*1*}* r *i*   (*Q,*ans*,*pf) *← P*e(aux*,ρ*)

By total probability,   *|*①*|≤ n*  *∧*(①*,*✇) *̸∈ R*   

|([Q ,ans|])|||
|---|---|---|---|
|i∈[k]||i i|i i|

Pr  *∧* V *i i i∈*[k] (①;*ρ*) = 1    V *∧* VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1   *|*①*|≤ n*  *∧*(①*,*✇) *̸∈ R*    ([*Q*e *i* *,*Π e *i*])*i∈*[k] = Pr   *∧* V (①; (*ρi*)*i∈*[k]) = 1    *∧* V([*Qi,*ans*i*])*i∈*[k]①; (*ρ*

|([Q ,ans])|i i∈[k]|||
|---|---|---|---|
|i∈[k]|i|i i|i|

*i* ) *i∈*[k]= 1   V  *∧* VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1   *|*①*|≤ n*  *∧*(①*,*✇) *̸∈ R*    ([*Q*e *i* *,*Π e *i*])*i∈*[k] + Pr   *∧* V (①; (*ρi*)*i∈*[k]) *̸*= 1   *.*  *∧* V([*Qi,*ans*i*])*i∈*[k]①; (*ρ*

|([Q ,ans])|i i∈[k]|||
|---|---|---|---|
|i∈[k]|i|i i|i|

*i* ) *i∈*[k]= 1   V  *∧* VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1

We first bound the probability on the left-hand side by using the soundness error definition of IOP in Definition 3.14.

**Construction 5.8.** We will construct an IOP prover Pe, and first define its auxiliary input distribution D as follows:

D:

1.Sample pp *←G*(1
*λ* *,n*) followed by ai *←D*.

||r +···+r N|r +···+r N|r N|
|---|---|---|---|
|i i∈[k]||||

1 k N 2 k N k N

2.Sample *ρ* := (*ρ*) *← {*0*,*1*} × {*0*,*1*} ×···× {*0*,*1*}*.
3.Output ai := pp*,*ai*, ρ*.
The IOP prover is then defined as follows.

- Pe (ai):
1.Parse ai as pp*,*ai*, ρ*.

2.Run (①*,*aux₀) *← P*e(pp*,*ai).
3.Set aux := pp*,*aux₀*, ρ*.
4.Output (①*,*aux).
- Pe (aux*,ρ*):
1.Parse aux as pp*,*aux

||, (cm|), ρ.|||
|---|---|---|---|---|
||i−1|j j<i|31||
|i−1|i|i|i−1|i−1|
|i i|P e(aux ,·)|j|j∈[i] j j<i|i|
|i|i|j j∈[i] j|j<i 32||
|i|i||||

2.Set *ρ* := *ρ* and run (cm*,*aux) *← P*e(aux*,ρ*) e e *i*
3.Run (*Q,* Π) *←R* pp*,*(cm)*,* (*ρ*)*,ϵ*; *ρ*.
4.Set aux := pp*,*aux*,*(cm)*,* (*ρ*)*, ρ*.
5.Output (Πe*,*aux). Using Definition 3.14 (with Experiment 1, the explicit public-coin IOP), we obtain

|([Q ,ans])|i i∈[k]|||
|---|---|---|---|
|i∈[k]|i|i i|i|



       *i−*1*,ρi−*1) 

  *|*①*|≤ n*  *∧* ① *̸∈ L*(*R*)    ([*Q*e *i* *,*Π e *i*])*i∈*[k] Pr   *∧* V (①; (*ρi*)*i∈*[k]) = 1    *∧* V([*Qi,*ans*i*])*i∈*[k]①; (*ρ* *i* ) *i∈*[k]= 1   V  *∧* VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1  ai *←* D  e  *|*①*|≤ n* (①*,*aux₀) *←* P(ai)   *∧* ① *̸∈ L*(*R*) *ρ₀* := *⊥* *≤* Pr   (Π e *i* ) For *i ∈* [k] :  *∧* V*i∈*[k]①; (*ρi*) *i∈*[k]) = 1  (Πe*i,*aux*i*) *←* Pe (aux *ρi←{*0*,*1*}* r *i*

*≤ ϵ*IOP(*n*)*.*

Lastly, an application of Lemma 5.4 yields  *|*①*|≤ n*  *∧* ① *̸∈ L*(*R*)  ([*Q*e *i* *,*Π e *i*])*i∈*[k] Pr   *∧* V (①; (*ρi*)*i∈*[k]) *̸*= 1  *∧* V([*Qi,*ans*i*])*i∈*[k]①; (*ρ*

|([Q ,ans])|i i∈[k]|||
|---|---|---|---|
|i∈[k] ([Q e ,Π e])|i i i∈[k]|i i|i|
|([Q, ans])|i i∈[k]|||
|i∈[k]||i i|i i|

*i* ) *i∈*[k]= 1  V *∧* VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1  V *i i i∈*[k] (①; (*ρ*)) = 1  *∧* V *i i i∈*[k] ①; (*ρ*) = 1 *≤* Pr  V *∧* VC*.*Check pp*,*cm*, Q,*ans*,*pf

*≤ ϵ*VC(*λ,*lmax*,* qmax*,t*VC) + *ϵ ,*

<u>which concludes the proof.</u> 31 Note that the round *i <* k is determined by the contents of aux. 32 We may assume aux = *⊥* in the case *i* = k, and the following step outputs (Πek*,*auxk) = Π



      



  = 1

e k.

+ log lmax*,* *, the knowledge soundness error of the argument*

*, the argument system’s extractor is t* *E*=

e (Construction 5.8) and E to construct the

### 5.4 Adaptive knowledge soundness

**Lemma 5.9.** *For every security parameter λ ∈* N*, circuit size bound t*ARG*≥ t*V+ *t*VC*.*Check+ log*|*Σ*|* *circuit P*e *of size t*ARG*, instance size bound n ∈* N *and ϵ >* 0 *system obtained by Construction 5.3 satisfies*

*κ*ARG(*λ,n,t*ARG) *≤ κ*IOP(*n*) + *ϵ*IOP(*n*) + *ϵ*VC(*λ,*lmax*,* qmax*,t*VC) + *ϵ ,*

*where t*VC= *O* <u>k</u> *ϵ* <u>·l</u> *· t*ARG*. If the IOP extractor’s runtime is t*E *t* E+ *O*(*t*VC)*.*

**Construction 5.10.** Let E be the extractor for IOP. We use P knowledge extractor *E* for ARG:

*P* e (aux) *E* (pp*,* ①*,*tr):

1.Parse tr as (cm*i,ρi, Qi,*ans*i,*pf*i*)
*i∈*[k]. r 1 +*···*+rkN r2+*···*+rkN rkN

2.Sample *ρ* := (*ρi*)*i∈*[k]*← {*0*,*1*} × {*0*,*1*} ×···× {*0*,*1*}*.
3.Set aux := pp*,*aux*, ρ*.
4.Run (Πe*i*)*i∈*[k]*←* Pe (aux) and set tr := (Πe*i,ρi*)*i<*k*,* Πek.
P(aux) e

5.Run ✇ *←* E (①*,*tr).
6.Output ✇.
*Proof.* From Definition 3.4 and Construction 5.3, out goal is to upper bound  *λ*  pp *←G*(1*,n*)  ai *←D*   *|*①*|≤ n*   (①*,*aux) *← P*e(pp*,*ai)  Pr  *∧*(①*,*✇) *̸∈ R*   tr e   *∧ b* = 1 *b ←− P*(aux)*, V*(pp*,*①)  *P* e (aux) ✇ *←E* (pp*,* ①*,*tr)  *λ* pp *←G*(1*,n*)  ai *←D*   (①*,*aux ) *← P*e(pp*,*ai)  0  *ρ* := *⊥*  *|*①*|≤ n*0   *∧*(①*,*✇) *̸∈ R* For *i ∈* [k] : = Pr   *∧* V ([*Qi,*ans*i*])*i∈*[k] ①; (*ρ*) = 1 (cm*,*aux ) *← P*e(aux*,ρ*)  V *i i∈*[k] *i i* r *i* *i−*1 *i−*1  *∧* VC*.*Check pp*,*cm*, Q ,* ans*,*pf = 1 *ρi←{*0*,*1*}*  *i∈*[k] *i i i i*  (*Q* *i* *,*ans*i,*pf*i*) *← P*e(auxk*,ρ*  *i∈*[k]  tr := (cm*,ρ ,*(*Q ,* ans*,*pf )) 

||||||i|i i|i i|i∈[k]|
|---|---|---|---|---|---|---|---|---|
||||||P e(aux)||||

✇ *←E* (pp*,* ①*,*tr)



             k )    

by appending an execution of E, for the rest of the proof. We consider the following experiment, which is equivalent to the above and augments that of Lemma 5.4

  *λ* pp *←G*(1*,n*)  ai   *←D*     *ρ*0:= *⊥*  Pk  r N r N  (*ρi*)*i∈*k*← {*0*,*1*}i*=*i j×···× {*0*,*1*}*k    For *i ∈* [k] :     (cm*,*aux*i*) *← P*e(aux*i−*1*,ρi−*1)  *i*  e e*P*e(aux*i,·*)*.*

|i i|P e(aux|,·)|ℓ ℓ∈[i]|ℓ ℓ<i|
|---|---|---|---|---|
|i|r||||
|i i|i i∈[k]||k k||
|i P(aux) e|i i∈[k−1]|k|||

 (*Q,* Π) *←R* pp*,*(cm)*,* (*ρ*)*,ϵ*; *ρi*    *i*  *ρ ←{*0*,*1*}*     (*Q,*ans*,*pf) *← P*e(aux*,ρ*)     aux :=   pp*,*aux*, ρ*   e e   tr := (Π*,ρ*)*,* Π  ✇ *←* E (①*,*tr)

By total probability,   *|*①*|≤ n*  *∧*(①*,*✇) *̸∈ R*  Pr    *∧* V([*Qi,*ans*i*])*i∈*[k]①; (*ρi*)*i∈*[k]= 1 

*∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1   *|*①*|≤ n*    *∧*(①*,*✇) *̸∈ R*  ([*Q*e*,*Πe])*i∈*[k] *i i* = Pr  *∧* V (①; (*ρi*)*i∈*[k]) = 1    *∧* V([*Qi,*ans*i*])*i∈*[k]①; (*ρ*) 

|([Q ,ans])|i i∈[k]|||
|---|---|---|---|
|i∈[k]|i|i i|i|

*i i∈*[k]= 1   V *∧* VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1   *|*①*|≤ n*    *∧*(①*,*✇) *̸∈ R*  ([*Q*e*,*Πe])*i∈*[k] *i i* + Pr  *∧* V (①; (*ρi*)*i∈*[k]) *̸*= 1*.*    *∧* V([*Qi,*ans*i*])*i∈*[k]①; (*ρ*) 

|([Q ,ans])|i i∈[k]|||
|---|---|---|---|
|i∈[k]|i|i i|i|

*i i∈*[k]= 1   V *∧* VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1

By the construction of Pe (Construction 5.8) and Definition 3.15, we have

  *|*①*|≤ n*    *∧*(①*,*✇) *̸∈ R*  ([*Q*e*,*Πe])*i∈*[k] *i i* Pr  *∧* V (①; (*ρi*)*i∈*[k]) = 1    *∧* V([*Qi,*ans*i*])*i∈*[k]①; (*ρ*) 

|([Q ,ans])|i i∈[k]|||
|---|---|---|---|
|i∈[k]|i|i i|i|

*i i∈*[k]= 1   V *∧* VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1   ai *←* D  *|*①*|≤ n*   (①*,*aux) *←* Pe (ai)  *≤* Pr  *∧*(①*,*✇) *̸∈ R*tr   *b ←−* P(aux) e*,*V(①)  *∧ b* = 1 P(aux) e ✇ *←* E (①*,*tr)

*≤ κ*IOP(*n*)*.*

Finally, Lemma 5.4 implies   *|*①*|≤ n*    *∧*(①*,*✇) *̸∈ R*  ([*Q*e*,*Πe])*i∈*[k] *i i* Pr  *∧* V (①; (*ρi*)*i∈*[k]) *̸*= 1    *∧* V([*Qi,*ans*i*])*i∈*[k]①; (*ρ*) 

|([Q ,ans])|i i∈[k]|||
|---|---|---|---|
|i∈[k] ([Q e ,Π e])|i i i∈[k]|i i|i|
|([Q, ans])|i i∈[k]|||
|i∈[k]||i i|i i|

*i i∈*[k]= 1   V *∧* VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1   *i i i∈*[k] V (①; (*ρ*)) *̸*= 1 *i i i∈*[k] *≤* Pr  *∧* V ①; (*ρ*) = 1  V *∧* VC*.*Check pp*,*cm*, Q,*ans*,*pf = 1

*≤ ϵ*VC(*λ,*lmax*,* qmax*,t*VC) + *ϵ ,*

### which concludes the proof.

## 6 Interactive arguments based on public-query IOPs

We argue that the security analysis for interactive arguments based on public-coin IOPs generalizes to interactive arguments based on public-query IOPs with an additional property: the existence of a *random* *continuation sampler (RCS)*. More precisely, we show that the existence of an RCS for Finale[IOP*,*VC] is equivalent to its existence for the underlying IOP; and that having an RCS for Finale[IOP*,*VC] is a sufficient condition for the (natural extension of the) public-coin security reduction to hold.

### Theorem 6.1. Consider these three ingredients:

- IOP = (P*,*V)*, a public-query IOP system for a relation R with round complexity* k*, alphabet* Σ*, proof* *length* l*, and query complexity* q*; moreover,* IOP *has an IOP random continuation sampler* S *with error α* *and running time t*S*; and*
- VC = (Gen*,*Commit*,*Open*,*Check)*, a vector commitment scheme over alphabet* Σ*.* *The* ARG = (*G, P, V*) := Finale[IOP*,*VC] *(Construction 6.2) is a* 4k*-message interactive argument system* *for R which, for every ϵ >* 0 *and t*ARG*≥ t*V+ *t*VC*.*Check+ log*|*Σ*|* + log lmax*, has soundness error ϵ*ARG*and* *knowledge soundness error κ*ARG*satisfying the following:*
<u>l · α</u> *ϵ* ARG(*λ,n,t*ARG) *≤ ϵ*IOP(*n*) + *ϵ*VC(*λ,*lmax*,* qmax*,t*VC) + *ϵ* + *and* *ϵ* <u>l · α</u> *κ*ARG(*λ,n,t*ARG) *≤ κ*IOP(*n*) + *ϵ*VC(*λ,*lmax*,* qmax*,t*VC) + *ϵ* +*,* *ϵ*

*where t*VC= *O* <u>k</u> *ϵ* <u>·l</u> *·* (*t*ARG+ *t*S)*. Moreover, the knowledge extractor runs in time tE*= *t*E+ *O*(*t*VC)*.*

Observe that if IOP admits an IOP random continuation sampler with error *√* <u>α</u> = 0, we obtain the same security bounds as in Theorem 5.1; conversely, if *α >* 0, then setting *ϵ* = *α ·* l achieves the minimum additional error of 2*ϵ*. Note, moreover, that ARG is public-coin if IOP is public-coin.

### 6.1 Construction

Below, we describe the construction of the interactive argument we denote (*P, V*) := Finale[IOP*,*VC].

**Construction 6.2** (Arguments from public-query IOPs)**.** The argument generator *G* receives as input a security parameter *λ ∈* N and an instance size bound *n ∈* N, and works as follows.

*G*(*λ,n*):

1.Sample public parameter for the VC scheme: ppVC*←* VC*.*Gen 1
*λ* *,* lmax(*n*).

2.Set public parameter for the interactive argument: pp := ppVC.
3.Output pp.
The argument prover *P* receives as input an instance ① and a witness ✇, and the argument verifier *V* receives as input the instance ①. Then *P* and *V* interact as follows.

1. *V*’s randomness: Sample *ρ ←{*0*,*1*}*
r.

2. *P*’s commitments. For *i ∈* [k]:
(a) *P*’s *i*-th commitment.

i.Compute the *i*-th IOP string and auxiliary state:
( P(①*,*✇) if *i* = 1 (Π*i,*aux*i*) *←.* P(aux*i−*1*,mi−*1) if *i >* 1

ii.Compute a VC commitment to the IOP string: (cm*i,*aux*i*) *←* VC*.*Commit(pp*,* Π*i*). iii.Send (cm*i,*aux*i*) to *V*.

(b) *V*’s *i*-th query.
i.Compute the *i*-th IOP verifier query set Q*i*:= Vq①*,ρ,* (ans*j*)*j<i*. ii.Send Q*i*to *P*.
(c) *P*’s *i*-th response.
i.Parse Q

|as (Q|,..., Q|), where Q|⊆ [l] is the query set of V to Π|||.||
|---|---|---|---|---|---|---|---|
|i i,1|i,i|i,j|i i|j|i,j|i i,j|j i,j|
|i i i i i i∈[k]|i,j j∈[i]|i|i,j j∈[i] i|m|j j∈[i]|||
|j≤i||j|i,j|i,j i,j||||
|q m|d|||||||
 ii.For every *j ∈* [*i*], compute pf *←* VC*.*Open(pp*,*aux*, Q*) and set ans := Π [*Q*].
iii.Set ans := (ans) and pf := (pf). iv.Send (ans*,*pf) to *V*.

(d) *V*’s *i*-th message.
i.Compute the *i*-th IOP verifier message *m* := V ①*,ρ,* (ans). ii.Send *m* to *P*.
3. *V*’s decision: Check if the following hold:
(a) Vd①*,ρ,* (ans) = 1.
V

(b)For every *i ∈* [k], VC*.*Check(pp*,*cm*, Q,*ans*,*pf). Above, we use V*,* V and V to denote the query, message and decision algorithms, respectively, for
the IOP verifier V.

The protocol has 2k rounds: Each round of the IOP needs two rounds to simulate because V’s message in the *i*-th round depends on the answers to the queries in the *i*-th round. We comment on the protocol’s efficiency measures:

•the generator communication to prover and verifier consists of *|*ppVC*|* bits; P P •the prover-to-verifier communication consists of (*|*cm*i|* + q *·* (log l*i*+ log*|*Σ*|*) + *|*pf*i,j|*) bits; P*i∈*[k] *j≤i* •the verifier-to-prover communication consists of *|mi|* + q *·* log l*i*bits; *i∈*[k] •the time complexity of the argument generator is *t*VC*.*Gen. <u>k·(k+1)</u> •the time complexity of the argument prover is *t*P+ k *· t*VC*.*Commit+ *· t*VC*.*Open; 2 <u>k·(k+1)</u> •the time complexity of the argument verifier is *t*V+ *· t*VC*.*Check. 2

### 6.2 Random continuation samplers

**Definition 6.3** (IOP transcript and partial execution)**.** *An* **IOP (interaction) transcript** tr **for a public-query** **IOP** *has the following form:* tr :=*.*

||||(Q, ans|,m )|
|---|---|---|---|---|
||||i|i i i∈[k]|
||||i||
|i|j|j j j<i|i||
|i|j|j j j≤i|||

*For every i ∈* [k]*, a* **partial IOP transcript** tr **for a public-query IOP** *has one of the following forms:*

- tr := (Q*,*ans*,m*)*,*(Q*i,*ans)*;*
- tr := (Q*,*ans*,m*) *for i <* k*.*

r *For every IOP prover* Pe*, auxiliary input* ai*, verifier randomness ρ ∈{*0*,*1*}, and integer i ∈* [k]*, the* *i***-round partial execution of the IOP with respect to** (Pe (ai)*,ρ*)*, denoted by* Pe (ai)*,*V(*ρ*)*, is* *i*

Pe (ai)*,*V(*ρ*) := (①*,*tr*i*)*,* *i*

*where* ① *and the partial IOP transcript* tr*i*= (Q*j,*ans*j,mj*)*,*(Q*i,*ans*i*) *are obtained via the* *j<i* *experiment*   (①*,*aux₀) *←* Pe (ai)  (Q₀*,m₀*) := (*⊥, ⊥*)      *For* 1 *≤ j < i* :     (Πe*j,*aux )*j←* Pe (aux*j−*1*,* Q*j−*1*,mj−*1)   

||Q ← V ①,ρ, (ans||)|||
|---|---|---|---|---|---|
||j j j i i i i||ℓ ℓ<j ℓ ℓ≤j ℓ ℓ≤j i−1 i−1 j j<i j j≤i|j i−1 i||
|j j∈[i]|i|j i,j|j∈[i]|i,j|j∈[i]|

 *j ℓ ℓ<j*  *,*  ans := GetAnswers (Πe)*,* Q     *m ←* V ①*,ρ,* (ans)     (Πe*,*aux) *←* Pe (aux*,* Q*,m*)     Q *←* V ①*,ρ,* (ans) 

### ans := GetAnswers (Πe), Q

*and* GetAnswers (Π)*,* Q *denotes* (Π [*Q*]) *where* (*Q*) = Q*i.*

**Definition 6.4** (ARG transcript and partial execution)**.** *An* **ARG (interaction) transcript** tr **for a public-** **query IOP based argument system** *has the following form:*

tr := (cm*i,* Q*i,*ans*i,*pf*i,mi*)*.* *i∈*[k]

*Similarly, for every i ∈* [k]*, a* **partial ARG transcript** tr*ihas one of the following forms:*

- tr*i*:= (cm*j,* Q*j,*ans*j,*pf*j,mj*)*,*(cm*i,* Q*i,*ans*i,*pf*i*)*;*
*j<i*

- tr*i*:= (cm*j,* Q*j,*ans*j,*pf*j,mj*) *for i <* k*.*
*j≤i*

r *For all public parameters* pp*, argument prover P*e*, auxiliary input* ai*, verifier randomness ρ ∈{*0*,*1*},* *and integer i ∈* [k]*, the i***-round partial execution of** ARG **with respect to** (pp*, P*e(ai)*,ρ*)*, denoted by* *P*e(ai)*, V*(*ρ*)*, is* *i* *P*e(ai)*, V*(*ρ*) := (①*,*tr*i*)*,* *i* *where* ① *and the partial ARG transcript* tr*i*= (cm*j,* Q*j,*ans*j,*pf*j,mj*)*,*(cm*i,* Q*i,*ans*i,*pf*i*) *are* *j<i* *obtained via the experiment*   (①*,*aux₀) *← P*e(pp*,*aux)  (Q₀*,m₀*) := (*⊥, ⊥*)     *For* 1 *≤ j < i* :      (cm*j,*aux )*j← P*e(aux*j−*1*,* Q*j−*1*,mj−*1)   

|Q ←V (①,ρ, (ans||) )|||
|---|---|---|---|---|
|j||ℓ ℓ<j|||
|j j|j j|ℓ ℓ∈[j]|j j||
|i i||i−1|i−1 i−1||
|i||j j<i|||
|i i|i||i||

 *j ℓ ℓ<j*  *.*  (ans*,*pf*,*aux) *← P*e(aux*,* Q)     *m ←V*(①*,ρ,* (ans))     (cm*,*aux) *← P*e(aux*,* Q*,m*)     Q *←V*(①*,ρ,* (ans)) 

### (ans,pf,aux) ← Pe(aux, Q)

**Definition 6.5.** *For every IOP prover* Pe *and IOP prover auxiliary input* ai*, a partial IOP execution* (①*,*tr*i*) *has* **non-zero measure with respect to** Pe (ai) *if* h i Pr (①*,*tr*i*) = Pe (ai)*,*V(*ρ*) *i* *ρ ←{*0*,*1*}* r *>* 0*.*

*A partial execution for* ARG *with non-zero measure is defined similarly.*

**Definition 6.6.** *Consider* IOP = (P*,*V) *with randomness complexity* r*. For any partial IOP execution* (①*,*tr*i*)*, we define* R(①*,*tr *i* ) *,* **the set of random strings consistent with** (①*,*tr)*, as follows:*

n o

|R|:=|e (ai), V(ρ) : P|= tr|
|---|---|---|---|
|(①,tr|) i|r (①,tr)|i i|

*i* *ρ ∈{*0*,*1*}.*

*For a partial argument execution* tr*, we define* R *i* *analogously.*

For simplicity, we often drop the instance ① (which is fixed by Pe (aux)) and refer to a partial transcript tr*i*with non-zero measure, or a set Rtr*i*of random strings consistent with tr*i*.

**Definition 6.7** (IOP random continuation sampler)**.** *Let* IOP *be a public-query IOP with round complexity* k*,* *and let* S *be a probabilistic algorithm with the following syntax:*

- *On input* (①*,*tr*i*) *where* tr*i*= (Q*j,*ans*j,mj*)
*j<i* *for i ∈* [k]*,* S *outputs a query set* Q*i;*

- *On input* (①*,*tr*i*) *where* tr*i*= (Q*j,*ans*j,mj*)
*j<i* *,*(Q*i,*ans*i*)*,* S *outputs a message mi.*

*Given α ≥* 0 *and t*S*∈* N*, we say* S *is an* **IOP random continuation sampler (IOP-RCS) with error** *α* **and** **running time** *t*S*if it satisfies the following guarantee: for every size bound t*IOP*, t*IOP*-size circuit* Pe*, IOP* *prover auxiliary input* ai*, i ∈* [k]*, and partial IOP execution* (①*,*tr*i*) *that has non-zero measure with respect* *to* (Pe*,*ai)*, we have* h i h i ∆ *D* Pe (ai)*,*S(①*,*tr*i*)*, U* Pe (ai)*,* R(①*,*tr *i* )= *α ,*

*where*

- ∆ (*·, ·*) *is the statistical (total variation) distance between two distributions;* h i
- *D* Pe (ai)*,*S(①*,*tr*i*) *is the distribution of IOP transcripts produced by* S*:*
  (①*,*aux₀) *←* Pe (ai)  (Q*,m*) := (*⊥, ⊥*)   0 0     *For* 1 *≤ j ≤ i* :   e e   (Π*j,*aux*j*) *←* P(aux*j−*1*,* Q*j−*1*,mj−*1)  h i   *m ←* S(①*,*tr )   e (ai) *i i*  *D* P*,*S(①*,*tr*i*) :=   (Q*j* *,*ans*j,mj*) *j∈*[k] *For i < j ≤* k : ;    (Πe *j* *,*aux*j*) *←* Pe (aux*j−*1*,* Q*j−*1*,mj−*1)    

||Q ← S ①,|(Q, ans ,m )|||
|---|---|---|---|---|
||j j j||ℓ ℓ ℓ ℓ≤j ℓ ℓ|ℓ<j j ℓ<j j|

*j*  *ℓ ℓ ℓ*  e   ans := GetAnswers (Π)*,* Q  *m ←* S ①*,* (Q*ℓ,*ans*,m*)*,*(Q*,*ans*j*)

h i

- *U* Pe (ai)*,* R(①*,*tr
*i* )*is the uniform distribution over all complete IOP transcripts consistent with* (①*,*tr*i*)*:* 33

  (①*,*aux₀) *←* Pe (ai)  *ρ ←* R   (①*,*tr*i*)   (Q*,m*) := (*⊥, ⊥*)   0 0  h i  *For j ∈* [k] :  e (ai)  

|:=  (Q|,m )|||||
|---|---|---|---|---|---|
|(①,tr)|j j j∈[k]|j j j j|j q m|j−1 ℓ ℓ<j ℓ ℓ∈[j] ℓ ℓ∈[j]|j−1 j−1 j|

*U* P*,* R *ij* *,*ans e e *.*  (Π*,*aux) *←* P(aux*,* Q*,m*)     Q *←* V ①*,ρ,* (ans)     ans := GetAnswers (Πe)*,* Q  *m ←* V ①*,ρ,* (ans)

**Definition 6.8** (ARG random continuation sampler)**.** *Let* ARG *be an argument system with round complexity* 2k *that follows the same message structure as defined in Construction 6.2, and let S be a probabilistic* *algorithm with the following syntax.*

- *On input* (pp*,* ①*,*tr*i*) *where* tr*i*= (cm*j,* Q*j,*ans*j,*pf*j,mj*)
*j<i* *,*cm*ifor i ∈* [k]*, S outputs* Q*i*+1*;*

- *On input* (pp*,* ①*,*tr*i*) *where* tr*i*:= (cm*j,* Q*j,*ans*j,*pf*j,mj*)
*j<i* *,*(cm*i,* Q*i,*ans*i,*pf*i*)*, S outputs mi.*

*Given α ≥* 0 *and tS∈* N*, S is an* **ARG random continuation sampler (ARG-RCS) with error** *α* **and** **running time** *tSfor* ARG *if it satisfies the following guarantee: for every size bound t*ARG*, t*ARG*-size circuit* *P* e*, ARG prover auxiliary input* ai*, public parameter* pp*, i ∈* [k]*, and partial ARG execution* (①*,*tr *i* ) *that has* *non-zero measure with respect to P*e(ai)*, we have* h i h i ∆ *D P*e(ai)*, S*(pp*,* ①*,*tr*i*)*, U P*e(ai)*,* R(①*,*tr *i* )= *α ,*

*where* h i

- *D P*e(ai)*, S*(pp*,* ①*,*tr*i*) *is a distribution of ARG transcripts produced by S:* h i *D P*e(ai)*, S*(pp*,* ①*,*tr*i*)  
(①*,*aux₀) *← P*e(pp*,*aux)  (Q₀*,m₀*) := (*⊥, ⊥*)     *For* 1 *≤ j ≤ i* :     e   (cm*j,*aux*j*) *← P*(aux*j−*1*,* Q*j−*1*,mj−*1)     *mi←S*(pp*,* ①*,*tr )*i*  :=  (cm*j,* Q*j,*ans*j,*pf*j,mj*) *j∈*[k] ;  *For i < j ≤* k :   e   (cm*j,*aux*j*) *← P*(aux*j−*1*,* Q*j−*1*,mj−*1)     Q *j←S*(pp*,* ①*,* (cm*ℓ,* Q*ℓ,*ans*ℓ,*pf*ℓ,mℓ*))*ℓ<j*     (ans *j* *,*pf*,*aux*j*) *← P*e(aux*j,* Q*j*)  *j*

|||||m ←S(pp,|(cm|, Q, ans|, pf ,m|)), (Q|, ans|, pf )|
|---|---|---|---|---|---|---|---|---|---|---|
|Note that we run the malicious IOP prover and the IOP verifier from scratch in the experiment. Alternatively, one may break it into two parts as in D|h P e (ai), S(①, tr||i ) : rounds 1 ≤ j ≤ i and i + 1 ≤ j ≤ k. We opt for the more concise notation.|j||ℓ ℓ ℓ|ℓ ℓ|ℓ<j|j|j j|

*j ℓ ℓ ℓ ℓ ℓ ℓ<j j j j* 33

*i*

h i

- *U P*e(ai)*,* R(①*,*tr
*i* )*is the uniform distribution over all complete ARG transcripts consistent with* tr*i:*

  (①*,*aux₀) *← P*e(pp*,*aux)  *ρ ←* R   (①*,*tr*i*)   (Q*,m*) := (*⊥, ⊥*)   0 0  h i  *For j ∈* [k] :  e(ai)   *U P,* R(①*,*tr *i* ):=  (cm*j,* Q*j,*ans*j,*pf*j,mj*)*j∈*[k] e *.*  (cm*j,*aux*j*) *← P*(aux*j−*1*,* Q*j−*1*,mj−*1)     Q*j←V*(①*,ρ,* (ans*ℓ*)*ℓ<j*)   

||||(ans, pf|, aux|e(aux ) ← P|, Q| )|
|---|---|---|---|---|---|---|---|
||||j j|j|j ℓ ℓ∈[j]|j j||

 *j j j j* *m ←V*(①*,ρ,* (ans))

### 6.3 Equivalence of IOP-RCS and ARG-RCS

We now show that an IOP-RCS exists if and only if a corresponding ARG-RCS exists.

**Lemma 6.9** (IOP sampler to ARG sampler)**.** *For every α ≥* 0 *and t*S*∈* N*, if* IOP *has an IOP-RCS with* *error α and running time t*S*, then* Finale[IOP*,*VC] *admits an ARG-RCS S with error α and running time* *t* *S*= *O*(*t*S)*.*

*Proof.* We first define the ARG random continuation sampler *S* from its IOP analogue S the natural way:

*S*(pp*,* ①*,*tr*i*):

1.Set tr*i*:= (Q*j,*ans*j,mj*)
*j<i* if tr*i*= (cm*j,* Q*j,*ans*j,*pf*j,mj*) *j<i* *,*cm*i*.

|:=|(Q, ans|,m )|, ans )|if tr = (cm|, Q, ans|, pf|,m ), (cm|, Q, ans|, pf ).|
|---|---|---|---|---|---|---|---|---|---|
|i|j|j j j<i|i i|i|j j|j j|j j<i|i i|i i|
||i|||||||||

2. Set tr*,*(Q
3.Output S(①*,*tr). It is clear from construction that *S* has running time *O*(*t*S). Moreover, since the argument verifier’s
messages in Construction 6.2 *only depend on the query sets and IOP prover answers* (*V* replies with the messages of V; an invalid opening interferes with the decision, but not the communication), the error of *S* <u>is</u> exactly *α*, the error of S.

We now show that given an ARG random continuation sampler, we can construct an IOP random continuation sampler.

**Lemma 6.10** (ARG sampler to IOP sampler)**.** *For every α ≥* 0 *and tS∈* N*, if* Finale[IOP*,*VC] *has an* *ARG-RCS with error α and running time tS, then* IOP *admits an IOP-RCS* S *with error α and running time* *t* S= *O*(*tS*)*.*

*Proof.* Note that the apparent difficulty is caused by the fact that IOP transcripts do not contain vector commitments nor VC openings, but to run the ARG-RCS, one needs to supply the commitments and openings as inputs. However, we observe (as we did above) that the argument verifier’s messages in Construction 6.2 are independent of the commitments and VC openings. Therefore, these are only syntactic requirements that an arbitrary sequence of strings can fulfil; in particular, it suffices for the ARG-RCS to receive empty strings as commitments and VC openings:

S(①*,*tr*i*):

1.Set tr*i*:= (*⊥,*Q*j,*ans*j, ⊥,mj*)
*j<i* *, ⊥* if tr*i*= (Q*j,*ans*j,mj*) *j<i*.

|, ans, ⊥,m|), (⊥, Q|, ans, ⊥)|, ans ,m|), (Q|, ans ).|
|---|---|---|---|---|---|
|j j i|j j<i|i i|j j|j j<i|i i|

2. Set tr*i*:= (*⊥,*Q if tr*i*= (Q
3.Output *S*(*⊥,*①*,*tr).
It is again clear from construction and definition of *S* that S has running time *O*(*tS*) and error *α*.

### 6.4 Security reduction

We show that given a random continuation sampler for IOP (or, equivalently, a random continuation sampler for ARG), a security reduction claim similar to Lemma 5.4 can be shown.

**Lemma 6.11.** *Assume there is an ARG-RCS S with error α and running time tS. There exist a probabilistic* *algorithms R which, for every ϵ >* 0*, size bound t*ARG*≥ t*V+ *t*VC*.*Check+ log*|*Σ*|*+ log lmax*, and t*ARG*-size circuit* *P*e*, satisfy*

  ([*Q*e*i,*Πe*i*])*i∈*[k] V (①;*ρ*) *̸*= 1  ([*Q ,i*ans])*i i∈*[k] Pr  *∧* V ①;*ρ* = 1  V V *∧* VC*.*Check(pp*,*cm*j, Qi,j,*ans*i,j,*pf*i,j*) *i∈*[k] *j≤i* <u>l · α</u> *≤ ϵ*VC(*λ,*lmax*,* qmax*,t*VC) + *ϵ* +*,* *ϵ*

*with respect to*   *λ* pp *←G*(1*,n*)  ai  *←D*    (①  *,*aux )0*← P*e(pp*,*ai)  r  *ρ ←{*0*,*1*}*    (5)  (cm*i,* Q*i,*ans*i,*pf*i,mi*) *← P*e(aux₀)*, V*(①;*ρ*)  *i∈*[k]   *For i ∈* [k] :    

||e(①, aux|, Q|,m|||
|---|---|---|---|---|---|
|i i||i−1|i−1 i−1|||
|i i|P e(aux ,·)||j j≤i|j j|j j<i|

 (cm*,*aux ) *← P*)  (*Q*e*,* Πe) *←Ri*pp*,* ①*,*(cm)*,* (Q*j,*ans*,*pf*,m*)*,ϵ*

<u>k·l</u> *where t*VC= *O ·* (*t*ARG+ *t*S)*.* *ϵ*

### The reductor is defined as follows:

- *R*post(*K,* l):
l

1.Initialize Πe := (*σ*), where *σ* is an arbitrary symbol in Σ.
2.For all (*Q,* ans*,*pf) *∈K* and *q ∈Q*: Set Π[e *q*] := ans[*q*].
S

3.Set *Q*e := *Q*.
(*Q,*ans)*∈K*

|4.Output (Q|e, Π) e.|||||
|---|---|---|---|---|---|
|P e(aux Note that, when i = 1 (i.e., when the second argument is ⊥) the reductor simply samples ρ and applies the functions V V as appropriate; there is no need for a sampler in this case. Equivalently, we assume S performs this trivial sampling when i = 1 and is only nontrivial when i > 1.|,·) ϵl|j j≤i ′i|j i|j j|j j<i|

- *Ri*pp*,* ①*,*(cm)*,* (Q*,*ans*,*pf*,m*)*,ϵ* :34
1.Initialize *K* = *∅*.
2.Set N := and cm := cm. 34
q and m

3.Repeat the following N times:
(a)Run Q

|←S pp, ①,|(cm, Q|, ans, pf|,m )|, cm|.|||||
|---|---|---|---|---|---|---|---|---|---|
|′i ′i ′i|ℓ ′i|ℓ ℓ i i|ℓ ℓ ℓ<i|i||||||
|′i|ℓ|ℓ ℓ|ℓ ℓ ℓ<i|′i|′i ′i|||||
|′j|′j|′j−1 ′j−1|′j−1|||||||
|′j||ℓ ℓ|ℓ ℓ|ℓ ℓ<i|′ℓ ′ℓ|′ℓ ′ℓ|′ℓ i≤ℓ<j|||
|′j|′j ′j|′j|′j|||||||
|′j|i ′j,i|ℓ ℓ ′j,i ′j,i|ℓ ℓ|ℓ ℓ<i ′j,i|′ℓ ′ℓ ′j,i ′j,i|′ℓ ′ℓ 35|′ℓ i≤ℓ<j|′j ′j|′j|
|i i|i|||||||||

(b)Run (ans*,*pf*,*aux) *← P*e(aux*,* Q).
(c)Run *m ←S* pp*,* ①*,* (cm*,* Q*,*ans*,*pf*,m*)*,*(Q*,*ans*,*pf).
(d)For *i < j ≤* k:
i.Run (cm*,*aux) *← P*e(aux*,* Q*,m*). ii.Run Q *←S* pp*,* ①*,* (cm*,* Q*,*ans*,*pf*,m*)*,* (cm*,* Q*,*ans*,*pf*,m*).
iii.Run (ans*,*pf*,*aux) *← P*e(aux*,* Q). iv. Run*m ←S* pp*,* ①*,* (cm*,* Q*,*ans*,*pf*,m*)*,* (cm*,* Q*,*ans*,*pf*,m*)*,*(Q*,*ans*,*pf).

v.If VC*.*Check(cm*, Q,*ans*,*pf) = 1, add (*Q,*ans*,*pf) to *K*.
4.Output (*Q*e*,* Πe) *←R*post(*K,*l).
*Proof.* Throughout the proof, probabilistic expressions are with respect to the experiment in Eq. 5. Our goal is to upper bound the following expression:

  ([*Q*e*i,*Πe*i*])*i∈*[k] V (①;*ρ*) *̸*= 1  ([*Q ,i*ans])*i i∈*[k] Pr  *∧* V ①;*ρ* = 1 *.* V V *∧* VC*.*Check(pp*,*cm*j, Qi,j,*ans*i,j,*pf*i,j*) *i∈*[k] *j≤i*

Similar to the proof of Lemma 5.9, the above even implies either there are valid openings with disagreeing answers or there is a missing query in one of the IOP strings. We analyze them separately.

**Valid openings with disagreeing answers.** We show that   *∃ i ∈* [k]*,j ∈* [*i,* k]*,q ∈Qj,i∩ Q*e*i* Pr  *∧* Πe*i*[*q*] *̸*= ans*j,i*[*q*]  *≤ ϵ*VC(*λ,*lmax*,* qmax*,t*VC) *∧*VC*.*Check(pp*,*cm*i, Qj,i,*ans*j,i,*pf*j,i*) = 1

<u>k·l</u> where *t*VC= *O ·* (*tS*+ *t*ARG). *ϵ* We define a VC adversary *A*VCas before:

*A*VC(pp*,*ai):

1.Run (①*,*aux₀) *← P*e(pp*,*ai).
r

2.Sample *ρ ←{*0*,*1*}*.
3.Run ((cm*i,* Q*i,*ans*i,*pf*i,mi*))*i∈*[k]*← P*e(aux₀)*, V*(pp*,* ①*,ρ*).
4.For every *i ∈* [k]:
(a)Run (cm*i,*aux*i*) *← P*e(aux*i−*1*,* Q*i−*1*,*ans*i−*1).
*P*e(aux*i,·*)

(b)Run *K*

|←R||pp, ①, (cm )|,|(Q, ans ,m )|,ϵ.|
|---|---|---|---|---|---|
|i|P e(aux ,·)||j j≤i|j j i|j j<i j,i|
|j,i|j,i|j,i||||

5. If there exists *i ∈* [k], *j ∈* [*i,* k], and (*Q,* ans*,*pf) *∈K* with *q ∈Q ∩Q* and ans*j,i*[*q*] *̸*= ans[*q*], output (cm*i,*ans*,*ans*, Q, Q,* pf*,*pf).
6.Otherwise, output (the “dummy” tuple) (cm₁*,*ans₁*,*ans₁*, Q₁, Q₁,*pf₁*,*pf₁).
Note that in *A*VC, we output *K* when invoking *R*. This is a notational overload where we partially execute <u>k·l</u> *R* without calling *R*post. The time complexity of *A*VCis *O ·* (*tS*+ *t*ARG). Therefore, according to *ϵ* 35 Note the order of indices: in order to fill in the *i*-th IOP proof, the reductor uses the *i*-th query sets and answers of all rounds *j > i* (i.e., all *Qj,i* and ans*j,i*).

|, Q|, ans|, pf ) = 1||
|---|---|---|---|
|i|j,i j,i|j,i||
|′|||λ|
|′||′||
||′ ′|′|′ ′|



  

For this case, we rely on the property of ARG-RCS. In particular, according to Definition 6.8, the ARG is statistically close to the “ideal” distribution of ARG verifier’s

ˆ works. In particular, *R*

Definition 3.8,   *∃ i ∈* [k]*,j ∈* [*i,* k]*,q ∈Qj,i∩ Q*e*i* Pr  *∧* Πe*i*[*q*] *̸*= ans*j,i*[*q*]  *∧*VC*.*Check(pp*,*cm*i j,i j,i j,i*  *|Q|* = *|Q |≤* q pp *←* VC*.*Gen(1*,* lmax)  *∧∃ q ∈Q∩Q* : ans[*q*] *̸*= ans [*q*] ai *←D* *≤* Pr   *∧* VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 cm*,*ans*,*ans*,* *′← A*VC(pp) *∧* VC*.*Check(pp*,*cm*, Q,*ans*,*pf) = 1 *Q, Q,*pf*,*pf

### ≤ ϵVC(λ,lmax, qmax,tVC).

**Missing positions in** Πe*i***.** We show that h i <u>α</u> Pr *∃ i ∈* [k]*,j ∈* [*i,* k]*,q ∈Qj,i\ Q*e*i≤ ϵ* + 2l *·.* *ϵ*

verifier’s next message in tr*i*sampled by *S* next message, namely the ARG execution with respect to verifier randomness in R(①*,*tr *i* ). h i We first define the following *ideal reductor R*ˆ with respect to *U P*e(ai)*,* R(①*,*tr *i* ) as if there were a perfect ARG-RCS as in the public-coin case:

*R* ˆ*Pi,·*)pp*,* ①*,*(cm *j* ) *j≤i,* (Q*j,*ans*j,*pf*j,mj*)*j<i,ϵ* : e(aux

1.Initialize *K* := *∅* and set N :=
*ϵ* <u>l</u>.

2.Repeat the following N times:
(a)Sample *ρ ←* R((cm
*j* *,*Q*j,*ans*j,*pf*j,mj*))*j<i*.

(b)Run Q*i←V*(①*,ρ,* (ans*j*)*j<i*).
(c)Run (ans*i,*pf*i,*aux*i*) *← P*e(aux*i,* Q*i*).
(d)Run *mi←V*(①*,ρ,* (ans*j*)*j∈*[*i*]).
(e)For *i < j ≤* k:
i.Run (cm*,*aux
*′j* ) *← P*e(aux*j−*1*,mj−*1). ii.Run Q*j←V*(①*,ρ,* (ans*ℓ*)*ℓ<j*). iii.Run (ans*j,*pf*j,*aux*j*) *← P*e(aux *′j* *,* Q*j*). iv.Run *mj←V*(①*,ρ,* (ans*ℓ*)*ℓ∈*[*j*]).

(f)If VC*.*Check(cm*i, Qj,i,*ans*j,i,*pf*j,i*) = 1, add (*Qj,i,*ans*j,i,*pf*j,i*) to *K*.
3.Output (*Q*ˆ*i,* Πˆ*i*) *←R*post(*K,*l*i*). We can adapt the proof of Lemma 5.4 to bound the following probability: *λ*
pp *←G*(1*,n*)  ai *←D*   (①*,*aux₀) *← P*e(pp*,*ai)   *ρ ←{*0*,*1*}* r  ˆ Pr *∃ i ∈* [k]*,j ∈* [*i,* k]*,q ∈Qj,i\ Qi* e

|, Q, ans|, pf ,m|)) ←|P (aux₀), V (pp, ①,ρ)|||
|---|---|---|---|---|---|
|j j|j j j|j∈[k]||||
|i i|i−1|i−1|i−1|||
|i i|P e(aux ,·)||j j≤i|j j|j j<i|

 ((cm   For *i ∈* [k] :  e  (cm*,*aux) *← P*(aux*,* Q*,m*) ˆ ˆ ˆ *i* (*Q,* Π) *← R* pp*,* ①*,*(cm)*,* (Q*j,*



      *.*      ans*,*pf*,m*)*,ϵ*

(6)

Fix prover auxiliary input ai, public parameters pp and a partial transcript tr (cm*j*

||||=|, Q, ans|, pf ,m|)|
|---|---|---|---|---|---|---|
||||i|j j|j|j j<i|
|||||i|||
|i||||tr (①,tr|)||
|)|ℓ∈[j]|ℓ j,ℓ|j,ℓ j,ℓ|j|j j|j j∈[k]|
||i||||||

that has non-zero measure with respect to *P*e(ai), we define the *weight* of a coordinate *q ∈* [l] with respect to (pp*,*ai*,*tr) as   *ρ ←* R *∃ j ∈* [*i,* k] : *q ∈Qj,ii*   *δ* V V e(pp*,* ①*,ρ*) (pp*,*ai*,*tr*i*(*q*) := Pr  *b ←− P,*ai)*, V*(pp *.* *∧* VC*.*Check(pp*,*cm*, Q,*ans*,*pf) *j∈*[k] (cm*,*ans*,*pf*,m*) := tr

A union bound over all *q ∈* [l] yields *λ* pp *←G*(1*,n*)  ai *←D*     (①*,*aux₀) *← P*e(pp*,*ai)     r  *ρ ←{*0*,*1*}*   Pr *∃ j ∈* [*i,* k]*,q ∈Qj,i*: *q /∈ Q*ˆ*i* e   ((cm*j,* Q*j,*ans*j,*pf*j,mj*))*j∈*[k]*← P*(aux₀)*, V*(pp*,* ①*,ρ*)     For *j ∈* [k] :     (cm*j,*aux*j*) *← P*e(aux*j−*1*,* Q*j−*1*,mj−*1)  *P*e(aux*j,·*)

|||||ˆ ˆ (Q, Π ) ← R|ˆ|pp, ①, (cm|),|(Q, ans|, pf ,m|) ,ϵ|
|---|---|---|---|---|---|---|---|---|---|---|
|||||j j|P e(aux|,·) (①,tr|ℓ ℓ≤j )|ℓ|ℓ ℓ|ℓ ℓ<j|
|||||||tr|||||
|(pp,ai,tr|)||i|j,i|i|j|j j|j j∈[k]|||
||||||N||||||
|(pp,ai,tr i|) q∈[l|(pp,ai,tr]|)|)|||||||

    *ρ ←* R   *i*    *≤* max Pr *∃ q ∈* [l]*,j ∈* [*i,k*] : *q ∈Q ∧ q /∈ Q*e *b ←−⟨P*e(pp*,*ai)*, V*(pp*,ρ*)*⟩*  *i*  (cm*,*ans*,*pf*,m*) := tr    X  *≤* max *δ* (*q*) *·* (1 *− δ*(pp*,*ai*,*tr(*q*)) *i i* *i*  *i* <u>l</u> *≤,* N

and another union bound over *i ∈* [k] gives *λ* pp *←G*(1*,n*)  ai *←D*     (①*,*aux₀) *← P*e(pp*,*ai)     r  *ρ ←{*0*,*1*}*   Pr *∃ i ∈* [k]*,j ∈* [*i,* k]*,q ∈Qj,i*: *q /∈ Q*ˆ*i* e   ((cm*i,* Q*i,*ans*i,*pf*i,mi*))*i∈*[k]*←⟨P*(aux₀)*, V*(pp*,*①;*ρ*)*⟩*     For *i ∈* [k] :    (cm e 

||, aux ) ← P (①, aux||, Q|,m )|||
|---|---|---|---|---|---|---|
|i i∈[k]|i i i i|P e(aux ,·)|i−1|i−1 i−1 j j≤i j,i|j j i|j j j<i|

(*Q*ˆ*,* Πˆ) *← R*ˆ *i*pp*,* ①*,*(cm)*,* (Q*,*ans*,*pf*,m*)*,ϵ*

X <u>l l</u> *≤* =*.* N N

h i It remains to show the connection between Eq. 6 and Pr *∃ i ∈* [k]*,j ∈* [*i,* k]*,q ∈Q* : *q /∈ Q*e. Accord- ing to Definition 6.8, h i h i ∆ *D P*e(ai)*, S*(pp*,* ①*,*tr*i*)*, U P*e(ai)*,* R(①*,*tr)= *α .* *i*

Therefore, for any N *∈* N,

h iNh iN ∆ *D P*e(ai)*, S*(pp*,* ①*,*tr*i*)*, U P*e(ai)*,* R(①*,*tr )= N *· α .* *i*

Consider the following distribution:  

             (Q *.* *, Q*ˆ*i,* Πˆ*i*) *i*  *i∈*[k]            *,mj*) *,ϵ* *j<i*

We can rewrite it equivalently in terms of

*,*Q*ℓ,*ans *ℓ*



          (Q *i* *, Q*ˆ*i,* Πˆ*i*)  *i∈*[k]        



          ˆ ˆ = ((Q*i, Qi,* Π*i*))*i∈*[k]         

*λ* pp *←G*(1*,n*) ai *←D* (①*,*aux ) *← P*e(pp*,*ai) 0 r *ρ ←{*0*,*1*}* e (cm*i,* Q*i,*ans*i,*pf*i,mi*) *i∈*[k] *← P*(aux₀)*, V*(pp*,* ①*,ρ*) For *i ∈* [k] : (cm*,*aux ) *← P*e(①*,*aux*,* Q*,m*) *i i i−*1 *i−*1 *i−*1 ˆ ˆ ˆ*P* e (aux*i,·*) (*Qi,* Π*i*) *← R* pp*,* ①*,*(cm*j*)*j≤i,* (Q*j,*ans*j,*pf*j*

h iN *U P*e(ai)*,* R(①*,·*):

*λ* pp *←G*(1*,n*) ai *←D* (①*,*aux₀) *← P*e(pp*,*ai) *ρ ←{*0*,*1*}* r e (cm*i,* Q*i,*ans*i,*pf*i,mi*) *i∈*[k] *← P*(aux₀)*, V*(pp*,* ①*,ρ*) For *i ∈* [k] : For *j ∈* [N] : h e ((cm*j,ℓ,* Q*j,ℓ,*ans*j,ℓ,*pf*j,ℓ,mj,ℓ*))*ℓ∈*[k]*←U P*(ai)*,* R(((cm

(*Qj,ℓ,i,*ans*j,ℓ,i,*pf*j,ℓ,i*) : *j ∈* [N]*,i ≤ ℓ ≤* k*,* *Ki*:= VC*.*Check(pp*,*cm*j,i, Qj,ℓ,i,*ans*j,ℓ,i,*pf) = 1 *j,ℓ,i* (*Q*ˆ*i,* Πˆ*i*) *←R*post(*Ki,* l*i*)

pp *←G*(1 *λ* *,n*) ai *←D* e (①*,*aux₀) *← P*(pp*,*ai) r *ρ ←{*0*,*1*}* e (cm*i,* Q*i,*ans*i,*pf*i,mi*) *← P*(aux₀)*, V*(pp*,* ①*,ρ*) *i∈*[k] For *i ∈* [k] : ((cm*,* Q*,*ans*,*pf*,m*)) *j,ℓ* h *j,ℓ j,ℓ j,ℓ j,ℓ j∈*[N]*,ℓ∈*[k] iN *← U P*e(ai)*,* R(((cm *j* *,*Q*j,*ans*j,*pf*j,mj*))*j<i,*cm*i*) (*Qj,ℓ,i,*ans*j,ℓ,i,*pf*j,ℓ,i*) : *j ∈* [N]*,i ≤ ℓ ≤* k*,* *Ki*:= VC*.*Check(pp*,*cm*j,i, Qj,ℓ,i,*ans*j,ℓ,i,*pf*j,ℓ,i*) = 1 (*Q*ˆ*i,* Πˆ*i*) *←R*post(*Ki,* l*i*)



          *.*         



            i   *ℓ* *,*pf*ℓ,mℓ*))*ℓ<i,*cm*i*)    

Similarly, we can write   *λ* pp *←G*(1*,n*)   ai *←D*      (①*,*aux )0*← P*e(pp*,*ai)  r  *ρ ←{*0*,*1*}*  ((Q*, Q*e*i,* Πe*i*))*i∈* *i* [k](cm*i,* Q*i,*ans*i,*pf*i,mi*) *← P*e(aux₀)*, V*(pp*,* ①*,ρ*)  *i∈*[k]   For *i ∈* [k] :    

||||e(①, aux|, Q|,m|||
|---|---|---|---|---|---|---|---|
|||i i i i|P e(aux ,·)|i−1|i−1 i−1 j j≤i|j j|j j<i|
|||N||||||

 (cm*,*aux ) *← P*)  (*Q*e*,* Πe) *←Ri*pp*,* ①*,*(cm)*,* (Q*j,*ans*,*pf*,m*)*,ϵ*

h i in terms of *D P*e(ai)*, S*(pp*,* ①*, ·*) :

  *λ* pp *←G*(1*,n*)    ai *←D*    (①*,*aux₀) *← P*e(pp*,*ai)   r  *ρ ←{*0*,*1*}*   

|||, Q, ans|, pf ,m|) ←|
|---|---|---|---|---|
|||i i i,j i,j i,j,1|i i i i,j i,j i,j,1|i∈[k] i∈[N],j∈[k] i,j,1|
|i i|i i∈[k]|||i,1 i,j,1|

 (cm *P*e(aux₀)*, V*(pp*,* ①*,ρ*)     h iN   ((cm*,* Q*,*ans*,m*)) *← U P*e(ai)*,* Rcm1      (*Q,*ans*,*pf) : *i ∈* [N]*,*1 *≤ j ≤* k*,*   *K₁* :=  *, Q*e*,* Πe)) ((Q VC*.*Check(pp*,*cm*, Q,*ans*i,j,*1*,*pf*i,j,*1) = 1 *.*    (*Q*e₁*,* Πe₁) *←R*post(*K₁,*l₁)     For 1 *< i ≤* k :      ((cm*j,ℓ,* Q*j,ℓ,*ans*j,ℓ,*pf*j,ℓ,mj,ℓ*))*j∈*[N]*,ℓ∈*[k]   h iN  

|← D|e(ai), S(pp, ①, P||(cm, Q|, ans, pf|,m|, cm )| )|
|---|---|---|---|---|---|---|---|
|i|j,ℓ,i|j,ℓ,i|j j,ℓ,i j,i j,ℓ,i|j j j,ℓ,i|j j j,ℓ,i|j<i|i|
|i i||i i||||||

 *j j j j j j<i i*    (*Q,*ans*,*pf) : *j ∈* [N]*,i ≤ ℓ ≤* k*,*   *K* :=   VC*.*Check(pp*,*cm*, Q,*ans*,*pf) = 1  (*Q*e*,* Πe) *←R*post(*K,* l)

Therefore, we conclude that h i h i Pr *∃ i ∈* [k]*,j ∈* [*i,* k]*,q ∈Qj,i\ Q*e*i≤* Pr *∃ i ∈* [k]*,j ∈* [*i,* k]*,q ∈Qj,i\ Q*ˆ*i*+ N *· α*

<u>l</u> *≤* + N *· α ,* N h i where Pr *∃ i ∈* [k]*,j ∈* [*i,* k]*,q ∈Qj,i\ Q*ˆ*i*is with respect to the same experiment as in Eq. 6.

## Acknowledgments

Alessandro Chiesa and Ziyi Guan are partially supported by the Ethereum Foundation. We thank Fermi Ma and Julius Vering for valuable discussions and participating in early stages of this work. We thank Zijing Di for valuable feedback and comments on earlier drafts of this paper.

## References

[AC20]

[ACK22]

[AF22]

[AFR23]

[BBHMR19]

[BBHR18]

[BCG20]

[BCS16]

[BG08]

[BGTZ23]

[BIN97]

[BKKMS13]

[BS06]

[CF13]

Thomas Attema and Ronald Cramer. “Compressed Σ-Protocol Theory and Practical Application to Plug & Play Secure Algorithmics”. In: *Proceedings of the 40th Annual International Cryptology* *Conference*. CRYPTO ’20. 2020, pp. 513–543.

Thomas Attema, Ronald Cramer, and Lisa Kohl. “A Compressed Σ-Protocol Theory for Lattices”. In: *Proceedings of the 41st Annual International Cryptology Conference*. CRYPTO ’21. 2022, pp. 549–579.

Thomas Attema and Serge Fehr. “Parallel Repetition of (*k₁,...,kµ*)-Special-Sound Multi-Round Interactive Proofs”. In: *Proceedings of the 42nd Annual International Cryptology Conference*. CRYPTO ’22. 2022, pp. 415–443.

Thomas Attema, Serge Fehr, and Nicolas Resch. *A Generalized Special-Soundness Notion and its* *Knowledge Extractors*. IACR Cryptology ePrint Archive, Report 2023/818. 2023.

James Bartusek, Liron Bronfman, Justin Holmgren, Fermi Ma, and Ron D. Rothblum. “On the (In)security of Kilian-Based SNARGs”. In: *Proceedings of the 17th Theory of Cryptography Confer-* *ence*. TCC ’19. 2019, pp. 522–551.

Eli Ben-Sasson, Iddo Bentov, Yinon Horesh, and Michael Riabzev. “Fast Reed–Solomon Interactive Oracle Proofs of Proximity”. In: *Proceedings of the 45th International Colloquium on Automata,* *Languages and Programming*. ICALP ’18. 2018, 14:1–14:17.

Jonathan Bootle, Alessandro Chiesa, and Jens Groth. “Linear-Time Arguments with Sublinear Verification from Tensor Codes”. In: *Proceedings of the 18th Theory of Cryptography Conference*. TCC ’20. 2020, pp. 19–46.

Eli Ben-Sasson, Alessandro Chiesa, and Nicholas Spooner. “Interactive Oracle Proofs”. In: *Proceed-* *ings of the 14th Theory of Cryptography Conference*. TCC ’16-B. 2016, pp. 31–60.

Boaz Barak and Oded Goldreich. “Universal Arguments and their Applications”. In: *SIAM Journal* *on Computing* 38.5 (2008). Preliminary version appeared in CCC ’02., pp. 1661–1694.

Alexander R. Block, Albert Garreta, Pratyush Ranjan Tiwari, and Michal Zajac. “On Soundness Notions for Interactive Oracle Proofs”. In: (2023), p. 1256.

Mihir Bellare, Russell Impagliazzo, and Moni Naor. “Does Parallel Repetition Lower the Error in Computationally Sound Protocols?” In: *FOCS ’97*. 1997, pp. 374–383.

Eli Ben-Sasson, Yohay Kaplan, Swastik Kopparty, Or Meir, and Henning Stichtenoth. “Constant Rate PCPs for Circuit-SAT with Sublinear Query Complexity”. In: *Proceedings of the 54th Annual* *IEEE Symposium on Foundations of Computer Science*. FOCS ’13. 2013, pp. 320–329.

Eli Ben-Sasson and Madhu Sudan. “Robust locally testable codes and products of codes”. In: *Random Structures and Algorithms* 28.4 (2006), pp. 387–402.

Dario Catalano and Dario Fiore. “Vector Commitments and Their Applications”. In: *Proceedings of* *the 16th International Conference on Practice and Theory in Public Key Cryptography*. PKC ’13. 2013, pp. 55–72.

[CHMMVW20]

[CL10]

[CMS19]

[CMSZ21]

[COS20]

[CY21a]

[CY21b]

[GK96]

[GW11]

[HPWP10]

[HR22]

[KPT97]

[Kil92]

[LM19]

[LMS22]

[Mic00]

[RR22]

Alessandro Chiesa, Yuncong Hu, Mary Maller, Pratyush Mishra, Noah Vesely, and Nicholas Ward. “Marlin: Preprocessing zkSNARKs with Universal and Updatable SRS”. In: *Proceedings of the* *39th Annual International Conference on the Theory and Applications of Cryptographic Techniques*. EUROCRYPT ’20. 2020, pp. 738–768. Kai-Min Chung and Feng-Hao Liu. “Parallel Repetition Theorems for Interactive Arguments”. In: *Proceedings of the 7th Theory of Cryptography Conference*. TCC ’10. 2010, pp. 19–36. Alessandro Chiesa, Peter Manohar, and Nicholas Spooner. “Succinct Arguments in the Quantum Random Oracle Model”. In: *Proceedings of the 17th Theory of Cryptography Conference*. TCC ’19. Available as Cryptology ePrint Archive, Report 2019/834. 2019, pp. 1–29. Alessandro Chiesa, Fermi Ma, Nicholas Spooner, and Mark Zhandry. “Post-Quantum Succinct Arguments: Breaking the Quantum Rewinding Barrier”. In: *Proceedings of the 62nd Annual IEEE* *Symposium on Foundations of Computer Science*. FOCS ’21. 2021, pp. 49–58. Alessandro Chiesa, Dev Ojha, and Nicholas Spooner. “Fractal: Post-Quantum and Transparent Recursive Proofs from Holography”. In: *Proceedings of the 39th Annual International Conference* *on the Theory and Applications of Cryptographic Techniques*. EUROCRYPT ’20. 2020, pp. 769–793. Alessandro Chiesa and Eylon Yogev. In: *Proceedings of the 41st Annual International Cryptology* *Conference*. CRYPTO ’21. 2021, pp. 711–741. Alessandro Chiesa and Eylon Yogev. “Tight Security Bounds for Micali’s SNARGs”. In: *Proceedings* *of the 19th Theory of Cryptography Conference*. TCC ’21. 2021, pp. 401–434. Oded Goldreich and Ariel Kahan. “How to construct constant-round zero-knowledge proof systems for NP”. In: *Journal of Cryptology* 9.3 (1996), pp. 167–189. Craig Gentry and Daniel Wichs. “Separating Succinct Non-Interactive Arguments From All Falsifi- able Assumptions”. In: *Proceedings of the 43rd Annual ACM Symposium on Theory of Computing*. STOC ’11. 2011, pp. 99–108. Johan Hastad, Rafael Pass, Douglas Wikstr ˚ om, and Krzysztof Pietrzak. “An Efficient Parallel ¨ Repetition Theorem”. In: *Proceedings of the 7th Theory of Cryptography Conference*. TCC ’10. 2010, pp. 1–18. Justin Holmgren and Ron D. Rothblum. “Faster Sounder Succinct Arguments and IOPs”. In: *Proceedings of the 42rd Annual International Cryptology Conference*. CRYPTO ’22. 2022, pp. 474–

503. Joe Kilian, Erez Petrank, and Gabor Tardos. “Probabilistically checkable proofs with zero knowl-´ edge”. In: *Proceedings of the 29th Annual ACM Symposium on Theory of Computing*. STOC ’97. 1997, pp. 496–505. Joe Kilian. “A note on efficient zero-knowledge proofs and arguments”. In: *Proceedings of the 24th* *Annual ACM Symposium on Theory of Computing*. STOC ’92. 1992, pp. 723–732. Russell W. F. Lai and Giulio Malavolta. “Subvector Commitments with Application to Succinct Arguments”. In: *Proceedings of the 39th Annual International Cryptology Conference*. CRYPTO ’19. 2019, pp. 530–560. Alex Lombardi, Fermi Ma, and Nicholas Spooner. “Post-Quantum Zero Knowledge, Revisited or: How to Do Quantum Rewinding Undetectably”. In: *Proceedings of the 63rd Annual IEEE* *Symposium on Foundations of Computer Science*. FOCS ’22. 2022, pp. 851–859. Silvio Micali. “Computationally Sound Proofs”. In: *SIAM Journal on Computing* 30.4 (2000). Preliminary version appeared in FOCS ’94., pp. 1253–1298. Noga Ron-Zewi and Ron D. Rothblum. “Proving as fast as computing: succinct arguments with constant prover overhead”. In: *Proceedings of the 54th Annual ACM Symposium on Theory of* *Computing*. STOC ’22. 2022, pp. 1353–1363.

[RRR16] Omer Reingold, Ron Rothblum, and Guy Rothblum. “Constant-Round Interactive Proofs for Dele- gating Computation”. In: *Proceedings of the 48th ACM Symposium on the Theory of Computing*. STOC ’16. 2016, pp. 49–62.

[Val08] Paul Valiant. “Incrementally Verifiable Computation or Proofs of Knowledge Imply Time/Space Efficiency”. In: *Proceedings of the 5th Theory of Cryptography Conference*. TCC ’08. 2008, pp. 1–

18.
