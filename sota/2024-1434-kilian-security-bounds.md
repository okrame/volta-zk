# Untangling the Security of Kilian’s Protocol: Upper and Lower Bounds

*

### Alessandro Chiesa Marcel Dall’Agnol

alessandro.chiesa@epfl.ch dallagnol@princeton.edu EPFL Princeton University

### Ziyi Guan Nicholas Spooner Eylon Yogev

ziyi.guan@epfl.ch nicholas.spooner@warwick.ac.uk eylon.yogev@biu.ac.il EPFL University of Warwick & NYU Bar-Ilan University

### September 13, 2024

**Abstract**

Sigma protocols are elegant cryptographic proofs that have become a cornerstone of modern cryptography. A notable example is Schnorr’s protocol, a zero-knowledge proof-of-knowledge of a discrete logarithm. Despite extensive research, the security of Schnorr’s protocol in the standard model is not fully understood. In this paper we study *Kilian’s protocol*, an influential public-coin interactive protocol that, while not a sigma protocol, shares striking similarities with sigma protocols. The first example of a succinct argument, Kilian’s protocol is proved secure via *rewinding*, the same idea used to prove sigma protocols secure. In this paper we show how, similar to Schnorr’s protocol, a precise understanding of the security of Kilian’s protocol remains elusive. We contribute new insights via upper bounds and lower bounds.

- *Upper bounds.* We establish the tightest known bounds on the security of Kilian’s protocol in the standard model, via strict-time reductions and via expected-time reductions. Prior analyses are strict-time reductions that incur large overheads or assume restrictive properties of the PCP underlying Kilian’s protocol.
- *Lower bounds.* We prove that significantly improving on the bounds that we establish for Kilian’s protocol would imply improving the security analysis of Schnorr’s protocol beyond the current state-of-the-art (an open problem). This partly explains the difficulties in obtaining tight bounds for Kilian’s protocol. **Keywords**: succinct interactive arguments; vector commitment schemes
* This paper extends a subset of the material presented in [https://ia.cr/2023/1737](https://ia.cr/2023/1737); for that material, this paper should be used as the most up-to-date reference.

## Contents

**1 Introduction 1**

1.1 Our results. ..................................................1
1.2 Discussion. ..................................................3
1.3 Related work.................................................5
**2 Techniques 7**

2.1 Kilian’s protocol...............................................7
2.2 Soundness analysis of Kilian’s protocol...................................8
2.3 Expected-time soundness analysis of Kilian’s protocol.......................... .10
2.4 Lower bounds from the Schnorr identification scheme......................... .. .14
2.5 Knowledge soundness analysis of Kilian’s protocol. ............................17
2.6 Succinct interactive arguments with adaptive security........................... .18
**3 Preliminaries 19**

3.1 Interactive arguments.............................................19
3.2 Vector commitments. ............................................20
3.3 Probabilistically checkable proofs. .................................... .21
**4 Kilian’s protocol 23**

**5 Strict-time security analysis 24**

5.1 Security reduction .. .............................................24
5.2 Adaptive soundness. .............................................27
5.3 Adaptive knowledge soundness... .................................... .29
**6 Expected-time soundness analysis 32**

6.1 Security reduction .. .............................................32
6.2 Adaptive soundness. .............................................34
**7 Expected-time soundness analysis for PCPs with non-adaptive verifiers 38**

7.1 Security reduction .. .............................................38
**8 Lower bounds from Schnorr identification scheme 41**

8.1 Schnorr identification scheme.... .................................... .41
8.2 From Kilian to Schnorr............................................42
8.3 Lower bound from discrete logarithm assumption..............................45
8.4 Lower bound from expected-time discrete logarithm assumption..................... .46
**Acknowledgments 47**

**References 47**

## 1 Introduction

Sigma protocols are a fundamental class of cryptographic proofs with notable applications in cryptography (see [KO21] and references therein). A sigma protocol is a public-coin interactive protocol that satisfies strong zero knowledge and soundness properties, and enjoys a simple structure. The prover sends a commitment, then the verifier responds with a random challenge, and finally, the prover sends an opening; the verifier computes a decision bit based on the instance and the interaction transcript. Perhaps the most prominent example of a sigma protocol is Schnorr’s protocol [Sch89; Sch91], which proves, in zero knowledge, the knowledge of the discrete logarithm of a given group element (for a given cyclic group and base group element). Numerous works study in detail Schnorr’s protocol (and its derivates), establishing upper and lower bounds on its security in different settings [Sho97; PS00; BP02; FPS20; BD20; RS21; SSY23]. Remarkably, gaps remain in our understanding of the security of Schnorr’s protocol, and closing these gaps remains a challenging open problem. In this paper we study *Kilian’s protocol* [Kil92], a public-coin interactive protocol that, while not a sigma protocol, shares striking similarities with sigma protocols. This protocol is historically significant as the first example of a *succinct argument*, a computationally-sound interactive proof for nondeterministic relations where the communication complexity is much smaller than the size of the relation’s witness. Kilian’s protocol is also the simplest example of a succinct interactive argument obtained via the VC-based approach, a fundamental paradigm for constructing succinct arguments from a probabilistic proof and a vector commitment (VC) scheme. The shared structure with a sigma protocol is evident. The argument prover commits to a probabilistically checkable proof (PCP) string via a VC scheme (Kilian’s presentation uses a Merkle commitment scheme, a VC scheme obtained from collision-resistant hash functions), and sends the resulting commitment to the argument verifier; the argument verifier sends PCP verifier randomness to the argument prover; and finally the argument prover reveals the values of the queried locations of the PCP string and accompanies these values with opening information. The argument verifier accepts if the opening information is valid and the PCP verifier accepts. Succinct arguments are a rare example of an “advanced” cryptographic primitive that can be achieved from simple cryptography. Indeed, it is remarkable that, based solely on the existence of a collision resistant hash function (even given as a black box), one can achieve cryptographic proof systems with such remarkable efficiency. On the other hand, the security reduction of a succinct argument is tasked with a challenging goal: find a “long” witness when given a malicious argument prover that only outputs “short” messages in any given interaction. This naturally leads to *rewinding*, a fundamental method of analysis in cryptography. While Kilian [Kil92] gives only an informal analysis, the security of Kilian’s protocol via rewinding is studied in later works. Barak and Goldreich [BG08] give a detailed analysis, but with limitations: their analysis incurs overheads and applies only to PCPs that satisfy restrictive properties. Other works [IMSX15; LM19; CMSZ21; LMS22] provide brief analyses in the setting of negligible errors, without quantifying security bounds in terms of the underlying ingredients. We further elaborate on prior work in Section 1.3. Motivated by the surge of interest in succinct arguments (e.g., in the context of blockchains [SSV19; SSV21]), we revisit the security of Kilian’s protocol. As we discuss shortly, we expose a fine structure and open problems, much alike to the state of affairs for arguably simpler protocols such as Schnorr’s protocol. This challenges the commonly-held belief that Kilian’s protocol is “understood”. We now turn to discuss our results.

### 1.1 Our results

Kilian’s protocol [Kil92] combines a PCP system PCP and a vector commitment scheme VC to obtain a succinct (public-coin) interactive argument. Throughout this section, we fix these ingredients (unless otherwise specified).

- PCP is a PCP system for a relation *R* with proof length *ℓ*, query complexity q, and soundness error *ϵ*PCP. (These may depend on the given instance ①.)
- VC is a vector commitment scheme VC and we denote by *ϵ*VCits *position binding error*, which bounds the probability that an adversary outputs valid openings for the same commitment that disagree in at least one position. In general, *ϵ*VCis a function of the security parameter *λ*, length *ℓ* of the committed vector, number *s*

of opened entries of the vector, and bound *t*VCon the adversary running time. **Soundness.** We provide the tightest known bounds for the soundness error of Kilian’s protocol.

**Theorem 1** (informal)**.** *The soundness error ϵ*ARG*of* Kilian[PCP*,*VC] *satisfies the following for every security* *parameter λ, instance* ① *∈/ L*(*R*)*, adversary time bound t*ARG*, and error tolerance ϵ >* 0*:*

<u>ℓ</u> *ϵ* ARG(*λ,*①*,t*ARG) *≤ ϵ*PCP(①) + *ϵ*VC*λ,ℓ,*q*,t*VC+ *ϵ, where t*VC= *O · t*ARG*.* *ϵ*

The above bound for Kilian’s protocol has an intuitive explanation. An adversary that commits to the PCP string Πe with maximal acceptance probability (and opens accordingly) convinces the argument verifier with probability at least *ϵ*PCP. Moreover, an adversary that then tries to find a collision when Πe is rejected achieves (under some mild conditions) a convincing probability of *ϵ*PCP+ (1 *− ϵ*PCP) *· ϵ*VC. The <u>ℓ</u> *ϵ* multiplicative loss in *t*VC compared to *t*ARGexpresses the *price of rewinding*: to reconstruct an almost full PCP string from small fragments revealed in each (valid) opening, we rewind the malicious argument prover sufficiently many times. Improving this multiplicative factor remains an open problem. Nevertheless, we show an exponential improvement when VC satisfies *expected*-time position binding, via an expected-time reduction that we discuss next. **Expected-time adversaries.** We use *ϵ* *⋆* VCto denote the *expected-time* position binding error of VC, in which case we use *t* *⋆* VCto denote a bound on the *expected* running time of the adversary. Namely, *ϵ* *⋆* VCis the error probability given an adversary that runs in *expected-time t* *⋆* VC. We provide the first soundness analysis of Kilian’s protocol against adversaries with bounded expected running time. Since the (strict-time) soundness error of Kilian’s protocol is upper-bounded by its expected-time soundness error, the following theorem gives an alternative upper bound on the (strict-time) soundness error in terms of the expected-time position binding error *ϵ* *⋆* VCof VC.

**Theorem 2** (informal)**.** *If* PCP *has a non-adaptive verifier with running time t*V*, the expected-time soundness* *error ϵ* *⋆* ARG*of* Kilian[PCP*,*VC] *satisfies the following for every security parameter λ, instance* ① *∈/ L*(*R*)*,*

||⋆||
|---|---|---|
|⋆ ⋆|⋆|⋆|

*adversary expected time bound t* *⋆* ARG*, and error tolerance ϵ >* 0*:*

*⋆*<u>q</u>*⋆* *ϵ* ARG(*λ,*①*,t*ARG) *≤ ϵ*PCP(①) + q *· ϵ*VC*λ,ℓ,*q*,t*VC+ *ϵ, where t*VC= *O* log *·* (*t*ARG+ *ℓ · t*V)*.* *ϵ*

This is an *exponential improvement* in the dependency of *ϵ* compared to the strict-time setting (Theorem 1). Note that Theorem 2 assumes that the PCP underlying Kilian’s protocol has a *non-adaptive verifier* (its queries are determined by the instance ① and the PCP verifier randomness). For PCPs with an adaptive verifier, we prove an alternative statement that achieves the same bound except with *t* *⋆* VC= *O* log <u>q</u> *ϵ* *· ℓ · t* *⋆* ARG. **Lower bounds on soundness.** Kilian’s protocol shares certain structural resemblances to a sigma protocol: both start with a prover’s commitment, followed by a verifier’s challenge, and end with an opening to the commitment. However, sigma protocols are special sound while Kilian’s protocol is not (see Section 1.3). Hence, it is unclear whether there is any formal connection between Kilian’s protocol and sigma protocols. We obtain the first lower bound on the soundness error of Kilian’s protocol by showing that bounding the soundness of Kilian’s protocol is *as hard as that of the Schnorr identification scheme*, a sigma protocol obtained from Schorr’s protocol whose security, despite significant research efforts, remains only partially understood.

**Theorem 3** (informal)**.** *There exists* PCP *for a relation R and* VC *such that, for every security parameter λ,* *instance* ① *∈/ L*(*R*)*, Schnorr adversary time bound* tID*∈* N*, and Schnorr adversary expected time bound t* *⋆* ID*∈* N*,*

*ϵ* Schnorr(*λ,*tID) *≤ ϵ*ARG(*λ,*①*,t*ARG)*, and* *ϵ* *⋆* Schnorr(*λ,t* *⋆* ID) *≤ ϵ* *⋆* ARG(*λ,*①*,t* *⋆* ARG)*.*

*Above, ϵ*ARG*and ϵ* *⋆* ARG*are the soundness error and the expected-time soundness error of* ARG := Kilian[PCP*,*VC]*,* *respectively; ϵ*Schnorr*and ϵ* *⋆* Schnorr*are the security against passive impersonation attacks of the Schnorr identification* *scheme and its expected-time analogue, respectively. Moreover, t*ARG= *O*(tID)*, and t* *⋆* ARG= *O*(*t* *⋆* ID)*.*

In Section 1.2 we discuss how Theorem 3 tells us that in the strict-time setting there is a polynomial gap between upper and lower bounds, whereas in the expected-time setting there is essentially no gap.

**Knowledge soundness.** The above discussion focuses only on the soundness error of Kilian’s protocol. Recall that the soundness error is an upper bound on the probability that a time-bounded adversary convinces the argument verifier to accept an instance not in the language. Another important security notion is the *knowledge* *soundness error*, which bounds the probability that a time-bounded adversary convinces the verifier but a corresponding extractor, given that adversary, fails to find a valid witness for the instance. The knowledge soundness error is an upper bound on the soundness error because any extractor cannot find a valid witness for an instance not in the language (there are no valid witnesses). We construct an extractor for Kilian’s protocol that runs in time *O* <u>ℓ</u> *ϵ* *· t*ARG, and similarly to Theorem 1, prove that its knowledge soundness error satisfies

<u>ℓ</u> *κ*ARG(*λ,*①*,t*ARG) *≤ κ*PCP(①) + *ϵ*VC*λ,ℓ,*q*,t*VC+ *ϵ,* where *t*VC= *O · t*ARG*.* *ϵ*

We prove this bound by making explicit, in the proof of Theorem 1, a subroutine with running time *O* <u>ℓ</u> *ϵ* *· t*ARG that outputs a “good” PCP (after which we rely on the PCP knowledge extractor to obtain a witness). What can we say about the setting of expected-time adversaries? A similar bound as the above can straightforwardly be proved, but this would not take advantage of an expected-time reduction to achieve a smaller upper bound. Ideally, we would convert the bound on soundness error in Theorem 2 into a similar bound on knowledge soundness error; however, this does *not* work. Indeed, while the proofs behind Theorems 1 and 2 both use rewinding arguments, they are qualitatively different (more details in Sections 2.2 and 2.3). Obtaining a knowledge soundness bound from the proof of Theorem 1 is straightforward because the extractor for the PCP and the collision finder for the VC are similar algorithms. However, the proof of Theorem 2 leverages extra efficiency by breaking this symmetry: only the VC collision finder is efficient, while the extractor that constructs a PCP is not. Hence, obtaining better bounds for the expected-time knowledge soundness of Kilian’s protocol remains open. We conclude by noting that similar considerations apply for proving the security of Kilian’s protocol when based on a probabilistically checkable *argument* (PCA) [KR09; BR22; Ben24] rather than a probabilistically checkable *proof*. Since a PCA is computationally sound, the running time to generate the PCA string is essential. Hence, our work yields a strict-time reduction that is compatible with PCAs, while our expected-time reduction is not compatible with PCAs.

**Remark 1** (adaptive choice of ①)**.** The results of Theorems 1 to 3 are stated, for simplicity, in the plain model (no trusted setups), where the argument verifier is responsible for sampling and sending public parameters pp for VC to the argument prover. However, we actually *prove* these results in the (adaptive) common reference string model, wherein public parameters pp for VC are sampled by a trusted party and *a malicious argument* *prover may adaptively choose the instance* ① *after learning* pp. Since in these stronger theorems there is no pre-set instance ①, the analogous statements (for corresponding security properties) in the common reference model replace ① with a size bound *n* (and hold for all instances such that *|*①*|≤ n*). The plain model variants are straightforwardly implied (see Section 2.6 and Remark 3.7).

### 1.2 Discussion

**How tight are the soundness bounds?** We discuss the tightness of the soundness upper bounds in Theorems 1 and 2. The takeaway is that, for the setting in Theorem 3: (i) there is a polynomial gap between Theorem 1 and the best strict-time analysis of the security of the Schnorr identification scheme; and (ii) there is essentially no gap between Theorem 2 and the best expected-time analysis of the security of the Schnorr identification scheme. This mirrors the state of the affairs for the Schnorr identification scheme, as we now elaborate.

The security of the Schnorr identification scheme relies on the hardness of the discrete logarithm problem. In the strict-time setting, the best analysis shows (roughly) a square-root loss in the error: p *ϵ* Schnorr(*λ,*tID) *≤ ϵ*DLOG(*λ,O*(tID))*,*

On the other hand, in the expected-time setting, it is straightforward to show that there is essentially no loss:

*⋆*

|ϵ|(λ,t|(λ,O(t ) ≤ ϵ|)).|
|---|---|---|---|
|⋆|⋆|⋆||
||||x|
||||⋆|

Schnorr *⋆* ID *⋆* DLOG *⋆* ID

Above *ϵ*DLOG= *ϵ*DLOG(*λ,*tDLOG) and *ϵ*DLOG= *ϵ*DLOG(*λ,t*DLOG) are the discrete logarithm error and the expected-time discrete logarithm error, respectively for a given group. That is, for every tDLOG*∈* N and tDLOG-time adversary, given random *y*, the probability of finding *x* such that *y* = *g* is bounded by *ϵ*DLOG(*λ,*tDLOG). Similarly, the success probability of any adversary that has expected running time *t*DLOGis bounded by *ϵ* *⋆* DLOG(*λ,t* *⋆* DLOG). Below we only state the bounds, the detailed calculation can be found in Sections 8.3 and 8.4.

- *Tightness of Theorem 1:* Consider the PCP and VC from Theorem 3. Let ARG := Kilian[PCP*,*VC]. Theorem 1 implies that
*−λ*<u>ℓ</u> *ϵ* ARG(*λ,*①*,t*ARG) *≤* 2 + *ϵ*DLOG*λ, · t*ARG+ *ϵ .* *ϵ*

For a natural setting of parameters, we can instantiate the bounds of *ϵ*Schnorrand *ϵ*ARGas follows: r! <u>t²</u> <u>ID</u> *ϵ* Schnorr(*λ,*tID) *≤ Oλ,* and 2 r! *−λ* 2*/*33 <u>t²ARG</u> *ϵ* ARG(*λ,*①*,t*ARG) *≤* 2 + *ℓ ·* Θ*λ.* 2

This shows a polynomial gap between the best analysis of the Schnorr identification scheme and our analysis of Kilian’s protocol. Closing this gap remains an open problem.

- *Tightness of Theorem 2:* From Theorem 2, ARG := Kilian[PCP*,*VC] has expected-time soundness error *ϵ*
*⋆* ARG where

*⋆ ⋆ −λ ⋆*<u>q</u>*⋆* *ϵ* ARG(*λ,*①*,t*ARG) *≤* 2 + *ϵ*DLOG*λ,O* log *· t*ARG+ *ϵ .* *ϵ*

This upper bound almost matches with the best known expected-time upper bound for the security of the Schnorr identification scheme, except for a polylogarithmic loss in the adversary running time.

**Why not use a random oracle?** One method of analyzing Kilian’s protocol is relying on idealized models such as the random oracle model. Here, the need to rewind the adversary is obviated as the PCP can be extracted directly by observing the queries performed by the adversary to the random oracle. This approach yields an analysis with tight bounds (see e.g., [CY24]) but is not applicable in the standard model. In applications, practitioners replace the random oracle with a specific hash function, choosing parameters based on the idealized model’s analysis. However, this limits the choice of hash functions to those presumed to sufficiently mimic a random oracle, excluding hash functions that offer notable benefits but cannot replace a random oracle. This includes, for example, hash functions with an algebraic structure (e.g., Pedersen hash), which can be fast to compute or friendly for recursive composition. Understanding the trade-offs in security bounds when using a rewinding-based analysis instead of the random oracle model is meaningful and valuable. **On the price of rewinding.** We compare the soundness of Kilian’s protocol when analyzed via: (i) a rewinding extractor when VC is based on a collision resistant hash function; or (ii) a straightline extractor when VC is based on an ideal hash function (a random oracle). This highlights the “price of rewinding”: the cost of a more expensive security reduction that works under weaker assumptions on the underlying cryptography.

(i) *Rewinding extractor.* Suppose that the vector commitment scheme VC is a Merkle commitment scheme obtained from a collision-resistant hash function with security *ϵ*CRH(*λ,t*CRH). By Remark 2,
*ϵ* VC(*λ,ℓ,s,t*VC) *≤ ϵ*CRH*λ,t*CRH= *t*VC+ *O*(*thλ·* q *·* log*ℓ*)*.*

Suppose that *ϵ*CRH(*λ,t*CRH) *≤ t²*CRH*/*2 *λ*, which is what would be achieved by an ideal hash function. In this case, Theorem 1 gives the following upper bound on the soundness error for Kilian[PCP*,*VC]: ! 2 <u>1 ℓ</u> *ϵ* ARG(*λ,*①*,t*ARG) *≤ ϵ*PCP(①) + *Oλ· · t*ARG+ *thλ·* q *·* log*ℓ* + *ϵ .* 2 *ϵ*

Setting *ϵ* = Θ((*ℓ · t*ARG) 2*/*3 *·* 2 *−λ/*3 ) minimizes the right-hand side at *ϵ*PCP(①) + Θ(*ℓ²* */*3 *·* (*t²*ARG*·* 2 *−λ* ) 1*/*3 ). 1

(ii) *Straightline extractor.* Suppose that we model the collision-resistant hash function as an ideal hash function, and analyze Kilian[PCP*,*VC] in the random oracle model. Then [CY24] shows that:

*ϵ* ARG(*λ,*①*,t*ARG) *≤ ϵ*PCP(①) + Θ(*t²*ARG*·* 2 *−λ* )*.*

This smaller upper bound is achieved thanks to a straightline (i.e., non-rewinding) extractor for the vector commitment scheme, which is a Merkle commitment scheme in the random oracle model.

**Remark 2** (security of underlying components)**.** We derive security bounds for argument systems *as a function* *of the security bounds of the underlying components*. In short, we take *ϵ*VC, *ϵ*PCP, *κ*PCPas given. While statistical soundness bounds on PCPs can be calculated (they are information-theoretic components), the position binding errors for VC must be derived from some (concrete) computational assumption. For example, if VC is a Merkle commitment scheme obtained from a collision-resistant hash function *hλ*: *{*0*,*1*}* 2*λ* *→{*0*,*1*}* *λ* computable in time *th* *λ* whose collision probability against *t*CRH-size adversaries is bounded by *ϵ*CRH(*λ,t*CRH) then VC has binding error *ϵ*VC(*λ,ℓ,s,t*VC) *≤ ϵ*CRH(*λ,t*CRH) where *t*CRH= *t*VC+ *O*(*th* *λ* *·* q *·* log*ℓ*) for a small hidden constant that can be derived from the security reduction. (The reduction transforms a *t*VC-size adversary *A*VCagainst the Merkle commitment scheme into a *t*CRH-size adversary *A*CRHagainst the collision-resistant hash function. Briefly, *A*CRHruns *A*VCand then looks for a collision among the authentication paths output by *A*VC, resulting in the additive increase of *O*(*th* *λ* *·* q *·* log*ℓ*) in size.)

### 1.3 Related work

The literature on succinct arguments presents a vast landscape of constructions exhibiting complex tradeoffs between efficiency, expressiveness, and security. The goal of this work is to study the security of Kilian’s protocol, which is a succinct *interactive* argument. Below we summarize only the most relevant prior work.

**Succinct arguments from collision-resistant functions.** The first construction of a succinct argument is due to Kilian [Kil92], and follows the VC-based approach (the underlying vector commitment is a Merkle commitment scheme based on a collision-resistant hash function). The security reduction in [Kil92] is informal, and does not provide any asymptotic (nor explicit) security bounds. Barak and Goldreich [BG08] provide a formal analysis of a variant of Kilian’s construction, towards their goal of constructing zero-knowledge arguments with a non-black-box simulator. Due to their setting, they restrict their result to the case where the PCP is *non-adaptive* and *reverse-samplable*. While the former restriction is mild (many known PCP constructions are non-adaptive, with few exceptions such as [KPT97]), the latter restriction is a non-standard strong property of the PCP query algorithm, which has not been shown to hold for a number of PCP constructions of interest (e.g., the short PCPs in [BS06; BKKMS13]). Under these conditions, they

Ignoring the lower-order term *th·* q *·* log*ℓ*. *λ*

establish that Kilian’s protocol achieves non-adaptive knowledge soundness, with a constant multiplicative factor loss in soundness versus the PCP soundness. In contrast, our work applies to *all* PCPs (including adaptive PCPs) and establishes the tightest known bound for adaptive knowledge soundness. 2

Ishai, Mahmoody, Sahai, and Xiao [IMSX15] provide a soundness analysis for Kilian’s protocol instantiated with a PCP with negligible soundness error and a Merkle commitment scheme with negligible position binding error; they do not quantify the security of the succinct argument in terms of the security of the underlying cryptography. Lai and Malavolta [LM19, Appendix C] prove secure a variant of Kilian’s protocol, realized with any *linear PCP* and *linear map commitment*; this generality can lead to shorter proofs. Chiesa, Ma, Spooner, and Zhandry [CMSZ21] prove *post-quantum* security of Kilian’s protocol. As part of their analysis, they give a proof of security for Kilian that also applies to the classical setting. Their analysis differs significantly from ours due to challenges unique to the quantum setting, and incurs a multiplicative soundness loss. In this work we consider soundness against classical adversaries only.

**Succinct arguments from ideal hash functions.** A line of work studies security reductions for succinct *non-interactive* arguments in the random oracle model (ROM) [Mic00; Val08; BCS16; CMS19; CY21a; CY21b; BGTZ23; CY24]. They take advantage of the ROM in two key ways. First, they use the observability of oracle queries to construct a vector commitment scheme with a *straightline* (i.e., non-rewinding) extractor: a Merkle commitment scheme in the ROM. As noted in Section 1.2, this leads to tighter security bounds. In fact, since these constructions are *unconditionally* secure in the ROM, it is often possible to compute their *exact* soundness. Second, these constructions use the Fiat–Shamir transformation to convert an underlying *interactive* argument into a *non-interactive* one; the general security of this transformation has been shown only in the ROM.

**Special-sound protocols.** Interactive protocols with *special soundness* are an important and well-studied family of public-coin protocols. In the sigma protocol setting (three-message public-coin protocols), *k*-special soundness means that a witness can be efficiently extracted from any *k* accepting protocol transcripts with distinct verifier challenges. A line of works extends this notion to multiple rounds [AC20; ACK22; AF22]. The concrete security of general special sound protocols is relatively well-understood. As noted in [CMSZ21], for reasonable choices of PCP, Kilian’s protocol is *not k*-special sound for any polynomial *k* (for example, one can find a set of transcripts that includes only queries to a small fraction of the PCP). 3 We are therefore not able to apply results about special soundness directly.

2 Formally, our result is incomparable with the one of Barak and Goldreich. In more detail, they use the reverse samplability property of the PCP to obtain a collision-finder whose running time does not depend on the PCP length. This is necessary in their setting, as there the size of an extracted PCP is not *a priori* bounded by any polynomial. It is open whether such a reduction is possible for (even polynomial-size) PCPs that are not reverse samplable. Towards a tighter security proof for Kilian in the post-quantum setting, Lombardi, Ma, and Spooner [LMS22] introduce the notion of *probabilistic special soundness* (PSS), a relaxation of special soundness, and show that Kilian’s protocol is PSS. We do not follow this approach, as we do not expect it to yield tight security bounds in the classical setting.

## 2 Techniques

We overview the main ideas underlying our results. In Section 2.1 we review Kilian’s protocol. In Section 2.2 we sketch our proof of Theorem 1. In Section 2.3 we sketch our proof of Theorem 2. In Section 2.4 we sketch our proof of Theorem 3. In Section 2.5 we explain how to show the strict-time knowledge soundness of Kilian’s protocol. In Section 2.6 we discuss adaptive security.

**Vector commitment schemes.** We fix a vector commitment scheme VC throughout this technical overview, whose interface and properties are sketched below; see Section 3.2 for formal definitions. Here we omit the algorithm that samples public parameters (and suppress these parameters in the interfaces of VC). 4

- VC*.*Commit: On input a message *m*, VC*.*Commit outputs a commitment cm and auxiliary state aux.
- VC*.*Open: On input the auxiliary state aux and a query set *Q*, VC*.*Open outputs an opening proof pf.
- VC*.*Check: On input a commitment cm, query set *Q*, answers ans, and opening proof pf, VC*.*Check determines if pf is valid for ans being the restriction to *Q* of the message committed in cm. The property of *perfect completeness* ensures that VC*.*Check always accepts if pf is output by VC*.*Open given the auxiliary information produced by VC*.*Commit. The security property of VC is *position binding*: VC has *position binding error ϵ*VC(*λ,ℓ,s,t*VC) if, when VC is instantiated with security parameter *λ* for messages of length *ℓ*, every *t*VC-time adversary that outputs (cm*,*ans*,*ans
*′* *, Q, Q* *′* *,*pf*,*pf *′* ) with *|Q|* = *|Q* *′* *|* = *s* satisfies the following predicate with probability at most *ϵ*VC(*λ,ℓ,s,t*VC) (over VC’s public parameters):

*∃ i ∈Q∩Q* *′* : ans[*i*] *̸*= ans *′* [*i*] *∧* VC*.*Check(cm*, Q,* ans*,*pf) = 1*.* *∧* VC*.*Check(cm*, Q* *′* *,*ans *′* *,*pf *′*

) = 1
In other words, position binding makes it hard to produce two incompatible openings to the same commitment. Moreover, we also consider *expected-time position binding*: the expected-time position binding error *ϵ* *⋆* VC= *ϵ* *⋆* VC(*λ,ℓ,s,t* *⋆* VC) is the position binding property against adversaries whose expected running time is at most *t* *⋆* VC. **Stateful algorithms.** Throughout this section, the interactive algorithms that participate in protocols are stateful. When it is important to distinguish different computation phases of a stateful algorithm, we make explicit the state passed from one phase to the next.

### 2.1 Kilian’s protocol

We review Kilian’s protocol that compiles a PCP and a VC scheme to a succinct interactive argument. Kilian’s protocol [Kil92] obtains a succinct interactive argument by combining two ingredients: a proba- bilistically checkable proof (PCP) and a vector commitment scheme VC (fixed above). Let PCP = (P*,*V) be a PCP system for a relation *R* with alphabet Σ, proof length *ℓ*, query complexity q, and verifier randomness complexity r. Kilian[PCP*,*VC] is an interactive argument ARG = (*P, V*) in which the argument prover *P* receives an instance ① and a witness ✇, and the argument verifier *V* receives the instance ①. Then *P* and *V* interact, exchanging 3 messages, as follows.

1. *P* computes the PCP string Π *←* P(①*,*✇), computes the commitment (cm*,*aux) *←* VC*.*Commit(Π), and sends cm to *V*.
2. *V* samples PCP verifier randomness *ρ ←{*0*,*1*}*
r and sends it to *P*.

3. *P* deduces the set *Q* of queries that V(①;*ρ*) makes to Π, sets the query answers ans := Π[*Q*], generates an opening proof pf *←* VC*.*Open(aux*, Q*), and sends the tuple (*Q,* ans*,*pf) to *V*.
4. *V* performs the following checks.
(a) VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 (i.e., ans are valid answers for positions *Q* relative to cm); For example, if VC is based on a Merkle commitment scheme, the public parameters are the (randomly sampled) collision-resistant
function to be used for hashing the given message down to the Merkle root.

(b) V [*Q,*ans]
(①;*ρ*) = 1 (i.e., the PCP verifier V(①;*ρ*) accepts the answers ans on *Q*).

Above, the notation V [*Q,*ans] (①;*ρ*) refers to the decision bit of the PCP verifier V, given instance ① and PCP randomness *ρ*, when each query *j ∈Q* is answered with ans[*j*] *∈* Σ. (If V queries outside the set *Q* then V [*Q,*ans] (①;*ρ*) = 0.)

### 2.2 Soundness analysis of Kilian’s protocol

We discuss the proof idea for Theorem 1.

### 2.2.1 Security reduction

Intuitively, the soundness error of Kilian[PCP*,*VC] should be at most the (statistical) soundness error of PCP plus the position binding error of VC. The key lemma below formalizes this intuition. Consider a malicious argument prover *P*e whose first message is the commitment cm. Intuitively, by the position binding property of VC, *P*e is “bound” to open locations of at most a single underlying PCP string Πe. By *rewinding P*e sufficiently many times to recover the underlying PCP string Πe, we can relate the probability of *P*e convincing the argument verifier *V* to the probability of Πe convincing the PCP verifier V.

**Lemma 1** (informal)**.** *There exists a probabilistic algorithm R (the **reductor**) that, for every instance* ①*, error* *parameter ϵ >* 0*, adversary time bound t*ARG*∈* N*, and t*ARG*-size adversary P*e*, satisfies*   cm *← P*e [*Q,* e eΠ]  V (①;*ρ*) *̸*= 1 e e*P* e   [*Q,*ans] (*Q,* Π) *←R* (cm*,ϵ*)  Pr  *∧* V (①;*ρ*) = 1 r  *≤ ϵ*VC(*λ,ℓ,*q*,t*VC) + *ϵ ,*  *ρ ←{*0*,*1*}*  *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 e (*Q,* ans*,*pf) *← P*(*ρ*)

*where t*VC= *O* <u>ℓ</u> *ϵ* *· t*ARG*.*

The reductor *R* handles the aforementioned rewinding process: *R* constructs a proof string Πe *∈* Σ *ℓ* whose convincing probability is approximately the same as that of the argument prover *P*e (up to the position binding error of VC and an arbitrary error term *ϵ*). Note that *R* requires only black-box access to *P*e. In the lemma above, the PCP verifier and the argument verifier are “coupled” in that they receive the same randomness *ρ*. The lemma states that it is unlikely, for a randomly-chosen *ρ*, that the argument verifier *V* accepts the answers provided by *P*e but the PCP verifier V rejects Πe under the same randomness. Intuitively, this allows us to approximately equate the probability that *P*e convinces the argument verifier *V* to the probability that Πe convinces the PCP verifier V. First we discuss how to use Lemma 1 to establish soundness error of Kilian[PCP*,*VC] in Section 2.2.2. Then in Section 2.2.3 we sketch the proof of Lemma 1. For simplicity, all probability statements in this section are with respect to the experiment in Lemma 1 unless otherwise specified.

### 2.2.2 Soundness analysis

We wish to upper bound the soundness error of Kilian[PCP*,*VC]. As claimed in Theorem 1, we argue that for every instance ① *∈/ L*(*R*), time bound *t*ARG*∈* N, and *t*ARG-size adversary *P*e, h i Pr *P*e*, V*(①) = 1 *≤ ϵ*PCP(①) + *ϵ*VC(*λ,ℓ,*q*,t*VC) + *ϵ .*

The above probability can be bounded with the following by the law of total probability:  e e   e e  V [*Q,*Π] (①;*ρ*) = 1 V [*Q,*Π] (①;*ρ*) *̸*= 1 Pr  *∧* V[*Q,*ans](①;*ρ*) = 1  + Pr  *∧* V[*Q,*ans](①;*ρ*) = 1 *.* *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1

The term on the right is bounded from above by *ϵ*VC(*λ,ℓ,*q*,t*VC) + *ϵ*, due to Lemma 1. The term on the left is bounded by *ϵ*PCP(①) (the soundness error of PCP). Indeed, we can view the first message of *P*e (cm in the experiment above) and the reductor *R* as a malicious PCP prover Pe that outputs a PCP string Πe. Since ① *∈/ L*(*R*), by the definition of soundness error of PCP,

 e e  V [*Q,*Π] (①;*ρ*) = 1 h i [*Q,*ans] Π e Pr  *∧* V (①;*ρ*) = 1 *≤* Pr V (①) = 1 *≤ ϵ*PCP(①)*.* *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1

### 2.2.3 Proof sketch of Lemma 1

We are left to sketch the proof of Lemma 1. To do so, we present a reductor algorithm *R*. The goal of *R* is to piece together a PCP string Πe obtained from the argument prover *P*e. Intuitively, Πe is “fixed” after *P*e outputs a commitment cm, and *R* attempts to obtain information about Πe by *rewinding* the second phase of *P*e, when given freshly sampled choices of PCP randomness *ρ*. Each such execution (if it outputs a valid opening) reveals a fragment of Πe. By repeating this process sufficiently many times, *R* obtains enough locations of the string Πe. Below we denote by N = N(*ϵ*) the number of samples (set later).

*P* e (aux*,·*) *R* (cm*,ϵ*):

1.Initialize a proof string: Πe := (*σ*)
*ℓ*, where *σ* is an arbitrary element in Σ.

2.Initialize an empty set *Q*e to track which locations of Πe are filled in.
3.Repeat the following N times:
(a)Sample PCP verifier randomness *ρ ←{*0*,*1*}*
r.

(b)Ask *P*e for answers to this randomness: (*Q,* ans*,*pf) *← P*e(aux*,ρ*).
(c)If VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1, set Π[e *Q*] := ans and update *Q*e := *Q∪Q* e.
4.Output (*Q*e*,*Π) e.
We make explicit the two computation phases of the (stateful) malicious argument prover *P*e:

(cm*,*aux) *← P*e and (*Q,* ans*,*pf) *← P*e(aux*,ρ*)*,*

where aux is the auxiliary state passed across the two computation phases of *P*e. The reductor *R* needs to rerun only the second phase of *P*e, so the oracle for *R* is *P*e(aux*, ·*). As stated in Lemma 1, with the above notation we wish to bound the following probability:

 e e  V [*Q,*Π] (①;*ρ*) *̸*= 1 Pr  *∧* V[*Q,*ans](①;*ρ*) = 1 *.* *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1

Π e [*Q,*ans] e and ans disagree If VC*.*Check(cm*, Q,* ans*,*pf) = 1 then V (①;*ρ*) *̸*= 1*∧* V (①;*ρ*) = 1 implies either: (i) Π at a position *q ∈Q∩ Q*e; or (ii) there is query *q* in *Q* but not in *Q*e. We analyze the two events separately, which bounds the probability above by a union bound. We suppress the probability experiment in the derivations below.

**(i) Valid openings with disagreeing answers.** We informally argue that
*∃ q ∈Q∩ Q*e : ans[*q*] *̸*= Π[e *q*] Pr *≤ ϵ*VC(*λ,ℓ,*q*,t*VC)*.* *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1

The reductor *R* checks the validity of the opening for each position it fills into Πe. Hence the event above implies that there are valid openings to two different values at the same query position; equivalently, one can construct an adversary *A*VCthat runs the reductor *R* and executes *⟨P*e*, V*(①*,ρ*)*⟩* for some verifier randomness *ρ* that breaks

VC’s position binding. Since *A*VChas running time *t*VC= *O*(N *· t*ARG) (its running time is dominated by the running time of *R*), the target probability is at most *ϵ*VC(*λ,ℓ,*q*,t*VC) by the position binding property of the VC.

**(ii) Missing position in** Πe**.** We show that

*Q\ Q̸*e = *∅* <u>ℓ</u> Pr *≤.* *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 N

To upper bound the probability of a query *q ∈Q* not having been filled in by *R*, we use the probability that a given position *q ∈* [*ℓ*] is queried. The *weight δ*(*q*) of a query *q ∈* [*ℓ*] is the probability that it is queried by the argument verifier with uniformly sampled randomness. We can write: h i h i X Pr *Q\ Q̸*e = *∅* = Pr *∃ q ∈* [*ℓ*] : *q ∈Q∧ q /∈ Q*e *≤ δ*(*q*) *·* (1 *− δ*(*q*)) N *,* *q∈*[*ℓ*]

where the inequality follows from the fact that *Q* and all query sets used to generate *Q*e correspond to indepen- dently sampled verifier randomness. Note that, for every *δ ∈* [0*,*1], *δ ·* (1 *− δ*) N *≤* 1*/*N. 5 Hence, the target probability is upper bounded by N <u>ℓ</u>. In fact, the proof for this case is more delicate than sketched above. If a position *q ∈* [*ℓ*] has weight *δ*(*q*), we cannot conclude that *q /∈ Q*e with probability at most (1 *− δ*(*q*)) N, because *P*e may often output invalid openings for *q* while *R* only includes valid openings. To fix this issue, we use a refined notion: *δ*(*q*) is the probability that during the execution of the interactive argument, the verifier *V* samples randomness that corresponds to a query set containing *q and the prover P outputs a valid VC opening for the query set*.

**Setting parameters.** By an union bound, the desired probability can be upper bounded by *ϵ*VC(*λ,ℓ,*q*,t*VC) + N <u>ℓ</u>. Setting N := *ℓϵ*, we get *t*VC= *O*(N *· t*ARG) = *O* *ℓϵ* *· t*ARGand N *ℓ* = *ϵ*, yielding the bound stated in Lemma 1.

**Remark 3.** Superficially one might hope for an improved analysis showing that one only needs q <u>ℓ</u> *·ϵ* rewindings rather than <u>ℓ</u> *ϵ*. Indeed, each rewinding that leads to an accepting transcript yields a freshly sampled fragment of the PCP containing q locations. However such a bound is unrealistic because, in general, a PCP may have dummy queries. For example, consider a PCP where only *O*(1) of the q queries are “real”, while all others are dummy queries to fixed locations of the PCP string. That said, there may be other metrics through which the factor <u>ℓ</u> *ϵ* can be improved, for example, our Theorem 2 considers VC schemes with expected-time position binding and avoids this multiplicative factor.

### 2.3 Expected-time soundness analysis of Kilian’s protocol

We provide an alternative analysis for the expected-time soundness of Kilian’s protocol (Theorem 2) to avoid the blowup of <u>ℓ</u> *ϵ* in the VC adversary running time. Recall that in the previous analysis, we “coupled” the reductor *R* and the VC adversary *A*VC: they are essentially the same algorithm. However, notice the running time of *A*VCaffects the soundness error, while the running time of *R* does not. This leads us to the following new security reduction lemma, which “decouples” the two algorithms:

(*i*)
**Lemma 2** (informal)**.** *There exists a probabilistic algorithm R (the **reductor**) and algorithms A*VC*(the **VC*** ***adversaries**) for each i ∈* [q] *that, for every instance* ①*, error tolerance ϵ >* 0*, adversary time bound t*ARG*∈* N*,*

5 A simple derivation of the inequality is the following: with *f* (*x*) = *x ·* (1 *− x*) N, we have <u>d</u> *f* (*δ*) = 0 *⇐⇒ δ* = <u>1</u>. As *dx* N+1 *f*(0) = *f*(1) = 0 and *δ* is the only critical point in [0*,*1], it achieves the maximum: max*x∈*[0*,*1]*{f*(*x*)*}* = *f* (*δ*) *≤* 1*/*N.

*and t*ARG*-time adversary P*e*, satisfies*   cm *← P*e Πe *⋆*e*⋆ P*e   V (①;*ρ*) *̸*= 1 Π *←R* (cm*,ϵ*)  [*Q,*ans] r  *∧* V (①;*ρ*) = 1 *ρ ←{*0*,*1*}*  Pr   *≤ ϵ ,*  *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 (*Q,* ans*,*pf) *← P*e(*ρ*)     *∧∀i ∈* [q]*,*ans[*Q*[*i*]] = ans(*i*)[*Q*[*i*]] *For i ∈* [q] : 

(*i*) (*i*) (*i*) (*i*)
(cm*, Q,* ans*,*pf*, Q,*ans*,*pf) *← A*VC(*ρ*)

(*i*) *⋆* <u>q</u>
*where the expected running time of A*VC*is t*VC= *O* log *·* (*t*ARG+ *ℓ · t*V) *for every i ∈* [q]*.* *ϵ*

For simplicity, all probability statements in the rest of this section are with respect to the experiment in Lemma 2 unless otherwise specified.

**Construction of the reductor.** Similar to the reductor in Section 2.2.3, our new reductor *R* rewinds to extract the PCP string committed by the adversary *P*e. In fact, *R* rewinds over all possible verifier randomness to extract the “best” PCP string.

*P*e *R* (cm): *⋆ ℓ*

1.Initialize a proof string: Πe := (*⊥*).
r

2.For every PCP verifier randomness *ρ ∈{*0*,*1*}* :
(a)Run (*Q,* ans*,*pf) *← P*e(*ρ*).
(b)If VC*.*Check(cm*, Q,* ans*,*pf) = 0, skip to next iteration.
(c)Record the answer for each location for later.
*⋆*

3. For every location *i ∈* [*ℓ*], set Πe [*i*] to be the most frequently appeared answer in the loop (break ties with the lexicographic order).
*⋆*

4.Output Πe.
**Constructions of the VC adversaries.** Let *C* be some constant to be specified later. For every *q ∈* [*ℓ*], we define *Sq*to be the following set:

r *Sq*:= *{ρ ∈{*0*,*1*}* : *q ∈Q* where *Q* is the set of queries make by V(①;*ρ*)*} .*

We first introduce a subroutine of the VC adversaries, the reverse sampler Samp. On input a query *q ∈* [*ℓ*], Samp outputs a randomness *ρ* sampled uniformly from *Sq*. We can implement Samp as follows.

Samp(*q*):

1.Repeat the following:
r

(a)Sample *ρ ←{*0*,*1*}*.
(b)Compute the query set *Q* corresponding to *ρ* by running the PCP verifier V(①;*ρ*).
(c)If *q ∈Q*, output *ρ*.
(*i*)
For every *i ∈* [q], we construct the VC adversary *A*VC. In particular, given a randomness *ρ* with corresponding

(*i*)
query set is *Q*, *A*VCtries to find inconsistent answers for the *i*-th query in *Q*.

(*i*)
*A*VC(*ρ*):

1.Run cm *← P*e(①) and (*Q,* ans*,*pf) *← P*e(*ρ*).
2.Check that VC*.*Check(cm*, Q,* ans*,*pf) = 1. If not, output (cm*,*ans*,*ans*, Q, Q,* pf*,*pf).
3.Define *q* := *Q*(*i*) and set *j* := 0.
4.Repeat the following:
*′*

(a)Run *ρ ←* Samp(*q*).

(b)Run (*Q*
*′* *,*ans *′* *,*pf *′* ) *← P*e(*ρ* *′* ).

(c)If VC*.*Check(cm*, Q*
*′* *,*ans *′* *,*pf *′*

) = 1:
i.If ans[*q*] *̸*= ans
*′* [*q*], output (cm*, Q,* ans*,*pf*, Q* *′* *,*ans *′* *,*pf *′* ). ii.If ans[*q*] = ans *′* [*q*], set *j* := *j* + 1. Further, if *j* = *C*, output (cm*,*ans*,*ans*, Q, Q,* pf*,*pf).

(*i*)
We compute the expected running time of *A*VC. For every *q ∈* [*ℓ*], let *pi,q*be the probability that the *i*-th query is *q* for a uniformly sampled randomness:   cm *← P*e *pi,q*:= Pr *Q*(*i*) = *q ρ ←{*0*,*1*}* r *.* (*Q,* ans*,*pf) *← P*e(*ρ*)

Let *X* be the running time of the reverse sampler Samp. Then, X <u>1</u> E [*X*] *≤ pi,q· · t*V= *ℓ · t*V*.* *pi,q* *q∈*[*ℓ*]

For every *q ∈* [*ℓ*], let *ξq*be the probability that *P*e gives a valid opening to a query set given that the *i*-th query is *q*:   VC*.*Check(cm*, Q,* ans*,*pf) = 1 cm *← P*e *ξ* *q*:= Pr  conditioned on *ρ ←{*0*,*1*}* r *.* *Q*(*i*) = *q* (*Q,* ans*,*pf) *← P*e(*ρ*)

Let *I* be the random variable that equals to 1 if the check in Step 2 passes and equals to 0 otherwise. Let *Y* be the

(*i*)
random variable for the running time of Step 4. The expected running time of *A*VCcan be computed as follows:

*t* *⋆* VC= *t* *⋆* ARG+E[*Y*]

|⋆|||
|---|---|---|
|⋆|i,q|⋆|
||q||
|⋆|||

= *t*ARG+ 0 *·* E [*Y | I* = 0] *·* Pr [*I* = 0] + E [*Y | I* = 1] *·* Pr [*I* = 1] X <u>1</u> *≤ t*ARG+ *C ·* E [*X*] + *C · p · · t*ARG*· ξq* *ξ* *q∈*[*ℓ*]

= *t*ARG+ *C ·* (*t* *⋆* ARG+ *ℓ · t*V)*.*

**Proof sketch of security reduction lemma.** We wish to bound the following probability:   Π e *⋆* V (①;*ρ*) *̸*= 1 [*Q,*ans]  *∧* V (①;*ρ*) = 1  Pr  *.*  *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1  *∧∀i ∈* [q]*,*ans[*Q*[*i*]] = ans

(*i*) [*Q*[*i*]] Π e *⋆*[*Q,*ans]
Similar to Section 2.2.3, if VC*.*Check(cm*, Q,* ans*,*pf) = 1, then V (①;*ρ*) *̸*= 1 and V (①;*ρ*) = 1 implies that Πe *⋆* and ans disagree at a position *q ∈Q*. Unlike before, here there is no case of missing queries, because the reductor *R*, by construction, exhausts all verifier randomness. On the other hand, we have a new condition, *∀i ∈* [q]*,*ans[*Q*[*i*]] = ans

(*i*) [*Q*[*i*]], which means that none of the VC adversaries successfully find inconsistent
openings to the same location. Hence, we focus on the following event:

*∃i ∈* [q]*,*ans[*Q*[*i*]] = ans

(*i*) [*Q*[*i*]] *̸*= Πe
*⋆* [*Q*[*i*]]*.*

For every *q ∈* [*ℓ*], Πe *⋆* [*q*] consists of the symbol that *P*e opens to with highest probability. In other words, let *p*(*q,σ*) be defined as follows:   *q ∈Q* cm *← P*e *p*(*q,σ*) := Pr  *∧*ans[*q*] = *σ ρ ←{,}* r *.* *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 (*Q,* ans*,*pf) *← P*e(*ρ*)

Then, by construction of *R*, Π e*⋆*[*q*] = arg max *{p*(*q,σ*)*},* *σ∈*Σ with ties broken lexicographically. Therefore, let *q ∈ Q* be the location such that Πe *⋆* [*q*] *̸*= ans[*q*], and *p*(*q,* ans[*q*]) *≤* <u>1</u> 2, as otherwise, *p*(*q,*Πe *⋆* [*q*]) *≥ p*(*q,* ans[*q*]) *>* 2 <u>1</u>, which implies that *p*(*q,*Πe *⋆* [*q*]) + *p*(*q,* ans[*q*]) *>* 1, a contradiction.

(*i*) *′ ′ ′ ′*e(*′ ′*
Since *A*VCsamples *C* randomness *ρ* such that for (*Q,*ans*,*pf) *← P ρ*) (i) *Q*[*i*] *∈Q*, (ii) ans[*Q*[*i*]] = ans *′* [*Q*[*i*]], and (iii) VC*.*Check(cm*, Q* *′* *,*ans *′* *,*pf *′*

) = 1, we can conclude that for every *i ∈* [q],
h i Pr ans[*Q*[*i*]] = ans

(*i*) [*Q*[*i*]] *̸*= Πe
*⋆* [*Q*[*i*]] *≤* 2 *−C* *.*

Hence, h i Pr *∃i ∈* [q]*,*ans[*Q*[*i*]] = ans

(*i*) [*Q*[*i*]] *̸*= Πe
*⋆* [*Q*[*i*]] *≤* q *·* 2 *−C* *.*

Setting *C* = log <u>q</u> *ϵ* gives us the desired bound. **Soundness analysis from Lemma 2.** Similar to Section 2.2.2, we wish to upper bound the soundness error of Kilian[PCP*,*VC]. As claimed in Theorem 2, we argue that for every instance ① *∈/ L*(*R*), time bound *t*ARG*∈* N, and *t*ARG-size adversary *P*e, h i Pr *P*e*, V*(①) = 1 *≤ ϵ*PCP(①) + *ϵ* *⋆* VC(*λ,ℓ,*q*,t* *⋆* VC) + *ϵ .*

Using the law of total probability, the above probability can be bounded by  e *⋆*   e *⋆*  V Π (①;*ρ*) = 1 V Π (①;*ρ*) *̸*= 1 Pr  *∧* V[*Q,*ans](①;*ρ*) = 1  + Pr  *∧* V[*Q,*ans](①;*ρ*) = 1 *.* *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1 *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1

The term on the left is bounded by *ϵ*PCP(①) (the soundness error of PCP) using similar reasoning as in Section 2.2.2. The term on the right can be bounded by Lemma 2 and the expected-time position binding error of the VC. Another application of the law of total probability gives  e *⋆*  V Π (①;*ρ*) *̸*= 1 Pr  *∧* V[*Q,*ans](①;*ρ*) = 1  *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1     Π e *⋆*Πe *⋆* V (①;*ρ*) *̸*= 1 V (①;*ρ*) *̸*= 1 [*Q,*ans] [*Q,*ans]  *∧* V (①;*ρ*) = 1   *∧* V (①;*ρ*) = 1  = Pr   + Pr    *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1   *∧*VC*.*Check(cm*, Q,* ans*,*pf) = 1  *∧∀i ∈* [q]*,*ans[*Q*[*i*]] = ans

(*i*) [*Q*[*i*]] *∧∃ i ∈* [q]*,*ans[*Q*[*i*]] *̸*= ans
(*i*) [*Q*[*i*]]
X h i *≤ ϵ* + Pr ans[*Q*[*i*]] *̸*= ans

(*i*) [*Q*[*i*]]*.*
*i∈*[q]

The term on the right can be bounded by q *· ϵ* *⋆* VC(*λ,ℓ,*q*,t* *⋆* VC= *O*(log <u>q</u> *ϵ* *·* (*t* *⋆* ARG+ *ℓ · t*V))) from the expected-time position binding property of the VC.

(*i*)
**Extension to PCPs with adaptive verifiers.** The above *A*VCconstruction only works for PCPs with non- adaptive verifiers because we cannot compute the query set as in Item 4a for adaptive PCP verifiers. However,

(*i*)
we can adapt the construction of *A*VCto work for adaptive PCP verifiers as follows.

(*i*)
*A*VC(*ρ*):

1.Run cm *← P*e(①) and (*Q,* ans*,*pf) *← P*e(*ρ*).
2.Check that VC*.*Check(cm*, Q,* ans*,*pf) = 1. If not, output (cm*,*ans*,*ans*, Q, Q,* pf*,*pf).
3.Define *q* := *Q*(*i*) and set *j* := 0.
4.Repeat the following:
(a)Repeatedly sample *ρ*
*′* *←{*0*,*1*}* r and run (*Q* *′* *,*ans *′* *,*pf *′* ) *← P*e(*ρ* *′* ) until the following holds:

i. *q ∈Q* *′*, and ii. VC*.*Check(cm*, Q*
*′* *,*ans *′* *,*pf *′*

) = 1.
(b)Run (*Q*
*′* *,*ans *′* *,*pf *′* ) *← P*e(*ρ* *′* ).

(c)If ans[*q*] *̸*= ans
*′* [*q*], output (cm*, Q,* ans*,*pf*, Q* *′* *,*ans *′* *,*pf *′* ).

(d)If ans[*q*] = ans
*′* [*q*], set *j* := *j* + 1. Further, if *j* = *C*, output (cm*,*ans*,*ans*, Q, Q,* pf*,*pf).

(*i*)
By a similar analysis (details in Section 6.1), we can conclude that, for the above *A*VC,

*t* *⋆* VC= *C · ℓ · t* *⋆* ARG*.*

(*i*)
The rest of the analysis can be directly applied to the new construction of *A*VC.

(*i*)
**Remark 4.** When the underlying PCP has an adaptive verifier, the expected running time of *A*VCcannot be better than *C · ℓ · t* *⋆* ARG. Consider a PCP with proof length *ℓ* and query complexity q. Assume that the PCP verifier is adaptive and the query distribution is almost uniform. Then, in order to sample a randomness that queries a fix location *q* as in Item 4a, the expected number of iterations is roughly *ℓ*. Since each iteration runs the argument e,(*i*) *⋆* adversary *P A*VChas expected running time *C · ℓ · t*ARGfor this PCP.

**Remark 5** (Comparison with [BG08])**.** [BG08] gives a formal analysis of a variant of Kilian’s protocol based on a *non-adaptive* and *reverse-samplable* PCP and a collision-resistance hash function. Their analysis shares similarities with our analysis in this section; both analyses construct the adversaries to the vector commitment scheme and to the PCP separately, contrary to the approach in Section 2.2. Nevertheless, our analysis in this section deviates from the analysis in [BG08] (and other previous analyses) due to the differences below.

- Our analysis considers VC adversaries that run in expected running time while [BG08] considers strict running time. As a result, [BG08] crucially relies on the PCP’s non-adaptivity and reverse sampler, as they cannot construct an efficient strict-time collision finder without these. Instead, our analysis works for all PCPs.
- The rewinding algorithm in [BG08] uses the PCP reverse sampler. For every location *q ∈* [*ℓ*], they reverse sample several PCP randomness strings that query *q* and record an answer only if *P*e opens to it sufficiently often. This construction has a tradeoff between the running time and error probability similar to our reductor in Section 2.2 (the
<u>1</u> *ϵ* blowup in the VC adversary time versus the additive error *ϵ*). In contrast, our reductor in this section searches over all PCP randomness strings to find the “best” PCP string according to *P*e’s answers. This difference allows us to significantly mediate this tradeoff: to achieve an additive error of *ϵ*, the expected running time of our VC adversary only has a blowup of log <u>1</u> *ϵ*. Unfortunately, while [BG08]’s analysis gives knowledge soundness guarantee, ours in this section does not. We discuss in Section 2.5 how to extend our strict-time soundness analysis in Section 2.2 to prove knowledge soundness.

### 2.4 Lower bounds from the Schnorr identification scheme

We discuss how to prove Theorem 3, and the connection to Schnorr’s protocol

### 2.4.1 Review: the Schnorr identification scheme

Let GroupGen be a group generation algorithm that, given a security parameter *λ*, samples a tuple (G*,p,g*) where G is a group of prime order *p ≥* *λ* and *g* is a generator of the group. The Schnorr identification scheme

[Sch89; Sch91] is of a tuple of algorithms IDSchnorr= (P*,*V) where, for a random ✇ in Z*p*, the prover P receives the instance ① = ((G*,p,g*)*,h* = *g* ✇ *∈* G) and witness ✇, and the verifier V receives the instance ①. Then P and V interact as follows.

1. P samples a random element *r ←* Z*p*, computes its first message *α* := *g*
*r* *∈* G, and sends *α* to V.

2. V samples a random challenge *β ←* Z*p*and sends it to P.
3. P computes its second message *γ* := ✇ *· β* + *r* mod *p* and sends it to V.
4. V checks that *g*
*γ* = *α · h* *β*.

We say that IDSchnorrhas error *ϵ*Schnorrif for every time bound tID*∈* N and tID-time adversary Pe,  *λ*  (G*,p,g*) *←* GroupGen(1 )  ✇ *←* Z *p*  Pr   *⟨*P e(①)*,*V(①)*⟩* = 1 ✇   *≤ ϵ*Schnorr(*λ,*tID)*.* *h* := *g* ① := ((G*,p,g*)*,h*)

The security of the Schnorr identification scheme is based on the hardness of the *discrete logarithm problem* (it is hard for any time-bounded adversary, given a random *y ∈* G, to find *x ∈* Z*p*such that *y* = *g* *x* ). The protocol has special soundness meaning that one can efficiently compute the discrete logarithm when given two valid interaction transcripts. Thus, given a transcript of the protocol, the security reduction rewinds the adversary in order to obtain an additional accepting transcript and then extracts a witness. The analysis uses the *forking* *lemma* [PS00] to bound the success probability of the second invocation of the adversary (conditioned on a successful first invocation).

### 2.4.2 VC scheme from the Schnorr identification scheme

While Kilian’s protocol shares a similar structure with sigma protocols like the Schnorr identification scheme (prover’s commitment, verifier’s challenge, and prover’s opening), Kilian’s protocol is *not* a sigma protocol. Nevertheless, we show how to construct a VC scheme whose security is based on that of the Schnorr identification scheme, and later we will see how to connect this to the security of Kilian’s protocol. Recall that the position binding property ensures that the probability for any time-bounded adversary to find two inconsistent openings for the same location is bounded. On the other hand, the security of the Schnorr identification scheme relies on the fact that the it is hard for any time-bounded adversary to find two accepting transcripts of the protocol. Therefore, the VC scheme we construct reduces finding inconsistent answers to finding accepting Schnorr transcripts, which ensures position binding from the hardness of discrete logarithm. We construct VC = (VC*.*Commit*,*VC*.*Open*,*VC*.*Check) as follows. (Our VC only supports messages of length 1.) Recall that in this section, we omit the algorithm for VC that samples the public parameters. For this construction, the public parameter consists of a description (G*,p,g*) of a group generated by GroupGen given the security parameter *λ*, and a random group element *h ∈* G.

- VC*.*Commit(*m*):
1.Sample *r ←* Z*p*.
2.Set cm := *g*
*r*.

3.Set aux := (*r,m*).
4.Output (cm*,*aux).
- VC*.*Open(aux = (*r,m*)*, {*1*}*): Output pf := *r* + *m*.
- VC*.*Check(cm*, {},* ans*,*pf): Check that *g*
pf = cm *· h* ans.

Consider a VC adversary *A*VCthat outputs (cm*, Q* = *{}, Q* *′* = *{},* ans*,*ans *′* *,*pf*,*pf *′* ) such that

- ans *̸*= ans
*′*,

- *g* pf = cm *· h*
ans, and pf *′* ans*′*

- *g* = cm *· h*. Then, one can recover *x ∈* Z*p*such that *h* = *g*
*x* :

*x* := (pf *′* *−* pf) *·* (ans *′* *−* ans) *−*1 *.*

We can conclude that VC has position binding error *ϵ*VCsuch that

*ϵ* VC(*λ,*1*,*1*,t*VC) *≤ ϵ*DLOG(*λ,O*(*t*VC))*.*

### 2.4.3 Security reduction from Kilian to Schnorr

We explain how to connect the security of Kilian’s protocol to the security of the Schnorr identification scheme. The VC scheme that we consider is described above. We are left to fix a PCP. Since the VC scheme works for messages of length 1, the PCP we consider has proof length 1. Moreover, we ensure that the PCP has very small soundness error, so that the dominant term will come from the VC scheme. In more detail, we consider a PCP system PCP for the empty relation *R* = *∅* with alphabet Σ = *{*0*,*1*}* *λ*, proof length *ℓ* = 1, query complexity q = 1, and verifier randomness complexity r = *λ*. For every instance ①, given a PCP proof Πe *∈* Σ, the PCP verifier V works as follows:

Π e V (①):

1.Sample randomness *ρ ←{*0*,*1*}*
*λ*.

2.Check that Π = e *ρ*.
The soundness error of PCP is *ϵ*PCP= 2 *−λ*. Let ARG := Kilian[PCP*,*VC]. Consider the optimal adversary Pe for the Schnorr identification scheme. We construct an argument adversary *P*e against the argument verifier for Kilian’s protocol. Note that the argument adversary *P*e has access to the public parameter for the VC scheme in Section 2.4.2, which consists of ((G*,p,g*)*,h*) where (G*,p,g*) is sampled by GroupGen and *h ∈* G is a random group element.

*P* e:

1. *P*e’s commitment:
(a)Set the instance ①Schnorr:= ((G*,p,g*)*,h*) (using the public parameter of VC).
(b)Run (*α,* aux) *←* Pe(①Schnorr).
(c)Output (cm*,*aux) := (*α,* aux).
2. *P*e’s opening given verifier challenge *ρ*:
(a)Run *γ ←* Pe(aux*,ρ*).
(b)Output (*Q* := *{*1*},* ans := *ρ,* pf = *γ*).
The running time of *P*e is *O*(tID), where tIDis the running time of Pe. Moreover, *⟨P*e*, V*(①)*⟩* = 1 if and only if *⟨*P e(① Schnorr)*,*V(①Schnorr)*⟩* = 1. Hence, we conclude that for every instance ① *∈/ L*(*R*) the following holds:

*ϵ* Schnorr(*λ,*tID) *≤ ϵ*ARG(*λ,*①*,O*(tID))*.*

Similarly, in the expected-time setting, we can show that

*ϵ* *⋆* Schnorr(*λ,t* *⋆* ID) *≤ ϵ* *⋆* ARG(*λ,*①*,O*(*t* *⋆* ID))*.*

### 2.5 Knowledge soundness analysis of Kilian’s protocol

We wish to upper bound the knowledge soundness error of Kilian[PCP*,*VC]. As claimed in Section 1.1, we argue that, for every *ϵ >* 0, there exists a probabilistic extractor *E* that runs in time *O* <u>ℓ</u> *ϵ* *· t*ARGsuch that, for every instance ①, time bound *t*ARG*∈* N, and *t*ARG-size adversary *P*e, " # *b* = 1 *b ← P* e*, V*(①) Pr *P* e*≤ κ*PCP(①) + *ϵ*VC(*λ,ℓ,*q*,t*VC) + *ϵ .* *∧*(①*,*✇) *∈/ R* ✇ *←E* (①)

By construction of the argument verifier *V*, the above probability is equivalent to the following:   [*Q,*ans] cm *← P*e  V (①;*ρ*) = 1 *ρ ←{*0*,*1*}* r    Pr  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 e *.*  (*Q,* ans*,*pf) *← P*(*ρ*)  *∧*(①*,*✇) *∈/ R* *P* e ✇ *←E* (①)

We construct *E* using the PCP prover Pe described in Section 2.2.2 and the PCP extractor E (which is given by the underlying PCP system):

*P* e *E* (①):

1.Run Πe *←* Pe.
2.Output ✇ *←* E(①*,*Π) e.
Using the law of total probability,   [*Q,*ans] cm *← P*e  V (①;*ρ*) = 1 *ρ ←{*0*,*1*}* r    Pr  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 e   (*Q,* ans*,*pf) *← P*(*ρ*)  *∧*(①*,*✇) *∈/ R* *P* e ✇ *←E* (①)  e e   e e  V [*Q,*Π] (①;*ρ*) = 1 V [*Q,*Π] (①;*ρ*) *̸*= 1  *∧* V [*Q,*ans] (①;*ρ*) = 1   *∧* V [*Q,*ans] (①;*ρ*) = 1  = Pr     + Pr    *,* *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 *∧*(①*,*✇) *∈/ R ∧*(①*,*✇) *∈/ R*

where the last two probabilities are with respect to the experiment   cm *← P*e  *ρ ←{*0*,*1*}* r     e   (*Q,* ans*,*pf) *← P*(*ρ*) *.*  e e   Π *←* P  ✇ *←* E(①*,*Π) e

The term on the right is bounded by *ϵ*VC(*λ,ℓ,*q*,t*VC) + *ϵ* due to Lemma 1. The term on the left is bounded by *κ*PCP(①) (the knowledge soundness error of PCP) as shown below:

 e e  V [*Q,*Π] (①;*ρ*) = 1  *ρ ←{*0*,*1*}* r   *∧* V [*Q,*ans] (①;*ρ*) = 1  V Π e (①;*ρ*) = 1 Pr     *≤* Pr  Πe *←* Pe  *≤ κ*PCP(①)*.* *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 *∧*(①*,*✇) *∈/ R* e ✇ *←* E(①*,*Π) *∧*(①*,*✇) *∈/ R*

### 2.6 Succinct interactive arguments with adaptive security

For simplicity, we described our security analyses in the *plain model*, where there are no public parameters available to all parties; in particular, the argument verifier is responsible for sampling and sending VC’s public parameters to the argument prover. However, in the technical sections (Sections 5 to 7) we prove stronger versions of Theorems 1 and 2 that hold *with adaptive security in the common reference string (CRS) model*. An interactive argument in the CRS model includes an additional algorithm: a trusted *generator algorithm* that samples public parameters pp for the argument prover and argument verifier (which can be used any number of times across different interactions). After that, based on pp, a malicious argument prover can choose the instance on which to interact with the argument verifier. This setting necessitates appropriate definitions of *adaptive* soundness and knowledge soundness (see Section 3.1), which require error bounds to hold for any instance ① chosen by the malicious argument prover up to an instance size bound *n*. 6 In particular, the (soundness and knowledge soundness) error bounds depend on *n* rather than ①. We achieve adaptive security in the CRS model by following the structure sketched in the sections above, with only syntactic modifications due to the different target definitions. (E.g., modifying experiments to replace a fixed instance ① with an instance size bound *n*, and letting the malicious argument prover choose the instance.) Overall, the (formal) statements provided in the technical sections (Sections 5 to 7) are stronger than the (informal) statements in Theorems 1 and 2 because we achieve adaptive security in the CRS model. 7

For consistency, the formal statement of Theorem 3 (our lower bounds for Kilian’s protocol) in the technical section (Section 8) is also proved in the setting of adaptive security in the CRS model. Nevertheless, as noted in Remark 8.12, the results hold even for non-adaptive security, which is an even stronger statement.

6 For convenience, we use soundness and knowledge notions for the PCPs in which the malicious prover chooses the instance (see Section 3.3). In to the information-theoretic setting, these definitions are equivalent to the standard ones with fixed instances. Adaptive security in the CRS model directly implies security in the plain model. Since no CRS is allowed, the argument verifier can begin the interaction by running itself the generator algorithm and sending the public parameters for the argument system to the argument prover. See Remark 3.7.

## 3 Preliminaries

**Definition 3.1.** *A* **relation** *R is a set of pairs* (①*,*✇) *where* ① *is an instance and* ✇ *a witness. The corresponding* **language** *L*(*R*) *is the set of instances* ① *for which there exists a witness* ✇ *such that* (①*,*✇) *∈ R.*

### 3.1 Interactive arguments

An *interactive argument* (in the common reference string model) for a relation *R* is a tuple of polynomial-time algorithms ARG = (*G, P, V*) that satisfies the following properties.

**Definition 3.2** (Perfect completeness)**.** ARG = (*G, P, V*) *for a relation R has* **perfect completeness** *if for every* *security parameter λ ∈* N*, instance size bound n ∈* N*, public parameter* pp *∈G*(1 *λ* *,n*)*, and instance-witness* *pair* (①*,*✇) *∈ R with |*①*|≤ n,*

Pr *P*(pp*,* ①*,*✇)*, V*(pp*,*①) = 1 = 1*.*

**Definition 3.3** (Adaptive soundness)**.** ARG = (*G, P, V*) *for a relation R has* **(adaptive strict-time) soundness** **error** *ϵ*ARG*if for every security parameter λ ∈* N*, instance size bound n ∈* N*, auxiliary input distribution D,* *adversary time bound t*ARG*∈* N*, and t*ARG*-time algorithm P*e*,*  *λ*  pp *←G*(1*,n*)  *|*①*|≤ n* *η ←D*  Pr   *∧* ① *∈/ L*(*R*) e   *≤ ϵ*ARG(*λ,n,t*ARG)*.* (①*,*aux) *← P*(pp*,η*) *∧ b* = 1 *b ← P*e(aux)*, V*(pp*,*①)

**Definition 3.4** (Adaptive expected-time soundness)**.** ARG = (*G, P, V*) *for a relation R has* **(adaptive) expected-** **time soundness error** *ϵ*ARG*if for every security parameter λ ∈* N*, instance size bound n ∈* N*, auxiliary input* *distribution D, adversary time bound t*ARG*∈* N*, and algorithm P*e *with expected running time t* *⋆* ARG*,*  *λ*  pp *←G*(1*,n*)  *|*①*|≤ n* *η ←D*  *⋆ ⋆* Pr   *∧* ① *∈/ L*(*R*) e   *≤ ϵ*ARG(*λ,n,t*ARG)*.* (①*,*aux) *← P*(pp*,η*) *∧ b* = 1 *b ← P*e(aux)*, V*(pp*,*①)

**Definition 3.5** (Adaptive knowledge soundness)**.** ARG = (*G, P, V*) *for a relation R has* **(adaptive) knowledge** **soundness error** *κ*ARG**with extraction time** *tEif there exists a probabilistic algorithm E such that for every* *security parameter λ ∈* N*, instance size bound n ∈* N*, auxiliary input distribution D, adversary time bound* *t* ARG*∈* N*, and t*ARG*-time algorithm P* e*,*  *λ*  pp *←G*(1*,n*)  *η ←D*   *|*①*|≤ n*   (①*,*aux) *← P*e(pp*,η*)  Pr  *∧*(①*,*✇) *̸∈ R*  *≤ κ*ARG(*λ,n,t*ARG);  tr e   *∧ b* = 1 *b ←− P*(aux)*, V*(pp*,*①)  *P* e (aux) ✇ *←E* (pp*,* ①*,*tr)

*moreover, E runs in time tE*(*λ,n,t*ARG)*.* tr e(aux) Above, *b ←− ⟨P, V*(pp*,*①)*⟩* denotes the fact that tr is the transcript of the interaction (i.e., public e and*P* e parameters and messages exchanged between *P V*). Moreover, *E* means that *E* has black-box access to (each next-message function of) *P*e; in particular *E* can send verifier messages to *P*e in order to obtain the next message of *P*e (for a partial interaction where *V* sent those messages). Moreover, we can assume, without loss of generality, that *P*e is deterministic relative to auxiliary input *η* (as the internal coin flips of a probabilistic *P*e can be incorporated into the auxiliary input distribution *D*).

**Remark 3.6.** The argument generator *G* receives two inputs: the security parameter *λ* and an instance size bound *n*. This means that the public parameter sampled by *G* may work only for instances of size at most *n*. However, one could consider the stronger notion where the sampled public parameter works for all instance sizes; in this case *G* receives only *λ* as input. Our analysis works for both cases; see Remark 4.2.

**Remark 3.7** (plain model variant)**.** The above definitions consider interactive arguments in the *common reference* *string model*, where a generator samples a public parameter used by the argument prover and the argument verifier. One could also consider interactive arguments in the *plain model*, where there is no generator. This latter notion is implied, at the cost of an additional verifier message, as we now explain. Suppose that (*G, P, V*) is an interactive argument in the common reference string model. We describe an interactive argument (*P* *′* *, V* *′* ) in the plain model with an additional verifier message. The argument prover *P* *′*

receives as input an instance ① and witness ✇, and the argument verifier *V* *′* receives as input the instance ①; both also receive as input the security parameter *λ* (in unary). They interact as follows:

|′||λ|′|
|---|---|---|---|
|′ ′||′ ′||
||||8|

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
- VC*.*Check(pp*,*cm*, Q,* ans*,*pf) *→ {*0*,*1*}*: On input a public parameter pp, a commitment cm, a query set *Q⊆* [*ℓ*], an answer string ans *∈* Σ
*Q*, and an opening proof string pf, VC*.*Check determines if pf is a valid proof for ans *∈* Σ *Q* being a restriction of the message committed in cm to *Q*.

The vector commitment scheme VC must satisfy perfect completeness and position binding.

**Definition 3.8** (Completeness)**.** VC = (Gen*,*Commit*,*Open*,*Check) *has* **perfect completeness** *if for every* *security parameter λ ∈* N*, message length ℓ ∈* N*, message m ∈* Σ *ℓ* *, and query set Q⊆* [*ℓ*]*,*  *λ*  pp *←* VC*.*Gen(1*,ℓ*) Pr VC*.*Check(pp*,*cm*, Q,m*[*Q*]*,*pf) = 1 (cm*,*aux) *←* VC*.*Commit(pp*,m*)  = 1*.* pf *←* VC*.*Open(pp*,*aux*, Q*)

**Definition 3.9** (Position binding)**.** VC = (Gen*,*Commit*,*Open*,*Check) *has* **(strict-time) position binding error** *ϵ* VC*if for every security parameter λ ∈* N*, message length ℓ ∈* N*, query set size s ∈* N *with s ≤ ℓ, auxiliary input* *distribution D, adversary time bound t*VC*∈* N*, and t*VC*-time algorithm A*VC*,*  *′ λ*  *|Q|* = *|Q |* = *s* pp *←* VC*.*Gen(1*,ℓ*)  *∧∃ i ∈Q∩Q′*: ans[*i*] *̸*= ans*′*[*i*] *η ←D*  Pr  *′*   *≤ ϵ*VC(*λ,ℓ,s,t*VC)*.* *∧* VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 cm*,*ans*,*ans*,* *′ ′ ′ ′ ′← A*VC(pp*,η*) <u>∧ VC.Check(pp,cm, Q,ans,pf</u>) = 1 *Q, Q,*pf*,*pf These standard definitions can be derived from Definitions 3.2, 3.3 and 3.5 by setting pp to be empty.

**Definition 3.10** (Expected-time position binding)**.** VC = (Gen*,*Commit*,*Open*,*Check) *has* **expected-time** **position binding error** *ϵ* *⋆* VC*if for every security parameter λ ∈* N*, message length ℓ ∈* N*, query set size s ∈* N *with s ≤ ℓ, auxiliary input distribution D, adversary time bound t* *⋆* VC*∈* N*, and an algorithm A*VC*with expected* *running time t* *⋆* VC*,*  

|′|||λ|
|---|---|---|---|
||′|′||
|||′ ′ ′|′ ′|

*|Q|* = *|Q |* = *s* pp *←* VC*.*Gen(1*,ℓ*)  *∧∃ i ∈Q∩Q* : ans[*i*] *̸*= ans [*i*] *η ←D*  *⋆ ⋆* Pr     *≤ ϵ*VC(*λ,ℓ,s,t*VC)*.* *∧* VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 cm*,*ans*,*ans*,* *′← A*VC(pp*,η*) *∧* VC*.*Check(pp*,*cm*, Q,*ans*,*pf) = 1 *Q, Q,*pf*,*pf

**Remark 3.11** (Monotonicity of *ϵ*VC)**.** We assume hereafter that the position binding error *ϵ*VCis monotone in each coordinate in the natural direction:

- *ϵ*VC(*·,ℓ,s,t*VC) is non-increasing (larger security parameters decrease an adversary’s success);
- *ϵ*VC(*λ, ·,s,t*VC) is non-decreasing (opening some set in a string is easier than opening in a substring);
- *ϵ*VC(*λ,ℓ, ·,t*VC) is non-decreasing (finding a collision in a set is easier than finding one in a subset); and
- *ϵ*VC(*λ,ℓ,s, ·*) is non-decreasing (the success of an adversary increases with its computational power). The last condition is trivially satisfied, while the first should also hold in any reasonable commitment scheme. The remaining two are natural (and satisfied in the case of Merkle commitment schemes); in any case, otherwise one may replace, in our computations, expressions of the type *ϵ*VC(*λ,ℓ*max*,s*max*,t*VC), when *ℓ*max= max*i{ℓi}* and *s*max= max*j{sj}*, with
max *{ϵ*VC(*λ,ℓi,sj,t*VC)*}.* *i,j*

Analogously, we assume the expected-time position binding error *ϵ* *⋆* VChas monotonicity as well.

### 3.3 Probabilistically checkable proofs

A *probabilistically checkable proof* (PCP) is an information-theoretic proof system where a probabilistic verifier has oracle access to a proof string.

**Definition 3.12** (Completeness)**.** PCP = (P*,*V) *for a relation R has* **perfect completeness** *if, for every* *instance-witness pair* (①*,*✇) *∈ R,*

ΠΠ *←* P(①*,*✇) Pr V (①;*ρ*) = 1r= 1*.* *ρ ←{*0*,*1*}*

**Definition 3.13** (Soundness)**.** PCP = (P*,*V) *for a relation R has* **soundness error** *ϵ*PCP*if, for every (unbounded)* *circuit* Pe *and auxiliary input distribution* D*,*   *|*①*|≤ n* ai *←* D Pr  *∧* ① *̸∈ L*(*R*) (①*,*Π) e *←* Pe (ai)  *≤ ϵ*PCP(*n*)*.* Π e r *∧* V (①;*ρ*) = 1 *ρ ←{*0*,*1*}*

**Definition 3.14** (Knowledge soundness)**.** PCP = (P*,*V) *for a relation R has* **knowledge soundness error** *κ*PCP**with extraction time** *t*E*if there exists a probabilistic algorithm* E *such that, for every adversary* Pe *and* *auxiliary input distribution* D*,*   ai *←* D *|*①*|≤ n*  (①*,*Π) e *←* Pe (ai)  Pr   *∧*(①*,*✇) *̸∈ R* r   *≤ κ*PCP(*n*); Π e*ρ ←{*0*,*1*}* *∧* V (①;*ρ*) = 1 e ✇ *←* E(①*,*Π)

### moreover, E runs in time tE(n).

We consider several efficiency measures for a PCP:

•the *proof alphabet* Σ is the alphabet over which a PCP string is written; •the *proof length ℓ* is the number of alphabet symbols in the PCP string;

- the *query complexity* q *∈* [*ℓ*] is the number of queries that the PCP verifier makes to the PCP string (each query is an index in [*ℓ*] and is answered by the corresponding symbol in Σ in the PCP string); •the *randomness complexity* r is the number of random bits used by the PCP verifier. An efficiency measure may be a function of the instance ① (e.g., of its size *|*①*|*).

## 4 Kilian’s protocol

The construction of (*G, P, V*) := Kilian[PCP*,*VC] is specified below.

**Construction 4.1.** The argument generator *G* receives as input a security parameter *λ ∈* N and an instance size bound *n ∈* N, and works as follows.

*G*(*λ,n*): *λ*

1.Sample public parameter for the VC scheme: ppVC*←* VC*.*Gen(1*,ℓ*(*n*)).
2.Set public parameter for the interactive argument: pp := ppVC.
3.Output pp.
The argument prover *P* receives as input the public parameter pp, an instance ① and a witness ✇, and the argument verifier *V* receives as input the public parameter pp and the instance ①. Then *P* and *V* interact as follows.

1. *P*’s commitment.
(a)Compute a PCP string: Π *←* P(①*,*✇).
(b)Compute a vector commitment to the PCP string: (cm*,*aux) *←* VC*.*Commit(pp*,*Π).
(c)Send cm to *V*.
2. *V*’s challenge.
r

(a)Sample PCP verifier randomness: *ρ ←{*0*,*1*}*.
(b)Send *ρ* to *P*.
3. *P*’s response.
Π

(a)Run the PCP verifier V (①;*ρ*) to deduce its query set *Q⊆* [*ℓ*].
(b)Compute a VC opening proof: pf *←* VC*.*Open(pp*,*aux*, Q*).
(c)Set ans := Π[*Q*].
(d)Send (*Q,* ans*,*pf) to *V*.
[*Q,*ans]

4. *V*’s decision: check that V (①;*ρ*) = 1 and VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1. The interactive argument consists of three messages: a prover message; a verifier message; and a prover message. The interactive argument is public-coin since the verifier’s (only) message is a uniform random string. The efficiency measures of interactive arguments are as follows: •the generator outputs public parameter of size *|*ppVC*|* bits; •the prover-to-verifier communication consists of *|*cm*|* + q *·* (log*ℓ* + log*|*Σ*|*) + *|*pf*|* bits; •the verifier-to-prover communication consists of r bits; •the time complexity of the argument generator is *t*VC*.*Gen. •the time complexity of the argument prover is *t*P+ *t*VC*.*Commit+ *t*V+ *t*VC*.*Open; •the time complexity of the argument verifier is *t*V+ *t*VC*.*Check. **Remark 4.2.** There are vector commitments for which VC*.*Gen needs only the security parameter *λ* as input (i.e., VC*.*Gen works for every message size); for example, Merkle commitment schemes are vector commitment schemes with this property, because the public parameter consists of (the description of) a hash function, which suffices for every message size. In this case, the argument generator *G* in Construction 4.1 requires only *λ* as input and works for every instance size. This leads the notion of an interactive argument discussed in Remark 3.6. **Remark 4.3.** In the plain-model variant of Construction 4.1 (see Remark 3.7), the public parameters pp := ppVC are sampled and sent by the argument verifier (resulting in a four-message protocol). Hence the plain-model variant is public-coin if (and only if) VC*.*Gen is a public-coin algorithm (its output includes all of its randomness).

## 5 Strict-time security analysis

### Theorem 5.1. Consider these two ingredients:

- PCP = (P*,*V)*, a PCP system for a relation R with alphabet* Σ*, proof length ℓ, and query complexity* q*; and*
- VC = (Gen*,*Commit*,*Open*,*Check)*, a vector commitment scheme over alphabet* Σ*.* *Then* ARG = (*G, P, V*) := Kilian[PCP*,*VC] *(Construction 4.1) is a three-message public-coin interactive* *argument system for R, whose soundness error ϵ*ARG*and knowledge soundness error κ*ARG*satisfy the following* *for every ϵ >* 0 *and t*ARG*≥ t*V+ *t*VC*.*Check+ log*|*Σ*|* + log *ℓ:*
*ϵ* ARG(*λ,n,t*ARG) *≤ ϵ*PCP(*n*) + *ϵ*VC(*λ,ℓ,*q*,t*VC) + *ϵ and* *κ*ARG(*λ,n,t*ARG) *≤ κ*PCP(*n*) + *ϵ*VC(*λ,ℓ,*q*,t*VC) + *ϵ .*

*Above, ϵ*PCP*and κ*PCP*are the soundness and knowledge soundness errors of* PCP*, and t*VC= *O* <u>ℓ</u> *ϵ* *· t*ARG*.* *Moreover, the knowledge extractor runs in time tE*= *O*(*t*E+ *t*VC)*.*

**Corollary 5.2.** *Let* ARG *be as in Theorem 5.1. Assume that for any n ∈* N*, ϵ*VC(*·, ·, ·,t*VC) = negl(*n*) *if* *t* VC= poly(*n*)*. Then, given that t*ARG= poly(*n*)*, we have*

*ϵ* ARG(*λ,n,t*ARG) *≤ ϵ*PCP(*n*) + negl(*n*) *and* *κ*ARG(*λ,n,t*ARG) *≤ κ*PCP(*n*) + negl(*n*)*.*

*Proof.* Let *p*(*n*) be an arbitrary polynomial. We set *ϵ* to be 2*p* <u>1</u>

(*n*) *>* 0. Hence, *t*VC= *O*
<u>ℓ</u> *ϵ* *· t*ARG= poly(*n*), which implies that *ϵ*VC(*λ,ℓ,*q*,t*VC) = negl(*n*). Therefore,

<u>1 1</u> *ϵ* ARG(*λ,n,t*ARG) *≤ ϵ*PCP(*n*) + negl(*n*) + *< ϵ*PCP(*n*) + negl(*n*) +*.* 2*p*(*n*) *p*(*n*)

Since *p* is an arbitrary polynomial, we conclude that

*ϵ* ARG(*λ,n,t*ARG) *≤ ϵ*PCP(*n*) + negl(*n*)*.*

### An analogous argument holds for κARG.

### 5.1 Security reduction

To analyze the soundness and knowledge soundness for the argument system of Construction 4.1, it is important to understand how the argument system is related to the PCP system. The core of the security analysis is the construction of a PCP prover Pe from an argument prover *P*e (which may or may not be malicious). More precisely, given a convincing argument prover *P*e, we want to obtain a convincing PCP prover Pe, which we achieve via the *reductor* algorithm *R* in Construction 5.5. Recall that if *V* accepts if and only if both V and VC*.*Check accept. Hence, Lemma 5.3 shows that PCP strings generated by the reductor *R* are, up to small errors, as convincing to the PCP verifier V as the argument prover *P* is to the argument verifier *V*; in other words, *R* transforms an argument prover *P*e into a PCP prover P

e.9We later use this lemma to prove (adaptive) soundness and knowledge soundness of ARG in Sections 5.2 and 5.3, respectively. 9 Moreover, *R* preserves uniformity: if *P*e is a uniform algorithm, then so is Pe.

**Lemma 5.3.** *There exists a probabilistic algorithm R which, for every ϵ >* 0*, auxiliary input distribution D,* *time bound t*ARG*≥ t*VC*.*Check+ 2q *·* (log*|*Σ*|* + log*ℓ*)*, and t*ARG*-size circuit P*e*, satisfies*  *λ*  pp *←G*(1*,n*)  *η ←D*  [*Q*e*,*Π]e   V (①;*ρ*) = 0 ①*,*(cm*,*aux) *← P*e pp*,η*   [*Q,*ans]  Pr  *∧* V (①;*ρ*) = 1 *P* e(aux*,·*)  (*Q*e*,*Π) e *←R* (pp*,*cm*,ϵ*)   *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 r   *ρ ←{*0*,*1*}*  (*Q,* ans*,*pf) *← P*e(aux*,ρ*)

*≤ ϵ*VC(*λ,ℓ,*q*,t*VC) + *ϵ ,*

*where t*VC= *O* <u>ℓ</u> *ϵ* *· t*ARG*. Moreover, R makes ℓ/ϵ queries to P*e *and runs in O*(*t*VC) *time.*

We stress that in the experiment above the reductor *R* is *independent* of *ρ*, since it does not receive the verifier randomness as input. (Otherwise, the lemma would be satisfied trivially with *Q*e := *Q* and Π[e *Q*e] := ans.) We now construct *R*, which will be convenient to separate into two parts: a sampling subroutine *S* followed by a post-processing layer *R*postthat deterministically pieces together a PCP string Πe from the samples obtained by *S* (and outputs the set *Q*e of “filled-in” coordinates along with Πe).

**Construction 5.4.** We construct the *sampler S* as follows.

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
The algorithm *S* makes N queries to *P*e, and runs in time¹⁰

*t* *S≤* N *·* (*t*ARG+ *t*VC*.*Check) *≤* 2N *· t*ARG*.*

**Construction 5.5.** The *reductor R* is defined as follows. (Below, *σ* is an arbitrary symbol in the alphabet Σ.)

*P* e (aux*,·*) 11 *R* (pp*,*cm*,ϵ*): <u>ℓ</u> *P*e(aux*,·*)

1.Set N :=
*ϵ* and run *K←S* (pp*,*cm*,*N).

2.Run (*Q*e*,*Π) e *←R*post(*K,ℓ*).
3.Output (*Q*e*,*Π) e.
The reductor’s second step is an execution of the following (deterministic) *post-processing* algorithm.

*R*post(*K,ℓ*):

1.Initialize Πe := *σ*
*ℓ* and *Q*e := *∅*.

2.For every (*Q*
*′* *,*ans *′* *,*pf *′* ) *∈K*:

(a)Set *Q*e := *Q∪Q* e
*′*.

(b)For every *q ∈Q*
*′*, set Π[e *q*] := ans *′* [*q*].

10 Note that the 2q(log*|*Σ*|* + log*ℓ*) overhead incurred by copying (*Q* *′* *,*ans *′* *,*pf *′* ) into *K* is accounted for in the difference between *t* ARG and the other terms. We also denote by *R* *P* e(aux*,·*) pp*,*cm*,ϵ*; *ρ*, where *ρ* = (*ρ*

(*ℓ*) ) (and similarly for *S*) the deterministic algorithm that uses *ρ*
(*ℓ*) as
*ℓ∈*[N] the randomness for *S*’s *ℓ*-th sample. This allows the PCP prover of Construction 6.6 to be deterministic.

3.Output (*Q*e*,*Π) e.
Note that *R* makes N = *ℓ/ϵ* queries to *P*e by construction, whose total N *· t*ARGtime dominates that of *R*.

*Proof.* Throughout this proof, probabilistic expressions are with respect to the following experiment unless explicitly denoted otherwise:     *λ λ* pp *←G*(1*,n*) pp *←G*(1*,n*)     *η ←D η ←D*      e     (①*,*aux₀) *← P*(pp*,η*)   ①*,*(cm*,*aux) *← P*e pp*,η*   =e(aux*,·*)*.* (1)  (cm*,*aux₁) *← P*e(aux₀)   (*Q,*e Π) e *←RP*(pp*,*cm*,ϵ*)      r r  *ρ ←{*0*,*1*}*   *ρ ←{*0*,*1*}*  (*Q,* ans*,*pf) *← P*e(aux₁*,ρ*) (*Q,* ans*,*pf) *← P*e aux*,ρ*

Our goal is to upper bound the probability of the following expression:   [*Q,*e eΠ] V (①;*ρ*) = 0  [*Q,*ans] *.* (2) *∧* V (①;*ρ*) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

Observe that Eq. 2 implies that either (i) Πe and ans disagree at a position *q ∈Q∩ Q*e; or (ii) there is a query *q* in *Q\ Q*e. We analyze the two cases separately.

**Valid openings with disagreeing answers.** Our goal is to prove the following bound:

*∃ q ∈Q∩ Q*e : ans[*q*] *̸*= Π[e *q*] Pr *≤ ϵ*VC(*λ,ℓ,*q*,t*VC)*,* *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

where *t*VC*≤* 3N *· t*ARG. Consider the following adversary *A*VCagainst the vector commitment scheme, which follows Experiment 1 (without executing *R*post) and attempts to find a collision using the output *K* of the sampler *S*.

*A*VC(pp*,η*):

1.Run ①*,*(cm*,*aux) *← P*e pp*,η*.
r

2.Sample *ρ ←{*0*,*1*}*.
3.Run (*Q,* ans*,*pf) *← P*e(aux*,ρ*).

|P e(aux,·)||ℓ|||
|---|---|---|---|---|
|′ ′|′|′ ϵ|′ ′|′|

4.Run *K←S* (pp*,*cm*,*N), with N = (as in Construction 5.5).
*′*

5. If there are (*Q,*ans*,*pf) *∈K* and *q ∈Q ∩Q* with ans [*q*] *̸*= ans[*q*], output (cm*,*ans*,*ans*, Q, Q,*pf*,*pf).
6.Otherwise, output (the “dummy” tuple) (cm*,*ans*,*ans*, Q, Q,* pf*,*pf). The time complexity of the sampler *S* is at most 2N *· t*ARGand the collision-finding check (Step 5) runs in
12 time N *·* 2q(log*|*Σ*|* + log*ℓ*) *≤* N *· t*ARG, so the time complexity of *A*VCis *t*VC*≤* 3N *· t*ARG. Therefore, according to Definition 3.9,

*∃ q ∈Q∩ Q*e : ans[*q*] *̸*= Π[e *q*] Pr *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1  

||′||λ|
|---|---|---|---|
||′|′||
|||′ ′ ′|′ ′|
|Searching for an intersection between Q omit the time required to produce the output (which can be accounted for in the running time of S).|and Q takes 2q log ℓ time, while each check for a symbol mismatch takes 2 log|Σ|. We|||

*|Q|* = *|Q |* = q pp *←* VC*.*Gen(1*,ℓ*)  *∧∃ q ∈Q∩Q* : ans[*q*] *̸*= ans [*q*] *η ←D*  = Pr    *∧* VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 cm*,*ans*,*ans*,*  *′← A*VC(pp*,η*) *∧* VC*.*Check(pp*,*cm*, Q,*ans*,*pf) = 1 *Q, Q,*pf*,*pf

*′*

*≤ ϵ*VC(*λ,ℓ,*q*,t*VC)*.*

**Missing positions in** Πe**.** We now upper bound the probability that there is a missing position in Πe; we claim that *Q\ Q̸*e = *∅* Pr *≤ ϵ .* *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

Fix a public parameter-auxiliary input pair (pp*,η*) (recall that these are obtained in the first steps of Experiment 1), and define the *weight* of a coordinate *q ∈* [*ℓ*] with respect to (pp*,η*) as   (①*,*cm*,*aux) *← P*e(pp*,η*) *q ∈Q*r  *δ* pp*,η*(*q*) := Pr  *ρ ←{*0*,*1*}.* *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 (*Q,* ans*,*pf) *← P*e(aux*,ρ*)

Then, by a union bound over *q ∈* [*ℓ*],

*Q\ Q̸*e = *∅* Pr *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

*∃ q ∈* [*ℓ*] : *q ∈Q∧ q /∈ Q*e = Pr *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1     e (①*,*cm*,*aux) *← P*e(pp*,η*)  *∃ q ∈* [*ℓ*] : *q ∈Q∧ q /∈ Q*r  *≤* max Pr  *ρ ←{*0*,*1*}* (pp*,η*)  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 e  (*Q,* ans*,*pf) *← P*(aux*,ρ*)    X  N = max *δ*pp*,η*(*q*) *·* 1 *− δ*pp*,η*(*q*) (pp*,η*)   *q∈*[*ℓ*] <u>ℓ</u> *≤,* N

where the last inequality follows from *δ ·* (1 *− δ*) N *≤* 1*/*N for any *δ ∈* [0*,*1]. 13 Finally, plugging in N = <u>ℓ</u> *ϵ* bounds Eq. 2 as desired, concluding the proof:  e e  V [*Q,*Π] (①;*ρ*) = 0 Pr  *∧* V[*Q,*ans](①;*ρ*) = 1  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

*∃ q ∈Q∩ Q*e : ans[*q*] *̸*= Π[e *q*] *Q\ Q̸*e = *∅* *≤* Pr + Pr *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

### ≤ ϵVC(λ,ℓ,q,tVC) + ϵ.

### 5.2 Adaptive soundness

**Lemma 5.6.** *For every ϵ >* 0*, security parameter λ ∈* N*, instance size bound n ∈* N*, auxiliary input distribution* *D, adversary time bound t*ARG*≥ t*VC*.*Check+ 2q *·* (log*|*Σ*|* + log*ℓ*) *and t*ARG*-size circuit P*e*, the soundness error of* *the argument system in Construction 4.1 satisfies*

*ϵ* ARG(*λ,n,t*ARG) *≤ ϵ*PCP(*n*) + *ϵ*VC(*λ,ℓ,*q*,t*VC) + *ϵ ,*

*where t*VC= *O* <u>ℓ</u> *ϵ* *· t*ARG*.*

A simple derivation of the inequality is the following: with *f* (*x*) = *x ·* (1 *− x*) N, we have <u>d</u> *f* (*δ*) = 0 *⇐⇒ δ* =. As *dx* N+1 *f*(0) = *f*(1) = 0 and *δ* is the only critical point in [0*,*1], it achieves the maximum *f* (*δ*) *≤ /*N.

*Proof.* Recall, from Definition 3.3 and Construction 4.1, that our goal is to upper bound

  *λ* pp *←G*(1*,n*) *|*①*|≤ n*  *η ←D*   *∧* ① *∈/ L*(*R*) Pr  e   (①*,*aux) *← P*(pp*,η*) *∧ b* = 1 *b ← P*e(aux)*, V*(pp*,*①) *λ*  pp *←G*(1*,n*) *|*①*|≤ n*   *η ←D*  *∧* ① *∈/ L*(*R*)   ①*,*(cm*,*aux) *← P*e pp*,η* = Pr  *.*  [*Q,*ans]  *∧* V (①;*ρ*) = 1 r   *ρ ←{*0*,*1*}* *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 e (*Q,* ans*,*pf) *← P*(aux*,ρ*)

e sends cm as the first message in Construction 4.1, the former experiment is equivalent to the latter, (Since *P* where we omit the auxiliary state of the choice of instance and aux denotes that of the first message.) As in Lemma 5.3, we consider the following experiment (a restatement of Experiment 1), which augments the above by executing *R*, and thus leaves the probability unchanged.  *λ*  pp *←G*(1*,n*)  *η ←D*     ①*,*(cm*,*aux) *← P*e pp*,η*     e e*P* e(aux*,·*)*.*  (*Q,* Π) *←R* (pp*,*cm*,ϵ*)   r   *ρ ←{*0*,*1*}*  (*Q,* ans*,*pf) *← P*e(aux*,ρ*)

By total probability,   *|*①*|≤ n*  *∧* ① *̸∈ L*(*R*)  Pr  [*Q,*ans]   *∧* V (①;*ρ*) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1    *|*①*|≤ n |*①*|≤ n*  *∧* ① *̸∈ L*(*R*)   *∧* ① *̸∈ L*(*R*)    [*Q,*e eΠ] [*Q,*e eΠ] = Pr  *∧* V (①;*ρ*) = 1  + Pr  *∧* V (①;*ρ*) = 0  [*Q,*ans]   [*Q,*ans]  *∧* V (①;*ρ*) = 1   *∧* V (①;*ρ*) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans



   *.*   *,*pf) = 1

### with respect to PCP).

**Construction 5.7.** We define the auxiliary input distribution D of the PCP prover P

D:

1.Sample pp *←G*(1
*λ* *,n*) followed by *η ←D* and *ρ* := (*ρ*

(*ℓ*) ) *ℓ∈*[N]*←* (*{*0*,*1*}*
r ) N.

2.Output ai := pp*,η, ρ*.
The PCP prover is then given by the following next message functions.

P e (ai):

1.Parse ai as pp*,η, ρ*.
2.Run (①*,*aux) *← P*e(pp*,η*). We first bound the probability of the leftmost term by the PCP system’s soundness error (i.e., Definition 3.13
### e as follows:

3.Set aux := pp*,*aux₀*, ρ*.
4.Output (①*,*aux). P e (aux):
1.Parse aux as pp*,*aux₀*, ρ*.
2.Run (cm*,*aux₁) *← P*e(aux₀). e e*P*
e (aux1*,·*)

3.Run (*Q,*Π) *←R* pp*,*cm*,ϵ*; *ρ*.
4.Output Πe.
Using Definition 3.13, 14

  *|*①*|≤ n*  *∧* ① *̸∈ L*(*R*)   *|*①*|≤ n*    [*Q,*e eΠ] *∧* ① *̸∈ L*(*R*)  Pr  *∧* V (①;*ρ*) = 1  *≤* Pr   [*Q,*ans]  [*Q* e *,*Π] e  *∧* V (①;*ρ*) = 1  *∧* V (①;*ρ*) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1   *|*①*|≤ n* ai *←* D *≤* Pr  *∧* ① *̸∈ L*(*R*) (①*,*aux) *←* Pe (ai)  Π e e e (aux) *∧* V (①) = 1 Π *←* P

*≤ ϵ*PCP(*n*)*.*

Lastly, an application of Lemma 5.3 yields   *|*①*|≤ n*  *∧*(①*,*✇) *̸∈ R*  [*Q*e*,*Π]e   V (①;*ρ*) = 0 [*Q,*e eΠ] [*Q,*ans]  Pr  *∧* V (①;*ρ*) = 0  *≤* Pr  *∧* V (①;*ρ*) = 1  [*Q,*ans]   *∧* V (①;*ρ*) = 1  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

*≤ ϵ*VC(*λ,ℓ,*q*,t*VC) + *ϵ ,*

where *t*VC*≤* <u>3</u> *ϵ* <u>ℓ</u> *· t*ARG, which concludes the proof.

### 5.3 Adaptive knowledge soundness

**Lemma 5.8.** *For every ϵ >* 0*, security parameter λ ∈* N*, instance size bound n ∈* N*, auxiliary input distribution* *D, adversary time bound t*ARG*≥ t*VC*.*Check+ 2q*·*(log*|*Σ*|*+ log*ℓ*) *and t*ARG*-size circuit P*e*, the knowledge soundness* *error of the argument system obtained by Construction 4.1 satisfies*

*κ*ARG(*λ,n,t*ARG) *≤ κ*PCP(*n*) + *ϵ*VC(*λ,ℓ,*q*,t*VC) + *ϵ ,*

*where t*VC= *O* <u>ℓ</u> *ϵ* *· t*ARG*. If the PCP extractor’s running time is t*E*, the argument system’s extractor is* *t* *E*= *t*E+ *O*(*t*VC)*.*

**Construction 5.9.** Let E be the extractor for PCP. We use Pe (Construction 6.6) and E to construct the knowledge extractor *E* for ARG as follows.

*P* e (aux) *E* (pp*,* ①*,*tr):

1.Sample *ρ ←* (*{,}*
r ) N.

Note that the prover in Definition 3.13 corresponds to the sequential execution of both steps in Construction 6.6.

2.Set aux := pp*,*aux*, ρ* and run Πe *←* Pe (aux).
3.Run ✇ *←* E(①*,*Π) e.
4.Output ✇. Note that *E* executes E once and *P*e for *ℓ/ϵ* times (as Pe runs the reductor *R*, which in turn sets N = *ℓ/ϵ* and
repeats N executions of *P*e). Therefore, *tE*= *t*E+ *O*(*t*VC).

*Proof.* From Definition 3.5 and Construction 4.1, our goal is to upper bound   *λ* pp *←G*(1*,n*)  *η ←D*   *|*①*|≤ n*    Pr  *∧*(①*,*✇) *̸∈ R* (①*,*aux) *← P*e(pp*,η*)   tr   *∧ b* = 1 *b ←− P*e(aux)*, V*(pp*,*①)  *P*e(aux) ✇ *←E* (pp*,* ①*,*tr)   *λ* pp *←G*(1*,n*)  *η ←D*     *|*①*|≤ n*   (①*,*aux )0*← P*e(pp*,η*)   *∧*(①*,*✇) *̸∈ R* e(aux  = Pr  (cm*,*aux₁) *← P*0) *.* [*Q,*ans]  *∧* V (①;*ρ*) = 1r  *ρ ←{*0*,*1*}*   *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1   (*Q,* ans*,*pf) *← P*e(aux₁*,ρ*)  *P*e(aux1) ✇ *←E* (pp*,* ①*,*tr)

Now, note that by Constructions 5.9 and 6.6, the experiment above is equivalent to the following.

  *λ* pp *←G*(1*,n*)  *η ←D*      pp *←G*(1*λ,n*)  (①  *,*aux₀) *← P*e(pp*,η*)    *η ←D*   (cm    *,*aux )1*← P*e(aux )0    r  ①*,*(cm*,*aux) *← P*e pp*,η*   *ρ ←{*0*,*1*}*   r   = *ρ ←{*0*,*1*}* *.*  (*Q,* ans*,*pf) *← P*e(aux₁*,ρ*)    e    (*Q,* ans*,*pf) *← P*(aux*,ρ*)  r N  *ρ ←* (*{*0*,*1*}*)  e(aux*,·*)    (*Q*e*,*Π) e *←RP*(pp*,*cm*,ϵ*)   aux := pp*,*aux₁*, ρ*    ✇ *←* E(①*,*Π) e  Πe *←* Pe (aux) 

### ✇ ← E(①,Π) e

We thus consider the above experiment, which augments that of Lemma 5.3 by appending an execution of E, for the rest of the proof. Note that, as in Lemma 5.6, the experiment consisting of (①*,*aux₀) *← P*e(pp*,η*) followed by (cm*,*aux₁) *← P*e(aux₀) can be replaced by ①*,*(cm*,*aux) *← P*e pp*,η* : since *R* only uses the second auxiliary state (which is obtained deterministically from the first), the former can be omitted. Note, moreover, that the explicit randomness for Pe on the left-hand side is replaced with sampling by *R* on the right-hand side. By total probability,

| |①|≤ n||
|---|---|
| ∧ (①, ✇) ̸∈ R| |
|Pr  ||

[*Q,*ans] *∧* V (①;*ρ*) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

*′*e(aux)). Therefore,

|Note that, by Construction 6.6, P|e only executes P|e(aux) (calls to P|e(aux ,ρ) are continuations of executions of P|
|---|---|---|---|
|an equivalent construction gives P|e oracle access to P|e(aux) (rather than to P|e), excluding aux from aux.|

    *|*①*|≤ n |*①*|≤ n*      *∧*(①*,*✇) *̸∈ R*   *∧*(①*,*✇) *̸∈ R*  [*Q,*e eΠ] [*Q,*e eΠ] = Pr  *∧* V (①;*ρ*) = 1  + Pr  *∧* V (①;*ρ*) = 0 *.*     [*Q,*ans] [*Q,*ans]  *∧* V (①;*ρ*) = 1   *∧* V (①;*ρ*) = 1  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

With the PCP prover Pe in Construction 6.6 and using Definition 3.14, we have   *|*①*|≤ n*     ai *←* D  *∧*(①*,*✇) *̸∈ R*  *|*①*|≤ n*  (①*,*Π) e *←* Pe  [*Q,*e eΠ] Pr  *∧* V (①;*ρ*) = 1  *≤* Pr  *∧*(①*,*✇) *̸∈ R*  *≤ κ* rPCP(*n*)*.*  e*ρ ←{*0*,*1*}* [*Q,*ans] Π  *∧* V (①;*ρ*) = 1  *∧* V (①;*ρ*) = 1 ✇ *←* E(①*,*Π) e *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

### Finally, Lemma 5.3 implies

  *|*①*|≤ n*   [*Q,*e eΠ] [*Q*e*,*Π]e V (①;*ρ*) = 0   *∧* V (①;*ρ*) = 0 Pr   *≤* Pr  *∧* V[*Q,*ans](①;*ρ*) = 1   [*Q,*ans]  *∧* V (①;*ρ*) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

*≤ ϵ*VC(*λ,ℓ,*q*,t*VC) + *ϵ ,*

<u>3ℓ</u> where *t*VC*≤ · t*ARG, which concludes the proof. *ϵ*

## 6 Expected-time soundness analysis

### Theorem 6.1. Consider these two ingredients:

- PCP = (P*,*V)*, a PCP system for a relation R with alphabet* Σ*, proof length ℓ, and query complexity* q*; and*
- VC = (Gen*,*Commit*,*Open*,*Check)*, a vector commitment scheme over alphabet* Σ*.* *Then* ARG = (*G, P, V*) := Kilian[PCP*,*VC] *is a three-message public-coin interactive argument system for R,* *whose soundness error ϵ*ARG*and expected-time soundness error ϵ*
*⋆* ARG*satisfies the following for every ϵ >* 0 *and* *t* ARG*≥ t*VC*.*Check+ log*|*Σ*|* + log*ℓ*

|⋆|⋆|⋆|
|---|---|---|
||qϵ ⋆||
|⋆|||

*ϵ* *⋆* ARG(*λ,n,t*ARG) *≤ ϵ*PCP(*n*) + q *· ϵ*VC(*λ,ℓ,*q*,t*VC) + *ϵ ,*

*where ϵ*PCP*is the soundness error of* PCP *and t* *⋆* VC= *O ℓ ·* log *· t*ARG*.*

It is clear that *ϵ*ARG(*λ,n,t*ARG) *≤ ϵ*ARG(*λ,n,t*ARG), so Theorem 6.1 gives an alternative bound of soundness error of ARG as well.

### 6.1 Security reduction

Similar to Section 5, we prove a slightly different security reduction lemma. We first introduce a few new definitions.

**Definition 6.2.** *For every argument prover P*e*, public parameter* pp*, auxiliary input η ∈D, coordinate q ∈* [*ℓ*] *and σ ∈* Σ*, we define p*pp*,η*(*q,σ*) *as follows:*

  *q ∈Q* ①*,*(cm*,*aux) *← P*e pp*,η* *p*pp*,η*(*q,σ*) := Pr  *∧*ans[*q*] = *σ ρ ←{*0*,*1*}* r *.* *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 (*Q,* ans*,*pf) *← P*e(aux*,ρ*)

*We also define the optimal PCP string* Πe *⋆* pp*,η(with respect to* pp*, η ∈D and P*

e*) by*
Π e*⋆* pp*,η*[*q*] := arg max *{p*pp*,η*(*q,σ*)*},* *σ∈*Σ

### with ties broken lexicographically.

(*i*)
**Lemma 6.3** (Alternative security reduction lemma)**.** *There exist probabilistic algorithms A*VC*for each i ∈* [q] *such that, for every C ∈* N*, adversary time bound t* *⋆* ARG*≥ t*VC*.*Check+ log*|*Σ*|* + log *ℓ and expected t* *⋆* ARG*-time* *adversary P*e*, satisfies*  *λ*  pp *←G*(1*,n*)  *η ←D*    Πe *⋆* pp*,η*①*,*(cm*,*aux) *← P*e pp*,η*   V (①;*ρ*) = 0   [*Q,*ans] r   *∧* V (①;*ρ*) = 1 *ρ ←{*0*,*1*}*  Pr  e  *≤ ϵ .*  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 (*Q,* ans*,*pf) *← P*(aux*,ρ*)  

(*i*)
  *∧∀i ∈* [q]*,*ans[*Q*[*i*]] = ans [*Q*[*i*]] *For i ∈* [q] :     cm*, Q,* ans*,*pf*,*(*i*)

(*i*) (*i*) (*i*)
*← A*VC(pp*,η,ρ*) *Q,*ans*,*pf

(*i*) *⋆* <u>q</u> *⋆*
*Moreover, A*VC*runs in expected time t*VC= *O ℓ ·* log *ϵ* *· t*ARG*for all i.*

(*i*)
We construct *A*VCbelow.

**Construction 6.4.** Given an argument prover *P*e, we construct each adversary *A*(VC*i*)as follows.

(*i*)
*A*VC(pp*,η,ρ*):

1.Run (①*,*cm*,*aux) *← P*e(pp*,η*) and (*Q,* ans*,*pf) *← P*e(aux*,ρ*).
2.Check that VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1. If not, output (cm*,*ans*,*ans*, Q, Q,* pf*,*pf).
3.Define *q* := *Q*(*i*) and set *j* := 0.
4.Repeat the following:
*′* r *′ ′ ′ ′*

|←{0, 1}|and run (Q|, ans, pf|e(aux,ρ ) ← P|).||
|---|---|---|---|---|---|
|′|′ ′|′ ′|′ (i)|′ ′ qϵ|(i)|
||||||pp,η|

(a)Sample *ρ*
*′ ′ ′ ′*

(b)If *q ∈Q* and VC*.*Check(pp*,*cm*, Q,*ans*,*pf) = 1:
*′*

i.If ans[*q*] *̸*= ans [*q*], output (cm*, Q,* ans*,*pf*, Q,*ans*,*pf). ii.If ans[*q*] = ans [*q*], set *j* := *j* + 1. Further, if *j* = log, output (cm*,*ans*,*ans*, Q, Q,* pf*,*pf).
We first analyze the expected running time of *A*VC. For every (pp*,η*) and *q ∈* [*ℓ*], we define *ξ* (*q*) as follows:   ①*,*(cm*,*aux) *← P*e pp*,η*

(*i*)*Q*(*i*) = *q*r
*ξ*  pp*,η*(*q*) := Pr  *ρ ←{*0*,*1*}.* *∧*VC*.*Check(pp*, Q,* ans*,*pf) = 1 (*Q,* ans*,*pf) *← P*e(aux*,ρ*)

P(*i*) Define, also, *ξ*pp*,η*(*q*) := *ξ*pp*,η*(*q*); note that this is the probability of the event *i∈*[q]

[*q ∈Q∧* VC*.*Check(pp*, Q,* ans*,*pf) = 1]

(under the same experiment). Finally, denote by *T* and *M*pp*,η*the distributions of running time of *P*e and the number of iterations of Step 4 in an execution of *A*VC(pp*,η,ρ*), respectively. Note that the conditional expectation <u>q</u> of *M ←M*pp*,η*on the above event is *O* log */ξ*pp*,η*(*q*). *ϵ*

(*i*)P
Then the running time of *A*VC VC*.*Check

||is O M · t|+|T|, where T|←T for all k ∈ [M]. Therefore,|
|---|---|---|---|---|---|
||||k∈[M]|k|k|
|||||λ||
|||pp,η||||
||k|||||
|k∈[M]||k||r||

*k∈*[*M*] *k k*

  pp *←G*(1*,n*)    *M ←M η ←D*   X  E  *M · t*VC*.*Check+ *T* For *k ∈* [*M*] :  ①*,*(cm*,*aux) *← P*e pp*,η*  E    *T ←T ρ ←{*0*,*1*}* 

(*Q,* ans*,*pf) *← P*e(aux*,ρ*) *λ* pp *←G*(1*,n*)    *η ←D*   X  = E  *M · t*VC*.*Check+ E [*Tk| Tk←T*] *M ←M*pp*,η* ①*,*(cm*,*aux) *← P*e pp*,η*  E   *k∈*[*M*] *ρ ←{*0*,*1*}*r

(*Q,* ans*,*pf) *← P*e(aux*,ρ*) *λ* pp *←G*(1*,n*)  *η ←D*    *⋆* = E  *M ·* (*t*VC*.*Check+ *t*ARG) *| M ←M*pp*,η*] ①*,*(cm*,*aux) *← P*e pp*,η*  E [   *ρ ←{*0*,*1*}*r

(*Q,* ans*,*pf) *← P*e(aux*,ρ*) X <u>log</u>*λ*

|⋆|(i)|q ϵ|
|---|---|---|
||pp,η||
|||pp,η|
|⋆|||

pp *←G*(1*,n*) = (*t*VC*.*Check+ *t*ARG) *·* E *ξ* (*q*) *·* *ξ* (*q*) *η ←D* *q∈*[*ℓ*] <u>q</u> = *O ℓ*log *· t*ARG*.* *ϵ*

*Proof of Lemma 6.3.* We consider the following experiment throughout the proof unless otherwise specified:  *λ*  pp *←G*(1*,n*)  *η ←D*     ①*,*(cm*,*aux) *← P*e pp*,η*     *ρ ←{*0*,*1*}* r   *.*  e   (*Q,* ans*,*pf) *← P*(aux*,ρ*)     For *i ∈* [q] : 

(*i*) (*i*) (*i*) (*i*)
(cm*, Q,* ans*,*pf*, Q,*ans*,*pf) *← A*VC(pp*,η,ρ*)

Then, we can deduce that   Π e *⋆* pp*,η* V (①;*ρ*) = 0  [*Q,*ans]   *∧* V (①;*ρ*) = 1  Pr    *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1  *∧∀i ∈* [q]*,*ans[*Q*(*i*)] = ans

(*i*) [*Q*(*i*)]
 *⋆*  *∃i ∈* [q]*,*ans[*Q*(*i*)] *̸*= Πepp*,η*[*Q*(*i*)] *≤* Pr  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 

(*i*)

|∧∀i ∈ [q], ans[Q(i)] = ans|[Q(i)]||||
|---|---|---|---|---|
||(i)|⋆|||
||(i)|pp,η ⋆|||
|||pp,η|||
|i∈[q]|||||
|− log|(i)||⋆ pp,η|q ϵ|
||⋆||||
||pp,η||||

*∃i ∈* [q]*,*ans[*Q*(*i*)] = ans [*Q*(*i*)] *̸*= Πe [*Q*(*i*)] *≤* Pr *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 X ans[*Q*(*i*)] = ans [*Q*(*i*)] *̸*= Πe [*Q*(*i*)] *≤* Pr *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 <u>q</u> *≤* q *·* 2*ϵ*= *ϵ ,*

(*i*)e
where the last inequality follows because *A*VCoutputs ans = ans and ans[*Q*[*i*]] *̸*= Π [*Q*(*i*)], so that log uniformly random valid openings matched ans in *Q*[*i*]; since Πe [*Q*(*i*)] is the most frequent answer, ans[*Q*(*i*)] appears with probability at most 1*/*2 (otherwise the sum of both probabilities would exceed 1).

### 6.2 Adaptive soundness

**Lemma 6.5.** *For every ϵ >* 0*, security parameter λ ∈* N*, instance size bound n ∈* N*, auxiliary input distribution* *D, adversary time bound t*ARG*≥ t*VC*.*Check+ 2q *·* (log*|*Σ*|* + log*ℓ*) *and t*ARG*-size circuit P*e*, the soundness error of* *the argument system in Construction 4.1 satisfies*

*ϵ* ARG(*λ,n,t*ARG) *≤ ϵ*PCP(*n*) + q *· ϵ* *⋆* VC(*λ,ℓ,*q*,t* *⋆* VC) + *ϵ ,*

*where t* *⋆* VC= *O ℓ*log <u>q</u> *ϵ* *· t*ARG*.*

*Proof.* Recall, from Definition 3.3 and Construction 4.1, that our goal is to upper bound  *λ*  pp *←G*(1*,n*)  *|*①*|≤ n* *η ←D*  Pr   *∧* ① *∈/ L*(*R*) e   (①*,*aux) *← P*(pp*,η*) *∧ b* = 1 *b ← P*e(aux)*, V*(pp*,*①) *λ* pp *←G*(1*,n*)  *|*①*|≤ n* *η ←D*   *∧* ① *∈/ L*(*R*)  = Pr   [*Q,*ans] ①*,*(cm*,*aux) *← P*e pp*,η*   *.*  *∧* V (①;*ρ*) = 1 *ρ ←{,}* r *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 e (*Q,* ans*,*pf) *← P*(aux*,ρ*)

(Since *P*e sends cm as the first message in Construction 4.1, the former experiment is equivalent to the latter, where we omit the auxiliary state of the choice of instance and aux denotes that of the first message.)

(*i*)
We consider the following experiment, which augments the above by executing *R* and *A*VC, and thus leaves the probability unchanged.   *λ* pp *←G*(1*,n*)  *η ←D*       ①*,*(cm*,*aux) *← P*e pp*,η*   r   *ρ ←{*0*,*1*}* *.*    (*Q,* ans*,*pf) *← P*e(aux*,ρ*)     For *i ∈* [q] : 

(*i*) (*i*) (*i*) (*i*)
(cm*, Q,* ans*,*pf*, Q,*ans*,*pf) *← A*VC(pp*,η,ρ*)

By total probability,   *|*①*|≤ n*  *∧* ① *̸∈ L*(*R*)  Pr    *∧* V[*Q,*ans](①;*ρ*) = 1  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1     *|*①*|≤ n |*①*|≤ n*      *∧* ① *̸∈ L*(*R*)   *∧* ① *̸∈ L*(*R*)  Πe *⋆*  Πe *⋆*  = Pr  *∧* Vpp*,η*(①;*ρ*) = 1  + Pr  *∧* Vpp*,η*(①;*ρ*) = 0 *.*      *∧* V[*Q,*ans](①;*ρ*) = 1   *∧* V[*Q,*ans](①;*ρ*) = 1 

*∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

We first bound the probability of the leftmost term by the PCP system’s soundness error (i.e., Definition 3.13 with respect to PCP).

**Construction 6.6.** We define the auxiliary input distribution D of the PCP prover Pe as follows:

D: *λ*

1.Sample pp *←G*(1*,n*) and *η ←D*.
2.Output ai := (pp*,η*).
The PCP prover is then given by the following next message functions.

### Pe (ai):

1.Parse ai as (pp*,η*).
2.Run (①*,*aux₀) *← P*e(pp*,η*).
3.Set aux := (pp*,η,* aux₀).
4.Output (①*,*aux).
### Pe (aux):

1.Parse aux as (pp*,η,* aux₀).
2.Run (cm*,*aux₁) *← P*e(aux₀).
r

3.Run (*Qρ,*ans*ρ,*pf*ρ*) *← P*e(aux₁*,ρ*) for all *ρ ←{*0*,*1*}*.
*⋆* 16

<u>4.Construct and output Π</u>e<u>pp,η.</u> 16 *⋆*

||e [q] = arg max|{p (|pp,η)(q,σ)}, where|||
|---|---|---|---|---|---|
|p (q,σ) = 2|·| ρ ∈{0, 1}|∧ ans [q] = σ ∧ VC.Check(pp, cm, Q||, ans, pf|) = 1|
 Recall that, by Definition 6.2, Πpp*,η σ∈*Σ pp*,η,*
*−*r r pp*,η* : *q ∈Qρ ρ ρ ρ ρ|.*



Using Definition 3.13,   *|*①*|≤ n*  *∧* ① *̸∈ L*(*R*)   *|*①*|≤ n*    Πe *⋆* pp*,η*  *∧* ① *̸∈ L*(*R*)  Pr  *∧* V (①;*ρ*) = 1  *≤* Pr   [*Q,*ans]  Π e *⋆*  *∧* V (①;*ρ*) = 1  *∧* Vpp*,η*(①;*ρ*) = 1 *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1  *|*①*|≤ n* ai *←* D = Pr  *∧* ① *̸∈ L*(*R*) (①*,*aux) *←* Pe (ai)  Π e *⋆* pp*,η* e e (aux) *∧* V (①) = 1 Π *←* P

*≤ ϵ*PCP(*n*)*.*

Then we bound the remaining term. By total probability,   *|*①*|≤ n*  *∧* ① *̸∈ L*(*R*)    Πe *⋆* pp*,η*  Pr  *∧* V (①;*ρ*) = 0   [*Q,*ans]   *∧* V (①;*ρ*) = 1  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1    *|*①*|≤ n |*①*|≤ n*  *∧* ① *̸∈ L*(*R*)   *∧* ① *̸∈ L*(*R*)    Πe *⋆* pp*,η*  Πe *⋆* pp*,η*  *∧* V (①;*ρ*) = 0   *∧* V (①;*ρ*) = 0 *≤* Pr  [*Q,*ans]  + Pr  [*Q,*ans]  *∧* V (①;*ρ*) = 1   *∧* V (①;*ρ*) = 1     *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1   *∧*VC*.*Check(pp*,*cm*, Q,* ans*,* *∧∀i ∈* [q]*,*ans[*Q*[*i*]] = ans

(*i*) [*Q*[*i*]] *∧∃i ∈* [q]*,*ans[*Q*[*i*]] *̸*= ans
(*i*) [*Q*[*i*]]
VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 *≤* q *· ϵ* + Pr

(*i*)
*,* *∧∃i ∈* [q]*,*ans[*Q*[*i*]] *̸*= ans [*Q*[*i*]]

where the last inequality follows from Lemma 6.3. *ϵ* *⋆* VC(*λ,ℓ,*q*,t* *⋆* VC), as we explain below. According to Definition 3.10, and by the fact that VC*.*Check(cm*, Q*

(*i*) *,*ans
(*i*) *,*pf
(*i*) ) =
(*i*)
construction of *A*VC),

VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 Pr

(*i*)
*∧∃i ∈* [q]*,*ans[*Q*[*i*]] *̸*= ans [*Q*[*i*]]   VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 = Pr  *∧*VC*.*Check(pp*,*cm*, Q*

(*i*) *,*ans
(*i*) *,*pf
(*i*)
) = 1 
*∧∃i ∈* [q]*,*ans[*Q*[*i*]] *̸*= ans

(*i*) [*Q*[*i*]]
  X VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1

|||(i)|(i) (i)||
|---|---|---|---|---|
|i∈[q]||(i)|||
|||||λ|
||(i) (i)||(i)|r|
|i∈[q]||(i) (i)|(i)|(i)|
|||||(i)|
|Note that the prover in Definition 3.13 corresponds to the sequential execution of both steps in Construction 6.6.|||||

*≤* Pr  *∧*VC*.*Check(pp*,*cm*, Q,*ans*,*pf) = 1  *∧∃i ∈* [q]*,*ans[*Q*[*i*]] *̸*= ans [*Q*[*i*]]  *|Q|* = *|Q |* = q pp *←* VC*.*Gen(1*,ℓ*)  *η ←D* X  *∧∃q ∈Q∩Q* : ans[*q*] *̸*= ans [*q*] *≤* Pr   *ρ ←{*0*,*1*}*  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 cm*,*ans*,*ans*,*(*i*) *∧*VC*.*Check(cm*, Q,*ans*,*pf) = 1(*i*)*← A*VC(pp*,η,ρ* *Q, Q,*pf*,*pf



      

*·*

*i* (by



     )

### pf) = 1 

The last remaining term can be upper bounded by q

### 1 for all

X *⋆ ⋆*

|≤|ϵ (λ,ℓ, q,t|)|
|---|---|---|
|= q · ϵ|(λ,ℓ, q,t|),|
|= O|ℓt log|is the expected runtime of the adversary that samples ρ then runs A|

VC VC *i∈*[q] *⋆ ⋆* VC VC

*⋆* <u>q</u> (*i*) where *t*VC ARG(pp*,η,ρ*). *ϵ*VC

## 7 Expected-time soundness analysis for PCPs with non-adaptive verifiers

### Theorem 7.1. Consider these two ingredients:

- PCP = (P*,*V)*, a PCP system with non-adaptive verifier for a relation R with alphabet* Σ*, proof length ℓ, and* *query complexity* q*; and*
- VC = (Gen*,*Commit*,*Open*,*Check)*, a vector commitment scheme over alphabet* Σ*.* *Then* ARG = (*G, P, V*) := Kilian[PCP*,*VC] *is a three-message public-coin interactive argument system for R,* *expected-time soundness error ϵ*
*⋆* ARG*satisfies the following for every ϵ >* 0 *and t* *⋆* ARG*≥ t*VC*.*Check+ log*|*Σ*|* + log *ℓ:*

*ϵ* *⋆* ARG(*λ,n,t* *⋆* ARG) *≤ ϵ*PCP(*n*) + q *· ϵ* *⋆* VC(*λ,ℓ,*q*,t* *⋆* VC) + *ϵ ,*

*where ϵ*PCP*is the soundness error of* PCP *and t* *⋆* VC= *O* log <u>q</u> *ϵ* *·* (*t* *⋆* ARG+ *ℓ · t*V)*.*

### 7.1 Security reduction

We prove the same security reduction lemma as in Section 6, but an improved bound on the expected running time of the VC adversaries. The corresponding improvement on *ϵ*ARGthen follows by the same argument as in Section 6.

(*i*)
**Lemma 7.2** (Alternative security reduction lemma)**.** *There exist probabilistic algorithms A*VC*for each i ∈* [q] *such that, for every C ∈* N*, adversary time bound t* *⋆* ARG*≥ t*VC*.*Check+ log*|*Σ*|* + log *ℓ and expected t* *⋆* ARG*-time* *adversary P*e*, satisfies*  *λ*  pp *←G*(1*,n*)  *η ←D*    Πe *⋆* pp*,η*①*,*(cm*,*aux) *← P*e pp*,η*   V (①;*ρ*) = 0   [*Q,*ans] r   *∧* V (①;*ρ*) = 1 *ρ ←{*0*,*1*}*  Pr  e  *≤ ϵ .*  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 (*Q,* ans*,*pf) *← P*(aux*,ρ*)  

(*i*)
  *∧∀i ∈* [q]*,*ans[*Q*[*i*]] = ans [*Q*[*i*]] *For i ∈* [q] :     cm*, Q,* ans*,*pf*,*(*i*)

(*i*) (*i*) (*i*)
*← A*VC(pp*,η,ρ*) *Q,*ans*,*pf

(*i*) *⋆* <u>q</u> *⋆*
*Moreover, A*VC*runs in expected time t*VC= *O* log *ϵ* *·* (*t*ARG+ *ℓ · t*V) *for all i.*

(*i*)
We construct *A*VCbelow.

e, we construct each adversary(*i*) **Construction 7.3.** Given an argument prover *P A*VCas follows.

(*i*)
*A*VC(pp*,η,ρ*):

1.Run (①*,*cm*,*aux) *← P*e(pp*,η*) and (*Q,* ans*,*pf) *← P*e(aux*,ρ*).
2.Check that VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1. If not, output (cm*,*ans*,*ans*, Q, Q,* pf*,*pf).
3.Define *q* := *Q*(*i*) and set *j* := 0.
4.Repeat the following:
(a)Repeat the following:

|′|r|||
|---|---|---|---|
||||′ ′|
|′||||
|′ ′|′ ′ ′|′ ′ ′|′ ′ ′|

i.Sample *ρ ←{*0*,*1*}*. ii.Run the PCP verifier V to obtain the query set *Q* (*ρ*) corresponding to *ρ*
*′*. iii.If *Q* (*i*) = *q*, exit this loop.

(b)Run (*Q,*ans*,*pf) *← P*e(aux*,ρ*).
(c)If VC*.*Check(pp*,*cm*, Q,*ans*,*pf) = 1:
i.If ans[*q*] *̸*= ans [*q*], output (cm*, Q,* ans*,*pf*, Q,*ans*,*pf).

ii.If ans[*q*] = ans *′* [*q*], set *j* := *j* + 1. Further, if *j* = log <u>q</u> *ϵ*, output (cm*,*ans*,*ans*, Q, Q,* pf*,*pf).

(*i*) (*i*)
We first analyze the expected running time of *A*VC. For every (pp*,η*) and *q ∈* [*ℓ*], we define *p*pp*,η*(*q*) be the probability that verifier’s *i*-th query is *q* for a uniformly sampled randomness:   ①*,*(cm*,*aux) *← P*e pp*,η*

(*i*) r
 *p*pp*,η*(*q*) := Pr *Q*(*i*) = *q ρ ←{*0*,*1*}.* (*Q,* ans*,*pf) *← P*e(aux*,ρ*)

(*i*)
For every (pp*,η*) and *q ∈* [*ℓ*], we define *ψ*pp*,η*(*q*) as follows:   VC*.*Check(pp*, Q,* ans*,*pf) = 1 ①*,*(cm*,*aux) *← P*e pp*,η*

(*i*) r
 *ψ*pp*,η*(*q*) := Pr  conditioned on *ρ ←{*0*,*1*}.* *Q*(*i*) = *q* (*Q,* ans*,*pf) *← P*e(aux*,ρ*)

Finally, denote by *X*, *T* and *M*pp*,η*the distribution of the running time of Item 4a, distributions of the running time of *P*e and the number of iterations of Step 4 in an execution of *A*VC(pp*,η,ρ*), respectively. Then the running

(*i*)
time of *A*VCis   X X *O* *M · t*VC*.*Check+ *Xk*+ *Tk**,* *k∈*[*M*] *k∈*[*M*]

where *Xk←X* and *Tk←T* for all *k ∈* [*M*]. Therefore, *λ*   pp *←G*(1*,n*)  *M ←M*pp*,η* *η ←D*    X X For *k ∈* [*M*] :   E  E  *M · t*VC*.*Check+ *Xk*+ *Tk*  ①*,*(cm*,*aux) *← P*e pp*,η*   *k∈*[*M*] *k∈*[*M*] *Xk←X* *ρ ←{*0*,*1*}* r *Tk←T* (*Q,* ans*,*pf) *← P*e(aux*,ρ*) *λ* pp *←G*(1*,n*)    *η ←D*   X 

|+ t|) +|E [X | X|←X]|M ←M||①, (cm, aux)|← P|
|---|---|---|---|---|---|---|---|
|⋆|k∈[M]|k|k||pp,η||r|

= E  E  *M ·* (*t*VC*.*Check ARGe pp*,η*    *ρ ←{*0*,*1*}* 

(*Q,* ans*,*pf) *← P*e(aux*,ρ*)  !  X

(*i*) (*i*)<u>tV</u>pp *←G*(1
*λ* *,n*) = E  *p*pp*,η*(*q*) *· ψ*pp*,η*(*q*) *· t*VC*.*Check+ *t* *⋆* ARG+(*i*)*·* E [*M|M ←M*pp*,η*]  *p* (*q*) *η ←D* *q∈*[*ℓ*] pp*,η*  !  X

(*i*) (*i*)<u>tVlog</u>
<u>q</u> pp *←G*(1 *λ* *,n*) *≤* E  *p*pp*,η*(*q*) *· ψ*pp*,η*(*q*) *· t*VC*.*Check+ *t* *⋆* ARG+(*i*)*·*(*i*) <u>ϵ</u> *η ←D*

|||||p (q)|ψ (q)||
|---|---|---|---|---|---|---|
|q∈[ℓ]||||pp,η|pp,η||
||⋆||||||

*q∈*[*ℓ*] pp*,η* pp*,η* <u>q</u> = *O* log *·* (*t*ARG+ *ℓ · t*V)*.* *ϵ* *Proof of Lemma 6.3.* We consider the following experiment throughout the proof unless otherwise specified:

| pp ←G(1 ,n)|||||
|---|---|---|---|---|
| η ←D |||| |
|  ①, (cm, aux)|← P e pp,η||| |
| ρ ←{0, 1} |||| .|
|  (Q, ans, pf) ← P (aux,ρ)|e||| |
|  For i ∈ [q] :|||| |
|(cm, Q, ans, pf, Q||, ans|, pf) ← A||

*λ*

r

(*i*) (*i*) (*i*) (*i*)
VC(pp*,η,ρ*)

Then, we can deduce that   Π e *⋆* pp*,η* V (①;*ρ*) = 0  [*Q,*ans]   *∧* V (①;*ρ*) = 1  Pr    *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1  *∧∀i ∈* [q]*,*ans[*Q*(*i*)] = ans

(*i*) [*Q*(*i*)]
 *⋆*  *∃i ∈* [q]*,*ans[*Q*(*i*)] *̸*= Πepp*,η*[*Q*(*i*)] *≤* Pr  *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 

(*i*)

|∧∀i ∈ [q], ans[Q(i)] = ans|[Q(i)]||||
|---|---|---|---|---|
||(i)|⋆|||
||(i)|pp,η ⋆|||
|||pp,η|||
|i∈[q]|||||
|− log|(i)||⋆ pp,η|q ϵ|
||⋆||||
||pp,η||||

*∃i ∈* [q]*,*ans[*Q*(*i*)] = ans [*Q*(*i*)] *̸*= Πe [*Q*(*i*)] *≤* Pr *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 X ans[*Q*(*i*)] = ans [*Q*(*i*)] *̸*= Πe [*Q*(*i*)] *≤* Pr *∧*VC*.*Check(pp*,*cm*, Q,* ans*,*pf) = 1 <u>q</u> *≤* q *·* 2*ϵ*= *ϵ ,*

(*i*)e
where the last inequality follows because *A*VCoutputs ans = ans and ans[*Q*[*i*]] *̸*= Π [*Q*(*i*)], so that log uniformly random valid openings matched ans in *Q*[*i*]; since Πe [*Q*(*i*)] is the most frequent answer, ans[*Q*(*i*)] appears with probability at most 1*/*2 (otherwise the sum of both probabilities would exceed 1).

## 8 Lower bounds from Schnorr identification scheme

In this section, we show that a generic bound (i.e., for arbitrary PCP and VC) for the security of Kilian’s argument system implies the same bound for the security of the Schnorr identification scheme [Sch89; Sch91].

### 8.1 Schnorr identification scheme

An identification scheme (ID scheme) for a relation *R* consists of a tuple ID = (G*,* P*,* V*,*C) that works as follows:

G(1 *λ* ): Sample an instance-witness pair (①*,*✇) *←* G(1 *λ* ) in the relation *R*.

The prover P and verifier V interact as follows:

1. P’s first message: (*α,* aux) *←* P(①*,*✇), then P sends *α* to V.
2. V’s challenge: sample *β ←* C and send *β* to P.
3. P’s second message: *γ ←* P(aux*,β*) and send *γ* to V.
4. V’s decision: output V(①*,α,β,γ*). **Definition 8.1** (Impersonation security)**.** ID = (G*,* P*,* V*,*C) *for a relation R has (strict-time) impersonation* *error ϵ*ID*if for every security parameter λ ∈* N*, adversary time bound* tID*, and* tID*-time adversary* Pe*,*
*λ* (①*,*✇) *←* G(1 )  (*α,* aux) *←* Pe(1*λ,*①)  Pr  V(① *,α,β,γ*) = 1   *≤ ϵ*ID(*λ,*tID)*.* *β ←* C *γ ←* Pe(aux*,β*)

In prior literature, security against passive impersonation attacks assume adversaries that have access to an oracle that produces honestly-generated transcripts for the instance ①. However, in this work we only consider identification schemes that are *simulatable*: there exists an efficient algorithm that samples a transcript from the distribution of honest executions of the protocol on input (①*,*✇). Hence, it is equivalent to define the adversaries without the oracle access because they can simulate the oracle themselves.

**Definition 8.2** (Expected-time impersonation security)**.** ID = (G*,* P*,* V*,*C) *for a relation R has (expected-time)* *impersonation error ϵ* *⋆* ID*if for every security parameter λ ∈* N*, adversary time bound t* *⋆* ID*∈* N*, and adversary* P e

*with expected running time t* *⋆* ID*,*

||||
|---|---|---|
||λ λ|⋆ ⋆|

(①*,*✇) *←* G(1 )  (*α,* aux) *←* Pe(1*,*①)  Pr  V(① *,α,β,γ*) = 1   *≤ ϵ*ID(*λ,t*ID)*.* *β ←* C *γ ←* Pe(aux*,β*)

Now we recall the construction of the Schnorr identification scheme. We rely on a group generation algorithm GroupGen that takes as input the security parameter 1 *λ* and outputs a description (G*,p,g*) of a cyclic group G of prime order *p* and the generator *g* of G. In particular, the security parameter *λ* determines a lower bound on the group order: *p ≥* 2 *λ*.

**Construction 8.3** (Schnorr identification scheme)**.** IDSchnorr= (G*,* P*,* V*,*C) works as follows:

- G(1 *λ* ):
1. (G*,p,g*) *←* GroupGen(1
*λ* ).

2.Sample ✇ *←* Z*p*.
3.Set ① := ((G*,p,g*)*,g*
✇ ).

4.Output (①*,*✇).
- P(①*,*✇):
1.Parse ① as ((G*,p,g*)*,h*).
2.Sample *r ←* Z*p*.
*r*

3.Compute the first message *α* := *g*.
4.Set aux := (✇*,r*).
5.Output (*α,* aux).
- P(aux*,β*):
1.Parse aux as (✇*,r*).
2.Output *γ* := ✇ *· β* + *r* mod *p*.
- V(①*,α,β,γ*):
1.Parse ① as ((G*,p,g*)*,h*).
*γ β*

2.Check that *g* = *α · h*.
### The challenge space C is Zp.

The security of the Schnorr identification scheme comes from the hardness of discrete logarithm problem.

**Definition 8.4** (Discrete logarithm assumption)**.** *The discrete logarithm assumption holds with error ϵ*DLOG*if for* *every security parameter λ, adversary time bound* tDLOG*∈* N *and* tDLOG*-size adversary* ADLOG*,*   *λ* (G*,p,g*) *←* GroupGen(1 ) *y ×* *≤ ϵ* Pr *x* = *g x ←* Z*p* DLOG(*λ,*tDLOG)*.* *y ←* ADLOG((G*,p,g*)*,x*)

**Definition 8.5** (expected-time discrete logarithm assumption)**.** *The expected-time discrete logarithm assumption* *⋆ ⋆* *holds with error ϵ*DLOG*if for every security parameter λ, adversary time bound t*DLOG*∈* N *and adversary* ADLOG *⋆* *with expected running time t*DLOG*,*   *λ* (G*,p,g*) *←* GroupGen(1 ) *y ×**⋆ ⋆*

|y|×|⋆ ⋆|
|---|---|---|
||p||

Pr *x* = *g x ←* Z *≤ ϵ*DLOG(*λ,t*DLOG)*.* *y ←* ADLOG((G*,p,g*)*,x*)

### 8.2 From Kilian to Schnorr

We show that the security of the Schnorr identification scheme is bounded by the soundness error of an argument system constructed by Kilian’s construction (Construction 4.1).

**Theorem 8.6.** *There exists* PCP *and* VC *such that for every n ∈* N*,*

*ϵ*Schnorr(*λ,*tID) *≤ ϵ*ARG(*λ,n,t*ARG)*,*

*where ϵ*Schnorr*is the impersonation security of the Schnorr identification scheme, ϵ*ARG*is the soundness error of* ARG := Kilian[PCP*,*VC] *and t*ARG= *O*(tID)*.*

**Theorem 8.7.** *There exists* PCP *and* VC *such that for every n ∈* N*,*

*⋆ ⋆ ⋆ ⋆* *ϵ*Schnorr(*λ,t*ID) *≤ ϵ*ARG(*λ,n,t*ARG)*,*

*⋆ ⋆* *where ϵ*Schnorr*is the expected-time impersonation security of the Schnorr identification scheme, ϵ*ARG*is the* *expected-time soundness error of* ARG := Kilian[PCP*,*VC] *and t*ARG= *O*(tID)*.*

We construct the PCP and VC in Theorems 8.6 and 8.7 below.

**Construction 8.8.** Consider the empty relation *R* = *∅*. Fix r *∈* N. We construct PCP = (P*,*V) for *R* as follows:

r

- P(①*,*✇): Output 0. Π
- V (①):
r

1.Sample randomness *ρ ←{*0*,*1*}*.
2.Check that Π[1] = *ρ*.
r Observe that PCP has alphabet Σ = *{*0*,*1*}*, proof length *ℓ* = 1 and query complexity q = 1. Moreover, it’s *−*r easy to show that the soundness error of PCP is *ϵ*PCP(*n*) = 2.

**Construction 8.9** (VC scheme from Schnorr)**.** We construct a VC scheme as follows:

*λ*

- VC*.*Gen(1):
*λ*

1.Run (G*,p,g*) *←* GroupGen(1).
2.Sample ✇ *←* Z*p*.
✇

3.Output pp := ((G*,p,g*)*,g*).
- VC*.*Commit(pp*,m*):
1.Parse pp as ((G*,p,g*)*,h*).
2.Sample *r ←* Z*p*.
*r*

3.Set cm := *g*.
4.Set aux := (*r,m*).
5.Output (cm*,*aux).
- VC*.*Open(pp*,*aux*, {*1*}*):
1.Parse aux as (*r,m*).
2.Output pf := *r* + *m*.
- VC*.*Check(pp*,*cm*, Q,* ans*,*pf):
1.Parse pp as ((G*,p,g*)*,h*).
pf ans

2.Check that *g* = cm *· h*.
**Lemma 8.10** (Position binding of Construction 8.9)**.** *Assume that the discrete logarithm assumption (Defini-* *tion 8.4) holds with error ϵ*DLOG= *ϵ*DLOG(*λ,*tDLOG)*. Let* VC *be constructed as in Construction 8.9. Then* VC *has* *binding error ϵ*VC*such that* *ϵ*VC(*λ,ℓ* = 1*,s* = 1*,t*VC) *≤ ϵ*DLOG(*λ,t*VC)*.*

*Proof.* Let *A*VCbe an adversary for VC. We construct an adversary ADLOGfor discrete log.

ADLOG((G*,p,g*)*,h*):

1.Set pp := ((G*,p,g*)*,h*).
*′ ′*

2.Run (cm*, {*1*}, {*1*},* ans*,*ans*,*pf*,*pf) *← A*VC(pp).
*′ ′ −*1

3.Set *y* := (pf *−* pf) *·* (ans *−* ans).
4.Output *y*.
*′* *′* pf ans pf ans*′y* If *A*VCsucceeds, then ans *̸*= ans, *g* = cm *· h* and *g* = cm *· h*. Therefore, *y* is well-defined and *g* = <u>h</u>, *β y·c c c* so ADLOGsucceeds as *g* = *g* = *h* = *α · h*.

**Lemma 8.11** (expected-time position binding of Construction 8.9)**.** *Assume that the expected-time discrete* *⋆ ⋆ ⋆* *logarithm assumption (Definition 8.5) holds with error ϵ*DLOG DLOG DLOG

||= ϵ (λ,t|). Let VC be constructed as in|
|---|---|---|
||⋆||
|⋆|⋆ ⋆||

*⋆* *Construction 8.9. Then* VC *has expected-time position binding error ϵ*VC*such that* *⋆* *ϵ*VC(*λ,ℓ* = 1*,s* = 1*,t*VC) *≤ ϵ*DLOG(*λ,t*VC)*.*

The proof of Lemma 8.11 is the same as the proof of Lemma 8.10.

*Proof of Theorem 8.6.* Let PCP be constructed as in Construction 8.8 and VC be constructed as in Construc- tion 8.9. Let ARG := Kilian[PCP*,*VC]. Let Pe be an adversary for the Schnorr identification scheme with running time tIDand success probability *ϵ* e as follows: Schnorr(*λ,*tID). We construct an argument adversary *P* *P*e(pp):

1. *P*e’s commitment:
(a)Parse pp as ((G*,p,g*)*,h*).
(b)Run (*α,* aux) *←* Pe((G*,p,g*)*,h*).
(c)Output (①*,*cm*,*aux) := (*⊥,α,* aux).
2. *P*e’s response given verifier randomness *ρ*:
(a)Run *γ ←* Pe(aux*,ρ*).
(b)Output (*Q* := *{*1*},* ans := *ρ,* pf := *β*).
Note that the running time of *P*e is *t*ARG= *O*(tID). It follows that *λ* pp *←G*(1*,n*)  *|*①*|≤ n η ←D*    *ϵ* e(pp*,η*)  ARG(*λ,n,t*ARG) *≥* Pr  *∧* ① *∈/ L*(*R*) (①*,*cm*,*aux) *← P*   *∧V*(pp*,* ①*, Q,* ans*,*pf) = 1 *ρ ←{*0*,*1*}*r

(*Q,* ans*,*pf) *← P*e(*P,ρ*) *λ* pp *←G*(1*,n*)  *η ←D*    = Pr *V*(pp*,* ①*, Q,* ans*,*pf) = 1 (*⊥,* cm*,*aux) *← P*e(pp*,η*)     *ρ ←{*0*,*1*}*r

(*Q,* ans*,*pf) *← P*e(*P,ρ*)   *λ* pp *←G*(1*,n*)    ((G*,p,g*)*,h*) := pp     ans = *ρ η ←D*  = Pr pf ans e  *∧ g* = cm *· h* (*⊥,* cm*,*aux) *← P*(pp*,η*)  r  *ρ ←{*0*,*1*}*  (*Q,* ans*,*pf) *← P*e(*P,ρ*) *λ* (①*,*✇) *←* G(1 )  (*α,* aux) *←* Pe(1*λ,*①)  = Pr *,α,β,γ*) = 1r V(① *β ←{*0*,*1*}* 

### γ ← Pe(aux,β)

= *ϵ*Schnorr(*λ,*tID)*.*

Theorem 8.7 can be proved in the same way as Theorem 8.6.

**Remark 8.12.** Note that the choice of the instance ① does not matter in the above proof. Hence, it is straightfor- ward to extend the proofs in this section to hold in the setting of a non-adaptively chosen instance ①.

### 8.3 Lower bound from discrete logarithm assumption

We explain how to obtain barriers for security of Kilian’s construction using known bounds for the Schnorr identification scheme.

**Lemma 8.13** (Schnorr security from discrete log [PS00; BN06; KMP16])**.** *Assume the discrete logarithm* *assumption holds with error ϵ*DLOG= *ϵ*DLOG(*λ,*tDLOG)*. For every security parameter λ ∈* N*, adversary time bound* t ID*∈* N*, and* tID*-time Schnorr impersonation adversary* P e*, let ϵ* Schnorr*be the impersonation error of the Schnorr* *identification scheme, the following holds:* p *ϵ* Schnorr(*λ,*tID) *≤ ϵ*DLOG(*λ,O*(tID))*.*

### Theorem 8.6 implies the following corollary.

**Corollary 8.14** (Lower bound from position binding)**.** *Consider these two ingredients:*

- PCP = (P*,*V)*, a PCP system for a relation R with alphabet* Σ*, proof length ℓ, and query complexity* q*; and*
- VC = (Gen*,*Commit*,*Open*,*Check)*, a vector commitment scheme over alphabet* Σ*.* *Let* ARG := Kilian[PCP*,*VC] *and let ϵ*ARG*be the soundness error of ϵ*ARG*. If we have a security analysis such* *that for every t ∈* N*,*
p *ϵ* ARG(*λ,n,t*ARG) *< ϵ*PCP(*n*) + *o ϵ*VC(*λ,ℓ,*q*,O*(*t*ARG))*,*

*then* p *ϵ* Schnorr(*λ,*tID) *< o ϵ*DLOG(*λ,O*(tID)) + 2 *−λ* *,*

### where tID= Ω(tARG).

For any cyclic group of order 2 *λ*, where the hardness of discrete logarithm is believed to hold [Sho97],

<u>t²</u> <u>DLOG</u> *ϵ* DLOG(*λ,*tDLOG) *≤λ.* 2 Hence, <u>t²</u> <u>VC</u> *ϵ* VC(*λ,*1*,*1*,t*VC) *≤ ϵ*DLOG(*λ,O*(*t*VC)) *≤ Oλ.* 2 According to Theorem 1, we have the following bound on the soundness error of ARG := Kilian[PCP*,*VC]:

*ϵ* ARG(*λ,*①*,t*ARG) *≤ ϵ*PCP(*n*) + *ϵ*VC(*λ,ℓ,*q*,t*VC) + *ϵ*

*≤* 2 *−λ* + *ϵ*VC(*λ,*1*,*1*,t*VC) + *ϵ*

*−λ*<u>t²VC</u> *≤* 2 + *O* *λ* + *ϵ .* 2

Setting *ϵ* := Θ((*ℓ · t*ARG) 2*/*3 *·* 2 *−λ/*3 ) minimizes the right-hand side at r! *−λ* 2*/*33 <u>t²ARG</u> 2 + *ℓ ·* Θ *λ*

*.* (3)
2

Hence, r! <u>t²</u> <u>ID</u> *ϵ* Schnorr(*λ,*tID) *≤ Oλ,* and 2 r! *−λ* 2*/*33 <u>t²ARG</u> *ϵ* ARG(*λ,*①*,t*ARG) *≤* 2 + *ℓ ·* Θ*λ,*

showing a polynomial gap between the best analysis of the Schnorr identification scheme and our analysis of Kilian’s protocol.

### 8.4 Lower bound from expected-time discrete logarithm assumption

**Lemma 8.15** (Expected-time security of the Schnorr identification scheme)**.** *Assume the expected-time discrete*

|⋆ ⋆|⋆||
|---|---|---|
|||⋆ ⋆|

*logarithm assumption holds with error ϵ*DLOG= *ϵ*DLOG(*λ,t*DLOG)*. For every security parameter λ ∈* N*, adversary* *time bound t* *⋆* DLOG*∈* N*, and Schnorr adversary* P e *with expected running time t* DLOG*, let ϵ*Schnorr*be the expected-time* *impersonation error of the Schnorr identification scheme, the following holds:*

*ϵ* *⋆* Schnorr(*λ,t* *⋆* ID) *≤ ϵ* *⋆* DLOG(*λ,O*(*t* *⋆* ID))*.*

From Theorem 6.1,

*ϵ* *⋆* ARG(*λ,*①*,t* *⋆* ARG) *≤ ϵ*PCP(①) + q *· ϵ* *⋆* VC(*λ,ℓ,*q*,t* *⋆* VC) + *ϵ* *−λ ⋆*<u>q</u>*⋆* *≤* 2 + q *· ϵ*DLOG(*λ,O*(log *· t*ARG)) + *ϵ .* *ϵ*

## Acknowledgments

Alessandro Chiesa and Ziyi Guan are partially supported by the Ethereum Foundation. We thank Fermi Ma and Julius Vering for valuable discussions and participating in early stages of this work. We thank Zijing Di for valuable feedback and comments on earlier drafts of this paper.

## References

[AC20] Thomas Attema and Ronald Cramer. “Compressed Σ-Protocol Theory and Practical Application to Plug & Play Secure Algorithmics”. In: *Proceedings of the 40th Annual International Cryptology Conference*. CRYPTO ’20. 2020, pp. 513–543.

[ACK22] Thomas Attema, Ronald Cramer, and Lisa Kohl. “A Compressed Σ-Protocol Theory for Lattices”. In: *Proceedings of the 41st Annual International Cryptology Conference*. CRYPTO ’21. 2022, pp. 549–579.

[AF22] Thomas Attema and Serge Fehr. “Parallel Repetition of (*k₁,...,kµ*)-Special-Sound Multi-Round Inter- active Proofs”. In: *Proceedings of the 42nd Annual International Cryptology Conference*. CRYPTO ’22. 2022, pp. 415–443.

[BCS16] Eli Ben-Sasson, Alessandro Chiesa, and Nicholas Spooner. “Interactive Oracle Proofs”. In: *Proceedings of* *the 14th Theory of Cryptography Conference*. TCC ’16-B. 2016, pp. 31–60.

[BD20] Mihir Bellare and Wei Dai. “The Multi-Base Discrete Logarithm Problem: Tight Reductions and Non- rewinding Proofs for Schnorr Identification and Signatures”. In: *Progress in Cryptology – INDOCRYPT* *’20*. 2020, pp. 529–552.

[BG08] Boaz Barak and Oded Goldreich. “Universal Arguments and their Applications”. In: *SIAM Journal on* *Computing* 38.5 (2008). Preliminary version appeared in CCC ’02., pp. 1661–1694.

[BGTZ23] Alexander R. Block, Albert Garreta, Pratyush Ranjan Tiwari, and Michal Zajac. “On Soundness Notions for Interactive Oracle Proofs”. In: (2023), p. 1256.

[BKKMS13] Eli Ben-Sasson, Yohay Kaplan, Swastik Kopparty, Or Meir, and Henning Stichtenoth. “Constant Rate PCPs for Circuit-SAT with Sublinear Query Complexity”. In: *Proceedings of the 54th Annual IEEE Symposium* *on Foundations of Computer Science*. FOCS ’13. 2013, pp. 320–329.

[BN06] Mihir Bellare and Gregory Neven. “Multi-signatures in the plain public-key model and a general forking lemma”. In: *Proceedings of the 13th ACM Conference on Computer and Communications Security*. CCS ’06. 2006, pp. 390–399.

[BP02] Mihir Bellare and Adriana Palacio. “GQ and Schnorr Identification Schemes: Proofs of Security against Impersonation under Active and Concurrent Attacks”. In: *Advances in Cryptology-CRYPTO 2002,* *22nd Annual International Cryptology Conference, Santa Barbara, California, USA, August 18-22, 2002,* *Proceedings*. Ed. by Moti Yung. Vol. 2442. Lecture Notes in Computer Science. Springer, 2002, pp. 162–

177.
[BR22] Liron Bronfman and Ron D. Rothblum. “PCPs and Instance Compression from a Cryptographic Lens”. In: *13th Innovations in Theoretical Computer Science Conference, ITCS 2022, January 31 - February 3, 2022,* *Berkeley, CA, USA*. Ed. by Mark Braverman. Vol. 215. LIPIcs. Schloss Dagstuhl-Leibniz-Zentrum fur¨ Informatik, 2022, 30:1–30:19.

[BS06] Eli Ben-Sasson and Madhu Sudan. “Robust locally testable codes and products of codes”. In: *Random* *Structures and Algorithms* 28.4 (2006), pp. 387–402.

[Ben24] Shany Ben-David. “Probabilistically Checkable Arguments for All NP”. In: *Advances in Cryptology -* *EUROCRYPT 2024 - 43rd Annual International Conference on the Theory and Applications of Crypto-* *graphic Techniques, Zurich, Switzerland, May 26-30, 2024, Proceedings, Part III*. Ed. by Marc Joye and Gregor Leander. Vol. 14653. Lecture Notes in Computer Science. Springer, 2024, pp. 345–374.

[CF13] Dario Catalano and Dario Fiore. “Vector Commitments and Their Applications”. In: *Proceedings of the 16th* *International Conference on Practice and Theory in Public Key Cryptography*. PKC ’13. 2013, pp. 55–72.

[CMS19]

[CMSZ21]

[CY21a]

[CY21b]

[CY24]

[FPS20]

[IMSX15]

[KMP16]

[KO21]

[KPT97]

[KR09]

[Kil92]

[LM19]

[LMS22]

[Mic00]

[PS00]

[RS21]

[SSV19]

[SSV21]

Alessandro Chiesa, Peter Manohar, and Nicholas Spooner. “Succinct Arguments in the Quantum Random Oracle Model”. In: *Proceedings of the 17th Theory of Cryptography Conference*. TCC ’19. Available as Cryptology ePrint Archive, Report 2019/834. 2019, pp. 1–29. Alessandro Chiesa, Fermi Ma, Nicholas Spooner, and Mark Zhandry. “Post-Quantum Succinct Arguments: Breaking the Quantum Rewinding Barrier”. In: *Proceedings of the 62nd Annual IEEE Symposium on* *Foundations of Computer Science*. FOCS ’21. 2021, pp. 49–58. Alessandro Chiesa and Eylon Yogev. In: *Proceedings of the 41st Annual International Cryptology Confer-* *ence*. CRYPTO ’21. 2021, pp. 711–741. Alessandro Chiesa and Eylon Yogev. “Tight Security Bounds for Micali’s SNARGs”. In: *Proceedings of* *the 19th Theory of Cryptography Conference*. TCC ’21. 2021, pp. 401–434. Alessandro Chiesa and Eylon Yogev. *Building Cryptographic Proofs from Hash Functions*. 2024. URL: [https://github.com/hash-based-snargs-book](https://github.com/hash-based-snargs-book). Georg Fuchsbauer, Antoine Plouviez, and Yannick Seurin. “Blind Schnorr Signatures and Signed ElGamal Encryption in the Algebraic Group Model”. In: *Advances in Cryptology – EUROCRYPT ’20*. 2020, pp. 63–

95. Yuval Ishai, Mohammad Mahmoody, Amit Sahai, and David Xiao. *On Zero-Knowledge PCPs: Limitations,* *Simplifications, and Applications*. Available at [http://www.cs.virginia.edu/˜mohammad/](http://www.cs.virginia.edu/˜mohammad/) files/papers/ZKPCPs-Full.pdf. 2015. Eike Kiltz, Daniel Masny, and Jiaxin Pan. “Optimal Security Proofs for Signatures from Identification Schemes”. In: *Proceedings of the 36th Annual International Cryptology Conference*. CRYPTO ’16. 2016, pp. 33–61. Stephan Krenn and Michele Orru.` *Proposal:* Σ*-protocols*. 2021. URL: [https://docs.zkproof](https://docs.zkproof). org/pages/standards/accepted-workshop4/proposal-sigma.pdf. Joe Kilian, Erez Petrank, and Gabor Tardos. “Probabilistically checkable proofs with zero knowledge”. In: ´ *Proceedings of the 29th Annual ACM Symposium on Theory of Computing*. STOC ’97. 1997, pp. 496–505. Yael Tauman Kalai and Ran Raz. “Probabilistically Checkable Arguments”. In: *Proceedings of the 29th* *Annual International Cryptology Conference*. CRYPTO ’09. 2009, pp. 143–159. Joe Kilian. “A note on efficient zero-knowledge proofs and arguments”. In: *Proceedings of the 24th Annual* *ACM Symposium on Theory of Computing*. STOC ’92. 1992, pp. 723–732. Russell W. F. Lai and Giulio Malavolta. “Subvector Commitments with Application to Succinct Arguments”. In: *Proceedings of the 39th Annual International Cryptology Conference*. CRYPTO ’19. 2019, pp. 530–560. Alex Lombardi, Fermi Ma, and Nicholas Spooner. “Post-Quantum Zero Knowledge, Revisited or: How to Do Quantum Rewinding Undetectably”. In: *Proceedings of the 63rd Annual IEEE Symposium on* *Foundations of Computer Science*. FOCS ’22. 2022, pp. 851–859. Silvio Micali. “Computationally Sound Proofs”. In: *SIAM Journal on Computing* 30.4 (2000). Preliminary version appeared in FOCS ’94., pp. 1253–1298. David Pointcheval and Jacques Stern. “Security Arguments for Digital Signatures and Blind Signatures”. In: *Journal of Cryptology* 13 (2000), 361–396. Lior Rotem and Gil Segev. “Tighter Security for Schnorr Identification and Signatures: A High-Moment Forking Lemma for Σ-Protocols”. In: *Proceedings of the 41st Annual International Cryptology Conference*. CRYPTO ’21. 2021, 222–250. Alessandra Scafuro, Luisa Siniscalchi, and Ivan Visconti. “Publicly Verifiable Proofs from Blockchains”. In: *Public-Key Cryptography-PKC 2019 - 22nd IACR International Conference on Practice and Theory of* *Public-Key Cryptography, Beijing, China, April 14-17, 2019, Proceedings, Part I*. Ed. by Dongdai Lin and Kazue Sako. Vol. 11442. Lecture Notes in Computer Science. Springer, 2019, pp. 374–401. Alessandra Scafuro, Luisa Siniscalchi, and Ivan Visconti. “Publicly Verifiable Zero Knowledge from (Collapsing) Blockchains”. In: *Public-Key Cryptography-PKC 2021 - 24th IACR International Conference* *on Practice and Theory of Public Key Cryptography, Virtual Event, May 10-13, 2021, Proceedings, Part II*. Ed. by Juan A. Garay. Vol. 12711. Lecture Notes in Computer Science. Springer, 2021, pp. 469–498.

[SSY23] Gil Segev, Amit Sharabi, and Eylon Yogev. “Rogue-Instance Security for Batch Knowledge Proofs”. In: *Proceedings of the 23th Theory of Cryptography Conference*. TCC ’23. 2023, pp. 121–157.

[Sch89] Claus P. Schnorr. “Efficient Identification and Signatures for Smart Cards”. In: *Proceedings of the 9th* *Annual International Cryptology Conference*. CRYPTO ’89. 1989, pp. 239–252.

[Sch91] Claus P. Schnorr. “Efficient signature generation by smart cards”. In: *Journal of Cryptology* 4.3 (1991), pp. 161–174.

[Sho97] Victor Shoup. “Lower bounds for discrete logarithms and related problems”. In: *Proceedings of the 16th* *International Conference on the Theory and Application of Cryptographic Techniques*. EUROCRYPT ’97. 1997, pp. 256–266.

[Val08] Paul Valiant. “Incrementally Verifiable Computation or Proofs of Knowledge Imply Time/Space Efficiency”. In: *Proceedings of the 5th Theory of Cryptography Conference*. TCC ’08. 2008, pp. 1–18.
