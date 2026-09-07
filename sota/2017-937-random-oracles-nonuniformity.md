# Random Oracles and Non-Uniformity

## Sandro Coretti

∗ Yevgeniy Dodis † Siyao Guo ‡

## New York University New York University Northeastern University

## corettis@nyu.edu dodis@cs.nyu.edu s.guo@neu.edu

## John Steinberger

jpsteinb@gmail.com

## August 8, 2022

Abstract We revisit security proofs for various cryptographic primitives in the *auxiliary-input random-* *oracle model* (AI-ROM), in which an attacker *A* can compute arbitrary *S* bits of leakage about the random oracle *O* before attacking the system and then use additional *T* oracle queries to *O* during the attack. This model has natural applications in settings where traditional random- oracle proofs are not useful: (a) security against non-uniform attackers; (b) security against preprocessing. We obtain a number of new results about the AI-ROM:

- Unruh (CRYPTO ’07) introduced the *pre-sampling technique*, which generically reduces security proofs in the AI-ROM to a much simpler *P -bit-xing random-oracle model* (BF-
coordinates,

|ROM), where the attacker can arbitrarily x the values of||O on some P|
|---|---|---|
|but then the remaining coordinates are chosen at random.|p|Unruh’s security loss for this|
|transformation is|ST=P. We improve this loss to the optimal value O(ST=P ), obtaining||

nearly tight bounds for a variety of indistinguishability applications in the AI-ROM.

- While the basic pre-sampling technique cannot give tight bounds for unpredictability ap- plications, we introduce a novel \multiplicative version" of pre-sampling, which allows to dramatically reduce the size of *P* of the pre-sampled set to *P* = *O*(*ST*) and yields nearly tight security bounds for a variety of unpredictability applications in the AI-ROM. Quali- tatively, it validates Unruh’s \polynomial pre-sampling conjecture"|disproved in general by Dodis *et al.* (EUROCRYPT ’17)|for the special case of unpredictability applications.
- Using our techniques, we reprove nearly all AI-ROM bounds obtained by Dodis *et al.* (using a much more laborious compression technique), but we also apply it to many settings where the compression technique is either inapplicable (e.g., computational reductions) or appears intractable (e.g., Merkle-Damgard hashing).
- We show that for any *salted* Merkle-Damgard hash function with *m*-bit output there exists a collision-nding circuit of size (2
*m=*3 ) (taking salt as the input), which is signicantly below the 2 *m=*2 birthday security conjectured against uniform attackers.

- We build two compilers to generically extend the security of applications proven in the traditional ROM to the AI-ROM. One compiler simply prepends a public salt to the random oracle, showing that *salting generically provably defeats preprocessing*.
Overall, our results make it much easier to get concrete security bounds in the AI-ROM. These bounds in turn give concrete conjectures about the security of these applications (in the standard model) against *non-uniform* attackers.

∗ Supported by NSF grants 1314568 and 1319051. † Partially supported by gifts from VMware Labs and Google, and NSF grants 1619158, 1319051, 1314568. ‡ Supported by NSF grants CNS1314722 and CNS-1413964. Work partially done at the Simons Institute for the Theory of Computing at UC Berkeley.

# 1 Introduction

We start by addressing the two main themes of this work|non-uniformity and random oracles|in isolation, before connecting them to explain the main motivation for this work.

Non-uniformity. Modern cryptography (in the \standard model") usually models the attacker *A* as non-uniform, meaning that it is allowed to obtain some arbitrary (but bounded) \advice" before attacking the system. The main rationale to this modeling comes from the realization that a determined attacker will know the security parameter *n* of the system in advance and might be able to invest a signicant amount of preprocessing to do something \special" for this xed value of *n*, especially if *n* is not too large (for reasons of eciency), or the attacker needs to break a lot of instances online (therefore amortizing the one-time oine cost). Perhaps the best known example of such attacks comes from *rainbow tables* ([32, 47]; see also [39, Section 5.4.3]) for inverting arbitrary functions; the idea is to use one-time preprocessing to initialize a clever data structure in order to dramatically speed up brute-force inversion attacks. Thus, restricting to uniform attackers might not accurately model realistic preprocessing attacks one would like to protect against. However, there are other, more technical, reasons why this choice is convenient:

- Adleman [2] showed that non-uniform polynomial-time attackers can be assumed to be deter- ministic (formally, *BPP=poly* = *P=poly*), which is handy for some proofs.
- While many natural reductions in cryptography are uniform, there are several important cases where the only known (or even possible!) reduction is non-uniform. Perhaps the best known example are zero-knowledge proofs [29, 28], which are *not* closed under *sequential* *composition* unless one allows non-uniform attackers (and simulators; intuitively, in order to use the simulator for the second zero-knowledge proof, one must use the output of the rst proof’s simulator as an auxiliary input to the verier).
1 Of course, being a special case of general protocol composition, this means that any work|either using zero-knowledge as a subroutine or generally dealing with protocol composition|must use security against *non-* *uniform* attackers in order for the composition to work.

- The non-uniform model of computation has many applications in complexity theory, such as the famous \hardness-vs-randomness" connection (see [46, 35, 36, 34, 37]), which roughly states that *non-uniform* hardness implies non-trivial de-randomization. Thus, by dening cryptographic attackers as non-uniform machines, any lower bounds for such cryptographic applications might yield exciting de-randomization results. Of course, despite the pragmatic, denitional, and conceptual advantages of non-uniformity, one
must ensure that one does not make the attacker \too powerful," so that it can (unrealistically) solve problems which one might use in cryptographic applications. Fortunately, although non-uniform attackers can solve undecidable problems (by encoding the input in unary and outputting solutions in the non-uniform advice), the common belief is that non-uniformity cannot solve interesting \hard problems" in polynomial time. As one indirect piece of evidence, the Karp-Lipton theorem [38] shows that if *NP* has polynomial-size circuits, then the polynomial hierarchy collapses. And, of course, the entire eld of cryptography is successfully based on the assumption that many hard problems cannot be solved even on average by polynomially sized circuits, and this belief has not been seriously challenged so far.

There are some workarounds (see [27]) that permit one to dene zero-knowledge under uniform attackers, but they are much harder to work with than assuming non-uniformity, and, as a result, were not adopted by the community.

Hence, by and large it is believed by the theoretical community that *non-uniformity is the right* *cryptographic modeling of attackers*, despite being overly conservative and including potentially unrealistic attackers.

The random-oracle model. Hash functions are ubiquitous in cryptography. They are widely used to build one-way functions (OWFs), collision-resistant hash functions (CRHFs), pseudorandom functions/generators (PRFs/PRGs), message authentication codes (MACs), etc. Moreover, they are often used together with other computational assumptions to show security of higher-level applications. Popular examples include Fiat-Shamir heuristics [24, 1] for signature schemes (e.g., Schnorr signatures [50]), full-domain-hash signatures [8], or trapdoor functions (TDFs) [8] and OAEP [9] encryption, among many others. For each such application *Q*, one can wonder how to assess its security *"* when instantiated with a concrete hash function *H*, such as SHA-3. Given our inability to prove unconditional lower bounds, the traditional approach is the following: Instead of proving an upper bound on *"* for some specic *H*, one analyzes the security of *Q* assuming *H* is a *truly random (aka \ideal") function O*. Since most *Q* are only secure against computationally bounded attackers, one gives the attacker *A* oracle access to *O* and limits the number of oracle queries that *A* can make by some parameter *T*. This now becomes the traditional *random-oracle model (ROM)*, popularized by the seminal paper of Bellare and Rogaway [8]. The appeal of the ROM stems from two aspects. First, it leads to very clean and intuitive security proofs for many primitives that resisted standard-model analysis under natural security assumptions (see some concrete examples below). Second, this resulting ROM analysis is *independent of the* *tedious specics* of *H*, is done only *once* for a given hash-based application, and also provides (for non-pathological *Q*’s) the *best possible* security one might hope to achieve with any concrete function *H*. In particular, we hope that a specic hash function *H* we use is suciently \well- designed" that it (essentially) matches this idealized bound. If it does, then our bound on *"* was accurate anyway; and, if it does not, this usually serves as strong evidence that we should not use this particular *H*, rather than the indication that the idealized analysis was the wrong way to guess the exact security of *Q*. Ironically, in theory we know that the optimistic methodology above is false [12, 11, 45, 30, 5], and some applications secure in the ROM will be insecure for any instantiation of *H*, let alone maintain the idealized bound on *"*. Fortunately, all counterexamples of this kind are rather articial, and do not shed much light on the security of concrete schemes used in practice, such as the use of hash functions as OWFs, CRHFs, PRFs, PRGs, MACs, and also as parts of natural signature and encryption schemes used in practice [24, 50, 9, 8]. In other words, despite purely theoretical concerns, the following *random-oracle methodology* appears to be a good way for practitioners to assess the best possible security level of a given (natural) application *Q*.

Random-oracle methodology. *For \natural" applications of hash functions, the con-* *crete security proven in the random-oracle model is the right bound even in the standard* *model, assuming the \best possible" concrete hash function H is chosen.*

Random oracles and non-uniformity. The main motivation for this work is to examine the soundness of the above methodology, while also being consistent with the fact that attackers should be modeled as *non-uniform*. We stress that we are not addressing the conceptual question of whether non-uniform security is the \right" way to model attackers in cryptography, as this is the subject of a rather heated on-going debate between theoreticians and practitioners; see [49, 10] for some discussion on the subject. Instead, assuming we want to model attackers as non-uniform (for the

reasons stated above and to be consistent with the theoretical literature), and assuming we want to have a way of correctly assessing the *concrete*, non-asymptotic security for important uses of hash functions in applications, we ask: is the random oracle methodology a sound way to achieve this goal? Unfortunately, with the traditional modeling of the random oracle, the answer is a resounding \NO," even for the *most basic* usages of hash functions, as can be seen from the following examples.

(i)In the standard model, no single function *H* can be collision-resistant, as a non-uniform attacker can trivially hardwire a collision. In contrast, a single (non-salted) random oracle *O* is trivially collision-resistant in the ROM, with excellent exact security *O*(*T²=M*), where *M* is the range of *O*. This is why in the standard model one considers a *family* of collision-resistant hash functions whose public key, which we call *salt*, is chosen *after A* gets its non-uniform advice. Interestingly, one of the results in this paper will show that the large gap (nding collisions in time *M¹*
*=*2 vs. *M¹* *=*3 ) between uniform and non-uniform security exists for the popular Merkle-Damgard construction *even if salting is allowed*.

(ii)In the standard model, no PRG candidate *H*(*x*) can have security better than 2 *n=*2 even against linear-time (in *n*) attackers [3, 21, 10], where *n* is the seed-length of *x*. In contrast, an expanding random oracle *O*(*x*) can be trivially shown to be (*T=*2 *n* )-secure PRG in the traditional ROM, easily surpassing the 2 *n=*2 barrier in the standard model (even for huge *T* up to 2 *n=*2, let alone polynomial *T*).

(iii)The seminal paper of Hellman [32], translated to the language of non-uniform attackers, shows that a random function *H* : [*N*]*!* [*N*] can be inverted with constant probability using a non- uniform attacker of size *O N²* *=*3, while Fiat and Naor [23] extended this attack to show that every (even non-random) function *H* can be inverted with constant probability by circuits of size at most *N³* *=*4. In contrast, if one models *H* as a random oracle *O*, one can trivially show that *O* is a OWF with security *O* (*T=N*) in the traditional ROM. For example, setting *T* = *N²* *=*3 (or even *T* = *N³* *=*4 ), one would still get negligible security *N* 1*=*3 (or *N* 1*=*4 ), contradicting the concrete non-uniform attacks mentioned above.

To put it dierently, once non-uniformity is allowed in the standard model, the separations between the random-oracle model and the standard model are *no longer* contrived and articial but rather lead to *impossibly good* exact security of *widely deployed* applications.

Auxiliary-input ROM. The above concern regarding the random-oracle methodology is not new and was extensively studied by Unruh [52] and Dodis *et al.* [19]. Fortunately, these works oered a simple solution, by extending the traditional ROM to also allow for oracle-dependent *auxiliary input*. The resulting model, called the *auxiliary-input random-oracle model (AI-ROM)*, is parameterized by two parameters *S* (\space") and *T* (\time") and works as follows: First, as in the traditional random-oracle model, a function *O* is chosen uniformly from the space of functions with some domain and range. Second, the attacker *A* in the AI-ROM consists of two entities *A₁* and *A₂*. The rst-stage attacker *A₁* is computationally unbounded, gets full access to the random oracle *O*, and computes some \non-uniform" advice *z* of size *S*. This advice is then passed to the second-stage attacker *A₂*, who may make up to *T* queries to oracle *O* (and, unlike *A₁*, might have additional application-specic restrictions, like bounded running time, etc.). This naturally maps to the preprocessing model discussed earlier and can also be used to analyze security against non-uniform circuits of size *C* by setting *S* = *T* = *C*. 2 Indeed, none of the concerns expressed in

But separating *S* and *T* can also model non-uniform RAM computation with memory *S* and query complexity *T*.

examples (i)-(iii) remain valid in AI-ROM: (i) *O* itself is no longer collision-resistant since *A₁* can precompute a collision; (ii)-(iii) the generic non-uniform PRG or OWF attacks mentioned earlier can also be performed on *O* itself (by letting *A₁* treat *O* as any other function *H* and computing the corresponding advice for *A₂*). In sum, the AI-ROM model allows us to restate the modied variant of the random oracle methodology as follows:

AI-Random-Oracle Methodology. *For \natural" applications of hash functions, the* *concrete security proven in the AI-ROM is the right bound even in the standard model* *against* <u>non-uniform</u> *attackers, assuming the \best possible" concrete hash function H* *is chosen.*

Dealing with auxiliary information. The AI-ROM yields a clean and elegant way towards obtaining meaningful non-uniform bounds for natural applications. Unfortunately, obtaining such bounds is considerably more dicult than in the traditional ROM. In retrospect, such diculties are expected, since we already saw several examples showing that non-uniform attackers are *very* *powerful* when exact security matters, which means that the security bounds obtained in the AI- ROM might often be noticeably weaker than in the traditional ROM. From a technical point, the key diculty is this: *conditioned on the leaked value z*, which can depend on the entire function table of *O* in some non-trivial manner, many of the individual values *O*(*x*) are no longer random to the attacker. And this ruins many of the key techniques utilized in the traditional ROM, such as: (1) *lazy sampling*, which allows the reduction to sample the not-yet-queried values of *O* at random, as needed, without worrying that such lazy sampling will be inconsistent with the past;

(2) *programmability*, which allows the reduction to dynamically dene some value of *O* in a special (still random) way, as this might be inconsistent with the leakage value *z* it has to produce *before* knowing how and where to program *O*; (3) *distinguishing-to-extraction argument*, which states that the attacker cannot distinguish the value of *O* from random without explicitly querying it (which again is false given auxiliary input). For these reasons, new techniques are required for dealing with the AI-ROM. Fortunately, two such techniques are known:
- Pre-sampling technique. This beautiful technique was introduced in the original, pioneer- ing work of Unruh [52]. From our perspective, we will present Unruh’s pre-sampling technique in a syntactially dierent (but technically equivalent) way which will be more convenient for our presentation. Specically, Unruh implicitly introduced an intermediate oracle model, which we term the *bit-xing random-oracle model (BF-ROM)*,
3 which can be arbitrarily xed on some *P* coordinates, but then the remaining coordinates are chosen at random and inde- pendently of the xed coordinates. Moreover, the non-uniform *S*-bit advice of the attacker can only depend on the *P* xed points, but not on the remaining truly random points. Intu- itively, dealing with the BF-ROM|at least when *P* is small|appears to be much easier than with the AI-ROM, as many of the traditional ROM proof techniques can be adapted provided that one avoids the \pre-sampled" set. Quite remarkably, for any value *P*, Unruh showed that any (*S;T*)-attack in the AI-ROM will have similar advantage in (appropriately chosen) p *P*-BF-ROM, up to an additive loss of (*S;T;P*), which Unruh upper bounded by *ST=P*. This yields a general recipe for dealing with the AI-ROM: (a) prove security *"*(*S;T;P*) of the given application in the *P*-BF-ROM; 4

(b) optimize for the right value of *P* by balancing
*"*(*S;T;P*) and (*S;T;P*) (while also respecting the time and other constraints of the attacker).

This naming in inspired by the bit-xing source [13] from complexity theory. Observe that the parameter *S* is still meaningful here. *A₁* xes *O* at *P* points but only passes *S* bits of advice to *A₂*. While none of information-theoretic proofs in this paper really use this, for computational reductions *S* "passes

- Compression technique.
p Unfortunately, Dodis *et al.* [19] showed that the concrete security loss (*S;T;P*) = *ST=P* proven by Unruh is not strong enough to get tight bounds for any of the basic applications of hash functions, such as building OWFs, PRGs, PRFs, (salted) CRHFs, and MACs. To remedy the situation, Dodis *et al.* [19] showed a dierent, less general technique for dealing with the AI-ROM, by adapting the *compression paradigm*, introduced by Gennaro and Trevisan [26, 25] in the context of black-box separations, to the AI-ROM. The main idea is to argue that if some AI-ROM attacker succeeds with high probability in breaking a given scheme, then that attacker can be used to reversibly encode (i.e., compress) a random oracle beyond what is possible from an information-theoretic point of view. Since we are considering attackers who perform preprocessing, our encoding must include the *S*- bit auxiliary information produced by the attacker. Thus, the main technical challenge in applying this technique is to ensure that the constructed encoding compress by (signicantly) more than *S* bits. Dodis *et al.* [19] proceeded by successfully applying this idea to show nearly tight (and always better than what was possible by pre-sampling) bounds for a variety of natural applications, including OWFs, PRGs, PRFs, (salted) CRHFs, and MACs.

Pre-sampling or compression? The pre-sampling and compression techniques each have their pros and cons, as discussed below. On a positive, pre-sampling is very general and seems to apply to most applications, as analyzing the security of schemes in BF-ROM is not much harder than in the traditional ROM. Moreover, as shown by Unruh, the pre-sampling technique appears at least \partially friendly" to computational applications of random oracles (specically, Unruh applied it to OAEP encryption [9]). Indeed, if the size *P* of the pre-sampled set is not too large, then it can be hardwired as part of non-uniform advice to the (ecient) reduction to the computational assumption. In fact, in the asymptotic domain Unruh even showed that the resulting security remains \negligible in security parameter ," despite not being smaller than any concrete negligible function (like the inverse Ackermann function). 5

On a negative, the *concrete* security bounds which are currently p obtainable using this tech- nique are vastly suboptimal, largely due to the big security loss *ST=P* incurred by using Un- ruh’s bound [52]. Moreover, for computational applications, the value of *P* cannot be made larger than the size of attacker for the corresponding computational assumption. p Hence, for xed (\non- asymptotic"; see Footnote 5) polynomial-size attackers, the loss *ST=P* cannot be made negligible. Motivated by this, Unruh conjectured that the security loss of pre-sampling can be improved by a tighter proof. Dodis *et al.* [19] showed that the best possible security loss is at most *ST=P*. For computational applications, this asymptotically disproves Unruh’s conjecture, as *ST=P* is still non- negligible for polynomial values of *P* (although we will explain shortly that the situation is actually more nuanced). Moving to the compression technique, we already mentioned that it led Dodis *et al.* [19] to establishing nearly tight AI-ROM bounds for several information-theoretic applications of random oracles. Unfortunately, each proof was noticeably more involved than the original ROM proof, or than the proof in the BF-ROM one would do if applying the more intuitive pre-sampling technique. Moreover, each primitive required a completely dierent set of algorithmic insights to get the re-

|through" for the nal non-uniform attacker against the computational assumption, and it is necessary to have S||||P|
|---|---|---|---|---|
|in this case.|||||
|Any AI-ROM attacker of size t = t(|p|= 1=p() for innitely many||’s|
|has advantage is polynomial and therefore suited for a reduction to a computational hardness assumption.|ST=P in the BF-ROM, which can be made to be =2 by suitably choosing P||O(t =), which||

5 ) getting inverse polynomial advantage

quired level of compression. And it is not entirely clear how far this can go. For example, we do not see any way to apply the compression paradigm to relatively basic applications of hash functions beyond using the hash function *by itself* as a given primitive; e.g., to show AI-ROM security of the classical Merkle-Damgard paradigm [43, 17] (whose *tight* AI-ROM security we will later estab- lish in this work). Moreover, unlike pre-sampling, the compression paradigm cannot be applied at all to computational applications, as the compressor and the decompressor are computationally unbounded.

## 1.1 Our Results

We obtain a number of results about dealing with the AI-ROM, which, at a high-level, take the best features from pre-sampling (simplicity, generality) and compression (tightness).

Improving Unruh. Recall, Unruh [52] showed that one can move from the AI-ROM to the p *P*- BF-ROM at the additive cost (*S;T;P*) *ST=P*, and Dodis *et al.* [19] showed that (*S;T;P*) = (*ST=P*) in general. We show that the true additive error bound is indeed (*S;T;P*) = (*ST=P*), therefore improving Unruh’s bound by a quadratic factor; see Theorem 5. Namely, the eect of *S* bits of auxiliary information *z* = *z*(*O*) against an attacker making *T* adaptive random-oracle queries can be simulated to within an additive error *O*(*ST=P*) by xing the value of the random oracle on *P* points (which depend on the function *z*), and picking the other points at random and independently of the auxiliary information. While the quadratic improvement might appear \asymptotically small," we show that it already matches the near-tight bound for all indistinguishability applications (specically, PRGs and PRFs) proved pby <u>[19]</u> using much more laborious compression arguments. For example, to match the *"* = *O*( *ST=N* + *T=N*) bound for PRGs with seed domain *N*, we show using a simple argument that the random oracle is *"* *0* = *O*(*P=N* + *T=N*)-secure in the *P*-BF-ROM, where the rst term corresponds to the seed being chosen from the pre-sampled set, and the second term corresponds *p* to the probability of querying the oracle on the seed in the attack stage. Setting *P* = *O*( *STN*) to balance the *P=N* and *ST=P* terms, we immediately get our nal bound, which matches that of [19]. For illustrative purposes, we also apply our improved bound to argue the AI-ROM security of a couple of indistinguishability applications not considered by [19]. First, we show an improved| compared to its use as a (standard) PRF|bound for the random oracle as a *weak* PRF, which is enough for chosen-plaintext secure symmetric-key encryption. Our proof is a very simple adaptation of the PRF proof in the BF-ROM, while we believe the corresponding compression proof, if possible at all, would involve noticeable changes to the PRF proof of [19] (due to the need for better compression to get the improved bound). Second, we also apply it to a typical example of a computational application, namely, the (KEM-variant of the) TDF-based public-key encryption scheme Enc*f*(*m*; *x*)=(*f* (*x*)*; O*(*x*) *m*) from the original Bellare-Rogaway paper [8], where *f* is a trapdoor permutation (part of the public key, while the inverse is the secret key) and *x* is the randomness used for encryption. Recall that the compression technique cannot be applied to such applications. To sum up, we conjecture that the improved security bound *ST=P* should be sucient to get good bounds for most natural indistinguishability applications; these bounds are either tight, or at least they match those attainable via compression arguments (while being much simpler and more general).

Improved pre-sampling for unpredictability applications. Even with our improved bound of *ST=P* for pre-sampling, we will not match the nearly tight compression bounds obtained by Dodis *et al.* [19] for OWFs and MACs. In particular, nding the optimal value of *P* will result in \square root terms" which are not matched by any existing attacks. As our key insight, we notice that this is not due to the limitations of pre-sampling (i.e., going through the BF-ROM), but rather to the fact that achieving an *additive* error is unnecessarily restrictive for *unpredictability* applications. Instead, we show that if one is happy with a multiplicative factor of 2 in the probability of breaking the system, then one can achieve this *generically* by setting the pre-sampling set size *P ST*; see Theorem 6. This has a number of implications. First, with this multiplicative pre-sampling technique, we can easily match the compression bounds for the OWF and MAC unpredictability applications considered by Dodis *et al.* [19], but with much simpler proofs. Second, we also apply it to a natural information-theoretic application where we believe the compression technique will fail to get a good bound; namely, building a (salted) CHRF family via the Merkle-Damgard paradigm, where the salt is the initialization vector for the construction (see Theorem 12). The salient feature of this example is that the random oracle is applied in iteration, which poses little diculties to adapting the standard-ROM proof to the BF-ROM, but seems to completely blow up the complexity of the compression arguments, as there are too many possibilities for the attacker to cause a collision for dierent salts when the number of blocks is greater than 1. 6 The resulting AI-ROM bound *O*(*ST²=M*) becomes vacuous for circuits of size roughly *M¹* *=*3, where *M* is the range of the com- pression function. This bound is well below the conjectured *M¹* *=*2 birthday security of CRHFs based on Merkle-Damgard against uniform attackers. Quite unexpectedly, we show that *M¹* *=*3 security we prove *is tight*: there exists a (non-uniform) collision-nding attack implementable by a circuit of size *O M¹* *=*3 (see Theorem 13)! This example illustrates once again the the surprising power of non-uniformity.

Implications to computational reductions. Recall that, unlike compression techniques, pre- sampling can be applied to computational reductions, by \hardwiring" the pre-sampling set of size *P* into the attacker breaking the computational assumption. However, this means that *P* cannot be made larger than the maximum allowed running time *t* of such an attacker. Since standard pre-sampling incurs additive cost (*ST=P*), one cannot achieve nal security better that *ST=t*, irrespective of the value of *"* in the (*t;"*)-security of the corresponding computational assumption. For example, when *t* is polynomial (in the security parameter) and *"* 1*=t* is exponentially small, we only get inverse polynomial security (at most *ST=t*) when applying standard pre-sampling. In contrast, the multiplicative variant of pre-sampling sets the list size to be roughly *P ST*, which is polynomial for polynomial *S* and *T* and can be made smaller than the complexity *t* of the standard model attacker for the computational assumption we use. Thus, when *t* is polynomial and *"* is exponentially small, we will get negligible security using multiplicative pre-sampling. For a concrete illustrative example, see the bound in Theorem 15 when we apply our improved pre- sampling to the natural *computational unpredictability* application of Schnorr signatures [50]. 7 To put it dierently, while the work of Dodis *et al.* [19] showed that Unruh’s \pre-sampling conjecture" is false in general|meaning that negligible security is not possible with a polynomial list size *P*|we show that it is qualitatively true for *unpredictability applications*, where the list size can be made 6 The same diculty of compression should also apply to indistinguishability applications of Merkle-Damgard, such as building PRFs [6]. Interestingly, general Fiat-Shamir transform is *not* secure in AI-ROM, and thus our proof used the specics of Schnorr’s signatures.

polynomial (roughly *ST*). Moreover, we show that in certain computational *indistinguishability* applications, we can still apply our improved pre-sampling technique *inside the reduction*, and get nal security higher than the *ST=t* barrier mentioned above. We illustrate this phenomenon in our analysis of TDF encryption (cf. Theorem 16) by separating the probability of the attacker’s success into 2 disjoint events: (1) the attacker, given ciphertext *f* (*x*), managed to query the random oracle on the TDP preimage *x*; (2) the attacker succeeds in distinguishing the value *O*(*x*) from random without querying *O*(*x*). Now, for the event (1), we can reduce to the TDP security with polynomial list size using our improved *multiplicative* pre-sampling (since is an *unpredictability* event), while for the event (2), we can prove *information-theoretic* security using standard additive pre-sampling, without the limitation of having to upper bound *P* by the running time of the TDP attacker. It is an interesting open question to classify precisely the type of indistinguishability applications where such \hybrid" reduction technique can be applied.

Going to the traditional ROM. So far, the general paradigm we used is to reduce the hard- to-analyze security of *any* scheme in the AI-ROM to the much simpler and proof-friendly security of the *same* scheme in the BF-ROM. However, an even simpler approach, if possible, would be to reduce the security in the AI-ROM all the way to the traditional ROM. Of course, we know that this is impossible without any modications to the scheme, as we have plenty of examples where the AI-ROM security of the scheme is much weaker than its ROM security (or even disappears completely). Still, when a simple modication is possible without much inconvenience to the users, reducing to the ROM has a number of obvious advantages over the BF-ROM:

- While much simpler than in the AI-ROM, one must still prove a security bound in BF-ROM. It would be much easier if one could just utilize an already proven result in ROM and seamlessly \move it" to the AI-ROM at a small cost.
- Some natural schemes secure in the traditional ROM are *insecure* in the BF-ROM (and also in the AI-ROM) without any modications. Simple example include the general Fiat-Shamir heuristic [24, 1] or the FDH signature scheme [8] (see Section C.1). Thus, to extend such schemes to the AI-ROM, we must modify them anyway, so we might as well try to generically ensure that ROM security is already enough. As our next set of results, we show two simple compilers which build a hash function *O⁰* to be
used in AI-ROM application out of hash function *O* used in the traditional ROM application. Both results are in the common-random-string model. This means that they utilize a public random string (which we call salt and denote *a*) chosen *after* the auxiliary information about *O* is computed by the attacker. The honest parties are then assumed to have reliable access to this *a* value. We note that in basic applications, such as encryption and authentication, the salt can simply be chosen at key generation and be made part of the public key/parameters, so this comes at a small price indeed. The rst transformation analyzed in Section 6.1 is simply *salting*; namely *Oa* *0*

(*x*) = *O*(*a;x*),
where *a* is a public random string chosen from the domain of size *K*. This technique is widely used in practice (going back to password hashing [44]), and was analyzed by Dodis *et al.* [19] in the context of AI-ROM, by applying the compression argument to show that *salting provably defeats* *preprocessing* for the few natural applications they consider (OWFs, PRGs, PRFs, and MACs). What our work shows is that salting provably defeats pre-processing *generically*, as opposed to a

few concrete applications analyzed by [19]. 8 Namely, by making the salt domain *K* large enough, one gets almost the same security in AI-ROM than in the traditional ROM. To put dierently, when salting is possible, one gets the *best of both worlds: security against non-uniform attacks, but with* *exact security matching that in the traditional ROM*. The basic salting technique sacriced a relatively large factor of *K* from the domain of the random oracle *O* in order to build *O⁰* (for *K* large enough to bring the \salting error" down). When the domain of *O* is an expensive resource, in Section 6.2 we also design a more domain-ecient compiler, which only sacrices a small factor *k* 2 in the domain of *O*, at the cost that each evaluation of *O⁰* takes *k* 2 evaluations of *O* (and the \salting error" decays exponentially in *k*). This transformation is based on the adaptation of the technique of Maurer [42], originally used in the context of key-agreement with randomizers. While the basic transformation needs *O*(*k*log*N*) bits of public salt, we also show than one can reduce the number of random bits to *O*(*k* + log*N*). And since we do not envision *k* to be larger than *O*(log*N*) for any practical need, the total length of the salt is always *O*(log*N*).

Our main lemma. The key technical contribution of our work is Lemma 1, proved in Section 2.1, which roughly shows that a random oracle with auxiliary input is \close" to the convex combination of \*P*-bit-xing sources" (see Denition 1). Moreover, we give both additive and multiplicative versions of this \closeness," so that we can later use dierent parameters to derive our Theorem 5 (for indistinguishability applications in the AI-ROM) and Theorem 6 (for unpredictability applications in the AI-ROM) in Section 2.2.

## 1.2 Other Related Work

Most of the related work was already mentioned earlier. The realization that multiplicative error is enough for unpredictability applications, and this can lead to non-trivial savings, is related to the work of Dodis *et al.* [20] in the context of improved entropy loss of key derivation schemes. Tessaro [51] generalized Unruh’s presampling techniques to the random-*permutation* model, albeit without improving the tightness of the bound. De *et al.* [18] study the eect of salting for inverting a *permutation O* as well as for a specic pseudorandom generator based on one-way permutations. Chung *et al.* [14] study the eects of salting in the design of collision-resistant hash functions, and used Unruh’s pre-sampling technique to argue that salting defeats preprocessing in this important case. Using salting to obtain non- uniform security was also advocated by Mahmoody and Mohammed [41], who used this technique for obtaining non-uniform black-box separation results. Finally, the extensive body of work on the *bounded storage model* [42, 4, 22, 53] is related to the special case of AI-ROM, where all *T* queries in the second stage are done by the challenger to derive the key (so that one tries to minimize *T* to ensure local computability), but the actual attacker is not allowed any such queries after *S*-bit preprocessing. 8 Of course, by performing a direct analysis of the *salted* scheme (e.g., using Theorems 5 or 6), we might get better exact security bounds than by using our general result; namely, shorter salt would be enough to get the claimed amount of security. Still, for settings where obtaining the smallest possible salt value is not critical, the simplicity and generality of our compilers oer a convenient and seamless way to argue security in AI-ROM without doing a direct analsyis.

# 2 Dealing with Auxiliary Information

Since an attacker with oracle-dependent auxiliary input may obtain the output of arbitrary functions evaluated on a random oracle’s function table, it is not obvious how the security of schemes in the *auxiliary-input random-oracle model (AI-ROM)* can be analyzed. To remedy this situation, Unruh [52] introduced the *bit-xing random-oracle model (BF-ROM)*, in which the oracle is xed on a subset of the coordinates and uniformly random and independent on the remaining ones, and showed that such an oracle is indistinguishable from an AI-RO. In Section 2.1, we improve the security bounds proved by Unruh [52] in the following two ways: First, we show that a BF-RO is indistinguishable from an AI-RO up to an additive term of roughly *ST=P*, where *P* is the size of the xed portion of the BF-RO; this improves greatly over p Unruh’s bound, which was in the order of *ST=P*. Second, we prove that the probability that any distinguisher outputs 1 in the AI-ROM is at most twice the probability that said distinguisher outputs 1 in the BF-ROM|already when *P* is roughly equal to *ST*. Section 2.2 contains the formalizations of the AI and BF-ROMs, attackers with oracle-dependent advice, and the notion of application. As a consequence of the connections between the two models, the security of *any* application in the BF-ROM translates to the AI-ROM at the cost of the *ST=P* term, and, additionally, the security of *unpredictability* applications translates at the mere cost of a multiplicative factor of 2 (as long as *P ST*). The corresponding theorems and their proofs can also be found in Section 2.2.

## 2.1 Replacing Auxiliary Information by Bit-Fixing

In this section, we show that any random oracle about which an attacker may have a certain amount of auxiliary information can be replaced by a suitably chosen convex combination of bit- xing sources. This substitution comes at the price of either an additive term to the distinguishing advantage or a multiplicative one to the probability that a distinguisher outputs 1. To that end, consider the following denition:

Denition 1. *An* (*N;M*)*-source is a random variable X with range* [*M*] *N* *. A source is called*

- ** (1)-dense *if for every subset I* [*N*]*,*
*H₁*(*XI*) (1) *jIj* log*M* = (1) log*M* *jIj* *:*

- ** (*P;*1)-dense *if it is xed on at most P coordinates and is* (1)*-dense on the rest,*
- *P*-bit-xing *if it is xed on at most P coordinates and uniform on the rest.*
That is, the min-entropy of every subset of the function table of a-dense source is at most a fraction of less than what it would be for a uniformly random one.

Lemma 1. *Let X be distributed uniformly over* [*M*] *N* *and Z* := *f* (*X*)*, where f* : [*M*] *N* *!f*0*;* 1*g* *S* *is an arbitrary function. For any >* 0 *and P 2* N*, there exists a family fYzgz2f*0*;*1*gS of convex* *combinations Yzof P -bit-xing* (*N;M*)*-sources such that for any distinguisher D taking an S-bit* *input and querying at most T < P coordinates of its oracle,*

*X Yf* (*X*)<u>(S + log 1=) T</u> P *D* (*f* (*X*)) = 1 P *D* (*f* (*X*)) = 1 + *P* *and* P *D* *X* (*f* (*X*)) = 1 (*S*+2 log 1*=*)*T=P* P *D* *Y* *f* (*X*)(*f* (*X*)) = 1 + 2*:*

Lemma 1 is proved using a technique (cf. Claim 2) put forth by Goos *et al.* [31] in the area of communication complexity. The technique was also adopted in a paper by Kothari *et al.* [40], who gave a simplied argument for decomposing high-entropy sources into bit-xing sources with constant density (cf. Denition 1). For self-containment, Section A of the appendix contains a proof of this decomposition technique. Furthermore, the proof of Claim 3 below uses the well-known H- coecient technique by Patarin [48], while following a recent re-formulation of it due to Hoang and Tessaro [33].

*Proof.* Fix an arbitrary *z 2f*0*;* 1*g* *S* and let *Xz*be the distribution of *X* conditioned on *f* (*X*) = *z*. Let *Sz*= *N* log*M H₁*(*Xz*) be the min-entropy deciency of *Xz*. Let *>* 0 be arbitrary.

Claim 2. *For every >* 0*, Xzis-close to a convex combination of nitely many* (*P⁰;* 1)*-dense* *sources for* *0*<u>Sz+ log 1=</u> *P* = *:* log*M*

The proof of Claim 2 can be found in Section A of the appendix. Let *Xz0*be the convex combination of (*P⁰;* 1)-dense sources that is-close to *Xz*for a =*z* to be determined later. For every (*P⁰;* 1) source *X⁰* in said convex combination, let *Y* *0* be the corresponding *P⁰*-bit-xing source *Y* *0*, i.e., *X⁰* and *Y* *0* are xed on the same coordinates to the same values. The following claim bounds the distinguishing advantage between *X⁰* and *Y* *0* for any *T*-query distinguisher.

Claim 3. *For any* (*P⁰;* 1)*-dense source X⁰ and its corresponding P⁰-bit-xing source Y* *0* *, it holds* *that for any (adaptive) distinguisher D that queries at most T coordinates of its oracle,*

*X0Y0* P *D* = 1 P *D* = 1 *T* log *M;*

*and* *X0T Y0* P *D* = 1 *M* P *D* = 1 *:*

*Proof.* Assume without loss of generality that *D* is deterministic and does not query any of the xed positions. *0 0*

|Let T|and T be the random variables corresponding to the transcripts containing||
|---|---|---|
|X|Y||
|0|X|0 0|

the query/answer pairs resulting from *D*’s interaction with *X⁰* and *Y*, respectively. For a xed transcript, denote by p *0* () and p*Y0* () the probabilities that *X⁰* and *Y*, respectively, produce the answers in if the queries in are asked. Observe that these probabilities depend only on *X⁰* resp. *Y* and are independent of *D*. Observe that for every transcript,

|X|(1|)T||Y|T|||
|---|---|---|---|---|---|---|---|
|0|X||X X||Y|X|Y X|

p *0* () *M* and p *0* () = *M* (1)

as *X⁰* is (1)-dense and *Y* is uniformly distributed. Since *D* is deterministic, P[*T 0* =] *2 f*0*;* p *0* ()*g*, and similarly, P[*T 0* =] *2 f*0*;* p *0* ()*g*. Denote by *TX*the set of all transcripts for which P[*T 0* =] *>* 0. For such, P[*T 0* =] = p *0* ()

and also P[*TY0* =] = p*Y0* (). Towards proving the rst part of the lemma, observe that

*X0Y0* P *D* = 1 P *D* = 1 SD(*TX0;TY0*) X = max*f*0*;*P[*TX0* =] P[*TY0* =]*g*

X = max*f*0*;* p*X0* () p*Y0* ()*g* *2TX* X <u>p</u> <u>Y</u>*0* <u>()</u> = p*X0* () max 0*;* 1 p*X0* () *2TX* 1 *M* *T* *T* log *M;*

where the rst sum is over all possible transcripts and where the last inequality uses 2 *x* 1 *x* for *x* 0. As for the second part of the lemma, observe that due to (1) and the support of *TX0* being a subset of *TY0*,

|||X|T|Y|
|---|---|---|---|---|
||D||||
|X|2T|X|T 2T|Y|

P[*TX0* =] *M* *T* P[*TY0* =]

for any transcript. Let *T* be the set of transcripts where *D* outputs 1. Then,

*0* X X *T Y0* P[*D* = 1] = P[*T 0* =] *M* P[*T 0* =] = *M* P[*D* = 1]*:* *D D*

Let *Yz0*be obtained by replacing every *X⁰* by the corresponding *Y* *0* in *Xz0*. Setting*z*= (*Sz*+ log 1*=*)*=*(*P* log*M*), Claims 2 and 3 imply

*Xz Yz0* <u>(Sz+ log 1=) T</u> P *D* (*z*) = 1 P *D* (*z*) = 1 +*;* (2) *P*

as well as *Xz* (*Sz*+log 1*=*)*T=P Yz0* P *D* (*z*) = 1 2 P *D* (*z*) = 1 + *:* (3)

Moreover, note that for the above choice of*z*, *P⁰* = *P*, i.e., the sources *Y* *0* are xed on at most *P* coordinates, as desired.

Claim 4.E*z*[*Sz*] *S and* P *Sf* (*X*)*> S* + log 1*=.*

*Proof.* Observe that *H₁*(*Xz*) = *H₁*(*XjZ* = *z*) = *H*(*XjZ* = *z*) since, conditioned on *Z* = *z*, *X* is distributed uniformly over all values *x* with *f* (*x*) = *z*. Therefore,

E*z*[*Sz*] = *N* log*M* E*z*[*H₁*(*XjZ* = *z*)] = *N* log*M* E*z*[*H*(*XjZ* = *z*)] = *N* log*M H*(*XjZ*) *S :*

Again due to the uniformity of *X*, P[*f* (*X*) = *z*] = 2 *Sz*. Hence, X P *Sf* (*X*)*> S* + log 1*=* = P *f* (*X*) = *z* 2 *S* 2 (*S*+log 1*=*) *:* *z2f; gS*: *Sz>S*+log 1*=*

The rst part of the lemma now follows (using *Y*

||:= Y|) by taking expectations over z of (2) and||
|---|---|---|---|
|X|z f (X)|z0|f (X)|
|(S+2 log 1=)T=P|Y|||
||||f (X)|
|(S+2 log 1=)T=P|Y|||

applying the rst part of Claim 4. The second part of the lemma is proved as follows:

P *D* *X* (*f* (*X*)) = 1 P *D* (*f* (*X*)) = 1*;S S* + log 1*=* + P *S > S* + log 1*=*

2 P *Df* (*X*)(*f* (*X*)) = 1*;S S* + log 1*=* + +

2 P *Df* (*X*)(*f* (*X*)) = 1 + 2*;*

where the second inequality follows by taking expectations over *z* of (3) (together with the condition *SzS* + log 1*=*) and the second part of Claim 4.

## 2.2 From the BF-ROM to the AI-ROM

2.2.1 Capturing the Models Before Lemma 1 from the preceding section can be used to show how security proofs in the BF- ROM can be transferred to the AI-ROM, it is necessary to formally dene the two models as well as attackers with oracle-dependent advice and the notion of an application. The high-level idea is to consider two-stage attackers *A* = (*A₁; A₂*) and (single-stage) challengers C with access to an oracle
*O*. Oracles have two interfaces pre and main, where pre is accessible only to *A₁*, which may pass auxiliary information to *A₂*, and both *A₂* and C may access main. Oracles. An oracle *O* has two interfaces *O:* pre and *O:* main, where *O:* pre is accessible only once before any calls to *O:* main are made. Oracles used in this work are:
- Random oracle RO(*N;M*): Samples a random function table *F FN;M*, where *FN;M* is the set of all functions from [*N*] to [*M*]; oers no functionality at *O:* pre; answers queries *x 2* [*N*] at *O:* main by the corresponding value *F* [*x*] *2* [*M*].
- Auxiliary-input random oracle AI-RO(*N;M*): Samples a random function table *F* *FN;M*; outputs *F* at *O:* pre; answers queries *x 2* [*N*] at *O:* main by the corresponding value *F* [*x*] *2* [*M*].
- Bit-Fixing random oracle BF-RO(*P;N;M*): Samples a random function table *F FN;M*; takes a list at *O:* pre of at most *P* query/answer pairs that override *F* in the corresponding positions; answers queries *x 2* [*N*] at *O:* main by the corresponding value *F* [*x*] *2* [*M*].
- Standard model: Neither interface oers any functionality.
The parameters *N*, *M* are occasionally omitted in contexts where they are of no relevance. Similarly, whenever evident from the context, explicitly specifying which interface is queried is omitted.

Attackers with oracle-dependent advice. Attackers *A* = (*A₁; A₂*) consist of a preprocessing procedure *A₁* and a main algorithm *A₂*, which carries out the actual attack using the output of *A₁*. Correspondingly, in the presence of an oracle *O*, *A₁* interacts with *O:* pre and *A₂* with *O:* main.

Denition 2. *An* (*S;T*)-attacker *A* = (*A₁; A₂*) in the *O*-model *consists of two procedures*

- *A₁, which is computationally unbounded, interacts with O:* pre*, and outputs an S-bit string,* *and*

- *A₂, which takes an S-bit auxiliary input and makes at most T queries to O:* main*.*
In certain contexts, additional restrictions may be imposed on *A₂*, captured by some parameters *p*. *A* is referred to as (*S;T;p*)-attacker in such cases. Examples of such parameters include time and space requirements of *A₂* or a limit on the number of queries of a particular type that *A₂* makes to a challenger it interacts with. Observe that the parameter *S* is meaningful also in the standard model, where it measures the length of standard non-uniform advice to the attacker. The parameter *T*, however, is not relevant as there is no random oracle to query in the attack stage. Consequently, standard-model attackers with resources *p* are referred to as (*S;;p*)-attackers.

Applications. Let *O* be an arbitrary oracle. An application *G* in the *O*-model is dened by specifying a challenger C, which is an oracle algorithm that has access to *O:* main, interacts with the main stage *A₂* of an attacker *A* = (*A₁; A₂*), and outputs a bit at the end of the interaction. The *success* of *A* on *G* in the *O*-model is dened as

*O:* main *O:* pre *O:* main

||Succ (A)|(A₁|
|---|---|---|
||G;O||
|O:main O:pre|O:main||

*G;O*:= P *A₂*) *$* C = 1*;*

where *A₂* (*A₁*) *$* C denotes the bit output by C after its interaction with the attacker. This work considers two types of applications, captured by the next denition.

Denition 3. *For an* indistinguishability *application G in the O-model, the* advantage of an at- tacker *A is dened as* <u>1</u> Adv*G;O*(*A*) := 2 Succ*G;O*(*A*) *:* 2

*For an* unpredictability *application G, the advantage is dened as*

## AdvG;O(A) := SuccG;O(A) :

*An application G is said to be* ((*S;T;p*)*;"*)-secure *in the O-model if for every* (*S;T;p*)*-attacker A,*

## AdvG;O(A) ":

Combined query complexity. In order to enlist Lemma 1 for proving Theorems 5 and 6 below, the interaction of some attacker *A* = (*A₁; A₂*) with a challenger C in the *O*-model must be \merged"

( ) ( ) ( )
into a single entity *D* = (*D₁; D₂*) that interacts with oracle *O*. That is, *D₁* := *A₁* and *D₂* (*z*) :=

( ) ( ) *S*
*A₂* (*z*) *$* C for *z 2f*0*;* 1*g*. *D* is called the *combination of A and* C, and the number of queries it makes to its oracle is referred to as *the combined query complexity of A and* C. For all applications in this work there exists an upper bound *T* *G* comb = *T* *G* comb (*S;T;p*) on the combined query complexity of any attacker and the challenger.

2.2.2 Additive Error for Arbitrary Applications Using the rst part of Lemma 1, one proves the following theorem, which states that the security of any application translates from the BF-ROM to the AI-ROM at the cost of an additive term of roughly *ST=P*, where *P* is the maximum number of coordinates an attacker *A₁* is allowed to x in the BF-ROM.

*0* Theorem 5. *For any P 2* N *and every >* 0*, if an application G is* ((*S;T;p*)*;"*)*-secure in the* BF*-*RO(*P*)*-model, then it is* ((*S;T;p*)*;"*)*-secure in the* AI*-*RO*-model, for*

1 comb *0*<u>2(S + log) T</u>

|P is the combined query complexity corresponding to G. P Moreover, x an (S;T be the family of distributions guaranteed to exist by Lemma 1, where the function A⁰ = (A⁰; A⁰ 1 AI-RO z A 1 and presets BF-RO to match and C. Hence, D queries to its oracle. Therefore, by the rst part of Lemma 1, 0|G + 2 ;) and let G)-attacker A = (A₁; A₂) (expecting to interact with BF-RO): 2 : pre. Then, it samples one of the 0 Y on the at most is a distinguisher taking an 1 comb (S + log) T G|
|---|---|
|(A) + G; BF-RO Since there is only an additive term between the two success probabilities, the above inequality 0|P 1 comb 2(S + log) T G|
|(A) + G; BF-RO Multiplicative Error for Unpredictability Applications Using the second part of Lemma 1, one proves the following theorem, which states that the security A₁ is allowed to x roughly 0, if an 1 (S + 2 log) RO(N;M) -model for 0 " 2 " + 2 is the combined query complexity corresponding to G.|P 9 application translates from the BF-ROM to the AI-ROM at the cost of a ST unpredictability comb T; G;|

*" "* +

comb *where T* *G*

*Proof.* Fix *P* as well as. Set BF-RO := BF-RO( be an arbitrary application and C the corresponding challenger.), and let *fYzgz2f*0*;*1*gS* *f* is dened by *A₁*. Consider the following (*S;T*)-attacker

*0*

- *A₁* internally simulates *A₁* to compute *P*-bit-xing
*0 0* sources *Y* making up *YzP* points where *Y* is xed. The output of *A⁰*1is *z*.

- *A⁰*2works exactly as *A₂*.
Let *D* be the combination of *A₂* = *A⁰*2*S*-bit input and comb making at most *T* *G*

## SuccG;AI-RO(A) Succ + :

implies

## AdvG;AI-RO(A) Adv + 2

## for both indistinguishability and unpredictability applications.

2.2.3 of any *unpredictability* multiplicative factor of 2, provided that coordinates in the BF-ROM.
*0* Theorem 6. *For any P 2* N *and every > application G is* ((*S;T;p*)*;"*)*-* *secure in the* BF*-*RO(*P;N;M*)*-model for*

*P*

*then it is* ((*S;T;p*)*;"*)*-secure in the* AI*-*

comb <u>where T</u> <u>G</u> 9 The extra factor of 2 is technically only necessary for indistingusihability applications.

*Proof.* Using the same attacker *A⁰* as in the proof of Theorem 5 and applying the second part of Lemma 1, one obtains, for any *P* (*S* + 2 log 1 ) *T* *G* comb,

(*S*+2 log 1*=*)*T*comb*=P 0* Succ*G;*AI-RO(*A*) 2*G*Succ*G;*BF-RO(*A*) + 2 2 Succ*G;*BF-RO(*A⁰*) + 2*;*

which translates into Adv*G;*AI-RO(*A*) 2 Adv*G;*BF-RO(*A⁰*) + 2

## for unpredictability applications.

2.2.4 The Security of Applications in the AI-ROM The connections between the *auxiliary-input random-oracle model (AI-ROM)* and the *bit-xing* *random-oracle model (BF-ROM)* established above suggest the following approach to proving the security of particular applications in the AI-ROM: rst, deriving a security bound in the easy-to- analyze BF-ROM, and then, depending on whether one deals with an indistinguishability or an unpredictability application, generically inferring the security of the schemes in the AI-ROM, using Theorems 5 or 6. The three subsequent sections deal with various applications in the AI-ROM: Section 3 is de- voted to security analyses of basic primitives, where \basic" means that the oracle is directly used as the primitive; Section 4 deals with the collision resistance of hash functions built from a ran- dom compression function via the Merkle-Damgard construction (MDHFs); and, nally, Section 5 analyzes several cryptographic schemes with computational security.
# 3 Basic Applications in the AI-ROM

This section treats the AI-ROM security of one-way functions (OWFs), pseudorandom generators (PRGs), normal and weak pseudorandom functions (PRFs and wPRFs), and message-authentication codes (MACs). More specically, the applications considered are:

- One-way functions: For an oracle *O* : [*N*]*!* [*M*], given *y* = *O*(*x*) for a uniformly random *x 2* [*N*], nd a preimage *x⁰* with *O*(*x⁰*) = *y*.
- Pseudo-random generators: For an oracle *O* : [*N*]*!* [*M*] with *M > N*, distinguish *y* = *O*(*x*) for a uniformly random *x 2* [*N*] from a uniformly random element of [*M*].
- Pseudo-random functions: For an oracle *O* : [*N*] [*L*]*!* [*M*], distinguish oracle access to *O*(*s;*) for a uniformly random *s 2* [*N*] from oracle access to a uniformly random function *F* : [*L*]*!* [*M*].
- Weak pseudo-random functions: Identical to PRFs, but the inputs to the oracle are chosen uniformly at random and independently.
- Message-authentication codes: For an oracle *O* : [*N*] [*L*]*!* [*M*], given access to an oracle *O*(*s;*) for a uniformly random *s 2* [*N*], nd a pair (*x;y*) such that *O*(*s;x*) = *y* for an *x* on which *O*(*s;*) was not queried.

AI-ROM Security Bound in [19] Lower Bound *ST T ST SN*2*T* 1*=*3 *T* OWFs *N* + *N* same min *N* *;*2+ *N* *ST* 1*=*2 *T S* 1*=*2 *T*

||+||same|||+||
|---|---|---|---|---|---|---|---|
|S(T +q)|1=2 T||||S 1=2|T||
|N|N||||N|N||
|S(T +q)q|1=2 T|||||||
|LN|N|||||||
|S(T +q)|T 1|S(T +q|) T|T|ST SN|T 1=3|T|
|N|N M|N|N|M|N||N|

PRGs *N N N N* *S*(*T* +*q*prf) 1*=*2 *T S* 1*=*2 *T* PRFs + same + <u>prf prf</u> wPRFs + not analyzed not known sig sig 2 MACs + + + + min*;*2+

Table 1: *Asymptotic upper and lower bounds on the security of basic primitives against* (*S;T*)*-*

*attackers in the AI-ROM, where q*prf*and q*sig*denote PRF and signing queries, respectively, and* *where (for simplicity) N* = *M for OWFs. Observe that attacks against OWFs also work against* *PRGs and PRFs.*

The asymptotic bounds for the applications in question are summarized in Table 1. For OWFs, PRGs, PRFs, and MACs, the resulting bounds match the corresponding bounds derived by Dodis *et al.* [19], who used (considerably) more involved compression arguments; weak PRFs have not previously been analyzed. The precise statements and the corresponding proofs can be found in the following sections; the proofs all follow the paradigm outlined in Section 2.2.4 of rst assessing the security of a particular application in the BF-ROM and then generically inferring the nal bound in the AI-ROM using Theorems 5 or 6.

## 3.1 One-Way Functions

The application *G* OWF*;N;M* in the *O*(*N;M*)-model is dened via the challenger C OWF*;N;M* that picks an *x 2* [*N*], passes *y* := *O*(*x*) to the attacker, and outputs 1 if and only if the attacker returns a value *x⁰ 2* [*N*] with *O*(*x⁰*) = *y*.

Theorem 7. *Application G* OWF*;N;M* *is* ((*S;T*)*;"*)*-secure in the* AI*-*RO(*N;M*)*-model, where*

~ <u>ST T</u> *"* = *O* + *:* min(*N;M*) min(*N;M*)

*Proof.* Observe that for the OWF application, *T* comb = *T* + 1. Let := min(*N;M*). It suces to show that in the *O* := BF-RO(*P;N;M*)-model, *G* := *G* OWF*;N;M* is ((*S;T*)*; "*^)-secure for

<u>P T</u> *"*^ = *O* + *:*

Then, by setting := 1*=* and *P* := (*S* + 2 log)*T* comb = *O*~ (*ST*) and applying Theorem 6, the desired conclusion follows. Towards proving the bound in the BF-RO, suppose *P* + *T < N=*2 since otherwise the bound of *O*((*P* + *T*)*=N*) holds trivially. Let *A* = (*A₁; A₂*) be an (*S;T*)-attacker. Without loss of generality, assume *A* is deterministic, *A₂* makes distinct queries to non-prexed coordinates only, and, at the

||0|0P 0|
|---|---|---|
|T T|1|P|
||0j||

cost of one additional query, always queries its output. Let *L* = *f*(*x⁰;y₁*)*;:::;*(*x;y*)*g* be the points of *O* xed by *A₁*, and let *Q* = *f*(*x₁;y₁*)*;:::;*(*x;y*)*g* the queries *A₂* makes, along with the corresponding answers. In slight abuse of notation, let *x 2L* stand for *x* = *x* for some *j 2* [*P*].

Let *E⁰* be the event that the challenge equals one of the prexed images of *O*, i.e., *E⁰* = *fy* = *y* *j0* *g* for some *j 2* [*P*]. Moreover, for *i 2* [*T*], let *Ei*be the event that the *i* th query to *O* inverts *y*, i.e., *y* = *yi*. Observe that Succ*G;*BF-RO(*A*) P[*E⁰*] + P[*[iEij E⁰*] *:*

Note that if *x =2L*, *y* is independent from *y* *i0* for any *i 2* [*P*]. Hence,

*0 0P P* 2*P* P[*E*] P[*x 2L*] + P[*E j x =2L*] + *:* *N M*

As per the second probability, observe that X P[*ij E₁ \ ::: \ E*

||[ E j E⁰]||P[E|\ E⁰] :|
|---|---|---|---|---|
||i i|||i 1|
||||i||
|||||i 1|
|i|i||i||
|i|i 1|0|||

For any xed *i*, conditioned on particular values *y₁ 6*= *y;:::;y 6*= *y*, the event *Ei*= *fyi*= *yg* occurs if either *x* = *x* or if *x 6*= *x* and *y* = *y*. In the latter case, additionally conditioned on *xi6*= *x*, *yi*is independent of *y*. Hence,

1 1 2 1 3 P[*E j E₁ \ ::: \ E \ E*] + +*;* *N P* (*i* 1) *M N M*

where the second inequality uses *P* + *T < N=*2. Thus, overall,

<u>P T</u> Succ*G;O*(*A*) *O* + *:*

There exists an attack using rainbow tables [32] that achieves an advantage of () 2 1*=*3 *ST S T T* min*;* 2 + *:* *N N N*

## 3.2 Pseudorandom Generators

The application *G* PRG*;N;M* in the *O*(*N;M*)-model is dened via the challenger C PRG*;N;M* that picks uniformly at random a bit *b*, a value *x 2* [*N*], as well as a value *y₁ 2* [*M*], computes *y₀* := *O*(*x*), passes *yb*to the attacker, and outputs 1 if and only if the attacker returns a bit *b⁰* = *b*.

Theorem 8. *Application G* PRG*;N;M* *is* ((*S;T*)*;"*)*-secure in the* AI*-*RO(*N;M*)*-model, where* r! ~ <u>ST T</u> *"* = *O* + *:* *N N*

*Proof.* Observe that for the PRGs, *T* comb = *T* + 1. It suces to show that in the *O* := BF-RO(*P;N;*

*M*)-model, *G* := *G*
PRG*;N;M* is ((*S;T*)*; "*^)-secure for

<u>P T</u> *"*^ = *O* + *:* *N N* *p* Then, by setting := 1*=N* and *P* := *STN* and applying Theorem 5, the desired conclusion follows.

Towards proving the bound in the BF-RO, suppose *P* + *T < N=*2 since otherwise the bound of *O*((*P* + *T*)*=N*) holds trivially. Let *A* = (*A₁; A₂*) be an (*S;T*)-attacker. Without loss of generality, assume *A* is deterministic, and *A₂* makes distinct queries to non-prexed coordinates only. Let

|1 0|0P P 0||T T|
|---|---|---|---|
||||0j|
|||i||
|i|||i|
|||0||

*L* = *f*(*x⁰;y₁*)*;:::;*(*x;y*)*g* be the points of *O* xed by *A₁*, and let *Q* = *f*(*x₁;y₁*)*;:::;*(*x;y*)*g* the queries *A₂* makes, along with the corresponding answers. Let *E⁰* be the event that the seed equals one of the prexed coordinates of *O*, i.e., *E⁰* = *fx* = *x g* for some *j 2* [*P*]. Moreover, for *i 2* [*T*], let *E* be the event that the *i* th query to *O* equals the seed *x*, i.e., *x* = *x*. Observe that *A* only has non-zero advantage if either *E⁰* or, for some *i 2* [*T*], *E* occurs. Clearly, <u>P</u> P[*E*] *:* *N* Furthermore, using an argument along the lines to that of the proof of Theorem 7,

*0* *T* <u>2T</u> P[*[iEij E*]*;* *N P T N* where the last inequality uses *P* + *T N=*2. Overall,

<u>P T</u> Adv*G;O*(*A*) *O* + *:* *N N*

p The best known attack on PRGs is by De *et al.* [18] and achieves advantage *S=N* for the case *T* = 0.

## 3.3 Pseudorandom Functions

Application *G* PRF*;N;L;M* in the *O*(*NL;M*)-model is dened via the following challenger C PRF*;N;L;M* : It picks uniformly at random a bit *b* and a key *s 2* [*N*]. Then, if the attacker queries *x 2* [*L*], the challenger answers it by *O*(*s;x*) if *b* = 0 or by *F* (*x*) for a function table *F* : [*L*]*!* [*M*] chosen uniformly at random. For attackers *A* = (*A₁; A₂*) against PRFs, we make explicit the number *q*prfof evaluation queries *A₂* asks from the challenger.

Theorem 9. *Application G* PRF*;N;L;M* *is* ((*S;T;q*prf)*;"*)*-secure in the*AI*-*RO(*NL;M*)*-model, where* r! ~ <u>S(T + qprf) T</u> *"* = *O* + *:* *N N*

*Proof.* Observe that for the PRFs, *T* comb = *T* + *q*prf. It suces to show that in the *O* := BF-RO(*P;NL;M*)-model, *G* := *G* PRF*;N;L;M* is ((*S;T;q*prf)*; "*^)-secure for

<u>P T</u> *"*^ = *O* + *:* *N N* p Then, by setting := 1*=N* and *P* := *S*(*T* + *q*prf)*N* and applying Theorem 5, the desired conclusion follows. The proof proceeds similarly to the case of PRGs. In particular, one observes that *A* only has non-zero advantage if one of the prexed coordinates or one of the queries to *O* is of the type (*s;*), where *s* is the key chosen by the challenger. As for PRGs, this probability can easily be bounded by *O* (*P=N* + *T=N*).

p De *et al.* [18] provide an attack on PRGs. It achieves advantage *S=N* for the case *T* = 0 and can be extended to pseudorandom functions [19].

## 3.4 Weak Pseudorandom Functions

Application *G* wPRF*;N;L;M* in the *O*(*NL;M*)-model is dened via the following challenger C wPRF*;N;L;M* : It picks uniformly at random a bit *b* and a key *s 2* [*N*]. Then, whenever the attacker sends a re- quest, the challenger chooses a random *x 2* [*L*] and answers the request by (*x; O*(*s;x*)) if *b* = 0 or by (*x;F*(*x*)) for a function table *F* : [*L*]*!* [*M*] chosen uniformly at random. For attackers *A* = (*A₁; A₂*) against wPRFs, we make explicit the number *q*prfof evaluation queries *A₂* asks from the challenger.

Theorem 10. *Application G* wPRF*;N;L;M* *is* ((*S;T;q*prf)*;"*)*-secure in the*AI*-*RO(*NL;M*)*-model, where* r! ~ <u>S(T + qprf)qprfT</u> *"* = *O* + *:* *NL N*

*Proof.* Observe that for the wPRFs, *T* comb = *T* + *q*prf. It suces to show that in the *O* := BF-RO(*P;NL;M*)-model, *G* := *G* wPRF*;N;L;M* is ((*S;T;q*prf)*; "*^)-secure for

<u>q</u> <u>prfP T</u> *"*^ = *O* + *:* *NL N* p Then, by setting := 1*=N* and *P* := *S*(*T* + *q*prf)*NL=q*prfand applying Theorem 5, the desired conclusion follows. The proof proceeds similarly to the case of PRFs. In particular, one observes that *A* only has non-zero advantage if (1) one of the random queries matches one of the prexed coordinates or (2) one of the queries to *O* is of the type (*s;*), where *s* is the key chosen by the challenger. Similarly to the proof for PRFs, this probability can easily be bounded by *O* (*q*prf*P=NL* + *T=N*).

## 3.5 Message-Authentication Codes

Application *G* MAC*;N;L;M* in the *O*(*NL;M*)-model is dened via the following challenger C MAC*;N;L;M* : It initially chooses a key *s 2* [*N*] uniformly at random and answers attacker queries *x 2 L* by returning *O*(*s;x*). The attacker wins if he submits a pair (*x;y*) *2* [*L*] [*M*] with *O*(*s;x*) = *y* for a previously unqueried *x*. For attackers *A* = (*A₁; A₂*) against MACs, we make explicit the number *q*sigof signing queries *A₂* asks from the challenger.

Theorem 11. *The application G* MAC*;N;L;M* *is* ((*S;T;q*sig)*;"*)*-secure in the*AI*-*RO(*NL;M*)*-model,* *where* ~ *S*(*T* + *q*sig) *T* 1 *"* = *O* + + *:* *N N M*

*Proof.* Observe that for the MAC application, *T* comb = *T* + *q*sig. It suces to show that in the *O* := BF-RO(*P;NL;M*)-model, *G* := *G* MAC*;N;L;M* is ((*S;T;q*sig)*; "*^)-secure for

*P T* *"*^ = *O* + + *:* *N N M*

Then, by setting := 1*=N* and *P* := (*S*+ 2 log*N*)*T* comb = *O*~ (*S*(*T* + *q*sig)) and applying Theorem 6, the desired conclusion follows. Similarly to all previous proofs, the advantage of *A* is at most 1*=M* unless one of the prexed coordinates or queries to *O* is of the type (*s;*), where *s* is the key chosen by the challenger. This event is easily upper bounded by *O* (*P=N* + *T=N*).

There exists an inversion attack using rainbow tables [32] that achieves an advantage of () 2 1*=*3 *ST S T T* min*;* 2 + *:* *N N N*

# 4 Collision Resistance in the AI-ROM

A prominent application missing from Section 3 is that of *collision resistance*, i.e., for an oracle *O* : [*N*] [*L*]*! M*, given a uniformly random salt value *a 2* [*N*], nding two distinct *x;x⁰ 2* [*L*] such that *O*(*a;x*) = *O*(*a;x⁰*). The reason for this omission is that in the BF-ROM, the best possible bound is easily seen to be in the order of *P=N*+*T²=M*. Even applying Theorem 6 for unpredictability applications with *P ST* results in a nal AI-ROM bound of roughly *ST=N* + *T²=M*, which is inferior to the optimal bound of *S=N* + *T²=M* proved by Dodis *et al.* [19] using compression. However, hash functions used in practice, most notably SHA-2, are based on the Merkle- Damgard mode of operation for a compression function *O* : [*M*] [*L*]*!* [*M*], modeled as a random oracle here. Specically, a *B*-block message *y* = (*y₁;:::;yB*) with *yj2* [*L*] is hashed to *O* *B*

(*y*),
where *O¹*(*y₁*) = *O*(*a;y₁*) and *O* *j* (*y₁;:::;yj*) = *O*(*O* *j* 1 (*y₁;:::;yj* 1)*;yj*) for *j >* 1.

While|as pointed out above|Dodis *et al.* [19] provide a tight bound for the one-block case, it is not obvious at all how their compression-based proof can be extended to deal with even two-block messages. Fortunately, no such diculties appear when we apply our technique of going through the BF-ROM model, allowing us to derive a bound in Theorem 12 below. Formally, the collision resistance of Merkle-Damgard hash functions (MDHFs) in the *O*(*ML;M*)- model is captured by the application *G* MDHF*;M;L*, which is dened via the following challenger C MDHF*;M;L* : It initially chooses a public initialization vector (IV) *a 2* [*M*] uniformly at random and

|||0 B 0|
|---|---|---|
|0 B|B 0||

sends it to the attacker. The attacker wins if he submits *y* = (*y₁;:::;yB*) and *y⁰* = (*y₁* *0* *;:::;y* *0* *0* ) *0* such that *y 6*= *y* and *O* (*y*) = *O* (*y*). For attackers *A* = (*A₁; A₂*) in the following theorem, we make the simplifying assumption that *T >* max(*B;B⁰*). We prove the following bound on the security of MDHFs in the AI-ROM:

Theorem 12. *Application G* MDHF*;M;L* *is* ((*S;T;B*)*;"*)*-secure in the* AI*-*RO(*ML;M*)*-model, where*

~ <u>ST² T²</u> *"* = *O* + *:* *M M*

*Proof.* Observe that for the MDHFs application, *T* comb = *T* + max(*B;B⁰*) = *O* (*T*). It suces to show that in the *O* := BF-RO(*P;ML;M*)-model, *G* := *G* MDHF*;M;L* is ((*S;T*)*; "*^)-secure for

<u>PT T²</u> *"*^ = *O* + *:* *M M*

Then, by setting := 1*=N* and *P* := (*S* + 2 log*N*)*T* comb = *O*~ (*ST*) and applying Theorem 6, the desired conclusion follows. Towards proving the bound in the BF-RO, let *A* = (*A₁; A₂*) be an (*S;T*)-attacker. With- out loss of generality, assume *A* is deterministic, *A₂* makes distinct queries to non-prexed co- ordinates only, and, at the cost of one additional query, always queries its output. Let *L* = *f*((*a⁰*1*;x⁰*1)*;y₁* *0* )*;:::;* ((*a* *0P* *;x* *0P* )*;y* *P* *0* )*g* be the points of *O* xed by *A₁*, and let *Q* = *f*((*a₁;x₁*)*;y₁*)*;:::;* ((*aT;xT*)*;yT*)*g* the queries *A₂* makes, along with the corresponding answers. Call a salt value *a⁰ 2* [*M*] *dirty* if it appears in *L*. Moreover, call it *reachable* if there exists a chain from the IV *a* chosen by the challenger, i.e., if there exist *j₁;:::;jd*such that *aj*1= *a*, *O*(*aj*1*;xj*1) = *aj*2*;:::; O*(*aj* *d* *;xj* *d* ) = *a⁰*. Let *Ri*denote the set of values *a⁰* is reachable after the rst *i* queries *A₂* makes to *O*. The set *Ri*is called *dirty* if some *a⁰ 2 Ri*is dirty and *clean* otherwise. Finally, for every *i 2* [*T*], (*ai;xi*) is said to *form a collision* if *ai2 Ri*and *O*(*ai;xi*) *2 Ri*. Assume without loss of generality that the queries of *A₂* contain the evaluation of *O* *B*

(*y*) and
*B00* *O* (*y*). The success probability of *A₂* is at most

X *T* P[(*ai;xi*) forms collision *j Ri*is clean] + P[*Ri*+1is dirty *j Ri*is clean] *i*=1 X *T* *i P PT T²* + = *O* + *:* *M M N N* *i*=1

Observe that if *S* and *T* are taken to be the circuit size, the bound in Theorem 12 becomes vacuous for circuits of size *M¹* *=*3, i.e., it provides security only *well below* the birthday bound and may therefore seem extremely loose. Quite surprisingly, however, it is tight:

Theorem 13. *There exists an* (*S;T*)*-attacker A* = (*A₁; A₂*) *against application G* := *G* MDHF*;M;L* *in the O* := AI*-*RO(*ML;M*)*-model with advantage at least*

~ <u>ST² 1</u> Adv*G;O*(*A*) = +*;* *M M*

## assuming ST² M=2 and L M.

The attack is loosely based on rainbow tables [32] and captured by the following (*S;T*)-attacker *A* = (*A₁; A₂*):

- *A₁*: Obtain the function table *F* : [*M*] [*L*]*!* [*M*] from *O*. For *i* = 1*;:::;m* := *S=*(3*d*log *Le*), proceed as follows:
1.Choose *ai;*0*2* [*M*] uniformly at random.

|i;‘ 1|(‘ 1)|i;0||10||
|---|---|---|---|---|---|
|i|0i|i;‘|i;‘ 1 i|i;‘|1 0i|

2.Compute *a F*
(*‘* 1) (*a;*0), where *‘* := *bT=*2*c*. 10

3.Find values *x 6*= *x* such that *a* := *F* (*a;x*) = *F* (*a;x*); abort if no such values exist.
Output the triples (*ai;‘;xi;x* *0i* ) for *i* = 1*;:::;m*.

*F*

(*k*) stands for the *k*-fold application of *F*, and, for the sake of concreteness, let [*L*] = *f;:::;L g*.

- *A₂*: Obtain the public initialization vector *a* from C
MDHF*;M;L* and the *m* triples output by *A₁*. Proceed as follows:

1.If *a* = *ai;‘* 1for some *i*, return (*xi;x*
*0i* ).

2.Otherwise, set ~*a a* and for *j* = 1*;:::;T*, proceed as follows:
(a)Query ~*a O* (~*a;* 0).
(b)If ~*a* = *ai;‘* 1for some *i*, return (0
*j* *kxi;* 0 *j* *kx* *0i* ); otherwise return (0*;*1).

Lemma 14. *The advantage of the* (*S;T*)*-attacker A* = (*A₁; A₂*) *against G* = *G* MDHF*;M;L* *in the* *O* = AI*-*RO(*ML;M*)*-model is*

<u>ST² 1</u> Adv*G;O*(*A*) +*;* 50*M* log*L M*

## assuming ST² M=2.

*Proof.* First, observe that the probability that for one of the values *ai;‘* 1, there is no collision (*xi;x* *0i* ) is at most <u>M!</u>(*M* 1)*=*2 *M=*2 *m* *M* *m e S e* *M* if *L* = *M* and zero if *L > M*. Let *A* := *fai;jj i* = 1*;:::;m; j* = 0*;:::;‘* 1*g* be the set of values encountered while building the *m* chains during preprocessing. Observe that the attack always succeeds if ~*a 2 A* within the rst *‘* queries *A₂* makes to *O*, as in such a case *ai;‘* 1(for the appropriate *i*) can be reached in the remaining *‘* queries. For *j* = 0*;:::;‘*, let *Ej*be the event that ~*a 2 A for the rst time* after the *j* th query to *O*. Then, conditioned on a particular set *A*, *j* *jAj jAj jjAj jAj jAj* P[*Ej*] = 1 1*;* *M M M M* 2*M*

using Bernoulli’s inequality as well as the facts that *j T*, *jAj m‘*, and *m‘T ST² M=*2. Since the events *Ej*are disjoint, the probability that ~*a 2 A* within the rst *‘* queries is at least

<u>‘jAj T jAj</u> *:* 2*M* 4*M*

## Putting the above together, one obtains

<u>T jAj</u>*M=*2 Adv*G;O*(*A*) E *S e;* 4*M*

and, hence, it only remains to compute the expected size of *jAj*. Towards this, following [32], let *Ei;j*be the event that *ai;j*is new when discovered during preprocessing. Note that

## P[Ei;j] P[Ei;0\ ::: \Ei;j]

Y *j*

||P[E|jE \ ::: \E|]|
|---|---|---|---|
|||i;k i;0|i;k 1|
||k=0|j+1|2|

*M i‘ m‘ ST* *M M M*

since at most *i‘* values are *not* new when *ai;k*is chosen. Therefore,

X *m* X *‘* 1 <u>m‘ ST</u> E[*jAj*] P[*Ei;j*] *:* 2 12*d*log *Le* *i*=1 *j*=0

## Combining all of the above yields

<u>ST²</u>*M=*2<u>ST²</u> Adv*G;O*(*A*) *S e :* 49*M* log*L* 50*M* log*L*

The additional term 1*=M* is the probability that the attack’s output (0*;*1) in case of failure is a collision.

It should be noted that in practice hash functions use a xed IV *a*, and, therefore|in contrast to, e.g., function inversion, where usually the cost of a single preprocessing stage can be amortized over many inversion challenges|the rather sizeable amount of preprocessing required by the attack to just nd a collision may not be justied. However, in some cases, the hash function used in a particular application (relying on collision-resistance) is salted by prepending a random salt value to the input. Such salting essentially corresponds to the random-IV setting considered here, and, therefore, the attack becomes relevant again as one might be able to break many instances of the application using a single preprocessing phase.

# 5 Computationally Secure Applications in the AI-ROM

This section illustrates the bit-xing methodology on two typical computationally secure applica- tions: (1) Schnorr signatures [50], where Theorem 6 can be applied since forging signatures is an unpredictability application, and (2) trapdoor-function (TDF) key-encapsulation (KEM) [8], where an approach slightly more involved than merely analyzing security in the BF-ROM and applying Theorem 5 is required in order to get a tighter security reduction; see below. (Please refer to Section B of the appendix for the denitions of digital signatures, KEMs, TDFs, and other standard concepts used in this section.)

Fiat-Shamir with Schnorr. Let *G* be a cyclic group of prime order *jGj* = *N*. The Schnorr signature scheme = (Gen*;*Sig*;*Vfy) in the *O*(*N²;N*)-model works as follows:

- Key generation: Choose *x 2* Z*N*uniformly at random, compute *y g*
*x*, and output sk := *x* and vk := *y*.

- Signing: To sign a message *m 2* [*N*] with key sk = *x*, pick *r 2* Z*N*uniformly at random, compute *a g*
*r*, query *c O* (*a;m*), set *z r* + *cx*, and output := (*a;z*).

- Verication: To verify a signature = (*a;z*) for a message *m* with key vk = *y*, query
*z*? *c* *c O* (*a;m*), and check whether *g* = *ay*. If the check succeeds and *c 6*= 0, accept the signature, and reject it otherwise.

For attackers *A* = (*A₁; A₂*) in Theorem 15, which assesses the security of Fiat-Shamir with Schnorr in the AI-ROM, we make the running time *t* and space complexity *s* of *A₂* explicit. Moreover, if *A* is an attacker against *G* DS*;*, there is an additional parameter *q*sigthat restricts *A₂* to making at most *q*sigsigning queries.

Theorem 15. *Assume G* DL*;G* *for a prime jGj* = *N is* ((*S⁰;;t⁰;s⁰*)*;"* *0* )*-secure, and let* = (Gen*;*Sig*;* Vfy) *be the Schnorr scheme. Then, for any T;q*sig*2* N*, G* DS*;* *is* ((*S;T;t;s;q*sig)*;"*)*-secure in the* AI*-*RO(*N²;N*)*-model for* *p* <u>Sq</u> <u>sig(qsig+ T)</u> *"* = *O*~ *T"* *0* +*;* *N*

*any S S⁰=O*~ (*T* + *q*sig)*, t t⁰ O*~ (*S*(*T* + *q*sig))*, and s s⁰ O*~ (*S*(*T* + *q*sig))*.*

*Proof.* Let *P 2* N be arbitrary, and set BF-RO := BF-RO(*P;N²;N*) and AI-RO := AI-RO(*N²;N*). One rst shows that *G* DS*;* is *"*-secure in the BF-RO-model for

*0*<u>T</u> *p* *0* *"* 2 max *"* + *E;* + *T"* *N*

for <u>q</u> <u>sig(qsig+ T + P + 1)</u> *E :* *N* Then, by observing that *T* *G* comb DS*;*= *q*sig+ *T* + 1 for digital signatures, setting := 1*=N* as well as *P* := (*S* + 2 log*N*)*T* *G* comb DS*;*, and applying Theorem 6 to the above, one gets a nal security bound of

*p* <u>Sq</u> <u>sig(qsig+ T)</u> *O* ~ *T"0*+ *N*

Let *A* = (*A₁; A₂*) be an (*S;T;t;s;q*sig)-attacker against *G* DS*;* in the BF-RO-model. Consider attacker *A⁰* = (*A⁰*1*; A⁰*2) against *G* DL*;G* :

- *A⁰*1: Run *A₁* internally, to get the list *L* of coordinates and values *A₁* would x its oracle to as well as the auxiliary information *z* that *A₁* would pass to *A₂*. For every entry ((*a;m*)*;c*) *2L*, compute the discrete logarithm *r* of *a* and store ((*a;m*)*;c;r*) in enhanced list *L⁰*. Output (*z; L⁰*).
- *A⁰*2: First, consider the following algorithm A(*y;h₁;:::;hT*), which internally runs *A₂*:
1.Run *A₂*(*z*) and answer oracle queries made by *A₂* using the values *h₁;:::;hT*. When *A₂* asks to see a signature of *m*, generate a simulated triple (*a;c;z*) (by choosing *z* and *c* uniformly at random and setting *a g*
*z* *y* *c* ) and return = (*a;z*). If *A₂* has made an oracle query (*a;m*) or if there exists a tuple ((*a;m*)*; ;*) *2L⁰*, halt and output (0*;*0). Otherwise, answer oracle queries for (*a;m*) by *c*.

2.When *A₂* terminates and outputs a valid forgery (*m ;*) for = (*a ;z*) proceed as follows:
(a)If ((*a ;m*)*;c ;r*) *2L⁰*, for some *c* and *r*, compute *x* (*z r*)*=c* and output ( 1*;x*).
(b)If (*a ;m*) was the *J*
th oracle query by *A₂*, output (*J;*(*;m*)). If no valid forgery is output, output (0*;*0).

*A⁰*2, on input *y* and auxiliary input (*z; L⁰*), proceeds as follows: It picks uniformly random values *h₁;:::;hT*, and runs A(*y;h₁;:::;hT*;), where are the uniformly random coins for use by A. Then:

{ If A outputs (*;x*), *A⁰* outputs *x*.

{ If A outputs (0*;*0), *A⁰*2aborts.

|2||0J|0T|J 1 0J|
|---|---|---|---|---|
|0|0|J 0J|2|J 0J|

{ If A outputs (*J;*), *A⁰* chooses fresh (*h* *0J* *;:::;h* *0T* ) and runs A(*y;h₁;:::;h;h* *0J* *;:::;h* *0T*; ). If the output is (*J;*) and *h 6*= *h*, *A⁰* extracts *x* := (*z z⁰*)*=*(*h h*) from = (*a;z*) and = (*a;z⁰*) and outputs it. Otherwise, *A⁰*2aborts.

Observe that for the above choice of *P*, *A⁰* is an (*S⁰;T⁰;t⁰;s⁰*)-attacker. Consider the rst execution of algorithm A(*y;h₁;:::;hT*;). The probability that the output has *J 6*= 0 is at least *"* *0* *E*, where

<u>q</u> <u>sig(qsig+ T + P + 1)</u> *E :* *N*

## Consider the following two cases:

- The probability that *J* = 1 is at least *"=*2 *E*. In that case, *A⁰*2has success probability *"* *0* *"=*2 *E*, or, equivalently, *"* 2(*"*
*0* + *E*).

- The probability that *J >* 0 is at least *"=*2. Following the forking lemma in [7, Lemma 1], the probability that *A⁰*2succeeds is at least
*0" "* 1 *";* 2 2*T N*

which implies <u>T</u> *p* *0* *"* 2 + *T" :* *N*

For comparison, note that the security of Schnorr signatures in the standard ROM is

*p* <u>q</u> <u>sig(qsig+ T)</u> *O T"* *0* +*;* *N*

i.e., in the AI-ROM the second term worsens by a factor of *S*. TDF Key Encapsulation. Let *F* be a trapdoor family (TDF) generator. TDF encryption is a key-encapsulation mechanism = (Gen*;*Enc*;*Dec) that works as follows:
- Key generation: Run the TDF generator to obtain (*f;f*
1 ) *F*, where *f;f* 1 : [*N*]*!* [*N*]. Set the public key pk := *f* and the secret key sk := *f* 1.

- Encapsulation: To encapsulate a key with public key pk = *f*, choose *x 2* [*N*], query *k O* (*x*), compute *y f* (*x*), and output (*c;k*) (*y;k*).
- Decapsulation: To decapsulate a ciphertext *c* = *y* with secret key sk = *f*
1, output *k* *O*(*f* 1

(*y*)).
Theorem 16 deals with the security of TDF key encapsulation in the AI-ROM. Once again, for attackers *A* = (*A₁; A₂*), the running time *t* and space complexity *s* of *A₂* is made explicit.

Theorem 16. *Let be TDF encapsulation. If G* TDF*;F* *is* ((*S⁰;;t⁰;s⁰*)*;"* *0* )*-secure, then, for any* *T 2* N*, G* KEM*-*CPA*;* *is* ((*S;T;t;s*)*;"*)*-secure in the* AI*-*RO(*N;N*)*-model, where* r! ~*0* <u>ST</u> *"* = *O "* + *N*

*and S* = *S⁰ O*~ (*ST*)*, t* = *t⁰ O*~ (*t*tdf*T*)*, and s* = *s⁰ O*~ (*ST*)*, where t*tdf*is the time required to* *evaluate the TDF.* *Moreover, G* KEM*-*CCA*;* *is* ((*S;T;t;s*)*;"*)*-secure with the same parameters, except that t* = *t⁰* *O* ~ (*t* tdf*ST*)*.*

Observe that the above security bound corresponds simply to the sum of the security of the TDF and the security of *O* as a PRG (cf. Section 3); in the standard random-oracle model, the security of TDF encryption is simply upper bounded by *O* (*"* *0* ) (cf. Section B.2). An important point about the proof of Theorem 16 is that it does not follow the usual paradigm of deriving the security of TDF encryption in the BF-ROM and thereafter applying Theorem 5 (for CPA/CCA security is an indistinguishability application). Doing so|as Unruh does for RSA- OAEP [52] (but in an \asymptotic sense," as explained in Footnote 5)|would immediately incur an additive error of *ST=P ST=t⁰*, since the size of the list *P* is upper bounded by the TDF attacker size *t⁰*. So the naive application Theorem 5 would result in poor exact security. Instead, our tighter proof of Theorem 16 considers two hybrid experiments (one of which is the original CPA/CCA security game in the AI-ROM). The power of the BF-ROM is used twice|with dierent list sizes: (1) to argue the indistinguishability of the two experiments and (2) to upper bound the advantage of the attacker in the second hybrid. Crucially, a reduction to TDF security is only required for (1), which has an unpredictability avor and can therefore get by with a list size of roughly *P ST*; observe that this is polynomial for ecient (*S;T*)-attackers. The list size for

(2) is obtained via the usual balancing between *ST=P* and the security bound in the BF-ROM.
11

*Proof.* Let *A* = (*A₁; A₂*) be an (*S;T;t;s*)-attacker against *G* KEM-CPA*;*. Denote by *H₀* the ex- periment in which *A* interacts with the challenger C KEM-CPA*;* (and oracle AI-RO). Consider the following hybrid *H₁*: It behaves as *H₀*, but when *A₂* queries *x* to *O*, the oracle answers by*?*. (The key is still generated as *O*(*x*).) Observe that *H₀* and *H₁* behave identically unless *A₂* queries *x*; denote this event by *E*. Towards bounding P[*E*], consider the following distinguisher *D* = (*D₁; D₂*) with oracle access to an (*N;N*)-source:

- *D₁* works exactly as *A₁*.
- *D₂*, on input *z*, simulates the interaction between *A₂*(*z*) and C
KEM-CPA*;*, answering oracle queries by either of them using its own oracle. If *A₂* queries *x* at some point, *D₂* outputs 1; if *A₂* terminates without querying *x*, *D₂* outputs 0.

Let *X* be a uniform (*N;N*)-source. Observe that

P[*E*] = P[*D₂* *X* (*D₁*(*X*)) = 1]

and that *D₂* makes at most *T* + 1 queries to its oracle.

A similar approach also works to improve the security bounds of [52] for RSA-OAEP in the AI-ROM.

Let *P* := *d*(*S*+2 log*N*)(*T*+1)*e*. By the second part of Lemma 1, there exists a family *fYzgz2f*0*;*1*gS* of convex combinations *Yz*of *P*-bit-xing (*N;N*)-sources such that h *Y* i *XD*2(*X*)1 P *D₂* (*D₁*(*X*)) = 1 2 P *D₁* (*D₂*(*X*)) = 1 + 2*N :*

Consider the following attacker against the TDF security of *F* :

- *B₁* internally runs *z A*1(*X*) on a uniform (*N;N*)-source *X*. Thereafter, it samples a *P*- bit-xing source *Y*
*0* from the convex combination *Yz*corresponding to *z* and outputs (*z; L*), where *L* is the list of the at most *P* input/output paris at which *Y* *0* is xed.

- *B₂*, on input (*z; L*), obtains a pair (*f;y*) from its challenger and internally runs *A₂*(*z*). It passes the public key pk := *f* to *A₂* and the challenge ciphertext (*y;r*) to *A₂*, where *r 2* [*N*] is chosen uniformly at random. When *A₂* makes an oracle query *x*, *B₂* answers it using lazy sampling but consistent with the list *L*. Each time, *B₂* computes *f* (*x*) and if the result equals *y*, *B₂* outputs *x* to its challenger.
*Y* *D*2(*X*) Note that unless *x* is in the pre-xed list *L*, *B* perfectly simulates the experiment *D₁* (*D₂*(*X*)) to *A*. Hence, h *Y* i <u>P P</u> *D*2(*X*)TDF*;F 0* P *D₁* (*D₂*(*X*)) = 1 Succ*B*(*G*) + *"* + *:* *N N* Summarizing, *0*<u>(S + logN)(T + 2)</u> P[*E*] 2 *"* + *:* (4) *N*

It remains to analyze the advantage of *A* in the hybrid experiment *H₁*. To that end, consider the following distinguisher *D* = (*D₁; D₂*) with oracle access to an (*N;N*)-source:

- *D₁* works exactly as *A₁*.
- *D₂*, on input *z*, simulates the interaction between *A₂*(*z*) and C
KEM-CPA*;*, answering oracle queries by either of them using its own oracle, except that whenever *A₂* queries *x*, *D₂* provides *?* as the answer. At the end, *D₂* outputs whatever bit the challenger outputs.

Let *P 2* N be an arbitrary integer. By the rst part of Lemma 1, there exists a family *fYzgz2f*0*;*1*gS* of convex combinations *Yz*of *P⁰*-bit-xing (*N;N*)-sources such that h *Y* i <u>(S + logN) T</u> *XD*2(*X*)1 P *D₂* (*D₁*(*X*)) = 1 P *D₁* (*D₂*(*X*)) = 1 + *N :* *P* *Y* *D*2(*X*) Consider now the experiment *D₁* (*D₂*(*X*)). Unless *x* is among the at most *P* positions at which *YD* 2

(*X*)is xed, the view of *A₂* is independent of the challenge bit *b*, and, hence,
h *Y* i <u>1 P</u> *D*2(*X*) P *D₁* (*D₂*(*X*)) = 1 + *:* 2 *N* *p* Choosing a list size *P* = *STN* allows to bound the advantage of *A* in *H₁* by r! *O* ~*;* <u>ST</u> *N*

which dominates the second term in (4). The theorem follows. The proof for CCA security is similar, except that the second stage *B₂* of the attacker against the TDF security of *F* proceeds as follows:

- *B₁* internally runs *z A*1(*X*) on a uniform (*N;N*)-source *X*. Thereafter, it samples a *P*- bit-xing source *Y*
*0* from the convex combination *Yz*corresponding to *z* and outputs (*z; L*), where *L* is the list of the at most *P* input/output paris at which *Y* *0* is xed.

- *B₂*, on input (*z; L*), obtains a pair (*f;y*) from its challenger. For every pair (*x; O*(*x*)) appearing in list *L*, *B₂* computes *y f* (*x*) and records the pair (*y; O*(*x*)). *B₂* then internally runs *A₂*(*z*). It passes the public key pk := *f* to *A₂* and the challenge ciphertext (*y;r*) to *A₂*, where *r 2* [*N*] is chosen uniformly at random. Decryption queries *y⁰* by *A₂* are answered as follows: If (*y⁰;r⁰*) has been recorded for some *r⁰*, the answer is *r⁰*; otherwise, *B₂* chooses a random value *r⁰*, records (*y⁰;r⁰*), and returns *r⁰*. When *A₂* makes an oracle query *x*, *B₂* answers it using lazy sampling but consistent with the list *L*. Each time, *B₂* computes *f* (*x*) and if the result equals *y*, *B₂* outputs *x* to its challenger.
# 6 Salting Defeats Auxiliary Information

There exist schemes that are secure in the standard ROM but not so in the AI-ROM. A simple example is if the random oracle itself is directly used as a collision-resistant hash function *O* : [*N*]*!* [*M*] for some *N* and *M*: in the ROM, *O* is easily seen to be collision-resistant, while in the AI-ROM, the rst phase *A₁* of an attacker *A* = (*A₁; A₂*) (cf. Section 2.2) can simply leak a collision to *A₂*, which then outputs it, thereby breaking the collision-resistance property. Section C.1 in the appendix briey highlights two schemes with computational security where the above phenomenon can be observed as well. The rst one is a generic transformation of an identication scheme into a signature scheme using the so-called *Fiat-Shamir transform*, and the second one is the well-known *full-domain hash*. 12

To remedy the situation with schemes such as those mentioned above, in this section we prove that the security of any *standard* ROM scheme can be carried over to the BF-ROM by sacricing part of the domain of the BF-RO for *salting*. First, in Section 6.1, we analyze the standard way of salting a random oracle by prexing a randomly chosen (public) value to every oracle query. Second, in Section 6.2, we also show how to adapt a technique by Maurer [42], originally used in the context of key-agreement with randomizers, to obtain a more domain-ecient salting technique, albeit with a longer salt value; the salt length can be reduced by standard derandomization techniques based on random walks on expander graphs. The salting method has the advantage of being applicable to every possible application that can be proven secure in the *standard* ROM. Moreover, for most of the applications presented in the preceding sections, salting with values from a suciently large space allows to recover the bounds proved by analyzing the security of the (unsalted) applications in the ROM directly. Thus, in this sense, *salting provably defeats preprocessing*. However, this comes at the price of assuming a much larger domain of the random oracle (so that *S* is now a much tinier fraction of the random oracle domain). Moreover, in many concrete cases we observe that by analyzing the *salted* scheme in the BF-ROM directly and using Theorems 5 or 6, we might get considerably better security bounds for 12 By virtue of Theorem 6, the existence of attacks in the AI-ROM against the above schemes obviously implies that these schemes cannot be secure in the BF-ROM either. It is also relatively straight-forward to devise direct attacks in the BF-ROM.

salted applications than by using our general theorems. 13 Nevertheless, for settings where obtaining the smallest possible salt value is not critical, the simplicity and generality of our compilers oer a convenient and seamless way to argue security in AI-ROM.

## 6.1 Standard Salting

The standard way of salting a scheme is to simply prepend a public salt value to every oracle query: Consider an arbitrary application *G* with the corresponding challenger C. Let Csaltbe the challenger that is identical to C except that it initially chooses a uniformly random value *a 2* [*K*], outputs *a* to *A₂*, and prepends *a* to every oracle query. Denote the corresponding application by *G*salt. Observe that the salt value *a* is chosen after the rst stage *A₁* of the attack, and, hence, as long as the rst stage *A₁* of the attacker in the BF-ROM does not prex a position starting with *a*, it is as if the scheme were executed in the standard ROM. Moreover, note that the time and space complexities *s* and *t*, respectively, of *A₂* increase roughly by *P* due to the security reduction used in the proof.

Theorem 17. *For any P 2* N*, if an application G is* ((*S⁰;T⁰;t⁰;s⁰*)*;"* *0* )*-secure in the* RO(*N;M*)*-* *model, then G*salt*is* ((*S;T;t;s*)*;"*)*-secure in the* BF*-*RO(*P;NK;M*)*-model for*

*0*<u>P</u> *"* = *"* +*;* *K*

*S* = *S⁰ O*~ (*P*)*, T* = *T⁰, t* = *t⁰ O*~ (*P*)*, and s* = *s⁰ O*~ (*P*)*.*

*Proof.* Fix *N*, *M*, *K*, as well as *P*. Set BF-RO := BF-RO(*P;N;M*) and RO := RO(*N;M*), and let *G* be an arbitrary application and C be the corresponding challenger. Fix an (*S;T;t;s*)-attacker *A* = (*A₁; A₂*) against *G*salt, and consider the following (*S⁰;T⁰;t⁰;s⁰*)- attacker *A⁰* = (*A⁰*1*; A⁰*2) against *G* (expecting to interact with RO):

- *A⁰*1internally runs *A₁* to obtain the list *L* of preset values and auxiliary information *z* and outputs (*z; L*).
- *A⁰*2, on input (*z; L*), chooses a uniformly random value *a 2* [*K*]. If there exists a query ((*a;x*)*;y*) *2L* for some *x 2* [*N*] and *y 2* [*M*], *A⁰*2halts. Otherwise, it internally simulates *A₂* on *z* as follows: *A⁰*2forwards all messages between *A₂* and the challenger; oracle queries (*a⁰;x*) by *A₂* are answered as follows: if *a⁰* = *a*, query *x* is asked to RO and the answer is passed to *A₂*; else if (*a⁰;x;y*) *2L* for some *y 2* [*M*], *y* is passed to *A₂*; otherwise, the query is answered from a function table chosen uniformly at random. It is easily seen that the view of *A₂* is the same in both the experiment where it interacts
directly as well as via Csaltwith BF-RO and the experiment where it interacts via *A⁰*2as well as via C with RO, unless the salt chosen by *A⁰*2happens to fall into the preset list *L*, which happens with probability at most *P=K*.

Combining Theorem 17 with Theorems 5 and 6 from Section 2.2 yields the following corollaries:

Corollary 18. *For any P 2* N *and every >* 0*, if an arbitrary application G is* ((*S⁰;T⁰;t⁰;s⁰*)*;"* *0* )*-* *secure in the* RO(*N;M*)*-model, then G*salt*is* ((*S;T;t;s*)*;"*)*-secure in the* AI*-*RO(*NK;M*)*-model for*

<u>2(S + log</u> 1 <u>) T</u> comb *0*<u>PGsalt</u> *"* = *"* + + + 2 <u>K</u> *P* This, of course, is not surprising, since our general analysis anyway goes through the BF-ROM model, so one would expect that direct analysis might be even better.

*and any S* = *S⁰ O*~ (*P*)*, T* = *T⁰, t* = *t⁰ O*~ (*P*)*, and s* = *s⁰ O*~ (*P*)*, where T* *G* comb salt *is the combined* *query complexity corresponding to G*salt*.*

Corollary 19. *For every >* 0*, if an unpredictability application G is* ((*S⁰;T⁰;t⁰;s⁰*)*;"* *0* )*-secure in* *the* RO(*N;M*)*-model, then G*salt*is* ((*S;T;t;s*)*;"*)*-secure in the* AI*-*RO(*NK;M*)*-model for*

<u>2(S + 2 log</u> 1 <u>) T</u> <u>G</u> comb

|t⁰ = t how salting aects the security of the applications presented in the preceding sections. provide examples to illustrate that directly analyzing a salted scheme in the BF-ROM can lead to much better bounds than combining a standard-ROM security bound with one of the above derived in the standard ROM, justifying our claim that salt defeats preprocessing. T= ST|salt K ~ (O P), and is the combined query complexity corresponding to G The following paragraphs briey discuss (in asymptotic terms and omitting logarithmic factors) For most of the basic applications from Section 3, large enough salt would yield AI-ROM bounds comparable to those derived by the direct AI-ROM analysis of the corresponding applications, and using even larger salt allows to match the much better bounds min(N;M). T|
|---|---|
|+ O K x ST|min(N;M)), we recover the AI-ROM bound in Theorem 7, while setting), we even get the same security as in the ROM (of course, on a much larger However, by inspecting the proof of Theorem 7, one can easily see that for the a T|
|O + KN via a direct analysis in the BF-ROM and then applying Theorem 6. T² M T² =M + M² to|min(N;M in order to get the same bound as in the traditional ROM. Similar phenomena For Merkle-Damgard hash functions (MDHFs), using salting, one gets a nal bound in the ST + : M ST² =M Note, however, that with this value of M|

*"* = 2*"* + + 2

*and any S* = *S⁰=O*~(*T* *G* comb salt )*, T* = *T⁰, s⁰* = *s O*~ (*P*)*, where P* = (*S* + 2 log 1 )*T* *G* comb salt *and where T* *G* comb saltsalt *.*

## We also

corollaries.

•

*unsalted* As an example, consider the one-way function application. It is easily seen that in the standard ROM, the security of the application is Combined with Corollary 19, one obtains a nal security bound of

*:*

Setting *K* := min(*N;M K* = *S* min(*N;M* domain). *salted* OWF application (i.e., given a randomly chosen, nding a preimage under *O*(*a;*) of *y* = *O*(*a;x*) for a randomly chosen), one can easily prove a considerably better bound of

)

14 Hence, it now suces to set *K* = *S* can be observed for PRGs, PRFs, wPRFs, and MACs.

<u>T</u>2<u>ST</u> order of *M* + *K*. Setting *K* = *M* to match the salt length already used in this application, we get a nal bound on the order of

This seems to improve the bound resulting from the direct analysis in the BF-ROM (see Theorem 12). *K* we now use a ran- dom oracle from *M³* to *M* instead of, while still using *B* evaluations of this more

Indeed, this bound for salted OWFs was already obtained Dodis *et al.* [19] using the compression technique.

compressing oracle to process a *B*-block message (as the salt is now appended to each eval- uation, instead of used as initialization vector at the beginning). In particular, for such a more compressing oracle from *M³* to *M*, the traditional MDHF chaining would only use *B=*2 evaluations, increasing the speed by a factor of 2. Thus, it is not immediately clear if tighter (provable) exact security is worth this eciency slowdown.

- For the computationally secure applications from Section 5, the situation is as follows:
(1) For Schnorr signatures, combining the standard ROM bound (cf. Theorem 27 in Section B.1 of the appendix) with Corollary 19 and using *K* := *N* yields a nal security bound of
*p* <u>(q</u> <u>sig+ S)(qsig+ T)</u> *T"* *0* +*;* *N*

which actually improves over the bound obtained by the direct analysis (cf. Theorem 15), again, however, at the cost of requiring a larger random-oracle domain. As with the basic applications, using even larger salt *K* := *SN*, one can recover the standard-ROM bound. By analyzing salted Schnorr signatures in the BF-ROM directly, one can prove a bound of

<u>T + q</u> <u>sig</u> 2 *p* <u>q</u> <u>sigS(qsig+ T)</u> + *T"* *0* +*;* *N KN*

and, therefore, setting *K* := *S* is sucient to match the bound in the standard ROM.

(2) For TDF encryption, the indirect approach using the standard ROM bound (cf. Theorem 28 in Section B.2 of the appendix), Corollary 18, and, once again, *K* := *N* results in the same bounds as the direct analysis. Choosing the salt value from a larger domain or analyzing the salted application in the BF-ROM directly will not yield further improvements, as the error term *ST=P* dominates the security bound.
- The applications mentioned in Section C.1, i.e., applications insecure in the AI-ROM, can be endowed with salt to obtain security bounds:
(1) For collision-resistant hashing, by combining the standard-ROM bound of *T²=M* with Corollary 19 and setting *K* := *M*, one obtains a nal security bound of
<u>T² ST</u> + *M M*

in the AI-ROM. Increasing the size of the salt space to *K* := *SM* results in the standard ROM bound. A direct analysis will not yield improved bounds since *A₁* can always leak collisions for (*P*) salt values, and, hence the above bound is optimal.

(2) Combining the standard-ROM bound for signature schemes based on ID schemes [1] of (roughly)
*0* <u>q</u> <u>sig(qsig+ T)</u> *T"* +*;* *N* where *"* *0* refers to the security of the underlying ID scheme, with Corollary 19, one obtains nal security *0* <u>(qsig+ S)(qsig+ T)</u> *T"* +*;* *N* using salt space [*N*]. As with Schnorr signatures, by setting *K* := *SN*, one recovers the standard-ROM bound. *Unlike* Schnorr signatures, however, for the general transform there

is no security improvement to be achieved by directly analyzing the salted application in the BF-ROM since *A₁* can launch the attack described in Section C.1 for (*P*) salt values.

(3) Combining the standard-ROM bound for full-domain hash signatures [16] of (roughly)
*q* sig*"* *0* *;*

where *"* *0* refers to the TDF-security of RSA (cf. Section B.2 of the appendix), with Corollary 19, one obtains nal security *0* <u>S(qsig+ T)</u> *q* sig*"* + *N* using salt space [*N*]. For similar reasons as above, a direct analysis of the salted scheme in the BF-ROM will not yield improved security bounds.

## 6.2 Improved Salting

One way to think of salting is to view the function table of BF-RO(*KN;M*) as a (*K N*)-matrix and let the challenger in the salted application randomly pick and announce the row to be used for oracle queries. However, *K* has to be around the same size as *N* to obtain meaningful bounds. In this section, based on a technique by Maurer [42], we provide a more domain-ecient means of salting, where the security will decay exponentially (as opposed to inverse linearly) with the domain expansion factor *K*, at the cost that each evaluation of the derived random oracle will cost *K* evaluations (as opposed to 1 evaluation) of the original random oracle. Consider an arbitrary application *G* with corresponding challenger C. Let Csalt*0* be the challenger works as follows: It initially chooses a uniformly random value *a* = (*a₁;:::;aK*) *2* [*N*] *K* and outputs *a* to *A₂*. Then, it internally runs C, forwards all messages between the attacker and C, but answers the queries *x 2* [*N*] that C makes to the oracle by

X *K* BF-RO*:* main(*i;x* + *ai*)*;* *i*=1

where addition is in Z*N*and Z*M*, respectively. In other words, the function table of BF-RO is arranged as a *K N* matrix, the *i* th row is shifted by *ai*, and queries *x* are answered by computing the sum modulo *M* of all the values in the *x* th column of the shifted matrix, denoted *Fa*. Denote the corresponding application by *G*salt*0*.

Theorem 20. *For any P 2* N*, if an application G is* ((*S⁰;T⁰;t⁰;s⁰*)*;"* *0* )*-secure in the* RO(*N;M*)*-* *model, then G*salt*0 is* ((*S;T;t;s*)*;"*)*-secure in the* BF*-*RO(*P;NK;M*)*-model for*

*K* *0*<u>P</u> *"* = *"* + *N;* *KN*

*S* = *S⁰ O*~ (*P*)*, T* = *T⁰, t* = *t⁰ O*~ (*P*)*, and s* = *s⁰ O*~ (*P*)*.*

In particular, assuming *P KN=*2, setting *K* = *O*(log*N*) will result in additive error *N* (*P=NK*) *K* = *o*( *N* <u>1</u> ) and domain size *O*(*N* log*N*). But if *P N¹*

(1), setting *K* = *O*(1) will result in the same
additive error *o*( *N* <u>1</u> ) in the original domain of near-optimal size *O*(*N*). Hence, for most practical pur- poses, the eciency slowdown *K* (in both the domain size and the complexity of oracle evaluation) is at most *O*(log*N*) and possibly constant.

*Proof.* Fix *N*, *M*, *K*, as well as *P*. Set BF-RO := BF-RO(*P;NK;M*) and RO := (*N;M*), and let *G* be an arbitrary application and C be the corresponding challenger. Fix an (*S;T;t;s*)-attacker *A* = (*A₁; A₂*) against *G*salt*0*. Consider the following (*S;T;t;s*)-attacker *A⁰* = (*A⁰*1*; A⁰*2) against *G* (expecting to interact with RO):

- *A⁰*1internally runs *A₁* to obtain the list *L* of preset values and auxiliary information *z*, and outputs (*z; L*).
- *A⁰*2, on input (*z; L*), chooses a uniformly random value *a 2* [*N*]
*K*. If (1*;x* + *a₁*)*;*(2*;x* + *a₂*)*;:::;*(*K;x* + *aK*) are all prexed coordinates in *L* for some *x*, then *A⁰*2halts. Otherwise, *A⁰*2simulates *A₂* on *z* as follows: *A⁰*2forwards all messages between *A₂* and the challenger. Moreover, it maintains a partial shifted function table *Fa*, that initially contains the points in

*L*. Whenever *A₂* makes a query (*i;x ai*), *A⁰*2proceeds as follows: { If *i* is the only row *j* for which coordinate (*j;x*) is undened in *Fa*, *A⁰*2queries *y*
P

||y|F [(j;x)].||
|---|---|---|---|
|a|j6=i|a||
|2|a|||

RO*:* main(*x*) and sets *Fa*[(*i;x*)] *j6*=*i a* { Otherwise, *F* [(*i;x*)] is set to a uniformly random value.

In either case, *A⁰* answers the query by *F* [(*i;x*)].

The view of *A₂* is the same in both the experiment where it interacts directly as well as via Csalt*0* with BF-RO and the experiment where it interacts via *A⁰*2as well as via C with RO, unless the salt vector chosen by *A₂* happens to lead to a column whose entries are all covered in *L*. Using a simple union bound over all columns, this happens with probability at most *K* <u>P₁ PKP</u> *N* *K* *N;* *N KN*

where the inequality follows from the relationship between the geometric and arithmetic means, and *Pi*is the number of prexed positions in the *i* th row of BF-RO’s function table, and, in particular, P *K* *i*=1 *Pi*= *P*.

Combining the above results with those in Section 2.2 yields the following corollaries:

Corollary 21. *For any P 2* N *and every >* 0*, if an application G is* ((*S⁰;T⁰;t⁰;s⁰*)*;"* *0* )*-secure in* *the* RO(*N;M*)*-model, then G*salt*0 is* ((*S;T;t;s*)*;"*)*-secure in the* AI*-*RO(*NK;M*)*-model for*

*K*<u>(S + log</u>1<u>) T</u>comb *0*<u>P Gsalt0</u> *"* = *"* + *N* + 2 + 2 *KN P*

*and any S* = *S⁰ O*~ (*P*)*, T* = *T⁰, t* = *t⁰ O*~ (*P*)*, and s* = *s⁰ O*~ (*P*)*, where T* *G* comb *0* *is the combined* salt *query complexity corresponding to G*salt*0.*

Corollary 22. *For every >* 0*, if an application G is* ((*S⁰;T⁰;t⁰;s⁰*)*;"* *0* )*-secure in the* RO(*N;M*)*-* *model, then G*salt*0 is* ((*S;T;t;s*)*;"*)*-secure in the* AI*-*RO(*NK;M*)*-model for*

1 comb !*K* <u>(S + 2 log)T</u> <u>G 0</u> *"* = 2*"* + 2*N* <u>salt</u> + 2 *KN*

|S = S⁰=O|~(T|), T =|
|---|---|---|
||G||
|1 G comb||G comb|

*and any* *G* comb *T⁰, t⁰* = *t O*~ (*P*)*, and s⁰* = *s O*~ (*P*)*, where P* = (*S* + salt 2 log)*T and where T is the combined query complexity corresponding to G*salt*.* salt salt

Applications. Concerning the applications from Sections 3 to 5, using the improved corollaries above, one can prove bounds similar to those obtained at the end of Section 6.1. The advantage of the domain-ecient salting is that one can get by with a smaller domain. However, the number of queries any application makes increases by a factor of *K*. As an example, consider MDHFs: The domain requirements are now lower as with standard salting, while the number of evaluations of the underlying random oracles increases signicantly, which is undesirable in practical applications of the Merkle-Damgard construction.

More randomness-ecient salting. Note that Csalt*0* requires *O*(*K* log*N*) random bits to gen- erate *a*. Although we never envision the value to *K* to be super-logarithmic, when *K* = log*N*, it would take *O*(log² *N*) random bits to generate *a*. We observe that the number of required random bits can be reduced to log*N* + *O*(*K*) via standard derandomization techniques, which brings the total randomness complexity to *O*(log*N*) even when *K* = log*N*. Specically, instead of drawing *a₁;:::;aK*uniformly and randomly, we generate them via a random walk over an expander graph. We provide the details below. Let *A* be the adjacency matrix of a *d*-regular graph over [*N*] vertices where *d* is a constant. Let *d* =1 *N*be the eigenvalues of *A* and suppose *jij d c* for 2 *i N*, where *c <* 1 is a constant. Given *A*, the modied Csalt*0* is the same as before except instead of choosing *a* uniformly over [*N*] *K*, we pick *a₁* uniformly over [*N*] then perform a *K* 1-step random walk over *A* and let *ai*be the *i*-th node on this walk.

Theorem 23. *For any P 2* N*, if an application G is* ((*S⁰;T⁰;t⁰;s⁰*)*;"* *0* )*-secure in the* RO(*N;M*)*-* *model, then G⁰* salt*0* *is* ((*S;T;t;s*)*;"*)*-secure in the* BF*-*RO(*P;NK;M*)*-model for*

r!*K* *0*<u>P</u> *"* = *"* + *N* + *c;* *KN*

*S* = *S⁰ O*~ (*P*)*, T* = *T⁰, t* = *t⁰ O*~ (*P*)*, and s* = *s⁰ O*~ (*P*)*.* p For *P KN=*2, *K* = *O*(log*N*) and suciently small *c*, the additive error term *N* ( *P=*(*KN*)+

*c*) *K* = *o*( *N* <u>1</u>
), and the public seed required by the challenger is now only *O*(log*N*).

*Proof.* The proof is similar as Theorem 20. In particular, the view of *A₂* is the same in both the experiment where it interacts directly with BF-RO and the experiment where it interacts via *A⁰*2 with RO, unless the salt chosen by *A₂* happens to lead to a column whose entries are all covered in *L*. For an arbitrary xed column, let BAD*i*be the set of shifts such that its *i*-th entry will be P *K* covered by *L* under those shifts. Note that

|||jBAD|j P. We claim:|
|---|---|---|---|
|||i=1|i|
|i|i||K|
||K|||
|K||||

*i*=1 *i* p Claim 24. P[*8i 2* [*K*]*;a 2* BAD] ( *P=*(*KN*) + *c*) *:*

In other words, for any xed column, the probability that all of its entries are all covered in p *L* is at most ( p <u>P=(</u>*KN*) + *c*). By a union bound, we can conclude *A₂* halts with probability at most *N* ( *P=*(*KN*) + *c*) and obtain the desired conclusion. The proof of Claim 24 is standard and included in Appendix C.2 for completeness.

Note that by combining Theorem 23 with Theorems 5 or 6, one can obtain corollaries similar to Corollaries 21 and 22, but with improved randomness complexity for generating salt.

# Acknowledgments

The authors thank Mika Goos for pointing out the decomposition lemma for high-entropy sources in [31], Andrej Bogdanov for discussions about derandomization using random walks, Daniel Wichs for suggestions on proving the security of computationally secure schemes in the AI-ROM, and Patrick Harasser for pointing out bugs in earlier versions of the proofs in Section 2. Sandro Coretti is supported by NSF grants 1314568 and 1319051. Yevgeniy Dodis is partially supported by gifts from VMware Labs and Google, and NSF grants 1619158, 1319051, 1314568. Siyao Guo is supported by NSF grants CNS1314722 and CNS-1413964; this work was done partially while the author was visiting the Simons Institute for the Theory of Computing at UC Berkeley.

# References

[1]Michel Abdalla, Jee Hea An, Mihir Bellare, and Chanathip Namprempre. From identication to signatures via the Fiat-Shamir transform: Minimizing assumptions for security and forward- security. In *Advances in Cryptology-EUROCRYPT 2002, International Conference on the* *Theory and Applications of Cryptographic Techniques, Amsterdam, The Netherlands, April 28*

*- May 2, 2002, Proceedings*, pages 418{433, 2002.
[2]Leonard M. Adleman. Two theorems on random polynomial time. In *19th Annual Symposium* *on Foundations of Computer Science, Ann Arbor, Michigan, USA, 16-18 October 1978*, pages 75{83, 1978.

[3]Noga Alon, Oded Goldreich, Johan Hastad, and Rene Peralta. Simple construction of almost k-wise independent random variables. *Random Struct. Algorithms*, 3(3):289{304, 1992.

[4]Yonatan Aumann, Yan Zong Ding, and Michael O. Rabin. Everlasting security in the bounded storage model. *IEEE Trans. Information Theory*, 48(6):1668{1680, 2002.

[5]Mihir Bellare, Alexandra Boldyreva, and Adriana Palacio. An uninstantiable random-oracle- model scheme for a hybrid-encryption problem. In *Advances in Cryptology-EUROCRYPT* *2004, International Conference on the Theory and Applications of Cryptographic Techniques,* *Interlaken, Switzerland, May 2-6, 2004, Proceedings*, pages 171{188, 2004.

[6]Mihir Bellare, Ran Canetti, and Hugo Krawczyk. Pseudorandom functions revisited: The cascade construction and its concrete security. In *37th Annual Symposium on Foundations of* *Computer Science, FOCS ’96, Burlington, Vermont, USA, 14-16 October, 1996*, pages 514{523,

1996.
[7]Mihir Bellare and Gregory Neven. Multi-signatures in the plain public-key model and a general forking lemma. In *Proceedings of the 13th ACM Conference on Computer and Communications* *Security, CCS 2006, Alexandria, VA, USA, Ioctober 30 - November 3, 2006*, pages 390{399,

2006.
[8]Mihir Bellare and Phillip Rogaway. Random oracles are practical: A paradigm for designing ecient protocols. In *CCS ’93, Proceedings of the 1st ACM Conference on Computer and* *Communications Security, Fairfax, Virginia, USA, November 3-5, 1993.*, pages 62{73, 1993.

[9]Mihir Bellare and Phillip Rogaway. Optimal asymmetric encryption. In *Advances in Cryptology*

*- EUROCRYPT ’94, Workshop on the Theory and Application of Cryptographic Techniques,* *Perugia, Italy, May 9-12, 1994, Proceedings*, pages 92{111, 1994.

[10]Daniel J. Bernstein and Tanja Lange. Non-uniform cracks in the concrete: The power of free precomputation. In *Advances in Cryptology-ASIACRYPT 2013 - 19th International* *Conference on the Theory and Application of Cryptology and Information Security, Bengaluru,* *India, December 1-5, 2013, Proceedings, Part II*, pages 321{340, 2013.

[11]Ran Canetti, Oded Goldreich, and Shai Halevi. On the random-oracle methodology as applied to length-restricted signature schemes. In *Theory of Cryptography, First Theory of Cryptogra-* *phy Conference, TCC 2004, Cambridge, MA, USA, February 19-21, 2004, Proceedings*, pages 40{57, 2004.

[12]Ran Canetti, Oded Goldreich, and Shai Halevi. The random oracle methodology, revisited. *J.* *ACM*, 51(4):557{594, 2004.

[13]Benny Chor, Oded Goldreich, Johan Hastad, Joel Friedman, Steven Rudich, and Roman Smolensky. The bit extraction problem of t-resilient functions (preliminary version). In *26th* *Annual Symposium on Foundations of Computer Science, Portland, Oregon, USA, 21-23 Oc-* *tober 1985*, pages 396{407, 1985.

[14]Kai-Min Chung, Huijia Lin, Mohammad Mahmoody, and Rafael Pass. On the power of nonuni- formity in proofs of security. In *Innovations in Theoretical Computer Science, ITCS ’13,* *Berkeley, CA, USA, January 9-12, 2013*, pages 389{400, 2013.

[15]Sandro Coretti, Yevgeniy Dodis, Siyao Guo, and John Steinberger. Random oracles and non- uniformity (full version of this paper). Cryptology ePrint Archive, Report 2017/937, 2017. https://eprint.iacr.org/2017/937.

[16]Jean-Sebastien Coron. On the exact security of full domain hash. In *Advances in Cryptology -* *CRYPTO 2000, 20th Annual International Cryptology Conference, Santa Barbara, California,* *USA, August 20-24, 2000, Proceedings*, pages 229{235, 2000.

[17]Ivan Damgard. A design principle for hash functions. In *Advances in Cryptology-CRYPTO* *’89, 9th Annual International Cryptology Conference, Santa Barbara, California, USA, August* *20-24, 1989, Proceedings*, pages 416{427, 1989.

[18]Anindya De, Luca Trevisan, and Madhur Tulsiani. Time space tradeos for attacks against one- way functions and prgs. In *Advances in Cryptology-CRYPTO 2010, 30th Annual Cryptology* *Conference, Santa Barbara, CA, USA, August 15-19, 2010. Proceedings*, pages 649{665, 2010.

[19]Yevgeniy Dodis, Siyao Guo, and Jonathan Katz. Fixing cracks in the concrete: Random oracles with auxiliary input revisited. In *Advances in Cryptology-EUROCRYPT 2017 - 36th Annual* *International Conference on the Theory and Applications of Cryptographic Techniques*, 2017.

[20]Yevgeniy Dodis, Krzysztof Pietrzak, and Daniel Wichs. Key derivation without entropy waste. In *Advances in Cryptology-EUROCRYPT 2014 - 33rd Annual International Conference on* *the Theory and Applications of Cryptographic Techniques, Copenhagen, Denmark, May 11-15,*

*2014. Proceedings*, pages 93{110, 2014.
[21]Yevgeniy Dodis and John P. Steinberger. Message authentication codes from unpredictable block ciphers. In *Advances in Cryptology-CRYPTO 2009, 29th Annual International Cryp-* *tology Conference, Santa Barbara, CA, USA, August 16-20, 2009. Proceedings*, pages 267{285,

2009.

[22]Stefan Dziembowski and Ueli M. Maurer. Tight security proofs for the bounded-storage model. In *Proceedings on 34th Annual ACM Symposium on Theory of Computing, May 19-21, 2002,* *Montreal, Quebec, Canada*, pages 341{350, 2002.

[23]Amos Fiat and Moni Naor. Rigorous time/space trade-os for inverting functions. *SIAM J.* *Comput.*, 29(3):790{803, 1999.

[24]Amos Fiat and Adi Shamir. How to prove yourself: Practical solutions to identication and signature problems. In *Advances in Cryptology-CRYPTO ’86, Santa Barbara, California,* *USA, 1986, Proceedings*, pages 186{194, 1986.

[25]Rosario Gennaro, Yael Gertner, Jonathan Katz, and Luca Trevisan. Bounds on the eciency of generic cryptographic constructions. *SIAM J. Comput.*, 35(1):217{246, 2005.

[26]Rosario Gennaro and Luca Trevisan. Lower bounds on the eciency of generic cryptographic constructions. In *41st Annual Symposium on Foundations of Computer Science, FOCS 2000,* *12-14 November 2000, Redondo Beach, California, USA*, pages 305{313, 2000.

[27]Oded Goldreich. A uniform-complexity treatment of encryption and zero-knowledge. *J. Cryp-* *tology*, 6(1):21{53, 1993.

[28]Oded Goldreich and Hugo Krawczyk. On the composition of zero-knowledge proof systems. *SIAM J. Comput.*, 25(1):169{192, 1996.

[29]Oded Goldreich and Yair Oren. Denitions and properties of zero-knowledge proof systems. *J.* *Cryptology*, 7(1):1{32, 1994.

[30]Sha Goldwasser and Yael Tauman Kalai. On the (in)security of the Fiat-Shamir paradigm. In *44th Symposium on Foundations of Computer Science (FOCS 2003), 11-14 October 2003,* *Cambridge, MA, USA, Proceedings*, pages 102{113, 2003.

[31]Mika Goos, Shachar Lovett, Raghu Meka, Thomas Watson, and David Zuckerman. Rectangles are nonnegative juntas. *SIAM J. Comput.*, 45(5):1835{1869, 2016.

[32]Martin E. Hellman. A cryptanalytic time-memory trade-o. *IEEE Trans. Information Theory*, 26(4):401{406, 1980.

[33]Viet Tung Hoang and Stefano Tessaro. Key-alternating ciphers and key-length extension: Exact bounds and multi-user security. In *Advances in Cryptology-CRYPTO 2016 - 36th* *Annual International Cryptology Conference, Santa Barbara, CA, USA, August 14-18, 2016,* *Proceedings, Part I*, pages 3{32, 2016.

[34]Russell Impagliazzo. Hardness as randomness: a survey of universal derandomization. *CoRR*, cs.CC/0304040, 2003.

[35]Russell Impagliazzo, Noam Nisan, and Avi Wigderson. Pseudorandomness for network algo- rithms. In *Proceedings of the Twenty-Sixth Annual ACM Symposium on Theory of Computing,* *23-25 May 1994, Montreal, Quebec, Canada*, pages 356{364, 1994.

[36]Russell Impagliazzo and Avi Wigderson. *P = BPP* if *E* requires exponential circuits: Deran- domizing the XOR lemma. In *Proceedings of the Twenty-Ninth Annual ACM Symposium on* *the Theory of Computing, El Paso, Texas, USA, May 4-6, 1997*, pages 220{229, 1997.

[37]Valentine Kabanets. Derandomization: a brief overview. *Bulletin of the EATCS*, 76:88{103,

2002.
[38]Richard M. Karp and Richard J. Lipton. Some connections between nonuniform and uni- form complexity classes. In *Proceedings of the 12th Annual ACM Symposium on Theory of* *Computing, April 28-30, 1980, Los Angeles, California, USA*, pages 302{309, 1980.

[39]Jonathan Katz and Yehuda Lindell. *Introduction to Modern Cryptography*. Chapman and Hall/CRC Press, 2007.

[40]Pravesh Kothari, Raghu Meka, and Prasad Raghavendra. Approximating rectangles by juntas and weakly-exponential lower bounds for LP relaxations of csps. *STOC*, 2017.

[41]Mohammad Mahmoody and Ameer Mohammed. On the power of hierarchical identity-based encryption. In *Advances in Cryptology-EUROCRYPT 2016 - 35th Annual International* *Conference on the Theory and Applications of Cryptographic Techniques, Vienna, Austria,* *May 8-12, 2016, Proceedings, Part II*, pages 243{272, 2016.

[42]Ueli M. Maurer. Conditionally-perfect secrecy and a provably-secure randomized cipher. *J.* *Cryptology*, 5(1):53{66, 1992.

[43]Ralph C. Merkle. A certied digital signature. In *Advances in Cryptology-CRYPTO ’89, 9th* *Annual International Cryptology Conference, Santa Barbara, California, USA, August 20-24,* *1989, Proceedings*, pages 218{238, 1989.

[44]Robert Morris and Ken Thompson. Password security-A case history. *Commun. ACM*, 22(11):594{597, 1979.

[45]Jesper Buus Nielsen. Separating random oracle proofs from complexity theoretic proofs: The non-committing encryption case. In *Advances in Cryptology-CRYPTO 2002, 22nd Annual* *International Cryptology Conference, Santa Barbara, California, USA, August 18-22, 2002,* *Proceedings*, pages 111{126, 2002.

[46]Noam Nisan and Avi Wigderson. Hardness vs. randomness (extended abstract). In *29th* *Annual Symposium on Foundations of Computer Science, White Plains, New York, USA, 24-* *26 October 1988*, pages 2{11, 1988.

[47]Philippe Oechslin. Making a faster cryptanalytic time-memory trade-o. In *Advances in* *Cryptology-CRYPTO 2003, 23rd Annual International Cryptology Conference, Santa Barbara,* *California, USA, August 17-21, 2003, Proceedings*, pages 617{630, 2003.

[48]Jacques Patarin. The \coecients h" technique. In *Selected Areas in Cryptography, 15th* *International Workshop, SAC 2008, Sackville, New Brunswick, Canada, August 14-15, Revised* *Selected Papers*, pages 328{345, 2008.

[49]Phillip Rogaway. Formalizing human ignorance. In *Progressin Cryptology-VIETCRYPT 2006,* *First International Conferenceon Cryptology in Vietnam, Hanoi, Vietnam, September 25-28,* *2006, Revised Selected Papers*, pages 211{228, 2006.

[50]Claus-Peter Schnorr. Ecient identication and signatures for smart cards. In *Advances in* *Cryptology-CRYPTO ’89, 9th Annual International Cryptology Conference, Santa Barbara,* *California, USA, August 20-24, 1989, Proceedings*, pages 239{252, 1989.

[51]Stefano Tessaro. Security amplication for the cascade of arbitrarily weak prps: Tight bounds via the interactive hardcore lemma. In *Theory of Cryptography - 8th Theory of Cryptography* *Conference, TCC 2011, Providence, RI, USA, March 28-30, 2011. Proceedings*, pages 37{54,

2011.
[52]Dominique Unruh. Random oracles and auxiliary input. In *Advances in Cryptology-CRYPTO* *2007, 27th Annual International Cryptology Conference, Santa Barbara, CA, USA, August 19-* *23, 2007, Proceedings*, pages 205{223, 2007.

[53]Salil P. Vadhan. Constructing locally computable extractors and cryptosystems in the bounded- storage model. *J. Cryptology*, 17(1):43{77, 2004.

# A Decomposing High-Entropy Sources

Let *X* be distributed uniformly over [*M*] *N N S* is an arbitrary

||and Z := f (X), where f : [M]|!f0; 1g|
|---|---|---|
|S|z||
|z z||z|
||0 z||

function. Fix an arbitrary *z 2f*0*;* 1*g* *S* and let *X* be the distribution of *X* conditioned on *f* (*X*) = *z*. Let *Sz*= *N* log*M H₁*(*X*) be the min-entropy deciency of *X*. Let *>* 0 be arbitrary.

Claim 2. *For every >* 0*, X is-close to a convex combination of nitely many* (*P⁰;* 1)*-dense* *sources for* <u>S + log 1=</u> *P* = *:* log*M*

*Proof.* For ease of notation, let *S* := *Sz*and *X* := *Xz*. Suppose *X* is not (1)-dense, as otherwise there is nothing to show. Let *Y* := *X* and *I* be the largest subset such that there exists a *yI*,

||I I|(1)jIjlog M|||
|---|---|---|---|---|
|||I I|||
|0|||||
|I|||||
|I 0||||J|
||J J|I I|(1)jJ jlog M||

P[*Y* = *y*] *>* 2 *:* (5)

Let *Y* *0* be the distribution of *Y* conditioned on *Y* = *y*.

## Claim 25. Y is (1)-dense.

*Proof.* Suppose *Y* is not (1)-dense. Then, there exists a non-empty set *J I* and *y* such that

P[*YJ0*= *yJ*] = P[*Y* = *y j Y* = *y*] *>* 2 *:*

The set *I[J* now forms a subset for which

P[*YI[J*= *yI[J*] =

|P[Y = y ^ Y|= y]||
|---|---|---|
|I I|J J||
|I I|J J|I I|

(1)jIjlog M (1)jJ jlog M
(1)jI[J jlog M

= P[*Y* = *y*] P[*Y* = *y j Y* = *y*]

## > 2 2

= 2*;*

since *I* and *J* are disjoint. This, however, contradicts the maximality of *I*.

## Claim 26. jIj S=( logM).

*Proof.* On the one hand, *H₁*(*Y*) *N* log*M S* implies that for any *yI*, X P[*YI I I I^ YI I*

|= y]|=|P[Y = y|= y]|
|---|---|---|---|
||(N jIj) log M (jIjlog M|(N log M S)|S)|

*y* *I* *2*[*M*]*N jIj*

2 (*N jIj*) log*M* 2 (*N* log*M S*)

= 2*;*

and, hence, *H₁*(*YI*) *jIj* log*M S*. On the other hand, because *YI*is not (1)-dense, *H₁*(*YI*) *<* (1) *jIj* log*M*. Combining the above two inequalities, one obtains the desired conclusion.

Hence, *Y* *0* is an (*S=*( log*M*)*;* 1)-dense source. Set *Y* now to be *Y* conditioned on *YI6*= *yI* and recursively decompose *Y* as long as

P[*X 2* supp(*Y*)] *> :* (6)

Observe that *H₁*(*Y*) *N* log*M* (*S* + log 1*=*) at any point in this decomposition process since

P[*Y* = *y*] = P[*X* = *y j X 2* supp(*Y*)] <u>P[X = y]</u> P[*X 2* supp(*Y*)] <u>2</u> (*N* log*M S*) (*N* log*M* (*S*+log 1*=*)) = 2 *:*

Note that *j*supp(*Y*)*j* decreases in every step, and since supp(*X*) is nite, after nitely many steps, this process ends with a *Y*nalwith P[*X 2* supp(*Y*nal)]. Hence, *X* is a convex combination of nitely many ((*S* + log 1*=*)*=*( log*M*)*;* 1)-dense sources and *Y*nal. 15 This implies that *X* is *-close* to a convex combination of ((*S* + log 1*=*)*=*( log*M*)*;* 1)-dense sources (e.g., the convex combination obtained by replacing *Y*nalby the uniform distribution).

# B Standard-ROM Denitions and Security

## B.1 Fiat-Shamir with Schnorr

Digital signature schemes. A digital signature scheme is a triple of algorithms = (Gen*;*Sig*;*Vfy), where Gen generates a signing key sk and a verication key vk, Sig takes a signing key sk and a message *m* and outputs a signature, and Vfy takes a verication key vk, a message *m*, and a signature and outputs a single bit, indicating whether is valid. In the *O*-oracle model, all three algorithms may make calls to *O:* main. The application of digital signatures *G* DS*;* is dened via the following challenger C DS*;*, which captures the (standard) EUF-CMA security of a digital signature scheme: Initially, C DS*;* generates a key pair (sk*;*vk) Gen and passes vk to the attacker. Then, the attacker may repeatedly submit signature queries *m* to the challenger, who answers them by the corresponding signature Sig (*m*). In the end, the challenger outputs 1 if and only if the attacker submits a pair (*m ;*) with Vfyvk(*m ;*) = 1 and such that no signature query was asked for *m*.

The bound on *jIj* is easily adapted to account for entropy deciency *S* + log 1*=* instead of *S*.

The discrete-logarithm problem. The discrete-logarithm problem in a group *G* = *hgi* can be phrased as an application *G* DL*;G*, dened via the challenger C DL*;G* that picks a uniformly random *x 2* Z*jGj*, passes *y* := *g* *x* to the attacker, and outputs 1 if and only if the attacker nds *x*. Observe that *G* DL*;G* is a *standard-model* application.

Schnorr signatures in the standard ROM. In the standard ROM, using the forking lemma as stated by Bellare and Neven [7], one can show the following security bound for Schnorr signatures.

|DL;G||0|
|---|---|---|
|DS;|sig 0 sig|sig|

Theorem 27. *Assume G for jGj* = *N is* ((*S;;t⁰;s⁰*)*;"*)*-secure, and let* = (Gen*;*Sig*;*Vfy) *be* *the Schnorr scheme. Then, G is* ((*S;T;t;s;q*)*;"*)*-secure in the* RO(*N²;N*)*-model for*

*p* <u>q (q + T)</u> *"* = *O T"* +*;* *N*

*where t* = (*t⁰*) *and s* = (*s⁰*)*.*

## B.2 TDF Encryption

Key-encapsulation mechanisms. A key-encapsulation mechanism (KEM) is a triple of algo- rithms = (*K;E;D*), where *K* generates a public key pk and a secret key sk, *E* takes a public key pk and outputs a ciphertext *c* and a key *k*, and *D* takes a secret key sk and a ciphertext *c* and outputs a key *k*. In the *O*-oracle model, all three algorithms may make calls to *O:* main. The application corresponding to CPA security for KEMs *G* KEM-CPA*;* is dened via the following challenger C KEM-CPA*;*, which captures the (standard) CCA security of a KEM scheme: Initially, C KEM-CPA*;* generates a key pair (pk*;*sk) *K* and passes pk to the attacker. Then, the challenger chooses a random bit *b* as well as a random key *k₁*, computes (*c;k₀*) *E*pk, and returns the challenge (*c;kb*). In the end, the challenger outputs 1 if and only if the attacker submits a bit *b⁰* with *b⁰* = *b*. To capture CCA security, one consideres the application C KEM-CCA*;* dened by the challenger C KEM-CCA*;* that proceeds as C KEM-CPA*;*, except that the attacker gets to ask decryption queries *c⁰*, which the challenger answers with *k⁰ D*sk(*c⁰*), provided *c⁰ 6*= *c*.

Trapdoor functions. The inversion problem for a trapdoor function generator *F* can be phrased as an application *G* TDF*;F*, dened via the challenger C TDF*;F* that generates (*f;f* 1 ) *F*, picks a random *x*, passes *y* := *f* (*x*) to the attacker, and outputs 1 if and only if the attacker nds *x*. Observe that *G* TDF*;F* is a *standard-model* application.

The security of TDF key encapsulation in the standard ROM. In the standard ROM, one can show the following security bound for TDF encryption.

Theorem 28. *Let be TDF key encapsulation. If G* TDF*;F* *is* ((*S⁰;;t⁰;s⁰*)*;"* *0* )*-secure, then G* KEM*-*CPA*;* *is* ((*S;T;t;s*)*;"*)*-secure in the* RO(*N;N*)*, where*

*"* = *O "* *0*

*and S* = *S⁰, t* = (*t⁰*)*, and s* = (*s⁰*)*.*

# C Salting: Deferred Material

## C.1 Schemes Insecure in the AI-ROM

Fiat-Shamir from identication schemes. Abdalla *et al.* [1] showed how to|using the Fiat- Shamir paradigm|generically build signature schemes in the ROM from identication schemes (ID schemes). In a nutshell, ID schemes set up public and private keys, and the party holding the private key, the prover, identies themselves to the party holding the public key, the verier, by executing a commit-challenge-response protocol, where rst the prover sends a \commitment" *a* and then answers a subsequent challenge *c* form the verier by a response *z*, which the verier either accepts or rejects. The main idea behind Fiat-Shamir signatures is the following: The singing and verication keys of the signature scheme are the private and public keys, respectively, of the ID scheme. To sign a message *m*, generate *a* according to the ID scheme, query the random oracle *O* to generate the challenge *c O* (*a;m*), and compute the corresponding response *z*. The signature for *m* will be = (*a;z*). Verication works in the obvious way. A simple attack against the generic transformation is the following: An ID scheme can be modied to always accept (*a;c;z*) = (*a ;*0 *N* *;z*) for some (arbitrary) *a* and *z* while remaining secure, since it is unlikely that the verier asks challenge 0 *N*. However, the signature scheme resulting from applying the above transformation to the modied ID scheme is insecure in the AI-ROM since *A₁* can (with high probability) nd a message *m* such that *O*(*a ;m*) = 0 *N* and therefore forge a signature = (*a ;z*) for *m*. The attack trivially extends to *P*-BF-ROM (for *P* = 1) by simply setting *O*(*a ;m*) = 0 *N*.

Full-domain hash. The full-domain hash is essentially the concatenation of the random oracle *O* with a trapdoor permutation (*f;f* 1 ): Sig(*m*) = *f* 1 (*O*(*m*)). That is, in order to sign a message *m*, the signer rst computes *d O* (*m*) and then inverts *d* with a trapdoor permutation using hte secret key *f* 1 (verication is obvious using public key *f*). Similarly to the application of collision- resistant hashing, full-domain hash is insecure in the AI-ROM (for any *f*) because one can leak two messages *m* and *m⁰* with *O*(*m*) = *O*(*m⁰*) to the attacker, who then gets a signature for one of them, which is obviously also a signature for the other. The attack trivially extends to *P*-BF-ROM (for *P* = 2) by simply making setting *O*(*m*) = *O*(*m⁰*).

## C.2 More Randomness-Ecient Salting

p

||i||K||
|---|---|---|---|---|
|1 d|i i v6=0|i jjMvjj jjvjj|T K|N i K 1|
||||i||
|||i|||

Claim 24. P[*8i 2* [*K*]*;ai2* BAD] ( *P=*(*KN*) + *c*) *:*

*Proof.* Let *W* = *A* be the transition matrix. Let *p₁* = 1*=N 2 R* denote our initial distribution of our random walk. For BAD, we dene diagnole matrix *B* whose (*j;j*)-entry (*j 2* [*N*]) is 1 if *j 2* BAD*i*, otherwise 0. Note that,

P[*8i 2* [*K*]*;a 2* BAD] = 1 *B WB W :::B₁p₁ :*

<u>2</u> For a matrix *M*, let *jjM jj₂* = max denote the matrix norm of *M*. We claim that for 2 *i 2* [*K*], r <u>jBAD j</u> *jjB W jj₂* + *c :* (7) *N*

Given (7), we can nish the proof. As *p₁* = *Wp₁* and *jjM₁M₂jj₂ jjM₁jj₂jjM₂jj₂*, we have that

1 *T* *BKWBK* 1*W :::B₁p₁* = 1 *T* (*BKW*)(*BK* 1*W*)*:::*(*B₁W*)*p₁*

*jj*1 *T* *jj₂i2*[*K*]*jjBiW jj₂ jjp₁jj* r! <u>jBADij</u> *i2*[*K*]+ *c* *N* r!*K* <u>P</u> + *c;* *KN*

p where the last inequality is because *f* (*y*) = ln( *y=N* + *c*) is concave for *y* 0. Now we prove (7). Given any non-zero vecotr *v* = *c⁰*1 + *v⁰* where 1 *T* *v⁰* = 0. As *W*1 = 1,

*jjBiWvjj₂* = *jjc⁰BiW*1 + *BiWyjj* = *jjc⁰Bi*1 + *BiWyjj₂ jjc⁰Bi*1*jj₂* + *jjBiWyjj₂ :* q *p* Note that *jjvjj₂* = (*c⁰ N*) 2 + *jjv⁰jj²* 2. Let1= 1*;*2*;:::;N*be *W*’s eigenvectors and *w₁;:::;wN* be correspdoning eigenvalues. Note that *wi*=*i=d c* for 2 *i N*. s X sX *jjWyjj₂* = ( *iT*

*y*) 2 *w* *i* 2 *c* (
*iT*

*y*) 2 = *c jjyjj₂ :*
2 *i N i* 2 p Therefore *jjBiWyjj₂ jjBijj₂jjWyjj₂ cjjyjj₂ cjjvjj₂*. Moreover, *jjc⁰Bi*1*jj₂* = *c⁰ j*BAD*ij* q <u>BADi</u> *jjvjj*. We conclude *N* 2 r! <u>jBADij</u> *jjBiWvjj₂* + *c jjvjj₂;* *N*

q <u>jBADij</u> and the matrix norm of *BiWv* is at most *N* + *c*.
