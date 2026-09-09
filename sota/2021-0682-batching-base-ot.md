# Batching Base Oblivious Transfers

### Ian McQuoid

∗ Mike Rosulek ∗ Lawrence Roy ∗

### May 25, 2021

Abstract

Protocols that make use of oblivious transfer (OT) rarely require just one instance. Usually a batch of OTs is required | notably, when generating base OTs for OT extension. There is a natural way to optimize 2-round OT protocols when generating a batch, by reusing certain protocol messages across all instances. In this work we show that this batch optimization is error-prone. We catalog many implementations and papers that have an incorrect treatment of this batch optimization, some of them leading to catastrophic leakage in OT extension protocols. We provide a full treatment of how to properly optimize recent 2-round OT protocols for the batch setting. Along the way we show several performance improvements to the OT protocol of McQuoid, Rosulek, and Roy (ACM CCS 2020). In particular, we show an extremely simple OT construction that may be of pedagogical interest.

## 1 Introduction

Oblivious transfer (OT) is a fundamental primitive for cryptographic protocols. It is well-known that OT cannot be constructed in a black-box way from symmetric-key primitives [IR90]. Never- theless, it is possible to generate a large number of OTs from symmetric-key primitives and *a small* *number of \base OTs"*, thanks to an idea called OT extension [Bea96]. OT extension to generate a polynomially large number *N* of OTs means that the *marginal cost* of OTs involves only cheap symmetric-key operations. Modern OT extension protocols [IKNP03,KK13,ALSZ13,KOS15] can generate millions of OTs per second. OT extension protocols require (*e.g.*, 128) base OTs, and yet most base-OT protocols in the literature are described in terms of a single OT instance. Obviously any single-instance OT protocol can be invoked times to produce base OTs; however, this overlooks the possibility of optimizations for the batch setting. In this work we provide a full treatment of the batch setting for recent leading OT protocols.

### 1.1 Overview of Our Results

There is a natural way to optimize certain 2-round OT protocols for the batch setting. When the OT sender is rst to speak, it is natural to reuse their protocol message for all OT instances in the batch. We call this method nave batching. We show that nave batching is very often insecure. Not only does nave batching fail to achieve an appropriate security notion, it is also demonstrably unsuitable as the base OTs for certain OT extension protocols. Specically, we show a serious attack on the 1-out-of-*N* OT ∗ Oregon State University, *f*mcquoidi,rosulekm,royl*g*@oregonstate.edu. Third author is partially supported by a DoE CSGF Fellowship.

<u>Sender</u> Receiver (input *c 2f*0*;* 1*g*) *a* KA*:R* *A* = KA*:* msg₁(*a*) <u>A</u> *b* KA*:R* *B* = KA*:* msg₂(*b;A*) <u>B</u> ~ <u>= (B) c</u>

*m₀* := KA*:* key₁(*a;* 1 (*B*~)) *mc*= KA*:* key₂(*b;A*) <u>m₁ := KA: key₁(a;</u> 1 <u>(B</u>~ <u>1))</u>

Figure 1: Our simple 1-of-2 random OT protocol. is an ideal permutation and KA is a 2-message

key agreement whose \*B*-messages" are pseudorandom bit strings.

extension protocol of Orru, Orsini, and Scholl [OOS17], when its base OTs are generated with nave batching. Unfortunately, we nd nave (or similarly improper) batching appearing in several protocol libraries [Rin,CMR,Kel20,Sma] and in several papers [CO15,HL17,CSW20]. We then give a complete treatment of how to correctly optimize leading OT protocols for the batch setting. Fortunately it is simple and cheap to x nave batching, although the complete secu- rity analysis requires care. We show how to correctly optimize the recent OT protocol of McQuoid, Rosulek, and Roy [MRR20] for the batch setting. As we show, the Masny-Rindal protocol [MR19] is a special case of the McQuoid-Rosulek-Roy protocol, and our analysis applies to that protocol as well. A comparison of our protocol to existing work is shown inTable 1. Finally, we present several new improvements to the McQuoid-Rosulek-Roy (MRR) protocol. Their OT protocol is actually an oblivious PRF protocol: the sender learns a pseudorandom func- tion *F*, the receiver chooses point *x* and learns *F* (*x*). Such a protocol yields 1-out-of-*n* [random] OT by letting *F*(1)*;:::;F*(*n*) be the *n* OT values, of which the receiver can learn only one. Their protocol supports *F* with domain *f*0*;* 1*g* (*i.e.*, 1-out-of-*n* OT for *any n*).

- The MRR protocol revolves around an object called a programmable-once public func- tion (POPF). A POPF with domain [*n*] leads to a protocol for 1-out-of-*n* endemic OT. MRR describe a new POPF with domain *f*0*;* 1*g*, leading to their OPRF protocol. But this is overkill for the case of 1-out-of-2 OT, which is all that is needed for OT extension. We show several improved POPF constructions for small domains (such as *n* = 2). One particularly interesting POPF is in the ideal random permutation model¹ and is inspired by the Even- Mansour block cipher construction [EM93]. When we instantiate MRR with this new POPF, we obtain an endemic OT protocol that is incredibly simple to describe. The protocol is not only ecient, but may be have pedagogical value as well. SeeFigure 1.
- The MRR protocol constructs endemic OT from a POPF and a key agreement (KA) protocol. These two components must be compatible, and in [MRR20] this was achieved at the cost of some nontrivial additional overhead | either hash-to-curve operations or Elligator [BHKL13] encoding steps. In this work, we suggest an alternative based on a trick due to Moller [Mol04]. Moller-DHKA avoids complicated encodings and the need for hash-to-curve operations in the protocol. It also avoids curve point addition, allowing us to use Montgomery Ladders to multiply, which are more ecient. It requires doubling the length of the sender’s protocol Like the random oracle model, all parties have access to a random permutation on *f; g²*, *and its inverse!*

|Scheme|Assumption|Setup|Flows|Exp (sender/receiver)|Comm (sender/receiver)|
|---|---|---|---|---|---|
|SimplestOT [CO15]|Gap-CDH|PRO|2|1f (m + 1)v / mf mv|1G / mG|
|BlazingOT [CSW20]|CDH|ORO|3|1f (m + 1)v / mf mv|m + 1G / 2|
|EndemicOT [MR19]|DDH|PRO|2|2mf 2mv / mf mv|2mG / 2mG|
|EndemicOT [MR19]|iDDH|PRO|1|mf 2mv / mf mv|mG / 2mG|
|Ours (MasnyRindal)|ODH|PRO|1|2fM 2mvM / mfM mvM|2G / 2mG|
|Ours (EKE/EvenMansour)|ODH|IC|1|2fM 2mvM / mfM mvM|2G / mG|
|Ours (Feistel)|ODH|PRO|1|2fM 2mvM / mfM mvM|2G / mG|

+ *m*G

Table 1: Comparison of *m*-instance random 1-of-2 OT protocols. \Exp" denotes exponentiations

(f = xed-base, v = variable-base, fM = xed-base Montgomery, vM = variable-base Montgomery). \Comm" denotes communication (G = one group element). PRO = programmable random oracle; ORO = observable random oracle; IC = ideal cipher.

message; however, in the batch setting it is exactly this sender’s message that is reused across all OT instances in the batch, so the eect of doubling its size is minimal.

Finally, we show how our batch OT protocol can be used as the base OTs in 2-round OT extension.

## 2 Preliminaries

### 2.1 Endemic OT

We use the security denitions for universally composable OT suggested by [MR19], which are a convenient middle-ground between random OT and chosen-message OT. An OT protocol results in outputs *r₀;r₁* for the sender and *rc*for the receiver (who has choice bit *c*). In endemic OT, a corrupt party may choose their own OT outputs, and all other OT outputs are chosen uniformly by the functionality. Hence, a corrupt sender can choose both *r₀* and *r₁*. A corrupt receiver can choose *rc*and the functionality will ensure that *r₁c*is uniform. As shown in [MR19], OT extension protocols are secure if the base OTs satisfy this notion of endemic OT. In this work we consider the batch setting, in which the parties wish to generate a batch of *n* OTs at once. InFigure 2we present a functionality that realizes *n* instances of OT with endemic security.

## 3 Problems With Nave Batching

### 3.1 Nave Batching

Consider an abstract 2-round protocol for (endemic) OT, with the following syntax:

||queries: • • • • • •|Functionality F batchEOT The functionality F is parameterized by the length of the OT strings ‘ and the number batchEOT of OTs in the batch. It interacts with two parties, a sender S and a receiver R via the following ‘ On input (ready; (~ r₁; r ~ ;:::; r ~; r ~)) from S, with ~ r 2f 0; 1 g :; 0 1; 1 n; 0 n; 1 i;c If S is corrupt, and there has been no previous ready command from S, then internally record r = ~ r for all i 2 [n], c 2f 0; 1 g. Otherwise do nothing. i;c i;c n ‘ On input (ready; (c₁ ;:::c) 2f 0; 1 g; (~ r₁ ;:::; r ~)) from R, with ~ r 2f 0; 1 g : n n i Do nothing if there has been a previous ready query from R. Internally record (c₁ ;:::c) n = ~ r for each i 2 [n]. If R is corrupt, then internally record r i i;c i After receiving ready queries from both S and R : ‘ For all i 2 [n] ;c 2f 0; 1 g, if r is not already dened, then sample r f 0; 1 g. i;c i;c Output (r₁ ;:::;r) to R and ((r₁ ;r₁) ;:::; (r ;r)) to S. ;c n;c; 0; 1 n; 0 n; 1 n 1||n|
|---|---|---|---|---|
||s m for|Figure 2: Batch Endemic 1-out-of-2 Oblivious Transfer functionality F. Adapted from the batchEOT endemic OT functionality of [MR19]. Sender Receiver (input c 2f 0; 1 g) s f 0; 1 g S m S m = OT : msg (s) S S S s f 0; 1 g R m = OT : msg (s ;m ;c) R R S R m R (r₀ ;r₁) = OT : out (s ;m) r = OT : out (s ;m ;c) c S S R R R S In such a protocol, the sender’s message m is clearly independent of the receiver’s inuence. S In many protocols m is also a message from a KA protocol, and it is well-known that in many S KA constructions a single KA message can be reused for many KA instances. These observations suggest the following optimization for generating a batch of n OTs: Sender Receiver (inputs fc g) i i2 [n] f 0; 1 g S m S = OT : msg (s) S S S for i 2 [n]: s f 0; 1 g R;i m = OT : msg (s ;m ;c i R;i R;i S R m ;:::;m R; 1 R;n i 2 [n]: for i 2 [n]: (r ;r) = OT : out (s ;m) r = OT : out (s ;m ;c) i; 0 i; 1 i;c i S S R;i R R;i S i|)||

We call this protocol transformation nave batching. Note that this protocol reuses OT*:* out*R*in such a way that disallows for internal domain separation.

Lemma 1. *Nave batching does not securely realize batch endemic OT (Figure 2).*

*Proof.* The attack is simple: a corrupt receiver simply sends *mR;*1= = *mR;n*. As a result, the sender must compute (*r₁;*0*;r₁;*1) = = (*rn;*0*;rn;*1). There is no way for the simulator to inuence the sender’s output in this way in the ideal model, hence this constitutes an attack.

Why not trivially patch this attack? The attack is for the receiver to send the same OT response for all instances. We could simply tell the sender to abort if it receives any repeated OT responses. However, the simple attack that we have described is only the tip of the iceberg. In all of the 2-round OT protocols that we consider, a corrupt receiver can induce more complicated correlations among the OT values. For example, a receiver can act honestly in the rst OT instance to learn *r₁;*0. Then *r₁;*1is unknown to the receiver. But there is a more sophisticated strategy for the receiver to force the ratio *r₁;*1*=r₂;*0to be a certain value. (The details of this strategy depend on the details of a specic base OT protocol, so we defer them toAppendix A.) Based on this kind of attack, one might wish to weaken the endemic OT functionality. Why not allow the simulator to specify these kinds of correlations in the ideal model? Even this will not work, because the attack is *perfectly* indistinguishable from honest behavior by the receiver. Thus, there is simply no way for the simulator to distinguish this kind of an attack (where the receiver must learn *r₁;*1*=r₂;*0) vs. honest behavior (where the receiver must learn *r₂;*0). For these reasons, we believe there is no way to closely capture the security of nave batching in a UC ideal functionality.

### 3.2 Implications for OT Extension

Since the main application for batch OTs is as base OTs for OT extension, it is natural to wonder whether the simple attack above jeopardizes the security of OT extension. It has been established that OT extension can be securely realized from base OTs with weakened security. For example, [CSW20] show that certain input-dependent aborts in the base OTs do not harm the security of OT extension. We show that out simple attack on nave batching indeed compromises security of some OT ex- tension protocols. Specically, we consider the protocol of Orru, Orsini, and Scholl (OOS) [OOS17]. This OT extension protocol generates many instances of 1-out-of-2 *t* OT, where in each one the sender obtains *r₁;:::;r₂t* and the receiver learns only *rc*, where *c* is an input. It will be convenient to consider *c* to be an element of *f*0*;* 1*g* *t* in the natural way. The OOS protocol is secure when the base OTs securely realize endemic batch OT; see [MR19] for details. However, it loses security when using nave batching to generate its base OTs.

Lemma 2. *The OOS protocol [OOS17] is demonstrably insecure when its base OTs are instantiated* *via nave batching.*

*Proof.* The complete details of OOS can be found in [OOS17]. We sketch the relevant details of their protocol here. Let Alice be the OOS sender (with no inputs) and Bob be the OOS receiver (with choice value *c* *i2f; g* *t* for the *i*th OT instance). The protocol proceeds as follows:

- The parties run *‘* base OT instances, with Alice acting as receiver and Bob acting as sender. Bob obtains base-OT outputs (*k₁;*0*;k₁;*1)*;:::;*(*k‘;*0*;k‘;*1). Alice’s inputs and outputs are not relevant here.
- When extending to *n* OTs, Bob constructs two *n ‘* matrices *K* and *R* as follows: { The *j*th column of *K* is PRG(*kj;*0) PRG(*kj;*1). { The *i*th row of *R* is *C*(*ci*) where *C* : *f*0*;* 1*g*
*t* *!f*0*;* 1*g* *‘* is a suitable binary error correcting code (the details of which are not relevant here).

### Bob sends K R to Alice.

These details of OOS are enough to understand the attack. A corrupt Alice will attack the base OTs (in the role of OT receiver as above) so that all *ki;*0’s are the same and all *ki;*1’s are the same. As a result, every column of *K* is identical. In other words, every *row* of *K* is either 0 *‘* or 1 *‘*. Then the *i*th row of Bob’s matrix *K R* is either *C*(*ci*) or its complement. This means that if *c;c⁰ 2f*0*;* 1*g* *t* are any two choices for Bob whose codewords are not bitwise complements of each other, then Alice can distinguish between Bob having choice *c* vs *c⁰* in each extended OT. For some choices of *C*, learning *C*(*x*) up to complement uniquely reveals *x*. This attack results in almost complete leakage of Bob’s private input.

What if *C* is a repetition code? *C* is a binary error-correcting code, the simplest of which is the repetition code *C* : *f*0*;* 1*g ! f*0*;* 1*g* *‘*. This corresponds to the case of *t* = 1, and hence 1-out-of-2 OT extension. Specically, instantiating OOS with a repetition code collapses it to the Keller-Orsini-Scholl 1-out-of-2 OT extension protocol (KOS) [KOS15]. In this case the only two codewords are 0 *‘* and 1 *‘*. Since these are bitwise complements of one another, it is not clear that our attack leads to any security problems. The rows of matrix *R* (encoding Bob’s private input) are masked by either 0 *‘* or 1 *‘*, depending on a bit that is unknown to Alice. We are not sure whether a more sophisticated attack on the base OTs (even for a specic navely batched OT) can break KOS OT extension.

### 3.3 Problematic Batching Found in the Wild

Looking ahead, the x for nave batching is simple and essentially free (although the security analysis of the x requires some care, as we show in the next sections). In Die-Hellman-based OT protocols, the OT outputs *r₀;r₁* are computed by taking a (random oracle) hash of a Die-Hellman value. The x is to include the OT index in that key derivation | *i.e.*, instead of *r₀* = *H*(*sid;g* *ab* ), use *r₀* = *H*(*sid;g* *ab* *;i*) in the *i*th OT instance in the batch. That way, even if all *g* *ab* values are identical (or correlated strangely), the nal OT values are independently random. Given that both the attack and the x are so simple, one may wonder whether this problem is well-known. In fact, we found problems related to OT batching in many libraries that imple- ment malicious-secure OT extension. 2 We focus on the implications for the overall OT extension protocols, which are minor in most cases. However, the consequences would be more severe for developers that directly access the base-OT functionalities of these libraries.

- The libote OT extension library [Rin] implements Masny-Rindal [MR19] base OTs and applies nave batching. The original Masny-Rindal paper considers only the single-instance We notied the maintainers of these libraries about the issues and the suggested x. By the time of writing, all
maintainers have either already xed or planned to x their handling of batch OTs.

setting and does not discuss security of the batch setting under nave batching. In some congurations, the libote implementation of OOS indeed uses these navely batched base OTs, thus falling victim to our attack. Other congurations use a hybrid approach, rst navely batching 128 base OTs, then using KOS to extend to 512 OTs, and using those 512 OTs as base for OOS. As mentioned above, we are not aware of any explicit attack on KOS extension, but our observations merely raise some concerns about its security with navely batched OTs.

- The swanky MPC library [CMR] implements the Chou-Orlandi protocol and reuses the sender’s message, but uses good domain separation in key derivation.
3 However, it allows the sender’s protocol message to be reused across several batches, while the domain separa- tion is local to the batch! In other words, parties could execute two batches of OTs, and the receiver could cause the batches to produce identical outputs, by replaying its protocol messages.

In this library’s implementation of OT extension, they rst apply the transformation in [MR19] from endemic OT to uniform-message OT on the base OTs. This prevents the receiver from forcing OT extension to operate on identical base OTs. If not for this additional step, even KOS OT extension would leak information across dierent batches. As it is, only the XOR of PRG seeds is leaked under our attack on nave batching, which is unlikely to lead to a concrete attack.

- The mp-spdz [Kel20] and scale-mamba [Sma] library implementations of OT use nave batch- ing of Chou-Orlandi base OTs. These libraries implement only KOS and not OOS, and therefore we know of no concrete attack against their OT extension.
We have also identied problematic handling of OT batching in several papers:

- The Chou-Orlandi OT protocol [CO15] explicitly considers the batch setting and uses nave batching to achieve it. As such, the protocol as written is not suitable as the base OT for certain OT extensions.
- Since security aws (unrelated to batching) were discovered in the Chou-Orlandi protocol, several works have attempted to address and repair them. Of those works, both [HL17] and [CSW20] explicitly consider the batch setting. The paper of Hauck & Loss [HL17] maintains the nave batching of the original.
- The \Blazing OT" construction of Canetti, Sarkar, and Wang [CSW20] does not technically use nave batching, since it introduces a joint consistency check across all instances in the batch. However, the key derivation in their base OTs does *not* include the OT index. This means that the attack inLemma 1has the intended eect: causing all OT instances to give identical output. The paper only considers a combined protocol with batched Chou-Orlandi base OTs and KOS OT extension, and as such we are not aware of an explicit attack on their nal OT extension protocol. However, their security analysis does not seem to acknowledge the possibility of all base OTs giving identical outputs. We found one instance of totally correct batching, in the implementation of Chou-Orlandi OT
in emp-toolkit [WMK16], despite nave batching being described in the paper.

The authors explicitly justify their correct key derivation as a bug in the Chou-Orlandi paper, and reference the attack in which all base OTs generate identical output. See chou orlandi.rs.

## 4 Properly Batching OTs

In this section we describe how to repair nave batching. We focus on the McQuoid-Rosulek-Roy (MRR) protocol [MRR20] since it subsumes the Masny-Rindal protocol, and the Chou-Orlandi protocol does not achieve UC security. As we saw, the main problem is that a corrupt receiver can force correlations among the OT outputs in dierent instances | even causing some OT values to be equal. The solution is to enforce \domain separation" among the dierent instances. Intuitively, parties should hash each instance’s OT outputs under a random oracle, with domain separation (*i.e.*, include the index of that instance in the hash). However, proving the security of this change requires some care. For example, we cannot prove security merely from the single-instance security of the OT protocol, since the single-instance protocol is not being used correctly. Instead, we must use some known structure of the protocol. The McQuoid-Rosulek-Roy (MRR) protocol derives its outputs from its underlying KA protocol, and we require stronger properties from that KA. The KA must accept an extra \tag" argument, so that even if the KA messages are identical, the resulting keys will be dierent under dierent tags.

### 4.1 Tagged KA

A tagged KA is identical in syntax to a traditional KA, except that the KA*:* key₁ and KA*:* key₂ algorithms take an additional tag argument. Correctness is that for all *a;b 2* KA*:R* and all tags :

KA*:* key₁(*a;* KA*:* msg₂(*b;* KA*:* msg₁(*a*))*;*) = KA*:* key₂(*b;* KA*:* msg₁(*a*)*;*)

Looking ahead to our batch OT protocol, we will let the tag be the index of the OT instance (*e.g.*, OT instance 1, 2, 3, *:::*). Intuitively, we will require that KA outputs under dierent tags appear indpendently random. This should hold not only when the KA protocol messages are identical, but also when the KA messages (*e.g.*, KA*:* msg₂) are correlated, since we previously observed (Section 3) that the adversary could induce arbitrary correlations across OT/KA instances.

Denition 3. *A tagged KA protocol is tag-non-malleable if a session with tag is secure, even* *against an eavesdropper that has oracle access to KA:key₁*(*a; ;*)*, provided the eavesdropper never* *queries the oracle on tag. Formally, the following distributions are indistinguishable, for all* *and every PPT A that never queries its oracle with second argument :*

*a;b* KA*:R a;b* KA*:R* *M₁* = KA*:* msg₁(*a*) *M₁* = KA*:* msg₁(*a*) *M₂* = KA*:* msg₂(*b;M₁*) *M₂* = KA*:* msg₂(*b;M₁*) *K* = KA*:* key₁(*a;M₂;*) *K* KA*:K* <u>return A</u> KA*:* key1(*a; ;*) <u>(M₁;M₂;K) return A</u> KA*:* key1(*a; ;*) <u>(M₁;M₂;K)</u>

Like [MRR20], we also require the KA protocol to satisfy the following randomness property:

Denition 4. *A key agreement protocol has strongly random responses if the honest output of* *KA:msg₂ is indistinguishable from random, even to an adversary who (perhaps maliciously) gener-*

*ated M₁. Formally, for all polynomial time A, the following distributions are indistinguishable:*

|(M₁ ;state b KA :R M₂ = KA : return (|) A () msg₂ (b;M₁) state;M₂)|||(M₁ ;state M₂ KA return (|) A () :M state;M₂)|
|---|---|---|---|---|---|
|Programmable-Once Public Functions We have specialized the denitions for the case of 1-out-of-2 OT⁴ N|OT (with exponential A 1-weak random oracle is a function F x N y := F (x) return x;y|The McQuoid-Rosulek-Roy protocol uses a primitive called programmable-once public functions (POPFs). We introduce denitions for POPF here, which slightly dier from the original denitions. exchange. In the original POPF denitions, a simulator simulated the random oracle setup in the service of a single POPF instance; in our batch setting there will be many POPF instances, thus we must adapt the denitions to explicitly allow simulation of multiple POPFs in a non-interfering||N : x N y O return x;y|N !O|
|property | it’s even satised by universal hashes. A batch g!N must provide the same interface as|when the adversary does not have access to F other than through these experiments. is only allowed to be used once this denition. 2-way H H|common reference strings, random oracles, ideal ciphers, etc. All parties (adversaries) may access the setup directly as well, although it is local to a single instance of the batch 2-POPF. The setup may be stateful (e.g., the \lazy" formulation of a random oracle, which samples outputs on the y).|A 2-POPF must also include alternative local setups, which are used in dierent security de-|programmable-once | depending on the instantiation,|public as well as an additional method HSim|

4.2
| [MRR20] dene POPFs in a way that is useful for 1-out-of-) and also password-authenticated key

way.

Denition 5. *such that the following two* *distributions are indistinguishable,*

Note that *F* This makes it an extremely weak

Denition 6 (Syntax). *function (batch 2-* *POPF) consists of algorithms:*

- *Eval* : *Mf*0*;* 1
- *Program* : *f*0*;* 1*gN !M*
*Both algorithms access some local setup* H *could consist of*

*nitions:*

- H*HSim*: *NN !*
<u>M.</u>
4 All of the POPFs in this paper have straightforward generalizations to the 1-out-of-*N* case, for polynomial *N*, and some to exponential *N* as well, but we restrict ourselves to the 1-out-of-2 case for simplicity.

- H*Extractmust provide the same interface as* H *as well as an additional method Extract*: *M!* *f*0*;* 1*g. Extract must not modify the private state of* H*Extract.* We write *A*
H to denote an algorithm *A* with oracle access to all methods provided by the setup

H. Denition 7 (Correctness). *A batch 2-POPF satises correctness if Eval*(*;x*) = *y with all but* *negligible probability, whenever Program*(*x ;y*)*.* Denition 8 (Security). *A batch 2-POPF is secure if it satises the following properties:*
*1.* Indistinguishable Local Setups: *The local setups* H*,* H*HSimand* H*Extractall implement a* *common interface. The setups must be indistinguishable to an adversary that only queries on* *this interface. Formally, if A is a polynomial-time algorithm that only queries its setup on* *the interface of* H *then the following probabilities are negligibly close:*
Pr[*A* H () = 1]; Pr[*A* H*HSim* () = 1]; Pr[*A* H*Extract* () = 1]

*2.* Honest Simulation: *Any that is generated honestly as Program*(*x ;y*)*, with y* *chosen uniformly, is indistinguishable from generated via the HSim algorithm of* H*HSim.* *Since HSim does not have a \preferred" input x, this establishes that an honestly generated* *hides the x on which it was programmed.*
### Formally, dene the following functions:

|sim phi(|x|2f|0|; 1 g;|D):|
|---|---|---|---|---|---|
|( s;y|)|D||||
|r x|:= y|||||
|r₁ return|x N HSim( s;;r₀||r₀ ;r₁ ;r₁|)||

real phi(*x 2f*0*;* 1*g;* D): (*s;y*) D Program(*x ;y*) *r₀* := Eval(*;*0) *r₁* := Eval(*;*1) return *s;;r₀;r₁*

*Then for all polynomial time A,*

Pr[*A* H*HSim;*real phi () = 1] Pr[*A* H*HSim;*sim phi () = 1]

*is negligible. Here we restrict A to always query with* D *a distribution over f*0*;* 1*g N such* *that the marginal distribution of y is indistinguishable from the uniform distribution over N.* *The other component s appears for technical reasons; the reader can think of it as the coins* *used to sample y .*

*Note that* sim phi *calls the HSim method of the local setup, and that A may even query the* *HSim method (both the real and ideal experiments use* H*HSim).*

*3.* Uncontrollable Outputs: *For any generated by the adversary, the Extract method of* H*Extractcan identify an input x such that the adversary has no control over Eval*(*;* 1
*x*)*. We say that Eval*(*;* 1 *x*) *is beyond the adversary’s control if F*(*Eval*(*;* 1 *x*)) *is* *indistinguishable from random, for any 1-weak-RO F.*
5

5 There are 1-weak ROs whose outputs can be distinguished from random when inputs are chosen in a certain adversarial way. Hence, requiring the RO outputs to remain random is a way of requiring that these values are not chosen in an adversarial way.

*Formally, the following distributions must be indistinguishable for all polynomial-time A₁; A₂* *and all 1-weak-RO F :*

||H Extract (;state) A () 1 x := Extract() r := F (Eval(; 1 x)) H Extract return A₂ (state;r)||H Extract (;state) A () 1 r N H Extract return A₂ (state;r)||
|---|---|---|---|---|
|may query this method as well. call provided by this experiment. The reader may be curious why we forced there is a bijection between values of the same 4.3 The Batch OT Protocol|As above, the left distribution calls the Extract method of the y letting the adversary choose it like in [MRR20]. The answer is that otherwise an ideal cipher would not be a POPF. An adversary could have already run Program(0 y and this is clearly a mistake. Ideal ciphers satisfy our new denition (Section 5.1).||H Extract Note that A does not have any access to F to be sampled inside Honest Simulation, instead of ;y, a call to HSim(y ;r₁ as before. Ideal ciphers were used as a motivating example for POPFs in [MRR20], so|setup, and the adversary beyond the one) earlier, and because for each) would be forced to return|
|Sender|||Receiver|(with input fc g) i i2 [n]|
|a KA :R m = KA : msg₁ (a) S|m S||for i 2 [n]:||
|for i 2 [n]:|;:::; 1|n|b KA :R i m := KA : R;i := Program(i|msg₂ (b ;m) i S c ;m) i R;i|
|for j 2f 0; 1 g : r = KA : key₁ (a; i;j|Eval(;j) ;i k j) i||for i 2 [n]: = KA : key₂ r i;c i|(b ;m ;i k c) i i S|

*x*

Figure 3: Our *n*-batch 1-of-2 Oblivious Transfer protocol.

InFigure 3we present the batch variant of the OT protocol of [MRR20]. The protocol is essentially the nave batching of the single-instance protocol, except we use a tagged KA and use dierent tags for each KA output.

Theorem 9. *When instantiated with a secure batch POPF and a tag-non-malleable KA scheme* *(Denition 3) with strongly random responses (Denition 4), the OT protocol in Figure* 3 *is a UC* *secure batch endemic OT (Figure 2), if the POPF’s output satises N* = *KA:M₂.*

*Proof.* Correctness of the POPF and KA clearly show that the protocol is correct in the case where both parties are honest. When both parties are corrupt, the simulator has direct access to both parties and can simulate the real protocol by just running it. This leaves the two interesting cases, where one party is malicious and the other is honest. We prove each case by giving rst a simulator, then a sequence of hybrids showing indistinguishability. The hybrids start from the real world and end at the ideal world: the simulator composed with an ideal batch endemic OT.

Simulator for Malicious Sender: The simulator uses HHSiminstead of H to implement the local setup. It then waits until the sender provides its protocol message *mS*. It creates fresh random values *bi;j2* KA*:R* for *i 2* [*n*]*;j 2f*0*;* 1*g*, then computes the KA messages *mi;j i;j S*

||||= KA:msg₂(b|;m ).|
|---|---|---|---|---|
||||i;j|i;j S|
|i;0 i;1|i;j|n i;j S|||

Then it chooses*i*HSim(*m;m*) and sends1*;:::;* as the simulated protocol message from the honest receiver. Finally, it submits *r* = KA*:* key₂(*b;m;i k j*) to the ideal functionality, for *i 2* [*n*] and *j 2f*0*;* 1*g* (as the endemic OT values).

Sequence of Hybrids for Malicious Sender: Starting at the real interaction between malicious sender and honest receiver:

1.Replace local setup H with HHSim. This change is indistinguishable by the Indistinguishable Local Setups property of the POPF.
2.Change how*i*is generated:

|b KA :R i m = KA : msg₂ (b ;m) i R;i S Program(c ;m) i i R;i|with|b KA :R i = KA : msg (b ;m) m i i;c S 2 i m KA :M i; 1 c i HSim(m ;m) i i; 0 i; 1|
|---|---|---|
|This is indistinguishable by the Honest Simulation property. Recall that this property requires to come from a distribution D over f 0 the second element is indistinguishable from uniform. is sampled:|; 1 g|N where the marginal distribution of This holds because KA has strongly|
|b KA :R i = KA : msg (b ;m) m i i;c S 2 i KA :M m i; 1 c i HSim(m ;m) i i; 0 i; 1|with|b ;b KA :R i; 0 i; 1 m = KA : msg (b ;m) i; 0 i; 0 S 2 m = KA : msg₂ (b ;m) i; 1 i; 1 S HSim(m ;m) i i; 0 i; 1|

replace

*b* *i* *;mi;ci*

random responses.

3.Change how *mi;*1 *ci*
replace

Later references to *bi*become references to *bi;ci*. This is indistinguishable because KA has strongly random responses.

This nal hybrid describes the ideal world. The receiver’s inputs *ci*are not used to simulate def protocol messages to the sender; they are used only to determine which *ri;j*= KA*:* key₂(*bi;j;mS*) the receiver takes as output. In the ideal world the simulator sends identically dened *ri;j*to the ideal functionality, which uses the receiver’s *ci*inputs to determine which ones to deliver as the receiver’s output.

Simulator for Malicious Receiver: The simulator uses HExtractinstead of H to implement the local setup. It generates *mS*in the same way as an honest sender, and sends it to the corrupted receiver. When the receiver provides1*;:::;n*, the simulator runs *ci*= Extract(*i*) for all *i 2* [*n*], and submits them to the ideal functionality. It also computes *ri;ci*= KA*:* key₁(*a;* Eval(*i;ci*)*;i k ci*), and submits these to the ideal functionality as well (as the endemic OT values).

### Sequence of Hybrids for Malicious Receiver:

1.Replace local setup H with HExtract, an indistinguishable change.
2.Rearrange how *ri;j*are computed:
for *j 2f*0*;* 1*g*: replace

|r = KA:key₁(a; Eval(|;j);i k j)||
|---|---|---|
|i;j i|i||
|i;c|i i|i|
|i;1 c|i|i|

*c* Extract(*i*) with *ri*= KA*:* key₁(*a;* Eval(*;c*)*;i k c*) *ri*= KA*:* key₁(*a;* Eval(*;* 1 *c*)*;i k* 1 *ci*)

This is indistinguishable because running Extract has no eect on the local setup’s internal state.

3.For each *i 2* [*n*] and *j 2f*0*;* 1*g*, create an oracle *Fi;j*= *y 7!* KA*:* key₁(*a;y;i k j*). Then rewrite the computation of *ri;j*in terms of these oracles as *ri;j*= *Fi;j*(Eval(*i;j*)). InLemma 10we show that every oracle *Fi;j*is a 1-weak random oracle.
4.Change how *ri;*1 *ci*is chosen:
*c* *i*Extract(*i*) *ci*Extract(*i*) replace *ri;ci*= *Fi;ci*(Eval(*i;ci*)) with *ri;ci*= *Fi;ci*(Eval(*i;ci*)) <u>r</u> <u>i;1 c</u>*i*<u>= Fi;c</u>*i*<u>1(Eval(i; 1 ci)) ri;1 c</u>*i*<u>KA:K</u>

This change is indistinguishable by the Uncontrollable Outputs property. Since each *Fi;j*is a 1-weak RO, we can apply the Uncontrollable Outputs property once for each *i* to make the change described here.

This nal hybrid describes the ideal world. After seeing the receiver’s protocol message, the sim- ulator extracts *ci*values and also computes values *ri;ci*which will be part of the sender’s output. The other OT values in the sender’s output (*ri;*1 *ci*) are sampled uniformly, just as in the ideal world.

Lemma 10. *For any tag-non-malleable key agreement KA with strongly random responses, and* *for any set of tags T, the following distribution outputs a key agreement message and a collection* *of jTj weak random oracles from KA:M₂ to KA:K.*

*a* KA*:R* *mS*:= KA*:* msg₁(*a*) for *2T* : *F* := *x 7!* KA*:* key₁(*a;x;*) return *mS; fF g2T*

*Proof.* We need to show that every *F* is a weak random oracle. We describe a sequence of hybrids starting from the real weak random oracle distribution and ending at random.

1.Sample the input *x* and compute *y* early, when the oracle *F* is created rather than when the weak RO experiment is run.

2.Instead of sampling *x* KA*:M₂*, sample *b* KA*:R* and set *x* = KA*:* msg₂(*b;mS*). This is indistinguishable by the strongly random responses property of KA.
3.We are now computing *y* = KA*:* key₁(*a;x;*) for a random KA message *x*, then giving oracle access to KA*:* key₁(*a;x⁰;*
*0* ) (from the other oracles *F 0*), but only for *0* *6*=. This is exactly the same as the real distribution for a tag-non-malleable KA, so it is indistinguishable to switch to the random distribution by randomly sampling *y* KA*:K* instead.

4.Use strongly random responses again, to sample *x* KA*:M₂* and remove *b*.
5.Delay the sampling of *x;y* until the 1-weak RO distribution is run. Our protocol considers an underlying KA with sequential messages. Yet Die-Hellman-based
KA protocols have independent messages that can be sent in any order. We call such a KA protocol 1-ow, where KA*:* msg₂(*b*) is independent of *mS*. When the KA is 1-ow, the OT protocol can also be made 1-ow by sending both messages in parallel.

Theorem 11. *Our OT protocol (Figure 3) becomes a 1-ow UC secure batch endemic OT when* *KA is 1-ow.*

*Proof.* This theorem largely the same asTheorem 9from the previous one, but with key changes. In the 1-ow instance, the adversary may rush the other party, requiring them to send their message rst before responding. For malicious receiver the adversary already went last, but it’s dierent for malicious sender. When the sender is corrupt, the simulator instead generates1*;:::;n*with HSim before receiv- ing *mS*, as each of the receiver’s messages from the key agreement may now be sampled indepen- dently of the sender’s. The hybrid proof continues as before, after replacing KA*:* msg₂(*b;MS*) with KA*:* msg₂(*b*).

## 5 New/Improved POPF Constructions

In this section, we describe several suitable POPF constructions for the batch OT protocol.

### 5.1 Ideal Cipher (EKE)

Our rst POPF is inspired by the EKE password-authenticated key exchange protocol of Bellovin & Merritt [BM92]. POPF was created as a generalization of an ideal cipher in the EKE protocol, and it is no surprise that in fact an ideal cipher is a POPF. The full denition is inFigure 4. We are not aware of prior work pointing out the connection between EKE and oblivious transfer. But it is easy to see that an ideal cipher is useful for OT: the adversary can know the trapdoor to at most one of *E* 1 (0*;*) and *E* 1 (1*;*). The local setup H is simply an ideal cipher. Actually, we have dened H in a way that is indistinguishable from an ideal cipher | it chooses oracle responses uniformly, instead guaranteeing that each *E*(*x;*) is a permutation. By a standard PRF/PRP switching lemma, the dierence is indistinguishable, and this choice makes the description of H simpler. HHSimis similar to H, but it programs *E* 1 so that Eval(*;i*) = *ri*, to satisfy the honest simulation property. In HExtract, Extract() nds the rst ideal cipher call that produced | either as the input to an *E* query or the output of an *E* query. The idea is that once has appeared in some ideal

||||H T := empty list E (x;y):||
|---|---|---|---|---|
|M := N Program(x;y):|||if 9: (x;y;) 2 T : return M||
|return E (x;y) Eval(;x):|||append (x;y;) to T return 1 E (x;):||
|1 return E (x;)|||if 9y: (x;y;) 2 T : return y y N append (x;y;) to T return y||
|H HSim|||||
|T := fg 1 // E and E are same as in H HSim(r₀ ;r₁):||T := // E|H Extract fg 1 and E are same as in H||
|if 9x;: (x;r ;) 2 T : x||Extract(|):||
|return ? M append (0 ;r₀ ;) to T append (1 ;r₁ ;) to T|||nd rst (x ;y ;) 2 T : return x if none exist: return 0||
|return|||||

Figure 4: Batch 2-POPF based on an ideal cipher.

cipher query, future forward queries to *E* give output only with negligible probability. Hence, all future calls that involve must be of the form *E* 1

(*;*), meaning that the adversary has no
control over the outputs of these queries (which are outputs of Eval). This is precisely the property needed for a POPF.

Theorem 12. *Figure 4denes a secure and correct batch 2-POPF with all distinguisher advantages* <u>q</u> 2 *except for Uncontrollable Outputs bounded by O* *jNj* *, when the adversary makes q ideal cipher* <u>q</u> 2 *lookups. Uncontrollable Outputs instead has advantage bounded by q* Adv(*wRO*) + *O* *jNj* *, where* Adv(*wRO*) *is the distinguisher advantage against the 1-weak RO F.*

*Proof.* We have deferred the security proofs for the POPF constructions to the appendix. See Appendix B.1.

### 5.2 Even-Mansour POPF

In [MRR20] the authors construct a POPF with a 2-round Feistel cipher. Intuitively, a POPF gen- eralizes an ideal cipher, but is strictly weaker. So while an 8-round Feistel cipher is indierentiable from an ideal cipher, a 2-round Feistel cipher suces for a POPF. Similarly, we suggest a POPF

||||H T := empty list (u):||
|---|---|---|---|---|
|M := N := f 0; 1 g Program(x;y):|||if 9v: (u;v) 2 T : return v v f 0; 1 g||
|return (y) x Eval(;x):|||append (u;v) to T return v 1 (v):||
|1 return (x)|||if 9u: (u;v) 2 T : return u u f 0; 1 g append (u;v) to T return u||
|H HSim|||||
|T := empty list 1 // E and E are same as in H HSim(r₀ ;r₁):||T // E|H Extract := empty list 1 and E are same as in H||
|if 9x;: (r; x) 2 T : x||Extract(|):||
|return ? f 0; 1 g append (r₀; 0) to T append (r₁; 1) to T|||nd rst (y; x) 2 T return x if none exist: return 0|:|
|return|||||

Figure 5: Batch 2-POPF based on an ideal permutation.

based on the Even-Mansour [EM93] construction. While the Even-Mansour construction is not an ideal cipher unless many rounds are added [DSST17], a single round suces for a POPF. The construction (Figure 5) is similar to the Ideal Cipher POPF, but with a few changes. The local setup H is not an ideal cipher, but a simpler ideal random permutation. In the ideal cipher POPF, every query to the oracles included the *x*-value (as the key of the cipher). In this Even- Mansour POPF the value *x* is used only by xor’ing with the ideal permutation output | it is not directly available to the simulator (in Extract). To deal with this challenge, we observe that *x* can be inferred by the simulator given. The only situation where *x* is ambiguous given is when (*y₁*) *x₁* = = (*y₂*) *x₂* for distinct bits *x₁;x₂*. This event implies (*y₁*) (*y₂*) = *x₁ x₂* = 1, which is negligibly likely for forward queries to. This turns out to be enough for the simulator to extract. The construction generalizes to strings *x* which are signicantly shorter than the ideal permutation output.

Theorem 13. *Figure 5denes a secure and correct batch 2-POPF where the distinguisher advan-* *tage is O*(*q²*2) *when the adversary makes q ideal permutation lookups, except for Uncontrollable* *Outputs which allows an additional advantage of q* Adv(*wRO*)*.*

*Proof.* We have deferred the POPF security proofs to the appendix. SeeAppendix B.2.

|M := G² Program(x;y):|||H record calls in a transcript T||
|---|---|---|---|---|
|s₁ G x|||H (u): x||
|1 s = y (H (s₁)) x x x return (s₀ ;s₁) Eval((s₀ ;s₁) ;x): return s H (s₁) x x x H HSim record calls in a transcript T U := empty assoc. array|||if 9v: (v H (u)) 2 T : x return v v G return v||
|H (u): x|||H Extract||
|if 9v: (v H (u)) 2 T : x return v if U [x;u] dened:||//|record calls in a transcript T H is the same as in H x Extract((s₀ ;s₁)):||
|return U [x;u] v G return v HSim(r₀ ;r₁):|||) in (s₁ nd rst query H x x return x if none exist:|T :|
|= (s₀ ;s₁) M U [0 ;s₁] := s r₀ 0 1 U [1 ;s₀] := s r₁ 1 1 return|||return 0||
|G are random oracles, and (G ;) is a group. Masny-Rindal POPF This next POPF is inspired by the OT construction of Masny and Rindal [MR19]. The local setup H consists of two random oracles is similar to H, but it also tracks the values satisfy the honest simulation property, it further programs the random oracles Eval(;x) = s H x x), upon seeing = (s₀ ;s₁), checks if. Extract(arbitrarily to be 0 if neither call was made. main idea is that for the adversary to program|Batch 2-POPF based on the OT constrution of Masny-Rindal [MR19]. (s₁ s₁|POPF in the context ofFigure 3we see that the Masny-Rindal OT protocol for 1-out-of-2 OT⁶ then a specic instance of our protocol. The description of the POPF can be found inFigure 6. the resulting OT protocol, the KA scheme must have protocol messages that reside in this group. x x|H₀ ;H₁ whose outputs are a group G. r₀ ;r₁ that have been given to HSim(H x 1) = s (s) r = r : x x x x is also very similar to H, but it also tracks chronological order of the oracle queries. was a query to the random oracle) then chooses the rst query (chronologically) and returns the associated As in the original proof in [MR19] the, they need to query on one of the two||

Figure 6: Here *H₀;H₁* :

G*!*

5.3
Using this is

|||In|
|---|---|---|
|H|R). to be consistent:|To|
|H|||
|Extract(|H, for either||
|x 2f0; 1g||x,|

HSim

Extract *x*

or chooses *x* *sx*values in

Generalizing to 1-out-of-*N* for polynomial *N* works the same as in [MR19].

### N := G

|M := G F Program(x;y):|||H record calls in a transcript T||
|---|---|---|---|---|
|u F|||H (x;u):||
|1 t := H (x;u) y s := u (t) x return s;t Eval((s;t) ;x): return H (x; (t) x + s) t H HSim record calls in a transcript T U := empty assoc. array|||if 9v: (v H (x;u)) 2 T : return v v G return v||
|H (x;u):|||H Extract||
|if 9v: (v H (x;u)) 2 T : return v if U [x;u] dened:||//|record calls in a transcript T H is the same as in H Extract((s;t)):||
|return U [x;u] v G return v HSim(r₀ ;r₁):|||nd rst query H (x; (t) x + return x if none exist:|s):|
|(s;t) G F 1 U [0; (t) 0 + s] := r₀ t 1 U [1; (t) 1 + s] := r₁ t return (s;t)|||return 0||
|with multiplication in a nite eld F. t. except for Uncontrollable Outputs bounded by O||order to nd the other, unless the \other" is sampled independently, in which case the adversary j|Variant of the Feistel POPF in [MRR20], where one random oracle has been replaced is an injection with an ecient left inverse Figure 6denes a secure and correct batch 2-POPF with all distinguisher advantages 2 q when the adversary makes q queries to the G j 2 q|q +2|

Figure 7:

1, *i.e.*, 1 *8t:* ( (*t*)) =

### fails to program.

### Theorem 14.

*random oracles. Uncontrollable Outputs instead has advantage bounded by* Adv(*wRO*) + 2 <u>q</u>2

*O.* *j*G*j* *Proof.* We have deferred this proof toAppendix B.3.
### 5.4 Streamlined Feistel POPF

[MRR20] propose a POPF based on 2-round Feistel, in which the value is 3 bits longer than the underlying value from *N*. We present an alternative construction (Figure 7) that improves on this

when G = *N* can be represented with less than 3 bits. This is useful because elliptic curve points usually can be represented with 2 bits. As with MRR20, we need *N* to be a group G, and the local setup H is a hash function *H* mapping into G. However, instead of a second random oracle *H⁰*(*x;T*), we use an injection from G into a nite eld F. The hash call *H⁰*(*x;T*) in one of the Feistel rounds is then replaced with multiplication (*T*)*x*. is required to have an eciently computable left inverse 1. These changes eliminate the main bad event in the security proof of MRR20, which occurs when the adversary manages to delay making the *H⁰* query, which the simulator needs to see in order to nd what *T* the adversary chose, until after the simulator needs to use *T* to program *H*. The simulator can now nd *T* directly using 1.

Theorem 15. *The streamlined Feistel POPF inFigure 7is a secure and correct batch 2-POPF.* <u>q</u> 2 *The distinguisher advantage is O* *j*G*j* *when the adversary makes q ideal permutation lookups,* <u>q</u> 2<u>q+2</u> *except for Uncontrollable Outputs which allows an additional advantage of* 2 Adv(*wRO*)*.*

*Proof.* We have deferred this proof toAppendix B.4.

The original 2-round Feistel POPF in [MRR20] also satises our new denitions. We omit the proof because it is substantially similar to the proof ofTheorem 15, just preserving a few more ideas from [MRR20].

## 6 Suitable Key Agreement Choices

Our batched OT protocol requires a tagged KA in which the receiver’s protocol messages are indistinguishable from the uniform distribution over the domain of the POPF (outputs of Eval). In this section we discuss several choices for KA, including one not considered in [MRR20] but which is well-suited to the batch setting. The main challenge is that traditional DHKA on an elliptic curve is not enough. Under the usual encoding (the *x*-coordinate), points on the curve are easily distinguishable from random strings, while it is more natural to dene a POPF operating on strings. Hence, some care is involved in making the POPF and KA compatible.

### 6.1 Curve Mappings

In [MRR20], the authors suggest two ways to achieve compatibility between POPF and KA. One choice is to ensure that the KA protocol messages are uniform *bit strings.* This can be done using the Elligator technique of [BHKL13] to encode curve elements. Elligator is an injective and eciently invertible function from *f*0*;* 1*g* to a large subset of the elliptic curve. If some party wishes to make their KA protocol message a uniform string, they simply sample from points in the image of. This is achieved in practice by re-sampling a DH exponent until the resulting curve point is in (*f*0*;* 1*g*). If the range of is a large fraction of the elliptic curve, then the expected number of re-samples is small. SeeFigure 8for a formal description of tagged Elligator ECDHKA. Another choice is to ensure that the POPF Eval function only outputs values on the curve. In the POPF construction of [MRR20] this can be achieved by instantiating a random oracle that gives outputs in the curve. Both of these techniques incur nontrivial computational overhead. The elligator approach re- quires resampling each curve element some constant number of times on average. The state of the art techniques for hashing-to-curve [BCI + 10,FFS + 10,TK17] have cost roughly 25% that of an exponentiation on the curve, and the POPF requires at least 2 hash-to-curve operations per party.

<u>Sender</u> (tag) <u>Receiver</u> (tag) do: *a* F*pb* F*p* *A* = *aG B* = *bG* while *B 62* (*f*0*;* 1*g*) <u>A</u>

<u>B</u> ~ <u>=</u>1<u>(B)</u>

### <u>return H(a (B</u>~<u>);) return H(bA;)</u>

Figure 8: Tagged Elligator ECDHKA. *G* is a generator of the curve and is the injective Elligator

mapping of [BHKL13].

### 6.2 Moller Variant of ECDHKA

We now suggest a more ecient approach that is well suited for the batch setting. Before continuing, let us give a brief review of elliptic curves. For the remainder of this section, we will consider curves over prime elds with order larger than 3. Further results and descriptions can be found in Silverman [Sil09].

Denition 16. *An elliptic curve Ea;bover a eld* F*pis dened by a congruence of the form* *Y* 2 = *X³* + *aX* + *b parameterized by elements a;b 2 Fpsuch that* 4*a³* + 27*b² 6*= 0*. The elements of* *Ea;bare given by tuples* (*X;Y*) *satisfying the congruence along with a neutral element O, the point* *at innity.*

We may equip this set with a group law called the chord-and-tangent law such that we arrive at a commutative group where the usual Die-Hellman problems are believed to be hard.

Denition 17. *Given an elliptic curve Ea;bover a eld* F*pand c 2* F*p, we may consider the* *elliptic curve Ec0*: *cY* 2 = *X³* + *aX* + *b. If c is a quadratic residue in* F*pthen E⁰ is isomorphic to* *E, otherwise, E⁰ is called the (quadratic) twist of E.*

As a twist of a given curve is unique up to isomorphism, we may consider, singly, a primary curve and its twist curve. It follows from the denition that any *x 2* F*p*is the abscissa (x-coordinate) of a point on *E* or of a point on the twist *E⁰*.

Lemma 18. *Let c 6*= 0 *be a quadratic non-residue in the eld* F*p, and let Ea;bbe an elliptic curve* *over* F*pwith twist Ec0. Then for every x 2* F*p:* *p*

*1.If x³* + *ax* + *b is a non-zero qudratic residue, then* (*x; x³* + *ax* + *b*) *are points on Ea;b.* *Furthermore,* (*x³*+*ax*+ *b*)*=c is a quadratic non-residue and x is not the abscissa of any point* *on Ec0*
*2.If x³* + *ax* + *b is a quadratic non-residue, then* <u>x</u> *is not a point on Ea;b. Furthermore,* (*x³* +
p *ax* + *b*)*=c is a quadratic residue and* (*x;* (*x³* + *ax* + *b*)*=c*) *are points on Ec0.*

*3.If x³* + *ax* + *b* = 0*, then* (*x;* 0) *is a point on Ea;band Ec0.* This idea is of importance as for many curves and applications, only the abscissa of a point is
needed. This means that we can work with bitstrings using the implicit mapping dened above.

<u>Sender</u> (tag) <u>Receiver</u> (tag) *a₀* F*pb* F*p* *a₁* F*p f* 0*;* 1*g* *A₀* = *a₀G₀ B* = *bG* <u>A ;A0 1</u> *A₁* = *a₁G₁* <u>Babscissa;sign</u>

if *B* on the curve: = 0 else: = 1 <u>return H(a B;) return H(b A;)</u>

Figure 9: Moller tagged ECDHKA. *G₀* is a generator of the curve and *G₁* is a generator of its twist.

Furthermore, there are a similar number of points on the twist as there are on the curve. If one were to toss a coin *b f* 0*;* 1*g*, and then sample an *x*-coordinate of a random curve point (if *b* = 0) or a random twist point (if *b* = 1), the result would be statistically close to the uniform distribution on the set of bitstrings.

*q* Lemma 19 ([CFGP06, Corollary 11]). *Given a curve Ea;band its twist Ec0over* F*p, where* 2 *p <* *q=*2 2 *(i.e., p is very close to a power of 2), the following distribution is indistinguishable from the* *q* *uniform distribution in f*0*;* 1*g*

*D* = *f f* 0*;* 1*g;x₀* [*Ea;b*]*abscissa;x₁* [*Ec0*]*abscissa*: *K* = *x g;*

*with statistical distance* *p* <u>1</u> X <u>1 + 2</u> = Pr [*K* = *x*] Pr [*K* = *x*] *:* 2 *K* F2*q K D* 2*q=*2 *x2*F*p*

This suggests the key agreement approach inFigure 9. The receiver will sample an *x*-coordinate as above. The sender cannot anticipate the receiver’s choice, so she prepares a DH message on both the curve and the twist, then chooses the correct one to compute the nal key.Lemma 19establishes that the receiver’s KA message is statistically indistinguishable from the uniform distribution on strings. Note that the sender sends two curve/twist elements instead just one as in standard DHKA. However, in batched OT it is exactly this sender message that is reused across all OT instances. Hence a slight increase in its size has minimal eect on the overall OT protocol’s eciency. Similar approaches to representation have been used used in the context of PAKE [BMN01], pseudo-random permutations [Kal91], authenticated key exchange [CFGP06], and by Moller [Mol04] in the context of ElGamal.

### 6.3 Curve Choice and Security

We now discuss the security of the Moller variant (tagged) KA protocol. The choice of curve must satisfy the following

*q q=*

- The nite eld must have order at least 2.

- The curve and its twist must be cryptographically secure.
- The curve and its twist must be cyclic. More specically, we need a security property similar to the oracle Die-Hellman (ODH)
assumption [ABR01]. That denition is as follows:

Denition 20 ([ABR01]). *Let* G *be a cyclic group of order n, with generator g, and let H* : *‘* *f*0*;* 1*g!f*0*;* 1*g be a hash function. Then the oracle Die-Hellman (ODH) assumption holds* *in* G *with respect to H if the following distributions are indistinguishable, for all A that do not* *b* *query their oracle at g.*

||a;b [n] a def H (X) = H (X) a ab K = H (g) H a b a return A (g ;g ;K)||a;b [n] a def H (X) = H (X) a ‘ K f 0; 1 g H a b a return A (g ;g ;K)||
|---|---|---|---|---|
|G|Our applications require a variant of ODH where the hash function with respect to H if the following distributions are indistinguishable, for all tags that do not query their oracle with second argument|be a cyclic group of order n, with generator g, and let H|H be a hash function. Then the tagged oracle Die-Hellman (TODH) assumption holds :||
|a;b def K|[n] a H (X;) = H (X ;) a ab = H (g ;) H a b a return A (g ;g ;K)||a;b [n] a def H (X;) = H (X; a ‘ K f 0; 1 g H a b a return A (g ;g ;K)|)|

takes an additional *tag* argument:

Denition 21. *Let* : *f*0*;* 1*g f*0*;* 1*g!* *‘* *f*0*;* 1*g* *in* G *and all A*

In [ABR01] the authors show that standard ODH is secure in the generic group model when *H* is a random oracle. This proof is easily adapted to the new TODH assumption as well.

Proposition 22. *Moller tagged DHKA (Figure 9) satises tag nonmalleability (Denition 3) if* *the TODH assumption holds in both the curve and its twist.*

A further small optimization is possible for Montgomery curves. The exponentiation algorithm only depends on the *x*-coordinate of its input and is uniform for both the curve and its twist, in the sense that the usual exponentiation algorithm for the curve also correctly exponentiates in the twist if the input is on the twist. So if the sender inFigure 9chooses *a₀* = *a₁* then there is no need to check whether the receiver’s *B* is on the curve or twist. Instead, the sender simply exponentiates *B* without any checking. However, security of this optimization requires that a kind of TODH assumption hold for the curve and twist jointly (instead of separately/independently for the curve and for the twist).

6.3.1 Instantiation When creating a concrete instantiation of Moller ECDHKA, we chose to use Curve25519 [Ber06]. The main reasons for this choice were:
*=*

1.The base eld F*p*is of prime order 2 *>*.

<u>Sender Receiver</u> (with input *fcigi2*[*m*]) <u>;:::;</u>

|1|n||1|n|S i;j|||
|---|---|---|---|---|---|---|---|
||||i||i|i|S i|
||||S|||||
|i;c i;j 0 i;j|i i;j 0 i2[m];j2f0;1g|S i|||i;c 0 i|i;c 0 i2[m]||

*:::* Base OT Receiver *m; fr g* Base OT Sender *fu g* OT Extension Receiver chal := *H*(*f g;m; fu g*) <u>m; fu g; resp</u> *ri*Base OT Receiver resp OT Extension Receiver chal := *H*(*f g;m; fu g*) check that resp answers chal *fr g* OT Extension Sender *fr g* OT Extension Receiver *i* <u>return fr g return fr g</u> <u>i</u>

Figure 10: Sketch of the composition of our batch OT protocol with the KOS OT extension

protocol, in 2 rounds.

2.Curve25519 is explicitly designed to have a twist that is as secure as the curve itself.
3.Curve25519 can take full advantage of Montgomery Ladders for scalar multiplication which allows us to use only the abscissa in computations.
4.Curve25519 and its twist have large prime subgroups of size #*E=*8 and #*Ec0=*4. Curve25519 also provides additional evidence for the security of the above optimization of
setting *a₀* = *a₁*, because [Ber06] recommends not checking whether a given point is on the curve or twist before performing scalar multiplication. This optimization is why Curve25519 was chosen to have a secure twist, and in fact the reference implementation does not check if an elliptic curve point is on the curve. This requires a similar additional security assumption to our optimization because it uses the same key for both the curve and its twist.

## 7 2-round Endemic OT Extension

When our protocol is used for base OTs, we can achieve a 2-round Endemic OT extension protocol, if the Fiat-Shamir heuristic is used. First, recall that our batch OT protocol is 1-ow when instantiated with a 1-ow KA protocol, *e.g.*, any Die-Hellman-based KA protocol. This gives us the exibility to send base OT messages in any order. Second, we summarize the 1-out-of-2 OT extension protocol of [KOS15]:

- The parties perform base OTs
- The receiver (who is base OT sender) sends data as in all IKNP-based [IKNP03] extension protocols.
- To protect against a malicious receiver, the sender gives a random challenge
- The receiver sends a response to this challenge, which the sender checks.
We can order the messages of the base OTs so that the receiver can send their IKNP data along with their base OT sender message. Additionally, we can collapse the malicious consistency check using the Fiat-Shamir heuristic, since the sender’s challenge is random. The resulting OT extension protocol is sketched inFigure 10. In related work, [CSW20] show how to use the Chou-Orlandi base OT protocol to achieve 3- + round OT extension. This is inevitable since their base OTs already require 3 rounds. [BCG 19]

show a 2-round OT extension protocol based on newer \silent OT" techniques. Note however that both these papers achieve chosen message OT, whileFigure 10only achieves endemic OT and would require a third round to derandomize the sender’s messages.

## 8 Performance Evaluation

In this section, we will explore the concrete performance benchmarks of multiple instantiations of the protocol inFigure 3.

### 8.1 Implementation Details

We implemented⁷ our protocol inside the libote OT extension library [Rin], modifying the library to use Rijndael-256 [DR99,BOS11] as a standin for an ideal cipher and libsodium [Den20] to implement elliptic curve operations. The library uses Blake2 [ANWW13] as a standin for a random oracle. We then tested the protocols on a machine running on an Intel Xeon E5-2699 v3 CPU, without assembly optimizations or multi-threading. For benchmarking, each protocol was run in a batch of 128 OTs for two settings of simulated latency and bandwidth limiting. The two settings are meant to shed light on the LAN vs WAN environments that these protocols may run in. The number of OTs to run was chosen to provide a realistic setting in the case of 128 base OTs as is common in OT extension. We compared the following implementations:

- Chou-Orlandi (Simplest OT).
- Naor-Pinkas OT
- Masny-Rindal (Endemic OT), with and without reusing the sender’s message. This protocol uses hash-to-curve operations.
- Our protocol instantiated with Moller’s DHKA and various POPFs. We used the original Feistel POPF of MRR, as well as the POPFs presented inSection 5. Because the messages from Moller’s scheme are uniformly random bit strings, our these POPFs avoid the hash-to- curve operations that are needed in [MR19]. We did not evaluate the Even-Mansour POPF (Figure 5), since its performance would be identical to the EKE POPF (Figure 4) when both the ideal cipher and ideal permutation are instantiated with Rijndael.
- Our protocol with traditional DHKA, and all POPF instantiations excluding EKE and Masny- Rindal. We did not implement the EKE POPF using DHKA; however this could be accom- plished using Elligator or a similar mapping to construct an ideal cipher on a subset of the curve points. We did not implement our protocol with Masny-Rindal POPF as it would be nearly identical to the Masny-Rindal protocol.
### 8.2 Results & Discussion

The performance benchmarks can be found inTable 2for both settings. As we would expect, when comparing the three instances of Masny-Rindal OT, each with their own improvement, we see a marked increase in eciency. Specically, reusing the sender’s message reduced the total time spent by both parties by 18% / 11% in the low latency and high bandwidth

Source code is at [https://github.com/Oreko/popfot-implementation](https://github.com/Oreko/popfot-implementation).

|Protocol||Security|Sender (ms)|Receiver (ms)|
|---|---|---|---|---|
||0.1ms latency, 10000Mbps bandwidth cap||||
|Simplest OT [CO15] (Sender-reuse)||standalone|35|17|
|Naor-Pinkas OT [NP01] (Sender-reuse)||standalone|43|34|
|Endemic OT [MR19] (No reuse)||UC|79|42|
|Endemic OT (Sender-reuse)||UC|62|37|
|Ours (Feistel POPF [MRR20] { DHKA)||UC|82|40|
|Ours (Streamlined Feistel POPFFigure 7{ DHKA)||UC|80|40|
|Ours (Feistel POPF | Moller DHKA)||UC|49|26|
|Ours (Streamlined Feistel POPF | Moller DHKA)||UC|50|27|
|Ours (Masny-Rindal POPFFigure 6| Moller DHKA)||UC|48|27|
|Ours (EKE POPFFigure 4| Moller DHKA)|30ms latency, 100Mbps bandwidth cap|UC|50|25|
|Simplest OT [CO15] (Sender-reuse)||standalone|105|111|
|Naor-Pinkas OT [NP01] (Sender-reuse)||standalone|101|107|
|Endemic OT [MR19] (No reuse)||UC|161|53|
|Endemic OT (Sender-reuse)||UC|137|53|
|Ours (Feistel POPF [MRR20] { DHKA)||UC|155|47|
|Ours (Streamlined Feistel POPFFigure 7{ DHKA)||UC|155|47|
|Ours (Feistel POPF | Moller DHKA)||UC|128|44|
|Ours (Streamlined Feistel POPF | Moller DHKA)||UC|128|44|
|Ours (Masny-Rindal POPFFigure 6| Moller DHKA)||UC|128|44|
|Ours (EKE POPFFigure 4| Moller DHKA)|Running time of batch OT protocols, for batch size of 128.|UC|128|44|

Table 2:

setting / the high latency and low bandwidth setting, respectively. Moving to Moller’s KA caused an additional 24% / 9% improvement, respectively, for the Masny-Rindal construction. On average, for the three protocols with both DHKA and Moller DHKA versions (Masny-Rindal and the two Feistel POPF variants) we saw an improvement of 32% / 13%, respectively, when moving to Moller’s KA. As expected, the Simplest OT protocol outperforms our instantiations for the sender since it uses fewer exponentiations in the group. One point to take note of in the evaluation data is the large gap in the performance for the receiver between the Naor-Pinkas and Simplest / Blazing OT constructions and the POPF and Masny-Rindal constructions in the high latency / low bandwidth setting. This is due to the dierent ow requirements between the two sets of protocols. Simplest OT and Naor-Pinkas constructions all require an additional ow (or two) which, in the WAN setting, will acrue more time for the party which needs to wait. It then follows that the advantages of our protocol over Simplest OT is our UC security and round/ow complexity.

## References

[ABR01]Michel Abdalla, Mihir Bellare, and Phillip Rogaway. The oracle Die-Hellman as- sumptions and an analysis of DHIES. In David Naccache, editor, *CT-RSA 2001*, volume 2020 of *LNCS*, pages 143{158. Springer, Heidelberg, April 2001.

[ALSZ13]Gilad Asharov, Yehuda Lindell, Thomas Schneider, and Michael Zohner. More e- cient oblivious transfer and extensions for faster secure computation. In Ahmad-Reza Sadeghi, Virgil D. Gligor, and Moti Yung, editors, *ACM CCS 2013*, pages 535{548. ACM Press, November 2013.

[ANWW13]Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O’Hearn, and Christian Win- nerlein. BLAKE2: Simpler, smaller, fast as MD5. In Michael J. Jacobson Jr., Michael E. Locasto, Payman Mohassel, and Reihaneh Safavi-Naini, editors, *ACNS* *13*, volume 7954 of *LNCS*, pages 119{135. Springer, Heidelberg, June 2013.

[BCG + 19]Elette Boyle, Georoy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, Peter Rindal, and Peter Scholl. Ecient two-round OT extension and silent non-interactive secure computation. In Lorenzo Cavallaro, Johannes Kinder, XiaoFeng Wang, and Jonathan Katz, editors, *ACM CCS 2019*, pages 291{308. ACM Press, November 2019.

[BCI + 10]Eric Brier, Jean-Sebastien Coron, Thomas Icart, David Madore, Hugues Randriam, and Mehdi Tibouchi. Ecient indierentiable hashing into ordinary elliptic curves. In Tal Rabin, editor, *CRYPTO 2010*, volume 6223 of *LNCS*, pages 237{254. Springer, Heidelberg, August 2010.

[Bea96]Donald Beaver. Correlated pseudorandomness and the complexity of private compu- tations. In *28th ACM STOC*, pages 479{488. ACM Press, May 1996.

[Ber06]Daniel J. Bernstein. Curve25519: New Die-Hellman speed records. In Moti Yung, Yevgeniy Dodis, Aggelos Kiayias, and Tal Malkin, editors, *PKC 2006*, volume 3958 of *LNCS*, pages 207{228. Springer, Heidelberg, April 2006.

[BHKL13]Daniel J. Bernstein, Mike Hamburg, Anna Krasnova, and Tanja Lange. Elligator: elliptic-curve points indistinguishable from uniform random strings. In Ahmad-Reza Sadeghi, Virgil D. Gligor, and Moti Yung, editors, *ACM CCS 2013*, pages 967{980. ACM Press, November 2013.

[BM92]Steven M. Bellovin and Michael Merritt. Encrypted key exchange: Password-based protocols secure against dictionary attacks. In *1992 IEEE Symposium on Security and* *Privacy*, pages 72{84. IEEE Computer Society Press, May 1992.

[BMN01]Colin Boyd, Paul Montague, and Khanh Quoc Nguyen. Elliptic curve based password authenticated key exchange protocols. In Vijay Varadharajan and Yi Mu, editors, *ACISP 01*, volume 2119 of *LNCS*, pages 487{501. Springer, Heidelberg, July 2001.

[BOS11]Joppe W. Bos, Onur Ozen, and Martijn Stam. Ecient hashing using the AES in- struction set. In Bart Preneel and Tsuyoshi Takagi, editors, *CHES 2011*, volume 6917 of *LNCS*, pages 507{522. Springer, Heidelberg, September / October 2011.

[CFGP06]Olivier Chevassut, Pierre-Alain Fouque, Pierrick Gaudry, and David Pointcheval. The Twist-AUgmented technique for key exchange. In Moti Yung, Yevgeniy Dodis, Aggelos

Kiayias, and Tal Malkin, editors, *PKC 2006*, volume 3958 of *LNCS*, pages 410{426. Springer, Heidelberg, April 2006.

[CMR]Brent Carmer, Alex J. Malozemo, and Marc Rosen. swanky: a suite of rust libraries for secure multi-party computation. [https://github.com/GaloisInc/swanky](https://github.com/GaloisInc/swanky).

[CO15]Tung Chou and Claudio Orlandi. The simplest protocol for oblivious transfer. In Kristin E. Lauter and Francisco Rodrguez-Henrquez, editors, *LATINCRYPT 2015*, volume 9230 of *LNCS*, pages 40{58. Springer, Heidelberg, August 2015.

[CSW20]Ran Canetti, Pratik Sarkar, and Xiao Wang. Blazing fast OT for three-round UC OT extension. In Aggelos Kiayias, Markulf Kohlweiss, Petros Wallden, and Vassilis Zikas, editors, *PKC 2020, Part II*, volume 12111 of *LNCS*, pages 299{327. Springer, Heidelberg, May 2020.

[Den20]Frank Denis. The sodium cryptography library, Nov 2020.

[DR99]Joan Daemen and Vincent Rijmen. Aes proposal: Rijndael. 1999.

[DSST17]Yuanxi Dai, Yannick Seurin, John P. Steinberger, and Aishwarya Thiruvengadam. Indierentiability of iterated Even-Mansour ciphers with non-idealized key-schedules: Five rounds are necessary and sucient. In Jonathan Katz and Hovav Shacham, editors, *CRYPTO 2017, Part III*, volume 10403 of *LNCS*, pages 524{555. Springer, Heidelberg, August 2017.

[EM93]Shimon Even and Yishay Mansour. A construction of a cipher from a single pseudo- random permutation. In Hideki Imai, Ronald L. Rivest, and Tsutomu Matsumoto, editors, *ASIACRYPT’91*, volume 739 of *LNCS*, pages 210{224. Springer, Heidelberg, November 1993.

[FFS + 10]Reza R. Farashahi, Pierre-Alain Fouque, Igor E. Shparlinski, Mehdi Tibouchi, and

J. Felipe Voloch. Indierentiable deterministic hashing to elliptic and hyperelliptic curves. Cryptology ePrint Archive, Report 2010/539, 2010. [http://eprint.iacr](http://eprint.iacr). org/2010/539.
[HL17]Eduard Hauck and Julian Loss. Ecient and universally composable protocols for oblivious transfer from the CDH assumption. Cryptology ePrint Archive, Report 2017/1011, 2017. [http://eprint.iacr.org/2017/1011](http://eprint.iacr.org/2017/1011).

[IKNP03]Yuval Ishai, Joe Kilian, Kobbi Nissim, and Erez Petrank. Extending oblivious transfers eciently. In Dan Boneh, editor, *CRYPTO 2003*, volume 2729 of *LNCS*, pages 145{

161. Springer, Heidelberg, August 2003.
[IR90]Russell Impagliazzo and Steven Rudich. Limits on the provable consequences of one- way permutations. In Sha Goldwasser, editor, *CRYPTO’88*, volume 403 of *LNCS*, pages 8{26. Springer, Heidelberg, August 1990.

[Kal91]Burton S. Kaliski Jr. One-way permutations on elliptic curves. *Journal of Cryptology*, 3(3):187{199, January 1991.

[Kel20]Marcel Keller. MP-SPDZ: A versatile framework for multi-party computation. Cryp- tology ePrint Archive, Report 2020/521, 2020. [https://eprint.iacr.org/2020/521](https://eprint.iacr.org/2020/521).

[KK13]Vladimir Kolesnikov and Ranjit Kumaresan. Improved OT extension for transferring short secrets. In Ran Canetti and Juan A. Garay, editors, *CRYPTO 2013, Part II*, volume 8043 of *LNCS*, pages 54{70. Springer, Heidelberg, August 2013.

[KOS15]Marcel Keller, Emmanuela Orsini, and Peter Scholl. Actively secure OT extension with optimal overhead. In Rosario Gennaro and Matthew J. B. Robshaw, editors, *CRYPTO 2015, Part I*, volume 9215 of *LNCS*, pages 724{741. Springer, Heidelberg, August 2015.

[Mol04]Bodo Moller. A public-key encryption scheme with pseudo-random ciphertexts. In Pierangela Samarati, Peter Y. A. Ryan, Dieter Gollmann, and Rek Molva, editors, *ESORICS 2004*, volume 3193 of *LNCS*, pages 335{351. Springer, Heidelberg, Septem- ber 2004.

[MR19]Daniel Masny and Peter Rindal. Endemic oblivious transfer. In Lorenzo Cavallaro, Johannes Kinder, XiaoFeng Wang, and Jonathan Katz, editors, *ACM CCS 2019*, pages 309{326. ACM Press, November 2019.

[MRR20]Ian McQuoid, Mike Rosulek, and Lawrence Roy. Minimal symmetric PAKE and 1- out-of-N OT from programmable-once public functions. In Jay Ligatti, Xinming Ou, Jonathan Katz, and Giovanni Vigna, editors, *ACM CCS 20*, pages 425{442. ACM Press, November 2020.

[NP01]Moni Naor and Benny Pinkas. Ecient oblivious transfer protocols. In S. Rao Kosaraju, editor, *12th SODA*, pages 448{457. ACM-SIAM, January 2001.

[OOS17]Michele Orru, Emmanuela Orsini, and Peter Scholl. Actively secure 1-out-of-N OT extension with application to private set intersection. In Helena Handschuh, editor, *CT-RSA 2017*, volume 10159 of *LNCS*, pages 381{396. Springer, Heidelberg, February

2017.
[Rin]Peter Rindal. libOTe: an ecient, portable, and easy to use Oblivious Transfer Li- brary. [https://github.com/osu-crypto/libOTe](https://github.com/osu-crypto/libOTe).

[Sil09]Joseph H Silverman. *The arithmetic of elliptic curves*, volume 106. Springer Science & Business Media, 2009.

[Sma]Nigel Smart. SCALE-MAMBA: Secure computation algorithms from LEuven, multi- party algorithms basic argot. [https://homes.esat.kuleuven.be/~nsmart/SCALE/](https://homes.esat.kuleuven.be/~nsmart/SCALE/).

[TK17]Mehdi Tibouchi and Taechan Kim. Improved elliptic curve hashing and point repre- sentation. Designs, Codes and Cryptography, 2017.

[WMK16]Xiao Wang, Alex J. Malozemo, and Jonathan Katz. EMP-toolkit: Ecient Multi- Party computation toolkit. [https://github.com/emp-toolkit](https://github.com/emp-toolkit), 2016.

## A Correlation Attack on Navely Batched MRR-OT

Consider the following strategy for a corrupt receiver, against nave batching of the MRR OT protocol.

- The sender rst sends its (reused) KA message *A* = *g*
*a*.

- In the rst instance, run honestly with choice bit *c₁* = 0. Generate1= Program(0*;g*
*b* ) for known *b*.

- The receiver can compute the value *B*~ = Eval(1*;*1). The security of the POPF is that the receiver has no control over this value (*i.e.*, doesn’t know its discrete log). The sender will compute OT output from this instance *r₁;*1= *B*~
*a*.

- In the second instance, set2= Program(0*; B*~ *g*
*s* ) for known *s*. This means that the sender will compute OT output from this instance

||~|~||||
|---|---|---|---|---|---|
|2 a|s a|s as|;1 as|;1 s||
|s s||||;0|;1|

*r₂;*0= Eval(*;*0) = (*Bg*) = *B g* = *r₁ g* = *r₁ A*

Note that the receiver can indeed compute *A*, and therefore it knows the ratio *r₂ =r₁*. Note also that if *s* is uniform then *B*~ *g* is distributed uniformly. From the simulator’s point of view, the receiver’s behavior is *identically distributed* to honest behavior | running Program(0*;X*) for a uniform group element *X*. Hence, even if the ideal functionality is weakened to allow the receiver to specify correlations among the OT values, in this protocol the simulator has no way of detecting which correlation is appropriate.

## B Security Proofs for POPFs

### B.1 Security Proof for Ideal Cipher (EKE) POPF

First, we have that HHSim*;* H*;* HExtractare indistinguishable, because they are all identical other than HSim and Extract. Extract only reads HExtract’s state, but does not modify it. Correctness follows directly from the correctness property of ideal ciphers. There is an invariant that must be maintained for the ideal cipher to continue working properly. For any *x;* there must not be *y₁ 6*= *y₂* such that (*x;y₁;*) *2 T* and (*x;y₂;*) *2 T*. Similarly, for any *x;y* there must not be1*6*=2such that (*x;y;*1) *2 T* and (*x;y;*2) *2 T*. If either case happened, the output of *E* or *E* 1 would not be well-dened. A birthday bound shows that *E* and *E* 1 maintain this invariant. HSim explicitly aborts if it is asked to break the invariant.

Honest Simulation: Recall that the *y* sampled by D must be uniform. By a birthday bound it is unique, not overlapping any previous *y* in *T*, with all but negligible probability. Then when real phi samples Program(*x ;y*), *E* will choose a uniformly random, the same distribution as sampled by HSim. It will also add (*x ;y ;*) to *T*. A similar birthday bound allows us to assume that this is also unique. Then a *E* 1 (1 *x ;*) query will be freshly random, so we can equivalently sample it ahead of time in a random value *r₁x*and add (1 *x ;r₁x;*) to *T*. But this is exactly what happens in sim phi, as the abort in HSim will not occur because *r₀* and *r₁* will be unique.

Uncontrollable Outputs: We provide a sequence of hybrids, starting from the real distribution and ending at the ideal distribution.

1.Create an empty associative array *Z* at the start of HExtract. Inside *E*
1, whenever *y* is sampled as freshly random, compute and save *Z*[*y*] = *F* (*y*). Then use the precomputed value as *r* in Uncontrollable Outputs instead of nding it again; since *y* = Eval(*;* 1 *x*) is calculated *Z*[*y*] must have been precomputed. This step just rearranges the order of computations, and so is indistinguishable.

2.For the rst *E*
1 query, instead of nding *F* (*y*), sample *Z*[*y*] as a uniformly random value in *O*. We would like to use the 1-weak RO’s security to prove that this is indistinguishable, but it seems like we are using *F* multiple times, and so cannot use the security property. However, this multiple use is illusory, as only single value in *Z* will ever be used and the rest will be discarded.

More concretely, if we construct a reduction from this change in the hybrid proof to the 1- weak RO security, without loss of generality we can assume that the adversary aborts if this rst *Z*[*y*] does not end up being used to nd *r*. If it is not used then the two distributions are identical anyway. Now the other computations of *F* are completely unused and can be removed, allowing us to reduce to 1-weak RO security.

3.Repeat Step 2 for subsequent *E*
1 queries.

4.Undo the changes in step 1. That is, delay randomly sampling the entries of *Z* until Uncon- trollable Outputs is run, so *r* will be uniformly random. The advantage is bounded by adding up the advantages of every step. All security properties
<u>q</u> 2 used a constant number of birthday bounds, which give the adversary an advantage of *O* *N*. Additionally, Uncontrollable Outputs used the security of the 1-weak RO once in each *E* 1 query, for a total advantage of *q* Adv(*wRO*).

### B.2 Security Proof for Even-Mansour POPF

The proof is very similar to that ofTheorem 12, and we will only describe the dierences. The invariant no longer mentions *x*, and just says that each *u* should have at most one *v* and vice versa. Honest Simulation works similarly to before, pre-programming the randomness that Eval will produce. It will preserve the invariant as long as it does not produce the same or 1 as one produced previously | ignoring a single bit should not aect collision resistance. For extraction, the only additional complication is arguing that the *x* produced by Extract is the only one where Eval(*;x*) is not freshly random on its rst call. The only way for it to not be random is for there to have been a previous (*u*) call that returned *x*, but this cannot happen for multiple *x* as we have assumed that the other bits of are unique. Extract checks *T* to nd the unique call *v* = (*u*) where this happened, which must have been the rst, then nds *x* such that *v* = *x*.

### B.3 Security Proof for Masny-Rindal POPF

First, we have HHSimH HExtract, because they are all identical when neither HSim nor Extract have been called, though some have extra bookkeeping. Extract only reads HExtract’s state, but 1 does not modify it. Correctness is ensured as if = (*s₀;y* (*H₁*(*s₀*))) Program(1*;y*) then 1 *y* = *y* (*H₁*(*s₀*)) *H₁*(*s₀*) = Eval(*;*1), and similarly for *x* = 0.

Honest Simulation: In the generation of = (*s₀;s₁*), we have that *s₁x*is uniform by con- struction, and furthermore since *y* is sampled from D and must be uniform we have that Program will generate uniform *sx*. *sx*is distinguishable only if *Hx*(*s₁x*) had previously been queried which for uniform *s₁x*only happens with probability at most *j*G <u>q</u> *j*. We also have uniqueness of *s₀;s₁* with all but negligible probability by an application of a birthday bound over G, so using *U* to program *Hx*will not interfere with any previous *Hx*queries or other HSim calls. Finally, we have that Eval(*; x*) = *s₁xH₁x*(*sx*) is close to uniform

(since the query *H₁x*(*sx*) will be fresh with probability 1 *j*G <u>q</u> *j* ), so we can sample it early and save it in *U*. This is exactly how HSim functions in the ideal world. Finally, by the enforced consistency of HSim we have that the outputs *r₀;r₁* from Eval are the values provided to HSim. This can be 1 veried as if = (*s₀;s₁*) HSim(*r₀;r₁*) then Eval(*;x*) = *sxHx*(*s₁x*) = *sx*(*sx*) *rx*= *rx*.

Uncontrollable Outputs: Similarly to the proof of Claim 4.3 in [MR19], we would like to guess a query *Hx*(*u*). Following MRR20, we will call this query an anchor query. The idea is that this is the query made by Program, or however the adversary constructed. Any subsequent query *H₁x*(*u*) can be programmed to be *u* 1 *y* to make Eval(*;* 1 *x*) = *y* if we guessed correctly. We will know we guessed correctly if later *u* is part of the that is input to Extract. However, instead of guessing a query like in [MR19], we will use a hybrid proof to get the same result. Some hybrids will make changes that are only useful if a guess is correct, but do nothing if the guess is wrong. Here is our sequence of hybrids starting with an interaction with the real protocol and ending with the ideal world.

1.Create a new associative array *Z* at the start of HExtract. When a uniformly random value *v* is sampled in *Hx*(*u*), look for possible anchor queries by iterating over all previous queries *H₁x*(*u*), and in each iteration, compute and save *Z*[*x;u ;u*] = *F* (*u v*).
2.Use the precomputed value *Z*[1 *x ;s₁x;sx*] as *r* in the Uncontrollable Outputs distribu- tion, instead of nding it again with *F*(Eval(*;* 1 *x*)), if it has already been computed.
3.For 1 *i q* and 1 *j < i*, repeat the following sequence of hybrids. That is, perform these transformations for the *i*th query to *H* and *j*th iteration of the loop over prior queries in *H*,
<u>q(q 1)</u> for a total of 2 repetitions.

(a)Instead of sampling *v* G in the *i*th query *Hx*(*u*), use *u* from the *j*th iteration of the loop over possible anchor queries to sample *y* G and set *v* = *u*
1

*y*.
(b)In the *j*th iteration of the *i*th query to *H*, instead of computing *Z*[*;x*] = *F* (*y*), sample *Z*[*;x*] as a uniformly random value in *O*. This change is indistinguishable because *F* is a 1-weak RO.
8

(c)Undo the changes in step 3a, so *v* is sampled as *v* G again.
4.Undo the changes in step 1. That is, wait until the Uncontrollable Outputs distribution is run before sampling the entries in *Z*. If *Z*[1 *x ;s₁x;sx*] is present, the Uncontrollable Outputs distribution now gets a uniformly random *r* instead of the output of *F*.
5.Finally, also replace *r* with random if it does not appear in *Z*. In this case, either *H₀*(*s₁*) or *H₁*(*s₀*) must not have been queried before, as otherwise whichever was queried rst would be the anchor query and then in the second query *r* would be precomputed and saved in *Z*. Either *x* will be the query that was made, or neither were queried | either way, *Hx*(*s₁x*) must not have been queried. Therefore Eval(*;* 1 *x*) must return a fresh uniformly random value, and the 1-weak RO property allows us to replace *F*’s output with random.
<u>q</u> 2 For Honest Simulation, the adversary just gets a birthday bound advantage *O* *N*. But in Un- controllable Outputs we use the security of 1-weak RO, which allows them an additional advantage. <u>q(q 1)</u> We use it 2 times in step 3b, and one additional time in step 5. Therefore, Uncontrollable <u>q</u> 2<u>q+2</u> Outputs allows the adversary an advantage of Adv(*wRO*), on top of the birthday bounds.

Although it appears that *F* is used in multiple places, only a single one is actually used in the end. See the proof for the EKE POPF for details.

### B.4 Security Proof for Feistel POPF

All three Hs are clearly indistinguishable on their common interface, as without any HSim queries they behave identically. For correctness, notice that

Eval(Program(*x ;y*)*;x*) = *H*(*x ;*(*t*)*x* + *u* (*t*)*x*) *t*

= *H*(*x ;u*) *H*(*x ;u*) 1 *y* = *y*

Honest Simulation: real phi chooses *u* uniformly randomly, so the *H*(*x ;u*) query will return fresh randomness as it has negligible probability of overlapping with any other query. Therefore = (*s;t*) will be uniformly random, the same distribution as produced by HSim. Next, we just need to prove that HSim successfully programs Eval, *i.e.*, that *r₀* and *r₁* will match between real phi and sim phis. It succeeds if the second if-statement in *H*(*x;*(*t*)*x* + *s*) is triggered, because then Eval(*;x*) will produce *H*(*x;*(*t*)*x* + *s*) *t* = *rxt* 1 *t* = *rx*. There are two ways that it could fail: either *H*(*x;*(*t*)*x* + *s*) had already been queried before HSim was called, or *U* [*x;*(*t*)*x* + *s*] gets overwritten by another HSim query. The former case has negligible probability because there are at most *q* previous queries *H*(*x;u*), each would cause a failure only if *s* = *u* (*t*)*x*, and *s* is chosen uniformly at random after the *H*(*x;u*) query. For the latter case, notice that every = (*s;t*) denes a unique line *u* = (*t*)*x* + *s*. A pair of such lines would have to intersect at some *x 2f*0*;* 1*g* in order for *U* to be overwritten. They can only intersect for a single value of *x*, and since both lines are uniformly random, this *x* will be uniformly random in F, so there is negligible probability of an intersection for *x 2f*0*;* 1*g*. 9

Uncontrollable Outputs: We use MRR20’s notion of anchor queries for this proof. An anchor query is a query made during Program that can be used by HExtractto identify before it is revealed by the adversary. More specically, a query *H*(*x ;u*) is the anchor query if it is the rst query on the line *u* = (*t*)*x* + *s*. It is, in fact, the query that Extract searches for in order to nd *x*. The anchor query is needed in order to nd *t* early and program the subsequent *H* queries such that Eval outputs a random value for the weak random oracle. MRR20 guessed the anchor query, taking a factor *q* security loss, and we will do something similar with hybrids. In a chain of hybrids we guess a possible anchor query and make some changes that make progress if the guess was correct and do nothing if we are wrong. Once the anchor query *H*(*x ;u*) has been made, on each subsequent query *H*(*x;u*) we assume it is on the same *u* = (*t*)*x* + *s* line and use this to nd and program *H*(*x;u*). Specically, *t* = 1 <u>u</u> *x* <u>u</u> *x* can be found from the slope of the line through the points (*x ;u*)*;* (*x;u*), and *s* = *u* (*t*)*x* is the *u*-axis intercept. If this assumption is wrong there is no harm, similarly to the anchor query. We use the following sequence of hybrids, from the real distribution to the ideal distribution.

1.Create an empty associative array *Z* at the start of HExtract. Inside *H*, whenever *v* is sampled as freshly random, iterate over all previous queries *H*(*x ;u*) for *x 6*= *x* to look for possible anchor queries. For each such query, compute = (*s;t*) as described above. Skip to the next *H*-query if this came up in a previous iteration, as then it is impossible for *H*(*x ;u*) to be the anchor query for. Compute and save *Z*[*;x*] = *F* (*v t*).
2.Use the precomputed value *Z*[*;* 1 *x*] as *r* in the Uncontrollable Outputs distribution if it is present, instead of computing it again as *F*(Eval(*;* 1 *x*)). When handling exponentially large *x* this becomes problematic, but can be xed by hashing *x* with another
random oracle *H⁰* before multiplying by, so that the adversary would need to solve a hard preimage problem to nd the *x* corresponding to an intersection.

3.For 1 *i q* and 1 *j < i*, repeat the following sequence of hybrids. That is, perform these transformations for the *i*th query to *H* and *j*th possible anchor query, for a total of at most <u>q(q 1)</u> 2 repetitions.
(a)Instead of sampling *v* G in the *i*th query *H*(*x;u*), use the inferred = (*s;t*) from the *j*th possible anchor query to sample *y* G and set *v* = *y t*
1.

(b)In the *j*th iteration in the *i*th query to *H*, instead of computing *Z*[*;x*] = *F* (*y*), sample *Z*[*;x*] as a uniformly random value in *O*. This change is indistinguishable because *F* is a 1-weak RO.
10

(c)Undo the changes in step 3a, so *v* is sampled as *v* G again.
4.Undo the changes in step 1. That is, delay randomly sampling the entries in *Z* until Uncon- trollable Outputs is run. If *Z*[*;* 1 *x*] is present, the Uncontrollable Outputs distribution now gets a uniformly random *r* instead of the output of *F*.
5.Finally, if *Z*[*;* 1 *x*] is not present, replace the output *r* of the 1-weak RO with random. In this case *H* 1 *x ;*(*t*)(1 *x*) + *s* cannot have been queried before, as otherwise either the anchor query would be at 1 *x* not *x*, or the anchor query *H*(*x ;*(*t*)*x* + *s*) would have been made before the other query and so *Z*[*;* 1 *x*] would be present, which are both contradictions. Therefore, the call to Eval(*;* 1 *x*) in the Uncontrollable Outputs distribution must return fresh randomness, and then the 1-weak RO property allows us to replace *r* with random. Again, we bound the advantage by summing the advantages of each step in the hybrid proof.
Excluding the birthday bounds, the only advantage the adversary gets is in Uncontrollable Outputs, <u>q(q 1)</u> when we use the 1-weak RO property. We use it 2 times in step 3b, once for each pair of oracle queries, because we have to loop over every previous query as a possible anchor query. Finally, we use it one last time in step 5. Therefore, Uncontrollable Outputs allows the adversary an advantage <u>q</u> 2<u>q+2</u> of 2 Adv(*wRO*), on top of the birthday bounds.

Although it may seem that *F* is used multiple times, only one of these values will actually be used in the end. For more details, see the proof for the EKE POPF.
