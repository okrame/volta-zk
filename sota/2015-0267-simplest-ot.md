# The Simplest Protocol for Oblivious Transfer

### Tung Chou and Claudio Orlandi

Technische Universieit Eindhoven and Aarhus University

Abstract Oblivious Transfer (OT) is one of the fundamental building blocks of cryptographic proto- cols. In this paper we describe the simplest and most ecient protocol for 1-out-of-*n* OT to date, which is obtained by tweaking the Die-Hellman key-exchange protocol. The protocol allows to perform *m* 1-out-of-*n* OTs using only 2 + 3*m* full exponentiations (2*m* for the receiver, 2 + *m* for the sender) and, sending only *m* + 1 group elements and 2*mn* ciphertexts. We also report on an implementation of the protocol using elliptic curves, and on a number of mechanisms we employ to ensure that our software is secure against active attacks too. Experimental results show that our protocol (thanks to both al- gorithmic and implementation optimizations) is at least one order of magnitude faster than previous

Update: The proceeding version of this paper contains incorrect claims. See Section 1.1 for

work.

details.

## 1 Introduction

Oblivious Transfer (OT) is a cryptographic primitive de- ned as follows: in its simplest avour, 1-out-of-2 OT, a sender has two input messages *M₀* and *M₁* and a re- ceiver has a choice bit *c*. At the end of the protocol the receiver is supposed to learn the message *Mc*and nothing else, while the sender is supposed to learn nothing. Per- haps surprisingly, this extremely simple primitive is suf- cient to implement any cryptographic task [Kil88]. OT can also be used to implement most advanced crypto- graphic tasks, such as secure two- and multi-party com- putation (e.g., the millionaire’s problem) in an ecient way [NNOB12, BLN + 15]. Given the importance of OT, and the fact that most OT applications require a very large number of OTs, it is crucial to construct OT protocols which are at the same time ecient and secure against realistic adversaries.

A Novel OT Protocol. In this paper we present a novel and extremely *simple*, *ecient* and *secure* OT protocol. The protocol is a simple tweak of the celebrated Die- Hellman (DH) key exchange protocol. Given a group G and a generator *g*, the DH protocol allows two players Alice and Bob to agree on a key as follows: Alice samples a random *a*, computes *A* = *g* *a* and sends *A* to Bob. Sym- *b* metrically Bob samples a random *b*, computes *B* = *g*

|B to Alice.|both parties|can compute|
|---|---|---|
|b a|a|ab a|

and sends Now *g* *ab* = *A* = *B* from which they can derive a key *k*. The key observation is now that Alice can also derive a dierent key from the value (*B=A*) = *g* 2, and that Bob cannot compute this group element (assuming that the computational DH problem is hard).

Die-Hellman Key Exchange

Sender Receiver Input: (*M*) Input: none Output: none Output: *M*

*a* Z*p* *a* *b* Z*p* <u>A = g</u> <u>-</u> <u>B = g</u> *b*

*a b* *k* = *H* (*B*) *k* = *H*(*A*) <u>e E (M</u>) <u>k</u> <u>-</u> *M* = *Dk*(*e*)

Our OT Protocol

Sender Receiver Input: (*M;M*) Input: *c* 0 1 Output: none Output: *Mc*

*a* Z*p* *a* *b* Z*p* <u>A = g</u> <u>-</u> if *c* = 0: *B* = *g* *b* if *c* = 1: *B* = *Ag* *b* <u>B</u> *k₀* = *H* (*B* *a* ) *kR* = *H*(*A* *b* ) <u>B</u> *a* *k₁* = *H* *A* *e₀ Ek*0(*M₀*) <u>e₁ E</u>*k*1<u>(M₁</u> <u>-</u> <u>)</u>

*M* = *D* (*e*) *c kR c*

Figure 1. Our protocol in a nutshell

We can now turn this into an OT protocol by letting Alice play the role of the sender and Bob the role of the receiver (with choice bit *c*) as shown in Figure 1. The rst message (from Alice to Bob) is left unchanged (and can be reused over multiple instances of the protocol) but now Bob computes *B* as a function of his choice bit *c*: if *c* = 0 Bob computes *B* = *g* *b* and if *c* = 1 Bob computes *B* = *Ag* *b*. At this point Alice derives two keys *k₀;k₁* from (*B*) *a* and (*B=A*) *a* respectively. It is easy to check that Bob can derive the key *kc*corresponding to his choice bit from *A* *b*, but cannot compute the other one. This can be seen as a *random* *OT* i.e., an OT where the sender has no input but instead receives two random messages from the protocol, which can be used later to encrypt his inputs, thus achieving the OT functionality.

A Secure and Ecient Implementation. We report on an ecient and secure implementation of the 1-out-of-2 random OT protocol: Our choice for the group is a twisted Edwards curve that has been used by Bernstein, Duif, Lange, Schwabe and Yang for building the Ed25519 signature scheme [BDL + 11]. The security of the curve comes from the fact that it is birationally equivalent to Bernstein’s Montgomery curve Curve25519 [Ber06] where ECDLP is believed to be hard: Bernstein and Lange’s SafeCurves website [BL14] reports cost of 2 125*:* 8 for solving ECDLP on Curve25519 using the *rho method*. The speed comes from the complete formulas for twisted Edwards curves proposed by Hisil, Wong, Carter, and Dawson in [HWCD08]. We rst modify the code in [BDL + 11] and build a fast implementation for a single OT. Later we build a vectorized implementation that runs OTs in batches. A comparison with the state of the art shows that our vectorized implementation is at least an order of magnitude faster than previous work (we compare in particular with the implementation reported by Asharov, Lindell, Schneider and Zohner in [ALSZ13]) on recent Intel microarchitectures. Furthermore, we take great care to make sure that our implementation is secure against both passive attacks (our software is *immune to timing attacks*, since the implementation is *constant-time*) and active attacks (by designing an appropriate encoding of group elements, which can be eciently veried and computed on). Our code can be downloaded from [http://orlandi.dk/simpleOT](http://orlandi.dk/simpleOT).

Organization. The rest of the paper is organized as follows: in Section 1 we discuss related work; in Section 2 we formally describe and analyse our protocol; Section 3 describes the chosen representation of group elements; Section 4 describes the low level building blocks of the group operations; and Section 5 reports the timings of our implementation.

Related Work. OT owes its name to Rabin [Rab81] (a similar concept was introduced earlier by Wies- ner [Wie83] under the name of \conjugate coding"). There are dierent avours of OT, and in this paper we focus on the most common and useful avour, namely *n* 1 -OT, which was rst introduced in [EGL85]. Many ecient protocols for OT have been proposed over the years. Some of the protocols which are most similar to ours are those of Bellare-Micali [BM89] and Naor-Pinkas [NP01]. More recent OT protocols such as [HL10, DNO08, PVW08] focus on achieving a strong level of security in concurrent settings¹ without re- lying on the random oracle model. Unfortunately this makes these protocols more cumbersome for practical applications: even the most ecient of these protocols i.e., the protocol of Peikert, Vaikuntanathan, and Waters [PVW08] requires 11 exponentiations for a single 2 1 -OT and a common random string (which must be generated by some trusted source of randomness at the beginning of the protocol).

OT Extension. While OT provably requires \public-key" type of assumptions [IR89] (such as factoring, discrete log, etc.), OT can be \extended" [Bea96] in the sense that it is enough to generate few \seed" OTs based on public-key cryptography which can then be extended to any number of OTs using symmetric-key primitives only (PRG, hash functions, etc.). This can be seen as the OT equivalent of *hybrid encryption* (where one encrypts a large amount of data using symmetric-key cryptography, and then encapsulates the symmetric-key using a public-key cryptosystem). OT extension can be performed very eciently both against passive [IKNP03,ALSZ13] and active [Nie07,NNOB12,Lar14,ALSZ15,KOS15] adversaries. Still, to bootstrap OT extension we need a secure and ecient OT protocol for the seed OTs (as much as we need secure and ecient public-key encryption schemes to bootstrap hybrid encryption): The OT extension of [ALSZ15] reports that it takes time (7 10 5 + 1*:* 3*m*)*s* to perform *m* OTs, where the xed term comes from running 190 base OTs. Using our protocol as the base OT in [ALSZ15] would reduce the initial cost to approximately

I.e., UC security [Can01], which is impossible to achieve without some kind of trusted setup assumptions [CF01].

190 114 2 10 4 *s* [Sch15], which leads to a signicant overall improvement (e.g., a factor 10 for up to 4 10 4 OTs and a factor 2 for up to 5 10 5 OTs).

1.1 Incorrect Security Claim in Proceeding Version The proceeding version of this work [CO15] claims that our protocol achieves UC security. The claim is incorrect, and has therefore been removed from this version. Li and Micciancio [LM18] showed that the protocol cannot be simulated in the equational framework, due to subtle timing attacks. Genc, Iovino and Rial [GIR17] pointed out a problem with the proof of security, noticing that the protocol cannot be proven secure under the CDH assumption.
2 This particular problem was later xed by Hauck and Loss using the GapDH assumption [HL17], who also proposed a dierent protocol based on the CDH assumption only. It was later pointed out by several authors (Byali, Patra, Ravi and Sarkar [BPRS17], Doerner, Kondi, Lee and shelat [DKLs18]), that the extraction strategy in the case of a corrupt receiver in the original proof of security is incompatible with composable security. In a nutshell, the issue is that a corrupt sender can \attack" the protocol by delaying decryption. Thus, the simulator cannot extract the input of the receiver before the protocol is over (and cannot use said inputs to simulate later protocol messages e.g., when combining our OT with garbled circuits). It appears that this problem can be circumvented if the next protocol message is from the receiver to the sender, and this message is a \proof of timely decryption" in the sense that the sender will check this \proof" and only accept if indeed the the receiver has performed the necessary decryption queries. This technique has been employed by Barreto, David, Dowsley, Morozov and Nascimento in [BDD + 17], where OT protocols in the random oracle from dierent assumptions are presented (their protocol contains an ad-hoc \proof of timely decryption") and in [DKLs18] (where our OT is combined with an OT extension protocol, which informally works as \proof of timely decryption"). See [CJS14] for a more thorough discussion of the issues arising in using random oracles in UC-proof of security, and for an OT protocol that can be proven secure in the \global" random oracle model.

## 2 The Protocol

Notation. If *S* is a set *s S* is a random element sampled from *S*. We work over an additive group (G*;B;p;* +) of prime order *p* (with log(*p*) *>* ) generated by *B* (the base point), and we use the additive notation for the group since we later implement our protocol using elliptic curves. Given the representation of some group element *P* we assume it is possible to eciently verify if *P 2* G. We use [*n*] as a shortcut for *f*0*;* 1*;:::;n* 1*g*.

Building Blocks. We use a hash-function *H* : (G G) G*!f*0*;* 1*g* as a key-derivation function to extract a bit key from a group element, and the rst two inputs are used to seed the function. 3 We model *H* as a random oracle when arguing about the security of our protocol.

Input/Outputs. We want to implement *m* *n* 1 -OT’s for *‘*-bit messages with-bit security between a sender *S* and a receiver *R*. The receiver *R* has a vector of indices (*c¹;:::;c* *m m*

|||) 2 [n]|, and the sender S has m|
|---|---|---|---|
|n i 1 i2[m]|n|‘|i|
||||ci|

vectors of message *f*(*M₀* *i* *;:::;M* *i* )*g* for all *i;j* : *Mij2f*0*;* 1*g* *‘*. At the end of the protocol the receiver *R* outputs a vector of *‘*-bit strings (*z¹;:::;z*), such that for all *i 2* [*m*], *z* = *Mi*.

2.1 Random OT We split the presentation in two parts: rst, we describe and analyze a protocol for *random OT* where the sender outputs *n* random keys and the receiver only learns one of them; then, we describe how to combine 2 See also [https://eprint.iacr.org/forum/read.php?18,962](https://eprint.iacr.org/forum/read.php?18,962). 3 Standard hash functions do not take group elements as inputs, and in later sections we will give explicit encodings of group elements into bitstrings.

this protocol with an appropriate encryption scheme to complete the OT. We are now ready to describe our novel *random OT* protocol:

Setup: (only once, independent of *m*):

1. *S* samples *y* Z*p*and computes *S* = *yB* and *T* = *yS*;
2. *S* sends *S* to *R*, who aborts if *S 62* G;
Choose: (in parallel for all *i 2* [*m*])

|i|i p||
|---|---|---|
|||i i|
|i|i||

1. *R* (with input *c 2* [*n*]) samples *x* Z and computes
*R* = *c S* + *x* *i* *B*

2. *R* sends *R* to *S*, who aborts if *R 62* G;
Key Derivation: (in parallel for all *i 2* [*m*])

1.For all *j 2* [*n*], *S* computes
*kji*= *H*(*S;Ri*)(*yR* *i* *jT*)

2. *R* computes
*kR* *i* = *H*(*S;Ri*)(*x* *i*

*S*)
Basic Properties. The key *kji*is computed by hashing *x* *i* *yB* + (*c* *i*

*j*)*T* and therefore at the end of the
protocol *kR* *i* = *k* *ci* *i*if both parties are honest. It is also easy to see that:

Lemma 1. *No (computationally unbounded) S on input R* *i* *can guess c* *i* *with probability greater than* 1*=n.*

*Proof.* *i i*

|Since B generates G, xed any P = x₀B the probability that R||||= P when c|= j is the probability|
|---|---|---|---|---|---|
|i|i|i|i|ji|ji|

that *x* *i* = (*x₀ c* *i*

*y*), therefore *8S;P 2* G*;j 2* [*n*], Pr[*R*
*i* = *P jc* *i* = *j*] = 1*=p*, which is independent of *j*.

Lemma 2. *No (computationally bounded) R can output any two keys k* 0 *and k* 1 *with j₀ 6*= *j₁ 2* [*n*] *if the* *computational Die-Hellman problem is hard in* G*.*

*Proof.* In the random oracle model *R* can only (except with negligible probability) compute *kji* 0 *;kji* 1 by querying the oracle on points of the form *U₀* *i* = (*yR* *i* *j₀T*) and *U₁* *i* = (*yR* *i* *j₁T*). Assume for the sake

|of contradiction that there exist a PPT R||||who outputs (R;j₀;j₁;U₀;U₁) R|||||(B;S) such that (j₁||
|---|---|---|---|---|---|---|---|---|---|---|
|1|||2||||||||
|||B|||||3|X|X X||
|Y Y|Y|||+|||||||
|||||0+ 1+|X|X|Y|Y|||
|||||0+ 1+|||||||
|||||3|||||||
|X|X|Y Y||0+ 1+||2|||p+1 2||

*j₀*) (*U₀ U₁*) = *T* = log (*S*) *B* with probability at least. We show an algorithm *A* which on input (*B;X* = *xB;Y* = *yB*) outputs *Z* = *xyB* with probability greater than. Run (*R;U₀;U₁*) *R* (*B;X*), (*R;U₀;U₁*) *R* (*B;Y*), then run (*R;U;U*) *R* (*B;X* + *Y*) and nally output

<u>(p + 1)</u> *Z* = (*U* + *U*) (*U₀* + *U₁*) (*U₀* + *U₁*) 2

Now *Z* = *xyB* with probability at least, since when all three executions of *R* are successful, then *U₀* + *U₁* = (*x²*)*B*, *U₀* + *U₁* = (*y²*)*B* and *U;U* = (*x* + *y*) *B* and therefore *Z* = 2*xyB* = *xyB*. *ut*

Note that the above proof loses a cubic factor. A better proof for this lemma, which only loses a quadratic factor, can be found in [BCP04].

From Random OT to *standard* OT. We start by adding a transfer phase to the protocol, where the sender sends the encryption of his messages to the receiver:

Transfer: (in parallel for all *i 2* [*m*])

1.For all *j 2* [*n*], *S* computes *e*
*ij* *E*(*kji;Mji*)

2. *S* sends (*e*
*i*

|1|||
|---|---|---|
||i|i ic|

0 *;:::;e* *in* 1 ) to *R*; Retrieve: (in parallel for all *i 2* [*m*])

1. *R* computes and outputs *z* = *D*(*k;ei*).

The protocol uses a symmetric encryption scheme (*E;D*). We call *K; M; C* the key space, message space and ciphertext space respectively and the security parameter. We allow the decryption algorithm to output a special symbol*?* to indicate an invalid ciphertext. We want to use an encryption scheme that satises the following properties:

Denition 1. *We say a symmetric encryption scheme* (*E;D*) *is* non-committing *if there exist PPT algo-* *rithms S₁; S₂ such that 8M 2M* (*e⁰;k⁰*) *and* (*e;k*) *are computationally indistinguishable where e⁰ S*1(1)*,* *k⁰ S*2(*e⁰;M*)*, k K and e E*(*k;M*) *(S₁; S₂ are allowed to share a state).*

The denition says that it is possible for a simulator to come up with a ciphertext *e* which can later be \explained" as an encryption of any message, in such a way that the joint distribution of the ciphertext and the key in this simulated experiment is indistinguishable from the normal use of the encryption scheme, where a key is rst sampled and then an encryption of *M* is generated.

Denition 2. *Let S be a set of random keys from K and VS;eS the subset of valid keys for a given* *ciphertext e i.e., the keys in S such that D*(*k;e*) *6*=*?.* *We say* (*E;D*) *satises* robustness *if for all ciphertexts e A* (1*;S*) *adversarially generated by a PPT* *A, jVS;ej* 1 *except with negligible probability.*

The denition says that it should be hard for an adversary to generate a ciphertext which can be decrypted to more than one valid ciphertext using any polynomial number of randomly generated keys (even for adversaries who see those keys before generating the ciphertext). Traditionally ciphertext integrity is dened for an adversary who has access to an encryption oracle, but the above denition suces for our goal.

A concrete example. We give a concrete example of a very simple scheme which satises Denition 1 and 2: let *M* = *f*0*;* 1*g* *‘* and *K* = *C* = *f*0*;* 1*g* *‘*+. The encryption algorithm *E*(*k;m*) parses *k* as (*;*) and *e* = (*m;*). The decryption algorithm *D*(*k;e*) parses *k* = (*;*) and *e* = (*e₁;e₂*) and outputs*?* if *e₂ 6*= or outputs *m* = *e₁* otherwise. It can be shown that:

Lemma 3. *The scheme* (*E;D*) *dened above satises Denition 1 and 2.*

*Proof.* We show that the scheme satises Denition 1 and 2 in a strong, information theoretic sense. For Denition 1: *S₁* outputs a random *e f* 0*;* 1*g* *‘*+; *S₂*(*e;M*) parses *e* = (*e₁;e₂*) and outputs *k* = (*e₁ M;e₂*). The simulated distribution is trivially identical to the real one. For Denition 2: given any ciphertext *e* = (*e₁;e₂*), *D*((*;*)*;e*) *6*=*?* implies that = *e₂*. Thus even an unbounded adversary can break robustness of the scheme only if there are two keys *ki;kj2 S* such that*i*=*j*which only happens with probability negligible in.

Non-Malleability in Practice. When instantiating our protocol we must replace the random oracle with a hash function. To approximate the model, one can \localize" the random oracle by prepending the parties *id*’s and the session *id* to the hash function. We argue here that our choice of using the transcript of the protocol (*S;R* *i* ) as salt for the hash function helps in making sure that the oracle is *local* to the protocol, and helps against malleability attacks in cases where the parties’ and session *id*’s are unavailable. Consider the following man-in-the middle attack, where an adversary *A* plays two copies of the *n* 1 -OT, one as the sender with *R* and one as the receiver with *S*. Here is how the attack works: 1) *A* receives *S* from *S* and forwards it to *R*; 2) Then the adversary receives *R* from *R* and sends *R⁰* = *S* + *R* to *S*; 3) Finally *A* receives the *feigi2*[*n*]from *S* and sets *e* *0i* = *e*(*i* 1 mod *n*)to *R*. It is easy to see that if the same hash function is used to instantiate the random oracle in the two protocols (and if *c 6*= 0), then the honest receiver outputs *z* = *Mc*+1, which is clearly a breach of security (i.e., this attack could not be run if the protocols are replaced with OT functionalities). The previous attack can be seen as a malleability attack on the choice bit. An adversary can also try a malleability attack on the sender messages by forwarding (*S⁰;R⁰*) = (*S;R*) but then manipulating the *ei*’s into ciphertexts *e* *0i* which decrypt to related messages. In the 2 -OT, these attacks can be mitigated by using

*authenticated encryption* for (*E;D*) (which also satises *robustness* as in Denition 2). Now an adversary who changes both ciphertext is equivalent to an ideal adversary using input (*?; ?*), while an adversary who only changes one ciphertext, say *ec*, is equivalent to an adversary which uses input bit 1 *c* on the left and inputs (*m₁c; ?*) on the right. This attack could also be run in an idealized world where parties have access to an OT functionality. Unfortunately for *n* 1 -OT (with *n >* 2) this is not the case, since the protocol allows to \copy" any subset of messages, which would not be possible in an idealized setting.

## 3 The Random OT Protocol in Practice

This section describes how the random OT protocol can be realized in practice. In particular, this section focuses on describing how group elements are represented as bitstrings, i.e., the *encodings*. In the abstract description of the random OT protocol, the sender and the receiver transmit and compute on \group ele- ments", but clearly any implementation of the protocol transmits and computes on bitstrings. We describe how the encodings are designed to achieve eciency (both for communication and computation) and security (particularly against a malicious party who might try to send malformed encodings).

The Group. The group G we choose for the protocol is a subset of G; G is dened by the set of points on the twisted Edwards curve

*f*(*x;y*) *2* F₂25519F₂25519: *x²* + *y²* = 1 + *dx²y²g*

### and the twisted Edwards addition law

<u>x₁y₂ + x₂y₁ y₁y₂ + x₁x₂</u> (*x₁;y₁*) + (*x₂;y₂*) =*;* 1 + *dx₁x₂y₁y₂* 1 *dx₁x₂y₁y₂*

introduced by Bernstein, Birkner, Joye, Lange, and Peters in [BBJ + 08]. The constant *d* and the generator *B* can be found in [BDL + 11]. The two groups G and G are isomorphic respectively to Z*p*Z₈ and Z*p*with *p* = 2 252 + 27742317777372353535851937790883648493.

Encoding of Group Element. An *encoding E* for a group G₀ is a way of representing group elements as xed-length bitstrings. We write *E*(*P*) for a bitstring which represents *P 2* G₀. Note that there can be multiple bitstrings that represent *P*; if there is only one bitstring for each group element, *E* is said to be *deterministic* (*E* is said to be *non-deterministic* otherwise⁴). Also note that some bitstrings (of the xed length) might not represent any group element; we write *E*(G₁) for the set of bitstrings which represent some element in G₁ G₀. *E* is said to be *veriable* if there exists an ecient algorithm that, given a bitstring as input, outputs whether it is in *E*(G₀) or not.

The Encoding *EX*for Group Operations. The non-deterministic encoding *EX*for G, which is based on the *extended coordinates* in [HWCD08], represents each point using the tuple (*X* : *Y* : *Z* : *T*) with *XY* = *ZT*, representing *x* = *X=Z* and *y* = *Y=Z*. We use *EX*whenever we need to perform group operations since given *EX*(*P*)*; EX*(*Q*) where *P;Q 2* G, it is ecient to compute *EX*(*P* + *P*), *EX*(*P* + *Q*), and *EX*(*P Q*). In particular, given an integer scalar *r 2* Z*p*it is ecient to compute *EX X*

||(rB), and given r and E||(P ) it is|
|---|---|---|---|
|X|X||X|

ecient to compute *E* (*rP*).

The Encoding *E₀* and Related Encodings. The deterministic encoding *E₀* for G represents each group element as a 256-bit bitstring: the natural 255-bit encoding of *y* followed by a sign bit which depends only on *x*. The way to recover the full value *x* is described in [BDL + 11, Section 5], and group membership can be veried eciently by checking whether *x²*(*y²* 1) = *dy²* + 1 holds; therefore *E₀* is veriable. See [BDL + 11] for more details of *E₀*. For the following discussions, we dene deterministic encodings *E₁* and *E₂* for G as

*E₁*(*P*) = *E₀*(8*P*)*; E₂*(*P*) = *E₀*(64*P*)*;P 2* G*:* 4 We stress that non-deterministic in this context does not mean that the encoding involves any randomness.

We also dene non-deterministic encodings *E*

(0) and *E*
(1) for G as
*E*

(0)
(*P*) = *E₀*(*P* + *t*)*; E*
(1)
(*P*) = *E₀*(8*P* + *t⁰*)*;P 2* G*;*
where *t;t⁰* can be any 8-torsion point. Note that each element in G has exactly 8 representations under *E*

(0)
and *E*

(1).
Point Compression/Decompression. It is ecient to convert from *EX*(*P*) to *E₀*(*P*) and back; since *E₀* represents points as much shorter bitstrings, these operations are called *point compression* and *point* *decompression*, respectively. Roughly speaking, point compression outputs *y* = *Y=Z* along with the sign bit of *x* = *X=Z*, and point decompression rst recovers *x* and then outputs *X* = *x;Y* = *y;Z* = 1*;T* = *xy*. We always check for group membership during point decompression. We use *E₀* for data transmission: the parties send bitstrings in *E₀*(G) and expect to receive bitstrings in *E₀*(G). This means a computed point encoded by *EX*has to be compressed before it is sent, and a received bitstring has to be decompressed for subsequent group operations. Sending compressed points helps to reduce the communication complexity: the parties only need to transfer 32 + 32*m* bytes in total.

Secure Data Transmission. At the beginning of the protocol *S* computes and sends *E₀*(*S*). In the ideal case, *R* should receive a bitstring in *E₀*(G) which he interprets as *E₀*(*S*). However, an attacker (a corrupted *S* or a man-in-the-middle) can send *R* 1) a bitstring that is not in *E₀*(G) or 2) a bitstring in *E₀*(G *n* G). In the rst case, *R* detects that the received bitstring is not valid during point decompression and ignores it. In the second case, *R* can check group membership by computing the *p*th multiple of the point, but a more ecient way is to use a new encoding *E⁰* such that each bitstrings in *E₀*(G) represents a point in G under *E⁰*. Therefore *R* considers the received bitstring as *E*

(0)
(*S*) = *E₀*(*S* + *t*), where *t* can be any 8-torsion point.
The encoding *E*

(0) (along with point decompression) makes sure that *R* receives bitstrings representing
elements in G. However, an attacker can derive *c* *i* by exploiting the extra information given by a nonzero *t*: a naive *R* would compute and send *E₀*(*c* *i* (*S* + *t*) + *x* *i*

*B*) = *E₀*(*c* *i* *t* + *R*
*i* ); now by testing whether the result is *E₀*(G) the attacker learns whether *c* *i* = 0. To get rid of the 8-torsion point, *R* can multiply received point by 8 1

|||||(8|mod p), but a more ecient|||
|---|---|---|---|---|---|---|---|
|i i|X S;R|X (1) i|i i|i X i|i i|i X|i|
|X||X||||||
||||||||i|

way is to just multiply by 8 and then operate on *E* (8*S*) and *E* (8*x* *i*

*B*) to obtain and send *E₁*(*R*
*i* ) = *E₀*(8*R* *i* ),

i.e, the encoding switches to *E₁* for *R*. After this *S* works similarly as *R*: to ensure that the received bitstring represents an element in G, *S* interprets the bitstring as *E* (*R*) = *E₀*(8*R* + *t*); to get rid of the 8-torsion point *S* also multiplies the received point by 8, and then *S* operates on *E* (64*R*) and *E* (64*T*) to obtain *EX*(64(*yR* *i*
*jT*)).

Key Derivation. The protocol computes *H i* (*P*) where *P* can be *x S;yR;* or *yR jT* for *j 2* [*n*]. This is implemented by hashing *E₁*(*S*)*kE₂*(*R*)*kE₂*(*P*) with Keccak [BDPVA09] with 256-bit output. The choice of encodings is natural: *S* computes *E* (*S*), and *R* computes *E* (8*S*); since multiplication by 8 is much cheaper than multiplication by (8 1 mod *p*), we use *E₁*(*S*) = *E₀*(8*S*) for hashing. For similar reasons we use *E₂* for *R* and *P*.

Actual Operations. For completeness, we present in Table 1 a full overview of operations performed during the protocol for the case of 1 out of 2 OT (i.e., *n* = 2).

## 4 Field Arithmetic

This section describes our implementation strategy for arithmetic operations in F₂25519, which serve as low-level building blocks for operations on the curve. Field operations are decomposed into double-precision oating-point operations using our strategy. A straightforward way for implementation is then using double- precision oating-point instructions. However, a better way to utilize the 64 64*!* 128-bit serial multiplier is to decompose eld operations into integer instructions as [BDL + 11] does. The real reason we decide to use oating-point operations is that it allows us to use 256-bit vector instructions on the target microarchi- tectures, which are functionally equivalent to 4 double-precision oating-point instructions. The technique,

|S||R|
|---|---|---|
|Output Input Operations||Output Input Operations|
|S y y B (0) S C (S) E (S) 8 S S 8 S E₁ (S) 8 S C (8 S) 64 T 8 y; 8 S 8 (y 8 S)||(0) (0) 8 S E (S) 8 D (E (S)) E₁ (S) 8 S C (8 S)|
|i (1) i (1) i 64 R E (R) 8 D (E (R) i i i E₂ (R) 64 R C (64 R) i i i 64 yR y; 64 R y 64 R i i i E₂ (yR) 64 yR C (64 yR) i i i 64(yR T) 64 T; 64 yR 64 yR 64 T i i i E₂ (yR T) 64(yR T) C (64(yR T))||i i i 8 x B 8 x 8 x B i i i 8 x B + 8 S 8 S; 8 x B 8 x B + 8 S i i (1) i 8 R C (8 R) E (R) i i i E₂ (R) 8 R C (8 8 R) i i i 64 x S 8 x; 8 S 8 x 8 S i i i E₂ (x S) 64 x S C (64 x S)|

Table 1. How the parties compute encodings of group elements: each row shows that the \Output" is computed

given \Input" using the operations \Operations". The input might come from the output of a previous row, a received string (e.g., *E*

(1) (*R* *i* )), or a random scalar that the party generates (e.g., 8*x*
*i* ). The upper half of the table are the operations that does not depend on *i*, which means the operations are performed only once for the whole protocol. *E* *X* is suppressed: group elements written without encoding are actually encoded by *EX*. *C* and *D* stand for point compression and point decompression respectively. Computation of the *r*th multiple of *P* is denoted as \*r P*". In particular, 8 *P* can be carried out with only 3 point doublings.

which is called *vectorization*, makes our vectorized implementation achieve much higher throughtput than our non-vectorized implementation based on [BDL + 11].

Representation of Field Elements. P Each eld element *x 2* F₂25519is represented as 12 *limbs* (*x₀;x₁;:::;x₁₁*) such that *x* = *xi*and *xi=*2 *d*21*:* 25*ie* *2* Z. Each *xi*is stored as a double-precision oating-point number. Field operations are then carried out by limb operations such as oating-point additions and multiplications.

When a eld element gets initialized (e.g., when obtained from a table lookup), each *xi*uses no more than 21 bits of the 53-bit mantissa. However, after a series of limb operations, the number of bits *xi*takes can grow. It is thus necessary to reduce the number of bits (in the mantissa) with carries before any precision is lost; see below for more discussions.

Field Arithmetic. Additions and subtractions of eld elements are implemented in a straightforward way: simply adding/subtracting the corresponding limbs. This does increase the number of bits in the mantissa, but in our application it suces to reduce bits only at the end of the multiplication function.

A eld multiplication is divided into two steps. The rst step is a schoolbook multiplication on the 2 12 input limbs, with reduction modulo 2 255 19 to bring the result back to 12 limbs. The schoolbook multipli- cation takes 132 oating-point additions, 144 oating-point multiplications, and a few more multiplications by constants to handle the reduction.

Let (*c₀;c₁;:::;c₁₁*) be the result after schoolbook multiplication. The second step is to perform carries to reduce number of bits in *ci*. Carry from *ci*to *ci*+1(indices work modulo 12), which we denote as *ci! ci*+1, is performed with 4 oating-point operations: *c ci*+*i*; *c ci*; *cicic*; *ci*+1*ci*+1+*c:* The idea is to use*i* *k* *i*

|= 3 2 where k|is big enough so that the less signicant part of c||||are discarded in c|+,|
|---|---|---|---|---|---|---|
|k|i||||i|i i|
||||i||||
|255|||||||

*i i i i* forcing *c* to contain only the more signicant part of *c*. For *i* = 11, one extra multiplication is required to scale *c* by 19 2 before it is added to *c₀*.

A straightforward way to reduce number of bits in all limbs is to use the carry chain *c₀! c₁! c₂!!* *c₁₁! c₀! c₁:* The problem with the straightforward carry chain is that there is not enough instruction level parallelism to hide the 3-cycle latencies (see discussion below). To hide the latencies we thus interleave

instruction latency throughput description

|vandpd|1|1|bitwise and|
|---|---|---|---|
|vorpd|1|1|bitwise or|
|vxorpd|1|1 (4)|bitwise xor|
|vaddpd|3|1|4-way parallel double-precision oating-point additions|
|vsubpd|3|1|4-way parallel double-precision oating-point subtractions|
|vmulpd|5|1|4-way parallel double-precision oating-point multiplications|

Table 2. 256-bit vector instructions used in our implementation. Note that vxorpd has throughput of 4 when it has

only one source operand.

### the following 3 carry chains:

*c₀! c₁! c₂! c₃! c₄! c₅;* *c₄! c₅! c₆! c₇! c₈! c₉;* *c₈! c₉! c₁₀! c₁₁! c₀! c₁:*

In total the multiplication function takes 192 oating-point additions/subtractions and 156 oating-point multiplications. When the input operands are the same, many limb products will repeat in the schoolbook multiplication; a eld squaring is therefore cheaper than a eld multiplication. In total the squaring function takes 126 oating-point additions/subtractions and 101 oating-point multiplications. Field inversion is implemented as a x sequence of eld squarings and multiplications.

Vectorization. We decompose eld operations into 64-bit oating-point and logical operations. The Intel Sandy Bridge and Ivy Bridge microarchitectures, as well as many recent microarchitectures, oer instructions that operate on 256-bit registers. Some of these instructions treat the registers as vectors of 4 double-precision oating-point numbers and perform 4 oating-point operations in parallel; there are also 256-bit logical instructions that can be viewed as 4 64-bit logical instructions. We thus use these instructions to run 4 scalar multiplications in parallel. Table 2 shows the instructions we use, along with their latencies and throughputs on the Sandy Bridge and Ivy Bridge given in Fog’s well-known survey [Fog14].

## 5 Implementation Results

This section compares the speed of our implementation of 2 1 -OT (i.e., *n* = 2) with other similar imple- mentations. We stress that our software is a constant-time one: timing attacks are avoided using the same high-level strategy as [BDL + 11]. To show that our speeds for curve operations are competitive, we modify the software to support the function of Die-Hellman key exchange and compare the results with existing Curve25519 implementations (our implementation performs scalar multiplications on the twisted Edwards curve, so it is not the same as Curve25519). The experiments are carried out on two machines on the eBACS site for publicly veriable benchmarks [BL15]: h6sandy (Sandy Bridge) and h9ivy (Ivy Bridge). Since our protocol can serve as the base OTs for an OT extension protocol, we also compare our speed with a base OT implementation presented in [ALSZ13], which is included in the Scapi multi-party computation library; the experiments are made on an Intel Core i7-3537U processor (Ivy Bridge) where each party runs on one core. Note that all experiments are performed with Turbo Boost disabled.

Comparing with Curve25519 Implementations. Table 3 compares our work with existing Curve25519 implementations. \Cycles to generate a public key" indicates the time to generate the public key given a secret key; the Curve25519 implementation is the implementation by Andrew Moon [MF15]. \Cycles to compute a shared secret" indicates the time to generate the shared secret, given a secret key and a public key; the Curve25519 implementation is from [BDL + 11]. Note that since our software runs 4 scalar multiplications

|||||||h6sandy|h9ivy|||
|---|---|---|---|---|---|---|---|---|---|
|[MF15] Average cycles to compute a public key +||||||61828|57612|||
|[BDL 11] Average cycles to compute a shared secret||||||194036 182708||||
|this work Average cycles to generate a public key||||||61458|60853|||
|Average cycles to compute a shared secret Table 3. DH speeds of our work and existing Curve25519 implementations.||||||182169 180343||||
|m|4|8|16|32|64|128|256|512|1024|
|this work Running time of|S 548|381|321|279|265|257|246|237|228|
|Running time of|R 472|366|279|229|205|200|193|184|177|
|[ALSZ13] Running time of|S 17976|10235|6132|4358|3348|2877|2650|2528|2473|
|Running time of|R 16968|9261|5188|3415|3382|2909|2656|2541|2462|

Table 4. Timings for per OT in kilocycles. Multiplying the number of kilocycles by 0*:* 5 one can obtain the running

time (in *s*) on our test architecture.

in parallel, the numbers in the table are the time for generating 4 public keys or 4 shared secrets divided by

4. In other words, our implementation is optimized for *througput* instead of *latency*. Comparing with Scapi. Table 4 shows the timings of our implementation for the random OT protocol, along with the timings of a base-OT implementation presented in [ALSZ13]. The paper presents several base-OT implementations; the one we compare with is Miracl-based with \long-term security" using random oracle (cf. [ALSZ13, Section 6.1]). The implementation uses the NIST K-283 curve and SHA-1 for hashing, and it is not a constant-time implementation. It turns out that our work is an order of magnitude faster for *m 2f*4*;* 8*;:::;* 1024*g*. Memory consumption. Our code for public-key generation uses a 284-KB table. For shared-secret com- putation the table size is 12 KB. For OTs, *S* uses a 12-KB table, while *R* is *allowed* to use a table of size up to 1344 KB which depends on the parameters given. The current code provides 4 copies of the precomputed points, one for each of the 4 scalar multiplcations, so it is possible to reduce the table sizes by a factor of 4 by broadcasting the precomputed points. Another reason that we have large tables is because of the representation for eld elements: each limbs takes 8 bytes, so each eld element already takes 12 8 = 96 bytes. The window sizes we use are the same as [BDL
+ 11]. See [BDL + 11] for issues related to table sizes.

Acknowledgments. We are very grateful to: Daniel J. Bernstein and Tanja Lange for invaluable comments and suggestions regarding elliptic curve cryptography and for editorial feedback on earlier versions of this paper; Yehuda Lindell for useful comments on our proof of security; Peter Schwabe for various helps on im- plementation, including providing low-level code for eld arithmetic; the anonymous LATINCRYPT reviewer and in particular Gregory Neven. Tung Chou is supported by Netherlands Organisation for Scientic Research (NWO) under grant 639.073.005. Claudio Orlandi is supported by: the Danish National Research Foundation and The National Science Foun- dation of China (grant 61361136003) for the Sino-Danish Center for the Theory of Interactive Computation; the Center for Research in Foundations of Electronic Markets (CFEM); the European Union Seventh Frame- work Programme ([FP7/2007-2013]) under grant agreement number ICT-609611 (PRACTICE).

## References

ALSZ13.Gilad Asharov, Yehuda Lindell, Thomas Schneider, and Michael Zohner. More ecient oblivious transfer and extensions for faster secure computation. In *Proceedings of the 2013 ACM SIGSAC conference on* *Computer communications security*, pages 535{548. ACM, 2013. ALSZ15.Gilad Asharov, Yehuda Lindell, Thomas Schneider, and Michael Zohner. More ecient oblivious transfer extensions with security for malicious adversaries. Cryptology ePrint Archive, Report 2015/061, 2015. [http://eprint.iacr.org/](http://eprint.iacr.org/). BBJ +

08.Daniel J Bernstein, Peter Birkner, Marc Joye, Tanja Lange, and Christiane Peters. Twisted edwards curves. In *Progress in Cryptology{AFRICACRYPT 2008*, pages 389{405. Springer, 2008.
BCP04.Emmanuel Bresson, Olivier Chevassut, and David Pointcheval. New security results on encrypted key exchange. In *Public Key Cryptography-PKC 2004, 7th International Workshop on Theory and Practice* *in Public Key Cryptography, Singapore, March 1-4, 2004*, pages 145{158, 2004. BDD +

17.Paulo S. L. M. Barreto, Bernardo David, Rafael Dowsley, Kirill Morozov, and Anderson C. A. Nascimento. A framework for ecient adaptively secure composable oblivious transfer in the rom. Cryptology ePrint Archive, Report 2017/993, 2017. [https://eprint.iacr.org/2017/993](https://eprint.iacr.org/2017/993), Version 21 December 2017.
BDL +

11.Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe, and Bo-Yin Yang. High-speed high-security signatures. In *Cryptographic Hardware and Embedded Systems { CHES 2011*, volume 6917 of *Lecture* *Notes in Computer Science*, pages 124{142. Springer-Verlag Berlin Heidelberg, 2011.
BDPVA09.Guido Bertoni, Joan Daemen, Michael Peeters, and Gilles Van Assche. Keccak sponge function family main document. *Submission to NIST (Round 2)*, 3:30, 2009. Bea96.Donald Beaver. Correlated pseudorandomness and the complexity of private computations. In *Proceedings* *of the Twenty-Eighth Annual ACM Symposium on the Theory of Computing, Philadelphia, Pennsylvania,* *USA, May 22-24, 1996*, pages 479{488, 1996. Ber06.Daniel J Bernstein. Curve25519: new Die-Hellman speed records. In *Public Key Cryptography-PKC* *2006*, pages 207{228. Springer, 2006. BL14.Daniel J. Bernstein and Tanja Lange. Safecurves: choosing safe curves for elliptic-curve cryptography, accessed 1 December 2014. [http://safecurves.cr.yp.to](http://safecurves.cr.yp.to). BL15.Daniel J Bernstein and Tanja Lange. eBACS: Ecrypt benchmarking of cryptographic systems, accessed 16 March 2015. [http://bench.cr.yp.to](http://bench.cr.yp.to). BLN +

15.Sai Sheshank Burra, Enrique Larraia, Jesper Buus Nielsen, Peter Sebastian Nordholt, Claudio Orlandi, Emmanuela Orsini, Peter Scholl, and Nigel P. Smart. High performance multi-party computation for binary circuits based on oblivious transfer. Cryptology ePrint Archive, Report 2015/472, 2015. http: //eprint.iacr.org/.
BM89.Mihir Bellare and Silvio Micali. Non-interactive oblivious transfer and spplications. In *Advances in* *Cryptology-CRYPTO ’89, 9th Annual International Cryptology Conference, Santa Barbara, California,* *USA, August 20-24, 1989, Proceedings*, pages 547{557, 1989. BPRS17.Megha Byali, Arpita Patra, Divya Ravi, and Pratik Sarkar. Fast and universally-composable oblivious transfer and commitment scheme with adaptive security. Cryptology ePrint Archive, Report 2017/1165,

2017. [https://eprint.iacr.org/2017/1165](https://eprint.iacr.org/2017/1165), Version 21 Mar 2018.
Can01.Ran Canetti. Universally composable security: A new paradigm for cryptographic protocols. In *42nd* *Annual Symposium on Foundations of Computer Science, FOCS 2001, 14-17 October 2001, Las Vegas,* *Nevada, USA*, pages 136{145, 2001. CF01.Ran Canetti and Marc Fischlin. Universally composable commitments. *IACR Cryptology ePrint Archive*, 2001:55, 2001. CJS14.Ran Canetti, Abhishek Jain, and Alessandra Scafuro. Practical UC security with a global random oracle. In *Proceedings of the 2014 ACM SIGSAC Conference on Computer and Communications Security,* *Scottsdale, AZ, USA, November 3-7, 2014*, pages 597{608, 2014. CO15.Tung Chou and Claudio Orlandi. The simplest protocol for oblivious transfer. In *Progress in Cryptology*

*- LATINCRYPT 2015 - 4th International Conference on Cryptology and Information Security in Latin* *America, Guadalajara, Mexico, August 23-26, 2015, Proceedings*, pages 40{58, 2015.
DKLs18.Jack Doerner, Yashvanth Kondi, Eysa Lee, and shelat abhi. Secure two-party threshold ecdsa from ecdsa assumptions. IEEE Security and Privacy Symposium, Cryptology ePrint Archive, Report 2018/499, 2018. [https://eprint.iacr.org/2018/499](https://eprint.iacr.org/2018/499), Version 23 May 2018. DNO08.Ivan Damgard, Jesper Buus Nielsen, and Claudio Orlandi. Essentially optimal universally composable oblivious transfer. In *Information Security and Cryptology-ICISC 2008, 11th International Conference,* *Seoul, Korea, December 3-5, 2008, Revised Selected Papers*, pages 318{335, 2008.

EGL85.Shimon Even, Oded Goldreich, and Abraham Lempel. A randomized protocol for signing contracts. *Commun. ACM*, 28(6):637{647, 1985. Fog14.Agner Fog. Instruction tables. 2014. [http://www.agner.org/optimize/instruction_tables.pdf](http://www.agner.org/optimize/instruction_tables.pdf). GIR17.Ziya Alper Genc, Vincenzo Iovino, and Alfredo Rial. "the simplest protocol for oblivious transfer" revisited. Cryptology ePrint Archive, Report 2017/370, 2017. [https://eprint.iacr.org/2017/370](https://eprint.iacr.org/2017/370), Version 24 May 2017. HL10.Carmit Hazay and Yehuda Lindell. *Ecient Secure Two-Party Protocols-Techniques and Constructions*. Information Security and Cryptography. Springer, 2010. HL17.Eduard Hauck and Julian Loss. Ecient and universally composable protocols for oblivious transfer from the cdh assumption. Cryptology ePrint Archive, Report 2017/1011, 2017. [https://eprint.iacr.org/](https://eprint.iacr.org/) 2017/1011, Version 24 October 2017. HWCD08.Huseyin Hisil, Kenneth Koon-Ho Wong, Gary Carter, and Ed Dawson. Twisted Edwards curves revisited. In *Advances in Cryptology-ASIACRYPT 2008*, pages 326{343. Springer, 2008. IKNP03.Yuval Ishai, Joe Kilian, Kobbi Nissim, and Erez Petrank. Extending oblivious transfers eciently. In *Ad-* *vances in Cryptology-CRYPTO 2003, 23rd Annual International Cryptology Conference, Santa Barbara,* *California, USA, August 17-21, 2003, Proceedings*, pages 145{161, 2003. IR89.Russell Impagliazzo and Steven Rudich. Limits on the provable consequences of one-way permutations. In *Proceedings of the 21st Annual ACM Symposium on Theory of Computing, May 14-17, 1989, Seattle,* *Washigton, USA*, pages 44{61, 1989. Kil88.Joe Kilian. Founding cryptography on oblivious transfer. In *Proceedings of the 20th Annual ACM* *Symposium on Theory of Computing, May 2-4, 1988, Chicago, Illinois, USA*, pages 20{31, 1988. KOS15.Marcel Keller, Emmanuela Orsini, and Peter Scholl. Actively secure ot extension with optimal overhead. CRYPTO, 2015. Lar14.Enrique Larraia. Extending oblivious transfer eciently, or-how to get active security with constant cryptographic overhead. *IACR Cryptology ePrint Archive*, 2014:692, 2014. LM18.Baiyu Li and Daniele Micciancio. Equational security proofs of oblivious transfer protocols. In *Public-Key* *Cryptography-PKC 2018 - 21st IACR International Conference on Practice and Theory of Public-Key* *Cryptography, Rio de Janeiro, Brazil, March 25-29, 2018, Proceedings, Part I*, pages 527{553, 2018. MF15.Andrew Moon \Floodyberry". Implementations of a fast elliptic-curve digital signature algorithm, ac- cessed 16 March 2015. [https://github.com/floodyberry/ed25519-donna](https://github.com/floodyberry/ed25519-donna). Nie07.Jesper Buus Nielsen. Extending oblivious transfers eciently-how to get robustness almost for free. Cryptology ePrint Archive, Report 2007/215, 2007. [http://eprint.iacr.org/](http://eprint.iacr.org/). NNOB12.Jesper Buus Nielsen, Peter Sebastian Nordholt, Claudio Orlandi, and Sai Sheshank Burra. A new ap- proach to practical active-secure two-party computation. In *Advances in Cryptology-CRYPTO 2012 -* *32nd Annual Cryptology Conference, Santa Barbara, CA, USA, August 19-23, 2012. Proceedings*, pages 681{700, 2012. NP01.Moni Naor and Benny Pinkas. Ecient oblivious transfer protocols. In *Proceedings of the Twelfth Annual* *Symposium on Discrete Algorithms, January 7-9, 2001, Washington, DC, USA.*, pages 448{457, 2001. PVW08.Chris Peikert, Vinod Vaikuntanathan, and Brent Waters. A framework for ecient and composable oblivious transfer. In *Advances in Cryptology-CRYPTO 2008, 28th Annual International Cryptology* *Conference, Santa Barbara, CA, USA, August 17-21, 2008. Proceedings*, pages 554{571, 2008. Rab81.Michael O. Rabin. How to exchange secrets with oblivious transfer. *Technical Report TR-81, Aiken* *Computation Lab, Harvard University*, 1981. Sch15.Thomas Schneider. Personal communication, 2015. Wie83.Stephen Wiesner. Conjugate coding. *SIGACT News*, 15(1):78{88, January 1983.
