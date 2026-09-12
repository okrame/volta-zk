# A Fast and Simple Partially Oblivious PRF, with Applications

## Nirvan Tyagi Sofa Celi Thomas Ristenpart Nick Sullivan Cornell University Cloudare Cornell Tech Cloudare

## Stefano Tessaro Christopher A. Wood University of Washington Cloudare

Abstract

We build the rst construction of a partially oblivious pseudorandom function (POPRF) that does not rely on bilinear pairings. Our construction can be viewed as combining elements of the 2HashDH OPRF of Jarecki, Kiayias, and Krawczyk with the Dodis-Yampolskiy PRF. We analyze our POPRF’s security in the random oracle model via reduction to a new one-more gap strong Die-Hellman inversion assumption. The most signicant technical challenge is establishing condence in the new assumption, which requires new proof techniques that enable us to show that its hardness is implied by the *q*-DL assumption in the algebraic group model. Our new construction is as fast as the current, standards-track OPRF 2HashDH protocol, yet provides a new degree of exibility useful in a variety of applications. We show how POPRFs can be used to prevent token hoarding attacks against Privacy Pass, reduce key management complexity in the OPAQUE password authenticated key exchange protocol, and ensure stronger security for password breach alerting services.

# Contents

1 Introduction 3

2 Preliminaries 6

2.1 Algebraic Group Model.................... .. .. .. .. .. .. .. .. .. .6
2.2 Random Oracle Model................................... .. .. .6
2.3 Non-interactive Zero Knowledge Proofs...... ....................... .7
3 Partially Oblivious Pseudorandom Functions8

4 The 3HashSDHI POPRF12

5 Security Analysis 14

5.1 Pseudorandomness.. ........................................14
5.2 Request Privacy. ..........................................19
6 Performance Evaluation21

7 Applications 21

7.1 Privacy Pass................ .. .. .. .. .. .. .. .. .. .. ...... .. .22
7.2 Private Set Membership and Breach Alerting...........................23
7.3 OPAQUE.................................. .. .. .. .. .....23
A Security of (*m;n*)-OM-Gap-SDHI 27

A.1 Simulation of (*m;n*)-OM-Gap-SDHI environment.... ....................27
A.2 Linear independence of winning elements.............................28
B Security Proofs for 3H 35

C Security with Restricted Tag Space37

D Security of 2HashDH OPRF38

E (Partially) Blind Signatures Preliminaries40

E.1 Syntax and Semantics. .......................................41
E.2 Security. ................. .. .. .. .. .. .. .. .. .. .. .. .. .. .. ..41
F (P)OPRFs from Unique (Partially) Blind Signatures42

G Security of ZSS Partially Blind Signature43

H Uniqueness from Request Privacy47

I Multiplicative Blinding48

# 1 Introduction

An oblivious pseudorandom function (OPRF) [FIPR05,JL09] allows a client holding a private input *x* and a server holding a key *sk* for a PRF *f* to engage in a protocol to *obliviously* evaluate *fsk*on *x*. The client learns (and optionally veries) the evaluation *fsk*(*x*) while the server learns nothing. *Partially-*oblivious PRFs (POPRF), rst introduced by Everspaugh et al. in the context of the Pythia password hardening system [ECS + 15], extend this functionality to include a public input (or metadata tag) *t* for the PRF evaluation. A client learns (and, optionally, veries) *fsk*(*t;x*) where *t* is known by both server and client; the private input *x* remains hidden. OPRFs are increasingly becoming a critical cryptographic tool for privacy-preserving protocols. Examples include one-time use anonymous credentials for spam prevention [DGS + 18,HIJ + 21], private set intersection (PSI) for checking compromised credentials [LPA + 19,TPY + 19], de-identied authenticated logging [HIJ + 21], and password-authenticated key exchange [JKX18,JKK14]. In all these applications, we observe that there is a need to \partition" the PRF in a productive manner, i.e., allowing computation of *fsk*(*t;x*) using domain separation on some public value *t*. OPRF blinding protocols do not support this in a secure manner, because the server cannot verify what *t* is used within a client’s oblivious request. Most OPRF applications therefore use a separate key instance for each *t*, with an associated increase in key management complexity. POPRFs directly provide this functionality, but the only known POPRF [ECS + 15] relies on bilinear pairings, which slows performance relative to the best known OPRF and also complicates deployment given the lack of widespread implementation support for pairings. In this work, we introduce a new POPRF that combines aspects of the 2HashDH OPRF of Jarecki et al. [JKK14], that is the de facto standard used in practice, with the Dodis-Yampolskiy (DY) veriable random function [DY05]. Our POPRF is also closely related to a signature scheme suggested by Zhang, Safavi- Naini, and Susilo (ZSS) [ZSS04,ZSS03]. Our new POPRF, called 3HashSDHI, is essentially as performant as 2HashDH and does not rely on pairings, thereby enabling support for a public input virtually *for free*. While 3HashSDHI’s protocol is simple, its analysis is not, requiring a new interactive discrete log (DL) assumption whose security we reduce to *q*-DL in the algebraic group model [FKL18]. We also provide new formal security notions for POPRFs and (as a special case) OPRFs, which we believe will be of independent interest.

Formal syntax and security notions for POPRFs. We start with the latter contribution. We provide a new formalization for POPRFs, including syntax, semantics, and security denitions. Our formal syntax builds o of [ECS + 15] and previous OPRF formalizations [JL09,JKK14]. In terms of security, we propose new property-based security denitions that cover pseudorandomness (in the face of malicious clients) as well as request privacy and veriability (in the face of malicious servers). Our property-based security games avoid the ideal function based formulations inherited from 2PC and used in prior works on OPRFs; they also avoid the non-standard \one-more" PRF security denition of [ECS + 15]. Our *pseudorandomness* notion for POPRFs guarantees that the evaluation outputs look random to a malicious client, even when the malicious client has access to a blinded evaluation oracle. It is formalized with a simulation-based indistinguishability game that takes rough inspiration from the UC-style all-in- one OPRF security denition of [JKK14] and prior notions for partially blind signatures [AF96]. Here an adversary must distinguish between real evaluations of the PRF given access to a blind evaluation oracle, and evaluations of a random function given access to a simulated blind evaluation oracle. The simulator can receive random function evaluations on a limited number of points for any given public input *t*, where the limit is determined by the number of times the adversary has queried the blind evaluation oracle for that *t*. This restriction captures that only one random function evaluation is learned for each blind evaluation. Note that our accounting is more granular than the general \ticketing" approaches of blind UC protocols [JKK14, KZ08,Fis06]), due to the need of tying invocations to particular *t* values. Our next notion is *request privacy* which captures that nothing about a client message *x* should leak to a malicious server during an oblivious evaluation, and, moreover, the server should not be able to link an output *fsk*(*t;x*) to particular oblivious request transcripts. The latter is often referred to as a linking attack, and is problematic in various applications of POPRFs. Our request privacy notion comes in two avors, depending on whether the malicious server behaves passively or actively. The former allows us to analyze the privacy of schemes that do not allow verication that a server legitimately computed the blinded evaluation protocol; the latter requires schemes to allow client-side verication of the server’s response. Finally we formalize a notion of *uniqueness*. It ensures that a malicious server cannot trick clients into

accepting inconsistent evaluations, relative to a shareable public key associated to the secret key *sk*.

The 3HashSDHI construction. The main contribution of this work is a new construction of a POPRF, which we call 3HashSDHI. The name refers to its use of three hashes and its reliance on the strong Die- Hellman inversion assumption. Its starting point is the 2HashDH construction of Jarecki et al. [JKK14], whose full PRF evaluation we dene as 2HashDH*:* Ev(*sk;x*) = H₂(*x;* H₁(*x*) *sk* ). The blinded evaluation protocol has the client send *B* = H₁(*x*) *r* for random *r*, and the server respond with *B⁰* = *B* *sk*. The client can unblind to (*B⁰*) 1*=r* = H₁(*x*) *sk* in order to complete the evaluation of the function. Here operations are over a prime- order group (written multiplicatively) such as an elliptic curve. Proof of evaluation consists of a simple

|||sk|
|---|---|---|
|g|B +|+|

Chaum-Pedersen proof of discrete log equality [CP92] proving log *pk* = log *B⁰* where *pk* = *g* is the server’s public key. As mentioned, 2HashDH is already in use in practice [DGS 18,TPY + 19,HIJ 21] and is on track to become a standard [DFHSW20]. We want a way to extend 2HashDH to allow public tags. To do so, we take inspiration from the Dodis- Yampolskiy PRF, whose evaluation is dened as DY*:* Ev(*sk;t*) = *g¹* *=*(*sk*+*t*). Put together, the 3HashSDHI scheme gives a PRF evaluated as:

3H*:* Ev(*sk;t;x*) = H₂ *t;x;* H₁(*x*) 1*=*(*sk*+H3 (*t*)) *:*

It can therefore be interpreted as evaluating the Dodis-Yampolskiy PRF on the public input *t* over a random generator determined by the private input *x*, followed by a nal hashing step. The basic structure of H₁(*x*) 1*=*(*sk*+H3 (*t*)) was also described in an attempt to build secure partially blind signatures by ZSS [ZSS03]. Their analysis is incorrect, as we discuss further below and in Section4. To perform a blind evaluation, the client hashes and blinds their private input as *B* = H₁(*x*) *r* using a random scalar *r* and sends *B* to the server holding *sk*. The server computes and sends back to the client the strong Die-Hellman inversion *B⁰* = *B¹* *=*(*sk*+H3 (*t*)) of the blinded element using the secret key and public hash of the public input *t*. The client can unblind by computing (*B⁰*) 1*=r* = H₁(*x*) 1*=*(*sk*+H3 (*t*)) and then complete the evaluation by hashing appropriately. To provide veriability, the server uses a Chaum-Pedersen zero- knowledge proof (ZKP) of discrete log equality to prove log*gpk⁰* = log*B0 B* where *pk⁰* = *pk g* H3 (*t*) which can be easily computed from public values by the client. Our protocol incurs minimal overhead on top of the OPRF blind evaluation of 2HashDH, requiring only an extra hash computation, group operation, and scalar inversion. It makes use of the same Chaum-Pedersen proof for veriability, which, as has been observed for 2HashDH, allows for evaluation of a batch of inputs whilst only constructing one Chaum-Pedersen proof [DGS + 18,DFHSW20] (provided the batch is for the same public metadata tag *t*). We formally show request privacy against passive adversaries (without ZKP) holds based just on the ran- domness of the blinding, and that request privacy against malicious adversaries holds additionally assuming the ZKP is sound. The key technical challenge is proving the new POPRF is pseudorandom. As is seemingly requisite for schemes with blinded evaluation protocols, we prove the pseudorandomness security of our scheme with respect to a one-more gap style assumption [BNPS03,Bol03]. In fact the algebraic structure exposed to adversarial clients by the 3HashSDHI blinded evaluation protocol | raising an arbi- trary group element *Y* to 1*=*(*sk* + H₃(*t*)) for adversarial *t* | requires new proof techniques compared to prior approaches. We start by introducing a new one-more gap strong Die-Hellman inversion (OM-Gap-SDHI) assumption, based on the perceived hardness of computing *Y* 1*=*(*x*+*c*) for any base *Y* and (restricted) scalars

*c*. We show via a relatively straightforward proof that this assumption is sucient to prove POPRF pseu- dorandomness for 3HashSDHI, modeling the hash functions as random oracles. Additionally, the veriable version requires that the ZKP is zero-knowledge. The main diculty is analyzing the security of our new computational assumption. In particular, for given

||n||=(x+c)|
|---|---|---|---|
|||m||
|1=(x+c)|1=(x+c)|||
|i|i|‘||
 distinct constants *c₁;:::;c*, the assumption considers a setting with an oracle SDH returning *B¹i*on input (*B;i*). Given some additional random group elements *Y₁;:::;Y*, it requires it to be hard to compute
*i i* *‘* elements *Y* 1 *;:::;Y* *‘*, for any *i 2* [*n*] and for distinct *i₁;:::;i 2* [*m*], using fewer than *‘* queries SDH(*;i*). The challenge is that we do *not* restrict the number of queries SDH(*X;j*) for *j 6*= *i*, and this could be for group elements of *X* that depend on *ci*(e.g., *X* is a prior output of an SDH(*;i*) query). Ultimately, we show in the algebraic group model (AGM) [FKL18] that the assumption reduces to one of the uber assumptions from Bauer, Fuchsbauer, and Loss [BFL20], and therefore, in turn, is implied by the *q*-DL assumption, where *q* is a bound on the number of oracle queries. This AGM analysis implies hardness

of the new assumption in the generic group model (GGM) [Sho97,Mau05]. In terms of concrete security, our analyses shows that, roughly speaking, 3HashSDHI is as hard as breaking the *q*-DL problem. Actually our main AGM proof is loose by a factor that is the maximum number of blind evaluation queries made by an adversary. Whether this AGM analysis can be tightened is an open question, but we observe in the body that a slight alternative to our AGM analysis gives a tight reduction in the GGM. We suggest using this tighter analysis to drive parameter selection: the best known attack against *q*-DL is due to Cheon [Che06] and indicates that a 256-bit group suces for 80-bit security and a 384-bit group for 128-bit security. Importantly this matches the situation for 2HashDH, and so moving to 3HashSDHI does not require changing group parameters to achieve the desired security levels.

Partially-blind signatures. Our techniques provide a new approach to building partially-blind signa- tures [AF96]. Whereas an OPRF requires access to the private key to verify a given input, a blind signature protocol only requires the public key. This property is useful for a number of applications and deployment settings. For example, in settings where multiple instances of a verier may check the output of the OPRF, each instance would either (a) require access to the private key or (b) request verication from an entity which holds the private key. The former may be problematic if instances that verify outputs do not mutually trust one another or cannot otherwise share private key material, and the latter may be problematic because it incurs a network performance penalty. Blind signatures avoid both problems by allowing each instance to use the public key for verication. Blind signatures are used in one-time use anonymous credentials, and are also being proposed as a tool for private click measurement (PCM) in the W3C [WTKW20]. One limitation in these use cases is that the protocols do not admit public metadata in the signature computation. PCM, for example, would benet from binding additional context to signature computations [WTKW20]. As previously mentioned, the 3HashSDHI construction is closely related to the ZSS partially blind signa- ture scheme [ZSS03], which uses pairings. As we explain in Section4, the original unforgeability proof is how- ever incorrect. We provide the rst (correct) formal analysis of the security of ZSS using our new techniques in AppendicesEandG. To the best of our knowledge, this result provides the most ecient partially-blind signature supporting arbitrary public metadata; previous RSA-based constructions [AF96,AO00] require the set of public metadata tags to be incorporated during parameter setup, previous Schnorr-based con- structions [AO00,FPS20] are vulnerable in the concurrent signing setting [BLL + 21], and other existing constructions are more heavyweight as they are tailored for the anonymous credential setting [CL04]. Finally, we also show how any unique (partially) blind signature scheme can be used to generically construct a POPRF by hashing the signature using a random oracle. This is apparently a folklore result for OPRFs, and we are unaware of any formal treatment it. We provide one that also covers partial obliviousness/blindness. See AppendixF.

Applications of our POPRF. Equipped with our new POPRF and the underlying design of 3HashSDHI, we return to our motivating applications and show how swapping in a POPRF for the existing OPRF can lead to various benets for deployments.

*One-time use anonymous credentials.* Privacy Pass [DGS + 18,CDFH21] is a protocol in which clients may be issued one-time use tokens that can later be redeemed anonymously to authenticate themselves. It has been proposed for use in the context of content distribution networks and web advertising, requiring users to authenticate with a token, and thereby reducing malicious web requests, protecting against, e.g., denial-of-service attacks and fraudulent advertisement conversions. Tokens are issued to users that prove trustworthiness, e.g., through a CAPTCHA challenge, The protocol is being considered for standardization by both the IETF and the World Wide Web Consortium (W3C), and a prototype deployment is already in production use by Cloudare, hCaptcha, and others. An OPRF is the core component of the protocol. Tokens are issued via an OPRF in which users obtain evaluations at random points, storing the point *x* and evaluation *y*. Redeeming a token simply involves showing the pair (*x;y*), which the server can check is valid, but cannot link *x* back to an issuance due to the oblivious evaluation. The server stores a strikelist of used tokens to prevent double spending. Additionally, all servers perform a global double-spend check to avoid clients from exploiting the possibility of spending tokens more than once against distributed token checking systems. The use of an OPRF leads to a more ecient issuance protocol than alternate approaches for keyed-verication anonymous credentials

that support attributes and proofs over attributes [CMZ14,CPZ20]. An abuse of the protocol that has been observed in its early use is individual users (or groups of users) gathering tokens over a long period of time and redeeming them all at once, e.g., in an attempt to overwhelm a website. We refer to such behavior as a hoarding attack. A conceptually easy way to mitigate the damage of a hoarding attack is to expire old unspent tokens after an amount of time: the way to do this with an OPRF is by rotating the OPRF key. But key rotations are complex, limiting their frequency: establishing trust in a frequently-rotating key is a challenging problem. Trustworthy keys are important in this context, as a server that equivocates on their public key can link token issuances and redemptions, by, for example, using a unique public key for each issuance. As we show, POPRFs address the issue of expiring tokens without the need of rotating keys by using the public metadata input to encode an expiration epoch.

*Bucketized PSI for checking compromised credentials.* Password breach alerting protocols [TPY + 19, LPA + 19] allow a user to query to determine if their username, password pair (*u;pw*) has appeared in a dataset *D* of known breaches. If so, the user is vulnerable to credential stung attacks and should change their password. Current services for breach alerting rely on an ad hoc 2HashDH-based private-set membership protocol that achieves scalability via bucketization: the user sends a truncated hash H(*u*) of their username to identify a subset *B D* that have matching truncated username hash. A 2HashDH-based protocol is then performed over *B*: the client obliviously evaluates 2HashDH*:* Ev(*sk;u k pw*) with *sk* held by server, and also obtains the OPRF outputs for all the values in the bucket *B*. Bucketization ensures scalability by limiting *jBj* despite *jDj* being on the order of billions of username, password pairs. One issue is that currently deployed protocols provide no cryptographic binding between the bucket identier H(*u*) and the blinded OPRF output: a malicious client can query for arbitrary usernames, not just ones that match H(*u*). Whether this is a signicant security problem in practice is not clear, but we note that POPRFs easily rectify it by replacing 2HashDH above with 3HashSDHI and setting *t* = H(*u*).

*Asymmetric password-authenticated key exchange.* Password authenticated key exchange (PAKE) proto- cols [BM93] allow a client and server to establish a shared session key authenticated by a short password. Strong asymmetric PAKE (SaPAKE) protocols [JKX18] additionally ensure that the server can store (just) what amount to salted hashes of user passwords, thereby making it so that PAKEs can achieve the same level of security achieved by standard password-based authentication in the case of a server breach. The OPAQUE [JKX18] SaPAKE protocol uses an OPRF as one of its core components; it is currently being considered for standardization by the IETF [KLW21]. The OPRF suggested for use is 2HashDH. In OPAQUE the server uses a separate OPRF key for each user. We show how we can instead use our 3HashSDHI POPRF to allow OPAQUE to work with a single master key *pk*; diversity across users can then be provided using usernames as the public input *t* to 3HashSDHI. We believe that this will simplify deployments and potentially improve their security, as discussed in the body.

# 2 Preliminaries

## 2.1 Algebraic Group Model

In some of our security proofs, we consider security against *algebraic* adversaries which we model using the algebraic group model, following the treatment of [FKL18]. We call an algorithm *A algebraic* if for all group elements *Z* that are output (either as nal output or as input to oracles), *A* additionally provides the representation of *Z* relative to all previously received group elements. The previous received group elements include both original inputs to the algorithm and outputs received from calls to oracles. More specically, if [*X*]*i*is the list of group elements [*X₀;:::;Xn*] *2* G that *A* has received so far, then, when producing group Q element *Z*, *A* must also provide a list [*z*]*i*= [*z₀;:::;zn*] such that *Z* =*iXiz* *i*.

## 2.2 Random Oracle Model

We will prove security using ideal primitives, modeling hash functions as random oracles. Since our schemes will make use of more than one hash function, it will be useful to have a general abstraction for the use of ideal primitives, following the treatment of [JT20]. An ideal primitive P species algorithms P*:* Init and P*:* Eval. The initialization algorithm has syntax *st*P$ P*:* Init(1). The stateful evaluation algorithm has

Game Sound *A* NiZK*;R;*P() Game ZK *A* NiZK *;b;R;* S*;*P() Oracle Prove(*x;w*) Oracle Prim(*x*) *pp* $ NiZK*:* Setup() *pp* $ NiZK*:* Setup() Require (*x;w*) *2R y₁* $ P*:* Eval(*x* : *st*P) *st*P $ P*:* Init() *st*P $ P*:* Init() 1 $ NiZK*:* Prove P (*x;w*) *y₀* $ S*:* Eval(*x* : *st*S)

|(x;)|A (pp)||st S:Init(pp)||S:Prove(x : st|)|Return y||
|---|---|---|---|---|---|---|---|---|
|Return 0||1|b⁰ A|(pp)|Return||||
|V@ NiZK:Ver 69 w|(x;) : (x;w) 2R|A|Return b⁰||||||

(*x;*) $ *A* P (*pp*) *st*S $ S*:* Init(*pp*) 0 $ S*:* Prove(*x* : *st*S) Return *yb* $ Prim*;*Prove *b* P

Figure 1: Soundness (left) and zero knowledge (right) security games for non-interactive zero knowledge proof systems.

syntax *y* $ P*:* Eval(*x* : *st*P). We sometimes use *A* P as shorthand for giving algorithm *A* oracle access to P*:* Eval( : *st*P). While, the stateful formulation of the ideal primitive is used to allow for ecient instantiation in our security proofs, e.g., by \lazy sampling", ideal primitives should be *essentially stateless* [JT20] to prevent contrived behavior. For example, a random oracle can be written to be stateless, but it would inecient to have to store a huge random table. We can combine access to multiple ideal primitives primitives P=P₁ *:::* P*m*as follows:

<u>P;i</u> *m*

|P:Init(1|) h|i|P:Eval(x : [st|])|
|---|---|---|---|---|
|[st]|P :Init(1|)|(i;x) x||
|Return [st|]||y P :Eval(x : st Return y|)|

<u>i</u> *m* $ *m* P*;i i i* P*;i* *m* *i* $ *i* P*;i* *i*

To concretize the above, we focus on random oracles. We dene a random oracle that takes arbitrary input and produces random output from a sampling algorithm Samp. It is captured by the ideal primitive RO[Samp] = (RO*:* Init*;*RO*:* H) dened as follows. When the range is clear from context, Samp may be omitted.

|RO:Init(1|)|RO:Eval(x : T )||
|---|---|---|---|
|T []||If x 62 T|Samp()|
|Return T||Return T [x]||
||||i|
|m||||
|i||||

then *T* [*x*] $

When clear from context and in an abuse of notation (since we will use H to denote a hash function as well), we will write P = H₁ H as the ideal primitive that gives access to *m* random oracles, accessible by querying directly an oracle labeled H.

Algebraic algorithms in the random oracle model. As in [FPS20], to support algebraic algorithms, we will require the structure of the domain and range to be specied for any random oracle RO. We assume an input can be eciently checked to be a valid member of the domain and perform such checks implicitly returning*?* if they fail. We will require that algebraic algorithms provide representations for any group element input, specied as part of the domain of RO. And similarly, any group element output of RO is included in the list of received group elements for the algebraic adversary.

## 2.3 Non-interactive Zero Knowledge Proofs

We dene a non-interactive proof system NiZK over an eciently computable relation *R* dened over pairs (*x;w*) where *x* is called the *statement* and *w* is called the *witness*. It is made up of the following algo- rithms. The setup algorithm produces the public parameters for execution, *pp* $ NiZK*:* Setup(). The proving algorithm takes a witness and statement and produces a proof, $ NiZK*:* Prove P *pp*(*w;x*). The veri- cation algorithm veries the proof for a statement, *b* NiZK*:* Ver P *pp*(*x;*). We dene the following security properties.

Completeness. A proof system is *complete* if given a true statement, a prover with a witness can convince the verier. We will make use of a proof system with perfect completeness. A proof system has *perfect* *completeness* if for all (*x;w*) *2R*, h i Pr NiZK*:* Ver P *pp*(*x;* NiZK*:* Prove P *pp*(*w;x*)) = 1 = 1 *:*

Knowledge soundness. A proof system is computationally *knowledge sound* if whenever a prover is able to produce a valid proof for a statement *x*, it is a true statement, i.e., there exists some witness *w* such that

<u>R: Prove</u> H <u>(; (g;U;V;W))R: Ver</u> H <u>((g;U;V;W);)</u> *r* $ Z*p* (*z;c*) *s* *Ug* *r*; *sWV* *r* *s* *Ug* *z* *U* *c*; *sWV* *z* *W* *c* *c* H(*g k U k V k W k sUk sW*) Return *c* = H(*g k U k V k W k sUk sW*) *z r c* (*z;c*) Return *R* = *f*()*;* (*g;U;V;W*) : *U* = *g ^ W* = *V g*

Figure 2: Description of Chaum-Pedersen discrete log equality Sigma protocol [CP92].

(*x;w*) *2 R*. Knowledge soundness is dened by the security game Sound *A* NiZK*;R;*P() (Figure1) in which an adversary is tasked with nding a verifying statement and proof where the statement is not in *R*. The advantage of an adversary is dened as Adv sound NiZK*;R;*P*;A*() = Pr[Sound *A* NiZK*;R;*P() = 1] with respect to ideal primitive P.

Zero knowledge. A proof system is computationally *zero-knowledge* if a proof does not leak any information besides the truth of a statement. Zero knowledge is dened by the security game ZK *A* NiZK *;b* *;R;*S*;*P () (Figure1) in which an adversary is tasked with distinguishing between proofs generated from a valid witness and simulated proofs generated without a witness. The advantage of an adversary is dened as

|zk|A;1|A;0|
|---|---|---|
|NiZK;R;S;P;A|NiZK ;R;S;P|NiZK ;R;S;P|

Adv () = Pr[ZK () = 1] Pr[ZK () = 1]*;*

with respect to simulator algorithm S and ideal primitive P.

Fiat-Shamir heuristic for Sigma protocols. Our protocol requires a non-interactive zero knowledge proof for the relation including two pairs of group elements with equivalent discrete logs:

*R* = *f*(*g;U;V;W*)*;* () : *U* = *g ^ W* = *V g :*

This relation falls into a general family of relations of discrete log linear homomorphisms for which there exist so-called \Sigma protocols" [Cam98] to construct interactive proofs of knowledge. These can be made non- interactive using the Fiat-Shamir heuristic in the standard way. We denote*R*[GGen] (shortened to*R*for simplicity) as the resulting non-interactive proof system for *R* known as the Chaum-Pedersen protocol [CP92] (shown in Figure2); it is perfectly complete, computationally sound, and perfectly zero-knowledge in the random oracle model. We refer readers to [BS17, Figure 19.7] for construction of a simulator S, which leads to the following well-known result that we state for completeness:

### Theorem 1 The simulator S

|is such that for any RO-model adversary A|||against ZK of|,|
|---|---|---|---|---|
|zk|||zk|R|
||;R;S ;RO;A|P P H|||
|H||||p|

Adv *R* zk () *q* (*q* + *q*)*=*2*;*

*where A*zk*makes at most q*P*and q queries to* Prove *and the random oracle* RO : G⁶*!* Z*.*

# 3 Partially Oblivious Pseudorandom Functions

We provide a new formalization for POPRFs, including syntax, semantics, and security. Our formalization builds o that from [ECS + 15], but we oer new security notions that cover simulation-based security as a PRF (in the presence of a blinded evaluation oracle), client input privacy, and veriability.

Syntax and semantics. A partially-oblivious pseudorandom function (POPRF) scheme, Fn, is a tuple of algorithms

(Fn*:* Setup*;*Fn*:* KeyGen*;*Fn*:* Req*;*Fn*:* BlindEv*;*Fn*:* Finalize*;*Fn*:* Ev) *:*

The setup and key generation algorithm generate public parameters *pp* and a public key, secret key pair (*pk; sk*), respectively. Oblivious evaluation is carried out as an interactive protocol run between client and server. The protocols we consider in this work make use of only a single round of interaction, so we simplify the syntax of the interactive oblivious evaluation protocol into algorithms (Fn*:* Req, Fn*:* BlindEv, Fn*:* Finalize) that work as follows:

(1)First, a client runs the algorithm Fn*:* Req
P *pp*(*pk;t;x*), which takes input a public key *pk*, tag (or public input) *t*, and private input *x*, and outputs a local state *st* and a request message *req*. The message *req* is sent to a server.

(2)A server runs algorithm Fn*:* BlindEv
P *pp*(*sk;t; req*), using as input a secret key, a tag *t*, and the request message. It produces a response message *rep* that should be sent back to the client.

(3)Finally, the client runs the algorithm Fn*:* Finalize(*rep* : *st*) and outputs a PRF evaluation or*?* if the response message is rejected, for example, due to the verication check failing. The unblinded evaluation algorithm Fn*:* Ev is deterministic, and takes as input a public key, secret key pair (*pk; sk*), an input pair (*t;x*), and outputs a PRF evaluation *y*. We also dene sets Fn*:* SK, Fn*:* PK, Fn*:* T, Fn*:* X, and Fn*:* Out representing the secret key, public key, tag, private input, and output space, respectively. We dene the input space Fn*:* In = Fn*:* T Fn*:* X. We assume ecient algorithms for sampling and membership queries on these sets. When it is clear from context, we drop the prex Fn and subscript *pp* from algorithm names. For correctness, we require that Ev is a function, and that the blinded and unblinded evaluations are consistent. To formalize the latter: we require that for any *pp* output from Setup, any *pk; sk* output by KeyGen, and any *t;x*, it holds that Pr[Ev(*sk;t;x*) = *y*] = 1 where the probability is taken over choice of *y* via the following process:
(*st; req*) $ Req P (*pk;t;x*); *rep* $ BlindEv P (*sk;t; req*); *y* $ Finalize P (*rep* : *st*) *:*

Security. We introduce three new security denitions for POPRFs. We use code-based games mostly following the framework of Bellare and Rogaway [BR06]. *Pseudorandomness.* The rst denition captures pseudorandomness, i.e., indistinguishability of the POPRF from a random function, even for malicious clients that have access to a blinded evaluation or- acle. We borrow some elements from the UC denition for standard OPRFs from [JKK14], but opt for what we believe to be a simpler, standalone formulation. We also extend to handle partial obliviousness, which has some subtleties. A pseudocode game appears in Figure3. The game is parameterized by a security parameter, an adversary *A*, a challenge bit *b*, a POPRF Fn, a simulator S = (S*:* Init*;* S*:* BlindEv*;* S*:* Eval), and an ideal primitive

P. The last will be used for random oracles in our main result. A simulator is a triple of algorithms that share state (explicitly denoted by *st*Sin the game). Algorithm S*:* Init initializes the simulator state and outputs a public key for the game. Algorithm S*:* BlindEv simulates blinded evaluation response messages while S*:* Eval simulates random oracle queries. Importantly, S*:* BlindEv and S*:* Eval can obtain Ev outputs, but they can only do so in a circumscribed way: the simulator has oracle access to LimEv which limits the number of full evaluations it can obtain to be at most the number of queries so far made by the adversary to the BlindEv. Importantly, this limit is per-metadata value *t* (indicated via the subscript): the LimEv query on any particular *t* is bound by the total number of blinded evaluation queries on that particular *t*. This follows from similar granular restrictions in the partially blind signatures literature [AF96]. A weaker version of the game would simply cap the total number of queries to LimEv by the total number of queries to BlindEv. This notion is, however, too weak for applications because we would like to ensure that querying, say, three times on public input *t₁* cannot somehow help an adversary complete the evaluation for another public input *t₂ 6*= *t₁*. We note that a recent preprint [SS21] contained this weaker notion, couched in the context of Privacy Pass. (We discuss this paper further in Section4.) We let the advantage of a POPRF adversary *A* be dened by
i i

||h|h|
|---|---|---|
|po-prf|A|A;;0S;P|
|Fn;S;P;A;|Fn;;1S;P|Fn|

Adv () = Pr POPRF ()*)* 1 Pr POPRF ()*)* 1

where the probability spaces are taken over the random choices made in the games and the events signify that the game outputs the value one. One could relax our denition in various ways. For example, by setting a parameter *qt;*maxthat upper bounds the total number of BlindEv queries on tag *t* over the course of the game and letting the simulator | at any point in the game | obtain *qt;*maxfull evaluations. This would seem to still provide qualitatively the same level of security, but our schemes meet the stronger notion that restricts the simulator over the course of the game. Another relaxation that does not preserve the same level of security would be to allow

*A*

|Game POPRF|(|)|Oracle Ev(t;x)||Oracle BlindEv(t; req)|||
|---|---|---|---|---|---|---|---|
|RandFn|FnGen(Fn:In; Fn:Out)||y₁ Fn:Ev|(sk;t;x)|q q + 1|||
|st P:Init(|)||y₀ RandFn(t;x)||rep₁ Fn:BlindEv|(sk;t;|req)|
|pp Fn:Setup(|)||Return y||(rep₀;st)|S:BlindEv|(t; req : st|
|(sk; pk₁)|Fn:KeyGen|()|||Return rep|||
|(st; pk₀)|S:Init(pp)||Oracle LimEv(t;x)||Oracle Prim(x)|||
|b⁰ A|(pp; pk|)|q|q + 1||||
|Return b⁰|||If q Return Ev(t;x) Return ?|q then|y₁ P:Eval(x : st (y₀;st) Return y|) S:Eval|(x : st)|

Fn *;b* *;*S*;*P $ P *t t* P P $ LimEv $ *b* S $ S) $ P*pp b* S $ $ Ev*;*BlindEv*;*Prim *b t;s t;s* *t;s t* $ LimEv P S $ S *b*

Figure 3: Simulation-based security denition for pseudorandomness against malicious clients, with granular ac-

counting for metadata in queries. The LimEval oracle limits the number of evaluations the simulator can make on a per-metadata tag basis.

<u>Game POPRIV1</u> *A* <u>Fn</u> *;b* <u>;P()</u> Game POPRIV2 *A* Fn *;b* *;*P()

|pp|$ Fn|: Setup(|)|
|---|---|---|---|
|st P|$|P : Init(|)|
|i|0|||
||$|Req; Fin|; P|
|b⁰|A||( pp )|
|Return||b⁰||
|Oracle Req(||pk;t;x₀|;x₁ )|
|i|i + 1|||
||||$ P|
|( st|i; 0; req₀|)|Fn : Req ( pk;t;x₀|
||||$ P|
|( st Return ( Oracle Fin(|i; 1; req₁|) req b; req₁ j; rep; rep⁰|Fn : Req ( pk;t;x₁ b ) )|

*pp* $ Fn*:* Setup()

|pp Fn:Setup(|)||||
|---|---|---|---|---|
|(pk; sk)|Fn:KeyGen(pp)||||
|st P:Init(|)||||
|b⁰ A Return b⁰ Oracle Trans(t;x₀;x₁)|(pp; pk; sk)||||
|(st₀; req₀)|Fn:Req (pk;t;x₀)||||
|(st₁; req₁)|Fn:Req (pk;t;x₁)|||)|
|rep₀ Fn:BlindEv|(sk;t; req₀)|||)|
|rep₁ Fn:BlindEv|(sk;t; req₁)||||
|y₀ Fn:Finalize|(rep₀; st₀)||||
|y₁ Fn:Finalize|(rep₁; st₁)|If j > i then return ?|||
|(req|; rep ;y₀)|y Fn:Finalize|(st; rep)||
|(req₁|; rep₁ ;y₁)|y Fnor|:Finalize|; rep )|
|Return (;|)|If¹ y = ? Return ? Return (y₀;y₁)|y = ?(st then||

$ P $ $ Trans*;*P

$ P $ P $ P $ P P P *b b* P *0* *b b* *b* P *j;b* *0* *0 b j;*1 *b* 0 1

Figure 4: Security denitions for honest-but-curious server unlinkability (left) and malicious server unlinkability

(right).

the simulator more queries than *qt;*max, for example, 2 *qt;*max. But this degrades the security guarantee as it means that in *q* queries to BlindEv on some *t* a malicious client can potentially compute up to 2*q* POPRF outputs for that tag *t*. *Request privacy and unlinkability.* Our second goal is to capture privacy for clients. This means not only that requests should hide the private input portion *x*, but also that request/response transcripts and output POPRF values should be unlinkable. We formalize two models for this goal, corresponding to the level of maliciousness by a misbehaving server. Game POPRIV1 (Figure4, top game) captures an indistinguishability experiment in which the adver- sary can query to obtain full transcripts (including output) resulting from honest blinded evaluation of a POPRF. The transcripts are either returned properly (*b* = 0) or with the request, response pairs swapped relative to the outputs (*b* = 1). Intuitively, if the adversary cannot distinguish between these two worlds, then there is no way to link a POPRF output value to a particular blinded evaluation, despite the adver- sary knowing the secret POPRF key. This captures also input privacy security: if a request reveals some information about the input *x* this can be used to win the POPRIV1 game. We sometimes refer to this as request privacy against passive adversaries, because the adversary cannot interfere with the server’s proper execution. The advantage of a POPRIV1 adversary *A* in the P-model is dened by h i h i Adv po-priv1 Fn*;*P*;A* () = Pr POPRIV1 *A* Fn *;;*1P

()*)* Pr POPRIV1
*A* Fn *;;*0P

()*)*
where the probability spaces are taken over the random choices made in the games and the events signify

that the game outputs the value one. We say a Fn scheme is *perfectly private* if Adv po-priv1 Fn*;*P*;A* () = 0 for all adversaries *A*. POPRIV1 security does not capture malicious servers that deviate from the protocol. So, for example, it doesn’t rule out attacks in which the server replies with garbage to a blinded evaluation request. Our next game POPRIV2 allows the adversary to choose the public keys used for request generation and leaves to the adversary how to reply to requests. The game therefore splits transcript generation across two oracles, a request oracle (Req) and nalize oracle (Fin). The rst oracle replies with a randomly ordered pair of request messages based on the challenge bit, and the second oracle can be queried with adversarially chosen response messages. The game requires that neither *y₀* nor *y₁* is equal to*?* | if either is then the nalize oracle returns*?*. This prevents the trivial attack of corrupting one reply but not the other. The advantage of a POPRIV2 adversary *A* in the P-model is dened by h i h i Adv po-priv2 Fn*;*P*;A* () = Pr POPRIV2 *A* Fn *;;*1P

()*)* 1 Pr POPRIV2
*A* Fn *;;*0P

()*)* 1
where the probability spaces are taken over the random choices made in the games and the events signify that the game outputs the value one. POPRIV2 is strictly stronger than POPRIV1. Looking ahead our new POPRF meets POPRIV1 when verication is omitted, and POPRIV2 when verication is required. *Uniqueness.* Lastly, we discuss an additional property that is relevant in the veriable setting when clients want to ensure that servers honestly perform blind evaluations. This means that the output of the blind evaluation protocol should be consistent relative to the public key pair, i.e., consistent with the output of unblinded evaluation using the secret key. Our correctness denition requires this is the case for honest execution of the algorithms. We formalize this correctness property for malicious servers as a uniqueness denition POUNIQ, taking inspiration from denitions used previously for veriable random functions (c.f., [DY05]). In short, no malicious server should be able to convince a client into accepting two dierent outputs for the same (*pk;t;x*). We show that uniqueness is implied by correctness and POPRIV2. The complete denition for POUNIQ, theorem statement, and proof are deferred to AppendixH.

Relation to partially blind signatures. POPRFs are related to two-move partially blind signatures, which were introduced by Abe and Fujisaki [AF96]. A partially blind signature is a tuple of algorithms

DS = (DS*:* Setup*;*DS*:* KeyGen*;*DS*:* Sign*;*DS*:* Ver*;*DS*:* Req*;*DS*:* BlindSign*;*DS*:* Finalize)

where the rst four algorithms dene a standard digital signature scheme for message space consisting of pairs (*t; m*), called the public input (or tag) and private message, respectively. Signatures can also be generated via an interactive protocol which, like we did for POPRFs, we formalize simply as a single round trip protocol initiated by a client running DS*:* Req(*pk;t; m*) to generate a request message *req* and client state *st*, sending the former to the server which runs DS*:* BlindSign(*sk; req*) to generate and send a response *rep* back to the client, which then computes a signature via DS*:* Finalize(*st; rep*). This protocol should achieve blindness, which can be dened similarly to our request privacy denition above for POPRFs. The main security property targeted is one-more unforgeability, which, roughly speaking, states that an adversarial client can’t generate *q* + 1 unique message-signature pairs (*m₁;*1)*;:::;*(*mq*+1*;q*+1) that all verify under a public key *pk* and public tag *t* even when given the ability to query a blind signing oracle with the only restriction being that only *q* queries can be made for the chosen public tag *t*. This intuitively enforces that each query to the blind signing oracle only results in one learned signature, and queries for a dierent public tag do not help in forging a signature for the target tag. We present a complete formal treatment of partially blind signatures in AppendixE. A partially blind signature is unique if DS*:* Sign is deterministic and its output on (*pk;t; m*) matches that of the interactive protocol when initiated on the same triple. A blind signature is just a partially blind signature with *t* omitted. JKK observed that one can transform unique blind signatures into OPRFs by hashing the signature. A similar transform exists to build a POPRF from a unique partially blind signature. We provide details and proof of this transform in AppendixFfor both cases, with and without public input). (As far as we are aware there has been no formal treatment of this observation.) Most prior partially blind signature schemes are not unique, e.g., [AF96,AO00]. The only unique scheme we are aware of is due to Zhang, Safavi-Naini, and Susilo (ZSS) [ZSS03], but it relies on bilinear pairings and so this generic transformation will not achieve our goals for a POPRF. Moreover as mentioned in the introduction, the security analysis in ZSS is wrong. That said, our construction shares much of the underlying

structure from the ZSS one. Using our new proof techniques, we furthermore provide the rst complete proof of the ZSS partially blind signature scheme (see AppendixG).

# 4 The 3HashSDHI POPRF

We now turn to our main result: providing a new POPRF. Our construction combines elements of the 2HashDH construction with a technique used by Dodis and Yampolskiy for their veriable PRF; it is also related to a partially blind signature scheme suggested by Zhang, Safavi-Naini, and Susilo. We call our construction 3HashSDHI, which we often abbreviate to 3H. The name refers to its use of three hashes and reliance on the strong inverse Die-Hellman assumption.

Algorithms. Our protocol relies on a group G of prime order *p* and with generator *g*. As mentioned in the introduction, the 3HashSDHI protocol computes a PRF output as

3H*:* Ev(*sk;t;x*) = H₂ *t;x;* H₁(*x*) 1*=*(*sk*+H3 (*t*))

where H₁ : *f*0*;* 1*g!* G, H₂ : *f*0*;* 1*g!f*0*;* 1*g*2, and H₃ : *f*0*;* 1*g!f*0*;* 1*g*3are the titular hash functions. Note that H₁ has range the group G, whereas the second and third hashes output bit strings of length2and 3. By default we set2= and3= 2. The third hash must be collision resistant for security to hold. Looking ahead to the security analysis, we will model the hash functions as random oracles. The setup, key generation, and full evaluation algorithms are shown in pseudocode below.

H1 H2 H3 H1 H2 H3 (*sk;t;x*)

|3H:Setup(|)|3H:KeyGen||(pp)|3H:Ev|
|---|---|---|---|---|---|
|(p;g; G)|GGen(|) (p;g; G)|pp||Y H₁(x)|
|pp (p;g; G)||sk|Z; pk|g|Z H₂(t;x;Y )|
|Return pp||Return (pk; sk)|||Return Z|

$ 1*=*(*sk*+H3 (*t*)) $ *p sk*

Here, GGen denotes a group parameter generator outputting a triple (*p;g;* G) consisting of a prime *p*, (the description of) a group G of order *p*, and a generator *g* of G. The blind evaluation protocol has a client compute H₁(*x*) and mask the resulting group element by raising it to a random scalar *r*. The client can send the resulting blinded value *B* to the server, who can then raise *B* to 1*=*(*sk* + H₃(*t*)) and return the result. The client then nalizes by raising the returned value to 1*=r* in order to remove the blinding, followed by the nal step of computing the nal hash H₂. The blinding ensures request privacy. We optionally can extend this blinded evaluation protocol to include a proof that the server properly exponentiated *B*. This is necessary to have the protocol enjoy POPRIV2 security, which is important in some (but not all) applications. At rst, it may not be obvious how to prove to the client that the server

|=(sk+H (t))|sk|||
|---|---|---|---|
||k|H (t) sk+H|(t)|

is returning *B⁰* = *B¹*3relative to the public key *g*, because the sum appears in the denominator. However, we can use the following trick: the server generates a standard DL proof that *B* = (*B⁰*) *k* for some

*k*. The client runs verication by explicitly reconstructing *g* = *pk g*3= *g*3. This means that the verication procedure checks the special structure of the exponent *k*. The full protocol, including the NIZK (which uses its own hash H₄), is shown in Figure5. Here we show that *t* is sent from the client to server, though in some applications the server may receive *t* out-of-band. Execution requires just one round trip. It requires just two group exponentiations on the client side (and, when using the NIZK, those used for its verication). The server uses one exponentiation plus one for the NIZK proof. Relation to partially blind signatures. 3HashSDHI is closely related to a partially blind signature suggested by Zhang, Safavi-Naini, and Susilo [ZSS03]. It uses groups G₁*;*G₂*;* G*T*each of order *p*, with generators *g₁;g₂;gT*, and that come equipped with an ecient-to-compute pairing *e*: G₁ G₂*!* G*T*such that for any*; 2* Z*p*it holds that *e*(*g₁;g₂*) = *gT*. Their signature is dened as
ZSS1*:* Ev(*sk;t;x*) = HG2(*x*) 1*=*(*sk*+H3 (*t*))

where HG: *f*0*;* 1*g!* G₂ hashes onto the group G₂ and H₃ is as dened above for 3HashSDHI. We use ZSS1 to dierentiate from our suggested modications, which we call ZSS2 and discuss in AppendixG. As can be seen, 3HashSDHI uses essentially the same structure, combined with a nal hash but we dispense with

<u>3H: Req</u> H1 H2 H3 H4 <u>(pk;t;x)</u> *r* $ *Zp*; *B* H₁(*x*) *r*

|Return ((pk;r;t;x);B)|||! B;t|3H:BlindEv|(sk;t;B)||
|---|---|---|---|---|---|---|
|||||k sk + H₃(t) B⁰ B¹ :Prove|(k; (g;g ;B ;B|))|
|3H:Finalize Y (B⁰)||(B ;; (pk;r;t;x))|B;|Return (B⁰;)|||
|Require Z H₂(t;x;Y )|:Ver ((g;g|pk;B⁰;B);)|||||
|Return Z|||||||

Return ((*pk;r;t;x*)*;B*)*! B;t* <u>3H: BlindEv</u> H1 H2 H3 H4 <u>(sk;t;B)</u>

*=k* $ *R* H4 *k 0* H1 H2 H3 H4 *0* *0*

1*=r* *R* H4 H3 (*t*)

Figure 5: Blind evaluation for our 3H POPRF construction. All three algorithms have implicit input the parameters

*pp* = (*p;g;* G) that describe the group used. The NIZK uses relation *R* = *f*(*g;U;V;W*)*;* () : *U* = *g ^ W* = *V g*.

the use of bilinear pairings using instead NIZKs to provide veriability. We also comment on two aspects of the original security analysis of the partially blind signature scheme in [ZSS03]: (1) the analysis of one-more unforgeability is incorrect; and (2) it contains an incorrect claim that so-called \exponential" blinding (see below for discussion in the context of OPRFs) is insecure. More precisely, for (1), the claimed security proof relies on a lemma (stated without a proof) which says that if the scheme is secure, in terms of one-more unforgeability, for any xed public input, then it is secure as a partially-blind signature { such lemma does not appear to be provable; for (2), the claimed distinguishing test does not work, rather it identies every pair of signature and signing transcript as a match, regardless of whether they are associated. Our new techniques, in particular a variant of the new gap assumption discussed in the next section, enable a new proof of unforgeability for the ZSS partially blind signature, and we also provide a proof that exponential blinding is secure. See AppendixGfor the details.

Comparison to prior (O)PRFs. Recall that the 2HashDH OPRF is dened by 2HashDH*:* Ev(*sk;x*) = H₂(*x;* H₁(*x*) *sk* ). On the other hand, the DY PRF [DY05] is evaluated on a message *t* via DY*:* Ev(*sk;t*) = *h¹* *=*(*sk*+*t*) for generator *h*. Thus, our 3HashSDHI can be seen as blending of the two approaches, basically dening, for each *x*, a separate instance of the DY PRF with generator *h* = H₁(*x*) and input message *t*. The way we combine them retains the simple blinding mechanism of 2HashDH to allow hiding *x*. Despite the similarity to the prior constructions, analyzing security requires new techniques (see the next section). 2HashDH is often formulated using an alternative \multiplicative" blinding strategy as opposed to the \exponential" blinding presented here. Multiplicative blinding enables client-side performance improvements of xed-base exponentiation with precomputation over variable-base exponentiation, but has been shown to have some security drawbacks in the non-veried setting [JKX21]. 3HashSDHI is not compatible with the multiplicative blinding protocol used by 2HashDH, however AppendixIpresents an alternative multiplicative blinding protocol [ZSS03] that enjoys the same performance benets. Miao et al. construct an oblivious evaluation protocol for the DY PRF [MPR + 20]. Their approach makes use of the additive-homomorphic Camenisch-Shoup encryption scheme [CS03] and related proofs of discrete log representation. In contrast, 3HashSDHI uses the more ecient oblivious evaluation approach of 2HashDH and uses the structure of DY to tie in the public metadata, meaning the more expensive DY oblivious evaluation techniques are avoided. Pythia [ECS + 15] provided the rst POPRF. It uses pairing-friendly groups G₁*;*G₂*;* G*T*each of order *p*, with generators *g₁;g₂;gT*. Then, the Pythia POPRF is dened by

Pythia*:* Ev(*sk;t;x*) = *e*(HG1(*t*)*;* HG2(*x*)) *sk*

where HG2and HG2are hash functions that map to the groups G₁*;*G₂. This construction enables blinded evaluation by sending *B* HG2(*x*) *r*, and having the server respond with *e*(HG1(*t*) *sk* *;B*). It also has some other features that were desirable in the password hardening context for which Pythia was designed, specif- ically, that one can have compact key rotation tokens of the form = *sk⁰=sk*. The token can be shared with a client to help it update previously computed POPRF values for any *t;x*. Compared to Pythia’s POPRF, 3HashSDHI avoids use of pairings. This makes it faster to compute and saves bandwidth. That said, the 3HashSDHI construction does not support key rotations even if one omits the nal H₂

evaluation. To expand, consider using a (non-compact) key rotation in a way analogous to Pythia, i.e., distributing to a client*t*1= (*sk* + H₃(*t₁*))*=*(*sk⁰* + H₃(*t₁*)) and*t*2= (*sk* + H₃(*t₂*))*=*(*sk⁰* + H₃(*t₂*)). This would allow rotating (unhashed) POPRF outputs on public inputs *t₁* and *t₂* from an old key *sk* to a new key *sk⁰*. But this also trivially reveals *sk* and *sk⁰*, given that H₃(*t₁*) and H₃(*t₂*) are publicly computable. While in the applications we explore in Section7we do not need key rotation tokens, the question of nding a POPRF that avoids pairings yet supports key rotations remains open. We also compare to the recent attribute-based veriable OPRF (AB-VOPRF) suggested by Huang et al. of Facebook [HIJ + 21] for use with Privacy Pass. An attribute-based VOPRF is a POPRF that separates out an explicit algorithm for converting a secret key and attribute *t* (what we call a tag) into a tag-specic public key, secret key pair. As with other VOPRFs, there is a veriable, blinded evaluation protocol by which a client can obtain an output on some (*t;x*) pair without revealing *x*. Any AB-VOPRF gives a POPRF, and vice versa. The Facebook construction of an AB-VOPRF combines the 2HashDH approach with the Naor-Reingold PRF [NR97]. Evaluation is dened by Q*t*[*i*] FB*:* Ev(*sk;t;x*) = H₁(*x*) *a* 0 *iai*

where *sk* = *a₀;a₁;:::;ajtj*and *t*[*i*] indicates the *i* *th* bit of *t*. To make this veriable, the scheme must provide a more complex NIZK involving *jtj* group elements, making it expensive to transmit and verify, particularly in applications where a wide variety of tags *t* will be used. In comparison 3HashSDHI is as ecient as 2HashDH. Finally, a concurrent, independent work by Silde and Strand [SS21] describe what we call the 3HashSDHI protocol and how it could be useful for Privacy Pass and the Facebook de-identied logging application. They formalize a notion of anonymous token security that is more tailored to Privacy Pass style applications (compared to our general POPRF denitions), but this denition contains the aforementioned problem (see Section3) of not performing query accounting on a per public input basis, making it too weak of a security notion for their applications. In addition, the security analysis relative to this notion is incomplete, and so the paper does not yet provide a proof even of this weaker security notion. Nevertheless, their work underscores the benets of the 3HashSDHI protocol in the applications they explore and our proof techniques (in particular, the new one-more gap SDHI assumption discussed in the next section) should enable improvements to their analysis.

Extension to private metadata bit. Recall a primary application of OPRFs is in the construction of anonymous tokens. We have thus far been concerned with adding support for public metadata, but there are also settings that benet from being able to associate *private* metadata to tokens that can only be identied by the issuer. To prevent trivial linking attacks by a malicious server, it is necessary that the private metadata space remain small. Kreuter et al. propose a variant of Privacy Pass (based on the 2HashDH OPRF) that supports a single private metadata bit [KLOR20]. The high level approach is to simply maintain two keys and prove in zero knowledge that the token is issued under one of the two keys. However, they observe that a deterministic primitive (like a PRF) is insucient to achieve indistinguishability between private metadata bits. Therefore, the core of their construction is a new anonymous token protocol that can be considered as a randomized variant of 2HashDH. It is likely similar techniques can be applied to construct a randomized version of 3HashSDHI to support public metadata as well as a private metadata bit; we leave the details of such a construction to future work. Silde and Strand propose a construction along these lines, but as mentioned before, the security analysis is incomplete [SS21].

# 5 Security Analysis

We show formally that the 3HashSDHI PO-PRF enjoys pseudorandomness and request privacy. The former is the more complex analysis; we start with it.

## 5.1 Pseudorandomness

The main technical challenge is showing that 3HashSDHI meets our pseudorandomness denition, captured by game POPRF (Figure3in Section3). We start with an overview of our proof strategy, and then state

### our main result.

Proof strategy. Our proof of pseudorandomness proceeds in several steps. First, we introduce a new discrete log (DL) type cryptographic hardness assumption: the one-more gap strong Die-Hellman inversion problem, denoted (*m;n*)-OM-Gap-SDHI for parameters *m;n* that we will explain. The new assumption is a generalization of prior one-more DL assumptions, but extended with two oracles and a more involved one-more winning condition which depends on the number of queries with a specic form to one of the oracles. We show that we can build a POPRF simulator such that, in the ROM, distinguishing between the real (*b* = 1) and ideal worlds (*b* = 0) reduces to breaking an instance of (*m;n*)-OM-Gap-SDHI where *m* is the number of H₃ queries made by *A* and *n* is the number of H₁ queries. We also analyze the security of our new assumption, showing that, in the Algebraic Group Model (AGM) [FKL18] it reduces to one of the uber assumptions from Bauer, Fuchsbauer, and Loss (BFL) [BFL20]. In turn, we can use a result from BFL to nally show that our new assumption is implied (again, in the AGM) by the *q*-DL assumption. This provides good evidence of the diculty of the problem, and allows us to derive precise concrete security bounds.

The one-more gap SDHI assumption. Game (*m;n*)-OM-Gap-SDHI is shown in Figure7. The game generates a group instance and a challenge secret *sk*. The adversary *A* = (*A₁; A₂*) runs in two stages. In the rst stage it receives the group description *p;* G and outputs a sequence of *n* scalar values *c₁;:::;cn*. Importantly *A₁* does not receive *g*, forcing it to commit to the *ci*values in a way independently of the generator *g*. We assume that *g* is randomly chosen;

||this will be important in our analysis.|||Then, the|
|---|---|---|---|---|
|i|sk|=(sk+c|)|y|
|)|||i||
||1=(sk+c|)||i i|
||i||||

second stage *A₂* is run on input the generator *g*, *g*, and a vector of *m* group elements *g* *y* 1 *;:::;gn*. The adversary is given access to two oracles. The SDH oracle returns *B¹i*for arbitrary *B* and one of the previously specied *c* values. The SDDH oracle is a decision oracle that helps the adversary determine whether *Z* = *Y* 1*=*(*sk*+*ci* for arbitrary *Y;Z* and one of the previously specied *c* values. The adversary outputs a distinguished index indicating a *c* value, as well as a set of *‘* pairs (*Z;*) *2* G [0*::m*]. The adversary wins if *‘ > q* and *Z* = *Yi*for all 1 *i ‘*. Here *q* is the number of queries to the SDH with second input set to. Without the \one more" restriction of *‘ > q*, it is trivial to win. We dene the (*m;n*)-OM-Gap-SDHI-advantage of an adversary *A* by h i (*m;n*)-om-gap-sdhi *A* Adv GGen*;A* () = Pr (*m;n*)-OM-Gap-SDHIGGen()*)* true *:*

An adversary *A* has query budget (*~q;q*SDDH) for *~q* = [*~q₁;:::;~qn*] if at the end of the game *A* has made at most *~qi*queries to SDH with index *i* and has made at most *q*SDDHqueries to SDDH. We note that a weakening of the assumption dispenses with the more granular per-*c*-value accounting, instead just asking that the adversary can’t come up with *‘ > q* solutions for any mixture of *Yi*and *cj*values. This variant is much easier to analyze in the AGM, but is not sucient for our analysis.

Reducing (*m;n*)-OM-Gap-SDHI to *q*-DL. In two steps, we show how to reduce this assumption, in the AGM, to the diculty of *q*-DL. The latter <u>Game q-DL</u> *A* <u>()</u> <u>GGen</u> involves a game *q*-DL (Figure6) that generates a group instance *p;g;* G for (*p;g;* G) $ GGen() *x x² x* *q* security parameter, and gives an adversary *g;g;g;:::;g* for a random *x* $ Z*p* h i *0* $ *xi q* scalar *x*. The adversary must output *x*. We dene the advantage of a *q*-DL-*x A p;*G*;g; g* *i*=1 adversary *A* to be Adv *q*-dl () = Pr *q*-DL *A*

()*)* true.Return *x* = *x*
*0* GGen*;A* GGen As a convenient middle layer, we rely on BFL’s \Uber-assumption" [BFL20], formalized via the game *m*-Uber in Figure8. It involves a game Figure 6: The *q*-type discrete where the adversary can obtain *g* (*~x*) by querying an arbitrarily chosen *m*-log security game. variate polynomial (*X~*) to an oracle Ev, for a secret vector *~x* $ Z *m*

*p*. The
adversary wins if it outputs successfully *g* (*~x*) for some polynomial (*X~*) which is *independent* of the polynomials1(*X~*)*;:::;q*(*X~*) queried to Ev, i.e., (*X~*) cannot be expressed as an ane combination (*X~*) =1 1(*X~*) + +*q q*(*X~*) +. The adversary can also query an additional Decide oracle with a polynomial (*X~*), as well as group elements *g* *y* 1 *;:::;g* *y* *m*, and learn whether *g*(*y*1*;:::;ym*)= 0 or not. We denote the corresponding advantage as Adv *m* GGen -uber *;A*() = Pr *m*-Uber *A* GGen()*)* true. We are going to prove the following theorem in AppendixA. Here and subsequently we use ‘ ’ to denote that runtimes are equal up to small constant factors.

||A Game (m;n)-OM-Gap-SDHI () Oracle SDH(B;i) GGen||
|---|---|---|
|(p;g; sk (st A (; [|$ G) GGen() Require i = 2 [1 ;n] m m $ $ Z; [y] [Z] q q + 1 p i p i i i i n = (sk + ci) $; [c]) A₁ (p; G) Z B¹ i i n Require 8 Return Z c 6 = c i j i6 = j SDH; SDDH ‘ sk yi m $) A : st Z ;] g;g; [g] i i A 2 i i Oracle SDDH(Y;Z;i) ‘ Require q < ‘ ^ 8 6 = i j 1 = (sk + ci i6 = j Return Z = Y h i ‘ y (sk + c) ‘ i = Return [Z] = g i i i Figure 7: The one-more gap strong Die-Hellman inversion security game. A ~ Game m -Uber () Oracle Ev((X)) GGen $ ~ (p;g; G) GGen() Q Q [f (X) g (~x) Q fg Return g m m $ ~x = [x] [Z] i p i i n ~ Ev; Decide) Oracle Decide((X); [Y] ~ i $ (U; (X)) A (p; G ;g) i n (~x) n ~ Return U = g ^ Q ??f (X) g ~y = [y] log Y i i g i i Return (~y) 0 p|)|
|interactive, GGen and q GGen and q max A₂ also be thought of as dividing some polynomial P|exible-output, polynomial uber assumption with decision For any algebraic adversary A of (m;n)-OM-Gap-SDHI with query budget sdhi outputting (p;g; G), where g is a uniformly chosen element of q (m;n)-om-gap-sdhi (m +1)-uber Adv () (q + 1) Adv () +; max GGen ;A GGen ;A sdhi uber p n = max fq g. Also, A makes at most q queries to its polynomial evaluation max i uber i + 1, and outputs a polynomial of degree at most q. It is important here to note that the theorem assumes that the query budgets q i a priori, rather than being chosen adaptively. Combined with a basic reduction from [BFL20], this gives us the following immediate corollary. For any algebraic adversary A of (m;n)-OM-Gap-SDHI, with query budget sdhi outputting (p;g; G), where g is a uniformly chosen element of q (m;n)-om-gap-sdhi (q +1)-dl Adv () (q + 1) Adv () +; max GGen ;A GGen ;A sdhi dl p n = max fq g. Further, T (A) T (A). i sdhi dl i The main diculty of the proof of Theorem2in AppendixAstems from the one-more requirement in the winning condition, which is dened in a way that depends on the specic number of queries To gain some intuition, it is convenient to think of the game in algebraic terms (and this point 1 of view is also accurate when casting our proof in the AGM). as formal polynomials X₀ (standing for the secret key) and). Initially, the adversary has these polynomials available, and now a call to SDH(P (or more generally, a rational function) by (can be any ane combination of the functions obtained so far, and SDH(new rational function to this set of available rational functions.|oracle. G G Specically, let us describe exponents of the In other words, consecutive queries induce|

Figure 8: The Here,*??* denotes

algebraic independence.

Theorem 2 (*~q* = [*q₁;:::;qn*]*;* *q*SDDH)*, and any, we give adversary* *A*uber*such that*

P*n* *where q* =*iqi* *oracle with maximum degree q Further, T*(*A*sdhi) *T* (*A*uber)*.*

corresponding to dierent *i*’s are *xed*

Corollary 3 (*~q* = [*q₁;:::;qn*]*;* *q*SDDH)*, and any, we give adversary* *A*dl*such that*

P*n* *where q* =*iqi*

*‘ > q* *q* to SDH(*;*).

elements provided to *X₁;:::;Xm*(for the values *y₁;:::;ymP;i*) can *X₀* + *ci*). The rational function *P;i*) adds a

We ignore the SDDH oracle in this discussion, and it will be easy to handle in the actual proof via the Decide oracle.

a *transcript* consisting of the initial functions *X₀;X₁;:::;Xm*, and the functions returned by SDH. The goal of the adversary is to ensure that, for some, the span² of contains *‘ > q* functions of the form

<u>X1X‘</u> *; :::; :* *X₀* + *c X₀* + *c*

An adversary cannot achieve this goal naively by querying SDH(*Xj;*) for *j 2* [*‘*] without violating the query budget. Still, the key diculty here is that the adversary *could*, after learning (say) *X₁=*(*X₀* + *c*) make a further query that would give *X₁=*(*X₀* + *c*)(*X₀* + *c 0*) for some *0* *6*=. This second query would *not* count towards *q*, and could potentially be helpful, as it *does* involve *c*. The bulk of our proof shows that arbitrary queries to SDH cannot, in fact, help the adversary. We do so via a careful inductive analysis which shows that the transcript can be rewritten in an equivalent way, call it *0*, without aecting its span. In particular, *0* only involves rational functions whose denominators have form (*X₀* + *ci*) *k* for some *i* and *k*, but no products involving multiple *ci*’s appear in the denominators. We leverage this structure to show that the span of such *0* can include at most *q* rational functions of the form *X*0 <u>X</u> + <u>i</u> *c*. Now, given the above algebraic game cannot be won, an adversary winning the game must necessarily *‘* produce an output (*;* [*Zi;i*]*i*) where for at least one *i 2* [*‘*], we have that the polynomial *Xi=*(*X₀* + *ci*) is not in the span of the queries to SDH. This lends itself naturally to a reduction to the Uber-assumption, which we describe in full in the proof.

Reducing to (*m;n*)-OM-Gap-SDHI. We now turn to showing that we can reduce the pseudorandomness security of 3HashSDHI to our new assumption. We focus on the veriable version of 3HashSDHI; an analysis for the non-veriable version is easily derived from our analysis here. Our analysis is in the RO model; we model all four hash functions as ROs. We start by describing the simulator used in the proof. The simulator’s goal is to respond to blind evaluation and RO queries so that the resulting transcript of values is indistinguishable from real responses. Importantly, the simulator must do this without making too many calls to the full evaluate oracle for each BlindEval-queried public input *t*. Intuitively, achieving this security enforces that a malicious client can not exploit the blinded evaluation oracle to do more than help it compute a single POPRF output for the particular requested *t*. The simulator works as follows. It chooses its own secret key *sk* and answers the H₁ and H₃ queries with random group elements and scalars, respectively. To answer a blinded evaluation query, it runs the scheme’s blind evaluation algorithm Fn*:* BlindEv(*sk;B*), except that it uses the NIZK’s simulator to generate the proof (and to simulate any ideal primitive underlying the NIZK, i.e., H₄). The key challenge is in simulating H₂ queries, that which enables the adversary to \complete" a blinded evaluation. The simulator must arrange that the value it returns in response to H₂ queries is consistent with the random value returned by Ev. To do so, the simulator checks whether a queried point (*t;x;Y*) is such that *Y* = H₁(*x*) 1*=*(*sk*+H3 (*t*))

and, if so, it queries LimEv(*t;x*) and returns the output. Otherwise, it chooses a random point to return. The simulator can perform this check because it chose *sk*. See Figure10in AppendixBfor the full details of the simulator. The simulation can fail should the adversary be able to query it on a point *Y* = H₁(*x*) 1*=*(*sk*+H3 (*t*)) when the simulator cannot make another call to LimEv for that value *t*. This can only arise should the adversary query H₂ on more such values *t;Y* than queries it so far made to BlindEv on that *t*. We show that an adversary, that can do so, can also win the (*m;n*)-OM-Gap-SDHI game where *m;n* are the total number of queries involving a distinct *x* value and distinct *t* value, respectively. (We dene this more precisely below.) This step also relies on the collision resistance of H₃, which holds in the ROM. To formalize this, we state below a theorem using the ideal primitive model in which P = H₁ H₂ H₃ H₄ for random oracles over H₁ :*!* G, H₂ : G*!f*0*;* 1*g*, H₃ :*!* Z*p*, H₄ : G⁶*!* Z*p*for (*p;* G) determined by GGen(). Here ‘ ’ denotes the set of arbitrary inputs. We dene the query budget for an adversary *A*prf in the P model to be a tuple (*m;n;q*E*;~q;q*H1*;q*H2*;q*H3*;q*H4) where: *m* is the maximum number of distinct *x* values queried by *A*prfto H₁ or H₂; *n* is the maximum number of distinct *t* values queried by *A*prfto BlindEv, H₂, or H₃;

By \span" we mean the set of rational functions that can be obtain by taking *ane* combinations of the functions in.

*~q* = [*~q₁;:::;~qn*] is a vector where each *~qi*is the maximum number of queries by *A*prfto BlindEv(*ti; req*) for any *req* and where we *t₁;:::;tn*are the (at most) *n* values *ti*queried in the course of the game in the order of when they are queried. (That is, *t₁* is the rst *t* value queried, *t₂* is the second, etc.) In words, the adversary is limited to some number *n* of public inputs *t* that it can target, and makes a limited number of blinded evaluation queries for each of those inputs *t*. *q* E, *q*H1, *q*H2, *q*H3, and *q*H4are the maximum number of queries made by *A*prfto the Ev, H₁, H₂, H₃, and H₄ oracles, respectively. Note that our query budget requirement *~q* does not restrict *which* values *t* the adversary can use; these can be picked adaptively. But the number of times each *t* value is queried is restricted by the order in which they are queried. The granular accounting of blinded evaluation queries via *~q* will be important when combining the following theorem with Theorem2.

||Let A be a P-model POPRF adversary against 3H with query budget (m;n; q||||; ~q; q|;; q|
|---|---|---|---|---|---|---|
||prf||||E|H H|
|H H|po-prf|zk zk||sdhi (m;n)-om-gap-sdhi|||
||3H;S[S|;R;H|;S ;A|GGen;A H|zk zk|H sdhi|
|A 3H;P;S|;1||||||

Theorem 41 2 *q*3*; q*4)*. Then we give a* H₄*-model adversary A and adversary A such that*

<u>n²</u> Adv]*;*P*;A*prf () Adv *R* 4 zk () + Adv sdhi () +*;* *p* *where* S *is the simulator dened in Figure10that makes use of NIZK simulator* S*. Adversary A makes q*4 *queries to its random oracle and A*sdhi*has query budget* (*~q;q*2)*. Further, T*(*A*prf) *T* (*A*) *T* (*A*)*.*

A detailed proof is given in AppendixB. It proceeds via a sequence of games, starting with the real world po-prf POPRF () and rst transitioning to a game that replaces the NIZK with one generated by the NIZK simulator S. Then we change how Ev queries are handled. Instead of computing the POPRF using *sk*, we pick a random value and add it to a table *R*. We also modify the handling of H₂ queries to check if *R* has been set on a relevant value and, if so, patch up H₂’s response so that it maintains consistency. This does not change the distribution of responses to the adversary. Finally, we are in position to perform a reduction to *A*prf*;*0 (*q*H1*;q*H3)-OM-Gap-SDHI: the only dierence between this game and the ideal world POPRF 3H*;*P*;*S[S] () is when H₂ needs to repair a *R* value more often than queries to BlindEv. This reduction step is made relatively simple by our new assumption, which provides the values and oracles necessary to simulate *A*prf’s view in a straightforward way. We can combine the two main theorems with a standard result about the NIZK that we use (restated in Section2) to give the following corollary.

Corollary 5 *Let A*prf*be a* P*-model POPRF adversary against* 3H *with query budget* (*m;n; q*E*; ~q; q*H1*; q*H2*;* *q* H3*; q*H4) *and* GGen *any group parameter generator outputting* (*p;g;* G)*, where p is a prime g is a uniformly* *chosen element of* G*. Then, we give adversary A*dl*such that* <u>q + n² 3q² + q(q + 4) + 2</u> po-prf (*q*+1)-dl <u>H₄</u> Adv 3H*;*S[S]*;*P*;A*prf () (*q*max+ 1) Adv GGen*;A*dl () + +*;* *p* 2 P*n* *n* *where q* =*iqi, q*max= max*fqigi. Further,* S *is the simulator dened in Figure10that makes use of NIZK* *simulator* S*, and T*(*A*prf) *T* (*A*dl)*.*

Concrete security and parameter selection. Corollary5is interpreted best in the generic-group model (GGM) [Sho97,Mau05], as this yields an absolute bound in terms of *A*prf’s resources. The advantage of a generic algorithm *A*dlrunning in time *T* (or more precisely, making *T* queries to the generic-group oracle) (*q*+1)-dl 2 against (*q* + 1)-DL in a group of order *p* is Adv GGen*;A*dl () (*T* + *q* + 2) (*q* + 1)*=*(*p* 1) (see, e.g., [BFL20] for a proof). This advantage is multiplied by *q*maxto obtain the dominating term in our nal bound. We conjecture however that the bound is somewhat pessimistic, and that the factor *q*maxis an artifact of the proof. In fact, as we discuss below, a dierent interpretation of our proof ow, which is particularly meaningful in the GGM, avoids this factor altogether. This improved bound omitting *q*maxis also essentially p tight, since Cheon’s attack [Che06] extracts³ the secret key from *q* BlindEval queries in time *p=q*, as long as *q* divides *p* 1 or *p* + 1.

Dene *x* = (*sk* + H (*t*)) for some xed *t*. Then, the attacker can just obtain, via consecutive iterative queries, the values *x x xq* *g;g;:::;g*, and then recover *x* via Cheon’s attack. Finally, *sk* = *x* H (*t*).

Cheon’s attack can therefore guide parameter selection, as is also done for 2HashDH deployments. For example, a 256-bit group may be sucient to achieve security for up *T* = 2 80, as this would still accommodate up to *q* 2 96 blind evaluations without violating our bounds. In contrast, to ensure security up to *T* = 2 128, moving to a 384-bit curve appears necessary. The conclusion being that our choice of parameters is consistent with that for 2HashDH, meaning we achieve the same group operation performance while adding public inputs. We also note that our reduction to the uber assumption requires the generator to be uniformly chosen. We cannot envision any security issues when the generator is instead xed, and the need for uniformly chosen generators is likely just an artifact of our proof technique.

Tighter GGM bound. We only sketch the main idea behind the tighter GGM proof, as it is the result of a minor modication of our AGM proof ow. First, note that the (*q*max+ 1) factor in Corollary5is inherited from Theorem2and is due to our inability to *eciently* nd, within the adversary *A*uber, a good index *j 2* [*‘*] that leads to a break of the uber-assumption. Therefore, we are left with guessing. However, an alternative is to nd such *j* by computing all *‘* possible polynomials (*X~*), and outputting the one which is independent from those input to Ev. Unfortunately, this is computationally expensive, and requires time at least (*q*max 2 ). In other words, we could make the proof tight with respect to advantage while losing tightness with respect to time complexity. While in our proof ow this needs to be taken into account, in the GGM only the number of group operations matters (i.e., the number of oracle calls), whereas \additional" running time is for free. Thus, if *A*prfmakes *T* queries to its GGM oracles, our proof ow yields (with the proposed modication) an adversary *A*dlwith roughly the same number of GGM queries and advantage against (*q* + 1)-DL.

## 5.2 Request Privacy

We now turn to request privacy, which is simpler to analyze. Intuitively, 3HashSDHI client requests leak no information because the blinding makes them independent of other requests and nalized outputs. The following theorem formalizes this for the case of POPRIV1 for the non-veriable version of 3HashSDHI.

Theorem 6 *For any* POPRIV1 *adversary A*po-priv1*against* 3H *(without client verication) we have that* Adv po-priv1 3H*;A*po-priv1 () = 0*.*

Note that the theorem makes no assumptions about the hash functions or group, instead privacy derives directly from the information-theoretic blinding.

||||A||r|
|---|---|---|---|---|---|
||||3H;b;P|d d|d|
|d r sk|d d|r r sk||||

Proof: Let G be the same as game POPRIV1 () except that we replace (*req; rep*) = (H₁(*x*)*d;* H₁(*x*)*d*) with (*req; rep*) = (*gd;gd*) for *d 2f*0*;* 1*g* and where *r₀;r₁* are the random exponents chosen in the two invocations of 3H*:* Req. Observe that in game G the values returned by Req are independent of the challenge bit *b*. Then we have that h i h i Pr POPRIV1 *A* 3H *;*1 *;*P

()*)* 1 = Pr [ G*)* 1] = Pr POPRIV1
*A* 3H *;*0 *;*P

()*)* 1 *:*
Non-veriable PO-PRFs, including the non-veriable version of 3HashSDHI, cannot achieve our stronger notion of malicious request privacy. The attack is straightforward since the adversary can simply replace one of the two responses with garbage, and determine the challenge bit. In detail for the case of 3H,

|po-priv2||
|---|---|
|=(sk+H (t))|1=(sk+H (t))|

adversary *A* can pick *sk 2* G arbitrarily, let *pk* = *g* *sk*, and then query Req(*pk;t;x₀;x₁*) for some arbitrary *t;x₀;x₁*. It obtains back from the oracle *req; req⁰*, and then parses *req* as a pair (*B;t*). It then queries Fin(*B¹*3*;g*) to get back reply (*y₀;y₁*). It checks if *y₀* = H₂(H₃(*x₀*)3) and returns 0 if so. Otherwise it returns one. This adversary wins with probability 1. The veriable version of 3HashSDHI achieves our stronger notion of malicious request privacy, due to the ZKP forcing the malicious server to respond honestly to blinded requests (relative to the public key being used). The following theorem formalizes this, where we model the hash used by the ZKP as a random oracle, and all other hashes as standard model.

Theorem 7 *Let A*po-priv2*be a* POPRIV2 *adversary in the* P*-model against* 3H *that makes at most q queries* *to* Fin*. We give in the proof below a* Sound *A* NiZK*;R;*H4*adversary B*sound*such that*

Adv po-priv2 3H*;*P*;A*po-priv2 () 4*q* Adv sound NiZK*;R;*H4*;B*sound()) *:* *Further, T*(*B*sound) *T* (*A*po-priv2)*.*

*A*po-priv2*;*1 Proof: Consider game POPRIV2 3H*;*P (). We consider the event that, in the course of the game, a Fin(*j;*(*B₁* *0* *;*1)*;* (*B₂* *0* *;*2)) query is made such that either

*0* 1*=*(*sk*+H₃(*tj*) H₄ H₃(*tj*) *0*

1. *B₁ 6*= *B* *j;b*
but*R:* Ver ((*g;g pkj;B₁;Bj;b*)*;*1) = 1; or

*0* 1*=*(*sk*+H₃(*tj*) H₄ H₃(*tj*) *0*

2. *B₂ 6*= *B* *j;*1 *b*
but*R:* Ver ((*g;g pkj;B₂;Bj;*1 *b*)*;*2) = 1.

Here *pkj;tj*are the values queried to the *j* *th* call to Req and we let *skj*= dlog*gpkj*. Recall that here *R* = *f*(*g;U;V;W*)*;* () : *U* = *g ^ W* = *V g*, and verication is therefore checking, in case (1), that *0* H₃(*tj*)+*skj 0* 1*=*(*skj*+H₃(*tj*)) *B₂* = *B* *j;b* *,* (*B₂*) = *Bj;b*

and a similar equality for case (2). So if this event occurs, this means the adversary has violated the soundness of the ZKP: only a single value = *skj*+ H₃(*tj*) can be the witness for *R*. *A*po-priv2 To formally reduce to ZKP soundness, rst let game G0 be the same as POPRIV2 3H*;*P*;b* () but the bit *b* is chosen at random from *f*0*;* 1*g*. Let \G0*) b*" be the event in game G0 that the game returns the value *b*. (We use this event notation for subsequent games analogously.) Further we let G0badbe the same as G0 except that within each Fin it rst computes *skj*= dlog*gpkj*and checks if conditions (1) and (2) hold. If either does not, then it sets a ag bad. Clearly G0badis not computationally ecient; our reduction will avoid this computationally inecient step. Finally we let G1 be the same as game G0 except that all *0 0 skj* Fin(*j; rep; rep*) queries are handled by rst replacing *rep* and *rep* with the correct values, i.e., *rep B* *j;b* *0 skj* and *rep B* *j;*1 *b* where *skj*dlog*g*(*pkj*). Notice that G0badand G1 are identical until the rst query, if any, that sets the ag bad. We have that

Adv po-priv2 3H*;*P*;A*po-priv2 () = 2 Pr [ G0*) b*] 1 *:*

and that

Pr [ G0*) b*] = Pr [ G0bad*) b*] Pr [ G1*) b*] + Pr [ G0badsets bad]*;*

where the inequality comes from the fact that G0badand G1 are identical-until-bad and application of the fundamental lemma of game playing [BR06]. We now bound the probability that Pr[G0badsets bad] via reduction to the soundness of the ZKP.

Adversary *B*soundworks as follows. First, it randomly chooses a number *q 2* [1*;* 2*q*] to serve as its guess for which ZKP will be forged by the adversary. Here *q* is the maximum number of Fin queries made by *A*po-priv2 sound po-priv2has

|; each such query includes two proofs.|||Then|B|runs G0,|stopping when A|||
|---|---|---|---|---|---|---|---|---|
||||sound|||H (t)|j 0 j;b|1|
|H (t)|j 0 j;1|b 2||sound|||j||
||||||j||||
|||bad||sound NiZK;R;P;B po-priv2|||||

made *j* = *dq =*2*e* queries to Fin. At this point, *B*soundstops outputting ((*g;g* H3 (*tj*) *pkj;B₁* *0* *;Bj;b*)*;*1) if *q* is odd and ((*g;g*3 *jpk;B₂;B*)*;*) otherwise. Adversary *B* avoids computing *sk*; it simply guesses which of the proofs would have caused bad to be set to true, had *sk* been computed and the conditions (1) and (2) been checked. A standard argument yields that

Pr [ G0 sets bad] 2*q* Adv sound () *:*

To nish the proof, we can observe that G1 always correctly computes responses, and a similar argument as we used for POPRIV1 gives that the transcript observed by *A* is independent of the challenge bit *b*, and so Pr[G1*) b*] = 1*=*2. Combining all the above yields the advantage statement in the theorem.

|Scheme|L (B) T (B)|KeyGen|KeyVerify|Req|BlindEv|Finalize|Ev|
|---|---|---|---|---|---|---|---|
|2HashDH|16|1|0|0 73|222|392|77|
|2HashDH|16|8|0|0 75|229|404|79|
|2HashDH|16|64|0|0 84|256|447|89|
|3HashSDHI|16|1|0|0 85|369|527|125|
|3HashSDHI|16|8|0|0 76|334|477|112|
|3HashSDHI|16|64|0|0 75|328|471|110|
|Pythia|16|1|168|0 849|4068|6070|2871|
|Pythia|16|8|180|0 831|4099|6092|2881|
|Pythia|16|64|171|0 809|3922|5849|2768|
|ABVOPRF|16|1|294|292 74|517|684|370|
|ABVOPRF|16|8 1910|2386|76|2135|2789|1981|
|ABVOPRF|16|64 15053|19196|80|15305|19702|15163|

Table 1: Average operation time for various POPRF protocols. All times are measured in s, and a zero time

represents some value much less than a single microsecond.

# 6 Performance Evaluation

We implemented 3HashSDHI to measure the computational cost of the protocol in comparison to related protocols, including the baseline 2HashDH VOPRF from [DFHSW20], Pythia [ECS + 15], and the recent attribute-based VOPRF (ABVOPRF) from Facebook [HIJ + 21]. Each protocol was implemented in a minimal fashion, e.g., by omitting domain separating hash function invocations, in order to emphasize the cost of core public key operations. Our implementations use the ristretto255 group [dVGT + 20] where prime-order groups are required, and the bn256 curve for Pythia, where pairing-friendly curves are required. We implemented each protocol in Go using the CIRCL experimental cryptographic library [FHK19] and bn256 package. These benchmarks were evaluated on a machine with a 2.6 GHz 6-Core Intel Core i7 CPU and 32 GB RAM running macOS 10.15.7. Below we report on the average time over 1000 measurements of each operation. Our benchmarks prole the functions needed to congure a client for the protocol, including the KeyGen and KeyVerify (for ABVOPRF), as well as the functions used to carry out the protocol, including Req, BlindEv, and Finalize. We also proled the FullEvaluation routine to compare the cost of the blinding and proof verication operations in the protocol. For each protocol scheme, we keep the input size (*L*) xed but vary the metadata size (*T*) in bytes. The results of our analysis are given in Table1. We comment on two key results in this data. First, the dierence between the baseline VOPRF protocol and POPRF protocol are minuscule (as a function of metadata size). In particular, the POPRF introduces approximately a 25% overhead (in terms of s to compute), though this is likely negligible at scale. Second, there is nearly an order of magnitude dierence between the POPRF and the ABVOPRF as a function of metadata size. This is primarily due to the online KeyGen process and its resulting linear cost in proof evaluation. This suggests that the POPRF construction scales better in the presence of arbitrary-size tag values. Some of the protocols included allow certain operations to be computed oine, thereby improving online protocol performance. For example, if the tag value is known in advance, 3HashSDHI can pre-compute the private key used in the BlindEv call. Likewise, in the ABVOPRF protocol, the key generation and verication operations can be computed oine and clients can cache the results. Table2summarizes the cost of operations, discounting precomputation costs. Note that although the performance of the ABVOPRF construction improves, it still introduces substantially more overhead than the 3HashSDHI construction.

# 7 Applications

POPRFs provide a new degree of exibility that we observe to be useful in a variety of applications. Essen- tially anywhere an OPRF is used we see opportunity for POPRFs to provide potential benets in terms of increasing deployment exibility, reducing key management challenges, and/or improving security. Here we

|Scheme|T (B) Request|Evaluate||Finalize|Ev|
|---|---|---|---|---|---|
|2HashDH|1|73|223|392|77|
|2HashDH|8|75|231|403|79|
|2HashDH|64|83|255|447|89|
|3HashDH|1|84|367|526|124|
|3HashDH|8|76|332|478|112|
|3HashDH|64|76|328|472|110|
|Pythia|1|847|3913|6074|2832|
|Pythia|8|824|3935|6085|2840|
|Pythia|64|806|3764|5843|2715|
|ABVOPRF|1|74|224|685|77|
|ABVOPRF|8|76|228|2790|79|
|ABVOPRF|64|75|230|19721|80|

Table 2: Average times for performance, excluding precomputation cost. All times are measured in s.

briey discuss three previously mentioned motivating applications: anonymous one-time-use tokens, pass- word breach alerting, and password-based authenticated key exchange.

## 7.1 Privacy Pass

Privacy Pass [DGS + 18,CDFH21] is a protocol in which users are allowed to receive one-time-use anonymous tokens, using an issuance protocol, that can later be used to anonymously authenticate themselves using a redemption protocol. It is often used in the context of fraud prevention online: tokens are issued to users that pass integrity challenges (e.g., CAPTCHA). The primary component underlying Privacy Pass is a veriable OPRF (VOPRF). Current implemen- tations use 2HashDH [JKK14]. The issuance protocol has a client request VOPRF output for a random input *x* under a Privacy Pass server held VOPRF secret key *sk*. The client must verify that the received token *y* = 2HashDH*:* Ev(*sk;x*) is correct relative to the server’s public key *pk*. A token (*x;y*) can then be redeemed by sending to the server (*x;* MAC*y*(*data*)) where MAC is a message authentication code such as HMAC and *data* is some application-specic bit string (called the binding data in [DGS + 18]). The server can recompute *y* and then use it to check the MAC value. The core security properties achieved by Privacy Pass are unlinkability and unforgeability. Unlinkability derives from the request privacy properties of the VOPRF, which ensures that a malicious server learns nothing about a client’s input *x* nor can they link (*x;y*) to a particular issuance query. Unforgeability derives from the pseudorandomness security of the VOPRF: given the ability to obtain *q* tokens, the adversary can at most compute *q* outputs of the VOPRF. However, one abuse of Privacy Pass not prevented by the current design is what we refer to as a hoarding attack, also called a farming attack [DGS + 18]. A malicious user (or group of users) can gather a large number of tokens by running the token issuance protocol as many times as possible over some period of time. Later, the malicious user can redeem all the gathered tokens at once in an eort to render the provided service unavailable in a (D)DoS attack (by, for example, overwhelming a website with expensive requests). One potential defense against hoarding attacks is to force periodic rotation of the VOPRF secret key, such as once per week. But this is clumsy because it requires clients to verify that key rotations are made legitimately: a server that rotates too often can violate unlinkability. In the limit, a malicious server could pick a separate *pk* for each client issuance, thereby completely violating unlinkability. Forcing clients to use gossip protocols (to verify that the same public keys are used) or using public ledgers to record public keys for monitoring purposes require further complicating infrastructure. Furthermore, keys are often stored and need to be deleted from secure storage locations (e.g., trusted hardware) and replaced with new ones. This process is prone to failure and can lead to potential leaks. Use of a veriable POPRF provides a simpler, more elegant solution. Tokens can be bound to a public input *t* that lets the server and client agree upon a scope for token issuance. In this case, one replaces

the Privacy Pass’ 2HashDH*:* Ev(*sk;x*) with DY*:* Ev(*sk;t;x*) in both the issuance and redemption phases. One could use as *t* a coarse timestamp, such as the current day or week at which an issuance occurred, and then redemption could enforce a policy about the staleness of tokens, forcing them to be redeemed within some time period. Alternatively, one could imagine using *t* to bind issuance and redemption to the client’s general network location, e.g., it’s autonomous system number (ASN). We note that all these hoarding mitigations reduce the anonymity set of a redemption to only the clients issued tokens under *t*. This is true also for the key rotation approach, reducing the anonymity set to clients that were issued tokens under the particular public key. Some loss of privacy is fundamental to restricted token use, and choosing how to make use of *t* requires care and further work to identify best practices. Nevertheless, POPRFs provide a degree of exibility that easily allows a variety of choices.

## 7.2 Private Set Membership and Breach Alerting

One widely deployed use of OPRFs is for password breach alerting (also called compromised credential checking) [TPY + 19,Hun]. These use an OPRF-based bucketized private set membership protocol [TPY + 19, LPA + 19] that works as follows. The server generates a long-lived 2HashDH secret key *sk* and computes *y* *u;pw*= 2HashDH*:* Ev(*sk;u;pw*) for each username, password pair (*u;pw*) *2 D*. Here *D* is a breach database of known-compromised pairs. Then, to perform a lookup for (*u ;pw*), the client sends a truncated hash of the username that forms a bucket identier = H(*u*), as well as a blind evaluation request for the client’s username, password pair (*u ;pw*) that they want to check. The server computes the OPRF response and sends it back along with the bucket *B* = *fyu;pwj* H(*u*) = *g* of values that have matching truncated username hash. The client nishes computing *y* = 2HashDH*:* Ev(*sk;u ;pw*) and checks if *y 2 B*. If so, their credential is known to be compromised; otherwise, it is not. In the currently deployed protocols, there is no way to enforce that the client’s query indicates the correct bucket identier *B*. Instead, they could query for *b⁰* = H(*u⁰*) for *u⁰ 6*= *u* and complete the protocol execution checking for values in some other bucket. Whether this opens up password breach alerting services to abuse is not clear. Nevertheless, we observe that replacing the OPRF with a POPRF provides a simple way to cryptograph- ically bind the buckets to particular bucket identiers, by setting *t* =. One could similarly do so using per-bucket secret keys *sk* for a standard OPRF, but this would complicate key management.

## 7.3 OPAQUE

As mentioned in the introduction, OPAQUE [JKX18] is a strong aPAKE protocol (SaPAKE) that provides password-based mutual authentication in a client-server setting without having to rely on Public Key Infras- tructure (PKI). It provides security against pre-computation attacks upon server compromise, and increases the protection against oine dictionary attacks, as an attacker will have to perform an exhaustive per-user attack upon server’s data compromise. OPAQUE is a protocol also amenable to a multi-server distributed implementation where an oine dictionary attack is only possible if a threshold of servers is compromised. OPAQUE can be thought of as a protocol that works as a \compiler" by transforming a suitable AKE protocol (resistant to key compromise impersonation attacks and forward secrecy) into a secure aPAKE protocol using an OPRF. Current implementations use 2HashDH. It consists of two phases: an oine registration phase and an online authenticated key exchange phase. The purpose of the oine phase is to register a user’s account using their unique user identity and their password. The user identity could be a username or email address. To do so, the user opaquely registers its password without the server ever knowing it. The client and server obliviously compute rwd = 2HashDH*:* Ev(*sku;x*), where *x* is the user’s password and *sku*is a server’s random, per-user generated OPRF secret key. The output of this functionality, rwd, is used to encrypt its AKE private key. The resulting ciphertext is stored on the server-side alongside with other user’s credentials, such as its corresponding user id. The server will store, as well, the per-user OPRF key *sku*used to generate rwd. To perform online authentication, the client and server obliviously recompute rwd, enabling the client to recover their AKE private key by decrypting the ciphertext (sent back to the client during the OPRF ows), and complete a (now password-authenticated) AKE exchange.

A complexity for deployment of OPAQUE is that the server has to maintain and keep a consistent view of the per-user OPRF keys and associated AKE private key ciphertexts. Implementation vulnerabilities may arise should servers incorrectly use the same OPRF key across multiple users, allowing potentially for cross- user attacks that allow logging in as the wrong user. Implementations are also likely to store the per-user OPAQUE secret keys in the same user database alongside other per-user data, meaning that compromises that allow exltrating the database (e.g., SQL injection) will reveal all information needed to brute-force recover passwords. One potential approach instead would be to, again, replace the per-user OPRF key *sku*with a POPRF with global *sk* and use the user identity as *t*. This would allow protecting *sk* by storing it in a separate hardened crypto service (similar to deployment models used in password hardening, see [ECS + 15]) only once. One potential complication is that performing periodic key rotations for *sk* would be more challenging, since it would require somehow either resetting all users passwords (not reasonable in most contexts by asking users to reset) or rolling clients to new keys as they login by maintaining old *sk* for some period of time. In contrast, the per-user *sku*approach can selectively rotate OPRF keys for each user as needed.

# Acknowledgments

The authors would like to thank Tjerand Silde and Martin Strand for discussions about their preprint.

# References

[AF96]Masayuki Abe and Eiichiro Fujisaki. How to date blind signatures. In *ASIACRYPT*, volume 1163 of *Lecture Notes in Computer Science*, pages 244{251. Springer, 1996.

[AO00]Masayuki Abe and Tatsuaki Okamoto. Provably secure partially blind signatures. In *CRYPTO*, volume 1880 of *Lecture Notes in Computer Science*, pages 271{286. Springer, 2000.

[BFL20]Balthazar Bauer, Georg Fuchsbauer, and Julian Loss. A classication of computational as- sumptions in the algebraic group model. In *CRYPTO (2)*, volume 12171 of *Lecture Notes in* *Computer Science*, pages 121{151. Springer, 2020.

[BFP21]Balthazar Bauer, Georg Fuchsbauer, and Antoine Plouviez. The one-more discrete logarithm assumption in the generic group model. *IACR Cryptol. ePrint Arch.*, 2021:866, 2021.

[BLL + 21]Fabrice Benhamouda, Tancrede Lepoint, Julian Loss, Michele Orru, and Mariana Raykova. On the (in)security of ROS. In *EUROCRYPT (1)*, volume 12696 of *Lecture Notes in Computer* *Science*, pages 33{53. Springer, 2021.

[BM93]Steven Bellovin and Michael Merritt. Augmented encrypted key exchange: a password based protocol secure against dictionary attacks and password le compromise. In *CCS*, pages 244{

250. ACM, 1993.
[BNPS03]Mihir Bellare, Chanathip Namprempre, David Pointcheval, and Michael Semanko. The one- more-rsa-inversion problems and the security of chaum’s blind signature scheme. *J. Cryptol.*, 16(3):185{215, 2003.

[Bol03]Alexandra Boldyreva. Threshold signatures, multisignatures and blind signatures based on the gap-die-hellman-group signature scheme. In *Public Key Cryptography*, volume 2567 of *Lecture* *Notes in Computer Science*, pages 31{46. Springer, 2003.

[BR06]Mihir Bellare and Phillip Rogaway. The security of triple encryption and a framework for code-based game-playing proofs. In *EUROCRYPT*, volume 4004 of *Lecture Notes in Computer* *Science*, pages 409{426. Springer, 2006.

[BS17]Dan Boneh and Victor Shoup. *A Graduate Course in Applied Cryptography*. 2017. Version 0.4.

[Cam98]Jan Camenisch. *Group signature schemes and payment systems based on the discrete logarithm* *problem*. PhD thesis, ETH Zurich, Zurich, Switzerland, 1998.

[CDFH21]Soa Celi, Alex Davidson, and Armando Faz-Hernndez. Privacy Pass Protocol Specication. Internet-Draft draft-ietf-privacypass-protocol-00, Internet Engineering Task Force, January

2021. Work in Progress.
[Che06]Jung Hee Cheon. Security analysis of the strong die-hellman problem. In *EUROCRYPT*, volume 4004 of *Lecture Notes in Computer Science*, pages 1{11. Springer, 2006.

[CL04]Jan Camenisch and Anna Lysyanskaya. Signature schemes and anonymous credentials from bilinear maps. In *CRYPTO*, volume 3152 of *Lecture Notes in Computer Science*, pages 56{72. Springer, 2004.

[CMZ14]Melissa Chase, Sarah Meiklejohn, and Greg Zaverucha. Algebraic macs and keyed-verication anonymous credentials. In *CCS*, pages 1205{1216. ACM, 2014.

[CP92]David Chaum and Torben P. Pedersen. Wallet databases with observers. In *CRYPTO*, volume 740 of *Lecture Notes in Computer Science*, pages 89{105. Springer, 1992.

[CPZ20]Melissa Chase, Trevor Perrin, and Greg Zaverucha. The signal private group system and anonymous credentials supporting ecient veriable encryption. In *CCS*, pages 1445{1459. ACM, 2020.

[CS03]Jan Camenisch and Victor Shoup. Practical veriable encryption and decryption of discrete logarithms. In *CRYPTO*, volume 2729 of *Lecture Notes in Computer Science*, pages 126{144. Springer, 2003.

[DFHSW20]Alex Davidson, Armando Faz-Hernndez, Nick Sullivan, and Christopher A. Wood. Oblivious Pseudorandom Functions (OPRFs) using Prime-Order Groups. Internet-Draft draft-irtf-cfrg- voprf-05, Internet Engineering Task Force, November 2020. Work in Progress.

[DGS + 18]Alex Davidson, Ian Goldberg, Nick Sullivan, George Tankersley, and Filippo Valsorda. Privacy pass: Bypassing internet challenges anonymously. *Proc. Priv. Enhancing Technol.*, 2018(3):164{ 180, 2018.

[dVGT + 20]Henry de Valence, Jack Grigg, George Tankersley, Filippo Valsorda, Isis Lovecruft, and Mike Hamburg. The ristretto255 and decaf448 Groups. Internet-Draft draft-irtf-cfrg-ristretto255- decaf448-00, Internet Engineering Task Force, October 2020. Work in Progress.

[DY05]Yevgeniy Dodis and Aleksandr Yampolskiy. A veriable random function with short proofs and keys. In *Public Key Cryptography*, volume 3386 of *Lecture Notes in Computer Science*, pages 416{431. Springer, 2005.

[ECS + 15]Adam Everspaugh, Rahul Chatterjee, Samuel Scott, Ari Juels, and Thomas Ristenpart. The pythia PRF service. In *24th USENIX Security Symposium (USENIX Security 15)*, pages 547{

562. USENIX Association, 2015.
[FHK19]Armando Faz-Hernndez and Kris Kwiatkowski. *Introducing CIRCL: An Advanced Crypto-* *graphic Library*. Cloudare, June 2019. https://github.com/cloudflare/circl.

[FIPR05]Michael J. Freedman, Yuval Ishai, Benny Pinkas, and Omer Reingold. Keyword search and oblivious pseudorandom functions. In *TCC*, volume 3378 of *Lecture Notes in Computer Science*, pages 303{324. Springer, 2005.

[Fis06]Marc Fischlin. Round-optimal composable blind signatures in the common reference string model. In *CRYPTO*, volume 4117 of *Lecture Notes in Computer Science*, pages 60{77. Springer,

2006.

[FKL18]Georg Fuchsbauer, Eike Kiltz, and Julian Loss. The algebraic group model and its applications. In *CRYPTO (2)*, volume 10992 of *Lecture Notes in Computer Science*, pages 33{62. Springer,

2018.
[FPS20]Georg Fuchsbauer, Antoine Plouviez, and Yannick Seurin. Blind schnorr signatures and signed elgamal encryption in the algebraic group model. In *EUROCRYPT (2)*, volume 12106 of *Lecture* *Notes in Computer Science*, pages 63{95. Springer, 2020.

[HIJ + 21]Sharon Huang, Subodh Iyengar, Sundar Jeyaraman, Shiv Kushwah, Chen-Kuei Lee, Zutian Luo, Payman Mohassel, Ananth Raghunathan, Shaahid Shaikh, Yen-Chieh Sung, and Albert Zhang. PrivateStats: De-Identied Authenticated Logging at Scale, January 2021.

[HKL19]Eduard Hauck, Eike Kiltz, and Julian Loss. A modular treatment of blind signatures from identication schemes. In *EUROCRYPT (3)*, volume 11478 of *Lecture Notes in Computer* *Science*, pages 345{375. Springer, 2019.

[Hun]Troy Hunt. Have i been pwned. https://haveibeenpwned.com/.

[JKK14]Stanislaw Jarecki, Aggelos Kiayias, and Hugo Krawczyk. Round-optimal password-protected secret sharing and T-PAKE in the password-only model. In *ASIACRYPT (2)*, volume 8874 of *Lecture Notes in Computer Science*, pages 233{253. Springer, 2014.

[JKX18]Stanislaw Jarecki, Hugo Krawczyk, and Jiayu Xu. OPAQUE: an asymmetric PAKE protocol secure against pre-computation attacks. In *EUROCRYPT (3)*, volume 10822 of *Lecture Notes* *in Computer Science*, pages 456{486. Springer, 2018.

[JKX21]Stanislaw Jarecki, Hugo Krawczyk, and Jiayu Xu. On the (in)security of the die-hellman oblivious PRF with multiplicative blinding. In *Public Key Cryptography (2)*, volume 12711 of *Lecture Notes in Computer Science*, pages 380{409. Springer, 2021.

[JL09]Stanislaw Jarecki and Xiaomin Liu. Ecient oblivious pseudorandom function with applications to adaptive OT and secure computation of set intersection. In *TCC*, volume 5444 of *Lecture* *Notes in Computer Science*, pages 577{594. Springer, 2009.

[JT20]Joseph Jaeger and Nirvan Tyagi. Handling adaptive compromise for practical encryption schemes. In *CRYPTO (1)*, volume 12170 of *Lecture Notes in Computer Science*, pages 3{32. Springer, 2020.

[KLOR20]Ben Kreuter, Tancrede Lepoint, Michele Orru, and Mariana Raykova. Anonymous tokens with private metadata bit. In *CRYPTO (1)*, volume 12170 of *Lecture Notes in Computer Science*, pages 308{336. Springer, 2020.

[KLW21]Hugo Krawczyk, Kevin Lewi, and Christopher A. Wood. The OPAQUE Asymmetric PAKE Protocol. Internet-Draft draft-irtf-cfrg-opaque-02, Internet Engineering Task Force, February

2021. Work in Progress.
[KZ08]Aggelos Kiayias and Hong-Sheng Zhou. Equivocal blind signatures and adaptive uc-security. In *TCC*, volume 4948 of *Lecture Notes in Computer Science*, pages 340{355. Springer, 2008.

[LPA + 19]Lucy Li, Bijeeta Pal, Junade Ali, Nick Sullivan, Rahul Chatterjee, and Thomas Ristenpart. Protocols for checking compromised credentials. In *CCS*, pages 1387{1403. ACM, 2019.

[Mau05]Ueli M. Maurer. Abstract models of computation in cryptography. In Nigel P. Smart, editor, *Cryptography and Coding, 10th IMA International Conference, Cirencester, UK, December 19-* *21, 2005, Proceedings*, volume 3796 of *Lecture Notes in Computer Science*, pages 1{12. Springer,

2005.
[MPR + 20]Peihan Miao, Sarvar Patel, Mariana Raykova, Karn Seth, and Moti Yung. Two-sided malicious security for private intersection-sum with cardinality. In *CRYPTO (3)*, volume 12172 of *Lecture* *Notes in Computer Science*, pages 3{33. Springer, 2020.

[NR97]Moni Naor and Omer Reingold. Number-theoretic constructions of ecient pseudo-random functions. In *FOCS*, pages 458{467. IEEE Computer Society, 1997.

[Sho97]Victor Shoup. Lower bounds for discrete logarithms and related problems. In Walter Fumy, editor, *EUROCRYPT*, volume 1233 of *Lecture Notes in Computer Science*, pages 256{266. Springer, 1997.

[SS21]Tjerand Silde and Martin Strand. Anonymous tokens with public metadata and applications to private contact tracing. *IACR Cryptol. ePrint Arch.*, 2021:203, 2021.

[TPY + 19]Kurt Thomas, Jennifer Pullman, Kevin Yeo, Ananth Raghunathan, Patrick Gage Kelley, Luca Invernizzi, Borbala Benko, Tadek Pietraszek, Sarvar Patel, Dan Boneh, and Elie Bursztein. Protecting accounts from credential stung with password breach alerting. In *USENIX Security* *Symposium*, pages 1556{1571. USENIX Association, 2019.

[WTKW20]John Wilander, Erik Taubeneck, Andrew Knox, and Chris Wood. Consider using blinded signatures for fraud prevention-Private Click Measurement, 2020. https://github.com/ privacycg/private-click-measurement/issues/41.

[ZSS03]Fangguo Zhang, Reihaneh Safavi-Naini, and Willy Susilo. Ecient veriably encrypted sig- nature and partially blind signature from bilinear pairings. In *INDOCRYPT*, volume 2904 of *Lecture Notes in Computer Science*, pages 191{204. Springer, 2003.

[ZSS04]Fangguo Zhang, Reihaneh Safavi-Naini, and Willy Susilo. An ecient signature scheme from bilinear pairings and its applications. In *Public Key Cryptography*, volume 2947 of *Lecture* *Notes in Computer Science*, pages 277{290. Springer, 2004.

# A Security of (m; n)-OM-Gap-SDHI

Proof of Of Theorem2: This proof proceeds in two parts. (1) First, we present *A*uberand argue that it almost perfectly simulates the (*m;n*)-OM-Gap-SDHI game for *A*sdhi, up to a small statistical dierence.

(2) Second, we argue that if *A*sdhioutputs a set of values that wins the (*m;n*)-OM-Gap-SDHI game, it must be that at least one of those values has a non-trivial representation in the exponent that wins the *m*-Uber game.
## A.1 Simulation of (m; n)-OM-Gap-SDHI environment

Q We construct adversary *n qi* *A*uberas shown in Figure9. The adversary rst constructs a polynomial *G*(*X~*) *i*(*X₀* + *ci*) from the chosen *c* values in the rst stage of *A*sdhi. The adversary receives an evaluation *g*^ = *g* *G*(*~x*) from its Ev oracle that it will pass as the generator in its simulation to the second stage of *A*sdhi. The public key ^*g* *x* 0is simulated by evaluating *X₀ G*(*X~*); and the *m* challenge points will each be simulated

with additional variables *Xi*for *i 2* [1*;m*] by evaluating polynomial *XiG*(*X~*).

To simulate the SDH oracle on input (*Y;i*), rst assume that *A*uberknows the polynomial *P* (*X~*) such that *Y* = *g* *P* (*~x*). We will show shortly how *A*ubercan compute *P* (*X~*) from the algebraic representation of *Y*. Given *P* (*X~*), *A*ubersimulates by computing the polynomial *P* (*X~*)*=*(*X₀* + *ci*) and returning its evaluation. Now to compute *P* (*X~*), *A*ubertakes the algebraic representation of *Y* in terms of elements given to *A*sdhi. The elements given to *A*sdhiare the initial elements plus the elements output from previous queries to SDH. The polynomial exponents of all of these elements are known to *A*uber, so they can be combined via the linear combination indicated by the algebraic representation to compute *P* (*X~*). Furthermore, *P* (*X~*)*=*(*X₀* + *ci*) will always be computable due to the construction of *G*(*X~*) including *qi*factors of (*X₀* + *ci*) where *qi*is the maximum number of queries for *ci*to SDH. All initial elements have the polynomial *G*(*X~*) as a factor of the exponent, and while subsequent elements returned from SDH divide out dierent factors of (*X₀* + *cj*), they

<u>Adversary A</u> Ev <u>uber</u> *;*Decide <u>(p;G;g) Oracle SDH(Y;i)</u> (*stA;* [*ci*] *n*

|(st; [c|] Q) A₁(p; G)||||Compute P (X|~ ) : Y = g|from representation of Y||
|---|---|---|---|---|---|---|---|---|
|G(X ~ )|(X₀ + c|)|||Z Ev(P (X|~ )=(X₀ + c|))||
|g ^ Ev(G(X|~ )); X|^ Ev(X₀|G(X ~ ))||Return Z||||
|[A ^]|[Ev(X|G(X ~ ))]|||||||
|(; [Z;|]) A|(^ g; X;|^ [A ^] :Qst|)|Oracle SDDH(Y;Z;i)||||
|j N|; (X ~ ) = X|(X₀ + c|)|(X₀ + c|) P (A₁;A₂;A₃)|(A₁ + c|) A₃|A₂|
|Return (Z|;(X ~ ))||||Return Decide(P (A₁;A₂;A₃); [X;Y;Z||^|])|

*i*) $ *A₁*(*p;* G) Compute *P* (*X~*) : *Y* = *gP* (*~x*)from representation of *Y* *n* *i i*
*qi* *i* *m* *i*=1 *i* *m* *i*=1 *i i* *‘* *i* $ SDH 2 *;*SDDH *m* *i A* $ *‘* *j* *q* 1 *n* *i6*= *i* *qi i*

*j*

Figure 9: Adversary *A*uberin the security proof of (*m;n*)-OM-Gap-SDHI.

never exhaust a factor (*X₀* + *cj*) unless the maximum number of queries for that index has been reached. Lastly, *A*ubersimulates SDDH by passing the query on to its own Decide oracle.

As long as the maximum query counts that *A*uberuses to create *G*(*X~*) are abided by, the environment for *A*sdhiis almost perfectly simulated, as we argue below. Moreover, *A*uberselects an output of *A*sdhiat random and returns it along with its polynomial representation.

Concretely, let0be the probability that at least one of the values in the output of *A*sdhihas a non-trivial representation in the exponent that wins the *m*-Uber game in the original game (*m;n*)-OM-Gap-SDHI. Let1be the probability that the same happens within the simulation of *A*uber. Then, we argue that

<u>q</u> 0 1*:* *p*

This can be seen as follows: The only dierence between the simulation and the original game is that the former uses (^*g; X*^), where ^*g* = *g* *G*(*x*) and *X*^ = *g* *x G*(*x*) for a *x* $ Z*p*and a polynomial *G*(*X*) of degree *q*, instead of (*g;g* *x* ) in the latter, where *g* is a random generator. In particular,0 1is upper bounded by the statistical distance between (*y G*(*x*)*;y x G*(*x*)) and (*y;y x*), where (*x;y*) $ Z²*p*. Now, let *S* Z²*p*be the set pairs (*x;y*) such that *G*(*x*) *6*= 0. For any (*z₁;z₂*) *2* Z²*p*, and (*x;y*) $ *S*, we now have

Pr [ (*y;y x*) = (*z₁;z₂*)] = Pr [ (*y;z₁ x*) = (*z₁;z₂*)] = Pr [ (*y G*(*x*)*;z₁ x*) = (*z₁;z₂*)] = Pr [ (*y G*(*x*)*;y x G*(*x*)) = (*z₁;z₂*)] *:*

Therefore, the statistical distance is upper bounded by the probability that (*x;y*) $ Z*p*is in *S*, which in turn is the probability that *G*(*x*) = 0. The latter is at most *q=p* by the Schwartz-Zippel Lemma.

### In conclusion, the advantage of Auberis

1*q*

||(m+1)-uber|1|0|
|---|---|---|---|
||GGen;A|max|max|
||||max|
|(m;n)-om-gap-sdhi||||
|GGen;A|0|||

Adv uber ()*;* *‘ q* + 1 *q* + 1 *p*(*q*max+ 1)

because, without loss of generality, we can assume that *‘ q* + 1. Below, we are going to prove that Adv sdhi () =, which concludes the proof.

## A.2 Linear independence of winning elements

Next, we argue that one of the strong Die-Hellman values output by a winning *A*sdhicorresponds to a group element with a non-trivial polynomial in the exponent, i.e., a polynomial that is linearly independent from all queried polynomials. Our ultimate goal will be to claim that if the adversary produces *‘* winning group elements for a value *c* having only queried SDH *q < ‘* times, then one of the winning elements must have a non-trivial (linearly-independent) polynomial exponent from all group elements given to the adversary during initialization and as output from SDH.

We will nd that it is easy to argue the linear independence of the initial group elements and winning elements. The main challenge we will face is reasoning about elements output from SDH. In previous

formulations of one-more assumptions [Bol03], the number of winning elements was required to be greater than the number of queries to the \one-more" oracle. In these cases, the typical proof strategy is show linear independence of the set of winning elements and initial elements { since this set is strictly larger than the set of query elements and initial elements, it must be that at least one winning element is linearly independent of the set of query elements and initial elements. However, this strategy will not work for OM-Gap-SDHI, which simply requires the number of winning elements to be greater than the number of queries *for the* *chosen* winning *c*.

Intuitively, we would like to say that elements returned from SDH for other *cj6*=will not be helpful in constructing a winning element for *c*. If this is the case, then we can conclude by arguing that a set of *q < ‘* elements cannot construct a set of *‘* linearly-independent winning elements.

Unfortunately, it is not immediately clear this is the case, as elements that were previously output for queries to *c* may be passed back in to SDH under a dierent *cj*. This leads to the possibility that many elements returned from SDH (*> q*) may have a \dependence" on *c*. The main step in our proof shows that whenever a query to SDH on *ci*is made, the output element can be refactored as an element that only depends on the queried *ci*, regardless of whether the input element includes previous outputs from SDH dependent on other *cj6*=*i*.

Rewriting transcript to separate *ci*dependence in SDH queries. First, we consider the polynomial exponent representation of group elements output from SDH given only queries to a single index *ci*. We will notate the exponent in its quotient form (note that the simulation multiplies all polynomial exponents by a least common multiple to remove quotients). We denote by*i*the *i* *th* output from SDH in which the input may be a linear combination of any previous*j<i*and initial values *X₁;:::;Xm*, where we denote coecients with *a*. In the below we denote *Yi*as arbitrary linear combinations of the formal variables *X₀;X₁;:::;Xm*

||i|||m|
|---|---|---|---|---|
||||i||

along with a constant. Without loss of generality, we will denote *c* = *c₁*.

*Y₁* 1= (binary string representation: 1) *X₀* + *c₁* *Y₂* + *a₂;*1 1*a₂;*1*Y₁ Y₂* 2= =2+ (11, 10) *X₀* + *c₁* (*X₀* + *c₁*) *X₀* + *c₁* <u>Y₃ + a₃;2 2+ a₃;1 1</u> 3= *X₀* + *c₁* *a₃;*2*a₂;*1*Y₁ a₃;*2*Y₂ a₃;*1*Y₁ Y₃* = 3 + 2 + 2 + (111, 110, 101, 100) (*X₀* + *c₁*) (*X₀* + *c₁*) (*X₀* + *c₁*) *X₀* + *c₁* <u>Y₄ + a₄;3 3+ a₄;2 2+ a₄;1 1</u> 4= *X₀* + *c₁* *a₄;*3*a₃;*2*a₂;*1*Y₁ a₄;*3*a₃;*2*Y₂ a₄;*3*a₃;*1*Y₁ a₄;*3*Y₃* = 4 + 3 + 3 + 2 (1111, 1110, 1101, 1100) (*X₀* + *c₁*) (*X₀* + *c₁*) (*X₀* + *c₁*) (*X₀* + *c₁*) *a₄;*2*a₂;*1*Y₁ a₄;*2*Y₂ a₄;*1*Y₁ Y₄* + 3 + 2 + 2 + (1011, 1010, 1001, 1000) (*X₀* + *c₁*) (*X₀* + *c₁*) (*X₀* + *c₁*) *X₀* + *c₁*

We observe that each term in*i*can be interpreted interpreted uniquely as mapping from a binary string. This leads us to the following closed form expression. We dene*!*(*s*) to take a positive integer *s* and return the list of indices at which the binary string representation of *s* has a 1. For example, 6 = 110 has *!*(6) = [3*;*2] (we use 1-indexing and reverse the list to make the expression below easier to parse). We dene the mapping of positive integer *s* to term in*i*as (*s*) (dened below). The coecients for the term are determined by the locations of the 1-bits in the binary string and the power of the denominator is determined by the number of 1-bits in the string. The *Yj*value is determined by the least signicant 1-bit set in the string. Intuitively, the locations of the 1-bits correspond to which queries to SDH the term has been passed

### (and repassed) into.

8 > > <u>Ylg(s)+1</u> if *9 i* s.t. *s* = 2 *i* < *X* + *c* 0 1Q

(*s*) = *j!*(*s*)*j*1 (1) > > <u>Y!(s)</u>
<u>j!(s)j k=1</u> <u>a!(s)k;!(s)k+1</u> : o.w. (*X₀* + *c₁*)*j!*(*s*)*j*

Then, we observe that the terms included in*i*correspond to the terms for binary strings 2 *i* 1 to 2 *i*

1. We
get the following expression for*i*based on the above interpretation:

P*i* 1 <u>Yi+j=1ai;j j</u> *i*= *X₀* + *c₁* 2 X *i*1 = (*s*) (2) *s*=2*i* 1

The above form follows from an induction argument on the form of all*j<i*. Multiplying*j*by *ai;j=*(*X₀*+*c₁*) corresponds exactly to transforming all (*s⁰*) for *s⁰ 2* [2 *j* 1 *;* 2 *j* 1] to (*s*) for *s 2* [2 *i* 1 + 2 *j* 1 *;* 2 *i* 1 + 2 *j* 1]. Summing up the terms performing this transformation on all*j<i*corresponds to all *s 2* [2 *i* 1 + 1*;* 2 *i* 1], and the nal term corresponding to *s* = 2 *i* 1 is added separately.

Lastly, we rearrange the terms of*i*grouping them by *Yj*which will be useful later on:

2 X *i*1

*i*= (*s*) *s*=2*i* 1 X *i* 1 2*i*X¹*j* = (2 *i* 1 ) + (2 *j* *s* + 2 *j* 1 ) *j*=1 *s*=2*i j* 1

X *i* 1 2*i*X*j*1 *Y* Q*j!*(2*js*+2*j* 1)*j*1 *a j j* 1 *j j* 1 *Yi j k*=1*!*(2 *s*+2)*k;!*(2 *s*+2)*k*+1 = + *j!*(2*js*+2*j* 1)*j*

(3)
*X₀* + *c₁* *j*=1*i j* 1 (*X₀* + *c₁*) *s*=2

Next, we consider a query made to a dierent *cj6*=1, following a transcript of *m* queries = [*i*] *m* *i*=1made to *c₁*. Without loss of generality, we will denote *cj*= *c₂*. This (*m*+ 1) *th* query output takes the following form: P*m* <u>Ym+1+i=1am+1;i i</u> ^ *m*+1= *X₀* + *c₂* The above is the same as*m*+1(Equation2) except the numerator is divided by (*X₀*+*c₂*) instead of (*X₀*+*c₁*). Thus, we can rewrite using the same binary string notation (again, grouped by *Yj*):

P*m* <u>Ym+1+i=1am+1;i iX₀ + c₁</u> ^ *m*+1= =*m*+1 *X₀* + *c₂ X₀* + *c₂* 0 *i* 1 2 X¹ <u>X₀ + c₁</u> @ = (*s*)A *X₀* + *c₂* *i* 1 *s*=2 0 *i j* 1 X *i* 1 2X¹ <u>X₀ + c₁</u> @(2*i* 1 *j j* 1 =) + (2 *s* + 2)A *X₀* + *c₂* *j*=1*i j* 1 *s*=2

X *m* 2*m*X*j*+11 *Y* Q*j!*(2*js*+2*j* 1)*j*1 *a j j j j* <u>Ym+1</u> *j k*=1*!*(2 *s*+2)*k;!*(2 *s*+2)*k*+1 = + *j!*(2*js*+2*j*)*j* *X₀* + *c₂* *j*=1*m j* (*X₀* + *c₁*) (*X₀* + *c₂*) *s*=2

The query output ^*m*+1is a sum of terms with mixed (*X₀* + *c₁*) and (*X₀* + *c₂*) factors in the denominator. We will show that ^*m*+1to*m* *0* +1of the form: P*m* *0* = <u>Ym+1+i=1biYi</u> *;* (4) *m*+1 *X* + *c* 0 2

for some set of coecients *b₁;:::;bm*, such that the span of the query outputs is preserved:

Claim 8 *We provide* [*bi*] *m* *i*=1*to constructm* *0* +1*(Equation4) such that*

Span([1*;:::;m;* ^*m*+1]) = Span([1*;:::;m;m* *0* +1])*:*

*Proof of Claim:* We choose [*bi*] *m* *i*=1such that ^*m*+1*2* Span([1*;:::;m;m* *0* +1]). This is sucient to complete the claim that the two spans are equivalent. We solve the following system of equations:

X *m* ^ *m*+1=*m*+1 *m* *0* +1+*i i* *i*=1 *m* X+1X*m* <u>Yi</u> =*i*+*i i*(5) *i*=1 *X₀* + *c₂* *i*=1

for unknowns1*;:::;m*+1*;b₁;:::;bm*, or equivalently, when reformulated, for unknowns1*;:::;m;*1*;* *:::;m*+1, where*m*+1=*m*+1and*i6*=*m*+1=*m*+1*bi*. Now consider the expanded Equation5:

X *m* 2*m*X*j*+11 *Y* Q*j!*(2*js*+2*j* 1)*j*1 *a j j* 1 *j j* 1 <u>Ym+1</u> *j k*=1*!*(2 *s*+2)*k;!*(2 *s*+2)*k*+1 + *j!*(2*js*+2*j* 1)*j*1 *X₀* + *c₂* *j*=1*m j* (*X₀* + *c₁*) (*X₀* + *c₂*) *s*=2 0 *i j* Q *j j* 1 1 *m* X+1X*m*X*i* 1 2X¹ *Y* *j!*(2 *s*+2)*j*1 *a j j* 1 *j j* 1 *Yi* @ *Yi j k*=1*!*(2 *s*+2)*k;!*(2 *s*+2)*k*+1 A =*i*+*i*+ *j!*(2*js*+2*j* 1)*j* *i*=1 *X₀* + *c₂* *i*=1 *X₀* + *c₁* *j*=1 *s*=2*i j* 1 (*X₀* + *c₁*)

One approach for solving this equation is by solving each of the partial equations, equating the coecients for a particular *Yi*. The partial equation for *Ym*+1is trivial and is easily solvable by setting*m*+1= 1: <u>Ym+1Ym+1</u> =*m*+1 *X₀* + *c₂ X₀* + *c₂* The other partial equations for 1 *i m* are more complex. We refer to the partial equation for *Yi*as *PEi*, and it is dened as follows:

2 *m* X *i*+11 *Y* Q*j!*(2*is*+2*i* 1)*j*1 *a i i* 1 *i i* 1 *i k*=1*!*(2 *s*+2)*k;!*(2 *s*+2)*k*+1

*m i* (*X₀* + *c₁*)*j!*(2 *is*+2*i* 1)*j*1 (*X₀* + *c₂*) *s*=2 X *m* 2*j*X*i*1 *Y* Q*j!*(2*is*+2*i* 1)*j*1 *a i i* 1 *i i* 1 *i* *Yi iYi i j k*=1*!*(2 *s*+2)*k;!*(2 *s*+2)*k*+1 = + + *j!*(2*is*+2*i* 1)*j* *X₀* + *c₂ X₀* + *c₁* *j*=*i*+1*j i* 1 (*X₀* + *c₁*) *s*=2

Note that *Yi*can be canceled out in *PEi*. We next show that there exists (and that we can solve for) a satisfying assignment of variables [*i*] *m* *i*=1and [*i*] *m* *i*=1 +1 for Equation5through a strong induction argument on the satisability of the partial equations.

*Induction hypothesis. H*(*i*): There exists a satisfying assignment of variables [*j*] *m* *j*=*i*and [*j*] *m* *j*=+1 *i*for the system of equations *PEm;PEm* 1*;:::;PEi*.

Note that *H*(1) implies that Equation5is satisable. We proceed by proving the base case, *H*(*m*), and then proving the induction step showing that *H*(*i* + 1)*) H*(*i*).

*Base case.* We prove *H*(*m*). Consider *PEm*:

*m mam*+1*;m* + = *X₀* + *c₂ X₀* + *c₁* (*X₀* + *c₁*)(*X₀* + *c₂*)

### We solve PEmas follows:

*m*(*X₀* + *c₁*) +*m*(*X₀* + *c₂*) = *am*+1*;m* *m*+*m*= 0 *mc₁* +*mc₂* = *am*+1*;m* <u>am+1;m</u> *m*= *c₁ c₂* <u>am+1;m</u> *m*= *c₂ c₁*

*Induction step.* We prove *H*(*i* + 1)*) H*(*i*). Consider the left hand side of *PEi*. It contains terms for (*m* + 1)-length binary strings, where * is a wildcard for either 0/1:

1 *k* * *m i* *k* 1 *k* 0 *i* 1

Now consider the left hand side of *PEj*for *j > i*. It contains terms for the following binary strings:

1 *k* * *m j* *k* 1 *k* 0 *j i* *k* 0 *i* 1

We observe that if we ip the *i* *th* least signicant bit of the binary strings from *PEj*, we obtain a subset of binary strings from *PEi*. In fact, if we do this for all *PEj*for *m j > i*, we obtain all binary strings from *PEi*except for 1 *k* 0 *m i* *k* 1 *k* 0 *i* 1.

A similar cancellation occurs on the right hand side of the equations. The right hand side of *PEi*contains terms for the *m*-length binary strings: * *m i* *k* 1 *k* 0 *i* 1

And the right hand side of *PEj*for *m j > i* contains terms for the *m*-length binary strings:

* *m j* *k* 1 *k* 0 *j i* *k* 0 *i* 1

Again, we observe that if we ip the *i* *th* least signicant bit of binary strings for all *PEj*, we obtain all binary strings from *PEi*except for 0 *m i* *k* 1 *k* 0 *i* 1.

This leads us to the following approach. We sum up all *PEj*for *m j > i*, transforming each one appropriately to \ip the *i* *th* bit" of all represented binary strings. This sum can then be subtracted from *PEi*to cancel out all terms on the left hand side of the equation except for the term corresponding to 1 *k* 0 *m i* *k* 1 *k* 0 *i* 1, and most terms on the right hand side of the equation except for the term corresponding to 0 *m i* *k* 1 *k* 0 *i* 1 and a set of terms*u*(*X₀* + *c₁*) *m i*+1 in each *PEu*that does not correspond to a binary string.

We create the summed equation: X *m* <u>aj;i</u> *PEj*(6) *j*=*i*+1 *X₀* + *c₁*

The following equation is what remains after taking the dierence of *PEi*and summed Equation6: *m*

|||X|a|
|---|---|---|---|
|i|i||j j;i|
|||j=i+1||

*a* *m*+1*;i i i j j;i* = + + (*X₀* + *c₁*)(*X₀* + *c₂*) *X₀* + *c₁ X₀* + *c₂* (*X₀* + *c₁*)(*X₀* + *c₂*)

By induction hypothesis *H*(*i* + 1), we have that there exists a satisfying assignment for*j*for *j > i*. We x those variables, then solve the above equation for*i*and*i*:

X *m* *i* (*X₀* + *c₁*) +*i*(*X₀* + *c₂*) = *am*+1*;i jaj;i* *j*=*i*+1

*i*+*i*= 0 X *m* *i* *c₁* +*ic₂* = *am*+1*;i jaj;i* *j*=*i*+1 P*m* <u>am+1;i j=i+1 jaj;i</u> *i*= *c₁ c₂* P*m* <u>am+1;i j=i+1 jaj;i</u> *i*= *c₂ c₁*

This concludes proof of the induction hypothesis and of the claim.

Generalizing transcript rewrite to all *ci*. Next, we argue that the above claim, which holds for a transcript of queries to *c₁* followed by one query to *c₂*, generalizes to a transcript that makes queries to arbitrary dierent *ci*values. We assume the transcript up until this point is made up of elements that are \separated by *cj*", i.e., each only have powers of a single (*X₀* + *cj*) in the denominator. Given this, we show that a new query to any *cv*(taking in a linear combination of all previous elements of the transcript) can be rewritten so that it too only depends on powers of (*X₀* + *cv*), such that the span of the full transcript is preserved.

As such, we assume the transcript has elements of the following form, where a transcript element*i;j*is the *i* *th* query to *cj*(following from Equation2and3). Element*i;j*depends only on previous1*;j;:::;i* 1*;j*and all only have powers of (*X₀* + *cj*) in the denominator:

P*i* 1 <u>Yi;j+u=1au;j u;j</u> *i;j*= *X₀* + *cj*

X *i* 1 2*i*X*u*1 *Y* Q*j!*(2*us*+2*u* 1)*j*1 *a u u* 1 *u u* 1 <u>Yi;j</u> *u;j k*=1*!*(2 *s*+2)*k;!*(2 *s*+2)*k*+1 = + *j!*(2*us*+2*u* 1)*j*

(7)
*X₀* + *cj* *u*=1*i u* 1 (*X₀* + *cj*) *s*=2

A new query to *cv*will have the following output form, where *qj*denotes the number of queries that have been made to *cj*: P P <u>Y⁰ +</u> *n qj* <u>a⁰</u> *0* = <u>q</u> <u>v</u> <u>+1;v j=1 i=1 qv+1;v;i;j i;j</u> *q* *v* +1*;v* *X* + *c* 0 *v*

We show that we can replace this output with*qv*+1*;v*of the following form which matches the form from Equation7: P*n*P*q* *j* P*q* *v 0q* *Yq0* *v* +1*;v*+*j*=1 *i*=1*bi;jYi;j*+*i*=1*av*+1*;v;i;v i;v* *j6*=*v* *q* *v* +1*;v*= *X₀* + *cv* P*q* *v* <u>Yqv+1;v+i=1ai;v i;v</u> = *X₀* + *cv* X *n*X*qj* where *Yqv*+1*;v*= *Yq0* *v* +1*;v*+ *bi;jYi;j* *j*=1 *i*=1 *j6*=*v* *ai;v*= *a* *0q* *v* +1*;v;i;v*

We want that the span of the new transcript is preserved by replacing the new output with the rewritten output, and thus we prove the following:

*q* *jn* Claim 9 *We provide* [*bi*]*i*=1 *j*=1 *to constructqv*+1*;vsuch that* h i h i *q* *jn qjn* Span [*i;j*]*i*=1 *j*=1 *;q0* *v* +1*;v*= Span [*i;j*]*i*=1 *j*=1*;qv*+1*;v*

*Proof of Claim:* We prove the claim by providing*i;j*and *bi;j*values such that:

X *n*X*qj* *0* = + *q* *v* +1*;v qv*+1*;v qv*+1*;v i;j i;j* *j*=1 *i*=1

This is implied by our previous claim which shows that for each *j 6*= *v*, we can nd*i;j*and *bi;j*such that:

X *q* *j* <u>aq +1;v;i;j i;j</u>X *q* *j* <u>b</u> <u>i;jYi;j</u> X *q* *j* ! <u>v</u> = + *q* *v* +1*;v i;j i;j* *i*=1 *X₀* + *cv* *i*=1 *X₀* + *cv* *i*=1

This concludes the argument that any new query output can be rewritten to be in the form of Equation7 in which it only has powers of the queried *cv*in the denominator, while preserving the span of the query output transcript.

Using rewritten transcript to show non-trivial winning element. We will continue to use the quotient notation, however, recall that in the simulation of the adversary’s environment (Section Q

A.1), the
*n qi* rational fractions are multiplied by a least common multiple,*i*=1(*X₀* + *ci*). The notions of independence we show for polynomial rational fractions hold true for the the polynomials once multiplied by the LCM as well.

The adversary is given initial group elements which we represent as polynomial rational fractions as follows: *g*^ *7!* 1, *X*^ *7! X₀*, [*Ai*] *m* *i*=1*7!* [*Xi*] *m* *i*=1. It is evident that these polynomials are linearly-independent as they each include a dierent formal variable (with exception of ^*g* which is the only element with a constant).

The adversary will also receive group elements from the P SDH oracle. We will denote the polynomial rational *n q* fraction outputs of the *q* =*i*=1*qi*queries to SDH as [*i0*]*i*=1. *‘* Lastly, the adversary will output a set of *‘* winning group elements for a selected, [*Zi;i*]*i*, where *‘ > q*. h i*‘* <u>Xi</u> These elements are represented by the following polynomial rational fractions: *X*0 +*c*. These *‘* elements *i*=1 are linearly-independent as they each include a dierent formal variable. *‘* We argue that at least one element from [*Xi=*(*X₀* + *c*)] *i*=1 is linearly independent from the initial elements and SDH elements given to the adversary. If so, then *A*uberwins if it guesses correctly and the proof is complete. In other words, we want that:

<u>Xi</u> *m q* *9 i 2* [1*;‘*] : *62* Span( 1*;* [*Xi*]*i*=0*;* [*i0*]*i*=1) *X₀* + *c*

*0 qj n* We use Claim9to rewrite the transcript into a new transcript that contains elements [[*i;j*]*i*=1]*j*=1of form dened in Equation7. The transcript is built element by element by repeatedly applying Claim9to the next query in *0*. Ultimately we have that: *q qjn*

|Span([|] ) = Span( [|]|)|||
|---|---|---|---|---|---|
||i0 i=1|i;j i=1 j=1||||
|m|q|m|q n|||
|i i=0|i0 i=1|i i=0|i;j i=1 j=1|||

*i0 i*=1 *i;j i*=1 *j*=1 h i *j* Span( 1*;* [*X*]*;* []) = Span( 1*;* [*X*]*;* [])

So instead we will show <u>Xi</u> h *m qjn* i *9 i 2* [1*;‘*] : Span( 1*;* [*Xi*]*i*=0*;* [*i;j*] *i*=1 *j*=1 ) *X₀* + *c*

Next, consider a linear combination of the above that results in a winning element *X =*(*X₀* + *c*) with linear combination coecients *r;si;ti;j*:

X *m*X*n*X*qj* <u>X</u> *r* 1 + *siXi*+ *ti;j i;j*= *i*=0 *j*=1 *i*=1 *X₀* + *c*

X *m*X*n*X*qj* <u>X</u> X *q* *r* 1 + *siXi*+ *ti;j i;j*= *ti; i;*(8) *i*=0 *j*=1 *i*=1 *X₀* + *c* *i*=1 *j6*=

Q*n* *q* *i* Now if we multiply both side of the above Equation8by the LCM expression*i*=1(*X₀*+ *ci*), the quotients are removed and we have an equation of two polynomials. By the structure of*i;j*from Equation7, we have that none of the*i;j*for *j 6*= have a (*X₀*+ *c*) term in the denominator. Thus, the left hand side polynomial has a factor of (*X₀* + *c*) *q*.

On the right hand side, because every*i;*term has (*X₀* + *c*) in the denominator, (*X₀* + *c*) *q* does not divide the right hand side polynomial. This implies that the two polynomials cannot be equal unless they are the zero polynomial, which is only possible if *r;*[*si*] *m* *i*=1coecients are equal to 0. h i *m qjn* Thus, if *X =*(*X₀* + *c*) *2* Span( 1*;* [*Xi*]*i*=0*;* [*i;j*] *i*=1 *j*=1 ), then it must be:

X *q* <u>X</u> *t* *i; i;*= *i*=1 *X₀* + *c*

*q* However, since there are only *q < ‘* [*i;*]*i*=1terms, they can at most generate a *q*-dimension space. Since the *‘* winning elements are linearly-independent and generate a *‘*-dimension space, it is not possible that *q* they can all be generated from a linear combination of [*i;*]*i*=1. This concludes the proof.

# B Security Proofs for 3H

For ease of reference, we restate the theorem here:

Theorem 4 *Let A*prf*be a* P*-model POPRF adversary against* 3H *with query budget* (*m;n; q*E*; ~q; q*H1*; q*H2*;* *q* H3*; q*H4)*. Then we give a* H₄*-model adversary A*zk*and adversary A*sdhi*such that* <u>n²</u> po-prf zk (*m;n*)-om-gap-sdhi Adv 3H*;*S[S]*;*P*;A*prf () Adv *R;R;*H4*;*S*;A*zk () + Adv GGen*;A*sdhi () +*;* *p* *where* S *is the simulator dened in Figure10that makes use of NIZK simulator* S*. Adversary A*zk*makes q*H4 *queries to its random oracle and A*sdhi*has query budget* (*~q;q*H2)*. Further, T*(*A*prf) *T* (*A*zk) *T* (*A*sdhi)*.*

Proof: We bound the advantage of *A*prfby bounding the advantage of each of a series of game hops. We *A*po-prf*;*1 dene G₀ = POPRF 3H*;*P*;*S () and intermediate games G₁*;*G₂*;*G₃*;*G₄*;*G₅ to gradually transform the view *A*po-prf*;*0 of the adversary until G₅ = POPRF 3H*;*P*;*S (). The most important games, G₂ G₄ are shown in Figure11). There we use tables *R₁;R₂;R₃;R₄* for RO simulation, and we restrict collisions in *R₃* (as described below) by sampling from Z*p*without replacement, which we do by dening Z*pn R₃* to be the set of points in Z*p* that do not appear in any entries of *R₃*.

The advantage bound follows from the following claims which we will justify:

<u>n(n</u>

2*p*

<u>1)</u> zk *R;R;*RO*;A*zk (*q*H1*;q*H3sdhi)-om-gap-sdhi GGen*;A*

LimEv

|S:Init(;pp)|||S:H|(x : (pp; sk;R₁;R₂;R₃;st||))|
|---|---|---|---|---|---|---|
|R₁ []; sk Z|R₂ [];|R₃ []|If x 62 R₁ then R₁[x] Return R₁[x]||G||
|st S|:Init(pp)||S:H|(t;x;Y|;R|;R ;st))|
|st (pp; sk;R₁;R₂;R₃;st||)|||||
|Return (st|;g)||If t 62 R₃ then R₃[x] If x 62 R₁ then R₁[x]||Z G||
|S:BlindEv|(t; req : (pp; sk;R₁;R₂;R₃;st||If (t;x;Y ) 62 R₂ then||||
|h S:H|(t : st)||If Y|= R₁[x]|then R₂[t;x;Y]||
|B req;|B⁰ B¹||Else R₂[t;x;Y]||f0; 1g||
|S :Prove((g;g||;B⁰;B) : st|Return R₂[t;x;Y]||||
|Return (B⁰;)|||S:H If x 62 R₃ then R₃[x] Return R₃[x] S:H Return S|(x : (pp; sk;R₁;R₂;R₃;st (x : (pp; sk;R₁;R₂;R₃;st :H(x : st|Z )|)) ))|

<u>1</u> $ $ *p* $ LimEv <u>: (pp; sk;R</u> <u>2 1 2 3</u> S S *sk* $ *p* LimEv $ <u>))</u> $ LimEv 3 S 1*=*(*sk*+*R*3 [*t*]) LimEv(*t;x*) *=*(*sk*+*h*) $ $ *sk*+*h*) LimEv <u>3</u> $ *p*

LimEv <u>4</u>

Figure 10: Simulator S[S] for PRF security of 3H where S is the zero knowledge simulator for *R*.

(5) *j*Pr[G₄ = 1] Pr[G₅ = 1]*j*
<u>n(n</u> 2*p*

<u>1)</u>
*Claim 1:* We rst transition to a game G₁ in which we disallow collisions in the output of RO₃, i.e., we replace sampling from Z*p*for new range values with sampling without replacement from Z*p*. Recall that at most *n* unique *t* values are queried by *A*prfin the course of the game, and so a standard birthday analysis establishes the claim’s upper bound of *n*(*n* 1)*=*2*p*.

*Claim 2:* In G₂, the proof generated in BlindEv is simulated along with the corresponding random oracle RO₄. Since this is the only change between G₁ and G₂, we can equate the distinguishing advantage between the two games to that of the zero-knowledge security game of*R*. We construct *A*zkthat runs G₁ and generates proofs using its Prove oracle and responds to queries to RO₄ using its own Prim oracle.

*Claim 3:* In G₃, the Ev oracle generates outputs independently from the random oracles and stores its choices in table *R*. For consistency, it must be that for *t;x* and *Y* = *R₁*[*x*] 1*=*(*sk*+*R*3 [*t*]), the random output stored in *R* is the same as the one stored in *R₂* for responding to RO₂ queries of (*t;x;Y*). G₃ checks if this is the case in RO₂, and if (*t;x;Y*) are of the above form, it repairs *R* and *R₂* to be consistent. Thus, from the adversary’s perspective, there is no change between G₂ and G₃.

*Claim 4:* In G₄, the repair between *R* and *R₂* in RO₂ only occurs if there have been more calls to BlindEv on *t* than calls of valid (*t;x;Y*) tuples to RO₂. Otherwise, a bad ag is set and the oracle returns*?* to *A*po-prf*;*0 the adversary. This matches the functionality of S in POPRF 3H*;*P*;*S () since the simulator is restricted to not run LimEv on *t* more than calls made to BlindEv on *t*. By an identical-until-bad argument via the fundamental lemma of game playing [BR06],

*j*Pr[G₃ = 1] Pr[G₄ = 1]*j* Pr[bad = 1]

where bad = 1 is the event that bad is sent in game G₄. We bound the probability of this event by the advantage of an adversary *A*sdhi, i.e., if bad is set, *A*sdhiwins the (*m;n*)-OM-Gap-SDHI game.

Adversary *A*sdhi= (*A₁; A₂*) (shown in Figure12) runs G₄ with the help of the (*m;n*)-OM-Gap-SDHI game. The [*Yi*] *m* *i*group elements are used for the values returned by RO₁. (This is often called \programming" RO₁.) The *n* values [*c*] *n* *i*from Z*p*output by *A₁* for use in the strong Die-Hellman queries are used for the return values from RO₃. By assumption on the query budget for *A*prf, the number of *Yi*values and the number of *ci*values are sucient for simulating the queries made by *A*prf. And since both of these sets of values are chosen at random, they have the same distribution as the random oracle responses in G₄. Queries to BlindEv are answered by computing the strong Die-Hellman evaluation with the appropriate *ci*value using SDH. Note that *A*sdhihas query budget *~q* because by assumption *A*prfqueries at most *~q₁* times to

Games G₂, G₃, G₄ Oracle Ev(*t;x*) Oracle H₁(*x*)

|If|t 62 R₃ then||R₃ [t]|$ Z p|n R₃||
|---|---|---|---|---|---|---|
|If|x 62 R₁|then|R₁ [x]|$ G|||
|Y|1 R₁ [x]|= (sk +|R t]) 3 [||||
|If (|t;x;Y)|62 R₂|then|R₂ [|t;x;Y]|$ f 0; 1 g|
|Z|R₂ [t;x;Y|]|||||
|If (|t;x) 62 R R [t;x]|then $ f 0|; 1 g||||
|Z|R [t;x]||||||

*R₁* []; *R₂* []; *R₃* [] If *x 62 R₁* then *R₁*[*x*] $ G *R* [] Return *R₁*[*x*] *i* 0; *j* 0; bad 0 <u>Oracle H (t;x;Y)</u> *pp* $ 3H*:* Setup() <u>2</u> *sk* $ Z*p*; *pk g* *sk* If *t 62 R₃* then *R₃*[*t*] $ Z*pn R₃* *st* $ S *:* Init(*pp*) If *x 62 R₁* then *R₁*[*x*] $ G *b⁰* $ *A*prf P*;*Ev*;*BlindEv (*pp; pk*) If (*t;x;Y*) *62 R₂* then Return *b⁰* *R₂*[*t;x;Y*] 1 $ *=* *f* (*sk* 0*;* + 1 *R* *g* 3 [*t*]) Return *Z* If *Y* <u>= R₁[x]</u> then <u>i</u> <u>tit+ 1</u> <u>Oracle BlindEv(t; req) If i</u> <u>t> jtthen bad 1; Return?</u> If *t 62 R₃* then *R₃*[*t*] $ Z*pn R₃* If (*t;x*) *62 R* then *R*[*t;x*] $ *f*0*;* 1*g* *B req*; *B⁰ B¹* *=*(*sk*+*R*3 [*t*]) *R₂*[*t;x;Y*] *R*[*t;x*] *j* *tjt*+ 1 Else *R₂*[*t;x;Y*] $ *f*0*;* 1*g* $ S *:* Prove((*g;gsk*+*h;B⁰;B*) : *st*) Return *R₂*[*t;x;Y*] Return (*B⁰;*) <u>Oracle H (x)</u> <u>3</u> If *x 62 R₃* then *R₃*[*x*] $ Z*pn R₃* Return *R₃*[*x*] Oracle H₄(*x*) Return S *:* H(*x* : *st*)

Figure 11: The key game transitions used in pseudorandomness security for 3H. Greyed highlighted statements are

only included in G₂, blue highlighted statements in G₃ and G₄, and boxed statements only in G₄.

BlindEv on the rst value *t₁* queried in the course of the game, at most *~q₂* times for the second value *t₂* queried in the course of the game, and so on.

In RO₂, the form of (*t;x;Y*) is checked using SDDH to determine if a repair between *R* and *R₂* needs to be performed. However, before the repair is done, if there have been more valid (*t;x;Y*) tuples queried to Prim₂ than queries to BlindEv, *A*]).

|then halts execution of A|and concludes by outputting (; Z^[|
|---|---|
|sdhi 1=(sk+c)|prf|
|i|i j|

In this case, the adversary has found \one more" valid strong Die-Hellman tuple (one corresponding to *j* each valid (*t;x;Y*) tuple since *Y* = *Y* for some *Y;c*) than calls made to SDH. The adversary therefore wins the (*m;n*)-OM-Gap-SDHI game.

*Claim 5:* The nal game transition restores the possibility of collisions to RO₃, and a birthday analysis gives the upper bound on this transition.

# C Security with Restricted Tag Space

Corollary 10 *For any adversary A*prf*against the partially-oblivious pseudorandomness of* 3H *with restricted* *tag space of size j*T*j, we give adversaries A*zk sdhi

|||and A|such that|||
|---|---|---|---|---|---|
|||zk|sdhi|||
|po-prf||zk||(q ;jTj)-om-gap-sdhi||
|3H;P;S[S|prf|;R;RO zk|;S ;A sdhi|GGen;A p prf|p H|

H1 Adv]*;A*prf () Adv *R* 4 zk () + Adv sdhi ()*;*

*where* S *is the simulator dened in Figure10, the ideal primitive* P = RO₁ RO₂ RO₃ RO₄ *for random* *oracles over* RO₁ :*!* G*,* RO₂ : G*!f*0*;* 1*g,* RO₃ :*!* Z*,* RO₄ : G⁶*!* Z *for* (*p;* G) *determined* *by* GGen()*. The running time T*(*A*) *T* (*A*) *T* (*A*) *and A makes at most q*1*queries to* RO₁*.*

Proof: The proof follows the same as above except only queries to Prim₃ that fall within the tag space T need to be programmed with a strong Die-Hellman constant *c*; otherwise, a random value can be sampled.

|A₁ (p; G)|Oracle H₁ (x)|
|---|---|
|C; For i = 1 to n : $ c Z n C; C C [fc g i p i n st (p; G; [c]) i A i n Return (st; [c]) i A i|If x 62 R₁ then R₁ [x] Y i K [x] i; i i + 1 Return R₁ [x] Oracle H₂ (t;x;Y)|
|SDH; SDDH m n A (g; pk; [Y] : (p; G; [c]) i i i i 2|If t 62 R₃ then|
|i 1; j 0; ‘ 1 ^ K []; Z []; ? R₁ []; R₂ []; R₃ []; R [] pp (p;g; G) $ st S : Init(pp) P; Ev; BlindEv $ b⁰ A (pp; pk) prf ^[Return (; Z]) Oracle Ev(t;x)|R₃ [t] ‘; ‘ ‘ + 1 If x 62 R₁ then R₁ [x] Y i K [x] i; i i + 1 If (t;x;Y) 62 R₂ then If SDDH(Y;R₁ [x] ;R₃ [t]) then ^[^[Z R₃ [t]] Z R₃ [t]] k (Y;K [x]) ^[If jZ R₃ [t]] j > j then t R [t]; abort A|
|$ If (t;x) 62 R then R [t;x] f 0; 1 g Z R [t;x] Return Z Oracle BlindEv(t; req)|3 prf $ If x 62 R then R [x] f 0; 1 g R₂ [t;x;Y] R [x] $ Else R₂ [t;x;Y] f 0; 1 g Return R₂ [t;x;Y]|
|If t 62 R₃ then R₃ [t] ‘; ‘ ‘ + 1|Oracle H₃ (x)|
|j j + 1 t t B req B⁰ SDH(B;R₃ [t]) cR t] 3 [$ ;B⁰ ;B) : st) S : Prove((g;X g Return (B⁰ ;)|If x 62 R₃ then R₃ [x] ‘; ‘ ‘ + 1 Return c R x] 3 [Oracle H₄ (x) Return S : H(x : st)|

Figure 12: Adversary *A*sdhi= (*A₁; A₂*) used in POPRF security proof of 3H.

# D Security of 2HashDH OPRF

In this section, we demonstrate the extensibility of our security denitions by proving the security of the 2HashDH OPRF [JKK14]. The only previous proof of security for 2HashDH is with respect to the UC denition provided by Jarecki et al. [JKK14]. The construction 2HashDH is given in Figure13. The security proofs for 2HashDH follow closely to the proofs of 3H. As such, we provide only proof sketches for 2HashDH referring heavily to the detailed proofs in AppendixBand Section5.

Pseudorandomness. First, we prove pseudorandomness of the 2HashDH OPRF with respect to a variant of POPRF given in Figure3for the OPRF setting, which we name OPRF. The security game OPRF is the same as POPRF except the public tag inputs to the oracles and algorithms are removed to t the OPRF setting and only a single query counter is maintained for tracking blind evaluation and limited evaluation oracle queries, rather than a separate query counter for each public tag. We let the advantage of a OPRF adversary *A* be dened by i i

||h|h|
|---|---|---|
|oprf|A|A;;0S;P|
|Fn;S;P;A;|Fn;;1S;P|Fn|

Adv () = Pr OPRF ()*)* 1 Pr OPRF ()*)* 1 *:*

We will reduce the pseudorandomness security of 2HashDH to the security against the so-called one-more gap computational Die-Hellman assumption [JKK14,Bol03] (with pseudocode given in Figure14). Here,

|x|y|i m i=1|
|---|---|---|
|i|x y||

an adversary receives *m* + 1 group elements, *g* = *X*, [*gi*= *Y*], and is tasked with computing *q* + 1 computational Die-Hellman values of the form *Z* = *gi*, where *q* is the number of queries the adversary makes to a helper oracle CDH( ) that returns the CDH value of the input element with *X*. The adversary also is given access to a gap oracle to answer the decisional Die-Hellman question on arbitrary inputs. The non-gap version of this assumption was recently shown secure in the generic group model [BFP21], however the same approach and bounds hold even when the gap oracle is included [BFL20]. We dene the *m*-OM-Gap-CDH-advantage of an adversary *A* by

Adv *m* GGen -om-gap-cdh *;A* () = Pr *m*-OM-Gap-CDH *A* GGen()*)* true *:* We state below a theorem using the ideal primitive model in which P = H₁ H₂ H₃ for random oracles

2HashDH*:* Setup() 2HashDH*:* KeyGenH1 H2 H3(*pp*) 2HashDH*:* EvH1 H2 H3(*pp; sk;x*) (*p;g;* G) $ GGen() (*p;g;* G) *pp*; *z* $ Z*p Y* H₁(*x*)*sk* *pp* (*p;g;* G) *sk z*; *pk gzZ* H₂(*x;Y*) Return *pp* Return (*sk; pk*) Return *Z*

2HashDH*:* ReqH1 H2 H3(*pk;x*) *r* $ *Zp*; *B* H₁(*x*)*r* H H H Return ((*pk;r;x*)*;B*)*! B* 2HashDH*:* BlindEv 1 2 3(*sk;B*) *B⁰ Bsk* $ *R :* ProveH3(*sk;*(*g;gsk;B;B⁰*)) 2HashDH*:* FinalizeH1 H2 H3(*B⁰;*; (*pk;r;x*)) *B⁰;* Return (*B⁰;*) *Y* (*B⁰*)1*=r* Require *R :* VerH3((*g; pk;B;B⁰*)*;*) *Z* H₂(*x;Y*) Return *Z*

Figure 13: The 2HashDH OPRF construction of [JKK14]. Algorithms have implicit input the parameters *pp* =

(*p;g;* G) that describe the group used. The NIZK uses relation *R* = *f*(*g;U;V;W*)*;* () : *U* = *g ^ W* = *V g*.

*A*

|Game m-OM-Gap-CDH||()||Oracle CDH(Y )|Oracle DDH(h;A;B;C)||
|---|---|---|---|---|---|---|
|(p;g; G)|GGen()|||q q + 1|a log|(A)|
|q 0||||Z Y|b log|(B)|
|x Z|; [y] [Z|]||Return Z|c log|(C)|
|[Z ;] Require q < ‘ Return [Z|A ^ 8] = [g|p; G;g;g 6=]|; [g]||Return c|ab|

GGen $ *h* *x* *h* $ *p i m i* $ *p m* *i h* *i i* *‘* *i* $ CDH*;*DDH *x yi m* *i p* *‘* *i6*=*j i j* *i* *‘* *i* *x yi ‘* *i*

Figure 14: The one-more gap computational Die-Hellman security game.

over H₁ :*!* G, H₂ : G*!f*0*;* 1*g*, H₃ : G⁶*!* Z*p*for (*p;* G) determined by GGen().

Theorem 11 *Let A*prf*be a* P*-model OPRF adversary against* 2HashDH*. Then we give a* H₃*-model adversary* *A*zk*and adversary A*cdh*such that*

|oprf||zk||(q +q)-om-gap-cdh||||
|---|---|---|---|---|---|---|---|
|2HashDH;S[S|];P;A|;R;H|;S ;A|GGen;A||H H|H|
|prf|||||zk|H||
|cdh|B|||prf|zk|cdh||

oprf zk (*q*H1+*q*H2)-*om*-*gap*-*cdh* Adv prf () Adv *R* 3 zk () + Adv cdh ()*;*

*where* S *is the simulator dened in Figure15that makes use of NIZK simulator* S*, and q*1*, q*2*, q*3*are* *the number of queries A makes to its respective ideal primitives. Adversary A makes q*3*queries to its* *random oracle and A makes q queries to its CDH oracle. Further, T*(*A*) *T* (*A*) *T* (*A*)*.*

Proof: The follows closely to the proof of pseudorandomness for 3H in AppendixB. We skip game hops G₀*!* G₁ and G₄*!* G₅ that deal with disallowing and restoring collisions in the random oracle used for public tags. The 2HashDH construction does not use that random oracle, and thus the birthday bound terms from the 3H analysis do not appear.

The rst game hop is instead G₁*!* G₂ (of AppendixB) which transitions to a game that replaces the NIZK generated in BlindEv with one generated by the NIZK simulator S.

The second game hop follows G₂*!* G₃ (of AppendixB) in which we modify the handling of H₂ queries to check if the table *R* from Ev has been set on a relevant value and, if so, patch up H₂’s response to maintain consistency. This does not change the distribution of responses to the adversary so there is no distinguishing advantage.

Lastly, the nal game hop follows G₃*!* G₄ (of AppendixB) by only repairing H₂’s response if there has been more queries to BlindEv than repairs required. The only dierence between this game and the ideal world is when more repairs occur than queries to BlindEv. We show an adversary against the OM-Gap-CDH assumption with advantage greater than or equal to the distinguishing advantage between these two games. The views of the games are simulated using the initial values to program H₁, the CDH oracle in BlindEv, and the DDH oracle to check for repairs in H₂.

Ev Ev

|S:Init (; pp)|||S:Eval|(x : (pp; sk;R₁;R₂;st||))|
|---|---|---|---|---|---|---|
|R₁ [];|R₂ []||(g;p; G)|pp|||
|st S st (pp; ?;R₁;R₂;st|:Init(; pp)|)|If x 62 R₁ then R₁[x] Return R₁[x]||G||
|Return st|||S:Eval|(x;Y : (pp; sk;R₁;R₂;st||))|
|S:KeyGen|(: (pp; sk;R₁;R₂;st|))|If x 62 R₁|then R₁[x]|G||
|(g;p; G)|pp; sk|Z|If (x;Y ) 62 R₂ then||||
|Return g|||If Y|= R₁[x]|then R₂[x;Y]|Ev(x)|
|S:BlindEv|(req : (pp; sk;R₁;R₂;st|))|Else R₂[x;Y] Return R₂[x;Y]||f0; 1g||
|B req;|B B||||||
|S :Prove((g;g|;B;B⁰) : st|)|S:Eval₃|(x : (pp; sk;R₁;R₂;st||))|
|Return (B⁰;)|||Return S|:Eval(x : st|)||
|S:Eval (x : (pp; sk;R₁;R₂;st||))|||||
|(i;x)|x||||||
|y S:Eval|(x : st)||||||
|Return y|||||||

<u>1</u>

$ $ S S Ev Ev <u>2</u> $ $ *p* *sk sk* Ev $ *0 sk* Ev $ *sk*

Ev

$ *i* S

Figure 15: Simulator S[S] for OPRF security of 2HashDH where S is the zero knowledge simulator for *R*.

Request Privacy. Next, we provide theorems for the two notions of request privacy (with and without proofs of correct blind evaluation) for 2HashDH. We again dene analogues of POPRIV1 and POPRIV2 (see Figure4) for the OPRF setting, which we refer to as OPRIV1 and OPRIV2. The games are identical except the public metadata tag is removed as input to oracles and algorithms. The advantage of a OPRIV1 adversary *A* in the P-model is dened by h i h i

|opriv1|A|A;;0P|
|---|---|---|
|Fn;P;A|Fn;;1P|Fn|
|opriv2|A|A;;0P|
|Fn;P;A|Fn;;1P|Fn|

Adv () = Pr POPRIV1 ()*)* 1 Pr POPRIV1 ()*)* 1*;*

and the advantage of a OPRIV2 adversary *A* dened by h i h i Adv () = Pr POPRIV2 ()*)* 1 Pr POPRIV2 ()*)* 1 *:*

We provide the following theorems without proof as they follow directly from the proofs given in Section5.

Theorem 12 *For any* OPRIV1 *adversary A*opriv1*against* 2HashDH *(without client verication) we have* *that* Adv opriv1 2HashDH*;A*po-priv1 () = 0*.*

Theorem 13 *Let A*opriv2*be a* OPRIV2 *adversary in the* P*-model against* 2HashDH *that makes at most q* *queries to* Fin*. We give an adversary B*sound*such that*

||opriv2|sound|
|---|---|---|
|opriv2|2HashDH;P;A|NiZK;R;H|

Adv opriv2 opriv2 () 4*q* Adv sound 3 *;B*sound()) *:* *Further, T*(*B*sound) *T* (*A*)*.*

# E (Partially) Blind Signatures Preliminaries

In this section, we dene the syntax, semantics, and security properties of partially blind digital signatures. As in our denitions for POPRFs, the formalism we present here supports the public metadata input of \partially" blind digital signatures, but can be easily adapted for the simpler blind digital signature setting without public metadata. Also as in our treatment of POPRFs, we simplify our handling of the interactive blind signing protocol by restricting our attention to a single round of interaction. This approach diers from related denitions [HKL19] for \three-move" blind signatures capturing Schnorr-type schemes; the constructions we consider in this work are only \two-move" and hence we benet from shedding the extra denitional complexity.

## E.1 Syntax and Semantics

A partially blind digital signature scheme, DS, is a tuple of algorithms

(DS*:* Setup*;*DS*:* KeyGen*;*DS*:* Sign*;*DS*:* Ver*;*DS*:* Req*;*DS*:* BlindSign*;*DS*:* Finalize)

The setup and key generation algorithm generate public parameters *pp* and a public key, secret key pair (*pk; sk*), respectively. Blind signing is carried out as an interactive protocol run between client and server:

(1)First, a client runs the algorithm DS*:* Req
P *pp*(*pk;t; m*), which takes input a public key *pk*, tag (or public input) *t*, and message *m*, and outputs a local state *st* and a request message *req*. The message *req* is sent to a server.

(2)A server runs algorithm DS*:* BlindSign
P *pp*(*sk;t; req*), using as input a secret key, a tag *t*, and the request message. It produces a response message *rep* that should be sent back to the client.

(3)Finally, the client runs the algorithm DS*:* Finalize(*rep* : *st*) and outputs an unblinded signature on the message-tag pair (*t; m*) or*?* if the response message is rejected, for example, due to the verication check failing. The unblinded signing algorithm DS*:* Sign is randomized, and takes as input a secret key *sk*, an input pair (*t; m*), and outputs a signature. The verication algorithm DS*:* Ver takes as input a public key *pk*, an input pair (*t; m*), and a signature, and outputs 1 if the signature is valid and 0 otherwise. We also dene sets DS*:* SK, DS*:* PK, DS*:* T, DS*:* M, and DS*:* representing the secret key, public key, tag, message, and signature space, respectively. DS is called *unique* if there exists only a single valid signature for input (*t;x*). For correctness, we require that both the unblinded signing algorithm and interactive blind signing protocol produce valid signatures. To formalize the latter: we require that for *pp* output from Setup, any *pk; sk* output by KeyGen, and any *t; m*, it holds that Pr[Ver(*pk;t; m;*) = 1] = 1 where the probability is taken over choice of via the following process:
(*st; req*) $ Req P (*pk;t; m*); *rep* $ BlindSign P (*sk;t; req*); $ Finalize P (*rep* : *st*) *:*

## E.2 Security

We introduce two new denitions of security for partially blind digital signatures, tailored for the case of one round blind signing. Our denitions match closely to those introduced for the POPRF setting. We use code-based games mostly following the framework of Bellare and Rogaway [BR06].

One-more unforgeability. The rst denition captures unforgeability, ensuring that it is not possible for malicious clients to forge signatures even when given access to a blinded signing oracle. We give a pseudocode game in Figure16. The adversary is tasked with producing *q* + 1 distinct message-signature tuples [(*mi;i*)] *q* *i*=1 +1 that all verify under a given public key *pk* and adversary-chosen public tag *t⁰*. The adversary is given access to a blinded signing oracles for *pk* but wins only if they query the oracle *q* times or less on the chosen tag *t⁰*. This intuitively enforces that each query to the blind signing oracle only results in one learned signature, and queries for a dierent public tag do not help in forging a signature for the target tag. We let the advantage of a OM-Unf adversary *A* be dened by

Adv om-unf DS*;*P*;A*() = Pr OM-Unf *A* DS*;*P()*)* true *:*

Blindness. The second denition captures message privacy of a client in the face of a malicious server. We give a pseudocode game in Figure17. The game is the exact analogue of the request privacy against malicious adversary game POPRIV2 (see Section3) for POPRFs adapted for blind signature syntax. The adversary is given access to a request oracle and nalize oracle representing client behavior. The request oracle takes an adversary-chosen public key, public tag, and pair of messages, and outputs a randomly ordered pair of client request messages (for the input messages) based on a challenge bit. The nalize oracle takes an adversary-chosen pair of response messages, and outputs the produced signatures (in the original order). To prevent trivial attacks of corrupting one response, the oracle requires that both signatures nalize without error, i.e. do not equal*?*.

||A Game OM-Unf () Oracle BlindSign(t; req) DS; P||
|---|---|---|
||q q + 1 t t $ st P : Init() P P rep : BlindSign (sk;t; req) $ pp DS : Setup() ReturnDS rep P $ (sk; pk) DS : KeyGen () pp BlindSign; P ‘ $) A (pp; pk) (t⁰; [m ;] i i i ‘ Require q < ‘ ^ 8 (m ;) 6 = (m ;) i i j j t0 i6 = j V ‘ 0 Return DS : Ver(pk;t; m ;) i i i||
|DS : T.|Figure 16: One-more unforgeability security game for partially blind signatures. The query counters|q|
|Game Blind|A ;b () Oracle Fin(j; rep; rep⁰) Oracle Req(pk;t; m₀; m₁) Fn; P||
|i 0 $ st P $ pp $ b⁰ Return|i i + 1 If j > i then return ? P P $ $ (st; req₀) DS : Req (pk;t; m₀) DS : Finalize (st; rep i; 0 b j;b P : Init() P P $ $ (st; req₁) DS : Req (pk;t; m₁) Fn : Finalize (st i; 1 1 b j; 1 b DS : Setup() Req; Fin; P Return (req; req₁) If = ? or = ? then 0 1 A (pp) b b Return ? b⁰ Return (;) 0 1|); rep⁰)|

*t* are initialized to 0 for all *t 2*

Figure 17: Security denition for blindness of message in partially blind signatures.

The advantage of a Blind adversary *A* is dened by i i

||h|h|
|---|---|---|
|blind|A|A;0;P|
|DS;P;A|DS;1;P|DS|

Adv () = Pr Blind ()*)* 1 Pr Blind ()*)* 1 *:*

# F (P)OPRFs from Unique (Partially) Blind Signatures

In this section, we provide proof for the folklore transform of a unique partially blind signature (resp. blind signature) to a POPRF (resp. OPRF) in the random oracle model. The transform, observed by Jarecki et al. [JKK14], simply consists of hashing the signature to create the PRF output. We call this transform HSig[DS] where if DS uses ideal primitive P, HSig uses ideal primitive P H where H is a random oracle over H : DS*:* T DS*:* M DS*:!f*0*;* 1*g*. The pseudocode is given in Figure18.

### Pseudorandomness. We prove the following theorem:

Theorem 14 *Let A*prf*be a* (P H)*-model POPRF adversary against* HSig[DS]*. Then we give a* P*-model* *adversary A*om-unf*such that*

||po-prf|||om-unf|
|---|---|---|---|---|
||HSig[DS];S[DS];P||H;A|DS;P;A|
|om-unf||om-unf|B;t B;t||
|||prf|||
|A ;1|||||
|HSig;P H;S|||||

Adv po-prf prf () Adv om-unf om-unf ()*;*

*where* S *is the simulator dened in Figure19. If q is the number of queries A*prf*makes to its blind* *evaluation oracle for tag t, adversary A makes q queries to its blind signing oracle for tag t. Further,* *T* (*A*prf) *T* (*A*)*.*

Proof: We bound the advantage of *A* by bounding the advantage of a series of game hops. We dene prf G₀ = POPRF (). In the rst game hop to G₁, we replace the proper evaluation and call to H in Ev with a separate random table. In H, we check if the inputs form a valid signature, and if so ensure that the hash table *R* is consistent with the random table from Ev. Because of this repair, the view of the adversary remains the same, and there is no distinguishing advantage between G₀ and G₁. This is the case because the partially blind signature is unique { there is only ever one repair for a (*t;x*) input pair.

In G₂, we track the number of calls to BlindEv for each tag and the number of repairs for each tag that occur in H. If the number of repairs for a tag ever exceeds the number of BlindEv calls, then a bad ag is set. In G₂, the game is aborted if the ag is set, while G₁ repairs and continues. By an identical-until-bad argument via the fundamental lemma of game playing [BR06], the distinguishing advantage between G₁ and

||P H P H HSig : Setup() HSig : KeyGen (pp) HSig : BlindEv (sk;t; req)||
|---|---|---|
||P Return DS : Setup() Return Return DS : KeyGen (pp) P DS : BlindSign (sk;t; req) P H P H HSig : Req (pk;t;x) HSig : Finalize (rep; st) P H HSig : Ev (sk;t;x) P $ (req;st) DS : Req (pk;t;x) (t;x;st) st DS DS P P $ $ DS : Sign (sk;t;x) st (t;x;st) DS : Finalize (rep; st) DS DS Return H(t;x;) Return (req;st) Return H(t;x;) Figure 18: The generic HSig[DS] transform to construct a POPRF from any partially blind signature scheme DS.||
|S|LimEv S : P (x : (pp; pk; sk;R;st)) : Init(;pp) P||
|R|[] Return P : Eval(x : st) P $ st P : Init() LimEv P S : H (t;x; : (pp; pk; sk;R;st)) P $||
|(S|sk; pk) DS : KeyGen(pp) If (t;x;) 62 R then st (pp; pk; sk;R;st) S P If DS : Ver(pk;t;x;) then R [t;x;] LimEv(t;x) Return (st; pk) S $ Else R [t;x;Y] f 0; 1 g LimEv : BlindEv (t; req : (pp; pk; sk;R;st)) P Return R [t;x;Y] P Return DS : BlindSign (sk;t; req)||

Figure 19: Simulator S[DS] for PRF security of HSig[DS].

*A*prf*;*0 G₂ is bounded by the probability the bad ag is set. Furthermore, G₂ = POPRF HSig*;*P H*;*S (), since its abort in H corresponds to the simulator calling LimEv without any budget. Thus, we conclude the proof by constructing an adversary for the one-more unforgeability game that wins whenever the bad ag is set.

The unforgeability adversary *A*om-unfsimulates the BlindEv oracle using its own BlindSign oracle. *A*om-unf stores the sets of all (*t;x;*) valid triples that are passed in to H keyed by the public tag *t*. If the number of valid triples for a tag exceeds the number of calls to BlindEv for a tag, i.e., the case where the bad ag is set, *A*om-unfreturns the valid (*x;*) message-signature pairs along with the given tag to win the game.

Request privacy. We prove the following theorem:

Theorem 15 *Let A*po-priv2*be a* (P H)*-model* POPRIV2 *adversary against* HSig[DS]*. Then we give a* P*-model adversary A*blind*such that*

|||po-priv2||blind||
|---|---|---|---|---|---|
|||HSig[DS];P|H;A|DS;P;A||
|blind|||||po-priv2|
|po-priv2|blind|||||
|blind|blind||po-priv2||po-priv2 po-priv2|

Adv po-priv2 po-priv2 () Adv blind blind ()*;*

*where A makes the same number of queries to its respective request and nalize oracles as A and* *T* (*A*) *T* (*A*)*.*

Proof: *A* is a wrapper adversary around the blindness security game that simulates *A* ’s envi- ronment perfectly. *A* simply forwards *A* ’s oracle queries to Req and Fin to its own respective queries, and in the case of Fin performs the nal hash, before forwarding the response back to *A*.

# G Security of ZSS Partially Blind Signature

In this section, we provide the rst complete security proof for the ZSS partially blind signature scheme [ZSS03]. Our 3HashSDHI POPRF construction follows closely the ZSS partially blind signature scheme, but diers in one signicant way. 3HashSDHI uses a NIZK to prove correctness of the blind evaluation, while ZSS uses a pairing verication check (which also gives it its public veriability property). We show the one-more unforgeability of ZSS is implied by our new one-more gap SDHI assumption, however, we must amend the (*m;n*)-OM-Gap-SDHI assumption for the bilinear pairing group setting including the extra group elements needed for verication. To be complete, we show that the amended assumption is secure with respect to a similarly generalized uber assumption for the bilinear pairing setting [BFL20]. There are two other small changes we make to original ZSS construction. For clarity, we refer to the original construction by ZSS1 and our modied version as ZSS2. First, we replace the multiplicative blinding

||H H2 1 ZSS2 : KeyGen () ZSS2 : Setup() pp||
|---|---|---|
||$ (p; G₁; G₂; G ;g₁ ;g₂ ;e;;) BGGen() z Z p T z pp (p; G₁; G₂; G ;g₁ ;g₂ ;e;;) sk z; pk g₁ T Return pp Return (sk; pk) H H2 H H2 1 1 ZSS2 : Sign (sk;t; m) ZSS2 : Ver (pk;t; m;) pp pp 1 = (sk +H2 (t)) H2 (t) H₁ (m) Return e g₁ pk; = e (g₁; H₁ (m)) Return H H2 1 ZSS2 : Req (pk;t; m) pp r $ r Z; B H₁ (m) p H1 H2 B ZSS2 : BlindSign (sk;t;B) pp ! Return ((pk;r;t; m) ;B) k sk + H₂ (t) =k H H2 1 B⁰ B¹ ZSS2 : Finalize (B⁰;; (pk;r;t; m)) pp 0 B Return B⁰ 0 1 =r (B) H1 H2 If not ZSS2 : Ver (pk;t; m;) return ? Return||
|has range G₂|Figure 20: The ZSS2 partially blind signature construction, a minor modication to the construction from [ZSS03]. Algorithms have implicit input the parameters pp = (p; G₁; G₂; G ;g₁ ;g₂ ;e) that describe the groups used. T and H₂ has range Z. p A Oracle SDH(B;i;j) Game (m;n)-OM-Gap-SDHI () BGGen (p; G₁; G₂; G ;g₁ ;g₂ ;e;;) BGGen() Require i 2 [1 ;n] T m m $ $ sk Z; [y] [Z] Require B 2 G p i p j i i n $ q q + 1 (st; [c]) A₁ (p; G) i i i A i = (sk + ci) n Z B¹ Require 8 c 6 = c i j i6 = j yi yi m SDH; SDDH sk sk ‘ Return Z $; g₁ ;g₂ : st ;g₂) A g₁ ;g₂ ;g₁ (; [Z; ;] i i i A 2 i i ‘ ‘ 2 [1; 2] 6 = ^ 8 Require q < ‘ ^ 8 i i j Oracle SDDH(Y;Z;i;j) i i6 = j ‘ yi i = (sk + c) ‘ Require Y;Z 2 G j Return [Z] = g i i 1 = (sk + c) i i Return Z = Y||

Hash function H₁

Figure 21: The one-more gap strong Die-Hellman inversion security game adapted for bilinear groups.

approach with exponential blinding (consistent with 3HashSDHI) which is both simpler and has security benets in the non-verication case [JKX21]. ZSS incorrectly claim that the blindness property is not satised under the exponential blinding approach, as we explain below where we discuss blindness. Nevertheless, the multiplicative blinding approach of ZSS is still interesting as it enables a client-side performance improvements of xed-base exponentiation with precomputation over variable-base exponenti- ation [JKX21]. We present this alternate blinding approach that can be applied to both 3HashSDHI and ZSS in AppendixI. The second dierence is that we change the signature structure to not include the public tag in the rst hash input. This change doesn’t aect the security of the signature and allows for the blind signing process to be initiated by the client before the public tag is known (allowing for server-chosen public tags). The construction is given in pseudocode as ZSS2 in Figure20.

Bilinear pairing groups. We follow the notation of [BFL20]. (1) Groups G₁*;*G₂*;* G*T*are cyclic groups of prime order *p*. (2) Group element *g₁* is a generator of G₁, *g₂* is a generator of G₂. (3) Pairing function *e* : G₁ G₂*!* G*T*is a computable map with the following properties: *Bilinearity*: *8 u 2* G₁*; v 2* G₂*;* and *a;b 2* Z*; e*(*u* *a* *;v* *b* ) = *e*(*u;v*) *ab*, and *Non-degeneracy*: *e*(*g₁;g₂*) *6*= 1. (4) is an isomorphism : G₁*!* G₂, and is an isomorphism : G₂*!* G₁. We assume an ecient setup algorithm that on input security parameter, generates a bilinear group, (*p;* G₁*;*G₂*;* G*T;g₁;g₂;e;;* ) BGGen(1), where *jpj* =. If there exist eciently computable isomorphisms : G₁*!* G₂ and : G₂*!* G₁, the bilinear group is called *Type* *1*; it is called *Type 2* if there is no eciently computable isomorphism, and called *Type 3* if there is neither nor. In the AGM, group element representations including elements computed from isomorphisms are explicitly indicated along with the representation of the element passed into the isomorphism. We also extend the (*m;n*)-OM-Gap-SDHI assumption for bilinear pairing groups in the game given in Figure21. The game is identical as before except the adversary is given group elements in both G₁

|A Game m -Uber () BGGen|~ Oracle Ev(j; (X))||
|---|---|---|
|(p; G₁; G₂; G ;g₁ ;g₂ ;e;;) BGGen() T Q₁ fg; Q₂ fg m m $ ~x = [x] [Z] i p i i Ev; Decide ~ $ (j;U; (X)) A (p; G₁; G₂; G ;g₁ ;g₂ ;e;;) T (~x) ~ Return U = g ^ (Q₁ [Q₂) ??f (X) g j|Require i 2 [1; 2] ~ Q Q [f (X) g j j (~x) Return g j n ~ Oracle Decide (j; (X); [Y]) i i h i n n ~y = [y] log Y i i gj i i Return (~y) 0 p||
|The interactive, exible-output, polynomial uber assumption with decision oracle adapted for bilinear and y. The SDH and SDDH oracles are also parameterized by an input i determine which group the oracle query takes place over.)-OM-Gap-SDHI is implied by a bilinear-version m been shown to be implied by a bilinear-version q The pseudocode games describing these assumptions are given in Figure22and Figure23, respectively. The uber assumption allows the adversary to specify a group in which to receive an evaluation and tracks the polynomial queries made to each group. (for Type 1 bilinear groups), in which the winning polynomial must be independent from queries made to both groups; relaxed winning conditions can be formulated for Type 2 and 3 bilinear groups in which depending on the group of the winning element, the winning polynomial must be independent from only one query set (see [BFL20] for details). However, the general formulation is sucient for proving security of)-OM-Gap-SDHI regardless of the underlying bilinear group type. We provide the following corollaries for the security of|We provide a corollary that the bilinear-version -Uber assumption [BFL20], which in turn has -DL assumption (both reductions make use of the AGM). The winning condition is stated in the most general way|j 2 [1; 2] to|
|m;n)-OM-Gap-SDHI. We reuse the|A Game q -DL () BGGen||
|query budget notation from Section5. For any algebraic adversary A of sdhi with query budget (~q = [q₁ ;:::;q]; n|(p; G; G; G ;g ;g ;e;;) 1 2 1 2 T $ x Z p 0 $ x A p; G₁; G₂; G ;g₁ ;g₂ T 0 Return x = x|BGGen() h i q i i x x ;e;;; g₁ ;g₂ i =1|

Figure 22:

groups.

### and G₂ for sk

(*m;n*

(*m;n*

### the bilinear version of (

Corollary 16 (*m;n*)-OM-Gap-SDHI *q* SDDH)*, and any* BGGen *outputting* (*p;g₁;g₂;*G₁*;*G₂)*, where* *g₁ and g₂ are uniformly chosen elements of* G₁ *and* G₂*, we*

Figure 23: The *q*-type discrete log security game.

*give adversary A*uber*such that* (*m;n*)-om-gap-sdhi (*m*+1)-uber<u>q</u>

|||(m;n)-om-gap-sdhi|||(m+1)-uber|
|---|---|---|---|---|---|
|uber|n i i|BGGen;A max|n i i|max uber|BGGen;A|

Adv sdhi () (*q* + 1) Adv uber () +*;* *p* P *where q* = *q and q* = max*fq g. Also, A makes at most q queries to its polynomial evaluation* *oracle with maximum degree q* + 1*, and outputs a polynomial of degree at most q. Further, T*(*A*sdhi) *T* (*A*)*.*

Again, when combined with a basic reduction from [BFL20], this gives us the following immediate corol- lary.

Corollary 17 *For any algebraic adversary A*sdhi*of* (*m;n*)-OM-Gap-SDHI*, with query budget* (*~q* = [*q₁;:::;qn*]*;* *q* SDDH)*, and any* BGGen *outputting* (*p;g₁;g₂;*G₁*;*G₂)*, where g₁ and g₂ are uniformly chosen elements of* G₁ *and* G₂*, we give adversary A*dl*such that* (*m;n*)-om-gap-sdhi (*q*+1)-dl<u>q</u>

||(m;n)-om-gap-sdhi|||(q+1)-dl|
|---|---|---|---|---|
||BGGen;A||max|BGGen;A|
|n||n|||
|i i|max|i i|sdhi|dl|

Adv sdhi () (*q* + 1) Adv dl () +*;* *p* P *where q* = *q and q* = max*fq g. Further, T*(*A*) *T* (*A*)*.*

These corollaries mirror exactly the results from Section5. The proof of Corollary16follows the same approach as the proof in AppendixA; the polynomial independence argument is not aected by the which group the evaluations are given in (and for Type 1 bilinear groups, it is irrelevant).

One-more unforgeability. We provide the following theorem for the one-more unforgeability of ZSS2. A similar result can be stated for ZSS1, and its proof would be almost identical. Here, the ideal model P=H₁ H₂ consists of random oracles H₁ :*!* G₂ and H₂ :*!* Z*p*for (*p;* G₂) determined by BGGen().

|Game G||Oracle Fin(j; rep; rep⁰)||||Oracle H₁(m)||
|---|---|---|---|---|---|---|---|
|i 0; R₁|[]|If j > i then return ?||||If m 62 R₁ then||
|R₁ [];|R₂ []|If not e|g₁|pk; (rep)|= e(g₁;g₂) then|h|Z|
|pp ZSS2:Setup(|)|Return ?||||R₁[m]|g₂|
|b⁰ A|(pp)|If not e|g₁|pk; (rep⁰)|= e(g₁;g₂) then|R₁ [m]|h|
|Return b⁰||Return ?||||Return R₁[m]||
|Oracle Req(pk;t; m₀; m₁)||(rep)||||Oracle H₂(t)||
|i i + 1|||(rep) )|||If t 62 R₂ then||
|t t;|pk pk|Return (|;|||R₂[t]|Z|
|m m₀ r Z r Z Return (req|; m m; req₀ g₂; req₁ g₂; req₁)|||||Return R₂[t]||

*0* H2 (*ti*) *i* 1*=ri;b* $ *p* $ *h* $ Req*;*Fin*;*P H2 (*ti*) *i* 1*=ri;*1 *b 0*

*0* *b* *R* 1 [*mi;b*]*=ri;b* *0 R0* [*mi;*1 *b*]*=ri;*1 *b* 1 *b* 1 *i i* 0 1 $ *p* *i;*0 *i;*1 *r* 1 *i;*0 $ *p* *ri;* 0 *i;*1 $ *p* *i;*1 *b b*

Figure 24: Game transition used in blindness security proof of ZSS2 in Theorem19. Algorithms have implicit input

*pp* = (*p;* G₁*;*G₂*;* G*T;g₁;g₂;e*).

Theorem 18 *Let A*om-unf*be a* P*-model one-more unforgeability adversary against* ZSS1*. Then we give an* *adversary A*sdhi*such that*

om-unf (*q*H1*;qt*)-om-gap-sdhi <u>qt</u> 2 AdvZSS2*;*P*;A* om-unf () Adv BGGen*;A*sdhi () +*;* *p* *where q*H1*is the maximum distinct queries A*om-unf*makes to* H₁ *and qtis the maximum distinct t queries* *A*om-unf*makes to* H₂ *and* BlindSign*. Further, T*(*A*om-unf) *T* (*A*sdhi)*.*

Proof: We dene G₀ = OM-Unf *A* ZSS2 om-unf *;*P (). We rst transition to a game G₁ in which we disallow collisions in the output of H₂, i.e., we replace sampling from Z*p*for new range values with sampling without replacement from Z*p*. Recall that at most *qt*unique *t* values are queried by *A*om-unfin the course of the game, and so a standard birthday analysis establishes an upper bound of *qt*(*qt*1)*=*2*p*.

We build adversary *A*sdhito simulate exactly *A*om-unf’s environment in G₁. Adversary *A*sdhisimulates the ideal primitives by using its input values *g₂* *y* *i* as random outputs of H₁ and randomly chosen unique *cj*values as outputs of H₂. Adversary *A*sdhisimulates BlindSign by looking up (or programming) the appropriate *cj* and forwarding a query to its SDH oracle, returning the result. When *A*om-unfreturns, *A*sdhimatches the returned messages to its programmed outputs in H₁, and returns the signatures along with appropriate *g₂* *y* *i*

index, specifying group *j* = 2. Whenever *A*om-unfwins G₁, then *A*sdhialso wins (*q*H1*;qt*)-OM-Gap-SDHI because if the signatures are valid, then so will be the SDHI checks.

Blindness. ZSS describe a possible linking attack against exponential blinding [ZSS03, Footnote 1]. Adapted to our version of the scheme and notation, their claimed attack checks if *e*(*;B*) = *e*(*B⁰;*H₁(*m*)), and if so concludes that *B;B⁰* is the partially blinded protocol transcript used to generate. (Note, that this computation is only possible for type 1 pairings, or type 2 pairings if one uses the map.) However, this check *always* passes for any *B;B⁰* (with *B⁰* = *B¹* *=*(*sk*+H2 (*t*)) ), regardless of whether the transcript *B;B⁰* is associated with the signature. Instead, we provide the following theorem for the blindness of ZSS2, which uses exponential blinding.

Theorem 19 *For any* Blind *adversary A*blind*in the* P*-model against* ZSS2*, we have that*

Adv blind ZSS2*;*P*;A*blind() = 0*:*

Proof:

We transition to a game G shown in Figure24in which the requests output from Req are swapped from

|d r|d r||
|---|---|---|
|||=(sk+H (t))|

*reqd*= H₁(*m*)*d*to *req* = *g₂* *d* for *d 2f*0*;* 1*g*. Observe that the outputs of Req are now independent of challenge bit *b*. Fin is also changed. In the original game, Fin outputs valid signatures if the responses given by the adversary are equal to *rep* = *req¹* where *pk* = *g₁* *sk*; this is conrmed by the pairing verication equation. Otherwise the output is*?*. In G, the same pairing check is made to see if the adversary responded in the correct manner. If pairing check succeeds, then a valid signature is created and returned

*A*

|Game POUNIQ|()||Oracle Req(pk; sk, t;x)||
|---|---|---|---|---|
|q 0; R|[]||Require Fn:Wellformed(pk; sk)||
|pp Fn:Setup(|)||(st; req)|Fn:Req|
|st P:Init(|)||q|q + 1|
|(i;j; rep; rep|) A|(pp)|R[q]|(st; pk;t;x)|
|Require 1 (st; pk ;t (st; pk ;t|i j q ;x) R[i] ;x) R[j]||Return req||
|y Fn:Finalize|(rep : st|)|||
|y Fn:Finalize If y = ? or y Return 0|(rep : st = ? then|)|||
|Return ((pk|;t ;x) = (pk|;t ;x)) ^ (y|)||

<u>Fn;P</u>

$ P (*pk;t;x*) P $ *i j* $ Req*;*P

*i i i i* *j j j j* *i* P *i i* *j* P *j j* *i j*

*i i i j j j i 6*= *yj*

Figure 25: Security denition for uniqueness of PO-PRF outputs despite a malicious server. The highlighted code is

included for simplicity to address rogue key attacks using the knowledge of secret key model [Bol03].

by simulating H₁ and using the discrete log of the programmed hash outputs. Importantly, the output valid signatures, do not include the blinding factor *rd*and are thus, independent of the challenge bit and the outputs from Req. Therefore, the outputs of G are distributed identically to the blind security game, and since they do not depend on the challenge bit, the adversary can have no advantage.

# H Uniqueness from Request Privacy

We formalize uniqueness via game POUNIQ shown in Figure25. It is parameterized by a security parameter, a PO-PRF scheme Fn, an adversary *A*, and an ideal primitive P. The adversary can query a request oracle Req to generate honest requests for adversary-chosen public key, public input *t* and private input *x*. The adversary nishes by outputting a pair of numbers indicating one or two queries to Req, as well as two response messages *repi; repj*. The adversary wins if the triple *pk;t;x* are the same for both queries but the client can be tricked into outputting distinct *y* values. We let the advantage of a POUNIQ adversary *A* be dened by

Adv po-uniq Fn*;A;P* () = Pr POUNIQ *A* Fn*;*P()*)* 1 where the probability space is taken over the random choices made in the game. Looking ahead, our proof of uniqueness will depend on our correctness property. However, our correctness property is stated to hold for wellformed public key pairs, while uniqueness captures a malicious adversary that may use a rogue public key. To bridge this gap, we require the adversary to prove knowledge of secret keys. For simplicity, we model this by asking the adversary to provide the secret key as input to the request oracle, shown highlighted in Figure25, following the knowledge of secret key model [Bol03]. This model can be instantiated by including extractable proofs of knowledge of secret keys, from which the secret key can be extracted and the proof may proceed in the KOSK model. In the game pseudocode, we use a wellformed predicate to capture this check, i.e., for a discrete log public key *X* and secret key *x*, checks *X* = *g* *x*. The next theorem captures that POUNIQ security is implied by POPRIV2 security.

Theorem 20 *Let A be a* POUNIQ *adversary against a PO-PRF scheme* Fn*. Then we give a* POPRIV2 *adversary B such that*

Adv *po* Fn-*;A* *uniq* *;P* () Adv po-priv2 Fn*;B;P* ()*;*

*where B makes the same number of queries to its respective request oracle as A, makes at most 2 queries to* *its nalize oracle, and T*(*A*) *T* (*B*)*.*

Proof: The reduction works as follows given a POUNIQ adversary *A*. Adversary *B* (given in pseudocode in Figure26) on input *pp* runs *A* on input *pp*. Upon receiving a request query Req(*pk;t;x*), adversary *B* makes oracle call Req(*pk;t;x;x*) to its own request oracle. Adversary *B* receives back two request messages

||Req; Fin; P Adversary B (pp) Oracle SimReq(pk; sk;t;x)||
|---|---|---|
||q 0; R [] Require Fn : Wellformed(pk; sk) $ $ st P : Init() (req₀; req₁) Req(pk;t;x;x) P SimReq; P $ (i;j; rep; rep) A (pp) q q + 1 i; 0 j; 0 Require 1 i j q R [q] (pk; sk;t;x; req₁) (pk; sk ;t ;x; req) R [i] Return req₀ i i i i i; 1 (pk; sk ;t ;x; req) R [j] j j j j j; 1 P $ rep Fn : BlindEv (sk ;t; req) i i i; 1 i; 1 P $ rep Fn : BlindEv (sk ;t; req) j j j; 1 j; 1 (y ;y) Fin(i; rep; rep) i; 0 i; 1 i; 0 i; 1 (y ;y) Fin(j; rep; rep) j; 0 j; 1 j; 0 j; 1 P y Fn : Ev (sk ;t ;x) i i i If y 6 = y then return y == y i; 0 i; 1 i; 0 Return y == y j; 0 Figure 26: Adversary B against POPRIV2 used in uniqueness security proof.||
|H1 3H : Req|H2 H3 H4 (pk;t;x)||
|$ r Z p|r H3 (t) g pk; B H₁ (x) H1 H2 H3 H4 B 3H : BlindEv !|(sk;t;B)|
|Return ((3H : Finalize|pk;r;t;x) ;B) k sk B⁰ H1 H2 H3 H4 0 (B;; (pk;r;t;x)) 0 H4 $|+ H₃ (t) =k B¹ k 0|
|0 Y B Require Z H₂ (Return Z|B (k; (g;g : Prove R r =g Return (H3 (t) H4 ((g;g pk;B⁰ ;B) ;) : Ver R t;x;Y)|;B ;B)) B⁰ ;)|

Figure 27: An alternative multiplicative blinding protocol [ZSS03] that provides client-side performance bene-

ts [JKX21].

*req₀; req₁* and returns *req₀* to *A*. *B* also stores the *pk; sk;t;x; req₁* associated with the query. Recall the *sk* is known due to the knowledge of secret key model. This perfectly simulates *A*’s request oracle.

When *A* returns (*i;j; repi;*0*; repj;*0), *B* retrieves *pki*, *ski*, *ti*, *xi*, *reqi;*1and *pkj*, *skj*, *tj*, *xj*, *reqj;*1. We consider the case where *A* wins uniqueness game. In this case, (*pki i i i j j j j*

|||; sk ;t ;x|) = (pk; sk|;t ;x ) so we drop||
|---|---|---|---|---|---|
|||i i i|j|j j j||
|i;0|i;0||i;1|i;1||

the subscripts.

*B* calls Fin by responding to *req* with the *A*-provided *rep* and responding to *req* with a *rep* generated honestly. By the correctness property, we know that the value returned from the honest ow with *repi;*1 is equal to *y* = Fn*:* Ev(*sk;t;x*). If Fin returns two dierent values, then by matching which position *y* is returned reveals the challenge bit and allows *B* to win the game.

If Fin returns two identical values, then we repeat the above for the *j* query. If *A* wins the uniqueness game, then we know that Fin will not return identical values for the *j* query, so the challenge bit will be revealed, and *B* wins the game. Thus, *B* outputs the correct challenge bit in the POPRIV2 game whenever *A* wins POUNIQ.

# I Multiplicative Blinding

In this section we present an alternate client-side blinding approach applying a blinding factor using group multiplication rather than group exponentiation. This approach was originally proposed by ZSS [ZSS03]. We show that it is a secure blinding alternative for both the 3HashSDHI POPRF and for the ZSS partially blind signature. The multiplicative blind evaluation protocol is given for 3HashSDHI in Figure27. It can be adapted for ZSS by including *pk₂* = *g₂* *sk* as a second component of the public key to be used for blinding. The multiplicative blinding proofs for 3H and ZSS1 follow symmetrically as those for Theorem7and Theorem19. To create a request for multiplicative blinding that is independent of challenge bit *b*, we H₃(*t*) *r* construct the request as *B g g pk*. This gives the following corollaries:

Corollary 21 *Let A*po-priv2*be a* POPRIV2 *adversary in the* P*-model against* 3H *with multiplicative blind-* *ing that makes at most q queries to* Fin*. We give in the proof below a* Sound *A* NiZK*;R;*H4*adversary B*sound *such that*

Adv po-priv2 3H*;*P*;A*po-priv2 () 4*q* Adv sound NiZK*;R;*H4*;B*sound()) *:*

### Further, T(Bsound) T (Apo-priv2).

Corollary 22 *For any* Blind *adversary A*blind*in the* P*-model against* ZSS1 *with multiplicative blinding,* *we have that* Adv blind ZSS1*;*P*;A*blind() = 0*.*
