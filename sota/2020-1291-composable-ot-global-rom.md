# Ecient Composable Oblivious Transfer from CDH in the Global Random Oracle Model

Bernardo David¹ *?* and Rafael Dowsley²

1 IT University of Copenhagen 2 Monash University

Abstract. Oblivious Transfer (OT) is a fundamental cryptographic pro- tocol that nds a number of applications, in particular, as an essential building block for two-party and multi-party computation. We construct the rst universally composable (UC) protocol for oblivious transfer se- cure against active static adversaries based on the Computational Die- Hellman (CDH) assumption. Our protocol is proven secure in the observ- able Global Random Oracle model. We start by constructing a protocol that realizes an OT functionality with a selective failure issue, but shown to be sucient to instantiate ecient OT extension protocols. In terms of complexity, this protocol only requires the computation of 6 mod- ular exponentiations and the communication of 5 group elements, ve binary strings of security parameter length, and two binary strings of message length. Finally, we lift this weak construction to obtain a pro- tocol that realizes the standard OT functionality (without any selective failures) at an additional cost of computing 9 modular exponentiations and communicating 4 group elements, four binary strings of security parameter length and two binary strings of message length. As an inter- mediate step before constructing our CDH based protocols, we design generic OT protocols from any OW-CPA secure public-key encryption scheme with certain properties, which could potentially be instantiated from more assumptions other than CDH.

## 1 Introduction

Oblivious transfer (OT) [39,28] is a fundamental cryptographic primitive that serves as a building block for a number of interesting applications, such as secure two-party and multi-party computation. In this work, we mainly focus on 1- out-of-2 string oblivious transfer, which is a two-party primitive. In this avor of OT, the sender Alice inputs two strings *m₀* and *m₁*, and the receiver Bob inputs a choice bit *c*, obtaining *mc*as the output. Bob must not be able to learn *m₁c*, while Alice must not learn *c*. Since oblivious transfer is normally used within other protocols as a primitive, it is desirable to ensure that its security is guaranteed even under arbitrary composition. *?* This work was supported by a grant from Concordium Foundation and by Inde- pendent Research Fund Denmark grants number 9040-00399B (TrA²C) and number 9131-00075B (PUMA).

The Universal Composability (UC) framework [8] is the most widely used methodology for analyzing protocol security under arbitrary composition. OT protocols UC-secure against static malicious adversaries can be designed under several computational assumptions, such as: Decisional Die-Hellman (DDH) [30,38], strong RSA [30], Quadractic Residuosity (QR) [38], Decisional Linear (DLIN) [34,17], Decisional Composite Residuosity (DCR) [34,14], McEliece Assumptions [19], low noise Learning Parity with Noise (LPN) [18] and Learning with Errors (LWE) [38]. Furthermore, there exist constructions based on simple generic prim- itives such as enhanced trapdoor functions [12] and public-key encryption plus semi-honest stand alone oblivious transfer [33], which mostly do not achieve the same eciency as the constructions that leverage properties of specic compu- tational assumptions.

It is a well-known fact that UC-secure OT protocols require a setup assump- tion [10]. Coincidentally, most of the UC-secure OT protocols (including the aforementioned ones) are based in the Common Reference String (CRS) model, where the parties are assumed to have access to a string randomly sampled from a given distribution before execution starts. While this setup assumption allows for the construction of ecient UC-secure OT protocols under a number of assumptions, questions have been raised about its practicality [11,15], since a local CRS is not readily available for a real world implementation of a protocol. Notice that OT can be UC-realized under a number of alternative setup assump- tions, such as the public-key infrastructure model [16], the random oracle model (ROM) [4,6], noisy channels [24], tamper-proof hardware [35,23,25]. However, these models still require each instance of the protocol to access a local instance of the setup assumption. Informally, it means that each instance of the protocol uses an instance of the ideal functionality representing the setup assumption that is independent from all other instances and accessible only to the parties participating in the protocol execution but not to the environment.

Assuming that each protocol instance has local access to an independent setup in order to obtain secure composition is far from optimal and results in several issues that have been pointed out in previous works [9,5,11]. In particular, assuming the existence of independent random oracles (RO) for each protocol instance contradicts the common practice of replacing a random oracle by a standardized hash function, which is freely accessible and used by everybody. Such issues were rst analyzed and addressed by Canetti *et al.* [9], who proposed the \Generalized UC model", where it is assumed that the instance of the trusted setup is globally available (and therefore also accessible by the environment) and used by all protocol instances. This formalism was subsequently extended to the random oracle setting by Canetti *et al.* [11], who dene a global random oracle model, where a single instance of the random oracle *F*gROis directly accessible by all parties, the adversary and the environment. Such a model precludes the use of proof techniques that require the simulator to \program" the random oracle’s answers to a given query, which are usually employed in random oracle based constructions. UC protocols based on a local programmable CRS also suer from issues similar to those of local programmable ROs [11], and formally the security

guarantees for protocols based on local setups (e.g. local CRS or programmable RO) only hold if a new fresh setup is available for each individual instance of the protocol, which is unrealistic. It is not known how to generate even a single CRS without heuristics, let alone a fresh one for each execution. Quoting Canetti *et al.* [11] on the strength of the global random oracle model: \This model provides signicantly stronger composable security guarantees than the traditional random oracle model of Bellare and Rogaway [4] or even the common reference string model". Note that more than one trusted setup instance can be available (in our construction we use 3 instances of global RO), but they should be globally available and not local for a protocol instance. Surprisingly, Canetti *et al.* [11] showed that using *F*gROas a setup assumption it is possible to construct universally composable DLOG based commitments and DDH based two-party computation and non-interactive secure computation secure against static malicious adversaries. Recently, new results in the global ROM were proven assuming certain relaxations of the model [7]. However, no ecient oblivious transfer protocol in the global random oracle model has been proposed so far.

1.1 Our contributions We rst propose a generic protocol for universally composable oblivious transfer secure against active static adversaries in the global random oracle model of [11]. The central building block of this construction is a One-Way Chosen Plaintext Attack (OW-CPA) secure public-key encryption (PKE) scheme with a number of properties. We show that such a scheme can be eciently instantiated un- der the Computational Die Hellman (CDH) assumption. Our results can be summarized as follows:
3 { The *rst* UC-secure OT protocol based on the CDH assumption.

{ The rst UC-secure OT protocol in the Global Random Oracle model [11] that achieves eciency for single executions (without OT extension) compa- rable to the most ecient previous work [38], which requires a programmable 4 CRS.

In order to obtain a protocol based on an assumption as weak as CDH, we introduce novel simulation techniques for extracting choice bits and messages in the simulation without resorting to programming the random oracle, which is not possible in the global random oracle model of Canetti *et al.* [11]. Notice that previous works required stronger computational assumptions (*e.g.* DDH [38,6]) even though they relied on stronger local setup assumptions (*e.g.* CRS [38] and programmable random oracles [6]). Hence, in comparison to such previous works, our results improve on both the computational and setup assumptions required for UC-secure OT. 3 Dottling *et al.* [26] proposed an independent UC secure OT protocol in the CRS model with other techniques that yield CDH instantiations. 4 The DDH based NISC of [11] is orders of magnitude less ecient than our approach and the protocol [13] has been introduced recently as independent work.

In terms of eciency, our protocols compare favorably to previous works based on stronger assumptions. In the setting where one wishes to execute a large number of OTs through OT extension, the costs of each seed OT with our CDH based protocol are only the computation of 6 modular exponentiations and the communication of 5 group elements, 5 binary strings of security parameter length, and 2 binary strings of message length. In the setting where few OTs are needed, our CDH based protocol requires 15 modular exponentiations and the communication of 9 group elements, 9 binary strings of security parameter length, and 4 binary strings of message length. We remark that, in contrast to previous works based on local setup assumptions, our protocols can be readily implemented while retaining their security properties by substituting the global random oracle by an extensively tested cryptographic hash function (*e.g.* SHA3). As an intermediate step towards our CDH based construction, we rst de- sign a generic protocol based on a public-key encryption scheme with certain properties. We start by constructing a generic protocol that realizes an OT func- tionality that captures a selective failure issue, which is nevertheless sucient for instantiating ecient OT extension protocols as shown in [22]. Interestingly, our protocol achieves high eciency, requiring only one key generation oper- ation, two encryption operations and one decryption operation, apart from a few calls to the random oracle. In terms of communication, our protocol only requires the transfer of one public-key, two ciphertexts, ve binary strings of se- curity parameter length, and two binary strings of message length. Later on, we obtain a generic protocol that realizes the standard OT functionality (without any selective failure) by augmenting our original protocol with four encryptions, one decryption, two ciphertexts, two binary strings of security parameter length and two binary strings of message length. If hundreds of OTs are needed, our OT with selective failures represents a new option of base OT for use with OT extension schemes. If only tens of OTs are needed, our OT without selective failures is a good option for usage. Besides yielding a CDH based instantiation, these generic protocols can be potentially instantiated under other assumptions, paving the way to post-quantum secure constructions of UC-secure OT under lattice and coding based assumptions.

1.2 Related Works The global random oracle model has been established by Canetti *et al.* in [11], where they also build UC-secure commitments, two-party computation and non- interactive secure computation (NISC) secure against static malicious adver- saries. In their construction of NISC in the global ROM, they state that a natu- ral way to construct such a protocol would be to instantiate existing approaches based on 2-round OT with a global ROM version of the originally CRS based UC-secure OT protocol by Peikert *et al.* [38]. However, they observe that there are signicant challenges in obtaining such a global ROM version of the protocol by Peikert *et al.*, and instead construct a one-side simulatable OT protocol that is only UC-secure against a malicious receiver. Their solution is *not generic* but intrinsically based on DDH via non-black-box use of the OT protocol of [38], only

implying 2-round UC OT based on DDH, and with communication/computation costs several orders of magnitude higher than ours. On the other hand, ours is the rst UC OT in the GRO built in a black-box way from a generic primitive (a PKE that we dene), yielding the rst UC OT based on CDH (a weaker as- sumption) while achieving much lower computation/communication costs. Even though the global ROM was recently revisited in [7], allowing for relaxations such as programming the random oracle in specic situations, no new results related to oblivious transfer were proposed in this relaxed model. The idea of constructing OT using two public-keys | the \pre-computed" one and the \randomized" one dates back to early days of OT development [28,3]. Naor and Pinkas [37] presented an improved stand alone CDH-based protocol in the (local) random oracle model under the same approach that is proven secure in the half-simulation paradigm. A recent result by Friolo *et al.* [29] shows how to construct 4 round fully simulatable OT from key agreement protocols with certain properties without requiring setup assumptions, which yields a protocol based on CDH. However, their results fundamentally fall short of UC security (since UC-secure OT protocols necessarily require a setup assumption [10]) and cannot be easily adapted to this setting. We remark that the \Simplest OT" protocol [15] and the protocol by Hauck and Loss [32] have been found to suer from a number of issues [31,6] and are not UC secure. The CDH based protocol of [22] only realizes an OT functionality with a selective failure (as our rst simple construction) and it is unclear how to use it to realize the standard OT functionality (without selective failure). The UC OT protocol of [1] can also be instantiated from a similar generic public key encryption scheme, for which a CDH instantiation is presented (among other assumptions). However, in order to prove the security of the construction of [1], it is also necessary to assume that the public key encryption scheme has circular security, which is an ad-hoc assumption not proven under CDH.

*Independent and concurrent works:* Dottling *et al.* [26] proposed a generic round optimal UC-secure OT protocol in the CRS model that can be instantiated from CDH. However, even though their protocol solves the important problem of achieving round optimality, it has computational and communication com- plexities orders of magnitude higher than our protocol, making it impractical. These overheads are intrinsic to the use of generic zero-knowledge proofs and garbled circuits in their construction. Canetti *et al.* [13] introduced a CDH based OT protocol that is UC-secure in the Global Random Oracle model. Similarly to our initial result, they focus on obtaining OT with selective failures in order to achieve better eciency when using their protocol as basis for OT extension. However, dierently from our nal result, they do not show how to eliminate selective failures in their protocol without using OT extension.

1.3 Our Techniques At a high level, we start by building a simple generic protocol that realizes a weak version of the OT functionality, which allows for a selective failure attack.

Starting from this weak avor of OT is useful because it allows us to showcase our techniques more clearly while still being useful for performing OT exten- sion, which results in an unlimited number of standard OTs (without selective failures) at very high eciency. We then lift our protocol with selective failures to a generic protocol that realizes the standard OT functionality by leveraging subtleties of the rst, simpler, construction. The central building block for both protocols is a public-key encryption (PKE) scheme satisfying a number of prop- erties, which we construct based on the CDH assumption departing from the ElGamal cryptosystem. In order to provide some intuition on the design of our schemes, we informally describe properties we require from our PKE scheme and discuss how they are used to build our protocols:

{ *Property 1 (informal)*: Let the public-key space *PK* form a group with operation denoted by \*?*". Then, for the public-keys (pk₀*;*pk₁), such that pk₀*?* pk₁ = *q*, where *q* is chosen uniformly at random from *PK*, one can- not decrypt both ciphertexts encrypted using pk₀ and pk₁, respectively. In particular, when a public/secret-key pair (pk*c;*sk*c*) is generated, the above relationship guarantees that pk₁*c*that is chosen to satisfy the constraint pk₀*?* pk₁ = *q* is \substantially random", so that learning the messages en- crypted with pk₁*c*is hard.

{ *Property 2 (informal):* pk obtained using the key generation algorithm is indistinguishable from a random element of *PK*. Note that we assume in this work that not all the elements of *PK* may represent valid public-keys.

{ *Property 3 (informal):* The PKE scheme must be \committing", meaning that it must be impossible to generate two pairs of randomness and plain- text messages (r₀*;*m₀) and (r₁*;*m₁) with m₀ *6*= m₁ such that encrypting m₀ with randomness r₀ under a uniformly random public-key pk yields the same ciphertext as encrypting m₁ with randomness r₁ under the same public-key.

{ *Property 4 (informal):* Property 3 only holds for key pairs generated ac- cording to the key generation algorithm or picked at random, but not for arbitrary key pairs, which could be crafted to be \non-committing". Intu- itively, this property says that encrypting a message under such an arbitrary \non-committing" public key will also cause some message bits to be lost, which will come in handy in the security proof.

{ *Property 5 (informal):* The PKE scheme has a witness-recovering decryp- tion algorithm that outputs the randomness used to generate the decrypted ciphertext along with the plaintext message.

A Toy Example: Consider a very simple protocol where the receiver generates a key pair (pk*c;*sk*c*), queries a global RO with a random seed value *s* to obtain *q*, computes pk₁*c*such that pk₀*?*pk₁ = *q*, and sends pk₀ and *s* to the sender. The latter recomputes pk₁ from pk₀ and *s* with the help of the RO and uses the public- keys to encrypt random seeds. The sender then uses these seeds to generate one-time pads (using the global RO) that she uses to encrypt her messages,

sending both the PKE ciphertexts containing the seeds and the one-time pad encryptions of the actual messages to the receiver. The receiver can retrieve the seed encrypted under pk*c*(since he has sk*c*), compute the one-time pad with the help of the global RO and retrieve the message associated with his choice bit

*c*. Intuitively, Property 2 now prevents the sender from learning the choice bit, while Property 1 ensures that the receiver learns at most one of the inputs. While this simple protocol intuitively implements a stand alone oblivious transfer, it is hard to construct a simulator to prove it UC-secure in the global RO model. If programming the RO was allowed, the simulator could program the answer of the RO to a query *s* in such a way that it knows the secret keys corresponding to both pk₀ and pk₁, allowing it to extract the messages from a corrupted sender. In the case of a corrupted receiver, the simulator could wait for the RO to be queried on one of the one-time pad seed (extracting the choice bit), retrieve the message associated to that choice bit and program the answer of this RO query in such a way that the one-time pad encryption related to that seed decrypts to the message obtained from the OT functionality. However, the global RO model precludes us from using any of these techniques. Instead, we develop novel techniques for extracting both a corrupted receiver’s choice bit and a corrupted sender’s messages solely by observing global RO queries. OT with Selective Failures: As a starting point, we design a protocol that UC-realizes a weaker version of the OT functionality, which captures a selective failure attack. This attack allows a malicious sender to try and \guess" the re- ceiver’s choice bit, only being caught if her guess is wrong. Allowing this selective failure makes it easier to implement mechanisms used by the simulator to extract the choice bit from a malicious receiver without the need to program the random oracle. Even though this protocol has a selective failure issue, it has been shown in [22] that it is sucient to instantiate ecient OT extension protocols such as the one of [36]. Many applications require such a high number of oblivious transfers that it makes sense to use an actual OT protocol only to seed an OT extension, which can then be used for an unlimited number of OTs at very low cost. In order to simulate an execution with a corrupted receiver, we augment our simple protocol with a challenge-response mechanism inspired by [22] that forces the receiver to query the global RO in such a way that it reveals its choice bit to the simulator. In the real world protocol, the adversary can mount a se- lective failure attack where it can \guess" the receiver’s choice bit, being caught if it guesses the wrong bit. However, a simulator who can observe the queries made to the global RO can easily determine the receiver’s choice bit without re- sorting to a selective failure attack. This mechanism works by having the sender pick two random values p₀*;*p₁, compute a challenge ch = H(H(p₀)) + H(H(p₁)) where H( ) is the random oracle and send this challenge to the receiver along with encryptions of p₀*;*p₁. The receiver decrypts p*c*corresponding to its choice bit and answers with chr = H(H(p*c*))+*c* ch, which will always be H(H(p₀)) when ch is computed correctly. After receiving chr, the sender provides the receiver with H(p₀) and H(p₁), so that it can check that ch was correctly computed and that H(p*c*) is consistent with the value it decrypted. However, a malicious sender

can always guess the receiver’s choice bit and compute ch in such a way that it will learn the actual choice bit but only be caught if it guesses wrong. Due to Properties 1 and 3, the simulator can be assured that the query p*c*done by the receiver corresponds to its choice bit. The case of a corrupted sender is handled by a novel technique where the sender is forced to query the global RO in a way that reveals both of its messages to a simulator who can observe RO queries. The basic idea is to modify the challenge-response mechanism by having the sender query the global RO not only with the challenge seed p*i*but also adding the public-key pk*i*, and randomness r*i*used to encrypt p*i*to the query. Using Property 5, the receiver can complete the challenge-response mechanism since it can recover r*i*used in the encryption of p*i*. Using Property 3, the simulator is assured that a malicious sender could only have generated one such query for each pair of value p*i*and randomness r*i*. Hence, the simulator can check which pairs r*i;* p*i*in the list of queries to the global RO results in the ciphertexts sent by the sender when used as input to an encryption under pk*i*. After extracting both p₀*;*p₁, the simulator detects whether the adversary is trying to guess the choice bit (as well as the bit being guessed), which it forwards to the function- ality. Later on, the sender uses the same p*i*and corresponding randomness r*i*to query a dierent instance of the global RO and obtain a one-time pad used to encrypt the actual messages it wants to transfer. Hence, the simulator can also use p₀*;*p₁ to extract both messages transferred by a malicious sender.

Eliminating Selective Failures: We are also interested in solving the prob- lem of directly UC-realizing a standard OT functionality in the observable global random oracle model. In order to do so, we must eliminate the selective failure issue of our rst protocol. We observe that we can do so by basically running two instances of our rst protocol in parallel with the same public-keys pk₀ and pk₁. Notice that these public-keys encode the choice bit, meaning that the same choice bit is used in both instances. The rst instance will be used to extract the receiver’s choice bit while ensuring a malicious sender cannot learn it through a selective failure attack. The other instance will be used to execute an oblivious transfer with the previously extracted choice bit and random messages, which can be later derandomized through standard techniques. We will run both pro- tocol instances with a random choice bit, so that the receiver’s actual choice bit does not leak in case the sender mounts a selective failure attack, which will be detected causing the execution to abort. In one of these instances, we will execute the challenge-response mechanism with the additional requirement that the sender must reveal both p₀*;*r₀ and p₁*;*r₁, allowing the receiver to be sure no selective failure attack occurred. With this instance we are able to extract the receiver’s random choice bit while ensuring that in the second instance the same bit will be used (because it is encoded in the keys pk₀ and pk₁, also used in the second instance). In the second instance, we do not execute the challenge- response mechanism but use pk₀ and pk₁ to encrypt a second pair of seeds p^0*;* p^1 with randomness r₀ *0* *;*r₁ *0*, which the sender queries to another instance of the global RO to obtain one-time pads for random messages being transferred. Due to Prop-

erty 3, the simulator can extract p^0*;* p^1from the queries to the global RO and retrieve these random messages. At this point we have executed a random obliv- ious transfer, which is then derandomized to the receiver’s actual choice bit and the sender’s actual messages using standard information theoretical techniques.

## 2 Preliminaries

$ We denote by the security parameter. Let *y F* (*x*) denote running the ran- domized algorithm *F* with input *x* and random coins, and obtaining the output

*y*. When the coins *r* are specied we use *y F* (*x*; *r*). Similarly, *y F* (*x*) is
$ used for a deterministic algorithm. For a set *X*, let *x X* denote *x* chosen uni- $ formly at random from *X*; and for a distribution *Y*, let *y Y* denote *y* sampled according to the distribution *Y*. We will denote by negl() the set of negligible functions of. We abbreviate *probabilistic polynomial time* as PPT.

Encryption Schemes: The main building block used in our OT protocol is a public-key encryption scheme PKE. It has public-key *PK*, secret-key *SK*, message *M*, randomness *R* and ciphertext *C* spaces that are functions of the security parameter, and consists of a PPT key generation algorithm KG, a PPT encryption algorithm Enc and a deterministic decryption algorithm Dec. $ $ For (pk*;*sk) KG(1), any m *2 M*, and *c* Enc(pk*;*m), it should hold that Dec(sk*;*ct) = m with overwhelming probability over the used randomness. We should emphasize that for some encryption schemes not all pk f *2PK* are \valid" in the sense of being a possible output of KG. The same holds for cte *2C* in relation to Enc and all possible coins and messages. Our OT protocol uses as a building block a PKE that satises a variant of the OW-CPA security notion: informally, two random messages are encrypted under two dierent public-keys, one of which can be chosen by the adversary (but he does not have total control over both public-keys). His goal is then to recover both messages and this should be dicult. Formally, this property is captured by the following denition.

*Property 1(Double OW-CPA Security).* Consider the public-key encryption scheme PKE and the security parameter. It is assumed that *PK* forms a group with operation denoted by \*?*". For every PPT two-stage adversary *A* = (*A₁; A₂*) running the following experiment:

$ *q PK* $ (pk₀*;*pk₁*;*st) *A*1(*q*) such that pk₀*;*pk₁ *2PK* and pk₀*?* pk₁ = *q* $ m*i M* for *i* = 0*;* 1 $ ct*i*Enc(pk*i;* m*i*) for *i* = 0*;* 1 $ (mf0*;* mf1) *A*2(ct₀*;*ct₁*;*st)

it holds that Pr[(mf0*;* mf1) = (m₀*;*m₁)] *2* negl()*:*

We also need a property about the indistinguishability of a public-key gen- erated using KG and an element sampled uniformly at random from *PK*.

*Property 2(Pseudorandomness of Public-Keys).* Consider the public-key en- $ cryption scheme PKE and the security parameter. Let (pk*;*sk) KG(1) and *0*$ pk *PK*. For every PPT distinguisher *A*, it holds that

*j*Pr[*A*(pk) = 1] Pr[*A*(pk⁰) = 1]*j2* negl()*:*

Moreover, we need the PKE scheme to be committing, meaning that an adver- sary can only generate two dierent pairs of randomness and plaintext message that result in the same ciphertexts when encrypted under a uniformly random public-key with negligible probability.

*Property 3(Committing Encryption).* Consider the public-key encryption scheme PKE and the security parameter. For every PPT adversary *A*, it holds that:

2$3 pk *PK;* 6 *;* r*;* m*;* m) *A* $ (pk)*;* 7 Pr 6 4Enc(pk *;*m₀; r₀) = Enc(pk*;*m₁; r₁) (r⁰1 0 1 7 5 *2* negl() r₀*;*r₁ *2R;* m₀*;*m₁ *2M;* m₀ *6*= m₁

Note that if Properties 2 and 3 hold for some PKE, then the modied version of Property 3 in which pk is chosen using KG also trivially holds. Moreover, we will need a variation of the committing property stating that even if an adver- sary is allowed to provide an arbitrary secret and public-key pair, it cannot both decrypt a ciphertext generated under that public-key *and* break the standard committing property. The rationale behind this property is that, for some com- mitting encryption schemes, an adversary can generate an arbitrary public-key that breaks the standard committing property. However, in most cases, such a public-key will also cause plaintext information to be lost, making it impossible for the adversary to recover the original message from a ciphertext encrypted under this key with probability 1. This property is formalized in Property 4.

*Property 4(Committing Encryption with Arbitrary Keys).* Consider the public- key encryption scheme PKE and the security parameter. For every PPT two- stage adversary *A* = (*A₁; A₂*) running the following experiment: $ (pk*;*st) *A*1(1) $ $ m *M*, r *R* ct Enc(pk*;*m; r) *0 0*$ ((m*;* r)*;*(m₁*;*r₁)*;:::;* (m*n* 1*;* r*n* 1)) *A*2(ct*;*st)

it holds that

*0 0*<u>1</u> Pr[m = m*^*r = r*^*(m*i;* r*i*) *6*= (m*;*r)*^*ct Enc(pk*;* m*i;* r*i*) *8 i* = 1*;:::;n* 1] +negl()*:* *n*

We require PKE to have a *witness-recovering* decryption algorithm. Infor- mally, this property means that the decryption algorithm also recovers the ran- domness used to generate the ciphertext it takes as input. Witness-recovering decryption is formally dened in Property 5.

*Property 5(Witness-Recovering Decryption).* A public-key encryption scheme PKE = (KG*;*Enc*;*Dec) has a witness-recovering decryption algorithm Dec if it takes as input the secret-key sk *2 SK* and a ciphertext ct *2 C* and outputs either a pair (m*;*r) for m *2 M* and r *2 R* or an error symbol*?*. For any $ $ (pk*;*sk) KG(1), any m *2M*, any r *R* and *c* Enc(pk*;*m; r), it should hold that Dec(sk*;*ct) = (m*;*r) with overwhelming probability over the randomness used by the algorithms.

In Appendix D, we prove that Properties 1, 2, 3 and 4 hold for the ElGamal cryptosystems based on the CDH assumption, yielding an ecient instantia- tion of our generic protocol. Even though the ElGamal cryptosystem does not have a straightforward witness-recovery decryption algorithm, we show how any OW-CPA secure public-key encryption scheme used on random messages can be augmented with such a decryption algorithm to achieve Property 5. This can be done through the encrypt-with-hash paradigm, where the randomness used for encryption is obtained by hashing the message being encrypted, which can be proven secure in the non-programmable random oracle model.

Universal Composability in the Global Random Oracle Model: We analyze our protocol in the UC model with global random oracles as presented in [11]. We refer interested readers to the original work for more details on the UC framework [8]. In the UC model with global random oracles, the parties are assumed to have access to a global random oracle functionality *F*gRO(see Figure 1 for details) and interfaces that leak the list of illegitimate queries *Qjs*to the adversary. Dierently from the basic UC model, the global random oracle model allows all parties (including the environment) to access a single instance of *F*gRO. The *F*gROfunctionality functions as a regular random oracle but is augmented with a mechanism for leaking queries performed by parties that are not part of a given execution. In the UC model parties are identied by a unique pair of program id (PID) and session id (SID). Queries that are no prepended with the same SID as the one identifying the party *P* = (pid*;*sid) making the query are added to a list of illegitimate queries that can be requested by instances of functionalities whose session id match the one in the query. This mechanism allows the simulator to learn queries made by the environment or adversary but keeps the queries made by honest parties secret (as honest parties will follow the protocol and prepend their queries with the correct SID). Moreover, the functionalities in the global random oracle model take into consideration the existence of this list of illegitimate queries, requesting it from *F*gROand handing it to the adversary, if requested by the adversary. Our construction will actually use three instances of *F*gRO: *F*gRO1with range *PK*, *F*gRO2with range *f*0*;* 1*g* and *F*gRO3with range *f*0*;* 1*g*.

Functionality *F*gRO

*F*gRO is parameterized by a range *D* and a list of ideal functionalities *F*. { Upon receiving a query *x* from some party *P* = (pid*;*sid) or from the adversary *S* do:

If there is a pair (*x;v*) for some *v 2D* in the (initially empty) list *Q* of $ past queries, return *v* to *P*. Else, sample *v D* and store the pair (*x;v*) in *Q*. Return *v* to *P*. Parse *x* as (*s;x⁰*). If sid *6*= *s*, then add (*s;x⁰;v*) to the (initially empty) list of illegitimate queries for SID *s*, denoted by *Qjs*.

{ Upon receiving a request from an instance of an ideal functionality in the list *F*, with SID *s*, return to this instance the list *Qjs*of illegitimate queries for <u>SID s.</u>

Fig. 1. Functionality *F*gRO.

We consider a static malicious adversary. I.e., it can deviate from the pre- scribed protocol in an arbitrary way, but has to corrupt the parties before the execution starts. Oblivious Transfer: The functionality *F*OT *;‘* that provides *‘* instances of the 1-out-of-2 string (of length) oblivious transfer in the *F*gRO-hybrid model is presented in Appendix A. This work focus on obtaining a weaker form of obliv- ious transfer that allows selective failure attacks, aiming for the same type of weaker OT as in Doerner et al. [22]. The ideal functionality *F*SFOTfor 1-out- of-2 string oblivious transfer with selective failure in the *F*gRO-hybrid model is described in Figure 2. Essentially, the sender is given the option of trying to guess the choice bit of the receiver. If she makes a wrong guess, the cheating is detected and the execution aborts. If she makes a right guess, she learns the choice bit and nothing is detected by the receiver. As proved by Doerner et al. in the full version of their work [21], *F*SFOTcan be used as the base OTs in the OT extension protocol of Keller et al. [36] to UC-realize *F*OT *;‘*.

Lemma 1. *The OT extension protocol of Keller et al. [36] UC-realizes F*OT *;‘* *in* *the F*SFOT*; F*gRO*-hybrid model.*

*Proof.* This follows directly from Lemma D.3 of [21], which proves that the rst part of the OT extension protocol UC-realizes the correlated OT with errors functionality *F*COTein the *F*SFOT*; F*gRO-hybrid model, and the reduction from *F*OT *;‘* to *F*COTeusing the remaining steps of the OT extension protocol [36].

## 3 The Generic Protocol

Our protocol uses as a building block a public-key encryption scheme that satis- es Properties 1, 2, 3, 4 and 5 (dened in Section 2). The basic high-level idea is

Functionality *F*SFOT.

*F*SFOTis parameterized by the length of the messages *2* N, which is publicly known. *F*SFOTinteracts with a sender Alice and a receiver Bob, proceeding as fol- lows:

{ Upon receiving a message (choose*;*sid*;c*) from Bob, where *c 2 f*0*;* 1*g*, record (sid*;*choice*;c*), send (chosen*;*sid) to Alice, and ignore future messages (choose*;*sid*;*) with the same sid.

{ Upon receiving a message (guess*;*sid*; c*^) from Alice, where ^*c 2 f*0*;* 1*; ?;* force*g*, if a tuple (sid*;*choice*;c*) is recorded, then record (sid*;*guess*; c*^), ignore future messages (guess*;*sid*;*) with the same sid and do the following:

1.If ^*c* =*?*, send (no cheat*;*sid) to Bob.
2.If ^*c* = *c*, send (cheat undetected*;*sid) to Alice and (no cheat*;*sid) to Bob.
3.If ^*c 6*= *c* or ^*c* = force, send (cheat detected*;*sid*;c*) to both Alice and Bob.
{ Upon receiving a message (send*;*sid*; x₀; x₁*) from Alice, where each *xi 2f*0*;* 1*g*, if there are tuples (sid*;*choice*;c*) and (sid*;*guess*; c*^) recorded such that ^*c* =*?* or *c*^ = *c*, then send (output*;*sid*; xc*) to Bob and ignore further messages from Alice with the same sid.

{ When asked by *S*, obtain from *F*gRO the list *Qj*sidof illegitimate queries for SID <u>sid and send it to S.</u>

Fig. 2. Functionality *F*SFOTin the Global Random Oracle model.

that Bob picks two public-keys pk₀*;*pk₁ such that he only knows the secret-key corresponding to pk*c*(where *c* is his choice bit) and hands them to Alice. She then uses the two public-keys to transmit two messages in an encrypted way, so that Bob can only recover the message for which he knows the secret-key sk*c*.

A crucial point in such schemes is making sure that Bob is only able to decrypt one of the messages. In order to enforce this property, our protocol relies on Property 1 and uses the random oracle to force the element *q* to be chosen uniformly at random from *PK*. After generating the pair of public and secret-key (pk*c;*sk*c*), Bob samples a seed *s*, queries the random oracle *F*gRO1with *s* to obtain *q*, and computes pk₁*c*such that pk₀*?* pk₁ = *q*. Bob then hands the public-key pk₀ and the seed *s* to Alice, enabling her to also compute pk₁. Since the public- keys are indistinguishable according to Property 2, Alice learns nothing about Bob’s choice bit. Next, Alice picks two uniformly random strings p₀*;*p₁, queries them to the random oracle *F*gRO2obtaining pe₀*;*pe₁ as response, and then she computes one-time pad encryptions of her messages m₀*;*m₁ as mf0= m₀ pe₀ and mf1= m₁ pe₁. Alice also computes ct₀ Enc(pk₀*;*p₀; r₀), ct₁ Enc(pk₁*;*p₁; r₁) and sends (mf0*;* mf1*;*ct₀*;*ct₁) to Bob. Bob can use sk*c*to decrypt ct*c*obtaining p*c*. He then queries p*c*to the random oracle *F*gRO2obtaining pe*c*as response, and retrieves m*c*= mf*c*pe*c*. Due to Property 1, Bob will not be able to recover p₁*c*

ProtocolSFOT

Let PKE be a public-key encryption scheme that satises Properties 1, 2, 3, 4 and 5, and be the security parameter. ProtocolSFOTis executed between Alice with inputs m₀*;*m₁ *2 f*0*;* 1*g* and Bob with input *c 2 f*0*;* 1*g*. Three instances of the random oracle ideal functionality *F*gRO are used: *F*gRO1 with range *PK*, *F*gRO2 with range *f*0*;* 1*g*, and *F*gRO3 with range *f*0*;* 1*g*. Alice and Bob proceed as follows: $

1. Bob generates a pair of keys (pk*c;*sk*c*) KG(1). He samples a random string $ *s f* 0*;* 1*g* and sends (sid*;s*) to *F*gRO1, obtaining *q* as answer. Bob computes pk₁*c*such that pk₀*?* pk₁ = *q* and sends (sid*;s;* pk₀) to Alice.
2.Upon receiving (sid*;s;* pk₀) from Bob, Alice queries *F*gRO1 with (sid*;s*), ob- taining answer *q*. Alice computes pk₁ such that pk₀*?* pk₁ = *q*. She sam-
$ $ ples p₀*;*p₁ *f* 0*;* 1*g*, r₀*;*r₁ *R* and queries *F*gRO3 with (sid*;*pk₀*;*p₀*;*r₀) and (sid*;*pk₁*;*p₁*;*r₁), obtaining p⁰0and p⁰1as answers. She then queries *F*gRO3 with (sid*;*p⁰0) and (sid*;*p⁰1), obtaining p⁰⁰0and p⁰⁰1as answers, and computes ch p⁰⁰0p⁰⁰1. Alice computes ct₀ Enc(pk₀*;*p₀; r₀), ct₁ Enc(pk₁*;*p₁; r₁), and sends (sid*;*ch*;*ct₀*;*ct₁) to Bob.

3.Upon receiving (sid*;*ch*;*ct₀*;*ct₁) from Alice, Bob computes (p*c;* r*c*) Dec(sk*c;*ct*c*). Bob queries *F*gRO3 with (sid*;*pk*c;* p*c;* r*c*) obtaining p
*0c* as the an- swer, and then with (sid*;* p *0c* ) obtaining p⁰⁰*c*. Bob computes chr p⁰⁰*c*(*c* ch) and sends (sid*;*chr) to Alice.

4.Upon receiving (sid*;*chr) from Bob, Alice veries that chr = p⁰⁰0. If this check fails, Alice aborts. Otherwise, Alice queries *F*gRO2 with (sid*;*pk₀*;*p₀*;*r₀) and (sid*;*pk₁*;*p₁*;*r₁), obtaining pe₀ and pe₁ as answers. Alice computes mf0 = pe₀ m₀, mf1 = pe₁ m₁. Alice sends (sid*;* mf0*;* mf1*;*p⁰0*;*p⁰1) to Bob.
5.Upon receiving (sid*;* mf0*;* mf1*;*p⁰0*;*p⁰1) from Alice, Bob checks if the p
*0c* that he received from Alice matches the one he locally computed. He also queries *F*gRO3 with (sid*;*p⁰1 *c*) obtaining p⁰⁰1 *c*, and checks if ch = p⁰⁰0p⁰⁰1. If any check fails, Bob aborts. Otherwise, he queries *F*gRO2 with (sid*;*pk*c;* p*c;* r*c*) obtaining pe*c* as <u>answer, and computes m</u>*c* <u>mf</u>*c* <u>pe</u>*c*<u>. Bob outputs m</u>*c*<u>.</u>

Fig. 3. ProtocolSFOT

in order to query it to the random oracle and to decrypt m]1 *c*. Therefore, the security for Alice is also guaranteed. Even though this simple protocol seemingly performs an oblivious transfer, it poses signicant challenges for a proof in the Global Random Oracle model of Canetti et al. [11], where the simulator cannot program the answers to random oracle queries. In the case of a malicious sender, the simulator would need to generate a seed *s* and public key pk₀ such that it knows both secret keys asso- ciated to the resulting public keys pk₀ and pk₁, which it needs to know in order to extract the messages m₀ and m₁. However, while this is easy if the simulator

could program an arbitrary random oracle answer given the seed *s*, it cannot be done in this model. In the case of a malicious receiver, Property 2 ensures that the simulator cannot learn any information about the choice bit *c* before the adversary queries the random oracle on p*c*, which only happens *after* the simulator has sent its last message. The simulator could possibly program the random oracle answer given p*c*so that the result is m*c*(received from the OT functionality), but this is not possible in this setting. In order to circumvent these challenges, we augment the simple protocol described before with mecha- nisms that allow the simulator to extract the choice bit *c* and messages m₀ and m₁ without resorting to programming the random oracle. In order to obtain security against a malicious receiver, we use a challenge- response mechanism that follows the approach of Doerner et al. [22]. Basically, before carrying out the actual transfer, Alice queries (pk₀*;*p₀*;*r₀) and (pk₁*;*p₁*;*r₁) ) ob-

|to the random oracle F||(note that this oracle is dierent from F||||
|---|---|---|---|---|---|
|||gRO3|||gRO2|
||0 1||0 1||gRO3|
|0 1|||0|1||
|gRO3|c c|c||0c|0c|
|c|c|||||
|0||0 1||||

taining p⁰*;*p⁰, and then queries p⁰*;*p⁰ to the random oracle *F* obtaining p⁰⁰*;*p⁰⁰. Alice xes the challenge as ch p⁰⁰ p⁰⁰ and sends ch to Bob. Bob queries *F* with (pk*;* p*;* r), which is possible because PKE has witness-recovering decryption according to Property 5, obtaining p and then with p obtaining p⁰⁰. Bob returns p⁰⁰ (*c* ch) to Alice, who checks if the returned value is equal to p⁰⁰. Alice then sends p⁰*;*p⁰ to Bob, who checks if these values are compatible with the values he previously computed and ch. After receiving a valid response from Bob, Alice proceeds with the transfer. A crucial aspect of this mechanism is that in order to obtain p⁰⁰*c*, Bob is forced to rst issue a query associated to its choice bit *c* to the random oracle, allowing for extraction. In the proof, the sim- ulator can extract *c* solely by observing the adversary’s queries after it receives the challenge, allowing it to obtain m*c*from the OT functionality and prepare the last message to the adversary accordingly. This mechanism allows selective failure attacks, but the resulting scheme fullls the requirements to be used as base OTs in the OT extension scheme of Keller et al. [36] (see Section 2). Instead of querying *F*gRO2with p₀*;*p₁, we query it with (pk₀*;*p₀*;*r₀) and (pk₁*;*p₁*;*r₁) to obtain pe₀*;*pe₁. These queries of the form (pk*i;* p*i;* r*i*) to *F*gRO2and *F*gRO3allow the simulator to extract both of the corrupt sender’s messages solely by observing the queries to the random oracle. In the simulation, the simulator

||^ = Enc(pk|^; p; ^r ) from all random oracle queries of|||
|---|---|---|---|---|
||j|i j j|||
|i j j|||j||
||||i||

reconstructs ciphertexts ct the form (pk*;* p^*;*^r), looking for a ciphertext ct^ that matches ciphertext ct*i* (for *i 2f*0*;* 1*g*) in the adversary’s message. Having found these ciphertexts the simulator can proceed to recover each message m. An adversary could try to confuse the simulator by making two dierent queries to the random oracle that pass the tests above. However, this is not possible due to Properties 3 and 4. ProtocolSFOTis described in Figure 3 and its security if formally stated in Theorem 1, which we prove in Appendix B. A CDH based instantiation is described in Appendix D.

Theorem 1. *Let* PKE *be a public-key encryption scheme that satises Proper-* *ties 1, 2, 3, 4 and 5. When instantiated with* PKE*, ProtocolSFOTUC-realizes*

*functionality F*SFOT*with security against static malicious adversaries in the* *global random oracle model.*

*;*1

## 4 Realizing F

OT directly

Our previous generic protocol can be modied to directly realize the standard 1-out-of-2 OT functionality *F*OT *;*1 without any selective failure issues, instead of rst realizing *F*SFOTand then employing the OT extension of Keller *et al.* to realize *F*OT *;‘*. However, we will rely directly on the specic CDH based PKE of Appendix D instead of a generic PKE with Properties 1, 2, 3, 4 and 5. This is necessary since the simulator will now need to extract messages encrypted under this PKE that it cannot extract by simply observing queries to the random oracle instances used in the protocol but that can be extracted by observing queries to the random oracle instance used by this specic PKE construction. In order to eliminate the potential selective failure from our rst protocol, we need to provide Bob with a proof that Alice has used exactly the values p₀*;*p₁ contained in ciphertexts ct₀*;*ct₁ to generate challenge ch. The main idea is to use two instances of our original protocol that are run using the same public keys pk₀*;*pk₁ (encoding the same choice bit). One of them is used to execute the challenge-response mechanism and the other is used to execute a random OT, which can be later derandomized. In our previous protocol, Alice only reveals the outputs of *F*gRO3upon being queried with (sid*;*pk*i;* p*i;* r*i*), which only allows Bob to check that these were the values used in the challenge with probability <u>1</u> 2. In order to prove that those values were indeed used, we will leverage the committing property (Property 3) of the underlying cryptosystem and have Alice reveal p₀*;*p₁*;*r₀*;*r₁ to Bob upon getting a valid response to the challenge. Using these values, Bob can recompute the challenge (checking that $ it matches ch received from Alice) and check that ct*i*Enc(pk*i;* p*i*; r*i*), for *i* = *f*0*;* 1*g*. If those checks fail, the receiver aborts but, if they succeed, it is assured by the committing property that those values were used in computing ct₀, ct₁ and ch (meaning the choice bit was not leaked). Having both p₀*;*p₁ revealed to Bob, we will need to have Alice generate new p^0*;* p^1and corresponding ct ^0*;*ct^1to complete the OT as in our rst protocol. However, notice that this protocol still leaks Bob’s choice bit to an adversary who mounts a successful selective failure attack, even though the attack is detected and the protocol is aborted. In order to deal with this, Bob uses a random choice bit to execute a random OT that is derandomized after Bob is certain no selective failure attack occurred. The simulator for a corrupt Alice does not have to extract the \guess" bit of the adversary, just acting as an honest Bob and extracting the messages m₀*;*m₁ using the same techniques as the simulator inSFOT. However, it will need to extract messages p^0*;* p^1from the ciphertexts ct^0*;*ct^1by observing queries to the random oracle used in the CDH based PKE from Appendix D. The simulator for a corrupt Bob uses the same techniques as the simulator inSFOTto extract the choice bit. The dierence is that the ciphertexts ct⁰0*;*ct⁰1obtained from the

challenger in the game of Property 1 are given to the adversary as ct*c;*ct^1 *c*in the reduction showing that an adversary that obtains m₁*c*when interacting with this simulator breaks Property 1. ProtocolOTis described in Figure 4 and its security if formally stated in Theorem 2, which we prove in Appendix C. The CDH based PKE instantiation is described in Appendix D.

Theorem 2. *Under the CDH assumption, ProtocolOTUC-realizes functional-* *ity F*OT *;*1 *with security against static malicious adversaries in the global random* *oracle model.*

## References

1.Paulo S. L. M. Barreto, Bernardo David, Rafael Dowsley, Kirill Morozov, and An- derson C. A. Nascimento. A framework for ecient adaptively secure composable oblivious transfer in the rom. Cryptology ePrint Archive, Report 2017/993, 2017. [https://eprint.iacr.org/2017/993](https://eprint.iacr.org/2017/993).
2.Mihir Bellare, Alexandra Boldyreva, and Adam O’Neill. Deterministic and e- ciently searchable encryption. In Alfred Menezes, editor, *CRYPTO 2007*, volume 4622 of *LNCS*, pages 535{552. Springer, Heidelberg, August 2007.
3.Mihir Bellare and Silvio Micali. Non-interactive oblivious transfer and applications. In Gilles Brassard, editor, *CRYPTO’89*, volume 435 of *LNCS*, pages 547{557. Springer, Heidelberg, August 1990.
4.Mihir Bellare and Phillip Rogaway. Random oracles are practical: A paradigm for designing ecient protocols. In V. Ashby, editor, *ACM CCS 93*, pages 62{73. ACM Press, November 1993.
5.Christina Brzuska, Marc Fischlin, Heike Schroder, and Stefan Katzenbeisser. Phys- ically uncloneable functions in the universal composition framework. In Phillip Rogaway, editor, *CRYPTO 2011*, volume 6841 of *LNCS*, pages 51{70. Springer, Heidelberg, August 2011.
6.Megha Byali, Arpita Patra, Divya Ravi, and Pratik Sarkar. Ecient, round- optimal, universally-composable oblivious transfer and commitment scheme with adaptive security. Cryptology ePrint Archive, Report 2017/1165, 2017. https: //eprint.iacr.org/2017/1165.
7.Jan Camenisch, Manu Drijvers, Tommaso Gagliardoni, Anja Lehmann, and Gre- gory Neven. The wonderful world of global random oracles. In Jesper Buus Nielsen and Vincent Rijmen, editors, *EUROCRYPT 2018, Part I*, volume 10820 of *LNCS*, pages 280{312. Springer, Heidelberg, April / May 2018.
8.Ran Canetti. Universally composable security: A new paradigm for cryptographic protocols. In *42nd FOCS*, pages 136{145. IEEE Computer Society Press, October
2001.
9.Ran Canetti, Yevgeniy Dodis, Rafael Pass, and Shabsi Walsh. Universally com- posable security with global setup. In Salil P. Vadhan, editor, *TCC 2007*, volume 4392 of *LNCS*, pages 61{85. Springer, Heidelberg, February 2007.
10.Ran Canetti and Marc Fischlin. Universally composable commitments. In Joe Kilian, editor, *CRYPTO 2001*, volume 2139 of *LNCS*, pages 19{40. Springer, Hei- delberg, August 2001.

ProtocolOT

Let PKE be the CDH based public-key encryption scheme of Appendix D that satises Properties 1, 2, 3, 4 and 5, and be the security parameter. Protocol OTis executed between Alice with inputs m₀*;*m₁ *2 f*0*;* 1*g* and Bob with input *c 2f*0*;* 1*g*. Bob and Alice interact with each other and with four instances of the random oracle ideal functionality: *F*gRO1 with range *PK*, *F*gRO2 with range *f*0*;* 1*g*, *F*gRO3 with range *f*0*;* 1*g*, and *F*gRO4 with range *R* (used by PKE). ProtocolOT proceeds as follows: *0*$ $

1. Bob samples *c f* 0*;* 1*g* and generates a pair of keys (pk*c0;*sk*c0*) KG(1). He
$ samples a random string *s f* 0*;* 1*g* and sends (sid*;s*) to *F*gRO1, obtaining *q* as answer. Bob computes pk₁*c0*such that pk₀*?* pk₁ = *q* and sends (sid*;s;* pk₀) to Alice.

2.Upon receiving (sid*;s;* pk₀) from Bob, Alice queries *F*gRO1 with (sid*;s*), obtaining answer *q* and computing pk₁ such that pk₀*?*pk₁ = *q*. For *i 2f*0*;* 1*g*, Alice samples $ $*0i* p *i* *;* p^*i f* 0*;* 1*g* and r*i;*^r*i R*, queries *F*gRO3 with (sid*;*pk*i;* p*i;* r*i*), obtaining p as answer, and then queries *F*gRO3 with (sid*;* p
*0i* ), obtaining p⁰⁰*i*as answer. Alice computes ch p⁰⁰0p⁰⁰1. For *i 2f*0*;* 1*g*, Alice computes ct*i* Enc(pk*i;* p*i*; r*i*), ct ^*i* Enc(pk *i* *;* p^*i*; ^r*i*). Alice sends (sid*;*ch*;*ct₀*;*ct₁*;*ct^0*;*ct^1) to Bob.

3.Upon receiving (sid*;*ch*;*ct₀*;*ct₁*;*ct^0*;*ct^1) from Alice, Bob computes (p*c0;* r*c0*) Dec(sk*c0;*ct*c0*), queries *F*gRO3 with (sid*;*pk*c0;* p*c0;* r*c0*), obtaining p
*0c0* as the an- swer, and then queries *F*gRO3 with (sid*;* p *0c0* ), obtaining p⁰⁰*c0*as the answer. Bob computes chr p⁰⁰*c0*(*c⁰* ch) and sends (sid*;*chr) to Alice.

4.Upon receiving (sid*;*chr) from Bob, Alice veries that chr = p⁰⁰0. If this check fails, Alice aborts. Otherwise, for *i 2f*0*;* 1*g*, Alice queries *F*gRO2 with (sid*;*pk*i;* p^*i;*^r*i*)
$ (obtaining pe*i* as answer), samples m^*i f* 0*;* 1*g* and computes mf*i* = pe*i* m^*i*. Alice sends (sid*;* mf0*;* mf1*;*p₀*;*p₁*;*r₀*;*r₁) to Bob.

5.Upon receiving (sid*;* mf0*;* mf1*;*p₀*;*p₁*;*r₀*;*r₁) from Alice, for *i 2f*0*;* 1*g*, Bob checks that ct*i* = Enc(pk*i;* p*i;* r*i*) and queries *F*gRO3 with (sid*;*pk*i;* p*i;* r*i*) (obtaining p
*0i* as answer) and queries *F*gRO3 with (sid*;* p *0i* ) (obtaining p⁰⁰*i*as answers). Next Bob checks that ch = p⁰⁰0p⁰⁰1. If any checks fail, Bob aborts. Otherwise, Bob com- putes (p^*c0;*^r*c0*) Dec(sk*c0;*ct^*c0*). If this decryption fails with*?* Dec(sk*c0;*ct^*c0*), $ Bob samples a random (p^*c0;*^r*c0*) *f* 0*;* 1*g R* in order to avoid a selective fail- ure. Bob queries *F*gRO2 with (sid*;*pk*c0;* p^*c0;*^r*c0*), obtaining ep*c0*as answer, com- putes m^*c0*mg*c0*pf*c0*, sets *d c c⁰* and sends (sid*;d*) to Alice.

6.Upon receiving (sid*;d*) from Bob, Alice sets m⁰0m^*d*m₀*;*m⁰1m^1 *d*m₁. Alice sends (sid*;*m⁰0*;*m⁰1) to Bob.
7.Upon receiving (sid*;*m⁰0*;*m⁰1) from Alice, Bob computes m*c* = m
*0c* m^*c0*, outputs <u>m</u>*c* <u>and halts.</u>

Fig. 4. ProtocolOT

11.Ran Canetti, Abhishek Jain, and Alessandra Scafuro. Practical UC security with a global random oracle. In Gail-Joon Ahn, Moti Yung, and Ninghui Li, editors, *ACM CCS 14*, pages 597{608. ACM Press, November 2014.
12.Ran Canetti, Yehuda Lindell, Rafail Ostrovsky, and Amit Sahai. Universally com- posable two-party and multi-party secure computation. In *34th ACM STOC*, pages 494{503. ACM Press, May 2002.
13.Ran Canetti, Pratik Sarkar, and Xiao Wang. Blazing fast OT for three-round UC OT extension. *IACR Cryptology ePrint Archive*, 2020:110, 2020. To appear at PKC 2020.
14.Seung Geol Choi, Jonathan Katz, Hoeteck Wee, and Hong-Sheng Zhou. Ecient, adaptively secure, and composable oblivious transfer with a single, global CRS. In Kaoru Kurosawa and Goichiro Hanaoka, editors, *PKC 2013*, volume 7778 of *LNCS*, pages 73{88. Springer, Heidelberg, February / March 2013.
15.Tung Chou and Claudio Orlandi. The simplest protocol for oblivious trans- fer. In Kristin E. Lauter and Francisco Rodrguez-Henrquez, editors, *LATIN-* *CRYPT 2015*, volume 9230 of *LNCS*, pages 40{58. Springer, Heidelberg, August
2015.
16.Ivan Damgard and Jesper Buus Nielsen. Universally composable ecient multi- party computation from threshold homomorphic encryption. In Dan Boneh, editor, *CRYPTO 2003*, volume 2729 of *LNCS*, pages 247{264. Springer, Heidelberg, Au- gust 2003.
17.Ivan Damgard, Jesper Buus Nielsen, and Claudio Orlandi. Essentially optimal universally composable oblivious transfer. In Pil Joong Lee and Jung Hee Cheon, editors, *ICISC 08*, volume 5461 of *LNCS*, pages 318{335. Springer, Heidelberg, December 2009.
18.Bernardo David, Rafael Dowsley, and Anderson C. A. Nascimento. Universally composable oblivious transfer based on a variant of LPN. In Dimitris Gritzalis, Aggelos Kiayias, and Ioannis G. Askoxylakis, editors, *CANS 14*, volume 8813 of *LNCS*, pages 143{158. Springer, Heidelberg, October 2014.
19.Bernardo Machado David, Anderson C. A. Nascimento, and Jorn Muller-Quade. Universally composable oblivious transfer from lossy encryption and the McEliece assumptions. In Adam Smith, editor, *ICITS 12*, volume 7412 of *LNCS*, pages 80{99. Springer, Heidelberg, August 2012.
20.Yevgeniy Dodis, Victor Shoup, and Shabsi Walsh. Ecient constructions of composable commitments and zero-knowledge proofs. In David Wagner, editor, *CRYPTO 2008*, volume 5157 of *LNCS*, pages 515{535. Springer, Heidelberg, Au- gust 2008.
21.Jack Doerner, Yashvanth Kondi, Eysa Lee, and abhi shelat. Secure two-party threshold ECDSA from ECDSA assumptions. Cryptology ePrint Archive, Report 2018/499, 2018. [https://eprint.iacr.org/2018/499](https://eprint.iacr.org/2018/499).
22.Jack Doerner, Yashvanth Kondi, Eysa Lee, and Abhi Shelat. Secure two-party threshold ECDSA from ECDSA assumptions. In *2018 IEEE Symposium on Secu-* *rity and Privacy*, pages 980{997. IEEE Computer Society Press, May 2018.
23.Nico Dottling, Daniel Kraschewski, and Jorn Muller-Quade. Unconditional and composable security using a single stateful tamper-proof hardware token. In Yuval Ishai, editor, *TCC 2011*, volume 6597 of *LNCS*, pages 164{181. Springer, Heidel- berg, March 2011.
24.Rafael Dowsley, Jorn Muller-Quade, and Anderson C. A. Nascimento. On the composability of statistically secure random oblivious transfer. *Entropy*, 22(1):107,
2020.

25.Rafael Dowsley, Jorn Muller-Quade, and Tobias Nilges. Weakening the isolation assumption of tamper-proof hardware tokens. In Anja Lehmann and Stefan Wolf, editors, *ICITS 15*, volume 9063 of *LNCS*, pages 197{213. Springer, Heidelberg, May 2015.
26.Nico Dttling, Sanjam Garg, Mohammad Hajiabadi, Daniel Masny, and Daniel Wichs. Two-round oblivious transfer from cdh or lpn. Cryptology ePrint Archive, Report 2019/414, 2019. [https://eprint.iacr.org/2019/414](https://eprint.iacr.org/2019/414).
27.Taher ElGamal. A public key cryptosystem and a signature scheme based on discrete logarithms. In G. R. Blakley and David Chaum, editors, *CRYPTO’84*, volume 196 of *LNCS*, pages 10{18. Springer, Heidelberg, August 1984.
28.Shimon Even, Oded Goldreich, and Abraham Lempel. A randomized protocol for signing contracts. *Commun. ACM*, 28(6):637{647, June 1985.
29.Daniele Friolo, Daniel Masny, and Daniele Venturi. A black-box construction of fully-simulatable, round-optimal oblivious transfer from strongly uniform key agreement. Cryptology ePrint Archive, Report 2018/473, 2018. (To appear in TCC 2019) [https://eprint.iacr.org/2018/473](https://eprint.iacr.org/2018/473).
30.Juan A. Garay. Ecient and universally composable committed oblivious transfer and applications. In Moni Naor, editor, *TCC 2004*, volume 2951 of *LNCS*, pages 297{316. Springer, Heidelberg, February 2004.
31.Ziya Alper Gen, Vincenzo Iovino, and Alfredo Rial. "the simplest protocol for oblivious transfer" revisited. Cryptology ePrint Archive, Report 2017/370, 2017. [https://eprint.iacr.org/2017/370](https://eprint.iacr.org/2017/370).
32.Eduard Hauck and Julian Loss. Ecient and universally composable protocols for oblivious transfer from the cdh assumption. Cryptology ePrint Archive, Report 2017/1011, 2017. [http://eprint.iacr.org/2017/1011](http://eprint.iacr.org/2017/1011).
33.Carmit Hazay and Muthuramakrishnan Venkitasubramaniam. On black-box com- plexity of universally composable security in the CRS model. In Tetsu Iwata and Jung Hee Cheon, editors, *ASIACRYPT 2015, Part II*, volume 9453 of *LNCS*, pages 183{209. Springer, Heidelberg, November / December 2015.
34.Stanislaw Jarecki and Vitaly Shmatikov. Ecient two-party secure computation on committed inputs. In Moni Naor, editor, *EUROCRYPT 2007*, volume 4515 of *LNCS*, pages 97{114. Springer, Heidelberg, May 2007.
35.Jonathan Katz. Universally composable multi-party computation using tamper- proof hardware. In Moni Naor, editor, *EUROCRYPT 2007*, volume 4515 of *LNCS*, pages 115{128. Springer, Heidelberg, May 2007.
36.Marcel Keller, Emmanuela Orsini, and Peter Scholl. Actively secure OT extension with optimal overhead. In Rosario Gennaro and Matthew J. B. Robshaw, editors, *CRYPTO 2015, Part I*, volume 9215 of *LNCS*, pages 724{741. Springer, Heidelberg, August 2015.
37.Moni Naor and Benny Pinkas. Ecient oblivious transfer protocols. In S. Rao Kosaraju, editor, *12th SODA*, pages 448{457. ACM-SIAM, January 2001.
38.Chris Peikert, Vinod Vaikuntanathan, and Brent Waters. A framework for e- cient and composable oblivious transfer. In David Wagner, editor, *CRYPTO 2008*, volume 5157 of *LNCS*, pages 554{571. Springer, Heidelberg, August 2008.
39.Michael O. Rabin. How to exchange secrets by oblivious transfer. Technical Report Technical Memo TR-81, Aiken Computation Laboratory, Harvard University, 1981.

## A OT Functionality

The functionality *F*OT *;‘* that provides *‘* instances of the 1-out-of-2 string (of length ) oblivious transfer in the *F*gRO-hybrid model is presented in Figure 5.

Functionality *F*OT *;‘*.

*F*OT *;‘* is parameterized by the length of the messages *2* N and by the number of message pairs *‘*, which are publicly known. *F*OT *;‘* interacts with a sender Alice and a receiver Bob, proceeding as follows:

{ Upon receiving a message (send*;*sid*; x₀;*1*; x₁;*1*;:::; x₀;‘; x₁;‘*) from Alice, where each *xi;j 2f*0*;* 1*g*, store the tuple (sid*;*sent*; x₀;*1*; x₁;*1*;:::; x₀;‘; x₁;‘*) and send (sent*;*sid) to Bob. Ignore further messages from Alice with the same sid.

{ Upon receiving a message (choose*;*sid*;c₁;:::;c‘*) from Bob, where each *cj 2* *f*0*;* 1*g*, check if a tuple (sid*;*sent*; x₀;*1*; x₁;*1*;:::; x₀;‘; x₁;‘*) was recorded. If yes, send (output*;*sid*; xc*1*;*1*;:::; xc‘;‘*) to Bob and (received*;*sid) to Alice, and ignore further messages from Bob with the same sid. Otherwise, send nothing, but continue running.

{ When asked by *S*, obtain from *F*gRO the list *Qj*sidof illegitimate queries for SID <u>sid and send it to S.</u>

Fig. 5. Functionality *F*OT

*;‘* in the Global Random Oracle model.

## B Security Analysis of ProtocolSFOT

In this appendix we analyse the security of ProtocolSFOTand present a full proof of Theorem 1. First we discuss the correctness of ProtocolSFOT. In Steps 2 and 3, if the message (sid*;*ch*;*ct₀*;*ct₁) is correctly generated by Alice, Bob is able to decrypt ct*c*with the secret-key sk*c*to obtain p*c*and r*c*(due to Property 5), allowing him to compute the right answer to the challenge, and also to decrypt m*c*in Step 5. We now formally state the security ofSFOTin Theorem 1.

Theorem 1 *Let* PKE *be a public-key encryption scheme that satises Properties* *1, 2, 3, 4 and 5. When instantiated with* PKE*, ProtocolSFOTUC-realizes the* *functionality F*SFOT*against static malicious adversaries in the global random* *oracle model.*

*Proof.* In order to prove the security ofSFOT, we will construct a simulator *S* such that no environment *Z* can distinguish between interactions with an adversary *A* throughSFOTin the real world and with *S* and *F*SFOTin the ideal world. For the sake of clarity, we will describe the simulator *S* separately for

dierent corruption scenarios. In all cases, *S* writes all the messages received from *Z* in *A*’s input tape, simulating *A*’s environment. Also, *S* writes all messages from *A*’s output tape to its own output tape, forwarding them to *Z*. Notice that simulating the cases where both Bob and Alice are corrupted or honest is trivial. If both parties are corrupted, *S* simply runs *A* internally. In this case, *A* generates the messages from both corrupted parties. If neither Alice nor Bob are corrupted, *S* runs the protocol between honest Alice and Bob internally on the inputs provided by *Z* and all messages are delivered to *A*. We analyze the cases where only Bob is corrupted and where only Alice is corrupted below.

Simulator *S* (Corrupted Bob)

Let be the length of the messages and be the security parameter. The simulator *S* interacts with an environment *Z*, functionality *F*SFOTand an internal copy *A* of the adversary that corrupts only Bob, proceeding as follows:

1. *S* forwards all messages between *A* and global random oracles *F*gRO1, *F*gRO2 and *F*gRO3. Moreover, it keeps up-to-date lists of adversarial and illegitimate queries (and associated answers) for each global random oracle.
2.Upon receiving (sid*;s;* pk₀) from *A*, *S* follows the instructions of an honest Alice in Step 2 ofSFOTto generate and send (sid*;*ch*;*ct₀*;*ct₁) to *A*:
(a) *S* sends (sid*;s*) to *F*gRO1, receiving *q* as answer. *S* computes pk₁ such that pk₀*?* pk₁ = *q*.
$ $

(b)For *i 2 f*0*;* 1*g*, *S* samples p*i f* 0*;* 1*g*, r*i; R*, computes ct*i* Enc(pk*i;* p*i*; r*i*), and queries *F*gRO3 with (sid*;*pk*i;* p*i;* r*i*) to obtain p
*0i*, and with (sid*;* p *0i* ) to obtain p⁰⁰*i*.

(c) *S* computes ch p⁰⁰0p⁰⁰1and sends (sid*;*ch*;*ct₀*;*ct₁) to *A*.
3.Whenever the rst query (sid*;*pk*c;* p*c;* r*c*) from *A* to *F*gRO2 or *F*gRO3 where *c 2 f*0*;* 1*g* happens, *S* sends (choose*;*sid*;c*) to *F*SFOT. Upon receiving (output*;*sid*;* m*c*) from *F*SFOT, *S* stores m*c*.
4.Upon receiving (sid*;*chr) from *A*, *S* checks that chr = p⁰⁰0, aborting otherwise (as an honest Alice would). If no query of the form (sid*;*pk*c;* p*c;* r*c*) has been recorded in the lists of *F*gRO3 or *F*gRO2, *S* outputs fail and halts. Otherwise,
$ *S* samples m₁ *c f* 0*;* 1*g* and executes Step 4 of ProtocolSFOTas an honest Alice to generate and send (sid*;* mf0*;* mf1*;*p⁰0*;*p⁰1) to *A*:

(a)For *i 2f*0*;* 1*g*, *S* queries *F*gRO2 with (sid*;*pk*i;* p*i;* r*i*) obtaining pe*i* and com- putes mf*i* = pe*i* m*i*.
(b) *S* sends (sid*;* mf0*;* mf1*;*p⁰0*;*p⁰1) to *A*.
<u>5.When A halts, S also halts and outputs whatever A outputs.</u>
Fig. 6. Simulator *S* for the case where only Bob is corrupted.

*Simulator for the case only* Bob *is corrupted.* In the case where only Bob is corrupted, the simulator *S* interacts with *F*SFOTand an internal copy *A* of the real world adversary (*S* acts as Alice in this internal simulated execution of the protocol). Additionally, *S* also receives queries from *A* to the instances of *F*gRO(*i.e. F*gRO1, *F*gRO2and *F*gRO3), which it forwards. When the query is answered, *S* forwards the answer to *A*. The goal of the simulator is to extract the corrupted receiver’s choice bit *c* in order to request the correct message from *F*SFOT, which is later transferred to the adversary. The simulator *S* is presented in Figure 6. Notice that, unless *S* outputs fail, it executes all the steps of an honest Alice in the real protocol with the sole dierence that it uses a random $ message m₁*c f* 0*;* 1*g* instead of the real message. We will show that *S* only outputs fail with negligible probability and that simulation with a uniformly random m₁*c*is indistinguishable from a real execution.

First, notice that *S* only outputs fail if it receives a message (sid*;*chr) from *A* such that chr = p⁰⁰0without a query (sid*;*pk*c;* p*c;* r*c*), where *c 2f*0*;* 1*g*, being made to *F*gRO3or *F*gRO2beforehand, meaning that *S* cannot extract the choice bit *c*. We remark that, in this argument, *c* is dened as the bit corresponding to the p*i*value contained in the rst such query and may not correspond to the actual choice bit. At this stage we are only interested in showing that *A* must issue a query (sid*;*pk*i;* p*i;* r*i*) to *F*gRO3in order to obtain the correct chr, resulting in *S* proceeding without outputting fail. Later on, we will show that the extracted bit *c* is indeed *A*’s choice bit, or rather that *A* cannot obtain m₁*c*without violating one of the properties of PKE.

Notice that ch = p⁰⁰

||p⁰⁰ (where p⁰⁰|and p⁰⁰|are outputs of a random oracle)|
|---|---|---|---|
||0 1|0|1|
|||0||
|0|0||gRO3|
|1||0|1|

and that the adversary *A* only receives ch*;*ct₀*;*ct₁ up to the challenge phase of the protocol. Hence, in order to obtain p⁰⁰ and pass the challenge-response test with non-negligible probability, *A* needs to: either (1) query *F*gRO3on (sid*;*pk₀*;*p₀*;*r₀) to obtain p⁰ and then p⁰⁰; or (2) query *F* on (sid*;*pk₁*;*p₁*;*r₁) to obtain p⁰1 followed by p⁰⁰ and then compute p⁰⁰ ch p⁰⁰.

Given that *S* does not output fail, it extracts a choice bit *c* and obtains the message m*c*from *F*SFOT. The only dierence between the simulation and a real execution is that *S* computes (sid*;* mf0*;* mf1*;*p⁰0*;*p⁰1) using a random mes- sage m₁*c f* 0*;* 1*g* instead of the real message. Notice that m₁*c*is \one- time pad encrypted" in m]1 *c*= pg1 *c*m₁*c*. Hence, *A* can only learn any information about m₁*c* gRO2

|||with non-negligible probability if it queries F|||with|
|---|---|---|---|---|---|
|||c|||gRO2|
|c c|c|1 c|||c|
|||||c||

(pk₁*;*p₁*;*r₁) to obtain pg. We will show that even though m₁ is chosen uniformly at random, the simulation is indistinguishable from the real execution because *A* cannot learn anything about m₁ without breaking some property of PKE. The main idea is to show that we can build an adversary *A₁* that breaks Property 1 with probability *p* given black-box access to a pair of *A* and *Z* such that *Z* distinguishes the ideal execution with *F*SFOTand *S* from a real exe- cution with *A* andSFOTwith probability *p*, *i.e.* where *A* queries *F*gRO3with

|||gRO3|
|---|---|---|
|c c c|c c|c|

(pk*;* p*;* r) and later manages to query *F*gRO2with (pk₁*;*p₁*;*r₁) also with probability *p*.

Reduction from a pair (*Z; A*) for which simulation fails to *A₁* that breaks Property 1: Given a pair of *A* and *Z* such that *Z* distinguishes the ideal execution with *F*SFOTand *S* from a real execution with *A* andSFOT with probability *p*, we construct an adversary *A₁* that breaks Property 2 with probability at least *p*. *A₁* interacts with the challenger in the game of Property 1 and with *copies* of *A* and *Z*, for which it simulates *S*, *F*gRO1, *F*gRO2and *F*gRO3. *A₁* rst receives *q* from the challenger in the game of Property 1, then randomly picks a query (sid*;s*) from the set of *A*’s queries to *F*gRO1and answers it with (sid*;q*), where *q* was received from the challenger of the security game. We remark that the no programming is done by *S* in the simulation ofSFOT. Notice that *A₁* programs the random oracle emulated inside this reduction where *copies* of *Z* and *A* are used in a black-box way to break Property 1. In this reduction, *A₁* (but *not S*) uses copies of both *Z* and *A* and emulates all the ideal functionalities and parties towards these copies. *A₁* does not interact with the actual environment *Z* nor with the actual ideal functionalities in the simulation. It also does not interfere with the ideal functionalities simulated by *S* towards its internal copy of *A*. The steps of *A₁* only aect its own copies of *Z; A* inside this reduction and and *S* only *observes* queries to *F*gRO1in its simulation. While this approach may seem counter-intuitive, similar techniques are used by Dodis *et al.* [20] and shown to be compatible with the Global UC framework.

*A₁* waits for pk₀*;s⁰* from *A* and, if *s 6*= *s⁰*, rewinds *A* to the the previous step, randomly picks a dierent query (sid*;s*) from the set of *A*’s queries to *F*gRO1and answers it with (sid*;q*), repeating the same procedure after receiving a new pk₀*;s⁰* from *A*. Notice that *A₁* (but *not S*) rewinds *copies* of both the environment *Z* and the adversary *A* only as a step of this reduction where these copies are used in a black-box way to break Property 1. *A₁* does not interact with the actual environment *Z* or *S*’s copy of *A* but only with its own copies of *A* and *Z* towards which it emulates all the ideal functionalities and parties. The steps of *A₁* only aect its own copies of *Z; A* inside this reduction and no rewinding is done by *S* in the simulation ofSFOT. While this approach may seem counter-intuitive, similar techniques are used by Dodis *et al.* [20] and shown to be compatible with the Global UC framework.

If *s* = *s⁰*, *A₁* computes pk₁ and sends pk₀*;*pk₁ to the challenger as public keys pk₀*;*pk₁ of the game. Upon receiving ciphertexts ct₀*;*ct₁ from the challenger in $*0 0* the game of Property 1, *A₁* samples ch *f* 0*;* 1*g* and sends (sid*;*ch*;*ct₀*;*ct₁)

|to A. Upon receiving a query (sid; pk||||; p|; r ) to F|or F|such that|
|---|---|---|---|---|---|---|---|
|||||i|i;j i;j|gRO2||
|i||i i;j i;j|gRO3|i;j 0i;j|i;j||i gRO2|
|i;j|||||0i;j|gRO3|00 i|
||0;j|0;j 1;j|1;j|00 i;j|i;j||00 i;j gRO3|
|gRO2||i|i;j i;j||i;j|||

gRO3 ct = Enc(pk*;* p; r), *A₁* adds (p*;* r) to an initially empty list *L* and $ answers the query to *F* as p *f* 0*;* 1*g* and the query to *F* as $ pg *f* 0*;* 1*g*. Upon receiving a query (sid*;* p) from *A* to *F*, if p₁ is $ not dened, *A₁* answers with p *f* 0*;* 1*g*. Otherwise, it answers with p₁ such that ch = p⁰⁰ p⁰⁰. Upon receiving (sid*;*chr) from *A*, *A₁* checks that chr = p⁰⁰ or ch p⁰⁰ (for one of the values p⁰⁰ given as answer from *F*), $ failing otherwise. *A₁* samples m₀*;*m₁ *f* 0*;* 1*g* and, for *i 2 f*0*;* 1*g*, queries *F* with (sid*;*pk*;* p*;* r) obtaining pg (simulating this answer accoding

||f g m = p|m. A₁|
|---|---|---|
|0 1 0;j|i i;j|i|

to the procedure described before) and computes sends (sid*;* mf*;* mf*;*p⁰*;*p⁰1*;j*) to *A*. Finally, when *A* terminates, *A₁* chooses a random p₀ *2 L₀* and p₁ *2 L₁* and sends (p₀*;*p₁) to the challenger in the game of Prop- erty 1. Notice that the queries to *F*gRO3will appear consistent with (sid*;*ch*;*ct⁰0*;*ct⁰1). Moreover, notice that, for each *i 2f*0*;* 1*g*, an adversary *A* that obtains any infor- mation about m*i*with probability *p* must rst recover (pk*i;* p*i;* r*i*) from ct*i*also with probability *p*. Due to Property 4, for any arbitrary public key pk*i*, *A* can only both obtain (p*i;* r*i*) from ct*i*such that ct*i*Enc(pk*i;* p*i;* r*i*) and generate *n* 1 alternative message and randomness pairs (p*i;*1 *i;*1 *i;n* 1 *i;n* 1

|||||; r );:::; (p||; r )|
|---|---|---|---|---|---|---|
|||||i;1 i;1|i;n|1 i;n 1|
|i i||i|i i;j||||
|n 1||||||i|
|i 1 n|||i i gRO3|c c|c|i|
|gRO2||c c|c||n1 n1||

dierent from (p*;* r) such that ct Enc(pk*;* p*;* r*i;j*) for *j* = 1*;:::;n* 1 with probability + negl(). Notice that an adversary that can generate *n* 1 such alternative message and randomness pairs for a ciphertext generated un- der public key pk can only recover pair p*;* r necessary for obtaining m with probability. Hence, an *A* who is able to generate *n₀* 1 (resp. *n₁* 1) such al- ternative message and randomness pairs for a ciphertext generated under public key pk₀ (resp. pk₁) can only both query *F* with (pk*;* p*;* r) and later man- age to query *F* with (pk₁*;*p₁*;*r₁) with probability 0 1 + negl(). Without loss of generality, we assume that *n* = *n₀* = *n₁*. Notice that for an *A* that does this, *L₀* and *L₁* must contain (p₀*;*r₀) and (p₁*;*r₁) such that p₀*;*p₁ win the game against the challenger of Property 1, since it must extract the exact pairs (p₀*;*r₀) and (p₁*;*r₁) used in generating ct₀ and ct₁. Since *A₁* samples a random pair (p*i;* r*i*) from the list *Li*of all pairs (p*i;j;* r*i;j*) that result in ct*i*under pk*i*, if *Li*has *n* elements, it selects both the correct value p₀ and value p₁ with probability *n* <u>1</u>

2. However, if *A* is also able to generate *n* 1 alternative pairs

|(p; r ) that result in ct||under pk|, it is also only able to recover (p|||; r ) from|
|---|---|---|---|---|---|---|
|i;j i;j||i|i|||i i|
|i||n 1|||||
|||n1|||||
|SFOT|||||SFOT||

*i;j i;j i i i i* ct with probability and, consequently, only able to recover both (p₀*;*r₀) and (p₁*;*r₁) with probability2. Hence, *A₁* wins the game of Property 1 with the same probability that *Z* in the pair of *A* and *Z* distinguishes the ideal execution with *F* and *S* from a real execution with *A* and. Notice that *A₁* needs to rewind its own *copies* of the environment *Z* and the adversary *A* and program the random oracle it simulates towards these copies only as a step of the reduction where *Z; A* are used to break Property 1. *A₁* does not interact with the actual environment *Z* nor with the actual (or simulated) ideal functionalities in the simulation. The steps of *A₁* only aect its own copies of *Z; A* inside that specic reduction and no programming or rewinding is done by the simulator *S* in the simulation ofSFOT. While this approach may seem counter-intuitive, similar techniques are used and shown to be compatible with the Global UC framework by Dodis *et al.* [20].

*Simulator for the case only* Alice *is corrupted.* In the case where only Alice is corrupted, the simulator *S* interacts with *F*SFOTand an internal copy *A* of the real world adversary (*S* acts as Bob in this internal simulated execution of the protocol). Additionally, *S* also receives queries from *A* to the instances of *F*gRO (*i.e. F*gRO1, *F*gRO2and *F*gRO3), which it forwards. When the query is answered, *S* forwards the answer to *A*. The goal of the simulator is to extract the messages

Simulator *S* (Corrupted Alice)

Let be the length of messages and be a security parameter. Simulator *S* interacts with an environment *Z*, functionality *F*SFOTand an internal copy *A* of the adversary that corrupts only Alice, proceeding as follows:

1. *S* forwards all messages between *A* and global random oracles *F*gRO1, *F*gRO2 and *F*gRO3. Moreover, it keeps up-to-date lists of adversarial and illegitimate queries (and associated answers) for each global random oracle.
$

2. *S* samples *c f* 0*;* 1*g* and follows the instructions of an honest Bob in Step 1 of
$ ProtocolSFOTto generate (sid*;s;* pk₀): *S* generates a pair of keys (pk*c;*sk*c*) $ KG(1), samples *s f* 0*;* 1*g*, sends (sid*;s*) to *F*gRO1, obtaining *q* as answer. Bob computes pk₁*c*such that pk₀*?* pk₁ = *q* and sends (sid*;s;* pk₀) to *A*.

3.Upon receiving (sid*;*ch*;*ct₀*;*ct₁) from *A*, *S* checks whether the challenge ch is valid or if *A* is trying to guess the choice bit by proceeding as follows:
(a)For *i 2 f*0*;* 1*g*, *S* checks if there exist queries (sid*;*pk*i;* p*i;* r*i*) to *F*gRO3 such that ct*i* = Enc(pk*i;* p*i*; r*i*). If these checks fail for both *i 2f*0*;* 1*g*, *S* sends (guess*;*sid*;*force) to *F*SFOT(as an honest Bob would abort with over- whelming probability when checking the values ch*;*p⁰0*;*p⁰1). If these checks succeed for both *i 2 f*0*;* 1*g* and ch is computed correctly from p₀*;*p₁, *S* sends (guess*;*sid*; ?*) to *F*SFOTand goes to 3(c).
(b)If there exists only one query (sid*;*pk*c0;* p*c0;* r*c0*) to *F*gRO3 such that ct*c0*= Enc(pk*c0;* p*c0*; r*c0*) or ch is invalid with respect to p₀*;*p₁ and *F*gRO3, *S* checks that there exists a query (sid*;* p
*0c0* ) to *F*gRO3 with output p⁰⁰*c0*such that p *0c0* was obtained as the output of a query (sid*;*pk*c0;* p*c0;* r*c0*) to *F*gRO3 and that p⁰⁰ *c0*satises p⁰⁰*c0*ch = *G⁰*, for *G⁰ 2 f*0*;* 1*g* obtained as the output of a query (sid*;G*) to *F*gRO3. If such a query exists, *S* sends (guess*;*sid*;c⁰*) to *F*SFOT. Otherwise, *S* sends (guess*;*sid*;*force).

(c)If (guess*;*sid*; ?*) was sent to *F*SFOT, *S* computes chr according to p₀ and *F*gRO3, sends (sid*;*chr) to *A* and goes to Step 4. Otherwise, *S* sets *c* = *c⁰* (resp. *c* = *c*~) if *F*SFOTanswers with (cheat undectected*;*sid) (resp. (cheat dectected*;*sid*; c*~)). *S* computes chr according to ch*;* p*c;c* and *F*gRO3, and sends (sid*;*chr) to *A*.
4.Upon receiving (sid*;* mf0*;* mf1*;*p⁰0*;*p⁰1) from *A*, if (guess*;*sid*; ?*) was sent to *F*SFOT or if *F*SFOTanswered (guess*;*sid*;c*) with (cheat undectected*;*sid), *S* runs the procedure of an honest Bob to check if p⁰0*;*p⁰1are valid according to ch*;* p*c;c* (set as in step 3(c)) and *F*gRO3. If this check fails, *S* aborts as an honest Bob would. If *F*SFOTanswered (guess*;*sid*;c*) with (cheat dectected*;*sid*; c*~), *S* allows the deliver of this message to Bob at this point. In the other cases, *S* sends (sid*;*pk*c;* p*c;* r*c*) to *F*gRO2 obtaining pe*c* as response and computing m*c* = pe*c* mf*c*. If (guess*;*sid*; ?*) was sent to *F*SFOT, *S* sends (sid*;*pk₁*c;*p₁ *c;*r₁ *c*) to *F*gRO2 obtaining pg 1 *c* as response and computing m₁ *c* = pg 1 *c* m] 1 *c*; otherwise *S*
$ sets m₁ *c f* 0*;* 1*g*. Finally, *S* sends (send*;*sid*;*m₀*;*m₁) to *F*SFOT.

<u>5.When A halts, S also halts and outputs whatever A outputs.</u>
Fig. 7. Simulator *S* for the case where only Alice is corrupted.

of the corrupted sender that it needs to deliver to *F*SFOT. Moreover, the simulator must extract the choice bit \guess" that the adversary might make and forward it to *F*SFOT. Again, we will adopt an strategy where the simulator executes all the steps of an honest Bob exactly as in the real protocol but using a random choice bit, as well as observing the queries to *F*gRO1, *F*gRO2and *F*gRO3. The rst dierence between the simulation performed by *S* and a real exe- $ cution ofSFOTis that *S* uses a random choice bit *c f* 0*;* 1*g* instead of the real one. This aects the messages sent in Step 2 and Step 3 of the simulation but we will show that the simulation with a random choice bit is indistinguishable from the real execution. In Step 2, pk₀ and pk₁ are computed exactly as inSFOTbut a random pk*c*is the valid public key. Nevertheless, the message (sid*;s;* pk₀) (and the pk₁ it denes) are indistinguishable from those generated in a real execution because a valid pk*c*is indistinguishable from an invalid pk₁*c*by Property 2. In the case of Step 3, we will show that we can extract *A*’s guessed choice bit (if it attempts a guess), provide it to *F*SFOTand generate a response chr consistent with a real execution. In Step 3(a), *S* extracts the pairs (p*i;* r*i*) used to generate each ct*i*from the list of queries (sid*;*pk*i;* p*i;* r*i*) to *F*gRO3using the fact that there must be exactly one pair (p*i;* r*i*) such that ct*i*= Enc(pk*i;* p*i*; r*i*), which is guaranteed by Property 3. Moreover, we leverage Property 5, which guarantees that an honest Bob would obtain the same (p*i;* r*i*) from ct*i*for *i* =

*c*. First, if for both ct*i*there is no query (sid*;*pk*i;* p*i;* r*i*) to *F*gRO3such that ct*i*= Enc(pk*i;* p*i*; r*i*), then *S* sends (guess*;*sid*;*force) to *F*SFOT, as an honest Bob would abort with overwhelming probability regardless of its choice bit *c* when he checks the consistency of the values p⁰0and p⁰1sent by *A* with p
*0c* that he computed locally and ch. Next, it checks that ch is consistent with (pk*i;* p*i;* r*i*) used to generate ct*i*, which means that *A* is not trying to guess the choice bit as a correctly computed ch consistent with ct₀*;*ct₁ has an answer chr that reveals no information about *c*. If everything is right, *S* sends (guess*;*sid*; ?*) to *F*SFOT. In case ch is not consistent with pk*i;* p*i;* r*i*or for one ct*i*there is no query (sid*;*pk*i;* p*i;* r*i*) to *F*gRO3such that ct*i*= Enc(pk*i;* p*i*; r*i*), *A* might be mounting a selective failure attack and *S* must extract the choice bit that *S* might be trying to guess. *A* can guess that an honest Bob’s choice bit is *i* by providing

|ct with a consistent a challenge ch generated from (pk||; p; r ) and a random|||
|---|---|---|---|---|
|i||i i i|||
|1 i|||1 i||
||i 1 i||i|1 i|
||i||||

p⁰ for which there is no query (sid*;*p₁*i*) to *F*gRO3with output p⁰. In this scenario, if an honest Bob has choice bit *i*, it will be able to validate ct and ch with respect to p*;*p⁰, since it does not see any inconsistency between p⁰ and the contents of ct₁ (which he cannot recover). However, if an honest bob has choice bit 1 *i*, he will be able to detect the inconsistency. Since *S* does not know the actual choice bit *c*, it tests ch*;*ct₀*;*ct₁ with respect to the p₀*;*r₀*;*p₁*;*r₁ extracted (or not) from the list of queries to *F*gRO3in order to check that *A* is trying to guess the choice bit is *i* using the strategy previously described. In case *S* detects that *A* is trying to guess that the choice bit is *i*, it sends (guess*;*sid*;i*) to *F*. On the other hand, if ch could not be generated by querying *F*

|SFOT||gRO3|
|---|---|---|
|i|1 i||
|||SFOT|

with p and a random p⁰, an honest Bob would detect that *A* is cheating with all but negligible probability. Hence, *S* sends (guess*;*sid*;*force) to *F*. In any

case, *S* uses the answer from *F*SFOTto set *c* and generate chr as an honest Bob would. In Step 4, *S* checks the validity of ch as an honest Bob would. Namely, if *S* has not detected that *A* tried to guess the choice bit or if *F*SFOTan- swered with (cheat undetected*;*sid), *S* performs these checks as an honest Bob would using p⁰0*;*p⁰1*;* p*c;c* (with *c* set in step 3(c)). If *F*SFOTanswered with (cheat detected*;*sid), *S* aborts as an honest Bob would upon detecting a cheat- ing Alice. Hence *S* validates ch as an honest Bob would with all but negligible probability. It remains to show that *S* can extract the necessary messages in case the checks with ch succeed. If that happens, either (1) the message (guess*;*sid*; ?*) was sent to *F*SFOTand *S* needs to extract both m₀ and m₁; or (2) the message (guess*;*sid*;c*) was sent to *F*SFOTwith the correct guess and *S* needs to extract m*c*. In the rst case, both (p₀*;*r₀) and (p₁*;*r₁) were already extracted from the list of queries to *F*gRO3. Similarly, in the second case the values (p*c;* r*c*) were extracted. Property 3 guarantees that there is a single pair (p*i;* r*i*) such that ct*i*= Enc(pk*i;* p*i*; r*i*) and Property 5 guarantees that this same pair would be recovered by an honest Bob with choice bit *i*. Hence, the simulator can use these values to query *F*gRO2, obtain the necessary one-time pads and extract the correct messages to send to *F*SFOT.

## C Security Analysis of ProtocolOT

In this appendix we analyse the security of ProtocolOTand present a full proof of Theorem 2, re-stated below.

Theorem 2 *Let* PKE *be a public-key encryption scheme that satises Proper-* *ties 1, 2, 3, 4 and 5. When instantiated with* PKE*, ProtocolOTUC-realizes* *the functionality F*OT *;*1 *against static malicious adversaries in the global random* *oracle model.*

*Proof.* In order to prove the security ofOT, we will construct a simulator *S* such that no environment *Z* can distinguish between interactions with an adversary *A* throughOTin the real world and with *S* and *F*OT *;*1 in the ideal world. For the sake of clarity, we will describe the simulator *S* separately for dierent corruption scenarios. In all cases, *S* writes all the messages received from *Z* in *A*’s input tape, simulating *A*’s environment. Also, *S* writes all messages from *A*’s output tape to its own output tape, forwarding them to *Z*. Notice that simulating the cases where both Bob and Alice are corrupted or honest is trivial. If both parties are corrupted, *S* simply runs *A* internally. In this case, *A* generates the messages from both corrupted parties. If neither Alice nor Bob are corrupted, *S* runs the protocol between honest Alice and Bob internally on the inputs provided by *Z* and all messages are delivered to *A*. We analyze the cases where only Bob is corrupted and where only Alice is corrupted below.

Simulator *S* (Corrupted Bob)

Let be the length of the messages and be the security parameter. The simulator *S* interacts with an environment *Z*, functionality *F*OT *;*1 and an internal copy *A* of the adversary that corrupts only Bob, proceeding as follows:

1. *S* forwards all messages between *A* and global random oracles *F*gRO1, *F*gRO2, *F*gRO3 and *F*gRO4. Moreover, it keeps up-to-date lists of adversarial and illegit- imate queries (and associated answers) for each global random oracle.
2.Upon receiving (sid*;s;* pk₀) from *A*, *S* follows the instructions of an honest Alice in Step 2 of ProtocolOTto generate and send (sid*;*ch*;*ct₀*;*ct₁*;*ct^0*;*ct^1) to *A*. Notice that an honest Alice’s inputs are not used in this step of ProtocolOT, so *S*’s message to *A* is distributed exactly as in a real execution of ProtocolOT.
3.Whenever the rst query (sid*;*pk*c0;* p*c0;* r*c0*) from *A* to *F*gRO2 or *F*gRO3 where *c⁰ 2f*0*;* 1*g* happens, *S* stores *c⁰* (*i.e.* the random choice bit used by *A*, which will be used in Step 5 to determine the actual choice bit *c*).
4.Upon receiving (sid*;*chr) from *A*, *S* checks that chr = p⁰⁰0, aborting otherwise (as an honest Alice would). If no query of the form (sid*;*pk*c;* p*c;* r*c*) has been recorded in the lists of *F*gRO3 or *F*gRO2, *S* outputs fail and halts. Otherwise, *S* executes Step 4 of ProtocolOTas an honest Alice to generate and send (sid*;* mf0*;* mf1*;*p₀*;*p₁*;*r₀*;*r₁) to *A*. Once again, notice that an honest Alice’s inputs are not used in this step of ProtocolOT, so that *S*’s message to *A* is distributed exactly as in a real execution of ProtocolOT.
5.Upon receiving (sid*;d*) from *A*, *S* sends (choose*;*sid*;d c⁰*) to *F*OT
*;*1 (*i.e.* using choice bit *c* = *d c⁰* where the random choice bit *c⁰* has been extracted in Step

3). Upon receiving (output*;*sid*;* m*c*) from *F*OT
*;*1, *S* samples a random message $ m₁ *c f* 0*;* 1*g* and uses m*c;*m₁ *c* as Alice’s inputs to execute Step 6 of Pro- tocolOTas an honest Alice, generating and sending (sid*;*m⁰0*;*m⁰1) to *A*. Notice that the only deviation from ProtocolOTis that m₁ *c* is sampled at random.

<u>6.When A halts, S also halts and outputs whatever A outputs.</u>
Fig. 8. Simulator *S* for the case where only Bob is corrupted.

*Simulator for the case only* Bob *is corrupted.* In the case where only Bob is corrupted, the simulator *S* interacts with *F*OT *;*1 and an internal copy *A* of the real world adversary (*S* acts as Alice in this internal simulated execution of the protocol). Additionally, *S* also receives queries from *A* to the instances of *F*gRO (*i.e. F*gRO1, *F*gRO2, *F*gRO3and *F*gRO4), which it forwards. When the query is answered, *S* forwards the answer to *A*. The goal of the simulator is to extract the corrupted receiver’s choice bit *c* in order to request the correct message from *F*OT *;*1, which is later transferred to the adversary. The simulator *S* is presented in

Figure 8. Notice that, unless *S* outputs fail, it executes all the steps of an honest

Alice in the real protocol with the sole dierence that it uses a random message

$ m₁*c f* 0*;* 1*g* instead of the real message. We will show that *S* only outputs fail with negligible probability and that simulation with a uniformly random m₁*c*is indistinguishable from a real execution. The fact that *S* only outputs fail with negligible probability has been estab- lished in the proof of Theorem 1. First, notice that *S*’s challenge consisting of ch*;*ct₀*;*ct₁ is generated exactly as in ProtocolSFOT. In the proof of Theorem 1 it is shown that *A* can only provide a valid response (sid*;*chr) to this challenge if it rst queries *F*gRO2or *F*gRO3with (sid*;*pk*c0;* p*c0;* r*c0*), except with negligible prob- ability. Moreover, it is shown that, if *A*’s rst such query to *F*gRO2or *F*gRO3is (sid*;*pk*c0;* p*c0;* r*c0*), then it can only decrypt ciphertext ct*c0* (*i.e.* it only has secret key sk*c0*) but not ciphertext ct₁*c0*. In order to show that our simulation with a uniformly random m₁*c*is indis- tinguishable from a real execution, we rst argue that *A* cannot decrypt ct^1 *c0*. Notice that ct^1 *c0* (resp. ct^*c0*) is generated under public key pk₁*c0* (resp. pk*c0*), which is the same public key used to generate ct₁*c0* (resp. ct*c0*). Hence, we can repeat the argument from the proof of Theorem 1 to show that *A* cannot de- crypt ct^1 *c0* (and can only decrypt ct^*c0*) if it has rst queried *F*gRO2or *F*gRO3 with (sid*;*pk*c0;* p*c0;* r*c0*). Since *A* cannot decrypt ct^1 *c0*, it cannot recover p]1 *c0*, which it needs in order to compute m^1 *c0* m^1 *c0* p]1 *c0* and subsequently m₁*c*= m⁰1 *c*m^1 *c0*. Hence m⁰1 *c*appears uniformly distributed towards *A* regardless of m₁*c*, which *S* samples uniformly at random (as opposed to us- ing Alice’s actual input as in ProtocolOT). On the other hand, *S* recovers the correct message m*c*from *F*OT *;*1 using *A*’s message (d*;*sid*;*) and *c⁰*, resulting in *A* obtaining the same message m*c*as it would in the real protocol execution.

*Simulator for the case only* Alice *is corrupted.* In the case where only Alice is corrupted, the simulator *S* interacts with *F*OT *;*1 and an internal copy *A* of the real world adversary (*S* acts as Bob in this internal simulated execution of the protocol). Additionally, *S* also receives queries from *A* to the instances of *F*gRO (*i.e. F*gRO1, *F*gRO2, *F*gRO3and *F*gRO4), which it forwards. When the query is answered, *S* forwards the answer to *A*. The goal of the simulator is to extract the messages of the corrupted sender that it needs to deliver to *F*OT *;*1. Again, we will adopt an strategy where the simulator executes all the steps of an honest Bob exactly as in the real protocol but using a random choice bit, as well as observing the queries to *F*gRO1, *F*gRO2, *F*gRO3and *F*gRO4. We argue that such a simulation with a random choice bit is indistinguishable from a real execution, since the (random) choice bit does not leak and both of *A*’s messages can be extracted if *S* does not abort, which it only does if an honest Bob would abort. First, as in ProtocolSFOT, we remark that message (sid*;s;* pk₀) does not leak information about the random choice bit *c⁰* used in the rst step of Pro- tocolOTdue to Property 2. The only way *A* can learn *c⁰* is by mounting a selective failure attack where it generates the challenge consisting of ch*;*ct₀*;*ct₁ maliciously in such a way that it can guess *c⁰* and conrm its guess by observing *S*’s response chr to the challenge. Notice that this is the selective failure attack to which ProtocolSFOTis vulnerable. However, in ProtocolOT, *A* must re- veal the messages and randomness p₀*;*p₁*;*r₀*;*r₁ used to generate the challenge

Simulator *S* (Corrupted Alice)

Let be the length of the messages and be the security parameter. The simulator *S* interacts with an environment *Z*, functionality *F*OT *;*1 and an internal copy *A* of the adversary that corrupts only Alice, proceeding as follows:

1. *S* forwards all messages between *A* and global random oracles *F*gRO1, *F*gRO2, *F*gRO3 and *F*gRO4. Moreover, it keeps up-to-date lists of adversarial and illegit- imate queries (and associated answers) for each global random oracle.
2. *S* follows the instructions of an honest Bob in Step 1 of ProtocolOTto compute (sid*;s;* pk₀) and send it to *A*. Notice that the choice bit of an honest Bob is not used at this step of ProtocolOT, so *S*’s message is distributed exactly as in the real execution.
3.Upon receiving (sid*;*ch*;*ct₀*;*ct₁*;*ct^0*;*ct^1) from *A*, *S* follows the instructions of an honest Bob in Step 3 of ProtocolOTto compute (sid*;*chr) and send it to Alice. Notice that the choice bit of an honest Bob is not used at this step of ProtocolOT, so *S*’s message is distributed exactly as in the real execution.
4.Upon receiving (sid*;* mf0*;* mf1*;*p₀*;*p₁*;*r₀*;*r₁) from *A*, *S* samples a random choice $ bit *c f* 0*;* 1*g* and follows the steps of an honest Bob in Step 5 of ProtocolOT to compute (sid*;d*) and send it to Alice (aborting if an honest Bob would have aborted).
5.Upon receiving (sid*;*m⁰0*;*m⁰1) from *A*, *S* proceeds as follows:
(a)For *i 2f*0*;* 1*g*, check that there exists a query (sid*;*pk*i;* p^*i*) to *F*gRO4 with answer ^r*i* such that ct^*i* Enc(pk*i;* p^*i*; ^r*i*) (checking that ciphertexts ct^*i* were correctly generated from values p^*i* using randomness ^r*i* obtained by querying *F*gRO4 with p^*i*).
$

(b)If the previous check fails for *i 2 f*0*;* 1*g*, set pe*i f* 0*;* 1*g* (since in this case an honest Bob with choice bit *c* = *i* would output a random mes- sage). For *i 2f*0*;* 1*g*, if the check succeed obtaining values p^*i;*^r*i*, send query (sid*;*pk*i;* p^*i;*^r*i*) to *F*gRO2 obtaining answer pe*i*.
(c)For *i 2f*0*;* 1*g*, compute m^*i* = pe*i* mf*i* and m*i* = m
*0i* m^*i* as an honet Bob would.

(d)Send (send*;*sid*;*m₀*;*m₁) to *F*OT
*;*1.

<u>6.When A halts, S also halts and outputs whatever A outputs.</u>
Fig. 9. Simulator *S* for the case where only Alice is corrupted.

ch*;*ct₀*;*ct₁ so that *S* (following the steps of an honest Bob) can check that the challenge was constructed correctly and that consequently its response chr does not leak any information about *c⁰*. Due to Property 3, *A* cannot generate alter- native messages and randomness (p⁰0*;*p⁰1*;*r₀ *0* *;*r₁ *0*

) *6*= (p₀*;*p₁*;*r₀*;*r₁) that result in the
same challenge ch*;*ct₀*;*ct₁ such that (p⁰0*;*p⁰1*;*r₀ *0* *;*r₁ *0* ) passes the check performed by *S* (*i.e.* the check of an honest Bob) but in fact (p₀*;*p₁*;*r₀*;*r₁) is maliciously con-

structed and used to generate ch*;*ct₀*;*ct₁ in such a way that chr reveals *c⁰*. Hence, if *S* does not abort in Step 4 (due to the check on p₀*;*p₁*;*r₀*;*r₁*;*ch*;*ct₀*;*ct₁ failing), *A* can only learn anything about *c⁰* if it breaks Property 2 and Property 3. In Step 4, *S* only aborts if an honest Bob would have aborted due to the check on p₀*;*p₁*;*r₀*;*r₁*;*ch*;*ct₀*;*ct₁ failing, so that the abort would be indistinguishable of an execution of ProtocolOTwith an honest Bob. If this check succeeds and *S* does not abort, we have established that *A* would not have learnt anything *0 0*$ about *c*. Hence, the message (sid*;d*) where *d* = *c c* and *c f* 0*;* 1*g* sent to *A* by *S* is indistinguishable from the message sent by an honest Bob, since *A* does not know *c⁰* (which acts as a one-time pad key in *d*) and consequently cannot distinguish *d* generated from a random *c* (as done by *S*) from the *d* generated by an honest Bob. Finally, having established that a simulation with a random *c* is indistin- guishable from an real execution with an honest Bob, we show that *S* correctly extracts *A*’s messages m₀*;*m₁. Notice that both pairs of ciphertexts ct₀*;*ct₁ and ct ^0*;*ct^1are generated with the same pair of public keys pk₀*;*pk₁. Due to the underlying PKE being committing (Property 3), for *i 2 f*0*;* 1*g*, there exists a unique triple (pk*i;* p^*i;*^r*i*) such that ct^*i*Enc(pk*i;* p^*i*; ^r*i*) unless *A* breaks Prop- erty 3, which only happens with negligible probability. Hence, if there is a query (sid*;*pk*i;* p^*i*) to *F*gRO4with answer ^r*i*such that ct^*i*Enc(pk*i;* p^*i*; ^r*i*), there is a unique value pe*i*that an honest Bob with *c⁰* = *i* obtains by successfully decrypting

|^ ct and querying F||^; p; ^r|). In this case, S obtains exactly the||||
|---|---|---|---|---|---|---|
|i i i|gRO2 i i c c 0i|i i c c|i||i i|i i i i i ;1|
|i|i|||||OT|

*i* gRO2with (sid*;*pk*i i i* same pe that an honest Bob with *c⁰* = *i* would obtain. On the other hand, if there is no query (sid*;*pk*;* p^) to *F*gRO4with answer ^r such that ct^ Enc(pk*;* p^; ^r), decryption would fail and an honest Bob with *c⁰* = *i* would obtain*?* when computing (p^ *0;*^r *0*) Dec(sk *0;*ct^ *0*). In this case, *S* obtains a random value pe, which is distributed exactly as the value an honest Bob with *c⁰* = *i* would obtain in the protocol. Once an honest Bob (and *S*) obtain pe₀*;*pe₁, the rest of the computation is deterministic since it only involves computing m^ = pe mf and m = m m^. Hence, *S* obtains m₀*;*m₁ and sends (send*;*sid*;*m₀*;*m₁) to *F* in a way indistinguishable from a real world execution with *A*. This completes the proof that an ideal world simulation with *S* is indistinguishable from a real world execution of ProtocolOTwith *A*.

## D Instantiating the Protocol with the CDH Assumption

We will instantiate our scheme by showing that the ElGamal cryptosystem is OW-CPA secure and has Properties 1, 2, 3, 4 and 5 under the Computational Die-Hellman (CDH) assumption in the Global Random Oracle model. First we will recall the CDH assumption:

Assumption 1 The Computational Die-Hellman assumption requires that for every PPT adversary *A* it holds that

Pr[*A*(G*;w;g;g* *a* *;g* *b* ) = *g* *ab*] *2* negl()*:*

where the probability is taken over the experiment of generating a group G of $ order *w* with a generator *g* on input 1 and choosing *a;b* Z*q*.

The classical ElGamal cryptosystem [27] is parametrized by a group (G*;g;w*) of order *w* with generator *g* where the CDH assumption holds. We assume that (G*;g;w*) is known by all parties. The cryptosystem consists of a triple of algo- rithms PKE = (KG*;*Enc*;*Dec) that proceed as follows:

$sk { KG samples sk Z*w*, computes pk = *g* and outputs a secret and public-key pair (pk*;*sk). $ { Enc takes as input a public-key pk and a message m *2* G, samples r Z*p* computes *c₁* = *g* r, *c₂* = *m* pk r and outputs a ciphertext ct = (*c₁;c₂*). { Dec takes as input a secret-key sk, a ciphertext ct and outputs a message m = *c₂=c* sk

1.
The ElGamal cryptosystem described above is well-known to be OW-CPA secure [27], leaving us to prove that it has Properties 1, 2, 3, 4 and 5. Property 2 follows trivially from the fact that pk is chosen uniformly over all elements of G.

Observation 1 The ElGamal cryptosystem described above satises Property 1 under the CDH assumption.

*Proof.* First we observe that *PK* is G, which is a group. Assume by contra- diction that an adversary *A* succeeds in the experiment of Property 1. Under the CDH assumption, *A* must know both sk₁ and sk₂ corresponding to pk₁ and $ pk₂. However, we know that pk₁ pk₂ = *q* for a uniformly random *q* G (us- ing multiplicative notation for G). If *A* freely generated pk₁ and pk₂ such that pk₁ pk₂ = *q* and knows secret-keys sk₁ and sk₂, then it knows the discrete log- arithm of *q*, since it is equal to sk₁ + sk₂. The CDH assumption implies that computing discrete logarithms is hard, hence we have a contradiction and the observation holds. Alternatively, we can construct an algorithm *B* solving the CDH problem from an adversary *A* breaking Property 1. *B* plays the game of Property 1 acting as the challenger towards *A* = (*A₁; A₂*). Given a CDH instance (*g;g* *x* *;g* *y* ), *B* sets *q* *x*

|= g and gives q to A₁, who outputs state st and public keys pk₀|||||=|
|---|---|---|---|---|---|
|sk|||x|||
|y|yr|||q||
|xy|h h|(x sk)y|sk y|||
||m m|||||

*g₀* sk *;*pk₁ = *g₁* sk such that pk₀ pk₁ = *q* = *g* *x* (*i.e.* sk₀ + sk₁ = *x*). *B* computers $ $ ct₀ = (*g;h₀*)*andct₁* = (*g;h₁*), where *r* Z and *h₀;h₁* G, and gives ct₀*;*ct₁*;*st to *A₂*. If *A* breaks Property 1, it outputs two correct messages m₀*;*m₁. <u>1</u> *B* computes *g* = <u>0</u> 0 <u>1</u> 1 *r* = *g*1*g*1.

Properties 3 and 4 hold for the ElGamal cryptosystem as the ciphertext is a one-to-one function of the plaintext and randomness. Property 5 can be achieved using the encrypt-with-hash technique as discussed below.

D.1 Obtaining Witness-Recovering Decryption Not all OW-CPA PKE schemes with the other properties we require immediately have Property 5. Nevertheless, for encryption scheme that do not enjoy witness- recovering decryption, we can obtain it with the following technique. By using the encrypt-with-hash technique [2] in the global random oracle model, it is possible to obtain a secure public-key encryption scheme with witness-recovering and that satises Property 1 given any secure public-key encryption that satises Property 1. Let PKE = (KG*;*Enc*;*Dec) be a secure public-key encryption that

|satises Property 1 and let F|be a global random oracle with outputs in||
|---|---|---|
|R. Now dene the modied cryptosystem PKE⁰ KG⁰ that is the same as KG except that it includes the public key pk into the secret key sk; (2) an encryption procedure Enc⁰ that given a public key pk and||= (KG⁰; Enc⁰; Dec⁰) with: (1)|
|a message m, rst queries F outputs ct for ct|with input (sid; pk; m) to get an output r and||
|secret key sk and a ciphertext ct rst computes m||Dec(sk; ct), outputting ?|
|if Dec outputs ?. Then it queries F|with input (sid; m) to get an output r||

gRO

gRO Enc(pk*;*m; r); (3) a decryption procedure Dec⁰ that given a

gRO and checks if Enc(pk*;*m; r) = ct, outputting*?* if they are not equal; and (m*;*r) otherwise. Note that since *M* is exponentially large in the security parameter (since otherwise an adversary *A* against PKE could trivially break its Property 1) and in the game dening Property 1 the challenge messages are independent and chosen uniformly at random in *M*, the probability that the challenge messages m₁*;*m₂ are equal (resulting in the same ciphertext) is negligible. Basically, the only extra advantage that the adversary has when attacking PKE⁰ is that it can test whether a challenge ciphertext encrypts a given message m by encrypting it and checking whether the resulting ciphertext matches the challenge ciphertext. However, the adversary can only test if a challenge ciphertext contains a given message m by performing a re-encryption test if he queries *F*gROwith input (sid*;*m). Given that there is an exponential number of messages in *M* and that the adversary can only perform a polynomial number of queries to *F*gRO, it is trivial to get an adversary *A* that breaks Property 1 of PKE from an adversary *A⁰* that breaks Property 1 of PKE⁰.
