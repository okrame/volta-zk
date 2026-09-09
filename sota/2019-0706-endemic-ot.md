# Endemic Oblivious Transfer

### Daniel Masny and Peter Rindal

### VISA Research

Abstract

Oblivious Transfer has played a crucial role in the design of secure multi party computation. Nevertheless, there are not many practical solutions that achieve simulation based security and at the same time instantiable based on dierent assumptions. In this work, we consider a simulation based security notion that we call endemic security. We show how to construct highly ecient oblivious transfer in the random oracle model that achieves endemic security under a wide range of assumptions, among them DDH, CDH, LWE and coding based assumptions. We construct a secure oblivious transfer based on DDH that takes only a single communication round which allows signicant performance gains. We also instantiate our oblivious transfer with the Crystals.Kyber key agreement. Our implementation shows that both instantiations can be computed in under one millisecond. Further, we revisit, correct and improve existing oblivious transfer extension techniques. We provide an implementation of an oblivious transfer extension protocol in the ideal cipher model that is actively secure, processing up to 23 million OTs per second and up to 10 times faster than previous secure implementations. We also show that our framework can compute endemically secure OT extension and the base OTs in just two rounds.

## 1 Introduction

An oblivious transfer (OT) [Rab81,EGL82] is a cryptographic primitive often used in the context of secure multi party computation, which allows to preserve the privacy during a joint computation. Among others, it solves the task of securely distributing cryptographic keys for garbled circuits, which can be seen as encrypted programs. The combination of garbled circuits and oblivious transfer gives a generic solution for securely computing any functionality between two parties [Yao82,Yao86,Kil88,IPS08,IKO + 11] and multiple parties [CvT95,BL18,GS18]. In an OT, a sender and a receiver interact in a protocol and at the end of the protocol, the sender outputs two messages *s₀*, *s₁* while the receiver outputs *b;sb*for choice bit *b*. Security asks that the sender does not learn *b* and the receiver does not learn *s₁b*. It is known that an OT implies key exchange and can be constructed from special types of public key encryption (PKE) [GKM + 00,PVW08,FMV18], generalizations of dual mode PKE [GIS18] or certied trapdoor permutations [ORS15]. Though, all of these solutions come with some drawbacks when it comes to practical deployment. They either only achieve a weak security notion [GKM + 00] or lack eciency due to a special type of commitment protocol [Kil92,ORS15,FMV18] or dual-mode cryptosystem [PVW08,GIS18], which is less ecient than standard PKE and only known from DDH, QR and LWE with weaker parameter choices¹. There exist also solutions tailored to specic assumptions.

Peikert et al. require SIVP hardness for approximation factor *O*~(*n³* *:* ) while Regev’s PKE [Reg05] only requires *O* ~(*n¹:*).

Naor and Pinkas [NP01] constructed OTs from the DDH assumption and Brakerski and Dottling [BD18] from the LWE assumption that requires similar parameter choices as Peikert et al [PVW08]. In practice, a common approach is to use a critical amount of OTs in the random oracle model (ROM) [BR93] and then extend the amount of OTs to the desired amount of OTs using OT exten- sion [Bea96,IKNP03,OOS17,ALSZ15,KOS15]. A random oracle is an ideal hash function that usually is instantiated with a concrete hash function in the implementation. The ROM brings ma- jor eciency improvements and is therefore very common for practical cryptographic constructions, even though it might bring potential security weaknesses [CGH98]. In the ROM, Bellare & Micali [BM90] constructed OT based on the CDH assumption. Chou & Orlandi [CO15] claimed a more ecient OT construction which was proven with some caveats under the GapDH assumption [HL17]. Hauck & Loss improved the construction to base it on the CDH assumption [HL17]. Barreto et al. [BDD + 17] constructed an CDH based OT in the global random oracle model. A drawback of the more ecient constructions of Chou & Orlandi, Hauck & Loss, and Barreto et al. is that they require three or more rounds. The former also suers technical issues with the ability to extract the input of the receiver [CO15,BPRS17]. Further, unlike the more generic constructions based on PKE, they are tailored to specic assumptions. A more generic construction for OT in the ROM would be preferable since it allows an easier transition to dierent assumption like LWE or LPN, which unlike CDH and DDH are assumed to oer security in presence of quantum computers. In this work, we therefore want to focus on the question:

*How to construct a versatile, highly ecient and fully secure OT in the ROM?*

For eciency, we ask for a minimal round complexity, low computational complexity and com- patibility with OT extension techniques.

### 1.1 Our Contribution

We start with a basic security denition which has previously been considered by Garg, Ishai and Srinivasan [GIS18] as OT correlations functionality. We call this security *endemic* security and denote an OT that is endemically secure with endemic OT. Endemic security allows to achieve a minimal round complexity, also denoted as non-interactive OT [BM90,GIS18] as well as analyze the security of optimized existing OT and OT extension protocols. InSection 3, we compare endemic security notion with other notions and show that an endemic OT can eciently be transformed such the other considered security notions are achieved but potentially at the cost of a higher round complexity. We also show that only endemic security permits a one-round or non-interactive OT. InSection 4, we give a construction in the ROM that transforms any two message key agreement protocol, where the distribution of one of the messages is computationally close to uniform, into an endemically secure two message 1-out-of-*n* oblivious transfer². Further, if the key agreement protocol is a one-round protocol, we obtain a one-round endemic OT. This implies that we get a one-round endemic OT from DDH, CDH and two round endemic OT from LWE, LPN, McEliece and Subset Sum. We emphasize that [GIS18] construct a one-round UC secure OT from LWE, DDH, QR in the CRS model, while we focus on stand-alone security in the random oracle model in favor of eciency. 2 InAppendix C, we show how the framework can be adapted to obtain an endemically secure (*n* 1)-out-of-*n* OT.

InSection 5, we show that our construction is compatible with OT extension techniques. Con- cretely, we show that endemic OTs can be extended to a larger amount of endemic OTs using only one additional round. This allows us to obtain poly() OTs using only *O*() public key operations in only two rounds. We revisit the OT extension protocol of Keller et al., Orru et al. and Asharov et al. [KOS15,OOS17,ALSZ17] under endemic security. It turns out that its uniform message security can be fully broken. We point out attacks and provide xes such that classical, uniform and endemic security can be obtained. Finally, we observe that most OT extension protocols are implemented [Rin,Kel,WMK16] using an ideal cipher in place of a random oracle. However, these implementations have no security proofs and we show that they too can be fully broken. We give new protocols and proofs in the ideal cipher model which allows a 10 times speed up on the ROM when implemented. InSection 6, we implement our construction based on the Die-Hellman key exchange and the Module LWE (MLWE) based Kyber key encapsulation [SAB + 17]. We emphasize that it can also be instantiated with many of the other NIST post-quantum standardisation candidates and is to the best of our knowledge the rst implementation of a quantum resistant OT.

### 1.2 Our Techniques

Endemic Security. When dening malicious security of an OT, one denes an ideal functionality *F*OT. An OT is called secure, if for any adversary against the OT scheme, there exists an adversary interacting with *F*OTproducing the same output. Classically, *F*OTeither receives the OT strings *s₀*, *s₁* as input from the sender or samples them uniformly at random and outputs them to the sender. But there are also OTs where the receiver can determine the OT strings or even both parties could inuence how the OT strings are generated. We distinguish four main security notions.

Uniform Message Security: The ideal functionality *F* OT U samples the OT strings uniformly and outputs them to sender and one to the receiver.

Sender Chosen Message Security: The ideal functionality *F* OT S receives the OT strings from the sender and outputs one of the strings to the receiver.

Receiver Chosen Message Security: The ideal functionality *F* OT R receives one of the OT strings from the receiver, samples the other one uniformly at random and outputs the strings to the sender.

Endemic Security If the sender is malicious, it chooses both strings. If the receiver is malicious, it chooses one of the strings. All strings that are not chosen yet, are sampled uniformly by the functionality *F* OT E. The sender obtains both strings and the receiver obtains one.

Notice that endemic security gives the weakest security guarantees, no matter whether the receiver or the sender is malicious, the malicious party can always determine the distribution of the OT messages. Uniform message security gives very strong security guarantees since a malicious party can never inuence the distribution.

Relations Between Security Notions. We show on one hand that an OT with uniform message security is also secure with respect to all other security notions. On the other hand, uniform, sender and receiver chosen message security imply endemic security. Still, there are very simple transformations from an endemically secure OT to an OT that achieves any of the other security notions. Though we remark that uniform message security implies and therefore requires a secure coin tossing protocol. InFigure 1we give an overview over these implications and transformations.

### Uniform Message Security

Lem. 3.1 Lem. 3.1 Lem. 3.7

|S||||R|
|---|---|---|---|---|
|OT||Lem. 3.6||OT|
||Lem. 3.1||Lem. 3.1||
|Lem. 3.4||||Lem. 3.5|

### F-Security Coin Tossing F-Security

### Endemic Security

Figure 1: The gure depicts the dierent security notions of OT and their relations. *A)B*

denotes the implication. *A!B* denotes that there is an ecient transformation.

We also show that endemic OT is weaker than the other notions but at the same time this allows a minimal round complexity of a single round. More precisely, we show that there is no one round OT that achieves sender or receiver chosen message security.

From Key Agreement to OT A common strategy to construct OT from PKE is to use a PKE where the public keys form a group [PVW08,BDD + 17], which we will denote with (*G;*). By giving a challenge *c* and forcing the receiver to generate two public keys pk₀ and pk₁ s.t. *c* = pk₀ pk₁, he can intuitively only decrypt ciphertexts with respect to one of them. But this does not actually follow from the standard notion of PKE since an adversary could generate pk₀ and pk₁ jointly given

*c*. It requires a dual-mode cryptosystem [PVW08,GIS18] that is tailored towards this property. Dual-mode cryptosystems are known from DDH, QR and LWE [PVW08] but is not clear how to extend these results to other assumptions. Another approach [ORS15,FMV18] uses specic commitment protocols which forces the re- ceiver to commit to a public key before *c* is known. The drawback of this approach is that it requires four rounds and the known constructions of such a commitment protocol are not ecient [Kil92,ORS15]. We propose a dierent solution that uses a novel and simple technique to leverage the power of a random oracle. Rather than choosing two public keys, we ask the receiver to generate two strings *r₀*, *r₁* in *G*. From these strings a sender can generate the public keys pk₀ = *r₀* H(*r₁*), pk₁ = *r₁* H(*r₀*) under which he can encrypt the two OT messages *s₀*, *s₁*. In the actual protocol, the receiver can program *rb2fr₀;r₁g* to a public key for his choice of *b 2f*0*;* 1*g*. He samples *r₁b* and sets *rb*= pk H(*r₁b*). This technique also allows to extract *s₀*, *s₁* from a malicious sender by programming the random oracle such that secret keys for both, pk₀ and pk₁ are known. Further, one can extract *b* from a malicious receiver by programming the random oracle as well. Intuitively, a malicious receiver needs to query either *r₀* or *r₁* rst. His choice will determine *r₁b*, since all following random oracle queries *q* can be programmed such that H(*q*) = pk⁰ *r₁b*for a public key pk⁰. If a malicious adversary can learn *s₁b*, he will decrypt a ciphertext for pk₁*b*= *r₁b*H(*q*) = pk⁰ and be able to break the PKE scheme. We optimize the protocol further by using a key agreement instead of a PKE scheme. In many settings, the OT messages don’t need to be chosen, it is sucient if they are pseudorandom. Hence, no ciphertext needs to be generated, only the exchanged keys need to be computed. This save in some settings a communication round, e.g. in case of the Die-Hellman key exchange [DH76].

In the main body of this paper, we only consider stand-alone security. We show UC security for some settings of our protocol inAppendix E.

Secure OT Extension. InSection 5we explore the rich implications endemic security has on ecient 1-out-of-*N* OT extension along with presenting three new attacks and xes of existing OT extension protocols[KOS15,OOS17] with Uniform Message security³. These protocols are derived from the seminal black-box protocol of Ishia, Kilian, Nissim and Petrank[IKNP03]. We note that in all cases the Sender Chosen Message variant of these protocols[IKNP03,KOS15,OOS17] are secure. The functionality of 1-out-of-*N* OT extension allows *nC*instances of 1-out-of-2 OTs to be transformed into *m* = poly() instances of 1-out-of-*N* OTs. There are several advantages of this transformation. 1) *m* can be polynomial times larger than *nC*. 2) Only symmetric key cryptography is required which provides a larger performance improvement. 3) In some cases *N* can be exponential in the security parameter which we indicate with the use of capital *N*. The 1-out-of-2 OTs that are being transformed are referred to as *base OTs*. Existing protocols [IKNP03,ALSZ15,KOS15,OOS17] have called for the use of base OTs with the sender chosen message security notion, e.g. *F* OT S. However, we show that this requirement can be relaxed to allow the base OTs to only achieve endemic security. In both cases (*F* OT S or *F* OT E base OTs) the OT extension protocol outputs messages that satisfy the endemic security notion. Traditional OT extension protocols, e.g. [IKNP03,ALSZ15,KOS15], then apply a simple transform ( S 1*;N*,

Figure 4) to realize the sender chosen message functionality *F*

OT S. This observation suggests that more ecient OT extension can be realized by replacing Sender Chosen Message base OTs with Endemic OTs, e.g. our protocol. The authors of [KOS15,OOS17] suggest that the S 1*;N* transform can be removed and resulting protocol would satisfy the uniform message security notion, but in Section 5.1we show this to not be the case. In particular,Section 5.1detail three attacks where the rst allows a malicious party to bias the OT messages that they output while the second and third attacks succeed even when base OTs with uniform message security are used. In all cases, the ability to bias the messages violates the ideal functionality which samples them uniformly at random. Therefore, we show that the protocol only achieves Endemic security. We note that many protocols that utilize Uniform Message security can likely tolerate the weaker notion of Endemic security, e.g. [RR17a,RR17b]. However, other protocols such as the set inclusion protocol of [OOS17, Figure 5] are insecure⁴ when Uniform Message security is not satised. Uniform message security can be achieved from endemic OT extension in several ways. One solution is a black-box transformation U 1*;N* (Figure 6) which lifts an OT protocol with endemic security to satisfy uniform message security. However, this would require additional rounds and signicant communication. We demonstrate an alternative solution which replaces the base OTs with a protocol that satises uniform message, uniform selection security *F* OT U*u* and prove that this yields an OT extension protocol with uniform message security with minimal need to modify the extension protocol. More generally,Figure 2shows the relation between dierent base OT security notions and the resulting OT extension security. For example, the protocols of [IKNP03,ALSZ15,KOS15] perform

S ext E S 1*;*2S

||F !F|!F||
|---|---|---|---|
|[KOS15,OOS17] refer to uniform OT as random OT F The sender set all the OT messages to be the same value and force the receiver to conclude their item is in the sender’s set.|OT|OT|OT|

OT OT OT 3 *m;* ROT

<u>Base OT Security OT Extension Security</u> ext

|Uu||U|
|---|---|---|
|OT||OT|
|Su||S|
|OT S OT||OT|
|R||R|
|OT||OT|
|E||E|
|OT||OT|
||u OT|OT|

Uniform Security *F*OT U*u* Uniform Security *F*OT U

Sender Chosen *F* Sender Chosen *F* Sender Chosen *F* Receiver Chosen *F* Receiver Chosen *F* Endemic Security *F* Endemic Security *F*

Figure 2: The gure shows the implications of the base OT security (Denition 2.6) when

ext fromFigure 9or a slight variation (dashed line) is applied. *F* denotes *F* security where the receiver’s selection is uniformly sampled by the functionalityDenition 2.4,A.13.

where ext is their respective extension protocol up to hashing. In addition,Section 5.3details new OT extension protocols that can eciently be realized in the ideal cipher model. These protocol are inspired by existing implementation [Rin,Kel,WMK16] but are provably secure. Unfortunately, these existing implementation improperly apply the ideal cipher model which could be leverage by a malicious receiver to fully break *all* OT messages.

Implementation. We instantiate our OT protocol with the Die-Hellman key exchange. We show how the security loss can be reduced using the random self-reducibility of the DDH assump- tion. We also instantiate it based on the Kyber key exchange [BDK + 17,SAB + 17]. This is a proof of concept instantiation that shows that our framework is very agile in terms of assumptions and allows to obtain post-quantum security eciently. We give implementations and benchmarks for the two OT protocols as well as ve implemen- tations of OT extension protocols. Both our OT protocols can perform an OT in one millisecond. We compare our results with the OTs of Chou & Orlandi [CO15] and Naor & Pinkas [NP01]. In a WAN network setting we observe that our one-round DDH protocol is the fastest, requiring 110ms. The next fastest framework was the two round protocol of [CO15], requiring 210ms. In addition to being faster than [CO15] in the WAN setting, our protocols achieve full simulation based security without performing additional rounds as [CO15] requires. Our communication optimized OT extension protocol achieving endemic security requires two rounds of communication and can processes 2 million OTs per second. This is on par with a throughput optimized version of [KOS15,Rin] in the LAN setting. In the WAN setting our pro- tocol becomes 2.5 times faster than [KOS15] (which achieves stronger security). Our computation optimized protocol in the ideal cipher model can process 23 million OTs per second in the LAN over the course of 5 rounds and achieves full uniform message security.

## 2 Preliminaries

### 2.1 Notation

denotes the security parameter. For *n 2* N, [*n*] := *f*1*;:::;ng* and (*sj*)*j6*=*i*denotes ther ordered set (*sj*)*j2*[*n*]*nfig*. We use A*;*B, when A and B are clear from the context, to denote a protocol between two parties A and B. *h*A*;* B*i* denotes as the transcript of the protocol, which consists of all the messages sent between them. We use (A(*a*)*;*B(*b*)) to denote the joint output distribution of A and B when interacting in protocol with inputs *a* and *b*.

Denition 2.1 (Random Oracle). *A* random oracle *over a set of domains and an image is a*

A: <u>m</u> B: <u>A</u> mAA(tA) <u>mB</u>

||||m B(t|; m )|
|---|---|---|---|---|
||||B|B A|
|A|A B||B|B A|

B B A k = Key(t*;* m) k = Key(t*;* m)

Figure 3: The gure shows a key agreement protocol between parties A and B with random tapes

t Aand tB. Correctness requires kA= kB.

*collection of functions* H *that map an element q within one of the domains to a uniform element* H(*q*) *in the image.*

Denition 2.2 (Ideal Cipher). *An* ideal cipher *over a set of tuples of domains and an image is a* *collection of functions such that for any element* k *of the rst domain,*k*is a permutation that* *map an element q within the second domain to a uniform element*k(*q*) *in the image.*

### 2.2 Key Agreement

Denition 2.3 ((Two Message) Uniform Key Agreement (UKA)). *Let G be a group. We call a* *protocol between two ppt parties* A *and* B *(two message) uniform key agreement if* A *rst sends* *a message* mA*2 G to* B *and* B *responds with a nal message* mB*and in the end, both establish* *a common key* k *(seeFigure 3) using a key establishing algorithm* Key*. Further, we require three* *properties:*

Correctness: Pr[kA= Key(tA*;* mB) = Key(tB*;* mA) = kB] 1 negl*;*

*where* tA *f* 0*;* 1*g ,* tB *f* 0*;* 1*g ,* mAA(tA) *and* mBB(tB)*.*

Key-Indistinguishability: *For any ppt distinguisher* D *and any polynomial size auxiliary input* *z,* *j*Pr[D(*z; h*A*;* B*i;* k) = 1] Pr[D(*z; h*A*;* B*i;u*) = 1]*j* = negl*;*

*where* k *is the established key between* A *and* B *and u is a uniform element from the key* *domain.*

Uniformity: *For any ppt distinguisher* D *and any polynomial size auxiliary input z,*

*j*Pr[D(*z;*mA) = 1] Pr[D(*z;u*) = 1]*j* = negl*;*

*where u is a uniform element from G and* mAA(tA)*.*

*When* A *and* B *can send their messages concurrently, we call it a one-round* UKA*.*

InAppendix A.1, we dene multi-instance security notions when executing multiple instances of a key agreement. All the considered notions follow from the standard notions from above, but potentially with a polynomial security loss.

### 2.3 Oblivious Transfer

Denition 2.4 (Ideal *k*-out-of-*n* Oblivious Transfer). *An* ideal *k*-out-of-*n* oblivious transfer *is a* *functionality that interacts with two parties, a sender* S *and a receiver* R*.* R *sends a set* S [*n*] *of* *size k to the functionality.* *The functionality is publicly parameterized by one of the following message sampling methods:*

Sender Chosen Message: S *sends the messages* (*mi*)*i2*[*n*]*to the functionality who sets si*:= *mi.*

|Receiver Chosen Message: R sends the messages (m|||)|to the functionality who sets s||:=|
|---|---|---|---|---|---|---|
|0i i|0i i2[n]|i i i i2[n]|‘ i i2[n] ‘ i i2S|n S 0i|‘ n S R OT OT|i i2[n] U E OT OT|

*i i2*[*k*] S*i* *s* *0i* *for i 2* [*k*] *and uniformly samples si f* 0*;* 1*g* *‘* *for i 2* [*n*] *n* S*.*

Uniform Message: *The functionality uniformly samples* (*s₁;:::;s*) *f* 0*;* 1*g.*

Endemic: *If* S *is corrupt,* S *sends the messages* (*s*) *to the functionality. If* R *is corrupt,* R *sends the messages* (*s*) *to the functionality who sets si*:= *s for i 2* [*k*]*. All remaining* *s for i 2* [*n*] *are uniformly sampled s f* 0*;* 1*g by the functionality.*

*As specied by the message sampling method, the functionality constructs messages* (*s*)*.* *Thereafter, the functionality sends* (*s*) *to* S *and* (*s*) *to* R*. We denote the ideal function-* *alities for sender chosen, receiver chosen, uniform message and endemic as F; F; F; F,* *respectively.*

Remark 2.5. *We generalize this denition for the case where n can be exponential. In addition,* *we consider the case when the set* S *is sampled uniformly by the functionality. We call this* uni- form selection *as opposed to* receiver selection*. In this case, we denote the analogous oracles for*

|S|R|U|E|Su|Ru|Uu|Eu|
|---|---|---|---|---|---|---|---|
|OT|OT|OT|OT|OT|OT|OT|OT|

*F; F; F; F as F; F; F; F, respectively. SeeDenition A.13.*

In our denition of OT, we use the simplied UC security denition that is sucient for full UC security [CCL15]. We also use this denition for our stand-alone security analysis in the main body of this paper, but in that case, we allow adversary *A*’ to rewind adversary *A*.

Denition 2.6 (*k*-out-of-*n* Oblivious Transfer (OT*k;n*)). *We call a protocol between two ppt* *parties, a sender* S *and a receiver* R*, a k*-out-of-*n* oblivious transfer *if at the end,* S *outputs n* *strings* (*si*)*i2*[*n*]*and* R *outputs* (*si*)*i2*S*and a set* S [*n*] *s.t. j*S*j* = *k. For security, we require two* *properties with respect to a functionality F*OT*.*

Security Against a Malicious Sender: *For any ppt adversary A, there exists a ppt adversary* *A’ such that for any ppt environment* D *and any polynomial size auxiliary input z*

*j*Pr[D(*z;*(*A;* R)) = 1] Pr[D(*z;*(*A⁰; F*OT)) = 1]*j* = negl*;*

*where all algorithms receive input* 1*.* R *additionally receives input* S*.*

Security Against a Malicious Receiver: *For any ppt adversary A, there exists a ppt adversary* *A’ such that for any ppt distinguisher* D *and any polynomial size auxiliary input z*

*j*Pr[D(*z;* (S*; A*)) = 1] Pr[D(*z;*(*F*OT*; A⁰*)) = 1]*j* = negl*;*

### where all algorithms receive input 1.

### We distinguish four dierent security notions.

Uniform Message Security: *The OT is secure with respect to F* OT U *, i.e. F* OT U *-secure.*

Sender Chosen Message Security: *The OT is secure with respect to F* OT S *, i.e. F* OT S *-secure.*

Receiver Chosen Message Security: *The OT is secure with respect to F* OT R *, i.e. F* OT R *-secure.*

Endemic Security: *The OT is secure with respect to F* OT E *, i.e. F* OT E *-secure.*

Remark 2.7. *It is important to notice that we distinguish the functionality an OT provides from the* *ideal functionality for which the OT is secure. Here, F* OT U *-security is the strongest security denition* *since a malicious party cannot tweak the distribution of the strings* (*si*)*i2*[*n*]*. Endemic security gives* *the weakest security guarantees since in both cases, the malicious receiver and malicious sender* *case, the adversary can potentially choose the strings* (*si*)*i2*S*.*

Remark 2.8. *In the following, we assume that all messages from a sender or a receiver also contain* *a session identier* sid *and that for every new session between a sender and a receiver, they receive* *access to a fresh random oracle that is unique to that session (local random oracle).*

## 3 Relations Between OT Security Notions

We show now how endemic security relates to the other security notions of uniform, receiver and sender chosen message security. For an overview, seeFigure 1.

Lemma 3.1. *Let the distribution of OT strings be eciently sampleable. Then F* OT U *-security implies* *F* OT S *as well as F* OT R *-security. F* OT S *or F* OT R *-security imply F* OT E *-security.*

*Proof.* In the rst step, we show that uniform message security implies sender chosen message security and receiver chosen message security implies endemic security. These two implications result from the same simple fact that a malicious sender interacting with the ideal OT is easier to construct when it can choose the OT strings than when it receives the strings from the ideal OT. The following claim formalizes this fact.

|Claim 3.2. Let|||||that|
|---|---|---|---|---|---|
|i i2[n] E OT|i i2[n]|i i2[n]|U OT|R OT|OT OT S|

*be an OT secure against a malicious sender with respect to an ideal OT F* *sends the OT strings* (*s*) *to the sender, i.e. functionality F and F, and the distribution* *of* (*s*) *is eciently sampleable. Then is also secure against a malicious sender with respect* *to ideal OT F*OT*, which receives the OT strings* (*s*) *from the sender, i.e functionality F and*

*F.* *Proof.* We show that if there is an adversary that breaks the security against a malicious security with respect to ideal OT *F*OTthen there is also an adversary that breaks the security with respect to *F* OT. More precisely, if there is a ppt adversary *A₁* such that for any ppt adversary *A⁰*1there exists a ppt distinguisher D₁ and a polynomial size auxiliary input *z* with
*j*Pr[D₁(*z;*(*A₁;*R)) = 1] Pr[D₁(*z;*(*A⁰*1*; F*OT)) = 1]*j* =*;*

where all algorithms receive input 1 and R additionally receives input S. Then there is also a ppt adversary *A₂* such that for any ppt adversary *A⁰*2there exists a ppt distinguisher D₂ and a polynomial size auxiliary input *z* with

*j*Pr[D₂(*z;*(*A₂;*R)) = 1] Pr[D₁(*z;*(*A⁰; F*OT)) = 1]*j* =*;*

where all algorithms receive input 1 and R additionally receives input S.

Sender((*si*)*i2*[*n*]): Receiver(S [*n*]): <u>S</u>

|||(m )|(m|)|||
|---|---|---|---|---|---|---|
|||i i2[n]|OT E|i i2S|||
|i ‘|i i i i2[n]|S k;n|i i2[n] OT|E|i i i i2S|i|

*8i 2* [*n*] : *F* *r* := *s m*

(*r*) *8i 2* S :
*s* := *r m* output (*s*) output (*s*)

Figure 4: Sender chosen OT protocol in the *F* hybrid (Denition 2.4). For all *i 2* [*n*], *ri*,

*mi*and *si*are in *f*0*;* 1*g*.

We set *A₂* := *A₁* and D₂ := D₁. Further, for any *A⁰*2, there is an *A⁰*1such that the distribution of (*A⁰*2

|; F ) is identical with the distribution (A⁰||; F|). This follows from the fact that A⁰|
|---|---|---|---|
|2 OT|i i2[n]|1|OT|
|||1||
|||1||

OT 1 OT 1 could choose the OT strings (*s*) from the same distribution as *F* OT does and otherwise follow the description of *A⁰*2. Since D₁ is successful for any *A⁰* it will be also for any *A⁰*2, which can be seen as a subset of the set of all ppt adversaries *A⁰*.

The remaining two implications, from uniform security to receiver chosen message security and from sender chosen message security to endemic security follow in a similar fashion. Again it is easier to construct a malicious receiver interacting with the ideal OT when he can choose the OT strings rather than receiving them from the ideal OT.

|Claim 3.3. Let|be an OT secure against a malicious receiver with respect to an ideal OT F||||||
|---|---|---|---|---|---|---|
|||i i2S||U OT|S OT|OT|
|E OT|i i2S||i i2S|||OT R|
|||||||2|
|||1|1||i i2S||
|||OT|||||

*that sends the learned OT strings* (*s*) *to the receiver, i.e. functionality F and F, and the* *distribution of* (*s*) *is eciently sampleable. Then is also secure against a malicious sender* *with respect to ideal OT F*OT*, which receives the OT strings* (*s*) *from the receiver, i.e. F and*

*F.* *Proof.* The proof is basically identical to the proof of ClaimA.11. Again, the set of all ppt *A⁰* is a subset of the set of all ppt *A⁰* and identical with the set of all *A⁰* that sample (*s*) from the same distribution as when sent by *F*. Even though endemic security is implied by all the other security notions and could be seen as the weakest, it is still sucient to obtain any of the other notions by using very simple transformations. In the following lemmas we show these transformations and sketch their security. Lemma 3.4.
S *k;n* *ofFigure 4realizes the sender chosen message ideal OT F* OT S *(Denition 2.4)* *with unconditional security in the F* OT E *hybrid.*

*Proof.* We construct a new adversary *A⁰*1which interacts with functionality *F* OT S and produces an identical output to *A₁*. *A⁰*1plays the role of *F* OT E and R in S *k;n* while running *A₁*. *A⁰*1receives the endemic OT strings *m₁;:::;mn*from *A₁*, along with the strings *r₁;:::;rn*. *A⁰*1extracts the OT strings of *A₁* as *si i i* 1 *i i2*[*n*]

|:= r|m. A⁰|sends (s|) to F|and outputs whatever A₁ outputs.||||
|---|---|---|---|---|---|---|---|
|i|i 1||i i2[n]|OT S||||
||||||||S|
||||||||k;n|
||S|||||||
|1|OT|||||||
|||||||2||
|S|||||||E|
|OT S||||||2|OT|
|k;n||2||||||

OT S

Observe that the output of the honest receiver is identical when *A₁* interacts with R in and when *A⁰* interacts with *F*. Now consider a corrupt receiver *A*. We construct a new adversary *A⁰* which interacts with the functionality *F* and produces an identical output distribution to *A₂*. *A⁰* plays the role of *F* and S in while running *A₂*. *A⁰* receives the set S [*n*] of size *k* and the endemic OT strings

Sender: Receiver(S*;* (*si*)*i2*S): <u>S</u> *8i 2* [*n*] *n* S : (*mi*)*i2*[*n*] *F* E<u>(m</u> <u>i</u> <u>)</u> <u>i2S</u> *‘* OT *ri f* 0*;* 1*g* *8i 2* [*n*] : (*r* *i* ) *i2*[*n*] *8i 2* S : *s* *i*:= *rimiri*:= *simi* output (*si*)*i2*[*n*]output (*si*)*i2*S

Figure 5: Receiver chosen OT protocol

R *k;n* in the *F* OT E hybrid (Denition 2.4). For all *i 2* [*n*], *ri*, *mi*and *si*are in *f*0*;* 1*g* *‘*.

(*mi*)*i2*Sfrom *A₂*. *A⁰*2sends S to *F* OT S and receives (*si*)*i2*Sin response. *A⁰*2computes *ri*:= *simi* for *i 2* S and uniformly samples *ri f* 0*;* 1*g* *‘* for *i 2* [*n*] *n* S. *A⁰*2sends *r₁;:::;rn*to *A₂* and outputs whatever *A₂* outputs. The transcripts of *A₂* in these two interactions are identical except for (*ri*)*i2*[*n*]*n*S. Observe that in the real interaction for *i 2* [*n*] *n* S, *ri*:= *simi*, where *mi*is sampled uniformly at random by functionality *F* OT E and is independent of the transcript of *A₂* (conditioned on *ri*). Therefore sampling *ri*directly induces an identical distribution. Therefore, any distinguishing advantage *A₁* or *A₂* produces in protocol S *k;n* implies that *A⁰*1or *A⁰*2would produce the same advantage against the instantiation of *F* OT E, i.e. negl.

Lemma 3.5. R *k;n* *ofFigure 5realizes the receiver chosen message ideal OT F* OT R *(Denition 2.4)* *with unconditional security in the F* OT E *hybrid.*

*Proof.* First let us consider any corrupt sender *A₁*. We construct a new adversary *A⁰*1which interacts with *F* OT R and produces an identical output distribution as *A₁*. *A⁰*1plays the role of *F* OT E and R in R while running *A*. *A⁰* receives the endemic OT strings *m ;:::;m* from *A*. *A⁰* invokes *F* R *k;n* 1 1 1 *n* 1 1 OT as the sender and receives *s₁;:::;sn*in response. *A⁰*1sends *r₁;:::;rn*to *A₁* where *ri*:= *m₁ si*and outputs whatever *A₁* outputs. The transcripts of *A₁* in these two interactions are identical except for (*ri*)*i2*[*n*]*n*S. Observe that in the real interaction for *i 2* [*n*] *n* S, *ri f* 0*;* 1*g* *‘* while *A⁰*1chooses *ri*:= *m₁ si*where *si*is sampled uniformly at random by *F* OT R. Therefore, computing *ri*:= *m₁ si*implies an identically distribution as when *ri f* 0*;* 1*g* *‘* given that *si f* 0*;* 1*g* *‘* is independent of the transcript of *A₁*. Now let us consider a corrupt receiver *A₂*. We construct a new adversary *A⁰*2which interacts with *F* OT R and produces an identical output as *A₂*. *A⁰*2plays the role of *F* OT E and S in R *k;n* while running *A₂*. *A⁰*2receives the set S [*n*] of size *k* and the endemic OT strings (*mi*)*i2*Sfrom *A₂*. *A⁰*2 receives *r₁;:::;rn*from *A₂* and extracts (*si*)*i2*Sas *si*:= *rimi*. *A⁰*2sends S and (*si*)*i2*Sto *F* OT R and outputs whatever *A₂* outputs. The output distribution of he honest sender is identical in these two interactions is identical

|except for (s|)||:= m|r where m|is sampled uniformly by|||
|---|---|---|---|---|---|---|---|
|OT E|||OT R|i|‘|||
||||||||R|
||||||||k;n|
|||||||E||
|1|2 U|E|||U OT|OT||
|||OT||||||

*i i2*[*n*]*n*S. In the real interaction S outputs *si i i i* *F* E and independent of the transcript. Therefore *F* R sampling *si f* 0*;* 1*g* *‘* directly is identically distributed. Therefore, any distinguishing advantage adversary *A₁* or *A₂* produces in protocol implies that *A⁰* or *A⁰* would produce the same advantage against the instantiation of *F*, i.e. negl.

Lemma 3.6. *ofFigure 6realizes the uniform message ideal OT F (Denition 2.4) with* *unconditional security in the F; F* coin *(Denition A.1)hybrid.*

||Receiver(S [n]): Sender: S||
|---|---|---|
||E (m) (m) i i2 [n] i i2 S F OT 8i 2 [n] : 8i 2 S : (r) (r) coin i i i2 [n] i2 [n] F s := r m s := r m i i i i i i output (s) output (s) i i2 [n] i i2 S||
|;|U E coin Uniform OT protocol in the F; F hybrid (Denition 2.4). For all k;n OT ‘ 1 g. Receiver: Sender: [k] U (m) (m) i i i2 [n] i2 [k] F OT output (m) output (m) i i i2 [k] i2 [k]||

Figure 6: *i 2* [*n*], *ri*,

*mi*and *si*are in *f*0

Figure 7: Coin ipping protocol

coin in the *F* OT U hybrid. For all *i 2* [*n*], *mi*is in *f*0*;* 1*g* *‘*.

*Proof.* First let us consider any corrupt sender *A₁*. We construct a new adversary *A⁰*1which interacts with functionality *F* OT U and produces an identical output distribution as *A₁*. *A⁰*1plays the role of *F* OT E *; F* coin and R in U *k;n* while running *A₁*. *A⁰*1receives the endemic OT strings *m₁;:::;mn* from *A₁*. *A⁰*1invokes *F* OT U as the sender and receives *s₁;:::;sn*in response. When *A₁* invokes *F* coin, *A⁰*1 sends *r₁;:::;rn*to *A₁* on behalf of *F* coin where *ri*:= *m₁ si*and outputs whatever *A₁* outputs. Observe that *si*is sampled uniformly at random by *F* OT U and is independent of the transcript of *A₁* (conditioned on *ri*). Therefore computing *ri*:= *m₁ si*induces an identical distribution as *r* *i f* 0*;* 1*g* *‘*. Now let us consider a corrupt receiver *A₂*. We construct a new adversary *A⁰*2which interacts with *F* OT R and produces an identical output as *A₂*. *A⁰*2plays the role of *F* OT E *; F* coin and S in U *k;n* while running *A₂*. *A⁰*2receives the set S [*n*] of size *k* and the endemic OT strings (*mi*)*i2*Sfrom *A₂*. *A⁰*2invokes *F* OT U as the receiver with input S and receives (*si*)*i2*Sin response. When *A₂* invokes *F* coin *A⁰*2sends *r₁;:::;rn*to *A₁* on behalf of *F* coin where *ri*:= *m₁ si*for *i 2* S and otherwise sets *ri* as the output of *F* coin

. *A⁰*2outputs whatever *A₂* outputs.
The transcripts of these two interactions are identical except for the messages (*ri*)*i2*S. In the real interaction *ri*is sampled uniformly at random by *F* coin as opposed to *A⁰*2computing *ri*:= *misi*. Observe that *si*is sampled uniformly at random by *F* OT U and is independent of the transcript of *A₂* (conditioned on *ri*). Therefore computing *ri*:= *m₁ si*induces an identical distribution as *r* *i f* 0*;* 1*g* *‘*. Therefore, any distinguishing advantage adversary *A₁* or *A₂* produces in protocol U implies that *A⁰*1or *A⁰*2would produce the same advantage against the instantiation of *F* OT E or *F* coin, i.e. negl.

Lemma 3.7. *coin* *ofFigure 7realizes an ideal coin ipping protocol (Denition A.1)with uncon-* *ditional security in the F* OT U *hybrid (Denition 2.4).*

Sender: Receiver(*i 2* [*n*]): *8j 2* [*n*] *nfig* : *rj G* *8j 2* [*n*] : tA *f* 0*;* 1*g* t B*;j f* 0*;* 1*g* (*r* *j* ) mAA(tA) *j2*[*n*]

|m = r|H ((r )||r = m|H ((r )|
|---|---|---|---|---|
|A;j|j ‘ ‘6=j||i A|i j j6=i|
|B;j|B;j A;j|B;j j2[n]|||
|B;j|B;j A;j||A;i|A B;i|

A*;j j j ‘ ‘6*=*j*)*i* A *i j j6*=*i*) m = B(t*;* m) *8j 2* [*n*]

(m)
*s* = Key(t*;* m) *s* = Key(t*;* m)

Figure 8: The gure depicts a 1 out of *n* OT using a UKA = (A*;* B*;*Key) and *n* random oracles,

where for all *j 2* [*n*], H*j*: *G* *n* 1 *!G* and *G* is a group with operations,. By the correctness of the UKA scheme, kA*;i*= kB*;i*holds. In case of a one-round UKA the messages can be sent simultaneously.

*Proof.* Follows straigthforwardly from the denition of *F* OT U and the ideal coin tossing functionality *F* coin, which outputs a random string to both parties.

As we have shown, endemic security allows to obtain any of the other notions eciently. But as we show in the following lemmas, there can not be a one-round OT that achieves receiver or sender chosen message security. An adversary is at least able to tweak the distribution of the OT messages. As we will show in the upcoming section, there are OT protocols with a single round based on one-round key agreement.

Lemma 3.8. *There is no sender chosen message secure two message OT where the sender sends* *its message rst.*

Lemma 3.9. *There is no receiver chosen message secure two message OT where the receiver sends* *its message rst.*

Intuitively, if a malicious sender or receiver can choose its message in a two message protocol after seeing the message of the other party, he can bias the output distribution by resampling his message after observing what the learned OT message would be. We refer the reader for the formal argument toAppendix B.

## 4 From Key Agreement to Oblivious Transfer

InFigure 8, we present the generic construction from any two round key agreement to a two round OT. InTheorem 4.1, we show that both constructions yield an endemically secure OT. We emphasize that the protocol can be easily adapted to yield an all but one OT (seeAppendix C). In our security analysis for a malicious receiver, the simulator will rewind the malicious receiver. Hence we only obtain stand-alone security against a malicious receiver. InAppendix E, we show UC security against malicious receivers for our two-round construction and the one-round OT based on the Die-Hellman key agreement under a stronger variant of the DDH assumption.

Theorem 4.1. *Given a correct and secure* UKA *scheme, then the* 1 *out of n oblivious transfer in*

*Figure 8is an endemic* OT₁*;nwith stand-alone security in the programmable random oracle model.*

*Proof.* Given a honest sender, receiver and the fact that UKA, an environment cannot distinguish the protocol from the ideal functionality. We focus now on security against a malicious sender.

Claim 4.2. *Given a* (*n* 1)*-multi-instance-uniform* UKA *scheme, then it holds that in the pro-* *grammable random oracle model for any ppt adversary A, there exists a ppt adversary A’ such that* *for any ppt distinguisher* D *and any polynomial size auxiliary input z,*

*j*Pr[D(*z;*(*A;* R)) = 1] Pr[D(*z;*(*A⁰; F*OT E )) = 1]*j ;*

*where all algorithms receive input* 1 *and* R *additionally receives input* S*.*

*Proof.* We dene *A⁰* as follows. It generates (*r*

||)|by sampling r₁;:::;r||G. Then, it samples|
|---|---|---|---|---|
||j j2[n]|||n|
||A;j||||
|i i6=j|i i|i i6=j j j2[n]|A;i|B;j j2[n]|
|A;j B;j|||A;j j2[n]|OT E|

for all *j 2* [*n*], tA*;j f* 0*;* 1*g* and mA*;j*A(t). Finally it programs the random oracle for all of the *j 2* [*n*] points (*r*) such that *r* H ((*r*)) = m. Now *A⁰* invokes *A*, answers his random oracle queries straightforwardly, sends (*r*) and receives (m) from *A*. It computes *s*A*;j*Key(t*;* m) for all *j 2* [*n*] and submits (*s*) to *F*. *A⁰* outputs the output of *A*. We show, that if there is a distinguisher D that distinguishes the distribution (*A;* R) from (*A⁰; F* OT E ), then there is an distinguisher DUKAagainst the *n*-multi-instance uniformity of the UKA scheme. DUKAhas access to an oracle *O* that either outputs uniform strings or messages of the UKA protocol. For all *j 2* [*n*]*nfig*, DUKAfollows the description of *A⁰* with the dierence that instead of sampling mA*;j*A(tA*;j*), it samples mA*;j*from *O*. Given (*rj*)*j6*=*i*, it samples mA*;i*A(tA*;i*) and sets *r* *i*such that *ri*H*i*((*rj*)*j6*=*i*) = mA*;i*. As *A⁰*, it computes *s*A*;i*Key(tA*;i;* mB*;i*) which is R’s output. It now invokes distinguisher D on R’s output *s*A*;i*and the output of *A*. In the end, it outputs the output of D. We now analyze the distributions. First, notice that the distribution of (*ri;* m*A;i*) when sampling

|r G|and then programming the random oracle||||r H ((r|) ) =|m is identical to the||
|---|---|---|---|---|---|---|---|---|
|i|||i j j6=i||i i i|j j6=i i|A;i i j j6=i|A;i|
||||||||A;i||

*i i i j j6*=*i* A*;i* distribution when sampling H ((*r*)) and choosing *r* such that *r* H ((*r*)) = m, both are the uniform distribution over *GG* conditioned to their sum being m. Therefore it follows straightforwardly from the denition of *O*, R and *A⁰* that when *O* outputs uniform messages, the output of *A* is distributed as when interacting with R while when *O* outputs UKA messages, it is distributed as the output of *A⁰*. Hence, if there is a distinguisher D for any *z* that distinguishes the output distribution of *A* given *s*A*;i*, i.e.

D*j*Pr[D(*z;*(*A;s*A*;i*) D *O*A) = 1] Pr[D(*z;*(*A;s*A*;i*) D *Ou*) = 1]*j* UKA UKA then it implicitly breaks the (*n* 1)-multi-instance uniformity of the UKA protocol, i.e. *O*A *Ou* := *j*Pr[D UKA

(*z*)) = 1] Pr[D
UKA

(*z*) = 1]*j*

|j Pr[D(z; (A;s|)|) = 1] Pr[D(z; (A;s|)|
|---|---|---|---|
|D|A;i D||A;i D|

=A*;iO*A A*;iOu*) = 1]*j* UKA UKA *:*

We nish the proof of the theorem by showing that the OT protocol is secure against a malicious receiver.

Claim 4.3. *Given a Q-multi-instanceu-uniform,* (*Q;n* 1)*-multi-instancek-key indistinguishable* UKA *scheme, where Q upper bounds the amount of random oracle queries by an adversary then it* *holds that in the programmable random oracle model for any ppt adversary A, there exists a ppt* *adversary A’ such that for any ppt distinguisher* D *and any polynomial size auxiliary input z,*

*j*Pr[D(*z;* (S*; A*)) = 1] Pr[D(*z;*(*F*OT E *; A⁰*)) = 1]*ju*+*k;*

*where all algorithms receive input* 1 *and A’ is expected to rewind A Q times.*

*Proof.* Intuitively, we need to argue that all the mA*;j*for which R does not learn *s*A*;j*, *s*A*;j*is indistinguishable from uniform. To do this, we rst exploit the uniformity of UKA to argue that mA*;j*looks like an actual message of UKA. Afterwards, we can exploit the key-indistinguishability of UKA. To achieve this, we need to carefully program the random oracle. We start by giving a description of *A*’. *A*’ guesses a query index *2* [*Q*], where *Q* is an upper bound on the amount of oracle queries of *A*. Then *A*’ invokes *A*. If later this guess turns out to be incorrect, *A*’ aborts the current run with *A*, rewinds *A* and makes a new guess. When *A* makes an oracle query *q* to H*i*for an *i 2* [*n*] and the query number is less or equal to, *A*’ responds with a random group element H*i*(*q*) *G*. If the query number equals, *A*’ stores *i* := *i* and (*g₁;:::;g* *i* 1 *;g* *i* +1 *;:::;gn*) := *q*. For all following random oracle queries, i.e. the query number *j* is higher than, *A*’ responds with a random group element H*i*(*q*) *G* if *i* = *i* or for all *g 2 G qj6*= (*g₁;:::;g* *i* 1 *;g;g* *i* +1 *;:::;gn*) *n g* *i*. Otherwise *A*’ samples random tape t*j f* 0*;* 1*g* and computes m*j*A(t*j*). It responds with H*i*(*qj*) := m*jg* *i*. When *A* sends (*ri i2*[*n*] *i* 1 *i* +1 *n* E

|)|, A’ aborts if q|6= (r₁;:::;r||;r|;:::;r|). A’ sends i|to F|. A’ computes|
|---|---|---|---|---|---|---|---|---|
|i i2[n]||||i 1 i +1|n|||OT E|
||A;i|i i|‘ ‘6=i B;i|||B;i|B;i A;i||
||B;i A;i||B;i|OT E|B;i i2[n] B;i i2[n]||||

for all *i 2* [*n*] m := *r* H ((*r*)), t *f* 0*;* 1*g* and m B(t*;* m). It also computes *s*B*;i*:= Key(t*;* m). *A*’ sends *s* to *F*, (m) to *A* and outputs the output of *A*. In case of one-round OT, *A*’ generates and sends (m) to *A* in the very beginnning. This concludes the description of *A*’. In total, *A*’ is expected to rewind *A Q* times. Let there be a distinguisher D with

:= *j*Pr[D(*z;* (S*; A*)) = 1] Pr[D(*z;* ((*s*)*; A⁰*)) = 1]*j;* D B*;i i2*[*n*]

where (*s*B*;i*)*i2*[*n*]are the outputs of Key(tB*;i;* mA*;i*). Then there is a distinguisher D*u*breaking the *Q*- multi-instance uniformity of the UKA protocol. D*u*gets access to an oracle *O* which either outputs uniform messages, i.e. *Ou*or messages of the form mAA(tA) for tA *f* 0*;* 1*g*. D*u*invokes D and creates its input as follows. It invokes *A* and interacts with him as *A*’ does with the dierence that m*j*are requested from *O* rather than computing them. After receiving the output, D*u*uses it as input for D together with (*s*B*;i*)*i2*[*n*], where *s*B*;i*Key(tB*;i;* mA*;i*). D*u*outputs the output of D. If *O* is oracle *Ou*, all m*j*are uniform and hence all random oracle queries *q* are answered with a uniformly random H*i*(*q*) *2G*. Otherwise, *A*’ is identical with S as well as (*s*B*;i*)*i2*[*n*]are identical with the output of S. Hence

= *j*Pr[D *O*A

(*z*)] = 1] *Pr*[D
*Ou*

(*z*) = 1]*j*
*u u u* = *j*Pr[D(*z;* ((*s*B*;i*)*i2*[*n*]*; A*) *O*A) = 1] D*u* Pr[D(*z;* ((*s*B*;i*)*i2*[*n*]*; A*) D *Ou*) = 1]*j* *u* D*:*

Next, we assume that there is a distinguisher D with

D:= *j*Pr[D(*z;*(*s*B*;i*)*i2*[*n*]*; A*) = 1] Pr[D(*z;*SB*;i; A*) = 1]*j;*

where for all *i 2* [*n*], *sn*).

||is sampled uniformly from the key space of UKA and S||||||:= (s₁;:::;s||;s|;s ;:::;s|
|---|---|---|---|---|---|---|---|---|---|---|
||i|||||B;i||i 1|B;i|i +1|
||k|k|hA;Bi||||u k|k|||
|||k|||||||||
|k A;j|j|A;i|i i|‘ ‘6=i|A;j A;j|B;j|hA;Bi||||

Then there is a distinguisher D that breaks the (*Q;n* 1)-multi-instance key-indistinguishability of the UKA protocol. D has access to oracles *O* and *O* which is either *O* or *O*. D invokes D and creates its input as follows. D invokes *A* and interacts with it as *A⁰* does with the dier- ence, that D generates m by querying a transcript *h*A*;* B*i* = (m⁰*;*m⁰) from *O* and setting m*j*= m⁰. *A*’ computes for all *i 2* [*n*] *nfi g*

m⁰ := *r* H ((*r*)) = m⁰

where there exists a *j 2* [*Q*] such that the last equality holds. It also uses oracle *O* to query for all *i 2* [*n*] *nfi g* the *n* 1 corresponding keys k*i*that match with the transcripts containing mA*;i*. D*k* sets mB*;i*:= m⁰ B*;j* and *s*B*;i*:= k*i*. It creates mB*;i*and *s*B*;i*as *A*’ does. It sends (mB*;i*)*i2*[*n*]to *A* to receive its output which it uses together with (*s*B*;i*)*i2*[*n*]as input for D. D*k*outputs D’s output.

*Ok Ou* *k*= *j*Pr[D*k*(*z*)] = 1] *Pr*[D*k*(*z*) = 1]*j* = *j*Pr[D(*z;* ((*s*B*;i*)*i2*[*n*]*; A*) *Ok*) = 1] D*k* *Pr*[D(*z;* (SB*;i; A*) D *Ou*) = 1]*j* *k* D*:*

### We conclude with:

= Pr[D(*z;*(*F*

|j Pr[D(z; (S; A)|) = 1]|; A)) = 1]j|
|---|---|---|
|||OT E|
|u u k|B;i i2[n]|B;i|

OT + *j*Pr[D((*s*)*; A*) = 1] Pr[D(S*; A*) = 1]*j* +*;*

## 5 OT Extension

Next we review the OT extension protocol of [KOS15,OOS17,ALSZ17] which we describe in

Figure 9. The base OTs are performed on inputs that are sampled uniformly at random where

the roles of the sender and receiver are reversed with respect to the OTs that are output by the *j m j j m m* extension. That is, S will receive (*bj; t* *b* *j*

) *2* F₂ F₂ while R will receive (*t₀; t₁*) *2* F₂ F₂ for
*j 2* [*nC*]. *m nC* R forms two matrices *T₀;T₁ 2* F₂ by concatenating the base OT messages as column vectors, 1 *nC* 1 *nC*

i.e. *Ti*:= (*t*
*i* *:::t* *i* ). Similarly, S forms the matrix *T*b:= (*t* *b* 1 *:::t* *b* *n* ). R then encodes their 1-out- *C* *m nC* of-*N* selections *w₁;:::; wm*into a matrix *C 2* F₂. Each row *ci*is the codeword *C*(*wi*), where *C* is a binary code of length *nC*, dimension *kC*= log₂ and minimum distance *dC*. R sends the matrix *U* = *T₀* + *T₁* + *C* to S. Observe that *U* encodes the selections of R but the selection is *j* perfectly masked/encrypted due to the *j*-th column of *U* being masked by the column *t₁* *b* *j* which is uniformly distributed in the view of S. Upon receiving *U*, S computes *Q 2* F *m nC* where the *j*-th *j j j j j* column is dened as *q* := *bju* + *t* *b* *j* = *bjc* + *t₀*. It holds that

### qi= cib + ti

where is bitwise multiplication, *ti; qi*is the *i*-th row of *T₀;Q*, respectively, and *b* := (*b₁;:::;bnC*) *2* *nC* F₂. R will output *vi;wi*:= H(*i; ti*). S can then generate any OT message by computing *vi;w*:= H(*i; qi*+ *C*(*w*) *b*). Correctness of this operation follows from

*qi*+ *C*(*w*) *b* =(*C*(*wi*) *b* + *ti*) + *C*(*w*) *b* =(*C*(*wi*) + *C*(*w*)) *b* + *ti:*

Let = *C*(*wi*) +*C*(*w*). In the event that *wi*= *w*, then = 0 and S computes the same *vi;wi*value as R. Otherwise the hamming distance HD( ) *dC*by construction of *C*. For R to generate

*nC* any other OT message *vi;w*s.t. *w 6*= *wi*, R must guess the value *b 2* F₂ given, which can be done with probability 2 HD() = *O*(2). Traditionally, two additional steps are specied to realize the ideal sender chosen message functionality *F* OT S [IKNP03,KOS15,OOS17,ALSZ17]:

1.A proof that all rows in *C* can be decoded. Ishai et al. [IKNP03] proposed a cut-and-choose approach while the more recent schemes [KOS15,OOS17] improve on the eciency of these proofs by making R send random linear combinations of *ti; wi*and having S check they are consistent with same combination of *U*. [OOS17] follows a slightly dierent strategy. We defer the details behind these proofs to [KOS15,OOS17,OOS17].
2.The parties apply the sender chosen OT transformation
S 1*;N* fromFigure 4which reduces sender chosen to endemic OT. That is, S must send their chosen messages (*xi;*1 *i;N i2*[*m*]

|||;:::;x|)|
|---|---|---|---|
|||i;1|i;N i2[m]|
|i;N i2[m]||i;j i;j|i;j|

encrypted under the corresponding key (*vi;*1*;:::; v*), e.g. S sends *e* := *x* + *v* to R who outputs *xi;wi*= *ei;wi*+ *vi;wi*. Note, this step is not included inFigure 9. Next we will show without this step the protocol only achieves endemic security.

### 5.1 OT Extension Attacks

The authors of [KOS15,ALSZ17] and [OOS17] provide protocol descriptions that are intended to (respectively) satisfy the sender and uniform chosen message security notion,Denition 2.6, but we show this to not be the case. These protocols can be summarized as the previous protocol description where the S 1*;N* transformation is not applied, i.e. output *vi;xi*. For the rest of this work we will refer to the protocol of [OOS17] as dened inDenition 5.1but note that the attacks by a malicious R apply to [KOS15, Figure 6, 7] and [ALSZ17, Protocol 10]. In particular, we detail three attacks where the rst (Lemma F.1) allows a malicious R to bias the OT messages that they output while the second and third attacks (Lemma F.2,F.3) succeed even when base OTs with stronger security are used. In all cases, the ability to bias the messages violates the ideal functionality which samples them uniformly at random.

Denition 5.1. *Let* *OOS* *be the protocol ofFigure 9where F*OT:= *F* OT S *.*

Remark 5.2. *[OOS17] is inconsistent which type of base OTs should be used, switching between* S*;nC* *standard Sender Chosen Message OT (F* OT = *F* *2-OT* *) in the protocol description, theorem state-* U*;nC* *ments and Uniform Message OT (F* OT = *F* *2-ROT* *) in their proof.Lemma F.1only applies to* S*;nC* U*;nC*

|F = F|whileLemma F.2andF.3apply even with F|||||= F||base OTs. All three attacks|
|---|---|---|---|---|---|---|---|---|
|OT|2-OT||S OT|;n 2-OT||OT|2-ROT||
|||||||||i;x|
|n|i|;x|i i;x||||||

OT *2-OT* OT *2-ROT* *;nC* *apply to [KOS15] which uses F* = *F.*

Lemma F.1details an attack which allows R to bias the output *vi*to be H(*i;x*) for any *C* *x 2* F₂. The core idea behind this attack is that R has complete control over the matrix *T₀* since they input it to the base OTs. As such, R can choose their output messages to be *vi;xi*= H(*i; ti*) for any *t*. For example, let *t₁* = *t* for all *i 2* [*m*]. Then the distinguisher can compare the output of S and outputs 1 if *v₁*1= *vi*.

Lemma 5.3. *There exists a ppt adversary A and distinguisher* D *s.t. 8A⁰*

*j*Pr[D((S*; A*) *OOS*) = 1] Pr[D((*F*OT U *; A⁰*)) = 1]*j* = 1 2

*where* *OOS* *is the protocol inDenition 5.1. All algorithms also receive input.*

Parameters: is the computational security parameter. *m* denotes the number of OTs. *N* denotes the number of messages each OT has. *C* is an [*nC;kC;dC*] binary linear code such that *kC*= log₂ *N* and *dC*. A bijective map *map* : [*N*]*!* F *k*

*C*.
Requirements: H : [*m*] F *n* 2 *C* *!* F₂ is a random oracle. Let *m⁰* = *m* + *s* where *s* is dened inStep 4. *m⁰* *F*OTis an 1-out-of-2 OT oracle with output messages in F₂.

Extend: On input (Extend) from S and (Extend*;* (*x₁;:::;xm*) *2* [*N*] *m* ) from R.

1.Both parties invoke *nC*instances of *F*OTwhere S takes the role of the receiver. If *F*OThas inputs, the corresponding party locally samples them uniformly from the input domains. S receives (*b⁰ 2f*1*;* 2*g*
*n* *C; ftjb* *j* *g* *j2*[*nC*]) where *bi*= (*b* *0i*

1) *2f*0*;* 1*g*. R receives *f*(*t*
*j* 0 *; t* *j* 1

)*gj2*[*nC*]. Let
*m⁰ nC* 1 *nC* *Ti2* F₂ denote the matrix formed by concatenating the column vectors *tijj:::jjti*.

2. R denes *wi*:= *map*(*xi*) for *i 2* [*m*] and samples random *wm*+*‘*F
*k* 2 *C*, for *‘ 2* [*s*]. Then *m⁰ nC* constructs a matrix *C 2* F₂ such that each row *ci*is the codeword *C*(*wi*). Then, R sends to S the values *u* *j* := *t* *j* 0+ *t* *j* 1+ *c* *j* *; 8j 2* [*nC*]*;*

where *c* *j* is the *j*-th column of *C*. *j m⁰*

3. S receives *u 2* F₂ and computes
*q* *j* := *bju* *j* + *t* *jb* *j* = *bjc* *j* + *t* *j* 0 *; 8j 2* [*nC*]

that form the columns of an (*m⁰ nC*) matrix *Q*. Denoting the rows of *T₀;T₁;Q* by *ti; t₁;i; qi*, R now holds *ci; ti*and S holds *b; qi*so that

*qi*= *cib* + *ti; 8i 2* [*m⁰*]*:*

4. *Consistency check:* R proves in zero knowledge that
*8i 2* [*m*]*; 9w 2* F *k* 2 *C* *j* 0 = *b* (*ui*+ *ti*+ *t₁;i*+ *C*(*w*))

Note: *b 2* F

*n* 2 *C* is distributed uniformly in the view of R. For example, the proof of [KOS15] for *N* = 2 or [OOS17] otherwise. *s* 0 is specied by the proof protocol.

5. R outputs *vi;xj*:= H(*i; ti*) for all *i 2* [*m*].
Output: On input (Output*;* (*i;x*)) from S. If *i 2* [*m*]*;j 2* [*N*], then S outputs *vi;x*:= H(*i; qi*+ <u>C(map(x)) b).</u>

Figure 9: 1-out-of-*N* OT Extension.

*Proof.* For simplicity let *N* = 2 and *m* = 1. We dene *A* as follows. *A* plays the role of R and *j j m0* replaces the input to base OTs, the sender input, with strings *t₀; t₁ 2f*0*g* and then completes the protocol as normal. We dene D as follows. D executes S and *A* with input *x₁* = 1. S outputs (*v₁;*1*; v₁;*2) and D outputs 1 if *v₁;*1= H(1*; f*0*g* *nC* ) and 0 otherwise. In the real interaction it clearly holds that Pr[D((S*; A*) OOS) = 1] = 1. In the ideal interaction the honest S will output a uniformly distributed *v₁;*1*2f*0*;* 1*g* which was sampled by *F* OT U and therefore Pr[D((*F* OT U *; A⁰*)) = 1] = 2.

We now focus our attention to a second class of adversary that can distinguish even when the base OTs output uniformly distributed messages, i.e. *F* OT U. [OOS17] is inconsistent which type of

||S|U||
|---|---|---|---|
||OT|OT||
|OOS+||OT U||
||i|||
|i||i||
|i|||OT U|

base OTs should be used, switching between *F* in the protocol and *F* in the proof. Regardless the next two attacks apply.

Denition 5.4. *Let* *be the protocol ofFigure 9where F*OT:= *F.*

The core idea behind theLemma F.2attack against OOS+ is that R can choose their selection *after* seeing their output message, i.e. *H*(*i; t*). This allows R to correlate their selection *xi*with their message *H*(*i; t*) and there by distinguish. For example, let *v* = H(*i; t*) mod *N* and then R makes their selection be *x* = *v* + 1. This can not happen when interacting with *F*.

Lemma 5.5. *There exists a ppt adversary A and distinguisher* D *s.t. 8A⁰*

*j*Pr[D((S*; A*) *OOS+*) = 1] Pr[D((*F*OT U *; A⁰*)) = 1]*j* = 1 2

*where* *OOS+* *is the protocol inDenition 5.4and all algorithms additionally receive input* 1*.*

*Proof.* For simplicity let *N* = 2 and *m* =. We dene *A* as follows. *A* plays the role of R and *j j m0* receives the strings *t₀; t₁ 2f*0*g* from *F*OT. *A* redenes the selection values *x₁;:::;xm2* [2] of R such that *xi*:= lsb(H(*i; ti*)) + 1. That is, *xi*equals the least signicant bit of *vi;xi*= H(*i; ti*) plus

1. *A* executes the rest of the protocol as R would and outputs (*xi*)*i2*[*m*]. We dene D as follows. D executes S and *A*. S outputs (*vi;*1*; vi;*2)*i2*[*m*]and D outputs 1

|if 8i 2 [m]; lsb(v|) + 1|= x and 0 otherwise.||||
|---|---|---|---|---|---|
||i;x|i||||
|i;1 i;2|||i|OT U||
||n i|i;w|i|i||

*i;xii*In the real interaction it clearly holds that Pr[D((S*; A*) OOS+) = 1] = 1. In the ideal interaction the honest S will output a uniformly distributed *v; v 2f*0*;* 1*g* which are independent of *x* and therefore Pr[D((*F; A⁰*)) = 1] = 2.

Lemma F.3details another attack where a malicious S sets the base OT selection values to be b *b* := (1*;:::;* 1) *2f*1*;* 2*gC*. As such S learns the matrix *T₀* in full. Therefore S can always output the same message H(*i; t*) = *vi*as R. For sender chosen message or endemic security a viable simulation strategy is to extract *H*(*i; t*) and dene *vi;j*:= H(*i; t*) for all *j*. However, there is no valid strategy for the receiver chosen or uniform message security where the oracle samples some of the messages uniformly. This attack breaks the security of the set inclusion protocol described by [OOS17, Figure 5].

Lemma 5.6. *There exists a ppt adversary A and distinguisher* D *s.t. 8A⁰*

*j*Pr[D((*A;* R) *OOS+*) = 1] Pr[D((*A⁰; F*OT E )) = 1]*j* = 1 negl

*where* *OOS+* *is the protocol inDenition 5.4and all algorithms additionally receive input* 1*.*

*Proof.* For simplicity let *N* = 2 and *m* =. We dene *A* as follows. *A* plays the role of S and replaces the input to *F* OT S, the receiver input, with the string *b* := *f*0*g* *nC*. *A* outputs the matrix *Q*. We dene D as follows. D samples the selection bits *x₁;:::;xm*[2] and sends them to R. D executes *A* who outputs *Q* and R outputs *v₁;x*1*m;xm i;xi i*

||;:::; v. If v|= H(i; q|) for all i 2 [m], output|||
|---|---|---|---|---|---|
||m;x|i;x|i|||
||i|||OT E|i i|
|;i i2[m]||OT R||||

1, otherwise 0. In the real interaction it clearly holds that Pr[D((*A;* R) OOS+) = 1] = 1 since *q* = *t*. By denition the input of *A⁰* is independent of *x* and receives no output from *F* (apart from their input (*v₀;i; v₁*)). Therefore, it must hold that Pr[D((*A⁰; F*)) = 1] = 2.

### 5.2 OT Extension with a Random Oracle

We now give a new security proof (Lemma 5.8) of the [KOS15,OOS17] protocols with respect to the *F* OT E ideal functionality. We then give new enhancements (Denition 5.14,5.17,F.6) to this protocol that provider stronger notions of security at a modest overhead, e.g. *F* OT U. Note that in

this section we used the generalize denition of the OT functionality,Denition A.13,where a circuit specifying the inputs are send instead of strings. We also give a data ow diagram inFigure 16 showing the various instantiations and their round complexity.

|ext-E|OT E||
|---|---|---|
|ext-E||E|
|||OT|

Denition 5.7. *Let* *be the protocol ofFigure 9where F*OT:= *F.*

Lemma 5.8. *The* *protocol (Denition 5.7) is a 1-out-of-N OT (F) satisfying endemic* *and receiver selection Security.*

*Proof.* Correctness of the protocol was demonstrated by [OOS17].

Claim 5.9 (Malicious Sender Security). *ext-E* *satises security against a malicious sender (De-* *nition 2.6) with respect to the F* OT E *functionality.*

*Proof.* Consider the following hybrids which will dene the simulator *A⁰*.

Hybrid 1. *A⁰* internally runs *A* while plays the role of R and base OT oracle *F*OT= *F* OT E. For *0 0j j m00j 0* *j 2* [*nC*], *A*

|receives (b||) 2 [2]; t|F₂ from A inStep 1where b||1.|A uniformly|
|---|---|---|---|---|---|---|
|j b|OT 0|OT E|0 j|0j j b|OT|0 m n|
||||b||||
|||j|||||
|||b|||||

*b* *j* *j*:= *b* *j j* samples *t₁* *j* as *F* = *F* would. *A* sends (*b; ft* *j*

*g*) to *A* on behalf of *F*. *A* outputs
whatever *A* outputs. *0* *C 0* Hybrid 2.ForStep 2 *A* does not sample *t₁* *j* and instead uniformly samples *U* F₂. *A* sends *U* to *A* and then computes *Q* as S would. The view of *A* is identically distributed. This follows from the fact that *t₁* *j* is uniformly distributed in the view of *A* and masks the *j*-th column of *U* in the previous hybrid.

Hybrid 3.For each row *qi*, *A⁰* denes the circuit *Mi*: [*N*]*!f*0*;* 1*g* such that on input *j 2* [*N*] it

|||to the ideal functionality F|as the input to the|
|---|---|---|---|
||i||OT E|
||||i|
|i|i||i|

outputs H(*i; qi*+*b C*(*map*(*j*))). *A⁰* sends *Mi* OT E *i*-th OT instance. This change allows the ideal functionality to output the same distribution as the real protocol. The view of *A* is unmodied. Note, *A* can inuence *M* (*j*) = H(*i; qi*+ *b* *C*(*map*(*j*))) = *H*(*i;*(*c* + *C*(*map*(*j*)) *b* + *t*) by choosing *b* and the bits *ft* [*j*] *j bj*= 0*g*.

Hybrid 4.ForStep 4 *A⁰* simulates the consistency proof.

Hybrid 5. *A⁰* does not take the input of R since it was not used. R only interacts with *F* OT E. This change is identically distributed.

Claim 5.10 (Malicious Receiver Security). *ext-E* *satises security against a malicious receiver* *(Denition 2.6) with respect to the F* OT E *functionality.*

*Proof.* Consider the following hybrids which will dene the simulator *A⁰*.

Hybrid 1.

|A⁰ internally runs A while plays the role of S and base OT functionality F|||= F|.|
|---|---|---|---|---|
||||OT|OT E|
|0|j j i2n 0|||n|
|i|j|i|||
||i|k i|i|i|
|i|i||||

*0* *A* receives *ft₀; t₁gC*from *A* inStep 1. *A* outputs whatever *A* outputs. The view of *A* is unmodied.

*C* Hybrid 2.InStep 2 *A* receives *U* from *A*, computes *C* := *T₀* +*T₁* and uniformly samples *b* F₂. Let *B* := *fj j b* = *ig*. For all *i 2* [*m*], *A⁰* attempts to erasure decode *c* with erasures indexed *C* by *B₀*. If *c* failed to decode, then there does not exist a *w 2* F₂ s.t. 0 = *b* (*c* + *C*(*w*)) and *A⁰* aborts inStep 4as S would. Otherwise, let *ci*decode to *w* and *A⁰* computes *x* s.t. *w* = *map*(*x*)

*A⁰* denes the circuit *Si*[1]*!f*0*;* 1*g* with support *fxig* and *Mi*: [1]*!* F₂ s.t. *Mi*(1) = H(*i; ti*). *A⁰* sends *Si*and *Mi*to *F* OT E as the receiver’s input to the *i*-th OT instance. The view of *A* is unmodied and the ideal-real output agree on *vi;xi*.

Hybrid 3.Assuming *A⁰* did not abort inStep 4, let *E* = *fj j9i 2* [*m*]*;* (*ciC*(*wi*))*j*= 1*g* index the columns of *C* where *A* added an error to any codeword *ci*(w.r.t *wi*). By the correctness ofStep 4, it holds that *E B₀*, otherwise the consistency proof would have failed. By passing the consistency proof, *A* learns what *bj*= 0 for all *j 2 E*. Similarly, the probability of passing the check and Pr[*jEj* = *d*] = Pr[*bj*= 0 *j8j 2 E*] = 2 *d* due to the proof being independent of

*b*. We will see that this is equivalent to *A* simply guessing *E* (which is correct with the same probability) and then being honest. For all *w 6*= *wi*, *A* has negl probability of computing *g* = *qi*+*b C*(*w*). If this was not the case, then *A* could compute
*g* + *ti*= (*ci*+ *C*(*w*)) *b* = (*C*(*wi*) + *C*(*w*)) *b*

This last equality holds due to *A⁰* aborting if (*ci*+ *C*(*wi*)) *b 6*= 0. Recall that *C* has minimum distance *dC*and therefore computing *g* is equivalent *A* guessing *dC*bits of *b* which happens with probability 2 *d* *C*2. As such, the probability that *A* has made a query of the form H(*i; qi*+ *b C*(*w*)) for *w 6*= *wi*is also negligible. If such as query does happen *A⁰* aborts. This hybrid is indistinguishably distributed from the previous.

Hybrid 4.When S makes an H query of the form H(*i;h*) which has not previously be queries, *A⁰* *k* *C* must determine if there is a unique *w 2* F₂ such that *h* = *qi*+ *b C*(*w*). First, let us assume *0 kC* there exists two distinct *w;w 2* F₂ that result in *h*. That is,

*b* (*ci*+ *C*(*w*)) = *b* (*ci*+ *C*(*w⁰*)) 0 = *b* (*C*(*w*) + *C*(*w⁰*))

Recall that *C* by construction has minimum distance *dC*and that *b* is uniformly distributed. Let = *C*(*w*) + *C*(*w⁰*) and *E* = *fi ji*= 1*g*, then *jEj dC*and for the above to hold we require *bi*= 0 *j8i 2 E* which occurs with probability Pr[*bi*= 0 *j8i 2 E*] = 2 *jEj* 2 *d* *C*2. In such an event the simulations fails but this occurs with negligible probability.

*A⁰* checks that (*h* + *qi*)*‘*= 0 for all *‘ 2 fi j bi*= 0*g* and if so uses Gaussian elimination to determine if there exists a *w* such that *h* + *qi*erasure decodes to *w* where the erasures are index by *B₀* = *fi j bi*= 0*g*. If so, *A⁰* computes *x* s.t. *map*(*x*) = *w* and sends (Output*;x*) to the *i*-th instance of *F* OT *E* and receives *vi;x f* 0*;* 1*g* *‘* in response. *A⁰* programs H to output *vi;x* on this query. All other H queries are answered as normal. The distribution of H after being programmed is identical since the input has not previously been queried and in both cases the result is uniformly distributed.

Hybrid 5. *A⁰* does not take the input of S and does not program H inHybrid 5.2. S only interacts with *F* OT E. This change is identically distributed.

Denition 5.11. *Let* *ext-S* *be the protocol ofFigure 9where F*OT:= *F* OT S *.*

Lemma 5.12. *The* *ext-S* *protocol realizes 1-out-of-N F* OT E *security.*

### Proof. Follows directly fromLemma 3.1andLemma 5.8.

|ext-S||S|R||
|---|---|---|---|---|
|||OT S OT|OT|R OT|
|ext-R||OT|OT Su||
|ext-R|R||||
||OT||||

Lemma 5.13. *The* *protocol does not realizes 1-out-of-N F or F security.*

*Proof.* Follows directly fromLemma 3.1withLemma F.2for *F* andF.3for *F*.

Denition 5.14. *Let* *be the protocol ofFigure 9where F* := *F.*

Lemma 5.15. *The* *protocol realizes 1-out-of-N F security.*

*Proof.* Security against a malicious receiver follows fromLemma 3.1andLemma 5.8.

Claim 5.16 (Malicious Sender Security). *ext-E* *satises security against a malicious sender (Def-* *inition 2.6) with respect to the F* OT R *functionality.*

*Proof.* The general security of this claim also follows fromLemma 3.1andLemma 5.8. What remains is programming the random oracle. Observe that the honest receiver uniformly chooses *j nC*S*u* *t₀* and *b 2f*0*;* 1*g* is uniformly sampled by the *F* OT functionality. Now observe that all of the outputs strings are of the form

*vi;j*= H(*i; qi*+ *b C*(*map*(*x*))) = H(*i; ti*+ *b* (*ci*+ *C*(*map*(*x*))))*:*

Prior to receiving the output of *F* OT S*u*, *ti*is uniformly distributed in the view of *A*. As such, *A* has negligible probability of querying strings of this form. Therefore, H can be programmed to return the ideal output of *F* OT R when *A* queries it. The second concern is there does not exist distinct *x;x⁰ 2* [*N*] s.t.

### b C(map(x)) = b C(map(x⁰))

as this would result in H(*i; qi*+ *b C*(*map*(*x*))) = *vi;x*= *vi;x0* = H(*i; qi*+ *b C*(*map*(*x⁰*))) and thereby allow *A* to distinguish. However, this happens with negligible probability as described in claim 2, hybrid 4 ofLemma 5.8.

Denition 5.17. *Let* *ext-U* *be the protocol ofDenition 5.14where the random oracle* H *is redened* *as follows.*

*0* [*m*] F *nC*

*1.Let* H : *f*0*;* 1*g*2*!f*0*;* 1*g be a random oracle.*
*nC*

*2.InStep 1,* S *samples k* F₂ *sends an extractable commitment (Denition A.2)of k to* R*.*
*3.After receiving U inStep 2,* S *decommits to k to* R *who aborts is the decommitment fails.*
*4.Both parties dene* H(*i;x*) = H⁰(*i;x* + *k*)*.*
Lemma 5.18. *The* *ext-U* *protocol realizes 1-out-of-N F* OT U *security.*

*Proof.*

Claim 5.19 (Malicious Sender Security). *ext-Su*+ *satises security against a malicious sender* *(Denition 2.6) with respect to the F* OT U *oracle.*

*Proof.* The simulation follows the same strategy asLemma 5.15except now *A* is allowed to sample *k* and have the parties output messages of the form *vi;x*:= H(*i;k*+ *ti*+ *b* (*ci*+ *C*(*map*(*x*)))). The simulator *A⁰* samples *ti*uniformly at random after *A* is bound to their choice of *k* and therefore its easy to verify that *A* has negligible probability of querying H on such an input before receiving

*k*. Claim 5.20 (Malicious Receiver Security).
*ext-Su*+ *satises security against a malicious receiver* *(Denition 2.6) with respect to the F* OT U *oracle.*

*Proof.* The simulation also follows the same strategy asLemma 5.15with a few key dierences.

1. *A⁰* sends a dummy commitment in place of the commitment to *k*, i.e. a uniform string from the same distribution.
2.Then *A⁰* runs the normal simulation described byLemma 5.15up to the point that S would decommit to *k* except that *A⁰* does not program H as described.
3.At this point *A⁰*

|has received U|in stepStep 2and A send a valid proof forStep 4(by||
|---|---|---|
|0|0||
|i;x|0 i|n|
|||n|

*nC* assumption or *A* would have aborted). *A* now uniformly samples *k* F₂ and programs the commitment random oracle to decommit to *k*. *A⁰* then programs H⁰ to output the ideal *C* output *vi*of R for the query H (*i;k*+ *t*). Since *k 2* F₂ is uniformly distributed in the view of *A*, it follows that *A* has probability at most *q*2*Cq*2 = negl probability of querying the oracle at this point, where *q* is the number of queries that *A* has made.

4. *A⁰* then sends the decommits of *k* to *A* and completes the simulation asLemma 5.15does.
### 5.3 OT Extension with an Ideal Cipher

We now discuss how to eciently implement OT extension by restricting the input domain of the random oracle H to be *f*0*;* 1*g* *nC*. In particular, we are interested in the 1-out-of-2 OT case where *nC*= = 128. The core motivation for OT extension in this setting is the pervasive support for hardware based implementations of AES, which we will then use as an ideal cipher to hash the output messages. In this model we design new protocols that satisfy *F* OT R *; F* OT S and *F* OT U -security and achieve better concrete performance than the protocols analyzed inSection 5.2. These previous *nCnC* protocols have required a random oracle with input domain [*m*] F₂ which we reduce to F₂ while maintaining security. Existing implementations[Rin,Zoh16,Kel,WMK16] have either instantiated H as a strong hash function such as SHA-256 or using AES. However, in most cases⁵ that we observed[Rin,Zoh16,Kel], *nC* these instantiation incorrectly reduce the input domain to F₂ before applying H which can lead to full loss of security. In most cases⁵ the instantiation of H eectively follows the form H(*i;x*) = H⁰(*c₁x*+*c₂i*)+*c₁x*+*c₂i* for constants *c₁ 2* Z₃*;c₂ 2* Z₂ where H⁰ is either a strong cryptographic hash function or AES with a xed and public key. Regardless of *c₁;c₂;*H⁰, it is trivial to nd collisions *nC 0* in such an instantiation. For example, let *x 2* F₂ and then it holds that *8i;i 2* [*m*]*;*H(*i;x* +

*i*) = H(*i⁰;x* + *i⁰*). In the context of the OT extension protocols in the previous section, this The authors of [WMK16,GKWY19] independently identied the same implementation issue concurrently to us. [WMK16] securely implement H(*i;x*) but requires twice the number of ideal cipher calls. See [GKWY19].

*m* Protocol Security*y*Rounds ASM 1 32 128 512 1 32 128 512

|Protocol|Security|Rounds|ASM|1 32|128|512 1|32 128|512|
|---|---|---|---|---|---|---|---|---|
||||||LAN||WAN||
|[CO15]|GapDH, RO! \Rand. OT"|2|No|5 70|230|662 106|179 301|581|
||||Yes|2 6|18|64 104|115 210|272|
|[NP01]|DDH, RO !F|3|No|5 67|203|573 155|185 304|593|
||IDDH, RO !F|1|No|3 46|148|480 54|135 240|550|
|This|||Some|1 11|28|111 53|75 110|225|
||LWE, RO !F|2|Yes|1 6|24|105 101|108 154|481|

OT S E OT OT Sor *F* OT S*u*

Figure 10: Running times in milliseconds of our OT protocols and [CO15,NP01]. ASM indicates

if the implementation was written in assembly (better performance). *y* We emphasize that both, [NP01] and [CO15] do not give full simulation based malicious security, but only weaker security guarantees.

attack translates into a malicious receiver being able to fully break the security. For example, let *c₁* = *c₂* = 1, then R can choose *T₀* such that *ti*+ *i* = *ti0* + *i⁰*. It then holds that all the output messages of the receiver will be the same value. That is, for all *i;i⁰ 2* [*m*]*;x 2* [*N*], it holds that *vi;x*= *vi0;x*. One solution is to implement H directly as a random oracle as opposed to rst adding the input together. However, in the case of 1-out-of-2 OT this would prevent the ecient use of AES based hashing. We take a dierent approach by removing the requirement for inputting *i* into the hash function, i.e. R outputs H(*ti*) as opposed to H(*i; ti*). We prove this approach secure given that *T₀* is sampled uniformly. Intuitively, this condition is sucient due to collisions on the input to H being negligible, i.e. the set *fti*+ *b C*(*x*) *j8i;xg* does not collide⁶. SeeAppendix F.6for details and proofs.

## 6 Implementation

We give a detailed description of how to instantiate the OT protocols based on Die-Hellman key exchange under tigther security loss and based on Kyber inAppendix D. We implement and benchmark the optimized DH based (Appendix D.2)and the Kyber based protocol along with ve implementations of our OT extension protocols. See [Rin] for source code. We then compare these two several other implementation including the Chou & Orlandi [CO15] and Naor & Pinkas [NP01] OT protocols and the chosen string variant of Keller, Orsini & Scholl [KOS15]. All protocols are in the random oracle model. All protocols are implemented using the elliptic curve implementation of Relic Took-kit[AG] and the assembly based curve25519 of [CO15,CO]. For the OT protocol based on Kyber we adapt the [SAB + 17] key exchange implementation. For our protocol we instantiate the Random Oracle using Blake2 or the hashing to curve implementation of [AG] and the Ideal Cipher using AES. We perform experiments on a multi-core Intel Xeon processor at 2.7GHz and 256GB of RAM. Each party is given a single thread to execute on. The parties communicate over a network loop- back device. We consider two settings, LAN where the parties have a 10Gbp connection and sub millisecond latency and a WAN setting where an articial latency of 50 ms and throughput of 100Mbps is imposed on the loopback device. We consider computation security parameter = 128 and statistical security of = 40. Some of the OT protocols take advantage of code written in assembly which can signicantly outperform the other c++ implementations. We begin with the performance results for our OT protocols. These are detailed inFigure 10.

Assuming *b* is uniformly sampled.

*m* Protocol Security Total *n* 212216220224212216220224

|Protocol|Security|Total|n 2|2 2|2|2|2 2|2|
|---|---|---|---|---|---|---|---|---|
|||Rounds||LAN|||WAN||
||F ;RO !F|4|2 20|151 1,612|24,060|345|833 7,003|103,481|
|[KOS15]|F ;RO !F|5|2 28|84 640|8,361|865|1769 7,504|85,077|
||F ;RO !F|2|2 14|76 610|8,224|406|700 2,488|32,315|
||F ;RO !F|4|2 18|70 547|7,429|407|708 2,666|32,856|
||F ;IC !F|3|2 14|22 174|1,158|300|530 2,097|25,701|
||F ;IC !F|5|2 6|24 101|720|395|645 2,128|26,256|

ext-U S*u* U 76 OT OT OT S OT S ext-R S*u* R ext-U OT S*u* OT U OT OT ext-R U*u* R ext-U OT U*u* OT U OT OT

Figure 11: Running times in milliseconds of our 1-out-of-*n* OT extension protocols and [KOS15]

as implemented by [Rin]. Base OT running times are *not* included. RO indicates that a random oracle is used to has while IC *additionally* indicates an ideal cipher was used in the Davie-Meyer compression function, seeSection 5.2. Rounds includes the rounds required for base OTs.

Interestingly, our two protocols are each more ecient than the other depending on the network setting. The Kyber based protocol protocol is most ecient in the LAN setting. This is due to the highly ecient operations which essentially comprise of linear algebra. However, the public keys and encryptions that are send in the Kyber based protocol are 40 times larger than the DH based OT. For example, a single OT using Kyber requires a total of 5,934 bytes while the DH protocol requires 145 bytes. In the LAN setting this added communication has little impact. To perform 128 OT the Kyber implementation requires 24 milliseconds while our DH based approach takes 25 milliseconds (when using an assembly based implementation). We note that one would rarely perform a dierent number of OTs than 128 which are used as a seed for OT extension. In the WAN setting the decreased round complexity and communication of the DH approach allows it to achieve the smallest running times. To perform 128 OTs the DH protocol requires 130 milliseconds while the Kyber protocol requires 154 milliseconds. However, this increased perfor- mance comes at the expense of only achieving *F* OT E -security. We also compare against the protocol of [CO15] and [NP01]. In the LAN setting the fast protocol is that of [CO15] which requires each party to performance an amortized three exponentiation per OT while our DH protocol requires four. Both require ve in the worst case. However, the [CO15] approach suers from a technical issue in the proof where the input of the receiver can not be extracted at the appropriate time. As a result, to compose this protocol with OT extension requires additional computation and rounds of communication which we do not consider in our comparison,

e.g. see [DKLs18, Appendix A]. In addition, our hash to group implementation which takes up the majority of the running time dierence is *not* written in assembly. We suspect the gap between us and [CO15] narrow signicantly if ours was fully optimized. We also note that our protocol achieve full endemic security in just one round or sender chosen message in two rounds. Regardless, in the WAN setting with 128 OT our protocols achieve the best performance of 110ms (DH) and 154ms (Kyber) compared to 210ms by [CO15]. To achieve simulation bases security, at least one more round of communication is requires which would bring their time to at least 260ms, a 2*:* 3 increase compared to our protocol. To perform a single OT, our DDH protocol requires 145 bytes of communication, our Kyber protocol requires 5,934 bytes, [CO15] requires the least with 112 bytes and [NP01] requires 165 bytes. We now turn our attention to the OT extension performance result as shown inFigure 11. We compare our protocols to the fastest implementation [KOS15,Rin]. In particular, we update the [Rin] implementation of [KOS15] to allow the sender to specify the output messages and include the index *i* in the call to the random oracle H, as specied by [KOS15].. We implement ve variants of our proposals where the output strings are sampled by the protocol (or possibly a malicious

party). The 1-out-of-2 ext-R *;* ext-R protocols in the random oracle and ideal cipher model require 2 and 3 rounds of communication, respectively, and achieves *F* OT R -security. To reduce the rounds we apply the Fiat-Shamir transformation [FS87] to the sigma protocol of [KOS15] forStep 4. We also implement the ext-U and ext-U which both achieve *F* OT U -security. In the LAN setting where communication and round complexity has little impact the fastest protocol is our ext-U protocol which achieves our strongest security notion. The performance of this approach derives from the exclusive use of AES in the protocol which has extremely fast hardware support. For example, ext-U is 10 faster compared to the ext-U protocol which achieves the same *F* OT U -security in the random oracle model. The next fastest protocol is ext-R which achieves *F* OT R -security in the ideal cipher model. This protocol only requires 3 rounds of communication which allows it to be the most ecient in the WAN setting. However, the improved round complexity requires hashing the transcript of the protocol which decrease the running time in the LAN setting compared to ext-U. In the random oracle model we implement the ext-R protocol which only requires 2 rounds of communication, including the base OTs. In particular, the OT extension sender sends the rst base OT message and the receiver sends the second base OT message, the extension matrix *U* and Fiat- Shamir proof of consistency. One short coming of this approach is that *F* OT R -security is achieved. However, we argue that this level of security could be sucient for special purpose protocols which require both high performance and low round complexity. We also implement the ext-U protocol which requires two more rounds and does not apply the Fiat-Shamir transformation which allows improved performance in the LAN setting at the expense of worse performance in the WAN setting. This protocol is also implemented for 1-out-of-2 76 OT where the sender computes three of the OT strings. For a point of comparison we benchmark the [KOS15] protocol and nd that our protocols are between 3 and 8 times more ecient, depending on the network setting. Our performance improvements stem from the use of of the Ideal Cipher model (AES) and that fact that our protocols output random strings where as the secure version of [KOS15] requires the sender to send encrypted strings. This eectively triples the communication overhead and adds an additional round to the protocol. In particular, all of our extension protocols require an amortized bits of communication per 1-out-of-2 OT while [KOS15] requires 3.

## Acknowledgements

We thank Jonathan Katz and Mike Rosulek for pointing out aws with the UC security in the original paper. In this version, we xed aws and removed wrong claims. This mainly aects UC security of our one-round OT constructions. It is an open question to obtain UC secure one-round endemic OT from uniform key agreement. For our one-round UC OT from cyclic group based assumptions, we seem to require signicantly stronger assumptions than previously claimed. We thank Sebastian R. Verschoor for pointing out that we do not need the correctness of the key exchange protocol to prove security against a malicious receiver or sender. This is in particular signicant for LWE based OTs where malicious parties can cause decryption errors.

## References

[AG]D. F. Aranha and C. P. L. Gouv^ea. RELIC is an Ecient LIbrary for Cryptography. [https://github.com/relic-toolkit/relic](https://github.com/relic-toolkit/relic).

[ALSZ15]Gilad Asharov, Yehuda Lindell, Thomas Schneider, and Michael Zohner. More ecient oblivious transfer extensions with security for malicious adversaries. In Elisabeth Os- wald and Marc Fischlin, editors, *EUROCRYPT 2015, Part I*, volume 9056 of *LNCS*, pages 673{701. Springer, Heidelberg, April 2015.

[ALSZ17]Gilad Asharov, Yehuda Lindell, Thomas Schneider, and Michael Zohner. More ecient oblivious transfer extensions. *Journal of Cryptology*, 30(3):805{858, July 2017.

[BD18]Zvika Brakerski and Nico Dottling. Two-message statistically sender-private OT from LWE. In Amos Beimel and Stefan Dziembowski, editors, *TCC 2018, Part II*, volume 11240 of *LNCS*, pages 370{390. Springer, Heidelberg, November 2018.

[BDD + 17]Paulo S. L. M. Barreto, Bernardo David, Rafael Dowsley, Kirill Morozov, and Anderson

C. A. Nascimento. A framework for ecient adaptively secure composable oblivious transfer in the ROM. Cryptology ePrint Archive, Report 2017/993, 2017. http: //eprint.iacr.org/2017/993.
[BDK + 17]Joppe Bos, Leo Ducas, Eike Kiltz, Tancrede Lepoint, Vadim Lyubashevsky, John M. Schanck, Peter Schwabe, and Damien Stehle. CRYSTALS { kyber: a CCA-secure module-lattice-based KEM. Cryptology ePrint Archive, Report 2017/634, 2017. http: //eprint.iacr.org/2017/634.

[Bea96]Donald Beaver. Correlated pseudorandomness and the complexity of private compu- tations. In *28th ACM STOC*, pages 479{488. ACM Press, May 1996.

[BL18]Fabrice Benhamouda and Huijia Lin. k-round multiparty computation from k-round oblivious transfer via garbled interactive circuits. In Jesper Buus Nielsen and Vincent Rijmen, editors, *EUROCRYPT 2018, Part II*, volume 10821 of *LNCS*, pages 500{532. Springer, Heidelberg, April / May 2018.

[BM90]Mihir Bellare and Silvio Micali. Non-interactive oblivious transfer and applications. In Gilles Brassard, editor, *CRYPTO’89*, volume 435 of *LNCS*, pages 547{557. Springer, Heidelberg, August 1990.

[BPRS17]Megha Byali, Arpita Patra, Divya Ravi, and Pratik Sarkar. Fast and universally- composable oblivious transfer and commitment scheme with adaptive security. Cryptol- ogy ePrint Archive, Report 2017/1165, 2017. [https://eprint.iacr.org/2017/1165](https://eprint.iacr.org/2017/1165).

[BR93]Mihir Bellare and Phillip Rogaway. Random oracles are practical: A paradigm for designing ecient protocols. In V. Ashby, editor, *ACM CCS 93*, pages 62{73. ACM Press, November 1993.

[BRS02]John Black, Phillip Rogaway, and Thomas Shrimpton. Black-box analysis of the block-cipher-based hash-function constructions from PGV. In Moti Yung, editor, *CRYPTO 2002*, volume 2442 of *LNCS*, pages 320{335. Springer, Heidelberg, August

2002.
[CCL15]Ran Canetti, Asaf Cohen, and Yehuda Lindell. A simpler variant of universally compos- able security for standard multiparty computation. In Rosario Gennaro and Matthew

J. B. Robshaw, editors, *CRYPTO 2015, Part II*, volume 9216 of *LNCS*, pages 3{22. Springer, Heidelberg, August 2015.

[CGH98]Ran Canetti, Oded Goldreich, and Shai Halevi. The random oracle methodology, revisited (preliminary version). In *30th ACM STOC*, pages 209{218. ACM Press, May

1998.
[CO]Tung Chou and Claudio Orlandi. The Simplest Oblivious Transfer Protocol. http: //users-cs.au.dk/orlandi/simpleOT/.

[CO15]Tung Chou and Claudio Orlandi. The simplest protocol for oblivious transfer. In Kristin E. Lauter and Francisco Rodr*i*guez-Henr*i*quez, editors, *LATINCRYPT 2015*, volume 9230 of *LNCS*, pages 40{58. Springer, Heidelberg, August 2015.

[CvT95]Claude Crepeau, Jeroen van de Graaf, and Alain Tapp. Committed oblivious trans- fer and private multi-party computation. In Don Coppersmith, editor, *CRYPTO’95*, volume 963 of *LNCS*, pages 110{123. Springer, Heidelberg, August 1995.

[DH76]Whiteld Die and Martin E. Hellman. New directions in cryptography. *IEEE Trans-* *actions on Information Theory*, 22(6):644{654, 1976.

[DKLs18]Jack Doerner, Yashvanth Kondi, Eysa Lee, and abhi shelat. Secure two-party threshold ECDSA from ECDSA assumptions. In *2018 IEEE Symposium on Security and Privacy*, pages 980{997. IEEE Computer Society Press, May 2018.

[EGL82]Shimon Even, Oded Goldreich, and Abraham Lempel. A randomized protocol for signing contracts. In David Chaum, Ronald L. Rivest, and Alan T. Sherman, editors, *CRYPTO’82*, pages 205{210. Plenum Press, New York, USA, 1982.

[FMV18]Daniele Friolo, Daniel Masny, and Daniele Venturi. Secure multi-party computation from strongly uniform key agreement. Cryptology ePrint Archive, Report 2018/473,

2018. [https://eprint.iacr.org/2018/473](https://eprint.iacr.org/2018/473).
[FS87]Amos Fiat and Adi Shamir. How to prove yourself: Practical solutions to identication and signature problems. In Andrew M. Odlyzko, editor, *CRYPTO’86*, volume 263 of *LNCS*, pages 186{194. Springer, Heidelberg, August 1987.

[GIS18]Sanjam Garg, Yuval Ishai, and Akshayaram Srinivasan. Two-round MPC: Information- theoretic and black-box. In Amos Beimel and Stefan Dziembowski, editors, *TCC 2018,* *Part I*, volume 11239 of *LNCS*, pages 123{151. Springer, Heidelberg, November 2018.

[GKM + 00]Yael Gertner, Sampath Kannan, Tal Malkin, Omer Reingold, and Mahesh Viswanathan. The relationship between public key encryption and oblivious trans- fer. In *41st FOCS*, pages 325{335. IEEE Computer Society Press, November 2000.

[GKWY19]Chun Guo, Jonathan Katz, Xiao Wang, and Yu Yu. Ecient and secure multiparty computation from xed-key block ciphers. *IACR Cryptology ePrint Archive*, 2019:74,

2019.
[GS18]Sanjam Garg and Akshayaram Srinivasan. Two-round multiparty secure computation from minimal assumptions. In Jesper Buus Nielsen and Vincent Rijmen, editors, *EU-* *ROCRYPT 2018, Part II*, volume 10821 of *LNCS*, pages 468{499. Springer, Heidelberg, April / May 2018.

[HL17]Eduard Hauck and Julian Loss. Ecient and universally composable protocols for oblivious transfer from the cdh assumption. Cryptology ePrint Archive, Report 2017/1011, 2017. [https://eprint.iacr.org/2017/1011](https://eprint.iacr.org/2017/1011).

[IKNP03]Yuval Ishai, Joe Kilian, Kobbi Nissim, and Erez Petrank. Extending oblivious transfers eciently. In Dan Boneh, editor, *CRYPTO 2003*, volume 2729 of *LNCS*, pages 145{161. Springer, Heidelberg, August 2003.

+ [IKO 11]Yuval Ishai, Eyal Kushilevitz, Rafail Ostrovsky, Manoj Prabhakaran, and Amit Sa- hai. Ecient non-interactive secure computation. In Kenneth G. Paterson, editor, *EUROCRYPT 2011*, volume 6632 of *LNCS*, pages 406{425. Springer, Heidelberg, May

2011.
[IPS08]Yuval Ishai, Manoj Prabhakaran, and Amit Sahai. Founding cryptography on oblivious transfer-eciently. In David Wagner, editor, *CRYPTO 2008*, volume 5157 of *LNCS*, pages 572{591. Springer, Heidelberg, August 2008.

[Kel]Keller, Marcel and Orsini, Emmanuela and Scholl, Peter. APRICOT OT Extension. [https://github.com/bristolcrypto/apricot](https://github.com/bristolcrypto/apricot).

[Kil88]Joe Kilian. Founding cryptography on oblivious transfer. In *20th ACM STOC*, pages 20{31. ACM Press, May 1988.

[Kil92]Joe Kilian. A note on ecient zero-knowledge proofs and arguments (extended ab- stract). In *24th ACM STOC*, pages 723{732. ACM Press, May 1992.

[KOS15]Marcel Keller, Emmanuela Orsini, and Peter Scholl. Actively secure OT extension with optimal overhead. In Rosario Gennaro and Matthew J. B. Robshaw, editors, *CRYPTO 2015, Part I*, volume 9215 of *LNCS*, pages 724{741. Springer, Heidelberg, August 2015.

[NP01]Moni Naor and Benny Pinkas. Ecient oblivious transfer protocols. In S. Rao Kosaraju, editor, *12th SODA*, pages 448{457. ACM-SIAM, January 2001.

[OOS17]Michele Orru, Emmanuela Orsini, and Peter Scholl. Actively secure 1-out-of-N OT extension with application to private set intersection. In Helena Handschuh, editor, *CT-RSA 2017*, volume 10159 of *LNCS*, pages 381{396. Springer, Heidelberg, February

2017.
[ORS15]Rafail Ostrovsky, Silas Richelson, and Alessandra Scafuro. Round-optimal black-box two-party computation. In Rosario Gennaro and Matthew J. B. Robshaw, editors, *CRYPTO 2015, Part II*, volume 9216 of *LNCS*, pages 339{358. Springer, Heidelberg, August 2015.

[PVW08]Chris Peikert, Vinod Vaikuntanathan, and Brent Waters. A framework for ecient and composable oblivious transfer. In David Wagner, editor, *CRYPTO 2008*, volume 5157 of *LNCS*, pages 554{571. Springer, Heidelberg, August 2008.

[Rab81]Michael O. Rabin. How to exchange secrets by oblivious transfer. Technical report, Harvard University, 1981.

[Reg05]Oded Regev. On lattices, learning with errors, random linear codes, and cryptography. In Harold N. Gabow and Ronald Fagin, editors, *37th ACM STOC*, pages 84{93. ACM Press, May 2005.

[Rin]Peter Rindal. libOTe: an ecient, portable, and easy to use Oblivious Transfer Library. [https://github.com/osu-crypto/libOTe](https://github.com/osu-crypto/libOTe).

[RR17a]Peter Rindal and Mike Rosulek. Improved private set intersection against mali- cious adversaries. In Jean-Sebastien Coron and Jesper Buus Nielsen, editors, *EURO-* *CRYPT 2017, Part I*, volume 10210 of *LNCS*, pages 235{259. Springer, Heidelberg, April / May 2017.

[RR17b]Peter Rindal and Mike Rosulek. Malicious-secure private set intersection via dual execution. In Bhavani M. Thuraisingham, David Evans, Tal Malkin, and Dongyan Xu, editors, *ACM CCS 17*, pages 1229{1242. ACM Press, October / November 2017.

[SAB + 17]Peter Schwabe, Roberto Avanzi, Joppe Bos, Leo Ducas, Eike Kiltz, Tan- crede Lepoint, Vadim Lyubashevsky, John M. Schanck, Gregor Seiler, and Damien Stehle. Crystals-kyber. Technical report, National Institute of Stan- dards and Technology, 2017. available at [https://csrc.nist.gov/projects/](https://csrc.nist.gov/projects/) post-quantum-cryptography/round-1-submissions.

[Win84]R. S. Winternitz. A secure one-way hash function built from des. In *1984 IEEE* *Symposium on Security and Privacy*, pages 88{88, April 1984.

[WMK16]Xiao Wang, Alex J. Malozemo, and Jonathan Katz. EMP-toolkit: Ecient Multi- Party computation toolkit. [https://github.com/emp-toolkit](https://github.com/emp-toolkit), 2016.

[Yao82]Andrew Chi-Chih Yao. Protocols for secure computations (extended abstract). In *23rd* *FOCS*, pages 160{164. IEEE Computer Society Press, November 1982.

[Yao86]Andrew Chi-Chih Yao. How to generate and exchange secrets (extended abstract). In *27th FOCS*, pages 162{167. IEEE Computer Society Press, October 1986.

[Zoh16]Michael Zohner. Encrypto Group OTExtension. [https://github.com/](https://github.com/) encryptogroup/OTExtension, 2016.

## A Additional Preliminary Denitions and Lemmata

Denition A.1 (Coin Tossing). *An* ideal coin tossing *is a functionality denoted with F* coin *that* *interacts with two parties* A *and* B*, samples a uniform string r 2f*0*;* 1*g and sends r to* A *and* B*.*

Denition A.2 (Extractable Commitments). *An* extractable commitment scheme *consists of three* *algorithms.*

com(*x;r*): *Commits to x using randomness r.*

open(com*;x;r*): *Outputs* 1 *if commitment* com *2* com(*x;r*)*.*

ext(com*;*aux): *Given some auxiliary information, it extracts committed value x.*

*For security, we ask that it is hiding, i.e. for any x;m, x;* com(*x;r*) *is indistinguishable from* *m;* com(*x;r*) *and that it is binding, i.e. for any x,* ext(com(*x;r*)) *outputs x.*

An extractable commitment can easily constructed using a random oracle by dening com(*x;r*) := *H*(*x;r*), open simply evaluates H and checks equality and the ext algorithm observes the random oracle queries from which *x* can be learned.

### A.1 Key Agreement

We give the following additional security denition for key agreement protocols.

Denition A.3 (One-Round Uniform Key Agreement). *We call a* UKA one-round uniform key agreement *if the function* m

|B(t; m ) does not depend on m|and can be computed solely using||
|---|---|---|
|B B A|A||
||A B|B A|

*input* tB*. More precisely, there is a function* B⁰ *such that for any* m*,* B⁰(t) = B(t*;* m)*, which* *we will in the following refer to with* B *as well.*

Denition A.4 (Multi-Instance Uniformity). *We call a* UKA *Q-*multi-instance-uniform *if for* *any ppt distinguisher* D *and any polynomial size auxiliary input z,*

*j*Pr[D *O*A

(*z*)] = 1] *Pr*[D
*Ou*

(*z*) = 1]*j ;*
*where O*A*outputs* mAA(tA) *for fresh randomness* tA*and Ououtputs u G and Q is a bound* *on the amount of queries to Ou, O*A*.*

Denition A.5 (Multi-Instance Key-Indistinguishability). *We call a* UKA (*Q;n*)*-*multi-instance -key-indistinguishable *if for any ppt distinguisher* D *and any polynomial size auxiliary input z,*

||O|;O|O ;O||||
|---|---|---|---|---|---|---|
|hA;Bi|||i|i i|k||
|A;j|B;j hA;Bi|A;j hA;Bi|A;i B;i|i u||k u|

*j*Pr[D*h*A*;*B*i* k

(*z*)] = 1] *Pr*[D*h*A*;*B*i*
*u*

(*z*) = 1]*j ;*
*where O outputs on the i-th query a transcript* T := *h*A*;* B *i, O outputs on query j, key* k*j*= Key(t*;* mB*;j*) = Key(t*;* m) *that matches transcript* T*. O outputs a uniform element u* *from the key domain. O uses fresh random tapes* t*;* t *f* 0*;* 1*g for every query. Q is a* *bound on the amount of queries to O, where n bounds the amount of queries to O, O.*

In case of a one-round UKA, we dene a stronger version of the multi-instance key-indistinguishability, which we call one-round multi-instance key-indistinguishability.

Denition A.6 (One-Round Multi-Instance Key-Indistinguishability). *We call a one-round* UKA one-round (*Q;n*)-multi-instance-key-indistinguishability *if for any ppt distinguisher* D *and any* *polynomial size auxiliary input z,*

*j*Pr[D *O*A*;O*k (*z;*mB)] = 1] *Pr*[D *O*A*;Ou* (*z;*mB) = 1]*j ;*

*where* mBB(tB) *for uniform* tB*. O*A*outputs on the i-th query* mA*;i*A(tA*;i*) *for uniform* tA*;i.* *O*k*outputs on query j, key* k*j* A*;j* B) = Key(tB A *u*

||= Key(t|; m|; m|). O outputs a uniform element u|
|---|---|---|---|---|
||j|A;j|B|A u|
|||||A|
|k u|||||

*from the key domain. Q is a bound on the amount of queries to O, where n bounds the amount* *of queries to O, O.*

In the next lemmata, we show that all the security notions are implied by the standard deni- tions, but potentially with a polynomial security loss.

Lemma A.7. *Let* UKA *be-uniform, then it is Q-multi-instance Q-uniform.*

Hybrid hyb

|Proof. This follows straightforwardly from using a simple hybrid argument.|samples|
|---|---|
||i|
|A;j|i|
|i+1|A;i+1|

m for *j i* from *Ou*and for *j > i* from *O*A. If there is an adversary that distinguishes hyb from hyb for any *i*, then we can break the uniformity of UKA by distinguishing m from uniform.

Lemma A.8. *Let* UKA *be-key-indistinguishable, then it is* (*Q;n*)*-multi-instance Q-key-indistinguishable.*

*Proof.* Again, we use a hybrid argument over hybrids hyb*i*. In hyb

|, (m|; m ); k|is sampled from|
|---|---|---|
|i A;j|B;j j i|i+1|

*Oh*A*;*B*iOu*for *j i* and from *Oh*A*;*B*iO*kfor *j > i*. If one distinguishes hyb from hyb for some *i*, one breaks the key-indistinguishability.

Lemma A.9. *Let a one-round* UKA *be-key-indistinguishable, then it is one-round* (*Q;n*)*-multi-* *instance Q-key-indistinguishable.*

*Proof.* This lemma follows for the same reason asLemma A.8.

### A.2 Oblivious Transfer

Lemma A.10 (Repeat ofLemma 3.1). *Let the distribution of OT strings be eciently sampleable.* *Then F* OT U *-security implies F* OT S *as well as F* OT R *-security. F* OT S *or F* OT R *-security imply F* OT E *-security.*

*Proof.* In the rst step, we show that uniform message security implies sender chosen message security and receiver chosen message security implies endemic security. These two implications result from the same simple fact that a malicious sender interacting with the ideal OT is easier to construct when it can choose the OT strings than when it receives the strings from the ideal OT. The following claim formalizes this fact.

Claim A.11. *Let be an OT secure against a malicious sender with respect to an ideal OT F* OT

|||||U|R|
|---|---|---|---|---|---|
||i i2[n]|i i2[n]|i i2[n]|OT|OT|
|S|E|||||
|OT|OT|||||

*that sends the OT strings* (*s*) *to the sender, i.e. functionality F and F, and the distri-* *bution of* (*s*) *is eciently sampleable. Then is also secure against a malicious sender with* *respect to ideal OT F*OT*, which receives the OT strings* (*s*) *from the sender, i.e functionality* *F and F.*

*Proof.* We show that if there is an adversary that breaks the security against a malicious security with respect to ideal OT *F*OTthen there is also an adversary that breaks the security with respect to *F* OT. More precisely, if there is a ppt adversary *A₁* such that for any ppt adversary *A⁰*1there exists a ppt distinguisher D₁ and a polynomial size auxiliary input *z* with

*j*Pr[D₁(*z;*(*A₁;*R)) = 1] Pr[D₁(*z;*(*A⁰*1*; F*OT)) = 1]*j* =*;*

where all algorithms receive input 1 and R additionally receives input S. Then there is also a ppt adversary *A₂* such that for any ppt adversary *A⁰*2there exists a ppt distinguisher D₂ and a polynomial size auxiliary input *z* with

*j*Pr[D₂(*z;*(*A₂;*R)) = 1] Pr[D₁(*z;*(*A⁰*2*; F*OT)) = 1]*j* =*;*

where all algorithms receive input 1 and R additionally receives input S. We set *A₂* := *A₁* and D₂ := D₁. Further, for any *A⁰*2, there is an *A⁰*1such that the distribution of (*A⁰*2

|; F ) is identical with the distribution (A⁰||; F|). This follows from the fact that A⁰|
|---|---|---|---|
|2 OT|i i2[n]|1|OT|
|||1||
|||1||

OT 1 OT 1 could choose the OT strings (*s*) from the same distribution as *F* OT does and otherwise follow the description of *A⁰*2. Since D₁ is successful for any *A⁰* it will be also for any *A⁰*2, which can be seen as a subset of the set of all ppt adversaries *A⁰*.

The remaining two implications, from uniform security to receiver chosen message security and from sender chosen message security to endemic security follow in a similar fashion. Again it is easier to construct a malicious receiver interacting with the ideal OT when he can choose the OT strings rather than receiving them from the ideal OT.

|Claim A.12. Let|be an OT secure against a malicious receiver with respect to an ideal OT F||||||
|---|---|---|---|---|---|---|
|||i i2S||U OT|S OT|OT|
|E OT|i i2S||i i2S|||OT R|
|||||||2|
|||1|1||i i2S||
|||OT|||||

*that sends the learned OT strings* (*s*) *to the receiver, i.e. functionality F and F, and the* *distribution of* (*s*) *is eciently sampleable. Then is also secure against a malicious sender* *with respect to ideal OT F*OT*, which receives the OT strings* (*s*) *from the receiver, i.e. F and*

*F.* *Proof.* The proof is basically identical to the proof of ClaimA.11. Again, the set of all ppt *A⁰* is a subset of the set of all ppt *A⁰* and identical with the set of all *A⁰* that sample (*s*) from the same distribution as when sent by *F*. In the following, we give a generalized denition of OT. Denition A.13 (Generalize Ideal *k*-out-of-*n* Oblivious Transfer). *A (generalized)* ideal *k*-out-of-*n* oblivious transfer *is a functionality that interacts with two parties, a sender* S *and a receiver* R*.* *Let* S [*n*] *of size k and s₁;:::;sn2f*0*;* 1*g*
*‘* *.* *The functionality is publicly parameterized by one of the following message sampling methods:*

Sender Chosen Message: S *sends the circuit M* : [*n*]*! f*0*;* 1*g* *‘* *to the functionality which* *denes si*:= *M*(*i*)*.*

Receiver Chosen Message: R *sends the circuit M* : [*k*]*!f*0*;* 1*g* *‘* *to the functionality which* *denes s*S*i*:= *M*(*i*) *for i 2* [*k*] *and uniformly samples si f* 0*;* 1*g* *‘* *for i 2* S *n* [*n*]*.*

Uniform Message: *The functionality uniformly samples si f* 0*;* 1*g* *‘* *for i 2* [*n*]*.*

Endemic: *If* S *is corrupt, then* S *sends the circuit M* : [*n*]*!f*0*;* 1*g* *‘* *to the functionality which* *denes si*:= *M*(*i*)*.*

*If* R *is corrupt,* R *sends the circuit M* : [*k*]*! f*0*;* 1*g* *‘* *to the functionality which denes* *s*S*i*:= *M*(*i*) *for i 2* [*k*]*.*

*All remaining sifor i 2* [*n*] *are uniformly samples si f* 0*;* 1*g* *‘* *.*

*The functionality is publicly parameterized by one of the following selection methods:*

Receiver Selection: R *sends the circuit S* : [*n*]*!f*0*;* 1*g to the functionality where the support* *of S is of size k. The functionality denes* S := *fi jS*(*i*) = 1*g.*

Uniform Selection: *The functionality uniformly samples* S P([*n*]) *s.t. j*S*j* = *k.*

*As specied by the message sampling method, the oracle receives the circuit M from the appro-* *priate party if one is called for. As specied by the selection method, the functionality receives the* *circuit S if one is called for. Thereafter, upon receiving the message* (Output*;i*) *from* S*, respond* *with si. Upon receiving* (Output*;i*) *from* R *and if i 2* S*, respond with si.* *We denote the ideal functionalities for sender chosen, receiver chosen, uniform and endemic*

|S|R|U|E|
|---|---|---|---|
|Su OT|Ru OT|Uu OT|Eu OT|
|OT|OT|OT|OT|

*with receiver selection as F; F; F; F, respectively. The analogous oracles for Uniform* *Selection are denoted as F; F; F; F, respectively.*

Remark A.14. *When n is polynomial in the security parameter, we simplify the above denition* *toDenition 2.4to allow the parties directly input the appropriate simessages as opposed to* *specifying a circuit M. Similarly for the set* S := *fi jS*(*i*) = 1*g. Lastly, instead of querying the* *oracle with* (Output*;i*)*, the oracle sends* (*si*)*i2*[*n*]*to* S *and* (S*;* (*si*)*i2*S) *to* R*. This simplication* *can trivially be simulated when n* = *poly*()*.*

Sender: (*s*) Receiver:

|(i) i2[n]||0|
|---|---|---|
||S|(i) i2S|
||OT||

<u>S</u>*0 0* *n*S P([*n*]) s.t. *j*S *j* = *k* *F*

(*s*) *0*
### S := fj j9i;j = (i)g

|(s )|S; (s )||
|---|---|---|
|i i2[n]|i i2S||
|||OT S|

Figure 12: Uniform selection *k*-out-of-*n* OT protocol

S*u* in the *F* hybrid.*n*is the set of permutations over [*n*].

The following transformation allows to transform an OT where the receiver’s choice bit is chosen to an OT with a random choice bit. This transformation is very useful in the context of OT extension.

|Su|||S||||
|---|---|---|---|---|---|---|
|OT|i i2S|(i) i2S|OT U E OT OT|R OT|i i2S|OT Su|

Lemma A.15. S*u* *ofFigure 12realizes the ideal uniform selection sender chosen message OT* *F (Denition 2.4) with unconditional security in the F hybrid.*

Remark A.16. *The same transformation applies to F; F; F except* S *does not input any-* *thing to F* OT *.*

*sketch.* Consider a corrupt S. Due to S⁰ being uniformly distributed, so is S = (S⁰) since is one to one. Consider a corrupt R. The simulator receives S⁰ from R and the S*;* (*s*) from *F*. The simulator uniformly samples s.t. *fs g* = *fs g 0* and completes the protocol.

## B Lower Bound on the Round Complexity of Sender and Receiver Chosen Message Security

InLemma 3.8, we state that there cannot be an two message OT that achieves sender chosen message security where the sender sends its message rst. Here we give the proof.

*Proof.* We show that the most general notion of OT, one out of two OT is impossible. For a two message OT where the sender sends its message rst, the sender’s message mSis a function *f*Son input tSand some auxiliary input aux. A sender could sample *s₀;s₁* during the protocol or receive them as input. We use aux to cover the second case. Further, there is a function *f*Rthat takes the random tape tR S OT*;*S S R

|, m and choice bit b of R. Finally, there are two functions f|||||(t|; m; aux) that|
|---|---|---|---|---|---|---|
|S|||||OT;S S|R|
|OT;R|R S||||||
||||S||||
|m ;(t ;aux)|OT;S|S R|S|S S|||

outputs (*s₀;s₁*) and *f* (t*;* m*;b*) that outputs *sb*. First, we assume that S is committed to (*s₀;s₁*) given m, i.e. there is a (*s₀;s₁*) such that

<u>3</u> Pr [*f* (t*;* m*;*aux) = (*s₀;s₁*) *j* m = *f* (t*;*aux)] *:* R S4

In this case, a malicious receiver can break the security as follows. It selects two random tapes

|t, t, two choice bits b₁ = 0, b₂ = 1 and computes for all i 2 [2], m|||(t; m|;b ) and|
|---|---|---|---|---|
|R;1 R;2|||R R;i|S i|
|b ;i OT;R|R;i S i|;1 ;2|||

R*;i*= *f* *si*= *f* (t*;* m*;b*). It outputs (*s₀;s₁*) as a guess for *s₀;s₁*. Let the scheme be correct, for 1 negl. Then, the probability that the rst malicious receiver reconstructs (*s₀;s₁*) correctly is lower bounded using Jensen’s inequality by

Pr[(*s₀;;s₁;*) = (*s₀;s₁*)] *>;*

where (*s₀;s₁*) = *f*OT*;*S(tS*;* mR*;*aux). A malicious receiver interacting with the ideal OT can achieve this at most with probability <u>1</u> 2. Hence, there is a distinguisher that breaks the sender chosen message security of the OT. Now assume that for any (*s₀;s₁*),

<u>3</u> Pr [*f*OT*;*S(tS*;* mR*;*aux) = (*s₀;s₁*) *j* mS= *f*S(tS*;*aux)] *< :* (1) mR*;*tS 4

In this case, we show that a malicious receiver can tweak the distribution of *s₀;s₁*. The malicious receiver uses a hardwired pseudorandom function (PRF) key k for a PRF PRF that outputs a single bit. 7 The malicious receiver samples two random tapes tR*;*1, tR*;*2, two uniform choice bits *b₁*, *b₂*, computes for all *i 2* [2] mR*;i*= *f*R(tR*;i;* mS*;bi*) and *sbi;i*= *f*OT*;*R(tR*;i;* mS*;bi*). If PRFk(*sb*1*;*1) = 0 it sends mR*;*1to S and outputs *sb*1*;*1otherwise it sends mR*;*2to S and outputs *sb*2*;*2 We rst give a bound on the probability that PRFk(*sbi;i*) = 0. LetPRFbe a probability such that <u>1</u> Pr[PRFk(*sbi;i*) = 0] =PRF*:* 2 Then there is a distinguisher D that simply outputs 1 if PRFk(*sbi;i*) = 0. Hence,

*j*Pr[D(1*;sbi;i;*PRFk(*sbi;i*)) = 1] Pr[D(1*;sbi;i;u*) = 1]*j* =PRF*;*

where *u f* 0*;* 1*g*. Since D breaks PRF with probabilityPRFand PRF is secure,PRFis negligible. By (1), it holds with at least probability 16 <u>3</u> that *sb*1*;*1*6*= *sb*2*;*2. Therefore, the probability that for the output *sbi;i*of the malicious holds PRFk(*sbi;i*) = 0 is at least

Pr[PRFk(*sbi;i*) = 0] = Pr[PRFk(*sb*1*;*1) = 0] + Pr[PRFk(*sb*1*;*1) = 1 *^* PRFk(*sb*2*;*2) = 0] 1 1 3 1 PRF+ +PRF PRF 2 2 16 2 <u>1 1</u> = + negl*:* 2 64

Since the OT is = 1 negl correct, we get by using a union bound that the malicious receivers

|output s is correct and PRF|(s ) = 0 holds at least with probability|+ negl.|
|---|---|---|
|b ;i k b ;i|k b ;i|2 1 64 1|

*i i*Hence, PRF (*si*) = 0 holds with a noticeable bias-given k- when the malicious receiver interacts with an honest sender. If there is a distribution of (*s₀;s₁*) from which the ideal OT samples with the same bias, then there is a distinguisher D that breaks the security of PRF. D samples from this distribution, queries PRF on the samples and outputs 1 if the query returns 0. Since there is no such a distribution for a secure PRF, there is no adversary *A⁰* that creates the same output distribution when interacting with the ideal OT as when the malicious receiver interacts with the honest sender. Hence, the OT is not sender chosen message secure.

The following proof is the proof forLemma 3.9, which states that there cannot be an two message OT that achieves receiver chosen message security where the receiver sends its message rst.

*Proof.* Again, we rule out the most general notion of OT, one out of two OT. We follow a similar strategy as in the previous lemma. A two message OT where the receiver sends its message rst has the following structure. The receiver’s message mRis a function *f*Ron input tR, *b* and some

OT implies one-way functions and hence also PRFs.

auxiliary input aux. Further, there is a function *f*Sthat takes the random tape tSand mRas input. Finally, there are two functions *f*OT*;*S(tS*;* mR) that outputs (*s₀;s₁*) and *f*OT*;*R(tR*;* mS*;b;* aux) that outputs *sb*. We distinguish two cases. In case one, we assume that R is committed to *sb*given mR, i.e. there is a *sb*such that

<u>3</u> Pr [*f*OT*;*R(tR*;* mS*;b;* aux) = *sbj* mR= *f*R(tR*;b;* aux)] = +*;* mS*;*(tR*;b;*aux) 4

for 0. Further, *s* *b* should not be determined by mR. Let *‘* be the length of *s₀*, *s₁*, then if there is a *s* *b*

s.t.
<u>1</u> Pr[*s* *b* is output of *f*OT*;*S(tS*;* mR) for bit *b j* mR] = *‘* +*;* t S 2 then a malicious receiver can sample tSand compute *f*OT*;*S(tS*;* mR) to learn *s* *b* with probability <u>1</u> + (1), where OT is = 1 negl correct. Since the ideal primitive samples *s* at uniform, 2 *‘b* the malicious receiver breaks the OT with probability negl. Therefore, = negl. But now, a malicious sender can sample two random tapes tS*;*1, tS*;*2and compute for all *i 2* [2], (*s₀;i;s₁;i*) = *f*OT*;*S(tS*;i;* mR) and checks for all *i 2f*0*;* 1*g* whether *si;*1= *si;*2. It outputs a random *b⁰* if it holds for both or no *i 2f*0*;* 1*g*, otherwise it outputs *b⁰* such that *sb0;*1= *sb0;*2. It holds that

2 2 3 1 1 9 Pr[*sb;*1= *sb;*2] = + + *‘* 4 4 2 1 16

and 1 Pr[*s* *b;*1 = *s* *b;*2] *‘* *:* 2 Therefore,

Pr[*b* = *b⁰*] 1 =)

|Pr[@!i : s|= s|] + Pr[s|= s|^ s|6= s|] (1|
|---|---|---|---|---|---|---|
|‘|i;1 ‘|i;2|b;1|b;2 b;1 ‘|b;2||
|‘+1|‘+1|b;1|b;2|‘|b;1|b;2|
|‘|‘||||||
|‘+1|‘+1|||‘+1|||

2 2 1 2 2 2 1 Pr[*s* = *s*] + Pr[*s* = *s*] negl 2 2 2 2 1 2 9 1 1 1 1 + negl + + negl 2 2 16 2 32 2 4

where we apply a union bound to argue that the outputs are correct and corresponds to the receivers choice. Given that *‘* 1, the malicious sender guesses *b* correctly with at least probability 1 + 1 negl. Since in the ideal model, an adversary can guess *b* only with probability 1, this 2 32 2 constitutes a break of receiver chosen message security. In the case two, for any *sb*,

<u>3</u> Pr [*f*OT*;*R(tR*;* mS*;b;* aux) = *sbj* mR= *f*R(tR*;b;* aux)] *< :* mS*;*(tR*;b;*aux) 4

Similar as in the proof of Lemma3.8, we argue that a malicious sender can tweak the output distribution of (*s₀;s₁*). Due to the similarity, we only exhibit a brief version. Again we hardwire a PRF key k for a PRF with a single output bit. Given mR, the malicious sender samples two random tapes tS*;* S*;*, computes for all *i 2* [2] (*s₀;i;i* OT*;*S S*;i* R k*;;*

|and t||;s₀|) = f|(t; m ). If PRF|(s₀|;s₁ ) =|
|---|---|---|---|---|---|---|
|S;1||;i|;i OT;S|S;i R|k ;1|;1|
|;1 ;1|S S;1|R|||;2 ;2||

0 output (*s₀;s₁*) and send mS*;*= *f* (t*;* m) to R. Otherwise output (*s₀;s₁*) and send

Sender: Receiver(*i 2* [*n*]): *r* *i G* for *j* = 1 to *n* 1 *‘* *j*:= (*i* + *j* mod *n*) + 1 *8j 2* [*n*] : tA*;‘j f* 0*;* 1*g* t B*;j f* 0*;* 1*g* (*r*) mA*;‘j*A(tA*;‘j*) *j j2*[*n*]

|h = H|(r|)||r := m|H|(r )|
|---|---|---|---|---|---|---|
|j|j (j 2 mod n)+1|||‘|A;‘|‘ ‘|
|B;j|B;j j|j|B;j j2[n]||||
|B;j|B;j|j j||A;j|A B;j||

*j j* (*j* 2 mod *n*)+1 *‘j*A*;‘j‘j‘j* 1 m = B(t*;r h*) *8j 2* [*n*]

(m)
*8j 2* [*n*] *nfig* k = Key(t*;r h*) k := Key(t*;* m)

Figure 13: The gure shows a *n* 1 out of *n* OT using a UKA = (A*;* B*;*Key) and a random oracle

H : *G ! G*, where *G* is a group with operations,. By the correctness of the UKA scheme, kA*;i*= kB*;i*holds. The scheme can be transformed in the same way in a one-round scheme given a one-round UKA as in the 1 out of *n* OT case inSection 4.

mS*;*2= *f*S(tS*;*2*;* mR) to R. This way, Prk(*s₀;s₁*) = 0 holds for the malicious sender’s output (*s₀;s₁*) with probability

Pr[PRFk(*s₀;s₁*) = 0] = Pr[PRF

|(s₀ ;s₁|) = 0]|||
|---|---|---|---|
|k ;1|;1|||
|k|;1 ;1||k ;2 ;2|
|PRF||PRF|PRF|

+ Pr[PRF (*s₀;s₁*) = 1 *^* PRF (*s₀;s₁*) = 0] 1 1 3 1 + + 2 2 8 2 <u>1 1</u> = + negl*;* 2 32

unless one breaks the security of the PRF. As previously, this constitutes an attack against the receiver chosen message security.

## C All But One OT from Key Agreement

In this section we show how to use the techniques inSection 4to construct an all but one, i.e. *n* 1 out of *n*, OT. We show the protocol inFigure 13and give a state the achieved security inLemma C.1without giving a detailed proof. Security follows from the same reasoning as in Section 4.

Lemma C.1. *Given a correct and secure* UKA *scheme, then the n* 1 *out of n oblivious transfer* *inFigure 13is an Endemic* OT*n* 1*;nin the programmable random oracle model.*

*Proof.* The proof is very similar to the security proof of the 1 out of *n* OT. In fact, the proof is even simpler since the random oracle receives only a single *r* as input and for a malicious receiver, distinguishing a single string, i.e. k*i*, needs to be hard. This even removes some of the complexity of the previous proof. In the following, we state the claims, which only require minor adaptations to the claims of the previous proofs. For this reason, we do not give their proofs here. Security against a malicious sender follows by the claim below.

Claim C.2. *Given an uniform* UKA *scheme, then it holds that in the programmable random oracle* *model for any ppt adversary A, there exists a ppt adversary A’ such that for any ppt distinguisher* D *and any polynomial size auxiliary input z*

*j*Pr[D(*z;*(*A;* R)) = 1] Pr[D(*z;*(*A⁰; F*OT S )) = 1]*j ;*

*where all algorithms receive input* 1 *and* R *additionally receives input* S*.*

By a second claim, the protocol is secure against a malicious receiver.

Claim C.3. *Given a Q-multi-instanceu-uniform,* (*Q;* 1)*-multi-instancek-key-indistinguishable* UKA *scheme, where Q upper bounds the amount of random oracle queries by an adversary then it* *holds that in the programmable random oracle model for any ppt adversary A, there exists a ppt* *adversary A’ such that for any ppt distinguisher* D *and any polynomial size auxiliary input z*

*j*Pr[D(*z;* (S*; A*)) = 1] Pr[D(*z;*(*F*OT R *; A⁰*)) = 1]*ju*+*k;*

*where all algorithms receive input* 1 *and adversary A’ rewinds A Q times.*

## D Instantiations

In the following, we rst show how to eciently instantiate the construction inFigure 8using the Die-Hellman key exchange. In particular, we show how a tighter security reduction can be obtained using the random self-reducibility of the DDH assumption. InFigure 14, we give an optimized variant based on an interactive DDH assumption. Afterwards, we show how to instantiate the construction inFigure 8based on the lattice based Kyber key agreement. We emphasize that the instantiations only achieve stand alone security. For UC security, one needs to assume that CODDH and Kyber are secure against non-uniform adversaries. For the proof of UC security against a malicious receiver, seeAppendix E.

### D.1 Instantiation from DDH

Denition D.1 (*n*-Multi-Instance DDH Assumption). *For a group G, the* decisional Die-Hellman *assumption is hard if for any ppt distinguisher* D*,*

*j*Pr[D(J1K*;* J*~a*K*;* J*b*K*;* J*~ab*K) = 1] Pr[*D*(J1K*;* J*~a*K*;* J*b*K*;* J*~c*K) = 1]*j* = negl*;*

*where ~a* Z *n* *p, b* Z*pand ~c* Z *n*

*p.*
By a standard hybrid argument, *n*-multi-instance DDH is secure under the DDH assumption with a security loss of *n*. In the following we show that the Die-Hellman key exchange is tightly multi-instance secure under multi-instance DDH.

Lemma D.2. *Let Q and n be polynomial in. The Die-Hellman key exchange over G is uncon-* *ditionally Q-multi-instance uniform. Further, let the n-multi-instance DDH assumption hold over* *group G except with advantage, then the Die-Hellman key exchange is one-round* (*Q;n*)*-multi-* *instance key-indistinguishable except advantage* negl*.*

*Proof.* The distribution of J*a*K over *G* is uniform, therefore

*j*Pr[D *O*A (1 )K = 1] *Pr*[D *Ou* (1 ) = 1]*j* = 0*;*

even against an unbounded D. Hence, the Die-Hellman key exchange is unconditional *Q*-multi- instance uniform. For proving the second part of the lemma, we construct a ppt distinguisher D that breaks *n*- multi-instance DDH assumption given a ppt distinguisher Dkthat breaks the (*Q;n*)-multi-instance key-indistinguishability of the Die-Hellman key exchange. D receives a challenge J*~a*K*;* J*b*K*;* J*~c*K, sets mB:= J*b*K and invokes Dkon input mB. On the *j*-th query of Dkto *O*A, D samples *~rj*Z *n* *p* +1 and responds with mA*;j*:= J*h*(*~a;* 1)*;~rji*K=J*a₁*K *rj;*1+ J*a₂*K *rj;*2*:::* J*an*K *rj;n*+ J*rj;n*+1K. When Dkqueries *O*kfor key k*j*, D responds with k*j*:= J*h~c;~rji*K=J*c₁*K *rj;*1+ J*c₂*K *rj;*2*:::* J*cn*K *rj;n*+ J*b*K *rj;n*+1. In the end, D outputs the output of Dk. It is easy to see that *O*Ahas the correct output distribution. *rj;n*+1is uniform over Z*p*and hence mA*;j*is. Further, conditioned on mA*;j*, *rj;*1*;:::;rj;n*are uniform. Given that *~c* = *~ab*, the output

k*j*= J*h~c;~rji*K+J*b*K *rj;n*+1= J*h~ab;~rji*K+J*b*K *rj;n*+1= J*h*(*~a;* 1)*;~rji*K *b* = mA*;jb*

of *O*kis also distributed correctly. In case that *~c* is uniform, we need to show that all the *n* outputs of *O*k, *~*k = k₁*;:::;*k*n*are uniform. Let m*i*be the message mA*;j*and *~ti*the randomness *~rj*that corresponds to k*i*. Since *~c* is uniform and *~*k = J*~c T*K, where *T* is the matrix with *i*-th column *~ti*, *~* k is uniform if *T* is invertible. Since *rj;*1*;:::;rj;n*are uniform given mA*;j*so is *T*. For a uniform *T* over Z *n* *p* *n*, the probability that *T* is invertible is that all the rows are linear independent, i.e.

*n* Y¹*n* <u>1</u>*n i*<u>1</u> Pr[*T* invertible] = *n*2 (*p p*) 1 1 negl*:* *p p* *i*=0

Therefore, except with negligible probability, D has the same advantage in breaking *n*-multi-instance DDH as Dkhas in breaking one-round (*Q;n*)-multi-instance key-indistinguishability.

Using Theorem4.1and LemmaD.2, we obtain the following corollary.

Corollary D.3. *When instantiating an* 1 *out of n OT inFigure 8with Die-Hellman key ex-* *change over group G, then in the programmable random oracle model the resulting endemic OT is* *statistically secure against malicious senders and secure against malicious receivers except advan-* *tage* (*n* 1)DDH+ negl *and a runing time loss Q, where the DDH assumption over group G holds* *except advantage*DDH*and Q is a bound on the amount of adversarial random oracle queries.*

Remark D.4. *If we apply a hardcore predicate to* kA*and* kB*in the Die-Hellman key agreement* *and apply the transformationFigure 8, we receive a one-round endemically secure OT in the random* *oracle model based on the computational Die-Hellman assumption. Alternatively, one could also* *use the random oracle instead of a hardcore predicate to obtain longer OT strings.*

### D.2 Optimized, Interactive DDH based Instantiation

InFigure 14, we show an optimized variant of our OT. It reduces the communication cost from the sender to the receiver by sending only a single group element. This is possible since it does not depend on any of the *n* elements sent by the receiver. A drawback of this construction is that we do not know how to prove its security under the standard DDH assumption.

||Receiver(i 2 [n]): Sender: 8j 2 [n] nfig : r G j a Z b Z p p (r) j j2 [n]||
|---|---|---|
||r = J a K H ((r)) 8j 2 [n] i i j j6 = i b J b K s = J ab K s = (r H ((r))) A ;i j j B ;j ‘ ‘6 = j||
|while at the same time given J1K know how to simulate correctly. interactive decisional Die-Hellman|The gure shows an optimized variant of the protocol fromFigure 8based on an The reason is simple, in our security proof during the simulation, A⁰; J a⁰ K; J b K, J ab⁰ K needs to be hard to distinguish from a uniformly Since a is picked by the adversary A and only transmits J The next denition formally states the assumption under which the protocol inFigure 14can be proven to be secure. Denition D.5 (Interactive Decisional Die-Hellman (IDDH) Assumption). assumption is hard if for any ppt distinguisher j Pr[D₂ (st; J1K; J a K; J xb K; J ab K) = 1] Pr[D₂ (st; J1K; J a K; J xb K; J c K) = 1] j = negl; Z and c Z and (st; J x K) D₁ (J b K). p p Instantiation based on Crystals-Kyber A: B: m A 32 (sk; m) Kyber : KeyGen() k B A B m B||
|k|m = Kyber : Enc(pk; k) B B = Kyber : Dec(sk; m) k A B B||
|= 256;|Figure 15: The gure shows a Kyber based key agreement protocol between parties A and B. (Crystals-Kyber CPAPKE). Crystals-Kyber CPAPKE secure public key encryption based on the Module LWE (MLWE cations of Kyber, in which B denotes the set f 0; 1 ;:::; 255 g. Kyber is parameterized by parameters n LWE, k 2f 2; 3; 4 g, q = 7681 and ring R = Z [X] = (X q q LWE Kyber : Enc; Kyber : Dec) have the following syntax.|) assumption. We follow the speci- + 1) k|

Figure 14:

interactive DDH assumption.

### needs compute the key JabK

random group element. *a*K, we do not

*For a group G, the* D₁*;*D₂*,*

### where a Zp, b

D.3
Denition D.6 *is a correct and CPA*

*dt*= 11*, n*LWE*.* (Kyber*:* KeyGen

<u>LWEnLWEdt</u>32 Kyber*:* KeyGen: *Outputs a secret and public key pair* pk*;*sk*, where* pk = (~t*;*) *2B*8*B.*

Kyber*:* Enc: *Takes as input a public key* pk*, a message* m *2 B³² and random coins* t *2 B³². It* *outputs a ciphertext* c*.*

Kyber*:* Dec: *Takes as input secret key* sk *and a ciphertext* c*. It outputs a message* m*.*

### Further, Crystals-Kyber species the following algorithms.

Decode*‘*: *Takes a an element in B³²* *‘* *and maps it to Rq. The inverse operation is* Encode*‘.*

Compress*q*(*;d*): *Takes a an element in Rqand maps it to a polynomial with coecients in* Z₂*d.* *The inverse is* Decompress*q*(*;d*)*.*

Parse: *Takes a uniform byte stream in B and maps it to a uniform element in Rq.*

It is important to know, that ~t := Encode*dt*(Compress*q*(t*;dt*), where t is computationally indis- tinguishable from a uniform element in *R* *k* *q* LWEbased on the MLWE assumption. In the following, we will choose *dt*= 13 such that *q <* 2 *d* *t*and no compression takes place. This will help us to avoid complications and does not decrease eciency besides a slightly larger public key pk. Further, we will keep component of pk consistent between all pk used in a single 1 out of *n* OT. In order to instantiate our framework, we need to dene a group operation pk pk and a hash functions that maps to a uniform ~t component of pk, i.e. a uniform element in *R* *k* *q* LWE. For the latter, we use a hash function that produces an output bit stream, which is in *B*, and use *k*LWE dierent parts of the stream and apply Parse to the *k*LWEstreams to obtain a (pseudo) uniform element in *R* *k* *q* LWEwhenever the bit streams are (pseudo) uniform. We dene the group operation pk₁ pk₂, by mapping pk₁ = (~t₁*;*), pk₂ = (~t₂*;*) to pk₃ = (~t₃*;*), where ~t₃ = Encode₁₃(Decode₁₃(~t₁) + Decode₁₃(~t₂)) and + is the addition in *R* *k* *q* LWE. is dened correspondingly. By usingTheorem 4.1,Lemma A.7andLemma A.8, we get the following corollary.

Corollary D.7. *When instantiating an* 1 *out of n OT inFigure D.3with Crystals-Kyber, then* *in the programmable random oracle model the resulting endemic OT is secure against a malicious* *sender except advantage* (*n* 1)MLWE+negl *and secure against malicious receivers except advantage* *Q*MLWE+negl *and a runing time loss Q, where the* MLWE *assumption holds except advantage*MLWE *and Q is a bound on the amount of adversarial random oracle queries.*

In this work, we will instantiate Kyber with *k* = 3 which is claimed to have a qbit security level of 161 bit. This security level does not immediately carry over to our Kyber based OT, there is an additional security loss of *Q²*. Though we are unaware of an attack that is signicantly more ecient on our Kyber based OT than the attacks on Kyber.

## E UC Security against Malicious Receivers

InTheorem 4.1inSection 4, we only show stand-alone security. While UC security for a malicious sender is already covered byClaim C.2,Claim C.3uses an adversary *A*’ that rewinds *A* and hence does not accomplish UC security. Here, we proof UC security against a malicious receiver for two settings. First, in case of a two-round OT from any uniform two-round key agreement. Second, in case of a one-round OT based on the Die Hellman key agreement under a variant of DDH.

### E.1 UC Security of the Two-Round OT

Claim E.1. *Given a Q-multi-instanceu-uniform,* (*Q;n* 1)*-multi-instancek-key indistinguish-* *able two-round* UKA *scheme, where Q upper bounds the amount of random oracle queries by an* *adversary. Then the proposed two-round OT is UC-secure against malicious receivers, i.e. in the* *programmable random oracle model for any ppt adversary A, there exists a ppt adversary A’ such* *that for any ppt distinguisher* D *and any polynomial size auxiliary input z,*

*j*Pr[D(*z;* (S*; A*)) = 1] Pr[D(*z;*(*F*OT E *; A⁰*)) = 1]*j Qu*+ *Qk;*

### where all algorithms receive input 1.

*Proof.* We follow the same line of arguement as inClaim C.3with the exception that we now use a hybrid argument rather than guessing the correct random oracle query. A malicious receiver will make random oracle queries and each query will correspond to a potential choice for (*ri*)*i2*[*n*]. For each potential choice of (*ri*)*i2*[*n*]there will be corresponding OT strings, i.e. keys computed by the key agreement. During the rst hybrid, we replace the corresponding keys of the rst random oracle query with uniform. Through a sequence of hybrids, we will do this for every query until all the keys are replaced with uniform. Notice that in each hybrid, D will only get to see the key that corresponds to the malicious receivers choice of (*ri*)*i2*[*n*]and not for all potential choices of (*ri*)*i2*[*n*]. We start by giving a description of *A*’. For each random oracle query *q* to H*i*for an *i 2* [*n*], *A*’ responds with a random group element H*i*(*q*) *G*. When *A* sends (*ri*)*i2*[*n*], *A*’ looks up the rst

|oracle query of the form q = (r₁;:::;r|||;r|;:::;r|) for an i||2 [n]. A’ sends i||to F. A’|
|---|---|---|---|---|---|---|---|---|---|
|||A;i|i 1 i i|i +1 ‘ ‘6=i|n B;i||B;i|B;i|OT E A;i|
||B;i|B;i A;i B;i|A;i|B;i|OT E|B;i i2[n]|OT E||B;i i6=i|
|||||||||Q+1||
|d k 2|d 1 d+1|n||i i2[n]||||||

*i* 1 *i* +1 *n* E computes for all *i 2* [*n*] m := *r* H ((*r*)), t *f* 0*;* 1*g* and m B(t*;* m). It also computes *s* := Key(t*;* m). *A*’ sends *s* to *F*, (m) to *A* and outputs the output of *A*. This concludes the description of *A*’. We emphasize that here, the other OT strings (*s*) will not be the output of Key(t*;* m) but sampled uniformly by *F*. We now dene a sequence of hybrids. The rst hybrid is hyb₁ and corresponds the interac- tion of *A* with the sender of the protocol description. The last hybrid, hyb₃, corresponds to simulator *A⁰*. Let us dene the *critical query* with index *j 2* [*Q*] as the rst query of the form *H* (*r₁;:::;r;r;:::;r*) where *A* sends (*r*). For *k 2* [*Q* + 1], we dene:

hyb₃ : In this hybrid the simulator *A⁰* does not program the random oracle and outputs uniform OT messages as the ideal functionality would if *j < k*. In more detail, *A⁰* does the following:

When *A* makes an oracle query *qj*respond normally with a random group element H*i*(*qj*) *G*.

|When A sends (r|), look up the the critical query of the form q||||= (r₁;:::;r||;r ;:::;r|)|
|---|---|---|---|---|---|---|---|---|
||i i2[n]||||j|d|1 d+1|n|
|d||||||A;i i|i ‘ ‘6=i||
|B;i|B;i|B;i|A;i i||B;i|B;i A;i i|B;i||
|B|d 1 B;d|d+1|n|B;i i2[n]||B|||

*i i2*[*n*] *j d* 1 *d*+1 *n* to H for a *d 2* [*n*]. Let *j* be the query index. Compute for all *i 2* [*n*], m := *r* H ((*r*)), t *f* 0*;* 1*g* and m B(t*;* m). Further, compute *s* := Key(t*;* m).

If *j < k*, sample for all *i 6*= *d*, *s* uniformly. Otherwise, for all *i 6*= *d*, *s* := *s*. Dene S := (*s₁;:::;s;s;s;:::;s*). Send (m) to *A* and output S together with the output of *A*.

hyb₃*k* 1: In this hybrid *A⁰* programs the oracle to prepare a switch to uniform keys when *j* = *k*. In particular, the hybrid is:

When *A* makes an oracle query *qj*respond normally with a random group element H*i*(*qj*) *G* except for the following queries. Let us dene *i ;*(*g₁;:::;g* *i* 1 *;g* *i* +1 *;:::;gn*) := *qk*s.t. the *k*’th oracle query *A* makes is H*i*(*qk*). For all following random oracle queries *Hi*(*qj*) and *i 6*= *i* s.t. *qj2f*(*g₁;:::;g* *i* 1 *;g;g* *i* +1 *;:::;gn*)*ng* *i* *j g 2 Gg*, sample random tape t*j f* 0*;* 1*g* and compute m*j*A(t*j*). Respond abnormally with H*i*(*qj*) := m*jg* *i*. Here we dene (*g₁;:::;g* *i* 1 *;g;g* *i* +1 *;:::;gn*) *n g* *i* as the ordered sequence with the element *g* *i* removed.

|When A sends (r|)|, look up the the critical query of the form q|||= (r₁;:::;r||;r|;:::;r )|
|---|---|---|---|---|---|---|---|---|
||i i2[n]||||j||d 1 d+1|n|
|d||||||A;i|i i|‘ ‘6=i|
|B;i|B;i|B;i|A;i i||B;i|B;i A;i i|B;i||
|B|d 1 B;d|d+1|n|B;i i2[n]||B|||

to H for a *d 2* [*n*]. Let *j* be the query index. Compute for all *i 2* [*n*], m := *r* H ((*r*)), t *f* 0*;* 1*g* and m B(t*;* m). Further, compute *s* := Key(t*;* m).

If *j < k*, sample for all *i 6*= *d*, *s* uniformly. Otherwise, for all *i 6*= *d*, *s* := *s*. Dene S := (*s₁;:::;s;s;s;:::;s*). Send (m) to *A* and output S together with the output of *A*.

hyb₃*k*: In this hybrid *A⁰* replaces the true key exchange keys for query *k* with the uniform challenges. This change is only observable if *j* = *k*. In particular, the hybrid is: When *A* makes an oracle query *qj*respond normally with a random group element H*i*(*qj*) *G* except for the following queries. Let us dene *i ;*(*g₁;:::;g* *i* 1 *;g* *i* +1 *;:::;gn*) := *qk*s.t. the *k*’th oracle query *A* makes is H*i*(*qk*). For all following random oracle queries *Hi*(*qj*) and *i 6*= *i* s.t. *qj2f*(*g₁;:::;g* *i* 1 *;g;g* *i* +1 *;:::;gn*)*ng* *i* *j g 2 Gg*, sample random tape t*j f* 0*;* 1*g* and compute m*j*A(t*j*). Respond abnormally with H*i*(*qj*) := m*jg* *i*. Here we dene (*g₁;:::;g* *i* 1 *;g;g* *i* +1 *;:::;gn*) *n g* *i* as the ordered sequence with the element *g* *i* removed.

|When A sends (r|)|, look up the the critical query of the form q|||= (r₁;:::;r||;r|;:::;r )|
|---|---|---|---|---|---|---|---|---|
||i i2[n]||||j||d 1 d+1|n|
|d||||||A;i|i i|‘ ‘6=i|
|B;i|B;i|B;i|A;i i||B;i|B;i A;i i|B;i||
|B|d 1 B;d|d+1|n|B;i i2[n]||B|||

to H for a *d 2* [*n*]. Let *j* be the query index. Compute for all *i 2* [*n*], m := *r* H ((*r*)), t *f* 0*;* 1*g* and m B(t*;* m). Further, compute *s* := Key(t*;* m). If *j k*, sample for all *i 6*= *d*, *s* uniformly. Otherwise, for all *i 6*= *d*, *s* := *s*. Dene S := (*s₁;:::;s;s;s;:::;s*). Send (m) to *A* and output S together with the output of *A*.

Claim E.2. *For any k 2* [*Q* + 1]*, let there be a distinguisher* D *and a polynomial size auxiliary* *input z with* D:= *j*Pr[D(*z;* hyb₃*k* 2) = 1] Pr[D(*z;* hyb₃*k* 1) = 1]*j:* *Then, there is a distinguisher* D*ubreaking the Q-multi-instance uniformity of the* UKA *protocol.*

*Proof.* D*u*gets access to an oracle *O* which either outputs uniform messages, i.e. *Ou*or messages of the form mAA(tA) for tA *f* 0*;* 1*g*. D*u*invokes D and creates its input as follows. It invokes *A* and interacts with him as hyb₃*k* 1does with the dierence that m*j*are requested from *O* rather than computing them. After receiving the output, D*u*uses it as input for D together with (*s*B*;i*)*i2*[*n*], where *s*B*;i*Key(tB*;i;* mA*;i*). D*u*outputs the output of D. If *O* is oracle *Ou*, all m*j*are uniform and hence all random oracle queries *q* are answered with a uniformly random H*i*(*q*) *2G*. Otherwise, *A*’ is identical with S as well as (*s*B*;i*)*i2*[*n*]are identical with the output of S. Hence

= *j*Pr[D *O*A

(*z*)] = 1] *Pr*[D
*Ou*

(*z*) = 1]*j*
*u u u* = *j*Pr[D(*z;* ((*s*B*;i*)*i2*[*n*]*; A*) *O*A) = 1] D*u* Pr[D(*z;* ((*s*B*;i*)*i2*[*n*]*; A*) D *Ou*) = 1]*j* *u* D*:*

Claim E.3. *For any k 2* [*Q* + 1]*, let there be a distinguisher* D *and a polynomial size auxiliary* *input z with* D:= *j*Pr[D(*z;* hyb₃*k* 1) = 1] Pr[D(*z;* hyb₃*k*) = 1]*j:* *Then there is a distinguisher* D*kthat breaks the* (*Q;n* 1)*-multi-instance key-indistinguishability* *of the* UKA *protocol.*

*Proof.h*A*;*B*i*and *O* which is either *O* invokes D and creates

|D has access to oracles O|||or O|. D|
|---|---|---|---|---|
|k|k j|A;j B;j|u k+2|k k hA;Bi|
|i i2[n]||k 1||k|
||k 1||||

its input as follows. D invokes *A* and interacts with it as hyb₃ does with the dierence, that D*k*generates m by querying a transcript *h*A*;* B*i* = (m⁰*;*m⁰) from *O* and setting m*j*= m⁰ A*;j*. If (*r*) corresponds to a query *j 6*= *k*, then hyb₃ and hyb₃ are equivalent. Follow the description of hyb₃ and ignore oracle *O*, since the keys for the challenge transcripts are not needed.

If (*r*) corresponds to query *k*, compute for all *i 2* [*n*] *nfi g*

|i i2[n]|||
|---|---|---|
||A;i i|i ‘ ‘6=i|

m := *r* H ((*r*)) = m⁰A*;j*

where there exists a *j 2* [*Q*] such that the last equality holds. It also uses oracle *O* to query for all *i 2* [*n*] *nfi g* the *n* 1 corresponding keys k*i*that match with the transcripts containing mA*;i*. D*k*sets mB*;i*:= m⁰ B*;j* and *s*B*;i*:= k*i*. It creates mB*;i*and *s*B*;i*as usual. It sends (mB*;i*)*i2*[*n*]to *A* to receive its output which it uses together with (*s*B*;i*)*i2*[*n*]as input for D. D*k*outputs D’s output.

*Ok Ou*

||= j Pr[D|(z)] = 1]||Pr[D (z) = 1]j||
|---|---|---|---|---|---|
|k||k|B;i i2[n] B;i|k D D||
||D|||||

*k k k* = *j*Pr[D(*z;* ((*s*)*; A*) *Ok*) = 1] *k* *Pr*[D(*z;* (S*; A*) *Ou*) = 1]*j* *k* *:*

Claim E.4. *For any k 2* [*Q*]*, let there be a distinguisher* D *and a polynomial size auxiliary input* *z with* D:= *j*Pr[D(*z;* hyb₃*k*) = 1] Pr[D(*z;* hyb₃*k*+1) = 1]*j:* *Then, there is a distinguisher* D*ubreaking the Q-multi-instance uniformity of the* UKA *protocol.*

*Proof.* The proof is almost identical to the proof ofClaim E.2and therefore omitted.

### We obtain

= *j*Pr[D(*z;* (S*; A*)) = 1] Pr[D(*z;*(*F* E *; A*)) = 1]*j* OT OT 2*Qu*+ *Qk:*

Remark E.5. *For stand alone security, security of* UKA *against uniform adversaries is sucient,*

*i.e. auxiliary input z is the empty string. Further, for UC security in the global random oracle* *model, it is sucient for the sender to send a salt at the start of each session that is used as an* *additional input to the random oracle within the session.*
E.2 Die-Hellman based One-Round Endemic OT with UC Security Denition E.6 (Choose-and-Open Decisional Die-Hellman (CODDH) Assumption). *For a group* *G, the* choose-and-open decisional Die-Hellman *assumption for parameters k;m is hard if for any* *ppt distinguisher* D₁*;*D₂ *and any polynomial size auxiliary input z,*
*j*Pr[D₂(st*;* (*a*

||); (Ja|b K)|) = 1]|
|---|---|---|---|
||j j2K j j2K|j j j62K j j62K||
|j j j|||j j j2[m]|

Pr[D₂(st*;* (*a*)*;*(J*c* K)) = 1]*j* = negl*;*

*where for j 2* [*m*]*, a;b;c* Z*pand* (st*;K*) D₁(*z;* J1K*;*(J*a* K*;* J*b* K)) *with K* [*m*]*, jKj* = *k.*

Lemma E.7. *Let the Choose-and-Open DDH assumption for parameters k* = *n, m* = 2*n (Def-* *inition E.6) hold over group G. Then the one-round Die-Hellman based protocol onFigure 8* *satises malicious receiver security (Denition 2.6) in the UC model with respect to the 1-out-of-n* *F* OT E *functionality.*

*Proof.* The dierence to the previous regimes is that now the simulator *A⁰* and sender will send their message before seeing the adversaries rst message. The simulator for the malicious receiver is still straight forward. It sends the rst message according to protocol. As previously, he will extract the receiver’s input after seeing the malicious receveirs response (*ri*)*i2*[*n*]. The input will be the index *ii*

|of random oracle H|for which the malicious receiver makes the rst query of||
|---|---|---|
||i||
|i 1 i +1|n||

the form (*g₁;:::;g;g;:::;g*). The simulator sends the choice bit and all keys to the ideal functionality, where only the *i* th key will be computed according to the protocol, all other keys are uniformly random. As in the previous regime, we dene a sequence of hybrids. We now dene a sequence of hybrids. The rst hybrid is hyb₁ and corresponds the interaction of *A* with the sender of the protocol description. The last hybrid, hyb*Q*+1, corresponds to simulator *A⁰*. Since the messages in the Die-Hellman key agreement are statistically close to uniform, we need less hybrids. Let us dene the *critical query* with index *j 2* [*Q*] as the rst query of the form *Hd*(*r₁;:::;rd* 1*;rd*+1*;:::;rn*) where *A* sends (*ri*)*i2*[*n*]. For *k 2* [*Q* + 1], we dene:

hyb*k*: In this hybrid the simulator *A⁰* outputs uniform OT messages as the ideal functionality would if *j < k*. In more detail, *A⁰* does the following:

*A⁰* sends (J*aj*K)*j2*[*n*]to the malicious receiver as its OT message. When *A* makes an oracle query *qj*, respond with a random group element H*i*(*qj*) *G*. When *A* sends (*ri*)*i2*[*n*], look up

|||= (r₁;:::;r|;r|;:::;r ) to H|for a d 2 [n]. Let j||
|---|---|---|---|---|---|---|
|||j i|d 1 d+1 B;i i|n i i|d ‘ ‘6=i|i B;i|
|d 1|B;d d+1|n|B||||

the the critical query of the form *qj d* 1 *d*+1 *n d* be the query index. Compute for all *i 2* [*n*], *s* := *a* (*r* H ((*r*))).

If *j < k*, sample for all *i 6*= *d*, *s* uniformly. Otherwise, for all *i 6*= *d*, *s* := *s*. Dene SB:= (*s₁;:::;s;s;s;:::;s*). Output S together with the output of *A*.

Claim E.8. *For any k 2* [*Q* + 1]*, let there be a distinguisher* D *and a polynomial size auxiliary* *input z with* D:= *j*Pr[D(*z;* hyb*k*) = 1] Pr[D(*z;* hyb*k*+1) = 1]*j:*

*Then there is a distinguisher* D⁰ *that breaks CODDH for parameter k* = *n, m* = 2*n.*

*Proof.* First, D⁰ receives challenge J1K*;*(J*ai*K*;* J*bi*K)*i2*[*m*]. He sends (J*ai*K)*i2*[*n*]to the malicious receiver as its OT message ((J*ai*K*;* J*bi*K)*i2*[*m*]*n*[*n*]are ignored). He programs the random oracle similar as in the proof ofClaim E.1. I.e. when *A* makes an oracle query *qj*respond normally with a random group element H*i*(*qj*) *G* except for the following queries. Let us dene *i ;*(*g₁;:::;g* *i* 1 *;g* *i* +1 *;:::;gn*) := *q* *k*s.t. the *k*’th oracle query *A* makes is H*i*(*qk*). For all following random oracle queries *Hi*(*qj*) and *i 6*= *i* s.t. *qj2f*(*g₁;:::;g* *i* 1 *;g;g* *i* +1 *;:::;gn*) *n g* *i* *j g 2 Gg*, sample*j*Z*p*and respond with H*i*(*qj*) := J*bi*K*jg* *i*. Here we dene (*g₁;:::;g* *i* 1 *;g;g* *i* +1 *;:::;gn*) *n g* *i* as the ordered sequence with the element *g* *i* removed. After A sends (*ri*)*i2*[*n*], D’ checks whether it corresponds to query *k*. If not, D’ requests (*ai*)*i2*[*n*] and continues as the honest server. If (*ri*)*i2*[*n*]corresponds to oracle query *k*, D’ requests *ai*, challenges J*ci*K*i2*[*n*]*nfi g*and computes *s*B*;i*according to protocol. For all *i 6*= *i*, *si*:= J*ci*K*j*, where *j*was sampled when query (*r‘*)*‘6*=*i*was made to the random oracle, i.e. the *j*th query for some *j 2* [*Q*]. D’ outputs SB:= (*s₁;:::;sd* 1*;s*B*;d;sd*+1*;:::;sn*) and the output of A to D. Clearly, since for all *j 2* [*Q*],*j*is uniform, *Hi*(*qj*) for the corresponding *i 2* [*n*] is uniform as well. When *ci*is uniform, so will be *si*and thus it is distributed as the ideal functionalities output. When *ci*= *aibi*, *si*= J*ci j*K = *ai*J*bi j*K = *ai*(*ri*+ H((*rj*)*j6*=*i*))

and thus distributed as the OT strings computed by the honest sender.

For the last step, we need to replace *s*B*;i*with *s*A*;i*. We use the same argument as in ClaimC.2 using the correctness of the scheme. Hence we obtain

= *j*Pr[D(*z;* (S*; A*)) = 1] Pr[D(*z;*(*F* E *; A*)) = 1]*j* OT OT *Q* + (1)*;*

where*k*is the advantage for breaking CODDH for parameters *k*, *m*.

## F OT Extension

### F.1 Protocol Diagrams

### F.2 Proof ofLemma F.1(Attack of

OOS )

Lemma F.1. *There exists a ppt adversary A and distinguisher* D *s.t. 8A⁰*

*j*Pr[D((S*; A*) *OOS*) = 1] Pr[D((*F*OT U *; A⁰*)) = 1]*j* = 1 2

*where* *OOS* *is the protocol inDenition 5.1. All algorithms also receive input* 1*.*

*Proof.* For simplicity let *N* = 2 and *m* = 1. We dene *A* as follows. *A* plays the role of R and *j j m0* replaces the input to base OTs, the sender input, with strings *t₀; t₁ 2f*0*g* and then completes the protocol as normal. We dene D as follows. D executes S and *A* with input *x₁* = 1. S outputs (*v₁;*1*; v₁;*2) and D outputs 1 if *v₁;*1= H(1*; f*0*g* *nC* ) and 0 otherwise. In the real interaction it clearly holds that Pr[D((S*; A*) OOS) = 1] = 1. In the ideal interaction the honest S will output a uniformly distributed

|and therefore Pr[D((F||; A⁰)) = 1] = 2|.|
|---|---|---|---|
|OT U||OT U||
||OOS+|||

*v₁;*1*2f*0*;* 1*g* which was sampled by *F*

### F.3 Proof ofLemma F.2(Attack of)

Lemma F.2. *There exists a ppt adversary A and distinguisher* D *s.t. 8A⁰*

*j*Pr[D((S*; A*) *OOS+*) = 1] Pr[D((*F*OT U *; A⁰*)) = 1]*j* = 1 2

*where* *OOS+* *is the protocol inDenition 5.4and all algorithms additionally receive input* 1*.*

*Proof.* For simplicity let *N* = 2 and *m* =. We dene *A* as follows. *A* plays the role of R and *j j m0* receives the strings *t₀; t₁ 2f*0*g* from *F*OT. *A* redenes the selection values *x₁;:::;xm2* [2] of R such that *xi*:= lsb(H(*i; ti*)) + 1. That is, *xi*equals the least signicant bit of *vi;xi*= H(*i; ti*) plus

1. *A* executes the rest of the protocol as R would and outputs (*xi*)*i2*[*m*]. We dene D as follows. D executes S and *A*. S outputs (*vi;*1*; vi;*2)*i2*[*m*]and D outputs 1

|if 8i 2 [m]; lsb(v|) + 1|= x and 0 otherwise.||||
|---|---|---|---|---|---|
||i;x|i||||
|i;1 i;2|||i|OT U||
||||OOS+|||

*i;xii*In the real interaction it clearly holds that Pr[D((S*; A*) OOS+) = 1] = 1. In the ideal interaction the honest S will output a uniformly distributed *v; v 2f*0*;* 1*g* which are independent of *x* and therefore Pr[D((*F; A⁰*)) = 1] = 2.

### F.4 Proof ofLemma F.3(Attack of)

Lemma F.3. *There exists a ppt adversary A and distinguisher* D *s.t. 8A⁰*

*j*Pr[D((*A;* R) *OOS+*) = 1] Pr[D((*A⁰; F*OT E )) = 1]*j* = 1 negl

*where* *OOS+* *is the protocol inDenition 5.4and all algorithms additionally receive input.*

ext-S R S ext-S R S : *F* *;* FS, RO*!F* : *F* *;* RO*!F* OT OT OT OT mA mA mB mB *U;ZKP*(H(*U*))

|U;ZKP (H(U ))|U|
|---|---|
|k|c;k ZKP (c)|
|: F; FS, RO !F|: F ;RO !F|
|m|m|
|m ;U;ZKP (H(U )); u-select.|m ;U; u-select.|

*U*

ext-R S*u* R ext-R S*u* R OT OT OT OT A A B B *c* *ZKP*(*c*)

ext-U S*u* U ext-U S*u* U : *F* *;* FS, RO*!F* : *F* *;*RO*!F* OT OT OT OT mA*;*Com(*k*) mA*;*Com(*k*) mB*;U;ZKP*(H(*U*))*; u*-select. mB*;U; u*-select.

|m ;U;ZKP (H(U )); u-select.|m ;U; u-select.|
|---|---|
|Decom(k)|c; Decom(k) ZKP (c)|
|: F; FS, IC !F|: F; IC !F|
|m|m|
|m|m|
|U;ZKP (H(U )).|U.|
|k|c;k ZKP (c).|
|: F; FS, IC !F|: F; IC !F|
|m; Com(u)|m; Com(u)|
|m|m|
|Decom(u);U;ZKP (H(U )); u-select.|Decom(u);U; u-select.|

ext-S R S ext-S U*u* R OT OT OT OT A A B B

ext-R U*u* R OT OT A B

ext-U : *F* U*u* *;* FS, IC*!F* U OT OT mA*;*Com(*u*) mB*;*Com(*k*) Decom(*u*)*;U;ZKP*(H(*U*))*; u*-select.

ext-R U*u* R OT OT A B

*c* *ZKP*(*c*)

ext-U : *F* U*u* *;* IC*!F* U OT OT mA*;*Com(*u*) mB*;*Com(*k*) Decom(*u*)*;U; u*-select.

|Decom(u);U;ZKP (H(U )); u-select.|Decom(u);U; u-select.|
|---|---|
|Decom(k)|c; Decom(k)|

*ZKP*(*c*)

are the rst and second messages of the base OTs. *U* is the OT extension matrix. *ZKP*(*x*) is the

Figure 16: Messages ow for our various OT extension protocols. The protocols on the left have

the Fiat-Shamir transformation applied, where the challenge value *c* is replaced with H(*U*). mA*;* mB

proof that *U* is correct given a challenge value of *x 2f*H(*U*)*;cg*. *u* is a seed used to randomized the sender or receiver chosen message OTs into uniform message OTs. *u* must be committed to in the rst round. *u*-select similarly transforms the receiver’s selection into a uniform selection. *k* is the key used to generated the output messages as described inSection 5.

*Proof.* For simplicity let *N* = 2 and *m* =. We dene *A* as follows. *A* plays the role of S and replaces the input to *F* OT S, the receiver input, with the string *b* := *f*0*g* *nC*. *A* outputs the matrix *Q*. We dene D as follows. D samples the selection bits *x₁;:::;xm*[2] and sends them to R. D executes *A* who outputs *Q* and R outputs *v₁;x*1*m;xm i;xi i*

|||;:::; v. If v|= H(i; q|) for all i 2 [m], output|||
|---|---|---|---|---|---|---|
|||m;x|i;x|i|||
|||i|||OT E|i i|
|;i i2[m]|||OT R||||
||U||||||
||OT||||||

1, otherwise 0. In the real interaction it clearly holds that Pr[D((*A;* R) OOS+) = 1] = 1 since *q* = *t*. By denition the input of *A⁰* is independent of *x* and receives no output from *F* (apart from their input (*v₀;i; v₁*)). Therefore, it must hold that Pr[D((*A⁰; F*)) = 1] = 2.

F.5 Proof ofLemma F.7: *F* Extension with a Random Oracle *Proof.* Claim F.4 (Malicious Sender Security).
*ext-Su*+ *satises security against a malicious sender* *(Denition 2.6) with respect to the F* OT U *oracle.*

*Proof.* The simulation follows the same strategy asLemma 5.15except now *A* is allowed to sample *k* and have the parties output messages of the form *vi;x*:= H(*i;k*+ *ti*+ *b* (*ci*+ *C*(*map*(*x*)))). The simulator *A⁰* samples *ti*uniformly at random after *A* is bound to their choice of *k* and therefore its easy to verify that *A* has negligible probability of querying H on such an input before receiving

*k*. Claim F.5 (Malicious Receiver Security).
*ext-Su*+ *satises security against a malicious receiver* *(Denition 2.6) with respect to the F* OT U *oracle.*

*Proof.* The simulation also follows the same strategy asLemma 5.15with a few key dierences.

1. *A⁰* sends a dummy commitment in place of the commitment to *k*, i.e. a uniform string from the same distribution.
2.Then *A⁰* runs the normal simulation described byLemma 5.15up to the point that S would decommit to *k* except that *A⁰* does not program H as described.
3.At this point *A⁰*

|has received U|in stepStep 2and A send a valid proof forStep 4(by||
|---|---|---|
|0|0||
|i;x|0 i|n|
|||n|

*nC* assumption or *A* would have aborted). *A* now uniformly samples *k* F₂ and programs the commitment random oracle to decommit to *k*. *A⁰* then programs H⁰ to output the ideal *C* output *vi*of R for the query H (*i;k*+ *t*). Since *k 2* F₂ is uniformly distributed in the view of *A*, it follows that *A* has probability at most *q*2*Cq*2 = negl probability of querying the oracle at this point, where *q* is the number of queries that *A* has made.

4. *A⁰* then sends the decommits of *k* to *A* and completes the simulation asLemma 5.15does.
### F.6 Proof ofLemma F.7: F

OT S Extension with an Ideal Cipher

|ext-S||OT|OT R|
|---|---|---|---|
|ext-E||||
|||n||
||k|||

Denition F.6. *Let* *ext-S* *be the protocol ofFigure 9where F* := *F* R *and the random oracle* H(*i;x*) *required by* *is replaced as follows: afterStep 4,* S *samples k f* 0*;* 1*g and sends it to* *C*

R*. Both parties dene* H(*x*) = (*x*) + *x where* : *f*0*;* 1*g* F₂*!f*0*;* 1*g is an ideal cipher. Note:* *the i parameter of* H *is removed.*

Lemma F.7. *The* *ext-S* *protocol realizes 1-out-of-N F* OT S *-security, for N* = *poly*()*. Against a* *malicious* R*,* *ext-R* *realizes F* OT U *-security. That is, the input messages of an honest* S *are sampled* *uniformly from f*0*;* 1*g by the protocol.*

*Proof.*

Claim F.8 (Malicious Sender Security). *ext-R* *satises security against a malicious sender (Def-* *inition 2.6) with respect to the F* OT S *functionality.*

*Proof.* The simulation follows essentially the same strategy asLemma 5.8. Consider the following hybrids which will dene the simulator *A⁰*.

Hybrid 1.OT

|A⁰ internally runs A while plays the role of R and base OT oracle F||||||= F|.|For|
|---|---|---|---|---|---|---|---|---|
|C OT|0 0|0j j b j b|OT j|m E OT|0 j b|j|0j m n|0 0|
||||b||||||
||||j||||||
||||b||||||

OT R *0 0j j m00j 0* *j 2* [*n*], *A* receives (*b; t* *j*

) *2* [2] F₂ from *A* inStep 1where *b* := *b* 1. *A*
*0* uniformly samples *t₁* *j* as *F* = *F* would. *A* sends (*b; ft g*) to *A* on behalf of

*F*. *A⁰* outputs whatever *A* outputs. The view of *A* is unmodied.
*0* *C* Hybrid 2.ForStep 2 *A* does not sample *t₁* *j* and instead uniformly samples *U* F₂. *A* sends *U* to *A* and then computes *Q* as S would. The view of *A* is identically distributed. This follows from the fact that *t₁* *j* is uniformly distributed in the view of *A* and masks the *j*-th column of *U* in the previous hybrid.

Hybrid 3.ForStep 4 *A⁰* simulates the consistency proof. This change is indistinguishable.

Hybrid 4.

|A⁰ receives k from A as specied inDenition F.6. For each row q||, A⁰ denes the circuit|
|---|---|---|
|||i|
|i||i|
|i|OT E||

*M* : [*N*]*!f*0*;* 1*g* such that on input *j 2* [*N*] it outputs H(*q* + *b C*(*map*(*j*))). *A⁰* sends *M* to the ideal oracle *F* as the sender’s input to the *i*-th OT instance. This change allows the ideal oracle to output the same distribution as the real protocol. The view of *A* is unmodied. Let *yj*= *qi*+ *b C*(*map*(*j*)) = *ti*+ *b* (*ci*+ *C*(*map*(*j*)) and note that *A* can inuence

|M (j) = H(y|) =|(y ) + y|by choosing k; b and the bits ft|[j] j b|
|---|---|---|---|---|
|i|j|k j|j|i|
|||||E|
|||||OT|

*i j k j j i j*= 0*g*.

Hybrid 5. *A⁰* does not take the input of R. R only interacts with *F*. This change is identically distributed since *A⁰* was not using the input of R.

Claim F.9 (Malicious Receiver *F* OT U -Security). *ext-R* *satises security against a malicious receiver* *(Denition 2.6) with respect to the F* OT U *functionality.*

*Proof.* The simulation also follows a similar strategy asLemma 5.8. Consider the following hybrids which will dene the simulator *A⁰*.

Hybrid 1. *A⁰* internally runs *A* while plays the role of S and base OT oracle *F*

|||= F|. A⁰|
|---|---|---|---|
|||OT|OT R|
|j j i2n|0 j j|0||

uniformly samples *ft₀; t₁gC*and sends them to *A* inStep 1. *A* samples *b* as S would. *A⁰* outputs whatever *A* outputs. The view of *A* is unmodied. *0 0* Hybrid 2.InStep 2 *A* receives *U* from *A*. *A* computes *C* and *Q* using *t₀; t₁; b*. *A* performs the proof ofStep 4as S would. If the proof fails, *A⁰* aborts as S would. Otherwise, by the correctness of the proof, *ci*decodes to *wi*and computes *xi*s.t. *wi*= *map*(*xi*). For all *i 2* [*m*], *A⁰* denes the circuit *Si*: [*N*]*! f; g* which outputs 1 at *xi*and 0 otherwise. *A⁰* sends *Si*and then (Output*;xi*) to *F* OT S as the receiver’s input to the *i*-th *F* OT S instance which responds with *vi;xi*. The view of *A* is unmodied.

Hybrid 3. *A⁰* then uniformly samples *k f* 0*;* 1*g* as S would and denes the ideal permutation*k*. If*k*has been queries by *A*, then *A⁰* aborts. The probability of this event is negligible due to *k* being uniformly sampled from *f*0*;* 1*g*. Otherwise, before sending *k* to S, *A⁰* programs*k*s.t.*k*(*ti*) = *vi;xi*+*ti*. Conditioned on these input/outputs not colliding for *i 2* [*m*], which happens with overwhelming probability, this modication is identically distributed due to *vi*0*;* 1*g* being sampled uniformly by *F*

|f||.||
|---|---|---|---|
|i;x|i|OT U i i i|j|
||j j||d|

Hybrid 4.Assuming *A⁰* did not abort inStep 4, let *E* = *fj j9i 2* [*m*]*;* (*c C*(*w*)) = 1*g* index the columns of *C* where *A* added an error to any codeword *c* (w.r.t *w*). By the correctness ofStep 4, it holds that *E B₀*, otherwise the consistency proof would have failed. By passing the consistency proof, *A* learns what *b* = 0 for all *j 2 E*. Similarly, the probability of passing the check and Pr[*jEj* = *d*] = Pr[*b* = 0 *j8j 2 E*] = 2 due to the proof being independent of *b*. We will see that this is equivalent to *A* simply guessing *E* (which is correct with the same probability) and then being honest.

For all *w 6*= *wi*, *A* has negl probability of computing *g* = *qi*+ *b C*(*w*). If this was not the case, then *A* could compute

*g* + *t* = *q* + *b C*(*w*) + *t*

|i i||i||
|---|---|---|---|
|i i i|i i|i|i|
||d|||
|k i|||i|

= *c b* + *t* + *b C*(*w*) + *t* = (*c* + *C*(*w*)) *b* = (*C*(*w*) + *C*(*w*)) *b*

This last equality holds due to *A⁰* aborting if (*c* + *C*(*w*)) *b 6*= 0. Recall that *C* has minimum distance *dC*and therefore computing *g* is equivalent *A* guessing *dC* bits of *b* which happens with probability 2*C*2. As such, the probability that *A* has made a query of the form (*q* + *b C*(*w*)) for *w 6*= *w* is also negligible. If such as query does happen *A⁰* aborts. This hybrid is indistinguishably distributed from the previous.

Hybrid 5.When S makes an*k*query of the form (*h*) which they have not previously been

||k||
|---|---|---|
|0||n|
|k|k|0|

*C* queried, *A* must determine if there is a unique *w 2* F₂*;i 2* [*m*] such that *h* = *qi*+ *b C*(*w*). For the sake of contradiction, let us assume there exists any two *i;i⁰ 2* [*m*] or *0 C 0* *w;w 2* F₂ which result in the same input to. If *i* = *i* and *w* = *w*, then a unique (*i;w*) exist. Otherwise,

*0 0*

|||t + b|(c + C(w)) = t||+ b|(c + C(w⁰))||
|---|---|---|---|---|---|---|---|
|||i|i i|i|i i i|i||
|||i|i i||i i C|||
|i||||||i|jEj|
|j||i|||||i|
||i|||||||

*b* (*C*(*w*) + *C*(*w⁰*) + *c* + *c 0*) = *t* + *t 0* *b* = *t* + *t 0*

where := *C*(*w*) + *C*(*w⁰*) + *c* + *c 0*. If *i* = *i⁰*, then it must hold *b* (*C*(*w*) + *C*(*w⁰*)) = 0 for *w 6*= *w⁰*. Recall that *C* by construction has minimum distance *dC*and that *b* is uniformly distributed. Let *E* = *fi j* = 1*g*, then *jEj d* and for the above to hold we require *b* = 0 *j8i 2 E* which occurs with probability Pr[*b* = 0 *j8i 2 E*] = 2 2 *d* *C*2. Therefore with overwhelming probability a unique (*i;w*) exist if *i* = *i⁰*.

Otherwise, let *B* := *fi j b* = *jg* and due toStep 4it holds that for all *i 2* [*m*], *c b* erasure decodes to *w* with *B₀* indexing the erasures. Therefore, by the linearity of *C*, erasure decodes to some *w* with *B₀* indexing the erasures s.t. *b c* = *b* where *c* := *C*(*w*).

Fixing some *i;i⁰*, the probability *b c* = *ti*+ *ti0* is *p₀* = Pr[(*ti*+ *ti0*)*‘*= 0 *j 8‘ 2* *B₀*] 2 *jB*0*j* times *p₁* = Pr*c*[(*ti*+ *ti0* + *c*)*‘*= 0 *j8‘ 2 B₁*] *N* 2 *jB*1*j*. Therefore, the probability that *i 6*= *i⁰* and *w 6*= *w⁰* is at most the union bound over all *i;i⁰ 2* [*m*],

Pr [*b c ti*+ *ti0*] *m²p₀p₁* = *m²N* 2 *nC*

(2)
*i;i0;c*

which is negligible⁸. Therefore we conclude that (*i;w*) is unique if such a pair exists.

If so then *A⁰* can use Gaussian elimination to identify it. In particular, *A⁰* computes *h* + *qi*for all *i 2* [*m*] and checks that (*h* + *qi*)*‘*= 0 for all *‘2B₁* and if so tries erasure decodes *h* + *qi*to *w* where the erasures are index by *B₀*. For *h* + *qi*this will happen and *A⁰* computes *x* s.t. *map*(*x*) = *w* and sends (Output*;x*) to the *i*-th instance of *F* OT S and receives *vi;x f* 0*;* 1*g* *‘* in response. Let *yi;x*:= *h* = *ti*+ *b*(*ci*+ *C*(*map*(*x*))).

*A⁰* programs*k*(*yi;x*) = *vi;x*+ *yi;x*. Programming*k*requires the input/output pair

|(y; v|+ y ) to have not previously been queried on||||||;|. It is easy to verify||
|---|---|---|---|---|---|---|---|---|---|
|i;x i;x|i;x|||k 1|i;x|i;x|k k 1||i;x|
||||i;x|||||i ;x|i ;x|
|k i ;x|i ;x|||||k||||
||k|||||||||

*i;x i;x i;x k* that with overwhelming probability (*v* + *y*) has not been queried since *v* is uniformly distributed.

In the other direction, *y* could have been queried in two ways. 1) D or *A* guessed it which is negligible as discussed inHybrid F.6. 2) D inverted *v 0 0* := H(*y 0 0*) = (*y 0 0*)+*y 0 0* and then recovered *b*. However, *v* = (*y*)+*y* is preimage resistant[BRS02, Win84] which informally follows from the diculty of nding an input to the random permutation which diers from *v* by itself.

Hybrid 6. *A⁰* does not take the input of S and does not program inHybrid F.6. S only interacts with *F* OT S. This change is identically distributed.

Claim F.10 (Malicious Receiver *F* OT S -Security). *ext-R* *satises Security Against a Malicious Re-* *ceiver (Denition 2.6) with respect to the F* OT S *functionality.*

*Proof.* Follows fromLemma 3.1and the previous claim.

Denition F.11. *Let* *ext-U* *be the protocol ofFigure 9where F*OT:= *F* OT U*u* *and the random oracle* H(*i;x*) *required byFigure 9is replaced as follows:*

*1.In round one,* S *samples k f* 0*;* 1*g and sends a commitment of k to* R*.*
*2.AfterStep 4,* S *decommits k to* R *who aborts if it fails.*
*nC*

*3.Both parties dene* H(*x*) =*k*(*x*) + *x where* : *f*0*;* 1*g* F₂*!f*0*;* 1*g is an ideal cipher.*
<u>Note: the i parameter of H</u> *is removed.*
 8 Note, *N* is assumed to be polynomial. This is true in the target use case where *N* = 2 and *nC* =.

### F.7 Proof ofLemma F.11: F

OT U Extension with an Ideal Cipher

Lemma F.12. *The* *ext-U* *protocol realizes 1-out-of-N F* OT U *-security, for N* = *poly*()*.*

*Proof.*

Claim F.13 (Malicious Sender Security). *ext-U* *satises security against a malicious sender (Def-* *inition 2.6) with respect to the F* OT U *functionality.*

*Proof.* The simulation follows essentially the same strategy asLemma F.7. The dierences to the hybrids are as follows.

Hybrid 1. *A⁰* extracts *k* from the commitment. Then *A⁰* samples *T₀;T₁* and the selections *b* uni- formly at random and simulates the base OTs using them.

Hybrid 4. *A⁰* no longer sends the messages specied by S to *F* OT U. Instead, when *A* makes a query to*k*(*h*), *A⁰* checks if *h* = *yi;x*= *ti*+ *b* (*ci*+ *C*(*map*(*x*))) for some pair (*i;x*). If so, then (*i;x*) are unique as described byLemma F.7. *A⁰* queries the *i*-th instance of *F* OT U with (Output*;x*) and receives *vi;x k i;x i;x*+ *yi;x*

|in response. A⁰ programs|||(y ) = v|. The|
|---|---|---|---|---|
|i;x i;x|||k i;x|i;x|
|||U|||
|||OT|||

probability of the input/output being previously queries is negligible due to *A* extracting *k* before *ti*was sampled and *v* being uniformly distributed.

Hybrid 5. *A⁰* does not take the input of R. R only interacts with *F*. This change is identically distributed since *A⁰* was not using the input of R.

Claim F.14 (Malicious Receiver *F* OT U -Security). *ext-R* *satises security against a malicious re-* *ceiver (Denition 2.6) with respect to the F* OT U *oracle.*

*Proof.* Follows directly fromLemma F.7claim 2 and the hiding property of the commitment.

### F.8 F

OT R Extension with an Ideal Cipher

|OT|||
|---|---|---|
||ext-R ext-E|OT Uu n|

Denition F.15. *Let* *be the protocol ofFigure 9where F*OT:= *F and the random oracle* *C* H(*i;x*) *required by* *is replaced as follows:* H(*x*) = (*x*) + *x where* : F₂*!f*0*;* 1*g is an* *ideal permutation. Note: the i parameter of* H *is removed.*

Lemma F.16. *The* *ext-*R *protocol realizes 1-out-of-N F* OT R *-security, for N* = *poly*()*.*

*sketch.* The proof follows the same strategy asLemma F.7except is not keyed. As such, R can compute H(*ti*) *before* making their selection *xi*. This can be simulator by having the simulator extract H(*ti*) as their chosen message.
