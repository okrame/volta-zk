# Relaxed Vector Commitment for Shorter Signatures

Seongkwang Kim¹, Byeonghak Lee¹, and Mincheol Son² *⋆*

1 Samsung SDS, Seoul, Korea sk39.kim@samsung.com,byghak.lee@samsung.com 2 KAIST, Daejeon, Korea encrypted.def@kaist.ac.kr

**Abstract.**MPC-in-the-Head (MPCitH) has recently gained traction as a foundation for post-quantum signature schemes, offering robust secu- rity without trapdoors. Despite its strong security profile, MPCitH-based schemes suffer from high computational overhead and large signature sizes, limiting their practical application. This work addresses these inefficiencies by relaxing vector commitments within MPCitH-based schemes. We introduce the concept of*vector semi-* *commitment*, which relaxes the binding property of traditional vector commitment. Vector semi-commitment schemes may allow an adversary to find more than one preimage of a commitment. We instantiate vector semi-commitment schemes in both the random oracle model and the ideal cipher model, leveraging recent optimizations on GGM tree such as correlated GGM tree. We apply the ideal-cipher-based vector semi-commitment scheme to the BN++ signature scheme and prove it almost fully secure in the ideal cipher model. Implementing these improvements in theAIMerv2.0 sig- nature scheme, we achieve up to 8.7% shorter signatures and up to 112% faster signing and verification speeds, setting new benchmarks for MPCitH-based schemes.

**Keywords:** MPC-in-the-Head, vector commitment, GGM tree, zero-knowledge proof, digital signature

*Publication History.*This paper is a revised version of Eurocrypt 2025 paper hav- ing the same name. In the proceeding version, the proposed signature scheme includes correlated GGM trees with secret key root which reduces*τλ*bits. Ko- suge and Xagawa pointed out thatG₆ (reduction to the MIH game) in EUF-CMA security proof is wrong in private communication [26], and published a related paper [25]. We admitted that our security proof is wrong, and removed “the secret key root” from the signature scheme while maintaining cGGM itself. *⋆* Mincheol Son was supported by the Institute of Information & Communications Technology Planning & Evaluation(IITP) grant funded by the Korea govern- ment(MSIT) (No.RS-2024-00399491, Development of Privacy-Preserving Multiparty Computation Techniques for Secure Multiparty Data Integration)

2 Seongkwang Kim, Byeonghak Lee, and Mincheol Son

So, in this version, we removed the cGGM-related technique which usessk as a fixed root of GGM tree, and revised the corresponding contents. Since this technique reduces the signature size by*τλ*bits, the signature scheme in this version has*τλ*bits larger than the previous version. The revised contents include: definition of MIH, security proofs, signature sizes, added*∆*sk*k*in algorithms, and some notations. For the performance figures ofrAIMer, we did not update the previous figures for the following reason; as the updatedrAIMerrequires one more AES evaluation per view, the effect on the performance would not be significant because of optimization techniques such as pipelined evaluation of AES.

## 1 Introduction

The MPC-in-the-Head (MPCitH) paradigm [20] has recently emerged as a promis- ing approach for designing post-quantum signature schemes. This paradigm leverages the concept of multi-party computation (MPC) to perform compu- tations within a single entity’s “head”, and has been applied to zero-knowledge proofs and signature schemes. MPCitH-based signature schemes enable a signer to generate a signature without relying on a trapdoor, making their security de- pends solely on the one-way function used in key generation. This advantage al- lows primitives without trapdoors, such as block ciphers [31,11,24], unstructured multivariate quadratic (MQ) problem [13], or unstructured syndrome decoding problem [14] to base the security of signature schemes. This makes them more reliable compared to schemes whose security is based on artificially constructed hardness assumptions with potential gaps in the security reduction. Despite their promising security feature, MPCitH-based signature schemes have been hindered by relatively high computational overhead and large signa- ture sizes, making them less efficient compared to their lattice-based counter- parts. The inherent complexity of simulating multi-party computations result in quadratic time and signature size with respect to the security parameter, which can be detrimental to practical adoption. In response, many studies have fo- cused on optimizing the efficiency of MPCitH-based signature schemes through protocol optimization [23,6,30,1] and improved cryptographic primitives [11,24]. One notable line of work for improving the efficiency of MPCitH-based sig- nature schemes is to optimize the GGM (Goldreich-Goldwasser-Micali) tree or vector commitment in the context of VOLE-in-the-Head (VOLEitH) [4] which includes the GGM tree and subsequent commitments afterward, a component used to generate shares of the virtual parties. The GGM tree enables the secure distribution of shares among the virtual parties. However, traditional GGM tree construction can be computationally expensive, contributing significantly to the overall inefficiency of MPCitH-based schemes. To address this, researchers de- veloped more efficient GGM tree constructions, such as double-length PRG in- stantiated by fixed-key block cipher [9,8] and the application of correlated GGM technique [10,9,19].

Relaxed Vector Commitment for Shorter Signatures 3

### 1.1 Our Contribution

In this work, we focus on improving vector commitments used in MPCitH-based signature schemes. Our primary enhancement is to relax the vector commit- ment requirements. A vector commitment scheme, a crucial component of our MPCitH-based signature scheme, must satisfy two key properties: hiding and (extractable) binding. The hiding property ensures that the commitment con- ceals the committed values, safeguarding the data’s secrecy. The binding prop- erty ensures that once a commitment is made, it is computationally infeasible to alter the committed values without detection. Notably, a violation of the binding property does not directly result in a signature forgery. We introduce a relaxed version of vector commitment, called*vector semi-* *commitment*, which ensures the hardness of finding a preimage and finding “many” collisions of a commitment. We call the latter characteristic*extractable* *semi-binding*– an extractor (only defined in the security proof) cannot find multi-collisions of a commitment more than a specific amount – and it is a key factor for the security proof. We then instantiate vector semi-commitment schemes in both the random oracle model and the ideal cipher model. For the latter, we fully instantiate all the random primitives using ideal cipher calls except a constant number of hash function calls, incorporate recent optimizations of the GGM tree construc- tion [9,8,19]. Previous works on optimizing the GGM tree can be divided into three contributions: the use of fixed-key block cipher, reducing primitive calls, and correlated GGM tree. While none of previous works include all the desirable characteristics, our vector semi-commitment scheme include all the above char- acteristics; ours calls(*N−*1)fixed-key block cipher for evaluating the GGM tree. By slightly modifying the Davies-Mayer construction provided in [8], our vector semi-commitment scheme enjoys better performance of both the fixed-key block cipher and the correlated GGM tree. To see the practical implication of our vector semi-commitment, we apply all the improvements to BN++ [22], an MPCitH-based signature scheme. We prove *λ* its security up to*O*(2)queries to the ideal primitives in the ideal cipher model. In other words, we prove that replacing a vector commitment with a vector semi- commitment does not compromise the security of the resulted signature scheme. Performance-related parameters, such as the number of repetitions, remain un- changed, thereby reducing the signature size while maintaining performance. We also implement our improvements inAIMerv2.0 [27], achieving up to

8.7% shorter signatures and up to 112% faster signing and verification speeds compared toAIMerv2.0. Compared to other MPCitH-based signature schemes such as SDitH [29] and FAEST [3], it also offers the fastest performance and the shortest signature size. Detailed performance figures are summarized in Table2.
### 1.2 Related Work

In MPCitH-based signature schemes, a prover emulates an MPC protocol among *N*parties “in her head” and then opens the views of(*N−*1)parties except one.

The verifier accepts if all the views are consistent with an honest execution of the MPC protocol. Katz et al. employed the GGM tree to reduce the number of opened random seeds from*N−*1tolog*N*, subsequently applying it to the MPCitH-based signature scheme Picnic [23]. Since then, the GGM tree has been used as a core technique to reduce the signature size in the MPCitH-based signature schemes [11,24,14,29,7]. There have been efforts to improve GGM trees. Guo et al. proposed a cor- related GGM tree [17] in the context of correlated oblivious transfer and dis- tributed point function. In a correlated GGM tree, the sum of all nodes at the same level is fixed. This technique reduces the number of random permutation calls by half. The correlated GGM tree was recently applied VOLE-in-the-Head- based signature schemes. Cui et al. reduces the number of random permutation calls for generating seeds is halved [10], and Huth and Joux reduces the sig- nature size by deleting the correction to the secret key share. Concurrently, Bui and Cong proposed applying the correlated GGM tree to MPC-in-the-Head and VOLE-in-the-Head [9]. They also replaced the random oracle calls used for commitment with random permutation calls, which can be implemented using efficient primitives such as fixed-key AES. However, the provable security of their proposal did not exceed the birthday bound. Independent with the correlated GGM tree, Bui et al. proposed a fast salted GGM tree which is fully secure in the ideal cipher model [8]. Using this salted tree, tree evaluation is as fast as the best unsalted version while preventing multi-target attacks. Compared to these works, our vector semi-commitment enjoys all the good characteristics: fast, salted, half number of calls, reduced signature size, and full security with respect to the number of ideal primitive queries.

## 2 Preliminaries

### 2.1 Notations

For two vectors or strings*a*and*b*, their concatenation is denoted by*a∥b*. For a vector or string*a*and non-negative integer*m*, we denote first*m*element of*a* by*a*[: *m*]. For integers*a*and*b*, we denote the bitwise XOR of*a*and*b*by*a⊕b*. Bitwise right shift by*i*of*a*is denoted by*a≫i*. We denote[*n*] =*{*1*,···,n}*. For a vector**x**,**x**[*a*: *b*]denotes a slice of the vector**x**from index*a*(inclusive) to*b*(inclusive).**x**[: *b*]and**x**[*a*:]denotes the same as**x**[1 : *b*]and**x**[*a*: *ℓ*]respectively, where*ℓ*refers to the length of the vector**x**. Unless stated otherwise, all logarithms are to the base2. For an integer *a∈{*0*,*1*,...,*255*}*,*⟨a⟩B*is the canonical binary representation of*a*, which is an 8-bit string. For a positive integer*n*and*k < n*, the falling factorial is denoted by(*n*)*k*=*n·*(*n−*1)*·····*(*n−k*+ 1). For a set*S*, we write*a←*$*S*to denote that*a*is chosen uniformly at random from*S*. For a probability distribution*D*,*a← D* denotes that*a*is sampled according to the distribution*D*. We denote the binomial distribution with*n* trials and probability*p*by*B*(*n,p*).

Throughout this paper, the security parameter is denoted by*λ*and assume *λ≥*64. In the multiparty computation setting, ∑ *x*

(*i*) denotes the*i*-th party’s
additive share of*x*, implying that*ix*

(*i*) =*x*.
### 2.2 Chernoff Bound

Chernoff bound is a well-known upper bound on the tail of a random variable. As our proof relies on this upper bound, we briefly introduce the Chernoff bound in its multiplicative form. Let*X*be a random variable following the binomial distribution*B*(*Q,p*). Then, the probability of the tail of*X*is upper bounded by

|)|(|)||
|---|---|---|---|
|δ µ||(1+δ)µ||
|1+δ|µ|||
|Q|i $|λ i|i λ−1|

( *e* 1 *eµ* Pr[*X≥*(1 +*δ*)*µ*]*≤ < ·* (1 +*δ*) *e* (1 +*δ*)*µ*

for any*δ >*0, where*e*is Euler’s number and*µ*=*Q·p*is the expectation of*X*. Given a multiset*S*=*{x₁,x₂,...,x}*with*x ← {*0*,*1*} \D* where*|D |≤* 2 *λ−*1, we can bound the probability that the maximum number of multi-collision mcollin*S*is greater than2*λ/*log*λ*as follows. With*λ≥*64and*Q≤*2, the probability is bounded by ()2*λ/*log*λ*()2*λ/*log*λ* <u>elogλ 2Q</u>*λ*<u>elogλ Q</u> Pr[mcoll*≥*2*λ/*log*λ*]*< ·* *λ* *·*2 *≤* 1*/*2 *·* *λ* 2*λ* 2 *λ* 2 ()2*λ/*log*λ* <u>2e Q 2Q</u> *≤ ·* *λ* *≤* *λ*

*.*(1)
3 2 2

Similarly, given a multiset*S*

|={y₁,...,y|}withy||← {0,1}|\D where|
|---|---|---|---|---|
|′ 5c|Q|i|$ ′|c i′ ′|
||13||||
|′|c|c 16|2c||

*|Di′|≤*2 *c−*1, we can bound the maximum multi-collisionmcoll in*S* is greater than13as follows. With*Q⁶ ≤*2, () [] <u>2eQ 1 Q</u> Pr mcoll *≥*13 *< ·*2 *≤ ·.*(2) 13*·*2 2 2

### 2.3 GGM Tree

GGM tree is a binary tree proposed by Goldreich, Goldwasser, and Micali [16]. For a power-of-two integer*N*, one can send*N−*1out of*N*random strings withlog*N*communication by using a GGM tree. For a pseudorandom generator *G*:*{*0*,*1*}* *n* *→{*0*,*1*}* 2*n* and a rootnode₀, the nodes in a GGM tree are defined recursively as follows.

|node₁ ∥node₁|=G(node₀)|||
|---|---|---|---|
|,1|,2|||
||||i−1|
|i,2j−1|i,2j|i−1,j||
||d|||
||d,k|||
|,(((k−1)≫(d−1))⊕1)+1||,(((k−1)≫(d−2))⊕1)+1|d,((k−1)⊕1)+1|

### node ∥node =G(node)fori≥2and0< j≤2

Let a GGM tree*T*has2 leaf nodes. If one wants to send all leaf nodes except *k*-th leaf node (i.e.,node), she can send a Merkle path () node₁*,*node₂*,...,*node*.*

We call this Merkle path an*associate path*of the unopened nodenode*d,k*. Con- versely, we will call the unopened nodenode*d,k*an*associate node*of the Merkle path described above. The depth of a node is defined by the length of the short- est upward path to the root (e.g., the depth ofnode₁*,*1is 1), and the height of a node is defined by the length of the longest downward path to a leaf node.

### 2.4 BN++ Zero-knowledge Protocol

In this section, we briefly review the BN++ proof system [22], one of the state- of-the-art MPCitH-based zero-knowledge protocols. At a high level, BN++ is a variant of the BN protocol [5] with several optimization techniques applied to reduce the signature size.

Protocol Overview.BN++ essentially simulates multiparty computation of*triple checking protocol*, which verifies that all the multiplication triples are honestly generated. To check*C*multiplication triples(*xj,yj,zj*=*xj·yj*) *C* *j*=1over a finite fieldFin the multiparty computation setting with*N*parties, ∑ *helping* *C C* *values*((*aj,bj*)*j*=1*,c*)are required, where*aj←*F*,bj*=*yj*, and*c*=*j*=1*aj·bj*. Each party holds secret shares of the multiplication triples(*xj,yj,zj*) *C* *j*=1and helping values((*aj,bj*) *C* *j*=1*,c*). Then, the protocol proceeds as follows. **–**A prover is given random challenges*ϵ₁,···,ϵC∈*F*.*

(*i*) (*i*) (*i*) (*i*) (*i*)
**–**For*i∈*[*N*], the*i*-th party locally sets*α₁,···,αC*where*αj*=*ϵj·xj*+*aj*. **–**The parties open*α₁,···,αC*by broadcasting their shares. **–**For*i∈*[*N*], the*i*-th party locally sets

∑ *C*

(*i*) ∑ *C*
(*i*)
*v*

(*i*) = *ϵj·zj− αj·bj*+*c*
(*i*) *.*
*j*=1 *j*=1 **–**The parties open*v*by broadcasting their shares and outputAcceptif*v*= 0.

By Lemma1, the probability that there exist incorrect triples and the parties outputAcceptin a single run of the above steps is upper bounded by1*/|*F*|*.

**Lemma 1 ([22])***If the secret-shared input*(*xj,yj,zj*)*j∈*[*C*]*contains an incor-* *rect multiplication triple, or if the shares of*((*aj,yj*)*j∈*[*C*]*,c*)*form an incorrect* *dot product, then the parties outputAcceptin the sub-protocol with probability* *at most*1*/|*F*|.*

Signature Size.By applying the Fiat-Shamir transform [12], one can obtain a signature scheme from the BN++ proof system. In this signature scheme, the signature size is given as

6*λ*+*τ·*(3*λ*+*λ·⌈*log₂(*N*)*⌉*+*M*(*C*))*,*

where*λ*is the security parameter,*C*is the number of multiplication gates in the underlying symmetric primitive, and*M*(*C*) = (2*C*+ 1)*·*log₂(*|*F*|*). In particular, *M*(*C*)is defined from the observation that sharing the secret share offsets for (*zj*) *C* *j*=1and*c*, and opening shares for(*αj*) *C* *j*=1occurs for each repetition, using *C*,1, and*C*elements ofF, respectively.

### 2.5 H-coefficient Technique

The H-coefficient technique is a powerful method used in the analysis of crypto- graphic algorithms, particularly in the context of provable security. Introduced by Patarin, this technique provides a systematic way to bound the distinguish- ing advantage of an adversary interacting with an idealized cryptographic system and a real implementation. The core idea of the H-coefficient technique is to par- tition the set of possible transcripts (i.e., sequences of queries and responses) into two subsets: “good” and “bad” transcripts. The probability of bad transcripts can be shown to be negligible, while the probability of distinguishing between the distributions of good transcripts can be tightly bounded. To illustrate the H-coefficient technique, we present the following lemma, which is a fundamental component of the technique:

**Lemma 2 (H-Coefficient Lemma)***LetAbe an algorithm that interacts with* *either an ideal world or a real world and tries to distinguish two worlds. LetT*id *andT*re*be the distribution of transcript in the ideal world and the real world,* *respectively, andTdenotes the set of all attainable transcripts in the ideal world.* *Suppose there exist partitionT*Good*(good transcripts) andT*Bad*(bad transcripts)* *ofT, and constantsϵandδsuch that for anyγ∈T*Good*,*

<u>Pr[γ=Tre]</u> Pr[*T*id*∈T*Bad]*≤ϵ, ≥*1*−δ.* Pr[*γ*=*T*id]

*Then, the distinguishing advantage ofAin distinguishingIfromRis bounded* *by:* **Adv** dist *I,R*(*A*)*≤ϵ*+*δ.*

This lemma provides a clear framework for analyzing the security of cryp- tographic protocols. By carefully defining the sets of good and bad transcripts and bounding their probabilities, one can apply the H-coefficient technique to obtain rigorous security proofs.

## 3 Vector Semi-commitment

In the context of MPCitH-based signature schemes, vector commitment (VC) abstracts the process of generating views and corresponding commitments. A VC scheme typically consists of four algorithms:Commit,Open,Recon, andVerify. TheCommitalgorithm generates the views of virtual parties and commits to these views. When a verifier challenges which views to reveal, the prover uses Opento disclose a subset of the views.Openproduces partial decommitment in- formation. Using this partial decommitment information, the verifier runsRecon to reconstruct the revealed messages and the corresponding commitments. Fi- nally, the verifier usesVerifyto check the validity of the partial decommitment information.

A vector semi-commitment scheme shares the same interface as vector com- mitments, with one of its properties relaxed compared to traditional vector com- mitments. We introduce the interface of vector semi-commitment in the random oracle model. Although the following is described in the context of the random oracle model, it can be easily adapted to the ideal cipher model.

**Definition 1(Vector Semi-commitment).***LetHbe a random oracle. An* *IV-based vector commitment scheme*VSC*with message spaceMin a random* *oracle model is defined by the following PPT algorithms.*

**–**Commit *H* (salt*,*root)*→*(com*,*decom*,*(*m₁,...,mN*))*: given an IV*salt*and a* *λ-bit string*root*, output a commitment*com*with opening information*decom *for messagesm*= (*m₁,...,mN*)*∈M* *N* *.* **–**Open *H* (salt*,*decom*,I*)*→*pdecom*: given an IV*salt*, opening information* decom*and a subsetI⊆*[*N*]*of indices, output a partial opening information* pdecom*forI.* **–**Recon *H* (salt*,*pdecom*,I*)*→*((*mi*)*i∈I,*com)*: given an IV*salt*, a partial opening* *information*pdecom*for a subsetI, output partially reconstructed messages* *and the full commitment*com*.* **–**Verify *H* (salt*,*com*,*pdecom*,I*)*→{*(*mi*)*i∈I}∪{⊥}: given an IV*salt*, a com-* *mitment*com*, a partial opening information*pdecom*, and a subsetI, either* *output the messages*(*mi*)*i∈I(accept) or⊥(reject).*

Although the interface is written for a general subset*I*, we will primarily consider*I*as a subset missing a single element unless otherwise specified. This opening is referred to as an*all-but-one*, with*I*being the all-but-one subset. If the context is clear, we will omit the random oracle indication ( *H* ). The major difference between vector semi-commitment and vector commit- ment is the binding property. Informally, the binding property of a commitment implies that it is hard to find multiple messages corresponding to the same com- mitment. A vector semi-commitment has a relaxed version of this property: the extractable semi-binding property. This property implies that while an adversary may find a small number of messages corresponding to the same commitment, it is hard to find a large number of such messages.

**Definition 2(Extractable Semi-binding).***Let*VSC*be an IV-based vector* *semi-commitment scheme in the random oracle model with random oracleH.*

(*j*)
*Let*Ext(salt*,Q,*com)*→{*(*mi*)*i∈*[*N*]*}j∈Jbe a PPT algorithm that, given a set* *of query-response pairs of random oracle queriesQand a commitment*com*,* *outputs the committed messages*(*mi*)*i∈*[*N*]*. Theu-extractable semi-binding game* *for*VSC*, denoted asu-*ESB*, withN*=*poly*(*λ*)*andQqueries to the random* *oracle and statefulA, is defined as follows.*

*1.*(salt*,*com*,*pdecom
*λ* *,Q*)

||,(m|) ,I)←A(1||
|---|---|---|---|
|(j)|I|i i∈I||
|i i∈[N]|j∈J||i i|

*2.{*(*m*)*} ←*Ext(salt*,Q,*com)*, whereQis the set{*(*x,H*(*x*))*}of* *query-response pairs of queriesAmade toHand|J|≤u.*

*3.Output 1 if*Verify(iv*,*com*,*pdecom*I,I*)*→*(*m*) *but there noj∈Jsuch*

|||∗ i i∈I|
|---|---|---|
|∗|(j)||
|i|i||
 *thatm* =*m for alli∈I; otherwise, output 0.* *We defineA’su-extractable semi-binding advantage by*
**Adv** *u* VSC *-*esb

(*A*) = Pr[*Awinsu-*ESB]*.*
(*j*)
Although the extractorExtextracts the set of messages(*mi*)*i,j*, the purpose of the extractable semi-binding game is to bound the number of validpdecom for the samecom. Therefore, the extractor should be programmed to extract messages only from validpdecom’s. We note thatExtmay output*mi*=*⊥*if the committed value at index*i*is invalid. The next property of vector semi-commitment is hiding, but the following definition is in the multi-instance form, and take into account the correlated property. The intuition behind the multi-instance hiding is that given multiple puncturable PRF instances and their commitments, the punctured messages are indistinguishable from random.

**Definition 3(Multi-Instance Hiding).***Let*VSC*be an IV-based vector semi-* *commitment scheme in the random oracle model with random oracleH. The* *multi-instance hiding game for vector semi-commitments,QI-*MIH*, withN*= *poly*(*λ*)*andQqueries to the random oracle and statefulAis defined as follows.*

*1.b* *∗* *←*$*{*0*,*1*}*
*2.Forj∈*[*QI*]*, do the following:*

|j $|λ|||
|---|---|---|---|
|j $|2λ+8|||
|j|j ∗ j,1|∗ j,N||
|j $|j|j||
|j|j|j||
|j,i ∗ j,i|j ∗|∗||
||j,i¯|||
|j,¯i||||
||$|||
|H j|j,i i∈[N]|j j|j∈[Q]|
||∗|||

*(a)*root*j←*$*{*0*,*1*}*
*λ*

*(b)*salt *← {*0*,*1*}*
*(c)*(com*,*decom*,*(*m,...,m*))*←*Commit(salt*j,*root*j*)
*(d)* ¯*i ←* [*N*]*,I* = [*N*]*\{*¯*i}*
*(e)*pdecom *←*Open(salt*,*decom*,I*)
*(f)m ←m fori∈I.*
{ *m* *j* *ifb* = 0*,*

*(g)Setm*
*j* *←* *← Motherwise.*

*3.b←A* (salt*,*(*m*)*,*pdecom*,I*)*I*)*.*
*4.Output 1 (win) ifb*=*b, else 0.* *We defineA’s multi-instance hiding advantage by*
∣ ∣ *QI-*mih ∣ <u>1</u> ∣ **Adv** VSC

(*A*) = ∣∣Pr[*AwinsQI-*MIH]*−* ∣∣*.*
2

*We call*VSC*is multi-instance hiding if advantage of anyQI-*MIH*adversary for* *polynomially boundedQIis negligible.*

### 3.1 Instantiation from Random Oracle

In this section, we instantiateVSCfrom a random oracle, dubbedRO-VSC, and prove the extractable semi-binding property and multi-instance hiding property. Let*H*com:*{*0*,*1*}* *∗* *→ {*0*,*1*}* *λ* ,*H*tree:*{*0*,*1*}* *∗* *→ {*0*,*1*}* *λ*, and*H*exp:*{*0*,*1*}* *∗* *→* F² *C*+2 be random oracles. Then,RO-VSCis constructed as Figure1. The commitment processCommitinvolves an evaluation of the correlated GGM tree to generate seeds and tapes, culminating in the output of a commit- mentcomand opening informationdecom. Compared to the traditional vector commitment based on the GGM tree, ourRO-VSCemploys the correlated GGM tree, and the commitment size is reduced from2*λ*to*λ*. The double-length PRG part (Step 2 inCommit *H* ) ofRO-VSCis depicted in fig.2a. Other algorithms are similar to vector commitment schemes. The opening algorithmOpenextracts path information for a given index set, while the reconstruction algorithmRecon rebuilds messages and commitments from path data and verifies the integrity of the commitment. Finally, the verification algorithmVerifyensures that the reconstructed messages match the original commitment. The integer*C*corre- sponds to the number of multiplication gates, and the integer*N*corresponds to the number of parties in the signature scheme. As this work focuses on security proof in the ideal cipher model, we only state Lemma3for extractable semi-binding property and Lemma4for multi- instance hiding property ofRO-VSC. The proofs of the lemmas are be provided in Supplementary MaterialB.1.

|com|∗|λ|tree|∗|λ|
|---|---|---|---|---|---|
|||||u-esb RO-VSC||
|λλ 2 log|u-esb RO-VSC||λ|||

**Lemma 3***LetH* :*{*0*,*1*} →{*0*,*1*} andH* :*{*0*,*1*} →{*0*,*1*} be random* *oracles. LetAbe an arbitrary adversary that makesQqueries to the random* *oracles. ThenA’su-extractable semi-binding advantage***Adv** (*A*)*against* RO*-*VSC*is bounded by* <u>10Q</u> **Adv** (*A*)*≤,* 2 () *foru*= 2*N.*

**Lemma 4***LetH*com:*{*0*,*1*}* *∗* *→{*0*,*1*}* *λ* *,H*tree:*{*0*,*1*}* *∗* *→{*0*,*1*}* *λ* *, andH*exp: *{*0*,*1*}* *∗* *→{*0*,*1*}* *∗* *be random oracles. LetAbe an arbitrary adversary that makes* *Qqueries to the random oracles. ThenA’s multi-instance hiding advantage* **Adv** *Q* RO *I* *--*VSC mih

(*A*)*against*RO*-*VSC*is bounded by*

|||Q mih|I||
|---|---|---|---|---|
|||RO--VSC|2λ|λ|

*I*<u>Q² Q</u> **Adv** (*A*)*≤* +*.* 2 2

### 3.2 Instantiation from Ideal Cipher

Now we replace the random oracles with an ideal cipher*E*. We instantiateVSC from the ideal cipher, namedIC-VSC, and also prove its properties. Let*E*:

**–Parameters**: a triple of random oracles*H*= (*H*

||||,H|,H ), an integer|
|---|---|---|---|---|
||||com|tree exp|
|H ,1|2λ+8|d|λ||
||e,2i−1 e,2i|e tree tree|e−1,i e−1,i|e−1,i|

*C*, a power-of-two integer*N*= 2. **–Inputs**:salt*∈{*0*,*1*}*, androot*∈{*0*,*1*}*.

**–**Commit (salt*,*root):

1.Setnode₀ *←*root.
2.For each level*e∈*[*d*]and*i∈*[2], set
node *←H* (salt*,e,i,*node) node *←H* (salt*,e,i,*node)*⊕*node*.*

3.For*i∈*[*N*], set
seed*i←*node*d,i* com*i←H*com(salt*,i,*seed*i*) tape*i←H*exp(salt*,i,*seed*i*) *mi*=tape*i*

4.Output a commitmentcom= (com₁*,...,*com*N*)with opening informa- tiondecom= ((node*e,i*)*e∈*[*d−*1]*,i∈*[2*e*]*,*com), and messages(*m₁,...,mN*).
**–**Open *H* (salt*,*decom*,I*= [*N*]*\{*¯*i}*):

1.Setpath*I←*(node*d−e*+1*,ie*)*e∈*[*d*]where*ie*= (*⌊*(¯*i−*1)*/*2
*e−*1 *⌋⊕*1) + 1for *e∈*[*d*].

2.Outputpdecom= (path*I,*com¯*i*).
**–**Recon *H* (salt*,*pdecom*,I*= [*N*]*\{*¯*i}*):

1.Similarly as Step 2 inCommit, expand each node inpath*I*and get (node*d,i*)*i∈I*.
2.For*i∈I*, do Step 3 inCommit.
3.Output((*mi*)*i∈I,*com).
**–**Verify *H* (salt*,*com= (com *∗* *i* ) *i∈*[*N*]*,*pdecom*,I*= [*N*]*\{* ¯ *i}*):

1.Similarly as Step 2 inCommit, expand each node inpath*I*and get (node*d,i*)*i∈I*.
2.For*i∈I*, do Step 3 inCommit.
3.Output(*mi*)*i∈I*ifcom=com
*∗* *i*for all*i∈I*, or output*⊥*otherwise.

Fig.1:RO-VSC

node*e,i*node*e,i*

salt saltpt

*H*treesaltkey *E σ*

node*e*+1*,*2*i−*1node*e*+1*,*2*i*node*e*+1*,*2*i−*1node*e*+1*,*2*i*

(a)RO-VSC (b)IC-VSC
### Fig.2: Double-length PRG ofRO-VSCandIC-VSC.

*{*0*,*1*}* *λ* *×{*0*,*1*}* *λ* *→{*0*,*1*}* *λ* be a ideal cipher, and*σ*:*{*0*,*1*}* *λ* *→{*0*,*1*}* *λ* be an linear orthomorphism. ThenIC-VSCis constructed as Figure3. The main difference betweenIC-VSCandRO-VSCis that all the random oracles are replaced with the ideal cipher, which requires sophisticated domain separation. The GGM tree evaluation (Step 2 inCommit *E* ), the share generation (Step 3 inCommit *E* ) are realized using only ideal cipher calls. We note that the whole*τ*GGM trees in a signature can be evaluated by a fixed-key block cipher. The double-length PRG part of the GGM tree evaluation is depicted in Figure2b. One noteworthy point is that the double-length PRG ofIC-VSCis inspired by Davies-Meyer-based GGM tree proposed by Bui et al. [8], and it is modified to an orthomorphism-applied version to work properly in correlated GGM tree. The new variablebrepresents the current repetition in the signature scheme. In the following, we prove the extractable semi-binding property and the multi-instance hiding property ofIC-VSCwith a supporting lemma. Although the proofs are straightforward, beware that the definition ofExtin Lemma6 will be used in the EUF-KO security proof. Lemma5is a supporting lemma which limits the probability of commitment collision from distinct height-1 nodes (height-0 nodes mean leaf nodes, not commitments), so that there is only one height-*≥*1node for each position for a fixed commitment.

||λ||λ|λ|||
|---|---|---|---|---|---|---|
|λ λ+λ+8||||′ λ|pt|key|
|σ(n)⊕E|(n⊕salt|) pt||B B|||
|σ(n )⊕E|(n ⊕salt|)|pt|B|B||
|σ(n)⊕E|(n⊕salt|)⊕n pt||B|B||
|σ(n )⊕E|(n ⊕salt|)⊕n|pt||B B||

**Lemma 5***LetE*:*{*0*,*1*} ×{*0*,*1*} → {*0*,*1*} be an ideal cipher andσ*: *{*0*,*1*} → {*0*,*1*}* *λ* *be an orthomorphism. LetAbe an arbitrary adversary that* *makesQqueries toE. Then, the probability thatAfinds*salt= (salt*,*salt*,*b)*∈* *{*0*,*1*},i∈{*0*,*2*,...,*254*},and distinctn,n ∈{*0*,*1*} such that*    *E*saltkey pt(salt [: *λ−*24]*∥*b*∥⟨i⟩ ∥⟨*0*⟩*)   = *E ′ ′* (salt [: *λ−*24]*∥*b*∥⟨i⟩ ∥⟨*0*⟩*)*,* saltkey pt

(3)
 *E*salt pt(salt [: *λ−*24]*∥*b*∥⟨i*+ 1*⟩ ∥⟨*0*⟩*)   key = *E ′ ′ ′*(salt [: *λ−*24]*∥*b*∥⟨i*+ 1*⟩ ∥⟨*0*⟩*)*,* saltkey pt

**–Parameters**: an ideal cipher*E*, an orthomorphism*σ*, integer*C*, a power- of-two integer*N*, and*N*= 2 *d*.

||pt|key|λ+λ+8||λ|
|---|---|---|---|---|---|
|E||||||
|,1||||||
||e,2i−1 e,2i|e,2i−1|e e−1,i|salt e−1,i|pt|

**–Inputs**:salt= (salt*,*salt*,*b)*∈{*0*,*1*}* *λ*+*λ*+8, androot*∈{*0*,*1*}* *λ*.

**–**Commit (salt*,*root):

1.Setnode₀ *←*root.
2.For each level*e∈*[*d*]and*i∈*[2], set
node *←σ*(node)*⊕E*key(node*e−*1*,i⊕*salt) node *←*node *⊕*node*.*

3.For*i∈*[*N*], set
seed *←*node

|i|d,i||
|---|---|---|
|||pt|
|i|seed||

ctr[b*,i,*0]*←*salt [: *λ−*24]*∥*b*∥⟨i⟩B∥⟨*0*⟩B* com *←Ei*(ctr[b*,i,*0])

(a)For*j∈*[2*C*+ 2],
ctr[b*,i,j*]*←*saltpt[: *λ−*24]*∥*b*∥⟨i⟩B∥⟨j⟩B* tape*i,j←E*seed*i*(ctr[b*,i,j*])

(b)Settape*i←*tape*i,*1*∥···∥*tape*i,*2*C*+2and*mi←*tape*i*.
4.Output a commitmentcom= (com₁*,...,*com*N*)with opening informa- tiondecom= ((node*e,i*)*e∈*[*d−*1]*,i∈*[*N*]*,*com), and messages(*m₁,...,mN*).
**–**Open *E* (salt*,*decom*,I*= [*N*]*\{*¯*i}*):

1.Setpath*I←*(node*d−e*+1*,ie*)*e∈*[*d*]where*ie*= (*⌊*(¯*i−*1)*/*2
*e−*1 *⌋⊕*1) + 1for *e∈*[*d*];

2.Outputpdecom= (path*I,*com¯*i*)
**–**Recon *E* (salt*,*pdecom*,I*= [*N*]*\{*¯*i}*):

1.Similarly as Step 2 inCommit, expand each node inpath*I*and get (node*d,i*)*i∈I*.
2.For*i∈I*, do Step 3 inCommit
*E*.

3.Output((*mi*)*i∈I,*com).
**–**Verify *E* (salt*,*com= (com *∗* *i* ) *i∈*[*N*]*,*pdecom*,I*= [*N*]*\{* ¯ *i}*):

1.Similarly as Step 2 inCommit, expand each node inpath*I*and get (node*d,i*)*i∈I*.
2.For*i∈I*, do Step 3 inCommit
*E*.

3.Output(*mi*)*i∈I*ifcom=com
*∗* *i*for all*i∈I*, or output*⊥*otherwise.

Fig.3:IC-VSC

*is at most*10*Q/*2 *λ* *.*

Technically speaking, we limit the number of single commitment collision by Markov’s inequality, and limit the probability of two adjacent commitments collisions. The intuition behind this so technical proof is that the total length of commitments assigned to a node with two leaves will be2*λ*. Therefore, there will be no two distinct height-1 nodes with same commits. For the full proof, see Supplementary materialB.2.

**Lemma 6***LetE*:*{*0*,*1*}* *λ* *×{*0*,*1*}* *λ* *→ {*0*,*1*}* *λ* *be an ideal cipher andσ*: *{*0*,*1*}* *λ* *→ {*0*,*1*}* *λ* *be an orthomorphism. LetAbe an arbitrary adversary that* *makesQqueries toE. Then,A’su-extractable semi-binding advantage***Adv** *u* IC *--*esb VSC(*A*) *against*IC*-*VSC*is bounded by*

*u--*esb<u>14Q</u> **Adv**IC VSC(*A*)*≤* *λ* *,* 2 ()2 *foru*= 2*N* log <u>λ</u> *λ* *.*

*Proof.*Intuitively, according to Lemma5, the probability of finding a collision in commitments derived by a non-leaf node is negligible. Furthermore, for each leaf node, the number of multi-collisions is bounded by the Chernoff bound. We now proceed to formally bound the adversary’s advantage. Let*Q*be the number of queries to*E*, and*Q*be the collection of all queries to*E*. Since the choice ofsaltandbdoes not affect extractable semi-binding, we can assume all salts andbare equaled to zero strings.

|λ|||N|
|---|---|---|---|
||d,i|||
|s|B|i||
|e||e,i||
|e+1,2i−1|||e+1,2i|

We first define the extractorExt(0*,Q,*com= (com₁*,...,*com))as follows.

1.For each*i∈*[*N*], find leaf node sets*S* such that
### Sd,i={s: E (ctr[⟨0⟩,i,0]) =com}

2.For each*e∈*[*d−*1]and*i∈*[2], find internal node sets*S* such that
### Se,i={n: E₀(n)⊕σ(n)∈S,E₀(n)⊕σ(n)⊕n∈S}

3.For*i∈*[*N*], let
{}

|A = (p₁,...,p|) :p|∈S fore∈[d]|
|---|---|---|
|i d−e|d e|e,i|

*e*

where*ie*= (*⌊*(*i−*1)*/*2 *⌋⊕*1) + 1for*e∈*[*d*]

4.Let*S*be the set of messages, where { *S*= (*s₁,...,sd,i*=*∅*and*s* otherwise*,*

|) :s|=⊥ifS|∈S|
|---|---|---|
|N|i|i d,i|
|d|i|i i∈I|

}
Recon(*p₁,...,p,*com*,I*= [*N*]*\{i}*) = (*s*) for(*p₁,...,pd*)*∈Ai*

5.Finally,Extoutputs arbitrary*u*or less elements in*S*.

For graphical description, we make an example in Figure4. For a fixed commit- mentcom,*Se,i*is the set of*i*-th depth-*e*nodes whose corresponding leaf nodes are consistent tocom.*Ai*is the set of copaths for hidden leaf node*i*. In Figure4, if red node is hidden, then blue nodes are the copath in*A₃*.*S*is the set of all the punctured seeds reconstructed from any*Ai*. Now we define some bad events.

**–**Bad₁ *⇔*there exists*e∈*[*d−*1]and*i∈*[2 *e*]such that*|Se,i|≥*2. **–**Bad₂ *⇔*there exists*i∈*[*N*]such that*|Sd,i|≥*2*λ/*log*λ*.

Since the probability of querying a fixed commitment is1*/*(2 *λ* *−Q*), we have Pr [*|Sd,i|≥c*]*≤*Pr [*X≥c*]where*X*follows*B*(*Q,*2*/*2 *λ* ). Similar to (1), one have

<u>4Q</u> Pr [Bad₂]*≤* *λ* 2

By Lemma5and (1), <u>14Q</u> Pr [Bad₁ *∨*Bad₂]*≤* *λ*

(4)
2 In the following, we analyze the extracting condition without bad events.

**–**As*S*contains all possible(pdecom*I,I*),*A*wins the game only if*|S|> u*. **–**By*¬*Bad₁, we have ∑ ∑ *|S|≤ |Sd,*2*i|·|A₂i−*1*|≤ |Sd,*2*i|·|Sd,*2*i−*1*|.* *i∈*[*N/*2] *i∈*[*N/*2]

Then, by*¬*Bad₂, we have ()2 <u>λ</u> *|S|≤*2*N.* log*λ*

Therefore,*A*cannot win the game without the bad events so we have

*u*<u>14Q</u> **Adv**IC--esb VSC(*A*)*≤*Pr [Bad₁ *∨*Bad₂]*≤* *λ* 2 ()2 provided that*u*= 2*N* log <u>λ</u> *λ* .*⊓⊔*

**Lemma 7***LetE*:*{*0*,*1*}* *λ* *×{*0*,*1*}* *λ* *→{*0*,*1*}* *λ* *be an ideal cipher. LetAbe an* *arbitrary adversary that makesQqueries toE. Then,A’s multi-instance hiding* *advantage***Adv** *Q* IC *I* *-*VSC *-*mih

(*A*)*against*IC*-*VSC*is bounded by*

|Q-mih|||2|I|
|---|---|---|---|---|
|IC-VSC|I||λ (2C 2 +4)N||

*I*(3 + 5*N²* + (2*C*+ 8) + log*N*)*Q* (25 + 24 log*N*)*Q* 2 **Adv** (*A*)*≤* + *λ* + *λ* *.* 2 2 2 { <u>5(λ−24)</u> *λ−*1 } *provided thatQ ≤*min 26*,.*

root

|node₁||node₁||
|---|---|---|---|
|,1||,2||
|,1|,2|,3|,4|

GGM node₂ node₂ node₂ node₂

seed

(1) seed
(2) seed
(3) seed
(4) seed
(5) seed
(6) seed
(7) seed
(8)
Commit

com

(1) com
(2) com
(3) com
(4) com
(5) com
(6) com
(7) com
(8)
Fig.4: The seed tree and commitments to the seeds. If the red seed is hidden, the blue nodes will be the copath of the red seed.

We basically bound advantage between the ideal world – hidden tapes are re- placed by random strings – and the real world using the H-coefficient technique. After*mj,*¯*i* *j* are given, an attacker learns ideal cipher key, input, output relations from the tree construction, the commitment, and the tape generation. If these queries are inconsistent at this moment – either given instances themselves or with the attacker’s own ideal cipher queries – the attacker can distinguish the ideal world from the real world (i.e., the hidden messages are unchanged). Oth- erwise, the two worlds remain indistinguishable. The full proof in Supplementary MaterialB.2.

## 4 Application of VSC to BN++

### 4.1 Description of rBN++

In this section, we applyIC-VSCto BN++, dubbed*rBN++*(reduced BN++). rBN++ is a signature scheme containing three algorithmsKeyGen,Signand Verify, whereKeyGenis assumed to be a one-way function. The signing and verification algorithms of the rBN++ can be found in the Algorithm5and Algorithm6in Supplementary materialA. The major differences between the rBN++ and the original BN++ can be summarized into three points:

**–**The GGM trees are replaced by correlated GGM trees. **–**The sizes of each commitments are reduced from2*λ*bits to*λ*bits. **–**Most of the random oracle calls are replaced by primitives based on an ideal cipher. Now, there are only 5 calls to random oracles for a signing query.

There are also some minor changes compared to the original BN++. The following modifications are made for either minor efficiency improvements or ease of proof.

**–**The message to be signed is hashed by*H₀* :*{*0*,*1*}* *∗* *→{*0*,*1*}* 2*λ* along with the public key. **–**The salt is generated by running*H₃* :*{*0*,*1*}* *∗* *→ {*0*,*1*}* 2*λ* with inputs the secret keysk, hashed message*µ*, and internal randomness*ρ*, rather than randomly sampled. **–**In each repetition, different saltsalt*j*is used. Each salt is generated from mas- ter saltsaltby feeding into hash functionExpandSalt:*{*0*,*1*}* 2*λ* *→{*0*,*1*}* 2*τλ*. **–**The offsets*∆*sk*k,∆ck,∆zk,j*are added to the last share, rather than to the first share. **–**The function expanding*h₁* and*h₂* (the original function name in BN++ is Expand) is divided into two different functions:ExpandH1:*{*0*,*1*}* 2*λ* *→*F *C·τ*

andExpandH2:*{*0*,*1*}* 2*λ* *→*[*N*] *τ*. These two functions are modeled as random oracles in the security proof.

### 4.2 Security Proof of rBN++

In this section, we prove the security of rBN++. The main difference between the security proofs for BN++ and rBN++ is that, semi-binding does not guar- antee the uniqueness of*H₁*-query input(*µ,σ₁*). In the original BN++, individual commitment is of length2*λ*bits so that the probability of*H₁*-query input col- lision (not*H₁* collision) is negligible. However, an EUF-KO adversary may find an*H₁*-query input collision by querying to ideal cipher*E*, as the individual commitment size is less than2*λ*bits. This case is covered in bad eventsBad₄, andBad₅ in the security proof. Except this difference, the security can proved similarly.

**Theorem 1(EUF-KO Security of rBN++).***Let*(*N,τ,λ,*F)*be parameters* *of rBN++ where|*F*|*= 2 *λ* *andN*= 2 *d* *. Assume thatH₁,H₂* :*{*0*,*1*}* *∗* *→* *{*0*,*1*}* 2*λ* *,*ExpandH1*, and*ExpandH2*are modeled as random oracles. LetAbe an* *arbitrary adversary against the EUF-KO security of rBN++ that makes a total* *ofQrandom oracle queries andPideal cipher queries. Then there exists PPT* *adversaries*

**–***Bagainst OWF security of*KeyGen*withQrandom oracle queries andP* *ideal cipher queries,* **–***Cagainst extractable semi-binding security withPideal cipher queries,*

*and*0*≤τ* *′* *< τsuch that*

*Q²* (4*ν*+ 2)*Q* 14*P*

|euf-ko||owf|u--esb|
|---|---|---|---|
|rBN++|λ τ|KeyGen i|IC VSC τ−i|
||i=τ|λ−1||

**Adv** *≤* 2*λ* + *λ* + +**Adv** (*B*) +**Adv** (*C*) 2 2 2 ∑ ( *τ* )( *u* ) ( *u* ) *Q₂* +*Q₁ ·* 1*−* + *τ−τ′* *′* *i |*F*| |*F*| N*

### whereν= 2λ/logλ,u=ν²N/2, andP,Q≤2.

*Proof.*Suppose that all the queries to*H₁*,*H₂*,*E*are listed in*Q₁*,*Q₂*, and*P*, respectively. Let*|Q₁|*=*Q₁*,*|Q₂|*=*Q₂*, and*|P|*=*P*. Suppose thatKeyGencan be verified by*C*number ofF-multiplications.

|Algorithm 1.|ExpandH1(|h₁|):|
|---|---|---|---|
|1 h 1 →H₁|.|||
|(|)|C|τ|
|2 ( ϵ k,j )|j∈ [ C] ← k∈ [ τ]|$ (F )|.|
||( )|||
|3 Return|( ϵ k,j ) j∈ [ C]|. k∈ [ τ]||

|Algorithm 2.|ExpandH2(|h₂|):|
|---|---|---|---|
|1 h₂ →H₂|.|||
|¯|¯|τ||
|2 (¯ i₁, i₂ ,...,|i τ ) ← $ ([|N]).||
|3 Return(¯|i₁, ¯ i₂ ,..., ¯ i|).||
|||τ||

We program the random oracles for*A*as in Algorithm1,2,3, and4, re-

|spectively. For convenience, we denote∆||,∆c ,(∆z|)|
|---|---|---|---|
|||k k|k,j j∈[C]|
|k,j j∈[C]|k,j j∈[C]|||
|||2λ||
|2λ||||

*k*= (*∆*sk),*αk*=

(*α*), and*ϵk*= (*ϵ*). We manage sets*H₁* and*H₂* while the ad- versary is querying to identify any collision of*H₁* and*H₂*. We also manage setsSucc₁[salt*,h₁*](resp.Succ₂[salt*,h₂*]) forsalt*,h₁ ∈ {*0*,*1*}* (resp.salt*,h₂ ∈* *{*0*,*1*}*). These sets contain*k∈*[*τ*]if and only if the*k*-th repetition passes the first (resp. second) multiplication check for a specific salt and first hash (resp. second hash). If one of such sets become equal to[*τ*], the adversary can forge a signature.Extis the extractor in the*u*-ESBgame.
(*i*) (*i*)
MultCheck₁ andMultCheck₂ in Algorithm4are the first round and sec- ond round of the multiplication checking protocol for the*i*-th party, which is explicitly defined by

|(i)||(i) (i)||||
|---|---|---|---|---|---|
|j j|i j|j j C|j C|||
|(i)|(i)||(i)|(i)|(i)|
|j j|i j j|j j=1|j j=1|j j||
|(i) (i)|(i) (i)|(i)||||
|j j|j j||||i|
|j|j|||||

### MultCheck₁ ((ϵ),m) = (ϵ ·x +a)

∑ ∑ MultCheck₂ ((*ϵ*)*,m,*(*α*)) = *ϵ ·z − α ·y* +*c*

whereF-elements*x,y,z,a*, and*c* are components of*m* in specific positions, andF-vectors(*∗*) are of length*C*. We note that the length of*mi*is 2*C*+ 2as some outputs are fed into some inputs.MultCheckin Algorithm3is defined by combining above two functions as follows.

(*i*)
MultCheck((*ϵj*)*j,mi*) = (MultCheck₁((*ϵj*)*j,mi*)*,*MultCheck₂((*ϵj*)*j,mi,*(*αj*)*j*))

() **Algorithm 3.***H₁* salt*,σ₁* = (com*k,∆k*)*k∈*[*τ*]: 2*λ* **1***h₁ ←*$*{*0*,*1*}* **2if***h₁ ∈H₁* **then** **3**RaiseBad₁ and abort

**4***h₁ →H₁*. **5**(*ϵ₁,...,ϵτ*)*←*ExpandH1(*h₁*) **6**(salt₁*,...,*salt*τ*)*←*ExpandSalt(salt)

**7**Succ₁[salt*,h₁*]*←∅* **8for***k∈*[*τ*]**do**
**9for**(*m₁,...,mN*)*∈*Ext((salt*k,k*)*,P,*com*k*)*where⊥/∈*(*m₁,...,mN*)
**do** **10***mN←mN⊕∆k* () ∑ **11**sk*←*msb*λ i∈*[*N*]*mi*

**12if**KeyGen(sk) =pk**then** **13**RaiseBad₂ and abort.//Secret key is found ()

(*i*) (*i*)
**14**(*α,v*)*i∈*[*N*]*←*MultCheck *ϵk,*(*mi*)*i∈*[*N*] ∑

(*i*)
**15if***i∈*[*N*]*v* = 0**then** **16***k→*Succ₁[salt*,h₁*]//Multiplication checking cheated

*′* **17if***|*Succ₁[salt*,h₁*]*|≥τ* **then** **18**RaiseBad₃ and abort.//Too many cheated iterations

**19**(salt*,σ₁,h₁*)*→Q₁* **20**Return*h₁*.

(*i*)
where(*αj*)*j*=MultCheck₁((*ϵj*)*j,mi*). We note that the above programmings do not change the output distribution of random oracles. We define bad eventsBadconsisting 6 small bad eventsBad*i*for*i*= 1*,...,*6 ∨6 (i.e.,Bad=*i*=1Bad*i*). If the bad event happens, the game aborts and the adversary wins. Each small bad event is explained as follows.

**–**Bad₁: A hash collision of*H₁* or*H₂* is found. **–**Bad₂: The PPT adversary*B*finds the preimage ofKeyGen. **–**Bad₃: There are too many repetitions which are illegitimately passed in the first challenge. **–**Bad₄: In this case, the extracted message in fact passes the first challenge, but the message was not extracted at the time of querying to*H₁* since the extractor lacks some query at that time. This event can be considered as preimage finding of the vector semi-commitment. **–**Bad₅: At least two punctured messages are extracted, where two punctured points are distinct. Since rBN++ signature contains a path of GGM tree rather than leaves, those two punctured messages can be combined to a

( ())

(*i*) (*i*)
**Algorithm 4.***H₂* salt*,h₁,σ₂* = (*α* *k* *,v* *k* ) *i∈*[*N*]*,k∈*[*τ*]:

**1***h₁ →H₁* **2***h₂ ←*$*{*0*,*1*}* 2*λ*

**3if***h₂ ∈H₂* **then** **4**RaiseBad₁ and abort.

**5***h₂ →H₂*,(salt*,h₁,σ₂,h₂*)*→Q₂*. ∑(*i*) **6if***∃k∈*[*τ*]*such thati∈*[*N*]*v* *k* *̸*= 0**then** **7**Return*h₂*.

**8if***∃σ₁ such that*(*h₁,σ₁*)*∈Q₁* **then** **9**Parse*σ₁* as(com*k,∆k*)*k∈*[*τ*] **10**(*ϵ₁,...,ϵτ*)*←*ExpandH1(*h₁*) () **11**¯*i₁,...,*¯*iτ←*ExpandH2(*h₂*) **12else** **13**Return*h₂*.

**14**Succ₂[salt*,h₂*]*←∅*. **15for***k∈*[*τ*]*\*Succ₁[salt*,h₁*]**do** **16***J←∅* **17for**(*m₁,...,mN*)*∈*Ext(salt*,P,*com*k*)**do** **18if***mN̸*=*⊥***then** **19***mN←mN⊕∆k*

**20if***⊥/∈{m₁,...,m* (*N* *}***then** ) ∑ **21**sk*←*msb*λ i∈*[*N*]*mi*

**22if**KeyGen(sk) =ct**then** **23**RaiseBad₂ and abort.//Secret key is found

(*i*) (*i*)
**24**for*i∈*[*N*],*β ←*MultCheck₁ (*ϵk,mi*)

(*i*) (*i*)
**25**for*i∈*[*N*],*w ←*MultCheck₂ (*ϵk,mi,αk*)

(*i*) (*i*) (*i*) (*i*)
**26if***∀i∈*[*N*]*,*(*α* *k* *,v* *k* ) = (*β,w*)**then** **27**RaiseBad₄ and abort.

(*i*) (*i*) (*i*) (*i*)
**28else if** *∃j,∀i∈*[*N*]*\{j},*(*α* *k* *,v* *k* ) = (*β,w*)**then** **29***j→J*.

**30if***|J|≥*2**then** **31**RaiseBad₅ and abort. {} **32else if***J*= ¯*ik***then** **33***k→*Succ₂[salt*,h₂*]

**34if***|*Succ₂[salt*,h₂*]*|≥τ−τ* *′* **then** **35**RaiseBad₆ and abort.//Too many cheated iterations

**36**Return*h₂*.

whole path for any undisclosed party. So, this event also means that the extractor finds a message which in fact passes the first challenge asBad₄. **–**Bad₆: there are too many repetitions which are illegitimately passed in the second challenge.

Bad₄ andBad₅ did not happen when the “individual” commitment size is2*λ* bits (i.e., vector commitment), as it is hard to find multiple preimages of in- dividual commitment itself. On the other hand, in our case (i.e., vector semi- commitment), there may be a few preimages of a fixed commitment.Bad₄ de- scribes an event that a directly found preimage from commitment queries passes the first challenge, andBad₅ describes an event that multiple directly found punctured images from commitment queries passes the first challenge. We will show that the probability of such bad events are negligible in the following. We have Pr [*A*wins]*≤*Pr [Bad] + Pr [*A*wins*|¬*Bad]

where the probability of each bad event is analyzed as follows.

**–**Upper boundingPr [Bad₁]. As*|h₁|*=*|h₂|*= 2*λ*, we have

<u>Q²</u> Pr [Bad₁]*≤* 2*λ* *.* 2

Note that withoutBad₁, we can avoid the event for preimage/collision- finding of*H₁* and*H₂*. **–**Upper boundingPr [Bad₂]. Let*B*be an OWF adversary that use*A*as a subroutine, and checks whetherBad₂ occurs by someroot. Then, the winning probability of*B*is at leastPr [Bad₂], so we have

Pr [Bad₂]*≤***Adv** owf KeyGen(*B*)

**–**Upper boundingPr [Bad₃]. By the definition ofExt, the number of extracted messages is always less or equal than*u*. Therefore, for each*k∈*[*τ*], the success probability of cheating the multiplication checking is upper bounded by *|* <u>u</u> F*|* and we have

∑ *τ*( *τ* )( <u>u</u> )*i*( <u>u</u> )*τ−i* Pr [Bad₃]*≤Q₁ ·* 1*−* *′* *i |*F*| |*F*|* *i*=*τ*

**–**Upper boundingPr [Bad₄]. Let us fix*H₁* query, and assume thatBad₄ occurs at*k*-th iteration with(*m₁,...,mN*). Denote*mi,j∈*Fbe the(*j*+ 1)-th com- ponent of*mi*for*j∈*[2*C*+ 1], interpreting asF-vector. Since(*m₁,...,mN*) is extracted messages, there exists ideal cipher queries such that

|E (ctr[⟨k⟩|,i,0]) =com|fori∈[N],(a)|
|---|---|---|
|seed|B|i|
|seed|B|i,j|

(*i*)
*E* (*i*) (ctr[*⟨k⟩,i,j*]) =*m* for*i∈*[*N*]*, j∈*[2*C*+ 1]*.*(b)

whereseed

(*i*) is the*i*-th seed. Let*A*and*B*be the list of ideal cipher queries
of the form (a) and (b), and*A∪B*be the union list of*A*and*B*while the orders are preserved. Let*i* *∗* *∈*[*N*]be the party index of the last query in

*A*. As*k /∈*Succ₁[salt*,h₁*], the above query is done after the query to*H₁*. We divide two cases as follows. *•*Case 1: The query*E*seed(*i∗*) (ctr[*⟨k⟩B,i*
*∗* *,*0]) =com*i∗* is the last query in *A∪B*. Considering a fixed first challenge*ϵk*, the multiplication checking protocol is a set of linear relations of the shares. As all the other ideal *∗* cipher queries are fixed, there are at most1candidate ofseed

(*i*) which
passes the multiplication checking protocol per*H₁* query (i.e., all the (*i* *∗* ) other variables in the linear relations are fixed, but onlyseed is not). Also, by (4) in Lemma6, there are at most*ν*= log <u>2λ</u> *λ* of(*N−*1)-tuples (seed

(*i*) ) *i∈*[*N*]*\{i∗}*which satisfies (a) except with probability14*P/*2
*λ*. (*i* *∗* ) Since*E*should satisfy the equation forseed, we have

*νQ₁* 14*P* 2*νQ₁* 14*P* Pr [Bad₄ with Case 1.]*≤* *λ* + *λ* *≤* *λ* + *λ* 2 *−P* 2 2 2

provided that*P≤*2 *λ−*1. *•*Case 2: The query*E* (*i∗*) *∗* *∗*

|(ctr[⟨k⟩|,i ,j]) =m|is the last query in||
|---|---|---|---|
|seed|B ∗|i ,j||
|||i ,j||
||||(i)|
|λ||||

*A∪B*. Similar to Case 1, the candidate of*m ∗* is now at most1. *∗* The difference is that there are at most*P*candidates ofseed, and*E* should satisfy both (a) and (b). So, there are at most*νP*candidates per *H₁* query except14*P/*2 probability by by (4) in Lemma6. We have

*νQ₁P* 14*P* 2*νQ₁* 14*P* Pr [Bad₄ with Case 2.]*≤* *λ* 2 + *λ* *≤* *λ* + *λ* (2 *−P*) 2 2 2

provided that*P≤*2 *λ−*1. All in all, we get <u>4νQ₁ 14P</u> Pr [Bad₄]*≤* *λ* + *λ* 2 2 **–**Upper boundingPr [Bad₅]. Let us fix the query to*H₂*, and assume thatBad₅ occurs by two extracted messages in the*k*-th iteration:(*m₁,...,mN*)adds*j₁* *′*

|toJ, and(m|,...,m||)addsj₂ toJ. Then, by the definition ofExt, there||||
|---|---|---|---|---|---|---|
|′′|′′ 1 ′′|′′ N 1|′′ j|′′ j|′′ i|i ′i|
|1|N||||||

1 *′N*

exists(*m* *′′* *,...,m* *′′* )in extracted message sets, such that*m* *′′* *∈ {m,m* *′i* *}* for*i∈*[*N*]*\{j₁,j₂}*, *m* 1 =*m* *′j* 1 and*m* 2 =*mj*2. As*k /∈*Succ₁[salt*,h₁*], (*m,...,m*)inducesBad₄, so

### Pr [Bad₅ ∧¬Bad₄] = 0.

Since the game immediately aborts ifBad₄ occurs, we can conclude that Pr [Bad₅] = 0.

1 We note that all the subtrees which do not contain both*j₁* and*j₂* should choose from the same kind of message. This is because of the structure of the GGM tree.

**–**Upper boundingPr [Bad₆]. IfBad₄ andBad₅ do not happen, then*|J|≤*1 for iterations in all queries to*H₂*. So, we have

<u>Q₂</u> Pr [Bad₆]*≤* *τ−τ′* *.* *N*

All in all, we have

*Q²* 4*νQ₁* 14*P*

|owf|||
|---|---|---|
|KeyGen|2λ λ|λ|
|τ|i|τ−i|
|i=τ|||

Pr [Bad]*≤***Adv** (*B*) + + + 2 2 2 ∑ ( *τ* )( *u* ) ( *u* ) *Q₂* +*Q₁ ·* 1*−* + *τ−τ′*

(5)
*′* *i |*F*| |*F*| N*

What is left is to upper boundPr [*A*wins*|¬*Bad]. Suppose that*A*outputs valid forgery () (¯*ik*) salt*,h₁,h₂,*(pdecom*k,∆k,α* *k* ) *k∈*[*τ*]

butBaddoes not occurs. Then, the forgery should satisfy followings.

**–**There exists*σ₁* = (com*k,∆k*)*k∈*[*τ*]such that(salt*,σ₁,h₁*)*∈Q₁*.

(*i*) (*i*)
**–**There exists*σ₂* = (*α* *k* *,v* *k* ) *i∈*[*N*]*,k∈*[*τ*]such that(salt*,h₁,σ₂,h₂*)*∈Q₂*. **–**LetFail= [*τ*]*\*(Succ₁[salt*,h₁*]*∪*Succ₂[salt*,h₁,h₂*])*.*Then,Fail*̸*=*∅*. **–**Fix*k* *∗* *∈*Fail, and let

ExpandH1(*h₁*) = (*ϵk*)*k∈*[*τ*]*,*

ExpandH2(*h₂*) = (¯*ik*)*k∈*[*τ*]*,*

|||) = ((m ,I|)|,com)|
|---|---|---|---|---|
|||k k|i i∈I||
|¯i|k|k k|k|i i∈I|
|N|k||||

Recon(salt*,*pdecom *∗k∗i i∈Ik∗* {} where*m* *k∗* =*⊥*and*I ∗* = [*N*]*\* ¯*i ∗*. Then, we have

### Verify(salt,com,pdecom ∗,I ∗) = (m)k∗.

If(*m₁,...,m*)*/∈*Ext(com*,∆ ∗*), it means that there are more than*u*messages to be extracted (which is inhibited by the definition of the extractor). One can directly construct adversary*C*against semi-binding security ofVSCusing*A*as subroutine, so

|||u|
|---|---|---|
|N|k|IC--esb VSC|
|N|k||

### Pr [Awins∧(m₁,...,m)/∈Ext(com,∆ ∗)|¬Bad]≤Adv (C).(6)

Now assume that(*m₁,...,m*)*∈*Ext(com*,∆ ∗*). Since the bad events are only checked in*H₁* and*H₂*, the only chance to forgery is that additional ideal cipher queries after queries to*H₁* and*H₂* makes extra extracted messages to pass the challenges. It is equivalent to the event that the additional ideal cipher queries incurBad₄ orBad₅. From the probability computation above, we have

<u>4νQ₁ 14P</u> Pr [*A*wins*∧*(*m₁,...,mN*)*∈*Ext(com*,∆k∗*)*|¬*Bad]*≤* *λ* + *λ*

*.*(7)
2 2

### We conclude the proof by combining5,6and7.⊓⊔

The EUF-CMA security is proved by game hopping technique as in the original BN++ scheme. Between the adjacent games, the security proof of BN++ mainly replaces a set of strings to random ones. Similarly, the security proof of rBN++ replaces strings in a straightforward manner, except one: commitment. Since the commitment size is*λ*bits, commitments cannot be replaced by random strings. This step is described inG₆. Because of the page limit, we provide the sketch here and refer to Supplementary MaterialCfor the full proof.

**Theorem 2(EUF-CMA Security of rBN++).***Assume thatH₀,H₁,H₂,* ExpandH1*,*ExpandH2*, and*ExpandSalt*are modeled as random oracles and that* *the*(*N,τ,λ*)*parameters of rBN++ are appropriately chosen where|*F*|*= 2 *λ* *. For* *a PPT adversaryAagainst the EUF-CMA security of rBN++ with a total of* *Q*sig*signing oracle queries,Qrandom oracle queries, andPideal cipher queries,* *there exist PPT adversaries*

**–***Bagainst the EUF-KO security of rBN++,* 2

**–***Cagainst the PRF security ofH₃,* 3

### –Dagainst the multi-instance hiding security ofIC-VSC

*such that*

<u>(Q +Q)</u>

|euf-cma|sig 2||prf|
|---|---|---|---|
|rBN++ sig|2λ τQ-mih IC-VSC (2C 2 +4)N|sig|H euf-ko rBN++|

**Adv** (*A*)*≤* +*Q ·***Adv** 3

(*C*)
2 sig +**Adv** (*D*) +**Adv** (*B*)*,* { <u>5(λ−24)</u> *λ−*1 } *provided thatτ·Q ≤*min 26*,.*

*Proof(Sketch).*Let*A*be an EUF-CMA adversary against rBN++ for given pk. LetG₀ be the original EUF-CMA game. Let*O*sigbe the signing oracle, and let*Qi*for*i*= 0*,*1*,*2be the number of queries made to*Hi*by*A*. We only prove the security of the deterministic version of rBN++ (*ρ←*0 *n* ) here. Without loss of generality, we assume that all messages in signing queries are distinct.

G₁:This game acts the same asG₀ except that it aborts if there exist two different queries on*H₀* with the same outputs. As the output length of*H₀* is2*λ*, the abort probability is negligible. G₂: *O*sigreplacessalt*∈{*0*,*1*}* 2*λ* with randomly sampled values, instead of com- puting*H₃*(sk*,µ,ρ*). As*µ*is always distinct for each query, the difference between this game and the previous one reduces to the PRF security of*H₃* with secret keysk. G₃: *O*sigsamples*h₁ ∈{*0*,*1*}* 2*λ* at random instead of computing*H₁*(*·*), and pro- grams the random oracle*H₁* to output*h₁* for the respective query. The simulation is aborted if the queries to*H₁* have been made previously in a 2 We assume*B*has the same amount of queries to random oracles. 3 *H₃* itself is not a PRF, but it is used as a PRF with key prepending. We use this notation for convenience.

signing oracle query. Assalt*∈ {*0*,*1*}* 2*λ* is random, this game is indistin- guishable from the previous game unless the simulation is aborted, and the probability of abort is negligible.

G₄: *O*signow samples*h₂ ∈{*0*,*1*}* 2*λ* at random instead of computing*H₂*(*·*), and also program the random oracle*H₂* to output*h₂* for the respective query. The simulation is aborted if the queries to*H₂* have been made previously in a signing oracle query. As*h₁ ∈{*0*,*1*}* 2*λ* is random, this game is indistin- guishable with the previous game unless the simulation is aborted, and the probability of abort is negligible.

G₅: *O*signow samples(salt₁*,...,*salt*τ*)*∈{*0*,*1*}* 2*τλ* at random instead of comput- ingExpandSalt(*·*), and also program the random oracleExpandSaltto output (salt₁*,...,*salt*τ*)for the respective query. The simulation is aborted if the queries toExpandSalthave been made previously in a signing oracle query. Assalt*∈{*0*,*1*}* 2*λ* is random, this game is indistinguishable with the previ- ous game unless the simulation is aborted, and the probability of abort is negligible. (¯*ik*) G₆:For each*k∈*[*τ*],*O*sigreplaces the hidden tapetape *k* by a random ele- ment inF² *C*+2. Since(decom*i*)*i∈*[*τ*]is computed independently fromsk, the distribution of(pdecom*i*)*i∈*[*τ*]is also independent tosk. The difference betweenG₅ andG₆ is bounded by the multi-instance hiding advantage ofIC-VSC.

G₇: *O*sigreplaces(*∆*sk*k,∆ck,*(*∆zk,j*)*j∈*[*C*])*k∈*[*τ*]with random elements instead of computing them usingskand S-box outputs. As the hidden tapes are random, the distribution of these variables does not change. (¯*ik*)∑(*i*) If the multiplication triple is wrong, then*v* *k* *←−i̸*=¯*i* *k* *v* *k* is different from an honest value derived from legitimate calculation. However,(¯*ik*)is unopened and the multiplication check is still passed. Since the signature oracle inG₇ does not depend on the secret keysk, it implies thatG₇ can be reduced to the EUF-KO security.

This proves the theorem. *⊓⊔*

### 4.3 Parameters and Efficiency

The parameters*N*and*τ*can be chosen to prevent the soundness attack [21]. As in the EUF-KO security proof, since the vector semi-commitment allows*u* valid partial decommitment information, the complexity of the soundness attack is slightly different from the original BN++ paper. The total complexity of the

attack*C*is computed as

∑ *τ*( *τ* )( <u>u</u> )*k*( <u>u</u> )*τ−k* *P₁* = *·* 1*−* *′* *k |*F*| |*F*|* *k*=*τ* <u>1</u> *P₂* = *τ−τ′* *N* *C*= min *′* (1*/P₁* + 1*/P₂*)*.* 0*≤τ ≤τ*

If the field size*|*F*|*is large enough, then*τ* *′* remains unchanged and it implies (*N,τ*)in rBN++ is same as the original BN++. For a small field,*τ*may be required to be much larger. Efficiency improvements of rBN++ can be explained by the reduced number of random oracle calls and reduced signature size. In the literature, random ora- cles are implemented as a comparatively heavy hash functions such as SHAKE, whereas pseudorandom generators and ideal ciphers are implemented using the AES block cipher. In rBN++, the random oracle calls for commitments are translated into ideal cipher calls, and PRG calls for GGM trees are translated into a halved number of ideal cipher calls. Signature size is reduced by*τλ*bits due to reduced commitment size. The results are summarized in Table1. In this table, it is assumed that the secret key size is*λ*bits.

|Scheme|Field|N τ|RO|PRG or IC|Sig. size|
|---|---|---|---|---|---|
||Size||call|call|(B)|
|BN++|2 2|16 33 256 17|5321056C+ 1518 43568704C+ 13022||1056C+ 3792 544C+ 3088|
|rBN++|2 2|16 33 256 17|51056C+ 2079 58704C+ 17391||1056C+ 3264 544C+ 2816|

128 128 128 128

Table 1: Parameter sets for 128 bit security and the number of calls to the

random oracles and the ideal cipher. Repeated multiplier is not applied for both schemes.

## 5 Performance

As many MPCitH-based signature schemes (specifically the first round candi- dates in the NIST call for additional post-quantum signatures) have similar forms with BN++, our improvements can be applied (possibly with some tweaks). However, our improvements may not be always applied in the best way for ef- ficiency; if the probability of passing the first challenge is tight enough before applying our improvements (e.g., SDitH-L1-hyp [29] has the probability2 *−*71*.*2 ), the application involves increasing*τ*for security. We chooseAIMerv2.0 [27] for

the performance measurement, as it is the best scheme for efficiency improve- ment. We will call it*reduced AIMer*(rAIMer). For application to similar non- interactive zero-knowledge proofs such as Threshold-Computation-in-the-Head (TCitH) [15] and VOLE-in-the-Head (VOLEitH) [4], we leave it as future work.

*Environment.*We developedrAIMerin C, with AVX2 instructions. A significant 4 portion of our implementation is based on the AIMer v2.0 source code. For other schemes, we used packages that have been officially submitted to NIST PQC standardization project, and all were compiled using the default options in compilation script. Our experiments were measured in AMD Ryzen Threadripper PRO 5995WX 64-cores with 128GB memory. For a fair comparison, we measure the execution time for each signature scheme on the same CPU using thetaskset command.

|Scheme||||pk|||sig|Sign||Verify|
|---|---|---|---|---|---|---|
||||(B)|(B)|(Kc)|(Kc)|
|Dilithium2 [28]|||1,312|2,420|162|57|
|SPHINCS|-128f|[18]|32|17,088|38,216|2,158|
|SPHINCS|-128s|[18]|32|7,856|748,053|799|
|SDitH-Hypercube-gf256 [29]|||132|8,496|20,820|10,935|
|FAEST-128f [3]|||32|6,336|2,387|2,344|
|FAEST-128s [3]|||32|5,006|20,926|20,936|
|AIMer-v2.0-128f [27]|||32|5,888|788|752|
|AIMer-v2.0-128s [27]|||32|4,160|5,926|5,812|
|rAIMer-128f|||32|5,376|421|395|
|rAIMer-128s|||32|3,904|2,826|2,730|

+ *∗* + *∗*

*: -SHAKE256-simple

Table 2: Performance comparison of post-quantum signature schemes.

In Table2, we compare the performance ofrAIMerwith various post-quantum signature schemes. We measured all the benchmarks of listed schemes in the same environment, and the table only contains publicly available implementations. It lists different schemes along with their respective public key sizes (*|pk|*), signature sizes (*|sig|*), signing times (Sign), and verification times (Verify). The sizes are provided in bytes (B), while the times for signing and verification are given in kilo-cycles (Kc). The table includes NIST-selected schemes Dilithium2, and + SPHINCS, as well as the first round MPCitH-based candidates of the NIST call for additional signatures like SDitH, FAEST, andAIMer. From the data, we observe significant improvements inrAIMercompared to AIMerv2.0.rAIMerenjoys up to 109% faster signing and 112% faster verification,

4 [https://aimer-signature.org/](https://aimer-signature.org/)

as well as up to 8.7% smaller signature sizes. Compared to other MPCitH-based signature schemes,rAIMerenjoys the fastest signing and verification times and smallest signature sizes. When compared with selected algorithms,rAIMershows significant superiority in performance compared to SPHINCS +, while it is quite inefficient compared to Dilithium. Additionally,rAIMercan be combined with the proof-of-work technique pro- posed in [2]. With this technique, the signature size of 128-bit securerAIMer becomes 5.1 KB (fast) / 3.7 KB (small) without a significant performance degra- dation. See Supplementary MaterialDfor the details.

## References

1.Aguilar-Melchor, C., Gama, N., Howe, J., Hülsing, A., Joseph, D., Yue, D.: The return of the SDitH. In: EUROCRYPT 2023. pp. 564–596. Springer (2023)
2.Baum, C., Beullens, W., Mukherjee, S., Orsini, E., Ramacher, S., Rechberger, C., Roy, L., Scholl, P.: One Tree to Rule Them All: Optimizing GGM Trees and OWFs for Post-Quantum Signatures. Cryptology ePrint Archive, Paper 2024/490 (2024), [https://eprint.iacr.org/2024/490](https://eprint.iacr.org/2024/490)
3.Baum, C., Braun, L., de Saint Guilhem, C.D., Klooß, M., Majenz, C., Mukherjee, S., Orsini, E., Ramacher, S., Rechberger, C., Roy, L., Scholl,
P.: FAEST. Technical report, National Institute of Standards and Technol- ogy, 2023 (2023), available at[https://csrc.nist.gov/Projects/pqc-dig-sig/](https://csrc.nist.gov/Projects/pqc-dig-sig/) round-1-additional-signatures
4.Baum, C., Braun, L., de Saint Guilhem, C.D., Klooß, M., Orsini, E., Roy, L., Scholl, P.: Publicly Verifiable Zero-Knowledge and Post-Quantum Signatures from VOLE-in-the-Head. In: Handschuh, H., Lysyanskaya, A. (eds.) CRYPTO 2023. pp. 581–615. Springer Nature Switzerland, Cham (2023)
5.Baum, C., Nof, A.: Concretely-Efficient Zero-Knowledge Arguments for Arithmetic Circuits and Their Application to Lattice-Based Cryptography. In: PKC 2020. pp. 495–526. Springer (2020)
6.Baum, C., Saint Guilhem, C.D.d., Kales, D., Orsini, E., Scholl, P., Zaverucha, G.: Banquet: Short and fast signatures from AES. In: PKC 2021. pp. 266–297. Springer (2021)
7.Beullens, W.: Sigma protocols for mq, pkp and sis, and fishy signature schemes. In: Canteaut, A., Ishai, Y. (eds.) EUROCRYPT 2020. pp. 183–211. Springer In- ternational Publishing, Cham (2020)
8.Bui, D., Carozza, E., Couteau, G., Goudarzi, D., Joux, A.: Short Signatures from Regular Syndrome Decoding, Revisited. Cryptology ePrint Archive, Paper 2024/252 (2024),[https://eprint.iacr.org/2024/252](https://eprint.iacr.org/2024/252)
9.Bui, D., Cong, K., de Saint Guilhem, C.D.: Improved all-but-one vector commit- ment with applications to post-quantum signatures. Cryptology ePrint Archive, Paper 2024/097 (2024),[https://eprint.iacr.org/2024/097](https://eprint.iacr.org/2024/097)
10.Cui, H., Liu, H., Yan, D., Yang, K., Yu, Y., Zhang, K.: ResolveD: Shorter signatures from regular syndrome decoding and vole-in-the-head. In: PKC 2024. pp. 229–258. Springer (2024)
11.Dobraunig, C., Kales, D., Rechberger, C., Schofnegger, M., Zaverucha, G.: Shorter Signatures Based on Tailor-Made Minimalist Symmetric-Key Crypto. In: ACM CCS 2022. pp. 843–857. Association of Computing Machinery

(November 2022),[https://www.microsoft.com/en-us/research/publication/](https://www.microsoft.com/en-us/research/publication/) shorter-signatures-based-on-tailor-made-minimalist-symmetric-key-crypto/

12.Don, J., Fehr, S., Majenz, C.: The Measure-and-Reprogram Technique 2.0: Multi- Round Fiat-Shamir and More. In: CRYPTO 2020. p. 602–631. Springer (2020)
13.Feneuil, T.: Building MPCitH-based Signatures from MQ, MinRank, Rank SD and PKP. Cryptology ePrint Archive (2022)
14.Feneuil, T., Joux, A., Rivain, M.: Syndrome Decoding in the Head: Shorter Signa- tures from Zero-Knowledge Proofs. In: Dodis, Y., Shrimpton, T. (eds.) CRYPTO
2022. pp. 541–572. Springer Nature Switzerland, Cham (2022)
15.Feneuil, T., Rivain, M.: Threshold Computation in the Head: Improved Framework for Post-Quantum Signatures and Zero-Knowledge Arguments. Cryptology ePrint Archive, Paper 2023/1573 (2023),[https://eprint.iacr.org/2023/1573](https://eprint.iacr.org/2023/1573)
16.Goldreich, O., Goldwasser, S., Micali, S.: How to Construct Random Functions.
J. ACM**33**(4), 792–807 (aug 1986).[https://doi.org/10.1145/6490.6503,https:](https://doi.org/10.1145/6490.6503,https:) //doi.org/10.1145/6490.6503
17.Guo, X., Yang, K., Wang, X., Zhang, W., Xie, X., Zhang, J., Liu, Z.: Half-tree: Halving the cost of tree expansion in cot and dpf. In: EUROCRYPT 2023. pp. 330–362. Springer (2023)
18.Hulsing, A., Bernstein, D.J., Dobraunig, C., Eichlseder, M., Fluhrer, S., Gazdag,
S.L., Kampanakis, P., Kolbl, S., Lange, T., Lauridsen, M.M., Mendel, F., Niederha- gen, R., Rechberger, C., Rijneveld, J., Schwabe, P., Aumasson, J.P., Westerbaan,
B., Beullens, W.: SPHINCS+. Technical report, National Institute of Standards and Technology, 2022 (2022), available at[https://csrc.nist.gov/Projects/](https://csrc.nist.gov/Projects/) post-quantum-cryptography/selected-algorithms-2022
19.Huth, J., Joux, A.: Mpc in the head using the subfield bilinear collision problem. In: Reyzin, L., Stebila, D. (eds.) Advances in Cryptology – CRYPTO 2024. pp. 39–70. Springer Nature Switzerland, Cham (2024)
20.Ishai, Y., Kushilevitz, E., Ostrovsky, R., Sahai, A.: Zero-knowledge from Secure Multiparty Computation. In: ACM STOC 2007. pp. 21–30 (2007)
21.Kales, D., Zaverucha, G.: An Attack on Some Signature Schemes Constructed from Five-Pass Identification Schemes. In: Krenn, S., Shulman, H., Vaudenay, S. (eds.) Cryptology and Network Security. pp. 3–22. Springer International Publishing, Cham (2020)
22.Kales, D., Zaverucha, G.: Efficient Lifting for Shorter Zero-Knowledge Proofs and Post-Quantum Signatures. Cryptology ePrint Archive, Paper 2022/588 (2022), [https://eprint.iacr.org/2022/588](https://eprint.iacr.org/2022/588)
23.Katz, J., Kolesnikov, V., Wang, X.: Improved Non-Interactive Zero Knowledge with Applications to Post-Quantum Signatures. In: ACM CCS 2018. pp. 525–537. ACM (2018)
24.Kim, S., Ha, J., Son, M., Lee, B., Moon, D., Lee, J., Lee, S., Kwon, J., Cho, J., Yoon, H., Lee, J.: Aim: Symmetric primitive for shorter signatures with stronger security. In: Proceedings of the 2023 ACM SIGSAC Conference on Computer and Communications Security. p. 401–415. CCS ’23, Association for Computing Ma- chinery, New York, NY, USA (2023).[https://doi.org/10.1145/3576915.3616579](https://doi.org/10.1145/3576915.3616579), [https://doi.org/10.1145/3576915.3616579](https://doi.org/10.1145/3576915.3616579)
25.Kosuge, H., Xagawa, K.: New Security Proofs of MPC-in-the-Head Signatures in the Quantum Random Oracle Model. Cryptology ePrint Archive, Paper 2025/1999 (2025),[https://eprint.iacr.org/2025/1999](https://eprint.iacr.org/2025/1999)
26.Kosuge, H., Xagawa, K.: Private communication (September 2025)

27.Lee, J., Cho, J., Ha, J., Kim, S., Kwon, J., Lee, B., Lee, J., Lee, S., Moon, D., Son, M., Yoon, H.: The AIMer Signature Scheme (2024), version 2.0, available at [https://kpqc.or.kr/competition_02.html](https://kpqc.or.kr/competition_02.html)
28.Lyubashevsky, V., Ducas, L., Kiltz, E., Lepoint, T., Schwabe, P., Seiler, G., Stehlé, D., Bai, S.: CRYSTALS-DILITHIUM. Technical report, National Institute of Standards and Technology, 2022 (2022), available at[https://csrc.nist.gov/](https://csrc.nist.gov/) Projects/post-quantum-cryptography/selected-algorithms-2022
29.Melchor, C.A., Feneuil, T., Gama, N., Gueron, S., Howe, J., Joseph, D., Joux, A., Persichetti, E., Randrianarisoa, T.H., Rivain, M., Yue, D.: The Syndrome Decoding in the Head (SD-in-the-Head) Signature Scheme (2023), available athttps:// csrc.nist.gov/Projects/pqc-dig-sig/round-1-additional-signatures
30.de Saint Guilhem, C.D., Orsini, E., Tanguy, T.: Limbo: Efficient Zero-Knowledge MPCitH-Based Arguments. In: ACM CCS 2021. p. 3022–3036. Association for Computing Machinery (2021)
31.Zaverucha, G., Chase, M., Derler, D., Goldfeder, S., Orlandi, C., Ramacher, S., Rechberger, C., Slamanig, D., Katz, J., Wang, X., Kolesnikov, V., Kales, D.: Pic- nic. Technical report, National Institute of Standards and Technology, 2020 (2022), available at[https://csrc.nist.gov/projects/post-quantum-cryptography/](https://csrc.nist.gov/projects/post-quantum-cryptography/) round-3-submissions

# Supplementary Material

## A Description of the rBN++ Signature Scheme

### Algorithm 5.Sign(sk,pk,m)- reduced BN++, signing algorithm.

//Phase 1: Committing to the views of the parties. **1**Compute the hash of the message: *µ←H₀*(pk*,m*) **2**Sample randomness: *ρ←*$*{*0*,*1*}* *λ* (*ρ←*0 *λ* for deterministic signature) **3**Compute salt:salt*←H₃*(sk*,µ,ρ*),(salt*k*)*k∈*[*τ*]*←*ExpandSalt(salt). **4for***each repetitionk∈*[*τ*]**do** **5**Sample a root seed:root*k←*$*{*0*,*1*}* *λ*.

(*i*)
**6**(com*k,*decom*k,*(tape *k* ) *i∈*[*N*])*←*IC-VSC*.*Commit(salt*k∥⟨k⟩B,*root*k*).

(*i*) (*i*)
**7**For each party*i*, samplesk *k* *←*Sample(tape *k* ).

(*N*) (*N*)
**8***∆*sk*k←*sk*−*root*k,*sk *k* *←*sk *k* +*∆*sk*k*. **9for***each gategwith indexj***do** **10if***gis an addition with inputs*(*xk,j,yk,j*)**then**

(*i*) (*i*) (*i*)
**11**For each party*i*, set the output share of*z* *k,j* =*x* *k,j* +*y* *k,j*.

**12if***gis a multiplication with inputs*(*xk,j,yk,j*)**then** **13**For each party*i*, sample an output share:

(*i*) (*i*)
*z* *k,j* *←*Sample(tape *k* ). **14**Compute output offset and adjust the last share: ∑(*i*) (*N*) (*N*) *∆zk,j*=*zk,j−iz* *k,j* ,*z* *k,j* *←z* *k,j* +*∆zk,j*. **15**For each party*i*, sample an helping values*a*:

(*i*) (*i*)
*a* *k,j* *←*Sample(tape *k* ). ∑(*i*) **16**Compute*ak,j*=*ia* *k,j* and set*bk,j*=*yk,j*. ∑ **17**Compute*ck*=*jak,j·bk,j*.

(*i*) (*i*)
**18**For each party*i*, sample*c* *k* *←*Sample(tape *k* ). ∑(*i*) **19**Compute offset and adjust the last share :*∆ck*=*ck−ic* *k*,

(*N*) (*N*) *c* *k* *←c* *k* +*∆ck*.
**20**Set*σ₁ ←*(salt*,*(com*k,∆*sk*k,∆ck,*(*∆zk,j*)*j∈*[*C*])*k∈*[*τ*]). //Phase 2: Challenging the checking protocol. **21**Compute challenge: *h₁ ←H₁*(*µ,σ₁*),((*ϵk,j*)*j∈*[*C*])*k∈*[*τ*]*←*ExpandH1(*h₁*). //Phase 3: Committing to the checking protocol. **22for***each repetitionk∈*[*τ*]**do** **23**Simulate the triple checking protocol as in Section2.4for all parties

(*i*) (*i*) (*i*) (*i*) (*i*) (*i*)
with challenge*ϵk,j*. The inputs are(*x* *k,j* *,y* *k,j* *,z* *k,j* *,a* *k,j* *,b* *k,j* *,c* *k* ),

(*i*) (*i*)
and let*α* *k,j* and*v* *k* be the broadcast values.

(*i*) (*i*)
**24**Set*σ₂ ←*(salt*,*(((*α* *k,j* ) *j∈*[*C*]*,vk*)*i∈*[*N*])*k∈*[*τ*]). //Phase 4: Challenging the views of the MPC protocol. Compute challenge hash: *h₂ ←H₂*(*h₁,σ₂*),(¯*ik*)*k∈*[*τ*]*←*ExpandH2(*h₂*). //Phase 5: Opening the views. **for***each repetitionk∈*[*τ*]**do** pdecom*k←*IC-VSC*.*Open((salt*,k*)*,*decom*k,*[*N*]*\{*¯*ik}*). (¯*ik*) Output*σ←*(salt*,h₁,h₂,*(pdecom*k,∆*sk*k,∆ck,*(*∆zk,j,α* *k,j* ) *j∈*[*C*])*k∈*[*τ*]).

**Algorithm 6.**Verify(pk*,m,σ*)- reduced BN++ signature scheme, ver- ification algorithm. (¯*ik*) **1**Parse*σ*as(salt*,h₁,h₂,*(pdecom*k,∆*sk*k,∆ck,*(*∆zk,j,α* *k,j* ) *j∈*[*C*])*k∈*[*τ*]). **2**Compute the hash value of the message: *µ←H₀*(pk*,m*) **3**Expand hashes:(salt*k*)*k∈*[*τ*]*←*ExpandSalt(salt), ((*ϵk,j*)*j∈*[*C*])*k∈*[*τ*]*←*ExpandH1(*h₁*), and(¯*ik*)*k∈*[*τ*]*←*ExpandH2(*h₂*).

**4for***each repetitionk∈*[*τ*]**do**

(*i*)
**5**((tape *k* ) *i∈*[*N*]*\{*¯*ik},*com*k*)*←* IC-VSC*.*Recon(salt*∥⟨τ⟩B,*pdecom*k,*[*N*]*\{*¯*ik}*). **6for***each partyi∈*[*N*]*\{*¯*ik}***do**

(*i*) (*i*)
**7**Samplesk *k* *←*Sample(tape *k* ). **8if***i*=*N***then**

(*i*) (*i*)
**9**Adjust the last share:sk *k* *←*sk *k* +*∆*sk*k*

**10for***each gategwith indexj***do** **11if***gis an addition with inputs*(*xk,j,yk,j*)**then**

(*i*) (*i*) (*i*)
**12**Compute the output share of*z* *k,j* =*x* *k,j* +*y* *k,j*.

(*i*) (*i*)
**13if***gis a multiplication with inputs*(*x* *k,j* *,y* *k,j* )**then**

(*i*) (*i*)
**14**Sample an output share: *z* *k,j* *←*Sample(tape *k* ). **15if***i*=*N***then**

(*i*) (*i*)
**16**Adjust the last share*ze,j←ze,j*+*∆ze,j*.

(*i*) (*i*) (*i*) (*i*)
**17**Sample*a* *k,j* *←*Sample(tape *k* ), and set*b* *k,j* =*y* *k,j*.

(*i*) (*i*)
**18**Sample*c* *k* *←*Sample(tape *k* ) **19if***i*=*N***then**

(*i*) (*i*)
**20**Adjust the last share*c* *k* *←c* *k* +*∆ck*.

(*i*)
**21**Letpk *k* be the final output shares. (¯*ik*)∑(*i*) **22**Computepk *k* =pk*−i̸*=¯*i* *k* pk *k*.

(*i*)
**23**Set*σ₁ ←*(salt*,*(com*k,*(pk *k* ) *i∈*[*N*]*,∆*sk*k,∆ck,*(*∆zk,j*)*j∈*[*C*])*k∈*[*τ*]). **24**Set*h* *′* 1*←H₁*(*µ,σ₁*). **25for***each parallel executionk∈*[*τ*]**do** **26for***each partyi∈*[*N*]*\{*¯*ik}***do** **27**Simulate the triple checking protocol as in Section2.4for all parties with challenge*ϵk,j*. The inputs are

(*i*) (*i*) (*i*) (*i*) (*i*) (*i*) (*i*) (*i*)
(*x* *k,j* *,y* *k* *,z* *k,j* *,a* *k,j* *,b* *k,j* *,c* *k* ), and let*α* *k,j* and*v* *k* be the broadcast values. (¯*ik*)∑(*i*) **28**Compute*v* *k* = 0*−i̸*=¯*i* *k* *v* *k*.

(*i*) (*i*)
**29**Set*σ₂ ←*(salt*,*(((*α* *k,j* ) *j∈*[*C*]*,vk*)*i∈*[*N*])*k∈*[*τ*]). **30**Set*h* *′* 2=*H₂*(*h* *′* 1 *,σ₂*). **31**OutputAcceptif*h₁* =*h* *′* 1and*h₂* =*h* *′* 2. **32**Otherwise, outputReject.

## B Proofs of Lemmas

### B.1 Proofs forRO-VSC

||com||λ tree|∗|λ||
|---|---|---|---|---|---|---|
||tree ′|λ||c|com 2λ|t|
|com|tree||com|tree|′||
|com|tree||com|tree|′|′|
||λ||||||

**Lemma 8***LetH* :*{*0*,*1*}* *∗* *→ {*0*,*1*},H* :*{*0*,*1*} → {*0*,*1*} be random* *oracles. LetAbe arbitrary adversary that makesQ queries toH andQ* *queries toH. Then, the probability thatAfinds*salt*∈{*0*,*1*},e,i∈*N*, and* *distinctn,n ∈{*0*,*1*} such that* { *H* (salt*,i,H* (salt*,e,i,n*)) =*H* (salt*,i,H* (salt*,e,i,n*))*,* *H* (salt*,i,*(*H* (salt*,e,i,n*)*⊕n*)) =*H* (salt*,i,*(*H* (salt*,e,i,n*)*⊕n*))

(8)
*is at most*8*Q/*2*.*

*Proof.*Without loss of generality, assume that*A*queries to the random oracles with fixedsalt*,e,*and*i*, and we omit thesalt,*e*, and*i*input for each random oracle query. At the end of the game, we define*H*tree(*x*) =*⊥*(resp.*H*com(*x*) =*⊥*) for non-queried input*x*to*H*tree(resp.*H*com), and we will consider that two*⊥*’s are not identical for simplicity. Let*H*tree(*n*) =*l*,*n⊕l*=*r*,*H*tree(*n* *′* ) =*l* *′*, and *n* *′* *⊕l* *′* =*r* *′*. We define { *′* 3*λ ′ ′* } *L₁* = (*n,l,l*)*∈{*0*,*1*}* : *H*tree(*n*) =*l,H*com(*l*) =*H*com(*l*)*,l̸*=*l,* { *′* 3*λ ′ ′* } *L₂* = (*n,r,r*)*∈{*0*,*1*}* : *H*tree(*n*)*⊕n*=*r,H*com(*r*) =*H*com(*r*)*,r̸*=*r,*

|{|||||}|||
|---|---|---|---|---|---|---|---|
||′|5λ|′||′|||
|||i|i i|c||||

*′ ′* 5*λ ′ ′* *L₃* = (*n,l,l,r,r*)*∈{*0*,*1*}* : (*n,l,l*)*∈L₁,*(*n,r,r*)*∈L₂*

### and auxiliary eventsAux fori∈[3], where

### Aux ⇔|L |> Q

and letAux=Aux₁ *∨*Aux₂ *∨*Aux₃. Then, by Markov’s inequality, we have ()

|Ex[|L₁|]||Q Q|Q Q|||
|---|---|---|---|---|---|
||c c c|t c c λ t c c λ t 2 c 2λc|t 2 2λc t 2 2λc t 3 3λ c|t 4 4λc||
|tree||||′||
|i||i||||
|′|′||com ′|com ′|′|
|tree||tree|com|com||

1 Pr [Aux₁]*≤ ≤* +*,* *Q Q* 2 2 () Ex[*|L₂|*] 1 *Q Q Q Q* Pr [Aux₂]*≤ ≤* +*,* *Q Q* 2 2 () Ex[*|L₃|*] 1 *Q Q* 2*Q Q Q Q* Pr [Aux₃]*≤ ≤* + +*.* *Q Q* 2 2 2

For each query*H* (*n*), we sayBadoccurs if there exists*n ̸*=*n*satisfies (8). Observing thatBadis the event of simultaneous two collisions, we divideBad into left collisionsL and right collisionsR, up to the freshness of*l*and*r*.

**–**L₁ *⇔l*=*l* or*l*is freshly queried, and*H* (*l*) =*H* (*l*). Then,*n*should satisfies

(*H* (*n*) =*l*)*∨*(*H* (*n*)*̸*=*l ∧H* (*l*) =*H* (*l*))*.*

**–**L₂ *⇔l*is not freshly queried,*l̸*=*l* *′*, and*H*com(*l*) =*H*com(*l* *′* ). Then,*n*should satisfies (*n* *′* *,l* *′* *,H*tree(*n*))*∈L₁.*

**–**R₁ *⇔r*=*r* *′* or*r*is freshly queried, and*H*com(*r*) =*H*com(*r* *′* ). Then,*n*should satisfies

|(H (n)⊕n=r|(n)⊕n̸=r|∧H|(r) =H||(r )).|
|---|---|---|---|---|---|
||′ ′|′ com||com|′|
||tree|||||

tree *′* )*∨*(*H*tree *′* com com *′*

**–**R₂ *⇔r*is not freshly queried,*r̸*=*r*, and*H* (*r*) =*H* (*r*). Then,*n* should satisfies (*n,r,H* (*n*)*⊕n*)*∈L₂.*

We have ∑ Pr [Bad]*≤*Pr [Aux] + Pr [L*i∧*R*j∧¬*Aux] *i,j∈*[2] *≤*Pr [Aux] + Pr [L₁ *∧*R₁] + Pr [L₂ *∧*R₁ *∧¬*Aux₁] + Pr [L₁ *∧*R₂ *∧¬*Aux₂] + Pr [L₂ *∧*R₂ *∧¬*Aux₃]

Each term can be bounded as follows.

**–**Pr [L₁ *∧*R₁]: This can be divided into 4 sub-cases;L₁ has 2 cases, andR₁ has 2cases. The first case –*l*=*l* *′* and*r*=*r* *′* at the same time – cannot achieved since it implies*n*=*n* *′*. Since the probability of each sub-cases is is upper bounded by*Q²t/*2 2*λ*, this case is upper bounded by3*Q²t/*2 2*λ*. **–**Pr [L₂ *∧*R₁ *∧¬*Aux₁]: SinceL₂ and*r*=*r* *′* cannot happen at the same time, this probability is upper bounded by*QtQc/*2 2*λ*. **–**Pr [L₁ *∧*R₂ *∧¬*Aux₂]: Similarly as the previous case, this is upper bounded by*QtQc/*2 2*λ*. **–**Pr [L₂ *∧*R₂ *∧¬*Aux₃]:L₂ *∧*R₂ means that(*n,l,l* *′* *,r,r* *′* )*∈L₃*. So, this proba- bility is upper bounded by*Qc/*2 *λ*.

Then, we have

2*Qt*+*Qc*3*Q²t*+ 5*QtQc*2*QtQ² QtQ³* 8*Q*

||+||+|+|≤|
|---|---|---|---|---|---|
|c t|λ−1|2λ|3λ c|4λc|λ|
|com|∗|λ|tree|∗|λ|
|||||u-esb RO-VSC||
|λλ 2 log|u-esb RO-VSC||λ|||

Pr [Bad]*≤* *λ* 2*λ* 3*λ c* 4*λc λ* 2 2 2 2 2

provided that*Q* +*Q ≤Q≤*2, which concludes the proof.*⊓⊔*

**Lemma 3***LetH* :*{*0*,*1*} →{*0*,*1*} andH* :*{*0*,*1*} →{*0*,*1*} be random* *oracles. LetAbe an arbitrary adversary that makesQqueries to the random* *oracles. ThenA’su-extractable semi-binding advantage***Adv** (*A*)*against* RO*-*VSC*is bounded by* <u>10Q</u> **Adv** (*A*)*≤,* 2 () *foru*= 2*N.*

*Proof.*Intuitively, according to Lemma8, the probability of finding a collision in commitments derived by a non-leaf node is negligible. Furthermore, for each leaf node, the number of multi-collisions is bounded by Chernoff bound. We now proceed to formally bound the adversary’s advantage. Let*Qt*be the number of queries to*H*treeand*Qc*be the number of queries to *H*com. Without loss of generality, assume that*A*queries to random oracles with fixedsalt, and we omit thesaltinput for each random oracle query. Let*Qt*and *Qc*be the collection of queries to*H*treeand*H*com, respectively. At the end of the game, we define*H*tree(*x*) =*⊥*(resp.*H*com(*x*) =*⊥*) for non-queried input*x*to *H*tree(resp.*H*com), and we consider that two*⊥*’s are not identical for simplicity. We first define the extractorExt(*Qt,Qc,*com= (com₁*,...,*com*N*))as follows.

1.For each*i∈*[*N*], find*Sd,i*such that
### Sd,i={s: Hcom(i,s) =comi}

2.For each*e∈*[*d−*1]and*i∈*[2
*e*], find*Se,i*such that

### Se,i={s: Htree(e+ 1,i,s)∈Se+1,2i−1,Htree(e+ 1,i,s)⊕s∈Se+1,2i}

3.For*i∈*[*N*], let
{}

|A = (p₁,...,p|) :p|∈S fore∈[d]|
|---|---|---|
|i d−e|d e|e,i|

*e*

where*ie*= (*⌊*(¯*i−*1)*/*2 *⌋⊕*1) + 1for*e∈*[*d*]

4.Let*S*be the set of messages, where { *S*= (*s₁,...,sd,i*=*∅*and*s* otherwise*,*

|) :s|=⊥ifS|∈S|
|---|---|---|
|N|i|i d,i|
|d|i|i i∈I|

}
Recon(*p₁,...,p,*com*,I*= [*N*]*\{i}*) = (*s*) for(*p₁,...,pd*)*∈Ai*

5.Finally,Extoutputs arbitrary*u*or less elements in*S*.
### We define some bad events.

**–**Bad₁ *⇔*there exists*e∈*[*d−*1]and*i∈*[2 *e*]such that*|Se,i|≥*2. **–**Bad₂ *⇔*there exists*i∈*[*N*]such that*|Sd,i|≥*2*λ/*log*λ*.

By Lemma8and (1), <u>10Q</u> Pr [Bad₁ *∨*Bad₂]*≤* *λ*

(9)
2 In the following, we analyze the extracting condition without bad events.

**–**As*S*contains all possible(pdecom*I,I*),*A*wins the game only if*|S|≥u*. ∑ **–**By*¬*Bad₁, we have*|S|≤i∈*[*N/*2]*|Sd,*2*i|·|Sd,*2*i−*1*|*. Then, by*¬*Bad₂, we have

()2 <u>λ</u> *|S|≤*2*N.* log*λ*

Therefore,*A*cannot win the game without bad events so we have

*u*-esb<u>10Q</u> **Adv**RO-VSC(*A*)*≤*Pr [Bad₁ *∨*Bad₂]*≤* *λ* 2 ()2 provided that*u*= 2*N* log <u>λ</u> *λ* .*⊓⊔*

||com|∗||λ tree|∗|
|---|---|---|---|---|---|
|∗|∗|||||
|Q mih||||||
|RO--VSC|t||Q mih RO--VSC|I 2λ tree|λ c|
|com|e|||exp|I|

**Lemma 4***LetH* :*{*0*,*1*} →{*0*,*1*},H* :*{*0*,*1*} →{*0*,*1*}* *λ* *, andH*exp: *{*0*,*1*} →{*0*,*1*} be random oracles. LetAbe an arbitrary adversary that makes* *Qqueries to the random oracles. ThenA’s multi-instance hiding advantage* **Adv** *I*

(*A*)*against*RO*-*VSC*is bounded by*
*I*<u>Q² Q</u> **Adv** (*A*)*≤* +*.* 2 2

*Proof.*Let*Q* be the number of queries to*H*,*Q* be the number of queries to*H*, and*Q* be the number of queries to*H*. Let*Q* be the number of instances. We will bound the advantage using the H-coefficient technique. Denote*I*as the ideal world where the hidden nodes are always replaced with random strings, and denote*R*the real world where the hidden nodes are remain unchanged. Let *γ*be the transcript of*A*which contains queries to the random oracles and the instances given in the game. The parent node of the hidden seed nodeis derived by node=seed¯*i⊕*seed((¯*i−*1)*⊕*1)+1. At the end of the game,rootis given to the adversary complimentarily for the convenience of probability computation. Since it is given after whole game, the adversary cannot additionally query to all the oracles afterrootis given. Afterrootis given, an adversary learns random oracle queries from the tree con- struction, commitment, and tape generation. If these queries are inconsistent – either internally or with the adversary’s own queries – the adversary can dis- tinguish the ideal world from the real world. Otherwise, the two worlds remain indistinguishable. Now we define some events of bad transcripts as follows. These bad events describes the collision between adversary’s random oracle queries and random oracle queries derived from instances.

**–**Bad₁: twosalt’s in the given instance collide. Sincesaltis sampled uniformly at random,Pr[Bad₁]*≤Q²I/*2 2*λ*. **–**Bad₂: a query(salt*,i,*seed<u>¯i</u> com *c* *λ*

|||)is queried toH||.Pr[Bad₂ ∧¬Bad₁]≤Q|/2.|
|---|---|---|---|---|---|
|||¯i i||com tree exp|c λ t λ e λ|
|Bad||||Good||
|id|re I||¯i||Good|
||id||re|Q+Q λ||

**–**Bad₃: a query(salt*,e,i,* node) is queried to*H*.Pr[Bad₃ *∧¬*Bad₁]*≤Q /*2. **–**Bad₄: a query(salt*,i,*seed)is queried to*H*.Pr[Bad₄ *∧¬*Bad₁]*≤Q /*2.

We say*T* be the set of bad transcripts, while*T* be the complement of *T*Bad, and let*T* (resp.*T*) be the distribution of*γ*in*I*(resp.*R*). As*Q*random oracle queries and*Q* instances of*m* are included in transcripts, for*γ∈T*, () *I* <u>1</u> Pr[*T* =*γ*] = Pr[*T* =*γ*] =*.* 2

So, the advantage is bounded by

*QI*mih<u>Q²IQ</u> **Adv** RO--VSC

(*A*)*≤* 2*λ* +
*λ* *.* 2 2 *⊓⊔*

### B.2 Proofs forIC-VSC

In this section, we provide the proofs of Lemma5and7.

**Lemma 5***LetE*:*{*0*,*1*}* *λ* *×{*0*,*1*}* *λ* *→ {*0*,*1*}* *λ* *be an ideal cipher andσ*: *{*0*,*1*}* *λ* *→ {*0*,*1*}* *λ* *be an orthomorphism. LetAbe an arbitrary adversary that* *makesQqueries toE. Then, the probability thatAfinds*salt= (saltpt*,*saltkey*,*b)*∈* *{*0*,*1*}* *λ*+*λ*+8 *,i∈{*0*,*2*,...,*254*},and distinctn,n* *′* *∈{*0*,*1*}* *λ* *such that*    *Eσ*(*n*)*⊕E*saltkey(*n⊕*saltpt)(saltpt[: *λ−*24]*∥*b*∥⟨i⟩B∥⟨*0*⟩B*)   = *E ′ ′* (saltpt[: *λ−*24]*∥*b*∥⟨i⟩B∥⟨*0*⟩B*)*,* *σ*(*n*)*⊕E*saltkey(*n ⊕*saltpt)

(3)
 *Eσ*(*n*)*⊕E*salt(*n⊕*saltpt)*⊕n*(saltpt[: *λ−*24]*∥*b*∥⟨i*+ 1*⟩B∥⟨*0*⟩B*)   key = *E ′ ′ ′*(salt [: *λ−*24]*∥*b*∥⟨i*+ 1*⟩ ∥⟨*0*⟩*)*,* *σ*(*n*)*⊕E*saltkey(*n ⊕*saltpt)*⊕n* pt *B B*

*is at most*10*Q/*2 *λ* *.*

*Proof.*At the end of game, we define*Ek*(*x*) =*⊥*for non-queried input(*k,x*) to*E*, and we will consider that two*⊥*’s are not identical for simplicity. We also denotectr*l*=saltpt[: *λ−*24]*∥*b*∥⟨i⟩B∥⟨*0*⟩B*andctr*r*=saltpt[: *λ−*24]*∥*b*∥⟨i*+ 1*⟩B∥⟨*0*⟩B*for readability. Let*σ*(*n*)*⊕E*saltkey(*n⊕*saltpt) =*l*,*n⊕l*=*r*,*σ*(*n* *′* )*⊕* *E*saltkey(*n* *′* *⊕*saltpt) =*l* *′*, and*n* *′* *⊕l* *′* =*r* *′*. We define

*L₁* =*{*(*n,l,l* *′*

)*∈{*0*,*1*}* 3*λ*
: *σ*(*n*)*⊕E*saltkey(*n⊕*saltpt) =*l,* *El*(ctr*l*) =*El′*(ctr*l*)*,l̸*=*l* *′* *},*

*L₂* =*{*(*n,r,r* *′*

)*∈{*0*,*1*}* 3*λ*
: *σ*(*n*)*⊕E*saltkey(*n⊕*saltpt)*⊕n*=*r,* *Er*(ctr*r*) =*Er′*(ctr*r*)*,r̸*=*r* *′* *},* { *′ ′* 5*λ ′ ′* } *L₃* = (*n,l,l,r,r*)*∈{*0*,*1*}* : (*n,l,l*)*∈L₁,*(*n,r,r*)*∈L₂*

### and auxiliary eventsAuxjforj∈[3], where

### Auxj⇔|Lj|> Q

and letAux=Aux₁ *∨*Aux₂ *∨*Aux₃. Then, by Markov’s inequality, we have ( 2 3 ) Ex[*|L₁|*] 1 *Q Q* Pr [Aux₁]*≤ ≤* *λ* + 2*λ* *,* *Q Q* 2 2 ( 2 3 ) Ex[*|L₂|*] 1 *Q Q* Pr [Aux₂]*≤ ≤* *λ* + 2*λ* *,* *Q Q* 2 2 ( 3 4 5 ) Ex[*|L₃|*] 1 *Q* 2*Q Q* Pr [Aux₃]*≤ ≤* 2*λ* + 3*λ* + 4*λ* *.* *Q Q* 2 2 2

For each query*E*saltkey(*n⊕*saltpt), we sayBadoccurs if there exists*n* *′* *̸*=*n*satisfies

(3). Observing thatBadis the event of simultaneous two collisions, we divide Badinto left collisionsL*i*and right collisionsR*i*, up to the freshness of*l*and*r*. **–**L₁ *⇔l*=*l*
*′* or*l*is freshly queried, and*El*(*l⊕*saltpt) =*El′* (*l* *′* *⊕*saltpt). Then, *n*should satisfies

(*σ*(*n*)*⊕E*saltkey(*n⊕*saltpt) =*l* *′* )*∨* (*σ*(*n*)*⊕E*saltkey(*n⊕*saltpt)*̸*=*l* *′* *∧El*(ctr*l*) =*El′*(ctr*l*))*.*

**–**L₂ *⇔l*is not freshly queried,*l̸*=*l* *′*, and*El*(*l⊕*saltpt) =*El′* (*l* *′* *⊕*saltpt). Then, *n*should satisfies

(*n* *′* *,l* *′* *,σ*(*n*)*⊕E*saltkey(*n⊕*saltpt))*∈L₁.*

**–**R₁ *⇔r*=*r* *′* or*r*is freshly queried, and*Er*(*r⊕*saltpt) =*Er′* (*r* *′* *⊕*saltpt). Then,*n*should satisfies

(*σ*(*n*)*⊕E*saltkey(*n⊕*saltpt)*⊕n*=*r* *′* )*∨* (*σ*(*n*)*⊕E*saltkey(*n⊕*saltpt)*⊕n̸*=*r* *′* *∧Er*(ctr*r*) =*Er′*(ctr*r*))*.*

**–**R₂ *⇔r*is not freshly queried,*r̸*=*r* *′*, and*Er*(*r⊕*saltpt) =*Er′* (*r* *′* *⊕*saltpt). Then,*n*should satisfies

(*n* *′* *,r* *′* *,*(*σ*(*n*)*⊕E*saltkey(*n⊕*saltpt)*⊕n*)*∈L₂.*

We have ∑ Pr [Bad]*≤*Pr [Aux] + Pr [L*i∧*R*j∧¬*Aux] *i,j∈*[2] *≤*Pr [Aux] + Pr [L₁ *∧*R₁] + Pr [L₂ *∧*R₁ *∧¬*Aux₁] + Pr [L₁ *∧*R₂ *∧¬*Aux₂] + Pr [L₂ *∧*R₂ *∧¬*Aux₃]

Each term can be bounded as follows.

**–**Pr [L₁ *∧*R₁]: This can be divided into 4 sub-cases;L₁ has 2 cases, andR₁ has 2 cases. The first case –*l*=*l* *′* and*r*=*r* *′* at the same time – cannot achieved since it implies () *n*=*n* *′*. Since the probability of each sub-cases is is upper bounded by *Q* 2 */*(2 *λ* *−Q*) 2, this case is upper bounded by6*Q²/*2 2*λ*. **–**Pr [L₂ *∧*R₁ *∧¬*Aux₁]: SinceL₂ and*r*=*r* *′* cannot happen at the same time, this probability is upper bounded by*Q²/*2 2*λ*. **–**Pr [L₁ *∧*R₂ *∧¬*Aux₂]: Similarly as the previous case, this is upper bounded by*Q²/*2 2*λ*. **–**Pr [L₂ *∧*R₂ *∧¬*Aux₃]:L₂ *∧*R₂ means that(*n,l,l* *′* *,r,r* *′* )*∈L₃*. So, this proba- bility is upper bounded by*Q/*2 *λ*.

Then, we have

3*Q* 11*Q²* 2*Q³ Q⁴* 10*Q* Pr [Bad]*≤* *λ* + 2*λ* + 3*λ* + 4*λ* *≤* *λ* 2 2 2 2 2

provided that*Q≤*2 *λ−*1, which concludes the proof. *⊓⊔*

**Lemma 7***LetE*:*{*0*,*1*}* *λ* *×{*0*,*1*}* *λ* *→{*0*,*1*}* *λ* *be an ideal cipher. LetAbe an* *arbitrary adversary that makesQqueries toE. Then,A’s multi-instance hiding* *advantage***Adv** *Q* IC *I* *-*VSC *-*mih

(*A*)*against*IC*-*VSC*is bounded by*

|Q-mih||2|I|
|---|---|---|---|
|IC-VSC|I|λ (2C 2 +4)N||

*I*(3 + 5*N²* + (2*C*+ 8) 2 + log*N*)*Q* (25 + 24 log*N*)*Q* 2 **Adv** (*A*)*≤* + *λ* + *λ* *.* 2 2 2 { <u>5(λ−24)</u> *λ−*1 } *provided thatQ ≤*min 26*,.*

*Proof.*We will bound the advantage using the H-coefficient technique. Denote *I*the ideal world where the hidden tapes are always replaced to random strings, and denote*R*the real world where the hidden tapes are unchanged. Let*T*be the transcript of*A*which contains queries to the ideal cipher and the instances given in the game. At the end of the game,rootis given to the adversary complimentarily for the convenience of probability computation. Since it is given after whole game, the adversary cannot additionally query to all the oracles afterrootis given. Afterrootis given, an adversary learns ideal cipher key, input, output relations from the tree construction, commitment, and tape generation. If these queries are inconsistent – either internally or with the adversary’s own queries – the adversary can distinguish the ideal from the real. Otherwise, the two worlds remain indistinguishable. Define*Q*as the set of the ideal cipher query made by the adversary. Let*Q*node (resp.*Q*com*,Q*tape) denote the set of the ideal cipher key-input-output relations learned from the tree construction (resp. commitment, tape generation). Specif- ically,(*K,X,Y*)*∈ Q•*for*• ∈ {*node*,*com*,*tape*}*(or nothing) means that the query*EK*(*X*) =*Y*is got from*•*. Additionally, define*Q*ctras*Q*com*∪Q*tape. For ( ¯

*i*)
each instance, parsesalt= (saltpt*,*saltkey*,*b)and defineseed is the hidden seed computed after receivingroot. And defineanc*e−*1for*e∈{*2*,...,d}*as follows. If it is not confusing, we will omit subscript*j∈*[*QI*]which is the instance index.

( ¯

*i*)
anc*d*=seed anc*e−*1=anc*e⊕*node*e,*((*ie−*1)*⊕*1)+1 ⌊ *d−e* ⌋ where*ie*:= (¯*i−*1)*/*2 +1. We note thatnode*e,*((*ie −*1)*⊕*1)+1is the sibling node ofnode*e,ie*. In the real world,anc*e*=node*e,ie*represents the ancestor ofnode*d,*¯*i* in the GGM tree at level*e∈*[*d*]. We give graphical description in Figure5. ( ¯

*i*)
Let*∆*=seed *⊕*node*d,*¯*i*wherenode*d,*¯*i*is the real hidden seed from the real GGM tree evaluation. By the correlation property,*∆*remains the same across

root

node₁*,*1 node₁*,*2 =anc₁

node₂*,*2 node₂*,*1node₂*,*3node₂*,*4 =anc₂

node₃*,*3 node₃*,*1node₃*,*2node₃*,*4node₃*,*5node₃*,*6node₃*,*7node₃*,*8 =anc₃

Fig.5: The seed tree. If the red seed is hidden,anc₁*,...,*anc*e*will be the ancestor of hidden node.

||e|e,i||||λ|
|---|---|---|---|---|---|---|
||||||λ||
|||||||node|
|e||e,i key|e−1|pt e|e−1||
||node||||||
|e|key|e,i e−1|pt|e,((i −1)⊕1)+1|e−1||
||node||||||

all instance andanc =node*e⊕∆*for all*e∈*[*d*]. In the real world,*∆*= 0, whereas in the ideal world,*∆*is chosen randomly from*{*0*,*1*}*. For each instance and*e∈{*2*,...,d}*, the following queries are added to*Q*.

**–**If*i* is odd (i.e.,node*e*is the left child), then the query

### (salt,anc ⊕salt,anc ⊕σ(anc))

is added to*Q*. **–**If*i* is even (i.e.,node*e*is the right child), then the query

(salt*,*anc *⊕*salt*,*node*e⊕σ*(anc))

### is added toQ.

Since*∆*is chosen uniformly at random, we remark that

anc*e−*1*⊕*saltpt=*∆⊕*node*e−*1*,ie−*1*⊕*saltpt

|anc ⊕σ(anc|) =node|⊕node||,||
|---|---|---|---|---|---|
|e|e−1|e,i e−1,i|e−1,i||e−1,i|
|e,i|e−1|e,i|e−1,i|||
|||||node||
||||||com|

*e e−*1 *e,ie e−*1*,ie−*1 *⊕*(node*e−*1*⊕∆*)*⊕σ*(node*e−*1*⊕∆*)*,* node*e⊕σ*(anc) =node*e⊕σ*(node*e−*1*⊕∆*)

for*e∈{*2*,...,d}*, which implies*X,Y*for(*K,X,Y*)*∈Q* are chosen uniformly at random up to the randomness of*∆*. For each instance, the following queries are added to*Q* and*Q*tape, respec- tively.

**–**An ideal cipher query from computing the hidden commitment:

( ¯

*i*)¯
(seed*,*ctr[b*,i,*0]*,*com¯*i*)*∈Q*com*.*

**–**Ideal cipher queries from computing the hidden tape, for*j∈*[2*C*+ 2] :

( ¯

*i*)¯
(seed*,*ctr[b*,i,j*]*,m*¯*i*[(*j−*1)*λ*+ 1 : (*j−*1)*λ*+*λ*])*∈Q*tape*.*

For each instance,log*N*,1and2*C*+ 2queries are added to*Q*node,*Q*comand *Q*tape, respectively. Therefore we have

### |Qnode|= logN·QI,|Qcom|=QI,|Qtape|= (2C+ 2)QI.

For*z∈{*0*,*1*}*

|, we define some subsets ofQ||,Q|,Q as follows.||
|---|---|---|---|---|
|λ|node|node node|com tape||
||+ ctr|ctr|||
||− com|com|||

*Q* [*z*] =*{*(*K,X,Y*)*∈Q* : *K*=*z},*

*Q* [*z*] =*{*(*K,X,Y*)*∈Q* : *X*=*z},*

### Q [z] ={(K,X,Y)∈Q : Y=z}.

Now, we will define two kind of bad events; one is the restriction of (multi- )collisions (Aux), and the other is the real events (Bad). When one of the latter event happens, the adversary surely distinguishes both worlds. On the other hand, the former events are not critical to distinguishing itself but made for the proof easy. We define the former events as follows. We note that the probability bound of following events is computed assuming the ideal world since the proba- bility of bad events in the ideal world should be bounded to use the H-coefficient technique.

**–**Aux₁: The maximal multi-collision insaltpt[: *λ−*24]is greater than12or the maximal multi-collision insaltkeyis greater than12. From (2), the probability is bounded by

Pr[Aux₁]*≤*2*QI/*(2 16 *·*2 2(*λ−*24) )*≤QI/*2 2*λ−*33 *.*

**–**Aux₂: There is a collision of at least two whole salts (saltpt*∥*saltkey). The probability of this event is bounded by

Pr[Aux₂]*≤Q²I/*2 2*λ* *.*

**–**Aux₃: During computing nodes inIC-VSC*.*Commit(salt*j,*root₁), there exists an input collision on*E*. In other words, there exists(saltkey*,*node*⊕*saltpt) such that*E*saltkey(node*⊕*saltpt)is queried at least twice. We remark that this event does not distinguishes the two worlds; as this event is not related to the replaced random strings, the probability of this event is same in the both worlds. This event may seems same withBad₅ in the later part, butBad₅ directly distinguishes these two worlds. The difference is: *•*Aux₃ checks that if there is a key-input collision on*E*while computing a real GGM trees, regardless replaced random string. As computation of GGM trees are same on both the real world and the ideal world, this event does not distinguish the two worlds. *•*Bad₅ checks that if there are a collision of queries made while computing the paths to the hidden nodes. As the hidden seeds will be replaced to a correlated random string, the collision will finds a contradiction on*E* computations.

As all the root nodes are same, the probability that(saltkey*,*root₁ *⊕*saltpt) collides with*¬*Aux₂ is 0. Similar to a mathematical induction, we will see how distinct parent nodes make child nodes collide. Two distinct node evaluations *E*saltkey(node*⊕*saltpt)and*E*salt*′* key (node *′* *⊕*salt *′* pt)from different instances incur an input collision at their child node levels if one of the two following pairs collide: { saltpt*⊕E*saltkey(node*⊕*saltpt)*⊕σ*(node) *′ ′ ′ ′*(left child) saltpt*⊕E*salt*′* key (node *⊕*saltpt)*⊕σ*(node) { saltpt*⊕E*saltkey(node*⊕*saltpt)*⊕σ*(node)*⊕*node *′ ′ ′ ′ ′*(right child)

|salt ⊕E|(node|⊕salt|)⊕σ(node|)⊕node||
|---|---|---|---|---|---|
|pt|salt ′key||pt||′|
|key||||pt||

pt salt *′* keypt

wheresalt andsalt also collide. Ifnode*⊕*salt andnode *⊕*salt *′* ptcollide, then those two pairs cannot collide since*σ*is an orthomorphism. Otherwise, each pair will collide with probability at most

<u>1 1</u> *λ* *≤* *λ* 2 *−*(# of previous evaluations withsaltkey) (2 *−*24*N*)

conditionedsaltkey=salt *′* key. Then, with*¬*Aux₁, the inputs collide at their child node levels with proba- bility at most

<u>2 2</u> *λ λ* *≤* *λ λ* *.* 2 (2 *−*(# of previous evaluations withsaltkey)) 2 (2 *−*24*N*)

Similarly, two nodes in a single instance collides with probability at most

<u>2</u> *λ* *.* 2 *−*24*N*

By a hybrid argument, we have ()() () *QI*2*N* <u>2</u> 2*N* <u>2QI</u> Pr [Aux₃ *∧¬*Aux₁ *∧¬*Aux₂]*≤*

||·|+|·|
|---|---|---|---|
||λ λ||λ|
|I|I|I||
|2λ|λ|λ||
||¯i|λ−1||
||I|||
|λ|λ 16 2λ−1|2λ+15||
|I||I||

*λ λ λ* 2 2 2 (2 *−*24*N*) 2 2 *−*24*N* 4*N²Q²* 4*N²Q* 5*N²Q* *≤* + *≤* 2 2 2

provided that*N≤*2 *λ−*1. **–**Aux₄: The maximal multi-collision incom is greater than12. As there are at most ((2*C*+ 2)*N*+ (*N−*1))*Q ≤*2*.*

queries to*E*made duringCommit, on top of*¬*Aux₃, the probability that com¯*i*=*x*for some*x∈{*0*,*1*}* is at most2*/*2. From (2), we have

### Pr [Aux₄ ∧¬Aux₃]≤Q /(2 ·2)≤Q /2.

Now we introduce the bad events. As a single incompatible ideal cipher query distinguishes the two worlds, each bad event corresponds to two of*{Q,Q*ctr*,Q*node*}* queries collide. As a collision between ideal cipher queries made by the adversary – both in*Q*– does not contribute to the distinguishing advantage, there are 5 bad events.

**–**Bad₁: There exists(*K,X,Y*)*∈Q*and(*K* *′* *,X* *′* *,Y* *′* )*∈Q*ctrsuch that(*K,X*) = (*K* *′* *,X* *′* )or(*K,Y*) = (*K* *′* *,Y* *′* ). Since*K* *′* is randomly chosen and*Y* *′* is ran- domly chosen if it is from*Q*tape, we have { 1 if(*K* *′* *,X* *′* *,Y* *′* )*∈Q* + [*X*]*,* *′ ′* 2*λ* ctr Pr [(*K,X*) = (*K,X*)]*≤* 0otherwise   21*λ*if(*K* *′* *,X* *′* *,Y* *′* )*∈Q* *−* com[*Y*]*,* Pr [(*K,Y*) = (*K* *′* *,Y* *′* )]*≤* 2 2 1 *λ*if(*K* *′* *,X* *′* *,Y* *′* )*∈Q*tape*,*   0otherwise.

By assuming*¬*(Aux₁ *∨*Aux₄), we get*|Q* + ctr[*X*]*|≤*12,*|Q* *−* com[*Y*]*|≤*12and ∑ <u>|Q</u>+ <u>ctr[X]|·(# of(·,X,·)∈Q)</u> Pr [Bad₁ *∧¬*(Aux₁ *∨*Aux₄)]*≤* *λ* *λ* 2 *X∈{*0*,*1*}* ∑ <u>|Q</u>*−*<u>[Y]|·(# of(·,·,Y)∈Q)</u> + <u>com</u> *λ* *λ* 2 *Y∈{*0*,*1*}* <u>|Qtape|·Q</u> + 2*λ* 2 24*Q* (2*C*+ 2)*QIQ* 25*Q* *≤* *λ* + 2*λ* *≤* *λ* *.* 2 2 2

**–**Bad₂: There exists(*K,X,Y*)*∈Q*and(*K,X* *′* *,Y* *′* )*∈Q*nodesuch that*X*=*X* *′*

or*Y*=*Y* *′*. Recall that random sampling of*∆*implies random sampling of *X* *′* ’s and*Y* *′* ’s. For each query(*K,X,Y*)*∈Q*and(*K,X* *′* *,Y* *′* )*∈Q*node[*K*], we have *′ ′*<u>2</u> Pr [*X*=*X ∨Y*=*Y*]*≤* *λ* *.* 2 By assuming*¬*Aux₁, we get*|Q*node[*K*]*|≤*12 log*N*and

∑ <u>|Q</u> <u>node[K]|·(# of(K,·,·)∈Q) 24 logN·Q</u> Pr [Bad₂ *∧¬*Aux₁]*≤* *λ−*1 *≤* *λ* *.* *λ* 2 2 *K∈{*0*,*1*}*

**–**Bad₃: There exist distinct triples(*K,X,Y*)*,*(*K* *′* *,X* *′* *,Y* *′* )*∈ Q*ctrsuch that (*K,X*) = (*K* *′* *,X* *′* )or(*K,Y*) = (*K* *′* *,Y* *′* ). If(*K,X,Y*)and(*K* *′* *,X* *′* *,Y* *′* ) are from the same instance, we trivially have*K*=*K* *′* ,*X̸*=*X* *′*, and Pr [*Y*=*Y* *′*] = 1*/*2 *λ*, so () 2*C*+ 2 <u>QI</u> Pr [Bad₃ occurs in a same instance]*≤* *λ* *.* 2 2

||′|′ ′||
|---|---|---|---|
|+ ctr|||′|
|− com|||′|
|ctr ′|tape|||
||22|||

Now, assume that(*K,X,Y*)and(*K,X,Y*)are from different instance. There are three cases thatBad₃ occurs in different instances: *•*two queries in*Q* [*X*]collide at key (i.e.,*K*=*K*); *•*two queries in*Q* [*Y*]collide at key (i.e.,*K*=*K*); *•*a query in*Q* and a query in*Q* collide at key and output. Since*¬*Aux₃ prevent the input collision while computing nodes inIC-VSC*.*Commit, we havePr [*K*=*K ∧¬*Aux₃]*≤λ*and the probability is bounded by

Pr[Bad₃ occurs in different instances*∧¬*(Aux₁ *∨*Aux₃ *∨*Aux₄)]   ))

|∑|(|Q||(|Q ∑|||
|---|---|---|---|---|---|
||+ ctr|||− com|ctr tape|
|λ|||||2λ|
|X∈{0,1}||Y∈{0,1}||||
|ctr|com||2 I|||
|λ|I|2λ 2 I||||
|λ||2λ||||

<u>2</u>  [*X*]*|* [*Y*]  + <u>|Q |·|Q |</u> *≤* + 2 *λ* 2 *λ* 2 2

<u>12(|Q |+|Q |) (2C+ 2) Q²</u> *≤* + 2 2 <u>12(2C+ 4)Q (2C+ 2) Q²</u> *≤* +*.* 2 2

All in all,

<u>(2C+ 7)</u> 2 <u>QI(2C+ 2)</u> 2 <u>Q²I</u> Pr [Bad₃ *∧¬*(Aux₁ *∨*Aux₃ *∨*Aux₄)]*≤* *λ* + 2*λ* 2 2 <u>(2C+ 7)</u> 2 <u>QI(2C+ 2)QI</u> *≤* *λ* + *λ* 2 2 <u>(2C+ 8)</u> 2 <u>QI</u> *≤* *λ* *.* 2

**–**Bad₄: There exist distinct triples(*K,X,Y*)*∈Q*nodeand(*K* *′* *,X* *′* *,Y* *′* )*∈Q*ctr such that(*K,X*) = (*K* *′* *,X* *′* )or(*K,Y*) = (*K* *′* *,Y* *′* ). Since [] <u>2</u> $ *λ ′ ′* Pr *∆ ←−{*0*,*1*}* : *X*=*X ∨Y*=*Y ≤* *λ* 2 [] <u>1</u> $ *λ ′* Pr saltkey*←−{*0*,*1*}* : *K*=*K |∆*=*δ ≤* *λ* 2

for any fixed*δ*, we have

2*|Q*node*|·|Q*ctr*|* 4(*C*+ 1) log*N·Q²I*2*QI* Pr [Bad₄]*≤* 2*λ* *≤* 2*λ* *≤* *λ*

||2||2||2|
|---|---|---|---|---|---|
||||′ ′|′|node|
|′ ′||′ ′ ′key|′e|e−1 ′pt|e−1,i|
|key e−1|pt||−1 ′key ′e||′pt|
|key e−1||pt|−1 ′key||′pt|
|key|e−1,i|pt||e −1,i||

**–**Bad₅: There exist distinct triples(*K,X,Y*)*,*(*K,X,Y*)*∈Q* such that (*K,X*) = (*K,X*)or(*K,Y*) = (*K,Y*). Recall thatanc =node*e−*1*⊕* *∆*. Then, we have

### (salt,anc ⊕salt) = (salt,anc ′ ⊕salt)

### ⇔(salt,anc ⊕∆⊕salt) = (salt,anc ′ ⊕∆⊕salt)

*⇔*(salt*,*node*e−*1*⊕*salt) = (salt*,*node *′ ′ ′ ⊕*salt) *e −*1

which implies Pr [(*K,X*) = (*K* *′* *,X* *′* )*∧¬*Aux₃] = 0

since*¬*Aux₃ restricts that there is no key-input collision while computing nodes inIC-VSC*.*Commit(). Similarly, we have

(saltkey*,*anc*e⊕σ*(anc*e−*1)) = (salt *′* key*,*anc *′e* *′ ⊕σ*(anc *′e* *′* *−*1)) *⇔*(saltkey*,*node*e,ie⊕σ*(node*e−*1*,ie−*1)) = (salt *′* key*,*node*e′,i* *′ ′ ⊕σ*(node*e′−*1*,i′ ′*))*,* *e e −*1 (saltkey*,*anc*e⊕σ*(anc*e−*1)) = (salt *′* key*,*node*e′,i* *′ ′ ⊕σ*(anc *′e* *′* *−*1)) *e* *⇔*(saltkey*,*node*e,ie⊕σ*(node*e−*1*,ie−*1)*⊕∆*) = (salt *′* key*,*node*e′,i* *′ ′ ⊕σ*(node*e′−*1*,i′ ′*)) *e e −*1 (saltkey*,*node*e,ie⊕σ*(anc*e−*1)) = (salt *′* key*,*node*e′,i* *′ ′ ⊕σ*(anc *′e* *′* *−*1)) *e* *⇔*(saltkey*,*node*e,ie⊕σ*(node*e−*1*,ie−*1)) = (salt *′* key*,*node*e′,i* *′ ′ ⊕σ*(node*e′−*1*,i′ ′*))*,* *e e −*1

where only the second proposition have the probabilistic variable*∆*. So, there is no chance to satisfy the first and third proposition with*¬*Aux₃. Then, it implies that *′ ′*<u>1</u> Pr [(*K,Y*) = (*K,Y*)*∧¬*Aux₃]*≤* 2*λ* *.* 2 All in all, we get

<u>(logN·QI)</u> 2 <u>logN·QI</u> Pr [Bad₅ *∧¬*Aux₃]*≤* 2*λ* *≤* *λ* 2 2

WithAux=Aux₁ *∨···∨*Aux₄ andBad=Bad₁ *∨···∨*Bad₅, we have

*QIQ²Iλ*5*N²QIQI* Pr[Aux*∨*Bad]*≤*

|+|+|+||||
|---|---|---|---|---|---|
|2λ−33|2|λ|2λ+15 2 I|I|I|
|λ|λ λ|2|λ I|λ λ|λ λ|

2*λ−*33 2 *λ* 2*λ*+15 2 2 2 2 25*Q* 24 log*N·Q* (2*C*+ 8) *Q* 2*Q* log*N·Q* + + + + + 2 2 2 2 2 (3 + 5*N²* + (2*C*+ 8) + log*N*)*Q* (25 + 24 log*N*)*Q* 2 *≤* + + 2 2 2

### where the inequalities assume thatλ≥78.

|We sayT|be the set of bad transcripts, whileT||||be the complement of|
|---|---|---|---|---|---|
||Bad||||Good|
|Bad s ¯i|id|re I id re|¯i (2C+2)λ (2C+2)λ|Q s∈{0,1} Q s∈{0,1}|λ P λ P|

*T*, and let*T* (resp.*T*) be the distribution of*γ*in*I*(resp.*R*). As*Q*ideal cipher queries and*Q* instances of*m* are included in transcripts, for*γ∈T*Good,

<u>1</u> ∏ <u>1</u> Pr[*γ*=*T*] = *·,*

(2)*I*
*λ*

(2)*s*
where*P* denotes the number of ideal cipher queries with key input*s*. Addition- ally, depending on oracle queries, some values may be excluded as candidates for*m*, <u>1</u> ∏ <u>1</u> Pr[*γ*=*T*]*≥ ·,*

(2)*I*
*λ*

(2)*s*

where*P* denotes the number of ideal cipher queries with key input*s*. Therefore,

|s||
|---|---|
|Q-mih|2|
|IC-VSC|λ|

by Lemma2, the advantage is bounded by

*I*(3 + 5*N²* + (2*C*+ 8) + log*N*)*QI*(25 + 24 log*N*)*Q* 2 **Adv** (*A*)*≤* + *λ* + *λ* *.* 2 2 2

*⊓⊔*

## C Full Proof of the EUF-CMA Security

**Theorem 2(EUF-CMA Security of rBN++).***Assume thatH₀,H₁,H₂,* ExpandH1*,*ExpandH2*, and*ExpandSalt*are modeled as random oracles and that* *the*(*N,τ,λ*)*parameters of rBN++ are appropriately chosen where|*F*|*= 2 *λ* *. For* *a PPT adversaryAagainst the EUF-CMA security of rBN++ with a total of* *Q*sig*signing oracle queries,Qrandom oracle queries, andPideal cipher queries,* *there exist PPT adversaries*

**–***Bagainst the EUF-KO security of rBN++,* 5

**–***Cagainst the PRF security ofH₃,* 6

### –Dagainst the multi-instance hiding security ofIC-VSC

*such that*

<u>(Q +Q)</u>

|euf-cma|sig 2||prf|
|---|---|---|---|
|rBN++ sig|2λ τQ-mih IC-VSC (2C 2 +4)N|sig|H euf-ko rBN++|

**Adv** (*A*)*≤* +*Q ·***Adv** 3

(*C*)
2 sig +**Adv** (*D*) +**Adv** (*B*)*,* { <u>5(λ−24)</u> *λ−*1 } *provided thatτ·Q ≤*min 26*,.*

*Proof.*Let*A*be an EUF-CMA adversary against rBN++ for givenpk. LetG₀ be the original EUF-CMA game. Let*O*sigbe the signing oracle, and let*Qi*for *i*= 0*,*1*,*2be the number of queries made to*Hi*by*A*. Let*Q*saltbe the number of queries made toExpandSaltby*A*. We begin to prove the security of the deterministic version of rBN++ (*ρ←*0 *n* ), and prove that of the probabilistic version later. Without loss of generality, we assume that all messages in signing queries are distinct.

G₁:This game acts the same asG₀ except that it aborts if there exist two different queries on*H₀* with the same outputs. This game is indistinguishable from the previous game unless the simulation is aborted. As the output length of *H₀* is2*λ*, we have <u>(Qsig+Q₀)</u> 2 Pr[G₁ aborts]*≤* 2*λ* *.* 2 5 We assume*B*has the same amount of queries to random oracles. 6 *H₃* itself is not a PRF, but it is used as a PRF with key prepending. We use this notation for convenience.

G₂: *O*sigreplacessalt*∈{*0*,*1*}* 2*λ* with randomly sampled values, instead of com- puting*H₃*(sk*,µ,ρ*). As*µ*is always distinct for each query, the difference between this game and the previous one reduces to the PRF security of*H₃* with secret keysk. Therefore, there exists a PPT adversary*C*against the PRF security of*H₃* such that

*|*Pr[*A*winsG₁]*−*Pr[*A*winsG₂]*|≤Q*sig prf

|||·Adv|(C).|
|---|---|---|---|
|2λ||sig|H|
||(i)|||
|k|k i∈[N]|k k,j j∈[C]|k∈[τ]|

*H*3

G₃: *O*sigsamples*h₁ ∈{*0*,*1*}* at random instead of computing

*H₁*(*µ,*salt*,*(com*,*(pk)*,∆c,*(*∆z*)))

and programs the random oracle*H₁* to output*h₁* for the respective query. The first challenge(*ϵk,j*)*k∈*[*τ*]*,j∈*[*ℓ*+1]is derived by expanding the randomly sampled*h₁*. The simulation is aborted if the queries to*H₁* have been made previously in a signing oracle query. Assalt*∈{*0*,*1*}* 2*λ* is random, this game is indistinguishable from the previous game unless the simulation is aborted, and the probability of abort is

<u>Qsig(Qsig+Q₁)</u> Pr[G₃ aborts]*≤* 2*λ* *.* 2

|2λ|||
|---|---|---|
|(i)|(i)||
|k i∈[N]|k i∈[N]|k∈[τ]|

G₄: *O*signow samples*h₂ ∈{*0*,*1*}* at random instead of computing

*H₂*(*h₁,*salt*,*((*α*)*,*(*v*)))

and also program the random oracle*H₂* to output*h₂* for the respective query. In this game, both*h₁* and*h₂* are sampled in advance, and all the derived values are computed from*h₁* and*h₂*. After computing all such values, *O*sigprogram the*H₁* oracle and the*H₂* oracle. The simulation is aborted if the queries to*H₂* have been made previously in a signing oracle query. As*h₁ ∈{*0*,*1*}* 2*λ* is random, this game is indistinguishable with the previous game unless the simulation is aborted, and the probability of abort is

<u>Qsig(Qsig+Q₂)</u> Pr[G₄ aborts]*≤* 2*λ* *.* 2

G₅: *O*signow samples(salt₁*,...,*salt*τ*)*∈ {*0*,*1*}* 2*τλ* at random instead of com- putingExpandSalt(salt), and also program the random oracleExpandSaltto output(salt₁*,...,*salt*τ*)for the respective query. The simulation is aborted if the queries toExpandSalthave been made previously in a signing oracle query. Assalt*∈{*0*,*1*}* 2*λ* is random, this game is indistinguishable with the previous game unless the simulation is aborted, and the probability of abort is <u>Qsig(Qsig+Qsalt)</u> Pr[G₅ aborts]*≤* 2*λ* *.* 2 (¯*ik*) G₆:For each*k∈*[*τ*],*O*sigreplaces the hidden tapetape *k* by a random ele- ment inF² *C*+2. Since(decom*i*)*i∈*[*τ*]is computed independently fromsk, the distribution of(pdecom*i*)*i∈*[*τ*]is also independent tosk.

The difference betweenG₅ andG₆ perfectly corresponds to multi-instance hiding game ofIC-VSC, so there exists a PPT adversary*D*against the multi- instance hiding game such that

*τQ*sig-mih *|*Pr [*A*winsG₅]*−*Pr [*A*winsG₆]*|≤***Adv** IC-VSC

(*D*)*.*
We note that the multi-instance hiding game is defined within a single rep- etition. So the adversary*D*should have*τ*times more instance than the number of signature queries. G₇: *O*sigreplaces (*∆*sk*k,∆ck,*(*∆zk,j*)*j∈*[*C*])*k∈*[*τ*]

with random elements instead of computing them usingskand S-box out- puts. As the hidden tapes are random, the distribution of these variables does not change. (¯*ik*) Note that now for all*k∈*[*τ*],(*α* *k* ) *k∈*[*τ*]is random and independent ofsk. (¯*ik*)∑(*i*) If the multiplication triple is wrong, then*v* *k* *←−i̸*=¯*i* *k* *v* *k* is different from an honest value derived from legitimate calculation. However,(¯*ik*)is unopened and the multiplication check is still passed. Since the signature oracle inG₇ does not depend on the secret keysk, it implies thatG₇ can be reduced to the EUF-KO security. Therefore, there exists a PPT adversary *B*on EUF-KO security against rBN++ such that

Pr[*A*winsG₇]*≤***Adv** euf rBN++ -ko

(*B*)*.*
All in all, we have

euf<u>(Qsig+Q₀)</u> 2 prf **Adv**rBN-cma ++(*A*)*≤* 2*λ* +*Q*sig*·***Adv***H* 3

(*C*)
2 *Q*sig(*Q*sig+*Q₁*) *Q*sig(*Q*sig+*Q₂*) *Q*sig(*Q*sig+*Q*salt) + 2*λ* + 2*λ* + 2*λ* 2 2 2 *τQ*sig-mih euf +**Adv** IC-VSC

(*D*) +**Adv**rBN-ko++(*B*)
<u>(Qsig+Q)</u> 2 prf *≤* 2*λ* +*Q*sig*·***Adv***H* 3

(*C*)
2 *τQ*sig-mih euf +**Adv** IC-VSC

(*D*) +**Adv**rBN-ko++(*B*)
provided that*Q₀* +*Q₁* +*Q₂* +*Q*salt*≤Q*. For the non-deterministic version of*A*, all games are defined in a manner almost identical to the deterministic version, with the exception of handling two queries to*O*sigthat involve the same messages and*ρ*values. If(*m,ρ*)are identical in two queries, the outputs must also be identical; thus, we avoid ran- dom sampling and use already programmed outputs for the random oracles in such cases. Consequently, the differences between the adjacent games remain unchanged from the deterministic version, leading to the same bounds on the advantage of*A*.*⊓⊔*

## D Application of One-tree Technique.

Recently, Baum et al. introduced*batched all-but-one vector commitment (BAVC)*[2] which consists of

1.a single large GGM tree containing all the*τN*seeds,
2.a proof-of-work mechanism. For the first one, the single large GGM tree generates all the*τN*seeds and reveals all-but-*τ*seeds. We leave the application of the first technique as a future work. For the second one, the last challenge hash (*H₂* in the rBN++ scheme) checks whether the last*w*bits are all zero. If the bits are not all zero, the prover calls the hash once more with an increased counter, which is called*proof-of-work*. The prover includes the counter in the signature for the verifier to verify without the proof-of-work. Fortunately, this technique can be directly applied to the rBN++ scheme. In Table3, we summarize the increased number of random oracle calls and reduced signature size for a reasonable amount of proof-of-work. Unlike FAEST, since the rBN++ scheme calls almost no random oracle per signature, there may be some computation overhead.

|N|τ|wRO call||IC call|Sig. size|
|---|---|---|---|---|---|
|16|33|0|5|4191|5376|
|16|32|4|21|4064|5218|
|16|31|8|271|3937|5058|
|256|17|0|5|34799|3904|
|256|16|8|271|32752|3682|

Table 3: The number of calls to the random oracles and the ideal cipher for
 rAIMerwhen the proof-of-work is applied.*w*is the number of bits for the proof- of-work. We assume that the counter is 2-byte long.
