# Unbalanced Private Set Union with Reduced Computation and Communication

Cong Zhang¹, Yu Chen² *,*3(B), Weiran Liu⁴, Liqiang Peng⁴, Meng Hao⁵, Anyu Wang¹ *,*6*,*7, and Xiaoyun Wang¹ *,*2*,*3*,*6*,*7*,*8

1 Institute for Advanced Study, BNRist, Tsinghua University, Beijing, China *{*zhangcong,anyuwang,xiaoyunwang*}*@tsinghua.edu.cn, 2 School of Cyber Science and Technology, Shandong University, Qingdao, China yuchen@sdu.edu.cn 3 Key Laboratory of Cryptologic Technology and Information Security, Ministry of Education, Shandong University, Qingdao, China 4 Alibaba Group *{*weiran.lwr,plq270998*}*@alibaba-inc.com, 5 Singapore Management University menghao303@gmail.com 6 Zhongguancun Laboratory, Beijing, China 7 National Financial Cryptography Research Center, Beijing, China 8 Shandong Institute of Blockchain, Jinan, China

Abstract. Private set union (PSU) is a cryptographic protocol that allows two parties to compute the union of their sets without revealing anything else. Despite some efficient PSU protocols that have been proposed, they mainly focus on the balanced setting, where the sets held by the parties are of similar size. Recently, Tu et al. (CCS 2023) proposed the first unbalanced PSU protocol which achieves sublinear communication complexity in the size of the larger set. In this paper, we are interested in improving the efficiency of the unbalanced PSU protocol. We find that oblivious key-value store (OKVS) data structure plays an essential role in the most recently proposed PSU constructions and formalize unbalanced PSU as an OKVS decoding process with sublinear communication. Our key insight lies in when OKVS satisfies sparsity property, obtaining the necessary decoding information precisely aligns with the batch private information retrieval (BatchPIR) problem. We give two concrete constructions of unbalanced PSU protocols based on different OKVS encoding strategies. The first is based on oblivious PRF (OPRF) and a newly introduced cryptographic protocol called permuted private equality test, while the second is based on re-randomizable public key encryption. Both our two constructions achieve sublinear communication complexity in the size of the larger set. We implement our two unbalanced PSU protocols and compare them with the state-of-the-art unbalanced PSU of Tu et al. Experiments show that our protocols achieve a 1*.*3 *−* 5*.*6*×* speedup in running time and 2*.*1 *−* 11*.*8*×* shrinking in communication cost, depending on set sizes and network environments.

## 1 Introduction

Private set union (PSU) enables two parties to learn the union of their private sets without revealing anything else about the individual sets. PSU serves as a key tool for multiple applications, includ- ing aggregation of network events [BSMD10], improving blacklist accuracy [RMY20], security risk

|+|||
|---|---|---|
|+ +|+ + +|+|

assessments [HLS 16] and universal identifier generation [GMR + 21,ZLDL23] etc. The first scalable PSU construction was proposed by Kolesnikov et al. [KRTW19]. Over the last few years, a line of works [GMR 21,JSZ 22,ZCL 23,CZZ 24] have greatly improved the efficiency of PSU. Recent advancements in PSU protocols [ZCL 23,CZZ 24] have demonstrated their computational efficiency and achieved linear communication complexity proportional to the size of the parties’ sets. Classical PSU protocols are typically designed for balanced settings, that is, the sets held by the parties are of similar size. However, in many scenarios, the size of one party’s input is much larger than the other party’s. A relevant example is blacklist aggregation [KRTW19,JSZ + 22,ZCL + 23], where two organizations aim to merge individual IP blacklists to mitigate vulnerabilities in their infrastructure. This necessitates privately computing the union of the IP blacklists, as revealing IP addresses in the intersection may leak the detection strategy of certain party. Ramanathan et al. [RMY20] showed that

the sets involved in this process are highly unbalanced, e.g., some blacklists include upwards of 500,000 IP addresses, while others contain fewer than 1,000 IP addresses. Leveraging existing PSU protocols in such settings imposes substantial overhead because their communication complexity scales at least linearly with the size of the larger set. This motivates the study of *unbalanced* PSU, where one set is much larger than the other. The design goal is to achieve sublinear communication complexity in the size of the larger set. Only two existing works have considered PSU in the unbalanced setting. Jia et al. [JSZ + 22] pro- posed an unbalanced PSU protocol based on the shuffle technique. Unfortunately, their protocol fails to achieve the standard security of PSU, which leaks the intersection size to the sender. Furthermore, the communication complexity of their protocol still scales linearly with the size of the larger set. Recently, Tu et al. [TCLZ23] designed the first unbalanced PSU protocol with sublinear communica- tion in the size of the larger set from fully homomorphic encryption (FHE). However, their concrete construction had a large constant term in asymptotic complexity due to the use of bin partition tech- niques, incurring a significant overhead in implementations. The constant term becomes prominent when the size of the sender’s set is relatively small, e.g., the set only contains several hundred ele- ments. In this work, we focus on unbalanced PSU with sublinear communication complexity, aiming to achieve concrete improvements both in communication and computational costs.

1.1 Our Contribution This paper contributes new unbalanced PSU protocols with reduced computation and communication costs. Our contributions can be summarized as follows. OKVS decoding with sublinear communication complexity. We observe that nearly all existing PSU protocols [KRTW19,GMR
+ 21,ZCL + 23,TCLZ23] explicitly or implicitly employ oblivious key- value store (OKVS) data structure [GPR + 21]. OKVS is primarily deployed in multi-query reverse private membership test (mq-RPMT), which is the core sub-protocol of PSU [ZCL + 23]. In mq-RPMT, the receiver encodes *n* key-value pairs (e.g., its set elements and set indicators) using OKVS, which are then decoded by the sender. Subsequently, the receiver tests the set membership relationship by matching the sender’s decoding values with the set indicators. Our core observation lies in that the recently proposed efficient OKVS schemes all satisfy *sparsity* [HLP + 24]. The decoding process of sparse OKVS could always be improved by using BatchPIR instead of sending the OKVS directly, which achieves sublinear communication complexity with the OKVS size. Two concrete unbalanced PSU constructions. Adopting different OKVS encoding strategies, we propose two concrete constructions of unbalanced PSU protocols. Our first construction follows the strategy of using oblivious PRF (OPRF) to generate *n* one-time pads for encrypting the set indicator. To perform value matching, we propose a new protocol called permuted private equality test (p-PEQT), which can be viewed as a generalization of permuted matrix PEQT [TCLZ23]. We provide two constructions of p-PEQT, one based on the Decisional Diffie-Hellman (DDH) assumption, while the other relies on the Permute+Share functionality. Our second construction employs a re- randomizable public key encryption (ReRand-PKE) scheme to encrypt the set indicator, which allows the receiver to match values itself. Both the two concrete protocols achieve sublinear communication in the size of the larger set. Evaluations. We implement our two unbalanced PSU constructions and compare them with the state- of-the-art unbalanced PSU [TCLZ23]. Our experiments show that our protocols achieve a 1*.*3 *−* 5*.*6*×* speedup in running time and 2*.*1 *−*11*.*8*×* shrinking in communication cost, depending on set sizes and network environments. In Figure1we display a comparison of running time and communication cost to the state-of-the-art unbalanced PSU [TCLZ23] for small set size *m* = 2 4, large set size *n* = 2 20 in low bandwidth setting.

1.2 Overview of Our Techniques We provide the high-level technical overview of our new unbalanced PSU protocols. For convenience, we denote the parties involved in PSU as the sender *S* and the receiver *R*, and their respective input sets as *X* and *Y* with *|X|* = *m, |Y |* = *n,m ≪ n*.

100*.*6
TCLZ-sym

100*.*4
TCLZ-pub

100*.*2 100 our PSU ps op

|Communication (MB)|our PSU|||
|---|---|---|---|
|10 our PSU||||
|10|10 10 Running Time (s)|10 10|10|
 *−*0*.*2
our PSUpk ddh op

1 1*.*1 1*.*2 1*.*3 1*.*4 1*.*5

Fig. 1: Running time and communication of our unbalanced PSU protocols (PSU

ddh op,PSU ps opand PSUpk) vs. the state of the art [TCLZ23] (TCLZ-pub and TCLZ-sym), for small set size *m* = 2 4, large set size *n* = 2 20 in low bandwidth setting (1 Mbps). Both axes are in log-scale.

Communication-efficient OKVS decoding from BatchPIR. An oblivious key-value store (OKVS) scheme [GPR + 21] consists of two algorithms, namely, (Encode*,*Decode). The Encode algorithm takes a set of key-value pairs *{*(*ki,vi*)*}i∈*[*n*]as input, and outputs an abstract data structure *D*. The Decode algorithm takes *D* and a key *k* as input, and outputs a value *v*. Decode can be called on any key, but if it is called on some *ki*that was used to generate *D*, then the output is the corresponding *vi*. The obliv- iousness stands for that the data structure *D* reveals nothing about the key set *K* = *{ki}i∈*[*n*], given that all the values *vi*are randomly selected. A typical choice of OKVS is polynomial, where encoding involves interpolating all points (*ki,vi*). The encoding complexity of the polynomial is *O*(*n*log² *n*). Recently, several works [GPR + 21,RR22,ZCL + 23,BPSY23] have made great progress on improving the efficiency and security of OKVS, achieving a linear *O*(*n*) encoding complexity. OKVS plays a crucial role in both balanced and unbalanced PSU constructions [KRTW19,GMR + 21, ZCL + 23,TCLZ23]. The key step is to have the sender *S* compute some decoding values of OKVS *D* which hold by the receiver *R*. Due to the obliviousness property of OKVS, *D* does not leak any information about *R*’s set. Therefore, a straightforward approach is to have the receiver *R* directly send *D* to the sender *S*, and let the sender compute the decoding itself. All known PSU protocols in the balanced setting [KRTW19,GMR + 21,ZCL + 23] follow this simple method, resulting in *O*(*n*) communication. However, in the unbalanced setting, where *n ≫ m*, the *O*(*n*) communication may significantly reduce the efficiency. Only Tu et al.’s protocol [TCLZ23] has achieved sublinear commu- nication complexity. Roughly speaking, their protocol uses polynomials as OKVS instantiation. To decode without directly communicating *D*, the sender *S* encrypts its elements with FHE and sends them to the receiver *R*. *R* utilizes these ciphertexts to homomorphically evaluate the polynomial and returns the ciphertexts to the sender. The compactness of FHE guarantees that the communication in this process is sublinear with *n*. Given the fact that polynomial is just an instantiation of OKVS (the encoding complexity is *O*(*n*log² *n*)), replacing it with the recently proposed OKVS [GPR + 21,BPSY23] directly enhances the encoding efficiency to *O*(*n*). However, things are not quite that simple. The decoding process of these efficient OKVS schemes is different from polynomials. Therefore, developing a novel approach to achieve decoding with sublinear communication becomes imperative. We give our solution as follows. We consider using the OKVS scheme satisfying *sparsity* [HLP + 24] as our instantiation, which is satisfied by all recent proposed efficient OKVS schemes [GPR + 21,RR22, BPSY23]. In sparse OKVS, the data structure *D* can be divided into two parts, i.e., *D* = *D₀||D₁*, where *|D₁|* = *o*(*|D₀|*). We refer to *D₀* as the sparse part, and *D₁* as the dense part. The decoding process involves summing a constant number (e.g., 2*−*3) of positions within the sparse part and an ar- bitrary number of positions within the dense parts. Directly sending the entire OKVS would introduce significant communication costs in the unbalanced setting due to the *O*(*n*) length of the sparse part. Our key observation is that the sender does not actually need to know all the information of sparse part *D₀*. Instead, it is sufficient to retrieve specific positions in *D₀* that correspond to the decoding of its set items. This exactly matches the batch private information retrieval (BatchPIR) [CKGS98] scenario. Leveraging this observation, we can achieve decoding with sublinear communication using the non-trivial BatchPIR scheme [MR23] to retrieve the constant positions in the sparse part. For the

dense part *D₁*, *R* can send it to *S* directly because its length is already *O*(log*n*). For clarity, we call the above decoding process as *communication-efficient decoding*. PSU framework. Before describing our construction, we first review the design ideas of existing PSU protocols. We observe that all the recent PSU constructions [JSZ + 22,ZCL + 23,TCLZ23,CZZ + 24] can be divided into two steps. The first step is multi-query reverse private membership test (mq-RPMT) [ZCL + 23]. In mq-RPMT, *S* inputs its set *X* and has no output. *R* inputs its set *Y* and receives a vector of indication bits *⃗b* = (*b₁,...,bm*), where *bi*= 1 if and only if *xi∈ Y*. Subsequently, the parties engage in a batch of oblivious transfer (OT) protocols. In the *i*-th OT instance, *S* inputs (*xi, ⊥*), where *⊥* denotes a dummy item. *R* inputs *bi*and learns *xi*if and only if *xi∈/ Y*. As a result, *R* learns *X\Y* and defines set union as *X∪Y* := (*X\Y*) *∪ Y*. Since the bottleneck of PSU lies in mq-RPMT, existing PSU protocols primarily focus on using different underlying cryptographic tools to design mq-RPMT. Notably, OKVS (with different instan- tiations) plays a crucial role in almost all of these constructions. Achieving sublinear communication in OKVS decoding will lead to more efficient PSU constructions in the unbalanced setting. Hereafter, we show two concrete constructions of mq-RPMT utilizing different OKVS encoding strategies, both achieving sublinear communication complexity in *n*. mq-RPMT from OPRF and p-PEQT. Our first construction uses oblivious PRF (OPRF) func- tionality to generate *n* one-time pads, which are employed to encrypt the set indicator in OKVS values. Additionally, we introduce a new cryptographic protocol named permuted private equality test (p-PEQT) to test whether the sender’s decoding results match the receiver’s set indicator. We note that our p-PEQT can be viewed as a generalization of permuted matrix PEQT (pm-PEQT) [TCLZ23]. The details of our construction are as follows. We start with a special case that the sender *S* has only one item *x* in its set *X*, i.e., *X* = *{x}*. A natural idea is to let the receiver *R* pick some random strings *ri*and compute the OKVS as *D* := Encode(*{*(*yi,ri*)*}i∈*[*n*]). Then, as we described before, we use the communication-efficient decoding process to render *S* to learn the decode result *r* *′* := Decode(*D,x*) in sublinear communication. After

||′ j|||′ t|
|---|---|---|---|---|
|||′ t|||

that, the parties test whether *r* *′* = *r* for each *j ∈* [*n*]. If *∃t ∈* [*n*], s.t. *r* *′* = *r*, *R* knows *x ∈ Y*. However, this idea encounters two key issues. Firstly, the parties need to perform *n* equality test, which is inefficient. Secondly, if the receiver *R* knows *r* = *r*, it directly implies *x* = *yt*instead of merely the fact that *x ∈ Y*, thereby leaking additional information to *R*. To address these challenges, we consider using the same indicator string to indicate the set membership, that is, *R* picks one random string *r* and computes the OKVS as *D* := Encode(*{*(*yi,r*)*}i∈*[*n*]). Then, *S* learns *r* *′* := Decode(*D,x*) and the parties perform a single instance of the equality test. Though this idea works, it ignores an important security issue. The obliviousness property of OKVS mandates that all encoded values must be randomly selected to prevent potential leakage of information about *Y*. To mitigate this risk, we incorporate an OPRF protocol. Specifically, in OPRF, the sender inputs *x* and retrieves the PRF value *q* = *Fk*(*x*), while the receiver, without any inputs, obtains a PRF key *k*. The PRF values could be regarded as one-time pads used to encrypt set indicator *r*. Subsequently, *R* computes the OKVS as *D* := Encode(*{*(*yi,r* + *Fk*(*yi*))*}i∈*[*n*]). The parties then engage in a communication-efficient decoding process, allowing *S* to learn ¯*r* = Decode(*D,x*). Finally, *S* computes the decryption *r* *′* := ¯*r − q* and tests whether *r* *′* = *r* with *R*. Expanding on the previous idea to accommodate the general case of *|X| >* 1, we encounter a challenge with reusing the same OKVS. Consider the scenario where *S* has two items *x₁,x₂*, both belonging to *Y*. If the same *D* is utilized for testing both *x₁* and *x₂*, *S* will obtain identical decoding results, i.e., *r₁* *′* = *r₂* *′* = *r*, potentially leaking the information that both *x₁* and *x₂* belong to the intersection. To ensure security, one must execute the aforementioned process for each *xi∈ X* using a fresh OKVS, resulting in substantial overhead. To overcome this limitation, we propose employing the standard hash-to-bin technique. Specifically, let *S* use hash functions *{h₁,h₂,h₃}* to assign its items to *mc*bins via cuckoo hashing [PR04], so that each bin has at most one item. *R* assigns each of its items *y* to all of the bins *h₁*(*y*)*,h₂*(*y*)*,h₃*(*y*). Then, the parties perform the above single-point test on each bin. Though it looks great, the hash-to-bin technique introduces a new security concern. *R* may gain additional information about the sender’s items, specifically whether the *i*-th item belongs to the *i*-th bin, which narrows down the range of *xi*. We note that PSU can only allow *R* to know if *xi*belongs to the entire set *Y*, rather than the *i*-th bin. To address this, we introduce a new cryptographic protocol named permuted private equality test (p-PEQT). In this functionality, the sender inputs the vector of decryptions *r⃗′*:= (*r₁* *′* *,...,rm* *′* *c* ) and a permutation *π* over [*mc*]. The receiver inputs the vector of

indicators *⃗r* := (*r₁,...,rmc*) and receives a bit vector *⃗b* = (*b₁,...,bmc*), where *bi*= 1 if and only
if *r* *π* *′*

(*i*) = *rπ*(*i*). Since *R* knows nothing about *π*, *bi*= 1 only infers *xπ*(*i*)*∈ Y*. We propose two p-
PEQT constructions, the first is based on the DDH assumption, while the second is based on the Permute+Share functionality [CGP20]. See Section3for more details.

mq-RPMT from ReRand-PKE. Our second construction leverages ReRand-PKE for encrypting the set indicator. The idea is inspired by the PSU protocol of Zhang et al. [ZCL + 23] in the balanced setting. Notably, while the communication complexity of their protocol scales linearly with the size of the larger set, i.e., *O*(*n*), our protocol achieves sublinear communication complexity. Therefore, our protocol can be seen as an extension of their protocol in the unbalanced setting. The details of our construction are as follows.

Firstly, the receiver *R* selects a fixed string *s* as the set indicator and encrypts it with ReRand- PKE for *n* times, that is, it computes *sj*:= Enc(*pk,s*) for *j ∈* [*n*]. Then, *R* computes the OKVS *D* := Encode(*{*(*yj,sj*)*}j∈*[*n*]). Following this, the sender *S* executes the communication-efficient decoding to

||′i|i|||
|---|---|---|---|---|
|′i|i|||′i|
|||||j j|
|′i t||i ′i|t|i i|
||?||||
||i||||

learn the decoding results, i.e., *s* *′i* := Decode(*D,xi*)*,i ∈* [*m*]. Now, the goal is to let *R* know whether Dec(*sk,s*) = *s*, which signifies whether *x ∈ Y*. However, *S* cannot send these *s* directly to *R*, since *R* can record the relationship between the randomness used for encrypting *s* and *y*. For example, if *R* observes *s* = *s* for some *t ∈* [*n*], then it deduces *x* = *y* rather than merely *x ∈ Y*. To address this concern, *S* re-randomizes each ciphertext *s* before sending it to *R*, i.e., *s*¯ := ReRand(*pk,s* *′i* ). Subsequently, by testing Dec(*sk, s*¯) = *s*, the receiver *R* learns whether *xi∈ Y*.

We highlight a subtle distinction between our two constructions in OKVS encoding. Specifically, the values encoded in this construction consist of ciphertexts generated by the ReRand-PKE scheme,

e.g., comprising two elements in a group G (when instantiated by ElGamal encryption [Gam85]), whereas the values in our first construction are bit strings. Notably, the bit string XOR operation is significantly more efficient than the group operation. Therefore, the encoding efficiency of OKVS in our first construction is much better than that in our second construction. To improve the encoding efficiency, we consider computing the OKVS over Z*p*instead of G, where *|*G*|* = *p* and *p* is a prime. This choice is motivated by the fact that addition over Z*p*is considerably more efficient than operations in
G. We employ a ”pull-down-then-lift” methodology, wherein we initially compute the OKVS over Z*p* and subsequently lift it to the exponent. See Section4for more details about this optimization.
1.3 Related Work In this section, we review previous PSU protocols that are relevant to our work. Most works of PSU protocol only consider balanced settings. Among them, the construction can be divided into two categories based on the underlying cryptographic techniques used. The first category predominantly relies on public-key techniques [KS05,Fri07,HN10,DC17]. The second category mainly relies on symmetric-key techniques in combination with OT [KRTW19,GMR
+ 21,JSZ + 22], which is several orders of magnitude faster than the public-key based constructions. Recently, Zhang et al. [ZCL + 23] made a breakthrough by proposing the first PSU with linear complexity. Then, Chen et al. [CZZ + 24] proposed an improved linear PSU protocol from the DDH assumption. However, when considering the unbalanced setting, all the aforementioned protocols require communication overhead that is at least linearly with the size of large set, resulting in notable performance degradation. For the first time, Jia et al. [JSZ + 22] considered the PSU protocol in the unbalanced setting. However, their protocol suffers from two primary drawbacks. Firstly, their protocol still requires communication complexity linear in the larger set size. Secondly, their protocol did not achieve standard security and may leak the intersection size to the sender. Tu et al. [TCLZ23] proposed the first unbalanced PSU protocol with standard security, which also achieved sublinear communication complexity in the size of the larger set. Their main idea is to transform the FHE-based unbalanced private set intersection (PSI) protocol [CLR17,CHLR18,CMdG + 21] to the PSU scenarios. They introduced a different polynomial randomization method, and used a newly introduced protocol called permuted matrix private equality test (pm-PEQT) to address potential leakage issues. However, due to the use of partition techniques, their concrete unbalanced PSU protocol had a large constant term in asymptotic complexity.

## 2 Preliminaries

2.1 Notation We use *κ* and *λ* to denote the computational and statistical security parameters, respectively. We use [*m,n*] to denote the set *{m,m* + 1*,...,n}* and [*n*] is shorthand for the case *m* = 1. For a bit string *v* we let *vi*denote the *i*th bit. We use the abbreviation PPT to denote probabilistic polynomial-time. We say that a function *f* is negligible in *κ* if it vanishes faster than the inverse of any polynomial in *κ*, and write it as *f* (*κ*) = negl(*κ*). By *a ← A*, we denote that *a* is randomly selected from the set *A*, *a ←* A(*x*) denotes that *a* is the output of the randomized algorithm A on input *x*, and *a* := *b* denotes that *a* is assigned by *b*. We denote the concatenation of string *x* with string *y* by *x||y*.
2.2 Security Model We use the standard security definition for two-party computation [Gol04,Lin17] in this work. Similar to most previous protocols for PSU, our work operates in the *semi-honest model*. Let *F* be a functionality between a sender *S* with input *X* and a receiver *R* with input *Y*. Let *Π* be a two-party protocol for computing *F*. Semi-honest Security. Let view
*Π* *P*(*X,Y*) be the views of party *P* (*P∈{S, R}*) in the protocol, which consists of *P*’s input, randomness tape, and received messages during the protocol. Let output(*X,Y*) be the output of both parties in the protocol.

Definition 1. *A protocol Π is said to securely compute functionality F against semi-honest P if for* *every PPT adversary A that corrupting P, there exists a PPT simulator* Sim*Psuch that for all inputs* *X and Y,*

*{*view *Π* *P*(*X,Y*)*,*output(*X,Y*)*}≈c{*Sim*P*(*In*(*P*)*, F*(*X,Y*))*, F*(*X,Y*)*}*

*where In*(*P*) *denotes the input of P.*

2.3 Oblivious Transfer Oblivious transfer (OT) [Rab05] is an important cryptographic primitive used in various multiparty computation protocols. The most commonly used variant is the 1-out-of-2 OT. It allows a sender with two inputs (*x₀,x₁*) and a receiver with a bit *b ∈{*0*,*1*}* to engage in a protocol where the receiver learns *xb*, and neither party learns any additional information. We give the formal definition of 1-out-of-2 OT functionality in Figure2. Parameters: Sender *S*, Receiver *R*, message length *κ* Functionality: – Wait for input *b ∈{*0*,*1*}* from the receiver *R*. – Wait for input (*x₀,x₁*) from the sender *S*. – Give *xb*to the receiver *R*.
Fig. 2: 1-out-of-2 Oblivious Transfer Functionality *F*ot

2.4 Oblivious PRF An oblivious PRF (OPRF) [FIPR05] is a 2-party protocol in which the sender learns (or chooses) a
random PRF key *k* and the receiver learns the PRF output *Fk*(*q₁*)*,...,Fk*(*qn*) on its inputs *q₁,...,qn*.
We describe the ideal functionality for an OPRF in Figure3.

Parameters: Sender *S*, Receiver *R*, a PRF *F*. Functionality:

– Wait for input *{q₁,...,qn}* from the receiver *R*. – Sample a random PRF key *k* and give it to the sender *S*. – Give *{Fk*(*q₁*)*,...,Fk*(*qn*)*}* to the receiver *R*.

Fig. 3: Oblivious PRF Functionality *F*oprf

Parameters: Sender *S*, Receiver *R*, vector length *n*. Functionality:

– Wait for input *π* from the receiver *R*. – Wait for input *⃗x* = (*x₁,...,xn*) *∈* (*{*0*,*1*}* *l* ) *n* from the sender *S*. – Pick random *ai ←{*0*,*1*}* *l* and compute *bi* = *ai ⊕ xπ*(*i*)for *i ∈* [*n*].
– Give *⃗a* = (*a₁,...,an*) to the sender *S* and give *⃗b* = (*b₁,...,bn*) to the receiver *R*.

Fig. 4: Permute + Share Functionality *F*ps

2.5 Permute + Share The Permute + Share [MS13,CGP20] functionality works as follows. The sender inputs a vector *⃗x* = (*x₁,...,xn*) and the receiver inputs a permutation *π* over [*n*]. As a result, the parties obtain the additive shares of *π*(*⃗x*) = (*xπ*(1) *π*(*n*) *n*) and the

|,...,x|), that is, the sender receives ⃗a = (a₁,...,a||
|---|---|---|
|π(1)|π(n)||
|n|i i|π(i)|
 receiver receives *⃗b* = (*b₁,...,b*), where *a ⊕ b* = *x* for *i ∈* [*n*]. The formal definition of Permute + Share functionality is given in Figure4.
2.6 Oblivious Key-Value Stores The Oblivious Key-Value Store (OKVS) [PRTY20,GPR
+ 21,ZCL + 23] is a data structure that maps a set of keys to corresponding values. The obliviousness means that when the values are randomly selected, the distribution of the data structure is independent from the key set. The formal definition is as follows:

Definition 2(Oblivious Key-Value Store). *An OKVS is parameterized by a set K of keys, a set* *V of values, and consists of two algorithms:*

– Encode(*{*(*x₁,y₁*)*,...,*(*xn,yn*)*}*)*: on input key-value pairs {*(*xi,yi*)*}i∈*[*n*]*⊆K×V, outputs an object* *D (or, with statistically small probability, an error ⊥).* – Decode(*D,x*) : *on input D and a key x, outputs a value y ∈V.*

Correctness. For all *A ⊆K×V* with distinct keys:

(*x,y*) *∈ A* and *⊥̸*= *D ←* Encode(*A*) =*⇒* Decode(*D,x*) = *y*

Obliviousness. For all distinct *{x⁰*1*,...,x⁰n}* and *{x¹*1*,...,x¹n}*, if Encode does not output *⊥* for
*{x⁰*1*,...,x⁰n}* or *{x¹*1*,...,x¹n}*, then the following distributions are computationally indistinguishable:

|||{D|y ←V,i ∈ [n], Encode((x⁰||,y₁),..., (x⁰|,y ))}|
|---|---|---|---|---|---|
|||i i||1 1|n n n n|
|∗|+||n n||∗|

### {D|y ←V,i ∈ [n],Encode((x¹,y₁),...,(x¹,y))}

In addition, our protocols also require OKVS to meet the *Randomness*[ZCL + 23], *Linearity*[GPR + 21] and *Sparsity*[HLP 24].
Randomness. For any *A* = *{*(*x₁,y₁*)*,...,*(*x,y*)*}* and for any *x ∈ { / x₁,...,xn}*, the output of
Decode(*D,x*) is statistically indistinguishable to that of uniform distribution over *V*, where *D ←* Encode(*A*).

Linearity. An OKVS is *linear* (over a field F) if *V* = F (i.e., “values” are elements of F), the output

P of Encode is a vector *m* *D* in F, and the Decode function is defined as: Decode( *m* *D,x*) = *⟨*row( *m*

*x*)*,D⟩* :=
*m*

*j*=1row(*x*)*jDj*for some function row : *K→* F. Hence Decode is a linear map from F to F. Sparsity. An OKVS is *sparse* if the output *D* of Encode can be structured as *D* = *D₀∥D₁* with *|D₁|* = *o*(*|D₀|*), and for any *x ∈ K*, Decode(*D,x*) := *⟨*spa(*x*)*∥*den(*x*)*,D₀∥D₁⟩*, where two mappings spa : *K→{*0*,*1*}* *|D*0 *|* outputs a sparse binary vector with a constant weight *w* and den : *K→{*0*,*1*}* *|D*1 *|*

outputs a dense binary vector. For convenience, let *|D₀|* = *s, |D₁|* = *d*, and define pos*j*: *K→* [*s*] be the function such that pos*j*(*x*) denotes the *j*-th position of 1 in spa(*x*). Note that row(*x*) = spa(*x*)*||*den(*x*) for any *x ∈K*.

Due to the extensive use of OKVS in the private set operation (PSO) protocols, many recent works have made significant improvements to the construction of OKVS [GPR + 21,RS21,RR22,BPSY23]. And all these efficient OKVS schemes satisfy randomness, linearity and sparsity we defined above.

2.7 Cuckoo Hashing Cuckoo hashing was introduced by Pagh and Rodler in [PR04]. In this hashing scheme, there are *α* hash functions *h₁,...,hα*used to map *n* items into *ρ* = (1 + *ϵ*)*n* bins and a stash, where *ϵ >* 0 is a constant. We denote the *i*-th bin as *Bi*. The Cuckoo hashing can guarantee that there is only one item in each bin, and the approach to avoid collisions is as follows: An element *x* is inserted into a

|bin B. Any prior items z of B||are evicted to a new bin B|, using h|
|---|---|---|---|
|h (x)||h (x)|h (z)|
||i|||
 1 1 *ii*to determine the new bin location, where *h* (*z*) *̸*= *h₁*(*x*) for *i ∈* [*α*]. The procedure is repeated until no more evictions are necessary, or until a threshold number of relocations has been performed. In the latter case, the last element is put in a special stash. According to the empirical analysis in [PSZ18], we can adjust the values of *α* and *ϵ* to reduce the stash size to 0 while achieving a hashing failure probability of 2
*−λ*.

2.8 Re-randomizable Public-Key Encryption A re-randomizable Public-Key Encryption (ReRand-PKE) scheme is a tuple of five algorithms: – Setup(1 *κ*
): on input the security parameter *κ*, outputs public parameters *pp*, which include the description of the plaintext and ciphertext space *M,C*. – KeyGen(*pp*): on input public parameter *pp*, outputs a keypair (*pk,sk*). – Enc(*pk,m*): on input a public key *pk* and a plaintext *m ∈ M*, outputs a ciphertext *c ∈ C*. – Dec(*sk,c*): on input a secret key *sk* and a ciphertext *c ∈ C*, outputs a plaintext *m ∈ M* or an error symbol *⊥*. – ReRand(*pk,c*): on input a public key *pk* and a ciphertext *c ∈ C*, outputs another ciphertext *c* *′* *∈ C*.

Correctness. For any *pp ←* Setup(1 *κ* ), any (*pk,sk*) *←* KeyGen(*pp*), any *m ∈ M*, any *c ←* Enc(*pk,m*), and any *c* *′* *←* ReRand(*pk,c*), it holds that Dec(*sk,c*) = Dec(*sk,c* *′* ) = *m*. Indistinguishability. For any *pp ←* Setup(1 *κ* ), any (*pk,sk*) *←* KeyGen(*pp*), and any *m ∈ M*, the distribution *c₀ ←* Enc(*pk,m*) and the distribution *c₁ ←* ReRand(*pk,c₀*) are identical. Security. We require the PKE scheme satisfying *single-message multi-ciphertext pseudorandomness* [ZCL + 23]. Formally, a PKE scheme is single-message multi-ciphertext pseudorandom if for any PPT *A* = (*A₁, A₂*): *κ* *pp ←* Setup(1);  (*pk,sk*) *←* KeyGen(*pp*);     *′* (*m,state*) *←A₁*(*pp,pk*);  <u>1</u> Pr   *β* = *β* : R  *−*  *β ←−{,}*; R   *∗ ∗*

|for i ∈ [n] : c|← Enc(pk,m),c||←− C; |
|---|---|---|---|
||i,0||i,1|
|′||∗ i,β i∈[n]||

*i, i,* *β* *′* *←A₂*(*pp,state, {c* *∗* *}*)

### is negligible in κ.

2.9 Batch Private Information Retrieval In a Batch Private Information Retrieval (BatchPIR) scheme [CGN98,IKOS04,ACLS18,MR23, LLWR24], the client wants to privately retrieve a batch of *b* entries from the server’s dataset *D* of size
*n*. A BatchPIR scheme consists of three algorithms, all taking the computational security parameter *κ* as an implicit input: – Query(*I*) *→* (qu*,*st): on input a set of distinct indexes *I* = *{i₁,...,ib}∈* ([*n*])
*b*, outputs a query qu and a private state st including the index set. – Answer(*D,* qu) *→* ans: on input the database *D* and the query qu, outputs an answer ans. – Recover(st*,*ans) *→{D₁,...,Db}*: given the state st and the answer ans, outputs a batch of entries *{D₁,...,Db}*.

Correctness. A BatchPIR is correct if for any dataset *D* and all distinct inputs *I* = *{i₁,...,ib}*, it holds that Recover(st*,*Answer(*D,* qu)) = *{D*[*i₁*]*,...,D*[*ib*]*},*

where (st*,*qu) *←* Query(*I*). Query privacy. The client’s query qu reveals no information about the query indexes. Formally, a BatchPIR scheme satisfies *Query privacy* if, for all PPT adversaries *A* and all distinct batch query sets *I₁,I₂* with *|I₁|* = *|I₂|*,

Pr[*A*(qu) = 1 *|* (st*,*qu) *←* Query(*I₁*)] *−*Pr[*A*(qu) = 1 *|* (st*,*qu) *←* Query(*I₂*)] *≤* negl(*κ*)*.*

2.10 Private Set Union PSU is a special case of secure two-party computation. The ideal functionality for PSU is given in Figure5. Parameters: Sender *S*, Receiver *R*, set sizes *m* and *n*. Functionality:

|– Wait for input X = {x₁,...,x||}⊂{0, 1}|from the sender S.|
|---|---|---|---|
|– Wait for input Y – Give output X∪Y|= {y₁,...,y to the receiver R.|}⊂{0, 1}|from the receiver R.|

*m* *∗*

*n* *∗*

Fig. 5: Private Set Union Functionality *F*psu

## 3 Unbalanced Private Set Union from OPRF and Permuted PEQT

In this section, we give our first construction of unbalanced PSU protocol based on OPRF and Per- muted Private EQuality Test (p-PEQT).

3.1 Permuted Private Equality Test We give the formal definition of p-PEQT functionality in Figure6. In this functionality, the sender inputs a vector *⃗r*
*′* = (*r₁* *′* *,...,rn* *′* ) and a permutation *π* over [*n*], while the receiver inputs a vector
*⃗r* = (*r₁,...,rn*). The functionality returns *⃗b* = (*b₁,...,bn*) to the receiver, where *bi*= 1 if and only
if *rπ*(*i*)= *r* *π* *′*

(*i*). In other words, the receiver obtains the permuted result indicating whether its inputs
match those of the sender. The p-PEQT could be viewed as a natural generalization of permuted *matrix* PEQT (pm-PEQT) [TCLZ23]. In pm-PEQT, the inputs to be compared by both parties are matrices, and the sender’s

other input is a matrix permutation (the row-column relationship of any two elements remains un- changed before and after the permutation), while p-PEQT only requires the inputs of both parties to be vectors (note that any *m × n* matrix can be represented as a length-*mn* vector), and there is no limitation for the sender’s input permutation. Therefore, the pm-PEQT [TCLZ23] is actually a special case of p-PEQT.

Parameters: Sender *S*, Receiver *R*, vector length *n* Functionality:

– Wait for input *⃗r* *′* = *{r₁* *′* *,...,rn* *′* *}∈* (*{*0*,*1*}* *l* ) *n* and *π* from the sender *S*. – Wait for input *⃗r* = *{r₁,...,rn}∈* (*{*0*,*1*}* *l* ) *n* from the receiver *R*. – For *i ∈* [*n*], set *bi* = 1 if and only if *rπ*(*i*)= *rπ* *′*

(*i*), otherwise, set *bi* = 0.
– Give *⃗b* = (*b₁,...,bn*) to the receiver *R*.

Fig. 6: Permuted Private Equality Test Functionality *F*p-peqt

Following a similar idea of pm-PEQT [TCLZ23], we propose two p-PEQT constructions. The first is based on the DDH assumption and the second is based on the Permute+Share functionality. The main difference between our p-PEQT constructions and pm-PEQT lies in the efficiency gained by performing only a single permutation, eliminating the need for sequential row and column permutations. The formal descriptions of our two p-PEQT protocols are given in Figure7and Figure8, respectively.

Theorem 1. *Assuming the DDH problem is hard in group* G*, the protocol in Figure7securely com-* *putes F*p*-*peqt*against semi-honest adversaries in the random oracle model.*

Theorem 2. *The protocol in Figure8securely computes F*p*-*peqt*against semi-honest adversaries in* *the* (*F*ps*, F*oprf)*-hybrid model.*

Since our two p-PEQT protocols borrow similar ideas from pm-PEQT [TCLZ23], we do not provide security proof here. For completeness, we give formal proofs of Theorem1and2in AppendixA.

3.2 Protocol Details The formal description of our unbalanced PSU protocol from OPRF and permuted PEQT is given in Figure9.

|Correctness. For all i||∈ [m], we consider the following three cases: (1) if X|||||[i]|Y, there is|
|---|---|---|---|---|---|---|---|---|
|∗|∗|∗ k ∗ π|∗ (i) ∗|∗ i|i′|||∗ i ∗|
|||||||i′|||
|i|k ∗ i′ i|∗|−λ|∗|∗|∗ π (i)|||
|||i|||||i′|π (i)|

*c* *∗* *∈* an *Y* *∗* [*i*][*α*] *∈ Y,α ∈* [*|Y* *∗* [*i*]*|*] s.t. *X* *∗* [*i*] = *Y* *∗* [*i*][*α*]. We have *r* = Decode(*D₀||D₁,X* *∗* [*i*]) *− qi*= Decode(*D₀||D₁,Y* [*i*][*α*]) *− F* (*Y* [*i*][*α*]) = *r*, according to the correctness of OPRF, OKVS and BatchPIR. Therefore, we have *b −*1 = 1 and the receiver learns *⊥* in the final OT, according to the correctness of p-PEQT and OT. (2) if *X* [*i*] *∈/ Y* and *X* *∗* [*i*] *̸*= *d*, we have *r* = Decode(*D₀||D₁,X* [*i*])*−* *q*, where *qi*= *F* (*X* [*i*]) is pseudorandom. By setting *l* = *λ* + log *|Y* [*i*]*|*, a union bound shows probability of *r* = *r* is negligible 2. As a result, the receiver learns *b −*1 = 0 with overwhelming probability and receives *X* [*i*] in OT. (3) if *X* [*i*] *∈/ Y* and *X* [*i*] = *d*, we have *r* is randomly selected by the sender, which equals *r* with negligible probability. As a result, the receiver learns *b −*1 = 0 with overwhelming probability and receives *d* in OT. Note that the receiver throws dummy item *d* away from the output. Overall, the receiver learns exactly the item in *Y \ X*, and the set union *X∪Y* = (*Y \ X*) *∪ Y*.

Theorem 3. *Given a BatchPIR with query privacy and a sparse OKVS scheme, the protocol in Figure* *9securely computes F*psu*against semi-honest adversaries in the* (*F*oprf*, F*p*-*peqt*, F*ot)*-hybrid model.*

*Proof.* Due to space limitation, we only sketch here the simulators for the two cases of corrupt *S* and corrupt *R*, and the full proof (via hybrid arguments) is deferred to AppendixB.

Parameters:

– Two parties: sender *S* and receiver *R*, vector length *n*. – A group G with generator *g* and order *p*, and the DDH problem is hard in G. – Random oracle *H* : *{*0*,*1*}* *l* *→* G.

Input of *S*: *⃗r* *′* = (*r₁* *′* *,...,rn* *′* ) *∈* (*{*0*,*1*}* *l* ) *n* *,π* Input of *R*: *⃗r* = (*r₁,...,rn*) *∈* (*{*0*,*1*}* *l* ) *n* Protocol:

1.The receiver *R* selects a random *a ←* Z*p* and computes *vi* := *H*(*ri*)
*a* for *i ∈* [*n*]. Then, *R* sends *{vi}i∈*[*n*]to the sender *S*.

2. *S* selects a random *b ←* Z*p* and computes *vi′*:= *H*(*rπ*
*′*

(*i*)) *b* *, v*¯*i* = (*vπ*(*i*))
*b* for *i ∈* [*n*]. Then, *S* sends *{vi′, v*¯*i}i∈*[*n*]to the receiver *R*.

3.For *i ∈* [*n*], the receiver *R* defines *bi* := 1 if and only if *vi′a*= ¯*vi*, otherwise, *bi* := 0. Then, *R* outputs *⃗b* := (*b₁,...,b*
*n*).
Fig. 7: Permuted Private Equality Test Protocol *Π*p-peqt from DDH Assumption

Parameters:

– Two parties: sender *S* and receiver *R*, vector length *n* – Ideal *F*oprfand *F*ps primitives specified in Figure3and Figure4respectively.

Input of *S*: *⃗r* *′* = (*r₁* *′* *,...,rn* *′* ) *∈* (*{*0*,*1*}* *l* ) *n* *,π* Input of *R*: *⃗r* = (*r₁,...,rn*) *∈* (*{*0*,*1*}* *l* ) *n* Protocol:

1. *S* and *R* invoke the Permute + Share functionality *F*ps. The receiver *R* acts as the sender in Permute + Share with input *⃗r*, and learns *⃗α*. The sender *S* acts as the receiver in Permute + Share with input *π* and receives *β⃗*, where *αi ⊕ βi* = *rπ*(*i*)*,i ∈* [*n*].
2. *S* and *R* invoke the OPRF functionality *F*oprf. The receiver *R* acts as the receiver in OPRF with input *{αi}i∈*[*n*], and learns *{Fk*(*αi*)*}i∈*[*n*]. The sender *S* acts as the sender in OPRF with no input, and receives a PRF key *k*.
3.The sender *S* computes *fi* := *Fk*(*rπ*
*′*

(*i*)*⊕ βi*) for *i ∈* [*n*] and sends *{fi}i∈*[*n*]to the receiver *R*.
4.For *i ∈* [*n*], the receiver *R* defines *bi* := 1 if and only if *fi* = *Fk*(*αi*), otherwise, *bi* := 0. Then, *R* outputs *⃗b* := (*b₁,...,bn*).
Fig. 8: Permuted Private Equality Test Protocol *Π*p-peqt from Permute + Share

<u>Corrupt Sender:</u> The simulator invokes the OPRF receiver’s simulator with random values to simulate the sender’s view in the OPRF protocol. Then, the simulator picks a random sparse OKVS *D* = *D₀||D₁*, and executes as an honest receiver with *D* to simulate the steps that involve OKVS, i.e., the steps 5-8. Finally, the simulator invokes the simulators of p-PEQT and OT to obtain the sender’s view in p-PEQT and OT protocols.

Briefly, this simulation is indistinguishable for the following reasons: the one-time pads generated by OPRF are computationally indistinguishable from random values, and then by the obliviousness of OKVS, *D* is distributed uniformly. The security of underlying OPRF, p-PEQT, and OT protocols also guarantees that the output of the simulator is indistinguishable from the real view.

<u>Corrupt Receiver:</u> The simulator defines the set *Z* := *X ∪Y \Y*, i.e., the set of elements that *X* “brings to the union”, and uses dummy items to pad *Z* to *m* elements. The simulator uses *Z* as the sender’s input to execute protocol honestly. For steps involving BatchPIR, the simulator selects some random indexes to simulate the sender’s query. This simulation is indistinguishable from the real view by the security of underlying OPRF, p-PEQT, and OT protocols and the query privacy of the BatchPIR scheme.

Parameters:

– Two parties: sender *S* and receiver *R*, set size *m* and *n*, where *m ≪ n*. – Ideal *F*ot, *F*oprfand *F*p-peqt primitives specified in Figure2, Figure3, and Figure6respectively. – A sparse OKVS scheme (Encode*,*Decode) with key space *K* = *{*0*,*1*}* *∗* and value space *V* = F. Let spa : *K→{*0*,*1*}* *s* and den : *K→{*0*,*1*}* *d* be the random function used in Encode, and pos*j*: *K→* [*s*] be the function such that pos*j*(*y*) denotes the *j*-th position of 1 in spa(*y*). Let *w* denote the Hamming weight of the sparse part.

Input of *S*: *X* = *{x₁,...,xm}⊂{*0*,*1*}* *∗* Input of *R*: *Y* = *{y₁,...,yn}⊂{*0*,*1*}* *∗* Protocol:

1.The sender *S* inserts set *X* into the Cuckoo hash table, and fills empty bins with the dummy item
*d*. Let *mc* = (1 + *ϵ*)*m* denote the length of the Cuckoo hash table. *S* denotes the filled Cuckoo hash table as *X* *∗*
and the item in *i*-th bin as *X* *∗* [*i*] for *i ∈* [*mc*]. Let *σ* : [*m*] *→* [*mc*] denote the injective function such that *σ*(1)*,...,σ*(*m*) are the non-dummy item bins of *X* *∗*.

2.The receiver *R* inserts set *Y* into the simple hash table. Then *R* denotes the simple hash table as *Y*
*∗*, the set of items in *i*-th bin as *Y* *∗* [*i*] and the *α*-th item in *Y* *∗* [*i*] as *Y* *∗* [*i*][*α*] for *i ∈* [*mc*]*,α ∈* [*|Y* *∗* [*i*]*|*].

3.The receiver *R* selects random *ri ∈* F for each bin *i ∈* [*mc*]. Let *⃗r* := (*r₁,...,rmc*).
4. *S* and *R* invoke the OPRF functionality *F*oprf. The receiver *R* acts as the sender in OPRF with no input, and learns a PRF key *k*. The sender *S* acts as the receiver in OPRF with input *{X*
*∗* [*σ*(*j*)]*}j∈*[*m*] and receives *Q* := *{q₁,...,qm}*, where *qj* = *Fk*(*X* *∗* [*σ*(*j*)])*,j ∈* [*m*].

5.The receiver *R* defines *P* := *{*(*Y*
*∗* [*i*][*α*]*,ri* + *Fk*(*Y* *∗* [*i*][*α*]))*}i∈*[*mc*]*,α∈*[*|Y ∗*[*i*]*|*]and computes the sparse OKVS *D₀||D₁* := Encode(*P*) *∈* F *s* *×* F *d*.

6.The sender *S* defines *I* := *{*pos*t*(*X*
*∗* [*σ*(*j*)])*}t∈*[*w*]*,j∈*[*m*]. Then, *S* computes (st*,*qu) *←* Query(*I*) and sends qu to the receiver *R*.

7.The receiver *R* computes ans *←* Answer(*D₀,*qu) and sends (ans*,D₁*) to the sender *S*.
8.The sender *S* computes *{D*
P *t,j}t∈*[*w*]*,j∈*[*m*]:= Recover(st*,*ans), where *Dt,j* = *D₀*[pos*t*(*X* *∗* [*σ*(*j*)])]. For *j ∈* [*m*], *S* computes *rj′*:=*t∈*[*w*]*Dt,j* + *⟨D₁,*den(*X* *∗* [*σ*(*j*)])*⟩− qj*. *S* also picks random *ri′←* F for *i ∈* [*mc*] *\{σ*(*j*)*}j∈*[*m*]. Let *⃗r* *′* := (*r₁* *′* *,...,rm* *′* *c* ).

9.The sender *S* selects a random permutation *π* over [*mc*]. Then, *S* and *R* invoke the permuted PEQT functionality *F*p-peqt. The receiver *R* acts as the receiver with input *⃗r* and receives *⃗b* = (*b₁,...,bmc*). The sender *S* acts as the sender with input (*⃗r*
*′* *,π*) and receives nothing. Note that *bi* = 1 if and only if *rπ*(*i*)= *rπ* *′*

(*i*).
10.The receiver *R* initialize set *Z* := *{}*. Then, for *i ∈* [*mc*], *S* and *R* invoke the OT functionality *F*ot: *S* acts as sender with input (*X*
*∗* [*π*(*i*)]*, ⊥*) and receives nothing. *R* acts as receiver with input *bi* and receives *zi*. *R* sets *Z* := *Z ∪{zi}* if *zi ̸*= *d*.

11.The receiver *R* outputs *Y ∪ Z*.
Fig. 9: Unbalanced PSU Protocol *Π*psu from OPRF and p-PEQT

## 4 Unbanlanced Private Set Union from Re-randomizable PKE

In this section, we give our second construction of unbalanced PSU protocol based on ReRand-PKE. The formal description is given in Figure9.

Correctness. For all *j ∈* [*m*], we consider the following two cases: (1) if *xj∈ Y*, there is an *yi∈* *Y,i ∈* [*n*] s.t. *xj*= *yi*. According to the correctness of ReRand-PKE, OKVS and BatchPIR, we have *s* *′j* = Decode(*D₀||D₁,xj*) = Decode(*D₀||D₁,yi*) = *si*. Since *si*= Enc(*pk,*0), we have Dec(*sk,si*) = 0, which means *bj*= 1. So the receiver learns *⊥* in the final OT. (2) if *xj∈/ Y*, from the random decoding property of OKVS, *s* *′j* = Decode(*D₀||D₁,xj*) is a random ciphertext, resulting in *s* *′j* is not the encryption of 0 with overwhelming probability. Since the size ciphertext space is at least

|κ λ+log m|||j|||′j|
|---|---|---|---|---|---|---|
||′j|||j|||
||j||||||

*≥*, the union bound guarantees that for all *x ∈/ Y*, the probability that there exists an *s*

s.t. Dec(*sk,s*) = 0 is negligible. As a result, the receiver learns *b* = 0 with overwhelming probability and receives *x* in OT. Overall, the receiver learns exactly the item in *Y \ X*, and the set union *X∪Y* = (*Y \ X*) *∪ Y*.

Parameters:

– Two parties: sender *S* and receiver *R*, set size *m* and *n*, where *m ≪ n*. – Ideal *F*ot primitive specified in Figure2. – A sparse OKVS scheme (Encode*,*Decode) with key space *K* = *{*0*,*1*}* *∗* and value space *V* = F. Let spa : *K→{*0*,*1*}* *s* and den : *K→{*0*,*1*}* *d* be the random function used in Encode, and pos*j*: *K→* [*s*] be the function such that pos*j*(*y*) denotes the *j*-th position of 1 in spa(*y*). Let *w* denote the Hamming weight of the sparse part. – A ReRand-PKE scheme (Setup*,*KeyGen*,*Enc*,*Dec*,*ReRand) that satisfies single-message multi- ciphertext pseudorandomness.

Input of *S*: *X* = *{x₁,...,xm}⊂{*0*,*1*}* *∗* Input of *R*: *Y* = *{y₁,...,yn}⊂{*0*,*1*}* *∗* Protocol:

1.The receiver *R* generates a random key pair *pp ←* Setup*,* (*pk,sk*) *←* KeyGen(*pp*), a randomness set *R* = *{r₁,...,rn}* and computes *si* := Enc(*pk,*0;*ri*) for *i ∈* [*n*].
2.The receiver *R* computes the sparse OKVS *D₀||D₁* := Encode((*y₁,s₁*)*,...,*(*yn,sn*)) *∈* F
*s* *×* F *d*.

3.The sender *S* defines *I* := *{*pos*t*(*xj*)*}t∈*[*w*]*,j∈*[*m*]. Then, *S* computes (st*,*qu) *←* Query(*I*) and sends qu to the receiver *R*.
4.The receiver *R* computes ans *←* Answer(*D₀,*qu) and sends (ans*,pk,D₁*) to the sender *S*.
5.The sender *S* computes
P *{Dt,j}t∈*[*w*]*,j∈*[*m*]:= Recover(st*,*ans), where *Dt,j* = *D₀*[pos*t*(*xj*)]. For *j ∈* [*m*], *S* computes *s* *′j* :=*t∈*[*w*]*Dt,j* + *⟨D₁,*den(*xj*)*⟩*.

6.The sender *S* selects random *r₁*
*′* *,...,rm* *′* and computes *s*¯*j* := ReRand(*pk,s* *′j*; *rj′*) for *j ∈* [*m*].

7.The sender *S* sends *s*¯1*,..., s*¯*m* to *R*.
8.The receiver *R* sets *bj* = 1 if and only if Dec(*sk, s*¯*j*) = 0 for *j ∈* [*m*].
9.The receiver *R* initialize set *Z* := *{}*. Then, for *j ∈* [*m*], *S* and *R* invoke the OT functionality *F*ot: *S* acts as sender with input (*xj, ⊥*) and receives nothing. *R* acts as receiver with input *bj*. *R* receives *z* *j* from OT and sets *Z* = *Z ∪{zj}*.
10.The receiver *R* outputs *Y ∪ Z*.
Fig. 10: Unbalanced PSU Protocol *Π*psu from ReRand-PKE

Theorem 4. *Given a BatchPIR scheme with query privacy, a ReRand-PKE scheme with single-* *message multi-ciphertext pseudorandomness property and a sparse OKVS scheme, the protocol in* *Figure10securely computes F*psu*against semi-honest adversaries in the F*ot*-hybrid model.*

*Proof.* Due to space limitation, we only sketch here the simulators for the two cases of corrupt *S* and corrupt *R*, and the full proof (via hybrid arguments) is deferred to AppendixC.

<u>Corrupt Sender:</u> The simulator picks a random sparse OKVS *D* = *D₀||D₁*, and executes as an honest receiver with *D* to simulate the steps that involve OKVS, i.e., the steps 1-5. Then, the simulator invokes the simulator of OT to obtain the sender’s view in OT protocol. Briefly, this simulation is indistinguishable for the following reasons: the single-message multi- ciphertext pseudorandomness of the ReRand-PKE scheme ensures that value (ciphertext) is indis- tinguishable from random, and then by the obliviousness of OKVS, *D* is distributed uniformly. The security of underlying OT protocol also guarantees that the output of the simulator is indistinguishable from the real view. <u>Corrupt Receiver:</u> Similar to theorem3, the simulator defines the set *Z* := *X∪Y \Y*, and pads *Z* to *m* elements. The simulator uses *Z* as the sender’s input to execute protocol honestly. For steps involving BatchPIR, the simulator selects some random indexes to simulate the sender’s query. This simulation is indistinguishable from the real view by the security of the underlying OT protocol and the query privacy of the BatchPIR scheme.

4.1 Optimization The encoding algorithm of OKVS actually involves solving a system of linear equations in the value space. In the protocol description in Figure10, the value space is the ciphertext space of the ReRand- PKE scheme, typically corresponding to a certain group G. In our implementation, we use the ElGamal

encryption scheme [Gam85] as the ReRand-PKE instantiation. The ciphertext space of the ElGamal encryption scheme is G², where DDH assumption holds in G and the order of G is a prime *p*. Solv- ing a linear system in G incurs a high cost. Therefore, we propose a “pull-down-then-lift” method. Specifically, we first compute the OKVS over Z*p*, where Z*p*denotes the finite field of integers modulo

*p*. Subsequently, we lift the computed OKVS from Z*p*to the exponent. This method allows us to mit- igate the computational overhead associated with solving linear systems in G, resulting in improved efficiency. Further details are provided below.

|||r|
|---|---|---|
|sk|r i i|p sk·r i|
|d|||
 The structure of ElGamal ciphertext *c* = (*g,m · pk*
*r* ), where *g ∈* G is the generator of group G, *pk* = *g*, and *r* is a random value in Z. Since *m* is the set indicator and could be set to an arbitrary value, we have *c* = (*c₁,c₂*) = (*g,g*) by setting *m* = 1. Our encoding process first com-
putes *d* = (*d₁,...,dN*) := Encode(*x,r ||sk · r*), and then outputs the OKVS *D* = (*D₁,...,DN*) :=
(*g* *d* 1 *,...,gN*). However, this approach may raise security concerns. One may want to know if the OKVS generated as above still satisfies obliviousness. The condition for obliviousness is that all val- ues are randomly selected, and in our construction, values are not completely random due to the correlation between *ri*and *sk · ri*. We argue that this construction actually satisfies obliviousness. The key observation is that the lift step is crucial as it can prevent a PPT adversary from “detect- ing” the correlation in exponential. Specifically, we split *di*in two parts, namely, (*d¹i,d²i*), where *d¹i* corresponds to the encoding of *{*(*xi,ri*)*}* and *d²i*corresponds to the encoding of *{*(*xi,sk · ri*)*}*. We have *d²i*= *sk · d¹i*from the linearity of the encoding algorithm. After lifting, the adversary only sees *sk d* *i* 1*d* *i* 2*sk·d* *i* 1 *pk* = *g, {g,g* = *g}*, which exactly corresponds to a DDH tuple. Therefore, the DDH assump- tion guarantees generating the OKVS in a “pull-down-then-lift” manner still satisfies obliviousness. We provide a formal proof in AppendixD.

## 5 Implementation and Performance

We experimentally evaluate our PSU protocols and compare them with the state-of-the-art counter- parts [TCLZ23]. For ease of description, we refer to each scheme as follows.

– PSU ddh op: our OPRF + p-PEQT based construction presented in Figure9, and the p-PEQT is built from DDH assumption, as shown in Figure7. – PSU ps op: our OPRF + p-PEQT based construction presented in Figure9, and the p-PEQT is built from Permute + Share functionality, as shown in Figure8. – PSUpk: our ReRand-PKE based construction presented in Figure10.

5.1 Implementation Details We implement our protocols and fully re-implement [TCLZ23] based on mpc4j [mpc]. In this way, we can conduct a comprehensive and fair comparison in a unified platform. The complete implementation is merged into mpc4j and freely available now. The reasons for re-implementing the protocol proposed by Tu et al. [TCLZ23] instead of directly running their implementation on our platform are as follows. Firstly, their implementation did not explore the potential benefits of using preprocessing techniques. The preprocessing technique is to divide protocol execution into two phases, namely the *setup phase* and the *online phase*. The setup phase, which typically includes key distribution, base OT, and input-independent pre-computation, only needs to be executed once. After the setup phase, the parties can then enjoy a faster online phase with their inputs. Preprocessing is a standard technique in secure multiparty computation, especially in PSO protocols [KLS
+ 17,RS21,ZCL + 23,KBM23]. We note that in the unbalanced setting, existing works additionally assume that the party with large set can ahead of time knows its input and further perform necessary pre-computations with this knowledge [CHLR18,CMdG + 21,HLP + 24]. In our re- implementations, we enabled [TCLZ23] to benefit from preprocessing techniques, resulting in a more efficient online phase. Moreover, the protocols in [TCLZ23] avoid the expensive noise flooding operations by leverag- ing OPRF to randomize elements in each party’s input set. This technique was first introduced in [CHLR18] and has been widely used in unbalanced PSO protocols. However, Tu et al. [TCLZ23] use the OT-based OPRF [KKRT16] in their implementation. As mentioned in [CHLR18], such OPRF has two main limitations: (1) it requires both parties to perform a hash-to-bin operation before OPRF

evaluation, hindering the potential for integrating OPRF preprocessing into the setup phase; (2) it requires the sender to pad its simple hash bin with dummy items to prevent the receiver from inferring partial information, which makes the actual number of OPRFs executed by both parties slightly higher than the set size, causing additional overhead. We follow the recommendation of [CMdG + 21] and use DH-based OPRF in our re-implementation [JL10]. The sender in such OPRF can select the key and perform arbitrary computations without the knowledge of the input from the receiver, allowing OPRF preprocessing in the setup phase. Additionally, no hash-to-bin operation is required in this OPRF, circumventing unnecessary OPRF evaluations. Aside from the above improvement, our re-implementation of [TCLZ23] fully complies with their open-source code [APS23]. That is, the underlying components we use are exactly the same as them, with the sole difference being the adoption of DH-OPRF [JL10] for OPRF preprocessing. The details of the underlying components in our protocol implementations are as follows. *OPRF*. Two OPRFs are used in our protocols. The first is the OPRF used in our PSU ddh opand PSU ps opto generate one-time pads (i.e., the step 4 in Figure9). We opt for the DH-based OPRF [JL10], allowing the receiver to compute the PRF values of its inputs during the setup phase. For better efficiency, we use the FourQ [CL15] to speed up the scalar multiplication of elliptic curve points. The second is the OPRF used in our PSU ps opto conduct the equality test (i.e., the step 2 in Figure8). Here, we employ BaRK-OPRF [KKRT16], which facilitates a faster running time during the online phase. *OKVS*. We implement the blazing-fast OKVS [RR22] with clustering as our sparse OKVS instan- tiation, and employ 3 hashing functions to create the sparse OKVS storage. Although the recently proposed RB-OKVS [BPSY23] also satisfies sparsity, its sparse part exhibits a large Hamming weight (typically *≥* 196), which significantly diminishes efficiency. Therefore, we opted not to use RB-OKVS as our instantiation. In PSUpk, the underlying field of OKVS is instantiated as F*p*, while in PSU ps opand PSU ddh op, the underlying field of OKVS is instantiated as F₂*l*. *ReRand-PKE*. We use ElGamal encryption [Gam85] as the ReRand-PKE instantiation. We choose the secp256r1 implementation in OpenSSL [Ope] as the underlying elliptic curve since it provides the most efficient assembly language implementation. We pre-compute lookup tables for the generator *g* and the public key *y* in the setup phase to accelerate fixed-point multiplication in the online phase. *BatchPIR*. We employ the state-of-the-art vectorized BatchPIR [MR23] as our BatchPIR instantiation. We adopt the Java Native Interface (JNI) technique to invoke the BFV homomorphic encryption [FV12] provided by Microsoft SEAL library v4.0 [SEA22]. We follow the same parameters used in the open-source codes of the vectorized BatchPIR [Vec23]. Specifically, the receiver uses stash-less cuckoo Hashing with 3 hash functions to insert the *n* entries into 1*.*2*n* bins. The receiver encodes entries in each bin in three dimensions, places them at suitable slots, and transfers the plaintext polynomial into NTT form. Vectorized BatchPIR also requires both Galois keys and relinearization keys for rotation and multiplication operations. All the above operations are done in the setup phase. *ECC*. In addition to DH-based OPRF and ReRand-PKE, our DDH-based p-PEQT also requires ECC (i.e., the p-PEQT construction in Figure7). Given that addition operations are not needed in this construction, we follow the recommendation by [CZZ + 24] and introduce X25519 in Sodium [Sod] for efficient scalar multiplications. *Permute + Share*. Similar to the TCLZ protocol [TCLZ23], we implement the Permute + Share functionality based on [MS13]. *OT*. We follow the default setting in mpc4j by choosing the base OT proposed in [NP01] and the OT extension proposed in [ALSZ13].

5.2 Experimental Setup We conducted our experiments on a single Intel Core i9-9900K with 3.6GHz and 128GB RAM. All experiments are executed with 8 threads. We set the computational security parameter *κ* = and the statistical security parameter *λ* = 40. We simulate the network connection using the Linux command tc. To evaluate the efficiency of the protocols in different network settings, we use two simulated network settings, including LAN (10Gbps bandwidth and 0.05ms RTT latency) and WAN (100Mbps, 10Mbps and 1Mbps bandwidth with 80ms RTT latency).

5.3 Performance Evaluation We compare our protocols with the state-of-the-art unbalanced PSU protocols [TCLZ23], which com- prises two protocols: TCLZ-pub and TCLZ-sym. A detailed benchmark for small set sizes *|X|* = *m ∈* *{*2 4 *,*2 6 *,*2 8 *,*2
10 *}* and large set sizes *|Y |* = *n ∈ {*2 18 *,*2 20 *,*2 22 *}* is presented in Table1. Additionally, Figure11illustrates the variation of communication/running time with small set size/bandwidth.

18TCLZ-pub 18TCLZ-pub = 2 TCLZ-sym = 2 *|* TCLZ-sym *|* PSUpk

||Y|PSU||Y|PSU|
|---|---|---|---|
|10||||

*|Y* PSUpk

|ddh PSU op|||1, 10 6|||||ddh PSU op|
|---|---|---|---|---|---|---|---|---|
|ps PSU op|||= 2 | |X|||||ps PSU op|
||||0||||||
|4 6 2 2 The size of small set|8 2 |X|∈{|10 2 4 6 8 10 2, 2, 2, 2} TCLZ-pub TCLZ-sym PSU pk ddh PSU op ps PSU op|10 Running time (s), 1Mbps 1. 8 10 1. 6 10, 1 Mbps 18 = 2 1. 4 | 10 |Y 1. 2|10Mbps TCLZ-pub TCLZ-sym PSU PSU op PSU|pk ddh ps op|100Mbps The network bandwidth (Mbps)||10Gbps|
||||10 1||||||
||||10||||||

*|Y*

0*.*5 100
Communication (in MB),

, 10 Gbps 18 = 2 0*.*5 *|* 10 *|Y*

100 Running time (s), Running time (s), 2 42628210

||2|2 2|2|2 2|
|---|---|---|---|---|
||The size of small set |X|∈{2|, 2, 2, 2}|The size of small set |X|∈{2|, 2, 2, 2}|

2 42628210 4 6 8 10 4 6 8 10

Fig. 11: Communication cost (in MB) and running time (in seconds) comparing our protocols to TCLZ-pub

and TCLZ-sym [TCLZ23]. Both *x* and *y*-axis are in log scale. The top left figure shows the communication cost increases as the small set size increases. The top right figure shows the runtime decreases as the bandwidth increases. The bottom two figures show the runtime increases as the small set size increases in different bandwidths (i.e., 10 Gbps and 1 Mbps).

Communication comparison. As indicated in Table1and the top left figure in Figure11, our protocols achieve the lowest online communication cost when the small set size is less than 2 8. Com- pared to the TCLZ protocols, the communication of our constructions is 2*.*1 *∼* 11*.*8*×* better. Notably, the communication costs of our protocols increase linearly with the size of small sets, while the com- munication of TCLZ protocols remains almost unchanged when the small set size is less than 2 10. The reason is that the TCLZ protocols use Single Instruction Multiple Data (SIMD) operations to package multiple plaintexts into one ciphertext for concurrent processing. Specifically, the TCLZ pro- tocols employ ciphertexts containing 1638 plaintext slots. Therefore, as long as the number of bins of the sender is less than 1638 (corresponding to a set size of approximately 2 10 ), their communication remains unchanged. As a result, our protocols perform better in the extremely unbalanced setting, showcasing increasing communication efficiency ratios as the gap between the sizes of the two sets widens. Running time comparison. The experimental results in Table1and Figure11indicate that our OPRF + p-PEQT based unbalanced PSU protocols PSU ps op*,*PSU ddh opperform better in most settings, and outperform TCLZ protocols. Specifically, the running time of our PSU ps opand PSU ddh opprotocols sur- passes TCLZ protocols by 1*. ∼. ×* in different bandwidth setting. For example, for *m* = 2*,n* = 2 in 1 Mbps bandwidth, our PSU ddh oprequires 7*.*98 seconds, while TCLZ-pub requires 14*.*5 seconds, achiev- ing a 1*. ×* improvement, and TCLZ-sym requires 21*.*93 seconds, achieving a 2*. ×* improvement. Our

Comm. (MB) Running time (s) Param. Protocol LAN 100Mbps 10Mbps 1Mbps

|Protocol|Setup Online|LAN|100Mbps|10Mbps||1Mbps|
|---|---|---|---|---|---|---|
|||Setup Online Setup Online Setup Online Setup Online|||||
|TCLZ-pub [TCLZ23]|0.76 1.52|2.98|1.15 3.67|1.99 3.93|3.11 9.71|14.46|
|TCLZ-sym [TCLZ23]|0.77 2.27|2.98|1.18 4.02|2.48 4.50|4.04 10.25|20.90|
|2 Our PSU|19.08 0.71|11.72|1.13 15.55|2.44 29.60|2.89 174.53|8.30|
|Our PSU|19.09 0.73|12.05|1.14 15.02|2.71 28.79|3.27 173.45|9.29|
|Our PSU|19.08 0.74|38.01|7.52 40.16|8.11 52.31|8.32 197.53|13.92|
|TCLZ-pub [TCLZ23]|0.76 1.52|2.84|1.12 3.38|2.01 3.90|3.03 9.59|14.50|
|TCLZ-sym [TCLZ23]|0.77 2.27|2.83|1.11 3.72|2.88 4.15|4.44 10.13|21.93|
|2 Our PSU|19.08 0.72|14.99|0.86 17.19|1.72 31.25|2.18 175.06|8.04|
|Our PSU|19.09 0.75|14.00|0.88 17.72|2.00 30.94|2.36 175.34|7.98|
|Our PSU|19.08 0.74|34.88|2.32 37.57|2.92 52.14|3.62 196.42|9.13|
|TCLZ-pub [TCLZ23]|0.76 1.53|2.85|1.15 3.48|1.91 3.92|3.08 9.55|14.66|
|TCLZ-sym [TCLZ23]|0.77 2.28|2.87|1.13 3.89|2.25 4.11|3.77 9.95|20.98|
|2 Our PSU|19.08 1.44|21.78|0.94 24.58|1.88 38.30|3.42 183.08|14.15|
|Our PSU|19.09 1.52|21.43|0.95 24.41|2.13 38.66|3.13 182.88|14.53|
|Our PSU|19.08 1.70|59.15|2.24 61.30|3.07 76.01|4.35 219.35|17.46|
|TCLZ-pub [TCLZ23]|0.76 1.58|2.80|1.17 3.43|1.94 3.69|3.17 9.70|14.97|
|TCLZ-sym [TCLZ23]|0.77 2.33|2.95|1.11 3.70|2.31 4.33|3.88 9.99|21.36|
|2 Our PSU|19.08 5.71|22.67|1.28 25.34|3.37 39.50|6.99 184.55|49.83|
|Our PSU|19.09 6.07|22.17|1.16 25.39|3.17 39.45|7.43 184.40|54.09|
|Our PSU|19.08 3.90|124.79|2.96 128.02|4.21 141.98|7.05 286.85|36.41|
|TCLZ-pub [TCLZ23]|0.76 1.86|14.47|1.68 15.27|2.55 15.62|3.90 20.76|18.51|
|TCLZ-sym [TCLZ23]|0.77 3.52|14.61|1.63 15.26|3.04 15.81|5.40 21.92|31.90|
|2 Our PSU|19.08 0.76|42.34|3.07 45.15|4.17 58.63|4.76 205.86|10.83|
|Our PSU|19.09 0.77|42.09|3.10 45.77|4.59 59.81|5.26 203.93|11.92|
|Our PSU|19.08 0.88|89.39|8.84 94.72|9.40 108.37|10.71 252.10|16.82|
|TCLZ-pub [TCLZ23]|0.76 1.87|14.20|1.61 14.48|2.44 15.16|3.78 21.33|17.95|
|TCLZ-sym [TCLZ23]|0.77 3.52|15.23|1.55 15.42|3.63 15.64|6.19 21.37|32.77|
|2 Our PSU|19.08 1.45|42.53|1.39 46.21|2.24 58.51|3.34 203.39|15.14|
|Our PSU|19.09 1.48|42.63|1.34 58.96|2.74 73.43|4.77 216.41|27.73|
|Our PSU|19.08 0.89|135.13|8.08 135.17|8.27 146.61|8.94 293.32|15.65|
|TCLZ-pub [TCLZ23]|0.76 1.88|14.66|1.59 15.14|2.41 15.05|3.81 20.70|18.00|
|TCLZ-sym [TCLZ23]|0.77 3.53|14.13|1.54 15.13|2.90 15.38|5.41 21.61|32.00|
|2 Our PSU|19.08 2.86|54.80|1.29 58.14|2.59 73.32|4.56 216.79|26.45|
|Our PSU|19.09 2.94|55.18|1.35 58.96|2.74 73.43|4.77 216.41|27.73|
|Our PSU|19.08 2.97|138.53|3.19 136.75|3.93 151.06|6.16 299.52|29.09|
|TCLZ-pub [TCLZ23]|0.76 1.92|14.42|1.60 15.22|2.45 15.15|3.86 21.41|18.43|
|TCLZ-sym [TCLZ23]|0.77 3.58|14.26|1.55 15.21|2.97 16.02|5.48 21.48|32.55|
|2 Our PSU|19.08 5.76|85.49|1.93 89.58|3.71 102.54|7.90 245.92|50.95|
|Our PSU|19.09 6.15|85.76|1.92 91.20|3.82 101.64|7.96 247.21|54.96|
|Our PSU|19.08 6.80|232.43|3.65 234.26|5.37 247.47|10.14 431.10|61.93|
|TCLZ-pub [TCLZ23]|0.76 3.59|60.60|3.21 60.69|4.51 60.64|6.89 67.03|34.86|
|TCLZ-sym [TCLZ23]|0.77 11.13|61.39|3.02 61.74|5.28 63.20|13.31 67.48|97.47|
|2 Our PSU|19.08 0.94|182.08|7.40 187.18|9.94 202.34|10.08 345.77|17.38|
|Our PSU|19.09 0.96|185.43|7.55 190.21|9.34 203.74|10.60 349.34|18.19|
|Our PSU|19.08 1.46|302.23|13.27 305.25|14.03 319.06|15.46 465.35|26.58|
|TCLZ-pub [TCLZ23]|0.76 3.59|62.04|3.05 62.10|4.24 61.96|6.75 67.95|34.47|
|TCLZ-sym [TCLZ23]|0.77 11.13|61.90|2.98 61.98|5.96 60.80|14.35 67.73|98.07|
|2 Our PSU|19.08 1.64|221.34|6.03 223.13|7.01 229.80|9.05 373.27|20.91|
|Our PSU|19.09 1.66|216.53|6.61 217.72|7.32 235.72|8.51 380.17|21.50|
|Our PSU|19.08 2.16|424.83|11.25 417.94|11.98 442.52|13.69 584.50|29.81|
|TCLZ-pub [TCLZ23]|0.76 3.60|60.62|3.26 61.03|4.39 61.71|6.89 66.99|34.31|
|TCLZ-sym [TCLZ23]|0.77 11.15|62.10|3.11 61.25|5.24 62.72|13.42 68.35|98.23|
|2 Our PSU|19.08 5.80|181.34|4.07 181.20|5.79 193.74|9.17 342.64|52.94|
|Our PSU|19.09 5.88|184.88|3.93 188.85|6.20 196.29|9.55 340.90|54.68|
|Our PSU|19.08 3.55|539.48|10.01 548.18|11.53 556.73|13.76 716.74|40.50|
|TCLZ-pub [TCLZ23]|0.76 3.65|60.36|3.07 61.46|4.82 63.69|7.13 67.58|34.65|
|TCLZ-sym [TCLZ23]|0.77 11.19|59.93|3.08 63.29|5.36 63.01|13.36 66.54|97.89|
|2 Our PSU|19.08 10.76|234.33|4.55 238.26|6.51 261.40|14.22 405.45|96.39|
|Our PSU|19.09 11.15|236.02|4.56 239.26|6.89 254.70|14.93 409.62|99.66|
|Our PSU|19.08 11.19|551.38|9.28 554.46|13.23 567.37|18.95 706.52 103.62||

Setup Online *n m*

4 ddh op ps op pk

6 ddh op ps op 18 pk 2

8 ddh op ps op pk

10 ddh op ps op pk

4 ddh op ps op pk

6 ddh op ps op 20 pk 2

8 ddh op ps op pk

10 ddh op ps op pk

4 ddh op ps op pk

6 ddh op ps op 22 pk 2

8 ddh op ps op pk

10 ddh op ps op pk

Table 1: Communication cost (in MB) and running time (in seconds) comparing our protocols to TCLZ-pub

and TCLZ-sym [TCLZ23]. The LAN network has 10 Gbps bandwidth and 0*.*05 ms RTT latency. The best result is marked ingreen, and the second best result is marked inblue.

ReRand-PKE based construction PSUpkexhibits less satisfactory performance due to the relatively long value length of OKVS encoding. In the PSUpkprotocol, the OKVS values are the ciphertexts of ReRand-PKE, which has a length of 256 bits in our instantiation (i.e., ElGamal encryption). The values of OKVS for protocols PSU ps opand PSU ddh opare bit strings, with a length of *λ*+ log*n*, and 64 bits are sufficient in practice. A counterintuitive phenomenon is that the running time for small set size of 2 4 is actually longer than that of 2 6, as shown in the bottom two figures of Figure11. This is due to the property of our BatchPIR instantiation, i.e., vectorized BatchPIR [MR23]. The vectorized BatchPIR scheme repre- sents the database as a three-dimensional matrix. During the server-side response process, the second dimension plays a crucial role, involving rotations and ciphertext-ciphertext multiplications. The over- all running time is heavily influenced by the size of this dimension. When the sender’s set size is 2 4, the number of bins is fewer than that of 2 6. This causes there are more elements in each bin, which leads to a larger matrix size generated by the server and consequently longer running time⁹.

## Acknowledgements

We are grateful for the helpful comments from the anonymous reviewers. This work is supported by the National Key R&D Program of China (2018YFA0704701, 2020YFA0309705), Shandong Key Research and Development Program (2020ZLYS09), the Major Scientific and Technological Innovation Project of Shandong, China (2019JZZY010133), the Major Program of Guangdong Basic and Applied Research (2019B030302008), Tsinghua University Dushi Program, the National Natural Science Foundation of China (Grant No. 62272269), Taishan Scholar Program of Shandong Province, the National Key Research and Development Program of China (Grant No. 2021YFA1000600), the Major Programs of the National Social Science Foundation of China (Grant No. 22&ZD147), and the National Natural Science Foundation of China (Grant No. 62402272).

## References

[ACLS18]Sebastian Angel, Hao Chen, Kim Laine, and Srinath T. V. Setty. PIR with compressed queries and amortized query processing. In *2018 IEEE Symposium on Security and Privacy, SP 2018,* *Proceedings, 21-23 May 2018, San Francisco, California, USA*, pages 962–979. IEEE Computer Society, 2018. [ALSZ13]Gilad Asharov, Yehuda Lindell, Thomas Schneider, and Michael Zohner. More efficient oblivious transfer and extensions for faster secure computation. In *CCS 2013*, 2013. [APS23] [https://github.com/real-world-cryprography/APSU](https://github.com/real-world-cryprography/APSU), 2023. [BPSY23]Alexander Bienstock, Sarvar Patel, Joon Young Seo, and Kevin Yeo. Near-optimal oblivious key-value stores for efficient psi, PSU and volume-hiding multi-maps. In Joseph A. Calandrino and Carmela Troncoso, editors, *32nd USENIX Security Symposium, USENIX Security 2023,* *Anaheim, CA, USA, August 9-11, 2023*, pages 301–318. USENIX Association, 2023. [BSMD10]Martin Burkhart, Mario Strasser, Dilip Many, and Xenofontas A. Dimitropoulos. SEPIA: privacy- preserving aggregation of multi-domain network events and statistics. In *19th USENIX Security* *Symposium, Washington, DC, USA, August 11-13, 2010, Proceedings*, pages 223–240. USENIX Association, 2010. [CGN98]Benny Chor, Niv Gilboa, and Moni Naor. Private information retrieval by keywords. *IACR* *Cryptol. ePrint Arch.*, page 3, 1998. [CGP20]Melissa Chase, Esha Ghosh, and Oxana Poburinnaya. Secret-shared shuffle. In Shiho Moriai and Huaxiong Wang, editors, *Advances in Cryptology-ASIACRYPT 2020 - 26th International* *Conference on the Theory and Application of Cryptology and Information Security, Daejeon,* *South Korea, December 7-11, 2020, Proceedings, Part III*, volume 12493 of *Lecture Notes in* *Computer Science*, pages 342–372. Springer, 2020. [CHLR18]Hao Chen, Zhicong Huang, Kim Laine, and Peter Rindal. Labeled PSI from fully homomorphic encryption with malicious security. In David Lie, Mohammad Mannan, Michael Backes, and XiaoFeng Wang, editors, *Proceedings of the 2018 ACM SIGSAC Conference on Computer and* *Communications Security, CCS 2018, Toronto, ON, Canada, October 15-19, 2018*, pages 1223–

1237. ACM, 2018.
A similar trend can also be found in the table III of original vectorized BatchPIR paper [MR23].

[CKGS98]Benny Chor, Eyal Kushilevitz, Oded Goldreich, and Madhu Sudan. Private information retrieval.

*J. ACM*, 45(6):965–981, 1998.
[CL15]Craig Costello and Patrick Longa. Fourq: Four-dimensional decompositions on a q-curve over the mersenne prime. In Tetsu Iwata and Jung Hee Cheon, editors, *Advances in Cryptology -* *ASIACRYPT 2015 - 21st International Conference on the Theory and Application of Cryptology* *and Information Security, Auckland, New Zealand, November 29 - December 3, 2015, Proceedings,* *Part I*, volume 9452 of *Lecture Notes in Computer Science*, pages 214–235. Springer, 2015. [CLR17]Hao Chen, Kim Laine, and Peter Rindal. Fast private set intersection from homomorphic en- cryption. In Bhavani M. Thuraisingham, David Evans, Tal Malkin, and Dongyan Xu, editors, *Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security,* *CCS 2017,*, pages 1243–1255. ACM, 2017. [CMdG + 21]Kelong Cong, Radames Cruz Moreno, Mariana Botelho da Gama, Wei Dai, Ilia Iliashenko, Kim Laine, and Michael Rosenberg. Labeled PSI from homomorphic encryption with reduced compu- tation and communication. In Yongdae Kim, Jong Kim, Giovanni Vigna, and Elaine Shi, editors, *CCS ’21: 2021 ACM SIGSAC Conference on Computer and Communications Security, Virtual* *Event, Republic of Korea, November 15 - 19, 2021*, pages 1135–1150. ACM, 2021. [CZZ + 24]Yu Chen, Min Zhang, Cong Zhang, Minglang Dong, and Weiran Liu. Private set operations from multi-query reverse private membership test. In *Public-Key Cryptography-PKC 2024 - 27th* *IACR International Conference on Practice and Theory of Public-Key Cryptography,*, Lecture Notes in Computer Science, 2024. [DC17]Alex Davidson and Carlos Cid. An efficient toolkit for computing private set operations. In *ACISP 2017*, 2017. [FIPR05]Michael J. Freedman, Yuval Ishai, Benny Pinkas, and Omer Reingold. Keyword search and obliv- ious pseudorandom functions. In Joe Kilian, editor, *Theory of Cryptography, Second Theory of* *Cryptography Conference, TCC 2005, Cambridge, MA, USA, February 10-12, 2005, Proceedings*, volume 3378 of *Lecture Notes in Computer Science*, pages 303–324. Springer, 2005. [Fri07]Keith B. Frikken. Privacy-preserving set union. In *ACNS 2007*, 2007. [FV12]Junfeng Fan and Frederik Vercauteren. Somewhat practical fully homomorphic encryption. *IACR* *Cryptol. ePrint Arch.*, page 144, 2012. [Gam85]Taher El Gamal. A public key cryptosystem and a signature scheme based on discrete logarithms. *IEEE Trans. Inf. Theory*, 31(4):469–472, 1985. [GMR + 21]Gayathri Garimella, Payman Mohassel, Mike Rosulek, Saeed Sadeghian, and Jaspal Singh. Pri- vate set operations from oblivious switching. In *PKC 2021*, 2021. [Gol04]Oded Goldreich. *The Foundations of Cryptography-Volume 2: Basic Applications*. Cambridge University Press, 2004. [GPR + 21]Gayathri Garimella, Benny Pinkas, Mike Rosulek, Ni Trieu, and Avishay Yanai. Oblivious key- value stores and amplification for private set intersection. In *CRYPTO 2021*, 2021. [HLP + 24]Meng Hao, Weiran Liu, Liqiang Peng, Hongwei Li, Cong Zhang, Hanxiao Chen, and Tianwei Zhang. Unbalanced circuit-psi from oblivious key-value retrieval. In *33rd USENIX Security* *Symposium (To appear)*, 2024. [HLS + 16]Kyle Hogan, Noah Luther, Nabil Schear, Emily Shen, David Stott, Sophia Yakoubov, and Arkady Yerukhimovich. Secure multiparty computation for cooperative cyber risk assessment. In *SecDev* *2016*, 2016. [HN10]Carmit Hazay and Kobbi Nissim. Efficient set operations in the presence of malicious adversaries. In *PKC 2010*, 2010. [IKOS04]Yuval Ishai, Eyal Kushilevitz, Rafail Ostrovsky, and Amit Sahai. Batch codes and their appli- cations. In L´aszl´o Babai, editor, *Proceedings of the 36th Annual ACM Symposium on Theory of* *Computing, Chicago, IL, USA, June 13-16, 2004*, pages 262–271. ACM, 2004. [JL10]Stanislaw Jarecki and Xiaomin Liu. Fast secure computation of set intersection. In Juan A. Garay and Roberto De Prisco, editors, *Security and Cryptography for Networks, 7th International* *Conference, SCN 2010, Amalfi, Italy, September 13-15, 2010. Proceedings*, volume 6280 of *Lecture* *Notes in Computer Science*, pages 418–435. Springer, 2010. [JSZ + 22]Yanxue Jia, Shi-Feng Sun, Hong-Sheng Zhou, Jiajun Du, and Dawu Gu. Shuffle-based private set union: Faster and more secure. In *USENIX Security 22*, 2022. [KBM23]Florian Kerschbaum, Erik-Oliver Blass, and Rasoul Akhavan Mahdavi. Faster secure comparisons with offline phase for efficient private set intersection. In *30th Annual Network and Distributed* *System Security Symposium, NDSS 2023, San Diego, California, USA, February 27 - March 3,*

*2023*. The Internet Society, 2023.
[KKRT16]Vladimir Kolesnikov, Ranjit Kumaresan, Mike Rosulek, and Ni Trieu. Efficient batched oblivious PRF with applications to private set intersection. In *CCS 2016*, 2016. [KLS + 17] Agnes Kiss, Jian Liu, Thomas Schneider, N. Asokan, and Benny Pinkas. Private set intersection ´ for unequal set sizes with mobile applications. *Proc. Priv. Enhancing Technol.*, 2017(4):177–197,

2017.
[KRTW19]Vladimir Kolesnikov, Mike Rosulek, Ni Trieu, and Xiao Wang. Scalable private set union from symmetric-key techniques. In *ASIACRYPT*, 2019. [KS05]Lea Kissner and Dawn Xiaodong Song. Privacy-preserving set operations. In *CRYPTO 2005*,

2005.
[Lin17]Yehuda Lindell. How to simulate it-A tutorial on the simulation proof technique. In Yehuda Lin- dell, editor, *Tutorials on the Foundations of Cryptography*, pages 277–346. Springer International Publishing, 2017. [LLWR24]J. Liu, J. Li, D. Wu, and K. Ren. Pirana: Faster multi-query pir via constant-weight codes. In *2024 IEEE Symposium on Security and Privacy (SP)*, pages 39–39, Los Alamitos, CA, USA, may

2024. IEEE Computer Society.
[mpc] [https://github.com/alibaba-edu/mpc4j](https://github.com/alibaba-edu/mpc4j). [MR23]Muhammad Haris Mughees and Ling Ren. Vectorized batch private information retrieval. In *44th IEEE Symposium on Security and Privacy, SP 2023, San Francisco, CA, USA, May 21-25,* *2023*, pages 437–452. IEEE, 2023. [MS13]Payman Mohassel and Seyed Saeed Sadeghian. How to hide circuits in MPC an efficient frame- work for private function evaluation. In *EUROCRYPT 2013*, 2013. [NP01]Moni Naor and Benny Pinkas. Efficient oblivious transfer protocols. In *Proceedings of the Twelfth* *Annual Symposium on Discrete Algorithms*, 2001. [Ope] [https://github.com/openssl/openssl](https://github.com/openssl/openssl). [PR04]Rasmus Pagh and Flemming Friche Rodler. Cuckoo hashing. *J. Algorithms*, 51(2):122–144, 2004. [PRTY20]Benny Pinkas, Mike Rosulek, Ni Trieu, and Avishay Yanai. PSI from paxos: Fast, malicious private set intersection. In *EUROCRYPT 2020*, 2020. [PSZ18]Benny Pinkas, Thomas Schneider, and Michael Zohner. Scalable private set intersection based on OT extension. *ACM Trans. Priv. Secur.*, 21(2):7:1–7:35, 2018. [Rab05]Michael O. Rabin. How to exchange secrets with oblivious transfer. *IACR Cryptol. ePrint Arch.*, 2005:187, 2005. [RMY20]Sivaramakrishnan Ramanathan, Jelena Mirkovic, and Minlan Yu. BLAG: improving the accuracy of blacklists. In *NDSS*, 2020. [RR22]Srinivasan Raghuraman and Peter Rindal. Blazing fast PSI from improved OKVS and subfield VOLE. In Heng Yin, Angelos Stavrou, Cas Cremers, and Elaine Shi, editors, *Proceedings of* *the 2022 ACM SIGSAC Conference on Computer and Communications Security, CCS 2022, Los* *Angeles, CA, USA, November 7-11, 2022*, pages 2505–2517. ACM, 2022. [RS21]Peter Rindal and Phillipp Schoppmann. VOLE-PSI: fast OPRF and circuit-psi from vector-ole. In *EUROCRYPT 2021*, 2021. [SEA22]Microsoft SEAL (release 4.0). [https://github.com/Microsoft/SEAL](https://github.com/Microsoft/SEAL), March 2022. Microsoft Research, Redmond, WA. [Sod] [https://github.com/jedisct1/libsodium](https://github.com/jedisct1/libsodium). [TCLZ23]Binbin Tu, Yu Chen, Qi Liu, and Cong Zhang. Fast unbalanced private set union from fully ho- momorphic encryption. In Weizhi Meng, Christian Damsgaard Jensen, Cas Cremers, and Engin Kirda, editors, *Proceedings of the 2023 ACM SIGSAC Conference on Computer and Commu-* *nications Security, CCS 2023, Copenhagen, Denmark, November 26-30, 2023*, pages 2959–2973. ACM, 2023. [Vec23] [https://github.com/mhmughees/vectorized_batchpir](https://github.com/mhmughees/vectorized_batchpir), 2023. [ZCL + 23]Cong Zhang, Yu Chen, Weiran Liu, Min Zhang, and Dongdai Lin. Linear private set union from Multi-Query reverse private membership test. In *32nd USENIX Security Symposium (USENIX* *Security 23)*, pages 337–354, Anaheim, CA, August 2023. USENIX Association. [ZLDL23]Cong Zhang, Weiran Liu, Bolin Ding, and Dongdai Lin. Efficient private multiset ID protocols. In Ding Wang, Moti Yung, Zheli Liu, and Xiaofeng Chen, editors, *Information and Communications* *Security - 25th International Conference, ICICS 2023, Tianjin, China, November 18-20, 2023,* *Proceedings*, volume 14252 of *Lecture Notes in Computer Science*, pages 351–369. Springer, 2023.

## A Security Proofs of Permuted-PEQT

A.1 Proof of Theorem1 Below we give the details of the proof of Theorem1. *Proof.* We exhibit simulators Sim*S*and Sim*R*for simulating corrupt *S* and *R* respectively, and argue the indistinguishability of the produced transcript from the real execution. <u>Corrupt Sender:</u> Sim*S*(*⃗r*
*′* = (*r₁* *′* *,...,rn* *′* )*,π*) simulates the view of corrupt semi-honest sender. Note that the simulator only needs to simulate *{vi}i∈*[*n*]in step 1, it chooses random group elements *v* *i←* G*,i ∈* [*n*] to simulate the view. Now we argue that the view output by Sim*S*is computationally indistinguishable from the real one based on DDH assumption. Specifically, if there is a distinguisher *D* can distinguish the view output by Sim*S*and real view with non-negligible probability, then we can construct a PPT adversary *A* to break the DDH assumption. *A* works as follows: when *A* receives DDH challenge *g* *x* *,g* *y* *i* *,g* *z* *i*, where *x,yi←* Z*p*, *A* is asked to distinguish if *zi*= *x · yi*or random values. *A* implicitly sets *a* = *x*, and simulates the view as below. For queries *ri*, if *ri*is not a component of vector *⃗r*, it picks a random group element to assign *H*(*ri*), otherwise, it assigns *H*(*ri*) = *g* *y* *i*. Now *A* invokes *D* with input *g* *z* *i* *,i ∈* [*n*] and outputs *D*’s output. If *z* *i*= *x · yi*, *A* simulates real view, else, the view corresponds to the simulator’s outputs. Therefore, *A* can break the DDH assumption with the same advantages as *D*. <u>Corrupt Receiver:</u> Sim*R*(*⃗r* = (*r₁,...,rn*)) simulates the view of corrupt semi-honest *R*. It executes as follows:

1.In step 1, Sim*i*like an honest receiver.

|chooses a ← Z|randomly and computes v||||
|---|---|---|---|---|
|R|p||||
|R|||i′|R|
|i i|i i′a|i||i′ i i∈[n]|
|||R|||
||||R||

2.In step 2, Sim chooses random group elements *v* for *i ∈* [*n*]. Sim also chooses random group elements ¯*v* if *b* = 0 and sets ¯*v* := *v* if *b* = 1. Then, it appends the *{v, v*¯*}* to the view. Now we argue that the view output by Sim is indistinguishable from the real one. We formally prove this by a standard hybrid argument method. We define three hybrid transcripts *T₀,T₁,T₂* where *T₀* is the real view of *R*, and *T₂* is the output of Sim. – Hybrid₀. The first hybrid is the real interaction described in Figure7. Here, an honest *S* uses input *⃗r* *′* *,π*, and honestly interacts with the corrupt *R*. Let *T₀* denote the real view of *R*. – Hybrid₁. Let *T₁* be the same as *T₀*, except that for *bi*= 0, *vi′*and ¯*vi*are replaced by randomly selected group elements. We argue that the view in *T₀* and *T₁* are computationally indistinguishable based on the DDH assumption. Specifically, if there is a distinguisher *D* who can distinguish the *T₀* and *T₁* with non-negligible probability, then we can construct a PPT adversary *A* to break the
*x yi yi* *′* *z* *i zi* *′* DDH assumption. *A* works as follows: when *A* receives DDH challenge *g*, *g*, *g*, *g*, *g*, where *x*, *yi*, *yi′←* Z*p*, *A* is asked to distinguish if *zi*= *x · yi*, *zi′*= *x · yi′*or random values. *A* implicitly *a* *−*1 *y* *i* sets *b* = *x*, and simulates the view as below. For queries *ri*and *ri′*, it assigns *H*(*ri*) = *g*, *y* *i* *′* *′* *H*(*ri′*) = *g* (note that *A* is a non-uniform adversary for DDH assumption, both *⃗r* and *⃗r* could *z* *i zi* *′* be its auxiliary inputs). Now *A* invokes *D* with input *g,g,i ∈* [*n*] and outputs *D*’s output. If *z* *i*= *x · yi*, *zi′*= *x · yi′*, *A* simulates *T₀*, else, it simulates *T₁*. Therefore, *A* can break the DDH assumption with the same advantages as *D*. – Hybrid₂. Let *T₂* be the same as *T₁*, except that for *bi*= 1, *vi′*is replaced by randomly selected group elements and ¯*vi*:= *vi′a*. We argue that the view in *T₁* and *T₂* are computationally indistinguishable based on the DDH assumption. Specifically, if there is a distinguisher *D* who can distinguish the *T₁* and *T₂* with non-negligible probability, then we can construct a PPT adversary *A* to break the DDH assumption. *A* works as follows: when *A* receives DDH challenge *g* *x* *,g* *y* *i* *,g* *z* *i*where *x,y* *i←* Z*p*, *A* is asked to distinguish if *zi*= *x · yi*or random values. *A* implicitly sets *b* = *x*, and simulates the view as below. For queries *ri*= *ri′*it assigns *H*(*ri*) = *H*(*ri′*) = *g* *y* *i*. Now *A* invokes *D* with input *g* *a·zi*, *g* *z* *i* *,i ∈* [*n*] and outputs *D*’s output. If *zi*= *x · yi*, *A* simulates *T₁*, else, it simulates *T₂*. Therefore, *A* can break the DDH assumption with the same advantages as *D*. The hybrid is exactly the view output by the simulator.

A.2 Proof of Theorem2 Below we give the details of the proof of Theorem2. *Proof.*

|We exhibit simulators Sim|||and Sim|for simulating corrupt S and R respectively, and argue|
|---|---|---|---|---|
||S ′ S|′|S n ′|R i|
|||R ps||n|
||S||||
|S|||||
|oprf|||||
|||||S|
 the indistinguishability of the produced transcript from the real execution. <u>Corrupt Sender:</u> Sim (*⃗r* = (*r₁,...,r*)*,π*) simulates the view of corrupt semi-honest sender. It exe- cutes as follows:
1.In step 1, Sim selects random values *β ←{*0*,*1*}*
*l* for *i ∈* [*n*]. Then, it invokes Permute + Share receiver’s simulator Sim (*π, β⃗* = (*β₁,...,β*)) and appends the output to the view.

2.In step 2, Sim generates a random PRF key *k*. Then, it invokes OPRF sender’s simulator Sim (*k*) and appends the output to the view. Now we argue that the view output by Sim is indistinguishable from the real one. Since *S*’s view only involves underlying Permute + Share and OPRF protocols, the correctness of this simulator directly follows the security of underlying protocols.
<u>Corrupt Receiver:</u> Sim*R*(*⃗r* = (*r₁,...,rn*)*,⃗b* = (*b₁,...,bn*)) simulates the view of corrupt semi-honest
receiver. It executes as follows:

1.In step 1, Sim*R*selects random values *αi←{*0*,*1*}*
*l* *,i ∈* [*n*] and invokes Permute + Share sender’s simulator Sim *S* ps(*⃗r,⃗α* = (*α₁,...,αn*)) and appends the output to the view.

2.In step 2, Sim*R*selects random values *qi← {*0*,*1*}*
*l* *,i ∈* [*n*]. Then, the simulator Sim*R*invokes OPRF receiver’s simulator Sim *R* oprf(*{αi}i∈*[*n*]*, {qi}i∈*[*n*]) and appends the output to the view.

3.In step 3, for *i ∈* [*n*], Sim*R*picks random *fi←{*0*,*1*}*
*l* if *bi*= 0 and sets *fi*= *qi*if *bi*= 1. Then, it appends (*f₁,...,fn*) to the view.

Now we argue that the view output by Sim*R*is indistinguishable from the real one. We formally prove this by a standard hybrid argument method. We define three hybrid transcripts *T₀,T₁,T₂* where *T₀* is real view of *R*, and *T₂* is the output of Sim*R*.

– Hybrid₀. The first hybrid is the real interaction described in Figure8. Here, an honest *S* uses input *⃗r* *′* *,π*, and honestly interacts with the corrupt *R*. Let *T₀* denote the real view of *R*. – Hybrid₁. Let *T₁* be the same as *T₀*, except that all PRF values *Fk*(*·*) are replaced by randomly selected values. This hybrid is computationally indistinguishable from *T₀* by the pseudorandomness of the PRF. – Hybrid₂. Let *T₂* be the same as *T₁*, except that the Permute + Share and OPRF execution are replaced by simulator Sim *S* ps, Sim *R* oprf. The security of Permute + Share and OPRF functionality guarantee this view is indistinguishable from *T₁*. This hybrid is exactly the view output by the simulator.

## B Proofs of Theorem3

Below we give the details of the proof of Theorem3.

*Proof.* We exhibit simulators Sim*S*and Sim*R*for simulating corrupt *S* and *R* respectively, and argue the indistinguishability of the produced transcript from the real execution.

<u>Corrupt Sender:</u> Sim*S*(*X* = *{x₁,...,xm}*) simulates the view of corrupt semi-honest sender. It executes as follows:

1.In step 1, Sim*S*inserts *X* into the Cuckoo hash table *X*
*∗* like an honest sender, and learns the injective function *σ*.

2.In step 4, Sim. Then, it invokes OPRF

|selects random values q|||← F,j ∈ [m]. Let Q = {q|||}|
|---|---|---|---|---|---|---|
|S|R oprf|∗|j j∈[m]|||j j∈[m]|
|S||||s d|||
||S||||||
 receiver’s simulator Sim (*{X* [*σ*(*j*)]*},Q*) and appends the output to the view.
3.In step 5-7, Sim samples random *D₀∥D₁ ←* F *×* F and executes as an honest sender to obtain (*I,* st*,*qu). Finally, Sim computes ans := Answer(*D₀,*qu) and appends (ans*,D₁*) to the view.

|computes r||:= Decode(D₀∥D₁,X||[σ(j)]) for j ∈ [m] and picks random r||← F|
|---|---|---|---|---|---|---|
|S||j′||∗||i′|
|c|j∈[m]|′|′ m ′||||
|S|c||S p-peqt S|′|S ot ∗|S|

4.In step 8, Sim for *i ∈* [*m*] *\{σ*(*j*)*}*. Let *⃗r* = (*r₁,...,r*
*c* )

5.In step 9, Sim selects a random permutation *π* over [*mc*]. Then, the simulator Sim invokes permuted PEQT sender’s simulator Sim (*⃗r,π*) and appends the output to the view.
6.In step 10, for *i ∈* [*m*], the simulator Sim invokes OT sender’s simulator Sim (*X* [*π*(*i*)]*, ⊥*) and appends the output to the view. Now we argue that the view output by Sim*S*is indistinguishable from the real one. We formally prove this by a standard hybrid argument method. We define four hybrid transcripts *T₀,T₁,T₂,T₃* where *T₀* is real view of *S*, and *T₃* is the output of Sim*S*. – Hybrid₀. The first hybrid is the real interaction described in Figure9. Here, an honest *R* uses input *Y*, honestly interacts with the corrupt *S*. Let *T₀* denote the real view of *S*. – Hybrid₁. Let *T₁* be the same as *T₀*, except that all PRF values *Fk*(*·*) are replaced by randomly selected values. This hybrid is computationally indistinguishable from *T₀* by the pseudorandomness of the PRF. – Hybrid₂. Let *T₂* be the same as *T₁*, except that *D₀∥D₁* is sampled uniformly from F
*s* *×* F *d*. Note that in the previous hybrid, the values used to compute sparse OKVS are forms of *{ri*+

|f }|, where f|’s are truly random values. For each bin i ∈ [m||||], the sender learns||
|---|---|---|---|---|---|---|---|
|i,α i∈[m],α∈[|Y ∗|[i]|] i i,α|i,α i,α i i,t R oprf|i i,α S p-peqt|∗ ∗ i i,α i∈[m S ot|∗ ∗],α∈[|Y [i]|]|c ∗ i i|i i,α|

*i,α i∈*[*mc*]*,α∈*[*|Y∗*[*i*]*|*] *i,α c* one random value *f* from OPRF¹⁰ or selected it by itself. If *X* [*σ*(*j*)] *∈/ Y* [*j*], the values *r* + *f* are all random due to *f* ’s are random. If *X* [*σ*(*j*)] *∈ Y* [*j*], w.l.o.g, assume *f* = *fi,t*for some *t ∈* [*|Y* [*i*]*|*], the value *r* + *f* is random from the view of sender because *r* is randomly selected by the receiver, and the values *r* + *f* for *αin*[*|Y* [*i*]*|*] *\{t}* are also ramdom because of the randomness of *f*. As a result, all values *{r* + *f}c ∗* are random from the view of the sender. By the obliviousness property of OKVS, *T₁* and *T₂* are statistically indistinguishable. – Hybrid₃. Let *T₃* be the same as *T₂*, except that the OPRF, permuted PEQT and OT execution are replaced by simulator Sim*,*Sim*,*Sim. The security of OPRF, permuted PEQT and OT functionality guarantee this view is indistinguishable from *T₂*. This hybrid is exactly the view output by the simulator.

<u>Corrupt Receiver:</u> Sim*R*(*Y* = *{y₁,...,yn},X ∪ Y*) simulates the view of corrupt semi-honest receiver. It executes as follows:

1.In step 1-3, Sim*R*inserts *Y* into the simple hash table *Y*
*∗* and picks a random *ri←{*0*,*1*}* *l* for each bin *i ∈* [*mc*] like an honest receiver. Let *⃗r* := (*r₁,...,rmc*).

2.In step 4, Sim*R*generates a random PRF key *k*. Then, it invokes OPRF sender’s simulator Sim *S* oprf(*k*) and appends the output to the view.
3.In step 5, Sim*R*computes sparse OKVS *D₀||D₁* as the honest receiver.
4.In step 6, Sim*R*samples random *I* := *{i₁, ··· ,imw}←* [*s*]
*wm*. Then, Sim*R*computes (st*,*qu) *←* Query(*I*) and appends qu to the view.

5.In step 9 and 10, Sim*R*defines the set *Z* := *X∪Y \Y*, i.e. the set of elements that *X* “brings to the union”. Now, it uses *⊥* to pad *Z* to *m* elements, then it uses dummy item *d* to pad *Z* to *mc* elements and permutes these elements randomly. Let *Z* = *{z₁,...,zmc}*. Sim*R*sets *bi*= 1 if and only if *zi*=*⊥* and *bi*= 0 otherwise for *i ∈* [*mc*]. Let *⃗b* := (*b₁,...,bmc*). Then, it invokes permuted PEQT receiver’s simulator Sim
*R* p-peqt(*⃗r,⃗b*), OT receiver’s simulator Sim *R* ot(*bi,zi*) and appends these outputs to the view.

Now we argue that the view output by Sim*R*is indistinguishable from the real one. We formally prove this by a standard hybrid argument method. We define four hybrid transcripts *T₀,T₁,T₂* where *T₀* is real view of *R*, and *T₂* is the output of Sim*R*.

– Hybrid₀. The first hybrid is the real interaction described in Figure9. Here, an honest *S* uses input *X*, honestly interacts with the corrupt *R*. Let *T₀* denote the real view of *R*. – Hybrid₁. Let *T₁* be the same as *T₀*, except that the query index set *I* is replaced by uniformly random *i₁, ··· ,iwm∈* [*s*] *wm*. This hybrid is computationally indistinguishable from *T₀* by the query privacy of the BatchPIR scheme.

Note that here the outputs of OPRF have been replaced with truly random values.

– Hybrid₂. Let *T₂* be the same as *T₁*, except that the OPRF, permuted PEQT and OT execution are replaced by simulator Sim *S* oprf*,*Sim *R* p-peqt*,*Sim *R* ot. The security of OPRF, permuted PEQT and OT functionality guarantee this view is indistinguishable from *T₁*. This hybrid is exactly the view output by the simulator.

## C Proofs of Theorem4

Below we give the details of the proof of Theorem4.

*Proof.* We exhibit simulators Sim*S*and Sim*R*for simulating corrupt *S* and *R* respectively, and argue the indistinguishability of the produced transcript from the real execution.

<u>Corrupt Sender:</u> Sim*S*(*X* = *{x₁,...,xm}*) simulates the view of corrupt semi-honest sender. It executes as follows:

1.In step 1-4, Sim*S*generates key pairs *pp ←* Setup(1
*κ* ), (*pk,sk*) *←* KeyGen(*pp*) and samples random *D₀∥D₁ ←* F *s* *×* F *d*. Then, it executes as an honest sender to obtain (*I,* st*,*qu). Finally, Sim*S* computes ans := Answer(*D₀,*qu), and appends (ans*,pk,D₁*) to the view.

2.In step 9, Sim*S*invokes OT sender’s simulator Sim
*S* ot(*xj, ⊥*) for *j ∈* [*m*] and appends the output to the view.

Now we argue that the view output by Sim*S*is indistinguishable from the real one. We formally prove this by a standard hybrid argument method. We define four hybrid transcripts *T₀,T₁,T₂,T₃* where *T₀* is real view of *S*, and *T₃* is the output of Sim*S*.

– Hybrid₀. The first hybrid is the real interaction described in Figure9. Here, an honest *R* uses input *Y*, and honestly interacts with the corrupt *S*. Let *T₀* denote the real view of *S*. – Hybrid₁. Let *T₁* be the same as *T₀*, except that the ciphertexts *{si}i∈*[*n*]are replaced by randomly sampled ciphertexts in the ciphertext space. This hybrid is computationally indistinguishable from *T₀* by the single-message multi-ciphertext pseudorandomness of the ReRand-PKE scheme. – Hybrid₂. Let *T₂* be the same as *T₁*, except that *D₀∥D₁* is sampled uniformly from F *s* *×* F *d*. Since the ciphertexts have been replaced with the random ones, the obliviousness property of OKVS guarantees *T₁* and *T₂* are statistically indistinguishable. – Hybrid₃. Let *T₃* be the same as *T₂*, except that the OT execution is replaced by simulator Sim *S* ot. The security of OT functionality guarantees this view is indistinguishable from *T₂*. This hybrid is exactly the view output by the simulator.

<u>Corrupt Receiver:</u> Sim*R*(*Y* = *{y₁,...,yn},X ∪ Y*) simulates the view of corrupt semi-honest receiver. It executes as follows:

1.In step 1-2, Sim

|generates (pk,sk) and computes {s|||}, D₀||D₁ as the honest receiver.|||
|---|---|---|---|---|---|
|R|||i i∈[n]|||
|R R||mw|wm|R||
|m|j|R|j||j|
|j||j||j j∈[m]||
||R|||R ot|j j|

2.In step 3, Sim samples random *I* := *{i₁, ··· ,i}←* [*s*]. Then, Sim computes (st*,*qu) *←* Query(*I*) and appends qu to the view.
3.In step 5-8, Sim define the set *Z* := *X∪Y \Y*, i.e. the set of elements that *X* “brings to the union”. Next, it uses *⊥* to pads *Z* to *m* elements and permutes these elements randomly. Let *Z* = *{z₁,...,z}*. For *j ∈* [*m*], if *z* =*⊥*, Sim sets *b* = 1 and *s*¯*j*:= Enc(*pk,*0), if *z ̸*=*⊥*, Sim*R* sets *bj*= 0 and *s*¯ := Enc(*pk,* Decode(*D₀||D₁,z*)). Then, it appends *{s*¯*}* to the view.
4.In step 9 and 10, for *j ∈* [*m*], Sim invokes OT receiver’s simulator Sim (*b,z*) and appends these outputs to the view. Now we argue that the view output by Sim*R*is indistinguishable from the real one. We formally prove this by a standard hybrid argument method. We define four hybrid transcripts *T₀,T₁,T₂,T₃* where *T₀* is real view of *R*, and *T₃* is the output of Sim*R*. – Hybrid₀. The first hybrid is the real interaction described in Figure10. Here, an honest *S* uses input *X*, and honestly interacts with the corrupt *R*. Let *T₀* denote the real view of *R*. – Hybrid₁. Let *T₁* be the same as *T₀*, except that the query index set *I* is replaced by uniformly random *i₁, ··· ,iwm∈* [*s*]
*wm*. This hybrid is computationally indistinguishable from *T₀* by the query privacy of the BatchPIR scheme.

– Hybrid₂. Let *T₂* be the same as *T₁*, except that ciphertexts *{s*¯*j}* are computed as the simulator instead of the real protocol. This hybrid is identical to *T₁* by the indistinguishability of the ReRand- PKE scheme. – Hybrid₃. Let *T₃* be the same as *T₂*, except that the OT execution is replaced by simulator Sim *R* ot. The security of OT functionality guarantees this view is indistinguishable from *T₂*. This hybrid is exactly the view output by the simulator.

## D Formal Proof of “Pull-down-then-lift” Encoding

As we mentioned in Section1.2, we use the “pull-down-then-lift” encoding technique in our ReRand- PKE based PSU construction to optimize encoding efficiency. We note that this optimization is deeply bound to the ElGamal encryption scheme. In this section, we formally prove that the OKVS generated in this way still satisfies (a tweaked definition of) obliviousness. Let (Encode*,*Decode) be a standard OKVS scheme, where the value space is Z*p*. We describe our new encoding and decoding algorithms (Encode *ptl* *,*Decode *ptl* ) as follows.

– Encode *ptl* (*{xi}i∈*[*n*]*,* (*pk,sk*)):

1.For *i ∈* [*n*], pick random *ri←* Z*p*.

|2.Compute d¹ = (d¹||,...,d¹ ) := Encode({(x||,r )}|) and d² = (d²|) := Encode({(x|,sk·|
|---|---|---|---|---|---|---|---|
|i i∈[n] ptl||1 N d¹ d² row(x)|d¹ d² d =1 row(x)|i i d =1|i∈[n]|N|i|
|||ptl||||||
||||||||i|
||||ptl|||||

1 *N i i i∈*[*n*] 1*,...,d²N i*

*r*)*}*), where the random tapes used in two encoding algorithms are the same.
1 1 *N N*

3.Output *D* = ((*g,g*)*,...,*(*g,g*))
– Decode (*D,x*): Q 1 Q 2 Output *c* = (*c₁,c₂*) := ( *j* *gj,* *j* *gj*)

Note that our new Encode algorithm takes (*pk,sk*) instead of group elements as inputs be- cause it requires to know the algebraic structure of group elements, i.e., the discrete logarithm *r* for *g* *r* *i*. Therefore, we prove our new Encode algorithm satisfying the following tweaked obliviousness property.

Theorem 5. *Assume the DDH assumption hold in group* G*, where order of* G *is p and g is a genera-*
*tor. For all distinct {x⁰*1*,...,x⁰n} and all distinct {x¹*1*,...,x¹n}, if the* Encode *algorithm does not output*
*⊥ for {x⁰*1*,...,x⁰n} or {x¹*1*,...,x¹n}, for any ElGamal key pair* (*pk,sk*)*, then the following distributions*
*are computationally indistinguishable:*

*{D|D ←* Encode *ptl* (*{x⁰i}i∈*[*n*]*,* (*pk,sk*))*}* *{D|D ←* Encode *ptl* (*{x¹i}i∈*[*n*]*,* (*pk,sk*))*}*

*Proof.* For any distinct *{x₁,...,xn}*, consider the computation process of Encode *ptl* (*{xi}i∈*[*n*]*,* (*pk,sk*))*}*: Firstly, it picks random *ri←* Z*p,i ∈* [*n*]. Then, it computes the OKVS *d¹* = (*d¹*1*,...,d¹N*) := Encode(*{*(*xi,ri*)*}i∈*[*n*]) and *d²* = (*d²*1*,...,d²N*) := Encode(*{*(*xi,sk · ri*)*}i∈*[*n*]). Since the random tapes used in two encoding algorithms are the same, we have *d²j*= *sk · d¹j*for *j ∈* [*N*]. Furthermore, since *ri*’s are randomly selected, the obliviousness of underlining OKVS (Encode*,*Decode) guarantees 1 *N d¹*1*d²*1*d¹Nd²N* *d* is indistinguishable to the uniform distribution over Z*p*. Let *D* = ((*g,g*)*,...,*(*g,g*)) = *ptl* 0 *d¹jd²jd¹jsk·d¹jd¹jd¹j* Encode (*{xi}i∈*[*n*]*,* (*pk,sk*))*}*. For *j ∈* [*N*], we have (*g,g*)=(*g,g*)=(*g,pk*), which exactly corresponds to a fresh ElGamal ciphertext of 1. Therefore, the distribution of *D* can also be written as: Dis(*{xi}i∈*[*n*]*,* (*pk,sk*)):

1.For *j ∈* [*N*], computes *Dj←* Enc(*pk,*1), where Enc is the encryption algorithm of the ElGamal encryption scheme.
2.Output *D* = (*D₁,...,DN*) By the single-message multi-ciphertext pseudorandomness of ElGamal encryption scheme, we have the above distribution is indistinguishable to the uniform distribution over ciphertext space, i.e., G². Note that the above new description of *D* is independent from *{xi}i∈*[*n*]. As a result, two distributions are computationally indistinguishable.
