# TinyLabels: How to Compress Garbled Circuit Input Labels, Efficiently

Marian Dietz¹, Hanjun Li², and Huijia Lin²

1 ETH Zürich, Switzerland marian.dietz@inf.ethz.ch 2 University of Washington, Seattle, WA, USA {hanjul,rachel}@cs.washington.edu

Abstract. Garbled circuits are a foundational primitive in both theory and practice of cryptog- raphy. Given (*C,*b K[x]), where *C*b is the garbling of a circuit *C* and K[x] = *{*K[*i,xi*]*}i∈*[*|*x*|*]are the input labels for an input x, anyone can recover *C*(x), but nothing else about input x. Most research efforts focus on minimizing the size of the garbled circuit *C*b. In contrast, the work by Applebaum, Ishai, Kushilevitz, and Waters (CRYPTO ’13) initiated the study of minimizing the cost for transferring the input labels K[x]. Later improved in a follow-up by Applebaum et al. (STOC ’23), the state-of-the-art techniques allow compressing the input labels to the optimal rate of 1 + *o*(1). That is, each input label can be transferred by essentially sending 1 bit. However, existing solutions are computationally expensive, requiring large numbers of public-key operations (such as RSA exponentiation). In this work, we present an *efficient* input label compression technique based on Ring-LWE. We achieve the same optimal rate of 1 + *o*(1), by making use of additional communication in an offline stage (before the input x becomes known), a paradigm that has already been explored in prior works. A novel feature of the offline communication in our scheme is that the information sent is either *reusable* or *compressible* using a random oracle, leading to small amortized offline cost *o*(*|*x*|*). We further demonstrate concrete efficiency through an implementation whose online latency out- performs the naive baseline (which sends all of K[x] in the online phase) in a realistic network with a bandwidth of up to 45Mbps. This break-even point could be pushed even further by leveraging the large potential for parallelization of computation. Finally, we apply our techniques to construct maliciously-secure two-party computation protocols with *succinct online communication*: The online phase starts once the circuit *C* becomes known, and requires exchanging only poly(*λ*) bits (independent of *|C|*). After inputs x*A,* x*B* arrive, an additional *|*x*A|* + *|*x*B |* + poly(*λ*) bits need to be sent.

# Table of Contents

1 Introduction................................................................ .3 2 Technical Overview.......................................................... .9

2.1 Instantiating Batch-Select................................................ .10
2.2 Making batch-select practical............................................. .12
2.3 Application: Preprocessing Garbling....................................... .13
2.4 Adaptive Security....................................................... .14
3 Preliminaries............................................................... .14

3.1 Ring-LWE............................................................. .14
4 Our Main Tool: Batch-Select.................................................. .19

4.1 First building block: LEnc................................................ .20
4.2 Second building block: LHE for Rings...................................... .23
4.3 Instantiating Batch-Select from LEnc and LHE.............................. .25
4.4 Sending encryptions of random strings with a random oracle.................. .27
5 Application: Preprocessing Garbling........................................... .29

5.1 Computational Model................................................... .30
5.2 Definition.............................................................. .30
5.3 Ingredients............................................................. .31
5.4 Construction........................................................... .32
6 Evaluation................................................................. .34 A Related Works on Sublinear 2PC Protocols and Succinct Garbling................. .40 B Details on LEnc............................................................. .42

B.1 Construction of Weak Linear Laconic Encryption............................ .45
B.2 LEnc Parameter Setting................................................. .49
C Details on LHE.............................................................. .50

C.1 LHE Parameter Setting.................................................. .53
D Details on Sel............................................................... .53

D.1 *Random* Batch-Select.................................................... .55
D.2 Batch-Select Parameter Settings.......................................... .57
E Details on Preprocessing Garbling............................................. .58 F Adaptive Security and Malicious 2PC.......................................... .60

F.1 Adaptive Security of LEnc............................................... .60
F.2 Adaptive Security of LHE................................................ .62
F.3 Adaptive Security of Batch-Select......................................... .66
F.4 Adaptive Security of Preprocessing Garbling................................ .69
F.5 Preprocessing *T*-Session Malicious 2PC.................................... .71

## 1 Introduction

Introduced by Yao in the 1980s [Yao82,BHR12], a garbling scheme allows efficiently transforming a Boolean circuit *C* : *{*0*,*1*}* *n* *→{*0*,*1*}* *m* into a *garbled circuit C*b and a pair of short, *λ*-bit, keys (K[*i,*0]*,*K[*i,*1]) for every input bit *i*, where *λ* is the security parameter. This transformation ensures that *C*b, along with the input labels K[x] = (K[1*,x₁*]*, ··· ,* K[*n,xn*]), reveals only the output y = *C*(x) and no other information about the input x. Over the years, Garbled circuits have found a diverse set of applications, in particular for building efficient constant-round multi- party computation protocols [Yao86,BMR90]. Although originally viewed as impractical, tremendous efficiency improvements in the past two decades has brought it to the forefront of practical and deployable cryptography. Much of this research focused on reducing the size of garbled circuits, and hence the communication costs of transferring them, providing a deep understanding on both the theoretical and practical limits [BMR90,NPS99,KS08,PSSW09,KMR14,GLNP15,ZRE15,RR21,GKP + 13,HLL23, AJS17,KLW15,BCG + 18,JLL23]. However, efficiency related to the other “half” of garbled circuits, namely the input labels, has been relatively neglected so far, and is the focus of this work. Consider the following simple use case: Many research institutes each want to perform differ- ent analyses, described by circuits *Ci*, over a common sensitive database x, e.g. patient records. Due to the sensitive nature of the data, only the results *Ci*(x) of approved analysis may be revealed. Garbled circuits offer a non-interactive solution: The data provider can first provide different garbled circuits *C*b*i*to the research institutes according to their proposed analysis, and later broadcast a single set of input labels K[x], e.g. through a blockchain. Since the dataset x may be very large, it’s desirable to minimize the size of labels K[x], which, naively, would require *λ ·|*x*|* bits. Applebaum, Ishai, Kushilevitz, and Waters [AIKW13] (AIKW) were the first to ask the following natural question: Is rate-*λ*, i.e., sending *λ* bits per input bit, optimal?

Optimal Rate 1+*o*(1). It turns out that rate-*λ* is far from optimal. AIKW achieves compression of input labels in an *online-offline setting* based on a variety of public key cryptography assump- tions including RSA, LWE, or DDH. They showed that after collecting the data x, i.e., in the *online phase*, it suffices to send just *|*x*|*+poly(*λ*) bits. This requires publishing a potentially large amount of information before seeing x, i.e., in the *offline phase*. Subsequent works [GS18,GOS18] show how to achieve this under weaker assumptions (Factoring or CDH), which however results in expensive non-black-box use of cryptographic tools. While all of these results achieve an *optimal* online rate of 1 + *o*(1), their techniques come at the cost of an offline communication *Ω*(*|*x*|· λ*). Therefore, a question left open by AIKW and [GS18,GOS18] is whether the *overall* rate (combining offline and online) can actually be reduced to less than *λ*. At first sight, it may seem impossible to communicate the labels K[x] (which have size *|*x*|· λ*) using less than *|*x*|· λ* bits overall. This intuition is however incorrect, because the 2*|*x*|* input keys might be generated in a pseudorandom way that is still sufficient for garbled circuits security. The above intuition can indeed be realized using a tool called *projective PRG* (pPRG) pro- posed recently by Applebaum et al. (ABI+) [ABI + 23]. A pPRG with public parameter pp is a pseudorandom generator with the new power that the seed sd can be “projected” to a subset *T* of all output bits, such that the projected seed sd*T*expands to these output bits indexed by *T*, while keeping the remaining output bits pseudorandom. pPRG with both succinct, i.e., poly(*λ*)-size, public parameters and projected seeds promises to eliminate the offline phase alto- gether, and simultaneously maintaining 1 +*o*(1) online rate. Built upon the techniques in AIKW,

communication computation

Naive *|*x*|· λ* 0 *|*x*|* + *|*x*|/λ* DDH ([AIKW13]) (*|*x*|· λ ·* log*p*) Mult*G* + offline: *|*x*|· λ ·* log*p* *|*x*|* + *|*x*|/λ* LWE ([AIKW13]) (*|*x*|· λ · n ·* log*q*) Add*q* + offline: *|*x*|·* poly(*λ,n,* log*q*) (*|*x*|· λ ·* log*p*) Mult

|+||⋆||G||
|---|---|---|---|---|---|
|+||||||
|||⋆||x| log |x| n|R|N|

bilinear DDH ([ABI 23]) *|*x*|* + *|*x*|/λ* + *|*x*|* Bilinear ops iO+SSBH ([ABI 23]) *|*x*|* + poly(log*|*x*|,λ*) (*|*x*|·* poly(*λ*)) iO-evals

RSA ([ABI + 23]) *|*x*|* + poly(*λ*) (*|*x*|·* log*|*x*|·* log*N*) Mult

Ring-LWE (this work) *|*x*|* + poly(*λ*) () Mult*q*

Table 1: Comparison between techniques for input label compression, in terms of *online com-*

*munication* and *online computation time*. Constant factors are omitted. *|*x*|* denotes the input length, *p* is the DDH group order, *N* is the RSA modulus, *n* is the Ring-LWE degree / LWE dimension and *q* is the (Ring-)LWE modulus (which is exponentially large, i.e., *q* = 2 *Θ*(*λ*) ). For computation time, we write Mult to denote the cost of a single multiplication within the ring or modulus indicated in the subscript. When indicated, the scheme requires an additional *offline* step which can be performed without knowing x. We use ⋆ to denote schemes that require an offline step that only needs to be executed *once*, whose communication therefore vanishes after a sufficiently large number of instances. We further remark that the costs of the (bilinear) DDH and LWE schemes shown here applies an optimization that splits the input into smaller blocks. See [AIKW13] for details.

ABI+ [ABI + 23] constructed pPRGs with different levels of succinctness based on several public key assumptions.

Summarizing [AIKW13,ABI + 23], we now have compression techniques with two levels of communication efficiency. *1)* Optimal overall-rate 1 + *o*(1) is achieved, based either on RSA, or on indistinguishability obfuscation (iO) combined with somewhere statistically binding hash functions (SSBH). This means each label can be transferred by sending essentially a single bit!

*2)* Optimal online rate 1 + *o*(1) is attained, albeit with sub-optimal *Ω*(*|*x*|· λ*) offline cost, based on LWE and DDH. The DDH-based technique can be further improved using bilinear groups, enabling *reusing* the large offline communication, achieving amortized overall-rate 1 + *o*(1) over multiple instances of garbled circuits. See Table1for detailed comparison. Theory vs Practice. Given the importance of practically efficient garbled circuits, it is exciting to try to apply these compression techniques in the wild. Unfortunately, the computational costs of current techniques are extremely high, establishing only feasibility, but not practicality. Specifically, the methods described in [AIKW13,ABI
+ 23] require performing a large number of expensive public key operations, namely group exponentiations (in either RSA or DDH groups), inner products of long vectors over Z*p*(LWE), or pairing operations (bilinear DDH), while the methods in [GS18,GOS18] are prohibitively expensive due to non-black-box cryptography. To underline these issues, take the RSA-based scheme as an example, which is one of the currently

most efficient methods. It requires the receiver to run *O*(*|*x*|·*log*|*x*|*) RSA-exponentiations³ (with large exponents) in order to recover the input labels. However, the concrete cost of this is very high: Suppose the input has 100*K* bits i.e., *|*x*|≥* 10 5, and one RSA-exponentiation consumes 1*ms*. Then the receiver can only process 60 input labels per second, and this rate decreases even further for larger inputs. While the DDH-based scheme could have similar performance (assuming

0*.*1*ms* per scalar multiplication on elliptic curves [BCLN16]), it does come with significant offline communication. All other schemes have even more computational overhead. Motivated by the state-of-affairs, the overarching goal of this work is: *Can we transfer input labels in online- or overall-rate less than λ,* efficiently*?* We remark that the state-of-affairs is reminiscent to the current landscape of research on the minimal size of garbled circuits. In theory, optimal poly(*λ,n,m*)-size garbled circuits is feasible (with *n,m* the input/output length), based on LWE or indistinguishability obfuscation and puncturable PRF [GKP
+ 13,HLL23,AJS17,KLW15,BCG + 18,JLL23]. However, these schemes are computationally prohibitive. In practice, optimized versions of Yao’s garbled circuits are far more efficient, despite their large communication costs. Similarly, current theoretically optimal input-label compression techniques have not yet brought benefits to practical efficiency. Narrowing the gap is the aim of this work.

Our Results in a Nutshell. We make progress towards the above overarching goal by presenting a new efficient compression technique with optimal overall-rate, 1 + *o*(1), based on Ring-LWE (depending on the choice of ring parameters), in the Random Oracle Model (ROM).

– <u>Lightweight communication:</u> The optimal overall-rate 1 + *o*(1) is achieved. While, unlike pPRG-based solutions, our scheme does make use of offline communication, it has the novel feature that information sent in the offline phase is either reusable or lightweight, with amor- tized offline-rate *o*(1). – <u>Concretely Efficient:</u> By leveraging Ring-LWE packing, our online computation is dominated <u>log|x|·λ</u> by *O*( *n*log*q* ) ring operations per input bit (where *n* is the Ring-LWE degree), a potentially *fractional* number. Indeed, in concrete settings an average of 0.14 ring operations is performed per input bit in our implementation. – <u>Implementation:</u> Our implementation demonstrates the practical efficiency of our method. For transferring the labels of 700*K* input bits, it takes about 0*.*90*µs* per bit for the garbler to compress and 1*.*77*µs* per bit for the evaluator to reconstruct, on a single-core PC.

As a further application, we construct *preprocessing garbled circuits*: relying on an offline phase with *O*˜(*λ|C|*) communication, the online phase (that starts once the plaintext circuit *C* becomes known to both parties) has a reduced communication cost of only poly(*λ*) bits, independent of the circuit size. These ideas naturally yield maliciously secure two-party computation protocols in the preprocessing model, with optimally *succinct online communication*. Namely, only poly(*λ*) bits are exchanged after the circuit *C* becomes available, and *|*x*A|* + *|*x*B|*+ poly(*λ*) bits are exchanged after the two parties receive their respective inputs x*A*and x*B*. While previous techniques for sublinear-communication 2PC did not rely on preprocessing, all of them require computationally expensive tools, such as, FHE, iO, HSS. Our protocols are much more concretely efficient.

On the Importance of Compressing Input Labels. Before moving on to describing our results in more detail, we want to call for further study on the efficiency of transferring input

This assumes some algorithmic optimization not described in [AIKW13,ABI + 23].

labels. This topic has so far had a limited history of study, perhaps due to the school of thought that the cost of transferring the input labels is dominated by that of transferring the garbled circuit. However, there are several strong reasons motivating its study. First, performance opti- mization entails saving costs in every possible avenue in practice. In big data applications the input might even be almost as large as the circuit. Second, in applications that allow preprocess- ing, the real-time performance becomes mostly dominated by the time required for transferring input labels. Third, the lack of theoretical understanding of this basic and natural question about garbled circuits is unsatisfactory; any progress here may lead to other applications. Finally, we are optimistic that in the future, practical garbled circuits with less than *λ* bit per gate, or even fixed polynomial size, might become possible. Then, the costs for transferring input labels may even outweigh that of the garbled circuit.

Our Results in More Detail. The key tool in this work, following AIKW techniques, are what we call *Batch-Select* schemes⁴. It enables the sender, Alice, to encode the keys K in the offline stage:

Sel*.*Enc₁(*{*K[*i,*1] *−* K[*i,*0]*}*) *→* (ct₁*,*st₁)*,* Sel*.*Enc₂(*{*K[*i,*0]*}*) *→* (ct₂*,*st₂)*.*

(Note that the 0-keys K[*i,*0] and the key offsets K[*i,*1]*−*K[*i,*0] are encrypted separately, which will be convenient later.) Alice publishes the ciphertext ct = (ct₁*,*ct₂) and keeps the secret state st = (st₁*,*st₂). After x arrives, Alice generates a very succinct key Sel*.*KeyGen(st*,*x) *→* skxof just poly(*λ*) size. The pair (skx*,*x) enables (partial) decryption of ct, revealing exactly the input labels Sel*.*Dec(ct*,*skx*,*x) *→* K[x] = *{*(K[*i,*1] *−* K[*i,*0]) *· xi*+ K[*i,*0]*}*, and nothing else. Security is formalized via simulation of ciphertext ct and secret key skx, given only the revealed labels K[x]. Batch-Select enables achieving optimal online rate when transferring input labels, because online Alice just sends x and skxof length *|*x*|* + *|*skx*|* = *|*x*|*+ poly(*λ*) 5. In this work, we present a concretely efficient Batch-Select scheme with the novel features that part of the offline commu- nication ct₁ can be *reused*, and the rest ct₂ can be *compressed* using the random oracle, leading to small offline-rate *o*(1). More precisely:

Theorem 1(Informal, New Batch-Select Scheme). *Let λ be the security parameter. As-* *suming* 2 *λ* *-secure Ring-LWE with dimension n, modulus* log*q* = *O*(*λ*)*, there exists a* 2 *λ* *-secure* *Batch-Select scheme. The scheme has the following asymptotic efficiency when the input length* *satisfies |*x*|* = *Ω*(*n*)*:* *√* – *|*ct₁*|* = *O*(*|*x*|*log*|*x*|· λ*)*. Ciphertext* ct₁ *can be reused for T* = *q times.* (If the modulus *q* is super-polynomial, this lets us reuse ct₁ for any polynomial number of times.) – *|*ct₂*|* = *O*(*|*x*|· λ*) *in the plain model. When* ct₂ *is used to encrypt* random *keys* K[*i,*0]*, its size*

|λ||1|
|---|---|---|
|q ·log q|2(1+ϵ)λ|2 ′|

*can be reduced to O*(1*/*2*−ϵ·|*x*|*) *bits in the ROM for any constant ϵ ∈* (0*,*)*. In particular:*

- *For sufficiently large polynomial modulus q* = poly(*n,λ*)*, the rate is o*(1)*.*
*′*

- *For exponentially large modulus q >* 2
*for any positive constant ϵ >* 0*,* ct₂ *can be* *transferred for free (with no communication).* – *|*skx*|* = *n*log*q* = poly(*λ*)*, i.e., the secret key consists of a single ring element.* 4 In [AIKW13], this gadget is “special randomized encoding for the *selection function*” and has a slightly different syntax. Nevertheless, it can be used in an analogous way to compress input labels. In order to achieve input hiding, Alice can apply a one-time pad r to the input. She would send x = x *′* +r, where x *′* is the *actual* input. The one time pad can be removed by modifying the computation to *C*r *′*

(x) = *C*(x *−* r).

– *The computational efficiency of all algorithms is* quasilinear *in the input length.*

Note that 2 *λ* -security is only assumed for the sake of fair comparison to the naive garbled circuit approach, and can be replaced by any super-polynomial value.

|Lightweight Offline Communication. Their absolute sizes are large, O (| crucially rely on the reusability of ct₁ is o (1) or below. While ct₂ and compressed size of ct₂|x | log | x (1) or below. Below we give more details on these two optimizations, and summarize the in Table2.|The offline communication of our scheme transfers |λ) and O (| x |λ), exceeding to establish that the amortized communication rate for is not reusable, it can be compressed in the ROM to|
|---|---|---|
|amortized | ct₁ | amortization modulus q||size | ct₂ | modulus q K[0]|
|O (λ) λ ·| x | log | x | T = 1 2 √ o (1) ·| x | T = q poly(λ) √ ω (1) negl(λ) T = q λ||O (λ) λ ·| x | 2 any o (1) ·| x | poly(λ) random ′ 2(1+ ϵ) λ 0 2 random|

## ct₁ and ct₂ λ-rate. We

transferring ct₁ rate *o* amortized size of ct₁

(a) Size of ct₁ (b) Size of ct₂
Table 2: The amount of offline communication (split into *|*ct₁*|* and *|*ct₂*|*) required by our batch-select scheme

in several different settings, omitting constant factors. On the left-hand side, we show the size of *|*ct₁*|* amortized across *T* instances (with the same offset K[1]*−*K[0]), assuming that *q* fulfills the stated constraint. On the right- hand side, we show the size of *|*ct₂*|* assuming that *q* fulfills the stated constraint. In the bottom two rows, the encrypted keys K[0] cannot be chosen arbitrarily but are generated as random within our batch-select scheme (this requires the ROM). Everywhere we assume the Ring-LWE dimension satisifies *n > λ* and *|*x*|* = *Ω*(*n*).

First, *T*-time reusability of ct₁ immediately reduces the per-instance cost of sending ct₁ by a factor of *T*, assuming Alice sends *T* garbled circuits and corresponding input labels. This amortization only works whenever ct₁ is encrypting the same values across all instances, but this is not an issue when using batch-select as a way to transfer input labels. The reason is that garbled circuits stay secure even when the key offset K[*i,*1] *−* K[*i,*0] is repeated for multiple indices *i*; or even when it is repeated across several garbled circuits. This assumes correlation-robust hash functions [CKKZ12], as in typical garbling with Free-XOR labels [KS08]. Alternatively (when it is not desired to garble several circuits), we can still amortize within the same instance, by treating the input x as *k ≤ T* shorter inputs x₁*, ···*x*k*of length *|*x*|/k*. Then, the size of ct₁ becomes *O*(*|*x*|*log*|*x*|· λ/k*). Using an optimized Batch-Select construction (which only yields benefits if not amortization across several instances; and it needs to assume identical secret offsets *∆* = K[*i,*1]*−*K[*i,*0] for all *i*) we can furthermore avoid the log*|*x*|*-factor. Thus, by choosing *k* = *ω*(*λ*), the size of ct₁ has rate *o*(1), even for just a single garbling instance. While Alice now needs to send *k* secret keys skx*j*in the online phase (for a total size of *k ·n·*log*q*), this cost is still bounded by poly(*λ*). A second optimization applies (in the ROM) whenever the keys *{*K[*i,*0]*}* that are encrypted by ct₂ are *uniformly random* (which is the case for most constructions of garbled circuits). This allows compressing ct₂ by a factor of *O*˜(*q¹* */ −ϵ* ) for any constant *ϵ ∈* (0*,*). Hence, even with sufficiently large *polynomial* Ring-LWE modulus *q*, we reduce the size of *|*ct₂*|* to e.g. *|*x*|/λ*, which

2(1+*ϵ′*)*λ* implies an *o*(1)-rate. Furthermore, when the modulus is exponentially large *q* = 2 for some constant *ϵ* *′* *>* 0, we can “transfer” ct₂ entirely for free, with no communication. Putting both reusability and ct₂ compression together, the batch-select offline rate approaches 0, while the online rate remains at 1 + *o*(1).

<u>Concretely Efficient Computation</u> The online computation cost of our scheme is domi- <u>log|x|·λ</u> nated by *O*( *n*log*q* ) ring operations per input bit. This fractional number is achieved by packing multiple input keys into a single RLWE element. We demonstrate concrete efficiency based on our batch-select implementation. To prioritize computational cost and simplicity of implementation, we choose a 109-bit modulus, and imple- ment a simplified version of our scheme that requires 6*|*x*|* bits of offline communication (and poly(*λ*) bits of online communication). Clearly, this is not the theoretically optimal overall *o*(1)- rate (see Table2), but nevertheless a large improvement over the baseline. Concretely, our implementation has an online computation time of 3*µs* per input bit, which we estimate to be 10 4 times faster than the AIKW RSA-based scheme (assuming that each RSA exponentiation takes 1*ms*). To demonstrate the practicality of our method, we show (in Table3) that the computation time (using a single CPU thread with 2.10GHz) from compressing and reconstructing input labels roughly equals the latency of naively transmitting un-compressed input labels over a network that has bandwidth 50 Mbps. But even when the network is faster than this, our method is still valuable e.g. when the input labels need to be broadcast to multiple evaluators, or when size plays more crucial role such as in blockchain-settings. Details on our evaluation can be found in Section6.

||#NTT|#Mult|Time (µs)|
|---|---|---|---|
|garbler (ours)|0.02|0.01|0.90|
|evaluator (ours)|0.02|0.12|1.77|
|Yao-style GC (1 Mbps)|sending 16 bytes||128.0|
|Yao-style GC (10 Mbps)|sending 16 bytes||12.8|
|Yao-style GC (50 Mbps)|sending 16 bytes||2.56|

Table 3: Concrete online costs (per input bit) of our implementation for input length *|*x*|≈* 700K. The compu-

tational costs are dominated by the number of NTT and component-wise vector multiplications (both in a ring of dimension 4096 and *<* 60-bit modulus). We compare these numbers with the amount of time that would be required for sending *uncompressed* input labels K[x] in standard Yao-style garbled circuits.

Application to Two Party Computation (2PC). In the literature there is a wealth of constructions of 2PC protocols. They can be roughly categorized into *i)* ones that are con- cretely efficient but have large communication linear in the complexity of the computation (e.g., [DPSZ12,LP11,WRK17,DILO22]), *ii)* ones with laconic communication depending only on the input/output lengths, but rely on computationally expensive tools like FHE (e.g., [Gen09, BV11,BGV12,GSW13]), or iO (e.g., [HW15]), etc, and *iii)* ones that enjoy both concrete effi- ciency and laconic communication, but are restricted to low depth computation like NC₁, using homomorphic secret sharing (e.g., [BGI16]). The latter protocols can be extended to evaluat- ing circuits, but only achieving mildly sublinear communication proportional to *|C|/* log *|C|* or *|C|/* log log *|C|*. Another drawback of protocols in ii) and iii) is that they rely on expensive generic

techniques, such as, succinct communication ZK to achieve malicious security. See AppendixA for a more detailed survey of prior sublinear communication 2PC. Using our compression technique, we explore building concretely efficient malicious 2PC with laconic *online* communication. We start with considering a new notion called preprocessing gar- bled circuits: By sending information of length proportional to the circuit size *O*˜(*λ|C|*) in an *instance-independent stage* that can be run before knowing *C* (depending only on certain meta- information such as circuit size), in the online stage after knowing *C*, the garbled circuit can be compressed to poly(*λ*) bits. This is achieved by simply sending a garbled universal circuit *U*b in the instance-independent offline stage, and using our compression technique to transfer input labels for *U*b that allow evaluating the circuit *C*. Since *C* is not hidden, the online stage only sends sk*C*of poly(*λ*) bits. By combining preprocessing garbled circuits and authenticated garbled circuits [WRK17, DILO22], we obtain maliciously secure 2PC with succinct online communication in the ROM based on Ring-LWE: The function-dependent online stage has communication poly(*λ*), while the input-dependent online stage has communication poly(*λ*) + *|*x*|* + *|*y*|*. The instance-independent preprocessing phase has quasilinear complexity in the circuit size. Importantly, the protocol is concretely efficient, as it only invokes authenticated garbling and our compression technique in a black-box way. (Of course it would also be possible to merge the function- and input-dependent steps into a single phase with communication poly(*λ*)+*|*x*|*+*|*y*|*. However, in practice the function *C* might become known much earlier than the inputs x*,*y, and for concrete efficiency reasons it would make sense to start processing it as soon as possible.) Prior works [IKM + 13,Cou19] have explored using *function-dependent* (instead of instance- independent) preprocessing to reduce the communication after the inputs are known. However, they are in the information-theoretic regime and their main messages have been relatively neg- ative, either the correlated randomness produced by preprocessing is exponentially long, or the online communication is only slightly sublinear, *|C|/O*(log log *|C|*). See AppendixA.

## 2 Technical Overview

Our focus is the efficient construction of a *batch-select* scheme Sel over a message space *M* that forms a ring. This primitive is a special case of functional encryption: The encryptor, given *two* message vectors l₁*,*l₂ *∈M* *w*, first computes one (large) ciphertext ct. Later, given any selection vector y *∈{*0*,*1*}* *w*, they compute a (small) decryption key sky. This allows the decryptor (who has the ciphertext ct, key sky, and selection vector y), to compute the evaluation lres:= l₁*⊙*y+l₂. Here, *⊙* denotes component-wise vector multiplication. The (simplified) batch-select syntax is as follows:

## <u>Encryptor Decryptor</u>

○1 Sel*.*Enc(l₁*,*l₂) *→* ct*,*st ○3 Sel*.*Dec(sky*,*ct*,*y) *→* l₁ *⊙* y + l₂*.*

## ○2 Sel.KeyGen(st,y) → sky

Security states that no information about l₁ and l₂ beyond l₁ *⊙* y + l₂ is learned. Importantly, we require the size of key skyto be independent of the message dimension *w*. We note that this primitive has already been studied in [AIKW13] (see Table1), where it was called “randomized encoding for subset functions” (we use the slightly different syntax described above, which is going to be conceptually closer to our construction). We are going to present a new and concretely efficient construction, along with new applications.

2.1 Instantiating Batch-Select We start by describing a generic way of instantiating the batch-select primitive, given linearly homomorphic encryption (LHE) and linear laconic encryption (LEnc), both working on the batch- select message space *M*. Linearly Homomorphic Encryption. The desired batch-select output lresfor messages l₁*,*l₂ and a selection vector y, is visualized on the left-hand side:
<u>Desired Achievable with LHE</u>          
..........
.  . .  vs. .  .  (1) l₁[*i*] *⊙* *y* *i*  + l₂[*i*] l₁[*i*] *· y* + l₂[*i*]          
..........
.....

The difficulty of achieving this comes from *component-wise* multiplication of message l₁ with some long vector y. In particular, if only *vector-scalar* multiplication of l₁ with a single element *y* were necessary (see right-hand side above), then we could easily achieve this using a key-and- message linearly homomorphic encryption scheme (LHE): The ciphertext returned by Sel*.*Enc

||i1|
|---|---|
|ires i1|i2|

would contain encryptions ct *←* LHE*.*Enc(sk₁*,*l₁[*i*]) and ct *i* 2*←* LHE*.*Enc(sk₂*,*l₂[*i*]) for all *i ∈* [*w*]. Given the *succinct* combined key sk := sk₁ *· y* + sk₂, one could decrypt all linearly-combined ciphertext ct := ct *· y* + ct to obtain lres[*i*] = l₁[*i*] *· y* + l₂[*i*]. In [AIKW13], their DDH-based and LWE-based schemes achieve component-wise multipli- cation by encrypting each column of the square matrix diag(l₁) using an LHE, but this results in quadratic ciphertext size.

Linear Laconic Encryption. Our idea for efficiently closing the gap between the two terms in Equation1is inspired by the recently proposed laconic encryption scheme from [DKL + 23] (it is based on Ring-LWE, but for now we describe it for any message space *M*). We are not going to use their scheme as-is. Instead, we use some of the underlying ideas towards our batch-select construction. Specifically, our observation is that [DKL + 23] implicitly uses a primitive that we denote by LEnc. It allows a sender to encrypt a vector s *∈M* *w* of ring elements, and anyone else to locally evaluate the resulting ciphertext ct to obtain the *component-wise multiplication* s *⊙* a between the encrypted vector s and any chosen vector a. However, this outcome is *masked* by the term r *· d*a, for some r *∈ M* *w* generated during encryption, and a publically computable digest *d*a*←* LEnc*.*Digest(a) that is also an element in *M*:

## <u>Sender Receiver</u>

○1 LEnc*.*Enc(s) *→* (r*,*ct) ○2 LEnc*.*Eval(ct*,*a) *→* r *· d*a*−* s *⊙* a

This gadget is helpful, because the evaluation outcome can be seen as “replacing” the difficult- to-achieve component-wise multiplication s *⊙* a by a simple vector-scalar multiplication r *· d*a.

Putting It Together. Our batch-select scheme applies the LEnc gadget to message s := l₁, which will allow the decryptor to obtain r *· d*a*−* l₁ *⊙* y, i.e., the desired component-wise multi- plication l₁ *⊙*y masked by the “decryption term” r *· d*y. In order to remove this decryption term and simultaneously take care of the second message vector l₂, our scheme additionally produces LHE encryptions of vectors r and l₂. The encryptor, once selection vector y is known, computes

a *short* combined secret key skythat may be used to evaluate r *· d*y+ l₂. Subtracting this from the LEnc outcome yields l₁ *⊙* y + l₂ as desired. We summarize the scheme as follows.

<u>Encryptor</u>

○1 Sel*.*Enc(l₁*,*l₂) *→* ct := (LEnc*.*ct*,*LHE*.*ct₁*,*LHE*.*ct₂) and st := (sk₁*,*sk₂)*,*

where (r*,*LEnc*.*ct) *←* LEnc*.*Enc(l₁)*,*

LHE*.*ct₁ *←* LHE*.*Enc(sk₁*,*r)*,*

## LHE.ct₂ ← LHE.Enc(sk₂,l₂).

○2 Sel*.*KeyGen(st*,*y) *→* sky*←* sk₁ *· d*y+ sk₂*,*

## where dy← LEnc.Digest(y).

<u>Decryptor</u>

○3 Sel*.*Dec(sky*,*ct*,*y) *→* <u>LHE.Dec</u>(sk<u>,ct</u>) *−*<u>LEnc.Eval</u>(<u>LEnc.ct, y</u>)*,*

|y|res|||
|---|---|---|---|
|r·d +l y||r·d|−l ⊙y|
|res||y||
|||y||

| {z} | {z} y 2 y 1 where *d ←* LEnc*.*Digest(y)*,*

ct := LHE*.*ct₁ *· d* + LHE*.*ct₂*.*

As desired, the resulting batch-select decryption key sk is only a single LHE key, independently of *w*. Leaving the idealized setting. So far we omitted several details that arise once we replace the generic message space *M* by an actual Ring-LWE ring *Rp*. *First*, we ignored Ring-LWE-induced noise. As usual, we can deal with this by multiplying the message vectors l₁*,*l₂ with a sufficiently large scaling factor *∆* and then work over the ring *Rq*for *q* = *p∆* instead. The final step of the decryptor is to divide and round the output. We note that this complicates the security proof: since the decryptor will know both the *exact* message l₁ *⊙* y + l₂ as well as its *noisy* variant, some function of the Ring-LWE noise will be leaked. Therefore, we use *noise flooding* to statistically hide the leakage. To keep its cost low, we use a result from [DKL + 23], which shows that (for the type of leakage that our scheme produces) it is sufficient to sample the flooding noise from a distribution that is only polynomially larger than the actual Ring-LWE noise. This saves us from an exponentially large Ring-LWE modulus when desired. *Second*, naive LHE incurs large noise growth. In particular, the noise resulting from naive multiplication ct₁ *· d*yduring LHE evaluation will exceed the modulus *q*. Therefore, we apply a standard decomposition trick to split ct₁ into *m* = *⌈*log*gq⌉* ciphertexts encrypting r*,* r*·g,*r*·g²,...*, which can then be multiplied with a decomposition of *d*y. Performing multiplication in this form will increase existing noise by only a factor of *q¹* */m* *·* poly(*λ*), which allows us to set *m* = *O*(1) without breaking correctness. Applying the same trick inside LEnc, the batch-select ciphertext for message space *M* = *Rp*has the following size:

*|*LEnc*.*ct*|* = *O*(*w*log *w ·|Rq|*)*, |*LHE*.*ct₁*|* = *O*(*w ·|Rq|*)*, |*LHE*.*ct₂*|* = *O*(*w ·|Rq|*)*.*

Fortunately, the noise growth of our scheme still allows a large plaintext modulus such as *p ≥ q¹* */c*

for constant *c* (even with polynomial modulus-to-noise ratio). Therefore, log *|Rq|* = *O*(log *|Rp|*), implying that a batch-select ciphertext asymptotically has the same size as its plaintext. *Third*, for our garbling application, we require batch-select with message space *M* = Z*p* instead of ring *Rp*. This can be achieved easily and efficiently with *packing*: for compatible primes

*p*, the Chinese Remainder Theorem shows that each *Rp*element is isomorphic to Z *n* *p*[SV10, GHS12] (where *n* is the degree of ring elements in *R*). Thus, whenever *w* = *Ω*(*n*), we also get a batch-select scheme for message space *M* = Z*p*with

*|*LEnc*.*ct*|* = *O*(*w*log*w*log*p*)*, |*LHE*.*ct₁*|* = *O*(*w*log*p*)*, |*LHE*.*ct₂*|* = *O*(*w*log*p*)*.*

2.2 Making batch-select practical Overall, batch-select on messages in *M*
*w* = Z *w* *p*with *p* = *Θ*(2 *λ* ) (as in our application for garbled circuits in Section2.3) would cost *|*ct*|* = *O*(*w*log *wλ*) bits. For certain settings, we present two optimizations to bring down this cost to essentially 0.

Reusability. Our first observation is that garbled circuit labels under free-XOR type assump- tions [KS08] have a special label format l₁ = *∆ ·*1*w*(for some fixed *∆ ∈M*). Even when garbling several circuits, the same label offset may be used for all of them, and hence the message vector l₁ will always be the same. Only l₂ and the selection vector y change across multiple runs. The only component of the batch-select ciphertext that depends on l₂ is LHE*.*ct₂; the other two components LEnc*.*ct, LHE*.*ct₁ can be reused. More precisely, we split Sel*.*Enc into two parts:

Reusable: ○1a Sel*.*Enc₁(l₁) *→* ct₁ := (LEnc*.*ct*,*LHE*.*ct₁) and st₁ := sk₁*,*

where (r*,*LEnc*.*ct) *←* LEnc*.*Enc(l₁)*,*

## LHE.ct₁ ← LHE.Enc(sk₁,r).

Non-reusable: ○1b Sel*.*Enc₂(l₂) *→* ct₂ := LHE*.*ct₂ and st₂ := sk₂*,*

## where LHE.ct₂ ← LHE.Enc(sk₂,l₂).

Later, Sel*.*KeyGen will be called with both states st₁ and st₂, and Sel*.*Dec will be called with both ciphertexts ct₁ and ct₂. The amortized cost for applying batch-select *T* times becomes *O*(( <u>log</u> *T* <u>w</u> + 1)*w*log*p*). For sufficiently large *T* = *Ω*(log*w*), the cost of *|*ct₁*|* vanishes, and only that of *|*ct₂*|* = *O*(*w*log*p*) remains. We also note an orthogonal optimization: Whenever l₁ = *∆ ·* 1*w*, we can apply an optimized LEnc construction (SectionB.1) that directly yields cost *|*LEnc*.*ct*|* = *O*(*w ·|Rq|*) = *O*(*w*log*p*) bits, even without amortization. However, using this construction does not allow us to get below the *|*ct₁*|* = *O*(*w*log*p*) barrier. Only when applying amortization, the following optimization will yield asymptotical advantages.

Compressing Random LHE Ciphertexts. Our second observation is that when transfering common garbled circuit labels, e.g. Yao’s garbling, batch-select is used with *completely random* l₂ message vectors. In this case, we may simply sample them within batch-select in the following optimized way: we first sample a *random LHE ciphertext* LHE*.*ct₂ (this can be done using the random oracle), and reversely derive a message vector l₂ *←* LHE*.*Dec(sk₂*,*LHE*.*ct₂). It then suffices to publish a seed of *λ* bits in place of the entire ciphertext LHE*.*ct₂. A complication arises as a randomly sampled LHE*.*ct₂ may not decrypt correctly. Roughly, decryption correctness requires the noise level in LHE*.*ct₂ to be much smaller than the scaling factor *∆*, while a randomly sampled one has uniform noise level in [0*,∆*). This only happens with negligible probability when the modulus *q* = 2 *Θ*(*λ*) is sufficiently exponentially large. For general modulus, we utilize rejection sampling to indicate whether a ciphertext is good. It requires sending *|*ct₂*|* = *O*( *q/* <u>w</u> *−ε* <u>·λ</u> *·*log*q* ) bits given plaintext modulus *p* = *q* *ε*. See Section4.4for more detail and our security analysis.

Putting It Together. In summary, when applying both discussed optimizations, the cost of batch-select (amortized across *T* instances with identical l₁ and *uniformly random* l₂ for each instance) becomes

*|*LEnc*.*ct*|* = *O*(*w*log*w*log *p/T*)*, |*LHE*.*ct₁*|* = *O*(*w*log *p/T*)*, |*LHE*.*ct *∗* 2 *|* = *O*(*w*)

for general modulus *q*. With *T* = *Ω*(log *w ·* log*p*), the amortized offline cost will be *O*(*w*), which may be much smaller than the plaintext that has size *w ·* log*p*. With exponential modulus 2(1+*ε′*)*λ ∗* *q* = 2, we even get *|*LHE*.*ct₂*|* = 0, and therefore the amortized cost converges towards 0.

2.3 Application: Preprocessing Garbling Now we sketch a natural application of batch-select: a garbling scheme in which the costly garbling splits into a *function-independent* part, and a subsequent *succinct, function-dependent* part. In other words, the main work can be performed before the circuit is even known. Our approach is conceptually simple: In a function-independent step (GarbleU), without know- ing the function description, the garbler prepares a standard garbling *C*c*U*(e.g. using Yao’s GC) of a *universal circuit CU*. This circuit *CU*(*f,* x), when given the description *f* and input x, returns *f*(x). We denote the *s* input keys corresponding to the function description *f* by K
Fn *∈K* *s×*2, and the input keys corresponding to the input x by K *∈K* *|*x*|×*2. In a function-dependent step (GarbleFunc), we only need to make sure that the evaluator obtains the function’s input labels

K Fn [f] = (K Fn [1] *−* K Fn [0]) *⊙* f + K Fn [0]*,*

where f *∈{*0*,*1*}* *s* is the bit-representation of function *f*. We can easily do so, *succinctly*, using batch-select message vectors l₁ = K Fn [1] *−* K Fn [0] and l₂ = K Fn [0]. Besides *C*c*U*, we place the (large) ciphertext ct into the function-independent garbling (denoted by *U*b := (ct*, C*c*U*)), and only need to send the short key skfin the function-dependent step. We summarize this process below. SG denotes a standard model garbling (such as Yao’s garbling scheme). The evaluation function Eval((*C*c*U,*skf)*,f,*kx) takes the function *f*, the entire garbling (*U,*b skf), and the input labels kxfor input x. See Section5for details.    *C* c *U←* SG*.*Garble(*CU,*(K Fn *,*K)) for random keys K Fn  GarbleU(K) ct*,*st *←* Sel*.*Enc(K Fn [1] *−* K Fn [0]*,* K Fn [0])    b c output *U* := (ct*, CU*) and st n GarbleFunc(st*,*f) output skf*←* Sel*.*KeyGen(st*,*f) ( Fn kf*←* Sel*.*Dec(skf*,*ct*,*f) Eval(*f,*(*U,*b skf)*,* kx) output y *←* SG*.*Eval(*CU, C*c*U,*(k Fn f*,* kx))

The function-dependent garbling size will be *|*skf*|* = poly(*λ*). Using the optimizations from Section2.2, the size of function-independent garbling is *|U*b*|* = *O*(*|C*c*U|*+*|*f*|·λ*) for a single instance, and converges towards *|C*c*U|* amortized across a large number of instances (in the ROM). We can naturally transform the garbling scheme above into a 2-party computation protocol with succinct function-dependent cost. One may additionally use batch-select to transfer input labels kxwith cost poly(*λ*) + *|*x*|* in the online phase, instead of the naive cost *|*x*|· λ*.

2.4 Adaptive Security In this work we mainly focus on the *selective* simulation security of batch-select, where the at- tacker must choose all inputs (x
(1) *,* x
(2) *, ··· ,*x
(*T*) ) before seeing any offline component. Similarly,
for preprocessing garbling, all functions *C*

(*t*) and inputs x
(*t*) must be chosen statically.
A stronger security requirement would be adaptive security, where the attacker can choose each x

(*t*) and/or *C*
(*t*) adaptively, dependent on previously generated components. This notion
is important for attaining *maliciously* secure two-party computation protocols, where malicious parties’ inputs are not defined at the beginning of the execution. In AppendixF, we show that in the ROM, it is simple to modify our batch-select scheme to become adaptively secure, using similar techniques as in [BHR12]. This requires an adaptive version of error-leakage Ring-LWE (see Definition4), which follows directly from plain Ring-LWE with exponential modulus-to-noise ratio using noise flooding. We apply the adaptively secure batch-select to construct a malicious 2-party computation protocol with only poly(*λ*) bits of communication in the function dependent phase, and *|*x*|* + *|*y*|* + poly(*λ*) in the online phase.

## 3 Preliminaries

We denote by *λ* the security parameter. For two families of distributions *X* = *{Xλ}λ∈*Nand *Y* = *{Yλ}λ∈*N, we say that they are 2 *λ* -indistinguishable, if for any probabilistic adversary *A* with running time bounded by *t*(*λ*), we have

<u>poly(λ)</u>

|| Pr[A(X|) = 1] − Pr[A(Y||) = 1]|≤||· t(λ)||
|---|---|---|---|---|---|---|
||λ||λ|λ|||
|||||2|||
||||poly(λ) 2|c|2 s||
|λ 2 x|w|ℓ ×2||i ℓ||x|
|||||||ℓ|

2 *λ* for some polynomial poly(*λ*). We also write this as *X ≈ Y*. Furthermore, if the *statistical* *λ* distance between *X* and *Y* is bounded by*λ*, then we write *X ≈*.

Garbling keys. In our garbling schemes, the *i*-th bit of an input x *∈ {*0*,*1*}* *ℓ* xis associated

with a pair of *keys* K[*i,*0]*,*K[*i,*1] *∈ K*. Here, *K* is the key space associated with the garbling scheme (e.g., *K* = Z). We call the selected key K[*i,x*] the *label* of the *i*-th bit. We write the set of all keys as a matrix K *∈ K*x. We use short-hands K[*b*] = (K[1*,b*]*,...,* K[*ℓ,b*]) and K[x] = (K[1*,x₁*]*,...,* K[*ℓ,x*]) (for *b ∈{*0*,*1*}* and x *∈{*0*,*1*}*x), to denote the set of all *b*-keys, and the set of all labels for input x, respectively. Note that both K[*b*] and K[x] are in *K*x.

3.1 Ring-LWE For Ring-LWE, we will follow the notation of [DKL
+ 23] for the most part. We recap all necessary definitions and notations. The *m*-th *cyclotomic polynomial* is defined as Y *Φm*(*X*) = (*X − ωm* *i* ) *∈* Z[*X*]*,* *i∈*Z*∗m*

where *ωm*is an *m*-th root of unity in C. In this work, we consider the polynomial rings *R* = Z[*X*]*/Φm*(*X*), where *Φm*(*X*) has a power-of-2 degree *n* = *ϕ*(*m*). Let *Φ* : *R →* R *n* be an embedding of *R* in R *n*. For example, the coefficient embedding P *n−*1 *i T*

||i=0 n−1 i|i|n−1 T||||||
|---|---|---|---|---|---|---|---|---|
||||||∞|∞|i=0,...,d|−1 i|
|d −1|i|||||||∥a·b∥|
|i=0 i||||||R|a,b∈R\{0} ∥a∥|·∥b∥|

maps *Φ*( *a X*)=(*a₀,...,a*). We define the *infinity norm* of a ring element *a ∈ R* with respect to its coefficient embedding, i.e., *∥a∥* = *∥Φ*(*a*)*∥* = max *R* *|a |* for *a* = P *R* <u>∞</u> *a X*. The *ring expansion factor* of *R* is given by *γ* := max *∞ ∞*.

Lemma 1([AL21], Proposition 2). *If the cyclotomic R has degree n* = 2 *k* *(i.e., the degree* *is a power of* 2*), then the expansion factor is bounded by γR≤ n.*

Given a modulus *q ∈* N, we use *Rq*to denote *R/qR*. For an element *a ∈Rq*, we use *∥a∥* *∞* in the ring modulo *q*, to denote the infinity norm of the element *a ∈R*, where we identify each coefficient *a*

|∈ Z of a with the corresponding representative element in [|||, ) ⊆ Z. We use ⌊|⌉|
|---|---|---|---|---|
|i q|q|i|2 q 2 q a ∆|∆ a|

to denote the ring element *b ∈R*, where the *i*-th coefficient *b* is equal to <u>i</u>, rounded to the nearest integer.

Definition 1(LWE*R,m,q,χ*Assumption). *The* LWE*R,m,q,χassumption, for a ring R, number* *of samples m, modulus q, and error distribution χ over Rq(all of which are parameterized by* *λ), states that the following two distributions are indistinguishable:*  

|$ m q|||
|---|---|---|
|$ q|2|$ m q|
|$ m|c|$ m q λ|
||λ||

  a *← R*     *s ← R λ* a *← R* (a*,*y) *≈* (a*,*y)   e *← χ*   y *← R*   y := a *· s* + e mod *q*

Distributions over *R*. We will use discrete Gaussians for error distributions in Ring-LWE. Over R, the *continuous* Gaussian distribution with parameter *s* is defined by the density function *−πx*2*/s*2 *ρs*(*x*) = *e*. Over Z, this yields the *discrete* Gaussian distribution with parameter *s* by <u>P</u> <u>ρ</u> <u>s</u>

<u>(x)</u> *n*
defining the density function *D*Z*,s*(*x*) = *′ ρs*(*x* *′* ). For a ring *R* with embedding *Φ* : *R→* R, *x ∈*Z the Gaussian distribution *DR,s*samples a vector in R *n* using *D* Z *n,s*, and then maps the result back to an element in *R*. For example, if *Φ* is the coefficient embedding, *DR,s*samples individual P *n−*1 *i*

|i $|Z,s|||n−1 i=0|i i|
|---|---|---|---|---|---|
||||n×n|||

coefficients *ai←*$ *D*Z*,s*, which then yields the ring element *a* = *aiX*. Gaussians may also be generalized to a *covariance matrix σ ∈* R, which allows individual coordinates to be correlated. To ensure perfect correctness of our constructions, we will actually use *truncated* discrete Gaussians, whose distribution *DR,s*is based on a security parameter *√* *λ*. This distribution *DR,s* is identical to *DR,s*, except that it rejects the sample if *√* *∥a∥* *∞* *> λ · s*, and instead continues sampling until it finds an *a ∈R* with *∥a∥* *∞* *≤ λ · s*.

Lemma 2. *For a ring R with degree n* = poly(<u>λ</u>)*, and for any parameter s, the following two* *λ*

|λ|R,s 2 s|R,s|||||
|---|---|---|---|---|---|---|
|+|$ R,s||−π·λ|λ R,s|poly(λ)|R,s|
||||||2||
||||||∞||
||||R,s||||
||+||||||

*distributions are* 2*-statistically close: D ≈ D.*

*Proof.* By [DKL 23, Lemma 2], we have

*√* <u>poly(λ)</u> Pr[*∥e∥ > λ · s | e ← D*] *<* 2 *· n · e <.* 2

Conditioned on the event given in the probability above not happening, *D* is identical to *D*, and hence the statistical distance between these two distributions is bounded by*λ*. *⊓⊔*

Given any distribution *χ*, we will use “ max*χ*” to denote the maximum norm *√* *∥a∥* that any value *a ← χ* sampled from this distribution can have (e.g., max*D* = *λ · s*). Error-leakage Ring-LWE. In [DKL 23], the following variant of Ring-LWE (called *error-* *leakage* Ring-LWE) was introduced. It provides the adversary with some additional information: *A* does not only receive the Ring-LWE sample (a*,* <u>y</u>), but also some *leakage* l = Z *·* e + e, where <u>e</u> is the error used to compute y = a *· s* + e, and e is a fresh error from a different distribution *χ*. The *leakage matrix* Z may be adversarially chosen, but it is restricted to a subset *L⊂R* *k×m*.

Definition 2(elLWE*R,q,χ,χ,L*Assumption, [DKL + 23]). *We say that the* elLWE*R,q,χ,χ,Las-* *sumption (with some set L ⊂ R* *k×m* *) holds, if for any probabilistic adversary A with running* *time bounded by t*(*λ*)*, we have*

*A,*0 *A,*1poly(*λ*) Pr[elLWE *R,q,χ,χ,L* = 1] *−* Pr[elLWE *R,q,χ,χ,L* = 1] *≤* *λ* *· t*(*λ*)*,* 2

*A,b* *where the* elLWE *R,q,χ,χ,L* *experiment is defined as follows.*

*1.The game samples a public parameters* a *←*$ *R*
*m* *q, and sends* a *to A.*

*2. A outputs a matrix* Z *∈L.*
*3.The game samples* e *←*$ *χ*
*m* *,* e *←*$ *χ* *k* *and computes the leakage* l = Z *·* e + e*. It sends to A* *the pair* (y*,*l)*, where* y *is computed as follows.* – *If b* = 0*, sample s ←*$ *Rqand define* y *T* = *s ·* a *T* + e *T* mod *q.* – *If b* = 1*, sample* y *←*$ *R* *m* *quniformly at random.*

*4. A outputs a bit b*
*′* *, which is also the output of the game.*

In [DKL + 23], the authors give a hardness result of elLWE under the standard assumption of Ring-LWE. The required parameters for standard Ring-LWE depend on spectral properties guaranteed for all leakage matrices Z *∈R* *k×m* in *L* (when viewed as a matrix in R *kn×mn* ). While these propertiese are only explicitly considered in the special case of *k* = 1 in [DKL + 23], their proof of elLWE hardness actually works for any matrix Z *∈R* *k×m*. We will use this more general version, but this also requires us to define the following formalization of a maximal singular value *σ*max(*L*). It is based on Lemma 9 of [DKL + 23].

Definition 3. *Let R be a ring of degree n, and let Φ* : *R →* R *n* *be an embedding of R in* R *n* *. For a vector* x *∈ R* *ℓ* *, we write Φ*(x) *∈* R *ℓn* *to mean the vector containing all Φ*(*xi*) *for* x = (*x₁,...,xℓ*) *T* *.* *For a matrix* Z *∈ R* *k×m* *, we may define a linear transformation Θ*Z: R *mn* *→* R *kn* *with* *corresponding matrix* AZ*∈* R *kn×mn* *as*

*Θ*Z(x) = *Φ*(Z *· Φ* *−*1

(x)) = AZ*·* x*.*
*For a set L⊂R* *m×k* *, we define the* maximal singular value *σmax*(*L*) *as*

*σmax*(*L*) = max*σmax*(AZ)*.* Z*∈L*

Theorem 2([DKL + 23], Theorem 3). *Let ϵ >* 0 *be negligible. Let R be a suitable ring with* *n* *√* *an embedding as a lattice in* R*, and let* Σ₀ *be a covariance matrix with* *√* Σ₀ *≥ ηϵ*(*R*)*. Let* *L⊂R* *k×m* *be an efficiently decidable set. Let s,t ≥* 2 2 *be such that*

|t σ|(Σ₀) ≥ (s² + 1)(s² + 2) σ||(Σ₀) · (σ|(L))||
|---|---|---|---|---|---|
|2 min||2|max|max|2|
||||∗|||
|R, (s +1)Σ|R,q,χ,χ,L R,q,χ,χ,L|R, (t +1)Σ|R,m,q,χ|R,s/2·√Σ|′|

*s*

*Now let χ* = *D √*2*, χ* = *D √*2*and χ* = *D* 0 *. Then, assuming that* 0 0 LWE*R,m,q,χ∗ is hard,* elLWE *is also hard. More precisely, if there exists an adversary A* *with advantage δ against* elLWE*, then there exists an adversary A with roughly the same* *running time and adavantage δ − ϵ against* LWE *∗.*

Leakage Considered in This Work. In this work, we will consider the set *Lk,m*(*β*) *⊂R* *k×m* of leakage matrices such that all contained ring elements have infinity norm bounded by *β* (under coefficient embedding). For such matrices, we can show the following bound on the maximal singular values as required by Theorem2:

Lemma 3([DKL + 23], Lemma 9 generalized). *Let R be a cyclotomic ring of degree n that is* *a power-of-2, and let* Z *∈R* *k×m* *be a matrix, s.t. each coefficient of* Z *has ∥·∥* *∞* *-norm bounded by* *β (in the coefficient embedding). Then, the maximal singular value of the matrix* *√* AZ*∈* R *kn×mn*

*is bounded by σmax*(AZ) *≤ βn km. This immediately implies* *√* *σmax*(*Lk,m*(*β*)) *≤ βn km .* P *n i* *Proof.* For any ring element *a ∈R* with *a* = *i*=1 *aiX* that fulfills *∥Φ*(*a*)*∥* *∞* *≤ β*, and for any *b ∈R*, we have

X *n* X *n* X *n*

|≤||a |·|Φ(X · b)|= |a||·∥Φ(b)∥|≤ β ·|∥Φ(b)∥|||
|---|---|---|---|---|---|---|---|---|
|2|i i=1|i|2 i=1|i|2|i=1|2||
|||2|||||||
||i|||Z|||Z|n×n|
||Z||||||||
|||||||dm|||
|T T 1|T m T|||j|d||||

*∥Φ*(*a · b*)*∥* *i*

= *βn∥Φ*(*b*)*∥.*

Here we used the fact that *X · b* is just a rotation of *b* which does not change its norm. We use this result in the following inequality. We split A into *k · m* blocks A [*i,j*] *∈* R for *i ∈* [*k*], *j ∈* [*m*] (note that A [*i,j*] is exactly the negacyclic matrix corresponding to the ring element in the *i*-th row and *j*-th column of Z). Furthermore, let x *∈* R be any vector, which we split into x = (x*,...,*x), i.e., *m* smaller vectors x *∈* R, each corresponding to one ring element. Then,

*√* X *√* X *∥*AZ*·* x*∥* 2 *≤ k ·* max AZ[*i,j*] *·* x*j≤ k ·* max *∥*AZ[*i,j*] *·* x*j∥* 2 *i∈*[*k*] *i∈*[*k*] *j∈*[*m*] 2 *j∈*[*m*] *√* X = *k ·* max *Φ*(Z[*i,j*] *· Φ* *−*1 (x*j*)) 2 *i∈*[*k*] *j∈*[*m*] *√* X *√* X = *βn*

|Φ(Φ k ·|(x ))|= βn|k · ∥x|∥||
|---|---|---|---|---|---|
|j∈[m] 2|−1 j|2|j∈[m]|j 2||

*√* *≤ βn km∥*x*∥.*

*⊓⊔*

We will also consider the following, *sparse*, version of leakage matrices: Let *L* *×* *k,m* *w*

(*β*) *⊂R* *wk×wm*
be the set of matrices consisting of *w* separate blocks (whose infinity norm are each bounded by *β*) of size *k × m* on the diagonal, i.e.,

*L* *×* *k,m* *w*

(*β*) = *{*diag(Z₁*,...,*Z*w*) *|* Z*i∈Lk,m*(*β*)*} .*
Intuitively, a leakage matrix in *L* *×* *k,m* *w*

(*β*) says that there are *w* leakages, each one computed
separately from *m* fresh Ring-LWE samples (but with the same secret key). Viewing *L* *×* *k,m* *w*

(*β*) as a subset of *Lwk,wm*(*β*) and then directly applying Lemma3would incur
a factor of *w* in the upper bound of *σ*max(*Lwk,wm*(*β*)). Instead, we use the following lemma that shows that this upper bound is independent of *w*.

Lemma 4. *Let R be a cyclotomic ring of degree n that is a power-of-2. Then, the maximal* *singular value of any matrix in L* *×* *k,m* *w*

(*β*) *is bounded by*
*√* *σmax*(*L* *×* *k,m* *w*

(*β*)) *≤ βn km .*

|Proof.|Applying Lemma3, we get for any Z = diag(Z₁,..., Z||||) with Z|∈ L (β) and x =|
|---|---|---|---|---|---|---|
|T|T T|wmd|||||
|1|w||||||
||Z|2|Z|2 i 2|2 i 2|2|

*w i k,m* (x *T* 1*,...,*x *T*

*w*) *T* *∈* R *wmd*
the inequality

s X *√* s X *√* *∥*A *·* x*∥* = *∥*A*i·* x *∥ ≤ βn km ∥*x *∥* = *βn km ·∥*x*∥.* *i∈*[*w*] *i∈*[*w*]

*⊓⊔*

Adaptive error-leakage Ring-LWE. In this work, we are additionally interested in an *adaptive* version of error-leakage Ring-LWE. Here, the adversary may choose the leakage matrix Z *∈L* after already seeing the Ring-LWE sample y, and then obtains the leakage. Z*·*e+e. Furthermore, this step may be repeated adaptively up to *T* times, with a separate leakage matrix Z

(*t*) and
noise e

(*t*).
Definition 4(Adaptive a-elLWE*R,q,χ,χ,T,L*Assumption). *We say that the adaptive* a*-*elLWE*R,q,χ,χ,T,L* *assumption (with some set L⊂R* *k×m* *) holds, if for any probabilistic adversary A with running* *time bounded by t*(*λ*)*, we have*

poly(*λ*)

|A,0||A,1||
|---|---|---|---|
|R,q,χ,χ,T,L A,b R,q,χ,χ,T,L|$ q|R,q,χ,χ,T,L $ m q T T|λ $ m|
||$ m q|||
|′|(t) (t) $ k||(t) (t)|

Pr[a*-*elLWE = 1] *−* Pr[a*-*elLWE = 1] *≤ · t*(*λ*)*,* 2

*where the* a*-*elLWE *experiment is defined as follows.*

*1.The game samples public parameters* a *← R and noises* e *← χ. It sends to A the pair* (a*,*y)*, where the Ring-LWE sample* y *is computed as follows.* – *If b* = 0*, sample s ← R and define* y = *s ·* a + e
*T* mod *q.* – *If b* = 1*, sample* y *← R uniformly at random.*

*2.For each t ∈* [*T*]*:* – *A outputs leakage matrix* Z *∈L.* – *The game samples* e *← χ and sends to A the leakage* l = Z *·* e + e
(*t*) *.*
*3. A outputs a bit b, which is also the output of the game.* Note that the adaptive version is easily implied by standard Ring-LWE whenever the noise e is sampled from a distribution *χ* that statistically hides Z *· e*. This variant, called *noise flooding*, has the disadvantage of increasing the bitlength of modulus *q* by *λ*. *g*-ary gadget vector. In order to constraint noise growth, it will sometimes be necessary to “decompose” an element *a ∈Rq*(of arbitrary norm) into several ring elements *a₁,...,am*of norm *∥a∥* *∞* *< g*. We denote the number of elements in the decomposition by *m* := *⌈*log*gq⌉*. By g
*−*1 we denote such a decomposition (written as a column vector), and its inverse is given by the vector

g *T* = 1 *g g²...g* *m−*1 *∈R* *m*

*q.*

## 4 Our Main Tool: Batch-Select

In this section, we discuss our new ideas towards an efficient *batch-select* construction. We first give its definition, then define two crucial building blocks LEnc and LHE in Sections4.1and4.2, and present our full construction in Section4.3. Finally, we discuss our RO-based optimization in Section4.4.

Definition 5(Batch-Select). *A* batch-select functional encryption scheme *with abelian mes-* *sage space M*(*λ*) *consists of five efficient algorithms:*

– Sel*.*Setup(1 *λ* *,*1 *w* ) *takes the security parameter λ and dimension w. It outputs public parame-* *ters* pp*, implicitly given as input to all remaining algorithms.* – Sel*.*Enc₁(l₁) *takes a message vector* l₁ *∈M* *w* *, and outputs a ciphertext* ct₁ *and a state* st₁*.* – Sel*.*Enc₂(l₂) *takes a message vector* l₂ *∈M* *w* *, and outputs a ciphertext* ct₂ *and a state* st₂*.* – Sel*.*KeyGen(st₁*,*st₂*,*y) *takes the two states* st₁*,*st₂ *returned by* Enc₁*,*Enc₂*, and a selection* *vector* y *∈{*0*,*1*}* *w* *. It outputs a decryption key* sky*.* – Sel*.*Dec(sky*,*ct₁*,*ct₂*,*y) *takes the decryption key* sky*, two ciphertexts* ct₁*,*ct₂*, and the selection* *vector* y*. It outputs a message vector* l *∈ M* *w* *(which should be* l = l₁ *⊙* y + l₂*, where ⊙* *denotes component-wise multiplication).*

*Correctness. The scheme* Sel *is correct if for all λ ∈* N*, w ≤* 2 *λ* *, message vectors* l₁*,*l₂ *∈M* *w* *,* *and selection vectors* y *∈{*0*,*1*}* *w* *, the following holds:*  *λ w*  pp *←* Setup(1*,*1)  (ct₁*,*st₁) *←* Sel*.*Enc₁(l₁)  Pr  Dec(sky *,*ct₁*,*ct₂*,*y) = l₁ *⊙* y + l₂   = 1 *.* (ct₂*,*st₂) *←* Sel*.*Enc₂(l₂) sky*←* Sel*.*KeyGen(st₁*,*st₂*,*y)

Definition 6(*T*-times Simulation Security). *A* Sel *scheme is T*(*λ*)-times 2 *λ* -simulation se-

(1) (*T*)
cure *if there exists an efficient simulator* Sel*.*Sim*, such that for all {wλ}λ∈*N*, {*l₁*,λ}λ∈*N*, {*l₂ *,λ* *,...,* l₂ *,λ* *}λ∈*N*,*

(1) (*T*) (*t*) *w*
*λ*

(*t*) *w*
*λ* *and {*y

|,..., y|}|, where w|≤ poly(λ), l₁||, l₂ ∈M(λ)|, and y||∈{0, 1}|, the fol-||
|---|---|---|---|---|---|---|---|---|---|---|
|λ|λ λ∈N||λ (t) (t)|[T]|,λ ,λ (t)|λ (t) (t)|λ w||||
|||||||||λ|||
|||||||λ w|||||
|2 c|(t) 2|(t) y [T]|(t)|(t) (t) y||(t)|(t)||λ||

*λ λ λ∈*N *λ,λ,λ λ* *lowing holds (where we suppress the subscript λ):* () pp *←* Sel*.*Setup(1*,*1) pp*,*Sel*.*Sim(pp*, {*l*,* y*}*) l = l₁ *⊙* y + l₂ *∀t ∈* [*T*]     pp *←* Sel*.*Setup(1*,*1)       *λ*pp*,*(ct₁*,* (ct₁*,*st₁) *←* Sel*.*Enc₁(l₁) *≈*(*t*)  *{*ct*,*sk*}*) (ct₂*,*st₂) *←* Sel*.*Enc₂(l₂) *∀t ∈* [*T*]       sk *←* Sel*.*KeyGen(st₁*,*st₂*,* y) *∀t ∈* [*T*]

We define two variations of batch-select: a *weak* version in which all entries of the reused message vector l₁ need to be identical (this will allow for a more efficient instantiation), and a *random* version in which the message vector l₂ is required to be uniformly random.

Definition 7(*Weak* Batch-Select). *A* weak *batch-select scheme is defined identically to Def-* *inition5, except that it is guaranteed that all messages in* l₁ *are identical. More specifically,* correctness *is only required to hold for messages* l₁ *of the form* l₁ = *∆ ·* 1*wfor some ∆ ∈M.* *Furthermore, for T*-times 2 *λ* -simulation security *to hold, it suffices if the indistinguishability* *in Definition6holds for all {*l₁*,λ}λ∈*N*where* l₁*,λ*= *∆ ·wfor some ∆ ∈M.*

Definition 8(*Random* Batch-Select). *A* random *batch-select scheme is defined identically* *to Definition5, except that the syntax of encryption algorithm* Sel*.*Enc₂ *changes to:*

– Sel*.*Enc₂() *takes no input, and outputs a ciphertext* ct₂*, a message vector* l₂ *∈ M* *w* *, and a* *state* st₂*.*

*The correctness property does not quantify over message vector* l₂*. Instead,* l₂ *is generated by* <u>poly(λ)</u> Sel*.*Enc₂()*. Correctness is only required to hold with overwhelming probability* 1 *−* 2 *λ.* *We say that a random batch-select scheme satisfies T*-times 2 *λ* -simulation security*, if there ex-*

(1) (*T*)
*ists an efficient simulator* Sel*.*Sim*, such that for all {wλ}λ∈*N*, {*l₁*,λ}λ∈*N*, and {*y *λ* *,...,*y *λ* *}λ∈*N*,* *wλ*(*t*) *wλ* *where wλ≤* poly(*λ*)*,* l₁*,λ∈M*(*λ*)*, and* y *λ* *∈{*0*,*1*}, the following holds (where we suppress* *the subscript λ):*

(*t*) (*t*) (*t*)pp *←* Sel*.*Setup(1
*λ* *,*1 *w* ) pp*, {*l*}*[*T*]*,*Sel*.*Sim(pp*, {*l*,* y*}*[*T*])

(*t*) *w* l *←*$ *M ∀t ∈* [*T*]
*λ*    pp*,* pp *←* Sel*.*Setup(1 *λ* *,*1 *w* )       *λ*(*t*) (*t*)(ct₁*,*st₁) *←* Sel*.*Enc₁(l₁) *≈*c2*{*l₁ *⊙* y + l₂*}*[*T*]*,*(*t*) (*t*) (*t*)   (ct₂*,*l₂*,*st₂) *←* Sel*.*Enc₂() *∀t ∈* [*T*]    (*t*) (*t*) (*t*) (*t*) (*t*)   (ct₁*, {*ct₂*,*sky*}*[*T*]) sk y*←* Sel*.*KeyGen(st₁*,*st*,* y) *∀t ∈* [*T*] 2 *λ*

4.1 First building block: LEnc Our first tool, *linear laconic encryption*, is formally defined in Definition9. Intuitively, it can be viewed as a functional encryption for (noisily) evaluating s *⊙* a over an encrypted vector s and a public vector a, but with a specific secret key format and (noisy) decryption procedure as illustrated below. Encrypt s : (st := r*,*ct) *←* LEnc*.*Enc(s)*,*

|Generate sk w.r.t. a :|sk = r · d|, d ← LEnc.Digest(a),|
|---|---|---|
|Decrypt res = s ⊙ a :|res + noise = δ − sk,||

a a *δ ←* LEnc*.*Eval(ct*,*a)

In particular, the sk is required to be a vector-scalar product between a secret state r and a public digest of the vector a. During decryption, the ciphertext can first be evaluated to *δ* using only the public vector a. The decryption result is then simply *δ −* sk.

Definition 9(Linear Laconic Encryption). *A* LEnc *scheme with associated message space* *Rq*(*λ*) *and error bound B*LEnc(*λ*) *consists of the following efficient algorithms:*

– LEnc*.*Setup(1 *λ* *,w*) *takes the security parameter λ and a message dimension w. It outputs* *public parameters* pp*, which is implicitly given as input to all remaining algorithms.* – LEnc*.*Enc(s) *takes output keys* s *∈R* *w*

*q. It returns input keys* r *∈R*
*w* *qand ciphertext* ct*.* – LEnc*.*Digest(a) *takes the database* a *∈R* *w*

*q. It outputs,* deterministically*, a digest d*a*∈Rq.*
– LEnc*.*Eval(ct*,*a) *takes a ciphertext* ct *and database* a *∈R* *w*

*q. It outputs δ ∈R*
*w*

*q.*
*Correctness. The* LEnc *scheme is correct if for all λ ∈* N*, w ≤* 2 *λ* *output keys* s *∈R* *w* *q, and* *database* a *∈R* *w* *qwith d*a= LEnc*.*Digest(a)*:*  *λ*  pp *←* LEnc*.*Setup(1*,w*) Pr *|δ −* (r *· d*a*−* s *⊙* a)*|≤ B*LEncr*,*ct *←* LEnc*.*Enc(s)  = 1*.* *δ ←* LEnc*.*Eval(ct*,*a)

Security, as captured by the following definition, states that the secret vector s remains hidden even if the noise e accumulated by evaluation (i.e., the difference between the *actual* outcome *δ* and the *expected* outcome r *· d*a*−* s *⊙*a) may be leaked. However, this only holds as long as this leakage is hidden by another noise e sampled from some distribution *χ*LEnc.

Definition 10(Simulation security with *T*-noise leakage). *A* LEnc *scheme is* 2 *λ* -simulation secure under *T* (*λ*)-noise leakage w.r.t. to noise-hiding distribution *χ*LEnc*if there exists an effi-*

(*t*)
*cient simulator* LEnc*.*Sim*, s.t. for all {wλ}λ∈*N*, {*s*λ}λ∈*N*, {*a *λ* *}λ∈*N*,t∈*[*T*]*, where wλ≤* poly(*λ*)*,* *wλ*(*t*) *wλ* s *λ∈Rq, and* a*λ∈Rq, the following holds (where we suppress the subscript λ):*  *λ*    pp *←* LEnc*.*Setup(1*,w*)         r*,*ct *←* LEnc*.*Enc(s)     (*t*) (*t*)  

(*t*) (*t*)*d*a*←* LEnc*.*Digest(a) *∀t ∈* [*T*]
(pp*,*ct*, {*e + e*}*[*T*])(*t*)

(*t*)
  *δ ←* LEnc*.*Eval(ct*,* a) *∀t ∈* [*T*]    (*t*) (*t*)     <u>e</u>

(*t*) := <u>δ</u> *−* (r *· d*a*−* s *⊙* a
(*t*) ) *∀t ∈* [*T*] 
    e

(*t*) *←*$ *χ* *w* LEnc
*∀t ∈* [*T*] *λ*  *λ*   pp *←* LEnc*.*Setup(1*,w*)  2 *λ*(*t*) (*t*)

(*t*) (*t*)
*≈*c(pp*,*cte*, {*ee + e*}*[*T*]) cte*, {*ee<u>}</u>[*T*]*←* LEnc*.*Sim(pp*, {*a*}*[*T*]) 

(*t*) *w*
 e *←*$ *χ* LEnc *∀t ∈* [*T*] *λ*

The following variant of LEnc may be used to construct *weak* batch-select (Definition7) instead of the full batch-select (Definition5).

Definition 11(*Weak* Linear Laconic Encryption). *A* Weak *Linear Laconic Encryption* *scheme is defined identically to Definition9, except that it is guaranteed that* all elements of the output key s are identical*. More specifically,* correctness *is only required to hold for output keys* s *of the form* s = *s ·* 1*wfor some s ∈Rq.* *Furthermore, for* 2 *λ* -simulation security with *T* (*λ*)-noise leakage *to hold, it suffices if the* *indistinguishability in Definition10holds for all {*s*λ}λ∈*N*where* s*λ*= *sλ·* 1*wfor some sλ∈Rq.*

Constructing LEnc. We now present a construction of LEnc over a ring *Rq*. It is parameterized by

(1)a base *g*, used for decomposing a ring element into *m* = log*gq* shorter ring elements of norm bounded by *g*,
(2)the parameter <u>s</u> for the internally used noise distribution *χ* = *DR,s*, and
(3)the parameter *s* for the noise distribution *χ*LEnc= *DR,s*used to hide the error resulting from LEnc evaluation. The correctness error will be bounded by
*√* *B*LEnc*≤ g · m · γR·* log₂ *w · s · λ ,*

where *m* = log*gq*, and the construction fulfills simulation security with *T*-noise leakage

w.r.t. noise distribution *χ*LEnc *R,q,χ,D*

||under the assumption of elLWE||.|
|---|---|---|---|
|+|LEnc|R,q,χ,D ,L|(g)|

*R,s,LT,*2*m*(*g*) The construction will essentially be a simplified version of laconic encryption as presented in [DKL 23]. We first briefly recap the important details of the underlying ideas, and then give the full construction.

We will, w.l.o.g., assume that *w* is a power of 2. If this is not the case, the database may be padded by sufficiently many zeroes. We identify each entry in the database a with a leaf of the complete binary tree of height *ℓ* := log₂ *w*. Let us further index the leaves by *ℓ*-bit bitstrings ind *∈ {*0*,*1*}* *ℓ*, and all other nodes on the tree by a prefix pre *∈ {*0*,*1*}* *<ℓ*. The empty string *ϵ* denotes the root of the tree. To compute the digest, we first assign *y*ind:= a[*i*] to the leaves (where ind is the bitstring corresponding to index *i ∈* [*w*]), and then assign a value *y*preto each node pre *∈ {*0*,*1*}* *<ℓ*, computed as a hash *f* (*·, ·*) of its two children as

|pre|T 0|−1 pre∥0|T 1|−1|pre∥1||
|---|---|---|---|---|---|---|
|ϵ|q|ℓ−1|$ q|ℓ|ϵ|ind ℓ−1|

*y* := *f* (*y*pre*∥*0*,y*pre*∥*1) := b *·* (*−*g (*y*)) + b *·* (*−*g (*y*))*.*

The root value *y* will represent the LEnc scheme’s digest. Given only a ring element *s ∈ R* and an index ind *∈ {*0*,*1*}*, LEnc*.*Enc needs to output *r₀ ∈Rq*and a ciphertext ct, such that an evaluator can obtain the result *r₀ · y − s · y* when
given y and ct. We do so by choosing random *r₀,...,r ← R* and selecting ct = (c₀*,...,*c),

s.t. for each *i* = 0*,...,ℓ −* 1,
 *r* *i·* b *T* b *T* + *ri*+1*·* g *T* 0 *T* if ind*i*= 0 0 1 c*i≈,* *r ·*

||i i|T 0 T 1|i+1|T T|i|
|---|---|---|---|---|---|
|i :i|−1 i −1 ϵ ℓ ind|ind ∥0 ind ∥1|i|ind i+1|ind|
||||||ℓ|
||ϵ|||||

b b + *r ·* 0 g if ind = 1

where ind is the *i*-th bit of ind. Now, by the way in which the hash function *f* was constructed, we can evaluate

*−*g (*y* : *i* ) c *· ≈ r · y*: *i− r · y*: *i*+1*,* *−*g (*y* : *i* )

where ind is the length-*i* prefix of ind. Therefore, summing up the terms above for all *i* = 0*,...,ℓ −* 1 yields *r₀ · y − r · y*, which is the desired result if the encryptor chooses *rℓ*:= *s*. The following construction implements this idea in a *vectorized* fashion, meaning that the ciphertexts above are created for *all* database entries ind *∈{*0*,*1*}* simultaneously, and evaluation will produce the vector r₀ *· y −* s *⊙* y.

## Construction 1(Linear Laconic Encryption LEnc).

<u>Setup(1</u> *λ* <u>,w) → pp</u>: Sample and output Ring-LWE public matrices pp := b₀*,*b₁ *←*$ *R* *m*

*q*.
<u>Enc(s) → r,ct</u>: Sample Ring-LWE secrets r*i←*$ *R* *w* *q*for each layer *i* = 0*,...,ℓ −*1. For notational *w×*2*m* convenience, set r*ℓ*:= s. Also sample *truncated* Ring-LWE noises E*i←*$ *DR,s*. Then, for each of the *w* rows, indexed by ind *∈{*0*,*1*}* *ℓ*, compute for each *i* = 0*,...,ℓ −* 1 the ciphertext

|C [ind] := r|b b|+ r [ind] ·|||+ E|
|---|---|---|---|---|---|
|i a|T 0 T 1|i+1 ℓ−1|i w q ×2m|T i ℓ−1|T|
||||ind|||
|ℓ||||||

*i* [ind] *·* ind *·* g ind *·* g*i*[ind]*.*

We write the results as *ℓ* matrices C₀*,...,*C *∈R*. Return input keys r := r₀ and ciphertexts ct := (C₀*,...,*C). <u>Digest(a) → d</u> : Build an *ℓ* = log*w*-level hash tree as follows, and output the root *yϵ*. Choose the hash values on the leaves of the tree as *y* := a[ind]. (where a[ind] denotes the ind-th row of a, where ind is interpreted as the binary integer corresponding to bitstring ind *∈{,}*).

Compute the hash values on the remaining binary tree as

*−*g (*y*)*<ℓ*

||T T|−1 pre∥0||
|---|---|---|---|
|pre||−1 pre∥1||
||ℓ−1||a ϵ|
|pre ℓ|ℓ−1 i=0|≤ℓ i|−1 −1 ind ∥0 ind ∥1|

*y* := b₀ b₁ *· ∀*pre *∈{*0*,*1*},* *−*g (*y*)

and return the digest that is chosen to be the root *d* := *y*. <u>Eval(ct,a) → δ</u>: Parse ct := (C₀*,...,*C). As in Digest, compute *y* for all pre *∈{*0*,*1*}* from database a. Then, for each ind *∈{*0*,*1*}*, compute the result

X *−*g (*y*) *δ*[ind] := C [ind] *·* : *i* *,* *−*g (*y* : *i* )

## and return the vector δ.

In AppendixB, we formally prove correctness of our LEnc construction above, and show that it fulfills 2 *λ* -simulation security under *T*-noise leakage when assuming elLWE*R,q,χ,D*

|||,L|
|---|---|---|
|R,q,χ,D ,L|(g)||

*R,s T,*2*m*(*g*). In AppendixB.1, we further give a modified version of a *weak* LEnc that is more efficient, but also requires the slightly stronger assumption elLWE *R,s Tw,*2*m*. Ciphertext size, running time, and error bounds all depend on the Ring-LWE parameters. For example, we can get the following result (proven in AppendixB.2).

Lemma 5(LEnc from Ring-LWE). *Assume* LWE*R,O*(1)*,q,D*

0*.*1 *holds (for a cyclotomic ring*
*R,q* *R of degree n ≥ λ that is a power-of-2, modulus q ≥ n¹⁵, and modulus-to-noise ratio q⁰*

*.*9 *).*
*√* *Then, there exists an* LEnc *scheme over message space Rqwith error bound B*LEnc*≤ q that* *λ√* *is* 2*-simulation secure under q-noise leakage w.r.t. to a noise distribution χ*LEnc*whose values* *√* *are bounded by* max*χ*LEnc= 1000 *q. Furthermore, when encrypting w-dimension messages, the* *components of the scheme have size (in terms of ring elements)*

*|*pp*|* = *O*(1)*, |*ct*|* = *O*(*w*log*w*)*,*

*and its algorithms run in time (in terms of ring multiplication operations)*

Enc : *O*(*w*log*w*)*,* Digest : *O*(*w*)*,* Eval : *O*(*w*log*w*)*.* *√* <u>q</u> *Under the same assumptions, there exists a* weak LEnc *scheme secure under* *w* *-noise leakage.* *Its ciphertext contains only |*ct*|* = *O*(*w*) *ring elements, and the* Enc *algorithm only requires O*(*w*) *ring multiplications.*

4.2 Second building block: LHE for Rings The second tool, *linearly homomorphic encryption*, is a functional encryption for (noisily) eval- uating m₁ *· y* + m₂ over encrypted vectors m₁*,*m₂ and a public element *y*. Definition 12(Noisy Linearly Homomorphic Encryption over Rings). *An* LHE *scheme* *with associated message space Rq*(*λ*) *and error bound B*LHE(*λ*) *consists of the following efficient* *algorithms:* – LHE*.*Setup(1
*λ* *,* *w* ) *takes the security parameter λ and a message dimension w. It outputs* *public parameters* pp*, which is implicitly given as input to all remaining algorithms.*

– LHE*.*Enc₁(m₁) *takes a message vector* m₁ *∈R* *w* *q, and outputs a ciphertext* ct₁ *and a state* st₁*.* – LHE*.*Enc₂(m₂) *takes a message vector* m₂ *∈R* *w* *q, and outputs a ciphertext* ct₂ *and a state* st₂*.* – LHE*.*KeyGen(st₁*,*st₂*,y*) *takes the two states* st₁*,*st₂ *output by* Enc₁*,*Enc₂*, and a ring element* *y ∈Rq. It outputs a decryption key* sk*y.* – LHE*.*Dec(sk*y,*ct₁*,*ct₂*,y*) *takes decryption key* sk*yand the two ciphertexts* ct₁*,*ct₂*. It outputs a* *decrypted message* mres*∈R* *w*

*q.*
*Correctness. The* LHE *scheme is correct if for all λ,w ∈* N*, messages* m₁*,*m₂ *∈ R* *w* *q, and* *coefficients y ∈Rq:*

 *λ w*  pp *←* LHE*.*Setup(1*,*1)  ct₁*,*st₁ *←* LHE*.*Enc₁(m₁)    Pr   *∥*mres*−* (m₁ *· y* + m₂)*∥* *∞* *≤ B*LHEct₂*,*st₂ *←* LHE*.*Enc₂(m₂)   = 1 *.*  sk *y←* LHE*.*KeyGen(st₁*,*st₂*,y*)  mres*←* LHE*.*Dec(sk*y,*ct₁*,*ct₂*,y*)

Definition 13(*T*-times Simulation Security). *An* LHE *scheme is T*(*λ*)-time 2 *λ* -simulation

(1) (*T*)
secure *if there exists an efficient simulator* LHE*.*Sim*, s.t. for all {wλ}λ∈*N*, {*m₁*,λ}λ∈*N*, {*m₂ *,λ* *,...,* m₂ *,λ* *}λ∈*N*,*

(1) (*T*) (*t*) *w* (*t*)
*{y* *λ* *,...,y* *λ* *}λ∈*N*, where wλ≤* poly(*λ*)*,* m₁*,λ,*m₂ *,λ* *∈Rq, and y* *λ* *∈Rq, the following holds* *(where we suppress the subscript λ):* () pp *←* LHE*.*Setup(1 *λ* *,*1 *w* )

(*t*) (*t*)
pp*,*LHE*.*Sim(pp*, {*mres*,y}*[*T*])(*t*)

(*t*) (*t*)
mres:= m₁ *· y* + m₂ *∀t ∈* [*T*]  *λ*    pp *←* LHE*.*Setup(1 *λ* *,*1 *w* )       2 *λ*(2*t*) ()ct₁*,*st₁ *←* LHE*.*Enc₁(m₁) *≈*cpp*,*(ct₁*, {*ct*,*sk*yt}* [*T*]) (*t*) (*t*) (*t*)   ct₂*,*st₂ *←* LHE*.*Enc₂(m₂) *∀t ∈* [*T*]      

||||(t)|(t)|(t)|
|---|---|---|---|---|---|
||||y|||

sk *←* LHE*.*KeyGen(st₁*,*st₂*,y*) *∀t ∈* [*T*] *λ*

Constructing LHE. In this section, we give a construction of LHE over a ring *Rq*(see Defini- tion12). It is parameterized by

(1)a base *g*, used for decomposing a ring element into *m* = log*gq* shorter ring elements of norm bounded by *g*,
(2)the parameter <u>s</u> for the noise distribution <u>χ</u> = *DR,s*, and
(3)the parameter *s* for the noise distribution *χ* = *DR,s*. The correctness error will be bounded by
*√* *B*LHE*≤* (*g · m · γR· s* + *s*) *· λ ,*

where *m* = log*gq*, and the construction fulfills *T*-times simulation security under the assump- tion of elLWE *R,q,χ,χ,L* *×w*

(*g*).
*T,*1

## Construction 2(LHE over rings LHE).

<u>Setup(1</u> *λ* <u>,</u> *w* <u>) → pp</u>: Output a public random vector pp = a *←*$ *R* *w* *q*of ring elements.

*m w×m* <u>Enc₁(m₁) → ct₁,st₁</u>: Sample Ring-LWE secrets s₁ *←*$ *Rq*and *truncated* noises E *←*$ *DR,s*. Output a ciphertext

ct₁ := a *·* s *T* 1+ m₁ *·* g *T* + E *∈R* *w* *q ×m,*

together with state st₁ = s₁. *w* <u>Enc₂(m₂) → ct₂,st₂</u>: Sample a Ring-LWE secret *s₂ ←*$ *Rq*and *truncated* noises e *←*$ *DR,s*. Output a ciphertext

ct₂ := a *· s₂* + m₂ + e *∈R* *w* *q,*

together with state st₂ = s₂. <u>KeyGen(st₁,st₂,y) → sky</u>: Parse the states st₁ = s₁ *∈R* *m* *q*and st₂ = *s₂ ∈Rq*. Output a decryp- tion key sk*y*:= s *T* 1*·* g *−*1

(*y*) + *s₂ ∈Rq.*
<u>Dec(sky,ct₁,ct₂,y) → mres</u>: First combine the ciphertexts into

ctres:= ct₁ *·* g *−*1

(*y*) + ct₂ *∈R*
*w* *q,* // s.t. ctres= a *·* (s *T* 1*·* g *−*1

(*y*) + *s₂*) + (m₁ *·* g
*T* *·* g *−*1

(*y*) + m₂) + noise
Then, use sk*y*to decrypt and return mres= ctres*−* a *·* sk*y*, which is supposed to equal mres= m₁ *· y* + m₂ + noise.

In AppendixC, we formally prove correctness of our LHE construction above, and show that it fulfills *T*-time 2 *λ* -simulation security when assuming elLWE *R,q,χ,χ,L* *×w*

(*g*).
*T,*1 Ciphertext size, running time, and error bounds all depend on the Ring-LWE parameters. For example, we can get the following result (proven in AppendixC.1).

Lemma 6(LHE from Ring-LWE). *Assume* LWE*R,w,q,D* *R,q*0*.*1 *holds (for a cyclotomic ring* *R of degree n ≥ λ that is a power-of-2, modulus q ≥ n¹⁵, and modulus-to-noise ratio q⁰*

*.*9 *).*
*√* *Then, there exists an* LHE *scheme over message space Rqwith error bound B*LHE*≤* 10 *q that is* *√λ* *q-times* 2*-simulation secure. Furthermore, when encrypting w-dimension messages, the com-* *ponents of the scheme have size*

*|*pp*|* = *O*(*w*)*, |*ct₁*|* = *O*(*w*)*, |*ct₂*|* = *w, |*sk*|* = 1*,*

*and its algorithms run in time (in terms of ring multiplications operations)*

Enc₁ : *O*(*w*)*,* Enc₂ : *O*(*w*)*,* KeyGen : *O*(1)*,* Dec : *O*(*w*)*.*

4.3 Instantiating Batch-Select from LEnc and LHE We now present a construction of *batch-select* (Definition5) based on LEnc and LHE. We will support the message space *M* = Z*p*, by working over a cyclotomic ring *R* of a power-of-2 degree *n* and composite modulus *q* = *p · ∆*. To ensure correctness, *∆* must fulfill *∆/*2 *> B*LEnc+ *B*LHE+ max*χ*LEnc(where *B*LEncand *B*LHEdenote the maximum error incurred by LEnc and LHE, and *χ*LEncis the distribution of noise required to hide any noise leakage from LEnc; see Definition10). Plaintext encoding. We use the Chinese Remainder Theorem (CRT) to pack *n* elements of Z*p* elements into a single plaintext in *Rp*. Specifically, in our choice of the ring *R* = Z[*X*]*/Φ*(*m*),

the *m*-th cyclotomic polynomial (of degree *n* = *ϕ*(*m*)) splits mod *p* if *p ≡* 1 mod *m*, i.e., *Φ*(*m*) = *F₁·... · F*

|over F|, where F|are degree 1 polynomials. By CRT, the plaintext space is isomorphic|||
|---|---|---|---|---|
|n p|p p n p|i p p|p|n p|
|p|||p||

to *n* times Z :

*R* = Z [*X*]*/ϕ*(*m*) *∼* = Z [*X*]*/F₁*(*X*) *×... ×* Z*p*[*X*]*/Fn*(*X*) *∼* = Z*.*

We write crt : Z *→ R* to denote a ring isomorphism that “encodes” *n* plaintexts from the space Z as a single ring element in *R*. Applying CRT to the plaintext space of Ring-LWE is a common idea in the literature [SV10,GHS12]. We refer readers to [GHS12] for more details of the underlying algebra. Using packing, we obtain an efficient encoding Encode that maps *w*-dimensional messages *w ′* <u>w</u> *w′* l *∈M* to *w* = *⌈* *n* *⌉*-dimensional ring elements in *Rp*. Importantly, this mapping fulfills the identity Encode(a *⊙* b) = Encode(a) *⊙* Encode(b) for any vectors a*,* b *∈M* *w*, and similarly for *w′* addition. Note that while Encode maps to *Rp*, in our construction we will treat the resulting *w′* vectors as elements in the larger space *Rq*.

## Construction 3(Batch-Select Sel).

*λ w λ w′λ ′ ′* <u>Setup(1,1) → pp</u>: Run ppLHE*←* LHE*.*Setup(1*,*1), ppLEnc*←* LEnc*.*Setup(1*,w*) with *w* = <u>w</u>

|⌉ as defined above, and output pp := (pp ⌈|, pp|).||
|---|---|---|---|
|n|LHE w w p|LEnc|w p|

*n* LHE LEnc *′* <u>Enc₁(l₁) → ct₁,st₁</u>: Encode messages l₁ *∈M* = Z as a vectorbl₁ = Encode(l₁) *∈R*, and then compute the laconic encryption ciphertext LEnc*.*ct for the resulting vector of ring elements:

## r,LEnc.ct ← LEnc.Enc(bl₁ · ∆)

Encrypt the corrosponding LEnc keys r using the *reusable* LHE component:

## LHE.ct₁,st₁ ← LHE.Enc₁(r)

Return ciphertext ct₁ := (LEnc*.*ct*,*LHE*.*ct₁) and state st₁. *w w w′* <u>Enc₂(l₂) → ct₂,st₂</u>: Encode messages l₂ *∈ M* = Z*p*as a vector bl₂ = Encode(l₂) *∈ Rp*. In *w′* addition, sample noise eLEnc*←*$ *χ* LEnc (recall that LEnc-security only holds as long as its leakage is hidden by noise sampled from *χ*LEnc). Then, encrypt bl₂ *· ∆* + eLEncusing the *non-reusable* LHE component.

LHE*.*ct₂*,*st₂ *←* LHE*.*Enc₂(bl₂ *· ∆* + eLEnc)

Return ciphertext ct₂ := LHE*.*ct₂ and state st₂. <u>KeyGen(st₁,st₂,y) → sky</u>: Encode selection vector y *∈{*0*,*1*}* *w* *⊆* Z *w* *p*as a vector yb = Encode(y) *∈* *w′* *Rp*. Then, compute the digest *d*yb*←* LEnc*.*Digest(yb), and return the LHE secret key sky*←* LHE*.*KeyGen(st₁*,*st₂*,d*yb). <u>Dec(sky,ct₁,ct₂,y) → ly</u>: As in KeyGen, encode selection vector y *∈{*0*,*1*}* *w* as yb = Encode(y) *∈* *w′* *Rp*and compute its digest *d*yb*←* LEnc*.*Digest(yb). Parse ct₁ = (LEnc*.*ct*,*LHE*.*ct₁), ct₂ = LHE*.*ct₂. To decrypt, first evaluate the LHE to obtain res *′* :

|||res ← LHE.Dec(sk||, LHE.ct₁, LHE.ct₂,d||)|
|---|---|---|---|---|---|---|
|||′||y||y b|
|||′|||||
||||y b||||

*//* s.t. res = r *· d* + bl₂ *· ∆* + noise

Now we will evaluate the laconic encryption to obtain r *· d*yb*−* (bl₁ *⊙* yb) *· ∆* (plus noise). Subtracting this from res *′* yields the encoding res of the desired message l₁ *⊙* y + l₂:

res := res *′* *−* LEnc*.*Eval(LEnc*.*ct*,* yb)

*//* s.t. res = (bl₁ *⊙* yb) *· ∆* + bl₂ *· ∆* + noise

Finally, return the decoded result Encode *−*1 (*⌊* <u>res</u> *∆* *⌉*).

We defer proving correctness and *T*-times simulation security (which holds when both LHE and LEnc are *T*-times simulation secure) to AppendixD. Our construction above works over message space Z*p*, where *p* depends on Ring-LWE param- eters. However, in our garbling application, we require a message space of size at least 2 *λ* (so that messages may hold input labels). To handle this even with small Ring-LWE modulus, we may easily turn our construction into a batch-select scheme with message space Z *ℓp* (s.t. *p* *ℓ* *≥* 2 *λ* ) by splitting each message across *ℓ* slots. Then, by combining this with underlying LEnc and LHE (Lemmas5and6), we can e.g. construct a batch-select scheme with the following parameters (proven in AppendixD.2):

Theorem 3(Batch-Select). *Assume* LWE*R,∞,q,D* *R,q*0*.*1 *holds (for a cyclotomic ring R of degree* *n ≥ λ that is a power-of-2, modulus q ≥ n¹⁵ with q ≥* 2 60 *of length* log*q* = *O*(*λ*)*, and modulus-* *to-noise ratio q⁰*

*.*9 *). Furthermore, suppose modulus q is a composite number q* = *p · ∆ for some*
*plaintext modulus p ≤ q¹* */*4 *(with p* = *q* *Θ*(1) *) that is an “NTT friendly” prime, i.e., n divides* (*p−*1)*.* *Then, there exists a batch-select scheme with message space M* := Z *ℓp* *of size |M|≥* 2 *λ* *that is* *√λ* *q-times* 2*-simulation secure. When encrypting w-dimensional messages (with w ≥ Ω*(*n*)*), the* *scheme’s components have size*

*|*pp*|* = *O*(*w · λ*)*, |*ct₁*|* = *O*(*w*log *w · λ*)*, |*ct₂*|* = *O*(*w · λ*)*, |*sky*|* = poly(*λ*)*,*

*and its algorithms run in time (in terms of ring multiplication operations):*

*w*log*w w w w*log*w* Enc₁ : *O,* Enc₂ : *O,* KeyGen : *O,* Dec : *O.* *n n n n* *√* <u>q</u> *A* weak *batch-select scheme with* *w* *-times* 2 *λ* *-simulation security can be constructed under* *the same parameters. Then, ciphertext* ct₁ *has only size |*ct₁*|* = *O*(*w · λ*)*, and the* Enc₁ *algorithm* *only requires O*( <u>w</u> *n* ) *ring multiplications.* *The latter also implies a weak batch-select scheme with* 1*-time* 2 *λ* *-simulation security whenever* *q ≥ ω*((*wλ*) 2 )*, where the size of* ct₁ *reduces to |*ct₁*|* = *o*(*w*)*.*

4.4 Sending encryptions of random strings with a random oracle We now present an optimization that only allows constructing a *random* batch-select scheme in the ROM. For this construction, we cannot use LHE as a black-box anymore. Instead, we need to look inside LHE*.*Enc₂, to revisit the way this algorithm is encrypting the messages bl₂ *· ∆* + eLEnc.
*w* Denote by a the public parameters used inside LHE, and by *s₂* and e *← DR,s*the secrets and noises sampled inside LHE*.*Enc₂. Then, the ciphertext LHE*.*ct₂ will have the form

LHE*.*ct₂ = a <u>· s₂ +</u> e<u>LEnc+</u> e + bl₂ *· ∆* | {z} c

However, regardless of the exact way this ciphertext is generated, we note that for the batch- select output to be correct it already suffices if LHE*.*ct₂ = a *· s₂* + bl₂ *· ∆* + e for *some* error e with *∥*e*∥∞*+ *B*LEnc+ (*B*LHE*−* max*DR,s*) *< ∆/*2*.* (2)

This is because the result res computed by the batch-select decryptor Dec will be bl₂ <u>·</u> *∆* + e + LEnc-noise + LHE-noise (note that we do not need to accomodate for the *≤* max*DR,s*noise resulting from e as it is already included in LHE*.*ct₂; hence LHE evaluation contributes at most another *B*LHE*−* max*DR,s*noise). Modifying batch-select. Our idea to reduce the size of LHE*.*ct₂ is to reverse the order of sampling. Instead of calculating LHE*.*ct₂ based on a random message bl₂, we sample some LHE*.*ct *∗* 2 using the random oracle *H* (with image Z*q*), and reversely determine bl₂. We replace Sel*.*Enc₂ by the following process (note that it does not take any input except pp, since we are constructing a *random* batch-select scheme): *w′*

(1)As before, sample noise eLEnc*← χ*
LEnc (used to hide the noise leakage resulting from LEnc *w′* evaluation). Further sample LHE secret *s₂ ←*$ *Rq*and noise e *← DR*<u>,s</u>(this was previously done inside LHE*.*Enc₂). Use these values to compute c := a *· s₂* + e + eLEnc(where a are the LHE public parameters). In addition, sample an RO-seed seed *←*$ *{*0*,*1*}* *λ*.

(2)We now sample the ciphertext LHE*.*ct
*∗* 2in the following way (where we abuse notation to *w′* denote by z[*i,j*] *∈* Z*q*the *j*-th coefficient of the *i*-th entry in a vector z *∈ Rq*of ring elements): for all indices *i ∈* [*w* *′*] and *j ∈* [*n*], find the smallest integer *di,j∈* N s.t.

*∥H*(seed*,i,j,di,j*) *−* c[*i,j*] mod *∆∥∞*+ *B*LEnc+ *B*LHE+ max*χ*LEnc*< ∆/*2*.* (3)

*(We can view this step as a form of rejection sampling: we continue increasing di,j*= 0 *until* *it reaches a value for which the sampled value has sufficiently small error.)* Choose LHE*.*ct *∗* 2 [*i,j*] := *H*(seed*,i,j,di,j*).

(3)Finally, we reversely compute messages bl₂ from LHE*.*ct
*∗* 2by computing

<u>LHE.ct</u> *∗* <u>− c</u> *′* bl₂ =<u>2</u>*∈Rw.* (4) *∆* *p*

(4)Return ciphertext ct₂ := (seed*,* (*di,j*)*i∈*[*w′*]*,j∈*[*n*]), labels bl₂, and state st₂ := *s₂*. We modify Sel*.*Dec in the following way:
(1)Before doing anything else, recover the ciphertext LHE*.*ct
*∗* 2given only ct₂ = (seed*,* (*di,j*)*i∈*[*w′*]*,j∈*[*n*]), by computing LHE*.*ct *∗* 2 [*i,j*] := *H*(seed*,i,j,di,j*).

(2)Then, continue as before. Correctness. We verify that correctness still holds: fix any ciphertext LHE*.*ct
*∗* 2generated by the *w′∗* process above, and denote by e *∈Rq*the unique vector for which LHE*.*ct₂ = a*·s₂*+bl₂*·∆*+e. Note that LHE*.*ct *∗*

|− c − bl₂ · ∆ = (LHE.ct||− c) mod ∆, see Equation4. Furthermore, by Equation3|||||||
|---|---|---|---|---|---|---|---|---|
|2||2|||||||
|∗ 2 LEnc||∞|LEnc|LHE|LEnc||||
|∗ 2||LEnc|∞|∗ 2 LEnc|∞ LEnc|∞ ≤max D R,s|LEnc ≤max χ|∞|

2 *∗* 2 we have *∥*(LHE*.*ct *∗* *−* c) mod *∆∥ < ∆/*2 *− B − B −* max*χ*. By definition of c = a *· s₂* + e + e, we thus get

*∥*e*∥∞*= *∥*LHE*.*ct *−* c *−*bl₂ *· ∆* + e + e *∥ ≤∥*(LHE*.*ct *−* c) mod *∆∥* + *∥*e*∥* + *∥*e <u>∥</u> | {z } | {z} *R,s* LEnc *≤ ∆/ − B −* (*B −* max*D*)*,*

## and therefore Equation2is fulfilled.

Efficiency. Revisiting Equation3, we see that (for fixed *i*, *j*, *di,j*) rejection independently hap- <u>BLEnc+BLHE+maxχLEnc</u> pens with probability *P* := *∆/*2. We can use this together with Chernoff in order P to bound the total number of “rejections” *R* := *i∈*[*w′*]*,j∈*[*n*] *di,j*, i.e., the number of times where Equation3does not hold during encryption, by *R≤O*(*P · w* *′* *n* +*λ²*) with probability 1*−*negl(*λ*). (Whenever the expected number of rejections is *P · w* *′* *n > λ*, then with overwhelming proba- bility, the total number of rejections will be *≤ O*(*P · w* *′*

*n*). Whenever the expected number of
rejections is *P · w* *′* *n ≤ λ*, then with overwhelming probability, the total number of rejections will be *≤ O*(*λ²*).) Assuming *P ≤* <u>1</u> 2, the size of the list (*di,j*)*i∈*[*w′*]*,j∈*[*n*](and therefore also the size of cipher- text *|*ct₂*|*) is roughly 2*w* *′* *n* + poly(*λ*). Alternatively, for small *P* it is more beneficial to express (*di,j*)*i∈*[*w′*]*,j∈*[*n*]within *R ·*log(*w* *′*

*n*) bits (by listing all pairs (*i,j*), potentially including duplicates,
for which a rejection took place). Hence, assuming *w ≥ Ω*(*n*) and therefore *w* *′* *n ≤ O*(*w*), the new size of Sel*.*ct₂ is now (with overwhelming probability)

*|*seed*|* + *|*(*di,j*)*i∈*[*w′*]*,j∈*[*n*]*|≤ λ* + *R ·* log(*w* *′*

*n*) *≤ O*(*P · w* log*w*) + poly(*λ*)
instead of *O*(*w*log*q*). Furthermore, whenever *B*LEnc+ *B*LHE+ max*χ*LEnc*< ∆/*2 *λ*, rejection happens only with probability *P ≤ O*( 2 <u>1</u> *λ*). Thus, we can choose ct₂ to be *completely empty* (as all *di,j*will be 0 with overwhelming probability, and we may insert the *λ*-size seed as a new component into sky) while <u>poly(λ)</u> still maintaining correctness with probability 1 *−* 2 *λ*.

Security. Intuitively, security follows from the fact that rejection happens with *public* probability, and therefore each *di,j*can be simulated easily. However, we additionally need to ensure that all *H*(seed*,i,j,d* *′* ) for *d* *′* *< di,j*are programmed in such a way that Equation3actually fails. We give a formal proof in AppendixD.1. For our construction above, we can e.g. get the following parameter setting when considering a message space *M* = Z *ℓp* with log *|M|* = *ℓ ·* log *p ≥ λ*, proven in AppendixD.2.

Theorem 4(*Random* Batch-Select). *Consider the same assumptions and parameters as in* *√*

||25|ε||
|---|---|---|---|
||||ℓp|
|w ·λ·log q||||
|q|2(1+ε)λ|ε λ|′|

*Theorem3, except that q ≥ n and p* = *Θ*(*q*) *for some ε >* 0*. Then, there exists a q-times* 2 *λ* *-simulation secure* random *batch-select scheme with message space* Z *of size |M|≥* 2 *λ* *in the* *ROM with the same efficiencies as described in Theorem3, except that the ciphertext* ct₂ *has* *only size O*(1*/*2*−ε*) + poly(*λ*)*.* *′ ′* *Furthermore, when q >* 2 *while p* = *Θ*(*q*) *for some ε >* 0*, then there is a batch-select* *scheme with the same properties, except that the size of* ct₂ *is* 0*.*

## 5 Application: Preprocessing Garbling

In this section, we apply our construction of batch-select towards the notion of *preprocessing* *garbling* with succinct function-dependent garbling. We first describe the model in Section5.1 and then our desired primitive in Section5.2. Afterwards, we define some existing building blocks that we require (apart from batch-select) in Section5.3, and give the final construction in Section5.4.

5.1 Computational Model A *preprocessing garbling scheme* will handle computations specified by a *universal* function and a *function* description. For example, a universal function may specify parameters of a Boolean circuit such as input and output lengths as well as circuit size, while the function description may specify the gate types and how they are connected. We formalize this model of computation as a family *U* = *{Uℓ*x*,ℓ*y*}ℓ*x*,ℓ*y*∈*Nof classes of *universal* functions *U ∈Uℓ*x*,ℓ*ywith the format
*U* : *FU×{*0*,*1*}* *ℓ* x *→{*0*,*1*}* *ℓ* y *,*

where *f ∈FU*is the *function* description. The two components *U,f* together with an input bit string x *∈{*0*,*1*}* *ℓ* xdetermine the output y = *U* (*f,* x). Our preprocessing garbling construction

will take as input the universal function *U* in as a Boolean circuit, and *f ∈FU*, a string. In the case where *U* is a universal function capable of handling any function *f* that is specified by a binary circuit, we may use the following result from prior work, which shows that there exists efficient universal circuits.

Lemma 7([ZYZL19]). *There is a Boolean circuit CUof size* 17*.*75*n*log *n (with* 4*.*5*n*log *n AND* *gates) that takes a function description f* : *{*0*,*1*}* *ℓ* x*→{*0*,*1*}ℓ*y*(represented by a Boolean circuit*

*with at most n gates) and an input* x *∈{*0*,*1*}* *ℓ* x *, and outputs f*(x)*.*

5.2 Definition In the following definition for *preprocessing garbling*, the algorithms RDGen, InputKeyGen, and GarbleU together form the *function-independent offline* phase that only depends on the universal function *U*. The *function-dependent offline* phase corresponds to GarbleFunc, which then takes the function description *f*. The ultimate goal, as achieved by our instantiation, is that the output of GarbleFunc is *succinct*, i.e., its length is independent of that of the function description *f*. Definition 14(Preprocessing Garbling). *Let U* = *{Uℓ*x*,ℓ*y*} be a class of computation, where* *each universal function U ∈Uℓ*x*,ℓ*y*has a signature U* : *FU×{*0*,*1*}*
*ℓ* x*→{*0*,*1*}ℓ*y*. A preprocessing*

*garbling scheme (with reusability) for U consists of five efficient algorithms, and is associated* *with a key space K*(*λ*)*, which is an abelian group with size |K*(*λ*)*|≥* 2 *λ* *.*

– RDGen(*U*) *takes the universal function U and outputs the reusable part U*brd*of the function-* *independent garbling, together with a reusable state* strd*.* – InputKeyGen(1 *λ* *,*1 *ℓ* x ) *takes an input length ℓ*x*, and returns input keys* K *∈K* *ℓ* x *×*2 *.* – GarbleU(strd*,*K) *takes the reusable state* strd*, and the input keys* K*. It outputs the non-reusable* *part U*b *of the function-independent garbling, and state* st*.* – GarbleFunc(st*,f ∈FU*) *takes the state* st*, a function description f, and outputs a* hint*, i.e.,* *the function-dependent garbling. We refer to* (*U*brd*, U,*b hint) *as the garbling of* (*U,f*)*.* – Eval(*f, U*brd*, U,*b hint*,* kx*∈K* *ℓ* x ) *takes a function description f, the garbling* (*U*brd*, U,*b hint)*, and* *input labels* kx*, and outputs the computation result* y *∈{*0*,*1*}* *ℓ* y *.*

*Correctness. The scheme is correct if for all λ,ℓ*x*,ℓ*y*∈* N*, universal functions U ∈Uℓ*x*,ℓ*y*and* *function descriptions f ∈FU, input keys* K *∈K* *ℓ* x *×*2 *, and inputs* x *∈{*0*,*1*}* *ℓ* x *, the following holds:*   b b (*U*brd*,*strd) *←* RDGen(*U*) Eval(*f, U*rd*, U,* hint*,*K[x]) Pr  (*U,*b st) *←* GarbleU(strd*,*K)  = 1*.* = *U* (*f,* x) hint *←* GarbleFunc(st*,f*)

Definition 15(*T*-times Input Privacy). *The scheme fulfills T -times input privacy if there* *exists an efficient simulator* SimPriv*s.t. for any efficient adversary A,*

*A,*0 *A,*1 Pr[Exp Priv

(*λ*) = 1] *−* Pr[Exp
Priv

(*λ*) = 1] *≤* negl(*λ*)*,*
*A,b* *where the game* Exp Priv

(*λ*) *is defined below.*
*1. A*(1 *λ* ) *selects* 1
*ℓ* x *,*1 *ℓ* y *, a universal function U ∈Uℓ*x*,ℓ*y*, and T function descriptions f*

(*t*) *∈FU,*
*and inputs* x

(*t*) *∈{*0*,*1*}*
*ℓ* x *, for t ∈* [*T*]*.*

*2.The game sends to A the reusable garbling U*brd*and the T individual garblings with their input* b(*t*) (*t*) (*t*) *keys {U,*hint*,* kx*}t∈*[*T*]*, computed as follows.* – *If b* = 0*, first run* (*U*brd*,*strd) *←* RDGen(*U*)*. Then for t ∈* [*T*] *run*
K

(*t*) *←* InputKeyGen(1
*λ* *,*1 *ℓ* x )*,*

(*U*b

(*t*) *,*st
(*t*) ) *←* GarbleU(strd*,* K
(*t*) )*,* hint
(*t*) *←* GarbleFunc(st
(*t*) *,f*
(*t*) )
(*t*) (*t*)
*Finally, set* kx= K [x]*.*

(*t*) (*t*) (*t*) (*t*) (*t*) (*t*)

||b|b||||||
|---|---|---|---|---|---|---|---|
||rd|(t)|(t) (xt)|Priv|(t)|(t) (t)|t∈[T]|
||′|||||||

– *If b* = 1*, run* (*U, {U,*hint*,* kx*}*) *←* Sim (*U, {f,U*(*f,* x)*}*)*.*

*3. A outputs a bit b, which is also the output of the game.*
5.3 Ingredients Standard Model Garbling. Traditional garbling (i.e., the standard model in which there is no separation between universal function and function description) may be seen as a special case of preprocessing garbling. It will be required for our construction of preprocessing garbling. Definition 16(Standard Model Garbling). *Let C* = *{Cℓ*x*,ℓ*y*}ℓ*x*,ℓ*y*∈*N*be the family of functions* *that do not take any function description, i.e., Cℓ*x*,ℓ*y*consists of all two-input functions C* : *∅×{*0*,*1*}* *ℓ* x*→{*0*,*1*}ℓ*y*, specified by their Boolean circuit representation.* *For this class, a corresponding garbling scheme (which we denote by* SG*, “standard garbling”)* *without support for preprocessing or reusability has the following simplified syntax, where* RDGen *and* GarbleFunc *are not needed anymore, and* GarbleU *is renamed to* Garble*.* – SG*.*InputKeyGen(1
*λ* *,*1 *ℓ* x ) *takes an input length ℓ*x*, and returns input keys* K *∈K* *ℓ* x *×*2 *.* – SG*.*Garble(*C,* K) *takes the circuit C and the input keys* K*, and outputs the garbling C*b*.* – SG*.*Eval(*C, C,*b kx*∈K* *ℓ* x ) *takes the circuit C, its garbling C*b *and input labels* kx*, and outputs* *the computation result* y *∈{*0*,*1*}* *ℓ* y *.*

*Further, we require that* SG*.*InputKeyGen(1 *λ* *,*1 *ℓ* x ) *samples each of the ℓ*x*input key pairs individ-* *ually, i.e., its implementation only consists of running* (K[0*,i*]*,*K[1*,i*]) *←* InputKeyGen *′* (1 *λ* ) *for* *some algorithm* InputKeyGen *′* *.* *Because we do not require reusability for the standard garbling scheme* SG*, we use the term* input privacy *to denote* 1-time input privacy *(Definition15).*

Garbling schemes in the standard model as above are known to exist, with the current state- of-the-art producing a garbling whose size is 1*.*5*λ* times the number of AND gates.

Lemma 8([RR21]). *There is a standard model garbling scheme* SG *(with global key offsets),* *with garblings of size |C*b*|* = (1*. λ* + 10)*n bits, where n denotes the number of AND gates in the* *circuit C.*

Correlation-robust hash functions In our construction of preprocessing garbling, we will need to translate the output of a batch-select scheme (which is in *M*, or concretely *M* = Z *ℓp* for our instantiation in Section4.3) into keys in *K* for the input wires of a circuit *CU*garbled using a standard garbling scheme SG. We do so by hiding a key in *K* using a hash function *H* : *M→K* applied to the corresponding batch-select output that is in *M*. Furthermore, whenever our garbling scheme is reused (*T >* 1), we will need to ensure that *H* is correlation-robust in the following sense.

Definition 17(Correlation-robust hash function). *A hash function H* : *M→K (where M* *and K are parameterized by the security parameter λ) is* correlation-robust*, if for any polynomial* *T* (*λ*) *and efficient adversaries A, the following holds (where we suppress λ):*

Pr[*A*(*{*l

(*t*) *,H*(l
(*t*) *− ∆*)*,H*(l
(*t*) + *∆*)*}t∈*[*T*]) = 1 *| ∆,*l
(1) *,...,*l
(*T*) *←*$ *M*] *−*
"

(1) (*T*)
#

||||l ,..., l|← M,||
|---|---|---|---|---|---|
|(t) λ|(t) (t) − +|t∈[T]|(1) −|(T ) (1) − +|(T ) + $|

(*t*) (*t*) (*t*)
$ Pr *A*(*{*l*,* u*,* u*}t∈*[*T*]) = 1 *≤* negl(*λ*)
u*,...,*u*,* u*,...,*u *← K*

Due to *|M|≥* 2, the correlation-robust hash function *H* can be instantiated using a random oracle. Also note that it is a *weaker notion* of the type of circular correlation-robustness that is already utilized by many existing garbling schemes involving e.g. the free-XOR optimiza- tion [KS08].

5.4 Construction We will construct a preprocessing garbling scheme for any computation class *U*, s.t. for any universal function *U*x y

|∈U, there is a universal circuit C||that takes a function description|
|---|---|---|
|ℓ ,ℓ|U|U ℓ|
||ℓp||
 *f ∈FU*whose bit-length is bounded by some *s*, an input x *∈{*0*,*1*}*x, and outputs *U* (*f,* x). For our construction, we assume a standard garbling scheme SG with key space *K* and a batch-select with message space *M* = Z. Further, we assume a correlation-robust hash function *H* : *M→K*.
## Construction 4(Preprocessing Garbling).

<u>RDGen(U) → Ubrd,strd</u>: *(This algorithm creates reusable data, which can be used again for subse-* *quent garbling sessions.)* First setup the batch-select Sel scheme with dimension *sU*, where *sU*is the description length of functions in *FU*: Sel*.*pp *←* Sel*.*Setup(1 *λ* *,*1 *s* *U* )*.*

Next, sample the first message vector l₁, and encrypt it using Sel*.*Enc₁:

l₁ *←*$ *M* *s* *U* *,* (Sel*.*ct₁*,*Sel*.*st₁) *←* Sel*.*Enc₁(l₁)*.*

Output the reusable part of the garbling *U*brd= (Sel*.*pp*,*Sel*.*ct₁), and the reusable state strd= (Sel*.*pp*,*Sel*.*st₁*,*l₁). <u>InputKeyGen(1</u> *λ* <u>,</u> *ℓ* x <u>) → K</u>: Output input keys K *←* SG*.*InputKeyGen(1 *λ* *,* *ℓ* x ).

|rd||Fn||
|---|---|---|---|
|U||||
|U||||
|Fn|λ s|U|U Fn|

<u>GarbleU(st,K) → U,b st</u>: First, sample the input keys K for the input wires of the universal circuit *C* that correspond to the function description, and use this to garble the universal circuit *C* :

K *←* SG*.*InputKeyGen(1*,*1 *U* )*, C*b *←* SG*.*Garble(*C,*(K*,*K))*.*

Next, sample the second message vector l₂, and encrypt it using Sel*.*Enc₂:

|M|, (Sel.ct₂, Sel.st₂) ← Sel.Enc₂(l₂).||||
|---|---|---|---|---|
|||′0,i|′1,i||
|′0,i||Fn|||
|′1,i||U|Fn ′0,i|′1,i|
||s||||
|Fn|||||

l₂ *←*$ *s* *U*

Then, for each *i ∈* [*sU*], produce the ciphertexts ct and ct that the evaluator will use to translate the batch-select output f [*i*] *·* l₁[*i*] + l₂[*i*] into the correct key K Fn [*i,* f [*i*]]:

## ct := H(l₂[i]) + K [i,0]

ct := *H*(l₁[*i*] + l₂[*i*]) + K [*i,*1]

Output function-independent garbling *U*b = (*C*b*,*Sel*.*ct₂*, {*ct*,*ct*}*), and the state st = (Sel*.*pp*,*Sel*.*st₁*,*Sel*.*st₂). <u>GarbleFunc(st,f) → hint</u>: Let f *∈{*0*,*1*}U*denote the bit representation of *f*. Output a batch- select secret key for selecting K [f]:

## hint = skf← Sel.KeyGen(Sel.st₁,Sel.st₂,f).

<u>Eval(f, Ubrd, U,b hint, kx) → y</u>: Parse the function-independent garbling as *U*brd= (Sel*.*pp*,*Sel*.*ct₁)

and *U*b = (*C*b*U,*Sel*.*ct₂*, {ct* *′* 0*,i* *,*ct *′* 1*,i* *}*). Let f *∈{*0*,*1*}* *s* *U*denote the bit representation of *f*.

First decrypt the batch-select ciphertexts to recover the messages lresselected by f :

l res*←* Sel*.*Dec(skf*,*Sel*.*ct₁*,*Sel*.*ct₂*,*f)*,* // s.t. lres= l₁ *⊙* f + l₂

Then, translate these messages into the appropriate input keys k Fn f by computing, for each *i ∈* [*sU*]:

k Fn f[*i*] := ct *′* f [*i*]*,i* *− H*(lres[*i*])*,*

// s.t. k Fn f[*i*] = K Fn [*i,* f [*i*]]*.*

Then evaluate the garbled universal circuit as y *←* SG*.*Eval(*C*b*U,*(k Fn f *,* kx)), and output y.

Correctness and security. Correctness follows straightforwardly from that of the standard model garbling scheme SG and that of the batch-select scheme Sel. We state security formally below, and defer the proof to AppendixE.

Lemma 9. *Assuming the standard garbling scheme* SG *satisfies input privacy, the batch-select* *scheme* Sel *satisfies T -times simulation security (Definition6), and the hash function H is* *correlation-robust (Definition17), the preprocessing garbling scheme in Construction4fulfills* *T -times input privacy (Definition15).*

Efficiency. With our instantiation of batch-select, the function-dependent phase (consisting only of sending skf) is succinct: The hint = skfconsists of a single ring element in *Rq*. The cost of *U*b essentially corresponds to the cost for garbling a universal circuit *C*b*U*(e.g. *|C*b*U|* = *λ · n*log*n* to support arbitrary Boolean circuits with at most *n* gates; see Lemmas7and8). The *reusable* part *U* b rdmay have size *O*(*λ · n*log² *n*), but one factor of log*n* can be avoided by using our optimized batch-select constructions (i.e., reusability or *weak* batch-select).

Note regarding Key Translation. The reason for including key translation ciphertexts ct *′* 0*,i* *,*ct *′* 1*,i* is the potential mismatch between the batch-select message space *M* = Z *ℓp*, and the SG key space *K* (which is typically of the form *{*0*,*1*}* *λ* ). If those two were equal (many existing garbling schemes could theoretically work with any sufficiently large key space, potentially at the cost of not sup- porting free-XOR anymore), then we may omit key translation ciphertexts. Orthogonally, if no reusability is needed (*T* = 1), we could also directly choose messages l₁ := *ϕ*(K Fn [1] *−* K Fn [0]) and l₂ := *ϕ*(K Fn [0]) for any injective embedding *ϕ* : *K→M*, avoiding key translation completely despite *K̸*= *M*.

## 6 Evaluation

To demonstrate concrete efficiency, we have implemented our batch-select scheme⁶ (Construc- tion3). Here, our primary focus is *computational efficiency* instead of optimal (near-0) offline communication cost that would requires exponential modulus (as described e.g. in Theorem3). Nevertheless, our (amortized) offline cost will be just *≈* 6 bits per 128-bit value transferred to a receiver.

Parameter Setting. We consider the ring *Rq*= Z*q*[*X*]*/*(*X⁴⁰⁹⁶* + 1) of degree *n* = 4096, and as required by our batch-select scheme, we choose the modulus *q* = *p · ∆* as a product of two primes *p,∆*. In order to be able to perform efficient computations, we choose the moduli *p* and *∆* as two different NTT-friendly primes (i.e., *p ≡ ∆ ≡* 1 mod 8192). Using the Chinese Remainder Theorem, this allows us to represent an element of the ring *Rq*as one *Rp*-element and one *R∆*- element. Multiplication and addition over *Rq*can then be performed separately over *Rp*and *R∆*. We choose *p* as a 50-bit prime (then, three elements of the plaintext space Z*p*will be enough to store one 128-bit key for our garbling application), and *∆* as a 59-bit prime (this is the maximum bitlength supported by the SEAL framework [SEA23] we build upon). For concreteness, suppose we apply Sel to vectors of *w* *′* = 512 ring elements, i.e., vectors of *′* 21 <u>2</u> 21 *w* = *w ·n* = 512*·n* = 2 elements in the message space *M* = Z*p*. This means that *⌊* 3 *⌋* = 699 050 elements in Z³*p*are supported. (Recall that we are interested in Z³*p*, because its size is larger than 2 *λ*, and hence we can encrypt 128-bit input labels in it.) We are now aiming to provide *λ* = 128-bit security. As recommended by the homomorphic encryption standard [ACC + 19], given the degree-4096 ring *Rq*(with log *q ≤* 111) we assume that the Ring-LWE assumption *√* LWE*R,∞,q,χ∗* holds with Gaussian noise of standard deviation *σ* *∗* = 8*/* 2*π ≈* 3*.*2, i.e., with error distribution *χ* *∗* = *DR,s∗* of parameter *s* *∗* = 8. Note that the security of LEnc and LHE (as invoked by our *T*-reusable batch-select scheme) *×′* relies on the elLWE assumption with two different types of leakage sets: *LT,*2*m*(*g*) and *L₁* *,w*1

(*g*).
To ensure that this follows from our assumption LWE*R,∞,q,χ∗*, we combine Theorem2with Lemmas3and4. It guarantees that it suffices to choose parameters *s* and *s* as follows, where *s* is used for distributions *χ* = *DR,s*inside both LHE and LEnc, and *s* is used for both distributions

The source code can be found under https://github.com/MarianDietz/tinylabels.

*χ*LEnc= *DR,s*(used to hide LEnc noise leakage) and *χ* = *DR,s*(used inside LHE):

*√* *s* = 2*s* *∗* + 1 + *ηϵ*(*R*) and *s* = (*s* + 1) *· g · n ·* 2*m · T .*

In the above, there are some tunable parameters: *m* (used inside our LHE and LEnc constructions, where the gadget vector is determined through its *base g* and *dimension m* with *g* *m* *< q*) affects the ciphertext size and therefore the amount of communication, and *T* denotes how often ct₁ may be reused. We can freely choose these parameters, as long as correctness is guaranteed, *√*

i.e., *∆ ≥* 2 *λ*(*g · m · d · s ·*(*⌈*log₂ *w*
*′* *⌉*+ 1) + 2*s*) still holds given the choices of *s* and *s* above. For our evaluation, we choose

*T* = 2 15 = 32 768 and *m* = 4*,*

and therefore also *g* = 2 28.

Communication. A single ring element can be represented with 56 KB (4096 coefficients with 109 bits each). Therefore, our basic batch-select construction (without RO-optimization) achieves the following efficiencies:

– Public parameters pp: *w* *′* + 2*m* ring elements (*≈* 29 MB) – Reusable ciphertext ct₁: *m · w* *′* + 2*m · w* *′* *⌈*log₂ *w* *′* *⌉* ring elements (*≈* 2*.*2 GB, or when amortized over *T* = 2 15 iterations: 67 KB) – Non-reusable ciphertext ct₂: *w* *′* ring elements (*≈* 29 MB) – Key sky: 1 ring element (*≈* 56 KB)

The following two optimizations regarding *communication size* may be applied:

– *Weak* laconic encryption would reduce the size of ct₁ to *m · w* *′* + 4*m · w* *′* ring elements (*≈* 571 MB instead of *≈* 2*.*2 *√* GB). However, this would simultaneously require the noise *s* to increase by another factor of *w* *′*; hence reducing the maximum number *T* of uses for ct₁ by a factor of *w* *′* = 512 (i.e., *T ≤* 2 6 ). – The RO optimization (see Section4.4) allows reducing the size of ct₂: Instead of sending *w* *′*

ring elements, it suffices to send a *λ*-bit seed, plus 2*w* *′* *n* = 2*w* rejection sampling-bits. This reduces the size of ct₂ to just *≈* 524 KB in our setting. Combining this with amortization over *T* = 2 15 iterations, the *total communication cost* per iteration, *|*ct₁*|/T* + *|*ct₂*|*, will be only 591 KB (i.e., only *≈* 6*.*4 bits per transferred element in Z³*p*).

Computation optimizations. Note that naive multiplication of two polynomials stored in coefficient form is very expensive: first, both polynomials need to be converted to NTT form, then they are multiplied component-wise, and then another inverse-NTT needs to be performed. To optimize this, our implementation keeps all polynomials in NTT form whenever possible. Then, each multiplication requires only one component-wise multiplication. NTT transformations are now only required when generating or removing noise, or when *w′w′* converting the LEnc database from a *∈Rp*to the larger modulus *Rq*. In addition—this is the dominating use of NTT transformations in the input-dependent phase consisting of Sel*.*KeyGen and Sel*.*Dec—computing the hash-tree inside LEnc*.*Digest requires 4*mw* *′* forward-NTT and 2*w* *′*

inverse-NTT.

Hardware setup. We implemented our batch-select scheme on top of the SEAL library [SEA23] (which allows us to utilize existing implementations of ring operations), and tested it on a server

|||Reusable||One-time Input-dependent|||
|---|---|---|---|---|---|---|
|||Setup|Enc₁|Enc₂ KeyGen||Dec|
|Conjectured time||0. 13|s 14. 93 s|0. 17 s|0. 44 s|0. 71 s|
|Time||0. 13|s 16. 65 s|0. 25 s|0. 63 s|1. 24 s|
|Time / msg||0. 18 µs|23. 83 µs|0. 35 µs|0. 90 µs 1|. 77 µs|
||15||||||
|Time ( T|= 2 )|3. 8 µs pp|0. 0005 s ct₁|" ct₂|" sk y|" n/a|
|Size||29MB|2. 2GB|29MB|56KB||
|Size / msg||42 byte|3. 1KB|41 byte 0. 08 byte|||
||15||||||
|Size ( T|= 2 )|885 byte|67KB|"|"||
||15||||||
|Size / msg (|T = 2 )|< 0. 01 byte|0. 1 byte|"|"||
|Size w/ RO opt.||||524 KB|||
|Size / msg w/ RO opt.||||0. 75 byte|||

Table 4: This table shows the amount of time spent within each of the algorithms of our batch-

select scheme, and the size of their outputs. All *time* rows (except the first one) show the actual times required by our implementation, where *per msg* is the time required on average by each of the *w* = 699 050 messages (i.e., input labels) encrypted by the batch-select scheme, and *T* = 2 15

indicates that we amortize the reusable parts across 2 15 iterations. The first row shows the computation time that we conjecture for a CPU that has AVX512-IFMA52 instructions. These numbers are estimated using the benchmarks from [BKS + 21], where one multiplication requires

1*.*08*µs*, one forward NTT requires 5*.*81*µs*, and one inverse NTT requires 5*.*72*µs*. with an Intel Xeon Platinum 8160M Processor, 2.10GHz. The implementation utilizes only a single core. We achieve an additional speedup using the Intel HEXL framework [BKS
+ 21], which utilizes the Intel AVX512 instruction set. However, the server we tested on only supports AVX512-DQ instructions, and therefore we can expect that a CPU with the AVX512-IFMA52 instruction set would be able to improve the computation time of NTT operations by another factor of 3.

Evaluation results. Table4displays the amount of computation time and the communication size on the discussed parameters (while our implementation does not directly support the RO- optimization, we do not expect the running time of Enc₂ to increase significantly when it generates its output from RO). In Table5, we further split the computation time to demonstrate which operations are causing the highest cost. Putting these results into context, suppose the batch-select scheme is used for transmitting input keys (of bitlength *λ* = 128) for a garbled circuit. Naively sending input labels without batch-select requires sending more than 11 MB in the online phase. On the other hand, batch- select allows a tradeoff: only 56 KB need to be sent (once the input is known), in exchange for

1*.*87*s* of computation time. Thus, our scheme could outperform the naive baseline whenever the bandwidth is limited by about 45 Mbps. Also note that our scheme allows for parallelization (because most computation happens independently for each of the *w*
*′* = 512 components). For example, when using 8 cores instead of 1 core, computation time in the input-dependent phase could be as small as 0*. s*, outperforming the naive baseline whenever the bandwidth is limited by 350 Mbps.

Add. (per msg) Mult. (per msg) NTT (per msg) CRT (per msg)

Setup 0 0 0 0 Enc₁ 0*.*46*s* (0*.*66*µs*) 0*.*79*s* (1*.*13*µs*) 1*.*30*s* (1*.*86*µs*) 0 118 784 (0*.*17) 77 824 (0*.*11) 77 824 (0*.*11) Enc₂ 0*.*01*s* (0*.*01*µs*) 0*.*01*s* (0*.*02*µs*) 0*.*03*s* (0*.*04*µs*) 0 3072 (0*.*004) 1024 (0*.*001) 2024 (0*.*003) KeyGen 0*.*01*s* (0*.*01*µs*) 0*.*05*s* (0*.*07*µs*) 0*.*17*s* (0*.*24*µs*) 0*.*28*s* (0*.*40*µs*) 8184 (0*.*01) 8184 (0*.*01) 11 254 (0*.*02) 4092 (0*.*01) Dec 0*.*09*s* (0*.*125*µs*) 0*.*56*s* (0*.*801*µs*) 0*.*20*s* (0*.*288*µs*) 0*.*28*s* (0*.*396*µs*) 97 776 (0*.*14) 87 024 (0*.*12) 12 278 (0*.*02) 4092 (0*.*01)

Table 5: For each function of our batch-select scheme, this table shows the computation time and

the number of invocations required by our implementation (in parentheses the time and number required on average for each of the *w* = 699 050 messages), for the most time-intensive compo- nents: (1) the number of polynomial additions (also including subtractions), (2) the number of component-wise multiplications in NTT form, (3) the number of NTT transformations (includ- ing both forward and inverse transformations), and (4) the number of CRT decompositions (the number of CRT compositions, ommitted from the table, is lower by a factor of *m*). In Enc₁, the majority of time is spent on generating noise polynomials.

Acknowledgments. The authors were supported by NSF grant CNS-2026774, and a Simons Collaboration on the Theory of Algorithmic Fairness.

References

ABI +

23.Benny Applebaum, Amos Beimel, Yuval Ishai, Eyal Kushilevitz, Tianren Liu, and Vinod Vaikun- tanathan. Succinct computational secret sharing. In Barna Saha and Rocco A. Servedio, editors, *55th* *ACM STOC*, pages 1553–1566. ACM Press, June 2023.
ACC +

19.Martin Albrecht, Melissa Chase, Hao Chen, Jintai Ding, Shafi Goldwasser, Sergey Gorbunov, Shai Halevi, Jeffrey Hoffstein, Kim Laine, Kristin Lauter, Satya Lokam, Daniele Micciancio, Dustin Moody, Travis Morrison, Amit Sahai, and Vinod Vaikuntanathan. Homomorphic encryption standard. Cryp- tology ePrint Archive, Report 2019/939, 2019.
ADOS22.Damiano Abram, Ivan Damgård, Claudio Orlandi, and Peter Scholl. An algebraic framework for silent preprocessing with trustless setup and active security. In Yevgeniy Dodis and Thomas Shrimpton, editors, *CRYPTO 2022, Part IV*, volume 13510 of *LNCS*, pages 421–452. Springer, Cham, August

2022.
AIKW13.Benny Applebaum, Yuval Ishai, Eyal Kushilevitz, and Brent Waters. Encoding functions with constant online rate or how to compress garbled circuits keys. In Ran Canetti and Juan A. Garay, editors, *CRYPTO 2013, Part II*, volume 8043 of *LNCS*, pages 166–184. Springer, Berlin, Heidelberg, August

2013.
AJS17.Prabhanjan Ananth, Abhishek Jain, and Amit Sahai. Indistinguishability obfuscation for Turing machines: Constant overhead and amortization. In Jonathan Katz and Hovav Shacham, editors, *CRYPTO 2017, Part II*, volume 10402 of *LNCS*, pages 252–279. Springer, Cham, August 2017. AL21.Martin R. Albrecht and Russell W. F. Lai. Subtractive sets over cyclotomic rings-limits of Schnorr- like arguments over lattices. In Tal Malkin and Chris Peikert, editors, *CRYPTO 2021, Part II*, volume 12826 of *LNCS*, pages 519–548, Virtual Event, August 2021. Springer, Cham. BCG +

18.Nir Bitansky, Ran Canetti, Sanjam Garg, Justin Holmgren, Abhishek Jain, Huijia Lin, Rafael Pass, Sidharth Telang, and Vinod Vaikuntanathan. Indistinguishability obfuscation for RAM programs and succinct randomized encodings. *SIAM J. Comput.*, 47(3):1123–1210, 2018.

+ BCG 19.Elette Boyle, Geoffroy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, and Peter Scholl. Efficient pseu- dorandom correlation generators: Silent OT extension and more. In Alexandra Boldyreva and Daniele Micciancio, editors, *CRYPTO 2019, Part III*, volume 11694 of *LNCS*, pages 489–518. Springer, Cham, August 2019. + BCG 20.Elette Boyle, Geoffroy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, and Peter Scholl. Efficient pseudo- random correlation generators from ring-LPN. In Daniele Micciancio and Thomas Ristenpart, editors, *CRYPTO 2020, Part II*, volume 12171 of *LNCS*, pages 387–416. Springer, Cham, August 2020. BCGI18.Elette Boyle, Geoffroy Couteau, Niv Gilboa, and Yuval Ishai. Compressing vector OLE. In David Lie, Mohammad Mannan, Michael Backes, and XiaoFeng Wang, editors, *ACM CCS 2018*, pages 896–912. ACM Press, October 2018. BCLN16.Joppe W. Bos, Craig Costello, Patrick Longa, and Michael Naehrig. Selecting elliptic curves for cryptography: an efficiency and security analysis. *Journal of Cryptographic Engineering*, 6(4):259– 286, November 2016. BDGM19.Zvika Brakerski, Nico Döttling, Sanjam Garg, and Giulio Malavolta. Leveraging linear decryption: Rate-1 fully-homomorphic encryption and time-lock puzzles. In Dennis Hofheinz and Alon Rosen, editors, *TCC 2019, Part II*, volume 11892 of *LNCS*, pages 407–437. Springer, Cham, December 2019. BGI16.Elette Boyle, Niv Gilboa, and Yuval Ishai. Breaking the circuit size barrier for secure computation under DDH. In Matthew Robshaw and Jonathan Katz, editors, *CRYPTO 2016, Part I*, volume 9814 of *LNCS*, pages 509–539. Springer, Berlin, Heidelberg, August 2016. BGV12.Zvika Brakerski, Craig Gentry, and Vinod Vaikuntanathan. (Leveled) fully homomorphic encryption without bootstrapping. In Shafi Goldwasser, editor, *ITCS 2012*, pages 309–325. ACM, January 2012. BHR12.Mihir Bellare, Viet Tung Hoang, and Phillip Rogaway. Foundations of garbled circuits. In Ting Yu, George Danezis, and Virgil D. Gligor, editors, *ACM CCS 2012*, pages 784–796. ACM Press, October

2012.
BKS19.Elette Boyle, Lisa Kohl, and Peter Scholl. Homomorphic secret sharing from lattices without FHE. In Yuval Ishai and Vincent Rijmen, editors, *EUROCRYPT 2019, Part II*, volume 11477 of *LNCS*, pages 3–33. Springer, Cham, May 2019. + BKS 21.Fabian Boemer, Sejun Kim, Gelila Seifu, Fillipe D.M. de Souza, and Vinodh Gopal. Intel HEXL: Accelerating homomorphic encryption with intel AVX512-IFMA52. Cryptology ePrint Archive, Report 2021/420, 2021. BMR90.Donald Beaver, Silvio Micali, and Phillip Rogaway. The round complexity of secure protocols (extended abstract). In *22nd ACM STOC*, pages 503–513. ACM Press, May 1990. BV11.Zvika Brakerski and Vinod Vaikuntanathan. Efficient fully homomorphic encryption from (standard) LWE. In Rafail Ostrovsky, editor, *52nd FOCS*, pages 97–106. IEEE Computer Society Press, October

2011.
Can01.Ran Canetti. Universally composable security: A new paradigm for cryptographic protocols. In *42nd* *FOCS*, pages 136–145. IEEE Computer Society Press, October 2001. CKKZ12.Seung Geol Choi, Jonathan Katz, Ranjit Kumaresan, and Hong-Sheng Zhou. On the security of the “free-XOR” technique. In Ronald Cramer, editor, *TCC 2012*, volume 7194 of *LNCS*, pages 39–53. Springer, Berlin, Heidelberg, March 2012. CM21.Geoffroy Couteau and Pierre Meyer. Breaking the circuit size barrier for secure computation un- der quasi-polynomial LPN. In Anne Canteaut and François-Xavier Standaert, editors, *EURO-* *CRYPT 2021, Part II*, volume 12697 of *LNCS*, pages 842–870. Springer, Cham, October 2021. Cou19.Geoffroy Couteau. A note on the communication complexity of multiparty computation in the corre- lated randomness model. In Yuval Ishai and Vincent Rijmen, editors, *EUROCRYPT 2019, Part II*, volume 11477 of *LNCS*, pages 473–503. Springer, Cham, May 2019. CRR21.Geoffroy Couteau, Peter Rindal, and Srinivasan Raghuraman. Silver: Silent VOLE and oblivious transfer from hardness of decoding structured LDPC codes. In Tal Malkin and Chris Peikert, editors, *CRYPTO 2021, Part III*, volume 12827 of *LNCS*, pages 502–534, Virtual Event, August 2021. Springer, Cham. CWYY23.Hongrui Cui, Xiao Wang, Kang Yang, and Yu Yu. Actively secure half-gates with minimum overhead under duplex networks. In Carmit Hazay and Martijn Stam, editors, *EUROCRYPT 2023, Part II*, volume 14005 of *LNCS*, pages 35–67. Springer, Cham, April 2023. DIJL23.Quang Dao, Yuval Ishai, Aayush Jain, and Huijia Lin. Multi-party homomorphic secret sharing and sublinear MPC from sparse LPN. In Helena Handschuh and Anna Lysyanskaya, editors, *Advances* *in Cryptology-CRYPTO 2023 - 43rd Annual International Cryptology Conference, CRYPTO 2023,* *Santa Barbara, CA, USA, August 20-24, 2023, Proceedings, Part II*, volume 14082 of *Lecture Notes* *in Computer Science*, pages 315–348. Springer, 2023.

DILO22.Samuel Dittmer, Yuval Ishai, Steve Lu, and Rafail Ostrovsky. Authenticated garbling from simple correlations. In Yevgeniy Dodis and Thomas Shrimpton, editors, *CRYPTO 2022, Part IV*, volume 13510 of *LNCS*, pages 57–87. Springer, Cham, August 2022. + DKL 23.Nico Döttling, Dimitris Kolonelos, Russell W. F. Lai, Chuanwei Lin, Giulio Malavolta, and Ahmadreza Rahimi. Efficient laconic cryptography from learning with errors. In Carmit Hazay and Martijn Stam, editors, *EUROCRYPT 2023, Part III*, volume 14006 of *LNCS*, pages 417–446. Springer, Cham, April

2023.
DNPR16.Ivan Damgård, Jesper Buus Nielsen, Antigoni Polychroniadou, and Michael Raskin. On the commu- nication required for unconditionally secure multiplication. In Matthew Robshaw and Jonathan Katz, editors, *CRYPTO 2016, Part II*, volume 9815 of *LNCS*, pages 459–488. Springer, Berlin, Heidelberg, August 2016. DPSZ12.Ivan Damgård, Valerio Pastro, Nigel P. Smart, and Sarah Zakarias. Multiparty computation from somewhat homomorphic encryption. In Reihaneh Safavi-Naini and Ran Canetti, editors, *CRYPTO 2012*, volume 7417 of *LNCS*, pages 643–662. Springer, Berlin, Heidelberg, August 2012. FGJS17.Nelly Fazio, Rosario Gennaro, Tahereh Jafarikhah, and William E. Skeith III. Homomorphic secret sharing from paillier encryption. In Tatsuaki Okamoto, Yong Yu, Man Ho Au, and Yannan Li, editors, *ProvSec 2017*, volume 10592 of *LNCS*, pages 381–399. Springer, Cham, October 2017. Gen09.Craig Gentry. Fully homomorphic encryption using ideal lattices. In Michael Mitzenmacher, editor, *41st ACM STOC*, pages 169–178. ACM Press, May / June 2009. GH19.Craig Gentry and Shai Halevi. Compressible FHE with applications to PIR. In Dennis Hofheinz and Alon Rosen, editors, *TCC 2019, Part II*, volume 11892 of *LNCS*, pages 438–464. Springer, Cham, December 2019. GHS12.Craig Gentry, Shai Halevi, and Nigel P. Smart. Fully homomorphic encryption with polylog overhead. In David Pointcheval and Thomas Johansson, editors, *EUROCRYPT 2012*, volume 7237 of *LNCS*, pages 465–482. Springer, Berlin, Heidelberg, April 2012. + GKP 13.Shafi Goldwasser, Yael Tauman Kalai, Raluca A. Popa, Vinod Vaikuntanathan, and Nickolai Zeldovich. Reusable garbled circuits and succinct functional encryption. In Dan Boneh, Tim Roughgarden, and Joan Feigenbaum, editors, *45th ACM STOC*, pages 555–564. ACM Press, June 2013. GLNP15.Shay Gueron, Yehuda Lindell, Ariel Nof, and Benny Pinkas. Fast garbling of circuits under standard assumptions. In Indrajit Ray, Ninghui Li, and Christopher Kruegel, editors, *ACM CCS 2015*, pages 567–578. ACM Press, October 2015. GOS18.Sanjam Garg, Rafail Ostrovsky, and Akshayaram Srinivasan. Adaptive garbled RAM from laconic oblivious transfer. In Hovav Shacham and Alexandra Boldyreva, editors, *CRYPTO 2018, Part III*, volume 10993 of *LNCS*, pages 515–544. Springer, Cham, August 2018. GS18.Sanjam Garg and Akshayaram Srinivasan. Adaptively secure garbling with near optimal online com- plexity. In Jesper Buus Nielsen and Vincent Rijmen, editors, *EUROCRYPT 2018, Part II*, volume 10821 of *LNCS*, pages 535–565. Springer, Cham, April / May 2018. GSW13.Craig Gentry, Amit Sahai, and Brent Waters. Homomorphic encryption from learning with errors: Conceptually-simpler, asymptotically-faster, attribute-based. In Ran Canetti and Juan A. Garay, editors, *CRYPTO 2013, Part I*, volume 8042 of *LNCS*, pages 75–92. Springer, Berlin, Heidelberg, August 2013. HLL23.Yao-Ching Hsieh, Huijia Lin, and Ji Luo. Attribute-based encryption for circuits of unbounded depth from lattices. In *64th FOCS*, pages 415–434. IEEE Computer Society Press, November 2023. HW15.Pavel Hubacek and Daniel Wichs. On the communication complexity of secure function evaluation with long output. In Tim Roughgarden, editor, *ITCS 2015*, pages 163–172. ACM, January 2015. + IKM 13.Yuval Ishai, Eyal Kushilevitz, Sigurd Meldgaard, Claudio Orlandi, and Anat Paskin-Cherniavsky. On the power of correlated randomness in secure computation. In Amit Sahai, editor, *TCC 2013*, volume 7785 of *LNCS*, pages 600–620. Springer, Berlin, Heidelberg, March 2013. IPS08.Yuval Ishai, Manoj Prabhakaran, and Amit Sahai. Founding cryptography on oblivious transfer-efficiently. In David Wagner, editor, *CRYPTO 2008*, volume 5157 of *LNCS*, pages 572–591. Springer, Berlin, Heidelberg, August 2008. JLL23.Aayush Jain, Huijia Lin, and Ji Luo. On the optimal succinctness and efficiency of functional encryp- tion and attribute-based encryption. In Carmit Hazay and Martijn Stam, editors, *EUROCRYPT 2023,* *Part III*, volume 14006 of *LNCS*, pages 479–510. Springer, Cham, April 2023. KLW15.Venkata Koppula, Allison Bishop Lewko, and Brent Waters. Indistinguishability obfuscation for Turing machines with unbounded memory. In Rocco A. Servedio and Ronitt Rubinfeld, editors, *47th ACM* *STOC*, pages 419–428. ACM Press, June 2015.

KMR14.Vladimir Kolesnikov, Payman Mohassel, and Mike Rosulek. FleXOR: Flexible garbling for XOR gates that beats free-XOR. In Juan A. Garay and Rosario Gennaro, editors, *CRYPTO 2014, Part II*, volume 8617 of *LNCS*, pages 440–457. Springer, Berlin, Heidelberg, August 2014. KRRW18.Jonathan Katz, Samuel Ranellucci, Mike Rosulek, and Xiao Wang. Optimizing authenticated gar- bling for faster secure two-party computation. In Hovav Shacham and Alexandra Boldyreva, editors, *CRYPTO 2018, Part III*, volume 10993 of *LNCS*, pages 365–391. Springer, Cham, August 2018. KS08.Vladimir Kolesnikov and Thomas Schneider. Improved garbled circuit: Free XOR gates and applica- tions. In Luca Aceto, Ivan Damgård, Leslie Ann Goldberg, Magnús M. Halldórsson, Anna Ingólfsdóttir, and Igor Walukiewicz, editors, *ICALP 2008, Part II*, volume 5126 of *LNCS*, pages 486–498. Springer, Berlin, Heidelberg, July 2008. LP11.Yehuda Lindell and Benny Pinkas. Secure two-party computation via cut-and-choose oblivious transfer. In Yuval Ishai, editor, *TCC 2011*, volume 6597 of *LNCS*, pages 329–346. Springer, Berlin, Heidelberg, March 2011. NPS99.Moni Naor, Benny Pinkas, and Reuban Sumner. Privacy preserving auctions and mechanism design. In Stuart I. Feldman and Michael P. Wellman, editors, *Proceedings of the First ACM Conference on* *Electronic Commerce (EC-99), Denver, CO, USA, November 3-5, 1999*, pages 129–139. ACM, 1999. OSY21.Claudio Orlandi, Peter Scholl, and Sophia Yakoubov. The rise of paillier: Homomorphic secret shar- ing and public-key silent OT. In Anne Canteaut and François-Xavier Standaert, editors, *EURO-* *CRYPT 2021, Part I*, volume 12696 of *LNCS*, pages 678–708. Springer, Cham, October 2021. PSSW09.Benny Pinkas, Thomas Schneider, Nigel P. Smart, and Stephen C. Williams. Secure two-party com- putation is practical. In Mitsuru Matsui, editor, *ASIACRYPT 2009*, volume 5912 of *LNCS*, pages 250–267. Springer, Berlin, Heidelberg, December 2009. QWW18.Willy Quach, Hoeteck Wee, and Daniel Wichs. Laconic function evaluation and applications. In Mikkel Thorup, editor, *59th FOCS*, pages 859–870. IEEE Computer Society Press, October 2018. RR21.Mike Rosulek and Lawrence Roy. Three halves make a whole? Beating the half-gates lower bound for garbled circuits. In Tal Malkin and Chris Peikert, editors, *CRYPTO 2021, Part I*, volume 12825 of *LNCS*, pages 94–124, Virtual Event, August 2021. Springer, Cham. RS21.Lawrence Roy and Jaspal Singh. Large message homomorphic secret sharing from DCR and appli- cations. In Tal Malkin and Chris Peikert, editors, *CRYPTO 2021, Part III*, volume 12827 of *LNCS*, pages 687–717, Virtual Event, August 2021. Springer, Cham. SEA23.Microsoft SEAL (release 4.1). https://github.com/Microsoft/SEAL, January 2023. Microsoft Re- search, Redmond, WA. SV10.Nigel P. Smart and Frederik Vercauteren. Fully homomorphic encryption with relatively small key and ciphertext sizes. In Phong Q. Nguyen and David Pointcheval, editors, *PKC 2010*, volume 6056 of *LNCS*, pages 420–443. Springer, Berlin, Heidelberg, May 2010. WRK17.Xiao Wang, Samuel Ranellucci, and Jonathan Katz. Authenticated garbling and efficient maliciously secure two-party computation. In Bhavani M. Thuraisingham, David Evans, Tal Malkin, and Dongyan Xu, editors, *ACM CCS 2017*, pages 21–37. ACM Press, October / November 2017. Yao82.Andrew Chi-Chih Yao. Protocols for secure computations (extended abstract). In *23rd FOCS*, pages 160–164. IEEE Computer Society Press, November 1982. Yao86.Andrew Chi-Chih Yao. How to generate and exchange secrets (extended abstract). In *27th FOCS*, pages 162–167. IEEE Computer Society Press, October 1986. ZRE15.Samee Zahur, Mike Rosulek, and David Evans. Two halves make a whole-reducing data transfer in garbled circuits using half gates. In Elisabeth Oswald and Marc Fischlin, editors, *EUROCRYPT 2015,* *Part II*, volume 9057 of *LNCS*, pages 220–250. Springer, Berlin, Heidelberg, April 2015. ZYZL19.Shuoyao Zhao, Yu Yu, Jiang Zhang, and Hanlin Liu. Valiant’s universal circuits revisited: An overall improvement and a lower bound. In Steven D. Galbraith and Shiho Moriai, editors, *ASIACRYPT 2019,* *Part I*, volume 11921 of *LNCS*, pages 401–425. Springer, Cham, December 2019.

A Related Works on Sublinear 2PC Protocols and Succinct Garbling

In this section, we summarize the state of sublinear 2PC and succinct garbling, and compare them with our solution in the preprocessing model.

Succinct Garbling In the literature, two types of garbling schemes give drastically different computation vs. communication trade-offs. Yao’s original garbled circuits and the successful line

of optimization upon it [BMR90,NPS99,KS08,PSSW09,KMR14,GLNP15,ZRE15,RR21] all rely on extremely efficient symmetric-key operations (e.g., a few calls to AES per gate of the circuit), making communication, rather than computation, the bottleneck. Parties must ex- change *O*(*λ*) bits per gate, resulting in total communication *O*(*λ|C|*). On the other hand, there are constructions of garbled circuits achieving asymptotically optimal size, i.e., poly(*λ*), inde- pendent of the circuit complexity. Unfortunately, they are computationally expensive, since they rely on heavy machinery, such as, ABE and FHE [GKP + 13,HLL23], or (multi-key) Functional Encryption [AJS17,KLW15,BCG + 18,JLL23]. Our preprocessing garbled circuits using the batch-select scheme achieves optimal *online* com- munication poly(*λ*) and are concretely efficient, by leveraging preprocessing and pre-communication of complexity quasilinear in the circuit size. We believe that the notion of preprocessing garbling is interesting on its own, as it provides a meaningful middle point between the aforementioned two types of garbling schemes. We note that the quasilinear offline complexity stems from garbling the universal circuits in our construction. However, there might be completely different techniques for constructing preprocessing garbling, perhaps without using the universal circuits. We think this is an interesting technical question.

Sublinear 2PC without Preprocessing In the standard model without preprocessing, the only 2PC protocols for all circuits that achieve communication complexity independent of cir- cuit size rely on powerful tools such as FHE and/or *iO*. When using FHE [Gen09,BV11, BGV12,GSW13], we can attain protocols where only Alice receives an output, with commu- nication complexity *Oλ*(*|*x*A|* + *|*y*|*), or *|*x*A|* + *|*y*|* + *Oλ*(1) if the underlying FHE has a rate- 1 property [BDGM19,GH19]. Laconic function evaluation [QWW18] which uses ABE and FHE gives protocols where only Alice receives an output, and the communication complexity is *O* (*|*x *|* + *|*y*|*). Combining FHE and *iO*, the work of [HW15] demonstrated how to eliminate

|λ B|||
|---|---|---|
||A B|λ|

the dependency on output length to achieve communication *|*x *|* + *|*x *|* + *O* (1) or *Oλ*(CC(*C*)), where CC represents the communication complexity of computing *C* without security. Without FHE or *iO*, we can still achieve sublinear communication complexity using Ho- momorphic Secret Sharing (HSS) [BGI16]. An advantage is that HSS can be based on var- ious assumptions that do not imply fully homomorphic encryption, including DDH [BGI16], DCR [FGJS17,OSY21,RS21], assumptions related to class groups of imaginary quadratic fields [ADOS22], and different variants of the Learning Parity with Noise (LPN) assumptions [BCG + 19, CM21,DIJL23]. However, current HSS schemes only support low depth computations like NC₁, giving 2PC for low depth computations with communication complexity *Oλ*(min(*|*x*A|, |*x*B|*)+*|*y*|*). When extended to circuits, the communication complexity is only slightly sublinear in circuit size, e.g., *|C|/O*(log *|C|*), reducing it by just a logarithmic (or even log-log) factor. Another drawback of the above techniques is that to achieve malicious security, they need to rely on generic techniques such as communication efficient zero-knowledge protocols, which makes the protocols even more expensive. In comparison, our 2PC protocols achieve succinct online communication – poly(*λ*) bits after receiving *C*, and *|*x*A|* + *|*x*B|* + poly(*λ*) bits after the two parties receiving their inputs – and malicious security, and are concretely efficient. The downside is the offline stage with complexity *O* ˜(*λ|C|*).

Sublinear 2PC with Preprocessing Recent years have witnessed significant progress in devel- oping practical secure multiparty computation (MPC) protocols within the online-offline model. These protocols, such as those in [IPS08,DPSZ12], utilize the offline stage for conducting com- putationally expensive cryptographic operations to distribute correlated random coins among

the parties. These coins are subsequently used in a fast and information-theoretically secure online computation stage. However, despite these advancements, the communication complexity of these protocols remains linear in the circuit size. This limitation was highlighted as a major bottleneck and formally investigated in [DNPR16], showing that it is inherent for gate-by-gate protocols. The exploration of low-communication protocols in the correlated randomness model was ini- tiated in [IKM + 13]. In their work, they introduced protocols with communication complexity of *O*(*|*x*A|*+*|*x*B|*+*|*y*|*) but with a requirement for *exponentially* long correlated randomness, referred to as the one-time truth table correlation. They further argued that reducing the amount of cor- related random coins from exponential to polynomial for general functions would be challenging and could potentially lead to breakthroughs in long-standing open problems related to private information retrieval. Couteau [Cou19] later extended this approach to achieve polynomially long correlations, albeit with slightly sublinear communication complexity *|C|/O*(log log *|C|*). There is a major difference between the preprocessing model considered in these two works and ours: The preprocessing of [IKM + 13,Cou19] depends on the function, meaning the correlated randomness is sampled based on the circuit *C*, only independent of the inputs x*A,* x*B*. In contrast, our preprocessing is both function and input independent, providing greater flexibility. On the other hand, the works of [IKM + 13,Cou19] aim for information theoretically secure online stage, whereas we settle for computational security. Hence, the models are incomparable. In fact, if we relax to the model to allow both function-dependent preprocessing and computationally secure online stage, it becomes trivial to achieve optimal online communication: Alice can simply send a non-succinct garbled circuit *C*b to Bob in the offline stage, and online they only need communication for obtaining the right input labels.

Tools Offline Comm. Online Comm. Assumptions FHE w/ LWE w/ [BDGM19,GH19] / *|*x*A|* + *|*y*|* + *Oλ*(1) rate-1 circular security LWE w/ FHE circular security [HW15] + *iO* / *|*x*A|* + *|*x*B |* + *Oλ*(1) +DLIN+LPN +NC⁰-PRG [BGI16,OSY21] / *O*(*|C|/* log *|C|*) DDH/DCR/ HSS [BKS19] LWE [BCG + 19,CM21] HSS / *O*(*|C|/* log log *|C|*) variants of [DIJL23] LPN [Cou19] Correlated randomness / *O*(*|C|/* log log *|C|*) /

This paper Batch-Select *Oλ*(*|UC |*) *|*x*A|* + *|*x*B |* + *Oλ*(1) RLWE

Table 6: Efficiency comparison with existing 2PC protocols. We write x*A,* x*B,*y to mean the inputs to Alice and

Bob, and the output. W.l.o.g. we assume *|*x*A|≤|*x*B |*. By *UC* we denote a universal circuit (which can be made as small as *|C|* log *|C|* for arbitrary circuits *C* [ZYZL19]).

## B Details on LEnc

We now prove correctness and security of Construction1, LEnc.

Correctness. In the following analysis of LEnc, whenever the public parameters b₀*,*b₁ and the database a *∈R* *w* *q*are fixed, we define (for any prefix pre *∈{*0*,*1*}* *<ℓ* ) the hash tree recursively as

*T T−*g *−*1 (*y*pre*∥*0) *y*pre= b₀ b₁ *·* zprewhere zpre:=*−*1*,* *−*g (*y*pre*∥*1)

and the leaves *y*indfor ind *∈{*0*,*1*}* *ℓ* are given by a. *√* We first show correctness with error bound *B*LEnc= *g · m · γR·* log₂ *w · s · λ*. Note that for any ind *∈{*0*,*1*}* *ℓ*, evaluation yields

X *ℓ−*1 *δ*[ind] = C*i*[ind] *·* zind: *i* *i*=0 X *ℓ−*1 = r*i*[ind] *·* b *T* 0b *T* 1+ r*i*+1[ind] *·* ind*i*g *T* ind*i*g *T* + E*i*[ind] *·* zind: *i* *i*=0 X *ℓ−*1 = r[ind] *· y*ind: *i−* r*i*+1[ind] *· y*ind: *i*+1+ E*i*[ind] *·* zind: *i* *i*=0 X *ℓ−*1 = r₀[ind] *· yϵ−* s[ind] *·* a[ind] + E*i*[ind] *·* zind: *i.* *i*=0

P *ℓ−*1 *√* Therefore, we just need to prove that *i*=0 E*i*[ind] *·* zind: *i< B*LEnc. Note that *∥*E*i∥* *∞* *≤ λ · s* *∞* and *∥*zind: *i∥* *∞* *< g*. We get

X *ℓ−*1 X *ℓ−*1 X E*i*[ind] *·* zind: *i≤ ∥*E*i*[ind*,j*] *·* zind: *i*[*j*]*∥* *∞* *i*=0 *∞ i*=0 *j∈*[*m*]

X *ℓ−*1 X *≤ γR·∥*E*i∥* *∞* *·∥*zind: *i∥* *∞* *i*=0 *j∈*[*m*] *√* *< ℓ · m · γR· λ · s · g* = *B*LEnc*.*

Lemma 10(Security of Construction1). *Assuming* elLWE*R,q,χ,D* *R,s,LT,*2*m*(*g*) *, Construction1* *(*LEnc*) fulfills* 2 *λ* -simulation security with *T*-noise leakage *(Definition10).*

*Proof.* The simulator Sim takes the public parameters and the databases (pp*, {*a

(*t*) *}*), and simu-
lates ciphertext and noise (cte*, {*ee

(*t*) *}*[*T*]) as follows:
– First, sample all ciphertexts purely random

C e *i←*$ *Rq* *w×*2*m* for *i* = 0*,...,ℓ −* 1*,*

and choose cte := (Ce₀*,...,*Ce*ℓ−*1). – Then, simulate the noise leakages as follows: sample

E*i←*$ *χ* *w× m* for *i* = 0*,...,ℓ −,*

and for each ind *∈{*0*,*1*}* *ℓ* and *t ∈* [*T*], compute

X *ℓ−*1

(*t*)
ee

(*t*) [ind] := E*i*[ind] *·* z
ind: *i* *.* *i*=0

Return (cte*, {*ee

(*t*) *}*[*T*]).
In order to prove that the *real world* is indistinguishable from the *simulated world*, we define *′* (*t*) Hyb₀ to output ((b₀*,*b₁)*,*(C₀*,...,*C*ℓ−*1)*, {*eeres*}*[*T*]), where these values are computed as follows:

b₀*,*b₁ *←*$ *R* *m* *q*(5)

For *i* = 0*,...,ℓ −* 1 and ind *∈{*0*,*1*}* *ℓ* :

C*i*[ind] := r*i*[ind] *·* b *T* 0b *T* 1+ r*i*+1[ind] *·* ind*i·* g *T* ind*i·* g *T* + E*i*[ind] (6)

r*i*[ind] *←*$ *Rq*and r*ℓ*:= s 2*m* E*i*[ind] *←*$ *DR,s*

For *t ∈* [*T*] and ind *∈{*0*,*1*}* *ℓ* : X

(*t*)
ee

(*t*) [ind] := E*i*[ind] *·* z
ind: *i*

(*t*) (*t*) (*t*)
eeres[ind] := ee [ind] + e [ind] 0*≤i<ℓ* (7)

e

(*t*) [ind] *←*$ *χ*LEnc
Note that Hyb *′* 0is identical to the real world. To see this, consider the real noise leakage e

(*t*) =
*δ*

(*t*) *−*(r*· y*
(*t*) *−* s *⊙* a
(*t*) ) with *δ*
(*t*) *←* LEnc*.*Eval(ct*,* a
(*t*) ). Then, as in the correctness analysis above
which calculates *δ*

(*t*) [ind], we get
X *ℓ−*1

(*t*)
e

(*t*) [ind] = *δ*
(*t*) [ind] *−* (r[ind] *· y*
(*t*) *−* s *⊙* a
(*t*) [ind]) = E*i*[ind] *·* z
ind: *i* = ee

(*t*) [ind]
*i*=0

for any ind *∈{*0*,*1*}* *ℓ* and *t ∈* [*T*]. As a first step, we define a hybrid Hyb₀ that is identical to the previous Hyb *′* 0, except that it samples the error matrices E*i*[ind] from the Gaussian *χ²* *m* = *D* *R* 2*m* *,s* instead of the *truncated* 2*m* (*t*) Gaussian *DR,s*, and similarly e [ind] from the Gaussian *DR,s*instead of *χ*LEnc= *DR,s*. By 2 *λ′* Lemma2, we have Hyb₀ *≈*sHyb₀. Next, for any *i* *∗* *∈* [*ℓ*], we define Hyb*i∗* to be identical to Hyb₀, except that the ciphertexts of the first *i* *∗* layers are sampled as

C e *i←*$ *R* *w×* *q* 2*m* for *i < i* *∗* *.*

Note that Hyb*ℓ*is identical to the simulated world. 2 *λ∗* It remains to show that Hyb*i∗ ≈*cHyb*i∗*+1for any *i* = 0*,...,ℓ −* 1. To do so, we further divide the hybrid Hyb*i∗* into several sub-hybrids Hyb*i∗,j*for 0 *≤ j ≤ w*, which are identical to Hyb*i∗*, except that C*i∗*[ind] is sampled as

C e *i* *∗* [ind] *←*$ *R²q* *m* for *j* *′* *< j ,*

where ind is the bitstring representing *j* *′*. We can see that Hyb*i∗ ≡* Hyb*i∗,*0and that Hyb*i∗,w≡* 2 *λ* Hyb*i∗*+1, and therefore it just remains to show that Hyb*i∗,j≈*cHyb*i∗,j*+1for any 0 *≤ j < w*. We do so by a reduction to the elLWE*R,q,χ,D* *R,s,LT,*2*m*(*g*) assumption. Specifically, assuming an adversary *D* that distinguishes between Hyb*i∗,j*and Hyb*i∗,j*+1, we construct an adversary *A* for elLWE as follows (where the running time of *A* additively increases by poly(*λ*) when compared to that of *D*). We use ind *∈{*0*,*1*}* *ℓ* as the bitstring representing the integer *j*.

– After receiving public parameters b₀*,*b₁ *∈ R* *m* *q*, choose the *leakage matrix* Z *∈ R* *T* *q ×* 2*m* in

(*t*)
such a way that the *t*-th row is equal to the transpose of z ind *∗*. : *i* – After receiving the LWE sample y *∈R²qm*and leakage l *∈R* *T* *q*, run and output the result of *D* on a simulation of Hyb*i∗,j*, with two modifications:

- ** The ind-th row of C*i∗* is replaced by
C*i∗*[ind] := y *T* + r*i∗*+1[ind] *·* ind*i∗ ·* g *T* ind*i∗ ·* g *T*

instead of being computed from the key r*i∗*[ind].

- ** For every *t ∈* [*T*], the ind-th error is replaced by
X

(*t*) (*t*)
ee

(*t*) [ind] := E*i*[ind] *·* z
ind: *i* and eeres[ind] := ee

(*t*) [ind] + l[*t*]*.*
0*≤i<ℓ* *i̸*=*i∗*

The error-leakage Ring-LWE experiment with adversary *A* has the following distributions: *A,*0 – Consider the experiment elLWE *R,q,χ,D,L* (*g*). Here, y corresponds to a real LWE sample, *R,s T,*2*m* *T T T* (*t*) (*t*)

i.e., y = r*i∗*[ind] *·* b₀ b₁ + E*i∗*[ind] with leakage l[*t*] = E*i∗*[ind] *·* z
ind *∗* + *e* [ind] (for some : *i* fresh key r*i∗*[ind] *←*$ *Rq*and errors E*i∗*[ind] *←*$ *χ²* *m* and *e*

(*t*) [ind] *←*$ *DR,s*).
*A,*0 Therefore, elLWE *R,q,χ,D,L* (*g*) is identically distributed as the output of *D* when given *R,s T,*2*m* input generated from distribution Hyb*i∗,j*. *A,*1 2 – Consider the experiment elLWE *R,q,χ,D,L* (*g*). Here, y *←*$ *Rqm*is uniformly random and *R,s T,*2*m*

(*t*) (*t*) 2*m*
the leakage is equal to l[*t*] = E*i∗*[ind] *·* z ind: *i* + *e* [ind] (for fresh errors E*i∗*[ind] *←*$ *χ* and *e*

(*t*) [ind] *←*$ *DR,s*).
Note that C*i∗*[ind] will be uniformly random (due to the randomness of y). Therefore, *A,*1 elLWE *R,q,χ,D,L* (*g*) is identically distributed as the output of *D* when given input gener- *R,s T,*2*m* ated from distribution Hyb*i∗,j*+1.

Therefore, the distinguisher *D* has exactly the same advantage as the adversary *A*. By the 2 *λ* elLWE*R,q,χ,D* *R,s,LT,*2*m*(*g*) assumption, this implies that Hyb*i∗,j≈*cHyb*i∗,j*+1. Our hybrid argument *′* 2*λ* thus shows Hyb₀ *≈*cHyb*ℓ*, which concludes the security proof. *⊓⊔*

B.1 Construction of Weak Linear Laconic Encryption We now present a slight modification of Construction1, to give a *weak* LEnc over a ring *Rq*(see Definition11). It utilizes the same parameters as Construction1and has the same correctness error. However, simulation security with *T*-noise leakage w.r.t. noise distribution *χ*LEncrequires the assumption of elLWE*R,q,χ,D*
*R,s,LTw,*2*m*(*g*). Construction The main motivation is the observation that in Construction1, for *every* single ind *∈{,}* *ℓ*, we created *independent* ciphertexts allowing us to obtain r[ind] *· yϵ−* s[ind] *·* a[ind].

Hence, a natural question to ask is whether there is potential for optimization by exploiting the repeated usage of the same functionality. Indeed, we are able to construct an optimized *weak* LEnc, i.e., when the output keys s provided to the encryption algorithm LEnc*.*Enc(s) are guaranteed to consist of *w identical* ring elements (s = *s ·* 1*w*for some *s ∈Rq*). The size of the ciphertext will be reduced by a factor of 2 <u>ℓ</u> = <u>log</u> 2 <u>w</u>. However, it also requires a slightly stronger assumption of elLWE in which the leakage matrix has dimensions *Tw ×* 2*m* instead of *T ×* 2*m*. To get some intuition of where the improvement is coming from, consider the ciphertext ct = (C₀*,...,*C*ℓ−*1) in Construction1. Taking a closer look at C*ℓ−*1, we can see that it will be equal to  *T T T T*  r*ℓ−*1[1] *·* b₀ b₁ + s[1] *·* g 0

||||||||
|---|---|---|---|---|---|---|
|||ℓ−1|T 0 T 1|T T|||
|ℓ−1|ℓ−1|ℓ−1|T 0 T 1 T 0 T 1|T T T|T|ℓ−1|
||||ℓ−1|T|T ℓ−1|T ℓ−1|
|ℓ−1|ℓ−1|ℓ−1 ℓ−1|T 0 T 1 T T|T T T T|ℓ−1 ℓ−1||

r [2] *·* b *T* b *T* + s[2] *·* 0 *T* g *T*   . ..  C =  +E*.*   r [*w −* 1] *·* b b + s[*w −* 1] *·* g 0  r [*w*] *·* b b + s[*w*] *·* 0 g

Now, because s only consists of identical elements *s*, the “ciphertexts” corresponding to rows 1*,*3*,*5*,...* are all used to hide the same vector *s ·* g *T*

0. Additionally, the ciphertexts corre-
sponding to rows 2*,*4*,*6*,...* are all used to hide the same vector *s ·* 0 1. To exploit this pattern, we will sample r in such a way that r [1] = r [3] =*...* and r*ℓ−*1[2] = r [4] =*...*, which allows us to use a “compressed” C of the form

br [1] *·* b b + *s ·* g 0 C b = + Eb*,* br [2] *·* b₀ b₁ + *s ·* 0 g

which consists only of two rows. We get the “decompressed” version by computing

C*ℓ−*1= 12*ℓ−*1 *⊗* Cb*ℓ−*1*,*

and they correspond to keys r*ℓ−*1*ℓ−*1

|= 1 ⊗ b|r.||||
|---|---|---|---|---|
|2|ℓ−1 ℓ−1 i|×2m q|i ℓ−1|w 2|

Note that we reduced the number of rows in Cb to just 2. This, in turn, can be used to see that in C*ℓ−*2, only 4 different patterns need to be encrypted, and so on. In general, through *w* 2 *ii*b this compression trick and reusing the same keys br *∈R* for 2 times, C will consist of*i* rows. The only potential issue with this approach is that the same noise, e.g. Eb, is leaked *w* times, and therefore we will slightly modify the security proof and depend on a variant of elLWE that allows more leakage than before. The resulting construction differs from that in SectionBonly in the encryption and evaluation algorithms:

Construction 5(Weak Linear Laconic Encryption). *w* 2 *i*

|) → r, ct:|Sample Ring-LWE secrets b||r|R for each layer i = 0,...,ℓ − 1. For|||
|---|---|---|---|---|---|---|
|w||ℓ|i|$ q ℓ−i|i $|×2m|
||2w||||||
|i|i|T 0 T 1|i+1 1:|T|i||
|||i|×2m q|ℓ−1|||

<u>Enc(s = s · 1</u> *←* *w* notational convenience, set br := *s*. Also sample *truncated* Ring-LWE noises Eb *← χ²i*. Then, for each of the*i*rows, indexed by suf *∈{*0*,*1*}*, compute for each *i* = 0*,...,ℓ −* 1 thecompressedciphertext

C b [suf]:= br [suf] *·* b b + br [suf] *·* suf₀ *·* g suf₀ *·* g*T*+ Eb [suf]*.*

*w* b*i* We write the results as *ℓ* matrices C *∈R*. Return input keys r := r₀ and ciphertexts ct := (Cb₀*,...,*Cb).

<u>Eval(ct,a) → δ</u>: Parse ct := (Cb₀*,...,*Cb*ℓ−*1).Decompress these ciphertexts in the following way:

||C := 1|b ⊗ C ∈R||.|
|---|---|---|---|---|
|pre ℓ|i ℓ−1 i=0|2 i ≤ℓ i|qw×2m −1 −1 ind ind|∥0 ∥1|

*i*

As in Digest, compute *y* for all pre *∈{*0*,*1*}* from database a. Then, for each ind *∈{*0*,*1*}*, compute the result

X *−*g (*y*) *δ*[ind] := C [ind] *·* : *i* *,* *−*g (*y* : *i* )

## and return the vector δ.

Correctness. Correctness of Construction5follows from the fact that the decompressed cipher- texts are equal to “normal” ciphertexts as created in Construction1:

## Ci[ind] = Cbi[indi:]

= br*i*[ind*i*:] *·* b *T* 0b *T* 1+ br*i*+1[ind*i*+1:] *·* ind*i·* g *T* ind*i·* g *T* + Eb*i*[ind*i*:]

= r*i*[ind] *·* b *T* 0b *T* 1+ r*i*+1[ind] *·* ind*i·* g *T* ind*i·* g *T* + E*i*[ind]*,*

where

r*i*:= 12*i ⊗* br*i*and E*i*:= 12*i ⊗* Eb*i*

denote the “decompressed” keys and noise. Now we can apply correctness of the original Con- struction1(which does make any assumptions on entries of r*i*or E*i*being independent of each other).

Lemma 11(Security of Construction5). *Assuming* elLWE*R,q,χ,D* *R,s,LTw,*2*m*(*g*) *, Construc-* *tion1fulfills* 2 *λ* -simulation security with *T*-noise leakage *(Definition10).*

*Proof.* The simulator Sim takes the public parameters and the databases (pp*, {*a

(*t*) *}*), and simu-
lates ciphertext and noise (cte*, {*ee

(*t*) *}*[*T*]) as follows:
– First, sample allcompressedciphertexts purely random *w* *×*2*m* e b 2*i* C*i←*$ *Rq*for *i* = 0*,...,ℓ −* 1*,*

e := (C e b e b and choose ct0*,...,*C*ℓ−*1). – Then, simulate the noise leakages as follows: sample *w* *×*2*m* E b *i←*$ *χ²* *i*for *i* = 0*,...,ℓ −* 1*,*

## “decompress” these noise matrices by choosing

||E|:= 1 ⊗ E|b for i = 0,...,ℓ − 1,|||
|---|---|---|---|---|---|
||i|2|i|||
||ℓ|(t)|ℓ−1|i|(t) ind|
||||i=0|||
|(t) [T]||||||

*i*

and for each ind *∈{*0*,*1*}* and *t ∈* [*T*], compute

X ee [ind] := E [ind] *·* z : *i* *.*

## Return (cte, {ee}).

In order to prove that the *real world* is indistinguishable from the *simulated world*, we define *′*b b(*t*) Hyb₀ to output ((b₀*,*b₁)*,*(C₀*,...,*C*ℓ−*1)*, {*eeres*}*[*T*]), where these values are computed as follows:

b₀*,*b₁ *←*$ *R* *m* *q*

For *i* = 0*,...,ℓ −* 1 and suf *∈{*0*,*1*}* *ℓ−i* :

C b *i* [suf] := br*i*[suf] *·* b *T* 0b *T* 1+ br*i*+1[suf1:] *·* suf₀ *·* g *T* suf₀ *·* g *T* + Eb*i*[suf] *w* *∗* 2*i* r*i*:= 12*i ⊗* br*i*for *i* = *i,...,ℓ* with br*i←*$ *Rq*and br*ℓ*:= *s* *w* *×*2*m* b b 2*i* E*i*:= 12*i ⊗* E*i*for *i* = 0*,...,ℓ −* 1 with E*i←*$ *D* *R,s*

For *t ∈* [*T*] and ind *∈{*0*,*1*}* *ℓ* : X

(*t*)
ee

(*t*) [ind] := E*i*[ind] *·* z
ind: *i*

(*t*) (*t*) (*t*)
eeres[ind] := ee [ind] + e [ind] 0*≤i<ℓ*

e

(*t*) [ind] *←*$ *χ*LEnc
Note that Hyb *′* 0is identical to the real world. To see this, consider the real noise leakage e

(*t*) =
*δ*

(*t*) *−*(r*· y*
(*t*) *−* s *⊙* a
(*t*) ) with *δ*
(*t*) *←* LEnc*.*Eval(ct*,* a
(*t*) ). Then, as in the correctness analysis above
which calculates *δ*

(*t*) [ind], we get
X *ℓ−*1

(*t*)
e

(*t*) [ind] = *δ*
(*t*) [ind] *−* (r[ind] *· y*
(*t*) *−* s *⊙* a
(*t*) [ind]) = E*i*[ind] *·* z
ind: *i* = ee

(*t*) [ind]
*i*=0

for any ind *∈{*0*,*1*}* *ℓ* and *t ∈* [*T*]. As a first step, we define a hybrid Hyb₀ that is identical to the previous Hyb *′* 0, except that it samples the error matrices Eb*i*[suf] from the Gaussian *χ²* *m* = *D* *R* 2*m* *,s* instead of the *truncated* 2*m* (*t*) Gaussian *DR,s*, and similarly e [ind] from the Gaussian *DR,s*instead of *χ*LEnc= *DR,s*. By 2 *λ′* Lemma2, we have Hyb₀ *≈*sHyb₀. Next, for any *i* *∗* *∈* [*ℓ*], we define Hyb*i∗* to be identical to Hyb₀, except that the ciphertexts of the first *i* *∗* layers are sampled as *w* *×*2*m* e b 2*i ∗* C*i←*$ *Rq*for *i < i.*

Note that Hyb*ℓ*is identical to the simulated world. It remains to show that Hyb*i∗ ≈*cHyb*i∗*+1for any *i* *∗* = 0*,...,ℓ −* 1. To do so, we further divide the hybrid Hyb*i∗* into several sub-hybrids Hyb*i∗,j*for 0 *≤ j ≤* 2 <u>w</u> *i∗*, which are identical to Hyb*i∗*, except that Cb*i∗*[ind] is sampled as

e b2*m ′* C*i∗*[suf] *←*$ *Rq*for *j < j ,*

where suf is the bitstring representing *j* *′*. We can see that Hyb*i∗ ≡* Hyb*i∗,*0and that Hyb*i∗,w≡* Hyb*i∗*+1, and therefore it just remains to show that Hyb*i∗,j≈*cHyb*i∗,j*+1for any 0 *≤ j < w*. We do so by a reduction to the elLWE*R,q,χ,D* *R,s,Li∗*(*g*) assumption. Specifically, assuming *T* 2*,*2*m* an adversary *D* that distinguishes between Hyb*i∗,j*and Hyb*i∗,j*+1, we construct an adversary *A* for elLWE as follows (where the running time of *A* additively increases by poly(*λ*) when compared to that of *D*). We use suf *∈{,}* *ℓ−i* as the bitstring representing the integer *j*.

*m* 2*i∗×*2*m* – After receiving public parameters b₀*,*b₁ *∈ Rq*, choose the *leakage matrix* Z *∈ RqT*, *i* *∗* with rows indexed by (*t,* pre), for *t ∈* [*T*] and pre *∈{*0*,*1*}*,in such a way that the (*t,* pre)-th

(*t*)
row is equal to the transpose of zpre. 2 2*i∗* – After receiving the LWE sample y *∈Rqm*and leakage l *∈RqT*, run and output the result of *D* on a simulation of Hyb*i∗,j*, with two modifications:

- ** The suf-th row of Cb*i∗* is replaced by
C b *i* *∗* [suf] := y *T* + br*i∗*+1[suf1:] *·* suf₀ *·* g *T* suf₀ *·* g *T*

instead of being computed from the key br*i∗*[suf]. *i* *∗*

- ** For every *t ∈* [*T*],and every pre *∈{*0*,*1*}*,the ind = pre*∥*suf-th error is replaced by
X

(*t*) (*t*)
ee

(*t*) [ind] := E*i*[ind] *·* z
ind: *i* and eeres[ind] := ee

(*t*) [ind] + l[*t,* pre]*.*
0*≤i<ℓ* *i̸*=*i∗*

The error-leakage Ring-LWE experiment with adversary *A* has the following distributions: *A,*0 – Consider the experiment elLWE *R,q,χ,D,L ∗* (*g*). Here, y corresponds to a real LWE sam- *R,s T* 2*i,*2*m* *T T T*b b(*t*) (*t*) ple, i.e., y = br*i∗*[suf]*·* b₀ b₁ + E*i∗*[suf] with leakage l[*t,* pre] = E*i∗*[suf] *·* zpre+ *e* [pre*∥*suf] (for some fresh key br*i∗*[suf] *←*$ *Rq*and errors Eb*i∗*[suf] *←*$ *χ²* *m* and *e*

(*t*) [pre*∥*suf] *←*$ *DR,s*).
*A,*0 Therefore, elLWE *R,q,χ,D,L ∗* (*g*) is identically distributed as the output of *D* when given *R,s T* 2*i,*2*m* input generated from distribution Hyb*i∗,j*. *A,*1 2 – Consider the experiment elLWE *R,q,χ,D,L ∗* (*g*). Here, y *←*$ *Rqm*is uniformly random and *R,s T* 2*i,*2*m* b(*t*) (*t*) 2*m* the leakage is equal to l[*t,* pre] = E*i∗*[suf] *·* zpre+ *e* [pre*∥*suf] (for fresh errors E*i∗*[suf] *←*$ *χ* and *e*

(*t*) [pre*∥*suf] *←*$ *DR,s*).
Note that C*i∗*[ind] will be uniformly random (due to the randomness of y). Therefore, *A,*1 elLWE *R,q,χ,D,L ∗* (*g*) is identically distributed as the output of *D* when given input *R,s T* 2*i,*2*m* generated from distribution Hyb*i∗,j*+1.

Therefore, the distinguisher *D* has exactly the same advantage as the adversary *A*. By the 2 *λ* elLWE*R,q,χ,D* *R,s,LTw,*2*m*(*g*) assumption, this implies that Hyb*i∗,j≈*cHyb*i∗,j*+1. Our hybrid argu- *′* 2*λ* ment thus shows Hyb₀ *≈*cHyb*ℓ*, which concludes the security proof. *⊓⊔*

B.2 LEnc Parameter Setting We now prove the claimed efficiencies for the parameter setting described in Lemma5. *Proof(of Lemma5).* Under assumption LWE*R,O*(1)*,q,D*
0*.*1, we may conclude (using Theorem2
*R,q* and Lemma3) that also the error-leakage version elLWE*R,q,D* *R,s,DR,s,LT,*2*m*(*g*) holds, with param- *√* eters *s* = 3*q⁰*

*.*1 and *s* = 2*s · g · n* 2*Tm*.
To obtain the claimed parameters, we choose the gadget-base *g* = *⌈q⁰*

*.*05 *⌉* (as used inside of
our LEnc construction) and hence *m ≤* 20. Thus, we get *√ √ √ √ √* max*χ*LEnc= *λ · s* = *q⁰*

*.*1 *· g ·*
|{z} *n · T · m · λ ·*6 2 |{z} |{z} |{z} |{z} *≤ q*0*.*05 *≤q* 1*/*15 *≤q*1*/*4*≤*20 *≤q*1*/*30 *√* *≤ q ,*

and similarly

*√*

|LEnc||R|||.1|
|---|---|---|---|---|---|
||2q ≤20|≤q|≤λ≤q||≤q|
||0.35|||||
|||||√q||
|||||w||
|R,q,D|,D ,L .1|(g)|||/4|

*B* = *g ·* |{z} *m · γ ·* log₂ *w ·q⁰ · λ ·*2 |{z} |{z} | {z } |{z}

0*.*05 1*/*15 1*/*15 1*/*30 *√*
*≤* 80*q ≤ q .*

Similarly, we also get a *weak* LEnc scheme with *T* =-noise leakage under the same param- eters, because the elLWE *R,s R,s Tw,*2*m* assumption holds under LWE*R,O*(1)*,q,D*

0*.*1, with
*√* *R,q* the same parameters as above: *s* = 3*q⁰* and *s* = 2*s · g · n* 2*m · q¹*. *⊓⊔*

## C Details on LHE

We now prove correctness and security of Construction2, LHE.

Correctness. We verify the decryption process, and show that the magnitude of the noise is *√*

||· g + s) ·|λ:||||
|---|---|---|---|---|---|
||res|ct −1||sk T 1 −1||
||||−1|||
|−1 λ|∞|R R R|−1 R,s|∞ R,s LHE R,q,χ,χ,L|∞ (g)|

bounded by *B*LHE(*λ*) = (*s · m · γR*

res *y* z}| { z}| { m = ct₁ *·* g (*y*) + ct₂ *−* a *·* (s *·* g (*y*) + *s₂*)

= (m₁ *· y* + m₂) + (E *·* g (*y*) + e)*,*

E *·* g (*y*) + e *≤ m · γ ·∥*E*∥* *∞* *·* g (*y*) + *∥*e*∥*

*< m · γ · g ·* max*D* + max*D* *√* *<* (*m · γ · g · s* + *s*) *· λ* = *B.*

Lemma 12(Security of Construction2). *Assuming* elLWE *×w, Construction2* *T,*1 *(*LHE*) fulfills T*-times 2-simulation security *(Definition13).*

*Proof.* The simulator Sim takes the public parameters pp, the evaluated messages and ring ele-

(*t*) (*t*) (*t*) (*t*)
ments *{*mres*,y}*, and simulates ciphertexts and decryption keys (ct₁*, {*ct₂*,*sk*y}*) as follows:

(*t*)
– Sample the first ciphertext ct₁ and all decryption keys sk*y*at random:

e

||$ w q ×m|(t) y|$ q|||
|---|---|---|---|---|---|
|||(t)|||w×m|

ct e₁ *← R,* sk *← R ∀t ∈* [*T*]*.*

(*t*) *w*
– Then, simulate the remaining ciphertexts ct₂ by sampling noises E *← χ* and e *← χ* as in an honest execution (except that they are not truncated), and computing

ct e := a *·* sk( *yt* ) + m + (E *·* g *−*1 (*y*

(*t*) ) + e
(*t*) ) *∀t ∈* [*T*]
(res*t*) (res*t*)

ct e := cte *−* cte₁ *·* g*−*1(*y*(*t*)) *∀t ∈* [*T*] (2*t*) (res*t*)

We show a series of hybrid experiments that transitions from Hyb₀ (the “real” distribution as defined in Definition13) to Hyb₄ (the “simulated” distribution). We abuse notation to also write Hyb*i*as the output of the distribution of the corresponding experiment.

(*t*) (*t*)
Hyb₀ To recall, Hyb₀ generates ciphertexts ct₁*, {*ct₂*}* and decryption keys *{*sk*y}* in the following way:

<u>a</u> *←*$ *R* *m* *q*(8) s₁ *←*$ *R* *m* *q* ct₁ := a *·* s *T* 1+ m₁ *·* g *T* + E *w×m*

(9)
E *←*$ *DR,s*

For *t ∈* [*T*] :

(*t*)
(*t*) (*t*) (*t*) (*t*)*s₂ ←*$ *Rq*
ct₂ := a *· s₂* + m₂ + e *w* (10) e

(*t*) *←*$ *DR,s*
() *T −*1 (*t*) (*t*) sk*yt*:= s₁ *·* g (*y*) + *s₂* (11)

Hyb₁ As a first step, in Hyb₁ we sample the errors E and e

(*t*) as Gaussians from *χ*
*w×m* = *D* *R* *w×* *,sm* *w w,s w×m w* and *χ* = *D* *R*, instead of truncated Gaussians from *DR,s*and *DR,s*, respectively. By 2 *λ* Lemma2, we have Hyb₁ *≈*sHyb₀.

(*t*) (*t*)
Hyb₂ Now, we switch the order of computation: instead of computing ct₂ directly from m₂,

(*t*) (*t*)
we first define the *combined* ciphertext ctres(which is an encryption of mresunder sk*y*), and

(*t*) (*t*)
then simulate ct₂ as a combination of ctresand ct₁.

(*t*)
More precisely, we leave ct₁ and sk*y*unchanged from the previous hybrid, but instead com- e

(*t*)
pute ct₂ as follows:

() *T −*1 (*t*) (*t*) (*t*) sk*yt*:= s₁ *·* g (*y*) + *s₂ s₂ ←*$ *Rq*

(2*t*) (res*t*) e

(*t*) *←*$ *χ* *w*
ct e := cte *−* cte₁ *·* g*−*1(*y*(*t*)) (res*t*) (res*t*) ct e := a *·* sk( *yt* ) + m + (E *·* g *−*1 (*y*

(*t*) ) + e
(*t*) )
(*t*) *T −*1 (*t*) (*t*) (*t*) (*t*) (*t*)
By definition of sk*y*= s₁ *·* g (*y*) + *s₂* and mres= m₁ *· y* + m₂, this way of defining ct₂ is identical to the previous one. Therefore, we have Hyb₂ *≡* Hyb₁.

(*t*)
Hyb₃ Note that in the previous hybrid, the uniformly random key *s₂* is used nowhere but in

(*t*) *T −*1 (*t*) (*t*)
the definition of sk*y*= s₁ *·* g (*y*) + *s₂*. Therefore, we may equivalently generate

<u>sk</u> e <u>y</u>*←*$ *Rq∀t ∈* [*T*]

(*t*)
(*t*)
uniformly random instead of computing it from *s₂*. We get Hyb₃ *≡* Hyb₂. Hyb₄ In this hybrid, we replace the first ciphertext ct₁ = a *·* s *T* 1+ m₁ *·* g *T* + E by a uniformly generated vector ct e₁ *←*$ *Rw* *q ×m.*

While we would like to use the Ring-LWE assumption for this step, note that the noise matrix e

(*t*)
E is still used in the definition of ctres. Therefore, we need to use the more powerful elLWE, which allows us to utilize the noise leakage E *·* g *−*1 (*y*

(*t*) ) + e
(*t*).
In more detail, we define sub-hybrids Hyb₃*,i*for *i* = 0*,...,m*, where Hyb₃*,i*is identical to Hyb₃, except that the first *i* columns of ct₁ are sampled uniformly random. Note that Hyb₃ *≡* Hyb₃*,*

and Hyb₃

|≡ Hyb₄. Therefore, in order to prove Hyb₄ ≈||Hyb₃, it only remains to show|
|---|---|---|
|,m||c|
|,i−1 c|,i||
|,i−1|,i|R,q,χ,χ,L|

Hyb₃ *≈* Hyb₃ for *i* = 1*,...,m*. To do so, assume there exists a distinguisher *D* for Hyb₃ and Hyb₃. We construct an adversary *A* for elLWE *×w*

(*g*) in the following
*T,*1 way (where the running time of *A* additively increases by poly(*λ*) when compared to that of

*D*):

||w|Tw ×w|
|---|---|---|
||q|q|
|−1 (t)||−1 (t)|
 – After receiving public parameters a *∈R*, choose the *leakage matrix* Z *∈R* in the following way. Let g (*y*)[*i*] be the *i*-th entry of the decomposition g (*y*). Then, select
z *T* := g *−*1 (*y*

(1) )[*i*]*...* g
*−*1 (*y*

(*T*) )[*i*]
and choose

Z := diag(z*,...,* z)*.* | {z} *w* times *Note that this is saying that the noise* E[*j,i*] *(i.e., j-th row and i-th column of* E*) is leaked*

(*t*)
*T times; once in the j-th row of each* ctres*.* – After receiving the LWE sample y *∈ R* *w* *q*and leakage l *∈ R* *Tw* *q*, first split the leakage l *T* = (l[1]*,...,* l[*Tw*]) into *T* separate vectors

l *T* *t*= (l[*t*]*,*l[*T* + *t*]*,...,* l[(*w −* 1)*T* + *t*]) *∀t ∈* [*T*]*.*

*Note that the vector* l*twill correspond to a leakage of the noise vector* E[:*,i*] *when multiplied* *with* g *−*1 (*y*

(*t*) )[*i*]*, and then hidden by a larger noise* e
(*t*) *.*
Then, run and output the result of *D* on a simulation of Hyb₃*,i*, with two modifications:

- ** the *i*-th column of ct₁ is computed as y
*T* + m₁ *· g* *i*, and

(*t*)
- ** for any *t ∈* [*T*], the ciphertext ctresis computed as
 

(*t*) () (*t*)
X *′ −*1 (*t*) *′* ctres:= a *·* sk*yt*+ mres+  E[:*,i*] *·* g (*y*)[*i*] + l*t.* *i* *′* *∈*[*T*]*\{i}*

The error-leakage Ring-LWE experiment with adversary *A* has the following distributions: *A,*0 – Consider the experiment elLWE*×w*. Here, y corresponds to a real LWE sample, *R,q,χ,χ,LT,*1(*g*)

i.e., y = a *·* s₁[*i*] + E[:*,i*] with leakage l*t*= E[:*,i*<u>]</u> *·* g
*−*1 (*y*

(*t*) )[*i*] + e
(*t*) (for some fresh key
s₁[*i*] *←*$ *Rq*and errors E[:*,i*] *←*$ *R* *w* *q*and e

(*t*) *←*$ *χ* *w* ).
*A,*0 Therefore, elLWE*×w*is identically distributed as the output of *D* when given *R,q,χ,χ,LT,*1(*g*) input generated from distribution Hyb₃*,i−*1. *A,*1 2 – Consider the experiment elLWE*×w*. Here, y *←*$ *Rqm*is uniformly random and *R,q,χ,χ,LT,*1(*g*) the leakage is equal to l*t*= E[:*,i*] *·* g *−*1 (*y*

(*t*) )[*i*] + e
(*t*) (for fresh errors E[:*,i*] *←*$ *R*
*w* *q*and e

(*t*) *←*$ *χ* *w* ).
Note that the *i*-th column of ct₁ will be uniformly random (due to the randomness of y). *A,*1 Therefore, elLWE*×w*is identically distributed as the output of *D* when given *R,q,χ,χ,LT,*1(*g*) input generated from distribution Hyb₃*,i*. Therefore, the distinguisher *D* has exactly the same advantage as the adversary *A*. By the 2 *λ* elLWE *R,q,χ,χ,L* *×w*

(*g*) assumption, this implies that Hyb₃*,i−*1*≈*cHyb₃*,i*.
*T,*1 *λ* By the hybrid argument, we get Hyb₀ *≈*cHyb₄. Because Hyb₄ is identical to the simulated world, *T*-times simulation security follows. *⊓⊔*

C.1 LHE Parameter Setting We now prove the claimed efficiencies for the parameter setting in Lemma6. *Proof(of Lemma6).* Under assumption LWE*R,w,q,D*
*R,q*0*.*1, we may conclude (using Theorem2and Lemma4) that also the error-leakage version elLWE <u>R</u>*,q,χ,χ,L* *×w*

(*g*) holds, with error distributions
*√* *T,*1 *χ* and *χ* of parameters *s* = 3*q⁰*

*.*1 and *s* = 2*s · g · n T*.
To obtain the claimed parameters, we choose the gadget-base *g* = *⌈q⁰*

*.*05 *⌉* (as used inside of
our LEnc construction) and hence *m ≤* 20. Thus, we get *√ √*

||R|.1|
|---|---|---|
|≤2q /2|≤20 ≤q|≤q|

*B*LHE*≤* ( *g ·* |{z} *m · γ* +2 *· g ·* |{z} *n · T*) *· q⁰ λ ·*3 |{z} |{z} |{z} |{z} |{z}

0*.*05 1*/*15*≤*2*q*0*.*05 *≤q*1*/*15*≤q*1*/*4 1*/*30
*≤* 10*q¹.*

*⊓⊔*

## D Details on Sel

In this section, we provide the deferred security proof of our batch-select instantiation. In Sec- tionD.1, we give the proof for the *random* batch-select version. Correctness. First, denote by l = l₁ *⊙* y + l₂ (over Z*p*) be the required output of Sel*.*Dec, with encoding bl := Encode(l), which (by the properties of Encode) is equal to bl₁ *⊙* yb + bl₂ over *Rp*. Considering the larger ring *Rq*that our construction works on, we have the identity bl *· ∆* = (bl₁ *· ∆*) *⊙* yb + bl₂ *· ∆*, because of

bl *· ∆* = [bl₁ *⊙* yb + bl₂] *p· ∆* = (bl₁ *⊙* yb + bl₂ *− p ·* z) *· ∆*

= (bl₁ *⊙* yb) *· ∆* + bl₂ *·∆−* (<u>p</u> *·* <u>∆</u>) *·*z | {z} =*q*

= (bl₁ *· ∆*) *⊙* yb + bl₂ *· ∆* (mod *q*)*,*

*w′* where [*.*]*p*denotes reduction modulo *p*, and z is some vector in *Rq*. Note that this equality crucially depends on the fact that the plaintext modulus *p* divides the larger ring modulus *q*. Now, by correctness of the underlying LHE, we have

|+ bl₂ · ∆ + e|)|≤ B,|
|---|---|---|
|y b|LEnc|LHE|
||∞||

res *′* *−* (r *· d*

and by correctness of the underlying LEnc, we have

<u>LEnc.Eval</u>(<u>LEnc.ct, yb</u>) *−*(r *· d*yb*−* (bl₁ *· ∆*) *⊙* yb) *≤ B*LEnc*.* | {z} =: *δ ∞* Combining these two bounds, the overall error is at most

res *−*bl *· ∆* = res *′* *− δ −* ((bl₁ *· ∆*) *⊙* yb + bl₂ *· ∆*) *∞ ∞*

= (res *′* *−* r *· d*yb*−*bl₂ *·∆−* eLEnc) *−* (*δ −* r *· d*yb+ (bl₁ *· ∆*) *⊙* yb) + eLEnc *∞*

|+ B|+ ∥e|∥|||
|---|---|---|---|---|
|LHE|LEnc|LEnc ∞|||
|LHE|LEnc|LEnc|||

*≤ B* <u>∆</u> *≤ B* + *B* + max*χ <,*

and therefore the output Decode(*⌊* <u>res</u> *∆* *⌉*) will be equal to Decode(bl) = l.

Lemma 13(Security of Batch-Select, Construction3). *Assuming that the underlying* LHE *scheme is T -times* 2 *λ* *-simulation secure, and the underlying* LEnc *scheme is* 2 *λ* *-simulation* *secure with T -noise leakage, Construction3is a correct batch-select scheme that fulfills T -times* 2 *λ* *-simulation security.*

*Proof.* We define the simulator Sel*.*Sim, which receives input pp = (ppLHE*,*pp) as well as *T*

|||LEnc|
|---|---|---|
|(t)|(t) [T]||
|(t)|(t)||

message and selection vectors *{*l*,* y*}*, as follows (where we define encoded values as in the construction: yb

(*t*) := Encode(y) and bl := Encode(l
(*t*) )):
– First, run the laconic encryption simulator

LEnc ^*.*ct*, {*ee(*t*)*}* [*T*]*←* LEnc*.*Sim(ppLEnc*, {*yb

(*t*) *}*[*T*])*.*
(*t*) (*t*)
– Second, compute the digest *d* yb and evaluate the laconic encryption *δ* :

(*t*) (*t*)
*d* yb *←* LEnc*.*Digest(yb) *∀i ∈* [*T*]

*δ*

(*t*) *←* LEnc*.*Eval(LEnc ^*.*ct*,* yb
(*t*) ) *∀i ∈* [*T*]
*′* – Third, simulate the output res f of the LHE, and invoke the LHE simulator to simulate all LHE

(*t*) (*t*) (*t*) (*t*)
ciphertexts and keys (note that *δ −* ee is equal to the “noise-free” r *· d* yb *−*((bl₁ *· ∆*) *⊙* yb), *′*(*t*) (*t*) (*t*) (*t*) and therefore res f is equal to r *· d* yb + bl₂ *·∆−* e LEnc ):

(*t*) *w′*
e LEnc *←*$ *χ*LEnc*∀i ∈* [*T*] *′*(*t*) (*t*) (*t*) (*t*) (*t*) res f := *δ −* ee + bl *·∆−* e LEnc *∀i ∈* [*T*]

(*t*) (*t*)
*′*(*t*) (*t*) LHE ^*.*ct₁*, {*LHE ^*.*ct₂*,*ske y(*t*)*}*[*T*]*←* LHE*.*Sim(pp*, {*res f*,d* yb *}*[*T*])

(*t*) (*t*)
– Finally, return cte₁ := (LEnc ^*.*ct*,*LHE ^*.*ct₁) and *{*LHE ^*.*ct₂*,*skey(*t*)*}*[*T*].

We show a series of hybrid experiments that transitions from Hyb₀ (the “real” distribution as defined in Definition6) to Hyb₃ (the “simulated” distribution). We abuse notation to also write Hyb*i*as the output of the distribution of the corresponding experiment.

Hyb₀ To recall, Hyb₀ (omitting generation of public parameters pp) computes ct₁ = (LEnc*.*ct*,*LHE*.*ct₁)

(*t*) (*t*)
and *{*LHE*.*ct₂*,*sk y(*t*) *}*[*T*]in the following way (where, as in the construction, we define the

(*t*) (*t*)
digests *d* yb := LEnc*.*Digest(yb), and encoded values bl₁ := Encode(l₁) and bl₂ := Encode(l₂)):

## r, LEnc.ct ← LEnc.Enc(bl₁ · ∆)

## LHE.ct₁,st₁ ← LHE.Enc₁(r)

## For t ∈ [T] :

(*t*) (*t*) (*t*) (*t*) (LEnc *t*) *w′*

|LHE.ct₂|·∆− e|)|e|← χ|
|---|---|---|---|---|
|||LEnc||$ LEnc|
|(t)|(t) (t)||||
|y|y b||||
 *,*st₂ *←* LHE*.*Enc₂(bl₂
LEnc $ LEnc

sk(*t*)*←* LHE*.*KeyGen(st₁*,*st₂*,d*)

(*t*) (*t*)
Hyb₁ We now use the simulation security of LHE to replace generation of LHE ^*.*ct₁, *{*LHE ^*.*ct₂*,*skey(*t*)*}*[*T*] (i.e., the final three lines in Hyb₀) by the following:

(*t*) (*t*)
*′*(*t*) (*t*) LHE ^*.*ct₁*, {*LHE ^*.*ct₂*,*ske y(*t*)*}*[*T*]*←* LHE*.*Sim(pp*, {*res*,d*yb*}*[*T*])

*′*(*t*) (*t*) (*t*) (*t*) res *←* r *· d* yb + bl₂ *·∆−* e LEnc *∀t ∈* [*T*]

2 *λ* The indistinguishability Hyb₀ *≈*cHyb₁ follows directly from the *T*-times simulation security of LHE. Hyb₂ In Hyb₂, we now rewrite res *′*(*t*) (for every *t ∈* [*T*]) as

*δ*

(*t*) *←* LEnc*.*Eval(LEnc*.*ct*,* yb
(*t*) )
(*t*) (*t*) (*t*) (*t*)
e := *δ −* (r *· d* yb *−* (bl₁ *· ∆*) *⊙* yb)

*′*(*t*) (*t*) (*t*) (*t*) (*t*) res *← δ −* e + bl *·∆−* e LEnc

(Note that e

(*t*) denotes the LEnc “evaluation error”, i.e., the difference between the expected
result r *· y*

(*t*) *−* (bl₁ *· ∆*) *⊙* yb
(*t*) and the noisy outcome *δ*
(*t*) .)
This way of defining res *′*(*t*) is identical to the previous one:

(*t*) (*t*) (*t*) (*t*) (*t*) (*t*) (*t*) (*t*)
r *· d* yb + bl₂ *·∆−* e LEnc = (*δ* + (bl₁ *· ∆*) *⊙* yb *−* e) + bl₂ *·∆−* e LEnc

(*t*) (*t*) (*t*) (*t*) (*t*)
= *δ −* e + (bl₁ *· ∆*) *⊙* yb + bl₂ *·∆−* e LEnc

(*t*) (*t*) (*t*) (*t*)
= *δ −* e + bl *·∆−* e LEnc *,*

(*t*) (*t*) (*t*)
where the last equality follows from bl *· ∆* = (bl₁ *· ∆*) *⊙* yb +bl₂ *· ∆*, which was shown in the correctness section. Therefore, we get Hyb₁ *≡* Hyb₂.

(*t*)
Hyb₃ Note that Hyb₂ does not make use of bl₂ anymore, but only bl₁ (in LEnc*.*ct and when computing the LEnc error e

(*t*) ). We now use the simulation security of LEnc in order to
eliminate the final usages of bl₁, by simulating LEnc*.*ct and e

(*t*). Specifically, in Hyb₃, we
replace the lines that compute LEnc*.*ct and e

(*t*) by
LEnc ^*.*ct*, {*ee(*t*)*}* [*T*]*←* LEnc*.*Sim(ppLEnc*, {*yb

(*t*) *}*[*T*])*.*
(*t*) (*t*) (*t*) *′*(*t*) is only used as part of the quantity e

|Because e||||+ e|(in the definition of res|) with|
|---|---|---|---|---|---|---|
|(t)|||w|||2|
|LEnc|||LEnc|||c|
||2||||||
||c||||||

LEnc

(*t*) *w′*2*λ*
e being a fresh noise generated from *χ*, we get the indistinguishability Hyb₂ *≈* Hyb₃.

Observe that Hyb₃ proceeds identically as the simulator Sel*.*Sim. By a hybrid argument, we *λ* conclude that Hyb₀ *≈* Hyb₃, which proves the security. *⊓⊔*

D.1 *Random* Batch-Select Lemma 14(Security of Random Batch-Select, Section4.4). *Assuming that the un-* *derlying* LHE *scheme is T -times* 2
*λ* *-simulation secure, and the underlying* LEnc *scheme is* 2 *λ* *-* *simulation secure with T -noise leakage, the Random Batch-Select scheme as described in Sec-* *tion4.4fulfills T -times* *λ* *-simulation security.*

*Proof.* To argue security, we describe a simulator Sim *∗* that first runs the batch-select simulator Sim for our original construction (see proof of Lemma13), and then additionally simulates the rejection sampling results *di,j*and programs the random oracle. It takes as input public parameters pp, messages bl

(*t*), and selection vectors y
(*t*).
## – First, run Sim to obtain

|∗ (t) (t)|(t) (t)|||
|---|---|---|---|
|2 y||[T]||
|λ|||(t)|
||||i,j|
|(t)||||
|i,j||||

(cte₁*, {*LHE ^*.*ct*,*ske*}*) *←* Sim(pp*, {*bl*,* y*}*)*.*

(*t*)
– Next, sample a random seed *←{*0*,*1*}*, and simulate the rejection sampling results *d* as follows. For *t ∈* [*T*], *i ∈* [*w*], *j ∈* [*n*]:

- ** Initially set the number of rejections *d* = 0.
- ** Sample a noise *e ←* [*∆*] and check if

|||e| < ∆/2 − (B||+ B + max χ|(12)|
|---|---|---|---|---|
|||LEnc|LHE||
||(t)|$ p (t)|∗(t)||
|||i,j|||
|(t)|||||
|i,j|(t)|(t)|∗(t)||
|||i,j|(t) y [T]|(t) (i,j t) i∈[w],j∈[n]|

LEnc)*.*

- ** If no, sample a random value *l ←* Z and program
^ *H*(seed*,i,j,d*) := LHE*.*ct₂ [*i,j*] + *l · ∆* + *e* mod *q.*

Increase *d* by 1 and repeat.

- ** If yes, program
^ *H*(seed*,i,j,d*) := LHE*.*ct₂ [*i,j*] + *e* mod *q .*

e e

(*t*) e e
(*t*)
– Finally, output the simulation results (ct₁*, {*ct₂*,*sk*}*), where we choose ct₂ := (seed*,* (*d*)).

We show a series of hybrids that transitions from Hyb₀ (the “real” distribution as defined in Definition8) to Hyb₄ (the “simulated” distribution), focusing on how the rejection results are computed, and how the random oracle is programmed. We abuse the notation to also write Hyb*i* as the output distribution of the corresponding experiment.

Hyb₀: We recall how the rejection results are generated in Hyb₀ (where we surpress the super- script (*t*) in the following for brevity). First, a vector c *∈R* *w* *q*is computed as

c = a *· s₂* + e + eLEnc*, s₂ ←*$ *Rq,* e *← χ* *w* *,* eLEnc*← χ* *w* LEnc*,*

where a is part of the public parameters Sel*.*pp, and a seed is sampled seed *←{*0*,*1*}* *λ*. Finally, an intermediate vector LHE*.*ct *∗* 2is computed as follows. For *i ∈* [*w*], *j ∈* [*n*]: – Initially set the number of rejections *di,j*= 0. – Check whether Equation3is fulfilled (this involves computing *H*(seed*,i,j,di,j*)). – If no, increase *di,j*and repeat. – If yes, set LHE*.*ct *∗* 2 [*i,j*] = *H*(seed*,i,j,di,j*). Finally, the messages bl₂ are computed as bl₂ = *⌊*(LHE*.*ct *∗* 2*−* c)*/∆⌉∈R* *w*

*p*.
Hyb₁: Instead of checking Equation3for the RO-value *H*(seed*,i,j,di,j*), we do so for a random value *r ←*$ Z*q*and then program *H*(seed*,i,j,di,j*) := *r*. Furthermore, we sample the value *r* in the following special (but still uniformly random) way:

*r* := c[*i,j*] + *l · ∆* + *e,* where *l ←*$ Z*p*and *e ←*$ [*∆*]*.*

## We have that Hyb₁ ≡ Hyb₀.

Hyb₂: Note that whether a value *r* passes the check in Equation3only depends on the error *e* but not *l* (both defined in the previous step). Hence, instead of checking Equation3, we will directly check Equation12on error *e*. Further, depending on whether the check is successful, we set *r* differently:

if no: *r* = c[*i,j*] + bl₂[*i,j*] *· ∆* + *l · ∆* + *e, l ←*$ Z*p*

if yes: *r* = c[*i,j*] + bl₂[*i,j*] *· ∆* + *e,*

where l₂ *←R* *w* *q*is a vector sampled only once (for any given *t*) and reused when a check fails and *di,j*is increased. We again have that Hyb₂ *≡* Hyb₁ (because in the no-case *r* looks uniformly random condi- tioned on not passing Equation3, and in the yes-case *r* looks uniformly random conditioned on passing Equation3). Hyb₃: In the previous hybrid, we eliminate the generation of c *∈R* *w* *q*as well as its underlying secret *s₂ ←*$ *Rq*and errors e*,* eLEnc. Furthermore, instead of computing *r* from the term c[*i,j*] + bl₂[*i,j*] *· ∆* as in the previous hybrid, we use the term Sel*.*ct₂[*i,j*]. These values are generated globally using (Sel*.*st₂*,*Sel*.*ct₂) *←* Sel*.*Enc₂(bl₂). Examining the construction of Sel and the underlying construction of LHE, we have that Hyb₃ *≡* Hyb₂. Hyb₄: To summarize, in Hyb₃, the rejection results and programmed entries of the random or- acle are entirely derived from Sel*.*ct₂. Instead of computing Sel*.*ct₂, we can therefore apply simulation security of the original batch-select scheme. In particular, Sel*.*ct₁, Sel*.*ct₂, and sky can all be alternatively generated from Sel*.*Sim(Sel*.*pp*, {*bl

(*t*) *,* y
(*t*) *}*[*T*]). By Lemma13, we get
2 *λ* Hyb₄ *≈*cHyb₃.

Observe that Hyb₄ proceeds identically as the simulated world with simulator Sim *∗*. By a hybrid 2 *λ* argument, we conclude that Hyb₀ *≈*cHyb₄, which proves the security. *⊓⊔*

D.2 Batch-Select Parameter Settings We now prove the claimed efficiencies for the parameter setting in Theorem3(normal batch- select) and in Theorem4(*random* batch-select). *Proof(of Theorem3).* Under the premises of this theorem, both primitives LEnc and LHE un- derlying our batch-select construction fulfill the error bounds as described in Lemmas5and6. Thus, due to *p ≤ q¹*
*/*4, i.e., *∆ ≥ q³* */*4, we get

*√ √ √* <u>1</u> *≤ q <*

|B + B|+ max χ||q + 10|q + 1000|q ≤ ∆/2,|
|---|---|---|---|---|---|
|LEnc|LHE|LEnc|||3/4|
|λ q log|′ wℓ n||λ p log ′ ′|′|60|
||′|||||

and the batch-select construction fulfills correctness (here we used *q ≥* 2). The claimed efficienies follow from those of LEnc and LHE: recall that these two building blocks are applied to dimension *w* =, where *ℓ* = *⌈ ⌉*. Due to log*p* = *Ω*(log*q*) and log*q* = *O*(*λ*), this means *ℓ* = *Θ*(). Each ring element has size *n ·*log*q*, and therefore we get ciphertext sizes

*|*ct₁*|* = *|*LEnc*.*ct*|* + *|*LHE*.*ct₁*|* = *O*((*w* log*w* + *w*) *· n ·* log*q*) = *O*(*w*log *w · λ*) and

*|*ct₂*|* = *|*LHE*.*ct₂*|* = *O*(*w · n · λ*) = *O*(*w · λ*)*,*

and the running time follows in a similar manner. *√* <u>q</u> Weak batch-select with *w* -times simulation security and *|*ct₁*|* = *O*(*w · λ*) follows with our weak LEnc construction. A weak batch-select scheme with 1-time simulation security for modulus *q ≥ ω*((*wλ*) 2 ) with *|*ct₁*|* = *o*(*w*) follows by simply applying the previous weak batch-select scheme in parallel for *k* = *ω*(*λ*) times on smaller instances of size <u>w</u> *k*, which yields *|*ct₁*|* = *O*(*w · λ/k*) = *o*(*w*) due to *w ≤* 2 *λ*. The new secret key sk will contain *k* individual keys of size poly(*λ*) each, and hences its size is still in poly(*λ*). Note that this trick does not change the size of *|*ct₂*|*, because this ciphertext now consists of *k* individual ciphertexts of size *O*( <u>w</u> *k* *· λ*). *⊓⊔*

*Proof(of Theorem4).* Under the given parameters (using *q ≥ n²⁵* instead of *q ≥ n¹⁵*) and log *w ≤* 1*/*25 <u>q</u> 1*/*2 *λ ≤ q*, we get the slightly stronger error bound *B*LEnc+ *B*LHE+ max*χ*LEnc*≤ O*( log*w* ) in a similar manner as in Lemmas5and6. Therefore, due to *∆* = *q/p ≥ q¹* *−ϵ*, the individual rejection <u>q</u> 1*/*2 <u>1</u> probability is *P ≤ O*( *∆·*log*w* ) *≤ O*( *q* 1*/*2*−ϵ*), and the size of *|*ct₂*|* will be, with overwhelming probability, bounded by *O*( log <u>wλ</u> *q* *·* *q* 1*/* <u>1</u> 2*−ϵ*) + poly(*λ*). 2(1+*ε′*)*λ* (2+*ε′*)*λ ε λ′* When *q >* 2 with *∆ ≥* 2 and *p ≤* 2, then rejection only happens with probability *≤ O*(1*/*2 *λ* ), and we may omit ct₂ completely while correctness is satisfied with over- whelming probability. *⊓⊔*

## E Details on Preprocessing Garbling

In this section, we provide the deferred security proofs of our preprocessing garbling scheme (Construction4).

*Proof(of Lemma9).* We describe the simulator SimPrivrequired by Definition14. It takes an offline function *U*, as well as *T* online descriptions *{f*

(*t*) *}* and evaluation results *{*y
(*t*) *}*. It simulates
*T* garblings and input keys as described below.

– First run the standard model garbling simulator to simulate

*C* e *U* *,* ke f *,* ke *←* SG*.*SimPriv(*CU,* y

(*t*) ) *∀t ∈* [*T*]*.*
(*t*) Fn*,*(*t*) (x*t*)
– Next, simulate the batch-select output message vector randomly as

el (res*t*) *←*$ *M* *s* *U* *,*

and apply *T*-times security of Sel to simulate

*λ sU*

||||Sel.pp ← Sel.Setup(1||, 1|),|
|---|---|---|---|---|---|---|
|||(t)|(t)|||(res t) (t)|
||||f||||
|(res t)|′(t) f [i],i|′(t) f [i],i||(res t)|Fn,(t) f||

Sel]*.*ct₁*, {*Sel]*.*ct₂*,*ske

(*t*)*}←* Sel*.*Sim(Sel*.*pp*, {*
el*,* f*}*)*.*

– Finally, simulate the key translation ciphertexts in accordance with the batch-select output el : for the ciphertexts cte

(*t*)that are decodable by the evaluator, we choose ct e
(*t*):= *H*(el [*i*]) + k
e [*i*]*,*

and we sample the remaining ciphertexts uniformly at random:

ct e₁ *−*f(*t*)[*i*]*,i* *←*$ *K .* *′*(*t*)

Output the simulated reusable garbling part *U*brd= (Sel*.*pp*,*Sel]*.*ct₁), and for each iteration b(*t*)e(*t*)]

(*t*) e *′*(*t*) e
*′*(*t*) *t ∈* [*T*] the simulated offline garbling *U* = (*C* *U* *,*Sel*.*ct₂*, {*ct₀*,i,*ct₁*,i}*), online garbling

(*t*)e
(*t*)
e(*t*) hint = skf(*t*), and input keys kx. *A,*0 *A,*1 We show a series of hybrids that transitions from Hyb₀ = Exp Priv

(*λ*) to Hyb₂ = Exp
Priv

(*λ*). We
abuse the notation to also write Hyb*i*as the output distribution of the experiment. *A,*0 *ℓ*x *ℓ*y Hyb₀: We briefly recall the game Exp Priv

(*λ*). *A* selects 1*,*1, an offline function *U*, and T online
descriptions *f*

(*t*) *∈FU*(with bit representations f
(*t*) *∈{*0*,*1*}*
*s*

*U*) and inputs x(*t*)*∈{*0*,*1*}ℓ*x.
The information received by the adversary is indicated through boxed terms.

Sel*.*pp *←* Sel*.*Setup(1 *λ* *,*1 *s* *U* ) l₁ *←*$ *M* *s* *U* (13) Sel*.*ct₁*,*Sel*.*st₁ *←* Sel*.*Enc₁(l₁)

## for t ∈ [T] :

(*t*) (*t*) (*t*)
Sel*.*ct₂*,*Sel*.*st₂ *←* Sel*.*Enc₂(l₂)

(*t*) *sU*
(14) l₂ *←*$ *M*

(*t*) (*t*) (*t*)
sk f

(*t*)*←* Sel*.*KeyGen(Sel*.*st₁*,*Sel*.*st₂*,* f) *C* b *U* *←* SG*.*Garble(*CU,*(K
Fn*,*(*t*) *,* K

(*t*) )) KFn*,*(*t*)*←* SG*.*InputKeyGen(1*λ,*1*sU*)
(*t*)
(15)

(*t*) (*t*) (*t*)K
(*t*) *←* SG*.*InputKeyGen(1
*λ* *,*1 *ℓ* x ) kx= K [x]*.*

*′*(*t*) (*t*) Fn*,*(*t*) ct₀ *,i* := *H*(l₂ [*i*]) + K [*i,*0] (16) *′*(*t*) (*t*) Fn*,*(*t*) ct₁ *,i* := *H*(l₁[*i*] + l₂ [*i*]) + K [*i,*1]

(*t*) (*t*)
Hyb₁: Instead of computing Sel*.*pp*,*Sel*.*ct₁ and *{*Sel*.*ct₂*,*sk f *}* as above (Equation13and14), Hyb₁ simulates them using Sel*.*Sim:

<u>Sel.pp</u> *←* Sel*.*Setup(1 *λ* *,*1 *s* *U* ) l *←*$ *M* *s* *U* 1

(*t*) (*t*) (*t*) *sU*
<u>Sel</u>]<u>.ct₁, {Sel</u>]<u>.ct₂,sk</u>e <u>f</u>

(*t*)<u>}</u>
l₂ *←*$ *M* (17)

(*t*) (*t*) (*t*)
(*t*) (*t*)lres:= l₁ *⊙* f + l₂
*←* Sel*.*Sim(Sel*.*pp*, {*lres*,* f*}*)*.*

The *T*-times simulation security of Sel guarantees that the (boxed) simulated terms are indis- tinguishable from the correctly computed ones. We have *|*Pr[Hyb₁(*λ*) = 1] *−* Pr[Hyb₀(*λ*)] = 1*|≤* negl(*λ*).

(*t*) (*t*)
Hyb₂: Instead of generating l₂res

||and then computing l||from it, we change Equation17in such a|||
|---|---|---|---|---|---|
||$|s (t) res|$ s|||
|||U||||
|′(t)|Fn,(t)|(res t)|Fn ,(t)|Fn,(t)|(t)|
|f [i],i|f||f (t)||(t)|
|′(t)|Fn,(t)|(t)|res|||
|−f [i],i|||(t) res||(t)|

*s* *U*

(*t*) *s* *U*
way that it generates both l₁ *←*$ *M* and el *←*$ *M* uniformly random. Then, we modify Equation16s.t. for any *t ∈* [*T*] and *i ∈* [*s*], the key translation ciphertexts are computed as

ct e

(*t*):= k + *H*(el [*i*]) k := K [*i,*f [*i*]] (18)
( *H*(el [*i*] + l₁[*i*]) if f [*i*] = 0 ct₁(*t*):= K [*i,*1 *−* f [*i*]] + (19) *H*(el [*i*] *−* l₁[*i*]) if f [*i*] = 1

Note that the distribution is unchanged, and we have Hyb₂ *≡* Hyb₁.

Hyb₃: Now we can apply the correlation-robustness of *H*: Instead of computing the “unused” key translation ciphertexts as in Equation19, we simulate it uniformly random:

ct e <u>1−f</u>(*t*)<u>[i],i</u> *←*$ *K* *′*(*t*)

By correlation-robustness of *H* (which may be applied because l₁ *←*$ *M* *s* *U*is used nowhere *′*(*t*) but in the definition of Equation19), the second summand in the definition of ct₁ *−*f(*t*)[*i*]*,i* can *′*(*t*) be replaced by uniformly random. This allows us to equivalently replace ct₁ *−*f(*t*)[*i*]*,i* itself by uniformly random, and therefore we have *|*Pr[Hyb₃(*λ*) = 1] *−* Pr[Hyb₂(*λ*)] = 1*|≤* negl(*λ*). Fn*,*(*t*)b(*t*) (*t*) Hyb₄: Instead of computing k f as in Equation18and *C* *U* *,* kxas in Equation15, Hyb₄ simulates them using SG*.*SimPriv:

(*t*) Fn*,*(*t*) (*t*)

|e e, k|e, k }||||||
|---|---|---|---|---|---|---|
|U f|||(t)|(t)|(t)||
||Priv|U (t) t∈[T]|||||

<u>{C</u> <u>U f x</u> (*t*) (*t*) (*t*) y = *U* (*f,* x) *←* SG*.*Sim (*{C,* y*}*)*.*

By input privacy (Definition15simplified for standard garbling, i.e., *T* = 1 and without RDGen and GarbleFunc), this hybrid is indistinguishable from the previous one: *|*Pr[Hyb₄(*λ*) = 1] *−* Pr[Hyb₃(*λ*)] = 1*|≤* negl(*λ*).

By a hybrid argument, we conclude that *|*Pr[Hyb₄(*λ*) = 1] *−* Pr[Hyb₀(*λ*)] = 1*|≤* negl(*λ*), which proves the theorem. *⊓⊔*

## F Adaptive Security and Malicious 2PC

The purpose of this section is to formulate a stronger adaptive security for batch-select (Defini- tion20) and show that our batch-select scheme (Construction3), unmodified, is adaptively secure if the two ingredients LEnc*,*LHE satisfy approprate adaptive security notions (see SectionsF.1 andF.2for definitions and modified constructions). We then sketch how an adaptively secure batch select scheme (SectionF.3), together with an adaptive standard garbling scheme, results in an adaptive preprocess garbling scheme (SectionF.4). Finally, in SectionF.5we apply the adaptively secure batch select scheme to construct a *T*- session malicious 2PC protocol with a function independent preprocessing phase, and *T succinct* function dependent preprocessing phases. Our construction is a natural application of batch select to the authenticated garbling framework [WRK17,KRRW18,DILO22,CWYY23] for malicious 2PC.

F.1 Adaptive Security of LEnc Definition 18(Adaptive *T*-noise Leakage Simulation Security of LEnc). *A* LEnc *scheme* *is* adaptive *T*-noise leakage simulation secure *w.r.t. a noise distribution χ*LEnc*if there exist two* *efficient simulators* LEnc*.*Sim₁*,*LEnc*.*Sim₂ *such that for any efficient adversary A,*

||A,0|A,1|
|---|---|---|
|A,0 LEnc|LEnc|LEnc|

Pr[Exp (*λ*) = 1] *−* Pr[Exp (*λ*) = 1] *≤* negl(*λ*)*,*

*where the game* Exp (*λ*) *is defined as follows.*

*1. A*(1 *λ* ) *decides a message dimension* 1
*w* *, and receives* pp *←* LEnc*.*Setup(1 *λ* *,w*)*.*

*2. A decides a message vector* s *∈R*
*w* *qand receives* ct*, where*

*If b* = 0 (r*,*ct) *←* LEnc*.*Enc(s)

*If b* = 1 (ct*,*st) *←* LEnc*.*Sim₁(pp)*.*

*3.Repeate the following for t* = 1*,...,T. In the end A outputs a bit b*
*′* *as the outcome of the* *game.*

(*t*) *w* (*t*) (*t*)
– *A decides a database* a*q*

||∈R|and receives a leakage e||+ e|, where|
|---|---|---|---|---|---|
|||q|||LEnc|
|(t)|w||(t)|(t)||
|LEnc||(t)|(t)|a||
|||(t)|a|(t)||

LEnc

(*t*)
e *← χ δ* = LEnc*.*Eval(ct*,* a) *d* = LEnc*.*Digest(a)

*If b* = 0 e = *δ −* r *· d −* s *⊙* a

*If b* = 1 e *←* LEnc*.*Sim₂(st*,* a)*.*

Our original LEnc construction already fulfills adaptivity, assuming the stronger *adaptive* error-leakage Ring-LWE assumption:

Lemma 15(Adaptive security of Construction1). *Assuming* adaptive a*-*elLWE*R,q,χ,χ* LEnc*,T,L*1*,*2*m*(*g*) *,* *Construction1(*LEnc*) fulfills* adaptive simulation security with *T*-noise leakage *(Definition18).*

*Proof.* The proof is similar to that of Lemma10. We naturally split the simulator (previously Sim) into two separate simulators Sim₁ and Sim₂ in the following way:

– Sim₁(pp) samples all ciphertexts purely random

C e *i←*$ *Rq* *w×*2*m* for *i* = 0*,...,ℓ −* 1*,*

and outputs ciphertext cte := (Ce₀*,...,*Ce*ℓ−*1) and state st := pp. – Sim₂(st*,* a

(*t*) ) simulates the noise leakages as follows: sample
E*i←*$ *χ* *w×*2*m* for *i* = 0*,...,ℓ −* 1*,*

and for each ind *∈{*0*,*1*}* *ℓ*, compute

X *ℓ−*1

(*t*)
ee

(*t*) [ind] := E*i*[ind] *·* z
ind: *i* *.* *i*=0

Return ee

(*t*).
The hybrids are the same as before, except that instead of Hyb*i∗,j*outputting the values

(*t*) *D*
((b₀*,*b₁)*,*(C₀*,...,*C*ℓ−*1)*, {*eeres*}*[*T*]), we turn it into an interactive game Hyb*i∗,j*with an adversary

*D*. The adversary first receives (b₀*,*b₁) as in Equation5, then chooses a message vector s and receives ciphertexts (C₀*,...,*C*ℓ−*1) as in Equation6, and finally (for each *t ∈* [*T*]) chooses a
(*t*) (*t*)
database a and receives eeresas in Equation7. In the end it outputs a decision bit. We now show that *|*Pr[Hyb *D* *i* *∗* *,j*= 1] *−* Pr[Hyb *D* *i* *∗* *,j*+1= 1]*|* is negligible for any *i* *∗* *∈* [*ℓ*] and *≤ j < w*. To do so, we construct an adversary *A* for a-elLWE as follows.

– First, *A* receives public parameters b₀*,*b₁ *∈ R* *m* *q*and a Ring-LWE sample y *∈ R²qm*. Pass b₀*,*b₁ *∈R* *m* *q*on to *D* who outputs message vector s *∈R* *w*

*q*.
Then, compute ciphertexts C₀*,...,*C*ℓ−*1as in Hyb*i∗,j*, except for the ind-th row of C*i∗* :

C*i∗*[ind] := y *T* + r*i∗*+1[ind] *·* ind*i∗ ·* g *T* ind*i∗ ·* g *T*

Send ciphertexts C₀*,...,*C*ℓ−*1to *D*.

(*t*) (*t*)
– For each *t ∈* [*T*]: *D* outputs a database a. Use these to compute vectors zprefor any prefix pre *∈{*0*,*1*}* *ℓ*.

(*t*) *T* (*t*)
Submit the leakage matrix (z ind *∗* ) to obtain leakage l[*t*] *∈Rq*. Compute errors eeresas in : *i* Hyb*i∗,j*, except for

X

(*t*) (*t*)
ee

(*t*) [ind] := E*i*[ind] *·* z
ind: *i* and eeres[ind] := ee

(*t*) [ind] + l[*t*]*.*
0*≤i<ℓ* *i̸*=*i∗*

(*t*)
Send eeresto *D*. – Output the same decision bit as *D*.

*A,*0 *D A,*1 As in the proof of Lemma10, we get a-elLWE *R,q,χ,χ,T,L* (*g*) *≡* Hyb*i∗,j*and a-elLWE *R,q,χ,χ,T,L* (*g*) *≡* 1*,*2*m* 1*,*2*m* Hyb *D* *i* *∗* *,j*+1. Thus, by a-elLWE, we get Hyb *D* *i* *∗* *,j≈*cHyb *D* *i* *∗* *,j*+1. By adaptive leakage-error Ring-LWE and the hybrid argument, we get Hyb₀ *≈*cHyb*ℓ*, which concludes the security proof. *⊓⊔*

F.2 Adaptive Security of LHE Definition 19(Adaptive *T*-times Simulation Security of LHE). *An* LHE *scheme is* adap- tive *T*-times simulation secure *if there exist three efficient simulators* LHE*.*Sim₁*,*LHE*.*Sim₂*,*LHE*.*Sim₃ *such that for any efficient adversary A,*
*A,*0 *A,*1 Pr[Exp LHE

(*λ*) = 1] *−* Pr[Exp
LHE

(*λ*) = 1] *≤* negl(*λ*)*,*
*A,*0 *where the game* Exp LHE

(*λ*) *is defined as follows.*
*1. A*(1 *λ* ) *decides a message dimension* 1
*w* *, and receives* pp *←* LHE*.*Setup(1 *λ* *,*1 *w* )*.*

*2. A decides the first message vector* l₁ *∈R*
*w* *qand receives* ct₁*, where*

*If b* = 0 (ct₁*,*st₁) *←* LHE*.*Enc₁(m₁)

*If b* = 1 (ct₁*,*st₁) *←* LHE*.*Sim₁(pp)*.*

*3.Repeated the following for t* = 1*,...,T. In the end A outputs a bit b*
*′* *as the outcome of the* *game.*

(*t*) *w*
– *A decides a second message vector* m₂ *∈Rqand receives* ct₂*, where*

(*t*) (*t*)
*If b* = 0 (ct₂*,*st₂) *←* LHE*.*Enc₂(m₂)

(*t*) (*t*)
*If b* = 1 (ct₂*,*st₂) *←* LHE*.*Sim₂(st₁)*.*

(*t*)
– *A decides an element y ∈Rqand receives* sk*y, where*

|q|y|||
|---|---|---|---|
|( ) yt|(t)|(t)||
|( )|(t) (t)|(t)|(t)|
|yt||res|res|

*If b* = 0 sk *←* LHE*.*KeyGen(st₁*,*st₂*,y*)

(*t*) (*t*)
*If b* = 1 sk *←* LHE*.*Sim₃(st₂*,y,* m)*,* m = m₁ *⊙ y* + m₂*.*

We need to modify our original construction of LHE and add a random oracle *H* in order to obtain adaptivity:

## Construction 6(Adaptive LHE over rings LHE).

|λ w||$ w q||
|---|---|---|---|
||$ m q||$ w×m R,s|

<u>Setup(1,1) → pp</u>: Output a public random matrix pp = a *← R*.

<u>Enc₁(m₁) → ct₁,st₁</u>: Sample Ring-LWE secrets s₁ *← R* and *truncated* noises E *← D*, Output a ciphertext

ct₁ := a *·* s *T* 1+ m₁ *·* g *T* + E *∈R* *w* *q ×m,*

together with state st₁ = s₁. *w* <u>Enc₂(m₂) → ct₂,st₂</u>: Sample a Ring-LWE secret *s₂ ←*$ *Rq*and *truncated* noises e *←*$ *DR,s*. Generate *r ←*$ *{*0*,*1*}* *λ* .Output a ciphertext

ct₂ := a *· s₂* + m₂ + e + *H*(*r*) *∈R* *w* *q,*

together with state st₂ = (s₂*,r*). <u>KeyGen(st₁,st₂,y) → sk</u> *′* <u>y</u> : Parse the states st₁ = s₁ *∈ R* *m* *q*and st₂ = (*s₂ ∈ Rq,r ∈{*0*,*1*}* *λ* ). Output sk *′y* := (sk*y,r*), where sk*y*is the decryption key

sk*y*:= s *T* 1*·* g *−*1

(*y*) + *s₂ ∈Rq.*
## <u>Dec((sky res</u>

|,r), ct₁, ct₂,y) → m|||: First combine the ciphertexts into|||||
|---|---|---|---|---|---|---|---|
|res|y|res res|−1 T 1 −1|res|w q T|−1 y R,q,χ,χ,L|(g)|

ct := ct₁ *·* g (*y*) + ct₂ *− H*(*r*) *∈R,*

// s.t. ct = a *·* (s *·* g (*y*) + *s₂*) + (m₁ *·* g *·* g (*y*) + m₂) + noise

Then, use sk to decrypt and return m = ctres*−* a *·* sk, which is supposed to equal m = m₁ *· y* + m₂ + noise.

Lemma 16(Security of Construction6). *Assuming* a*-*elLWE *×w, Construction2* *T,*1 *(adaptive LHE) fulfills* adaptive *T*-times simulation security *(Definition19) in the Random Or-* *acle Model.*

*Proof.* The proof is analogous to that of Lemma10. The main difference is that we need to additionally handle the term *H*(*r*) used to mask the ciphertext ct₂. The simulator manages the random oracle *H*. Whenever a query is being made (including queries made by the adversary), the simulator answers consistently, sampling random elements upon each query that was never seen before.

## – Sim₁(a) samples ct₁ uniformly random:

ct e₁ *←*$ *Rw* *q ×m*

(*t*)
– Sim₂(st₁) samples ct₂ uniformly random:

ct e *←*$ *Rw* *q* (2*t*)

(*t*) (*t*) (*t*)
– Sim₃(st₂*,y,* mres) first samples the key uniformly random:

sk e *y←*$ *Rq*

(*t*)
Then, it programs the random oracle by choosing *r*

(*t*) *←*$ *{*0*,*1*}*
*λ* and setting

ct e := a *·* sk( *yt* ) + m + (E *·* g *−*1 (*y*

(*t*) ) + e
(*t*) ) *∀t ∈* [*T*]
(res*t*) (res*t*)

(*t*) (*t*)e(*t*)e*−*1 (*t*)
*H*(*r*) := ct₂ *−* (ctres*−* ct₁ *·* g (*y*))*.*

*′y*

(*t*) (*t*)
Return sk f := (ske*y,r*

(*t*) ).
(*t*) (*t*)
Hyb₀ To recall, Hyb₀ generates ciphertexts ct₁*, {*ct₂*}* and decryption keys *{*sk*y}* in the following way:

<u>a</u> *←*$ *R* *m* *q*(20) s₁ *←*$ *R* *m* *q* ct₁ := a *·* s *T* 1+ m₁ *·* g *T* + E *w×m* (21) E *←*$ *DR,s*

For *t ∈* [*T*] :

(*t*)
*s₂ ←*$ *Rq*

(*t*) (*t*) (*t*) (*t*) (*t*) (*t*) *w*
ct₂ := (a *· s₂* + m₂ + e) + *H*(*r*) e *←*$ *D* *R,s* (22)

*r*

(*t*) *←*$ *{*0*,*1*}*
*λ*

() *T −*1 (*t*) (*t*) (*t*) sk*yt*:= s₁ *·* g (*y*) + *s₂*<u>, r</u> (23)

Hyb₁ As a first step, in Hyb₁ we sample the errors E and e

(*t*) as Gaussians from *χ*
*w×m* = *D* *R* *w×* *,sm* *w w,s w×m w* and *χ* = *D* *R*, instead of truncated Gaussians from *DR,s*and *DR,s*, respectively. By Lemma2, we have Hyb₁ *≈*sHyb₀.

(*t*)
Hyb₂ Now, we defer choosing the “actual” value of ct₂ (i.e., its value after removing the mask

(*t*) (*t*) (*t*)
*H*(*r*)) until the adversary has chosen *y*. In particular, we sample ct₂ uniformly at ran- dom, and before revealing *r*

(*t*), we program the random oracle *H* on input *r* in such a way
(*t*) (*t*) (*t*) (*t*) (*t*)
that ct₂ *− H*(*r*) has the value a *· s₂* + m₂ + e as before. Formally,

(*t*) *w*
ct₂ *←*$ *Rq*

(*t*)
() *T −*1 (*t*) (*t*) (*t*) *s₂ ←*$ *Rq* sk*yt*:= s₁ *·* g (*y*) + *s₂*<u>, r</u> *r*

(*t*) *←*$ *{*0*,*1*}*
*λ*

(*t*) (*t*) (*t*)
Furthermore, before sending sk*y*and *r* to the adversary, *H*(*r*) is programmed as follows:

(*t*) (*t*) (*t*) (*t*) (*t*) (*t*) *w*
*H*(*r*) := ct₂ *−* (a *· s₂* + m₂ + e) e *←*$ *χ*

Note that this hybrid Hyb₂ is statistically close to Hyb₁: conditioned on the adversary *A* not querying *H*(*r*

(*t*) ) before the programming step is completed, the two worlds are identical.
Furthermore, the adversary *A* will not query *H*(*r*

(*t*) ) with more than negligible probability,
because *r*

(*t*) is freshly sampled right before programming *H*(*r*
(*t*) ).
Hyb₃ Now we continue in a similar way as in the proof of Lemma12: instead of computing

(*t*) (*t*) (*t*)
*H*(*r*) directly from m₂, we first define the *combined* ciphertext ctres, and then simulate

(*t*) (*t*)
*H*(*r*) as a combination of ctresand ct₁. More, precisely, *H*(*r*

(*t*) ) is programmed as follows:
e

(*t*) *←*$ *χ* *w*
(*t*) (*t*)e(*t*)e*−*1 (*t*)
*H*(*r*) := ct₂ *−* (ctres*−* ct₁ *·* g (*y*))

(*t*) (*t*)
ct e res:= a *·* sk ( *yt* ) + mres+ (E *·* g *−*1 (*y*

(*t*) ) + e
(*t*) )
(*t*) *T −*1 (*t*) (*t*) (*t*) (*t*) (*t*)
By definition of sk*y*= s₁ *·* g (*y*) + *s₂* and mres= m₁ *· y* + m₂, this way of choosing *H*(*r*

(*t*) ) is identical to the previous one. Therefore, we have Hyb₃ *≡* Hyb₂.
(*t*)
Hyb₄ Note that in the previous hybrid, the uniformly random key *s₂* is used nowhere but in

(*t*) *T −*1 (*t*) (*t*)
the definition of sk*y*= s₁ *·* g (*y*) +*s₂*. Therefore, in Hyb₂, we may equivalently generate

<u>sk</u> e <u>y</u>*←*$ *Rq*<u>, r</u>

(*t*) *←*$ *{*0*,*1*}*
*λ*

(*t*) e
(*t*) (*t*)
uniformly random instead of computing sk*y*from *s₂*. We get Hyb₄ *≡* Hyb₃. Hyb₅ In this hybrid, we replace the first ciphertext ct₁ = a *·* s *T* 1+ m₁ *·* g *T* + E by a uniformly generated vector ct e₁ *←*$ *Rw* *q ×m.* We define sub-hybrids Hyb₄*,i*for *i* = 0*,...,m*, where Hyb₄*,i*is identical to Hyb₄, except that the first *i* columns of ct₁ are sampled uniformly random. Note that Hyb₄ *≡* Hyb₄*,*0 and Hyb₄*,m≡* Hyb₅. Therefore, in order to prove Hyb₅ *≈*cHyb₄, it only remains to show Hyb₃*,i−*1*≈*cHyb₃*,i*for *i* = 1*,...,m*. To do so, assume there exists a distinguisher *D* for Hyb₄*,i−*1and Hyb₄*,i*. We construct an adversary *A* for a-elLWE *R,q,χ,χ,T,L* *×w*

(*g*) in the following
1*,*1 way (where *H*-queries by *D* are handled the same way as by our simulator): – First, *A* receives public parameters a *∈ R* *w* *q*and a Ring-LWE sample y *∈ R* *w*

*q*. Pass
pp := a on to *D*, who outputs the first message vector m₁ *∈R* *w*

*q*.
Then, compute the first ciphertext ct₁ as in Hyb₄*,i−*1, except for the *i*-th column, which is chosen to be y. Send ct₁ to *D*.

(*t*) *w*
– For each *t ∈* [*T*]: *D* outputs the second message vector m₂ *∈Rq*.

(*t*) *w* (*t*)
Then, we sample ct₂ *←*$ *Rq*randomly and send ct₂ to *D*, who outputs the element *y*

(*t*) *∈Rq*.
Now, submit the leakage matrix

diag(g *−*1 (*y*

(*t*) )[*i*]*,...,*g
*−*1 (*y*

(*t*) )[*i*])
to the challenger, who outputs leakage l*t*(*this is saying that* l*tis a leakage of the noise* E[:*,i*] *when multiplied with* g *−*1 (*y*

(*t*) )[*i*]).
(*t*) (*t*) *λ*
Then, sample sk*y←*$ *Rq*and *r ←*$ *{*0*,*1*}* randomly (as in Hyb₄), and program

(*t*) (*t*)e(*t*)e*−* (*t*)
*H*(*r*) := ct₂ *−* (ctres*−* ct₁ *·* g (*y*))*,*

(*t*)
where ctresis computed as   (res*t*) (res*t*) X ct e := a *·* sk( *yt* ) + m +  E[:*,i* *′*] *·* g *−*1 (*y*

(*t*) )[*i* *′*] + l*t**.*
*i* *′* *∈*[*m*]*\{i}*

(*t*)
Send (sk*y,r*) to *D*. – Output the same decision bit as *D*. *A,*0 *D A,*1 As in the proof of Lemma12, we get a-elLWE*×w≡* Hyb₄*,i−*1and a-elLWE*×w≡* *R,q,χ,χ,LT,*1(*g*) *R,q,χ,χ,LT,*1(*g*) Hyb *D* 4*,i*. Thus, by a-elLWE, we get Hyb *D* 4*,i−*1*≈*cHyb *D* 4*,i*.

By the hybrid argument, we get Hyb₀ *≈* Hyb₅. Because Hyb₅ is identical to the simulated world, adaptive *T*-times simulation security follows. *⊓⊔*

F.3 Adaptive Security of Batch-Select We now formalize adaptive *T*-times simulation security of the batch-select scheme below. In
(1) (*T*)
contrast to the selective version (Definition6), where the challenge messages l₁*,*l₂*,...,* l₂ and selection vectors y

(1) *,...,*y
(*T*) are decided in one-shot, we now allow an adversary to adaptively
query messages and selection vectors, and receive corresponding ciphertexts and decryption keys immediately.

Definition 20(Adaptive *T*-times Simulation Security of Sel). *A* Sel *scheme is* adaptive *T*-times simulation secure *if there exist three efficient simulators* Sel*.*Sim₁*,*Sel*.*Sim₂*,*Sel*.*Sim₃ *such* *that for any efficient adversary A,*

||A,0|A,1||
|---|---|---|---|
|A,0 Sel|Sel w|Sel|λ w|
|||w||

Pr[Exp (*λ*) = 1] *−* Pr[Exp (*λ*) = 1] *≤* negl(*λ*)*,*

*where the game* Exp (*λ*) *is defined as follows.*

*1. A*(1 *λ* ) *decides a batch size* 1*, and receives* pp *←* Sel*.*Setup(1*,*1)*.*
*2. A decides the first message vector* l₁ *∈M and receives* ct₁*, where*
*If b* = 0 (ct₁*,*st₁) *←* Sel*.*Enc₁(l₁)

*If b* = 1 (ct₁*,*st₁) *←* Sel*.*Sim₁(pp)*.*

*3.Repeated the following for t* = 1*,...,T. In the end A outputs a bit b*
*′* *as the outcome of the* *game.*

||(t)|w||
|---|---|---|---|
|||(t) (t) (t) (t)||
|(t)|w||(t) y|
|(t) y||(t)|(t)|
|(t)||(t) (t) (t)|(t)|
|y||res|res|

– *A decides a second message vector* l₂ *∈M and receives* ct₂*, where*

*If b* = 0 (ct₂*,*st₂) *←* Sel*.*Enc₂(l₂)

*If b* = 1 (ct₂*,*st₂) *←* Sel*.*Sim₂(st₁)*.*

– *A decides a selection vector* y *∈{*0*,*1*} and receives* sk*, where*

*If b* = 0 sk *←* Sel*.*KeyGen(st₁*,*st₂*,* y)

(*t*) (*t*)
*If b* = 1 sk *←* Sel*.*Sim₃(st₂*,* y*,* l)*,* l = l₁ *⊙* y + l₂*.*

It turns out that our original construction, unmodified, is already adaptively secure if the two ingradients LEnc*,*LHE satisfy their respective adaptive security notions (see AppendicesF.1, andF.2). The proof of the following lemma is analogous to Lemma13of selective security. We include the proof in AppendixDfor completeness.

Lemma 17(Adaptive Security of Construction3). *Assuming that the underlying* LHE *scheme is* adaptively *T -times simulation secure, and the underlying* LEnc *scheme is* adaptively *simulation secure with T -noise leakage, our earlier construction for batch select (Construction3)* *fulfills* adaptive *T -times simulation security.*

*Proof.* The simulator is similar to that of Lemma13, but we need to split it into the following three parts:

## – Sel.Sim₁(pp): Run

LEnc ^*.*ct*,*LEnc*.*st *←* LEnc*.*Sim₁(pp LEnc)

LHE ^*.*ct₁*,*LHE*.*st₁ *←* LHE*.*Sim₁(pp LHE)

and output ciphertext cte₁ := (LEnc ^*.*ct*,*LHE ^*.*ct₁) and state st₁ = (LEnc*.*st*,*LHE*.*st₁). – Sel*.*Sim₂(st₁): Run

LHE ^*.*ct₂*,*LHE*.*st₂ *←* LHE*.*Sim₂(LHE*.*st₁)

and output ciphertext cte₂ := LHE ^*.*ct₂ and state st₂ = (LEnc*.*st*,*LHE*.*st₂). – Sel*.*Sim₃(st₂*,* y*,*l): Compute the encoded values yb := Encode(y) and bl := Encode(l). Simulate the LEnc noise and evaluate the laconic encryption *δ*:

## ee ← LEnc.Sim₂(LEnc.st, yb)

## δ ← LEnc.Eval(LEnc ^.ct, yb)

*′*e Then, simulate the output res f of the LHE and accordingly its key skyas follows, where the digest is computed as *d*yb*←* LEnc*.*Digest(yb):

*w′* e *←*$ *χ*LEnc *′* res f := *δ −* ee + bl *·∆−* e

sk e y*←* LHE*.*Sim₃(LHE*.*st₂*,*res f*,d*yb) *′*

## Output skey.

We use an analogous series of hybrid experiments that transitions from Hyb₀ (the “real” distribution as defined in Definition6) to Hyb₃ (the “simulated” distribution). We abuse notation to also write Hyb*i*as the output of the distribution of the corresponding experiment.

Hyb₀ To recall, Hyb₀ (omitting generation of public parameters pp) computes in the first phase

(*t*)
ct₁ = (LEnc*.*ct*,*LHE*.*ct₁), and in the second phase, for each *t ∈* [*T*], (1) LHE*.*ct₂, and

(*t*)
(2) sk, in the following way (where, as in the construction, we define the digests *d*yb:= y(*t*)
(*t*)
LEnc*.*Digest(yb), and encoded values bl₁ := Encode(l₁) and bl₂ := Encode(l₂)):

## r, LEnc.ct ← LEnc.Enc(bl₁ · ∆)

## LHE.ct₁,st₁ ← LHE.Enc₁(r)

## For t ∈ [T] :

(*t*) (*t*) (*t*) (*t*) (*t*) *w′*
LHE*.*ct₂*,*sk₂ *←* LHE*.*Enc₂(bl₂ *·∆−* e) e *←*$ *χ* LEnc LEnc

|(t)|(t) (t)||||
|---|---|---|---|---|
|y|y b||||

sk(*t*)*←* LHE*.*KeyGen(sk₁*,*sk₂*,d*)

Hyb₁ We now use the *adaptive* simulation security of LHE to replace generation of LHE ^*.*ct₁,

(*t*) (*t*)
*{*LHE ^*.*ct₂*,*skey(*t*)*}*[*T*](i.e., the final three lines in Hyb₀) by the following:

## LHE ^.ct₁,LHE.st₁ ← LHE.Sim₁(LHE.pp)

## For t ∈ [T] :

(*t*)
(*t*)
LHE ^*.*ct₂*,*LHE*.*st₂ *←* LHE*.*Sim₂(LHE*.*st₁)

(*t*) *w′*
(*t*) (*t*) (*t*)e *←*$ *χ*LEnc
*′*(*t*) LEnc ske y(*t*) *←* LHE*.*Sim(LHE*.*st₂*,d*yb*,*res)*′*(*t*) (*t*) (*t*) (*t*) res *←* r *· d* + lb *·∆−* e yb 2 LEnc

The indistinguishability Hyb₀ *≈*cHyb₁ follows directly from the adaptive *T*-times simulation security of LHE. *′*(*t*) Hyb₂ In Hyb₂, we now rewrite res as

(*t*) (*t*)
*δ ←* LEnc*.*Eval(LEnc*.*ct*,* yb) *∀i ∈* [*T*]

(*t*) (*t*) (*t*) (*t*)
e := *δ −* (r *· d −* (bl₁ *· ∆*) *⊙* yb) yb *′*(*t*) (*t*) (*t*) (*t*) (*t*) res *← δ −* e + bl *·∆−* e *∀t ∈* [*T*] LEnc

(*t*)
Note that e denotes the LEnc “evaluation error”, i.e., the difference between the expected

(*t*) (*t*) (*t*)
result r *· d −* (bl₁ *· ∆*) *⊙* yb and the noisy outcome *δ*. yb As in the proof of Lemma13, we have Hyb₁ *≡* Hyb₂.

(*t*)
Hyb₃ Note that Hyb₂ does not make use of bl₂ anymore, but only bl₁ (in LEnc*.*ct and when

(*t*)
computing the LEnc error e). We now use the simulation security of LEnc in order to

(*t*)
eliminate the final usages of bl₁, by simulating LEnc*.*ct and e. Specifically, in Hyb₃, we replace the computation of r and LEnc*.*ct by the simulation

LEnc*.*st*,*LEnc ^*.*ct *←* LEnc*.*Sim₁(ppLEnc)*,*

(*t*)
and the computation of the noise e by the simulation

(*t*) (*t*)
ee *←* LEnc*.*Sim₂(LEnc*.*st*,* yb)

|(t)||(t) (t)|′(t)|
|---|---|---|---|
|||LEnc||
|(t)|w|||
|LEnc|||c|

Because e is only used as part of the quantity e + e (in the definition of res) with *′* e being a fresh noise generated from *χ*, we get the indistinguishability Hyb₂ *≈* Hyb₃.

Observe that Hyb₃ proceeds identically as the simulated world. By a hybrid argument, we con- clude that Hyb₀ *≈*cHyb₃, which proves the security. *⊓⊔*

F.4 Adaptive Security of Preprocessing Garbling In this section, we sketch a simple way of achieving *adaptive T*-times input privacy for prepro- cessing garbling in the RO model, assuming a batch-select that fulfills adaptive security as above, and an adaptively secure garbling scheme in the standard model. First, we need to modify the preprocessing garbling interface (Definition14) slightly: GarbleFunc(st*,f*) *→* hint*,d* will output some output decoding information *d* in addition to the hint. Furthermore, Eval(*f, U*brd*, U,*b hint*,* kx*,d*) utilizes this decoding information for evaluating the circuit. Defining Adaptive *T*-times Input Privacy. In contrast to standard *T*-times input privacy (Definition15), the adversary can now choose the online descriptions *f*
(*t*) and inputs x *∈{*0*,*1*}*
*ℓ* x

## one after another:

1.The adversary only selects 1
*ℓ* x *,*1 *ℓ* yand the offline function *U ∈ U* *ℓ* x *,ℓ*y. It receives *U* b rdand *{U*b

(*t*) *}*, generated in the real resp. simulated world as follows:
## (Ubrd,strd) ← RDGen(U)

K

(*t*) *←* InputKeyGen(1
*λ* *,*1 *ℓ* x ) or *U* b rd*, {U* b(*t*)*}←* Sim Priv(*U*)*.*

(*U*b

(*t*) *,*st
(*t*) ) *←* GarbleU(strd*,* K
(*t*) )
2.Then, for each *t ∈* [*T*]: – The adversary chooses the online description *f*
(*t*), and receives the hint
(*t*), generated in
the real resp. simulated world as follows:

hint

(*t*) *,d*
(*t*) *←* GarbleFunc(st
(*t*) *,f*
(*t*) ) or hint
(*t*) *←* SimPriv(*f*
(*t*) )*.*
(*t*) *ℓ*x(*t*)
– The adversary chooses the input x *∈ {*0*,*1*}*, and receives the input labels kxand input decoding *d* generated in the real resp. simulated world as follows:

(*t*) (*t*) (*t*) (*t*) (*t*) (*t*) (*t*)
kx= K [x] or kx*,d ←* SimPriv(*U* (*f,* x))*.*

For a *standard* garbling scheme (without separate preprocessing phase or *T*-reusability) to fulfill adaptive input privacy, the definition above is simplified towards *T* = 1 and skipping the second stage (since the online description *f*

(*t*) does not contain any information).
Modifying the Preprocessing Garbling Scheme. In the adaptive security game above, note that with our plain preprocessing garbling scheme (Construction4), the adversary would be able to view the function’s input labels k Fn f to the garbling *C*b*U*already after selecting the online description *f*

(*t*). However, it may adaptively choose the input x
(*t*) after this step. Therefore, we
cannot apply (adaptive) SG input privacy to show our scheme secure. Instead, we will modify Construction4slightly. We account for the issue above by hiding k Fn f until the adversary has received the decoding information *d* in the final step. Specifically, we require the hash function *H* used for key translation (which previously just needed to ful- fill correlation-robustness) to be a Random Oracle, and modify the scheme’s algorithms in the following way.

– In GarbleU, we generate an additional seed *←*$ *M* *s* *U*, which is used for computing the key translation ciphertexts

ct *′* 0*,i*:= *H*(l₂[*i*]+ seed) + K Fn [*i,*0]

ct *′* 1*,i*:= *H*(l₁[*i*] + l₂[*i*]+ seed) + K Fn [*i,*1]

– GarbleFunc additionally outputs the decoding information, which is exactly the seed: *d* := seed. – Eval replaces its computation of the function’s input labels by

k Fn f[*i*] := ct *′* f [*i*]*,i* *− H*(lres[*i*]+ seed)*.*

Proving Adaptive *T*-times Input Privacy. In the security game for the scheme described above, the function’s input labels k Fn f to the garbling *C*b*U*of the universal circuit are effectively hidden by seed until the adversary also receives the remaining input labels kx. We now sketch how to show security, assuming that the underlying scheme SG satisfies adaptive privacy, the batch-select scheme Sel satisfies adaptive security, and *H* is a programmable random oracle. The three stages of our simulator will be as follows:

– SimPriv(*U*) simulates the reusable part of the garbling as *U*brd= (Sel*.*pp*,*Sel*.*ct₁), where

Sel*.*pp *←* Sel*.*Setup(1 *λ* *,*1 *s* *U* )*,* (Sel*.*st₁*,*Sel]*.*ct₁) *←* Sel*.*Sim₁(Sel*.*pp)*.*

b(*t*)e(*t*)^ e *′*(*t*) e *′*(*t*) It also simulates the non-reusable offline garblings *U* := (*C* *U* *,*Sel*.*ct₂*, {*ct₀*,i,*ct₁*,i}*), where

(*t*) SG (*t*) (*t*) *′*(*t*) *′*(*t*)

|b C ← Sim|.Sim(C|), (Sel.st₂|], Sel.ct₂|) ← Sel.Sim₂(Sel.st₁),||e₁, ct|← K|
|---|---|---|---|---|---|---|---|
|U|Priv|U||||,i ,i|$|
|(t)||||||(t)||
|Priv||(t) f||(t) (t)|(t) res|f||
|res (t)|$ s|||||||
|Priv||Fn,(t) f|(t) x|SG Priv||||
 *U* Priv *U*
ct e₀ *,i,i* $

e – Sim (*f*) then uses the final batch-select simulator to simulate the hint := sk (*t*) as

sk e

(*t*) *←* Sel*.*Sim₃(Sel*.*st₂*,* f*,*lf)*,*
where lf *← MU*is uniformly random. – Sim (y) then runs the standard garbling simulator to obtain the input keys

## k(t), k ← Sim.Sim(y).

It programs the random oracle to “fix” the decodable key translation ciphertext:

(*t*) *′*(*t*) (*t*)

|H (el [i] + seed) := ct||− k [i]|∀i ∈ [s]|
|---|---|---|---|
|res|f [i],i|f|U|
|$ s|||(t) x|
 res
f Fn*,*(*t*)[*i*]*,i* f(*t*) *U*

*U* for some random seed *← M*. Then, it outputs input keys k and decoding information *d* := seed.

The hybrids are very similar to that in the proof of Lemma9.

– First, starting from the real world, we replace the outputs of the batch-select scheme Sel by

(*t*)
its simulations. This eliminates the need to know messages l₁ and l₂ : simulation of Sel*.*ct₁

(*t*)
and Sel*.*ct₂ happens in the first stage of the game, and simulation of sk f

(*t*)happens in the
(*t*) (*t*)
second stage, for which only the “visible” messages lres:= l₁ *⊙* f + l₂ are required.

– Second, we also modify generation of the key translation ciphertexts, in such a way that it

||res $|s||
|---|---|---|---|
|′(t)|(res t)||Fn,(t)|
|f [i],i|||f|
|′(t) −f [i],i|$|||

only depends on a uniformly random l *← MU*(there is no usage of individual messages

(*t*)
l₁ and l₂ anymore):

ct e

(*t*):= *H*(el [*i*] + seed) + k
e [*i*]

ct e₁

(*t*)*← K*
We can do so because *H* is a random oracle, and therefore it is unlikely that the adversary will ever query *H* on two inputs that differ in exactly l₁. – Now we can use the RO properties to delay choosing the key translation ciphertexts until the e *′*(*t*) final phase where the output y is known: we generate ct f

(*t*)[*i*]*,i←*$ *K* uniformly random, and

|||f [i],i|
|---|---|---|
|(t)|′(t)|Fn,(t)|
|res|f [i],i|f|

in the final phase we program

e e *H*(el [*i*] + seed) := ct(*t*)*−* k [*i*]*.*

This is indistinguishable from the previous hybrid, because seed is completely hidden from

(*t*)
the adversary, so it is unlikely that it will query elres[*i*] + seed before this programming step. Fn*,*(*t*) – Finally, the function’s input labels k f

(*t*)are not used until the final stage (where the output
y is known) to program *H*. Therefore, we may use adaptive input privacy of the garbling of

|(t)|||Fn,(t)|
|---|---|---|---|
|U|(t) U|SG Priv|f|
|Fn,(t)|(t)|SG||
|f|x|Priv||

b(*t*) the universal circuit to replace *C* (computed in the first stage) and input labels k(*t*)*,* kx (computed in the final stage) by

*C* b *←* Sim*.*Sim(*C*

*U*)
## k(t), k ← Sim.Sim(y)

F.5 Preprocessing *T*-Session Malicious 2PC In this section, we construct a protocol, in the random oracle model, realizing the *T*-session 2PC functionality (Figure1) against malicious adversaries. The protocol has a instance-independent preprocessing phase, where Alice and Bob know only an upper bound *sU*of the function discrip- tion length, with amortized *O*(*λ · sU*) bits of communication. In each session, it has a succinct function dependent preprocessing phase with poly(*λ*) bits of communication, and an online phase with with *ℓ*x*A*+ *ℓ*x*B*+ poly(*λ*) bits of communication. We will first recall and summarize the authenticated garbling framework of [WRK17,DILO22] for malicious 2PC protocols, and then describe how to achieve succinct function dependent and online phases with our *adaptively* secure batch select scheme in the framework. The Authenticated Garbling Framework. The framework has three main steps, which we summarize below. While the original framework considers evaluating a target circuit *C* with two private inputs x*A,* x*B*from Alice and Bob, it can be easily extended to support circuits with an additional *public* input x*P*that’s only known at the input step together with x*A,* x*B*. Preprocessing: Alice and Bob jointly run a sub-protocol AuthGarb
*C* (Figure3), parameterized by the target circuit *C*. – Alice obtains input keys K*P,* <u>K</u>*A,* K*B*, an input mask a*I*, and decryption information *D*. – Bob obtains a garbled circuit *C* and an input mask b*I*. Input:

*T,sU* Functionality *F* 2PC For *t* = 1*,...,T*:

(*t*) (*t*) (*t*) (*t*) (*t*) (*t*)
– Upon receiving (*t,f* *A* *,* x *A* ) from Alice or (*t,f* *B* *,* x *B* ) from Bob, leak *f* *A* or *f* *B* to the adversary. – After receiving inputs from both Alice and Bob:

(*t*) (*t*) (*t*) (*t*)
1.If *f* *A* or *f*
*B* has description length more than *sU*, or if *f* *A* *̸*= *f* *B*, output *⊥* to Bob and abort.

(*t*) (*t*) (*t*)
<u>2.Otherwise, output ∅ to Alice and (t,f</u>
<u>A</u> <u>(x</u> <u>A</u> <u>, x</u> <u>B</u> <u>)) to Bob.</u>

## Fig.1: The T-session 2PC functionality.

1.Bob masks his input x*B*= x*B⊕* b*I*, and sends x*B*to Alice.
2.Alice masks her input x*A*= x*A⊕* a*I*and selects input labels according to the inputs, k*P*= K*P P A A A B B B P A B A*

|[x], k|= K [x] k|= K|[x]. Alice sends D, k||, k, k|, x to Bob.|
|---|---|---|---|---|---|---|
|P P|A A|B|B B||P A|B A|
|C|P A B|P A|B||||
|||||C|||

Output: Bob locally runs an evaluation algorithm AuthEval (Figure4) and outputs the result y *←* AuthEval (*C,D,*k*,* k*,* k*,* x*,* x*,* x).

For completeness, we recreate the sub-protocol AuthGarb and the evaluation algorithm AuthEval *C*

in Figures3and4. In [DILO22], the authors showed that the preprocessing step, i.e. the AuthGarb sub-protocol, can be realized in constant rounds and with *O*(*|C|·* (*λ* + *κ*)) bits of communication using pseu- dorandom correlation generators (PCG) for vector oblivious linear evaluation [BCGI18,CRR21] (VOLE) and multiplication triples [BCG + 20] (MT) correlations. We refer to [DILO22] for more details. Minimizing Function Dependent Communication Using Batch Select. The idea is ana- loguous to how we minimize the function dependent garbling size in our preprocessing garbling construction. In an instance *independent* offline phase, Alice and Bob run the AuthGarb sub-protocol on a universal circuit *U* that takes a function description *f* (of bounded length *sU*) as the public input, and two inputs x*A*, x*B*from Alice and Bob. In the function *dependent* offline phase, it remains for Alice to transmit the input labels selected by the target function descriptoin *f* to Bob. Our batch select scheme lets Alice achieve this succinctly, with poly(*λ*) bits. Applying the same idea for the input labels selected by Alice’s and Bob’s inputs also reduces the online phase communication to poly(*λ*) bits. We illustrate the modified protocol below. For simplicity, we assume here a batch select scheme Sel with matching message space to encrypt the input labels.

Instance Independent Offline:

1.Alice and Bob jointly run the sub-protocol AuthGarb
*U*, w.r.t. a universal circuit *U*. – Alice gets input keys K*P,* <u>K</u>*A,* K*B*, an input mask a*I*, and decryption information *D*. – Bob gets a garbled circuit *U* and an input mask b*I*.

2.Alice encrypts the input keys using batch select as follows, and the decryption information using a random oracle ct*O*= *D⊕H*(seed), (st*P,,*Sel*.*ct*P,*) *←* Sel*.*Enc(K*P*[1] *−* K*P*[0])*,* (st*P,,*Sel*.*ct*P,*) *←* Sel*.*Enc(K*P*[0])*,* (st*I,,*Sel*.*ct*I,*) *←* Sel*.*Enc(K*I*[1] *−* K*I*[0])*,* (st*I,,*Sel*.*ct*I,*) *←* Sel*.*Enc(K*I*[0])*,*

where K, Sel*.*ct

|:= K|∥ K|, and seed ←{0, 1}|. Alice sends the ciphertexts Sel.ct||||,|
|---|---|---|---|---|---|---|---|
|I|A B||λ|||P,1|P,2|
|I,1|I,2 O|B A A|P B I I|P|P,1 P,1|P,2 P,2|I|
||I,1 I,2|A B||A I||||
||||A B|||||

Sel*.*ct, Sel*.*ct, ct to Bob. Function Dependent Offline:

1.Alice computes and sends a decryption key sk *←* Sel*.*KeyGen(st*,*st*,f*) to Bob.
2.Bob locally decrypts input labels for *f*, k *←* Sel*.*Dec(sk*P,*Sel*.*ct*,*Sel*.*ct*,f*).
Online:

1.Bob masks his masked input x = x *⊕* b to Alice.
2.Alice masks her input x = x *⊕* a and computes a decryption key accordingly: sk *←* Sel*.*KeyGen(st*,*st*,* x *∥* x). Alice sends x, sk, seed to Bob.
3.Bob locally decrypts input labels for k*,* k, output information *D*, and runs the evalu- ation algorithm to recover the result as in the original framework.
Amortizing the Instance Independent Offline Phase. While achieving succinct instance dependent and online phases, the above solution incurs an overhead to the instance independent phase. First, Alice and Bob runs the sub-protocol AuthGarb on a universal circuit *U*, which is at least *O*(log *|f |*) times larger than the actual target circuit *f*. Second, the first batch select ciphertext Sel*.*ct*P,*1is concretely much larger than the authenticated garbling size of the universal circuit *U*. (The cost of sending Sel*.*ct*P,*2and the public parameters Sel*.*pp are concretely similar to sending *U*.) Fortunately our batch select scheme allows re-using Sel*.*ct*P,*1upto *T* times. We leverage this reusability to amortize the communication overhead of sending Sel*.*ct*P,*1, and construct a *T*- session 2PC protocol. When *T* = *Ω*(log *|f |*), the amortized function independent preprocessing takes *O*(*λ ·|f |* log *|f |*) = *O*(*λ · sU*) bits of communication. We describe our *T*-session 2PC protocol in Figure2. The ingradients to the protocol are:

– the AuthGarb sub-protocol (Figure3), and the evaluation algorithm AuthEval (Figure4) from the authenticated garbling framework. – a batch select scheme Sel with message space *M* and adaptive *T*-times simulation security; – two random oracles *H* : *{*0*,*1*}* *λ* *→{*0*,*1*}* *∗*, *H* *′* : *M→{*0*,*1*}* *λ*.

The communication costs of the protocol are:

– *O*(*T · λ · sU*) bits in the instance independent offline phase; – poly(*λ*) in each function dependent offline phase; – *ℓ*x*A*+ *ℓ*x*B*+ poly(*λ*) bits in each online phase.

Theorem 5. *Let λ be the computational security parameter, and sU*= poly(*λ*) *be an upper* *bound on target circuits’ description length. Assuming the underlying batch select scheme* Sel *has adaptive T -times simulation security, the protocol* 2PC *T,sU* *UC-realizes the T -session 2PC* *T,sU* *functionality F* 2PC *in the F*pre*-hybrid model and in the random oracel (RO) model, the presence* *of malicious adversaries who statically corrupt one of the participants.*

Before proving Theorem5, we briefly recap the UC framework.

Overview of the Universal Composibility (UC) Framework The UC framework [Can01] *T,sUT,sU* captures the security of the protocol 2PC with an ideal functionality *F* 2PC. The functionality defines an ideal protocol execution, where an environment *Z* provides inputs to and reads outputs from the two parties. And the parties simply forward their inputs to and receive outputs from *F*2PCas specified in Figure1.

2PC *T,sU*

## Function Independent Offline Phase:

1.Alice and Bob run *T* instances of the sub-protocol AuthGarb
*U* in parallel, where *U* : *{*0*,*1*}* *s* *U×* *{*0*,*1*}* *ℓ* x*A×{*0*,*1*}ℓ*x*B→ {*0*,*1*}ℓ*yis a universal circuit accepting function descriptions of size

bounded by *sU*. For each *t ∈* [*T*]:

(*t*) (*t*) (*t*) (*t*) (*t*)
– Alice obtains input labels K *P* *,* K *A* *,* K *B* masks a *I*, and decryption information *D*.

(*t*) (*t*)
– Bob obtains authenticated garblings *U* and masks b *I*.

(*t*) (*t*)
2.Alice first encrypts the labels for public inputs into ct*P*= (Sel*.*pp*P*, ct*P,*1, *{*ct
*P,*2 *}*, *{*ct *P,i,b* *}*): *s* *U*

(*t*) *s* *U*
– Sample l₁ *←M*, and l₂ *←M* for *t ∈* [*T*], and compute

(*t*) *′* (*t*) (*t*)
*∀i ∈* [*sU*]*,t ∈* [*T*] ct *P,i,b* = *H* (l₁[*i*] *· b* + l₂ [*i*]) *⊕* K *P* [*i,b*]*,*

– Run Sel*.*pp*P←* Sel*.*Setup(1 *λ* *,*1 *s*

*U*) and compute
(*t*) (*t*) (*t*)
(st*P,*1*,*Sel*.*ct*P,*1) *←* Sel*.*Enc₁(l₁)*,* (st *P,*2 *,*Sel*.*ct *P,*2 ) *←* Sel*.*Enc₂(l₂) *∀t ∈* [*T*]*.*

Alice then analogously encrypts the labels for private inputs into ct*I*(with another instance

(*t*) (*t*) (*t*)
of batch select), and the decryption information into ct *O* = *D ⊕ H*(seed) using random

(*t*)
seeds. Alice sends ct*P,*ct*I, {*ct *O* *}* to Bob.

## t-th Funtion Dependent Offline Phase:

(*t*)
1.Alice sends a batch select decryption key sk
*P* computed as follows to Bob.

|(t)|||(t) (t)|||
|---|---|---|---|---|---|
|P (t) P||P,1|P,2 A|||
|(t)||(t) (t)|(t)|(t)|′ (t)|
|P|P,1|P,2 B|P|P,i,f||

## sk ← Sel.KeyGen(st,st,f).

2.Bob locally decrypts labels k, where
(*t*) l *←* Sel*.*Dec(sk*,*Sel*.*ct*,*Sel*.*ct*,f*)*,* k [*i*] = ct
*B,i* *⊕ H* (l [*i*])*.* (24)

*t*-th Online Phase:

(*t*) (*t*) (*t*)
1.Bob sends x
*B* = b *I* *⊕* x *B* to Alice.

(*t*) (*t*) (*t*)
2.Alice sends x
*A* *,*sk *I* *,*seed to Bob, where

(*t*) (*t*) (*t*) (*t*) (*t*) (*t*) (*t*)
sk *I* *←* Sel*.*KeyGen(st*I,*1*,*st *I,*2 *,* x *A* *∥* x *B* )*,* x *A* = a *I* *⊕* x *A* *,*

(*t*) (*t*)
3.Bob locally recover labels k
*A* *,* k *B* (analogously to Equation24) and decryption information

|(t)|(t)|||||U (t)|(t)|(t) (t)|(t)||
|---|---|---|---|---|---|---|---|---|---|---|
|O||||||||P A|B B|A B|

(*t*) (*t*) (*t*) *U* (*t*) (*t*) (*t*) (*t*) (*t*)
<u>D = ct ⊕ H(seed), and evaluates y = AuthEval (U,D, k, k, k,C, x, x).</u>

Fig.2: Our preprocessing *T*-session malicious 2PC protocol.

The ideal adversary/simulator Sim lets *F*2PCknow of a corrupted party in the beginning, and then interacts with *F*2PCaccording to the corresponding adversarial interface. In additional

to explicitly specified adversarial interfaces, Sim receives all messages sent to and determins all outgoing messages from the corrupted party. The environment *Z* communicates with Sim freely throughout the protocol execution. To prove the security of the protocol 2PC, we show that the ideal protocol specified above *emulates* a real protocol execution with an adversary *A* controlling a corrutped party, the honest party, and the environment *Z*. We describe the real protocol execution, and the meaning of emulation below. In the real protocol execution, the environment *Z* provides inputs to and reads outputs from the actual protocol participants. An adversary *A* decides a corrupted party in the beginning, and controls them throughout the protocol. The environment *Z* also communicates with *A* freely throughout the protocol execution. We say that an ideal protocol execution with an ideal adversary Sim emulates a real protocol execution with an adversary *A*, if no environment *Z* can tell whether it’s interacting in the ideal *T,sUT,sU* or the real protocol. We say the protocol 2PC UC-realizes the functionality *F* 2PC if for all efficient adversary *A*, there exists an efficient ideal adversary Sim such that the ideal protocol with Sim emulates the real protocol with *A*. Formally, let IDEAL *T,sU* and Real 2PC *T,sU* *,A,Z* denotes the output of an environment *F*2PC*,*Sim*,Z* after interacting in the ideal and the real protocol. We require that for all efficient *A*, there exists an efficient Sim such that for all efficient *Z*:

IDEAL *T,sU ≈c*Real 2PC *T,sU* *,A,Z* *.* *F*2PC*,*Sim*,Z*

The UC framework allows for a modular presentation of protocols, thanks to the universal composition theorem. Consider an inner protocol *π*inthat UC-realizes an inner functionality *F*in, and an outer protocol *π*outthat has access to copies of *F*in, i.e., in a *F*in-hybrid model, and UC- realizes another outer functionality *F*out. The composition theorem ensures the composition of *π*outand *π*in, i.e., replacing each copy of *F*inwith an instance of *π*i, still UC-realizes *F*out.

Proof of Theorem5 We describe an ideal adversary Sim that externally interacts with the functionality *F*2PCand the environment *Z*, while internally simulates a protocol execution with an instance of the adversary *A*. When interacting with *Z*, Sim simply forwards all communication between *A* and *Z*. We consider separately the case when Alice or Bob is corrupted. <u>When Bob is Corrupted.</u> Sim proceed as follows.

Instance Independent Offline Phase: – Sim plays the role of *F*prewith Bob following its description (Figure5). In the process, *λ* (*t*) Sim samples its own global MAC key *∆A←{*0*,*1*}*, input masks a *I*, and output masks (*w,t*) (*w,t*) *κ* *{a}w∈O*and tags *{M* *A* *}w∈O*. It also receives Bob’s global MAC key *∆B∈{*0*,*1*}*

(*t*)
and input masks b *I*. – Sim follows the description of AuthGarb (Figure3) to compute and send garbled tables to

(*t*) (*t*) (*t*)
Bob. In the process, Sim samples and stores input labels K *P* *,* K *A* *,* K *B*. – Sim runs the (stateful) simulator Sel*.*Sim to simulate the batch select ciphertexts ct*P*=

(*t*) (*t*)
(Sel*.*pp*P,*Sel*.*ct*P,*1*, {*Sel*.*ct *P,*2 *}, {*ct *P,i,b* *}*) for public inputs:

Sel*.*pp*P←* Sel*.*Setup(1 *λ* *,*1 *s* *U* )*,* Sel*.*ct*P,*1*←* Sel*.*Sim(Sel*.*pp*P*)*,*

(*t*)
Sel*.*ct *P,* *←* Sel*.*Sim() for *t ∈* [*T*]*,*

(*t*)
and then compute the ciphertexts *{*ct *i,b* *}* honestly:

*s* *U*(*t*) *sU* l *P,*1*←M,* l*P,*2*←M ∀t ∈* [*T*]

(*t*) (*t*) (*t*)
ct *P,i,b* = *H*(l*P,*1[*i*] *· b* + l *P,*2 [*i*]) *⊕* L *P* [*i,b*]*, ∀i ∈* [*sU*]*,t ∈* [*T*]

It analogously simulates the ciphertexts ct*I*for private inputs, and then the ciphertext

(*t*)
for decryption information at random ct *O* *←* $.

(*t*)
It sends honestly computed public parameters Sel*.*pp, ciphertexts *{*ct *i,b* *}* and the simulated

(*t*)
ciphertexts Sel*.*ct₁, *{*Sel*.*ct₂*}* to Bob. *t*-th Function Dependent Offline Phase: In order to simulate the *t*-th batch select decryp-

(*t*)
tion key, Sim waits for the functionality *F*2PCto leak the target circuit *f* *A*, and runs the (stateful) simulator Sel*.*Sim:

(*t*) (*t*) (*t*)
sk *P* *←* Sel*.*Sim(l*P,*1*⊙ f* *A* + l *P,*2 )*.*

(*t*)
It sends the simulated decryption key sk *P* to Bob. *t*-th Online Phase:

(*t*) (*t*)
– Sim receives masked inputs x*B*from Bob, and extracts the actual input x *B* = x*B⊕* b *I*.

(*t*) (*t*)
Sim then sends a message (*t,f* *A* *,* x *B* ) to the functionality *F*2PC.

(*t*)
– Sim simulates the masked inputs from Alice as x*A*= a *I* *⊕* 0, and the batch select

(*t*)
decryption key sk *I* as

(*t*) (*t*)
sk *I* *←* Sel*.*Sim(l*I,*1*⊙* x*A∥* x*B*+ l *I,*2 )*.*

– In order to simulate the decryption information *D*

(*t*), Sim waits for the functionality to
reveal the evaluation result y

(*t*), and program *D*
(*t*) so that evaluation on the simulated
input labels correctly reveals y

(*t*). Sim first computes a difference vector
(*t*) (*t*)
*δ* = *fA*(0*,* x *B* ) *⊕* y*,*

(*w,t*) (*w,t*) and then adjusts Alice’s bits *a* and tags *M* *A* on output wires: (We abuse notations to write *δ*[*w*] to mean the difference bit in *δ* corresponding to the output wire *w ∈ O*.)

(*w,t*) (*w,t*) (*w,t*) (*w,t*) *∀w ∈ O,* if *δ*[*w*] = 1*, a ← a ⊕* 1*, M* *A* *← M* *A* *⊕ ∆B.*

(*t*) (*w,t*) (*w,t*) (*t*)
Sim sets *D*

|= {a|,M|}, samples a random seed|, and programs the random||
|---|---|---|---|---|
||A|w∈O|||
|(t)|(t) O|(t)|(t) (t) A I|(t)|

*A w∈O*

(*t*) (*t*) (*t*)
oracle *H*(seed) *←* ct *⊕ D*. Finally, Sim sends x, sk, and seed to Bob.

It remains to show the output of any environment *Z* in the a real protocol execution is indistinguishable from that in an ideal execution, i.e. IDEAL *T,sU ≈* Real *T,sU* *,A,Z*. We

|F|c|2PC|
|---|---|---|
|i|2PC|,A,Z|

2PC*,*Sim*,Z* describe a series of hybrid experiments that transitions from Hyb₀ = Real *T,sU* to Hyb₃ = IDEAL *T,sU*. We abuse the notation to also write Hyb as the output distribution of the *F*2PC*,*Sim*,Z* environment.

Hyb₀: This is the real protocol execution between an honest Alice and a corrupted Bob in the *F*pre-hybrid and random oracle model.

(*t*)
Hyb₁: Instead of honestly computing the batch select ciphertexts Sel*.*ct*P,*1*, {*Sel*.*ct *P,*2 *}* and de-

(*t*)
cryption keys Sel*.*sk *P* for public inputs, Alice runs the (stateful) batch select simulator as follows. – In the instance independent offline phase, run

(*t*)
Sel*.*ct*P,*1*←* Sel*.*Sim(Sel*.*pp*P*)*,* for *t ∈* [*T*]*,*Sel*.*ct *P,*2 *←* Sel*.*Sim()*.*

– In the function dependent offline phase, run

(*t*) (*t*) (*t*)
sk *P* *←* Sel*.*Sim(I*P,*1*⊙ f* *A* + I *P,*2 )*.*

The adaptive *T*-times simulation security of Sel guarantees that the Hyb₁ is computationally indistinguishable from Hyb₀. Hyb₂: Simulate the batch select ciphertexts and decryption keys for private inputs analogously to the previous hybrid:

(*t*)
Sel*.*ct*I,*1 *I*

|← Sel.Sim(Sel.pp|),|for t ∈ [T], Sel.ct||← Sel.Sim().|
|---|---|---|---|---|
|I,1|I|||I,2|
|(t)|||(t)||
|I|I,1 A|B|I,2||

*I,*2

sk *←* Sel*.*Sim(I *⊙* x *∥* x + I)*.*

The adaptive *T*-times simulation security of Sel guarantees that the Hyb₂ is computationally indistinguishable from Hyb₁.

(*t*) (*t*)
Hyb₃: In the instance independent offline phase, instead of computing ct *O* honestly as ct *O* =

(*t*) (*t*) (*t*)
*D ⊕ H*(seed), sample ct *O* directly at random. Then in the online phase, program the

(*t*) (*t*) (*t*)
random oracle phase as *H*(seed) *←* ct *O* *⊕ D*. Since seed

(*t*) is sampled at random, the adversary has only negligable probability of query-
ing *H*(seed

(*t*) ) before obtaining seed
(*t*) in the online phase. Therefore, Hyb₃ is statistically
indistinguishable from Hyb₂. Hyb₄: Alice additionally plays the role of *F*prewhich allows her to learn Bob’s global MAC key

(*t*)
*∆B*and input masks b *I* submitted to *F*preduring the instance independent offline phase.

(*t*)
Then during the *t*-th online phase, Alice receives a masked input x *B* from Bob, and extracts

(*t*) (*t*) (*t*) (*t*) (*t*)
an input x *B* = x *B* *⊕* b *I*. Alice computes y = *f* *A* (x*A,* x*B*), and program the decryption information *D*

(*t*) such that the evaluation result of AuthEval equals y
(*t*).
Note that Hyb₄ is distributed identically to Hyb₃ because Alice is still computing her masked

(*t*) (*t*) (*t*) (*t*)
inputs honestly as x *A* = x *A* *⊕* a *I*, and the programmed decryption information *D* is the same as the honestly computed.

(*t*) (*t*)
Hyb₅: In the input phase, Alice simulates her masked inputs as x *A* = a *I* *⊕* 0, independent of

(*t*) (*t*)
her actual inputs x *A*, and then program the decryption information *D* such that AuthEval

(*t*) (*t*)
still evaluates to the correct result y = *f* *A* (x*A,* x*B*). Note that this hybrid is distributed identically to IDEAL *T,sU*. The fact that Hyb₅ is *F*2PC*,*Sim*,Z* statistically indistinguishable from Hyb₄ (in the random oracle model) follows from the same proof as Theorem 5.1 in [WRK17]. Hence we omit details here.

<u>When Alice is Corrupted</u> Sim proceed as follows.

## Instance Independent Offline Phase:

– Sim plays the role of *F*prewith Alice following its description. In the process, Sim samples

(*t*)
its own input masks b*I*, and receives Alice’s input masks a *I*. – Sim receives garbled tables and batch select ciphertexts from Alice and store them.

(*t*)
*t*-th Function Dependent Offline Phase: Sim receives a batch select decryption key sk *P*

(*t*)
from Alice, and use it to recover input labels k *P* following the description of 2PC. *t*-th Online Phase:

(*t*)
– Sim simulates its masked inputs as x *B* = b*I⊕* 0, and sends x*B*to Alice.

(*t*) (*t*)
– Sim receives, besides a masked input x*A*

||, a batch select decryption key sk|||and a seed|,|
|---|---|---|---|---|---|
||A (t) A|(t) B||I (t)||
||||(t)|||
|(t) (t)|2PC||B (t) A|(t) (t) A I||
|B A||2PC||||
|||||2PC||

*I* and use them to recover input labels k*,* k and decryption information *D*. – Sim waits for the functionality *F* to leak the target circuit *f*, and then runs AuthEval to check whether the evaluation prcedure aborts.

- ** If AuthEval doesn’t abort, then extract Alice’s input as x = x *⊕* a, and send a message (*t,f,* x) to the functionality *F*.
- ** If AuthEval aborts, then trigger an abort for the functionality *F* by sending a message (*t, ∅, ∅*).
The fact that IDEAL *T,sU* is statistically indistinguishable from Real 2PC *T,sU* *,A,Z* follows from *F*2PC*,*Sim*,Z* the same proof as Theorem 5.1 in [WRK17]. Hence we omit details here.

AuthGarb *C* *C,λ,κ* The protocol assumes the *F*prefunctionality defined in Figre5. Let *W* be the set of indices of all wires in *C*, and *IP,IA,IB,O* be those of public inputs, Alice and Bob’s inputs, and output wires. Let *W∧*be the output wires of all AND gates.

(*C,λ,κ*)

1.Alice and Bob invoke *F*pre.
*λ* (*w*) (*w*) *κ* – Alice samples a global MAC key *∆A←{*0*,*1*}*, bits *a ←{*0*,*1*}*, tags *M* *A* *←{*0*,*1*}*

(*w*)

|for w ∈ W, and sets a||= 0 for w ∈ I|∪ I|.|||
|---|---|---|---|---|---|---|
||(w)|B (w) A|(w) A (w) B|(w)|(w) (w) B|A P|
|(w)|(w) (w)||(w) (w)|(w)|(w)||
|A|A A||B|B|B||

*B P*

(*w*) (*w*) (*w*)
– Bob analogously samples *∆B, {b}, {M}*, and sets *b* = 0 for *w ∈ IA∪ IP*. They send (*∆A, {a,M}*) and (*∆, {b,M}*) to *F*preand receive back

(*w*)c b b c b
(*{K}, {*b*a, M, K}*) and (*{K}, {b, M, K}*).

2.Alice and Bob locally computes intermediate bits, tags, and MAC keys for each AND gate (*i,j,k, ∧*) as follows: – Alice computes
(*k*) (*k*) (*k*) (*k*) (*k*) (*k*) (*i*)
*a₀* = *a ⊕* b*a, a₁* = *a ⊕* b*a ⊕ a,*

(*k*) (*k*) (*k*) (*j*) (*k*) (*k*) (*k*) (*i*) (*j*)
*a₂* = *a ⊕* b*a ⊕ a, a₃* = *a ⊕* b*a ⊕ a ⊕ a ⊕* 1*,*

(*k*) (*k*)
c(*k*)

(*k*) (*k*)
c(*k*) (*i*) *MA,*0= *M* *A* *⊕ M* *A* *, MA,*1= *M* *A* *⊕ M* *A* *⊕ M* *A*

(*k*) (*k*)
c(*k*) (*j*)

(*k*) (*k*)
c(*k*) (*i*) (*j*) *MA,*2= *M* *A* *⊕ M* *A* *⊕ M* *A* *, MA,*3= *M* *A* *⊕ M* *A* *⊕ M* *A* *⊕ M* *A* *,*

(*k*) (*k*)
b(*k*)

(*k*) (*k*)
b(*k*) (*i*) *KA,*0= *K* *A* *⊕ K* *A* *, KA,*1= *K* *A* *⊕ K* *A* *⊕ K* *A*

(*k*) (*k*)
b(*k*) (*j*)

(*k*) (*k*)
b(*k*) (*i*) (*j*) *KA,*2= *K* *A* *⊕ K* *A* *⊕ K* *A* *, KA,*3= *K* *A* *⊕ K* *A* *⊕ K* *A* *⊕ K* *A* *⊕ ∆A.*

(*k*) (*k*) (*k*)
– Bob analoguously computes *bd, MB,d, KB,d*for *d ∈* [3].

3.Alice compute garbled tables as follows and sends them to Bob.
(*w*) *λ* (*w*) (*w*)
– For each wire *w ∈ W*, sample a random key *L₀ ←{*0*,*1*}*, and set *L₁* = *L₀ ⊕ ∆A*.

(k) (*k*) (*k*) (*k*) (*k*)
– For each AND gate (*i,j,k, ∧*), compute a garbled table tb = (ct₀*,*ct₁*,*ct₂*,*ct₃) where for *d ∈* [3]

(*k*) (*i*) (*j*) (*k*) (*k*) (*k*) (*k*) (*k*)
ct *d* = *H*(*L* *d* 0 *∥L* *d* 1 *∥d*) *⊕ a* *d* *∥MA,d∥L₀ ⊕ a* *d* *· ∆A⊕ KA,d*

4.Alice outputs
(*w*) (*w*)
– the input keys *L₀P A B P A B*

||,L₁ for w ∈ I|∪ I ∪ I|, organized into K||, K|, K;|
|---|---|---|---|---|---|---|
|||P A|B||P|A B|
|(w)|A||I||||
|||(w) A w∈O (k) B|(k) d|(k) B,d|(k) B,d||
|(w)|B||I||||

– the bits *a* for *w ∈ I* organized as a vector a;

(*w*)
– decryption information *D* = *{a,M}*. Bob outputs b = ( – the authenticated garbling *C ∆, {*tb*}, {b, M, K}*); <u>– the bits b for w ∈ I organized as a vector b.</u>

## Fig.3: Sub-protocol AuthGarb, adapted from [WRK17,DILO22].

*C* AuthEval (*C,D,*k

|, k|, k, x|, x, x )|
|---|---|---|
|P|A B P|A B|
||P A B||
|∧|||

Let *W* be the set of indices of all wires in *C*, and *I,I,I,O* be those of public inputs, Alice and Bob’s inputs, and output wires. Let *W* be the output wires of all AND gates.

1.Parse the inputs as:
(*k*) (*k*) (*k*) (*k*)
*C* = (*∆B k∈W∧ d B,d B,d k∈W*)*,*

||, {tb|}|, M, {b|, K|}||
|---|---|---|---|---|---|---|
|(i) (j)|B (k) d d∈[3]|k∈W|d (w)|B,d B,d (w) A w∈O|k∈W ,d∈[3]|(i) (j)|

*∧,d∈*[3]

(*k*)
tb = *{*ct*}, D* = *{a,M}.*

2.In topological order, for every gate (*i,j,k,* Type) the algorithm holds *L,L* and bits *x, x*, and proceed as follows: – If Type is *⊕*, then compute
(*k*) (*i*) (*j*) (*k*) (*i*) (*j*)

|L|= L|⊕ L,|x = x|⊕ x|.||
|---|---|---|---|---|---|---|
|||(k)|||(i)|(j)|
|||d|||||
|(k) d|(k) (k) d A|(k) d||(i)|(j)||
|(k) (k)||(k)|||||
|d d|B|B,d|||||
|(k)|(k) d|(k) d|(k)|(k) A|(k) B,d||
||(w) (w) A|(w) B|(w) B|||(w)|

– If Type is *∧*, first decrypt the ciphertext ct where *d* = 2 *· x* + *x* :

(*a ∥M ∥L*) = ct *⊕ H*(*L ∥L ∥d*)*,*

Next verify that *M* = *a · ∆ ⊕ K*, and then compute

*x* = *a ⊕ b, L* = *L ⊕ M.*

3.In the end, the algorithm holds *x* for every *w ∈ O*, and proceeds as follows.
(*w*) (*w*) (*w*)
– For every *w ∈ O*, verify that *M* = *a ·∆ ⊕K*, and compute *x* = *x ⊕a ⊕b*. <u>– Output the values on the output wires as y.</u>

## Fig.4: Algorithm AuthEval, adapted from [WRK17,DILO22].

(*C,λ,κ*) Functionality *F*pre Let *W* be the set of indices of all wires in *C*, *I,O ⊂ W* be the indices of input and outptu wires, and *W∧*, output wires of AND gates. Further divide *I* input indices for public inputs *I*

||and Bob’s inputs I||.||||
|---|---|---|---|---|---|---|
||A|λ (w)||A (w)|κ w∈W|B|
|κ (w)||(w) B A|λ w∈W|(w)||B|
|||(w)|||||

*P*, Alice’s inputs *IA B*

– On receiving (*∆ ∈{*0*,*1*}, {a ∈{*0*,*1*},M ∈{*0*,*1*}}*) from Alice, or (*∆ ∈* *{*0*,*1*}, {b ∈{*0*,*1*},M ∈{*0*,*1*}}*) from Bob, store them. – Once received messages from both Alice and Bob:

1.For every input wire *w ∈ I*, adjust Bob’s bit *b* = 0. For every input wire *w ∈ I*, adjust Alice’s bit *a* = 0.
2.For every XOR gate (*i,j,k, ⊕*), adjust the bits and tags on the output wire *k*:
(*k*) (*i*) (*j*) (*k*) (*i*) (*j*)
*a* = *a ⊕ a, M* *A* = *M* *A* *⊕ M* *A* *,*

(*k*) (*i*) (*j*) (*k*) (*i*) (*j*) *b* = *b ⊕ b, M*
*B* = *M* *B* *⊕ M* *B* *.*

3.For every AND gate (*i,j,k, ∧*), sample random additive shares b*a*
(*k*) *,* b *b*
(*k*) *∈ {*0*,*1*}*
such that b*a*

(*k*) *⊕* b*a*
(*k*) = (*a*
(*i*) *⊕ b*
(*i*) ) *·* (*a*
(*j*) *⊕ b*
(*j*) )*,*

|(k)|κ|(k)|λ||||
|---|---|---|---|---|---|---|
|A||B|||||

c c and random tags *M ←{*0*,*1*}, M ←{*0*,*1*}*.

4.For every tag, compute the corresponding mac key:
(*w*) (*w*) (*w*) (*w*) (*w*) (*w*)
*∀w ∈ W, K* *B* = *M* *A* *⊕ a · ∆BK* *A* = *M* *B* *⊕ b · ∆A*

b(*k*)c(*k*) (*k*)b(*k*)c(*k*)b(*k*) *∀k ∈ W∧, K* *B* = *M* *A* *⊕* b*a · ∆BK* *A* = *M* *B* *⊕ b · ∆A.*

*w* (*w*)c(*w*)b*w w*b(*k*)c(*k*)b*k* Output (*{K* *A* *}, {*b*a, M* *A* *, K* *A* *}*) and (*{K* *B* *}, {b, M* *B* *, K* *B* *}*) to Alice and Bob <u>respectively.</u>

Fig.5: The preprocessing functionality adapted from [WRK17,DILO22].
