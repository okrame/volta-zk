# Wolverine: Fast, Scalable, and Communication-Ecient Zero-Knowledge Proofs for Boolean and Arithmetic Circuits

## Chenkai Weng Kang Yang Jonathan Katz

*y*

Northwestern University State Key Laboratory of Cryptology University of Maryland ckweng@u.northwestern.edu yangk@sklc.org jkatz2@gmail.com

## Xiao Wang

Northwestern University wangxiao@cs.northwestern.edu

## January 13, 2021

Abstract

Ecient zero-knowledge (ZK) proofs for arbitrary boolean or arithmetic circuits have re- cently attracted much attention. Existing solutions suer from either signicant prover over- head (i.e., high memory usage) or relatively high communication complexity (at least bits per gate, for computational security parameter). In this paper, we propose a new proto- col for constant-round interactive ZK proofs that simultaneously allows for an ecient prover with asymptotically optimal memory usage and signicantly lower communication compared to protocols with similar memory eciency. Specically: The prover in our ZK protocol has linear running time and, perhaps more importantly, mem- ory usage linear in the memory needed to evaluate the circuit non-cryptographically. This allows our proof system to scale easily to very large circuits. For statistical security parameter = 40, our ZK protocol communicates roughly 9 bits/gate for boolean circuits and 2{4 eld elements/gate for arithmetic circuits over large elds. Using 5 threads, 400 MB of memory, and a 200 Mbps network to evaluate a circuit with hundreds of billions of gates, our implementation ( = 40*;* = 128) runs at a rate of 0*:* 45 *s*/gate in the boolean case, and 1*:* 6 *s*/gate for an arithmetic circuit over a 61-bit eld. We also present an improved subeld Vector Oblivious Linear Evaluation (sVOLE) protocol with malicious security that is of independent interest.

# 1 Introduction

Zero-knowledge (ZK) proofs (of knowledge) [GMR85,GMW91] are a fundamental cryptographic tool. They allow a prover *P* to convince a verier *V*, who holds a circuit *C*, that the prover knows a witness *w* for which *C*(*w*) = 1, without leaking any extra information. While ZK proofs for arbitrary circuits are possible [GMW91], until recently such proofs were inecient as they relied on reduc- tions to generic NP-complete problems. Over the past decade, however, several ZK proof systems have been developed that yield far more ecient protocols. These include *zero-knowledge suc-* *cinct non-interactive arguments of knowledge* (zk-SNARKs) [Gro10,GGPR13,BCG + 13,BCTV14, BCC + 16,BBB + 18,WTS + 18,BCR + 19,BBHR19,Set20], ZK proofs based on Interactive Oracle *y* Work done as a consultant for Stealth Software Technologies, Inc.

Proofs (IOPs) and techniques from the setting of veriable outsourcing [GKR08,XZZ + 19,BFS20, ZXZS20], ZK proofs following the \MPC-in-the-head" approach [IKOS07,GMO16,CDG + 17,AHIV17, KKW18,dDOS19], and a line of work constructing ZK proofs from garbled circuits (ZKGC) [JKO13, FNO15,ZRE15,HK20]. Each of these works oers dierent tradeos between underlying assump- tions (both computational hardness assumptions as well as setup assumptions), round complexity (in particular, whether the proof requires interaction or can be made non-interactive), expressive- ness (e.g., whether the scheme natively handles boolean or arithmetic circuits), and eciency. With regard to eciency, measures of interest include the prover complexity (including time complexity and memory requirements), the verier complexity, and the communication as a function of the circuit size. One important factor is the memory overhead of ZK protocols. In particular, high memory requirements can impose a hard limit on the maximum circuit size that a protocol can support in practice. As shown in Table1, prior ZK proof systems can be characterized roughly as either

(1) having short proofs (e.g., sublinear in the circuit size, or even sublinear in the length of a witness) but signicant memory overhead for the prover as in the case of zk-SNARKs, IOP-based schemes, and some schemes following the MPC-in-the-head paradigm, or (2) imposing low memory overhead for the prover but having high communication complexity, as in the case of ZKGC schemes. In this paper, we propose a new approach to ZK proofs that enables an extremely ecient prover in both running time and memory usage while having lower communication compared to the ZKGC approach that oers similar prover eciency. As in the ZKGC approach, we obtain prover complexity|in terms of both time and memory usage|linear in the complexity required to evaluate the circuit non-cryptographically; this allows our ZK protocol to scale easily to very large circuits. At the same time, we achieve communication complexity that is more than an order of magnitude lower than what can be achieved using the ZKGC approach, while natively supporting boolean or arithmetic circuits. As compared to the other work in Table1, the main drawback of our protocol|shared by the ZKGC approach|is that it requires interaction. Our protocol does, however, oer a non-interactive *online* phase following an interactive oine phase that can be executed by the parties before the circuit is known.
## 1.1 Outline of Our Solution

Our ZK protocol (named Wolverine) can be separated into two phases: an interactive oine phase that can be executed by the prover and verier before both the circuit and the witness are known, and an online phase that can be made non-interactive in the random-oracle model. We view the online phase as our main conceptual contribution, though we oer eciency improvements for the oine phase as well.

Online phase. The online phase of our protocol can be viewed as adapting the core idea of the ZKGC approach by viewing a ZK proof as a special case of secure two-party computation (2PC) where one party has no input. We dier from the ZKGC approach in the underlying 2PC protocol we use as our starting point: rather than using garbled circuits, we instead rely on a \GMW-style" approach [GMW87] using authenticated multiplication triples [Bea92,NNOB12] (whose values are known to the prover) generated during the oine phase. A drawback of GMW-style protocols in the context of generic 2PC is that they have round complexity linear in the depth of the circuit being evaluated. Crucially, in the ZK context, we can exploit the fact that only one party has input to obtain an online phase that runs in constant rounds (or can even be non-interactive in the random-oracle model). The prover and verier run in linear time since they each make only one pass over the circuit. Moreover, they can evaluate the circuit \on-the-y" (i.e., with memory overhead linear in what is

||Protocol|Spartan [Set20]|Virgo [ZXZS20]|Ligero [AHIV17]|[HK20]|Wolverine|
|---|---|---|---|---|---|---|
||Type Prover time|zk-SNARK 55 s|IOP-based 53 s|MPC-in-the-head 400 s|ZKGC 7.3 s|sVOLE-based 11 s|
|Merkle tree|Verier time|< 0:1 s|< 0:1 s|< 0:1 s|7.3 s|11 s|
|(boolean circuit)|Overall time|55 s|53 s|400 s|7.3 s|11 s|
||Communication|100 KB|253 KB|1.5 MB|182.2 MB|12.4 MB|
||Prover memory Prover time Verier time|7 GB 677 s < 0:1 s|1 GB 64 s < 0:1 s|5 GB|400 MB|400 MB 320 s 320 s|
|Matrix mult.|Overall time|677 s|64 s|||320 s|
|(arithmetic circuit)|Communication|100 KB|200 KB|||4.2 GB|
||Prover memory|86 GB|18 GB|||400 MB|

Table 1: Comparing our ZK protocol with prior work. The rst example proves knowledge of 256

leaves that hash to a public root of a Merkle tree based on SHA-256 (511 hash-function evaluations). The second example proves knowledge of two 512 512 matrices over a 61-bit eld whose product is a public matrix (roughly 134 million eld multiplications). Performance of our protocol ( = 40, = 128) is measured by running the prover and verier on two machines, each using 1 thread, connected via a 200 Mbps network, and is the total running time of both the oine and online phases. For ZKGC and Wolverine, the prover and verier can execute the protocol in a *pipelined* fashion, which is why the overall time is the maximum of the prover and verier times. Spartan uses a 256-bit eld while Virgo and Wolverine use a 61-bit eld. See Section6for details.

needed to evaluate the circuit non-cryptographically), which allows our protocol to scale easily to very large circuits. Our approach is communication-ecient as well: for a circuit with *C* multipli- cation gates over an arbitrary nite eld F*p*, the marginal communication complexity is only either 3*=*log*C* + 1 elements per gate for small elds or 2{4 elements per gate for large elds.

Instantiating the oine phase. During the oine phase we set up authenticated multiplication triples (over the relevant eld F*p*) between the prover and verier using subeld Vector Oblivious Linear Evaluation (sVOLE) [BCGI18,BCG + 19b]. For boolean circuits (i.e., *p* = 2), we use the recent work by Yang et al. [YWL + 20] to generate an initial pool of authenticated bits, and then use those authenticated bits to generate authenticated triples as in prior work [NO09]. For *p >* 2, we extend the protocol of Yang et al. to obtain an ecient sVOLE protocol for arbitrary elds (which we believe to be of independent interest). We defer further details to Section4.

## 1.2 Performance and Comparison to Prior Work

We have implemented Wolverine for both boolean and arithmetic circuits. Running over a 200 Mbps network, Wolverine processes boolean circuits at the rate of 2,000,000 AND gates per second (XOR gates are free), and arithmetic circuits over a 61-bit large eld at the rate of 600,000 multipli- cation gates per second (addition gates are free). In Table1we provide benchmarks comparing Wolverine to prior work for two examples: proving knowledge of the leaves that hash to a Merkle- tree root (naturally represented as a boolean circuit) and proving knowledge of the inputs to matrix multiplication over a large eld (naturally represented as an arithmetic circuit). In the boolean setting, Wolverine uses 15 less communication than ZKGC [HK20] along with lower running time; Wolverine outperforms all other work in terms of overall time and memory usage. In the arithmetic setting, Wolverine is 5 slower than Virgo [ZXZS20] but needs only 3% of the memory. The ad- vantage in memory usage would be even larger for larger circuits, and would enable Wolverine to scale to circuits larger than what can be feasibly handled by Virgo.

Comparison to ZK proofs based on VOLE/OT. Boyle et al. [BCGI18,BCG + 19b] also pro-

posed a framework for ZK proofs in which an oine phase is used to set up correlated randomness between the prover and verier, and the subsequent online phase is non-interactive. With regard to the online phase, the primary advantages of their work are that the online phase can be non- interactive without the random-oracle model, and can be run any polynomial number of times following a single execution of the oine phase (that is, the oine phase is *reusable*). An advan- tage of our work is that it applies to circuits over arbitrary elds, whereas the work of Boyle et al. applies either to boolean circuits [BCG + 19b] or arithmetic circuits over large elds [BCGI18]. More to the point, the focus of our work is concrete eciency, which was not investigated by Boyle et al. For boolean circuits, the ZK protocol of Boyle et al. [BCG + 19b] based on oblivious transfer requires communicating over 100,000 bits per gate when = 40, which is four orders of magnitude larger than our protocol. For large elds, the VOLE-based ZK protocol of Boyle et al. [BCGI18] requires communication of at least 16 elements per gate, whereas our protocol sends only 2{4 elements per gate. We also oer concrete eciency improvements for the oine phase in the large-eld case. In particular, our sVOLE protocol avoids the generic, maliciously secure two-party computation used by Boyle et al. [BCGI18].

Comparison to zk-SNARKs. Our ZK protocol occupies a dierent portion of the solution space than (existing) zk-SNARKs. Existing zk-SNARKs impose concretely high memory requirements on the prover (cf. Table1), even when the memory requirements are linear in the circuit size. (While there are zk-SNARKs in which the prover asymptotically uses sublinear memory [COS20], such schemes are currently 200 slower than state-of-the-art zk-SNARKs that uses linear mem- ory [Set20].) The prover memory in Wolverine is signicantly lower, allowing Wolverine to scale to very large circuits. On the other hand, zk-SNARKs have many advantages: they are non-interactive and have lower communication. They also have better eciency for the verier, although their *overall* time (i.e., including the time for the prover to generate the proof) might be longer. In independent and concurrent work, Dittmer, Ishai, and Ostrovsky [DIO20] have also developed a ZK protocol based on VOLE. They focus on communication complexity rather than concrete performance; their protocol only considers the case of large elds, and has lower communication complexity than our protocol in that case. Subsequent to our work, Baum, Malozemo, Rosen and Scholl [BMRS20] have also proposed a dierent VOLE-based ZK protocol.

Organization of the paper. After reviewing some preliminaries in Section2, we describe the online phase of our ZK proof in Section3. In Section4we describe the details of our sVOLE construction used in the oine phase of our ZK proof. We provide experimental results in Section6.

# 2 Preliminaries

We use and to denote the computational and statistical security parameters, respectively. We let negl( ) denote a negligible function, and use log to denote logarithms in base 2. We write *x S* to denote sampling *x* uniformly from a set *S*, and *x D* to denote sampling *x* according to a distribution *D*. We dene [*a;b*) = *fa;:::;b* 1*g* and write [*n*] = *f*1*;:::;ng*. We use bold lower- case letters like *a* for row vectors, and bold upper-case letters like A for matrices. We let *a*[*i*] denote the *i*th component of *a* (with *a*[0] the rst entry), and let *a*[*i* : *j*) represent the subvector (*a*[*i*]*;:::; a*[*j* 1]). A circuit *C* over a eld F*p*is dened by a set of input wires *I*inand output wires *I*out, along with a list of gates of the form (*;;;T*), where*;* are the indices of the input wires of the gate, is the index of the output wire of the gate, and *T 2f*Add*;*Mult*g* is the type of the gate. If *p* = 2, then *C* is a boolean circuit with Add = and Mult = *^*. If *p >* 2 is prime, then *C* is an arithmetic

circuit where Add/Mult correspond to addition/multiplication in F*p*. We let *C* denote the number of Mult gates in the circuit. When we work in an extension eld F*pr* of F*p*, we x some monic, irreducible polynomial *f* (*X*) of degree *r* and so F*pr*= F*p*[*X*]*=f*(*X*). We let X *2* F*pr* denote the element corresponding to P *r* 1 *i*

||p|||r i=0 1 i|i|i p|
|---|---|---|---|---|---|---|
|p|p p|p|rp|||p|

*X 2* F*p*[*X*]*=f*(*X*); thus, every *w 2* F*pr* can be written uniquely as *w* = *wi*X with *wi2* F*p* for all *i*, and we may view elements of F *r* equivalently as vectors in F. When we write arithmetic expressions involving both elements of F and elements of F *r*, it is understood that values in F are viewed as lying in F *r* in the natural way. We let F denote the nonzero elements of a eld F.

## 2.1 Information-Theoretic MACs and Batch Opening

We use *information-theoretic message authentication codes* (IT-MACs) [NNOB12,DPSZ12] to au- thenticate values in a nite eld F*p*using an extension eld F *r* F. In more detail, let *2* F *r*

|p|p|p|
|---|---|---|
||B||
|||A|
|p|||

be a *global key*, sampled uniformly, that is known only by one party P. A value *x 2* F*p*known by the other party PAcan be authenticated by giving PBa uniform key K[*x*] *2* F*pr* and giving P the corresponding MAC tag M[*x*] = K[*x*] + *x 2* F *r :*

We denote such an authenticated value by [*x*]. Authenticated values are additively homomorphic,

i.e., if PAand PBhold authenticated values [*x*]*;* [*x⁰*] then they can locally compute [*x⁰⁰*] = [*x* + *x⁰*] by having PAset *x⁰⁰* := *x* + *x⁰* and M[*x⁰⁰*] := M[*x*] + M[*x⁰*] and having PBset K[*x⁰⁰*] := K[*x*] + K[*x⁰*]. Similarly, for a public value *b 2* F*p*, the parties can locally compute [*y*] = [*x* + *b*] or [*z*] = [*bx*]. We denote these operations by [*x⁰⁰*] = [*x*] + [*x⁰*], [*y*] = [*x*] + *b*, and [*z*] = *b* [*x*], respectively. We extend the above notation to vectors of authenticated values as well. In that case, [*u*] means that (for some *n*) PAholds *u 2* F
*n* *p*and *w 2* F *n* *p* *r*, while PBholds *v 2* F *n* *p* *r* with *w* = *v* + *u*. An *authenticated multiplication triple* consists of authenticated values [*x*]*;* [*y*]*;* [*z*] where *z* = *x y*.

Batch opening of authenticated values. An authenticated value [*x*] can be \opened" by ? having PAsend *x 2* F*p*and M[*x*] *2* F*pr* to PB, who then veries that M[*x*] = K[*x*] + *x*. This has soundness error 1*=p* *r*, and requires sending an additional *r*log*p* bits (beyond *x* itself). While this can be repeated in parallel when opening multiple authenticated values [*x₁*]*;:::;*[*x‘*], communication can be reduced using batching [NNOB12,DPSZ12]. We describe two approaches in AppendixB. Hereafter, we write Open([*x*]) to denote a generic batch opening of a vector of authenticated values. In addition, we write CheckZero([*x*]) for the special case where all *xi*are supposed to be 0 and so need not be sent. We let *"*opendenote the soundness error (which depends on the technique used); when using either of the techniques described above, *"*openis independent of the number *‘* of authenticated values opened.

## 2.2 Security Model and Functionalities

We use the *universal composability* (UC) framework [Can01] to prove security in the presence of a malicious, static adversary. We say that a protocol *UC-realizes* an ideal functionality *F* if for any probabilistic polynomial time (PPT) adversary *A*, there exists a PPT adversary (simulator) *S* such that for any PPT environment *Z* with arbitrary auxiliary input *z*, the output distribution of *Z* in the *real-world* execution where the parties interact with *A* and execute is computationally indistinguishable from the output distribution of *Z* in the *ideal-world* execution where the parties interact with *S* and *F*. The protocol that we construct in this work UC-realizes the standard zero-knowledge function- ality *F*ZK, reproduced in Figure1for completeness. (We omit session identiers in all our ideal

<u>Functionality FZK</u>

Upon receiving (prove*; C;w*) from a prover *P* and (verify*; C*) from a verier *V* where the same (boolean or arithmetic) circuit *C* is input by both parties, send true to *V* if *C*(*w*) = 1; otherwise, send false to *V*.

Figure 1: The zero-knowledge functionality.

<u>Functionality F</u> <u>sVOLE</u> *p;r*

Initialize: Upon receiving init from PB, sample *r r*

||||and P|F|if P is honest or receive 2 F|||from||
|---|---|---|---|---|---|---|---|---|---|
||||A|p|B|||p||
|||||B|||A|B||
|B|||‘p||‘p|||||
|A|‘p|A A|‘p B|0||‘p|‘p 0 p|0|‘p|
||A|||||||||

the adversary otherwise. Store global key and send to P, and ignore all subsequent init commands.

Extend: This procedure can be run multiple times. Upon receiving (extend*;‘*) from P and P, do:

1.If P is honest, sample K[*x*] F *r*. Otherwise, receive K[*x*] *2* F *r* from the adversary.
2.If P is honest, sample *x* F and compute M[*x*] := K[*x*] + *x 2* F *r*. Otherwise, receive *x 2* F and M[*x*] *2* F *r* from the adversary, and then recompute K[*x*] := M[*x*] *x 2* F *r*.
3.Send (*x;* M[*x*]) to P and K[*x*] to P. Global-key query: If P is corrupted, receive (guess*;*) from the adversary with *2* F *r*. If =, send success to P and ignore any subsequent global-key query. Otherwise, send abort to both parties and abort.
Figure 2: Functionality for subeld VOLE.

functionalities for the sake of readability.) Our ZK protocol relies on the *subeld Vector Oblivious* *Linear Evaluation* (sVOLE) functionality (see Figure2), which is the same as that by Boyle et al. [BCG + 19a], except that the adversary is allowed to make a global-key query on and would incur aborting for an incorrect guess. After an initialization that is done once, this functionality allows two parties to repeatedly generate a vector of authenticated values known to PA. Other functionalities are given for reference in AppendixA.

# 3 Our Zero-Knowledge Protocol

*p;r* In Figure3, we describe our zero-knowledge protocolZK, which operates in the *F* sVOLE -hybrid model. As noted in Section1.1, our protocol can be viewed as following a \GMW-style" approach to secure two-party computation using authenticated multiplication triples [NNOB12,DPSZ12]. In the secure-computation setting, the evaluation of a multiplication gate requires two rounds of interaction, since the parties hold shares of the values on the input wires, but neither party knows those values. In the ZK setting, however, the prover *P* knows the values on all wires; thus, evaluation of a multiplication gate can be done without any interaction at all. At a high level, our protocol consists of the following steps:

1. Initialization. The parties prepare authenticated values *f*[*i*]*g* for the witness, and *f*[*si*]*g* for each multiplication gate in the circuit. The parties also generate some number of authenticated multiplication triples *f*([*xi*]*;* [*yi*]*;* [*zi*])*g*; a malicious prover may cause some or all of these triples to be incorrect (i.e., *zi6*= *xiyi*).
2. Circuit evaluation. Starting with the authenticated values *f*[*wi*]*g* at the input wires, the par- ties inductively compute authenticated values for all the wires in the circuit. For addition gates,

<u>ProtocolZK</u>

Inputs and parameters: The prover *P* and verier *V* hold a circuit *C* over a nite eld F*p*with *C* multiplication gates; *P* holds a witness *w* such that *C*(*w*) = 1. Fix parameters *B;c*, and *r*, and let *‘* = *C B* + *c*.

Oine phase:

1. *P* (acting as PA B

||) and V (acting as P||) send init to F||, which returns a uniform 2 F|to V.|
|---|---|---|---|---|---|---|
||A||B||sVOLE|p|
|||in||p;r sVOLE||i i2I|
|i i|i i2[‘]|p;r i i2[C]|||||
|||sVOLE i i|i p|||i i|

sVOLE *p;r* *p* *r*

2. *P* and *V* send (extend*; jI j* + 3*‘* + *C*) to *F*, which returns authenticated values *f*[]*g*in, *f*([*x*]*;* [*y*]*;* [*r*])*g*, and *f*[*s*]*g* to the parties. (If *V* receives abort from *F*, then it aborts.)
3.For *i 2* [*‘*], *P* sends *di*:= *x y r 2* F to *V*, and then both parties compute [*zi*] := [*r*] + *d*. Online phase:
4.For *i 2I*in, *P* sends*i*:= *wi i2* F*p*to *V*, and then both parties compute [*wi*] := [*i*] +*i*.
5.For each gate (*;;;T*) *2C*, in topological order:
(a)If *T* = Add, then the two parties locally compute [*w*] := [*w*] + [*w*].
(b)If *T* = Mult and this is the *i*th multiplication gate, *P* sends *d* := *w w si2* F*p*to *V*, and then both parties compute [*w*] := [*si*] + *d*.
6. *V* samples a random permutation on *f*1*;:::;‘g* and sends it to *P*. The two parties use to permute the *f*([*xi*]*;* [*yi*]*;* [*zi*])*gi2*[*‘*]obtained in step3.
7.For the *i*th multiplication gate (*;;;* Mult), where the parties obtained ([*w*]*;* [*w*]*;* [*w*]) in step5, do the following for *j* = 1*;:::;B*:
(a)Let ([*x*]*;* [*y*]*;* [*z*]) be the (*i* 1)*B* + *j* th authenticated triple (after applying in step6).
(b)The parties run := Open([*w*] [*x*]) and := Open([*w*] [*y*]). The parties then compute [] := [*z*] [*w*] + [*x*] + [*y*] +, and nally run CheckZero([]).
8.For each of the remaining *c* authenticated triples, say ([*x*]*;* [*y*]*;* [*z*]), the parties run *x* := Open([*x*]) and *y* := Open([*y*]). They also compute [] := [*z*] *x y* and then run CheckZero([]).
9.For the single output wire *o 2I*outwith authenticated value [*wo*], the parties run CheckZero([*wo*] 1).
*p;r*

Figure 3: Zero-knowledge proof in the *F*

sVOLE -hybrid model.

this is easy. For the *i*-th multiplication gate, the prover uses [*si*] to enable the verier to com- pute its component of the authenticated value for the output wire without revealing information about the values on the input wires. Specically, given authenticated values [*w*]*;* [*w*] on the input wires to the *i*th multiplication gate, the prover sends *w w si*to the verier; the prover and verier then compute [*w*] := [*si*] + (*w w si*)

as the authenticated value of the output wire. All communication here is from the prover to the verier, so the entire circuit can be evaluated using only one round of communication.

Once the parties have an authenticated value [*wo*] for the output wire, the prover simply opens that value, and the verier checks that it is equal to 1.

3. Verifying correct behavior. So far, nothing prevents a malicious prover from cheating. To detect cheating, the verier needs to check the behavior of the prover at each multiplication gate

using the initial set of authenticated multiplication triples the parties generated. This can be done in various ways. In the protocol as described in Figure3, which works for circuits over an arbitrary eld, the verier checks the behavior of the prover as follows (adapting [ABF + 17]):

The verier checks a random subset of the authenticated triples to make sure they are correctly formed. For an authenticated multiplication triple ([*x*]*;* [*y*]*;* [*z*]), this can be done by having the prover run Open([*x*]) and Open([*y*]) followed by CheckZero([*z*] *x y*). The verier then uses the remaining authenticated triples to check that each multiplication gate was computed correctly. For a multiplication gate with authenticated values [*w*]*;* [*w*] on the input wires and [*w*] on the output wire, the relation *w* = *w w* can be checked using an authenticated multiplication triple ([*x*]*;* [*y*]*;* [*z*]) by having the prover run := Open([*w*] [*x*]) and := Open([*w*] [*y*]), followed by

CheckZero [*z*] [*w*] + [*x*] + [*y*] + *:*

Each multiplication gate is checked in this way using *B* authenticated multiplication triples.

In Section3.2, we describe other approaches for verifying correct behavior.

Note that the checks for the openings of all the authenticated values (i.e., all the executions of Open and CheckZero) can be batched together at the end of the protocol.

Non-interactive online phase. The ZK protocol described in Figure3can be implemented in constant rounds. If we use the Fiat-Shamir heuristic both for deriving the permutation as well as for non-interactive opening of authenticated values, the online phase can be made non-interactive.

## 3.1 Proof of Security

Before giving the proof of security forZK, we analyze the procedure used to check correctness of the multiplication gates. Consider some multiplication gate with authenticated values [*w*], [*w*] on the input wires and [*w*] on the output wire. If *P* cheated, so *w 6*= *w w*, then this cheating will be detected in step7of the protocol unless all *B* of the multiplication triples used to check that gate are incorrect. (We ignore for now the possibility that *P* is able to successfully cheat when running Open/CheckZero.) But if too many of the initial multiplication triples are incorrect, then there is a high probability that *P* will be caught in step8. We can analyze the overall probability with which a cheating *P* can successfully evade detection by considering an abstract \balls-and-bins" game with an adversary *A*, which is based on a similar game considered previously in the context of secure three-party computation [ABF + 17]. The game proceeds as follows:

1. *A* prepares *‘* = *CB* + *c* balls *B₁;:::; B‘*, each of which is either good or bad. *A* also pre- pares *C* bins, each of which is either good or bad. The balls *fBigi2*[*‘*]correspond to the triples *f*([*xi*]*;* [*yi*]*;* [*zi*])*gi2*[*‘*]dened in step3of the protocol, and the bins correspond to the triples *f*([*w*]*;* [*w*]*;* [*w*])*g* dened for the multiplication gates during the circuit evaluation.
2.Then, *c* random balls are chosen. If any of the chosen balls is bad, *A* loses. Otherwise, the game proceeds to the next step.
3.The remaining *CB* balls are randomly partitioned into the *C* bins, with each bin receiving exactly *B* balls.
4.We say that a bin is fully good (resp., fully bad) if it is labeled good and all the balls inside it are good (resp., labeled bad and all the balls inside it are bad). *A* wins if and only if there exists at least one bin that is fully bad, and all other bins are either fully good or fully bad.

*CB*+*c* 1 Lemma 1. *Assume c B. Then A wins the above game with probability at most* *B* *.*

*Proof.* Assume *A* makes *m* bins bad for 1 *m C*. It is easy to see that *A* can only possibly win if exactly *mB* balls among *B₁;:::; B‘*are bad, and they are exactly placed in the *m* bins that are bad. We compute the probability that *A* wins for some xed *m*. Since exactly *mB* balls of the *‘* = *CB* + *c* balls are bad, the probability that none of the bad balls is chosen in step2of the game is exactly

*‘ mB* *c* = ( *‘ mB*)! (*‘ c*)! = (*CB* + *c mB*)! (*CB*)! *:* *‘* *‘*! (*‘ mB c*)! (*CB* + *c*)! (*CB mB*)! *c*

Assume that this occurs. We are left with *‘ c* = *CB* balls, of which *mB* are bad. The probability that *B* bad balls are placed in each bad bin is

<u>(mB)! (CB mB)!</u> *p₁* = *:* (*CB*)!

Thus, the probability that *A* wins is exactly

*‘ mB* 1 <u>c</u> *p* = <u>(CB + c mB)! (mB)!</u> = *CB* + *c* *:* *‘* 1 (*CB* + *c*)! *mB* *c*

For *c B*, 1 *m C*, this is maximized when *m* = 1.

Now we prove security of protocolZK. *p;r*

|B. Protocol|UC-realizes F||-hybrid model. In particular,|
|---|---|---|---|
||ZK||sVOLE|
|CB+c|1 r|||
|B||open||

Theorem 1. *Let c*ZK ZK*in the F* sVOLE *no environment Z can distinguish the real-world execution from the ideal-world execution except* *with probability at most* + *p* + *".*

*Proof.* We rst consider the case of a malicious prover (i.e., soundness) and then consider the case of a malicious verier (i.e., zero knowledge). In each case, we construct a PPT simulator *S* given access to *F*ZK, and running the PPT adversary *A* as a subroutine while emulating functionality *p;r* *F* sVOLE for *A*. We always implicitly assume that *S* passes all communication between *A* and *Z*.

Malicious prover. *S* interacts with adversary *A* as follows: *p;r* *r*

1. *S* emulates *F*

|||for A by choosing uniform 2 F||||g,|
|---|---|---|---|---|---|---|
||sVOLE|||p|p;r|i i2I|
|i i i|i2[‘]|i i2[C]|0|p;r|sVOLE||
|||||sVOLE|||
||||ZK||||

sVOLE *p* and recording all the values *fi i2I* in *p;r* *f*(*x;y;r*)*g*, and *fs g*, and their corresponding MAC tags, sent to *F* by *A*. These values dene corresponding keys in the natural way.

*0*

2.If *A* makes a global-key query (guess*;*) to *F*, then *S* checks if =. If not, *S* sends abort to *A*, sends (prove*; C; ?*) to *F*, and aborts. Otherwise, *S* sends success to *A* and continues.
3.When *A* sends *figi2I*
in in step4, *S* sets *wi*:=*i*+*i*for *i 2I*in.

4. *S* runs the rest of the protocol as an honest verier, using and the keys dened in the rst step. If the honest verier outputs false, then *S* sends (prove*; C; ?*) to *F*ZKand aborts. If the honest verier outputs true, then *S* sends (prove*; C;w*) to *F*ZKwhere *w* is dened as above.

We assume that *A* does not correctly guess; this is true except with probability at most *p* *r*. It is clear that the view of *A* is perfectly simulated by *S*. Whenever the verier simulated by *S* outputs false, the real verier outputs false as well (since *S* sends*?* to *F*ZK). It thus only remains to bound the probability with which the simulated verier run by *S* outputs true but the witness *w* sent by *S* to *F*ZKsatises *C*(*w*) = 0. Below, we show that if *C*(*w*) = 0 then the probability that *CB*+*c* 1 the simulated verier outputs true is at most *B* + *"*open. If *C*(*w*) = 0 then either *wo*= 0 or else at least one of the triples *f*([*w*]*;* [*w*]*;* [*w*])*g* dened at the multiplication gates during the circuit evaluation must be incorrect. In the former case, the probability that *P* succeeds when running CheckZero([*wo*] 1) is at most *"*open. In the latter case, *CB*+*c* 1 Lemma1shows that the probability that *A* avoids being \caught" in steps6{8is at most *B*; if *A* is caught, then it succeeds in opening some incorrect value with probability at most *"*open. This completes the proof for the case of a malicious prover.

Malicious verier. If *S* receives false from *F*ZK, then it simply aborts. Otherwise, *S* interacts with adversary *A* as follows: *p;r*

1. *S* emulates *F*
sVOLE by recording the global key, and the keys for all the authenticated values, sent to the functionality by *A*. Then, *S* samples uniform values for *figi2I* in, *f*(*xi;yi;ri*)*gi2*[*‘*], and *fsigi2*[*C*], and computes their corresponding MAC tags in the natural way.

2. *S* executes steps3{8of protocolZKby simulating the honest prover with input *w* = 0
*jI*in*j*. *p;r*

3.In step9, *S* computes K[*wo*] (based on the keys sent to *F*
sVOLE by *A*) and then sets M[*wo*] := K[*wo*] +. Finally, it uses M[*wo*] to run CheckZero([*wo*] 1) with *A*.

The view of *A* simulated by *S* is distributed identically to its view in the real protocol execution. This completes the proof.

## 3.2 Other Approaches for Verifying Correct Behavior

Here we describe alternative approaches for checking correctness of multiplication gates for large *p* (i.e., log*p*).

Approach 1. The rst approach can be viewed as a simplied version of the check used by SPDZ [DPSZ12]. Both parties now prepare a *single* authenticated multiplication triple ([*x*]*;* [*y*]*;* [*z*]) per multiplication gate (so only *C* in total), which may be incorrect if *P* is malicious. To check correctness of a multiplication gate with authenticated values [*w*], [*w*] on the input wires and [*w*] on the output wire, the verier sends a uniform *2* F*p*to the prover, who responds by running := Open( [*w*] [*x*]) and := Open([*w*] [*y*]), followed by

CheckZero([*z*] [*w*] + [*x*] + [*y*] +)*:*

This has soundness error 1*=p* + *"*open. To see this, say *w* = *w w* +*w*with*w6*= 0, and let *z* = *xy* +*z*. Then *z w* + *x* + *y* + = 0 i =*z=w*, which occurs with probability 1*=p*. Note that this checking procedure can be done for all multiplication gates in parallel using a single value, and the overall soundness error remains unchanged. It can also be made non-interactive using the Fiat-Shamir heuristic in the random-oracle model.

Approach 2: Trading o communication and computation. This approach, which is a simplied and improved variant of the polynomial approach used by SPDZ [DPSZ12], reduces the communication complexity by roughly half (from 4 to 2 eld elements per gate) at the expense

of increased computation. Intuitively, the prover and verier dene polynomials *F;G;H* that interpolate to *fw* *i* *g*, *fw* *i* *g*, and *fw* *i* *g*, respectively. If *w* *i* = *w* *i* *w* *i* for all *i*, then *H* = *F G*, and this can be veried by checking whether *H*() = *F* () *G*() at a random point *2* F*pr*. Details follow. Assume *p* 2*C* 1. Let ([*w* *i*]*;* [*w* *i*]*;* [*w* *i*]) be the authenticated values corresponding to the *i*th multiplication gate. The parties additionally compute *C* 1 authenticated values *f*[*si*]*gi2*[*C*+1*;*2*C*); they also compute an authenticated multiplication triple ([*x*]*;* [*y*]*;* [*z*]) (which may be incorrect if *P* is malicious) with *x;y;z 2* F*pr*. 1 They then do the following:

1.Let *F 2* F*p*[*X*] (resp., *G 2* F*p*[*X*]) be the polynomial of degree at most *C* 1 such that *F* (*i*) = *w*
*i* (resp., *G*(*i*) = *w* *i* ) for *i 2* [*C*]. Note that *P* can compute *F* and *G* explicitly, and *P* and *V* can *k* def *k* def compute the authenticated value [*w*] = [*F* (*k*)] (resp., [*w*] = [*G*(*k*)]) for any *k 2* F*pr* using Lagrange interpolation over the shares *f*[*w* *i*]*gi2*[*C*](resp., *f*[*w* *i*]*gi2*[*C*]).

2.For *k 2* [*C* + 1*;* 2*C*), *P* sends *d*
*0k* := *w* *k* *w* *k* *sk*to *V*, and both parties compute [*w* *k*] := [*sk*] +*d* *0k*. Let *H 2* F*p*[*X*] be the polynomial of degree at most 2*C* 2 such that *H*(*i*) = *w* *i* for *i 2* [2*C* 1]. Note that *P* can compute *H* explicitly, while *P* and *V* can compute the authenticated value [*H*(*k*)] for any *k 2* F*pr* using Lagrange interpolation over the shares [*w* *i*].

3. *V* sends a uniform *2* F*pr* to *P*. Then the parties compute authenticated values [*F* ()], [*G*()], and [*H*()].
4.Finally, *V* veries that *F* () *G*() = *H*() as in approach 1, above. That is, *V* sends a uniform *2* F*pr* to *P*, who responds by running := Open( [*F* ()] [*x*]) and := Open([*G*()] [*y*]), followed by
CheckZero([*z*] [*H*()] + [*x*] + [*y*] +)*:*

This has soundness error (2*C* 1)*=p* *r* + *"*open. To see this, note that if there exists an *i 2* [*C*] with *w* *i* *w* *i* *6*= *w* *i* then the polynomials *F G* and *H* are dierent, and so agree in at most 2*C* 2 points. Thus, *F* () *G*() *6*= *H*() except with probability at most (2*C* 2)*=p* *r*. When that is the case, an analysis in the rst approach shows that the nal check fails except with probability at most 1*=p* *r* + *"*open. This approach can also be made non-interactive using the Fiat-Shamir heuristic in the random- oracle model.

# 4 Subeld VOLE

In this section, we present an sVOLE protocol that can be used during the oine phase of our ZK protocol. In Section5, we rst present an sVOLE protocol with linear communication complexity. Although this already suces for our ZK protocol, we can obtain much better eciency using \sVOLE extension" (by analogy with OT extension), by which we extend a small number of \base" sVOLE correlations into a larger number of sVOLE correlations. Toward this end, in Section5.1 *p;r* we construct a protocol for *single-point* sVOLE (spsVOLE) in the *F* sVOLE -hybrid model, where spsVOLE is like sVOLE except that the vector of authenticated values has only a *single* nonzero entry. Then, in Section5.2, we present an ecient protocol for \sVOLE extension" using spsVOLE 1 A uniform authenticated value [*z*] with *z 2* F*pr* can be generated from *r* uniform authenticated values [*z₁*]*; : : : ;*[*zr*] P*i* with *zi* F*p* by setting *z* =*izi* X. An authenticated multiplication triple can be computed from such authenticated values in the natural way.

<u>Functionality F</u> <u>COPEe</u> *p;r*

Initialize: Upon receiving init from parties PA, PB, sample F*pr* if PBis honest, and receive *2* F*pr* from the adversary otherwise. Store global key, send to PB, and ignore all subsequent init commands. *rm* Let*B2f*0*;* 1*g* be the bit-decomposition of, where *m* = *d*log *pe*. Extend: Upon receiving (extend*;u*) with *u 2* F*p*from PAand (extend) from PB, this functionality operates as follows:

1.Sample *v* F*pr*. If PBis corrupted, instead receive *v 2* F*pr* from the adversary.
2.Compute *w* := *v* + *u 2* F*pr*.
3.If P *r*
*rm*

|is corrupted, receive w 2 F||and u 2 F|from the adversary, and recompute|||
|---|---|---|---|---|---|
|A||p|rm p|B|p|

*v* := *w hg u; i2* F *r;*

where denotes the component-wise product.

4.Output (*u;w*) to PAand *v* to PB.
Figure 4: Functionality for correlated oblivious product evaluation with errors

(COPEe).

as a subroutine and relying on a variant of the *Learning Parity with Noise* (LPN) assumption. We provide some intuition for each protocol in the relevant section. Our implementation shows that this protocol outperforms all prior work; we discuss its concrete performance in Section6.1.

# 5 Base sVOLE Protocol

We present a \base" sVOLE protocol that is based on oblivious transfer (OT) and is inspired by prior work of Keller et al. [KOS15,KOS16]. Our protocol relies on the *correlated oblivious* *product evaluation with errors* (COPEe) functionality *F*COPEe, which extends the analogous func- tionality introduced by Keller et al. [KOS16] to the subeld case we are interested in. We show in AppendixB.1how to UC-realize *F*COPEefrom OT. Functionality *F*COPEeis described in Figure4, where *m* = *d*log *pe*. In *F*COPEe, we dene a \gadget vector" *g 2* F *rm* *p* *r* by

*g* = (1*;* 2*;:::;*2 *m* 1

)*;*(1*;* 2*;:::;*2
*m* 1 ) X*;:::;* (1*;* 2*;:::;*2 *m* 1 ) X *r* 1 *:*

For a vector *x 2* F *rm* *p* *r*, we dene

X *r* 1 *m* X¹ *hg; xi* = *x*[*i m* + *j*] 2 *j* X *i* *2* F*pr;* *i*=0 *j*=0

where the denition can be extended to the cases *x 2f*0*;* 1*g* *rm* or *x 2* F *rm* *p*by viewing *x* as lying in *rm* *r* *rm* F*pr* in the natural way. The bit-decomposition of *2* F*p*is the string*B2f*0*;* 1*g* satisfying *hg;Bi* =. *p;r p;r* In Figure5, we present a protocol base-sVOLE that UC-realizes *F* sVOLE in the *F*COPEe-hybrid *p;r* model. We rst describe a sub-protocol base-LsVOLE, which allows two parties to generate sVOLE correlations with a selective-failure leakage on, meaning that a malicious PAis allowed to guess

<u>Protocol</u> *p;r* <u>base-sVOLE</u>

Sub-protocol *p;r* base-LsVOLE with selective-failure leakage:

1. PAand PBsend init to *F*
COPEe *p;r*, which returns to PB.

2. PAsamples *ui*F*p*for *i 2* [0*;n*) and *ah*F*p*for *h 2* [0*;r*). For *i 2* [0*;n*), PAsends (extend*;ui*) to *F* COPEe *p;r* and PBsends (extend) to *F*
COPEe *p;r*, which returns *wi2* F*pr* to PAand *vi2* F*pr* to PBsuch that

|w = v +|u. For h 2 [0;r), both parties also call F|||||on respective inputs (extend;a|||) and|
|---|---|---|---|---|---|---|---|---|---|
|i i|i|A|h p|B|COPEe h|p|h h|h h||
|||||||||n 1||
|B|0|n 1|p||A|A||i=0 i|i|
|r 1|h|n 1|r 1|h||||||
|h=0 h||i=0 i n 1|i h=0 r 1|h h||B||||
|B|A|i=0 i|h=0 h i|i|B|i||B||

*i i i* COPEe *p;r* *h* (extend), following which P gets *c 2* F *r* and P obtains *b 2* F *r* such that *c* = *b* + *a*. P

3. P samples*;:::;* F *r*, and sends them to P. Then P computes *x* := *u* + P P P *a* X, *z* := *w* + *c* X, and sends (*x;z*) to P.
P P

4. P computes *y* := *vi*+ *b* X and checks that *z* = *y* + *x*. If not, P aborts.
5.For *i 2* [0*;n*), P denes *u*[*i*] = *u* and *w*[*i*] = *w*, and P sets *v*[*i*] = *v*. Full protocol without any leakage: Let *‘* = *d*2*=r* log *pe* + 1.
1.Both parties execute the above sub-protocol with parameters *p* and *k* = *‘ r*. Then, PAobtains
*n*

|(u; w) 2 F|F|and P|gets 2 F|and v 2 F||such that w = v +||
|---|---|---|---|---|---|---|---|
||n p n p p|B|‘p|p|n p|i i2[‘]|i i i2[‘]|
|i|i|i i i|n p|i||||
|B|1|‘ p ‘|||A ‘||‘|
|A||i=1 i|i B||i=1|i i|i=1 i i|
|A||B||||||

*p* *n* *p* *k* B *pk* *n* *p* *ku*. By viewing an element in F *k* as a vector in F *r*, two parties obtain *fw g* and *f*(*; v*)*g* respectively such that *w* = *v* + *u*, *w; v 2* F *r* and *2* F*pr*.

2. P samples*;:::;* F *r* and sends them to P.
P P P P computes *t* := *w*; P computes *s* := *v* and :=, where *t* = *s*+ *u*.

3. P outputs *u* and *t*; P outputs and *s*.
Figure 5: Base sVOLE protocol in the *F*COPEe-hybrid model.

a subset of and the protocol execution aborts for an incorrect guess. In this sub-protocol, PB performs a *correlation check* in steps3and4to verify that the resulting sVOLE correlations are *p;r* correct (i.e., *w* = *v* + *u*). Then, based on base-LsVOLE, we show how to generate sVOLE *p;r* correlations without such leakage using the leftover hash lemma [ILL89]. In protocol base-sVOLE, all the uniform coecients (i.e., *fig; fig*) can be computed from a random seed and a hash function modeled as a random oracle. We prove the following in the full version of our work. *p;r p;r p;r* Theorem 2. *Protocol* base*-*sVOLE *UC-realizes F* sVOLE *in the F* COPEe *-hybrid model. In particular,*

|base-sVOLE||sVOLE|COPEe|
|---|---|---|---|
||2 r|||

*no PPT environment Z can distinguish the real-world execution from the ideal-world execution,* *except with probability at most* (*r*log*p*) *=p* + 1*=*2*.*

Optimization. For many applications (e.g., our protocols) where learning the entire global key is necessary in order to violate security of some higher-level protocol, it is unnecessary to eliminate the selective-failure leakage about. This can be argued as follows. Assume the adversary guesses a set *S* (if there are multiple guesses then *S* is the intersection of all guessed sets) and is caught cheating if *62 S*. The probability that the selective-failure attack is successful is *jSj=p* *r*; conditioned on this event, the min-entropy of is reduced to log *jSj*. Therefore, the overall probability for the adversary to determine is *jSj=p* *r* 2 log *jSj* = *p* *r*, which is the same as the probability in the absence of any leakage. Similar observations have been used in secure-computation protocols [KOS16,CDE + 18, YWZ20].

<u>Functionality F</u> <u>spsVOLE</u> *p;r*

Initialize: Upon receiving init from PAand PB, sample F*pr* if PBis honest and receive *2* F*pr* from the adversary otherwise. Store global key, send to PB, and ignore all subsequent init commands. Extend: Upon receiving (sp-extend*;n*), where *n* = 2 *h* for some *h 2* N, from PAand PB, do:

1.If PBis honest, sample *v* F
*n* *p*

*r*. Otherwise, receive *v 2* F
*n* *p* *r* from the adversary.

2.If PAis honest, then sample uniform *u 2* F
*n* *p*with exactly one nonzero entry, and compute *w* := *v* + *u 2* F *n* *p*

*r*. Otherwise, receive *u 2* F
*n* *p*(with at most one nonzero entry) and *w 2* F *n* *p* *r* from the adversary, and recompute *v* := *w u 2* F *n* *p*

*r*.
3.If PBis corrupted, receive a set *I* [0*;n*) from the adversary. Let *2* [0*;n*) be the index of the nonzero entry of *u*. If *2 I*, send success to PBand continue. Otherwise, send abort to both parties and abort.
4.Send (*u; w*) to PAand *v* to PB. Global-key query: If PAis corrupted, receive (guess*;*
*0* ) from the adversary with *0* *2* F*pr*. If *0* =, send success to PAand ignore any subsequent global-key query. Otherwise, send abort to both parties <u>and abort.</u>

Figure 6: Functionality for single-point sVOLE.

## 5.1 Single-Point sVOLE

Single-point sVOLE is a variant of sVOLE where the vector of authenticated values contains exactly *p;r* one nonzero entry. We present the associated functionality *F* spsVOLE in Figure6, where the vector length *n* = 2 *h* is assumed to be a power of two for simplicity. In Figure7, we present a protocol *p;r p;r p;r* spsVOLE that UC-realizes *F* spsVOLE in the (*F* sVOLE *; F*OT*; F*EQ)-hybrid model, where *F*OTis the

|standard OT functionality and F||||’s input|
|---|---|---|---|---|
|B|EQ|||A|

EQcorresponds to a weak equality test that reveals PA to P. (See AppendixAfor formal denitions of both functionalities.) Conceptually, the protocol can be divided into two steps: (1) the parties run a semi-honest protocol for generating a vector of authenticated values [*u*] having a single nonzero entry; then (2) a consistency check is performed to detect malicious behavior. We explain both steps in what follows. PAbegins by choosing a uniform *2* F*p*and a uniform index. Letting *u 2* F *n* *p*be the vector that is 0 everywhere except that *u*[] =, the goal is for the parties to generate [*u*]. That is, they want PAto hold *w 2* F *n* *p* *r* and PBto hold *v 2* F *n* *p* *r* such that *w* = *v*+ *u*. To do so, the parties begin *p;r* by generating the authenticated value []; this is easy to do using a call to *F* sVOLE. Next, they use a subroutine [BGI15,BGI16,BCG + 17] based on the GGM construction [GGM86] to enable PBto generate *v 2* F *n* *p* *r* while allowing PAto learn all the components of that vector except for *v*[]. This is done in the following way. Let *G* : *f*0*;* 1*g!f*0*;* 1*g²* and *G⁰* : *f*0*;* 1*g!* F²*pr* be pseudorandom generators (PRGs). PBchooses uniform *s 2f*0*;* 1*g* and computes all nodes in a GGM tree of depth *h* with *s* at the root: That is, letting *s* *ij* denote the value at the *j*th node on the *i*th level of the tree,

PBdenes *s⁰*0:= *s* and then for *i 2* [1*;h*) and *j 2* [0*;* 2 *i* 1 ) computes *s* *i* 2*j* *;s* *i* 2*j*+1 := *G*(*s* *ij* 1 ); nally,

PBcomputes a vector *v* at the leaves as (*v*[2*j*]*; v*[2*j* + 1]) := *G⁰*(*s* *h* *j* 1 ) for *j 2* [0*;* 2 *h* 1 ). Next, PB lets *K₀* *i* (resp., *K₁* *i* ) be the XOR of the values at the even (resp., odd) nodes on the *i*th level. (When *i* = *h* we replace XOR with addition in F*pr*.) We write

*fvjgj2*[0*;n*)*; f*(*K₀* *i* *;K₁* *i*

)*gi2*[*h*]:= GGM(1
*n* *;s*)

<u>Protocol</u> *p;r* <u>spsVOLE</u>

Initialize: This procedure is executed only once.

PAand PBsend init to *F* sVOLE *p;r*, which returns to PB.

Extend: This procedure can be run multiple times. On input *n* = 2 *h*, the parties do:

|1. P and P|send (extend; 1) to F||, which returns (a;c) 2 F|||F to P|and b 2 F|to P|such|
|---|---|---|---|---|---|---|---|---|---|
|A|B||sVOLE A|p||p p|A|p B p B||
||||||p|||||
|A||||n p||||||
|B|||n||j j2[0;n)|i|i i2[h]||j|
|A|A j j6=|A i i|OT i i2[h]|B|i i|OT||i A||
|B||i2[0;n)|p|A|A|n p|||i|
||||i6=|||||||

A B sVOLE *p;r* *p pr*A *pr*B that *c* = *b* + *a*. Then, P samples F, sets := *c*, and sends *a⁰* := *a 2* F to P, who computes := *b a⁰*. Note that = + *2* F *r*, so the parties now hold []. P samples [0*;n*) and denes *u 2* F as the vector that is 0 everywhere except *u*[] =.

2. P samples *s f* 0*;* 1*g*, runs GGM(1*;s*) to obtain *fv g; f*(*K₀;K₁*)*g*, and sets *v*[*j*] := *v* for *j 2* [0*;n*). P lets be the complement of the *i*th bit of the binary representation of. For *i 2* [*h*], P sends *2f*0*;* 1*g* to *F* and P sends (*K₀;K₁*) to *F*, which returns *K*
*i* to P. Then P runs *fv g* := GGM⁰(*; fK* *i*

*g*).
P

3. P sends *d* := *v*[*i*] *2* F *r* to P. Then, P denes *w 2* F *r* as the vector with *w*[*i*] := *v*
P for *i 6*= and *w*[] := *d* + *w*[*i*]. Note that *w* = *v* + *u*.

Consistency check:

4.Both parties send (extend*;r*) to *F*
sVOLE *p;r*, which returns (*x; z*) *2* F *r* *p*F *r* *p* *r* to PAand *y 2* F *r* *p* *r* to PB such that *z* = *y* + *x*. P*r* 1 *i r*

5. PAsamples*i*F*pr* for *i 2* [0*;n*), and writes =*i*=0*;i*X. Let = (*;*0*;:::;;r* 1) *2* F*p*. PAthen computes *x* := *x 2* F
*r* *p*and sends *figi2*[0*;n*)*; x* to PB, who computes *y* := *y x 2* F *r* *p*

*r*. P*r* 1
*i* P*n* 1

6. PAcomputes *Z* :=*i*=0*z*[*i*] X *2* F*pr* and *V*A:=*i*=0 *iw*[*i*] *Z 2* F*pr*, while PBcomputes P*r* 1
*i* P*n* 1 *Y* :=*i*=0*y*[*i*] X *2* F*pr* and *V*B:=*i*=0 *iv*[*i*] *Y 2* F*pr*. Then PAsends *V*Ato *F*EQ, and PB sends *V*Bto *F*EQ. If either party receives false or abort from *F*EQ, it aborts.

7. PAoutputs (*u; w*) and PBoutputs *v*.
Figure 7: Single-point sVOLE protocol in the (*F*

sVOLE *p;r* *; F*OT*; F*EQ)-hybrid model.

to denote this computation done by PB. It is easily veried that if PAis given *fK* *i* *i* *gi2*[*h*](where *i*is the complement of the *i*th bit of), then PAcan compute *fv*[*j*]*gj6*=, while *v*[] remains com- putationally indistinguishable from uniform given PA’s view. We denote the resulting computation of PAby *fvjgj6*=:= GGM⁰(*; fK* *i* *i* *gi2*[*h*]). (PAcan obtain *fK* *i* *i* *gi2*[*h*]using *h* OT invocations.) Following the above, PAsets *w*[*i*] := *v*[*i*] for *i 6*=. Note that *w*[*i*] = *v*[*i*] + *u*[*i*] for *i 6*= (since *u*[*i*] = 0 for *i 6*=), so all that remains is for PAto obtain the missing value *w*[] = *v*[]+ (without revealing*;* to PB). Recall the parties already hold [], meaning that PAholds M[] P and PBholds K[] with M[] = K[] +. So if PBsends K[] *i* *v*[*i*], then PAcan compute the missing value as P P *w*[] = M[] (K[] *i* *v*[*i*]) *i6*= *v*[*i*]

= M[] K[] + *v*[] = *v*[] + *:*

This completes the \semi-honest" portion of the protocol. To verify correct behavior, we generalize the approach of Yang et al. [YWL + 20] that applies only to the case *p* = 2. We want to verify that *w*[*i*] = *v*[*i*] for *i 6*=, and *w*[] = *v*[] +. Intuitively, the parties do this by having PAchoose uniform*;:::;n*F*pr* and then checking

that *n* X 1 *n* X 1 *iw*[*i*] =*iv*[*i*] + *:* *i*=0 *i*=0 *p;r* Of course, this must be done without revealing*;* to PB. To do so, PAand PBuse *F* sVOLE to compute *Z;Y 2* F*pr*, respectively, such that *Z* = *Y* +. (We discuss below how this is P *n* 1 P *n* 1 done.) They then use *F*EQto check if *V*A= *i*=0 *i* *w*[*i*] *Z* is equal to *V*B= *i*=0 *i* *v*[*i*] *Y*. To complete the description, we show how the parties can generate *Z;Y* (held by PA, PB, respectively) such that *Z* = *Y* +. (This is like an authenticated value [], but note that lies in F*pr* rather than F*p*.) PAviews *2* F*pr* as = (*;*0*;:::;;r* 1) *2* F *rp* (i.e., P *i i* = *i2*[0*;r*)*;i* X, where *f*X *gi2*[0*;r*)form a basis for F*pr* over F*p*), and then the parties use *p;r* *F* sVOLE to generate the vector of authenticated values []. This means PAholds *z* and PBholds P *i* P *i* *y* such that *z* = *y* +. Let *Z* = *i2*[0*;r*) *z*[*i*] X and *Y* = *i2*[0*;r*) *y*[*i*] X. We have that

X *r* 1 X *r* 1 *Z* = *z*[*i*] X *i* = (*y*[*i*] + [*i*]) X *i* *i*=0 *i*=0 X *r* 1 X *r* 1 = *y*[*i*] X *i* + [*i*] X *i* *i*=0 *i*=0 = *Y* + *;*

as desired.

|We remark that this check allows a malicious P||to guess, and allows a malicious P||to guess|
|---|---|---|---|---|
|||A||B|
|||p;r spsVOLE|p;r|p;r|
|p;r|||spsVOLE|spsVOLE|
|sVOLE|OT EQ||||
|||||r|

a subset in which the index lies. (This will become evident in the proof of security.) Such guesses are incorporated into the ideal functionality *F*.

*0* Theorem 3. *If G and G are pseudorandom generators, then UC-realizes F in* *the* (*F; F; F*)*-hybrid model. In particular, no PPT environment Z can distinguish the* *real-world execution from the ideal-world execution except with probability at most* 1*=p* + negl()*.*

The proof of Theorem3is given in AppendixB.3.

Optimizations. We discuss various optimizations of the protocol shown in Figure7: *p;r*

1.For large *p* (i.e., log*p*), the parties can use the output of *F*
sVOLE directly as [] in step1of *p;r* protocol spsVOLE, since *6*= 0 with overwhelming probability.

2.In the consistency check, PAcan send uniform seed *2f*0*;* 1*g* to PB, who then derives the *fig* from seed using a hash function modeled as a random oracle.
3.When *t* extend executions are needed, we can batch the consistency checks using the ideas of Yang et al. [YWL
+ 20] to reduce the total number of sVOLE correlations needed from *t* (1 +*r*) to *t* + *r*. The approach is as follows:

(a)After *t* executions of the semi-honest portion of the extend phase, the parties hold *f*(*uj; wj*)*g*
*tj* =1 and *fv* *tj*

|g|, respectively, where for all j 2 [t] we have w|||= v +|a vector||
|---|---|---|---|---|---|---|
|j tj=1||||j j|j||
|||j j|j|B|p;r sVOLE||
||A|B i;j p j2[t] j|;j|;j i;j i2[0;n);j2[t]|;j B|rp|
|||rp|||||

=1 *uj*with *u* that is 0 everywhere except *u* [] =. Then PAand P send (extend*;r*) to *F*, which returns (*x; z*) to PAand *y* to P.

(b)For *j 2* [*t*], P samples F *r* for *i 2* [0*;n*), and views*j*as the vector*j*F.
P It then computes *x* :=*jx* and sends *f g* and *x* to P, who computes *y* := *y x* F *r*.

P *n* 1 P *t* P *r* 1 *i* P *n* 1 P *t*

(c) PAcomputes *V*A:=
*i*=0 *j*=1 *i;j* *wj*[*i*] *i*=0 *z*[*i*] X; PBcomputes *V*B:= *i*=0 *j*=1 *i;j* P *r* 1 *i* *vj*[*i*] *i*=0 *y*[*i*] X. Then both parties check whether *V*A= *V*Bby calling *F*EQ.

## 5.2 sVOLE Extension

We show here a protocol that can be viewed as a means of performing \sVOLE extension." That is, our protocol allows two parties to eciently extend a small number of sVOLE correlations (created in a setup phase) to an arbitrary polynomial number of sVOLE correlations. The protocol relies on spsVOLE as a subroutine, as well as a variant of the LPN assumption that has been used in prior work [HOSS18,BCG + 19a,YWL + 20].

Protocol overview. The parties use the base-sVOLE protocol to generate a length-*k* vector of authenticated values [*u*]. They also use spsVOLE to generate *t* vectors of authenticated values, each of length *n=t* and having a single nonzero entry; they let [*e*] be the concatenation of those vectors. The parties then use a public matrix A to dene the length-*n* vector of authenticated values [*u* A + *e*]; by the LPN assumption, the corresponding values (which PAknows) will appear pseudorandom to PB. This provides a way to extend *k* random sVOLE correlations to *n* pseudorandom sVOLE correlations once. As in prior work [YWL + 20], however, we can generate *‘* = *n k* correlations as many times as desired by simply using this idea to generate *n* sVOLE correlations and reserving the rst *k* of those correlations for the next iteration of the extend phase.

LPN assumption. Let *Dn;t*denote the distribution over an error vector *e 2* F *n* *p*in which *e* is divided into *t* blocks (each of length *n=t*), and each block of contains exactly one uniform nonzero entry at a uniform location within that block.

Denition 1 (LPN with static leakage [BCG + 19a]). *Let G be a polynomial-time algorithm that on* *input* 1 *k* *;* 1 *n* *;p outputs* A *2* F *k* *p* *n* *. Let parameters k;n;t be implicit functions of security parame-* *ter. We say that the* LPN *G* *k;n;t;p* *assumption holds if for all PPT algorithms A we have*

Pr[LPN*-*Succ *G* *A* () = 1] 1*=*2 negl()*;*

*where the experiment* LPN*-*Succ *G* *A* () *is dened as follows:*

*1.Sample* A *G* (1
*k* *;* 1 *n* *;p*)*, u* F *k* *p, and e Dn;t. Let*1*;:::;tbe the indices of the nonzero* *entries in e (each of which is located in a disjoint block of length n=t).*

*2. A outputs t subsets I₁;:::;It*[0*;n*)*. Ifi2 Iifor all i 2* [*t*]*, then send* success *to A; otherwise,* *abort the experiment and dene b⁰* := 0*.*
*3.Pick b f* 0*;* 1*g. If b* = 0*, let x* := *u* A + *e; otherwise, sample x* F
*n*

*p. Send x to A, who then*
*outputs a bit b⁰ (if the experiment did not abort).*

*4.The experiment outputs 1 i b⁰* = *b.*
*p;r p;r* Protocol description. In Figure8, we present our sVOLE extension protocol in the (*F* sVOLE *; F* spsVOLE )- hybrid model. For simplicity, we assume a public matrix A *2* F *k* *p* *n*, output by an ecient algorithm *G*(1 *k* *;* 1 *n* *;p*), that is xed at the outset of the protocol. (It is also possible to have PAgenerate A *p;r p;r* and then send it to PB.) We assume that *F* spsVOLE and *F* sVOLE share the same initialization (i.e., *p;r* use the same global key ). This holds, in particular, when we use protocol spsVOLE from the *p;r* previous section to UC-realize *F* spsVOLE.

<u>Protocol</u> *p;r* <u>sVOLE</u>

Parameters: Fix *n;k;t*, and dene *‘* = *n k* and *m* = *n=t*. Let A *2* F*p* *k n* be a matrix output by *G*(1 *k* *;* 1 *n* *;p*).

Initialize: This procedure is executed only once.

1. PAand PBsend init to *F*
sVOLE *p;r*, which returns *2* F*pr* to PB.

2. PAand PBsend (extend*;k*) to *F*
sVOLE *p;r*, which returns (*u; w*) to PAand *v* to PBsuch that *w* = *v* + *u 2* F *k* *p*

*r*.
Extend: This procedure can be executed multiple times.

3.For *i 2* [*t*], PAand PBsend (sp-extend*;m*) to *F*
spsVOLE *p;r*, which returns (*ei; ci*) to PAand *bi*to PBsuch that *ci*= *bi*+ *ei2* F *m* *p* *r* and *ei2* F *m* *p*has exactly one nonzero entry. If either party receives abort from *F* spsVOLE *p;r* in any of these spsVOLE executions, it aborts.

4. PAdenes *e* = (*e₁;:::; et*) *2* F
*n* *p*and *c* = (*c₁;:::; ct*) *2* F *n* *p*

*r*. Then PAcomputes *x* := *u* A + *e 2* F
*n* *p* and *z* := *w* A + *c 2* F *n* *p*

*r*. PBdenes *b* = (*b₁;:::; bt*) *2* F
*n* *p* *r* and computes *y* := *v* A + *b 2* F *n* *p*

*r*.
5. PAupdates *u; w* by setting *u* := *x*[0 : *k*) *2* F
*k* *p*and *w* := *z*[0 : *k*) *2* F *k* *p* *r*, and outputs (*s;* M[*s*]) := (*x*[*k* : *n*)*; z*[*k* : *n*)) *2* F *‘p* F *‘p*

*r*. PBupdates *v* by setting *v* := *y*[0 : *k*) *2* F
*k* *p* *r*, and outputs K[*s*] := *y*[*k* :

*n*) *2* F *‘p*
*r*.
Figure 8: The sVOLE extension protocol in the (*F*

sVOLE *p;r* *; F* spsVOLE *p;r* )-hybrid model.

*G p;r p;r p;r p;r* Theorem 4. *If the* LPN *k;n;t;p* *assumption holds, then* sVOLE *UC-realizes F* sVOLE *in the* (*F* sVOLE *; F* spsVOLE )*-* *hybrid model.*

A proof of the above can be found in AppendixB.4, where we also describe further optimizations *p;r* for protocol sVOLE.

# 6 Performance Evaluation

In this section, we report on the performance of our sVOLE protocol and our overall ZK pro- tocol for both boolean and arithmetic circuits. All our protocols were implemented in the EMP toolkit [WMK16], and we will release an open-source version of our code. In all our experiments, we use two Amazon EC2 instances of type m5.4xlarge with 16 vCPUs and 64 GB of RAM, using 5 threads. We articially limit the network bandwidth as indicated in each experiment. All imple- mentations achieve the statistical security parameter 40 and computational security parameter = 128.

## 6.1 (Subeld) Vector Oblivious Linear Evaluation

*p;r* We focus here on the performance of protocol sVOLE over large elds; specically, we x the Mersenne prime *p* = 2 61 1 and set *r* = 1. (Since *r* = 1, sVOLE is equivalent to VOLE in this case.)

Parameter selection. As suggested in prior work [BCGI18,SGRR19,YWL + 20], we choose the public LPN matrix A as a generator of a 10-local linear code, which means that each column of A contains exactly 10 (uniform) nonzero entries. This is advantageous since it means that computing each entry of *u* A involves reading only 10 positions of *u 2* F *k*

*p*. To ensure that reading those

<u>One-time setup Extend execution</u> *k₀ n₀ t₀ k n t* 19,870 642,048 2,508 589,760 10,805,248 1,319

Table 2: LPN parameters used in our VOLE protocol.

||20 Mbps|50 Mbps|100 Mbps|500 Mbps|1 Gbps|
|---|---|---|---|---|---|
|Init. (ms)|1343|640|478|451|438|
|Extend (ns/VOLE)|101|87|85|85|85|

Table 3: Eciency of our VOLE protocol as a function of network bandwidth. The communication

per VOLE correlation is 0.42 bits; the overall communication of the one-time setup is 1.1 MB.

positions can be done quickly, we set *k* so that *u* ts in the L1 CPU cache (i.e., the size of *u* is less than 8 MB). With *k* xed, for any choice of *n > k* we can take the smallest *t* for which all known attacks on the LPN problem require at least 2 128 operations [BCGI18,BCG + 19a]. When we apply the optimizations described at the end of the previous section to our protocol, we see that using LPN parameters (*n;k;t*) means that each invocation of the extend procedure results in *n k t* 1 usable VOLE correlations. We perform exhaustive search to nd the smallest *n* so that *n k t* 1 10 7. For the parameters of the setup phase, we follow the same step as above, except that we will ensure that *n₀ k₀ t₀* 1 *k*. This results in the LPN parameters shown in Table2. *p;r* Performance. We evaluate the eciency of protocol sVOLE in Table3. The extend procedure requires very little communication (less than half a bit per usable VOLE correlation), and its execution time is largely unaected by the network bandwidth above 100 Mbps. The one-time initialization only communicates 1.1 MB and takes roughly 478 milliseconds under a 100 Mbps network. In Table4, we compare our VOLE protocol with the best known protocols that have been implemented [SGRR19,dCJV20]. Since our protocol needs an one-time setup, that can be amor- tized over multiple executions, we report our performance both without one-time setup (in case multiple extensions are executed), and the one with one-time setup (in case only one extension is executed). We x the network bandwidth to 500 Mbps to match the experiments of Castro et al. [dCJV20]. Our protocol outperforms prior work even though prior work is secure only against *semi-honest* adversaries, whereas our protocol is secure in the malicious setting. Note in particular that the communication complexity of our protocol is orders of magnitude lower than prior work. Boyle et al. [BCG + 19a] also proposed a maliciously secure sVOLE protocol but only implemented their protocol for the special case *p* = 2*;r* = 128. Based on their implementation in that case, we estimate that for our choice of *p* their protocol would communicate roughly 0.14 bits per sVOLE;

Ours Ours [SGRR19] [dCJV20] (w/o setup) (w/ setup)

Communication (bits) 960 160 0.42 1.32 Execution time (*ns*) 2000 400 85 130

Table 4: Our VOLE protocol vs. prior protocols. We x the network bandwidth to 500 Mbps

and report the marginal cost per VOLE correlation. Running time for the protocol of Schoppmann et al. [SGRR19] is the time for communication alone; numbers for the protocol of Castro et al. [dCJV20] are taken from their paper and are based on the same network and CPU conguration but using 8 threads.

however their computation is much heavier than ours and would take time at least 900 *ns* per VOLE correlation. Therefore, we believe that our protocol is still more ecient for most network bandwidth settings.

## 6.2 Zero-Knowledge Proofs

We report on the performance of our ZK protocol for boolean and arithmetic circuits. In both cases, we use pipelining [HEKM11] to streamline the protocol execution. This signicantly reduces the memory usage (from linear in the circuit size to linear in the memory needed to evaluate the circuit non-cryptographically) and allows us to scale to very large circuits. To further reduce the memory usage for large circuits, we changed the protocol so that rather than checking the correctness of all *C* multiplication gates at the end, we check blocks of *C⁰ < C* gates at a time. This increases the round complexity to *O*(*C=C⁰*) but reduces the memory usage to *O*(*C⁰*).

6.2.1 Zero-Knowledge Proofs for Boolean Circuits In the boolean setting, we check correctness of multiplication gates as in Figure3. Theorem1
*C B0*+*c* shows that to achieve-bit statistical security we need *B* *>* 2. Setting *c* = *B*, we have

Q

|0|B|B 1|||
|---|---|---|---|---|
||i=1|||0|
|||i=0|||
|=B|||||
|||||p;r|
|||||sVOLE|

*0* *C B* + *B* <u>(C B + i)</u> Y <u>B</u>*0B* = = *C* + 1 *C;* *B B*! *B i*

and so we need *C⁰* 2. For the best eciency, we set *B* = 2 when possible. For batched opening of authenticated values, we use the second approach described in Section2.1along with + the Fiat-Shamir heuristic to make it non-interactive. We instantiate *F* using Ferret [YWL 20] with *p* = 2 and *r* = 128.

Performance. The execution of our protocol can be split into two stages: input processing, whose cost is proportional to the witness length, and circuit processing, whose cost is proportional to the number of AND gates. Therefore, we measure the scalability of our ZK protocol by increasing either the witness length or the circuit size while articially keeping the other value xed. The experimental results in Figure9show that the execution time is indeed linear in both the witness length and the circuit size, with very small marginal cost for each bit of the witness or each AND gate. For example, under a 50 Mbps network, the marginal time of our protocol is 3.35 *s* per bit of the witness and 0.5 *s* per AND gate of the circuit. The ZKGC approach [JKO13,HK20] is the only previous approach for ecient ZK proofs that scales to large circuits while using less than 10 GB of memory. The communication complexity of our protocol is roughly 15 lower than the ZKGC approach. For this reason, our protocol is particularly well-suited for settings involving a low-bandwidth network.

Example 1: Merkle trees. As a representative example highlighting the eciency and scalability of our protocol, we consider proving knowledge of the *n* = 2 *d* leaves in a complete Merkle tree of depth *d* using SHA-256 as the internal hash function, where the root digest is known to both parties. In Figure10, we report on the running time and overall memory usage of our protocol for *d* ranging from 6 to 19 (totaling 63{524,287 calls to SHA-256). Since the boolean circuit for SHA-256 has 22,573 AND gates, the largest circuit in these experiments contains more than 11 billion gates. The overall memory consumption of our protocol is about 400 MB; this is dominated by the initial generation of 10 sVOLE correlations during the oine phase of the execution. During the

2000 10 Mbps, 854 ns/bit50 Mbps, 185 ns/bit100 Mbps, 104 ns/bit 10 Mbps, 1 µ*s* /gate*.*31 1500 50 Mbps, 0 µ*s* /gate*.*50 100 Mbps, 0 µ*s* /gate*.*46 1000

500 24 2 Running time (s) Running time (s) 0 2 24 2 28 2 29 2 30 Bit-length of the witness

Figure 9: Scalability of Wolverine for boolean circuits.

## 10 Mbps50 Mbps100 Mbps 211

2 7

2 3 6 8 10 Running time (s) Memory usage (GB) 5 7 9 11 13 15 17 19 Depth of Merkle tree

Figure 10: Running time and memory usage of Wolverine when proving knowledge of all leaves

in a Merkle tree of a given depth.

online phase, the Merkle-tree computation is implemented in a post-order, depth-rst fashion so that the additional memory usage at any point corresponds only to authenticated values for *O*(*d*) tree nodes (at most 150 KB). Since this is dominated by the memory usage during the online phase, the memory usage plotted in Figure10is nearly constant even as *d* increases. In Table1, we compare the performance of our protocol to that of the state-of-the-art protocols for the same problem, in a 200 Mbps network. (There, we report on the performance of our protocol using only one thread.) We benchmarked all prior work except for Ligero [AHIV17], for which we obtained performance estimates from the authors. Spartan [Set20] uses the R1CS representation, so we conservatively assume that each SHA-256 hash requires 22,573 constraints. Virgo [ZXZS20] does not support free-XOR, and thus for each SHA-256 hash it uses roughly 2 18 gates. (For this reason, the running time of Virgo for the Merkle-tree example is close to its running time for the matrix-multiplication example.) Compared to the ZKGC approach, Wolverine achieves better running time and about 15 lower communication, which means that it will be up to 15 faster when running in a low-bandwidth network. Compared to other protocols, we achieve at least a 5 improvement in execution time while using less memory.

Example 2: Proving existence of a bug in programs. We also apply our system to prove the existence of a bug in one out of a set of *n* program snippets in zero knowledge (in particular, without revealing which snippet contains the bug). This problem was recently studied by Heath and Kolesnikov [HK20], who showed how to adapt the ZKGC approach using a technique called *stacked garbling* so as to obtain communication proportional to the size *‘* of the largest program snippet, rather than the total size *O*(*n ‘*) of all programs snippets.

<u>10 Mbps 100 Mbps</u> Number of snippets 4 50 200 4 50 200 Stacked garbling (*s*) 22 22.1 22.2 2.3 2.5 3.18 Our protocol (*s*) 0.42 5.2 20.8 0.15 1.8 7.2

Table 5: Comparing Wolverine to ZKGC with stacked garbling for proving the existence of a

bug in one of multiple code snippets.

<u>DECO [ZMM</u> + <u>20] Blind CA [WAP</u> + <u>19]</u>

## Protocol DECO Wolverine Blind CA Wolverine

Execution time 12.6 *s* 0.28 *s* 71 *s* 3.3 *s* Communication 1.7 KB 184 KB 85.1 MB 2.8 MB

Table 6: Using our protocol Wolverine in ZK-enabled applications. All benchmarks are based on a

10 Mbps network and reect the ZK component only.

We performed experiments using the same programs as in the work of Heath and Kolesnikov. These result in boolean circuits whose sizes range from 70,869{90,772 AND gates and whose largest input length is 112 bits. We show the results in Table5. Wolverine does not use the stacked garbling optimization, 2 and so has communication complexity *O*(*n ‘*). Nevertheless, for moderate values of *n*, Wolverine is still noticeably faster than ZKGC with stacked garbling. The eect is more pronounced in lower-bandwidth networks.

Example 3: Accelerating ZK-enabled applications. Here we discuss the use of Wolverine in two recent applications that rely on ZK proofs. Both applications require interaction anyway, and so there is no real disadvantage to using an interactive ZK proof in these cases. We describe the applications below, and present the relevant benchmarking results in Table6. DECO [ZMM + 20] allows third-party proofs of data provenance for TLS connections, i.e., it allows a client to prove that certain data originated at a particular website. (We conrmed with the authors that interactive ZK proofs can also be used in their system.) One example considered by DECO is where a customer proves the existence of price discrimination by proving in zero knowledge that it was sent a price exceeding a certain threshold. Proving this statement involves a boolean circuit containing roughly 163,000 AND gates. In the original paper [ZMM + 20], a ZK proof for this statement was implemented using libSNARK; this resulted in a short proof but required high computational overhead. When running over a 10 Mbps network, Wolverine is able to reduce the execution time of the ZK-proof component by 45, resulting in a 9 end-to-end improvement in the overall DECO protocol. A blind Certicate Authority (CA) is able to issue a valid certicate binding a party with an as- sociated public key, without learning the party’s identity. A recent proposal of a blind CA [WAP + 19] required a ZK proof of a statement corresponding to a boolean circuit with roughly 2.5 million AND gates. The existing implementation used a ZK proof based on the MPC-in-the-head approach; the proof took more than 70 seconds to execute over a 10 Mbps network. Plugging Wolverine into their protocol, we improve the communication complexity by 30 and the execution time by 20, compared to the original protocol [WAP + 19] for CA-proof generation. 2 We leave incorporating stacked garbling into Wolverine as a future work.

50 Mbps, 1 µ*s* /element*.*38 50 Mbps, 5 2000 µ*s* /gate*.*52 2000 100 Mbps, 1 µ*s* /element*.*17 100 Mbps, 2 µ*s* /gate*.*97 1500 1500 500 Mbps, 1 µ*s* /element*.*10 500 Mbps, 1 µ*s* /gate*.*04 1000 1000

## 500 500

## Running time (s) Running time (s)

0 0 2 24 2 28 2 29 2 30 2 22 2 26 2 27 2 28 Number of field elements for a witness Number of multiplication gates in a circuit

Figure 11: Performance of Wolverine for arithmetic circuits.

6.2.2 Zero-Knowledge Proofs for Arithmetic Circuits We also evaluated Wolverine for arithmetic circuits over F*p*with *p* = 2
61 1 using our VOLE implementation shown in Section6.1. In this setting we check correctness of multiplication gates using the rst optimization described in Section3.2, and we use the rst approach discussed in Section2.1for batched opening of authenticated values.

Performance. Similar to the boolean case, we study the performance of Wolverine as a function of the witness length and circuit size; the experimental results are reported in in Figure11. As the communication complexity is inherently higher for the arithmetic case than the boolean set- ting (since each eld element is 61 bits long), we benchmarked performance in higher-bandwidth networks. Wolverine can execute proofs at a rate of about 1 million multiplication gates per second in a 500 Mbps network, and roughly 200,000 multiplication gates per second in a 50 Mbps. We are not aware of any memory-ecient ZK protocol that natively works with arithmetic circuits. While one could always convert an arithmetic circuit to a boolean circuit, this will generally impose signicant overhead.

Example 1: Matrix multiplication. We apply our ZK protocol to prove knowledge of two *n n* matrices whose product is a publicly known matrix. While the problem itself is meaningless, it has been used as a benchmark in prior work [BCC + 16,WTS + 18,XZZ + 19,ZXZS20]. We experimented with *n* ranging from 64{768 (with the witness ranging from 8,192 to over 1 million eld elements), using a matrix-multiplication circuit corresponding to the naive *O*(*n³*)-time algorithm. The time and memory usage of Wolverine are shown in Figure12. The memory usage of Wolverine grows slowly as *n* increases, and never exceeds 350 MB. As shown in Table1, our protocol is 2 faster than Spartan but 5 slower than Virgo. Impor- tantly, however, the prover memory of Wolverine is only 3% of that used by Virgo and 0.5% of that needed by Spartan.

Example 2: Solutions to lattice problems. Various prior works have explored ZK proofs for the Short Integer Solution (SIS) problem. Here, we have public A *2* Z *n* *q* *m* and *t 2* Z *n* *q*, and the prover’s goal is to convince the verier that it knows a short *s* such that A*s* = *t* mod *q*. We evaluate Wolverine based on dierent notions of shortness for *s* as explained next. Baum and Nof [BN20] recently showed a ZK proof for SIS in the case where *s 2 f*0*;* 1*g* *m* is a binary vector. We compare Wolverine to their protocol in Table7. In our experiments, we use *q* 2 61, *n* = 1024, and *m* = 4096 to align with the parameters used by Baum and Nof; those parameters are also sucient for the somewhat homomorphic encryption scheme used for the SPDZ setup phase [BGV12]. As shown in Table7, our protocol is over 16 more ecient than the protocol of Baum and Nof even when run over a much slower network.

3000 350 50 Mbps100 Mbps500 Mbps 300 2000 250

1000 200 200 400 600 800 Running time (s) Number of columns Memory usage (MB)0 0 200 400 600 800 Number of columns

Figure 12: Using Wolverine for matrix multiplication.

||Our ZK protocol Wolverine (|ms )|[BN20]||
|---|---|---|---|---|
||50 Mbps 100 Mbps|500 Mbps 10 Gbps|10 Gbps||
||74 63|55|55 1228||
|Table 7: Running time of knowledge of an SIS solution. The solution is assumed to be a binary vector.|Wolverine vs.|the protocol by Baum and Nof [BN20] for proving|||
|Protocol|BLS [BLS19]|Aurora [BCOS20]|ENS [ENS20]|Ours|
|Communication|384 KB|233 KB|53 KB|32.8 KB|

Table 8: Communication complexity of Wolverine vs. dedicated protocols for proving knowledge

of an SIS solution. The solution is assumed to be a vector over *f*1*;* 0*;* 1*g*. Numbers for prior work are taken from Esgin et al. [ENS20].

In Table8, we compare Wolverine with other ZK proofs for SIS [BLS19,BCOS20,ENS20] that apply when *s 2f*1*;* 0*;* 1*g* *m*. Here we x *q* 2 32, *n* = 2048, and *m* = 1024 to align with prior work. We see that Wolverine uses only 60% of the communication compared to the best prior work. (We are not able to compare the running time, since it was not reported by prior work.)

# Acknowledgements

This material is based upon work supported in part by DARPA under Contract No. HR001120C0087. The views, opinions, and/or ndings expressed are those of the author(s) and should not be in- terpreted as representing the ocial views or policies of the Department of Defense or the U.S. Government. Work of Kang Yang is supported by the National Natural Science Foundation of China (Grant No. 61932019). Distribution Statement \A" (Approved for Public Release, Distribu- tion Unlimited).

# References

[ABF + 17]Toshinori Araki, Assi Barak, Jun Furukawa, Tamar Lichter, Yehuda Lindell, Ariel Nof, Kazuma Ohara, Adi Watzman, and Or Weinstein. Optimized honest-majority MPC for malicious adversaries-breaking the 1 billion-gate per second barrier. In *IEEE* *Symp. Security and Privacy 2017*, pages 843{862. IEEE, 2017.

[AHIV17]Scott Ames, Carmit Hazay, Yuval Ishai, and Muthuramakrishnan Venkitasubrama- niam. Ligero: Lightweight sublinear arguments without a trusted setup. In *ACM* *Conf. on Computer and Communications Security (CCS) 2017*, pages 2087{2104. ACM Press, 2017. + [BBB 18]Benedikt Bunz, Jonathan Bootle, Dan Boneh, Andrew Poelstra, Pieter Wuille, and Greg Maxwell. Bulletproofs: Short proofs for condential transactions and more. In *IEEE Symp. Security and Privacy 2018*, pages 315{334. IEEE, 2018.

[BBHR19]Eli Ben-Sasson, Iddo Bentov, Yinon Horesh, and Michael Riabzev. Scalable zero knowl- edge with no trusted setup. In *Advances in Cryptology|Crypto 2019, Part III*, volume 11694 of *LNCS*, pages 701{732. Springer, 2019. + [BCC 16]Jonathan Bootle, Andrea Cerulli, Pyrros Chaidos, Jens Groth, and Christophe Petit. Ecient zero-knowledge arguments for arithmetic circuits in the discrete log setting. In *Advances in Cryptology|Eurocrypt 2016, Part II*, volume 9666 of *LNCS*, pages 327{357. Springer, 2016. + [BCG 13]Eli Ben-Sasson, Alessandro Chiesa, Daniel Genkin, Eran Tromer, and Madars Virza. SNARKs for C: Verifying program executions succinctly and in zero knowledge. In *Advances in Cryptology|Crypto 2013, Part II*, volume 8043 of *LNCS*, pages 90{108. Springer, 2013. + [BCG 17]Elette Boyle, Georoy Couteau, Niv Gilboa, Yuval Ishai, and Michele Orru. Homo- morphic secret sharing: Optimizations and applications. In *ACM Conf. on Computer* *and Communications Security (CCS) 2017*, pages 2105{2122. ACM Press, 2017. + [BCG 19a]Elette Boyle, Georoy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, Peter Rindal, and Peter Scholl. Ecient two-round OT extension and silent non-interactive secure computation. In *ACM Conf. on Computer and Communications Security (CCS) 2019*, pages 291{308. ACM Press, 2019. + [BCG 19b]Elette Boyle, Georoy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, and Peter Scholl. Ecient pseudorandom correlation generators: Silent OT extension and more. In *Advances in Cryptology|Crypto 2019, Part III*, volume 11694 of *LNCS*, pages 489{

518. Springer, 2019.
[BCGI18]Elette Boyle, Georoy Couteau, Niv Gilboa, and Yuval Ishai. Compressing vector OLE. In *ACM Conf. on Computer and Communications Security (CCS) 2018*, pages 896{912. ACM Press, 2018.

[BCOS20]Cecilia Boschini, Jan Camenisch, Max Ovsiankin, and Nicholas Spooner. Ecient post-quantum SNARKs for RSIS and RLWE and their applications to privacy. In *PQCrypto 2020*, pages 247{267. Springer, April 9{11 2020. + [BCR 19]Eli Ben-Sasson, Alessandro Chiesa, Michael Riabzev, Nicholas Spooner, Madars Virza, and Nicholas P. Ward. Aurora: Transparent succinct arguments for R1CS. In *Ad-* *vances in Cryptology|Eurocrypt 2019, Part I*, volume 11476 of *LNCS*, pages 103{128. Springer, 2019.

[BCTV14]Eli Ben-Sasson, Alessandro Chiesa, Eran Tromer, and Madars Virza. Succinct non- interactive zero knowledge for a von neumann architecture. In *USENIX Security Sym-* *posium 2014*, pages 781{796. USENIX Association, 2014.

[Bea92]Donald Beaver. Ecient multiparty protocols using circuit randomization. In *Advances* *in Cryptology|Crypto 1991*, LNCS, pages 420{432. Springer, 1992.

[BFS20]Benedikt Bunz, Ben Fisch, and Alan Szepieniec. Transparent SNARKs from DARK compilers. In *Advances in Cryptology|Eurocrypt 2020, Part I*, volume 12105 of *LNCS*, pages 677{706. Springer, 2020.

[BGI15]Elette Boyle, Niv Gilboa, and Yuval Ishai. Function secret sharing. In *Advances in* *Cryptology|Eurocrypt 2015, Part II*, volume 9057 of *LNCS*, pages 337{367. Springer,

2015.
[BGI16]Elette Boyle, Niv Gilboa, and Yuval Ishai. Function secret sharing: Improvements and extensions. In *ACM Conf. on Computer and Communications Security (CCS) 2016*, pages 1292{1303. ACM Press, 2016.

[BGV12]Zvika Brakerski, Craig Gentry, and Vinod Vaikuntanathan. (Leveled) fully homomor- phic encryption without bootstrapping. In *ITCS 2012*, pages 309{325, Cambridge, MA, USA, January 8{10, 2012. Association for Computing Machinery.

[BLS19]Jonathan Bootle, Vadim Lyubashevsky, and Gregor Seiler. Algebraic techniques for short(er) exact lattice-based zero-knowledge proofs. In *Advances in Cryptology|* *Crypto 2019, Part I*, volume 11692 of *LNCS*, pages 176{202. Springer, 2019.

[BMRS20]Carsten Baum, Alex J. Malozemo, Marc Rosen, and Peter Scholl. Mac’n’cheese: Zero-knowledge proofs for arithmetic circuits with nested disjunctions. Cryptology ePrint Archive, Report 2020/1410, 2020. https://eprint.iacr.org/2020/1410.

[BN20]Carsten Baum and Ariel Nof. Concretely-ecient zero-knowledge arguments for arith- metic circuits and their application to lattice-based cryptography. In *Intl. Conference* *on Theory and Practice of Public Key Cryptography 2020, Part I*, LNCS, pages 495{

526. Springer, 2020.
[Can01]Ran Canetti. Universally composable security: A new paradigm for cryptographic protocols. In *42nd Annual Symposium on Foundations of Computer Science (FOCS)*, pages 136{145. IEEE, 2001.

[CDE + 18]Ronald Cramer, Ivan Damgard, Daniel Escudero, Peter Scholl, and Chaoping Xing. SPD Z₂*k*: Ecient MPC mod 2 *k* for dishonest majority. In *Advances in Cryptology|* *Crypto 2018, Part II*, volume 10992 of *LNCS*, pages 769{798. Springer, 2018.

[CDG + 17]Melissa Chase, David Derler, Steven Goldfeder, Claudio Orlandi, Sebastian Ramacher, Christian Rechberger, Daniel Slamanig, and Greg Zaverucha. Post-quantum zero- knowledge and signatures from symmetric-key primitives. In *ACM Conf. on Computer* *and Communications Security (CCS) 2017*, pages 1825{1842. ACM Press, 2017.

[COS20]Alessandro Chiesa, Dev Ojha, and Nicholas Spooner. Fractal: Post-quantum and trans- parent recursive proofs from holography. In *Advances in Cryptology|Eurocrypt 2020,* *Part I*, volume 12105 of *LNCS*, pages 769{793. Springer, 2020.

[dCJV20]Leo de Castro, Chiraag Juvekar, and Vinod Vaikuntanathan. Fast vector oblivious linear evaluation from ring learning with errors. Cryptology ePrint Archive, Report 2020/685, 2020. https://eprint.iacr.org/2020/685.

[dDOS19]Cyprien de Saint Guilhem, Lauren De Meyer, Emmanuela Orsini, and Nigel P. Smart. BBQ: Using AES in picnic signatures. In *Annual International Workshop on Selected* *Areas in Cryptography (SAC) 2019*, LNCS, pages 669{692. Springer, 2019.

[DIO20]Samuel Dittmer, Yuval Ishai, and Rafail Ostrovsky. Line-point zero knowledge and its applications. Cryptology ePrint Archive, Report 2020/1446, 2020. https://eprint. iacr.org/2020/1446.

[DPSZ12]Ivan Damgard, Valerio Pastro, Nigel P. Smart, and Sarah Zakarias. Multiparty computation from somewhat homomorphic encryption. In *Advances in Cryptology|* *Crypto 2012*, volume 7417 of *LNCS*, pages 643{662. Springer, 2012.

[ENS20]Muhammed F. Esgin, Ngoc Khanh Nguyen, and Gregor Seiler. Practical exact proofs from lattices: New techniques to exploit fully-splitting rings, 2020.

[FNO15]Tore Kasper Frederiksen, Jesper Buus Nielsen, and Claudio Orlandi. Privacy-free gar- bled circuits with applications to ecient zero-knowledge. In *Advances in Cryptology|* *Eurocrypt 2015, Part II*, volume 9057 of *LNCS*, pages 191{219. Springer, 2015.

[GGM86]Oded Goldreich, Sha Goldwasser, and Silvio Micali. How to construct random func- tions. *J. ACM*, 33(4):792{807, October 1986.

[GGPR13]Rosario Gennaro, Craig Gentry, Bryan Parno, and Mariana Raykova. Quadratic span programs and succinct NIZKs without PCPs. In *Advances in Cryptology|* *Eurocrypt 2013*, LNCS, pages 626{645. Springer, 2013.

[Gil99]Niv Gilboa. Two party RSA key generation. In *Advances in Cryptology|Crypto 1999*, volume 1666 of *LNCS*, pages 116{129. Springer, 1999.

[GKR08]Sha Goldwasser, Yael Tauman Kalai, and Guy N. Rothblum. Delegating computa- tion: interactive proofs for muggles. In *40th Annual ACM Symposium on Theory of* *Computing (STOC)*, pages 113{122. ACM Press, 2008.

[GMO16]Irene Giacomelli, Jesper Madsen, and Claudio Orlandi. ZKBoo: Faster zero-knowledge for Boolean circuits. In *USENIX Security Symposium 2016*, pages 1069{1083. USENIX Association, 2016.

[GMR85]Sha Goldwasser, Silvio Micali, and Charles Racko. The knowledge complexity of interactive proof-systems (extended abstract). In *17th Annual ACM Symposium on* *Theory of Computing (STOC)*, pages 291{304. ACM Press, 1985.

[GMW87]Oded Goldreich, Silvio Micali, and Avi Wigderson. How to play any mental game or A completeness theorem for protocols with honest majority. In *19th Annual ACM* *Symposium on Theory of Computing (STOC)*, pages 218{229. ACM Press, 1987.

[GMW91]Oded Goldreich, Silvio Micali, and Avi Wigderson. Proofs that yield nothing but their validity or all languages in NP have zero-knowledge proof systems. *J. ACM*, 38(3):691{729, 1991.

[Gro10]Jens Groth. Short pairing-based non-interactive zero-knowledge arguments. In *Ad-* *vances in Cryptology|Asiacrypt 2010*, LNCS, pages 321{340. Springer, 2010.

[HEKM11]Yan Huang, David Evans, Jonathan Katz, and Lior Malka. Faster secure two-party computation using garbled circuits. In *USENIX Security Symposium 2011*. USENIX Association, 2011.

[HK20]David Heath and Vladimir Kolesnikov. Stacked garbling for disjunctive zero-knowledge proofs. In *Advances in Cryptology|Eurocrypt 2020, Part III*, volume 12107 of *LNCS*, pages 569{598. Springer, 2020.

[HOSS18]Carmit Hazay, Emmanuela Orsini, Peter Scholl, and Eduardo Soria-Vazquez. TinyKeys: A new approach to ecient multi-party computation. In *Advances in* *Cryptology|Crypto 2018, Part III*, volume 10993 of *LNCS*, pages 3{33. Springer, 2018.

[IKNP03]Yuval Ishai, Joe Kilian, Kobbi Nissim, and Erez Petrank. Extending oblivious transfers eciently. In *Advances in Cryptology|Crypto 2003*, volume 2729 of *LNCS*, pages 145{

161. Springer, 2003.
[IKOS07]Yuval Ishai, Eyal Kushilevitz, Rafail Ostrovsky, and Amit Sahai. Zero-knowledge from secure multiparty computation. In *39th Annual ACM Symposium on Theory of* *Computing (STOC)*, pages 21{30. ACM Press, 2007.

[ILL89]Russell Impagliazzo, Leonid A. Levin, and Michael Luby. Pseudo-random generation from one-way functions (extended abstracts). In *21st Annual ACM Symposium on* *Theory of Computing (STOC)*, pages 12{24. ACM Press, 1989.

[JKO13]Marek Jawurek, Florian Kerschbaum, and Claudio Orlandi. Zero-knowledge using garbled circuits: how to prove non-algebraic statements eciently. In *ACM Conf.* *on Computer and Communications Security (CCS) 2013*, pages 955{966. ACM Press,

2013.
[KKW18]Jonathan Katz, Vladimir Kolesnikov, and Xiao Wang. Improved non-interactive zero knowledge with applications to post-quantum signatures. In *ACM Conf. on Computer* *and Communications Security (CCS) 2018*, pages 525{537. ACM Press, 2018.

[KOS15]Marcel Keller, Emmanuela Orsini, and Peter Scholl. Actively secure OT extension with optimal overhead. In *Advances in Cryptology|Crypto 2015, Part I*, volume 9215 of *LNCS*, pages 724{741. Springer, 2015.

[KOS16]Marcel Keller, Emmanuela Orsini, and Peter Scholl. MASCOT: Faster malicious arith- metic secure computation with oblivious transfer. In *ACM Conf. on Computer and* *Communications Security (CCS) 2016*, pages 830{842. ACM Press, 2016.

[NNOB12]Jesper Buus Nielsen, Peter Sebastian Nordholt, Claudio Orlandi, and Sai Sheshank Burra. A new approach to practical active-secure two-party computation. In *Advances* *in Cryptology|Crypto 2012*, volume 7417 of *LNCS*, pages 681{700. Springer, 2012.

[NO09]Jesper Buus Nielsen and Claudio Orlandi. LEGO for two-party secure computation. In *6th Theory of Cryptography Conference|TCC 2009*, volume 5444 of *LNCS*, pages 368{386. Springer, 2009.

[Set20]Srinath Setty. Spartan: Ecient and general-purpose zkSNARKs without trusted setup. In *Advances in Cryptology|Crypto 2020, Part III*, LNCS, pages 704{737. Springer, 2020.

[SGRR19]Phillipp Schoppmann, Adria Gascon, Leonie Reichert, and Mariana Raykova. Dis- tributed vector-OLE: Improved constructions and implementation. In *ACM Conf. on* *Computer and Communications Security (CCS) 2019*, pages 1055{1072. ACM Press,

2019.
[WAP + 19]Liang Wang, Gilad Asharov, Rafael Pass, Thomas Ristenpart, and Abhi Shelat. Blind certicate authorities. In *IEEE Symp. Security and Privacy 2019*, pages 1015{1032. IEEE, 2019.

[WMK16]Xiao Wang, Alex J. Malozemo, and Jonathan Katz. EMP-toolkit: Ecient Multi- Party computation toolkit. https://github.com/emp-toolkit, 2016.

[WTS + 18]Riad S. Wahby, Ioanna Tzialla, Abhi Shelat, Justin Thaler, and Michael Walsh. Doubly-ecient zkSNARKs without trusted setup. In *IEEE Symp. Security and Pri-* *vacy 2018*, pages 926{943. IEEE, 2018.

[XZZ + 19]Tiancheng Xie, Jiaheng Zhang, Yupeng Zhang, Charalampos Papamanthou, and Dawn Song. Libra: Succinct zero-knowledge proofs with optimal prover computation. In *Advances in Cryptology|Crypto 2019, Part III*, volume 11694 of *LNCS*, pages 733{

764. Springer, 2019.
[YWL + 20]Kang Yang, Chenkai Weng, Xiao Lan, Jiang Zhang, and Xiao Wang. Ferret: Fast extension for correlated OT with small communication. In *ACM Conf. on Computer* *and Communications Security (CCS) 2020*, pages 1607{1626. ACM Press, 2020.

[YWZ20]Kang Yang, Xiao Wang, and Jiang Zhang. More ecient MPC from improved triple generation and authenticated garbling. In *ACM Conf. on Computer and Communica-* *tions Security (CCS) 2020*, pages 1627{1646. ACM Press, 2020.

[ZMM + 20]Fan Zhang, Deepak Maram, Harjasleen Malvai, Steven Goldfeder, and Ari Juels. DECO: Liberating web data using decentralized oracles for TLS. In *ACM Conf. on* *Computer and Communications Security (CCS) 2020*, pages 1919{1938. ACM Press,

2020.
[ZRE15]Samee Zahur, Mike Rosulek, and David Evans. Two halves make a whole-reduc- ing data transfer in garbled circuits using half gates. In *Advances in Cryptology|* *Eurocrypt 2015, Part II*, volume 9057 of *LNCS*, pages 220{250. Springer, 2015.

[ZXZS20]Jiaheng Zhang, Tiancheng Xie, Yupeng Zhang, and Dawn Song. Transparent polyno- mial delegation and its applications to zero knowledge proof. In *IEEE Symp. Security* *and Privacy 2020*, pages 859{876. IEEE, 2020.

# A Other Functionalities

We review the standard ideal functionality for oblivious transfer (OT) in Figure13.

|In Figure14we dene a functionality F|||implementing a weak equality test that reveals P||’s|
|---|---|---|---|---|---|
||||EQ||A|
|B||||B|A|
|||?||||
|A|B|A B|||B|
|||||?||
|B|||B|A B||

input to P. This functionality can be easily realized as follows: (1) P commits to *V*B; (2) P sends *V* to P; (3) PBoutputs (*V* = *V*) and aborts if they are not equal, and then opens *V*;

(4) if P opened its commitment to a value *V*, then PAoutputs (*V* = *V*); otherwise it aborts. UC commitments can be realized eciently in the random-oracle model.

<u>Functionality FOT</u>

On receiving (*m₀;m₁*) with *jm₀j* = *jm₁j* from a sender PAand *b 2f*0*;* 1*g* from a receiver PB, send *mb* to PB.

Figure 13: The OT functionality between PAand PB.

<u>Functionality FEQ</u>

? Upon receiving *V*Afrom PAand *V*Bfrom PB, send (*V*A= *V*B) and *V*Ato PB, and do: ? If PBis honest and *V*A= *V*B, or is corrupted and sends continue, then send (*V*A= *V*B) to PA.

If PBis honest and *V*A*6*= *V*B, or is corrupted and sends abort, then send abort to PA.

Figure 14: Functionality for a weak equality test.

# B Methods for Batch Checking

We describe two approaches for batch checking of authenticated values. The rst relies on a cryp- tographic hash function H. Specically, P

||||sends (in addition to the values x₁;:::;x|themselves)|
|---|---|---|---|---|
||||A|‘|
|||||?|
|||‘|||
|‘|‘||||
|H 2|2|r|H|A|

a digest *h* := H(M[*x₁*]*;:::;* M[*x*]) of all the MAC tags; PBthen checks that *h* = H(K[*x₁*] + *x₁;:::;* K[*x*] + *x*). Modeling H as a random oracle with 2-bit output, it is not hard to see that the soundness error (i.e., the probability that PAcan successfully cheat about *any* value) is upper bounded by (*q* + 1)*=*2 + 1*=p*, where *q* denotes the number of queries that P makes to H. The communication overhead is only 2 bits, independent of *‘*. The second approach, which is information theoretic, works as follows:

|1. P sends x₁;:::;x|2 F to P|.|||
|---|---|---|---|---|
|A|‘ p|B|||
|B|1|‘ p||A|
||‘||||
|A|i=1 ‘|i|i|B ‘|
|B|i=1 i|i|p|i=1 i|

2. P picks uniform*;:::; 2* F *r* and sends them to P.
P

3. P computes M[*x*] := M[*x*], and sends it to P.
P P

4. P computes *x* := *x 2* F *r* and K[*x*] := K[*xi*] *2* F*pr*. It accepts the opened values if and only if M[*x*] = K[*x*] + *x*. The soundness error of this approach is given by Lemma2. Lemma 2. *Let x₁;:::;x r*

||2 F|and M[x₁];:::; M[x||] 2 F|be arbitrary values known to P|||, and|
|---|---|---|---|---|---|---|---|---|
||‘|p||‘ p||||A|
|||‘|||||||
|i|i|i i=1 1|0‘|p ‘|B|B r|||
|0|0‘|‘|A i|||def r|‘ i=1 i|0i i|

*r* *let and f*K[*x*] = M[*x*] *x g, for uniform 2* F*, be given to* P*. The probability that* PA*can successfully open values* (*x⁰;:::;x*) *6*= (*x₁;:::;x*) *to* P *is at most* 2*=p.*

P *Proof.* Fix (*x₁;:::;x*) *6*= (*x₁;:::;x*) sent by P in the rst step. If we let*!* = (*x x*), then the probability (over uniform choice of *f g*) that*!* = 0 is at most 1*=p*.

<u>Protocol</u> *p;r* <u>COPEe</u>

Let *m* = *d*log *pe* and PRF be a keyed function. Initialize: This initialization procedure is executed only once.

1.For *i 2* [*rm*], PAsamples *K₀*
*i* *;K₁* *i* *f* 0*;* 1*g*. PBsamples F*pr* and lets*B*= (1*;:::;rm*) *2* *rm* *f*0*;* 1*g* be its bit-decomposition.

|A|i i|OT|B||i|B|
|---|---|---|---|---|---|---|
|||||p|A||

2.For *i 2* [*rm*], P sends (*K₀;K₁*) to *F* and P sends*i2f*0*;* 1*g* to *F*OT, which returns *K*
*i* to P.

Extend: This procedure can be executed multiple times. For the *j*th input *u 2* F from P, the parties execute the following:

3.For *i 2* [*rm*], do the following in parallel:
(a) PAsets *w₀*
*i* := PRF(*K₀* *i* *;j*) and *w₁* *i* := PRF(*K₁* *i* *;j*) with *w₀* *i* *;w₁* *i* *2* F*p*; PBcomputes *w* *i* *i* := *i*

|PRF(K|;j).|||||||
|---|---|---|---|---|---|---|---|
|A|i|i i|p|B||||
|B|i rm|i|i i 1|i i rm|p|B|rm p|
|A||p|B||p|||

*i*

(b) P sends := *w₀ w₁ u 2* F to P.
(c) P computes *v* := *w*
*i* + = *w₀ u 2* F.

4.Let *v* = (*v¹;:::;v*) and *w* = (*w₀;:::;w₀*) such that *w* = *v* + *u 2* F.
5. P outputs *w* = *hg; wi2* F *r* and P outputs *v* = *hg; vi2* F *r*, where *w* = *v* + *u 2* F*pr*.
Figure 15: COPEe protocol in the *F*OT-hybrid model.
 Assume*! 6*= 0. If PAsends M *2* F*pr*, then PBaccepts only if
X *‘* X *‘* M =*i*K[*xi*] +*ix* *0i* *i*=1 *i*=1 X *‘* X *‘* = *0i*

|||(M[x]|x ) +||x|
|---|---|---|---|---|---|
||i i=1|i|i|i i=1|0i|
||‘ i|i||||
||i=1|||||
||||||A|
|‘ i=1 i|||r|||

X = M[*x*] + *!:*

Everything in the nal expression is xed except for. Moreover, P succeeds i =*!* 1 (M P M[*xi*]), which occurs with probability 1*=p*.

We can make the second approach *non-interactive*, using the Fiat-Shamir heuristic in the random-oracle model, by computing the coecients *fig* as the output of a hash function H evalu- ated on the values *fxig* sent by PAin the rst step. Adapting the above proof, one can show that this has soundness error at most (*q*H+ 2)*=p* *r*.

## B.1 Construction of COPEe

*p;r p;r* In Figure15, we present a protocol COPEe that UC-realizes *F* COPEe in the *F*OT-hybrid model. This protocol follows the construction of Keller et al. [KOS16], which is in turn based on the IKNP OT-extension protocol [IKNP03] and Gilboa’s approach [Gil99] for oblivious product evaluation. The main dierence from prior work is that we support the subeld case.

*p;r p;r* Lemma 3. *If* PRF *is a pseudorandom function, then* COPEe *UC-realizes F* COPEe *in the F*OT*-hybrid* *model.*

The proof of Lemma3can be straightforwardly obtained by following the proof of Keller et al. [KOS16], and is thus omitted.

## B.2 Proof of Theorem2

*p;r p;r* Recall that our protocol

||is established over the sub-protocol||with a selective-|
|---|---|---|---|
|base-sVOLE||base-LsVOLE|p;r|
|p;r|p;r|p;r|base-LsVOLE|
|LsVOLE|LsVOLE|sVOLE||

base-sVOLE base-LsVOLE *p;r* failure leakage on (the rst part of Figure5). Thus, we rst prove that protocol UC-realizes functionality *F*, where *F* is the same as *F* except that the global-key query is replaced with the following selective-failure queries:

Wait for the adversary to input (guess*;S*) where *S* eciently describes a subset of F*pr*. If *2 S*, then send success to the adversary and continue. Otherwise, send abort to both parties and abort.

Based on the leftover hash lemma [ILL89], we can prove that the full protocol (the second part *p;r p;‘ r* of Figure5) UC-realizes *F* sVOLE in the *F* LsVOLE -hybrid model, where the resulting global key is uniform in F*pr* except with probability at most 1*=*2, as the inner product denes a universal *p;‘ r p;‘ r p;r* hash function. Replacing *F* LsVOLE with sub-protocol LsVOLE, we obtain that protocol base-sVOLE *p;r* UC-realizes *F* sVOLE. *p;r p;r* Below, we focus on proving that sub-protocol base-LsVOLE UC-realizes *F* LsVOLE. We rst consider the case of a malicious PAand then consider the case of a malicious PB. In each case, we construct *p;r* a PPT simulator *S* that runs a PPT adversary *A* as a subroutine and emulates *F* COPEe. We always implicitly assume that *S* passes all communication between *A* and environment *Z*. *p;r* Malicious PA. Given access to *F* sVOLE ,*S* interacts with *A* as follows: *p;r*

1. *S* emulates *F*
COPEe, and receives (*wi; ui*) for *i 2* [0*;n*) and (*ch; ah*) for *h 2* [0*;r*) from *A*, where *ui; ah2* F *rm* *p*and *m* = *d*log *pe*. (In the honest case, we have that *ui*= (*ui;:::;ui*) for some *ui2* F*p*and *ah*= (*ah;:::;ah*) for some *ah2* F*p*. )

2. *S* samples0*;:::;n* 1F*pr* and sends them to *A*. Then, *S* receives *x 2* F*pr* and *z 2* F*pr* from
*A*. Next, *S* computes an adversarially chosen error

|n 1|r 1||
|---|---|---|
|i|i h|h|
|i=0|h=0||

X X *ez*:= *z w c* X *2* F*pr :*

3. *S* computes a set *S* as follows:
## Solve the following equation:

||n 1||r 1||
|---|---|---|---|---|
||i i=0|i|h h=0|h B|
|B||B|||
|p;r|||p;r||
|LsVOLE|||LsVOLE||

D X X E *g x g u g a* X*;* = *ez*(1)

For each solution, compute := *hg; i* and add to the set *S*.

4. *S* sends (guess*;S*) to *F*. If receiving abort from *F*, *S* aborts. Otherwise, *S* continues the simulation.
5. *S* computes another set *S*~~as follows:

## Solve the following equation:

D*n*X1X*r* 1E *g x giuig ah*X *h* *;* ~*B*= 0 (2) *i*=0 *h*=0

For each solution ~*B*, compute := ~ *hg;* ~*Bi* and add into the set ~ *S*~~.

6.If *S*~~only involves a single entry 0, then *S* aborts. Otherwise, *S* chooses any nonzero element ~ *2 S*~ ~, and then for *i 2* [0*;n*), computes
*ui*:= ~ 1 *hg ui;* ~*Bi* (3)

where *hg;* ~*Bi* = .~ (In the following analysis, we will show that *ui*is unique over all possible in set ~ *S*~ ~.)

7.For *i 2* [0*;n*), *S* computes an adversarially chosen error *ei*:= *ui*(*ui;:::;ui*) *2* F
*rm* *p*, and then

|computes w|:= w|hg|e; i2 F|for any||such that hg;||i2 S|.|Then, S sends|
|---|---|---|---|---|---|---|---|---|---|---|
||i0 n 1|i|i B 0|p n 0 1||B|LsVOLE p;r|B|||

*i i B prB B* *u* = (*u₀;:::;u*) and *w* = (*w₀;:::;w*) to functionality *F*.

The simulation for the protocol transcript is straightforward. Below, we rst consider the case of *p* = 2, and later discuss the case of a prime *p >* 2. In the real protocol execution, the correlation check has the following equation:

|n 1|r|1||||
|---|---|---|---|---|---|
|i|i|h|h h|z||
|i=0|h=0|||||
|i i|i B|||h h|h B|

X X *x* = *z y* = (*wiv*) + (*c b*) X + *e* (4)

For a malicious PA, we have that *w v* = *hg u; i* for *i 2* [0*;n*) and *c b* = *hg a; i* for *h 2* [0*;r*). Thus, we can rewrite equation (4) as follows:

|n 1|||r 1|||
|---|---|---|---|---|---|
|i|i|B||h B|h z|
|i=0|n 1 i i=0|i|h=0 r 1 h h=0|h B|z|

X X *x hg u; i hg a; i* X = *e*

D X X E *, g x g u g a* X*;* = *e :*

Therefore, the set *S* corresponds to *A*’s guess of, and the probability of aborting in the ideal- world execution is the same as that in the real-world execution. For any two dierent solutions *;* *0* *2 S*, we dene = ~ *0* *2* F*pr* and thus ~*B*= *0* *2f*0*;* 1*g* *rm*. From equation (1), we easily obtain that equation (2) holds. This also shows *B B* that the set *S* for equation (1) is an ane subspace of F*pr*. Note that the set *S*~~from equation (2) is a linear space parallel to *S*. If there is only one solution for equation (1), then *S*~~includes only one zero entry. In this case, *S* aborts, and the probability that the real protocol execution does not abort is at most 1*=p* *r*. For *h 2* [0*;r*), we dene *ah*= ~ 1 *hg ah;* ~*Bi* (5)

where = ~ *hg;* ~*Bi2 S*~~is used to compute *ui*for *i 2* [0*;n*) in equation (3). Clearly, equations (3) P *n* P *r h* and (5) provide a solution for *x* = *i*=0 *i* *ui*+ *h*=0 *ah*X such that for some = ~ *hg;* ~*Bi2 S*~~ P *r* we have *h*=0 *g ahg ah;* ~*B*= 0 for all *h 2* [0*;r*) and *g uig ui;* ~*B*= 0 for all *i 2* [0*;n*).

Below, we need to prove that the *fuigi2*[0*;n*)computed by equation (3) give the unique solution for a suciently large subspace of *S*~~. Now, we assume that for some *l 2* N, for each *f 2* [*l*], there exists a P *n* 1 P *r* 1 *h* dierent set *fuf;igi2*[0*;n*)along with the set *faf;hgh2*[0*;r*)such that *x* = *i*=0 *i* *uf;i*+ *h*=0 *af;h*X and

X *r* 1 ~*f*~*f h* *hg uf;ig ui;* *B* *i* = 0 for all *i 2* [0*;n*) and *hg af;hg ah;* *B* *i* X = 0*;* (6) *h*=0

~*f*~*f*~ ~ ~ ~ for all = *hg;* *B* *i2 SfS*~such that *jSfj >* 1. The condition of *jSfj >* 1 is required for *A* to pass the correlation check with probability more than 1*=p* *r*. Since *S*~*f*is a linear space for all *f 2* [*l*] and *S*~*f\ S*~*f0* = *f*0*g* from the denition, and *jS*~~*j p* *r* by denition, we have that *l r*log*p*. *0* P *n* 1 P *r* 1 *h* Let *f 6*= *f 2* [*l*]. From equation (2) and *x* = *i*=0 *i* *uf0;i*+ *h*=0 *af0;h*X, we have:

*n* X 1 *n* X 1 X *r* 1 X *r* 1 *u 0*~ *f* *hg u;* ~ *f* *i* + *a 0*~ *f* X *h* *hg a;* ~ *f* *i* X *h* = 0*:* *i f;i i i B f;h h B* *i*=0 *i*=0 *h*=0 *h*=0

## Using equation (6), we obtain

*n* X 1 X *r* 1 (*u 0 u*) ~ *f* + (*a 0 a*) ~ *f* X *h* = 0 (7) *i f;i f;i f;h f;h* *i*=0 *h*=0

By denition, there exists some *j 2* [0*;n*) such that *uf;j6*= *uf0;j*. Furthermore, there are at least two values for ~ *f* *2 S*~*f*, and thus we assume that in the above equation ~ *f* *6*= 0. Thus, (*uf0;juf;j*) ~ *f* *6*= 0. Note that0*;:::;n* 1are sampled uniformly at random and independent from the other values involved in equation (7). Therefore, equation (7) holds with probability at most 1*=p* *r*. There are fewer than *l²* (*r*log*p*) 2 pairs *f 6*= *f⁰ 2* [*l*]. Thus, the overall probability is bounded by (*r*log*p*) 2 *=p* *r*. We have established that there exists a unique solution *ui*for *i 2* [0*;n*). This means that for all = ~ *hg;* ~*Bi 2 S*~~, we have that *hg uig ui;* ~*Bi* = 0 for *i 2* [0*;n*). Therefore, we obtain that *hg ei;* ~*Bi* = 0 for all *i 2* [0*;n*). If there exists two dierent*;* *0* *2 S* such that *hg ei;Bi6*= *hg ei;* *0B* *i* for some *i 2* [0*;n*) where *hg;Bi* = and *hg;* *0B* *i* = *0*, then we dene ~*B*:=*B* *0B* and have that = ~ *hg;* ~*Bi 2 S*~~and *hg ei;* ~*Bi 6*= 0. This is contradict with *hg ei;* ~*Bi* = 0. This concludes that *hg ei;Bi* is a unique value for all possible = *hg;Bi2 S*, and can be computed by the simulator using any *2 S*. In the real protocol execution, *A* can compute *w* *i0* := *wihg ei;Bi* for *i 2* [0*;n*) just as that computed by *S*. Together with that *wi*= *vi*+ *hg ui;Bi*, we have that

*wi0*= *vi*+ *hg ui;Bihg ei;Bi* = *vi*+ *ui:*

We now discuss the case of a prime *p >* 2. The main dierence from the case of *p* = 2 is that *r* *rm* the canonical maps between *2* F*p*and*B2f*0*;* 1*g* are not bijective. This implies that the solutions of equations (1) and (2) are not necessarily vectors of bits rather than elements of F*p*. Following the proof of [KOS16, Lemma 2], we have that if *S*~*f*includes at least two vectors that only consist of bits, which is necessary for the adversary to pass the correlation check with probability more than 1*=p* *r*, then it has dimension at least 1 for all *f 2* [*l*]. We also have the fact that *S*~~has dimension at most *r*log*p* and *S*~*f\ S*~*f*= *f g* for *f 6*= *f⁰* [*l*] by denition. Together, we obtain that *l r*log*p* as above.

Overall, we have that no environment *Z* can distinguish the real-world execution from the ideal-world execution, except with probability at most (*r*log*p*) 2 *=p* *r*. *p;r* Malicious PB. *S* is given access to *F* LsVOLE, and interacts with adversary *A* as follows: *p;r*

1. *S* emulates *F*
COPEe, and receives the values, *vi*for *i 2* [0*;n*) and *bh*for *h 2* [0*;r*) from *A*. P *n*

2.After receiving coecients1*;:::;n prpr*

||||2 F|, S samples x|F, computes y :=|||v +|
|---|---|---|---|---|---|---|---|---|
|r h=1 h|h 1|p n|n|p n p|p LsVOLE p;r||i=1|i i|
||r h=1 h|h 1|p|h|n i=1 i i|p;r r COPEe h=1 h|h 1|p|
||p||||||||

*i*=1 *i i* P *r h* 1 *b* X *2* F *r*, and computes *z* := *y* + *x 2* F*pr*. Then *S* sends (*x;z*) to adversary *A*.

3. *S* denes *v* = (*v₁;:::;v*) and sends *v 2* F *r* to functionality *F*. In the real protocol execution, the elements *a* for all *h 2* [0*;r*) output by *F* are uniform in F.
P P P Therefore, *a* X is uniform in F *r*, and thus *x* = *u* + *a* X is uniformly random in F *r*. We obtain that the simulation is perfect. It is easy to see that the outputs of two parties have the same distribution between the real-world execution and the ideal-world execution.

## B.3 Proof of Theorem3

We rst consider the case of a malicious PAand then consider the case of a malicious PB. In each *p;r*

|||p;r|
|---|---|---|
||p;r|spsVOLE|
|OT|sVOLE||

case, we construct a PPT simulator *S* given access to *F* that runs the PPT adversary *A* as a subroutine, and emulates functionalities *F*, *F*, and *F*EQ. We always implicitly assume that *S* passes all communication between *A* and environment *Z*.

Malicious PA. Every time the extend procedure is run (on input *n*), *S* interacts with *A* as follows: *p;r p;r*

1. *S* emulates *F*
sVOLE and records the values (*a;c*) that *A* sends to *F* sVOLE. When *A* sends the message *a⁰ 2* F*p*, then *S* sets := *a⁰* + *a 2* F*p*and := *c*.

2.For *i 2* [1*;h*), *S* samples *K*
*i* *f* 0*;* 1*g*; it also samples *K* *h* F*pr*. Then for *i 2* [*h*], *S* emulates *F*OTby receiving*i2f*0*;* 1*g* from *A*, and returning *K* *i* *i* := *K* *i* to *A*. It sets :=1 *h*and denes *u 2* F *n* *p*as the vector that is 0 everywhere except that *u*[] :=. Next, *S* computes *fvjgj6*=:= GGM⁰(*; fK* *i* *i* *gi2*[*h*]).

3. *S* picks *d* F*pr* and sends it to *A*. Then, *S* denes *w* as the vector of length *n* with *w*[*i*] := *vi*
P for *i 6*= and *w*[] := *d* + *i6*= *w*[*i*]. *p;r*

4. *S* emulates *F*
sVOLE by recording (*x; z*) from *A*.

*rp 0 rp 0* P *r* 1 *0 i*

5. *S* receives *figi2*[0*;n*)and *x 2* F from *A*, and sets *x* := *x* + *x 2* F and *x* :=
*i*=0 *x* [*i*] X.

*0* P *n* 1 P *r* 1 *i*

6. *S* records *V*A*2* F*pr* that *A* sends to *F*EQ. It then computes *V*
A := *i*=0 *i* *w*[*i*] *i*=0 *z*[*i*] X *2* F*pr* and does:

If *x⁰* =, then *S* checks whether *V*A= *V* A *0*. If so, *S* sends true to *A*, and sends *u; w* to *p;r* *F* spsVOLE. Otherwise, *S* sends abort to *A* and aborts. Otherwise, *S* computes *0* := (*V* A *0* *V*A) *=*( *x⁰*) *2* F*pr* and sends a global-key query *0 p;r p;r* (guess*;*) to *F* spsVOLE. If *F* spsVOLE returns success, *S* sends true to *A*, and sends *u; w* to *p;r* *F* spsVOLE. Otherwise, *S* sends abort to *A* and aborts.

~*p;r*

7.Whenever *A* sends a global-key query (guess*;*) to functionality *F*
sVOLE, *S* forwards the query *p;r* to *F* spsVOLE and returns the answer to *A*. If the answer is abort, *S* aborts.

In the above simulation, if *A* succeeds to guess, then *S* simulates the *A*’s view using without *p;r* making any further global-key query to *F* spsVOLE. We claim that the joint distribution of the view of *A* and the output of the honest PBin the ideal-world execution above is computationally indistinguishable from their distribution in the real- world execution. By the standard analysis of the GGM construction, it is not hard to see that *d* and the *fK* *i* *i* *g* sent to *A* in the above simulation, as well as the vector *v* that would be output by PBwhen it does not abort, are computationally indistinguishable from the corresponding values in the real protocol execution. It thus only remains to analyze steps4{6, which determine whether PBaborts. *0 0 0* P *r* 1 *0 i 0* Let = *a* + *a*, *x* = *x* + *x*, and *x* = *i*=0 *x* [*i*] X, as above. (Note that *a;a; x; x* are well-dened in the real-world execution as well.) In the real-world execution, PBcomputes

*n* X 1 X *r* 1 *V*B=*iv*[*i*] *y*[*i*] X *i* *i*=0 *i*=0 X X *r* 1 =*iv*[*i*] + *v*[] (*z*[*i*] *x⁰*[*i*]) X *i*

*i6*= *i*=0 X X =*iv*[*i*] + ( *d v*[*i*]) *i6*= *i6*= X *r* 1 *z*[*i*] X *i* + *x⁰* *i*=0 *n* X 1 X *r* 1 =*iw*[*i*] *z*[*i*] X *i* ( *x⁰*) *i*=0 *i*=0 = *V*A *0* ( *x⁰*)*:*

where *w* and *V* A *0* are dened as in the description of *S* above. Say that *A* sends *V*Ato *F*EQ. If *x⁰* = (as will be the case when *A* behaves honestly), then *F*EQreturns true i *V*A= *V* A *0*. Otherwise, *F*EQreturns true i = (*V* A *0* *V*A)*=*( *x⁰*). We thus see that the ideal-world behavior of *F*EQmatches what would occur in the real world.

Malicious PB. Simulator *S* interacts with *A* as follows. First, *S* simulates the initialization step by *r* *p;r* recording the global key *2* F*p*that *A* sends to *F* sVOLE. Then, every time the extend procedure is executed (on input *n*), *S* does:

*r* *p;r 0*

1. *S* records *b 2* F*p*that *A* sends to *F*
sVOLE. Then *S* samples *a* F*p*and sends it to *A*. Next, *S* computes := *b a⁰*, and then samples F*p*and sets := +.

2. *S* records the values *f*(*K₀*
*i* *;K₁* *i*

)*gi2*[*h*]sent to *F*OTby *A*.
3. *S* receives *d 2* F*pr* from *A*. Then, for each *2* [0*;n*), it computes a vector *w* as follows:
(a)Execute *fv*
*j* *gj6*=:= GGM⁰(*; fK* *i* *i* *gi2*[*h*]) and set *w* [*i*] = *v* *i* for *i 6*=. P

(b)Compute *w* [] := (*d* +
*i6*= *w* [*i*]). *p;r*

4. *S* records the vector *y* sent to *F*
sVOLE by *A*.

5. *S* samples*i*F*pr* for *i 2* [0*;n*) and *x* F
*rp*, and sends them to *A*. Then *S* computes *y* := *y x*.

P *r* 1 *i*

6. *S* computes *Y* :=
*i*=0 *y*[*i*] X. It then records *V*Bsent to *F*EQby *A*. Next, *S* computes a set *I* [0*;n*) as follows: P *n* 1

(a)For

|2 [0;n), compute V||:=||w|[i]|
|---|---|---|---|---|---|
|p;r spsVOLE||A A|i=0 B|i||
||||||B|

A *i*=0 *i*

*Y*.
(b)Dene *I* := *f 2* [0*;n*) *j V* = *V g*. *S* sends *I* to *F*; if it returns abort, *S* picks ~ [0*;n*)*nI*, sends false*;V*
A~ to *A* on behalf of *F*EQ, and then aborts. Otherwise, *S* sends (true*;V*) to *A*.

7. *S* chooses an arbitrary *2 I* and computes a vector *v* as follows:
(a)Set *v*[*i*] := *w* [*i*] for *i 2* [0*;n*)*;i 6*=.
P

(b)Set *v*[] := *d*
*i6*= *v*[*i*]. *p;r* *S* sends *v* to *F* spsVOLE and outputs whatever *A* outputs.

We rst consider the view of adversary *A* in the ideal-world execution and the real-world execution. The values *a⁰* and *x* simulated by *S* have the same distribution as the real values, which are masked *p;r* by a uniform element/vector output by *F* sVOLE. The set *I* extracted by *S* corresponds to the selective *p;r* failure attack on the output index of PA. If *S* receives abort from *F* spsVOLE, we have that *2= I*. In the real protocol execution, if *V*B*6*= *V* A, then PAaborts. By previous considerations, this is *p;r* equivalent to *2= I*. Therefore, *F* spsVOLE aborts if and only if the real protocol execution aborts. For an honest PA, the index *2* [0*;n*) is sampled uniformly in both the real-world execution and *p;r* the ideal-world execution. If receiving abort from *F* spsVOLE, then *S* needs to send false along with an element *V* A~ *6*= *V*Bto *A*. Although *S* does not know the actual index, it can sample a random index ~ from the set [0*;n*)*nI* and send *V* A~ to *A*. In the case of aborting, this simulation is perfect, since *Z* cannot obtain the output of PAdue to aborting, and the dummy index ~ has the same distribution as the actual index under the condition that *I* is an incorrect guess. Overall, we have that the adversary’s view is perfectly indistinguishable between the real- world execution and the ideal-world execution. Below, we prove that except with probability 1*=p* *r*, the distribution of PA’s output in the real-world execution is the same as that in the ideal- world execution. It is easy to see that the output vector *u* that is 0 everywhere except that *u* [] = in the ideal-world execution and the real-world execution have the same distribution, from the above analysis and that is perfectly hidden. In the following, we focus on proving the indistinguishability of *w* output by PAbetween the ideal-world execution and the real-world execution. Firstly, we prove that the vector *v 2* F *n* *p* *r* computed by *S* in the step7is unique (i.e., independent of the choice *2 I*).

Claim 1. *For any ;* *0* *2* [0*;n*)*, let v; v 0 be the vectors computed by S with ;* *0* *following the* *step7, then we have* n *0* o <u>1</u> Pr *v 6*= *v 0 V*A= *V*A *r* *:* *p* *0* *Proof.* Since *V* A = *V* A, we have X X *iw* [*i*] *Y* =*iw 0* [*i*] *0 Y,* *i2*[0*;n*) *i2*[0*;n*) X (*w* [*i*] *w* [*i*]) + (*w* [] *w* []) + (*w* [] *w* [] + ) = 0*:* *i* *i6*=*;*

Note that ,, *w* and *w 0* have already been dened before *figi2*[0*;n*)are sampled. Furthermore, each coecient*i*is uniform. Therefore, except with probability 1*=p* *r*, we have:

*w* [*i*] = *w 0* [*i*] for *i 2* [0*;n*)*;i 6*=*;* *0* *;* *w* [] *w 0* [] = *w 0* [ *0*] *w* [ *0*] = *:*

From the rst equation, we directly obtain that *v* [*i*] = *v 0* [*i*] for *i 6*=*;* *0*. From the denitions of *w* [] and *v* [], we have that *v* [] = *w* []. Together with *w* [] = *w 0* [] +, we further have that *v* [] = *w 0* [] = *v 0* []. Similarly we also have *v 0* [ *0*] = *v* [ *0*].

Let *w; u* be the output of PAand *v* be the input from *S* (or PB). It is obvious that *w* = *v* + *u* in the ideal-world execution. Now we look at the real-world execution. We dene P a vector *v* as *v* [*i*] = *w* [*i*] for *i 6*= and *v* [] = *d* *i6*= *v* [*i*], where recall that P is the output index of PA. From *w* [] = + (*d* + *i6*= *w* [*i*]), we have that *w* [] = *v* [] +. Therefore, we obtain that *w* = *v* + *u* where *w* = *w*. Note that *v* in both the ideal-world execution and the real-world execution are dened in the identical way, and thus have the same distribution. Based on Claim1, we know that in the ideal-world execution, *v* is indistinguishable from *v* computed by *S*, except with probability at most 1*=p* *r*. Therefore *v* in the ideal-world execution is indistinguishable from *v* in the real-world execution, which implies the indistinguishability of the output of PAin the ideal world and the real world.

## B.4 Proof of Theorem4and Protocol Optimizations

*Proof.* We rst consider the case of a malicious PAand then consider the case of a malicious PB. *p;r* In each case, we construct a PPT simulator *S* given access to *F* sVOLE that runs the adversary *A* as *p;r p;r* a subroutine, and emulates functionalities *F* sVOLE and *F* spsVOLE. We always implicitly assume that *S* passes all communication between *A* and *Z*. *k k p;r* Malicious PA. *S* records the vectors (*u; w*) *2* F*p*F*pr* that *A* sends to *F* sVOLE during initialization. Then in each iteration, *S* runs as follows:

|||spsVOLE p;r|||i|m p||||
|---|---|---|---|---|---|---|---|---|---|
|i|m p ‘p|p;r sVOLE|n p 0|p;r|t n p|n p|k p|n p ‘p k p p;r||
|p;r sVOLE||||spsVOLE||||sVOLE||

1.For *i 2* [*t*], *S* emulates *F*
and receives the value *e 2* F (with at most one nonzero entry) and *c 2* F *r* from *A*; it then denes *e* := (*e₁;:::; e*) *2* F and *c* := (*c₁;:::; ct*) *2* F *r*.

2. *S* computes *x* := *u* A + *e 2* F and *z* := *w* A + *c 2* F *r*, and sends *x*[*k* : *n*) *2* F and *z*[*k* : *n*) *2* F *r* to *F*. It also locally updates *u* := *x*[0 : *k*) *2* F and *w* := *z*[0 : *k*) *2* F *r* for the next iteration.
3.If *A* ever makes a global key query to *F*, then *S* forwards that query to *F*. If *F* responds with abort, *S* aborts; otherwise, it continues. It is easy to see that the simulation provided by *S* is perfect. Malicious PB. *S* runs *G*(1
*k* *;* 1 *n* *;p*) to generate A *2* F *k* *p* *n*. During initialization, *S* records the values *r* *k p;r p;r* *2* F*p*and *v 2* F*pr* that *A* sends to *F* sVOLE, and sends to *F* sVOLE. Then in each iteration, *S* runs as follows:

*m p;r n*

1.For *i 2* [*t*], *S* receives the value *bi2* F*pr* that *A* sends to *F*
spsVOLE; it sets *b* := (*b₁;:::; bt*) *2* F*pr*.

*p;r*

2.For *i 2* [*t*], *S* receives the set *Ii*

||||[0;m) that A sends to F|||. Then S samples e D|and|
|---|---|---|---|---|---|---|---|
|||i|||spsVOLE||n;t|
|1|t||||i|i||

spsVOLE *n;t* denes *f;:::; g* to be the nonzero entries of *e*. If mod *m 2 I* for all *i*, then *S* continues; otherwise, it aborts.

||n|‘p p;r|
|---|---|---|
|k p|p|sVOLE|

3. *S* computes *y* := *v* A + *b 2* F *r*, and sends *y*[*k* : *n*) *2* F *r* to *F*. It also locally updates *v* := *y*[0 : *k*) *2* F *r* for the next iteration. The view of *A* is simulated perfectly, and in both the ideal-world simulation and the ideal-world execution of the protocol the output (*s;* M[*s*]) of PAsatises *y*[*k;n*) = M[*s*] *s*. The dierence is that in the ideal world *s* is uniform, whereas in the real world *s* = *u* A +*e* for a uniform vector <u>u.</u> It is not hard to see that this dierence is undetectable if the LPN
*G* *k;n;t;p* assumption holds.

*p;r p;r* Optimizations. In each iteration of the extend procedure, protocol sVOLE makes *t* calls to *F* spsVOLE. *p;r p;r* If *F* spsVOLE is instantiated by protocol spsVOLE from Section5.1, and we use the optimization de- *p;r p;r* scribed at the end of that section, the *t* calls to spsVOLE require only *t* + *r* calls to *F* sVOLE. *p;r* Moreover, we can push all the calls to *F* sVOLE into the initialization phase, so that the extend *p;r p;r* procedure does not invoke *F* sVOLE at all. Specically, if we make *n₀* = *k* + *t* + *r* calls to *F* sVOLE *p;r* during initialization, we can run the extend procedure without any additional call to *F* sVOLE. Each time the extend procedure is run, we reserve *n₀* of the sVOLE correlations that are produced for the following iteration, and output *n n₀* \usable" sVOLE correlations. We can further optimize the generation of the initial set of *n₀* sVOLE correlations during initialization. Let (*k₀;n₀;t₀*) be another set of LPN parameters. (Note that *n₀ n*, so we can take *k₀ k* and *t₀ t* while achieving security comparable to what is achieved for the LPN parameters (*n;k;t*).) We then make *n⁰*0= *k₀*+*t₀*+ *r* calls to the base-sVOLE protocol described in Section5to *p;r* generate that number of sVOLE correlations, after which we run the extend procedure of sVOLE once to obtain *n₀* sVOLE correlations.
