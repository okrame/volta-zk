# Authenticated Garbling from Simple Correlations

Samuel Dittmer 1[0000*−*0003*−*0018*−*6354], Yuval Ishai², Steve Lu 1[0000*−*0003*−*1837*−*8864], and Rafail Ostrovsky¹ *,*3[0000*−*0002*−*1501*−*1330]

1 Stealth Software Technologies, Inc. 2 Technion-Israel Institute of Technology 3 University of California, Los Angeles

Abstract. We revisit the problem of constant-round malicious secure two-party computation by considering the use of *simple correlations*, namely sources of correlated randomness that can be securely generated with sublinear communication complexity and good concrete efficiency. The current state-of-the-art protocol of Katz et al. (Crypto 2018) achieves malicious security by realizing a variant of the *authenticated garbling* functionality of Wang et al. (CCS 2017). Given oblivious transfer corre- lations, the communication cost of this protocol (with 40 bits of statis- tical security) is comparable to roughly 10 garbled circuits (GCs). This protocol inherently requires more than 2 rounds of interaction. In this work, we use other kinds of simple correlations to realize the authenticated garbling functionality with better efficiency. Concretely, we get the following reduced costs in the random oracle model: – Using variants of both vector oblivious linear evaluation (VOLE) and multiplication triples (MT), we reduce the cost to 1*.*31 GCs. – Using only variants of VOLE, we reduce the cost to 2*.*25 GCs. – Using only variants of MT, we obtain a *non-interactive* (i.e., 2- message) protocol with cost comparable to 8 GCs. Finally, we show that by using recent constructions of pseudorandom correlation generators (Boyle et al., CCS 2018, Crypto 2019, 2020), the simple correlations consumed by our protocols can be securely realized without forming an efficiency bottleneck.

## 1 Introduction

Practical protocols for low-latency secure 2-party computation typically rely on Garbled Circuits (GC) [23]. Such protocols have constant round complexity, on- line communication proportional to the input size, total communication propor- tional to the circuit size, and good computational cost. We revisit the question of concretely efficient GC-based protocols with malicious security, which has been the topic of a long line of work originating from [16,15]. The authenticated gar- bling approach of Wang et al. [20] and Katz et al. [14] gives the state-of-the-art protocols along this line. This approach relies on oblivious transfers for a cut- and-choose based implementation of a preprocessing functionality made up of a collection of authenticated wire labels.

S. Dittmer et al.
This work is motivated by recent techniques for securely generating simple forms of correlated randomness [3,5,18,4,6,22,7], which make it feasible to explore practical alternatives to constructions based only on OTs. In this work, we give three new constructions, including a non-interactive secure computation (NISC) protocol [13], which use simple correlations that can be securely generated with sublinear communication complexity and good concrete efficiency.

|Protocol|Correlation|Cost (garbled circuits)||
|---|---|---|---|
|||Dep. + online Total||
|WRK [20]|OT|2.5|11.0|
|KRRW [14] v1|OT|1.5|7.75|
|KRRW [14] v2|OT|1|9.7|
|KRRW [14] with VOLE|F VOLE|1|2.5|
|KRRW [14] with SPDZ|MT|1|7|
|KRRW [14] with SPDZ and cert. VOLE MT-|F-F VOLE subVOLE|1|2.9|
|Ours, v1 (KRRW with F compiler to F) DAMT pre(κ)|F-F - F DAMT subVOLE VOLE|1|1.31|
|Ours, v2|F-F - F bVOLE subVOLE VOLE NISC in the single-execution setting|1.47|2.25|
|Ours, v3|F OLE|8|8|
|AMPR14 [1]|CRS|40|40|

Table 1. Communication complexity for evaluating a large circuit after a “silent”

randomness generation step, as a ratio to the cost of a semi-honest garbled circuit. The bucket size for KRRW is set to *B* = 3, which is a lower bound for circuits of size less than 2 *ρ*. Dep. + online communication refers to the higher of the two party’s one-way *circuit-dependent* communication cost, including online and offline phase costs. The total column adds in the cost of circuit-independent offline communication.

Our approach achieves significant savings over the approach of [14], reducing the total communication cost from around 10 semi-honest GCs to 1*.*31 GCs in our first protocol (comparing to the size of half-gates garbled circuits in both cases). Our second protocol uses a compressed preprocessing functionality that is expensive to generate for small circuits, but outperforms [14] in the large circuit setting, requiring only 2*.*25 GCs and using only simple “VOLE-type” correlations (see §1.1). Our third protocol is non-interactive (NISC) and achieves comparable com- munication complexity (8 GCs) than the variant of [14] with round complexity proportional to the circuit depth, and roughly 5x the communication efficiency of the best NISC protocols [1] in the single execution setting. Part of our advantage comes from swapping out less efficient ways of gener- ating correlated randomness with recent advantages. For example, a large part of the cost of [14] comes from their methods of generating an *authenticated bits* *functionality*, which can be realized without any communication given two in- stances of vector oblivious linear evaluation (VOLE), defined in § 1.1. But our

Authenticated Garbling from Simple Correlations

main advantage comes from novel compilers from new forms of simple corre- lated randomness to authenticated garbling functionality, including the use of efficient generalizations of *certified VOLE* protocols (see §3.2) that allow verifi- cation across more of the verification work to be done under statistical security instead of computational security (see § 4.2). As we show in Table 1, our most efficient protocol still uses roughly 2x less communication than [14] would use, even if we replaced their authenticated bits generation procedure with VOLE. Alternatively, the SPDZ protocol [10] could be used to realize the prepro- cessing functionality of [14] with authenticated multiplication triples (MTs) in a black box way. Doing this would require 7 GCs. Applying our certified random- ness optimization of § 4.2 to this SPDZ approach would reduce communication to 2.9 GCs, which is still more than both our non-NISC variants. As we further discuss below, the secure generation of the correlated ran- domness required by our protocols is typically cheaper than the protocol that consumes it, especially for VOLE-type correlations or when using multiple cores. Moreover, this secure generation is circuit-independent and only involves local computation without any interaction.

1.1 Simple correlations Our informal definition of a *simple correlation* is one that can be securely gener- ated with sublinear communication complexity and good concrete efficiency. The cost of sending a GC in the semi-honest setting is already linear in the circuit size, and so will dominate the communication cost of setting up the randomness, and any reasonably efficient randomness protocol can be run on multiple cores in the background faster than the communication of the main protocol. We note that all of the flavors of simple correlations discussed here can be realized with a one-time setup step that generates randomness seeds. These seeds can then be expanded into the full correlated randomness locally by each party. This property facilitates running these protocols in a streaming mode, where the randomness is unpacked as needed. To draw attention to this, and to simplify the presentation, we write Extend(*F*) to denote unpacking additional entries from the correlated randomness seeds. Additionally, this one-time setup can be performed non-interactively, which we need to make step 2 of Figure 12 non- interactive for our NISC protocol. We describe these properties more formally as part of an ideal functionality for the correlation calculus in the full version of this paper. We rely on two main flavors of simple correlations: vector oblivious linear evaluation (VOLE)-type correlations, and multiplication triple (MT)-type cor- relations. In VOLE, a receiving party learns v := a*β*+ c along with the scalar *β*, while the sending party learns a*,*c. VOLE with sublinear communication com- plexity was introduced by Boyle et al. [3] in 2019 and has been improved since then, see [7] for the most efficient current variant. In MT, parties learn shares of vectors x*,*y along with shares of the piecewise product z, *zi*= *xi· yi*. MT have been studied as an important primitive for

|Functionality|F|-notation Mathematical relation|Cost comparison|
|---|---|---|---|
|||VOLE-type correlations||
|Vector OLE|F VOLE|ρ v = a β + c, for a, c ∈ F₂|1 VOLE|
|Subfield Vector OLE|F subVOLE|ρ v = a β + c, for a ∈ F₂, c ∈ F₂|≈ 0. 6 VOLE|
|Block Vector OLE|F bVOLE|v = a β + c, for i = 1 ...,L i i i MT-type correlations|L VOLE|
|Two-sided authenticated multiplication triples|F DAMT|Choose x · y = z, then share [x], [y], [z], [αz], [βz]|2 MT|
|Programmable OLE|F OLE|v = a · β + c i,j i i,j j for (i,j) ∈ Q||Q| MT|

Table 2. Correlated randomness used throughout the paper. For programmable OLE,
 the set *Q* is an arbitrary set of ordered pairs of indices. Cost comparison is given with reference to the “base” randomness protocol, either VOLE or MT. Generating 1 million entries of VOLE costs roughly 0.05 seconds on standard computers. Generating 1 million entries of MT costs roughly 10 seconds. years, e.g. [10] but only recently have been able to be generated efficiently and silently [6]. We require several variants of these two types of randomness, as summarized in Table 2. We define all non-standard correlations as functionalities where they arise in the presentation. Crucially, both flavors of randomness generation allow for “progammability” in such a way that each new variant does not require an entirely new protocol, see e.g. [4,6]. Indeed, we can think of VOLE-type and MT-type correlations in terms of simple atomic operations under a “correlation calculus”. For VOLE, atomic op- erations consist of choosing a vector v *∈ F*
*n*, for some field *F*, multiplying v by a scalar *β* (possibly in an extension field *E*), sending a vector to a party, and secret-sharing a vector between parties. Taking *F* = *E* = F₂*ρ* or F₂*κ* gives standard VOLE, taking *F* = F and *E* = F₂*ρ* gives subfield VOLE. Reusing the vector v with a set of scalars *βi*gives block VOLE and block subfield VOLE. For MT-type correlations, atomic operations consist of picking a random vec- tor x *∈ F* *n*, computing the scalar product *β*x, computing the point-wise product x *·*y, sending a vector to a party, and sharing a vector between parties. Standard authenticated triples come from computing z := x*·*y and *β*z and sharing all four vectors. Our *two-sided authentication triples* come from additionally computing *α*z, and sharing this as well. Finally, programmable OLE consists of a family of OLE vectors v*i,j*= a*iβj*+ c*i,j*, where the parties agree to re-use certain vectors a*i*and *βj*on certain entries. The generation time and seed size of programmable OLE scales linearly with the number of pairs (*i,j*) for which we generate a vector of OLE entries. The VOLE protocol of [7] can generate a million entries of VOLE correlations in roughly 0.05 seconds, or a million entries of subfield VOLE in roughly 0.03 seconds. The OLE protocol of [6] can generate a million OLE correlations in roughly 10 seconds. For each of these protocols, the dominant cost is the secret sharing of vectors. We therefore expect that block VOLE over *L* instances costs

roughly *L* times as much computation as a single VOLE, that standard authen- ticated triples costs two times as much communication as OLE, and two-sided authenticated triples cost three times as much. We remark here that the Ring-LPN approach only allows silent generation of authenticated multiplication triples over large fields of characteristic 2 such as F₂*ρ*. If authenticated triples could be silently generated over F₂, then the preprocessing functionality of [14] could be generated with only 2 bits of com- munication per gate, via a procedure similar to that given in Lemma 3. It is precisely because there is no simple correlation that can generate the prepro- cessing functionality directly that the question of the most efficient compiler from simple correlations to that functionality arises.

1.2 Notation We let *f* be a function realized by a circuit *C*, where *C* is made up of input gates *I*, boolean gates *G*, and output gates *O*. Let the input *I* = *IA∪IB*be held by two parties *A* and *B*, and define *n* to be the number of AND gates in *G*, and *m* = *|I|* + *|G|*, including all gates in *m*. We use *κ* and *ρ* as a computational and statistical security parameter, re- spectively, and take *κ* = 128 and *ρ* = 40 for our concrete communication metrics. During the evaluation of a garbled circuit, we write *zi*for the true value of a wire, *λi*for the wire mask, and share *λi*among *A* and *B* as *λi*= *ai⊕ bi*. We use (*⊕, ∧*) for field addition and multiplication over F₂, any of (*⊕,*+*, −*) for field addition over larger fields of characteristic 2, and *·* or concatenation for field multiplication over larger fields of characteristic 2. We use *α,β* for VOLE receiver inputs over F₂*ρ* held by *A,B* respectively, and *∆A*for a VOLE receiver input held by *A* over F₂*κ*. When discussing randomness certification in § 3.2, we need to distinguish between an instance of *F*VOLEwhere party *A* is the receiver and party *B* the sender with another instance of *F*VOLEwith the roles reversed. In this instance, we refer to the latter functionality as *F*ELOV.
1.3 Our contribution Our first protocol relies on both VOLE-type and MT-type correlations. It em- ploys the same authenticated garbling technique as that in [14], but uses authen- ticated triples over F₂*ρ*, rather than cut-and-choose techniques, to generated au- thenticated wire labels. This construction relies on a new compiler from a special flavor of authenticated triples to the desired preprocessing functionality given in §4.1, as well as a lightweight compiler from preprocessing with statistical security to preprocessing with computational security, given in §4.2. Theorem 1. *There is a protocol that securely computes f against malicious* *adversaries in the RO−F*DAMT*−F*VOLE*−F*subVOLE*-hybrid model with the following* *features:*

–Online Communication: *O*(*κ*(*|I|* + *|O|*))*.* –Circuit Dependent Communication: (2*κ* + 2)*n bits of communication.* –Total Communication: (2*κ*+ 2*ρ*+ 2)*n (one-way) or* (2*κ*+ 4*ρ*+ 2)*n (two-* *way) plus terms sublinear in n.* –Computation: *O*(*κn*)*.*

Our second protocol relies only on VOLE-type correlations, and a modifica- tion of the authenticated garbling protocol that, approximately, uses a garbling approach from [20] to replace the authentication procedure in [14]. We give this modified garbling protocol and prove its correctness in §5.1. This modified approach increases the communication cost of the online plus circuit dependent step, but allows the use of a simple *block VOLE* functionality instead of one of the more computationally intensive PCGs used to build authen- ticated triples. As written, the protocol uses quasi-linear work instead of linear work, but this can be reduced to linear work by dividing the gates into blocks of some large fixed size, and running the compressed preprocessing functionality *F*cpon each block in parallel. This approach is best suited to the large circuit setting, since it requires *L ≈ ρ*log *|C|* instances of VOLE (or for sufficiently large *N* and *|C| > N*, *L* = *|C|* <u>ρlog</u> *N* <u>N</u> ), in order to construct the compressed functionality *F*cp. Because VOLE-type correlations are so much more efficient, the computation of the ran- domness generation for this protocol is roughly comparable to that of the first protocol, but the communication of the VOLE seeds is much larger.

Theorem 2. *There is a protocol that securely computes f against malicious* *adversaries in the RO−F*VOLE*−F*subVOLE*−F*bVOLE*-hybrid model with the following* *features:*

–Online Communication: *O*(*κ*(*|I|* + *|O|*))*.* –Circuit Dependent Communication: (2*κ*+ 3*ρ*)*n bits of communication.* –Total Communication: (2*κ* + 8*ρ* + 1)*n* + *o*(*n*)*.* –Computation: *O*(*κn*log*n*) *or O*(*κn*) *with running F*cp*on blocks.*

Our third protocol relies only on MT-type correlations. It uses a similar preprocessing functionality and authenticated garbling protocol as our first pro- tocol, but combines them into a (single-use) NISC protocol. These protocols require certain modifications in order to make them non-interactive. In partic- ular, we require a conditional disclosure of secrets (CDS) functionality to allow the receiver to authenticate their inputs without communication to the prover. We give the details in §6.1.

Theorem 3. *There is a NISC protocol that securely computes f against mali-* *cious adversaries in the RO −F*OLE*-hybrid model with the following features:*

–Online Communication: *O*(*κ*(*|I|* + *|O|*))*.* –Circuit Dependent Communication: (2*κ*+ 3*ρ*)*n bits of communication.* –Total Communication: 16*κn*+ *o*(*n*) *(one-way) or* (29*κ*+3*ρ*)*n* + *o*(1) *(two-* *way).*

### –Computation: O(κn).

We expect the first and third protocols to be dominant in the secure 2PC and NISC settings, respectively, in the million gate setting and the second protocol to be competetive around ten million gates.

1.4 Structure of paper In Section 2, we give an overview of the construction of [14], and explain how this construction can be treated as a blueprint pattern for a family of authenticated garbling constructions. We then describe, at a high-level, how each level of the blueprint is modified for each of our three protocols. In Section 3 we describe a series of technical results about certified VOLE, combining correlated random- ness functionalities, and conditional disclosure of secrets. Each of these results serve the same general purpose of allowing one party to authenticate that their inputs are well-formed to the other party. We give some additional protocols and proofs in Appendix A. We then give our three protocols Π
DAMT 2pc, Π VOLE 2pcand Π NISC 2pcin Sections 4, 5, 6, respectively.

## 2 Authenticated garbling: blueprints and variations

We will present the authenticated garbling protocols in this paper as three dif- ferent constructions following the same general blueprint design. The protocols can be pictured as a series of structures built side-by-side with the same number of *levels*, and corresponding levels play a similar role in each protocol. We begin by reviewing the approach of [14] through this framework, and then go into more detail about how our approaches differ.

2.1 Review: The authenticated garbling blueprint of KRRW [14] Authenticated shared bits. The first level of the construction is an authen- ticated shared bits functionality. In [14], this functionality is presented through the language of IT-MACs. We offer an equivalent definition in the language of simple correlations: The authenticated shared bits functionality is a pair of im- plementations of *F*subVOLE, the first instance is over F₂*ρ*, with party *A* acting as sender and *B* acting as receiver, so that *B* receives *β ∈* F₂*ρ*, *A* receives a *∈* F
*m* 2 and c *∈* F *m* 2 *ρ*, and *B* receives v := a*β* + c. In the second instance, the roles re- versed and the *F*subVOLEis given over F₂*κ*, so that *A* receives *α ∈* F₂*κ*, *B* receives b *∈* F *m* 2and d *∈* F *m* 2 *κ*, and *A* receives w := b*α* + d. These shares will play the role of the wire masks in Yao’s garbled circuits. For the *i*-th wire, party *B* will learn the value *ai⊕ bi⊕ zi*, where *zi*is the true wire value under a plaintext evaluation of the circuit. Because the value *ai*is unknown to *B*, *B* learns nothing from this value. Because the value *bi*is unknown to *A*, *A* is unable to employ a selective-failure attack to deduce which row of the garbled table *B* is attempting to read.

Authenticated parallel AND. To make the protocol secure against a mali- cious *A*, party *B* needs to be able to verify that the row of the garbled table *B* is reading from was constructed correctly. In order to do this, the parties augment the authenticated bit randomness above with authenticated shares of the bits (*ai⊕ bi*) *∧* (*aj⊕ bj*), for every AND gate *Gk*:= (*i,j,k, ∧*), as shown in Figure 1. This construction requires two stages. The first stage we call *authenticated* *parallel AND*. Let PAnd(*n*) be a circuit consisting of *n* AND gates executed in parallel, so that the *k*th gate has input wires (2*k −* 1*,*2*k*) and output wire (PAnd(*n*)*,κ,ρ*) 2*n* + *k*. To simplify notation, we write *F*pre(*κ*)for *F*preand *F*pre(*ρ*)for (PAnd(*n*)*,ρ,ρ*) *F*prewhere *n* is clear from context. In [14], the parties realize the prepro- cessing functionality in the special case of *F*pre(*κ*). Equivalently, they construct authenticated multiplication triples with entries in F₂; as remarked above, there is no simple correlation that can generate these triples silently. In [14], these triples are generated using cut-and-choose techniques, which makes up the lion’s share of the *circuit-independent* communication cost of that protocol.

*Remark 1.* We note that, as well as translating the language of *F*prein [14] from IT-MACs to VOLE, we now require that if *A* holds an input bit, *B*’s share of that input bit’s wire mask is 0, and vice versa. This does not alter the security of the protocol but it simplifies some of the proofs.

<u>Fig. 1. Authenticated wire labels</u>

Functionality *F*pre (*C,ρ,κ*) : Pre-processing of wire labels for authenticated garbling.

Parametrized by values *ρ,κ*, and a circuit *C* consisting of *W* wires, *I* input wires, *O* output wires, and gates *G* of the form (*i,j,k,T*)*,* for *T ∈{∧, ⊕}*, *i,j ∈I∪W*, and *k ∈W∪O*. Recall that *m* := *|I|* + *|G|*.

– *A* chooses *α ∈* F₂*κ* and wire labels a *∈* F *m* 2, c *∈* F *m* 2 *ρ* and sends them to *F*pre. – *B* chooses *β ∈* F₂*ρ* and wire labels b *∈* F *m* 2, d *∈* F *m* 2 *κ* and sends them to *F*pre. – For each input wire *i ∈I*, if *i ∈IA*, set *bi* := 0, and if *i ∈IB*, set *ai* := 0. – For each gate *G* = (*i,j,k,T*), in topological order:

- ** If *T* = *⊕*, *F*pre sets the values *ak*= *ai* + *aj*, *bk*= *bi* + *bj*, *ck*= *ci* + *cj*, and *d* *k*= *di* + *dj*, where the addition is performed in the appropriate field of characteristic 2.
- ** If *T* = *∧*, *F*pre chooses values ˆ*ak*uniformly at random from F₂*ρ*, ˆ*ck*uniformly at random from F, *d*ˆ*k*uniformly at random from F₂*κ*, and ˆ*bk*= (*ai* + *bi*) *·* (*aj* + *bj*) + ˆ*ak*.
– *F*pre computes

(v*,* vˆ*,* w*,* wˆ) = (a*β* + c*,* aˆ*β* + cˆ*,* b*α* + d*,* bˆ*α* + dˆ)*.*

<u>– F</u>pre <u>sends (v, vˆ, b</u>ˆ<u>, d</u>ˆ<u>) to B and (w, wˆ, aˆ, cˆ) to A.</u>

Authenticated circuit wires. The second step is to convert this generic pre- processing *F*pre(*κ*), which serves the parallel AND gate circuit only, to the circuit- (*C,ρ,κ*) dependent preprocessing *F*pre. In other words, we now want shares of the bit (*ai⊕ bi*) *∧* (*aj⊕ bj*) for arbitrary pairs of indices (*i,j*), and *ai⊕ bi*, *aj⊕ bj*may in turn represent the XOR of several prior bits. This conversion is done using standard Beaver triple techniques [2], as we show below in §4.2. In one variant of [14] the triples are instead constructed “in-place”, which gives a modified construction with less total communication, but some additional communication in the circuit-dependent phase. The main result of [14] can now be re-stated as follows:

Theorem 4([14]). *The KRRW protocol [14] securely computes a functionality* *f against malicious adversaries in the RO-F*pre*-hybrid model, with* 2*κ*+ 2 *bits of* *communication per AND gate, κ* + 1 *bits of communication per input gate, and* 1 *bit of communication per output gate.*

Authenticated garbling. The authenticated garbling protocols of both [20] and the follow-up work [14] are both instructive here. After the authenticated circuit wire labels are completed, party *A* plays the role of the sender in a semi- honest evaluation of Yao’s garbled circuit, and some additional interaction allows *B* to verify the correctness of the opened entry of each AND gate. be the authenticated bit shares

|For an AND gate G|:= (i,j,k, ∧), let ˆ||a, ˆb|
|---|---|---|---|
||k||k k|
|i i|j j i|k i|k k i|

of (*a ⊕ b*) *∧* (*a ⊕ b*), and let *λ* := *a ⊕ b*, with *λ*ˆ*k*defined similarly. If both parties know the value (*λ ⊕ z*), where *z* is the true value of the wire, then they can locally construct authenticated bit shares of

*z* *i∧ zj⊕ λk*= *λk⊕ λ* ˆ *k⊕* (*zi⊕ λi*)*λj⊕* (*zj⊕ λj*)*λi⊕* (*zi⊕ λi*) *∧* (*zj⊕ λj*)*.*

From there, *B* evaluates the garbled circuit, *A* securely opens their bit share of

|z ∧ z ⊕ λ|, and B verifies that the value z||∧ z ⊕ λ|is equal to the wire label|||
|---|---|---|---|---|---|---|
|i j k k|k|i j|i j k|k|i i i j|i j|

*z ∧ λ* computed from garbled circuit evaluation. The primary distinction between [20] and [14] is how the value of *λ ⊕ z* is computed. In [20], party *A* computes all four possibilities of (*λ ⊕ z,λ ⊕ z*), with the accompanying shares of *z ∧ z ⊕ λ*. They then construct what are essentially two garbled circuits. The first garbled circuit, used for evaluation, uses computational security to hide gate labels from *B*. The second garbled circuit, used for authentication, hides only the masked wire labels *zi⊕ λi*and the accompanying share of *zi∧zj⊕λk*, and uses statistical security to stop *A* from flipping a bit of the masked wire label. In [20], the first garbled circuit requires 3*κ* communication per gate, and the second requires 4*ρ* bits of communication. In the [14] protocol, the first circuit is improved to 2*κ* bits of communication by applying the half-gate technique of Zahur et al. [24], and the second circuit is replaced with one more round of communication wherein *B* opens all masked wire labels to *A*, and *A* then batches together the proof of correct garbling on the traveled path.

*Remark 2.* A recent advance due to Rosulek and Roy [17] reduces the cost of semi-honest garbled circuits to 1*.*5*κ*+5 bits per AND gate and is compatible with

free XOR. A natural question is whether the approach of [14] can be extended to this new “three-halves” garbled circuit construction. We hope the answer is yes, although there are some obstacles to overcome. In the [17] construction, the gates and wire labels are “sliced and diced“ into half labels, but there is no canonical way for the evaluator to perform a linear combination of these half labels and compute the output wire’s half labels. In- stead, the desired linear combination is *garbling-dependent*, and randomized and encrypted in such a way that the evaluator learns the desired linear combination without learning anything about the garbling. In the [14] paradigm, the garbler cannot know the garbling, and naturally, it is harder to randomize and encrypt something you do not know. We leave the study of this question to future work.

2.2 New Ideas: Authenticated shared bits We now go through the levels of this blueprint again, this time explaining the changes that each of our three protocols make to the pattern laid out above. First, for authenticated shared bits, as mentioned above, two instances of *F*subVOLE are sufficient to generate this randomness, and we use exactly this for our first protocol, Π
DAMT 2pc. For the protocol using only VOLE-type correlations, Π VOLE 2pc, we introduce a complication. We now generate all wire tags *bi*as a (public) linear combination of entries of a vector e*b* of wire tags. The length of e*b* is *O*(*ρ*log*n*). This allows us to generate shares of values *ai∧ bj*as a linear combination of values *ai∧* e*bj′*, which can in turn be represented as entries of VOLE. To ensure that security against a malicious *A* remains, we have to verify that we are still protected against selective failure attacks. Following the protocol of [20], we do not allow *A* to learn the values *zi⊕ λi*, and instead send a second garbled circuit that allows *B* to learn *zi⊕ λi*and the accompanying share of *z* *i∧ zj⊕ λk*. If *A* corrupts only a single gate, then by the randomness of e*b*, *A* will learn nothing from an abort. However, if *A* corrupts more gates, the values *b* *i*may be linearly related, and so *A* could learn something from whether or not *B* aborts. However, with an appropriate choice of parameters, the values *bi* will only be linearly related if *A* has corrupted so many gates that an abort is inevitable. We note that a similar approach that generates the vector a as a linear transformation of a shorter vector e*a* (i.e. a = *MH*e*a*) would be insecure. Indeed, any vector w in the (non-empty) left kernel of *MH*is orthogonal to a. *B* must learn the values *zi⊕ λi*in order to evaluate the circuit, and can then subtract their share to obtain *zi⊕ ai*. Taking the dot product of a*⊕*z with w gives w*·*z, and *B* has broken the zero-knowledge property of the secure computation. Finally, for the NISC protocol Π NISC 2pc, we can not realize an instance of *F*subVOLEwhere *B* is the sender and *A* is the receiver non-interactively. Instead, we let one of *A*’s inputs to programmable OLE be the vector *α* := (*α,α,...,α*), and then *B*’s input b intended for *F*subVOLEcan instead be given to *F*OLE.

2.3 Authenticated parallel AND For our first protocol, Π
DAMT 2pc, we construct authenticated parallel AND gates from doubly authenticated multiplication triples in two steps. First, we convert (*ρ,n*) from *F* DAMT to *F*pre(*ρ*)using a construction inspired by Beaver triples, see § 4.2. This conversion requires 2*ρ* bits of communication per AND gate. We then convert from *F*pre(*ρ*)to *F*pre(*κ*), that is, from preprocessing for parallel AND gates over F₂*ρ* to parallel AND gates where bits held by party *B* are authenticated over F₂*κ* instead of F₂*ρ*, using a lightweight protocol that requires only 3 + *o*(1) bits per AND gate. This can be done with semi-honest security using the usual compiler from random to fixed subfield VOLE (see e.g. [3]). To make this secure against malicious *B*, *B* must convince *A* that the bits used for this instance of fixed *F*subVOLEmatch the authenticated bits generated by *F*pre(*ρ*). We give a lightweight protocol for this authentication in §4.2. For our VOLE-only protocol, we instead use the block VOLE construction (*F*bVOLE) to obtain bit shares of the product (*a₂i−*1*⊕ b₂i−*1) *∧* (*a₂i⊕ b₂i*) term by term. Party *A* holds the bit *a₂i−*1*∧ a₂i*locally, and can use this value as an entry of its authenticated bits constructed above, and verify its correctness under LPZK. Likewise party *B* holds the bit *b₂*

||∧ b₂|locally and can authenticate||||
|---|---|---|---|---|---|
||i−1 i−1|i i|i|i−1||
|i−1|j|i|j|||

and verify under LPZK. The cross terms *a₂ ∧ b₂* and *a₂ ∧ b₂* are linear combinations of terms of the form *a₂ ∧* e*b* and *a₂ ∧* e*b*, respectively, and so bit shares of these terms can be obtained from the block VOLE. In order to obtain *authenticated* shares, we also need to generate shares of (*ai∧* e*bj*)*β*. To do this, we double the size of *B*’s input to the block VOLE, so that *B*’s inputs are e*bj,* e*bjβ*. (For security reasons, we need to shift all of *B*’s inputs by a random value *γ*, which is an additional input. We give the details in § 5.2 and Appendix B.1). To verify that *B*’s inputs satisfy the correct relation, *B* passes their inputs to an instance of *F*VOLE, playing the role of Sender, and proves correctness under LPZK. For technical reasons, our protocol does not guarantee that a cheating *A* is detected immediately, but instead ensures that, if *A* cheats, *A* corrupts their own share of ˆ*biα*, which will then be detected during the evaluation of the garbled circuit with overwhelming probability. Because of the linear dependence on *B*’s bits, this is no longer a realization of *F*pre(*ρ*) cp

|. We define a modified functionality F||||and show that the converter||
|---|---|---|---|---|---|
|||||(ρ)|(κ)|
|pre(ρ) i i|pre(κ) i|i−1|i−1 i−1 OLE i−1|cp i i|cp i subVOLE|
|OLE|i−1|i|||′|

(*ρ*) (*κ*)
from *F* to *F* can likewise convert from *F*cpto *F*cp. For our NISC protocol, we follow the same approach as in the VOLE-only protocol to produce shares of (*a₂ ⊕ b₂*) *∧* (*a₂ ⊕ b₂*) and (*a₂i−*1*⊕ b₂i−*1) *∧* (*a₂ ⊕ b₂*)*β*, term by term. As discussed above, the parties have to generate authenticated bits through a call to *F* instead of *F*. To generate the pairwise products *b₂ ∧ a₂* and *b₂ ∧ a₂*, and so-on, we re-use *A*’s input a to the *F* functionality, and pair it with a new vector b, which reverses the order of every pair (*b₂,b₂*). Because the protocol is non-interactive, *B* cannot prove anything about their inputs to *A* (in the CRS model, this would require a CRS generated by *A* and

a message from *B* to *A* before *A*’s final message from *A* to *B* for the secure computation, giving a 3 round protocol). Instead, *A* and *B* use a lightweight conditional disclosure of secrets protocol (CDS) which ensures that either *B*’s inputs are well-formed or *A*’s message to *B* in the NISC protocol appears uni- formly random to *B*. We sketch the protocol briefly here, and describe it in more detail in § 6.1. For the CDS protocol, parties *A* and *B* generate an instance of *F*OLEwith *A*’s
input the vector *α* := (*α,α,...,α*), and *B*’s input the vector *β* := (*β,β,...,β*).
Call the resulting shares (v*,*c), so that if both parties are honest, we have *vi*+*ci*= *αβ* for all *i*. Then likewise *v₁ − vi*= *c₁ − ci*for all *i* if both parties are honest, and are otherwise offset by a term unknown to the cheating party. Let the vector s := (*ci− ci*) be held by *A* and the vector t := (*v₁ − vi*) be held by *B*. Then *A* adds *H*(s) to all future messages, *B* subtracts *H*(t) from all future messages. if *B* cheats, *B* will be unable to construct s, and so *A*’s messages will appear random. Similar protocols are used to guarantee that the vector b *′* really holds the desired re-ordering of b, and that all necessary polynomial relations on b hold. We give more detail in § 6.1. We note that our converters from authenticated gates over *ρ* to authenticated gates over *κ* (i.e. the conversion from *F*pre(*ρ*)to *F*pre(*κ*), and related protocols) can no longer be applied in the NISC setting because this protocol requires opening certain shared values publicly, and thus is interactive. This is one of the reasons that our NISC protocol requires more communication than our other two protocols.

2.4 Authenticated circuit wires

||DAMT|||(C,κ,ρ)|
|---|---|---|---|---|
||2pc||pre(κ)|pre pre(κ)|
|(C,κ,ρ)||VOLE|||
|pre||2pc|||
|(C,ρ,ρ)|||(C,κ,ρ)||
|cp|||cp (C,ρ,κ) pre−wbc||
||||cp||
 For our first interactive protocol, Π, the converter from *F* to *F* follows the approach of [14]. We give the protocol converting from *F* to *F* in § 4.2. For our VOLE-based protocol Π, we give instead build *F* directly and convert from that functionality to *F*. We describe these conversions in § 5.2. For our NISC protocol, we define a modified functionality *F* which is similar to the functionality *F*pre, but has the property from *F* that a cheating *A* is not immediately detected but corrupts their own shares. We observe that the protocol sketched above for obtaining authenticated parallel AND gates from authenticated bits can be used to obtain authenticated wires for an arbitrary circuit. Instead of swapping *b₂* and *b₂i*in a second input vector to *F*OLE, we

||i−1||
|---|---|---|
|L|OLE R|i j|
|L|R||
 have one input vector b to the *F* of all left inputs *b* to gates *Gk*= (*i,j,k, ∧*), and a second input vector b of all right inputs *b*. The same techniques are used to ensure that b and b hold the correct linear transformations of b.
2.5 Authenticated garbling For our first protocol, we can use the authenticated garbling protocol of [14]
(*C,ρ,κ*) directly, once the functionality *F*prehas been realized, with a small modifi-

cation to the step where the initial gate labels are determined to account for our (*C,ρ,κ*) small modification to *F*prewhere we allow a party’s wire mask zero when the other party knows the true wire value. The protocol still requires, as in [14], 2*κ* + 2 bits of offline circuit dependent communication per AND gate. For our VOLE-only protocol, we can no longer use the authentication ap- proach of [14] where *B* reveals to *A* the masked wire labels *zi⊕ λi*= *z*

||⊕ a ⊕ b|.|
|---|---|---|
||i i|i|
|i|i|i|
|i i||i|

Of course, *A* can XOR these shares by the values *a* that *A* holds, leaving *z ⊕ b*, and, because the values *bi*are computed as linear combinations of some shorter vector e*b*, there is some linear combination of the *z ⊕ b* terms that causes the *b* terms to cancel identically, and *A* would learn some linear relation on the vector z of true wire values. Instead, we combine the techniques of [20] with Zahur’s half-gate techniques, so that *B* can open exactly one authenticated bit, corresponding to (*zi∧ zj*)*⊕ λk*, for the *k*-th multiplication gate. This requires only statistical security, since the output is only used for verification, and does not play the role of a gate label for an output wire. On the other hand, since the output is being used for verification, we can no longer allow a term *H*(*Li,*0*,k*)*⊕ H*(*Lj,*0*,k*) to be added to the output, so we need to send an additional element of F₂*ρ* as part of the garbled table. In total, the authenticated garbling requires 2*κ*+3*ρ* bits of offline circuit dependent communication per AND gate. In our NISC protocol, we also cannot have party *B* revealing masked wire labels to *A*, because that would require additional rounds of communication. We use the same approach as in our VOLE-only protocol, but need to show additional care to verify that the protocol can be made non-interactive. We give the details in §6.2 and Appendix B.5.

## 3 Authenticating correlated randomness

Before we proceed with a technical description of our main protocols, we give an overview of the techniques related to correlated randomness we use throughout the rest of the paper.

3.1 Compilers from “random” to “fixed” randomness variants There is a standard compiler from random VOLE to fixed VOLE (see e.g. [3]) that allows parties to replace a randomly selected vector v := a*β* + c, where all entries are chosen randomly, with a new vector v
*′* := a *′* *β* *′* + c *′*, where a *′* *,* c *′* are chosen by the sender, *β* *′* is chosen by the receiver, and the receiver additionally learns v *′* given above. The conversion protocol can be stated simply: the receiver

|′|||′|′|′|′|
|---|---|---|---|---|---|---|
||′|′ ′|||′||
|||||||′|
|||′|||||

sends *β* *′* *− β* to the sender, the sender sends a *′* *−*a and c *′* *−*c + (*β* *′* *− β*) *·* a *′* to the receiver, and both parties adjust their shares locally. In cases where the sender does not need to control the value of c, the sender sends only a *−* a, and sets their pair of vectors to (a*,* c *−* (*β − β*) *·* a). We can use this same compiler with block VOLE, where a vector a is used across several instances of VOLE. To replace a random a with a fixed vector a, party *A* only needs to send the message a *−* a once across all instances.

A similar compiler exists for a batch of OLE correlations v := ab + c, where one party sends a *′* *−*a, the other sends b *′* *−*b, and both parties compute locally to obtain v *′* := a *′* b *′* + c *′*. As with block VOLE, if the random vector a is used in multiple instances of programmable OLE, a single message suffices to convert this vector to a *′* across all instances. For a careful accounting of round complexity, we note that, when the value of c can be chosen randomly, these messages can be sent concurrently or in sequence, in either order. If one party does not require fixed inputs, that party does not need to send a message at all.

3.2 Certification between varieties of correlated randomness Recall the “correlation calculus” introduced in §1.1, that allows us to express each of our randomness functionalities in terms of a short list of atomic oper- ations. This same “correlation calculus” allows us to re-use vectors and scalars across distinct flavors of correlated randomness as long as they are of the same type (that is, VOLE-type or MT-type). For example, if we wish to have an instance of *F*VOLEand an instance of *F*subVOLEusing the same value *β* but different vectors a*,* a
*′*, then we generate a*,* a *′* randomly, multiple each vector by *β*, and share each of the results over the desired field. Similar approaches allow us to use the same vector and different values *β,β* *′*, and can also be applied to use the same vectors or values between instances of *F*subVOLEor *F*VOLEover different (top-level) fields. By combining this with the previous observation about compilers from ran- dom to fixed VOLE and OLE, we can allow any vector or scalar to be used as an input to any instance of *F*VOLE, *F*subVOLE, or *F*bVOLE. There are three situations that are not covered by this approach, for which we require bespoke protocols. Each of them work by extending the randomness instances with fresh randomness and evaluating some short polynomial expres- sion on the outputs, which will produce equal outputs for both parties if and only if the desired equality condition holds. A random oracle is applied to the outputs and then the results are compared; any number of certifications of this form can be batched together by applying the random oracle to the collection of outputs. First, in Section 4 we wish to authenticate that the same value *α* is used in a call to *F*VOLEand a call to *F*DAMT. These are generated by different “correlation calculuses”, and it would be a massive efficiency hit to generate *F*VOLEas MT- type randomness. We give a lightweight protocol Π DAMT cert *∧*VOLE in Appendix A.1 Second, in Section 5, we wish to show that, for two calls to VOLE with the parties switching between the role of receiver and sender, the constant value *β* used by one party in their role as receiver matches another value *b* used by the same party while playing the role of the sender. We give a lightweight protocol Π VOLE cert *∧*ELOV in Appendix A.2. Third, in Sections 4 and 5, we wish to certify that two instances of subfield VOLE with different receiver inputs *α,∆A*over different fields F₂*ρ*, F₂*κ* have the same vector inputs b, even if one vector is generated via the compiler from

random to fixed VOLE, and another is generated using an unspecified possibly interactive protocol. We give a lightweight protocol Π *ρ* cert *∧κ* in Appendix A.3.

3.3 Line Point Zero Knowledge In [11], Dittmer, Ishai and Ostrovsky introduced *Line Point Zero Knowledge*, or LPZK, a protocol for building a NIZK for general circuits using a single instance of VOLE. When working in the random oracle model on circuits corresponding to low degree polynomials, LPZK is especially powerful, because many verifications can be batched together. As shown in [21], any number of polynomials on a total of *n* inputs of degree at most *d* can be verified with communication of (*n* + *d*)*κ* bits communication. For completeness, and because we use similar arguments elsewhere in this paper, we sketch the argument here. A prover *P* wishes to convince a verifier *V* that *P* holds inputs a = (*ai*) such that *g*(a) = 0. Each input *ai*becomes the entry of a VOLE *vi*= *aiβ* + *c* *i*, and *V* evaluates *g*(v), which will be a polynomial in *β* of degree at most *d −* 1 if *P* is telling the truth. After masking these values with an oblivious polynomial evaluation of degree *d −* 1, *P* opens the coefficients and *V* confirms the desired equality. In the ROM, many such checks can be batched together,
P P with *V* computing *g*(v)*H*(m;*i*) and *P* computing the coefficients of *g*(a*t* +

c)*H*(m;*i*), where m represents some message transcript committing *P* to the values a, and *i* is the index representing the number of times we’ve evoked this batch check. This construction includes the cost of the compiler from random VOLE to fixed VOLE. In our case, where we wish to prove relations on an already set fixed VOLE, we can omit the *nκ* bits of communication, and send only *dκ* bits. In this paper, we exclusively apply LPZK to the setting where we wish to prove that already set VOLE inputs satisfy some collection of polynomials of degree *d*, and take *d ≤* 3 throughout. We write ΠLPZK(a*,* c*,β,*v*, R*) for the protocol that proves that a satisfies the set of relations *R*, when one party holds (a*,*c) and the other party holds *β* and v := a*β* + c.
## 4 Authenticated garbling from authenticated garbled triples

We follow the blueprint laid out in Section 2, giving the full protocol description and proofs. Recall that in Figure 1, we gave the a preprocessing functionality (*C,ρ,κ*) *F*preused in the constructions of [20] and [14]. Let PAnd(*n*) be a circuit con- sisting of *n* AND gates executed in parallel, so that the *k*th gate has input wires (PAnd(*n*)*,κ,ρ*)

|(2k − 1, 2k) and output wire 2n + k. Recall that we write F||for F|
|---|---|---|
||(PAnd(n),ρ,ρ)||
|pre(ρ)|pre||

pre(*κ*) pre (PAnd(*n*)*,ρ,ρ*) and *F* for *F*pre.

4.1 From authenticated bits to parallel AND with authenticated triples The underlying correlated randomness we need for our protocol is subfield VOLE for generating authenticated bits, VOLE, for running proofs of input correctness under LPZK, and doubly authenticated multiplication triples, for converting from authenticated bits to authenticated parallel AND. Doubly authenticated multiplication triples can be generated from Ring-LPN under the “correlation calculus” discussed in §1.1. This correlated randomness is nonstandard, although it can be viewed as a modified form of the authenticated triples of SPDZ [10]. We give the functionality formally in Figure 2. We then prove the following lemma, which shows how to generate authenticated bits and how to convert these bits to authenticated parallel AND gates.
<u>Fig. 2. Two-sided authenticated triples</u>
 Functionality *F*DAMT
(*ρ,n*) : Two-sided authenticated triple generation

Parametrized by values *ρ,n ∈* N.

– *A* chooses *α ∈* F₂*ρ* and sends *α* to *F*DAMT. – *B* chooses *β ∈* F₂*ρ* and sends *β* to *F*DAMT. – *F*DAMTsamples vectors (x*,*y) uniformly at random from F *n* 2 *ρ*. – *F*DAMTsets z := x *·* y, where the multiplication is done element-wise. – *F*DAMTgenerates random shares (x*A,*1*,* y*A,*1*,* z*A,*1) and (x*B,*1*,* y*B,*1*,* z*B,*1) of the vectors (x*,* y*,*z), with random shares chosen in F₂*ρ*. – *F*DAMTgenerates random shares (x*A,*2*,* y*A,*2*,* z*A,*2) and (x*B,*2*,* y*B,*2*,* z*B,*2) of the vectors (*α*x*,α*y*,α*z), with random shares chosen in F₂*ρ*. – *F*DAMTgenerates random shares (x*A,*3*,* y*A,*3*,* z*A,*3) and (x*B,*3*,* y*B,*3*,* z*B,*3) of the vectors (*β*x*,β*y*,β*z), with random shares chosen in F₂*ρ*. <u>– For i ∈{1,2,3}, F</u>DAMT<u>sends (x</u>*A,i*<u>, y</u>*A,i*<u>, z</u>*A,i*<u>) to A and (x</u>*B,i*<u>, y</u>*B,i*<u>, z</u>*B,i*<u>) to B.</u>

Lemma 1. *The protocol in Figure 3 securely computes F*pre(*ρ*)*against malicious* *adversaries in the F*DAMT*−F*subVOLE*−F*VOLE*-hybrid model with* 2*ρ bits of com-* *munication from B to A and* 2*ρ bits of communication from A to B per AND* *gate.*

Completeness. Expanding as in the standard Beaver triple approach, we have

*a*ˆ*k*+ ˆ*bk*= *ef* + *ey* + *fx* + *z* = (*ai*+ *bi*)(*aj*+ *bj*)*,*

as desired. Then note that

*w*ˆ*k*+ *d*ˆ*k*= (*ai*+ *bi*)(*aj*+ *bj*)*α* + ˆ*akα* = ˆ*bkα,*

<u>Fig. 3. Authenticated parallel AND gates from FDAMT</u>

Protocol Π pre DAMT

(*ρ*) : Circuit dependent pre-processing of wire labels from authenticated parallel AND gates.
Parametrized by values *ρ,κ*, and a circuit *C* consisting of *W* wires, *I* input wires, *O* output wires, and gates *G* of the form (*i,j,k,T*)*,* for *T ∈{∧, ⊕}*, *i,j ∈I∪W*, and *k ∈W∪O*.

1. *A* and *B* invoke *F*subVOLEwith *A* as sender and *B* as receiver so that *A* receives *α ∈* F₂*κ*, *B* receives b *∈* F
*m* 2and d *∈* F *m* 2 *κ*, and *A* receives w := b*α* + d.

2. *A* and *B* invoke *F*subVOLEwith *B* as sender and *A* as receiver, so that *B* receives *β ∈* F₂*ρ*, *A* receives a *∈* F
*m* 2and c *∈* F *m* 2 *ρ*, and *B* receives v := a*β* + c.

3. *A* and *B* invoke *F*DAMTwith *A*’s input *α*, *B*’s input *β*, so that party *P* receives (*xP,ℓ,i,yP,ℓ,i,zP,ℓ,i*) for *ℓ ∈{*1*,*2*,*3*}* and 1 *≤ i ≤ n*.
4. *A* and *B* compute the authentication messages (m*A,* m*B*) using Πcert
DAMT*∧*subVOLE. *A* sends *H*(m*A*) to *B*, who verifies that this equals *H*(m*B*), and otherwise aborts.

5.Initialize a counter *t ←* 1*.*
6.For each gate *G* = (*i,j,k,T*), in topological order: – If *T* = *⊕*:
- *A* sets the values *ak*= *ai* + *aj*, *ck*= *ci* + *cj*, and *wk*= *wi* + *wj*.
- *B* sets the values *bk*= *bi* + *bj*, *dk*= *di* + *dj* and *vk*= *vi* + *vj*.
– If *T* = *∧*:

- *A* sends to *B* the messages (*m* *A* 1*,m* *A* 2*,m*
*A* 3*,m* *A*

4) := (*ai* + *xA,*1*,t,aj* + *yA,*1*,t,ci* + *xA,*3*,t,cj* + *yA,*3*,t*)*.*
- *B* sends to *A* the messages (*m* *B* 1*,m* *B* 2*,m*
*B* 3*,m* *B*

4) := (*bi* + *xB,*1*,t,bj* + *yB,*1*,t,di* + *xB,*2*,t,dj* + *yB,*2*,t*)*.*
- *A* locally verifies that (*wi* +*αxA,*1*,t* +*xA,*2*,t* +*m*
*B* 3*,wj* +*yA,*2*,t* +*αyA,*1*,t* + *m* *B*

4) = (*m* *B* 1*α,m*
*B* 2*α*) and aborts if not.

- *B* locally verifies that (*vi* + *βxB,*1 + *xB,*3 + *m*
*A* 3*,vj* + *yB,*3*,t* + *βyB,*1*,t* + *m* *A*

4) = (*m* *A* 1*β,m*
*A* 2*β*) and aborts if not.

- ** Both parties locally compute *e* := *m*
*A* 1+ *m* *B* 1and *f* := *m* *A* 2+ *m* *B*

2.
- *A* locally computes
*a*ˆ *k*= *ef* + *eyA,*1*,t* + *fxA,*1*,t* + *zA,*1*,t* *c*ˆ *k*= *eyA,*3*,t* + *fxA,*3*,t* + *zA,*3*,t* *w*ˆ*k*= (*ef* + ˆ*ak*)*α* + *eyA,*2*,t* + *fxA,*2*,t* + *zA,*2*,t.*

- *B* locally computes
ˆ *b* *k*= *eyB,*1*,t* + *fxB,*1*,t* + *zB,*1*,t* *d* ˆ *k*= *eyB,*2*,t* + *fxB,*2*,t* + *zB,*2*,t* *v*ˆ *k*= (*ef* + ˆ*bk*)*β* + *eyB,*3*,t* + *fxB,*3*,t* + *zB,*3*,t.*

- *t ← t* + 1.
7.Party *A* performs
wˆ *→* wˆ + (a + lsb(aˆ))*α,*aˆ *→* lsb(aˆ)

8.Party *B* performs
<u>vˆ → vˆ + (b + lsb(b</u>ˆ<u>))β,b</u>ˆ <u>→ lsb(b</u>ˆ<u>),</u>

as desired. Similarly, we have ˆ*akβ* + ˆ*ck*= ˆ*vk,* as desired. At the end of the protocol, parties *A* and *B* locally adjust these shares so that aˆ and bˆ become vectors of bits. Since aˆ + bˆ *∈{*0*,*1*}* *n*, we have (a + lsb(aˆ)) = (b + lsb(bˆ)), so this adjustment preserves the desired relations. Security. By the symmetry of the protocol, it is sufficient to consider the case of a malicious *A*. Let *A* be an adversary corrupting *A*. First, we show that if *A* sends incorrect values in a message, *B* will abort with overwhelming probability. Indeed, if *A* sends *ai*+ *xA,*1+*ϕ₁* instead of *ai*+ *xA,*1and *ci*+ *xA,*3+*ϕ₂* instead of *ci*+ *xA,*3, *B* will verify whether

(*ai*+ *xA,*1+ *ϕ₁*)*β* = (*ai*+ *xA,*1)*β* + *ϕ₂,*

i.e. whether *βϕ₁* = *ϕ₂*. We can then construct a simple simulator *S* that runs *A* as a subroutine and plays the role of *A* in the ideal world. The simulator generates *B*’s last two messages uniformly at random, and the first two messages so that they satisfy the desired check. By the uniform randomness of *y*

|||and y|, the distribution of||
|---|---|---|---|---|
|||B,1|B,2||
|i B,1|j B,2|i i B,1|B,1 j B,2|j B,2|
 *B*’s messages *d* +*y,d* +*y* in the real world are identical to the distribution of *S*’s simulation of *B* in the ideal world. Since *b* + *x* and *b* + *x* can be computed from *A*’s data and the message *d* + *y,d* + *y*, the distribution of these values are identical as well. *S* then sends *B*’s messages to *A*, and aborts if *A* responds with anything besides (*ai*+*xA,*1*,aj*+*yB,*1*,ci*+*xA,*3*,cj*+*yA,*3). Otherwise, *S* outputs whatever *A* outputs. As discussed above, with overwhelming probability an honest *B* aborts in the real world whenever *S* aborts, so the joint distribution of the outputs of *A* and an honest *B* in the real world are indistinguishable from the joint distribution of the outputs of *A* and *S* in the ideal world.
4.2 Circuit-dependent preprocessing from parallel AND gates We now go from authenticated parallel AND gates over *ρ* to authenticated par- allel AND gates over *κ*, and then to authenicated circuit wires. We begin with the conversion from *F*

|to F|.||||
|---|---|---|---|---|
|pre(ρ)|pre(κ)|(C,ρ,κ) pre||(C,ρ,ρ) pre|
|pre(κ)|′|′ A ′|pre(ρ) ′ ′ (C,ρ,ρ)|subVOLE A ′|
||||pre|ρ∧κ|
|||||cert|
 Lemma 2. *The protocol in Figure 4 realizes F*
*securely in the F −* *F*subVOLE*-RO hybrid model, at the cost of an additional* 3*n* + *O*(*κ*) *bits of commu-* *nication. In particular, F is securely realizable in the F −F-RO* *hybrid model.*

*Proof.* Completeness. We have w = b *∆* + d and wˆ = bˆ *∆* + dˆ both immediately before Step 4 and immediately after Step 5. The desired relations ˆ follow from the correctness of the on the vectors a+b, aˆ+b *F* functionality. Security. Security of steps 1,2, and 6 follow from the security of the underlying protocols. Security against a malicious *B* follows from the correctness of Π, shown in Lemma 10, which guarantees that *A* (or a simulator *S*) will detect an incorrect message with high probability.

For security against a malicious *A*, note that *A* sends no message in steps

|3 through 5, and that the messages|m₁, m₂|can be simulated by sampling|
|---|---|---|
|uniformly random sequences of bits, by the security of F|||
|Complexity. We have |w| = 2n and |w|ˆ | = n, so the messages m₁, m₂ take 2n +||
|n = 3n bits. The certification step calling Π||costs O(κ) bits by Lemma 10.|

subVOLE.

cert *ρ∧κ*

See § 3.2 for an overview of this certified functionality notation.

<u>Fig. 4. Authenticated wire labels over κ from wire labels over ρ</u>

Protocol Π pre pre(( *κ* *ρ*)): Circuit dependent pre-processing of wire labels from authenticated parallel *ρ*-AND gates.

Parametrized by values *ρ,κ*, and a circuit *C* consisting of *W* wires, *I* input wires, *O* output wires, and gates *G* of the form (*i,j,k,T*)*,* for *T ∈{∧, ⊕}*, *i,j ∈I∪W*, and *k ∈W∪O*.

1. *A* and *B* invoke *F*pre
(*C,ρ,ρ*), generating vectors a*,* c*,* w*,* aˆ*,* cˆ*,* wˆ and a value *α* for *A* and vectors b*,* d*,* v*,* bˆ*,* dˆ*,* vˆ and a value *β* for *B*.

2. *A* and *B* invoke *F*subVOLEwith *B* as sender and *A* as receiver for the fields (F₂*,*F₂*κ*), so that *B* learns b
*′* *,* d *′* *,* b ˆ*′,* dˆ*′*, and *A* learns *∆* *A ∈* F₂*κ* and vectors w *′* := b *′* *∆A* + d *′* and wˆ *′* := bˆ *′* *∆A* + dˆ *′*.

3. *B* sends to *A* the vectors m₁ := b + b
*′* and m₂ := bˆ + bˆ *′*.

4. *A* adds to obtain w
*′* *←* w *′* + m₁*∆A* and wˆ *′* *←* wˆ *′* + m₂*∆A*.

5. *B* adds to obtain b
*′* *←* b *′* + m₁, bˆ *′* *←* bˆ *′* + m₂.

6. *A* and *B* invoke Π
*ρ* cert *∧κ* to certify that the new values of b*,* bˆ match their original values.

<u>7. A and B return a, c, w</u>
*′* <u>, aˆ, cˆ, wˆ</u> *′* <u>,∆A and b</u> *′* <u>, d</u> *′* <u>, v, b</u>ˆ *′* <u>, d</u> ˆ*′*<u>, vˆ,β respectively.</u>

Next, for completeness, we give a protocol for converting from *F*pre(*κ*)to (*C,ρ,κ*) *F*pre. The following result is implicit in [14] and [20].

Lemma 3. *Let C be a circuit with n AND gates. Then the protocol in Figure 5* (*C,κ,ρ*) *securely computes F*pre*against malicious adversaries in the RO-subVOLE-* *F*pre(*κ*)*hybrid model, with an additional* 2*n bits of communication.*

*Proof.* The security of the first three steps follows from the security of the un- derlying protocols. Correctness is immediate, and the proof of security against malicious parties is similar to the proof of Lemma 1.

*Remark 3.* As discussed in §2.1, Katz et al in [14] realize *F*pre(*κ*)using an opti- mized version of the TinyOT protocol. Their protocol, in addition to the cost of producing authenticated bits, which could be done with sublinear communication

<u>Fig. 5. Authenticated wire labels from authenticated parallel AND gates</u>

Protocol Π pre pre(( *C* *κ*)): Circuit dependent pre-processing of wire labels from authenticated parallel AND gates.

Parametrized by values *ρ,κ*, and a circuit *C* consisting of *W* wires, *I* input wires, *O* output wires, and gates *G* of the form (*i,j,k,T*)*,* for *T ∈{∧, ⊕}*, *i,j ∈I∪W*, and *k ∈W∪O*.

1. *A* and *B* invoke *F*subVOLEwith *A* as sender and *B* as receiver, so that *A* receives *α ∈* F₂*κ*, *B* receives b *∈* F
*m* 2and d *∈* F *m* 2 *κ*, and *A* receives w := b*α* + d.

2. *A* and *B* invoke *F*subVOLEwith *B* as sender and *A* as receiver, so that *B* receives *β ∈* F₂*ρ*, *A* receives a *∈* F
*m* 2and c *∈* F *m* 2 *ρ*, and *B* receives v := a*β* + c.

3. *A* and *B* invoke *F*pre
(PAnd

(*ρ*)(
*n*)*,κ,ρ*) so that *A* obtains (w
*′* *,* wˆ *′* *,* aˆ *′* *,* cˆ *′* ) and *B* obtains (v *′* *,* vˆ *′* *,* aˆ *′* *,* cˆ *′* ).

4.For each gate *G* = (*i,j,k,T*), in topological order: – If *T* = *⊕*:
- *A* sets the values *ak*= *ai* + *aj*, *ck*= *ci* + *cj*, and *wk*= *wi* + *wj*.
*B* sets the values *bk*= *bi* + *bj*, *dk*= *di* + *dj* and *vk*= *vi* + *vj*. – If *T* = *∧* is the *t*-th AND gate:

- *A* sends (*ai* + *a*
*′* 2*t−*1*,aj* + *a* *′* 2*t*) to *B*

- *B* sends (*bi* + *b*
*′* 2*t−*1*,bj* + *b* *′* 2*t*) to *A*

- *A* and *B* locally compute *ek*:= *ai* + *bi* + *a*
*′* 2*t−*1+ *b* *′* 2*t−*1and *fk*:= *a* *j* + *bj* + *a* *′* 2*t*+ *b* *′* 2*t*.

- *A* locally computes
*a*ˆ *k*= *ekfk*+ *ekaj* + *fkai* + ˆ*a* *′t*

*c*ˆ *k*= *ekcj* + *fkci* + ˆ*c* *′t*

*w*ˆ*k*= *ekwj* + *fkwi* + ˆ*wt′.*

- *B* locally computes
ˆ *b* *k*= *ekbj* + *fkbi* + ˆ*b* *′t*

*d* ˆ *k*= *ekdj* + *fkdi* + *d* ˆ *′t*

*v*ˆ *k*= *ekfkβ* + *ekvj* + *fkvi* + ˆ*vt′.*

under VOLE, requires *Bκ* bits of communication per gate, with *B ≈ ρ/* log *|C|*. In particular, *B ≥* 3 for *|C| <* 2 *ρ*. Adding back in the 2*κ* bits required in the online phase, the cost of [14] is at least 2.5x the cost of a semi-honest garbled circuit for circuits with size *|C| <* 2 *ρ*. Unfortunately, Lemma 2 does not offer any improvements the approach of [14], since their compiler to *F*pre(*κ*)requires computational security, and so replacing it with a compiler to *F*pre(*ρ*)would still require *Bκ* bits per gate. An alternative realization of the *F*pre(*κ*)functionality could be accomplished by the SPDZ protocol [10]. This would consume 6 authenticated multiplication triples per AND gate and require 12*κ* additional communication under a naive implementation. Applying Lemma 2 to the naive SPDZ-style approach gives a compiler to *F*pre(*κ*)by way of *F*pre(*ρ*)that costs 12*ρ*+3 bits of communication per gate, and thus 2*κ* + 12*ρ* + 3 bits per gate for the entire protocol, approximately 3x the cost of a semi-honest garbled circuit.

4.3 Authenticated garbling The only changes we make to the authenticated garbling protocol of [14] are after-effects of our decision to alter the preprocessing functionality so that *A* does not hold a mask for a wire value that is one of *B*’s inputs, and vice versa. The only steps that change materially therefore are steps 3 and 4. Step 3 in [14], after translating into the language of VOLE, reads: – For each *i ∈Ii*

|, A sends a|to B and invoke Π||to prove that this a|
|---|---|---|---|
|B i,y ⊕λ|i pre|LPZK i i i|i i|
 matches the value in *F*. *B* then sends *y ⊕ λ* = *y ⊕ a ⊕ b* to *A*. Finally, *A* sends *Li i*to *B*. We replace this step with the following: – For each *i ∈IB*, *B* sends *yi⊕ bi*to *A*. Then *A* sends *Li,yi ⊕*b*i*to *B*. It is possible to simulate the previous protocol from this version by having *B* generate *A*’s messages *ai*uniformly at random for *i ∈ IA*, and adjusting their value *bi*to keep the sum *ai⊕ bi*constant, and having *A* set *ai*= 0. These adjustments can occur without any communication, since the values *ai*, *bi*are never used again by *A*, *B* respectively. Therefore the security of one protocol implies the security of the other. We make similar adjustments to Step 4. Proof of Theorem 1 Combining the three lemmas in this section gives a real-
(*C,ρ,κ*) ization of *F*prein the *F*DAMT*−F*VOLE*−F*subVOLEmodel. Applying Theorem 4 and incorporating the minor changes to the authenticated garbling protocol out- lined above gives that the desired Π DAMT 2pcprotocol.

## 5 Authenticated garbling from block VOLE

5.1 Compressed authenticated bits from block VOLE We begin by stating formally the compressed preprocessing functionality and the block (subfield) VOLE functionality.

The compressed preprocessing functionality *compresses B*’s wire labels be- longing to AND gates in b to a much shorter vector e*b* of length

<u>ρlog n − ρlogρ</u> *L* := + 2*ρ.* log 2

|I||′|
|---|---|---|
||I ′||
|||H|
|H|L 2||

Write b for input wires, and b for AND gate wires. Then the vector b is determined from b *∪*b in the obvious way, and b *′* is determined from e*b* by some public linear transformation *M*. Similarly *B*’s wire masks d *′* are computed as *M d*e, where *d*e*∈* F *κ*.

<u>Fig. 6. Compressed authenticated wire labels</u>

Functionality *F*cp (*C,ρ*) : Compressed pre-processing of wire labels for authenticated garbling.

Parametrized by the value *ρ*, and a circuit *C* consisting of *W* wires, *I* input wires, *O* output wires, and gates *G* of the form (*i,j,k,T*)*,* for *T ∈{∧, ⊕}*, *i,j ∈I∪W*, and *k ∈W∪O*. Let *n* be the number of AND gates. Where clear from context, we omit the parameters *C,ρ,κ* and write *F*cp for *F*cp (*C,ρ,κ*).

– All parties compute <u>ρlog n − ρlogρ</u> *L* = + 2*ρ.* log 2 – *A* chooses *α ∈* F₂*ρ* and wire labels a *∈* F *n* 2, c *∈* F *n* 2 *ρ* and sends them to *F*cp. – *B* chooses *β ∈* F₂*ρ* and wire labels b*I ∈* F *|I|* *,* e *b ∈* F *L* 2, d*I ∈* F *|I|* 2 *ρ, d*e *∈* F *L* 2 *ρ* and sends them to *F*cp. – *F*cp chooses a random *n × L* matrix *MH* over F₂ and sends *MH* to *A* and *B*. – *F*cp computes the vectors b *′* *,* d *′* via b*,* = *MH*e*b* and d *′* = *MH d*e, and computes b*,*d from b *′* *,* d *′*. – As a sub-protocol, *F*cp runs a simulation of the interaction of *A*, *B*, and *F*pre (*C,ρ,κ*)

using *α,β,*a*,* b*,* c*,*d as the various parties’ inputs, and stores the output. – *F*cp sends (v*,* vˆ*,* bˆ*,* dˆ) to *B* and (w*,* aˆ*,* cˆ) to *A*. – *A* sends either Honest or (Cheat*,* m *∗* ) to *F*cp. – If *A* sent Honest, then *F*cp sends (wˆ) to *A*. <u>– If A sent (Cheat, m</u> *∗* <u>), then F</u>cp <u>sends (wˆ + m</u> *∗* <u>β</u> *−*1 <u>) to A.</u>

The other change made in this pre-processing functionality is that we allow party *A* to cheat in such a way that is not immediately detected, but corrupts its own output. Specifically, if *A* sends faulty messages, *A* can ensure both parties hold shares of ˆ*biα* + *m* *∗* *β* *−*1, rather than ˆ*biα*. Since *A* does not know *β*, *A* cannot use these corrupted shares, and *B* will discover the error and abort during the execution of the authenticated garbling, as we show in § 5.3.

<u>Fig. 7. Block subfield VOLE</u>

Functionality *F*bVOLE (*F,E,k,n*) : Block VOLE

Parametrized by a pair of fields *F ⊆ E* and integers *k* and *n*. In this paper, we have *F ∈{*F₂*,*F₂*ρ}* and *E* = F₂*ρ*. We refer colloquially to the first variant as block subfield VOLE and the second as block VOLE.

– *B* chooses parameters *β₁,...,βk∈ E* and sends them to *F*bVOLE. – *F*bVOLEchooses a collection of vectors b₁*,...,*b*k∈ E* *n* and sends the vectors to

*A*.
– *A* chooses a vector a *∈ F* *n* and sends a to *F*bVOLE. – For *i* = 1*,...,k*, the functionality *F*bVOLEcomputes v*i* = a*βi* + b*i* and sends <u>the result to B.</u>

5.2 From block VOLE to compressed authenticated wire labels We realize this preprocessing functionality using block VOLE, a collection of VOLE or subfield VOLE instances where one party *A* uses the same inputs across the VOLE calls. We define this protocol formally in Figure 7, and give the converter from block VOLE to *F*cpin Figure 8. We note that, in Step 12, if *a* is one of *A*’s input to a block VOLE, and *b* + *γ* and *γ* are two of *B*<u>’s</u> inputs to that block VOLE, then *A* and *B* can produce shares of the value *ab* by subtracting their respective shares of *a*(*b* + *γ*) and *aγ*. All monomial terms in Step 12 can be shared in this fashion. We defer the proof of the following lemma to Appendix B.1.
(*C,ρ,ρ*) Lemma 4. *The protocol in Figure 8 can securely compute F*cp*against ma-* *licious adversaries in the F*bVOLE*−F*VOLE*−F*subVOLE*model with* 1 + *O*( <u>L</u> *n* ) *bits* *of communication per gate from B to A and* 5*ρ* + 1 *bits of communication per* *gate from A to B.*

|(C,ρ,ρ)|(C,ρ,κ)||||
|---|---|---|---|---|
|cp|cp pre(ρ)|pre(κ)|(C,ρ,κ) cp|(C,ρ,ρ) cp|
|(C,ρ,ρ)||(C,ρ,ρ)|||
|pre||cp|||

To convert from *F* to *F*, we used almost the identical protocol to that used to convert from *F* to *F*.

Lemma 5. *The protocol in Figure 4 realizes F in the F −F*subVOLE*-* *hybrid model, replacing F with F in Step 1.*

*Proof.* The argument is identical to the argument in Lemma 2. We need only note that the messages m₁*,*m₂ are still uniformly random in *A*’s view, in spite of the linear relations on b allowed by *F*cp, because of the masks b *′* *,* bˆ *′*.

5.3 Authenticated garbling In Figure 9, we give our modified authenticated garbled circuit protocol. The wire labels are computed as in [14], but in the authentication step we apply

<u>Fig. 8. Compressed authenticated wire labels from block VOLE</u>
 Protocol Πcp(*C,ρ*): Compressed pre-processing of wire labels for authenticated
garbling.

Parametrized by the value *ρ*, and a circuit *C* consisting of *W* wires, *I* input wires, *O* output wires, and gates *G* of the form (*i,j,k,T*)*,* for *T ∈{∧, ⊕}*, *i,j ∈I∪W*, and *k ∈W∪O*. Let *n* be the number of AND gates.

1.All parties compute
<u>ρlog n − ρlogρ</u> *L* = + 2*ρ* log 2 and choose a public *n × L* matrix *MH* over F₂.

2. *A* and *B* invoke *F*subVOLEwith *B* as sender and *A* as receiver, so that *B* learns (e*b, d*e) and *A* holds *w*e, with length of the VOLE equal to *L*.
3.The parties extend the VOLE by length *n*, with additional entries (*wi,j,bi,j,di,j*) where *bi,j* is the (*i,j*)-th entry of (*MH*e*b*)
*T* *·* (*MH*e*b*).

4.Party *A* locally computes *w* = *MH w*e.
5. *B* constructs the vector b = e*biβ* + *γ,β* + *γ,γ* with *γ ∈* F₂*ρ* chosen randomly.
6.Party *A* constructs the vector a := a*∪*(*aiaj*)*∪*(ˆ*ai*). The first vector is *A*’s input to *F*cp, the second vector is the the values *ai ∧ aj*, for every multiplication gate *Gk*= (*∧,i,j*), and the third vector is a string of random bits which will be part of *A*’s output.
7.The parties call Extend(*F*subVOLE), adding b as an additional *L* + 2 entries.
8. *A* and *B* perform <u>F</u>bVOLE
(F2*ρ,*F2*,L*+2*,n*), the subfield variant of block VOLE, with *B*’s inputs the vector b and *A*’s inputs the vector a.

9. *A* and *B* invoke *F*bVOLE
(F2*ρ,*F2*ρ,L*+2*,n*). *B*’s input to the block VOLE is again the vector b with *γ* as above, and *A*’s input is the vector *α ·* a *∪* (ˆ*ai,*2) *∪{α}*, that is, *A*’s input above multiplied by *α*, along with a vector of masks ˆ*ai,*2 *∈* F₂*ρ* and the additional input *α*.

10.Both parties call ΠLPZKto prove correctness of the values *ai ∧ aj*, *bi,j*, and e*biβ* under LPZK.
11. *B* certifies that their inputs to the block VOLE match their inputs to the VOLE with *A* as receiver, with the Π
VOLE cert *∧*ELOV protocol discussed in §3.2.

12. *B* locally computes:
*v*ˆ *i* := ˆ*aiβ* + ˆ*ci* *v* *i,*2 := ˆ*ai,*2*β* + *ci,*2 *v* *i,*3 := ˆ*aiαβ* + *ci,*3 *v* *i,*4 := (*aiaj* + *aibj* + *aj bi*)*β* + *ci,*4 *v* *i,*5 := (*aiaj* + *aibj* + *aj bi*)*αβ* + *ci,*5 where all terms ˆ*ci,ci,j* can be computed locally by *A*.

13. *A* sends to *B* the terms (*mi,*1*,mi,*2) := (ˆ*ci* + *ci,*4*,ci,*2 + *ci,*3 + *ci,*5), and *B* defines
ˆ *b* *i* := (ˆ*vi* + *vi,*4 + *mi,*1) *β* *−*1 + *bibj*

and

*d* ˆ *i* := (*vi,*2 + *vi,*3 + *vi,*5 + *mi,*2)*β* *−*1 + *di,j,*

respectively.

<u>14. A adds locally to hold wˆ</u>*i* <u>:= ˆa</u>*i,*2 <u>+ w</u>*i,j*<u>.</u>

the half gate technique of Zahur et al. [24] to the secondary garbled circuit approach of [20].We also replace *F*prewith *F*cp, and modify Steps 3 and 4 by setting unneeded wire masks to 0 as in §4.3.

Lemma 6. *The protocol given in Figure 9 securely computes a functionality* (*C,ρ,κ*) *f against malicious adversaries in the RO-F*cp*−F*subVOLE*−F*VOLE*-hybrid* *model, with* 2*κ* + 3*ρ bits of communication per AND gate, κ* + 1 *bits of commu-* *nication per input gate, and* 1 *bit of communication per output gate.*

The key difficulty is protecting against a selective failure attack by *A*. Learn- ing whether or not *B* aborts is equivalent to corrupting some subset of *t* table entries (by corrupting the messages *Gi,j*or *G* *′i,j* ), and learning whether *B* opened *any* of those table entries during circuit evaluation. If the *t* table entries chosen correspond to rows of *MH*that are linearly independent, then the labels *MH*e*b* are independent, and the probability of failure is 1 *−* 2 *−t*. We therefore give a simulator that aborts with probability 1*−*2 *−t*, and restrict our attention to the case where the *t* entries correspond to linearly dependent rows of *MH*. To treat this case, we recall the notion of (*t,k*)-independent sets (the concept was first introduced in [12], see [19] for a thorough treatment, and [9,8] for additional discussion). A (*t,k*)-independent set over F*q*is a subset of F *k* *q*such that no *t* + 1 element subset is linearly dependent. For our purposes, it is sufficient to construct a (*ρ −* 1*,L*)-independent set B *⊆* F *L* 2such that *|*B*|* = *n* via a randomized algorithm. Then either the simulator gives the correct abort probability or the protocol aborts almost surely, with probability at least 1*−*2 *−ρ*, and either way party *A* learns nothing. We give the full proof in Appendix B.2.

|Proof of Theorem 2 We begin with F||. We use Lemma 4 to construct||||
|---|---|---|---|---|---|
|(C,ρ,ρ)|(C,ρ,κ)||||VOLE|
|cp|cp||||2pc|

bVOLE (*C,ρ,ρ*) (*C,ρ,κ*) VOLE *F*cp, Lemma 5 to construct *F*cpand prove the correctness of Π2pcin Lemma 6.

## 6 NISC from garbled circuits

6.1 Conditional Disclosure of Secrets from programmable OLE We construct a NISC protocol with *A* as sender and *B* as receiver. We generate our authenticated bits and the related conversion protocol to authenticated cir- cuit wire labels using the programmable OLE functionality given in Figure 10. This protocol allows us to to the piece-wise product of any pair of vectors selected from a collection of *p* vectors from *A* and *q* vectors from *B*. Two obstacles present themselves in the conversion from programmable OLE to authenticated circuit wire labels. First, we can no longer use ΠLPZKto certify *B*’s inputs, since this would violate non-interactivity. Instead, we use a special- ized conditional disclosure of secrets (CDS) protocol that ensures that any future messages from *A* will be uniformly random if *B* cheats. The second obstacle is

<u>Fig. 9. Authenticated garbling protocol in the Fcp hybrid model</u>

Protocol Π VOLE 2pc

Inputs: Party *A* holds *x ∈{*0*,*1*}* *|I*1*|* and *B* holds *y ∈{*0*,*1*}* *|I*2*|*. Both parties hold a circuit *C* for a function *f* : *{*0*,*1*}* *|I*1*|*+*|I*2*|* *→{*0*,*1*}* *|O|*.

1. *A* and *B* call *F*cp
(*C,ρ,ρ*) and then the compiler from *F*cp (*C,ρ,ρ*) to *F*cp (*C,ρ,κ*), so that *A* holds *∆A,* w*,* wˆ*,* a*,* aˆ*,* c*,* cˆ and *B* holds *β,,*v*,* vˆ*,* b*,* bˆ*,* d*,* dˆ. For each *i ∈I₁ ∪I₂*, *A* also picks a uniform *κ*-bit string *Li,*0. The parties jointly determine keys to hash functions *H* : F₂*κ ×{*1*,...,n}→* F₂*κ* and *H* *′* : F₂*κ ×{*1*,...,n}→* F₂*ρ*.

2.Following the topological order of the circuit, for each gate *G* = (*i,j,k,T*), – If *T* = *⊕*, *A* computes *Lk,*0:= *Li,*0 *⊕ Lj,*0 – If *T* = *∧*, *A* computes *Li,*1 := *Li,*0 *⊕ ∆A*, *Lj,*1 := *Lj,*0 *⊕ ∆A*, and
- *Gk,*0:= *H*(*Li,*0*,k*) *⊕ H*(*Li,*1*,k*) *⊕ wj ⊕ aj ∆A*
- *Gk,*1:= *H*(*Lj,*0*,k*) *⊕ H*(*Lj,*1*,k*) *⊕ wi ⊕ ai∆A ⊕ Li,*0
- *Lk,*0:= *H*(*Li,*0*,k*) *⊕ H*(*Lj,*0*,k*) *⊕* (*wk⊕ w*ˆ*k*) *⊕* (*ak⊕ a*ˆ*k*) *· ∆A*
- *G* *′k,* 0:= *H*
*′* (*Li,*0*,k*) *⊕ H* *′* (*Lj,*0*,k*) *⊕ ck⊕ c*ˆ*k*

- *G* *′k,* 1:= *H*
*′* (*Li,*0*,k*) *⊕ H* *′* (*Li,*1*,k*) *⊕ cj*

- *G* *′k,* 2:= *H*
*′* (*Lj,*0*,k*) *⊕ H* *′* (*Lj,*1*,k*) *⊕ ci* *A* sends *Gk,*0*,Gk,*1*,G* *′k,* 0 *,G* *′k,* 1 *,G* *′k,* 2to *B*.

3.For each *i ∈IB*, *B* sends *yi ⊕ bi* to *A*. Then *A* sends *Li,yi ⊕*b*i*to *B*.
4.For each *i ∈IA*, *A* sends *xi ⊕ ai* and *Li,xi ⊕ai* to *B*.
5. *B* evaluates the circuit in topological order. For each gate *G* = (*i,j,k,T*), *B* initially holds (*zi ⊕ λi,Li,zi ⊕λi*) and (*zj ⊕ λj,Lj,zj ⊕λj*), where *zi,zj* are the underlying values of the wires.
(a) If *T* = *⊕*, *B* computes *zk⊕ λk*:= (*zi ⊕ λi*) *⊕* (*zj ⊕ λj*) and *Lk,zk ⊕λk*:= *Li,zi ⊕λi⊕ Lj,zj ⊕λj*.
(b) If *T* = *∧*, *B* computes *G₀* := *Gk,*0*⊕ dj*, *G₁* := *Gk,*1*⊕ di*, and evaluates the garbled table (*G₀,G₁*) to obtain the output label *Lk,zk ⊕λk*:= *H* ((*Li,zi ⊕λi*)*,k*) *⊕ H* (*Lj,zj ⊕λj,k ⊕* (*dk⊕ d*ˆ*k*)
*⊕*(*zi ⊕ λi*)*G₀ ⊕* (*zj ⊕ λj*)(*G₁ ⊕ Li,zi ⊕λi*)*.*

Then *B* computes

*b* *k⊕* ˆ *b* *k⊕* (*zi ⊕ λi*)*bj ⊕* (*zj ⊕ λj*)*bi ⊕* (*zi ⊕ λi*) *∧* (*zj ⊕ λj*) *⊕* ((*vk⊕ v*ˆ*k⊕* (*zi ⊕ λi*)*vj ⊕* (*zj ⊕ λj*)*vi*) *β* *−*1

*⊕ H* *′* (*Li,zi⊕λi*) *⊕ H* *′* (*Lj,zj⊕λj*) *⊕ G* *′k,* 0*⊕* (*zi ⊕ λi*)*G* *′k,* 1*⊕* (*zj ⊕ λj*)*G* *′k,* 2*β* *−*1

= *λk⊕ λ*ˆ*k⊕* (*zi ⊕ λi*)*λj ⊕* (*zj ⊕ λj*)*λi ⊕* (*zi ⊕ λi*) *∧* (*zj ⊕ λj*) = *λk⊕ zk*

6.For each *i ∈ O*, *A* sends *ai* to *B* and calls ΠLPZKto prove these values are <u>correct. B computes z</u>*i* <u>:= (λ</u>*i* <u>⊕ z</u>*i*<u>) ⊕ a</u>*i* <u>⊕ b</u>*i*<u>.</u>

<u>Fig. 10. Programmable OLE</u>
 Functionality *F*OLE
(*n,κ,p,q,Q*) : Programmable OLE over a field F₂*κ* and relations *Q*.

Parametrized by integers *n,p,q,κ ∈* N and a set of relations *Q ⊆ {*1*,...,p}×* *{*1*,...,q}*, i.e. elements *q ∈ Q* are ordered pairs of integers.

– *A* chooses a collection of vectors a¹*,...,*a *p* of length *n* and sends them to *F*OLE (*n,κ,p,q,Q*). – *B* chooses a collection of vectors b¹*,...,*b *q* of length *n* and sends them to *F*OLE (*n,κ,p,q,Q*). – For each entry *q* = (*i,j*) *∈ Q*, *F*OLE (*n,κ,p,q,Q*) chooses vectors v *q*, c *q* with v *q* + c *q* = a *i* *·* b *j*. <u>– FOLE</u> (*n,κ,Q*) <u>sends v</u> *q* <u>to A and c</u> *q* <u>to B, for all q ∈ Q.</u>

related to the task of minimizing *p* and *q* so that the protocol is concretely efficient, and we cover it in § 6.2.

For CDS, informally, *B* sends a message to *A* that allows *A* to learn a secret

|value s known to B if and only if B’s message satisfies a desired set of relations.|||
|---|---|---|
|Otherwise, A will compute a guess s|, which on at least one entry will appear||
|random to B. Then A appends H (s|) to all future messages to B, so that B||
|can recover the underlying message if and only if s||= s. We give a formal|

B *A* *A* *A B* definition of this functionality in Figure 11.

We give a protocol realizing this functionality in Figure 12, and prove its correctness in Appendix B.3. Our protocol works by first proving that *A* and *B* each have one input vector that is constant, and using that to realize instances of subfield VOLE over *A*’s input *α* and each of *B*’s input vectors b *i*. Write *Q* *′* := *Q ∪{*(*p* + 1*,j*)*}∪{*(*i,q* + 1)*}*, for 1 *≤ j ≤ q* + 1 and 1 *≤ i ≤ p*, and *Q* *′′* := *Q* *′* *∪{*(*p* + 1*,j}* for *j* = *q* + 2*,q* + 3*,q* + 4.

It is possible to move Step 6 to Step 2, making the protocol non-interactive, (*j,k*) since the values ˆ*ci*used in Step 6 can be computed locally by *B* from the output of the random *F*OLEfunctionality and *B*’s inputs. Step 6 is separated from Step 2 because the most complicated part of the protocol is in Steps 6 and 7, which are used to verify the relations in *R₂*. Removing Steps 6 and 7 and using *Q* *′* instead of *Q* *′′* gives a warm-up CDS protocol for certifying the relations in *R₁* only.

(*n,κ,p,q,Q,R*) Lemma 7. *The protocol in Figure* 12 *realizes the functionality F* CDS (*n,κ,p*+1*,q*+4*,Q* *′′* *,R*) *non-interactively in the RO-F* OLE *-hybrid model.*

<u>Fig. 11. Programmable OLE with conditional disclosure of secrets</u>

Functionality *F*CDS (*n,κ,p,q,Q,R*) : CDS for *F*OLE (*n,κ,p,q,Q*) over a field F₂*κ* and relations

*R*.
Parametrized by integers *n,κ,p,q, ∈* N, a set of relations *Q ⊆{*1*,...,p}×{*1*,...,q}*
as above, and a set of relations *R* = *R₁ ∪R₂*, where *R₁* is a collection of equality constraints *b* *j* *i*= *b* *ℓ* *k*, and *R₂* is a collection of quadratic relations of the form *b¹i· b¹j*= *b¹* *k*. Additionally, let m be a message that *A* plans to send to *B*.

– *A* and *B* interact with *F*CDSplaying the role of *F*OLEon *B*’s input vectors b *i* *∈* F *n* 2for 1 *≤ i ≤ q* and *A*’s input vectors a *i* *,* v *q* *∈* F *n* 2 *κ* for 1 *≤ i ≤ p* and *q ∈ Q*. – If the vectors b *i* satisfies the relations in *R*, *F*CDSsends m to *B*. – If any of the vectors b *i* do not satisfy the relations in *R*, *F*CDSsends a random <u>vector to B.</u>

6.2 Non-interactive authenticated circuit wires and authenticated garbling The remainder of the construction is similar to the construction given in Sec- tion 5. We give a brief overview here, and a more detailed description in the appendices. As discussed in 1.1, the randomness computation time and the seed size grow with the number of piece-wise products required, i.e. with *|Q|* using the notation in the functionality description. In order to minimize the numbers *p*, *q* required, we construct for *A* three vectors of inputs: a*,* a
*L*, a *R*, where a, chosen randomly, represents authenticated bits for all wires, a *L* represents only bit labels for wires used as labels for left inputs to multiplication gates, so that *a* *L* *k*is the left input to the *k*th multiplication gate, and a *R* likewise represents only bit labels for wires used as labels for right inputs to multiplication gates. We similarly define b*,* b *L* *,* b *R*. The full construction of the preprocessing func- tionality is similar to the protocol Πcp. We give this protocol and a proof of its correctness in Appendix B.4. The authenticated garbling functionality is also similar to the protocol Π VOLE 2pc used in the VOLE-only case, replacing *F*cpwith the NISC preprocessing func- tionality. Besides the first step of generating the preprocessing functionality, which is non-interactive by construction, the only message from *B* to *A* is given in Step 3, when *B* sends bit masks of its input values *yi⊕ bi*. This communica- tion can be moved to Step 1 with no loss of security, making the entire protocol non-interactive, which we prove in Appendix B.5.

Acknowledgements. Supported in part by DARPA Contract No. HR001120C0087. Any opinions, findings and conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of

<u>Fig. 12. Conditional disclosure of secrets</u>

Protocol ΠCDS: Conditional disclosure of secrets over programmable OLE.

Parametrized by integers *n,κ,p,q, ∈* N, a set of relations *Q ⊆{*1*,...,p}×{*1*,...,q}*
as above, and a set of relations *R* = *R₁ ∪R₂* as above. Additionally, let m be a message that *A* plans to send to *B*.

1. *A* and *B* choose random values *α,β ∈* F₂*κ* and define the vectors *α* :=
(*α,...,α*) and *β* := (*β,...,β*).
(*n,κ,p*+1*,q*+1*,Q′*) *p*+1 *q*+1

2. *A* and *B* invoke *F*OLE
with the additional inputs a := *α*, b := *β*. Let (m *iA* ) be the messages that *A* sends during the random-to-fixed OLE compiler, and let cˆ ( *ij,k* ) be the vectors held by *B* before receiving (m *iA* ).

3. *A* computes s¹*A*:= (*v₁*
(*p*+1*,q*+1) *− v₂* (*p*+1*,q*+1) *,...,v₁* (*p*+1*,q*+1) *− vn* (*p*+1*,q*+1) ).

4. *B* computes s¹*B*:= (*c*
(1*p*+1*,q*+1) *− c* (2*p*+1*,q*+1) *,...,c* (1*p*+1*,q*+1) *− c* ( *np* +1*,q*+1) ).

5.For each relation *b*
*j* *i*= *b* *ℓ* *k∈ R₁*, *A* appends *vi* (*p*+1*,j*) *− vk* (*p*+1*,ℓ*) to s²*A*and *B* appends *c* ( *ip* +1*,j*) *− ck* (*p*+1*,ℓ*) to s²*B*

6. *B* constructs three additional vectors, each of length equal to *|R₂|*, with b *q*+2 = (*b¹ic*ˆ
( *jp* +1*,*1) + (*b¹jc*ˆ ( *ip* +1*,*1) ), b *q*+3 = (*b¹ib¹j*), and b *q*+4 = ˆ*c* ( *kp* +1*,*1) for triples (*i,j,k*) *∈ R₂*, and both parties call Extend(*F*OLE),so that *A* and *B* now hold (*n,κ,p*+1*,q*+4*,Q′′*) *F*OLE.

7.For each relation *b¹i· b¹j*= *b¹k∈R₂*, let *r* be the index of this relation in *R₂*. *A* appends *vi*
(*p*+1*,*1) *· vj* (*p*+1*,*1) *− αvk* (*p*+1*,*1) *− vr* (*p*+1*,q*+2) *−* (*vr* (*p*+1*,q*+3) ) *·* (*m¹A,i*+ *m¹A,j*) *−* (*vr* (*p*+1*,q*+4) )*m¹A,k*to s³*A*, and *B* appends *c* ( *ip* +1*,*1) *· c* ( *jp* +1*,*1) *−* (*c* ( *rp* +1*,q*+3) ) *·* (*m¹A,i*+ *m¹A,j*) *−* (*c* ( *rp* +1*,q*+4) )*m¹A,k*to s³*B*.

8.Each party *P* computes s*P* := *∪i*s
*iP*.

9. *A* sends m₁ := m + *H*(s*A*) to *B*.
<u>10. B computes m₂ := m₁ + H(s</u>*B*<u>) and outputs m₂.</u>
DARPA. Y. Ishai supported in part by ERC Project NTSC (742754), BSF grant 2018393, and ISF grant 2774/20.

## References

1.Arash Afshar, Payman Mohassel, Benny Pinkas, and Ben Riva. Non-interactive secure computation based on cut-and-choose. In *Eurocrypt*, pages 387–404, 2014.
2.Donald Beaver. Efficient multiparty protocols using circuit randomization. In Joan Feigenbaum, editor, *CRYPTO ’91*, pages 420–432, 1991.
3.Elette Boyle, Geoffroy Couteau, Niv Gilboa, and Yuval Ishai. Compressing vector OLE. In *CCS 2018*, pages 896–912, 2018.
4.Elette Boyle, Geoffroy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, Peter Rindal, and Peter Scholl. Efficient two-round OT extension and silent non-interactive secure computation. In *CCS 2019*, pages 291–308, 2019.
5.Elette Boyle, Geoffroy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, and Peter Scholl. Efficient pseudorandom correlation generators: Silent OT extension and more. In *CRYPTO 2019, Part III*, pages 489–518, 2019.

6.Elette Boyle, Geoffroy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, and Peter Scholl. Efficient pseudorandom correlation generators from ring-lpn. In *Crypto* *2020*, pages 387–416, 2020.
7.Geoffroy Couteau, Peter Rindal, and Srinivasan Raghuraman. Silver: Silent VOLE and oblivious transfer from hardness of decoding structured LDPC codes. In *CRYPTO 2021*, pages 502–534. Springer, 2021.
8.SB Damelin, G Michalski, and Gary L Mullen. The cardinality of sets of k- independent vectors over finite fields. *Monatshefte f¨ur Mathematik*, 150(4):289–295,
2007.
9.SB Damelin, G Michalski, GL Mullen, and D Stone. The number of linearly independent binary vectors with applications to the construction of hypercubes and orthogonal arrays, pseudo (t, m, s)-nets and linear codes. *Monatshefte f¨ur* *Mathematik*, 141(4):277–288, 2004.
10.Ivan Damg˚ard, Valerio Pastro, Nigel P. Smart, and Sarah Zakarias. Multiparty computation from somewhat homomorphic encryption. In *CRYPTO*, 2012.
11.Sam Dittmer, Yuval Ishai, and Rafail Ostrovsky. Line-point zero knowledge and its applications. In *ITC 2021*, 2021. Full version:[https://eprint.iacr.org/2020/1446](https://eprint.iacr.org/2020/1446).
12.Yevgeniy Dodis and Sanjeev Khanna. Space-time tradeoffs for graph properties. In *ICALP 1999*, pages 291–300. Springer, 1999.
13.Yuval Ishai, Eyal Kushilevitz, Rafail Ostrovsky, Manoj Prabhakaran, and Amit Sahai. Efficient non-interactive secure computation. In *EUROCRYPT 2011*, pages 406–425, 2011.
14.Jonathan Katz, Samuel Ranellucci, Mike Rosulek, and Xiao Wang. Optimizing authenticated garbling for faster secure two-party computation. In *Crypto 2018*, pages 365–391. Springer, 2018.
15.Yehuda Lindell and Benny Pinkas. An efficient protocol for secure two-party com- putation in the presence of malicious adversaries. In *EUROCRYPT*, pages 52–78,
2007.
16.Payman Mohassel and Matthew K. Franklin. Efficiency tradeoffs for malicious two-party computation. In *PKC*, pages 458–473, 2006.
17.Mike Rosulek and Lawrence Roy. Three halves make a whole? beating the half- gates lower bound for garbled circuits. In *CRYPTO 2021*, pages 94–124, 2021.
18.Phillipp Schoppmann, Adri`a Gasc´on, Leonie Reichert, and Mariana Raykova. Dis- tributed vector-OLE: Improved constructions and implementation. In *CCS 2019*, pages 1055–1072, 2019.
19.Tamir Tassa and Jorge L Villar. On proper secrets, (*t,k*)-bases and linear codes. *Designs, Codes and Cryptography*, 52(2):129–154, 2009.
20.Xiao Wang, Samuel Ranellucci, and Jonathan Katz. Authenticated garbling and efficient maliciously secure two-party computation. In *CCS 2017*, pages 21–37,
2017.
21.Kang Yang, Pratik Sarkar, Chenkai Weng, and Xiao Wang. Quicksilver: Efficient and affordable zero-knowledge proofs for circuits and polynomials over any field. In *CCS*, 2021. Full version:[https://eprint.iacr.org/2021/076](https://eprint.iacr.org/2021/076).
22.Kang Yang, Chenkai Weng, Xiao Lan, Jiang Zhang, and Xiao Wang. Ferret: Fast extension for correlated OT with small communication. In *CCS ’20*, pages 1607– 1626, 2020.
23.Andrew Chi-Chih Yao. How to generate and exchange secrets (extended abstract). In *FOCS*, pages 162–167, 1986.
24.Samee Zahur, Mike Rosulek, and David Evans. Two halves make a whole. In *Eurocrypt 2015*, pages 220–250, 2015.

## A Supplemental: Additional certification protocols

A.1 Certification between VOLE instances and authenticated triples We give a lightweight protocol for establishing that the parameter *α* for an instance of VOLE matches the parameter *α* from an authenticated triple.
<u>Fig. 13. Certification between authenticated triples and VOLE</u>
 Protocol Π
DAMT cert *∧*VOLE : The certification that a value *α* is consistent across a call to *F*DAMTand a call to *F*VOLE.

Inputs are the functionalities *F*DAMT, *F*VOLE, equipped with the operation Extend, and party *A*’s inputs *α,α* *′* to *F*DAMT*, F*VOLE, respectively.

1.Both parties call Extend(*F*DAMT) so that the parties learn (*xA,*1*,xA,*2) and (*xB,*1*,xB,*2), *A* and *B*’s respective shares of (*x,αx*) from a fresh two-sided authenticated triple.
2.Both parties call Extend(*F*subVOLE) so that *B* learns (*a,b*) and *A* learns *v* := *aα* *′* + *b* generated by the VOLE.
3. *B* sends *xB,*1 *− a* to *A*, so that *A* now holds *v*
*′* := *xB,*1*α* *′* + *b*.

4. *A* computes
*m* := *H*(*v* *′* + *xA,*1*α* *′* *− xA,*2) to *B*.

<u>5. B verifies that m = H(x</u>*B,*2 <u>+ b) and otherwise aborts.</u>

|(ρ,n₁)|ρ,n₂|(ρ,n₁+1)|ρ,n₂+1|
|---|---|---|---|
|DAMT|VOLE|DAMT|VOLE|

Lemma 8. *F ∧α,α,*F2*ρF is realizable in the F −F-hybrid* *model.*

*Proof.* Let (*x*

|,x|) and (x|,x ) be A and B’s respective shares of (x,αx)|||
|---|---|---|---|---|
|A,1 A,2|B,1|B,2|||
|||||′|
||B,1||′|B,1 ′|
|′ ′||′|||
|A,1|A,2|A,2|B,2||

from a two-sided authenticated triple, and let *B* hold (*a,b*) and *A* hold *α,v* := *aα* *′* +*b* generated by the VOLE. Using the standard compiler from random VOLE to fixed VOLE, *B* sends *x − a* to *A*, so that *A* now holds *v* := *x α* + *b*. Then *A* computes

*v* + *x α − x* = *xα − x* + *b* = *x*(*α* *′* *− α*) + *x* + *b,*

applies a cryptographic hash function *H* to the result, and sends this to *B*. Now *B* compares this value to *H*(*xB,*2+*b*), which they can compute locally, and aborts if the values are not equal. Otherwise they continue with *F*VOLEand *F*DAMT. For security against a malicious *B*, note that if an adversary *A* corrupts *B*, a simulator *S* can simulate the message they receive from *A* as a random value

from F₂*κ*, by the security of *H*, and if *A* sends the correct information, the simulator simply outputs *H*(*xB,*2+ *b*). Security against a malicious *A* follows from the security of the random VOLE to fixed VOLE compiler, and because the randomness of *b* guarantees that a simulator *S* can generate *v* *′* uniformly at random and match the distribution under the real world protocol execution. Finally, if a malicious *A* has *α* *′* *̸*= *α*, guessing *H*(*xB,*2+ *b*) is equivalent to guessing *x*, which *A* can only do with negligible probability, and so the ideal world and real world abort probabilities are equal up to a negligible term.

A.2 Certification across VOLEs with reversed sender and receiver Our second protocol is used to certify that a party playing the role of both VOLE receiver and VOLE sender uses the same value in both protocols.
<u>Fig. 14. Certified across VOLEs with reversed sender and receiver</u>
 Protocol Π
VOLE cert *∧*ELOV : The certification that a value *α* is consistent across two calls to *F*VOLEwith roles of sender and receiver reversed.

Inputs are the functionalities *F*VOLE, *F*ELOV, equipped with the operation Extend, and party *B*’s inputs *β,β* *′* to *F*VOLE*, F*ELOV, respectively.

1.Both parties call Extend(*F*VOLE) so that *A* learns *a,c* and *B* learns *w* := *aβ* + *c*.
2.Both parties call Extend(*F*ELOV) so that *B* holds (*β*
*′* *,d*) and *A* learns *v* := *β* *′* *α*+*d*.

3. *A* chooses a random value *e* and sends (*m₁,m₂*) := (*α − a,v* + *e*) to *B*.
4. *B* computes *m₃* := *H*(*w* + *m₁β* + *d − m₂*) to *A*.
<u>5. A verifies that m₃ = H(c − e) and otherwise aborts.</u>

|(ρ,n₁)||ρ,n₂|(ρ,n₁+1)|ρ,n₂+1|
|---|---|---|---|---|
|VOLE|α,a ,F|ELOV|VOLE|ELOV|
|||′|||

Lemma 9. *F ∧*1 2*ρF is realizable in the F −F-hybrid* *model.*

*Proof.* Suppose *A* holds the values *a,c,v* := *β* *′* *α* + *d* and *B* holds the values *β* *′* *,d,w* := *aβ*+*c*, where the values *a,c,α,β* are chosen uniformly at random, and *B* wishes to convince *A* that *β* = *β*. Then *A* chooses some random value *e* and sends *m₁* := (*α − a*) and *m₂* = *v* + *e* to *B*. *B* computes *w* +*m₁β* +*d − m₂* = *c − e*, and sends *m₃* = *H*(*c − e*) to *A*. *A* verifies that *m₃* = *H*(*c − e*), and otherwise aborts. If *A* does not abort, both parties continue evaluating the *F*VOLEand *F*ELOVfunctionalities. For security against a malicious *A*, the simulator outputs a random message for *m₃* when *A* cheats in its message for *m₁*, and otherwise outputs the correct value of *H*(*c − e*), where it computes *e* as *m₂ − v*, where *m₂* is output by *A*.

When *A* cheats in *m₁*, the value of *m₃* is equal to *H* ((*m₁* + *a − α*)*β* + *c − e*), and so appears random to *A*, since the value of *β* is random. For security against a malicious *B*, the randomness of *a* and *e* ensures that a simulator *S* can generate the messages *m₁,m₂* uniformly at random and match the distribution under the real world protocol execution. Additionally, if an adversary *A* has *β* *′* *̸*= *β*, then *w* + *m₁β* + *d − m₂* = *α*(*β − β* *′* ) + (*c − e*), and so guessing *H*(*c−e*) is equivalent to guessing *α*, which *A* can only do with negligible probability, and so the ideal world and real world abort probabilities are equal up to a negligible term.

A.3 Certification between subfield VOLE and interactively generated subfield VOLE
Fig. 15. Certification of senders’ inputs between subVOLE instances with distinct
 <u>parameters ρ,κ</u> Protocol Π
*ρ* cert *∧κ* : The certification that a value *b* is consistent across two distinct calls to *F*subVOLE, which may be generated non-silently.

Inputs are the functionalities *F*subVOLE *ρ*, *F*subVOLE *κ*, *F*VOLE, equipped with the operation Extend, party *A*’s inputs *α,∆A*, and party *B*’s inputs b₁*,*b₂, where we desire to certify that b₁ = b₂. Assume *ρ* divides *κ* for simplicity.

1.The parties *A* and *B* call Extend(*F*subVOLE) twice, using the correlation calculus so that *B*’s inputs match across both instances, so that *B* holds b₃ *∈* F, d₃ *∈* F₂*ρ* and d₄ *∈* F₂*κ*, and *A* holds v₃ := b₃*α* + d₃, v₄ := b₃*∆A* + d₄.
2. *B* sends m₁ := b₁ *−* b₃ to *A*.
3. *A* adds v₃ *←* v₃ + m₁*α* and v₄ *←* v₄ *←* v₄ + m₁*∆A*.
4. *B* computes *m₂* = *H*(d₁ *−* d₃; d₂ *−* d₄) and sends to *A*.
<u>5. A aborts if m₂</u> *̸*<u>= H(v₁ − v₃; v₂ − v₄).</u> We note that this protocol is necessary only in the particular setting where
*A* and *B* generate an instance of fixed *F*subVOLEusing some optimized proto- col, rather than the generic compiler from random to fixed VOLE, and so the “correlation calculus” cannot be used to ensure that the fixed *F*subVOLEoutputs match. We obtain the desired certification simply by replacing these artifically generated instances of *F*subVOLEwith fresh instances that are generated with the same vector b₃.

|(ρ,n)||(κ,n)|(ρ,2n)|(κ,2n)|
|---|---|---|---|---|
|subVOLE A|b ,b ,F|subVOLE|subVOLE|subVOLE|

Lemma 10. *F ∧*1 2 2*F is realizable in the RO-F-F-* *hybrid model under the “correlation calculus” with O*(*κ*) *bits of communication* *when A’s inputs α,∆ are chosen uniformly at random.*

*Proof.* Correctness follows because, if *A* and *B* follow the protocl, each of v*i*, for *i* = 1*,*2*,*3*,*4, is of the form v*i*= b₁*α*+ d*i*or b₁*∆A*+ d*i*, so that v₁*−*v₃ = d₁*−*d₃ and v₂ *−*v₄ = d₂ *−*d₄. *A* sends no messages in the protocol, so security against a malicious *A* follows from the security of the underlying correlated randomness functionalities. Security against a malicious *B* follows because the vector m₁ is distributed uniformly at random under an honest run of the protocol, by the randomness of b₃, and so a simulator for an adversary *A* simply generates m₁ uniformly at random and computes *m₂* from m₁.

## B Deferred proofs

B.1 proof of Lemma 4 Completeness. When both parties are honest, in Step 13 we have

|ˆb := (ˆ v + ˆ|c + v + c|) β|+ b b|
|---|---|---|---|
|i i|i i,4|i,4|i j|
|i j|i j j|i i j|i|

*i i i i,*4 *i,*4 *−*1 *i j* = *a a* + *a b* + *a b* + *b b* + ˆ*a*

and

*d* ˆ *i*:= (*vi,*2+ *ci,*2+ *vi,*3+ *ci,*3+ *vi,*5+ *ci,*5)*β* *−*1 + *di,j* = (*ai j i j j i i i,*2 *i,j*

|a + a b + a|b + ˆ a )α + ˆ|a + d|,|
|---|---|---|---|
|i j i j|j i i|i,2|i,j|
|i|i,2|i,j i|i|

respectively, so that *A* holds *w*ˆ := ˆ*a* + *w* = ˆ*b α* + *d*ˆ*,* as desired. Security. Most of the communication in this protocol involves compilers to fixed VOLE and subfield VOLE from random VOLE and subfield VOLE that only touch the linear terms (that is, the *a* term in *aβ* + *c*, not the *c* term), and so appear uni- formly random by the randomness of each *c* term. Because of the certification of inputs, *B* has no space to cheat that will not be detected by *A* with overwhelm- ing probability, and the only place *A* can cheat is in the messages *mi,*1:= ˆ*ci*+*ci,*4 and *mi,*2:= *ci,*2+ *ci,*3+ *ci,*5*.* For security against a malicious *A*, in the ideal world if *A* cheats on any messages *mi,*1by sending *mi,*1*∗*, the simulator *S* aborts. In the real world, *B* computes ˆ*b* *∗* *i*= ˆ*bi*+ (*m* *∗* *i,*1*− mi,*1)*β* *−*1, and aborts unless this lies in *{*0*,*1*}*, which happens with negligible probability, since it only happens if *A* guesses *β*. If *A* cheats on *mi,*2by sending instead (*m* *∗* *i,*2) the simulator *S* records the message (Cheat*,* m *∗* ), where m *∗* = (*mi,*2*− m* *∗* *i,*2), and sends *A* the vector wˆ + m *∗* *β* *−*1. In the real world, let (ˆ*bi, d*ˆ *∗* *i* ) be the values computed by *B* when *A* sends (*mi,*1*, m*ˆ*i,*2). Then *A* can compute

*a*ˆ*i,*2+ *wi,j*= ˆ*biα* + *d*ˆ*i*= ˆ*biα* + *d*ˆ *∗* *i*+ (*mi,*2*− m* *∗* *i,*2)*β* *−*1 = *w*ˆ*i∗*+ *m* *∗* *i* *β* *−*1

and so *A*’s view in the ideal world and real world are indistinguishable. Note that when *A* holds *wi∗*:= ˆ*biα* + *d*ˆ *∗* *i*+ *m* *∗* *i* *β* *−*1 and *B* holds ˆ*bi, d*ˆ *∗* *i*, *A* has a negligible

probability of sending some false *wi∗*+ *s* to *B* and convincing *B* that *m* *∗* *i*= 0, since this is equivalent to guessing *β*. We use this in the proof of Lemma 6. For security against a malicious *B*, as noted above the abort probabilities in the ideal world and real world are identical. In the ideal world, a simulator *S* chooses all values *v*ˆ*i*and *vi,j*uniformly at random except for *v*ˆ*i*and *vi,*2, and chooses the values *mi,*1 *i,*2 *i i*

|,m|, ˆb, dˆ|uniformly at random.|||
|---|---|---|---|---|
|i,1|i,2 i|i|||
|i i,5|i|i j|i,2|i i,j|

Then *S* computes ˆ*v* = (ˆ*b − b b*)*β − mi,*1*− vi,*4and *v* := (*d*ˆ *− d*)*β −* *mi,*2*− vi,*3*− v*.

B.2 Proof of Lemma 6 *Proof.* Completeness. The computation of *Lk,zk⊕λk*is unaltered from [14]. The correctness of the computation of *λk⊕ zk*follows from expanding the expression in Step 5(b) of the protocol for each of the four possible values of (*λi⊕zi,λj⊕zj*). Security against a malicious *A*. If *A* cheats during *F*cp, then the computation of *Lk,zk⊕λk*will be off by the value *m*
*∗* *k* *β* *−*1, and *A* has only a negligible probability of successfully offsetting this with suitable adjustments to *Gk,*0*,Gk,*1. Thus *B* will abort with overwhelming probability, and *A* learns nothing. The only messages *A* receives during the protocol are in the compiler to (*C,ρ,κ*) *F*cpand in step 3 and 4, along with a message *⊥* if *B* aborts. Let *A* be an adversary corrupting *A*. A simulator *S* can match the real world view of *A* on steps 3 and 4 by choosing random bits in steps 3 and 4, and the security of step 1 is established by Lemma 4. Learning whether or not *B* aborts is equivalent to corrupting some subset of *t* table entries (by corrupting the messages *Gi,j*or *G* *′i,j* ), and learning whether *B* opened *any* of those table entries during circuit evaluation. If the *t* table entries chosen correspond to rows of *MH*that are linearly independent, then the labels *MH*e*b* are independent, and *A*’s view can be simulated as the logical conjunction of *t* random values. Therefore we restrict our attention to the case where the *t* entries correspond to linearly dependent rows of *MH*. To treat this case, we recall the notion of (*t,k*)-independent sets (the concept was first introduced in [12], see [19] for a thorough treatment, and [9,8] for additional discussion). A (*t,k*)-independent set over F*q*is a subset of F *k* *q*such that no *t* + 1 element subset is linearly dependent. For our purposes, it is sufficient to construct a (*ρ −*1*,L*)-independent set B *⊆* F *L* 2such that *|*B*|* = *n* via a randomized algorithm. If we generate *n* uniformly random vectors from F *L* 2, and let *R* be a random variable denoting the number of relations on B with at most *ρ* elements. We then have X *ρ* *n* E[*R*] *≤* ( <u>1</u> 2 ) *L* *k* *k*=1 by linearity of expectation, and so by Markov’s inequality we have

<u>(ρ + 1)n</u> *ρ* Pr[*R≥* 1] *≤* *L* *,*

(*ρ*)!2

and taking <u>ρlog n − ρlogρ</u> *L* = + 2*ρ* log 2 and by Stirling’s approximation, this gives

Pr[*R* = 0] *≥* 1 *−* 2 *−ρ* *.*

Thus if the *t* entries chosen above correspond to linearly dependent rows of *MH*, we have *t ≥ ρ*. The probability that corrupting *ρ* independent random table entries causes an abort is equal to 1 *−* 2 *−ρ*, and so with *t ≥ ρ*, *B* aborts except with negligible probability, and again *A* learns nothing. Formally, a simulator *S* aborts with probability 1*−*2 *−t* for *t < ρ*, and aborts with probability 1 otherwise, and the view of *A* interacting with *S* is indistinguishable from the real world execution in both cases. Security against a malicious *B*. The proof here is similar to the proof in [14]. When a simulator *S* acts as an honest *A* with input *x* = 0, the view of an adversary *A* corrupting *B* is identical to the view of *A* when *A* uses their actual input, by the security of *H* and *H* *′*. Similarly, because the wire values *ak*are still drawn from a uniformly inde- pendent distribution, *A*’s view of *λk⊕ zk*is uniformly random, whether *x* = 0 or *x* is *A*’s actual input.

B.3 Proof of Lemma 7 Correctness. When both parties are honest we have (*p*+1*,q*+1) (*p*+1*,q*+1)

|1|(p+1,q+1)|(p+1,q+1)|1|
|---|---|---|---|
|A,i−1|i|i|B,i−1|
 *s* := *v₁ − v* = *αβ* +*c₁ −* (*αβ* + *c*) = *s,* and 2 (*p*+1*,j*) (*p*+1*,ℓ*) *ji* (*p*+1*,j*) *ℓk* (*p*+1*,ℓ*) 1 *s* *A,r*:= *vi− vk*= *αb* + *ci−* (*αb* + *ck*) = *sB,r,* as desired. For the relation *b¹i· b¹j*= *b¹k*, the calculation is more involved, but similar: 3 (*p*+1*,*1) (*p*+1*,*1) (*p*+1*,*1) (*p*+1*,q*+2) *s* *A,r*:= *vi· vj−αvk− vr*
*−*(*vr* (*p*+1*,q*+3) ) *·* (*m¹A,i*+ *m¹A,j*) *−* (*vr* (*p*+1*,q*+4) )*m¹A,k* 2 (*p*+1*,*1) (*p*+1*,*1) (*p*+1*,*1) = *α* (*bibj− bk*) + (*cibj*+ *cjbi− c* *k* *−b* ( *rq* +2) *−b* ( *rq* +3) (*m¹A,i*+ *m¹A,j*) *− b* ( *rq* +4) *m¹A,k*)*α* (*p*+1*,*1) (*p*+1*,*1) ( +1*,q*+3) 1 1 ( +1*,q*+4) 1 +*ci·cj−* (*crp*) *·* (*mA,i*+ *mA,j*) *−* (*crp*)*mA,k* (*p*+1*,*1) (*p*+1*,*1) ( +1*,q*+3) 1 1 ( +1*,q*+4) 1 = *ci· cj−*(*crp*) *·* (*mA,i*+ *mA,j*) *−* (*crp*)*mA,k*

= *s³B,r.*

Security against malicious *A*. Party *A* receives no messages from *B* during the protocol besides the compiler from random to fixed *F*OLEin Steps 2 and 6,

and whether or not *B* aborts. Recall that the message in Step 6 can be moved to Step 2, preserving non-interactivity. The messages in Steps 2 and 6 can be simulated as uniformly random vectors, by the security of the random to fixed *F*OLEcompiler. Assume that *B* aborts whenever *sA̸*= *sB*, and instruct the simulator *S* to construct the correct message s *′A*, and abort if the vector a *p*+1 *̸*= *α* or if s *′A* *̸*= s*A*. *p*+1 *∗*

|If a|̸= α, then a|:= a|− a||̸= 0 for some index i > 1. But then|||
|---|---|---|---|---|---|---|---|
|||i|1+1|i +1||||
|(p+1,q+1) p+1|(p+1,q+1) i ′A|∗ i κ|(p+1,q+1) (p+1,j) i||(p+1,q+1) i|κ||
||B|||||||

*i* *p* 1+1 *p* *i* +1 (*p*+1*,q*+1) (*p*+1*,q*+1) *∗* (*p*+1*,q*+1) (*p*+1*,q*+1) *c₁ − c* = *a β* + *v₁ − v*, which *A* can guess only with probability 1*/*2, and so *B* will abort with probability 1 *−* 1*/*2 while *S* aborts with probability 1. If a = *α*, then all terms *c* will be computed correctly by *b*, and so we have s = s, by the correctness of the protocol. Therefore the probability that *S* aborts is computationally indistinguishable from the probability that *B* aborts during a real world execution of the protocol, and a cheating *A* is detected with overwhelming probability. Security against malicious *B*. We construct a simulator *S* that has access to the intended message m in the ideal world setting. *S* generates (m *iA* ) uniformly at random, computes *H*(s*B*), and outputs m₁ = m + *H*(s*B*) if *B* follows the protocol honestly, and a random message otherwise. The distribution of (m *iA* ) matches the distribution under a real world execution of the protocol by the correctness of *F*.

|OLE|||
|---|---|---|
|q+1|∗ i|q q 1+1 i +1|
|(p+1,q+1)|∗ (p+1,q+1)|(p+1,q+1)|
|i|i|i|
|κ|B,i−1|A,i−1|
|ji ℓk|(p+1,j) i|(p+1,ℓ) k|
|i j k||B,r|
|||q+i|
|B||A|

As above, if b *̸*= *β*, then *b* := *b − b ̸*= 0 for some index *i >* 1. But (*p*+1*,q*+1) then *v₁ −v* = *b α*+*c₁ −c*, which *B* can guess only with probability 1*/*2, and so *s ̸*= *s* with overwhelming probability. Similarly, if *b ̸*= *b*, the value *v − v* will be off by some multiple of *α*, and if *b¹b¹ ̸*= *b¹*, then the expression *s³* will be off by some multiple of *α²* (and a possibly additional multiple of *α*). Finally, if *B* has inputs that satisfy the relations *R*, but cheats on the values b, for *i ∈{*2*,*3*,*4*}*, then in Step 7, *B* will hold some linear expression in *α*, whose coefficients *B* can compute. Then the expression *H*(s) will not be equal *H*(s) with overwhelming probability if the coefficient of *α* in this expression is nonzero. In the ideal world execution, the simulator *S* can likewise compute the coefficients of this linear expression from the adversary’s messages and the randomly generated (m *iA* ), and outputs a random string for m₂ if and only if the coefficient of *α* is nonzero.

B.4 Non-interactive circuit wires from programmable OLE
(*C,ρ,κ*) We define a modified form of the functionality *F*pre, replacing the last line (*C,ρ,κ*) of *F*prewith the last four lines of *F*cp, and call it *F* pre*−*wbc, preprocessing with blind cheating. In other words, as in *F*cp, we allow party *A* to cheat in such a way that is not immediately detected, but leaves *A* with corrupted shares that cannot be used as shares of ˆ*ai∆A*. We give the protocol realizing this functionality in Figure 16. The proof of correctness is similar to the proof for our VOLE-based protocol. Here we give a careful accounting of the total communication cost.

The CDS protocol requires an additional *κn* bits of communication for *A* and an additional 3*|R₂|κ* bits for *B*. The relations we need to verify on *B*’s inputs are b*L· β* = b*Lβ*, b*R· β* = b*Rβ*, and b*L·* b*Rβ* = *bibjβ*, so the cost of CDS is equal to 9*κn* bits of communication for *B*. We can use *A*’s constant value from ΠCDSas *∆A*, and the values *ai,*2can be chosen uniformly at random over F₂*κ*, but the remainder of *A*’s inputs require communication, giving an additional 10*κ* bits of communication for *A*. Similarly *B* requires another 7*κ* bits of communication. This gives 11*κ* bits of communication for *A* and 16*κ* bits of communication for *B*. Adding in the 2*κ* + 3*ρ* bits of communication for *A* in the garbled circuit gives total communication of 13*κ* + 3*ρ* bits for *A* and 16*κ* bits for *B*.

B.5 Non-interactive authenticated garbling We only make two changes from Π
VOLE 2pcto give the garbling protocol Π NISC 2pc. First, we replace Πcpwith Π nisc pre(*C,ρ,κ*) in Step 1. Second, we move the communication in Step 3 to Step 1. The correctness and non-interactivity of Π nisc prefollows from the previous sub- section. Moving *B*’s message earlier does nothing to help a malicious *B*, so secu- rity against *B* still holds. What remains is to verify security against a malicious

*A*. The proof of security is very close to the proof of security in [14]. Essentially, we notice that the proof does not anywhere require Step 3 to occur after Step 2, and so everything goes through after re-ordering. We give the formal proof below for completeness. First, we note that, if *λi⊕ zi*and *λj⊕ zj*are correct, the expression in 5(*b*) will either be equal to *λk⊕ zk*or *λk⊕ zk⊕ β*
*−*1 *x* *∗*, for some value *x* *∗*. Therefore either *B* aborts or *B* outputs *f* (*x,y*) with overwhelming probability. Next, let *A* be an adversary corrupting *A*. We construct a simulator *S* that runs *A* as a subroutine and plays the role of *A* in the ideal world involving an ideal functionality *F* evaluating *f*. *S* is defined as follows. (*C,ρ,κ*) (*C,ρ,κ*) – Step 1. *S* plays the role of *F* pre*−*wbc and records all values that *F* pre*−*wbc sends to both parties. – Step 3. (re-ordered) *S* acts as an honest *B* using *y* := 0. – Step 2. *S* receives *A*’s messages. – Step 4. *S* receives *A*’s message *x*ˆ*i*and computes *xi*:= ˆ*xi⊕ ai*, where *ai*is (*C,ρ,κ*) the value used by *F* pre*−*wbc previously. – Steps 5-6. *S* acts as an honest *B*, and aborts if *B* would abort, and otherwise sends *x* to *F*.

We show that the joint distribution on the outputs of *A* and an honest *B* in the real world execution is indistinguishable from the joint distribution on the outputs of *A* and *S* in an ideal world execution, through a series of hybrid model protocols.

<u>Fig. 16. Non-interactive authenticated wire labels from programmable OLE</u>

Protocol Π nisc pre(*C,ρ,κ*): Non-interactive pre-processing of wire labels for authenticated garbling from programmable OLE.

Parametrized by the value *ρ*, and a circuit *C* consisting of *W* wires, *I* input wires, *O* output wires, and gates *G* of the form (*i,j,k,T*)*,* for *T ∈{∧, ⊕}*, *i,j ∈I∪W*, and *k ∈W∪O*. Let *n* be the number of AND gates.

1.The parties invoke a Π
(CDS *n,κ,*11*,*7*,Q,R*) functionality, where *A*’s inputs are (*∆A,* a*,* a*L,* a*R,* (*aiaj*)*,* aˆ*,∆A*a*,∆A*a*L,∆A*a*R,∆A*(*aiaj*)*,∆A*aˆ*,* (*ai,*2)) and *B*’s in- puts are the set (b + *γ,*b*L* +*γ,*b*R* +*γ,*b*Lβ* +*γ,*b*Rβ* +*γ,bibj β* +*γ, β, γ*). The correspondence between *A* inputs and *B* inputs given by *Q* arise in the protocol description. The relations *R₁* are the permutations required to construct b*L* and b*R*. The relations *R₂* are the product relations on *bi,bj,β*.

2. *A* and *B* store the resulting value s and add *H*(s) to all subsequent messages.
3.Party *B* computes ˆ*vi,vi,*2 as in Πcp, and computes
*v* *i,*3 := ˆ*ai∆Aβ* + *ci,*3

*v* *i,*4 := (*aiaj* + *aibj* + *aj bi* + *bibj*)*β* + *ci,*4 *v* *i,*5 := (*aiaj* + *aibj* + *aj bi* + *bibj*)*∆Aβ* + *ci,*5

4. *A* and *B* construct as entries of OLE:
*ui* = *∆A*(*bi* + *γ*) + *ei*

and *u* *′i* = *∆A*(*γ*) + *e* *′i* *,*

The parties then take *wi* = *ei* + *e* *′i* and *di* = *ui* + *u* *′i* in *F*pre (*C,ρ,κ*). The value *wi,j* := *bibj ∆Aβ* + *di,j* is computed similarly.

5.As in Πcp, *A* sends the messages ˆ*ci* + *ci,*4 and *ci,*2 + *ci,*3 + *ci,*5 to *B* to open ˆ *b* *i* *, d*ˆ*i* to *B*, and *A* can locally compute *w*ˆ*i*.
6.The parties produce entries of OLE corresponding to secret shares of the prod- uct of each of *aiaj,∆Aai,∆Aaiaj,∆Aa*ˆ*i* with *β*.
7.Treating the resulting secret sharing as a realization of VOLE, *A* and *B* invoke ΠLPZKto verify that the terms *aiaj,∆Aai,∆Aaiaj,∆Aa*ˆ*i* have been computed <u>correctly.</u>

Hybrid-1. *S* plays the role of an honest *B*, using *B*’s input *y*, and also plays (*C,ρ,κ*) the role of *F* pre*−*wbc. Hybrid-2. *S* plays the role of an honest *B*, using *B*’s input (*C,ρ,κ*) *y*, and also plays the role of *F* pre*−*wbc, in steps 1-3. In step 4, *S* extracts the value *xi*:= *x*ˆ*i⊕ ai*, and then aborts if *B* would abort and otherwise sends *x* to *F*. Hybrid-3. *S* follows the ideal-world setting laid out above. There is no difference in *A*’s view between Hybrid-1 and Hybrid-2, because *S* aborts in both cases if *B* would abort, and as noted above, if *B* fails to abort, it will necessarily output *f* (*x,y*), which is also what is output by Hybrid-2. The only difference between Hybrid-2 and Hybrid-3 is that *S* sets *y* := 0, but the values *yi⊕ bi*= *bi*will still appear totally random to *A*. All of *B*’s calculations in steps 5 and 6 do not depend on *y*, only on the values *yi⊕ bi*and *z* *i* *⊕ λi*, so that whether or not *B* aborts is not affected by which scenario we are in, and *A* will be unable to distinguish between Hybrid-2 and Hybrid-3. This completes the proof.

## C Formalization of the correlation calculus
