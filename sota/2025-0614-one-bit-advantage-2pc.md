# Highly Efficient Actively Secure Two-Party Computation with One-Bit Advantage Bound

Yi Liu¹, Junzuo Lai¹, Peng Yang², Anjia Yang¹, Qi Wang³, Siu-Ming Yiu², and Jian Weng¹

1 College of Cyber Security, Jinan University, Guangzhou 510632, China liuyi@jnu.edu.cn, laijunzuo@gmail.com, anjiayang@gmail.com, cryptjweng@gmail.com 2 Department of Computer Science, The University of Hong Kong, Hong Kong SAR, China stuyangpeng@gmail.com, smyiu@cs.hku.hk 3 Department of Computer Science and Engineering & National Center for Applied Mathematics Shenzhen, Southern University of Science and Technology, Shenzhen 518055, China wangqi@sustech.edu.cn

Abstract. Secure two-party computation (2PC) enables two parties to jointly evaluate a func- tion while maintaining input privacy. Despite recent significant progress, a notable efficiency gap remains between actively secure and passively secure protocols. In S&P’12, Huang, Katz, and Evans formalized the notion of *active security with one-bit leakage*, providing a promising approach to bridging this gap. Protocols derived from this notion have become foundational in designing highly efficient actively secure 2PC protocols. However, a critical challenge identified by Huang, Katz, and Evans remains unexplored: these protocols face significant weaknesses in ensuring fairness for honest parties when employed in standalone settings rather than as components within larger protocols. While the authors proposed two potential solutions to mit- igate this issue, both approaches are prohibitively expensive and lack formalization of security guarantees. In this paper, we first formally define an enhanced notion called *active security with one-bit-* *advantage bound*, in which the adversaries’ advantages are strictly bounded to at most one bit beyond what honest parties obtain. This bound is enforced through a *progressive revela-* *tion* mechanism, where the evaluation result is disclosed incrementally bit by bit. In addition, we propose a novel approach leveraging label structures within garbled circuits to design a highly efficient constant-round 2PC protocol that achieves active security with one-bit advan- tage bound. Our protocol demonstrates *runtime performance nearly identical to that of passively* *secure garbled-circuit counterparts* in duplex networks (*e*.*g*., 1*.*033*×* for the SHA256 circuit in LAN), with *low overhead* for output progressive revelation (only 80 communicated bytes per bit release). With its strengthened security guarantees and minimal overhead, our protocol is highly suitable for practical 2PC applications.

## 1 Introduction

Secure two-party computation (2PC) [36] allows two mutually distrusting parties to jointly evaluate a function on their inputs while preserving input privacy. Based on garbled circuits [37,4], 2PC protocols for arbitrary (efficiently computable) functions can be realized in a constant number of rounds. Over the past four decades, this kind of 2PC protocols has achieved substantial improvements in both communication [2,29,24,38,32] and computation [3,15,14], leading to their broad adoption in a range of applications, either on their own or as fundamental building blocks. Despite these advancements, a *significant efficiency gap* remains between actively secure (a.k.a. malicious) and passively secure (a.k.a. semi-honest) 2PC protocols. From the perspective of communi- cation, the size of garbled circuits for passive security settings recently has been reduced from 2*κ* bits per AND gate (using the half-gates scheme [38]) to 1*.*5*κ*+ 5 bits (using the three-halves scheme [32]). However, even with recent progress in constant-round actively secure 2PC [34,22,35,10,7], the lat- est protocol [7] has only reached 2*κ* + 5 bits per AND gate for one-way communication. 4 From a

4 The two-way communication cost of this protocol is 4*κ* + 10 bits per AND gate. In duplex networks, we can only consider one-way communication cost. Though approaches like the GMW compiler [12,1] could potentially close this communication gap, their computational overheads are prohibitively high.

computational standpoint, recent actively secure protocols [10,7] are notably complex and thus *no* implementations are currently available. While they theoretically achieve communication overhead comparable with passively secure 2PC using the earlier half-gates scheme, it remains to be exper- imentally verified whether the overall runtime benefits from the added complicated components in the protocol, as many of these introduce significant overhead. Existing implementations [34,18,35] demonstrate that passively secure 2PC protocols are still at least an order of magnitude faster than actively secure protocols for small circuits (*e*.*g*., SHA-256). This gap is likely to be widened even further for larger circuits, where components such as oblivious transfer (OT) account for a smaller fraction of total runtime. The notion of *active security with one-bit leakage* [27,19,23,17,26,39] offers a promising approach to bridging the efficiency gap between passive and active security in constant-round 2PC. Originally introduced by Mohassel and Franklin [27] and later formalized by Huang, Katz, and Evans [19], this security model guarantees that *the adversary is limited to learning at most one additional bit of* *information about the honest party’s input beyond the evaluation result, while output correctness is* *preserved*. Huang, Katz, and Evans developed a framework for designing actively secure 2PC protocols with one-bit leakage based on garbled circuits, referred to in this paper as *the HKE framework*. This is the most common framework for designing one-bit-leakage protocols. By applying this framework to the state-of-the-art garbling scheme, we could obtain a *highly efficient* actively secure 2PC proto- col with one-bit leakage, with runtime *very close* to that of its passively secure counterpart. Thus, although a single bit of extra information may be revealed to the adversary, this trade-off provides significant efficiency gains. In recent years, due to the high efficiency and security guarantees, proto- cols derived from the HKE framework have been *widely adopted as a component* for designing actively secure 2PC [28,23,30,7,39], 2PC with robust publicly verifiable covert security [26], and private set intersection (PSI) [31]. While one-bit-leakage protocols derived from the HKE framework are highly efficient and can limit the adversary to gain at most one extra bit of information, when these protocols are used in *standalone* *settings* instead of being used as a component in other protocols, they are *practically limited*. This limitation arises because, when used on their own, these protocols have critical security weaknesses in fairness for honest parties. An adversary in one-bit-leakage protocols can *always* choose to learn the evaluation result, together with an extra bit of information about the honest party’s inputs, while having the honest party learn *nothing*. Specifically, in these protocols, parties will obtain an evaluation result (which may be incorrect if misbehavior occurs) and then perform a verification to confirm its correctness. As a result, an honest party might initially obtain an incorrect result, only to later reject it upon verification, ultimately learning nothing (see Section 2.2 for more details). This advantage for adversaries actually encourage dishonest behaviors, which is practically unacceptable in many scenarios, thereby severely limiting the direct applicability of one-bit-leakage 2PC. Huang, Katz, and Evans indeed identified this critical problem in their original work [19] and proposed two heuristic enhancements to address it. The first approach aims to verify the garbled outputs, *i*.*e*., (potentially incorrect) evaluation results in encrypted form, before revealing them, thus preventing an adversary from learning the result if they are caught cheating during verification. To accomplish this, they employ a fully-fledged actively secure garbled circuit protocol that takes the garbled outputs as inputs for verification. However, this approach is *prohibitively expensive*. For exam- ple, when evaluating an AES-128 circuit with a (2*×*128)-bit input and a 128-bit output, the garbled outputs comprise 128 output-wire labels, each 128 bits in length. These 128 *×* 128 bits would serve as a portion of inputs for the verification’s garbled circuit. In fact, this approach requires a complex verification circuit with at least 6*×*128 2 bits of inputs. Such an approach is even more expensive than evaluating AES-128 directly with fully-fledged active security. The second enhancement is progressive revelation [5,11,21,8]. It ensures that the adversary’s advantage is limited to only one additional bit of output beyond what the honest party obtains, by revealing the evaluation result bit by bit. How- ever, this also relies on a fully-fledged actively secure garbled circuit protocol to process output-wire labels from the one-bit-leakage protocol, resulting in significant overhead. These approaches, while theoretically addressing the fairness problem, *impose expensive overhead and conflict with the original* *goal of developing efficient actively secure protocols*. Additionally, *no clear method to combine these* *approaches has been provided*, and *what security guarantees they provide lacks formalization*. Therefore, the following question is open so far:

*How can we provide an effective solution to the fairness problem in one-bit-leakage protocols?*

1.1 Our Contributions In this paper, we integrate both of the aforementioned enhancements within a new formalized se- curity model and provide a *highly efficient* protocol that effectively addresses this fairness problem. Specifically: New security notion. We propose a new notion for 2PC named *active security with one-bit ad-* *vantage bound* to address the fairness problem inherent in one-bit leakage protocols. Protocols achieving active security with one-bit advantage bound limit the *advantage* of an (actively) cor- rupted party to at most one bit. That is, instead of *n* + 1 bits in one-bit leakage protocols, *the* *adversary can gain at most one more bit of information beyond what the honest party obtains*. The security model employs a *progressive revelation* mechanism in which one bit of the evalua- tion result is disclosed iteratively. It also supports *adjustable advantage*, allowing the adversary’s one-bit advantage to be adjusted to arbitrary *k*-bit advantage.
5 Protocol with low overhead. We design a *highly efficient* constant-round 2PC protocol that achieves active security with one-bit advantage bound. Note that our protocol is *fully compatible* with the state-of-the-art garbling schemes – the three-halves scheme and the half-gates scheme. 6 Besides the progressive revelation phase, the runtime of our protocol is *almost identical* to that of the passively secure counterpart in duplex networks (*e*.*g*., 1*.*033*×* for the SHA256 circuit in LAN, see more in Section 6). The progressive revelation phase itself is highly efficient: the number of rounds can be minimized to almost the same as the bit-length of the evaluation result, while the one-way communication required to securely release each bit of the result is only 80 bytes, with no dependency on public-key operations.

With its stronger security guarantees and low overhead, our improved protocol is highly suitable for practical applications of secure two-party computation.

## 2 Technical Overview

In this section, we first introduce the notations used throughout the paper, and then present an overview of the HKE framework for designing actively secure 2PC protocols with *one-bit-leakage* and describe why the aforementioned fairness problem arises. Subsequently, we provide intuition behind our improved 2PC protocol, detailing how the structure of wire labels in garbling schemes can be exploited to achieve active security with *one-bit advantage bound*.

2.1 Notation We denote the security parameter by *κ*, which may be used as an implicit input to algorithms in this paper. We denote the size of a set *S* as *|S|* and use the notation *x ←*$ *S* to indicate that an element *x* is sampled uniformly at random from *S*. For any positive integer *n*, let [*n*] = *{*1*,...,n}*, and for positive integers *a < b*, define [*a,b*] = *{a,a* + 1*,a* + 2*,...,b}*. For a vector *v*, we denote the *i*th element of *v* as *v*[*i*]. For a string *s ∈{*0*,*1*}*
*∗*, the *i*th bit of *s* is written as either *si*or *s*[*i*]. We write F₂*κ∼*= F₂[*X*]*/f*(*X*) for monic irreducible polynomial *f* (*X*) of degree *κ* and use X *∈* F₂*κ* to represent the element corresponding to *X ∈* F₂[*X*]*/f*(*X*). When it is clear from the context, we interchangeably use *{*0*,*1*}* *κ*, F *κ* 2, and F₂*κ*. Hence, addition in F *κ* 2and F₂*κ* corresponds to XOR in *{*0*,*1*}* *κ*. A Boolean circuit *C* consists of a list of gates, where each gate is given in the form of (*i,j,k,T*). Here, *i* and *j* are the indices of input wires, *k* is the index of output wire, and *T ∈{⊕, ∧}* specifies the gate type. We denote the set of circuit wire indices as *W*, with *n* representing the number of input wires and *n*Othe number of output wires. For the *i*th output wire, the function out maps *i ∈* [*n*O] to a wire index *w ∈W*. The set of output wires is represented as *W*O= *{w | w* = out(*i*) for *i ∈* [*n*O]*}*, with *n*O= *|W*O*|*. In the 2PC setting, let *W*A B A’s and PB’s input wires,

||and W||represent the sets of indices for P|||
|---|---|---|---|---|---|
||A A|B B|B|A B||

respectively, where *n*A= *|W |* and *n* = *|W |*, satisfying *n* = *n* + *n*. 5 This can reduce the number of rounds and is useful for scenarios where the length of evaluation result is long, or the network latency is high, allowing trade-off between security and efficiency. 6 Recent implementations of the three-halves scheme [16,6] demonstrate that the half-gates scheme out- performs the three-halves scheme in many common scenarios. Accordingly, we consider both schemes to represent the state-of-the-art.

2.2 Overview of Prior Work The HKE framework employs a technique called dual execution to limit the leakage to one bit. The core idea of dual execution is that two parties PAand PBexecute the classical garbled circuit protocol twice over the same circuit and inputs, where actively secure OT protocols for input-wire retrieval are used. In one execution, PAacts as the garbler and PBas the evaluator; in the other, their roles are reversed, *i*.*e*., PBbecomes the garbler, and PAbecomes the evaluator. Each party also sends the decoding information for their garbled outputs to the other party. Once both executions are complete, the parties perform an actively secure *equality test* on the output materials of the two garbled circuits to determine the final result. Specifically, for an *n*

|||-bit-output circuit, the honest P|||’s input to the|
|---|---|---|---|---|---|
||O i′ i,y i∈[n|]|i′|i′|A|
|||||B||
|i,y B|||A||i′|
 equality test includes output-wire labels *Y,Y*
*i′*, where *Y* (resp. *y*) denotes the *i*th output- O wire label (resp. the *i*th bit of output) of the garbled circuit generated by P and evaluated by PA, while *Y* *i′* represents the *i*th output-wire label generated by P with real bit value *y*. The inputs provided by P to the equality test follow a similar structure. If the test passes, both parties accept the output as correct; otherwise, the protocol terminates, signaling that one party is corrupted and has deviated from the protocol. Given that actively secure OTs are cheap, the total cost is only around twice as much as a passively secure garbled circuit protocol, and it is nearly no overhead in duplex networks. This method effectively limits a corrupted party to learning, at most, a single additional bit of information about the honest party’s input beyond the evaluation result. The reasoning is that while a corrupted party may deviate from the protocol when garbling the circuit, it cannot cheat in the circuit evaluation as the evaluator if the OT protocols are actively secure. Therefore, the only additional information the corrupted party can gain from the incorrectly generated garbled circuit is the output of the equality test — either a true or false result, providing at most one bit of information that could potentially depend on the honest party’s input. Nevertheless, as we have mentioned in Section 1, the security guarantees offered by the one- bit-leakage protocols derived from HKE framework are still practically limited due to the fairness problem. In particular, for the equality test, PAmust obtain the evaluation result *y* *′* of PB’s garbled circuit beforehand (from the decoding information). Therefore, a corrupted PBcan *always* learn the evaluation result by evaluating PA’s garbled circuit while generating a malicious circuit for PA, thereby gaining an extra bit of information about PA’s inputs through the equality test. As a result, a corrupted PBcould *always* obtain *n*+ 1 bits of information while having the honest PAlearn *nothing*.

2.3 Overview of Our Solution We introduce the idea behind our 2PC protocol in the following. Section 4.2 formally describes our protocol in detail, and some improvement techniques and optimizations that could be used in implementations are introduced in Section 5. In protocols derived from the HKE framework, the parties may obtain a potentially incorrect evaluation result from the garbled circuit generated by the other party, which they need to verify through an equality test later. To solve the aforementioned fairness problem, it is necessary to verify the correctness of the output once it has been released or even before it is released. In our protocol, we maintain the dual execution procedure as previously described, with one key modification: neither party transmits the decoding information for garbled outputs to the other party. This change delays the point at which both parties learn the evaluation result, and both parties, as the evaluator, only hold the garbled outputs after the garbled circuit evaluation. From this stage onward, we divide the protocol into two main phases: verification and progressive revelation. In the verification phase, we introduce a novel approach that enables both parties to *blindly* verify, via one equality test, whether the garbled outputs from their respective circuits encode the same evaluation result without disclosing it. If this test fails, the protocol terminates, and the corrupted party learns no more than one bit of information from the test outcome. Conversely, if the test passes, it confirms that even if the corrupted party may have improperly generated the garbled circuit, both parties still hold the consistent evaluation result. Intuitively, if the underlying OT protocol is actively secure, the evaluator cannot deviate undetected within the garbled circuit framework. Thus, the successful completion of this test assures the honest party that the evaluation result of the other party’s garbled circuit aligns with the evaluation result of his own garbled circuit, thereby preserving the *correctness* of the evaluation result.

The protocol then advances to the progressive revelation phase, where the evaluation result is gradually disclosed, *i*.*e*., output in a bit-by-bit manner. During this phase, each bit of the evaluation result is sequentially opened and verified. If any bit fails to be opened correctly, the protocol aborts, limiting the adversary’s gain to at most one additional bit of information. Moreover, this gradual opening procedure, bounded by a one-bit advantage, can be adapted to release *k* bits of the evaluation result at a time, thereby reducing the protocol’s round complexity through a security trade-off. We begin by describing our method for verifying that the garbled outputs from both parties encode the same evaluation result without disclosing it. This method is compatible with the current state-of-the-art half-gates and three-halves garbling schemes. To set the stage, we first briefly review the label structure utilized in these garbling schemes, and then introduce how to exploit this structure to achieve our goal. Both the half-gates and three-halves garbling schemes employ the point-and-permute and free- XOR techniques. For the point-and-permute technique, the actual bit *zw*on each wire *w* is masked by a point-permute bit (a.k.a. random bit) *λw*generated by the garbler, and the resulting masked bit *z*ˆ*w*= *zw⊕ λw∈{*0*,*1*}* allows to be known by the evaluator for garbled circuit evaluation. The free-XOR technique enables XOR gates to be garbled with no communication. In particular, the garbler sets L*w,*0*⊕* L*w,*1= ∆ for each wire *w*, where L*w,b∈ {*0*,*1*}* *κ* is the label for wire *w* with masked bit *b ∈{*0*,*1*}*, and ∆ *∈{*0*,*1*}* *κ* is a global key (a.k.a. fixed offset). The output-wire label of an XOR gate is computed by simply XORing the two input-wire labels of that gate. The masked bit is often encoded in the least significant bit of the wire labels, and thereby let lsb(∆) = 1 resulting in *z*ˆ *w*= lsb(L*w,z*ˆ*w*). Suppose that a garbler PAand an evaluator PBleverage a garbling scheme with point-and-permute and free-XOR technique (*e*.*g*., half-gates or three-halves) to execute a passively secure 2PC protocol for a circuit *C*, where only PAobtains the final *n*-bit outputs. PAgenerates and sends a garbled circuit to PB. Both parties then execute an OT protocol, such that PBobliviously retrieves the input-wire labels corresponding to his inputs from PA. PAalso sends input-wire labels corresponding to her inputs to PB. Given all input-wire labels, PBcan evaluate the garbled circuit. Denote the global key by ∆A. During the evaluation of garbled circuit, for a wire *w*, the evaluator PBholds the wire label L*w,z*ˆ*w*= L*w,*0*⊕ z*ˆ*w*∆A, which also contains the masked bit ˆ*zw*= lsb(L*w,z*ˆ*w*). Meanwhile, the garbler PAholds the point-permute bit *λw*. In other words, the actual bit *zw*= ˆ*zw⊕λw* remains secret and is shared between the two parties. After the evaluation, the evaluator PBsends L*w,z*ˆ*w*(implicitly containing *z*ˆ*w*) for each output wire *w ∈W*Oto the garbler PA. The garbler PAthen computes *zw*= ˆ*zw⊕ λw*and verifies whether L*w,z*ˆ*w*= L*w,*0*⊕* (*λw⊕ zw*)∆A. This verification is equivalent to checking whether the following holds.

### Lw,zˆw⊕ (Lw,0⊕ λw∆A) = zw∆A.

By the authenticity property of garbling schemes, a corrupted evaluator PBcannot send a tampered label Lˆ*w̸*= L*w,z*ˆ*w*to pass this check, except with negligible probability. Notably, before PBsends L*w,z*ˆ*w*, PBholds L*w,z*ˆ*w∈{*0*,*1*}* *κ*, while PAcan locally compute L*w,*0*⊕ λw*∆A*∈{*0*,*1*}* *κ*. Therefore, PA and PBhold secret shares of both *zw∈{*0*,*1*}* and *zw*∆A*∈{*0*,*1*}* *κ*. Similarly, if the roles of the parties are reversed, with PBas the garbler and PAas the evaluator for the same circuit *C*, then for an output wire *w*, PAholds the masked bit *z*ˆ*w* *′* and the wire label L *′w,z* ˆ *w* *′*. Meanwhile, PBholds *λ* *′w* and can compute L *′w,* 0*⊕ λ* *′w* ∆B. Thus, in this case, PAand PBsecretly share *zw* *′* and *zw* *′* ∆B. The table below summarizes the values held by PAand PBfor wire *w* during the *dual* executions, where the garbled circuit GC is generated by PAwhile GC *′* is generated by PB.

Values held by PAValues held by PB GC ∆A, L*w,*0, *λw z*ˆ*w*, L*w,z*ˆ*w*= L*w,*0 *⊕ z*ˆ*w* ∆A GC *′* *z*ˆ *w* *′*, L *′w,z* ˆ *w* *′*= L *′w,* 0*⊕ z*ˆ*w* *′* ∆B∆B, L *′w,* 0, *λ* *′w*

For *i ∈* [*n*O] and *w* := out(*i*), define *Bi,*1:= L*w,z*ˆ*w*(held by PB), *Ai,*1:= L*w,*0*⊕ λw*∆A(held by PA), and *ωi*= *zw*. We have *Ai,*1*⊕ Bi,*1= (*λw⊕ z*ˆ*w*)∆A= *zw*∆A= *ωi*∆A*.*

Similarly, let *Ai,*2:= L *′w,z* ˆ *w* *′* (held by PA), *Bi,*2:= L *′w,* 0*⊕ λ* *′w* ∆B(held by PB), and *ωi′*= *zw* *′*. We have

*Ai,⊕ Bi,*= (*λ* *′w* *⊕ z*ˆ*w* *′* )∆B= *zw* *′* ∆B= *ωi′*∆B*.*

Now PAcan compute *Ai*:= *Ai,⊕ Ai,*, while PBcan compute *Bi*:= *Bi,⊕ Bi,*. Let ∆ = ∆A*⊕*∆B. If both parties are honest, we expect *ωi w w w w* *′ ′w*

||||= z|= ˆ z ⊕ λ|= ˆ z ⊕ λ|= z = ω|, and thus||
|---|---|---|---|---|---|---|---|---|
||A|i i B|i i,1 i|w w i,2 i,1 i′|w w ′ i,2 i i i|′w w ′ A i′ B|i′||
|i|i′||||||i||

*w* *′* *i′*

*A ⊕ B* = *A ⊕ A ⊕ B ⊕ B* = *ω* ∆ *⊕ ω* ∆ = *ω* ∆ = *ω* ∆*.*

In this scenario, P and P effectively share the values *ω* and *ω* ∆. Although derived from different methods, this resembles the SPDZ authentication, where both parties *secretly share* the global key ∆, the value *ω* = *ω*, and the corresponding message authentication code (MAC) *ω* ∆. If one party is corrupted, the outputs of the two garbled circuits from dual executions may not be consistent. Our key insight for verifying the consistency of garbled outputs stems from the technique of opening SPDZ-style authenticated secret sharing. Without loss of generality, assume that PAis honest and PBis corrupted. In the case of garbled circuits, if the OT protocol is actively secure, a corrupted party cannot cheat (without being detected) when playing the role of the evaluator due to the authenticity property of garbling schemes. In the execution where the corrupted PBis the garbler, the honest PAhaving input *x*Ais indeed evaluating a function *F*B *∗* that could be fully defined by PB: n o (ˆ*zw* *′* *,* L *′w,z* ˆ *w* *′*) := *F*B *∗* (*x*A)*.* *w∈W*O

As previously mentioned, for an output wire *w*, the two parties hold a SPDZ-like authenticated secret sharing of the actual value. They can open this bit as *ωi′′*:= ˆ*zw* *′* *⊕ λ* *′w*, 7 where *i* = out *−*1

(*w*),
and then proceed with an SPDZ-style opening verification for *ωi′′*. In this SPDZ-style verification, PA and PB *i i′′* A *i i′′* B

|must commit to and subsequently open the values A|||⊕ ω|∆ and B|⊕ ω|∆, respectively.||
|---|---|---|---|---|---|---|---|
||||i|i′′ A|i|i′′ B||
|||||||A||

The verification checks whether these two committed values are equal. Specifically, P will commit to and open the value:

*Ai⊕ ωi′′*∆A= *Ai,*1*⊕ Ai,*2*⊕ ωi′′*∆A = L*w,*0*⊕ λw*∆A*⊕ Ai,*2*⊕ ωi′′*∆A*,*

where *Ai,*2= L *′w,z* ˆ *w* *′* is derived from *F*B *∗*. To pass this verification, PBmust also commit to and open a value that equals *Ai⊕ωi′′*∆A(*i*.*e*., the XOR of the two committed values must be zero). It is important

|to note that the value held by the corrupted P|||||corresponding to L||is B|= L|⊕ zˆ|∆.|
|---|---|---|---|---|---|---|---|---|---|---|
|||w,0|B||B|i,1 i,1 i|w,0 i,1 i′′ A|w,zˆ w A|w,0 w i,2 i′′|A A|
|i,2 B|w|i′′ A A B||w|i′′ i,2|A A|B|i′′ A|||

B *w,*0 *i,*1 *w,z*ˆ*w*= L*w,*0 *w* A Thus, to cancel out L, P ’s committed value must include *B* (in the form of XOR), except with negligible probability of simple guessing. Given that *B ⊕ A ⊕ ω* ∆ = *z* ∆ *⊕ A ⊕ ω* ∆ = *A ⊕* (*z ⊕ ω*)∆, we observe that if *z ⊕ ω ̸*= 0, *i*.*e*., the opened bit *ω* is inconsistent with the output of the garbled circuit generated by the honest party P, then P can only make his committed value match P ’s by correctly guessing the value of ∆, which occurs with negligible probability, even though P has full control over the value *A*. A similar conclusion holds if P is corrupted and P is honest. Therefore, except with negligible probability, this procedure allows the two parties to determine whether the opened bit is correct. Can this procedure be *directly* applied to open and verify the output of garbled circuits? *The*

||could manipulate F||so that the honest P|||obtains|
|---|---|---|---|---|---|---|
||B||B ∗|||A|
|i′′ A|i,2 w|i′′ A|w i′′|A|w|i′′|
|i|i′′ A B A|B A||A|A||

*answer is no*. For example, a corrupted P *Ai,*2= 0. Since *Bi,*1*⊕ Ai⊕ ω* ∆ = *A ⊕* (*z ⊕ ω*)∆ = (*z ⊕ ω*)∆, when *z ⊕ ω* = 1, after observing PA’s committed value *A ⊕ ω* ∆, P can can deduce the value of ∆. Even though the protocol would terminate due to an invalid opening, P could still exploit ∆ to open the previously received garbled circuit generated by P and learn P ’s inputs. This problem can be resolved by having both parties execute a secure *equality test* protocol instead, which only reveals whether the two committed values are identical. This verification can be done in batches. We can treat bits and *κ*-bit strings as elements in F *κ* 2 and F₂*κ*. To batch-verify the opened bits, both parties can first use coin-tossing protocols to select P random values *ri←*$ F *κ* 2for *i ∈* [*n*O] and compute *ω* *′′* =*i∈*[*n* O] *r* *i* *ωi′′∈* F *κ*

2. Then PAand PBcompute
P P *′′ ′′* *A* :=*i∈*[*n* O] *r* *i* *Ai*and *B* :=*i∈*[*n* O] *r* *i* *Bi*, respectively, such that *A⊕B* = *ω* ∆. To verify *ω*, PA

7 Reconstructing this bit as *ω* *′′* := ˆ*zw ⊕ λw* using shares from a garbled circuit generated by the honest party *i* PAis also an option. However, here we only aim to introduce the intuition behind our protocol and do not concern ourselves with how *ω* *′′* is reconstructed.

computes *A ⊕ ω* *′′* ∆A, where

    X X *A ⊕ ω* *′′* ∆A=  *riAi* *⊕*  *riωi′′* ∆A *i∈*[*n*O] *i∈*[*n*O] X = *ri*(*Ai⊕ ωi′′*∆A) *i∈*[*n*O] X = *ri*(L*w,*0*⊕ λw*∆A*⊕ Ai,*2*⊕ ωi′′*∆A)*,* *i∈*[*n*O]

and uses this in the equality test. To make these openings valid, corrupted PBmust provide a value equal to *A ⊕ ω* *′′* ∆A. Since *ri*’s are randomly chosen and *|*F *κ* 2*|* is large enough, if the equality test passes, then *Ai⊕ ωi′′*∆Ais equal to *Bi⊕ ωi′′*∆Bexcept with negligible probability. Similar to verifying a single opening, in the equality test, PB’s value must account for all *riBi,*1terms (in XOR form) to cancel out L*w,*0, leaving only a negligible probability of successful guessing. Then, if *zw̸*= *ωi′′*, the only way for PBto align their values with those of PAis by correctly guessing ∆A.

Since both parties hold authenticated secret shares of each *ωi′′*for *i ∈* [*n*O], they can locally compute the authenticated secret sharing of *ω* *′′* as a whole, opening only *ω* *′′* rather than revealing each indi- vidual *ωi′′*. This process is equivalent to verifying that, for each pair of MAC shares (*Ai,Bi*), the two parties correctly possess correct shares of the corresponding bit. In the dual execution setting, these shared bits appear as *ωi*= ˆ*zw⊕ λw*or/and *ωi′*= ˆ*zw* *′* *⊕ λ* *′w*. Therefore, both *ωi*’s and *ωi′*’s can be verified simultaneously in batch. To accomplish this, the parties jointly sample random values *ri,ri′←*$ F *κ* 2 P P and locally compute the share of *ω* :=*i∈*[*n* O] *r* *i* *ωi⊕i∈*[*n* O] *r* *i′* *ωi′*, which is then opened. They P P subsequently compute the associated MACs, defined as *A* :=*i∈*[*n* O] *r* *i* *Ai⊕i∈*[*n* O] *r* *i′* *Ai*and P P *B* :=*i∈*[*n* O] *r* *i* *Bi⊕i∈*[*n* O] *r* *i′* *Bi*, using these to validate *ω*.

Now, with both parties holding MAC shares *{*(*Ai,Bi*)*}i∈*[*n*O], they can efficiently verify whether their shares satisfy the condition *ωi*= ˆ*zw⊕ λw*= ˆ*zw* *′* *⊕ λ* *′w* = *ωw* *′* for *w* = out(*i*) and *i ∈* [*n*O], ensuring both correctness and authentication by revealing only *ω* and performing a single equality test. This approach eliminates the need to individually open *ωi*and *ωi′*. However, a direct revelation of *ω* would expose a linear combination of *ωi*and *ωi′*. To conceal this linear combination result, the two parties can generate an authenticated secret sharing of a random value *ω₀ ←*$ F *κ* 2and incorporate it into the linear combination. Let *A₀* and *B₀* represent the MACs held by PAand PB, respectively, where P P *A₀ ⊕ B₀* = *ω₀·*∆. The two parties can then open *ω* := *ω₀⊕i∈*[*n* O] *r* *i* *ωi⊕i∈*[*n* O] *r* *i′* *ωi′*and verify its correctness as previously outlined. By introducing the random value *ω₀*, this approach effectively conceals the linear combination of the shares.

At this stage, both parties have *blindly* verified the consistency of the outputs from the garbled circuits generated by PAand PBthrough a single equality test. If the outputs are consistent, they proceed to the progressive revelation phase. With both parties holding *ωi*= *ωi′*for all *i ∈* [*n*O], they can gradually open each bit of the evaluation result and verify its correctness. Specifically, PAsends *ai,*1= *λw*to PBwhile PBsends *bi,*2= *λ* *′w* to PAfor *w* = out(*i*). Then PAand PBcan reconstruct

|ω = a|⊕ b and ω|= a|⊕ b, respectively. An equality test is subsequently used to verify the||||||
|---|---|---|---|---|---|---|---|---|
|i′ i,2|i,2|i i,1|i,1 i|i A|i i′|B|i|i B|

*i′ i,*2 *i,*2 *i i,*1 *i,*1 opening of each bit with respect to *A* and *B* : P inputs *A ⊕ ω* ∆A and P inputs *B ⊕ ω* ∆. If any verification fails, the protocol terminates; otherwise, both parties securely obtain the final evaluation result. Throughout these two phases, a corrupted party gains at most a one-bit advantage over the honest party, yielding an actively secure 2PC protocol with a one-bit advantage bound.

Additionally, by batching the opening and verification process of the progressive revelation phase through random linear combinations, *k* bits of the evaluation result can be opened and verified simultaneously. This approach yields an actively secure 2PC protocol with a *k*-bit advantage bound, thereby reducing round complexity. We note that *k* could even be different in each iteration to adapt to different scenarios flexibly.

## One-Bit Advantage Bound

Based on the discussion in Section 2, we define the ideal functionality *F*OneBitAdvfor 2PC with a one- bit advantage bound as follows. A two-party protocol *Π*OneBitAdvfor the circuit *C* is said to securely compute *C* with one-bit advantage bound if it securely realizes the functionality *F*OneBitAdv.

<u>Functionality FOneBitAdv</u>

Public inputs: Both parties agree on a circuit *C* with *n* = *n*A+ *n*Binput wires and *n*Ooutput wires. Private inputs: PAhas input *x*A*∈{*0*,*1*}* *n* A, whereas PBhas input *x*B*∈{*0*,*1*}* *n* B.

Upon receiving *x*Afrom PAand *x*Bfrom PB, store these values and compute *y* := *C*(*x*A*,x*B).

Verification

Upon receiving a set of functions *{gi,gi′}i∈*[*n* O], where *gi,gi′*: *{*0*,*1*}* *n* *→* F *κ* 2, from the adversary, compute *αi* := *gi*(*x*A*,x*B) and *αi′*:= *gi′*(*x*A*,x*B) for each *i ∈* [*n*O]. Then, send random *ri,ri′←*$ F *κ* 2for *i ∈* [*n*O] to the adversary and receive *β ∈* F *κ* 2in return. P P Verify whether *β* =*i∈*[*n* O] *r* *i* *αi ⊕i∈*[*n* O] *r* *i′* *αi′*. Send the verification result to the adversary. If the verification fails, send cheating to the honest party and terminate. Otherwise, send *{*(*αi,αi′*)*}i∈*[*n* O] to the adversary and proceed.

Progressive revelation For each *i ∈* [*n*O]:

– Send *yi* to the adversary. – If continue from the adversary is received, send *yi* to the honest party and continue. If abort from the adversary is received, send *⊥* to the honest party and terminate.

We note that the ideal functionality *F*OneBitAdvborrows the idea for the definition of one-bit leakage [19]. In the definition of one-bit leakage, the adversary in the ideal world can send a Boolean function *g* to the ideal functionality and receive the one-bit outcome of *g* applied to both parties’ inputs, thus defining the one-bit leakage. To better align with our security proof, we adapt this approach. Instead, during the verification phase, the adversary is allowed to submit a set of functions

|{g ,g } to F||. The functionality responds by generating random values r||||||and r|
|---|---|---|---|---|---|---|---|---|
|i i′|OneBitAdv|||||||i|
|O|i|i′|i A B i i′|i′ i∈[n i∈[n]|i′ A B] i i i∈[n]|8 i∈[n] i i i|i′ i′ i∈[n i′|] i′ i′|

*i′*for each *i ∈* [*n*], while computing *αi*:= *g* (*x,x*) and *α* := *g* (*x,x*). The adversary then submits a value P P *β*, which is checked against the equation *β* = O *r α ⊕* O *r α*. This way, the adversary learns only a single bit of information (*i*.*e*., the truth value of the equation) during verification. P P Since *r* and *r* are uniformly random, if *β* = O *r α ⊕* O *r α* holds and the adversary knows this fact, this adversary must have known each *α* and *α*, except with negligible probability. Therefore, sending *{*(*α,α*)*}* O to the adversary after successful verification does not provide any additional information beyond what the adversary has already inferred.

*Remark 1.* The progressive revelation phase of *F*OneBitAdvcan be straightforwardly modified to reveal *k* bits instead of a single bit in each iteration. Consequently, the resulting ideal functionality would limit the adversary’s advantage to *k* bits. Protocols securely realizing this ideal functionality are actively secure with *k*-bit advantage bound. We also note that the variable *k* could even differ in each iteration.

## 4 Our One-Bit Advantage Bound Protocol

In this section, we first introduce the building blocks of our protocol. Then, we describe our protocol in detail.

Note that notation *gi* (resp. *αi*) is essentially equivalent to *g* *′* (resp. *α* *′* ); the use of *prime symbols* here *i i* serves solely to simplify description in our security proof.

4.1 Building Blocks We first introduce the syntax of projective garbling schemes [4] as follows. Definition 1. *A projective garbling scheme consists of five algorithms:* – (GC*,e,* dk) *←* Gb(1
*κ* *, C*)*. The garbling algorithm* Gb *takes as input the security parameter* 1 *κ* *and* *a circuit C with n* = *n*A+ *n*B*input wires and n*O*output wires. It outputs a garbled circuit* GC*, a* *mapping of input-wire labels e* := *{*(*Xi,*0*,Xi,*1)*}* *i∈*[*n*] *, and a decoding key* dk*.* – (*d,D*) := Dc(dk)*. The decoding information derivation algorithm* Dc *takes as input a decoding key* dk *and outputs the* simple *decoding information d and* authenticated *decoding information D.* – *X* := En(*e,x*)*. The encoding algorithm* En *takes as input the input-wire label mapping e* =

|,X|)} and input x ∈{0, 1}||, and outputs input-wire labels X := {X||}|
|---|---|---|---|---|---|
|i,0 i,1|i∈[n]|i i∈[n]|n i i∈[n]|i i∈[n]|i,x i∈[n] i i∈[n]|

*{*(*Xi.* – *Y* := Ev(GC*,X*)*. The evaluation algorithm* Ev *takes as input the garbled circuit* GC *and the* *input-wire labels X* = *{X}, and outputs the output-wire labels Y* := *{Y}* O *.* – *y* := De(*d,Y*)*. The simple decoding algorithm* De *takes as input the simple decoding information* *d and output-wire labels Y* = *{Y}* O *, and outputs the decoded result y.* – *y* := AuDe(*D,Y*)*. The authenticated decoding algorithm* AuDe *takes as input the authenticated* *decoding information D and output-wire labels Y* = *{Y}* O *, and outputs the decoded result y.* *If decoding fails, y may take the value ⊥.*

*The scheme is correct if for any (polynomial-size) circuit C and input x, after computing* (GC*,e,* dk) *←* Gb(1 *κ* *, C*) *and* (*d,D*) := Dc(dk)*, we have*

### C(x) = De(d, Ev(GC,En(e,x)))

*and* *C*(*x*) = AuDe(*D,* Ev(GC*,*En(*e,x*)))

*except with negligible probability.* 9

Different from the garbling scheme definition in [4], we separate the decoding into simple decoding and authenticated decoding algorithms. This distinction aligns naturally with most existing garbling schemes. When context permits, we may combine the Gb and Dc algorithms into a single function: (GC*,e,* dk*,d,D*) *←* Gb(1 *κ* *, C*). For our protocol, we require that the garbling scheme adheres to the *point-permute-freeXOR-* *compatible* property, defined as follows:

Definition 2. *A projective garbling scheme along with an algorithm* EvalAND *for the security pa-* *rameter κ is* point-permute-freeXOR-compatible *if:*

Point-and-Permute Compatibility. *Each wire w in the garbled circuitis associated with a point-* *permute bit λw. During garbled circuit evaluation, the wire label* L*w,z*ˆ*w∈{*0*,*1*}* *κ* *is derived, and* *the true bit for wire w is zw*= *λw⊕ z*ˆ*w, where z*ˆ*w*= lsb(L*w,z*ˆ*w*) *represents the (public) masked bit* *on* L*w,z*ˆ*w.* FreeXOR Compatibility. *There is a global offset* ∆ *∈{*0*,*1*}* *κ−*1 *||*1*, such that the XOR of each wire* *label pair are* ∆ *and the masked bit of* L*w,z*ˆ*wis z*ˆ*w*= lsb(L*w,z*ˆ*w*)*. For any gate G* = (*α,β,γ,T*)*,* *where the evaluator holds* L*α,z*ˆ*α β,z*ˆ*βα β*

||and L|(alongside zˆ||and zˆ ), evaluation proceeds as follows:||
|---|---|---|---|---|---|
|α,zˆ|β,zˆ||α|β||
|γ,zˆ|α,zˆ|β,zˆ|γ|α|β|
|γ|α β|||||
|γ,zˆ||α,zˆ|β,zˆ|||

– *If T* = *⊕, compute* L*γ*:= L*α⊕* L*β(with z*ˆ := ˆ*z ⊕ z*ˆ *implicitly). The point-permute* *bit for wire γ is then λ* = *λ ⊕ λ.* – *If T* = *∧, compute* (L*γ*) := EvalAND(L*α,* L*β*)*, where* EvalAND *is the multiplication gate* *evaluation algorithm that inputs the labels of the input wires for an AND gate, evaluates the* *garbled gate, and outputs the corresponding output-wire label.*

We denote Gb(1 *κ* *, C*; ∆) to specify the global offset ∆ explicitly. For a point-permute-freeXOR-compatible garbling scheme, such as the half-gates scheme [38] and three-halves scheme [32], the global offset ∆ and a wire label L*w*(where *λw*

||||= lsb(L||)) suffice to|
|---|---|---|---|---|---|
||w,λ|w,λ|w i,b out(i) i∈[n|w,λ w,λ]|w∈W|
|i i∈[n]|i|w||O||

determine output-wire labels as *Yi,b*:= L*w⊕b*∆ for *b ∈{*0*,*1*}*, where *Y* represents the label for the real bit *b* on the *i*th output wire. Consequently, we set the decoding key as dk = (∆*, {*L*w}* O ). In our protocol, we define the simple decoding information as *d* = *λ*. Given output-wire O labels *{Y}* O, the output of De(*d,Y*) is *y* := lsb(*Yi*) *⊕ λ*, for *w* = out(*i*) and *i ∈* [*n*]. We give the security definition for such garbling schemes as follows.

We allow a negligible failure probability as the definition in [32].

Definition 3. *A projective point-permute-freeXOR-compatible garbling scheme achieves* oblivious- ness *if there is a probabilistic polynomial-time (*PPT*) simulator S*Gb*, such that for any circuit C and* *input x, the outputs of the following two games are indistinguishable.*

(GC*,e,* dk*,d,D*) *←* Gb(1 *κ* *, C*)*κ* (GC*,X*) *←S*Gb(1*, C*) *X* := En(*e,x*) return (GC*,X*) return (GC*,X*)

We adapt the privacy property introduced in [4] and define the *equivocable privacy* property as follows.

Definition 4. *A projective point-permute-freeXOR-compatible garbling scheme achieves* equivocable privacy *if there is a tuple of* PPT *simulators* (*S*Gb*, S*Gb *′* )*, such that for any circuit C and input x, the* *output of the following games are indistinguishable.*

(GC*,e,* dk*,d,D*) *←* Gb(1 *κ* *, C*) (GC*,X,z*) *←S*Gb(1 *κ* *, C*) *X* := En(*e,x*) *d ←S*Gb *′* (*C*(*x*)*,z*) return (GC*,X,d*) return (GC*,X,d*)

Now, the simulator is split into two components *S*Gband *S*Gb *′*. The first component *S*Gbdoes not require the evaluation result *C*(*x*) as input and generates (GC*,X*) independently. Additionally, *S*Gb produces auxiliary data *z*, which could be *Y* := Ev(GC*,X*) for most existing garbling schemes and is then used as input to *S*Gb *′*. The second component *S*Gbtakes *C*(*x*) and *z* as inputs to produce the simulated simple decoding information *d*. In other words, the simulated garbled circuit GC and garbled input *X* are generated initially, while the simulated simple decoding information *d* can be generated subsequently once the evaluation result *C*(*x*) is known, ensuring consistency with (GC*,X*). Notably, both the half-gates and three-halves garbling schemes satisfy equivocable privacy, as the simulator in their security proofs of privacy generates *d* with respect to *C*(*x*) after GC and *X* are generated. In our protocol, parties only receive *d*, and thus, we do not need to consider the authenticated decoding information *D*. We introduce a relaxed form of authenticity property [4] for our protocol, termed *authenticity* *against one-bit leakage*.

Definition 5. *A projective point-permute-freeXOR-compatible garbling scheme for the security pa-* *rameter κ achieves* authenticity against one-bit leakage *if for any circuit C and input x, no tuple of* PPT *adversaries (A₁, A₂, A₃) can make the following game output* true *with non-negligible probability:*

(GC*,e,* dk*,d,D*) *←* Gb(1 *κ* *, C*) *X* := En(*e,x*) (*ℓ, {gi*(*·*)*}i∈*[*ℓ*]*,z₁*) *←A₁*(GC*,X,d*) *αi* := *gi*(dk)*, ri ←*$ F *κ* 2for *i ∈* [*ℓ*] (*β,z₂*) P *←A₂*(*{ri}i∈*[*ℓ*]*,z*) If *β ̸*=*i∈*[*ℓ*]*riαi,* return false Else *Y ←A₃*(*{αi}i∈*[*ℓ*]*,z₂*) return AuDe(*D,Y*) *∈{⊥ /, C*(*x*)*}*

Unlike traditional authenticity, this relaxed definition allows an adversary to learn at most a single bit of information about dk. Using the idea of *F*OneBitAdv, we allow the adversary to define a set of functions *gi*applied to dk, specify a value *β*, and then learn if a random linear combination of the evaluations result of *gi*, denoted by *αi*, equals *β*. As a result, the adversary may learn at most one bit of information about dk. Since the linear combination is random, if the adversary confirms that the equation holds, it should know each *αi*except with negligible probability. Therefore, we can safely provide the adversary *A₃* with *αi*, and no additional information is leaked. This relaxed definition is reasonable as it offers security guarantees similar to traditional au- thenticity. If an adversary could breach the authenticity against one-bit leakage with non-negligible probability, it can also randomly guess the leaked bit by itself, and thus with probability 50% the adversary might correctly guess this bit, enabling it to produce *Y* such that AuDe(*D,Y*) *∈{⊥ /, C*(*x*)*}* with non-negligible probability. We can easily verify that both the half-gates and three-halves garbling schemes satisfy authenticity against one-bit leakage.

Definition 6. *A projective point-permute-freeXOR-compatible garbling scheme is* secure *if it achieves* *obliviousness, equivocable privacy, and authenticity against one-bit leakage.*

Our protocol is built upon the components *F*Comfor commitment, *F*OTfor oblivious transfer, *F*OLE for oblivious linear evaluation, *F*Eqfor equality testing, and *F*Randfor generating random values.

|We use standard F||and F|within our protocol. For F||, a sender inputs ∆ ∈ F|and|
|---|---|---|---|---|---|---|
|||Com|OT|OLE||κ 2|
|κ 2|κ i|κ 2|κ 2|Rand|Eq|κ|

Com OT OLE *κ* 2 *v ∈* F, while a receiver inputs *u ∈* F and learns *w* := *v ⊕ u*∆. For *F*, two parties input *x ∈{*0*,*1*}* and *y ∈{*0*,*1*}* respectively and learn whether *x* = *y*. For *F* with parameter *ℓ*, the functionality outputs random *r ←*$ F for *i ∈* [*ℓ*] to both parties.

4.2 Our Scheme We give a high-level description of our protocol *Π*OneBitAdvbelow, and the formal description of our protocol is given in Figure 1. The protocol *Π*OneBitAdvemploys a secure projective garbling scheme that is point-permute-freeXOR- compatible. It consists of three main phases: evaluation, verification, and output progressive revela- tion. –Evaluation: Each party begins by independently generating a garbled circuit for the agreed- upon circuit *C* using their respective global keys ∆Aand ∆B. They then execute two instances of garbled circuits, swapping their roles between the two instances. After evaluating the garbled circuit generated by the other party, each party derives the garbled output. They then compute the respective SPDZ-like MACs *Ai*and *Bi*based on both the derived garbled outputs and the output-wire labels of their own garbled circuits, as outlined in Section 2.3. –Verification: Both parties use *F*OLEto jointly generate an authenticated secret sharing of a ran- dom value, which serves to mask the linear combination, as detailed in Section 2.3. Additionally, they obtain a set of random values over F
*κ* 2from *F*Rand. Using this set of values as coefficients, they then perform a random linear combination on their shares and MACs of the random value and the output bits of both circuits, where the same MAC applied to corresponding output bits from both circuits. The result of this linear combination is then revealed, and *F*Eqis applied to confirm the validity of this opening. If the equality test fails, the protocol halts immediately, signaling potential cheating. –Output Progressive Revelation: In this final phase, both parties jointly reveal the evaluation result bit by bit. For each output bit, the parties exchange the point-permute bit associated with that wire and reconstruct the output bit by combining the received point-permute bit with the masked bit derived from evaluating the other party’s garbled circuit. An equality test is then conducted to validate this opening. The protocol aborts if any opening is invalid. This procedure thus ensures that the adversary’s advantage is strictly limited to a single bit.

Theorem 1. *The protocol Π*OneBitAdv*along with a secure projective garbling scheme that is point-* *permute-freeXOR-compatible securely realizes functionality F*OneBitAdv*against* PPT *malicious (rush-* *ing) adversaries in the (F*Com*, F*OT*, F*OLE*, F*Rand*, F*Eq*)-hybrid world.*

We give the sketch proof of this theorem as follows.

*Proof.* Without loss of generality, we assume that PBis honest, while PAis corrupted by the adversary

*A*. The roles of PAand PBin protocol *Π*OneBitAdvare symmetric, so a similar proof applies when PB is corrupted. For an adversary *A* corrupting PAin the (*F*Com, *F*OT, *F*OLE, *F*Rand, *F*Eq)-hybrid world, we construct a simulator *S*, which plays the role of PBand runs *A* as a subroutine with auxiliary input *z*, interacting with *F*OneBitAdvin the ideal world. The simulation is given Figure 2. We now need to prove that the joint distribution of the view of *A* and the output of PBin the ideal world is computationally indistinguishable from the joint distribution of the view of *A* and the output of PBin the real protocol execution. We give the details in Appendix A. *Remark 2.* To achieve a *k*-bit advantage bound, both parties can reveal *k* bits of the evaluation result in each iteration and verify their correctness. This verification can be conducted in batches using random linear combinations, as discussed in Section 2.3.

<u>Protocol ΠOneBitAdv</u> Public inputs: Both parties agree on the security parameter *κ* and a circuit *C*, which has *n* = *n*A+ *n*B input wires and *n*Ooutput wires. Private inputs: PAhas input *x*A*∈{*0*,*1*}* *n* A. PBhas input *x*B*∈{*0*,*1*}* *n* B.

Evaluation

1 PApicks ∆A*←*$ F *κ* 2, such that lsb(∆A) = 1. PBalso samples ∆B*←*$ F *κ* 2in the form that lsb(∆B) = 1. 2 PAgenerates the garbled circuit GC via (GC*,e,* dk*,d,D*) *←* Gb(1 *κ* *, C*; ∆A), where *e* = *{*(*Xi,*0*,Xi,*1)*}i∈*[*n*]. Similarly, PBgenerates the garbled circuit GC *′* via (GC *′* *,e* *′* *,*dk *′* *,d* *′* *,D* *′* ) *←* Gb(1 *κ* *, C*; ∆B), where *e* *′* = (*Xi,* *′* 0 *,Xi,* *′* 1 ) *i∈*[*n*]. Here dk and dk *′* can be used to derive point-permute bits (resp. output-wire labels) *λw* and *λ* *′w* (resp. L*w,*0 and L *′w,* 0 ) for each wire *w ∈W*O, respectively. Both PAand PBthen commit to their garbled circuits via *F*Com. 3 PB, as the sender, sends (*Xi,* *′* 0 *,Xi,* *′* 1 ) *i∈*[*n*] to *F*OT, while PA, acting as the receiver, sends *x*A and receives *X* *′* := *X* *′*. Meanwhile, A two parties switch their roles, with PAsending *i i,x*A[*i*] *i∈*[*n* A] *{*(*Xi,*0*,Xi,*1)*}i∈*[*n* A +1*,n*]for PB’s input-wire labels, and PB, as the OT receiver, sending *x*Band re- ceiving *Xi* := *Xi,x*B[*i−n*A] *i∈*[*n* +1*,n*]. A 4Each party sends the label they generated corresponding to their own input to the other party, *i*.*e*., PAsends *Xi* := *Xi,x*A[*i*] *i∈*[*n*] to PB, and PBsends *Xi′*:= *Xi,x* *′* B [*i−n*A] *i∈*[*n* +1*,n*]to PA. A *′* A *′* 5Both parties open their garbled circuits GC and GC to each other via *F*Com. PAevaluates GC by computing *Y* *′* := Ev(GC *′* *,X* *′* ), where *X* *′* = *{Xi′}i∈*[*n*]consists of all input-wire labels PAhas retrieved from *F*OTand received from PB. For each *w* = out(*i*), where *i ∈* [*n*O], PAsets *ai,*2 := ˆ*zw* *′* := lsb(*Yi′*) and *Ai,*2 := *Yi′*. Simultaneously, PBdefines *bi,*2 := *λ* *′w* and *Bi,*2 := L *′w,* 0*⊕ λ* *′w* ∆B. Meanwhile, PBevaluates GC by computing *Y* := Ev(GC*,X*), where *X* contains the input-wire labels PBhas retrieved and received. For each *i ∈* [*n*O], PBsets *bi,*1 := ˆ*zw* := lsb(*Yi*) and *Bi,*1 := *Yi*, while PA defines *ai,*1 := *λw* and *Ai,*1 := L*w,*0 *⊕ λw* ∆A. PAand PBcompute *Ai* := *Ai,*1 *⊕ Ai,*2 and *Bi* := *Bi,*1 *⊕ Bi,*2 for *i ∈* [*n*O], respectively.

Verification

6 PArandomly selects L₀ *←*$ F *κ* 2, and, as the sender, sends L₀ and ∆Ato *F*OLE. Meanwhile, PBsends a random *b₀ ←*$ F *κ* 2to *F*OLEand receives *B₀,*1 = L₀ *⊕ b₀*∆A. The parties switch roles, with PBsending L *′* 0*←*$ F *κ* 2and ∆Bto *F*OLE, while PAsends *a₀ ←*$ F *κ* 2and receives *A₀,*2 = L *′* 0*⊕ a₀*∆Bas the receiver. PBcomputes *B₀* := *B₀,*1 *⊕* L *′* 0*⊕ b₀*∆B, while PAcomputes *A₀* := *A₀,*2 *⊕* L₀ *⊕ a₀*∆A. 7Both parties call *F*Randto obtain random values *ri ←*$ F *κ* 2and *ri′←*$ F *κ* 2for *i ∈* [*n*O]. P P P PAthen computes *A* := *A₀ ⊕i∈*[*n* O] *r* *i* *Ai ⊕i∈*[*n* O] *r* *i′* *Ai* and *a* := *a₀ ⊕i∈*[*n* O] *r* *i* *a* *i,*1 *⊕* P*′*P P*′* *i∈*[*n*O]*riai,*2, and sends *a* to PB. PBalso computes *B* := *B₀ ⊕i∈*[*n*O]*riBi ⊕i∈*[*n*O]*riBi* P P and *b* := *b₀ ⊕i∈*[*n* O] *r* *i* *b* *i,*1 *⊕i∈*[*n* O] *r* *i′* *b* *i,*2, and sends *b* to PA. 8 PAand PBinput *A ⊕* (*a ⊕ b*)∆Aand *B ⊕* (*a ⊕ b*)∆Bto *F*Eq, respectively, to verify if the values match. If *F*Eqreturns false, parties output cheating and the protocol aborts with termination.

Output Progressive Revelation

9For *i ∈* [*n*O], PAand PBfollow the procedure below to derive each bit *yi* of the evaluation result *y*.

(a) PAsends *ai,*1 = *λw* to PB, while PBsends *bi,*2 = *λ*
*′w* to PAfor *w* = out(*i*). PAcomputes *yi′*:= *a* *i,*2 *⊕ bi,*2 and PBcomputes *yi* := *ai,*1 *⊕ bi,*1.

(b) PAinputs *Ai ⊕ yi′*∆Ato *F*Eq, and PBinputs *Bi ⊕ yi*∆Bto *F*Eq. If *F*Eqreturns false, parties output *⊥* with abortion. Otherwise, the *i*th bit of the evaluation result is output by both PAand PBas *y* *i′*and *yi*, respectively.
Fig. 1: Our constant-round 2PC protocol achieving active security with one-bit advantage bound in

the (*F*Com, *F*OT, *F*OLE, *F*Rand, *F*Eq)-hybrid world.

1 *S* samples ∆B*←*$ F *κ* 2, such that lsb(∆B) = 1, as in the protocol. 2 *S* computes (GC *′* *,X* *′* *,z*) *←S*Gb(1 *κ* *, C*), where *X* *′* = *{Xi′}i∈*[*n* O]. Let *Y* *′* = *{Yi′}i∈*[*n* O]= Ev(GC *′* *,X* *′* ). For each output wire *w* = out(*i*), *S* defines ˆ*zw* *′* = lsb(*Yi′*). Acting as *F*Com, *S* informs the adversary *A* that the honest party PBhas committed his garbled circuit to *F*Com. Subsequently, *S* obtains the garbled circuit GC from *A*. 3If PAis the receiver in *F*OT, *S* receives *x*Afrom *A*, sends *{Xi′}i∈*[*n* A]to *A*. Then *S* sends *x*Ato *F*OneBitAdv. If PAacts as the sender in *F*OT, *S* receives *{*(*Xi,*0*,Xi,*1)*}i∈*[*n* A +1*,n*]from *A*. 4 *S* sends *{Xi′}i∈*[*n* A +1*,n*]to *A* and receives *{Xi}i∈*[*n*A]from *A*. 5Acting as *F*Com, *S* opens GC *′* to *A*. 6In the role of receiver in *F*OLE, *S* receives L₀ and ∆ˆAfrom *A*. As the sender, *S* receives *a₀* from *A* and returns *A₀,*2 *←*$ F *κ* 2to *A*. Set L *′* 0:= *A₀,*2 *⊕ a₀*∆B. 7For each *i ∈* [*n*O], *S* defines the Boolean function *gi* (resp. *gi′*) with fixed input *x*Aand variable *x*B*∈{*0*,*1*}* *n* Bas follows. Note that corresponding values are hard-coded in *g* *i* and *gi′*.

(a)Let *Xi* := *Xi,x*B[*i−n*A]for *i ∈* [*n*A+ 1*,n*].
(b)Compute *Y* := Ev(GC*,X*), where *X* = *{Xi}i∈*[*n*].
(c)Define *Bi,*1 := *Yi* and *bi,*1 := ˆ*zw* = lsb(*Yi*) for *w* = out(*i*).
(d)Compute *y* := *C*(*x*A*,x*B), where *y* = (*y₁, ··· ,yn*O) *∈{*0*,*1*}*
*n* O.

(e)Let *λ* *′w* := *yi ⊕ z*ˆ*w*
*′* (*i*.*e*., this is what is done by *S*Gb *′* with respect to equivocable privacy), and define *bi,*2 := *λ* *′w* for *w* = out(*i*).

(f)Set *Bi,*2 := *Yi′⊕ yi*∆Band *Bi* := *Bi,*1 *⊕ Bi,*2.
(g)Output *αi* := *Bi ⊕ bi,*1∆ˆA*⊕ bi,*1∆B(resp. *αi′*:= *Bi ⊕ bi,*2∆ˆA*⊕ bi,*2∆B). *S* sends *{gi,gi′}i∈*[*n*
O]to *F*OneBitAdv, receives random values *{ri,ri′}i∈*[*n*O], and forwards these values to *A* with respect to *F*Rand. *S* randomly selects *b ←*$ F *κ* 2and sends it to *A*, while receiving *a ∈* F *κ* 2from *A*. 8 *S* receives *β*ˆ *∈* F *κ* 2from *A* with respect to *F*Eq, computes *β* := *β* ˆ *⊕ b*∆ˆ A*⊕* L₀ *⊕* L *′* 0*⊕ a*∆B, sends it to *F*OneBitAdv, and receives the output. If the output is false, *S* simulates rejection by honest PB. Otherwise, receive *{*(*αi,αi′*)*}i∈*[*n* O]from *F*OneBitAdv. 9For each *i ∈* [*n*O], *S* follows the procedure below.

(a) *S* receives *yi* from *F*OneBitAdv, computes *bi,*2 = *λ*
*′w* := *yi ⊕ z*ˆ*w* *′* for *w* = out(*i*), sends it to *A*, and receives *ai,*1 from *A*.

(b) *S* receives *α*˜*i* with respect to *F*Eq. Then *S* computes ˆ*bi,*1 := *yi ⊕ ai,*1 and checks if *αi ⊕* ˆ*bi,*1∆B*⊕* ˆ *b* *i,*1∆ ˆ A= *αi′⊕ bi,*2∆B*⊕ bi,*2∆
ˆ A. If the equation does not hold, *S* simulates rejection by PBand sends abort to *F*OneBitAdv. Then *S* checks if *α*˜*i* = *αi ⊕ ai,*1∆B*⊕ ai,*1∆ˆA*⊕ yi*∆ˆA. If the equation does not hold, *S* simulates rejection by PBand sends abort to *F*OneBitAdv. Otherwise, *S* sends continue to *F*OneBitAdv, outputs whatever *A* outputs and continues.

Fig. 2: The simulator *S* with respect to *F*OneBitAdvin the ideal world.

## Improvements and Optimizations

Our protocol is actively secure and already highly efficient, but we briefly discuss some additional improvements and optimizations that can be further applied. As with other 2PC protocols utiliz- ing garbled circuits, we can leverage cost-effective correlated oblivious transfer and oblivious linear evaluation to improve efficiency. We can also apply circuit pipelining, allowing parties to transmit gar- bled gates while simultaneously evaluating the garbled circuit. Additionally, we introduce approaches specifically applicable to our protocol as follows.

Leveraging *F*Randfor free. Since we use standard garbling schemes, garbled circuits GC and GC *′*

in the protocol have high entropy. Therefore, two parties can generate pseudorandom values non- interactively by employing a pseudorandom function, where GC and GC *′* are collectively used to derive the key, to generate necessary random values in CTR mode. Randomize order of output revelation. We can further limit adversaries’ advantage by random- izing the order of output bit revelation. Both parties can collaboratively generate a random per- mutation *P* over [*n*O], defining the sequence for output bit disclosure. We can also use a similar method to determine which party reveals the output bits first for each iteration. The required randomness can be generated non-interactively, as described above. Optimizations in the random-oracle model. Since our protocol uses standard garbling schemes, all values involved in the equality test maintain high entropy when unknown to the adversary. Therefore, to perform an equality test with inputs *a* and *b*, both parties can simply commit to and open H(*a*) and H(*b*), respectively, where H is modeled as a random oracle, then verify if H(*a*) = H(*b*). We can also use the random oracle for commitment by defining Com(*m*; *r*) = H(*m,r*), where *r ←*$ *{*0*,*1*}* *κ*. With this setup, we can further reduce rounds in the progressive output revelation phase. For the *i*th output, PAcan first commit to both H(*Ai*) and H(*Ai⊕* ∆A) using the same randomness *r* *i*, while PBcommits to H(*Bi*) and H(*Bi⊕* ∆B) using randomness *ri′*. Note that it is essential to ensure that commitments from the two parties are distinct to prevent an adversary from copying the honest party’s commitments and decommitments. They decommit by exchanging *ri*and *ri′*, allowing each party to derive the output bit: for instance, if H(*Ai*) matches PB’s first commitment, PAconcludes *yi*= 0; if H(*Ai⊕*∆A) is PB’s second committed value, then *yi*= 1. If neither matches, the output is rejected. Furthermore, commitments for the *i*th output bit can be sent alongside decommitments for the (*i −* 1)-th output, thus requiring only *n*O+ 1 rounds to reveal and verify all output bits. In protocols with *k*-bit advantage bound, enumerating all possible *k*-bit outputs may be relatively expensive. Therefore, both parties can simply perform *k* parallel iterations of 1-bit revelation.

## 6 Performance

6.1 Comparison In the following, we argue that each phase of our protocol incurs low additional overhead compared to the passively secure counterparts. Evaluation. Steps 1 to 4 are nearly identical to those in passively secure protocols, aside from the use of actively secure OT protocols. It is well-known that actively secure OTs are highly efficient and perform comparably to passively secure OTs in both local area network (LAN) and wide area network (WAN). If the input lengths of the two parties are asymmetric, *e*.*g*., if PAhas a longer input while PB’s input is shorter, then passively secure protocols may require fewer OTs. But we note that OTs are employed solely for retrieving input-wire labels, so for large circuits, they contribute only a small fraction of the overall protocol cost. Sending and evaluating garbled circuits in Step 5 remain the same as in passively secure protocols. The primary difference of Step 5 lies in computing (*Ai,*1*,Ai*) and (*Bi,*2*,Bi*); however, only XOR operations over *{*0*,*1*}*
*κ* are required, amounting to 2*n*OXORs per party. This added overhead is minimal. It is easy to see that this phase requires only a small constant number of rounds. Verification. The execution cost of two oblivious linear evaluations in Step 6 is constant. As dis- cussed in Section 5, randomness in Step 7 can be generated efficiently and non-interactively. Given that *ai,*, *ai,*, *bi,*, and *bi,*are bits, the computations of *a* and *b* in Step 7 involve only XOR

operations over *{,}* *κ*, with 2*n*OXORs per party. For the computations of *A* and *B*, each party performs 2*n*Omultiplications and additions (*i*.*e*., XORs) over F *κ*. Therefore, the computational overhead of these operations is minimal. The communication cost of Step 7 involves only the exchange of two elements in F *κ*

2. For the equality test in Step 8, employing the optimizations
described in Section 5, one hash value (serving as a commitment) and a single *κ*-bit opening are required; there is no need to send the committed hash value for the equality test since, if the test passes, the other party must possess this value. This phase also requires only a small constant number of rounds. Output Progressive Revelation. Utilizing the optimizations via random oracles in Section 5, the output progressive revelation phase can be implemented in *n*O+ 1 rounds, which is *nearly optimal* for realizing output progressive revelation in 2PC. In each round, both parties compute two hash values, exchanging these along with one *κ*-bit opening. Both the communication and computation costs are minimal. The same efficiency also applies when releasing *k* bits of output per round.

Moreover, we note that upon successful completion of the verification phase, both parties are secretly sharing a consistent and correct evaluation result. We assert the correctness of the evaluation result here because garbled circuits generated by honest parties must yield correct output. As a result, even if all *n*Obits of the evaluation result are revealed in a single iteration (*i*.*e*., under *n*O-bit advantage bound) during output progressive revelation and the adversary forces an abort, the adversary gains only the additional knowledge that its garbled circuit output aligns with that of the honest party. This differs from one-bit-leakage protocols, where adversary could learn the correct evaluation result even if the equality test fails. The security guarantees of our protocol approach those of traditional active security with abort. In addition, achieving verifiable output progressive revelation is a non-trivial task for actively secure protocols, and it often involves additional overhead. Therefore, our protocol achieves both high efficiency and high security guarantees.

6.2 Implementation and Evaluation We provide a proof-of-concept implementation to demonstrate the performance of our protocol. All experiments are conducted on an ecs.hfr7.4xlarge instance of Alibaba Cloud, equipped with 128 GiB of memory. Each party is run on a 3*.*69 GHz vCPU core in single-threaded mode. The protocol is evaluated under both LAN and WAN settings: in the LAN configuration, the network bandwidth is 2 Gbps with 0*.*1 ms latency; in the WAN configuration, the bandwidth is 200 Mbps with 60 ms latency. Our implementation builds upon the EMP-Toolkit [33]. This implementation includes methods for non-interactive randomness generation and optimiza- tions in the random-oracle model, as described in Section 5. Specifically, we utilize AES-NI in CTR mode as a pseudorandom generator (PRG) and SHA-256 to instantiate the random oracle. Given recent results [16,6] that the half-gates scheme [38] outperforms the three-halves scheme [32] in many practical scenarios and has more mature implementations, we use the half-gates scheme [38] in our proof-of-concept implementation to benchmark against passively secure protocols that also employ this scheme. We note that comparable results should hold for the three-halves scheme [32].
Table 1: Evaluated Boolean circuits. The parameters *n*A, *n*B, and *n*Odenote the bit lengths of PA’s
 input, PB’s input, and the circuit output, respectively. The total number of gates and AND gates are also listed.
Circuit *n*A*n*B*n*O#Total gates #AND gates

AES-128 128 128 128 33,616 6,800 SHA-128 256 256 160 106,601 37,300 SHA-256 256 256 256 236,112 90,825 Hamming Dist. 1,048,576 1,048,576 22 8,388,524 2,097,130 Integer Mult. 2,048 2,048 2,048 12,568,585 4,192,257 Sorting 131,072 131,072 131,072 56,903,681 10,223,616

We compare the running time and communication overhead of our protocol with state-of-the-art passively and actively secure 2PC implementations based on garbled circuits (GC). The running time

includes both computational costs and network I/O, while the communication overhead is defined as the cumulative size of all messages exchanged between the parties. To ensure a fair compari- son with protocols lacking progressive revelation, we release all outputs simultaneously during the progressive revelation phase of our protocol. Our comparison covers circuits are commonly used in previous work (*e*.*g*., [9,20,13]) and representative of the primary categories encountered in practical applications. Table 1 details these circuits, either sourced from SCALE-MAMBA [25] or generated using EMP-Toolkit [33]. Specifically, the Boolean circuit AES-128 computes the encrypted value of a 128- bit input using a 128-bit key, while SHA-128 and SHA-256 compute the hash values of 128-bit and 256-bit inputs, respectively. The Hamming distance circuit calculates the Hamming distance between two 2 20 -bit large integers. The integer multiplication circuit involves multiplying two 2048-bit large integers. The sorting circuit sorts an array containing 4096 32-bit integers using the bitonic sorting algorithm. The number of AND gates for AES-128, SHA-128, and SHA-256 ranges from 10 3 to 10 5, which corresponds to small circuits, while the number of AND gates for Hamming distance, integer multiplication, and sorting ranges from 10 6 to 10 7, which corresponds to large circuits. Note that the input sizes for Hamming distance, integer multiplication, and sorting are custom-defined and widely used as benchmarks in MPC literature.

Table 2: Comparison of running time between the passively and actively secure GC-based 2PC pro-

tocol and our protocol in LAN. Runtime for LAN (ms) Circuits Ours Passive 2PC [38] Slowdown Active 2PC [34] Speedup

||Ours|Passive 2PC [38]||Slowdown|Active 2PC [34]|Speedup|
|---|---|---|---|---|---|---|
|AES-128|5.186|3.917||1.324×|35.765|6.896×|
|SHA-128|21.420|20.109||1.065×|170.425|7.956×|
|SHA-256|50.800|49.177||1.033×|408.673|8.045×|
|Hamming Dist.|1,130.237|1,125.191||1.004×|10,386.330|9.190×|
|Integer Mult.|2,134.655|2,119.995||1.092×|18,481.636|8.658×|
|Sorting|5,687.642|5,676.164||1.002×|46,234.423|8.129×|

Table 3: Comparison of running time between the passively and actively secure GC-based 2PC pro-

tocol and our protocol in WAN.

|Circuits||Runtime for WAN (ms)||||
|---|---|---|---|---|---|
||Ours|Passive 2PC [38]|Slowdown|Active 2PC [34]|Speedup|
|AES-128|355.447|21.664|16.407×|636.300|1.790×|
|SHA-128|555.088|164.875|3.366×|1,291.858|2.328×|
|SHA-256|782.826|266.713|2.935×|2,648.022|3.383×|
|Hamming Dist.|5,742.006|3,645.433|1.575×|60,855.122|10.598×|
|Integer Mult.|11,460.162|7,353.140|1.559×|108,088.760|9.431×|
|Sorting|26,767.659|17,687.417|1.513×|237,419.610|8.870×|

Running Time in the LAN and WAN Setting. Tables 2 and 3 compares the running time of the proposed 2PC protocol with passively and actively secure GC-based 2PC protocols in both LAN and WAN. Compared to the passively secure GC-based 2PC protocol [38], the results indicate that over a LAN, our protocol incurs an overhead of up to 32*.*4%, consistent with our prior analysis. In a WAN environment, however, the overhead more than doubles for small circuits (*i*.*e*., AES-128, SHA-128, and SHA-256) and remains around 50% for larger circuits (*i*.*e*., Hamming Distance, Integer Multiplication, and Sorting). This elevated overhead for smaller circuits is because network I/O dominates the total running time for small-size circuits. As shown in Figure 1, our protocol consists of three phases: 1) evaluation, 2) verification, and 3) output progressive revelation. For small circuits such as AES-128, the evaluation phase takes 37*.*21 ms, while the verification and output progressive revelation phases together require 318*.*237 ms, accounting for 89*.*53% of the total running time.The overhead of the

latter two phases is mainly due to the 5 rounds of communication introduced, with each round incurring a 60 ms delay in the WAN setting. On the other hand, for larger circuits, the evaluation phase of the protocol constitutes over 95% of the total running time. The other two phases have minimal running time, but due to the 200 Mbps bandwidth limit and cost of synchronization in the WAN setting, the evaluation phase of our protocol, which requires parallel instance computation, is more significantly impacted by the network limitation. Compared to the state-of-the-art actively secure GC-based 2PC protocol implementation [34], our protocol achieves significantly better running time in both LAN and WAN settings, as expected, with an improvement factor of 6*.*9*−*10*.*6*×*, except for small circuits (*i*.*e*., AES-128, SHA-128, and SHA-256) in the WAN setting, where the improvement is only 1*.*8*−*3*.*4*×*. The reason for this is similar to the above. For small circuits in the WAN setting, the verification and output progressive revelation phases introduced by our protocol add approximately 300 ms of network I/O time, which is on the same order of magnitude as the running time of the evaluation phase. This results in some communication advantage of our protocol being offset by the overhead introduced by these phases. However, in the LAN setting or for large circuit evaluations in the WAN setting, network I/O time accounts for less than 5%, which allows our protocol to achieve significant performance improvements due to the low- overhead circuit computation phase. This indicates that our protocol is highly efficient compared to existing actively secure GC-based 2PC protocols.

Table 4: Comparison of communication costs (MiB) between passively and actively secure GC-based

2PC protocols and our protocol, where PAis the garbler and PBis the evaluator in the passively and actively secure GC-based 2PC protocols. <u>Passive 2PC [38] Our Protocol Active 2PC [34]</u> Circuits PA’s PB’s Total PA’s PB’s Total PA’s PB’s Total

AES-128 0.207 0.003 0.210 0.214 0.214 0.428 1.908 1.358 3.266 SHA-128 1.138 0.003 1.141 1.146 1.146 2.292 10.429 7.430 17.859 SHA-256 2.772 0.002 2.774 2.784 2.784 5.568 25.367 18.080 43.446 Hamming Dist. 63.999 0.163 64.162 64.163 64.163 128.326 655.255 455.257 1,110.497 Integer Multi. 127.938 0.002 127.940 128.034 128.034 256.068 1170.087 834.178 2,004.265 Sorting 312.000 0.002 312.002 312.240 312.240 624.480 2862.491 2038.866 4,901.358

Communication Cost. Table 4 presents a comparison of per-party and total communication over- head between our protocol and both passively and actively secure 2PC protocols. In passively and actively secure GC-based 2PC protocols, PAis the garbler while PBis the evaluator. In passively secure GC-based 2PC protocols, PAneeds to generate and send a large number of garbled circuits to PB, with communication costs proportional to the number of AND gates. In contrast, most of PB’s tasks involve performing the GC evaluation locally without requiring extensive communication. As a result, the communication cost for PAis significantly higher than that for PB. In actively secure GC-based 2PC protocols, although PAacts as the garbler, the garbled circuits are generated jointly with PB. Consequently, the communication cost for PAis higher than that for PB, though both costs remain within the same order of magnitude. In our protocol, PAand PBperform GC evaluations sym- metrically and exchange data of nearly identical size during the verification and output progressive revelation phases, resulting in equal communication costs for both parties. In terms of total communication, our protocol’s communication cost is double that of the passively secure 2PC protocol, as it requires two symmetric GC evaluations to compute a circuit. However, compared to the actively secure 2PC protocol, our protocol achieves a 7*.*6*−*8*.*6*×* reduction in com- munication cost by eliminating complex verification overhead, highlighting its high communication efficiency. Cost Breakdown of Our Low-Overhead Protocol Execution. We analyze our protocol by breaking down the execution cost of each component for AES-128, SHA-128, SHA-256, Hamming distance, integer multiplication, and sorting circuits. As previously outlined, our protocol is divided into three phases: evaluation, verification, and output progressive revelation. We measured the average wall-clock time for each phase of a single protocol execution in both LAN and WAN settings. As shown in Figure 3, circuit evaluation in the first phase accounts for 93*.*88% to 99*.*80% of the total runtime

AES-128 Evaluation AES-128 Evaluation Verification Verification SHA-128 Output Progressive Revelation SHA-128 Output Progressive Revelation

SHA-256 SHA-256

Integer Mult. Integer Mult.

Hamming Dist. Hamming Dist.

Sorting Sorting 0 1000 2000 3000 4000 5000 6000 0 5000 10000 15000 20000 25000 30000

(a) Running time for LAN (ms) (b) Running time for WAN (ms)
Fig. 3: Cost breakdown of our low-overhead protocol execution in the LAN and WAN settings.

for most circuits. The verification and output progressive revelation phases we introduced contribute only a very small portion to the total runtime. This is because the evaluation phase incurs overhead proportional to the number of AND gates, while the verification and output progressive revelation phases scale linearly with the output length *n*O. Since the output length *n*Ois generally much smaller than the number of AND gates in most circuits, our protocol achieves high efficiency. Different Progressive Revelation Factors. Our protocol supports adjustable output progressive revelation, allowing the adversary’s one-bit advantage to be extended to an arbitrary-bit advantage. This flexibility can reduce the number of communication rounds, making it valuable in scenarios where the size of evaluation result is large or network latency is high, thus achieving a trade-off between security and efficiency. To assess this, we conducted experiments to evaluate the impact of the progressive revelation factor on performance. Table 5 presents the average running time required to release each output bit, calculated by dividing the total running time of the output progressive revelation phase by the output size, with the revelation factor set to *k*. The reported data was obtained using the AES-128 circuit. However, since the output progressive revelation phase of our protocol depends only on the output size and is independent of the specific circuit used, the results in Table 5 are generalizable and not tied to a particular circuit. As shown in the table, as *k* increases, the running time initially decreases rapidly and then plateaus in both LAN and WAN settings. The running time with *k* = 1 is 68*.*3*×* longer than with *k* = 128 in the LAN setting and 114*.*6*×* longer in the WAN setting. The impact on running time primarily stems from the reduction in the number of communication rounds in the protocol’s output progressive revelation phase, which is calculated as *⌈n*O*/k⌉* + 1, where *n*Ois the output length of the circuits. Hence, as *k* increases, the number of communication rounds decreases significantly, resulting in a proportional reduction in network I/O time. This effect is particularly beneficial for communication-sensitive applications.

Table 5: The impact of different progressive revelation factors *k* on the protocol’s running time,

assuming the circuit’s output length exceeds *k*.

|Revelation factor|Running time for LAN|Running time for WAN|
|---|---|---|
|||− 3|
|k = 1|119.594 × 10|ms 60.50 ms|
|||− 3|
|k = 8|18.352 × 10|ms 7.503 ms|
|||− 3|
|k = 32|4.563 × 10|ms 1.876 ms|
|||− 3|
|k = 64|1.898 × 10|ms 0.938 ms|
|||− 3|
|k = 128|1.750 × 10|ms 0.528 ms|

## 7 Acknowledgements

We would like to express our sincere appreciation to the anonymous reviewers for their valuable comments. This work was supported in part by National Key Research and Development Pro- gram of China under Grant No. 2021ZD0112802, in part by National Natural Science Foundation

of China under Grant Nos. 62302194, 62472198, 62072215, 62250710682, 62332007, and U22B2028, in part by Guangzhou Basic and Applied Basic Research Foundation under Grant Nos. 2025A04J2146, 2024A03J0405, and 2024A04J3458, in part by Guangdong Basic and Applied Basic Research Foun- dation under Grant Nos. 2023B1515040020 and 2019B030302008, in part by Science and Technology Major Project of Tibetan Autonomous Region of China (No. XZ202201ZD0006G), in part by Open Research Fund of Machine Learning and Cyber Security Interdiscipline Research Engineering Center of Jiangsu Province (No. SDGC2131), in part by HKU-SCF FinTech Academy and Shenzhen-Hong Kong-Macao Science and Technology Plan Project (Category C Project: SGDX20210823103537030) and Theme-based Research Scheme T35-710/20-R, and in part by National Joint Engineering Re- search Center of Network Security Detection and Protection Technology, Guangdong Key Laboratory of Data Security and Privacy Preserving, Guangdong Hong Kong Joint Laboratory for Data Security and Privacy Protection, and Engineering Research Center of Trustworthy AI, Ministry of Education.

## References

1.Abascal, J., Sereshgi, M.H.F., Hazay, C., Ishai, Y., Venkitasubramaniam, M.: Is the classical GMW paradigm practical? the case of non-interactive actively secure 2pc. In: Ligatti, J., Ou, X., Katz, J., Vigna, G. (eds.) CCS ’20: 2020 ACM SIGSAC Conference on Computer and Communications Security, Virtual Event, USA, November 9-13, 2020. pp. 1591–1605. ACM (2020)
2.Beaver, D., Micali, S., Rogaway, P.: The round complexity of secure protocols (extended abstract). In: Ortiz, H. (ed.) Proceedings of the 22nd Annual ACM Symposium on Theory of Computing, May 13-17, 1990, Baltimore, Maryland, USA. pp. 503–513. ACM (1990)
3.Bellare, M., Hoang, V.T., Keelveedhi, S., Rogaway, P.: Efficient garbling from a fixed-key blockcipher. In: 2013 IEEE Symposium on Security and Privacy, SP 2013, Berkeley, CA, USA, May 19-22, 2013. pp. 478–492. IEEE Computer Society (2013)
4.Bellare, M., Hoang, V.T., Rogaway, P.: Foundations of garbled circuits. In: Yu, T., Danezis, G., Gligor,
V.D. (eds.) the ACM Conference on Computer and Communications Security, CCS’12, Raleigh, NC, USA, October 16-18, 2012. pp. 784–796. ACM (2012)
5.Blum, M.: How to exchange (secret) keys. ACM Trans. Comput. Syst. 1(2), 175–193 (1983)
6.Br¨uggemann, A., Hundt, R., Schneider, T., Suresh, A., Yalame, H.: FLUTE: fast and secure lookup table evaluations. In: 44th IEEE Symposium on Security and Privacy, SP 2023, San Francisco, CA, USA, May 21-25, 2023. pp. 515–533. IEEE (2023)
7.Cui, H., Wang, X., Yang, K., Yu, Y.: Actively secure half-gates with minimum overhead under duplex networks. In: Hazay, C., Stam, M. (eds.) Advances in Cryptology-EUROCRYPT 2023 - 42nd Annual International Conference on the Theory and Applications of Cryptographic Techniques, Lyon, France, April 23-27, 2023, Proceedings, Part II. Lecture Notes in Computer Science, vol. 14005, pp. 35–67. Springer (2023)
8.Damg˚ard, I.: Practical and provably secure release of a secret and exchange of signatures. J. Cryptol. 8(4), 201–222 (1995)
9.Disser, Y., G¨unther, D., Schneider, T., Stillger, M., Wigandt, A., Yalame, H.: Breaking the size bar- rier: Universal circuits meet lookup tables. In: Guo, J., Steinfeld, R. (eds.) Advances in Cryptology-ASIACRYPT 2023 - 29th International Conference on the Theory and Application of Cryptology and Information Security, Guangzhou, China, December 4-8, 2023, Proceedings, Part I. Lecture Notes in Computer Science, vol. 14438, pp. 3–37. Springer (2023)
10.Dittmer, S., Ishai, Y., Lu, S., Ostrovsky, R.: Authenticated garbling from simple correlations. In: Dodis,
Y., Shrimpton, T. (eds.) Advances in Cryptology-CRYPTO 2022 - 42nd Annual International Cryptology Conference, CRYPTO 2022, Santa Barbara, CA, USA, August 15-18, 2022, Proceedings, Part IV. Lecture Notes in Computer Science, vol. 13510, pp. 57–87. Springer (2022)
11.Even, S., Goldreich, O., Lempel, A.: A randomized protocol for signing contracts. Commun. ACM 28(6), 637–647 (1985)
12.Goldreich, O., Micali, S., Wigderson, A.: How to play any mental game or A completeness theorem for protocols with honest majority. In: Aho, A.V. (ed.) Proceedings of the 19th Annual ACM Symposium on Theory of Computing, 1987, New York, New York, USA. pp. 218–229. ACM (1987)
13.G¨unther, D., Schmidt, J., Schneider, T., Yalame, H.: FLUENT: A tool for efficient mixed-protocol semi- private function evaluation. In: Annual Computer Security Applications Conference, ACSAC 2024, Hon- olulu, Hawaii, USA, December 9-13, 2024. pp. 1–14. ACM (2024)
14.Guo, C., Katz, J., Wang, X., Weng, C., Yu, Y.: Better concrete security for half-gates garbling (in the multi-instance setting). In: Micciancio, D., Ristenpart, T. (eds.) Advances in Cryptology-CRYPTO 2020
- 40th Annual International Cryptology Conference, CRYPTO 2020, Santa Barbara, CA, USA, August 17-21, 2020, Proceedings, Part II. Lecture Notes in Computer Science, vol. 12171, pp. 793–822. Springer (2020)

15.Guo, C., Katz, J., Wang, X., Yu, Y.: Efficient and secure multiparty computation from fixed-key block ciphers. In: 2020 IEEE Symposium on Security and Privacy, SP 2020, San Francisco, CA, USA, May 18-21, 2020. pp. 825–841. IEEE (2020)
16.Hamacher, K., Kussel, T., Schneider, T., Tkachenko, O.: PEA: practical private epistasis analysis using MPC. In: Atluri, V., Pietro, R.D., Jensen, C.D., Meng, W. (eds.) Computer Security-ESORICS 2022 - 27th European Symposium on Research in Computer Security, Copenhagen, Denmark, September 26-30, 2022, Proceedings, Part III. Lecture Notes in Computer Science, vol. 13556, pp. 320–339. Springer (2022)
17.Hazay, C., Shelat, A., Venkitasubramaniam, M.: Going beyond dual execution: MPC for functions with efficient verification. In: Kiayias, A., Kohlweiss, M., Wallden, P., Zikas, V. (eds.) Public-Key Cryptography
- PKC 2020 - 23rd IACR International Conference on Practice and Theory of Public-Key Cryptography, Edinburgh, UK, May 4-7, 2020, Proceedings, Part II. Lecture Notes in Computer Science, vol. 12111, pp. 328–356. Springer (2020)
18.Hong, C., Katz, J., Kolesnikov, V., Lu, W., Wang, X.: Covert security with public verifiability: Faster, leaner, and simpler. In: Ishai, Y., Rijmen, V. (eds.) Advances in Cryptology-EUROCRYPT 2019 - 38th Annual International Conference on the Theory and Applications of Cryptographic Techniques, Darmstadt, Germany, May 19-23, 2019, Proceedings, Part III. Lecture Notes in Computer Science, vol. 11478, pp. 97–121. Springer (2019)
19.Huang, Y., Katz, J., Evans, D.: Quid-pro-quo-tocols: Strengthening semi-honest protocols with dual execution. In: IEEE Symposium on Security and Privacy, SP 2012, 21-23 May 2012, San Francisco, California, USA. pp. 272–284. IEEE Computer Society (2012)
20.Huang, Z., Lu, W., Wang, Y., Hong, C., Wei, T., Chen, W.: *Coral:* maliciously secure computation framework for packed and mixed circuits. In: Luo, B., Liao, X., Xu, J., Kirda, E., Lie, D. (eds.) Proceedings of the 2024 on ACM SIGSAC Conference on Computer and Communications Security, CCS 2024, Salt Lake City, UT, USA, October 14-18, 2024. pp. 810–824. ACM (2024)
21.Impagliazzo, R., Yung, M.: Direct minimum-knowledge computations. In: Pomerance, C. (ed.) Advances in Cryptology-CRYPTO ’87, A Conference on the Theory and Applications of Cryptographic Techniques, Santa Barbara, California, USA, August 16-20, 1987, Proceedings. Lecture Notes in Computer Science, vol. 293, pp. 40–51. Springer (1987)
22.Katz, J., Ranellucci, S., Rosulek, M., Wang, X.: Optimizing authenticated garbling for faster secure two- party computation. In: Shacham, H., Boldyreva, A. (eds.) Advances in Cryptology-CRYPTO 2018 - 38th Annual International Cryptology Conference, Santa Barbara, CA, USA, August 19-23, 2018, Proceedings, Part III. Lecture Notes in Computer Science, vol. 10993, pp. 365–391. Springer (2018)
23.Kolesnikov, V., Mohassel, P., Riva, B., Rosulek, M.: Richer efficiency/security trade-offs in 2pc. In: Dodis,
Y., Nielsen, J.B. (eds.) Theory of Cryptography - 12th Theory of Cryptography Conference, TCC 2015, Warsaw, Poland, March 23-25, 2015, Proceedings, Part I. Lecture Notes in Computer Science, vol. 9014, pp. 229–259. Springer (2015)
24.Kolesnikov, V., Schneider, T.: Improved garbled circuit: Free XOR gates and applications. In: Aceto,
L., Damg˚ard, I., Goldberg, L.A., Halld´orsson, M.M., Ing´olfsd´ottir, A., Walukiewicz, I. (eds.) Automata, Languages and Programming, 35th International Colloquium, ICALP 2008, Reykjavik, Iceland, July 7-11, 2008, Proceedings, Part II-Track B: Logic, Semantics, and Theory of Programming & Track C: Security and Cryptography Foundations. Lecture Notes in Computer Science, vol. 5126, pp. 486–498. Springer (2008)
25.Leuven, K.: SCALE and MAMBA. [https://github.com/KULeuven-COSIC/SCALE-MAMBA/](https://github.com/KULeuven-COSIC/SCALE-MAMBA/) (2018)
26.Liu, Y., Lai, J., Wang, Q., Qin, X., Yang, A., Weng, J.: Robust publicly verifiable covert security: Limited information leakage and guaranteed correctness with low overhead. In: Guo, J., Steinfeld, R. (eds.) Ad- vances in Cryptology-ASIACRYPT 2023 - 29th International Conference on the Theory and Application of Cryptology and Information Security, Guangzhou, China, December 4-8, 2023, Proceedings, Part I. Lecture Notes in Computer Science, vol. 14438, pp. 272–301. Springer (2023)
27.Mohassel, P., Franklin, M.K.: Efficiency tradeoffs for malicious two-party computation. In: Yung, M., Dodis, Y., Kiayias, A., Malkin, T. (eds.) Public Key Cryptography-PKC 2006, 9th International Con- ference on Theory and Practice of Public-Key Cryptography, New York, NY, USA, April 24-26, 2006, Proceedings. Lecture Notes in Computer Science, vol. 3958, pp. 458–473. Springer (2006)
28.Mohassel, P., Riva, B.: Garbled circuits checking garbled circuits: More efficient and secure two-party computation. In: Canetti, R., Garay, J.A. (eds.) Advances in Cryptology-CRYPTO 2013 - 33rd Annual Cryptology Conference, Santa Barbara, CA, USA, August 18-22, 2013. Proceedings, Part II. Lecture Notes in Computer Science, vol. 8043, pp. 36–53. Springer (2013)
29.Naor, M., Pinkas, B., Sumner, R.: Privacy preserving auctions and mechanism design. In: Feldman, S.I., Wellman, M.P. (eds.) Proceedings of the First ACM Conference on Electronic Commerce (EC-99), Denver, CO, USA, November 3-5, 1999. pp. 129–139. ACM (1999)
30.Rindal, P., Rosulek, M.: Faster malicious 2-party secure computation with online/offline dual execution. In: Holz, T., Savage, S. (eds.) 25th USENIX Security Symposium, USENIX Security 16, Austin, TX, USA, August 10-12, 2016. pp. 297–314. USENIX Association (2016)

31.Rindal, P., Rosulek, M.: Malicious-secure private set intersection via dual execution. In: Thuraisingham,
B., Evans, D., Malkin, T., Xu, D. (eds.) Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security, CCS 2017, Dallas, TX, USA, October 30 - November 03, 2017. pp. 1229–
1242. ACM (2017)
32.Rosulek, M., Roy, L.: Three halves make a whole? beating the half-gates lower bound for garbled circuits. In: Malkin, T., Peikert, C. (eds.) Advances in Cryptology-CRYPTO 2021 - 41st Annual International Cryptology Conference, CRYPTO 2021, Virtual Event, August 16-20, 2021, Proceedings, Part I. Lecture Notes in Computer Science, vol. 12825, pp. 94–124. Springer (2021)
33.Wang, X., Malozemoff, A.J., Katz, J.: EMP-toolkit: Efficient MultiParty computation toolkit. https: //github.com/emp-toolkit (2016)
34.Wang, X., Ranellucci, S., Katz, J.: Authenticated garbling and efficient maliciously secure two-party computation. In: Thuraisingham, B., Evans, D., Malkin, T., Xu, D. (eds.) Proceedings of the 2017 ACM SIGSAC Conference on Computer and Communications Security, CCS 2017, Dallas, TX, USA, October 30 - November 03, 2017. pp. 21–37. ACM (2017)
35.Yang, K., Wang, X., Zhang, J.: More efficient MPC from improved triple generation and authenticated garbling. In: Ligatti, J., Ou, X., Katz, J., Vigna, G. (eds.) CCS ’20: 2020 ACM SIGSAC Conference on Computer and Communications Security, Virtual Event, USA, November 9-13, 2020. pp. 1627–1646. ACM (2020)
36.Yao, A.C.: Protocols for secure computations (extended abstract). In: 23rd Annual Symposium on Foun- dations of Computer Science, Chicago, Illinois, USA, 3-5 November 1982. pp. 160–164. IEEE Computer Society (1982)
37.Yao, A.C.: How to generate and exchange secrets (extended abstract). In: 27th Annual Symposium on Foundations of Computer Science, Toronto, Canada, 27-29 October 1986. pp. 162–167. IEEE Computer Society (1986)
38.Zahur, S., Rosulek, M., Evans, D.: Two halves make a whole-reducing data transfer in garbled circuits using half gates. In: Oswald, E., Fischlin, M. (eds.) Advances in Cryptology-EUROCRYPT 2015 - 34th Annual International Conference on the Theory and Applications of Cryptographic Techniques, Sofia, Bulgaria, April 26-30, 2015, Proceedings, Part II. Lecture Notes in Computer Science, vol. 9057, pp. 220–250. Springer (2015)
39.Zhang, W., Guo, X., Yang, K., Zhu, R., Yu, Y., Wang, X.: Efficient actively secure DPF and ram-based 2PC with one-bit leakage. In: IEEE Symposium on Security and Privacy, SP 2024, San Francisco, CA, USA, May 19-23, 2024. pp. 561–577. IEEE (2024)
## A Proof of Security

The rest of this section is devoted to a proof of the following theorem: Theorem 1. *The protocol Π*OneBitAdv*along with a secure projective garbling scheme that is point-* *permute-freeXOR-compatible securely realizes functionality F*OneBitAdv*against* PPT *malicious (rush-* *ing) adversaries in the (F*Com OT OLE Rand Eq

||, F|, F, F|, F )-hybrid world.||||
|---|---|---|---|---|---|---|
||Com OT|OLE|Rand Eq B||A||
|A|B|OneBitAdv A|Com OT|OLE Rand|Eq|B|
|||B|||||
|||||||B|
|B|||||||
||||||B||

*Proof.* Without loss of generality, we assume that P is honest, while P is corrupted by the adversary

*A*. The roles of P and P in protocol *Π*
are symmetric, so a similar proof applies when P is corrupted. For an adversary *A* corrupting P in the (*F*, *F*, *F*, *F*, *F*)-hybrid world, we construct a simulator *S*, which plays the role of P and runs *A* as a subroutine with auxiliary input *z*, interacting with *F*OneBitAdvin the ideal world. The simulation has been given in Figure 2. We now proceed to prove that the joint distribution of the view of *A* and the output of P in the ideal world is computationally indistinguishable from the joint distribution of the view of *A* and the output of P in the real protocol execution. We prove this by defining a sequence of experiments, where the output of each consists of the view of *A* and the output of P, and showing that the output of each is computationally indistinguishable from the output of the subsequent one. Expt₀. This experiment represents the ideal-world execution between the simulator *S* and the honest party PB, holding the input *x*B. Both interact with *F*OneBitAdv. We inline the actions of *S*, *F*OneBitAdv, and PB, and rewrite the experiment as follows.

1Sample ∆B*←*$ F *κ* 2, such that lsb(∆B) = 1. 2Compute (GC *′* *,X* *′* *,z*) *←S*Gb(1 *κ* *, C*) where *X* *′* = *{Xi′}i∈*[*n* O]. Let *Y* *′* = *{Yi′}i∈*[*n* O]= Ev(GC *′* *,X* *′* ). For each output wire *w* = out(*i*), *S* defines *z*ˆ *w* *′* = lsb(*Yi′*).

Acting as *F*Com, inform the adversary *A* that the honest party PBhas committed his garbled circuit to *F*Com. Subsequently, obtain the garbled circuit GC from *A*. 3If PAis the receiver in *F*OT, receive *x*Afrom *A*, send *{Xi′}i∈*[*n* A]to *A*, and store *x*A. If PAis the sender in *F*OT, receive *{*(*Xi,*0*,Xi,*1)*}i∈*[*n* A +1*,n*]from *A*. 4Send *{Xi′}i∈*[*n* A +1*,n*]to *A* and receive *{Xi}i∈*[*n*A]from *A*. 5Acting as *F*Com, open GC *′* to *A*. 6As the receiver of *F*OLE, receive L₀ and ∆ˆAfrom *A*. As the sender, receive *a₀* from *A* and return *A₀,*2 *←*$ F *κ* 2to *A*. Set L *′* 0:= *A₀,*2 *⊕ a₀*∆B. 7For *i ∈* [*n*O], define the Boolean function *gi* (resp. *gi′*) with fixed input *x*Aand variable *x*B*∈{*0*,*1*}* *n* B as follows:

(a)Let *Xi* := *Xi,x*B[*i−n*A]for *i ∈* [*n*A+ 1*,n*].
(b)Compute *Y* := Ev(GC*,X*), where *X* = *{Xi}i∈*[*n*].
(c)Define *Bi,*1 := *Yi* and *bi,*1 := ˆ*zw* = lsb(*Yi*) for *w* = out(*i*).
(d)Compute *y* := *C*(*x*A*,x*B), where *y* = (*y₁, ··· ,yn*O) *∈{*0*,*1*}*
*n* O.

(e)Let *λ* *′w* := *yi ⊕ z*ˆ*w*
*′*, and define *bi,*2 := *λ* *′w* for *w* = out(*i*).

(f)Set *Bi,*2 := *Yi′⊕ yi*∆Band *Bi* := *Bi,*1 *⊕ Bi,*2.
(g)Output *αi* := *Bi ⊕ bi,*1∆ˆA*⊕ bi,*1∆B(resp. *αi′*:= *Bi ⊕ bi,*2∆ˆA*⊕ bi,*2∆B). Compute *αi* := *gi*(*x*A*,x*B) and *αi′*:= *gi′*(*x*A*,x*B) for *i ∈* [*n*O], pick random values *{ri,ri′}i∈*[*n*
O], and forward these random values to *A* with respect to *F*Rand. Randomly select *b ←*$ F *κ* 2and send it to *A*. Meanwhile, receive *a ∈* F *κ* 2from *A*. 8Receive *β*ˆ *∈* F *κ* 2from *A* with respect to *F*Eq. Compute *β* := *β* ˆ*⊕ b*∆ˆ A*⊕* L₀ *⊕* L *′* 0*⊕ a*∆B, and then check P P if *β* =*i∈*[*n* O] *r* *i* *αi ⊕i∈*[*n* O] *r* *i′* *αi′*. If the equation does not hold, simulate rejection by honest PB. Otherwise, proceed to the next step. 9Compute *y* := *C*(*x*A*,x*B). For *i ∈* [*n*O], proceed as follows.

(a)Compute *bi,*2 = *λ*
*′w* := *yi ⊕ z*ˆ*w* *′* for *w* = out(*i*) and send it to *A*. Simultaneously, receive *ai,*1 from

*A*.
(b)Receive ˜*αi* with respect to *F*Eq. Then compute ˆ*bi,*1 := *yi ⊕ ai,*1 and check if *αi ⊕* ˆ*bi,*1∆B*⊕* ˆ*bi,*1∆ˆA= *αi′⊕ bi,*2∆B*⊕ bi,*2∆ˆA. If the equation does not hold, simulate rejection by PB. Then check if ˜*αi* = *αi ⊕ ai,*1∆B*⊕ ai,*1∆ˆA*⊕ yi*∆ˆA. If the equation does not hold, simulate rejection by PB. Otherwise, output whatever *A* outputs and continue.
Expt₁. Since each *gi*and *gi′*perform similar computation in steps 7a–7g, redundant calculations can be combined. Step 7 of the previous experiment can be modified as follows:

7Pick random *{ri,ri′}i∈*[*n* O]and forward them to *A* as *F*Rand. Follow the procedure below to compute *αi* and *αi′*for *i ∈* [*n*O].

(a)Let *Xi* := *Xi,x*B[*i−n*A]for *i ∈* [*n*A+ 1*,n*].
(b)Compute *Y* := Ev(GC*,X*), where *X* = *{Xi}i∈*[*n*].
(c)Define *Bi,*1 := *Yi* and *bi,*1 := ˆ*zw* = lsb(*Yi*) for *w* = out(*i*) and *i ∈* [*n*O].
(d)Compute *y* := *C*(*x*A*,x*B), where *y* = (*y₁, ··· ,yn*O) *∈{*0*,*1*}*
*n* O.

(e)Let *λ* *′w* := *yi ⊕ z*ˆ*w*
*′*, and define *bi,*2 := *λ* *′w* for *w* = out(*i*) and *i ∈* [*n*O].

(f)Set *Bi,*2 := *Yi′⊕ yi*∆Band *Bi* := *Bi,*1 *⊕ Bi,*2 for *i ∈* [*n*O].
(g)Let *αi* := *Bi ⊕ bi,*1∆ˆA*⊕ bi,*1∆Band *αi′*:= *Bi ⊕ bi,*2∆ˆA*⊕ bi,*2∆Bfor *i ∈* [*n*O]. Randomly select *b ←*$ F
*κ* 2and send it to *A*. Meanwhile, receive *a ∈* F *κ* 2from *A*.

It is easy to verify that the outputs of Expt₁ and Expt₀ are identically distributed. Expt₂. Move the computation of *y* := *C*(*x*A*,x*B) from Step 7 to Step 3, with the same computation of *y* in Step 9 eliminated. Since the computation of *y* based on *x*A, *x*B, and *C* is deterministic, this rearrangement does not alter the output distribution. Additionally, the assignment *Xi*:= *Xi,x*B[*i−n*A] for *i ∈* [*n*A+ 1*,n*] is moved from Step 7 to Step 3. Moreover, computations including *Y* := Ev(GC*,X*),

|⊕ y ∆|, λ := y|⊕ zˆ, b|, B|, b := ˆ|z = lsb(Y|), and B|:= B|⊕ B|
|---|---|---|---|---|---|---|---|---|
|i′ i|B ′w O|i w ′ i,2|′w i,1|i i,1|w|i i,2|i|i,1 i,2|

*Bi,*2:= *Yi′ i* B *′w* *i w* *′* *i,*2:= *λ* *′w* *i,*1:= *Yi i,*1 *w i i i,*1 *i,*2 for *w* = out(*i*) and *i ∈* [*n*], are moved from Step 7 to Step 5. We also note that *b* does not need to be recomputed in Step 9, as it is already computed (in Step 5 of this experiment). It is evident that the outputs of Expt₂ and Expt₁ are identically distributed. Expt₃. Step 6 of the previous experiment is modified as follows.

6Use *F*OLEto receive L₀ and ∆ˆAfrom *A*. Sample L *′* *←*$ F *κ*. As the sender of *F*OLE, receive *a₀* from *A*, compute *A₀,* := L *′* *⊕ a₀*∆B, and send it to *A*.

Since L *′* is uniquely defined by the randomly generated *A₀,∈* F *κ* in the previous experiment, al- tering the order in which *A₀,*and L *′* are generated does not impact the output distribution of the experiment. Consequently, the outputs of Expt₃ and Expt₂ remain identically distributed. Expt₄. Step 3 in the previous experiment is modified as follows.

3If PAis the receiver in *F*OT, receive *x*Afrom *A* and send *{Xi′}i∈*[*n* A]to *A*. Compute *y* := *C*(*x*A*,x*B). If PAis the sender, use *F*OTwith input *x*Bto obtain *Xi* := *Xi,x*B[*i−n*A]for *i ∈* [*n*A+ 1*,n*].

Since values *Xi,*1*−x*B[*i−n*A]are not used in the experiment, executing *F*OThonestly does not change the output of the experiment. Step 6 is also modified as follows.

6Pick *b₀ ←*$ F *κ* 2. As the receiver, use *F*OLEto receive *B₀,*1 := L₀ *⊕ b₀*∆ˆA, where L₀ and ∆ˆAare from *A*. Sample L *′* 0*←*$ F *κ* 2. As the sender, use *F*OLEwith input L *′* 0and ∆B, sending *A₀,*2 := L *′* 0*⊕ a₀*∆Bbased on *A*’s input *a₀* to *A*. Let *B₀,*2 := L *′* 0*⊕ b₀*∆Band *B₀* := *B₀,*1 *⊕ B₀,*2.

In this modified step, *F*OLEis honestly executed in the sender role. Additionally, added *B₀,*1, *B₀,*2 and *B₀* are values unused elsewhere in the protocol. Therefore, these modifications do not affect the experiment’s output. P P In Step 7, the value *b* sent to *A* is now computed as *b* := *b₀ ⊕i∈*[*n* O] *r* *i* *b* *i,*1*⊕i∈*[*n*O]*ri′bi,*2, and we rewrite it as follows.

7Use *F*Randto choose random *{ri,ri′}i∈*[*n* O]and forward them to *A*. P P*κ* Compute *b* := *b₀ ⊕i∈*[*n* O] *r* *i* *b* *i,*1 *⊕i∈*[*n* O] *r* *i′* *b* *i,*2 and send it to *A*. Meanwhile, receive *a ∈* F₂ from *A*. Let *αi* := *Bi ⊕ bi,*1∆ˆA*⊕ bi,*1∆Band *αi′*:= *Bi ⊕ bi,*2∆ˆA*⊕ bi,*2∆Bfor *i ∈* [*n*O].

Since *b₀* is randomly selected and is not used elsewhere, *b* maintains the same distribution as before. The outputs of Expt₄ and Expt₃ are thus identically distributed. Expt₅. In this experiment, Step 8 from the previous experiment is modified as follows.

ˆ*κ*ˆ = P P 8Receive *β ∈* F₂ from *A* with respect to *F*Eq. Verify if *β B₀ ⊕i∈*[*n* O] *r* *i* *Bi ⊕i∈*[*n* O] *r* *i′* *Bi ⊕* (*a ⊕ b*)∆B. If this equation does not hold, simulate a rejection by the honest PB. Otherwise, proceed to the next step.

ˆ ˆ*′* P In the previous experiment, we compute *β* := *β⊕b*∆A*⊕*L₀*⊕*L₀*⊕a*∆Band check if *β* =*i∈*[*n* O] *r* *i* *αi⊕* P *′ ′* *i∈*[*n*O]*riαi*. This is equivalent to verifying that     X X *β* ˆ =  *r* *i* *αi* *⊕*  *ri* *′* *αi* *′*  *⊕ b*∆ˆ A*⊕* L₀ *⊕* L *′* 0*⊕ a*∆B *i∈*[*n*O] *i∈*[*n*O]   X =  *riBi⊕ bi,*1∆ˆA*⊕ bi,*1∆B *i∈*[*n*O]   X *⊕*  *ri′Bi⊕ bi,*2∆ˆA*⊕ bi,*2∆B *i∈*[*n*O]

*⊕ b*∆ˆA*⊕ b*∆B*⊕* L₀ *⊕* L *′* 0*⊕ a*∆B*⊕ b*∆B     X X =  *riBi* *⊕*  *ri′Bi* *⊕ b₀*∆ˆA*⊕ b₀*∆B *i∈*[*n*O] *i∈*[*n*O]

*⊕* L₀ *⊕* L *′* 0*⊕* (*a ⊕ b*)∆B     X X =*B₀ ⊕*  *riBi* *⊕*  *ri′Bi* *⊕* (*a ⊕ b*)∆B*,* *i∈*[*n*O] *i∈*[*n*O]

P P ˆ*′* where we use the fact that *b₀* = *b ⊕i∈*[*n* O] *r* *i* *b* *i,⊕i∈*[*n*O]*ri′bi,*, *B₀,*= L₀ *⊕ b₀*∆A, *B₀,*= L₀*⊕* *b₀*∆B, and *B₀* = *B₀,⊕ B₀,*. Therefore, the outputs of Expt₅ and Expt₄ are identically distributed. Expt₆. Step 9 in the previous experiment is modified as follows.

9For *i ∈* [*n*O], follow the procedure below.

(a)Send *bi,*2 to *A*. Meanwhile, receive *ai,*1 from *A*.
(b)Receive *α*˜*i* with respect to *F*Eq. Then check if *bi,*1 *⊕ ai,*1 = *yi*. If the equation does not hold, simulate rejection by PB. Then check if ˜*αi* = *Bi ⊕ yi*∆B. If the equation does not hold, simulate rejection by PB. Otherwise, output whatever *A* outputs and continue.

|||||⊕ ˆb ∆|ˆ ⊕ ˆb ∆|⊕ b = α|∆ ⊕ b|ˆ ∆,|
|---|---|---|---|---|---|---|---|---|
|||||i i,1|B i,1|A i′|i,2 B|i,2 A|
|i i,1|i i i i,1|i,1 B B i,1 i|i,1 A A i i,2 B|i′ i i,1 B i,2 A i,2|i,2 B i i,1 B i,2|i,2 A A A|||

In the previous experiment, we begin by verifying if *α* where ˆ*bi,*1:= *y ⊕ a*, *α* = *B ⊕ b* ∆ *⊕ b* ∆ˆ, and *α* = *B ⊕ b* ∆ *⊕ b* ∆ˆ. This is equivalent to checking if

*B ⊕ b* ∆ *⊕ b* ∆ˆ *⊕* (*y ⊕ a*)∆ *⊕* (*y ⊕ a*)∆ˆ

= *B ⊕ b* ∆ *⊕ b* ∆ˆ *⊕ b* ∆ *⊕ b* ∆ˆ

### and thus checking

||(b|⊕ a ⊕ y|)(∆ ⊕ ∆|ˆ ) = 0.|||
|---|---|---|---|---|---|---|
||i,1|i,1|i B|A|||
||′|||B|A||
|i,1|i,1 i||||||
|i,1 i,1|i||i|i i,1 B|i,1 A|i A|

Since ∆Bis randomly chosen and GC is simulated, we have ∆ *̸*= ∆ˆ except with negligible proba- bility. Hence, verifying *b ⊕ a* = *y* is sufficient. Furthermore, if *b ⊕ a* = *y*, then checking *α*˜ = *α ⊕ a* ∆ *⊕ a* ∆ˆ *⊕ y* ∆ˆ is equivalent to verifying

|α ˜ = B ⊕ b|∆ ⊕ b|ˆ ∆ ⊕ a|∆ ⊕ a|ˆ ∆ ⊕ y|ˆ ∆|
|---|---|---|---|---|---|
|i i|i,1 B|i,1 A|i,1 B|i,1 A|i A|
|i|i B|||||

### = B ⊕ y ∆

Therefore, the output of Expt₆ and Expt₅ are identically distributed. Since now *αi*and *αi′*are no longer required in this experiment, they can be safely removed. Expt₇. In this experiment, the functionality *F*Comin Step 2 and 4 is executed honestly as in the real world. Since GC and GC *′* are not used before Step 5, this modification does not change the P P output distribution. Additionally, in Step 7, compute *B* := *B₀⊕i∈*[*n* O] *r* *i* *Bi⊕i∈*[*n* O] *r* *i′* *Bi*and

honestly execute *F*Eqin Step 8 to verify if *β*ˆ = *B ⊕*(*a ⊕ b*)∆B. It is straightforward to verify that the outputs of Expt₇ and Expt₆ remain identically distributed. Expt₈. Step 2 to Step 5 of the previous experiment is modified as follows.

2Compute (GC *′* *,e* *′* *,*dk *′* *,d* *′* *,D* *′* ) *←* Gb(1 *κ* *, C*; ∆B)*,* where *e* *′* = (*Xi,* *′* 0 *,Xi,* *′* 1 ). Here dk *′* can be used to derive the point-permute bit *λ* *′w* ’s and output-wire label L *′w,* 0 ’s for each wire *w ∈W*O, respectively. Use *F*Comto commit GC *′*. 3If PAis the receiver in *F*OT, send *Xi,x* *′* A [*i*] *i∈*[*n*]with respect to *A*’s input *x*Ato *A*. If PAis the sender, A use *F*OTto obtain *Xi* := *Xi,x*B[*i−n*A]for *i ∈* [*n*A+ 1*,n*]. Compute *y* := *C*(*x*A*,x*B). 4Send *Xi′*= *Xi,x* *′* B [*i−n*A] *i∈*[*n* +1*,n*]to *A*. Receive *{Xi}i∈*[*n*A]from *A*. 5Open GC *′* to *A* via *F*Com. Learn the garbled circuit GC generated by A *A* from *F*Com. Compute *Y* := Ev(GC*,X*), where *X* = *{Xi}i∈*[*n*]. Define *Bi,*1 := *Yi* and *bi,*1 := *z*ˆ*w* = lsb(*Yi*) for *w* = out(*i*) and *i ∈* [*n*O]. Set *Bi,*2 := L *′w,* 0*⊕ λ* *′w* ∆Band *bi,*2 := *λ* *′w* for *w* = out(*i*) and *i ∈* [*n*O]. Let *Bi* := *Bi,*1 *⊕ Bi,*2.

Since the garbling scheme achieves equivocable privacy, replacing the garbled circuits simulated by (*S*Gb*, S*Gb *′* ) by an honestly generated garbled circuit only incurs a negligible difference in the output distribution. Note that in the previous experiment, we set *Bi,*2:= *Yi′⊕ yi*∆B. Since

*Bi,*2= *Yi′⊕ yi*∆B= L *′w,z* ˆ *w* *′ ⊕ yi*∆B

= L *′w,* 0*⊕ z*ˆ*w* *′* ∆B*⊕ yi*∆B= L *′w,* 0*⊕ λ* *′w* ∆B

Computing *Bi,*2= L *′w,* 0*⊕ λ* *′w* ∆Bderive the same *Bi,*2as *Bi,*2= *Yi′⊕ yi*∆B. Therefore, the output distribution of Expt₈ is computationally indistinguishable from that of Expt₇. Expt₉. In this experiment, we modify Step 9 in the previous experiment as follows.

9For *i ∈* [*n*O], follow the procedure below.

(a)Send *bi,* to *A*. Meanwhile, receive *ai,* from *A*.
(b)Receive ˜*αi* with respect to *F*Eq. Then check if ˜*αi* = *Bi ⊕* (*ai, ⊕ bi,*)∆B. If the equation does not hold, simulate rejection by honest PB. Otherwise, output whatever *A* outputs and continue.
Since the value *y* is no longer used in this experiment, we can remove the assignment *y* := *C*(*x*A*,x*B) in Step 3. If *ai,*1*⊕ bi,*1= *yi*, where *y* = *C*(*x*A*,x*B) as computed in the previous experiment, then verifying if *α*˜*i*= *Bi⊕ yi*∆Bis equivalent to verifying if *α*˜*i*= *Bi⊕* (*ai,*1*⊕ bi,*1)∆B. Thus, the output distribution of Expt₉ is identical to that of Expt₈. We proceed to show that if *ai,*1*⊕ bi,*1*̸*= *yi*, then ˜*αi̸*= *Bi⊕* (*ai,*1*⊕ bi,*1)∆Bexcept with negligible probability. Consequently, PAwill reject *A* as in the previous experiment. Define ¯*yi*= *ai,*1*⊕ bi,*1= *yi⊕* 1. If *ai,*1*⊕ bi,*1*̸*= *yi*and ˜*αi*= *Bi⊕* (*ai,*1*⊕ bi,*1)∆B, then the value ˜*αi* provided by *A* satisfies

*α*˜*i*= *Bi⊕* (*ai,*1*⊕ bi,*1)∆B= *Bi,*1*⊕ Bi,*2*⊕ y*¯*i*∆B

||= Y ⊕ (L|⊕ λ|∆ ) ⊕ y¯|∆|||
|---|---|---|---|---|---|---|
|i i B|i i i|′w,0 ′w,zˆ ⊕1|B ′w i ′w i|i B B w ′ ′w,zˆ ⊕1|||

*i* *′w,* 0 *′w* B *i* B = *Y ⊕* L *⊕* (*λ ⊕ y*¯)∆

= *Y ⊕* L *w* *′*

for *w* = out(*i*), where we use the fact that *λ ⊕ y*¯ = *z*ˆ *⊕* 1 in the last equation. Since *A* knows both *α*˜ and *Y*, it can derive the output-wire label L *w* *′* of the garbled circuit GC generated by the honest P. This result contradicts the authenticity against one-bit leakage property of the secure garbling scheme. Therefore, the output of Expt₉ is indistinguishable from that of Expt₈. As Expt₉ corresponds to a real-world execution of the protocol, this concludes the proof. *⊓⊔*
