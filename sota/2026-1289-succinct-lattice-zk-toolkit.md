# A Toolkit for Succinct Lattice-Based Zero Knowledge Proofs

Beatrice Biasioli¹ *,*2, Madalina Bolboceanu¹ *,*2, Vadim Lyubashevsky¹, Antonio Merino-Gallardo¹ *,*2, Micha l Osadnik³, Gregor Seiler¹, and Patrick Steuer¹ *,*4

1 IBM Research Europe, Zurich, Switzerland beatrice.biasioli@ibm.com, madalina.bolboceanu@ibm.com, vad@zurich.ibm.com, antonio@m-g.es, gseiler@posteo.net, ick@zurich.ibm.com 2 University of Potsdam, Potsdam, Germany 3 Aalto University, Espoo, Finlandmichal.osadnik@aalto.fi 4 Radboud University, Nijmegen, Netherlands

Abstract.The development of proof systems whose security relies on the hardness of lattice problems has been a fruitful research area in recent years. By leveraging the techniques introduced in LaBRADOR (Beullens, Seiler, Crypto 2023), the state-of-the-art lattice-based schemes have very fast provers and have output sizes under 100KB for arbitrarily large statements. These proofs are in fact the smallest, and often have the fastest provers, out of all post-quantum schemes. In addition to succinctness, many applications also require witness privacy. Achieving this can, in theory, be done by combining LaBRADOR with a linear-size zero-knowledge proof. While such a combination has already been described in the LaBRADOR paper itself, as well as in the works of Albrecht et al. (Eurocrypt 2024) and del Pino et al. (Crypto 2025), its concrete costs remained unexplored. In this work, we provide the first concrete construction and implementation that adds zero-knowledge proofs to LaBRADOR by integrating the linear-size zero-knowledge proof from (Lyubashevsky, Nguyen, Plan¸con, Crypto 2022) into the protocol. We describe the non-trivial challenges that this entails and show practicality of the construction by benchmarking several use-cases. We make the proof system and primitives accessible by extending the LaZer library (Lyubashevsky, Seiler, Steuer, CCS 2024) in a way that they can easily be used in other applications.

Keywords:Lattice Cryptography, Zero-Knowledge, Succinct Proofs, Implementation, Privacy, Quantum- Safe

## 1 Introduction

Succinct lattice-based proof systems have been shown to be competitive with proof systems based on other hardness assumptions. In recent times, there has been a lot of progress, and many concretely efficient lattice- based constructions have been proposed, e.g. [11, 13, 15, 16, 32, 42]. The two other main categories of succinct proof systems are pairing-based SNARKs, e.g. [21, 28, 31], and hash-based STARKs, e.g. [8, 9, 46]. SNARKs offer extremely small constant-size proofs but are not secure against quantum computers and have relatively slow provers. STARKs are quantum safe, do not need any structured computational assumptions, and offer faster runtimes, but produce quite large proofs. In comparison, lattice-based proof systems have the potential to combine quantum-safety and fast runtimes with proof sizes that are smaller than those of the STARKs. Indeed, the computationally friendly mathematical structure of lattice commitments that are simple high-dimensional linear functions over polynomial rings has been shown to allow for lattice-based polynomial commitment schemes that have leading prover runtimes [32,42] and competitive verifier runtimes in the single- digit millisecond range [32]. Polynomial commitment schemes (PCSs) are the core cryptographic component in modern proof system constructions. At the same time, the proof sizes of these lattice-based PCSs are leading among quantum-safe PCSs. An important but somewhat neglected feature in current succinct lattice-based proof systems and their implementations is the zero-knowledge property. Only the linear-sizeLNPproof system [36] and its imple- mentation in the LaZer library [40] comes with zero-knowledge.

For many proof system applications, the succinctness property is the main enabling feature. A typical example is signature aggregation, where a large number of signatures are compressed into a small proof that can be verified in very little time. Here, the signatures do not need to be hidden as there is no privacy requirement, and hence the proof system does not need to have the zero-knowledge property. The situation is completely different in privacy-preserving applications where zero-knowledge is the cen- tral feature provided by the proof system. Typical application examples are blind signature schemes and anonymous credential systems constructed with the help of zero-knowledge proofs. In such protocols, users possess signatures from some underlying basic signature scheme, but they do not want to reveal these signa- tures in the clear, as this would make them traceable. Instead, the users only provide zero-knowledge proofs of possession of the signatures and hence keep the signatures private. In light of the ongoing and pressing transition to quantum-safe cryptography, it is also important to tran- sition advanced privacy-preserving cryptographic protocols such as Privacy Pass, and hence, there is a strong need for practical quantum-safe zero-knowledge proof systems and implementations thereof. Furthermore, given that the main quantum-safe signature scheme Dilithium [25], which is standardized as ML-DSA by NIST, is a lattice scheme, it is often necessary to prove statements about lattice schemes. In this case there are significant synergies when the proof system is also based on lattices. In particular, the proof system then shares a lot of the mathematical structure with the scheme to-be-proven, and hence can be implemented using similar implementation techniques. Furthermore, a large fraction of the operations in the scheme can be phrased as polynomial relations that are native to the proof system. Thus, the proof statement can often be constructed manually, and one does not need to resort to circuit representations and (trusted) compiler tool chains. This provides further reasons to consider lattice-based zero-knowledge proofs beyond small proof sizes and computational performance. In the present paper we propose a lattice-based proof system that offers both succinct proof sizes as well as zero-knowledge. Concretely, our proof system is a combination of a variant of theLaBRADORproof system with a modification of theLNPproof system that we callLNP-Lite. While such constructions have been suggested before, we provide the first detailed instantiation and the first implementation of such a proof system. In more detail, prior works [3,44] have suggested constructing a lattice-based zero-knowledge proof system with succinct proof sizes by proving the input relation withLNPin a first step. InLNPproofs, only the last prover message (the so-called masked openingz) scales linearly with the witness size. The remaining inner prover messages are sublinear in size, so they can be revealed in the clear. This allows the verifier to compute all Fiat-Shamir hashes. Then, what remains is to prove knowledge ofzfulfilling all verifier checks performed on it inLNP. These are all simple polynomial relations of the type supported byLaBRADOR. So instead of also outputting the masked opening, we can prove knowledge of it usingLaBRADOR, resulting in a succinctly-sized zero-knowledge proof. There are two drawbacks to this approach. First, as also realized by [44], the innerLNPprover messages, while sublinear in size, are still concretely quite large, and hence blow up the proof size of the combined proof system. Second, and more importantly, the masking of the secret inzblows up the size of the witness for LaBRADOR, and hence results in poor runtimes. Therefore, a better approach is to first run several iterations of a sublinear-size proof protocol that reduces the witness size. This was already suggested in [11] but without a concrete instantiation. The sublinear-size protocol does not need to be fully zero-knowledge. It suffices if the inner prover messages, which are output, are simulatable. On the contrary, the last prover messages are not output and do not need to be simulatable. They are proven by the next iteration of the protocol, or, in case of the last protocol iteration, proven in zero-knowledge byLNP. Finally, one can proceed as before and prove the last prover message ofLNPwith further iterations ofLaBRADORwhere no zero-knowledge requirements exist anymore. In this way, the masking inLNPonly increases the size of a witness that is much smaller than the initial input witness. For the sublinear-size proof protocol, we use the improved variant ofLaBRADORfrom [13], which we refer to asLaBRADOS. In this protocol all the inner prover messages are wrapped in binding lattice commitments to minimize their size. These commitments can be made simulatable easily by adding sufficient randomness so that the commitments become hiding under LWE. OurLNPvariantLNP-Litecontains commitment

wrappers similarly to [44] in order to reduce the impact on the final proof size. Moreover, we further modify LNPin several ways. Most importantly, we propose a new technique to mask the random projection that allows us to instantiate the protocol with a modulus*q*small enough for theLaBRADORimplementation. The naive way of masking and committing to the random projection requires moduli that are too big for LaBRADOR. Finally, we implementLNP-Liteon top of the same arithmetic implementation that is used by theLaBRADORimplementation in order to obtain a unified implementation of the complete proof system. Also, we added support for the quadratic input constraints required for provingLaBRADOS. Those constraints are not supported by the LaZer implementation ofLNP. We showcase the performance and practicality of our construction and implementation by using it for proving several useful lattice statements that require sublinear proof sizes as well as zero-knowledge. Con- cretely, our benchmarks center around proving symmetric-key primitives such as collision-resistant hash functions and PRG evaluation. Such proofs are useful in the construction of numerous high-level protocols. For example, proving PRG evaluation can be used for constructing a verifiable encryption scheme.

## 2 Preliminaries

*Notation*Let*q*be an odd prime. We denote byZ*q*the ring of integers mod*q*. We write [*n*] =*{*1*,*2*,...,n}.* We say*x←S*when*x∈S*is sampled uniformly at random from a finite set*S*and similarly*x←χ*when *x*is sampled according to a distribution*χ*. We denote by*U*(*S*) the uniform distribution over the finite set

*S*. Given two moduli*q≥p≥*2, we define the rounding function fromZ*q*toZ*p*that maps*x∈*Z*q*to *⌈x⌋q→p*:=*⌈*
<u>p</u> *q* *·x⌋*mod*p*and we extend this function to integer vectors coordinate-wise. Let*d*be a power of two, and let*R,Rq*be the ringsZ[*X*]*/*(*X* *d* + 1) andZ*q*[*X*]*/*(*X* *d* + 1), for any integer*q.*Most of the times, *q*is chosen such that*X* *d* + 1 splits in two irreducible factors mod*q*. We work with*d*= 256 or 512. For a polynomial*f*=*a₀* +*a₁X*+*...*+*ad−*1*X* *d−*1 *∈R*, we denote byct(*f*) its constant-term, i.e.ct(*f*) =*a₀.* We use*σ−*1 *−*1 *−*1 *−*1

|(·) to denote the “conjugation automorphism”, i.e.σ||||||∈Aut(R) such thatσ||(X) =X|.|
|---|---|---|---|---|---|---|---|---|---|
|−1||||||−1||−1|−1|
||q|||||||||
|||n||||||||
|r|||||||n q|n q|r|
||n +n|||||||||
||q c|||c|n1|||||

Vectors overZ,*R*,*R* are denoted by italic-bold lower-case and matrices by italic-bold capital letters. For any polynomial vectora*∈R*, we denote by dim(*·*) their dimension as integer vector, i.e. dim(a) =*nd*. We denote by1 the column vector containing all entries equal to (the constant polynomial) 1, and by0 the one containing all entries equal to (the constant polynomial) 0. Ifa*∈ Ra*andb*∈ Rb*are vectors, we denote by (a*,*b)*∈Ra b*their concatenation. A function*f*:N*→*Ris said to be negligible if for all*c∈*N there exists some*n ∈*Nsuch that for all*n > n*,*|f*(*n*)*|<c*. In the context of probabilities, we say*a≈b* if*a−b*is negligible. Further notation and additional preliminaries can be found in Section A.

2.1 The Challenge Space

||q|′|
|---|---|---|
|||op|
|op r∈R\{0} ∥∥cr|r∥∥||
 The challenge space*C⊆R* is chosen such that*c−c* is invertible for any pair of distinct*c,c*
*′* *∈C*and with bounded*ℓ₂* norm and*operator norm*, i.e.*∥c∥≤τ*and*∥c∥ ≤T,*for any*c∈C*, for some constants*τ,T∈*R, where*∥c∥* := sup*.*A popular choice [11] is to sample*c*with small*∥c∥*=*τ*by taking a fixed number of short non-zero entries (e.g.*±*1,*±*2) that ensures a large-enough size of*C*, while the invertibility is guaranteed by their shortness as proved in [39, Cor.1.2].

2.2 Lattice Assumptions Here we recall the computational lattice problems Module-Short Integer Solution (M-SIS), Module-Learning With Errors (M-LWE), and Module-Learning with Rounding (M-LWR) [25, 34]. Definition 1(M-SIS).*For integersM,N,q >*0*and real numberβ >*0*,we define M-SISq,M,N,βproblem* *as follows: Given*A*←R*
*M* *q* *×N* *, find*v*∈R* *N* *qsuch that*Av= 0*and*0*<∥*v*∥≤β.*

Definition 2(M-SIS with*ℓ∞*norm).*We define M-SIS* *∞* *q,M,N,βanalogously to Definition 1 with∥·∥* *replaced with∥·∥∞.*

Definition 3(Decision M-LWE).*For integersn,m,q >*0*andχa distribution overR, we define the* *decision M-LWEq,m,n,χproblem as follows: for*s*←χ* *n* *, distinguish between the following cases*

–(A*,*As+e)*, for*A*←R* *m* *q ×n,*e*←χ* *m* *,* –(A*,*b)*, for*A*←R* *m* *q ×n,*b*←R* *m*

*q.*
We recall the Extended M-LWE problem [38], used in proving zero-knowledge of our proofs of knowledge.

Definition 4(Extended M-LWE).*For integersn,m,q >*0*,χa distribution overR, a positive real* *numberσ >*0*and a challenge spaceC⊆Rq,we define the Extended M-LWEq,m,n,χproblem as follows: for* r*←χ* *n* *,distinguish between the following two cases*

|m|n||
|---|---|---|
|q ×n|σ||
|m|m|n|
|q ×n|q|σ|

–(B*,*Br*,c,*z*,sign*(*⟨*z*,c*r*⟩*))*, for*B*←R,*z*←D, c←C,* –(B*,*u*,c,*z*,sign*(*⟨*z*,c*r*⟩*))*, for*B*←R,*u*←R,*z*←D, c←C,*

### wheresign(a) = 1,ifa≥0,and 0 otherwise.

The Module-Learning with Rounding problem deals with two integer moduli,*q≥p≥*2*.*

Definition 5(Decision M-LWR).*For integersn* *′* *,m* *′* *,q≥p >*0*andχbe a distribution overR, then the* *n* *′*

|q,p,m ,n ,χ|||n|
|---|---|---|---|
|q→p|m ×n q|m q ×n m p||

*decision M-LWR ′ ′ problem as follows: for*s*←χ, distinguish between the following two cases:* *′ ′* –(A*,⌈*As*⌋*)*, for*A*←R,* *′ ′ ′* –(A*,*u)*, for*A*←R,*u*←R.*

2.3LaBRADOR LaBRADORis a proof system introduced by Beullens and Seiler [11] whose security is based on the hardness of the M-SIS problem. This proof system enjoys a concretely small communication size, and is tailored for proving lattice-related relations.LaBRADORhas a core base protocol and becomes*succinct*by leveraging recursion: the last message of one iteration of the base protocol becomes the witness for the next one, and the new statement corresponds to the verifier’s checks from the previous iteration. In this way, the size of the witness is reduced with each iteration, until no further progress is made, and the prover finally sends the last witness for the verifier to check directly. More concretely, theLaBRADOR
P proof system proves knowledge of short witness vectorss¹ *,...,*s*r∈R* *n* *,* satisfying a*global*norm bound*i∈*[*r*]*∥*s*i∥* 2 *≤β*and dot-product constraints*f*: *R* *n* *q×...×R* *n* *q→Rq*of the form X X

||f(s₁,...,s|)≜|a ⟨s ,s|⟩+|⟨φ ,s ⟩−b,(1)||||
|---|---|---|---|---|---|---|---|---|
|||r i,j∈[r]|ij i|j i∈[r]|i i||||
|q i|n q|ij|ji||′||||
||||′||||||
|Lab|||||||||

where*aij,b∈ R*,*φ ∈ R*, such that*a* =*a*. For some constraints*f*, we are only interested in the constant termct(*·*) of their output, so the other coefficients of*b*are not included in the statement. We collect these*constant term*constraints in a family*F*, separated from the*full*constraints, that we collect in a family*F*. It is worth noting that the witness vectors will actually be proven to satisfy p *looser*norm bounds, by a slack factor of*c* := 128*/*30, due to the use of random projections. This proof system is not*zero-knowledge*, i.e., the prover messages leak information about the witness. Commitment Layers.LaBRADORworks with two layers of commitments, that their authors refer to as *inner*and*outer*layers. The inner commitments are Ajtai commitments of the witness vectorss*i*, of rank*k*in, whereas the outer ones are Ajtai commitments, of rank*k*mid, of the decompositions of the inner commitments. In anticipation of the additional layer of commitments that we consider in the next section, we refer to the outer commitement layer ofLaBRADORinstead as*middle*commitments. LaBRADOS.A recent work [13] introduced a variant ofLaBRADORthat further compresses the size of the prover’s messages sent in each iteration of the protocol (see [13, Sec.7.3]), and that serves as an important building block in our construction. We refer to this variant ofLaBRADORasLaBRADOS.

LaBRADOSworks by binary-decomposing the original messages ofLaBRADOR, and sending*outer*commit- ments of them. This means that the decompositions need to be included in the last prover message (i.e. the witness for the next iteration) and the verifier has to check that they are indeed binary and the correct openings to the outer commitments. One of the main advantages of this outer layer is that the rank of these commitments can be very small by relying on the hardness of M-SIS for infinity norm bound 1 (following the analysis in Dilithium, see [25, Appendix C.3]). Another advantage is that, since the projections are no longer sent in the clear, one can prove individual norm bounds on the witness vectors, rather than a global norm bound. The downside is that, rather than checking the exact*ℓ₂*-norm of the projections, the verifier only checks that they have been decomposed in binary with a certain number of bits. This leads to a slack factor of*c*Lab-new:= 9*.*75*/*0*.*74*,*by the use of Theorem 4. Lastly, the main reason why we useLaBRADOSis that everything the prover sends (except for the last message) are Ajtai commitments. These can be easily made*hiding*by appending a long enough uniform binary vector before committing and relying on the hardness of the M-LWE problem.

2.4LNP Lyubashevsky, Nguyen, and Plan¸con introduced in [36] a proof system for lattice-related relations that achieves zero-knowledge, and that we refer to asLNP. UnlikeLaBRADOR, the proof size ofLNPis*linear*, since the size of the last prover message scales linearly with the size of the witness. Its security also relies on the assumed hardness of the M-SIS problem.
## 3 A Succinct Zero-Knowledge Proof System

We obtain a succinct zero-knowledge proof system by combining iterations of different protocols in the following way. We start by proving knowledge of the input witness withLaBRADOSequipped with hiding commitments. The last message ofLaBRADOS, i.e., the output witness, is then recursively fed as input to the same protocol, and several iterations are run until the size of the witness is sufficiently small. We then proceed to feed the resulting small witness toLNP-Lite, a compressed version of the linear-size protocol LNPthat is tailored to the output ofLaBRADOSand that we describe in Section 3.3. The output ofLNP-Lite could safely be made public, but we further compress it by running several iterations ofLaBRADOS(now with non-hiding commitments), and finishing with several iterations of the originalLaBRADOR. Once the size of the final witness cannot be decreased any more, the witness is finally sent to the verifier. We give an overview of this succinct zero-knowledge proof in Figure 1.

LaBRADOS Section 3.1 LNP-Lite Section 3.4 LaBRADOS LaBRADOR

Sections 3.2 and 3.3

Fig. 1.Overview of the succinct zero-knowledge proof system from Section 3.

3.1 Understanding the Output ofLaBRADOS The variant ofLNPthat we describe in the subsequent sections is tailored to proving the output ofLaBRADOS. In this section, we take a closer look at the latter, with an emphasis on what the output witness looks like and what the output statement to prove is.

LaBRADOSworks with the polynomial ring*R*of degree*d*= 256 and the challenge space*C*(Section 2.1). The input of theLaBRADOSiterations is made of short witness vectorss₁*,...,*s*r∈ R* *n* *,*satisfying norm bounds*∥*s*i∥≤βi*and constant-term and full-domain dot-product constraints of type (1). Output Witness. P As inLaBRADOR, the last message ofLaBRADOScontains a linear combination of witness vectors,z :=*i∈*[*r*]*ci*s*i*, with random challenges*ci← C*from the verifier. To ensure that the size of the coefficients ofzdoes not blow up when recursing this protocol, [11] considers decomposingzin two parts,z₀ andz₁, with respect to a basis*b*asz=z₀+*b*z₁. Additionally, the output ofLaBRADOScontains the openings of the middle commitments, collected inxmid, and the openings to the outer commitments and the random binary vectors used to make the outer commitments hiding, all binary vectors collected inxbin. Overall, the output witness is (z₀*,*z₁*,*xmid*,*xbin*,σ−*1(xbin)), where the presence of the last element is justified in next subsection. Output Statement.In order to ensure the binding property of the commitments, all the output witness vectors need to satisfy certain*ℓ₂*-norm bounds, which are derived from the bases used to decompose their elements. Additionally, the output vectors satisfy constant-term and full dot-product constraints of type (1). They include the final aggregated dot-product constraint, the correctness of all commitment layers, and of the so-called*garbage terms*needed for checking the final aggregated constraint. Finally, we need to perform a binary check forxbin. We follow the standard technique of including the additional vector*σ−*1(xbin) in the witness, and proving its well-formedness together with the appropriate quadratic equation (see Section A.3 for more detail). Note that for this vector we do not provide an approximate norm proof, as its norm bound trivially follows from that ofxbin. Overall, the only quadratic checks are the correctness of the quadratic garbage terms, which contains the dot-products*⟨*z*i,*z*j⟩*for*i,j∈ {*0*,*1*}*, and the binary equation, which

|||i j|
|---|---|---|
|bin −1|bin||

contains the term*⟨*x*,σ* (*x*)*⟩*. Soundness.The proof of knowledge soundness follows, via Lemma 4, the same lines as the proof of [11, Thm 5.1] and assumes the binding of the outer commitment layer. The only difference is that, asLaBRADOS proves individual projections of the witness vectors as binary vectors using log (9*.*75*βi*) bits (Theorem 3), it leads to proving approximate norm bounds with a slack factor*c*Lab-new:= 9*.*75*/*0*.*74, by Theorem 4. The statement of knowledge soundness is as follows.

Theorem 1.*LetC⊂Rqbe the challenge space from Section 2.1, of polynomials with operator norm bounded* *byT. Suppose M-SIS is hard forℓ₂ norm bound*2*γand rankkmid, and forℓ₂ norm bound*max*{*8*Tγ* *′* *,*2*γ* *′* + 9 9

|·maxβ 4T·|}, rankk|, and|β|<. ThenLaBRADOSis a knowledge-sound proof with knowledge||||
|---|---|---|---|---|---|---|---|
|9 0..75 74|i 128|in λ|0 9..74 75 i d/2 i|91 q|9 Lab-new i 0..75 74 i|9..74 75 0||

*..*74 75 *q*
*soundnessκ* := 1*/*2 + (1*/q*) + 1*/q* + 2*/|C|and norm slackc* :=*,i.e. the extractor is only* *guaranteed to extract witness vectors* s¯ *with norm bounds∥*s¯*∥≤ β.*

3.2 Overview of Improvements toLNP The linear-size zero-knowledge protocolLNP[36] lies at the heart of our construction. The iterations of LaBRADOSrun at the beginning ensure that the input toLNPis small. Similarly, the iterations ofLaBRADOS andLaBRADORrun on the output witness ofLNPensure that the final witness sent in the end to the verifier will be succinct. This section deals with reducing the communication of theLNPprotocol itself. We describe the main challenges we overcome and techniques we employ for obtaining a compressed version ofLNP. The resulting protocol we propose isLNP-Lite, and we provide a full description in Section 3.3. We note that since this protocol is meant to be run on the output ofLaBRADOS, we make some optimizations tailored to it. New Challenge Space and Witness.The challenge space*C*that we use for this protocol is the same asLaBRADOS(Section 2.1), not stable under the automorphism*σ−*1*,*as opposed toLNP[36]. It is thus crucial to include*σ−*1(xbin) in the witness so as to prove thatxbinis binary. Additional Commitment Layer.We compressLNPby adding an outer commitment layer to all but the last prover message, in a similar way thatLaBRADOSis a compressed version ofLaBRADOR. The original LNPcommitments are then called*inner*commitments, which in our case are just hiding Ajtai commitments. The outer ones are also Ajtai commitments, but these do not need to be hiding. It is easy to check that extendingLNPwith outer commitments preserves its zero-knowledge (see Lemma 5).

Increase of the Projection Slack.Proving binary withLNPwould become impractical if one simply extends [36] with outer commitments. The problem lies in the fact that the masked projections, designed to obtain approximate*ℓ₂* norms on the input witness vectors, are no longer sent directly to the verifier, but only a commitment to their binary decompositions. In particular, the masked projection of the output binary *√ √* vectorxbin*∈R* *n* follows, due to rejection sampling, a distribution close to*Dσ,*for*σ* :=*γ* 337 *nd*, so we could write it using log (14*σ*) bits. Suppose that the prover proves that the decomposed projection is indeed binary and written in that many bits. Then, adapting the Johnson-Lindenstrauss proof to deal with the*ℓ∞* norm of the masked projections (Theorem 5), we could prove that*∥*xbin*∥ ≤* <u>2</u> 0 <u>·14</u>

*.*67 <u>σ</u> with high probability,
<u>14</u> *√* leading to a slack factor*α* := 2*·*

0*.*67 *·γ* 337*≈*12275. To prove thatxbincontains, for example*n*= 1024
binary polynomials, we would need to set 2*∥*xbin*∥* 2 *≤*2*α²nd≤q*, to ensure that the binary equation does not wrap around mod*q*(see Section A.3), leading to a modulus*q≈*2

46*.*2 pfor *d*= 256. For comparison, [36]
*√ √* can provide an approximate proof forxbinwith a slack factor*α* := 2 256*/*26*·* 2*·γ* 337*≈*2606*.*8, ( [36, Proposition 5.1]), for a repetition constant*γ*set, e.g., equal to 16, which leads to setting a modulus *q≈*2

41*.*7 *,*for the same*n*.
Two-Step Projection.We employ a technique that allows us to obtain a smaller slack than the naive approach outlined above. In fact, we get a smaller slack than the originalLNP. In our two-step projection approach, we delay using the expensive Gaussian masking and instead prove binary for vectors of*small* *fixed*dimension, regardless of the dimension of the input binary vectors, allowing for a smaller modulus

*q.*Thus, the standard deviation of the Gaussian masking becomes a fixed parameter, independent of the input norm bounds. More precisely, we could write the projection of
*√* xbin, a vector inZ²⁵⁶*,*on*k*+ 1 bits, as*k* :=*⌈*log (9*.*75 *nd*)*⌉*(Theorem 3). In fact, it could be written with high probability on just*k*bits, so one could think of the high-order bit as an extra bit equal to 0. Then we could mask the lower*k*bits of the projection with a maskuuniformly sampled over [*−*2 *k−*1 *,*2 *k−*1 *−*1] 256 and reject if there are more than*N*= 32 nonzero high-order values (called*carries*), being -1 or 1, across the 256 high-order values (in*{−*1*,*0*,*1*}*) of each of the projection entries. One could safely send the low-order bits of the projection, collected asv₀ *∈*Z²⁵⁶*,*as they are uniform, but not the high-order values, collected asv₁ *∈{−*1*,*0*,*1*}* 256 *,* since they leak possible carries. This is where the second projection comes into play: we prove that this vector v₁ is ternary by writing it asv₁ :=w*−*tforw*,*t*∈{*0*,*1*}* 256 and by providing an approximate proof for (w*,*t) as in [36], whose norm is exactly the number of carries, less than*N*. Its projection needs to be masked for assuring zero-knowledge and could be sent in the clear, without computing its outer commitment. Note *√ √* that, compared toxbin, this vector has only*n*= 2 binary ring elements. Using the tighter bound *N*= 32 for*∥*(w*,*t)*∥*and applying the rationale of [36, Proposition 5.1], one needs to set a modulus*q≈*2

28*.*7 to prove
(w*,*t) is binary. Projecting individually each of the fourLaBRADOSoutput vectors leads to proving binary for a vector of*n*= 8 binary ring elements, which increases*q*to being*≈*2

30*.*7. Note that the infinity norm of the
*√*

|bin|∞|k 1 ∞|∞ k−1|k k−1|k+1|
|---|---|---|---|---|---|
|||9..74 75|||9|
||bin|0|||0..75 74|
||||||bin|
|28.4||||||

projection of our vectorx is at most*∥*u*∥* +*∥*2 *k* *√* v <u>∥</u> +*∥*v₀*∥ ≤*2 *k−*1 + 2 *k* + 2 *k−*1 = 2 *k*+1 *≈*2*·*9*.*75 *nd,* which, applying Theorem 4, leads to*∥*x *∥≤*2 *nd,*giving us a slack factor*α* := 2*· ≈*26*.*35*,*doubled compared to the one ofLaBRADOS*.*Therefore, using the same requirement on*q*to provex is binary leads us to a modulus*q≈*2*.* No Bimodal Rejection Sampling.The*bimodal*rejection sampling [24] used in approximate proofs in [36] involves a bit that needs to be considered as part of the witness, and thus makes the projection constraints quadratic in the witness. In our case, we instead opted for the standard rejection sampling.

3.3LNP-Lite We present the linear-size protocol that effectively provides zero-knowledge to our whole construction. It is based on theLNP[36] protocol, upgraded with the modifications described in Section 3.2. Its setup consists of the same polynomial ring*R*of degree*d*= 256, modulus*q*asLaBRADOS, and challenge space*C*(Section 2.1), for easier composition of the protocols. This protocol proves knowledge of theLaBRADOSoutput vectors, denoted for simplicity bys*i∈R*
*n* *i* ,*i∈*[5], with bounded norms*βi*, and satisfying the verification checks ofLaBRADOS. Notice that in these checks, the vectors₃ appears only in the linear part. In addition, the dimensions*ni*could be different and, in fact, we do not require them to be the same, as inLaBRADOS. We

proceed to describe the protocol. We apply the outer commitment layer as mentioned in Section 2.3. Hence, unless otherwise specified, all the prover’s messages are decomposed in binary and the prover sends instead an outer commitment of them. For simplicity of exposition, we do not make this outer layer explicit in the description. Commit.To ensure zero-knowledge, we sample additional masks whose binary decompositions are col- lected in a new witness vectors₆ *∈R* *n* 6 :

–u*i←*[*−*2 *k* *i* *−*1 *,*2 *k* *i* *−*1 *−*1] 256 ,*i≤*4 masks the projections ofs*i*, for*ki*:=*⌈*log (9*.*75*βi*)*⌉.*We identify each u*i*with the corresponding polynomial*ui∈R*, –*y←Dσ*over*R*masks the projection of high-order values in*{−*1*,*0*,*1*}*, –*gi←{x∈Rq*:ct(*x*) = 0*}*,*i≤⌈*128*/*log*q⌉*masks the aggregation of constant-term constraints.

The prover computes and sends the hiding commitment of ˜s := (s₁*,...,*s₆). For this, he samples a random binary vectorr*s∈R* *n* *s*, to make it indistinguishable from random under M-LWE:

t *s*:=A₁˜s+A *′* 1 r *s∈R* *k* *q* *s* *,*(2) P *k* *s* *×ini′ k* *s* *×ns* whereA₁ *∈Rq,*A₁ *∈Rq*are public matrices. Project in Two Steps.In the first step, the prover replaces the norm statements of the vectorss*i*, *i∈*[4], with modular Johnson-Lindenstrauss projections [11,13,30,36] of their coefficient vectorss*i∈*Z²⁵⁶ *n* *i*. Upon receivingΠ*i←*Bin²⁵⁶1 *×*256*ni* from the verifier, the prover computes the projectionsΠ*i*s*i∈*Z²⁵⁶*q*. Note that the prover does not need to compute the projections ofs₅ or ofs₆. We can assume that the maps Π*i*come from the same projection matrix, by properly removing some columns to compute the respective projections. As*ki*=*⌈*log (9*.*75*βi*)*⌉*,*i∈*[4]*,*we get*∥*Π*i*s*i∥∞≤*2 *k* *i*with high probability. We mask this projection usingu*i←*[*−*2 *k* *i* *−*1 *,*2 *k* *i* *−*1 *−*1] 256 *,*and decompose it as

*k* *i*(1) (0) 256 Π*i*s*i*+u*i*= 2 v*i*+v*i∈*Z*q,*

(0) *ki −*1 *ki −*1 256 (1) 256
withv*i∈*[*−*2*,*2 *−*1]*,*v*i∈{−*1*,*0*,*1*}.*The role ofu*i*here is to uniformize the low-order

(0) (0)
values,v*i*, of the projectionΠ*i*s*i*. Sending them as ring elements*vi∈R*to the verifier would then not

(1)
leak any information. The high-order values,v*i*, would leak possible carries that took place when padding, so they need to be committed. We also control the number of carries, i.e., the number of nonzero entries

(1) (1) 2
that the ternary vectorv*i*has, which is why we reject whenever*∥*v*i∥ > N*, for a fixed threshold*N*. To

(1) (1)
:=w 256 prove thatv*i*is ternary, we write it asv*i i−*t*i,*forw*i,*t*i∈{*0*,*1*},*such thatw*i*encodes the 1’s

(1) (1)
ofv*i*andt*i*encodes the -1’s ofv*i*, i.e., for any*j∈*[256]*,* ( (

(1) (1)
1 ifv*i*[*j*] = 1 1 ifv*i*[*j*] =*−*1 w*i*[*j*] =*,*t*i*[*j*] =. 0 else 0 else

(1) 2 2
Therefore,*∥*v*i∥* =*∥*(w*i,*t*i*)*∥ ≤N*. As*d*= 256, each binary vectorw*i*ort*i*corresponds to a binary ring element*wi*or*ti*. Thus, from the four projections, we collect them all in v˜1*∈R⁸.*As the challenge space is not invariant under*σ−*1*,*we also need to commit to˜v₂ :=*σ−*1(˜v₁)*∈R⁸*. Note that*∥*˜v₁*∥* 2 =*∥*˜v₂*∥* 2 *≤*4*N.* The prover computes and sends the hiding commitment of v˜ := (v˜1*,* v˜2)*∈R¹⁶*. For this, he samples a random binary vectorr*v∈R* *n* *v*, to make it indistinguishable from random under M-LWE:

t *v*:=A₂v˜+A *′* 2 r *v∈R* *k* *q* *v* *,*(3)

whereA₂ *∈R* *k* *q* *v* *×*16 *,*A *′* 2*∈R* *k* *q* *v* *×nv* are public matrices. Along witht*v*, the prover also sends the low-order

(0)
bits,*vi, i∈*[4]*.* Starting from the second step of projection, we follow the lines of [36], for proving knowledge of two witness vectors, ˜sand v˜satisfying dot-product constraints and norm bounds. Thus, the prover creates a masked projectionz := Π˜v ¯1+y*∈*Z²⁵⁶*q*of only˜v₁ *∈R⁸*, using a projection map Π¯ *←*Bin²⁵⁶ *×*2048 received

from the verifier, and a Gaussian masky*←Dσ*froms₆ for zero-knowledge. Note that v˜2=*σ−*1(v˜1) does not need to be projected, as its shortness trivially follows from proving its well-formedness. The prover applies *√* rejection sampling (Lemma 3 (1)) and sendsz, upon acceptance. Then, the verifier checks if*∥*z*∥≤σ* 2*·*256*.* By rejection sampling,zfollows a distribution close to*Dσ,*so this check holds with high probability. For this particular step, we do not apply the outer commitment, as herezis just one polynomial. In addition, the norm check will not be part of the input statement of the upcomingLaBRADOSiteration. Aggregate the Constraints.In this step, the prover aggregates the constraints, following standard techniques [11, 13, 36]. First, the constant-term constraints, the ones from theLaBRADOSchecks and addi- tional ones, are aggregated with random integer challenges from the verifier. The additional constant-term constraints are needed for proving the correctness of:

–the masked projections ofs*i*,*i≤*4, all linear in ˜s*,* v˜, – v˜1being binary, containing the dot-product*⟨*v˜1*,* v˜2*⟩*, – v˜2=*σ−*1(v˜1)*∈R⁸*, all linear in v˜, –the projection of v˜1, all linear in v˜.

Aggregating these constraints preserves the zero constant coefficient. This is performed*λ* :=*⌈*128*/*log*q⌉* many times, as the soundness of one is just 1*/q*. As these aggregations, called*hi*, for*i∈*[*λ*], could leak information on the witness vectors when being sent, the prover masks them with the*gi*’s froms₆. By the definition of*gi*, the coefficients of*hi*are all uniform, except the constant coefficient, which is 0. The verifier can then check ifct(*hi*) = 0. For proving well-formedness of the*hi*’s, the prover constructs new quadratic constraints in ˜s*,* v˜and aggregates them, along with the full constraints fromLaBRADOSchecks, with random polynomial challenges from the verifier. The prover then obtains a single constraint, quadratic in ˜s*,* v˜: X *f*≜ *aij⟨*s*i,*s*j⟩*+*a⟨*v˜1*,* v˜2*⟩*+*⟨φ,*(˜s*,* v˜)*⟩*+*f₀* = 0*,*(4) *i,j∈*[5] P *i∈*[6]*ni*+16 (0) where*aij,a∈ Rq, φ∈ Rq,*and*f₀* a linear function in*hi*’s and*vi*’s. After aggregation, the vectorss₃ ands₆ still appear only in the linear part. If one of the full constraints is not satisfied, then the final constraint*f*would be satisfied with probability 1*/q* *d/*2, assuming*q*splits into two factors. Prove the Final Quadratic.Now the prover wants to let the verifier check Equation (4) in terms P *s vi∈*[6] *n* *i* +16 of the*masked openings*of (˜s*,* v˜) and (r*s,*r*v*), namelyz₁ = (z₁*,*z₁) :=y₁ +*c·*(˜s*,* v˜)*∈ Rq* P and z₂ = (z *s* 2 *,*z *v* 2 ) :=y₂ +*c·*(r*s,*r*v*)*∈ R* *n* *q* *s* +*nv*, for some challenge*c∈ C*and masksy₁ *∈ Ri∈*[6] *n* *i* +16 and y₂ *∈ R* *n* *s* +*nv*. Applying rejection sampling to separate masked openings of ˜sand v˜would be too costly, which is why we treat them together. Let us split thez*i*’s andy*i*’s:

z₁ := (z *s* 1*,*1*,...,*z *s* 1*,*6*,*z *v* 1*,*1*,*z *v* 1*,*2)*,*z *s* 1*,i∈R* *n* *q* *i* *,*z *v* 1*,i∈R⁸q,* z₂ := (z *s* 2 *,*z *v* 2 )*,*z *s* 2*∈R* *n* *q* *s* *,*z *v* 2*∈R* *n* *q* *v* *,*

y₁ := (y₁ *s,* 1 *,...,*y₁ *s,* 6 *,*y₁ *v,* 1 *,*y₁ *v,* 2 )*,*y₁ *s,i* *∈R* *n* *q* *i* *,*y₁ *v,i* *∈R⁸q,*

y₂ := (y₂ *s* *,*y₂ *v* )*,*y₂ *s* *∈R* *n* *q* *s* *,*y₂ *v* *∈R* *n* *q* *v* *.*

For proving Equation (4), he provides the verifier some*garbage termsu* *′* *,v* *′* *∈Rq*, to make the following hold X *aij⟨*z *s* 1*,i,*z *s* 1*,j⟩*+*a⟨*z *v* 1*,*1*,*z *v* 1*,*2*⟩*+*c·⟨φ,*z₁*⟩*+*c² ·f₀* *i,j∈*[5] X =*c²*( *aij⟨*s*i,*s*j⟩*+*a⟨*v˜1*,* v˜2*⟩*+*⟨φ,*(˜s*,* v˜)*⟩*+*f₀*) +*cu* *′* +*v* *′*

*.*(5)
*i,j∈*[5]

To prove that the coefficient of*c²* in Equation (5) vanishes, we send a commitment*u*to*u* *′* and a randomized version*v*of*v* *′* as

*u* :=*u* *′* +*⟨φrand,*r*s⟩, v* :=*v* *′* +*⟨*(*φrand,*0)*,*y₂*⟩.*(6)

If the verifier is given*u,v*and the masked openingsz*i*, he can check X *aij⟨*z *s* 1*,i,*z *s* 1*,j⟩*+*a⟨*z *v* 1*,*1*,*z *v* 1*,*2*⟩*+*c·⟨φ,*z₁*⟩*+*c² ·f₀* *i,j∈*[5] =*cu*+*v−⟨*(*φrand,*0)*,*z₂*⟩,*(7)

which is exactly Equation (5) when the coefficient of*c²* is 0. Now we explainPthe remaining steps of the protocol. The prover samples the masking vectorsy₁ := *s vi∈*[6] *n* *i* +16 *s v ns* +*nv* (y₁*,*y₁)*←Dσ*1andy₂ := (y₂*,*y₂)*←Dσ* 2 and computes their Ajtai commitments as

w*s*:=A₁y₁ *s* +A *′* 1 y₂ *s* *∈R* *k* *q* *s* *,*w*v*:=A₂y₁ *v* +A *′* 2 y₂ *v* *∈R* *k* *q* *v*

*.*(8)
Then he computes*u,v*as in Eqs. (5) and (6). At this point, the prover could sendw*s*,w*v*,*u*, and*v*. Next, after receiving the challenge*c← C*from the verifier, the prover computesz₁ :=y₁ +*c·*(˜s*,* v˜) andz₂ :=y₂ +*c·*(r*s,*r*v*) and applies the rejection sampling from Lemma 3 (1), for eachz*i*,*i∈*[2]. If both algorithms do not abort, the prover outputsz₁*,*z₂. Note that randomness (r*s,*r*v*) is used only once, so a bit of leakage is allowed as when applying Lemma 3 (2). The standard deviations*σ₁* and*σ₂* are set in Section D.2. By rejection sampling, eachz*i*(and its splits) follows a distribution close to p *Dσi,*so that the verifier can check if it is small enough, i.e.*∥*z*i∥≤σi*2dim(z*i*)*,*with high probability. (see Lemma 2). Output and Checks.The last message of the prover is, in fact, made by the masked openingsz*i*and the openings of the outer commitments, which are all binary polynomials collected in the vectorxbin*∈R* *n* bin. In addition to the correctness of the commitments and the binary check onxbin, the verifier has to check the quadratic constraint and separate norm bounds on the splits ofz₁, as these appear in the dot-products of Eq. (7), along with the norm bound onz₂:

|s|′1 s|||
|---|---|---|---|
|1|2|s s||
|v|′2 v|||
|1 i|2 s s|v v v|v|
|ij i,j∈[5]|1,i 1,j|1,1|1,2|
||rand|||
|s||||
|,i||i||
|v|v|||
|,1|,2|s|v|
||bin|||

A₁z +A z =w +*c*t (9) A₂z +A z =w +*c*t (10) ct(*h*) = 0*, i∈*[*λ*] (11) X *a ⟨*z*,*z *⟩*+*a⟨*z*,*z *⟩*+*c·⟨φ,*z₁*⟩*+*c² ·f₀*

=*cu*+*v−⟨*(*φ,*0)*,*z₂*⟩*(12) *√* *∥*z₁ *∥≤σ₁* 2*·*256*n, i∈*[6] (13) *√* *∥*z₁ *∥,∥*z₁ *∥≤σ₁* 2*·*256*·*8 (14) p *∥*z₂*∥≤σ₂* 2*·*256*·*(*n* +*n*) (15) bin-check(x) (16)

Note that the second masked openingz₂ appears only in the linear part of Eq. (7), so there is no need to split. Moreover, all these checks are compatible with the constraint system ofLaBRADOS.

*Security.*Here we analyze the security ofLNP-Lite, at a high level, and refer the reader to Section B.2 for more details. Completeness.Assume that the prover and the verifier behave honestly. Eqs. (9) and (10) hold thanks to Eqs. (2), (3) and (8). Equation (12) holds thanks to Equation (5). Then the verifier is convinced of the well-formedness of*hi*’s,*i∈*[*λ*], whose check Equation (11) holds, because of the masks*gi*. The norm bounds hold with overwhelming probability, according to Lemma 2, as, thanks to rejection sampling (Lemma 3),z₁ andz₂ follow (closely) Gaussian distributions. Zero-Knowledge.It is enough to check that the protocol with no outer commitment has zero-knowledge, thanks to Lemma 5. For this, we follow the same lines as [36, Thm 4.2], except that here we deal with two different Extended M-LWE problems, whose secrets correspond to the random vectorsr*s*andr*v*used in hiding the (inner) commitments.

Soundness.Again, we prove knowledge soundness only for the protocol without outer commitments, thanks to Lemma 4. For simplicity, let us consider the norm bounds as*∥*z *s* 1 *∥≤Bs,∥*z *v* 1 *∥≤Bv,∥*z *s* 2 *∥,∥*z *v* 2 *∥≤* *∥*z₂*∥ ≤Br.*Here we state knowledge soundness. At a high level, we derive the proof by viewing the first step of the projection as a reduction of knowledge from the input relation to a new relation, which could be proven by the originalLNP[36, Prop 5.1.].

Theorem 2.*LetC ⊂ Rqbe the challenge space from Section* p

<u>2.1, of</u> *polynomials with operator norm*
*bounded*

|by|Suppose|M-SIS is|bound8|B +B|rankk, and|
|---|---|---|---|---|---|
|||||s2 r2|s|
|v2|r2|v|||k +1|
|2·9.75 2 0.74||2||||
|128|λ|d/2|LNP-Lite i|20·9.74 .75 i||

p

<u>T.</u> *hard forℓ₂ norm*
p *T*<u>s</u>2 *r*2*andsforℓ₂ norm* *bound*8*T B* +*B* <u>and rank</u>*k. Moreover, assume*max*{*2*σ* 512*/*26*·*2048*·*41*,{*2*i/*0*.*74*·*91*}i≤*4*,*2*·d·* p *n₄ ·,*2*·*(2*σ* 512*/*26)*}≤q.ThenLNP-Liteis a knowledge-sound proof with knowledge soundness* *κ* := 5*/*2 + (1*/q*) + 1*/q* + 2*/|C|and norm slackc* := *≃*26*.*35*, i.e., the extractor is only* *guaranteed to extract witness vectors* s¯*iof norm bounds∥*¯s *∥≤*26*.*35*β.*

3.4 Proving theLNP-LiteOutput withLaBRADOS Now we take theLNP-Liteoutput, (z₁*,*z₂*,*xbin) and the checks it satisfies, and feed them intoLaBRADOS. Note that, thanks to the zero-knowledge protocol, hiding the outer commitments ofLaBRADOSis no longer needed.

|Decompose.As [11], we decompose eachz||into two parts, with respect to some integer basisb|||
|---|---|---|---|---|
|i i|i i|bin|−1 bin|−1 bin|

(0) (1)

*i i*, namely

(0) (1)
z*i*=z +*bi*z, following a rationale similar to that in [11]. Notice that*σ−*1(xbin) has to be part of the witness ofLaBRADOS, asbin-checkconsiders bothx and*σ* (x) and further, the challenge space used inLaBRADOSis not invariant under*σ−*1*.* Minimize the Number of Witness Parts.We note that the input vectors ofLNPs₃ ands₆ are only involved in the linear parts of the aggregated quadratic*f*. Thus, we could think of concatenating (the parts of) their masking openingsz *s* 1*,*3andz *s* 1*,*6together, along with the (the parts of) masked openingz₂. Moreover, Equation (12) considers the dot-products between different parts of the masked openings, namelyz *s* 1*,i*, for *i∈{*1*,*2*,*4*,*5*}*,z *v* 1*,*1*,*z *v* 1*,*2, so these parts should be considered as separate witness vectors forLaBRADOS. In addition to this, we also consider further improvements. Thus, we feedLaBRADOSwith the witness made of the parts of each vector

z *s* 1*,*1*,*z *s* 1*,*2*,*z *s* 1*,*4*,*z *s* 1*,*5*,*z *v* 1*,*1*,*z *v* 1*,*2*,*(z *s* 1*,*3*,*z *s* 1*,*6*,*z₂)*,*

along withxbin*,σ−*1(xbin)*.*The statement that this witness satisfies is created by adapting the verifier checks (Equations (9) to (12)), when replacing the masked openings with their decompositions, and the norm checks *√* updated as before, and on the binary vector*∥*xbin*∥≤ d·n*bin. We use the fact that*⟨*z

(0) +*b*z
(1) *,*z
(0) +*b*z
(1) *⟩*=
*⟨*z

(0) *,*z
(0) *⟩*+*b·*(*⟨*z
(0) *,*z
(1) *⟩*+*⟨*z
(1) *,*z
(0) *⟩*) +*b² ·⟨*z
(1) *,*z
(1) *⟩*.
3.5 The Security of the Pack We analyze the security of the entire construction. Completeness follows as each iteration of it,LaBRADOS, LNP-LiteandLaBRADOR, satisfies completeness. Soundness follows by coupling the soundness of each itera- tion, via [11, Lem.3.7.], and the soundness of each iteration follows by Theorem 1 forLaBRADOS, Theorem 2 forLNP-Liteand by [11, Thm.5.1] forLaBRADOR, each combined with Lemma 4 (when extending with outer commitments). Zero-knowledge is straightforward. To simulate a proof, the simulator can first simulate the prover messages from the iterations ofLaBRADOSbeforeLNP-Liteas commitments of 0, which, by hiding the outer commitments, are indistinguishable from the real ones. When getting toLNP-Lite, he can first simulate the last message ofLNP-Liteand compute the outer commitments of everything from this message, except of the masked openings, which become the remainingLNPprover’s messages. Then, when entering the next iterations ofLaBRADOSandLaBRADOR, he can simply honestly compute the remaining transcript of the com- position, feeding them with the simulatedLNP-Liteoutput. We discuss the security of the non-interactive version in Section C.

## 4 Zero-Knowledge in Practice: Case Studies

We evaluate the performance of our proof system from Section 3 by implementing relevant benchmark exam- ples. To this end, we describe our instantiations of some known primitives, that we tailor to the constraints our proof system supports. As a first example, detailed in Section 4.1, we describe a construction of*verifiable symmetric encryption* built upon a pseudorandom generator, obtained from iterative*learning with rounding*. We note that one can use such a scheme in practice with a public key verifiable encryption scheme which encrypts the PRG seed to construct a very efficient public key verifiable encryption scheme that encrypts long messages. Second, in Section 4.2, we employ a variant of Ajtai’s collision-resistant hash that allows for committing to large inputs (in a streaming manner), and for membership proofs (via Merkle trees). In Section 4.3, we describe a verifiable*mixing subroutine*that, combined with the previous building blocks, leads to a potential candidate of a*full-fledged cryptographic hash function*. 5 We choose to benchmark*blind signatures*as one of the useful examples that the verifiable hash enables. We also describe, for theoretical interest, how one can use such a hash to construct*Incrementally Verifiable Computation*(IVC), which is not yet practically achieved by*any* lattice-based constructions. For all the use cases (except IVC), we provide implementations on top of the LaZer library [40] and report the prover and verifier timings, both when zero-knowledge is enabled (labelled as “zk”) and when it is not (labelled as “not zk”). The secure version is the zero-knowledge-enabled one. The reason why we also include the timings without zero-knowledge is to assess the overhead of adding zero-knowledge to the proof. All the timings come from running the benchmarks on a single core of an Intel Tiger Lake-H CPU. We remark that the proof size remains quite constant across use cases and input size, since the proof size is dominated by the last round ofLaBRADORand therefore we do not report them explicitly. The proof size for non-zero-knowledge examples is around 100KB, whereas the zero-knowledge enabled ones result in around 110KB. The 10KB difference comes from the commitments sent inLNP-Liteand in the extra rounds ofLaBRADOSthat come afterLNP-Lite. This relatively small constant overhead in the proof size is achieved thanks to the strategy of runningLNP-Liteonly once the input is small enough and compressing its messages. Throughout this section, we work with the polynomial ring*R*=Z[*X*]*/*(*X* *d* + 1) with*d*= 512. All the operations in this ring could be translated as operations over the proof system ring (with degree*d*= 256), according to [37, Sec.2.8].

4.1 Pseudorandom Generator The goal of the pseudorandom generator (PRG) is to produce many pseudorandom polynomials (output) from a few random ones (seed). The idea is to apply an expansion function and use part of its output as a new seed and part to compose the PRG output. In this construction, the pseudorandomness of the computed values is based on the hardness of the M-LWR problem. In detail, the expansion function takes as input two binary polynomials*x₀,x₁ ∈R₂*, computes
*⌈*A(*x₀,x₁*) *T* *⌋* 256*→*64 1

|forA← R|, and binary decomposes the result. As the rounding drops the two least significant bits,|||||
|---|---|---|---|---|---|
|||T 256→64 (7) T 256→64 (7) T 256→64||(2) (2) (2)|(7) (7) T (7) T|

(6) (7)

256 *×*2

we write with abuse of notation*⌈*A(*x₀,x₁*) *T* *⌋* 256*→*64=G₂(*y*

(2) *,...,y*
(7) ) withG₂ = (1*,*2*,...,*2
5 ). Let *s₀,s₀ ∈R₂* be the seed. The pseudorandom generator works as follows:

(6)
*⌈*A(*s₀,s₀*) *⌋* =G₂ (*s₁,...,s₁*)

(6)
*⌈*A(*s₁,s₁*) *⌋* =G₂ (*s₂,...,s₂*) (17) ... 5 We have not performed any cryptanalysis of this function, so it should be viewed as a possible line of research for further study orthogonal to the main results of the paper.

(2) (3) (4) (5) (2) *T*
The output iss := (*s₁,s₁,s₁,s₁,s₂,...*).

(6) (7) *T ′* (0) (7) *T*
Proof-friendly.Note that the expansion equation can be written asA(*si,si*) =G₂(*si*+1*,...,si*+1) mod 256 withG *′* 2= (1*,−*2*,*2 2 *,...,*2 7 ), where -2 is required to write the product coefficients in [-2, 253] and correctly drop the two least significant bits. To prove correct execution of the PRG, one needs to prove

(6) (7) (0) (7)
knowledge of the input*s₀,s₀* and the intermediate witnesses*si,...,si*that are binary and satisfy

(6) (7) *T ′* (0) (7) *T*
A(*si,si*) =G₂(*si*+1*,...,si*+1) mod 256. This is natively proven by the proof system in Section 3, since

(6) (7) *T*
that the statement can be written over a ring*Rq*with sufficiently large modulo*q*, asA(*si,si*) *−*256*li*= *′* (0) (7) *T* G₂(*si*+1*,...,si*+1) for some*li∈R*. Security.This function is a pseudorandom generator under the hardness assumption of some Module- LWR problem. Informally, an adversary distinguishing a PRG output with advantage*ϵ*distinguishes with advantage*ϵ/k*a pair of successive hybrids, hence an instance of the Module-LWR problem with parameters *q*= 256,*p*= 64,*m* *′* = 1,*n* *′* = 2,*χ*=*U*(*R₂*), whose concrete hardness we analyze with [4]. The full proof is deferred to Section E.2. Output transformations.The output obtained at this point is a binary vector over the ring*R*of degree*d*= 512. However, one may target uniformly random vectors over the quotient ring*Rq*for some *q >*2, or of a different degree*d* *′*. To obtain a uniformly random vectort*∈ R* *lq*, one needs a binary output of the PRGs*∈ R* *l* 2 *·ℓ* with *ℓ* :=*⌈*log₂ *q⌉*+ 1. A polynomial*ti*is obtained by multiplying a block of the binary vector, ˜s*i∈R* *ℓ* 2, by a *′ ′* 1*×⌈*log₂ *q⌉* matrixB= (B*,*I₁) whereB *←Rq*:

t *T*
= (*t₀,t₁,...*) =B*·*(˜s₀*,*˜s₁*,...*) mod*q.*

The security follows from the hardness of some M-LWE problem with the hybrid argument. We defer its proof to Section E.3. To obtain an element in a ring of different degree, one can use the isomorphism described in [37, Sec.2.8].

Verifiable Symmetric EncryptionPseudorandom generators are often used in stream ciphers, where, given a binary plaintext*m*and a PRG-expanded key, the ciphertext*c*is obtained as*c*=*m⊕*PRG(*k*). Noticing that this equation can be equivalently written as*c*=*m*+PRG(*k*) mod 2, one can achieve verifiable symmetric encryption by proving knowledge of binary plaintext*m*, key*k*, and lifting*l*satisfying*c−*2*l*=*m*+ PRG(*k*) over the proof system ring. In Table 1, we present the results of benchmarking the expansion component of that construction. In particular, we expand a small seed of fixed-length (1024 bits) into outputs of increasing length, and use our proof system to prove the correctness of that expansion.

||Prover|Verifier|
|---|---|---|
||zk not zk|zk not zk|
|2|1.04 0.12|0.51 0.1|
|2|1.01 0.22|0.51 0.17|
|2|1.51 0.6|0.7 0.35|
|2|2.87 1.87|1.27 0.91|
|2|7.86 6.78|3.09 2.69|
|2|27.87 26.57|9.69 9.3|

Output Dimension 6 8 10 12 14 16

Table 1.Timing results in seconds for proving theexpansionof a seed into vectors of binary polynomials. The

dimension refers to the number of output polynomials of degree 512.

4.2 Collision Resistant Hash Function The hash function described in the following is based on the Merkle-Damg˚ard construction to build collision- resistant hash functions [23,41]. Informally, the arbitrary-length input is divided in blocks, and a compression function is applied iteratively to them to obtain a fixed-length output. If the compression function is collision resistant, then the hash function is also collision resistant. In this construction, collision resistance is based on the hardness of the M-SIS problem. In details, letxbe an arbitrary-length binary input, written as a polynomial vector over the ring*R*
6. Firstly, a padding is applied to make the input divisible into blocks. It consists of the minimum number of zero polynomials, followed by one polynomial encoding the dimension of the input in binary:

### padded(x) = (x,0,poly(dim(x))).

The compression function is composed by matrix multiplication over*R₂₅₆*, followed by binary decomposition. LetA*←R¹*256 *×*16, we define the compression function*f*: *R¹⁶*2*→R⁸*2as

### x7→y:= BinDecomp(Axmod 256).

With abuse of notation, we will denote this operation asAx=G₂ymod 256 withG₂ := (1*,*2*,...,*2 7 ). Finally, letx₀*,*x₁*,...∈R⁸*2be the blocks of 8 polynomials composing the padded input, and let IV*∈R⁸*2be a fixed initial vector. We compute as follows:

A(IV*,*x₀) =G₂y₀ mod 256 A(y₀*,*x₁) =G₂y₁ mod 256 (18) ...

The output is the last value ofy*.*

|i|||
|---|---|---|
||i−1 i|i|
|q|i i|i|

Proof-friendly.To prove knowledge of a preimage of the hash function, one needs to prove knowledge of the input blocksx*i*and the intermediate witnessesy*i*that are binary and satisfyA(y*,*x) =G₂y mod 256. The hash preimage is natively proven by the proof system in Section 3, noticing that the last statement can be written over a ring*R* with sufficiently large modulo*q*, asA(y*i−*1*,*x)*−*256*l* =G₂y for some*li∈R*. Security.The hash function is collision resistant under the hardness assumption of some Module-SIS problem, whose concrete hardness is more than 256-bits [4]. At a high level, this is because from an adversary that finds collisions in the hash function, one constructs an adversary that finds collisions in the compression function, namely pairs (y*i−*1*,*x*i*)*̸*= (y*i′−*1*,*x *′i* ) such thatA(y*i−*1*,*x*i*) =A(y*i′−*1*,*x *′i* ) mod 256, and obtains a solution to the M-SIS problem. The full proof is deferred to Section E.1.

Committing to Large InputsThe hash function presented above can be used as an alternative to the Ajtai commitment for inputs of large dimension. The advantage is that the public key and the modulus are smaller and fixed. We show results in Table 2 when using our proof system to prove correctness of such commitments to inputs of increasing length.

Batched Proof of MembershipSuppose that we want to prove knowledge of a private element contained in a public set*S*consisting of 2 *N* elements (e.g. the public keys of users). We can do so by proving knowledge of a path in a Merkle tree of height*N*computed as follows:

–The leaves are the hashes of the elements in the set. –The parent nodey*∈R⁸*2is computed from the childrenx*l,*x*r∈R⁸*2using the compression function*f*as A(x*l,*x*r*) =G₂ymod 256. 6 If the input is originally not in this ring, a padding may be required.

||Prover||Verifier||
|---|---|---|---|---|
||zk|not zk|zk|not zk|
|2|1.13|0.13|0.53|0.1|
|2|1.26|0.32|0.56|0.21|
|2|1.84|0.68|0.74|0.39|
|2|2.8|1.93|1.21|0.89|
|2|7.16|6.29|2.8|2.48|
|2|29.35|29.44|9.18|9.58|

Input Dimension 6 8 10 12 14 16

Table 2.Timing results in seconds for proving thecompressionof vectors of polynomials. The dimension refers to

the number of input polynomials of degree 512.

To prove knowledge of a path in the tree from the root to the leaf corresponding to the private element in zero-knowledge, one proves knowledge of the nodesv*i∈R⁸*2, their siblingsw*i∈R⁸*2, and the path indicators *xi∈{*0*,*1*}*(encoding 0 ifv*i*is the left child, 1 otherwise) satisfying, for any level index*i*,

### (1−xi)·A(vi,wi) +xi·A(wi,vi) =G₂vi−1mod 256.

Additionally, all witnesses must be binary, and the path indicators also be integers. In our results in Table 3, we consider a tree of height 64 and prove knowledge of several private elements belonging to the tree.

||Prover||Verifier||
|---|---|---|---|---|
||zk|not zk|zk|not zk|
|1|1.61|0.56|0.7|0.33|
|2|1.68|0.82|0.82|0.46|
|4|2.39|1.37|1.09|0.72|
|8|3.37|2.23|1.48|1.06|
|16|5.22|4.39|2.2|1.91|
|32|9.37|8.59|3.97|3.68|
|64|17.85|17.62|6.35|6.32|
|128|39.2|35.73|12.63|11.61|

### Number of Paths

Table 3.Timing results in seconds for provingmembershipof increasing numbers of elements in a tree of height

64.
4.3 Beyond Collision Resistance In this section, we attempt to construct a cryptographic hash function candidate with the intention of instan- tiating a random oracle with this candidate primitive. This hash function relies on the*mixing*subroutine, a function that behaves as much as possible like a truly random one. We present how this instantiation gives rise to a construction of a blind signature. MixingThe goal of the mixing is to obtain a function that behaves as much as possible like a truly random one, and can be used in practice to instantiate it (eventually combined with other components). Let the input vector bez₀ *∈R⁹*. The mixing consists of applying a fixed number of times two functions,

|2 1 ×9 ′|×8|
|---|---|
|256|257|

described by public parametersA*← R*,A *← R¹*, and*c₀,...c₄ ← R₂₅₆*. LetG₂ = (1*,*2*,...,*2
7 ),

G *′* 2= (1*,*2*,...,*2 8 ). Then

Az₀ +*c₀* =G₂z *′* 1mod 256 A *′* z *′* 1=G *′* 2 z₁ mod 257 Az₁ +*c₁* =G₂z *′* 2mod 256 .. (19). A *′* z *′* 4=G *′* 2 z₄ mod 257 Az₄ +*c₄* =G₂z *′* 5mod 256

If the mixing achieves its scope, in practice, it can only be validated by cryptanalysis; however, in the following, we give the intuition behind its components. The matrix multiplication provides collision resistance and*confusion*, namely, makes the relation between input and output as complex as possible. The binary decomposition yields*diffusion*, spreading the influence of an input polynomial across many output ones; additionally, it introduces some non-linearity. The alternating moduli aim at further avoiding patterns that an adversary could exploit in distinguishing the output from random. Finally, the public constants*ci*ensure that, at any iteration, the zero input is not assigned to the zero output. Proof-friendly.Due to the operations over the ring*R₂₅₇*, proving the mixing relation additionally requires ensuring that the elementz*i*is the binary representation of a polynomial modulo 257, i.e. that either the most significant bit is 0, or all the others are. This can be proven by imposing that the sums

(0) (8) (7) (8)
*z* *i*+*zi*, ...,*zi*+*zi*are binary.

Cryptographic Hash Function CandidateMany protocols involving hash functions prove security in the random oracle model (ROM), [7], namely, treating a hash function as a truly random function. One could attempt to construct such a candidate hash function by combining the previous building blocks. First, the collision resistant hash function in Section 4.2 is applied to compress the arbitrary-length input. Second, we apply a “mixing component” described in in Section 4.3; however, one could use any alternative instantiation of a random function. Finally, we can apply the pseudo-random generator in Section 4.1. It can be proved that if the mixing is simulated by a random oracle, the candidate full-fledged hash function is pseudorandom. Our “compress-mix-expand” cryptographic hash function construction cannot be proven secure in the indifferentiability framework (c.f. [20]) by just viewing the mixing part as a random oracle. Nevertheless, we believe that because the lattice-based compression and expansion components are well- understood cryptographic constructions, one could try to cryptanalyze the function as a whole. We leave this line of research to future work.

Blind signaturesBlind signatures are protocols in which the user obtains signatures of their messages without revealing to the signer any information about the message. In [10], the authors propose a blind signature scheme from lattice assumptions, whose security is proven in the random oracle model. At a high level, in this protocol the user commits to the message*µ*computingc=Br+*H*(*µ,H*(r))*∈ Rq*with commitment matrixB*←R¹q×* 2 and randomnessr*←χ²*, and sends to the signer the commitmentcwith a zero-knowledge proof of knowledge for its correctness. The issuer signs the commitment providing a short preimages, i.e. such thatAs=c. The user proves that they have a valid signature for*µ*, with a zero- knowledge proof of knowledge fors,rsuch thatAs=Br+*h*. While this linear proof can be efficiently done with the originalLNP, proving the correctness of the commitmentcbenefits from the proof system in Section 3. In the following, we benchmark this proof, when instantiating the hash function with the hash function candidate presented in Section 4.3.

Incrementally Verifiable Computation from Folding Scheme[15, 16, 18, 19, 26, 29, 33, 43] propose quantum-secure folding schemes (or accumulation schemes) that fold witness-statement pairs for a relation into a single pair. Folding schemes are used as building blocks for incrementally verifiable computation

<u>Prover Verifier</u> Message Dimension zk not zk zk not zk 10 1*.*18 0*.*26 0*.*5 0*.*18

Table 4.Timing results in seconds for proving the knowledge of a commitment in the blind signature protocol. The

dimension refers to the number of input polynomials of degree 512.

protocols (IVC) [45] and proof-carrying data (PCD) [22]. Both primitives follow a general blueprint: the verifier circuit (including hash functions after the Fiat–Shamir transformation) is expressed as a set of constraints for an input relation, and the folding-scheme prover recursively folds the witness-statement pairs of that verifier circuit at each computation step. A key advantage is that the proof size and verification time of IVC/PCD are independent of the number of computation steps, and the memory required by the prover is also step-independent, unlike “monolithic” SNARKs (following the terminology in, e.g., [17]). A crucial component, and the main reason current constructions remain impractical, is the hash function embedded in the verifier circuit, which must be efficiently verifiable.

## 5 Implementation

We have implemented the benchmarks reported in Section 4 on top of the LaZer library [40]. They can be reproduced at

[https://github.com/lazer-crypto/lazer](https://github.com/lazer-crypto/lazer).

Those benchmarks depend on two core modules that we have implemented: the proof system of this work, accessible at[https://github.com/lazer-crypto/labrador](https://github.com/lazer-crypto/labrador); and a C library for the hash function of Sec- tion 4.3, located in thesrc/lattice-hashfolder of thelazer-crypto/lazerGitHub repository.

5.1 Proof System We implement the proof system of this work on top of the C arithmetic and protocols of [13], which in turn builds on top of [11, 40, 42]. We describe here our main contributions. Dachshundv2.In practice, the statement that a user wants to prove may not be directly compatible with the statements thatLaBRADORcan prove. The reason for this is that this protocol expects a small number of witness vectors for efficiency, and there is some pre-processing required to prove exact*ℓ₂*-norms and binary constraints. This was addressed by the LaZer library [40] with theDachshundfrontend. We re-implement it to make it compatible withLaBRADOSand extend it in several fronts, resulting in the protocol that we refer to here asDachshundv2. Therefore, one can seeDachshundv2as the frontend protocol whose output is fed to the first iteration ofLaBRADOSin Figure 1. First, in addition to exact*ℓ₂*-norms and binary, the user can indicate instead that the*ℓ₂*-norm of a vector is to be proven approximately, giving both the public bound it satisfies and the public bound that the proof system should guarantee.Dachshundv2will then merge many witness vectors, as long as the norm guarantee resulting from projecting all of them together inLaBRADOSis small enough for all the vectors involved (also accounting for the slack from the projection). This makes the proof more efficient, since proving exact norms requires proving a quadratic over the integers, and thus a larger modulus to ensure there is no wrap-around in the quadratic. Second, we support arbitrary quadratics between witness vectors. We do so by committing to the witness and obtaining polynomial challenges that can aggregate the quadratic equations, in a similar fashion to how Dachshunddeals with exact*ℓ₂*-norms (see [40, Section 4]). We then extend the witness with two witness vectors that contain the concatenation of the left and right parts of all the quadratic terms, multiplying one of the sides by the polynomial challenges. This means that, after proving the consistency of these new parts with respect to the original witness, the original quadratics can be proven by simply proving the dot- product between these two new witness vectors. As a consequence, the original witness vectors appearing

in quadratics can safely be merged together, as long as their norm requirements allow it. Additionally, we support quadratics taking place over rings with a higher degree than that of the proof system by expanding one of the sides of the dot product into the rotation matrix and aggregating its rows with challenges before adding it to the new witness vectors (see [37, Section 2.8.] for expressing multiplication over higher-degree rings in terms of a rotation matrix). LNP-Lite.Both the originalLNPconstruction and its implementation are not suitable for use as a round in our composed protocol. The conceptual changes and new techniques are described in Sections 3.2 and 3.3, with the two-step projection being the core improvement. Those improvements allowLNP-Liteto use the same small modulus asLaBRADOR, allowing us to base our implementation onLaBRADOR’s AVX-512 optimized single-precision coefficient arithmetic. To enable protocol composition, the verifier was expressed in dot- product constraints usingLaBRADOR’s constraint library. BothLNP-Lite’s input and output areLaBRADOR- compatible constraint systems (plus prover messages). The generation ofLNP-Liteparameters plays a crucial role in determining the round structure of the composed protocol: if it is not possible to find the secure LNP-Liteparameters, more precedingLaBRADOSrounds will be added. Pack.We implement aPacklogic that orchestrates the composition of the different protocols. Its param- eter generation decides how many iterations to perform of each protocol and in which order, according to the flow of Figure 1. By default, iterations ofLaBRADORandLaBRADOSare added as long as the improve- ment in witness size is more than 10%. Internally, the parameter generations of those two protocols look for the split of the witness that leads to the smallest output witness. At the end of the protocol, the last iteration ofLaBRADORis the special last round described in [11] where no middle (nor outer) commitments are computed. WhenLaBRADOSis run beforeLNP-Lite, then the former is indicated to use randomness in the outer commitments, and further iterations are run untilLNP-Litesuccessfully finds secure parameters. Additional complexity comes from the fact that the parametrization ofLaBRADOSchanges depending on whether the protocol that comes after isLaBRADOS,LNP-LiteorLaBRADOR, since each of them proves the *ℓ₂*-norms with different slacks. The inclusion of theLNP-Literound in betweenLaBRADOSrounds is optional, and determined by a flag of whether the proof requires zero-knowledge. Python Wrapper.LaZer provides a convenient way of defining the statement and to populate the witness that is then fed either toLaBRADORor toLNP. We extend LaZer so that the proof system used underneath is the composition of protocols described in Section 3, with an optional zero-knowledge flag that determines whether a round ofLNP-Liteis performed or not. We additionally extend the Python API to support the definition of quadratics and approximate*ℓ₂*-norms, powered by our newDachshundv2.

5.2 Lattice Hash The proof-friendly hash of Section 4.3 is realised as a stand-alone C library exposing compression, mixing, and expansion as separate entry points, with padding left to the caller. The library is independent of the rest of the toolkit and can be used externally; a companion Python module ships inside LaZer, integrating the construction with the proof-system frontend. The hash is defined over*R*=Z[*X*]*/*(*X*
*d* + 1) with*d*= 512. Multiplications are evaluated in*Rq*for an auxiliary prime*q*chosen large enough that no reduction modulo*q*ever occurs on a reused result, and small enough to admit a length-*d*negacyclic NTT and Intel HEXL’s AVX-512 modular kernels [12]. The choice of *q*is a coding artefact and does not affect any output. Non-NTT stages, namely splitting modulo 256 or 257 and bit decomposition, are vectorised with AVX-512. Compression (described in Section 4.2) applies a fixed public matrixA*∈R¹* *×*16 to the concatenation of two binary inputsx*∈{*0*,*1*}* 16*d*, withAprecomputed in NTT form. Each output coefficient is split into a remainderrand quotientq; the surrounding proof system has no native primitive for reducing modulo 256, so the rounding is tracked by committing to both, allowingAx= 256*·*q+rto be enforced as a constraint in the ambient ring. Mixing (described in Section 4.3) alternates two variants of the same primitive differing only in rounding modulus: one reduces modulo 256, producing eight binary output layers (with a public shift selected by round index), the other modulo 257, producing nine. The latter is implemented with a precomputed Shoup multiplier for 257 *−*1 mod*q*, avoiding per-coefficient division. Expansion (done via PRG from Section 4.1) reuses the same NTT and splitting machinery: each iteration computesa₁s₁ +a₂s₂, rounds

modulo 256, and bit-decomposes the result, feeding two bit-planes into the next iteration and emitting the rest as digest material. All public matrices and shifts are derived deterministically from a single fixed published seed viashake128, isolating all randomness in one string and enabling independent audit. All primitives are data-oblivious: HEXL’s NTT and elementwise kernels, the custom AVX-512 helpers for splitting and bit decomposition, and the Shoup-based reduction modulo 257 all run in time independent of operands, with no input-dependent branches or memory accesses. A SageMath transcript checker recomputes each stage symbolically inZ[*X*]*/*(*X* *d* + 1) as an independent correctness oracle. The C library, checker, and parameter generator are self-contained, and the construction can be used as a Fiat–Shamir or Merkle-tree hash outside of LaZer.

## Acknowledgements

This work was supported by the ERC Consolidator Grant PLAZA (101002845), the ERC Starting Grant GLAZE (101222273), Research Council of Finland (358951) and Technology Industries of Finland Centennial Foundation’s Future Makers 2025 grant (project SPICED).

## References

1.Aardal, M.A., Aranha, D.F., Boudgoust, K., Kolby, S., Takahashi, A.: Aggregating falcon signatures with LaBRADOR. In: Reyzin, L., Stebila, D. (eds.) CRYPTO 2024, Part I. LNCS, vol. 14920, pp. 71–106. Springer, Cham (Aug 2024).[https://doi.org/10.1007/978-3-031-68376-3_3](https://doi.org/10.1007/978-3-031-68376-3_3)
2.Albrecht, M.R., Curtis, B.R., Deo, A., Davidson, A., Player, R., Postlethwaite, E.W., Virdia, F., Wunderer, T.: Estimate all the LWE, NTRU schemes! In: Catalano, D., De Prisco, R. (eds.) SCN 18. LNCS, vol. 11035, pp. 351–367. Springer, Cham (Sep 2018).[https://doi.org/10.1007/978-3-319-98113-0_19](https://doi.org/10.1007/978-3-319-98113-0_19)
3.Albrecht, M.R., Davidson, A., Deo, A., Gardham, D.: Crypto dark matter on the torus-oblivious PRFs from shallow PRFs and TFHE. In: Joye, M., Leander, G. (eds.) EUROCRYPT 2024, Part VI. LNCS, vol. 14656, pp. 447–476. Springer, Cham (May 2024).[https://doi.org/10.1007/978-3-031-58751-1_16](https://doi.org/10.1007/978-3-031-58751-1_16)
4.Albrecht, M.R., Player, R., Scott, S.: On the concrete hardness of learning with errors. J. Math. Cryptol.9(3), 169– 203 (2015),[http://www.degruyter.com/view/j/jmc.2015.9.issue-3/jmc-2015-0016/jmc-2015-0016.xml](http://www.degruyter.com/view/j/jmc.2015.9.issue-3/jmc-2015-0016/jmc-2015-0016.xml)
5.Attema, T., Lyubashevsky, V., Seiler, G.: Practical product proofs for lattice commitments. In: Micciancio, D., Ristenpart, T. (eds.) CRYPTO 2020, Part II. LNCS, vol. 12171, pp. 470–499. Springer, Cham (Aug 2020). [https://doi.org/10.1007/978-3-030-56880-1_17](https://doi.org/10.1007/978-3-030-56880-1_17)
6.Banaszczyk, W.: New bounds in some transference theorems in the geometry of numbers. In: Mathematische Annalen. vol. 296, p. 625–635 (1993)
7.Bellare, M., Rogaway, P.: Random oracles are practical: A paradigm for designing efficient protocols. In: Denning,
D.E., Pyle, R., Ganesan, R., Sandhu, R.S., Ashby, V. (eds.) ACM CCS 93. pp. 62–73. ACM Press (Nov 1993). [https://doi.org/10.1145/168588.168596](https://doi.org/10.1145/168588.168596)
8.Ben-Sasson, E., Bentov, I., Horesh, Y., Riabzev, M.: Scalable, transparent, and post-quantum secure computa- tional integrity. Cryptology ePrint Archive, Report 2018/046 (2018),[https://eprint.iacr.org/2018/046](https://eprint.iacr.org/2018/046)
9.Ben-Sasson, E., Chiesa, A., Riabzev, M., Spooner, N., Virza, M., Ward, N.P.: Aurora: Transparent succinct arguments for R1CS. In: Ishai, Y., Rijmen, V. (eds.) EUROCRYPT 2019, Part I. LNCS, vol. 11476, pp. 103–128. Springer, Cham (May 2019).[https://doi.org/10.1007/978-3-030-17653-2_4](https://doi.org/10.1007/978-3-030-17653-2_4)
10.Beullens, W., Lyubashevsky, V., Nguyen, N.K., Seiler, G.: Lattice-based blind signatures: Short, efficient, and round-optimal. In: Meng, W., Jensen, C.D., Cremers, C., Kirda, E. (eds.) ACM CCS 2023. pp. 16–29. ACM Press (Nov 2023).[https://doi.org/10.1145/3576915.3616613](https://doi.org/10.1145/3576915.3616613)
11.Beullens, W., Seiler, G.: LaBRADOR: Compact proofs for R1CS from module-SIS. In: Handschuh, H., Lysyan- skaya, A. (eds.) CRYPTO 2023, Part V. LNCS, vol. 14085, pp. 518–548. Springer, Cham (Aug 2023).https: //doi.org/10.1007/978-3-031-38554-4_17
12.Boemer, F., Kim, S., Seifu, G., de Souza, F.D.M., Gopal, V.: Intel HEXL: Accelerating homomorphic encryption with intel AVX512-IFMA52. Cryptology ePrint Archive, Report 2021/420 (2021),[https://eprint.iacr.org/](https://eprint.iacr.org/) 2021/420
13.Bolboceanu, M., Bootle, J., Lyubashevsky, V., Merino-Gallardo, A., Seiler, G.: Orthus: Practical sublinear batch- verification of lattice relations from standard assumptions. Cryptology ePrint Archive, Report 2026/398 (2026), [https://eprint.iacr.org/2026/398](https://eprint.iacr.org/2026/398)

14.Bolboceanu, M., Costache, A., Hales, E., Player, R., Rosca, M., Titiu, R.: Designs for practical SHE schemes based on ring-LWR. CiC2(1), 21 (2025).[https://doi.org/10.62056/av7tudy6b](https://doi.org/10.62056/av7tudy6b)
15.Boneh, D., Chen, B.: LatticeFold: A lattice-based folding scheme and its applications to succinct proof systems. In: ASIACRYPT 2025, Part III. pp. 330–362. LNCS, Springer, Singapore (Dec 2025).[https://doi.org/10](https://doi.org/10). 1007/978-981-95-5099-9_11
16.Boneh, D., Chen, B.: LatticeFold+: Faster, simpler, shorter lattice-based folding for succinct proof systems. In: CRYPTO 2025, Part VII. pp. 327–361. LNCS, Springer, Cham (Aug 2025).[https://doi.org/10.1007/](https://doi.org/10.1007/) 978-3-032-01907-3_11
17.B¨unz, B., Chiesa, A., Fenzi, G., Wang, W.: Linear-time accumulation schemes. Cryptology ePrint Archive, Report 2025/753 (2025),[https://eprint.iacr.org/2025/753](https://eprint.iacr.org/2025/753)
18.B¨unz, B., Mishra, P., Nguyen, W., Wang, W.: Accumulation without homomorphism. In: ITCS 2025. pp. 23:1– 23:25. LIPIcs (Jan 2025).[https://doi.org/10.4230/LIPIcs.ITCS.2025.23](https://doi.org/10.4230/LIPIcs.ITCS.2025.23)
19.B¨unz, B., Mishra, P., Nguyen, W., Wang, W.: Arc: Accumulation for reed-solomon codes. In: CRYPTO 2025, Part VII. pp. 128–160. LNCS, Springer, Cham (Aug 2025).[https://doi.org/10.1007/978-3-032-01907-3_5](https://doi.org/10.1007/978-3-032-01907-3_5)
20.Canteaut, A., Fuhr, T., Naya-Plasencia, M., Paillier, P., Reinhard, J.R., Videau, M.: A unified indifferentiability proof for permutation- or block cipher-based hash functions. Cryptology ePrint Archive, Paper 2012/363 (2012), [https://eprint.iacr.org/2012/363](https://eprint.iacr.org/2012/363)
21.Chiesa, A., Hu, Y., Maller, M., Mishra, P., Vesely, P., Ward, N.P.: Marlin: Preprocessing zkSNARKs with universal and updatable SRS. In: Canteaut, A., Ishai, Y. (eds.) EUROCRYPT 2020, Part I. LNCS, vol. 12105, pp. 738–768. Springer, Cham (May 2020).[https://doi.org/10.1007/978-3-030-45721-1_26](https://doi.org/10.1007/978-3-030-45721-1_26)
22.Chiesa, A., Tromer, E.: Proof-carrying data and hearsay arguments from signature cards. In: Yao, A.C.C. (ed.) ICS 2010. pp. 310–331. Tsinghua University Press (Jan 2010)
23.Damg˚ard, I.: A design principle for hash functions. In: Brassard, G. (ed.) CRYPTO’89. LNCS, vol. 435, pp. 416–427. Springer, New York (Aug 1990).[https://doi.org/10.1007/0-387-34805-0_39](https://doi.org/10.1007/0-387-34805-0_39)
24.Ducas, L., Durmus, A., Lepoint, T., Lyubashevsky, V.: Lattice signatures and bimodal Gaussians. In: Canetti,
R., Garay, J.A. (eds.) CRYPTO 2013, Part I. LNCS, vol. 8042, pp. 40–56. Springer, Berlin, Heidelberg (Aug
2013).[https://doi.org/10.1007/978-3-642-40041-4_3](https://doi.org/10.1007/978-3-642-40041-4_3)
25.Ducas, L., Kiltz, E., Lepoint, T., Lyubashevsky, V., Schwabe, P., Seiler, G., Stehl´e, D.: CRYSTALS-Dilithium: A lattice-based digital signature scheme. IACR TCHES2018(1), 238–268 (2018).[https://doi.org/10.13154/](https://doi.org/10.13154/) tches.v2018.i1.238-268,[https://tches.iacr.org/index.php/TCHES/article/view/839](https://tches.iacr.org/index.php/TCHES/article/view/839)
26.Fenzi, G., Knabenhans, C., Nguyen, N.K., Pham, D.T.: Lova: Lattice-based folding scheme from unstructured lattices. In: Chung, K.M., Sasaki, Y. (eds.) ASIACRYPT 2024, Part IV. LNCS, vol. 15487, pp. 303–326. Springer, Singapore (Dec 2024).[https://doi.org/10.1007/978-981-96-0894-2_10](https://doi.org/10.1007/978-981-96-0894-2_10)
27.Fiat, A., Shamir, A.: How to prove yourself: Practical solutions to identification and signature problems. In: Odlyzko, A.M. (ed.) CRYPTO’86. LNCS, vol. 263, pp. 186–194. Springer, Berlin, Heidelberg (Aug 1987).https: //doi.org/10.1007/3-540-47721-7_12
28.Gabizon, A., Williamson, Z.J., Ciobotaru, O.: PLONK: Permutations over Lagrange-bases for oecumenical non- interactive arguments of knowledge. Cryptology ePrint Archive, Report 2019/953 (2019),[https://eprint.iacr](https://eprint.iacr). org/2019/953
29.Garreta, A., Lipmaa, H., Luha¨a¨ar, U., Osadnik, M.: Cyclo: Lightweight lattice-based folding via partial range checks. Eurocrypt 2026, to appear (2026),[https://eprint.iacr.org/2026/359](https://eprint.iacr.org/2026/359)
30.Gentry, C., Halevi, S., Lyubashevsky, V.: Practical non-interactive publicly verifiable secret sharing with thou- sands of parties. In: Dunkelman, O., Dziembowski, S. (eds.) EUROCRYPT 2022, Part I. LNCS, vol. 13275, pp. 458–487. Springer, Cham (May / Jun 2022).[https://doi.org/10.1007/978-3-031-06944-4_16](https://doi.org/10.1007/978-3-031-06944-4_16)
31.Groth, J.: On the size of pairing-based non-interactive arguments. In: Fischlin, M., Coron, J.S. (eds.) EU- ROCRYPT 2016, Part II. LNCS, vol. 9666, pp. 305–326. Springer, Berlin, Heidelberg (May 2016).https: //doi.org/10.1007/978-3-662-49896-5_11
32.Klooss, M., Lai, R.W.F., Nguyen, N.K., Osadnik, M., Tucci, L.: RoKoko: Lattice-based succinct arguments, a committed refinement. Cryptology ePrint Archive, Paper 2026/575 (2026),[https://eprint.iacr.org/2026/575](https://eprint.iacr.org/2026/575)
33.Kuriyama, S., Lai, R.W.F., Osadnik, M., Tucci, L.: SALSAA – sumcheck-aided lattice-based succinct arguments and applications. Cryptology ePrint Archive, Report 2025/2124 (2025),[https://eprint.iacr.org/2025/2124](https://eprint.iacr.org/2025/2124)
34.Langlois, A., Stehl´e, D.: Worst-case to average-case reductions for module lattices. DCC75(3), 565–599 (2015). [https://doi.org/10.1007/s10623-014-9938-4](https://doi.org/10.1007/s10623-014-9938-4)
35.Lyubashevsky, V.: Lattice signatures without trapdoors. In: Pointcheval, D., Johansson, T. (eds.) EURO- CRYPT 2012. LNCS, vol. 7237, pp. 738–755. Springer, Berlin, Heidelberg (Apr 2012).[https://doi.org/10](https://doi.org/10). 1007/978-3-642-29011-4_43

36.Lyubashevsky, V., Nguyen, N.K., Plan¸con, M.: Lattice-based zero-knowledge proofs and applications: Shorter, simpler, and more general. In: Dodis, Y., Shrimpton, T. (eds.) CRYPTO 2022, Part II. LNCS, vol. 13508, pp. 71–101. Springer, Cham (Aug 2022).[https://doi.org/10.1007/978-3-031-15979-4_3](https://doi.org/10.1007/978-3-031-15979-4_3)
37.Lyubashevsky, V., Nguyen, N.K., Plan¸con, M., Seiler, G.: Shorter lattice-based group signatures via “almost free” encryption and other optimizations. In: Tibouchi, M., Wang, H. (eds.) ASIACRYPT 2021, Part IV. LNCS, vol. 13093, pp. 218–248. Springer, Cham (Dec 2021).[https://doi.org/10.1007/978-3-030-92068-5_8](https://doi.org/10.1007/978-3-030-92068-5_8)
38.Lyubashevsky, V., Nguyen, N.K., Seiler, G.: Shorter lattice-based zero-knowledge proofs via one-time commit- ments. In: Garay, J. (ed.) PKC 2021, Part I. LNCS, vol. 12710, pp. 215–241. Springer, Cham (May 2021). [https://doi.org/10.1007/978-3-030-75245-3_9](https://doi.org/10.1007/978-3-030-75245-3_9)
39.Lyubashevsky, V., Seiler, G.: Short, invertible elements in partially splitting cyclotomic rings and applications to lattice-based zero-knowledge proofs. In: Nielsen, J.B., Rijmen, V. (eds.) EUROCRYPT 2018, Part I. LNCS, vol. 10820, pp. 204–224. Springer, Cham (Apr / May 2018).[https://doi.org/10.1007/978-3-319-78381-9_8](https://doi.org/10.1007/978-3-319-78381-9_8)
40.Lyubashevsky, V., Seiler, G., Steuer, P.: The LaZer library: Lattice-based zero knowledge and succinct proofs for quantum-safe privacy. In: Luo, B., Liao, X., Xu, J., Kirda, E., Lie, D. (eds.) ACM CCS 2024. pp. 3125–3137. ACM Press (Oct 2024).[https://doi.org/10.1145/3658644.3690330](https://doi.org/10.1145/3658644.3690330)
41.Merkle, R.C.: One way hash functions and des. In: Brassard, G. (ed.) CRYPTO 1989. LNCS, vol. 435, pp. 428–446. Springer, New York, NY (1990).[https://doi.org/10.1007/0-387-34805-0_40](https://doi.org/10.1007/0-387-34805-0_40)
42.Nguyen, N.K., Seiler, G.: Greyhound: Fast polynomial commitments from lattices. In: Reyzin, L., Stebila, D. (eds.) CRYPTO 2024, Part X. LNCS, vol. 14929, pp. 243–275. Springer, Cham (Aug 2024).[https://doi.org/](https://doi.org/)
10.1007/978-3-031-68403-6_8
43.Nguyen, W., Setty, S.: Neo: Lattice-based folding scheme for CCS over small fields and pay-per-bit commitments. Cryptology ePrint Archive, Report 2025/294 (2025),[https://eprint.iacr.org/2025/294](https://eprint.iacr.org/2025/294)
44.Pino, R.D., Katsumata, S., Niot, G., Reichle, M., Takemure, K.: Unmasking traccoon: A lattice-based threshold signature with an efficient identifiable abort protocol. In: Kalai, Y.T., Kamara, S.F. (eds.) CRYPTO 2025, Part VI. pp. 423–456. LNCS, Springer (2025).[https://doi.org/10.1007/978-3-032-01887-8_14,https://doi.org/](https://doi.org/10.1007/978-3-032-01887-8_14,https://doi.org/)
10.1007/978-3-032-01887-8_14
45.Valiant, P.: Incrementally verifiable computation or proofs of knowledge imply time/space efficiency. In: Canetti,
R. (ed.) TCC 2008. LNCS, vol. 4948, pp. 1–18. Springer, Berlin, Heidelberg (Mar 2008).[https://doi.org/10](https://doi.org/10). 1007/978-3-540-78524-8_1
46.Wahby, R.S., Tzialla, I., shelat, a., Thaler, J., Walfish, M.: Doubly-efficient zkSNARKs without trusted setup. In: 2018 IEEE Symposium on Security and Privacy. pp. 926–943. IEEE Computer Society Press (May 2018). [https://doi.org/10.1109/SP.2018.00060](https://doi.org/10.1109/SP.2018.00060)

## Appendix

## A Deferred Preliminaries

p

|||||P|P|
|---|---|---|---|---|---|
|||p||p i|i i|
|||p|2 i i p||p|
||||q|||
|q−|q−|||||
|2 1|2 1|||||
||||′|||
|d/d|||d/d|||

*p* We consider the norm of elements in*R*to be*∥a∥* =*|a|*if<u>a∈Z</u>and*∥a∥p*= *|a |* if*a*= *a X ∈R*, q P for*p >*1. We extend the notation to vectors*∥*a*∥* = *∥*a *∥*. We remove the subscript of*∥·∥* when *p*= 2. In the quotient ring, the norm of an element in*R* is the norm of its unique representative*R*with coefficients in [*−,*]. In power-of-two cyclotomic rings, working over subrings*S*of*R*is possible, as detailed in [37, Section *d* *′*

2.8.]. Namely, if*S*=Z[*X*]*/*(*X* + 1) a subring of*R*, for*d |d*, then, there is a norm-preserving bijection
*′ ′* *Φ*: *R→S,*using the embedding of*S*in*R*via*X→X*. This bijection can be naturally extended to vectors over*S*and*R*and over their quotients mod*q*. Using this embedding, one could translate the multiplication by a ring element*a∈R*as a linear map over*S*, described by the so-called*rotation matrix* *′ ′ ′*

|d/d ×d/d|a|d/d||
|---|---|---|---|
||||d/d − 1|
||||q|
|∞ 2 1 /2|/2|q||

Rot(*a*)*∈S* as*Φ*(*ab*) =Rot *·Φ*(*b*)*∈S*. The rotation matrixRot(*a*) is defined as follows

*′* Rot(*a*) := *Φ*(*a*)*Φ*(*aX*)*... Φ*(*aX*)*.*

We recall the result of [39] which says that short elements in*R* are invertible.

Lemma 1(Cor.1.2, [39]).*Letq≡*5 mod 8*be a prime. Then, anyf∈Rqwhich satisfies either*0*≤* *∥f∥ < q¹ or*0*<∥f∥< q¹ is invertible inR.*

A.1 Rejection Sampling and the Gaussian Distribution In lattice-based zero-knowledge proofs, the prover may want to producezwhose distribution is independent of a witness vectorv, so the verifier would not obtain any secret information. The achievement of this independence is done by*rejection sampling*[35] to ensure a target distribution. We use Gaussian distributions to sample the*mask*yin our proofs of knowledge. Definition 6.*The discrete Gaussian distribution overR*
*n* *centered at*v*∈ R* *n* *, with standard deviation* <u>−∥x−v∥</u>2

||n,σ|exp (|)|
|---|---|---|---|
|n n,σ σ|v|P exp (|)|

<u>2σ2</u> *n* *σ >*0*is defined byD* (*x*) :=<u>−∥x′ ∥2</u>*.When it is centered around*0*∈ R,we simply write* x *′ ∈Rn* 2*σ*2 *D* =*D₀.*

We also use the following Gaussian tail bound, following from [6, Lem 1.5(i)] and adapted in [5, Lem 2.5]. *√* *−nd/*2*·*log (*e/*2) *−nd/*8 Lemma 2.Prz*←D* *σ* *n* [*∥*z*∥< σ* 2*nd*]*>*1*−*2 *>*1*−*2*.*

Lemma 3( [35, 38]).*LetV⊆ R* *n* *be a set of vectors with norm at mostBandρ*: *V→*[0*,*1]*be a* *probability distribution. Letσ*=*γBa standard deviation, for some constantγ >*0*.*

*1LetM* := exp (14*/γ*+ 1*/*(2*γ²*))*.Sample*v*←ρand*y*←Dσ* *n* *and set*z=y+v*.Runb←Rej₁*(z*,*v*,σ*) *from Fig. 2. Then the probability thatb*= 0*is at least*(1*−*2 *−*128 )*/Mand the distribution of*(v*,*z)*,* *conditioned onb*= 0*, is within statistical distance of*2 *−*128 *ofρ×Dσ* *n* *.* *2LetM* := exp (1*/*(2*γ²*))*.Sample*v*←ρand*y*←Dσ* *n* *and set*z=y+v*.Runb←Rej₂*(z*,*v*,σ*)*from*

*Fig. 2. Then the probability thatb*= 0*is at least*1*/*(2*M*)*and the distribution of*(v*,*z)*, conditioned on*

*b*= 0*, is identical to the one obtained as follows: sample*s*←ρ,*z*←Dσ* *n* *, conditioned on⟨*z*,*v*⟩ ≥*0 *output*(v*,*z)*with probability*1*/M.*

<u>Rej₂(z,v,σ)</u>

|Rej₁(z,v,σ)|05if⟨z,v⟩<0|
|---|---|
|00u←[0,1)|06return 1 (i.e.reject)|
|01ifu >|) 07u←[0,1)|
|02return 1 (i.e.reject)|08ifu >|
|03else|09return 1 (i.e.reject)|
|04return 0 (i.e.accept)|10else|

|1|−2⟨z,v⟩+∥v∥|||
|---|---|---|---|
|M|2σ|1 M|−2⟨z,v⟩+∥v∥ 2σ|

*·*exp (2 2 *·*exp (2)

11return 0 (i.e.*accept*)

Fig. 2.Two rejection sampling algorithms: [35] (left) and [38] (right).

A.2 The Johnson-Lindenstrauss Lemmas These results use Gaussian tail bounds derived under the heuristic of [30] of the projection matrices with entries from the binomial distributionBin*k*, having instead normally distributed entries. Theorem 3. q
*Under the heuristic substitution ofBinkwith the normal distribution of standard deviation* <u>k</u> *,from [30, Cor 3.2], for anyk∈{*1*,*2*},we have for*w*∈*Z *n* *,* 7 2

<u>1</u> Pr *n* [*|⟨*r*,*w*⟩|>*9*.*75*∥*w*∥*]*<* 141 *,* r*←Bin*12 <u>1</u> Pr *n* [*|⟨*r*,*w*⟩|≤*0*.*74*∥*w*∥*]*< √.* r*←Bin*1 2

We recall the Johnson-Lindenstrauss lemma from [13] that relates the infinity norm of the projection with the*ℓ₂* norm of the witness.

||n|2|||
|---|---|---|---|---|
|Π←Bin||∞|128||
||n|2|∞||
|Π←Bin||∞|128||
|||||×n|
|||||2|
||256||||

Theorem 4.*For every vector*w*∈*[*±q/*2] *with∥*w*∥ ≥b,for some boundb≤q/*91*,we have*

<u>1</u> Pr₂₅₆ *×n* [*∥*Πw*modq∥ ≤*0*.*74*b*]*<.* 1 2

Here we introduce a new Johnson-Lindenstrauss lemma that relates the*ℓ* norm of the masked projection with the*ℓ₂* norm of the witness. It follows from [13, 36].

Theorem 5.*For every vector*w*∈*[*±q/*2] *with∥*w*∥ ≥b,for some boundb≤q/*165*,we have*

<u>1 1</u> Pr₂₅₆ *×n* [*∥*Πw+y*modq∥ ≤* 0*.*67*b*]*<.* 1 2 2

The theorem follows the one of [36, Lem 2.9.], which requires an auxiliary lemma involving the infinity norm of the projectionΠw, forΠ*←*Bin₂*.*The latter lemma follows [13, Thm.6], adapted toBin²⁵⁶ distribution, aiming for a smaller failure probability, 1*/*2*.*Thanks to the heuristic of [30, Cor. 3.2], we can assume that the entries ofΠfollow the standard normal distribution, which might lead to a slightly different application of the Berry-Esseen theorem in the proof of [13, Thm.6].

A.3 Particular Constraints Here we recall how binary proofs or exact norm proofs can be given, using lattice techniques from previous work [11, 36]. 7 The bounds were computed via a python command, see https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.chi2.html

*Binary proof.*For proving a vector x˜*∈ R* *m* *q*is made only of ring elements with binary coefficients, or equivalently, the coefficients of any entry of this vector are binary vectors, we make use of the observation [36, Lem 5.2] saying that an integer vectorx*∈*Z *md* is binary if and only if*⟨*x*,*x*−*1*md⟩*= 0 over the integers, where1*n*is the integer vector with all entries equal to 1. This translates into showing that the corresponding polynomial vector x˜over*R*satisfies

### ct(⟨σ−1(x˜−1), x˜⟩) = 0.(20)

For proving this, we need to add an auxiliary witness vector,*σ−*1(x˜). However, one could prove Equation (20) only mod *√*

<u>q</u>. In order to prove this holds overZ*,*we would need to also prove that the vector x˜is small, i.e.
*∥*x˜*∥≤ md*, by projecting it as before, and thus prove its norm, up to some slack factor*α*. As the left hand side of Equation (20) is*|⟨*x*,*x*−*1*md⟩|≤*2*∥*x*∥* 2, for anyx*∈*Z *md* integer vector, by letting 2*·α² ·md < q*, we guarantee that Equation (20) holds over the integers. For a binary vector polynomial inputv*∈R* *n* ,bin-checkworks as follows:

–append*σ−*1(v) tov, –include constraints on correctness of*σ−*1(v), –includect(*⟨*v*,σ−*1(v*−*1)*⟩*) = 0, p –include approximate norm proof for*∥*v*∥≤ d·*dim(v).

*Automorphism proof.*As particular constraints, such as binary or exact norm proofs, involve adding new witness vectors when applying the automorphism*σ−*1, one needs to prove their correctness. More precisely, as in [1, 11], we have to prove that the*k*-th coefficient of some polynomial*a∈R*matches the (*d−k*)-th coefficient of ˜*a* :=*σ−*1(*a*), up to a sign, as in

ct(*X* *d−k* *a−X* *k* ˜*a*) = 0*.*(21)

## B Deferred proofs

B.1 On the Outer Commitment Layer Here we show that applying the outer commitment layer preserves the knowledge soundness and zero- knowledge. For achieving zero-knowledge, one needs to use the hiding version of the outer commitment. Lemma 4.*LetΠbe a knowledge sound proof system and an extractorEthat extracts with knowledge error* *κa valid witness forΠ. LetΠ*
*′* *be a derived protocol fromΠby applying the outer commitment layer with* *hiding, i.e. any prover’s message is postponed to the last message and sent instead in a committed form.* *Then there exists an extractorE* *′* *that either produces a valid witness forΠ* *′* *or breaks the binding of the* *outer commitment layer.*

*Proof.*This extractor*E* *′* will use as subroutine an extractor*E*for the protocol*Π.*Indeed, let*E* *′* run the prover of*Π* *′* and look at his last message. By construction, the last message contains the openings of the commitments the prover sent earlier in*Π* *′*. The binding property of the outer commitment layer ensures that these openings are exactly the prover’s messages in*Π.*Then*E*can reconstruct the transcript of*Π.*He uses*E*to extract a valid witness for*Π,*which, by construction, turns out to be a valid witness for*Π* *′* *.*

Lemma 5.*LetΠbe a zero-knowledge proof system andΠ* *′* *be a derived protocol fromΠby applying the* *outer commitment layer with hiding, i.e. any prover’s message is postponed to the last message and sent* *instead in a committed form. ThenΠ* *′* *also satisfies the zero-knowledge property.*

*Proof.*We extend in a straightforward way the simulator of*Π*to the additional commitment layer involved in*Π* *′*. Namely, we construct a simulator*S* *′* for the protocol*Π* *′* by using as subroutine a simulator*S*for the protocol*Π.*As*S*simulates a valid transcript for*Π*, indistinguishable from the real distribution, thanks to zero-knowledge,*S* *′* simply takes all the messages from this transcript and creates commitments of them, in order to create a valid transcript for the protocol*Π* *′* *.*By the hiding of the commitment layer, these commitments look indistinguishable from the ones of the messages from the real transcript of*Π*.

B.2 Security ofLNP-Lite Completeness error.In the first projection step, the threshold*N*is set (Section D) such that each of the four masked projections has less than*N*carries with probability*p₁* := 0*.*99. Note that the projec- tions are not independent since they are derived from the same projection matrix. Then, by union bound, we can upper bound the probability that one of them is rejected by 4(1*−p₁*), which leads to the prob- ability that they all are accepted to be at least 1*−*4(1*−p₁*)*.*In the second projection step, by rejection sampling,zfollows a distribution
*√* close *√* <u>to</u>*Dσ*and accepted with probability*p₂* := exp (14*/γ*+ 1*/*(2*γ²*)) (Lemma *√* <u>3 (1)),</u> where*σ*=*γ* 337 4*N*. By the Gaussian tail bound (Lemma 2), the verifier checks *∥*z*∥≤σ* 2*·*256 with probability at least 1*−*2 *−*128. In the last step, the prover obtains by rejection sampling z*i*following a close distribution to*Dσi*and passes both the rejection sampling algorithms with probability 1*/*exp (14*/γ₁* + 1*/*(2*γ₁₂*))*·*1*/*(2 exp (1*/*(2*γ₂₂*))), where*σ₁* =*γ₂ ·T·∥*(˜s*,* v˜)*∥*and*σ₂* =*γ₂ ·T·∥*(r*s,*r*v*)*∥*. Again, by tail bound (Lemma 2), for*ni,ns*+*nv≥*128*·*8*/d*= 4, the verifier checks Equations (13) to (15) with probability at least 1*−*2 *−*128 each. Then the honest prover convinces the verifier with probability

*≃*(1*−*4(1*−p₁*))*p₂ ·*1*/*(2 exp (14*/γ₁* + 1*/*(2*γ₁₂*) + 1*/*(2*γ₂₂*)))*.*

Zero-knowledgeWe follow the lines of [36, Thm 4.2]. We recall the prover messages inLNP-Lite

(0)
(Section 3.3):t*s*,t*v*,*{vi}i*,z,*{hi}i*,w*s*,w*v*,*u*,*v*,z₁,z₂*.*We show that we can simulate a non-aborting transcript between honest prover and verifier through a series of simulators.

–The first simulator*S₀* knows the witness vector ˜s= (s*i*)*i∈*[6]and honestly computes its commitment t *s*under randomnessr*s*(sampled from the uniform binary distribution) and the masked projections ofs*i, i∈*[4], to derive the high-order values and the low-order bits. Then he is able to compute the second commitmentt*v*to the high-order values (and their*σ−*1’s), v˜, under randomnessr*v*(sampled from the uniform binary distribution). The simulator samplesz₁ *←Dσ*1*,*and*hi← {x∈ Rq|*ct(*x*) = 0*}*, for*i∈*[*λ*]. Given verifier challenges, the simulator can also compute*u* *′* *∈ Rq*, (one of the garbage terms needed for the final quadratic check, see Equation (5)) and its commitment*u* :=*⟨φrand,*r*s⟩*+*u* *′*. *s*

|Given a challengec←C, he also samplesz₂ := (z|||||,z )←D|such that⟨z₂,c(r||,r )⟩≥0 and sets|
|---|---|---|---|---|---|---|---|---|
||||||s 2 v 2|σ||s v|
|s|s 1 ′1 s 2 s|s v|k q v s|v 1|′2 v 2 v ′|k q q k k +1 q|+1 k q||
||||v||k q||||

2 *v* 2 *σ*2 *s v* w :=A₁z +A z *−c*t *∈Rs*,w :=A₂z +A z *−c*t *∈Rv*. Then, by Lemma 3, the transcript output of*S₀* is statistically close to the one of the non-aborting protocol. –The second simulator*S₁* still knows ˜s(and thus v˜) and runs identically to*S₀*, but it computes the commitments (t*,u,*t) in the following way: it samples (u₁*,*u₂)*←Rs×Rv*and sets

t A₁˜s*s* :=u₁ + *∈R* (22) *u u*

t :=u₂ +A₂v˜*∈R* *v*

*.*(23)
Note that in the real transcript and in the output of*S₀*

||t|A||A₁˜s||
|---|---|---|---|---|---|
||s|′1 T|s|′|k +1 q|
|s v|′2 v v s|rand v|k q|||

*s* = r + *∈R* *u φ u*

t =A r +A₂v˜*∈R* *v* *,*

and in both cases, the sign of*⟨*z₂*,c*(r*,*r)*⟩*is known. This looks like the Extended M-LWE problem but with two secrets,r*,*r*,*where the sign of the inner product of their (scaled) concantenation withz₂ is leaked. We claim that if a PPT adversary*A*can distinguish between the outputs of*S₁* and*S₀* with probability*ϵ*, then there is a PPT adversary*B*that can break the two corresponding Extended M-LWE problems with probability at least*ϵ/*4. Therefore, if the two-Extended M-LWE problems are hard, then the outputs of the simulators*S₀* and*S₁* should be indistinguishable. Indeed, assume that*B*is given (C₁*,*u₁*,c,*z *s* 2 *,b₁*) and (C₂*,*u₂*,c,*z *v* 2 *,b₂*)

A *′* 1 *′* C₁ :=*T,*C₂ =A₂*.* *φrand*

Then*B*computes (t*s,u,*t*v*) as in Eqs. (22) and (23) and simulates the rest of the transcript identically to that above and sends it to*A.*Let us assume that*b₁* =*b₂* = 1*,*so then*⟨*z *s* 2 *,c*r*s⟩*,*⟨*z *v* 2 *,c*r*v⟩≥*0*.*Summing *s v*A *′* 1 *′*

|s v|s v|T 1|s|′|v|
|---|---|---|---|---|---|
|||rand||||

up, we get*⟨*z₂*,c*(r*s,*r*v*)*⟩≥*0, forz₂ = (z₂*,*s₂). Ifu₁ =*T*r*s*andu₂ =A₂r*v,*then the output of*B* *φ* is exactly the one of*S₀.*Ifu₁ andu₂ are both uniform, then, the output of*B*is exactly the one of*S₁.* Then, conditioned on*b₁* =*b₂* = 1*,*the adversary*B*solves the Extended-MLWE with probability*ϵ*. But since*b₁,b₂* are both 1 with probability at least 1*/*4*,*the claim follows. –The third simulator*S₂* does not know any information about ˜sand runs identically to*S₁,*except that it sets (t*s,u,*t*v*) :=u*←Rq* *k* *s* +*kv*+1. Then the distribution of the output of*S₂* is exactly the same as of *S₁.*We get the conclusion by using hybrid argument.

SoundnessHere we present the proof of Theorem 2.

*Proof.*As the outer commitment preserves knowledge soundness (Lemma 4), it is enough to focus on proving knowledge soundness of our zero-knowledge layer without outer commitments. Recall the output vectors of LaBRADOS, (s₁*,...,*s₄), which satisfy the checks ofLaBRADOSand the norm bounds*βi*,*i∈*[4]. Let us collect the full-constraints of theLaBRADOSchecks in*F*and the constant-term ones in*F* *′*. Note thatbin-checkfor provings₄ being binary considerss₅ =*σ−*1(s₄) and the corresponding constant-term constraints, already collected in*F* *′* *.*Keep in mind that an approximate proof fors₅ is not needed. All of these output vectors, together with the additional vectors₆ made by the masks, form the witness ˜sof our zero-knowledge layer and are all committed by hiding the Ajtai commitment, with the randomness vectorr*s*. For simplicity, we extend the domains of the constraints from*F*and*F* *′* to be satisfied by ˜s, althoughs₆ is not involved. Formally, our zero-knowledge layer gives a proof-of-knowledge for the following relation  *′*    t *s*=A₁˜s+A₁r*s*  *′* ((t*s,F,F ,*(*βi*) )*i, f*(˜s) = 0*,∀f∈F* *R*LNP=*′ ′ ′.*   (˜s*,*r*s*) ct(*f* (˜s)) = 0*,∀f ∈F*     *∥*s₁*∥≤*¯*γβ₁,...,∥*s₄*∥≤*¯*γβ₄*

for ¯*γ* := <u>2</u> 0 <u>·9</u>

*.*74
<u>.75</u> *.*Recall that in the first projection step, each of the vectorss*i,*for*i∈*[4] receives a masked
projection, using random projection matricesΠ*i*, all coming from the sameΠof the verifier, and the uniform masksu*i*, part of the vectors₆. Decomposing these projections, we get the high-order values and low-order bits: *k* *i*(0) Πis*i*+u*i*= 2 (w*i−*t*i*) +v*i,∀i∈*[4]*,*(24)

(0)
where*ki*=*⌈*log (9*.*75*βi*)*⌉*. All low-order bits,v*i*, could be sent in the clear, as they are uniform. All high-order values, represented by the binary vectorsw*i*andt*i*, are collected in the vector v˜1*∈R⁸.*These *√* masked projections are accepted if they contain less than*N*nonzero high-order values, i.e.*∥*(w*i,*t*i*)*∥≤ N,* each with probability*p₁.*Then, (with probability 1 *√* *−*4(1*−p₁*)), we can construct a new witness vector v˜1, for which we prove binary and*∥*v˜1*∥≤* 4*N*. For this, we also consider v˜2=*σ−*1(v˜1) and, thus a hiding Ajtai commitmentt*v*to v˜= (v˜1*,* v˜2) is provided, under randomnessr*v*. The projections from Equation (24) get translated into new constant-term constraints to be proven to be satisfied by ˜sand v˜, and we collect them all into*F* *′′* *.*Note that starting from the second step of projection, the zero-knowledge layer follows exactly [36, Sec. 5], so we can treat the following steps together as a subprotocol. Therefore, formally written, the first projection step could be viewed as reducing*R*LNPto the following relation  *′*    t *s*=A₁˜s+A₁r*s*     t =A v˜+A*′*r    *v* 2 2 *v*    (0)   ((t*s,*t*v,*(v*i*)*i, f*(˜s) = 0*,∀f∈F*  *R*LNP *′* = *F,F* *′* *,*(*βi*)*i,* ct(*f* *′* (˜s)) = 0*,∀f* *′* *∈F* *′* *.*   *′′ ′′ ′′*   *N,*Π)*,* ct(*f* (˜s*,* v˜)) = 0*,∀f ∈F*        (˜s*,* v˜*,*r*s,*r*v*)) bin-check *√* (<u>v˜)</u>    *′*  *∥*v˜ *∥≤γ* 4*N*

*′* p *√* for*γ* := 2 2*·*256*/*26*γ* 337*,*for a repetition rate*γ.* Our extractor*E*for the zero-knowledge protocol uses as a subroutine the extractor*E* *′* of the subprotocol. Therefore, we can rely on the knowledge soundness of the latter to extract a witness ¯s*,* v¯*,*¯r*s,*¯r*v*that satisfies

t *s*=A₁¯s+A *′* 1 ¯r *s* t *v*=A₂v¯+A *′* 2 ¯r *v* *f*(¯s) = 0*,∀f∈F* ct(*f* *′* (¯s)) = 0*,∀f* *′* *∈F* *′*

ct(*f* *′′* (¯s*,* v¯)) = 0*,∀f* *′′* *∈F* *′′* (25) bin-check(v˜1) (26)

except with probability*κ* *′* := 1*/*2 128 + (1*/q*) *d/*2 + (1*/q*) *λ* + 2*/|C|*(see [36, Prop.5.1]). Moreover, if the value of any of ¯s*,* v¯*,*¯r*s,*¯r*v*was dependent on the challengeΠ, then we would be able to use the knowledge extractor p <u>E</u> *′*

to break the binding of the commitmentst p *s*<u>andtv</u>, i.e. the M-SIS problems for*ℓ₂* norm bound 8*T Bs* 2+*B* *r* 2

and rank*ks*and for*ℓ₂* norm bound 8*T Bv*2+*Br*2and rank*kv.*Therefore, ¯s*,* v¯*,*¯r*s,*¯r*v*are unique and, in particular, do not depend onΠ. Thus, it suffices to compute the probability, over the randomness ofΠthat the extracted vectors do not satisfy the relation*R*LNP*.*As the extracted vectors already satisfy theLaBRADOS checks from*F*and*F* *′* *,*it suffices to compute the probability that one of the vectors ¯s*i*, for some*i∈*[4], does not satisfy the norm bound, i.e.*∥*¯s*i∥>*¯*γβi.* First, we argue that the extractor*E* *′* of the subprotocol extracts the vector p *√ √* p v¯1*∈R⁸* that is indeed binary. Note that this vector satisfies*∥*v¯1*∥≤*2 2*·*256*/*26*γ* 337 p <u>4N</u>= 2*σ* 512*/*26*.*( [36, Prop 5.1.]). For this approximate norm bound, it was used*q≥*41*·*2048*·*2*σ* 512*/*26. As this vector v¯1satisfiesbin-check, i.e. v¯2=*σ−*1(v¯1) and*⟨*v¯1*,*v¯2*⟩−⟨*v¯1*,σ−*1(1)*⟩*= 0 mod p <u>q,</u>we can upper-bound (the absolute value of) the left hand side of the latter equation, 2*∥*v¯1*∥* 2 *≤*2*·*(2*σ* 512*/*26) 2 *≤q,*so we are guaranteed that this equation actually holds overZ*.*This proves that v¯1*,*and, in particular, the vectors w¯*i,*¯t*i*v¯1is made of, are indeed binary. Second, we argue that the extracted vectors ¯s*i*satisfy*∥*Π*i*¯s*i∥∞≤*2 *k* *i* +1. As the vectors extracted from *E* *′* satisfy Equation (25), they also satisfy Equation (24) written as follows

*k* *i*¯t(0) Π*i*¯s*i*= 2 (w¯*i−i*) +v*i−* u¯*i*mod*q.*

(0) *ki −*1 *ki −*1 256 *ki −*1 *ki −*1 256
Recall that the vectorsv*i∈*[*−*2*,*2 *−*1] are public and the extractor*E*finds u¯*i∈*[*−*2*,*2] from the length of its bit-decomposition. Moreover, since w¯*i,*¯t*i*are binary,*∥*w¯*i−* ¯t*i∥∞≤*1. Therefore, by the triangle inequality, the infinity norm of the right hand side could be at most 2 *k* *i*+ 2*ki −*1+ 2*ki −*1= 2*ki*+1*.* Moreover,*q*is set so big that no wraparound mod*q*is happening on this side. (Imagine*q*on 38 bits and LaBRADOS’s output norm bound*βi*on 13-15 bits, so then 2 *k* *i≃*9*.*75*β* *i*is on, say, 17-19 bits.) Therefore, our extracted vectors ¯s*i*satisfy*∥*Π*i*¯s*i*mod*q∥∞≤*2 *k* *i* +1 *,*for any*i∈*[4]*.*By Theorem 4, if it happens that some of the extracted vectors ¯s*i*are too long, i.e. they do not satisfy the norm bound*∥*¯s*i∥≤* <u>2</u> *k* <u>i</u> +1 *≃* <u>2·9.75</u> *β*, then*∥*Π ¯s mod*q∥ ≤*2 *k* *i* +1 holds only with probability 1*/*2 128, because of Theorem 4

0*.*74 0*.*74 *i*
*k* +1 *i i ∞* (here we use*q >*91*·*2*i/*0*.*74 for any*i∈*[4]). By union bound, the probability that at least one of the four norm checks fails is at most 4*/*2 128 *.* Therefore, we obtain the knowledge error of the zero-knowledge layer as*κ* :=*κ* *′* + 4*/*2 128 *.*Thus, the extracted vectors ¯s*i*satisfy*∥*¯s*i∥≤* <u>2</u> 0 <u>·9</u>

*.*74
<u>.75</u> *βi*, and theLaBRADOSchecks, collected in*F,F*
*′*, unless with small probability. What is left to check is ¯s₄ being binary: note that it already satisfies thebin-checkfunction, 2 <u>2·9.75</u> 2 so then, as long as 2*∥*s¯4*∥ ≤*2*·d·n₄ ·*

0*.*74 *≤q,*the binary equation holds overZ*,*which leads to the
conclusion.

## C The Fiat-Shamir Transformation

*Public-coin interactive*proofs (those where all the verifier’s messages are randomly sampled values) can be turned*non-interactive*using the Fiat-Shamir transformation [27]. The security of the composition ofLNP

(with outer commitments), as the starting protocol, withLaBRADORwas already studied in [44]. In our case, we have iterations ofLaBRADOS(which isLaBRADORwith outer commitments), before going toLNP-Lite, a version ofLNP, which is further fed into iterations ofLaBRADOSandLaBRADOR. Thus, the security of our composition should follow almost the same lines as the security analyzed in [44], with the differences we detail below. Completeness follows directly from the construction of the Fiat-Shamir transformation, whereas non- interactive zero-knowledge is derived by the fact that the composition itself is honest-verifier zero-knowledge [35]. Thus, we focus only on the aspect of knowledge soundness, looking at each kind of protocol,LaBRADOS*,* LNP-LiteandLaBRADOR*.* [1] proved the knowledge soundness ofLaBRADORin the random oracle model (ROM) [7], using the *predicate special soundness*framework. This framework could be viewed as a natural extension of the special soundness that comes with a collection of*predicates*, i.e. properties satisfied (with an overwhelming proba- bility) by the extracted openings and the challenges at each prover-verifier interaction. As the property of *predicate special soundness*is preserved when applying outer commitments on a proof system*Π*(as noted also by [44, Sec.B.6.1], due to the binding of the outer commitments, they never open to distinct values, a similar property to Lemma 4), then, due to [1, Thm 5.2.], we can heuristically rely on the soundness of LaBRADORandLaBRADOScompiled via Fiat-Shamir. [1] also showed that predicate special soundness protocols are composed nicely and thus their composition can be soundly compiled via Fiat-Shamir (see [1, Thm 5.1]). Therefore, it suffices to analyze the soundness of our zero-knowledge layer in the discussed framework. The knowledge soundness ofLNPin a non-interactive version was analyzed in [36, 44], where the latter explicitly used the*predicate*special-soundness machinery. Using our zero-knowledge protocolLNP-Lite(without outer commitments), we could derive its soundness proof as [44] cast in the*predicate*special-soundness framework. We recall that this protocol has, compared toLNP, an additional prover-verifier interaction, corresponding to the first projection step. In this step, note that the upper bound on the fraction of projection matrices (i.e.*failure density*), used in this step is at most 1*/*2 128 (Theorem 4), since the projections of the invalid (i.e. of too big norm) extracted witness vectors to have a certain number of bits is at most 1*/*2 128 *.*Thus, in the analysis of [44, Lem.B.10], we inquire about an extra*failure density*value of 1*/*2 128. As inLaBRADOS, the predicate special soundness ofLNP-Liteeasily extends when considering the outer commitments. Therefore, the whole composition ofLNP-LitewithLaBRADOSandLaBRADORhas predicate special soundness, and thus shall be considered (heuristically) secure after applying the Fiat–Shamir transformation. Following the observations from [44, Thm 5.1], the knowledge error*κ*of our construction in the ROM shall be adjusted for a multiplicative loss arising from the number of queries the adversary is allowed to make to the random oracle.

## D Deferred Parameters

D.1 Parameters forLaBRADOS

|||9|q|
|---|---|---|---|
|||0..75 74 i|n 91|
|||bin||
|9 0..75 74|bin Lab-new|||
 The Modulus*q*.From Theorem 1, we need *β ≤.*For provingbin-checkoverZ, (Section A.3), as all witness vectors ofLaBRADOS*,*includingx *∈R*bin, benefit from approximate range proofs with slack *c* Lab-new=*,*we set 2*dn ·c² ≤q.* The rest of the parameters involved inLaBRADOSandLaBRADORare chosen following the same rationale of [11, 13].
D.2 Parameters forLNP-Lite We set the parameters forLNP-Litedescribed in Section 3.3. We use the challenge space*C*from Section 2.1 of ring elements of operator norm*T*. The Dimension and Bound of the Additional Witness s₆.Recall*s₆ ∈R*
*n* 6is made of the binary decompositions of the masksu*,*y*,*g. Asy*←Dσ i*has coefficients

||, with high probability∥y∥|≤14σ. Eachu|
|---|---|---|
|||∞|
|k −1 k|log 128 q|i|

uniform in [*−*2*i,*2*i−*1]*,*so on*ki*bits. Each of the*⌈ ⌉*polynomials*g* has uniform coefficients mod*q*,

P except the constant coefficient which is 0, so on*⌈*log*q⌉*bits each. Then*n₆* :=*i∈*[4]*ki*+ (*⌈*log 14*σ⌉*+ 1) + *⌈* log <u>128</u> *q* *⌉·⌈*log*q⌉*and*∥*s₆*∥≤β₆* for

v u X u <u>128</u> *β₆* := t256( *ki*) + 256(*⌈*log 14*σ⌉*+ 1) + 255*·⌈ ⌉·⌈*log*q⌉.* log*q* *i∈*[4]

(1) 2
The Number of Carries*N*.We set the number of carries such that the probability that*∥*v*i∥ ≤N*is

(1) 256
:= Pr[

(1)
around 0.99, wherev*i∈{−*1*,*0*,*1*}* is the vector of high-order values. If we denote by*p |*v*i*[*j*]*|*= 1]

(1) 2P(1) 2
the probability of a carry, for any entry of index*j∈*[256]*,*then we can model*∥*v*i∥* =*j∈*[256](v*i*[*j*]) as*X∼*Bin(256*,p*)*,*so we can find*N*such that its cumulative distribution function, Pr[*X≤N*] = P*N* 256 *k* 256*−k* *k*=0 *kp* (1*−p*) is close to 0.99. Thus, it suffices to compute the probability*p.*The masked pro- jection of some witness vectorsat any of the 256 indices looks like*⟨π,*s*⟩*+*u*= 2 *k* *v*

(1) +*v*
(0), for some
projection row*π*, uniform mask*u←*[*−*2 *k−*1 *,*2 *k−*1 *−*1],*v*

(1) *∈{−*1*,*0*,*1*}*and*v*
(0) *∈*[*−*2 *k−*1
*,*2 *k−*1 *−*1] and*k* depends on the norm bound ons*.*Then a carry happens if the following event*E*happens:*⟨π,*s*⟩*+*u≥*2 *k−*1

or*⟨π,*s*⟩*+*u≤−*2 *k−*1 *−*1. Then

X 2 *k* *p*= Pr[*E*] = Pr[*E|⟨π,*s*⟩*=*a*]*·*Pr[*⟨π,*s*⟩*=*a*] *π,u* *k* *u π* *a*=*−*2

X 2 <u>1 a²</u> *k* = *pa· √* exp (*−* 2 )*,* *kσ* 2*π* 2*σ* *a*=*−*2

where we denoted the first term of the product by *√* *pa*and we computed the second term under the assumption that*⟨π,*s*⟩ ∼N*(0*,σ*), for*σ* :=*∥*s*∥/* 2. 8 The sum above is truncated for*|a| ≤*2 *k*, as, for the contrary, Pr*π*[*⟨π,*s*⟩*=*a*] = 0, by the choice of*k*. We claim that, for*a*= 0,*pa*= 0 and else, equals <u>|</u> 2 <u>a</u> *k* <u>|</u> *.*Then

X 2 <u>a 1 a²</u> *k* *p*=2 *k* *· √* exp (*−* 2 ) *a*=1 2 *σ* 2*π* 2*σ* Z*∞* 2 1 <u>a</u> *≤ √* exp (*−* 2 )*·ada* 2 *k−*1*σ* 2*π* 02*σ* Z*−∞* 12 *≤ √* exp (*x*)*·*(*−σ*)*dx* 2 *k−*1*σ* 2*π* 0 2 *√* *σ σ* 2 1 *≤ √* = *k* *√ ≈ √* 2 *k−*1*σ* 2*π* 2 *π* 9*.*75 *π*

<u>−x² −a²</u> For the first inequality, we use that exp ( 2*σ*2 ) is a decreasing positive function, and thus exp ( 2*σ*2 )*≤* R*a* <u>−x</u> 2 *a−*1 exp ( 2*σ*2 )*dx*. About the claim on*pa*, note that

*pa*= Pr[*a*+*u≥*2 *k−*1 or*a*+*u≤−*2 *k−*1 *−*1*|⟨π,*s*⟩*=*a*]*.* *u*

Keep in mind that*u*takes uniform values over [*−*2 *k−*1 *,*2 *k−*1 *−*1]. Then, if*a*= 0*,*for sure*pa*= 0. If 0*< a≤*2 *k*, *pa*= Pr*u*[*u≥*2 *k−*1 *−a*] = 2 <u>a</u> *k,*whereas, if*−*2 *k* *≤a <*0,*pa*= Pr*u*[*u≤−*2 *k−*1 *−a−*1] = <u>|</u> 2 <u>a</u> *k* <u>|</u> *.* <u>1</u> P*N* 256 *k* 256*−k* Setting*p*=

9*.*75 *√* *π* *,*we get for*N*= 32 the value*k*=0
*k* *p* (1*−p*) to be close to 0.99.

8 It relies on the heuristic assumption of [30] that the entries of any projection row, fromBin₁, follow a normal *√* distribution of standard deviation 1*/* 2*.*

The Standard Deviations*σ,σ₁,σ₂*.In general, the standard deviation of the Gaussian distribution, used in rejection sampling (Lemma 3) is set as*γ·α,*where*α*is an upper bound of*∥*x*∥*, for a vectorxover *R*we want to mask, and a repetition constant*γ*. Recall that by definition of the challenge space*C*from Section 2.1,*∥c·*x*∥≤Tα,*for any challenge*c∈C.*

–In the first rejection sampling application, we want to mask *√* Πv ¯ 1 *,*<u>where</u> *√* <u>v₁</u> is the vector of high-order values. As*∥*v₁*∥≤* *√* 4<u>·N,</u>we have with high probability*∥*Πv ¯1*∥≤* 337*·*4*·N*. (Theorem 3) Therefore, we can set*σ* :=*γ·* 337*·*4*·N.*

||||˜),andc(r c(˜sP, v||,r ),for a given challenge|
|---|---|---|---|---|---|
|2|i 2|1 2|2 2 i∈[6]|i2||
|i∈[6] i2|s|v 2|s v s|v||

–In the last rejection sampling application, we want to mask P*s v* *c∈ C*. Note that<u>∥(˜s, v˜)∥</u> 2 <u>=</u>*i∈*[6]*∥*s*i∥* 2 +*∥*v˜1*∥* 2 +*∥*v˜2*∥* 2 *≤i∈*[6]*βi* 2 + 2*·*4*·N*. Then, we can set q P *σ₁* :=*γ₁ ·T· β* + 8*N*. Moreover,*∥*(r*,*r)*∥ ≤d·*(*n* +*n*), as these random vectors are made p of binary ring elements. Then, we can set*σ₂* :=*γ₂ ·T·* 256*·*(*n* +*n*).

The parameters*γ₁,γ₂* are repetition rate-related constants coming from the rejection sampling algorithms. The Modulus*q*for the NextLaBRADOSIteration.We want theLaBRADOSmodulus to coincide with the one ofLNP-Lite. To prove correctness of the binary constraint on the vector *√* xbin, we prove an

|d·n, with the slack factorc|||=|.To make sure this|
|---|---|---|---|---|
|bin|||9 0..75 74||
|||bin 2|||
|bin|Lab-new||||

approximate norm bound of it,*∥*xbin*∥≤*bin Lab-new <u>9</u> 0 <u>.</u> *.* <u>75</u> 74 constraint does not wraparound mod*q,*it suffices to set 2*∥*x *∥ ≤q.*This leads to setting

### 2·d·n ·c² ≤q.

TheLNP-LiteModulus*q*.One can set the modulus*q*as indicated by Theorem 2 and as above.

## E Security of the Primitives

E.1 Collision Resistant Hash Function The hash function in Section 4.2 is collision resistant, assuming the intractability of the M-SIS problem with parameters*M*= 1,*N*= 16,*q*= 256,*β∞*= 1 over*R*of degree*d*= 512. *Proof.*Let*A*CR-hashbe a probabilistic polynomial-time adversary that finds collisions with some advantage *ϵ*. One constructs a probabilistic polynomial-time adversary*A*M-SISthat solves M-SIS instances with the same advantage as follows: –*A*M-SIScalls*A*CR-hashto obtain a pairx*̸*=x
*′* *∈R* *∗* 2, and aborts if it is not a collision. –If the inputsx*,*x *′* have different dimensions, the last block of the padded input is different,x*k−*1*̸*= x *′k* *′* *−*1. Then, there is a collision in the last compression, i.e. (y*k−*2*,*x*k−*1)*̸*= (y*k* *′* *′* *−*2*,*x *′k* *′* *−*1)*∈R¹⁶*2with A(y*k−*2*,*x*k−*1) =A(y*k* *′* *′* *−*2*,*x *′k* *′* *−*1).*A*M-SISreturns the difference (y*k−*2*,*x*k−*1)*−*(y*k* *′* *′* *−*2*,*x *′k* *′* *−*1), which is a non-zero vectorvwith coefficients in*{−*1*,*0*,*1*}*satisfyingAv= 0 mod 256. –Else, sincex*̸*=x *′*, the number of blocks of the padded inputs is equal and there existsx*i̸*=x *′i*. It follows that either (y*i−*1*,*x*i*)*̸*= (y*i′−*1*,*x *′i* ) andA(y*i−*1*,*x*i*) =A(y*i′−*1*,*x *′i* ) ory*i̸*=y*i′*, hence (y*i,*x*i*+1)*̸*= (y*i′,*x *′i* +1). In the first case,*A*M-SISreturns the difference (y*i−*1*,*x*i*)*−*(y*i′−*1*,*x *′i* ). In the second case, it proceeds until it finds an iteration in the compression function and returns the difference. *√* We estimate the concrete hardness of the SIS problem with*d*rows, 16*d*columns,*ℓ₂* norm bound*β*= 16*d* as at least 256-bits secure, by the Lattice Estimator [4], commit 6019056.

E.2 Pseudorandom Generator The function in Section 4.1 is a pseudorandom generator, assuming the hardness of some Module-LWR problem.

*Proof.*Let*A*PRGbe a probabilistic polynomial-time algorithm that distinguishes the PRG output from a uniformly random one with advantage*ϵ*PRG, i.e.

1*×*2 (6) (7) (6) (7) Pr *A*PRG(A*,*s) = 1*|*A*←R₂₅₆, s₀,s₀ ←R₂,*s= PRG(*s₀,s₀*)

*−*Pr *A*PRG(A*,*s) = 1*|*A*←R¹*256 *×*2 *,*s*←R⁴*2 *k*+2 =*ϵ*PRG*.*

One constructs a probabilistic polynomial-time algorithm*A*M-LWRthat distinguishes M-LWR samples from uniformly random ones with advantage*ϵ*MLWR=*ϵ*PRG*/k*as follows.

–Receive as input a pair (A*,t*) whereA*←R¹*256 *×*2 and*t∈R₆₄*. –Sample*i←*[*k*] and lets*i*be the decomposition of*t*,*t*=G₂s*i*.

(2) (5)
–Sample*sj,...,sj←R₂* for*j∈*[*i−*1].

(6) (7)
–Compute*⌈*A(*sj,sj*)*⌋*256*→*64=G₂s*j*+1for*j∈*[*i,k−*1]. –Return*A*PRG(A*,*s).

### Fori= 0,...,k, let thehybridHidescribe the distribution

1*×*2 (2) (5) *Hi*=*{*(A*,*s) :A*←R₂₅₆, sj,...,sj←R₂* for*j∈*[*i*]*,*

(6) (7) (6) (7) *s* *i,si←R₂,⌈*A(*sj,sj*)*⌋*256*→*64=G₂s*j*+1for*j∈*[*i,k−*1]*}.*
(6) (7)
Note that*H₀* describes the evaluation of the pseudorandom generator on a random input*s₀,s₀ ←R₂*, while*Hk*presents a random binary output. Then,*ϵ*PRGcan be written as

Pr *A*PRG(*H₀*) = 1 *−*Pr *A*PRG(*Hk*) = 1*.*

By the construction of*A*M-LWRand the union bound, we have Pr *A*M-LWR(*A,t*) = 1*|t*=*⌈A*s*⌋*256*→*64= <u>1</u> P*k* Pr *A*(*H*) = 1 and Pr *A* (*A,t*) = 1*|t←R* = <u>1</u> P*k* Pr *A*(*H*) = 1, then *k i*=1 *i−*1 M-LWR 64 *k i*=1 *i*

X *k* <u>1</u> *ϵ* M-LWR= Pr *A*PRG(*Hi−*1) = 1 *−*Pr *A*PRG(*Hi*) = 1 *k* *i*=1 <u>1 1</u> = Pr *A*PRG(*H₀*) = 1 *−*Pr *A*PRG(*Hk*) = 1 = *ϵ*PRG*.* *k k*

To estimate the concrete hardness of the Module-LWR problem with parameters*q*= 256,*p*= 64,*m* *′* = 1, *n* *′* = 2,*χ*=*U*(*R₂*), we model the LWR problem as an LWE problem, with*d*rows, 2 p <u>·dcolumns, modulus</u>*q*, secret distribution as*χ*, and error distribution as Gaussian of standard deviation ((*q/p*)2*−*1)*/*12*.*( [2,14]). According to the Lattice Estimator, [4], commit 6019056, this instance costs at least 2 300 ring operations.

E.3 Output Transformation The modulus transformation in Section 4.1 is, intuitively, an expander that converts a binary input into ring elements. For simplicity, we chose the output entropy of the PRG to be the same as the size of the ring and we perform the mapping via a matrix-vector multiplication where the matrix consists of random ring elements from the target ring. If the binary input to this multiplication is uniformly-random, then one can view the output distribution as a Ring-LWE instance. Because the entropy of the input is as large as the output, this in fact the hardest LWE instance for the ring. The security of this transformation is therefore much larger than the security of the PRG (roughly 7000 bits), and we include the formal analysis below merely for completeness. If we treat the input to this expander as random, then the output is indistinguishable from a random element, assuming the hardness of some Module-LWE problem.

*Proof.*The proof is analogous to the previous one. From the adversary*A*modthat distinguishes the output of the function from a random one with advantage*ϵ*mod, one constructs a Module-LWE adversary*A*M-LWE with advantage*ϵ*mod*/l*as follows

–sample*i←*[*l*] and set*t* =*t*,

|||i|
|---|---|---|
|j|q||
|j|j|j|
|mod|||

–sample*t ←R* for*j∈*[0*,i−*1], –compute*t* =B˜s with˜s *←R* *ℓ* 2for*j∈*[*i*+ 1*,l−*1]. –return*A* (B*,*t) witht= (*t₀,t₁,...*) *T*.

The hybrids are defined, for*i∈*[0*,l*] as

*Hi*=*{*(B*,*t) : *tj←Rq*for*j∈*[0*,i−*1]*,*˜s*j←R* *ℓ* 2 *t* *j*=B˜s*j*mod*q*for*j∈*[*i,l−*1]*}.*

The concrete hardness of the LWE problem with*d*rows,*d·⌈*log (*q*)*⌉*columns, secret and error distributions uniform binary, for the Falcon modulus*q*= 12289, is estimated to be at least 7000-bits secure by the Lattice Estimator. [4].
