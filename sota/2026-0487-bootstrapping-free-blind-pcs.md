# Linear-Time, Constant-Depth Blind Polynomial Commitments from Generalized RAA Codes,

# with an End-to-End Blind SNARK Implementation

Kexi Huang, Yanpei Guo, Wenjie Qu, and Jiaheng Zhang *⋆*

National University of Singapore {kexi.huang, jhzhang}@u.nus.edu

Abstract.We construct the first*blind polynomial commitment scheme* (PCS) whose prover performs strictly linear*O*(*N*)work at constant FHE multiplicative depth, and we compose it into an end-to-end*blind SNARK* for arbitrary R1CS. We give what is, to our knowledge, the first*end-to-* *end measured*implementation of such a blind SNARK at scale, which we provide as supplementary material. The construction rests on the*Generalized RAA code*over a fixed non- binary fieldF*q*, which encodes in linear time at constant homomorphic depth. We prove linear minimum distance in the fixed-*q*regime required by FHE plaintext moduli. The key estimate is a pairwise-product upper bound for the accumulator’s normalized input–output weight enumerator (IOWE), which drives the failure probability to*o*(1*/N*)for every fixed prime power*q≥*3(Lemma2). Plugging the code into a Ligero-style proximity test and composing it with a depth-controlled Spartan sum- check PIOP yields the blind SNARK, with*O*(*N*)ciphertext–ciphertext multiplications and*O*(*N*log*N*)total FHE operations at constant depth. In our performance evaluation, we instantiate the scheme with (*q,N,k,δ*) = (2 16 + 1*,*2 22 *,*4*,*0*.*30). Conditional on a successful code setup, the IOPP reaches128-bit per-proof soundness with query count *ℓ* *∗* = 843, and the end-to-end prover produces a proof in*∼*25s. At *N*= 2 20 our single-core prover is over400*×*faster thanPhalanx[30] and over650*×*faster thanLaminate’s [23] fastest single-instance vari- ant (Section7). Neither prior scheme has released source code, whereas our implementation enables reproducible single-thread measurement on commodity hardware.

Keywords:Blind PCS*·*Blind SNARK*·*Verifiable FHE*·*Polynomial Commitment Schemes*·*Linear-Time Encoding*·*RAA Codes

## 1 Introduction

Verifiable Computation over Encrypted Data (VCoED) [14,9] composes fully homomorphic encryption (FHE) with succinct non-interactive arguments *⋆* Corresponding author.

(SNARKs): a server homomorphically evaluates a circuit on a client’s encrypted input, and additionally produces a proof that the evaluation was performed correctly. When the proof itself is generated entirely over FHE ciphertexts, so that the client only ever sees encrypted intermediate state, the resulting object is a*blind*SNARK [23]. Two efficiency axes are fundamental for any practical blind SNARK [23]:

*•*Prover complexity: the number of FHE operations the prover performs as a function of the circuit size*n*. *•*Multiplicative depth: the depth of homomorphic multiplications in the prover’s circuit, which directly controls FHE parameter blowup (and hence ciphertext size, evaluation noise budget, and bootstrapping frequency).

In leveled BGV/BFV [10,11], a depth-*d*prover requires ciphertext modulus log*Q*=*Θ*(*d·*log*q₀*), where*q₀* is the per-level prime. Each homomorphic op- eration on a ring-F*q*[*X*]*/*(*X* *M* +1)ciphertext then costs *O*˜(*M·*log*Q*) = *O*˜(*M·d*) via NTT-based polynomial arithmetic. Hence*T*depth-*d*ciphertext operations incur total work*T· O*˜(*M·d*), giving apoly(*d*)multiplicative blowup per cipher- text operation over the plaintext operation count. 1

*The PCS-layer trilemma.*A SNARK follows the standard modular blueprint of a polynomial IOP (PIOP) composed with a polynomial commitment scheme (PCS). Recent blind and FHE-friendly constructions, including Laminate [23], Phalanx [30], and the blind-SNARK line of [15], have concentrated most of their effort on the PIOP layer. The PCS layer presents a separate obstruction. Codes with usable distance guarantees have historically required either super-linear encoding or*Ω*(log*n*)multiplicative depth, making PCS encoding the dominant homomorphic cost in NTT-based blind SNARKs. We ask whether a blind PCS can simultaneously provide*O*(*n*)prover work, *O*(1)FHE multiplicative depth, and support for the non-binary plaintext mod- ulus used by BGV/BFV. No prior construction attains all three. Once this trilemma is resolved, the bottleneck shifts: in our implementation, the Spar- tan PIOP sumcheck rather than the PCS dominates the measured prover time (Section7). Existing code families miss at least one requirement:

*•*Reed–Solomon codes(used by Phalanx [30] and the RS-based variants of FRI [7], BaseFold [29], DeepFold [18], WHIR [5]). A 1D-NTT runs in *O*(*n*log*n*)time at*O*(log*n*)FHE depth. HELIOPOLIS [4] introduced the low- depth 2D-NTT evaluation of Reed–Solomon encoding; Phalanx [30] uses this decomposition to reduce depth to*O*(1)at the cost of*O*(*n* 1+1*/k* )work. *•*Expander-based codes(Brakedown [16], Orion [27]). Linear-time encoding, but each expander cascade contributes one FHE multiplicative level, so the FHE depth is*Ω*(log*n*). The concurrent QA construction [22] uses an*O*(log*n*)- stage Walsh–Hadamard transform with the same depth cost. 1 This BGV/BFV scaling is the standard accounting (see e.g. [10, §3]). Modulus- switching keepslog*Q*at*Θ*(*d*log*q₀*)rather than letting noise grow exponentially.

Table 1.Codes for blind PCS. “Provable distance regime” is the parameter range

in which a published proof gives a non-vacuous failure bound. Here*n*is the block length, and*q,p*are base-field sizes. The Generalized RAA code is shared with Akhiani– Zhang [2]. Their bound contains an*O*(1*/*(*q−*1))term, whereas ours does not.

|Code Family|Encoding Mult. Depth|Field|Provable Distance Regime|
|---|---|---|---|
|Reed–Solomon (1D-NTT) [7]|O ( n log n ) O 1+1 /k|(log n )Non-binary|Any q|
|Reed–Solomon (2D-NTT) [4,30]|O ( n ) O|(1)Non-binary|Any q|
|Brakedown [16] O|( n ) O|(log n )Non-binary|Any q|
|EA Code [8] O|( n log n ) O|(1)Non-binary|Any q|
|QA Code [22] O|( n log n ) O|(log n )Non-binary|p≫n, vacuous at fixed p|
|Binary RAA [12] O Generalized RAA (this work)O(n)O(1)Non-binary Any fixed|( n ) O|(1)Binary|q = 2only q≥ 3|

*•*Binary RAA[12]. Linear-time encoding at depth1with a tight distance proof, but restricted toF₂, incompatible with the non-binary plaintext modu- lus used by standard FHE parameter sets (e.g. the Fermat prime*q*= 2 16 + 1).

*Where each candidate code fails.*Table1compares candidate codes along the three axes that matter for blind PCS deployment: linear-time encoding,*O*(1) multiplicative depth, and a provable distance bound at the FHE plaintext mod- ulus. Reed–Solomon, Brakedown, and EA codes encounter the encoding-time versus depth tradeoff. QA codes have no asymptotic distance guarantee at fixed *p*, while binary RAA is restricted toF₂. The Generalized RAA code was also studied by Akhiani–Zhang [2]. Their failure-probability bound retains an*O*(1*/*(*q−*1))term, which is too large at the FHE plaintext modulus (approximately10 *−*4*.*8 for*q*= 2 16 + 1). Our fixed-*q* analysis removes this term and proves the required distance property over non- binaryF*q*. We also give a setup-time parameter-selection procedure for fixed tuples (Section5) and a full end-to-end implementation (Section7).

1.1 Our Contributions We give three contributions. First, we close the fixed-*q*distance analysis for Generalized RAA codes. Second, we construct the first blind PCS with*O*(*N*) prover work at*O*(1)FHE depth. Third, we give the first end-to-end*measured* blind SNARK implementation at*N*= 2
22 by composing this PCS with a depth- controlled Spartan PIOP.

*Contribution 1: Distance analysis of Generalized RAA over fixed non-binary* *fields (Section4.3).*The Generalized RAA code already has the desired encoding complexity (linear encoding at depth1over a non-binary field), but a fixed-*q* distance theorem with explicit failure decay was missing. We supply it:

Theorem 1(Linear Minimum Distance, informal).*For any fixed prime* *powerq≥*3*there exist a repetition thresholdK∈*N + *and a relative-distance*

*constantδ >*0*such that fork > K,*

Pr [*∃x̸*= 0 : wt(RAA(*x*))*≤δN*] =*o* *N* <u>1</u> *.* $ *π* 1 *,π*2*←−SN* $ *N* r 1 *,*r2*←−*(F*q\{*0*}*)

*The thresholdKmay depend onq, whileδmay be chosen universally. The* *asymptotic decay rateo*(1*/N*)*holds for every fixed prime powerq≥*3*.*

For an accumulator, let *A*e(*w,h*)denote the probability that a uniformly ran- domized weight-*w*input produces an output of weight*h*. The proof rests on the following pairwise-product upper bound (Lemma2):

<u>w² h</u>*⌊*(*w−*1)*/*2*⌋* *A* e(*w,h*)*≤ · ·*6*w.* *N N−w*

The inequality follows from direct factorial bounds on the IOWE summands. Unlike prior analyses, it does not partition those summands according to their nonzero-symbol factor. It therefore contributes no additive*O*(1*/*(*q−*1))term to the final failure bound. In contrast, the bound of [2] contains such a term, which does not vanish as*N→∞*. Our bound tends to zero for every fixed*q≥*3.

*Contribution 2: First blind PCS withO*(*N*)*work atO*(1)*FHE depth (Section6).* Plugging the Generalized RAA code into a Ligero-style proximity-test frame- work [3] yields a blind PCS with*O*(*N*)FHE operations at constant depth. The protocol uses two public linear-combination queries, denotedLinComb, in which the prover combines committed rows using verifier-supplied coefficients. SIMD ciphertext repacking consolidates each response into a single packed ci- phertext without increasing depth (Section6.4). Brakedown-FHE has linear work but*Ω*(log*N*)depth, while RS-based PCSs require either super-linear work or *O*(log*n*)depth.

*Contribution 3: End-to-end blind SNARK implementation (Sections6.2,7).* Composing the PCS with a Spartan-style sumcheck PIOP for R1CS yields a complete blind SNARK. To preserve*O*(1)FHE depth, each round recomputes its partial fold from the original ciphertexts rather than applyingmult_plainto the result of the previous round. This adds alog*N*factor in plaintext–ciphertext multiplication work. The resulting prover performs*O*(*N*)ciphertext–ciphertext multiplications and*O*(*N*log*N*)total FHE operations at constant depth. Our Rust implementation uses Microsoft SEAL on a single Apple M4 Pro core, with BFV plaintext modulus*q*= 2 16 + 1and ring degree2 14. It produces a128-bit- soundness proof in approximately25seconds at*N*= 2 22. Section7gives the full breakdown.

*Underlying tool: efficient concrete parameter selection (Section5).*For fixed in- puts(*N,q,k,δ*),RAA-Certifyefficiently computes a rigorous upper bound on the distance-failure probability. An explicit bound covers every possible output

weight of the second accumulation, and a two-state moment-generating matrix bounds the output-weight distribution of the first. The algorithm partitions the complete ranges1*≤h≤N*and1*≤w≤N/k*into intervals; it does not as- sume that either*D*(*h*)or*T*(*w*)is monotone.RAA-ParamSelectthen searches candidate(*k,δ*)grids and returns the lowest-cost tuple satisfying a deployment- specified setup-failure budget. At(*N,q,k,δ*) = (2 20 *,*65537*,*4*,*0*.*30), the current prototype completes the ordinary floating-point pass in24*.*70seconds and gives the candidate unfiltered valuelog₁₀ *ϵ*cert*≈−*11*.*0304. Our core concrete obser- vation is that the weight-one contribution dominates this value. A deployment may either choose a conservative tuple whose complete unfiltered bound meets its budget, or perform an exact setup-time scan of every weight-one message and use a more aggressive tuple. At the displayed tuple, this optional scan leaves the anal- ysis of all weights*w≥*2and gives the filtered candidatelog₁₀ *ϵ*setup*≈−*21*.*0817. Final numerical verification requires directed-rounding interval arithmetic. Two distinct budgets govern deployment (Section5.6).*Soundness*against an adaptive prover is set by the IOPP query count*ℓ*and extension-field degree *e*, independently of the code-distance analysis.*Setup-time risk*is the one-time probability that the sampled code misses relative distance*δ*. A parameter tuple is used only when Algorithm1returns a machine-verified upper bound below the deployer’s chosen setup budget. Brakedown [16, §1.2, §7] likewise treats code generation as a public setup event. Our selector leaves the precise setup threshold to the deployment rather than identifying it with per-proof soundness.

1.2 Technical Overview *Blind PCS and SNARK construction.*Over leveled BGV/BFV with plaintext fieldF*q*and SIMD batch size*B*, an encrypted vector[[*f*]]*∈*F
*N* *q*is arranged as an*r×m*matrix. The rows are encoded and the resulting matrix is Merkle- committed column-wise, with*B*rows packed in each ciphertext. Evaluation and proximity testing use theLinComboperation defined above. SIMD repacking compresses each response (Section6.4). The PCS performs*O*(*N*)FHE op- erations at depth1. Composing it with Spartan’s two-sumcheck PIOP gives an end-to-end SNARK with*O*(*N*)ciphertext–ciphertext multiplications and *O*(*N*log*N*)total FHE operations at constant depth.

*Distance analysis: stratified union bound.*After repetition, a weight-*w*message enters the first randomized accumulation with weight*kw*. Let *A*e(*kw,s*)be the probability that this step produces intermediate weight*s*, and let*D*(*s*)be the probability that the next randomized accumulation produces fewer than*δN* nonzero symbols. A union bound gives *N/k* X X*N* *N/kw* e( Pr[dist(*C*)*< δN*]*≤* (*q−*1) *A kw,s*)*D*(*s*)*.* *w*=1 *w* *s*=1 For*w≥*0*.*01*N/k*, entropy estimates obtained from Stirling’s formula give an exponentially small contribution (Theorem3). For smaller*w*, the direct pairwise- product bound of Lemma2gives the required inverse-polynomial estimate.

*Organization.*After preliminaries (§2–3), §4defines the code and states the dis- tance theorem. Section4.3proves it, and §5gives the failure-probability certifier and concrete parameter-search procedure. Section6constructs the blind PCS and SNARK. Section7evaluates performance.

## 2 Related Work

Our work intersects three threads: distance analysis of accumulator-based codes, blind polynomial commitments and verifiable FHE, and coding-based polynomial commitments more broadly. We briefly position the paper in each thread here. AppendixGgives the detailed technical comparisons.

*Distance analysis of accumulator-based codes.*The binary case (*q*= 2) has been studied for over two decades and is settled by [13,21,12]. Non-binary analyses in the*n≫q*regime [28,20,25,17] introduce the code family and give approximate or numerically verified spectral analyses. They do not give a closed-form failure probability with explicit constants for a target(*N,q,k,δ*). Akhiani–Zhang [2] prove *O*˜(*N* *−η* ) +*O*(1*/*(*q−*1)), which is tight when*q*grows super-polynomially but retains a non-vanishing term for fixed*q*. The concurrent Quasi-Abelian codes of [22] attain near-GV concrete distance for*p≫N*. As their authors note, they have no asymptotic distance guarantee for fixed*p*, and their bound becomes vacuous at an FHE plaintext modulus. Lemma2addresses the fixed non-binary- *q*regime and yields failure probability*o*(1*/N*)without a*q*-dependent residual term.

*Blind PCS and verifiable FHE.*Verifiable computation over encrypted data was framed by [14,9] and instantiated with proximity-test IOPs by HELIOPOLIS [4]. HELIOPOLIS introduced the low-depth 2D-NTT evaluation of Reed–Solomon encoding, which Phalanx [30] uses to obtain*O*(1)FHE depth with an*O*(*N* 1+1*/k* ) prover. Laminate [23] obtains*O*(*N*log*N*)prover work at*O*(1)depth through blind GKR and transcript packing. Lasagne [31] follows the same GKR and sum- check route, introducing “multiplication-layered” circuits to reflect FHE depth. Both GKR-based schemes are restricted to layered payload circuits. Phalanx, Laminate, and Lasagne report projected prover times obtained from operation counts and microbenchmarks rather than end-to-end measurements. A parallel line of work [1] applies non-binary RAA codes in the plaintext domain for outsourced SNARKs, but does not address the constant-depth re- quirement created by encryption. Our PCS is the first to combine*O*(*N*)prover work with*O*(1)FHE depth. Composing it with a depth-controlled Spartan PIOP gives an end-to-end blind SNARK with*O*(*N*log*N*)total work at*O*(1)depth, while supporting arbitrary R1CS rather than layered circuits.

*Coding-based PCS more broadly.*Reed–Solomon based schemes (FRI [7], Base- Fold [29], Ligero [3], DeepFold [18], WHIR [5]) pay*O*(*n*log*n*)encoding and *O*(log*n*)FHE multiplicative depth via NTT. Linear-time expander-based codes

(Brakedown [16], Orion [27]) cut encoding to*O*(*n*)but reintroduce*O*(log*n*) depth from the expander cascade. QA codes [22] use*O*(log*n*)-stage Walsh– Hadamard transforms, also*O*(log*n*)depth. Binary RAA [12] is depth-1and linear-time but field-restricted toF₂. Table1(Introduction) summarises the encoding-time, multiplicative-depth, and provable-distance-regime axes. Concurrent work further improves the plaintext coding-based PCS frontier. Lightning [24] composes a base code with a new linear code to trade relative dis- tance for faster commitment. Bolt [19] develops sketched codes and code switch- ing for fast multilinear commitments. ERA codes [6] combine encoding, repe- tition, and accumulation with an IOPP for field-agnostic hash-based SNARKs. These results are complementary to our setting: they optimize plaintext hash- based commitments, whereas we analyze fixed-modulus distance and homomor- phic encoding depth for a blind PCS over FHE ciphertexts. The detailed survey in AppendixGexpands each thread. In particular, it compares our direct combinatorial upper bound with the partitioned IOWE analysis of [2], and it gives a more detailed comparison with [1].

## 3 Preliminaries

For*x∈*F *k* *q*, letwt(*x*)denote its Hamming weight. We use*ρ*and*δ*for relative Hamming weights,*C*for a linear code or its generator matrix, and*C*for a code ensemble. We write encoding as the row-vector product*c*=*xC*.

3.1 Coding Theory Definition 1(Input-Output Weight Enumerator).*For an*[*n,k*]*codeC,* *its input–output weight enumerator (IOWE) is*
*Aw,h*(*C*) =*|{x∈*F *k* *q*: wt(*x*) =*wand*wt(*xC*) =*h}|.*

### ThusAw,h(C)counts weight-wmessages whose encodings have weighth.

Definition 2(Code Ensemble and Average IOWE).*A code ensemble is* *a collectionC*=*{Cr}indexed by a random seedr. Its average IOWE is*

<u>1</u> X *Aw,h*(*C*) = *Aw,h*(*C*) *|C|* *C∈C*

Definition 3(Accumulate Code).*The accumulate codeAis the memory-1,* *rate-1 convolutional code with generator matrix*   1 1 1*...*1 0 1 1*...*1   *...*1 *A*= 0 0 1 *.. .. ... ...*
*.... .*
0 0 0*...*1

### Thus(x₁,...,xn)A= (x₁,x₁ +x₂,...,x₁ +···+xn).

Definition 4(Repeat Code).*The rate-*1*/krepeat codeRhas generator ma-* *trix*   *R* *′*  *R′*  *n* *R*= *.*  *∈*F*q ×kn* *..*  *R* *′*

*whereR* *′* = (1 1*...*1)*∈*F *k* *q* *. It repeats each symbol ofxexactlyktimes.*

3.2 Polynomial Commitment Schemes and IOPPs Definition 5(Polynomial Commitment Scheme).*A polynomial commit-* *ment scheme (PCS) forµ-variate multilinear polynomials over*F*qis a tuple of* *algorithms*(Setup*,*Commit*,*Eval)*:* *•*Setup(1 *λ* *,µ*)*→*pp*: given security parameterλand number of variablesµ,* *outputs public parameters.* *•*Commit(pp*, f*˜)*→*(*C,D*)*: commits to a multilinear polynomial f*˜:F
*µ* *q→*F*q* *and returns a commitmentCtogether with prover auxiliary dataD.* *•*Eval(pp*,C,z,y*;*f,*˜ *D*)*: an interactive protocol between proverPand verifierV* *in whichPconvincesVthat the committed polynomial satisfies f*˜(*z*) =*yon* *a verifier-chosen evaluation pointz∈*F *µ*

*q.*
*The scheme must satisfy the following three security properties.*

*1.*Completeness.*For everyµ-variate multilinear f*˜*, everyz∈*F
*µ* *q, andy*= *f* ˜(*z*)*,*

*an honest execution of*Eval(pp*,C,z,y*;*f,*˜ *D*)*on*(*C,D*)*←*Commit(pp*, f*˜)*has* *the verifier accept with probability*1*over the protocol’s internal randomness.*

*2.*Binding.*For every PPT adversaryA:*  ˜ ˜
 *f₀ ̸*= *f₁ ∧λ* ˜ pp*←*Setup(1*,µ*);  Pr Eval(pp*,C,z₀,y₀*;*f₀,D₀*) =*accept∧* ˜ *≤*negl(*λ*)*.* ˜ (*C,{*(*fb,Db,zb,yb*)*}b∈{*0*,*1*}*)*←A*(pp) Eval(pp*,C,z₁,y₁*;*f₁,D₁*) =*accept*

*No PPT adversary, given*pp*, can produce a single commitmentCtogether* *with two convincing openings for distinct polynomials, except with negligible* *probability.*

*3.*Knowledge Soundness.*There exists a PPT extractorEsuch that, for ev-* *ery PPT proverP*
*∗* *that causes*Eval*to accept on commitmentCwith non-* *P* *∗* ˜ ˜( *negligible probabilityϵfor some*(*z,y*)*,E* (pp*,C*)*outputs fsatisfying f z*) = *ywith probability at leastϵ−*negl(*λ*)*.*

Definition 6(Interactive Oracle Proof of Proximity (IOPP)).*LetC⊆* F*q* ˆ*n* *be a linear code with relative minimum distanceδ. An IOPP forCis an* *interactive protocol⟨P,V⟩in whichVhas oracle access to a purported codeword* y*∈*F*q* ˆ*n* *and to the messagesPwrites onto a public oracle:*

*1.*Completeness.*If*y*∈C, the verifier interacting with the honestPaccepts* *with probability*1*.*
*2.*Soundness (proximity gap).*If*y*is more thanδ/*3*-far fromC(in relative* *Hamming distance), then for any (possibly unbounded) malicious proverP*
*∗* *,* *the verifier accepts with probability at mostβ*(*δ,ℓ*)*, whereℓis the verifier’s* *query complexity andβis the protocol’s*soundness error*.*

*For the Ligero proximity-test framework [3] we use, the soundness error takes* *the formβ*(*δ,ℓ*) = (1*−δ/*3) *ℓ* +negl(*λ*)*where the negligible term comes from a* *Schwartz–Zippel check on a verifier-chosen random linear combination.*

3.3 (Leveled) Homomorphic Encryption We use a leveled homomorphic encryption (LHE) scheme [11,10]*E*= (KeyGen*,*Enc*,*Dec*,*Eval)over plaintext space*P*=F
*D* *p*, with standard syn- tax and a maximum multiplicative depthMAXDEPTHbeyond which decryption is no longer guaranteed correct. BGV/BFV ciphertexts are SIMD-packed across *D*slots [10]: an encryption of*m∈*F *D* *p*, denoted[[*m*]], supports component-wise

|p|||
|---|---|---|
|13|14||

homomorphic addition[[*u*]] + [[*v*]], plaintext–ciphertext multiplication*w·*[[*u*]], and ciphertext–ciphertext multiplication[[*u*]]*·*[[*v*]], all acting on all*D*slots in parallel. Throughout this paper,*D∈{*2*,*2*}*(the standard BFV/BGV SIMD batch sizes).

## 4 Generalized RAA Codes and Distance Analysis

We introduce the code family, state the main distance theorem, and give the proof.

*Notation (Sections4–5).*Throughout the distance analysis,*N*denotes the*code-* *word block length*of the (per-row) Generalized RAA code and*N/k*its message length. In the blind-PCS application (Sections6onward) the witness is arranged in a balanced Ligero matrix and*each row*is encoded by this code, so a code- word length*N*supports a circuit of size(*N/k*) 2; the application sections write the circuit size itself as*N*and the per-row codeword length explicitly.

Definition 7(Random Interleavers [21]).*A uniformly sampled permuta-* *tionπ∈S,...,x*

|induces the rate-1 codeP||defined byxP||= (x|)for|
|---|---|---|---|---|---|
|n||π||π π(1)|π(n)|
|n|n q|||||
|||||n||
|q n||r||r|n n|
||N/k|||||
||q|π r|π r|||

*x*= (*x₁,...,x*)*∈*F*.*

Definition 8(Random Weightors).*For*r= (*r₁,...,r*)*sampled uniformly* *from*(F *\{*0*}*)*, the random weightorW acts asxW* = (*r₁x₁,...,r x*)*.*

Definition 9(Generalized RAA Code Ensemble).*The Generalized RAA* *code encodesx∈*F *as*

*c*=*xR*(*P*1*W*1*A*)(*P*2*W*2*A*)*,*

||2|5 1|x= (2,5,1)||
|---|---|---|---|---|
|R|||||
|P W A|2 2 2 5 6 3 5 2|5 5 1 1 6 6 4 1|1 xR 1 P|W (xR)|
|P W A|6 2 0 2 2 4 3 4 2 6 2 6|1 0 4 5 0 3 1 6 6 2 3 2|6 u₁ (afterA) 0 P 2 c(codeword,wt = 9)|W (u₁)|

*π* 1 r1 *π* 1 r1

*π* 2 r2 *π* 2 r2

Fig.1.The Generalized RAA encoding pipeline of Example1(*q*= 7,*k*= 3,*x*= (2*,*5*,*1), all arithmetic mod7): repeat (*R*), interleave-and-weight (*Pπ*1*W*r1), accumulate

(*A*), and a second interleave-weight-accumulate round. Every stage is an element-wise multiplication or a prefix-sum scan (no field inversions or FFTs), so the pipeline is natively FHE-compatible. *whereRis the rate-*1*/krepeat code,Pπiare random permutations,W*r*iare* *random diagonal weightors, andAis the accumulator (prefix-sum operator).* *TheensembleCkis the collection over all*(*π₁,π₂,*r₁*,*r₂)*.* *Example 1(RAA Encoding withk*= 3*).*For*q*= 7,*N/k*= 3,*k*= 3,*x*= (2*,*5*,*1)and parameters*π₁* = (1*,*4*,*7*,*2*,*5*,*8*,*3*,*6*,*9),r₁ = (3*,*2*,*5*,*1*,*4*,*6*,*2*,*3*,*1), *π₂* = (5*,*9*,*2*,*7*,*3*,*8*,*1*,*4*,*6),r₂ = (2*,*3*,*5*,*1*,*4*,*2*,*6*,*3*,*1), the pipeline produces the codeword*c*= (2*,*6*,*2*,*6*,*6*,*2*,*3*,*2*,*2)(all arithmetic mod7); Figure1traces the intermediate vectors stage by stage. The codeword*c*has Hamming weight9(all nonzero); every step is element-wise multiplication or a prefix-sum scan, with no field inversions or FFTs, so the pipeline is natively FHE-compatible.
### The key structural properties are immediate:

*•*Linear-time encoding.Each operation (repeat, permute, scale, accumu- late) is*O*(*N*). *•*Constant multiplicative depth.Per FHE-operation accounting: the re- peat step*R*is a plaintext rearrangement (depth0); the permutation*πi*is a public coordinate reshuffle implemented either via SIMD slot rotations (depth0) or, when packed across*B*rows, by a permutation network of constant-depth rotate-and-mask blocks (which we account as depth0*.*5to flag the masking pt-ct multiplication); the weightor*W*r*i*is one round of plaintext-ciphertext multiplication by a public weight vector (depth0*.*5, since pt-ct mults consume half the noise budget of a ct-ct mult); the accumula- tor*A*is the depth-0prefix-sum scan implemented with ct-ct additions only. Summing along the pipeline*R→*(*Pπ*1*W*r1)*→A→*(*Pπ*2*W*r2)*→A*, the total multiplicative depth is0*.*5 + 0*.*5 = 1level, one pt-ct multiplication’s worth of noise growth from each weightor, accumulated additively.

*•*Defined over any prime power.The encoding pipeline is well-defined over any finite fieldF*q*with*q >*2; the distance analysis (Section4.3) covers the fixed-*q*regime.

4.1 IOWE Machinery The input–output weight enumerator (IOWE) of the non-binary accumulator is [28,25,17]:
*w* X *−*1 *h−*1 *N−h* *Aw,h*=<u>w−i w−i</u>

|i=0|2||2|
|---|---|---|---|
|||w−i||
|||2||

*i*=0 2 *−*1 2 *h−* *⌈* <u>w−i</u> 2*⌉ i* *·* (*q−*1) (*q−*2)*.* *i*

Lemma 1(IOWE of composed encoders [21]).*For two codesC₁,C₂* *over*F*q, whereC₁ has block lengthn, the average IOWE of the ensemble* P*n* <u>A</u>

||n A|(C)A|(C)|
|---|---|---|---|
|π r|l=1|(q−1)||

<u>w,l(C1)Al,h(C2)</u> *C*=*{C₁PπW*r*C₂}is Aw,h*(*C*) =*n l.* ( *l* )

The random interleaver makes the composition memoryless on the support distribution, while the random weightor eliminates the dependence on specific nonzero values. If we composed two codes directly without an interleaver, the weight distribution of the final codeword would depend on both the support pattern and the values of the nonzero elements in the intermediate codeword, yielding a correlated distribution. The random interleaver breaks this correlation by uniformly randomizing the support, while the weightor uniformly randomizes the values. As a result, the IOWE of the composed code factors cleanly into a product of the individual IOWEs, the key structural property that enables our analysis.

4.2 Main Theorem Theorem 2(Linear Minimum Distance, Asymptotic).*For any fixedq >* 2*, there existK∈*N
+ *andδ >*0*such that for repetition factork > K:*

Pr [*∃x̸*= 0 : wt(RAA(*x*))*≤δN*] =*o* *N* <u>1</u> *.* $ *π* 1 *,π*2*←−SN* $ *N* r 1 *,*r2*←−*(F*q\{*0*}*)

*The thresholdKmay depend onqbut not onN; the distance constantδmay be* *chosen universally. The asymptotic conclusiono*(1*/N*)*holds for any fixed prime* *powerq≥*3*.*

*Remark 1(Explicit dependence onq).*The following gives one explicit sufficient choice. Put*η₀* = 0*.*01and choose

<u>0.99</u>
*δ₀* := 2 *.* 144e

Let*ψη*0:=*Ψη*0((1*−η₀*)*/*199)*<*0be the exponent from AppendixD.1, set *Λη*0:=*−ψη*0*/*2, and put r r <u>2δ₀</u> *√* <u>η₀</u> *µ₀* :=*η₀Λη*0*, a₀* := 6*, b₀* := 6 *a₀.*

0*.*99 2(1*−η₀*)
Hereeis Euler’s number,*a₀ <*e *−*1, and*b₀ <*1. One sufficient threshold is

<u>logq log(e(q−1)/η₀)</u> *K*(*q*) := max 9*,,.*(1) *µ₀ −*log*b₀*

Then the theorem holds with*δ*=*δ₀* for every fixed*k > K*(*q*)and all sufficiently large*N*. The term involving*µ₀* closes the large-weight branch. Indeed,*η₀ >*2*δ₀*, so the accumulator’s support condition makes the second-accumulator collapse probability exactly zero whenever its input weight exceeds*η₀N*. The constants 9and*b₀* close the two endpoints of the remaining small-weight branch. Floors, ceilings, and polynomial prefactors affect only the threshold on*N*.

4.3 Distance Proof We prove Theorem2by bounding the probability that any nonzero input*x*maps to a codeword of weight below*δN*. *Proof strategy: stratified union bound.*A naïve union bound over all*q*
*N* possible nonzero inputs would be exponentially loose. Instead, we partition the input space by weight and bound each weight class separately. Write the normalized IOWE *A*˜(*w,h*) =*Aw,h/*[ *N* *w* (*q−*1) *w*]and, for a relative threshold*η*, define

*⌊* X *ηN⌋* *Dη*(*s*) := *A*˜(*s,h*)*, D*(*s*) :=*Dδ*(*s*)*.* *h*=1

Using the union bound and stratifying by input weight:

Pr[dist(*C*)*< δN*] = Pr [*∃x̸*= 0 : wt(RAA(*x*))*≤δN*] *N/k* X *≤* Pr [*∃x*: wt(RAA(*x*))*≤δN|*wt(*x*) =*w*]*.*(2) *w*=1

*Weight evolution through the pipeline.*For a fixed input*x*of weight*w*, we trace the weight distribution through the encoding process*c*=*xR*(*Pπ*1*W*r1*A*)(*Pπ*2*W*r2*A*):

1.*Repeater*: The output of*xR*has weight exactly*kw*, since each nonzero coor- dinate is replicated*k*times.
2.*Random interleaver + weightor*: Since*Pπ*1and*W*r1preserve the number of nonzero coordinates, the weight remains*kw*after these operations.

3.*First accumulator*: The weight distribution of*xRPπ*1*W*r1*A*is governed by the (*kw*)-th row of the IOWE matrix of the accumulator, i.e.,Pr[wt(*xRPπ*1*W*r1*A*) = *s*] = *A*˜(*kw,s*).
4.*Second round*: Similarly, for the second round,Pr[wt(*xPπ*2*W*r2*A*) =*h|* wt(*x*) =*s*] = *A*˜(*s,h*). Composing via Lemma1, the probability that a weight-*w*input produces a low- weight output is:
<u>N</u>X*N* Pr[*∃x*: wt(RAA(*x*))*≤δN|*wt(*x*) =*w*]*≤* *k* (*q−*1) *w* *A* ˜(*kw,s*)*·D*(*s*)*.*(3) *w* *s*=1

Our objective is to show that each weight-*w*term in (2) is*o*(1*/N²*), so that summing over all*w∈*[*N/k*]yields*o*(1*/N*). The analysis splits at*w*= 0*.*01*N/k* into two regimes, each requiring distinct analytical techniques. The constant0*.*01 is a convenient source of slack, not an empirically estimated phase transition. It makes the repeated weight in the large branch at least0*.*01*N*, while in the small branch it gives*N/*(*N−kw*)*≤*100*/*99. Any sufficiently small fixed constant could replace0*.*01, with corresponding changes to the proof constants.

### Large Weight Regime (w≥0.01N/k).

*Intuition.*In this regime the input weight to the first accumulator is*kw≥*

0*.*01*N*, but its output weight remains random. We split according to whether that output falls below0*.*01*N*. Such a collapse is exponentially unlikely by applying the following theorem with threshold*η₀* = 0*.*01; above the split, the second accumulator’s low-output probability is exponentially small by applying it with threshold*δ*. Theorem 3(Exponential decay of*D*(*w*)).*Fix anyηin the regime where* *the functionΨηbelow is monotone decreasing on its relevant range. There exist* *constantsΛη>*0*andNηsuch that, for everyN≥Nηand everyr≥*0*.*01*N,*
*Dη*(*r*)*≤e* *−Λη r* *.*

*Proof sketch.*Bound *A*˜(*r,h*)for*h≤ηN*by replacing the nonzero-symbol factor (*q−*1) *a* (*q−*2) *i* */*(*q−*1) *r* by1. Entropy estimates obtained from Stirling’s formula then bound the remaining trinomial sum. Writing*a*=*αN*,*h*=*βN*, and*i*=*θN* gives *A*˜(*r,h*)*≤rN* *O*(1) max*ie* *Φ*(*α,β,θ*)*N*, where the polynomial factor also absorbs the one-unit parity gap between*⌈*(*r−i*)*/*2*⌉*and*⌊*(*r−i*)*/*2*⌋*. Maximizing first over*β*and then over*θ*reduces the exponent to*Ψη*(*α*). In the stated regime,

|η η|||η|O(1) ψ N||
|---|---|---|---|---|---|
|η|η|||η|εr η|

*ψη*:=*Ψη*((1*−η*)*/*199)*<*0. Thus*Dη*(*r*)*≤rN* *O*(1) *e* *ψη N*. Since*N≥r*and*ψη<*0, we have*ψ N≤ψ r*; the polynomial prefactor is at most*e* for all sufficiently large*N*and any fixed*ε >*0. Taking0*< ε <−ψ* and*Λ* =*−ψη−ε*proves the theorem. The full derivation, including the entropy estimate, the*∂Φ/∂β*and *∂Φ/∂θ*calculations, the monotonicity check for*Ψ*, and the resulting*δ*range, is given in AppendixD.1.

Corollary 1.*Fixδin the regime of Theorem3. There existK∈*N + *andC >*0 *such that, fork > K,Nsufficiently large, andw≥*0*.*01*N/k,*

X ˜ *N* *N/kw −CN* (*q−*1) *A*(*kw,s*)*Dδ*(*s*)*≤e.* *w* *s*=1

Corollary 2.*Under the same assumptions, there existK∈*N + *andC >*0*such* *that, fork > Kand everyw≤*0*.*01*N/k,*

X *N* *N/kw* ˜*−CN* (*q−*1) *A*(*kw,s*)*Dδ*(*s*)*≤e.* *w* *s*=*⌈*0*.*01*N⌉*

The first corollary applies Theorem3twice: *D₀.*01(*kw*)controls collapse in the first accumulator, while*Dδ*(*s*)controls the second accumulator above the split. The second corollary uses only the latter bound. Full derivations appear in AppendixD.2.

### Small Weight Regime (w <0.01N/k).

*Intuition: bounding all symbol assignments uniformly.*When the input weight*w* is small, the Stirling-based bounds used in the large-weight regime become too loose: they estimate*o*(1)but cannot achieve the*o*(1*/N²*)precision needed to survive the union bound over*O*(*N*)weight classes. Prior analyses of accumulator- based codes [8,2] partition the IOWE sum by collision count*i*. On one part they retain the nonzero-symbol factor(*q−*1) *a* (*q−*2) *i* */*(*q−*1) *w*, which contributes *O*(1*/*(*q−*1))to the final bound. On the other part they replace this factor by the trivial upper bound1. This decomposition is what produces the*O*(1*/*(*q−*1)) floor that prevents prior bounds from going below*∼*10 *−*5 when*q*= 2 16 + 1. <u>(q−1)</u> *a* <u>(q−2)</u> *i* We instead apply (*q−*1)*w* *≤*1uniformly for every*i*. This removes the *q*-dependent term. We then bound the complete remaining combinatorial sum di- rectly, using a pairwise-product inequality. For small input weight*w*and output weight*h≤δN*, the resulting upper bound is sufficient to avoid the*O*(1*/*(*q−*1)) term in the prior analysis.

Lemma 2(Pairwise-Product IOWE Bound).*ForN≥*100*,w≤*0*.*01*N,* *and*1*≤h≤N−w:*

<u>w² h</u> *⌊*(*w−*1)*/*2*⌋* *A* ˜(*w,h*)*≤ · ·*6*w* *N N−w*

### Consequently, for everyδ≤0.30:

2 *⌊*(*w−*1)*/*2*⌋* <u>w δN+ 1 δN+ 1</u>*w* *D*(*w*)*≤ · · ·*6*.* *⌊*(*w−*1)*/*2*⌋*+ 1 *N N−w*

*Proof sketch.*The nonzero-symbol factor(*q−*1) *a* (*q−*2) *i* */*(*q−*1) *w* is at most1 because*a*+*i≤w*. Write*a*=*⌈*(*w−i*)*/*2*⌉*and*b*=*⌊*(*w−i*)*/*2*⌋*. Direct factorial estimates, together with *N* *w* = (*N/w*) *N* *w−−*11 and*N/*(*N−w*)*≤*100*/*99*<*2, give a per-summand upper bound

*⌊*(*w−*1)*/*2*⌋* <u>w</u>*w*<u>h</u>

6*.*
*N N−w*

Summing first over*i*and then over*h≤δN*proves the two displayed bounds. AppendixD.3gives the parity cases*a*=*b*and*a*=*b*+ 1.

*Remark 2(Regime split vs. [2]).*The analysis of [2] partitions the IOWE sum at *i*=*w₂ −*2*w₀ −*1. It retains the nonzero-symbol factor on one part and uses the trivial bound on the other. This gives the asymptotically tight rate *O*˜(*N* *−*(*k−*2) ) when*q≫n*, but it also introduces an additive*O*(1*/*(*q−*1))term when*q*is fixed. Lemma2applies the trivial bound uniformly and controls the combinatorial part directly. The prior decomposition is tighter when*q*=*ω*(poly(*n*)), because its nonzero-symbol factor decays as1*/*(*q−*1) (*w*1*−i*)*/*2. Ours is tighter for fixed*q*, where it has no*q*-dependent residual term. The FHE-plaintext regime (*q*= 2 16 + 1,*q≪N*) is in our favourable half of the trade.

Lemma 3.*There existsKsuch that fork > Kandw≤*0*.*01*N/k:*

*⌈*0*.*01 X *N⌉−*1 *N/kw* ˜2 (*q−*1) *A*(*kw,s*)*·D*(*s*) =*o*(1*/N*)*.* *w* *s*=1

*Proof sketch.*Substituting the bounds from Lemma2for both *A*˜(*kw,s*)and*D*(*s*) gives a product whose logarithmic derivative in*s*is negative for sufficiently small *δ*. The largest summand is therefore attained at the left endpoint, up to constant slack. After applying *N/k* *w* *≤*(*Ne/*(*kw*)) *w* and accounting for at most0*.*01*N* summands, the per-weight bound has the form

*p*(*w*) =*C₁ ·C₂* *w* *·w* *O*(1) *·*(*w/N*) (*k/*2*−*1)*w*+*O*(1)

for constants*C₁,C₂* independent of(*N,w*). This is enough to conclude*p*(*w*) = *o*(1*/N²*)uniformly over*w≤*0*.*01*N/k*once*k*is sufficiently large and*δ*is suffi- ciently small. Full derivation, including the explicit thresholds on*k*and*δ*pro- duced by the analysis, is in AppendixD.4.

Theorem 4(Small-weight bound).*There existsKsuch that fork > Kand* *w≤*0*.*01*N/k:*

X ˜ *N* *N/kw* 2 (*q−*1) *A*(*kw,s*)*·D*(*s*) =*o*(1*/N*)*.* *w* *s*=1

The theorem follows by splitting the inner sum at*s*= 0*.*01*N*and bounding each half: the lower half by Lemma3(*o*(1*/N²*)), the upper half by Corollary2 (*e* *−Ω*(*N*) ). See AppendixD.5.

Completing the Proof.The proof of Theorem2follows by summing (3) over*w*, then splitting at*w*= 0*.*01*N/k*: the large-weight portion is*e* *−Ω*(*N*) by Corollary1, the small-weight portion is*o*(1*/N²*)per term by Theorem4, and summing over*w∈*[*N/k*]gives*o*(1*/N*). The full proof is in AppendixD.5.

## 5 Concrete Distance Analysis and Parameter Selection

Theorem2establishes asymptotic linear distance for fixed*q*and sufficiently large*k*and*N*. A PCS deployment instead fixes a finite block length and typi- cally uses a small repetition factor, so we analyze each concrete tuple(*N,q,k,δ*) directly. We express its distance-failure probability as a union bound over all message weights and intermediate weights, majorize the second-accumulator failure probability by a geometrically contracting function, and bound the first- accumulator lower tail with a two-state generating matrix. Interval partitions then combine these bounds over the complete weight ranges. This gives the ef- ficientRAA-Certifyprocedure for evaluating a fixed tuple and a feasibility oracle for searching cost-minimizing parameters under a deployment-specified setup-failure budget.

*Proof outline.*A weight-*w*message has weight*kw*after repetition. To simplify the notation in the concrete analysis and certification procedure, let*Hs*denote the output weight of the first randomized accumulator when its input has weight

*s*. Thus its intermediate output weight is*Hkw*. Writing*d*=*⌈δN⌉−*1, recall the two central quantities
*D*(*h*) := Pr[wt(*yPWA*)*≤d|*wt(*y*) =*h*]*,* *N/kw* *T*(*w*) := (*q−*1) E[*D*(*Hkw*)]*.* *w*

Thus*D*(*h*)is the conditional failure probability of the second accumulator, and *T*(*w*)is the union-bound contribution of all weight-*w*messages. To bound every *T*(*w*), we first derive an explicit decreasing upper bound on*D*(*h*). We then use a two-state generating matrix to bound the probability that*Hkw*lies in a prescribed weight interval. Summing over partitions of the complete*h*- and *w*-ranges gives the failure-probability upper bound returned byRAA-Certify.

5.1 The Concrete Union Bound Put
*q₀* :=*q−*1*, n*:=*N/k, d*:=*⌈δN⌉−*1*.* Thus a codeword has relative weight below*δ*exactly when its weight is at most

*d*. The case*d*= 0has failure probability zero because every stage of the encoder is injective on nonzero inputs, so below we assume*d≥*1. For an accumulator whose randomized input has weight*h*, define
X*d*<u>A</u> <u>h,s</u> *D*(*h*) := Pr[wt(*yPWA*)*≤d|*wt(*y*) =*h*] = *N h*

*.*(4)
*s*=0 *h* *q₀*

Here*PW*is an independent random interleaver and weightor, and*A·,·*is the unnormalized accumulator IOWE from Section3. Section4.3writes *A*e(*s,h*)for the corresponding normalized IOWE. For concise notation in the concrete anal- ysis and certification procedure, we represent this distribution by the random output weight*Hs*. Hence

e( <u>As,h</u> Pr[*Hs*=*h*] = *A s,h*) = *N s*

*.*(5)
*s* *q₀*

The random interleaver chooses the support uniformly and the random weightor chooses every nonzero value independently and uniformly, so Equation (5) ap- plies to the repeated word with*s*=*kw*. For a message of weight*w*, let

*nw* *T*(*w*) := *q₀* E[*D*(*Hkw*)]*.*(6) *w*

The standard union bound is then X *n* Pr[dist(*C*)*< δN*]*≤ T*(*w*)*.*(7) *w*=1

The following lemmas give an efficiently computable upper bound on the right- hand side.

5.2 An Explicit Upper Bound for the Second Accumulator The first observation removes more than half of the possible intermediate-weight range.
### Lemma 4.For everyh >2d,D(h) = 0.

### For0≤h≤N, define

|min {h,d}|h 2 d||
|---|---|---|
||t t|−(h−t)|
||N||
|t=0|t||

X *U⋆*(*h*) := *q₀.*(8)

Theorem 5(Second-accumulator upper bound).*For every*0*≤h≤N,*

*D*(*h*)*≤U⋆*(*h*)*.*

*Moreover, for everyx∈*(0*,*1)*and*0*≤h < N,*

<u>1 d/N</u> *U⋆*(*h*+ 1)*≤* 2 + 2 *U⋆*(*h*)*.*(9) *q₀*(1*−x*) *x*

*Consequently,*

|||−1/3|1/3 3|
|---|---|---|---|
|⋆|⋆ ⋆|⋆||
|⋆||⋆||

*U* (*h*+ 1)*≤ρ U* (*h*)*, ρ* := *q₀* + (*d/N*)*.*(10)

*In particular,U is globally decreasing whenρ <*1*.*

*Proof(Proof sketch).*Condition on the*h*support positions of the accumulator input. Their gap vector is a uniformly random weak composition of*N−h*into *h*+ 1bins. A union bound over the prefix indices at which the running sum returns to zero gives

X *h* <u>1</u> *h N−h*+*j d−j* *D*(*h*)*≤* *N* *q₀.* *h j*=0 *j j h−j*

Substituting*t*=*h−j*yields Equation (8). For the contraction, write the*t*-th summand as*uh,t*. The two exact parent ratios are

|h+1,t|2|h+1,t|2|
|---|---|---|---|
|h,t|2|h,t−1|2|

*u* (*h*+ 1) 2 *u* (*h*+ 1) 2 (*d−t*+ 1) =*,* =*.* *u q₀*(*h*+ 1*−t*) *u t* (*N−t*+ 1)

Split the child terms at*t*=*⌊x*(*h*+ 1)*⌋*and compare the two parts to the cor- responding parents. This proves Equation (9). Minimizing its coefficient over*x* gives Equation (10). AppendixE.1contains the full counting and endpoint de- tails.*⊓⊔*

For the parameters(*q,N,δ*) = (65537*,*2 20 *,*0*.*30), Equation (10) gives*ρ⋆<*

0*.*3346. This is a proved contraction factor for the explicit majorant*U⋆*.
5.3 A Two-State Moment-Generating Function for the First Accumulator
### Fora∈(0,1]andz >0, define the positive matrix

1*q za*0 *Ma*(*z*) :=*.*(11) *z a*(1 + (*q−*2)*z*)

The states indicate whether the running accumulator value is zero or nonzero. The variable*z*marks a nonzero input coordinate, and*a*marks a nonzero output coordinate.

Lemma 5.*Lete₀* = (1*,*0) *T* *and*1= (1*,*1) *T* *. For a polynomialF*(*z*)*, let* coeff*s*(*F*)*denote the coefficient ofz* *s* *. Then* X

|T|N|wt(Ax)|
|---|---|---|
|s 0 a|||
||x∈F wt(x)=s||
|H|s T 0 a N|N s|
||s||

coeff *e M* (*z*) 1 = *a.*(12) *N* *q*

*Consequently,*

*s* <u>coeff e M (z) 1</u> E[*a*] =*.* *q₀*

*Proof.*From state zero, a zero increment remains zero and each of the*q₀* nonzero increments enters the nonzero state. From a nonzero state, a zero increment remains nonzero, exactly one nonzero increment returns to zero, and the other *q−*2nonzero increments remain nonzero. These four possibilities are exactly the entries of (11). Multiplying over all coordinates and extracting the coefficient of *z* *s* proves the claim.*⊓⊔*

*Remark 3.*The matrix is a transfer matrix for accumulator paths. Each multi- plication advances one coordinate, while the powers of*z*and*a*record the input and output weights. The coefficient functional therefore isolates inputs of weight *s*exactly, and the positive-matrix comparison below converts this identity into an optimizable lower-tail bound.

For*r >*0, put n <u>z</u> o *λ*(*a,z,r*) := max 1 +*q₀zar, a*(1 + (*q−*2)*z*) +*, C*(*r*) := max*{*1*,*1*/r}.* *r* (13)

Lemma 6.*For everya∈*(0*,*1]*,z,r >*0*, and integerR,*

||−R||N|
|---|---|---|---|
|s||s N s||
|||s||
|T||a||
||T 0 a N||N|
|s|s|s|H −R|

<u>a C(r)λ(a,z,r)</u> Pr[*H ≤R*]*≤.*(14) *z q₀*

*Proof.*For*v*= (1*,r*), the definition of*λ*gives*M* (*z*)*v≤λ*(*a,z,r*)*v*component- wise, and1*≤C*(*r*)*v*. Therefore*e M* (*z*) 1*≤C*(*r*)*λ*(*a,z,r*). The nonnegative- coefficient inequalitycoeff (*F*)*≤F*(*z*)*/z* and1[*H ≤R*]*≤as*complete the proof.*⊓⊔*

5.4 Complete Failure-Probability Certification Theorem 6(Complete failure-probability bound).*Assumeρ⋆<*1*, and* *partition the complete active intermediate-weight range into consecutive intervals*
### [1,H⋆] =B₁ ⊔···⊔B

|,|H := min{N,2d},B||= [L|,R].|
|---|---|---|---|---|
|J|⋆||j w,j|j j w,j|
|J|−R|||N|
|w|w,j|w,j w,j|w,j w,j||
|⋆ j=1|j|kw N w,j kw|kw||

*For everyw∈*[*n*]*, everyj∈*[*J*]*, and arbitrary parametersa ∈*(0*,*1]*,z >*0*,* *andrw,j>*0*,*

X <u>a</u>*j*<u>C(r)λ(a,z,r)</u> *n* *T*(*w*)*≤ q₀ U* (*L*)*.*(15) *w z q₀*

*Summing the displayed quantities over all*1*≤w≤nis therefore an upper bound* *on*Pr[dist(*C*)*< δN*]*.*

*Proof.*Lemma4removes*h >*2*d*. On*Bj*, Theorem5and*ρ⋆<*1give*D*(*h*)*≤* *U⋆*(*h*)*≤U⋆*(*Lj*). Hence

X *J* E[*D*(*Hkw*)]*≤ U⋆*(*Lj*) Pr[*Hkw≤Rj*]*.* *j*=1

Applying Lemma6to each term and multiplying by the outer factor in (6) proves (15). Finally, sum over the complete range*w∈*[*n*]in (7).*⊓⊔*

We batch the outer sum over a consecutive message-weight interval*I⊆*[*n*]. Fix one intermediate-weight interval[*L,R*]and use a common parameter triple (*a,z,r*)for all*w∈I*. The*w*-dependent factor in Equation (15) is

<u>q</u>

|w n 0 w|w n|1−k −k|w|
|---|---|---|---|
|kw N kw|N|||
|kw|kw|||

*Γw*(*z*) := = *q₀ z.*(16) *z q₀*

Then the contribution of this pair of weight intervals is at most X *U⋆*(*L*)*a* *−R* *C*(*r*)*λ*(*a,z,r*) *N* *Γw*(*z*)*.*(17) *w∈I*

The finite scalar sum in (17) is evaluated directly over every integer*w∈ I*. Sharing one parameter triple over*I*reduces the number of witness optimizations, while the complete message-weight and intermediate-weight partitions retain every term in (7).

Algorithm 1:RAA-Certify: distance-failure probability certifica- tion. Input: *N,q,k,δ*; an optional exact set*W₀* and complete*w*- and *h*-interval partitions Output:An upper bound*ϵ*certsatisfyingPr[dist(*C*)*< δN*]*≤ϵ*cert, or FAIL 1*q₀ ←q−*1;*n←N/k*;*d←⌈δN⌉−*1;*H⋆←*min*{N,*2*d}*; 2Compute an outward-rounded interval enclosure of*ρ⋆*; 3ifsup*ρ⋆≥*1then 4return*FAIL* 5Bound every*w∈W₀* by directed-rounded exact IOWE sums; 6Verify that*W₀* and the*w*-intervals partition[1*,n*]; 7Verify that the*h*-intervals partition[1*,H⋆*]; 8foreach*w-intervalIandh-interval*[*L,R*]*⊆*[1*,H⋆*]do 9Use floating point to choose a parameter triple(*a,z,r*); 10Re-evaluate every factor in ( P

17), including*U⋆*(*L*),*a*
*−R* ,*C*(*r*), *λ*(*a,z,r*), and*w∈IΓw*(*z*), with directed-rounding intervals; 11if*the parameter domain or interval evaluation cannot be verified* then 12Refine the failing interval, orreturn*FAIL*; 13Add the upper endpoint of (17) to*ϵ*cert; 14return*ϵ*cert

*Numerical evaluation.*Theorem6proves the bound returned by Algorithm1, provided every arithmetic operation is enclosed by directed-rounding intervals. Ordinary floating point is used only to choose the interval partitions and the parameters(*a,z,r*). The current prototype covers every1*≤w≤N/k*and completes the ordinary floating-point pass for(*N,q,k,δ*) = (2 20 *,*65537*,*4*,*0*.*30) in24*.*70seconds, giving the candidate value

log₁₀ *ϵ*cert*≈−*11*.*0304*,*

with*w*= 1dominating and the batched*w≥*4contribution below10 *−*27*.*13. This value comes from the full-range calculation. It becomes a verified numerical bound once the same calculation is repeated with directed-rounding interval arithmetic.

*Small-weight screening.*Our core deployment observation is that*T*(1)dominates the certified failure bound at the baseline tuple. This exposes a direct setup- time tradeoff. A deployment may spend additional one-time work to check every weight-one message and thereby use a more aggressive tuple, such as a smaller *k*or a larger target distance. Alternatively, it may omit this scan and select a more conservative tuple whose unfiltered bound, including*T*(1), already meets the same setup budget.

For fast parameter screening, let*S₁* :=*T*(1). Exact IOWE sums over a selected set of small intermediate weights give a lower bound*L₁ ≤S₁*, while the exact first-accumulator prefix together with the*U⋆*contraction gives an upper bound*S₁ ≤U₁*. In the unfiltered mode,*L₁ > ϵ*setupsafely discards the tuple immediately. In the filtered mode,*U₁* bounds the expected resampling overhead of the exact setup filter below. The complete range, including every*w≥*2, remains certified by Algorithm1.

5.5 Optional Exact Setup-Time Filtering of Weight-One Messages For deployments choosing the filtered mode, the union bound supports exact rejection sampling at setup time. Let*G*be the realized*n×N*generator matrix, with rows*g₁,...,gn*. Every weight-one message is*aei*for some*a∈*F
*×* *q*, and its codeword is*agi*. Nonzero scaling preserves Hamming weight, so it suffices to computewt(*gi*)once for every*i∈*[*n*]. The filter accepts exactly when all these weights exceed*d*=*⌈δN⌉−*1.

This scan does not materialize*G*. For a unit message, repetition and the first interleaver–weightor produce exactly*k*weighted events. Their sorted positions and prefix values determine the complete first-accumulator output. Streaming the second interleaver, weightor, and accumulator then computeswt(*gi*)in*O*(*N*) field operations and*O*(*k*)scratch space. The rows are independent and can be checked in parallel.

Algorithm 2:Exact setup-time weight-one rejection filter. Input: *N,q,k,δ* Output:A sampled RAA code description(*P₁,W₁,P₂,W₂*) 1*d←⌈δN⌉−*1; 2whiletruedo 3Sample independent(*P₁,W₁,P₂,W₂*)and fix the resulting code*G*; 4restart*←*false; 5foreach*i∈*[*n*]do 6Computewt(*gi*) = wt(RAA(*ei*))by the streaming scan; 7ifwt(*gi*)*≤d*then 8restart*←*trueand stop this scan 9if*¬*restartthen 10return(*P₁,W₁,P₂,W₂*) P*n* Let*ϵ₁* be a certified upper bound on*T*(1)and let*ϵ≥*2bound*w*=2*T*(*w*).

Theorem 7(Filtered setup bound).*Assumeϵ₁ <*1*and run Algorithm2.* *The expected number of sampled code descriptions is at most*(1*−ϵ₁*) *−*1 *, and the* *returned code satisfies* <u>ϵ</u> <u>≥2</u> Pr[dist(*C*)*< δN|*accepted]*≤.*(18) 1*−ϵ₁* *Proof.*Let*B₁* be the event that the sampled code has a bad weight-one message, and let*B≥*2be the corresponding event for a message of weight at least two. The scan accepts exactly on *B₁*, because every weight-one codeword is a nonzero multiple of one checked row. ThereforePr[accepted]*≥*1*−ϵ₁*, which also gives the expected resampling bound. Moreover,

Pr[*B≥*2*∩*accepted]*≤*Pr[*B≥*2]*≤ϵ≥*2*.*

Dividing by the acceptance probability proves Equation (18).*⊓⊔*

The complete scan costs*O*(*nN*) =*O*(*N²/k*)field operations and stores the *O*(*N*)-size code description, while row checks parallelize directly. At the baseline tuple, the ordinary-floating witnesses givelog₁₀ *ϵ₁ ≈−*11*.*0304andlog₁₀ *ϵ≥*2*≈* *−*21*.*0817, so the filtered candidate haslog₁₀ *ϵ*setup*≈−*21*.*0817. The exact scan of all2 18 unit messages completed in69*.*43seconds on the Apple M4 Pro used for our experiments. The scan itself is exact. The displayed probability becomes a verified numerical bound after the directed-rounding replay of the certificate.

5.6 Concrete Parameter Search Algorithm1evaluates one fixed tuple. The setup-timeRAA-ParamSelect algorithm enumerates candidate(*k,δ*)values and usesRAA-Certifyas a fea- sibility oracle. It separates the returned bound into*ϵ₁* and*ϵ≥*2. For a deployment policy*b*filter*∈{*0*,*1*}*, its setup bound is
( *ϵ₁* +*ϵ≥*2*, b*filter= 0*,* *ϵ* mode= (19) *ϵ* *≥*2*/*(1*−ϵ₁*)*, b*filter= 1*.*

The first line certifies a code sampled once without an exact scan. The second in- vokes Algorithm2and follows from Theorem7. The selector retains a tuple only when*ϵ*mode*≤ϵ*setup, and then chooses the IOPP query count*ℓ*and extension degree*e*according to the independent per-proof soundness bound

*ϵ* total*≤*(1*−δ/*3) *ℓ* +*N/q* *e*

*.*(20)
It returns the accepted tuple minimizing the specified deployment-cost function, which may account separately for the one-time*O*(*N²/k*)setup scan and the per- proof cost. Thus the result is optimal over the supplied candidate grids. Under the same failure budget, the filtered mode can therefore admit higher-rate tuples that the unfiltered mode rejects because of their weight-one contribution. The setup event and per-proof soundness remain separate budgets: the former is checked once when sampling the code, while the latter is enforced for every proof. Full selector pseudocode appears in AppendixE.3. Correctness follows from the interval enclosures. Interval choices and floating-point optimization affect running time and tightness, and failed verification causes refinement or FAIL.

## 6 Application: Blind PCS and End-to-End Blind SNARK

The Generalized RAA code (Section4) is the core algorithmic ingredient that un- locks the first blind PCS with strictly linear*O*(*N*)prover work at constant FHE multiplicative depth. Following the standard Ligero-style modular blueprint, our blind PCS is built on top of an*FHE-friendly IOPP*(Interactive Oracle Proof of Proximity) for the RAA code; composing this PCS with a depth-controlled Spartan PIOP for R1CS then yields the end-to-end blind SNARK we implement and evaluate. Our central technical contributions at this layer are (i) the IOPP itself and (ii) the depth-controlled sumcheck folding that preserves*O*(1)FHE depth across the PIOP at an*O*(log*N*)-factor cost inmult_plainwork.

*Section organization.*Section6.1constructs the FHE-friendly IOPP for Gen- eralized RAA codes; this is the core. Section6.2composes the IOPP with a depth-controlled Spartan PIOP to prove R1CS; its sumcheck is the source of the*O*(log*N*)factor in total work. Section6.3uses the IOPP as a black box to build the blind PCS for multilinear polynomial evaluation, the strictly-linear, constant-depth component. Section6.4presents an FHE-aware SIMD ciphertext repacking optimization. Section6.5compares the assembled SNARK against prior work asymptotically; concrete prover times are in Section7.

6.1 FHE-Friendly IOPP for the Generalized RAA Code The IOPP construction follows the Ligero proximity-test framework [3], instan- tiated with the Generalized RAA code as the underlying linear code and adapted to operate on FHE-encrypted matrix entries. We first state the interface that the PIOP and PCS will consume, then give the construction and analyze its FHE cost.

*Interface.*An IOPP for a linear code*C⊆*F*q* ˆ*n* is a protocol*⟨P,V⟩*with three operations:

*•*Commit(*{*[[*mi*]]*}* *r* *i*=1)*→*com: the prover encodes each input row[[*mi*]]with*C* and Merkle-commits the resulting encoded matrix. *•*LinComb(*γ*)*→*[[*u*]]: given a verifier-chosen vector*γ∈*F *r* *q* *e* and a uniformly sampled query set*I⊆*[ˆ*n*]Pof size*ℓ*, the prover returns the encrypted random linear combination[[*u*]] =*iγi*[[*mi*]]together with openings of the committed encoded matrix at the columns in*I*. *•*Verify: the verifier, holdingsk, verifies the Merkle openings, decrypts the opened columns and the response[[*u*]], then checks in plaintext (a) that each opened column is consistent with*u*at the corresponding output index, and

(b) that*u*is*δ*-close to a codeword by re-encoding it and comparing with the opened columns at the test positions.
The soundness error of any singleLinCombquery is(1*−δ/*3) *ℓ* +*N/q* *e*, where*δ* is the relative minimum distance of*C*,*ℓ*is the number of column openings, and *e*is the extension-field degree used by the Schwartz–Zippel check on the linear combination.

*Construction (with SIMD packing).*Algorithm3instantiates this interface with the Generalized RAA code. The input vector is arranged as an *√* *r×m*matrix (*r*= 2 *s* ,*rm*=*n*, with*r≈m≈ n*); each row is RAA-encoded to a length- ˆ*n*=*m/ρ*codeword, and the encoded matrix is Merkle-hashed column by column. To exploit BGV/BFV’s*B*= 2 13 –2 14 SIMD slots, we pack*B*consecutive matrix rows into the same column-aligned ciphertext: because RAA encoding is element- wise within each row (permutations and per-row weights are public; accumulator scans run along columns), the packing introduces no cross-row dependencies, and one ciphertext operation encodes*B*rows in parallel.

*Cost and soundness.*Commit costs *Bρ* <u>2n</u> pt-ct multiplications and the same order of ct-ct additions at depth1(the per-row weighter*W*ris the only non-linear step); LinComb is a depth-0pt-ct linear combination, and Verify runs in plaintext after the verifier decrypts. The encrypted-data portion of the proof is *√* *ℓ*column openings plus[[*u*]], i.e.*O*(*λ n*)encrypted field elements before the optimizations of Section6.4. Conditional on the selected code having relative distance*δ*, the soundness of a singleLinCombquery is(1*−δ/*3) *ℓ* +*N/q* *e*. For*λ*-bit security one sets*ℓ*=*⌈λ/*log₂(3*/*(3*−δ*))*⌉*and*e*=*⌈*(*λ*+ log₂ *n*)*/*log₂ *q⌉*; Table2gives the resulting(*ℓ* *∗* *,e* *∗* )at standard target levels for*δ*= 0*.*30. The IOPP parameters in the table control per-proof soundness. The one-time code-sampling risk is a separate budget: before deployment, Algorithm1must certify the selected(*N,q,k,δ*)tuple. If the rate-1*/*4candidate does not meet the chosen setup budget, Algorithm4selects a lower rate or returnsFAIL; this choice does not change the IOPP query count at a fixed*δ*.

|packed)|Algorithm 3:FHE-Friendly IOPP for Generalized RAA (SIMD-||
|---|---|---|
|Input:SIMD-packed rows holds the //Commit 1 {[[c]]} b,j j∈ [ˆ n] pt-ct ops per block */ 2 com ← MT. packed ciphertext */ 3; //LinComb (verifier 4 V samples I P 5 [[u]] ← b i∈ block //Verify 6 V and checks E|{[[m]]} wherem b,j b∈ [⌈r/B⌉] ,j∈ [m] B rows of column j in block b. ←E ([[m]] ,..., [[m]])for each block b C b, 1 b,m encode in parallel across the B SIMD slots; depth1, Commit {[[c]]} ;/*Merkle by column; one leaf per b,j r γ∈ F) e q uniformly among the size- ℓ subsets of[ˆ n]; γ · [[m]]; P opens columns j∈I i b,· b verifies the Merkle openings, decrypts[[u]]and the opened columns, P ? (u) = γ c slot-wise for j∈I C j b,j (b) b|B ∈ F b,j q ;/*RAA O (m) with Merkle proofs; in plaintext;|
|IOPP query count ℓ −λ 2|Table 2.IOPP parameters. For the rate-1 / 4code at δ = 0. 30, q = 2 ∗ ∗ and extension-field degree e achieving runtime soundness at each security level (per-proof soundness is independent of the code length; the one-time setup risk is treated separately in Section5.6). Only(ℓ,e ∗ ∗ ∗ ∗ ℓ e λ ℓ e log₂ (1 −δ/ 3) log₂ N/q log₂ ϵ total 80 527 7 − 80. 10 − 90. 00 − 80. 10 100 658 8 − 100. 02 − 106. 00 − 100. 02 128 843 10 − 128. 14 − 138. 00 − 128. 14|16 +1, the minimum ϵ ≤ total)scale with λ.|

6.2 Composing the PCS with a Depth-Controlled Spartan PIOP For a public R1CS instance(*A,B,C*)*∈*F
*n* *q ×n*and encrypted witness[[*z*]]*∈*F *n* *q*, we discharge*Az◦Bz*=*Cz*via Setty’s Spartan PIOP [26]: two sumchecks reduce R1CS to one multilinear evaluation˜(*z ry*) =*vz*, discharged by our blind PCS (Section6.3, with *f*˜:= ˜). We choose Spartan over a direct Hadamard-product *z* PIOP because the latter would require*n*ct-ct multiplications (one per Hadamard slot), whereas Spartan’s degree-3sumcheck spreads them geometrically across log*n*rounds for an aggregate*O*(*n*)ct-ct cost.

*Depth-controlled sumcheck folding.*Each sumcheck round picks a challenge*ri* and “folds” the working ciphertext array by setting[[*aj*]]*←*[[*a₂j*]] +*ri*[[*a₂j*+1]]*−* [[*a₂j*]]. Done in place acrosslog*n*rounds, this is*O*(*n*)mult_plainwork butlog*n* FHE multiplicative depth, since each round’smult_plainchains on the previous round’s already-folded ciphertexts, incompatible with our*O*(1)-depth target.

To preserve*O*(1)depth, we instead recompute, at each round*i*, the partial

(*i*)P
fold[[*aj*]] :=*b∈{*0*,*1*}i* eeq((*r₁,...,ri*)*,b*)*·*[[*a*(*j∥b*)]]from the*original*ciphertext array. Eachmult_plainnow acts on a depth-0ciphertext, contributing only one level regardless of*i*; per-round work rises to*O*(*n*)(totalling*O*(*n*log*n*)over log*n*rounds) in exchange. This is the explicit depth-versus-work trade: alog*n* factor in cheapermult_plainfor constant FHE depth. Per-step costs and the full protocol description appear in AppendixF.1; soundness is the standard Spartan analysis plus the PCS soundness,*ϵ*PIOP*≤*(1*−δ/*3) *ℓ* + 7*N/q* *e*.

*End-to-end FHE cost.*Combining matrix–vector products (*O*(*n*)pt-ct, depth

0), the two sumchecks (*O*(*n*)ct-ct plus*O*(*n*log*n*)mult_plain, depth*≤*2each), and the downstream PCS evaluation (*O*(*n*)pt-ct at depth1), the end-to-end SNARK prover performs*O*(*n*)ct-ct multiplications and*O*(*n*log*n*)total FHE operations at total FHE depth*O*(1).
6.3 Blind PCS for Multilinear Polynomial Evaluation For a*µ*-variate multilinear *f*˜with*N*= 2
*µ* encrypted coefficients arranged as an *r×m*matrix (*r*= 2 *s* ,*m*= 2 *µ−s* ,*s*=*⌈µ/*2*⌉*), we obtain a blind PCS by com- posing the IOPP with the standard Ligero-style tensor decomposition P N N *f* ˜(*z*) = *⟨q₂,i≥s*(1*−z*

|q₁ f˜ ⟩whereq₁ =|(1−z|,z )∈F|andq₂ =|,z )∈F|.|
|---|---|---|---|---|---|
|i ,i i|i<s|i i|r q|i i|m q|
||||i|||

Concretely the prover (i) runsIOPP.Commit(*{*[[*f*˜]]*}*)at commit time, then for evaluation at*z*, (ii) runsIOPP.LinComb(*γ*)on a verifier-random*γ*for proxim- ity testing and (iii) runs P IOPP.LinComb(*q₁*)on the tensor-structured*q₁* to ob- tain[[*f* *′′*]] =*iq₁,i*[[*f*˜*i*]], which the verifier decrypts and then outputs*y*=*⟨q₂,f* *′′* *⟩* in plaintext. Total cost: *O*(*N*)FHE operations at depth1, strictly linear, dom- inated by the IOPP commit phase; soundness*ϵ*PCS*≤*(1*−δ/*3) *ℓ* +*N/q* *e* (cf. Equation (20)). The security proof (completeness, binding, knowledge sound- ness) follows the Ligero/Brakedown framework and is deferred to AppendixB; the complete protocol is given as Algorithm6in AppendixF.3.

6.4 IOPP-Layer Optimization: Ciphertext Repacking The base IOPP of Algorithm3produces a proof of*ℓ*Merkle-opened columns plus the encrypted linear-combination response[[*u*]]. We compress the response with an FHE-aware repacking optimization that operates purely at the IOPP layer and therefore benefits the PIOP and the PCS uniformly. *Ciphertext repacking (Algorithm*
P *5, AppendixF.2).*TheLinCombresponse is the length-ˆ*n*vector[[*u*]] *∗* =*iγi*f*i*, but because data is SIMD-packed by column, each scalar*u* *∗* *j*initially lives alone in its own column ciphertext (using1of*B* slots), so[[*u*]] *∗* is spread overˆ*n*ciphertexts with the other*B−*1slots wasted. A two-step*rotate-and-sum*/*mask-and-add*procedure (Algorithm5) collapses each column to its scalar and then gathers allˆ*n*scalars into*⌈*ˆ*n/B⌉*packed ciphertexts, a single ciphertext whenˆ*n≤B*(true for all*N≤*2 25 at standard SIMD batch sizes) and anˆ*n*-fold reduction in transmitted ciphertexts. It costs ˆ*n*log₂ *B*rotations plus*O*(ˆ*n*)pt-ct mults at zero additional multiplicative depth.

Table 3.Asymptotic comparison of blind SNARK constructions (*n*= number of gates,

*N*= BFV/BGV SIMD slot count,*d*= circuit depth). “Ct-ct mults” counts the dom- inant FHE operation; “Total work” counts all FHE operations including the cheaper mult_plain. Measured prover-time / proof-size numbers appear in Section7.

|Scheme|Ct-ct mults Total work FHE Depth|Proof Size|IOP / IOPP Layer|
|---|---|---|---|
||1+1 /k 1+1|/k √||
|Phalanx[30]|O ( kn ) O ( kn|) k + O (1) O ( k n + kN|log n )RS-IOPP via 2D-NTT|
|Laminate[23]|O ( n ) O ( n log n|) O (1) O ( d log n|)GKR + sumcheck (no IOPP)|
|||√||
|Ours O|( n ) O ( n log n|) O (1) O ( λ n|)RAA-IOPP + Spartan PIOP|

6.5 End-to-End Blind SNARK and Comparison Combining the FHE PCS (Section6.3) with the depth-controlled Spartan PIOP (Section6.2), both built on the IOPP of Section6.1with the optimizations of Section6.4, yields the end-to-end blind SNARK. Table3compares it asymptot- ically against prior work. Our construction achieves linear*O*(*n*)ct-ct multiplications at constant FHE multiplicative depth, with an*O*(log*n*)overhead in total work coming from the depth-controlled Spartan sumcheck (Section6.2). The PCS layer alone (Section6.3) is strictly*O*(*n*)at*O*(1)depth, the first blind PCS to attain this Pareto point. At the SNARK level, our asymptotic profile matches Laminate(*O*(*n*log*n*)total work at*O*(1)depth), while supporting arbitrary R1CS rather than layered uniform circuits, and improving over
*√* Phalanx’s super-linear*O*(*n* 1+1*/k* )work at constant depth. Our*O*(*λ n*)proof is larger thanLaminate’s folding-based proof, the trade-off we accept in exchange for arbitrary-R1CS support at constant FHE depth.

*Why the SNARK-level*log*nfactor.*The PCS layer of our construction sidesteps any sum-check via Ligero-style proximity testing, and the Generalized RAA code provides the linear-time, constant-depth encoding that makes proximity testing efficient under FHE. The remaininglog*n*factor in the SNARK enters*only*at the PIOP layer, in Spartan’s sumcheck. In the FHE setting, a standard in-place sumcheck fold takes*O*(*n*)work but contributeslog*n*multiplicative depth (each round’smult_plainchains on the previous round’s already-folded ciphertexts); preserving*O*(1)depth via the recompute-from-scratch fold of Section6.2costs an extralog*n*factor inmult_plainwork. Whether a depth-controlled sumcheck can be made*strictly linear*under FHE (which would yield a fully linear blind SNARK on top of our PCS) is, to our knowledge, open.

## 7 Performance Evaluation

We report end-to-end prover time and proof size for the full blind SNARK pipeline: PIOP (Spartan) composed with the RAA-based PCS, all stages run over FHE ciphertexts. All measurements are taken on the same machine and BFV parameter set, namely an Apple M4 Pro (24GB RAM, single-thread) with Microsoft SEAL using BFV: ring degree*N*ring= 2 14, plaintext modulus

*q*= 2 16 + 1(Fermat prime),3RNS limbs ([30, 50, 50]bits). Per-proof soundness target is128-bit with*δ*= 0*.*30and code rate1*/k*= 1*/*4, giving IOPP query count*ℓ* *∗* = 843from the parameter-selection procedure of Section5.6.

*Scope of comparison.*NeitherPhalanx[30] norLaminate[23] has released source code at the time of writing, and by their own description both report*esti-* *mated*prover times rather than end-to-end measurements:Phalanx’s Table 3 is labelled “estimated performance” [30, §6], andLaminateprovides “an estimation of the runtime... using detailed operation counts and microbenchmarks” [23, §1.5]. The concurrentLasagne[31] likewise*projects*its scaling table by substi- tuting microbenchmarked per-operation constants into operation counts [31, §7], measuring only a single application end-to-end. Our comparison therefore takes the form: (i) we present*measured*single-thread prover times from thee2e-full benchmark binary in our codebase (to our knowledge the first end-to-end*mea-* *sured*blind-SNARK implementation at this scale, provided as supplementary material); (ii) we plot prior-work prover times as*paper-reported*(projected) an- chors and extrapolate via each scheme’s own asymptotic formula:Phalanx[30,

Table 3] reports2*.*27hr at*N*= 2

20 on Intel Xeon Silver 4310 (0*.*68hr exclud- ing witness packing, the apples-to-apples figure since our prover also assumes a pre-packed witness),Laminate[23, Table 20] reports (single-instance,*N*= 2 20, Google Cloud N4)13*.*9hr (base) /43*.*9hr (fold) /1*.*1hr (laned). 2 Our hardware is an Apple M4 Pro; an Apple Silicon core is typically1*.*5–2*×*faster than these baselines on single-thread SEAL workloads, so the headline factors we report below should be discounted accordingly.

*What the three schemes prove, and why direct comparison is subtle.*Phalanx proves*n*-wire R1CS in the regime where the payload computation uses a*single* SIMD slot per ciphertext (Phalanx’s prover-internal SIMD parallelism acceler- ates its Reed–Solomon encoding, but the R1CS itself is non-batched, see [23]). Laminateproves*layered*arithmetic circuits via a GKR-based BhIOP. Its fastest variant,Laminatelaned, additionally requires the payload to be*laned*: *B*disjoint instances of the same per-instance circuit, packed one per SIMD slot, with no rotation gates (so the batch is capped at the slot count*B*= 2 14, with “free batching” up to that cap); itsLaminatefoldvariant lifts the laned restriction to wide (rotation-bearing) layered circuits, but at substantially higher prover cost. Either way the payload must be a layered circuit. Our scheme proves*arbi-* *trary*R1CS via Spartan and an RAA-IOPP, with no layered structure required; SIMD slots carry distinct wire values of one R1CS instance, and the prover scales linearly in the total wire count. 2 We useLaminate’s May 2026 revision [23], which corrects a soundness issue in its transcript-packing compiler (a randomized well-formedness test adding*λ*cipher- texts); the fix increases the folded proof size from the0*.*27MB reported in earlier versions (and still cited by concurrent work) to13*.*45MB, and the figures above are the corrected Table 20 numbers. The*laned*variant attains its1*.*1hr only on*laned* payload circuits without rotation gates; the*fold*variant is the one supporting the wide/arbitrary circuits comparable to our R1CS.

7.1 End-to-End Prover Time: Total vs. Paper-Reported SOTA Figure2compares our measured total prover time against the paper-reported numbers forPhalanxand the two principalLaminatevariants, extrapolated to common*N*values via each paper’s own asymptotic formula. Concretely we measure1*.*46s,6*.*11s, and25*.*5s at*N*= 2
18 *,*2 20 *,*2 22 respectively; the per- doubling-of-*N*growth factor is*∼*4*.*2*×*, essentially linear in*N*: the*O*(log*N*) overhead from the depth-controlled sumcheck (Section6) is barely visible in this range, sincelog*N*only varies from18to22.

*Versus Phalanx.*At*N*= 2 20 R1CS wires,Phalanx’s reported2*.*27hr includes witness packing; its core prover excluding packing is0*.*68hr (2*,*448s), and since our measurement likewise assumes a pre-packed witness, the apples-to-apples comparison is0*.*68hr versus our6*.*11s, a*∼*400*×*speedup (modestly overstated by the hardware mismatch). The gap is structural:Phalanx’s Reed–Solomon encoding uses the low-depth 2D-NTT decomposition introduced by HELIOPO- LIS [4] and costs*O*(*N* 1+1*/k* ), whereas our RAA code encodes in linear time at constant FHE depth.

*Versus Laminate (per-instance cost depends on batch fill).*Laminatecomes in three variants [23, Table 20], of which onlyLaminatefoldsupports the wide (cross-slot, rotation-bearing) circuits comparable to arbitrary R1CS;Lami- natelanedis restricted to*laned*payload circuits with no rotation gates, and Laminatebasetrades a2*,*604MB proof for speed. SinceLaminateSIMD-packs up to*B*= 2 14 instances per proof, its per-instance cost spans a band, from the single-instance figure down to the full-batch amortized figure (total runtime*/B*); our cost is a flat6*.*11s at*n*= 2 20 regardless of batch, since we SIMD-pack one instance’s distinct wires. TakingLaminatefold, the apples-to-apples variant, its single-instance cost is43*.*9hr versus our6*.*11s, a*∼*26*,*000*×*per-instance speedup; even at a*full*2 14 batch of identically-structured circuits it amortizes only to*≈*9*.*7s/instance, still slower than our batch-independent6*.*11s. The one configuration that proves faster than us is the restrictedLaminatelaned at near-full batch (15*.*8 hr*/*2 14 *≈*3*.*5s/instance), which needs2 14 identical rotation-free laned circuits, exactly the batchable-uniform structure our scheme does not require; single-instance,Laminatelanedis1*.*1hr, i.e. we are*∼*650*×* faster. On proof size, at*n*= 2 20 our*∼*32MB is*∼*81*×*smaller thanLami- natebase(2*,*604MB) and only*∼*2*.*4*×*larger thanLaminatefold/Laminatelaned (*∼*13*.*4MB), a far narrower size gap than earlierLaminateversions reported (see the footnote above).

7.2 Per-Phase Breakdown of Our Prover Figure3shows where the time goes inside our prover. Across all three sizes, the Spartan PIOP dominates (*≥*94%of total prover time); the entire PCS pipeline sums to under0*.*9s even at*N*= 2
22 : RAA encoding (0*.*02–0*.*45s), Merkle commit (0*.*02–0*.*34s), LinComb (8–70ms), column openings (6–10ms), and

Fig.2.Per-instance prover time (log*y*-axis). EachLaminatevariant from the cor- rected Table 20 [23, Table 20] is drawn as a*band*spanning its per-instance cost from a single instance (upper edge) down to a full*B*= 2 14 batch amortized (lower edge): Laminatefold(red) supports wide/arbitrary circuits, whileLaminatelaned(teal) is the fastest but restricted to laned rotation-free circuits.Phalanx[30, Table 3] cannot SIMD-batch its R1CS, so it is a single-instance line (shown excluding witness pack- ing, apples-to-apples with our pre-packed-witness setting). Our per-instance cost (solid blue) is fixed regardless of batch, since we SIMD-pack one instance’s distinct wires; it sits orders below every single-instance edge (about26*,*000*×*belowLaminatefoldat *n*= 2 20 ), belowLaminatefold’s full-batch edge, and is undercut only byLaminatelaned at a full2 14 batch of identical rotation-free circuits. Prior-work numbers are extrapo- lated to other*N*via each paper’s stated asymptotic scaling.

repacking of*u* *∗* (33ms). The repack phase is essentially*N*-independent because the LinComb response*u* *∗* fits in a single SIMD-packed ciphertext (Section6.4); repacking1ciphertext costslog₂(*B/*2) + 1rotations regardless of*N*.

*What the breakdown says about the asymptotic claims.*The breakdown empiri- cally corroborates the asymptotic split (Section6): the PCS phases scale at most linearly with essentially flat per-wire cost, while the only super-linear component is the depth-controlled Spartan sumcheck, whose*O*(log*N*)factor inmult_plain work is the sole source of the end-to-end*O*(*N*log*N*)term (the ct-ct multiplica- tions remain*O*(*N*)).

*Counterfactual code cost.*The subsecond PCS contribution in Figure3depends on the linear-time, depth-1RAA encoding. Replacing it with the low-depth Reed–Solomon encoding used by Phalanx would require*O*(*kN* 1+1*/k* )homomor- phic operations at depth*k*+ 1. For every fixed*k*, this exceeds the*O*(*N*log*N*) Spartan cost asymptotically and therefore moves the bottleneck back to the PCS.

Fig.3.Per-phase prover-time breakdown of our prover (linear*y*-axis). Stacked bars are oure2e-fullmeasurements on Apple M4 Pro at*N∈ {*2 18 *,*2 20 *,*2 22 *}*; totals are annotated above each bar. The Spartan PIOP dominates uniformly across the range; all PCS phases together are under5%of total prover time.

Brakedown retains*O*(*N*)encoding operations, but its*O*(log*N*)multiplicative depth enlarges the ciphertext modulus, and hence the cost of each homomorphic operation, by the same asymptotic factor. Its effective ring-arithmetic cost is therefore*O*(*N*log*N*), of the same order as the PIOP rather than the negligible PCS fraction measured here.

7.3 Proof Size We do not include a proof-size figure because the comparison does not have a single clean axis of advantage. Concretely, our proof at*N*= 2
22 ,*λ*= 128,*ℓ* *∗* = 843is*∼*105MB (dominated by the843Merkle-opened codeword columns plus one packed-ciphertext LinComb response after SIMD repacking). At*N*= 2 *√* 20 it is*∼*32MB. For context,Phalanxreports58MB at*N*= 2 20 and an*O*( *N*) growth that reaches*∼*116MB at*N*= 2 22 [30, Table 3], essentially the same order as ours.Laminate[23, Table 20] reports, at*n*= 2 20 ,2*,*604MB (base),

13*.*45MB (fold), and13*.*33MB (laned); the two compact variants land within a factor of*∼*2*.*4of our proof (corrected May 2026 figures; see the comparison- scope footnote above). On the time–size frontier, then, our proof is*∼*81*×*smaller thanLam- inatebase(2*,*604MB) at*n*= 2
20 and only*∼*2*.*4*×*larger thanLami- natefold/Laminatelaned(*∼*13*.*4MB), while our single-instance prover is orders of magnitude faster (Section above). We do not claim a proof-size win; the chosen operating point is the trade-off we accept in exchange for arbitrary- R1CS support: a moderate proof and fast prover (linear in ct-ct multiplications, near-linear in total FHE work; see Section6), with no circuit-shape constraint.

7.4 Multiplicative Depth and Per-Operation Cost Holding the circuit at2
22 gates and*δ*= 0*.*30fixed, the only quantities that vary with the per-proof soundness target*λ*are the IOPP query count*ℓ* *∗* and extension-field degree*e* *∗* (Table2, Section6.1). The one-time code-sampling risk is independent of*λ*and must be checked for the chosen per-row code length by Algorithm1.

*Depth–cost.*Our scheme uses3RNS limbs (1 multiplicative level for the per-row weightor at depth0*.*5+ 1 level for the Spartan PIOP’s ct-ct multiplication + 1 base, totallinglog*Q≈*130bits). Brakedown’s expander codes require*O*(log*N*) levels, negating their linear encoding advantage under FHE; the Reed–Solomon 2D-NTT of HELIOPOLIS [4], as used by Phalanx, requires*k*+ 1levels at*k*- way decomposition. Per-ciphertext-op cost scales as *O*˜(*M*log*Q*) = *O*˜(*M·d*) (Section1), so a7*×*depth gap (Brakedown at*N*= 2 30 ) translates to a*∼*7*×* per-op cost penalty over our1*×*baseline.

## 8 Conclusion and Future Work

We established linear minimum distance with failure probability*o*(1*/N*)for Gen- eralized RAA codes over any fixed non-binary field, via the Pairwise-Product IOWE Bound (Lemma2), together with an efficient concrete failure-probability certifier and setup-time parameter-search procedure (Algorithm1). Combined with a Ligero-style proximity test this gives the first blind PCS with strictly lin- ear*O*(*N*)prover work at*O*(1)FHE depth; composing it with a depth-controlled Spartan PIOP for R1CS yields, to our knowledge, the first end-to-end*measured* blind SNARK implementation at this scale, with*O*(*N*)ct-ct multiplications and *O*(*N*log*N*)total FHE work at constant depth. Empirically (Section7) the prover scales near-linearly in*N*(*∼*4*.*2*×*per doubling), in clear contrast toPhalanx’s 1+1*/k*

|super-linearO(kN|)growth.|
|---|---|
|Limitations and future work.AtN= 2||
|Phalanx’s58MB proof and within∼2.4×ofLaminate’s compact∼13.4MB||
|variants. AtN= 2|, our proof is∼105MB, comparable toPhalanx’s∼|

20, our*∼*32MB proof is smaller than

116MB proof (Section7). Reducing this size while retaining constant FHE depth is a natural refinement. The concrete distance bound covers all intermediate and message weights without empirical tail extrapolation. Tightening its analytic up- per bounds, completing portable directed-rounding verification of the full-range calculation, and making the depth-controlled sumcheck strictly linear under FHE remain useful directions.

## References

1.Abbaszadeh, K., Hafezi, H., Katz, J., Meiklejohn, S.: Single-server private out- sourcing of zk-snarks. Cryptology ePrint Archive, Paper 2025/2113 (2025),https: //eprint.iacr.org/2025/2113

2.Akhiani, P., Zhang, Y.: Distance of RAA codes over large finite fields (with appli- cations in zksnarks and pcgs). Cryptology ePrint Archive, Paper 2026/524 (2026), [https://eprint.iacr.org/2026/524](https://eprint.iacr.org/2026/524)
3.Ames, S., Hazay, C., Ishai, Y., Venkitasubramaniam, M.: Ligero: Lightweight sublinear arguments without a trusted setup. Cryptology ePrint Archive, Paper 2022/1608 (2022).[https://doi.org/10.1145/3133956,https://eprint.iacr](https://doi.org/10.1145/3133956,https://eprint.iacr). org/2022/1608
4.Aranha, D.F., Costache, A., Guimarães, A., Soria-Vazquez, E.: Heliopolis: Veri- fiable computation over homomorphically encrypted data from interactive oracle proofs is practical. In: International Conference on the Theory and Application of Cryptology and Information Security. pp. 302–334. Springer (2024)
5.Arnon, G., Chiesa, A., Fenzi, G., Yogev, E.: Whir: Reed–solomon proximity testing with super-fast verification. In: Annual International Conference on the Theory and Applications of Cryptographic Techniques. pp. 214–243. Springer (2025)
6.Baweja, A., Fenzi, G., Mishra, P., Mopuri, T.: Field-agnostic SNARKs with small proofs via encode-repeat-accumulate (ERA) codes. Cryptology ePrint Archive, Pa- per 2026/864 (2026),[https://eprint.iacr.org/2026/864](https://eprint.iacr.org/2026/864)
7.Ben-Sasson, E., Bentov, I., Horesh, Y., Riabzev, M.: Fast reed-solomon interac- tive oracle proofs of proximity. In: 45th international colloquium on automata, languages, and programming (icalp 2018). pp. 14–1. Schloss Dagstuhl–Leibniz- Zentrum fuer Informatik (2018)
8.Block, A.R., Fang, Z., Katz, J., Thaler, J., Waldner, H., Zhang, Y.: Field-agnostic snarks from expand-accumulate codes. In: Annual International Cryptology Con- ference. pp. 276–307. Springer (2024)
9.Bois, A., Cascudo, I., Fiore, D., Kim, D.: Flexible and efficient verifiable computa- tion on encrypted data. In: IACR international conference on public-key cryptog- raphy. pp. 528–558. Springer (2021)
10.Brakerski, Z., Gentry, C., Vaikuntanathan, V.: (leveled) fully homomorphic encryp- tion without bootstrapping. ACM Transactions on Computation Theory (TOCT) 6(3), 1–36 (2014)
11.Brakerski, Z., Vaikuntanathan, V.: Efficient fully homomorphic encryption from (standard) lwe. SIAM Journal on computing43(2), 831–871 (2014)
12.Brehm, M., Chen, B., Fisch, B., Resch, N., Rothblum, R.D., Zeilberger, H.: Blaze: Fast snarks from interleaved raa codes. In: Annual International Conference on the Theory and Applications of Cryptographic Techniques. pp. 123–152. Springer (2025)
13.Divsalar, D., Jin, H., McEliece, R.: Coding theorems for turbo-like codes. In: Pro- ceedings of the 36th Annual Allerton Conference on Communication, Control, and Computing (1998)
14.Fiore, D., Gennaro, R., Pastro, V.: Efficiently verifiable computation on encrypted data. In: Proceedings of the 2014 ACM SIGSAC conference on computer and com- munications security. pp. 844–855 (2014)
15.Gama, M., Heydari Beni, E., Kang, J., Spiessens, J., Vercauteren, F.: Blind zk- snarks for private proof delegation and verifiable computation over encrypted data. Cryptology ePrint Archive (2024),[https://eprint.iacr.org/2024/1684](https://eprint.iacr.org/2024/1684)
16.Golovnev, A., Lee, J., Setty, S., Thaler, J., Wahby, R.S.: Brakedown: Linear-time and field-agnostic snarks for r1cs. In: Annual International Cryptology Conference. pp. 193–226. Springer (2023)
17.Graell i Amat, A., Rosnes, E.: On the minimum distance properties of weighted nonbinary repeat multiple-accumulate codes. In: Information Theory and Appli- cations Workshop (ITA) (2011)

18.Guo, Y., Liu, X., Huang, K., Qu, W., Tao, T., Zhang, J.:*{*DeepFold*}*: Efficient multilinear polynomial commitment from*{*Reed-Solomon*}*code and its applica- tion to zero-knowledge proofs. In: 34th USENIX Security Symposium (USENIX Security 25). pp. 3497–3516 (2025)
19.Gurkan, K., Novakovic, A., Rothblum, R.D.: Bolt: Faster SNARKs from sketched codes. Cryptology ePrint Archive, Paper 2026/310 (2026),[https://eprint.iacr](https://eprint.iacr). org/2026/310
20.Kim, Y., Cheun, K., Lim, H.: Performance of weighted nonbinary repeat- accumulate codes overGF(*q*)with*q*-ary orthogonal modulation. IEEE Transac- tions on Communications59(5), 1208–1212 (2011)
21.Kliewer, J., Zigangirov, K.S., Koller, C., Jr, D.J.C.: Coding theorems for repeat multiple accumulate codes (2008),[https://arxiv.org/abs/0810.3422](https://arxiv.org/abs/0810.3422)
22.Li, Z., Liu, H., Xing, C., Yao, Y., Yuan, C.: More efficient SNARKs via quasi- abelian codes: Faster, smaller, and field-agnostic. Cryptology ePrint Archive, Paper 2026/939 (2026)
23.Peshawaria, K., Liu, Z., Fisch, B., Tromer, E.: Laminate: Succinct simd-friendly verifiable fhe. Cryptology ePrint Archive (2025),[https://eprint.iacr.org/2025/](https://eprint.iacr.org/2025/) 2285, version 20260506:204946 (revised May 2026)
24.Qu, W., Guo, Y., Zhang, J.: Lightning, field-agnostic super-efficient polynomial commitment scheme. Cryptology ePrint Archive, Paper 2026/258 (2026),https: //eprint.iacr.org/2026/258
25.Rosnes, E., Graell i Amat, A.: On the analysis of weighted non-binary repeat multiple-accumulate codes. arXiv preprint arXiv:1101.5966 (2011)
26.Setty, S.: Spartan: Efficient and general-purpose zksnarks without trusted setup. In: Annual International Cryptology Conference. pp. 704–737. Springer (2020)
27.Xie, T., Zhang, Y., Song, D.: Orion: Zero knowledge proof with linear prover time. In: Annual International Cryptology Conference. pp. 299–328. Springer (2022)
28.Yang, K.: Weighted nonbinary repeat-accumulate codes. IEEE Transactions on Information Theory50(3), 527–531 (2004)
29.Zeilberger, H., Chen, B., Fisch, B.: Basefold: efficient field-agnostic polynomial commitment schemes from foldable codes. In: Annual International Cryptology Conference. pp. 138–169. Springer (2024)
30.Zhang, X., Wang, R., Liu, Z., Xiang, B., Deng, Y., Fisch, B., Lu, X.: Phalanx: An fhe-friendly snark for verifiable computation on encrypted data. In: Proceedings of the 2025 ACM SIGSAC Conference on Computer and Communications Security. pp. 4035–4048 (2025)
31.Zhang, X., Wang, R., Niu, Q., Liu, P., Lu, X., Zhao, L., Hou, R., Deng, Y.: Lasagne: Practical verifiable computation over encrypted data. Cryptology ePrint Archive (2026),[https://eprint.iacr.org/2026/857](https://eprint.iacr.org/2026/857), concurrent work
## A Numerical Illustration

This section illustrates two features of the analysis. First, it shows how the low- output probability*D*(*h*)and the normalized accumulator IOWE *A*e(*w,h*)vary with their input weights. These plots explain why the asymptotic proof uses different inequalities in its small- and large-weight branches. Second, it plots the per-weight union-bound contribution*T*(*w*)from Equation (6). The observed shapes guide the choice of weight intervals, but they are not assumptions in the proof.

Fig.4.Low-output probability*D*(*h*)at*q*= 2 16 + 1.*Left:* fixed*δ*= 0*.*25and varying *N∈{*2 14 *,*2 16 *,*2 17 *}*.*Right:* fixed*N*= 2 16 and varying*δ∈{*0*.*10*,*0*.*20*,*0*.*25*,*0*.*30*}*. The horizontal axis is*h/N*. The near-linear decline on the logarithmic scale illustrates the decay used in the large-weight analysis.

A.1 Why the Proof Splits at*w≈*0*.*01*N/k* *D*(*h*)*decays exponentially inh.*Figure4plotslog₁₀ *D*(*h*), where*D*(*h*)is the probability that a weight-*h*input to the second randomized accumulation pro- duces at most*δN*nonzero outputs. The curves are close to linear on a logarithmic scale. At fixed*δ*= 0*.*25, the slope becomes steeper as*N*grows. At fixed*N*= 2
16, it becomes steeper as*δ*decreases. This behavior is consistent with the exponen- tial estimate used in the large-weight proof. The formal asymptotic statement is Theorem3; Theorem5gives the explicit finite-parameter bound.

Fig.5.Conditional accumulator output-weight profiles at*N*= 2 14 and*q*= 2 16 + 1. *Left:* for*w∈{*4*,*16*,*64*,*256*}*, we plot*w* *−*1 log₁₀(*A*e(*w,h*)*/*max*u A*e(*w,u*))so that every small-weight curve remains visible. Zero denotes the peak of each normalized profile and is not a failure probability.*Right:* for*w∈{*0*.*01*N,*0*.*05*N,*0*.*10*N,*0*.*20*N}*, we plot the unnormalized quantitylog₁₀ *A*e(*w,h*). The panels illustrate why the proof uses direct combinatorial bounds for small inputs and entropy estimates for inputs of linear weight.

*The accumulator distribution has different useful descriptions.*Figure5plots the conditional probability *A*e(*w,h*)that a randomized weight-*w*input produces output weight*h*. The left panel rescales each small-*w*curve by its own maxi- mum and by*w*. This puts all four shapes on a readable common scale, including *w*= 4. The plotted quantity is a relative profile, not a distance-failure probabil- ity. In this regime, direct factorial bounds are more useful than Stirling approx- imations, which motivates Lemma2. The right panel keeps the unnormalized log-probability for input weights that are constant fractions of*N*, where entropy estimates are effective. The figure illustrates the two proof techniques but does not select the cutoff

0*.*01*N/k*. As explained in Section4.3,0*.*01is a convenient fixed constant that simultaneously supplies slack to the large-weight entropy argument and ensures *N/*(*N−kw*)*≤*100*/*99in the small-weight argument. Other sufficiently small constants would also work after changing the proof constants.
A.2 Empirical Shape of*T*(*w*)
*n w* P Figure6documents the empirical shape of*T*(*w*) = *w* (*q−*1)*hP₁*(*h|* *kw*)*D*(*h*). These profiles motivate the weight partition used in the finite com- putation, but they are not a correctness assumption: Theorem6bounds every message weight even if an untested parameter tuple has a non-monotone profile. Figure6reportslog₁₀ *T*(*w*)across the deployment regime*q*= 2 16 + 1,*k*= 4, *δ∈{*0*.*10*,*0*.*20*,*0*.*25*,*0*.*30*}*,*N∈{*2 18 *,*2 20 *,*2 22 *}*. In every slice,*T*(*w*)is monotone non-increasing, with the per-step ratio*T*(*w*+ 1)*/T*(*w*)shrinking as*w*grows. This decay is purely an empirical observation at the deployment scale; we do not claim it as a general theorem.

Fig.6.Monotonic decay of*T*(*w*).*Left:* fixed*δ*= 0*.*25, varying*N∈ {*2 18 *,*2 20 *,*2 22 *}*. *Right:* fixed*N*= 2 20, varying*δ∈{*0*.*10*,*0*.*20*,*0*.*25*,*0*.*30*}*. Both slices show strict mono- tonicity with geometric slope at deployment-scale*N*. All curves use*k*= 4,*q*= 2 16 + 1.

## B Blind PCS Security Properties

We instantiate the security model from Laminate’s BhIOP framework [23]. Throughout,*E*= (KeyGen*,*Enc*,*Dec*,*Eval)is an IND-CPA-secure leveled HE scheme,*H*:*{*0*,*1*}* *∗* *→{*0*,*1*}* *λ* is a hash function modelled as a random oracle, andMTdenotes a Merkle commitment scheme built from*H*in the standard way.

B.1 Security Model: Blind Indexed PCS *Indexed blind language for multilinear PCS.*Fix message spaceF*q*, message length*n*, codeword length*N*, and let*C*:F
*n* *q→*F *N* *q*denote the RAA encoder. A blind PCS for*µ*-variate multilinear polynomials is associated with the indexed blind language n *µ* o *E*[*L*PCS] = (params*,*sk); (ct[*f*˜]*, z, y*) : *E.*Decsk(ct[*f*˜]) = *f*˜*∈*F²*q, f*˜(*z*) =*y.*

The blind index is*i* *′* = ((params*,n,N,C*)*,*sk). Following Laminate’s Defini- tion 2.6, the verifier*V*holdssk(designated-verifier setting); the prover*P*holds only the evaluation keyevk.

*Public-coin BhIOP execution.*The PCS protocol of Section6.3is a3-message public-coin BhIOP*Π*: *P*’s commit messagecom=MT*.*Commit(ct[*c₁*]*,...,*ct[*cr*]), *V*’s challenge(*q₁,*idx₁*,...,*idx*ℓ,γ*)(column-opening indices and proximity-test coefficients), and*P*’s response (encrypted column openings and the linear- combination ciphertextct[*f* *′′*]). The Fiat–Shamir compilation derives challenges via*H*applied to the transcript so far. Throughout we work in the random- oracle model and treat the Merkle/Fiat–Shamir layer as binding except with

probabilitynegl(*λ*)(the standard preimage and collision events over*H*), as in the BhIOP framework [23]; we fold these into a singlenegl(*λ*)term and do not track hash constants explicitly.

*Extractor interface.*The knowledge extractor*E*knis granted three capabilities, matching the BhIOP designated-verifier setting: (E1) black-box access to a ma- licious prover*P* *∗* (with rewinding); (E2) oracle access to*H*via the standard ROM simulation (with query log*QH*); (E3) access to the secret-key decryption oracle*E.*Decsk(*·*). (E3) is the FHE analogue of "extractor sees the witness" in plaintext extraction: in the BhIOP model, the verifier’sskis the only thing dis- tinguishing the verifier from a public-coin observer, and granting it to*E*knis the canonical relaxation [23]. Without (E3) the extractor would have to break IND-CPA security to recover any plaintext, contradicting the FHE assumption.

B.2 Completeness and Binding Theorem 8(Completeness).*IfPandVfollow the PCS protocol of Sec-* *tion6.3honestly, then*Pr[*Vaccepts*] = 1*.*
P ˜ P ˜ *Proof.*RAA encoding isF*q*-linear, soEnc*C iγifi*=*iγi*Enc*C*(*fi*)at every column. Since BGV/BFV homomorphic addition and pt-ct multiplication im- plement the corresponding plaintext operations exactly (no decryption noise at depth*≤*1given the parameter choice), the column-consistency check passes at every opened column. The evaluation output*⟨q₂,f* *′′* *⟩*= *f*˜(*z*)follows from the multilinear-extension tensor identity.

Theorem 9(Computational Binding).*Condition on a successful setup (C* *attains relative minimum distance≥δ, except with the separately-budgeted one-* *time riskϵ*RAA*of Theorem2; Section5.6). Then no PPT adversary opens a* *commitment*com *∗* *to two distinct encrypted polynomials*ct[*f*˜]*̸*=ct[*f*˜ *′*]*except* *with probabilityϵ*bind*≤N/q* *e* +negl(*λ*)*.*

*Proof.*The Merkle commitment bindscom *∗* to a unique tuple of ciphertext rows except withnegl(*λ*)(AppendixB.1); since*E.*Decskis deterministic, these de- crypt to a unique tuple of plaintext rows(*c₁,...,cr*). Under the good-setup conditioning each row lies within the unique-decoding radius*δN/*2of at most one codeword of*C*, and the column-consistency check forces each opened row to equal that codeword except with probability*≤N/q* *e* (Schwartz–Zippel over F*qe*). The recovered polynomial is thus unique, contradicting *f*˜*̸*= *f*˜ *′*.

B.3 Knowledge Soundness in the BhIOP Setting Theorem 10(Knowledge Soundness).*Condition on a successful setup (C* *attains relative distance≥δ, except with the separately-budgeted one-time risk* *ϵ* RAA*of Theorem2; Section5.6). Then there exists an expected-PPT extractorE*kn *with the interface (E1)–(E3) of AppendixB.1, such that for every PPT prover*

*∗ P* *∗* *,H,E.*Decsk *P convincing the BhIOP verifier with probability≥ε,E* kn *outputs a* ˜ 2 *µ* ˜( *multilinear polynomial f∈*F*qsatisfying f z*) =*ywith probability at least*

*ε−ε*total*, ε*total= (1*−δ/*3) *ℓ* +*N/q* *e* +negl(*λ*)*.* | {z} {z}

|{z ||}|||
|---|---|---|
|IOPP soundness r||ROM/commitment|

*IOPP soundness Schwartz–Zippel ROM/commitment*

*Proof.*Executed over plaintexts, the protocol is exactly the Ligero/Brakedown PCS for the interleaved code*C*; the only FHE-specific features are that the committed objects are ciphertexts and that the response is SIMD-repacked. We dispatch both and inherit the rest.

*(1) Determinism reduces ciphertext-soundness to plaintext-soundness.*
*E.*Decskis a deterministic function, so the ciphertext layer gives a cheating prover no extra freedom: a commitment and its openings decrypt to a single fixed plaintext transcript, and the verifier’s column-consistency and evaluation checks read only those decryptions. Concretely, by Merkle binding (except negl(*λ*); AppendixB.1) the commitmentcom
*∗* fixes a unique tuple of ciphertext rows, which*E*knreads from the query log*QH*via (E1),(E2); decrypting them with (E3) yields a unique tuple of plaintext rows(*c₁,...,cr*)*∈*F *N* *q ×r*—exactly the rows the honest verifier decrypts in-protocol. The execution is therefore iden- tical to the plaintext interleaved-code PCS run on(*c₁,...,cr*), and soundness over ciphertexts reduces to soundness over those plaintexts.

*(2) SIMD repacking does not affect soundness.*The repacking optimization
(Section6.4, AppendixF.2) changes only the*transmission format*of theLinComb response: it deterministically gathers theˆ*n*per-column scalars*u* *∗* *j*into*⌈*ˆ*n/B⌉* packed ciphertexts by public slot rotations and masking, assigning each scalar to a distinct slot (a single ciphertext whenˆ*n≤B*), at zero added multiplicative depth. It touches neither the commitment nor the committed rows. This slot map is a public bijection, so the verifier recovers the same*u* *∗* by reading the designated slots before running its checks; the checked values—and hence both binding and knowledge soundness—are unchanged.

*(3) Inherited soundness.E*knruns the Ligero/Brakedown extractor on
the decrypted rows, and knowledge soundness is exactly that of the plaintext PCS [3,16]. With*ℓ*random column openings at proximity parameter*δ/*3(within *C*’s unique-decoding radius under the good-setup conditioning), that analysis returns *f*˜with *f*˜(*z*) =*y*except with probability(1*−δ/*3) *ℓ* +*N/q* *e* (testing soundness plus the Schwartz–Zippel evaluation check overF*qe*); the random- oracle/commitment layer contributesnegl(*λ*). HencePr[ExtractOK]*≥ε−ε*total, and*E*knruns in expected polynomial time (one transcript,*r*decryptions, and the plaintext extractor).

## C Per-Operation FHE Cost Derivation

The RAA encoding pipeline*ci*=*fiR*(*Pπ*1*W*r1*A*)(*Pπ*2*W*r2*A*)has the following per-row costs:

*•*Repeat & Permute: data movement only, zero FHE operations, 0 depth.

*•*Weight (*W*r1):ˆ*n*pt-ct multiplications, 0.5 depth (public weights). *•*Accumulate (*A*):ˆ*n−*1ct-ct additions, 0 depth (additions are noise- additive, not multiplicative, in BGV/BFV). *•*Second round: identical to the first:ˆ*n*pt-ct mults,ˆ*n−*1ct-ct adds, 0.5 depth.

Total per row:2ˆ*n*pt-ct mults,2ˆ*n−*2ct-ct adds, 1 level. With SIMD packing (*B*rows per ciphertext): 2 *Bρ* *N* pt-ct mults, 2 *Bρ* *N* *−* 2 *Br* ct-ct adds, 1 level.

## D Deferred Proofs from the Distance Analysis

This appendix contains the detailed proofs of the lemmas, theorem, and corol- laries used in Section4.3(the distance proof of Theorem2). The statements themselves remain in the main body; only the proofs are deferred here.

D.1 Proof of Theorem3(Exponential decay of*D*(*w*)) *Proof(Proof of Theorem3).*Fix the theorem’s threshold*η*and, within this proof, write*δ*:=*η*and*D*:=*Dη*. We alias*a*=*⌈*(*w−i*)*/*2*⌉*and*b*=*⌊*(*w−i*)*/*2*⌋*, so*a−b∈{*0*,*1*}*. First we analyze the dominant term in *A*˜(*w,h*)for*h∈*[*δN*]:

|w −1 h−1|N−h|h−a|a|i|
|---|---|---|---|---|
|a−1|b N|i|w||
|i=0|w||||
|w −1 h|N−h h−a||||
|a|bN|i|||
|i=0|w||||

X *A* ˜(*w,h*) = *·* <u>(q−1) (q−2)</u> (*q−*1)

X *≤* (21)

The parity gap*a−b≤*1changes the logarithm of each adjacent binomial coefficient, and of the denominator when its index is shifted by one, by at most *O*(log*N*). We therefore absorb an*N* *O*(1) factor and write*a*=*αN*,*h*=*βN*, and *i*=*θN*; then*w/N*= 2*α*+*θ*+*O*(1*/N*). Applying the standard entropy bounds for binomial coefficients gives, up to this polynomial factor:

*hH*(*α/β*)*βNN−hH*(*α/*(1*−β*))(1*−β*)*N* *≤e, ≤e,* *a b* *h−aH*(*θ/*(*β−α*))(*β−α*)*NN−O*(1) *H*(2*α*+*θ*)*N* *≤e, ≥N e.* *i w*

### Substituting into (21):

||O(1)||Φ(α,β,θ)N|
|---|---|---|---|
|||0≤i≤w−1||
|αβ|α||θ α|
|1− h|β||β−|
||O(1)|0≤i≤w−1 1≤h≤δN|Φ(α,β,θ)N|

*A* ˜(*w,h*)*≤wN ·*max *e*

where*Φ*= (1*−β*)*H*() +*βH*() + (*β−α*)*H*()*−H*(2*α*+*θ*). Since*D*(*w*)*≤δN·*max *A*˜(*w,h*), we have:

### D(w)≤wN max e

### Maximizing overβ.We compute:

<u>∂Φ (1−β−α)β</u> = log *∂β* (1*−β*)(*β−α−θ*)

When*β≤δ <* 2 <u>1</u>, the inequality(1*−β−α*)*β >*(1*−β*)(*β−α−θ*)holds, giving *∂Φ/∂β >*0. Hencemax*βΦ*=*Φ*(*α,δ,θ*). Maximizing over*θ*.Setting*∂Φ/∂θ*= 0yields*θ* *∗* = <u>2</u> 1+ <u>α(δ</u> *α* <u>−</u> *−* <u>α</u> *δ* <u>)</u>, giving:

max*Φ*=*δH*( *α* *δ* ) + (1*−δ*)*H*( 1*−* *αδ*

)*−*(1*−δ*+*α*)*H*(
1*−* 2 *δα*+*α* ) *θ* *α αδ αδ ∆* *≤δH*( *δ* ) + (1*−δ*)*H*( 1*−*

)*−*(1*−δ*)*H*(
12*−* ) =*Ψδ*(*α*)

### Monotonicity ofΨδ.

<u>dΨδ(5δ−1)(1−δ)−4δα</u> = log 1 + 2 *dα* (1*−δ−*2*α*)

When*δ <*0*.*2,*dΨδ/dα <*0for all*α*. Since2*α*+*θ≥*0*.*01and*θ* *∗* = <u>2</u> 1+ <u>α(δ</u> *α* <u>−</u> *−* <u>α</u> *δ* <u>)</u>, we get 1*−* 2 *δα*+*α* *≥*0*.*01, hence*α≥* 1199 *−δ*. Thusmax*Ψδ*=*Ψδ*( 1199 *−δ*

)*<*0when*δ <*0*.*2.
Conclusion.Put*ψη*:=*Ψη*((1*−η*)*/*199)*<*0. For*w≥*0*.*01*N*,

*Dη*(*w*)*≤wN* *O*(1) *e* *ψη N* *.*

Because*w≤N*and*ψη<*0, we have*ψηN≤ψηw*. Moreover, for every fixed *ϵ >*0, the condition*w≥*0*.*01*N*implies

log *wN* *O*(1) =*O*(log*N*)*≤ϵw*

### for all sufficiently largeN. Hence

*Dη*(*w*)*≤e* (*ψη* +*ϵ*)*w* *.*

Choose0*< ϵ <−ψη*and set*Λη*=*−ψη−ϵ >*0. The explicit constants in Remark1use the valid choice*ϵ*=*−ψη/*2, hence*Λη*=*−ψη/*2.

D.2 Proofs of Corollaries1and2 *Proof(Proof of Corollary1).*Put*η₀* := 0*.*01. Apply Theorem3at thresholds*η₀* and*δ*, obtaining positive constants*Λη*0and*Λδ*. Since*kw≥η₀N*, split the true first-accumulator distribution at*η₀N*: X *N*X X
*A* ˜(*kw,s*)*D* *δ*

(*s*)*≤ A*˜(*kw,s*) + *A*˜(*kw,s*)*e*
*−Λδs*

*s*=1 *s≤η₀N s>η₀N* *≤Dη*0(*kw*) +*e* *−η*0 *ΛδN*

*≤e* *−Λη*0*kw* +*e* *−η*0 *ΛδN*

*≤*2*e* *−µN* *,*

where *µ*:=*η₀* min*{Λη*0*,Λδ}>*0*.*

### The complete message-weight prefactor satisfies

*N/k* X *N/kwN/ku N/k* (*q−*1) *≤* (*q−*1) =*q.* *w* *u*=0 *u*

### Therefore the weight-wcontribution is at most

<u>logq</u> 2 exp *− µ− N.* *k*

Choose*K >* log(*q*)*/µ*. For any fixed*k > K*, the constant factor2can be absorbed by decreasing the positive exponent constant, giving the claimed*e* *−CN*

### bound for all sufficiently largeN.

For the explicit constants in Remark1, the same argument simplifies. Since *η₀ >*2*δ₀*, an accumulator whose input has weight*s > η₀N*cannot have output weight at most*δ₀N*: every nonzero output run accounts for at most two nonzero input symbols. Hence*Dδ*0(*s*) = 0on this branch. The inner sum in the proof of Corollary1is therefore at most*Dη*0(*kw*)*≤e* *−Λη*0*kw*, and the large-weight condition reduces to*k >*log(*q*)*/*(*η₀Λη*0), as recorded in Equation (1). The same support condition makes the*s≥η₀N*term in Corollary2identically zero.

*Proof(Proof of Corollary2).*Put*η₀* := 0*.*01. Theorem3at threshold*δ*gives X X *A* ˜(*kw,s*)*D* *δ*

(*s*)*≤e* *−η*0 *ΛδN*
*A* ˜(*kw,s*) *s≥η₀N s≥η₀N* *≤e* *−η*0 *ΛδN* *.*

Using the same uniform prefactor bound *N/k* *w* (*q−*1) *w* *≤q* *N/k*, the full contri- bution is at most <u>logq</u> exp *− η₀Λδ− N.* *k*

### ChoosingK >log(q)/(η₀Λδ)proves the claim.

D.3 Proof of Lemma2(Pairwise-Product IOWE Bound) *Proof(Proof of Lemma2).*Alias*a*=
<u>w</u> 2 <u>−i</u> and*b*= <u>w</u> 2 <u>−i</u>, so*a*+*b*=*w−i* and*a−b∈{*0*,*1*}*. Since*a*+*i≤*(*w*+*i*+ 1)*/*2*≤w*, the nonzero-element factor <u>(q−1)</u> *a* <u>(q−2)</u> *i* satisfies (*q−*1)*w* *≤*1.

|N N|N||||
|---|---|---|---|---|
|w w|w− −11 h−1 N−h a−1 b N w|h−a i|h−1 a−1|N−h h−a b i N−1 w−1|

Using *N* = <u>N</u> *N*, we get:

*≤* <u>w</u> *·.* *N*

Also,*w≤*0*.*01*N*implies <u>N 100</u> *≤ <*2*.* *N−w* 99 Case*a*=*b*+ 1:

*h−*1 *N−h h−*1 *N−h* <u>h</u> *b* <u>N</u> *b* = *≤* 2 *.*

||a−1|b|b b|(b!)|
|---|---|---|---|---|
|h− i a|i h−1 N−h a−1 b|N w− −11 h−a i|w−1|a+i−1|
||N||||
||w||||
||||b||

### With ≤h /i!and ≥(N−w) /(w−1)!:

*≤ w* *w−*1 *h* *N a−*1*,b,i N−w*

<u>N</u> *·* *N−w* *w a*+*i−*1 <u>w·6 h</u> *≤.*

||N|N−w||
|---|---|---|---|
|w−1|N b|b w||
|a−1,b,i|N−w|a−1|a|

Here we used *≤*3 *w−*1, *≤*2 *≤*2, and*a*+*i−*1 =*b*+*i*. Case*a*=*b*: *h−*1 *N−h h N* *≤.*

||a−1|a|(a−1)!a!|
|---|---|---|---|
|h− i a|i|N w− −11|w−1|
|h−1 N−h|h−a|||
|a−1 a N w|i|w|a+i−1|

### Again using ≤h /i!and ≥(N−w) /(w−1)!:

*a*+*i−*1 *a* *≤ w* *w−*1 *h N* *N a−*1*,a,i N−w N−w*

<u>w·6</u> *h* *≤.* *N N−w*

In both cases,*a*+*i−*1*≥* <u>w−</u> 2 <u>1</u>. Since*h≤N−w*, the base *N−* <u>h</u> *w* is at most 1, so lowering the exponent only enlarges the right-hand side. Summing over all *i∈{*0*,...,w−*1*}*yields

<u>w·6</u> *w* *h* *⌊*(*w−*1)*/*2*⌋* <u>w² h</u> *⌊*(*w−*1)*/*2*⌋* *A* ˜(*w,h*)*≤w·* = 6*w.* *N N−w N N−w*

For*D*(*w*), write*r*=*⌊*(*w−*1)*/*2*⌋*. Since*δ≤*0*.*30and*w≤*0*.*01*N*, every *h≤δN*also satisfies*h≤N−w*, so the previous bound applies throughout the

|P|R|||
|---|---|---|---|
|δN r|δN+1|r|(δNr+1)|
|h=1|1 w||+1 r+1|
||r|||
|2|||r|
||||w|

*r*+1 summation range. Using *h ≤ x dx*= :

<u>w² 6 (δN+ 1)</u> *D*(*w*)*≤ · ·* *N* (*N−w*) *r*+ 1 *w* <u>δN+ 1 δN+ 1</u> = *· · ·*6*.* *r*+ 1 *N N−w*

D.4 Proof of Lemma3 *Proof(Proof of Lemma3).*Put*η₀* = 0*.*01. To obtain the explicit choice in Remark1, set*δ*=*δ₀* = 0*.*99*/*(144e²)and assume*N≥*1*/δ₀*. Then(*δ₀N*+1)*/N≤* *δ* ¯:= 2*δ₀*. Define
r <u>δ</u> <u>¯</u> *−*1 *a₀* := 6 *<*e*.*

0*.*99
Lemma2, together with*⌊*(*s−*1)*/*2*⌋≥s/*2*−*1, gives for*s≤η₀N*

¯ <u>δ</u> <u>¯</u> *s s* *s/*2*−*1 *D*(*s*)*≤*2*sδ* 6 = 1*.*98*sa₀.*

0*.*99
The first accumulator has support only for*s≥ ⌈kw/*2*⌉*. Applying the same lemma to its IOWE gives

2 *kw/*2*−*1 ˜( <u>(kw) s</u>*kw s* *g*(*s*) := *A kw,s*)*D*(*s*)*≤* 6 *·*1*.*98*sa₀.* *N N−kw*

### Its logarithmic derivative is at most

<u>kw</u> + log*a₀ ≤*1 + log*a₀ <*0*.* 2*s*

Hence the largest summand is at the left support endpoint, and evaluating the decreasing upper bound at*kw/*2only enlarges it. Write*α*=*kw/N≤η₀* and r *√ α* *b*(*α*) := 6 *a₀, b₀* :=*b*(*η₀*)*<*1*.* 2(1*−α*)

Combining the preceding bound with *N/k* *w* *≤*(e*N/*(*kw*)) *w* and summing at most*η₀N*intermediate weights yields *w* *O*(1)<u>e(q−1)</u>*k* *p*(*w*)*≤N b*(*α*)*.* *α*

The same second-derivative calculation as in the unparameterized bound shows that its logarithm is convex for*k≥*9, so it suffices to check the two endpoints.

|q,k|−⌊(k−1)/2⌋|
|---|---|
||η₀N/k|
|O(1)|k|

At*w*= 1, the unsimplified bound is*O* (*N¹*) =*o*(*N* *−*2 )for*k≥*9. At *w*=*η₀N/k*, <u>e(q−1)</u> *p*(*η₀N/k*)*≤N b₀,* *η₀*

### which is exponentially small whenever

<u>log(e(q−1)/η₀)</u> *k >.* *−*log*b₀*

These are exactly the two small-weight conditions included in Equation (1).

D.5 Proof of Theorem4and Completion of Theorem2 *Proof(Proof of Theorem4).*Put*s₀* =*⌈*0*.*01*N⌉*and split the sum at*s₀*:
X ˜ *N* *N/kw* (*q−*1) *A*(*kw,s*)*D*(*s*) *w* *s*=1 *s*

|s −1||N||
|---|---|---|---|
|N/k|w|N/k|w|
|w||w||
|s=1||s=s₀||
|o(1/N²),Lemma3|−Ω(N)|e|,Corollary2|

X 0 *−*1 X *N* = (*q−*1) *A*˜(*kw,s*)*D*(*s*) + (*q−*1) *A*˜(*kw,s*)*D*(*s*)

| {z} | {z} *−Ω*(*N*)

### The total iso(1/N²) +e =o(1/N²).

*Proof(Proof of Theorem2(completion)).*Summing (3) over all*w*:

*N/k* X *N/k* X Pr[dist(*C*)*< δN*]*≤* Pr[*···|*wt(*x*) =*w*]*≤ o*(1*/N²*) =*o*(1*/N*)*.* *w*=1 *w*=1

The large-weight terms (*w≥*0*.*01*N/k*) are*e* *−Ω*(*N*) by Corollary1, and the small-weight terms (*w <*0*.*01*N/k*) are*o*(1*/N²*)by Theorem4.

## E Deferred Proofs for the Concrete Analysis

This appendix gives the counting details behind Theorem5, a complete proof of Theorem6, and the parameter-selection procedure.

E.1 Proofs for the Concrete Distance Bound *Proof(Detailed proof of Theorem5).*Fix the*h*support positions1*≤p₁ <···<* *ph≤N*of the accumulator input and define *g₀* =*p₁ −*1*, gi*=*pi*+1*−pi−*1 (1*≤i < h*)*, gh*=*N−ph.* The support is uniform, so(*g₀,...,g*

||)is a uniform weak composition of||N−h|
|---|---|---|---|
||h||r|
|h ℓ||r|ℓ=1 ℓ|

P into*h*+1parts. Let*ξ₁,...,ξ* be the nonzero input values and*S* = *ξ*. For *J⊆*[*h*], write*j*=*|J|*and consider the event*Sr*= 0for every*r∈J*. Ordering the indices in*J*partitions the*ξ* into*j*disjoint nonempty blocks whose sums must vanish. After fixing all but the final value in each block, at most one of the *q₀* possible final values satisfies its constraint. Thus

Pr[*Sr*= 0for all*r∈J*]*≤q₀* *−j*

*.*(22)
The accumulator output is zero on the initial gap of length*g₀*, and a zero return at*r*contributes the support coordinate*pr*together with the following gap of length*gr*. Ifwt(*Ax*)*≤d*, then for the actual zero-return set*J*, X *g₀* + *gr*+*j≥N−d.* *r∈J*

Equivalently, the*h−j*complementary gaps have total mass at most*d−h*+*j*. If *d−h*+*j <*0, this candidate contributes zero. Otherwise, for a fixed candidate *J*, condition on their total mass*y*. The selected*j*+ 1gaps have *N−hj−y*+*j*

weak compositions, which is at most *N−jh*+*j*. Summing the complementary compositions and using the hockey-stick identity gives

*d−* X *h*+*j* *y*+*h−j−*1 *d* =*.* *y*=0 *h−j−*1 *h−j*

The identity also holds at the endpoint*h*=*j*, under the usual empty-family convention. A union bound over the *h* *j* candidate return sets, followed by (22), yields X *h* <u>1</u> *h N−h*+*j d−j* *D*(*h*)*≤* *N* *q₀.*(23)

||j|j|
|---|---|---|
|h j=0|N−t h−t N h|h t N t|

*h j*=0 *h−j*

### Sett=h−jand use

=*.*

### Equation (23) becomes

min X *{h,d} h* 2 *d* *t t −*(*h−t*) *D*(*h*)*≤* *N* *q₀* =*U⋆*(*h*)*.* *t*=0 *t*

It remains to prove the contraction. Denote the*t*-th summand by

*h* 2 *d* *t t −*(*h−t*) *uh,t*:= *N* *q₀,* *t*

and set invalid summands to zero. Direct cancellation gives

|h+1,t||2|
|---|---|---|
|h,t||2|
|h+1,t|2||
|h,t−1 2|2||

<u>u</u> (*h*+ 1) =*,*(24) *u q₀*(*h*+ 1*−t*) <u>u (h+ 1) (d−t+ 1)</u> = (*t≥*1)*.*(25) *u t* (*N−t*+ 1)

Fix*x∈*(0*,*1)and put*c*= min*{d,⌊x*(*h*+ 1)*⌋}*. For*t≤c*, Equation (24) is at most1*/*[*q₀*(1*−x*)]. For*t≥c*+ 1, we have*t > x*(*h*+ 1)and

<u>d−t+ 1 d</u> *≤,* *N−t*+ 1 *N*

so Equation (25) is at most(*d/N*)*/x²*. Summing the first comparison over*t≤c* and the second over*t≥c*+ 1gives

1 <u>d/N</u> *U⋆*(*h*+ 1)*≤* 2 + 2 *U⋆*(*h*)*.* *q₀*(1*−x*) *x*

The parent*uh,c*may appear in both sums, which only loosens the upper bound. Minimization over*x*gives

<u>(d/N)</u> 1*/*3 *x⋆*= *−*1*/*3 *,* *q₀* + (*d/N*)1*/*3

*−*1*/*3 1*/*3 3 and substituting*x⋆*yields*ρ⋆*= (*q₀* + (*d/N*)).*⊓⊔*

*Proof(Detailed proof of Lemma6).*Let*v*= (1*,r*) *T*. From Equation (13),

*Ma*(*z*)*v≤λ*(*a,z,r*)*v*

### componentwise. Since1≤C(r)v, positivity ofMa(z)gives

*e* *T* 0*Ma*(*z*) *N* 1*≤C*(*r*)*e* *T* 0*Ma*(*z*) *N* *v≤C*(*r*)*λ*(*a,z,r*) *N* *e* *T* 0*v*=*C*(*r*)*λ*(*a,z,r*) *N* *.*

All coefficients of*e* *T* 0*Ma*(*z*) *N* 1are nonnegative, so

coeff*se* *T* 0*Ma*(*z*) *N* 1 *≤z* *−s* *e* *T* 0*Ma*(*z*) *N*

1*.*
Finally, because0*< a≤*1,1[*Hs≤R*]*≤a* *Hs−R*. Taking expectations and applying Lemma5proves Equation (14).*⊓⊔*

*Proof(Detailed proof of Theorem6).*For every interval*Bj*= [*Lj,Rj*]and every *h∈Bj*, Theorem5and*ρ⋆<*1imply

*D*(*h*)*≤U⋆*(*h*)*≤U⋆*(*Lj*)*.*

### Lemma4givesD(h) = 0outside[1,H⋆], whereH⋆= min{N,2d}. Therefore

X *H⋆* E[*D*(*Hkw*)] = Pr[*Hkw*=*h*]*D*(*h*) *h*=1 X *J* *≤ U⋆*(*Lj*) Pr[*Hkw∈*[*Lj,Rj*]] *j*=1 X *J* *≤ U⋆*(*Lj*) Pr[*Hkw≤Rj*]*.* *j*=1

Use Lemma6with*s*=*kw*and the parameters(*aw,j,zw,j,rw,j*)in the*j*-th sum- mand. Multiplication by *w* *n* *q₀* *w* proves Equation (15). Summing over the com- plete range1*≤w≤n*and applying Equation (7) proves the failure-probability claim. For completeness, if one parameter triple(*a,z,r*)is shared by every*w∈I*, its factors independent of P *w*can be pulled out of the sum. The remaining finite sum is exactly*w∈IΓw*(*z*)from Equation (17). Thus the batching step is an exact regrouping of the complete upper bound.*⊓⊔*

E.2 Computation and Interval Verification The computation uses interval partitions of the complete*w*- and*h*-ranges. For each distinct*h*-interval endpoint it evaluates*U⋆*(*L*)by a stable summand re- currence. For each pair of intervals it optimizes three positive scalars(*a,z,r*) and evaluates the corresponding finite*Γw*sum directly over all integer weights in the interval. A short set of small message weights may instead be evaluated with the exact accumulator IOWE; this improves tightness but is not needed for coverage. For the screening step, let*S₁* =*T*(1). Summing exact IOWE cells over any selected intermediate-weight subsets gives a lower bound*L₁ ≤S₁*, because ev- ery omitted cell is nonnegative. The exact first-accumulator prefix and the*U⋆* contraction give an upper bound*S₁ ≤U₁*. Directed rounding therefore pro- duces a verified bracket[*L₁,U₁*]. In the unfiltered mode, the lower endpoint can reject a tuple before the full calculation. In the filtered mode, the upper endpoint bounds the rejection probability and expected resampling overhead of
P*n* Algorithm2. Full-range certification separately bounds*w*=2*T*(*w*)and remains the acceptance test.

The ordinary floating-point pass only chooses the partitions and parameter triples. The verification data consist of these partitions and parameters, together with outward-rounded interval enclosures of every term in Equation (17). The verifier also checks that the exact weights together with the*w*-intervals partition [1*,n*], the*h*-intervals partition[1*,H⋆*]for*H⋆*= min*{N,*2*d}*, andsup*ρ⋆<*1. It returns the sum of the upper interval endpoints. Consequently, numerical overflow, optimizer failure, or an uncovered integer causes refinement orFAIL, never an unsupported numerical answer.

E.3 ParamSelect Algorithm Algorithm4usesRAA-Certifyas a feasibility oracle over candidate grids for (*k,δ*)and returns the accepted tuple minimizing the specified deployment-cost function. For each candidate it separates the certified setup bound into*ϵ₁* and *ϵ* *≥*2and applies Equation (19) according to the deployment’s filtering policy. Its optimality is therefore relative to the supplied grids and cost function. The proof-error budget is split as*ϵ*IOPP+*ϵ*SZ*≤ϵ*proof, avoiding any dependence between the one-time code-sampling event and per-proof soundness.

Algorithm 4:RAA-ParamSelect: setup-time parameter selection. Input:Codeword length*N*, field size*q*, candidate grids for*k*and*δ*; filtering policy*b*filter*∈{*0*,*1*}*; budgets*ϵ*setupand*ϵ*proof *∗ ∗ ∗ ∗* Output:A cost-minimizing accepted tuple(*k,δ,ℓ,e*), orFAIL 1Choose*ϵ*IOPP*,ϵ*SZ*>*0with*ϵ*IOPP+*ϵ*SZ*≤ϵ*proof; *∗* 2cost *←∞*; 3foreach*kin the candidate repetition grid*do 4foreach*δin the candidate distance grid*do 5(*ϵ₁,ϵ≥*2)*←*RAA-CertifyByWeight(*N,q,k,δ*); 6if*certification fails orϵ₁ ≥*1then 7continue; 8if*b*filter= 1then 9*ϵ*mode*←ϵ≥*2*/*(1*−ϵ₁*); 10else 11*ϵ*mode*←ϵ₁* +*ϵ≥*2; 12if*ϵ*mode*> ϵ*setupthen 13continue; 14*ℓ←⌈*ln(1*/ϵ*IOPP)*/*[*−*ln(1*−δ/*3)]*⌉*; 15*e←* log*q*(*N/ϵ*SZ); 16cost*←*DeploymentCost(*N,k,ℓ,e,b*filter); *∗* 17ifcost*<*cost then *∗ ∗ ∗ ∗ ∗* 18Update(*k,δ,ℓ,e,*cost); *∗* 19ifcost =*∞*then 20return*FAIL* *∗ ∗ ∗ ∗* 21return(*k,δ,ℓ,e*)

After parameter selection, the unfiltered mode samples one concrete code description directly. The filtered mode instead invokes Algorithm2and checks every weight-one message. All certified quantities in the selector, including*ϵ₁*, *ϵ≥*2, and*ϵ*mode, are evaluated with outward rounding.

## F Deferred Details: IOPP-Level Optimizations and FHE Costs

This appendix contains the deferred material from Sections6.1–6.4: detailed per-step FHE cost analyses (Sections6.2and6.3) and the full step-1/step-2 description of ciphertext repacking (Section6.4).

F.1 Per-Step FHE Cost Tables for the IOPP, PIOP, and PCS We tabulate the per-step FHE costs that underlie the asymptotic claims of Sec- tions6.1–6.5. Table4reports the per-row encoding cost of our RAA code against an RS code under the low-depth 2D-NTT trick introduced by HELIOPOLIS [4] and used byPhalanx.

Table 4.Per-row FHE encoding cost comparison (*m*= row length, rate*ρ*). This is
 the cost that the IOPP commit phase incurs.
Code Pt-Ct Mults Depth Scaling

RS (2D-NTT)*k*(*m/ρ*) 1+1*/k* *k O*(*m* 1+1*/k* ) RAA (ours)2*m/ρ*1*O*(*m*)

*PIOP per-step costs (expanded from Section6.2).*The Spartan PIOP for R1CS has three phases. (i) The encoded R1CS matrices*A,B,C*are public; comput-

|ingM =Az,M|=Bz,M|=Czin the encrypted setting costsO(n)pt-ct|
|---|---|---|
|a|b|c|
|x|b|c|

multiplications at depth0. (ii) The first sumcheck (degree3,log*n*rounds) over eeq(*r,x*)(*M*g*a*(*x*)*M*f (*x*)*− M*f (*x*)): per round, the sum-computation contributes ct-ct multiplications geometrically (round*i*does*n/*2 *i* ct-ct mults), summing to *O*(*n*)ct-ct mults total at depth*≤*2; the depth-controlled folding contributes *O*(*n*)mult_plainper round at depth1, summing to*O*(*n*log*n*)mult_plainto- tal. (iii) The second sumcheck (degree2,log*n*rounds) over˜(*z y*)*M*g*r* *x* *′* (*y*): the integrand has *M*g*r* *x* *′* as a plaintext multilinear polynomial (the verifier evalu- ates it on its own), so the per-round work is*O*(*n/*2 *i* )mult_plainfor the sum- computation plus*O*(*n*)mult_plainfor the depth-controlled folding, totalling *O*(*n*log*n*)mult_plainat depth1with no ct-ct multiplications. Total PIOP cost: *O*(*n*)ct-ct multiplications,*O*(*n*log*n*)mult_plain, FHE depth*O*(1).

*PCS per-step costs (expanded from Section6.3).*The commit phase invokes IOPP.Commit at cost*O*(*N*)pt-ct ops, depth1. The twoLinCombqueries (one for proximity, one for evaluation) are*O*(*N*)pt-ct ops each at depth0. Total: *O*(*N*)FHE operations at depth1, dominated by the IOPP’s commit phase, strictly linear with nolog*N*factor.

F.2 Ciphertext Repacking (Step 1 and Step 2) *The problem repacking solves.*The IOPP
P LinCombresponse is the length-ˆ*n*vec- *∗ ∗ ∗ ∗ B* tor*u* = (*u₁,...,u*ˆ*n*)with*uj*=*i*=1*γifi,j*, where*fi,j*is the encoded value of row*i*at column*j*. Because the data is SIMD-packed*by column*(column*j* occupies one ciphertext, with the*B*rows in its*B*slots), each scalar*u* *∗* *j*is initially produced inside its own column ciphertext as a cross-slot sum, so*u* *∗* is spread across*M*ciphertexts, each using1of its*B*slots and wasting the other*B−*1. Transmitting all*M*ciphertexts is hugely redundant (*∼*196MB at*N*= 2 21 ). *Repacking*(Algorithm5) gathers the*M*scalars into a single packed ciphertext (when*M≤B*, true for all*N≤*2 25 ), an*M*-fold reduction in transmitted ci- phertexts. Cost:2ˆ*n*pt-ct multiplications (the*γ*scaling and theˆ*n*masks)+ ˆ*n*log₂ *B*ro- tations+ ˆ*n−*1ct-ct additions, all at*zero additional multiplicative depth*(ro- tations and pt-ct multiplications consume no ct-ct level). Repacking consoli- dates the*u* *∗* response fromˆ*n*column ciphertexts down to1, so the proof is

Algorithm 5:Repack: consolidate theLinCombresponse*u* *∗* into one ciphertext Input:Column ciphertextsct*jj∈* [ˆ*n*], wherect*j*packs the*B*per-row values(*f₁,j,...,fB,j*)of encoded column*j*; row-combination coefficients*γ*= (*γ₁,...,γB*)as one plaintext; SIMD batch*B* (assume*M≤B*). Output:One packed ciphertextct *∗* holding(*u* *∗* 1 *,...,u* *∗* ˆ*n* ), *∗* P*B* *uj*=*i*=1*γifi,j*. //Step 1 (rotate-and-sum): collapse each column to its scalar*u* *∗* *j*, replicated across all*B*slots 1for*j*= 1*,...,*ˆ*n*do 2ct*j←γ·*ct*j*;/*slot-wise pt-ct mult; slot*i*now holds *γifi,j**/ 3for*t*= 0*,...,*log₂ *B−*1do 4ct*j←*ct*j*+Rot(ct*j,*2 *t* );/*rotate-and-add; after the loop every slot=*u* *∗* *j**/ //Step 2 (mask-and-add): copy each*u* *∗* *j*into distinct slot*j* of one output ciphertext 5ct *∗* *←*0; 6for*j*= 1*,...,*ˆ*n*do 7ct *∗* *←*ct *∗* +e*j·*ct*j*;/*e*j*= one-hot plaintext mask on slot *j*; isolates*u* *∗* *j*into slot*j**/ 8returnct *∗*;

(*ℓ*+ 1)*×*128KB*≈*105*.*5MB at*N*= 2 22 (*ℓ* *∗* = 843), versus(*ℓ*+ ˆ*n*)*×*128KB without repacking, a*∼*2*.*2*×*reduction; the repack step itself adds only*∼*33ms of prover time (measured, Section7).

F.3 Complete Blind PCS Protocol For completeness we spell out the full blind PCS for*µ*-variate multilinear eval- uation, assembling the components of Section6.3: the FHE-friendly IOPP con- struction of Algorithm3, the tensor decomposition of the evaluation, and the ciphertext repacking of Algorithm5. The scheme is designated-verifier: the ver- ifier*V*holds the FHE secret keysk, the prover*P*holds only the evaluation key. Completeness, binding, and knowledge soundness are proved in AppendixB. Commitcosts*O*(*N*)FHE operations at depth1and dominates;Evaladds two depth-0linear combinations,*ℓ*Merkle openings, and one repacking at no extra depth. The verifier performs no homomorphic arithmetic: it decrypts the*O*(*ℓ*) opened ciphertexts and the two responses, then encodes and checks entirely in plaintext. A singleEvalhas knowledge-soundness error*ϵ*PCS*≤*(1*−δ/*3)
*ℓ* +*N/q* *e*.

|Algorithm|6:Blind|PCS|for|µ|-variate|multilinear|evaluation,|
|---|---|---|---|---|---|---|---|
|designated-verifier||||˜(|||µ|
|Input:encrypted coefficients|r×m matrix with rows[[||{ [[|f ˜ f|x )]] } x∈{ i]]and r|0, 1 } µ, N = 2 ⌈µ/ 2 ⌉ = 2; rate-|, viewed as an ρ Generalized|
||RAA code|C of relative distance|||≥δ|, encoder|E C; evaluation|
||pointN z∈ F|µ q. With|s = ⌈µ/||2 ⌉, the tensors|||
||q₁ = i<s|(1 −z i ,z i|) ∈ F|r q, q₂|N =|(1 −z i ,z i≥s|m i ) ∈ F q give|
||˜( f z ) = ⟨q₂|P ˜, q₁ ,i f|i ⟩.|||||
|||i||||||
|//Setup||||||||
|1 Audit the chosen code parameters by Algorithm1; fix random oracle|||||||H,|
|query count|ℓ, extension degree|||e|;|||
|//Commit||||||||
|||˜||||||
|2 com ← each row, Merkle by column */ 3;|IOPP.Commit(|{ [[ f|i]] } i∈|[ r] );/*Algorithm3: RAA-encode||||
|//Eval at|z|||||||
||r|||||||
|4 V→P under Fiat–Shamir */ 5;|: γ∈ F q e and columns||I⊂|[ˆ|n], |I| = ′′|ℓ ;/*(|γ,I ) = H (com ,z )|
|6 P→V repacked by Algorithm5; column openings paths; 7 V verifies the Merkle paths, then decrypts ′′|:[[ u]] ← IOPP.LinComb( ′′|||γ );[[|f]] ←|IOPP.LinComb( { [[c ·,j]] } u← Dec sk|q₁ ), j∈I with Merkle ([[ u]]),|
|f ← below are in plaintext */ 8;|Dec sk ([[ f]]), and|c i,j P|← Dec||sk ([[c i,j ′′|]]), j∈I ;/*all checks P||
|9 V checks|E C ( u ) j =|γ i c i,j i ′′|and ˜(|E|C ( f )|j = q₁ ,i i|c i,j for all j∈I,|
|then outputs|y←⟨q₂|,f ⟩|as f|z );||||

## G Detailed Related Work Survey

This appendix expands the brief overview in Section2into a detailed technical comparison. We organize the literature into three threads: (i) distance analysis of accumulator-based codes (the analytical lineage our work belongs to), (ii) blind PCS and verifiable FHE (the application setting), and (iii) coding-based PCS more generally (the broader design space).

G.1 Distance Analysis of Accumulator-Based Codes The distance of accumulator-based codes over the binary field has been studied for over two decades [13,21,12]. Pfister et al. [21] established that*L*-fold accu- mulation with*L≥*2suffices for linear minimum distance overF₂; Blaze [12]

leveraged this to construct efficient interleaved-code-based SNARKs with linear- time provers. These analyses are tight forF₂ but do not transfer to non-binary fields, because their core combinatorial identities exploit binary-specific cancel- lations (e.g. XOR of two ones equals zero).

*Non-binary in then≫qregime.*Three threads have studied non-binary accu- mulator codes in the regime where the block length*n*greatly exceeds the field size*q*, but each falls short of a rigorous closed-form distance bound:

*•Code family introduction.*Yang [28] introduced weighted nonbinary repeat- accumulate codes and gave simulation-based evidence on the AWGN channel; no minimum-distance theorem is stated. *•Approximate IOWE for performance analysis.*Kim, Cheun, and Lim [20] de- rived an approximate input–output weight enumerator (IOWE) for the nonbi- nary accumulator and used it to compute approximate ML decoding thresh- olds; the bound is asymptotic and does not yield a concrete failure probability for finite*N*. *•Asymptotic distance with numerical verification.*Rosnes and Graell i Amat [25,17] give the first formal asymptotic distance theorem, proving ([25, Thm. 4]) that the symbol-wise minimum distance grows linearly with the block length*conditional on the strict positivity of a spectral-shape-* *function thresholdρ₀*. The verification of*ρ₀ >*0([25, Thm. 5]) is performed by*numerically solving a non-convex optimization over a high-dimensional* *simplex*, with the result reported only at the discrete set of field sizes *q∈{*3*}∪{*2 *l* : 2*≤l≤*25*}*. For*q >*2 25 positivity is asserted by graphical extrapolation (“from the figures we observe that the result will also hold for larger values of*q*” [25, §IV]). The framework provides neither closed-form *q*-dependence of*ρ₀*, nor a concrete failure probability for finite*N*, nor explicit constants applicable to a target(*N,q,k,δ*).

*Asymptotically large-field regime.*A separate line of work targets the regime*q*= *ω*(poly(*n*)), where the field size grows super-polynomially. Block et al. [8] gave the first rigorous large-field analysis for Expander–Accumulate codes. Akhiani and Zhang [2] later obtained failure probability *O*˜(*N* *−η* ) +*O*(1*/*(*q−*1))for RAA codes using generating functions. Their bound is tighter than ours when*q*grows super-polynomially. For fixed*q*, however, the*O*(1*/*(*q−*1))term remains. It arises from partitioning the IOWE sum and retaining the nonzero-symbol factor on only one part. This term prevents the bound from certifying the fixed plaintext modulus used by FHE.

*Quasi-Abelian codes (concurrent).*A very recent ePrint [22] introduces Quasi- Abelian (QA) codes over group ringsF*p*[Z *n* 2]and obtains a concrete-regime distance bound that approaches the Gilbert–Varshamov line with gap(1 + log*pN*)*/c*, where*c*is the inverse code rate. For*p*much larger than*N*(e.g. a128- bit prime with*N≤*2 40 ), the gap is small and they obtain very strong concrete distances (e.g.*δ≥*0*.*41at rate1*/*2). As the authors explicitly note, however,*“it*

*remains open whether QA code is asymptotically good for fixed indexcand field* *sizep, as our lower bound is meaningless when|G|*=*N→∞.”*Concretely, when *p*is the small FHE plaintext prime (*q*= 2 16 + 1in our setting), thelog*pN/c*gap is already1*.*25*/c*at*N*= 2 20 and grows without bound, so QA codes provide no usable distance guarantee in the FHE-plaintext regime that motivates our work. In addition, QA encoding uses an*O*(log*N*)-stage Walsh–Hadamard Transform, inheriting the same multiplicative-depth limitation as NTT-style transforms, so it does not resolve the complexity–depth dilemma.

*Our position.*The technical core of our proof, Lemma2, gives an elementary combinatorial upper bound on *A*˜(*w,h*). It avoids both the spectral-shape analysis of [25,17] and the partitioned generating-function analysis of [2]. The proof uses (*q−*1) *a* (*q−*2) *i* */*(*q−*1) *w* *≤*1uniformly over the complete IOWE sum and then bounds the remaining combinatorial terms directly. Consequently, it has no irreducible*O*(1*/*(*q−*1))term. The prior decomposition is tighter when*q* grows, while ours is tighter for fixed*q*. The latter is the deployment regime for blind PCS over BGV/BFV ciphertexts.

G.2 Blind PCS and Verifiable FHE The development of blind PCS is closely tied to the adaptation of interactive proofs to the FHE domain. Fiore et al. [14] and Bois et al. [9] studied verifiable computation over encrypted data, establishing the theoretical foundations. The concept of performing proximity testing over encrypted values can be traced to HELIOPOLIS [4], which provided the first study on applying the FRI (Reed– Solomon IOPP) protocol to FHE ciphertexts, though their security model is limited to freshly encrypted values. *Constant-depth full SNARKs.*Building on the low-depth 2D-NTT evaluation of Reed–Solomon encoding introduced by HELIOPOLIS [4],Phalanx[30] pro- posed the first constant-depth full SNARK for the VCoED setting. However, both its prover time and proof size scale super-linearly as the circuit grows: the prover incurs*O*(*kN*
1+1*/k* )FHE operations.

*Linear-prover blind PCS withO*(log*n*)*depth.*Laminate[23] addresses the proof-size explosion by adapting the GKR protocol and incorporating folding- based techniques like blind BaseFold, achieving*O*(*N*log*N*)prover, but its outer PCS still incurs*O*(*N*log*N*)FHE operations and inherits*O*(log*N*)multiplica- tive depth from the underlying FFT.

*Concurrent application of RAA codes in the plaintext domain.*A parallel line of work by Akhiani et al. [1] applies non-binary RAA codes in the*plaintext*domain for outsourced SNARKs. Our work targets the*encrypted*(blind) setting, which additionally requires constant multiplicative depth and SIMD-compatible oper- ations, and integrates the code into a full PCS with constant-depth ciphertext repacking.

*Our position.*No prior blind PCS simultaneously achieves*O*(1)FHE multiplica- tive depth and*O*(*N*)prover work. Our PCS is the first to resolve the “complexity- depth dilemma” at the PCS layer (identified explicitly by [23]), by replacing the underlying code with the Generalized RAA structure analyzed in this paper. At the SNARK level, our composition with a depth-controlled Spartan PIOP retains*O*(*N*)ct-ct multiplications and*O*(1)FHE depth, with an additional *O*(log*N*)factor in total work arising from the depth-controlled sumcheck fold- ing (Section6.2), asymptotically matchingLaminate’s*O*(*N*log*N*)total work at constant depth, while supporting arbitrary R1CS rather than layered uniform circuits.

G.3 Coding-Based PCS We categorize coding-based PCS into three families based on the underlying code. *Reed–Solomon (RS) based*constructions (FRI [7], BaseFold [29], Ligero [3], DeepFold [18], WHIR [5]) exploit the optimal distance of RS codes but inher- ently require*O*(*n*log*n*)encoding via NTT. In the blind setting, the logarithmic multiplicative depth of NTTs (or the complexity explosion of constant-depth grouped NTTs) poses a significant bottleneck. *Linear-time encodable*constructions such as Brakedown [16] and Orion [27] replace RS codes with expander-based codes, achieving*O*(*n*)prover time and *O*(log² *n*)proof size. While asymptotically optimal in the plaintext domain, their internal algebraic structures involve complex bit-level operations or high-depth circuits, making them impractical for FHE. *Accumulator-based*constructions (Blaze [12], EA codes [8]) leverage prefix- sum operations for*O*(1)depth encoding, but existing work is limited to binary fields (Blaze) or requires super-linear encoding (EA,*O*(*n*log*n*)). Our Generalized RAA code is the first to simultaneously achieve*O*(*n*)encoding,*O*(1)depth, and non-binary field support. Table1(in Section2) provides a comparative summary.
