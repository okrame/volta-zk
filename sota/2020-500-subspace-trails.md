IACR Transactions on Symmetric Cryptology ISSN 2519-173X, Vol. 0, No. 0, pp. 0–0.DOI:10.46586/tosc.v0.i0.0-0

# Proving Resistance Against Infinitely Long Subspace Trails: How to Choose the Linear Layer

### Lorenzo Grassi¹, Christian Rechberger² and Markus Schofnegger²

1 Digital Security Group, Radboud University, Nijmegen 2 IAIK, Graz University of Technology, Austria

l.grassi@cs.ru.nl,firstname.lastname@iaik.tugraz.at
**Abstract.** Designing cryptographic permutations and block ciphers using a substitution- permutation network (SPN) approach where the nonlinear part does not cover the entire state has recently gained attention due to favorable implementation character- istics in various scenarios. For word-oriented partial SPN (P-SPN) schemes with a fixed linear layer, our goal is to better understand how the details of the linear layer affect the security of the construction. In this paper, we derive conditions that allow us to either set up or prevent attacks based on infinitely long truncated differentials with probability 1. Our analysis is rather broad compared to earlier independent work on this problem since we consider *(1)* both invariant and non-invariant/iterative trails, and *(2)* trails with and without active S-boxes. For these cases, we provide rigorous sufficient and necessary conditions for the matrix that defines the linear layer to prevent the analyzed attacks. On the practical side, we present a tool that can determine whether a given linear layer is vulnerable based on these results. Furthermore, we propose a sufficient condition for the linear layer that, if satisfied, ensures that no infinitely long truncated differential exists. This condition is related to the degree and the irreducibility of the minimal polynomial of the matrix that defines the linear layer. Besides P-SPN schemes, our observations may also have a crucial impact on the Hades design strategy, which mixes rounds with full S-box layers and rounds with partial S-box layers. **Keywords:** Partial SPN · Linear Layer · Subspace Trails · Hades Schemes

## 1 Introduction

Modern cryptography developed many techniques that go well beyond solving traditional confidentiality and authenticity problems in two-party communications. This includes practical applications of secure multi-party computation (MPC), (fully) homomorphic encryption (FHE), and zero-knowledge (ZK) proofs using symmetric primitives. Designs of primitives in symmetric cryptography for these applications are usually led by heuristics such as simplifying their arithmetic representations or linear operations being more efficient than nonlinear ones in these scenarios. The latter example is also used in the context of masking, a widespread countermeasure against side-channel attacks in which all the computations are performed on shared secrets. Driven by all these application areas, many new symmetric primitives have recently been proposed. They include on one hand masking-friendly designs like NOEKEON [DPAR00], PICARO [PRC12], Zorro [GGNPS13], LS-designs [GLSV14], and candidates from the currently ongoing effort of choosing a next “lightweight” generation of primitives for e.g. au- thenticated encryption [BCDM20, DEMS19]. On the other hand, there is an increasing num-

Licensed underCreative Commons License CC-BY 4.0.

<u>Lorenzo Grassi, Christian Rechberger and Markus Schofnegger</u>

|||+|
|---|---|---|
|+|+|+|
|+|+ +|+|

ber of MPC-/FHE-/ZK-friendly proposals, including LowMC [ARS 15], FLIP [MJSC16], Kreyvium [CCF 18], Rasta [DEG 18], and Dasta [HL20], MiMC [AGR 16, GRR + 16b], GMiMC [AGP 19], HadesMiMC [GLR 20b], Ciminion [DGGK19], Jarvis and Fri- day [AD18], *Vision* and *Rescue* [AAB 20], and Poseidon [GKR 21].

### 1.1 Choosing the Linear Layer in Partial SPN Schemes

Some of the recalled designs (e.g., LowMC, Zorro, HadesMiMC and Poseidon) reach the goal of minimizing the total number of multiplications by making use of rounds with a partial S-box layer. These designs are called partial substitution-permutation network (P-SPN) schemes. They are a variant of SPN schemes, in which an input block is transformed into an output block by applying several alternating *rounds* of substitution boxes and affine permutations to provide confusion and diffusion. For a *t*-word SPN scheme over a fixed finite field, the substitution layer usually consists of *t* parallel (independent) nonlinear functions, called S-boxes. In many cases, the permutation layer is a linear operation defined by the multiplication of the state with a *t × t* matrix. In the case of a partial substitution-permutation network (P-SPN), however, part of the substitution layer is replaced by an identity mapping, leading to practical advantages for applications in which nonlinear operations are more expensive than linear operations. This approach was proposed and applied to AES with Zorro in [GGNPS13]: reducing the number of S-boxes per round from 16 to only 4 (to compensate, the number of rounds has been increased to 24). A similar approach has then been considered in LowMC [ARS + 15]. LowMC is a family of block ciphers that combines an incomplete S-box layer with a strong linear layer to provide security and be competitive in applications like MPC, FHE, or ZK. Many strategies proposed in the literature to guarantee security for SPN schemes are no longer applicable to P-SPN schemes and have to be replaced by more ad-hoc approaches. This includes the well-known *wide trail strategy* [DR02], which is one of the main techniques for achieving security against various statistical attacks, as the differential [BS91, BS93] and linear [Mat93] ones. Instead of choosing larger S-boxes with strong properties, the wide trail strategy aims to design the linear round transformations so that the minimum number of active S-boxes over multiple rounds is increased. This strategy is directly applicable in the case in which the nonlinear layer is (almost) full. In the case in which the nonlinear layer covers less than half of the state, a dedicated strategy is instead required and tools such as mixed integer linear programming (MILP) or SAT solvers can be used in order to find a good estimation of the minimum number of active S-boxes over multiple rounds. 1

In the case of Zorro, the heuristic argument proposed by the designers turned out to be insufficient, as iterative differential and linear characteristics were later found and used to break the full construction [WWGY14, BDD + 15]. Similarly, the authors of LowMC chose the number of rounds to guarantee that no differential or linear characteristic can cover the entire function with non-negligible probability. However, they do not provide similarly strong security arguments against other attack vectors, including algebraic attacks, and key-recovery attacks on LowMC have thus been found [DLMW15]. A crucial difference between Zorro and LowMC regards the fact that Zorro uses the same linear layer in all rounds, whereas LowMC uses different pseudo-randomly generated linear layers for each round. Both these two strategies have their advantages and disad- vantages. For example, even if the second strategy may provide security against statistical attacks (as discussed in [ARS + 15]), it has some drawbacks. First, the computation time or memory may become a problem, even when considering the optimizations proposed in [KPP + 17, DKP + 19]. Secondly, the security analysis against other attacks may become harder, since the linear layer is different in each round. Further, a poor (but valid with

1 For completeness, we mention that these tools are actually often used/required also in the case in which the nonlinear layer is full.

<u>Proving Resistance Against Infinitely Long Subspace Trails</u>

respect to the specification) choice of the linear layers can significantly reduce the security, as shown concretely in [DLMW15]. Finally, the possibility to have different matrices at every round can be exploited in order to insert a backdoor, as recently shown in [PW20] in the case of a tweakable version of LowMC.

### 1.2 Our Contribution and Related Work

Automated characteristic search tools and dedicated key-recovery algorithms for SP + networks with partial nonlinear layers have been presented in [BDD 15], where the authors propose generic techniques for differential and linear cryptanalysis. As a main result, this tool can be used to understand how many rounds a *given* scheme requires to be secure. However, focusing on the matrix that defines the fixed linear layer in a P-SPN scheme like Zorro, it is not clear which properties this matrix must satisfy to prevent cryptanalytic attacks in general.

**Our Goal.** While we cannot hope to tackle this question in its generality, we aim at a relevant subset of undesirable properties that can lead to attacks: infinitely long truncated differentials with probability 1 [Knu94], or equivalently *infinitely long subspace trails* *tq* [GRR16a, GRR17], i.e., the existence of a nontrivial subspace *U ⊆* F of inputs (where *n n* *q* = 2 or *q* = *p* for a prime *p ≥* 3 and *n ∈* N) that is mapped into a proper (affine) subspace of the state space over any number of rounds.

**Impact of Subspace Trails on Hades-Like Schemes.** While such a subspace trail on its own represents a distinguisher (i.e., its existence can be exploited to distinguish the analyzed P-SPN scheme from a pseudo-random permutation), it can also be the starting point for an attack. As a concrete example, a preimage attack on the hash function + Poseidon based on the existence of such trails has recently been shown in [BCD 20, + Sect. 6.2]. The attacked hash function is based on the Hades design strategy [GLR 20b], which uses external rounds with full S-box layers and middle rounds with partial S-box layers. The linear layer is defined as the multiplication with a fixed MDS matrix, where no other properties were originally required on such a matrix. Thus, in the case of a “weak” MDS matrix (i.e., a matrix that does not satisfy the properties proposed in this work), an attacker can potentially choose an input space of texts for which no S-box is activated in the rounds with partial S-box layers. This weakness was exploited for the particular + + matrices used in [GKR 19, GKR 21], where attacks on the corresponding hash functions + have been found [BCD 20,KR21].

#### Infinitely Long Subspace Trails: Necessary & Sufficient Conditions for P-SPN Schemes.

We present sufficient and necessary conditions that the matrix defining the linear layer must satisfy to guarantee that no infinitely long (nontrivial) subspace trails exist. Specifically, we analyze

*(1)* the case *without* active S-boxes in which the input of the S-box is constant, or equivalently, the input difference is equal to zero (see Section3and Section4), and
*(2)* the case *with* active S-boxes in which the input of the S-box can take any possible value (see Section6).
In both cases, we work independently of the round keys and round constants, and we show how to construct an infinitely long subspace trail if it exists. We note that the first case is independent of the details of the S-box. In the second case, we distinguish between S-boxes with nontrivial linear structures and S-boxes without them. If the S-boxes do not have any nontrivial linear structures (which is often the case), the only possible infinitely long subspace trails with/without active S-boxes are the ones studied in this paper.

In the particular case in which the matrix is diagonalizable, the infinitely long subspace trail (if existent) is always related to the eigenspaces of the matrix. This is not surprising since the relation between the eigenvalues and eigenvectors of the linear layer matrix and the existence of an infinitely long (invariant) subspace trail is already known in the literature. Such a relation was e.g. pointed out in [AÅBL12], and later on generalized in [Bey18]. In more detail, the results in [AÅBL12] were found by analyzing the invariant subspace trails of PRINTcipher (which was presented one year before in [LAAZ11]), while the result in [Bey18] was found as a generalization and improvement of the nonlinear invariant subspace attack on Midori-64 [TLS16]. However, all these results focus only on SPN schemes and invariant subspaces. Consequently, this analysis heavily depends on the effect of the key (namely, the invariant subspace only holds in the case of weak keys) and, in general, on the details of the S-box, which is not the case here. For example, if the subkeys are defined as the sum of the master key and a round constant, the existence of such an invariant subspace can be prevented by carefully choosing the round constants, as shown in [BCLR17]. More generally, the infinitely long subspace trails (if existent) are always related to the invariant subspaces of the matrix *M* defining the linear layer, namely the subspaces *X* that remain invariant when applying the matrix multiplication: *M ·X* = *X*. These subspaces can be found via the *primary decomposition theorem*, which allows splitting the full space F *tq* into a direct sum of invariant and independent subspaces for *M*. This is possible by computing the Frobenius normal form of the matrix (as recalled in Section2). Besides nontrivial infinitely long invariant subspace trails, our analysis also covers iterative subspace trails. A subspace trail is invariant if it is related to the invariant subspaces of *M*, and not invariant if it is related to the invariant subspaces of *M* *l* for *l ≥* 2 (where *M* *l* *6*= *µ · M* for each *µ ∈* F*q*). In the last case, we call the subspace trail iterative. In both cases, examples are provided to present and support the results. To summarize, both in the case with active and without active S-boxes, we present rigorous *necessary and sufficient conditions which guarantee that no infinitely long (invari-* *ant or iterative) subspace trail exists*. As a final result, we can present a *sufficient* (but in general not necessary) condition for the linear layer that – if satisfied – ensures that no infinitely long truncated differential exists. This condition is related to the degree and the irreducibility of the minimal polynomial of the matrix that defines the linear layer.

**Dedicated Tool.** Together with our theoretical observations, we also provide practical Sage implementations based on our results. Given a square matrix, the tool can detect the vulnerabilities described in this paper (invariant and iterative trails), both in the case with and without active S-boxes and for binary and prime fields. We make our implementation available online. 2

The tool is split into three different algorithms to cover all our results. The vulnerability of a single matrix can be evaluated quickly. To better understand the number of vulnerable matrices for given dimensions and field sizes, we applied our tool to large sets of pseudo- randomly sampled matrices. These tests show that the number of vulnerable matrices is in general small (and slightly larger than 10% only in a few particular cases). Details about the tool and the results are given in Section5and Section7.

## 2 Preliminaries

**Notation.** We denote the finite fields we are working with by F*q*, where *q* = 2 *n* or *q* = *p* *n* for a prime *p ≥* 3 and *n ∈* N. For brevity, and where there is no difference regarding the results, we abuse the notation F instead of F*q*. We denote subspaces with

2 [https://extgit.iaik.tugraz.at/krypto/linear-layer-tool](https://extgit.iaik.tugraz.at/krypto/linear-layer-tool)

calligraphic letters (e.g., *S*). Further, we use the superscript notation together with parentheses to differentiate subspaces with similar properties (e.g., *S*

(*i*) ). Given a subspace
*S ⊆* F *t*, we denote by *S* *c* *⊆* F *t* a complementary subspace such that *S⊕S* *c* = F *t*. We recall that two cosets *S* + *a* and *S* + *b* are equal if and only if *a − b ∈S ⊆* F *t*. We use the symbol *⊕* together with two spaces to denote the direct sum of two spaces. Given *v,w ∈* F *t t*

|, the span 〈v,w〉⊆ F||is always defined with respect to the space F, that is,||||
|---|---|---|---|---|---|
||||t|tq|i|
||t|||||
||||i,j|||
|t||||||

*〈v,w〉* = *{α · v* +*β · w | α,β ∈* F*}*. We denote by *{e₁,...,e}* the unit vectors of F *tq* (i.e., *e* has a single 1 in the *i*-th word). Matrices are denoted by non-calligraphic letters. The entry of a vector *x ∈* F is denoted by *x*[*i*] for *i ∈{*1*,...,t}*, while the entry of a matrix *M* in the *j*-th column of the *i*-th row is denoted by *M*. Given an arbitrary subspace *X ⊆* F and a matrix *M*, let *M ·X* := *{M · x | x ∈X}*.

### 2.1 Partial SPN Schemes

In this paper, we will focus on P-SPN block ciphers and permutations over (F *tq* *,* +*, ·*). 3

All our results are independent of the round keys and constants. For this reason, in the following we do not clearly distinguish between block ciphers and unkeyed permutations, and we just refer to them using the term *schemes*.

**Partial SPN (P-SPN) Schemes.** We denote the application of *r* rounds of a *t*-word P- SPN scheme by *E* *r t t*

|||: F → F|. For every input x = (x₁,...,x||) ∈ F|, the output is defined||
|---|---|---|---|---|---|---|---|
|r (i)|r||(0)|i t|t||i|
|||||||4||
|i|||||s s s+1||t t|

*t* *t*

by *E* *r*

(*x*) = (*R ◦···◦ R₁*) (*x* + *c*
(0) ), where *R* : F
*t* *→* F *t* is defined as *R* (*x*) = *R*(*x*) + *c*

(*i*)
and *c* is a publicly known round constant or a secret round key for *i ∈{*0*,...,r}*. Let 1 *≤ s < dt/*2*e* be the number of S-boxes per round. We denote by *R* the composition of the S-box layer and of the linear layer, i.e., we have *R* : F *→* F *t* with

*R*(*x*) = (*M ◦ S*)(*x*) = *M* (*S₁*(*x₁*)*,...,S* (*x*)*,x,...,x*)*,* (1)

where *S* : F *→* F for *i ∈{*1*,...,s}* is a nonlinear permutation, and hence *t − s* input words are unaffected by the S-box layer, which is the only difference to classical SPN schemes. We also assume that the *s* S-boxes are applied to the first *s* words (note that given any P-SPN scheme with the S-boxes in fixed positions, it is always possible to find an equivalent representation such that the S-boxes are applied to the first *s* words). The linear layer *M* (*·*) is defined by the multiplication with an invertible matrix *M ∈* F *t×t*, that is, *M* (*x*) = *M · x*. In the following, we assume that the matrix *M* ensures *full diffusion* *after a finite number of rounds*, in the sense that there exists an *r ∈* N such that every word of the internal state after the application of *r* rounds depends on every input word *x₁,...,xt*. For example, the smallest integer *r* that satisfies the previous condition for an MDS matrix is 1, for the linear layer in AES it is 2, while it does not exist for a diagonal matrix. We refer to [BJK + 16a, BJK + 16b, App. D] for a more detailed analysis about this concept. Before going on, we point out that all word-wise (aligned) P-SPN schemes can be written in the above way.

**Hades-Like Schemes.** The recently proposed Hades strategy [GLR + 20b] combines both SPN and partial SPN schemes. In particular, the initial *Rf*and the final *Rf*rounds contain full S-box layers, for a total of *RF*= 2*Rf*rounds with full S-box layers. However, in the middle of the construction, *RP*rounds with partial S-box layers are used. 3 In the case in which *q* = 2*n*, the field corresponds to (F*t n, ⊕, ·*), where *⊕* corresponds to the XOR 2 operation. In order to avoid confusion between the XOR sum and the direct sum, we use the symbol *⊕* to denote the direct sum only, and we use the symbol + to denote the sum of two elements in F*q*. 4 Note that if *s ≥dt/*2*e*, then at least one S-box is active every two rounds in the case in which the linear layer is instantiated with an MDS matrix (namely, a matrix with maximum branch number).

### 2.2 Invariant Subspaces and Subspace Trails

**Subspace Trails.** Subspace trails were first defined in [GRR16a], and they are strictly related to truncated differential attacks, as shown in [LTW18].

**Definition 1** (*Subspace Trail*)**.** Let (*U₁,..., Ur*+1) denote a collection of *r* + 1 nontrivial subspaces with dim(*Ui i*+1 *i* *t*

||) ≤ dim(U|) < t. If for each i ∈{1,...,r} and for each a||∈ F|
|---|---|---|---|---|
||i|i+1||i t|
|i+1 r+1|ic+1|i i|i i+1||

there exists *a ∈U* such that

*R* (*U* + *a*) *⊆U* + *ai*+1*,*

then (*U₁,..., U*) is a *subspace trail* of length *r* for the function *F* (*·*) = *Rr◦···◦ R₁*(*·*). If the relations hold with equality, the subspace trail is called a *constant-dimensional* *subspace trail*.

In the entire paper, we sometimes refer to a subspace trail (*U₁,..., Ur*+1) as a subspace trail “generated” by *U₁*. Before going on, we mention that the link between truncated differential trails and subspace trails is recalled in AppendixA.

**Invariant Subspace Trails.** We use the term “invariant subspace trail” for referring to a subspace trail in which the subspace is invariant (that is, *Ui*= *Uj*for each *i,j* = 1*,...,r*).

**Definition 2** (*Invariant Subspace Trail*)**.** Let *U⊂* F *t* be a subspace. *U* generates an *r*- round invariant subspace trail for the function *F* (*·*) = *R ◦···◦R₁*(*·*) if for each *i ∈{*1*,...,r}*

|||r|
|---|---|---|
|i+1|ic+1||
|i|i|i+1|

and for each *ai∈* F *t* there exists *a ∈U* such that

*R* (*U* + *a*) = *U* + *a.*

We point out that this is not the original definition introduced in [LAAZ11] and reconsidered

e.g. in [LMR15]. In these cases, the authors consider SPN schemes, and the existence

|of an invariant subspace is related to the existence of weak keys. In particular, given a||(|)||
|---|---|---|---|---|
|||(0)|(r)||
||t||||
|(k)||||r t|
|(k)|i|i (i)|i+1||
 weak key *k* (with *k* = *k,...,k*, where *k*
(*j*) is the *j*-th round key), a (nontrivial)
subspace *I⊂* F generates an invariant subspace trail of length *r* for the round function
*R* (*·*) = *R*(*·*) + *k* if for each *i ∈ {*1*,...,r}* there exist *a₀,a₁,...,a ∈* F such that

(*i*)
*R* (*I* + *a*) = *R*(*I* + *a*) +*k* = *I* + *a* for each *i ∈{*0*,*1*,...,r −*1*}*. In our case, this restriction is not mandatory anymore, and we are free to work independently of the value of the secret key.

**Iterative (Constant-Dimensional) Subspace Trails.** We now introduce the concept of infinitely long iterative (constant-dimensional) subspace trails.

**Definition 3** (*Iterative Subspace Trail*)**.** Let (*V₁, V₂,..., Vl*) be a constant-dimensional subspace trail for *l* rounds with dim(*Vi*) *< t*. We call this subspace trail an *infinitely long* *iterative (constant-dimensional) subspace trail of period l* for the considered scheme if it repeats itself an arbitrary number of times, i.e., if

(*V₁, V₂,..., Vl, V₁, V₂,..., Vl,..., V₁, V₂,..., Vl*)

#### is a subspace trail.

Clearly, an invariant subspace trail is also an iterative subspace trail for the case of P-SPN schemes (under the previous assumptions), while not every iterative subspace trail is also an invariant subspace trail. At the same time, the following result holds.

**Proposition 1.** *Working over* F *t* *, let* (*V₁,..., Vl*) *be an infinitely long iterative subspace*
*trail of period l. If* dim(*〈V₁,..., Vl〉*) *< t, then 〈V₁,..., Vl〉 generates an infinitely long*
*invariant subspace trail.*

*Proof.* The subspace *〈V₁,..., Vl〉* is invariant since each coset of *Vi*is mapped into a coset of *Vi*+1(where each coset of *Vl*is mapped into a coset of *V₁*).

To the best of our knowledge, no example of infinitely long iterative constant-dimensional subspace trails for SPN schemes is given in the literature. However, a poor choice of the linear layer allows to find them for the case of P-SPN schemes.

### 2.3 Decomposition Theorem & Frobenius Normal Form

In this section, we recall several notions from linear algebra useful for presenting our results, starting with the concept of eigenvalues and eigenspaces.

||t×t||d t|
|---|---|---|---|
|i i||||
|t×t|t t|−1|t|

**Definition 4.** Given an invertible matrix *M ∈* F, the subspace *P* = *〈ρ₁,...,ρ 〉⊆* F (with *P6*= *{*0*}*) is the (right) eigenspace of *M* for the eigenvalue *λ ∈* F*\{*0*}* if the condition *M · ρ* = *λ · ρ* is satisfied *∀i ∈{*1*,...,d}*.

**Definition 5.** *M ∈* F *t×t* is a diagonalizable matrix if and only if there exists an (invertible)
matrix *P ∈* F and there exist *λ₁,...,λ ∈* F such that *P ·M ·P* = *D* = diag(*λ₁,...,λ*)
is a diagonal matrix.

**Definition 6.** A field F is *algebraically closed* if every nonconstant polynomial in F[*x*] has a root in F.

**Definition 7.** Let *M ∈* F *t×t* be an invertible matrix. The characteristic polynomial *ψ ∈* F[*x*] is defined as *ψ*(*x*) = det(*x · I − M*). The minimal polynomial *φ ∈* F[*x*] is the monic polynomial of minimal degree such that

*t T t t*

*(1) φ*(*M*) *· v* = 0 = (0*,*0*,...,*0) *∈* F for each *v ∈* F, and
*(2)* for each polynomial *p ∈* F[*x*] that is annihilating (in the sense that *p*(*M*) *· v* = 0
*t* for each *v ∈* F *t* ), *φ* divides *p*.

**Proposition 2** ([Kai08, Theorem 1])**.** *Let M ∈* F *t×t* *be an invertible matrix with the* *minimal polynomial φ. There exists (at least) one vector v ∈* F *t* *such that*

*v,M · v,M² · v,...,M* deg(*φ*)*−*1 *· v*

#### are linearly independent.

By definition, det(*M*) = (*−*1) *t* *· ψ*(0). Moreover,

*(1)* the minimal polynomial divides the characteristic polynomial (which implies that deg(*φ*) *≤* deg(*ψ*) = *t*), and
*(2)* an eigenvalue of the matrix is a root of both the minimal and of the characteristic polynomial, and vice-versa (i.e., each root is an eigenvalue).
**Definition 8.** Let *M ∈* F *t×t* be an invertible matrix and let *V⊆* F *t* be a subspace. *V* is said to be *M -invariant* if and only if *M ·V* = *V*.

**Definition 9.** Let *M ∈* F *t×t* be an invertible matrix and let *V⊆* F *t* be a subspace.

- *V* is said to be *directly indecomposable* if there are *no* nontrivial subspaces *V₁, V₂ ⊆V* such that *V* = *V₁ ⊕V₂*.
- *V* is said to be *cyclic* if *∃v ∈V* such that *V* = *〈v,M · v,M² · v,...,M*
*l* *· v,... 〉≡〈v〉M*.

As is well-known, not all matrices are diagonalizable. When working over a field F, there always exists an invertible matrix *Q ∈* F *t×t* such that *F* := *Q* *−*1 *· M · Q* is in the *Frobenius normal form*. The Frobenius normal form can be exploited to easily compute the characteristic and the minimal polynomial of a given matrix. It can also be used to split the full space F *t* into independent subspaces that are invariant through the matrix *M*.

**Definition 10.** Let *M ∈* F *t×t*. The Frobenius normal form of *M* is the matrix *F ∈* F *t×t*

for which there exists an invertible matrix *Q ∈* F *t×t* such that   *C₀* 0*.. .* 0 0  0 *C₁.. .* 0 0  *−*1 
...... 
 *F* = *Q×M ×Q* = diag(*C₁,C₂,...,Cl*) =   ...   0

0*... C* 0  *l−*1
0 0*.. .* 0 *Cl*

for 1 *≤ l ≤ t*, where *Ci∈* F *t* *i* *×ti* is the (invertible) companion matrix   0 0*.. .* 0 *−c₀,i* 1 0*.. .* 0 *−c₁,i*  

1*.. .* 0 *−c*
 *Ci*=  0 2*,i*  
......
...  0 0*.. .* 1 *−cti −*1*,i* *t* *i* ∑*t −* *i* 1 *j* associated to the monic polynomial *pi*(*x*) = *x* +*j*=0*cj,i· x* such that

*(1)* for each 1 *≤ i ≤ l −* 1 the polynomial *pi*divides the polynomial *pi*+1, and
∏*l*

*(2) pl*corresponds to the minimal polynomial *φ* of *M* and *ψ*(*x*) =*i*=0*pi*(*x*) is the characteristic polynomial of *M*.

||||i|t||C||
|---|---|---|---|---|---|---|---|
|t×t|t|i i t|i ,i α|i t −2 ,i|t −1 t −1,i α|i t −1 t|t|
|||||m||||
|i|i|j|||||t|
|||t||||||
|||||m||||
 Note that given a companion matrix *C* over F*i*, we have that *〈e₁〉i*generates the
full subspace F*i*, since *p* (*e₁*) = *e₂,p* (*e₂*) = *e₃,...,p* (*ei*) = *ei,p* (*ei*) = *ei*are linearly independent, while *p* (*ei*) = *−c₀ · e₁ − c₁ · e₂* + *···− ci· ei.*

**Theorem 1** (Primary Decomposition Theorem [Hog16, Sect. 6.4] - [Kai08, Theorem 3])**.** *Let M ∈* F *be an invertible matrix. Let φ ∈* F[*x*] *be its minimal polynomial such that*

*φ*(*x*) = [*p₁*(*x*)] 1 *·* [*p₂*(*x*)] *α*2 *·····* [*p* (*x*)] *m* *,*

*where α ≥* 1 *and p* (*·*)*,p* (*·*) *are monic, irreducible, and relatively prime. The subspace* F *can be rewritten as a direct sum decomposition*

F = *A₁ ⊕A₂ ⊕···⊕A,* (2)

*where for each j ∈{*1*,...,m}*  ∣ 

|||∣∣|||
|---|---|---|---|---|
||α|t α|||
|j|j|j|||
||||≡0||
|||t×t|||
|i|||||
|||i|i|α i|

 *A* := ker([*p* (*M*)] *j* ) := *x ∈* F ∣∣ [*p* (*M*)] *j* *· x* = 0 <u>|| 0 ||···||</u> 0*,*  ∣ ︸ ︷︷ ︸ *t*

*(where* ker(*X*) *is the kernel of the matrix X ∈* F*) such that*

*1. A are M -invariant for each i, and*
*i*

*2.the minimal polynomial of a linear operator M induced on A by M is* (*p* (*·*))*.* We emphasize that the previous decomposition does not imply that there are no
nontrivial subspaces of *Ai*that are *M*-invariant. For example, consider a 3 *×* 3 matrix *M* = diag(1*,*1*,*2). In such a case the minimal polynomial is *φ*(*x*) = (*x −* 1) *·* (*x −* 2), and F³ = *A₁ ⊕A₂*, where *A₁* = *〈e₁,e₂〉* and *A₂* = *〈e₃〉*. At the same time, while *A₂* is “irreducible”, it is easy to find subspaces of *A₁* that are invariant through *M*, namely all subspaces of dimension one of the form *A* *′* 1= *〈α · e₁* + *β · e₂〉* for *α,β ∈* F.

## Infinitely Long Invariant Subspace Trails for P-SPN Schemes (Without Active S-Boxes)

Focusing on P-SPN schemes which use the same linear layer in each round (e.g., Zorro [GGNPS13]), here we study the properties that the matrix that defines the linear layer must satisfy in order to prevent infinitely long invariant subspace trails without active S-boxes.

### 3.1 Preliminary Results

Due to the fact that the nonlinear layer is only partial in P-SPN schemes, parts of the state go through the S-box layer unchanged. In particular, if the nonlinear layer consists of *s ≥* 1 S-boxes (applied to the first *s* words) and *t − s ≥* 1 identity functions, it is always possible to find an initial subspace such that no S-box is active (at least) in the { ⌊ ⌋} ⌊ ⌋ first max 1*,* <u>t−</u> *s* <u>s</u> rounds. Note that <u>t−</u> *s* <u>s</u> *≥* 1 if and only if *s < dt/*2*e*. Indeed, if the matrix that defines the linear layer has maximum branch number and if *s ≥dt/*2*e*, then at least one S-box is active every two rounds (however, since *s < t*, then it is always possible to choose the initial subspace such that no S-box is active in the first round). By choosing texts in the same coset of *S* = *〈v₁,...,v*dim(*S*)*〉* such that { ⌊ ⌋} <u>t − s</u>*i−*1 *s*
*∀i ∈* 1*,...,* : (*M · vj*)[1*,*2*,...,s*] = 0 *||* 0 *||···||* 0 *∈* F
*s*

for each *j ∈{*1*,...,* { ⌊dim (⌋}

*S*)*}* and where *M⁰* = *I* is the identity matrix, no S-box is active
in the first max 1*,* <u>t−</u> *s* <u>s</u> rounds. We formalize this result in the following definition.

**Definition 11.** Consider the case of a P-SPN scheme over F *t* with 1 *≤ s < t* S-boxes applied to the first *s* words defined as in Eq. (1). Let *S*

(*i*) *⊆* F *t* be defined as
{

(*i*)F *t*
if *i* = 0*,* *S* = { *t* ∣ *j s* } (3) *v ∈* F ∣ (*M · v*)[1*,...,s*] = 0 *||···||* 0 *∈* F*,*0 *≤ j < i* otherwise.

**Lemma 1.** *Given a P-SPN scheme over* F *t* *with s S-boxes applied to the first s words* *defined as in Eq.* (1)*, let S*

(*i*) *be defined as in Definition11. For each i ≥* 1*,*
{ ∣} (*i*+1) (*i*)∣*s* (*i*) *−*1 (*i*) (*i*) *S* = *v ∈S* ∣ (*M · v*)[1*,...,s*] = 0 *||···||* 0 *∈* F = *S ∩* (*M ·S*) *⊆S,*

(

(*i*) )
*where t − i · s ≤* dim *S ≤ t.*

*Proof.* Let *x ∈S*

(1). By definition, *x ∈S*
(2) if and only if
*x ∈S*

(1) *∩{y ∈* F
*t* *|* (*M · y*)[1*,...,s*] = 0 *||···||* 0 *∈* F *s* *},* { *t* ∣ *j s* } or equivalently, if *x ∈ v ∈* F ∣ (*M · v*)[1*,...,s*] = 0 *||···||* 0 *∈* F*,j ∈{*0*,*1*}*. Since

*{y ∈* F *t* *|* (*M · y*)[1*,...,s*] = 0 *||···||* 0 *∈* F *s* *}*

= *{*(*M* *−*1 *· z*) *∈* F *t* *| z*[1*,...,s*] = 0 *||···||* 0 *∈* F *s* *}*

= *M* *−*1 *·{z ∈* F *t* *| z*[1*,...,s*] = 0 *||···||* 0 *∈* F *s* *}*

= *M* *−*1 *·S*

(1) *,*
it follows that { *S*

(2) = *S*
(1) *∩ M* *−*1 *·S*
(1). Working recursively,
} *x ∈S* (*i*+1) if and only if *x ∈ v ∈* F *t* *|* (*M* *j* *· v*)[1*,...,s*] = 0 *||···||* 0 *∈* F *s* *,*0 *≤ j ≤ i*, that is, if *x ∈S*

(*i*) *∩{y* <u>∈</u>
*S*

(*i*) *|* (*M · y*)[1*,...,s*] = 0 *||···||* 0 *∈* F
*s* *}*. It follows that *S* (*i*+1) = *S*

(*i*) *∩ M* *−*1 *·S*
(*i*).

#### Moreover, the following result holds.

**Lemma 2.** *Consider the case of a P-SPN scheme over* F *t* *with* 1 *≤ s < t S-boxes applied* ⌊ ⌋ *to the first s words as in Eq.* (1)*, and let S*

(*i*) *be defined as before. Let* R *≥*
<u>t−</u> *s* <u>s</u> *be* (

(R) ) (
(R+1) ) *the (positive) integer such that* dim *S ≥* 1 *and* dim *S* = 0 *(where* R = *∞ if* (

(*r*) )
dim *S ≥* 1 *for each r ≥* 1*). For each r ≤* R*, the collection* () *S*

(*r*) *,M ·S*
(*r*) *,M² ·S*
(*r*) *,...,M* *r−*1
*·S*

(*r*)
*is a subspace trail for the first r rounds generated by S*

(*r*) *without active S-boxes.*
(

(*r*) (*r*) 2 (*r*) *r−*1 (*r*)
) *Proof. S,M ·S,M ·S,...,M ·S* is a subspace trail if for each *i ∈{*0*,*1*,* *...,r −*1*}* and for each *a ∈* F *t*, there exists *b ∈* F *t* such that *R*(*M* *i* *·S*

(*r*) +*a*) = *M*
*i*+1 *·S*

(*r*) +*b*.
By definition of the round function *R*(*x*) = *c* + *M ◦ S*(*x*):

- The S-box layer only changes the coset. Indeed, the first *s* words of *M*
*i* *·S*

(*r*) + *a*
are constant, due to the definition of *S*

(*r*) and due to the fact that the S-box
layer is composed of *s* nonlinear functions and *t − s* identity functions. Hence, *S*(*M* *i* *·S*

(*r*) + *a*) = *M*
*i* *·S*

(*r*) + *a* *′* for a certain *a*
*′* *∈* F *t*.

*i* (*r*) *′ i*+1 (*r*) *′′*

- Since the linear layer is a linear operation, *M ·* (*M ·S* + *a*) = *M ·S* + *a*.
- Finally, the last key or constant addition only changes the coset. This well-known result (see e.g. [ARS
+ 15, Sect. 5.1] or [GGNPS13, Sect. 4.1]) does not require any assumption on the matrix *M* that defines the linear layer. In the following, we will explore in which cases it is possible to set up an infinitely long subspace trail. In order to do this, we start by reconsidering some results already published in the literature.

### 3.2 Infinitely Long Invariant Subspace Trails via Eigenspaces of M

As it is well-known in the literature [AÅBL12, Bey18], invariant subspace trails can be set up by exploiting the eigenspaces of the matrix *M* that defines the linear layer.

**Proposition 3.** *Given a P-SPN scheme over* F *t* *with s S-boxes per round defined as in* *Eq.* (1)*, let M ∈* F *t×t* *be the invertible matrix defining the linear layer. Let λ₁,...,λτ∈* F

|τ|t||
|---|---|---|
|s+1 t|t|τ|

*be its eigenvalues and let P₁,..., Pτ⊆* F *t* *be the corresponding eigenspaces. Let* 〈 〈 〉 〈 〉〉
*I* = *P₁ ∩ e,...,e,..., P ∩ es*+1*,...,et.*

*If* 1 *≤* dim(*I*) *< t, then I⊆* F *generates a (nontrivial) infinitely long invariant subspace* *trail without active S-boxes.*

*Proof.* To prove the previous result, we have to show that for each *a ∈* F *t* there exists *b ∈* F *t*

such that *M ◦ S*(*I* + *a*) = *I* + *b*. Hence, we omit the key and constant additions since they 〈 〉 only change the coset. First of all, note that no S-box is active since *I⊆ es*+1*,...,et*, and thus only the coset changes through the S-box layer. Secondly, since 〈 *Pi*is an eigenspace 〉
of the linear layer *M* for each *i ∈{*1*,...,τ}*, it follows that *Pi∩ es*+1*,...,et*remains
invariant through it. The result follows immediately.

**Examples.** Consider a P-SPN scheme over F⁴*p*with *s* = 1 for a prime *p ≥* 101. If the 4 *×* 4 matrix *M* is   4 4 5 1 1 3 5 3 *M* =     *,* 3 2 4 1 4 1 4 4

*T* then *I* = *〈*(0*,, −,*1) *〉* generates an infinitely long invariant subspace trail. Indeed, note *T T T* that (0*,*1*, −*1*,*1) is an eigenvector of *M* and *〈*(0*,*1*, −*1*,*1) *〉∩〈e₂,e₃,e₄〉* = *〈*(0*,*1*, −*1*,*1) *〉*. Hence, this is a concrete example of the result given in the previous theorem, and it is independent of the branch number of *M* (e.g., such a 4*×* 4 matrix is MDS matrix for each *p ≥* 101). As a second example, if   2 3 1 1 3 1 1 2 *M* = circ(2*,*3*,*1*,*1) =     *,* 1 1 2 3 1 2 3 1

*T T* the only eigenspace are given by *〈*(1*,*1*,*1*,*1) *〉* and *〈*(1*, −*1*,*1*, −*1) *〉* (with eigenvalues equal to 7 and *−*1, respectively). Neither of them satisfies the results of the theorem just given. Hence, there exist matrices which provide security against invariant subspace trails without active S-boxes even if they have eigenspaces.

**3.3 A Necessary and Sufficient Condition for the Existence of Infinitely Long Invariant Subspace Trails (Without Active S-boxes)** As shown in Section2.3, a subspace does not have to be an eigenspace of a matrix *M* in order to be *M*-invariant. In particular, as we have seen in Theorem1, the space F
*t* can be rewritten as a direct sum decomposition F *t* = *A₁ ⊕A₂ ⊕···⊕Am,* where – among other properties – all subspaces *Ai*are *M*-invariant. Here we generalize the previous result by replacing the eigenspaces of the matrix with the subspaces *Ai*, which lead us to a necessary and sufficient condition.

**Theorem 2.** *Given a P-SPN scheme over* F *t* *with s S-boxes defined as in Eq.* (1)*, let* *M ∈* F *t×t* *be the invertible matrix that defines the linear layer. A subspace I, where* 1 *≤* dim(*I*) *< t, generates an infinitely long invariant subspace trail without active S-boxes* () *if and only if I⊆S*

(1) *and I* = (*M ·I*)*. In particular, I⊆S*
(1) *∩ M ·S*
(1) *.*
*Proof.* We work with differences. That is, instead of proving that each coset of *I* is mapped into a coset of *I* after one round, we are going to prove that given two elements in the same coset of *I* (namely, an input difference in *I*), then the corresponding output elements are still in the same coset of *I* (namely, the output difference lies in *I*), i.e., given *x,y ∈* F *t*, Prob(*R*(*x*) *− R*(*y*) *∈I| x − y ∈I*) = 1. We use this approach in the entire paper. The fact that a subspace *I ⊆S*

(1) such that *I* = *M ·I* generates an infinitely long
invariant subspace trail without active S-boxes is trivial. Indeed, the definition of *S*

(1)
(which implies that no S-box is active) together with the fact that *I* = *M ·I* implies the result. Vice-versa, here we show that given an infinitely long invariant subspace trail *I* without active S-boxes, it must satisfy *I⊆S*

(1) and *I* = *M ·I*. To do this, observe that
all pairs of texts which do not activate any S-box in the next round are in the same coset of *S*

(1) (by its definition). Focusing on the linear layer, note that a subspace *X* is invariant
if and only if *M ·X* = *X*. The result follows immediately. () Finally, we prove that *I⊆S*

(1) *∩ M ·S*
(1). Since *I⊆S*
(1), it follows that (*M ·I*) <u>⊆</u>
(*M ·S*

(1) ), where *M* is a linear operation. As a result, *I⊆* (*M ·S*
(1) ) since *I* = *M ·I*.
**Theorem 3.** *Given a P-SPN scheme over* F *t* *with s S-boxes defined as in Eq.* (1)*, let*

|t×t||||m|
|---|---|---|---|---|
|m|t i|i s+1|t|i i|

*M ∈* F *t×t* *be the invertible matrix that defines the linear layer. Let {A₁,..., A} be* *the primary decomposition of* F *with respect to the matrix M, as defined in Theorem* ⊕ *1,*

*i.e., a collection of M -invariant independent subspaces in* F *such that* F
*t* = *A. Let* *{X₁,..., X} be a collection of subspaces defined as*

*X* := *A ∩〈e,...,et〉.* (4)

*A subspace I, where ≤* dim(*I*) *< t, generates an infinitely long invariant subspace trail* *without active S-boxes if and only if*

||||I = 〈P₁, P₂,..., P||〉,|||
|---|---|---|---|---|---|---|---|
||||||m|||
|i|i||i s+1|t||i i|i (1)|
|||||m||||
|||||||i||
|i i|s+1 i|t|||i|||

*where P ⊆X is an M -invariant subspace. In particular, P ⊆X ∩* (*M ·Xi*)*.*

Note that the condition *A ∩〈e,...,e 〉* can be replaced by the condition *A ∩S*.

*Proof.* Proving that *I* = *〈P₁, P₂,..., P 〉* generates an infinitely long invariant subspace trail without active S-boxes is trivial. Indeed, by definition of *P*, no S-box is active (since
*P ⊆X ⊆〈e,...,e 〉* for *i ∈{*1*,...,m}*). The fact that *I* is *M*-invariant follows from
the fact that all *P* are *M*-invariant subspaces of *X* (by assumption). Hence, every input difference in *I* is mapped into an output difference in *I*. Vice-versa, assume that *I* generates an infinitely long invariant subspace trail without active S-boxes. Let *Pi*:= *Ai∩I.*

Obviously, all *Pi*are subspaces. First of all, note that all *Pi*are subspaces of *〈es*+1*,...,et〉*, since no S-box is active by definition of *I*. Indeed, if there exists a nontrivial *Pi*such that *Pi∩〈e₁,...,es〉6*= *{*0*}*, then eventually at least one S-box is active (remember that we are working with differences and that *I* generates an infinitely long subspace trail), which contradicts the assumption that no S-box is active. Secondly, note that *Pi⊆Ai*is *M*-invariant. Indeed, if *x ∈Pi*, then *M · x* belongs to *Ai*(since *Ai*is *M*-invariant) and to *I* (since it generates an infinitely long subspace trail), which implies that *M ·x ∈* (*A* ⊕ *i* *∩I*) = *Pi*. Moreover, *I* = *〈P₁, P₂,..., Pm〉* since *Ai∩Aj*= *{*0*}* for *i 6*= *j*, and since F *t* =*iAi*. Finally, *Pi⊆Xi∩* (*M ·Xi*) follows from the fact that *Pi⊆Xi*and *Pi*= *M ·Pi*, as in the proof of Theorem2.

(0)
**Proposition 4.** *Under the assumptions of the previous theorem, let Xi*:= *Ai∩* *〈es*+1*,...,et〉. For j ≥* 1*, we define* ()

(*j*) (*j−*1) (*j−*1)
*Xi*= *Xi∩ M ·Xi.*

(*li*) (*li*+1) *Let li≥* 0 *be the smallest (finite) integer such that Xi*= *Xi. The biggest M -invariant* (*li*) *subspace Piof Xithat satisfies Theorem3is equal to Xi.*

(*j*) (0)
*Proof.* All *Xi*are subspaces of *Xi⊆Ai*, where *Ai*is invariant under *M* by construction.

(*j*) (*j−*1) (*j*) (*j−*1) (*j*)
Hence, either dim(*Xi*) *<* dim(*Xi*) or dim(*Xi*) = dim (( *Xi*). If dim(*Xi* )) = (*j−*1) (*j*) (*j−*1) (*j−*1) (*j−*1) dim(*Xi*), then *Xi*= *Xi*. Indeed, note that dim *Xi∩* (*M ·Xi*) = () (*j−*1) (*j−*1) (*j−*1) (*j*) (*j−*1) dim(*Xi*) if and only if *Xi*= *M ·Xi*, which implies that *Xi*= *Xi*. By construction, this is the biggest *M*-invariant subspace of *Ai∩〈es*+1*,...,et〉*.

(*j*) (*j*+1)
Finally, note that the index *li*such that *Xi*= *Xi*for each *j ≥ li*is always finite.

(*j*) (*j−*1)
Indeed, in the case in which dim(*Xi*) *<* dim(*Xi*) for each *j < li*, we have that

(*j*) (*j*) (*j*+1)
*Xi*= *{*0*}* for each *j ≥ li*. Otherwise there exists *li*such that *Xi*= *Xi6*= *{*0*}* for

(0)
each *j ≥ li*. In both cases, *li*is at most equal to the dimension of *Xi*, since at each step

(*j*)
the dimension of *Xi*either remains constant or decreases by 1.

**Corollary 1.** *The infinitely long invariant subspace trail without active S-boxes presented* *in Proposition3satisfies Theorem3. The two results are equivalent if the matrix is* *diagonalizable.*

*Proof.* The invariant subspace considered in Proposition3is equal to the one considered in Theorem3under the condition { *Xi*if *Xi*is an eigenspace of *M,* *Pi*= *{*0*}* otherwise.

#### This concludes the proof.

Before going on, we highlight that Theorem3and Proposition3are not equivalent, in the sense that there are matrices *M* that admit infinitely long invariant subspace trails which are independent of their eigenspaces. A concrete example is given by the Cauchy matrix *M* generated as in [GKR + 19, GKR + 21] (recalled in Section4.1) for *t* = 24 and F₂*n*, where *n* = 63. As shown in [KR21, Page 20], the subspace *S*

(5) defined as in Eq. (3)
satisfies *M ·S*

(5) = *S*
(5) and (*M · x*)[1] = 0 for all *x ∈S*
(5). At the same time, the subspace
*S*

(5) is not related to any eigenspaces of *M*
*j* for *j ∈{*1*,...,*5*}*.

## 4 Iterative Subspace Trails Without Active S-Boxes

The previous results can be generalized to obtain a necessary and sufficient condition regarding the existence of infinitely long *iterative* subspace trails without active S-boxes.

**Proposition 5.** *Given a P-SPN scheme over* F *t* *with s S-boxes defined as in Eq.* (1)*,* *let M ∈* F *t×t* *be the invertible matrix that defines the linear layer. A subspace I, where* 1 *≤* dim(*I*) *< t, generates an infinitely long iterative (non-invariant) subspace trail of* ()

|||(l)|
|---|---|---|
|l|(l) 5||

*period l ≥* 2 *without active S-boxes if and only if I⊆S and I* = *M* *l* *·I. In particular,*

(*l*) ()
*I⊆S ∩ M ·S.*

The proof is a simple generalization of the one given for Theorem2.

**Proposition 6.** *Given a P-SPN scheme over* F *t* *with s S-boxes defined as in Eq.* (1)*, let* *t×t* (*l*) (*l*) (*l*) *M ∈* F *be the invertible matrix that defines the linear layer. Let {A₁m*

|||||, A₂ ,..., A|}|
|---|---|---|---|---|---|
||t||l|||
|l|||t|t|(l)|
||||||i i|
|m|i|(l) (l) i||||

*be the primary decomposition of* F *t* *with respect to the matrix M* *l* *, as defined in Theorem1,* ⊕ *that is, a collection of M-invariant independent subspaces in* F *for which* F = *A.* *For each l ≥* 2*, let {X₁,..., X} be a collection of subspaces defined as*

#### X := A ∩S.

*A subspace I, where* 1 *≤* dim(*I*) *< t, generates an infinitely long iterative subspace* *trail without active S-boxes of period l ≥* 2 *if and only if*

*I* = *〈P₁, P₂,..., Pm〉,*

*l* ( *l* ) *where Pi⊆Xiis a subspace that is M-invariant. In particular, Pi⊆Xi∩ M ·Xi.*

*Proof.* The proof of this result is equivalent to the one given in Theorem3. In particular,

||i (l)|l−1|
|---|---|---|
||(l)|(l)|
|l In order to simplify the notation, we use I to denote either an invariant subspace trail or an iterative subspace trail. The period of the trail is clear from the context.||i|

the condition *P ⊆S* guarantees that no S-box is active in (*I,M ·I,...,M ·I*) by definition of *S*, and the subspace *I* is *l*-round invariant, since each subspace *A* is *M*-invariant.

**Connection to the Existence of Invariant Subspace Trails.** One may wonder if there exists an example of a P-SPN scheme for which there exists no infinitely long invariant subspace trail, but at the same time there exists an infinitely long iterative subspace trail without active S-boxes. As we are going to show, this is not possible.

**Proposition 7.** *Consider a P-SPN scheme over* F *t* *with s S-boxes defined as in Eq.* (1)*.* *An infinitely long iterative subspace trail without active S-boxes can only exist if there exists* *an infinitely long invariant subspace trail without active S-boxes.*

*Proof.* As shown in Proposition1, let (*V₁,..., Vl*) be an infinitely long *iterative* subspace
trail of period *l* (without active S-boxes). If dim(*〈V₁,..., Vl〉*) *< t*, then *〈V₁,..., Vl〉*
generates an infinitely long *invariant* subspace trail. Hence, if dim(*〈V₁,..., Vl〉*) = *t*, it would be possible that an iterative subspace trail without active S-boxes exists and at the same time no invariant subspace trail exists. However, note that dim(*〈V₁,..., Vl〉*) = *t* can *never* occur in the case without active S-boxes. Indeed, since *Vi s*+1 *t*

|⊆〈e|,...,e|〉 for each i ∈||
|---|---|---|---|
|i|s+1 l|t s+1|t|
|l|s|||

*{*1*,...,l}* (to guarantee that no S-box is active), it follows that *〈V₁,..., V 〉⊆〈e,...,e 〉*
can never generate the full space F *t*
(indeed, *〈V₁,..., V 〉∩〈e₁,...,e 〉* = *{*0*}*).

This does not mean that iterative subspace trails without active S-boxes are useless. Indeed, let (*V₁,..., Vl*) be an infinitely long iterative subspace trail of period *l* without active S-boxes. If dim(*Vi*) *<* dim(*〈V₁,..., Vl〉*) (note: *strictly* less), then the data cost of setting up the iterative subspace trail may be smaller than the cost of setting up an invariant subspace trail. This can be crucial in scenarios in which there is a limitation on the data allowed for an attack.

### 4.1 Linear Layers with Low Multiplicative Order

As a first concrete example, we consider the case of a linear layer defined via a matrix with low multiplicative order.

**Definition 12.** Let *M ∈* F *t×t* be an invertible matrix. *M* has a multiplicative order equal to *l ≥* 1 if and only if *l* is the smallest (positive) integer for which there exists *µ ∈* F *\{*0*}* such that *M* *l* = *µ · I*, where *I ∈* F *t×t* is the identity matrix.

**Proposition 8.** *Given a P-SPN scheme over* F *t* *defined as in Eq.* (1)*, let M ∈* F *t×t* *be* *the invertible matrix defining the linear layer. If the multiplicative order of* ⌊ *M* ⌋ *is l such* *that* 2 *≤ l ≤* R *(that is, M* *l* = *µ · I for a certain µ ∈* F *\{*0*}), where* R *≥* <u>t−</u> *s* <u>s</u> *is defined* *as in Lemma2, then S*

(*l*) *generates an infinitely long iterative subspace trail of period l.*
(

(*l*) (*l*) *l−*1 (*l*)
) *Proof.* To prove the result, it is sufficient to see that *S,M ·S,...,M ·S* is an iterative subspace trail without active S-boxes. This is a consequence of the fact that

|l (l)|(l)|(l)|||||(l)|
|---|---|---|---|---|---|---|---|
|||+||||||
||||t×t|+ +||||

*M ·S* = *µ · I ·S* = *S*, and because no S-boxes are active by the definition of *S*.

**Cauchy Matrices in [GKR 21] – An Example from the Literature.** An example has recently been pointed out in [KR21] and [BCD 20]. In these papers, the authors focus on the Cauchy matrix *M ∈* (F₂*n*) proposed in [GKR 21] and defined as

<u>1</u> *Mi,j*=*,* (5) *xi*+ *xj*+ *r*

where *xi*= *i −* 1 for *i ∈{*1*,...,t}* and *t ≤ r ≤ p − t*. Such a matrix is used as the linear layer of some Hades-like permutations, namely Starkad *π* and Poseidon *π* [GKR + 21]. In [YMT97, Sect. 3.2] and in [KR21, BCD + 20], the authors prove that if *t* = 2 *τ*, the previous matrix has a multiplicative order equal to 2, namely that *M²* is a multiple of

the identity. Hence, the previous result applies perfectly to this case. For the concrete definition of such a subspace we refer to [KR21, Sect. 5.2].

### 4.2 Linear Layers with Low-Degree Minimal Polynomials

As we have just seen, a matrix *M* has a low multiplicative order if there exists a small *l* such that *M* *l* = *µ · I*, or equivalently *M* *l* *− µ · I* = 0. Given the polynomial *p*(*x*) = *x* *l* *− µ*, it is easy to see that *p*(*·*) annihilates the entire space, since

*∀v ∈* F *t* : *p*(*M*) *· v* = (*M* *l* *− µI*) *· v* = 0 *t×t* *· v* = 0 *t* *.*

Hence, the minimal polynomial of *M* divides *p*(*·*). A generalization of the previous result is given in the following proposition.

**Proposition 9.** *Given a P-SPN scheme over* F *t* *defined as in Eq.* (1)*, let M ∈* F *t×t* *be* *the invertible matrix that defines the linear layer. Let φ be the minimal polynomial of* ⌊ *M* ⌋ *,* *and let l be its degree. Assume l is “low”, namely l satisfies* 2 *≤ l ≤* R *(where* R *≥* <u>t−</u> *s* <u>s</u>

*is defined as in Lemma2). Moreover, let* 1 *≤ h ≤ l be a divisor of l (and let l* *′* *≥* 1 *such* *that l* = *l* *′* *· h). Assume that the minimal polynomial is of the form*

*l* ∑ *′* *−*1 *φ*(*x*) = *x* *l* + *αi·h· x* *i·h* + *α₀,* (6) *i*=1

*i.e., only monomials whose exponents are a multiple of h appear. Let us define I as*
*I* = *〈S*

(*l*) *,M* *h* *·S*
(*l*) *,M²* *h* *·S*
(*l*) *,...,M* *l−h*
*·S*

(*l*) *〉,*
*where S*

(*l*) *is defined as in Eq.* (3)*. If* 1 *≤* dim(*I*) *< t, I generates an infinitely long*
*iterative subspace trail of period h (invariant if h* = 1*) without active S-boxes.*

Note that the special case *h* = *l* corresponds to the one presented in Proposition8.

*Proof.* The proof is similar to the one already presented in Proposition8, noting that:

|i|i (l)|h+i|(l) h+i|(l)|
|---|---|---|---|---|
|h (l)|h (l)|l−h|(l)||
|l|l −1 i=0 i·h|i·h|||
|||||(l)|

1. *∀i* = 0*,*1*,...,h −* 1: *M ·I∈〈M ·S,M ·S,M² ·S,...,M*
*l−h*+*i* *·S*

(*l*) *〉*.
2. *M* *h* *·I ∈ 〈S*
(*l*) *,M ·S,M² ·S,...,M ·S 〉* follows from the fact that
∑ *′* *φ*(*M*) = 0 (hence, *M* = *− α · M*).

The fact that no S-box is active follows from the definition of *S*.

#### 4.2.1 A Concrete Example: The Starkad Matrix

A concrete example for this case is given by the matrix used for Starkad over F₂63 with *t* = 24, built by using the definition given in Eq. (5) in Section4.1. Indeed, the minimal polynomial of this matrix is

*φ*Starkad(*x*) = *x⁶* + *α₄ · x⁴* + *α₂ · x²* + *α₀*

for particular *α₄,α₂,α₀ ∈* F₂63. Following Proposition9, we see that *l* = 6, *h* = 2, *l* *′* = 3. An iterative subspace trail can thus be constructed, as also shown in [KR21].

6 +

|In [BCD 20], the authors generalize the result by assuming that {x₁,x₂,...,x|} forms a closed|
|---|---|
|subgroup of GF (2). By definition of x|if t is a power of 2.|

*t* *n* *i*, this is always the case for Starkad*π*

#### 4.2.2 A Generic Example via the Eigenspaces of M

***l***

Finally, we show a concrete example of a matrix that satisfies the previous result. Consider a ∑*l′* *i·h* matrix *M* whose minimal polynomial is defined as in Eq. (6), that is, *φ*(*x*) =*i*=0*αi·h·x*, *′* ∑*l′* *i* and assume *h ≥* 2. This polynomial is related to *φ* (*y*) =*i*=0*αi·h· y* by replacing *y* with *x* *h*. By definition, note that if *φ* is the minimal polynomial of *M*, then *φ* *′* is a multiple of the minimal polynomial of *M* *h*. Moreover, remember that every solution *y*ˆ of *φ* *′* (namely, such that *φ* *′* (*y*ˆ) = 0) is an eigenvalue of *M* *l* and that each solution *x*ˆ of *φ* is an eigenvalue of *M*. Since the finite field F is not algebraically closed, given a zero *y*ˆ of *φ* *′* as before, it is possible that there is no *x*ˆ that satisfies (*x*ˆ) *h* = *y*ˆ, which is related to the existence of an eigenspace of the matrix *M* *l* that is not an eigenspace of *M*. In more details, if *E* is an eigenspace of *M* with eigenvalue *λ*, then *E* is also an eigenspace of *M* *l* with eigenvalue *λ* *l*,

i.e., *M ·E* = *λ ·E* implies *M*
*l* *·E* = *λ* *l* *·E*. Working over a space which is not algebraically closed, the other direction is not true in general. Here we exploit these facts in order to present a more generic example of an iterative subspace trail.

*Given a P-SPN scheme over* F *t*

|Lemma 3.|with s S-boxes defined as in Eq. (1), let|||||
|---|---|---|---|---|---|
|t×t (l) τ|(l)|τ(l) (l)|(l) t (l) (l)|(τl) (l)|t (l)|

*t×t* (*l*) (*l*) *t* *M ∈* F *be the invertible matrix that defines the linear layer. Let λ₁,...,λτ∈* F *be* *l* *the eigenvalues of M for some l ≥* 1*, and let P₁,..., P ⊆* F *be their corresponding* 〈 *eigenspaces (where τ ≤ t). The subspace I defined as I* := *S ∩P₁, S ∩P₂,..., S ∩* 〉 *P generates an infinitely long iterative subspace trail of period l with no active S-box.*

*Proof.* The proof of this result is analogous to the one proposed for Proposition8. In particular, it is sufficient to note that no S-box is active due to the definition of *S*

(*l*) (see
Eq. (3)), and that the subspace trail is iterative with a period equal to *l* since *I*

(*l*) <u>is</u>
constructed via the eigenspaces of *M* *l*.

We point out that this result includes the case in which the matrix has a low multi- plicative order, or more formally, the condition stated in Lemma3implies the condition stated in Proposition8. Indeed, let *l ≥* 2 be the smallest integer such that *M* *l* = *µ · I*.

|t||l||(l)|
|---|---|---|---|---|
|||||(l)|
|l|t (l)|(l)|l (l)||

Then *e₁,...,e* are all eigenvectors of *M* *l* with eigenvalue *µ*. Given *S*

(*l*) constructed as
in Eq. (3) such that no S-box is active in the first *l* rounds, then *S* is an invariant subspace of *M*, since ( *〈e₁,...,e 〉* is an eigenspace of *M* corresponding to the eigenvalue ) *µ*. It follows that *S*

(*l*) *,M ·S,M² ·S,...,M*
*l−*1 *·S* is an infinitely long iterative (constant-dimensional) subspace trail. We remark that the two conditions are not equivalent (that is, the condition stated in Proposition8does in general not imply the condition stated in Lemma3), as shown in the following concrete example.

**Example.** Consider the circulant matrix *M* = circ(*a,b,c,d*) over F⁴. Its eigenvalues and eigenvectors are equal to

*T* *λ₀* = *a* + *b* + *c* + *d* : (1*,*1*,*1*,*1)*,* *T* *λ₁* = *a − b* + *c − d* : (1*, −*1*,*1*, −*1)*,*

and √ *T* *λ₂* = *− a²* + *b² −* 2*ac* + *c² −* 2*bd* + *d²* : (*b − d, −a* + *c* + *λ₁,d − b,a − c − λ₁*)*,* √ *T* *λ₃* = *a²* + *b² −* 2*ac* + *c² −* 2*bd* + *d²* : (*b − d, −a* + *c* + *λ₂,d − b,a − c − λ₂*)*,*

*if a²* + *b² − ac* + *c² − bd* + *d²* is a quadratic residue modulo *p*, while the eigenvalues and eigenvectors of *M²* are given by

2 2 2 2 2 *T* Λ₀ = (*λ₀*) = *a* + 2*a*(*b* + *c* + *d*) + *b* + 2*b*(*c* + *d*) + *c* + 2*cd* + *d* : (1*,*1*,*1*,*1)*,* 2 2 2 2 2 *T* Λ₁ = (*λ₃*) = *a −* 2*a*(*b − c* + *d*) + *b −* 2*b*(*c − d*) + *c −* 2*cd* + *d* : (1*, −*1*,*1*, −*1)*,* 2 2 2 2 2 *T* Λ₂ = (*λ₁*) = *a* + *b −* 2*ac* + *c −* 2*bd* + *d* : (1*,*0*, −*1*,*0)*,* 2 2 2 2 2 *T* Λ₃ = (*λ₂*) = *a* + *b −* 2*ac* + *c −* 2*bd* + *d* : (0*,*1*,*0*, −*1)*.*

Since *x 7→ x²* is not a permutation over F*p*for any prime *p ≥* 3 (see Hermite’s criterion), it is possible that there exist *a,b,c,d,* such that *a²*+*b²−* 2*ac*+*c²−* 2*bd*+*d²* = (*a − c*) 2 + (*b − d*) 2

is a quadratic non-residue. As a concrete example, by taking *a − c* = *b − d*, then (*a − c*) 2 + (*b − d*) 2 = 2 *·* (*a − c*) 2 is not a quadratic residue modulo *p* if *Lp*(2) = *−*1 (where *Lp*: F*p→{−*1*,*0*,*1*}* is the Legendre symbol), which happens if *p* = 3*,*5 mod 8 (we refer to [Nag51] for more details). Hence, while *M²* has always four eigenvalues, it is possible that *M* has only two eigenvalues for certain values of *a,b,c,d ∈* F*p*. 8 This fact can be exploited in order to construct a matrix *M* that is not a multiple of the identity and for which an infinitely long iterative subspace trail exists. Given a P-SPN 5 scheme over (F*p*) with *s* = 1, an example of such a matrix is   *x y w y w* *z₀ a b c d*    *M* = *z₁ b c d a*   *z₂ c d a b*  *z₃ d a b c*

for particular values of *a,b,c,d,x,y,w,zj∈* F*p*such that *(1)* the matrix is invertible and it provides full diffusion (at word level after a finite number of rounds) for cryp- tographic purposes and *(2)* the circulant matrix circ(*a,b,c,d*) has only two eigenvalues. { *T* The iterative (non-invariant) subspace trail is thus given by *I* = *〈*(0*,*0*,*1*,*0*, −*1) *〉,* *T* } 2 2 *M ·I* = *〈*(0*,b − d,c − a,d − b,a − c*) *〉,* where *M ·I* = *I* and where *M 6*= *µ · I* for each *µ ∈* F*p*. Finally, note that *M²* is not necessarily equal to a multiple of the identity. For () example, note that (*M²*)1*,*5*6*= 0, where *M²* 1*,*5 = *xy₀* + *y₀a* + *y₁b* + *y₀c* + *y₁d* is different from 0 by appropriately choosing the entries.

## 5 Practical Tests (Without Active S-Boxes)

In this section, we first present an algorithm which can be used to find vulnerabilities and to detect weak matrices (with respect to the attacks presented before). Moreover, we test several matrices over F*p*and over F₂*n* to give an idea of the number of these matrices.

### 5.1 Algorithm for Detecting Weak Matrices

In order to find the vulnerabilities, we use the results given in Theorem3and Proposition4. In more detail, we first decompose the full space into (potentially smaller) ⊕ *M*-invariant *t m* subspaces, that is, F =*i*=1*Ai*, where this decomposition results from Theorem1. For this purpose, we need the minimal polynomial of the matrix obtained by the Frobenius normal form. We then take the intersection of these subspaces with the unit vectors

(0)
at the identity positions of the nonlinear layer, i.e., *Xi*= *Ai∩〈es*+1*,...,et〉*. Now we

(0)

|apply Proposition4to each of these subspaces X||||, which means reducing the dimensions||||
|---|---|---|---|---|---|---|---|
|By definition, x ∈ F non-residue otherwise.|is a quadratic residue modulo p if y ∈ F||||such that x = y|, while it is a quadratic||
|E.g., given (a,b,c,d) = (1, 1, 2, 3), a|||+ b − 2ac + c|− 2bd + d|is a square in F||, but not in F|
 *i*
7 *p p* 2

8 2 2 2 2 11 13.

**Algorithm 1:** Determining the existence of invariant infinitely long subspace trails without active S-boxes, using Theorem3and Proposition4. **Data:** P-SPN scheme over F *t* with *s* S-boxes applied to the first *s* words. **Result:** 1 if an invariant infinitely long subspace trail without active S-boxes exists, 0 otherwise.

|Obtain A₁, A₂,..., A|||using Theorem1.|
|---|---|---|---|
|1 2||m||
|3|i i|s+1|t|
|4||i||
|5 6|i|i||
|7|i|i|i|
|8 9 10 11||m||

**for** *i ←* 1 **to** *m* **do** *A ←A ∩〈e,...,e 〉*. **while** dim(*A*) *>* 0 **do** **if** *A* = *M ·A* **then** **break** *A ←* (*M ·A ∩A*). *I←〈A₁, A₂,..., A 〉*. **if** dim(*I*) *>* 0 **then** **return** *1: Discard the matrix M (due to existence of an invariant subspace* *trail generated by I – Theorem3)*. **return** *0: No infinitely long subspace trail without active S-boxes found*.

of these subspaces until the dimension becomes either zero or until the subspace has a nonzero dimension and does not change when applying the matrix multiplication. These final subspaces are *Pi*for *i ∈{*1*,...,m}*. We now build the space

#### I = 〈P₁, P₂,..., Pm〉

and report that the matrix is vulnerable with respect to infinitely long invariant subspace trails if and only if dim(*I*) *>* 0. The detailed steps are shown as a pseudo code in Algorithm1. We emphasize that, while Algorithm1only detects infinitely long invariant subspace trails, this is sufficient in order to also prevent infinitely long iterative subspace trails. We refer to Proposition7for more details.

**Computational Cost of Algorithm1.** The complexity of computing the Frobenius normal form is an element of *O*(*t³*) for a *t × t* matrix [Sto98]. Moreover, since *m ≤ t* and since the dimension of each *Ai*can be reduced at most *t* times, the complexity of the loop is an element of *O*(*t²*). Hence, the computational cost is an element of *O*(*t³* + *t²*) = *O*(*t³*).

**Computational Cost in Practice.** In our practical runtime tests, we focus on prime fields F*p*for *p ≥* 3 and we use Sage. To give some concrete numbers, for *d*log₂(*p*)*e* = 16, the test for a single matrix takes about 4 milliseconds for *t* = 4, while it takes about 30 milliseconds for *t* = 16 (using an Intel Xeon E5-2699v4 with a maximum clock frequency of 3.60 GHz).

### 5.2 Percentage of Weak Linear Layers

We implemented Algorithm1in Sage and used it to get an idea of the percentage of matrices that are vulnerable to the attack without active S-boxes presented in Section3.

**Different Classes of Matrices.** For concrete use cases, we set *s* = 1 and we focus on two scenarios, namely random invertible matrices and random Cauchy matrices. 9 As the source for randomness we use Sage’s random engine in both cases (and for choosing

9 *t×t*

|We recall that M ∈ F|is a Cauchy matrix if there exists {x||,y} such that M|
|---|---|---|---|
|for each i 6= j : x|, y 6= y, x|+ y 6= 0. Cauchy matrices are MDS matrices.||

*i i* *t* *i,j*= <u>1</u>, where *i*=1 *xi*+*yj* *i6*= *xj i j i j*

**Table 1:** Percentage of vulnerable matrices for Algorithm1and orders *t*, when considering

prime fields F*p*.

|dlog₂(p)e||8|4|6|16|8|12|16|8|
|---|---|---|---|---|---|---|---|---|---|
|t||3|4|4|4|8|8|8|12|
|Vulnerable (%) (Random Invertible)||0.46|8.94|2.06|< 0.01|0.51|0.03|< 0.01|0.50|
|Vulnerable (%) (MDS, Random Cauchy) Table 2: Percentage of vulnerable matrices for Algorithm1and orders t, when considering||0.49|6.12|2.03|< 0.01|0.49|0.03|< 0.01|0.52|
|binary fields F₂|.|||||||||
|n||8|4|6|16|8|12|16|8|
|t||3|4|4|4|8|8|8|12|
|Vulnerable (%) (Random Invertible) Vulnerable (%)||0.37|6.26|1.50|< 0.01|0.40|0.03|< 0.01|0.41|

*n*

0*.*39 5*.*14 1*.*48 *<* 0*.*01 0*.*41 0*.*02 *<* 0*.*01 0*.*37
#### (MDS, Random Cauchy)

e.g. the prime numbers). In the first scenario, we create a matrix space, sample random matrices, and finally determine if they are invertible. In the second scenario, we generate Cauchy matrices using random (and valid) starting sequences. We tested all matrices using both prime fields and binary fields, focusing on square matrices of order *t ∈{*3*,*4*,*8*,*12*}* and on F₂*n* and F*p*with *n ∈{*4*,*6*,*8*,*12*,*16*}* and *d*log₂(*p*)*e∈{*4*,*6*,*8*,*12*,*16*}*, respectively. Moreover, we tested our algorithm on the concrete matrices used to instantiate Starkad and Poseidon. We present these results in AppendixC.1. **Concrete Results.** The sample size for all tests was set to 100 000 and the results are given in Table1and Table2. We used different values for *p* for each specified range. We can immediately see that the size of *p* (or *n*) has a significant impact on the number of vulnerable matrices. Specifically, increasing *p* (or *n*) tends to result in a higher probability for a matrix to be secure against the attacks presented here. We can observe that this is also true when keeping *N* = *n · t* constant. For example, (*n,t*) = (16*,*4) results in a very different probability compared to (*n,t*) = (8*,*8) (similar for (*n,t*) = (8*,*3) and (*n,t*) = (6*,*4), or for (*n,t*) = (12*,*8) and (*n,t*) = (8*,*12)). However, even for small fields, a secure matrix can easily be found by just testing a small number of matrices with our tool.
## 6 Infinitely Long Subspace Trails for P-SPN Schemes (Ac- tive S-Boxes)

Until now, we focused on the case in which no S-box is active. Here, we analyze the scenario in which S-boxes are active.

**Assumption on the S-Box.** From now on, we only work with S-boxes that do not have any nontrivial linear structures. That is, for an S-box *S* over F, we assume that it is not possible to find nontrivial subspaces *U, V⊂* F (that is, *U, V6*= *{*0*},* F) such that *for each*

*u ∈* F there exists *v ∈* F such that *S*(*U* + *u*) = *V* + *v*. If the S-box has no nontrivial linear structures, there are only two essential subspace trails (*{*0*}→{*0*}* and F *→* F) when working at word level, as was shown in [LTW18]. Under this assumption, one can work independently of the details of the S-box. For example, both the AES S-box and the cube one (*x 7→ x³*) satisfy this assumption. This choice is made both in order to simplify the presentation and since many of the S-boxes used in the literature satisfy this assumption. Note that given an infinitely long subspace trail with probability 1, the following facts hold.

- If the S-box does not have any nontrivial linear structure, then each S-box can either be fully active or fully passive (equivalently, each input of the S-boxes either takes all possible values or is constant).
- If the S-box has a nontrivial linear structure, then it is possible that the input of the S-boxes can take values only in a specific nontrivial affine subspace.
It follows that the infinitely long subspace trails analyzed in the following can be constructed for all possible S-boxes. However, if the S-box has a nontrivial linear structure, then other infinitely long subspace trails may exist as well.

### 6.1 Preliminary Results: Subspace Trails & Truncated Differentials

We first present a generic result regarding the minimum number of rounds for which it is possible to set up a subspace trail with a probability of 1.

#### Proposition 10.

*t*

|⌊ ⌋|Given a partial SPN scheme over F||with s S-boxes defined as in Eq.|( ) (1),|
|---|---|---|---|---|
|t− s s (R+1)||||(R)|
|||t−|||
|||s s|||
||(R)|(R)|(R) (1)||
|(i)|||(i)|(i−1)|

(0) R−1 (R)

*let* R *≥* <u>t−</u> *be the (positive) integer defined as in Lemma2(namely,* dim *S*

(R) *≥* 1
() *and* dim *S* = 0*). Let* R ⌊ *< ∞* ⌋ *be a finite number. There exists a subspace trail with* *probability 1 on at least* R + *rounds, defined by* ( <u>t−s</u> ) *S,M ·S,...,M* R*−*1 *·S, A,..., A* (*bsc*) *,*

〈 〉 *where S is defined as in Eq.* (3) *and where A* := *M* (*e₁*)*,...,M*(*es*)*,M ·A for* *i ≥* 1 *(where A* := *M ·S).*

As for Lemma2, this well-known result (whose proof can be found in AppendixA) only depends on the number of S-boxes, and no assumption on the matrix *M* is made. Like in the case presented in Section3.1, note that depending on the details of the linear layer, a longer subspace trail of dimension 1 can be set up.

### 6.2 Infinitely Long Invariant Subspace Trails with Active S-Boxes via the Eigenspaces of M

Using the approach from Section3.2, here we present some simple examples of infinitely long invariant subspace trails with active S-boxes based on the eigenspaces of the matrix

*M*. For this purpose, let us first introduce the concept of “compatible” subspaces. **Definition 13.** Let *s ∈{*1*,...,t −* 1*}* be an integer. Let *V⊆* F
*t* be a subspace and let *I ⊆{*1*,...,s}*. We say that the subspace *V* is *I-compatible* if and only if

- if *I* = *∅*, then *V⊆〈es*+1*,...,et〉*,
- if *I* = *{ι₁,ι₂,...,ι|I|}*, then
1. *V⊆〈eι*1*,...,eι|I|,es*+1*,...,et〉*,

2. *〈eι,...,eι|I|〉⊆V*.
If there exists *I ⊆{*1*,...,s}* such that *V* is *I*-compatible, then *I* is unique, in the sense that *V* cannot be *J*-compatible for any *J 6*= *I*. At the same time, note that it is possible *t* that there is no *I* such that *V* is *I*-compatible. For example, working over (F*p*) for a prime *p ≥* 3 and *t ≥* 3, consider the subspace *V* = *〈e₁* + 2 *· e₂〉*. If *s* = 1, we can immediately see that there is no *I* such that the subspace *V* is *I*-compatible.

**Proposition 11.** *Given a P-SPN scheme over* F *t* *with s S-boxes defined as in Eq.* (1)*,* *let M ∈* F *t×t* *be the invertible matrix defining the linear layer. Let λ₁,...,λτ∈* F *be the* *eigenvalues of M, and let P₁,..., Pτ⊆ F* *t* *be the corresponding eigenspaces (where τ ≤ t).*
*Let I* = *{ι₁,...,ι|I|}⊆{*1*,...,s} be the indices of the active S-boxes (where I 6*= *∅), and*
〈 *′* 〉 *I* = *P₁,..., Pτ′,*

*where Ph* *′* *is a subspace¹⁰ of Phfor h ∈ {*1*,...,τ}. If* 1 *≤* dim(*I*) *< t and if I is I-* *compatible, then I generates an infinitely long invariant subspace trail with active S-boxes.*

*Proof.* Since *I* is *I*-compatible, the first condition in Definition13ensures that the *l*-th S-box is not active if *l /∈ I*. For each *i*-th active S-box, where *i ∈ I*, the second condition in Definition13implies that the entire space *〈ei〉* is included in *I*. The consequence is that, when applying the S-box, the subspace remains the same. As for the results given in the previous sections, this subspace remains invariant through the linear layer since it is defined via the eigenspaces of *M*. Hence, *I* results in an infinitely long invariant subspace trail.

Note that the number of active S-boxes in the previous subspace trail is proportional to the number of rounds (so, potentially “infinite”). As before, we emphasize that, in general, the previous observation provides only a sufficient condition.

**Example.** Let *ω ∈{*0*,*1*}*. Given a P-SPN scheme with *s* = 1, consider the following 4*×* 4 matrix *M* defined over a field F*p*for *p ≥* 3:   *ω* ((1 *− ω*) *− M₁,*3 *· b − M₁,*4 *· c*)*/a M₁,*3 *M₁,*4 *a* (*−a · ω − M₂,*3 *· b − M₂,*4 *· c*)*/a M₂,*3 *M₂,*4 *M* =  *,* (7) *b* (*−b · ω − M₃,*3 *· b − M₃,*4 *· c*)*/a M₃,*3 *M₃,*4 *c* (*−c · ω − M₄,*3 *· b − M₄,*4 *· c*)*/a M₄,*3 *M₄,*4

where *a 6*= 0. A proper choice of *a,b,c* and *M·,·*provides invertibility and “full diffusion” (at word level after a finite number of rounds) for cryptographic purposes. The subspace

〈 *T T* 〉 *I* = *e₁* = (1*,*0*,*0*,*0)*,v* = (*ω,a,b,c*)*,*

where *M · e₁* = *v* and *M · v* = *e₁*, is invariant under the round transformation for any number of rounds. Indeed, since the first word can take every value and because the S-box is applied only to this word, *I* remains invariant (note that the S-box is active). Hence, this is a concrete example of an infinitely long invariant subspace trail with active S-boxes, where *P₁* = *〈v* + *e₁〉* and *P₂* = *〈v − e₁〉* are the eigenspaces of the matrix *M* that satisfy the conditions given in the previous theorem. Lastly, we remark that matrices of the form Eq. (7) are currently used in the literature. For example, the circulant almost-MDS matrix over F₂*n* defined as circ(0,1,1,1) is used in Midori [BBI + 15] and QARMA[Ava17].

10We start with eigenspaces since any such constructed input space is invariant when ignoring the S-boxes. By imposing additional conditions for the active S-boxes we finally arrive at subspaces of eigenspaces.

**6.3 A Necessary and Sufficient Condition for the Existence of Infinitely Long Invariant Subspace Trails with Active S-boxes** As done before, the natural step is to replace the eigenspaces of *M* with subspaces that are *M*-invariant. As a main result, in this section we present a necessary and sufficient condition that allows to discard “weak” matrices with respect to invariant subspaces with and without active S-boxes. **Theorem 4.** *Given a P-SPN scheme over* F
*t* *with s S-boxes defined as in Eq.* (1)*, let* *M ∈* F *t×t* *be the invertible matrix that defines the linear layer. Assume that the S-box has* *no (nontrivial) linear structure. Let I ⊆{*1*,...,s} be the positions of the active S-boxes* *(note that I* = *∅ is also possible, that is, we do not require |I|≥* 1*). A subspace I with* 1 *≤* dim(*I*) *< t generates an infinitely long invariant subspace trail (with active S-boxes if* *|I|≥* 1*) if and only if I is both M -invariant and I-compatible.*

*Proof.* The case *I* = *∅* corresponds to the case analyzed in Theorem2. Hence, here we assume *|I|≥* 1 (where *I* = *{i₁,i₂,...,i|I|}*). Our approach is based on the strategy proposed for Theorem3and Proposition11. We first show that an *M*-invariant and *I*-compatible subspace generates an infinitely long invariant subspace trail with active S-boxes. The proof is almost equal to the one given for Proposition11. The only difference is that the condition that *I* is related to the eigenspaces of *M* is replaced by the more generic assumption that *I* is an *M*-invariant subspace. At the same time, since *I* is *I*-compatible (i.e., *〈e*1*,e*2*,...,ei|I|〉 ⊆ I* and

|||i i|
|---|---|---|
|i i|i s+1||

*I ⊆〈e*1*,e*2*,...,e|I|,e,...,et〉*), every *i*-th S-box is active if and only if *i ∈ I*, and
inactive otherwise. We recall that for an active S-box the input difference can take each possible value in F, and for an inactive S-box the input difference is equal to zero. Vice-versa, assume that a subspace *I* generates an infinitely long invariant subspace trail with active S-boxes. First of all, this can happen if and only if it satisfies the condition *I* = *M ·I*. Indeed, by contradiction, if there exists *x ∈I* such that *M · x /∈I*, then *I* would not be *M*-invariant. Moreover, since the subspace trail is *M*-invariant and with active S-boxes, each S-box can only be either constant or active. In particular, only two scenarios are possible. Either the input difference (and the output difference) of the S-box is equal to zero¹¹ or the input (and the output) of the S-box is active. Since the S-box does not have any linear structure, other cases are not compatible with the hypothesis of an invariant subspace trail with active S-boxes. Hence, there must exist *I ⊆{*1*,...,s*<u>}</u> such that *I* is *I*-compatible.

As expected, the result presented in Proposition11satisfies the previous theorem. This is due to the fact that the subspace *I* defined in Proposition11is related to the eigenspaces of *M*, which satisfy the condition *I* = *M ·I*. We formulate the following corollary.

**Corollary 2.** *The infinitely long subspace trail with active S-boxes presented in Proposi-* *tion11satisfies Theorem4.*

A generalization of Proposition11(by replacing the eigenspaces with the generic invariant subspaces of *M*) is given in the following Theorem.

**Theorem 5.** *Given a P-SPN scheme over* F *t* *with s S-boxes defined as in Eq.* (1)*, let* *M ∈* F *t×t* *be the invertible matrix that defines the linear layer. Assume that the S-box has* *no (nontrivial) linear structure. Let {A₁, A₂,..., Am} be the primary decomposition of* F *t*

*with respect to the matrix M, as defined in Theorem1.* *A subspace I, where* 1 *≤* dim(*I*) *< t, generates an infinitely long invariant subspace*
*trail with active S-boxes only in positions I* = *{i₁,...,i|I|}⊆{*1*,*2*,...,s} (that is, where*

11Equivalently, the input and the output of the S-box are constant.

*the i-th S-box is active if and only if i ∈ I) if and only if*

*I* = *〈P₁, P₂,..., Pm〉,*

*where* ()

*1. for each i ∈{*1*,...,m}: Pi⊆ Ai∩〈ei*1*,ei*2*,...,ei|I|,es*+1*,...,et〉 is an M -invariant* *subspace, and*
*2. I is I-compatible.*
*Proof.* The proof of this theorem is a consequence of the result given in Theorem4and in Theorem1. In particular, due to the argument given in Theorem4, we immediately see that *I* = *〈P₁, P₂,..., Pm〉*, where *I* is both *M*-invariant and *I*-compatible, generates an infinitely long invariant subspace trail with active S-boxes. Vice-versa, if a subspace generates an infinitely long invariant subspace trail with active S-boxes, then it must be *M*-invariant and *I*-compatible, due to Theorem4and due to the fact that the S-box has no nontrivial linear structure. The particular shape of *I* is due to Theorem1. Following the proof of Theorem3, let

#### Pi:= Ai∩I.

|All P are M -invariant subspaces. In particular, we have that I = 〈P₁, P₂⊕|||,..., P 〉 since|
|---|---|---|---|
|i|||m|
|i|i|j|i i|

all *A* are independent (in the sense that *A ∩A* = *{*0*}*) and since F *t* = *A*.

We emphasize that in general it is not trivial to give a precise “description/shape” of the subspaces *Pi*. This is due to the fact that we have two conditions, first all *Pi*have to be *M*-invariant and secondly the full subspace *I* must be *I*-compatible. For example, there may be two subspaces *Ai, Aj*such that they are both *M*-invariant and such that

•

|neither A nor A|are I-compatible, but|||
|---|---|---|---|
|i i j|j|||
||i j|i j|tp|

- *〈A, A 〉* is *I*-compatible.
In such a case, the span *〈A, A 〉* can generate an infinitely long invariant subspace with active S-boxes, but not the two subspaces *A, A*. As a concrete example working over F for a prime *p* 1 and *t ≥* 3, consider the subspace *V* = *〈e₁* + 2 *· e₂〉* and *W* = *〈e₁ − e₂〉*, and assume that they are both *M*-invariant for a particular matrix *M*. If *s* = 1, it is not hard to see that neither *V* nor *W* are *I*-compatible, while *〈V, W〉* = *〈e₁,e₂〉* is obviously *{*1*}*-compatible. Hence, while in the case without active S-boxes we can work independently on the subspaces *Ai*(obtained as the decomposition of the F *t* ), here it is not possible. A special (trivial) case of the previous theorem is given in the following corollary.

**Corollary 3.** *Given a P-SPN scheme over* F *t* *with s S-boxes defined as in Eq.* (1)*, let* *M ∈* F *t×t* *be the invertible matrix that defines the linear layer. Let {A₁, A₂,..., Am} be* *the primary decomposition of* F *t* *with respect to the matrix M. If there exists I ⊆{*1*,...,s}* *and a subspace Aisuch that Aiis I-compatible, then Aigenerates an infinitely long* *invariant subspace trail with active S-boxes.*

**An Example for Showing the Difference Between Inactive and Active S-Boxes.** Finally, one may ask if there exist P-SPN schemes which are vulnerable to subspace trails with active S-boxes, but not to trails without active S-boxes. Assuming a P-SPN scheme with *s* = 1, an example for a matrix fulfilling these properties is given by the 4*×*4 MDS matrix   3 1 1 2 3 4 2 1 *M* =     2 1 3 4 4 1 4 1

〈 *T T T* 〉 over F*p*for *p ≥* 101. In such a case, *I* = (1*,,,*0)*,*(0*,,,*2)*,*(0*,,,p −* 1) generates an infinitely long invariant subspace trail with active S-boxes. Using our proposed tool, it is possible to see that no infinitely long invariant or iterative subspace trail without active S-boxes exists.

### 6.4 Infinitely Long Iterative Subspace Trails with Active S-Boxes

Here we generalize the previous results in order to cover the case of iterative subspace trails with active S-boxes.

**Theorem 6.** *Given a P-SPN scheme over* F *t* *with s S-boxes defined as in Eq.* (1)*, let* *M ∈* F *t×t* *be the invertible matrix that defines the linear layer. Assume that the S-box has* *no (nontrivial) linear structure. Let l ≥* 1 *be the period of the iterative subspace trail. For*
*each j ∈{*1*,*2*,...,l}, let Ij⊆{*1*,...,s} be the positions of the active S-boxes (note that*
*I* *j*= *∅ is also possible, that is, we do not require |Ij|≥* 1*) at the* (*r* + 1)*-th round for r* = *j* mod *l. A subspace I of dimension* 1 *≤* dim(*I*) *< t generates an infinitely long iterative* *subspace trail (with active S-boxes if at least one Ijsatisfies |Ij|≥* 1*) of period l if and* *only if*

*(1) M* *j* *·I is Ij-compatible for j ∈{*0*,*1*,...,l −* 1*};*
*(2) I is M* *l*
*-invariant.*

*Proof.* This result is a generalization of Theorem4. In particular, *I* forms an *l*-round invariant subspace trail, i.e., a trail that is equal every *l* rounds. Hence, all *l*-round iterative subspace trails are of the form *{I,M ·I,M² ·I,...,M* *l−*1 *·I}*. Since we assume that the S-box has no (nontrivial) linear structure, such a trail has active S-boxes if and only if the first condition (namely, for each *j ∈{*1*,*2*,...,l}* there exists *Ij*such that *M* *j−*1 *·I* is <u>Ij</u> compatible) is satisfied.

We highlight that the active S-boxes are not forced to be in an active position (it is also possible that no S-box is active in some rounds). Moreover, the following result holds.

**Theorem 7.** *Given a P-SPN scheme over* F *t* *with s S-boxes defined as in Eq.* (1)*, let* *M ∈* F *t×t* *be the invertible matrix that defines the linear layer. Assume that the S-box has*

(*l*) (*l*) (*l*)
*no (nontrivial) linear structure. Let l ≥* 2*, and let {A₁, A₂,..., Am} be the primary* *decomposition of* F *t* *with respect to the matrix M* *l* *, as defined in Theorem1.* *A subspace I, where* 1 *≤* dim(*I*) *< t, generates an infinitely long iterative subspace*
*trail of period l ≥* 2 *with active S-boxes only in positions Ij*= *{i₁,j,...,i|Ij|,j}⊆{*1*,...,s}*
*in the j-th round (where j is taken modulo l) if and only if*

*I* = *〈P₁, P₂,..., Pm〉,*

*where* ()

(*l*)
*1. for each i ∈ {*1*,...,m}: Pi⊆ Ai∩〈ei*1*,*0*,ei*2*,*0*,...,ei|I*
0 *|,*0*,es*+1*,...,et〉 is an* *M* *l* *-invariant subspace, and*

*2.for each j ∈{*0*,*1*,...,l −* 1*}:* (*M*
*j* *·I*) *is Ij-compatible.*

The proof is a simple generalization of the one given for Theorem5based on Theorem6.

**Examples.** Given a P-SPN scheme with 〈 *s* = 1, consider again the 〉 *×*4 matrix *M* defined *T* in Eq. (7). The subspace *I* = *e₁* = (1*,*0*,*0*,*0) generates an infinitely long iterative subspace trail with active S-boxes (of period 2) of the form { 〈 〉 〈 〉} *T T* *I* = *e₁* = (1*,*0*,*0*,*0)*,M ·I* = (0*,a,b,c*)*,*

where *I₂i*= *{*1*}* and *I*1+2*i*= *∅* for each *i ≥* 0. *n* 4 For a second example, consider the case of a P-SPN scheme over (F₂) with *s* = 1 and 〈 *T* 〉 〈 *T* 〉 *M* = circ(0*,*1*,*1*,*1). Clearly, both (0*,*1*,*1*,*0) and (0*,*1*,*0*,*1) are invariant subspace 〈 *T T* 〉 trails without active S-boxes. As shown before, (1*,*0*,*0*,*0)*,*(0*,*1*,*1*,*1) is an invariant 〈 *T* 〉 subspace trail with active S-boxes, while (1*,*0*,*0*,*0) is an iterative (non-invariant) subspace trail with active S-boxes. By combining them, it is possible to set up new iterative 〈 〉 *T T T* subspace trails with active S-boxes, e.g., *I* = (1*,*0*,*0*,*0)*,* (0*,*1*,*1*,*0)*,*(0*,*1*,*0*,*1).

#### About Iterative Subspace Trails with Active S-Boxes

Due to the results presented in Proposition7, one may ask if there exist nontrivial iterative subspace trails with active S-boxes, namely P-SPN schemes for which there exist iterative subspace trails with active S-boxes but no subspace trails without active S-boxes or invariant subspace trails with active S-boxes. For this purpose, consider a P-SPN scheme over F³*p*(for *s* = 1 and *t* = 3), where the linear layer is defined by the matrix   0 1 *−*1 *M* = 1 *−*2 1 *.* (8) 1 *−*4 2

The (nontrivial) subspace trail () *T T* 2 *T* *V₀* = *〈*(1*,*0*,*0) *〉, V₁* = *M ·V₀* = *〈*(0*,*1*,*1) *〉, V₂* = *M ·V₀* = *〈*(0*,*1*,*2) *〉*

is iterative (since *V₀* is a proper subspace of F³*p*and *V₀* = *M³ ·V₀*) with active S-boxes. Since dim(*〈V₀, V₁, V₂〉*) = 3, it is not possible to set up an invariant subspace trail via the previous iterative subspace trail. Moreover, using the results and the tools presented in the paper, it is possible to show that (e.g., for *p* = 251) no invariant subspace trail (either with or without active S-boxes) can cover an infinite number of rounds.

## 7 Practical Tests (Active S-Boxes)

The results given in Theorem5to Theorem7seem hard to exploit in practice. A direct construction of the infinitely long subspace trail with active S-boxes is indeed missing. Without that, the cost of evaluating all subspaces *I* would likely be too large, since one has to compute all possible subspaces of *A₁, A₂,..., Am*. Here, we fix this problem by proposing two algorithms, namely one for the case of infinitely long invariant subspace trails and one for the case of iterative trails (both with active S-boxes). Further, we test several matrices over F*p*and over F₂*n* to get an idea of the number of “weak” matrices. Before going on, we emphasize again that we work under the assumption that the S-box has no linear structure. This assumption is crucial in order to have only two cases, namely the case in which the input of the S-box is constant and the case in which the input of the S-box is active (namely, the input can take any possible value). Since the S-box is a permutation, these two cases remain unchanged through the S-box. In other words, if the input is neither constant nor active, all information is lost when applying the S-box. This is not the case if the S-box has a linear structure.

**Algorithm 2:** Determining the existence of infinitely long invariant subspace trails with *active* S-boxes. **Data:** P-SPN scheme over F *t* with *s* S-boxes applied to the first *s* words (where the S-box has no linear structure). **Result:** 1 if an (invariant) infinitely long invariant subspace trail with *active* S-boxes is found, 0 otherwise.
**1 foreach** *Is⊆{*1*,*2*,...,s} such that |Is|≥* 1 *(where Is*:= *{ι₁,...,ι|Is |})* **do**
**2** *I←〈eι*1*,...,eι|Is |〉*. **3 foreach** *i ∈ Is***do** **4** *v ← ei*. **5 do** **6** *δ ←* dim(*I*). **7** *v ← M · v*. **8** *I←〈I,v〉*.
**9 if** dim(*I*) = *t **or** I∩〈eι*1*,...,eι|Is |,es*+1*,...,et〉6*= *I* **then**
**10 break** (move to next *Is*) **11 while** dim(*I*) *> δ* **12 return** *1: infinitely long invariant subspace trail with active S-boxes found: I* *with active S-boxes in Is.* **13 return** *0: No infinitely long invariant subspace trail with active S-boxes found.*

### 7.1 Related Strategies in the Literature

In order to find invariant or iterative subspaces with active S-boxes, we decided to adapt algorithms already existing in the literature for our goal, that is the one proposed in [LMR15] for the detection of invariant subspace trails and the one proposed in [GLR + 20a] for the detection of weak-key subspace trails. Let us focus on the algorithm proposed in [LMR15]. Given an SPN-like permutation, the goal is to find a subspace *U* and an offset *u* that is invariant under the keyless round function *R*(*·*), namely *R*(*U* + *u*) = *U* + *v* for a certain *v*. In the case of an SPN scheme, it is sufficient to choose the round key *k ∈ K*weak= *U* + (*u − v*) if one aims to keep the coset invariant (depending on the key schedule, such a subspace trail can cover either a finite or an infinite number of rounds). The approach described in [LMR15, Lemma 1] serves as the basis for our algorithms. After first guessing one possible offset *u* of the subspace to be found and fixing *v* = *R*(*u*), the idea is then to guess a one-dimensional subspace *A₀* and to increase the space by computing *Ai*+1= *〈R*(*Ai*+ *u*) *− v, Ai〉.*

If *Ai*+1= *Ai*for some *i >* 0, the attacker has found an invariant subspace. If this is not the case, they keep increasing the dimension of the subspace until full dimension is reached.

### 7.2 Algorithms for Detecting “Weak” Matrices

#### 7.2.1 Infinitely Long Invariant Subspace Trails with Active S-Boxes

Our main algorithm is based on the idea proposed in [LMR15] and briefly recalled in Section7.1. In particular, the procedure is as follows.

1. We choose an initial subspace *I* generated by the unit vectors at the active S-box positions defined in *Is*= *{ι₁,...,ι|Is |}*.

**Table 3:** Percentage of vulnerable matrices using Algorithm1, Algorithm2, Algorithm3

over prime fields F *tp*. We denote by “S*x*” and “V*x*” the security and vulnerability w.r.t. Algorithm *x*, respectively (e.g., S1 denotes security w.r.t. Algorithm1, while V2 denotes vulnerability w.r.t. Algorithm2). For Algorithm3, we use a maximum period of *l* = 2*t*.

|dlog₂(p)e|8|4|6|16|8|12|16|8|
|---|---|---|---|---|---|---|---|---|
|t|3|4|4 Random Invertible|4|8|8|8|12|
|% (V2)|0.48|8.94|2.02|< 0.01|0.47|0.03|< 0.01|0.51|
|% (V2 ∧ S1)|0.48|7.46|1.94|< 0.01|0.46|0.03|< 0.01|0.51|
|% (V2 ∨ V1)|0.94|16.41|4.00|< 0.01|0.97|0.06|< 0.01|1.01|
|% (V3 ∧ S2)|< 0.01|0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|
|% (V3 ∧ S1 ∧ S2)|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|
|% (V3 ∨ V2 ∨ V1)|0.94|16.41 MDS, Random Cauchy|4.00|< 0.01|0.97|0.06|< 0.01|1.01|
|% (V2)|0.51|6.12|1.84|< 0.01|0.53|0.04|< 0.01|0.48|
|% (V2 ∧ S1)|0.50|5.29|1.76|< 0.01|0.52|0.04|< 0.01|0.47|
|% (V2 ∨ V1)|0.99|11.41|3.79|< 0.01|1.01|0.07|< 0.01|0.99|
|% (V3 ∧ S2)|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|
|% (V3 ∧ S1 ∧ S2)|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|
|% (V3 ∨ V2 ∨ V1)|0.99|11.41|3.79|< 0.01|1.01|0.07|< 0.01|0.99|

2. Now, as in the approach described in [LMR15], we keep increasing the dimension of the subspace until it stabilizes. For this purpose, we keep including *M*
*j* *· ei*to the space for the active S-box positions for *j ≥* 1. Indeed, note that if we require that *I* = *M ·I* and if *x ∈I*, it follows that *M* *j* *· x ∈I*.

3. If for every active S-box position *i* there exists a *ji≥* 1 s.t. *M*
*j* *i* +*h* *· ei∈I* for *h ≥* 1,

〈 *j j* 〉
*I* = *eι*1*,M · eι*1*,...,M · eι*1*,...,eι|I|,M · eι|I|,...,M · eι|I|*(9)

generates an infinitely long invariant subspace trail for the S-box positions in *Is*, where *j* = max(*ji*). However, if this condition is not fulfilled for some *i*, then

dim(*〈I,M · ei,...,M* *j* *i* *· ei,M* *j* *i* +1 *· ei〉*) = 1 + dim(*〈I,M · ei,...,M* *j* *i* *· ei〉*)*,*

and hence the dimension of *I* increased by 1. If the condition is never fulfilled, the largest possible dimension *t* will be reached after a finite number of iterations. In this case, it follows that no infinitely long invariant subspace trail with active S-boxes exists (apart from the trivial one) for the particular set of active S-box positions *Is* chosen in the first step.

A pseudo code for this procedure is given in Algorithm2. Note that in the first step, an input space has to be chosen based on some particular unit vectors. In the original approach [LMR15], this quickly becomes too expensive due to the large number of unit vectors in the nonlinear parts of the designs being considered. However, in our setting we focus on word-based designs, and further the number of S-boxes *s* is often small (e.g., *s* = 1 for HadesMiMC/Poseidon). Hence, we are able to determine if an invariant subspace trail with active S-boxes exists by evaluating all possibilities in a reasonable amount of time – an advantage that is not related to our algorithm, but to the setting we consider.

**Table 4:** Percentage of vulnerable matrices using Algorithm1, Algorithm2, Algorithm3

over binary fields F *t* 2

*n*. We denote by “S*x*” and “V*x*” the security and vulnerability w.r.t.
Algorithm *x*, respectively (e.g., S1 denotes security w.r.t. Algorithm1, while V2 denotes vulnerability w.r.t. Algorithm2). For Algorithm3, we use a maximum period of *l* = 2*t*.

|n|8|4|6|16|8|12|16|8|
|---|---|---|---|---|---|---|---|---|
|t|3|4|4 Random Invertible|4|8|8|8|12|
|% (V2)|0.38|6.25|1.56|< 0.01|0.42|0.02|< 0.01|0.41|
|% (V2 ∧ S1)|0.38|5.54|1.51|< 0.01|0.42|0.02|< 0.01|0.40|
|% (V2 ∨ V1)|0.75|11.80|3.01|< 0.01|0.82|0.04|< 0.01|0.81|
|% (V3 ∧ S2)|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|
|% (V3 ∧ S1 ∧ S2)|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|
|% (V3 ∨ V2 ∨ V1)|0.75|11.80 MDS, Random Cauchy|3.01|< 0.01|0.82|0.04|< 0.01|0.81|
|% (V2)|0.40|5.13|1.51|< 0.01|0.36|0.03|< 0.01|0.42|
|% (V2 ∧ S1)|0.39|4.10|1.44|< 0.01|0.36|0.03|< 0.01|0.41|
|% (V2 ∨ V1)|0.79|9.24|2.92|< 0.01|0.77|0.05|< 0.01|0.79|
|% (V3 ∧ S2)|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|
|% (V3 ∧ S1 ∧ S2)|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|< 0.01|
|% (V3 ∨ V2 ∨ V1)|0.79|9.24|2.92|< 0.01|0.77|0.05|< 0.01|0.79|

**Computational Cost of Algorithm2.** Here we analyze the computational cost of Algo- rithm2in terms of loop iterations. First, consider the loop starting in the second line, and note that there are 2 *s* *−* 1 non-empty subsets of *{*1*,...,s}*. The second loop is iterated *|Is|* times for each of these subsets. For the Do-While loop, there are two possible cases. Either it finishes if the dimension of the new *I* is equal to the dimension of the old *I*, or the dimension of *I* increased in the last iteration. Observe that the loop ends when dim (*I*) = *t*, and hence this loop is iterated at most *t −* 1 times. Consequently, the runtime of Algorithm2is an element in *O*(2 *s* *st*). Note that this runtime, even though being exponential in *s*, is not a major issue in the schemes we consider, since in these schemes the number of S-boxes per round (i.e., *s*) tends to be small.

**Computational Cost in Practice.** We used the same hardware as for the practical tests in Section5.2, i.e., an Intel Xeon E5-2699v4 with a maximum clock frequency of 3.60 GHz, together with Sage. Again, we evaluate the performance of Algorithm2when using matrices over prime fields and for *n* = 16, *t ∈{*4*,*12*}*. For *t* = 4, Algorithm2takes about 3 milliseconds. For *t* = 12, Algorithm2takes about 16 milliseconds.

#### 7.2.2 Infinitely Long Iterative Subspace Trails with Active S-Boxes

A similar algorithm can also be used to search for infinitely long iterative subspace trails with active S-boxes. Following the observations from Theorem6, in this case we need to replace the single set *Is*by *l* potentially different sets *I₁,I₂,...,Il*, where *l* is the period of the iterative subspace trail and where each of these sets denotes the positions of active S-boxes in a specific round. A pseudo code for this approach is given in Algorithm3in AppendixB.

### 7.3 Percentage of “Weak” Linear Layers

As in the case of Algorithm1, we estimate the percentage of “weak” linear layers w.r.t. Algorithm2and Algorithm3. We refer to Section5.2for a description about the matrices we used for our tests. Our sample size is 100 000, we focus on the case *s* = 1, and we used different values for *p* for each specified range. To get a better understanding of the results provided by our algorithms, we made the following distinctions:

*(1)* matrices which are vulnerable with respect to Algorithm2,
*(2)* matrices which are vulnerable with respect to Algorithm2and secure with respect to Algorithm1,
*(3)* matrices which are vulnerable with respect to Algorithm3and secure with respect to Algorithm2,
*(4)* matrices which are vulnerable with respect to Algorithm3and secure with respect to Algorithm1and Algorithm2.
Table3and Table4show the results for matrices over F*p*and F₂*n* respectively. We can immediately observe that the numbers are not very different from the numbers obtained by testing Algorithm1. Indeed, a similar amount of matrices seems to be vulnerable with respect to Algorithm2. Interestingly, when first excluding matrices detected by Algorithm1, the percentage is in most cases slightly lower but the difference is negligible. This fact suggests that using only one of the two algorithms is not sufficient in order to find all vulnerabilities. Moreover, when looking at the numbers obtained by testing Algorithm3, we can see the “rarity” of matrices which are vulnerable with respect to Algorithm3, but not vulnerable with respect to the other two algorithms (see also Section6.4). Indeed, for our sample size, the percentage for these matrices is close to zero.

## 8 Security Against Infinitely Long Subspace Trails

Until now, we presented necessary and sufficient conditions that a (highly nontrivial) linear layer must satisfy in order to prevent the existence of infinitely long subspace trails. Here, we present a sufficient condition on the matrix that defines the linear layer of the P-SPN scheme that – if satisfied – ensures that no infinitely long (invariant/iterative) subspace trail (with/without active S-boxes) exists. Finally, we list some open problems that could be interesting for future research.

### 8.1 Sufficient Condition for Preventing Infinitely Long Subspace Trails

As a final result, we propose a sufficient condition on the matrix *M* defining the linear layer of the P-SPN scheme that – if satisfied – ensures that no infinitely long (invariant/iterative) subspace trail (with/without active S-boxes) exists. This condition only involves the details of the minimal polynomial of the matrix, and it is independent of the number of S-boxes per round. At the same time, we emphasize that it is only a sufficient condition. Hence, there exist matrices which do not satisfy it but which provide security against the approaches discussed in this paper. In order to reach this goal, we first prove the following result:

**Proposition 12.** *Let φ be the minimal polynomial of an invertible matrix M ∈* F *t×t* *.*

|||t|′|
|---|---|---|---|
|′|′|′|′|
|′|t|||

*Assume that φ is irreducible and let v ∈* F *t* *\{*0*}. For each monic polynomial φ* *′* *∈* F[*x*] *such that φ* (*M*) *· v* = 0 *and* deg(*φ*) *≤* deg(*φ*)*, it follows that φ* *′* = *φ.*

Before proving the result, we mention that if *φ* is a multiple of *φ*, then deg(*φ*) *>* deg(*φ*) and *φ* (*M*) *· w* = 0 for each *w ∈* F.

*Proof.* Let *v ∈* F *t* *\{}* such that *φ* *′*

(*M*) *· v* = 0 for a certain polynomial *φ*
*′* for which deg(*φ* *′* ) *<* deg(*φ*). In such a case, *{v,M · v,...,M* deg(*φ*)*−*1 *· v}* are not linearly independent. deg(*φ* *′*

)*−*1
In particular, the subspace *V* = *〈v,M · v,...,M* ∣ *· v〉* is a proper *M*-invariant subspace of F *t*. Due to [Kai08, Prop. 2], we have that *φ*∣ *V* = *φ* *′* divides *φ*. However, this is not possible, since *φ* is irreducible. It follows that each monic polynomial *φ* *′* *∈* F[*x*] such that *φ* *′*

(*M*) *· v* = 0 and deg(*φ*
*′* ) *≤* deg(*φ*) has the same degree as *φ*. Next, we have to prove that *φ* *′* = *φ*. As before, let *v ∈* F *t* *\{*0*}* such that *φ* *′*

(*M*) *· v* = 0
for a certain monic polynomial *φ* *′* where *d* = deg(*φ* *′* ) = deg(*φ*) and *φ* *′* *6*= *φ*. It follows that there are two linear combinations of *{v,M · v,...,M* *d* *· v}* that are equal to zero, one induced by *φ* *′* and one induced by *φ* (note that they are different since *φ* *′* *6*= *φ* and since the two polynomials are monic, that is, *φ* *′* is not a multiple of *φ*). Hence, there exists a linear combination of *{v,M · v,...,M* *d−*1 *· v}* that is equal to zero. 12 Thus, there also exists a *′′ ′′* polynomial *φ* of degree strictly less than *d* for which *φ* (*M*) *· v* = 0. Such a polynomial is a nontrivial divisor of *φ*, which leads to a contradiction.

Based on this result, we can prove the following proposition.

**Proposition 13.** *Given a P-SPN scheme over* F *t* *with s S-boxes defined as in Eq.* (1)*, let* *M ∈* F *t×t* *be the invertible matrix that defines the linear layer. Assume that the S-box has* *no (nontrivial) linear structure. If the minimal polynomial φ of M has maximum degree t* *and is irreducible, there is no infinitely long invariant subspace trail with/without active* *S-boxes.*

*Proof.* Due to Proposition12and since deg(*φ*) = *t*, *for each v ∈* F *t* *\{*0*}* the vectors

*{v,M · v,M² · v,...,M* *t−*1 *· v}*

are linearly independent. Hence, there is no nontrivial subspace of F *t* that is *M*-invariant. Indeed, if *S* is an *M*-invariant subspace, then *{v,M · v,M² · v,...,M* *t−*1 *· v}* must be in *S* for each *v ∈S\{*0*}*. Since *{v,M · v,M² · v,...,M* *t−*1 *· v}* are linearly independent and since *S* is a subspace, it follows that *〈v,M · v,M² · v,...,M* *t−*1 *· v〉⊆S*, that is, dim(*S*) = *t*, which implies that *S* is a trivial subspace. Hence, there is no nontrivial subspace *S* in F *t*

that generates an infinitely long invariant subspace trail both in the case with and without active S-boxes (under the assumption that the S-box has no nontrivial linear structure).

Note that this result does not imply security against infinitely long *iterative* subspace trails with active S-boxes. Indeed, as shown in the example given in Eq. (8), there are matrices for which there exists an infinitely long iterative subspace trail with active S-boxes but no infinitely long invariant subspace trails. In order to guarantee security against all infinitely long subspace trails (under the assumption that the S-box has no nontrivial linear structure), we propose the following result.

**Theorem 8.** *Let l ≥* 1*. Given a P-SPN scheme over* F *t* *with s S-boxes defined as in* *Eq.* (1)*, let M ∈* F *t×t* *be the invertible matrix that defines the linear layer. Assume that the* *S-box has no (nontrivial) linear structure. If all the minimal polynomials of M,M²,...,M* *l*

*are of maximum degree t and irreducible, then there is no infinitely long subspace trail* *with/without active S-boxes of period less than or equal to l.*

The proof is a simple generalization of the previous results, by keeping in mind that an iterative subspace trail of period *l ≥* 2 is an *l*-round invariant subspace trail.

12E.g., if ∑*d* *αi*(*Mi· v*) = 0 and ∑*d* *β* *i* (*Mi· v*) = 0, then ∑*d−*1 (*αiβd− βiαd*)(*Mi· v*) = 0. *i*=0 *i*=0 *i*=0

**Table 5:** Percentages of Cauchy MDS matrices fulfilling the requirement in Proposition13.

Cauchy MDS matrices over F*p*

*d*log₂(*p*)*e* 8 4 6 16 8 12 16 8 *t* 3 4 4 4 8 8 8 12

<u>Secure (%) ≥ 33.79 ≥ 26.52 ≥ 24.66 ≥ 25.23 ≥ 13.42 ≥ 12.89 ≥ 12.42 ≥ 8.10</u>

Cauchy MDS matrices over F₂*n*

*n* 8 4 6 16 8 12 16 8 *t* 3 4 4 4 8 8 8 12

<u>Secure (%) ≥ 33.75 ≥ 18.93 ≥ 24.96 ≥ 25.42 ≥ 12.22 ≥ 12.34 ≥ 12.78 ≥ 8.73</u>

**Discussion.** Lastly, one may ask how many matrices satisfy the required property just given. Assume an irreducible polynomial *φ ∈* F[*x*] of degree *t*. Working with matrices over F *tq×t*, it is always possible to associate a companion matrix *C* to such a minimal polynomial, as given in Definition10(the characteristic polynomial and the minimal polynomial are equal in this case). Hence, all matrices *M similar* to *C* (i.e., all matrices *M* of the form *A* *−*1 *·C·A* for an invertible matrix *A*) satisfy Proposition13by construction. For this reason, here we focus on the case of MDS matrices. We practically evaluated the percentage of Cauchy MDS matrices which satisfy the condition given in Proposition13. The results are shown in Table5. For each of the tests, we set the sample size to 10 000. It is possible to observe that increasing the state size leads to a lower probability of the matrix to satisfy the condition given in Proposition13. In any case, we recall that the condition just given is only a *sufficient* condition, that is, a matrix does not have to satisfy it in order to provide security against the attacks studied in this paper.

### 8.2 Open Problems

As already mentioned, several problems are still open for future research. They are summarized in the following.

- The goal of this work is to guarantee that the choice of the matrix *M* prevents *infinitely long* subspace trails. As a next step, given a matrix for which no infinitely long subspace trail exists, one may ask how many rounds are needed in order to activate at least one S-box. In our practical tests regarding this issue, and when focusing on *s* = 1, we observed that *t* + *ε* rounds for *ε ∈{*0*,*1*}* are in general sufficient with high probability. We leave the open problem to find an upper bound on the number of rounds needed for reaching this goal that depends both on *(1)* the details of the matrix defining the scheme and *(2)* the number of S-boxes per round.
- If the analyzed S-box has a nontrivial linear structure (namely, there exist nontrivial linear structures *U, V* such that for each *u* there exists a certain *v* such that *S*(*U* +*u*) = *V* + *v*), then it is potentially possible to extend the result given in this paper for the case of active S-boxes in order to include this case as well.
- Here, we only considered the case of linear layers defined as invertible matrices over

|t×t|n||
|---|---|---|
|q|t|n −1|
||i,j j=1|(i,j) i,j h h=0|

F. In the binary case (i.e., *q* = 2), it could be interesting to extend our results to the case in which the linear layer *M* is defined as
∑ ∑*h* (*M* (*x*))[*i*] = *L* (*x*[*j*])*,* where *L* (*z*) = *λ · z²*

are linearized polynomials (which can be efficiently computed over a binary field) and where *z ∈* F.

**Acknowledgements.** We thank the anonymous reviewers for their valuable comments. In particular, we thank them for the hint of using the Frobenius normal form and primary decomposition theorem in order to present the results proposed in the paper, and for the suggestion regarding the condition on the linear layer given in Section8.1for preventing infinitely long subspace trails. The authors also thank Christof Beierle for shepherding this final version of the paper. Further, we thank Nathan Keller for interesting discussions regarding the topic. Lorenzo Grassi is supported by the European Research Council under the ERC advanced grant agreement under grant ERC-2017-ADG Nr. 788980 ESCADA.

## References

[AAB + 20] Abdelrahaman Aly, Tomer Ashur, Eli Ben-Sasson, Siemen Dhooghe, and Alan Szepieniec. Design of Symmetric-Key Primitives for Advanced Cryptographic Protocols. *IACR Trans. Symmetric Cryptol.*, 2020(3):1–45, 2020.

[AÅBL12] Mohamed Ahmed Abdelraheem, Martin Ågren, Peter Beelen, and Gregor Leander. On the Distribution of Linear Biases: Three Instructive Examples. In *CRYPTO 2012*, volume 7417 of *LNCS*, pages 50–67, 2012.

[AD18] Tomer Ashur and Siemen Dhooghe. MARVELlous: a STARK-Friendly Family of Cryptographic Primitives. Cryptology ePrint Archive, Report 2018/1098,

2018.
[AGP + 19] Martin R. Albrecht, Lorenzo Grassi, Léo Perrin, Sebastian Ramacher, Chris- tian Rechberger, Dragos Rotaru, Arnab Roy, and Markus Schofnegger. Feistel Structures for MPC, and More. In *Computer Security-ESORICS 2019*, volume 11736 of *LNCS*, pages 151–171, 2019.

[AGR + 16] Martin R. Albrecht, Lorenzo Grassi, Christian Rechberger, Arnab Roy, and Tyge Tiessen. MiMC: Efficient Encryption and Cryptographic Hashing with Minimal Multiplicative Complexity. In *ASIACRYPT 2016*, volume 10031 of *LNCS*, pages 191–219, 2016.

[ARS + 15] Martin R. Albrecht, Christian Rechberger, Thomas Schneider, Tyge Tiessen, and Michael Zohner. Ciphers for MPC and FHE. In *EUROCRYPT 2015*, volume 9056 of *LNCS*, pages 430–454, 2015.

[Ava17] Roberto Avanzi. The QARMA Block Cipher Family. Almost MDS Ma- trices Over Rings With Zero Divisors, Nearly Symmetric Even-Mansour Constructions With Non-Involutory Central Rounds, and Search Heuristics for Low-Latency S-Boxes. *IACR Trans. Symmetric Cryptol.*, 2017(1):4–44,

2017.
[BBI + 15] Subhadeep Banik, Andrey Bogdanov, Takanori Isobe, Kyoji Shibutani, Harunaga Hiwatari, Toru Akishita, and Francesco Regazzoni. Midori: A Block Cipher for Low Energy. In *ASIACRYPT 2015*, volume 9453 of *LNCS*, pages 411–436, 2015.

[BCD + 20] Tim Beyne, Anne Canteaut, Itai Dinur, Maria Eichlseder, Gregor Leander, Gaëtan Leurent, María Naya-Plasencia, Léo Perrin, Yu Sasaki, Yosuke Todo, and Friedrich Wiemer. Out of Oddity-New Cryptanalytic Techniques Against Symmetric Primitives Optimized for Integrity Proof Systems. In *CRYPTO* *2020*, volume 12172 of *LNCS*, pages 299–328, 2020.

[BCDM20] Tim Beyne, Yu Long Chen, Christoph Dobraunig, and Bart Mennink. Dumbo, Jumbo, and Delirium: Parallel Authenticated Encryption for the Lightweight Circus. *IACR Trans. Symmetric Cryptol.*, 2020(S1):5–30, 2020.

[BCLR17] Christof Beierle, Anne Canteaut, Gregor Leander, and Yann Rotella. Proving Resistance Against Invariant Attacks: How to Choose the Round Constants. In *CRYPTO 2017*, volume 10402 of *LNCS*, pages 647–678, 2017.

[BDD + 15] Achiya Bar-On, Itai Dinur, Orr Dunkelman, Virginie Lallemand, Nathan Keller, and Boaz Tsaban. Cryptanalysis of SP Networks with Partial Non- Linear Layers. In *EUROCRYPT 2015*, volume 9056 of *LNCS*, pages 315–342,

2015.
[Bey18] Tim Beyne. Block Cipher Invariants as Eigenvectors of Correlation Matrices. In *ASIACRYPT 2018*, volume 11272 of *LNCS*, pages 3–31, 2018.

[BJK + 16a] Christof Beierle, Jérémy Jean, Stefan Kölbl, Gregor Leander, Amir Moradi, Thomas Peyrin, Yu Sasaki, Pascal Sasdrich, and Siang Meng Sim. The SKINNY Family of Block Ciphers and Its Low-Latency Variant MANTIS. In *Advances in Cryptology-CRYPTO 2016*, volume 9815 of *LNCS*, pages 123–153, 2016.

[BJK + 16b] Christof Beierle, Jérémy Jean, Stefan Kölbl, Gregor Leander, Amir Moradi, Thomas Peyrin, Yu Sasaki, Pascal Sasdrich, and Siang Meng Sim. The SKINNY Family of Block Ciphers and its Low-Latency Variant MANTIS. Cryptology ePrint Archive, Report 2016/660, 2016. [https://eprint.iacr](https://eprint.iacr). org/2016/660.

[BLN17] Céline Blondeau, Gregor Leander, and Kaisa Nyberg. Differential-Linear Cryptanalysis Revisited. *Journal of Cryptology*, 30(3):859–888, 2017.

[BS91] Eli Biham and Adi Shamir. Differential Cryptanalysis of DES-like Cryptosys- tems. *Journal of Cryptology*, 4(1):3–72, 1991.

[BS93] Eli Biham and Adi Shamir. *Differential Cryptanalysis of the Data Encryption* *Standard*. Springer, 1993.

[CCF + 18] Anne Canteaut, Sergiu Carpov, Caroline Fontaine, Tancrède Lepoint, María Naya-Plasencia, Pascal Paillier, and Renaud Sirdey. Stream Ciphers: A Practical Solution for Efficient Homomorphic-Ciphertext Compression. *J.* *Cryptology*, 31(3):885–916, 2018.

[DEG + 18] Christoph Dobraunig, Maria Eichlseder, Lorenzo Grassi, Virginie Lallemand, Gregor Leander, Eik List, Florian Mendel, and Christian Rechberger. Rasta: A Cipher with Low ANDdepth and Few ANDs per Bit. In *CRYPTO 2018*, volume 10991 of *LNCS*, pages 662–692, 2018.

[DEMS19] Christoph Dobraunig, Maria Eichlseder, Florian Mendel, and Martin Schläffer. ASCON v1.2. NIST Lightweight Cryptography Finalist (2021), CAESAR Finalist, 2019.

[DGGK19] Christoph Dobraunig, Lorenzo Grassi, Anna Guinet, and Daniël Kuijsters. Ciminion: Symmetric Encryption Based on Toffoli-Gates over Large Finite Fields. In *EUROCRYPT 2021*, LNCS, 2019.

[DKP + 19] Itai Dinur, Daniel Kales, Angela Promitzer, Sebastian Ramacher, and Chris- tian Rechberger. Linear Equivalence of Block Ciphers with Partial Non-Linear Layers: Application to LowMC. In *EUROCRYPT 2019*, volume 11476 of *LNCS*, pages 343–372, 2019.

[DLMW15] Itai Dinur, Yunwen Liu, Willi Meier, and Qingju Wang. Optimized Interpola- tion Attacks on LowMC. In *ASIACRYPT 2015*, volume 9453 of *LNCS*, pages 535–560, 2015.

[DPAR00] Joan Daemen, Michaël Peeters, Gilles Van Assche, and Vincent Rijmen. Nessie Proposal: NOEKEON, 2000.

[DR02] Joan Daemen and Vincent Rijmen. AES and the Wide Trail Design Strategy. In *EUROCRYPT 2002*, volume 2332 of *LNCS*, pages 108–109, 2002.

[GGNPS13] B. Gérard, Vincent Grosso, M. Naya-Plasencia, and François-Xavier Stan- daert. Block Ciphers That Are Easier to Mask: How Far Can We Go? In *Cryptographic Hardware and Embedded Systems-CHES 2013*, volume 8086 of *LNCS*, pages 383–399, 2013.

[GKR + 19] Lorenzo Grassi, Dmitry Khovratovich, Christian Rechberger, Arnab Roy, and Markus Schofnegger. Poseidon: A New Hash Function for Zero-Knowledge Proof Systems. Cryptology ePrint Archive, Report 2019/458, 2019.

[GKR + 21] Lorenzo Grassi, Dmitry Khovratovich, Christian Rechberger, Arnab Roy, and Markus Schofnegger. Poseidon: A New Hash Function for Zero-Knowledge Proof Systems. In *30th USENIX Security Symposium (USENIX Security 21)*. USENIX Association, 2021.

[GLR + 20a] Lorenzo Grassi, Gregor Leander, Christian Rechberger, Cihangir Tezcan, and Friedrich Wiemer. Weak-Key Distinguishers for AES. In *SAC*, LNCS. Springer, 2020.

[GLR + 20b] Lorenzo Grassi, Reinhard Lüftenegger, Christian Rechberger, Dragos Rotaru, and Markus Schofnegger. On a Generalization of Substitution-Permutation Networks: The HADES Design Strategy. In *EUROCRYPT*, volume 12106 of *LNCS*, pages 674–704, 2020.

[GLSV14] Vincent Grosso, Gaëtan Leurent, François-Xavier Standaert, and Kerem Varici. LS-Designs: Bitslice Encryption for Efficient Masked Software Imple- mentations. In *Fast Software Encryption-FSE 2014*, volume 8540 of *LNCS*, pages 18–37, 2014.

[GRR16a] Lorenzo Grassi, Christian Rechberger, and Sondre Rønjom. Subspace Trail Cryptanalysis and its Applications to AES. *IACR Trans. Symmetric Cryptol.*, 2016(2):192–225, 2016.

[GRR + 16b] Lorenzo Grassi, Christian Rechberger, Dragos Rotaru, Peter Scholl, and Nigel P. Smart. MPC-Friendly Symmetric Key Primitives. In *ACM SIGSAC* *Conference on Computer and Communications Security – 2016*, pages 430–443. ACM, 2016.

[GRR17] Lorenzo Grassi, Christian Rechberger, and Sondre Rønjom. A new structural- differential property of 5-round AES. In *EUROCRYPT 2017*, volume 10211 of *LNCS*, pages 289–317, 2017.

[HL20] Phil Hebborn and Gregor Leander. Dasta-Alternative Linear Layer for Rasta. *IACR Trans. Symmetric Cryptol.*, 2020(3):46–86, 2020.

[Hog16]Leslie Hogben.

[Kai08]

[Knu94]

[KPP + 17]

[KR21]

[LAAZ11]

[LMR15]

[LTW18]

[Mat93]

[MJSC16]

[Nag51]

[PRC12]

[PW20]

[Sto98]

[TLS16]

[WWGY14]

[YMT97]

*Handbook of Linear Algebra*. CRC Press, 2nd edition, 2016.

Klaus Kaiser. Advanced Linear Algebra. [https://www.math.uh.edu/](https://www.math.uh.edu/) ~klaus/Advanced%20Linear%20Algebra_rev.pdf, 2008.

Lars R. Knudsen. Truncated and Higher Order Differentials. In *Fast Software* *Encryption – FSE 1994*, volume 1008 of *LNCS*, pages 196–211, 1994.

Daniel Kales, Léo Perrin, Angela Promitzer, Sebastian Ramacher, and Chris- tian Rechberger. Improvements to the Linear Layer of LowMC: A Faster Picnic. Cryptology ePrint Archive, Report 2017/1148, 2017.

Nathan Keller and Asaf Rosemarin. Mind the Middle Layer: The HADES Design Strategy Revisited. In *EUROCRYPT 2021*, LNCS. Springer, 2021.

Gregor Leander, Mohamed Ahmed Abdelraheem, Hoda AlKhzaimi, and Erik Zenner. A Cryptanalysis of PRINTcipher: The Invariant Subspace Attack. In *CRYPTO 2011*, volume 6841 of *LNCS*, pages 206–221, 2011.

Gregor Leander, Brice Minaud, and Sondre Rønjom. A Generic Approach to Invariant Subspace Attacks: Cryptanalysis of Robin, iSCREAM and Zorro. In *EUROCRYPT 2015*, volume 9056 of *LNCS*, pages 254–283, 2015.

Gregor Leander, Cihangir Tezcan, and Friedrich Wiemer. Searching for Subspace Trails and Truncated Differentials. *IACR Trans. Symmetric Cryptol.*, 2018(1):74–100, 2018.

Mitsuru Matsui. Linear Cryptanalysis Method for DES Cipher. In *EURO-* *CRYPT 1993*, volume 765 of *LNCS*, pages 386–397, 1993.

Pierrick Méaux, Anthony Journault, François-Xavier Standaert, and Claude Carlet. Towards Stream Ciphers for Efficient FHE with Low-Noise Ciphertexts. In *EUROCRYPT 2016*, volume 9665 of *LNCS*, pages 311–343, 2016.

T. Nagell. Euler’s Criterion and Legendre’s Symbol. Introduction to Number Theory, 1951. Gilles Piret, Thomas Roche, and Claude Carlet. PICARO-A Block Cipher Allowing Efficient Higher-Order Side-Channel Resistance. In *Applied Cryp-* *tography and Network Security-ACNS 2012*, volume 7341 of *LNCS*, pages 311–328, 2012. Thomas Peyrin and Haoyang Wang. The MALICIOUS Framework: Embed- ding Backdoors into Tweakable Block Ciphers. In *CRYPTO 2020*, volume 12172 of *LNCS*, pages 249–278, 2020. Arne Storjohann. An *O*(*n*
3) algorithm for the frobenius normal form. In
*ISSAC*, pages 101–105. ACM, 1998.

Yosuke Todo, Gregor Leander, and Yu Sasaki. Nonlinear Invariant Attack

- Practical Attack on Full SCREAM, iSCREAM, and Midori64. In *ASI-* *ACRYPT 2016*, volume 10032 of *LNCS*, pages 3–33, 2016. Yanfeng Wang, Wenling Wu, Zhiyuan Guo, and Xiaoli Yu. Differential Cryptanalysis and Linear Distinguisher of Full-Round Zorro. In *ACNS 2014*, volume 8479 of *LNCS*, pages 308–323, 2014.
A. M. Youssef, S. Mister, and S. E. Tavares. On the Design of Linear Transformations for Substitution Permutation Encryption Networks. In *Selected Areas in Cryptography-SAC 1996*, pages 40–48, 1997.

## A Truncated Differentials and Subspace Trails

Differential attacks [BS91] exploit the fact that pairs of inputs with certain differences yield other differences in the corresponding outputs with a probability distribution that is different from that one would expect from a random permutation. A variant of this attack/distinguisher is the truncated differential one [Knu94], in which the attacker can predict only part of the difference between pairs of texts. Using the subspace terminology, given pairs of inputs that belong to the same coset of a subspace *X*, one considers the probability that the corresponding outputs belong to the same coset of a subspace *Y* to set up an attack (see e.g. [BLN17] for details). In particular, note that two texts *x,y ∈* F *t*

are in the same coset of a given subspace (i.e., there exists *v ∈* F *t* such that *x,y ∈V* + *v*) if and only if their difference belongs to such a subspace (i.e., *x − y ∈V*). The relation between truncated differential trails and subspace trails has been studied in details in [LTW18,BLN17].

### Proof of Proposition10

As done before, in the following we omit the round keys and the constant additions (we recall that they only change the cosets, while here we deal with differences). The subspace trail defined over the first R rounds is already analyzed in Section3.1. By definition of R, at least one S-box is active after R rounds. It follows that the only way to extend the trail is by increasing the dimension of such a subspace, that is, () 〈 〉 *R M* R*−*1 *·S*

(R) *⊆A*
(1) = *M* R *·S*
(R) *,M*(*e₁*)*,...,M*(*es*)*.*
Indeed, the only thing one can do is to consider the biggest subspace for which

|〈||〉|
|---|---|---|
|||(R)|
|1|s||
|Due to S-boxes|Due to identity part||

() S-box *M*

(R) *·S*
(R) *⊆ e*<u>,e₂,...,e</u>*, M*
︸ R ︷︷ *·S* ︸ *.* ︸ ︷︷ ︸

In this way, we lose information about the output of the S-box layer (while nothing changes for the part of the identity layer), but we can extend the subspace trail. Working in the () 〈 〉 same way, it follows that *R A*

(1) *⊆ A*
(2) = *M ·A*
(1) *,M*(*e₁*)*,...,M*(*es*), and, more
generally, ()

(*r*) (*r*+1)
〈

(*r*)
〉 *R A ⊆A* = *M ·A,M*(*e₁*)*,...,M*(*es*)*.*

This step can be repeated as long as the dimension of the subspace is smaller than *t*. Since for a generic scheme the dimension of *S*

(R) is *s* and the dimension increases by
⌊ ⌋ *s* in each additional round, the dimension remains smaller than *t* for up to R + <u>t−</u> *s* <u>s</u> rounds.

**Remark.** Due to the relation between subspace trails and truncated differentials [LTW18] mentioned before, it is possible to set up a truncated differential distinguisher on at least ⌊ ⌋ R + <u>t−</u> *s* <u>s</u> rounds with probability 1. We stress that the details of the construction (e.g., the S-box, the linear layer, the key schedule) can potentially be used to improve the ⌊ ⌋ previous attacks. That is, R + <u>t−</u> *s* <u>s</u> rounds refer only to the “basic” variants of such attacks, and this number must be considered only as a lower bound in order to provide security. Hence, we do not discuss the minimum number of rounds necessary to provide security against these attacks, since they strongly depend on the details of the linear layer.

## B Infinitely Long Iterative Subspace Trails with Active S-Boxes

In this section, we give the algorithm using the results described in Section7.2.2for a maximum period of *l* = 2*t*.

**Algorithm 3:** Determining the existence of (iterative) infinitely long subspace trails with *active* S-boxes of period at most *l ≥* 2 based on [LMR15] and Theorem6. **Data:** P-SPN scheme over F *t* with *s* S-boxes applied to the first *s* words (where the S-box has no linear structure). **Result:** 1 if (iterative) infinitely long iterative subspace trail with *active* S-boxes (of period at most *l ≥* 2) is found, 0 otherwise. **1** *flag ←* 0. **2** *T ←∅*. // *T* stores all iterative subspace trails found **3 for** *r ←* 2 **to** *l* **do**
**4 foreach** *I ⊆{*1*,*2*,...,s} (where I* := *{ι₁,...,ι|I|} and I 6*= *∅)* **do**
**5** Apply Algorithm2to *M* *r*, and let *I* be the resulting “invariant” subspace trail with active S-boxes in *I*, or let *I* = *∅* if such a trail does not exist. //Check for a meaningful iterative subspace trail **6 if** dim(*I*) *≥* 1 **then** **7 if** *I* = *M ·I (i.e., the subspace trail is invariant)* **then** **8 break** (move to next *r*) **9** *I*

(1) *←∅,I*
(2) *←∅,...,I*
(*r−*1) *←∅*. **10 for** *j ←* 1 **to** *r −* 1 **do** **11** *I← M ·I*. **12 for** *i ←* 1 **to** *s* **do** **13** *E*

(*i*)
*←〈e₁,...,ei−*1*,ei*+1*,...,es,es*+1*,...,et〉*.
**14 if** *I∩E*

(*i*) *6*= *I (eq., I6⊆E*
(*i*) *)* **then**
**15 if** *I∩〈ei〉* = *〈ei〉* **then** **16** *I*

(*j*) *← I*
(*j*) *∪{i}*.
**17 else** **18 break** (move to next *r*) **19** *flag ←* 1. **20** *T ← T ∪{I,r, {I,I*

(1) *,I*
(2) *,...,I* (*r−*1)
*}}*. //In the case *flag* = 0 (hence, *T* = *∅*), no infinitely long iterative subspace trail (of period *≤ l*) was found. **21 return** *flag: infinitely long iterative subspace trails T with active S-boxes* *found.*

**Computational Cost of Algorithm3.** We mainly focus on loop iterations for the indicator of the final cost. First, we fix the maximum period *l* of the iterative non-invariant subspace trail. Now, Algorithm2is run *l −* 1 times. After that, the next loop is iterated *l* *′* *−*1 times for each *l* *′* *∈{*2*,...,l}*, leading to a total number of repetitions of at most <u>l(l+1)</u> 2. Finally, the last loop is iterated *s* times. Operation costs inside these iterations are negligible. This leads to the total runtime being an element in *O* (*ls* (2 *s* *t* + *l*)), which is not a major issue in the schemes we consider, since in these schemes the number of S-boxes per round (i.e.,

*s*) tends to be small. **Computational Cost in Practice.** We used the same hardware as for the practical tests in Section5.2, i.e., an Intel Xeon E5-2699v4 with a maximum clock frequency of 3.60 GHz. Again, we evaluate the performance of Algorithm3when using matrices over prime fields and for *n* = 16, *t ∈{*4*,*12*}*, and *l* = 2*t*. For *t* = 4, Algorithm3takes about 40 milliseconds. For *t* = 12, Algorithm3takes about 1 second.

## C Results Using our Tool and More Examples of Subspace Trails with Active S-Boxes

### C.1 Starkad and Poseidon Matrices

In addition to the statistical tests described in Section5, we also used our tool for the Cauchy matrices using specific starting sequences defined for Starkad and Poseidon + *′* *′′* [GKR 21]. We recall that the matrix *M* over F₂*n* for Starkad and the matrix *M* over F*p*for Poseidon are defined by

*′*<u>1</u> *′′* <u>1</u> *Mi,j*= and *Mi,j*=*,* (10) *xi⊕ yjxi*+ *yj*

where *xi*= *i*, *yi*= *i* + *t*, and *i ∈* [0*,t −* 1].

**Table 6:** Vulnerable matrices for Algorithm1and orders *t* and field sizes *n* = *d*log₂(*p*)*e*

when considering the Starkad and Poseidon specifications.

#### Poseidon Specification (over Fp)

*d*log₂(*p*)*e* 8 4 6 16 8 12 16 8 *t* 3 4 4 4 8 8 8 12

Vulnerable No No No No No No No No

#### Starkad Specification (over F₂n)

*n* 8 4 6 16 8 12 16 8 *t* 3 4 4 4 8 8 8 12

<u>Vulnerable No Yes Yes Yes Yes Yes Yes Yes</u>

**Comparison with Related Results.** When using our tool for matrices with various sizes (i.e., different values for *t*), we can observe that some matrices over F₂*n* (i.e., the matrices used for Starkad) are vulnerable to the attacks described in this paper. We can also observe, however, that matrices over F*p*using the same *t* values are not vulnerable. The detailed results for some instances are shown in Table6. These results are not new in the literature, since similar conclusions have already been shown in [KR21, BCD + 20]. Moreover, in [KR21] the authors explain how to modify the choice of *xi*and *yj*in Eq. (10) in order to fix this problem. This solution consists in changing the starting sequences for the Cauchy generation method. For completeness, we also tested our algorithm for the matrices suggested in [KR21]. As expected, we arrive at the same conclusion, namely, that it is not possible to set up infinitely long subspace trails without active S-boxes for the Cauchy matrices proposed in [KR21].

### C.2 Zorro Matrix

We also evaluated the Zorro [GGNPS13] matrix with our tool. Zorro is a variant of AES where only 4 S-boxes (at the first row) are applied per round. In our setting, Zorro is 8 16 a P-SPN scheme over (F₂) with *s* = 4 where the linear layer is defined by a 16 *×* 16 matrix, where 8 16 *∀x ∈* (F₂) : *M*Zorro*· x* := *MC · SR · x,*

|where|||||
|---|---|---|---|---|
||||I 0 SR =   0 0|0 0 0 I₂ 0 0   , 0 I₃ 0 0 0 I₄|
|where I is the 4||||× 4 null matrix, and|
|||| |  |
|0|1|0|0 0|0 1 0 0 0 0 1|
|0|0|1|0 0|0 0 1 1 0 0 0|
|I₂ =  ||| , I₃ =  | , I₄ =    ,|
|0|0|0|1 1|0 0 0 0 1 0 0|
|1|0|0|0 0|1 0 0 0 0 1 0|
|and where where again I||| 2 · I 3 · I MC =   I I| · I I I I I 2 · I   , I 2 · I 3 · I · I 3 · I I ≡X∈ F₂ 8 and 3 ≡ X + 1 ∈ F₂ 8.|
|||||13|
|13|||||
|subspace trails.|||||

*×* 4 identity matrix, 0 is the 4

is the 4 *×* 4 identity matrix, and where 2 As expected, using our tool, we found that there exists no infinitely long (iterative or invariant) subspace trail for this matrix, neither with nor without active S-boxes.

We recall that the statistical attacks on Zorro [WWGY14] exploit the existence of differentials with a probability higher than what was expected by the designers, and not the existence of infinitely long
