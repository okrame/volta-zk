# Private Polynomial Commitments and Applications to MPC

Rishabh Bhadauria¹, Carmit Hazay¹ *,*3, Muthuramakrishnan Venkitasubramaniam² *,*3, Wenxuan Wu⁴, and Yupeng Zhang⁴

1 Bar Ilan University, Israel 2 Georgetown University, USA 3 Ligero Inc 4 Texas A&M University

Abstract. Polynomial commitment schemes allow a prover to commit to a polynomial and later reveal the evaluation of the polynomial on an arbitrary point along with proof of validity. This object is central in the design of many cryptographic schemes such as zero-knowledge proofs and verifiable secret sharing. In the standard definition, the polynomial is known to the prover whereas the evaluation points are not private. In this paper, we put forward the notion of *private polynomial commitments* that capture additional privacy guarantees, where the evaluation points are hidden from the verifier while the polynomial is hidden from both. We provide concretely efficient constructions that allow simultaneously batch the verification of many evaluations with a small additive over- head. As an application, we design a new concretely efficient multi-party private set-intersection with malicious security and improved asymptotic communication and space complexities. We demonstrate the concrete efficiency of our construction via an imple- mentation. Our scheme can prove 2 10 evaluations of a private polynomial of degree 2 10 in 157s. The proof size is only 169KB and the verification time is 11.8s. Moreover, we also implemented the multi-party private set intersection protocol and scale it to 1000 parties (which has not been shown before). The total running time for 2 14 elements per party is 2,410 seconds. While existing protocols offer better computational complexity, our scheme offers significantly smaller communication and better scala- bility (in the number of parties) owing to better memory usage.

### 1 Introduction

A polynomial commitment is a cryptographic building block that allows a prover to commit to a polynomial, which can later be opened at any evaluation point with proof that the evaluation is correctly computed. Polynomial commitments, which serve as an important building block in constructing cryptographic pro- tocols, were introduced by Kate et al. [49] for the construction of verifiable secret sharing in the synchronous and asynchronous setting [6]. The scheme

was generalized to multivariate polynomials by Papamanthou et al. [54], and to zero-knowledge proofs of knowledge by Zhang et al. [72]. In recent years, they are extensively used to build efficient zero-knowledge proof systems [71,65,68, 62,34,24], where recent new schemes without a trusted setup were proposed in [65,70,16,64,50]. Subsequent works considered batched openings for mul- tiple evaluations [63] and multiple polynomials [40]. Another application where polynomial commitments are utilized is “Proof of retrievability” [48,69]. In this problem, the server wishes to prove to a verifier that all of the client’s data is stored correctly. The polynomial commitment allow the prover to prove the integrity of the data storage. Logarithmic and constant size polynomial commit- ments are also used in constructing vector commitments [19,18,23]. To date, all concretely efficient polynomial commitments require the verifier to know the evaluation point and the prover to know the polynomial. While such a notion is sufficient to design succinct zero-knowledge arguments, secure multi- party computation (MPC) requires additional privacy guarantees. In this paper, we consider a different setting where the polynomial is unknown to the prover and is encrypted. Moreover, the evaluation points are committed by the prover and may not be publicly known to the verifier. This setting is very common in MPC where both the polynomial and the evaluation points must remain private as they are defined based on the parties’ inputs. We denote this primitive by *private* *polynomial commitment* and show that it can be used as a building block in many applications that arise in the secure multi-party setting; see Sections1.1and5. Our scheme is particularly useful in batch scenarios when there are multiple evaluation points. In this case, the proof size and verifier’s complexity grow additively with the number of points.

1.1 Our Contributions Our contribution is threefold. (1) abstracting the new notion of private polyno- mial commitments and providing two constructions. (2) demonstrating its appli- cability for MPC and (3) implementing our commitment schemes and presenting a new multi-party private set-intersection (MPSI) protocol. Private Polynomial Commitments Our contribution includes two flavours of private polynomial commitments with a hidden (encrypted) polynomial; one where the evaluation points are public and the other where they are private. Our schemes are built on the recent scheme of an inner product argument [17], which generalizes the inner product argument from [15] to bilinear groups. Specifically, we embed the ciphertexts encrypting the coefficients in the base group using an Additively Homomorphic Encryption (AHE) scheme introduced in [13]. Working with bilinear maps allow to publicly verify a single multiplication in the exponent which allows any party to verify the proof. More specifically, for a polynomial of degree *d*, the overhead is dominated by *O*(*d*) bilinear pairings whereas the proof size is *O*(log*d*) and the verifier time is *O*(*d*) exponentiations. Our construction supports batched evaluations efficiently. To open at *m* evaluation points, the
2

proof size is *O*(*m*+ log*d*) and the verifier time is only *O*(*m* + *d*). The polynomial is hidden from all parties and only an encrypted form is available to the prover. Our constructions rely on two different commitment schemes for committing to the encrypted polynomial (using the pairing-based scheme from [4]) and the evaluation points (using Pedersen commitment [55]). We further rely on the Boneh et al. pairing-based encryption scheme [13] to be compatible with our pairing-based commitment scheme, both of which rely on the Decisional Linear Assumption (DLIN) and Double Pairing Problem (DPP). Our commitment scheme uses an inner product argument [15] as a building block (denoted by BBB-IPA) and is the first polynomial commitment scheme where the prover does not know the actual polynomial and only has access to its encryption. The main challenge in constructing this commitment scheme was the integration of encrypted polynomials into the polynomial commitment scheme. Secondly, directly constructing a scheme would not provide batching. To ensure batching and overall small proof size, we reduce the proving of the polynomial evaluation to multiple inner products. First, we provide a new inner product ar- gument that allows the prover to verify inner products on encrypted ciphertext with the evaluation vector. Second, we prove the correct structure of multiple evaluation vectors by verifying the linear and quadratic constraints. Both our linear and quadratic tests reduce the multiple constraints on all different eval- uation vectors to verify a single inner product argument, thereby ensuring the batching feature is effective. An additional feature is that the proof can be made non-interactive using Fiat-Shamir.

Applications Private polynomial commitment schemes are useful for private computations based on polynomials. We list four such applications that can benefit from the scalability and batching of the evaluations as inherent in our commitment scheme. Firstly, we use our new private polynomial commitment as a building block to present a new scalable multi-party PSI protocol that is secure against malicious adversaries. We also discuss three other applications-Oblivious Polynomial Evaluation, Verifiable Polynomial Evaluation, and Non- Interactive two-party PSI; for more details see Section5. Scalable multi-party private set-intersection (MPSI). PSI is a funda- mental problem in secure computation that has been widely studied in the past
decade. In this problem a set of parties *P₁,...,Pn*, holding input sets *X₁,...,Xn*
of sizes *m₁,...,mn*, respectively, wish to compute *X₁ ∩ X₂ ∩... ∩ Xn*. The two-
party setting has been studied extensively and continues to be a hot topic of research owing to numerous applications such as contact discovery, dating ser- vices, data mining, recommendation systems, and law enforcement. In a long line of works, highly efficient two-party protocols have been designed with al- most linear overhead in the set sizes (see some recent works at [58,56,57,22] and references therein). Furthermore, Google has recently leveraged this technology to match login credentials against an encrypted database. While considerable progress has been made in the two-party setting, very few works have explored the concrete efficiency of PSI in the multi-party setting and the existing works have mostly considered only the semi-honest setting. Further-

more, current approaches fail to achieve overheads as in the two-party setting and do not scale well due to communication and space bottlenecks. Multiparty PSI is a fundamental cryptographic primitive with a richer set of applications beyond the two-party ones such as distributed intrusion detection, identifying the most visited sites or watched movies, contact tracing and more. Our starting point is the work of Freedman et al. [33] who designed a simple two-party PSI protocol based on polynomials. Roughly speaking, *P₁* creates a polynomial *Q*(*·*) whose roots correspond to its input data set and sends this poly- nomial to *P₂*, encrypted under an additively homomorphic encryption scheme. *P₂* homomorphically evaluates a “masked” variant of the encrypted polynomial on its data set. In more detail, for each element *x* in *P₂*’s input set, *P₂* generates fresh randomness *r* and sends an encryption of *r ·Q*(*x*)+*x* to *P₁*. *P₁* decrypts and identifies the elements in the set intersection. Namely, if the decrypted value *x* is in *P₁*’s set, then *x* is extracted from the decryption of the ciphertext. Whereas if the item *x* is not in the intersection, with very low probability, there exists an element *z* for which *r · Q*(*z*) + *z* is a false positive. More recently, Hazay and Venkitasubramaniam [46] extended [33] to the multi-party setting by reducing the multi-party PSI (MPSI) task among *n* par- ties to *n* instances of two-party PSI. In this work we explore the practicality of [46] in the malicious setting where up to *n −* 1 parties can be corrupted. On a high level, in [46], parties *P₂,...,Pn*create a polynomial whose roots cor- respond to their respective inputs and send their encrypted coefficients to *P₁*. *P₁* then aggregates the polynomials and homomorphically evaluates the result- ing encrypted polynomial on its input set. To make the protocol secure against malicious adversaries, [46] introduced a simple mechanism for *P₁* to prove and the parties to verify that *P₁* aggregated the polynomials correctly, and relied on zero-knowledge proofs for the remaining steps. The protocol presented in [46] implies an overall communication complexity of *O*(*n²* +*n · m*max+*n · m*min*·*log*m*max) where *m*max(resp. *m*min) is the size of the largest (resp. smallest) input set. The threshold key generation incurs a com- munication cost of *O*(*n²*). The central party aggregates the input polynomials of all the parties and returns the encrypted coefficients of the aggregated poly- nomial. This yields a communication overhead of *O*(*n · m*max). The main source of overhead is due to the zero-knowledge proof applied by the central party for proving correct evaluation, which implies an overhead of *O*(*n · m*min*·*log*m*max). This phase is captured in our protocol by private polynomial commitments. More precisely, in this work, we introduce a variant of [46] where we rely on a new abstraction that is based on private polynomial commitments. By leveraging the efficiency and batching features of our commitment schemes, we manage to improve the communication and computation complexities of [46]. We further provide an implementation of our PSI protocol and explore its concrete efficiency. This is in contrast to [46] which had the potential of being concretely efficient but did not provide an implementation.

The complexity of our protocol. In addition to our new abstraction, we P 2 *n* further improve the asymptotic complexity of [46] to *O*(*n* +*i*=1*mi*+*n·*(*m*min+

log*m*max)). Introducing private polynomial commitments (PPC) as a building block, the central party in our protocol does not send the encrypted aggregated polynomial. Instead, a commitment of encrypted aggregated polynomials is sent to the parties. This allows us to remove the *O*(*n · m*max) factor. To further reduce the communication complexity, we leverage the batching feature of PPC which allows the central party to prove the correctness of multiple evaluations on the aggregated polynomial. The proof size, in this case, is *O*(*m*min+log*m*max) which contributes an additive factor of *O*(*n ·*(*m*min+ log*m*max)) to the communication complexity of our MPSI protocol. A detailed analysis is provided in Table3 where the communication complexity is broken according to the central party overhead and the other parties and is presented for each phase separately.

Comparison with recent work. Three recent works that design PSI proto- cols with malicious security are [9,36,41]. Similarly to our work, these works also achieve linear communication complexity in the number of parties by re- lying on a star topology. The main advantage of these protocols is that they rely on oblivious transfer (OT), oblivious linear evaluation (OLE) (used in [41]) and symmetric-key primitives for which we have very efficient instantiations. In comparison to previous work [9,36,41], our protocol achieves the best commu- nication and space complexities. Specifically, our communication complexity is dominated by the term *O*(*n²κ* + *nmκ*) where the gain compared to previous work is due to an aggregation of the encrypted input polynomials and the small batched proof size. We compare the communication complexity in Table1. In the typical parameter regime, the computational security parameter *κ* is greater than the statistical parameter *λ* satisfying the inequality *λ*+ log *m < κ* where *m* is the input set size. Applying this inequality to the asymptotic communication complexity of [36] yields communication complexity that matches ours. Most MPSI protocols (including ours) are designed for a star topology, where a central party aggregates the other parties’ messages and therefore requires larger space. In prior works, the space complexity of the central party is inflated with a factor that depends both on the input and the number of parties, whereas our space complexity only grows with *O*(*mκ*). The space complexity of the other, “non-central” parties, is independent of the number of parties. We compare the space complexity in Table2 Our paper realizes a standard MPSI functionality where a single party (typ- ically the central party) receives the output, but can be extended to guarantee security even when all parties receive the output. Both [41] and our protocol achieve this standard security whereas the works of [9,36] provide a weaker se- curity guarantee that allows the party that first receives the output (if controlled by the adversary) to unnoticeably remove certain elements from the output when broadcasting it to all parties. Note that these protocols can achieve full security, but this will require applying general-purpose zero-knowledge proofs. On the other hand, the computational cost of [9,36,41] grows with *Ω*(*mnκ*) field multiplications, while the dominating cost of our computation is *O*(*m²*) exponentiations. This can be further reduced into *O*(*m* log log <u>log m</u> *m* ) using hashing. While for a small number of parties, our protocol is slower, the total running

||P₁ P i|Total|
|---|---|---|
|[9]|O (nmκ² + nmκ log mκ) O (mκ² + mκ log mκ) O (|nmκ² + nmκ log mκ)|
|[36]|O (nκ + nm (κ + λ + log m)) O (nκ + m (κ + λ + log m)) O (n² κ|+ nm (κ + λ + log m))|
|[41]|O (nmκ + nλκ log m) O ((n + m) κ + λκ log m) O (n² κ|+ nmκ + nλκ log m)|
|Theorem2|O (nmκ) O ((n + m) κ)|O (n² κ + nmκ)|
|the number of parties, central party. parties and 2|Table 1: The communication complexity analysis of MPSI in bits where computational security parameter, λ is the statistical security parameter, m is an upper bound on the inputs set sizes and time essentially remains the same when the number of parties increases. For instance, our experiments show that our scheme takes 9,141 seconds for 1000 16 elements per party. Prior works cannot run at this scale. We highlight some applications which require PSI for a large number of parties and large input sizes: (1) Cache-sharing [53] involves multiple network providers who wish to cache common elements with high access frequency in a shared cache and require privacy of their local cache. (2) Another application is to generate statistics over the Tor network. Prior literature e.g., [27,66] has relied on MPC, secure aggregation and differential privacy to generate statistics on Tor servers in a privacy-preserving manner. Large-scale MPSI can be useful here where common features need to be extracted among the relay servers without compromising the users’ privacy. (3) Hospitals and healthcare providers can collaborate to analyze common features between databases which include a large number of medical records. (4) Finally, MPSI can be applied for contact tracing. A large group of patients can execute an MPSI protocol to find common locations they have been to without leaking each individual’s travel history. The result can help the actions of testing or quarantine in these areas. P₁ P i [9] O (nmκ² + mκ log mκ) O (mκ²) [36] O (nmκ + m (κ + λ + log m)) O (m (κ + λ + log m)) [41] O (nmκ) O (mκ) Theorem2 O (mκ) O (mκ)|κ is the n is P₁ is the|

Table 2: The space complexity analysis of MPSI *in bits* where *κ* is the compu-

tational security parameter, *n* is the number of parties, *m* is an upper bound on the inputs set sizes and *P₁* is the central party.

Private polynomial commitments are also useful for reusable non-interactive two-party PSI. Non-interactive secure computation introduced in [47], considers a “receiver” that publicly broadcasts a single message and any “sender” can in- teract in a two-party secure computation protocol with the receiver by sending a single message to the receiver. The receiver only needs to broadcast once and

any number of interactions with the receiver can be performed. Specializing the setting to PSI, our protocol enables non-interactive PSI which can be applied to dating services, ride-share matching, and contact tracing. While such a protocol may introduce high computational cost compared to existing works e.g., [60], its communication cost is competitive as it benefits from our batching feature, which is extremely useful in a client-server setting; see more details in Section5.3.

Oblivious polynomial evaluation. The oblivious polynomial evaluation (OPE) functionality is an important functionality in the field of secure two-party com- putation. It considers a setting where party *P₂* holds a *d*-degree polynomial *Q*(*·*) and party *P₁* holds an element *t*, and the goal is that *P₁* obtains *Q*(*t*) and nothing else while *P₂* learns nothing. OPE has proven to be a useful building block and can be used to solve numerous cryptographic problems; e.g., secure equality of strings, set-intersection, approximation of a Taylor series, RSA key generation, oblivious keyword search, set membership, blacklisting anonymous users, data entanglement and more [33,32,52,8,43,38]. In this work, we consider a distributed variant of OPE, where the input polynomial is additively secret-shared amongst the parties, and the goal of the parties is to evaluate (in the exponent) the aggregated polynomial privately and correctly. The scenario where the polynomial is distributed naturally arises in settings where the data cannot be stored on a single memory device due to privacy considerations. Secret-sharing sensitive data protects it against leakage attacks and eliminates the risk of breaching the stored memory. In some cases, the data is distributed to avoid a single point of failure and to ensure continuous access to the data. Private polynomial commitments are useful in this context and enable secure evaluation of the combined polynomial in the presence of *n −* 1 malicious cor- ruptions, similar to our PSI protocol. The incoming communication complexity of *P₁* is linear in the size of shares, whereas the outgoing communication only grows logarithmically in the polynomial degree plus *P₁*’s input size (and hence sublinear in *d*). The bulk of the computational overhead is attributed to *P₁*, which evaluates the aggregated polynomial on its input. An interesting feature of our protocol is its usage for multi-point evaluations. Here *P₁* evaluates *Q*(*·*) on multiple points *t₁,t₂,...* where the accumulated overhead per evaluation point for ensuring malicious security vanishes away due to our batching property.

Verifiable polynomial evaluations. In this setting, computationally weak devices (or clients) wish to outsource their computation and data to an *untrusted* server in the cloud. The ultimate goal in this setting is to design efficient protocols that minimize the computational overhead of the clients and instead rely on the extended resources of the server. Of course, the amount of work invested by the client for verifying the correctness of the computation is *substantially* smaller than running the computation by itself. Another ambitious challenge of verifiable computation is to minimize the *communication* from the cloud. The problem of delegating a single polynomial was studied by Benabbas et al. [10], who introduced a new cryptographic primitive of algebraic PRFs, which en- ables the generation of short authentication message to verify the server’s reply.

Followup works [29,7,20,21] improved different aspects of [10]. Nevertheless, all prior constructions considered a setting where a single client communicates with the server. Extending these solutions to the multi-client setting is not immediate (even in the non-private setting) since the server needs to aggregate the shares of the polynomials and provide proof for validating the aggregation, which is highly non-trivial. We observe that polynomial commitment schemes directly imply a verifiable evaluation of distributed polynomials where correctness is established via the proof provided by the server. When considering verifiable computation, one can consider a setting where the function is either public or private. Verifiable computation with function privacy is often harder to achieve. We note that our construction follows even if the polynomials are encrypted while the evaluation points are given in the clear. This can capture scenarios where the polynomial represents a database with secret payloads yet the queries are not private.

Implementation Details To validate the concrete efficiency of our construc- tion, we implemented our private polynomial commitment scheme and multi- party PSI protocol. Our implementation of the private polynomial commitment scheme demonstrates the advantage of batch opening. For a polynomial of de- gree 2 16, the proof size is 18.6KB and the verifier time is 53.7s to open one evaluation, while they are only 6.1MB and 757s for 2 16 evaluations respectively, which are significantly better than repeating the single opening 2 16 times. Our multi-party PSI protocol with malicious security can scale to 1000 parties with 2 16 elements per party. The majority of the time is spent on the computa- tion of the proofs of our private polynomial commitment, which can be fur- ther accelerated through multi-threading and hashing. The communication and the memory usage of our protocol is an order of magnitude better than ex- isting schemes, and thus our protocol performs better for a large number of parties and networks with limited bandwidth; see Section6for further details. We plan to open-source our implementation and the source code is available at [https://anonymous.4open.science/r/PCOM-CCF4](https://anonymous.4open.science/r/PCOM-CCF4).

### 2 Preliminaries

2.1 Basic Notations We denote the security parameter by *κ*. We say that a function *µ* : N *→* N is negligible if for every positive polynomial *p*(*·*) and all sufficiently large *κ* it holds that *µ*(*κ*) *<*
*p*( <u>1</u> *κ*). We use the abbreviation PPT to denote probabilistic polynomial time. We further denote by *a ← A* the random sampling of *a* from a distribution *A*, by [*d*] the set of elements (1*,...,d*) and by [0*,d*] the set of elements (0*,...,d*). We now specify the definition of computationally indistinguishable.

Definition 1 (Computational Indistinguishability) *Let X* = *{X*(*a,κ*)*}a∈{*0*,*1*}∗,κ∈*N *and Y* = *{Y* (*a,κ*)*}a∈{*0*,*1*}∗,κ∈*N*be two distribution ensembles. We say that X and*

*Y are computationally indistinguishable, denoted X ≈ Y, if for every PPT ma-* *chine D, every a ∈ {*0*,*1*}* *∗* *, every positive polynomial p*(*·*) *and all sufficiently* *large κ:*

*κ κ*<u>1</u> Pr[*D*(*X*(*a,κ*)*,*1) = 1] *−* Pr[*D*(*Y* (*a,κ*)*,*1) = 1] *<.* *p*(*κ*)

We denote *A*[*i*] as *i* *th* element in vector *A*. We denote *A*[: *d* *′*] as a vector consisting of only the first *d* *′* elements of vector *A* while *A*[*d* *′* :] denotes all the elements in *A* starting from index *d* *′*. For two vectors *A* and *B*, we define the point-wise product as *A⊙B*. For a given vector *A* and a value *x*, *B* = *A* *x* is defined as point-wise exponentiation where *Bi*= *A* *x* *i*for all each index *i ∈* [*|B|*]. We denote *⟨A,B⟩* for the inner product between two vectors *A* and *B*.

2.2 Hardness Assumptions Let *G* be a group generation algorithm, which outputs (*p,*G*,*G₁*,e,g*) given 1
*κ*, where G*,*G₁ are the descriptions of groups of prime order *p*, *e* is a bilinear mapping (see below) and *g* is a generator of G.

Definition 2 (DLIN) *We say that the decisional linear problem (DLIN) is* *hard relative to G, if for any PPT distinguisher D there exists a negligible func-* *tion* negl *such that*

|x y xr|ys r+s||
|---|---|---|
|||c|
|x y|xr ys|d|
||p||

(*p,*G*,*G₁*,e,g,g,g,g,g,g*) *≈*

(*p,*G*,*G₁*,e,g,g,g,g,g,g*)*,*

*where* (*p,*G*,*G₁*,e,g*) *←G*(1 *κ* ) *and x,y,r,s,d ←* Z *where d is the degree of the* *polynomial.*

Definition 3 (Bilinear pairing) *Let* G₁*,* G₂ *and* G*Tbe multiplicative cyclic* *groups of prime order p and let g, v be a generator of* G₁ *and* G₂ *repsectively.* *A map e*: G₁ *×*G₂ *→* G*Tis a bilinear map for* G₁ *and* G₂ *if it has the following* *properties: (1) Bi-linearity: ∀w ∈* G₁*,g ∈* G₂*, ∀a,b ∈* Z*p, e*(*w* *a* *,g* *b* ) = *e*(*w,g*) *ab* *.*

*(2) Non-degeneracy: e*(*w,g*) *generates* G*T.* We assume that the *D*-linear assumption holds in G₁. Definition 4 (DPP) *We say that the double pairing problem (DPP) is hard* *relative to* G₁*,*G₂*, if for any PPT adversary A there exists a negligible function* negl *such that* Pr

|(w ,w ) ← G₁; (r,t) ←A(S,w|,w|) | (r,t) ∈ G₂ × G₂|
|---|---|---|
|r t|r r|t t|
|t|κ||

*∧ e*(*w,r*) *· e*(*w,t*) = 1 *≤* negl

#### where S = (G₁,G₂, G,p,e,w,g) ←G(1)

2.3 Public Key Encryption Schemes (PKE) We specify first the definitions of public key encryption and IND-CPA. Definition 5 (Public Key Encryption Scheme) *A Public-Key Encryption* *Scheme is a tuple for four algorithms* (KeyGen*,* Enc*,* Dec*,* Rerand) : – (*PK, SK*) *←* KeyGen(1
*κ* )*: inputs security parameter κ and outputs public key* *PK and secret key SK.* – *ca←* Enc*PK*(*a*; *r*)*: inputs a message a, randomness r and public key PK and* *outputs a ciphertext ca.* – *a ←* Dec*SK*(*ca*) : *inputs a cipertext ca, a and secret key SK and outputs a* *plaintext message a.* – *c* *′a* *←* Rerand*PK*(*ca*; *r*) : *inputs a ciphertext ca, randomness r and public key* *PK and outputs a ciphertext c* *′a* *which encrypts the same message but by* *homomorphically adding randomness r to ciphertext ca.*

For a public key encryption scheme *Π* = (KeyGen, Enc, Dec, Rerand) and a non-uniform adversary *A* = (*A₁, A₂*), we consider the following IND-CPA game:

(PK*,*SK) *←* KeyGen(1 *κ* )*.* (*m₀,m₁,history*) *←A₁*(PK), s.t. *|m₀|* = *|m₁|.* *c ←* EncPK(*mb*), where *b ←{*0*,*1*}.* *b* *′* *←A₂*(*c,history*)*.* *A* wins if *b* *′* = *b*.

Denote by *AΠ,A*(*κ*) the probability that *A* wins the IND-CPA game.

Definition 6 (IND-CPA) *A public key encryption scheme Π* = (KeyGen*,*Enc*,*Dec*,*Rerand) *has indistinguishable encryptions under chosen plaintext attacks (IND-CPA), if* *for every non-uniform adversary A* = (*A₁, A₂*) *there exists a negligible function* negl *such that AΠ,A*(*κ*) *≤* <u>1</u> 2 + negl(*κ*)*.*

Additionally, we introduce another algorithm Eval which inputs an encrypted polynomial and an evaluation point and outputs a ciphertext which represents the encrypted evaluation.

Additively Homomorphic PKE A public key encryption scheme is addi- tively homomorphic if given two ciphertexts *c₁* = EncPK(*m₁*;*r₁*) and *c₂* = EncPK(*m₂*;*r₂*) it is possible to efficiently compute EncPK(*m₁* + *m₂*; *r*) with in- dependent *r*, and without the knowledge of the secret key. Clearly, this assumes that the plaintext message space is a group; we actually assume that both the plaintext and ciphertext spaces are groups (with respective group operations + or *·*).

The [13] PKE In this paper, we utilize the additive variant of [13] PKE (de- noted by BBS) which is similar to the additive variant of El-Gamal encryption [35]. The public key is a tuple PK = (G*,p,g,h,u,v*) and the corresponding se-

|||x|y|
|---|---|---|---|
||p|||
|r s r+s|m|||
|SK||x y||

cret key SK = (*x,y,z*) s.t. *u* = *g,v* = *g,h* = *g* *z*. To encrypt a message *m ∈* G we choose *r,s ←* Z and let the ciphertext be BBS*.*EncPK(*m,*(*r,s*)) = (*a,b,c*) = (*u,v,g · h*). To decrypt a ciphertext (*a,b,c*) *∈* G³ we first compute *h* *m* = BBS*.*Dec ((*a,b,c*)) = *c/a b* and then finding *m* by running an exhaustive search. This variant is only applicable for small plaintext domains, which is the case in our work. We also require a rerandomization algorithm Rerand which in- puts a ciphertext and randomness and outputs a new ciphertext with the same plaintext but new randomness (*a* *′* *,b* *′* *,c* *′* ) = BBS*.*RerandPK((*a,b,c*); (*r* *′* *,s* *′* )). The homomorphic scheme is IND-CPA secure assuming the hardness of the DLIN assumption. Threshold version. In this version, the parties first agree on a group G of order *p* and a generator *g*. Then each party *P*

|||||picks x|,y ,z|∈ Z and sends|
|---|---|---|---|---|---|---|
|||||i|i i i|p|
|x i i i i|y i n i=1 n i i=1 i|z n n i =1 n i=1 i i=1|i i|n i=1 i|||

*ui*= *gi,v* Q= *gi,h* = *g* Q *i*it to all other parties. Finally, the parties com- Q pute *u* = P *u*, P*v* = P *v* and *h* = *h*. Clearly the secret key (*x,y,z*)=( *x, y, z*) is shared amongst the parties. In order to ensure correct behaviour, the parties must prove knowledge of their secret key (*x,y,z*) by running a zero-knowledge proof on it. To ensure simulation- based security, each party must commit to its share first and decommit this commitment only after the commit phase is completed. Note that the simulator can enforce the public key outcome by rewinding the corrupted parties after seeing their decommitment information. Furthermore, the threshold decryption can be made non-interactive by posting a decryption share and proof of consis- tency. For using the encryption scheme in the protocol, we also use two more algorithms Rerand and Eval. Rerand is the algorithm used to rerandomize the ciphertext while Eval is added to evaluate a polynomial encrypted using an en- cryption scheme at an evaluation point. The BBS threshold encryption scheme is a tuple of protocols (*π*KeyGen*,π*DecZero) and a tuple of three algorithm (Enc*,*Rerand*,*Eval):

|– π|is an interactive protocol among parties P₁ ...,P|||where each party P||
|---|---|---|---|---|---|
|KeyGen|||n||i|
||i|i|i|||
|m|PK|||||
|||m||||
|′|PK|||||
||||′|||
|y|PK|||||
||||||y|
|DecZero||||n||

receives an output (PK*,*SK) where PK is the public key used for encryption and SK is the share of the secret key given to SK which will be used in threshold decryption. – *c ←* Enc (*m*; (*r,s*)): inputs a message *m*, randomness *r,s* and public key PK and outputs a ciphertext *c*. – *c ←* Rerand (*c*; (*r,s*)): inputs a ciphertext *c*, randomness (*r,s*) and public key PK and outputs a re-randomized ciphertext *c*. – *c ←* Eval (*,* C*,t*; (*r,s*)): inputs the encrypted polynomial C in form of a vector of ciphertext represented the encrypted coefficient of the polynomial, randomness (*r,s*), an evaluation point *t* and public key PK and outputs *c* which is encrypted evaluation. – *π* is an interactive protocol among parties *P₁,...,P* where a party inputs a ciphertext *c*. Additionally, all the parties input their share of secret

key (SK*i*) as an input. The protocol outputs 1 if *c* encrypts a 0-message and 0 otherwise.

#### Protocol πKeyGen:

-Parties first agree on a group G of order *p* and two generator *u,v*. -Each party *Pi*randomly chooses *xi,yi∈* F such that *u* *x* *i*= *vyi*. *P* *i*also computes *gi*= *u* *x* *i*. -*Pi*broadcast: Each party *Pi*sends *gi*and *π*DLwith inputs ((G*,u,gi*)*,xi*) to prove knowledge of *xi*. Q*n* *z* *i* -Each party *Pi*randomly chooses *zi∈* F and computes *g* =*i*=1*gi*, *hi*= *g*. -*Pi*broadcast: Each party *Pi*sends *hi*and *π*DLwith inputs ((G*,g,hi*)*,zi*) to prove knowledge of *xi*. Q*n* -Each party *Pi*computes *h* =*i*=1*hi*. -Upon verifying the zero-knowledge proof received, each party *Pi*outputs PK = (G*,p,g,h,u,v*) and SK*i*= (*xi,yi,zi*).

Algorithm EncPK(*m,*(*r,s*)): Output *cm*= (*u* *r* *,v* *s* *,g* *r*+*s* *h* *m* ).

Algorithm RerandPK(*c,*(*r,s*)): Split (*c₁,c₂,c₃*) = *c* and output *c* *′* = (*c₁ ·* *u* *r* *,c₂ · v* *s* *,c₃ · g* *r*+*s* ).

Algorithm EvalPK(C*,t*; (*r,s*)): Split C = *{c₀,c₁,...cd}* and compute *cy*= Q*d* *t* *i* *′ r s r*+*s* *i*=0*ci*. Next, split (*x,y,z*) = *cy*and output *c* = (*x · u ,y · v ,z · g*).

#### Protocol πDecZero:

-*Pi*broadcast: Each party *Pi*rerandomizes the ciphertext *c* as *ci*. *Pi*sends *ci* along with proof *π*eqshowing the message encrypted in Q *c* and *ci*is same. *∗ n* -Each party compute *c* =*i*=1*ci*. -*Pi*broadcast: Set (*d,e,f*) = *c* *∗*. Each party *Pi*sends *d* *′* = *d* *x* *i*and *e′*= *eyi*. To ensure consistency with their secret key, *π*powis used to show that the exponent is same in *d* *′* *,u* *x* *i*as well as *e′,vyi*. -Each party verifies if *d* *′* <u>f</u> *·e′* = 1. Output 1 if true else outputs 0.

2.4 Commitment Schemes A commitment scheme is a cryptographic primitive that allows a commitment to commit to a message by sending a commitment which reveals nothing about the message while later can be opened to a specific message. Definition 7 (Commitment Scheme) *A commitment scheme is a tuple of* *three algorithm* (Setup*,*KeyGen*,*Commit) *and defined as follows:* – *params ←* Setup(1
*κ* )*: Inputs security parameter κ and outputs parameters* *params.* – ck *←* KeyGen(*params*)*: Inputs parameter params and outputs commitment* *key* ck*.*

– com *←* Commitck(*m*; *r*)*: Inputs commitment key* ck*, message m and random-* *ness r and outputs commitment* com*.*

*A commitment scheme satisfies these security properties:*

– *Binding: For all PPT adversaries A, there exists a negligible function ϵ*(*·*) *such that:* h Pr *params ←* Setup(1 *κ* );

ck *←* KeyGen(*params*); (*m₀,r₀,m₁,r₁*) *←A*(1 *κ* *,params*; *rA*); com₀ = Commitck(*m₀*;*r₀*) com₁ = Commitck(*m₁*;*r₁*) i com₀ = com₁ *∧ m₀ ̸*= *m₁ ≤ ϵ*(*κ*)

– *Hiding: For all PPT adversaries A* = (*A₁, A₂*)*, there exists a negligible func-* *tion ϵ*(*·*) *such that:* h Pr *params ←* Setup(1 *κ* );

ck *←* KeyGen(*params*); (*m₀,m₁,r*) *←A₁*(1 *κ* *,params*; *rA*); *b ←R{*0*,*1*}* com = Commitck(*mb*) ˜ *b ←A₂*(com*,r*) i *b* = ˜*b ≤* 1*/*2 + *ϵ*(*κ*)

For our polynomial commitment protocol, we require two instances of com- mitment. One commitment scheme is used for committing to the encrypted poly- nomials while the other is used for committing the evaluation point. We require an additional property for one of the commitments (commitment used for en- crypted polynomials). The commitment needs to be a randomized variant of doubly homomorphic as defined in [17].

Definition 8 (Doubly Homomorphic Commitment Scheme) *A Commit-* *ment scheme* (Setup*,*KeyGen*,*Commit) *is randomized doubly homomorphic if:*

– Commitck(*m*; *r*) + Commitck(*m* *′*; *r* *′* ) = Commitck(*m* + *m* *′*; *r* + *r* *′* )*.* – Commitck*m*(*m*; *r*) + Commitck*′ m*(*m*; *r* *′* ) = Commit(ck*m*+ck*′ m*)(*m*; *r* + *r* *′* )*.*

*where* ck*r,*ck *′r* *are parts of the commitment key associated with randomness* *and* ck*m,*ck *′m* *are parts of the commitment key associated with the message com-* *mitted while* ck *is a commitment key. m and m* *′* *are messages while r,r* *′* *are the* *randomness used.*

The Pedersen Commitment Scheme. The Pedersen commitment scheme (denoted by Ped) [55] is defined as follows:

– (G*,p*) *←* Ped*.*Setup(1 *κ* ): Outputs G with order *p*. – ck = (*g₀,...,gd−*1*,h*) *←* Ped*.*KeyGen(G*,p,d*): Outputs the commitment key ck. Here *d* is the number of group elements to be committed. Q *i*

|ck|r d−1 i=0|m|
|---|---|---|
||d−1||

– comm= Ped*.*Commit (m*,r*) = *h g* : Outputs the commitment of message m where m = (*m₀,...,m*).

The Pedersen commitment scheme is computationally binding under the dis- crete logarithm assumption, i.e., any two different openings of the same com- mitment are reduced to computing log*gh*. Finally, it is perfectly hiding since a commitment is uniformly distributed in G. The scheme is additively homomor- phic.

The Commitment Scheme in [4]. The pairing based commitment in [4] (denoted by AFG) is defined as follows:

|t||κ|||
|---|---|---|---|---|
|r|d−1|||t|
||||d−1||
|m|ck|r|i=0|i i|
||||d−1||

– (G₁*,*G₂*,* G*,p,e,w,g*) *←* AFG*.*Setup(1): Outputs G₁*,* G₂ and G*t*of order *p* with *w* and *g* being generators for G₁ and G₂ while *e* is the bilinear map. – ck = (*w,w₀,w₂,...,w*) *←* AFG*.*KeyGen(G₁, G₂, G, *p*, *e*, *w*, *g*, *d*) : Out- puts the commitment key ck. Here *d* is the number of group elements to be committed. Q – com = AFG*.*Commit (m*,r*) = *e*(*w,r*) *e*(*w,m*): Outputs the com- mitment of message m where m = (*m₀,...,m*).

The above commitment scheme is perfectly hiding since a commitment is uniformly distributed in G. The scheme is also computationally binding under the double pairing assumptions stated in Definition4.

Forking Lemma Consider a public-coin interactive protocol with *r* rounds. We define (*n₁,...,nr*)-tree of accepting transcripts for this interactive protocol as follows. The tree is of depth *r* where the root is labelled with the statement and each node in depth *i* has *ni*children, where each child is associated with the *i* *th* challenge. Each edge from parent to child node is associated with a message sent from the prover to the verifier. Each root-to-leaf path corresponds to an Q*r* accepting transcript. Thus, the tree represents*i*=1*ni*different transcripts.

Lemma 1. *Forking Lemma [14] Let (*C*,* R*) be an r-round public coin interactive* *protocol. Let X be a witness extraction algorithm that succeeds with probability* 1 *−* negl(*κ*) *for some negligible function* negl(*κ*) *in extracting a witness from an* *(n₁,...,nr)-tree of accepting transcripts in probabilistic polynomial time. As-* Q*r* *sume thati*=1*niis bounded above by a polynomial in the security parameter* *κ. Then (*C*,* R*) has witness-extended emulation.*

We utilize the forking lemma to reduce the witness-extended emulation prop- erty of our polynomial commitment schemes to the existence of a PPT extractor, which given (*n₁,...,nr*)-tree of accepting transcripts can extract the witness of the polynomial commitment scheme.

2.5 Zero-Knowledge Proofs Our PSI protocol employs three types of ZK proofs. The following proof *πDL* is required for proving consistency in our maliciously secure threshold decryp- tion protocol. Namely, *πDL*is employed for demonstrating the knowledge of a solution *x* to a discrete logarithm problem [61]. Formally stating, *RDL*= *{*((G*,g,h*)*,x*) *| h* = *g*
*x* *}.* *π*EXPis a ZK proof of knowledge for demonstrating the knowledge with respect to an additively homomorphic commitment scheme. This protocol is used in our multi-party PSI protocol for two different purposes. Firstly, *P₁* broadcasts its input by sending the commitment of its input and proving knowledge of it. Secondly, it is also used by all other parties while they broadcast a ciphertext generated by evaluating their input polynomial on a common random point to demonstrate the knowledge of plaintext of the ciphertext. As *P₁* uses Pedersen commitment to commit to its input, we realize *π*EXPusing a standard *Σ*-protocol

||EXP|′|′ m r|
|---|---|---|---|
|pow||||
|pow COIN|m|m||

for the following relation: *R*EXP= *{*((G*,g,h,h* *′* )*,* (*m,r*)) *| h* *′* = *g* *m* *h* *r* *}.* The proof *π* is a ZK proof for demonstrating the equality of exponent. This is used for generating the public key for the threshold encryption scheme. We realize *π* using a standard *Σ−*protocol for the following relation: *R*pow= *{*((G*,g,h,c₁,c₂*)*,* (*m*)) *| c₁* = *g ∧ c₂* = *h}.* Additionally, *π* is a coin tossing protocol which is executed in the PSI protocol in order to sample a random group element for verifying the correctness of aggregation. Its overhead is *O*(*n²*) for *n* parties.

2.6 Inner Product Argument [15] The inner product argument allows a party to provide proof for correct inner product evaluation. More formally, given two vectors *a* and *b* (where the vectors can be hidden or known), proves that the inner product is equal to a known (or committed) value *c*. [14] introduces an inner product argument with logarithmic proof size which is improved by [15] which relies on Discrete Log (DL) assumption. The vari- ant of the protocol used in our construction requires both vectors and inner products to be private. Therefore, the prover provides commitments to the two vectors and the inner product. The inner product argument utilizes masking to achieve honest-verifier zero-knowledge in addition to completeness and witness extended emulation [15] (Section 4). The prover recursively reduces verifying the inner product of two large vectors into verifying the inner product of small vectors. In the last iteration, This utilizes the doubly homomorphic property of the underlying commitments wherein the commitments used are homomorphic in both key-space and message-space. In Figure1, we present the inner product argument using our notations and is denoted by BBB-IPA.
### 3 Private Polynomial Commitment Schemes

In this section, we introduce a new polynomial commitment scheme with privacy features. Loosely speaking, such a protocol is carried out between a committer C

Inner Product Argument (BBB-IPA)

Private Inputs: C : *A ∈* Z *d* *p* +1 *,B ∈* Z *d* *p* +1 *,c ∈* Z*p*. Public Inputs: ck₁*,*ck₂*,*ck₃*,*com*A,*com*B,*com*c*. Protocol:

1. C and R compute the combined commitment com = com*A ·* com*B ·* com*c*. For round *rnd* = 1 to log *d −* 1:
2.Set *d* *′* = (*d* + 1)*/*2. C sets *AL* = *A*[: *d*
*′*], *AR* = *A*[*d* *′* :], *BL* = *F*[: *d* *′*] and *BR* = *F* [*d* *′* :] while both C and R sets ck₁*L* = ck₁[: *d* *′*], ck₁*R* = ck₁[*d* *′* :], ck₂*L* = ck₂[: *d* *′*], and ck₂*R* = ck₂[*d* *′* :].

3. C generates intermediate cross-commitments: com*AL* = Commitck1*R*(*AL,rAL*). com*AR* = Commitck1*L*(*AR,rAR*) com*BL* = Commitck2*R*(*BL,rBL*), com*BR* = Ped*.*Commitck2*L*(*BR,rBR*), where *rAL,rAR,rBL,rBR ∈* Z*p*.
4. C *→* R: C generates *L* and *R* and sends *L,R* to C: *c* *l*= *⟨AR,BL⟩*, *cr* = *⟨AL,BR⟩*, *L* = com*AR ·* com*BL ·* Commitck3(*cl*), *R* = com*AL ·* com*BR ·* Commitck3(*cr*).
5. R *→* C: R sends a random challenge *x ∈* Z*p*.
6. C sets *A* *′*
= *AL* + *x · AR B* *′* = *BL* + *x* *−*1 *· BR* while C and R both locally *′ x−*1*′ x* compute the new keys ck₁ = ck₁*L ⊙*ck₁*R*and ck₂ = ck₂*L ⊙*ck₂*R*where *⊙* denotes element-wise multiplication of two vectors. *′ x x−*1

7. R computes the new commitment com = *L ·* com *· R*.
8. C and R will update *A* = *A*
*′*, *B* = *B* *′*, com = com *′*, and ck*i* = ck *′i* *∀i ∈* [2].

In round log*d*:

9.In the last round,C opens com to *A*
*′* *,B* *′* and *c* *′* and R accepts if *c* *′* = *⟨A* *′* *,B* *′* *⟩*.

10.If all checks pass, R outputs *b* = 1 else output *b* = 0.
#### Fig.1: Inner Product Argument (BBB-IPA)

and a receiver R where C commits to an encrypted polynomial C, denoted by a sequence of ciphertexts C = (*c₀,c₁,...,cd*) where *ci*is a ciphertext that encrypts the *i* *th* coefficient of the underlying plaintext polynomial. In these schemes, upon committing to the encrypted polynomial, C sends C to R and later evaluates it at an evaluation point *t*. Following that, C proves that a ciphertext *cy*is a correct evaluation of the encrypted polynomial at some private evaluation point *t*.

3.1 Security Definitions We continue with the security definition of our new polynomial commitments. Definition 9 *(Private Polynomial Commitments with Hidden Evaluation Points)*
16

*Let* E = (KeyGen*,*Enc*,*Dec*,*Eval*,*Rerand) *be an AHE scheme with groups M and*

*C.Let PK be the public key of the underlying AHE scheme and generated by*
E*.*KeyGen*. A private commitment scheme* PCOM *w.r.t* E *is a tuple of algorithms* (Setup*,*Commit*,*CommitPt) *and a protocol* (C*,*R) *defined as follows:* – pp *←* Setup(1
*κ* *,d*)*: takes an input κ,d where κ is the security parameter and* *d is the degree of the polynomial, and outputs public parameters* pp*.* – comC*←* Commit(pp*,*C;*r*C)*: takes as input a public parameters* pp*, a vector of*

|ciphertexts (representing an encrypted polynomial) C = (c₀,c₁,...,c||) where|
|---|---|---|
|||d|
|i|C|C|
|T|T||
||T||
||T||

*d* *c ∈C for all i and randomness r, and outputs a commitment* com*.* – com *←* CommitPt(pp*,t,d*; *r*) : *takes as input public parameters* pp*, an eval-* *uation point t, a randomness r and d is the degree of the polynomial and* *outputs a commitment* com*.* – (C*,*R) *is a public-coin interactive protocol between* C *and* R*. Both* C *and* R *have common inputs, public parameters* pp*, a public-key PK for the under-* *lying AHE scheme, a commitment* comC*, another commitment* com*Tand an* *evaluation ciphertext cy, ∈ C.* C *additionally receives as input an encrypted* *polynomial* C*, an evaluation point t and randomness r*C *cy t*

|||||,r ,r|. At the end|
|---|---|---|---|---|---|
|||||C c|t|
|C c|T|C|T y|||

*of the protocol execution,* R *either outputs accept or reject. We denote by* C(C*,t,r,ry,r*)*,* R (pp*, PK,* ck*,*com*,*com*,c*) *the random variable rep-* *resenting an execution and given an instance of the execution e, we denote* *by* view₁(*e*) *(resp.* view₂(*e*)*) the view of the* C *(resp.,* R*) and* out₁(*e*) *(resp.,* out₂(*e*)*) the output of* C *(resp.,* R*).*

*We require the following security properties to be satisfied:*

Completeness: *For any vector of ciphertexts* C = (*c₀,c₁,...,cd*) *generated* *using PK ←* E*.*KeyGen(1 *κ* ) *and an evaluation point t, we have that:*

h

||κ||
|---|---|---|
|C||C|
|T||T|
|y|c||
||C c T||
||C T y||

Pr pp *←* PCOM*.*Setup(1*,d*);

com *←* PCOM*.*Commit(pp*,*C;*r*); com *←* PCOM*.*CommitPt(pp*,t,d*; *r*); *c* = Eval(*PK,*C*,t*; *ry*) : out₂(C(C*,t,r,ry,r*)*,*R) i (pp*, PK,* com*,*com*,c*) = 1 = 1

Binding: *For all PPT adversaries A, there exists a negligible function ϵ*(*·*) *such* *that:*

h Pr pp *←* PCOM*.*Setup(1 *κ* *,d*); *κ*

|PK ← E.KeyGen(1|);||
|---|---|---|
|||κ|
|C|C T|T|
|C||C|
|C||C|
|T||T|
|T||T|
|C|C||
|T|T||

(C₀*,r*0*,*C₁*,r*1*,t₀,r*0*,t₁,r*1) *←A*(1 *κ* *,n,* pp*, PK*; *rA*); com0= PCOM*.*Commit(pp*,*C₀; *r*0) com1= PCOM*.*Commit(pp*,*C₁; *r*1) com0= PCOM*.*CommitPt(pp*,t₀,d*; *r*0) com1= PCOM*.*CommitPt(pp*,t₁,d*; *r*1) (com0= com1*∧* C₀ *̸*= C₁) i *∨* (com0= com1*∧ t₀ ̸*= *t₁*) *≤ ϵ*(*κ*)

Witness-Extended Emulation: *For all PPT adversaries A, there exists an* *expected polynomial time emulator E and negligible function ϵ*(*·*) *such that:* h Pr *pp ←* PCOM*.*Setup(1 *κ* *,d*);

*PK ←* E*.*KeyGen(1 *κ* ); (comC *T y* *κ*

|, com ,c|) ←A(1 ,n, pp, PK; r||);|
|---|---|---|---|
|C T y|||A|
|A|A(pp,PK,com|C T ,com|y ,c ;r)|
|C c T|C|T y||
|C||C||
|T|||T|
|y|PK|c||

*A* *e ←* (*A*(*r*)*,*R)(*pp, PK,* com*,*com*,c*);

(C*,t,r,ry,r*) *←E* C *T y A*

(pp*, PK,* com*,*com*,c,e*) : (out₂(*e*) = 1) *⇒* (com = PCOM*.*Commit(pp*,*C;*r*) *∧* com = PCOM*.*CommitPt(pp*,t,d*; *r*) i *∧ c* = Eval (C*,t*; *ry*)) *≥* 1 *− ϵ*(*κ*)

Honest Verifier Privacy: *There exists a tuple of expected PPT algorithms S,* *given any vector of coefficient of polynomial* (*p₀,...,pd*) *and an evaluation* *point*  *t, such that the following distributions are indistinguishable:*    pp *←* PCOM*.*Setup(1 *κ* *,d*);    *κ*   *PK ←* E*.*KeyGen(1);       C
*←* (*c₀,...,cd*) = (Enc*PK*(*p₀*;*r₀*)*,...,* Enc*PK*(*pd*; *rd*)) :
     comC*←* PCOM*.*Commit(pp*,*C;*r*C); 

|← PCOM.CommitPt(pp,t,d; r|||);||
|---|---|---|---|---|
|T|||t||
|y|PK|c|||
||C c C|T A T y|||
||2||||
|κ|||||
|κ|||||
|S|||||

– com*T t*      *c ←* Eval (C*,t*; *ry*);        *e ←* (C(C*,t,r,ry,r,r*)*,*R)        (pp*, PK,* com*,*com*,c*) :      view 

(*e*)
*pp ←* PCOM*.*Setup(1*,d*); – *PK ←* E*.*KeyGen(1);   *S*(pp*, PK,d*; *r*)

3.2 Our Protocols In this section, we present the construction of our private polynomial commit- ment. Our construction is based on the additive homomorphic encryption (AHE) scheme from [13] and the inner-pairing product argument from [17]. As a warm- up, we start by considering a single point where the idea is that the evaluation
P*d* *i* of a polynomial *f* (*x*) =*i*=0*aix* at point *t* can be viewed as the inner prod- uct between the coefficients vector (*a₀,a₁,...,ad*) and the evaluation vector *T* = (1*,t,t²,...,t* *d* ). Therefore, given the ciphertexts encrypting the coefficients and the commitments of the evaluation vector *T*, the committer proves in Phase 1 that the polynomial evaluation on the ciphertext is indeed the inner product between the two vectors using the techniques in [17]. Next, it remains to show that the committed evaluation vector is well-formed, i.e., it is indeed the powers of the evaluation point *t*. To prove this property, denoting the *i*-th element in a vector *T* as *T* [*i*], it suffices to show that (1) the 0-th element *T*[0] is 1; (2) *T* [*i* + 1] = *T* [*i*] *· T*[1] for *i* = 0*,...,d −* 1. These two conditions can further be translated into two types of constraints: linear constraints and quadratic con- straints. The first condition is equivalent to the inner product between *T* and a public vector (1*,*0*,...,*0) is 1. For the second condition, we define three selector matrices *A,B,C ∈* F *d×*(*d*+1) such that

*X* = *A×T* = (*T*[0]*,T*[1]*,...,T*[*d −* 1])*,* *Y* = *B×T* = (*T*[1]*,T*[1]*,...,T*[1])*,* *Z* = *C×T* = (*T*[1]*,T*[2]*,...,T*[*d*])*.* (1)

Finally, the committer proves that *X ⊙ Y* = *Z*, where *⊙* denotes the Hadamard (element-wise) product. It is not hard to see that *T* is the correct evaluation vector if and only if it satisfies these constraints. We use standard techniques such as [15] to reduce the linear constraints and the quadratic constraints to inner product arguments in Phases 2 and 3. Note that the protocols in these two phases are independent of the ciphertexts encrypt- ing the coefficients. The formal protocol of our private polynomial commitment is presented in Figure2. This protocol uses the encryption scheme from [13], the pairing-based commitment from [4] and the Pedersen commitment [55] (see Appendix2) as building blocks. The protocol also involves private inner product argument, linear constraints test and quadratic constraints test, as described above in the three phases. We present these protocols later in Figures4,5and6 together with our scheme for multiple evaluations. Multiple Evaluations. The major advantage of our construction is that it sup- ports batched evaluations on multiple points efficiently, where the proof size and the receiver’s time do not increase by much compared to a single evaluation. We describe our scheme for multiple evaluations in Figures3. The differences from the single evaluation variant are highlighted inpurple. In particular, in Phase 1 (Steps 1 and 2 in Figure3), C and R check the inner products between the coefficient vector in the ciphertext and all the evaluation vectors in the com- mitments using a single private inner product argument protocol via a random

Setup(1 *κ* *,d*): Generate the public parameters of the bilinear map and the com- mitment scheme Ped and AFG. (G₁*,*G₂*,* G*t,p,e,w,g*) *← G*(1 *κ* ), ck₁ = (*wr,w₀,...,wd*)*,a,b*) *←* AFG*.KeyGen*(*S,*3*d* + 8). ck₂ = (*vr,v₀,...,vd*) *←* Ped*.*KeyGen(1 *κ* *,d* + 2), ck₃ *←* Ped*.*KeyGen(1 *κ* *,*2), ck₄ = (*xr,x₀,...,xd*) *←* Ped*.*KeyGen(1 *κ* *,d* + 2). Output *pp* = (ck₁*,*ck₂*,*ck₃*,*ck₄*,a,b*).

Commit(*pp,*C*,r*C): Given the ciphertext of the coefficients Q C = (*c₀,...,cd*), out- put AFG*.*Commitck1(C*,g* *r*

C) = *e*(*gr*C*,w*
*r* ) *·* *d* *i*=0*e*(*ci,wi*), where *r*C*∈* Z*p*. CommitPt(*pp,t,rT,d*): Given an evaluation point *t*, generate *T* = (1*,t,...,t* *d* ) and output Ped*.*Commitck2(*T,rT*) where *rT ∈* Z*p*.

Protocol *Πpriv*(C(C*,r*C*,t,rT*)*,*R)(*pp,* comC*,*com*T,cy*):

1. C and R execute Private inner Product Argument specified in (Figures
4) with common input *pp,* comC*,*com*T,cy* and C*,T* as private inputs to C.
2. C *→* R: Let *A,B,C* be public selector matrices defined in Equation1. C computes *X* = *A×T* = (1*,t,...,t*
*d−*1 ), *Y* = *B×T* = (*t,...,t*), *Z* = *C×T* = (*t,...,t* *d* ). C commits to *X,Y,Z* by com*X* = Ped*.*Commitck2(*X,rX*)*,*com*Y* = Ped*.*Commitck2(*Y,rY*)*,*com*Z* = Ped*.*Commitck2(*Z,rZ*), where *rX,rY,rZ ∈* Z*p*. C sends com*X,*com*Y,*com*Z* to R.

3. C *↔* R:C and R execute Linear Constraints Test specified in Figure5 with common input com*T,*com*X* and *T,X* as private inputs to C. Repeat the same for *Y* and *Z*. Let D be public selector matrix defined as *D×T* = [1], C and R execute Linear Constraints Test specified in Figure5with common input com*T,D* and *T* as private inputs to C.
4. C *↔* R:C and R execute Quadratic Constraint Test specified in Figure6 with common input com*X,*com*Y,*com*Z* and *X,Y,Z* as private inputs to C.
5. R outputs 1 if all checks pass.
#### Fig.2: Private Polynomial Commitments (Single Evaluation).

linear combination. In Phase 2 (Step 4 in Figure3), the product between a se- lector matrix (i.e., *A,B* or *C*) and all the evaluation vectors can be reduced to a single inner product via two random linear combinations, as shown in Figure5. In Phase 3 (Step 5 in Figure3), the protocol of the quadratic constraint test is more complicated. We are not able to reduce the Hadamard product of matrices *X ⊙ Y* = *Z* to a single inner product. Instead, we reduce the Hadamard product to the sum of *m* inner products via a random linear combination in Step 1 of Figure6. Then we propose a protocol (Step 3 of Figure6) to prove the sum of the inner products with a proof size of only *O*(log*d*). The protocol is an extension of the scheme for the Hadamard product in [15] in a non-black-box way.

Protocol *Πpriv* *batched* (C(C*,r*C*, {ti}i∈*[*m*]*, {rTi}i∈*[*m*])*,*R)(*pp,* comC*, {*com*Ti}i∈*[*m*]*,* *{cyi}i∈*[*m*]):

1. R *→* C:R sends *S* = (*s₁,s₂, ··· ,sm*) *∈* Z
*m*

*p*.
P*m*Q*m s*Q*m s*

2. C *↔* R : Let *F* =*i*=1*si · Ti*, com*F* =*i*=1com*Tii*and *cy* =*i*=1*cyii*. C and R execute Private inner Product Argument specified in (Figures4) with common input *pp,* comC*,*com*F,cy* and C*,F* as private inputs to C
3. C *→* R: Let *A,B,C* be public selector matrices defined in Equation1. C computes *Xi* = (1*,ti,...,t*
*d* *i −* 1
), *Yi* = (*ti,...,ti*) and *Zi* = (*ti,...,t*
*d* *i* ).Let *T ∈* Z ( *pd* +1)*×m* be the matrix with the *i*-th column as *Ti*. C commits to each column of *X,Y,Z*, namely, com*Xi* = Ped*.*Commitck2(*Xi,rXi*)*,*com*Yi* = Ped*.*Commitck2(*Yi,rYi*)*,*com*Zi* = Ped*.*Commitck2(*Zi,rZi*) where *rXi,rYi,rZi ∈* Z*p* and sends *{*com*Xi,*com*Yi,*com*Zi}i∈*[*m*]to the R.

4. C *↔* R : C and R execute Linear Constraints Test specified in Figure5 with common input pp*, {*com*Ti}i∈*[*m*]*, {*com*Xi}i∈*[*m*]and *T,X* as private inputs to C. Repeat the same for *Y* and *Z*. Let D be public selector matrix defined as *D×T* = [1]
*m*, C and R execute Linear Constraints Test specified in Figure5 with common input com*T,D* and *T* as private inputs to C.

5. C *↔* R:C and R execute Quadratic Constraint Test specified in Figure 6with common input pp*, {*com*Xi}i∈*[*m*]*, {*com*Yi}i∈*[*m*]*, {*com*Zi}i∈*[*m*]and *X,Y,Z* as private inputs to C.
6. R outputs 1 if all checks pass. Fig.3: Batched proof for Private Polynomial Commitments.
Theorem 1. *Protocol* PCOM *(Figure3) is a private polynomial commitment* *scheme as in Definition9, under the Decisional Linear (DLIN) and the Double* *Pairing Problem (DPP) hardness assumptions (see Section2.2).*

Proof Sketch: To show PCOM is a private polynomial commitment scheme (Definition9), we show that the protocol satisfies completeness, binding, witness- extended emulation and honest verifier privacy.

Completeness: In the private inner product argument test, there are two phases

- the masking phase and the inner product phase. In the end, R accepts if the combined commitment of the private polynomial, evaluation vector and evalua- tion ciphertext is decommitted correctly. This essentially follows from showing that the commitment of the private polynomial, the commitment of the evalua- tion vector and the evaluation ciphertext are updated correctly in each round. The rest of the protocol involving the linear constraint test, quadratic test and the BBB-IPA follow essentially observing that the corresponding constraints are satisfied.
21

Private inner Product Argument

Private Inputs: C : C = (*c₀,...,cd*) *∈* G *d* *E* +1 *,F* = (*f₀,...,fd*) *∈* Z *d* *p* +1. Public Inputs: *pp* = (ck₁*,*ck₂*,*ck₃*,a,b,* PK)*,*comC*,*com*F,cy*.

1. Masking Phase:
(a) C *→* R: C generates a random encrypted polynomial E = (*e₀,...,ed*) *∈* G *d* *E* +1 where *ei* = EvalPK(*ri*) and *ri ∈* Z*p*. A random vector *M* = (*M₀,...,Md*) *∈* Z
*d* *p* +1 is also sampled and generates commitment comE= AFG*.*Commitck1(E*,r*E) and com*M* = Ped*.*Commitck2(*M,rM*) where *r*E*,rM ∈* Z*p*. C also computes: *cl*= *⟨*E*,F ⟩*, *cr* = *⟨*C*,M ⟩*, *cm* = *⟨*E*,M ⟩* and sends comE*,*com*M,cl,cr,cm* to R.

(b) R *→* C: R sends a random challenge *x ∈* Z*p*.
(c)Both parties set com
*′* where: com = comC*· e*(com*F,a*) *· e*(*cy,b*), com *′* = *x x−*1*x x−*1*′ x* com *·* comE*· e*(com*M,a*) *· e*(*cl· cm · cr,b*), and C sets C = C *⊙* E and *F* *′* = *F* + *x* *−*1 *· M* where *⊙* denotes element-wise multiplication of two vectors.

(d)Both parties update com = com
*′* ,C=C *′*, *F* = *F* *′*.

2. Inner Product Phase: For round *rnd* = 1 to log *d −* 1:
(a)Set *d* *′* = (*d* + 1)*/*2. C sets C*L* = C[: *d*
*′*], C*R* = C[*d* *′* :], *FL* = *F*[: *d* *′*] and *FR* = *F* [*d* *′* :] while both C and R sets ck₁*L* = ck₁[: *d* *′*], ck₁*R* = ck₁[*d* *′* :], ck₂*L* = ck₂[: *d* *′*], and ck₂*R* = ck₂[*d* *′* :].

(b) C generates intermediate cross-commitments: comC*L*= AFG*.*Commitck1*R*(C*L,r*C*L*), comC*R*= AFG*.*Commitck1*L*(C*R,r*C*R*), com*FL* = Ped*.*Commitck2*R*(*FL,rFL*), com*FR* = Ped*.*Commitck2*L*(*FR,rFR*), where *r*C*L,r*C*R,rFL,rFR ∈* Z*p*.
(c) C *→* R: C generated *L* and *R*: *cl*= *⟨*C*R,FL⟩*, *cr* = *⟨*C*L,FR⟩* *L* = comC*R· e*(com*FL,a*) *· e*(*cl,b*), *R* = comC*L· e*(com*FR,a*) *· e*(*cr,b*), where *a,b ∈ pp* and sends *L,R* to C.
(d) R *→* C: R sends a random challenge *x ∈* Z*p*.
(e) C sets C
*′* = C*L ⊙* C *x* *R*and *F* *′* = *FL* + *x* *−*1 *· FR* where *⊙* denotes element-wise multiplication of two vectors while C and R both locally compute the new *′ x−*1*′ x* keys ck₁ = ck₁*L ⊙* ck₁*R*and ck₂ = *ck₂L ⊙* ck₂*R* *′ x x−*1

(f) R computes new commitment com = *L ·* com *· R*
(g) C and R will update C = C
*′*, *F* = *F* *′*, com = com *′*, and ck*i* = ck *′i* *∀i ∈* [2] In round log*d*:

(h)In the last round,C opens com to C
*′* *,F* *′* and *c* *′y* and R accepts if *cy* = *⟨*C *′* *,F ⟩*.

(i)If all checks pass, R outputs *b* = 1 else output *b* = 0.
#### Fig.4: Private Inner Product Argument.

Binding: To argue the binding property of PCOM, it can be trivially reduced to the binding property of the Ped and AFG commitment scheme. Witness-Extended Emulation: To argue witness-extended emulation of PCOM, as shown in [15], it is enough to show that given (*n₁,...,nr*)-tree of

Linear constraint Test (Prove *A×T* = *X*)

– Private Inputs: C has private inputs: *X ∈* Z *d* *p×m,T ∈* Z *d* *p* +1*×m*. – Public Inputs: *pp* = (ck₁*,*ck₂*,*ck₃*,a,b,* PK), *{*com*Ti}i∈*[*m*], *{*com*Xi}i∈*[*m*]where com*Ti,*com*Xi ∈* G₁.

1. R *→* C: R sends random vectors *S ∈* Z
*d* *p*and *U ∈* Z *m*

*p*. Let *SA* = *S×A*,
*TU* = *T × U*, *XU* = *X×U*. We observe that if *A×T* = *X* then for any *S ∈* Z *d* *p*and *U ∈* Z *m* *p*we have:

*S×A×T×U* = *S×X× U,* i.e, *⟨SA,TU⟩−⟨S,XU ⟩* = 0*.*

2. C *→* R : C computes two cross terms inner product *l* and *r* and sends their respective commitments com*l,*com*r* to R: *l* = *⟨SA, −XU ⟩*, *r* = *⟨S,TU ⟩*, com*l*= Ped*.*Commitck3(*l,rl*), com*r* = Ped*.*Commitck3(*r,rr*), where *rl,rr ∈* Z*p*.
3. R *→* C: R sends a random challenge *x ∈* Z*p*.
4. R *↔* C: C computes *L* = *SA* + *x*
*−*1 *· S* and *R* = *TU − x · XU*. C and R both compute com*L* = Ped*.*Commit*ck*4(*SA* + *x* *−*1 *· S*; 0) and com*R* = Q*m U* [*i−*1] *U* [*i−*1]*·x* *i*=1com*Ti·* com*Xi*.C and R execute BBB-IPA (Figure1) on com- *x x−*1 mon inputs is ck₄*,*ck₂*,*ck₃*,*com*L,*com*R,*com*l·* com*r*and private inputs of C are*,L,R,x · l* + *x* *−*1 *· r*.

5.If all checks pass, R outputs *b* = 1 else output *b* = 0.
– A special case is when *D×T* = *X* where *X* is a known vector of dimensions 1*× m*. The above test can be simplified where R sends a random vector *U ∈* Z *m* *p* and the check is reduced from P *D×T* = *X* to *⟨D,TU ⟩* = *d* where *TU* = *T × U* and *d* = *m* *i*=0 *−*1 *U* [*i*]. C and R compute com*D* = Ped*.*Commitck4(*D,*0), com*TU* = Q*m U* [*i−*1] *i*=1com*Ti*,com*d*= Ped*.*Commit(*d,*0) .C and R execute BBB-IPA (Figure1) on common inputs is ck₄*,*ck₂*,*ck₃*,*com*D,*com*TU,*com*d*and private inputs of C are *D,TU,d*. If all checks pass, R outputs *b* = 1 else output *b* = 0.

#### Fig.5: Linear Constraint Test.

accepting transcripts, there exist a PPT extractor *X* which extracts the witness for PCOM. To construct *X*, we first construct a witness-extraction algorithm *X₁* that succeeds in extracting the witness of Private Inner Product Argument given (*n₁,...,nr*)-tree of accepting transcripts. Using the rewinding property of the extractor and choosing different randomness in each rewinding, the extrac- tor *X₁* can extract the witness. Here, the witness is the encrypted polynomial, evaluation vector, encrypted evaluation and the randomness used to generate the commitments. Next *X* extracts the evaluation vector from Linear Test and Quadratic test to verify if the evaluation used in all three tests is the same. We use the witness-extended emulation extractor of BBB-IPA as a subprotocol in extracting the evaluation vector from the Linear and Quadratic tests. Honest Verifier Privacy: To show honest verifier privacy, we construct a simulator *S*. Indistinguishability of the simulation essentially follows from se- mantic security of the underlying encryption scheme, hiding of the commitment

Quadratic Constraint Test (Prove *X⊙Y* = *Z*)

Private Inputs: C : *X,Y,Z ∈* Z *d* *p×m*. Public Inputs: *pp* = (ck₁*,*ck₂*,*ck₃*,*ck4*,a,b,* PK)*, {*com*Xi}i∈*[*m*]*, {*com*Yi}i∈*[*m*]*,* *{*com*Zi}i∈*[*m*]where com*Xi,*com*Yi,*com*Zi ∈* G₁.

1. R *→* C: R sends a random vector
P *S ∈* Z *m* *p*and a random value *w*. Now if *X⊙Y* = *Z*, then*i∈mw* *i* (*⟨Xi,Yi ⊙ S⟩−⟨Zi,S⟩*) = 0.

2.Let *Li* = *w*
*i* *· Xi,Li*+*m* = *w* *i* *· Zi*, *Ri* = *Yi ⊙ S,Ri*+*m* = *−S* *S j*]*−*1 C and R compute a new key ck₅ where ck₅[*j*] = ck2 [[*j*] for all *j ∈* [0*,d*] *wiwi* and compute the commitments as follows: com*Li* = com*Xi,*com*Li*+*m*= com*Zi*, com*Ri* = com*Yi,*com*Ri*+*m*= Ped*.*Commitck5(*−S*)

3. C sets *d* = 0 while R sets com*d*= 1. Also set *m*
*′* = 2*m*. For round 1 to log*m*:

(a) C *→* R: Set m’ = m’/2. C computes two cross terms inner product *l* = P*m′*P*m′* *i*=1*⟨Li,Ri*+*m′⟩* and *r* =*i*=1*⟨Li*+*m′,Ri⟩* and sends a Ped commitment of these two (com*l*and com*r*) to R. where *rl,rr ∈* Z*p*.
(b) R *→* C : R sends a random challenge *x ∈* Z*p*.
(c) C computes *{L*
*′ i* = *Li* + *x* *−*1 *· Li*+*m}i∈*[*m′*]and *{R* *′ i* = *Ri* + *x · Ri*+*m}i∈*[*m′*] *x* *−*1 while R updates the commitments com*L′i*= com*Li ·* com*Li* +*m* and com*Ri′*= com*Ri ·* com *x* *Ri*+*m*.

(d) C computes *d*
*′* = *d* + *x · l* + *x* *−*1 *· r* while R computes com*d′*= com*d·* com *x* *l·* *x* *−*1 com*r*.

(e) C updates *Li* = *L*
*′i*, *Ri* = *Ri′*, *d* = *d* *′* while R updates com*d*= com*d′*. In round log*m* + 1:

(f) C sets *L* = *L₁* and *R* = *R₁* while R sets com*L* = com*L*1and com*R* = com*R*1C and R execute BBB-IPA (Figure1) on instance with common input ck₂*,*ck₅*,*ck₃*,*com*L,*com*R,*com*d*and *L,R,d* as private inputs of C.
#### Fig.6: Quadratic Constraint Test.

scheme, honest-verifier zero-knowledge property of the underlying BBB-IPA and standard masking techniques. We provide the full proof in AppendixA.1.

Complexity.The communication complexity of our polynomial commitments is *O*(log*d*) for a single evaluation and *O*(*m* + log*d*) for *m* points where *d* is the degree of the polynomial. Their round complexity is *O*(log*m* + log*d*) rounds. The computational complexity of the committer is *O*(*m · d*) modular expo- nentiations and *O*(*d*) bilinear pairings, while the complexity of the receiver is *O*(*m* + *d*) exponentiations. The space complexity of our private polynomial com- mitment scheme is *O*(*m* + *d*) for the committer as it needs to store the encrypted polynomial and the evaluation points. The space complexity of the receiver is *O*(*m*) (resp. *O*(*m*+ log*d*)) in the interactive (resp. non-interactive setting). This

difference is because, in the non-interactive setting, the entire proof is stored for validation.

3.3 Other variants of the Private Polynomial Commitment Non-interactive proofs and public verifiability via Fiat-Shamir trans- form. As the proof systems for the single and batched setting of private polyno- mial commitment schemes are public-coin (i.e. *R* only sends random coins during the interaction of the protocol), it can be transformed to a non-interactive proof system via the Fiat-Shamir transform [28]. Furthermore, these proofs will be publicly-verifiable. Private polynomial commitment with public evaluation points. In the private polynomial commitment protocols from Figures2and3, the evaluation points are known only to the committer and are committed to the receiver. It is not hard to change the protocols to support public evaluation points known both to the committer and the receiver. A naive approach is to execute Phase 1 only. As the receiver knows the evaluation points, it can compute the well-formed evaluation vectors on its own without the checks in Phases 2 and 3. However, in the batched variant in Figure3, the complexity of the receiver would become *O*(*dm*), as computing the commitments of the evaluation vectors takes *O*(*dm*) time. Instead, to maintain the same complexity, the committer and the receiver still execute all three phases of the protocol. In Phase 2, the receiver computes the commitment of *Y* on its own. As *Yi*= (*ti,ti,...,ti*), computing the commitments of all *Yi*s only takes *O*(*d* + *m*) time. In our application for multi-party private set intersection (MPSI), we will rely on the non-interactive proof variant of our private polynomial commitment both with hidden and public points. Precisely, we will have a polynomial committed once and then incorporate proofs of evaluations on both types of points. Multivariate polynomial commitment. Our protocols can also be general- ized to support multivariate polynomials. The evaluation of a multivariate poly- nomial can also be viewed as the inner product between the coefficient vector and the evaluation vector computed by all monomials of the evaluation point. Therefore, Phase 1 of the protocols in Figure2and3remains the same. In Phases 2 and 3, we instead check the form of the evaluation vectors of the mul- tivariate polynomial. These can be reduced to linear and quadratic constraints with different *A,B,C* matrices. The techniques to batch multiple evaluations in Figures3,6and5remain the same.
### 4 Scalable Multi-Party PSI

Our first application is a new scalable PSI protocol that follows the blueprint of [46]. This protocol is carried out in a star topology network with *P₁* being the central party. In this work, we show that the actions of *P₁* can be captured by the abstraction of a private polynomial commitment.

We broadly split our protocol description into four main phases. In the first phase (Key Generation), the parties jointly generate a public key without dis- closing their corresponding secret key shares, as well as the public parameters for the two polynomial commitments. The second phase (Commitment Phase) is executed by the central party *P₁* that broadcasts commitments of its input together with a proof of knowledge. In the third phase (Aggregation), all parties (except *P₁*) send it an encrypted polynomial whose roots correspond to their inputs. *P₁* combines these polynomials for each party and provides a commit- ment of the encrypted aggregated polynomial while proving the correctness of aggregation. The last phase (Intersection) concludes the protocol by extracting the intersection, where *P₁* evaluates the aggregated polynomial on its input and provides proof of correct evaluation. Once the proof is validated, the parties decrypt each evaluation to get the intersection. Our polynomial commitments will be useful in [46] for two purposes; proving the correctness of aggregation by evaluating on a public point and proving the correctness of evaluations on *P₁*’s input finally to reveal the intersection. We use the following primitives in our construction:

– A threshold additively homomorphic encryption scheme with protocols (*Π*GEN and *Π*DecZero) to respectively sample a public key together with the secret key shares, and a protocol to determine if a target ciphertext decrypts to 0. We instantiate our scheme with the BBS encryption scheme (Section2.3) which relies on the DLIN assumption (Definition2). – Our polynomial commitment scheme PCOM, (that is compatible with the threshold encryption scheme), and is instantiated with non-interactive pub- licly verifiable proofs of evaluation of hidden points (in the batched setting) and public points (in the single instance setting). We respectively denote the committer and receiver algorithms for the corresponding (non-interactive) proof systems by (PCOM*.*C *batch* *hid,*PCOM*.*R *batch* *hid*) and (PCOM*.*C*pub,*PCOM*.*R*pub*). To construct PCOM, we require two commitment schemes: Pederson Commit- ment scheme (Section2.4) which relies on the DL assumption and the AFG Commitment scheme (Section2.4) that is based on bilinear pairing and relies on the DPP assumption (Definition4). – An *n*-party protocol *Π*COINto sample random coins. – A simulation extractable non-interactive publicly verifiable proof system *Π*EXP to prove knowledge of exponent. We instantiate this with the non-interactive variant of the classic protocol due to [61] via the Fiat-Shamir transform. We denote the prover and verifier algorithms by (DL*.Ppub,*DL*.Vpub*).

The protocol is split into two parts and presented in Figures7and8. The first three phases of the protocol: Key Generation, Commitment Phase and Aggre- gation are covered in Figure7whereas the Intersection is contained in Figure8.

Theorem 2. *The protocol π*MPSI*described in Figure7and Figure8securely* *realizes FMPSI(described in Figure9) in the presence of malicious adversaries* *and dishonest majority under Decisional Linear (DLIN) and Double Pairing* *Problem (DPP) hardness assumptions.*

Protocol *π*MPSIwith Malicious Security (Part 1)

Input: Party *Pi* is given a set *Xi* = *{x¹i,...,x* *m* *i* *i* *}* of size *mi* for all *i ∈* [*n*]. All parties are given a security parameter 1 *κ* and a description of a group G. The protocol:

1. Key Generation. The parties mutually generate a public key PK and the cor- responding secret key shares (SK₁*,...,* SK*n*) by running *π*GEN. *P₁* also runs the setup for the polynomial commitment scheme by running PCOM*.Setup*(1
*κ* *,m*max).

2. Commitment phase. *P₁* creates commitments to its inputs *{comT*1*,...,* com*Tn}* where com*Ti* = PCOM*.*CommitPt(pp*,x*
*i* 1 *,rTi,m*max) and *rTi ∈* Z*p* is randomly cho- sen and generates a proof using DL*.P* proving knowledge of the committed message and broadcasts the commitment and proof to all parties.

3. Aggregation
(a)For all *i ∈* [2*,n*], party *Pi* computes the coefficients of a polynomial *Ai*(*·*) = (*a* *i* 0 *,...,a*
*imi* ) of degree *mi*, with roots set to the *mi* elements of *Xi*. In addition, *Pi* chooses a random element *λi ←* G and computes the product *λi·a* *ij* for every coefficient within *Ai*. *Pi* sends *P₁* the sets of ciphertexts C*i* = *c* *i* 0 *,...,c* *imi*, encrypting the coefficients of *λi · Ai*(*·*).

(b)Upon receiving the ciphertexts from all parties, party *P₁* combines the follow- ing ciphertexts
Y*n* *i* Y*n* *im* *c₀* = *c₀,...,cm*max= *c*max *i*=2 *i*=2 where *m*max = max(*m₂,...,mn*). Note that *P₁* generates the ciphertexts by encrypting the coefficients of the combined polynomial *A*(*·*) = *λ₂ · A₂*(*·*) +*···*+ *λn·An*(*·*). *P₁* then generates and broadcasts comCwhich is a commitment of the encrypted polynomial C(*·*) = (*c₀,...,cm*max) using PCOM*.*Commit(*pp,*C*,r*C) where *r*Cis generated randomly.

(c)Next, the parties verify whether the polynomials aggregation was done cor- rectly. Specifically, the parties first agree on a random element *u* from the appropriate plaintext domain using the coin tossing protocol *π*COIN (Section
2.5). *P₁* broadcasts the encrypted evaluation *λ*˜ = Eval(PK*,* C*,u*) along with a proof of correct evaluation by using PCOM*.*C*pub*on public inputs pp*,*com*C,u, λ*˜ and private inputs C*,r*C.
(d)Then, each party broadcasts the ciphertext *λ*˜*i* = Eval(PK*,* C*i,u*), together with a ZK proof of knowledge generated using DL*.P* for proving the knowledge of the plaintext. If all the proofs are verified correctly, then the parties check that Q *λ* ˜ *−n* *i*=2*λ*
˜ *i* encodes a 0-message using *π*DecZero.

#### Fig.7: Multi-party PSI protocol (Part 1).

Proof sketch: We split the analysis into two cases based on whether the set of corrupted parties includes the central party *P₁* or not. Consider an adversary *A* that corrupts a set of parties that includes *P₁*. We define a simulator *S* and prove that the real and simulated executions are computationally indistinguishable. The indistinguishability between the real and simulated execution is reduced to the privacy property of the encryption scheme, the hiding property of the

|Protocol π with Malicious Security (Part 2) MPSI The protocol (continued): 4. Intersection. (a)If the above verification is completed correctly, P₁ evaluates the aggregated, on its in- polynomial that is encrypted within ciphertexts C = c₁ ,...,c m max j m 1, and proves consistency with the commitment com. P₁ put elements {x} C 1 j =1 forwards the encrypted evaluations c = Eval(PK, C ,t) along with a proof gen- y batch}}, {c erated using PCOM. C on public inputs pp, com, {com yi Ti C i∈ [m i∈ [m] hid 1} and private inputs C ,r ,X₁, {r Ti C i∈ [m] 1 (b)All parties verify the evaluations and then decrypt the evaluations using pro- tocol π to reveal the intersection. DecZero|]|
|---|---|
|Fig.8: Multi-party PSI protocol (Part 2).||
|Functionality F MPSI F communicates with parties P₁ ,...,P with input sets X₁ ,...,X and an MPSI n n adversary A controlling a subset of parties. 1.Upon receiving a message (input ,P ,X) from party P, store the set X. Once i i i i n all inputs i ∈ [n] are received, set X = ∩ X and send (input) to A. i i =1 2.Upon receiving (deliver) from A, output (output ,X) to P₁. If received (abort) from A, output ⊥ to P₁.||

#### Fig.9: Multi-party PSI Functionality.

commitment schemes, and the privacy property of the polynomial commitment. In the first case, the central party *P₁* is corrupted, and the input of *P₁* can be extracted from *P₁*’s input commitment in the commit phase. The input of other corrupted parties can be extracted by rewinding the aggregation phase. This is achieved by extracting *d*+ 1 evaluation points of every corrupted party’s polynomial as shown in [46]. In the second case, the simulation is the same as the previous case with the exception that it does not need to extract *P₁*’s input. The complete proof is provided in SectionA.2.

Complexity. The communication complexity of our protocol is linear in the in- put sizes and the number of parties, where the smallest input size can be given to P 2 *n* *P₁*. Naively, the communication complexity of our protocol is *O*(*n* +*i*=1*mi*+ *n · m*min*·*log*m*max) when the polynomial commitment is separately used for each evaluation point. The batching feature of our scheme reduces the communica- P 2 *n* tion cost of our protocol to *O*(*n* +*i*=1*mi*+ *n ·* (*m*min+ log*m*max)). For the central party *P₁*, the communication cost is *O*(*n*(*m*min+ log*m*max). *P₁* generates a batched evalution proof of size *O*(*m*min+ log*m*). The dominating cost for *P₁* is sending the evaluation proof to all other parties. For all other parties, the

*P₁ Pi* Total KeyGen *O*(*n*) *O*(*n*) *O*(*n²*) Commit *O*(*n · m*min) — *O*(*n ·* P *m*min) Aggregate *O*(*n ·* log*m*max) *O*(*mi* + *n*) *O*(*n²* + *n* *i*=2*mi*+ *n ·* log*m*max) Intersection *O*(*n ·* (*m*min + log*m*max)) *O*(*m*min) *O*(*n ·* (*m*min + log*m*max)) 2P*n* MPSI *O*(*n ·* (*m*min + log*m*max)) *O*(*n* + *m*min + *mi*) *O*(*n* +*i*=1*mi*+ *n ·* (*m*min + log*m*max))

Table 3: MPSI Communication Complexity.

communication cost is *O*(*n* + *m*min+ *mi*) where *O*(*n*) is sent during the Key Generation phase as well as verifying the aggregation. Additionally, the com- munication cost in sending the encrypted polynomial to *P₁* and generating the intersection is *O*(*mi*) and *O*(*m*min) respectively. We provide a detailed analysis in Table3, providing the communication complexity of the parties individually as well as together along every phase of the MPSI protocol. The round com- plexity of our protocol is dominated by the round complexity of the underlying polynomial commitments. In the random oracle model, the round complexity is

4. Computationally, the dominating part of the protocol is evaluating the ag- gregated polynomial and executing the private polynomial commitment from Section3. The complexity of our protocol is *O*(*m*max*· m*min) exponentiations. We further reduce the polynomial degrees and the overall workload using hash- ing techniques; see below for more details. The space complexity of our protocol

|in the interactive setting is O(m||) for P₁ and O(m|) for every other party|
|---|---|---|---|
|||max|i|
|i|||max|
|i|max|i||
 *P*, while in the non-interactive setting the complexity is *O*(*m*) for *P₁* and *O*(*m* + log*m*) for party *P*. We note that the space complexity of *P₁* is in- dependent of the number of parties. In particular, the polynomials received by the parties can be aggregated on-the-fly and do not require any extra space. Regarding the polynomial commitments, the non-interactive variant requires *Pi* to store the entire proof in the memory which increases the space complexity by an additive factor of *O*(log*m*max). Hashing. A notable optimization in PSI protocols is using simple hashing to map the input into smaller sets (buckets) and running a different instance per bucket. In our context, this enables us to reduce the workload of *P₁* from quadratic to quasilinear. The idea behind simple hashing lies in splitting the input set into bins where based on a hash function, each element is assigned to a bin. Next, the parties sort their input into bins and run an MPSI protocol separately on each bin. Splitting the input into bins reduces the size of the de- gree of the polynomials and improves the computation cost of the parties for the computationally heavy tasks of polynomials interpolations and evaluations. Simple hashing can be directly used in the malicious setting where each bin induces a separated polynomial. Note that the adversary can only attempt to put an item in the wrong bin but this item can be ignored by the simulator. Let *h* be
29

a hash function, *m*maxbe the maximum number of items in an input set, *B* be the number of bins and *M* is the maximum of items in a bin. It is known that if a hash function maps *m*maxitems into q <u>B</u> bins and *m*max*≥B* log*B* then with very high

probability, *M* = *m*max *B* + *m*max *B* log *B* [59,67]. Setting *B* = *m*max log log log *m*max *m*max and

applying the Chernoff bound implies that *M* = *O*( log log <u>log m</u> *m* <u>max</u> max ) with negligible error in *m*max. Simple hashing can be used to reduce the number of exponentia- tions, thereby reducing the computational cost. Namely, for each bin, the number of required exponentiations is *O*(*M²*) and the overall number of exponentiations will be *O*(*BM²*). Substituting the values of *B* and *M* using the above analysis will result in *O*(*m*max log log <u>log m</u> *m* ) exponentiations. We refer to Section6for more details regarding the concrete improvement. The hashing techniques are not useful for improving [9] as they cannot be broken into small instances. While the improvement for [36] will potentially be smaller since its computational complexity is quasilinear in the input size.

### 5 Other Applications

In this section, we consider a list of distributed tasks in different settings, whose realization can make use of private polynomial commitments. All applications can benefit from the batching of our scheme while achieving malicious security.

5.1 Oblivious Polynomial Evaluation Following the discussion from Section1, in this work, we consider a distributed variant of the oblivious polynomial evaluation functionality denoted by DOPE, where the polynomial *Qi*(*·*) is linearly shared amongst a set of *n −* 1 parties. More formally, we define the DOPE functionality as follows. The input of party *Pi*for *i ∈* [2*,n*] is a polynomial *Qi*(*·*) of degree at most
P *d* whereas the input of *P₁* is an element *t*, and the goal is that *P₁* learns*i∈*[2*,n*]*Qi*(*t*).

*P₁* comm *Pi* comm Total comm *P₁* comp *Pi* comp [45] *O*(*n*(*dκ*) + *nλ*) *O*(*dλκ*) *O*((*n* + *λ*)*dκ*) *O*(*ndλ*) *O*(*dλ*) [43] *O*(*nκ*log*d*) *O*(*dκ*) *O*(*ndκ*) *O*(*nd*) *O*(*d*) Our Work *O*(*nκ*log*d*) *O*(*dκ*) *O*(*ndκ*) *O*(*d*) *O*(*d*)

Table 4: Comparison between different DOPE protocols where comm refers to

the communication complexity and comp refers to the computational complex- ity (stated as the number of exponentiations), *κ* is the computational security parameter, *λ* is the statistical security parameter, *n* is the number of parties and *d* is the degree of the polynomial.

We can realize our DOPE functionality (in Figure10)in the presence of *n −*1 malicious corruptions based on our polynomial commitment scheme following

Functionality *FDOPE*

*FDOPE* communicates with parties *P₂,...,Pn* with input polynomial *Q₂*(*·*)*,...,Qn*(*·*), party *P₁* with input point *t* and an adversary *A* controlling the subset of parties.

1.Upon receiving a message (input*,Pi,Qi*) from party *Pi* for *i ∈* [2*,n*], store the polynomial *Qi* and send a message (input) to *A*.
2.Upon receiving a message (input*,P₁,t*) from party *P₁*, store the value *t* and send a message (input) to *A*.
P

3.Upon receiving a message (deliver) from *A*, set *x* =
*n* *i*=2*Qi*(*t*) and output (output*,x*) to *P₁*. If received the message (abort) from *A*, output *⊥* to *P₁*.

#### Fig.10: DOPE Functionality.

the blueprint of our PSI protocol. Namely, the parties send their encrypted coefficients to *P₁* that aggregates the ciphertexts and evaluates *Q*(*·*) on its input

*t*. *P₁* further attaches proofs of correct aggregation and evaluation. Finally, the parties run a distributed decryption protocol for *P₁* to learn *Q*(*t*). Note that, while in PSI the inputs of the parties are extracted from the polynomials’ roots, where the inputs are the polynomial’s shares that form *Q*(*·*). Our scheme is further flexible regarding the level of threshold introduced by the underlying secret sharing scheme. In particular, one may use any threshold linear secret sharing for splitting the polynomial into shares (rather than simple additive sharing), where the threshold parameter can be smaller than *n −* 1. We also have a simple aggregation mechanism which allows the DOPE to be reduced to a single OPE execution where *n −* 1 parties play the role of *P₂*. Two prior OPE constructions with malicious security [45,43] can be extended to the distributed setting, where each party *Pi*for *i ∈* [2*,n*] carries out an indi- vidual OPE with *P₁*. Compared to previous work; see Table4, our construction achieves better computational complexity for the central party *P₁* due to the fact that the aggregation mechanism allows *P₁* to combine the polynomials cheaply and then run the protocol with almost the same cost as running a two-party in- stance of OPE. The overall communication complexity of our protocol is similar to [43] and is better than [45]. Finally, we note that we can further extend our protocol to support multi- variate polynomials to cover a broader class of functionalities.
5.2 Verifiable Polynomial Evaluations In this setting, we focus on verifying the evaluations of a polynomial *Q*(*·*), lin- early shared across a set of *n −* 1 clients, that are aggregated and stored by a cloud server. Specifically, a set of clients outsource their shares of a *d*-degree polynomial (potentially in the clear), to an untrusted server while storing a short state. The server stores the aggregated polynomials and prepares proof for this
31

computation. Next, whenever the clients provide an input *x*, the server com- putes *Q*(*x*) and a short proof that allows the clients to verify this computation in sub-linear time in *d*. We require the verification process to be *public*. Finally, the client’s output *Q*(*x*). Employing our polynomial commitment by the server, the clients can non- interactively verify the proofs it provides. Furthermore, our solution supports the feature that the polynomial may also be kept private since the shares can be stored on the server while encrypted, where only the evaluation points are public. In more detail, each party *Pi*sends the server its polynomial share *Qi*(*·*). The server aggregates the shares and computes a proof of correct aggregation (that can be made non-interactive by using the random oracle to choose the random evaluated point for this test). Upon receiving an input *x*, the parties forward it to the server that computes (the encryption of) *Q*(*x*) together with a proof of correctness. Our protocol is secure in the presence of *n −* 2 corrupted clients, and a colluding server. Note that the degree of *Q*(*·*) may be huge, yet uploading it is a one-time phase whose complexity amortizes away over multiple evaluation points. Moreover, the proofs of correct evaluations can be batched. Related modelling is multi-clients verifiable computation where a set of clients wish to compute some function *f* on their joint inputs while non-interactively communicating only with the server over a sequence of evaluations [25,42,11]. Such constructions have only been demonstrated in a setting where the clients and the server do not collude [42]. Our protocol achieves full security but requires an additional round of communication at the end due to decryption.

Verifiable polynomial evaluations on encrypted data. The second appli- cation in this area is verifiable computation on encrypted data. The notion was proposed by Gennaro et al. in [37] and follow-up works [39,30,31,12] proposed constructions for computations such as linear functions and polynomial evalu- ations. These schemes provide both privacy of the outsourced data to the un- trusted server and the integrity of the results computed by the server. However, these constructions rely on fully or somewhat homomorphic encryptions based on lattice and zero-knowledge proofs over polynomial rings, thus their overhead is high and they have not been realized in practice. Also, these protocols cannot be directly extended to multi-clients. Our scheme yields a more efficient verifiable computation on encrypted data for polynomial evaluations. The prover’s computation only involves operations on bilinear maps, making it one step closer to being practical. In the amortized setting, the verifier’s time is faster than evaluating the polynomial locally for multiple evaluations. In particular, to compute *m* evaluations on a degree-*d* polynomial, the proof size is *O*(*m* + log*d*) and the verifier’s time is *O*(*d* + *m*). Our model requires a setup phase for the clients prior to communicating with the server. This setup phase is independent of the input and is only carried out once, regardless of the number of polynomial evaluations computed later. The clients store a short state upon concluding this phase, which is later used to extract *Q*(*x*). In our protocol, the parties run the key generation protocol for

the underlying threshold encryption scheme, store the secret key share, and use it to partially decrypt the ciphertext returned from the server.

5.3 Non-interactive Two-party PSI (NISI) Ishai et al. [47] introduced the Non-interactive Secure computation (NISC) model where a Receiver first posts an “encryption” of its input publicly and then a Sender can compute a function over the encrypted input along with its input and obtain an “encryption” of the output that the Receiver can decrypt. The classic Yao’s garbled circuit-based two-party protocol in the semi-honest setting when combined with a 2-round OT is an example of such a protocol. Several works have explored the feasibility and concrete efficiency of such protocols in the malicious Boolean setting [47,5,51,44,3]. Private polynomial commitments can be used directly to implement a non-interactive secure private set-intersection protocol by relying on a variant of the [33] protocol. Such a scheme will additionally have the feature of reusability where the receiver only needs to post its encrypted input once and any number of senders can transmit the result of the set intersection to the receiver. An important application of reusable NISI is applicable is contact discovery in messaging services such as Signal and Telegram. Concretely to PSI in the malicious setting, Cristofaro et al. [26] design a two- round PSI protocol with linear communication complexity. More recently, the work by Rosulek and Trieu [60] showed how to obtain a 2-round PSI by relying on a variant of the Diffie-Hellman Key Agreement and an ideal permutation oracle. This work has highly competitive communication and computation costs for small set sizes (between 2
7 and 2 16 elements). We provide a comparison of the communication costs in Table5. We can see that our work is competitive in communication because the proofs are succinct in the batch setting. Additionally, we rely on more standard assumptions. Even though our computation costs are higher our protocol could be useful in a client-server setting where the receiver is a lightweight client device and the sender is the server with significantly bigger computational resources. We further point out that the reported computational costs could be improved by further parallelizing our implementation. We leave this as future work to explore.

### 6 Implementation

We implemented our encrypted polynomial commitment scheme and the multi- party PSI scheme, and we present the experimental results in this section.

*n* 2 8 2 16 2 20 [26] 62.74 (KB) 13.33 (MB) 213 (MB) [60] 16.38 (KB) 4.19 (MB) 67.11 (MB) Here (est.) 49.7 (KB) 5.86 (MB) 68 (MB)

Table 5: Communication cost of two-party PSI with set size *m*.

Software and hardware. The system is implemented in C++. We use the ate- pairing library [1] for bilinear maps and the GMP library [2] for field arithmetic. Our experiments are executed on a BN-curve over a 254-bit prime, which offers 128-bit of security. There are 3200 lines of code for the encrypted polynomial commitment and 1000 lines for the other building blocks in the MPSI protocol. We ran all experiments on an AWS c5.9xlarge instance with an Intel Xeon Plat- inum 8000 processor and 72GB of RAM. We report the average running time over 5 executions, except for the largest instances due to the long running time.

6.1 Private Polynomial Commitments Single evaluation. We first present the performance of our encrypted polyno- mial commitment scheme as a stand-alone primitive. Figure11shows the prover and verifier times (left *y*-axis) and proof size (right *y − axis*) of one evaluation of the variant with committed points (Section3.2). We vary the degree of the polynomial from 2
4 to 2 16. As shown in the figure, the prover time grows linearly with the polynomial degree. It takes 11s to generate the proof for *d* = 2 10 and 701s to generate the proof for *d* = 2 16. The verifier time also grows linearly with the degree, as it has to update the commitment key together with the prover in our scheme. It takes 0.93s to verify the proof for *d* = 2 10 and 53.7s for *d* = 2 16, which roughly matches the time on reducing the commitment key in the prover’s time. The proof size is only logarithmic on the degree of the polynomial and is very small in practice. It is 11.9KB for *d* = 2 10 and 18.6KB for *d* = 2 16.

10445 106 3 Prover Time 40 Prover Time Batch 1013 10 Verifier Time Verifier Time 1012 2 Proof Size 35 104 Proof Size11 10 30 10 110 10 10 25 1010 0 20 10 2 10 Time (seconds) 10 15Proof Size (KB) Time (seconds) 10 89 Proof Size (bytes) 10*−* 1 10 10 010 67 10*−* 25 10 10 5 4 6 8 degree of poly 10 12 14 161 10 *−* 2 2 42628210212214216 104 2 2 2 2 2 2 2 degree of poly

Fig.11: Performance of single eval-Fig.12: Performance of multiple uation of our encrypted polynomial evaluations of our encrypted polyno- commitment with point hiding. mial commitment with point hiding. *m* = *d*.

Multiple evaluations. The major advantage of our scheme is the batched proofs for multiple evaluations and we further present the performance of eval- uating multiple points in Figure12. In the figure, we set the number of evalua- tions the same as the degree of the polynomial, but our implementation supports

|# of elements m|2|2|2|2|2|
|---|---|---|---|---|---|
|Size of bin M|2|2|2|2|2|
|# of bins B|1|81|334|1,366 5,487||
|n = 2|13.94 130.01||536.1|2,192 8,264||
|n = 8|13.96|130.1|536.66 2,194 8,270|||
|n = 32|13.97|130.4|538.4|2,199 8,292||
|n = 128|14.02|131.7|545.56 2,220 8,376|||
|n = 500|14.26|136.4|562.76 2,301 8,712|||
|n = 1000|14.58|142.9|589.5|2,410 9,141||

8 6 6 6 6

Table 6: Total running time of our multiparty PSI scheme in seconds.

both a larger degree and a larger number of evaluations. As shown in the fig- ure, the prover time grows quadratically. It takes 0.225s to generate a proof for *m* = *d* = 2 4 and 242,395s for *m* = *d* = 2 16. The proof size and the verifier time are particularly good for multiple evalu- ations. The proof size is only 7.9KB for *m* = *d* = 2 4 evaluations and 6.1MB for *m* = *d* = 2 16 evaluations, which is significantly smaller than repeating the single evaluation protocol the same number of times. The experimental result matches the logarithmic complexity in *d* and the linear complexity in *m*. The verifier time only grows quasi-linearly now. It only takes 757s to verify 2 16 proofs of evaluations of a degree-2 16 polynomial, which is merely 14*×* larger than verifying a single proof. The experimental result justifies that the verifier time is amortized to *O*(log*d*) for multiple evaluations and is particularly efficient in our application of multiparty PSI.

6.2 Performance of Multi-Party PSI In this section, we report the performance of our multiparty PSI protocol with malicious security. We executed all parties on the single AWS instance and we simulated a network connection using the Linux tc command, communicating via a localhost network. We simulated a LAN setting with 10 Gbps network bandwidth. We executed *P₂* to *Pn*on the same machine but only count the running time of one of them in the total time. This is to better simulate the scheme in practice where all the parties can run the computation simultaneously. We tested our MPSI protocol for 2–1000 parties and 2
8 –2 16 elements per party (here we set *m*max= *m*min) and the total running time are shown in Table6. We applied the hashing technique described in Section4and the pa- rameters achieving 40-bit of statistical security are included in the table. As shown in the table, our protocol is slow for a small number of parties where it takes 13.94s to compute a two-party intersection with 2 8 elements per party. This is 55*×* slower than the malicious MPSI scheme based on symmetric key primitives from [9, Table 5]. The gap is even larger on larger sets, which is expected as our protocol relies on public-key primitives. However, our running time hardly grew with the number of parties where it still takes 14.02s for 128 parties with 2 8 elements each, and 14.58s for 1000 parties. This is because most of the running time is due to evaluating the aggregated polynomial and generating

Evaluation Verify+Decrypt Encryption 6 6 0 0 Proving Communication Random point 10 2 parties 5 0 0 128 parties 104 1000 parties 4 0 0 3 0 0 102Time (s) 2 0 0 Communication cost (MB) 100 1 0 0 0 2 8 3 2 1 2 8 5 0 01 0 0 0 10*−*22 42628 degree of poly210212214216 Numer of Parties

Fig.13: Communication of our mul- Fig.14: Breakdown of the running tiparty PSI protocol. time in our multiparty PSI protocol. *m* = 2 12 elements per party.

the proofs using our commitment scheme, which only depends on the maximum size of the set *m*maxand the size of *P₁*’s set *m*min. In contrast, the running time of PSimple [9] grows linearly with the number of parties and is 0*.*8s for 32 parties with 2 8 elements each, which is 17*×* faster than ours. We expect that our protocol is faster than PSimple for 500 parties with 2 8 elements per party. Our protocol is also efficient in communication. The total communication is shown in Figure13. As shown in the figure, the communication size for 2 parties with 2 8 elements per party is 279 KB, whereas the total communication for 1000 parties with 2 8 elements per party is 278MB, which is not the bottleneck of our protocol. Compared with [9], the communication size is 7.5MB for 2 parties and

7.5GB for 1000 parties respectively, which is around 27*×* larger than ours. The jump in Figure13for *m* = 2
10 is due to using the hashing technique for *m ≥* 2 10. We further show the breakdown of our total running time in Figure14. We fix the size of the set per party at 2 12 and vary the number of parties from 2 to 1000. As shown in the figure, our protocol is clearly computation-heavy and most of the time is on the evaluations of the aggregated polynomial, the proof generation and the verification of our private polynomial commitment. Even with 1000 parties, they contribute to 97.5% of the total running time. Due of this observation, we could improve the total running time significantly through parallelization. Both the polynomial evaluations and the private polynomial commitment are trivially parallelizable. Moreover, the total running time of our scheme is not sensitive to the bandwidth of the network. On a WAN network with 100Mbps bandwidth, our scheme would become around two times slower for 1000 parties. By contrast, the performance of symmetric-key-based schemes such as PSimple is limited by the communication overhead. It cannot be improved through parallelization and will become worse on a network with lower bandwidth. Finally, another major advantage of our protocol is memory usage and scal- ability. As the memory usage of *P₁* is only *O*(*m*max), we are able to scale up to 1000 parties and 2 16 elements per party. The memory usage of *P₁* on this largest instance is only 1GB. We did not test more elements per party due to the long running time, but not have high memory usage. To compare, the PSim- ple scheme [9] runs out of memory for 12 parties and 2 20 elements per party.

This is because *P₁* has to store random OTs for the garbled bloom filter with each party, which leads to a high overhead on the memory. Overall, the experimental results show that our scheme has good scalability and communication in practice, and is particularly efficient for applications with a large number of parties or limited bandwidth networks.

### 7 Acknowledgements

We thank the anonymous PKC‘23 reviewers for their helpful comments. The first and second authors are supported by ISF grant No. 1316/18. The sec- ond, third and fifth authors are supported by DARPA under Contract No. HR001120C0087. The third author was supported by Technology and Humanity Fund from Georgetown University’s McCourt School of Public Policy. Any opin- ions, findings and conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the United States Government or DARPA. Distribution Statement A. Approved for public release. Distribution Unlimited.

### References

1.Ate pairing. [https://github.com/herumi/ate-pairing](https://github.com/herumi/ate-pairing)
2.The GNU multiple precision arithmetic library. [https://gmplib.org/](https://gmplib.org/)
3.Abascal, J., Sereshgi, M.H.F., Hazay, C., Ishai, Y., Venkitasubramaniam, M.: Is the classical GMW paradigm practical? the case of non-interactive actively secure 2pc. In: CCS. pp. 1591–1605 (2020)
4.Abe, M., Fuchsbauer, G., Groth, J., Haralambiev, K., Ohkubo, M.: Structure- preserving signatures and commitments to group elements. J. Cryptol. pp. 363–421 (2016)
5.Afshar, A., Mohassel, P., Pinkas, B., Riva, B.: Non-interactive secure computation based on cut-and-choose. In: EUROCRYPT. pp. 387–404 (2014)
6.Backes, M., Datta, A., Kate, A.: Asynchronous computational VSS with reduced communication complexity. In: CT-RSA. vol. 7779, pp. 259–276 (2013)
7.Backes, M., Fiore, D., Reischuk, R.M.: Verifiable delegation of computation on outsourced data. In: CCS. pp. 863–874 (2013)
8.Bayer, S., Groth, J.: Zero-knowledge argument for polynomial evaluation with application to blacklists. In: EUROCRYPT. pp. 646–663 (2013)
9.Ben-Efraim, A., Nissenbaum, O., Omri, E., Paskin-Cherniavsky, A.: Psimple: Prac- tical multiparty maliciously-secure private set intersection. In: ASIA CCS. pp. 1098–1112 (2022)
10.Benabbas, S., Gennaro, R., Vahlis, Y.: Verifiable delegation of computation over large datasets. In: CRYPTO. pp. 111–131 (2011)
11.Bhadauria, R., Hazay, C.: Multi-clients verifiable computation via conditional dis- closure of secrets. In: SCN. pp. 150–171 (2020)
12.Bois, A., Cascudo, I., Fiore, D., Kim, D.: Flexible and efficient verifiable compu- tation on encrypted data. In: Garay, J.A. (ed.) Public-Key Cryptography – PKC 2021 (2021)
13.Boneh, D., Boyen, X., Shacham, H.: Short group signatures. In: CRYPTO. pp. 41–55 (2004)
14.Bootle, J., Cerulli, A., Chaidos, P., Groth, J., Petit, C.: Efficient zero-knowledge arguments for arithmetic circuits in the discrete log setting. In: EUROCRYPT. pp. 327–357 (2016)
15.Bünz, B., Bootle, J., Boneh, D., Poelstra, A., Wuille, P., Maxwell, G.: Bulletproofs: Short proofs for confidential transactions and more. In: IEEE S&P. pp. 315–334 (2018)
38

16.Bünz, B., Fisch, B., Szepieniec, A.: Transparent snarks from dark compilers. In: EUROCRYPT. pp. 677–706 (2020)
17.Bünz, B., Maller, M., Mishra, P., Tyagi, N., Vesely, P.: Proofs for inner pairing products and applications. In: ASIACRYPT. pp. 65–97 (2021)
18.Camenisch, J., Dubovitskaya, M., Haralambiev, K., Kohlweiss, M.: Composable and modular anonymous credentials: Definitions and practical constructions. In: ASIACRYPT. vol. 9453, pp. 262–288 (2015)
19.Catalano, D., Fiore, D.: Vector commitments and their applications. In: PKC. vol. 7778, pp. 55–72 (2013)
20.Catalano, D., Fiore, D., Gennaro, R., Vamvourellis, K.: Algebraic (trapdoor) one- way functions and their applications. In: TCC. pp. 680–699 (2013)
21.Catalano, D., Fiore, D., Warinschi, B.: Homomorphic signatures with efficient ver- ification for polynomial functions. In: CRYPTO. pp. 371–389 (2014)
22.Chase, M., Miao, P.: Private set intersection in the internet setting from lightweight oblivious PRF. In: Micciancio, D., Ristenpart, T. (eds.) CRYPTO. pp. 34–63 (2020)
23.Chepurnoy, A., Papamanthou, C., Zhang, Y.: Edrax: A cryptocurrency with state- less transaction validation. IACR Cryptol. ePrint Arch. p. 968 (2018)
24.Chiesa, A., Hu, Y., Maller, M., Mishra, P., Vesely, N., Ward, N.: Marlin: Prepro- cessing zksnarks with universal and updatable srs. In: EUROCRYPT. pp. 738–768 (2020)
25.Choi, S.G., Katz, J., Kumaresan, R., Cid, C.: Multi-client non-interactive verifiable computation. In: TCC. pp. 499–518 (2013)
26.Cristofaro, E.D., Kim, J., Tsudik, G.: Linear-complexity private set intersection protocols secure in malicious model. In: Abe, M. (ed.) ASIACRYPT. pp. 213–231 (2010)
27.Fenske, E., Mani, A., Johnson, A., Sherr, M.: Distributed measurement with private set-union cardinality. In: CCS. pp. 2295–2312 (2017)
28.Fiat, A., Shamir, A.: How to prove yourself: Practical solutions to identification and signature problems. In: CRYPTO. pp. 186–194 (1986)
29.Fiore, D., Gennaro, R.: Publicly verifiable delegation of large polynomials and matrix computations, with applications. In: CCS. pp. 501–512 (2012)
30.Fiore, D., Gennaro, R., Pastro, V.: Efficiently encrypted data. In: ACM SIGSAC. pp. 844–855 (2014)
31.Fiore, D., Nitulescu, A., Pointcheval, D.: Boosting verifiable computation on en- crypted data. In: PKC (2020)
32.Freedman, M.J., Ishai, Y., Pinkas, B., Reingold, O.: Keyword search and oblivious pseudorandom functions. In: Kilian, J. (ed.) TCC. pp. 303–324 (2005)
33.Freedman, M.J., Nissim, K., Pinkas, B.: Efficient private matching and set inter- section. In: EUROCRYPT. pp. 1–19 (2004)
34.Gabizon, A., Williamson, Z.J., Ciobotaru, O.: Plonk: Permutations over lagrange- bases for oecumenical noninteractive arguments of knowledge. IACR Cryptol. ePrint Arch. 2019, 953 (2019)
35.Gamal, T.E.: A public key cryptosystem and a signature scheme based on discrete logarithms. IEEE Trans. Inf. Theory pp. 469–472 (1985)
36.Garimella, G., Pinkas, B., Rosulek, M., Trieu, N., Yanai, A.: Oblivious key-value stores and amplification for private set intersection. In: CRYPTO. pp. 395–425 (2021)
37.Gennaro, R., Gentry, C., Parno, B.: Non-interactive verifiable computing: Out- sourcing computation to untrusted workers. In: CRYPTO
39

38.Ghosh, S., Nielsen, J.B., Nilges, T.: Maliciously secure oblivious linear function evaluation with constant overhead. In: Takagi, T., Peyrin, T. (eds.) ASIACRYPT. pp. 629–659 (2017)
39.Goldwasser, S., Kalai, Y.T., Popa, R.A., Vaikuntanathan, V., Zeldovich, N.: How to run turing machines on encrypted data. In: CRYPTO. pp. 536–553. Springer (2013)
40.Gorbunov, S., Reyzin, L., Wee, H., Zhang, Z.: Pointproofs: Aggregating proofs for multiple vector commitments. In: ACM SIGSAC. pp. 2007–2023 (2020)
41.Gordon, S.D., Hazay, C., Le, P.H.: Fully secure PSI via mpc-in-the-head. PoPETS 2022(3), 291–313 (2022)
42.Gordon, S.D., Katz, J., Liu, F., Shi, E., Zhou, H.: Multi-client verifiable computa- tion with stronger security guarantees. In: TCC. pp. 144–168 (2015)
43.Hazay, C.: Oblivious polynomial evaluation and secure set-intersection from alge- braic prfs. In: TCC. pp. 90–120 (2015)
44.Hazay, C., Ishai, Y., Venkitasubramaniam, M.: Actively secure garbled circuits with constant communication overhead in the plain model. In: TCC. pp. 3–39 (2017)
45.Hazay, C., Lindell, Y.: Efficient oblivious polynomial evaluation with simulation- based security. IACR Cryptol. ePrint Arch. p. 459 (2009)
46.Hazay, C., Venkitasubramaniam, M.: Scalable multi-party private set-intersection. In: PKC. pp. 175–203 (2017)
47.Ishai, Y., Kushilevitz, E., Ostrovsky, R., Prabhakaran, M., Sahai, A.: Efficient non-interactive secure computation. In: EUROCRYPT. pp. 406–425 (2011)
48.Juels, A., Jr., B.S.K.: Pors: proofs of retrievability for large files. In: CCS. pp. 584–597 (2007)
49.Kate, A., Zaverucha, G.M., Goldberg, I.: Constant-size commitments to polyno- mials and their applications. In: Abe, M. (ed.) ASIACRYPT. pp. 177–194 (2010)
50.Lee, J.: Dory: Efficient, transparent arguments for generalised inner products and polynomial commitments. IACR Cryptol. ePrint Arch. 2020, 1274 (2020)
51.Mohassel, P., Rosulek, M.: Non-interactive secure 2pc in the offline/online and batch settings. In: EUROCRYPT. pp. 425–455 (2017)
52.Naor, M., Pinkas, B.: Oblivious polynomial evaluation. SIAM J. Comput. pp. 1254– 1281 (2006)
53.Nguyen, D.T., Trieu, N.: Mpccache: Privacy-preserving multi-party cooperative cache sharing at the edge. IACR Cryptol. ePrint Arch. (2021), [https://eprint](https://eprint). iacr.org/2021/317
54.Papamanthou, C., Shi, E., Tamassia, R.: Signatures of correct computation. In: TCC. pp. 222–242. Springer (2013)
55.Pedersen, T.P.: Non-interactive and information-theoretic secure verifiable secret sharing. In: CRYPTO. pp. 129–140 (1991)
56.Pinkas, B., Rosulek, M., Trieu, N., Yanai, A.: Spot-light: Lightweight private set intersection from sparse OT extension. In: Boldyreva, A., Micciancio, D. (eds.) CRYPTO. pp. 401–431 (2019)
57.Pinkas, B., Rosulek, M., Trieu, N., Yanai, A.: PSI from paxos: Fast, malicious private set intersection. In: Canteaut, A., Ishai, Y. (eds.) EUROCRYPT. pp. 739– 767 (2020)
58.Pinkas, B., Schneider, T., Tkachenko, O., Yanai, A.: Efficient circuit-based PSI with linear communication. In: Ishai, Y., Rijmen, V. (eds.) EUROCRYPT. pp. 122–153. Springer (2019)
59.Raab, M., Steger, A.: "balls into bins" - A simple and tight analysis. In: Random- ization and Approximation Techniques in Computer Science. pp. 159–170 (1998)
40

60.Rosulek, M., Trieu, N.: Compact and malicious private set intersection for small sets. IACR Cryptol. ePrint Arch. p. 1159 (2021)
61.Schnorr, C.: Efficient signature generation by smart cards. J. Cryptol. pp. 161–174 (1991)
62.Setty, S.T.V.: Spartan: Efficient and general-purpose zksnarks without trusted setup. In: Micciancio, D., Ristenpart, T. (eds.) CRYPTO. pp. 704–737 (2020)
63.Tomescu, A., Chen, R., Zheng, Y., Abraham, I., Pinkas, B., Gueta, G.G., Devadas,
S.: Towards scalable threshold cryptosystems. In: IEEE S&P. pp. 877–893 (2020)
64.Vlasov, A., Panarin, K.: Transparent polynomial commitment scheme with poly- logarithmic communication complexity. IACR Cryptol. ePrint Arch. 2019, 1020 (2019)
65.Wahby, R.S., Tzialla, I., Shelat, A., Thaler, J., Walfish, M.: Doubly-efficient zk- SNARKs without trusted setup. In: IEEE S&P. pp. 926–943 (2018)
66.Wails, R., Johnson, A., Starin, D., Yerukhimovich, A., Gordon, S.D.: Stormy: Statistics in tor by measuring securely. In: CCS. pp. 615–632 (2019)
67.Wieder, U.: Balanced allocations with heterogenous bins. In: SPAA. pp. 188–193 (2007)
68.Xie, T., Zhang, J., Zhang, Y., Papamanthou, C., Song, D.: Libra: Succinct zero- knowledge proofs with optimal prover computation. In: CRYPTO (2019)
69.Yuan, J., Yu, S.: Proofs of retrievability with public verifiability and constant communication cost in cloud. In: SCC@ASIACCS. pp. 19–26. ACM (2013)
70.Zhang, J., Xie, T., Zhang, Y., Song, D.: Transparent polynomial delegation and its applications to zero knowledge proof. In: IEEE S&P (2020)
71.Zhang, Y., Genkin, D., Katz, J., Papadopoulos, D., Papamanthou, C.: vsql: Ver- ifying arbitrary SQL queries over dynamic outsourced databases. In: IEEE S&P. pp. 863–880 (2017)
72.Zhang, Y., Genkin, D., Katz, J., Papadopoulos, D., Papamanthou, C.: A zero- knowledge version of vsql. IACR Cryptol. ePrint Arch. 2017, 1146 (2017)
## Supplementary Material

### A Full proofs

A.1 Proof of Theorem1
#### Claim. Protocol PCOM (Figures3) satisfies completeness.

To argue completeness of PCOM, it suffices to prove that R accepts in each of the three tests: (1) Private Inner Product Argument (2) Linear Constraints Test, and (3) Testing Quadratic Test. We argue this for each test below: Private Inner Product Argument. This test (Figure4) has two phases, the Masking Phase (Step 1) and the Inner Product Phase (Step 2). At the end of the Product Phase, R accepts if com = comC*′ · e*(com*F′,a*) *· e*(*c* *′y* *,b*) and C opens the com to C *′* *,F* *′* and *c* *′y* in the last round. We will argue that com *′* = comC*′ ·e*(com*F′,a*)*·e*(*c* *′y* *,b*) is where comC*′* and com *′F* are commitments to C *′* and *F* *′* respectively and *c* *′y* = *⟨*C *′* *,F* *′* *⟩*. We show that the invariant is satisfied after every round. First, we will argue that

the invariant holds at the end of the masking phase. The inner product phase proceeds in rounds and we will argue the invariant holds at the end of each iteration and this will conclude the proof of completeness of the inner product phase.

For the Masking Phase, E and *M* are the masking encrypted polynomial and vector respectively. To argue that the invariant holds, we show the com *′*

generated in Step 1(c) is a combined commitment of C *′* = C *⊙* E *x*, *F* *′* = *F* + *x* *−*1 *· M* and *c* *′y* as the inner product of the two. From Step 1(c) we have that com *′* is :

*x x* *−*1 *x x* *−*1 com *·* comE *M l m r*

|· e(com|,a)|· e(c · c|· c ,b)||
|---|---|---|---|---|
|E|M|l|m r x|x|
|C B|y||E|M|
|x|x||||
|l m|r||||
|x|||x||
|C E y|B x l m|x r|M||
|x|||x||
|C E y|B x l m|x r|M||
|x||x|||
|C E|B|M|||
|x|x||||
|y l|m r||||

*−*1 = com *· e*(com*,a*) *· e*(*c,b*) *·* com *· e*(com*,a*) *−*1 *· e*(*c · c · c,b*) *−*1 = com *·* com *· e*(com*,a*) *· e*(com*,a*)) *−*1 *· e*(*c,b*) *· e*(*c · c · c,b*) *−*1 = com *·* com *· e*(com*,a*) *· e*(com*,a*)) *−*1 *· e*(*c,b*) *· e*(*c · c · c,b*) *−*1 = com *·* com *· e*(com *·* com*,a*) *−*1 *· e*(*c · c · c · c,b*) = *P₁ · e*(*P₂,a*) *· e*(*P₃,b*) (2)

*−*1 *−*1

||· com|, P₂ = com|· com|· c · c|. · c|
|---|---|---|---|---|---|
|C|x E||B x M|y x l m|x r|
|′|x|||−1||
|′y ′|′|ck|ck|||

where *P₁* = com and *P₃* = *c*

In order to prove the invariant holds, we need to show that *P₁* is a commit- ment of C = C *⊙* E, *P₂* is a commitment of *B* *′* = *B* + *x · M* and *P₃* is *c* *′y*

#### where c = ⟨C,B ⟩.

We denote AFG*.*Commit1as Commit1. We have

*P₁* = comC*·* com *x* E *x* = Commitck1(C;*r*C) *·* Commitck1(E;*r*E) = Commitck1(C;*r*C) *·* Commitck1(E *x*; *r*E) = Commitck1 *x*

|(C ⊙ E|; r|+ x · r )||
|---|---|---|---|
|ck|C|E||
||′|||
|ck C|C|E||

C E = Commit1(C *′*; *r* + *x · r*) = com *′*

We denote Ped*.*Commitck2as Commitck2and show that *P₂* is a commitment *′* of *B*

*−*1 *x* *P₂* = com*B·* com*M* *−*1 *x* = Commitck2(*B,rB*) *·* Commitck2(*M,rM*) *−*1 = Commitck2(*B,rB*) *·* Commitck2(*x · M,rM*) *−*1 *−*1 = Commitck2 *B M*

|(B + x|· M,r|+ x|· r )|
|---|---|---|---|
|ck ck ′B|′ −1 B|B M|M|

= Commit2(*B,r* + *x · r*) = com

*′y ′y ′ ′* Lastly, we show that *P₃* = *c* where *c* = *⟨*C*,B ⟩* :

*−*1 *x x*

|· c · c|· c|||
|---|---|---|---|
|y l m|r x x x|x x|x x −1|
|x||x −1||
|x ′ ′ ′y|−1|||

*P₃* = *cy l m r* *−*1 = *⟨*C*,B⟩·⟨*E*,B⟩ ·⟨*E*,M ⟩·⟨*C*,M ⟩* *−*1 = *⟨*C*,B⟩·⟨*E*,B⟩·⟨*E*,M ⟩·⟨*C*,M ⟩* *−*1 = *⟨*C*,B⟩·⟨*E*,B⟩·⟨*E*,M ⟩·⟨*C*,x · M ⟩*

= *⟨*C *⊙* E*,B⟩·⟨*C *⊙* E*,x · M ⟩*

= *⟨*C *⊙* E*,B* + *x · M ⟩* = *⟨*C*,B ⟩* = *c*

Substituting the values of *P₁,P₂* and *P₃* in Equation2:

com₀ = *P₁ · e*(*P₂,a*) *· e*(*P₃,b*) *′B ′y* = comC*′ · e*(com*,a*) *· e*(*c,b*)

This shows that the invariant is satisfied at the end of the masking phase.

*′* For the Inner Product Phase (Step 2), we argue that com = comC*′·e*(com*F′,a*)*·* *′y ′ x ′ −*1 *′y ′ ′* *e*(*c,b*) where C = C*L⊙* C*R*, *B* = *BL*+ *x · BR*and *c* = *⟨*C*,B ⟩* and comC*′* *′ ′ ′* and com*B′* are commitments to C and *B* respectively. Let the com generated

in step 2(f) be denoted as com*i*and expanded below:

com*i*= *L* *x* *·* com *· R* *x*

= (comC*R· e*(com*BL,a*) *· e*(*cl,b*)) *x*

*·* (comC*· e*(com*BL,a*) *· e*(*cy,b*)) *x* *−*1 *·* (comC*L· e*(com*BR,a*) *· e*(*cr,b*)) *x x* *−*1 = (comC *R* *·* comC*·* comC *L* ) *x x* *−*1 *·* (*e*(com*BL,a*) *· e*(com*B,a*) *· e*(com*BR,a*)) *x x* *−*1 *·* (*e*(*cl,b*) *· e*(*cy,b*) *· e*(*cr,b*)) *x x* *−*1 = (comC *R* *·* comC*·* comC *L* ) *x x* *−*1 *·* (*e*(com*B* *L* *,a*) *· e*(com*B,a*) *· e*(com*B* *R* *,a*)) *x x* *−*1 *·* (*e*(*cl,b*) *· e*(*cy,b*) *· e*(*cr,b*)) *x x* *−*1 = (comC *R* *·* comC*·* comC *L* ) *x x* *−*1 *· e*(com*B* *L* *·* com*B·* com*B* *R* *,a*) *x x* *−*1 *· e*(*cl· cy· cr,b*) = *P₁ · e*(*P₂,a*) *· e*(*P₃,b*) (3)

*x x* *−*1 *x x* *−*1 where *P₁* = comC *R* *·* comC*·* comC *L*, *P₂* = com*B* *L* *·* com*B·* com*B* *R* and *P₃* = *x x* *−*1 *c* *l· cy· cr*. In order to prove the invariant, we show that *P₁* is a commitment of C *′* = C*L⊙* C *x* *R*, *P₂* is a valid commitment of *B* *′* = *BL*+ *x* *−*1 *· BR*and *P₃* is *c* *′y* where *c* *′y* = *⟨*C *′* *,B* *′* *⟩*. We denote AFG*.*Commitck1as Commitck1and we show that *P₁* is a commit- ment of C *′* :

*x x* *−*1 *P₁* = comC *R* *·* comC*·* comC *L* = Commitck1*L*(C*R,r*C*R*) *x* *·* Commitck1(C*,r*C) *x* *−*1 *·* Commitck1*R*(C*L,r*C*L*) = Commitck1*L*(C *x* *R,x · r*C*R*) *·* Commitck1(C*,r*C) *·* Commit ck*x−* 1 (C*L,x* *−*1 *· r*C*L*) 1*R* = Commitck1*L*(C *x* *R,x · r*C*R*) *·* Commitck1*L*(C*L,r*C*L*) *·* Commitck1*R*(C*R,*0) *·* Commit ck*x−* 1 (C*L,x* *−*1 *· r*C*L*) 1*R* = Commitck1*L*(C *x* *R,x · r*C*R*) *·* Commitck1*L*(C*L,r*C *·* Commit ck*x−* 1 (C *x* *R,*0) *·* Commitck*x−*1 (C*L,x* *−*1 *· r*C*L*) 1*R* 1*R* = Commitck1*L*(C*L⊙* C *x* *R,x · r*C*R*+ *r*C) *·* Commit ck*x−* 1 (C*L⊙* C *x* *R,x* *−*1 *· r*C*L*) 1*R* = Commit ck1*L⊙*ck*x−* 1 (C*L⊙* C *x* *R,x · r*C*R*+ *r*C+ *x* *−*1 *· r*C*L*) 1*R* = Commit ck1*L⊙*ck*x−* 1 (C *′* *,x · r*C*R*+ *r*C+ *x* *−*1 *· r*C*L*) 1*R* = comC*′*

We denote Ped*.*Commitck2as Commitck2and we show that *P₂* is a valid com- *′* mitment of *B* : *−*1 *x x* *P₂* = com*B·* com*B·* com*B* *L R* *x* = Commitck2*R*(*BL,rBL*) *·* Commitck2(*B,rB*)*·* *−*1 *x* Commitck2*LR BR*

|(B|,r )||||
|---|---|---|---|---|
|ck|R B||||
||x||||
|ck L|B|ck|R||
|||||x|
|ck|L B|ck|R B||
|ck L|B|ck|R −1|−1|
|ck|L B|ck|R|B|
||||−1||
|ck L|B|ck|R −1|−1|
|ck|L B|ck|R|B|
||−1||||
|ck L|R −1|B|−1||
|ck|L −1|R B|B|−1|
|ck ⊙ck|L ′|R B −1|B|B|
|ck ⊙ck|B|B|B||
|′y x x l y r|′y|′ ′|||
|x||x|||
|R L||L R|||
|x||x|||
|R L||L R|||
|x|||x||
|R L|L L|R R|L R||
|x||x|−1||
|R L|L L|R R|L|R|
|x||x −1|||
|L R|L L|R|R||
|x|−1||||
|L R ′ ′ ′y|L|R|||

*x* = Commit2*R*(*B,rL*) *·* Commit2*R*(*B,*0) *−*1 *·* Commit2*L*(*B,r*) *·* Commit2*L*(*B,rR*) = Commit *x* (*B,x · rL*) *·* Commit2*R*(*B,*0) 2*R* *·* Commit2*L*(*B,r*) *·* Commit2*L*(*x · B,x · rR*) = Commit *x* (*B,x · rL*) *·* Commit *x* (*x · B,*0) 2*R* 2*R* *·* Commit2*L*(*B,r*) *·* Commit2*L*(*x · B,x · rR*) = Commit *x* (*B* + *x · B,x · rL*) 2*R* *·* Commit2*L*(*B* + *x · B,r* + *x · rR*) = Commit2*L x* (*B* + *x · B,x · rL*+ *r* + *x · rR*) 2*R* = Commit2*L x* (*B,x · rL*+ *r* + *x · rR*) 2*R* = com*B′*

Lastly, we show that *P₃* = *c* where *c* = *⟨*C*,B ⟩* :

*−*1 *P₃* = *c · c · c* *−*1 = *⟨*C*,B ⟩ ·⟨*C*,B⟩·⟨*C*,B ⟩* *−*1 = *⟨*C*,B ⟩·⟨*C*,B⟩·⟨*C*,B ⟩* *−*1 = *⟨*C*,B ⟩·⟨*C*,B ⟩·⟨*C*,B ⟩·⟨*C*,B ⟩*

= *⟨*C*,B ⟩·⟨*C*,B ⟩·⟨*C*,B ⟩·⟨*C*,x · B ⟩*

= *⟨*C *⊙* C*,B ⟩·⟨*C *⊙* C*,x · B ⟩*

= *⟨*C *⊙* C*,B* + *x · B ⟩* = *⟨*C*,B ⟩* = *c*

Substituting the values of *P₁,P₂* and *P₃* in Equation3:

com*i*= *P₁ · e*(*P₂,a*) *· e*(*P₃,b*) *′B ′y* = comC*′ · e*(com*,a*) *· e*(*c,b*)

This shows that the invariant is satisfied. In the last round, C opens up all the commitment and is trivially complete. Linear Constraint Test: In the “Linear Constraint Test", the protocol reduces checking *A×T* = *X* to checking *S×A×T×U* = *S×X×U* where *S* and *U* are generated by R. As *S,U* are random linear combiners, this allows the reduction of the problem to go through. Assuming that BBA-IPA satisfies completeness,

in the “Linear Constraint Test", we reduce the test from checking *⟨S,T ⟩* =

|||A U|
|---|---|---|
|−1|A U|U|
|−1|||

*⟨S,XU⟩* to *⟨L,R⟩* = *x · l*+ *x r* where *l* = *⟨S, −X ⟩* and *r* = *⟨S,T ⟩*. We show that *⟨L,R⟩* = *x · l* + *x · r* below:

*⟨L,R⟩* = *x · l* + *x* *−*1 *· r*

= *x ·⟨SA, −XU⟩* + *x* *−*1 *·⟨S,TU⟩*

= *⟨SA, −x · XU⟩* + *⟨x* *−*1 *· S,TU⟩* = *⟨SA U A U*

|, −x · X|⟩ + ⟨S|,T ⟩+||
|---|---|---|---|
|A|U A|U||
||−1|||
|U||U||
|A|U A|U||
|−1|U|−1|U|
|||−1||
|A U −1|U||U|
|A|U|U||

*⟨S, −X ⟩* + *⟨x · S,T ⟩* = *⟨S, −x · X ⟩* + *⟨S,T ⟩*+

*⟨x · S, −x · X ⟩* + *⟨x · S,T ⟩*

= *⟨S,T − x · X ⟩* + *⟨x · S,T − x · XU⟩*

= *⟨S* + *x · S,T − x · X ⟩*

At the end, the completeness property of BBB-IPA ensures the completeness of this phase.

Quadratic Constraint Test: In the “Quadratic Constraint Test", the protocol reduces checking *∀i ∈* [*m*]*,X*

||⊙ Y = Z|is modified to a single check for each i by|||
|---|---|---|---|---|
|m i|i i|i|i i i i|i i|
|i=1|i i|i|||

using a random linear combiner and is modified as *X ⊙Y ⊙R* = *Z ⊙R*. This can furthermore be written as in inner product *∀i ∈* [*m*]*⟨X,Y ⊙ R⟩−⟨Z ⊙ R⟩* = 0. This, in turn, can be reduced to a single inner product using another random P linear combiner *w* (*⟨X,Y ⊙ R⟩−⟨Z ⊙ R⟩*). Using the similar technique in phase 2 (or "Linear Constraint Test"), the summation formerly introduces can be reduced to a single inner product (at every iteration, the number of inner products is reduced by a factor of 2). The analysis used to show the completeness of phase 2 can also be applied here to show completeness after every iteration. In the end, the completeness property of BBB-IPA ensures the completeness of this phase. This concludes the proof of completeness.

#### Claim. Protocol PCOM (Figures3) satisfies Binding

To argue the binding property of PCOM, it can be trivially reduced to the binding property of the Ped and AFG commitment scheme.

*Claim.* Protocol PCOM (Figures3) satisfies Witness-Extended Emulation

Consider a public-coin interactive protocol with *r* rounds. We define (*n₁,...,nr*)- tree of accepting transcripts for this interactive protocol as follows. The tree is of depth *r* where the root is labelled with the statement and each node in depth *i* has *ni*children, where each child is associated with the *i* *th* challenge. Each edge from parent to child node is associated with a message sent from the prover to the verifier. Each root-to-leaf path corresponds to an accepting transcript.

Using the Forking Lemma (Lemma1), we can reduce the witness-extended emulation property to the existence of a PPT extractor *X*, which given (*n₁,...,nr*)- tree of accepting transcripts can extract the witness of the polynomial com- mitment scheme. In the proof discussed below, we will assume we have these (*n₁,...,nr*)-tree of accepting transcripts where each *n* = 3 except *n₁* = *m*

|||i|
|---|---|---|
|i=1|⌈log (d)+1⌉|3/2|
|r i|||

Q. This ensures *n* = *m ·* 32*≤* 3 *· md* which is bounded by a polynomial in *d* and *m* and in turn *λ*. First, we construct a witness-extraction algorithm *X₁* that succeeds in ex- tracting the witness of the “Private Inner Product Argument" given (*n₁,...,nr*)- tree of accepting transcripts. Denote the challenge message send by C in Round *i* as *x*

(*i*). We also represent
variables in each round with superscript (*i*). In round *a*, C opens the commitment com. This allows *X₁* to get C

(*a*) and
*B*

(*a*) for round *a*. The extractor *X₁* rewinds C three times. Except with negligible
probability, it receives three different values of *x*

(*i*) denoted by *x₁,x₂,x₃* such
that *xi̸*= *xj*for 1 *≤ i < j ≤* 3. Let us denote these transcripts as *T₁,T₂,T₃*. Using *T₁,T₂,T₃*, *X₁* obtains *BL*and *BR*by solving the linear equation below:

*−*1 (*a*) *BL*+ *xi· BR*= *Bi*(4)

(*a*) (*a*)
where *Bj*is *B* extracted in transcript *Tj*. *X₁* extracts *B* (*a−*1) = *BL||BR*. Using *T₁,T₂,T₃*, *X₁* obtains C*L*and C*R*by solving the linear equation below:

*x* *i*(*a*) C*L⊙* C*R*= C*j*

(*i*+1) (*i*+1) where C*j*is C extracted in transcript *Tj*. *X₁* extracts C (*a−*1) = C*L||*C*R*. We can repeat the above steps recursively for every round. We also use this same technique for extracting the unmasked version of C and *B*. Now to extract all the evaluation vectors *X* extracts different *B* using *X₁* based on the random linear combiner (*r₁,...,rm*). Now *X* rewinds the C *m−* times where it receives, except with negligible probability, *m−* transcript *T₁,...Tm* with *m−* different set of linear combiners where (*r₁* *i* *,...rm* *i* ) is set as the random linear combiners for each transcript *Ti*. Using *T₁,...,Tm*, *X* obtains *ti*by solving the linear equation below:

X *m* *Bj*= *rijti* *i*=1

where *Bj*is *B* extracted in transcript *Tj*. Once *B* is extracted, *X* can rewind the protocol to Figure3(Step 1) and repeat it till there are *m* + 1 set of different vectors *S*. Using this and solving linear equations, *X* can extract each evaluation vector *{Ti}i∈*[*m*]and can extract *{ti}i∈*[*m*]trivially.

*Claim.* Protocol PCOM (Figures3) satisfies Honest Verifier Privacy

We describe the Simulator *S* in Figure15. Indistinguishability of the sim- ulation essentially follows from semantic security of the underlying encryption scheme, hiding of the commitment scheme and masking techniques. More for- mally, we consider a sequence of intermediate hybrid experiments and argue indistinguishability via a standard hybrid argument. Hybrid₀: This hybrid experiment proceeds as in the real world, i.e. the output of the experiment is the output of the malicious receiver when interacting with the honest committer. Hybrid₁ : This hybrid is identical to Hybrid₀ with the exception that we consider a simulator that proceeds as an honest committer against the malicious receiver but replaces the protocol of BBB-IPA in “Linear Test Constraints" and “Quadratic Test Constraints" with its simulation *SBBB−IPA*. The indistinguisha- bility of Hybrid₀ and Hybrid₁ follows from the Zero-Knowledge property of BBB-IPA. Hybrid₂ : This hybrid is identical to Hybrid₁ with the exception that the simulator replaces all the *li*and *ri*vector in “Quadratic Constraint Test" with random vectors. This is possible due to the fact that any checks related to *li*and *r* *i*were done in BBB-IPA which is replaced by its simulator *SBBB−IPA*and will generate a transcript that is always accepted by R. This is the same as replacing the “Quadratic Constraint Test" with *Sp*3. Hybrid₃ : This hybrid is identical to Hybrid₂ with the exception that the simulator chooses a random vector *v* in “Linear Constraint Test" with a random *x x* *−*1 *−*1 vector as well as chooses *l,r* such that *l* + *r* =*< sA− x · s,v >*. This is possible due to the fact that any checks related to *v,l* and *r* were done in BBB- IPA which is replaced by its simulator *SBBB−IPA*and will generate a transcript that is always accepted by R. This is the same as replacing the “Linear Constraint Test" with *Sp*2. Hybrid₄ : This hybrid is identical to Hybrid₃ with the exception that the simulator chooses random encrypted polynomial C *′* and a random vector *B* *′* and *x* *mxm* *−*1

||such that com||· E = com|, com|such that com||· com|=|
|---|---|---|---|---|---|---|---|---|
|B|l r||x l y|x r|′y||||
|||||||||p1|
|||y|||||||

set comE C C*′M B M* *x* *m xm* *−*1 *′y* com *′* and *c,c* such that *c · c · c* = *c*. This is possible due to the fact the inner product part of the "Private Inner Product Argument" will accept this proof. This is the same as replacing “Private Inner Product Argument" with *S*. Hybrid₅: This hybrid is identical to Hybrid₄ with the exception that the simulator replaces *c* in Eval algorithm with *S₃*. This involves outputting a ran- dom ciphertext. The indistinguishability of Hybrid₄ and Hybrid₅ follows from the IND-CPA security of the encryption scheme. Hybrid₆ : This hybrid is identical to Hybrid₅ with the exception that the simulator replaces comCgenerated using Commit algorithm with *S₁*. This involves committing to a random encrypted polynomial. The indistinguishability of Hybrid₅ and Hybrid₆ follows from the hiding property of the commitment scheme. Hybrid₇ : This hybrid is identical to Hybrid₆ with the exception that the simulator replaces com*T*generated using CommitPt algorithm with *S₂*. This

involves committing to a random point. The indistinguishability of Hybrid₆ and Hybrid₇ follows from the hiding property of the commitment scheme. Hybrid₈ : This hybrid is identical to Hybrid₇ with the exception that the simulator replaces protocol (C*,*R) with *S*. We argue that Hybrid₇ and Hybrid₈ are perfectly indistinguishable. This is due to the fact that protocol (C*,*R) in Hybrid₇ does not use the real inputs in the simulation. Hybrid₉: This hybrid is identical to Hybrid₈ with the exception that sim- ulator does not get the real inputs. We argue that Hybrid₈ and Hybrid₉ are perfectly indistinguishable. This is due to the fact that Hybrid₈ does not use the real inputs in the simulation.

A.2 Proof of Theorem2 We split the analysis into two cases based on whether the set of corrupted parties includes the central party *P₁* or not. Case 1: the corrupted set includes the central party *P₁* : Consider an adversary *A* that corrupts a set of parties that includes *P₁*. We define the simu- lator *S* in Figure16. We prove that the real and simulated executions are com- putationally indistinguishable. The differences in both executions reduce to the privacy property of the encryption scheme and the hiding property of the com- mitment scheme. Our proof follows via a sequence of hybrids between Hybrid₀ to Hybrid₄ where Hybrid₀ is identical to the real execution while Hybrid₄ is identical to the simulated execution. Hybrid₀: The first game is the real execution. Hybrid₁: This hybrid is identical to Hybrid₀ with the exception that we define a simulator that extracts the input of corrupted parties as done in the simulation. More specifically, let *Xi*denote the input of party *Pi*. Recall that the simulator knows the input of the honest parties as well, it then checks whether the final output is correct with respect to all inputs and aborts otherwise. Finally, based on the witness-extended emulation property of PCOM, the correctness of *π*DecZero and the binding property of the commitment generated by *P₁*, the extracted values will be consistent. Therefore the simulator will only abort with negligible probability. This implies that the output distributions of the two executions are statistically close. Hybrid₂: This hybrid is identical to Hybrid₁ with the exception that the sim- ulator replaces *π*GENand *π*DecZerowith *S*GENand *S*DecZero, respectively. Note that, this allows the simulator to simulate *π*DecZerowithout knowing the actual secret key. Let *Z* denote the intersection as computed in the previous hybrid. In this hybrid, the simulator enforces the output of *π*DecZeroaccording to whether the evaluated point is in *Z* or not. Namely, for every *z ∈ X₁*, if *z ∈ Z* then *S*DecZeroenforces the output to be zero, else a random element. This is done by invoking *S*DecZeroon the public key, the secret key shares of the corrupted parties and the resultant plaintext. Indistinguishability follows from the security
49

of the threshold encryption scheme. This implies that Hybrid₁ and Hybrid₂ are indistinguishable.

Hybrid₃: This hybrid is identical to Hybrid₂ with the exception that the simu- lator replaces *π*EXPwith its simulator *S*EXPrespectively. The indistinguishability of Hybrid₂ and Hybrid₃ follows from the zero-Knowledge property of *π*EXP.

Hybrid₄: This hybrid is identical to Hybrid₃ with the exception that the simu- lator replaces the real inputs of honest parties with random inputs. Namely, the simulator sends ciphertexts encrypting random polynomials on behalf of the hon- est parties. The indistinguishability of Hybrid₃ and Hybrid₄ follows from the IND-CPA security of the encryption scheme. As the simulator does not need to know the secret key, the ciphertexts obtained from the IND-CPA security game can directly be plugged into the protocol and can be reduced to the IND-CPA security game. Finally, we note that the above hybrid is identical to the simulation. This concludes the proof of the first case. Case 2: the corrupted set excludes the central party *P₁*: The proof for this corruption case is very similar to the previous case with the exception that the simulator does not need to extract the input of *P₁*. Consider an adversary *A* that corrupts a set of parties that excludes *P₁*. We define the simulator *S* in Figure17. We prove that the ensemble of real execution and simulated execution are computationally indistinguishable. The difference in both the ensemble reduces to the privacy property of the encryption scheme and hiding property of perfectly hiding commitments. Our proof follows a sequence of hybrid proofs. Our proof consists of multiple hybrids from Hybrid₀ to Hybrid₅. Hybrid₀ is identical to the real execution while Hybrid₅ is identical to the simulated execution. Hybrid₀: The first game is the real execution. Hybrid₁: This hybrid is identical to Hybrid₀ with the exception that the simulator extracts the input of corrupted parties. The simulator extracts the inputs of all corrupted parties from *π*EXP, and aborts if it fails to extract. Let *Xi*be the inputs for each corrupt party *Pi*. It checks if the final output is correct with respect to *Xi*. This is possible as the simulator in this hybrid knows the real input of honest parties. For extracting the inputs of corrupt parties, the simulator rewinds to the point where all parties generate a random value *u*. The simulator rewinds till *d*+ 1 evaluations are recorded where *π*EXPprovides a valid proof and the message can be extracted. For each corrupt party *Pi*, the simu- lator receives *d* + 1 evaluation on its polynomial and then can be interpolated. The roots of the interpolated polynomial are the inputs of the corrupt party. Taking the intersection of these inputs generates *X* *∗*. Finally using the witness- extended emulation of PCOM, soundness of *π*DecZeroand the binding property of the commitment generated by *P₁*, the extracted values will be consistent. There- fore the simulator will abort with negligible probability if extracted inputs is not consistent and will deviate from Hybrid₀ otherwise Hybrid₀ will be perfectly indistinguishable from Hybrid₁. This shows that Hybrid₀ and Hybrid₁ are indistinguishable.

Hybrid₂: This hybrid is identical to Hybrid₁ with the exception that the simulator replaces *π*GENand *π*DecZerowith *S*GENand *S*DecZerorespectively. The set intersection *X* can also be evaluated based on the extracted inputs of corrupt parties and inputs of the honest parties. *S*DecZerois given a message and it needs to bias the output of decryption according to the message. For every *z ∈ X₁*, if *z ∈ X* then *S*DecZerowill bias the output to be zero else a random element. The indistinguishability follows from the property of threshold decryption. This shows that Hybrid₁ and Hybrid₂ are indistinguishable. Hybrid₃: This hybrid is identical to Hybrid₂ with the exception that the simulator replaces PCOM and *π*EXPwith their respective simulators *S*PCOMand *S*EXPrespectively. The indistinguishability of Hybrid₂ and Hybrid₃ follows from the Zero-Knowledge property of PCOM. Hybrid₄: This hybrid is identical to Hybrid₃ with the exception that the simulator replaces the commitment generated by *P₁* with a commitment to 0- message. The indistinguishability of Hybrid₃ and Hybrid₄ follows from the hiding property of the commitment scheme. We reduce the indistinguishability of Hybrid₃ and Hybrid₄ to the hiding game of commitment. Hybrid₅: This hybrid is identical to Hybrid₄ with the exception that the simulator replaces the real inputs of honest parties with random inputs. The simulator sends the encryption evaluation of random polynomials on behalf of the honest parties. The indistinguishability of Hybrid₄ and Hybrid₅ follows from the IND-CPA security of the encryption scheme. As the simulator does not need to know the secret key, the ciphertext obtained from the IND-CPA security game can directly be plugged into the protocol and can be reduced to the IND-CPA security game.

*S* for PCOM

*S*(pp*,*PK*,d*; *rs*) :

1.Invoke Simulator *S₁*, *S₂* and *S₃* to generate comC*← S₁*(pp*,*PK;*rs*), com*T ←* *S₂*(pp*,d*; *rs*) and *cy ←S₃*(PK;*rs*).
2.The simulators *Sp*1, *Sp*2 and *Sp*3 are simulators for "Private Inner Product Argu- ment", "Linear Constraint Test" and "Quadratic Constraint Test". *S₄* invokes the simulator *Sp*1(pp*,*PK*,*comC*,*com*T,cy*; *rs*), *Sp*2(pp*,*com*T*; *rs*) and *Sp*3(pp*,*com*T*; *rs*) comC*←S₁*(pp*,*PK;*rs*) :
1.Generate a random encrypted polynomial C
*∗* and compute com *∗* *C*as follows:

comC= Commit(pp*,* C *∗*; *r*C *∗* )

where *r*C *∗* is randomly chosen. We use randomness *rs* to generate C *∗* and *r*C *∗*.

com*T ←S₂*(pp*,d*; *rs*) :

1.Generate a random point *t*
*∗* and compute com*T* as follows:

com*T* = CommitPt(pp*,t* *∗* *,d,rt∗*)

where *rt∗*is randomly chosen. We use randomness *rs* to generate *t* *∗* and *rt∗*.

*c* *y ←S₃*(PK;*rs*) :

1.Generate a random value *m* and *r* and compute *cy* as follows:
*c* *y* = BBS*.*EncPK(*m*; *r*)

where PK is the public key.We use randomness *rs* to generate *m* and *r*.

*Sp*1(pp*,*PK*,*comC*,*com*T,cy*; *rs*) :

1.Generate a random encrypted polynomial C
*′* and a random vector *B* *′* using ran- domness *rs*. Also generate their respective commitments comC*′* and com*B′*hon- estly. Also set *c* *′y* =*<* C *′* *,B* *′* *>*.

2.Based on the challenge *xm* in the masking phase, set: – comEsuch that comC*·* com
*x* E *m* = comC*′* is satisfied. *x−*1 – com*M* such that com*B ·* com*Mm*= com*B′*is satisfied. *x xm−*1*′y* – *cl,cr* such that *cl m· cy · cr*= *c* is satisfied.

3.Run the test similar to “Private Inner Product Argument" with the changes above in the masking part. *Sp*2(pp*,*com*T*; *rs*) :
1.Choose a random vector *v* using randomness *rs* and set *l,r* such that *l · x* + *x*
*−*1 *·* *r* =*< sA − x* *−*1 *· s,v >*.

2.Run the test similar to “Linear Constraint Test" with the changes above in Step 3 in the protocol as well as replace BBB-IPA and instead execute its simulator *SBBB−IPA* on the inner product *< sA − x*
*−*1 *· s,v >*= *x · l* + *x* *−*1 *· r*.

*Sp*3(pp*, {*com*t*1*,...,* com*tm}*; *rs*) : 52

1.Choose 4m random vector *li* and *ri* for *i ∈* [2*m*] using randomness *rs*.
2.Run the test similar to the “ Quadratic Constraint Test" with the changes above in Step 3 in the protocol as well as replace BBB-IPA and instead execute its simulator *SBBB−IPA*.
#### Fig.15: Simulator S for PCOM

Simulator *S*

1. Key Generation: *S* generates (PK*,*SK) *←* KeyGen and invokes the simulator *S*Gen(PK) for *π*Gen.
2. Commitment Phase: Upon receiving the commitments on *P₁* inputs’ as well as a proof of knowledge *π*EXP, *S* extracts the input *X₁* of *P₁* by invoking the extractor *E*
DL.

3. Aggregation:
(a)For every party *i ∈ H* where *H* is set of all honest parties, *S* generates a random polynomial *Ci*(*·*) of degree *mi*, encrypts its coefficients and sends the ciphertexts to *P₁* on behalf of *Pi*.
(b)Upon receiving the commitment of the encrypted polynomial C denoted by comC, *S* participates honestly in *π*COIN on behalf of the honest parties.
(c)Let *u* denote the output of *π*COIN. *S* then participates uses PCOM*.Vpub*and verifies whether *λ*˜ = Eval(PK*,* C*,u*) and comC= PCOM*.*Commit(pp*,*C).
(d) *S* honestly evaluates its input polynomial on *u* and invokes the simulator for *π*EXP on behalf of the honest parties.
(e)Excluding the central party *P₁*, *S* extracts the corrupt parties’ inputs. This is achieved by extracting *d* + 1 evaluation points of every corrupted party’s polynomial. In more details, each corrupt party sends a ciphertext together with a proof of knowledge *π*EXP, where these ciphertexts are generated by evaluating the input polynomials on the evaluation point *u*. Upon receiv- ing the ciphertexts and the proofs, *S* extracts the plaintexts by running the simulation-extractor *E*
DL. This process is repeated for every corrupted party multiple times. Namely, to extract the input polynomial of each corrupted party, *S* rewinds the adversary to the beginning of *π*COIN in order to generate a new random element *v*. *S* records *d*+ 1 such evaluations for each corrupted party and use them to interpolate each input polynomial and extract its roots. Let the input set extracted for a corrupt party *Pi* denoted by *Xi*. *S* also in- vokes the simulator of *π*DecZero on behalf of the honest parties.

4. Intersection:
(a) *S* sends *Xi* as an input of corrupt party *Pi* to the trusted party and receives set intersection *Z* from the trusted party.
(b) *S* receives *cyi* for each *xi ∈ X₁*. *S* furthermore participates honestly in PCOM on behalf of other honest parties to ensure *cyi* = Eval(PK*,* C*,xi*) and com*xi* is a commitment to *xi*.
(c)For every *x*
*j* 1*∈ Z* where *x* *j* 1is *j* *th* element in set *X₁*, *S* enforces the decryption to be zero and a random element otherwise. This is achieved by invoking the simulator *S*DecZero on the appropriate plaintext (zero if element in *Z* or a random element otherwise), PK and corrupted parties’ share of secret key.

5. *S* outputs the same as *A*.
Fig.16: Simulator for MPSI protocol (Case 1)

Simulator *S*

1. Key Generation: *S* generates (PK*,*SK) *←* KeyGen and invokes the simulator *S*Gen(PK) for *π*Gen.
2. Commitment Phase: *S* commits to all 0 for *P₁* commitment and executes a fake proof of knowledge by invoking the simulator *S*EXP.
3. Aggregation:
(a)For every honest party *i ∈H* where *H* is set of all honest parties, *S* generates a random polynomial *Ci*(*·*) of degree *mi*, encrypts this random polynomial by encrypting the coefficients on behalf of *Pi*.
(b) *S* generates the commitment comCby invoking the simulator *S*PCOMand sends to the adversary on behalf of *P₁*.
(c) *S* participates honestly in *π*COIN on behalf of the honest parties.
(d)Upon receiving *u* as the output of *π*COIN, *S* invoke the simulator *S*PCOMto pass the verification.
(e) *S* sends a ciphertext and invokes *π*EXP honestly on behalf of the honest parties where the input polynomial used is the same polynomial which was encrypted.
(f) *S* extracts the corrupt parties’ inputs. This is achieved by extracting *d* + 1 evaluation points of every corrupted party’s polynomial. In more detail, each corrupt party sends a ciphertext together with a proof of knowledge *π*EXP, where these ciphertexts are generated by evaluating the input polynomials on the evaluation point *u*. Upon receiving the ciphertexts and the proofs, *S* extracts the plaintexts by running the simulation-extractor *E*
DL. This process is repeated for every corrupted party multiple times. Namely, to extract the input polynomial of each corrupted party, *S* rewinds the adversary to the beginning of *π*COIN in order to generate a new random element *v*. *S* records *d* + 1 such evaluations for each corrupted party and uses them to interpolate each input polynomial and extract its roots. Let the input set extracted for a corrupt party *Pi* denoted by *Xi*. *S* also invokes the simulator of *π*DecZero on behalf of the honest parties.

4.Concluding the intersection:
(a) *S* sends *Xi* as an input of corrupt party *Pi* to the trusted party and receives set intersection *Z* from the trusted party.
(b)For every *x*
*j* 1*∈ Z* where *x* *j* 1is *j* *th* element in set *X₁*, *S* biased the decryption to be zero and random element otherwise. This is achieved by invoking the simulator *S*DecZero on the appropriate plaintext (zero if the element in *Z*), PK and corrupted parties’ share of the secret key.

5. *S* outputs the same as *A*.
Fig.17: Simulator for MPSI protocol (Case 2)
