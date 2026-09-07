*⋆*

# Succinct Homomorphic Secret Sharing

Damiano Abram [0009*−*0004*−*3916*−*7550], Lawrence Roy, and Peter Scholl [0000*−*0002*−*7937*−*8422]

Aarhus University

damiano.abram@cs.au.dk ldr709@gmail.com peter.scholl@cs.au.dk

Abstract. This work introduces homomorphic secret sharing (HSS) with succinct share size. In HSS, private inputs are shared between parties, who can then homomorphically evaluate a function on their shares, obtaining a share of the function output. In succinct HSS, a portion of the inputs can be distributed using shares whose size is sublinear in the number of such inputs. The parties can then locally evaluate a function *f* on the shares, with the restriction that *f* must be linear in the succinctly shared inputs. We construct succinct, two-party HSS for branching programs, based on either the decisional composite residuosity assumption, a DDH-like assumption in class groups, or learning with errors with a super- polynomial modulus-to-noise ratio. We then give several applications of succinct HSS, which were only previously known using fully homomorphic encryption, or stronger tools: –Succinct vector oblivious linear evaluation (VOLE): Two parties can obtain secret shares of a long, arbitrary vector *x*, multiplied by a scalar *∆*, with communication sublinear in the size of the vector. –Batch, multi-party distributed point functions: A protocol for distributing a batch of secret, random point functions among *N* parties, for any polynomial *N*, with communication sublinear in the number of DPFs. –Sublinear MPC for any number of parties: Two new constructions of MPC with sublin- ear communication complexity, with *N* parties for any polynomial *N* : (1) For general layered Boolean circuits of size *s*, with communication *O*(*Ns/* log log*s*), and (2) For layered, sufficiently wide Boolean circuits, with communication *O*(*Ns/* log*s*).

## 1 Introduction

Homomorphic secret sharing (HSS) allows two or more parties to perform a distributed computation on private inputs. HSS can be seen as a distributed analogue of homomorphic encryption, where instead of having a single server carry out a computation on encrypted inputs, several parties are each given a share of the inputs, and can then locally carry out homomorphic computations on the shares, to obtain a share of the desired result. HSS was first introduced by Boyle, Gilboa and Ishai [BGI16], who showed how to build two-party HSS for branching programs based on the decisional Diffie-Hellman (DDH) assumption. Concretely, [BGI16] actually build HSS for a class of *restricted multiplication straightline* programs, or RMS programs, which are circuits with the restriction that every multiplication gate is between an input wire to the computation and one other intermediate wire. It was shown in [BGI16] that RMS programs are powerful enough to capture all logspace computations, which includes polynomial-sized branching programs. A major application of the [BGI16] result was to obtain secure two-party computation for arbitrary, layered Boolean circuits of size *s* with a communication complexity of *O*(*s/* log*s*) bits. This was the first work

*⋆* Supported by the Aarhus University Research Foundation (AUFF), the Independent Research Fund Denmark (DFF) (grant DFF-0165-00107B “C3PO”), and the DARPA SIEVE program (contract HR001120C0085 “FRO- MAGER”). Any opinions, findings and conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of DARPA. Distribution Statement “A” (Approved for Public Release, Distribution Unlimited).

to bypass the circuit-size barrier in secure computation, without relying on fully homomorphic encryption (FHE). Since then, many subsequent works on HSS have focused on improving efficiency and obtaining HSS under new assumptions, offering alternative approaches to sublinear secure computation without FHE. For example, [OSY21] obtained an HSS construction based on Paillier encryption, which removed an inverse polynomial correctness error present in the original DDH-based construction, while [RS21] extended this to the Damg˚ard-Jurik cryptosystem. Many works have shown other applications of HSS and its techniques, including building trapdoor hash functions [DGI + 19,RS21], correlated pseudorandomness [BCG + 19,OSY21] and more [BGI + 18, BDG + 22].

1.1 Our Results In this work, we introduce a new family of *succinct HSS* schemes. In succinct HSS, a subset of the inputs from one party can be shared succinctly, with a share size of *o*(*n*) for *n*-bit inputs. This is in contrast to classical HSS, where all known constructions have share size *Ω*(*n*). We build two-party, succinct HSS for the class of *special, restricted multiplication straightline* (special RMS) programs. A function *f* is a special RMS program if it is an RMS program, and furthermore if *f* (*x,y*) is linear in *x*, where *x* is the subset of inputs with succinct shares. Below is an overview of our main results, including applications to distributed point functions and MPC with sublinear communication. *Bilinear HSS and succinct VOLE.* We start by building a form of HSS for bilinear functions, that is, two- party HSS where one party, Alice, holds as input a vector *x ∈* Z
*n* *q*, while Bob holds a matrix *M ∈* Z *m* *q ×n*. The goal is to obtain additive secret shares of the bilinear function *M · x*, using only a single round of interaction. We construct a succinct form of bilinear HSS, where Alice’s message has size *independent of n* *and m*, using techniques from previous trapdoor hash functions for linear predicates [DGI + 19, RS21]. We obtain instantiations based on each of the following assumptions:(1)decisional composite residuosity (DCR),

(2)quadratic residuosity (QR),(3)a DDH-like assumption in class groups, or(4)learning with errors (LWE) with a superpolynomial modulus-to-noise ratio. We show that bilinear HSS can be used to build a succinct form of *vector oblivious linear evaluation* (VOLE), that is, the functionality *f*((*x₀, x₁*)*,∆*) = *x₀∆* + *x₁*, with input vectors (*x₀, x₁*) from Alice and a scalar *∆* from Bob: we obtain a one-round protocol, where Alice’s input *x₁* is sampled at random and the total communication is is sublinear in the dimension of *x₀*. We call this primitive *succinct, half-chosen* *VOLE*. Half-chosen VOLE suffices for many applications of VOLE, such as designated-verifier zero-knowledge proofs [BMRS21, DIO21, YSWW21] and private set intersection [RR22]. Theorem 1(informal). *There exists a protocol for half-chosen VOLE of length n, with one parallel message* *from each party, and total communication complexity O*(*n²*
*/*3 )*,* 1 *if one of the following assumptions holds:*

*(1) DCR, (2) QR, (3) a DDH-like assumption in class groups, or (4) LWE with a superpolynomial modulus-* *to-noise ratio.* The communication can further be reduced to *O*(*n¹*
*/*2 ), by relying on a variant of bilinear HSS for structured matrices with reduced communication cost. This requires either the power-DDH assumption over Paillier groups or class groups, or a new variant of ring-LWE called the *power ring-LWE* assumption. We note that previous constructions of laconic function evaluation (LFE) also imply succinct, bilinear HSS and half-chosen VOLE. However, LFE constructions are only known from LWE with a sub-exponential modulus-to-noise ratio [QWW18], or from ring-LWE with a polynomial modulus [Ros22]. Furthermore, the resulting bilinear HSS and half-chosen VOLE schemes would require two rounds of interaction.

*Optimized Constructions From Power-DDH or Power Ring-LWE.* The communication of our half-chosen VOLE protocol can further be reduced to *O*(*n¹* */*2 ), by relying on a variant of bilinear HSS for structured

1 Ignoring factors of poly(*λ*), for security parameter *λ*.

matrices with reduced communication cost. This requires either the power-DDH assumption over Paillier groups or class groups, or a new variant of ring-LWE called the *power ring-LWE* assumption. Power-DDH, introduced by [GJM03], has since been used over both groups and pairing groups, for a variety of applications. Security in the generic group model was proven by [CNs07] (over the target group of a generic pairing), and it is easily shown from generic group model master theorems. When instantiated over Paillier groups or class groups, the hidden subgroup assumption implies that Power-DDH over the full group *G* is equivalent to Power-DDH over the hidden subgroup *H*. Other than having unknown order, *H* behaves similarly to the groups considered in previous works using Power-DDH. Power Ring-LWE requires pseudorandomness of a set of ring-LWE samples of the form (*a* *i* *,a* *i* *s* + *ei*), where *a* is a single, public random ring element. The SIS problem dual to this was introduced under the name of “Vanishing SIS” by [CLM23]. However, further research is needed to understand the security of the Power Ring-LWE problem.

*Bilinear HSS + HSS for RMS ⇒ succinct HSS for special RMS.* We observe that existing constructions of two-party HSS for RMS programs can be upgraded to achieve succinct HSS for special RMS programs, by applying our succinct, half-chosen VOLE protocol. This leads to constructions based on DCR, class groups or LWE (here, we cannot use QR, since there is no suitable HSS for RMS programs based on QR). Next, we present several applications of succinct HSS.

*Batch, multi-party distributed point functions.* A point function *fα,β*: *{*0*,*1*}* *k* *→ {*0*,*1*}* is a function, parametrized by *α,β*, where *fα,β*(*α*) = *β*, and *fα,β*(*x*)=0 for all *x ̸*= *α*. A distributed point function (DPF) is a way of distributing succinct shares of a secret point function to *N* parties, such that they can locally compute a share of *fα,β*(*x*), for any public *x*. Using two-party, succinct HSS, we construct a batch, *N*-party DPF protocol, which distributes shares for *m* DPFs on a domain of size 2 *k*, using *O*(*m* + *k*) +*o*(*m ·*2 *k* ) communication (ignoring poly(*λ,N*) factors). Therefore, for sufficiently high *m* (but still poly(*λ*)), the per-DPF communication becomes poly(*λ*). If the *α,β* values defining the point functions are uniformly random, the per-DPF communication even becomes *o*(1). This effectively gives a pseudorandom correlation generator [BCG + 19] for distributing a batch of random DPF instances. This was not known previously, without relying on FHE.

*Sublinear MPC without FHE.* Finally, we present two new results on MPC with sublinear communication, for any (polynomial) number of parties. The following results are obtained, respectively, via our batch DPF construction and one-time truth tables [Cou19], and directly via succinct HSS.

Theorem 2(informal). *Let N* = poly(*λ*)*, and assume either DCR or a DDH-like assumption in class* *groups. Then, for a sufficiently large Boolean circuit C with s gates, there exists an N -party protocol that* *securely computes C with semi-honest security and total communication complexity:*

*1. O*(*Ns/* log log*s*)*, for arbitrary layered circuits C.*
*2. O*(*Ns/* log*s*)*, for layered circuits C that are sufficiently wide.* For comparison with previous works, the standard, semi-honest GMW protocol with multiplication triples has *O*(*Ns*) communication complexity. The result from [BGI16] for 2 parties, using HSS based on DDH, achieved *O*(*s/* log*s*) complexity for arbitrary layered circuits. Couteau [Cou19] used one-time truth tables to obtain *O*(*Ns/* log log*s*) in the correlated randomness model, for any *N*. The recent work of [DIJL23] achieves *O*(*Ns/* log log*s*) complexity for any *N*, for sufficiently wide, layered circuits using sparse LPN, while [BCM23] achieves *O*(*s/* log log*s*) for arbitrary circuits and up to 5 parties. *On malicious security.* We present all of our results in the semi-honest security model. Analogous results in the malicious model can be obtained by applying communication-preserving compilers [NN01] based on succinct zero-knowledge arguments, which can be built from collision-resistant hashing [Kil92].

1.2 Technical Overview — Construction of Succinct HSS *Homomorphic secret sharing.* Here we briefly review the two-party HSS technique introduced by [BGI16], and subsequently extended in [BKS19, OSY21, RS21, ADOS22]. Suppose that there are secret values *x* and *y*, which are unknown to Alice and Bob. However, they both get ciphertexts *c* and *c*
*′* encrypting *x* and *y* under some public key pk. Let *k* be the private counterpart of pk. The parties also have subtractive secret shares [[*k*]] of the secret key *k*, i.e., Alice has [[*k*]]0and Bob has [[*k*]]1such that [[*k*]]0*−* [[*k*]]1= *k*. Alice and Bob want to get secret shares of *x · y*, without communicating. Some properties are required of the encryption scheme. First, it must be additively homomorphic, i.e., *c·c* *′*

consists of an encryption of *x*+*y*. Second, decryption is required to work in a particular way: *k·x* = DLog *c* *k*. 2

Note that this requires some instances of discrete logarithm to be easy. For schemes based on DCR or class groups, there is a subgroup where discrete logarithm is easy, and DLog works within this group. For LWE- based schemes, the equivalent of DLog becomes scaling and rounding, which works whenever the plaintext is only hidden by small noise. Now, Alice and Bob start by converting the ciphertext *c* into secret shares, by doing a distributed decryption. They first compute ⟪*k · x*⟫ = *c* [[*k*]]; this is a *multiplicative sharing* of *k · x*, which means that DLog(⟪*k·x*⟫ */*⟪*k·x*⟫) = *k·x*. Next they use a *distributed discrete-log* operation DDLog on their multiplicative

|0 1|||
|---|---|---|
||0|0 1 3|

shares, which has the property that DDLog(⟪*z*⟫) *−* DDLog(⟪*z*⟫1) = DLog(⟪*z*⟫ */*⟪*z*⟫) = *z*, allowing the DLog shares to be computed through purely local computation. They use it to convert ⟪*k·x*⟫ into a subtractive sharing [[*k · x*]] = DDLog(⟪*k · x*⟫). This process can then be repeated starting from [[*k · x*]] (instead of [[*k*]]) *′ ′*[[*k·x*]] and *c* (instead of *c*), to get ⟪*k · x · y*⟫ = *c* and [[*k · x · y*]] = DDLog(⟪*k · x · y*⟫). From [[*k · x · y*]], there are various techniques that allow retrieving [[*x · y*]]. Alice and Bob have now successfully multiplied *x* by *y*. Generalizing this technique gives two-party HSS for Restricted Multiplication Straight-line (RMS) pro- grams. These are arithmetic circuits that support two kinds of values:(a)input ciphertexts (encryptions *c* of an input *x* under pk), and(b)memory shares (subtractive secret-sharings [[*k · x*]] where *x* is the value and *k* is the private counterpart of pk); with the restriction that multiplication is only allowed between an input ciphertext and a memory share, but never between two memory shares. In the HSS scheme, multiplications between input ciphertexts and memory wires can be performed without any communication as we outlined above. Additions between memory wires come at essentially no cost thanks to the linearity of subtractive secret sharing. We recall that RMS programs are powerful enough to implement branching programs and log-depth circuits [BGI16, Appendix A].

*Succinct HSS from half-chosen VOLE.* While the communication cost of HSS is independent of the circuit size, it still requires sending (encryptions of) both parties’ inputs to each other. Even in the worst case, information theory only requires that one party send data proportional to its input size, so we sought to build *succinct HSS*, where some inputs are sent with only sublinear communication. We found a construction of succinct HSS for special RMS programs. Special RMS programs are RMS programs with two different classes of inputs: Standard inputs are the usual input ciphertexts, and can be multiplied by memory values as normal. Special inputs can only be used as memory values, and can never be multiplied by memory values. A succinct HSS scheme is an HSS scheme for special RMS programs with communication sublinear in the size of the special inputs. We highlight that since HSS supports complex non-linear operations on the input ciphertexts, succinctness for these is impossible in general, by information complexity [Yao83]. In the HSS framework outlined earlier, notice that implementing succinct HSS for a vector of special
inputs *x* = (*x₁,...,xn*) boils down to succinctly obtaining shares [[*k · x*]] = ([[*k · x₁*]]*,...,* [[*k · xn*]]) of *x*’s
product with the secret key. Without loss of generality, suppose that Alice is the party who knows the input

*x*. In our construction, she will only send a compact hash of her input, so we will call her the *hasher* and 2 Technically, this is a simplification for Damg˚ard–Jurik-based HSS [RS21]. For other schemes, *k* becomes a vector, and *c* becomes a matrix of group elements which has *k* as a kind of eigenvector (in the exponent). 3 For HSS based on DDH, this is only possible with probability 1 *−* 1*/*poly(*λ*).

<u>Hasher Encryptor</u> $ *w ←* $ *x₀ ←* [*ℓ*] [*ℓ*] Y *n* *x e₀ ← g₀* *w* *d ← gj j* *y w* *e* *j ← f* *j* *g* *j∀j ∈* [*n*] *j*=0*e₀,...,en*

Y *n* *xd* ⟪*z*⟫0 *← ej j* *w* *j*=0⟪*z*⟫1 *← d* [[*z*]]0 *←* DDLog(⟪*z*⟫0) [[*z*]]1 *←* DDLog(⟪*z*⟫1) output [[*z*]]0 output [[*z*]]1

Fig. 1. Bilinear HSS for inner product.

Bob the *encryptor*. Since the parties already have secret shares of [[*k*]], we have that [[*k · x*]] = [[*k*]]0*x −* [[*k*]]1*x*, and the hasher can locally compute the first term [[*k*]]0*x*. The second term, *−*[[*k*]]1*· x*, is a product of a scalar *−*[[*k*]]1known by the encryptor with a vector *x* known by the hasher. That is, they need a vector oblivious linear evaluation (VOLE), where the hasher chooses vector *x* and gets [[*∆ · x*]]0, while the encryptor chooses the scalar *∆* = *−*[[*k*]]1and gets [[*∆ · x*]]1, such that [[*∆ · x*]]0*−* [[*∆ · x*]]1= *k · x*. Since the hasher only chooses one vector and gets a second vector sampled pseudorandomly, we call this a *half-chosen VOLE*. See Section 7 for more discussion of succinct HSS.

*Realizing half-chosen VOLE and bilinear HSS.* We consider half-chosen VOLE as a special case of a more general problem, *bilinear HSS*. The hasher and the encryptor have input vectors *x* and *y*, respectively, and they want secret shares of some bilinear function of *x* and *y*. We additionally require that bilinear HSS has only one simultaneous round, i.e., they must each send some hash or encryption of *x* and *y*, but further communication (which might depend on both *x* and *y*) is disallowed. For efficiency, we require that the communication sent by the hasher must be sublinear in their input size. We start with a bilinear HSS protocol for the dot product *z* = *⟨x, y⟩*. Our protocol, illustrated in

Fig. 1, is inspired by existing constructions of trapdoor hash functions for linear predicates [DGI

+ 19, RS21]. We work over a group, and assume that the elements *g₀,...,gn*each generate the same cyclic subgroup. Moreover, we assume the existence of a subgroup generated by an element *f* where discrete log is easy. This is consistent with the non-interactive discrete logarithm sharing (NIDLS) framework of [ADOS22], which can be instantiated either from DCR or class groups. In our protocol, the hasher only sends a Pedersen commitment⁴

*d* = *g₀* *x* 0 *g₁* *x* 1 *··· gn* *x* *n*

(the *hash*) to their input (*x₁,...,xn*) (*x₀* is a random mask), which has size independent of *n*. Meanwhile, the encryptor picks a random private key *w*, and sends ElGamal-like ciphertexts *ej*= *f* *y* *j* *g* *jw*for *j* = 0*,...,n* (where *y* Q 0:= 0). Using the homomorphism on these ciphertexts, they can then get multiplicative shares *n xj w* ⟪*z*⟫0 *j*=0 *j* 1

|:=|e and ⟪z⟫|:= d|of z = ⟨x, y⟩.||||||
|---|---|---|---|---|---|---|---|---|
|0 j=0|j|1 0 1|n x j=0 j w|n x j=1 n j=0 jw·x|·y w·x j|n x ·y j=1|⟨x,y⟩||

Q *j w·x*0 Q *j j j* ⟪*z*⟫ *e g₀ f g* Y *j j* = = Q *j* = *f* = *f* ⟪*z*⟫ *d g*

Finally, DDLog converts these to additive shares [[*z*]]. Note that Fig. 1 has one simultaneous round, as is required for bilinear HSS. One simultaneous round protocols often have a very useful property: the messages sent by each party can be reused. If the hasher

4 Note that in any such protocol both parties must at least commit to their inputs. If one didn’t, then it could learn two different output shares [[*z*]]*i,*[[*z* *′*]] *i*, and take the difference to get *z − z* *′* (since the other party’s share must be the same both times), which would leak.

<u>Hasher Encryptor</u> $ *x₀ ←* [*ℓ*] $ Y *n* *x*+*j−i* *w ←* [*ℓ*] *d ← gj j E* *ij ← f* *δij ·∆* *g* *w·αn* *∀i ∈* [1*..n*]*,j ∈* [0*..n*] *j*=0<u>E</u>

Y *n* *xd* ⟪*zi*⟫0 *← Eijj* *w·αn−i* *j*=0⟪*zi*⟫1 *← d ∀i ∈* [1*..n*] [[*zi*]]0 *←* DDLog(⟪*zi*⟫0) [[*zi*]]1 *←* DDLog(⟪*zi*⟫1) *∀i ∈* [1*..n*] output [[*z*]]0 output [[*z*]]1

Fig. 2. Bilinear HSS for scalar-vector product from Power DDH. Before this protocol is run, the hasher must receive

*α* *j* *g* *j* = *g* for *j ∈* [0*..n*] from the encryptor.

generates *l* messages and the encryptor generates *m* messages, they can compute secret shares of all *l · m* inner products. That is, if the hasher’s input vectors are the columns of a matrix *X* and the encryptor’s input vectors are the rows of a matrix *Y*, then they get secret shares of the matrix product *Y · X*. They get all *m · l* outputs, even though the hasher sends only *l* group elements and the encryptor sends only *m ·*(*n*+ 1) group elements. The output can have significant length, even though we are building on an inner product protocol, which only produces a single output. Next, we construct bilinear HSS for scalar-vector product with sublinear communication in both directions – i.e., succinct half-chosen VOLE. Let *N* be the length of the original vector *x*, and let *n* = *m* = *N¹* */*3 and *l* = *N²* */*3. Let *Y* = *∆ ·* id*n*, where *∆* is the scalar input to the VOLE from Bob, and let *X* be an *n × l* matrix such that *x* is the columns of *X* stacked together. Then the result is *Y · X* = *∆·X*, and stacking its columns gives *∆ · x*, so we have a half-chosen VOLE. We have achieved half-chosen VOLE, while sending a total of only *l* + *m ·* (*n* + 1) *≈* 2 *· N²* */*3 group elements. We formally define bilinear HSS in Section 3, detail our initial construction in Section 4.1, and explain how to build succinct half-chosen VOLE in Section 5.

*More Efficient Bilinear HSS.* In the previous bilinear HSS construction, the hasher had to send an encryption *E* of the whole matrix *Y*, even though it was structured as a multiple of the identity matrix. If we could somehow preserve some of this structure in *E*, then we could compress it. In Fig. 2, we present such a bilinear HSS construction, based on the Power-DDH assumption used by the efficient range-trapdoor functions of [GHO20]. Here, we describe its relation with Fig. 1. Run Fig. 1 with *n* repetitions of the encryptor, one for each of the *n* rows of *Y*. However, make two changes to reduce the entropy of *E*, by sampling values in a correlated manner. First, instead of sampling *g₀,...,g* independently,

|||n|
|---|---|---|
|j|α 5|j|
|i||n−i|

*j* have the encryptor sample a random exponent *α*, and set *g* = *g*. We require that the *g* ’s are given to the hasher in an initial setup phase. The Power-DDH assumption states that these are indistinguishable from random group elements. Second, sample the secret keys *w* in a correlated way, as *wi*= *w · α* for random

*w*. With these two changes, we have
*∆·δij i ∆·δij w·α* *n*+*j−i* *Eij*= *f gjw*= *f g,*

where *δij*is the Kronecker delta function (1 if *i* = *j*, and 0 otherwise). Note that *Eij*now only depends on *j − i*, so *E* is constant along diagonals, making it a Toeplitz matrix. Therefore, it can be compressed: the first row and column are enough to reconstruct the rest. This takes 2*n* group elements, as *E* is an *n ×*(*n*+ 1) matrix.

5 This requires some Setup to be run before the protocol starts, since the hasher must not learn *α*.

<u>Hasher Encryptor</u> $ *k* *w ←* Z*q* $ $ ⊺ *u ← ξ e ← A · w* + *χ* + *⌈q/p⌋· y* *′* *′* $ ⊺ *d ← A · x* + *B · u* <u>e, e</u> *e ← B · w* + *χ*

⊺ *′*⊺*d*⊺ [[*z*]]0 *←⌈e · x* + *e · u⌋⌈q/p⌋*[[*z*]]1 *←⌈w · d⌋⌈q/p⌋* output [[*z*]]0 output [[*z*]]1

Fig. 3. Bilinear HSS for inner product (mod *p*) from LWE. Here *A ∈* Z

*k* *q ×n,B ∈* Z *k* *q ×t*are public random matrices, and *ξ* and *χ* are noise distributions.

Correctness still works in the same way:

Q*n x* *j* Q*n* *δ* *ij ·∆·xj w·α* *n*+*j−i* *·xj* Q*n* *w·α* *n*+*j−i* *·xj* ⟪*zi*⟫0 *j*=0*Eij j*=0*f g∆·x* *ij*=0 *g* *∆·xi*

|=||=|Q||= f|· Q|= f|
|---|---|---|---|---|---|---|---|
|i 1|w·α||n j=0|w·α ·x j||n w·α j=0|·x|
|/2|||||k|||
|/2|/2|||||/2||

*w·αn−in w·αn−i·x n w·αn*+*j−i·x* ⟪*zi*⟫1*d gjgj*

After DDLog, the protocol outputs additive shares of the vector *∆ · x*. Now, we can further improve efficiency by reusing *E* for many different hashes. Divide *x* into *N¹* */*2 blocks *xk*of *n* = *N¹* elements each, then compute shares of *∆ · x* for all *k* to get *∆ · x*. The communication cost is *O*(*N¹*): *N¹* hashes, plus a single matrix *E* containing 2 *· N¹* group elements. We detail this construction in Section 6.1.

*LWE-Based Bilinear HSS.* We also designed protocols for bilinear HSS from the learning with errors (LWE) assumption. In Fig. 3 we present a direct translation of Fig. 1 from groups to lattices. Assume that *x ∈* Z *n* *p* and *y ∈* Z *n* *p*are encoded into the larger ring Z*q*by taking the smallest representative modulo *p*. Then the digest becomes the usual SIS hash function: *d* = *A · x* + *B · u* [Ajt96], for public random matrices *A ∈* Z *k*

|,B ∈ Z|, and a small random mask u. The encryption e, e||of y becomes a dual-Regev-like||
|---|---|---|---|---|
|q ×n|q ×t|′ ⊺|||

*q ×n* *k* *q ×t* *′*

ciphertext *e* = *A* ⊺ *· w* + *χ* + *⌈q/p⌋· y, e* = *B · w* + *χ,*

where *χ* is a noise distribution [GPV08]. For correctness, first notice that before rounding the output shares are nearly correct, assuming that the noise distribution is sufficiently small.

⊺ *′*⊺ ⊺ ⊺ ⊺ ⊺ ⊺ ⊺ *e · x* + *e · u − w · d* = (*w · B* + *χ*) *· u*

|· A + χ|+ ⌈q/p⌋· y|) · x + (w|
|---|---|---|
|⊺|⊺|⊺|

*− w* ⊺ *·* (*A · x* + *B · u*)

= *⌈q/p⌋· y · x* + *χ* ⊺ *· x* + *χ · u*

### ≈⌈q/p⌋· (⟨x, y⟩ mod p)

Next, if this pre-rounding correctness error is negligible compared to *q/p*, after rounding, the result will be correct with all but negligible probability:

⊺ *′*⊺ ⊺ [[*z*]]0*−* [[*z*]]1= *⌈e · x* + *e · u⌋⌈q/p⌋−⌈w · d⌋⌈q/p⌋≡⟨x, y⟩* mod *p*

The communication cost is asymptotically the same as for Fig. 1, with each hash being *k* elements of Z*q*, and each vector *y* being *n* + *t* elements of Z*q*. We detail this construction in Section 4.2.

*Power Ring-LWE.* We also adapted the ideas from Fig. 2 to work with LWE. Our protocol is Fig. 4. Again, the main idea of the protocol is structure the ciphertexts so that *E* becomes a Toeplitz matrix, and so can be compressed. To support this additional structure, we need to define a new security assumption: Power Ring-LWE. In standard Ring-LWE, the adversary is given as many samples of the form (*ai,ai· s*+ *ei*) as they

<u>Hasher Encryptor</u> $ $ *x−*1 *← χ w ← Rq* $ $ *x₀ ← χ ek← χ ∀k ∈* [*−n..n*]

X *n* *j*+1 *n*+*j−i*+1 *∀i ∈* [1*..n*]*,j ∈* [*−*1*..n*]: *d ← a · xj Eij ← a · w* + *ej−i*+1 + *⌈q/p⌋· δij · ∆* <u>E</u> *j*=*−*1

[[*z*]]0 *←⌈E · x⌋⌈q/p⌋* *d* [[*zi*]]1 *←⌈d · a* *n−i* *· w⌋⌈q/p⌋∀i ∈* [1*..n*] output [[*z*]]0 output [[*z*]]1

Fig. 4. Bilinear HSS for scalar-vector product from Power Ring-LWE. Here *a ∈ Rq* is a public ring element, and *χ* is

a noise distribution on *Rq*.

want, where *s* and all *ai*are uniform and *ei*is from a noise distribution *χ*, and they must distinguish from

||i|||i i|
|---|---|---|---|---|
|n+j−i+1|6|n j+1 j=−1 i n−i|j||
|ij|ij||||

random. Power Ring-LWE is similar, but the public ring elements *ai*are structured: they satisfy P *ai*= *a* *i*. In this way, the digest value *d* becomes a polynomial evaluation at *a*: *d* = *a x*. Note that some random values have been prepended to *x* to hide the hasher’s input. Also like with Fig. 2, the encryptor’s secret keys *wi*values are correlated by *w* = *a · w*. Ignoring noise, this makes the ciphertexts become

*E ≈ a · w* + *⌈q/p⌋· δ · ∆,*

which again only depends on *j −i*, so it is a Toeplitz matrix. For negligible noise-to-modulus ratio, correctness holds because

X *n*X*n* *Eij· xj− d · a* *n−i* *· w* = *a* *n*+*j−i*+1 *· w* + *ej−i*+1+ *⌈q/p⌋· δij· ∆ · xj* *j*=*−*1 *j*=*−*1 X *n* *− a* *n*+*j−i*+1 *· xj· w* *j*=*−*1 X *n* = *⌈q/p⌋· ∆ · xi*+ *ej−i*+1*· xj* *j*=*−*1 *≈⌈q/p⌋·* (*∆ · xi*mod *p*)*.*

The communication cost is similar to Fig. 2, with the hasher sending a single ring element, and the encryptor sending 2*n* + 1 ring elements: the first row and first column of *E*. We detail this construction in Section 6.2.

1.3 Technical Overview — Applications of Succinct HSS One main application of HSS is to MPC with sublinear communication [BGI16]. Alice and Bob divide their circuit into layers of logarithmic depth, and use HSS to evaluate each layer. Communication is only required between layers, so they only send *O*(*s/* log*s*) bits for a circuit with *s* gates. The biggest limitation of this technique is that it only applies to two parties, since the underlying HSS only works for two parties. Recent work has addressed this gap by building truth tables for (log log *s*)-depth circuit blocks, which have at most log(*s*) inputs and so have polynomial-sized truth tables. [Cou19] showed that if the parties are given correlated randomness in the form of (batched) One-Time Truth-Tables (OTTTs)
7

6 The SIS problem corresponding to *d* being a collision-resistant hash was defined in [CLM23]. They named it vanishing SIS, and gave some evidence for its hardness. 7 An OTTT [IKM + 13] is a truth table, permuted according to a random input mask, secret shared among all *N* parties.

for these blocks, then they can evaluate the layered circuit with *O*(*s/* log log*s*) communication. However, they were unable to efficiently generate these OTTTs without using assumptions that imply FHE. [BCM23] got past this issue by generating truth tables for two parties with HSS, then evaluating them on the third party’s input using a variant of PIR. Their technique can be stretched to work with 5 parties, but no further. Recently, another work [DIJL23] managed to achieve *O*(*s/* log log*s*) communication — when the circuit is sufficiently wide — for any number of parties, based on a sparse variant of the learning parity with noise assumption.

*Sublinear MPC from succinct HSS.* We show how to generate these OTTTs with only sublinear com- munication, using succinct HSS. We consider the following procedure to generate a OTTT of a function *f* : *{*0*,*1*}* *k* *→{*0*,*1*}*.

1.Party *P₁* generates a random mask *r₁ ∈ {*0*,*1*}*
*k*, and computes their permuted truth table *s₁*[*x*] *←* *f* (*x ⊕ r₁*) for all *x ∈{*0*,*1*}* *k*.

2.For *j* = 2*,...,N*, party *Pj*generates a random mask *rj∈{*0*,*1*}*
*k*, and uses succinct HSS to permute the truth table as follows: P*j−*1

(a)Currently, we have that*i*=1*si*[*x*] = *f* (*x ⊕ r₁ ⊕···⊕ rj−*1).
(b)For every *i < j*, parties *Pi*and *Pj*run 2-party succinct HSS on input the truth table *si*and the mask *r* *j*. They compute secret shares *s*
*′ij* [*x*] and *s* *′ji* [*x*] of *si*[*x ⊕ rj*] for all *x*, so *s* *′ij* [*x*] *− s* *′ji* [*x*] = *si*[*x ⊕ rj*]. Party *Pi*updates their share *si← s* *′ij*. P*j−*1 *′ji*

(c)Party *Pj*sets their share to *sj←−i*=1*s*. X
*j* X *j−*1 X *j−*1

(d)Now *si*[*x*] = *s*
*′ij* [*x*] *− s* *′ji* [*x*] = *f x ⊕ r₁ ⊕... ⊕ rj−*1*⊕ rj*. *i*=1 *i*=1 *i*=1 P*N*

3.Each party *Pi*outputs *si*as their share of the OTTT. The loop invariant guarantees that*i*=1*si*[*x*] =
L*N* *f* (*x ⊕ r*), where *r* =*i*=1*ri*, so these shares form a OTTT for *f*.

This protocol can also be batched to generate many OTTTs at once. If the underlying HSS has sublinear communication complexity in its inputs then this protocol can generate the OTTTs needed by [Cou19] with communication sublinear in the circuit size, completing their sublinear MPC protocol. We notice that in all HSS evaluation, the input *s* is only used linearly, as the circuit is only permuting

||i||
|---|---|---|
|j||i|
|j||i|
|||j|

the entries of *si*according to *x 7→ x ⊕ r*. In other words, given succinct HSS, *s* can be compressed. Unfortunately, the random mask *r* is used non-linearly as it defines the permutation on *s*, so it cannot be compressed in the same way. However, it is sampled randomly, so for each *j*, all the *r* ’s across all OTTTs can be compressed together using a PRF in NC₁. Since all inputs can be compressed, we achieve sublinear communication MPC. We detail this construction in Section 8.1.

*Multiparty DPFs.* In the special case of a OTTT for the function *f*, given by *f*(0) = *β* and otherwise *f* (*x*) = 0, we get a protocol for generating a batch of multiparty DPFs using sublinear communication (the OTTT mask *r* corresponds to the non-zero point of the point function). Most directly, this would require giving *β* to *P₁*, but with a minor tweak to the protocol, *β* can be secret shared among the *N* parties instead. Note that the communication complexity is polynomial in the number of parties, and that for a sufficiently large batch size the per-DPF communication can be made arbitrarily small. We detail this construction in Section 8.

*Sublinear MPC for RMS programs.* Another application of succinct HSS is to (interactively) evaluate layered RMS programs in MPC for a polynomial number of parties, with communication sublinear in the program size. A layered RMS program allows arbitrary fan-in addition gates and 2-input multiplication gates, with the restriction that every gate must output into a later layer than any of its inputs. Our protocol for evaluating layered RMS programs works as follows. Maintain additive secret shares *y₁* + *···* + *yN*of every memory value in the RMS program. We can initially share the inputs as well, since
(0*,...,x,...,*0) is an additive sharing of *x*, and every input is known by some party. We can easily evaluate

addition gates directly on the shares, just by adding the shares. The difficulty comes when we need to multiply an input *x* by some memory value *y*. We implement multiplications with succinct HSS, by having the shares of *y* be compressed as special inputs. In more detail, to handle the multiplications for each layer, we run a succinct HSS evaluations between every pair of parties. If party *Pi*has an input *xi*, it provides *xi*as a standard input to all of its succinct HSS evaluations. 8 Now, every multiplication in this layer can be handled as follows. If we need to evaluate *x · y*, for an input *x* held by party *P* and a memory value *y* = *y₁* + *···* + *y* :

||i||N|
|---|---|---|---|
||j|||
|j||j||
|i|i|||
||||N|

1.For all *j ̸*= *i*, include *y* as a special input (if it is not already included) to the succinct HSS between *Pi* and *P*, and compute shares of *x · y*.
2. *P* locally evaluates *x · y*.
3.Sum the above shares to get shares of *x · y₁* + *···* + *x · y* = *x · y*. Note that all multiplications in a single layer use the same succinct HSS, so that all of these share inputs get compressed together in the succinct HSS. Therefore, for efficiency we need a sufficiently wide RMS program. Note also that the round complexity is proportional to the number of layers. We can also use this protocol to get sublinear complexity MPC for layered circuits, as long as the layers are wide enough and even in size. Similarly to [BGI16], divide the circuit into blocks of depth *c ·* log*s* for some 0 *< c <* 1, and convert each block into an *o*(*s*)-layer RMS program. Evaluate each block using the above protocol for RMS programs, and input the shares output from each layer into the next. For efficiency, however, we require hybrid encryption for the inputs, so the parties will instead generate symmetric-key ciphertexts from their shares, and input log(*λ*)-depth PRF keys to the RMS program so that they can be decrypted. This increases the circuit depth to *c ·* log*s* + *O*(log(*λ*)), and so the RMS program will have *s* *c* poly(*λ*) layers. For sufficiently wide circuits, the symmetric-key ciphertexts become the biggest term asymptotically, and so the whole circuit can be evaluated with *O*(*s/* log*s*) communication. However, this construction blows up
<u>s</u> *c* <u>poly(λ)</u> the round complexity to *d ·* *c*log *s*, if *d* is the depth of the original circuit. We detail this construction in Section 9.

## 2 Notation and Preliminaries

We denote the security parameter by *λ*. For any *n ∈* N, we define [*n*] := *{*1*,...,n}* and [0*..n*] := *{*0*,*1*,...,n}*.
For any *x,N ∈* N where *N* is odd, we use *N* <u>x</u> to denote the Jacobi symbol of *x* and *N*. Given a real number *x* and an integer *p*, we use *⌈x⌋p*to denote the integer *y* such that *y · p* is the multiple of *p* that is closest to

*x*. We use *⌈x⌋* to denote rounding to the closest integer. Objects in vectorial form are represented using bold font. For any vector *v*, we denote the *i*-th entry either by *v*[*i*] or by *vi*. Matrices are represented using capital letters. The element in the *i*-th row and *j*-th column of a matrix *A* is denoted by *Ai,j*. The transposition of a matrix *A* is denoted by *A*
⊺. Unit-vectors are vectors where all the entries are zero except for, perhaps, one. We call the latter the *special position* or the *special entry*. The corresponding value is called the *non-zero element*. We denote a unit vector with special position *α* and non-zero element *β* by *uα,β*. We use *⊗* to denote the outer product. $ For any randomised algorithm Alg, we use *y ←* Alg(*x*) to mean that *y* is assigned the output of Alg on input *x* and uniformly random coins. We use instead *y ←* Alg(*x*; *r*) to mean that *y* is assigned the output of Alg on input *x* and randomness *r*. If Alg is deterministic, we simply write *y ←* Alg(*x*). Finally, for any finite $ set *S*, we write *y ← S* if *y* is assigned the value of a uniformly random element in *S*. Throughout the paper, we deal with multiparty computation protocols. We denote the number of parties by *N*. The *i*-th party is denoted by *Pi*. In all protocols, we assume static, semi-honest corruption.

8 These input ciphertexts can sent to all parties at the start, and reused for all layers.

2.1 Standard Assumptions Below, we recall some basic computational assumptions we use throughout the paper. We start from the quadratic residuosity (QR) assumption over the RSA group. The latter states that given a product of random safe-primes *N* (where the factorisation is kept secret), it is hard to distinguish between a random square in Z *∗* *N*and a random element in Z
*∗* *N*having Jacobi symbol equal to 1. We recall that a safe prime is a prime number *p* = 2*p* *′* + 1 where *p* *′* is also prime.

Definition 1(Quadratic Residuosity over the RSA Group). *We say that the quadratic residuosity* *(QR) assumption holds over the RSA group, if the following distributions are computationally indistinguish-* *able*  $    *p,q ← random λ-bit safe-primes*    *g,N N ← p · q*  $ n <u>x</u> o    *g ← x ∈* Z *∗* = 1  *N* *N*     *p,q ←* $ *random λ-bit safe-primes*   *g²,N N ← p · q*     *g ←* $ Z *∗*  *N*

We now recall the decisional composite residuosity (DCR) assumption over the Paillier group. We recall that the Paillier group is Z *∗* *N*2 where *N* is the product of two random safe-primes. The DCR assumption states that over the Paillier group (where the factorisation of *N* is kept secret), it is hard to distinguish between a random *N*-th power and a random element of the group.

Definition 2(Decisional Composite Residuosity). *We say that the decisional composite residuosity* *(DCR) assumption holds over the Paillier group, if the following distributions are computationally indistin-* *guishable*     *p,q ←* $ *random λ-bit safe-primes*   *g,N N ← p · q*     *g ←* $ Z *∗*  *N²*     *p,q ←* $ *random λ-bit safe-primes*   *g* *N* *,N N ← p · q*     *g ←* $ Z *∗*  *N²*

Finally, we recall the learning with errors (LWE) assumption [Reg05]. The latter states that, given a random lattice described by a thin matrix *A* over Z*q*, if we perturb a random point of the lattice with some noise, the result looks like a random point of the space.

Definition 3(Learning with Errors). *Let χ* *M* *σdenote a discrete Gaussian distribution over* Z *M* *with noise* *parameter σ. We say that the learning with errors (LWE) assumption holds for the parameters N*(*λ*)*,M*(*λ*)*,q*(*λ*)*,α*(*λ*) *if, for σ* := *α*(*λ*) *· q*(*λ*)*, the following distributions are computationally indistinguishable*  $    *A ←* Z *M* *q* *×N*     *A,A · s* + *e s ←* $ Z *N* *q*     $*M* *e ← χσ* ( $*M ×N* ) *A ←* Z*q* *A, v* $ *v ←* Z *M* *q*

2.2 Assumptions in the NIDLS Framework Some of our bilinear HSS constructions are based on the non-interactive discrete logarithm sharing (NIDLS) framework of [ADOS22]. We recall here its definition and some known instantiations. The NIDLS framework consists of a finite commutative group *G* that can be decomposed as the direct product *F × H*. The subgroup *F* is cyclic of known order. Furthermore, it is easy to solve discrete logarithms with respect to a generator *f*. The subgroup *H* is instead of unknown order and computing discrete logarithms over it is hard. The framework is also equipped with an upper-bound on the order of *G*, which we denote by *ℓ*, and a distribution *D* that provides (non-necessarily uniformly) random elements in *G*. The most interesting property of the framework is that it allows compute discrete logarithms in a dis- tributed way: if two parties *P₀* and *P₁* hold elements *g₀* and *g₁* such that *g₀* = *f*
*m* *· g₁* for some *m ∈* N, the parties can derive a subtractive secret-sharing of *m* without having to interact. The operation is called *distributed discrete logarithm* or DDLog.

Definition 4(The NIDLS Framework [ADOS22]). *The NIDLS framework consists of a triple of PPT* *algorithms* (Gen*, D,* DDLog) *with the following syntax:*

– Gen(1l *λ* ) *outputs a tuple* par := (*G,F,H,f,q,ℓ,* aux) *where*

- *G is a finite abelian group*
- *F and H are subgroups of G such that G* = *F × H*
- *F* = *⟨f ⟩ and |F |* = *q*
- *ℓ is a positive integer*
- ** aux *consists of auxiliary information*
– *D*(1l *λ* *,*par) *outputs an element g ∈ G along with auxiliary information ρ* – DDLog(par*,g*) *is deterministic and outputs an element s ∈* Z*q.*

### We additionally require the following properties:

– *For every PPT adversary A,*

|||||
|---|---|---|---|
||par := (G,F,H,f,q,ℓ, aux) ← Gen(1l||) |
| |(g ,m) ←A|(1l, par)| |
|Pr s₀ − s₁ ̸≡ m mod q  |g₁ ← f|· g₀|  ≤ negl(λ) |
| |s ← DDLog(par,g )|| |

$*λ*

$*λ* 0 *m*

0 0 *s₁ ←* DDLog(par*,g₁*)

– *The following distributions are statistically indistinguishable*

|||||
|---|---|---|---|
|  |par := (G,F,H,f,q,ℓ, aux) ← Gen(1l||)  |
| par,g,ρ,g|(g,ρ) ←D|(1l, par)||
| |r ← [ℓ]|| |
|||||
|  |par := (G,F,H,f,q,ℓ, aux) ← Gen(1l||)  |
| par,g,ρ,h|(g,ρ) ←D|(1l, par)||
| |h ←⟨g⟩|| |

$*λ*

*r* $*λ*

$

$*λ*

$*λ*

$

2.3 Known Instantiations of the Framework. We now recall the known instantiations of the framework: the Paillier group (and its generalisation Damg˚ard- Jurik) [OSY21,RS21], Goldwasser-Micali (and some variants of its generalisation Joye-Libert) [ADOS22] and class groups [ADOS22].

*The Paillier instantiation.* We consider the subgroup *G* of squares of Z *∗* *N*2. Such subgroup is cyclic of order *N · ϕ*(*N*)*/*4 where *ϕ*(*N*) denotes Euler’s totient function. It is possible to decompose *G* as the direct product of *F* := *⟨*1 + *N ⟩* and *H*, the subgroup of 2*N*-th powers of Z *∗* *N*2. It is easy to observe that (1 + *N*) *a* *≡* 1 + *a · N* mod *N²* for any *a ∈* N. From this we can easily conclude that the order of *F* is *N* and discrete logarithms are easy compute. We refer to [ADOS22] for a detailed discussion on how the distributed DLOG can be computed over Paillier. In Fig. 5, we present a formal description of the Paillier instantiation of the framework (see GenPaillierand *D*Paillier).

*The Goldwasser-Micali instantiation.* Let *N* be the product of two large random safe-primes. We consider the subgroup *G* of all elements in Z *∗* *N*having Jacobi symbol equal to 1. Such group is cyclic of order *ϕ*(*N*)*/*4. It is possible to decompose *G* as the product of *F* = *{*1*, −*1*}* and *H*, the subgroup of squares of Z *∗*

*N*. Due to the
size, discrete logarithms over *F* are trivially to solve. The same holds for distributed DLOGs (see [ADOS22]). In Fig. 5, we present a formal description of the Goldwasser-Micali instantiation of the framework (see GenGM and *D*GM).

*The class group instantiation.* The last known instantiation of the framework is given by class groups. Class groups are commutative groups for which it is computationally expensive to compute the order. One of the reasons why class groups are popular in cryptography is the fact that it is possible to generate the parameters of the group with a transparent setup: while the security of Paillier and Goldwasser-Micali requires that the factorisation of *N* is kept secret, the computational assumptions on class groups remain solid even if we leak the random coins used to sample the group (GenCLwill provide them as part of aux). Any class groups *G* can be decomposed as the product of *F* and *H*. The subgroup *F* is generated by a group element *f* of prime order *q* (such *q* does not need to be sampled at random, it can be given as input to GenCL). Computing DLOGs over *F* is easy. The subgroup *H* has instead unknown order and, in most cases, it is not even cyclic. The sampling procedure *D*CLcan be instantiated in different ways: it could either be a distribution that is statistically close to uniform over *G* or it could be a distribution producing random (but not uniformly random) elements of high unknown order. In both cases *D*CLoutputs the random coins it uses as part of the auxiliary information *ρ*. We refer to [ADOS22] for a detailed discussion on how the distributed DLOG can be computed over class groups. Below, we recall the computational assumptions that are believe to hold in all known instantiations of the NIDLS framework [ADOS22]. We start from the hidden subgroup assumption, which states that, given the description of the NIDLS group and a sample (*g,ρ*) from *D*, it is difficult to distinguish between a random power *g* *r* and *f* *s* *· g* *r* for a random *s ∈* Z*q*.

Definition 5(Hidden Subgroup Assumption). *We say that the hidden subgroup assumption holds in* *the NIDLS framework if the following distributions are computationally indistinguishable*

 $*λ*    par := (*G,F,H,f,q,ℓ,* aux) *←* Gen(1l)     $*λ* *s r* (*g,ρ*) *←D*(1l*,*par) par*,g,ρ,f · g* $   *s ←* Z*q*      $ *r ←* [*ℓ*]  $ 

|||λ|
|---|---|---|
|r|λ||

  par := (*G,F,H,f,q,ℓ,* aux) *←* Gen(1l)   par*,g,ρ,g* (*g,ρ*) *←D* $ (1l*,*par)     $  *r ←* [*ℓ*]

We then recall the small exponent assumption. The latter states that, for a random sample (*g,ρ*) from *r*$*λ* *D*, the power *g* for *r ←* [2] looks like a random element in *⟨g⟩*.

Instantiations of the NIDLS Framework over Paillier and Goldwasser-Micali *λ* GenPaillier(1l)

1.Sample random *λ*-bit safe-primes *p* and *q*
2. *N ← p · q*
*∗*

3. *G ←{g²|g ∈* Z*N*2*}* *N ∗*
4. *H ←{g |g ∈* Z*N*2*}*
5. *f ←* 1 + *N*
6. *q ← N* *λ*
7. *ℓ ←* 2 *· N²*
8. *F ←⟨*1 + *N ⟩*
9.Output par := (*G,F,H,f,q,ℓ,* aux := *N*) *λ* *D*Paillier(1l*,*par) $*∗*
1. *ρ ←* Z*N*2
2.Output (*ρ², ρ*) *λ* GenGM(1l)
1.Sample random *λ*-bit safe-primes *p* and *q*
2. *N ← p · q*
*∗* <u>x</u>

3. *G ← x ∈* Z*N N*= 1
4. *H ←{g²|g ∈ G}*
5. *f ←−*1
6. *q ←* 2
7. *ℓ ← N*
8. *F ←{*1*, −*1*}*
9.Output par := (*G,F,H,f,q,ℓ,* aux := *N*) *λ* *D*GM(1l*,*par) $*∗* <u>x</u>
1. *x ← x ∈* Z*N*= 1
*N*

2.Output (*x,ρ* := *x*)
Fig. 5. Instantiations of the NIDLS Framework over Paillier and Goldwasser-Micali

Definition 6(Small Exponent Assumption). *We say that the small exponent assumption holds in the* *NIDLS framework if the following distributions are computationally indistinguishable*

|||||
|---|---|---|---|
|  |par := (G,F,H,f,q,ℓ, aux) ← Gen(1l||)  |
| par,g,ρ,g|(g,ρ) ←D|(1l, par)||
| |r ← [ℓ]|| |
|||||
|  |par := (G,F,H,f,q,ℓ, aux) ← Gen(1l||)  |
|  par,g,ρ,g|(g,ρ) ←D|(1l, par)| |
||r ← [2|]||

$*λ*

*r* $*λ*

$

$*λ*

*r* $*λ*

$*λ*

Finally, we formalise adaptations of DDH and power-DDH to the NIDLS framework. Essentially, these correspond to the usual formulation of the assumptions, but we also provide the adversary with a description of the NIDLS group parameters and the auxiliary information *ρ* output by *D* (which is used to sample the base group element *g*).

Definition 7(Decisional Diffie-Hellman). *We say that the decisional Diffie-Hellman (DDH) assumption* *holds in the NIDLS framework if the following distributions are computationally indistinguishable*

||||||
|---|---|---|---|---|
|  ||par := (G,F,H,f,q,ℓ, aux) ← Gen(1l||)  |
| par,ρ,g,g|,g ,g|(g,ρ) ←D|(1l, par)||
| ||a,b ← [ℓ]|| |
||||||
|  ||par := (G,F,H,f,q,ℓ, aux) ← Gen(1l||)  |
| par,ρ,g,g|,g ,g|(g,ρ) ←D|(1l, par)||
| |||| |

$*λ*

*a b a·b* $*λ*

$

$*λ*

*a b c* $*λ*

$ *a,b,c ←* [*ℓ*]

Definition 8(Power-DDH). *We say that the n-ary Power-DDH assumption holds in the NIDLS frame-* *work if the following distributions are computationally indistinguishable*

||||||
|---|---|---|---|---|
|  ||par := (G,F,H,f,q,ℓ, aux) ← Gen(1l||)  |
| par,ρ,g,g|,g ,...,g|(g,ρ) ←D|(1l, par)||
| ||α ← [ℓ]|| |
||||||
|  ||par := (G,F,H,f,q,ℓ, aux) ← Gen(1l||)  |
|  par,ρ,g,g|,g ,...,g|(g,ρ) ←D|(1l, par)| |
|||∀i ∈ [n] : α|← [ℓ]||

$*λ*

2 *n* *α α α* $*λ*

$

$*λ*

*α*1 *α*2 *αn* $*λ*

$ *i*

## 3 Defining Bilinear HSS

In this section, we provide formal definitions of bilinear HSS, describing its syntax and properties. A bilinear HSS scheme consists of a 2-party primitive: one party is called the hasher and provides as input an *n*-dimensional vector *x*, the other party is called the encryptor and provides as input a matrix *M*. The primitive relies on a setup that takes as input *n* and distributes keys to the parties. Such keys allow the hasher and the encryptor to obtain a secret-sharing of *M · x* using a single round of interaction. Furthermore, the digest sent by the hasher will have sublinear size in *n*.

Definition 9(Bilinear HSS). *Let R be a commutative ring. An R-bilinear HSS scheme for the matrix* *class M is a tuple of PPT algorithms* (Setup*,*Hash*,*Matrix*,*HasherEval*,*MatrixEval) *with the following syntax:*

– Setup *is randomised and takes as input the security parameter* 1l *λ* *and the input length* 1l *n* *. The output* *is a hasher key* hk *and a matrix key* mk*.* – Hash *is randomised and takes as input a hasher key* hk *and an input x ∈ R* *n* *. The output is a digest d* *and the hasher secret information ψ.* – Matrix *is randomised and takes as input a matrix key* mk *and an n-column matrix M ∈M of elements* *in R. The output is an encoding E and the matrix secret information ϕ.* – HasherEval *is deterministic and takes as input a hasher key* hk*, a matrix encoding E and hasher secret* *information ψ. The output is a vector s₀.* – MatrixEval *is deterministic and takes as input a matrix key* mk*, a digest d and matrix secret information* *ϕ. The output is a vector s₁.*

### We require also the following properties

*1. (Correctness). For every n ∈* N*, x ∈ R*
*n* *and n-column matrix M ∈M, we have*  $*λ n*  (hk*,*mk) *←* Setup(1l*,*1l)  $   (*d,ψ*) *←* Hash(hk*, x*)     $  Pr *s₀ − s₁ ̸*= *M · x* (*E,ϕ*) *←* Matrix(mk*,M*)  *≤* negl(*λ*)*.*      *s₀ ←* HasherEval(hk*,E,ψ*)

### s₁ ← MatrixEval(mk,d,ϕ)

*2. (Hasher Privacy). No PPT adversary A can win the game in Fig. 6 with non-negligible advantage.*
The Game *Gn* HP

(*λ*)
Initialisation: This procedure is run only once at the beginning of the game. $

(a) *b ←{*0*,*1*}*
(b)Activate *A* with 1l
*λ* and receive *n* in unary notation. $*λ n*

(c)(hk*,*mk) *←* Setup(1l*,*1l)
(d)Provide mk to the adversary. Query: This procedure can be run multiple times and at any moment.
(a)Receive *x ∈ R*
*n* from *A*. $

(b)(*d,ψ*) *←* Hash(hk*, x*)
(c)Provide the adversary with *d*. Challenge: This procedure can be run only once and at any moment.
(a)Receive *x₀, x₁ ∈ R*
*n* from *A*. $

(b)(*d,ψ*) *←* Hash(hk*, xb*)
(c)Provide the adversary with *d*. Win: The adversary wins if it ends its execution outputting *b*.
Fig. 6. The Game for Hasher Privacy

*3. (Matrix Privacy). No PPT adversary A can win the game in Fig. 7 with non-negligible advantage.*
*4. (Efficiency). The size of the hash d is* poly(*λ,* log*|R|*) *· o*(*n*)*.* Notice that hasher privacy is essentially saying that the digests sent by the hasher reveal no information about the underlying messages, even if they are all generated using the same hasher key. In a similar way, matrix privacy states that the messages sent by the encryptor leak no information about the input matrices. Again, this holds even if the matrix key is reused multiple times. In general, both properties are guaranteed as long as the hasher key and the matrix key remain secret (similarly to what happens in every symmetric encryption scheme). We now formalise, however, stronger security notions that, if satisfied, ensure the privacy of both parties even if the keys are made public (similarly to all public key encryption schemes).

The Game *Gn* MP

(*λ*)
Initialisation: This procedure is run only once at the beginning of the game. $

(a) *b ←{*0*,*1*}*
(b)Activate *A* with 1l
*λ* and receive *n* in unary notation. $*λ n*

(c)(hk*,*mk) *←* Setup(1l*,*1l)
(d)Provide hk to the adversary. Query: This procedure can be run multiple times and at any moment.
(a)Receive an *n*-column matrix *M ∈M* from *A*. $
(b)(*E,ϕ*) *←* Matrix(mk*,M*)
(c)Provide the adversary with *E*. Challenge: This procedure can be run only once and at any moment.
(a)Receive two *n*-column matrices with the same number of rows *M₀,M₁ ∈M* from *A*. $
(b)(*E,ϕ*) *←* Matrix(mk*,Mb*)
(c)Provide the adversary with *E*. Win: The adversary wins if it ends its execution outputting *b*.
Fig. 7. The Game for Matrix Privacy

Definition 10(Strong Hasher Privacy). *Let* (Setup*,*Hash*,*Matrix*,*HasherEval*,*MatrixEval) *be a bilinear* *HSS scheme over the ring R. We say that the scheme satisfies strong hasher privacy if, for every n ∈* N *and* *values x₀, x₁ ∈*(*R* *n* *, the following distributions are computationally indistinguishable* $ ) ( $ ) (hk*,*mk) *←* Setup(1l *λ* *,*1l *n* ) (hk*,*mk) *←* Setup(1l *λ* *,*1l *n* ) (*d,* hk*,*mk) $ (*d,* hk*,*mk) $ (*d,ψ*) *←* Hash(hk*, x₀*) (*d,ψ*) *←* Hash(hk*, x₁*)

Definition 11(Strong Matrix Privacy). *Let* (Setup*,*Hash*,*Matrix*,*HasherEval*,*MatrixEval) *be a bilinear* *HSS scheme over the ring R. We say that the scheme satisfies strong matrix privacy if, or every n,m ∈* N *and m × n matrices* ( *M₀,M₁ ∈M over* $ *R, the following distributions are computationally indistinguishable*) ( $ ) (hk*,*mk) *←* Setup(1l *λ* *,*1l *n* ) (hk*,*mk) *←* Setup(1l *λ* *,*1l *n* ) (*E,* hk*,*mk) $ (*E,* hk*,*mk) $ (*E,ϕ*) *←* Matrix(mk*,M₀*) (*E,ϕ*) *←* Matrix(mk*,M₁*)

If strong hasher privacy and strong matrix privacy hold simultaneously, we say that we are dealing with a public-key bilinear HSS scheme. In these situations, we use pk to denote the concatenation of hk and mk. We modify the syntax of Hash and Matrix by providing them directly with pk instead of just hk and mk.

Definition 12(Public-Key Bilinear HSS). *A bilinear HSS scheme is public-key if it simultaneously* *satisfies both strong hasher privacy and strong matrix privacy.*

We finally present a even stronger version of hasher privacy, which we call *transparent hasher privacy*. The latter states that the privacy of the hashed messages holds even if we provide the adversary with the random coins used to run the setup. We will use this property to build our sublinear communication MPC protocols.

Definition 13(Transparent Hasher Privacy). *Let* (Setup*,*Hash*,*Matrix*,*HasherEval*,*MatrixEval) *be a bi-* *linear HSS scheme over the ring R. Let L*(*λ,n*) *denote the length of the randomness needed by* Setup(1l *λ* *,*1l *n* )*.* *We say that the scheme satisfies transparent hasher privacy if, for every n ∈* N *and values x₀, x₁ ∈ R* *n* *, the* *following distributions are computationally indistinguishable*  $   $    *ρ ←{*0*,*1*}* *L*(*λ,n*)    *ρ ←{*0*,*1*}* *L*(*λ,n*)       (*d,ρ*) (hk*,*mk) *←* Setup(1l *λ* *,*1l *n*; *ρ*) (*d,ρ*) (hk*,*mk) *←* Setup(1l *λ* *,*1l *n*; *ρ*)       $   $  (*d,ψ*) *←* Hash(hk*, x₀*) (*d,ψ*) *←* Hash(hk*, x₁*)

A bilinear HSS scheme guarantees that the size of the digests is sublinear in the size of the hasher input

*n*. This does not prevent however that the size of the keys and matrix encoding scales polynomially in *n*

(we recall that the length of the hasher input is fed into Setup). If the size of the keys grows sublinearly in *n*, we say that the scheme satisfies key-compactness. If instead the matrix encoding of any *n × n* matrix in the class *M* is sublinear in *n*, we say that the scheme is matrix-compact. Observe that, in order for matrix compactness to be satisfied, the class of *n × n* matrices in *M* must contain *o*(2 *n* ) elements. In other words, any bilinear scheme for the class of all matrices *M∈R* *n×n* cannot satisfy matrix compactness.

Definition 14(Key-Compact Bilinear HSS). *A bilinear HSS scheme over the ring R is key-compact* *if, for every λ,n ∈* N*, the size of the keys* (hk*,*mk) *output by* Setup(1l *λ* *,*1l *n* ) *is* poly(*λ,* log*|R|*) *· o*(*n*)*.*

Definition 15(Matrix-Compact Bilinear HSS). *A bilinear HSS scheme over the ring R is matrix-* *compact if, for every λ,n ∈* N*, and matrix M ∈ R* *n×n* *, the size of the encoding E output by* Matrix(mk*,M*)*,* $*λ n* *where* (hk*,*mk) *←* Setup(1l*,*1l)*, is* poly(*λ,* log*|R|*) *· o*(*n*)*.*

## 4 Public-Key Bilinear HSS Constructions

In this section, we show how to build public-key bilinear HSS schemes for all matrices based on DLOG over unknown order groups (such as Paillier or class groups, see Section 4.1) or lattices (see Section 4.2).

4.1 Public-Key Bilinear HSS for all Matrices Based in the NIDLS Framework We formalise our construction in the NIDLS framework of [ADOS22], which can be instantiated e.g. using Paillier, Goldwasser-Micali where the RSA modulus is product of safe-primes or class groups. We recall that class groups have the advantage of requiring only a transparent setup. We start by formalising the complexity assumptions we need.
### New Assumptions in the NIDLS Framework.

*The uniformity assumption.* We introduce a new computational assumption over the framework, we call it the *uniformity assumption*. The latter essentially says that given the parameters of the NIDLS group, a sample *g₀* from *D* and the corresponding auxiliary information *ρ₀* 9, it is hard to distinguish between a random power of *g₀* and another sample *g₁* from *D* where the corresponding auxiliary information *ρ₁* is kept secret.

Definition 16(The Uniformity Assumption). *We say that the uniformity assumption holds in the* *NIDLS framework if the following distributions are computationally indistinguishable*  $*λ*    par := (*G,F,H,f,q,ℓ,* aux) *←* Gen(1l)  par  $*λ* *w*(*g ,ρ*0 0) *←D*(1l*,*par)  *g₀,ρ₀,g₀*   $  *w ←* [*ℓ*]  $*λ*    par := (*G,F,H,f,q,ℓ,* aux) *←* Gen(1l)  par  $*λ* (*g ,ρ*0 0) *←D*(1l*,*par)  *g₀,ρ₀,g₁*   $*λ* (*g₁,ρ₁*) *←D*(1l*,*par)

The above assumption is useful only when the NIDLS group is not cyclic of prime order. Indeed, if that was not the case, the assumption holds information-theoretically. We observe that the subgroup of squares of the Paillier group Z *∗* *N*2 is cyclic. If *N* is product of distinct safe-primes, also the subgroup of elements with Jacobi symbol 1 in Z *∗* *N*is cyclic. So, in these settings the uniformity assumption holds unconditionally. 9 For instance, *ρ₀* can represent the randomness used to produce *g₀*, if we aim to generate them using common random string or a random oracle.

Class groups, unfortunately, are not cyclic and we could not relate uniformity to any other known as- sumption. We believe however that uniformity is likely to hold even in this setting. Our claim is supported by the hardness of computing discrete logarithms over class groups. We also highlight that the assumption resembles, to some extent, the DXDH assumption of [ADOS22], which says that given the description of the NIDLS group and two samples *g₀,g₁* from *D*, it is hard to distinguish (*g₀* *r* *,g₁* *r* ) from (*g₀* *r* *,g₀* *s* ) for random $ *r,s ←* [*ℓ*]. This implies that it is hard to tell whether a group element belongs to *⟨g₀⟩*.

Theorem 3. *If* Gen *outputs a cyclic group G of order N such that ϕ*(*N*)*/N* = 1*−*negl(*λ*)*, D is the uniform* *distribution over G and |ℓ − N |/N ≤* negl(*λ*)*, the uniformity assumption holds information theoretically.*

*Proof.* We notice that *D* outputs a generator of *G* with overwhelming probability as the number of generators $ is *ϕ*(*N*) and *ϕ*(*N*)*/N* is negligible. Furthermore, the distribution of *w* mod *N* where *w ←* [*ℓ*] is statistically close to the uniform distribution over Z*N*. We conclude that the distribution of *g₀* *w* is statistically close to the uniform distribution over *G*. *⊓⊔*

*The n-ary enhanced DDH assumption.* We introduce the second assumption needed to build bilinear HSS in the NIDLS framework, we call it *enhanched DDH (EDDH) assumption*. The latter states that given the parameters of the NIDLS group and *n* + 1 group elements *g₀,...,gn*sampled from *D* (along with the

|||n||n w|
|---|---|---|---|---|
|r w|r n w|n|q||

corresponding auxiliary information *ρ₀,...,ρn*), it is hard to distinguish between (*g₀* *w* *,...,gn* *w* ) for a random
*w* and (*f*0*· g₀,...,fn· g*) for random *r₀,...,r ∈* Z.

Definition 17(The *n*-ary Enhanced DDH Assumption). *We say that the n-ary Enhanced DDH (n-* *EDDH) assumption holds in the NIDLS framework if the following distributions are computationally indis-* *tinguishable*

    par par := (*G,F,H,f,q,ℓ,* aux) *←* $ Gen(1l *λ* )    *g₀,...,gn*$ *λ* *∀j ∈* [0*..n*] : (*g ,ρj j*) *←D*(1l*,*par)  *ρ₀,...,ρn*  $  *g₀* *w* *,...,gn* *w w ←* [*ℓ*]  $*λ*    par par := (*G,F,H,f,q,ℓ,* aux) *←* Gen(1l)     $*λ* *g₀,...,gn∀j ∈* [0*..n*] : (*gj,ρj*) *←D*(1l*,*par)   *ρ₀,...,ρnw ←* $ [*ℓ*]       *f* *r* 0 *· g* *w* *,...,f* *r* *n* *· g* *w* $   0 *n* *∀j ∈* [0*..n*] : *rj←* Z*q*

The above assumption is related to DDH. For instance, it is easy to see that if the NIDLS group has prime order, and *D* outputs a random group element without any auxiliary information, *n*-EDDH is implied by DDH and the hidden subgroup assumption for any polynomial *n*(*λ*). Unfortunately, however, all known instantiations of the NIDLS framework do not have prime order (in particular, class groups, the RSA group and the Paillier group are not even cyclic). Moreover, we have often an additional issue because the distri- bution *D* might be different from the uniform distribution and, furthermore, it can be non-explainable (this if for instance the case, as far as we know, over class groups), meaning that, given a group element produced by *D*, we are not able to simulate the corresponding auxiliary information. This fact prevents the reduction from EDDH to DDH from working as we can no longer substitute e.g. *gj*with a random power of *g₀* (we would not be able to simulate *ρj*).

Definition 18(Explainable Sampler). *The distribution D is explainable if there exists a PPT algorithm* Explain *such that the following distributions are computationally indistinguishable* ( $*λ* ) par := (*G,F,H,f,q,ℓ,* aux) *←* Gen(1l) par*,g,ρ* $ (*g,ρ*) *←D*(1l *λ* *,*par)  $ 

|||λ|
|---|---|---|
|′|λ||
|′|λ||

  par := (*G,F,H,f,q,ℓ,* aux) *←* Gen(1l)   par*,g,ρ* (*g,ρ*) *←D* $ (1l*,*par)     $  *ρ ←* Explain(1l*,*par*,g*)

*Enhanced DDH over class groups.* As we have already mentioned, over class groups, the distribution *D* is not known to be explainable (unless we decide to give up on the transparent setup by not revealing the randomness *ρ* used by the sampling procedure). That prevents the reduction from EDDH to DDH from succeeding. We believe however that *n*-ary EDDH is likely to hold in this setting for any polynomial *n*(*λ*). To support our claim, we observe that the points highlighted in [ADOS22] to argue the hardness of DXDH can also be applied to *n*-ary EDDH.

*Enhanced DDH over the Paillier group and the RSA group.* Compared to the class group case, analysing the hardness of EDDH over Paillier and Goldwasser-Micali is significantly easier. We show that, for any poly- nomial *n*(*λ*), the *n*-ary EDDH assumption over the Paillier group is implied by DCR and, over Goldwasser- Micali, by the QR assumption.

### Theorem 4. The following are true.

– *Suppose that* Gen = GenPaillier*and D* = *D*Paillier*. Then, DCR implies the n-ary EDDH assumption for any* *polynomial n*(*λ*)*.* – *Suppose that* Gen = GenGM*and D* = *D*GM*. Then, QR implies the n-ary EDDH assumption for any* *polynomial n*(*λ*)*.*

*Proof.* We prove both points of the theorem simultaneously by relying on the ideas of [BG10, Lemma B.1]. We proceed by considering the following sequence of hybrids. Hybrid 0:

$*λ*

1. par := (*G,F,H,f,q,ℓ,* aux = *N*) *←* Gen(1l)
$*λ*

2. *∀j ∈* [0*..n*] : (*gj,ρj*) *←D*(1l*,*par) $
3. *w ←* [*ℓ*]
4.Provide the adversary with *N,g₀,...,gn,ρ₀,...,ρn,g₀*
*w* *,...,gn* *w*

### Hybrid 1:

$*λ*

1. par := (*G,F,H,f,q,ℓ,* aux = *N*) *←* Gen(1l)
$*λ*

2. *∀j ∈* [0*..n*] : (*hj,ηj*) *←D*(1l*,*par)
3. *∀j ∈* [0*..n*] : *gj← h*
*q* *j*

4. *∀j ∈* [0*..n*] : *ρj← ηjq* $
5. *w ←* [*ℓ*]
6.Provide the adversary with *N,g₀,...,gn,ρ₀,...,ρn,g₀*
*w* *,...,gn* *w*

### Hybrid 2.i.0:

$*λ*

1. par := (*G,F,H,f,q,ℓ,* aux = *N*) *←* Gen(1l)
$*λ*

2. *∀j ∈* [0*..n*] : (*hj,ηj*) *←D*(1l*,*par)
$

3. *∀j ∈* [0*..n*] : *rj←* Z*q*

*q*

4. *∀j ∈* [0*..n*] : *gj← hj*
5. *∀j ∈* [0*..n*] : *ρj← ηjq* $
6. *w ←* [*ℓ*]
*r*0*· g₀w,...,fri−*1 *w*

7.Provide the adversary with *N,g₀,...,gn,ρ₀,...,ρn,f · giw−*1*,giw,...,gn* Hybrid 2.*i*.1: Let *C* := 2 if Gen = GenPaillier, let *C* := 1 otherwise.
$*λ*

1. par := (*G,F,H,f,q,ℓ,* aux = *N*) *←* Gen(1l)
$*λ*

2. *∀j ∈* [0*..n*] : (*hj,ηj*) *←D*(1l*,*par)
$

3. *∀j ∈* [0*..n*] : *rj←* Z*q*
*q*

4. *∀j ∈* [0*..n*] *\{i}* : *gj← hj*
5. *∀j ∈* [0*..n*] *\{i}* : *ρj← ηjq* $
6. *s ←* Z*q* *s q*
7. *gi← f · hi* *s/C*
8. *ρi← f · ηiq* $
9. *w ←* [*ℓ*]
*r*0*· g₀w,...,fri−*1 *w*

10.Provide the adversary with *N,g₀,...,gn,ρ₀,...,ρn,f · giw−*1*,giw,...,gn*
### Hybrid 2.i.2:

$*λ*

1. par := (*G,F,H,f,q,ℓ,* aux = *N*) *←* Gen(1l)
$*λ*

2. *∀j ∈* [0*..n*] : (*hj,ηj*) *←D*(1l*,*par)
$

3. *∀j ∈* [0*..n*] : *rj←* Z*q*
*q*

4. *∀j ∈* [0*..n*] *\{i}* : *gj← hj*
5. *∀j ∈* [0*..n*] *\{i}* : *ρj← ηjq* $
6. *s ←* Z*q* *s q*
7. *gi← f · hi* *s/C*
8. *ρi← f · ηiq* $
9. *w ←* [*q · φ*(*N*)*/*4]
*r*0*· g₀w,...,fri−*1 *w*

10.Provide the adversary with *N,g₀,...,gn,ρ₀,...,ρn,f · giw−*1*,giw,...,gn*
### Hybrid 2.i.3:

$*λ*

1. par := (*G,F,H,f,q,ℓ,* aux = *N*) *←* Gen(1l)
$*λ*

2. *∀j ∈* [0*..n*] : (*hj,ηj*) *←D*(1l*,*par)
$

3. *∀j ∈* [0*..n*] : *rj←* Z*q*
*q*

4. *∀j ∈* [0*..n*] *\{i}* : *gj← hj*
5. *∀j ∈* [0*..n*] *\{i}* : *ρj← ηjq* $
6. *s ←* Z*q* *s q*
7. *gi← f · hi* *s/C*
8. *ρi← f · ηiq* $
9. *w ←* [*q · φ*(*N*)*/*4]
*r*0*· g₀w,...,fri−*1 *ri· gw*

10.Provide the adversary with *N,g₀,...,gn,ρ₀,...,ρn,f · giw−*1*,fiw,giw*+1*,...,gn*
### Hybrid 2.i.4:

$*λ*

1. par := (*G,F,H,f,q,ℓ,* aux = *N*) *←* Gen(1l)
$*λ*

2. *∀j ∈* [0*..n*] : (*hj,ηj*) *←D*(1l*,*par)
$

3. *∀j ∈* [0*..n*] : *rj←* Z*q*
*q*

4. *∀j ∈* [0*..n*] *\{i}* : *gj← hj*
5. *∀j ∈* [0*..n*] *\{i}* : *ρj← ηjq*

$

6. *s ←* Z*q*
7. *gi← f* *s* *· h*
*q* *i*

8. *ρi← f* *s/C*
*· ηiq* $

9. *w ←* [*ℓ*]
10.Provide the adversary with *N,g₀,...,gn,ρ₀,...,ρn,f*
*r* 0*· g₀w,...,fri−*1*· g* *iw−*1*,f* *r* *i· g* *iw,giw*+1*,...,gn* *w*

### Hybrid 3:

$*λ*

1. par := (*G,F,H,f,q,ℓ,* aux = *N*) *←* Gen(1l)
$*λ*

2. *∀j ∈* [0*..n*] : (*gj,ρj*) *←D*(1l*,*par)
$

3. *∀j ∈* [0*..n*] : *rj←* Z*q* $
4. *w ←* [*ℓ*]

||n|n r|w|r n w|
|---|---|---|---|---|
|Paillier|||||
|||||GM|

5.Provide the adversary with *N,g₀,...,g,ρ₀,...,ρ,f*0*· g₀,...,fn· g* If Gen = Gen, Hybrid 0 and Hybrid 1 are indistinguishable under the DCR assumption and so are also Hybrid 2.*i*.0 and Hybrid 2.*i*.1 (for every *i ∈* [0*..n*]), Hybrid 2.*i*.4 and Hybrid 2.(*i* + 1).0 (for every *i ∈* [0*..n*]), and Hybrid 2.(*n*+ 1).0 and Hybrid 3. If instead Gen = Gen, these hybrids are indistinguishable under the QR assumption. Hybrid 1 and Hybrid 2.0.0 are identical. Hybrid 2.*i*.2 and Hybrid 2.*i*.3 are statistically indistinguishable for every *i ∈* [0*..n*]. This is due to the fact that *ℓ* is 2
*λ* times greater than the order of *G*. Finally, Hybrid

2.*i*.3 and Hybrid 2.*i*.4 are perfectly indistinguishable for every *i ∈* [0*..n*]. This is due to the fact that the order of *f* and the order of *h*
*q* *j*are coprime for every *j ∈* [0*..n*]. *⊓⊔*

The Bilinear HSS Scheme in the NIDLS Framework. We are ready to present our first bilinear HSS scheme. The construction is public-key, supports all *m × n* matrices over Z*q*, and is secure in the NIDLS framework under the uniformity assumption (see Def. 16), the *n*-ary EDDH assumption (see Def. 18) and the hidden subgroup assumption. We describe it in Fig. 8. The rationale behind the scheme is explained in Section 1.2. We highlight that the construction does not satisfy key-compactness.

Theorem 5. *If the n-ary EDDH assumption, the uniformity assumption and the hidden subgroup assump-* *tion hold in the NIDLS framework [ADOS22], the construction in Fig. 8 is a secure public-key bilinear HSS* *scheme for the class M of m × n matrices over* Z*q.* *Moreover, if the NIDLS framework is instantiated using Paillier or Goldwasser-Micali or class groups,* *the scheme satisfies transparent hasher privacy.*

*Proof.* It is trivial to see that the size of the digest *d* is independent of *n*. We start by proving correctness. We observe that, for every *i ∈* [*m*],       *n*

|Y||Y|||Y||
|---|---|---|---|---|---|---|
|u0|x|w ·u|M ·x|·x||·w|
|i,|i,j|||jw|j−x||
|j=1||j=1 P M ·x|||j=1||

*x* *n* *·x* *n* *·w* *E* *i,* *u* 0*· E* *j*  *· d−wi*= *g₀wi·u· fMi,j ·xj· gi j* *·* *g₀−u·wi· gj i*

*n* = *fj*=1 *i,j j*

By the properties of the distributed DLOG procedure, we conclude that, with overwhelming probability, *s₀ − s₁* = *M · x*. We now proceed by proving the hasher privacy. We do this by relying on a sequence of *n* + 1 indistin- guishably hybrids, the *t*-th one of these consisting of the following Hybrid *t*.0.

$*λ n*

1. pk := (par*,g₀,...,gn n*) *←* Setup(1l

||,ρ₀,...,ρ|, 1l )|
|---|---|---|
||n||
|x|x||
|tu t+1|n||
 $
2. *u ←* [*ℓ*]
*t*+1 *n*

3. *d ← g ··g ····· g*

Bilinear HSS for all Matrices based on DDLOG Setup(1l *λ* *,*1l *n* ):

$*λ*

1. par := (*G,F,H,f,q,ℓ,* aux) *←* Gen(1l)
$*λ*

2. *∀j ∈* [0*..n*] : (*gj,ρj*) *←D*(1l*,*par)
3.Output pk := (par*,g₀,...,gn,ρ₀,...,ρn*).
Hash pk = (par*,g₀,...,gn,ρ₀,...,ρn*)*, x* :

$

1. *u ←* [*ℓ*] Q *u n x*
2. *d ← g₀ ·j*=1*gj j*
3. *ψ ←* (par*,u, x*)
4.Output *d* and *ψ*.
Matrix pk = (par*,g₀,...,gn,ρ₀,...,ρn*)*,M* :

$

1. *∀i ∈* [*m*] : *wi ←* [*ℓ*]
2. *∀i ∈* [*m*] : *Ei,*0 *← g₀*
*wi*

3. *∀i ∈* [*m*]*,j ∈* [*n*] : *Ei,j ← f*
*Mi,j* *· gjwi*

4.Output *E* := (*Ei,j*)*i,j* and *ϕ* = (par*,w₁,...,wm,M*). HasherEval *E,ψ* = (par*,u, x*) :
*u*Q*n xj*

1. *∀i ∈* [*m*] : *s₀,i ←* DDLog(par*,Ei,*0*·j*=1*Ei,j*)
2.Output *s₀* MatrixEval *d,ϕ* = (par*,w₁,...,wm,M*) :
1. *∀i ∈* [*m*] : *s₁,i ←* DDLog(par*,d*
*wi* )

2.Output *s₁*
Fig. 8. Bilinear HSS for all Matrices based on DDLOG

4.Output (pk*,d*)
### Hybrid t.1.

$*λ n*

1. pk := (par*,g₀,...,gn,ρ₀,...,ρn*) *←* Setup(1l*,*1l) *′*$*λ*
2.(*h,ρ*) *←D*(1l*,*par)
*x* *t*+1 *xn*

3. *d ← h · gt*+1*····· gn*
4.Output (pk*,d*) Observe that under the uniformity assumption, the Hybrid *t.*0 is indistinguishable from Hybrid *t*.1. Furthermore, under the same assumption, Hybrid *t*.1 is indistinguishable from Hybrid (*t*+ 1).0. We observe that in Hybrid 0.0, the distribution of (pk*,d*) is as if *d* was produced by Hash(pk*, x*). In Hybrid (*n −* 1).1, *d* is independent of *x*. Hasher privacy immediately follows. Next, we prove matrix privacy. We do this by relying on the following sequence of indistinguishably hybrids. Hybrid 0.
$*λ n*

1. pk := (par*,g₀,...,gn,ρ₀,...,ρn*) *←* Setup(1l*,*1l)
$

2. *∀i ∈* [*m*] : *wi←* [*ℓ*]
3. *∀i ∈* [*m*] : *Ei,*0*← g₀*
*wi*

4. *∀i ∈* [*m*]*,j ∈* [*n*] : *Ei,j← f*
*Mi,j* *· gjw* *i*

5.Output (pk*,E*)
### Hybrid 1.

$*λ n*

1. pk := (par*,g₀,...,gn,ρ₀,...,ρn*) *←* Setup(1l*,*1l)
$

2. *∀i ∈* [*m*] : *wi←* [*ℓ*]
$

3. *∀i ∈* [*m*]*,j ∈* [*n*] : *ri,j←* Z*q*

||i,j r|w q||
|---|---|---|---|
|i,0|i,j|M|+r|

4. *∀i ∈* [*m*] : *E ← fi,*0*· g₀*
*i*

5. *∀i ∈* [*m*]*,j ∈* [*n*] : *E ← fi,j i,j· gjw*
*i*

6.Output (pk*,E*) Observe that Hybrid 0 and Hybrid 1 are indistinguishable under the *n*-ary EDDH assumption. We conclude the proof by observing that the distribution of (pk*,E*) in Hybrid 0 is exactly as if *E* was generated by Matrix(pk*,M*). Furthermore, the distribution of (pk*,E*) in Hybrid 1 is independent of *M* as all information is masked by (*ri,j*)*i∈*[*m*]*,j∈*[*n*]. *⊓⊔*
4.2 Public-Key Bilinear HSS for all Matrices Based on Lattices The techniques of the construction in Section 4.1 can be adapted to work over lattices, similarly to how the techniques of [BGI16] were used in [BKS19]. In this section, we show how this is done in detail. Since the resulting scheme can be instantiated under multiple variants of the LWE problem, such as plain LWE or Ring-LWE, we abstract out how the LWE matrix and the noise are sampled. In particular, we rely on a randomised algorithm LWEGen that, on input 1l
*λ*, 1l *n*, *p ∈* N, produces matrices *A ∈* Z *n* *q ×k*, *B ∈* Z*q* *t×k*, for some *q,t,k ∈* N, along with descriptions of noise distributions. We require that primal LWE holds with respect to the matrix (*A∥B*) ⊺. Furthermore, we require that dual LWE holds with respect to *B*. Finally, we ask that the noise produced by the given distributions remains small relative to *q/p*. Below, we formalise the exact properties we desire.

Definition 19(LWE sampler). *An LWE sampler is a PPT algorithm* LWEGen *that, on input the se-* *curity parameter* 1l *λ* *,* 1l *n* *and p ∈* N*, produces a positive integers q,t,k, matrices A ∈* Z*q* *n×k* *,B ∈* Z *tq×k* *and* *distributions ξ,χ.* *We require the following properties:*

– *(Primal). For every n,p ∈* N*, the following distributions are computationally indistinguishable*  $*λ n*   *q,A,B,ξ,χ* (*q,t,k,A,B,ξ,χ*) *←* LWEGen(1l*,*1l*,p*)   *A* ⊺ *w* + *e w ←* $ Z *k* *q*  ⊺ *′*  *B w* + *e ′*$  (*e, e*) *← χ*  $*λ n*    (*q,t,k,A,B,ξ,χ*) *←* LWEGen(1l*,*1l*,p*)  *q,A,B,ξ,χ*  $*n* *′v ←* Z*q*   *v, v*  *′*$*t* *v ←* Z*q*

– *(Dual). For every n,p ∈* N*, the following distributions are computationally indistinguishable* ( $*λ n* ) *q,A,B,ξ,χ* (*q,t,k,A,B,ξ,χ*) *←* LWEGen(1l*,*1l*,p*)

*B · u u ←* $ *ξ* ( $*λ n* ) *q,A,B,ξ,χ* (*q,t,k,A,B,ξ,χ*) *←* LWEGen(1l*,*1l*,p*)

*v v ←* $ Z *k* *q*

– *(Small noise). There exists a function T*(*λ*) *such that, for every x ∈* Z *n* *p* " $*λ n* # ⊺ ⊺ *′* (*q,t,k,A,B,ξ,χ*) *←* LWEGen(1l*,*1l*,p*) Pr *|x · e* + *u · e | > T*(*λ*) $ $ *≤* negl(*λ*) (*e, e* *′* ) *← χ, u ← ξ*

### and p · T(λ)/q ≤ negl(λ).

Bilinear HSS for all Matrices based on Lattices Setup(1l *λ* *,*1l *n* ):

$*λ n*

1.(*q,t,k,A,B,ξ,χ*) *←* LWEGen(1l*,*1l*,p*)
2.Output pk = (*A,B*). Hash pk = (*A,B*)*, x* : $
1. *u ← ξ*
2. *d ← A · x* + *B · u*
3. *ψ ←* (*A,B, u, x*)
4.Output *d* and *ψ*.

|Matrix pk = (A,B),M|:|||
|---|---|---|---|
|1. ∀i ∈ [m] : w|← Z|||
|2. ∀i ∈ [m] : (e|, e) ← χ|||
|3. ∀i ∈ [m] : E|← A · w|+ e + ⌈q/p⌋· M||
|4. ∀i ∈ [m] : E|← B · w|+ e||
|5.Output E := (E HasherEval E,ψ = (A,B, u, x) :|,E)|and ϕ = (A,B, w₁,..., w||
|1. ∀i ∈ [m] : s₀ 2.Output s₀|←⌈x · E|+ u · E|⌋|
|MatrixEval d,ϕ = (A,B, w₁,..., w|||,M ) :|
|1. ∀i ∈ [m] : s₁|←⌈d · w|⌋||

$*k* *i q* *′i*$ *i* *i* ⊺ *i i i* ⊺

*i′* ⊺ *i* *′i*

*i i′ i∈*[*m*] *m,M*).

*,i* ⊺ *i* ⊺ *i′ ⌈q/p⌋*

*m*

*,i* ⊺ *i ⌈q/p⌋*

2.Output *s₁*
Fig. 9. Bilinear HSS for all Matrices based on Lattices
 We are ready to present our second public-key bilinear HSS scheme for all matrices. Its description can
be found in Fig. 9, the rationale behind the construction is explained in Section 1.2. Below, we prove security under the assumption that LWEGen satisfies Def. 19. We highlight that even this construction does not satisfy key-compactness.

Theorem 6. *If* LWEGen *is a LWE sampler, the construction in Fig. 9 is a secure public-key bilinear HSS* *scheme for the class M of all matrices over* Z*p.* *Moreover, if* LWEGen *is instantiated using plain LWE (or Ring-LWE) with superpolynomial modulus-to-* *noise ratio, the scheme satisfies transparent hasher privacy.*

*Proof.* We start by proving correctness. We observe that, for every *i ∈* [*m*],

(*x* ⊺ *· Ei*+ *u* ⊺ *· Ei′*) *− d* ⊺ *· wi*=

= (*x* ⊺ *· A* ⊺ *· wi*+ *x* ⊺ *· ei*+ *u* ⊺ *· B* ⊺ *· wi*+ *u* ⊺ *· e* *′i* + *⌈q/p⌋· Mi· x*) ⊺ ⊺

|− (x · A|· w + u · B|· w )||||
|---|---|---|---|---|---|
||⊺ i|⊺ i|′i|||
|i|||||⊺ i|

*i* ⊺ ⊺ *i* = *⌈q/p⌋· Mi· x* + *x* ⊺ *· ei*+ *u* ⊺ *· e* *′i* *.*

We also observe that *w* is random, *d* is indistinguishable from random, and *k* is *ω*(log*λ*) 10, so *z₁,i*:= *d · w* is also indistinguishable from random. Thanks to this fact, along with the small noise property of LWEGen, we conclude that, with overwhelming probability, *s₀* + *s₁* = *M · x*.

10 We need this last property because *q* may not be prime. If *k* = *ω*(log*λ*), we are sure that with overwhelming probability one of the entries of *wi*is in Z *∗* *q*.

Indeed, suppose that *z₁,i*= *s₁,i·⌈q/p⌋* + *s* *′* 1*,i*where *|s* *′* 1*,i|≤* <u>1</u> 2 *⌈q/p⌋*. We know that

*z₀,i*:= *x* ⊺ *· Ei*+ *u* ⊺ *· Ei′*= (*s₁,i*+ *Mi· x*) *·⌈q/p⌋* + *s* *′* 1*,i*+ *e*e*i*

where *e*e*i*is some error term of magnitude ad most *T* (*λ*). We observe that *|s₁,i− Mi· x|≤ n · p²/*2. We rewrite *s₁,i i,i*+ *p · ρ₀,i,i p*

|− M · x as s₀|where s₀|∈ Z|, and we observe that|||||
|---|---|---|---|---|---|---|---|
|,i i|,i|,i ,i ,i|p|,i||′1,i i||
|||||||,i||

*z₀* = *s₀ ·⌈q/p⌋* + *ρ₀ ·* (*p ·⌈q/p⌋*) + *s* + *e*e*.*

Furthermore, since *|p ·⌈q/p⌋|≤ p/*2, with overwhelming probability, *|ρ₀ ·* (*p ·⌈q/p⌋*) + *e*e*i|≤ T*(*λ*) + *n · p²*. Correctness is preserved as long as

*′*<u>1</u> *|ρ₀,i·* (*p ·⌈q/p⌋*) + *s₁,i*+ *e*e*i|≤ ⌈q/p⌋.* 2

When *z₁,*1is at least (*T* (*λ*) + *p²*)-away from (*ℓ*+ 1*/*2) *·⌈q/p⌋* for every *ℓ ∈* Z*p*, we are sure that the bad event will not occur. The probability of the bad even is therefore bounded from above by *p ·* (*T* + *n · p²*)*/q*, which is negligible. We can easily prove hasher privacy by the dual security of LWEGen. Indeed, *B · u* is indistinguishable from random. Such value masks all information about *x* hidden in *d*. In a similar way, under the primal security of LWEGen, we can show that *E* leaks no information about

*M*. This concludes the proof. *⊓⊔*
## 5 Succinct Half-Chosen Vector OLE

In this section and in Section 6, we study bilinear HSS schemes for the class *K* of matrices that are multiples of the identity. Formally, denoting the ring by *R*,

*K* := *{k ·* id*m|m ∈* N*,k ∈ R}*

This class is particularly interesting because any bilinear HSS scheme for *K* immediately gives a “half-chosen” non-interactive Vector-OLE (VOLE) protocol: in a VOLE, one party, called the *Sender*, inputs two vectors *x, y*, whereas the other party, called the *Receiver*, inputs a scalar *k*. At the end of the protocol, the Receiver obtains *z* := *k · x* + *y* without learning anything else (the Sender learns no information at all). Observe that the pair (*z, y*) consists of a secret-sharing of *k · x*. In a fully random VOLE protocol, on the other hand, the parties have no inputs. At the end of the protocol, the Sender will receive random vectors *x, y*, whereas the Receiver will obtain a random constant *k* along with *z* = *k · x* + *y* (the parties will learn no other information). Choosing *x* later requires sending a full correction vector *x* *′* *− x*. Our VOLE protocol will be a middle ground between these two notions: the Sender will only input *x*, and the Receiver will only input the constant *k*. The output will be a random secret-sharing of *k · x*. We probably do not need to explain how important VOLE protocols are in cryptography. What we want to argue is, however, that, in many applications, we do not need a true VOLE protocol – a half-chosen VOLE is sufficient. The surprising fact is that, while it can be proven that VOLE protocols require *Ω*(*n*) communication¹¹ (*n* denotes the length of the vectors *x, y* and *z*), half-chosen VOLE protocols can achieve sublinear communication in *n*. This fact was not known before this work, in this section, we show how bilinear HSS allows us to achieve this. Then, in Section 6, we focus our energy in constructing bilinear HSS schemes for *K* where the communi- cation complexity of the encryptor is *o*(*n²*). Due to an entropy matter, this is of course impossible to achieve in bilinear HSS scheme for all matrices.

11 If that wasn’t the case, we could send a length-*n* message *m* with *o*(*n*) communication by just inputting *x* = 0 and *y* = *m* in the VOLE protocol.

5.1 Succinct Half-Chosen VOLE and Key-Compact, Matrix-Compact Bilinear HSS We consider the half-chosen non-interactive Vector OLE problem (VOLE): Alice holds a vector *x ∈* Z
*n* *p* whereas Bob holds a constant *k ∈* Z*p*. We would like to non-interactively obtain an additive secret sharing of *k · x*. We observe that multiplying by the constant *k* is equivalent to multiplying by the matrix *k ·* id*n*. Now, if we would naively use the bilinear HSS schemes presented in Section 4 to perform such operation, the communication of Alice would be independent of *n*, however, the communication of Bob would be *Ω*(*n²*). Furthermore, the size of the public key would be *O*(*n*). Is it still possible to use our results to build a half-chosen non-interactive VOLE protocol with *o*(*n*) total communication? To answer this question, we rely on the fact that the messages of bilinear HSS schemes can be reused: if the ciphertext sent by Bob (encoding a matrix *M*) were to be reused with a new message from Alice, let’s say a digest of *x* *′*, the parties would still obtain a secret-sharing of *M · x* *′*. To achieve sublinear communication in the VOLE protocol, we can therefore apply the following trick: Bob will send an encoding of the matrix *k ·* id*n*1*/*3, Alice will instead split its input into *n²* */*3 chunks of *n¹* */*3 elements and will send a digest of each segment. By running the bilinear HSS scheme *n²* */*3 times, once for each digest sent by Alice, the parties will therefore obtain a secret-sharing of *k · x*. Surprisingly, the total communication is now *O*(*n²* */*3 ), equally distributed between Alice and Bob. The size of the public key has also decreased to *O*(*n¹* */*3 ). In other words, our scheme would satisfy both key-compactness and matrix-compactness. We summarise our idea in the following theorem.

Theorem 7. *Let* (Setup*,*Hash*,*Matrix*,*HasherEval*,*MatrixEval) *be a bilinear HSS scheme over R for the ma-* *trix class M⊇K. Suppose that the size of the HSS digest is upper bounded by f*(*n*) *·* poly(*λ,* log*|R|*) *and the* *encoding of an n × n matrix is upper bounded by g*(*n*) *·*poly(*λ,* log*|R|*)*. Assume also that the size of the keys is* *upper bounded by κ*(*n*)*·*poly(*λ,* log*|R|*)*. Then, there exists a bilinear HSS scheme for K with g*(*t*)*·*poly(*λ,* log*|R|*) *communication per party and κ*(*t*) *·* poly(*λ,* log*|R|*) *key size, where t is such that n* = *t · g*(*t*)*/f*(*t*)*. Moreover,* *this transformation preserves the properties of strong hasher privacy, strong matrix privacy, and transparent* *hasher privacy.*

The following corollary summarises what we know so far about succinct non-interactive half-chosen VOLE with semi-honest security.

### Corollary 1. The following hold:

– *Under DCR over the Paillier group* Z *∗* *N*2 *, there exists a half-chosen, semi-honest, non-interactive VOLE* *protocol over* Z*Nwith O*(*n²* */*3 ) *communication per party.* – *Under QR over the the RSA group* Z *∗* *Nwhere N is the product of large safe-primes, there exists exists a* *half-chosen, semi-honest, non-interactive VOLE protocol over* Z₂ *with O*(*n²* */*3 ) *communication per party.* – *For any prime q* = *Ω*(2 *λ* )*, under the n¹* */*3 *-ary EDDH assumption and the uniformity assumption over* *class groups, there exists a half-chosen, semi-honest, non-interactive VOLE protocol over* Z*qwith O*(*n²* */*3 ) *communication.* – *For any integer p, under LWE with superpolynomial modulus-to-noise ratio, there exists a half-chosen,* *semi-honest, non-interactive VOLE protocol over* Z*pwith O*(*n²* */*3 ) *communication per party.*

## 6 Bilinear HSS Constructions for Multiples of the Identity

In this section, we show how to build a bilinear HSS schemes for *K* with strong hasher privacy where the communication complexity of the encryptor is *O*(*n*) instead of *Θ*(*n²*).

6.1 Bilinear HSS for Multiples of the Identity from Power DDH Our first scheme satisfies strong hasher privacy but not strong matrix privacy. The construction is presented in Fig. 10 and is based on the Power-DDH assumption over the NIDLS framework. The rationale behind the construction was explained in Section 1.2. We highlight that, even if we instantiate the framework with class groups, the setup is not transparent. Notice also that the size of the keys is *O*(*n*).

Bilinear HSS for Multiples of the Identity from Power DDH Setup(1l *λ* *,*1l *n* ):

$*λ*

1. par := (*G,F,H,f,q,ℓ,* aux) *←* Gen(1l) $*λ*
2.(*g,ρ*) *←D*(1l*,*par) $
3. *α ←* [*ℓ*]
*α* *j*

4. *∀j ∈* [0*..n*] *\{n* + 1*}* : *gj ← g*
5. hk *←* (par*,ρ,g₀,...,gn*)
6. mk *←* (par*,ρ,g,α*)
7.Output hk and mk. Hash hk = (par*,ρ,g₀,...,gn*)*, x* : $
1. *u ←* [*ℓ*] Q *u n x*
2. *d ← g₀ ·j*=1*gj j*
3. *ψ ←* (*u, x*)
4.Output *d* and *ψ*. Matrix mk = (par*,ρ,g,α*)*,M* = *k ·* id*n* : $
1. *r ←* [*ℓ*]
*r·αj*

2. *∀j ∈* [0*..*2*n −* 1]
*n* *\{n}* : *Ej ← g*

3. *En ← f* *k*
*· g* *r·α*

4.Output *E* = (*E₀,...,E₂n−*1) and *ϕ* := *r*.
HasherEval hk = (par*,ρ,g₀,...,gn*)*,E* = (*E₀,...,E₂n−*1)*,ψ* = (*u, x*) :

*u−i*Q*n xj*

1. *∀i ∈* [*n*] : *s₀,i ←* DDLog par*,En·j*=1*En−i*+*j*
2.Output *s₀* MatrixEval mk = (par*,ρ,g,α*)*,d,ϕ* = *r* :
*r·αn−i*

1. *∀i ∈* [*n*] : *s₁,i ←* DDLog par*,d*
2.Output *s₁*
Fig. 10. Bilinear HSS for Multiples of the Identity from Power DDH

Theorem 8. *If the* 2*n-ary Power-DDH assumption, the uniformity assumption and the* 2*n-ary EDDH as-* *sumption hold in the NIDLS framework, the construction in Fig. 10 is a secure bilinear HSS scheme over* Z*qsatisfying transparent hasher privacy.*

*Proof.* We start by proving correctness. We observe that, for every *i ∈* [*n*],   Y *n* *x−n−i*

|u−i|x−|−r·α|||
|---|---|---|---|---|
|n j=1|n i+j|n|n||
|u·r·α|k·x|x ·r·α j=1|−x j=1|·r·α|

*E* *n* *u−i* *· E* *j* *· d* *−r·α* =

    Y Y *n−i* *i j* *n−i*+*j* *−u·r·α* *n−i* *j* *n−i*+*j* *k·xi* = *g · f · g*  *·* *g · g*  = *f.*

We conclude that, with overwhelming probability,   Y *n* *xn−i* DDLog par*,En* *u−i* *· En−* *j* *i*+*j*  *−* DDLog par*,d−r·α*= *k · x* *i* *.* *j*=1

Proving transparent hasher privacy is straightforward: all information about *x* in *d* is masked by *g₀* *u* = *g* *u*. The distribution of this element is statistically indistinguishable from the uniform distribution over *⟨g⟩*. Proving matrix privacy is almost as simple. We observe that, under the uniform assumption, under Power- *r·α r·α²* *n−*1 *r·α₁ n−*1 $

|r·α₂||n−1||
|---|---|---|---|
|α|α|||
|k||r r|rn−1|

DDH, *g,...,g* are indistinguishable from elements *g,...,g* for *α₁,...,α₂ ←* [*ℓ*]. Then,
under the uniformity assumption, we switch to the hybrid in which *g*1*,...,g*2*n−*1are substituted with random samples *g₁,...,g₂n−*1from *D*(1l *λ* *,*par). Notice that at this point, *f* is masked by *g,g₁,...,g₂*. We conclude by arguing that, under the 2*n*-ary EDDH assumption, no information about *k* is leaked. This ends the proof. *⊓⊔*

By applying Theorem 7 to build succinct non-interactive VOLE protocols, we obtain the following corol- lary.

### Corollary 2. The following hold:

– *Under DCR+Power-DDH over the Paillier group* Z *∗* *N*2 *, there exists a half-chosen,* *√* *semi-honest, non-* *interactive VOLE protocol over* Z*Nwhere the communication complexity is O*( *n*)*.* – *Under QR+Power-DDH over the RSA group* Z *∗* *Nwhere N is the product of large random safe-primes,* *there exists a half-chosen, semi-honest, non-interactive VOLE protocol over* *√* Z₂ *where the communication* *complexity is O*( *n*)*.* – *For any prime q* = *Ω*(2 *λ* )*, under the uniformity assumption, the EDDH assumption and Power-DDH* *over class groups, there exists a half-chosen, semi-honest, non-interactive VOLE protocol over* *√* Z*qwhere* *the communication complexity is O*( *n*)*.*

6.2 Public-Key Bilinear HSS for Multiples of the Identity from Power Ring-LWE In this section, we adapt the ideas based on Power-DDH (see Section 6.1) to the lattice setting. In this way, we obtain a bilinear HSS scheme for *K* where the communication of the encryptor is *O*(*n*). Interesting, differently from the DLOG-based construction in Section 6.1, the scheme we obtain is public-key. The Power Ring-LWE Assumption. The bilinear HSS scheme we are going to present is based on a new assumption we called *Power Ring-LWE*. We recall that the Ring-LWE assumption with ring *R* and noise distribution *χ* states that the following are indistinguishable
    *∀i ∈* [*m*] : *ai←* $ *R*     ()   $$
*a₁,...,am w ← R a₁,...,am∀i ∈* [*m*] : *ai← R*


|||∀i ∈ [m] : u|← R|
|---|---|---|---|
|m|i|m|i|
||i i|||

*u₁,...,u ∀i ∈* [*m*] : *e ←* $ *χ*   *u₁,...,u* $       *∀i ∈* [*m*] : *u ← a · w* + *ei*

In the Power Ring-LWE assumption, we require that indistinguishability holds even if *a₁,...,am*are no $ longer random, but the consists of the first *m* powers of a random ring element *a ← R*. Before formalising the definition of Power Ring-LWE, we recall the definition of norm over rings.

Definition 20. *Let I* = *⟨f*(*X*)*⟩ be an ideal of* Z[*X*] *where f is a monic polynomial of degree K. Let R be* *the ring* Z[*X*]*/I. For any r ∈ R, we define the infinity norm ∥r∥∞as* max*i∈*[1*..M*]*|ri| where* (*r₁,...,rM*) *is* *the only vector in* Z *M* *such that r* = *r₁* + *r₂ · X* + *···* + *rM· X* *M −*1 + *I.*

Definition 21(Power Ring LWE). *For every λ ∈* N*, let Iλ⟨fλ*(*X*)*⟩ be an ideal of* Z[*X*] *where fλis a monic* *polynomial. Let R*(*λ*) := Z[*X*]*/Iλ. Let Rq*(*λ*) = Z*q*[*X*]*/Iλ. Consider positive integers q*(*λ*)*,m*(*λ*) *∈* N *and* *distributions Γ*(1l *λ* ) *and χ*(1l *λ* ) *over Rq*(*λ*)*. We say that Power Ring-LWE holds with respect to* (*q,m,R,Γ,χ*) *if the following distributions are computationally indistinguishable*  $    *a ← Γ*(1l *λ* )      $ *w ← Rq*(*λ*) *a,v ,...,v*0 *m*   *∀i ∈* [0*..m*] : *e ←* $ *χ*(1l *λ* )     *i*    *i* *∀i ∈* [0*..m*] : *vi← a · w* + *ei* ( $*λ* ) *a ← Γ*(1l) *a,v₀,...,vm* $ *∀i ∈* [0*..m*] : *vi← Rq*(*λ*)

The Construction Based on Power Ring-LWE We are now ready to present our bilinear HSS scheme for *K* based on the Power Ring-LWE assumption. The scheme is formalised in Fig. 11. The rationale behind the construction was described in Section 1.2. We highlight that the scheme is public-key but does not satisfy key-compactness.

Theorem 9. *Let p,q be security-parameter-dependent positive integers, let I be an ideal of* Z[*X*] *and define* *R* := Z[*X*]*/I, R be a distribution over R*

||:= Z [X]/I and R||:= Z|[X]/I. Let Γ||. Consider a symmetric|
|---|---|---|---|---|---|---|
||q q||p|p||q|
||12||||||
|n|||||||
|p|1|n||||λ|
||j j=0|j j=1|j j+1|∞|j j|λ|
|||p|||||

*noise distribution χ such that, there exists a function T*(*λ*) *such that p · T*(*λ*)*/q ≤* negl(*λ*) *and, for every* *x ∈ R,*   X X *∀j ∈{*0*,*1*}* : *u ←* $ *χ*(1l) Pr  *u · e* + *x · e > T*(*λ*) $  *≤* negl(*λ*) *∀j ∈* [0*..n* + 1] : *e ← χ*(1l)

*Under Power Ring-LWE with respect to* (*q,n,R,Γ,χ*)*, the construction in Fig. 11 is a secure public-key* *bilinear HSS scheme over* Z *satisfying transparent hasher privacy.*

*Proof.* We start by proving correctness. We observe that, for every *i ∈* [*n*],   X *n* *u₀ · E* *n−i*+ *u₁ · En−i*+1+ *xj· En−i*+*j*+1  *− d · an−i· w* = *j*=1

= *u₀ · a* *n−i* *· w* + *u₀ · en−i*+ *u₁ · a* *n−i*+1 *· w* + *u₁ · en−i*+1 X *n* + *xj· a* *n−i*+*j*+1 *· w* + *xj· en−i*+*j*+1+ *⌈q/p⌋· k · xi* *j*=1   X *n* *−* *u₀ · a* *n−i* *· w* + *u₁ · a* *n−i*+1 *· w* + *xj· a* *n−i*+*j*+1 *· w* = *j*=1

X1X*n* = *⌈q/p⌋· k · xi*+ *uj· en−i*+*j*+ *xj· en−i*+*j*+1*.* *j*=0 *j*=1 12 A distribution *χ* is symmetric if *χ* and *−χ* coincide.

Public-Key Bilinear HSS for Multiples of the Identity from Power Ring-LWE *λ n* Setup(1l*,*1l):

$*λ*

1. *a ← Γ*(1l)
2.Output hk := *a* and mk := *a*. Hash hk = *a, x* : $*λ*
1. *u₀,u₁ ← χ*(1l)
P*n j*+1

2. *d ← u₀* + *a · u₁* +*j*=1*xj · a*
3. *ψ ←* (*d, u, x*)
4.Output *d* and *ψ*. Matrix mk = *a,M* = *k ·* id*n* : $
1. *w ← Rq*
$*λ*

2. *∀j ∈* [0*..*2*n*] : *ej ← χ*(1l)
*j*

3. *∀j ∈* [0*..*2*n*] *\{n* + 1*}* : *Ej ← a · w* + *ej*
*n*+1

4. *En*+1 *← a · w* + *en*+1 + *⌈q/p⌋· k*
5.Output *E* := (*E₀,...,E₂n*) and *ϕ* := *w*. HasherEval hk = *a,E* = (*E₀,...,E₂n*)*,ψ* = (*d, u, x*) :
lP k 1P*n*

1. *∀i ∈* [*n*] : *s₀,i ←j*=0*uj · En−i*+*j* +*j*=1*xj · En−i*+*j*+1
*⌈q/p⌋*

2.Output *s₀* MatrixEval hk = *a,d,ϕ* = *w* :
*n−i*

1. *∀i ∈* [*n*] : *s₁,i ← d · a · w*
*⌈q/p⌋*

2.Output *s₁*
Fig. 11. Public-Key Bilinear HSS for Multiples of the Identity from Power Ring-LWE

In order to complete the proof of correctness, we need to show that the probability that

X *n*

|||z₀ := u₀ · E||+ u₁ · E|x · E|||||
|---|---|---|---|---|---|---|---|---|---|
|||,i|n−i|n−i+1|j n−i+j+1|||||
||||||j=1|||||
||||||p|,i|,i|′0,i||
|′0,i ∞|2 1||,i|n−i|,i i i ∞||′0,i i|i ,i|i|
|,i|,i|p ,i|,i|,i|′0,i|i ,i|i ∞|||

*,i n−i n−i*+1+*j n−i*+*j*+1

is at most (*T* (*λ*) + *p²*)-away from (*ℓ* + 1*/*2) *·⌈q/p⌉* for some *ℓ ∈* Z is negligible. Indeed, when that event does not occur, the correctness of the scheme is guaranteed: suppose that *z₀* = *s₀ ·⌈q/p⌋* + *s* where *∥s ∥ ≤ ⌈q/p⌋*. We know that *z₁* := *d · a · w* = (*s₀ − k · x*) *·⌈q/p⌋* + *s* + *e*e where *e*e is some error term of magnitude ad most *T* (*λ*). We observe that *∥s₀,i− k · x ∥ ≤ p²/*2. We rewrite *s₀ − k · x* as *s₁* + *p · ρ₁* where *s₁,i∈ R*, and we observe that

*z₁* = *s₁ ·⌈q/p⌋* + *ρ₁ ·* (*p ·⌈q/p⌋*) + *s* + *e*e*.*

Furthermore, since *|p ·⌈q/p⌋|≤ p/*2, with overwhelming probability, *∥ρ₁ ·* (*p ·⌈q/p⌋*) + *e*e *∥ ≤ T*(*λ*) + *p²*. Correctness is preserved as long as

*′*<u>1</u> *∥ρ₁,i·* (*p ·⌈q/p⌋*) + *s₀,i*+ *e*e*i∥∞≤ ⌈q/p⌋.* 2

When *z₀,*1is at least (*T* (*λ*) + *p²*)-away from (*ℓ*+ 1*/*2) *·⌈q/p⌋* for every *ℓ ∈* Z*p*, we are sure that the bad event will not occur. Now, we cannot directly argue that *z₀* = (*z₀,*1*,...,z₀,n*) looks random, but we can argue that, if we $*n* sample *u*e *← χ*, the vector *u* + *z₀* looks random under Power Ring-LWE. Indeed, as we are going to show below, *E₀,...,E₂n*are indistinguishable from random. We notice that one of the terms of *z₀,i*+ *u*e*i*is *u*e*i*+*u₀ · En−i*. Under Ring-LWE with lattice distribution given by *Γ* (which is implied by Power Ring-LWE), such elements are indistinguishable from random. This fact, along the property that *p · T/q* is negligible, imply the correctness of the construction. Proving transparent hasher privacy is very simple: all information about *x* contained in *d* is masked by *u₀* + *a · u₁*. Since Power Ring-LWE implies Ring-LWE with respect to lattice distribution *Γ*, the latter is indistinguishable from random. Notice that all the information in hk is already contained in mk. Also matrix privacy is easy to prove: under Power Ring-LWE, the elements *E₀,...,E₂n*are indistinguish- able from random. So they hide all information about *k*. This ends the proof. *⊓⊔*

By applying Theorem 7, we obtain the following corollary.

Corollary 3. *For any integer p, under Power Ring LWE with superpolynomial modulus-to-noise ratio, there* *exists half-chosen, semi-honest, non-interactive VOLE protocol over* *√* Z*pwhere the communication complexity* *is O*( *n*)*.*

## 7 Succinct HSS

In this section, we show how bilinear HSS schemes for multiples of the identity can be used to obtain particularly efficient 2-party HSS schemes for NC₁ circuits where the encoding of some of the inputs can be compressed into small digests. We call such primitive a *succinct HSS scheme*. Specifically, for any NC₁

|m||n|
|---|---|---|
|q||q|
|m|n||
|q|q||

circuit *C* mapping a vector in Z into a vector in Z, a succinct HSS schemes allows two parties Alice and Bob, having inputs *x ∈* Z and *y ∈* Z respectively, to obtain a secret-sharing of the inner product *⟨C*(*x*)*, y⟩* using a single round of interaction where the communication of Bob is independent of *n*. In other words, we obtain 2-party non-interactive protocols for particular classes of functions that achieve sublinear communication in the size of the inputs.

*Special RMS Programs.* In order to explain our idea, we need to first introduce the notion of *special restricted* *multiplication straightline (RMS) program*. We recall that the class of RMS programs over a ring *R* consists of all arithmetical circuits over *R* with fan-in 2, where linear operation are free, but multiplications require at least one of the factors to be an input wire. We also recall that all circuits in NC₁ can be represented as an RMS program of polynomial size [BGI16, Appendix A]. Special RMS programs generalise what we just explained. We will split the input wires into two classes: *standard inputs* and *special inputs*. Linear operations are again free, however, multiplications not only require at least one of the factors to be an input wire, but they also require the latter to be of standard type. The only operations allowed on special inputs are therefore linear gates or multiplications by a standard input. In other words, despite being input wires, special inputs are treated as any other internal wire of the RMS program. The latter are usually referred to as *memory wires*.

Definition 22(Special RMS Program). *A special restricted multiplication straightline program (RMS)* *consists of a bound B ∈* N*, a modulus q ∈* N *such that B ≤ q and an arithmetic circuit C with unbounded* *fan-out where the inputs wires are divided into two classes: standard inputs and special inputs. Furthermore,* *the only allowed gate types are the following:*

– ConvertInput(*Ix*) *→ Mx. Load the value of the standard input wire Ixto the memory wire Mx.* – ConvertSpecialInput(*Sx*) *→ Mx. Load the value of the special input wire Sxto the memory wire Mx.* – Add(*Mx y z x y*

|,M ) → M|. Add the values of the memory wires M|and M|and store the result in the memory||
|---|---|---|---|---|
|x y z x y y|z z|x|y x||
|z||z|||

*wire M.* – Mult(*I,M*) *→ M. Multiply the values of the standard input wire I by the value of the memory wire*

*M. Store the result in the memory wire Mz.*
– Output(*M*) *→ z. Output the value of the memory wire M reducing it modulo q.*

*All inputs must belong to* Z*. If the absolute value of any wire exceeds the bound B, the output of the evaluation* *is ⊥.*

In the following lemma, we prove that if *C* is in NC₁, then the function *⟨C*(*x*)*, y⟩* can be represented as a special RMS program where *y* are special inputs.

Lemma 1. *Let R be a ring and let C be an RMS program over R taking inputs in R* *m* *and outputting in* *R* *n* *. Then, the function f* : *R* *m* *× R* *n* *→ R that maps* (*x, y*) *into ⟨C*(*x*)*, y⟩ is computable by a special RMS* *program C* *′* *where x is the standard input and y is the special input.*

*Proof.* For every *i ∈* [*n*], let *Ci*be the subprogram of *C* that computes the *i*-th element of the output. We consider the program *Ci′*obtained by modifying *Ci*as follows:

– the program starts by loading the special input *yi*into a memory wire, – every addition gate, output gate and multiplication gate are left untouched, – every input conversion gate is substituted by a multiplication of the input by *yi* – every addition of a constant *k ∈ R* is substituted by an addition of *k · yi*.

We claim that *Ci′*computes *yi· Ci*(*x*). Indeed, if a memory wire stored a value *z* during the evaluation of *Ci*(*x*), in the evaluation of *Ci′*, the wire stores *yi· z*. We prove this by induction. If the memory wire is the output of an input conversion gate, our claim is easily verified. Now, consider a multiplication gate. By inductive hypothesis, if in *Ci*the gate computed the product *x · z* where *x* comes from the input wire and *z* from the memory wire, in *Ci′*, we will compute *x ·* (*yi· z*). So our claim holds also for the output wire of the multiplication. Moving on to addition gates, by inductive hypothesis, if in *Ci*the gate computed the sum *z₁* +*z₂*, in *Ci′*, we will compute (*yi· z₁*) + (*yi· z₂*). Again, our claim is verified. Finally, we consider additions by constants. If in *Ci*any of these gates computed the sum *z* + *k* where *z* was the value of a memory wire

|and k a constant, in C||, we will compute (y||· z) + (y|· k). To conclude, we know that C||(x, y) will compute|
|---|---|---|---|---|---|---|---|
|i i||i′||i|i||i′|
|||′||||||
|||||i′||||

*i′ i i i′* *y · C* (*x*). We therefore build *C* by evaluating *C* (*x, y*) for every *i ∈* [*n*] and then adding the results. *⊓⊔*

*Defining succinct HSS.* Below, we formalise the definition of succinct HSS: a 2-party HSS scheme for the evaluation of special RMS programs, where the parties can compress the encodings of their special inputs into small digests. The primitive relies on a setup that takes as input an upper-bound *n* on the number of special inputs that can be hashed into the same digest. In order to evaluate a special RMS program where the number of special inputs exceeds *n*, the parties simply need to send multiple digests.

Definition 23(Succinct HSS). *A succinct HSS scheme over* Z*qis a tuple of PPT algorithms* (Setup*,*Hash*,* Input*,*Eval) *with the following syntax:*

– Setup *is randomised and takes as input the security parameter* 1l *λ* *and the input length* 1l *n* *. The output* *is a public key* pk *and evaluation keys* ek₀ *and* ek₁*.* – Hash *is randomised and takes as input a public key* pk*, b ∈{*0*,*1*} and an input x ∈* Z *n* *. The output is a* *digest d and the hasher secret information ψ.* – Input *is randomised and takes as input a public key* pk *and a value y ∈* Z*. The output is an encoding I* *of the input.* – Eval *is deterministic and takes as input the evaluation key* ek*, the description of a special RMS program*
*f, standard input encodings I₁,...,Im, digests d₁,...,dℓ*0*and hasher secret information ψ₁,...,ψℓ*1*for*
*some m,ℓ₀,ℓ₁ ∈* N*. The output is an element s ∈* Z*q.*

### We require also the following properties

*1. (Correctness). For every n,m,ℓ₀,ℓ₁ ∈* N*, special inputs x⁰*1 *ℓ*

||,..., x⁰|, x¹|,..., x¹|∈ Z, standard input|
|---|---|---|---|---|
||1|ℓ|1|ℓ|
|n·(ℓ +ℓ)|q λ b b i i|n|b i||
|j|j||||
||m|1|0 ℓ|ℓ0|
|1|m 1|0 ℓ|0 1 ℓ|1 ℓ|
||||n||

01 *ℓ*1 *n*

*y ∈* Z *m* *and special RMS program f* : Z *n·*(*ℓ*0 +*ℓ*1) *×* Z *m* *→* Z*, the following probability must be negligible.*

$ (pk*,*ek₀*,*ek₁) *←* Setup(1l*,*1l)  $   *∀b ∈{*0*,*1*},i ∈* [*ℓb*] : (*d ,ψ*) *←* Hash(pk*,b, x*)     $   *∀j ∈* [*m*] : *I ←* Input(pk*,y*)  Pr   *s₀* + *s₁ ̸*= *z*  
 *s₀ ←* Eval(ek₀*,f,I₁,...,I,d¹,...,d¹*
1 *,ψ₁,...,ψ* 0 )    
 *s₁ ←* Eval(ek₁*,f,I₁,...,I,d₁,...,d*0*,ψ₁,...,ψ*1)

*z ← f*(*x⁰,..., x⁰ℓ* 0 *, x¹,..., x¹* 1 *, y*)

*2. (Hasher Privacy). For every n ∈* N*, b ∈{*0*,*1*} and special inputs x₀, x₁ ∈* Z*, the two values i ∈{*0*,*1*}* *are computationally indistinguishable in the following distribution*
( $*λ n* ) (pk*,*ek₀*,*ek₁) *←* Setup(1l*,*1l) (pk*,*ek*b,d*) $ (*d,ψ*) *←* Hash(pk*,*1 *− b, xi*)

*3. (Input Privacy). For every n ∈* N*, b ∈{*0*,*1*} and standard inputs y₀,y₁ ∈* Z*, the two values i ∈{*0*,*1*}* *are computationally indistinguishable in the following distribution*
( $*λ n* ) (pk*,*ek₀*,*ek₁) *←* Setup(1l*,*1l) (pk*,*ek*b,I*) $ *I ←* Input(pk*,yi*)

*4. (Efficiency). The size of the hash d is* poly(*λ,* log*|R|*) *· o*(*n*)*.* We highlight that, in succinct HSS schemes, we can evaluate special RMS programs on standard inputs provided by external entities (in particular, none of the HSS participants needs to know the values hidden in the encodings of these inputs). Special inputs, on the other hand, need to be provided by the participant as the private information used for the generation of the digests is later on needed in the evaluation. Below, we formalise an additional property of succinct HSS schemes: we say that the scheme has pseu- dorandom shares if, as long as both evaluation keys are kept private, the shares produced by the evaluation

look random conditioned on adding up to the correct value. We highlight that any succinct HSS scheme can be easily converted into a succinct HSS scheme with pseudorandom shares by simply augmenting the evaluation keys with a PRF key. We use the latter to rerandomise the shares produced by the evaluation without having to interact.

Definition 24(Pseudorandom Shares). *We say that an succinct HSS scheme* (Setup*,*Hash*,*Input*,*Eval)

||||,..., x⁰|,..., x¹, x¹|
|---|---|---|---|---|
||n·(ℓ +ℓ|) m|1 q|ℓ 1|
||λ n b b||b||
|b|i i||i||
|j|j||||
||1 m|1 0 ℓ|0 ℓ||

*over* Z*qhas pseudorandom shares if, for every n,m,ℓ₀,ℓ₁ ∈* N*, special inputs x⁰* 0 *ℓ*1 *∈* Z *n* *,* *standard input y ∈* Z *m* *and special RMS program f* : Z0 1*×* Z *→* Z*, the following distribution is* *indistinguishable from uniform.*  $    (pk*,*ek₀*,*ek₁) *←* Setup(1l*,*1l)      $ *∀b ∈{*0*,*1*},i ∈* [*ℓ*] : (*d ,ψ*) *←* Hash(pk*,b, x*) *s₀*   *∀j ∈* [*m*] : *I ←* $ Input(pk*,y*)        
*s₀ ←* Eval(ek₀*,f,I₁,...,I,d₁,...,d*
1 *,ψ₁,...,ψ* 0 )

In many applications of succinct HSS, we need to rely on a trusted dealer that generates and distributes the evaluation keys to the parties. This is for instance the case in our sublinear communication MPC protocols for layered circuits. Our goal is however to achieve security in the plain model, so, we need to substitute such trusted setup with another MPC protocol and the latter needs low communication complexity. In particular, we desire the communication to be *O*(*n²*) *·* poly(*λ*) or even *o*(*n*) *·* poly(*λ*), where *n* is the parameter given as input to the setup of succinct HSS.

Definition 25(Setup Tightness and Setup Sublinearity). *We say that a succinct HSS scheme* (Setup*,* Hash*,*Input*,*Eval) *has a tight setup if there exists a semi-honest protocol that implements the functionality* *F*HSS*-*Setup*(see Fig. 12) with O*(*B*) *·*poly(*λ*) *communication complexity, where B denotes the size of the triple* (pk*,*ek₀*,*ek₁)*. We say that the scheme satisfies setup sublinearity if there exists a semi-honest protocol that* *implements the functionality F*HSS*-*Setup*(see Fig. 12) with o*(*n*) *·* poly(*λ*) *communication complexity, where n* *is the parameter given as input to* Setup*.*

The succinct HSS Setup *F*HSS-Setup On input (Init*,n*) from all parties, the functionality performs the following operations:

$*λ n*

1.(pk*,*ek₀*,*ek₁) *←* HSS*.*Setup(1l*,*1l)
2.Provide *P₀* with (pk*,*ek₀) and *P₁* with (pk*,*ek₁).
Fig. 12. The succinct HSS Setup *F*HSS-Setup

7.1 Building Succinct HSS using Bilinear HSS We are ready to explain how we can build succinct HSS schemes: we present a compiler that, using a strongly hasher private bilinear HSS scheme, converts any HSS scheme for RMS programs satisfying particular prop- erties into a succinct HSS scheme. Most known HSS constructions for RMS programs [BGI16,BKS19,OSY21, ADOS22] satisfy the conditions needed for compilation. *Special HSS schemes.* We formalise the properties that the compiler requires from the HSS scheme for RMS programs. We call any construction of this type a *special HSS scheme*. Essentially, an HSS scheme is special if, during the evaluation, every memory wire of the evaluated RMS program is associated with at most an additive secret-sharing of the underlying value *x* and an additive secret-sharing of *k · x* for some private key *k* that can be reconstructed from the evaluation keys. Given any special RMS program *C*, encodings of the standard inputs and secret-sharings of *x* and *k ⊗ x* for every special input *x*, the scheme should allow to evaluate *C* on the inputs without any interaction.

Definition 26(Special HSS). *Let q be a positive integer. A 2-party HSS scheme* (Setup*,*Input*,*Eval) *over* Z*qis special if there exist PPT algorithms* (Key*,*SpecialEval) *with the following syntax:*

– Key *is deterministic and takes as input the evaluation keys* ek₀ *and* ek₁*. The output is a secret key k ∈* Z *tq* *.* –*b, a special RMS program f* : Z *n*

|SpecialEval is deterministic and takes as input an evaluation key ek|||×|
|---|---|---|---|
|m|n||b n q|
|b|q t·n|b q||

Z *m* *→* Z *n* *for some m,n ∈* N *such that f ∈C, standard input encodings I₁,...,Imand values xb∈* Z *n*

*and x*ˆ *∈* Z*. The output is a values s ∈* Z*.*

### We require also the following properties:

– *for every n,m ∈* N*, special RMS program f* : Z *n* *×* Z *m* *→* Z*q, standard input y ∈* Z *m* *, special input* *x ∈* Z *n* *and values x₀ ∈* Z *n* *qand x*ˆ₀ *∈* Z *tq·n* *,*

 $*λ*  (pk*,*ek₀*,*ek₁) *←* Setup(1l)    *k ←* Key(ek₀*,*ek₁)     *x₁ ← x − x₀* mod *q*    Pr *s₀* + *s₁ ̸*= *f* (*x, y*)  *≤* negl(*λ*)  *x*ˆ₁ *← k ⊗ x − x*ˆ₀ mod *q*     $   *∀j ∈* [*m*] : *Ij←* Input(pk*,yj*) 

*∀b ∈{*0*,*1*}* : *sb b m b b*

|← SpecialEval(ek||,f,I₁,...,I|, x|, x ˆ )||
|---|---|---|---|---|---|
|n|m q|||m|n q|
||λ|||||
|j|j|||||
||0 1|m 0|0|||

– *for every n,m ∈* N*, special RMS program f* : Z *×* Z *→* Z*, standard input y ∈* Z *and values x₀ ∈* Z *and x*ˆ₀ *∈* Z *tq·n* *, the following distribution is computationally indistinguishable from uniform.*

    (pk*,*ek₀*,*ek₁) *←* $ Setup(1l)    *s₀ ∀j ∈* [*m*] : *I ←* $ Input(pk*,y*)     *s ←* SpecialEval(ek*,f,I ,...,I, x, x*ˆ) 0

Almost all known HSS constructions for RMS programs satisfy the properties of Def. 26. The only exception is the DDH-based construction of [BGI16], which suffers from a non-negligible correctness error.

Theorem 10( [OSY21, ADOS22, BKS19]). *The following hold:*

– *Under DCR over the Paillier group* Z *∗* *N*2 *, there exists a special 2-party HSS scheme over* Z*N.* – *Under DDH, the hidden subgroup assumption and the small exponent assumption over class groups, there* *exists a special 2-party HSS scheme over* Z*qfor any prime number q* = *O*(2 *λ* )*.* – *Under LWE with superpolynomial modulus-to-noise ratio, there exists a special 2-party HSS scheme over* Z*pfor any p ∈* N*.*

*The succinct HSS compiler.* We finally formalise our compiler. Notice that a special HSS scheme already almost allows evaluating special RMS programs: the only thing that we are missing is a mechanism to non- interactively provide secret-sharings of *k · x* for every special input *x*, without leaking any information about the secret-key *k*. We further desire this mechanism to require sublinear communication in the size of the special inputs. Luckily, bilinear HSS schemes for multiples of the identity give exactly what we need: we generate random vectors *k₀* and *k₁* such that *k₀* +*k₁* = *k*. Then, we encode each entry of *k₀* using the bilinear HSS scheme. We repeat the operation for *k₁*. In this way, we obtain vectors of matrix encodings and corresponding secret information (*E₀, ϕ₀*) and (*E₁, ϕ₁*). We include *E₀* and *E₁* as part of the HSS public key. We include instead *k₀* and *ϕ₀* in the first party’s evaluation key and *k₁* and *ϕ₁* in the second party’s evaluation key. Notice that if the first party now sends a bilinear HSS digest of its special inputs *x*, the players can immediately obtain a secret-sharing of *k₁ ⊗ x*. In order to convert the latter in a secret-sharing of *k · x*, the first party just needs to add *k₀ ⊗ x* to its share.

Theorem 11. *Assume the existence of a 2-party bilinear HSS scheme for the matrix class M⊇K satisfying* *strong hasher privacy. Suppose also a 2-party special HSS scheme, both over* Z*q. Then, there exists a succinct* *HSS scheme over* Z*qwith pseudorandom shares.* *Moreover, if the bilinear HSS scheme satisfies transparent hasher privacy, the succinct HSS scheme has* *a tight setup. If the bilinear HSS scheme satisfies transparent hasher privacy, key-compactness and matrix-* *compactness, the succinct HSS scheme has a sublinear setup.*

*Proof.* Let BHSS := (Setup*,*Hash*,*Matrix*,*HasherEval*,*MatrixEval) be the bilinear HSS scheme and let HSS := (Setup*,*Input*,*Eval*,*Key*,*SpecialEval) be the special HSS scheme. The succinct HSS scheme is described in

Fig. 13.

succinct HSS Scheme Let *L₁*(*λ,n*) and *L₂*(*λ,n*) be the length of the randomness needed by BHSS*.*Setup and BHSS*.*Matrix.

Setup(1l *λ* *,*1l *n* )

*′ ′ ′*$*λ*

1.(pk*,*ek₀*,*ek₁) *←* HSS*.*Setup(1l)
2. *k ←* HSS*.*Key(ek
*′* 0 *,*ek *′* 1 ) $*tq*

3. *k₀ ←* Z
4. *k₁ ← k − k₀*
$*L*1(*λ,n*)

5. *∀b ∈{*0*,*1*}* : *rb←{*0*,*1*}*
$*L*2(*λ,n*)

6. *∀j ∈* [*t*]*,b ∈{*0*,*1*}* : *rb,j←{*0*,*1*}*
7. *∀b ∈{*0*,*1*}* : (hk*b,*mk*b*) *←* BHSS*.*Setup(1l
*λ* *,*1l *n*; *rb*)

8. *∀j ∈* [*t*]*,b ∈{*0*,*1*}* : (*Eb,j,ϕb,j*) *←* BHSS*.*Matrix(mk*b,kb,j*; *rb,j*)
9. pk *←* (pk *′*
*,*hk₀*,*hk₁*,E₀,*1*,...,E₀,t,E₁,*1*,...,E₁,t*)

10. *∀b ∈{*0*,*1*}* : ek*b←* (*b, kb, rb, rb,*1*,..., rb,t,*ek
*′b* *,ϕb,*1*,...,ϕb,t,*mk*b*)

11.Output pk, ek₀ and ek₁. Hash(pk = (pk
*′* *,*hk₀*,*hk₁*,* (*E₀,j,E₁,j*)*j∈*[*t*])*,b, x*)

1.(*d, ψ*b) *←* BHSS*.*Hash(hk₁*−b, x*)
2.Output *d* and *ψ* := (*x, ψ*b) Input(pk = (pk
*′* *,*hk₀*,*hk₁*,* (*E₀,j,E₁,j*)*j∈*[*t*])*,y*)

1.Output HSS*.*Input(pk
*′* *,y*)

Eval ek*,f,I₁,...,Im,d¹*1 *−b* *,...,d¹ℓ* 1 *−−bb* *,ψ₁* *b* *,...,ψℓbb*

1.rewrite ek as (*b, kb, rb, rb,*1*,..., rb,t,*ek
*′b* *,ϕb,*1*,...,ϕb,t,*mk*b*)

2. *∀i ∈* [*ℓb*], rewrite *ψib*as (*x*
*b* *i* *, ψ*b*ib*)

3. *∀i ∈* [*ℓb*] : *x*
*b* *i,b← x* *b* *i*

4. *∀i ∈* [*ℓ₁−b*] : *xi,b*
1*−b* *←* 0

5. *∀i ∈* [*ℓb*]*,j ∈* [*t*] : *x*ˆ
*b* *i,b*[*j*] *← kb,j· x* *b* *i*+ BHSS*.*HasherEval(hk₁*−b,E₁−b,j, ψ* b *ib* )

6. *∀i ∈* [*ℓ₁−b*]*,j ∈* [*t*] : *x*ˆ¹*i,b*
*−b* [*j*] *←−*BHSS*.*MatrixEval(mk*b,d¹i −b,ϕb,j*)

7. *∀i ∈* [*ℓb*] : *x*ˆ
*b* *i,b←* (*x*ˆ *b* *i,b*[1]*,..., x*ˆ *b* *i,b*[*t*])

8. *∀i ∈* [*ℓ₁−b*] : *x*ˆ*i,b*
1*−b* *←* (*x*ˆ¹*i,b* *−b* [1]*,..., x*ˆ¹*i,b* *−b* [*t*])

9. *x*ˆ*b←* (*x*ˆ⁰1*,b,..., x*ˆ⁰*ℓ*0*,b, x*ˆ¹1*,b,..., x*ˆ¹*ℓ*1*,b*)
10. *xb←* (*x⁰*1*,b,..., x⁰ℓ*0*,b, x¹*1*,b,..., x¹ℓ*1*,b*)
11. *sb←* HSS*.*SpecialEval(ek
*′b* *,f,I₁,...,Im, xb, x*ˆ*b*)

12.Output *sb*.
Fig. 13. succinct HSS Scheme

We prove our claim starting from correctness. By the correctness of BHSS, we have that, for every *i ∈* [*ℓ₀*] and *j ∈* [*t*],

### xˆ⁰i,0[j] + xˆ⁰i,1[j] = k

|· x⁰ + BHSS.HasherEval(hk₁,E₁|||, ψb )|
|---|---|---|---|
|j,0 i|||,j i0|
|||i ,j||
|j,0 i|j,1 i|j i||

### − BHSS.MatrixEval(mk₁,d⁰,ϕ₁)

= *k · x⁰* + *k · x⁰* = *k · x⁰.*

In an analogous way, we have that for every *i ∈* [*ℓ₁*] and *j ∈* [*t*],

### xˆ¹i,0[j] + xˆ¹i,1[j] = k

|· x¹|+ BHSS.HasherEval(hk₀,E₀|||, ψb )|
|---|---|---|---|---|
|j,1 i||i|,j|,j i1|
|j,1 i|j,0 1|i j ℓ 1|i ℓ||

### − BHSS.MatrixEval(mk₀,d¹,ϕ₀)

= *k · x¹* + *k · x¹* = *k · x¹.*

In other words, *x*ˆ₀ + *x*ˆ₁ = *k ⊗* (*x₀* + *x₁*) = *k ⊗* (*x⁰,..., x⁰* 0 *, x¹,..., x¹* 1 ). We conclude by relying on the correctness of the special HSS scheme HSS. The pseudorandomness of the shares is immediately implied by the second property of special HSS schemes. Hasher privacy is immediately implied by the strong hasher privacy of BHSS. Finally, we prove input privacy. Consider any *b ∈{*0*,*1*}*. We rely on a sequence of indistinguishable hybrids to prove that no PPT adversary can distinguish Input(pk*,y₀*) from Input(pk*,y₁*) even when provided with pk and ek*b*. Hybrid 0. In this hybrid, we generate pk, ek₀ and ek₁ using Setup(1l *λ* *,*1l *n* ). Hybrid 1. In this hybrid, we change the distribution of *E₁−b,j*for every *j ∈* [*t*]: instead of computing BHSS*.*Matrix(mk₁*−b,k₁−b,j*), we generate *E₁−b,j*by running BHSS*.*Matrix(mk₁*−b,*0). This hybrid is indis- tinguishable from the previous one due to the matrix privacy of BHSS. Observe that pk and ek*b*are now independent of *k₁−b*. Hybrid 2. In this hybrid, instead of providing the adversary with Input(pk*,y₀*) or Input(pk*,y₁*), we provide it with the output of Input(pk*,*0). Finally, we show that if the bilinear HSS scheme is key-compact and matrix-compact, the succinct HSS scheme satisfies setup sublinearity. We start by observing that there exists a semi-honest protocol *Π*SpecialHSS-Setupthat implements the functionality *F*SpecialHSS-Setupin Fig. 14 with poly(*λ*) communication.

|Our succinct HSS setup protocol will start by executing Π|||||||. In this way, each party P|||obtains|
|---|---|---|---|---|---|---|---|---|---|---|
|′ ′b|b||b|b|L₁(λ,n)|b,j|L₂(λ,n)||||
|||b b,1|b,j b,j|b b b,j||λ n b b,j|b b,j −b|−b,1|−b,j||
||||b||′|,1|,t ,1|,t|b|b b|
||′b||||||||||
|b,1|b,t HSS-Setup|b,1|b,t b||||||||

SpecialHSS-Setup *b* *′ ′b*$*L₁*(*λ,n*)$*L₂*(*λ,n*) (pk*,*ek*, kb*). Subsequently, *Pb*samples *rb←{*0*,*1*}* and *rb,j←{*0*,*1*}* for every *j ∈* [*t*]. It then computes (hk*,*mk) *←* BHSS*.*Setup(1l*,*1l; *r*)

and, for every *j ∈* [*t*], (*E,ϕ*) *←* BHSS*.*Matrix(mk*,k*; *r*)*.*

Finally, it sends (hk*,E,...,E*) to the other party. After receiving, (hk₁*,E₁,...,E₁*) from the
other participant, party *P* outputs pk := (pk*,*hk₀*,*hk₁*,E₀,...,E₀,E₁,...,E₁*) and ek := (*b, k, r,*
*r,..., r,*ek*,ϕ,...,ϕ,*mk). We observe that, thanks to transparent hasher privacy, this protocol
implements *F* (see Fig. 12) and the communication complexity is *O*(*B*) *·* poly(*λ*). Moreover, if the bilinear HSS scheme is key-compact and matrix-compact, the communication complexity is poly(*λ*) + *o*(*n*) *·* poly(*λ,* log*q*) + *t · o*(*n*) *·* poly(*λ,* log*q*). Since *t* and log*q* are polynomial in *λ*, our claim follows. This ends the proof. *⊓⊔*

The following corollary summarises all known succinct HSS constructions.

### Corollary 4. The following hold:

– *Under DCR over the Paillier group* Z *∗* *N*2 *, there exists a succinct HSS scheme over* Z*Nwith pseudorandom* *shares and setup sublinearity where the public key size, evaluation key size and the hash size is O*(*n²* */*3 ) *·* poly(*λ*)*. If we additionally assume Power-DDH over* Z *∗* *N*2 *, there exists a succinct HSS scheme with* *pseudorandom shares and setup sublinearity where the public key size, evaluation key size and the hash* *√* *size is O*( *n*) *·* poly(*λ*)*.*

The functionality *F*SpecialHSS-Setup The functionality computes the following operations:

*′ ′ ′*$*λ*

1.(pk*,*ek₀*,*ek₁) *←* HSS*.*Setup(1l)
2. *k ←* HSS*.*Key(ek
*′* 0 *,*ek *′* 1 ) $*tq*

3. *k₀ ←* Z
4. *k₁ ← k − k₀*
5.Provide *P₀* with (pk
*′* *,*ek *′* 0 *, k₀*), provide *P₁* with (pk *′* *,*ek *′* 1 *, k₁*).

Fig. 14. The functionality *F*SpecialHSS-Setup

– *For any prime q* = *Ω*(2 *λ* )*, under DDH, the hidden subgroup assumption, the small exponent assumption,* *the n¹* */*3 *-ary EDDH assumption and the uniformity assumption over class groups, there exists a succinct* *HSS scheme over* Z*qwith pseudorandom shares and setup sublinearity where the public key size, evalu-* *ation key size and the hash size is O*(*n²* */*3 ) *·* poly(*λ*)*. If we additionally assume Power-DDH over class* *groups, there exists a succinct HSS scheme with pseudorandom shares and setup sublinearity where the* *√* *public key size, evaluation key size and the hash size is O*( *n*) *·* poly(*λ*)*.* – *For any integer p, under LWE with superpolynomial modulus-to-noise ratio, there exists a succinct HSS* *scheme over* Z*pwith pseudorandom shares and setup sublinearity where the evaluation key size and the* *hash size is O*(*n²* */*3 ) *·* poly(*λ*)*. Furthermore, under Power Ring-LWE with superpolynomial modulus-to-* *noise ratio, there exists a succinct HSS scheme over* Z *√* *pwith pseudorandom shares and setup sublinearity* *where the evaluation key size and the hash size is O*( *n*) *·* poly(*λ*)*.*

On Succinct HSS over Z₂. Any 2-party succinct HSS scheme with pseudorandom shares over Z*q*, where *q* is superpolynomial in the security parameter can be easily converted into a succinct HSS scheme with pseudorandom shares over Z₂. The conversion comes at no additional cost. In order to evaluate a binary circuit, we just evaluate it modulo *q*. At the end, both parties reduce their shares modulo 2 and, if *q* is odd, the first party also flips its value. The reason why this trick works is that *q* is sufficiently large to not create any wrap-arounds during the evaluation of the circuit. Indeed, since RMS programs required that at least one of the inputs of every multiplication gate is actually an input to the whole circuit (and the latter is necessarily a bit), multiplications do not increase the magnitude of the values in the internal wires. Also, since the RMS program is over Z₂, all linear operations correspond to additions of subsets of wires (multiplying by a constant over Z₂ is either a multiplication by 1 or by 0). In conclusion, during the evaluation, the maximum value that a wire can assume is the size of the program, which is polynomial in *λ*. We conclude that, at the end of the evaluation, the parties obtain an additive secret-sharing modulo *q* of a value 0 *≤ y < q* such that *|y|≤* poly(*λ*). The output of the evaluation of the program over Z₂ corresponds to *y* mod 2. Let 0 *≤ y₀,y₁ < q* be the two shares. Since the succinct HSS scheme has pseudorandom shares and *q* is superpolynomial, the probability that *y₀ < y* is negligible. Therefore, with overwhelming probability, we have that *y₀* +*y₁* = *q* + *y*, where the addition is here performed over the integers. By reducing both sides modulo 2, we obtain that

(*y₀* mod 2) *⊕* (*y₁* mod 2) = (*y* mod 2) *⊕* (*q* mod 2)*.*

### This is exactly what we wanted.

## 8 Multiparty Distributed Point Function

We now show how 2-party succinct HSS can be used to build an *N*-party DPF for any *N* = poly(*λ*). We do this by presenting a semi-honest protocol that allows *N* parties holding additive secret-sharings of the bits of

*α ∈* [*n*] and a multiplicative secret sharing of *β ∈* Z *∗* *q*, to obtain an additive secret sharing of the unit vector

(0*,...,*<u>0,β</u>*,*0*,...,*0) *∈* Z
*n* *q* | {z} *α*

with *o*(*n*) communication. It is easy to observe that such protocol leads immediately to an *N*-party DPF construction: in order to generate the DPF keys for a unit vector with special position *α ∈* [2 *n*] and non-zero value *β ∈* Z *∗* *q*, we run the protocol on input a random additive secret-sharing of the bits of *α* and a random multiplicative secret-sharing of *β*. The DPF key of any party *Pi*will consist of *Pi*’s view in the protocol execution. The idea behind the protocol is rather simple: we rely on a trusted setup that provides each pair of parties with the evaluation keys of a different 2-party succinct HSS instance. The execution will be started by party *P₁*, which will define the vector *s₁,*2as the unit vector *uα*1*,β*1having special position *α₁* (i.e. *P₁*’s share of *α*) and non-zero value *β₁* (i.e. *P₁*’s multiplicative share of *β*). We then enter a loop whose iterations are indexed by *j* = 2*,...,N*. Each party *Pi*will participate in the protocol only in the iterations indexed by *j ≥ i*. In particular, party *P₁* will be involved in all iterations, while party *PN*only in the last one. In the iteration indexed by *j*, each party *Pi*with *i < j* will obtain a 2 *n* vector *si,j*+1*∈* Z*q*. We will satisfy the invariant

X *j* *si,j*+1= *uα′j,β* *j* *′* (1) *i*=1 L*j*Q*j* where *αj′*:=*i*=1*αi*and *βj′*:=*i*=1*βi*. In the iteration indexed by *j*, party *Pj*will input the bits of *αj*(i.e. *Pj*’s share of *α*) and *βj*(i.e. *Pj*’s multiplicative share of *β*) in all succinct HSS execution where, on the other end, there is a party *Pi*with *i < j*. On the other side, *Pi*will send a digest of the vector *si,j*. Then, *Pi*and *Pj*will evaluate a special RMS program that multiplies all the entries of *si,j*by *βj*and shuffles them according to *αj*(i.e., entry *x* will be moved to entry *x ⊕ αj*). The share of the output obtained by party *Pi*will be the vector *si,j*+1. Party *Pj*will instead obtain *sj,j*+1by adding the shares it obtained in the *j* succinct HSS executions. It is easy to see that the invariant (1) is preserved. So, at the end of the protocol, the vectors *si,N*+1will consist of secret-sharing of the desired unit-vector.

Theorem 12. *Let* HSS = (Setup*,*Hash*,*Input*,*Eval) *be a succinct HSS scheme over* Z*qand let F be a PRF.* *Then, the protocol in Fig. 15 UC-implements the functionality F*DPF*(see Fig. 16) in the F*HSS*-*Setup*-hybrid* *model (see Fig. 12) against static, semi-honest adversaries corrupting up to N −* 1 *parties.* *Furthermore, consider the algorithm pair* DPF = (Gen*,*Eval) *where*

||||k||q|||N|
|---|---|---|---|---|---|---|---|---|
|i|||i||DPF||j j|j∈[N]|
|N||N|||||||
|j=1|j|j=1 j i|∗ 14|k i,N +1 k||DPF|i||
||||q||||||

– Gen *takes as input α ∈ {*0*,*1*} where k <* log *n and β ∈* Z *and outputs keys κ₁,...,κ such that* *κ consists of the view¹³ of party P in the protocol Π on input random* (*α,β*) *such that* L Q *α* = *α and β* = *β.* – Eval *takes as input a key κ and an index ℓ ∈* [2]*. It reruns Π from P ’s perspective using the* *transcript in κiand outputs the ℓ-th entry of s.*

*Then,* DPF *is an N -party DPF over* Z *with domain* [2] *having key size N · k ·*poly(*λ,* log*q*) +*O*(*N*) *·* (*t₀*+ *t₁* + *t₂*)*, where t₀*(*λ,n*)*, t₁*(*λ,n*) *and t₂*(*λ,n*) *are the public key size, the evaluation key size and the digest* *size of* HSS*, respectively.*

*Proof.* We start by proving correctness. We claim that, for every *j ∈* [*N*], we have

X *j* *si,j*+1= *uα′j,β* *j* *′* *i*=1 13 The view of party *Pi* consists of *Ki*, *αi*, *βi*, (pk*,*ek*i,j*)*j>i* and (pk*,*ek*j,i*)*j<i* and the messages received by *Pi* in *i,j i,j* *Π*DPF. 14 The construction guarantees the secrecy of *β* as long as it belongs to Z *∗*. The privacy of *α* is always guaranteed. *q*

The *N*-Party DPF Protocol *Π*DPF *i,j* For every *{i,j}⊆* [*N*], let *F*HSS-Setupbe a copy of *F*HSS-Setupto which only *Pi* and *Pj* have access.

Initialisation: On input (Init*,n*), each party *Pi* performs the following operations: *i,j*

1.for every *j ̸*= *i*, send (Init*,n*) to *F*HSS-Setup. Receive (pk*i,j,*ek*i,j*) (if *i < j*) or (pk*i,j,*ek*j,i*) (if *i > j*) as an answer (*Pj* will obtain the other half of the key). $*λ*
2. *Ki←{*0*,*1*}*. Input: On input (Input*,*id*,x*), party *Pi* performs the following operations:
1. *rj← F*(*Ki,*(id*,j*)) id
2. *∀j < i* : *Ij←* HSS*.*Input(pk*i,j,x*; *rj*)
3.Send (id*,Ij*) to party *Pj* for every *j < i*.
4.Store *x,*(*Ij*)*j<i* under the identity id. DPF: On input (DPF*,*(id*j,*0*,*id*j,*1*,...,* id*j,k*)*j∈*[*N*]) from the environment, for some *k ≤* log*n*, the parties performs the following operations:
0

1.For every *i ∈* [*N*], *Pi* retrieves the values *βi* and (*Ij,i*)*j<i* it stored under the identity id*i,*0. For every
*b* *b ∈* [*k*], *Pi* also retrieves the values *αi,b*and (*Ij,i*)*j<i* it stored under the identity id*i,b*. Finally, it sets *αi*:= (*αi,*1*,...,αi,k*). *b*

2.For every *j < i*, and *b ∈* [0*..k*], *Pi* retrieves the value *Ii,j*it received from *Pj* under the identity id*j,b*.
3. *P₁* sets *s₁,*2 *← uα*1*,β*1
4.for *j* = 2*,...,N*: – each *Pi* such that *i < j* computes:
(a) *ri,j← F Ki,* (*j,* (id*ℓ,*0*,*id*ℓ,*1*,...,* id*ℓ,k*)*ℓ∈*[*N*])
(b)(*di,j,ψi,j*) *←* HSS*.*Hash(pk*i,j,*0*, si,j*; *ri,j*)
(c)Send *di,j* to *Pj*
1 *k* 0

(d) *si,j*+1*←* HSS*.*Eval(ek*i,j,fk,Ii,j,...,Ii,j,Ii,j,ψi,j*) (see below)
– *Pj* computes:

(a)Receive *di,j* from *Pi* for every *i < j*
P*j−*1 1 *k* 0

(b) *∀i < j* : *sj,j*+1*←i*=1HSS*.*Eval(ek*j,i,fk,Ii,j,...,Ii,j,Ii,j,di,j*) (see below)
5.Each party *Pi* outputs *si,N*+1
The Special RMS Program *fk* *k* Special Input: an 2-dimensional vector *v* Standard Input: bits *α₁,...,αk*and an element *β ∈* Z

1. *v₀ ← v*
2.For *i* = 1*,...,k*:
*k k−i*

(a) *∀j ∈* [0*..*2 *−* 1] : *vi*[*j*] *← vi−*1[*j*] + *αi ·* (*vi−*1[*j ⊕* 2] *− vi−*1[*j*]) *k*
3. *∀j ∈* [0*..*2 *−* 1] : *w*[*j*] *← vk*[*j*] *· β*
4.Output *w*
Fig. 15. The *N*-Party DPF Protocol

The *N*-Party DPF Functionality *F*DPF Initialisation: On input (Init*,n*) from each party, the functionality activates and stores *n*. Subsequent calls to this procedure are ignored. Let *ι* denote the index of a fixed honest party. Input: On input (Input*,*id*,x*) from a party *Pi* where *x ∈* Z*q*, store *x* under the identity id. DPF: On input (DPF*,*(id*j,*0*,*id*j,*1*,...,* id*j,k*)*j∈*[*N*]) from each party *Pi* for some *k ≤* log*n*, the functionality performs the following operations:

1.For every *i ∈* [*N*], retrieve the value *βi* stored under the identity id*i,*0.
2.For every L
*i ∈* [*N*] and *b ∈* [*k*], retrieve the value *αi,b*stored under the identity id*i,b*. Let *αi*:= (*αi,*1*,...,αi,k*).

3. *α ←* *N* *i*=1*αi* Q*N*
4. *β ←i*=1*βi*
2 *k*

5.Receive *si∈* Z*q*from the adversary for every corrupted party *Pi*
$2*k*

6.For every honest party
P *Pi* with *i ̸*= *ι*, *si←* Z*q*

7. *sι ← uα,β−i̸*=*ιsi*.
8.Output *si*to every party *Pi*.
Fig. 16. The *N*-Party DPF Functionality *F*DPF
 *′j* L*j*Q*j*
where *α* :=*i*=1*αi*and *βj′*=*i*=1*βi*. The claim is clearly true for *j* = 1. We prove by induction that if the claim is true for *j −* 1, then the claim is true also for *j*. We observe that, by the correctness of HSS, we have

X *j* X *j−*1 *si,j*+1= *si,j*+1+ *sj,j*+1 *i*=1 *i*=1 X *j−*1 = HSS*.*Eval(ek*i,j,fk,Ii,j* 1 *,...,Ii,j* *k* *,Ii,j* 0 *,ψi,j*) *i*=1 X *j−*1 + HSS*.*Eval(ek*j,i,fk,Ii,j* 1 *,...,Ii,j* *k* *,Ii,j* 0 *,di,j*) *i*=1 X *j−*1 = *fk*(*si,j,αj* 1 *,...,αjk,βj*) *i*=1

We also observe that *fk*is linear in the first entry (it only permutes the entries of the vector and multiplies all of them by the same element). So,

|j|j−1||||
|---|---|---|---|---|
|i,j+1|k|i,j j1|jk j||
|i=1|i=1||||
||j−1 k|i,j j1|jk j||
||i=1 k α|,β j1|jk j|α ,β|

X X *s* = *f* (*s,α,...,α,β*)

X !

### = f s,α,...,α,β

= *f u ′j−* 1 *j* *′ −* 1 *,α,...,α,β* = *u ′j* *j* *′* *.*

Next, we prove security. We consider the simulator *S* that just runs the protocol using dummy inputs for the honest parties, forwarding the inputs of the corrupted players to *F*DPFand sends *si,N*+1to *F*DPFfor every corrupted party *Pi*. We show that no semi-honest adversary can distinguish between real world and ideal world using a sequence of indistinguishable hybrids. Hybrid 0. This hybrid corresponds to the real world. P Hybrid 1. In this hybrid, we fix an honest party *Pι*. We compute the output of *Pι*as *uα,β−i̸*=*ιsi,N*+1. By the correctness of the protocol, this hybrid is indistinguishable from the previous one.

Hybrid 2. In this hybrid, for every honest party *Pi*, we do not evaluate *F* on input *Ki*anymore. We instead sample the outputs at random. This hybrid is indistinguishable from the previous one due to the security of the PRF. Hybrid 3. In this hybrid, for every honest party *Pi*, instead of inputting *αi* 1 *,...,αik*and *βi*in the succinct HSS scheme with any other party *Pj*, we input 0. This hybrid is indistinguishable from the previous one due to the input privacy of succinct HSS. Hybrid 4. In this hybrid, for every honest party *Pi*, instead of hashing *si,j*for every *j*, we hash 0. This hybrid is indistinguishable from the previous one thanks to the hasher privacy of the succinct HSS scheme. Hybrid 5. This hybrid corresponds to the ideal world. What changed compared to Hybrid 3 is that the shares of the honest parties are now random conditioned on adding up to the right unit vector. This hybrid is indistinguishable from the previous one thanks to the fact that our succinct HSS scheme has pseudorandom shares. The fact that DPF = (Gen*,*Eval) is a DPF is an immediate consequence of the security of the protocol. This ends the proof. *⊓⊔*

8.1 Sublinear Communication *N*-party Computation from *N*-party Distributed Point Functions In this subsection, we show how our *N*-party DPF can be used to build *N*-party computation protocols for layered circuits achieving sublinear communication in the circuit size. We recall that layered circuits are boolean circuits where the nodes of the underlying graph can be partition into subsets *L₁,...,Ld*called layers and each wire of the circuit goes from a gate in some layer *Li*to a gate in the layer *Li*+1. The width of the layer coincides with its cardinality. The number of layers is called the depth of the circuit. We achieve our result following the blueprint of Couteau [Cou19], who showed how to build sublinear communication MPC in the correlated randomness model. We recall his main result below. Theorem 13( [Cou19]). *Assume the existence of authenticated point-to-point channels. For any N -party* *functionality F represented by a layered boolean circuit C of size s with k inputs and m outputs, there exists* *a protocol that perfectly realises F against semi-honest adversaries corrupting up to N −* 1 *parties in the* *F*Prep*-hybrid model (see Fig. 17) with O*(*k* + *N ·* (*m* + *s/* log log*s*)) *communication, polynomial storage and* *needing a single call to F*Prep*.* To obtain our sublinear communication MPC protocol, we just need to implement the functionality *F*Prepwith sublinear communication in the size of the evaluated circuit. We observe that *F*Prepis essentially generating *B* one-time-truth-tables [IKM
+ 13], one for each block of the circuit. We recall that a one-time-

|m|||
|---|---|---|
|jr|j|j|
||||S ||

truth-table for a function *f* : *{*0*,*1*}* *n* *→{*0*,*1*}* *m* consists of a secret sharing of a random shift *r ∈{*0*,*1*}* *n*

and a secret-sharing of the truth table of *f* (*x*) := *f* (*x ⊕ r*[*Sj*]) for every *j ∈* [*m*]. Here, *S* consists of the subset of input bits upon which the *j*-th output bit of *f* may depend. The function *fj*: *{*0*,*1*}j→{*0*,*1*}* computes the *j*-th output bit of *f*. We observe that *N*-party DPFs can be used to easily generate *N*-party one-time-truth-tables for any *O*(log*λ*)-local function *f* : *{*0*,*1*}* *n* *→{*0*,*1*}* *m* (i.e. any function for which each output bit depends on at most *O*(log*λ*) input bits). The idea is the following: the parties pick the secret-sharing of a random *r ∈{*0*,*1*}* *n*. Then, for every *j ∈* [*m*], they use the DPF protocol to generate the secret-sharing of the unit-vector with special position *r*[*Sj*] and non-zero value equal to 1. The latter can be easily converted in a secret-sharing of the truth-table of *fjr*: suppose that the secret-shared unit-vector J*vj*K, the parties just need to output the truth table of the function X q y *f* *js· vj*[*s*] *s∈{*0*,*1*}n* P The issue of this approach is that, in order to implement *F*Prep, we would need*ℓ∈*[0*..B*]*w*ˆ*ℓ∼ s/* log log*s* executions of the DPF. Each of these executions requires at least poly(*λ*) communication. The total com- munication would therefore be roughly *s/* log log *s ·* poly(*λ*) = *Ω*(*s*) (indeed, since *s* = poly(*λ*), log log*s* = *O*(log log*λ*)).

The Preprocessing Functionality *F*Prep Let *d* denote the depth of *C*. Split *C* into *⌈d/u⌉* blocks, where *u* := 2 <u>1</u> log log*s* *a*, as in [Cou19, Section 4.1]: let *L* P *i* denote the *i*-th layer of the circuit *C* and let *wi* be its width. We consider a value *t ∈* [0*..u −* 1] such that *B* *w ≤⌈s/u⌉* where *B* is max*{j|j · u* + *t ≤ d}*. Such *t* exists [Cou19]. For every such *j*, let *L*ˆ denote *j*=0 *j·u*+*t j* layer *Lj·u*+*t*, let *w*ˆ*j* denote its width. For every *ℓ ∈* [0*..B*] and *j ∈* [ ˆ*wℓ*], let *Cℓ,j*be the minimal subcircuit of *C* that computes the *j*-th gate of *L*ˆ*ℓ*given only values of input gates and gates in layer S *L* ˆ *ℓ−*1. Let *Sℓ,j*denote the subset of gates that are input in *Cℓ,j*. Let *Sℓ*:=*jSℓ,j*, *kℓ*:= *|Sℓ|* and *kℓ,j*:= *|Sℓ,j|*.

Initialisation: On input Init from all parties, the functionality activates. Let *ι* be the index of a fixed honest party. One-Time-Truth-Table: On input (OTTT*,*id) from all parties, the functionality performs the following oper- ations for every *ℓ ∈* [0*..B*]:

1.Receive (*ri, Ti*
1 *,..., Tiw* ˆ *ℓ* ) for every corrupted party *Pi* from the adversary. $*kℓ*

2.For every honest L
*Pi*, sample *ri←{*0*,*1*}*

3. *r ←* *N* *i*=1*ri*
4. *∀j ∈* [ ˆ*wℓ*] : *T*
*j* *← Cℓ,j*0 *⊕ r*[*Sℓ,j*]*,Cℓ,j*1 *⊕ r*[*Sℓ,j*]*,...,Cℓ,j*(2 *kℓ,j* *−* 1) *⊕ r*[*Sℓ,j*] $2*kℓ,j*

5.For every honest *Pi*, *i ̸*= *ι* and *j ∈* [ ˆ*wℓ*] : *Tij←{*0*,*1*}*
*j*L

6. *∀ℓ ∈* [ ˆ*wi*] : *Tιj← T ⊕i̸*=*ιTij*
7.Output (*ri, Ti*
1 *,..., Tiw* ˆ *ℓ* ) to every party *Pi*.

*a* In order for our techniques to work, we need *u* := *c ·* log log*s* for any constant 0 *< c <* 1.

Fig. 17. The Preprocessing Functionality *F*Prep

To work around this issue, we modify the construction in Fig. 15: we use succinct HSS to simultaneously run all the DPF instances corresponding to the same block of the circuit. In particular, at the beginning, each party *Pi*will input a key *Ki*for a PRF in NC₁. Such PRF will be used to generate, for every *ℓ ∈* [0*..B*], the share of the shift *ri∈{*0*,*1*}* *k* *ℓ*. Notice that the strings *r₁,..., rN*uniquely determine the special positions of the DPFs. In other words, since the non-zero elements are all equal to 1, the parties do not need to provide any additional standard HSS input, the only communication will consist of the hashes of the special HSS inputs. Since, for every *ℓ ∈* [0*..B*], we are running *w*ˆ*ℓ*DPF executions simultaneously, we do not need to send *w*ˆ*ℓ*digests: we can concatenate all the *w*ˆ*ℓ*special inputs and we send a single digest. In this way the total communication of the protocol will be sublinear in *s*.

Theorem 14. *Let* HSS = (Setup*,*Hash*,*Input*,*Eval) *be a 2-party succinct HSS and let F be a PRF in* NC₁*.* *Let F* *′* *be another PRF. Assume the existence of authenticated point-to-point private channels. The protocol* *Π*Prep*(see Fig. 18) UC-implements the functionality F*Prep*(see Fig. 17) in the F*HSS*-*Setup*-hybrid model (see*

*Fig. 12) against static, semi-honest adversaries corrupting up to N −* 1 *parties.*

*The average communication per channel of the protocol is O*(*λ · t₀*(*λ*) + *B · t₁*(*λ,n*)) *where t₀*(*λ*) *and* *t₁*(*λ,n*) *denote the size of the succinct HSS input messages and digests respectively.*

*Proof.* We start by showing correctness of the correlation. Consider the execution for any L L *ℓ ∈* [0*..B*]. We define *rj′*:=*i≤jri*and *r* :=*i∈*[*N*]*ri*. We claim that, for every *j ∈* [*N*] and *h ∈* [ ˆ*wℓ*],

X *j* *s* *h* *i,j*+1= *urj* *′* [*Sℓ,h*]*,*1 *i*=1

P The Preprocessing Protocol P*w*ˆ=1 *ℓ kℓ,h* *Π*Prep *′* Let *n* be (*ℓ∈*[0*..B*]*τℓ*)*/*(*B* + 1) where *τℓ*:=*h*2. Let *F* be a PRF in NC₁, let *F* be another PRF. For every *ℓ ∈* [0*..B*] and identity id, let *g*id *ℓ* be the special RMS program described in Fig. 19. For every *{i,j}⊆* [*N*], let *F*HSS *i,j* -Setupbe a copy of *F*HSS-Setupto which only *Pi* and *Pj* have access. Initialisation: On input Init, each party *Pi* performs the following operations

1.for every *j ̸*= *i*, send (Init*,n*) to *F*HSS
*i,j* -Setup. Receive (pk*i,j,*ek*i,j*) (if *i < j*) or (pk*i,j,*ek*j,i*) (if *i > j*) as an answer (*Pj* will receive the other half of the key). $*λ*

2. *Ki←{*0*,*1*}*
$*λ*

3. *∀j < i* : *Ki,j←{*0*,*1*}*
$

4. *∀j < i,t ∈* [*λ*] : *Ii,j*[*t*] *←* HSS*.*Input(pk*i,j, Ki*[*t*])
5.Send (*Ii,j*[1]*,...,Ii,j*[*λ*]*, Ki,j*) to party *Pj* for every *j < i*
6.Receive (*Ij,i*[1]*,...,Ij,i*[*λ*]*, Kj,i*) from party *Pj* for every *j > i*. One-Time-Truth-Table: On input (OTTT*,*id) from the environment, the parties perform the following oper- ations for every *ℓ ∈* [0*..B*].
1.each party *Pi* computes *ri← F*(*Ki,*(id*,ℓ*))
*a*

2. *P₁* sets *s* *h* 1*,*2*← ur*1[*Sℓ,h*]*,*1for every *h ∈* [ ˆ*wℓ*]
3.for *j* = 2*,...,N*: – each *Pi* such that *i < j* computes:
$1 *w*ˆ*ℓ b*

(a)(*di,j,ψi,j*) *←* HSS*.*Hash pk*i,j,*0*,* (*si,j,..., si,j*)
(b)Send *di,j* to *Pj*
(c)(*s¹i,j*+1*,..., s*
*w* *i,j* ˆ *ℓ* +1) *←* HSS*.*Eval(ek*i,j,g*id *ℓ* *,Ij,i*[1]*,...,Ij,i*[*λ*]*,ψi,j*) – *Pj* computes:

(a)Receive *di,j* from *Pi* for every *i < j*
(b)For every *i < j*, compute
1 *w*ˆ X *j−*1 *ℓ* (*sj,j*+1*,..., sj,j* *ℓ* +1) *←* HSS*.*Eval(ek*j,i,g*id*,Ij,i*[1]*,...,Ij,i*[*λ*]*,di,j*) *i*=1

4.For every *h ∈* [ ˆ*wℓ*], *y ∈{*0*,*1*}*
*kℓ,h*, each party *Pi* computes

M *h* *Tih*[*y*] *← Cℓ,h*(*y ⊕ z*) *· si,N*+1[*z*] *z∈{*0*,*1*}kℓ,h* M *′* *⊕ F* (*Ki,j,*(id*,ℓ,h,y*)) *j<i* M *′* *⊕ F* (*Kj,i,*(id*,ℓ,h,y*)) *j>i*

5.Each party *Pi* outputs (*ri, Ti*
1 *,..., Tiw* ˆ *ℓ* ).

*a* We assume that the output of the PRF is truncated at the right length *kℓ*. *b* If the given vector is too long, we split into chunks of *n* elements and we hash each of them.

Fig. 18. The Preprocessing Protocol *Π*Prep

The Special RMS Program *g*id *ℓ*

For every *h ∈* [ ˆ*wℓ*] and *i ∈* [*kℓ*], let *δh,i* *ℓ* be the *kℓ,h*-bit string that is zero everywhere except for the position *t*, where *i* is the *t*-th element in *Sℓ,h*(*t* might also not exist). 1 *w*ˆ*ℓh τℓ,h kℓ,h* Special Input: a vector (*s,..., s*) where, for every *h ∈* [ ˆ*wℓ*], *s ∈* Z₂ and *τℓ,h*= 2. Standard Input: a PRF key *K ∈{*0*,*1*}* *λ*

1. *r ← F*(*K,* (id*,ℓ*))
2. *∀h ∈* [ ˆ*wℓ*] : *v₀*
*h* *← s* *h*

3.For *i* = 1*,...,kℓ*:
(a) *∀h ∈* [ ˆ*wℓ*]*,j ∈{*0*,*1*}*
*kℓ,h* : *vih*[*j*] *← vih−*1[*j*] + *r*[*i*] *·* (*vih−*1[*j ⊕ δh,i* *ℓ*] *− vih−*1[*j*])

4.Output *vk*
1 *ℓ* *,..., vk* *w*ˆ *ℓℓ*

Fig. 19. The Special RMS Program *g*id

*ℓ*

The claim is clearly true for *j* = 1. Now suppose that the claim is true for *j −* 1. We prove it also for *j*. We observe that, by the correctness of HSS, we have

X *j* X *j−*1 (*s¹i,j*+1*,..., s* *w* *i,j* ˆ *ℓ* +1 ) = (*s¹i,j*+1*,..., s* *w* *i,j* ˆ *ℓ* +1 ) + (*s¹j,j*+1*,..., s* *w* *j,j* ˆ *ℓ* +1 ) *i*=1 *i*=1 X *j−*1 = HSS*.*Eval(ek*i,j,g*id *ℓ* *,Ij,i*[1]*,...,Ij,i*[*λ*]*,ψi,j*) *i*=1 X *j−*1 + HSS*.*Eval(ek*j,i,g*id *ℓ* *,Ij,i*[1]*,...,Ij,i*[*λ*]*,di,j*) *i*=1 X *j−*1 = *g*id *ℓ* (*s¹i,j,..., s* *w* *i,j* ˆ *ℓ* *, Kj*) *i*=1

We also observe that *g*id *ℓ* is linear in *s¹i,j,..., s* *w* *i,j* ˆ *ℓ* (it only permutes the entries of the vectors). So,

|j|j−1||||
|---|---|---|---|---|
|h|ℓ|w ˆ|||
|i,j+1|id i,j|i,j|j||
|i=1|i=1||||
||j−1 ℓ id|w ˆ i,j|j||
||i=1||||
||ℓ id r r [S],1|],1 r [S|r [S],1|],1 j|

X X *s* = *g* (*s¹,..., s* *ℓ* *, K*)

X !

= *g* (*s¹i,j,..., s* *ℓ* )*, K*

= *g u* *j* *′ −* 1 [*Sℓ,*1*,..., uj* *′ −* 1 *ℓ,w*ˆ *, K* *ℓ* = (*u* *j* *′* *ℓ,*1 *,..., u* *j* *′* *ℓ,w*ˆ )*.* *ℓ*

We conclude that

X *N* *s* *h* *i,N*+1= *ur*[*Sℓ,h*]*,*1 *i*=1

Now, pick any *h ∈* [ ˆ*wℓ*] and *y ∈{*0*,*1*}* *k* *ℓ,h*, we observe that, for every *h ∈* [ ˆ*w* *ℓ*],

M M M *Tih*[*y*]= *Cℓ,h*(*y ⊕ z*) *· s* *h* *i,N*+1[*z*] *i∈*[*N*] *i∈*[*N*] *z∈{*0*,*1*}kℓ,h* M *⊕ F* *′* (*Ki,j,*(id*,ℓ,h,y*)) *j<i* M *⊕ F* *′* (*Kj,i,*(id*,ℓ,h,y*)) = *j>i*   M M = *Cℓ,h*(*y ⊕ z*) *·*  *s* *h* *i,N*+1[*z*] *z∈{*0*,*1*}* *kℓ,hi∈*[*N*] M = *Cℓ,h*(*y ⊕ z*) *· ur*[*Sℓ,h*]*,*1[*z*] *z∈{*0*,*1*}* *kℓ,h*

### = Cℓ,h(y ⊕ r[Sℓ,h]).

We now focus our attention on security. We consider the simulator *S* that just runs the protocol using dummy inputs for the honest parties and, for every *ℓ ∈* [0*..B*], sends (*ri, Ti* 1 *,..., Tiw* ˆ *ℓ* ) to *F*Prepfor every corrupted party *Pi*. We show that no semi-honest adversary can distinguish between real world and ideal world using a sequence of indistinguishable hybrids. Hybrid 0. This hybrid corresponds to the real world. Hybrid 1. In this hybrid, we fix an honest party *Pι*. For every *ℓ ∈* [0*..B*], we compute the output of *Pι* as follows

$

1. *∀i ∈* L [*N*] : *ri← F*(*Ki,*(id*,ℓ*))
2. *r ←i∈*[*N*]*ri*

|i∈[N] i|||
|---|---|---|
|ℓ|k|i̸=ι ih|

*ℓ,h* L

3. *∀h ∈* [ ˆ*w*]*,y ∈{*0*,*1*}* : *Tιh*[*y*] *← Cℓ,h*(*y ⊕ r*[*Sℓ,h*]) *⊕ T* [*y*] By the correctness of the protocol, this hybrid is indistinguishable from the previous one.

|Hybrid 2. In this hybrid, for every honest party P|with i ̸= ι, every ℓ ∈ [0..B] and every h ∈ [ ˆ|w], we|
|---|---|---|
|τ ′ ih|i i|ℓ i|
 $ *ℓ,h* sample *T ←* Z₂. This hybrid is indistinguishable from the previous one due to the security of the PRF in *F*. Hybrid 3. In this hybrid, for every honest party *P*, during the initialisation, instead of inputting *K* in the succinct HSS scheme, we input 0. This hybrid is indistinguishable from the previous one due to the input privacy of succinct HSS. Hybrid 4. In this hybrid, for every honest party *Pi*and every *ℓ ∈* [0*..B*], instead of hashing (*s¹i,j,..., s*
*w* *i,j* ˆ *ℓ* ) for every *j > i*, we hash 0. This hybrid is indistinguishable from the previous one thanks to the hasher privacy of the succinct HSS scheme. Hybrid 5. This hybrid corresponds to the ideal world. For every honest party *Pi*and every *ℓ ∈* [0*..B*], we do not evaluate *F* on input *Ki*and (id*,ℓ*) anymore. We instead sample the outputs *ri*at random. This hybrid is indistinguishable from the previous one due to the security of the PRF in NC₁. This ends the proof. *⊓⊔*

Putting together Corollary 4, Theorem 13 and Theorem 14, we obtain the following corollary.

Corollary 5. *Assume that one of the following holds:*

– *DCR over the Paillier group,* – *DDH, hidden subgroup assumption, small exponent assumption, the uniformity assumption and n¹* */*3 *-ary* *EDDH over class groups,* – *LWE with superpolynomial modulus-to-noise ratio.*

*For any N -party functionality F represented by a layered boolean circuit C of size s with k inputs and m* *outputs, there exists a protocol that realises F against semi-honest adversaries corrupting up to N −*1 *parties* *in the plain model with total communication.*

*O*(*k* + *N ·* (*m* + *s/* log log*s*)) + *O*(*N² · s²* */*3*·*(1+*ϵ*) ) *·* poly(*λ*)

### for any constant ϵ > 0.

*Proof.* We build our MPC protocol by considering the protocol of [Cou19] (see Theorem 13) and instantiating *F*Prepusing *Π*Prep. Under any of the assumptions of Corollary 5, it is possible to build succinct HSS schemes with hash input bound *n*, where the input message size is poly(*λ*) and independent of *n*. The key size and the digest size is instead *O*(*n²* */*3 ) *·* poly(*λ*). Using any of these schemes, the communication of *Π*Prep(averaged over all channels) is *O*(*n²* */*3 ) *·B·* poly(*λ*). To this, we need to add the communication complexity of a protocol that implements the trusted setup. Since all the considered succinct HSS schemes satisfy setup sublinearity, the communication complexity of the setup is *O*(*N² · n* P 2*/*3 ) *·* poly(*λ*). We observe that *w*ˆ *≤⌈*2*s/* log log *s⌉* and

|ℓ∈[0..B]|ℓ||||
|---|---|---|---|---|
|||2||√ log s|
||ℓ||||
|ℓ∈[0..B]|i,j||1 2||
|u||1+ϵ|/3·(1+ϵ)||

X*u* *n ≤ τ /B ≤⌈*2*s/* log log *s⌉·* 2 */B* = *O*(*s/* log log *s ·* 2)*/B.*

This is because, since each *√* *C* is a 2-ary circuit of depth at most *u* = log log*s*, the number of inputs of *Ci,j*is at most 2 = log*s*. That proves that *n* = *o*(*s*)*/B* for any constant *ϵ >* 0. We conclude that the total communication of the protocol is therefore bounded by

*O*(*k* + *N ·* (*m* + *s/* log log*s*)) + *O*(*N² · s²*) *·* poly(*λ*)*.*

*⊓⊔*

## 9 Asymptotically Better Sublinear Communication MPC for Layered Circuits

The *N*-party protocol for layered circuits we presented in the previous section achieves *O*(*s/* log log*s*) com- munication, where *s* denotes the size of the circuit we want to evaluate. While this is an interesting result, as it proves that sublinear communication MPC without FHE is possible for every number of parties, the log log*s* factor is quite small. In this section, we show that using succinct HSS, it is possible to build *N*-party protocols that achieve *O*(*s/* log*s*) communication for a slightly smaller class of circuit. Before explaining our idea, we introduce the notion of layered RMS program. Essentially, this consists of an RMS program in which the gates are partitioned into layers S *S₁,...,SL*. If a gate belongs to the layer *Si*, all its input must belong to the above layers*j<iSj*. We require that *S₁* consists of all and only the input gates. On the other hand, *SL*consists of all and only the output gates.

Definition 27(Layered RMS Program). *A layered RMS program over the ring R consists of a direct* *graph* (*D,E*) *where the nodes are partitioned into L layers S₁,...,SLfor some L ∈* N*. Each node belongs to* *exactly one of the following types:*

– *Input Gate. It has in-degree 0 and it belongs to S₁.* – *Linear Gate.* S *It has unbounded in-degree. If the gate belongs to the layer Sj, the parent nodes must* *belong toi<jSi. Each of these gates is associated with a vector z in R* *m* *where m is the in-degree of* *the node.* – *Multiplication Gate. It has in-degree 2. If the gate belongs to the layer Sj, one parent node, called* *the* S input parent*, must belong to S₁, the other one, called the* internal parent*, must instead belong to*

*i<jSi.*

– *Output Gate. It is a node with in-degree 1 and out-degree 0. The gate must belong to the layer* S *SL, the* *parent node must belong toi<LSj.* P*L* *We use k* := *|S₁| to denote the number of input gates and s* :=*j*=1*|Sj| to denote the total number of* *gates. For every j ∈* [*L*]*, we use Ujto denote the list of all input parents of multiplication gates in layer Sj.* *Similarly, we use Vjto denote the list of all internal parents of multiplication gates in layer Sj.* *We say that a family of layered RMS programs* (*Cn*)*n∈*N*, where Cnhas k*(*n*) *input gates and s*(*n*) *gates,* *is efficient if there exists a polynomial p such that s*(*n*) *≤ p*(*k*(*n*)) *except for a finite number of n ∈* N*.*

Below, we formalise how a layered RMS program is evaluated. The procedure is analogous to the evalu- ation of a standard RMS program.

Definition 28(Evaluation of Layered RMS Programs). *Let C be a layered RMS program over R with* *k input gates. Let x be a vector of length k over R. The evaluation of C over x consists of the unique labelling* *of the nodes in C satisfying the following properties:*

– *The i-th input gate of C is labelled by xi* – *Every linear gate is labelled by the inner-product ⟨z, x⟩ where z is the vector associated with the gate and* *x is the vector consisting of the labels of the parent nodes.* – *Every multiplication gate is labelled by x · y where x and y are the labels associated with the parent nodes.* – *Every output gate is associated with the same label of the parent node.*

*The result of the evaluation consists of the list of labels of the output nodes.*

Now that we have formalised the necessary notions, we presents an *N*-party protocol *Π*RMS(see Fig. 21) for the secure evaluation of layered RMS programs. This will be the basic building block for our sublinear communication MPC protocol. The communication complexity of *Π*RMSwill scale linearly in the number of inputs, outputs and depth of the program. It will instead be sublinear in the width. The protocol relies on a setup that generates and distributes a pair of evaluation keys for a 2-party succinct HSS scheme to each pair of participants (as we did in our *N*-party DPF). After that, the evaluation of the RMS programs begins from the parties providing their inputs: in order to supply a value *x*, party *Pi* will insert it in all 2-party succinct HSS executions it is involved. After this phase, the protocol will proceed by evaluating the RMS program layer after layer. Throughout its execution, we will satisfy and invariant: after processing the *ℓ*-th layer, the parties will hold an additive secret-sharing of the content of all wires in the *ℓ*-th layer. Before the protocol begins, this is of course true: the share of a party providing the input *x* will be *x*, the shares of the other parties will all be 0. Now, suppose that the parties hold an additive secret-sharing of all values in the *ℓ*-th layer. Using local computations, they can easily derive additive secret-sharings of all outputs of linear gates in the (*ℓ* + 1)- th layer. The hard part is the evaluation of the multiplication gates. Luckily, since we are dealing with an RMS program, we know that one of the inputs of every multiplication gate is an input to the whole protocol. The value of the other input will instead be secret-shared among all parties. In order to evaluate the multiplications in the (*ℓ*+ 1)-th layer, for every *i ∈* [*N*], each party *Pj*will collect the shares of all wires that need to be multiplied by inputs that were provided by *Pi*. Then, it will hash them using the succinct HSS instance with party *Pi i i j*

||and will send the digest to P||. At that point, the two parties P|||and P|will run|
|---|---|---|---|---|---|---|---|
||i||i|||i|j|
||||||||i|
||||j|||j|i|
|j|i|j||i,j|j|i i,j|j j|
||N|i|i|i,j||||
||||j̸=i|||||
|i||||||||

the special RMS program that multiplies the hashed shares by the corresponding inputs of party *P*. Concretely, suppose that, in the (*ℓ* + 1)-th layer, we need to multiply the input *x* supplied by *P* by the secret-shared internal wire J*y*K. For every *j ∈* [*N*], let *y* be the share of party *P*. We observe that, in our protocol, *y* is hashed along with other values by *P* and the resulting digest is sent to *P*. After the evaluation of the special RMS program, *P* and *Pj*obtain respectively shares *z* and *z* such that *z* + *z* = *x · y*. We therefore notice that *z₁,...,z*, where X *z* := *x · y* + *z*

is an additive secret-sharing of *x · y*. So, to derive the secret-sharing of the outputs of the multiplication gates, party *P* needs to add all the shares obtained from the succinct HSS evaluations (there is one with

every party *Pj*) and then correct the result by adding the product of the inputs it provided by its shares of the internal wires. By performing these operations for every layer, the parties will obtain a secret-sharing of the output.

The Functionality *F*RMS Initialisation: The functionality activates after receiving (Init*,n*) from all parties. Let *ι* be the index of an honest party. Input: On input (Input*,*id*,i*) from all parties. Receive *x ∈* Z*q* from *Pi* and store it under the identity id. RMS: On input (RMS*,C,* id₁*,...,* id*k*) for some *k ∈* Z from each party *Pi*, where *C* is the description of a layered RMS program over Z*q* with *k* inputs, *m* outputs and with at most *n* multiplications per layer, the functionality outputs *y ← C*(*x₁,...,xk*) to all parties, where, for every *j ∈* [*k*], *xj* denotes the element stored under the identity id*j*.

Fig. 20. The Functionality *F*RMS

Theorem 15. *Assume the existence of 2-party succinct HSS over* Z₂ *and PRFs in* NC₁*. Suppose that the* *parties are connected by authenticated point-to-point channels. Then, the protocol in Fig. 21 UC-implements* *the functionality F*RMS*(see Fig. 20) against a semi-honest, static adversary corrupting up to N −* 1 *parties* *in the F*HSS*-*Setup*-hybrid model (see Fig. 12).* *The total communication complexity required in order to evaluate a layered RMS program with k inputs,* *L layers and m outputs is* *N · k · t₀*(*λ,n*) + *N · m* + *N² · L · t₁*(*λ,n*)*,*

*where t₀*(*λ,n*) *and t₁*(*λ,n*) *denote the input message size and the digest size of the succinct HSS scheme.* *The round complexity is Θ*(*L*)*.* P *Proof.* We start by showing correctness. We proceed by induction over the layers to show that*i∈*[*N*]*vℓ,i* P corresponds to the correct evaluation of the *ℓ*-th layered of the program. It is easy to see that*i∈*[*N*]*v₁,i*= *x* where *x* denotes the vector of inputs. It remains to show that, if the hypothesis holds for the first *ℓ −*1 layers, so does for the *ℓ*-th layer. The claim comes for free for linear gates. We therefore focus on multiplication gates. Consider a gate and suppose that the input parent is provided by party *Pi*. Let *ui*be its value. Let *vj* be the value of the entry of *v₁,j,..., vℓ−*1*,j*corresponding to the internal parent. Observe that by inductive P hypothesis, in the evaluation of the RMS program, the value of the internal parent is*j∈*[*N*]*vj*. At the end

|||||j∈[N]|j|
|---|---|---|---|---|---|
|ℓ,j||i|j|i j||
|j|||i||i i|
||||j|||
|j∈[N] i|j i|||||

of their succinct HSS execution, *P* and *P* obtain a two-party secret-sharing of *u · v*. For every *j ̸*= *i*, the entry of *v* corresponding to the considered multiplication gate will be the succinct HSS share obtained by *P* in the above procedure. For party *P*, instead, the entry will be the addition between *u · v* and the sum of all the succinct HSS shares obtained by *Pi*(observe that *Pi*is involved in *N −* 1 executions of the procedure, each one with a different P

*P*). We conclude by observing that the sum of the resulting shares is
*u · v* = *u · v*. This is exactly what we wanted. This ends the proof of correctness. Security is a straightforward application of the hasher privacy, the input privacy, and the pseudorandom shares of the succinct HSS scheme. After receiving the inputs of the corrupted parties, the simulator will just forward them to the functionality and run the protocol using dummy inputs for the honest players. It will then provide the functionality with the output shares of the corrupted players. *⊓⊔*

We finally explain how to use the *N*-party protocol for RMS protocols to build *N*-party computation protocols with sublinear communication in the circuit size. Before describing the details, we however recall the following result, which shows that every depth *d* circuit can be converted into an RMS program of depth *O*(2 *d* ).

Theorem 16( [Weg00, BGI16]). *If C is a layered boolean circuit of depth d and width w, then, C is* *computable by a layered RMS program of depth O*(2 *d* ) *with at most w multiplications in each layer.*

Sublinear Communication MPC for RMS Programs *Π*RMS Let *N* be the number of parties. For every *{i,j}⊆* [*N*], let *F*HSS *i,j* -Setupbe a copy of *F*HSS-Setupto which only *Pi* and *Pj* have access.

Initialisation: On input (Init*,n*), each party *Pi* performs the following operations:

1.for every *j ̸*= *i*, send (Init*,n*) to *F*HSS
*i,j* -Setup. Receive (pk*i,j,*ek*i,j*) (if *i < j*) or (pk*i,j,*ek*j,i*) (if *i > j*) as an answer (*Pj* will obtain the other half of the key).

Input: In order to input a value *x ∈* Z*q* under the identity id, party *Pi* performs the following operations:

$

1. *∀j < i* : *Ii,j ←* HSS*.*Input(pk*j,i,x*)
$

2. *∀j > i* : *Ii,j ←* HSS*.*Input(pk*i,j,x*)
3.Send *Ii,j* to *Pj* for every *j ̸*= *ι*.
4.Store (*Ii,j*)*j̸*=*i*and *x* under id Each other party *Pj* stores *Ii,j* under the identity id.
RMS: Given identities id₁*,...,* id*k*and an RMS program *C* with *k* inputs, *L* layers *S₁,...,SL* and with at most
*n* multiplications per layer, each party *Pi* computes the following operations:

1.Each party retrieves the values stored under the identities id₁*,...,* id*k*
2.Define a vector *v₁,i*with the same dimension as the number of gates in *S₁*. Each entry is assigned with the value of the corresponding input wire if the latter was provided by *Pi*, with 0 otherwise.
3.Evaluate the gates in *Sℓ*for *ℓ* = 2*,...,L* as follows:
(a)For every *j ∈* [*N*] *\{i}*, using pk*i,j*or pk*j,i*(depending on whether *j < i* or *j > i*), hash all entries in *v₁,i,..., vℓ−*1*,i*corresponding to gates in *Vℓ*where the associated input parent was provided by *Pj*. Send the resulting hash *d*
*ℓ* *i,j*to *Pj* and store the corresponding private information *ψi,j* *ℓ*.

(b)Receive *d*
*ℓ* *j,i*from every party *Pj*.

(c)Evaluate all linear gates in *Sℓ*on *v₁,i,..., vℓ−*1*,i*.
(d)For every multiplication gate in *Sℓ*where the value of the input parent is provided by another party *Pj*, use *ψi,j* *ℓ*
and *Ij,i* to evaluate the special RMS program (see Lemma 1) that multiplies the input parent by the share of the internal parent hashed in *d* *ℓ* *i,j*.

(e)For every multiplication gate in *Sℓ*where the value of the input parent is provided by *Pi*, for every *j ̸*= *i*, use *d*
*ℓ* *j,i*and *Ii,j* to evaluate the special RMS program (see Lemma 1) that multiplies the input parent by the share of the internal parent hashed in *d* *ℓ* *j,i*. Finally, add to the resulting HSS shares the multiplication between the value of the input parent and the entry in *v₁,i,..., vℓ−*1*,i*corresponding to the internal parent.

(f)Store the values obtained in steps 3c, 3d and 3e into a vector *vℓ,i*.
4.Broadcast P
*vL,i*and receive (*vL,j*)*j̸*=*i*.

5.Output*j∈*[*N*]*vL,j*.
Fig. 21. Sublinear Communication MPC for RMS Programs *Π*RMS

To construct a sublinear communication MPC protocol for a layered circuit *C*, we follow the idea of [BGI16]: we split the layers of *C* into blocks *B₁,...,BL*of *O*(log*λ*) depth. Thanks to Theorem 16, each of these blocks can be converted into a poly(*λ*)-sized RMS program which can be evaluated using *Π*RMS(see

Fig. 21). At the end of the execution of *Π*RMSon the *ℓ*-th block, the players will end up with an additive secret-

sharing of the outputs of *Bℓ* RMS *ℓ*+1

||. Such shares would need to be reinput into Π|||for the evaluation of B||.|
|---|---|---|---|---|---|---|
||ℓ|||RMS||ℓ+1|
|||||ℓ+1|||
|ℓ+1|ℓ RMS|ℓ+1 i|||RMS||
|||||||ℓ|
|RMS|||ℓ||||

If we perform this in a naive way, however, that operation would require *N² · k ·* poly(*λ*) communication where *k* denotes the input length of *B*. To avoid this *N ·*poly(*λ*) multiplicative overhead, we adopt the following trick: we let each party *P* select a key for a PRF in NC₁. Such key will be input in *Π* at the very beginning of the sublinear communication MPC protocol. Instead of directly inputting the shares of the results produced by *B* into *Π*, we let each party encrypt their shares under their PRF key, broadcasting the ciphertext. We can then use the PRF keys already input in *Π*RMSto recover the actual output of *B* inside *Π*. In this way, the operation requires only *N · k* communication.

The Functionality *F*MPC MPC: On input (*C,xi*) from each party *Pi* where *C* is a layered circuit and *xi* is the input of party *Pi*, the functionality outputs *y ← C*(*x₁,...,xN*) to all the parties.

Fig. 22. The Functionality *F*MPC

Theorem 17. *Assume the existence of point to point channels and PRFs in* NC₁*. The protocol in Fig. 23* *UC-realises the functionality F*MPC*in Fig. 22 in the F*RMS*-hybrid model against a semi-honest, static adver-* *sary corrupting up to N −* 1 *parties.* *If F*RMS*is implemented using the protocol in Fig. 21, the total communication is*

X *L*X*L* *N · kℓ*+ *N² · λ · t₀*(*λ,n*) + *N² ·* 2 *d* *ℓ* *· t₁*(*λ,n*) + *N · m.* *ℓ*=1 *ℓ*=1

*where m is the output size of C, k is the input size and t₀*(*λ,n*) *and t₁*(*λ,n*) *denote the input message size* P*L* *d* *ℓ* *and the digest size of the succinct HSS scheme. The round complexity is Θ*(*ℓ*=12)*.*

Sublinear Communication MPC

Let *C* be a layered circuit over Z*q* of width *n*. We split *C* into *L* blocks *B₁,...,BL* of consecutive layers. Let *dℓ* be the depth of *Bℓ*. We require that *dℓ*= *O*(log*λ*). Let *kℓ*denote the input length of *Bℓ*. Let *F* be a PRF in NC₁.

MPC: Let sid be the session identity, let *x* be the vector of inputs. Each party *Pi* performs the following operations.

1.Send (Init*,n*) to *F*RMS $*λ*
2. *Ki←{*0*,*1*}*
3.Send (Input*,j,* (sid*,j,t*)) to *F*RMSfor every *j ∈* [*N*] and *t ∈* [*λ*]. If *j* = *i*, provide *F*RMSwith *Ki*[*t*].
4.For each input wire *t* of *C* whose value is provided by *Pi*, *Pi* broadcasts *c₁*[*t*] *← x*[*t*] *⊕ F*(*Ki,*(1*,t*)).
5.For each other input wire *t*, receive *c₁*[*t*] from the party providing the corresponding value.
6.Let *c₁* be the vector (*c₁*[1]*,..., c₁*[*k*]).
7.For *ℓ* = 1*,...,L*, call *F*RMSon input (RMS*, B*e*ℓcℓ,*(sid*,j,t*)*j∈*[*N*]*,t∈*[*λ*]) and receive *cℓ*+1as output. (see Fig. 24)
8.Output *cL*+1.
Fig. 23. Sublinear Communication MPC for Layered Programs
 Putting the results of Theorem 17 and Theorem 15 together, we obtain the following corollary.

The RMS Program *B*e*ℓcℓ* Input: Keys *K₁,..., KN∈{*0*,*1*}* *λ*

1.If *ℓ* = 1, for every *t ∈* [*kℓ*], compute *xt ← cℓ*[*t*]*⊕ F*(L *Kj,* (*ℓ,t*)) where *Pj* is the party providing the *t*-th input.
2.If *ℓ >* 1, for every *t ∈* [*kℓ*], compute *x*[*t*] *← cℓ*[*t*] *⊕j∈*[*N*]*F* (*Kj,* (*ℓ,t*))
3. *y ← Bℓ*(*x*)
4.If *ℓ* = *L*, output *y*.
L

5.If *ℓ < L*, for every *t ∈* [*kℓ*+1], compute *cℓ*+1[*t*] *← y*[*t*] *⊕j∈*[*N*]*F* (*Kj,* (*ℓ* + 1*,t*))
6.Output *cℓ*+1.
Fig. 24. The RMS Program *B*e*ℓcℓ*

Corollary 6. *Assume the existence of a succinct HSS scheme with tight setup and PRFs in* NC₁*. Let t₀*(*λ,n*)*,* *t₁*(*λ,n*)*, t₂*(*λ,n*) *be the message input size, the digest size and the key size of the succinct HSS keys respec-* *tively.* *For any constant c and every N -party functionality F represented by a layered boolean circuit C of size* *s, depth d, width n, with k inputs and m outputs, there exists a protocol that realises F against semi-honest* *adversaries corrupting up to N −* 1 *parties in the plain model with total communication.*

*O*(*N ·* (*k* + *m* + *s/* log*s*)) + *N² · λ · t₀*(*λ,n*)

+ *O*(*N² ·* (*d/* log*s*) *· s¹* */c* ) *· t₁*(*λ,n*) + *N² · t₂*(*λ,n*) *·* poly(*λ*)

*The round complexity is Ω*(*d/* log *s · s¹* */c* )*.*

*Proof.* We consider the composition of the protocols of Theorem 17 and Theorem 15. We observe that they rely on *N²* executions of the trusted setup *F*HSS-Setup. Since the succinct HSS scheme has a tight setup, the latter can be implemented with *t₂*(*λ,n*) *·* poly(*λ*) communication. P

||1|||a|
|---|---|---|---|---|
|d t|c u −1 a t=0 j=0|u·j+t||j=0 u·j+t|
||(j−1)·u+t|j·u+t|t||
|a ·u+t||ℓ|ℓ||

*t* Let *S₁,...,S* be the layers of *C*. Let *u* := *·* log*s*. We consider *t ∈* [0*..u −* 1] such that *|S |≤* *⌈s/u⌉*, where *a* := max*{j|u · j* + *t ≤ d}* = *O*(*d/u*). Such *t* exists, otherwise we would have

X X*t* *|C|* = *|S | > u ·⌈s/u⌉≥ s.*

We define the block *B₁* as the one consisting of the layers *S₁,...,S*. For every *j ∈* [*at−*1], we define *Bj* as the block consisting of the layers *S,...,S*. We define the block *Bat*as the one consisting of the layers *St,...,Sd*. Notice that the depth *d* of each block *B* is at most *u*. If we run the protocol in

Fig. 23 with such choice of blocks, the communication complexity becomes

*O*(*N ·* (*k* + *m* + *s/u*)) + *N² · λ · t₀*(*λ,n*)

+ *O*(*N² ·* (*d/u*) *·* 2 *u* ) *· t₁*(*λ,n*) + *N² · t₂*(*λ,n*) *·* poly(*λ*)*.*

*⊓⊔*

The following result shows the communication complexity of our MPC protocol when the succinct HSS scheme is instantiated with the constructions of Section 4.

Corollary 7. *Assume that one of the following holds:*

– *DCR over the Paillier group,* – *DDH, hidden subgroup assumption, small exponent assumption, the uniformity assumption and n¹* */*3 *-ary* *EDDH over class groups,* – *LWE with superpolynomial modulus-to-noise ratio.*

*For any constant c >* 0 *and for every N -party functionality F represented by a layered boolean circuit C* *of size s, depth d, width n, with k inputs and m outputs, there exists a protocol that realises F against* *semi-honest adversaries corrupting up to N −* 1 *parties in the plain model with total communication.*

*O*(*N ·* (*k* + *m* + *s/* log*s*)) + *N² ·* (*d/* log*s*) *· s¹* */c* *·* poly(*λ*) + *N² · n² ·* poly(*λ*)*.*

*The round complexity is Θ*(*d/* log *s · s¹* */c* )*.*

Finally, the following result shows the communication complexity of our MPC protocol when the succinct HSS scheme is instantiated by applying Theorem 7 on the constructions of Section 4.

Corollary 8. *Assume that one of the following holds:*

– *DCR over the Paillier group,* – *DDH, hidden subgroup assumption, small exponent assumption, the uniformity assumption and n¹* */*3 *-ary* *EDDH over class groups,* – *LWE with superpolynomial modulus-to-noise ratio.*

*For any constant c >* 0 *and for every N -party functionality F represented by a layered boolean circuit C* *of size s, depth d, width n, with k inputs and m outputs, there exists a protocol that realises F against* *semi-honest adversaries corrupting up to N −* 1 *parties in the plain model with total communication.*

*O*(*N ·* (*k* + *m* + *s/* log*s*)) + *N² ·* (*d/* log*s*) *· s¹* */c* *· n²* */*3 *·* poly(*λ*)*.*

*The round complexity is Θ*(*d/* log *s · s¹* */c* )*.*

## References

ADOS22.Damiano Abram, Ivan Damg˚ard, Claudio Orlandi, and Peter Scholl. An algebraic framework for silent preprocessing with trustless setup and active security. In Yevgeniy Dodis and Thomas Shrimpton, editors, *CRYPTO 2022, Part IV*, volume 13510 of *LNCS*, pages 421–452. Springer, Heidelberg, August 2022. Ajt96.Mikl´os Ajtai. Generating hard instances of lattice problems (extended abstract). In *28th ACM STOC*, pages 99–108. ACM Press, May 1996. BCG +

19.Elette Boyle, Geoffroy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, and Peter Scholl. Efficient pseu- dorandom correlation generators: Silent OT extension and more. In Alexandra Boldyreva and Daniele Micciancio, editors, *CRYPTO 2019, Part III*, volume 11694 of *LNCS*, pages 489–518. Springer, Heidel- berg, August 2019.
BCM23.Elette Boyle, Geoffroy Couteau, and Pierre Meyer. Sublinear-communication secure multiparty compu- tation does not require FHE. In Carmit Hazay and Martijn Stam, editors, *EUROCRYPT 2023, Part II*, volume 14005 of *LNCS*, pages 159–189. Springer, Heidelberg, April 2023. BDG +

22.Elette Boyle, Itai Dinur, Niv Gilboa, Yuval Ishai, Nathan Keller, and Ohad Klein. Locality-preserving hashing for shifts with connections to cryptography. In *13th Innovations in Theoretical Computer Science* *Conference, ITCS 2022*, pages 27–1. Schloss Dagstuhl-Leibniz-Zentrum fur Informatik GmbH, Dagstuhl Publishing, 2022.
BG10.Zvika Brakerski and Shafi Goldwasser. Circular and leakage resilient public-key encryption under subgroup indistinguishability - (or: Quadratic residuosity strikes back). In Tal Rabin, editor, *CRYPTO 2010*, volume 6223 of *LNCS*, pages 1–20. Springer, Heidelberg, August 2010. BGI16.Elette Boyle, Niv Gilboa, and Yuval Ishai. Breaking the circuit size barrier for secure computation under DDH. In Matthew Robshaw and Jonathan Katz, editors, *CRYPTO 2016, Part I*, volume 9814 of *LNCS*, pages 509–539. Springer, Heidelberg, August 2016. BGI +

18.Elette Boyle, Niv Gilboa, Yuval Ishai, Huijia Lin, and Stefano Tessaro. Foundations of homomorphic secret sharing. In *9th Innovations in Theoretical Computer Science Conference (ITCS 2018)*. Schloss- Dagstuhl-Leibniz Zentrum f¨ur Informatik, 2018.
BKS19.Elette Boyle, Lisa Kohl, and Peter Scholl. Homomorphic secret sharing from lattices without FHE. In Yuval Ishai and Vincent Rijmen, editors, *EUROCRYPT 2019, Part II*, volume 11477 of *LNCS*, pages 3–33. Springer, Heidelberg, May 2019.

BMRS21.Carsten Baum, Alex J. Malozemoff, Marc B. Rosen, and Peter Scholl. Mac’n’cheese: Zero-knowledge proofs for boolean and arithmetic circuits with nested disjunctions. In Tal Malkin and Chris Peikert, editors, *CRYPTO 2021, Part IV*, volume 12828 of *LNCS*, pages 92–122, Virtual Event, August 2021. Springer, Heidelberg. CLM23.Valerio Cini, Russell W. F. Lai, and Giulio Malavolta. Lattice-based succinct arguments from vanishing polynomials - (extended abstract). In *CRYPTO 2023, Part II*, LNCS, pages 72–105. Springer, Heidelberg, August 2023. CNs07.Jan Camenisch, Gregory Neven, and abhi shelat. Simulatable adaptive oblivious transfer. In Moni Naor, editor, *EUROCRYPT 2007*, volume 4515 of *LNCS*, pages 573–590. Springer, Heidelberg, May 2007. Cou19.Geoffroy Couteau. A note on the communication complexity of multiparty computation in the correlated randomness model. In Yuval Ishai and Vincent Rijmen, editors, *EUROCRYPT 2019, Part II*, volume 11477 of *LNCS*, pages 473–503. Springer, Heidelberg, May 2019. DGI +

19.Nico D¨ottling, Sanjam Garg, Yuval Ishai, Giulio Malavolta, Tamer Mour, and Rafail Ostrovsky. Trap- door hash functions and their applications. In Alexandra Boldyreva and Daniele Micciancio, editors, *CRYPTO 2019, Part III*, volume 11694 of *LNCS*, pages 3–32. Springer, Heidelberg, August 2019.
DIJL23.Quang Dao, Yuval Ishai, Aayush Jain, and Huijia Lin. Multi-party homomorphic secret sharing and sublinear mpc from sparse lpn. Springer-Verlag, 2023. DIO21.Samuel Dittmer, Yuval Ishai, and Rafail Ostrovsky. Line-point zero knowledge and its applications. In *2nd Conference on Information-Theoretic Cryptography (ITC 2021)*. Schloss Dagstuhl-Leibniz-Zentrum f¨ur Informatik, 2021. GHO20.Sanjam Garg, Mohammad Hajiabadi, and Rafail Ostrovsky. Efficient range-trapdoor functions and appli- cations: Rate-1 OT and more. In Rafael Pass and Krzysztof Pietrzak, editors, *TCC 2020, Part I*, volume 12550 of *LNCS*, pages 88–116. Springer, Heidelberg, November 2020. GJM03.Philippe Golle, Stanislaw Jarecki, and Ilya Mironov. Cryptographic primitives enforcing communication and storage complexity. In Matt Blaze, editor, *FC 2002*, volume 2357 of *LNCS*, pages 120–135. Springer, Heidelberg, March 2003. GPV08.Craig Gentry, Chris Peikert, and Vinod Vaikuntanathan. Trapdoors for hard lattices and new cryp- tographic constructions. In Richard E. Ladner and Cynthia Dwork, editors, *40th ACM STOC*, pages 197–206. ACM Press, May 2008. IKM +

13.Yuval Ishai, Eyal Kushilevitz, Sigurd Meldgaard, Claudio Orlandi, and Anat Paskin-Cherniavsky. On the power of correlated randomness in secure computation. In Amit Sahai, editor, *TCC 2013*, volume 7785 of *LNCS*, pages 600–620. Springer, Heidelberg, March 2013.
Kil92.Joe Kilian. A note on efficient zero-knowledge proofs and arguments (extended abstract). In *24th ACM* *STOC*, pages 723–732. ACM Press, May 1992. NN01.Moni Naor and Kobbi Nissim. Communication preserving protocols for secure function evaluation. In *33rd ACM STOC*, pages 590–599. ACM Press, July 2001. OSY21.Claudio Orlandi, Peter Scholl, and Sophia Yakoubov. The rise of paillier: Homomorphic secret sharing and public-key silent OT. In Anne Canteaut and Fran¸cois-Xavier Standaert, editors, *EUROCRYPT 2021,* *Part I*, volume 12696 of *LNCS*, pages 678–708. Springer, Heidelberg, October 2021. QWW18.Willy Quach, Hoeteck Wee, and Daniel Wichs. Laconic function evaluation and applications. In Mikkel Thorup, editor, *59th FOCS*, pages 859–870. IEEE Computer Society Press, October 2018. Reg05.Oded Regev. On lattices, learning with errors, random linear codes, and cryptography. In Harold N. Gabow and Ronald Fagin, editors, *37th ACM STOC*, pages 84–93. ACM Press, May 2005. Ros22.Razvan Rosie. Adaptively secure laconic function evaluation for *NC¹*. In Steven D. Galbraith, editor, *CT-RSA 2022*, volume 13161 of *LNCS*, pages 427–450. Springer, Heidelberg, March 2022. RR22.Srinivasan Raghuraman and Peter Rindal. Blazing fast PSI from improved OKVS and subfield VOLE. In Heng Yin, Angelos Stavrou, Cas Cremers, and Elaine Shi, editors, *ACM CCS 2022*, pages 2505–2517. ACM Press, November 2022. RS21.Lawrence Roy and Jaspal Singh. Large message homomorphic secret sharing from DCR and applications. In Tal Malkin and Chris Peikert, editors, *CRYPTO 2021, Part III*, volume 12827 of *LNCS*, pages 687–717, Virtual Event, August 2021. Springer, Heidelberg. Weg00.Ingo Wegener. *Branching Programs and Binary Decision Diagrams*. Society for Industrial and Applied Mathematics, 2000. Yao83.Andrew Chi-Chih Yao. Lower bounds by probabilistic arguments (extended abstract). In *24th FOCS*, pages 420–428. IEEE Computer Society Press, November 1983. YSWW21.Kang Yang, Pratik Sarkar, Chenkai Weng, and Xiao Wang. QuickSilver: Efficient and affordable zero- knowledge proofs for circuits and polynomials over any field. In Giovanni Vigna and Elaine Shi, editors, *ACM CCS 2021*, pages 2986–3001. ACM Press, November 2021.
