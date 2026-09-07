# Succinct Oblivious Tensor Evaluation and Applications: Adaptively-Secure Laconic Function Evaluation and Trapdoor

# Hashing for All Circuits

### Damiano Abram Giulio Malavolta

abram.damiano@protonmail.com giulio.malavolta@hotmail.it Bocconi University Bocconi University

### Lawrence Roy

ldr709@gmail.com Aarhus University

Abstract

We propose the notion of succinct oblivious tensor evaluation (OTE), where two parties compute an additive secret sharing of a tensor product of two vectors x *⊗* y, exchanging two simultaneous messages. Crucially, the size of both messages and of the CRS is independent of the dimension of x. We present a construction of OTE with optimal complexity from the standard learning with errors (LWE) problem. Then we show how this new technical tool enables a host of cryptographic primitives, all with security reducible to LWE, such as:

- Adaptively secure laconic function evaluation for depth-*D* functions *f* : *{*0*,*1*}*
*m* *→{*0*,*1*}* *ℓ* with communication *m* + *ℓ* + *D ·* poly(*λ*).

- A trapdoor hash function for all functions.
- An (optimally) succinct homomorphic secret sharing for all functions.
- A rate-1*/*2 laconic oblivious transfer for batch messages, which is best possible.
In particular, we obtain the first laconic function evaluation scheme that is adaptively secure from the standard LWE assumption, improving upon Quach, Wee, and Wichs (FOCS 2018). As a key technical ingredient, we introduce a new notion of *adaptive lattice encodings*, which may be of independent interest.

## Contents

1 Introduction 2

1.1 Our Results............. .. ........................ ..2
1.2 Technical Outline. ...... ..... ... ..................... ..4
1.3 Other Applications. ....... ... .................. ........10
1.4 Concurrent Work.. .. ...... ................ ............12
2 Preliminaries 12

2.1 Lattices and Learning with Errors... ... .. ..... .. .............14
2.2 Laconic Function Evaluation. .... ... ..... .. ................14
2.3 Fully Homomorphic Encryption `a la GSW.. ... ..... ... ... ........15

3 Non-Interactive Oblivious Tensor Evaluation16

|3.1|Definitions..|. .....|..... ...|. ...|. ....|.......|.... .16|
|---|---|---|---|---|---|---|---|
|3.2|Half-Succinct NI-OTE from LWE.||.....|......|.. ...|. .... ....|.. .18|
|3.3|Bootstrapping to Fully-Succinct NI-OTE..|||.......|....|.. ....|..... .20|
|3.4 4 Adaptive Lattice Encodings24|From Succinct NI-OTE to Succinct NI-MOLE..|||...|.....|......|. .... .23|
|4.1|Homomorphic Operations.|....|.....|......|. ....|.... ...|.... .24|
|4.2 5 Rate-1 Adaptive LFE for all Bounded-Depth Functions28 5.1|Compressing Lattice Encodings. Almost Optimal, Weak Reverse Trapdoor Hashing for RMS...||......|......|......|.... ........|. ...26..... .28|
|5.2 6 Reverse Trapdoor Hashing for all Functions36|Rate-1 Adaptive LFE for all Bounded-Depth Functions..||||..|......|... ...31|
|6.1|Definition..|....|..... ...|. ...|. .....|.....|..... .36|
|6.2|Laconic Function Evaluation with Pre-Encoding..|||.|.....|......|. .... .38|
|6.3|Construction..|. ......|.. ...|.. ....|.... ...|....|..... .40|

.....

.......

...

### 7 A Counterexample for Adaptive LWE42

## 1 Introduction

Consider the scenario where Alice holds a *long* vector x, Bob holds a *smaller* secret vector y and, after a single round of simultaneous messages, they should be able to locally compute an additive secret share of the tensor product x *⊗* y while preserving the privacy of y. That is, after one simultaneous round of messages, Alice computes *α* and Bob computes *β* such that:

*α* + *β* = x *⊗* y*.*

We refer to this problem as *non-interactive oblivious tensor evaluation* (NI-OTE). In this work, we are interested in the communication complexity of secure NI-OTE, i.e., the minimum size of the messages needed in order to compute a correct additive secret sharing, while preserving the privacy of y. While one may intuitively expect that Alice and Bob’s messages should be long enough to fully specify both the vectors, this is in fact not so. Counterintuitively, we show that it is possible to complete the above protocol with communication complexity *logarithmic* in the dimensions of the input x. The objective of this work is to construct explicit protocols for NI-OTE with minimal commu- nication, and to explore the cryptographic consequences of this primitive.

### 1.1 Our Results

Our main technical contribution is a protocol for NI-OTE with minimal communication complexity, where the security is proven against the standard learning with errors (LWE) assumption [Reg05]. We prove this result in two steps: First, we construct an elementary (half-succinct) NI-OTE protocol where only the message of one party is short, whereas the message of the other party can depend arbitrarily on *|*x*|*. Then we show a generic *bootstrapping* procedure that makes the scheme fully succinct, i.e., the messages of both parties are short. Overall, our main result is captured by the following informal theorem statement (treating the security parameter as constant).

Theorem 1.1 (Informal). *If the LWE problem is hard, then there exists an NI-OTE protocol for* x *∈* Z *m* *qand* y *∈* Z *ℓq* *with communication complexity ℓ ·* poly(*λ*) + poly(*λ,* log*m*) *and CRS of size* poly(*λ,* log*m*)*.*

Besides being a primitive of independent interest, we show that the existence of our succinct NI-OTE protocol has surprising applications in cryptography.

Application I: Trapdoor Hash Functions. For starters, we show how succinct NI-OTE, com- bined with recent results in laconic function evaluation [QWW18,HLL23,DHM + 24], enables a construction of a trapdoor hash (TDH) function [DGI + 19] for all functions (or even RAM pro- grams, from Ring-LWE), where the size of the hash is constant, and the size of the encoding key depends only on the description of the program *f*, which is optimal. This improves upon prior works [DGI + 19,RS21] that constructed TDHs with similar communication complexity for the class of linear functions. This is summarized by the following (informal) theorem statement.

Theorem 1.2 (Informal). *If the LWE problem is hard, then there exists a TDH for functions with* *depth D, where the size of the encoding is bounded by* (*|f |* + *D*) *·* poly(*λ*)*. Additionally assuming* *the hardness of* circular *LWE, we obtain a bound on the size of the encodings of |f |·* poly(*λ*)*.*

Application II: Succint Homomorphic Secret Sharing and More. As a direct consequence of the above result, we obtain a new protocol of succinct homomorphic secret sharing [ARS24] for all functions with logarithmic communication complexity in the first party’s input x, which is optimal. Prior work [ARS24] only supported NC₁ circuits and had communication complexity proportional to *|*x*|* *ε*, for some *ε ∈ O*(1). In addition, we obtain a new *batched* laconic oblivious transfer protocol [CDG + 17], with constant-size receiver’s message and with rate 1*/*2, which is best possible. We refer the reader to Section1.3for a more detailed and precise discussion on these primitives, along with additional applications of succinct NI-OTE such as spooky encryption, and pseudoran- dom correlation generators.

Application III: Laconic Function Evaluation. Finally, we show how to leverage succinct NI-OTE to construct a laconic function evaluation (LFE) [QWW18] protocol that is simultaneously:

- *Adaptively secure*: The attacker can choose the input adaptively, possibly depending on the public parameters.
- *Rate-1*: The size of the encoding equals the size of the input, plus the size of the output, plus an additive factor.
Prior to our work, even constructing LFE with either of the two properties was considered an open problem. The question of adaptively-secure LFE from LWE was raised in [QWW18], where they proposed a construction provable against the *adaptive* LWE assumption, whereas our con- struction is adaptively secure against the *standard* LWE assumption. Furthermore, we present a counterexample against the adaptive LWE assumption (Appendix7) which translates into an adaptive attack against their scheme, underscoring the need for constructions proven adaptively secure against standard assumptions. The question of rate-1 LFE was considered in [Wee24], where they proposed a construction from *ℓ*-succinct LWE, a recently-introduced variant of the LWE assumption. We improve upon this work by relying only on the standard LWE problem. Overall, our results can be summarized as follows:

Laconic Function Evaluation [QWW18,HLL23,DHM + 24] Regular TDH Succinct NI-MOLE Reverse TDH (Section3.4) (Section6) Succinct HSS

Rate-1*/*2 Laconic OT Half-Succinct NI-OTE Succinct NI-OTE Weak Reverse TDH (Section3.2) (Section3.3) (Section5.1)

Adaptive Lattice Encodings Compressed Encodings Rate-1 Adaptively Secure LFE (Section4.1) (Section4.2) (Section5.2)

Figure 1: A schematic representation of our results, and a summary of the implications to different

cryptographic primitives.

Theorem 1.3 (Informal). *If the LWE problem is hard, there exists an adaptively secure LFE for* *depth-D functions f* : *{*0*,*1*}* *m* *→{*0*,*1*}* *ℓ* *with communication m* + *ℓ* + *D ·* poly(*λ*)*.*

As a key technical ingredient, we present a new variant of *homomorphic lattice encodings* [BGG + 14] that naturally supports adaptive security. This is the first construction of homomorphic lattice encodings that departs from the framework of [BGG + 14], and we expect it to find other applications in the future. A diagram summarizing our results is given in Figure1.

### 1.2 Technical Outline

From now on, we call Alice *the hasher* and Bob *the encoder*. We start by presenting a half-succinct OTE, i.e., an OTE protocol where only the hasher’s message is succinct in its input size. This is inspired by the work of [ARS24] and we extend their ideas in the context of tensor products. Suppose that we work over Z*q*, the hasher’s input is a vector over Z *m* 2, while the encoder’s input lies in Z *ℓq*. The construction relies on a setup that outputs a random matrix A *∈* Z *n* *q ×m*where *m > n*. To hash x, we simply compute an SIS-based hash d *←* A *·* x. To encode y, on the other hand, we compute C *←* A ⊺ *·* S+E+I*m⊗* y ⊺

$ *n×*(*m·ℓ*) $*λ* where S *←* Z*q*and E *← χ*(1). Above, we use I*m*to denote the *m × m* identity matrix and *χ* to denote a low-norm distribution. Notice that, under LWE, C leaks no information about y. Suppose that Alice and Bob exchanged C and d. Alice can compute a “noisy” share of x *⊗* y by computing

v := x ⊺ *·* C = x ⊺ *·* A ⊺ *·* S + x ⊺ *·* E + x ⊺ *·* (I*m⊗* y ⊺ ) = x ⊺ *·* A ⊺ *·* S + x ⊺ *·* E + (x ⊺ *⊗* y ⊺ )*.*

Bob can derive instead his own “noisy” share by computing

w := *−*d ⊺ *·* S = *−*x ⊺ *·* A ⊺ *·* S*.*

|||⊺ ⊺|⊺|m|
|---|---|---|---|---|
|||||2|
|||||p|
|q ⊺|q||||
|⊺ p|⊺||||

It is easy to see that v + w = x *⊗* y + x *·*E. Moreover, since x *∈* Z, the magnitude of x ⊺ *·*E is small. From this we can derive a fully correct, half succinct OTE over Z where *p* is a sufficiently small divisor of *q*: Instead of hashing x, hash its bit decomposition, instead of encoding y, encode log*q* *q/p ·* y *⊗* g where g is the gadget (row) vector (1*,*2*,...,*2). To reconstruct an exact secret- sharing of x *⊗* y mod *p*, it is sufficient to apply a linear operation on the shares and round the result over Z following the ideas of [DHRW16].

An Attempt at Bootstrapping. Now, let us try to achieve full succinctness. In the construction we described above, the encoder’s message has size *m·ℓ*, while the hash size is independent of both *m* and *ℓ*. Inspired by [ARS24], we rely on the non-interactive nature of the primitive and the linearity of the functionality. Specifically, we observe that the encoding can be reused across multiple hashes: Imagine that Alice’s input is now much bigger, let’s say of dimension *M ≫ m,ℓ*. We can split x into *N* blocks x₀*,...,*x*N −*1of dimension *m* and hash each of them. Alice would therefore send *N* digests d₀*,...,*d*N −*1. At this point, if Bob sends a single encoding for y *∈* Z *ℓq*, the parties are able to derive a secret-sharing of x*i⊗*y for every *i ∈* [*N*]. By rearranging these, we can easily retrieve a secret sharing of x *⊗* y. Notice that now the size of the encoding is sublinear in the size of x. The communication from Alice’s side has however increased proportionally to *M/m*. In other words, small encodings come at the price of bigger digests. We however continue in this direction: We keep *m* small (a constant *t · n*) and instead we find a way to compress the *N* digests. We rely on a property of our noisy half-succinct construction: Bob’s share consists of product between the digests and the randomness S used in his encoding. We also observe that if Alice and Bob could obtain a secret-sharing of d*i⊗* vec(S) 1 for every *i ∈* [*N*], they would also be able to derive a secret-sharing of Bob’s noisy shares: it would just suffice to apply a local linear operation on the shares. From this we could easily derive a noisy secret-sharing of x *⊗* y (which can be later rounded as we sketched above).

Then, why not to use our half-succinct OTE to derive a secret-sharing of d *′* *⊗* vec(S) where d *′* denotes the concatenation of d₀*,...,*d*N −*1?

With this approach, we may derive a secret-sharing of the output without asking Alice to send messages as big as d *′*. Moreover, if we keep recursing, we may end up with a protocol in which Alice sends a single Merkle hash of x, whereas Bob sends an encoding for each recursive step (at the *i*-th step, Bob encodes the randomness S*i−*1used in the previous level). This technique could even reduce the communication to polylog(*M*)! Alas, we cannot: S is too big. At each recursion step, the size of S increases by a factor of *n · m* and consequently so does the size of Bob’s encodings. We need to find a way to decrease the size of S while preserving the linearity of Bob’s share derivation procedure.

Decreasing the size of S. Instead of sampling a random S, we generate a pseudorandom one using LWE. Specifically, include *m · ℓ* random *n × n* matrices B₀*,...,*B*ℓ·m−*1as part of the setup. $*n* Then, at encoding time, we sample a random vector s *←* Z*q*and we set the *i*-th row of S to be

1 vec(S) denotes the vectorisation of S.

$*λ* B*i·* s + e*i*where e*i← χ*(1). In matrix notation, we obtain that   s  s   *′*
S = B₀*...* B*ℓ·m−*1*·* .  + e₀*...* e*ℓ·m−*1= B *·* (I*m·ℓ⊗* s) + E*.*
| {z}  ..  | {z} B s E*′* | {z} *m·ℓ* times

### The encoding of y becomes

C=A ⊺ *·* B *·* (I*m·ℓ⊗* s) + A ⊺ *·* E *′* +E+I*m⊗* y ⊺ *.*

We also introduce another modification: Instead of sampling the entries of A and B uniformly at random over Z*q*, we sample them uniformly over Z₂. This trick ensures that the magnitude of A ⊺ *·* E *′* remains small, while, at the same time, it does not compromise security: LWE with respect to random *binary* matrices is known to be as hard as standard LWE [BLMR13]. With these modifications to our half-succinct OTE, Alice’s share becomes

v := x ⊺ *·* C = x ⊺ *·* A ⊺ *·* B *·* (I*m·ℓ⊗* s) + x ⊺ *·* A ⊺ *·* E *′* + x ⊺ *·* E + x ⊺ *·* (I*m⊗* y ⊺ ) = x ⊺ *·* A ⊺ *·* B *·* (I*m·ℓ⊗* s) + x ⊺ *·* A ⊺ *·* E *′* + x ⊺ *·* E + (x ⊺ *⊗* y ⊺ )*.*

### Bob’s share becomes instead

w := *−*d ⊺ *·* B *·* (I*m·ℓ⊗* s) = *−*x ⊺ *·* A ⊺ *·* B *·* (I*m·ℓ⊗* s)*.*

This allows us to apply recursion without blowing up the size of s: Since w is a bilinear function of d and s, if the parties hold a “noisy” secret-sharing of d *′* *⊗* s, they can easily convert it into a “noisy” secret-sharing of Bob’s share by computing a local linear operation depending on B. Moreover, since B is a binary matrix, this linear computation will not significantly increase the “noisiness” of the secret-sharing. At each recursion step, the size of d *′* decreases by a factor of *t*(*λ*) := *m/n*; the size of s, on the other hand, remains always the same. The final result is an LWE-based succinct OTE where the digest and the CRS dimensions are poly(*λ*) and the encoding dimension is *O*(log*M*) *· ℓ ·* poly(*λ*).

Succinct MOLEs and VOLEs. No, this paragraph is not about tiny mammals: It’s about two cryptographic primitives called *matrix oblivious linear evaluation* and (non-interactive, half- chosen) *vector oblivious linear evaluation*. In a MOLE, Alice holds a matrix M *∈* Z *m* *q ×ℓ*where *m ≫ ℓ*, whereas Bob holds a secret vector x *∈* Z *ℓq*. Their goal is to derive a secret-sharing of M *·* x in one round and without revealing any information about x. A VOLE corresponds to a MOLE in the special case *ℓ* = 1. We would like to minimize the communication complexity of these protocols, especially in relation to *m*. It is easy to see that the succinct OTE protocol we just presented gives immediately a succinct MOLE where communication scales logarithmically in *m*: First, we use the succinct OTE protocol to compute a secret-sharing of vec(M) *⊗* x, then, we apply local linear operations on the shares to obtain a secret-sharing of M*·*x. Along the way, this solves a question left open in [ARS24]: We have just built the first non-interactive (half-chosen) VOLE with logarithmic communication in *m* from LWE.

Reverse Trapdoor Hashing. We observe that many laconic function evaluation schemes have a particular structure [QWW18,HLL23,DHM + 24,Wee24]. First of all, their digests consist of matrices A*f*with a constant number of columns and a number of rows proportional to the output size of *f*. Moreover, the encoding can be split into two parts: A function-independent pre-encoding *E* and an input-independent post-encoding *c* consisting of an LWE-like sample where the matrix is (essentially) the digest A*f*and the secret s is a random vector generated by the pre-encoding procedure. Finally, the output is computed by rounding the sum *c* + Eval(*E,f*). We observe that, if we ignore the noise, LWE samples are essentially matrix-vector multiplica- tions. Therefore, by relying on the succinct MOLE we just built, the parties can derive a noisy secret-sharing of the post-encoding *c* in a single round of simultaneous interaction and with loga- rithmic communication in the output size of *f*. Moreover, the encoder can send the pre-encoding *E* along with its MOLE message. In this way, the parties can derive a secret-sharing of the output without the need for further interaction. This yields the first rate-1 *reverse* trapdoor hashing scheme. Usually, in rate-1 trapdoor hashing, we obtain a secret-sharing of *f* (*x*) by sending a digest of *x* and generating an encoding key for *f*. In reverse trapdoor hashing, we do the opposite: We send a digest for *f* and an encoding key for *x*. In our construction, the former corresponds to the MOLE hash of A*f*, whereas the latter corresponds to the pre-encoding *E* and the MOLE encoding of s. 2

Adaptive Lattice Encodings. Much of the recent advancement in lattice-based homomorphic cryptography can be traced back to a single technique introduced in 2014 by Boneh et al. [BGG + 14]: + *k×*(*ℓ·k·*log*q*) BGG encodings. Suppose that we are provided with a CRS consisting of a matrix A *∈* Z*q*. A BGG + encoding of a bit string x *∈{*0*,*1*}* *ℓ* consists of the vector

⊺ ⊺ ⊺

|||c = s|· (A − x|⊗ G) + e||
|---|---|---|---|---|---|
||k q|k q||λ||
||||ℓ|||
|f|f,x||f,x ⊺|f||
|f|f|+||||

$ $ where G := I *⊗* g, s *←* Z and e *← χ*(1). These encodings have amazing homomorphic properties: For any function *f* : *{*0*,*1*} → {*0*,*1*}*, there exist efficiently computable, low-norm matrices H and H (independent of the random s and the noise e of the encoding) such that

c *·* H *≈* s *·* (A *− f*(*x*) *·* G)

where A := A *·* H. Alas, BGG encodings are secure only in the selective setting: If x is independent of A, the encoding c looks like a random vector, if, however, x is adaptively chosen after seeing A, there exists an attack that allows us to recover s. To see why, observe that there exists a binary matrix H *′* such that, for any matrix M *∈* Z *k* *q ×k*, if x = Bits(M), we have that

c *·* H *′* *≈* s ⊺ *·* (A *·* H *′* *−* M)*.*

Suppose for convenience that *q* is a power of 2. To recover the *i*-th most significant bit of s, it is sufficient to set M := A *·* H *′* *−* 2 *i* *·* I*k*and compute the most significant bit of c *·* H *′*. This proves that the Adaptive LWE assumption of [QWW18] does not hold in the optimistic parameter setting in which *ℓ* can be arbitrarily bigger than *k*. Notice in the provable parameter setting (where the encodings are secure under the *subexponential* hardness of LWE), our attack fails as the bound on *ℓ* is too small to encode M := A *·* H *′* *−* 2 *i* *·* I*k*. 2 We mention that we can recover the usual notion of trapdoor hashing via universal circuits. On the other hand, the reverse implication does not seem to trivially hold, since the universal circuit would introduce an efficiency penalty in the size of the encoding.

To circumvent the attack without relying on complexity leveraging (and therefore obtain better asymptotic parameters), we introduce a new version of lattice encodings: The encoding of x is now

|||⊺|⊺ ⊺|
|---|---|---|---|
|k|k|λ||
|q|q|||

c = s *·* A + r *·* (x *⊗* G) + e ⊺

$ $ $ where s *←* Z, r *←* Z and e *← χ*(1). We call s *the encryption key* of the encoding, whereas we refer to r as *the authentication key*. We say that c is a (s*,*r)-encoding. Observe that BGG + encodings correspond to the special case in which r = *−*s. It is easy to see also that these encodings are adaptively secure under standard LWE, no matter the value of x and r. The drawback, however, becomes clear when we look at the homomorphic properties of the modified scheme. It is easy to see that the construction is linearly homomorphic, however, we no longer know how to perform multiplications. Or at least, we do not know *when the factors* *are encoded using the same keys*. If instead the authentication key of the first encoding matches the encryption key of the second one, there is a solution: Suppose that we want to multiply the ⊺ ⊺ ⊺ ⊺ ⊺ ⊺ encodings c*x*= s *·* A + r *·* (*x ·* G) + e*x*and c*y*= r *·* B + t *·* (*y ·* G) + e*y*. We observe that

c*z*:= *−*c*x·* G *−*1

(B) + *x ·* c*y≈−*s
⊺ *·* AG *−*1

(B) + t ⊺ *·* (*xy ·* G)*.*
In other words, we have obtained an encoding of *x · y* using s as encryption key and t as authentica- tion key. Moreover, the matrix relative to the encoding is *−*A *·* G *−*1

(B). Notice that this is publicly
computable, no need to know the keys or the plaintexts! To summarise, we are able to compute linear operations between (s*,*r)-encodings obtaining other (s*,*r)-encodings. Moreover, we are able to perform multiplications between (s*,*r)-encodings and (r*,*t)-encodings, obtaining (s*,*t)-encodings as results.

Compressing Adaptive Lattice Encodings. We present a procedure to compress our adaptive lattice encodings, where a compressed encoding of x *∈ {*0*,*1*}* *ℓ* will have size poly(log *ℓ,λ*). By leveraging the knowledge of x, it can then be re-expanded into a standard adaptive encoding. Once again, our techniques rely on our succinct OTE protocol and the (bi)linear structure of Bob’s share derivation. Specifically, the compressed encoding is composed of two parts h and *E*. The former consists of an adaptive lattice encoding of d := OTE*.*Hash(x). Let r be the authentication key of h; then *E* consists of an OTE encoding of a fresh authentication key t where r is used as randomness for *E* (this is secure as h looks random even when r is leaked). We observe that

h *≈* s ⊺ *·* A + r ⊺ *·* (d ⊺ *⊗* G) ⊺ ⊺ ⊺

|= s · A + r|· (d|⊗ I|⊗ g|)|
|---|---|---|---|---|
|⊺|⊺|⊺|q||
|||||⊺|

*k q* = s ⊺ *·* A + (d ⊺ *⊗* r ⊺ *⊗* g)*.*

In other words, h can be viewed as some sort of encoding of d *⊗* r ⊺ where r is the randomness of *E*. Now, Bob’s share of x *⊗* t would be w := P *·* (d *⊗* r), where P is a public low-norm matrix derived from B. Thus, by multiplying h on the right by P, we derive

h *′* := h *·* P *≈* s ⊺ *·* AP + w ⊺ *⊗* g*q.*

Using x and *E*, we can also derive the other share v. We conclude by observing that

|′ ⊺|q ⊺|⊺ ⊺|q|
|---|---|---|---|
||⊺|⊺ ⊺||

h + v *⊗* g *≈* s *·* AP + (x *⊗* t *⊗* g) = s *·* AP + t *·* (x *⊗* G)

We have just obtained a (s*,*t)-encoding of x.

Rate-1 Adaptive LFE. We build our rate-1 adaptive LFE scheme using our compressed adap- tive encodings in two steps: First, we construct a weak variant of (adaptive) reverse TDH for the functions that map pairs (x*,*a) to *f*(x) *⊗* a where *f ∈* NC₁. The scheme satisfies all the security properties of standard reverse TDH, however, in order for correctness to hold, the hasher needs to know x (but not a) for the derivation of her share. On the positive side, the scheme achieves polylogarithmic communication in the size of x (but not a). As a second step, we use our weak reverse TDH to build an adaptive LFE scheme for all depth-*D* functions *f* : *{*0*,*1*}* *m* *→{*0*,*1*}* *ℓ*. The size of the hash will be poly(*λ*) whereas the size of the encoding will be *ℓ* + *m* + *D ·* poly(*λ*).

Step I: a Weak Reverse TDH. We start by describing the weak reverse TDH. Suppose that we want to evaluate functions of depth at most log*d*: Each of them can be converted into an RMS program of depth *d* [BGI16]. We recall that an RMS program consists of an arithmetic circuit over Z where multiplications are allowed only if one of the factors is an input. We start by describing the generation of encoding keys: We sample a chain of *d* keys s₀*,...,*s,

|||d−1|
|---|---|---|
|d|i i i∈[d]|i i|
|i i+1|||
||i||

we set s := a and we generate compressed encodings (h*,E*) so that, when we expand (h*,E*), we obtain a (s*,* s)-encoding of (x*,*1). Notice that we can homomorphically evaluate *f* on these encodings: The operation proceeds by levels, starting from level 1 (the inputs) to level *d* (the output). A level-*i* encoding consists of any (s₀*,* s)-encoding. We observe that (h₀*,E₀*) gives us a level-1 encoding of the inputs. In the previous paragraphs, we showed that the levels are closed under linear operations. More- over, we can also perform multiplications by inputs: If the first factor belongs to level *i*, we can multiply it by the (s*i,* s*i*+1)-encoding of the other factor (the input), which can be derived from (h*i,Ei*). Finally, we can perform hops across levels (always from level *i* to level *i*+ 1) by performing multiplications by 1 3. To summarise, given x and (h*i,Ei*)*i∈*[*d*], Alice is able to derive an encoding

⊺ ⊺ ⊺ c*f≈* s₀ *·* A*f*+ a *·* (*f*(x) *⊗* G) ⊺ ⊺ ⊺ = s₀ *·* A*f*+ (*f*(x) *⊗* a *⊗* g*q*)*.*

To derive a secret-sharing of *f*(x)*⊗*a, it is therefore sufficient that the parties run a succinct MOLE ⊺ to compute a secret-sharing of A *f* *·*s₀ similarly to what we did for the other reverse TDH we built. At that point, it is just a matter of applying local linear computations and rounding.

Step II: Building Rate-1 Adaptive LFE. It is finally time to talk about the rate-1 adaptive LFE scheme. Our approach is the following: We pick a *constant d* and we decompose our function *f* as *fL−*1*◦···◦ f₀* where each *fi*is described by an RMS program of depth *d*. Our goal is to use our reverse TDH to evaluate all *fi*until we obtain the output. The issue is that Bob does not know what input to encode for *fi*. Instead of evaluating *fi*, we evaluate a function that allows us to retrieve the encoding key for x*i*:= (*fi◦···◦ f₀*)(x). Specifically, for every *i ∈* [*L*], define⁴

*f* ˆ *i*: (x*,*a) *7−→* OTE*.*Hash(*fi*(x)) *⊗* a*.*

Suppose that Alice sent a hash for *f*ˆ*i*for every *i ∈* [*L*]. Suppose also that we somehow managed $*k* to find a way to provide Alice with an encoding key for (x*i,* a*i*+1) where a*i*+1*←* Z*q*. Under these premises, the parties can derive an additive secret-sharing y *i* A+1 + y *i* B+1 = d*i*+1*⊗* a*i*+1where

Remember that the expansion of (h*i,Ei*) provides also an (s*i,* s*i*+1)-encodings of 1. In our construction, OTE*.*Hash has depth 0 because it is linear.

d*i*+1= OTE*.*Hash(x*i*+1). We can convert this into a compressed adaptive encoding of x*i*+1by making Bob send ⊺ ⊺ B+1 ⊺ c*i*+1= s *i*+1 *·* A + e *i*+1 + (y*i*) *⊗* g*q* $*k*$*λ* A+1 ⊺ where s*i*+1*←* Z*q*and e*i*+1*← χ*(1). By adding (y *i* ) *⊗*g*q*to c*i*+1, Alice can derived a (s*i*+1*,* a*i*+1)- encoding of d*i*+1. Indeed,

A+1 ⊺ ⊺ B+1 A+1 ⊺ c*i*+1+ (y*i*) *⊗* g*q≈* s *i*+1 *·* A + (y*i*+ y*i*) *⊗* g*q* ⊺ ⊺ ⊺

||||= s|· A + (d||⊗ a ⊗ g|)||
|---|---|---|---|---|---|---|---|---|
|||||i+1 ⊺ i+1|i+1 ⊺ i+1|i+1 ⊺ i+1|q||

*i*+1 *i*+1 *i*+1 *q* = s *·* A + a *·* (d *⊗* G)*.*

Bob can of course send also the other information needed to complete the encoding key for (x*i*+1*,* a*i*+2) as this is independent of *f* and x*i*+1. Notice that the size of all this material that Bob sends is independent of the input size and the output size of *f*. By continuing in this way, the $*k* parties end up with an additive secret-sharing of *f*(x) *⊗* a*L*where a*L←* Z*q*. There is still one matter we need to take care of: In order to perform the operations we just described, Alice needs to know x. So, how can we achieve privacy of the input? The trick is the same as in [BTVW17]: We provide Alice with a GSW [GSW13] encryption of x using a*L*as a secret key (we also send the corresponding encoding key, which is polylogarithmic in size). Then, instead of evaluating *f*, we evaluate *f* *′* := GSW*.*Eval(*f, ·*). At the end, the parties obtain a secret-sharing of Bits(ct) *⊗* a*L*where ct is a GSW encryption of *f*(x). Given that a*L*is the secret-key and the GSW decryption consists of linear operations between a*L*and ct (followed by rounding), the parties can obtain a secret-sharing of *f*(x) by applying only local operations. This immediately gives rate-1 communication in the output. What about rate-1 communication in the input? Well, instead of $*λ* sending a GSW encryption of x, send z := x *⊕* PRG(*K*) for *K ←{*0*,*1*}* and a GSW encryption of

*K*. Then, during the evaluation of *f*
*′*, we remove the one-time-pad inside FHE.

### 1.3 Other Applications

We outline a few additional additional applications of our results. In particular, we discuss some of the new implications from our construction of reverse TDH.

Regular Trapdoor Hash. As an immediate implication of our reverse TDH, we obtain a (reg- ular) TDH [DGI + 19] with close to optimal parameters, that is: The size of the encoding key is *|f |·* poly(*λ,* log*m*) where *|f |* denotes the size of the description of the encoded function and *m* denotes the size of its input. For instance, notice that if *f* is a point function with domain of size *L*, *|f |* = log*L*. We achieve this with a simple application of universal circuits: Instead of hashing a function, we hash the universal circuit *U*xwith the input x hardwired, that on input a function *f*, returns *f*(x). Note that the size of the digest is anyway constant (ignoring factors in the security parameter) so the complexity of the TDH only grows with the bit description of *f*. To our knowledge, this (along with a concurrent work [BJSS25]) is the first trapdoor hashing schemes that support all functions. This is also the first LWE-based TDH constructions achieving nearly optimal communication for a non-trivial class of functions. To our knowledge, the only other construction where the size of the encoding key is sublinear in the dimension of the input is a recently built pairing-based TDH for point functions [BBD]. Such construction, however, pays the succinctness of the encoding key with a non-succinct CRS of size *O*(*m*).

Homomorphic Secret Sharing, Spooky Encryption and Public-Key PCGs. In addition, note that the reconstruction of our reverse TDH is additive over Z₂, thus, a reverse trapdoor hash also implies the existence of a (public-key) 2-party homomorphic secret sharing [BGI16] scheme as follows: Suppose that Alice and Bob respectively hold inputs x and y and they want to evaluate the function *f*. Suppose also that x is much longer than y. Alice proceeds by hashing the function *f*xthat maps any y to *f*(x*,*y). She sends the digest to Bob and keeps the randomness as her part of the share of x. Bob, on the other hand, sends an encoding key ek for y to Alice. He keeps the corresponding trapdoor td as his share of y. By the correctness of reverse TDH, the parties can locally derive a secret sharing of the output. Notice also that the scheme is succinct in x: The total communication of the protocol is *|*y*|·* poly(*λ,* log*|*x*|*)! Previously, succinct homomorphic secret sharing had been built by Abram, Roy and Scholl [ARS24] under several assumptions, including LWE, DCR and DDH over class groups. Their constructions, however, supported only a limited class of functions: Alice and Bob could only compute secret-sharings of x ⊺ *· C*(y) for any circuit *C ∈* NC₁. Their constructions have also a second drawback: The total complexity of the protocol is *|*y*|·|*x*|* *ε* *·*poly(*λ*) for a constant *ε ∈* (0*,*1). Our solution instead scales polylogarithmically in *|*x*|*. On the negative side, unlike [ARS24], our solution does not allow the parties to evaluate a function that is adaptively chosen *after* the secret- sharing phase. We can however plug our MOLE in the constructions of [ARS24] to obtain an HSS scheme that allows the evaluation of any *adaptively* chosen function x ⊺ *· C*(y) with improved communication *|*y*|·* poly(*λ,* log*|*x*|*). Observe that our succinct HSS scheme can be also viewed as a form of 2-party spooky encryption for additively shared correlation [DHRW16] where one of the parties can just send a small hash of its input instead of a full-size ciphertext. Once again, differently from [DHRW16], our construction does not allow us to choose the correlation after we committed to the inputs. Finally, our HSS scheme can have interesting applications in the context of (public-key) pseu- dorandom correlation generators (PCGs) [BCG + 19,OSY21,ASY22], especially when the tackled additively-shared correlation takes a long input from Alice: Let *C*(*x*) be the correlation function $*λ* with long input. Alice can sample *s₀ ←{*0*,*1*}* and hash the function that maps *y* to (*C*(*x*; *ri*))*i∈*[*n*] $*λ* where (*r₀,...,rn−*1) *←* PRG(*s₀⊕y*). Bob instead picks a random *y ←{*0*,*1*}* and sends its encoding to Alice.

Rate-1*/*2 Laconic Oblivious Transfer. Since our construction of reverse TDH also extends to RAM programs, we obtain a new construction of laconic oblivious transfer [CDG + 17] with rate 1*/*2 in the batch settings (which is best possible), where one transfers a set of messages with respect to different indices. The receiver hashes the function *fD*that has hardwired a database *D* and, on input a PRF key *k*, does the following for all indices *i* and all bits *b*:

- If *b* = *Di*: Return 0.
- Else return PRF(*k,i*).
Then the sender, on input a set of indices *I* and pairs of bits *{mi,*0*,mi,*1*}i∈I*, samples a key *k* and $ sends ek *←* Gen(hk*,k*) along with:

*c* *i,b*:= *{*Dec(hk*,*td*,d*)*i,b⊕ mi,b}i,b*

where we slightly abuse the notation and assume that Dec(hk*,*td*,d*)*i,b*returns the (*i,b*)-bit of the share (which can be computed by a RAM program in time independent of the size of the database).

Note that if *b* = *Di*, then Dec(hk*,*td*,d*)*i,b*= Enc(hk*,*ek*,fD,ρ*)*i,b*and therefore the receiver can re- cover *mi,b*. Otherwise the pseudorandomness of PRF guarantees that the message is computationally hidden.

Attribute-Based Non-Interactive Key-Exchange. Finally, reverse TDH implies the exis- tence of a non-interactive key exchange (NIKE) with the following additional property: One of the two parties can include the hash of a function *f* as part of their public key, whereas the other party holds an input x. The NIKE succeeds if *f*(x) = 1 and otherwise the key of either party is computationally indistinguishable from random. This can be constructed from reverse TDH in a natural manner: The former party hashes the function *Ff,k*0that takes as input some x and a key *k₁* and returns 0 if *f*(x) = 1 and PRF(*k₀,*x) *⊕* PRF(*k₁,*x) otherwise. If *f* is satisfied, then both parties hold the same share, that can be used as a shared key, otherwise the pseudorandomness of PRF protects the share of either party.

### 1.4 Concurrent Work

A concurrent work by Boyle et al. [BJSS25] also construct a family of TDHs for all functions *f* : *{*0*,*1*}* *m* *→{*0*,*1*}* *ℓ*, using a similar idea. An important difference is that they rely on the *|*x*|* 2*/*3 - succinct VOLE protocol from [ARS24], whereas we (implicitly) construct a polylog(*|*x*|*)-succinct one, derived from our OTE. This translates in different parameters for the encoding key of the TDH: The encoding key of [BJSS25] has size (*|f |* + *ℓ²* */*3 + *D*) *·* poly(*λ*), whereas in our TDH the encoding key has size *|f |·* poly(*λ,* log*m*), which is close to optimal. Besides TDHs, the results in [BJSS25] are largely orthogonal to ours. We also mention here that plugging in our OTE protocol in [BJSS25] leads to similar parameter improvements for their other applications. For instance, following the outline of [BJSS25], OTE yields a rate-1 fully homomorphic encryption (FHE) with optimal parameters. We fully credit [BJSS25] for discovering the connection, and we sketch here the transformation only for the sake of completeness. Take any FHE scheme with almost-linear decryption [BDGM19], i.e., where decryption is a linear function is the secret key s, followed by a rounding, such as [GSW13]. Then add to the public key an MOLE encoding Enc(s). We can compress *m* ciphertexts (c₁*,...,*c*m*) as follows: Stack them into a matrix C, then compute the MOLE-hash Hash(C), and run the Hash-Eval algorithm, to obtain a additive share of Round(C*·*s) *∈{*0*,*1*}* *m*. Return the hash Hash(C), along with the bits of the share. Decryption works by simply running the Encoder-Eval algorithm of the MOLE, and reconstructing the output. Crucially, the compressed ciphertext consists of a hash (whose size is a fixed polynomial in the security parameter) plus *m* bits, i.e., it is poly(*λ*) +*m*, which is optimal. This improves upon [BDGM19] since the size of the public key does not depend on *m* (no amortization is needed).

## 2 Preliminaries

Notation. We denote the security parameter by *λ*. We say that a function negl(*λ*) is negligible if it vanishes faster than any polynomial, i.e., 0 *≤* negl(*λ*) *≤ λ* *−ω*(1). We say that an event happens with overwhelming probability, if it occurs with probability negligibly close to 1. For any *n ∈* N, we use [*n*] to denote the set *{*0*,*1*,...,n −* 1*}*. All vectors are denoted using lowercase bold font, whereas matrices are denoted using uppercase bold font; by default, all vectors are columns. Given a matrix M, we denote its transpose by M ⊺, whereas vec(M) denotes its vectorisation, i.e., stacking the columns of M one underneath the other. For any *n ∈* N, we denote the *n × n* identity matrix by I*n*and the *n*-dimensional row vector where

all entries are equal to 1 by 1 *n*. We define the Kronecker product between two *n × m* matrices A *⊗* B to be   *a₁,*1B*... a₁,m*B .
.....
. ..  A *⊗* B :=  *.* *an,*1B*... an,m*B

For a vector x, we denote its infinity norm, i.e., the magnitude of its largest coordinate, by *∥*x*∥∞* and we extend this notation to matrices by taking the maximum over their columns. For any integer *q >* 0, let g*q*be the gadget row-vector (1*,*2*,...,*2 log*q* ) and we omit the subscript when clear from the context. Let G *−*1 be the algorithm that takes as input a matrix M *∈* Z *n* *q ×m*and outputs *′* (*n·*log*q*)*×m* a matrix M *∈* Z₂, where each column is derived by stacking the bit-decompositions of the entries in the corresponding column of M. Notice that (I*n q* *−*1

(M) = M. We use Bits(M)

||||⊗ g|) · G|||
|---|---|---|---|---|---|---|
|−1|p|q||||p p|

to denote vec(G *−*1

(M)). Given an integer *x ∈* Z and an integer *p* that divides *q*, we use *⌈x⌋* to
denote rounding to Z, in other words, if *x* = *y · q/p*+ *z* where *z ∈* [*−q/*2*p,q/*2*p*), we have *⌈x⌋* = *y*. We state the following useful lemma about matrices.

Lemma 2.1 (Matrix Linearisation). *There exists a deterministic polynomial-time computable func-* *tion:*

||(qt·ℓ)×m|tq×(m·ℓ)||
|---|---|---|---|
|(t·ℓ)×m q|||m q|
|t|⊺||∞|
|t i∈[ℓ] j∈[m]|⊺ ℓ·h+i,j|i j||

Lin : Z *→* Z

*ℓq* *such that, for any matrix* B *∈* Z *and any pair of vectors* x *∈* Z *and* s *∈* Z*, it holds that:*

Lin(B)(x *⊗* s) = (I *⊗* s)Bx *and ∥*Lin(B)*∥* = *∥*B*∥∞.*

*Proof.* Note that the *h*-th entry of (I *⊗* s)Bx is: X X B *·* (s *·* x)*.*

In other words, there exists a matrix Lin(B), obtained by rearranging the entries of B such that Lin(B)(x *⊗* s) = (I*t⊗* s ⊺ )Bx. Since rearranging the entries does not change the infinity norm, the claim follows.

We also recall the definition of RMS program. Essentially this consists of an algebraic circuit over Z where we can multiply two wires only if at least one of them is an input.

Definition 2.2 (Restricted Multiplication Straightline). *A restricted multiplication straightline* *program (RMS) consists of a polynomial-sized family of algebraic circuits over* Z *where the only* *allowed gates are the following:*

- *Additions: this gate takes as input two wires x and y and outputs their sum x* + *y.*
- *Scalar multiplication: each of these gates is parametrised by a constant α ∈* Z*. It takes as* *input a single wire x and outputs α · x.*
- *Multiplication: this gate takes as input two wires x and y* where *y* is an input to the RMS program*. The output is their product x · y.*
*We say that the program has depth d if the* multiplicative depth *of the program is d.* *Let T be a positive integer. We say that an RMS program is T -bounded if, during any evaluation* *over* binary *inputs, the absolute value of the wires never exceeds T.*

We recall the following result which states that any circuit in NC₁ can be converted into a polynomial size RMS program (paying exponentially in the depth).

Theorem 2.3 ([Bar86,BGI16]). *Let f* : *{*0*,*1*}* *n* *→{*0*,*1*} be described by a boolean circuit of size* *s and depth d made entirely of NAND gates. Then, f can be computed using a* 1*-bounded RMS*

|s and depth d made entirely of NAND gates.|Then, f|can be computed using a 1-bounded RMS|
|---|---|---|
|program of depth at most 2|).||

*d* *and size O*(*s ·* 2 *d*

### 2.1 Lattices and Learning with Errors

Throughout the paper, we often rely on a low-norm distribution *χ*(1 *λ* ) over Z. We say that *χ*(1 *λ* ) is *B*(*λ*)-bounded if: h i $*λ* Pr *|e|≤ B*(*λ*) *e ← χ*(1) = 1*.*

$*λ* Sometimes, we abuse notation and we write v *← χ*(1), even if v is a vector: with this, we mean that each entry of v is sampled from *χ*(1 *λ* ) independently of all the others. We recall the learning with error assumption, introduced for the first time by Regev [Reg05].

Definition 2.4 (Learning with Errors). *Let k* := *k*(*λ*)*, m* := *m*(*λ*) *and q* := *q*(*λ*) *be positive* *integers. Let χ*(1 *λ* ) *be a low-norm distribution over* Z*. We say that the* (*χ,k,m,q*)*-LWE problem* *is hard if, for every PPT adversary A there exists a negligible function* negl(*λ*) *such that, for every* *λ ∈* N*, we have*   $ $

||m|k||
|---|---|---|---|
||q ×k|q|m|
|λ|m λ||q ×k|
||||m|
||||q|
|λ||||

" # M *←* Z*,* s *←* Z$   *λ* M *←* Z Pr   *A*(1*,* M*,*u) = 1 e *←* $ *χ* (1)   *−* Pr *A*(1*,* M*,*u) = 1 $ *≤* negl(*λ*)*.* u *←* Z u *←* M *·* s + e

*Suppose that χ*(1) *is B*(*λ*)*-bounded. We call the quantity α* := *q/B the modulus-noise ratio.*

We also define the *non-uniform LWE* assumption identically as above, except that the matrix M is no longer uniformly random over Z *m* *q ×k*but over Z *m* 2 *×k*. It is shown in [BLMR13] that non- uniform LWE is at least as hard as LWE, with a slightly increased parameter size.

Theorem 2.5 ([BLMR13]). *Assume the hardness of* (*χ,k,m,q*)*-LWE. Then,* (*χ,k ·* log *q,m,q*)*-* *NLWE is hard.*

### 2.2 Laconic Function Evaluation

Definition 2.6 (Laconic Function Evaluation [QWW18]). *Let m* := *m*(*λ*) *and ℓ* := *ℓ*(*λ*) *be* *positive integers. Let F* = (*Fλ*)*λ∈*N*be a function class containing functions f* : *{*0*,*1*}* *m* *→* *{*0*,*1*}* *ℓ* *. A laconic function evaluation scheme (LFE) for F consists of a tuple of PPT algorithms* (Setup*,*Hash*,*Enc*,*Dec) *with the following syntax:*

Setup(1 *λ* ): *The setup algorithm is probabilistic, it takes as input the security parameter* 1 *λ* *and* *outputs a public key* pk*.*

Hash(pk*,f*): *The hashing algorithm is probabilistic, it takes as input a public key and the description* *of a function f ∈Fλ. The output is a digest h and hasher’s private information ψ.*

Enc(pk*,h,x*): *The encoding algorithm is probabilistic, it takes as input a public key* pk*, a digest h* *and an input x ∈{,}* *m* *. The output is an encoding E.*

Dec(pk*,E,f,ψ*): *The decoding procedure is deterministic, it takes as input a public key* pk*, an* *encoding E, a function f ∈Fλand hasher’s private information ψ. The output is a value* *y ∈{*0*,*1*}* *λ* *.*

Definition 2.7 (Correctness of LFE [QWW18]). *Let m* := *m*(*λ*) *and ℓ* := *ℓ*(*λ*) *be positive integers.* *Let F* = (*Fλ*)*λ∈*N*be a function class containing functions f* : *{*0*,*1*}* *m* *→{*0*,*1*}* *ℓ* *. A LFE scheme for* *F* (Setup*,*Hash*,*Enc*,*Dec) *is correct if there exists a negligible function* negl(*λ*) *such that, for every* *sufficiently large λ, every f ∈Fλand every x ∈{*0*,*1*}* *m* *, it holds that:*

Pr [Dec(pk*,E,f,ψ*) *̸*= *f* (*x*)] *≤* negl(*λ*)*,*

$*λ*$ *where the probability is taken over the random choice of* pk *←* Setup(1)*,* (*h,ψ*) *←* Hash(pk*,f*) *and* $ *E ←* Enc(pk*,x*)*.*

Definition 2.8 (Adaptive Encoder Privacy [QWW18]). *Consider the following experiment* AEncExp*A,*Sim(1 *λ* ) *parametrized by an adversary A* = (*A₀, A₁*) *and a simulator* Sim*:*

$*λ*

- *Sample a public key* pk *←* Setup(1)*.*
$*λ*

- *Activate the adversary* (*x,f,* aux) *←A₀*(1*,*pk)*.*
$

- *Compute* (*h,ψ*) *←* Hash(pk*,f*; *r*) *where r denotes freshly sampled randomness.*
$

- *Sample a random bit b ←{*0*,*1*}.*
$ $*λ*

- *If b* = 0 *compute* (*E₀,ϕ₀*) *←* Enc(pk*,h,x*)*, else compute E₁ ←* Sim(1*,*pk*,f,r,f*(*x*))*.*
- *Compute b*
*′* *←A₁*(*Eb,r,* aux)*.*

- *Return* 1 *if and only if b* = *b*
*′* *.*

*We say that an LFE scheme* (Setup*,*Hash*,*Enc*,*Dec) *is adaptively encoder-private if there exists a* *PPT simulator* Sim*, such that for every PPT adversary A, there exists a negligible function* negl(*λ*) *such that, for every λ ∈* N*, we have that:*

<u>1</u> h *λ* i *−* Pr AEncExp*A,*Sim(1 ) = 1 *≤* negl(*λ*)*.* 2

### 2.3 Fully Homomorphic Encryption `a la GSW

We recall the fully homomorphic encryption scheme of [GSW13], which will be used in our rate-1 LFE construction.

- Keys: the secret key and the public key are generated as follows
r M sk := pk :=⊺ ⊺ *−*1 r *·* M + e

$ $ $

|qk− 1|q (k−1)×(k·log q+λ)|λ|⊺|⊺|
|---|---|---|---|---|
|||||k×(k·log q+λ)|
|||||q|

where r *←* Z, M *←* Z and e *← χ*(1). Notice that sk *·*pk = *−*e. Moreover, under LWE, the public key is indistinguishable from a random matrix in Z.

*m*$ (*k·*log*q*+*λ*)*×*(*m·k·*log*q*)

- Encryption: to encrypt a vector x *∈* Z₂, sample R *←* Z₂ and output
ct *←* pk *·* R + x ⊺ *⊗* G

where G := I*k⊗* g*q*. We call *∥*R*∥∞the noise magnitude* of the ciphertext. Notice that in any freshly generated ciphertext, this is equal to 1. Observe that if we substitute pk with a *k×*(*k·*log*q*+*λ*) random matrix in Z*q*, then the ciphertext ct is statistically indistinguishable from random by the Leftover Hash Lemma [ILL89].

- Decryption: suppose we have a ciphertext ct = pk*·*R + y
⊺ *⊗*G where the noise magnitude is *∥*R*∥∞*= *α* and y *∈{*0*,*1*}* *ℓ*. Let u be the last vector of the standard basis of Z *k*

*q*. To recover
y, we compute

*′*<u>q</u>

|⊺|ℓ −1||||
|---|---|---|---|---|
|⊺|ℓ|−1||⊺ ⊺|
|⊺|ℓ|−1||⊺ ⊺|
|⊺|ℓ|−1||⊺ ⊺|
|⊺|⊺|ℓ −1|||
|⊺ ′|ℓ −1|2 q|∞||

y :=sk *·* ct *·* I *⊗* G *− ·* u 2 <u>q</u>*−*1<u>q</u> =sk *·* pk *·* R *·* I *⊗* G *− ·* u + sk *·* (y *⊗* G) *·* I*ℓ⊗* G *− ·* u 2 2 <u>q q</u> = *−* e *·* R *·* I *⊗* G *− ·* u *− ·* sk *·* (y *⊗* u) 2 2 <u>q q</u> = *−* e *·* R *·* I *⊗* G *− ·* u *− ·* y *⊗* (sk *·* u) 2 2 <u>q q</u> = *·* y *−* e *·* R *·* I *⊗* G *− ·* u*.* 2 2

Notice that *∥*e *·* R *·* I *⊗* G *− ·* u *∥ ≤ k · α · B*. So, if *q* is sufficiently big (in particular, bigger than 4*k · α · B*, we are able to recover y by computing the most significant bit of the entries of y.

- Homomorphic evaluation: there exists a deterministic polynomial-time algorithm GSW*.*Eval that, on input a function *f* : *{*0*,*1*}*
*m* *→{*0*,*1*}* *ℓ* and an encryption of a string x *∈{*0*,*1*}* *m*, produces an encryption of *f*(x). The operation, however, increases the magnitude of the noise proportionally to the number of operations required by *f*. In particular, there exists a limit after which the magnitude of the noise is so high that decryption fails.

There exist multiple ways in which GSW*.*Eval can be instantiated and not all of them are equivalent in the way they manage to keep the noise magnitude low. In this paper, we use the approach of Brakerski and Vainkuntanathan [BV14] which makes the noise magnitude grow linearly in the depth of the evaluated circuit.

## 3 Non-Interactive Oblivious Tensor Evaluation

In the following we define and construct a succinct Non-Interactive Oblivious Tensor Evaluation (NI-OTE) protocol.

### 3.1 Definitions

We begin by defining the syntax of NI-OTE.

Definition 3.1 (Non-interactive oblivious tensor evaluation). *Let m* := *m*(*λ*)*, ℓ* := *ℓ*(*λ*)*, and* *q* := *q*(*λ*) *be a positive integer. A NI-OTE for* Z *m* *q⊗* Z *ℓq* *consists of a tuple of PPT algorithms* (Setup*,*Hash*,*Enc*,*HashEval*,*EncEval) *with the following syntax:*

Setup(1 *λ* ): *The setup algorithm is probabilistic, takes as input the security parameter* 1 *λ* *and outputs* *a public key* pk*.*

Hash(pk*,*x): *The hashing algorithm is probabilistic and takes as input a public key* pk *and the* *description of a vector* x *∈* Z *m*

*q. The output is a digest d and hasher’s private information ψ.*
Enc(pk*,*y): *The encoding algorithm is probabilistic and takes as input a public key* pk*, and a vector* y *∈* Z *ℓq* *. The output is an encoding E and encoder’s private information ϕ.*

HashEval(pk*,E,ψ*): *The hasher’s evaluation algorithm is deterministic and takes as input a public* *key* pk*, an encoding E and hasher’s private information ψ. The output is a vector* v *∈* Z *m* *q ·ℓ.*

EncEval(pk*,d,ϕ*): *The encoder’s evaluation algorithm is deterministic and takes as input a public* *key* pk*, a digest d and encoder’s private information ϕ. The output is a vector* w *∈* Z *m* *q ·ℓ.*

Sometimes it will be convenient for us to fix the private information *ϕ* and provide it as an input to the encoding algorithm. In a slight abuse of notation, we denote this by Enc(pk*,* y*,* [*ϕ*]), in which case, the algorithm just outputs *E*. If the NI-OTE scheme satisfies this syntactical requirement, which in particular means that *ϕ* does not depend on y, we say that the scheme is *programmable*. Additionally, we say that an NI-OTE has a *bilinear encoder evaluation* if:

- The digest *d* is a vector in Z
*n*

*q*.
- The encoder secret information *ϕ* is a vector in Z
*k*

*q*.
- The encoder evaluation algorithm consists of
EncEval(pk*,d,ϕ*) := P *·* (*d ⊗ ϕ ⊗* g*q* ⊺ )

(*m·ℓ*)*×*(*n·k·*log*q*) where the matrix P *∈* Z*q* can be publicly derived from pk.

We say that an NI-OTE is *succinct* if the size of the hash and the size of the encodings are sublinear in the size of the hasher’s input. Depending on the context, we will make the dependence explicit. If only the hash is sublinear, then we say that the scheme is *half-succinct*.

Correctness. Next, we define (approximate) correctness for an NI-OTE, parametrized by an error function *α*. If *α* = 0, then we say that the NI-OTE is perfectly correct, or simply correct.

Definition 3.2 (*α*-Correctness). *An NI-OTE scheme* (Setup*,*Hash*,*Enc*,*HashEval*,*EncEval) *is α-* *correct if there exists a negligible function* negl(*λ*) *such that, for every sufficiently large λ ∈* N*, for* *every* x *∈* Z *m* *qand* y *∈* Z *ℓq* *, we have that:*

Pr [*∥*HashEval(pk*,E,ψ*) + EncEval(pk*,d,ϕ*) *−* x *⊗* y*∥∞> α ·∥*x*∥∞*] *≤* negl(*λ*)

$*λ*$ *where the probability is taken over the random choice of* pk *←* Setup(1)*,* (*d,ψ*) *←* Hash(pk*,*x)*, and* $ (*E,ϕ*) *←* Enc(pk*,*y)*.*

The definition of approximate correctness will be sufficient for our applications. Nevertheless, for future reference, we mention here that there is a general (standard) method to drive the correctness error down to *α* = 0, which may be more convenient to work with. Specifically, let *p* to be a divisor of *q* with *p/q ∈ λ* *−ω*(*λ*). Instead of encoding y, one encodes *q/p ·*y. Then, we return HashEval(pk*,E,ψ*)

and EncEval(pk*,d,ϕ*) rounded to the nearest multiple of *q/p*. By the *α*-correctness guarantee of the protocol, it holds that:

HashEval(pk*,E,ψ*) + EncEval(pk*,d,ϕ*) = *q/p ·* y *⊗* x *± α ·∥*x*∥∞.*

Rounding to the nearest multiple of *q/p* returns: l k *q/p ·* y *⊗* x *± α ·∥*x*∥∞*= *⌈q/p ·* y *⊗* x*⌋p*= y *⊗* x (mod*p*) *p*

### with high probability.

Encoder Privacy. We define encoder privacy, which guarantees that the encoding is simulatable, without knowing the underlying vector. This is formalized as follows.

Definition 3.3 (Encoder Privacy). *Consider the following experiment* EncExp*A,*Sim(1 *λ* ) *parametrized by an adversary A* = (*A₀, A₁*) *and a simulator* Sim*:* $*λ*

- *Sample a public key* pk *←* Setup(1)*.*
$*λ*

- *Activate the adversary* (y*,*aux) *←A₀*(1*,*pk)*.*
$

- *Sample a random bit b ←{*0*,*1*}.*
$ $*λ*

- *If b* = 0 *compute* (*E₀,ϕ₀*) *←* Enc(pk*,*y)*, else compute E₁ ←* Sim(1*,*pk)*.*
- *Compute b*
*′* *←A₁*(*Eb,*aux)*.*

- *Return* 1 *if and only if b* = *b*
*′* *.*

*We say that a non-interactive OTE scheme* (Setup*,*Hash*,*Enc*,*HashEval*,*EncEval) *is encoder-private* *if there exists a PPT simulator* Sim*, such that for every PPT adversary A, there exists a negligible* *function* negl(*λ*) *such that, for every λ ∈* N*, we have that:*

<u>1</u> h *λ* i *−* Pr EncExp*A,*Sim(1 ) = 1 *≤* negl(*λ*)*.* 2

### 3.2 Half-Succinct NI-OTE from LWE

We present our first NI-OTE protocol that only satisfies a weak form of succinctness, namely that only the size of the digest is sublinear in the size of the hasher’s input. Let *n* := *k ·* log*q*, where *k* = Θ(*λ*), and suppose that for convenience that *q* is a power of 2. Our protocol is described in Construction3.4. Construction 3.4. Half-Succinct NI-OTE

*λ*$ *n×m* $ *n×*(*m·ℓ·n*) Setup(1): Sample A *←* Z₂ and B *←* Z₂, then return pk := (A*,*B).

Hash(pk*,*x): Compute d := A *·* x and return *d* := d and *ψ* := x.

$ˆ$ $

|k|′||
|---|---|---|
|q|||
|⊺|q⊺|⊺ ′|

Enc(pk*,*y): Sample s *←* Z, E *← χ*(*λ*), and E *← χ*(*λ*). Compute

C := A *·* B *·* (I*m·ℓ⊗* s *⊗* g) + A *·* E + Eˆ + I*m⊗* y ⊺ *.*

Return *E* := C and *ϕ* := s.

⊺ HashEval(pk*,E,ψ*): Return v := C *·* x.

⊺ ⊺ EncEval(pk*,d,ϕ*): Return w := *−*(I*m·ℓ⊗* s *⊗* g*q*) *·* B *·* d.

The scheme is trivially programmable, since *ϕ* consists of a uniformly sampled vector s that in particular is independent from y. Then, we observe that the scheme has indeed a bilinear encoding evaluation algorithm. By Lemma2.1, it holds that:

⊺ ⊺ ⊺ ⊺ *−*(I*m·ℓ⊗* s *⊗* g*q*) *·* B *·* d = Lin(*−*B)(d *⊗* s *⊗* g*q*) (1)

⊺ ⊺ with *∥*Lin(*−*B)*∥∞*= *∥−*B *∥∞≤* 1. We can also bound the norm of the digest by

*∥*d*∥∞*= *∥*A *·* x*∥∞≤ m ·∥*A*∥∞·∥*x*∥∞≤ m ·∥*x*∥∞*(2)

with a triangle inequality. Finally, it is easy to see that the scheme is half succinct, since the hash d is *n*-dimensional vector over Z*q*, whose size is in particular independent of the length of x and y. On the other hand, the encoding consists of an *m ×* (*m · ℓ*) matrix over Z*q*. Next, we argue that the scheme satisfies approximate correctness. Indeed, let us rewrite

|||⊺|m ⊺|
|---|---|---|---|
|q ⊺|⊺ ⊺ ⊺|⊺ ′ ⊺ ⊺ ⊺|m ⊺|
|′|⊺|⊺ ′|⊺ ′|
|||∞||

C=A *·* Z+Ee + I *⊗* y*,*

where Z := B *·* (I*m·ℓ⊗* s *⊗* g) and Ee := A *·* E + Eˆ. Substituting, we obtain

v + w = C *·* x *−* Z *·* d ⊺ = (Z *·* A) *·* x + Ee *·* x + (I *⊗* y) *·* x *−* Z *·* d

= Z *·* d + Ee *·* x + x *⊗* y *−* Z *·* d

= x *⊗* y + Ee *·* x*.*

Since A is a matrix in Z₂ with *n* rows, the entries of Ee = A *·* E + Eˆ is obtained by adding at most *n* + 1 entries of the vectors E and Eˆ, which are *B*(*λ*)-bounded. In other words,

A *·* E + Eˆ *≤* (*n* + 1) *· B*(*λ*)*.*

Therefore we can bound the correctness error by

Ee⊺*·* x *≤ m ·* (*n* + 1) *· B*(*λ*) *·∥*x*∥* (3) *∞.* *∞*

with a triangle inequality. Finally, we show that the scheme satisfies encoder privacy.

Theorem 3.5 (Encoder Privacy). *Assuming the hardness of LWE, Construction3.4satisfies en-* *coder privacy.*

*Proof.* Consider the following sequence of hybrids.

- Hybrid *H₀*: This is the original distribution.
- Hybrid *H₁*: We define
⊺ ⊺ C := A *·* U+Eˆ + (I*m⊗* y) $ *n×*(*m·ℓ*) where U *←* Z*q*.

We claim that this hybrid is indistinguishable from the previous once, by the LWE assumption. To see why, observe that the encoding provided to the adversary in the previous hybrid equals:

C=A ⊺ *·* U+Eˆ + (I*m⊗* y ⊺ )*,*

⊺ *′*ˆ$*′*$ where U := B *·* (I*m·ℓ⊗* s *⊗* g*q*) + E for E *← χ*(*λ*) and E *← χ*(*λ*). This last term consists ⊺ of an LWE sample with secret s and public matrix obtained by splitting B *·* (I*m·ℓ·k⊗* g*q*) in *m · ℓ* blocks in Z *n* 2 *×k* and stacking them one underneath the other. (*n·m·ℓ*)*×k* In more details, consider a reduction that receives a matrix M *∈* Z*q* and a vector u *∈* Z *n* *q ·m·ℓ*that is either an LWE sample with respect to M or a uniformly random vector. The reduction splits the rows of M into *ℓ · m* blocks in Z *n* *q ×k*, denoted by   M₀ . ..  M= *.* M*m·ℓ−*1

*−*1 ⊺ ⊺ *n×n* For every *j ∈* [*m · ℓ*], set B*j*:= G (M *j* ). Notice that B*j*is a random matrix over Z₂, since M*j*is uniformly sampled and *q* is a power of 2. Finally, construct B as

### B = (B₀,...,Bm·ℓ−1)

and generate the columns in U by splitting u into *m · ℓ* vectors in Z *n*

*q*. Then set C to
A ⊺ *·* U+Eˆ + (I*m⊗* y ⊺ ).

$ (*m*)*×*(*m·ℓ*)

- Hybrid *H₂*: We sample C *←* Z*q*. Indistinguishability from the previous hybrid follows by another reduction to the LWE prob- lem. Indeed, notice that A
⊺ *·*U+Eˆ is a batch of *m · ℓ* LWE samples with A ⊺ as public matrix. The LWE secrets consist of the columns of U. $ (*m*)*×*(*m·ℓ*) The proof is concluded by defining the simulator Sim to output a uniformly random C *←* Z*q* as the encoding.

### 3.3 Bootstrapping to Fully-Succinct NI-OTE

We now show a bootstrapping procedure to turn the NI-OTE constructed in Section3.2into a fully

|m ℓq||r||
|---|---|---|---|
|q|||tq·n n|
||n q|k q|q|

succinct NI-OTE for Z *⊗* Z. We assume that *m* := *t · n*, for some *t,r ∈* Z, and we assume the existence of a half-succinct *α*-correct hOTE = (Setup*,*Hash*,*Enc*,*HashEval*,*EncEval) for Z *⊗* Z with bilinear encoder evaluation, where *d ∈* Z and *ϕ ∈* Z, with *n* := *k ·* log*q*. We describe our scheme in Construction3.6.

### Construction 3.6. Fully Succinct NI-OTE

*λ*$*λ* Setup(1): Return pk *←* hOTE*.*Setup(1).

Hash(pk*,*x): Set x₀ := x. Then for every *i ∈* [*r*] proceed as follows:

- Parse x *r−i−*1) where x

|as the vertical concatenation of (x|,..., x|∈ Z.|
|---|---|---|
|i r−i−1|i,1 i,t|i,j tq·n|

- For every *j ∈* [*t*], compute
$ (d*i,j,ψi,j*) *←* hOTE*.*Hash(pk*,* x*i,j*)*.*

- Define x*i*+1to be the vertical concatenation of the d*i,j*.
Return *d* := x*r*and *ψ* := *{ψi,j}i∈*[*r*]*,j∈*[*tr−i−*1].

Enc(pk*,*y): Set y₀ := y, then for *i ∈* [*r*], compute

$⊺ (*Ei,ϕi*+1) *←* Enc(pk*,* y*i*) and y*i*+1:= *ϕi*+1*⊗* g*q*

Output *E* := *{Ei}i∈*[*r*]and *ϕ* := *ϕr*.

HashEval(pk*,E,ψ*): Let P be the public matrix derived from pk. For all *i ∈* [*r*] and *j ∈* [*t* *r−i−*1], compute

|P := (I|and|v := hOTE.HashEval(pk,E|,ψ|).||
|---|---|---|---|---|---|
|i t||i,j|i i,j|||
|i|r −1 i|i,j j∈[t|i∈[r] r|i k=1|k i|
||i=1|||||

*r−i ⊗* P) P Q Let v*i*be the vertical concatenation of *{*v*} r−i−*1]. Return v := P *·*v.

EncEval(pk*,d,ϕ*): Let P be defined as above. Return ! Y w := P *·* hOTE*.*EncEval(pk*,d,ϕ*)*.*

The scheme is clearly programmable, if the underlying hOTE is. Furthermore, note that the scheme maintains a bilinear encoder evaluation, since, by Equation (1) we have that: ! *r* Y *−*1 EncEval(pk*,d,ϕ*) = (4)

||P|· P · (d ⊗ ϕ ⊗ g|).||
|---|---|---|---|---|
||i||q⊺||
|r −1|i=1 i|n ×(t·n q r|)|∞|
|i=1|∞||||
|||||i,j|
|∞ r|∞|r ∞|||

2 2 To bound the norm of the public matrix, recall that P *∈* Z and *∥*P*∥ ≤* 1. So, for every *i ∈* [*r*], each row of P*i*= (I*tr−i ⊗* P) has at most *n²* non-zero entries. Thus, multiplying by P*i* increases the infinity norm at most by a factor *n²*. Thus we have that:

Y P *·* P *≤ n².* (5)

On the other hand, we can bound the norm of the digest by recalling that x *∈* Z *tq·n* and by Equation (2) the norm of the digest is increased by a factor *t · n* each time it is hashed. Thus:

*∥d∥* = *∥*x *∥ ≤* (*tn*) *·∥*x*∥.* (6)

Furthermore, the dimension of the digest is *n*, and therefore independent of the dimensions of the input vector, and its bit-length is at most *n ·* (*r ·* log *tn* + log*∥*x*∥∞*). The size of the encoding is *r* = *O*(log*m*) times the size of an encoding of hOTE (whose size is independent of *m*). Thus, the scheme is fully succinct.

Approximate Correctness. Towards proving approximate correctness, we begin by observing that, by the *α*-correctness of hOTE, for every *i ∈* [*r*] and *j ∈* [*t* *r−i−*1], we have:

hOTE*.*EncEval(pk*,* d*i,j,ϕi*+1) + hOTE*.*HashEval(pk*,Ei,ψi,j*) = x*i,j⊗* y*i*+ e*i,j,* (7)

where *∥*e*i,j∥∞≤ α ·∥*x*i,j∥∞≤ α ·∥*x*i∥∞*= *tn*(*n* + 1)*B*(*λ*) *·∥*x*i∥∞*, by Equation (3). To establish correctness, it suffices to prove the following.

Lemma 3.7 (Approximate Correctness). *For every i ∈* [*r*]*:*

|||!||!||
|---|---|---|---|---|---|
||r−1 j=i|j k k=1|j|i k k=1|i i|
|i ∞|r−1 k=i|3 k|∞|||

X Y Y P *·* v + w = P *·* (x *⊗* y) + ee*i*

P *where ∥*ee *∥ ≤ α ·* (*t · n*) *·∥*x*∥.*

Before proceeding with the proof, we can indeed see that, setting *i* = 0, we obtain:

v + w = (x *⊗* y) + e

where *∥*e*∥∞≤ α ·* (*t · n³*) *r* *·∥*x*∥∞*. Thus, the scheme satisfies *α*(*t · n³*) *r* -correctness.

*Proof.* We proceed by induction on the index *i*, starting from *i* := *r −*1. For the base case, we have We proceed by induction starting from *i* = *r −* 1 and going all the way down to *i* = 0. It is easy to see that v*r−*1= hOTE*.*HashEval(pk*,Er−*1*,ψr−*1*,*0), whereas *d* = d*r−*1*,*0. Therefore, by Equation (7), we obtain: !! *r* Y *−*1 *r* Y *−*1 P*k·* v*r−*1+ w = P*k·* hOTE*.*HashEval(pk*,Er−*1*,ψr−*1*,*0) + hOTE*.*EncEval(pk*,d,ϕr*) *k*=1 *k*=1 !! *r* Y *−*1 *r* Y *−*1 = P*k·* (x*r−*1*,*0*⊗* y*r−*1) + P*k·* e*r−*1*,*0 *k*=1 *k*=1 ! *r* Y *−*1 = P*k·* (x*r−*1*⊗* yr*−*1) + ee*r−*1 *k*=1 Q *r−*1 where ee*r−*1:= *k*=1 P*k·* e*r−*1*,*0. Notice that

*∥*ee*r−*1*∥∞≤* (*n²*) *r−*1 *·∥*e*r−*1*,*0*∥∞≤* (*n²*) *r−*1 *· α ·∥*x*r−*1*∥∞≤ α ·* (*t · n³*) *r−*1 *·∥*x*∥∞*

by Equation (5) and Equation (6). Then, by induction hypothesis: !

||||!|||!|||
|---|---|---|---|---|---|---|---|---|
|r−1|j k|i−1|k|i−1|i|k|i|i i|
|j=i−1|k=1|k=1|||k=1||||
|||i−1|k|i−1|i|i|i|i|
|||k=1|||||||

X Y Y Y P *·* v*j*+ w = P *·* v + P *·* (x *⊗* y) + ee

! Y = P *·* v + P *·* (x *⊗* y) + ee*.*

Moreover:  ⊺    P *·* (d*i−*1*,*0*⊗ ϕi⊗* g*q*) hOTE*.*EncEval(pk*,* d*i−*1*,*0*,ϕi*)  P *·* (d *i−*1*,*1*⊗ ϕi⊗* g*q* ⊺ )   hOTE*.*EncEval(pk*,* d*i−*1*,*1*,ϕi*)      P*i·* (x*i⊗* y*i*) = . =. *.* ..  ..  ⊺ P *·* (d*i−*1*,tr−i ⊗ ϕi⊗* g*q*) hOTE*.*EncEval(pk*,* d*i−*1*,tr−i,ϕi*)

We also observe that:     v*i−*1*,*0hOTE*.*EncHash(pk*,Ei−*1*,ψi−*1*,*0)  v *i−*1*,*1   hOTE*.*EncHash(pk*,E* *i−*1*,ψi−*1*,*1)      v*i−*= . =. *.* ..  ..  v*i−,tr−i* hOTE*.*EncHash(pk*,Ei−,ψi−,tr−i*)

Furthermore, by Equation (7), we have:     (x*i−*1*,*0*⊗* y*i−*1) + e*i−*1*,*0e*i−*1*,*0  (x *i−*1*,*1*⊗* y*i−*1) + e*i−*1*,*1   e *i−*1*,*1      v*i−*1+P*i·*(x*i⊗*y*i*) = .  = (x*i−*1*⊗*y*i−*1)+e*i−*1*,* where e*i−*1:= . *.* ..  ..  (x*i−*1*,tr−i ⊗* y*i−*1) + e*i−*1*,tr−i* e*i−*1*,tr−i*

Notice that *∥*e*i−*1*∥∞≤ α ·∥*x*i−*1*∥∞≤ α ·* (*tn*) *i−*1 *·∥*x*∥∞*by Equation (5) and Equation (6). We conclude that!! X *r−*1 Y *j* Y *i−*1 P*k·* v*j*+ w = P*k·* (x*i−*1*⊗* y*i−*1) + ee*i−*1 *j*=*i−*1 *k*=1 *k*=1 Q *i−*1 where ee*i−*1:= ee*i*+ *k*=1 P*k·* e*i−*1. Observe that

! X *r−*1 *∥*ee*i−*1*∥∞≤∥*ee*i∥∞*+ *α ·* (*t · n³*) *i−*1 *·∥*x*∥∞≤ α ·* (*t · n³*) *k* *·∥*x*∥∞* *k*=*i−*1

as desired.

Encoder Privacy. The following theorem establishes encoder privacy.

Theorem 3.8. *Assuming that* hOTE *is encoder private, Construction3.6is encoder private.*

*Proof.* The proof follows by a standard hybrid argument, where we gradually substitute the encod- ings *{Ej}j∈*[*r*]with the outputs of the simulator Sim(1 *λ* *,*pk), provided by the definition of encoder privacy of hOTE.

How to Build a Fully Succinct OTE for Z *m* *q⊗*Z *ℓq*. Construction3.6presents a non-interactive OTE for Z *m* *q⊗*Z *n* *q*where the hash size is a vector in Z *n* *q*and the encoding consists of *r* matrices of size (*tn*) *×* (*tn²*). A trivial way to build a fully succinct OTE for Z *m* *q⊗* Z *ℓq* is to instantiate Construction

3.6with *n* := *ℓ*. If *ℓ* = *O*(*λ ·* log*q*), this is secure, however, the encoder size would scale as *r · ℓ³* while the hash size would be linear in *ℓ*. We can do better: just split y into blocks y₀*,...,*y*N*of size *n*. Then, compute an OTE encoding of each of them using Construction3.6and send them to the hasher. Given the hasher’s digest (notice, a single digest is sufficient for all y₀*,...,*y*N*), we can then derive shares for x *⊗* y₀*,...,*x *⊗* y*N*. By reordering these, we obtain a secret-sharing of x *⊗* y. In this way, the digest dimension is *n*, while the encoding dimension is *ℓ · r · t² · n²*.
### 3.4 From Succinct NI-OTE to Succinct NI-MOLE

We will also consider an modification of NI-OTE where instead of computing a tensor product, we compute a matrix-vector product. More specifically, we let the hasher take as input a matrix M and the encoder a vector y and we require that

### HashEval(pk,E,ψ) + EncEval(pk,d,ϕ) ≈ My.

Furthermore, we require the protocol to be succinct, in the sense that the communication complexity should be independent of the number of rows of the matrix M. We refer to this protocol as Non- Interactive Matrix Oblivious Linear Evaluation (NI-MOLE).

It is easy to see that one can generically construct an (*ℓ · α*)-correct NI-MOLE from an *α*-correct NI-OTE: Simply hash x := G *−*1 (vec(M)) and encode y *⊗* g*q*. Then the hasher and the encoder return Lin(I*m·ℓ·*log*q*) *·* HashEval(pk*,E,ψ*) and Lin(I*m·ℓ·*log*q*) *·* EncEval(pk*,d,ϕ*)

respectively. By the correctness of the NI-OTE we have:

||) · (x ⊗ y ⊗ g|) + Lin(I|
|---|---|---|
|m·ℓ·log q||q⊺|
|m ⊺|q|m·ℓ·log q|
|m ⊺|⊺ m·ℓ·log q|m·ℓ·log q|

v + w = Lin(I*m·ℓ·*log*q*) *·* e

= (I *⊗* y *⊗* g) *·* x + Lin(I) *·* e = (I *⊗* y) *·* vec(M) + Lin(I) *·* e = M *·* y + Lin(I) *·* e *≈* M *·* y

ignoring low-order error terms, since *∥*Lin(I*m·ℓ·*log*q*)*∥∞*= 1 by Lemma2.1. Notice that

*∥*Lin(I*m·ℓ·*log*q*) *·* e*∥∞≤ ℓ · α ·∥*x*∥∞*= *ℓ · α.*

Thus, henceforth we will assume the existence of succinct NI-OTE and succinct NI-MOLE inter- changeably, with the understanding the succinct NI-OTE implies the existence of both.

## 4 Adaptive Lattice Encodings

In the following we present our new construction of adaptive lattice encodings. Let *k* := *k*(*λ*) and *q* := *q*(*λ*) be positive integers, and let G be the *k*-dimensional gadget matrix G := I *⊗* g. For

|||k q|
|---|---|---|
|k q|k×(k·log q) q||
|A|⊺||

*k·*log*q* element *x ∈* Z*q*, vectors s*,* r *∈* Z, matrix A *∈* Z and noise term e *∈* Z, we define the corresponding *adaptive lattice encoding* as:

LEnc (*x*; s*,* r*,*e) := s A + *x ·* r ⊺ G + e ⊺ *.*

Note that, for an appropriately sampled A, s, and e. It is straightforward to see that the encod- ing is computationally close to uniform under the LWE assumption. Next, we demonstrate the homomorphic properties of such encodings.

### 4.1 Homomorphic Operations

We show that our lattice encodings support addition, scalar multiplication, and even multiplication, provided that the encodings are encrypted with correlated secrets. We present a formal description of the algorithms below. Construction 4.1. Homomorphic Operations on Lattice Encodings

||q|k q||k×(k·log q) q||
|---|---|---|---|---|---|
|k·log q||||||
|q||||||
|A k·log q q|A|q|A +A k q||k×(k·log q) q|
|A|−1|A·G||−1|⊺|

Addition: For every *x₀,x₁ ∈* Z, vectors s*,* r *∈* Z, matrices A₀*,*A₁ *∈* Z and noise terms e₀*,*e₁ *∈* Z, we have:

LEnc0(*x₀*; s*,* r*,*e₀) + LEnc1(*x₁*; s*,* r*,*e₁) = LEnc0 1(*x₀* + *x₁*; s*,* r*,*e₀ + e₁)*.*

Scalar Multiplication: For every *x,δ ∈* Z, vectors s*,* r *∈* Z, matrix A *∈* Z and noise terms e *∈* Z, we have:

LEnc (*x*; s*,* r*,*e) *·* G (*δ ·* G) = LEnc *−*(*δ·*G)(*x · δ*; s*,* r*,* G (*δ ·* G) *·* e)*.*

|||q|k q|k×(k·log q) q|
|---|---|---|---|---|
||k·log q||||
||q||||
|A|||A −1 ⊺||
|−A|·G (A|)|||

Multiplication: For every *x₀,x₁ ∈* Z, vectors s₀*,*s₁*,*s₂ *∈* Z, matrices A₀*,*A₁ *∈* Z and noise terms e₀*,*e₁ *∈* Z, we have:

*−* LEnc0(*x₀*; s₀*,*s₁*,*e₀) *·* G *−*1 (A₁) + *x₀ ·* LEnc1(*x₁*; s₁*,*s₂*,*e₁)

= LEnc 0 *−*1 1 (*x₀ · x₁*; (s₀*,*s₂*, −*G (A₁) *·* e₀ + *x₀ ·* e₁))*.*

We elaborate on the correctness of the claimed homomorphic operations. For addition, we observe that: ⊺ ⊺ ⊺ ⊺ ⊺ ⊺ LEncA0(*x₀*; s*,* r*,*e₀) + LEncA1(*x₁*; s*,* r*,*e₁) = s

|A₀ + x₀ · r|G + e₀|+ s|A₁ + x₁ · r|G + e₁|
|---|---|---|---|---|
|⊺ A +A|||⊺|⊺ ⊺|

⊺ ⊺ ⊺ ⊺ = s *·* (A₀ + A₁) + (*x₀* + *x₁*) *·* r G + (e₀ + e₁) = LEnc0 1(*x₀* + *x₁*; s*,* r*,*e₀ + e₁)*.*

### For scalar multiplication, we have:

LEncA(*x*; s*,* r*,*e) *·* G *−*1 (*δ ·* G) = s ⊺ AG *−*1 (*δ ·* G) + *x ·* r ⊺ GG *−*1 (*δ ·* G) + e ⊺ G *−*1 (*δ ·* G)

= s ⊺ *−*1 ⊺ ⊺ *−*1

|AG|(δ · G) + (x · δ) · r|G + e|G (δ · G)||
|---|---|---|---|---|
|||−1|⊺||
|A·G|(δ·G)||||

= LEnc *−*1 (*x · δ*; s*,* r*,* G (*δ ·* G) *·* e)*.*

### Finally, for homomorphic multiplication, we have:

*−* LEncA0(*x₀*; s₀*,*s₁*,*e₀) *·* G *−*1 (A₁) + *x₀ ·* LEncA1(*x₁*; s₁*,*s₂*,*e₁) ⊺ ⊺ ⊺ *−*1 ⊺ ⊺ ⊺ = *−*(s₀A₀ + *x₀ ·* s₁G + e₀) *·* G (A₁) + *x₀ ·* (s₁A₁ + *x₁ ·* s₂G + e₁) ⊺ *−*1 ⊺ ⊺ ⊺ ⊺ *−*1 ⊺ = s₀ *·* (*−*A₀G (A₁)) *− x₀ ·* s₁A₁ + *x₀ ·* s₁A₁ + (*x₀ · x₁*) *·* s₂G *−* e₀G (A₁) + *x₀ ·* e₁

= LEnc*−*A 0 *·*G*−*1(A1)(*x₀ · x₁*; (s₀*,*s₂*, −*G *−*1 (A₁) ⊺ *·* e₀ + *x₀ ·* e₁))*.*

Evaluating RMS Programs. From the homomorphic operations described above, one can de- rive a general routine to evaluate any *T*-bounded (i.e., the maximum norm of an intermediate variable of the computation is bounded by *T*) RMS program of depth *d*. Recall that in an RMS program, one can sum any two variables, whereas multiplication can be done only so long as one of the two variables is an input. Before discussing the evaluation algorithm, let us generalize the notation described above to vectors, with:

LEncA(x; s*,* r*,*e) := s ⊺ A + r ⊺ (x ⊺ *⊗* G) + e ⊺

by increasing the dimensions of the components appropriately. We refer to s as the *encryption* *key* and r as the *authentication key*. Homomorphic operations can be extended to vectors in a straightforward manner. We are now ready to state the algorithm to evaluate RMS programs. *k×*(*m·k·*log*q*) *m* 1 Lemma 4.2 (Evaluation of RMS Programs). *Let* A *∈* Z*qbe a matrix,* x *∈* Z*q −be an* *input, and let f be a T -bounded depth-d*(*λ*) *RMS program. Define* xˆ *as the vertical concatenation* *of* x *and* 1*. For all i ∈* [*d*]*, let:* c*i*:= LEncA(xˆ; s*i,* s*i*+1*,* e*i*)

*with* s*i∈* Z *k* *qand such that* max*i∥*e*i∥∞≤ β. Then there exist two polynomial-time algorithms* EvalRMSK *and* EvalRMSC *such that:*

|A ← EvalRMSK(A,f )||}|
|---|---|---|
|f||i i∈[d]|
|A|d|d|

### and c˜ ← EvalRMSC(A,f,x, {c)

*with* c˜ *∈* LEnc *f* (*f*(x)*,*s₀*,* s*,* e˜) *such that ∥*e˜*∥∞≤ β · O*(*T ·* (*k ·* log*q*))*.*

*Proof.*

|We refer to any encoding using s|as encryption key and s|||as authentication key a level-(i,j)|
|---|---|---|---|---|
||i||j||
||A|j i i+1|i i,j||
|j i|j|||i,j|

encoding. Observe that splitting a level-(*i,i* + 1) encoding c into blocks of dimension *k ·* log*q*, we obtain level-(*i,i* + 1) encodings: LEnc*j*(*x*; s*,* s*,* e)

where *x* is the *j*-th entry of xˆ, A is the *j*-th block of A, and e is the *j*-th block of *k ·* log*q* entries in ee). Using the addition and multiplication by a constant, we can apply linear operations over en- codings lying on the same level (*i,j*). In this way, we obtain a level-(*i,j*) encoding of the result. On the other hand, the operation increases the norm of the noise in the encodings: If the linear P operation is described by a vector *ℓ*, the noise magnitude increases by a factor *v* log*ℓv*. We can also homomorphically compute multiplications between any encoding on level (*i,j*) and any encoding on level (*j,j* + 1). In this way, we obtain a level-(*i,j* + 1) encoding of the product. This time the noise magnitude increases by a factor *O*(*k ·* log*q*) and by an additive term *T · β* for each multiplication. Finally, we observe that we can convert a level-(*i,j*) encoding into a level (*i,j* + 1) encoding by simply multiplying by a level-(*j,j* + 1) encoding of 1. Notice that the latter is know given that the last entry of xˆ is a 1. Overall, the growth of the noise norm is bounded by a factor *β · O*(*T ·* (*k ·* log*q*) *d* ). We also highlight that for all these operations we described, we are able to derive the matrix underlying the output encodings from the matrices underlying the input encodings. Thus both algorithms are well-defined.

### 4.2 Compressing Lattice Encodings

We describe a procedure to compress and decompress lattice encodings. Formally, this consists of a triple of algorithms (Setup*,*Compress*,*Expand) that allows one to sample a compressed version of a lattice encoding, that can be later on expanded into the format described above. Let *n* := *n*(*λ*)*,k* := *k*(*λ*), *m* := *m*(*λ*), and *q* := *q*(*λ*) be positive integers. We are going to assume the existence of an *α*-correct succinct NI-OTE protocol OTE = (Setup*,*Hash*,*Enc*,*HashEval*,*EncEval)

|m q|k·log q q||n q|
|---|---|---|---|
||k q|k q||

with bilinear encoder evaluation for Z *⊗* Z where digests are vectors in Z and the encoder private information consists of a vector in Z. Let G := I *⊗* g. Our scheme is formally described in Construction4.3. Observe that if we instantiate OTE with Construction3.6, the size of the compressed encoding scales logarithmically in the size of its input.

### Construction 4.3. Compression of Lattice Encodings

*λ*$*λ* Setup(1): Return ck := pk *←* OTE*.*Setup(1).

$ Compress(ck*,* A*,* x*,*s₀*,*s₁*,*r): Compute (d*,ψ*) := OTE*.*Hash(pk*,*x), then sample e *← χ*(*λ*). Compute ⊺ ⊺ ⊺ ⊺ h := s₀A + r (d *⊗* G) + e $ ⊺ and set *E ←* OTE*.*Enc(pk*,*s₁ *⊗* g*q,*r). Return (h*,E*).

Expand(ck*,* A*,* h*,E,* x): Recompute the hash (d*,ψ*) := OTE*.*Hash(pk*,*x) and set v := OTE*.*HashEval(pk*,E,ψ*). Let P be the matrix of the OTE protocol that can be pub- licly derived from pk. Return c := hP ⊺ + v ⊺ *.*

We show that the expansion algorithm indeed leads to well-formed lattice encoding. By the correctness of the NI-OTE protocol, we have that:

⊺ w := OTE*.*EncEval(pk*,* d*,*s) = P *·* (d *⊗* s *⊗* g*q*)*.*

### Then let us rewrite:

⊺ ⊺ c = h *·* P + v ⊺ ⊺ ⊺ ⊺ ⊺ ⊺ ⊺ = s₀ *·* A + r *·* (d *⊗* G) *·* P + e *·* P + v ⊺ ⊺ ⊺ ⊺ ⊺ ⊺ ⊺ ⊺ = s₀ *·* A *·* P + r *·* (d *⊗* I*k⊗* g*q*) *·* P + e *·* P + v ⊺ ⊺ ⊺ ⊺ ⊺ ⊺ ⊺ ⊺ = s₀ *·* A *·* P + (d *⊗* r *⊗* g*q*) *·* P + e *·* P + v ⊺ ⊺ ⊺ ⊺ ⊺ ⊺ = s₀ *·* A *·* P + w + e *·* P + v ⊺ ⊺ ⊺ ⊺ ⊺ ⊺ *′*⊺

|= s₀ · A · P|+ x ⊗ (s₁ ⊗ g|) + e|· P|+ e||
|---|---|---|---|---|---|
|⊺|⊺ ⊺|⊺ k|q ⊺|⊺ ′⊺||
|⊺|⊺ ⊺|⊺|⊺ ⊺|′⊺||
|AP||⊺ ⊺|′⊺|||

*q* = s₀ *·* A *·* P + s₁ *·* (x *⊗* I *⊗* g) + e *·* P + e = s₀ *·* A *·* P + s₁ *·* (x *⊗* G) + e *·* P + e = LEnc ⊺(x; s₀*,*s₁*,* e *·* P + e)

by the *α*-correctness of the NI-OTE. We can bound the norm of the noise term by:

⊺ ⊺ *′*⊺ *′ r*+1 *∥*e *·* P + e *∥∞≤ k · n ·* log *q ·∥*e*∥∞·∥*P*∥∞*+ *∥*e *∥∞≤ k · n² ·* log *q · B*(*λ*) + *α ·∥*x*∥∞.*

by Equation (5) and by the *α*-correctness of the NI-OTE. We prove that the compressed encodings satisfy a notion of simulation that we define below.

*λ* Theorem 4.4 (Simulatability). *Consider the following experiment* CompExp*A,*CSim(1) *parametrized by an adversary A* = (*A₀, A₁*) *and a simulator* CSim*:*

$*λ*$ *k×*(*n·k·*log*q*) $*k*

- *Sample* ck *←* Setup(1)*,* A *←* Z*q, and* s₀*,* r *←* Z*q.*
*λ*

- *Activate the adversary* (x*,*s₁*,*aux) *←A₀*(1*,*ck*,*A)*.*
$

- *Sample b ←{*0*,*1*}. If b* = 0 *compute:*
$ (h₀*,E₀*) *←* Compress(ck*,* A*,* x*,*s₀*,*s₁*,*r)

*whereas if b* = 1 *compute:* $*λ* (h₁*,E₁*) *←* CSim(1*,*ck*,*A)*.*

*′ ′*

- *Obtain b ←A₁*(h*b,Eb,*aux) *and return* 1 *if and only if b* = *b.*
*Then assuming the hardness of LWE and that* OTE *is encoder private, there exists a PPT simulator* CSim*, such that for every PPT adversary A, there exists a negligible function* negl(*λ*) *such that, for* *every λ ∈* N*, we have that:*

h i <u>1</u>*λ* *−* Pr CompExp*A,*CSim(1 ) = 1 *≤* negl(*λ*) 2

*where the probability is taken over the random coins of the experiment.*

*Proof.* Consider the following sequence of hybrid experiments.

- Hybrid *H₀*: This is the original experiment.
$ *n·k·*log*q* $

- Hybrid *H₁*:*q*

|We provide the adversary A₁ with a pair (h,E) where h ← Z||and E ←|
|---|---|---|
|||q|
|q ⊺|k q ⊺ ⊺|⊺|

$ OTE*.*Enc(pk*,*s₁ *⊗* g*,*r) for r *←* Z.

Indistinguishability from the previous hybrid follows by a direct reduction to LWE. Indeed, in Hybrid *H₀*, we have that h = A *·*s₀ + e + (d*⊗* G ⊺ ) *·*r, where in particular A *·*s₀ + e is an LWE sample. $*λ*

- Hybrid *H₂*: We also simulate *E ←* OTE*.*Sim(1*,*pk). Indistinguishability follows from a straightforward reduction to the encoder privacy of OTE.
We conclude by observing that in Hybrid *H₂* the pair (h*,E*) given to *A₁* is independent of the values x and s₁ chosen by *A₀*. This concludes the proof.

## 5 Rate-1 Adaptive LFE for all Bounded-Depth Functions

5.1 Almost Optimal, Weak Reverse Trapdoor Hashing for RMS As a stepping stone, we present a variant of a trapdoor hashing (TDH) scheme [DGI
+ 19] with reversed syntax, achieving almost optimal encoding key size but supporting a restricted family of functions. The syntax is *reversed* from the original definition from [DGI + 19] where a TDH hashes inputs and encodes functions, whereas we do the opposite. Let *m* := *m*(*λ*), *ℓ* := *ℓ*(*λ*), *p* := *p*(*λ*), *d* := *d*(*λ*), *T* := *T* (*λ*), *k* := *k*(*λ*) and *t* := *t*(*λ*) be positive integers. Construction5.1allows the evaluation of functions that map any pair (x*,*a), where x *∈ {*0*,*1*}* *m* and a *∈* Z *tp·k*, into *f*(x) *⊗* a where *f* : *{*0*,*1*}* *m* *→ {*0*,*1*}* *ℓ* is described by a depth-*d*, *T*-bounded RMS program. Our construction only achieves a weak mix of (adaptive) privacy and correctness: Although the encoding key leaks no information about x and a, in order to successfully run the encoding procedure, we are required to know x (but not a). Although this properties may seem artificial, they will later be useful in combination with techniques of [BTVW17], to build adaptive LFE with rate-1 encodings (Section5.2). Concerning efficiency, the digest size in our construction is logarithmic in *m*, *tℓ* and *d*. Moreover, the size of the encoding key is *d² · t ·* poly(*λ,* log *m,* log*ℓ*). Notice that we can achieve logarithmic dependency in *m* only because the encoding procedure needs x in order to run successfully.

The Construction. We now invite the reader to take a look at Construction5.1. The scheme re- lies on the compressed, adaptive lattice encodings of Section4. We instantiate them over Z*q*, where *q* = ∆*·p* where ∆ := ∆(*λ*) is a positive integer. We use (Setup*,*Compress*,*Expand) to denote the algo- rithms of Construction4.3and we use *n* := *n*(*λ*) to denote the digest size of the *α*-correct OTE with which it is instantiated. Let P be the matrix used for the hasher evaluation in the OTE protocol. We also rely on an ˆ*α*-correct succinct NI-MOLE protocol MOLE = (Setup*,*Hash*,*Enc*,*HashEval*,*EncEval) (*t·ℓ·k·*log*q*)*×k* for matrices of size Z*q*.

Construction 5.1. Almost Optimal, Weak Reverse TDH for RMS

Setup(1 *λ* ): Run the setup for the MOLE and the compressed lattice encodings

$*λ*$*λ* ck *←* Setup(1)*,* mpk *←* MOLE*.*Setup(1)*.*

$ *k×*(*n·k·*log*q*) $ *k×*(*t·k·*log*q*) Then, sample A *←* Z*q*, B *←* Z*q* and return hk := (ck*,*mpk*,* A*,*B).

### Hash(hk,f): Compute:

A*f←* EvalRMSK(AP ⊺ *,f*)*,* F *←−*A*f·* (I*ℓ⊗* G *−*1

(B))*.*
$⊺ Then output (d*,ψ*) *←* MOLE*.*Hash(mpk*,* F).

Gen hk*,* x*,*a;*{*r*i}i∈*[*d*]: Let xˆ be the vertical concatenation of x and 1. For every *i ∈* [*d* + 1], $*k* sample s*i←* Z*q*and set:

$ (h*i,Ei*) *←* Compress(ck*,* A*,* xˆ*,* s*i,* s*i*+1*,* r*i*)*.*

$*λ* ⊺ ⊺ ⊺ Next, sample e *← χ*(1) and set b *←* s *d* B + a (I*t⊗* G) + e, where G = I*k⊗* g*q*. $ $*λ* Proceed by generating (*C,ϕ*) *←* MOLE*.*Enc(mpk*,*s₀) and sampling seed *←{*0*,*1*}*.

Output ek := (*C,*b*, {*h*i,Ei}i∈*[*d*]*,*seed) and td := (*ϕ,* seed)

Enc(hk*,*ek*,ψ,*x*,f*): For every *i ∈* [*d*], compute c*i←* Expand(ck*, A,*h*i,Ei,* xˆ) and set

c *←* EvalRMSC(AP ⊺ *,f,*x*, {*c*i}i∈*[*d*])

Next, derive z *←−*c *·* (I*ℓ⊗* G *−*1

(B)) + *f*(x)
⊺ *⊗* b. Finally, compute

v *←* MOLE*.*HashEval(mpk*,C,ψ*)*,* u *′* *←* (z *−* v ⊺ ) *·* (I*t·ℓ·k⊗* G *−*1

(∆))*,*
y *′* *←⌈*u *′* + PRG(seed)*⌋p*

Output y *′*.

### Dec(hk, d, td): Compute

w *←* MOLE*.*EncEval(mpk*,* d*,ϕ*)*,* u *←* w ⊺ I *t·ℓ·k⊗* G *−*1

(∆)*,*
y *←⌈−*u *−* PRG(seed)*⌋p*

### Then, output y.

Correctness. In order for the construction to be fully correct, we need to choose a sufficiently large modulus *q*. Specifically, it must hold that

<u>∥P∥∞·T·B· (k · logq)</u> *d* <u>+ α · T · (k · logq)</u> *d* <u>+ ˆα</u>*−ω*(log*λ*) *p ·* = 2*.* *q*

|||||∞|r||5|
|---|---|---|---|---|---|---|---|
|||⊺ i i|⊺ ⊺ i+1|⊺|⊺ i|||
|i ∞|∞|⊺|i i∈[d]|⊺ f|⊺ d|⊺|⊺|

Notice that in the OTE of Section3.3, it holds that *∥*P*∥* = *n²* where *r* = *O*(log*m*). We begin by observing that, by the correctness of Construction4.3, for every *i ∈* [*d*]:

c = s AP + s (xˆ *⊗* G) + e

where *∥*e *∥ ≤ k · n ·∥*P*∥ ·* log *q · B*(*λ*) + *α*. Therefore, by Lemma4.2, we have that:

c = EvalRMSC(AP*,f,*x*, {*c*}*) = s₀ *·* A + s *·* (*f*(x) *⊗* G) + ee*,*

By a careful choice of parameters, *r* can also be made a constant:e.g., by setting *t* = *λ* in Construction3.6.

where *∥*e*∞ ∞* *d*+1 *d*

|e∥|≤ n ·∥P∥|·B·T· (k · log q)||+ α · T · (k · log q)||. We obtain that:||||
|---|---|---|---|---|---|---|---|---|---|
|ℓ|−1||⊺|||||||
|⊺|f ℓ|−1|⊺ d|⊺|ℓ|−1|⊺ ℓ|−1||
|⊺|⊺ d|⊺|⊺ ℓ|−1||⊺ ⊺ d|⊺|t|⊺|
|⊺|⊺|⊺ d|⊺ ℓ|−1||⊺ ⊺ d|⊺|t|⊺|
|⊺|⊺|⊺ t||⊺ ℓ|−1|⊺|⊺|||
|⊺|⊺|⊺ t|⊺|ℓ|−1|⊺|⊺|||
|⊺|⊺|⊺ q|⊺ ℓ|−1||⊺ ⊺||||

z = *−*c *·* (I *⊗* G (B)) + *f*(x) *⊗* b ⊺ = *−*s₀ *·* A *·* (I *⊗* G (B)) *−* s *·* (*f*(x) *⊗* G) *·* (I *⊗* G (B)) *−* ee *·* (I *⊗* G (B)) + *f*(x) *⊗* b

= s₀ *·* F *−* s *·* (*f*(x) *⊗* B) *−* ee *·* (I *⊗* G (B)) + *f*(x) *⊗* s *·* B + a *·* (I *⊗* G) + e

= s₀ *·* F *− f*(x) *⊗* (s *·* B) *−* ee *·* (I *⊗* G (B)) + *f*(x) *⊗* s *·* B + a *·* (I *⊗* G) + e

= s₀ *·* F + *f*(x) *⊗* (a *·* (I *⊗* G)) *−* ee *·* (I *⊗* G (B)) + *f*(x) *⊗* e

= s₀ *·* F + a *·* (*f*(x) *⊗* I *⊗* G) *−* ee *·* (I *⊗* G (B)) + *f*(x) *⊗* e

= s₀ *·* F + (*f*(x) *⊗* a *⊗* g) *−* ee *·* (I *⊗* G (B)) + *f*(x) *⊗* e

Finally, by the ˆ*α*-correctness of the MOLE, we observe that

⊺ ⊺ ⊺ ⊺ ⊺ ⊺ *−*1 ⊺ ⊺ ⊺ ⊺ z *−* v *−* w = s₀ *·* F + (*f*(x) *⊗* a *⊗* g*q*) *−* ee *·* (I*ℓ⊗* G (B)) + *f*(x) *⊗* e *−* v *−* w ⊺ ⊺ ⊺ ⊺ *−*1 ⊺ ⊺ ⊺ ⊺

||= s₀ · F + (f (x)|⊗ a|⊗ g ) − e|e · (I ⊗ G|(B)) + f (x)|⊗ e|− s₀ · F − ˆe||
|---|---|---|---|---|---|---|---|---|
|||⊺ q|⊺ ℓ|−1|⊺|⊺ ⊺|||
|∞|∞|⊺ ℓ ∞|−1|⊺ d+2|⊺ ⊺|d|||

*q ℓ* = (*f*(x) ⊺ *⊗* a *⊗* g) *−* ee *·* (I *⊗* G (B)) + *f*(x) *⊗* e *−*ˆe

where *∥*ˆe*∥ ≤ α*ˆ. Let *ε* := *−*ee *·* (I *⊗* G (B)) + *f*(x) *⊗* e *−*ˆe. It holds that:

*∥ε∥ ≤ n ·∥*P*∥ ·B·T·* (*k ·* log*q*) + *α · T ·* (*k ·* log*q*) + *B* + ˆ*α.*

### We observe that:

(z *−* v ⊺ *−* w ⊺ ) *·* (I*t·ℓ·k⊗* G *−*1

(∆)) = ∆ *·* (*f*(x)
⊺ *⊗* a ⊺ ) + *ε ·* (I*t·ℓ·k⊗* G *−*1

(∆))*.*
Notice also that *∥ε ·* (I*t·ℓ·k* *−*1

||⊗ G (∆))∥|≤ log q ·∥ε∥||.|||
|---|---|---|---|---|---|---|
|∞|′|⊺|⊺||||
|||||||∞|

*∞ ∞* Finally, we observe that y *′* + y *̸*= *f*(x) ⊺ *⊗* a ⊺ mod *p* only if one of the entries of u *−* PRG(seed) is less than log *q ·∥ε∥* away from an odd multiple of ∆*/*2. Since seed is independent of u and by the security of the PRG, the probability of this event is at most *p ·* log *q ·∥ε∥ /q* + negl(*λ*). By hypothesis, this quantity is negligible.

Adaptive Privacy. We now show that our construction satisfies adaptive privacy: un- der the LWE assumption with superpolynomial modulus-noise ratio, we can simulate (*C,*b*, {*h*i,Ei}i∈*[*d*]*,*seed) without knowing any information about x and a even if these are cho- sen by the adversary after seeing the output of the setup.

Theorem 5.2 (Adaptive Privacy). *Consider the following experiment* AdaptivePrivacy*A,*Sim(1 *λ* ) *parametrized by an adversary A* = (*A₀, A₁*) *and a simulator* Sim*:*

$*λ*

- *Sample* hk *←* Setup(1)*.*
- *Activate the adversary* (x*,* a*,*aux) *←A₀*(1
*λ* *,*hk)*.*

$ $*k*

- *Sample b ←{*0*,*1*}. If b* = 0*, sample ri←* Z*qfor every i ∈* [*d*]*. Then, compute*
$ (ek₀*,*td₀) *←* Gen(hk*,* x*,*a;*{*r*i}i∈*[*d*])

*If b* = 1 *compute:* $*λ* ek₁ *←* Sim(1*,*hk)*.*

- *Obtain b*
*′* *←A₁*(ek*b,*aux) *and return* 1 *if and only if b* = *b* *′* *.*

*Then assuming the hardness of LWE with superpolynomial modulus-noise ratio and that* MOLE *and* OTE *are encoder private, there exists a PPT simulator* Sim*, such that for every PPT adversary A,* *there exists a negligible function* negl(*λ*) *such that, for every λ ∈* N*, we have that:*

<u>1</u> h *λ* i *−* Pr AdaptivePrivacy*A,*Sim(1 ) = 1 *≤* negl(*λ*) 2

*where the probability is taken over the random coins of the experiment.*

*Proof.* We prove the theorem through a series of indistinguishable hybrids.

- Hybrid *H₀*: This is the original experiment: We provide the adversary *A₁* with
$ (*C,*b*, {*h*i,Ei}i∈*[*d*]*,*seed) where ((*C,*b*, {*h*i,Ei}i∈*[*d*]*,*seed)*,*td) *←* Gen(pk*,* x*,*a).

- Hybrid *H₁*: In this hybrid, we generate *C* using MOLE*.*Sim(1
*λ* *,*mpk). The rest remains as in the previous hybrid.

Indistinguishability from Hybrid *H₀* follows from the encoder privacy of MOLE.

*i*$*λ*

- Hybrid *H₂*: In this hybrid, for every *j < i*, we generate (h*j,Ej*) *←* CSim(1*,*ck*,*A), where CSim is the simulator of Theorem4.4. The rest remains as in the previous hybrid. We observe that Hybrid *H₁* is identical to Hybrid *H₂*
0. Moreover, for every *i ∈* [*d*], Hybrid *H₂* *i* is computationally indistinguishable from Hybrid *H₂* *i*+1 due to Theorem4.4(notice that in Hybrid *H₂* *i*, the pair (h*i−*1*,Ei−*1) is independent of s*i*).

$ *t·k·*log*q*

- Hybrid *H₃*: In this hybrid, we sample b *←* Z*q*. The rest remains as in the previous hybrid. Hybrid *H₂*
*d* is computationally indistinguishable from *H₃* under LWE. Notice that in Hybrid *H₂* *d*, the terms *C, {*h*i,Ei}i∈*[*d*]no longer contain information about s*d*. This allows us to reduce indistinguishability to LWE. Indeed, all information about a ⊺ *·* (I*t⊗* G) in b is masked by ⊺ ⊺ s *d* *·* B + e

This can be viewed as an LWE sample with respect to the matrix B ⊺ and secret s*d*.

Notice that in Hybrid *H₃* all material provided to *A₁* is independent of x and a.

### 5.2 Rate-1 Adaptive LFE for all Bounded-Depth Functions

We now present our adaptive LFE scheme for bounded-depth functions. We described it in Con- struction5.3. Let *ℓ* := *ℓ*(*λ*), *m* := *m*(*λ*), and *D* := *D*(*λ*) be positive integers. The construction allows the evaluation of any function *f* : *{*0*,*1*}* *m* *→ {*0*,*1*}* *ℓ* described by a polynomial-sized cir- cuit of depth at most *D*(*λ*). The digest size is poly(*λ,* log *m,* log *ℓ,* log*D*), whereas the size of the encodings is *m* + *ℓ* + *D ·* poly(*λ,* log *m,* log *ℓ,* log*D*). The construction builds upon the reverse trapdoor hashing scheme RTDH := (Setup*,*Hash*,* Gen*,*Enc*,*Dec) of Construction5.1. We assume the latter outputs a secret-sharing over Z*p*where *p* = 2 *ω*(log*λ*). Moreover, we assume that RTDH is instantiated using the OTE protocols in Construction

3.6and3.4. The basic idea is the following: we pick a constant *d* = *O*(1) and we rewrite *f* as the composition of *L* = *D/* log*d* functions of depth at most log*d*. Each of these can be regarded as a depth-*d* RMS program, which can therefore be evaluate using RTDH.

Construction 5.3. Rate-1 Adaptive LFE for Bounded-Depth Circuits

*λ*$*λ* Setup(1): Output pk := hk *←* RTDH*.*Setup(1)

Hash(pk*,f*): For any vector z, let *f*zbe the function that maps a key *K* to *f*(z *⊕* PRG(*K*)). Let *f* *′* be the function that maps a pair (ct*,*z) to GSW*.*Eval(ct*,f*z) where the evaluation is performed as in [BV14]. Rewrite *f* *′* as

*f* *′* = *fL* *′ −* 1*◦ fL* *′ −* 2*◦···◦ f₀* *′*

where each *f* *i′* is described by a *T*-bounded depth-*d* RMS program, all with the same input and output size. For every *i ∈* [*L −* 1], let *f*ˆ*i*be the function that maps x to OTE*.*Hash(tpk*,fi*(x)) and set *f*ˆ*L−*1*← f* *L* *′ −* 1. Notice that OTE*.*Hash is linear so its depth is 0 *a*. Here tpk denotes the OTE public key that is used in Construction4.3. Let *f*ˆ the func- tion that maps any vector x to (*f*ˆ₀(x)*,..., f*ˆ*L−*1(x)). Output (d*,ψ*) *←* RTDH*.*Hash(hk*, f*ˆ).

$ (*k−*1)*×*(*k·*log*q*+*λ*) $*k* 1$*λ* Enc(pk*,h,* x): Sample M *←* Z*q*, r *←* Z*q −*and e *← χ*(1) and generate a GSW key r M skGSW:= pkGSW:=⊺ ⊺ *−*1 r *·* M + e $*λ* Sample *K ←{*0*,*1*}* and encrypt the input

$ z *←* x *⊕* PRG(*K*)*,* ct *←* GSW*.*Enc(pkGSW*,K*)*.*

$*k* For every *i ∈* [*L*]*,j ∈* [*d*] sample randomness r*i,j←* Z*q*and define:  *−*1  G (r*i,*0) . .. *−*1 a*i*:=   a*L←* G (skGSW) G *−*1 (r*i,d−*1)

Then, set x₀ := (Bits(ct)*,*z) and compute

$ (ek₀*,*td₀) *←* RTDH*.*Gen(hk*,*x₀*,*a₁; *{*r₀*,j}j∈*[*d*]) *′i*$; *{*r

|∀i > 0 :|(ek, td ) ←|RTDH.Gen(hk, 0, a|||} )|
|---|---|---|---|---|---|
||′i|i||i+1|i,j j∈[d]|
|′i i i i,0|i i i,j j∈[d] i i,n·d−1|i ′i,j i|i,j j∈[d]|i i|i|
|i,j|i,j|i,d+j|i,d·(n−1)+j|||
|i,j|′i+1,j|i,j|q n·k|q⊺ log q||

For every *i ∈* [*L*], let ek = (*C,* b*, {*h*,E},*seed). Compute

### y ←−RTDH.Dec(hk, d,td) mod p

and set ek*i*:= (*C,* b*, {E},*seed). Let *n* be the digest size of OTE. For every *i ∈* [*L −* 1], take the block of y corresponding to the evaluation of *f*ˆ and split it into *d · n* subblocks yˆ*,...,*yˆ of dimension *k ·* log*q* and set

y *←* yˆ *∥* yˆ *∥... ∥* yˆ

w *←* h *−* (y *⊗* g) *·* (I *⊗* g *⊗* I) mod *q*

Let u be the last element of the standard basis of Z and let y be the block of y*L−*1

||||k q|L−1|
|---|---|---|---|---|
||L−1||||
|ℓ·k ·log q|q⊺ k|q⊺|ℓ·k ·log q|⊺ −1|
|λ|i i∈[L]|L−1 i,j i∈[L−1],j∈[d]||2|

corresponding to the output of *f*ˆ. Compute

w*L−*1*←−*y*L−*1*·* (I 2 *⊗* g *⊗* I *⊗* g) *·* Lin(I 2) *·* G (*−*∆ *·* (I*ℓ⊗* u)) mod *q.*

$ Sample seed *←{*0*,*1*}* and set w *←⌈*w + PRG(seed)*⌋*.

Output *E* = (ct*,* z*,*seed*,*ek₀*, {*ek*}, {*w*},*w)

Dec(pk*,E,f,ψ*): Initially, set x₀ *←* (Bits(ct)*,*z). Then, for *i* = 0*,...,L −* 2:

- compute y
*i′* *←* RTDH*.*Enc(hk*,*ek*i,ψ,*x*i, f*ˆ)

- take the block of y
*i′* corresponding to the evaluation of *f*ˆ*i*and split it into *d · n* subblocks yˆ *i,* *′* 0 *,...,*yˆ *i,n* *′* *·d−*1 of dimension *k ·* log*q* and set

y*i,j* *′* *←* yˆ*i,j* *′* *∥* yˆ*i,d* *′* +*j∥... ∥* yˆ*i,d* *′* *·*(*n−*1)+*j* h*i*+1*,j←* w*i,j*+ (y*i,j* *′* *⊗* g*q*) *·* (I*n·k⊗* g*q* ⊺ *⊗* Ilog*q*) mod *q*

- set ek*i*+1*←* (ek*i*+1*, {*h*i*+1*,j}j∈*[*d*])
- compute the input to the next RMS program x*i*+1*← f*
*i′* (x*i*)

Finally, let u be the last element of the standard basis of Z *k*

*q*. Derive
y*L* *′ −* 1*←* RTDH*.*Enc(hk*,*ek*L−*1*,ψ,*x*L−*1*, f* ˆ)

w*L* *′ −* 1*←* y *′L−* 1*·* (I*ℓ·k*2*·*log*q⊗* g*q* ⊺ *⊗* I*k⊗* g*q* ⊺ ) *·* Lin(I*ℓ·k*2*·*log*q*) ⊺ *·* G *−*1 (*−*∆ *·* (I*ℓ⊗* u)) mod *q.*

where y *′L−* 1 denotes the block of y *L* *′ −* 1 corresponding to the evaluation of *f*ˆ*L−*1.

Output *⌈*(w *L* *′ −* 1 *−* PRG(seed)*⌋*2*⊕* w *a* See Construction3.4and Construction3.6.

Correctness. Towards proving correctness, we prove the following lemma, which states that the term h*i,j*computed by the server during the decoding procedure is an adaptive lattice encoding of OTE*.*Hash(tpk*,* x*i*). In other words, ek*i*is an encoding key for x*i*= (*f* *i′−*1 *◦···◦ f₀* *′* )(Bits(ct)*,*z).

Lemma 5.4. *For every i ∈* [*L*] *and j ∈* [*d*]*, we have that* ⊺ ⊺ *′i*⊺ ⊺

||· A + r h = s|· (d||
|---|---|---|---|
||i,j i,j|i,j|i|
|′i i′ i ∞|i i,j|||

*i,j i,j i,j⊗* G) + e*i*

*where* (d*,ψ*) *←* OTE*.*Hash(tpk*,* x)*,* s *is the encryption key used in the encoding* h *′i,j* (h₀*,j, if* *i* = 0) *and ∥*e *∥ ≤ B*(*λ*)*.*

*Proof.* We proceed by induction over *i*. The claim is trivially true for *i* = 0. Now, we show that if it holds for *i*, it holds also for *i* + 1. We observe that

h*i*+1*,j*

|= w + (y|⊗ g|) · (I ⊗ g|⊗ I|) mod q||
|---|---|---|---|---|---|
|i,j|i,j ′ q|n·k|q⊺ log q|||
|′i+1,j|i,j ′|q n·k|q⊺ log q|i,j|q⊺ log q|
|′i+1,j|i,j ′|i,j|q n·k|q⊺ log q||

= h + (y *⊗* g) *·* (I *⊗* g *⊗* I) *−* (y *⊗* g*q*) *·* (I*n·k⊗* g *⊗* I) mod *q*

= h + ((y *−* y) *⊗* g) *·* (I *⊗* g *⊗* I) mod *q.*

ˆ(x⊺ ⊺ Now, by Theorem5.2and the inductive hypothesis, we recall that y *i′* *−* y*i*= *fi*) *⊗* a *i*+1 mod *p*. We also recall that this subtractive secret-sharing was initially over Z*q*, i.e. the parties held vectors *′i ′i*ˆ(x⊺ ⊺

|i|′i|i|i ⊺ ⊺ i+1|i|i ∞|||
|---|---|---|---|---|---|---|---|
|i+1|ω(log λ) i i′ i i′ i,j ′|i ⊺ ⊺ i+1 i i,j ′ i,j|′i ⊺ +1|i i+1 −1 i+1,j|i ⊺ ⊺ i+1 ⊺|i i ′i+1|′i+1|

u and u*i*such that u *−* u*i*= *q/p · fi*) *⊗* a + *εi*where *∥εi∥∞*is low. This secret-sharing was rerandomised using PRG(seed) and then rounded. We argue that y is pseudorandom. In particular, since *p* = 2, with overwhelming probability, all entries of y are in the interval ˆ(x [*−p/*2*,p/*2 *−* 1). Since *f*) *⊗* a has all entries in *{*0*,*1*}*, we conclude that (with overwhelm- ˆ(x ing probability) y and y is a subtractive secret-sharing of *f*) *⊗* a even over the integers. Continuing, we observe that the *i*-th *n*-entry block of *f*ˆ(x) coincides with d where d is the output of OTE*.*Hash(tpk*,f* (x)) = OTE*.*Hash(tpk*,* x). Moreover, we observe that, by the way we constructed a, y and y, we have that

y *−* y*i,j*= d *⊗* G (r)

### Putting everything together, we obtain

||i+1,j|′i +1,j|′i +1 ⊺|−1 i+1,j|⊺ q|n·k q ⊺|log q|
|---|---|---|---|---|---|---|---|
|′i|⊺|′i +1,j ′i +1,j ′i +1,j ⊺|′i +1 ⊺ ′i ⊺ +1 ⊺ i+1,j|−1 i+1,j ⊺ i+1,j ′i ⊺ +1|⊺ q q|n ⊺|log q|
|+1,j|i+1,j|i+1 i+1,j|i+1 ⊺ i+1,j|∞ ⊺ i+1,j|′i ⊺ +1|⊺ i+1||

h = h + (d *⊗* G (r) *⊗* g) *·* (I *⊗* g *⊗* I)

= h + (d *⊗* G (r) *⊗* g) *·* (I *⊗* G *⊗* I)

= h + d *⊗* r *⊗* g

= h + r *·* (d *⊗* G)*.* (8)

Since h = s *·* A + e where *∥*e *∥ ≤ B*(*λ*), we obtain that

h = s *·* A + r *·* (d *⊗* G) + e

This ends the proof of the lemma.

Continuing with our analysis, by Lemma5.4, we have that y *L* *′ −* 1 and y*L−*1form a subtractive ˆ(x⊺ ⊺ secret sharing of *fL−*1) *⊗* a *L* over Z*p*. Furthermore, similarly to how we argued in the proof of Lemma5.4, it is possible to prove that the probability that any entry of y*L−*1lies outside ˆ(x⊺ ⊺ of [*−p/*2*,p/*2 *−* 1) is negligible. Given that all entries of *fL−*1) *⊗* a *L* belong to *{*0*,*1*}*, we conclude that, with overwhelming probability, y *L* *′ −* 1 and y*L−*1form a subtractive secret sharing of *f* ˆ(x *L−*1) ⊺ *⊗* a *L* even over Z. By the way we constructed *f,*ˆ y*L−*1and y *′* *L−*1, we infer that y *′* *L−*1 *−* ⊺

ˆ⊺ ⊺ y*L−*1) = *fL−*1(x*L−*1) *⊗* a *L* We also notice that a*L*= G *−*1 (skGSW), whereas

*f* ˆ *L−*1(x*L−*1) = *fL−* *′* 1 (x*L−*1) = (*fL−* *′* 1*◦···◦ f₀* *′* )(x₀) = Bits(*f* *′* (ct*,*z)) = Bits(vec(GSW*.*Eval(ct*,f*z)))*.*

Let ctˆ := GSW*.*Eval(ct*,f*z). We obtain that

|w + w|= ((y|− y|) · (I|⊗ g|⊗ I ⊗ g|) · Lin(I||) · G|(−∆ · (I|⊗ u))|
|---|---|---|---|---|---|---|---|---|---|---|
|L ′ −1|L−1|′L−1 L−1 L−1 ⊺ ⊺ ⊺ GSW|L−1 ℓ·k ⊺ ⊺ L ⊺ GSW ℓ·k·log q −1|·log q ℓ·k ·log q ℓ·k ·log q GSW ℓ|q⊺ k q ⊺ ⊺ −1 −1|q⊺ k q ⊺ ℓ|ℓ·k ·log q ℓ·k ℓ|⊺ −1 ·log q ⊺|−1|ℓ ℓ|

2 2 ˆ = (*f* (x) *⊗* a) *·* (I 2 *⊗* g *⊗* I *⊗* g) *·* Lin(I 2) *·* G (*−*∆ *·* (I *⊗* u)) ˆ) = (vec(ct *⊗* sk) *·* Lin(I 2) *·* G (*−*∆ *·* (I *⊗* u))

= vec(ctˆ) *·* (I *⊗* sk) *·* G (*−*∆ *·* (I *⊗* u)) ˆ = sk *·* ct *·* G (*−*∆ *·* (I *⊗* u))*.*

⊺ ˆ ⊺ ⊺ ⊺ By the correctness of GSW evaluation, we have that sk GSW *·* ct = sk GSW *·* (*f*z(*K*) *⊗* G) + eˆ where *∥*eˆ*∥∞≤B·D·* poly(*λ*). Notice that *f*z(*K*) = *f*(z *⊕* PRG(*K*)) = *f*(x). We conclude that

*′ −* ⊺ ⊺ ⊺ *−*1 w*L* 1+ w*L−*1= (sk GSW *·* (*f*(x) *⊗* G) + eˆ) *·* G (*−*∆ *·* (I*ℓ⊗* u)) ⊺ ⊺ ⊺ *−*1 = *−*∆ *·* sk GSW *·* (*f*(x) *⊗* u) + eˆ *·* G (*−*∆ *·* (I*ℓ⊗* u)) ⊺ ⊺ ⊺ *−*1 = *−*∆ *· f*(x) *⊗* (sk GSW *·* u) + eˆ *·* G (*−*∆ *·* (I*ℓ⊗* u))

= ∆ *· f*(x) ⊺ + eˆ ⊺ *·* G *−*1 (*−*∆ *·* (I*ℓ⊗* u))*.* (9)

Notice that *∥*eˆ ⊺ *·* G *−*1 (*−*∆ *·*(I*ℓ⊗*u))*∥∞≤∥*eˆ*∥∞*. So, unless any of the entries of w*L−*1+ PRG(seed) is less than *∥*eˆ*∥∞*away from *q/*4 or *−q/*4, we have that

*f*(x) = *⌈*(w*L* *′ −* 1*−* PRG(seed)*⌋*2*⊕⌈*w*L−*1+ PRG(seed)*⌋*2*.*

Since seed is sampled independently of w*L−*1, the probability of the bad event is at most poly(*λ*) *·* *∥*eˆ*∥∞/q*) + negl(*λ*). Given our choice of *q* for RTDH, this is a negligible amount.

Security. Next, we prove that our construction is encoder private.

Theorem 5.5. *Assume the hardness of LWE with superpolynomial modulus-noise ratio. Then,* *Construction5.3is an adaptively encoder private LFE.*

*Proof.* We prove our claim by relying on a series of indistinguishable hybrids.

- Hybrid *H₀*: This hybrid corresponds to the original game: we provide the adversary with a tu- ple (ct*,* z*,*seed*, {*h₀*,j}j∈*[*d*]*, {*ek*i}i∈*[*L*]*, {*w*i,j}i∈*[*L−*1]*,j∈*[*d*]*,*w) generated using LFE*.*Enc(pk*,h,* x).
- Hybrid *H₁*: In this hybrid, we change the distribution of w: using pk*,f*, (ct*,* z*,*seed*, {*h₀) and following the same operations as in

|}|, {ek }, {w|}||
|---|---|---|---|
|,j j∈[d]|i i∈[L]|i,j i∈[L−1],j∈[d] L ′ −1|L ′ −1|
 the decoding procedure, we compute w. Then, we set w *← f*(x) *⊕⌈*w *−*PRG(seed)*⌋*2. This hybrid is statistically indistinguishable from Hybrid *H₀* due to the correctness of the primitive.
- Hybrid *H₂*: In this hybrid, we change the distribution of w*i,j*for every *i ∈* [*L −*1] and *j ∈* [*d*]: using pk*,f*, (ct*,* z*, {*h₀*,β β∈*[*d*] *γ γ∈*[*i*] *γ,β γ∈*[*i*]*,β∈*[*d*]

||}|, {ek }|, {w|}|) and following the same operations|||
|---|---|---|---|---|---|---|---|
||,β β∈[d]|γ γ∈[i]|γ,β|γ∈[i],β∈[d]||||
||||′|||||
||′i|⊺|i,j ′i ⊺|′||⊺||
|i,j|+1,j|i+1,j|+1|i,j|q|n·k q|log q|
|′i+1 i′+1|||i+1|i+1|i′|′||
|||||||i,j||
 as in the decoding procedure, we compute y. Then, we set
w *←* h + r *·* (d *⊗* G) *−* (y *⊗* g) *·* (I *⊗* g *⊗* I)*,* (10)

where (d*,ψ*) *←* OTE*.*Hash(tpk*,* x) and x *←* (*f ◦···◦ f₀*)(Bits(ct)*,*z).

This hybrid is statistically indistinguishable from Hybrid *H₁*. Indeed, w satisfies the relation in (10) even in *H₁*. This is highlighted in Lemma5.4, specifically in (8).

- Hybrid *H₃*: In this hybrid, for every *i ∈* [*L*] *\{*0*}*, we compute
$ (ek*i,*td*i*) *←* RTDH*.*Gen(hk*,* x*i*+1*,* a*i*+1; *{*r*i,j}j∈*[*d*])

where x*i*+1*←* (*f* *i′* *◦···◦ f₀* *′* )(Bits(ct)*,*z). Let ek*i*= (*Ci,* b*i, {*h*i,j,Ei,j}j∈*[*d*]*,*seed*i*). For every *i ∈* [*L −* 1] and *j ∈* [*d*], we set

w*i,j←* h*i*+1*,j−* (y*i,j* *′* *⊗* g*q*) *·* (I*n·k⊗* g*q* ⊺ *⊗* Ilog*q*)*,*

We also argue that *H₂* is perfectly indistinguishable from Hybrid *H₃*. Indeed, the only difference between the output of RTDH*.*Gen(hk*,* x*i*+1*,* a*i*+1; *{*r*i,j}j∈*[*d*]) and

|RTDH.Gen(hk, 0, a||} ) is that, in the first case, the encoding h||is “shifted” by||
|---|---|---|---|---|---|
|||i,j j∈[d]||i,j||
|⊺|′i ⊺|′i||||
|i+1,j|+1|+1|i′+1|||

*i*+1; *{*r*i,j j∈*[*d*] *i,j* r *·* (d *⊗* G) where (d*,ψ*) *←* OTE*.*Hash(tpk*,* x*i*+1) (see Construction4.3). In the second case, no shift is essentially applied. This is because, by the linearity of our OTE hashing (see Construction3.4and Construction3.6), OTE*.*Hash(tpk*,*0) outputs 0.

- Hybrid *H₄*
*ι* : In this hybrid, for every *i < ι*, we generate

$*λ* ek*i*:= (*Ci,* b*i, {*h*i,j,Ei,j}j∈*[*d*]*,*seed*i*) *←* RTDH*.*Sim(1*,*hk)

We observe that Hybrid *H₃* is identical to *H₄* 0. Moreover, by Theorem5.2, for every *ι ∈* [*L −* 1], we have that *H₄* *ι* is computationally indistinguishable from *H₄* *ι*+1. Notice that here we are implicitly relying on the fact that, in Hybrid *H₄* *ι*, the tuple *{*ek*i}i<ι*no longer contains information about *{*r*ι,j}j∈*[*d*].

$ *k×*(*k·*log*q*+*λ*)

- Hybrid *H₅*: In this hybrid, we sample pkGSW*←* Z*q*. We argue that *H₄*
*t* is computationally indistinguishable from *H₅*. Indeed, under LWE, the term r ⊺ *·*M + e ⊺ is indistinguishable from random. Here, we are implicitly relying on the fact that, in *H₄* *t*, the tuple *{*ek*i}i∈*[*L*]no longer contains information about r.

$ *k×*(*λ·k·*log*q*)

- Hybrid *H₆*: In this hybrid, we generate ct *←* Z*q*. Hybrid *H₆* is statistically indistinguishable from *H₅*. Indeed, now pkGSWis a uniformly random matrix, so we can apply the leftover hash lemma to argue that ct is indistinguishable from random.
$*m*

- Hybrid *H₇*: In this hybrid, we sample z *←* Z₂. Since ct no longer contains information about the PRG seed *K*, we can argue that *H₆* is computationally indistinguishable from *H₇* thanks to the security of the PRG. Notice that in *H₇* all the material provided to the adversary can be computed by a simulator
with no information about x except *f*(x). This ends the proof of security.

## 6 Reverse Trapdoor Hashing for all Functions

We construct reverse TDHs for all functions. Note that, for an expressive enough class of functions, in terms of functionality reverse TDHs are identical to the standard notion of TDH [DGI + 19], since one can always encode the universal circuit as the input, and vice-versa. However, since the encoding key grows with the size of the input, embedding a universal circuit introduces a dependency in the size of the function. Thus, we pay a price in succinctness, when going from TDH to reverse TDH. On the other hand, the opposite direction (reverse TDH =*⇒* TDH) has no such problem, since the size of the hash is anyway constant. Thus, reverse TDH appears to be a more powerful abstraction.

### 6.1 Definition

Definition 6.1 (Reverse Trapdoor Hashing). *A reverse trapdoor hashing scheme for the function* *class F* = (*Fλ*)*λ∈*N*with input size m*(*λ*) *and output of size ℓ*(*λ*) *consists of a tuple of PPT algorithms* (Setup*,*Hash*,*Gen*,*Enc*,*Dec) *with the following syntax:*

Setup(1 *λ* ): *The setup algorithm is randomised and takes as input the security parameter* 1 *λ* *. The* *output is a hash key* hk*.*

Hash(hk*,f*): *The hashing algorithm is randomised takes as input a hash key* hk *and a function* *f ∈Fλ. The output is a digest d and hasher’s private information ρ.*

Gen(hk*,*x): *The generation algorithm is randomised and takes as input an hash key* hk*, an element* x *∈* Z *m*

2*. The output is an encoding key* ek *and a trapdoor* td*.*
Enc(hk*,*ek*,f,ρ*): *The encoding algorithm is deterministic and takes as input a hash key* hk*, an* *encoding key* ek *and a function f ∈Fλand hasher’s private information ρ. The output is an* *encoding* e *∈* Z *ℓ* 2 *.*

Dec(hk*,*td*,d*): *The decoding procedure is deterministic and takes as input a hash key* hk*, a trapdoor* td *and a digest d. The output is an encoding* e *′* *∈* Z *ℓ* 2 *.*

Definition 6.2 (Correctness). *We say that a reverse TDH scheme is correct if there exists a* *negligible function* negl(*λ*) *such that, for every λ ∈* N*, function f ∈Fλand* x *∈* Z *m* 2*, it holds that:*

Pr [Enc(hk*,*ek*,f,ρ*) *⊕* Dec(hk*,*td*,d*) *̸*= *f*(x)] *≤* negl(*λ*)

$*λ*$ *where the probability is taken over the random choice of* hk *←* Setup(1)*,* (*d,ρ*) *←* Hash(hk*,f*)*, and* $ (ek*,*td) *←* Gen(hk*,*x)*.*

Definition 6.3 (Function privacy of reverse trapdoor hashing). *Consider the following experiment* FuncExp*A*(1 *λ* ) *parametrized by an adversary A* = (*A₀, A₁*)*:*

$*λ*

- *Sample a hash key* hk *←* Setup(1)*.*
$*λ*

- *Activate the adversary* (*f₀,f₁,*aux) *←A₀*(1)*.*
$

- *Sample a random bit b ←{*0*,*1*}.*
$

- *Compute* (*d,ρ*) *←* Hash(hk*,fb*)*.*
- *Compute b*
*′* *←A₁*(hk*,d,* aux)*.*

- *Return* 1 *if and only if b* = *b*
*′* *.*

*We say that a reverse trapdoor hashing scheme* (Setup*,*Hash*,*Gen*,*Enc*,*Dec) *is function private if* *for every PPT adversary A, there exists a negligible function* negl(*λ*) *such that, for every λ ∈* N*,* *we have that:* h i <u>1</u>*λ* *−* Pr FuncExp*A*(1 ) = 1 *≤* negl(*λ*)*.* 2

*If the above property holds for every adversary (even computationally unbounded ones) we say that* *the scheme is statistically function private.*

Definition 6.4 (Input privacy of reverse trapdoor hashing). *Consider the following experiment* InpExp*A,*Sim(1 *λ* ) *parametrized by an adversary A* = (*A₀, A₁*) *and a simulator* Sim*:*

$*λ*

- *Sample a hash key* hk *←* Setup(1)*.*
$*λ*

- *Activate the adversary* (x*,*aux) *←A₀*(1)*.*

$

- *Sample a random bit b ←{*0*,*1*}.*
$ $*λ*

- *If b* = 0 *compute* (ek₀*,*td₀) *←* Gen(hk*,*x)*, else compute* ek₁ *←* Sim(1*,*hk)*.*
- *Compute b*
*′* *←A₁*(hk*,*ek*b,*aux)*.*

- *Return* 1 *if and only if b* = *b*
*′* *.*

*We say that a reverse trapdoor hashing scheme* (Setup*,*Hash*,*Gen*,*Enc*,*Dec) *is function-private if* *there exists a PPT simulator* Sim*, such that for every PPT adversary A, there exists a negligible* *function* negl(*λ*) *such that, for every λ ∈* N*, we have that:*

<u>1</u> h *λ* i *−* Pr InpExp*A,*Sim(1 ) = 1 *≤* negl(*λ*)*.* 2

### 6.2 Laconic Function Evaluation with Pre-Encoding

We now define a new variant of LFE. We ask that the encoding procedure is split into two parts: First, the encoder sends a function-independent pre-encoding of the input, then, once the hash of the function is revealed, it sends an input-independent post-encoding. We also require that the function digest and the post-encoding have a particular structure: the former consists of a matrix, the latter consists of a *LWE-like* sample. Finally, we ask that the output of the decoding procedure is produced by rounding the sum between the post-encoding and a (possibly non-linear) function of the pre-encoding. The reader may have already noticed that these properties are satisfied by many LFE schemes studied in the literature [QWW18,HLL23,DHM + 24,Wee24].

Definition 6.5 (Laconic Function Evaluation with Pre-Encoding). *Let F* := (*Fλ*)*λ∈*N*be a family* *of functions, an LFE scheme consists of a tuple of PPT algorithms* (Setup*,*Hash*,*Enc*,*Dec) *with the* *following syntax:*

Setup(1 *λ* ): *The probabilistic setup algorithm takes as input the security parameter and outputs a* *public key* pk*.*

Hash(pk*,f*): *The hashing algorithm takes as input a public key* pk *and the description of a function* *m k×*(*k·*log*q*) *f ∈ Fλwith f* : *{*0*,*1*} → {*0*,*1*}. The output is a digest* A*f∈* Z*qand hasher’s* *private information ψ.*

Enc(pk*,* A*f,*x): *The encoding algorithm takes as input a public key* pk *a hash* A*f, and an input* *string* x *∈{*0*,*1*}* *m* *. The algorithm is divided into two subroutines.*

PreEnc(pk*,*x): *The pre-encoding algorithm is independent of the hash: it takes as input a* *public key* pk*, an input* x *(and sometimes a vector* r *∈* Z *k* *q −* 1 *). It returns a pre-encoding* *of the input E, along with a private information* s *∈* Z *k*

*q.*
PostEnc(pk*,* A*f,*s): *The post-encoding algorithm does not depend on the input and returns a* *post-encoding defined as:* *c* := s ⊺ *·* A*f·* t + *e ∈* Z*p* $*λ k·*log*q* *where e ← χ*(1) *and* t *is sampled over* Z₂ *(not necessarily at random).*

*The algorithm outputs an encoding* (*E,c,* t)*.*

Dec(pk*,* (*E,c,* t)*,ψ*): *The decoding algorithm takes as input a public key* pk*, an encoding* (*E,c,* t) *and hasher’s private information ϕ. The output is a bit*

### ⌈Eval(E,ψ) · t + c⌋2

*k·*log*q* *where* Eval *is a polynomial-time deterministic algorithm that returns a vector in* Z*q.*

We define a particular version of correctness that applies in most scheme as in Definition6.5

Definition 6.6 (Special correctness). *Let B*e := *B*e(*λ*) *be a function of the security parameter.* *An LFE scheme with pre-encoding satisfies B*e(*λ*)*-special correctness if, for every λ ∈* N*, function* *f ∈F*

|and input x ∈ Z|, we have|||
|---|---|---|---|
|λ|m 2|⊺|f ⊺|
|k|q|∞||

Eval(*E,ψ*) = s *·* A + r *· f*(x) *·* G + ee ⊺

*where* G=I *⊗* g*,* ee *is such that ∥*ee*∥ ≤ B*e(*λ*) *and the last entry of* r *is −*1*.*

We recall the notion of hasher privacy.

Definition 6.7 (Hasher privacy). *Consider the following experiment* HashExp*A*(1 *λ* ) *parametrized* *by an adversary A* = (*A₀, A₁*)*:*

$*λ*

- *Sample a public key* pk *←* Setup(1)*.*
$*λ*

- *Activate the adversary* (*f₀,f₁,*aux) *←A₀*(1)*.*
$

- *Sample a random bit b ←{*0*,*1*}.*
$

- *Compute* (*d,ρ*) *←* Hash(pk*,fb*)*.*
- *Compute b*
*′* *←A₁*(pk*,d,* aux)*.*

- *Return* 1 *if and only if b* = *b*
*′* *.*

*We say that an LFE scheme with pre-encoding* (Setup*,*Hash*,*PreEnc*,*PostEnc*,*Dec) *is hasher-private* *if for every PPT adversary A, there exists a negligible function* negl(*λ*) *such that, for every λ ∈* N*,* *we have that:* h i <u>1</u>*λ* *−* Pr HashExp*A*(1 ) = 1 *≤* negl(*λ*)*.* 2

*If the above property holds for every adversary (even computationally unbounded ones) we say that* *the scheme is statistically hasher private.*

Finally we define a slightly weaker version of the standard encoder privacy, which however suffices for our purposes. Namely, we only require security against a distinguisher that sees the pre-encoding information (and we do not pose any requirement on the post-encoding).

Definition 6.8 (Pre-Encoding privacy). *Consider the following experiment* PreEncExp*A,*Sim(1 *λ* ) *parametrized by an adversary A* = (*A₀, A₁*) *and a simulator* Sim*:*

$*λ*

- *Sample a public key* pk *←* Setup(1)*.*
$*λ*

- *Activate the adversary* (x*,*aux) *←A₀*(1)*.*
$

- *Sample a random bit b ←{,}.*

$ $*λ*

- *If b* = 0*, compute* (*E₀,ϕ₀*) *←* Enc(pk*,*x)*. Otherwise, compute E₁ ←* Sim(1*,*pk)*.*
- *Compute b*
*′* *←A₁*(pk*,Eb,*aux)*.*

- *Return* 1 *if and only if b* = *b*
*′* *.*

*We say that an LFE scheme with pre-encoding* (Setup*,*Hash*,*PreEnc*,*PostEnc*,*Dec) *is pre-encoder* *private if for every PPT adversary A, there exists a negligible function* negl(*λ*) *such that, for every* *λ ∈* N*, we have that:* <u>1</u> h *λ* i *−* Pr PreEncExp*A*(1 ) = 1 *≤* negl(*λ*)*.* 2

Most known LFE schemes satisfy (or can be adapted to satisfy) the above syntactical require- ments. We summarize the state of the art in the following:

- Assuming the hardness of LWE, there exists an LFE scheme with pre-encoding for all bounded-depth circuits [QWW18, Appendix E].
- Assuming the hardness of small-secret circular LWE, there exists an LFE scheme with pre- encoding for all (no bound on the depth) circuits [HLL23].
- Assuming the hardness of Ring-LWE (small-secret circular Ring-LWE, resp.) there exists an LFE scheme with pre-encoding for all bounded-depth (unbounded-depth, resp.) RAM programs [DHM
+ 24].

For our purposes, the details of these constructions will be irrelevant, provided that they satisfy the above syntax. Henceforth, we just assume that such an LFE exists, with the understanding that the exact efficiency guarantees of our construction will depend on the building block used to instantiate it.

### 6.3 Construction

In the following we define our construction for a reverse TDH for functions

*f* : *{*0*,*1*}* *m* *→{*0*,*1*}* *ℓ* *.*

We will use the following ingredients instantiating them over the ring Z*q*:

- The *α*-correct, succinct MOLE protocol (Protocol3.4). (Setup*,*Hash*,*Enc*,*HashEval*,*EncEval)
- An LFE scheme with pre-encoding. (Setup*,*Hash*,*PreEnc*,*PostEnc*,*Dec). Suppose that the scheme satisfies *B*e-special correctness.
- A pseudorandom generator PRG : *{*0*,*1*}*
*λ* *→* Z *ℓq* that can be evaluated uniformly (e.g., instan- tiated via a pseudorandom function).

For convenience, we assume that *q* is even. Moreover, we assume that *α, B*e *≤ q ·* negl(*λ*). The protocol description is presented below. Construction 6.9. Reverse Trapdoor Hash

Setup(1 *λ* ): Sample keys

$*λ*$*λ* pk *←* LFE*.*Setup(1)*,* mpk *←* MOLE*.*Setup(1)*.*

$*λ* Then, sample seed *←{,}* and output hk := (pk*,*mpk*,*seed).

### Gen(hk,x): Compute

$*′*$ (*E,* s) *←* LFE*.*PreEnc(pk*,*x)*,* (*E,ϕ*) *←* MOLE*.*Enc(mpk*,*s)

Output ek := (*E,E* *′* ) and td := *ϕ*.

Hash(hk*,f*): Let u be the last element of the standard basis over Z *k*

*q*. Let (*f₀,...,fℓ−*1) be the
functions that compute the *i*-th bit of the output of *f*. For every *i ∈* [*ℓ*] compute

$ (A*fi,ψi*) *←* LFE*.*Hash(pk*,fi*)*.*

### Finally, compute

*−*1<u>q</u>*−*1<u>q</u> A *←* A*f*0*·* G *− ·* u*...* A*f* *ℓ−*1 *·* G *− ·* u 2 2 $⊺ (*d,ψ*) *←* MOLE*.*Hash(mpk*,* A)

and output *d* and *ρ* := (*ψ,ψ₀,...,ψℓ−*1).

Enc(hk*,*ek*,f,ρ*): Let u be the last element of the standard basis over Z *k*

*q*. Compute
v *←* MOLE*.*HashEval(mpk*,E* *′* *,ψ*)*.*

Parse v as the vertical concatenation of (*v₀,...,vℓ−*1) and let (*r₀,...,rℓ−*1) *←* PRG(seed).
For every *i ∈* [*ℓ*], compute

|e ← r + LFE.Eval(E,ψ|) · G (−q/2 · u) − v||
|---|---|---|
|i i ℓ−1|i −1|i 2|

### Finally, output e := (e₀,...,e).

Dec(hk*,d,* td): Compute w *←* MOLE*.*EncEval(mpk*,d,ϕ*)*.*

Parse w as the vertical concatenation of (*w₀,...,wℓ−*1) and derive (*r₀,...,rℓ−*1) *←*
PRG(seed). Then, for all *i ∈* [*ℓ*], compute

*e* *′i* *←⌈−ri− wi⌋* 2

Finally, output e *′* := (*e* *′* 0 *,...,e* *′ℓ−* 1 ).

Correctness. For correctness, observe that for all *i ∈* [*ℓ*] we have that:

*r* <u>i+ LFE.Eval(E,ψi</u>) *·* <u>G</u> *−*1 <u>(−q/2 · u) − v</u>*i*+ *−*<u>r</u>*i−* <u>v</u>*i′* | {z} | {z} *s* 0*s*1 = LFE*.*Eval(*E,ψi*) *·* G *−*1 (*−q/*2 *·* u) *−* (*vi*+ *vi′*) ⊺

|= (s|· A + r|· f (x) · G + e||e ) · G|(−q/2 · u) − s||· A · G|
|---|---|---|---|---|---|---|---|
|i ⊺|i i −1|⊺ i|⊺ i|−1||i ⊺|−1|

*f* *i* ⊺ *i* ⊺ *−*1 ⊺ *f* *i* *−*1 (*−q/*2 *·* u) *− ei*

= *−q/*2 *· f* (x) *·* r *·* u + ee *·* G (*−q/*2 *·* u) *− e* = *q/*2 *· f* (x) + ˆ*e*

where ˆ*e* := ee *·* G (*−q/ ·* u) *− e* and the second equality follows from the *α*-correctness of the MOLE and the special correctness of the LFE. Notice that *|*ee *·* G (*−q/ ·*u) *− ei|≤ α*(*λ*) +*B*e(*λ*).

Thus we have that *s₀* and *s₁* is a noisy secret sharing of *f* (x). Furthermore, it holds that

|||i|
|---|---|---|
|i|2|2|
|i|i|i|

*f* (x) = *⌈s₀* + *s₁⌋* = *⌈s₀⌋ ⊕⌈s₁⌋*2

except if *s₀ ∈* [*q/*4*−|e*ˆ*i|,q/*4 + *|e*ˆ *|*] *∪*[3*q/*4*−|e*ˆ *|,*3*q/*4 + *|e*ˆ *|*]. Note that the size of the interval is at most 4 *·|e*ˆ*i|*, which is a negligible fraction of *q*. Thus, by the pseudorandomness of PRG, this event happens with negligible probability, concluding our proof of correctness.

Security. We prove security in the following.

Theorem 6.10. *Suppose that* MOLE *is encoder private. If* LFE *is pre-encoding secure, Construction*

*6.9is input private. Finally, if* LFE *is (statistically) function private, the reverse tradpoor hashing* *scheme is (statistically) function private.* *Proof.* It is easy to see that the construction is (statistically) function private if LFE is (statistically) function private. As for input privacy, we proceed by a series of indistinguishable hybrids.
- Hybrid *H₀*: This hybrid corresponds to the original game: We provide the adversary *A₁* with an encoding key (*E,E*
*′* ) generated using Gen(hk*,*x).

- Hybrid *H₁*: In this hybrid, we generate *E*
*′* using MOLE*.*Sim(1 *λ* *,*mpk). The rest remains as in the previous hybrid.

Hybrid *H₀* and Hybrid *H₁* are computationally indistinguishable thanks to the encoder pri- vacy of the MOLE.

- Hybrid *H₂*: In this hybrid, we generate *E* using LFE*.*Sim(1
*λ* *,*pk). The rest remains as in the previous hybrid.

Hybrid *H₁* and *H₂* are indistinguishable under the input privacy of LFE.

Notice that in Hybrid *H₂*, the pair (*E,E* *′* ) provided to the adversary contains no information about

x. From this, we can easily derive a simulator. This ends the proof.
## 7 A Counterexample for Adaptive LWE

We present a counterexample to a conjecture from [QWW18]. The conjecture (adaptive LWE) says that the probability of that any polynomial-time attacker wins the following experiment is negligibly close to 1*/*2.

$

- The challenger samples random matrices *{*A

||||← Z|} and sends them to the attacker.|
|---|---|---|---|---|
|||i|n q ×m|i∈[k]|
||k−1||||
||n||||
|m|q i|⊺ i|i|⊺ i i∈[k]|
|i|m q i∈[k]||||

- The attacker chooses an *x ∈{*0*,*1*}* and sends it to the challenger. Let ˆ*x* := (*x,*0).
$ $

- The challenger samples an s *←* Z and a bit *b ←{*0*,*1*}*.
- If *b* = 0 it computes:
*{*b := s (A *− x*ˆ *·* G) + e*}* $ where e*i← χ*(*λ*).

$

- If *b* = 1 it samples *{*b *←* Z*}*.

- The attacker wins if, given *{*b*i}i∈*[*k*], it correctly guesses *b*.
We show that, if *k* is allowed to grow independently of the LWE parameters (*n,q,χ*), the assumption is false. This roughly corresponds to the *optimistic parameter* settings proposed in [QWW18]. We sketch the attack in the following. We assume for convenience that *q* is a power of 2, but the attack can be adapted to other moduli. Let A := (A₀ *∥... ∥* A*k−*1). By the homomorphic properties of the lattice encodings, we know that there exists a matrix H with *∥*H*∥∞*= 1 such that, for any matrix M *∈* Z *n* *q ×n*, if x := Bits(M), we have that:

(s ⊺ (A *−* x *⊗* G) + e ⊺ ) *·* H = s ⊺ (A *·* H *−* M) + e ⊺ *·* H *≈* s ⊺ (A *·* H *−* M)

since *∥*e ⊺ H*∥∞≈* 0. To recover the *i*-th most significant bit of (each component of) s, it is sufficient to set M*i*:= A*·*H*−*2 *i* *·*I*n*and x*i*:= Bits(M*i*). Then compute the (component-wise) most significant bit of: (s ⊺ (A *−* x*i⊗* G) + e ⊺ ) *·* H *≈* s ⊺ (A *·* H *−* M*i*) = 2 *i* *·* s ⊺ *.*

We can then recover the entire secret key s, by setting the input x to be the concatenation of (x₁*,...,*xlog*q*). This shows that the conjecture is false if *k* is allowed to be arbitrarily bigger than *n*. Notice in the provable parameter setting (where the encodings are secure under the *subexponential* hardness of LWE), our attack fails as the bound on *k* is too small to encode M*i*:= A*·* H *−* 2 *i* *·* I*n*.

Acknowledgments

D.A. and G.M. are supported by the European Research Council through an ERC Starting Grant (Grant agreement No. 101077455, ObfusQation). G.M. is also funded by the Deutsche Forschungs- gemeinschaft (DFG, German Research Foundation) under Germany’s Excellence Strategy-EXC 2092 CASA – 390781972. L.R. is supported by the European Research Council (ERC) under the European Union’s Horizon 2020 research and innovation programme under grant agreement number 101124977 (DECRYPSIS) and the Danish Independent Research Council under Grant-ID DFF-0165-00107B (C3PO).
## References

[ARS24]Damiano Abram, Lawrence Roy, and Peter Scholl. Succinct homomorphic secret shar- ing. In Marc Joye and Gregor Leander, editors, *Advances in Cryptology – EURO-* *CRYPT 2024, Part VI*, volume 14656 of *Lecture Notes in Computer Science*, pages 301–330, Zurich, Switzerland, May 26–30, 2024. Springer, Cham, Switzerland.

[ASY22]Damiano Abram, Peter Scholl, and Sophia Yakoubov. Distributed (correlation) sam- plers: How to remove a trusted dealer in one round. In Orr Dunkelman and Ste- fan Dziembowski, editors, *Advances in Cryptology – EUROCRYPT 2022, Part I*, vol- ume 13275 of *Lecture Notes in Computer Science*, pages 790–820, Trondheim, Norway, May 30 – June 3, 2022. Springer, Cham, Switzerland.

[Bar86]David A Barrington. Bounded-width polynomial-size branching programs recognize exactly those languages in nc. In *Proceedings of the eighteenth annual ACM symposium* *on Theory of computing*, pages 1–5, 1986.

[BBD]Rishabh Bhadauria, Pedro Branco, and Nico D¨ottling. Rate-1 registration-based en- cryption and laconic oblivious transfer. (Personal Communication).

+ [BCG 19]Elette Boyle, Geoffroy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, and Peter Scholl. Efficient pseudorandom correlation generators: Silent OT extension and more. In Alexandra Boldyreva and Daniele Micciancio, editors, *Advances in Cryptology –* *CRYPTO 2019, Part III*, volume 11694 of *Lecture Notes in Computer Science*, pages 489–518, Santa Barbara, CA, USA, August 18–22, 2019. Springer, Cham, Switzerland.

[BDGM19]Zvika Brakerski, Nico D¨ottling, Sanjam Garg, and Giulio Malavolta. Leveraging linear decryption: Rate-1 fully-homomorphic encryption and time-lock puzzles. In Dennis Hofheinz and Alon Rosen, editors, *TCC 2019: 17th Theory of Cryptography Confer-* *ence, Part II*, volume 11892 of *Lecture Notes in Computer Science*, pages 407–437, Nuremberg, Germany, December 1–5, 2019. Springer, Cham, Switzerland.

+ [BGG 14]Dan Boneh, Craig Gentry, Sergey Gorbunov, Shai Halevi, Valeria Nikolaenko, Gil Segev, Vinod Vaikuntanathan, and Dhinakaran Vinayagamurthy. Fully key- homomorphic encryption, arithmetic circuit ABE and compact garbled circuits. In Phong Q. Nguyen and Elisabeth Oswald, editors, *Advances in Cryptology – EURO-* *CRYPT 2014*, volume 8441 of *Lecture Notes in Computer Science*, pages 533–556, Copenhagen, Denmark, May 11–15, 2014. Springer Berlin Heidelberg, Germany.

[BGI16]Elette Boyle, Niv Gilboa, and Yuval Ishai. Breaking the circuit size barrier for secure computation under DDH. In Matthew Robshaw and Jonathan Katz, editors, *Advances* *in Cryptology – CRYPTO 2016, Part I*, volume 9814 of *Lecture Notes in Computer* *Science*, pages 509–539, Santa Barbara, CA, USA, August 14–18, 2016. Springer Berlin Heidelberg, Germany.

[BJSS25]Elette Boyle, Abhishek Jain, Sacha Servan-Schreiber, and Akshayaram Srinivasan. Simultaneous-message and succinct secure computation. In *EUROCRYPT 2025*, 2025.

[BLMR13]Dan Boneh, Kevin Lewi, Hart William Montgomery, and Ananth Raghunathan. Key homomorphic PRFs and their applications. In Ran Canetti and Juan A. Garay, editors, *Advances in Cryptology – CRYPTO 2013, Part I*, volume 8042 of *Lecture Notes in* *Computer Science*, pages 410–428, Santa Barbara, CA, USA, August 18–22, 2013. Springer Berlin Heidelberg, Germany.

[BTVW17]Zvika Brakerski, Rotem Tsabary, Vinod Vaikuntanathan, and Hoeteck Wee. Private constrained PRFs (and more) from LWE. In Yael Kalai and Leonid Reyzin, editors, *TCC 2017: 15th Theory of Cryptography Conference, Part I*, volume 10677 of *Lecture* *Notes in Computer Science*, pages 264–302, Baltimore, MD, USA, November 12–15,

2017. Springer, Cham, Switzerland.
[BV14]Zvika Brakerski and Vinod Vaikuntanathan. Lattice-based FHE as secure as PKE. In Moni Naor, editor, *ITCS 2014: 5th Conference on Innovations in Theoretical Com-* *puter Science*, pages 1–12, Princeton, NJ, USA, January 12–14, 2014. Association for Computing Machinery.

+ [CDG 17]Chongwon Cho, Nico D¨ottling, Sanjam Garg, Divya Gupta, Peihan Miao, and Antigoni Polychroniadou. Laconic oblivious transfer and its applications. In Jonathan Katz and Hovav Shacham, editors, *Advances in Cryptology – CRYPTO 2017, Part II*, volume 10402 of *Lecture Notes in Computer Science*, pages 33–65, Santa Barbara, CA, USA, August 20–24, 2017. Springer, Cham, Switzerland.

[DGI + 19]Nico D¨ottling, Sanjam Garg, Yuval Ishai, Giulio Malavolta, Tamer Mour, and Rafail Ostrovsky. Trapdoor hash functions and their applications. In Alexandra Boldyreva and Daniele Micciancio, editors, *Advances in Cryptology – CRYPTO 2019, Part III*, volume 11694 of *Lecture Notes in Computer Science*, pages 3–32, Santa Barbara, CA, USA, August 18–22, 2019. Springer, Cham, Switzerland.

[DHM + 24]Fangqi Dong, Zihan Hao, Ethan Mook, Hoeteck Wee, and Daniel Wichs. Laconic func- tion evaluation and ABE for RAMs from (ring-)LWE. In Leonid Reyzin and Douglas Stebila, editors, *Advances in Cryptology – CRYPTO 2024, Part III*, volume 14922 of *Lecture Notes in Computer Science*, pages 107–142, Santa Barbara, CA, USA, Au- gust 18–22, 2024. Springer, Cham, Switzerland.

[DHRW16]Yevgeniy Dodis, Shai Halevi, Ron D. Rothblum, and Daniel Wichs. Spooky encryption and its applications. In Matthew Robshaw and Jonathan Katz, editors, *Advances in* *Cryptology – CRYPTO 2016, Part III*, volume 9816 of *Lecture Notes in Computer* *Science*, pages 93–122, Santa Barbara, CA, USA, August 14–18, 2016. Springer Berlin Heidelberg, Germany.

[GSW13]Craig Gentry, Amit Sahai, and Brent Waters. Homomorphic encryption from learn- ing with errors: Conceptually-simpler, asymptotically-faster, attribute-based. In Ran Canetti and Juan A. Garay, editors, *Advances in Cryptology – CRYPTO 2013, Part I*, volume 8042 of *Lecture Notes in Computer Science*, pages 75–92, Santa Barbara, CA, USA, August 18–22, 2013. Springer Berlin Heidelberg, Germany.

[HLL23]Yao-Ching Hsieh, Huijia Lin, and Ji Luo. Attribute-based encryption for circuits of un- bounded depth from lattices. In *64th Annual Symposium on Foundations of Computer* *Science*, pages 415–434, Santa Cruz, CA, USA, November 6–9, 2023. IEEE Computer Society Press.

[ILL89]Russell Impagliazzo, Leonid A. Levin, and Michael Luby. Pseudo-random generation from one-way functions (extended abstracts). In *21st Annual ACM Symposium on* *Theory of Computing*, pages 12–24, Seattle, WA, USA, May 15–17, 1989. ACM Press.

[OSY21]Claudio Orlandi, Peter Scholl, and Sophia Yakoubov. The rise of paillier: Homomorphic secret sharing and public-key silent OT. In Anne Canteaut and Fran¸cois-Xavier Stan- daert, editors, *Advances in Cryptology – EUROCRYPT 2021, Part I*, volume 12696 of *Lecture Notes in Computer Science*, pages 678–708, Zagreb, Croatia, October 17–21,

2021. Springer, Cham, Switzerland.
[QWW18]Willy Quach, Hoeteck Wee, and Daniel Wichs. Laconic function evaluation and applica- tions. In Mikkel Thorup, editor, *59th Annual Symposium on Foundations of Computer* *Science*, pages 859–870, Paris, France, October 7–9, 2018. IEEE Computer Society Press.

[Reg05]Oded Regev. On lattices, learning with errors, random linear codes, and cryptography. In Harold N. Gabow and Ronald Fagin, editors, *37th Annual ACM Symposium on* *Theory of Computing*, pages 84–93, Baltimore, MA, USA, May 22–24, 2005. ACM Press.

[RS21]Lawrence Roy and Jaspal Singh. Large message homomorphic secret sharing from DCR and applications. In Tal Malkin and Chris Peikert, editors, *Advances in Cryptology –*

*CRYPTO 2021, Part III*, volume 12827 of *Lecture Notes in Computer Science*, pages 687–717, Virtual Event, August 16–20, 2021. Springer, Cham, Switzerland.

[Wee24]Hoeteck Wee. Circuit ABE with poly(depth*,λ*)-sized ciphertexts and keys from lat- tices. In Leonid Reyzin and Douglas Stebila, editors, *Advances in Cryptology –* *CRYPTO 2024, Part III*, volume 14922 of *Lecture Notes in Computer Science*, pages 178–209, Santa Barbara, CA, USA, August 18–22, 2024. Springer, Cham, Switzerland.
