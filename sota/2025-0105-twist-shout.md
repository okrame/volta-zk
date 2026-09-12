# Twist and Shout: Faster memory checking arguments via one-hot addressing and increments

### Srinath Setty

∗

### Justin Thaler

†

Abstract

A memory checking argument enables a prover to prove to a verifier that it is correctly processing reads and writes to memory. They are used widely in modern SNARKs, especially in zkVMs, where the prover proves the correct execution of a CPU including the correctness of memory operations. We describe a new approach for memory checking, which we call the *method of one-hot addressing* *and increments*. We instantiate this method via two different families of protocols, called Twist and Shout. Twist supports read/write memories, while Shout targets read-only memories (also known as lookup arguments). Both Shout and Twist have logarithmic verifier costs. Unlike prior works, these protocols do not invoke “grand product” or “grand sum” arguments. Twist and Shout significantly improve the prover costs of prior works across the full range of realistic memory sizes, from tiny memories (e.g., 32 registers as in RISC-V), to memories that are so large they cannot be explicitly materialized (e.g., structured lookup tables of size 2 64 or larger, which arise in Lasso and the Jolt zkVM). Detailed cost analysis shows that Twist and Shout are well over 10*×* times cheaper for the prover than state-of-the-art memory-checking procedures configured to have logarithmic proof length. Prior memory-checking procedures can also be configured to have larger proofs. Even then, we estimate that Twist and Shout are at least 2–4*×* faster for the prover in key applications. Finally, using Shout, we provide two fast-prover SNARKs for non-uniform constraint systems, both of which achieve minimal commitment costs (the prover commits *only* to the witness): (1) SpeedySpartan applies to Plonkish constraints, substantially improving the previous state-of-the-art protocol, BabySpar- tan; and (2) Spartan++ applies to CCS (a generalization of Plonkish and R1CS), improving prover times over the previous state-of-the-art protocol, Spartan, by 6*×*.

∗ Microsoft Research † a16 crypto research and Georgetown University

## Contents

1 Introduction 4

2 Overview of Twist and Shout and their costs 7

2.1 Background............................................. .7
2.2 Formulation of the memory checking problem.......................... .9
2.3 Prior work: Arguments via offline memory checking.......................11
2.4 Costs of Twist and Shout......................................14
2.5 Overview of Shout......................................... .17
2.6 Overview of Twist......................................... .20
2.7 Other benefits and implications...................................23
2.8 Appropriate settings of *d*.......................................24
2.9 Additional discussion .........................................25
3 Technical preliminaries 29

3.1 Prover costs in elliptic-curve-based SNARKs ............................29
3.2 Multilinear extensions........................................32
3.3 The sum-check protocol.......................................34
3.4 SNARKs and commitment schemes.. .............................. .36
3.5 Polynomial IOPs and polynomial commitments..........................37
3.6 Zero-check PIOP.......................................... .37
3.7 One-hot encodings......................................... .39
4 The Shout PIOP 39

4.1 A special case: *d* =1.........................................39
4.2 Shout for general *d*......................................... .42
5 The Twist PIOP 45

6 Fast Shout prover implementation (small memories) 49

6.1 Core Shout prover for *d* =1.................................... .49
6.2 Core Shout prover (general *d*, small memories)..........................49
6.3 Booleanity-checking and one-hot-encoding-checking.......................52
6.4 Cost summary for the combined Shout prover...........................56
7 Fast Shout prover for large, structured memories 56

7.1 Sparse-dense sum-check protocol..................................57
7.2 Extension to the Booleanity-checking sum-check when *K¹*
*/d*
*≫T*................58

7.3 Shout’s read-checking sum-check..................................63
7.4 The raf f -evaluation sum-check and Hamming-weight-one check when *K≫T*..........63
7.5 Cost summary for Shout when *K≫T*...............................64
8 Fast Twist prover implementation 64

8.1 Val f -evaluation sum-check .......................................64
8.2 Read-checking and write-checking sum-checks...........................65
8.3 Cost summary............................................72
9 Faster SNARKs for non-uniform computation 72

9.1 Overview...............................................72
9.2 Details of SpeedySpartan.. .....................................73
9.3 Details of Spartan++.. .......................................79
A Overview of offline memory-checking protocols

B Details of the Val f -evaluation sum-check prover 87

B.1 Computing the Less-Than evaluation table............................87
B.2 Optimizing the Val f -evaluation sum-check prover further.... .. .. .. .. .. .. .. .. .88
C A Shout variation with a linear prover dependence on *d* 90

C.1 Fast prover implementation.... .. .. .. .. .........................91

## 1 Introduction

A zero-knowledge virtual machine (zkVM) is a cryptographic protocol that allows an untrusted prover to succinctly prove that it correctly ran some computer program Ψ on a witness. In a zkVM, the computer program is specified to run on a specific CPU architecture, which is also called a virtual machine (VM) or an instruction set architecture (ISA). In a zkVM proof, the prover proves that it correctly ran Ψ cycle-by-cycle.

Generally speaking, zkVMs produce short proofs and have fast verification. Even if the zkVM first produces a proof *π* that is moderately large, *π* can be generically shrunk via *SNARK composition*. This means generating a smaller proof *π* *′* that establishes that the prover knows a valid *π*. Accordingly, the bottleneck in zkVM performance is prover runtime. zkVM provers today remain hundreds of thousands of times slower than native execution (i.e., the amount of work done to generate a proof *π* relative to that required to simply run Ψ with no proof of correctness).

Background on zkVMs and memory checking. zkVM provers prove that they did two things correctly, over and over. They first prove the correct execution of the “fetch-decode-execute” logic of the VM, once per cycle. Second, they prove that reads and writes to registers and RAM were executed faithfully.

A state-of-the-art zkVM, called Jolt [AST24], turns almost everything a VM does into reads and writes to memory. This includes the “fetch-decode-execute” logic of the VM. Roughly speaking, Jolt turns “fetch and decode” into a lookup into a read-only memory storing the program bytecode. Meanwhile, executing each primitive instruction is done via a lookup into a gigantic pre-determined table of size 2 64. Jolt accomplishes this by using Lasso [STW24], which internally turns this one lookup into a giant table into a short sequence of lookups into smaller tables, and combines the results to get the output of the instruction.

In summary, a key bottleneck for zkVM provers, and for the Jolt prover in particular, is proving that it correctly processed all reads and writes to memory. The fastest known methods for this task are called *offline memory checking* techniques. These techniques date back to work of Lipton [Lip89, Lip90] and Blum et al. [BEG + 91]. In the context of zkVMs, offline memory checking techniques allow a prover to commit to a constant number of values, and perform a constant number of field operations, per memory operation performed by the CPU. Jolt currently uses Spice [SAGL18] as its memory-checking argument for registers and RAM, and Lasso [STW24] for read-only memories.

Our contributions. We describe a new approach to memory-checking that improves significantly on offline memory checking techniques, promising substantial end-to-end speedups for zkVM provers. For reasons that will become clear, we call our approach the *method of one-hot addressing and increments*.

We instantiate this method via two different families of protocols, called Twist and Shout. Twist supports read/write memories, while Shout targets read-only memories (also known as lookup arguments). 1 Both families are parameterized by an integer *d ≥* 1. The smaller the memory, the smaller *d* can be, and the cheaper each memory operation is for the prover as a result.

Twist and Shout significantly improve on prior works across the full range of realistic memory sizes, from tiny memories (e.g., 32 registers as in RISC-V), to read-only memories that are so large they can’t be explicitly materialized (e.g., structured lookup tables of size 2 64 or larger, as arise in the Jolt zkVM).

Detailed cost analysis shows that Twist and Shout are over 10*×* cheaper for the prover than state-of-the-art memory-checking procedures configured to have similar proof length. Prior memory-checking procedures can also be configured to have larger proofs. Even then, we estimate that Twist and Shout are (at least) 2–4*×* faster for the prover.

Not only do Twist and Shout significantly speed up the prover across all practical memory sizes, they also give the prover a cost profile that more closely matches real CPUs. Unlike offline memory-checking techniques, the method of one-hot addressing is significantly faster for small memories than big ones, and Twist is faster for sequences of memory accesses with high locality (see Section 8.2.3 for details). This means that existing

Twist is short for Tracking Write Increments via Sum-check Techniques and Shout for Sum-check-based Handling of Unchanging Tables.

compiler toolchains that optimize for program execution time on real CPUs are more likely to also lead to fast zkVM provers once memory-checking is done via Twist and Shout.

At the highest level, Twist and Shout leverage the power of the sum-check protocol [LFKN90] to minimize the amount of data the prover has to commit to, and to prove satisfaction of very large but very sparse constraint systems (i.e., a huge number of witness variables, but almost all of them are 0) while only “paying” for the sparsity of the witness (number of non-zeros) rather than the size of the witness.

The parameter *d*: where it comes from and what it buys. When applied to memories of size *K*, the prover in the simplest variations of Twist and Shout commits to *K −* 1 0s and a single 1 per read or write operation. This makes these protocols especially efficient when combined with elliptic-curve-based commitment schemes, which are uniquely fast at committing to 0s: any committed 0s literally do not alter the commitment so they are free to commit, and committing to a 1 requires a single group operation requiring only 6–7 field operations. This performance profile is an excellent fit for the Jolt zkVM for RISC-V [And17], which currently achieves state-of-the-art prover performance and uses elliptic curve commitment schemes (specifically, HyperKZG [ZSC24] or Zeromorph [KT23]).

However, even when 0s are free to commit to, large memories are problematic for the simplest instantiations of our methods, primarily because the commitment key (which must be stored by the prover) gets very large. 2 To address this, we describe an entire family of protocols in which, for any desired integer *d ≥* 1, the prover only commits to roughly *d · K¹* */d* 0s per read or write operation. Using a large value of *d* comes at a cost: the prover also commits to *d* 1s per read or write operation, and each committed 1 forces the prover to perform one group operation. Hence, large values of *d* mean vastly fewer 0s are committed, which keeps the commitment key size bounded, but it also means slightly more 1s are committed, which modestly slows down the prover. Larger values of *d* also increase the amount of work the Twist and Shout provers do “outside of commitments”, and proof size grows linearly with *d* too. So one wants to choose *d* as small as possible, subject to the constraint that the commitment key is not too large.

Choosing a value *d ≥* 2 renders our methods suitable for memory sizes *K* in the millions or billions. It also allows our techniques to be productively instantiated with hashing-based multilinear commitment schemes over binary fields like Binius [DP23], FRI-Binius [DP24], and Blaze [BCF + 24]. Even though committing to 0s is not “free” with these schemes, committing to values that are known a priori to be in *{*0*,*1*}* is cheap enough that our results still offer improvements over prior works. 3 For these commitment schemes, *d* should be set just large enough to ensure that commitment time is not a prover bottleneck.

Since the Twist and Shout provers commit to *dK¹* */d* bits per address, to ensure committing with a hashing- based scheme is sufficiently fast, *dK¹* */d* should be between a few dozen and a couple hundred bits, with larger memories leading to larger values of *d* (and more committed bits).

To summarize, in applications we expect *d* to be between 1 and 4 if using an elliptic curve commitment scheme and between 1 and 16 if using a binary-field hashing-based commitments. Larger memories necessitate larger values of *d*. See Section 2.8 for details.

The high-level ideas of Twist and Shout. A simple observation underlying Twist and Shout is that when memory addresses are specified in one-hot form, correctness of reads and writes becomes equivalent to very simple (i.e., rank-one) constraint systems. This observation is already explicit in prior works on lookup arguments [ZBK + 22, ZGK + 22, STW24, GM24].

These constraint systems can be directly checked for correctness via the standard sum-check-based zero-check PIOP for, say, R1CS (see Section 3.6 for details). But there is a challenge: the constraint systems are very large, so large that we cannot tolerate a prover that runs in time linear in the number of witness variables, since for *T* operations into a memory of size *K*, there are (more than) *K·T* witness variables. Fortunately, the constraint systems are highly *sparse*: although they involve a huge number of variables, only about *T* 2 If the commitment key is structured, it must be generated via a trusted setup, which further limits its size. For memories consisting of just a few cells, such as the 2 registers in the Cairo Virtual Machine [GPR21, Section 2.4] and even the 32 registers in RISC-V, our protocols improve on prior work even when hashing-based commitment schemes over non-binary fields are used.

of them are non-zero. This lets us implement the sum-check prover applied to these constraint systems in roughly *O*(*K* + *T*) time rather than *O*(*K·T*) time. Roughly speaking, the sum-check prover does not “pay” for 0-variables, and neither does the prover when committing to those variables, at least when using a curve-based commitment scheme.

On top of this, for very large but “structured” read-only memories, where *K* = *T* *C* with *C ≥* 1, by invoking (and generalizing) the sparse-dense sum-check protocol from the Generalized-Lasso protocol [STW24], we can implement Shout’s sum-check prover in time *O*(*C·T*) *≪ O*(*K* + *T*).

When using parameter *d >* 1, Twist and Shout further exploit that every “one-hot” vector (meaning a vector in *{*0*,*1*}* *K* with exactly one entry equal to 1) can be expressed as a tensor product of *d* smaller one-hot vectors, each of length *K¹* */d*. We use this to control the negative effects of large memory sizes *K*, especially the size of the commitment key when using curve-based commitment schemes and the total number of committed bits when using hashing-based commitment schemes. This does come at the cost of higher-complexity constraints in the resulting constraint systems: they change from rank-1 to rank-*d*.

Twist needs to overcome an additional obstacle that threatens to bring in a Θ(*K·T*) cost to the prover’s runtime in the context of read/write memory. Specifically, a natural first attempt at designing Twist involves the prover committing to the value of *every register at every cycle*. This would be *K·T* committed non-zero values. Twist addresses this by instead having the prover commit to *increments*: the difference in value for each register cycle-by-cycle. Since at most one register is written per cycle, this entails committing to only *T* rather than *K·T* non-zero values (moreover, all *T* of these non-zero values are “small” and hence fast to commit to). At the end of the sum-check protocol, when the verifier needs to compute a random evaluation of (the multilinear extension of) the register values themselves, we offload that evaluation to the prover with a second invocation of the sum-check protocol that relates the register values to the increments. At the end of *that* sum-check, the verifier needs to evaluate the multilinear extension of the increments at a random point, which it can do because the increments themselves were committed.

We give two different implementations of the Twist prover. An important property of one of them is that the prover is faster when memory operations are *local*. Roughly, for a read or write operation to a memory cell that was accessed at most 2 *i* time steps prior, the Twist prover performs only *O*(*i*) field multiplications to process that operation, less than the *O*(log*K*) multiplications that the prover performs per memory operation in the worst case. In order to achieve this, this variant of the Twist prover binds variables in a different order than the Shout prover: the Twist prover binds “cycle-count-specification” (i.e., time) variables first, rather than “memory-address-specification” (i.e., memory) variables. This ensures that in the first log*K* rounds, temporally-close accesses to the same memory cell quickly “coalesce”, which is what allows the prover to benefit from locality of memory access. In other words, by binding time variables first, the sparsity (i.e., number of non-zeros) in the vectors the prover is processing falls quickly round-over-round when memory accesses are local, and the prover’s runtime in each round grows only with the number of non-zeros in these vectors.

Fast-prover SNARKs for non-uniform constraints. We also use Shout to give two new, fast-prover SNARKs for non-uniform circuits or constraint systems. We call these SNARKs SpeedySpartan and Spartan++. Both offer a a significant improvement in overall prover time relative to the previous state of the art, BabySpartan [ST23], and in particular a 4*×* improvement in commitment costs. In SpeedySpartan and Spartan++, the prover commits to the witness (the solution to the constraint system), and nothing else.

(At least this is the case when using polynomial commitment schemes with fast evaluation proof generation,

e.g., Hyrax [WTS
+ 18], Dory [Lee21]). For other schemes like HyperKZG, Zeromorph, and Bulletproofs/IPA, evaluation proofs themselves require committing to a linear amount of data.)

SpeedySpartan is concretely faster than Spartan++, due primarily to SpeedySpartan’s use of a lookup table that is quadratically smaller than the one used by Spartan++. Hence, we consider SpeedySpartan to be of practical interest and Spartan++ to be primarily of conceptual interest (although even Spartan++ is concretely almost an order of magnitude faster than Spartan itself [Set20]). Spartan++’s most interesting performance property is that its prover’s commitment costs grow linearly with the number of multiplication gates in the circuit and not the total gate count (i.e., addition gates do not contribute to commitment costs). But both SpeedySpartan

and Spartan++ reduce commitment costs so much that they are not a prover bottleneck, and hence this property of Spartan++ does not translate to major improvements in concrete costs.

The high-level ideas of SpeedySpartan and Spartan++. SpeedySpartan and Spartan++ observe that correct processing of circuit wires boils down to lookups. By circuit wires here, we mean which gate outputs need to be treated as inputs to which other gates.

There are two different ways this reduction from wires to lookups can be done. One technique originates in Spartan and its use of the Spark sparse polynomial commitment scheme [Set20]. The other originates in BabySpartan [ST23]. SpeedySpartan is a major refinement of the BabySpartan approach, while Spartan++ is a major improvement of the Spartan/Spark approach.

In the case of SpeedySpartan, BabySpartan already showed that each input to any gate can be computed with a lookup into the table that stores all gate outputs. BabySpartan invokes Lasso as the lookup argument. SpeedySpartan replaces Lasso with Shout. We further observe that this replacement allows certain polynomials that were explicitly committed by the BabySpartan prover to instead be *virtual*: they are *not* committed by the prover, and Shout nonetheless allows the verifier to evaluate these polynomials at the necessary evaluation point. This leads to a 4*×* reduction in commitment costs, with field work improvements coming from the improved efficiency of Shout relative to Lasso.

In the case of Spartan++, we directly give a major improvement of the Spark sparse polynomial commitment scheme. In its evaluation proofs, Spark has the prover prove it correctly ran a fast algorithm for evaluating the committed sparse polynomial at the requested evaluation point (see [STW24, Section 3.1] for details of this view of Spark). This algorithm performs lookups into a large table that stores evaluations of multilinear Lagrange basis polynomials at the requested (random) evaluation point. Spark effectively applies the Lasso lookup argument to this table. This requires the prover to commit to two random values per non-zero coefficient of the sparse polynomial (these random values are the results of lookups into “subtables” decomposing the large table). We replace Lasso with Shout, and further observe that this allows for the values returned by the lookups to be virtual polynomials. This eliminates the major prover bottleneck in Spark.

To summarize, SpeedySpartan and Spartan++ use lookups in very different ways to deal with circuit wires. For circuits with *n* gates, SpeedySpartan computes a gate’s inputs via lookups into the size-*n* table storing all gate outputs. Spartan++ performs lookups into a size-*n²* table storing all evaluations of multilinear Lagrange basis polynomials at a random evaluation point. Spartan++ pays increased costs relative to SpeedySpartan because the lookup table it uses is quadratically bigger, its use of the larger table does enable its commitment costs to grow linearly only with the number of multiplication gates.

## 2 Overview of Twist and Shout and their costs

### 2.1 Background

zkVMs and Jolt. The RISC-V instruction set architecture involves 32 registers. In each CPU cycle, at most two registers are read and one is written. The Jolt zkVM [AST24] forces an untrusted prover to correctly process reads and writes to registers (and random access memory) using an offline-memory-checking procedure called *Spice* [SAGL18]. Spice’s application in Jolt currently accounts for about 20% of total prover time today, with most of this cost coming from registers (which are read and written nearly every CPU cycle, unlike RAM, which is accessed only via explicit load and store instructions).

On top of the cost of Spice for checking registers and RAM, another 25% of Jolt prover time is spent on Lasso [STW24], an offline-memory-checking procedure tailored to read-only memories. Jolt uses Lasso to ensure the prover correctly executes the appropriate primitive RISC-V instruction during each CPU cycle (Jolt turns primitive instruction execution into a handful of lookups into fixed tables of size about 2 16 ). So in total, the Jolt prover currently spends almost half of its time in offline-memory-checking procedures. We anticipate that the fraction of Jolt’s prover costs will grow substantially over time, as other parts of the Jolt protocol continue to be optimized.

Polynomial IOPs and polynomial commitments. As with most SNARKs, Jolt consists of a *polynomial* *IOP* (PIOP), which can be combined with any polynomial commitment scheme (for multilinear polynomials, in the case of Jolt) to obtain a SNARK. A polynomial IOP is an interactive protocol where the prover is allowed to send one or more large polynomials to the verifier, but the verifier is only allowed to query those polynomials’ evaluation at, say, a single randomly chosen point.

A polynomial commitment scheme is a cryptographic protocol specifically designed to transform any polynomial IOP into a succinct argument. Specifically, rather than having the polynomial IOP prover explicitly send large polynomials to the verifier, a polynomial commitment scheme allows a prover to succinctly commit to those polynomials, and later reveal only the evaluations of the polynomials that are queried by the verifier (along with *evaluation proofs*, which prove that the returned evaluations are indeed consistent with the committed polynomials). One can render the succinct argument non-interactive with the Fiat-Shamir transformation [FS86a].

Jolt uses multilinear polynomial commitment schemes based on elliptic curves, like HyperKZG [ZSC24] and Zeromorph [KT23]. The commitment to a polynomial of size *n* with these schemes consists of a single group element, and evaluation proofs consist of *O*(log*n*) group elements. 4 In the future, Jolt plans to incorporate support for hashing-based commitment schemes over binary fields.

Costs of elliptic-curve-based commitments. When a polynomial IOP is combined with an elliptic curve commitment scheme (e.g., HyperKZG [ZSC24]), the vast majority of the work done by the prover consists of elliptic curve group operations and finite field operations (over the field F used by the polynomial IOP, which is also the *scalar field* of an elliptic curve). For small memories, the method of one-hot addressing substantially lowers *both* the number of field operations over F and the number of group operations performed by the prover.

There are two facts about elliptic curve commitments that the method of one-hot addressing takes heavy advantage of. The first is that committing to 0s is “free”. That is, when committing to a vector *v ∈* F *ℓ*, any *i* for which *vi*= 0 literally does not affect the commitment, and can just be “ignored” by the prover when computing the commitment to *v*. The number of committed 0s does influence some other prover costs arising in the protocol, especially the size of the commitment key, but it does not influence commitment time. Fortunately, the effect of the 0s on these other costs can be controlled, see Section 3.1 for details. Hence, in this informal overview it is both clearest and reasonably accurate to treat committed 0s as literally free for the prover. Second, *small* (but non-zero) values are cheap (but not free) to commit to. For example, any *i* such that *vi*= 1 costs the prover just one group operation when computing the commitment.

For simplicity, in this work we consider any value in *{*0*,*1*,...,*2 32 *−* 1*}* to be “small”. We select the threshold of 2 32 *−* 1 as the limit of smallness for convenience of accounting: most zkVMs today use 32-bit data types, and so registers store arbitrary elements of *{*0*,*1*,...,*2 32 *−* 1*}*. 5 Since the prover has no choice but to commit to the values read from or written to registers, it is convenient to call these values small. But this is also a reasonable notion of smallness: at practical instance sizes, committing to a 32-bit value with an elliptic curve commitment scheme takes roughly two group operations via Pippenger’s bucketing algorithm⁶. This is much cheaper than committing to an arbitrary field element, which can require a dozen group operations or more. 7

Costs of hashing-based commitments over binary fields. A nice property of hashing-based commit- ment schemes relative to curve-based ones is that the commitment key is small (often it simply specifies a cryptographic hash function), no matter the size of the vectors that need to be committed. However, hashing-based commitments have a major downside: committing to 0s is not free. This is a challenge because, 4 If *p* is a *v*-variate multilinear polynomial, then its size is 2*v*. This is because *p* is uniquely described by 2*v*coefficients, or equivalently its evaluations over an interpolating set such as *{*0*,*1*}v*, which has size 2*v*. 5 In this work, we use the terms *register* and *memory cell* interchangeably. 6 See [EHB22, Section 4] for a clear overview of Pippenger’s algorithm and its costs 7 For maximal precision of cost accounting it may be useful to distinguish the “smallness” of elements of, say, *{*0*,*1*,... ,*216*−* 1*}* vs. *{*216*,... ,*232*−* 1*}*. The former take only about one group operation to commit to at practical instance sizes, while the latter require about two group operations. To simplify our cost accounting, we do not make this distinction in this paper. However, our findings would not be substantially changed if we did.

when Twist and Shout (say, with *d* = 1) are applied to prove *T* memory operations into a memory of size *K*, the prover needs to commit to *K·T* values, and we cannot tolerate Θ(*K·T*) prover time.

Fortunately, all of these *K · T* values are known *a priori* to be in *{*0*,*1*}*: not only are almost all of the values 0, the non-zeros are always equal to 1. There is one (recently-identified) subclass of hashing-based commitment schemes that make such known-to-be-in-*{*0*,*1*}* values sufficiently fast to commit to that Twist and Shout are useful when combined with such commitments. These are hashing-based commitment schemes for multilinear polynomials over *binary fields*, which allow the prover to “pack” 128 values into a single element of GF(2 128 ), and commit to the packed values with an appropriate multilinear commitment scheme defined over GF(2 128 ). 8

This packing technique results in a 128-fold reduction in the number of committed GF(2 128 ) field elements, compared to the naive approach of assigning an entire GF(2 128 )-element to represent each committed value. Examples include Binius [DP23], FRI-Binius [DP24], and Blaze [BCF + 24].

For tiny memories like the 32 registers in RISC-V, *d* = 1 is fine: the means the prover commits to 32 bits per address, and four such addresses can be packed into a single GF(2 128 ) field element before committing. 9

As another attractive example, consider applying Twist with *d* = 4 to a memory with *K* = 2 20 cells (which corresponds to a zkVM with about 4 MBs of memory). Rather than committing to *K* values in *{*0*,*1*}* per memory operation as in Twist with *d* = 1, with *d* = 4 the Twist prover commits to only 4 *·* 2 5 = 128 values in *{*0*,*1*}*. These 128 values can all be packed into a single element of GF(2 128 ) before committing with the above hashing-based commitment schemes. On the other hand, increments are not guaranteed to be in the set *{*0*,*1*}* (although most increments will be 0s). Each increment is guaranteed to be an element of GF(2 32 ), so four increments can be packed into single element of GF(2 128 ) before committing.

### 2.2 Formulation of the memory checking problem

Motivation. Most primitive RISC-V instructions read two registers (the “source registers” containing the inputs to the primitive instruction executed at that cycle) and writes to one register (the “destination register”) that stores the output of the primitive instruction. We denote the source registers ra₁ and ra₂ (ra is short for read address), and the destination register by wa (short for write address).

To force an untrusted prover to prove that it is reading and writing to registers correctly, RISC-V zkVMs demand that the prover commit to

- the register addresses ra₁, ra₂, and wa each cycle.
- the values that the prover claims is returned by the reads to ra₁ and ra₂,
- the value that is written to wa.
The goal of the memory checking problem is to devise a succinct argument that lets the prover prove that indeed the value committed for every read operation is the value most recently written to the relevant register.

Formulation for read/write memories. Say there are *K* memory cells, which we will refer to as *registers* for short (for example, there are *K* = 32 registers in RISC-V). In the case of read/write memory, let us assume that operations alternate between reads and writes. 10 Let *T* denote the *number of cycles* being checked. More specifically, *T* denotes the number of read operations in the case of read-only memory. For read/write memory, each cycle consists of a read followed by a write, so there are *T* reads and *T* writes (i.e., 2*T* memory operations in total). 8 All hashing-based polynomial commitment schemes ultimately need to work over a field that is at least 128 bits in size to ensure adequate security. 9 Committing to *N* GF(2128) elements with these schemes involves Θ(*N*) or Θ(*N* log*N*) GF(2128) multiplications to apply the encoding procedure of an error-correcting code, followed by Θ(*N*) cryptographic hash evaluations. Computing evaluation proofs for these schemes can be fairly expensive for the prover, due to various invocations of the sum-check protocol in order to relate the “packed” committed values to the unpacked values. 10In a zkVM for RISC-V like Jolt, there are two committed register read operations and one committed register write operation per CPU cycle. But since this paper is focused on memory-checking, we find it clearest to use the term cycle to refer to a single memory operation rather than, say, a sequence of two reads and one write.

The memory-checking problem begins with the prover sending commitments to four vectors: raf, waf, rv and wv. We denote the *j*’th entry of these vectors with function notation, i.e., the *j*’th entry of raf is raf(*j*).

The *j*’th entries of raf and waf specify the address of the registers read and written in cycle *j*. In the context of zkVMs (and in typical offline-memory checking procedures like Spice), each register is indexed by one field element, and so raf and waf are also both in F *T*, with raf(*j*)*,*waf(*j*) *∈* F specifying the register addresses read and written at cycle *j*. Here, any injective mapping from registers to field elements suffices for the indexing. In large prime-order fields, the *K* field elements used to address the registers can simply be *{*0*,*1*,...,K −* 1*}*; for simplicity, this is the mapping we use throughout this manuscript. We use the letter *f* at the end of raf and waf to reflect that these are addresses specified via one field element per address. The *j*’th entry of rv specifies the value returned by the *j*’th read operation, and wv specifies the value written by the write operation. rv and wv are vectors in F *T* (i.e., registers store field elements).

The memory checking problem then demands that the prover establish that rv(*j*) equals wv(*j* *′* ) where *j* *′* *< j* denotes the largest cycle number less than or equal to *j* such that waf(*j* *′* ) = raf(*j*). If no such *j* *′* exists, then it is required that rv(*j*) = 0. Conceptually, this means that all registers are initialized to contain value 0, and every read to a register is required to return the value most recently written to that register.

It is also possible to demand that the contents of memory be initialized to a set of values that is not identically

0. In this case, either the vector of initial memory values (one value per cell) is committed by an honest party, or is simply public.
11

Read-only memories. Our formulation of the memory-checking problem for read-only memories is identical to read/write memories, except that the contents of the memory cells are public (i.e., known to both the verifier and the prover) and each cycle involves only a read operation, rather than a read followed by a write. We sometimes refer to the contents of the read-only memory as the *lookup table*. 12

One-hot encoding of addresses. Recall that in the above formulation of the memory-checking problem, each address is indexed by a single field element. This is how memory addresses are naturally specified in zkVM contexts. For example, in RISC-V, when performing a load or store from RAM, the relevant address is the value stored in the first source register, plus the “immediate” value for that instruction. Each zkVM register naturally stores a single field element, and the immediate value for any instruction is naturally represented by a single field element.

However, internal to the Twist and Shout proof systems, the register addresses must actually be specified via one-hot encoding. This means that within the Twist and Shout protocols, each address is a unit vector in *{*0*,*1*}* *K* *⊆* F *K*. Accordingly, we introduce two vectors ra*,*wa *∈* F *T ·K* that, for a sequence of *T* memory operations, specify all *T* memory addresses via one-hot encoding. We think of ra and wa as consisting of *T* rows each of length *K*. If the prover is honest, then the *j*’th row of ra, denoted ra(*j*), specifies via one-hot encoding the register read at cycle *j*, and similarly for wa. So if register *ℓ* is read at cycle *j*, then ra(*j*) is the *ℓ*’th unit vector *eℓ∈{*0*,*1*}* *K*. We denote the *k*’th entry of this vector by ra(*k,j*).

Because zkVMs naturally specify addresses via a single field element, when used within zkVMs, memory- checking arguments do need to give the verifier “access” to the vectors raf and waf, in which each address is specified via a single field element. In particular, the zkVM verifier needs to be able to evaluate the *multilinear extension polynomials* raf f and waf g at a random point. Twist and Shout support this. Even though raf f and waf g are *not* committed by the Twist and Shout provers (only rae and wa f are), we still give a way for

the verifier to evaluate raf f and waf g at a random point. 11In many applications, the initial contents of memory have a description that is much smaller than explicitly listing the value stored in each memory cell, and with some memory-checking arguments it is possible in these settings to avoid having the verifier spending time linear in the size of the memory to “process” the initial values [STW24, AST24]. 12Many lookup arguments, including Arya [BCG+18], plookup [GW20b], Caulk [ZBK+22], and LogUp [Hab22], actually solve a different problem, which is sometimes referred to as *unindexed lookups* (in contrast to reads into read-only memory, which is sometimes referred to as *indexed lookups*) [STW24]. Unindexed lookup arguments ensure that a vector of committed values all reside *somewhere* in a read-only memory, but do not specify an address at which each value must reside. Unindexed lookup arguments can be transformed into indexed ones, though the transformation adds prover and verifier overheads. See [STW24] for details.

To use a term coined in work on Binius [DP23], Twist and Shout can be integrated into zkVMs by treating raf f and waf g as *virtual polynomials*: they are not explicitly committed by the prover, but can still be evaluated by the verifier at any point, by asking the prover to provide the requested evaluation and then prove that the evaluation is correct. This is done expressing the needed raf f and waf g evaluations in terms of rae and wa f, and then applying the sum-check protocol to compute this expression. This effectively reduces the verifier’s task of evaluating raf f and waf g at a point, to the task of evaluating rae and wa f at a different point. These evaluations can be obtained directly from the commitments to rae and wa f. See Section 4.1.2 for details.

Can read-values be virtual too? We formulated the memory-checking problem above to assume that the vector rv of values returned by read operations are committed by the prover (or more precisely, their multilinear extension polynomial rve is committed). However, the “correct” value of every read operation is fully determined by the write operations and the read-addresses (or, in the case of read-only memories, simply by the read-addresses rae). And in applications to zkVMs, the SNARK verifier only ever needs to valuate rve at a random point *r*. 13

So, in principle, rve need *not* be committed: as soon as the prover commits to rae and to any polynomials specifying writes, rve is *implicitly* specified as well, and all we need to ensure is that the verifier is able to evaluate rve at a random point *r*. Twist and Shout directly give a protocol to accomplish this: from the verifier’s perspective, Twist and Shout use the sum-check protocol to reduce the task of evaluating rve (*r*) to the task of evaluating different polynomials that *are* committed by the prover.

Hence, unlike prior memory-checking arguments, Twist and Shout do allow the polynomial rve to be virtual, rather than committed by the prover. Our prover cost estimates throughout this work reflect this.

Relevant memory sizes. In the motivating example of 32 RISC-V registers, the memory size *K* is tiny (32 cells), especially relative to the number of CPU cycles executed. Even simple computer programs often run for at least 2 30 CPU cycles in total, and real computer programs often run for 2 50 cycles or more. 14

Indeed, the clock rate of modern laptops allows for several billion CPU cycles to be executed per second, even by a single thread. Our results are strongest (and cleanest to understand) in this parameter regime where *K≪T*, since then our the *O*(*K* + *T*) field operations incurred by the Twist and Shout provers is clearly dominated by the *T* term.

However, all possible relationships between *K* and *T* are also of interest. For example, L1 cache in real CPUs is often dozens of KBs, corresponding to *K ≈* 2 13 memory cells, and L2 cache is an order of magnitude larger (*K ≈* 2 16 ). 15 And many programs may only use MBs of main memory (RAM), while others can use GBs (translating to 2 30 memory cells or even more).

Less intuitively, in the case of read-only memories, we are also interested in the situation where *K ≈* 2 64 is so big that the entire contents of the memory cannot possibly be materialized. This setting arises in Jolt, where primitive instruction execution is handled by performing lookups into the “evaluation table” of the primitive instruction, which has size 2 64. These tables are highly structured, which ensures no one ever needs to materialize the entire gigantic memory. In other words, for “structured” read-only memories, one can achieve a prover runtime that is sublinear in *K*.

### 2.3 Prior work: Arguments via offline memory checking

Memory-checking procedures such as Spice [SAGL18] work by reducing the task of proving that all reads and writes were processed correctly, to the task of proving two related vectors *a ∈* F *ℓ* and *b ∈* F *ℓ* are permutations of each other. The precise value of *ℓ* differs amongst different memory-checking procedures, but is typically *O*(*T* + *K*). Confirming that *a* and *b* are permutations of each other is done via “Lipton’s trick” [Lip89, Lip90]: 13It is, of course, essential that the prover not be able to choose the polynomial rve with knowledge of the point *r* at which the verifier will evaluate it. 14Though in zkVMs today, program executions are broken into “shards” consisting of only about 220cycles each, with each shard proved semi-independently, in order to keep the prover space bounded. See Section 3.1.1 for additional details. Reads into L1 cache on real CPUs typically take just 1-4 clock cycles, while reads into L2 cache often take 5-20 cycles.

the verifier picks a random *r ∈* F, and confirms that

Y *ℓ*Y*ℓ* (*ai− r*) = (*bi− r*)*.* (1) *i*=1 *i*=1

Equation (1) clearly holds if *a* and *b* are permutations of each other, and if they are not, it holds with probability at most *ℓ/|*F*|* over the random choice of *r*.

Appendix A provides a brief overview of how these transformations from checking read-write memories to checking permutations work.

Offline memory-checking procedures confirm that Equation (1) holds using of a *grand product argument*: a SNARK for computing the product of many committed values. Many memory-checking procedures in the literature invoke grand product arguments that interpret the committed vectors as univariate polynomials, and prove that a certain divisibility relationship holds between the committed polynomials. These arguments can lead to excellent verifier costs (often with proofs consisting of only a constant number of group elements), but generally lead to slow provers.

The grand product arguments used by Spice as instantiated in Jolt (as with the method of one-hot addressing) interpret committed vectors as *multilinear polynomials* and invokes the sum-check protocol of Lund, Fortnow, Karloff, and Nisan [LFKN90]. There are several such grand product arguments one can choose from, offering various tradeoffs between prover time and verifier costs [Tha13, Set20, SL20]. Depending on which grand product argument it invokes, Spice can have proofs of size between *O*(log² *n*) and *O*(log*n*) field elements, where *n* is the number of memory operations proven. The bigger the proofs, the faster the Spice prover.

As described in Appendix A, there are only a handful of known approaches to offline memory-checking for read/write memory [SAGL18, ZGK + 18]. For *read-only* memories there is somewhat more diversity in solutions. Memory-checking arguments for read-only memories are also known as *lookup arguments*, and examples include Arya [BCG + 18], plookup [GW20b], cq [EFG22], Lasso [EFG22], LogUp [Hab22, PH23], and others. We give a brief overview of this body of work in Appendix A.

Baselines for read/write memory: costs of Spice. We refer to Appendix A for an overview of how Spice works. Here, we merely discuss its costs. On each read to memory, the Spice prover commits to 5 values. The first three of these are an address, value, and “timestamp”, while the remaining two arise during range checks that are performed on values derived from the timestamp. In the context of memory-checking within zkVMs like Jolt, all five of these values are “small”, and hence fast to commit to (see Section 3.1 and Footnote 7 for details). 16 (If proving more than 2 32 memory operations, the committed timestamps will not actually meet our threshold for “smallness”. But we will treat them as small for simplicity of accounting–this only leads to an underestimate of the speedups we achieve relative to Spice.)

On top of committing to these 5 values, each read contributes six additional terms contributed to various grand products (see Equation (1)), and proving these grand products requires work by the prover. (Additionally, irrespective of how many memory operations are processed, each memory cell contributes two committed values and two factors to the grand product).

Using the fastest known grand product argument, due to Thaler [Tha13] 17, the prover can process these six factors per read with about six field multiplications each, so roughly 40 field operations in total. This grand product argument has proofs of size *O*(log² *n*). In total this means the Spice prover using Thaler’s grand product argument does 40*T* + 40*K* field operations.

Setty and Lee, in a work called Quarks [SL20], describe an alternative that has proofs of size *O*(log*n*) but <u>has much higher prover costs.</u> In particular, for computing a grand product over a vector of size *n*, the 16Whether we should count committed addresses and write-values towards the costs of the memory-checking procedure is debatable, since the addresses and write-values have to be committed simply to specify the memory-checking instance that Spice is applied to. We choose to count these two committed values towards prover costs. This accounting only has the effect of reducing our claimed factor speedups relative to prior work, since it increases the costs of all memory-checking arguments by the same absolute amount. Thaler’s grand product argument is a refinement of the GKR protocol [GKR15], and our cost accounting for it incorporates recent optimizations [Gru24, DT24].

prover has to commit to *n* partial products, which are going to be random field elements in our context. In the memory checking context, in addition to performing about 40 field operations per read operation as with Thaler’s grand product argument, the prover in Quarks’ has to commit to 6 *random* field elements per operation. 18 Committing to six random field elements is expensive, equivalent in cost to performing over 500 field operations. Quarks more generally describe a spectrum of grand product arguments that have prover time and proof size costs “in between” the above two extremes.

Writes to memory in Spice have similar costs to reads; the only difference is that rather than the Spice prover committing to 5 values, for each write it commits to 6 values.

The above describes Spice’s costs in large prime-order fields. Prover costs are slightly higher for fields of small characteristic (e.g., binary fields), due to complications with how committed timestamps must be specified in these fields [DP23, Section 4.4]. This applies to prior lookup arguments as well.

Baselines for read-only memory: Small or unstructured tables. Lasso’s prover [STW24] commits to 3*T* + *K* small values in total, and performs about 12*T* + 12*K* field operations within the grand product argument. Inspired by the use of Thaler’s grand product argument [Tha13] in Spark [Set20] and Lasso [STW24], LogUpGKR [PH23] combines the LogUp lookup argument [Hab22] with GKR protocol. LogUpGKR’s prover commits 2*T* + *K* small values, which is slightly fewer than the 3*T* committed by Lasso, at least when *K≤T*. But LogUpGKR’s prover performs about twice as many field operations as Lasso’s prover. This stems from LogUpGKR’s use of a “grand sum of rational values” in place of a grand product: summing two rationals, *a/b* + *c/d*, requires three products, namely *a · d*, *b · c*, and *b · d*, to ultimately derive *a/b* + *c/d* = (*ad* + *bc*)*/bd*.

We state the costs of these baselines in Figures 1–3. For all baselines, we incorporate all of the most recent known optimizations to the prover in the GKR protocol and Thaler’s grand product argument [DT24, Gru24]. Further, we assume that the multilinear extension of the table values is efficiently evaluable by the verifier (as is the case for all lookup tables in Jolt, see Footnote 11).

Other relevant baselines are FLI [GM24], a folding scheme for lookups, and Proofs for Deep Thought [BC24], a folding scheme for read/write memory. We discuss these schemes further in Section 2.4.2 below.

Baselines for read-only memory: Gigantic, structured tables. Lasso [STW24] gives two different approaches to performing lookups into gigantic, structured tables. By gigantic, we mean the table size *K* is on the order of *T* *C* for some integer *C ≥* 2. One, called Generalized-Lasso, applies to any MLE-structured table but requires the prover to commit to *c* random field elements, which is generally a bottleneck for the prover. The other, called simply Lasso, applies to tables satisfying a natural decomposability property, which roughly means that one lookup into the giant table can be turned into *O*(*C*) lookups into “subtables” of size at most *T¹* */C* (Lasso then applies a “base” lookup argument to prove validity of the *O*(*C*) subtable lookups). Lasso does not require the prover to commit to any random field elements. Other works have considering using different “base” lookup arguments within this approach [Dor24].

In order to prove that primitive instructions were correctly executed, Jolt applies Lasso to gigantic decom- posable tables (namely, the entire evaluation table of the relevant primitive instruction). However, there are some overheads that come from the interaction of how zkVMs work with Lasso’s use of decompositions. Specifically, the addresses of the subtable lookups have two “parts”, with one part coming from the first input to the primitive instruction, and the other coming from the second part. This forces inputs to be decomposed into smaller chunks than would otherwise be necessary.

For example, to compute the bitwise XOR of two 32-bit inputs *x* and *y*, Jolt currently splits *x* and *y* each into four 8-bit chunks, and uses one subtable lookup (into a subtable of size 2 16 ) to compute the bitwise XOR of each chunk of *x* with the corresponding chunk of *y*. So even though the subtable addresses are 16 bits, *x* 18Two of these six random committed values are from Spice turning each read or write to memory into two separate operations. The other four are from range checks (done using Lasso) that Spice must do to implement appropriate updates to “timestamps” associated with each read and write to memory. See Appendix A for details. Given how expensive it is to commit to random values, when using Quarks as the grand product argument, a naive range check based on bit-decomposition would actually result in a faster prover than using Lasso. This would lower the Spice-with-Quarks-grand-product prover cost by a factor of about 2 compared to what is reported here, but it would not change the qualitative comparison to Twist.

Read/write memory checker Non-zero committed values Field multiplications Proof size

||Spice 5 R + 6 W + 2 K ≈ 11 T 80 T + 80 K ≈ 80 T O (log² Twist (d = 1) R + 3 W = 4 T (5 log(K) + 16) T + O (K log K) O (d Twist (d = 2) 2 R + 4 W = 6 T (5 log(K) + 32) T + O (K) O (d|T) log T) log T)|
|---|---|---|
||Figure 1: Prover costs for Twist: read/write memory checking for R = T reads and W = T writes (R + W memory operations in total). We report a worst-case bound on field multiplications for Twist. For i the Twist prover performs many fewer field operations if memory accesses are local. Roughly, 2 memory accesses (see Section 8.2.1 for a definition) cost only 7 i field multiplications rather than 5 log Appropriate values for d in Twist are discussed in Section 2.8. Reported Twist costs in this table include Booleanity-checking costs. Read-only memory checker Non-zero committed values Field multiplications Proof size Lasso 3 T + min {K,T} 12 T + 12 K O (log² T) LogUpGKR 2 T + min {K,T} 21 T + 21 K O (log² T) Shout (d = 1) T 4 T + O (K log K) O (d log T) Shout (d = 2) 2 T 11 T + O (K) O (d log T)|= 2 T d = 1, -local K.|

Figure 2: Prover costs for Shout (read-only memory checking for *T* reads, into a memory of size *K*). All

committed values are small. Appropriate values for *d* in Shout are discussed in Section 2.8. Reported costs for Shout are inclusive of field multiplications required to prove that committed addresses are valid one-hot encodings (including Booleanity-checking).

and *y* must each be decomposed into only 8-bit chunks. Furthermore, these committed 8-bit chunks must all be range-checked to confirm they are indeed field elements in *{*0*,*1*,...,*2 8 *−* 1*}*. As we will see, Shout avoids any explicit table decomposition, and hence also avoids the above overheads when used in the context of a zkVM such as Jolt.

Closest related work: Generalized-Lasso. Shout can be viewed as a natural generalization or im- provement of the Generalized-Lasso protocol from [STW24]. Shout with *d* = 1 is in fact equivalent to Generalized-Lasso, except that Shout uses any standard (i.e., dense) polynomial commitment scheme to commit to the one-hot encodings of addresses, rather than the sparse polynomial commitment scheme Spark [Set20] invoked by Generalized-Lasso. Shout thereby avoids Generalized-Lasso’s need to commit to random field elements (which comes from Spark). However, setting *d* = 1 only works for very small lookup tables due to the constraints described in Section 1. At the other extreme, Shout with *d* = log*K* (the largest meaningful value of *d*) is roughly equivalent to combining Generalized-Lasso with a different sparse polynomial commitment scheme called “Spark-Naive” [Set20]. Setting *d* this large brings high costs–see Remark 1 for details.

From this standpoint, Shout can be viewed as an improvement in sparse polynomial commitment schemes rather than in lookup arguments. Shout effectively identifies a family of sparse polynomial commitment schemes, with all schemes in the family avoiding Spark’s need to commit to random field elements. There is a different scheme for each value of *d ≥* 1, where committing to bigger, sparser polynomials calls for higher settings of *d*. Shout then simply combines Generalized-Lasso with this family of sparse polynomial commitment schemes. This perspective, of Shout as an advance in the speed of sparse polynomial commitment schemes is made explicit in Section 9.3.1 (as Spartan++, one of our SNARKs for non-uniform circuits, explicitly uses such a Shout-based sparse polynomial commitment, which we call Spark++).

### 2.4 Costs of Twist and Shout

As with offline memory-checking techniques such as Spice, Twist and Shout can be formulated as a polynomial IOPs for the memory-checking problem, and the PIOP can be turned into a SNARK by combining it with any suitable polynomial commitment scheme. Recall that Twist and Shout actually refer to a family of PIOPs

<u>Read-only memory checker Non-zero committed values Number of field multiplications Proof size</u> Lasso *≥* 16*T ≥* 144*T O*(log² *T*) Shout (*d* = 2) 2*T* 42*T O*(*d*log*T*) Shout (*d* = 4) 4*T* 65*T O*(*d*log*T*) Shout (*d* = 8) 8*T* 112*T O*(*d*log*T*)

Figure 3: Prover costs for Shout when doing *T* lookups into an appropriately structured read-only memory

of size *K* such that *K¹* */C* = *o*(*T*) for integer *C* = 4. All committed values are small. Reported Shout costs are inclusive of field multiplications required to prove that committed addresses are valid one-hot encodings (including Booleanity-checking). For comparison, we report (optimistic estimates of) the costs of Lasso as used today in Jolt, whereby each lookup into the table of size *K ≈* 2 64 is decomposed into between 4 and 10 lookups into “subtables” of size 2 16, and where committing to the addresses for those subtables necessitates committing to 2 small values per subtable address and range-checking each such value.

Memory checker Memory size Bits of Committed Data Field multiplications Proof size Lasso *K* = 2 64 (structured) at least 928*T* at least 194*T O*(log² *T*) Shout (*d* = 16) *K* = 2 64 (structured) 256*T* 131*T O*(*d*log*T*) Spice *K* = 32 421*T* 95*T O*(log² *T*) Twist (*d* = 1) *K* = 32 128*T* 35*T O*(*d*log*T*)

Figure 4: Amount of committed data measured in bits for Twist and Shout vs. prior work for two important

applications: the 32 read/write registers of the RISC-V instruction set, and lookups into structured tables of size 2 64 used for proving correct primitive instruction execution in Jolt [AST24]. Bits of committed data is the relevant measure of commitment costs when using binary-field hashing-based multilinear commitments like Binius [DP23, DP24] and Blaze [BCF + 24]. *T* denotes the number of reads in the read-only case, and the number of alternating reads and writes in the read/write case (2*T* total memory operations). We assume values read or written are 32 bits as in RISC-V, and that timestamps used in Spice are up to 32 bits (which is roughly sufficient for values of *T* up to 2 30 ). For Twist and Shout, we omit the field multiplications needed to prove Booleanity, as the commitment schemes themselves ensure this. For prior work (Lasso and Spice), we incorporate the slightly larger prover costs these protocols incur in the setting of small-characteristic fields [DP23, Section 4.4].

parametrized by an integer parameter *d >* 0 that helps control commitment key size (in the case of elliptic curve commitment schemes) or commitment time (in the case of hashing-based commitment schemes). The higher *d* is, the more non-zero values the Twist and Shout provers commit to, and the more field work the Twist and Shout provers do. With elliptic curves commitment schemes *d* will typically be between 1 and 4, and with hashing-based commitments *d* will typically be between 1 and 16. See Section 2.8 for details.

2.4.1 Proof size and verifier costs Twist and Shout avoid invoking a grand product argument. They inherently invokes the sum-check protocol a constant number of times, leading to proofs of size *O*(*d ·* (log(*T*) + log(*K*))), where *T* is the number of memory operations and *K* the size of the memory. When combined with a commitment scheme that has logarithmic-size evaluation proofs such as HyperKZG, Zeromorph, or Dory, they yield SNARKs for memory-checking whose proofs consist of *O*(*d*(log(*T*) + log(*K*))) field and group elements. Via standard batching techniques, the verifier only needs to perform a single evaluation proof verification, which involves a constant number of MSMs of size *O*(log(*T*) + log(*K*)) and a constant number of pairing evaluations.
2.4.2 Prover time Commitment costs. For read operations, both the Twist and Shout provers commit only to the address ra specified via (*d*-dimensional) one-hot encoding. These commitments are unavoidable, as the memory-checking problem formulation itself requires that the address to be committed. The *values* returned by any read operation, captured by the multilinear polynomial rve, need *not* be committed: rve is a virtual polynomial.

For write operations, the Twist prover commits to the address and the value written, plus a single additional “small” value (which we call the write *increment*, a notion we will define later).

Field work. We give a variety of algorithms for quickly implementing the prover in the various sum-check invocations throughout the Twist and Shout PIOPs. Which algorithm to use depends on various aspects including: is the number of memory operations *T* significantly bigger than the memory size *K*? In the case of Twist, are reads and writes to memory local? Here, we provide a concise summary of the prover times we achieve in different contexts. We explicitly state Booleanity-checking costs in each regime (i.e., the cost of proving that various committed values lie in *{*0*,*1*}*), as Booleanity-checking can be omitted when using a commitment scheme like Binius [DP23, DP24] that itself enforces Booleanity of committed values. 19

Shout with *K* = *o*(*T*). We hide additive terms of *O*(*K*) and *O*(*K¹* */d* log*K*) in this summary. The core Shout PIOP with *d* = 1 (Figure 5) costs *T* field multiplications for the prover (Section 6.1). The core Shout PIOP for *d >* 1 (Figure 7) costs *d²* + 1 field multiplications (Section 6.2). Booleanity-checking (Section 6.3) costs an additional 3*dT* field multiplications (other parts of the one-hot-encoding checking PIOP in Figure 8) contribute only low-order costs for the prover). This translates to 4*T* multiplications in total when *d* = 1, 12*T* multiplications when *d* = 2, and so forth.

Shout for gigantic structured memories. Let *C* = *cd* be a constant such that *CK¹* */C* = *o*(*T*). 20 Then the core Shout PIOP (Figure 5) combined with one-hot-encoding-checking costs at most 7*C* + *d²* + 3*d* + *c* + 2 *T* field multiplications. For example, when *C* = 4 and *d* = 2, this translates to 40*T* multiplications. Of these, (4*C* + 3*d*)*T* are due to Booleanity checking. See Section 7.5 for details.

In Appendix C, we describe a variation of Shout with prover work that has a linear rather than quadratic dependence on *d*. Specifically, the *d²T* term in the prover time above is reduced to (8*d −* 7*.*5)*T*. This variant is more efficient for values of *d* that are greater than or equal to 8. Such values of *d* naturally arise for gigantic lookup tables when combining Shout with hashing-based commitment schemes, but not when using commitments based on elliptic curves.

Twist costs. Again we assume *K* = *o*(*T*) and *K¹* */d* log*K* = *o*(*T*) and hence suppress additive terms of *O*(*K*) and *O*(*K¹* */d* log*K*). The core Twist PIOP (Figure 9) costs (5 log(*K*) + 2*d²* + 4*d* + 4)*T* field multiplications in the worst case (Section 8.3). However, when *d* = 1, this calls falls substantially for local memory accesses. Specifically, if the bulk of the memory accesses are 2 *i* -local (meaning they access a cell that was previously accessed at most 2 *i* cycles prior), then the 5 log*K* term falls to just 7*i*. Booleanity-checking costs an additional 6*dT* field multiplications (again, other parts of the one-hot-encoding checking PIOP are low-order costs).

Comparing to prior works. Figures 1–3 give precise comparisons of Twist and Shout to the previously fastest provers in the context of elliptic-curve-based commitment schemes. Twist and Shout generally improve on *both* field multiplications and commitment costs. This improvement holds even when Twist and Shout are configured to have significantly shorter proofs than the prior works.

Exactly how big a prover-time improvement is achieved by Twist and Shout depends on context. Fortunately, the biggest improvements are achieved in the two settings that are most central to the Jolt zkVM: lookups into gigantic structured tables (i.e., how Lasso is current used in Jolt to prove correct execution of primitive RISC-V instructions), and reads and writes into 32 RISC-V registers (two such reads and one such write occur in Jolt for nearly every cycle of the RISC-V CPU).

In the case of gigantic structured lookup tables, Shout improves up to 8*×* in commitment costs and up to about 3*×* in field multiplications relative to Lasso’s application in Jolt today. The largest improvements are achieved when Shout is applied with *d* = 2, which is appropriate if using Dory as the polynomial commitment scheme (see Section 2.8 for details). Shout actually achieves even bigger improvements for some lookup tables, 19Arguably, this merely pushes the field multiplication necessary for Booleanity-checking into the polynomial evaluation protocol of the polynomial commitment scheme, as that phase itself invokes the sum-check protocol [DP24]. *C* may be smaller than *d* when *d* is very large, e.g., *d* = 16. Such settings of *C* and *d* naturally arise when using hashing-based commitments but typically not with elliptic curve commitments.

since the costs of prior work depend on how “nicely decomposable” the table is, and that varies for the lookup tables arising in Jolt.

In the case of 32 read/write registers, where *d* = 1 is appropriate regardless of the commitment scheme used (again, see Section 2.8 for details), Twist improves over the commitment costs of Spice by about 3*×* and the field multiplications of Spice by a factor of 2.

For larger read/write memories, we expect Twist to achieve more modest but still significant speedups over prior work (while also achieving significantly reduced proof size).

Figure 4 compares Twist and Shout to prior works in the context of hashing-based commitment schemes.

For small memories, both the commitment costs and field work of Twist improve by 2*×*-3*×*. For very large real-only memories (e.g., structured lookup tables of size 2 64 as arise in Jolt), Shout’s commitment costs improve at least 3*×* compared to prior work, while prover field work improves more modestly. Again, Shout achieves bigger improvements for some lookup tables.

Comparison of Shout to FLI. Shout with *c* = 1 has quite a bit in common with FLI [GM24]: They both represent addresses via one-hot encoding, commit to the one-hot encodings with curve-based commitments (at the cost of one group operation per address for the prover), and observe that given the one-hot encodings, the validity of the lookups can then easily be expressed via R1CS. Unlike Shout, FLI then directly applies a Nova-type folding scheme [KST22] to fold these R1CS instances. Shout instead applies the sum-check protocol to directly prove satisfaction of the R1CS.

Inspired by Lasso [STW24], FLI also considers lookups into giant, decomposable tables. In this context, our improvements over FLI are analogous to our improvements over Lasso: by avoiding table decompositions, Shout lowers the amount of committed data (see Section 2.3 for details).

Ideas from FLI offer one possible approach to combining Shout with folding. In a nutshell, Shout can be directly turned into a folding scheme using the NeutronNova framework [KS24b], achieving better efficiency. More generally, Section 2.9.3 discusses various approaches to combining both Twist and Shout (and zkVMs that use them) with folding techniques.

Comparison of Twist to Proofs for Deep Thought. B¨unz and Chen [BC24] present an incremental verifiable computation (IVC) framework for read/write memory (while FLI targets read-only memory). Their solution involves techniques reminiscent of Twist’s use of increments. However, to check correctness of the increments they invoke Spice [SAGL18] and LogUp [Hab22]. The focus of Twist and Shout is precisely to eliminate the overheads of these prior memory-checking arguments. Hence, B¨unz and Chen’s work can be viewed as targeting how to efficiently “link” the state of memory between adjacent shards in an instance of IVC, but they incur overheads similar to the baselines we consider and improve upon.

### 2.5 Overview of Shout

2.5.1 The sum-check protocol in a nutshell Let *g* be an *ℓ*-variate polynomial over field F. From the verifier’s perspective, the sum-check protocol is an efficient reduction from the task of computing
X *g*(*x*) (2) *x∈{*0*,*1*}ℓ*

to the potentially easier task of evaluate *g*(*r*) for a *r ∈* F *ℓ* chosen at random by the verifier over the duration of the protocol. So long as *g* has constant degree in each of its variables, the proof length of the sum-check protocol is *O*(*ℓ*) field elements, and the soundness error is *O*(*ℓ/|*F*|*).

2.5.2 The Shout PIOP when *d* = 1 Shout is targeted at read-only memories. Let Val(*k*) denote the fixed value of register *k*. Shout with *d* = 1 is a special case: to obtain the best possible prover costs, our protocol for *d* = 1 deviates substantially from the

#### general case of d > 1.

As observed in Baloo [ZGK + 22] and Lasso [STW24], the lookups are all valid if and only if for every cycle *j*,

X ra(*k,j*)Val(*k*) = rv(*j*)*.* (3) registers *k*

Indeed, since ra(*k,j*) = 1 for the register *k* that was read at cycle *j* (and ra(*k* *′* *,j*) = 0 for all other registers *k* *′* *̸*= *k*), Equation (3) holds if and only if rv(*j*) equals Val(*k*). To check that these constraints are satisfied, the verifier picks a random *r*cycle*∈* F log *T*, and the sum-check protocol is applied to confirm that:

X rve (*r*cycle) = rae (*k,r*cycle) *·* Val f (*k*)*.* (4) *k∈{*0*,*1*}*log *K*

Here, rae, rve, and Val f are the *multilinear extension polynomials* of the vectors ra, rv, and Val respectively,

Indeed, the right hand side of Equation (4) is a multilinear polynomial in *r* *′* and this polynomial agrees with rve at all *r* *′* *∈{*0*,*1*}* log *T* if and only if all constraints from Expression (7) are satisfied. Hence, the right hand side and left hand side of Equation (8) are equal as formal polynomials if and only if all constraints are satisfied. By the Schwartz-Zippel lemma, up to soundness error log(*T*)*/|*F*|*, checking that Equation (8) holds at a randomly chosen *r* *′* *∈* F log *T* is equivalent to checking all constraints are satisfied.

At the end of the sum-check protocol, the verifier has to evaluate rae (*r*address*,r*cycle), Val f (*r*address). for random values *r*address*∈* F log *K* and *r*cycle*∈* F log *T* chosen by the verifier. The verifier can can obtain the rae (*r*address*,r*cycle) evaluation from the commitment to that polynomial. For many lookup tables (including all arising in the Jolt zkVM [AST24]), the verifier can evaluate Val f (*r*address) on its own in *O*(log*K*) time. Following Lasso [STW24], we call such tables *MLE-structured*. For non-MLE-structured tables, Val f can be committed in advance by an honest party, and the verifier can force the prover to provide the necessary evaluation of Val f.

This is the entire core Shout PIOP for *d* = 1. It is essentially just the Generalized-Lasso protocol from [STW24], but without using the Spark sparse polynomial commitment scheme to commit to the rae polynomial. Avoiding Spark is important, as Spark requires committing to several random values per lookup, which is a prover bottleneck both concretely and asymptotically.

The core Shout PIOP sketched above assumes all committed addresses are valid one-hot encodings of values in *{*0*,*1*,...,K −* 1*}*. In Section 4.1.2, we give a separate PIOP for confirming this is the case. This PIOP amounts to identifying a straightforward (very large, but sparse) constraint system capturing correctness of one-hot encodings, and showing that the satisfaction of all constraints can be proved in time proportional to the sparsity of the constraint system rather than the size.

2.5.3 The Shout PIOP when *d >* 1 A more expensive but generalizable protocol for *d* = 1. The *d* = 1 case is special because only when *d* = 1 is the right hand side of Equation (4) multilinear in *r*cycle. This allowed us to avoid a sum over *j ∈{*0*,*1*}* log *T*
on the right hand side of Equation (4). Before covering the *d >* 1 case, we give a slightly *different* PIOP for the *d* = 1 case that *does* sum over *j ∈{*0*,*1*}* log *T*. This PIOP is less efficient than the one in Section 2.5.2, but generalizes straightforwardly to *d >* 1.

Recall from Equation (3) that checking that all reads are correct is equivalent to confirming that for all cycles *j*, the following constraint is satisfied: X ra(*k,j*)Val(*k*) = rv(*j*)*.* registers *k*

To check that this, the verifier can pick a random *r* *′* *∈* F log *T* and apply the sum-check protocol to confirm that:

X rve (*r* *′* ) = eqe (*r* *′* *,j*) *·* rae (*k,j*) *·* Val f (*k*)*.* (5) *k∈{*0*,*1*}*log *K, j∈{*0*,*1*}*log *T*

Here, rae, rve, and Val f are the multilinear extension polynomials of the vectors ra, rv, and Val respectively, while eqe is the multilinear extension of a standard function known as the equality function (see Section 3.2 for details).

|||e (r ,r ), ra|,r|
|---|---|---|---|
|||′ cycle|address cycle|
|′ cycle|log T|||

At the end of the sum-check protocol, the verifier has to evaluate eq e (*r*), Val f (*r*address) for random values *r*address*∈* F log *K* and *r,r ∈* F chosen by the verifier over the course of the protocol. The verifier can compute the eqe evaluations on its own in *O*(log*K*+ log*T*) time, and the remaining evaluations are obtained exactly as in Section 2.5.2.

Obtaining a fast prover in this application of the sum-check protocol is a challenge that did not arise in the simpler application of Section 2.5.2. The issue is that the sum in Equation (5) is over *K·T* terms, so naively implemented, the prover in this application of sum-check would perform *O*(*KT*) field operations. This would make Shout more expensive than prior lookup arguments, except for very small memories (say, *K ≤* 10 or so).

Fortunately, Equation (5) is a *very* special application of sum-check. For example, rae (*k,j*) is sparse: only *T* out of *KT* of its evaluations are non-zero over the domain *{*0*,*1*}* log *K* *×{*0*,*1*}* log *T*. And there’s additional structure on top of that, such as the fact that Val f depends only on *k* and not on *j*. Leveraging all of this structure, one can implement the sum-check prover with just *O*(*K*) + 5*T* field operations (up to low-order terms).

Shout for *d >* 1. Fix an integer *d >* 1 and let *N* = *K¹* */d*. We view the memory of size *K* as a *d*-dimensional cube of length *N* in each dimension, indexing the cube by [*N*] *d* where [*N*] = *{*0*,*1*,...,N −*1*}*. As in Section 2.2 for a sequence of *T* reads into memory, let raf(*j*) *∈* [*K*] *⊆* F denote the address read by the *j*’th memory operation, with the address specified as a single field element. Reinterpret raf(*j*) as an element of [*N*] *d* using the natural bijection between [*K*] and [*N*] *d*, and for *i* = 1*,...,c*, let ra*i*(*·,j*) denote the one-hot encoding of the *i*’th coordinate of raf(*j*), i.e., ra*i*(*k,j*) equals 1 if the *i*’th coordinate of ra(*j*) equals *k*, and equals 0 for all other *k ∈* [*N*]. We call this the *d-dimensional one-hot encoding* of raf(*j*).

The Shout prover commits to the *d* multilinear extension polynomials rae₁*,...,* rae*d*. This entails committing to *dN* field elements per cycle, of which exactly *d* per cycle are 1, and the rest of 0.

Because only *dN* = *dK¹* */d* rather than *K* field elements are committed, the size of the commitment key (when using a polynomial commitment scheme like HyperKZG) falls from *K* group elements to *dN* group elements. For example, by setting *d* = 2, a HyperKZG commitment key of size 2 *·* 2 20 suffices to prove 2 20 reads into a memory of size *K* = 2 20, and this commitment key is under 100 MBs in size. This can be reduced even further at the cost of a small increase in verifier costs via standard batching techniques (see Section 3.1.1).

Then the Shout PIOP applies the sum-check protocol to compute the following variation of Equation (5):

!

|||d|
|---|---|---|
|′||′ ℓ ℓ|
|k=(k₁,...,k|), j∈{0,1}|ℓ=1|

X Y rve (*r*) = eqe (*r,j*) *·* rae (*k,j*) *·* Val f (*k*)*.* (6) *d*

)*∈*(*{*0*,*1*}*log *N d* log *T*
The right hand side of Equation (6) has degree three in each variable of *k* exactly as in Equation (5), but the degree in each variable of *j* increases from 3 in Equation (5) to 2 + *d*. This degree increase raises the prover’s time to *O*(*K* +*d² · T*). In Appendix C, we give a variation of Shout that reduces the prover’s runtime dependence of *d* from quadratic to linear. It comes with worse constant factors, and hence concretely offers an improvement only for *d ≥* 8. We suspect that additional improvements for large values of *d* are possible.

Shout for gigantic, structured tables. In fact, for ”structured” tables (including all of those arising in the Jolt zkVM), we can invoke the sparse-dense sum-check protocol [STW24, Appendix G] to nearly remove the dependence on *K*. If *K* is very large (i.e., *K≈T* *C* for *C >* 1) the sum-check prover can in fact be implemented in time *O*(*CK¹* */C* + *CT*) = *O*(*CT*). We further explain how to generalize the sparse-dense sum-check protocol to achieve a similar time bound for proving that all committed addresses are correct one-hot encodings of values in *{*0*,*1*,...,K −* 1*}*.

Remark 1 (The relationship between Shout and Generalized-Lasso). *Shout with d* = log *K (the largest* *possible value of d) is roughly equivalent to running the Generalized-Lasso protocol of [STW24], but using* *“Spark-naive” [Set20, Section 7.1] instead of Spark [Set20, Section 7.2] as the sparse polynomial commitment* *scheme to commit to the one-hot encodings of addresses (see also [STW24, Appendix D] for an overview of* *Spark-naive).*

*Indeed, Spark-naive commits to the* binary representation *of each address (i.e., the index of each non-zero* *entry of the sparse vector being committed). This is very similar to what Shout does when d* = log *K.*

*What’s going on is that Shout has the prover commit to addresses using the one-hot encoding of the digits of* *the address* when represented in base *K¹* */d* *. Spark-naive represents addresses in base-*2 *(i.e., binary), which* *matches the base used by Shout when d* = log *K. Prior works like Spark-naive do not use one-hot encodings.* *However, the standard encoding and one-hot encoding of a value* almost coincide *for base-*2*: in both cases* *each bit in the binary representation of an address is represented in the encoding with one or two bits.*

*Setting d in Shout to its maximum value of* log *K minimizes the number of committed bits for the prover,* *leading to the fastest possible commitment computation when using a binary-field hashing-based commitment* *scheme like Binius [DP23, DP24]. However, the downsides of taking d this big outweigh the advantages: the* *prover time “outside of committing” is superlinear (i.e, at least O*(*T* log*K*) *field multiplications) and the* *proof size is somewhat big (i.e, O*(log²(*K*) + log(*T*) log(*K*)) *field elements).*

*The fastest prover in Shout (as well as short proofs) is obtained by taking d to be as small as possible, subject* *to the appropriate constraints.*

### 2.6 Overview of Twist

Recall that there are 2*T* memory operations, which alternate between reads and writes (say, with the first operation being a read). It is convenient to number both the read-cycles and the write-cycles from 0 up to *T*.

A first attempt. We first explain a somewhat naive approach to memory-checking, which has high costs, before explaining how to lower the costs.

Recall the memory has size *K*, and let [*K*] = *{*0*,...,K −* 1*}*. We can have the prover commit to the value, Val(*k,j*) of every register *k ∈* [*K*] for every cycle *j ∈* [*T*]. We do have to find a way to ensure that the committed values are actually correct, i.e., that the committed value Val(*k,j*) is indeed the value most recently written to register *k* when cycle *j* is executed. We address how to do this later in our overview.

Once the Val(*k,j*) values are committed and confirmed to be correct, one can force rv*j*to equal the value stored in cell ra*j*at cycle *j* by confirming that X ra(*k,j*) *·* Val(*k,j*) = rv(*j*) for all cycles *j ∈* [*T*]*.* (7) *k∈*[*K*]

If register *k* is the (unique) register read at cycle *j*, then ra(*k,j*) = 1 and ra(*k* *′* *,j*) = 0 for all *k* *′* =*̸ k* with

|′ log K|||
|---|---|---|
||′|log T|
||′ (k,j)∈{0,1}|×{0,1}|

*k* *′* *∈{*0*,*1*}* log *K*, and Equation (7) is therefore satisfied if and only if rv(*j*) = Val(*k,j*), i.e., the value returned by the read at cycle *j* equals the value stored in register *k* at that cycle. To check that these constraints are satisfied, the verifier picks a random *r ∈* F, and the sum-check protocol is applied to confirm that:

X rve (*r*) = eqe (*r* *′* *,j*) *·* rae (*k,j*) *·* Val f (*k,j*)*.* (8) log *K* log *T*

Indeed, the right hand side is multilinear in *r* *′* and agrees with the left hand side at all *r* *′* *∈{*0*,*1*}* log *T* if and only if Equation (7) is satisfied. Hence, the right hand side and left hand side are equivalent as formal polynomials if and only if Equation (7) is satisfied, and up to soundness error log(*T*)*/|*F*|* it suffices to check equality at a single random point *r* *′* *∈* F log *T*.

We call this invocation of sum-check the *read-checking sum-check*. It is very similar to the core Shout PIOP (Section 2.5.2). It is not quite as structured as the sum-check instance arising in Shout, but we are nonetheless able to show how to implement the prover in *O*(*K* + *T* log*K*) time, an exponential improvement in the dependence on *K* compared to a naive *O*(*KT*)-time prover implementation. We do this by leveraging two properties. First, that ra(*k,j*) is sparse: only *T* out of *kT* of its entries are non-zero. Second, that when moving from cycle *j* to *j* + 1, only one entry of Val(*k,j*) changes (namely, the register written at cycle *j*).

|||cycle|log T|
|---|---|---|---|
|address cycle|′ cycle|log T||

At the end of the read-checking sum-check, the verifier needs to evaluate rve at a random point *r ∈* F, Val f at a random point (*r,r*) *∈* Flog *K×* Flog *T*, and eqe at (*r,r*) *∈* Flog *T×* F. The eqe evaluation can be computed by the verifier directly in *O*(log*T*) time. The verifier can obtain the evaluations of rve and Val f from the commitments to these polynomials.

The key performance issue with the above proposal is the cost of committing to the vector Val(*k,j*) (or more precisely, its multilinear extension Val f). This vector specifies all register values at all cycles means committing to *K* non-zero values per cycle. Even for very small memories like *K* = 32, this alone is more expensive than Spice, which commits to only 7 small values per read and 8 per write.

Enter increments: virtual polynomials to the rescue. To avoid this, we use an idea implicit in many works involving the sum-check protocol, and explicit in Binius, which refers to the notion of “virtual polynomials” [DP23]. These are polynomials that are *not* committed by the prover, but that the verifier can “pretend” are committed. We already discussed virtual polynomials in Section 2.2, in the context of evaluating the multilinear polynomials raf f and waf g (which specify addresses via a single field element rather than one-hot encoding).

In more detail, if the sum-check protocol is applied to a polynomial derived from *p*, then at the end of the sum-check protocol the verifier has to evaluate *p* at a random point *r*. If *p* were committed with a polynomial commitment scheme, then *p*(*r*) could be provided by the prover along with a proof that the provided evaluation is correct.

However, if *p* is expensive to commit to directly, the prover will not want to commit to *p*. The idea of virtual polynomials is to have the prover commit to *p indirectly* as follows. Suppose there is some alternative *ℓ*-variate polynomial *q* that is cheaper to commit to than *p*. Moreover for any input *r* to *p* P, there is some

|(which depends on r) such that the following two properties hold: (1) p(r) =|||g|
|---|---|---|---|
|r|||x∈{0,1} r|
|′||r ′||
|′|r ′|′|r|

polynomial *g ℓ* (*x*)*,* and (2) For any point *r*, the verifier can quickly derive *g* (*r*) from *q*(*r* *′* ).

Then when the verifier needs to evaluate *p*(*r*), it can simply apply the sum-check protocol to *g*, at the end of which the verifier needs to evaluate *g* (*r*) for a random point *r*. And by (2) above, for this, it suffices for the verifier to learn *q*(*r*). Since *q was* committed by the prover, the prover can provide this evaluation directly.

In the case of Twist, the polynomial *p*(*k,j*) = Val f (*k,j*) is expensive to commit to directly, since it requires committing to *K* non-zero values per cycle *j*. Instead, let us define the polynomial *q*(*k,j*) = Inc f (*k,j*) as the (multilinear extension of) the *increments* of Val. Here, we define the increment of register *k* at cycle *j ∈* [*T*] to be the difference between the register’s value at cycle *j* vs. cycle *j −* 1. In other words,

Inc(*k,j*) := Val(*k,j* + 1) *−* Val(*k,j*) = wa(*k,j*) *·* (wv(*k,j*) *−* Val(*k,j*))*.* (9)

Here, the final equality holds by the following reasoning. If register *k* is not written at cycle *j*, then wa(*k,j*) = 0, and that forces Inc(*k,j*) to 0 per the right hand side of Equation (9). While if register *k* is written at cycle *j*, then wa(*k,j*) = 1, and the right hand side of Equation (9) forces Inc(*j*) to be the difference between wa(*k,j*), i.e., the value written at cycle *j*, and Val(*k,j*), the value stored at that cell at the start of the cycle.

The key point is that, since only one register is written per cycle *j*, Inc(*k,j*) is non-zero for only one register

*k*. Moreover, since registers contain 32-bit values, the one non-zero increment at each cycle *j* is “small” (i.e., in *{−*2 32 *−* 1*,...,*2
32 *−* 1*}*), and hence fast to commit to. This makes Inc f roughly *K* times cheaper to commit to than Val f.

Giving the verifier query-access to Val f. But now we run into the key issue arising from the use of virtual polynomials: recall that at the end of the zero-check for correctness of read operations, the verifier has to evaluate Val f (*r*address*,r*cycle) for a random point

(*r*address*,r*cycle) *∈* F log *K* *×* F log *T*

*.* (10)
Since Val f is not committed directly, it is not obvious how the verifier can obtain this evaluation. The way to do it is to apply the sum-check protocol to the following equation:

X

|f (r Val|,r ) =||f (r Inc|f(j ,j ) · LT|,r ).|
|---|---|---|---|---|---|
|address ′|cycle|j ∈{0,1}|address ′|log T address|cycle cycle|
|address|cycle|log K|log T|||
||||||′|

address cycle address *′ ′* cycle(11) *′* log *T*

We call this the Val f*-evaluation sum-check*. Here, LT is the multilinear extension of the function the so-called *less-than* function, which takes as input two binary strings *j,j ∈{*0*,*1*}* and outputs 1 if and only if the integer represented by *j* is *strictly* less than the integer represented by *j*. One can check that Equation (11) holds because the right hand side is multilinear in the variables of *r* and *r*, and agrees with the right hand side whenever (*r,r*) *∈{*0*,*1*} ×{*0*,*1*}*, owing to the fact that the value of any register *k* at time *j* is the sum of the increments for that register at all cycles *j < j*.

At the end of the Val f -evaluation sum-check, the verifier needs to evaluate Inc f at a random point and LT f at a random point. The former evaluation can come from the commitment to Inc f, while the latter the verifier can perform on its own in time *O*(log*T*) (see Section 3.2 for details).

The remaining issue. We have deferred until now discussion of how to ensure that each value Val(*k,j*) is the actual value stored in register *k* at cycle *j*. Given that Val(*k,j*) is in fact implicitly specified by Inc(*k,j*) per Equation (11), this problem manifests as ensuring that the committed polynomial Inc f indeed equals (the multilinear extension of) the *correct increments*, per the definition in Equation (9).

To check this, we apply the zero-check PIOP once again, to confirm that indeed for all *k ∈{*0*,*1*}* log *K* and *j ∈{*0*,*1*}* log *T*, Inc(*k,j*) = wa(*k,j*) *·* (wv(*j*) *−* Val(*k,j*))*.*

This involves the verifier picking a random *r* *′* *∈* F log *K* and *r* *′′* *∈* F log *T* and applying the sum-check protocol to confirm that X

|′ ′′|′ ′′ ′|
|---|---|
|(k,j)∈{0,1}||

Inc f (*r,r*) = eqe (*r,k*) *·* eqe (*r,j*) *·* wa f(*k,j*)(wv f(*j*) *−* Val f (*k,j*))*.* (12) log *K×{*0*,*1*}*log *T*

#### We call this the write-checking sum-check.

At the end of the write-checking sum-check, the verifier needs to evaluate each of Inc f, wa f, wv f, and Val f each at a random point. Since Inc f, wa f and wv f are committed by the prover already, the required evaluations of these polynomials can be obtained directly from the prover. The evaluation of Val f can be obtained via another invocation of the Val f -evaluation sum-check. In fact, by running the read-checking and write-checking sum-check instances in parallel, we can ensure only one evaluation of Val f is needed, and hence we only need to run the Val f -evaluation once.

Summary of the protocol. Twist had to address three issues:

- How to “implicitly commit” to Val f given that explicitly committing to Val f would be expensive (requiring *K* committed non-zero values per cycle).
- How to confirm that Val f actually assigns the correct value to each register at each cycle, given the committed sequence of write operations specified by wa f, and wv f. In other words, how to make sure the prover processed all the writes correctly.
- How to ensure that each read operation (specified by the committed polynomial rae and the virtual polynomial rve) returns the correct value. In other words, how to make sure the reads were processed correctly.
The first issue was addressed by committing to the *increments* Inc f rather than to Val f. Committing to Inc f is cheap because Inc f is sparse and its non-zero entries are small.

The second issue (checking writes) was addressed via the write-checking sum-check (Equation (12)).

The third issue (checking reads, and giving the verifier query access to the virtual polynomial rve) was addressed by the read-checking sum-check (Equation (8)).

At the end of the read-checking and writing-checking sum-checks, the verifier has to evaluate Val f at a random point. This is addressed via the Val f -evaluation sum-check (Equation (11)). This equation expresses the necessary Val f evaluations in terms of Inc f as per Equation (11).

### 2.7 Other benefits and implications

Improved soundness error. Offline memory-checking techniques introduce soundness error at least (*T* + *K*)*/|*F*|* where *T* is the number of memory operations proven and *K* is the size of the memory, thanks to the grand product in Equation (1) introducing a univariate polynomial in the random field element *r*, of degree Θ(*T* + *K*). Meanwhile, the method of one-hot addressing has soundness error of only log(*TK*)*/|*F*|*.

This difference is not important when working over 256-bit prime order fields, as required by most standard elliptic curves. However, there may be contexts where it is relevant. For example, consider elliptic curves defined over extensions of 64-bit prime fields and targeted at a security level of 128 bits [SSS22]. To keep as much of the prover’s work as possible over a relatively small subfield (thereby keeping the field operations relatively fast), SNARK designers will want to choose the value *r* from Equation (1) at random from a 128-bit subfield (i.e., a degree-2 extension of the 64-bit base field). However, if the memory size *K* is, say, one billion, this will lead to only at most 98 bits of security, due to the soundness error of at least 2 30 */*2 128 = 2 *−*98. Processing a trillion cycles (equivalent to a couple of minutes of single-threaded compute on a modern laptop), at least without invoking SNARK recursion, would lead to an even lower security level, of 2 *−*88. The method of one-hot addressing, by contrast, achieves over 120 bits of security in these settings.

Benefiting from small memories and locality. Modern CPUs can make random accesses to a large memory. But they also have smaller, faster memories. At the extreme end are *registers*, which are very fast memory cells directly accessible to the processor. In contrast, offline memory checking techniques are not substantially more efficient when applied to small memories. That is, the cost of proving *T* reads and writes into a memory of size *K* is roughly *O*(*T* + *K*) committed values and field operations, and hence this cost is about the same for all all *K≤T*. In other words, zkVM provers do not currently enjoy the benefits of small, fast memories like registers or caches, the way actual CPUs do. The cost profile of Twist matches that of actual CPUs much more closely. For starters, the smaller the memory, the smaller the parameter *d* can be in both Twist and Shout, and the smaller *d* is, the lower the commitment costs and prover field multiplications in both Twist and Shout. Furthermore, the Twist prover (appropriately implemented, see Section 8 for details) performs many fewer field multiplications for *local* memory accesses–reads and writes to memory cells that were recently read from or written to.

The closer the prover cost profile of zkVMs matches that of actual CPUs, the more likely it is that existing compilers (optimized for actual CPUs rather than SNARK provers) lead to fast zkVM proving. In other words,

Twist and Shout offer a strong counterpoint to a prevailing belief that it is better for zkVM performance to design “SNARK-friendly” VMs, rather than using mature toolchains for existing VMs like RISC-V that were not designed with SNARK proving in mind.

### 2.8 Appropriate settings of d

How to set *d* when using elliptic curve commitments. When applying Twist and Shout with an elliptic curve commitment scheme, there are multiple tools at the protocol designer’s disposal to control commitment key size. One is the precise choice of polynomial commit scheme. For example, Dory has square-root sized commitment key, while HyperKZG is linear-sized commitment key. So using Dory rather than HyperKZG helps to control commitment key size. Of course, the choice of Dory comes with its own costs, such as concretely larger polynomial evaluation proofs and the need to do (in addition to MSMs) a *√* multi-pairing of size *n* when committing to a polynomial of size *n*.

Another tool is the ability to reduce commitment key size by any desired factor *k* at the cost of increasing commitment size from one group element to *k* (see Section 3.1.1 for details).

As a separate and complementary tool, we also introduced the parameter *d* to Twist and Shout themselves. If one uses parameter *d* with Dory as the commitment, the commitment key size is Θ (*K¹* */d* *· T*) 1*/*2 when proving *T* accesses to a memory of size *K*. If one uses parameter *d* and HyperKZG as the commitment, the commitment key size is Θ(*K¹* */d* *· T*).

Generally speaking, for commitment schemes based on elliptic curves, one wants to set *d* as small as possible subject to the constraint that the commitment key is not too large for the prover to generate and store (the key must be big enough to commit to *d* vectors of length *N* = *K¹* */d* ).

How to set *d* when using hashing-based commitments. For commitment schemes based on hashing over binary fields like Binius, one also wants to set *d* as small as possible, but subject to a very different constraint. Since 0s are not free to commit to with hashing-based schemes, the key constraint is ensuring that committing is sufficiently fast. The larger *d* is, the faster it is to commit to addresses in Twist and Shout with a binary-field hashing-based commitment scheme, but the more work the prover does in the sum-check protocol (and the larger the proof size). Hence, with hashing-based commitment schemes, *d* should be chosen large enough that committing to addresses in Twist and Shout is not the prover bottleneck, but no larger.

For illustration, we now discuss how one can set *d* in various applications covering the gamut of memory sizes, from tiny to large.

Application 1: *K* = 32, *T* = 2 20. Recall that zkVMs today break CPU executions into “shards” consisting of roughly 2 19 cycles each. Also, the RISC-V ISA has 32 registers, with each cycle reading two registers and writing to one. Hence, one important application is to *K* = 32 with *T ≈* 2 21. In this case, setting *d* = 1 in Twist and using HyperKZG leads to a commitment key (powers-of-tau SRS) containing 32 *·* 2 21 = 2 26

group elements. This is smaller than some powers-of-tau SRSes that have already been generated (which have contained up to 2 29 powers of tau²¹), though it does require GBs of prover storage. Per Section 3.1.1, one can further lower SRS size, say to 2 21, by increasing the size of the commitment from one group element to 2 5 = 32 group elements. Or one could keep the commitment size at one group element, but use *d* = 2, obtaining an SRS size of only about 2 11 group elements.

With a hashing-based commitment scheme over GF(2 128 ) like Binius or FRI-Binius [DP23, BCF + 24] or Blaze [BCF + 24], the key issue to address is not commitment key size, but rather the time cost of committing to each address (as 0s are not free to commit to with these schemes). For this application, the memory is sufficiently tiny that one can set *d* = 1 and maintain small commitment costs. This requires the prover to commit to 32 values in *{*0*,*1*}* per address. Four such addresses could be packed into a single GF(2 128 ) before committing. 21See for example [https://github.com/privacy-scaling-explorations/perpetualpowersoftau](https://github.com/privacy-scaling-explorations/perpetualpowersoftau).

Application 2: *K* = 2 20, *T* = 2 20. This captures VMs with several MBs of main memory (alternatively, it captures typical L2 or even L3 cache sizes on modern CPUs). With HyperKZG, one cannot take *d* = 1, as this would lead to an SRS of size *KT* = 2 40. However, setting *d* = 4 is feasible, leading to an SRS size of *K¹* */d* *· T* = 2 25 with address commitments consisting of *d* = 4 group elements. As above, this SRS size can be driven lower with a further increase in commitment size. *√* Using Dory instead of HyperKZG, one can take *d* = 1, leading to a commitment key of size 2 *· KT* = 2 21 group elements in a pairing-friendly group (2 20

from G₁ and 2 20 from G₂).

As discussed in Section 1, *d* = 4 is also a reasonable setting in this application if using a hashing-based multilinear commitment scheme over GF(2 128 ), such as Binius or FRI-Binius [DP23, BCF + 24] or Blaze [BCF + 24]. Then each each address is specified by *dK¹* */d* = 4 *·* 2 20*/*4 = 2 7 = 128 bits, which can all be packed into a single GF(2 128 ) field element before committing.

Application 3: *K* = 2 30, *T* = 2 32. We anticipate that techniques for controlling prover space *without* invoking SNARK recursion [NT25] will eventually enable efficient non-recursive proving of *T* = 2 30 or more RISC-V cycles. *K* = 2 30 corresponds to giving the VM about 4 GBs of main memory (RAM).

Applying Twist to prove *T* = 2 32 memory accesses is incompatible with commitment schemes like HyperKZG requiring a linear-size SRS. But with Dory, *√* one could set *d* = 2 and obtain a commitment key of size 2 *· K¹/d· T ≈* 2 26 group elements. This could be further lowered per Section 3.1.1 at the cost of increasing the size of the commitments.

Application 4: *K* = 2 64, *T* = 2 20 (structured read-only memory). This captures “primitive instruction execution” lookups in Jolt. With HyperKZG, one could set *d* = 8 and have address commitments consist

||/d|26||
|---|---|---|---|
|||/d|18 19|
||27|||
|128||||
|64/16|||128|

of 4*c* = 32 group elements. This would lead to an SRS with *K¹ /*4 *· T* = 2 group elements, which is significantly smaller than some powers-of-tau SRSes that have been generated today. *√* With Dory, setting *d* = 4 would lead to a (transparently generated) commitment key of size just 2 *K¹ · T* = 2*·* 2 = 2. One could even take *d* = 2, which would give a commitment key of size 2, and this key size could be further reduced at the cost of larger commitments per Section 3.1.1.

If using a hashing-based commitment scheme over GF(2), a reasonable setting of *d* is 16. Then the number of bits in each committed address is *d · K¹* */d* = 16 *·* 2 = 256 bits. These can be packed into two GF(2) field elements before committing.

### 2.9 Additional discussion

2.9.1 Pros and cons of Dory Dory is an especially attractive choice of polynomial commitment scheme for combination with Twist and Shout. This is primarily because it is a curve-based commitment scheme with a sublinear-size commitment key, and this helps keep the parameter *d* in Twist and Shout small (which in turn ensures very few committed values, and minimal field work for the prover). Implementations of Dory exist²², but Dory has not seen wide deployment to date. We briefly discuss the downsides of Dory that are the likely reasons it hasn’t been widely deployed, and argue that these aspects of Dory do not preclude its use in contexts where its cost profile is particularly valuable. We believe Twist and Shout offer the most compelling such context to date. One potential downside of Dory is that
*√* when committing to a polynomial *√* of size *N*, computing the commitments involves (in addition to *N* multi-exponentiations of size *N*, which is roughly equivalent in cost to other elliptic curve commitment schemes like KZG or HyperKZG, Bulletproofs/IPA, etc.), a *√* multi-pairing of size *N*. For small values of *N* the multi-pairing can be a prover bottleneck. But for moderate-to-large values of *N*, this will not be the case. Indeed, a pairing evaluation is equivalent in cost to at most about 4000 group operations, and multi-pairings also benefit from a “Pippenger’s speedup” meaning *√ √* a multi-pairing of size *N* is actually a factor of pip *≈* (1*/*2) log(*N*) faster than *N* independent pairings. 22[https://github.com/yacovm/DualDory](https://github.com/yacovm/DualDory)

This means that if Shout is applied (even with *d* = 1) to, say, *T ≥* 2 22 memory operations, the multi-pairing *√* will not be a prover bottleneck, as the multi-pairing will be equivalent in cost to 4000 *· T/*pip *≪* 2 22 group operations, while the MSMs involved in the commitment will cost this much or more. *√* Furthermore, for any *t >* 1, Dory can be configured so the multi-pairing is only of size *√* *N/t*, at the cost of increasing the commitment key size to *t N*.

Another aspect of Dory that may be construed as a downside is that its proofs consists of 6 log*N* elements of the target group of a pairing-friendly group, translating to roughly a dozen KBs. This is still much smaller than the proof size of hashing-based commitment schemes like FRI. And proof size can be reduced via SNARK composition.

A final potential downside of Dory is verifier *time*: verifying Dory evaluation proofs requires (logarithmically many) scalar multiplications in the target group of a pairing-friendly elliptic curve, and these can be slow, as, naively implemented, target group operations are about 6 times slower than G₁ operations. If this indeed turns out to be a significant verifier cost, there are multiple possible mitigations. First, as with proof size, verifier time can be reduced via SNARK composition. Second, even short of SNARK composition, one could outsource the target group operations to the prover using, say, data parallel variants of the GKR protocol [GKR15, Tha13]. Third, there has been recent progress on speeding up target-group operations in BLS12-381, at least on high-end consumer CPUs. 23 Such techniques could keep Dory’s verification time from becoming problematic even in the absence of SNARK composition or outsourcing verification.

We expect the benefits of Dory in the context of Twist and Shout (especially controlling commitment key size while keeping *d* small) to outweigh any downsides.

Section 9.2.3 contains yet more discussion of Dory’s costs and how it works.

2.9.2 Twist and Shout design philosophy The design of Twist and Shout reflects a philosophy that leverages the unique strengths of the sum-check protocol to achieve high prover performance. Below, we highlight key aspects of this approach and its broader implications for SNARK design. Barely paying for zeros: a superpower of sum-check (and elliptic curve commitments). The method of one-hot addressing leans heavily on the ability of elliptic-curve commitment schemes to commit to 0-values for “free” (i.e., committing to a vector incurs prover costs proportional to its *sparsity*, i.e., number of non-zeros, not its length). The method also works well with hashing-based commitments over binary fields such as Binius [DP23, DP24], since such schemes ensure that it is cheap to commit to values known a priori to reside in *{*0*,*1*}*. Importantly, these commitment schemes “pack” many small values into a single field element, and later use use the sum-check protocol to relate the packed field elements to unpacked ones. Indeed, committing very quickly to 0s (or small values in general) is not enough on its own to get a fast SNARK prover. Also essential is the ability of the sum-check protocol to allow the prover to avoid paying *field operations* to process 0-values. This appears difficult or impossible to achieve with polynomial IOPs based on univariate polynomials. This is because the number of non-zero evaluations of various “quotient polynomials” arising in polynomial IOPs based on univariate polynomials grows with the degree of the polynomials regardless of how sparse they are. These non-zero quotient evaluations increase prover work. This prover cost is in addition to 0s contributing significantly to commitment time for popular univariate hashing-based polynomial commitments like FRI [BBHR18]. Twist and Shout are new examples in a growing body of work showing that the “free 0s” cost profile of elliptic-curve-based commitments opens up a rich design space enabling highly performative SNARKs. This body of work offers a strong counterpoint to the widespread view that SNARKs using elliptic curves—due to their use of 256-bit fields—are less performative than alternatives that rely only on hashing-based commitment <u>schemes.</u> 23[https://github.com/mratsim/constantine/pull/485](https://github.com/mratsim/constantine/pull/485)

Indeed, the Jolt RISC-V zkVM implementation²⁴ already extensively leverages this property of elliptic curves (even without yet incorporating Twist and Shout). For example, Jolt forces the prover to evaluate primitive instructions correctly by performing lookups into “subtables” of size 2 16. There are over a dozen subtables used across all primitive instructions, but each instruction only accesses a handful of the subtables. This is loosely analogous to how RISC-V has 32 registers but each cycle only two are read and one is written. The way Jolt handles the subtable lookups today is analogous to how Twist and Shout handle registers: For each cycle, the Jolt prover commits to a vector of binary flags indicating for each subtable whether or not it is actually accessed at that cycle. If not, the Jolt prover is free to commit to only 0s for all values “capturing” the lookup into that subtable for that cycle. This is analogous to how Twist and Shout commit to a 0 for each register that is not accessed in a given cycle (and on writes, Twist, additionally commits to a 0-increment for each register that is not accessed).

Similar techniques leveraging “free 0s” have also recently been exploited in Nebula [AS24], a collection of techniques for efficiently applying folding schemes in a zkVM context.

Going fully multilinear. The technical ethos underlying our work is that SNARKs based on the sum- check protocol and multilinear polynomials, rather than univariate polynomials (and establishing quotient relationships between them), are best for prover speed. In sum-check-based zkVMs like Jolt, there is one place today where univariate polynomials still arise: permutation-checking via Lipton’s trick (see Equation (1)), which is the central component of offline memory-checking procedures and other key SNARK components. This entails treating the two vectors to be permutation-checked as the roots of a univariate polynomial and evaluating that polynomial at a random point via a grand product argument. Twist and Shout replace this source of “univariate-ness” with the sum-check protocol, eliminating grand product arguments completely.

2.9.3 Integrating Jolt (with Twist and Shout) with folding schemes As described in the Jolt paper [AST24] and implemented in code as of this writing, Jolt is a “monolithic” SNARK, meaning that it produces a proof of execution of a fixed number of CPU cycles at once. We now discuss how to extend Jolt to prove *any* number of CPU cycles. Here, we assume that Jolt is instantiated with an additively homomorphic commitment scheme such as HyperKZG [ZSC24] or Zeromorph [KT23]. We focus on a simple approach, which we refer to as “naive folding”, that composes Jolt (with Twist and Shout) with a folding scheme such as Nova [KST22]. There are alternatives to “naive folding”, which are more efficient but require additional design and engineering: distill reductions in protocols such as Twist and Shout and directly construct folding schemes for virtual machine executions, offering a folding-centric route to constructing zkVMs (see NeutronNova [KS24b] and Nebula [AS24] for more details). Details of naive folding. We restrict our attention to Nova here because using a more advanced folding scheme than Nova does not immediately provide significant benefits for naive folding. However, the description applies if we replace Nova with another similar scheme. Recall that Nova [KS24b] is a proof system (also called an IVC scheme) that proves incremental computations of the form *y* = *F*
(*ℓ*)
(*x*), where *F* is a possibly non-deterministic polynomial time computation, *x* is the initial
input, and *y* is the output after *ℓ >* 0 iterations. The proof is produced in an incremental fashion: the prover takes as input a proof of *i* iterations of *F* and updates it to produce a proof of *i*+ 1 iterations of *F*. Crucially, the prover’s work, the proof size, and the verifier’s work do not grow with the number of iterations executed. Internally, Nova is built using a simple primitive called a folding scheme, which reduces the task of checking two NP instances of certain size *n* to the task of checking a single NP instance of size *n*.

Suppose that Jolt is modified to prove a certain pre-determined number of CPU cycles *n* starting from a given register and memory state *S* and ending with a given register and memory state *S* *′*. Then given a program that executes for *N* CPU cycles (without loss of generality, assume that *N* is a multiple of *n*), we can break the execution of the program into *ℓ* = *N/n* “shards”, and have Jolt produce *ℓ* separate proofs, one per shard. Each proof attests to the correct execution of the CPU for *n* cycles transitioning state from

[https://github.com/a16z/jolt](https://github.com/a16z/jolt)

*S* to *S* *′*. When using Twist, this requires commiting to the state of memory and registers at the end of shard, which requires time linear in memory size for each shard to prove that *S* *′* is consistent with committed increments. Note that approaches such as Nebula [AS24] do not incur this *O*(*M*) costs for each shard, where *M* is the size of memory and register state. They only incur this cost at the end of *N* cycles. Obtaining a similar performance profile with Twist remains open.

We then write a function *F* in Nova that verifies a single Jolt proof. *F* also needs to ensure that the register state and memory state are consistent from shard-to-shard. This can be done by making *F* output commitments to memory and register state, which are provided as part of Jolt’s proof of a shard. Furthermore, *F* can then check that the starting state of a Jolt proof (for shard *i* where *i >* 1) is consistent with the ending state of prior shard *i −* 1 by comparing commitments provided at shard *i* (as part of Jolt proof for shard *i*) with outputs provided by *F* at shard *i −* 1. In Nova, the output of a shard is automatically fed as input to the next shard. We could then have the prover feed the *ℓ* Jolt proofs it produced to *ℓ* sequential steps of Nova’s IVC scheme. This produces a single Nova proof attesting to the correct execution of *ℓ* shards of the program’s execution, which in turn proves the correct execution of *N* CPU cycles.

The upshot is that this composition of Jolt with Nova allows it scale to prove any number of CPU cycles while benefiting from the prover-memory-efficiency properties of Nova. Note that we only need to fix a value of *n* and we do not need to fix a particular value for *N*. In other words, with this design, the prover can pause its VM and resume it at any time to execute additional cycles.

An optimization to defer polynomial evaluation arguments. Recall that a Jolt proof consists of three components: (1) multilinear polynomial commitments, (2) sum-check proofs, and (3) polynomial evaluation arguments to prove the evaluation of committed polynomials at a random point chosen over the course of the sum-check protocol. In the description above, *F* verifies both the sum-check proofs and polynomial evaluation proofs arising from “monolithic” Jolt. We now discuss an optimization that allow the Jolt prover to defer producing polynomial evaluation proofs. This optimization is particularly attractive because polynomial evaluation arguments are particularly expensive for the prover. For example, with HyperKZG and Zeromorph, for a polynomial of size *m* (i.e., a multilinear polynomial with log*m* variables) the prover must compute several MSMs of size *m* and the scalars in the MSMs are random. Furthermore, with Shout and Twist, the committed polynomials are slightly superlinear in size. For example, they are of size *m* = *T · K¹* */d*, where *T* is the number of CPU cycles proven in a shard, *K* is the size of memory, and *d* is a parameter. So, it is important to avoid proving evaluations of those polynomials for every shard.

Instead of producing a polynomial evaluation proof, the Jolt prover outputs an instance-witness pair (and the Jolt verifier outputs an instance) in the *R*polyevalrelation [KS24a, Definition 21]. In a nutshell, an instance in this relation is of the form *u* = (*C,x,y*) and a witness is a polynomial *w* = *P*. A witness is satisfying if *P* is a multilinear polynomial, *C* is a commitment to *P*, and that *P* (*x*) = *y*.

These instances can be folded using a small variant of HyperNova’s multi-folding scheme, which we now sketch. The “running” instance is a single instance in the *R*polyevalrelation and the “incoming” instances (which are produced via a Jolt proof) are rerandomized so that they all share the same evaluation point. This is analogous to how HyperNova rerandomizes running instances in its multi-folding scheme for CCS by running the sum-check protocol. Once all the instances share the same evaluation point, all instances can be folded into a single instance with a simple random linear combination.

With this folding scheme in place, *F* would simply fold instance-witness pairs in *R*polyeval(present in a Jolt proof) into a running instance. This requires representing HyperNova’s folding scheme verifier in *F*, which involves verifying a sum-check proof and taking a weighted sum of *k* commitments, where *k* is the number of instance-witness pairs folded per Jolt proof. The prover does incur *O*(*m*) = *O*(*T · K¹* */d* ) field operations in the folding scheme. This is tolerable in our setting as long as we set *d* sufficiently large to ensure that the cost contribution from this component is smaller than the cost to generate a Jolt proof of a shard. For example, with *K* = 2 30 memory cells (representing several GBs of memory), we can set *d* = 4 or *d* = 8.

With this optimization, Jolt+Nova’s IVC proof includes a Nova proof and a single instance-witness pair (*u,w*) in *R*polyeval. In addition to verifying Nova’s IVC proof, the Jolt+Nova verifier will have to verify the validity of that instance-witness pair. Alternatively, the prover can replace the instance-witness pair (*u,w*)

with (*u,π*), where *π* is a polynomial evaluation argument proving the knowledge of a witness satisfying *u* and the verifier would validate *π* in addition to validating a Nova proof.

## 3 Technical preliminaries

### 3.1 Prover costs in elliptic-curve-based SNARKs

Cost of field operations. On modern CPUs, multiplying two elements of a 256-bit prime field using Montgomery multiplication costs between 40 and 80 CPU cycles. Field additions for such fields are an order of magnitude cheaper.

Elliptic curve commitments. In order to understand the advantages of the method of increments, it is necessary to explain the prover cost profile in SNARKs that use elliptic curve commitments. Three points are paramount: (1) committing to 0s is “free” (2) commitment to “small” values is faster than committing to “big values”, and (3) under appropriate conditions, we can “ignore” the cost of computing evaluation proofs. Details follow.

Let *ℓ* = log(*n*) and *p* be an *ℓ*-variate multilinear polynomial over a field F. Let G be a cryptographic group with scalar field equal to F.

With elliptic-curve-based polynomial commitment schemes, the commitment to an *ℓ*-variate multilinear polynomial *p* is simply a multi-exponentiation of size *n* = 2 *ℓ*, namely: Y *y* *g* *i* *i* *,* (13) *x* *i* *∈{*0*,*1*}ℓ*

where *yi*= *p*(*xi*) is the evaluation *p* at input *xi∈{*0*,*1*}* *ℓ*. (In this paper, we treat G as a multiplicative group, so the product in Equation (13) refers to the group operation.) Here, each *gi∈* G is an element of the *commitment key*, a publicly known vector of group elements of length *n* = 2 *ℓ* that is needed to produce commitments.

Equation (13) is also referred to as a *Pedersen vector commitment*, with the vector at hand being the exponents in Equation (13), i.e., the vector *y* of evaluations of *p* as its input ranges over *{*0*,*1*}* *ℓ*. Accordingly, we will often refer to the procedure of committing to *p* as “committing to *n* = 2 *ℓ* values”, those values being the entries of *y*.

Commitment costs. The “smaller” the *yi*values, the faster it is to compute the commitment in Equation (13). Specifically, using Pippenger’s bucketing algorithm, for any desired *B ≪ n*, roughly one group operation
is incurred for each *yi∈{*0*,*1*,...,B}*, two group operations are incurred for each *yi∈{B* + 1*,...,B²}*, and
in general *c* group operations are required for each *yi∈{B* *c−*1 + 1*,...,B* *d* *}*. In other words, committing to a *c*log(*n*)-bit value *yi*requires about *c* group operations.

Accordingly, in order to understand the cost of committing to a vector, it is not enough to analyze the *length* of the committed vector, one must also analyze how big or small the vector’s values are.

Notice in particular that if *yi*= *p*(*xi*) = 0, then *giy* *i* = 1, and hence the multi-exponentiation in Equation (13) is unaffected by the *i*’th term. This means that committing to 0s is free for the prover, in the sense that any 0-values that are committed do not alter the commitment whatsoever.

We refer to the number of non-zero entries of *y* as the *sparsity* of *p* and of *y*. The above means that the time to commit to *p* and *y* depend only on the sparsity, and not the ambient dimension *n* = 2 *ℓ*. The ambient dimension of *y* does factor into other prover costs, discussed shortly, but not into the time required to compute the commitment.

Another important special case is an exponent *yi*= 1. The total contribution to the commitment of all such exponents can be computed with *exactly* one group operation per entry *i* with *yi*= 1, as this contribution is: Y *g* *i* *.* *i* : *yi*=1

Pippenger’s bucketing algorithm achieves an amortized cost of *very close to* one group operation per committed value in *{*2*,...,B}*, but not exactly one. The smaller *B* is relative to the length *n* of the committed vector *y* (or more precisely, the number of entries of *y* outside of *{*0*,*1*}*), the closer the amortized cost of commitment is to one group operation per value *yi*in *{*2*,...,B}*.

Not only is it fast to commit to small positive values via Equation (13), it is also fast to commit to “small negative values”, i.e., values in *{−B* *d* *,..., −*1*}*. To do this, one can in preprocessing invert each element of
the original commitment key, so that the commitment key becomes (*g₁,...,gn,h₁,...,hn*), where *hi*= *gi−*
1. Then committing to a negative value *yi*can be done by committing to the positive value *−yi*using group element *hi*in place of *gi*. The Twist prover will need this in order to commit to “increments” quickly, since increments can be negative.

The cost of computing evaluation proofs. While *commitment time* depends only on the sparsity of *p* when using elliptic-curve-based polynomial commitment schemes, committed 0s are not literally free. They do affect the time required to compute evaluation proofs.

Specifically, if the committed vector *y* has length *n*, then evaluation proofs for multilinear polynomial commitment schemes like HyperKZG and Zeromorph require the prover to compute commitments to (i.e., multi-exponentiations over) a vector *v* of length *n* with *random* entries (in fact, several such vectors). If *y* is sparse and only contains small values, committing to *v* as required in the evaluation proof is potentially orders of magnitude more expensive than merely committing to *y*. This is because *v* is *not* sparse, nor are its entries small.

Furthermore, if using HyperKZG or Zeromorph, committed 0s also affect the size of the “powers-of-tau” SRS [KZG10] used by these commitment schemes. Specifically, to commit to an *ℓ*-variate multilinear polynomial with these schemes, one needs an SRS of size 2 *ℓ* regardless of the sparsity of the committed polynomial.

Fortunately, both of the above issues (large evaluation proof computation time, and large SRS) can be addressed by the standard amortization technique described next.

3.1.1 Amortizing the cost of computing evaluation proofs via homomorphism Elliptic curve commitment schemes automatically come with extremely powerful amortization properties for evaluation proofs that render this concern moot, at least so long as *n* is not *too* much bigger than *m*. For example, let *ℓ* = *ℓ₁* + *ℓ₂*. Rather than committing to *p* directly, instead commit to 2
*ℓ* 1different *ℓ₂*-variate multilinear polynomials, where for each *z ∈{*0*,*1*}* *ℓ* 1, the *z*’th committed polynomial is *gz*(*x*) = *p*(*z,x*).

Suppose the verifier requests the evaluation *p*(*r,r* *′* ) for *r ∈* F *ℓ* 1and *r′∈* F*ℓ*2. The verifier on its own can, via homomorphism, compute a commitment to the *ℓ₂*-variate polynomial *g*(*x*) = *p*(*r,x*), and the prover merely needs to provide an evaluation proof for *g*(*r₂*). Computing this evaluation proof is roughly 2 *ℓ* 1times cheaper than computing an evaluation proof if *p* had been committed directly.

The downside of this technique is that the commitment size grows by a factor of 2 *ℓ* 1, and the verifier has to perform 2 *ℓ* 1group exponentiations²⁵ to homomorphically compute the commitment to *g*(*x*) = *p*(*r,x*). In many contexts, this is an acceptable increase in verifier costs even for 2 *ℓ* 1in the dozens or hundreds. For example, HyperKZG and Zeromorph evaluation proofs require the verifier to do a couple of dozen group exponentiations regardless, so having the verifier do an extra couple of dozen exponentiations at most doubles verifier costs. And SNARK verifiers do more than merely process commitments, so doubling the verifier’s costs to process commitments may mean less than a doubling of total verifier costs.

Even more powerful amortization via folding. A related reason that the cost of polynomial evaluation proofs can often be ignored is the use of folding schemes. Folding schemes are closely related to the above amortization procedure, except that by invoking recursion, they avoid the 2 *ℓ* 1 -factor increase in verifier costs.

More precisely, a multi-exponentiation of length 2*ℓ₁*.

Here is a sketch what folding schemes can accomplish in the context of zkVMs. Say a prover wants to prove it ran a RISC-V program correctly for *C* cycles. To bound the prover’s memory usage, one can split the computation up into, say, *C/S* shards each consisting of *S* cycles. One can apply a zkVM to prove correct execution of each shard separately, and then use folding techniques to recursively aggregate the proofs. Specifically, represent the zkVM verifier (*minus* verification of polynomial evaluation proofs, as such claims can be “accumulated” similar to the above example, rather than verified directly) via a constraint system like R1CS. Then proving that one knows a valid proof for each of the *C/S* shards is equivalent to proving that one knows satisfying assignments for *C/S* instances of the constraint system, one per shard. One can apply an efficient folding procedure such as Nova [KST22] to obtain a single “folded” instance of the constraint system such that knowledge of a satisfying assignment to the folded instance is equivalent to knowledge of a satisfying assignment of all *C/S* original instances. Section 2.9.3 provides more details.

The key point for our purposes is that in this setting, only a single polynomial evaluation needs to be provided, for a polynomial whose size is proportional to the size of a *single* shard. 26 That is, by breaking the CPU’s execution into *C/S* shards and applying folding, one obtains a roughly (*C/S*)-fold reduction in the cost of computing an evaluation proof, compared to if the entire *C*-cycle CPU execution was proved in a monolithic fashion.

For the reasons above, it is often reasonable to ignore the computation of polynomial evaluation proofs when analyzing SNARK prover costs. Henceforth in this work, we do this.

Comparison to sparse polynomial commitment schemes. Readers may wonder about the relationship between the discussion above and the notion of *sparse polynomial commitment schemes* such as Spark [Set20]. These are polynomial commitment schemes that enable the prover to efficiently commit to an *ℓ*-variate multilinear polynomial *p* in time proportional to the number *T* of inputs *x ∈{*0*,*1*}* *ℓ* such that *p*(*x*) *̸*= 0. We refer to *T* as the *sparsity* of *p*. Haven’t we just asserted that a simple Pedersen vector commitment achieves exactly this property, and also that the cost of evaluation proofs can be ignored due to amortization techniques? Doesn’t that mean that any elliptic-curve based polynomial commitment scheme immediately gives a sparse polynomial commitment scheme?

The answer is that sparse polynomial commitment schemes like Spark are generally targeted at settings where *n* = 2 *ℓ* is so much larger than the sparsity *T* that the cost of computing evaluation proofs *cannot* be ignored, even given the excellent amortization properties described above.

For example, the situation where *n* = *T²* naturally arises in SNARKs for R1CS or circuit satisfiability, and this is the setting that motivated the development of Spark (and also arises in our study of SNARKs for non-uniform constraint systems, see Section 9). In the zkVM context, *n* turns out to equal *K·T* where *K* is the size of the memory being checked. There are two potential differences between our setting and Spark’s:

- We are interested in settings where *T* is in the millions or billions or larger (in a zkVM context, *T* corresponds roughly to the number of cycles in the VM’s execution), but where *K* may (or may not) be much smaller. For example, in the setting of RISC-V registers, *K* is just 32. This is a setting where the cost of evaluation proofs can definitely be ignored due to amortization, but this this may not be the case if *n ≥ T²* as considered in Spark.
- Spark is a polynomial commitment scheme for *arbitrary* sparse polynomials. Whereas, Twist and Shout do not need to commit to arbitrary sparse polynomials, but rather to polynomials whose evaluations can be viewed as a *K×T* matrix that have *exactly one non-zero entry per row*. Nonetheless, we show in Section 9.3.1 that Shout indirectly yields a general sparse polynomial commitment scheme, a major improvement over Spark that we call Spark++.
26This ability to avoid having the prover produce a polynomial evaluation proof for each shard, and avoid recursively proving that it verified such a proof, is a key benefit of folding schemes compared to the “brute force recursion” [Tea22, COS20] that is used today by all zkVMs that avoid elliptic curves.

3.1.2 An analytic cost model: relating group operations to field operations When committing to a multilinear polynomial *p* defined over field F using an elliptic curve group G, F will always be the *scalar field* of G, which is why we can interpret evaluations of *p* as *exponents* of group elements in Equation (13). Elements of G correspond to pairs of elements (*x,y*) in a *different* field B called the *base field* of G. And group operations are naturally defined in terms of base field operations. Specifically, multiplying two group elements together typically requires about 6 base-field multiplications [GW20a]. Despite the fact that B and F are different fields, often operations in B and F have the same cost. For example, if the elliptic curve is BN254, both field implementations involve 256-bit Montgomery arithmetic [Mon85]. This allows us to directly relate the cost of group operations to F-operations: a single operation in G has roughly the same cost as 6 multiplications in F. We ignore the cost of field additions, as in 256-bit fields they are an order of magnitude cheaper than field multiplications. Some pairing-friendly curves, like BLS12-381, have a larger base field than scalar field (e.g., the base field is 381 bits for BLS12-381 while the scalar field is only 256 bits). For these fields and curves, the method of increments is still attractive relative to memory-checking techniques. This is because the method of increments has substantially lower commitment costs compared to memory-checking techniques (by commitment costs, we mean the number of group operations required to commit to data). And the bigger the base field of the elliptic curve group, the more expensive those group operations are. Summary of our analytic cost model. On CPUs, we consider a 256-bit field multiplication to be 40-80 times more expensive than a native multiplication of two 64-bit data types [MvOV01, Chapter 14]. We consider a group operation (often called a group addition, using additive-group terminology) to be roughly 6 times as expensive as a field operation [GW20a]. We treat small committed values as costing exactly one group operation (see Section 2.1, especially Footnote 7, and Section 3.1 for discussion). We treat random values as costing about 11 group operations to commit to (as this is an optimistic bound on the runtime of Pippenger’s algorithm at realistic input sizes [EHB22]). We ignore field additions, as well as multiplications by small constants such as 2, since 2*x* can be computed with a single addition: 2*x* = *x* + *x*. A scalar multiplication (aka group exponentiation) by an arbitrary field element is equivalent in cost to roughly 400 group operations via the standard double-and-add algorithm, and a pairing evaluation is equivalent in cost to roughly 10 scalar multiplications. Caveats. Of course, any such cost model will only approximately match actual system performance. Different cryptographic groups have different base field sizes, and real hardware is complicated (e.g., some operations are memory-bound rather than compute bound). However, the above approximate costs are carefully informed by examination of how field operations and group operations are actually computed, as well as by microbenchmarks. Any inaccuracies in our cost model generally understate our improvements over prior works. For example, we treat all small committed values as costing exactly one group operation, when in fact committing to a 1-value truly requires one group operation, and committing to larger-but-still-small values is somewhat more expensive. Since our protocols commit to more 1-values and fewer larger-but-still-small values than prior work, this cost model understates our speedups.
### 3.2 Multilinear extensions

Our treatment of multilinear extension polynomials, polynomial commitment schemes, and SNARKs is standard and taken verbatim from Setty and Thaler [STW23].

An *ℓ*-variate polynomial *p*: F *ℓ* *→* F is said to be *multilinear* if *p* has degree at most one in each variable. Let *f* : *{*0*,*1*}* *ℓ* *→* F be any function mapping the *ℓ*-dimensional Boolean hypercube to a field F. A polynomial *g*: F *ℓ* *→* F is said to *extend f* if *g*(*x*) = *f* (*x*) for all *x ∈{*0*,*1*}* *ℓ*. It is well-known that for any *f* : *{*0*,*1*}* *ℓ* *→* F, there is a unique *multilinear* polynomial *f*e: F *→* F that extends *f*. The polynomial *f*e is referred to as the *multilinear extension* (MLE) of *f*.

A basic fact about multilinear polynomials is the following.

Fact 3.1. *Let p*: F *n* *→* F *be any multilinear polynomial. Then for any c ∈* F *and any x* *′* *∈{*0*,*1*}* *n−*1 *,*

*p*(*c,x* *′* ) = (1 *− c*) *· p*(0*,x* *′* ) + *c · p*(1*,x* *′*

)*.* (14)
*Proof.* The right and left hand sides of Equation (14) are both multilinear polynomials and are easily seen to evaluate to the same value whenever (*c,x* *′*

) *∈{*0*,*1*}×{*0*,*1*}*
*n−*1. Since *{*0*,*1*}* *n* is an interpolating set for multilinear polynomials, the left hand side and right hand side of Equation (14) must be equal for all *c ∈* <u>F</u> (and any *x* *′* *∈* F *n−*1 as well).

The right hand side of Equation (14) can be computed with a single field multiplication, as it equals *p*(0*,x* *′* ) + *c ·* (*p*(1*,x* *′* ) *− p*(0*,x* *′* )).

A particular multilinear extension that arises frequently in the design of interactive proofs is the eqe is the MLE of the function eq : *{*0*,*1*}* *s* *×{*0*,*1*}* *s* *→* F defined as follows: ( 1 if *x* = *e* eq(*x,e*) = 0 otherwise*.*

#### An explicit expression for eqe is:

Y *s* eqe (*x,e*) = (*xiei*+ (1 *− xi*)(1 *− ei*))*.* (15) *i*=1

Indeed, one can easily check that the right hand side of Equation (15) is a multilinear polynomial, and that if evaluated at any input (*x,e*) *∈{*0*,*1*}* *s* *×{*0*,*1*}* *s*, it outputs 1 if *x* = *e* and 0 otherwise. Hence, the right hand side of Equation (15) is the unique multilinear polynomial extending eq. Equation (15) implies that eqe (*r₁,r₂*) can be evaluated at any point (*r₁,r₂*) *∈* F *s* *×* F *s* in *O*(*s*) time. 27

Another multilinear extension that we will make use of is the MLE of the *less-than* function. Given any vector *j* = (*j₁,...,j*log *T*) *∈{*0*,*1*}* log *T*, define

log X *T* int(*j*) = 2 *i−*1 *· ji.* *i*=1

That is, int(*j*) is the integer whose binary representation is *j*. Then define

( *′*1 if int(*j* *′* ) *<* int(*j*) LT(*j,j*) = 0 otherwise*.*

It was shown in [STW24, Appendix G, see Equation 58 on Page 56] that LT f can be evaluated at any input (*r* *′* *,r*) *∈* F log *T* *×* F log *T* with *O*(log*T*) field operations. See also Appendix B.

Multilinear extensions of vectors. Given a vector *u ∈* F *m*, we will often refer to the *multilinear* *extension of u* and denote this multilinear polynomial by *u*e. *u*e is obtained by viewing *u* as a function mapping *{*0*,*1*}* log *m* *→* F in the natural way²⁸: the function interprets its (log*m*)-bit input (*i₀,...,i*log *m−*1) as the binary representation of an integer *i* between 0 and *m −* 1, and outputs *ui*. *u*e is defined to be the multilinear <u>extension of this function.</u> Throughout this manuscript, we consider any field addition or multiplication to require constant time. All logarithms in this paper are to base 2.

Multilinear Lagrange interpolation. An explicit expression for the MLE of a vector *u ∈* F *m* is as follows: X *u*e(*x*) = *uy·* eqe (*y,x*)*.* *y∈{*0*,*1*}*log *m*

Indeed, it is easily checked that the right hand side of the above equality is multilinear in *x*, and for any *x ∈{*0*,*1*}* log *m* the right hand side equals *ux*. Hence, the right hand side is the unique multilinear extension of *u*.

For each *y ∈{*0*,*1*}* log *m*, the multilinear polynomial

log Y *m* *x 7→* eqe (*y,x*) = (*yixi*+ (1 *− yi*)(1 *− xi*)) *i*=1

is called the *yth multilinear Lagrange basis polynomial*.

#### The following lemma is well-known [VSBW13].

Lemma 1 (Vu et al. [VSBW13]). *Given as input a point r ∈* F log *m* *, it is possible to evaluate all Lagrange* *basis polynomials at r using only m field multiplications. Given a vector u ∈* F *m* *, it is possible to compute* *u*e(*r*) *with* 2*m field multiplications.*

*Proof.* For *i* = 1*,...,m*, define *Ai*to be the array of length 2 *i*, with entries indexed by *x ∈{*0*,*1*}* *i*, such that *Ai*[*x*] = eqe (*x,r₁,...,ri*). Then *Ai*+1[*x,*1] = *ri· Ai*[*x*]

and

|||A [x, 0] = (1 − r|) · A|[x] = A [x] − A||[x, 1].|
|---|---|---|---|---|---|---|
|||i+1|i|i i|i+1||
|log m|m||||log m|log m|
||||||log m||

*A* contains the desired evaluations. The total cost to compute *A* is 1 + 2 + *···* + *m/*2 = *m* multiplications. See [Rot24] for an alternative algorithm.

Given a vector *u ∈* F, *u*e(*r*) is simply the inner product of *u* with *A*. This inner product can be computed with *m* field multiplications (on top of the *m* required to compute *A*).

### 3.3 The sum-check protocol

Let *g* be some *ℓ*-variate polynomial defined over a finite field F. The purpose of the sum-check protocol is for prover to provide the verifier with the following sum: X *H* := *g*(*b*)*.* (16) *b∈{*0*,*1*}ℓ*

To compute *H* unaided, the verifier would have to evaluate *g* at all 2 *ℓ* points in *{*0*,*1*}* *ℓ* and sum the results. The sum-check protocol allows the verifier to offload this hard work to the prover. It consists of *ℓ* rounds, one per variable of *g*. In round *i*, the prover sends a message consisting of *di*field elements, where *di*is the degree of *g* in its *i*’th variable, and the verifier responds with a single (randomly chosen) field element. If the prover is honest, this polynomial (in the single variable *Xi*) is X *g*(*r₀,...,r* (17)

||,X|,b ,...,b|).|
|---|---|---|---|
|(b ,...,b|i−1 i|i+1|ℓ−1|

*i*+1 *ℓ−*1)*∈{*0*,*1*}ℓ−i*

Here, we are indexing both the rounds of the sum-check protocol and the variables of *g* starting from zero
(i.e., indexing them by *{*0*,*1*,...,ℓ −* 1*}*), and *r₀,...,ri−*1are random field elements chosen by the verifier
across rounds 0*,...,i −* 1 of the protocol. P*ℓ* The protocol has perfect completeness, and soundness error*i*=1*di/|*F*|*. The verifier’s runtime is P*ℓ* *ℓ* *Oi*=1*di*, plus the time required to evaluate *g* at a single point *r ∈* F. In the typical case that *di*= *O*(1)

for each round *i*, this means the total verifier time is *O*(*ℓ*), plus the time required to evaluate *g* at a single point *r ∈* F *ℓ*. This is exponentially faster than the 2 *ℓ* time that would generally be required for the verifier to compute *H*. See [AB09, Chapter 8] or [Tha22, §4.1] for details.

Review of linear-time sum-check proving. P Suppose the sum-check protocol is applied to compute *n* eqe (*r ,x* *′* ) *· g*(*x*) for some fixed *r* *′* *∈* F *n*, where *x∈{*0*,*1*}*

Y *ℓ* *g*(*x*) = *pi*(*x*)*,* (18) *i*=1

and where each *pi*is multilinear. Let *N* = 2 *n*. The standard linear-time sum-check prover algorithm [CTY11, Tha13] has the prover begin by storing arrays *A₁,...,Aℓ*each of size *N* with entries indexed by *{*0*,*1*}* *n*, where *Ai*(*x*) stores *pi*(*x*). The prover also stores an array *B* containing all evaluations eqe (*r,x*) as *x* ranges over *{*0*,*1*}* *n*. It is known how to build this array with *N* field multiplications in total.

In round *m* of the sum-check protocol, for each *c* *′* *∈{*0*,*1*,*2*,...,ℓ* + 1*}*, the must compute X *s* *m*(*c* *′* ) = eq(*r* *′* *,r₁,...,rm−*1*,c* *′* *,y*)*g*(*r₁,...,rm−*1*,c,y*)*,* (19) *y∈{*0*,*1*}n−m*

where *sm*is the degree-(*ℓ* + 1) univariate polynomial sent by the sum-check prover in round *ℓ*.

Accordingly, the sum-check prover at the start of each round *m* makes sure that *Ai*stores *pi*(*r₁,...,rm−*1*,y*) as *y* ranges over *{*0*,*1*}* *n−*(*m−*1). By Fact 3.1, the following procedure suffices to ensure this. At the end of each round *m*, when the verifier selects that round’s random challenge *rm∈* F, the sum-check prover updates each entry *Ai*(*y*) for *y ∈{*0*,*1*}* *n−m* to:

(*r₁,...,r*

|A|(y) ← p|,y) = (1 − r|) · p (r₁,...,r||, 0,y) + r|· p|(r₁,...,r|, 1,y)||
|---|---|---|---|---|---|---|---|---|---|
||i i|m|m i i m|m−1 i|i|m i||m−1||
|′|i ′|′ n−m m−1 ′|m|||m m−1|′||m−1 ′|

= *A* (0*,y*) + *r ·* (*A* (*y,*1) *− A* (*y,*0))*.* (20)

We refer to this procedure as the prover *binding* the *m*’th variable to *r*. A similar update is performed on the array *B* of evaluations eqe (*r,r₁,...,r,y*).

Given the *A* arrays at each round *m*, the prover can evaluate *g*(*r₁,...,r,c,y*) for the *ℓ* + 2 relevant points *c* and all *y ∈{*0*,*1*}* with *ℓ −* 1 field multiplications per point. Multiplying *g*(*r₁,...,r,c,y*) by the value eqe (*r,r₁,...,r,c,y*) (which is easily derivable from the array *B* without additional general field multiplications) costs an additional field multiplication per point, and this counts all field operations needed to compute the quantities appearing in Equation (19).

Hence, the prover’s total work across all rounds of the sum-check protocol is *ℓ · N* field multiplications across all binding operations for the arrays *A₁,...,Aℓ*, plus 2*N* operations to compute and then bind the *B* array, plus *ℓ ·* (*ℓ* + 2) *· N* field multiplications across all rounds to compute the prover’s messages given the arrays *A₁,...,Aℓ*. That is (*ℓ²* + 3*ℓ* + 2)*N*

#### field multiplications in total.

Recent optimizations have brought this cost down. Dao and Thaler [DT24] show how to effectively eliminate the 2*N* operations required to build and bind the *B* array of eqe evaluations. And it’s well-known that the prover need not consider the evaluation point *c* *′* = 1 in each round because when the prover is honest, *s* *m*(1) = *sm−*1(*rm−*1) *− sm*(0). On top of this, Gruen [Gru24] effectively showed that the evaluation point *ℓ* + 1 can be omitted as well (see Section 3.6.1 for details). Combining these optimizations, the number of field multiplications performed by the prover falls to roughly

#### (ℓ² + ℓ) · N.

### 3.4 SNARKs and commitment schemes

SNARKs We adapt the definition provided in [KST22].

Definition 3.1. *Consider a relation R over public parameters, structure, instance, and witness tuples. A* *non-interactive argument of knowledge for R consists of PPT algorithms* (*G, P, V*) *and deterministic K,* *denoting the generator, the prover, the verifier and the encoder respectively with the following interface.*

- *G*(1 *λ* ) *→* pp*: On input security parameter λ, samples public parameters* pp*.*
- *K*(pp*,*s) *→* (*pk,* vk)*: On input structure* s*, representing common structure among instances, outputs the* *prover key pk and verifier key* vk*.*
- *P*(*pk,u,w*) *→ π: On input instance u and witness w, outputs a proof π proving that* (pp*,* s*,u,w*) *∈R.*
- *V*(vk*,u,π*) *→{*0*,*1*}: On input the verifier key* vk*, instance u, and a proof π, outputs 1 if the instance* *is accepting and 0 otherwise.*
*A non-interactive argument of knowledge satisfies completeness if for any PPT adversary A*  *λ*  pp *←G*(1)*,*  (s*,* (*u,w*)) *←A*(pp)*,*    Pr   *V*(vk*,u,π*) = 1 (pp*,* s*,u,w*) *∈R,*   = 1 *.*  (*pk,* vk) *←K*(pp*,*s)*,*  *π ←P*(*pk,u,w*)

*A non-interactive argument of knowledge satisfies knowledge soundness if for all PPT adversaries A there* *exists a PPT extractor E such that for all randomness ρ*  *λ*  pp *←G*(1)*,*  *V*(vk*,u,π*) = 1*,* (s*,u,π*) *←A*(pp;*ρ*)*,*  Pr     = *negl*(*λ*)*.* (pp*,* s*,u,w*) *̸∈R* (*pk,* vk) *←K*(pp*,*s)*,* *w ←E*(pp*,ρ*)

*A non-interactive argument of knowledge is succinct if the verifier’s time to check the proof π and the size of* *the proof π are at most polylogarithmic in the size of the statement proven.*

Polynomial commitment scheme We adapt the definition from [BFS20]. A polynomial commitment scheme for multilinear polynomials is a tuple of four protocols PC = (Gen*,*Commit*,*Open*,*Eval):

- pp *←* Gen(1
*λ* *,ℓ*): takes as input *ℓ* (the number of variables in a multilinear polynomial); produces public parameters pp.

- *C←* Commit(pp*,g*): takes as input a *ℓ*-variate multilinear polynomial over a finite field *g ∈* F[*ℓ*]; produces a commitment *C*.
- *b ←* Open(pp*, C,g*): verifies the opening of commitment *C* to the *ℓ*-variate multilinear polynomial *g ∈* F[*ℓ*]; outputs *b ∈{*0*,*1*}*.
- *b ←* Eval(*pp, C,r,v,ℓ,g*) is a protocol between a PPT prover *P* and verifier *V*. Both *V* and *P* hold a commitment *C*, the number of variables *ℓ*, a scalar *v ∈* F, and *r ∈* F
*ℓ*. *P* additionally knows a *ell*-variate multilinear polynomial *g ∈* F[*ℓ*]. *P* attempts to convince *V* that *g*(*r*) = *v*. At the end of the protocol, *V* outputs *b ∈{*0*,*1*}*.

Definition 3.2. *A tuple of four protocols* (Gen*, Commit, Open, Eval*) *is an extractable polynomial commitment* *scheme for multilinear polynomials over a finite field* F *if the following conditions hold.*

- *Completeness. For any ℓ-variate multilinear polynomial g ∈* F[*ℓ*]*,*
pp *←* Gen(1 *λ* *,ℓ*)*; C← Commit*(pp*,g*)*:* Pr *≥ − negl*(*λ*) *Eval*(pp*, C,r,v,ℓ,g*) = 1 *∧ v* = *g*(*r*)

- *Binding. For any PPT adversary A, size parameter ℓ ≥* 1*,*
 *λ*   pp *←* Gen(1*,ℓ*)*;* (*C,g₀,g₁*) = *A*(pp)*;*  Pr *b₀ ← Open*(pp*, C,g₀*)*; b₁ ← Open*(pp*, C,g₁*)*: ≤ negl*(*λ*)   *b₀* = *b₁ ̸*= 0 *∧ g₀ ̸*= *g₁*

- *Knowledge soundness. Eval is a succinct argument of knowledge for the following NP relation given* pp *←* Gen(1
*λ* *,ℓ*)*.*

*REval*(pp) = *{⟨*(*C,r,v*)*,* (*g*)*⟩* : *g ∈* F[*µ*] *∧ g*(*r*) = *v ∧ Open*(*pp, C,g*) = 1*}*

### 3.5 Polynomial IOPs and polynomial commitments

Modern SNARKs are constructed by combining a type of interactive protocol called a *polynomial IOP* [BFS20] with a cryptographic primitive called a *polynomial commitment scheme* [KZG10]. The combination yields a succinct *interactive* argument, which can then be rendered non-interactive via the Fiat-Shamir transformation [FS86b], yielding a SNARK.

Roughly, a polynomial IOP is an interactive protocol where, in one or more rounds, the prover may “send” to the verifier a very large polynomial *g*. Because *g* is so large, one does not wish for the verifier to read a complete description of *g*. Instead, in any efficient polynomial IOP, the verifier only “queries” *g* at one point (or a handful of points). This means that the only information the verifier needs about *g* to check that the prover is behaving honestly is one (or a few) evaluations of *g*.

In turn, a polynomial commitment scheme enables an untrusted prover to succinctly *commit* to a polynomial *g*, and later provide to the verifier any evaluation *g*(*r*) for a point *r* chosen by the verifier, along with a proof that the returned value is indeed consistent with the committed polynomial. Essentially, a polynomial commitment scheme is exactly the cryptographic primitive that one needs to obtain a succinct argument from a polynomial IOP. Rather than having the prover send a large polynomial *g* to the verifier as in the polynomial IOP, the argument system prover instead cryptographically commits to *g* and later reveals any evaluations of *g* required by the verifier to perform its checks.

Costs of some specific polynomial commitment schemes. The following elliptic-curve-based polyno- mial commitments are of particular interest to us. Two are HyperKZG and Zeromorph [ZSC24, KT23]. These are homomorphic commitment schemes for multilinear polynomials. The commitment consists of one group element in a pairing friendly group G₁, and committing to an *ℓ*-variate multilinear polynomial *p* consists of applying an MSM to the vector of evaluations of *p* across all inputs in *{*0*,*1*}* *ℓ*. The commitment key is the powers-of-tau SRS (also used in KZG commitments [KZG10]) of size *N* = 2 *ℓ*. Evaluation proofs have logarithmic size and verifying them requires performing two or three pairings and an MSM of logarithmic size. Computing the evaluation proof requires, for each *i* = 1*,...,ℓ*, a constant number of MSMs of length 2 *i*

(the scalars in this MSM are random field elements, if the evaluation point is random).

Dory [Lee21] is a transparent elliptic-curve-based polynomial commitment scheme that also uses pairings. *√* An attractive property of Dory is that its commitment key is sublinear size, consisting of only *√* *N* elements of *√* <u>G₁</u> and *N* elements of G *√*2 <u>.</u> Committing to an *ℓ*-variate multilinear polynomial entails performing roughly *N* MSMs each of length *N* (as with HyperKZG and Zeromorph, the scalars the MSMs are applied to comprise evaluations of *√* *p* across all inputs in *{*0*,*1*}* *ℓ* ). In addition, committing requires computing a *multi-pairing* of size *N*. 29 Dory has a transparent linear-time pre-processing phase, which produces a verification key of size just *O*(log*N*). Evaluation proofs consist of 6 log*N* target group elements and verifying them involves logarithmically many scalar multiplications in the target group.

### 3.6 Zero-check PIOP

Let *g* be an *ℓ*-variate polynomial of, say, constant degree in each variable. The following standard interactive proof establishes that that *g*(*x*) = 0 for all *x ∈{*0*,*1*}* *ℓ*, while requiring the verifier to merely evaluate *g* at a single point in F *ℓ* (after processing a proof consisting of *O*(*ℓ*) field elements).

A multi-pairing of size *S* is an expression of the form Q *S* *e*(*ai, bi*) where each *ai∈* G and *bi∈* G. *i*=1

The verifier picks an input *r ∈* F *ℓ* at random. The prover and verifier apply the sum-check protocol to confirm that X 0 = eqe (*r,x*) *· g*(*x*)*.* (21) *x∈{*0*,*1*}ℓ*

This PIOP is perfectly complete. By a direct application of the Schwartz-Zippel lemma, the soundness error is *ℓ/|*F*|* (plus the soundness error of the sum-check protocol itself).

3.6.1 An optimization of Gruen Suppose the polynomial *g*(*x*) in Equation (21) has degree *d* in each variable of *x*. Then eqe (*r,x*) *· g*(*x*) has degree *d* + 1 in each variable of *x*. As a consequence, when applying the sum-check protocol to eqe (*r,x*) *· g*(*x*), the prover’s message *si*(*X*) in each round *i* is a univariate polynomial of degree *d* + 1. This has implications for prover time: the prover must evaluate *si*at *d* + 2 points, say *{*0*,*1*,...,d* + 1*}* (in fact, the evaluation *s* *i*
(1) can be omitted and/or had “for free” as it is quickly derivable from *si*(0) and *si−*1. See Section 3.3 for
details).

Gruen [Gru24, Section 3] shows that the sum-check protocol can be modified so that in each round *i* the prover only has to compute a degree-*d* polynomial *s* *′i*, not the degree *d* + 1 polynomial *si*(and *si*can then be derived from *s* *′i*, in time that depends only on *d*). This saves the prover the work of evaluating the relevant polynomial at one point (say, point *d* + 1). (Gruen describes his optimization as having the prover send *s* *′i*

instead of *si*, but this requires modifying the standard sum-check verifier so as to process *s* *′i* rather than *si*. We prefer to leave the standard sum-check verification procedure unchanged).

The idea is roughly to define *s* *′i* to “leave out” the contribution of eqe (*r,x*) to *si*when defining *s* *′i*. This reduces the degree of *si*by one. More precisely, since eqe (*r,x*) factors into a product of terms where each term depends on a single variable, *s* *′i* leaves out the contribution of variable *i* to eqe (*r,x*). This contribution is independent of the other variables still being summed over in round *i*, so the prover can “add this contribution back in” (i.e., compute *si*from *s* *′i* ) in time independent of the number of terms being summed.

Specifically, if (r₁*,...,*r*i−*1) denotes the randomness chosen by the sum-check verifier in rounds 1*,...,i −* 1,
then recall that X *s* *i*

(*c*) = eqe (*r,* r₁*,...,*r*i−*1*,c,x*
*′* ) *· g*(r₁*,...,*r*i−*1*,c,x* *′* ) *x* *′* *∈{*0*,*1*}ℓ−i*   *i* Y *−*1X =  (*rj*r*j*+ (1 *− rj*)(1 *−* r*j*))*·* (<u>ric + (1</u> *− r*<u>i)(1 − c</u>)) eqe (*ri*+1*,...,rℓ,x* *′* )*g*(r₁*,...,*r*i−*1*,c,x* *′* )*.* | {z} *′ ℓ−i* *j*=1 call this factor *B*(*c*) *x ∈{*0*,*1*}* | {z} | {z} call this factor *A* call this factor *C*(*c*)

The modified polynomial *s* *′i*

(*X*) for round *i* is
*s* *′i*

(*c*) = *A·C*(*c*)*.*
Crucially, for each *c ∈{*0*,...,d* + 1*}*, *si*(*c*) = *s* *′i*

(*c*) *· B*(*c*). Effectively, this modification has removed from the
prover’s message *si*(*c*) the degree-1 factor *B*(*c*) that the *i*’th variable of *x* contributed to the term eqe (*r,x*).

The prover can compute *s* *′i*

(*c*) for *d* + 1 points via the standard linear-time sum-check proving algorithm
(Section 3.3). These *d*+ 1 evaluations fully specify *s* *′i* since *s* *′i* has degree *d* rather than *d*+ 1 (note that, per a standard observation, the evaluation *s* *′i*

(0) can be computed in constant time from *s*
*′i*

(1) and *si*(0)).
So once the prover has computed *s* *′i*, in time that depends only on *d* it can compute *si*(*c*) at the *d* + 2 points *c ∈{*0*,...,d* + 1*}*, thereby fully specifying *si*.

1. *P* and *V* have agreed upon a size-*K* lookup table whose multilinear extension is given by Val f (which we assume to be evaluable in *O*(log*K*) time), and *P* has already committed to a multilinear polynomial rae : F
log *K* *×* F log *T* *→* F. *P* wishes to give the verifier query access to the virtual polynomial rve : F log *T* *→* F, defined as the unique multilinear polynomial satisfying that: for all log *T* P f ( *j ∈{*0*,*1*}*, rve (*j*) =*k∈{*0*,*1*}*log *K* rae (*k,j*) *·* Val *k*)*.*

2. *V→P*: pick the desired evaluation point *r*cycle*∈* F
log *T* send it to *P*.

3. *V* and *P* apply the sum-check protocol to compute
X rve (*r*cycle) = rae (*k,r*cycle) *·* Val f (*k*)*.* *k∈{*0*,*1*}*log *K*

4. Let *r*addressdenote the randomness chosen over the course of the sum-check protocol. To perform *V* *′* *s* check in the final round of the sum-check protocol, *V* evaluates the committed polynomial rae respectively at the random point (*r*address*,r*cycle), and *V* evaluates Val f (*r*address) directly in *O*(log*K*) time.
Figure 5: The core Shout PIOP when *d* = 1, assuming the lookup table is MLE-structured (i.e., *V* can

evaluate Val f at a random input in *O*(log*K*) time).

### 3.7 One-hot encodings

Fix *K* and let *z ∈{*0*,*1*,...K −* 1*}⊆* F. The (one-dimensional) *one-hot encoding* of *z* is the unit vector *e* *z∈* F *K* whose *z*’th entry is 1 and all other entries of which are 0.

Next, let us assume for simplicity that *K¹* */d* is an integer. For *d >* 1, the *d*-dimensional one-hot encoding of *z* refers to the collection of *d* unit vectors, say *v₁,...,vd*, each of length *K¹* */d*, whose tensor product *v₁⊗v₂ ···⊗vd*
equals *ez*. In other words, if we index the *K* entries of *ez*by *k* = (*k₁,...,kd*) *∈{*0*,...,K¹*
*/d* *−* 1*}* *d*, then *v₁,...,vd*are the unique unit vectors such that the *k*’th entry of *ez*equals

Y *d* *v* *i* (*ki*)*.* *i*=1

This implies that, if *z* itself corresponds to (*z₁,...,zd*) via the natural bijection between *{*0*,...,K −* 1*}* and
1*/d d K¹* */d*
*{*0*,...,K −* 1*}*, then *vi*= *ezi∈{*0*,*1*}* for *i* = 1*,...,d*.

## 4 The Shout PIOP

This section gives a complete description of the Shout PIOP (both the special case when *d* = 1 and the case of general *d*). We defer until Section 6 an explanation of how to quickly implement the prover in this PIOP.

### 4.1 A special case: d = 1

4.1.1 Core Shout PIOP for *d* = 1
Figure 5 contains the core Shout PIOP when *d* = 1. It is identical to (the first sum-check invocation) in the
 Generalized-Lasso protocol [STW24]. Theorem 1. *Consider an instance of read-only memory-checking, and assume that for each j ∈{*0*,*1*}*
log *T* *,* rae (*·,j*) *is the one-hot representation of the address read at cycle j. Then the PIOP in Figure 5 has perfect* *completeness and soundness error* (2 log(*K*) + log(*T*))*/|*F*|.*

*Proof.* Since rae (*·,j*) is the one-hot representation of the address read at cycle *j*, rve (*j*) is indeed the table

value stored at that address if and only if X rve (*j*) = rae (*k,j*) *·* Val f (*k*)*.* (22) *k∈{*0*,*1*}*log *K*

Both the left hand side and right hand side of Equation (22) are multilinear polynomials in *j*. Hence they are

|||log T|
|---|---|---|
||cycle|log T|
|cycle|cycle||
|k∈{0,1}|||

equal as formal polynomials if and only if this equality holds for all *j ∈{*0*,*1*}*. By the Schwartz-Zippel lemma, up to soundness error log(*T*)*/|*F*|*, in order to check that the left hand side and right hand side are the same multilinear polynomial it suffices for *V* to pick *r* at random from F and confirm that X rve (*r*) = rae (*k,r*) *·* Val f (*k*)*.* (23) log *K*

Figure 5 applies the sum-check protocol to confirm this. The claim now follows from the completeness and

soundness properties of the sum-check protocol (Section 3.3).

According to our formulation of the memory-checking problem (Section 2.2), one should separately check that for each *j ∈{*0*,*1*}* log *T*, rae (*·,j*) is indeed the one-hot representation of some address raf(*j*) *∈{*0*,*1*,...,K −* 1*}* that is read at cycle *j* (and query access to the multilinear polynomial raf f should be granted to the verifier). A PIOP for establishing this is given in Section 4.1.2 below.

We describe in Section 6.1 how to quickly implement the prover in core Shout PIOP when *d* = 1.

4.1.2 Checking correctness of one-hot encodings
*K T* Suppose the prover has committed to (the multilinear extension of) a vector ra *∈* F and is also prepared to grant the verifier query access to a log(*T*)-variate multilinear virtual polynomial raf f. The prover claims that for each *j ∈{*0*,*1*}* log *T*, raf f (*j*) *∈{*0*,*1*,...,K −* 1*}* and the vector rae (*·,j*) as *·* ranges over *{*0*,*1*}* log *K*, equals the one-hot encoding of raf f (*j*). We describe a PIOP to check these claims. In other words, the PIOP allows the verifier to:

- Confirm that rae (*k,j*) *∈{*0*,*1*}* for all *k ∈{*0*,*1*}*
log *K*.

- Confirm that rae (*k,j*) equals 1 for exactly one register *k ∈{*0*,*1*}*
log *K*.

- Obtain query access to raf f (*j*), where the *k ∈{*0*,*1*}*
log *K* from the previous bullet is the binary represen- tation of raf f (*j*).

Checking the first bullet. To check the first bullet point, simply apply the zero-check PIOP to confirm that for all (*k,j*) *∈{*0*,*1*}* log *K* *×{*0*,*1*}* log *T*,

rae (*k,j*) 2 *−* rae (*k,j*) = 0*.* (24)

We will show later (Section 6.3) that the prover in this zero-check PIOP performs only *O*(*K*) + 2*T* field multiplications.

Checking the second bullet. The second bullet point is equivalent to the following constraint holding for all *j ∈{*0*,*1*}* log *T* :

X 1 = rae (*k,j*)*.* (25) *k∈{*0*,*1*}*log *K*

Since the left hand side and right hand side of Equation (25) are both multilinear polynomials in *j* (in fact, the left hand side has degree 0), satisfaction of this constraint system implies that e*a* equals the right hand side

of Equation (27) as formal polynomials (and vice versa). Hence, the entire constraint system can be checked (with soundness error log(*T*)*/|*F*|*) by having the verifier pick a random *r* *′* *∈* F log *T* and confirming that X 1 = rae (*k,r* *′*

)*.* (26)
*k∈{*0*,*1*}*log *K*

Since e*b* is multilinear, it is easy to see that, so long as the field characteristic is greater than 2, this sum is in fact equal to *K ·* rae (2 *−*1 *,...,*2 *−*1 *,r* *′* )*,*

(see for example [AW09, End of Section 1.4] for reference). And so Equation (26) can be confirmed to hold by the verifier with a single evaluation query to rae, at point (2 *−*1

*...,*2 *−*1 *,r* *′* ).
This technique does not work over binary fields (where 2 *−*1 is undefined). In that case, one can simply apply the sum-check protocol directly to compute Equation (26). This has the additional benefit that it lowers the number of evaluation queries to rae performed by the verifier (i.e., by running this sum-check in parallel with the one used to check the third bullet below, we can ensure that both sum-checks wind up evaluating rae at the same point).

Checking the third bullet. Given the first two bullet points hold, the third bullet point is equivalent to to the following constraint holding for all *j ∈{*0*,*1*}* log *T* :

  X log( X

*K*)*−*1
e*a*(*j*) =  2 *i* *ki* *·* rae (*k,j*)*.* (27) *k∈{*0*,*1*}*log *Ki*=0

Since the left hand side and right hand side of Equation (27) are both multilinear polynomials in *j*, satisfaction of this constraint system implies that e*a* equals the right hand side of Equation (27) as formal polynomials (and vice versa). Hence, the entire constraint system can be checked (with soundness error log(*T*)*/|*F*|*) by having the verifier pick a random *r* *′* *∈* F log *T* and confirming that

||||
|---|---|---|
||log(K)−1||
|′||i|
|||i|
|k∈{0,1}|i=0||

X X raf f (*r*) =  2 *k*  *·* rae (*k,r′*)*.* log *K*

The verifier can obtain the evaluation raf f (*r*) from the commitment to raf f. To compute   X log( X

*K*)*−*1 *i*

||| · ra e (k,r 2 k|
|---|---|---|
|||i|
|k∈{0,1}|i=0||
|′ log K|log T||
 *i*
*′* )*,* log *K*

the prover and verifier can apply the sum-check protocol, at the end of which the verifier needs to evaluate rae (*r,r* *′* ) for a random point (*r,r*) *∈* F *×* F. This evaluation can be obtained by the verifier from the commitment to rae.

Figure 6 provides the entire PIOP. The following theorem is immediate from completeness and soundness of

the sum-check protocol and the discussion above.

Theorem 2. *Figure 6 satisfies perfect completeness and has soundness error* (6 log(*K*) + 4 log(*T*))*/|*F*|. That* *is, if* ra(*j*) *is not the one-hot encoding of some value* raf(*j*) *∈{*0*,*1*,...,K −*1*} for all j ∈{*0*,*1*}* log *T* *, or if the* *claim that* raf f (*r* *′* ) = *y is false, the verifier will accept with probability at most* (2 log(*K*) + log(*T*))*/|*F*|.*

*Proof.* First, suppose that for some *j ∈{*0*,*1*}* log *T*, rae (*·,j*) is not the correct one-hot-representation of some P value in *{,,...,K −}*. Then either rae (*k,j*) *̸∈{,}* for some *k ∈{,}* log *K*, or*k∈{,}*log *K* rae (*k,j*) *̸*= 1. We claim this implies that the verifier in Figure 6 rejects with sufficiently high probability.

Observe that the following polynomial *g*(*r,r* *′* ) is multilinear: X *g*(*r,r* *′* ) = eqe (*r,k*)eqe (*r* *′* *,j*) rae (*k,j*) 2 *−* rae (*k,j*)*.* *k∈{*0*,*1*}*log *K, j∈{*0*,*1*}*log *T*

Furthermore, if there is any (*k,j*) *∈{*0*,*1*}* log *K* *×{*0*,*1*}* log *T* such that rae (*k,j*) *̸∈{*0*,*1*}*, *g* is not the identically- zero polynomial. Hence, by the Schwartz-Zippel lemma, with probability at least 1 *−* (log(*K*) + log(*T*))*/|*F*|* over the random choice of *r,r* *′*, Equation (29) fails to hold. In this event, the soundness guarantee of the sum-check protocol ensures that the verifier rejects within the Booleanity-checking sum-check with probability at least 1 *−* 3(log(*K*) + log(*T*))*/|*F*|*. P log *T* Let *h*(*j*) =*k∈{*0*,*1*}*log *K* rae (*k,j*). *h* is multilinear in *j*, and if there is any *j ∈{*0*,*1*}* for which *h*(*j*) *̸*= 1, then *h* is not the identically-1 polynomial. In this case, by the Schwartz-Zippel lemma, with probability at least 1 *−* log(*T*)*/|*F*|* over the random choice of *r*cycle, 1 = *h*(*r*cycle) will fail to hold. In this event, the soundness guarantee of the sum-check protocol ensures that the verifier will reject in the Hamming weight 1 check will probability at least 1 *−* log(*K*)*/|*F*|*. This completes the proof of the claim.

Finally, suppose that raf f (*r*cycle) *̸*= *y*. We claim that raf f (*r*cycle) satisfies the the following equality:   X log( X

*K*)*−*1
raf f (*r* cycle) =  2*i· k* *i*  *·* rae (*k,r* cycle)*,* (28) *k∈{*0*,*1*}*log *Ki*=0

Indeed, the right hand side of this equation is multilinear in *r*cycleand agrees with raf whenever *r*cycle*∈* *{*0*,*1*}* log *T*. Since *{*0*,*1*}* log *T* is an interpolating set for multilinear polynomials, the left hand side and right hand side must be equal as formal polynomials in *r*cycle*.*

Hence, if raf f (*r*cycle) *̸*= *y*, soundness of the sum-check protocol guarantees that the verifier will reject in the raf f -evaluation sum-check invocation with probability at least 1 *−* 2 log(*K*)*/|*F*|*. This completes the proof of the soundness property stated in the theorem.

Perfect completeness is immediate from perfect completeness of the sum-check protocol, combined with the following facts:

- If every rae (*·,j*) is a valid one-hot encoding for all *j ∈{*0*,*1*}*
log *T*, then rae (*k,j*) *∈{*0*,*1*}* for all (*k,j*) *∈* *{*0*,*1*}* log(*K*) *×{*0*,*1*}* log *T*, and hence rae (*k,j*) 2 *−* rae (*k,j*) = 0. log *T* P

- If every rae (*·,j*) is a valid one-hot encoding for all *j ∈{*0*,*1*}*, then*k∈{*0*,*1*}*log *K* rae (*k,j*) = 1 for all *j ∈{*0*,*1*}*
log *T*, and since the left hand side is a multilinear polynomial in P *j* and *{*0*,*1*}* log *T* is an interpolating set for such polynomials, this implies*k∈{*0*,*1*}*log *K* rae (*k,j*) = 1 holds for all *j ∈* F log *T*.

- Equation (28) holds.
This completes the proof of the theorem.

### 4.2 Shout for general d

Figure 7 has pseudocode for the core Shout PIOP for a general parameter *d*, and Figure 8 specifies the PIOP

for proving correctness of *d*-dimensional one-hot encodings, for general *d*.

Theorem 3. *Figures 7 and 8 satisfy perfect completeness. Assuming each address* rae (*·,j*) *for j ∈{*0*,*1*}* log *T* *is* *indeed the d-dimensional one-hot encodings of some value* raf f (*j*) *∈{*0*,*1*,...,K −* 1*}, Figure 7 has soundness* *error at most* ((*d* + 2) log*T* + 2 log*K*)*/|*F*|.*

*Figure 8 has soundness error at most*

#### (4dlogT + 6 logK)/|F|.

||log K|log T|
|---|---|---|
|log T|||
|cycle|||
|′|′||

1. As input, *P* has already committed to a multilinear polynomial rae : F *×*F *→* F. *P* claims that for each *j ∈{*0*,*1*}*, rae (*·,j*) is the one-hot representation of some value raf f (*j*) *∈{*0*,*1*,...,K −*1*}*, and (optionally) that raf f (*r*) = *y*.
2. *V* picks *r ∈* F
log *K* and *r ∈* F log *T* at random and sends (*r,r*) to *P*.

3. (Booleanity check): *V* and *P* apply the sum-check protocol to confirm that
X 0 = eqe (*r,k*)eqe (*r* *′* *,j*) rae (*k,j*) 2 *−* rae (*k,j*)*.* (29) log *K* log *T*

|||k∈{0,1}|, j∈{0,1}|
|---|---|---|---|
|′|′|log K|log T|
|address|cycle|||

4. Let (*r,r*) *∈* F *×* F be the randomness chosen over the course of the sum-check protocol invoked in Line 3.
5. (Hamming weight 1 check): *V* and *P* apply the sum-check protocol to confirm that
X 1 = rae (*k,r*cycle *′* )*.* *k∈{*0*,*1*}*log *K*

6. (raf f -evaluation sum-check): In parallel with the sum-check invocation in Line 5, *V* and *P* apply the sum-check protocol to confirm that
  X log( X

*K*)*−*1
*y* =  2 *i* *· ki* *·* rae (*k,r*cycle)*.* *k∈{*0*,*1*}*log *Ki*=0

Let *r*address *′′* be the randomness chosen by the verifier over the course of this sum-check instance.

7. To perform *V*’s check in the final round of the two sum-checks (Lines 3 and 6), and *V*’s check in

|||address ′|′ cycle ′||address ′|
|---|---|---|---|---|---|
|′′|′|||||
|address|cycle|||||
 Line 5, *V* evaluates eqe (*r,r*) and eqe (*r,r*) on its own, and evaluates rae (*r,r*cycle), and rae (*r,r*) with two queries to rae. Alternatively, standard techniques can reduce these two evaluations to a single evaluation of rae.
Figure 6: A PIOP for checking that for each *j ∈{*0*,*1*}*

*T*, rae (*·,j*) is the (one-dimensional) one-hot representation of some value raf f (*j*) *∈ {*0*,*1*,...,K −* 1*}*. This PIOP also grants the verifier query access to the virtual polynomial raf f (i.e., when only rae, not raf f, is sent/committed by the prover).

*That is, the verifier in Figure 7 will reject with overwhelming probability if there is any j ∈{*0*,*1*}* log *T* *such* *that* rve (*j*) *̸*= Val f (*k*)*, where k ∈{*0*,*1*}* log *K* *is the binary representation of the address whose d-dimensional* *one-hot encoding is given by* (rae₁(*j*)*,...,* rae*d*(*j*))*.*

*Proof.* The completeness and soundness of Figure 8 is nearly identical to Theorem 2. The main difference is that in place of Equation (28), we now invoke that:

  X X*d* log(*K* X

)*/d−*1
Y *d* raf f (*r* cycle *′* ) = eqe (*r*cycle *′* *,j*)  2 *i·*log(*K*)*/d*+*ℓ* *· ki,ℓ* *·* rae*i*(*ki,j*)*.* *k*=(*k*1*,...,kd*)*∈*(*{*0*,*1*}*log(*K*)*/d*) *d* *, j∈{*0*,*1*}*log *T* *i*=1 *ℓ*=0 *i*=1

This equality holds by the following reasoning. The right hand side is multilinear in *r*cycle *′*. Since *{*0*,*1*}* log *T*

is an interpolating set for multilinear polynomials, we can conclude that the right hand side and left hand side are equal as a formal polynomials (and thus agree at all *r*cycle *′* *∈* F log *T* ) so long as they agree whenever whenever *r*cycle *′* *∈{*0*,*1*}* log *T*. To see that this is the case, observe that if *r*cycle *′* and *j* are both in *{*0*,*1*}* log *T*,

1. *P* and *V* have agreed upon a size-*K* lookup table whose multilinear extension is given by Val f (which we assume to be evaluable in *O*(log*K*) time). *P* has already committed to multilinear polynomials rae₁*,...,* rae*d*: F
log(*K*)*/d* *×* F log *T* *→* F. *P* wishes to give the verifier query access to the virtual polynomial rve : F log *T* *→* F, defined as the unique multilinear polynomial satisfying that: for all *j ∈{*0*,*1*}* log *T*,

*d* ! X Y rve (*j*) = rae*i*(*ki,j*) *·* Val f (*k*)*.* *k*=(*k*1*,...,kd*)*∈*(*{*0*,*1*}*log(*K*)*/d*) *di*=1

2. *V→P*: pick the desired evaluation point *r*cycle*∈* F
log *T* at random and send it to *P*.

3. (Read-checking for Shout): *V* and *P* apply the sum-check protocol to confirm that
*d* ! X Y

|e (r rv ) =||||e (r eq|,j)|e ra (k|f (k). ,j) · Val|
|---|---|---|---|---|---|---|---|
||k=(k ,...,k (1)|)∈ {0,1} (d)|, j∈{0,1} log(K)/d|d||i=1||
|address|address|address||||||
|||||′||||
|′|d||(i) address|cycle ′ cycle|||address|

cycle cycle *i i*(30) *k*=(*k*1*,...,kd*)*∈*(*{*0*,*1*}*log(*K*)*/d*) *d* *, j∈{*0*,*1*}*log *T* *i*=1

4. Let *r* = (*r,...,r*) *∈* F denote the randomness chosen over the first log(*K*) rounds of the sum-check protocol and *r* the randomness over the final log*T* rounds. To perform *V s* check in the final round of the sum-check protocol, *V* queries the committed
f polynomials rae₁*,...,* rae respectively at (*r,r*), and evaluates Val at *r* in *O*(log*K*) time.

Figure 7: The core Shout PIOP with integer parameter *d >* 1, assuming the lookup table is MLE-structured

(i.e., *V* can evaluate Val f at a random input in *O*(log*K*) time).

|e (r ,j) = 0 unless j = r||. In this case, eq|e (r|||
|---|---|---|---|---|---|
|cycle|k=(k ,...,k|cycle )∈ {0,1}|cycle d log(K)/d−1 i=1 ℓ=0|d i,ℓ i=1|i i|

then eqcycle *′* cycle *′* cycle *′* *,j*) = 1, while   X X X Y raf(*j*) =  2 *i·*log(*K*)*/d*+*ℓ* *· k*  *·* rae (*k,j*)

1 *d* (log(*K*)*/d*) *d*

is immediate from the definition of *d*-dimensional one-hot encodings (Section 3.7).

Similarly, completeness and soundness of Figure 7 is nearly identical to Theorem 1, except that we replace Equation (23) with

*d* ! X Y

||||e (r eq ,j)|e ra|(k ,j) · Val|
|---|---|---|---|---|---|
|k=(k ,...,k|)∈ {0,1}|, j∈{0,1}||i=1||
||||||cycle|
||||cycle|log T|cycle|
|log T||cycle|cycle|||
|||||d i=1 i|i|

rve (*r*cycle) =cycle *i i*f (*k*)*.* (31) *k*=(*k*1*,...,kd*)*∈*(*{*0*,*1*}*log(*K*)*/d*) *d* *, j∈{*0*,*1*}*log *T* *i*=1

To see that Equation (31) holds, observe that the right hand side is multilinear in *r*. Since *{*0*,*1*}* log *T* is an interpolating set for multilinear polynomials, to show the equality holds for all *r ∈* F log *T*, it suffices to show the right hand side and left hand side agree whenever *r ∈{*0*,*1*}*. To see this, observe that eqe (*r*cycle*,j*) = 0 if *j ∈{*0*,*1*}* unless *j* = *r*, in which case eqe (*r,j*) = 1. Meanwhile, by the definition Q f ( of *d*-dimensional one-hot encoding of addresses (Section 3.7), rve (*j*) = rae (*k,j*) *·* Val *k*).

4.2.1 A standard optimization for verifier costs: Batching parallel sum-check instances A standard technique to control proof size when running *t >* 1 parallel sum-check instances is to instead apply a single instance of the sum-check protocol to a random linear combination of the *t* claims. In other words, the verifier picks *z ∈* F at random, sends *z* to the prover, and then the prover applies the sum-check protocol a single time, to prove that:

1. As input, *P* has already committed to multilinear polynomials rae₁*,...,* rae*d*: F
log *K* *×* F log *T* *→*

F. *P* claims that for each *j ∈{*0*,*1*}*
*T*, rae₁(*·,j*)*,...,* rae*d*(*j*) is the correct *d*-dimensional one-hot representation of some value raf f (*j*) *∈{*0*,*1*,...,K −* 1*}*, and also (optionally) that raf f (*r*cycle *′* ) = *y*.

2. *V* picks *r ∈* F
log(*K*)*/d* and *r* *′* *∈* F log *T* at random and sends (*r,r* *′* ) to *P*. Assuming that *r*cycle *′* was chosen by the verifier at random after rae₁*,...,* rae*d*and rve were committed, then *V* can set *r* *′* = *r*cycle *′*.

3. (Booleanity check): *V* and *P* apply the sum-check protocol *d* times in parallel to confirm that for *i* = 1*,...,d*,
X 0 = eqe (*r,k*)eqe (*r* *′* *,j*) rae*i*(*k,j*) 2 *−* rae*i*(*k,j*)*.* *k∈{*0*,*1*}*log(*K*)*/d, j∈{*0*,*1*}*log *T*

4. (Hamming weight 1 check): Let *r*cycle
*′′* *∈* F log *T* be any value chosen at random by *V* after rae*i* was committed. For each *i* = 1*,...,d*, *V* and *P* apply the sum-check protocol to confirm that X 1 = rae*i*(*ki,r*cycle *′′* )*.* *k* *i* *∈{*0*,*1*}*log(*K*)*/d*

5. (raf f -evaluation sum-check): In parallel with the Booleanity check (and the read-checking sum- check from the core Shout PIOP, see Line 3 of Figure 7), *V* and *P* apply the sum-check protocol to confirm that
  X X*d* log(*K* X

)*/d−*1
Y *d*

|y =||e (r ,j)  eq||·|e ra (k ,j).|
|---|---|---|---|---|---|
|||cycle||i,ℓ|i i|
|k=(k ,...,k|)∈ {0,1}||i=1 ℓ=0|i=1||

cycle *′* 2 *i·*log(*K*)*/d*+*ℓ* *· ki,ℓ i i*

1 *d* (log(*K*)*/d*) *d* *, j∈{*0*,*1*}*log *T*

Figure 8: A PIOP for checking that for each *j ∈{*0*,*1*}*

*T*, rae₁(*·,j*)*,...,* rae*d*(*j*) is the correct *d*-dimensional one-hot representation of some value raf f (*j*) *∈{*0*,*1*,...,K −* 1*}*, and also granting the verifier query access to the virtual polynomial raf f (i.e., enabling only rae, not raf f, to be sent/committed by the prover). Some hashing-based commitment schemes directly ensure Booleanity of committed values, in which case the Booleanity check (Line 3) can be omitted.

|t|||
|---|---|---|
|ℓ−1|′ i|2 i|
|i=1 k∈{0,1}|||

X X 0 = *z ·* eqe (*r,k*)eqe (*r,j*) rae (*k,j*) *−* rae (*k,j*)*.* (32) log(*K*)*/d, j∈{*0*,*1*}*log *T*

This adds at most *t/|*F*|* to the soundness error, and avoids a *t*-fold increase in proof size. In the context of Twist and Shout, it can also have prover time benefits (see for example Section 6.3).

## 5 The Twist PIOP

The core Twist PIOP is given in full in Figure 9. The PIOP in this figure is sound assuming that all one-hot encodings are provided correctly, i.e., that for all *j ∈{*0*,*1*}* log *T*, rae (*j*) are wa f(*j*) are the correct *d*-dimensional one-hot encodings of some values raf f (*j*) and waf g(*j*) in *{*0*,*1*,...,K −* 1*}*. To confirm this, one can invoke the one-hot-encoding-checking PIOP of Figure 8 (replacing rae*i*and raf f with wa f*i*and waf g as appropriate).

Theorem 4. *Figure 9 has perfect completeness and soundness error at most*

((2*d* + 3) log*T* + 3 log*K*)*/|*F*|.*

*That is, the verifier in Figure 9 will reject with overwhelming probability if the claimed value of* rve (*r* *′* ) *does*

1. As input, *P* has already committed to the multilinear polynomials Inc f : F
log *K* *×* F log *T* *→* F,

|d|d log(K)/d|log T|
|---|---|---|
|||log K|
||j ∈{0,1}|′|
|||log T|
|||d|
|||i i|
|k=(k ,...,k)∈|{0,1}|i=1|

wv f : F log *T* *→* F, and rae₁*,*wa f₁*,...,* rae*,*wa f : F log(*K*)*/d* *×* F log *T* *→* F. If the prover is honest, then Inc f is the MLE of the vector Inc defined via Equation (9). Val f : F *×* F log *T* is a virtual polynomial that is defined as X Val f (*k,j*) = Inc f (*k,j*)LT f(*j,j*)*.* *′* log *T*

The prover wishes to give the verifier query access to the virtual polynomial rve, defined as the unique multilinear polynomial satisfying that for all *j ∈{*0*,*1*}*, ! X Y rve (*j*) = rae (*k,j*) *·* Val f (*k,j*)*,*

1 *d* (log(*K/d*)) *d*

where Val f (*k,j*) is the value stored in register *k* during cycle *j* according to wa f and wv f.

2. *V→P*: pick a desired evaluation point *r*
*′* *∈* F log *T* for rve and send it to *P*. Also pick *r ∈* F log *K* at random and send it to *P*. Then *V* and *P* run the following two instances of the sum-check protocol in parallel:

3. Read-checking sum-check. *V* and *P* apply the sum-check protocol to compute
*d* ! X Y

|) =||e ra (k ,j)|
|---|---|---|
|||i i|
|k=(k|,...,k)∈ {0,1}|i=1|

rve (*r* *′* eqe (*r* *′* *,j*) *·i i·* Val f (*k,j*) (33)

1 *d* (log(*K*)*/d*) *d*, *j∈{*0*,*1*}*log *T*

4. Write-checking sum-check. In parallel with the read-checking sum-check, *V* and *P* apply the sum-check protocol to confirm that Inc f (*r,r*
*′* ) equals:

*d* !! X Y *′*

|||e (r,k) · eq eq|e (r ,j) ·|f wa|(k ,j) ·|f (k,j)|. (34)|
|---|---|---|---|---|---|---|---|
|k=(k ,...,k|)∈ {0,1}|, j∈{0,1} address|cycle|i=1 address|cycle|address address|cycle cycle|

*i i*wv f(*j*) *−* Val *k*=(*k*1*,...,kd*)*∈*(*{*0*,*1*}*log(*K*)*/d*) *d*, *j∈{*0*,*1*}*log *T* *i*=1

5. At the end of the above instances of the sum-check protocol, for random values *r,r*, the verifier has to evaluate wa f(*r,r*cycle), wv f(*r*), rae (*r,r*) and Val f (*r,r*). The wa f, wv f, and rae evaluations are obtained directly from the commitments to these polynomials. The Val f evaluation is obtained from the Val f -evaluation sum-check below.
6. Val f -evaluation sum-check. *V* and *P* apply the sum-check protocol to compute
X Val f (*r* address*,r*cycle) = Inc f (*r* address*,j* *′* ) *·* LT f(*j* *′* *,r*cycle)*.* *j* *′* *∈{*0*,*1*}*log *T*

7. To perform *V*
*′* *s* check in the final round of this sum-check protocol, the verifier has to evaluate Inc f at a random point and LT f. The verifier computes the LT f evaluation on its own in *O*(log*T*) time. The evaluation of Inc f is obtained via the commitment to Inc f.

Figure 9: The core Twist PIOP for parameter *d ≥* 1, ignoring checking correctness of one-hot decompositions

(which is covered in Figure 8).

*not actually equal* rve (*r* *′* ) *for the unique multilinear polynomial satisfying that for all j ∈{*0*,*1*}* log *T* *,*

rve (*j*) *̸*= Val f (*k,j*)*,* (35)

*where k ∈{,}* log *K* *is the binary representation of the address whose d-dimensional one-hot encoding is* *given by* (rae₁(*j*)*,...,* rae*d*(*j*))*, and* Val f (*k,j*) *is the value most recently written to address k prior to the j’th*

*write operation.*

*Proof.* We begin with the soundness analysis.

Defining some polynomials. Let cInc g denote the actual MLE of the “correct” increments implies by the write operations specified by wa f and wv f (as opposed to Inc f, which denotes the committed multilinear polynomial that is *claimed* by the prover to equal cInc g). Similarly, let crv f denote the MLE of the “correct” values returned by each read operation. Finally, let cVal g (*k,j*) denote the MLE of the “correct” values stored in register *k* after *j −* 1 writes have occurred, while Val f (*k,j*) denotes the multilinear polynomial defined via: X Val f (*k,j*) = Inc f (*k,j′*) *·* LT f(*j′,j*)*.* (36) *j* *′* *∈{*0*,*1*}*log *T*

Relationships between these polynomials. Note that for all (*k,j*) *∈{*0*,*1*}* log *K* *×{*0*,*1*}* log *T*,

Y *d* !

cInc g (*k,j*) = rae *i* (*k,j*) wv f(*j*) *−* cVal g (*k,j*)*.* (37) *i*=1

(This is not an equality of formal polynomials, since the right hand side is not multilinear in *k* and *j*, but the equality does hold at all inputs in *{*0*,*1*}* log *K* *×{*0*,*1*}* log *T* ).

In addition, X cVal g (*k,j*) = cInc g (*k,j′*) *·* LT f(*j′,j*)*.* (38) *j* *′* *∈{*0*,*1*}*log *T* This is an equality of formal polynomials, since the right hand side is multilinear in *k* and *j* and the agrees with the left hand side pointwise over the interpolating set *{*0*,*1*}* log *K* *×{*0*,*1*}* log *T*.

Finally, note that

*d* ! X Y

|) =||e ra (k ,j)|
|---|---|---|
|||i i|
|k=(k|,...,k)∈ {0,1}|i=1|

crv f (*r* *′* eqe (*r* *′* *,j*) *·i i·* cVal g (*k,j*)*.* (39)

1 *d* (log(*K*)*/d*) *d*, *j∈{*0*,*1*}*log *T*

This too is an equality of formal polynomials. Indeed, the left and side and right hand side are both multilinear

|||′||log T|
|---|---|---|---|---|
||′|′||′|
|||d|||
|′|||||
||||i i||
|k=(k|,...,k)∈ {0,1}|i=1|||

in *r* *′*, so we need only confirm that they agree at all *r* in the interpolating set *{*0*,*1*}*. When *r* *′* is in this set, then eqe (*r* *′* *,j*) equals 0 unless *j* = *j*, in which case eqe (*r,j*) = 1. And for *j* = *r*, it indeed holds that ! X Y crv f (*r*) = rae (*k,j*) *·* cVal g (*k,j*)*.*

1 *d* (log(*K*)*/d*) *d*

Overview of the soundness analysis. Informally, the soundness analysis proceeds via a three-step argument:

- The read-checking sum-check correctly grants query access to crv f *assuming* Val f = cVal g.
- The write-checking sum-check makes sure that Inc f = cInc g, also *assuming* Val f = cVal g.
- The Val f -evaluation sum-check makes sure that Val f = cVal g *assuming* that Inc f = cInc g.
As written, the second and third bulletpoints introduce circular assumptions, so the soundness analysis cannot actually proceed in this manner. Fortunately, the assumption in the third bulletpoint is stronger than what is actually needed. In order for the Val f -evaluation sum-check to ensure that Val f (*k,j*) = cVal g (*k,j*) for a given *k ∈{,}* log *K* and *j ∈{,}* log *T*, one need only assume that Inc f (*k,j* *′* ) = cInc g (*k,j* *′* ) for all *j* *′* such that LT(*j* *′* *,j*) = 1 (which we’ll henceforth denote by *j* *′* *< j* as shorthand). This means that we can avoid circular assumptions in our soundness analysis by focusing on the smallest such *j* for which Val f (*k,j*) *̸*= cVal g (*k,j*).

Formal soundness analysis. First, suppose that Inc f and cInc g are not the same polynomial. Since they are both multilinear and *{*0*,*1*}* log *K* *×{*0*,*1*}* log *T* is an interpolating set for multilinear polynomials, this means

|log K|||∗ ∗||
|---|---|---|---|---|
|∗|′ ∗|log K ∗ ∗||∗ ∗|

there is at least one input (*k,j*) *∈{*0*,*1*}* log *K* *×{*0*,*1*}* log *T* such that Inc f (*k,j*) *̸*= cInc g (*k,j*). Let (*k* *∗* *,j* *∗* ) be one such input with the smallest possible value of *j*. That is, for all *j < j* and all *k ∈{*0*,*1*}*, we assume that Inc f (*k,j′*) = cInc g (*k,j′*). It follows then, by the definition of Val f (Equation (36)), that Val f (*k,j*) = cVal g (*k,j*). But this means that

*d d* !!

||Y||||Y|||||
|---|---|---|---|---|---|---|---|---|---|
|∗ ∗|∗ i i=1|∗|∗|∗ ∗|i i=1|∗ ∗|∗ ∗ ∗|∗ ∗|∗ ∗|
|∗ ∗|∗ ∗|||||||||
|||∗ ∗|d|∗ ∗|∗|∗ ∗||||
||||i|||||||
||||i=1|||||||

cInc g (*k∗,j∗*) = rae *i* (*k* *∗* *,j* *∗* ) wv f(*j* *∗* ) *−* cVal g (*k* *∗* *,j* *∗* ) = rae*i*(*k* *∗* *,j* *∗* ) wv f(*j* *∗* ) *−* Val f (*k* *∗* *,j* *∗* )*,*

where the first equality holds by Equation (37) and the final equality holds because Val f (*k,j*) = cVal g (*k,j*). Since Inc f (*k,j*) *̸*= cInc g (*k,j*) by assumption, we conclude that

Y !

Inc f (*k,j*) *̸*= rae (*k,j*) wv f(*j*) *−* Val f (*k,j*)*.* (40)

Let

*d* ! X Y *∗ ∗*

|h(k ,j ) =|||f wa|(k ,j)|f (k,j)|.|
|---|---|---|---|---|---|---|
||k=(k ,...,k|)∈ {0,1} ∗ ∗|i=1||∗ ∗|∗ ∗|

eqe (*k* *∗* *,k*) *·* eqe (*j* *∗* *,j*) *·i i·* wv f(*j*) *−* Val *k*=(*k*1*,...,kd*)*∈*(*{*0*,*1*}*log(*K*)*/d*) *d*, *j∈{*0*,*1*}*log *T* *i*=1

It is easily seen that *h*(*k,j*) equals the right hand side of Expression (40), and hence Inc f (*k,j*) *̸*= *h*(*k,j*). Since *h* and Inc f are both multilinear polynomials, and they are distinct, the Schwartz-Zippel lemma implies that with probability at least 1 *−* (log(*K*) + log(*T*))*/|*F*|,*

Inc f (*r,r′*) *̸*= *h*(*r,r′*) when (*r,r′*) is chosen at random from Flog *K×* Flog *T*. By soundness of the sum-check protocol, in this event the write-checking sum-check verifier rejects with probability at least

#### 1 − (dlog(T) + log(K))/|F|.

Thus, if the verifier accepts with probability more than ((*d* + 1) log(*T*) + 2 log(*K*))*/|*F*|*, then Inc f = cInc g. We assume henceforth that indeed Inc f = cInc g. Then by Equation (38) and soundness of the sum-check protocol as invoked, we conclude (up to an additional soundness error of 2 log(*T*)*/|*F*|*) that for whatever evaluation

|,r ) on which the Val|f -evaluation sum-check is invoked, it holds that||
|---|---|---|
|address cycle|address cycle|address cycle|

point (*r*

Val f (*r,r*) = cVal g (*r,r*)*.* (41)

Absorbing 2 log(*T*)*/|*F*|* into the soundness error, we assume henceforth that Val f and cVal g agree at the point (*r*address*,r*cycle) at which the Val f -evaluation sum-check is applied.

It follows by Equation (39) and soundness of the sum-check protocol, the verifier will reject during the read-checking sum-check with probability at least (*d*log(*T*) + log(*K*))*/|*F*|*). This completes the soundness analysis.

The total soundness error according to the above analysis is at most ((2*d* + 3) log(*T*) + 3 log(*K*))*/|*F*|.*

Perfect completeness is an easy consequence of completeness of the sum-check protocol and Equations (37) and (38). Equation (37) ensures that the write-checking sum-check is perfectly complete and Equation (38) ensures that the Val f -evaluation sum-check is perfectly complete.

## 6 Fast Shout prover implementation (small memories)

This section explains how to implement the prover in the various invocations of the sum-check protocol in Shout. Our treatment assumes familiarity with the standard linear-time sum-check prover implementation [CTY11, Tha13] covered in the preliminaries (Section 3.3). In this section, we are generally focused upon the case that *K* = *o*(*T*), and hence we do not seek to avoid additive terms in the prover time of *O*(*K*). This is what we mean by “small” memories in the section title.

Because Shout with *d* = 1 is a special case, we present the fast prover for *d* = 1 in Section 6.1. before turning to the general case (Figures 7 and 8) in Sections 6.2 and 6.3.

### 6.1 Core Shout prover for d = 1

An algorithm for small or unstructured memories. Recall that the core Shout PIOP prover with *d* = 1 (Figure 5) applies the sum-check protocol to prove that X rve (*r*cycle) = rae (*k,r*cycle) *·* Val f (*k*)*.* (42) *k∈{*0*,*1*}*log *K*

|With T field multiplications,|||) as j|
|---|---|---|---|
|log T|||cycle|
||log K|||
|j : ra e (k,j)=1|cycle|||
|||30||

the prover can compute a vector *E* storing eqe (*j,r*cycleranges over *{*0*,*1*}* log *T* [VSBW13] (see Lemma 1). Given *E*, computing a vector *F* storing all rae (*k,r*cycle) evaluations for all P *k ∈ {*0*,*1*}* can be done with only additions and lookups into *E*. Specifically, rae (*k,r*cycle) = eqe (*j,r*). Given this array, the standard linear-time sum-check proving algorithm (Section

3.3) requires 3*K* field multiplications. Hence, the total number of field multiplications done by the core Shout PIOP prover is: *T* + 3*K.* Theorem 5. *The prover in the core Shout PIOP with d* = 1 *(Figure 5) can be implemented in* 3*K* + *T field* *multiplications.* An algorithm for large, structured memories. If *K≫T*, we would not be happy with the additive 2*K* factor in the prover runtime above. However, we generally do not expect Shout to be applied with *d* set to 1 in this case, as it would either lead to a very large commitment key (in the case of an elliptic curve commitment) or high time to compute commitments (in the case of a hashing-based commitment scheme, where 0s are not free to commit to). Still, for completeness, we outline a prover implementation that avoids this linear-in-*K* term. This implementation is an immediate consequence of the sparse-dense sum-check protocol from [STW24, Appendix G]. Indeed, if *T ≫ K* the vector *F* above is *sparse*: only (at most) *T* of its entries are non-zero. Suppose that *K≤T* *c* for some constant *c >* 0. The sparse-dense sum-check protocol of [STW24, Appendix G] identifies conditions on Val f that guarantee that the prover (in the sum-check protocol invoked to establish Equation (42) holds) runs in time *O*(*c · T*). [STW24, Appendix G] also showed that important lookup tables of size 2
64

arising in Jolt satisfy the necessary structural conditions for this runtime bound to hold. See Section 7.1 for further details.

### 6.2 Core Shout prover (general d, small memories)

Recall that the core Shout PIOP for any *d ≥* 1 (Figure 7) applies the sum-check protocol to check that

*d* ! X Y

||e (r rv ) =|||||e ra|(k ,j)|
|---|---|---|---|---|---|---|---|
|Section 3.3 states a time bound of 2K field multiplications, but this does not account for the cost of computing the claimed||k=(k ,...,k|)∈ {0,1}|, j∈{0,1}||i=1||
|answer, in this case ra|e (k, r|). Given the array F, ra||e (k, r|) can be computed with K additional field operations.|||

cycleeqe (*r*cycle*,j*)*i i·* Val f (*k*)*.* (43)

*k*=(*k*1*,...,kd*)*∈*(*{*0*,*1*}*log(*K*)*/d*) *d* *, j∈{*0*,*1*}*log *T* *i*=1

30 cycle cycle

Before the sum-check protocol even begins, the prover can compute the following array *E* *∗* with one entry per *j ∈{*0*,*1*}* log *T*. *E* *∗* stores eqe (*r*cycle*,j*) for all *j ∈{*0*,*1*}* log *T*

*.* (44)
This array *E* *∗* is useful later in the protocol.

Turning to the sum-check invocation, we bind the variables of the register *k ∈{*0*,*1*}* log *K* before the variables of the cycle *j ∈{*0*,*1*}* log *T*.

6.2.1 The first log*K* rounds of sum-check The prover’s message in the first log*K* rounds is independent of *d*, in the following sense: the prover messages sent in the first log*K* rounds is the same if the term
Y *d* rae*i*(*ki,j*) (45) *i*=1

in Expression (43) is replaced with the multilinear polynomial rae (*k₁,...,kd,j*) that takes the same values as Expression (45) over inputs in *{*0*,*1*}* log *K* *×{*0*,*1*}* log *T*. This is because the first log(*K*) rounds of the sum-check protocol bind variables only the variables in *k* = (*k₁,...,kd*), and Expression (45) has degree one in the variables of *k*—it only has degree more than one in the variables of *j*. So changing the degree of Expression (43) in *j* without changing its evaluations over the relevant domain does not alter the sum-check prover’s message in the first log*K* rounds.

Hence, for simplicity of notation, let us focus on the case the *d* = 1 for the first log*K* rounds.

Our first key observation is that for the first log*K* rounds, and each register *k ∈{*0*,*1*}* log *K*, each cycle at which register *k* is read “contributes identically” to Expression (43). Accordingly, for each register *k*, we can “aggregate” together at the start of the protocol all cycles *j* at which register *k* is read. Details follow.

|A key fact.|The following is a key consequence of the fact that ra(k,j) is a unit vector for each cycle j.||||||
|---|---|---|---|---|---|---|
|||m cycle|log T|mem ′|cycle|log T|
|mem ′|log(K)−m||m mem ′|cycle||log K|
||cycle||||||
|||||m|||

Consider the set of values rae (*r₁,...,r,y*) as *y* = (*y,y*) ranges over *{*0*,*1*}* log(*K*)*−m* *×{*0*,*1*}*. For any round *m ≤* log*K*, for each *y ∈{*0*,*1*}*, this set of values is highly structured: there is exactly one *y ∈{*0*,*1*}* for which rae (*r₁,...,r,y,y*) is non-zero, and if register *k ∈{*0*,*1*}* was read in cycle *y*, then this non-zero value equals

#### eqe ((k₁,...,k), (r₁,...,rm)). (46)

The prover’s data structures for the first log*K* rounds. The prover maintains two arrays that initially store *K* values and halve in size each round. Let’s call these two arrays *A* and *C*.

*A*[*k*] initially stores Val f (*k*). And *C*[*k*] initially stores X *v* *k*:= eqe (*r*cycle*,j*)*.* (47) *j∈{*0*,*1*}*log *T*: rae (*k,j*)=1

Initializing *C* costs no field multiplications since each entry of *C* is a sum of entries of the already-computed array *E* *∗* (Expression (44)).

At the end of round *m*, when the verifier sends the prover the random challenge *rm*, the prover binds the *A* and *C* arrays as in Section 3.3. That is, for each *k ∈{*0*,*1*}* log(*K*)*−m*, the prover sets

*A*[*k*] *←* (1 *− rm*)*A*[*k,*0] + *rmA*[*k,*1] = *A*[*k,*0] + *rm·* (*A*[*k,*1] *− A*[*k,*0])

*C*[*k*] *←* (1 *− rm*)*C*[*k,*0] + *rmC*[*k,*1] = *C*[*k,*0] + *rm·* (*C*[*k,*1] *− C*[*k,*0])*.*

By Fact 3.1, this ensures that after round *m*, *A*[*k*] stores Val f (*r₁,...,rm,k*) and X *C*[*k*] = *vk∗ ·* eqe (*r₁,...,rm,k* *′*

)*.* (48)
*k* *∗* =(*k′,k*)*∈{,}m×{,}*log(*K*)*−m*

Leveraging the data structures. In the middle of round *m*, for any *k ∈{*0*,*1*}* log(*K*)*−m*, let us use

*A*[*c* *′* *,k*]

as shorthand for (1 *− c* *′* ) *· A*[0*,k*] + *c* *′* *· A*[1*,k*]*,* (49)

and similarly with *C* in place of *A*. Then with the above data structures, the following holds. For each *c* *′* *∈{*0*,*2*}*, the prescribed prover message *sm*in round *m* includes *sm*(*c* *′* ), which equals:

  X X

|s (c|) =|f (r₁,...,r Val|,c ,k) ||,c ,k,j)|
|---|---|---|---|---|---|
|m|k∈{0,1} k∈{0,1}|′|m−1 ′|m−1||
||||log(K)−m|log T||
|′|m−1 ′|′||||
|||||′||
||||||∗|
|||cycle||||

*m* *′* *m−*1 *′* eqe (*r* *′′* *,j*)rae (*r₁,...,rm−*1 *′* (50) log(*K*)*−mj∈{*0*,*1*}*log *T* X = *A*[*c,k*] *· C*[*c,k*]*.* (51) log(*K*)*−m*

This last equality exploits Fact 3.1, as well as the key fact above, that for each *j ∈{*0*,*1*}*, rae (*r₁,...,rm−*1*,c* *′* *,k,j*) is non-zero for exactly one value of *k ∈{*0*,*1*}*, and per Equation (46), at this *k* its value is precisely eqe (*k,r₁,...,r,c*) where *k* is the first *m* coordinates of the register read at cycle *j*. By Equation (48), this means that the quantity in parenthesis in Expression (50) precisely equals *C*[*c,k*].

Thus, we have shown that the prover in the first log*K* rounds of the sum-check protocol applied to Expression (43), the prover performs at most 4*K* multiplications (not counting the construction of *E* which we already charged for in the evaluation of rve (*r*)). Here is the accounting:

- *K* multiplications to bind the *A* array.
- *K* to bind the *C* array.
- 3 *· K* across all rounds *m* to evaluate Expression (51) given these arrays (see Footnote 30 for an explanation of why this cost is 3*K* and not 2*K*).
6.2.2 The final log*T* rounds of sum-check The degree of the univariate polynomial the prover sends in each of the last *d* rounds is *d* + 1, so the prover time in the last *d* rounds does grow with *d*. Nonetheless, for simplicity let us begin by considering the case *d* = 1. Let *τ* = (*r₁,...,r*log *K*) *∈* F
log *K* denote the random challenges chosen during the first log*K* rounds of Shout’s sum-check protocol invocation. Per Equation (43), the final log *T* rounds are intended to compute:

X Val f (*τ*) eqe (*r* cycle*,j*) *·* rae (*τ,j*)*.* (52) *j∈{*0*,*1*}*log *T*

With *K* field multiplications, the prover can compute an array *E* of length *T* whose *j*’th entry stores rae (*τ,j*) (as *j* ranges over *{*0*,*1*}* log *T* ). Indeed, per Equation (46), rae (*τ,j*) simply equals eqe (*τ,k*) where *k ∈{*0*,*1*}* log *K*

is the register read at cycle *j*. And it’s known how to compute a size-*K* array storing all evaluations eqe (*τ,k*) for *k ∈{*0*,*1*}* log *K* with *K* field multiplications (see Lemma 1). Each entry of *E* can be computed with one lookup into this size-*K* array.

With this array *E* in hand, as well as the array *E* *∗* computed before round one (see Expression (44)), the standard linear-time sum-check proving algorithm (Section 3.3) implements the sum-check prover applied to compute Expression (52) with only about 4*T* field multiplications: *T* for binding the array *E* round-over-round, *T* for binding the array *E* *∗* round-over-round, and 2*T* more for evaluating *si*(0) and *si*(2) in each round *i* = log(*K*) + 1*,...,* log(*K*) + log(*T*). In fact, now-standard optimizations [DT24, Gru24] reduce this to 2*T*, as the optimization of [Gru24, Section 3] covered in Section 3.6.1 eliminates the need to evaluate *si*(2) and [DT24] eliminates the cost of binding the array *E* *∗*. We even discuss below a final optimization that effectively eliminates the cost of binding *E* when *K* = *o*(*T*). That brings the total number of prover multiplications for the final log*T* rounds down to only about *T* when *d* = 1 and *K* = *o*(*T*).

An optimization leveraging small memory size. When *K* = *o*(*T*), the following additional optimization

|e (τ,j) takes on at most K distinct values across all j ∈{0, 1}|||e (τ,r|||
|---|---|---|---|---|---|
||||log T|log(K)+1|m|
|2|m||log(K)+1|2 m m|′ ′|
|m||m||||
||j|||||
|m||||||

applies. Since ra, ra*,...,r,j*) *m* log(*T*)*−m* *m* takes on at most *K* distinct values as *j* ranges over *{*0*,*1*}*. In fact, each of these *K* values is a size-2 *m* *sum* of values from a set *S* of size *K ·*2 quantities that can all be computed in *O*(*K*2) time. Namely, *S* consists of each of the *K* distinct values in rae (*τ,j*), times a value of the form eqe (*r,...,r,j*) as *j* ranges over *{*0*,*1*}*. This means that as long as *K ·* 2 *≪ T*, we can speed up the task of binding rae for each of the first *m* rounds. Rather than costing *T/*2 field multiplications at the end of round *j*, it can instead cost *O*(*K ·* 2) field multiplications.

General *d*. For general *d >* 1, the prover in each of the final log*T* rounds sends a univariate polynomial of degree *d* + 1. There are also *d* arrays tracking evaluations of rae₁*,...,* rae*d*, rather than the single array *E* considered above when we focused on the case that *d* = 1. As long as *K¹* */d* = *o*(*T*), the optimization above that nearly eliminates the cost of binding *E* applies to binding each of these *d* arrays.

Thus, when *K* = *o*(*T*), the prover cost of the final log(*T*) rounds for general *d* is, up to low-order terms, *d²T* field multiplications. This simply amounts to applying the standard linear-time sum-check prover algorithm from Section 3.3, combined with the various optimizations described above.

#### To summarize the costs:

- *T* field multiplications to compute the array *E*
*∗*.

- 5*K* additional multiplications to implement the first log *K* rounds.
- *dT* multiplications to bind the arrays of rae₁*,...,* rae*d*evaluations over the final log*T* rounds. This cost falls to *o*(*T*) if *K¹*
*/d* = *o*(*T*).

- *d²T* multiplications given the above arrays to evaluate the prover’s messages over the final log*T* rounds.
#### We have established the following theorem.

Theorem 6. *For d >* 1*, the core Shout PIOP prover (Figure 7) can be implemented with* (*d²* + *d* + 1)*T* + 5*K* + *o*(*T*) *field multiplications. If K¹* */d* = *o*(*T*)*, this falls to* (*d²* + 1)*T* + 5*K* + *o*(*T*)*.*

### 6.3 Booleanity-checking and one-hot-encoding-checking

Here is how to efficiently implement the prover in the PIOP of Figure 8 when an additive *O*(*K¹* */d* log(*K*)) term in the prover cost is acceptable. When *K¹* */d* log(*K*) is bigger than *T*, one should instead use our generalization of the sparse-dense sum-check protocol given later, in Section 7 (that protocol has a much better dependence on *K*, but a worse dependence on *T*, by a significant constant factor).

Let us start with the Booleanity-checking sum-check invocation (Line 3 of Figure 8), which for each *i* = 1*,...,d* applies the sum-check protocol to confirm that X 0 = eqe (*r,k*)eqe (*r* *′* *,j*) rae*i*(*k,j*) 2 *−* rae*i*(*k,j*)*.* *k∈{*0*,*1*}*log(*K*)*/d, j∈{*0*,*1*}*log *T*

We bind the log(*K*)*/d* variables of *k* first, followed by the log*T* variables of *j*.

First log(*K*)*/d* rounds. Before the first round, the prover builds arrays *B* and *D* of size *K¹* */d* and *T* respectively, storing the following values:

*B* stores eq(*r,k*) for all *k ∈{*0*,*1*}* log(*K*)*/d* (53)

and *D* stores eq(*r* *′* *,j*) for all *j ∈{*0*,*1*}* log *T*

*.* (54)
By Lemma 1, computing *B* requires *K¹* */d* field multiplications, while computing *D* requires *T* field multipli- cations.

At the end of round *m*, let r = (r₁*,...,*r*m*) denote the random values chosen by the sum-check prover in the first *m* rounds. Via standard binding techniques (Section 3.3), the prover can ensure that at the end

|||/d m||′|log(K)/d−m||
|---|---|---|---|---|---|---|
|m ′|||||||
||||||m||
|log T|mem ′|log(K)/d−m||i|m mem ′|cycle|
|||cycle m|m|m||m|
||m|m||m|m||
||||/d||||

of round *m*, the array *B* has shrunk to length *K¹ /*2, and for every *k ∈{*0*,*1*}*, *B*[*k* *′*] stores eqe (*r,* r₁*,...,*r*,k*).

Recall from Equation (46) that for at the end of any round *m ≤* log(*K*)*/d* when r is selected, for each *y* cycle*∈{*0*,*1*}*, there is exactly one *y ∈{*0*,*1*}* for which rae (r₁*,...,*r*,y,y*) is non-zero, and if register *k ∈{*0*,*1*}* log *K* was read in cycle *y*, then this non-zero value equals

eqe ((*k₁,...,k*)*,*(r₁*,...,*r))*.*

The prover can maintain an array *F* that at the end of round *m* has size 2 and stores all 2 such values, i.e.,

*F* stores eqe ((*k₁,...,k*)*,*(r₁*,...,*r)) for all (*k₁,...,k*) *∈{*0*,*1*}* (55)

Via standard techniques (see Lemma 1), maintaining *F* costs *K¹* field multiplications across the first log(*K*)*/d* rounds.

Next, consider a specific *i* from the set *{*1*,...,d}*. The prover can, with only additions, before the protocol begins, compute a size-*K¹* */d* array *Gi*that for *k ∈{*0*,*1*}* log(*K*)*/d* stores X *Gi*[*k*] = *D*[*j*]*.* *j∈{*0*,*1*}*log *T*: rae*i* (*k,j*)=1

In the middle of round *m*, as per Expression (49), let us use *B*[*c* *′* *,k* *′*] as shorthand for

(1 *− c* *′* ) *· B*[0*,k* *′*] + *c* *′* *· B*[1*,k* *′*]*.*

and *F* [*k₁,...,km−*1*,c* *′*] as shorthand for

*F* [*k₁,...,km−*1] *·* eqe (*km,c* *′* )*,*

and where in the middle of round *m* = 1, the factor *F* [*k₁,...,km−*1] is simply 1.

The prover’s message *sm*in round *m ≤* log(*K*)*/d* of sum-check for the *i*’th Booleanity check satisfies that *s* *m*(*c*) equals:

X *Gi*[*k*] *· B*[*c,k* *′*] *· F* [*k₁,...,km−*1*,c*] 2 *− F*[*k₁,...,km−*1*,c*]*.* (56) *k*=(*k₁,...,km,k′*)*∈{*0*,*1*}m×{*0*,*1*}*log(*K*)*/d−m*

In round *m*, the prover has to evaluate *sm*(*c*) for all relevant values of *c*. Using Gruen’s technique (Section

3.6.1), there are 2 relevant values of *c*, say *c ∈{*0*,*2*}*. Given the arrays *Gi*, *B*, and *F*, both *sm*(0) and *sm*(2) can be computed via Expression (56) with the following total number of multiplications:
*m /d*

|||||2 + 2K¹|.|||||
|---|---|---|---|---|---|---|---|---|---|
|m||||||m−1 2||m−1|m|
|||m−1||||||||

Here, the 2 multiplications are needed to compute *F* [*k₁,...,k,c*] from *F* [*k₁,...,k,c*] for all 2
relevant values of (*k₁,...,k,c*).

The above description refers to implementing the Booleanity-checking sum-check for a single *i*. That sum-check in fact must be applied *d* times (once for each *i* = 1*,...,d*). However, a full *d*-fold cost increase does not quite occur, since several arrays can be reused between for all *i* = 1*,...,d*. This holds in particular for arrays *B*, *D*, and *F*.

In summary, across the first log(*K*)*/d* rounds of the sum-check protocol, the prover’s costs are as follows.

- *K¹* */d* field multiplications to build the array *B*.

- *T* multiplications to build *D*.
- *K¹* */d* multiplications to bind the array *B* across all rounds.
- *K¹* */d* multiplications to build up the array *F* across all log(*K*)*/d* rounds.

|/d|m−1|2||
|---|---|---|---|
||/d /d||m|
||||/d|
|||/d||

- *K¹* multiplications to *F* [*k₁,...,k,c*] for all relevant values of (*k₁,...,km−*1*,c*) across all rounds
*m*.
- For each *i* = 1*,...,d*, 2*K¹* log(*K¹*) field multiplications to evaluate *s₁*(*c*)*,...,s* (*c*) across all log(*K*)*/d* rounds for *c ∈{*0*,*2*}* given the above arrays. Across all *i* = 1*,...,d*, this is 2*K¹ ·* log(*K*) multiplications total.
Summing the above yields *T* + (2 log(*K*) + 4) *· K¹* field multiplications in total for the first log(*K*)*/d* rounds for all *d* Booleanity-checking sum-check invocations across all *i* = 1*,...,d*.

Last log*T* rounds. The last log*T* rounds of sum-check are used to compute X

|||′|2||
|---|---|---|---|---|
|j∈{0,1}||cycle|i|i|
|/d|j∈{0,1}||2 i|i|
||i|i||i|

eqe (*r,* r) *·* eqe (*r,j*) rae (r*,j*) *−* rae (r*,j*) log *T* X = eqe (*r,* r) *· D*[*j*] *·* rae (r*,j*) *−* rae (r*,j*) (57) log *T*

Given the contents of the size-*K¹* array *F* (Expression (55)) at the end of round log(*K*)*/d*, the prover can, with no further multiplications, construct for each *i* = 1*,...,d*, an array *H* of length *T* such that

#### H [j] = rae (r,j).

Indeed by Equation (46), if *k* is the register read at cycle *j* then

rae*i*(r*,j*) = eqe (*k,* r)*,*

and at the end of round log(*K*)*/d* this value is simply equal to *F* [*k*]. Then Expression (57) equals: X eqe (*r,* r) *· D*[*j*] *·* (*Hi*[*j*] *· Hi*[*j*] *− Hi*[*j*])*.* *j∈{*0*,*1*}*log *T*

Given the arrays *Hi*and *D*, the standard linear-time sum-check proving algorithm (Section 3.3) implements the final log(*T*) rounds of the sum-check protocol (i.e., applies the sum-check protocol to compute Expression (57)) with the following costs, for each *i* = 1*,...,d*.

- *T* field multiplications to bind the array *D* across all log*T* rounds.
- *dT* field multiplications to bind the arrays *H₁,...Hd*across all log*T* rounds.
- 2 *·* 2 *· d · T* field multiplications suffice to complete the prover’s work given the above arrays.
Hence, without further optimization, the total cost for the prover of the last log*T* rounds is (5*d* + 1)*T* field multiplications. Added to the cost of the first log*K* rounds, this is (5*d* + 2)*T* + *O*(*K¹* */d* log(*K*)) field multiplications. However, further significant further optimizations are possible.

#### Further optimizations.

- So long as rae₁*,...,* rae*d*are committed before the core Shout PIOP (Figure 7) commences, one can set *r* *′* in Figure 8 to *r*cycle, i.e., share verifier-chosen randomness between the core Shout PIOP and the one-hot-encoding-checking PIOP. This makes the array *D* (Expression (54)) built by the Booleanity- checking prover the same as the array *E*
*∗* (Expression (44)) built by the core Shout PIOP prover. This eliminates *T* field multiplications from the cost of the Booleanity-checking prover (and thereby renders the number of prover field multiplications for the first log(*K/d*) rounds independent of *T*).

- The techniques of Dao and Thaler [DT24] directly apply to reduce the cost of binding the array
*√* *D* = *E* *∗*

to a low-order number of field multiplications (i.e., *O*( *T*) of them). Ignoring low-order terms, this eliminates another *T* field multiplications from the prover’s cost.

- Exactly as in the final log(*T*) rounds of the core Shout PIOP (Section 6.2.2), in round log(*K*)*/d* + *m* of
2 *m* sum-check, the number of distinct values in each array *H₁,...,Hd*is at most *K*, and each of these values is a sum of at most 2 *m* elements of a set of size 2 *m* *· K* (and all quantities in this set can be computed in time *O*(*K*2 *m* )). This can be exploited to save most of the *T* multiplications devoted to binding each of the arrays *H₁,...,Hd*. It also saves the work of squaring *H₁*[*c,x* *′*]*,...,Hd*[*c,x* *′*] for each *x* *′* *∈{*0*,*1*}* log(*T*)*−t* in each sum-check round, for each evaluation point *c*. This is a total of 2*dT* multiplications saved in total.

This brings to the total number of prover multiplications for Booleanity-checking down from (5*d* + 2)*T* + *O*(*K¹* */d* log*K*) to essentially 3*dT* + *O*(*K¹* */d* log*K*).

raf f -evaluation sum-check when *d* = 1 (Line 6 of Figure 6). This is a log(*K*)-round sum-check protocol. The prover sends a degree-2 univariate polynomial in each round. It’s easy to make the prover run in time *O*(*K*) once given an *E* array of length *K*, that stores at cell *k* *′* *∈{*0*,*1*}* log(*K*) the value rae (*k* *′* *,r*cycle *′* ). Observe that X rae (*k* *′* *,r*cycle *′* ) = eqe (*j,r*cycle *′*

)*.* (58)
*j∈{*0*,*1*}*log *T*: rae (*k′,j*)=1

Hence, if given an array *D* *′* of size *T* storing all values of them form eqe (*j,r*cycle *′* ) as *j* ranges over *{*0*,*1*}* log *T*, the array *E* can be computed with no additional multiplications. *D* *′* can be computed with *T* field multiplications.

However, if *K* = *o*(*T*), this procedure can be optimized further to avoid even the *T* multiplications needed to build *D* *′*, using techniques similar to those in [DT24] that exploit multiplicative structure in the definition of eqe (Equation (15)). This is done by avoiding building the “full” size-*T* array *D* *′*, whose sole purpose is to help initialize the array *E*. Instead, the prover builds a smaller array *D* *′′* of size *T/*2 *ℓ* whose definition is identical to *D* *′* but “leaves out” the last *ℓ* coordinates of *j* and *r*cycle *′*. Specifically, for each *j* *′* *∈{*0*,*1*}* log(*T*)*−ℓ*, letting *r* = *r*cycle *′*, log( Y

*T*)*−ℓ*
*D* *′′* [*j* *′*] *←* eqe (*rm,jm* *′* )*.* *m*=1

The prover also builds an array *D* *′′′* of size 2 *ℓ* the “incorporates” the last *ℓ* coordinates that were left out of the definition of *D* *′′*. That is, for all *j* *′′* *∈{*0*,*1*}* *i*,

Y *i* *D* *′′′* [*j* *′′*] *←* eqe (*r*log(*T*)*−m*+*ℓ,jℓ′′*)*.* *m*=1

Then, for each register address *k* *′* *∈ {*0*,*1*}* *K/d*, the prover computes 2 *ℓ* quantities, one per *j* *′′* *∈ {*0*,*1*}* *ℓ*, namely: X *v* *k* *′* *,j′′* := *D* *′′* [*j* *′*]*.* *j*=(*j′,j′′*)*∈{*0*,*1*}*log(*T*)*−ℓ×{*0*,*1*}ℓ*: : rae (*k′,j*)=1

Then recalling from Equation (58) that X

|′ ′|||′|
|---|---|---|---|
||||cycle|
|j∈{0,1}|: ra e (k|,j)=1||
|′ ′||′′′ ′′||
||j ∈{0,1}||k ,j|
|i|ℓ ℓ+1|||

*D* [*k*] = eqe (*r,j*)*,* log *T ′*

it follows that X *D* [*k*] = *D* [*j*] *· v ′ ′′.* *′′ ℓ*

The cost of this protocol for building *√* <u>E</u> is *T/* + 2 field multiplications. Minimizing this quantity, the cost to compute the array *E* is *O*( *TK*) = *o*(*T*) multiplications.

Hamming-weight-one check for general *d* (Line 4 of Figure 8). This sum-check (for general *d*) is similar to the raf f -evaluation sum-check for *d* = 1, but even simpler, as the prover only sends a degree-1 polynomial in each round. Given the arrays *Ei*computed for the raf f -evaluation sum-check, the Hamming- weight-one sum-check prover can be implemented with *O*(*dK¹* */d* ) field multiplications if *dK¹* */d* = *o*(*T*).

raf f -evaluation sum-check for *d >* 1 (Line 5 of Figure 8). Recall that here the sum-check protocol is applied to compute:

  X X*d* log(*K* X

)*/d−*1
Y *d*

|||e (r eq ,j) || ·|e ra (k ,j).|
|---|---|---|---|---|---|
|||cycle||i,ℓ|i i|
|k=(k ,...,k|)∈ {0,1}||i=1 ℓ=0|i=1||

cycle *′* 2 *i·*log(*K*)*/d*+*ℓ* *· ki,ℓ i i*

1 *d* (log(*K*)*/d*) *d* *, j∈{*0*,*1*}*log *T*

This is similar to the read-checking sum-check in Shout, which was applied to compute:

*d* ! X Y eqe (*r*cycle*,j*) rae*i*(*ki,j*) *·* Val f (*k*)*.*

|||i i|
|---|---|---|
|k=(k ,...,k|)∈ {0,1}|i=1|

1 *d* (log(*K*)*/d*) *d* *, j∈{*0*,*1*}*log *T*

The only difference is that the raf f -evaluation sum-check replaces Val f (*k*) with

X*d* log(*K* X

)*/d−*1 2 *i·*log(*K*)*/d*+*ℓ*
*· ki,ℓ,* *i*=1 *ℓ*=0

which is the MLE of the function that maps *k* to int(*k*).

In applications, one can set the random value *r*cyclechosen by the verifier before the read-checking PIOP to equal *r*cycle *′*. In this case, the prover in the raf f -evaluation sum-check can be implemented with only *K* field multiplications of additional work, by batching Shout’s core read-checking sum-check instance with the raf f -evaluation sum-check per Section 4.2.1. Effectively, at the start of both sum-checks, the prover simply

replaces Val f (*k*) with Val f (*k*) + *z ·* int f (*k*), where *z* is randomness used in the standard batching technique of Section 4.2.1.

### 6.4 Cost summary for the combined Shout prover

Suppose *K* = *o*(*T*). In this case, recall Section 6.2 gave an upper bound for the core Shout PIOP prover (Figure 5) of roughly the following number of field multiplications:

#### (d² + 2)T.

And Section 6.3 gave an upper bound for the one-hot-encoding-checking PIOP prover (Figure 8) of *O*(*K¹* */d* log*K*) + 3*dT* when *K¹* */d* log*K* = *o*(*T*). Summing the two, when *K* = *o*(*T*) and *K¹* */d* log*K* = *o*(*T*), the total prover work is at most (*d²* + 3*d* + 2) *· T.*

## 7 Fast Shout prover for large, structured memories

The sparse-dense sum-check protocol from (Generalized-)Lasso [STW24, Appendix G] is the key tool allowing the Shout prover to efficiently prove *T* lookups into (structured) memories of size vastly larger than *T*.

### 7.1 Sparse-dense sum-check protocol

7.1.1 Informal Overview Consider two very large vectors *a,b ∈* F
*N* and suppose we want to compute their inner product

X *N* *⟨a,b⟩* = *ai· bi.* (59) *i*=1

Say we want to outsource this work to an untrusted prover using the sum-check protocol. A standard application would apply the sum-check protocol to the polynomial e*a ·*e*b* where e*a* and e*b* are the multilinear extensions of *a* and *b* respectively. Note that e*a ·*e*b* is a polynomial in log*N* variables with degree two in each variable. The standard linear-time prover implementation of the sum-check protocol in this context (Section

3.3) would require about 4*N* field operations. However, the prover can be implemented far faster if *a* and *b* are structured in certain ways. [STW24, Appendix G] refers to such a fast prover implementation as the *sparse-dense sum-check protocol*.
31

Suppose we use two (not necessarily multilinear) extensions *a*ˆ and ˆ*b* of *a* and *b*. At the end of round 1, when the first variable gets bound to *r₁ ∈* F, both *a*ˆ and ˆ*b* become (log(*N*) *−* 1)-variate polynomials
*a*ˆ(*r₁,x₂,...,x*log *N*) and ˆ*b*(*r₁,x₂,...,x*log *N*). The sparse-dense sum-check protocol asks: how do these “new”
polynomials relate to the “old” polynomials *a*ˆ(*x₁,...,x*log *N*) and ˆ*b*(*x₁,...,x*log *N*)? In particular, is the
relationship between *a*ˆ(*x₁,...,x*log *N*) and *a*ˆ(*r₁,x₂,...,x*log *N*) largely independent of *x₂,...,x*log *N*, and
similarly for ˆ*b*(*x₁,...,x*log *N*) and ˆ*b*(*r₁,x₂,...,x*log *N*)? If so, then major optimizations are possible.

Let *ri*denote the random field element chosen by the sum-check verifier in round *i*. Suppose that we can chunk the entries of *a* and *b* into two groups, *H*(0) and *H*(1), such that when variable one gets bound to r₁, each evaluation *a*ˆ(*i*) for *i ∈ H*(0) gets multiplied by the same value (say *m₀,r*1) and similarly each term *ai*of *a* in *H*(1) gets multiplied by *m₁,*r1. Suppose further that each term *bi*of *b* in *H*(0) (respectively, *H*(1)) gets multiplied by the same value, say *v₀,r*1and *v₁,r*1.

Illustrative example. A key example to have in mind is

ˆ *b*(*x*) = eqe (*r* *′* *,x*)*,*

|′ log N|||
|---|---|---|
||′|′|
||1|1|

for some random vector *r ∈* F. Then for any *x* = (*k,y*) with *k ∈{*0*,*1*}* and *y ∈{*0*,*1*}* log(*N*)*−*1,

ˆ *b*(*r₁,y*)*/*ˆ*b*(*k,y*) = eqe (*r,r₁*)*/*eqe (*r,k*)*.*

In other words, changing the first coordinate fed to ˆ*b* from *k* to *r₁* results in a multiplicative update that depends only on *k*, *r₁*, and *r₁* *′*.

Hence, letting *H₀* and *H₁* denote points in *{*0*,*1*}* log(*N*) of the form (0*,y*) and (1*,y*) respectively, ˆ*b* satisfies the informal condition above if we define

*v₀,r*1= eqe (*r₁* *′* *,r₁*)*/*(1 *− r₁* *′*

) (60)
and *v₁,r*1= eqe (*r₁* *′* *,r₁*)*/r₁* *′*

*.* (61)
Meanwhile, if ˆ*a* is multilinear (i.e., ˆ*a* = ˆ*a*) then by Fact 3.1,

*a*ˆ(*r₁,y*) = (1 *− r₁*)ˆ*a*(0*,y*) + *r₁a*ˆ(1*,y*)*.* (62)

So in this example, we have the following expression for the prescribed prover’s message in round two of sum-check, where *r₁* is the random challenge in round 1:

To clarify, the term “sparse-dense sum-check protocol” used in [STW24, Appendix G] refers to a fast *prover implementation*. The protocol itself (i.e., the checks the verifier does on the prover’s messages) is no different than in the standard sum-check protocol.

X *s₁*(*r₁*) = e*a*(*r₁,y*) *·* ˆ*b*(*r₁,y*) *y∈{*0*,*1*}*log(*N*)*−*1     X X =  (1 *− r₁*)ˆ*a*(0*,y*) *·* ˆ*b*(*r₁,y*) +  *r₁a*ˆ(1*,y*) *·* ˆ*b*(*r₁,y*) (0*,y*) : *y∈{*0*,*1*}*log(*N*)*−*1(1*,y*) : *y∈{*0*,*1*}*log(*N*)*−*1     X X =  *ai· bi·* (1 *− r₁*) *· v₀,r*1+ (1 *− r₁*) *· ai· bi· r₁ · v₁,r*1*,* *i∈H*(0) *i∈H*(1)

where *v₀,r*1and *v₁,r*1are defined in Equations (60) and (61).

This means that in moving from the sum defining the prover’s claim at the start of round 1 (Expression (59)) to the sum defining the prover’s claim at the start of round 2, every term *aibi*for an *i ∈ H*(0) gets multiplied by the same factor, namely (1 *− r₁*) *· v₀,r*1, and similarly for every term for an *i ∈ H*(1). Rather than performing this multiplication for each term individually, it is much faster to first *aggregate* (i.e., sum up) all the terms *ai· bi*in *H*(0) and *H*(1) respectively, and just multiply each aggregated value by the relevant factor. This costs only two multiplications *in total across all terms*, rather than one for each of the *N* terms.

This is the key idea in the sparse-dense sum-check protocol from [STW24, Appendix G]. In round *i*, there are 2 *i* relevant groups (one group for each *k ∈{*0*,*1*}* *i*, with the *k*’th group capturing all terms whose binary representations begin with *k*). At the end of round *i*, when variable *i* gets round to *ri∈* F, each term within a group gets multiplied by the same value.

If *N* is considered too large for linear-in-*N* prover time to be acceptable, say, because only *T ≪ N* terms *ai· bi*are non-zero, then the sparse-dense sum-check protocol is capable of running in time *O*(*CT*) where *C* is any integer such that *N≤T* *C*.

The sparse-dense sum-check protocol also applies when binding the *j*’th variable to *ri*causes each ˆ*b*’s value to change by an additive rather than multiplicative factor that depends only on *rj*. This is explained in detail in [STW24, Appendix G]. The canonical example to have in mind here is

log X *N* ˆ *b*(*x*) = 2 *i−*1 *xi,* *i*=1

which arises when applying Generalized-Lasso or Shout to a “range-check” table storing all field elements in

|{0, 1,...,N − 1}. In this case, changing x|increases ˆb(x) by an additive factor of 2|||(r − c).|
|---|---|---|---|---|
||i|||i−1 i|
||||/d||

*i*from *c* to *r*

### 7.2 Extension to the Booleanity-checking sum-check when K¹ ≫ T

Overview. Recall that in the Booleanity-checking sum-check (Line 3 of Figure 8), the sum-check protocol is applied to compute X eqe (*r,k*)eqe (*r* *′* *,j*) rae*i*(*k,j*) 2 *−* rae*i*(*k,j*)*.* *k∈{*0*,*1*}*log(*K*)*/d, j∈{*0*,*1*}*log *T*

Let us first focus on the “sub-sum” X eqe (*r,k*)eqe (*r* *′* *,j*)rae*i*(*k,j*) 2 *,* *k∈{*0*,*1*}*log(*K*)*/d, j∈{*0*,*1*}*log *T*

as this is the heart of the protocol.

Let *a*ˆ(*k,j*) = rae*i*(*k,j*)

and ˆ *b*(*k,j*) = eqe (*r,k*)eqe (*r* *′* *,j*)*.*

The treatment of the sparse-dense sum-check protocol in [STW24, Appendix G] assumes *a*ˆ is multilinear, i.e., *a*ˆ = e*a*. This is not the case here, as ˆ*a* is the *square* of a multilinear polynomial.

Fortunately, rae*i*(*k,j*) satisfies an “ultrastructured” sparseness property: for each *j ∈{*0*,*1*}* log *T*, there is at most (in fact, exactly) one *k ∈{*0*,*1*}* log(*K*)*/d* such that rae*i*(*k,j*) *̸*= 0. Exploiting this property ensures that the sparse-dense sum-check protocol still applies to the Booleanity-checking sum-check. At a high level, what’s going on is the following.

The treatment in [STW24, Appendix G] exploited that when *a*ˆ(*k,j*) is multilinear, Equation (62) holds, which roughly states that binding the first variable of *a*ˆ to *r₁* causes the resulting evaluations of *a*ˆ(*r₁,y*) to be a linear combination of *a*ˆ(0*,y*) and *a*ˆ(1*,y*). When *a*ˆ(*k,j*) = rae*i*(*k,j*) 2, Equation (62) does not hold, but something just as nice does: if *k* is the unique value in *{*0*,*1*}* log(*K*)*/d* with rae*i*(*k,j*) *̸*= 0, then assuming wlog that the first entry of *k* is 0, and letting *y* denote the remaining log(*K*)*/d* + log(*T*) *−* 1 entries of (*k,j*), it holds that:

|2|2 2|2|
|---|---|---|
|i|i||
|||2|

rae²*i*(*r₁,y*) = ((1 *− r₁*)rae*i*(0*,y*) + *r₁*rae (1*,y*)) = (1 *− r₁*) rae (0*,y*) = (1 *− r₁*) *a*ˆ(0*,y*)*.*

In other words, binding variable one to *r₁* causes *a*ˆ(*k,j*) to get multiplied by a factor (1 *− r₁*) that only depends on the first coordinate of *k* and on *r₁*.

Algorithm details. As in the overview above, let

*a*ˆ(*k,j*) = rae*i*(*k,j*) 2

and ˆ *b*(*k,j*) = eqe (*r,k*)eqe (*r* *′* *,j*)

and suppose we apply the sum-check protocol to compute X *a*ˆ(*k,j*) *·* ˆ*b*(*k,j*)*.* (63) *k∈{*0*,*1*}*log(*K*)*/d, j∈{*0*,*1*}*log *T*

Let *c ≥* 1 be a positive integer such that *cK¹* */*(*cd*) = *o*(*T*). For simplicity, assume log(*K*)*/d* is divisible by *c*. We will break each *k ∈{*0*,*1*}* log(*K*)*/d* into *c* chunks each of size log(*K*)*/*(*cd*), writing

||log(K)/(dc)|c|
|---|---|---|
|c c|log(K)/(dc)|c|

#### k = (k₁,...,k) ∈ {0,1}.

Similarly, write *r* = (*r₁,...,r*) *∈* F*.*

Evaluating all ˆ*b*(*k,j*) values. The first thing the prover needs to do is compute ˆ*b*(*k,j*) for all (*k,j*) *∈*

|log T|||′|
|---|---|---|---|
|||/(cd)||
|ℓ|log T|log(K)/(cd) /(dc)|′|
|||log T||

*{*0*,*1*}* log(*K*)*/d* *×{*0*,*1*}* such that *a*ˆ(*k,j*) *̸*= 0. In Booleanity-checking where ˆ*b*(*k,j*) = eqe (*k,r*) *·* eqe (*j,r*), this can be done with (*c* + 1) *· K¹* + *T*

field multiplications as follows. First, the prover computes *c* + 1 tables, each of size *K¹* */*(*dc*), storing for each *ℓ ∈{*1*,...,c}*, the values eqe (*r,x*) as *x* ranges over *{*0*,*1*}*, as well as a table storing eqe (*r,x*) as *x* ranges over the same domain *{*0*,*1*}*. This requires *c · K¹* + *T* multiplications in total (by Lemma 1). Given these tables, for any desired (*k,j*) *∈{*0*,*1*}* log *K* *×{*0*,*1*}*, ˆ*b*(*k,j*) can be evaluated with one lookup into each of the *c* + 1 tables followed by *c* multiplications.

Building a partial sum tree. Before the start of the protocol, the prover builds a “tree of partial sums”. Specifically, for each *k₁ ∈{*0*,*1*}* log(*K*)*/*(*cd*), let X *L*(*k₁*) = *a*ˆ(*k,j*) *·* ˆ*b*(*k,j*)*.* *k*=(*k₁,k′*)*∈{*0*,*1*}*log(*K*)*/*(*cd*)*×{*0*,*1*}*log(*K*)*/d−*log(*K*)*/*(*cd*)*, j∈{*0*,*1*}*log *T*

The prover builds a binary tree over these leaf values, with each interior node storing the sum of its children. Note that the tree has 2 log(*K*)*/*(*cd*) = *K¹* */*(*cd*) = *o*(*T*) leaves. This step requires (*c* + 1)*T* field multiplications in total, because there are *T* non-zero entries of *a*ˆ(*k,j*) and for each such entry, ˆ*b*(*k,j*) can be computed with *c* multiplications and then multiplied by ˆ*a*(*k,j*) with a single additional multiplication.

Let us index the internal nodes at distance *i* from the root by *{*0*,*1*}* *i* (we will label the root by *∅*). This ensures that the root of the tree, *L*(*∅*) computes the entire sum in Expression (63).

Round one message. The round-1 message of the prover can computed via a constant number of field operations (and inversions) given the values stored at the two children of the root. Indeed,

X *s₁*(0) = *a*ˆ(*k,j*) *·* ˆ*b*(*k,j*)*,* *k*=(0*,k′*)*∈{*0*,*1*}×{*0*,*1*}*log(*K*)*/d−*1*, j∈{*0*,*1*}*log *T*

and this quantity is equal to *L*(0) (the left child of the root). Similarly, *s₁*(2) is a constant-time-computable linear combination of *L*(0) and *L*(1):

||2|−1||2|||
|---|---|---|---|---|---|---|
|||||′||log T|
|i i ′|i ′ ′ ′|i ′ log T ′|′ ′|2 i −1|−1|i|
|||||1|||
||||i||||
|||||||i|

*s₁*(2) = eqe (2*,*0) *·* eqe (2*,r₁*) *·* (1 *− r₁*) *· L*(0) + eqe (2*,*1) eqe (2*,r₁*) *· r₁* *−*1 *· L*(1)*.*

This equality holds by the following reasoning. For each *k* = (0*,k*) and each *j ∈ {*0*,*1*}* satisfying rae (*k,j*) *̸*= 0, it holds that rae (*k,j*) = 1 and rae (2*,k,j*) = eqe (2*,*0). Meanwhile,

ˆ *b*(2*,k,j*) = eqe ((2*,k* *′* )*,r*) *·* eqe (*r,j*) = eqe (2*,r₁*) *·* (1 *− r₁*) *·* ˆ*b*(*k,j*)*.*

Similarly, for each *k* = (1*,k*) and each *j ∈{*0*,*1*}* satisfying rae (*k,j*) *̸*= 0, it holds that rae (*k,j*) = 1 and rae (2*,k,j*) = eqe (2*,*1) 2, and

ˆ *b*(2*,k,j*) = eqe (2*,k,r*) *·* eqe (*r,j*) = eqe (2*,r₁*) *· r ·* ˆ*b*(*k,j*)*.*

(Even though each round’s sum-check prover message *s* is a degree-3 univariate polynomial, Gruen [Gru24, Section 3] shows how a slight modification of the protocol allows the prover to only send *s* (0) and *si*(2) in each round, see Section 3.6.1).

Round two message. At the end of round 1, the verifier sends the random value r₁. Similar to round 1, the prover’s round-2 message is a quickly-computable linear combination of the four values stored at level two of the tree (grandchildren of the root). Indeed,

X

|||,j) · ˆb(r₁, 0,k|,j).||
|---|---|---|---|---|
|k ∈{0,1}|, j∈{0,1}||||
|log T|k ′′|′|′′|log(T )−1 ′|

*s₂*(0) = *a*ˆ(r₁*,*0*,k* *′ ′* *′* log(*K*)*/d−*2 log *T*

Recall that for each *j ∈{*0*,*1*}*, the prover can quickly ascertain the unique *k ∈{*0*,*1*}* for which *a*ˆ(r₁*,k* *′′* *,j*) *̸*= 0, and quickly compute the factor *m* 1 *′* (which depends only only r₁ and *k₁*) such that

*a*ˆ(r₁*,k,j*) = *m · a*ˆ(*k,j*)*,*

where *k* *′* *∈{*0*,*1*}* log *K* is the unique vector such that *a*ˆ(*k* *′* *,j*) *̸*= 0. Similarly, we have assumed that the prover can quickly compute the factors *v₀,v₁* (which depend on only r₁) such that ˆ*b*(r₁*,*0*,k* *′* *,j*) = *v₀ ·* ˆ*b*(0*,*0*,k* *′* *,j*) and ˆ*b*(r₁*,*0*,k* *′* *,j*) = *v₁ ·* ˆ*b*(0*,*1*,k* *′* *,j*). Hence,

#### s₂(0) = m₀v₀L(0,0) + m₀v₁L(0,1).

Similarly, *s₂*(2) is a quickly-computable linear combination of the four nodes at distance two from the root: *L*(0*,*0), *L*(0*,*1), *L*(1*,*0), *L*(1*,*1):

*s₂*(2) = *c₀,*0*· L*(0*,*0) + *c₀,*1*L*(0*,*1) + *c₁,*0*L*(1*,*0) + *c₁,*1*L*(1*,*1)*,*

where for each *k₁,k₂ ∈{*0*,*1*}*, *c* *k* 1 *,k*2= *mk*1*,k*2*vk*1*,k*2*,*

where *mk*1*,k*2= eqe (r₁*,k₁*) 2 *·* eqe (2*,k₂*) 2

and *v* *k* 1 *,k*2= eqe (*k₁,r₁*) *−*1 *·* eqe (r₁*,r₁*) *·* eqe (2*,r₂*) *·* eqe (*k₂,r₂*) *−*1 *.*

Round *i ≤* log(*K*)*/*(*cd*). In general, *si*(0) and *si*(2) are each quickly-computable linear combinations of the nodes at distance *i* from the root. For example, when ˆ*a* = rae²*i*and ˆ*b*(*k,j*) = eqe (*r,k*) *·* eqe (*r* *′* *,j*), then:

X *s₂*(2) = *ck· L*(*k*)*,* *k∈{*0*,*1*}i*

where *ck*= *mk· vk*, defined as follows:

*mk*= eqe (r₁*,...,*r*i−*1*,*2*,k*) 2

and

||))|e (r₁,..., r · eq|,r₁,...,r|
|---|---|---|---|
||i||i|
||||i|

*v* *k*= eqe (*k,*(*r₁,...,ri* *−*1 *i i*)*.*

Each round *i ≤* log(*K*)*/*(*cd*) can be implemented in roughly *O*(2) field operations. 32

Tree-recomputation procedure. The prover performs a tree-recomputation procedure at the end of round log(*K*)*/*(*cd*). Specifically, the prover computes, for every *j ∈{*0*,*1*}* log *T*, the unique *k* = (*k₂,...,kc*) *∈* *{*0*,*1*}* (*c−*1)*·*log(*K*)*/*(*cd*) such that *a*ˆ(r₁*,...,*rlog(*K*)*/c,k,j*) *̸*= 0, and moreover for this *k*, the prover can compute
both ˆ*a*(r₁*,...,*rlog(*K*)*/c,k,j*) and ˆ*b*(r₁*,...,*rlog(*K/c*)*,k,j*).

Indeed, by Lemma 1, with *K¹* */*(*cd*) multiplications the the prover can compute eqe (r₁*,...,*rlog(*K*)*/*(*cd*)*,k* *′* ) for all *k* *′* *∈{*0*,*1*}* log(*K*)*/*(*cd*). Since *a*ˆ = rae²*i*, each quantity *a*ˆ(r₁*,...,*rlog(*K*)*/*(*cd*)*,k,j*) can be identified with a single lookup into this table followed by a squaring operation. Similarly, for each non-zero *a*ˆ(r₁*,...,*rlog(*K*)*/*(*cd*)*,k,j*), the value ˆ*b*(r₁*,...,*rlog(*K*)*/*(*cd*)*,k,j*) can also be computed with one multiplication given partial products computed and stored during the course of the procedure computing ˆ*b*(*k,j*) for all relevant values of (*k,j*) while building the partial sum tree prior to the start of round 1. This is 2*T* + *K¹* */*(*cd*) field multiplications in <u>total.</u> 32More precisely, by using a batch-inversion procedure, it’s possible to implement round *i* in with *O*(2*i*) field multiplications and one inversion.

Given these quantities, the prover can construct, with *T* more multiplications, a new partial-sum tree with *T* leaves, such that leaf *k* *′* stores X *a*ˆ(r₁*,...,*rlog(*K*)*/c,k* *′*
*,k₂,...,kc*) *·* ˆ*b*(r₁*,...,*rlog(*K*)*/*(*cd*)*,k*
*′* *,k₂,...,kc*)*.* *k*=(*k₁,k′,k₃,...,kc*)*∈{*0*,*1*}*log(*K*)*/d, j∈{*0*,*1*}*log *T*

The next log(*K*)*/*(*cd*) rounds proceed analogously to the first log(*K*)*/*(*cd*) rounds, followed by another tree-recomputation step, and so on until the first log(*K*)*/d* rounds are complete.

The final log*T* rounds can then be implemented exactly as in the case of small memory sizes (Section 6.3). The total cost for these final log*T* rounds is 5*dT* field operations (Section 6.3 implemented those rounds with only 3*dT* multiplications, but 2*dT* multiplications were saved there by exploiting that *K¹* */d* = *o*(*T*), which does not hold here if *c >* 1).

The full Booleanity-checking sum-check. Recall that the Booleanity-checking sum-check actually applies the sum-check protocol to compute X eqe (*r,k*)eqe (*r* *′* *,j*) rae*i*(*k,j*) 2 *−* rae*i*(*k,j*)*.* *k∈{*0*,*1*}*log(*K*)*/d, j∈{*0*,*1*}*log *T*

We have explained above how to apply the sum-check protocol to compute X eqe (*r,k*)eqe (*r* *′* *,j*)rae*i*(*k,j*) 2

*.* (64)
*k∈{*0*,*1*}*log(*K*)*/d, j∈{*0*,*1*}*log *T*

It suffices to now explain how to apply the sum-check prover to compute X eqe (*r,k*)eqe (*r* *′* *,j*)rae*i*(*k,j*)*,* (65) *k∈{*0*,*1*}*log(*K*)*/d, j∈{*0*,*1*}*log *T*

since in the Booleanity-checking sum-check the prover’s message in each round is just the difference between the corresponding message for Expressions (64) and (65).

Walking through the algorithm described above for proving Expression (64) and modifying it appropriately for Expression (65), it is easy to see that the sum-check prover for Expression (65) only needs to do *O*(*cK¹* */*(*cd*) ) additional field multiplications on top of what the prover for Expression (65) does. In other words, “handling” Expression (65) in addition to Expression (64) does not substantially change the prover cost.

Cost summary for Booleanity-checking when *K¹* */d* *≫ T*. In total, across all *i* = 1*,...,d*, the Booleanity-checking prover performs the following field multiplications:

- *c · K¹* */*(*cd*)
+ *T* multiplications in pre-computation to evaluate eqe polynomials at appropriate points.

- *d*(*c* + 1)*T* more multiplications to build the *d* partial-sum trees prior to round one.
- *O*(*dK¹* */*(*cd*)
) to compute the first log(*K*)*/*(*dc*) rounds worth of messages given these trees.

- 3*dT*+*O*(*dK¹*
*/*(*cd*) ) field multiplications every time the partial-sum tree is rebuilt and the next log(*K*)*/*(*cd*) rounds of messages are computed.

- 5*dT* field multiplications in the final log(*T*) rounds.
Since the partial sum tree for each *i* = 1*,...,d* is rebuilt *c −* 1 times, this means the prover performs

*O*(*dcK¹* */*(*dc*) ) + (*d*(*c* + 1) + 3*d*(*c −* 1) + 5*d* + 1)*T* = *O*(*dcK¹* */*(*dc*) ) + (4*dc* + 3*d* + 1)*T*

#### field multiplications in total.

For example, if *c* = 2 and *d* = 2, this is *O*(*K¹* */*

) + 23*T* field multiplications. This is an appropriate setting
of parameters when *K* = 2 as arises in Jolt (see Application 4 in Section 2.8), as in this case *K¹* */* = 2, which is substantially less than typical values of *T*.

### 7.3 Shout’s read-checking sum-check

Recall that the read-checking sum-check within Shout (Line 3 in Figure 7) applies the sum-check protocol to confirm that rve (*r*cycle) equals:

*d* ! X Y eqe (*r*cycle*,j*) rae*i*(*ki,j*) *·* Val f (*k*)*.* (66) *k*=(*k*1*,...,kd*)*∈*(*{*0*,*1*}*log(*K*)*/d*) *d* *, j∈{*0*,*1*}*log *T* *i*=1

[STW24, Appendix G] showed that the Val f polynomials corresponding to the lookup tables arising in the Jolt RISC-V zkVM satisfy the conditions necessary to apply the sparse-dense sum-check protocol to compute X *a*ˆ(*k*) *·* Val f (*k*) (67) *k∈{*0*,*1*}*log *K*

for any sparse, multilinear polynomial *a*ˆ. It extends trivially to also handle the case that *a*ˆ takes an additional log*T* variables and the sum is over *KT* terms rather than *K*, i.e., X *a*ˆ(*k,j*) *·* Val f (*k*)*.* (68) (*k,j*)*∈{*0*,*1*}*log *K×{*0*,*1*}*log *T*

To implement the read-checking sum-check prover quickly, we would like to apply the sparse-dense sum-check protocol to compute X *a*ˆ(*k,j*) *·* ˆ*b*(*k,j*)*,* log *K* log *T* 1

|||(k,j)∈{0,1}|×{0,1}|, k=(k ,...,k|)∈ {0,1}|
|---|---|---|---|---|---|
|||cycle|d i=1 i i|||
|||||d i=1 i|i|
||||||d|
|d||||||
|i=1|i i|||||

*d* ( log(*K*)*/d*)*d*

Q f ( with *a*ˆ(*k,j*) = eqe (*r,j*) *·* rae (*k,j*) and ˆ*b*(*k,j*) = Val *k*)*.* However, this does not *quite* map into the Q formulation of Expression (68), because rae (*k,j*) does not have degree one in each variable of *j* (though it *does* have degree one in each variable of *k₁,...,k*). Fortunately, this issue is not substantive. Since Q rae (*k,j*) is multilinear with respect to the variables of *k₁,...,kd*, we can still apply the sparse-dense sum-check protocol for the first log*K* rounds of the read-checking sum-check, and then “switch over” to the standard linear-time prover algorithm (Section 3.3) for the final log*T* rounds. If *C* is an integer such that *K¹* */C* = *o*(*T*), then the resulting total prover cost for the first log*K* rounds is, up to low-order terms, 2*CT* field multiplications.

The final log*T* rounds of Shout proceed identically to the case of small memories (Section 6.2), requiring *d²T* multiplications up to low-order terms.

Remark 2. *[STW24, Appendix G] also describes two prover algorithms that are simpler but slower than* *the one that uses just* 2*dcT field multiplications to implement the first* log *K rounds above. These simpler* *algorithms replace* 2*dc with an O*(log² *K*) *and O*(log*K*) *factor respectively. Even these simpler algorithms* *may be fast enough for Shout to improve on Lasso as applied in Jolt.*

### 7.4 The raf

### f -evaluation sum-check and Hamming-weight-one check when K≫T

As pointed out in Section 6.3, the raf f -evaluation sum-check of Figure 8 is identical to the read-checking sum-check in the core Shout PIOP, just with Val f (*k*) replaced with

X*d* log(*K* X

)*/d−*1 2 *i·*log(*K*)*/d*+*ℓ*
*· ki,ℓ,* *i*=1 *ℓ*=0

which is the MLE of the function that maps *k* to int(*k*). In other words, the R raf f -evaluation sum-check is equivalent to checking reads into the table whose *k*’th entry is (*k*). As further observed in Section 6.3, in

applications the prover can set *r*cyclein the core Shout PIOP equal to *r*cycle *′* (the random point at which the verifier wishes to evaluate raf f via the raf f -evaluation sum-check). Then running the raf f -evaluation sum-check and the read-checking sum-check in a batched manner per Section 4.2.1 is equivalent to replacing the lookup table Val f (*k*) with Val f (*k*) + *z ·* int f (*k*). The first log*K* rounds of the batched sum-check can be implemented by separately applying the read-checking sum-check to the two tables with MLEs given by Val f and int f, with the latter costing *CT* + *o*(*T*) multiplications for the prover. The final log*T* rounds of the batched protocol are no more expensive than the read-checking sum-check alone, as the value Val f (*r* *′′′* ) in the read-checking sum-check (where *r* *′′′* is the verifier’s random challenges chosen over the course of the first log*K* rounds) is simply replaced in the batched sum-check with Val f (*r* *′′′* ) + *z ·* int( f *r* *′′′* ).

Hamming weight one check. Checking that each committed address has Hamming weight one (Line 4 of Figure 8) can be directly implemented with *O*(*dK¹* */d* ) field multiplications after the prover computes an array storing eqe (*j,r*cycle *′′* ) for all *j ∈{*0*,*1*}* log *T* (which, for appropriate choice of *r*cycle *′′*, will have already been computed elsewhere within Shout). If *c >* 1 so *O*(*dK¹* */d* ) time is not acceptable, the original sparse-dense sum-check protocol applies with *a*ˆ(*k*) = rae*i*(*k,r*cycle *′′* ) and ˆ*b* = 1 and achieves cost *cT* + *O*(*CK¹* */C* ) field multiplications, where *C* = *cd*.

### 7.5 Cost summary for Shout when K≫T

In summary, for gigantic structured memories where *K¹* */C* = *o*(*T*), the Shout prover incurs the following costs up to low-order terms:

- 2*T* multiplications for evaluating rve (*r*cycle) before applying the read-checking sum-check.
- 2*C* + *d² T* multiplications for the read-checking sum-check.
- (4*C* + 3*d*) *T* for Booleanity checking.
33

- *CT* for the raf f -evaluation sum-check.
- *cT* for the Hamming-weight-one-checking sum-check if *c >* 1.
In total, this is at most 7*C* + *d²* + 3*d* + *c* + 2 *T* multiplications.

## 8 Fast Twist prover implementation

Recall from Figure 9 that the core Twist PIOP consists of three sum-check invocations: the read-checking sum-check, the write-checking sum-check, and the Val f -evaluation sum-check.

### 8.1 Val

### f -evaluation sum-check

Let us start by considering the Val f -evaluation sum-check, as it is the simplest. This invocation applies the sum-check protocol to compute:

X Inc f (*r* address*,j* *′* ) *·* LT f(*j* *′* *,r*cycle)*.* *j* *′* *∈{*0*,*1*}*log *T*

We explain in Appendix B that, with 3*T/*2 field multiplications, the prover can compute a table storing all evaluations of LT f(*j* *′* *,r*cycle) as *j* *′* ranges over *{*0*,*1*}* log *T*. Similarly, (but more straightforwardly) with 2*K* f (*r*

|field multiplications, the prover can compute a table storing all Inc|||||,j ) evaluations. To do this, one|
|---|---|---|---|---|---|
||||address||log K|
|Here, we avoid T multiplications by setting r|||= r|within the Booleanity-checking sum-check, and thereby reusing a||
|table of eq|e evaluations between the first bullet and this bullet, same as in Section 6.3.|||||

address *′*

first builds a size-*K* table storing all eqe (*r*address*,k*) evaluations for *k ∈{*0*,*1*}* log *K*, which requires *K* field 33 *′* cycle

multiplications (see Lemma 1). Given this table, each Inc f (*r*address*,j* *′* ) evaluation is simply the product of an increment with an entry of the size-*K* table.

Given the above two tables, the standard linear-time sum-check prover algorithm (Section 3.3) performs 4*T* additional field multiplications. Hence, total prover time in a straightforward implementation of the Val f -evaluation sum-check is 2*K* + 5*.*5 *· T* field multiplications. In Appendix B.2, we explain how to lower this to 2*K* + 4*T* field multiplications.

### 8.2 Read-checking and write-checking sum-checks

Achieving a fast prover in the read-checking and write-checking sum-checks requires new techniques. Let us begin by focusing on the read-checking sum-check, which in the case *d* = 1 confirms that rve (*r* *′* ) equals:

X eqe (*r* *′* *,j*) *·* rae (*k,j*) *·* Val f (*k,j*)*.* (69) (*k,j*)*∈{*0*,*1*}*log *K×{*0*,*1*}*log *T*

8.2.1 Overview We give two different prover algorithms. One, which we present in Section 8.2.5, achieves *O*(*T* log(*K*)+*K*+*d²T*) prover time. The other, which we call our “local algorithm”, has a worse dependence on *d* (though the same worst-case runtime when *d* = 1) but the following major advantage. Call a memory operation 2
*i* *-local* if it accesses for a memory cell that was previously accessed within the last 2 *i* cycles. For our local algorithm, any 2 *i* -local memory access only contributes *O*(*i*) field operations to the prover’s work. This is potentially much less than the worst-case bound of *O*(log*K*) field operations per memory operation. Due to the potentially poor concrete runtime when *d >* 1, we restrict our description of the local algorithm to the *d* = 1 case (though the generalization to *d >* 1 is straightforward).

The main difference between our two prover algorithms is as follows. In our local algorithm, we bind the log*T* variables of the cycle *j* first, starting with the “low-order” bit *j₁* of *j* and proceeding towards the high-order bit *j*log *T*. Intuitively, this allows the prover to benefit from local memory accesses during the first log*K* rounds of sum-check because round *i* “coalesces” the values at any given register *k* across a contiguous chunk of 2 *i* time steps. So, if fewer than 2 *i* distinct registers were read or written during these 2 *i* time steps, then the prover does less than 2 *i* work to process those time steps in round *i*. This leads to less than *T* total prover work in round *i*, resulting in a prover time that is less than *T* log*K* across those log*K* rounds. After round log*K*, there are only *T* terms to be summed, and the standard linear-time sum-check achieves *O*(*T*) *total* time for those rounds (as opposed to *O*(*T*) time *per round*).

The other algorithm binds the log(*K*) variables of the register address *k* first, rather than the log*T* variables of *j*.

8.2.2 Details of the local algorithm for read-checking Consider the standard linear-time sum-check prover implementation (Section 3.3). Our local-algorithm prover can be viewed as simply running this standard procedure, but optimized for the specific structure of this sum-check instance. Recall that for the local algorithm, we restrict our attention to the case that *d* = 1. Tracking increments instead of values. Naively implemented, the standard algorithm requires *K·T* space, with the bottleneck being storing all *K · T* evaluations of Val(*k,j*) for *k ∈{*0*,*1*}*
log *K* and *j ∈{*0*,*1*}* log *T*. However, we can avoid this by exploiting the same observation that leads to fast commitments: rather than explicitly storing all Val f (*k,j*) values for (*k,j*) *∈{*0*,*1*}* log *K* *×{*0*,*1*}* log *T*, the prover can instead just store, for each *j ∈{*0*,*1*}* log *T*, the unique register *k* that was written at cycle *j*, and the non-zero increment Inc(*k,j*) (see Definition 9).

Under this definition, for all *k ∈{*0*,*1*}* log *K* and *j ∈{*0*,*1*}* log *T*, X Val f (*k,j*) = Inc f (*k,j′*)*,* (70) *j* *′* *<j*

where *j* *′* *< j* is shorthand for LT(*j* *′* *,j*) = 1, i.e., for *j* *′* being the binary representation of an integer int(*j* *′* ) that is strictly less than int(*j*). Note that Equation (70) is *not* an equality of formal polynomials, but rather an equality that holds pointwise at all (*k,j*) *∈{*0*,*1*}* log *K* *×{*0*,*1*}* log *T*. Nonetheless, Equation (70) implies that for any *r₁,...,ri∈* F and any *j ∈{*0*,*1*}* log(*T*)*−i*, X Val f (*k,r₁,...,r* *i* *,j*) = Inc f (*k,r₁,...,ri,j*) *·* LT f(*j* *′* *,r₁,...,ri,j*)*.* (71) *j* *′* *∈{*0*,*1*}*log *T*

Indeed, the right hand side of Equation (71) is a multilinear polynomial in the log(*K*) + log(*T*) variables (*k,r₁,...,ri,j*), and by Equation (70) and the definition of LT, the right hand side and left hand side agree

|i|||
|---|---|---|
||log T|i|
|log(T )−i||log T|
||i||

whenever (*k,r₁,...,ri,j*) *∈{*0*,*1*}* log *K* *×{*0*,*1*}* log *T*.

Simplifying Expression (71). Break the *T* cycles *j ∈{*0*,*1*}* into *T/*2 “chunks” each of size 2 *i*. For each *j ∈{*0*,*1*}*, chunk *j* refers to the collection of all cycles in *{*0*,*1*}* whose last log(*T*) *− i* bits equal *j*, i.e., all cycles of the form (ˆ*j,j*) for some ˆ*j ∈{*0*,*1*}*.

We say that chunk ¯*j* is strictly less than chunk *j* (denoted ¯*j < j*) if LT f(¯*j,j*) = 0, i.e., if ¯*j* is the binary representation of an integer strictly less than the integer represented by *j*. Similarly, we say that chunk ¯*j* is strictly greater than chunk *j* (denoted ¯*j > j*) if ¯*j* is the binary representation of an integer strictly greater than *j*.

|′ ′′|log T||′′ ′|
|---|---|---|---|
||′ ′′|||
|∗ i||i||
|′|log T|′ ∗||

If *j,j ∈{*0*,*1*}* are respectively in chunks ¯*j* and *j* such that ¯*j < j*, then LT f(*j,j*) = 1. Meanwhile, if ¯ *j > j* then LT f(*j,j*) = 0.

Let *j* = (0*,j*) denote the first cycle in chunk *j*, where 0 denotes the all-zeros vector of length *i*. Then a cycle *j ∈{*0*,*1*}* is in a chunk ¯*j < j* if and only if *j < j*. Combining this with the preceding paragraph and Fact 3.1, we conclude that:   X X Val f (*k,r₁,...,r* *i* *,j*) =  Val f (*k,r₁,...,ri,j*) + Inc f (*k,j* *′′* ) *·* LT f(*j* *′′* *,r₁,...,ri,j*) *j* *′* *∈{*0*,*1*}*log *T*: *j′<j∗*ˆ*j∈{*0*,*1*}i, j′′*=(ˆ*j,j*) X = Val f (*k,j* *∗* ) + Inc f (*k,j* *′′* ) *·* LT f(*j* *′′* *,r₁,...,ri,j*)*.* ˆ *j∈{*0*,*1*}i, j′′*=(ˆ*j,j*)

It follows from the definition of LT f (Equation (87)) that for any *j* *′′* = (ˆ*j,j*), LT f(*j* *′′*
*,r₁,...,ri,j*) = LT f(ˆ*j,r₁,...,ri*).
Hence, we conclude that X Val f (*k,r₁,...,r* *i* *,j*) = Val f (*k,j* *∗* ) + Inc f (*k,j* *′′* ) *·* LT f(ˆ*j,r₁,...,ri*)*.* (72) ˆ *j∈{*0*,*1*}i*: *j′′*=(ˆ*j,j*)

Ensuring the prover runs in *O*(*T*) time per round. Since there is only one non-zero increment per cycle, the following fact follows easily from Fact 3.1.

Fact 8.1. *For any fixed j* *′′* *∈{*0*,*1*}* log(*T*)*−i* *, there at most* 2 *i* *registers k ∈{*0*,*1*}* log *K* *for which*

Inc f (*k,r₁,...,r* *i* *,j* *′′* ) *̸*= 0*.*

In round *i*, for fixed *j* *′* *∈{,}* log(*T*)*−*(*i−*1), let us refer to the vector n o Val f (*k,r₁,...,r* *i−,j* *′* ) : *k ∈{,}* log *K*

as *row j* *′* *of* Val f *in round i.* The prover will proceed iteratively through the rows in lexicographic order, starting with row 0 log(*T*)*−i* and proceeding to row 1 log(*T*)*−i*.

Per the above, the prover can maintain an array *I* that in round *i* stores the following values:

*I* in round *i* stores all non-zero evaluations of the form Inc f (*k,r₁,...,ri,j* *′′* ) for *j* *′′* *∈{*0*,*1*}* log(*T*)*−i*

*.* (73)
Given these increments, Equation (72) ensures that when processing row *j* *′*, the prover can indeed store in its memory all *K* values Val f (*k,r₁,...,ri,j* *′* ) as *k* ranges over *{*0*,*1*}* log *K*. By Fact 8.1, updating the array *I* round over round requires at most *T* multiplications for each round *i* = 1*,...,* log*K*. For a given row *j* *′*, the prover also has to computing the size-2 *i* sum in Expression (72) for each of the (at most) 2 *i* values of *k* for which rae (*k,r₁,...,ri,j* *′* ) *̸*= 0. This can be done with only 2 *i* multiplications per row, using the fact that for any ˆ*j ∈{*0*,*1*}* *i−*1 and *b ∈{*0*,*1*}*,

LT f(ˆ*j,b,r₁,...,r* *i* ) = eqe (*b,ri*) *·* LT f(ˆ*j,r₁,...,ri−*1) + (1 *− b*)*ri.*

In summary, for the first log(*K*) rounds of the read-checking sum-check, with 2*T* multiplications per round, the prover can ensure that in each round *i*, it can iterate over rows *j* *′* one-by-one and when processing row *j* *′*

ensure that it has in its memory the *K* values

Val f (*k,r₁,...,r* *i−*1*,j* *′* ) : *k ∈{*0*,*1*}* log *K*

*.* (74)
Computing other necessary arrays and worst-case cost accounting. Via standard techniques (see Lemma 1), with *K* field multiplications across all of the first log*K* rounds, the prover can maintain at each round *i* an array *A* storing all evaluations eqe (*x,r₁,...,ri*) as *x* ranges over *{*0*,*1*}* *i*. Since only one register is read per cycle, at the end of round *i*, each row *j* *′′* of rae (*·,r₁,...,ri,j* *′′* ) has at most 2 *i* non-zero entries, and each such entry is an entry of this array (this holds because ra(*k,j*) *∈{*0*,*1*}* for all (*k,j*) *∈{*0*,*1*}* log *K* *×{*0*,*1*}* log *T*, and is similar to Equation (46), which considered the case where *m* “register variables” rather than *i* “cycle variables” were bound to random field elements).

Similarly, with standard techniques, the prover can across all rounds *i* maintain an array storing all evaluations eqe (*r* *′* *,r₁,...,ri,j* *′′* ) as *j* *′′* ranges over *{*0*,*1*}* log(*T*)*−i*. This costs 2*T* field multiplications in total (*T* to build the size-*T* array at the start of the protocol, and *T* more to bind it round-over-round over the course of the protocol). These are the arrays (along with *I*) needed to run the standard linear-time sum-check proving algorithm described in Section 3.3. However, a significant optimization is possible to avoid these 2*T* field multiplications, and more significantly, to also save one field multiplication per relevant evaluation point *c* for each of the first log*K* rounds.

An optimization. The optimizations of Dao and Thaler [DT24] can be adapted to speed up the prover further. *√ √* Specifically, assuming *K* = *o*(*T*) so *KT* = *o*(*T*), the prover builds two different arrays of size at most *KT*, defined as follows. Let *rL* *′ ′*

||= (r₁ ,...,r||) and r|= (r|||,...,r|).|The first|
|---|---|---|---|---|---|---|---|---|---|
||L ′ L|(log(K)+log(T ))/2 ′′ i|′′|R|(log(K)+log(T ))/2+1 (log(K)+log(T ))/2−i|||log T||
|′′||||′′|||′′ ′′′||log(T )−i|
|′ ′|i ′ ′′′||i|′′′|||log(T )/2−log(K)/2|||
||R i||i−1||i−1|′′′|′|i||

(log( *′*

*K*)+log(*T*))*/*2 *R*
*′* (log( *′*

*K*)+log(*T*))*/*2+1 log
*′* *T* array *E*, at the end of round *i*, stores the following values:

*E* stores eqe (*r,r₁,...,r,j*) as *j* ranges over *{*0*,*1*}.* (75)

Intuitively, *E*(*j*) captures the contribution of the “left part” *j* of a cycle index *j* = (*j,j*) *∈{*0*,*1*}* to the value eqe (*r,r₁,...,r,j*).

The second array *E*, in round *i*, stores the following values

*E* *′* stores *A*(*x*) *·* eqe (*r,j*) as *x* ranges over *{*0*,*1*}* and *j* ranges over *{*0*,*1*}.* (76)

This array captures the *combination* (i.e., product) of the contribution of *j* to eq(*r,r₁,...,r,j*) and the
value rae (*k,j*) if rae (*k,r₁,...,r,j*) *̸*= 0, namely eqe (*r₁,...,r,k₁,...,k*).

For each index *j* *′′* *∈{*0*,*1*}* (log(*K*)+log(*T*))*/*2*−i*, the prover maintains an “aggregated value” agg*j′′*, initialized to

0. When the prover in round *i* wants to compute its prescribed message *si*(*c*), it sums over all
(*k,j*) *∈{*0*,*1*}* log *K* *×{*0*,*1*}* log(*T*)*−i*

such that rae (*k,r₁,...,ri−*1*,c,j*) *̸*= 0*.*

Recall that for each row *j ∈{*0*,*1*}* log(*T*)*−i*, there are at most 2 *i* such values of *k*.

For each such pair (*k,j*), write *j* = (*j* *′′* *,c,j* *′′′* ) with *j* *′′* *∈{*0*,*1*}* (log(*K*)+log(*T*))*/*2*−*(*i−*1) and *j* *′′′* *∈{*0*,*1*}* log(*T*)*/*2*−*log(*K*)*/*2. The prover uses a constant number of lookups into the arrays *E* *′* and *I*, followed by a single field multiplication, to compute eqe (*rR* *′* *,j* *′′′*
) *·* eqe (*r₁,...,ri−*1*,c,k₁,...,ki−*1*,ki*) *·* Val f (*k,r₁,...,ri−*1*,c,j*)*,*

and adds the result to agg*j′′*. This ensures that when all relevant pairs (*j,k*) have been processed, the following holds: X *s* *i*

(*c*) = agg*j′′ ·* eqe (*c,ri′*) *· E*[*j*
*′′*]*.* *j* *′′* *∈{*0*,*1*}*(log(*K*)+log(*T*))*/*2*−i*

Worst-case cost accounting. In total, maintaining the arrays *√* *E* (Expression (75)) and *E* *′* (Expression (76)) across the first log*K* rounds requires *O*( *KT*) = *o*(*T*) field multiplications. Maintaining the array *I* (Expression (73)) costs at most 2 *i* *·* (*T/*2 *i* ) = *T* multiplications per round, as there are *T/*2 *i* rows in round *i* and computing one row given the previous row requires at most 2 *i* multiplications. This yields a total of *T* log*K* multiplications to maintain the array *I* over the first log*K* rounds. Translating the values in the array *I* into necessary evaluations of Val f costs another *T* multiplications per round. We call these (at most) 2*T* log*K* field multiplications *write-induced multiplications.* *i i* *√* Given these arrays, the prover in round *i* = 1*,...,* log*K* performs at most *T/*2 *·* 2 + *O*( *TK*) = *T* + *o*(*T*) field multiplications for each of the relevant evaluation points *si*(*c*). Since *d* = 1, there are two evaluations points, namely *c ∈ {*0*,*2*}*. This means there are 3 log(*K*)*T* + *o*(*T*) field multiplications, which we call *read-induced multiplications.*

In total, this means the first log*K* rounds of the sum-check protocol applied to Expression (69) incur at most the following number of field multiplications when *d* = 1:

#### 4 log(K)T + o(T).

After round log*K*, the number of terms being summed has fallen from *KT* down to *T*, and the standard linear-time sum-check proving algorithm (appropriately optimized [DT24, Gru24]) requires at most 6*T* total field multiplications to implement all subsequent rounds. In fact, when *K* = *o*(*T*), this falls to roughly 5*T* due to binding of the *E* array taking much less than *T* field operations, as in each round *i*, there are two different algorithms the prover can choose between to bind *E*, one taking time 2 *i*, which leverages that at the start of the protocol *E* contains only values in *{*0*,*1*}*, and the other taking time *T · K/*2 *i*.

Hence, in total, for small memories the number of prover field multiplications when *d* = 1 is upper bounded by roughly: (4 log(*K*) + 6)*T* + *o*(*T*)*.*

8.2.3 A refined time bound for local memory accesses The dominant term in the (worst-case) time bound for our main prover algorithm is 4 log(*K*)*T* field multipli- cations. This comes from performing 4 multiplications per cycle for each of the first log*K* rounds. One of these four multiplications is *write-induced*: it comes from updating the array *I* that stores Inc f evaluations: there are only *T/*
*i* “rows” of such evaluations stored in round *i*, but computing one row given the previous row can require 2 *i* field multiplications. This means that every write operation, in the worst case, contributes one field multiplication per round, for each of the first log *K* rounds.

The other (at most) three field multiplications per cycle per round are read-induced. In round *i* + 1, one of these three comes from translating values in *I* into relevant evaluations of the form Val f (*k,r₁,...,ri,j*) for

|log(T )−i|||
|---|---|---|
|′′ ′′|i||
|||i|
|i||i i|

*j ∈{*0*,*1*}* log(*T*)*−i*. This costs one multiplication per distinct register *k* that is actually read during cycles of the form (*j,j*) with *j ∈{*0*,*1*}*, and there are 2 *i* such registers in the worst case. The other two read-induced multiplications per cycle in round *i* + 1 occur as follows. Each of the *T/*2 rows of *E* at the end of round *i* has at most 2 distinct values, which means round (*i* + 1) incurs at most 2 *·* (*T/*2) field multiplications per evaluation point *c ∈{*0*,*2*}*. This means that every read operation, in the worst case, contributes two field multiplications per round for the first log*K* rounds.

Refined cost analysis for write-induced operations. At the end of round *i*, updating the array *I*

|i|log(T )−i||
|---|---|---|
|′ i||′|
||′||
|||i|

requires at most 2 field multiplications. However, a tighter bound holds. For any *j* *′* *∈{*0*,*1*}* consider cycles between int(*j*) *·* 2 and (int(*j* *′*

) + 1) *·* 2 *i*. These are the cycles whose high-order log(*T*) *− i* bits equal *j*.
If at most *Z* distinct registers were written during these cycles, then in round *i*, computing row *j* of *I* from the preceding row requires only *Z* field multiplications. In particular, if there were *D* duplicate writes during these cycles (meaning a write to a register that was already written during these cycles) then *Z* equals 2 *− D*.

Refined cost analysis for read-induced operations. Similarly, if there were *D* “duplicate reads” during these cycles, then the number of field multiplications in round *i* due to read operations performed during these cycles falls from a worst-case bound of 2 *·* 2 *i* to 2 *·* (2 *i* *− D*).

In summary, if a write operation is made to a register that was written 2 *i* cycles previously, then that write operation does not increase the number of distinct write operations in its chunk of write cycles in any round after round *i*. Hence, it only contributes *i* total multiplications to the prover’s work across all rounds (vs. a worst-case bound of log*K* multiplications).

Similarly, if a read operation is made to a register that was read 2 *i* cycles previously, then that read operation only contributes 3*i* total multiplications to the prover’s work across all rounds (vs. a worst-case bound of 3 log*K* multiplications).

8.2.4 Write-checking sum-check via the local algorithm Recall from Equation (34) that the write-checking sum-check is applied to compute
*d* !! X Y eqe (*r,k*) *·* eqe (*r* *′* *,j*) *·* wa f*i*(*ki,j*) *·* wv f(*j*) *−* Val f (*k,j*)*.* (77)

|||i i|
|---|---|---|
|k=(k ,...,k|)∈ {0,1}|i=1|

1 *d* (log(*K*)*/d*) *d*, *j∈{*0*,*1*}*log *T*

Let us focus on the case *d* = 1. We begin by considering a slightly simpler expression: X eqe (*r,k*) *·* eqe (*r* *′* *,j*) *·* wa f(*k,j*) *·* Val f (*k,j*)*.* (78) *k*=(*k*1*,...,kd*)*∈*(*{*0*,*1*}*log(*K*)*/d*) *d*, *j∈{*0*,*1*}*log *T*

The sum-check invocation computing Expression (78) is almost identical to the one in the read-checking sum-check, with the main difference being the eqe (*r,k*) factor appearing in each term of the sum. If *K²* = *o*(*T*), this factor can be handled with no major modifications to the read-checking sum-check nor any significant increase in prover cost, and if *K* = *o*(*T*) incorporating this factor increases prover costs by at most *T* multiplications. Furthermore, since the sum-check for Expression (78) is run in parallel with the read-checking sum-check, the work to maintain the array *I* capturing evaluations of Val f can be reused within both the read-checking and writing-checking sum-check.

To apply the sum-check protocol to Expression (77) instead of the simpler Expression (78), simply run the prover for Expression (78), but every time the prover processes a value Val f (*k,r₁,...,ri,j*), replace this with Val f (*k,r₁,...,r* *i* *,j*) *−* wv f(*r₁,...,ri,j*).

8.2.5 Alternative algorithm for read-checking and write-checking We describe an alternative prover implementation for the read-checking sum-check in Twist that performs *O*(*T*) field operations for each of the first log*K* rounds. Standard linear-time sum-check prover algorithms implement the final log*T* rounds with roughly *d²T* field multiplications (see Section 6.2.2 for details). Let us begin with the read-checking sum-check. Recall that for general *d >* 1, the read-checking sum-check within Twist is used to confirm that:
*d* ! X Y

|) =||e ra (k ,j)|
|---|---|---|
|||i i|
|k=(k|,...,k)∈ {0,1}|i=1|

rve (*r* *′* eqe (*r* *′* *,j*) *·i i·* Val f (*k,j*)*.*

1 *d* (log(*K*)*/d*) *d*, *j∈{*0*,*1*}*log *T*

We describe the algorithm as if it is sequential, but it is easy to see that a (*T/K*)-fold parallel speedup is achievable with at most a constant-factor increase in total prover work, by processing in parallel Θ(*T/K*) “chunks” of operations consisting of Θ(*K*) cycles in each. 34

Our algorithm is essentially just the standard linear-time sum-check proving algorithm (Section 3.3), but optimized to leverage the specific structure of this particular sum-check instance. Specifically, before round one, the prover computes *d* + 2 arrays, say *B*, *C*, and *A₁,...,Ad*. *B* has size *T*, *C* has size *K·T*, and and *A₁,...,Ad*have size *K¹* */d* *· T*. As we will see, the prover need not ever explicitly materialize *C* or *A₁,...,Ad* in their entirety, due to their structure in this particular sum-check instance. But for now let us consider a naive implementation of the standard algorithm, despite its unacceptably large runtime.

*B* initially stores all evaluations of eqe (*r* *′* *,j*) as *j* ranges over *{*0*,*1*}* log *T*. *B* can be computed with *T* multiplications via standard techniques (Lemma 1). *C* initially stores Val f (*k,j*) for all (*k,j*) *∈{*0*,*1*}* log *K* *×* *{*0*,*1*}* log *T*. And *Aℓ*stores rae*ℓ*(*kℓ,j*) for all *kℓ∈{*0*,*1*}* log(*K*)*/d* and *j ∈{*0*,*1*}* log *T*. By applying the binding procedure described in Section 3.3, the prover ensures that at the end of each round *ℓ ≤* log(*K*), *C* has size

|and C[k|,j] = Val|f (r₁,...,r|,k ,j) for all (k|,j) ∈{0, 1}||×{0, 1}||
|---|---|---|---|---|---|---|---|
|||′||i ′|′|log(K)/d−i|log T|
||ℓ|||||||
|||||d||||
|||||log T||||
|′||log(K)−i||||||

(*K·T*) */*2 *ℓ ′* *i* *′ ′* log(*K*)*−i* log *T*. Similarly, at the end of each round *i ≤* log(*K*)*/d*, *A₁*[*k* *′* *,j*] = rae₁(*r₁,...,r,k* *′* *,j*) for all *k* *′* *∈{*0*,*1*}* log(*K*)*/d−i* and *j ∈{*0*,*1*}* log *T*, and similarly *A* halves in size during each of rounds (*ℓ −* 1) *·* log(*K*)*/d* + 1*,...,ℓ*log(*K/d*).

The above naive implementation of the standard linear-time algorithm is extremely wasteful because it ignores the following structure in the arrays *C* and *A₁,...,A*.

- At the end of any given round *i*, for fixed *j ∈{*0*,*1*}*, let us refer to all entries of *C* of the form *C*[*k,j*] for some *k*
*′* *∈{*0*,*1*}* as the *j’th row of C*. Then any two adjacent rows differ in at most one entry. This is because at most one address gets written in each cycle.

- At the end of any given round *i*, any given row of *Aℓ*has exactly one non-zero entry (see Equation (46) for details).
Avoiding spending *K¹* */d* *· T* time and space processing *Aℓ*. Per the second bullet, our prover will store, for each row of *Aℓ*, merely the index *k* of the non-zero entry in that row, and the associated value of that entry. In fact, it’s not even necessary to store that value: in round (*ℓ −* 1) *·* log(*K*)*/d* + *i*, there are only 2 *i* distinct values in the array *Ai*(see Equation (46) for what those values are), so the prover merely needs to store a lookup table of size 2 *i* storing those values and that lookup table can be shared amongst all the rows. The first *i* bits of the index *k* of the non-zero entry in a given row specify the appropriate index in the lookup table storing the associated non-zero value.

Avoiding spending *KT* time and space processing *C*. Per the first bullet, the prover will not explicitly store *C*. Rather, in each round *i* + 1, the prover will iteratively generate each row of *C* and “process” that row’s contributions to the prescribe round-*i* message. 34Bigger parallel speedups are possible at the cost of increased total prover work. Also, sharding described in Section 3.1.1 provides additional opportunities for parallelism beyond whatever parallelism is available when processing a single shard.

In more detail, via repeated application of Fact 3.1, one easily derives that for any *k* *′* *∈{*0*,*1*}* log(*K*)*−i* and any *j ∈{*0*,*1*}* log *T*

||,||X||
|---|---|---|---|---|
||′′ ′|′ i|k ∈{0,1} log(K)−i|′′ ′|
|′′′ ′|′′′|′′′|||
|′|′||||

*C*[*k* *′* *,j*] = Val f (*k* *′′* *,k* *′* *,j*) *·* eqe (*k* *′′* *,r₁,...,ri*)*.* (79) *′ i*

Suppose that *k* = (*k,k*) *∈{*0*,*1*} ×{*0*,*1*}* is the (binary representation of) the address written at cycle *k*. Let next(*j*) be the binary representation of the “next” row, i.e., of int(*j*) + 1. Then by Equation (79), for any *k ̸*= *k*, *C*[*k,j*] = *C*[*k,*next(*j*)]. That is, the only column that differs between rows *j* and next(*j*) is column *k* (i.e., *k* is the column whose trailing log(*K*) *− i* bits equal those of the binary representation of the register that was written at cycle *j*).

Moreover, recall from the Twist PIOP that the *increment* Inc(*k,j*) is the difference between the value stored at register *k* at cycle *j* + 1 vs. cycle *j*. Then if *k* = (*k* *′′* *,k* *′* ) is the cell written at cycle *j*,

*C*[*k* *′* *,* (*j*)] *− C*[*k* *′* *,j*] = Inc(*k,j*) *·* eqe (*k* *′′* *,r₁,...,ri*)*.* (80)

And via standard techniques (see Lemma 1) the prover can, with *K* field operations across all of the first log*K* rounds, build an array that in round *i* stores all values of the form eqe (*k* *′′* *,r₁,...,ri*) as *k* *′′* ranges over *{*0*,*1*}* *i*.

Hence, putting all of the above together, the prover can, in each round *i* = 1*,...,* log*K* of the read-checking sum-check, iterate one-by-one over all cycles *j ∈{*0*,*1*}* log *T*, and ensure at all times that it has in its memory the *j*’th row of *C*, i.e., *C*[*k* *′* *,j*] as *k* *′* ranges over *{*0*,*1*}* log(*K*)*−i*+1. By Equation (80), the total number of field multiplications needed to accomplish this is *T* per round.

Total prover costs. To get through the first log*K* rounds of the read-checking sum-check, the prover incurs the following costs.

- *T* field multiplications to build the array *B* of eqe (*r*
*′* *,j*) evaluations.

- *O*(*dK¹* */d* ) multiplications to maintain the arrays *A₁,...,Ad*.
- *T* log*K* + *O*(*K*) to maintain the array *C* throughout.
- If one directly applies the standard linear-time sum-check prover, then given the above arrays, the prover incurs 4 field multiplications per row *j ∈{*0*,*1*}*
log *T* per round. Here, 4 comes from there being two relevant evaluation points *c ∈{*0*,*2*}* in each of these rounds, and two multiplications needed for each of them (one to multiply an entry of *C* by an evaluation of the relevant array *Aℓ*for that round, and another to multiply the result by the eqe (*r* *′* *,j*) value for that row *j*).

However, the optimization adapted from [DT24] that applied to the local algorithm also applies here. *√* Roughly, this entails replacing the array *B* and the arrays *A₁,...,Ad*with 2*d KT*-sized arrays (two per *Ai*). This eliminates the *T* multiplications needed to build *B* and one of the two multiplications per evaluation point *c*.

Hence, if *K* = *o*(*T*), the first log*K* rounds of Twist’s read-checking sum-check require 3 log(*K*)*T* + *o*(*T*) field multiplications of the prover. The last log*T* rounds require (*d²* + 2*d* + 1)*T* field multiplications via the standard linear-time sum-check algorithm (Section 3.3), appropriately optimized [DT24, Gru24].

Write-checking sum-check. As with the local algorithm, implementing the write-checking sum-check prover is similar to the read-checking case. The situation is actually nicer in the case of the alternative algorithm, since for the alternative algorithm both the read-checking and write-checking sum-checks bind the log*K* variables of *k* before the log*T* variables of *j*. If *K* = *o*(*T*), this ensures that the total number of prover multiplications incurred to implement the write-checking sum-check (on top of the work the prover does in the read-checking sum-check) is at most

(2 log(*K*) + *d²* + 2*d* + 2)*T.*

### 8.3 Cost summary

Local algorithm for *d* = 1. If *K* = *o*(*T*), then using the local proving algorithm, the entire core Twist PIOP with *d* = 1 can be implemented with the following number of field multiplications, up to low-order terms:

- 4*T* from the Val f -evaluation sum-check.
- (4 log(*K*) + 6)*T* from the read-checking sum-check.
- An additional (3 log(*K*) + 5)*T* from the write-checking sum-check.
This is at most (7 log(*K*) + 15)*T* field operations to process *T* reads and *T* writes. For *K* = 32 = 2 5, this is 50*T* field multiplications. For *K* = 2 20, it is 155 *· T*.

However, the costs benefit significantly from locality. For large memories, the dominant term by far is the 7 log(*K*)*T* field operations, 4 log*K* of which can be attributed to each write and 3 log*K* to each read. If a write operation is 2 *i* -local, then 4 log*K* falls to 4*i* and similarly if a read operation is 2 *i* -local, then 3 log*K* falls to 3*i*.

Checking correctness of one-hot encodings (Figure 8) for all 2*T* committed addresses must be done in addition to the above costs. Per Section 6.3, this costs 6*dT* + *O*(*dK¹* */d* ) field multiplications (up to low-order terms, all of this extra cost is coming from Booleanity-checking).

The alternative algorithm. The alternative algorithm algorithm has similar (in fact, slightly better) costs in the worst-case to the local algorithm when *d* = 1, but generalizes more nicely to *d >* 1 because it binds the variables of *k* before the variables of *j*, and the degree in the variables of *k* is independent of *d* for all of the polynomials that the sum-check protocol is applied to within Twist. Specifically, the costs are:

- 4*T* from the Val f -evaluation sum-check.
- (3 log(*K*) + *d²* + 2*d* + 1)*T* from the read-checking sum-check.
- An additional (2 log(*K*) + *d²* + 2*d* + 2)*T* from the write-checking sum-check.
In total, this is at most (5 log(*K*) + 2*d²* + 4*d* + 4)*T* field multiplications. For *d* = 1, this is

(5 log(*K*) + 10)*T,*

slightly improving the worst-case bound of the local algorithm of (5 log(*K*) + 19)*T*.

## 9 Faster SNARKs for non-uniform computation

This section describes SpeedySpartan and Spartan++, fast SNARKs for non-uniform circuits. A distinguishing aspect of both is that they incur minimal commitment costs: the prover simply commits to its witness, and the rest of the prover’s work is field operations in the sum-check protocol and the cost to prove a polynomial evaluation (which, for appropriate polynomial commitment schemes, can be sub-linear in the size of the circuit). This improves significantly on Spartan and BabySpartan (and other prior SNARKs) for non-uniform circuits.

### 9.1 Overview

In this overview, let us consider the simple and clean setting of proving satisfiability of an arithmetic circuit consisting of fan-in two addition and multiplication gates over field F. This treatment extends easily to more general constraint systems.

Suppose that the circuit has size *T* and consider two log(*T*)-variate multilinear polynomials *z*e*A*and *z*e*B*that respectively capture the left and right inputs to each gate of the circuit and a third polynomial *z*e that captures the output of each gate. The first two polynomials, *z*e*A*and *z*e*B*are *virtual polynomials*: they are not explicitly committed/sent by the SpeedySpartan prover. The third polynomial *z*e *is* explicitly committed/sent by the prover.

Overview of SpeedySpartan. SpeedySpartan applies the sum-check protocol once to confirm that *z*e respects the operation of its gate. That is, if *j ∈{*0*,*1*}* log(*T*) is the label of a multiplication gate, then the sum-check confirms that *z*e

||(j) = ze|(j) · ze|(j), and similarly if j is an addition gate then the sum-check confirms that|||
|---|---|---|---|---|---|
||C|A|B|||
|C A|B|||||
||||||A B|
|||||A||
|||||A B||
|A|||||L|
||||R|||

*z*e (*j*) = *z*e (*j*) + *z*e (*j*).

At the end of this sum-check, the verifier has to evaluate each of *z*e, and *z*e and *z*e at a random point. Since *z*e was explicitly committed by the prover, the evaluation of *z*e can be obtained via the evaluation argument of the polynomial commitment scheme. Since *z*e and *z*e*B*are virtual polynomials the verifier cannot obtain their evaluations directly. SpeedySpartan applies the sum-check protocol a second time to reduce the task of computing the necessary evaluations of *z*e and *z*e to the task of evaluating *z*e at single point. In particular, this second sum-check invocation is simply the Shout read-checking sum-check (see Figure 7). That is, the left input *z*e (*j*) to gate *j* is equal to the value *output* by some other gate *j*, and similarly the right input *z*e*B*(*j*) to *j* is the output of some gate *j*. This is the same as a *lookup* into the table whose entries are given by *z*e. The wires of the circuit (i.e., the identities of the left and right inputs to each gate) determine the addresses that are looked up. In the context of SpeedySpartan, these addresses depend only on the circuit wires and hence can be committed (as in Shout) by an honest party in pre-processing. This a complete overview of the SpeedySpartan protocol.

Overview of Spartan++. Recall that Spartan is a SNARK for R1CS and that SuperSpartan extends it to CCS [STW23], a generalization of Plonkish, R1CS, and AIR. Spartan++ is essentially just SuperSpar- tan [STW23], but with an improved sparse polynomial commitment scheme used to commit to “constraint matrices”. Specifically, if the prover is claiming to know a solution vector *z* to an R1CS instance

*Az ◦ Bz* = *Cz,*

(where, unlike in SpeedySpartan, *A*, *B*, and *C*, may have many non-zeros per row), then Spartan has the multilinear extension polynomials *A*e, *B*e, and *C*e committed in pre-processing via Spark. In the online phase of Spartan, the sum-check protocol is applied several times, and at the end of these invocations, the Spartan verifier needs to evaluate *A*e, *B*e, and *C*e at a random point *r* (in the case of CCS, the verifier needs evaluations of *M*f₀*,..., M*f*t−*1for a chosen value of *t*). This evaluation in Spartan is provided by the prover along with a Spark evaluation proof. Spark uses the Lasso lookup argument internally, to perform lookups into a structured table storing all multilinear Lagrange basis polynomials evaluated at *r*. Spartan++ is the same, except we give a much faster sparse polynomial commitment scheme, based on Shout rather than Lasso. We call this scheme Spark++. Unlike Lasso, Shout allows the values returned by the to be virtual, which eliminates the primary bottleneck for the Spark prover (namely, committing to the values returned by the lookups; these values are random since *r* is random, and hence very slow to commit to).

### 9.2 Details of SpeedySpartan

9.2.1 Detailed protocol description Our presentation below borrows text from BabySpartan [ST23]. Like BabySpartan [ST23], our focus here is on Plonkish constraint systems. For simplicity and easier adoption, we focus on degree-2 Plonkish, but the protocol readily applies to arbitrary degree Plonkish with custom gates. In particular, we use the definition from Plonk [GWC19, §6], which we state below. Definition 9.1 (Plonkish). *Consider a finite field* F*. Let the public parameters consist of size bounds* *m,n,ℓ ∈* N*, with ℓ < n. The Plonkish structure consists of: (1) vectors qm,ql,qr,qo,qc∈* F
*m* *, and (2) a set* *of vectors* (*a,b,c*) *∈* [*n*] *m* *specifying the left, right, and output indices in a vector containing public IO and* *witness. An instance x ∈* F *ℓ* *consists of public IO and is satisfied by a witness w ∈* F *n−ℓ* *if the following holds* *for all i ∈* [*m*]*.* (*ql*)*i· zai*+ (*qr*)*i· zbi*+ (*qo*)*i· zci*+ (*qm*)*i·* (*zai· zbi*) + (*qc*)*i*= 0*, where z* = (*w,x*) *and zai* *denotes the entry of z at index provided by the ith entry of vector a.*

Note that Plonkish is a special case of CCS [STW23]. Observe that the vector *z* can be viewed as a lookup table and its entries are “looked up” at indices provided by vectors *a,b,* and *c*. In the language of CCS, we can represent these indices as three sparse matrices. Let *A,B,C ∈* F *m×n* denote those matrices. In particular,

for all *i ∈* [*m*], the *i*th row of *A* (similarly *B* and *C*) is the unit vector that encodes the position specified by the *i*th entry of vector *a* (similarly *b* and *c*). In other words, each row of *A,B,C* contains a single non-zero entry of 1 so that the matrix-vector products *Az,Bz,Cz* “lookup” the correct entry of *z*. Thus, we can express the Plonkish satisfiability check as follows:

*q* *l◦ Az* + *qr◦ Bz* + *qo◦ Cz* + *qm◦ Az ◦ Bz* + *qc*= 0

SpeedySpartan can use any multilinear polynomial commitment scheme. In a preprocessing phase, the verifier (or other honest party) commits to polynomials that encode the circuit structure (i.e., sparse matrices *A,B,C*) using a multilinear polynomial commitment scheme. In the online phase, the prover begins by committing to its purported witness *w*e. The prover then reduces the circuit satisfiability check to claims about evaluations of *w*e and polynomials committed in the preprocessing phase. Finally, the prover uses the polynomial evaluation argument of the polynomial commitment scheme to prove those claimed evaluations.

Figure 10 depicts the SpeedySpartan PIOP in full. Below, we describe via prose the resulting SNARK one

obtains by combining the PIOP with a multilinear polynomial commitment scheme.

Preprocessing phase. In a preprocessing step, the verifier (or another trusted party) computes commit- ments to the multilinear extensions of the matrices *A,B,C ∈* F *m×n*. Each row in these matrices is a unit vector, i.e., each row contains a single entry equal to 1 (the rest are zeros). In other words, each matrix proves the one-hot encodings of *m* addresses into a table of size *n*.

For a chosen parameter *d ≥* 2, the commitment to each sparse matrix encodes *m* lookup addresses using *d*-dimensional one-hot encodings (Section 3.7). Since this commitment is created by the verifier (or another trusted party), there is no need to ensure, as part of Shout, that the underlying vectors are one-hot encodings. That is, Booleanity-checking and additional checks from Figure 8 are not needed. This is analogous to how in Spartan’s preprocessing step [Set20], there is no need to prove the correctness of timestamps in its use of offline memory checking procedure.

Online phase. Without loss of generality, let *m* and *n* be powers of 2 and that *ℓ* = *n/*2. Let *s* = log *m,s* *′* = log*n*. For a purported witness *w ∈* F *n−ℓ* and public IO *x ∈* F *ℓ*, let *z* = (*w,x*) *∈* F *n*. We can view the vector *z* *s* *′* as a function with the signature *{*0*,*1*} →* F. Similarly, we can view the sparse matrices *A,B,C* as functions with the following signature: *{*0*,*1*}* *m* *×{*0*,*1*}* *n* *→* F. Crucially, in our target setting, each row of these sparse matrices is a unit vector (i.e., there is a single non-zero entry of 1 and the rest are zeros).

For all *x ∈{*0*,*1*}* *s* and *M ∈{A,B,C}*, let   X *z*f *M*(*x*) =  *M* f(*x,y*) *· z*e(*y*)

*y∈{*0*,*1*}s′*

#### Also, let

*f* (*x*) = (*q*e*l*(*x*) *· z*e*A*(*x*) + *q*e*r*(*x*) *· z*e*B*(*x*) + *q*e*o*(*x*) *· z*f*C*(*x*) + *q*f*m*(*x*) *· z*e*A*(*x*) *· z*e*B*(*x*) + *q*e*c*(*x*)) (82)

The prover begins by sending a commitment to its purported witness *w*e. To check satisfiability, the verifier selects a random *τ ∈* F *s*, and applies the sum-check protocol to the polynomial

*g*(*x*) = eq˜ (*τ,x*) *· f*(*x*)*,*

using it to confirm that X 0 = *g*(*x*)*.* *x∈{*0*,*1*}s*

If *z* satisfies the constraint system then this equality is guaranteed to hold, and if *z* does not satisfy the constraint system then this equality will fail to hold with probability at least 1 *− O*(*s*)*/|*F*|*.We call this the “Spartan-sum-check” since this sum-check invocation is exactly how Spartan begins [Set20].

Preprocessing phase. The input to this step includes sparse matrices *A,B,C ∈* F *m×n*, where each row of the sparse matrix is a unit vector, and vectors *q* *m*

|||,q|,q ,q ,q|∈ F. The preprocessing phase||
|---|---|---|---|---|---|
|||l|r o m c|m||
|l r /d|o m c|C|||M|
|M||M,1|M,d||/d n−ℓ|
|ℓ||ℓ||||
||s|||||

outputs a set of polynomials for which the verifier has a query access.

- Output (*q*e*, q*e*, q*e*, q*f*, q*e*,*addr g*A,*addr g*B,*addr g), where for *M ∈{A,B,C}*, addr is the vector of size *m · d · n¹* listing the *d*-dimensional one-hot encodings of addresses provided in *M* per Section
3.7 (i.e., viewing each row of *M* as the one-hot encoding of an address into a lookup table of size
*n*). addr g is sent as *d* separate polynomials addr*,...,* addr each of size *m · n¹*.
Online phase. The prover is given as input a purported witness vector *w ∈* F and a public IO vector *x ∈* F. The verifier is given as input *x ∈* F.

1. *P→V*: A purported witness polynomial *w*e.
2. *V→P*: pick *τ ∈* F at random and send it to *P*.
3. *V↔P*: Let *f* be defined as per Equation (82) (degree-2 Plonkish) or (83) (arithmetic circuits). *V* and *P* apply the sum-check protocol to confirm that
X 0 = eq(*τ,x*) *· f*(*x*)*.* *x∈{*0*,*1*}s*

At the end of the sum-check protocol, the verifier is left with checking whether

*c* = eq(*τ,r*) *· f*(*r*)*,*

where *c* and *r* are determined over the course of the sum-check protocol.

4. *P →V*: Let *z* = (*w,x*), and *zA*= *A · z*, *zB*= *B · z* and *zC*= *C · z*. Send *vA,vB,vC*defined as follows:
*v* *A← z*e*A*(*r*)*, vB← z*e*B*(*r*)*, vC← z*e*C*(*r*)*.*

5. *V*: Let *e* = eq(*τ,r*), and obtain the following values by querying polynomials committed during pre-processing: *v*

|← qe (r),v|← qe (r),v|← qe ,v|← qe. Reject if|||
|---|---|---|---|---|---|
|l l|r r l A|o o r B|c c o C|m A|B c|

*c ̸*= *e ·* (*v · v* + *v · v* + *v · v* + *v · v · v* + *v*)*.*

6. *V ↔ P* : Apply the core Shout PIOP with addresses from the preprocessing phase (addr*A,*addr

|, addr|) to validate claims v|,v ,v. That is, for M ∈{A,B,C}, apply the sum-check|||
|---|---|---|---|---|
|B C||A B C|||
||||d||
|M||||M,i i|
|k=(k|,...,k)∈ {0,1}|, j∈{0,1}|i=1||
 protocol to confirm that:
! X Y *v* = eqe (*r,j*) addr g (*k,j*) *· z*e(*k*)*.* (81)

1 *d* (log(*K*)*/d*) *d* log *T*

This is equivalent to the Shout read-checking sum-check (Equation (30)) to check the claim that *v* *M*= *z*e*M*(*r*) where *z*e*M*is the MLE of the purported read values (denoted rve in Equation (30)), *z*e is the MLE of the lookup table (denoted Val f in Equation (30)), and addr g*M,*1*,...,* addr g*M,d*together represent the *d*-dimensional one-hot encoding of the addresses (denoted rae₁*,...,* rae*d*in Equation (30)).

Figure 10: The description of SpeedySpartan PIOP. Let *d* denote the parameter chosen for Shout.

At the end of this invocation of the sum-check protocol, the verifier has to evaluate *z*e*A*(*r*), *z*e*B*(*r*) and *z*f*C*(*r*), where *r ∈* F *s* is a random point chosen over the course of the sum-check protocol. Hence, the invocation of the sum-check protocol reduced the task of checking that *z* satisfies the constraint system, to the task of evaluating the multilinear extensions of *zA*, *zB*, and *zC*each at a random point *r ∈* F *s*.

Recall that by design, each row of *A,B,C* has a single non-zero entry (i.e., viewing *z* as a lookup table, each row of *A*, *B*, and *C* is the one-hot encoding of some address of *z*). So, we invoke the Shout protocol to prove the desired evaluations of *z*e*A, z*e*B*, and *z*f*C*at *r*. In more detail, by using the Shout read-checking sum-check (Equation (30)), the prover reduces the claims about *z*e*A*(*r*)*, z*e*B*(*r*), and *z*f*C*(*r*) into evaluations claims about the lookup table *z*e and polynomials committed in the preprocessing phase. 35 The prover then proves the evaluations of these committed polynomials using a polynomial evaluation argument.

Note that multiple invocations of the sum-check protocol and polynomial evaluation arguments, arising from running Shout for each of *z*e*A, z*e*B, z*f*C*, can be batched together using standard techniques (see Sections 4.2.1 and 3.1.1 for details).

9.2.2 The special case of arithmetic circuit satisfiability Arithmetic circuit satisfiability trivially reduces to the following special case of Plonkish:
*f* (*x*) = (1 *− q*e*m*(*x*)) *·* (*z*e*A*(*x*) + *z*e*B*(*x*)) + *q*e*m*(*x*) *· z*e*A*(*x*) *· z*e*B*(*x*) (83)

Here, *qm*(*x*) = 1 if gate *x* is a multiplication gate, and equals 0 otherwise. For simplicity and ease of comparing to prior works, we focus on this special case when assessing the costs of SpeedySpartan

9.2.3 SpeedySpartan: Analysis of costs Polynomial evaluation proofs and the choice of commitment scheme. SpeedySpartan’s speedups relative to prior work are largest when polynomial evaluation proofs are not a major contributor to prover time. There are several reasons this could be the case. One is that SpeedySpartan can be instantiated with a commitment scheme that comes with very fast evaluation proofs. Another, discussed in Section 3.1.1, is that in applications where many different instances of (one or more) constraint systems arise, folding techniques can ensure only a single evaluation proof needs to be produced across all instances. We now discuss attractive choices of polynomial commitment schemes that lead to fast SpeedySpartan prover even in settings that are not amenable to folding techniques. Commitment schemes with fast evaluation proof computation. For fast evaluation proof computa- tion, the most extreme choice is Hyrax [WTS
+ 18]. In Hyrax, the prover simply performs a linear number of field multiplications, which are required anyway to compute the requested evaluation. Moreover, if the committed polynomial is sparse (as is the case in SpeedySpartan), the Hyrax prover’s field work grows linearly with the sparsity of the polynomial (i.e., the number of non-zeros). More precisely, if *M* out of *N* entries of the *√* committed vector are non-zero, the Hyrax prover’s work during evaluation proof computation is *N* + *O*( *M*) field multiplications.

This is a perfect fit to ensure a very fast SpeedySpartan prover. On top of this, Hyrax is transparent and has sublinear (square-root) size commitment key. The downside of Hyrax is that its commitment size and *√* evaluation proof size are fairly large: they are each *N* field and group elements where *N* is the size of the committed polynomial. In summary, Hyrax is an attractive choice for SpeedySpartan when prover time is a top priority and sublinear-but-large verifier costs are acceptable.

Another commitment scheme with fast evaluation proof computation is Dory [Lee21]. Indeed, Dory can be seen as a refinement of both Hyrax and Bulletproofs/IPA [BBB + 18, BCC + 16], and inherits the fast evaluation proofs from Hyrax. 36 Dory evaluation proofs entail the same field work as in Hyrax evaluation proof computation, plus some extra cryptographic work that is asymptotically sublinear. This cryptographic work 35More precisely, if *z* = (*w, x*) for a public vector *x*, then the prover commits to *w*e, and *z*e(*r*) can be evaluated efficiently with one evaluation query to *w*e. See [Set20, STW23] for details. *√* 36Essentially, the Dory committer uses pairings to *commit to a Hyrax commitment*, thereby obviating the *n* commitment size of Hyrax. For evaluation proofs, the Dory prover uses a protocol reminiscent of Bulletproofs/IPA to succinctly prove that it

(a) knows a Hyrax commitment that opens the Dory commitment and (b) knows a valid Hyrax evaluation proof. *√*
It thereby obviates the *n* evaluation proof size of Hyrax.

*√* consists of roughly 16 *√* *N* scalar multiplications in G₁ or G₂ of a pairing-friendly group, and 6 multi-pairings of size *N/*2 *i* for each *i* = 1*,...,* log*N*.

Because pairings are concretely expensive (one pairing is equivalent in cost to about 4000 group operations), these evaluation proofs can be the concrete prover bottleneck (i.e., more expensive than committing or sum- check-proving in SpeedySpartan) unless *N* is not too small. This effect is somewhat amplified in SpeedySpartan, become some polynomials arising in the protocol (which are committed in pre-processing) are of slightly superlinear size *m · n¹* */d*. These polynomials have only *m* non-zero coefficients, *√* so they do not require superlinear time to commit to even in pre-processing, but this does mean that the *O*( *√*

<u>N</u>) cryptographic costs *√*
arising in Dory evaluation proof computation apply with *N* = *m · n¹* */d*. So while *O*( *N*) = *O*( *m · n¹* */*2*d* ) is still sub-linear in *m* and *n* (and hence evaluation proof computation is asymptotically a low-order prover cost), it can be a concrete SpeedySpartan prover bottleneck if the circuit is small *and* the parameter *d* is small. If this is the case, per Section 3.1.1 one can always further lower the cost of Dory evaluation proof computation by a factor of log*T* with a constant-factor increase in verifier costs, by increasing the commitment size from one target group element to log*T* group elements.

Calculations with our analytic cost model (Section 3.1.2) show that Dory evaluation proofs represent a small fraction of total prover time (at most 30%) so long as *m* and *n* are at least 2 26 and *d ≥* 3.

Challenges with HyperKZG or Bulletproofs. HyperKZG [ZSC24] and Bulletproofs/IPA [BCC + 16, BBB + 18] have expensive evaluation proof computation, as evaluation proofs require the prover to commit to a linear number of random field elements. As discussed above, this issue is amplified in the context of SpeedySpartan because some committed polynomials have size *m · n¹* */d* (though they have sparsity only *m*). This means the commitment key size when using HyperKZG or Bulletproofs is slightly superlinear *m · n¹* */d*, and the evaluation proofs require committing to *O*(*m · n¹* */d* ) random field elements. On top of that, unlike Hyrax and Dory, the field work required to compute evaluation proofs grows with the size *m · n¹* */d* of the committed polynomial and not only its sparsity *m*. For these reasons, HyperKZG and Bulletproofs appear to be poor fits for SpeedySpartan.

Detailed costs for SpeedySpartan. As a running example throughout this section, we consider the case of *d* = 2 and Hyrax as the choice of polynomial commitment scheme. This leads to a very fast SpeedySpartan prover and achieves non-trivial verifier costs of *O*(*m¹* */*2 *n¹* */*4 ). In this running example, we set *m* = *n* = 2 24

for concreteness. We also assume that the entries of the witness vector *z* are all “small” (see Section 2.1) and hence fast to commit to. This is indeed the case in many applications (where the entries of *z* often represent bit or byte decompositions, or 32-bit values).

Size of proving key. When Hyrax (or Dory) is used in *√* SpeedySpartan, the (transparently generated) commitment key consists of *m · n¹/d*group elements. For example, if *m* = *n* = 2 24 and *d* = 2, this is only 2 18 group elements, translating to MBs of space.

Pre-processing. Pre-processing in SpeedySpartan requires committing to 3*dm* unit vectors each of length *n¹* */d*, plus 5 vectors of length *m*. With Hyrax, committing to the unit vectors requires *dm* group operations, while committing to the other 5 vectors (assuming they have small entries per Section 2.1) requires roughly 5*m* group operations.

Online phase prover costs. In SpeedySpartan, during the online phase, the prover only commits to the witness vector *z* and nothing else (more precisely, the prover commits to the MLE of its purported witness vector *w* of length *n − ℓ*). Thus, if the witness vector contains “small” field elements, then the prover only commits to small field elements.

Then the SpeedySpartan prover applies the sum-check protocol several times. Once is the Spartan sum-check, and the other is Shout’s read-checking sum-check, applied to twice in parallel (once for each matrix *A* and

*B*). The Spartan sum-check can be implemented with 9*m* field multiplications. This is the cost of the standard linear-time sum-check proving algorithm (Section 3.3) combined with optimizations of Dao and Thaler [DT24] and Gruen [Gru24] (see Section 3.6.1). As a modest additional optimization, we also exploit

Plonk Plonk BabySpartan SpeedySpartan SpeedySpartan (small proof) (fast prover) (*d* = 2) (*d* = 3)

|Committed field elements|8 m random|6 m random|3 m + n small|n small|n small|
|---|---|---|---|---|---|
|(excluding pre-processing)|3 m small|3 m small||||
|Field multiplications|54 m log m|54 m log m|33 m + 24 n|19 m + 8 n|29 m + 8 n|
|Total field multiplications (approximate)|54 m log m + 546|m 54 m log m + 414|m 51 m + 30 n|19 m + 14 n|29 m + 14 n|
||20|24|24|24|24|
|Total field multiplications|1842 · 2|1710 · 2|81 · 2|33 · 2|43 · 2|
||24|||||
|(for m = n = 2|)|||||

Figure 11: Prover costs for SpeedySpartan compared with two versions of Plonk [GWC19] and BabySpartan

when applied to arithmetic circuits of fan-in two (*n* is the total witness size and *m* is the number of constraints (i.e., *n − m* is the number of auxiliary, unconstrained inputs). For simplicity we assume *m* = *n* when stating Plonk’s costs. When translating committed field elements to field multiplications, we treat each small committed field element as costing one group operation, each random committed field element as costing 11 group operations, and each group operation as costing 6 field operations. See Section 3.1.2 for justification of these translations. The qualitative comparison between protocols is insensitive to these precise choices.

here that *qm*(*x*) *∈{*0*,*1*}* for all *x ∈{*0*,*1*}* log *m*. This ensures that binding the array storing *qm*evaluations produces only 2 *O*(*i*) distinct values in round *i*, which ensures that the prover only incurs 2 *O*(*i*) multiplications to bind the array in that round.

Per Theorem 6 with *T* = *m*, *m* = *n* and *d* = 3, both invocations of the Shout read-checking sum-check costs (*d²* + 2)*m*+ 4*n* + *o*(*m*) field operations. Of these, *m* field multiplications are devoted to the prover evaluating *z*e *A*(*r*) and *z*e*B*(*r*), which is already done over the course of the Spartan sum-check and accounted for in the costs reported there. So the actual cost of each of these three invocations is (*d²* + 1)*m* + 4*n* + *o*(*m*). For *d* = 2 and *m* = *n*, this simplifies to about 9*m* field multiplications per invocation of Shout, and hence 18*m* across both invocations.

In total, the SpeedySpartan prover performs 25*m* field multiplications across all invocations of the sum-check protocol.

The SpeedySpartan prover must also provide an evaluation for each committed polynomial. Per the discussion in Section 9.2.3, we focus on settings where this is not a significant contributor to prover time.

Verifier costs. The proof size is *O*(*d*log(*n* + *m*)) field elements, plus the polynomial evaluation proof provided for each committed polynomial. If desired, standard techniques can batch these evaluation proofs at minimal cost to the prover, ensuring that only a single evaluation proof is provided and verified (see for example [GLH + 24, Section 5]). The verifier’s runtime is *O*(*d*log(*n* + *m*)) field operations plus the cost of checking the polynomial evaluation proof(s).

9.2.4 Comparison of SpeedySpartan with Plonk and BabySpartan
Figure 11 reports quantitative prover costs for Plonk, BabySpartan, and SpeedySpartan. The reported costs
 apply when these protocols are combined with any elliptic-curve commitment scheme like Hyrax and Dory. The reported costs also apply to HyperKZG and Bulletproofs/IPA, but these commitment schemes are poor fits for SpeedySpartan due to high evaluation proof computation time and commitment key size (§9.2.3). We use the reported costs from Plonk [GWC19]. We omit other natural baselines such as HyperPlonk [CBBZ23] as BabySpartan is strictly faster than these baselines. For all schemes, we ignore the cost of evaluation proof computation. This is justified for SpeedySpartan by the discussion above (i.e., we are focused either on choices of commitment schemes for which this is not a significant prover cost, or settings where this cost is insignificant for other reasons). The comparison can be summarized as follows. With *d* = 2, SpeedySpartan improves over the field multi- plications performed by the Plonk prover by roughly 50*×*, and improves the commitment costs by about *×*. For commitment costs, the large improvement comes both because SpeedySpartan commits to about 9*×*

fewer field elements than Plonk, and because all of the values committed by the SpeedySpartan prover are small, while 2*/*3 of the values committed by the Plonk prover are random (recall from Sections 2.1 and 3.1.2 that random values take an order of magnitude more time to commit to than small ones). SpeedySpartan with *d* = 2 improves over the commitment cost of BabySpartan by about 4*×*, and over the field work of BabySpartan by about 2*×*.

With *d* = 3, the field work of SpeedySpartan increases about 30% relative to *d* = 2, and the online commitment costs remain the same. The reason to consider higher values of *d* is that commitment key size, evaluation proof size, evaluation proof computation time (in the case of Dory), and pre-processing time all decrease as *d* grows.

9.2.5 Obtaining a folding scheme from SpeedySpartan Like how an “early stopping” (Super)Spartan leads to HyperNova [KS24a], SpeedySpartan leads to a folding scheme for Plonkish with attractive characteristics: the folding scheme can fold multiple Plonkish instances defined with respect to Plonkish constraint systems that do *not* necessarily share the same circuit structure. Compared to a naive solution that achieves this property, a SpeedySpartan-based solution has far better costs. In fact, the costs are similar to HyperNova: the prover simply commits to its witness and incurs some field operations in the sum-check protocol. The verifier circuit size is logarithmic in the circuit sizes, which is similar to HyperNova’s. We leave it to the future work to improve the size of the verifier circuit with ideas from NeutronNova to use an early-stopping sum-check protocol [KS24b].
### 9.3 Details of Spartan++

9.3.1 Spark++: A faster commitment scheme for sparse polynomials Commitment phase. Let *p* be a *T*-sparse multilinear polynomial to be committed. This means *p* is a polynomial in *ℓ* variables, so *p* has size 2
*ℓ* ,but there are only *T* = *o*(2 *ℓ* ) values of *x ∈{*0*,*1*}* *ℓ* such that *p*(*x*) *̸*= 0. Let *S* = *{x ∈{*0*,*1*}* *ℓ* : *p*(*x*) *̸*= 0*}*. For simplicity, let us assume that *p*(*x*) *∈{*0*,*1*}* for all *x ∈{*0*,*1*}* *ℓ*; this is sufficient to give a SNARK for arithmetic circuits, and the below protocol easily extends (with some increased costs) to eliminate this assumption.

Consider a memory of size *K* = 2 *ℓ*. Associate each index of memory with an input *x ∈ {*0*,*1*}* *ℓ*. For parameter *d ≥* 1, the commitment to *p* is simple the *d*-dimensional one-hot encoding of each *x ∈ S*. That is, the commitment to *p* consists of *d* committed polynomials rae₁*,...,* rae*d*, where for each *j ∈{*0*,*1*}* log *T*, rae₁(*·,j*)*,...,* rae*d*(*·,j*) provides the *d*-dimensional one-hot encoding of the *j*’th element of *S*.

If the commitment were computed by an untrusted party, any verifier, before running the evaluation phase, would need to run the one-hot-encoding-checking PIOP (Figure 6) to ensure that the commitment to *p* is a valid list of *d*-dimensional one-hot encodings. However, in the context of Spartan++, the commitments to sparse polynomials *p* are all computed by an honest party and hence these checks can be omitted.

Evaluation phase. Suppose the verifier requests *p*(*r*). By multilinear Lagrange interpolation and the assumption that *p*(*x*) *∈{*0*,*1*}* for all *x ∈{*0*,*1*}* *ℓ*, we can write:

*d* ! X Y *p*(*r*) = rae*i*(*ki,j*) *·* eqe (*k,r*)*.* *k₁,...,kd∈{*0*,*1*}ℓ/d,j∈{*0*,*1*}*log *T i*=1

In other words, if we consider the lookup table of size *K* = 2 *ℓ* whose *k*’th entry (for *k ∈{*0*,*1*}* *ℓ* ) is eqe (*k,r*), and we consider *S* to be a list of *T* addresses for lookups into this table, then *p*(*r*) is simply X rve (*j*)*,* (84) *j∈{*0*,*1*}*log *T*

where rve is the MLE of the values returned by the lookups.

Based on Equation (84), to prove the correct value of *p*(*r*), the prover has two options. One is to apply the sum-check protocol to compute Expression (84), at the end of which the verifier has to evaluate rve (*r* *′* ) for a random *r* *′* *∈* F log *T*. The verifier can then accomplish this using Shout’s read-checking sum-check applied to the table above. The other option is to observe that Expression (84) equals *T ·* rve (2 *−*1 *,...,*2 *−*1 ) (this observation also arose surrounding Equation (26) in Section 4.1.2), and apply Shout’s read-checking sum-check to compute this particular evaluation of rve.

Note that the table to which Shout is applied above is MLE-structured. Indeed, for this table Val f (*k*) = eqe (*k,r*), which can clearly be evaluated at any point *k ∈* F *ℓ* in *O*(log*K*) = *O*(*ℓ*) time, via Equation (15).

Costs. Committing to the sparse polynomial *p* entails committing to *d* vectors, each with *T* 1s and *K¹* */d* 0s. The evaluation phase involves applying Shout to *T* lookups into a table of size *K* = 2 *ℓ*. This is a canonical table to which the sparse-dense sum-check protocol applies (Section 7.1), enabling the Shout prover to run in time *O*(*CT*) where *C* is such that *K≤T* *C*.

9.3.2 Details of Spartan++ Recall that Spartan++ is essentially just SuperSpartan, but with the Spark sparse polynomial commitment scheme replaced with Spark++. Here, we spell out the details. For ease of exposition, we focus on R1CS (a special case of CCS) and Spartan (a special case of SuperSpartan). A special case of R1CS capturing arithmetic circuits. In Spartan++ the prover only commits to the values (i.e., outputs) *w* of multiplication gates. If there are *M* multiplication gates, then *w ∈* F
*M*, and the prover begins the protocol by committing to the multilinear extension *w*e.

Let *z* = (*w,x*) *∈* F *n* where *x ∈* F *n−M* is public input. Ensuring that *w* indeed contains the correct value of every multiplication gate entails proving that *z* satisfies *M* rank-one constraints. Specifically, if *ai*and *bi*are the left and right inputs to multiplication gate *i*, then the *i*’th constraint is simply

#### ai· bi= wi.

Let us express this constraint system as *Az ◦ Bz* = *w* where *A* and *B* are appropriate matrices in F *M ×n*. Note that, unlike in SpeedySpartan, any particular row of *A* and *B* may have many non-zero entries (addition gates in the circuit lead to non-zero entries in *A* and *B*, but addition gates do not increase the number of rows). Further, notice that all of the non-zero entries of these matrices are equal to 1.

The Spartan++ protocol. In pre-processing, an honest party commits to *A*e and *B*e using Spark++.

In the online phase, as in Spartan, the prover first applies the standard zero-check PIOP (Section 3.6) to confirm that all constraints are satisfied. That is, letting *a* = *Az* and *b* = *Bz*, the verifier picks a random *r ∈* F log *M* and checks that X 0 = eqe (*r,x*) *·* e*a*(*x*) *·* e*b*(*x*) *− w*e(*x*)*.* (85) *x∈{*0*,*1*}*log *M*

At the end of the sum-check protocol, the verifier has to evaluate e*a*(*r* *′* ), e*b*(*r* *′* ), *w*e(*r* *′* ) and eqe (*r,r* *′* ) where *r* *′* *∈* F log *M* is the randomness chosen round-over-round during the sum-check protocol. The evaluation *w*e(*r* *′* ) can be obtained from the commitment to *w*e(*r* *′* ), and eqe (*r,r* *′* ) can be computed in *O*(log*M*) time. But e*a* and e *b* are not committed—they are effectively virtual polynomials. Hence, e*a*(*r* *′* ) and e*b*(*r* *′* ) are computed with an additional application of the sum-check protocol, applied to compute the right hand sides of the following two expressions for e*a*(*r* *′* ) and e*b*(*r* *′* ): X e*a*(*r* *′* ) = *A*e(*r* *′* *,j*) *· z*e(*j*)*,* *j∈{*0*,*1*}*log *n*

and X e *b*(*r* *′* ) = *B*e(*r* *′* *,j*) *· z*e(*j*)*.* *j∈{,}*log *n*

At the end of these two instances of sum-check (which can be run in parallel and batched per Section 4.2.1),

|′ ′′|′ ′′|′′|
|---|---|---|
|||′′|

the verifier needs to evaluate *A*e(*r,r*), *B*e(*r,r*) and *z*e(*r* *′′* ) where *r* denotes the randomness chosen over the course of the two parallel sum-check instances. The evaluation *z*e(*r*) can be obtained from the commitment to *z*e. The evaluations of *A*e and *B*e are obtained via Spark++.

Prover Costs. Assume for simplicity that *A* and *B* have the same number of non-zero entries and that this number is *T* (*T* is proportional to total number of gates in the circuit, counting both addition and multiplication gates).

Given the vectors *a* = *Az* and *b* = *Bz*, the first sum-check (to compute Expression (85)) costs 5*M* field operations (see [DT24] for full details), while the other two sum-check invocations (to compute e*a*(*r* *′* ) and e *b*(*r* *′* )) together cost *M* + 5*n* multiplications. In total this is 6*M* + 5*n* multiplications for the prover.

It remains to account for the prover cost of applying Shout. Shout is applied to perform 2*T* lookups into a table of size *M · n*, and this table is amenable to the sparse-dense sum-check protocol (Section 7.1). Hence, the cost is at most 2(*d²* + 4)*T* field multiplications for the prover.

The prover must also provide one evaluation of each committed polynomial rae*i*. If Hyrax is the commitment scheme used, this costs *T* field multiplications for the prover (and no cryptographic operations), with the field operations needed simply to compute the requested evaluations. If Dory is the commitment scheme p used, then additionally several multi-pairings and scalar multiplications all of size at most (*Mn*)1*/d· T* are also required (see Section 9.2.3 for details of what Dory evaluation proofs entail). Asymptotically this is a low-order cost relative to the linear field work required in Shout, though concretely it may be a prover bottleneck unless *d* is fairly large, say *d ≥* 4.

Most applications have a small number of public inputs, and hence *n ≈ m*. Then the above costs can be summarized as follows. Ignoring the (asymptotically low-order) costs of computing evaluation proofs, the Spartan++ prover commits only to the values of all *M* multiplication gates in the circuit, and performs the following number of field multiplications:

6*M* + 5*n* + 2(*d²* + 5)*T ≈* 11*M* + (2*d²* + 10)*T.*

For *d* = 4 this translates to about 42 field multiplications per addition gate and 53 per multiplication gate. This is concretely slower than SpeedySpartan (see Figure 11) though it is interesting that the Spartan++ prover’s commitment costs grow only with *M*, the number of multiplication gates.

Despite being slower than SpeedySpartan, Spartan++ is about 6*×* faster than Spartan itself. The cost analysis for Spartan underlying this comparison is as follows. Recall that Spartan applies Spark to *A*e and *B*e, and that Spark applies Lasso internally. In this application of Lasso, the prover commits to 2 random field elements per non-zero entry of *A* and *B*. This translates to about 22 group operations per non-zero, which is roughly equivalent to 22 *·* 6 = 132 field operations. On top of the commitment costs, the prover also performs 24 field operations within Lasso. So this yields 156 field operations per non-zero matrix entry. Since there are 2*T* non-zeros between the two matrices, this is about 312*T* field operations in total to implement Lasso-within-Spark-within-Spartan. This is about 6*×* the prover cost of Spartan++ with *d* = 4.

Disclosures. Justin Thaler is a Research Partner at a16z crypto and is an investor in various blockchain- based platforms, as well as in the crypto ecosystem more broadly (for general a16z disclosures, see https: //www.a16z.com/disclosures/.)

## References

[AB09] Sanjeev Arora and Boaz Barak. *Computational complexity: a modern approach*. Cambridge University Press, 2009.

[And17] Andrew Waterman1, Krste Asanovic. The RISC-V instruction set manual. [https://riscv](https://riscv). org/wp-content/uploads/2017/05/riscv-spec-v2.2.pdf, 2017.

[AS24] Arasu Arun and Srinath Setty. Nebula: Efficient read-write memory and switchboard circuits for folding schemes. Cryptology ePrint Archive, 2024.

[AST24] Arasu Arun, Srinath Setty, and Justin Thaler. Jolt: Snarks for virtual machines via lookups. In *Proceedings of the International Conference on the Theory and Applications of Cryptographic* *Techniques (EUROCRYPT)*, 2024.

[AW09] Scott Aaronson and Avi Wigderson. Algebrization: A new barrier in complexity theory. *ACM* *Transactions on Computation Theory (TOCT)*, 1(1):1–54, 2009.

[BBB + 18] Benedikt B¨unz, Jonathan Bootle, Dan Boneh, Andrew Poelstra, Pieter Wuille, and Greg Maxwell. Bulletproofs: Short proofs for confidential transactions and more. In *Proceedings of the IEEE* *Symposium on Security and Privacy (S&P)*, 2018.

[BBHR18] Eli Ben-Sasson, Iddo Bentov, Yinon Horesh, and Michael Riabzev. Fast Reed-Solomon interactive oracle proofs of proximity. In *Proceedings of the International Colloquium on Automata, Languages* *and Programming (ICALP)*, 2018.

[BC24] Benedikt B¨unz and Jessica Chen. Proofs for deep thought: Accumulation for large memories and deterministic computations. In *International Conference on the Theory and Application of* *Cryptology and Information Security (Asiacrypt)*, pages 269–301. Springer, 2024.

[BCC + 16] Jonathan Bootle, Andrea Cerulli, Pyrros Chaidos, Jens Groth, and Christophe Petit. Efficient zero-knowledge arguments for arithmetic circuits in the discrete log setting. In *Proceedings* *of the International Conference on the Theory and Applications of Cryptographic Techniques* *(EUROCRYPT)*, 2016.

[BCF + 24] Martijn Brehm, Binyi Chen, Ben Fisch, Nicolas Resch, Ron D Rothblum, and Hadas Zeilberger. Blaze: Fast SNARKs from interleaved RAA codes. Cryptology ePrint Archive, 2024.

[BCG + 18] Jonathan Bootle, Andrea Cerulli, Jens Groth, Sune Jakobsen, and Mary Maller. Arya: Nearly linear-time zero-knowledge proofs for correct program execution. In *Proceedings of the Inter-* *national Conference on the Theory and Application of Cryptology and Information Security* *(ASIACRYPT)*, 2018.

[BCGT13] Eli Ben-Sasson, Alessandro Chiesa, Daniel Genkin, and Eran Tromer. Fast reductions from RAMs to delegatable succinct constraint satisfaction problems: Extended abstract. In *Proceedings of* *the Innovations in Theoretical Computer Science (ITCS)*, 2013.

[BEG + 91] Manuel Blum, Will Evans, Peter Gemmell, Sampath Kannan, and Moni Naor. Checking the correctness of memories. In *Proceedings of the IEEE Symposium on Foundations of Computer* *Science (FOCS)*, 1991. Journal version in Algorithmica, 199.

[BFS20] Benedikt B¨unz, Ben Fisch, and Alan Szepieniec. Transparent SNARKs from DARK compilers. In *Proceedings of the International Conference on the Theory and Applications of Cryptographic* *Techniques (EUROCRYPT)*, 2020.

[BSCG + 13]Eli Ben-Sasson, Alessandro Chiesa, Daniel Genkin, Eran Tromer, and Madars Virza. SNARKs for C: Verifying program executions succinctly and in zero knowledge. In *Proceedings of the* *International Cryptology Conference (CRYPTO)*, August 2013.

[CBBZ23] Binyi Chen, Benedikt B¨unz, Dan Boneh, and Zhenfei Zhang. HyperPlonk: Plonk with linear-time prover and high-degree custom gates. In *Proceedings of the International Conference on the* *Theory and Applications of Cryptographic Techniques (EUROCRYPT)*, 2023.

[COS20]

[CTY11]

[DP23]

[DP24]

[DT24]

[EFG22]

[EHB22]

[FS86a]

[FS86b]

[GKR15]

[GLH + 24]

[GM24]

[GPR21]

[Gru24]

[GW20a]

[GW20b]

[GWC19]

[Hab22]

[KS24a]

Alessandro Chiesa, Dev Ojha, and Nicholas Spooner. Fractal: Post-quantum and transparent recursive proofs from holography. In *Proceedings of the International Conference on the Theory* *and Applications of Cryptographic Techniques (EUROCRYPT)*, 2020.

Graham Cormode, Justin Thaler, and Ke Yi. Verifying computations with streaming interactive proofs. *Proc. VLDB Endow.*, 5(1):25–36, 2011.

Benjamin E. Diamond and Jim Posen. Succinct arguments over towers of binary fields. Cryptology ePrint Archive, Paper 2023/1784, 2023. [https://eprint.iacr.org/2023/1784](https://eprint.iacr.org/2023/1784).

Benjamin E Diamond and Jim Posen. Polylogarithmic proofs for multilinears over binary towers. Cryptology ePrint Archive, 2024.

Quang Dao and Justin Thaler. More optimizations to sum-check proving. Cryptology ePrint Archive, Paper 2024/1210, 2024.

Liam Eagen, Dario Fiore, and Ariel Gabizon. cq: Cached quotients for fast lookups. Cryptology ePrint Archive, 2022.

Youssef El Housni and Gautam Botrel. EdMSM: multi-scalar-multiplication for SNARKs and faster montgomery multiplication. *Cryptology ePrint Archive*, 2022.

Amos Fiat and Adi Shamir. How to prove yourself: Practical solutions to identification and signature problems. In *Conference on the theory and application of cryptographic techniques*, pages 186–194. Springer, 1986.

Amos Fiat and Adi Shamir. How to prove yourself: Practical solutions to identification and signature problems. In *Proceedings of the International Cryptology Conference (CRYPTO)*, pages 186–194, 1986.

Shafi Goldwasser, Yael Tauman Kalai, and Guy N Rothblum. Delegating computation: interactive proofs for muggles. *Journal of the ACM (JACM)*, 62(4):1–64, 2015.

Yanpei Guo, Xuanming Liu, Kexi Huang, Wenjie Qu, Tianyang Tao, and Jiaheng Zhang. Deepfold: Efficient multilinear polynomial commitment from reed-solomon code and its application to zero-knowledge proofs. Cryptology ePrint Archive, 2024.

Albert Garreta and Ignacio Manzur. FLI: Folding lookup instances. Cryptology ePrint Archive, Paper 2024/1531, 2024.

Lior Goldberg, Shahar Papini, and Michael Riabzev. Cairo–a turing-complete stark-friendly cpu architecture. Cryptology ePrint Archive, 2021.

Angus Gruen. Some improvements for the piop for zerocheck. Cryptology ePrint Archive, 2024.

Ariel Gabizon and Zachary Williamson. Proposal: The TurboPlonk program syntax for specifying SNARK programs, 2020.

Ariel Gabizon and Zachary J Williamson. plookup: A simplified polynomial protocol for lookup tables. Cryptology ePrint Archive, 2020.

Ariel Gabizon, Zachary J. Williamson, and Oana Ciobotaru. PLONK: Permutations over Lagrange-bases for oecumenical noninteractive arguments of knowledge. ePrint Report 2019/953,

2019. Ulrich Hab¨ock. Multivariate lookups based on logarithmic derivatives. Cryptology ePrint Archive, Paper 2022/1530, 2022. Abhiram Kothapalli and Srinath Setty. HyperNova: Recursive arguments for customizable constraint systems. In *Annual International Cryptology Conference*, pages 345–379, 2024.
[Dor24]Daniel Dore. TaSSLE: Lasso for the commitment-phobic. Cryptology ePrint Archive, 2024.

[KS24b]

[KST22]

[KT23]

[KZG10]

[Lee21]

[LFKN90]

[Lip89]

[Lip90]

[Mon85]

[MvOV01]

[OLB24]

[PH23]

[PK22]

[Rob91]

[Rot24]

[SAGL18]

[Set20]

[SL20]

[SSS22]

Abhiram Kothapalli and Srinath Setty. NeutronNova: Folding everything that reduces to zero-check. Cryptology ePrint Archive, 2024.

Abhiram Kothapalli, Srinath Setty, and Ioanna Tzialla. Nova: Recursive Zero-Knowledge Arguments from Folding Schemes. In *Proceedings of the International Cryptology Conference* *(CRYPTO)*, 2022.

Tohru Kohrita and Patrick Towa. Zeromorph: Zero-knowledge multilinear-evaluation proofs from homomorphic univariate commitments. Cryptology ePrint Archive, 2023.

Aniket Kate, Gregory M. Zaverucha, and Ian Goldberg. Constant-size commitments to polyno- mials and their applications. In *Proceedings of the International Conference on the Theory and* *Application of Cryptology and Information Security (ASIACRYPT)*, pages 177–194, 2010.

Jonathan Lee. Dory: Efficient, transparent arguments for generalised inner products and polynomial commitments. In *Theory of Cryptography Conference*, pages 1–34. Springer, 2021.

Carsten Lund, Lance Fortnow, Howard Karloff, and Noam Nisan. Algebraic methods for interactive proof systems. In *Proceedings of the IEEE Symposium on Foundations of Computer* *Science (FOCS)*, October 1990.

Richard J Lipton. *Fingerprinting sets*. Princeton University, Department of Computer Science,

1989. Richard J Lipton. Efficient checking of computations. In *Annual Symposium on Theoretical* *Aspects of Computer Science*, pages 207–215. Springer, 1990. Peter L Montgomery. Modular multiplication without trial division. *Mathematics of computation*, 44(170):519–521, 1985. Alfred J. Menezes, Paul C. van Oorschot, and Scott A. Vanstone. *Handbook of Applied Cryptog-* *raphy*. CRC Press, 2001. Alex Ozdemir, Evan Laufer, and Dan Boneh. Volatile and persistent memory for zkSNARKs via algebraic interactive proofs. Cryptology ePrint Archive, Paper 2024/979, 2024. Shahar Papini and Ulrich Hab¨ock. Improving logarithmic derivative lookups using GKR. Cryptology ePrint Archive, 2023. Jim Posen and Assimakis A Kattis. Caulk+: Table-independent lookup arguments. Cryptology ePrint Archive, 2022. John Michael Robson. An o (t log t) reduction from ram computations to satisfiability. *Theoretical* *Computer Science*, 82(1):141–149, 1991. Ron D. Rothblum. A note on efficient computation of the multilinear extension. Cryptology ePrint Archive, Paper 2024/1103, 2024. Srinath Setty, Sebastian Angel, Trinabh Gupta, and Jonathan Lee. Proving the correct execution of concurrent services in zero-knowledge. In *Proceedings of the USENIX Symposium on Operating* *Systems Design and Implementation (OSDI)*, October 2018. Srinath Setty. Spartan: Efficient and general-purpose zkSNARKs without trusted setup. In *Proceedings of the International Cryptology Conference (CRYPTO)*, 2020. Srinath Setty and Jonathan Lee. Quarks: Quadruple-efficient transparent zkSNARKs. Cryptology ePrint Archive, Report 2020/1275, 2020. Robin Salen, Vijaykumar Singh, and Vladimir Soukharev. Security analysis of elliptic curves over sextic extension of small prime fields. Cryptology ePrint Archive, 2022.
[NT25]Vineet Nair and Justin Thaler. Proving CPU executions in small space. 2025.

[ST23] Srinath Setty and Justin Thaler. BabySpartan: Lasso-based SNARK for non-uniform computa- tion. Cryptology ePrint Archive, 2023.

[STW23] Srinath Setty, Justin Thaler, and Riad Wahby. Customizable constraint systems for succinct arguments. Cryptology ePrint Archive, 2023.

[STW24] Srinath Setty, Justin Thaler, and Riad Wahby. Unlocking the lookup singularity with Lasso. Proceedings of the International Conference on the Theory and Applications of Cryptographic Techniques (EUROCRYPT), 2024.

[Tea22]Polygon Zero Team. Plonky2: Fast recursive arguments with PLONK and FRI, 2022.

[Tha13] Justin Thaler. Time-optimal interactive proofs for circuit evaluation. In *Proceedings of the* *International Cryptology Conference (CRYPTO)*, 2013.

[Tha22] Justin Thaler. Proofs, arguments, and zero-knowledge. *Foundations and Trends in Privacy and* *Security*, 4(2–4):117–660, 2022.

[VSBW13] Victor Vu, Srinath Setty, Andrew J. Blumberg, and Michael Walfish. A hybrid architecture for verifiable computation. In *Proceedings of the IEEE Symposium on Security and Privacy (S&P)*,

2013.
[WSR + 15] Riad S. Wahby, Srinath Setty, Zuocheng Ren, Andrew J. Blumberg, and Michael Walfish. Efficient RAM and control flow in verifiable outsourced computation. In *Proceedings of the Network and* *Distributed System Security Symposium (NDSS)*, 2015.

[WTS + 18] Riad S. Wahby, Ioanna Tzialla, Abhi Shelat, Justin Thaler, and Michael Walfish. Doubly-efficient zkSNARKs without trusted setup. In *Proceedings of the IEEE Symposium on Security and* *Privacy (S&P)*, 2018.

[YH23] Yibin Yang and David Heath. Two shuffles make a RAM: Improved constant overhead zero knowledge RAM. Cryptology ePrint Archive, Paper 2023/1115, 2023.

[ZBK + 22] Arantxa Zapico, Vitalik Buterin, Dmitry Khovratovich, Mary Maller, Anca Nitulescu, and Mark Simkin. Caulk: Lookup arguments in sublinear time. Cryptology ePrint Archive, 2022.

[ZGK + 18] Yupeng Zhang, Daniel Genkin, Jonathan Katz, Dimitrios Papadopoulos, and Charalampos Papamanthou. vRAM: Faster verifiable RAM with program-independent preprocessing. In *Proceedings of the IEEE Symposium on Security and Privacy (S&P)*, 2018.

[ZGK + 22] Arantxa Zapico, Ariel Gabizon, Dmitry Khovratovich, Mary Maller, and Carla R`afols. Baloo: Nearly optimal lookup arguments. Cryptology ePrint Archive, 2022.

[ZSC24] Jiaxing Zhao, Srinath Setty, and Weidong Cui. MicroNova: Folding-based arguments with efficient (on-chain) verification. Cryptology ePrint Archive, Paper 2024/2099, 2024.

## A Overview of offline memory-checking protocols

Read/write memories. For read/write memories, there are two high-level approaches. In the first approach, which we refer to as *reordering-based approach*. the prover commits to a *re-ordering* of the memory operations (both reads and writes) such that they are grouped by which memory cell is accessed, and ordered by timestep (i.e., cycle) within each group. Confirming that this “second” committed vector of memory operations is indeed a reordering of the first amounts to a permutation check. It must be proved that within each group the memory operations are indeed ordered by timestep. Given this ordering, it is then relatively straightforward to prove that each write to that cell returns the value most recently written to that cell. This approach was first implemented in [BSCG + 13, WSR + 15], but dates back to the much older work [Rob91, BCGT13]. For proving a permutation check, these old works employ a permutation network (a technique originally motivated by non-interactivity requirements of the PCP model). The approach was refined in vRAM [ZGK + 18] with the use of interaction to use fingerprinting techniques [Lip89, Lip90] (see

Section 2.3) rather than a permutation network. See also a recent work by Ozdemir et al. [OLB24] that uses the reordering-based approach.

The second approach, which we refer to as “reordering-free approach”, was first implemented and made practical by Spice [SAGL18], building on the older work of Blum et al. [BEG + 91]. Spartan [Set20] refined this approach to use fingerprinting-based multiset equality check, and employed it for proving sparse polynomial evaluations. This approach is further refined in Jolt [AST24], to use lookup arguments for establishing timestamp checks in the memory checking algorithm. Recently, Yang and Heath [YH23] describe an approach that is essentially the same as Spice’s for proving memory operations.

In this approach, the prover does not reorder the memory operations, but commits to some extra data for each read and write to memory. Specifically, each cell is augmented to store not only a value but a timestamp, which is returned with each read and updated with each write. Also, each read to memory is followed by a “dummy write” operation that writes the returned value back to the same cell with the timestamp updated. Similarly, each write operation is preceded by a “dummy read” operation to that cell. The point of having the prover commit to this extra data (timestamps, dummy reads, and dummy writes) is that it ensures the set of “read tuples” (i.e., address, value, timestamp triples) returned by all read operations is a permutation of the set of all “write tuples” if and only if the value returned by every read operation is indeed the value most recently written to that cell.

At least as implemented in Jolt, the way that timestamps are computed on write operations in Spice necessitates range-checking two values. Specifically, Spice maintains a *global timestamp* gt. At the end of cycle *i*, gt is set to *i*. Here, we use the term cycle to refer to one read operation followed by one write operation, where one of the two operations is a “dummy” operation as described above.

In Spice, when a read operation returns a value along with timestamp *t*, the associated write operation (if the prover is honest) uses timestamp *t* *′* = max*{t* + 1*,*gt + 1*}*. Intuitively, the point of using this timestamp update procedure is to prevent “time travel attacks”, where a cheating prover returns on an early read a value that will only be written in the future to that cell, and returns on a later read a value that was written in the distant past to that cell. The timestamp update procedure in Spice forces the timestamps to increase monotonically as the cycles proceed, preventing this attack.

If the prover is honest, the timestamp *t* returned by a read operation at cycle *i* is always less than or equal to gt = *i −* 1, and under this guarantee, the prescribed write timestamp *t* *′* simply equals gt + 1. To ensure that *t* is indeed less than or equal to gt, Jolt confirms that both *t* itself and gt *− t* are in the range *{*0*,...,T −* 1*}*, where *T* is (an upper bound on) the total number of cycles that the zkVM is run for.

These “read-timestamp range checks” are implemented in Jolt by applying the Lasso lookup argument [STW24] to the table *{*0*,...,T −* 1*}*. In this application of Lasso, the prover commits to two small values per lookup, and hence four small values total. These four values also contribute one factor each (so four factors in total) to a grand product that must be proved within the invocation of Lasso.

Read-only memories and lookup arguments. Lookup arguments refer to protocols that allow a prover to prove that every value in one vector *v* is present in some position in another vector called a lookup table *t*. The verifier in this protocol holds commitments to both *v* and *t* (or, in many cases, *t* is sufficiently structured that no commitment to it is needed).

While lookup arguments as typically formulated do not care about the position of the entries in the lookup table, Lasso [STW24] introduced a generalization of lookup arguments, called *indexed lookups*, where there is an additional committed vector *a*, and the prover must prove that *∀i ∈* [*|v|*], *v*[*i*] = *t*[*a*[*i*]]. For ease of reference, we refer to traditional lookup arguments as unindexed lookup arguments. Note that indexed lookup arguments trivially provide unindexed lookup arguments by having the prover provide a commitment to the vector *a* as its first message. There are also transformations from unindexed lookup arguments to indexed lookup arguments (see [STW24] for details). Indexed lookup arguments are equivalent to memory-checking arguments for read-only memory.

There are many lookup arguments in the literature [BCG + 18, GW20b, ZBK + 22, PK22, ZGK + 22, EFG22, Hab22, STW24, PH23], and they all rely on fingerprinting techniques described in Section 2.3 to prove that

the lookup relation holds. We now provide details on some of these works.

Among these, Lasso [STW24] directly builds on the reordering-free read-write memory approach, specifically it generalizes the approach in Spartan [Set20], which itself was specialized from the read/write memories in Spice [SAGL18]. Since the values are only read and never written, some simplifications are possible compared to the read/write setting solved in Spice: there is no need to perform range checks on timestamps, they can be simply incremented by 1.

The first explicit (unindexed) lookup argument was given in Arya [BCG + 18]. In Arya, the prover commits to the binary representation of address *multiplicities*, i.e., the number of times each address is read. The prover then proves that looked-up values are a permutation of the vector in which each table element is repeated a number of times equal to its (committed) multiplicity. The approach in Plookup [GW20b] can be viewed as similar to the reordering-based read-write memory in vRAM, with some simplifications arising from the unindexed lookup argument setting. In particular, in Plookup, the prover commits to a sorting of the table entries and looked-up values. The approach in LogUp [Hab22] is similar to plookup [GW20b] except that it changes the fingerprinting strategy: while plookup uses a grand product, LogUp uses a grand sum of inverses.

A key insight of Lasso [STW24] is that the use of sum-check-based layered grand product arguments [Tha13] avoids the need to commit to random field elements, resulting in large prover speedups. Inspired by this, LogUpGKR [PH23] employs a sum-check-based layered grand sum argument to improve the prover efficiency of LogUp. LogUpGKR can also be viewed as a refinement of the original lookup argument, Arya, in that the LogUpGKR prover commits only to the multiplicities of each address (unlike Arya, in LogUpGKR, these multiplicities are each specified via a single field element rather than via its binary representation).

Separately, a line of work starting with Caulk and culminating in cq [ZBK + 22, PK22, ZGK + 22, EFG22], seeks lookup arguments in which an expensive pre-processing phase is performed (requiring, e.g., a number of scalar multiplications that is quasilinear in table size) after which *m* lookups can be answered in time that depends only on *m* and not on table size. However, these solutions are concretely expensive (e.g., cq requires the prover to commit to seven random field elements per lookup).

## B Details of the Val

## f -evaluation sum-check prover

### B.1 Computing the Less-Than evaluation table

In the Val f -evaluation sum-check in Twist (Figure 9), the prover needs to compute LT f(*j* *′* *,r*) for all *j* *′* *∈{*0*,*1*}* log *T*

for *r* = *r*cycle*∈* F log *T*. Here, LT f is the multilinear extension of the LT(*x,y*) function defined in Section 3.2, which indicates whether or not *x* is the binary representation of an integer that is strictly less than (the integer with binary representation given by) *y*.

We explain here how the prover can do this with only *T* field multiplications. We use simple, explicit expressions for LT f given in [STW24].

Let *x* = (*x₁,...,x*log *T*) and *y* = (*y₁,...,y*log *T*). If *x* and *y* are binary representations of integers between 0
and *T −* 1, we think of *x*log *T*and *y*log *T*as the “low-order bit” of the two binary representations, and *x₁* and *y₁* as the high order bit.

For *i* = 2*,...,* log*T*, let *x*). Define

||= (x|,...,x|) and x|= (x|,...,x|
|---|---|---|---|---|---|
||>i|i+1 i|log T|≥i i i|i log T >i >i|
|||||log T||
|||||i||
|||||i=1||
|i||||||
|i||||||

LT f (*x,y*) = (1 *− x*) *· y ·* eqe (*x,y*)*.* (86)

It is easy to see that X LT f(*x,y*) = LT f (*x,y*)*.* (87)

Note that LT does not depend on the first (i.e., low-order) *i −* 1 bits of *x*. Accordingly, while Equation (86) expresses LT as a function of all log*T* bits of *x* and *y*, we can equivalently think of LT*i*as a function only of the last log(*T*) *−* (*i −* 1) bits of *x* and *y*. We will follow this convention henceforth.

Suppose the prover has already computed a table *Ei*defined as follows:

*Ei*stores all *T/*2 *i* evaluations of eqe (*j>i* *′* *,r>i*) as *j>i* *′* ranges over *{*0*,*1*}* log(*T*)*−i*

*.* (88)
Suppose further that the prover has also already computed a table *Di*of size *T/*2 *i−*1 such that for all *x ∈{*0*,*1*}* log(*T*)*−*(*i−*1), log X *T* *Di*[*x*] = LT f*ℓ*(*x,r≥ℓ*)*.* (89) *ℓ*=*i*

Via standard observations [VSBW13] (see Lemma 1), the tables *E*log(*T*)*−*1*,...,E₁* can all be computed with *T/*2 field multiplications in total. Furthermore, given table *Ei*, the table *Di*(which recall has size 2 *· T/*2 *i* ) can be computed with just *T/*2 *i* field multiplications. To see this, observe that the following holds.

Let *x* = (*xi,...,x*log *T*) *∈{*0*,*1*}* log(*T*)*−*(*i−*1) and let *x>i*= (*xi*+1*,...,x*log *T*). Then:

- If *xi*= 1, *Di*[*x*] = *Di*+1[*x>i*]. This is because
LT f *i* (*x,r≥i*) = (1 *− xi*) *· ri·* eqe (*x>i,r>i*) = 0*.*

- If *xi*= 0 then *Di*[*x*] = *Di*+1[*x>i*] + *ri· Ei*[*x>i*].
The table *D₁* is exactly the table we want, containing all *T* evaluations of LT f(*j* *′* *,r*) as *j* *′* ranges over *{*0*,*1*}* log *T*. As explained above, *D₁* can be computed with 3*T/*2 multiplications in total. *T/*2 of these are devoted to computing all of the *Ei*tables, and an additional *T* multiplications are devoted to computing all of the *Di* tables.

### B.2 Optimizing the Val

### f -evaluation sum-check prover further

Consider using the sum-check protocol to compute X LT f(*r′,x*) *· g*(*x*)*.* *x∈{*0*,*1*}m*

In Twist we are interested in the case where *g* is multilinear, i.e., where *g* has degree *d* = 1 in each variable, so let us restrict our discussion to that case. We assume that an array storing all evaluations of *g* over *{*0*,*1*}* *m*

is already computed prior to the start of the prover algorithm (i.e., our accounting in this section does not charge the prover to compute such an array. In Twist, it will cost 2*K* field operations per Section 8.1).

Let (*r₁,...,ri−*1) denotes the randomness chosen by the sum-check verifier in rounds 1*,...,i −* 1. Then
X *s* *i*

(*c*) = LT f(*r*
*′* *,r₁,...,ri−*1*,c,x* *′* ) *· g*(*r₁,...,ri−*1*,c,x* *′* ) *x* *′* *∈{*0*,*1*}m−i*   X X*m* =  (1 *− rj′*) *· rj·* eqe (*r>j* *′* *,* (*r₁,...,ri−*1*,c,x* *′* ) *>j*) *· g*(*r₁,...,ri−*1*,c,x* *′* ) *x* *′* *∈{*0*,*1*}m−ij*=1     X X*i−*1 =   (1 *− rj′*) *· rj·* eqe (*r>j* *′* *,rj*+1*,...,ri−*1*,c,x* *′* ) *· g*(*r₁,...,ri−*1*,c,x* *′* ) *x* *′* *∈{*0*,*1*}m−ij*=1   X +  (1 *− ri*) *· c ·* eqe (*r>i* *′* *,x* *′* ) *· g*(*r₁,...,ri−*1*,c,x* *′* ) *x* *′* *∈{*0*,*1*}m−i*     X X*m* +   (1 *− rj′*) *· x* *′j−i* *·* eqe (*r>j* *′* *,rj*+1*,...,ri−*1*,c,x* *′* ) *· g*(*r₁,...,ri−*1*,c,x* *′* ) *x* *′* *∈{*0*,*1*}m−ij*=*i*+1     X X*i−*1 =   (1 *− rj′*) *· rj·* eqe (*r>j* *′* *,rj*+1*,...,ri−*1*,c,x* *′* ) *· g*(*r₁,...,ri−*1*,c,x* *′*

) (90)
*x* *′* *∈{*0*,*1*}m−ij*=1   X +  (1 *− ri*) *· c ·* eqe (*r>i* *′* *,x* *′* ) *· g*(*r₁,...,ri−*1*,c,x* *′*

) (91)
*x* *′* *∈{*0*,*1*}m−i*   X +  *Di*+1[*x* *′*] *· g*(*r₁,...,ri−*1*,c,x* *′* )*.* (92) *x* *′* *∈{*0*,*1*}m−i*

Here, the first equality invokes Expressions (86) and (87) for LT f and LT f*i*. The final equality invokes the definition of *Di*+1(Equation (89)), using the shorthand

*Di*+1[*c,x* *′*] = (1 *− c*) *· Di*+1[0*,x* *′*] + *c · Di*+1[1*,x* *′*]*.*

Call Expression (90) (i.e., the first sum the final expression) *A*(*c*), the second sum (i.e., Expression (91)) *B*(*c*) and and the third sum (i.e., Expression (92)) *C*(*c*).

Turning our attention to *A*(*c*) + *B*(*c*), for each 1 *≤ j ≤ i*, let

*i* Y *−*1
*Qj,i*(*c*) = (1 *− rj′*) *· rj·* eqe (*rj′* +1*,...,ri′−*1*,rj*+1*,...,ri−*1) *·* eqe (*ri′,c*)*.*
*z*=*j*+1

The prover can, with a constant number of field multiplications per round, maintain the quantity *Qi,c*:= P*i* *j*=1*Qj,i*(*c*).

Observe that   *i*

|X|X||
|---|---|---|
|||′ ′|
|j,i||>i|
|j=1|x ∈{0,1}||

*A*(*c*) + *B*(*c*) =  *Qj,i*(*c*) eqe (*r>i* *′* *,x* *′* ) *· g*(*r₁,...,ri−*1*,c,x* *′* )*.* *′ m−i*

Define X X *′*

|A (c) =|e (r eq ,x ) · g(r₁,...,r|) =|E [x] · g(r₁,...,r|
|---|---|---|---|
||>i||i|
|x ∈{0,1}||x ∈{0,1}||

*>i* *′ ′* *i−,c,x* *′* *i* *′* *i−,c,x* *′* )*,* *′ m−i ′ m−i*

where recall that *Ei*is defined in Equation (88). Then for any point *c*,   X *i−*1

|||s (c) = |Q (c) A|
|---|---|---|---|
|||i|j,i|
||||j=1|
|||i||
|m m−1|m m−1|||

*i j,i* *′*

(*c*) + *C*(*c*)*.* (93)
The sum-check prover needs to evaluate *s* at *c ∈{*0*,*2*}*. The prover will store all the intermediate arrays
*D,D,...* and *E,E,...,E₁* en route to building *D₁* per Section B.1. (As we will see momentarily,
ultimately the prover does not even need the array *D₁*). Then per the standard linear-time sum-check proving algorithm (Section 3.3), the prover can compute X *C*(*c*) = *Di*+1[*x* *′*] *· g*(*r₁,...,ri−*1*,c,x* *′* )*,* *x* *′* *∈{*0*,*1*}m−i*

and X *A* *′*

(*c*) = *Qi,c· Ei*[*x*
*′*] *· g*(*r₁,...,ri−*1*,c,x* *′* )*,* *x* *′* *∈{*0*,*1*}m−i*

with 2 *m−i* field multiplications each.

In total, across the entire protocol, the prover spends *T/*2 multiplications to build the arrays *Em,...,E₁*, *T/*2 additional multiplications to build the arrays *Dm,...,D₂*, *T* multiplications to bind the array storing evaluations of *g*, *T* multiplications to compute *C*(0) and *C*(2) across all rounds *i* given these arrays, and *T* to compute *A* *′*

(0) and *A* *′*
(2) across all rounds. This is 4*T* multiplications in total.
## C A Shout variation with a linear prover dependence on d

Recall from Equation (30) that Shout simply applies the sum-check protocol to confirm that:

*d* ! X Y rve (*r*cycle) = eqe (*r*cycle*,j*) rae*i*(*ki,j*) *·* Val f (*k*)*.*

|||i i|
|---|---|---|
|k=(k ,...,k|)∈ {0,1}|i=1|

1 *d* (log(*K*)*/d*) *d* *, j∈{*0*,*1*}*log *T*

For very large values of *d*, a nuisance is that the final log*T* rounds of this protocol cause the prover to incur roughly *d²T* field multiplications. Here, we describe an alternative application of the sum-check protocol that avoids quadratic dependence on *d* (but has a worse leading constant, and hence is only preferable when *d* is very large).

Let *j₀,j₁,...,jd*each consist of log*T* variables. Let eqe (*j₀,j₁,...,jd*) denote the multilinear extension of the
function that evaluations to 1 if all *d* + 1 vectors *j₀,...,jd*are equal, and zero otherwise. Then

log Y *T* Y *d* ! Y *d* !!

eqe (*j₀,j₁,...,jd*) = (1 *− jk,i*) + *jk,i.* (94) *i*=1 *k*=0 *k*=1

Now, in our modified version of Shout, replace Equation (30) with:

*d* ! X Y

||||ra )|e (k ,j )|
|---|---|---|---|---|
||||d|i i i|
|k=(k ,...,k|)∈ {0,1}|, j ,...,j ∈{0,1}|i=1||

rve (*r*cycle) = eqe (*r*cycle*,j₁,j₂,...,jd i i i·* Val f (*k*)*.* (95)

1 *d* (log(*K*)*/d*) *d* 1 *d* log *T*

Note that this invocation of the sum-check protocol has log(*K*) + *d*log*T* rounds rather than log(*K*) + log(*T*) rounds in the standard variant of Shout (i.e., applying sum-check to check Equation (30)). However, the total proof size remains *O*(log(*K*) + *d*log(*T*)) field elements, as each of the final *d*log*T* rounds in the new variant has the prover send a degree-2 polynomial (whereas in the standard variant the prover sent a degree-*d* polynomial in each of the final log*T* rounds).

Theorem 7. *Shout (Figure* (7)*) with Equation* (30) *replaced by Equation* (95) *is perfectly complete and has* *soundness error O*((log(*K*) + *d*log(*T*))*/|*F*|*)*.*

*Proof.* The proof is identical to Theorem 3, except that we must establish that Equation (95) holds. To see this, observe that the right hand side of Equation (95) is a multilinear polynomial in *r*cycle. So it suffices to establish that the right hand side and left hand side agree at all inputs *r*cycle*∈{*0*,*1*}* log *T*. Observe that for

||∈{0, 1}|, then eq|,j₁,j₂,...,j|
|---|---|---|---|
||d d|log T cycle||
|cycle d|d|||
|i=1 i i d|i|||
|i=1 cycle|i i i|||

any term of the sum on the right hand side, if *j₁,...,jd* log *T* e (*r*cycle *d*) = 0 unless

*j₁* = *j₂* = *···* = *j* = *r,* (96)

and if this equality does hold then eqe (*r,j₁,j₂,...,j*) = 1. Q If Equation (96) does hold, then rae (*k,j*) = 1 if the register with binary representation *k* = Q (*k₁,...,kd*) is read at cycle *r*cycle, and rae (*k,j*) = 0 otherwise. Hence, the right hand side equals

Val f (*k*) where *k* is the register read at cycle *r*. The result follows.

### C.1 Fast prover implementation

First log*K* rounds. The first log*K* rounds of this sum-check invocation proceed identically to the standard variant of Shout (in these rounds, the prover message is no different between the two variants). The reader may be initially surprised by this because Expression (95) has *K·T* *d* terms while Expression (30) only has *K·T* terms. However, per the proof of Theorem 7, the factor eqe (*r*cycle*,j₁,j₂,...,jd*) evaluates to 0 over log *T d* *{*0*,*1*}* unless *j₁* = *j₂* = *···* = *jd*. This means that in the first log*K* rounds (where only variables of *k*
are being bound, not variables of *j₁,...,jd*), *j₁,...,jd*effectively act as a single entity *j ∈{*0*,*1*}*
log *T*, and this leads to the same prover messages as in the original Shout protocol for these rounds.

log(*K*)*/d d* Final *d*log*T* rounds. Let *r* = (*r₁,...,rd*) *∈* F denote the randomness chosen by the verifier across the first log*K* rounds of sum-check. Then the final *d*log*T* rounds compute the following sum:

*d* ! X Y Val f (*r*) *·* eqe (*r* cycle*,j₁,j₂,...,jd*) rae*i*(*ri,ji*)*.* (97) *j₁,...,jd∈{*0*,*1*}*log *Ti*=1

We bind the first variable of *j₁,j₂,...,jd*in sequence, followed by the second variable of each, and so on. Let us call the first *d* rounds “Stage 1” (i.e., when we bind the first variable of each of *j₁,j₂,...,jd*), the next *d* rounds Stage 2, and so forth.

The key insight for a fast prover. While there are *T* *d* terms in Expression (97), round-over-round almost all of them are zero. Specifically, eqe (*r*cycle*,j₁,j₂,...,jd*) is a product of log(*T*) terms, one per variable in each *j* *i* –intuitively, it tests equality of *j₁,...,jd*“bitwise”. Since eqe checks equality of each bit independently, it turns out that in each round of the protocol, the prover need only consider terms that agree in all but their first bit. This keeps the total prover time in each round of Stage *S* to *T/*2 *S*. Since there are *d* rounds in each Plog *T* *s* stage, this is *O*(*S*=1*dT/*2) = *O*(*dT*) time in total.

C.1.1 Detailed prover algorithm description for *d* = 2 To simplify notation, we begin with a description of the prover algorithm in the case *d* = 2. Further, let *r* *′* = *r*cycle. Consider the first round within Stage *i*. This is round *t* = 2(*i −* 1) + 1 within the final *d*log*T* rounds of the sum-check applied to compute Expression (95), and round *t*
*′* = log(*K*) + *t* within the entire modified-Shout protocol.

|,1|,i−1 i−1||
|---|---|---|
|||,1 ,i−1|

Let *w₁* = (*w₁,...,w₁*) *∈* F denote the vector of random values chosen for the first *i −* 1 coordinates of *j₁* across the already-completed *i −* 1 stages, and similarly let *w₂* = (*w₂,...,w₂*).

Simplifying the prover’s message definition. The prover’s prescribed message *st′* in round *t* *′* of our modified version of Shout satisfies:

X *s* *t*

(*c*) = Val f (*r*) *·* eqe (*r*
*′* *,* (*w₁,c,j₁* *′* )*,* (*w₂,j₂* *′* )) *·* rae₁(*r,w₁,c,j₁* *′* ) *·* rae₂(*r,w₂,j₂* *′* )*.* *j₁* *′* *∈{*0*,*1*}*log(*T*)*−i,j₂′∈{*0*,*1*}*log(*T*)*−i*+1

Clearly, eqe (*r* *′* *,* (*w₁,c,j₁* *′* )*,* (*w₂,j₂* *′* )) = 0 unless *j₂* *′,>* 1= *j₁* *′*. So this sum simplifies to

X

|||||′|′|′||′||′||
|---|---|---|---|---|---|---|---|---|---|---|---|
||j₁ ∈{0,1} log T||,b∈{0,1} >i i −1|||||||||
|′|′|′|ℓ′|,ℓ ,ℓ|ℓ′|,ℓ|,ℓ|i′||′ >i ,>i|,>i|
||||ℓ=1|||||||||

Val f (*r*) *·* eqe (*r,* (*w₁,c,j₁*)*,* (*w₂,b,j₁*)) *·* rae₁(*r,w₁,c,j₁*) *·* rae₂(*r,w₂,b,j₁*)*.* (98) *′* log(*T*)*−i*

For any vector *x ∈* F, let *x* denote the last log(*T*) *− i* coordinates of *x*. By Equation (94),

Y !

eqe (*r,* (*w₁,c,j₁*)*,* (*w₂,b,j₁*)) = (*r w₁ w₂* + (1 *− r*)(1 *− w₁*)(1 *− w₂*)) *·* eqe (*r,c,b*) *·* eqe (*r,w₁,w₂*)*.*

Hence, letting ! *i* Y *−*1 *C* = Val f (*r*) *·* (*ri′w₁,ℓw₂,ℓ*+ (1 *− rℓ′*)(1 *− w₁,ℓ*)(1 *− w₂,ℓ*))*,* (99) *ℓ*=1 Expression (98) equals: X

||||′|′ ′|
|---|---|---|---|---|
|||i′|>i||
|j₁ ∈{0,1}|,b∈{0,1} ′|log(T )−i ′ >i|′ ′|′ ′ >i|

*C ·* eqe (*r,c,b*) *·* eqe (*r,j₁,j₁*) *·* rae₁(*r,w₁,c,j₁* *′* ) *·* rae₂(*r,w₂,b,j₁* *′*

)*.* (100)
*′* log(*T*)*−i*

Furthermore, note that for *j₁ ∈{*0*,*1*}*,

eqe (*r,j₁,j₁*) = eqe (*r,j₁*)*,*

where the polynomial eqe on the right hand side refers to Equation (15). Hence, Expression (100) equals:

X *C ·* eqe (*ri′,c,b*) *·* eqe (*r>i* *′* *,j₁* *′* ) *·* rae₁(*r,w₁,c,j₁* *′* ) *·* rae₂(*r,w₂,b,j₁* *′*

)*.* (101)
*j₁* *′* *∈{*0*,*1*}*log(*T*)*−i,b∈{*0*,*1*}*

Similarly, turning our attention to the prover’s message in round *t* + 1, X

||′ ′|′|
|---|---|---|
|i′ ,i j₂ ∈{0,1}|>i|,i|

*s* *t*+1(*c*) = *C ·* eqe (*r,w₁,c*) *·* eqe (*r,j₂*) *·* rae₁(*r,w₁,r₁,j₂*) *·* rae₂(*r,w₂,c,j₂* *′*

)*.* (102)
*′* log(*T*)*−i*

Prover algorithm and cost accounting for *d* = 2. Before the final *d*log*T* rounds of Shout’s read-checking sum-check protocol begin, the prover the prover computes and stores log(*T*) *−* 1 arrays *E*log(*T*)*−*1*,...,E₁*,

|contains all evaluations eq||e (r ,j ) as j|ranges over {0, 1}|
|---|---|---|---|
|i||>i >i|>i|
|′|′||log T|
||/d|||

where *Ei >i >i >i* log(*T*)*−i*. Also, at the start of these final log*T* rounds, the prover will have already computed two arrays, say *A₁* and *A₂*, that store all evaluations of the form rae₁(*r,j*) and rae₂(*r,j*) as *j* ranges over *{*0*,*1*}*. As per the standard linear-time sum-check prover algorithm (Section 3.3), the prover will bind *A₁* and *A₂* (see Equation (20)) as appropriate round-over-round. Per Section 6.2.2, if *K¹* = *o*(*T*), the cost of binding these arrays round-over-round is a low-order cost, so we ignore it in our accounting below.

The prover can maintain the value *C* from Equation (99) round-over-round with only a constant number of field multiplications per round.

During the first round in Stage *i*, with prover message given by Expression (101). Note that for *c* = 0, eqe (*ri′,c,b*) = 0 if *b* = 1, so for *c* = 0 *b* = 1 need not be considered at all by the prover. In addition, eqe (*r>i* *′* *,j₁* *′* ) can be obtained with a single lookup into *Ei*. The prover can compute Expression (101) for *c* = 0 with 2*T/*2 *i* + *O*(1) field multiplications. Expression (101) for *c* = 2 can be computed with 4*T/*2 *i* + *O*(1) multiplications (twice as many as for *c* = 0 because both *b* = 0 and *b* = 1 must be considered when *c* = 2).

The prover’s message for second round of Stage *i* (Expression (102)) requires at most 4*T/*2 *i* field multiplications, with 2*T/*2 *i* required for *c* = 0 and the same number required for *c* = 2.

Hence, each stage *i* = 1*,...,* log(*T*) requires 10*T/*2 *i* field multiplications for the prover. Summing across all *i*, this is at most 10*T* multiplications. Accounting also for the *T/*2 multiplications to compute the arrays *E*log(*T*)*−*1*,...,E₁*, in total across all stages *i* this is 10*.*5 *· T* field multiplications.

1*/d* *√* 1*/d* *√* An optimization when *K* is *o*( *T*). When *K* = *o*( *T*), a significant optimization is possible, similar to the one described in Section 6.2.2 that renders binding the arrays *A₁* and *A₂* a low-order cost. At the start of the final *d*log*T* rounds of sum-check, for each *ℓ ∈{*1*,*2*}*, rae*ℓ*(*r,j*) takes on only *K¹* */d* distinct values as *j* ranges over *{*0*,*1*}* log *T*. Hence, all possible products of the form rae₁(*r,j₁*) *·* rae₂(*r,j₂*) as *j₁* and *j₂* range over *{*0*,*1*,*2*}×{*0*,*1*}* log(*T*)*−*1 can be computed and stored in a table of size *O*(*K²* */d* ), thereby saving the prover the need to incur *T* field multiplications to compute such quantities arising in Expression (100) for round log(*T*) + 1. Similar optimizations apply for several rounds, with the size of the lookup table of “pre-computed products of rae₁ and rae₂ evaluations” growing (rapidly) round-over-round. After a few rounds, the lookup tables would have size larger than *T* and this optimization is no longer helpful. 1*/d* *√* Depending on how much smaller *K* is than *T*, this can save up to about half of the 10*T* field multiplications accounted for above. This yields a total number of multiplications of roughly 5*.*5 *· T.*

C.1.2 General *d*: Simplifying the prover’s message definition Consider the first round in stage *i*. This is round *t*
*′* = log(*K*) + *t* where *t* = *d*(*i −* 1) + 1 = *di − d* + 1. The prover’s prescribed message *st′* in round *t* *′* satisfies:

X Y*d* *s* *t* *′* (*c*) = Val f (*r*)*·* eqe (*r* *′* *,* (*w₁,c,j₁* *′* )*,* (*w₂,j₂* *′* )*,...,*(*wd,jd* *′* ))*·*rae₁(*r,w₁,c,j₁* *′* )*·* rae*ℓ*(*r,wℓ,jℓ′*)*.* *j₁* *′* *∈{*0*,*1*}*log(*T*)*−i,j₂′,...,jd′∈{*0*,*1*}*log(*T*)*−i*+1*ℓ*=2

Clearly, eqe (*r* *′* *,* (*w₁,c,j₁* *′* )*,* (*w₂,j₂* *′* )*,...,*(*wd,jd* *′* )) = 0 unless *j₁* *′* = *j₂* *′,>* 1= *···* = *jd,>* *′* 1. So this sum simplifies to

X Y*d* *s* *i*

(*c*) = Val f (*r*) *·* eqe (*r*
*′* *,* (*w₁,c,j₁* *′* )*,* (*w₂,b,j₁* *′* )*,...,*(*wd,b,j₁* *′* )) *·* rae₁(*r,w₁,c,j₁* *′* ) rae*ℓ*(*r,wℓ,b,j₁* *′* )*.* *j₁* *′* *∈{*0*,*1*}*log(*T*)*−i,b∈{*0*,*1*} ℓ*=2 (103)

Let!!!! *i* Y *−*1Y*d*Y*d* *D* = *rz* *′* *wℓ,zw₂,z*+ (1 *− rz* *′*

) (1 *− wℓ,z*)*.*
*z*=1 *ℓ*=1 *ℓ*=1

By Equation (94), for *b ∈{*0*,*1*}*,

eqe (*r* *′* *,* (*w₁,c,j₁* *′* )*,* (*w₂,b,j₁* *′* )*,...,*(*wd,b,j₁* *′* )) = *D ·* eqe (*ri′,c,b*) *·* eqe (*r>i* *′* *,j₁* *′* *,j₁* *′* *,...,j₁* *′* )*.*

Hence, letting *C* = Val f (*r*) *· D,* (104)

Expression (103) equals:

X Y*d*

|||′|′ ′|′|′||′|
|---|---|---|---|---|---|---|---|
||i′|>i||||ℓ ℓ||
|j₁ ∈{0,1}|′|log(T )−i ′ ′ >i|′ ′|′ ′ >i|ℓ=2|||

*C ·* eqe (*ri′,c,b*) *·* eqe (*r>i* *′* *,j₁* *′* *,j₁* *′* *,...,j₁* *′* ) *·* rae₁(*r,w₁,c,j₁* *′* ) *·* rae*ℓ*(*r,wℓ,b,j₁* *′*

)*.* (105)
*′* log(*T*)*−i,b∈{*0*,*1*}*

Furthermore, note that for *j₁ ∈{*0*,*1*}*,

eqe (*r,j₁,j₁,...,j₁*) = eqe (*r,j₁*)*,*

where the polynomial eqe on the right hand side refers to Equation (15). Hence, Expression (100) equals:

X Y*d* *C ·* eqe (*ri′,c,b*) *·* eqe (*r>i* *′* *,j₁* *′* ) *·* rae₁(*r,w₁,c,j₁* *′* ) *·* rae*ℓ*(*r,wℓ,b,j₁* *′*

)*.* (106)
*j₁* *′* *∈{*0*,*1*}*log(*T*)*−i,b∈{*0*,*1*} ℓ*=2

Similarly, turning our attention to the prover’s message in round *M* of Stage *i*, for *M* = 2*,...,d −* 1, let

*C* *′* = *C ·* eqe (*ri′,w₁,i,w₂,i,...,wM −*1*,i,c*)*.*

Then

*M −*1 ! *d* ! X Y Y

|s|·|) · ,j||e ra (r,w|) ,j|) · ,c,j||e ra (r,w ,b,j|).|
|---|---|---|---|---|---|---|---|---|---|
|t +M −1|j ∈{0,1}|>i M|N =1|N|N,i M|M|ℓ=M +1|ℓ ℓ|M|

*t* *′* +*M −*1(*c*) = *C* *′* eqe (*r>i* *′* *M* *′* *N N,i M* *′* *·* rae*M*(*r,wM M* *′* *ℓ ℓ M* *′*

*M* *′* log(*T*)*−i,b∈{*0*,*1*}* (107)

Finally, for round *M* = *d* of Stage *i*, the prover’s message is:

*M −*1 ! X Y

|s|·|) · ,j||e ra (r,w|) ,j|). ,c,j|
|---|---|---|---|---|---|---|
|t +M −1|j ∈{0,1}|>i M|N =1|N|N,i M|M|

*t* *′* +*M −*1(*c*) = *C* *′* eqe (*r>i* *′* *M* *′* *N N,i M* *′* *·* rae*M*(*r,wM M* *′* (108) *M* *′* log(*T*)*−i*

Prover algorithm for general *d*. Before the final *d*log*T* rounds of Shout’s read-checking sum-check protocol begin, the prover the prover computes and stores log(*T*) *−* 1 arrays *E*log(*T*)*−*1*,...,E₁*, where *Ei*

||,j ) as j|ranges over {0, 1}||
|---|---|---|---|
||>i >i|>i||
||||ℓ|
|ℓ ′||log T||
|||ℓ||

contains all evaluations eqe (*r>i >i >i* log(*T*)*−i*. Also, at the start of these final log*T* rounds, the prover will have already computed *d* arrays, say *A₁,A₂,...,Ad*, such that *A* stores all evaluations of the form rae (*r,j*) as *j* ranges over *{*0*,*1*}*. As per the standard linear-time sum-check prover algorithm (Section 3.3), the prover will bind each *A* (see Equation (20)) as appropriate round-over-round.

The prover can maintain the value *C* from Equation (104) round-over-round with only a constant number of field multiplications per round.

For each *jM* *′* *∈{*0*,*1*}* log(*T*)*−i*, the prover can compute

Y *d* !

rae*ℓ*(*r,wℓ,b,jM* *′*

) (109)
*ℓ*=*M*+1

for *all* relevant values of *M* (i.e., for *M* = *d −*1*,d −*2*,...,*1) with *d −* 2 multiplications. So that’s (*d −* 2)*T/*2 *i*

||′|log(T )−i||
|---|---|---|---|
||M|||

multiplications in total across all *j* *′* *∈{*0*,*1*}* log(*T*)*−i*.

Also, across all *d* rounds *M* of Stage *i*, the prover can also compute

*M* Y*−* !

rae*N*(*r,wN,i,jM* *′*

) (110)
*N*=1

with (*d −* 2) *· T/*2 *i* multiplications in total.

Given these values, for round *M* = 1*,...,d −* 1 in Stage *i*, the prover can compute its message (Expression (107)) at *c* = 0 with 2 *· T/*2 *i* field multiplications and at *c* = 2 with 4 *· T/*2 *i* field multiplications (up to additive *O*(*d*) terms). For round *d*, due to the lack of a sum over *b ∈{*0*,*1*}*, the evaluation of the prover’s message at each of *c* = 0 and *c* = 2 takes 2*T/*2 *i* field multiplications.

#### Summarizing the costs:

- *T/*2 to compute the *Ei*arrays before the start of the final *d*log*T* rounds of the sum-check protocol.
- 2(*d −* 2)*T* to compute the products in Expression 109 and (110).
- 6(*d −* 1)*T* for the first *d −* 1 rounds of all stages in total.
- 4*T* for the final round of all stages in total.
The total number is multiplications is therefore

#### (8d − 5.5)T.

#### Additional optimizations.

- In the final round of every stage, Gruen’s optimization (Section 3.6.1) applies. Recall that Gruen’s optimization considers applying sum-check to polynomials of the form eqe (*r*
*′* *,x*)*· g*(*x*) and avoids eqe (*r* *′* *,x*) from contributing to the degree of the univariate polynomial *st*(*c*) the prover computes in each round *t*. This same technique applies to the factor

#### eqe (ri′,w₁,i,w₂,i,...,wM −1,i,c) (111)

appearing above in the definition of *C* *′* and hence Equation (108) capturing the prover’s message in the final round of stage *i*. The key property that ensures Gruen’s optimization applies is that all values other than *c* appearing in Expression (111) are fixed. In other words, *ri′,w₁,i,...,wM −*1*,i*are *not* being summed over in the final round of stage *i*. Accordingly Expression (108) is a degree-1 polynomial in *c* alone. This is all Gruen’s optimization needs in order to apply.

This reduces the 4*T* multiplications required for the final round of all stages down to 2*T*. Hence, it reduces total prover multiplications from (8*d −* 5*.*5)*T* down to

#### (8d − 7.5)T.

1*/d* *√*

- The optimization that we described in the case of *d* = 2 that applies when *K* is *o*( *T*) also applies for general *d*. In the context of *d >* 2, this optimization can be used to save a significant fraction of the 2(*d −* 2)*T* multiplications needed to compute the products in Expression 109 and (110). Details follow. This optimization is primarily applicable when combining Shout with a binary-field hashing-based commitment scheme like Binius [DP23, DP24] or Blaze [BCF
+ 24], as this is the context in which *d* may get set quite large (and hence *K¹* */d* quite small) especially when considering gigantic, structured tables. For instance, if *K* = 2 64 then setting *d* = 16 is natural (see Section 2.8). In this case, *K¹* */d* is just 2 4 = 16).

Optimization details. For each fixed *i* = 1*,...,d*, the evaluations rae*i*(*r,j*) take on only *K¹* */d* as *j* ranges over *{*0*,*1*}* log *T*. Hence, during round log(*K*) + 1 of the modified-Shout protocol, for any integer

|||/d|/d|ℓ/d||
|---|---|---|---|---|---|
||M|||||
||v=M −i|v||||
|log T|i/d|||||
||||||log T|

*ℓ >* 1, the prover can compute lookups tables of size *K²* */d* *,K³* */d* *,...,K* *ℓ/d*, with the *i*’th table storing all *possible* products of the form Y ra (*r,j*)*,* (112)

for *j ∈{,}*, since there are only *K* such values. After this table is computed, the prover can compute Expression (109) (i.e., the actual quantities of Expression (112) for all *T* values of *j ∈{,}*)

with a single lookup into this table for each *j*. This saves (*ℓ −* 1) *· T* multiplications. A similar technique applies for computing Expression (110) in round log(*K*) + 1, but the *i*’th table has size 4*K²* *id* in this case, and similarly for computing Expression (109) in round log(*K*) + 2, and so on.

In the context of *K* = 2 64 and *d* = 16, using a handful of tables each of size at most 2 20 (i.e., several dozen MBs of space), this can save 5*T* multiplications: 3*T* during the computation of Expression (110) in round log(*K*) + 1 with *ℓ* set to 4, *T* during the computation of Expression (110) in round log(*K*) + 1 with *ℓ* set to 2, and *T* during the computation of Expression (109) in round log(*K*) + 1. This brings the total number of prover field multiplications in this application down to 8*d −* 12*.*5*T*.
