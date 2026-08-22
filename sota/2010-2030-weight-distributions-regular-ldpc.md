ACCEPTED FOR PUBLICATION IN IEEE TRANSACTIONS ON INFORMATI ON THEORY (VERSION: OCTOBER 26, 2018)

## Weight Distributions of Regular Low-Density Parity-Check Codes over Finite Fields

Shengtian Yang, *Member, IEEE,* Thomas Honold, *Member, IEEE,* Yan Chen, *Member, IEEE,* Zhaoyang Zhang, *Member, IEEE,* Peiliang Qiu,*Member, IEEE*

***Abstract*—The averageweight distribution ofa regular low-** by zero-one parity-check matrices. Ever since the publication **density parity-check(LDPC) code ensemble over a finite field** of [1], there has been a lot of work extending the analysis **is thoroughly analyzed. In particular, a precise asymptotic ap-** ofweightdistributionsofbinary LDPCcodesindifferent **proximationoftheaverage weight distributionisderivedf or the small-weightcase, and a series of fundamental qualitat ive** ways, such as [2]–[7]. A generalization of weight distributions, **properties of the asymptotic growth rate of the average weight** alsoknown as spectra,ofregular LDPCcodesover finite **distribution are proved. Based on this analysis, a general result,** fields and arbitrary abelian groups were later studied in [8], **including all previous results as special cases, is established for** [9].Morerecently, the binaryweightdistributions ofnon- **the minimum distance ofindividual codesin a regular LDPC** binary LDPC codes also received some attention [10]. By now **code ensemble.** a bundle of formulas about weight distributions of various ***Index Terms* —Low-density parity-check (LDPC) codes, mini-**LDPCcodesisknown,butthevalueandsignificanceof **mum distance, weight distribution.** most formulas is far from being fully understood, except in thecaseofbinaryregular LDPCcodes,whichhave been

I.I NTRODUCTION
well studied [1], [2]. The difficulty is dueto the complex expressions for the weight distributions of LDPC codes, which OW-DENSITY parity-check (LDPC)codes,originally are usually obtained by the generating function approach and

# Lintroduced by Gallager [1], are a family of linear codes

hence are typically expressed as coefficients of a polynomial. characterizedbyasparseparity-checkmatrix.Owingto Given a polynomial p(x) with nonnegative coefficients, a usual their capacity-approaching performance under low-complexity approach for estimating the coefficient of a monomialx k in iterativedecodingalgorithms,LDPCcodeshaveattracted [p(x)] n istocalculate the infimumof [p(x)] n /x k over all tremendous attention in the past years. To evaluate the the- positivex, which gives an upper bound of the coefficient and in oretical performance of an LDPC code, a typical method is to fact has the same asymptotic growth rate as the coefficient [4, estimate its performance under maximum-likelihood (ML) or Theorem 1]. However, analyzing functions likeinfy>0f (x, y) iterative decoding assumptions. The performance of a linear is not an easy job. When f (x, y) is complicated, determining code under ML decoding can be well estimated based on its theshape,suchasmonotonicity,convexity, and zeros,of weight distribution [1], so having the knowledge about weight infy>0f (x, y) becomes a difficult mission. distributions of LDPC codes facilitate the analysis of the ML In this paper, we shall perform such a mission for ensembles decoding performance. of regular LDPC codes over finite fields. At first, as an easy The first analysis work on the weight distributions of LDPC consequence of the results in [8], [9], [11], an exact expression codes was given by Gallager in his pioneering work [1], where is introduced for the average weight distribution of a(c, d)-

### arXiv:1010.2030v3 [cs.IT] 15 Jul 2011

he studied the weight distributions of binary regular LDPC regular LDPC code ensemble over the finite field Fqof order codes.Moreover, he alsogeneralizedtheanalysistonon- q, where c and d, in a less strict sense, correspond to the binary regular LDPC codes over Zm( m > 2), characterized column and row weight of parity-check matrix, respectively. Based on this expression, we show that, when averaged on the This work was supported in part by the National Natural Science Foundation of Chinaunder Grants60772093,60802014,and60872063,the Chinese whole ensemble, the fraction of codewords of small weightl Specialized Research Fund for the Doctoral Program of Highe r Education un- in an LDPC code is at most asymptotically n −⌈(c−2)l/2⌉ as der Grants 200803351023 and 200803351027, the National High Technology the coding length n goes to infinity. Next, using the upper- Research and Development Program of China under Grant 2007A A01Z257, the Zhejiang Provincial Natural Science Foundation of Chin a under Grant bound technique mentioned above, we analyze the asymptotic Y106068, and the Program for New Century Excellent Talents in University growth rateωq,c,d(x) of the average weight distribution, where under grant NCET-09-0701.x denotesthenormalizedweight.Aseriesoffundamental

S.Yangisself-employedat Zhengyuan Xiaoqu10-2-101,Hang zhou
310011, China (email: yangst@codlab.net). qualitative properties ofωq,c,d(x) are found and proved. In

T.Honoldiswiththe Departmentof Information Scienceand E lec-particular, we show that for d ≥ c ≥ 3, ωq,c,d(x) hasa
tronic Engineering, Zhejiang University, Hangzhou 310027,China(email:unique zerox₀ in (0, 1 − 1/q]. This zero just corresponds to honold@zju.edu.cn).

Y. Chen iswith Huawei Technologies Co.,Ltd(Shanghai),Sha nghai
the normalized minimum distance of a typical LDPC code, 201206, China (email: eeyanchen@huawei.com). andhenceprovidesimportantinformationaboutthecode

Z. Zhang and P. Qiu are with the Department of Information Science and
ensemble. Finally, we prove that for d ≥ c ≥ 3, there are at Electronic Engineering, Zhejiang University, Hangzhou 310027, China (email: −⌈(c−2)l₀/2⌉ ning ming@zju.edu.cn; qiupl@zju.edu.cn). most a fraction Θ(n) of all codes in the ensemble Copyright (c) 2011 IEEE. Personal use of this material is permitted. whose minimum distance is between the constantl₀ and αn,

where α ∈ (0, x₀). • For any real functionsf (n) and g(n) with n ∈ N, the Therestofthispaperisorganizedasfollows.In Sec-asymptotic Θ-notation f (n) = Θ(g(n)) means that there tion II,weintroducethenotationsandconventionstobe exist positive constantsc₁ and c₂ such that usedthroughoutthepaper.In Section III,wedefinethe c g(n) ≤ f (n) ≤ c g(n). 1 2 ensemble of regular LDPC codes over a finite field and give its average weight distribution function; moreover, we study for sufficiently largen. the asymptotic behavior of the average weight distributionfor• Forx ∈ R, ⌊x⌋ denotes the largest integer not exceeding the small-weight case. The main analysis, consisting of two x, and ⌈x⌉ denotes the smallest integer not less than x. stages, for the asymptotic growth rate of the average weight distribution is performed in Sections IV and V. The minimum III.R EGULAR LDPC C ODES OVER FINITE FIELDS distance of individual codes in a regular LDPC code ensemble We first define some basic F -linear transformations.q is analyzed in Section VI. Section VII concludes the paper. *Definition 3.1:* A *single symbol repetition* with a parameter c ∈ N isamapping fq,c REP : Fq→ F c qgivenby x 7→ II.N OTATIONS AND CONVENTIONS (x, x,..., x). Inthissection,weintroducesomebasicnotationsand *Definition 3.2:* A *single symbol check* with a parameterd ∈ CHK d ∑d conventions to be used throughout the rest of this paper. N is a mapping f : F q,d q→ Fqgiven byx 7→i=1xi.

- Ingeneral,symbols,realvariables,anddeterministic *Definition 3.3:* A *single symbol random multiplier map*is a mappingsaredenotedbylowercaseletters.Setsand random mapping F
qRM: Fq→ Fqgiven byx → Cx where C random elements are denoted by capital letters. is an independent random variable uniformly distributed over

- The symbols Z, N, N₀,R denote the ring of integers, the F
×

q.
set of positive integers, the set of nonnegative integers,*Definition 3.4:* A *uniform random interleaver* of Fn qis a and the field of real numbers, respectively. For a primerandomautomorphism Σq,n: Fn q→ F n qgivenby x 7→ power q ≥ 2 the finite field of order q is denoted by Fq. (xΠ−1(1), xΠ−1(2),..., xΠ−1(n)), where Π is an independent The multiplicative subgroup of nonzero elements of Fq random permutation uniformly distributed over the symmetric is denoted by F ×

q. group Sn, i.e., all permutations onn letters.
- The n-fold cartesian product of a set A is denoted by A
n. Next, we define a random linear transformation based on An element of A n is denoted byx = (x₁, x₂,..., xn), the above simple maps. where xi∈ A denotes the ith component of x. *Definition 3.5:* F q,c,d,n LD : F n q→ F cn/d qis a random mapping

- For any vectorc ∈ F
n q, the*weight*w(c) of c is the number defined by △ of nonzero symbols in it, that is,w(c) = |{i : ci6= 0}|.LD△CHK RM REP Fq,c,d,n= fq,d,cn/d◦ Fq,cn◦ Σq,cn◦ fq,c,n(1)

- Given the functionsf : X → Y and g : Y → Z, their composite is the function
g ◦ f : X → Z given by x 7→ where c, d ∈ N, d divides cn, and g(f (x)).n n n △ ⊙ △ ⊙ △ ⊙

- Given the functionsf : X₁ → Y₁ and g : X₂ → Y₂, f
q,c,n REP = fq,c REP, fq,d,n CHK = fq,d CHK, Fq,n RM = FqRM. their cartesian product is the functionf ⊙ g : X₁ × X₂ →i=1 i=1 i=1 Y₁ × Y₂ given by (x₁, x₂) 7→ (f (x₁), g(x₂)).LD Considering the kernel of Fq,c,d,n, we thus obtain an ensem-

- Whenperformingprobabilisticanalysis,allobjectsof
ble of regular LDPC codes over F, which is called aq*random* study are relative to a basic probability space(Ω, A, P)(n) 1 where A isa σ-algebra in Ω and P isaprobability (c, d)*-regular LDPC code over* Fqand is denoted by C q,c,d.

measure on (Ω, A). For any event A ∈ A, P A = P (A) This ensemble was originally introduced in [8], [12], [13] by

is called the probability of A. Any measurable mapping the method of bipartite graphs. LD of Ω intosomemeasurablespace (B, B) isgenerally To see the connection of REP Fq,c,d,nwith a bipartite graph, we

called a random element. For any random set or function, may regard each fq,cas a variable node with c sockets and eachf CHK as a check node with d sockets. Then in total there wetacitlyassumethattheir ⊙ n-fold cartesianproducts q,d n narenc variable sockets and nc check sockets. We say that the (e.g.,A ori=1F) arecartesianproductsoftheir independent copies. ith variable socket and the jth check socket are connected

- All logarithms are taken to the natural base
e and denoted by an edge ifj = Π(i), where Π is the random permutation

by ln. defined in Definition 3.4. We also define the label of the edge

- For any x ∈ [0, 1] and any integer q ≥ 2, the *entropy*
connecting thesetwo sockets to be the random variable C

*function* Hq(x) is defined by defined in Definition 3.3. Then we dispose of the sockets (i.e. edges are considered as connections between variable nodes △1 1 and check nodes). The resulting random graph (which may Hq(x) = x ln + (1 − x) ln + x ln(q − 1). x 1 − x have repeated edges) is exactly the random regular bipartite For anyx, y ∈ [0, 1], the *information divergence function* graph with independent and uniformly distributed random edge D(x‖y) is defined by labels taken from F × qas in [8]. △ x 1 − x D(x‖y) = x ln + (1 − x) ln. We shall tacitly assume throughoutthe paper thatthe block l ength n y 1 − yalways takes values such thatd divides cn.

(n)
Now let us investigate the weight distribution of C q,c,d. The where next theorem gives its average weight distribution. [ ()d]n

(n) △ 1 qx
*Theorem 3.6 (cf. [8], [9], [11]):* For c, d ∈ N, the average gˆ q,d

(x) = n 1 + (q − 1) 1 −.
(n) q q − 1
weight distribution of C q,c,d is given by

( ) n ( (cn/d) cl
) Taking logarithms of both sides of (10) and using the lower- [] l coef g q,d

(x), x bound in Lemma A.1, we further have
(n)
() E A q,c,d

(l) =cn
(c−1)l

(2) []
(q − 1) 1(q,c,d n)c clln E A (l) ≤ H q

(α) + [δq,d(α, xˆ) − ln q] + cβcn(cl)
(n)
n d where A q,c,d

(l) denotes the number of codewords of weight l△
(n)(l) where α = l/n. The theorem is finally established by taking
in C q,c,d ( 0 ≤ l ≤ n), coef p(x), x denotes the coefficient the infimum of the right side over allxˆ ∈ (0, 1). ofx l in the polynomialp(x), and *Remark 3.7:* Loosely speaking, for anyα ∈ [0, 1], if we

(n) △ 1 {d d}ntakel = αn, then it follows from [4, Theorem 1] that
g q,d

(x) = n [1 + (q − 1)x] + (q − 1)(1 − x). (3) q ()
g

(1)
(x)
1(cn/d) clcq,d Furthermore, we haven lim →∞ n ln coef g q,d

(x), x = d
x> inf₀ ln xdα [] ()(cm/d) 1(n)l 1 g q,d

(x)
ln E A q,c,d

(l) ≤ ωq,c,d+ cβcn(cl) (4) = inf
n nx>0 m ln xcmα

where for any m > 0. Comparing this identity with the proof of △ c Theorem 3.6 and noting that the second term in the right hand ωq,c,d(x) = Hq(x) + [δq,d(x) − ln q] (5) d side of (4) is asymptotically negligible, we immediately have △[] δ q,d(x) = inf δq,d(x, xˆ) (6) 1(n) xˆ∈(0,1) lim ln E A q,c,d (αn) = ωq,c,d(α). n→∞ n △ δ q,d(x, xˆ) = dD(x‖xˆ) + ρq,d(ˆx) (7) The functionωq,c,d(x) thus represents the asymptotic growth [ ()] rate of the average weight distribution of C

(n), and hence
d q,c,d △qx deserves further investigations. In the subsequent sections, we ρq,d(x) = ln 1 + (q − 1) 1 − (8) q − 1 shall provide an in-depth analysis ofω q,c,d(x). () () Although in general the average weight distribution of C(n) △l 1 n q,c,d βn(l) = H₂ − ln. (9) is very complex, it becomes simple for some speciald. The n n l next two theorems give its complete characterization ford = *Proof:* The average weight distribution (2) is in fact a1, 2. known result. Note that *Theorem 3.8:* []

(n)
{ ∣} [

(n)] { 1
l = 0

(n) l (n) ∣
E A (l) = E A q,c,d

(l) = (q − 1) P c ∈ C
q,c,d∣ w(c) = lq,c,1 l 0 otherwise.

||||||q,c,d,n LD|q,cn RM q,cn|q,c,n REP|
|---|---|---|---|---|---|---|---|
|(n)|q,d,cn/d CHK||(n)||(n)|||
|q,c,d|cn|cl|q,c,1||q,c,1|||
|CHK|cl (cn/d)||(n) q,c,2|(q−1)||||
|q,d,cn/d|q,d|||||||
||||(n) q,c,2||q|cn||

and *Proof:* Ford = 1, we have F = F ◦Σ ◦f, ∣{}∣ which is injective. In other words, the defining parity-check { ∣} ∣∣ cˆ ∈ ker f : w(ˆc) = cl ∣∣ ∣ () matrix of C has rankn, so that C = {0}. P c ∈ C ∣ w(c) = l =. (q − 1) *Theorem 3.9:*  []  ( n )( cn/2 ) For a proof ofl cl/2 cncl is even ∣{}∣ () E A (l) = (c/2−1)l( cl) (11) ∣ ∣cl 0 otherwise ∣ ˆc ∈ ker f : w(ˆc) = cl ∣ = coef g (x), x

1 ln E [] () ( l ) the reader is referred to [8, Appendix III], [9], [11]. A (l) ≤ 1 − c H + cβ (cl). (12) n 2 n Now let us prove the inequality (4). By the upper-bound technique introduced in Section I, it follows from (2) that *Proof:* By (3) it follows that

||( )||||]|
|---|---|---|---|---|---|
||n (cn/d)|||(n)|2 n|
|(n)|l q,d|||q,2||
|q,c,d|cn|(c−1)l||||
||cl||(cn/2)|cl|cl/2 cn/2 cl/2|
||||q,2|||

[] g (x) g (x) = [1 + (q − 1)x. ) E A (l) ≤ ( cl (q − 1) x Then we have { () for anyx > 0. Taking () (q − 1) cl is even coef g (x), x = xˆ 0 otherwise. x = (q − 1)(1 − xˆ) This together with (2) gives (11), which further yields (12)by where xˆ ∈ (0, 1), we obtain Lemma A.1.

|||(n)|
|---|---|---|
||l n (cn/d)|q,c,d|
|(n)|l q,d||
|q,c,d|cn cl cn−cl||
||cl||

() As shown above, the average weight distribution of C [] (q − 1) gˆ (ˆx) () istrivialfor d = 1, 2. Inthesequel,weshalltherefore E A (l) ≤ (10) xˆ (1 − xˆ) concentrate on the general case ofd ≥ 3.

Another well-known fact to be noted is that whenq = 2 and We shall show by induction onm that

(n) (n){
d is even, the weight distribution of C satisfies A (l) = q,c,d 2,c,d0 q = 2 and m is odd

(n) ()
A (n − l) for 0 ≤ l ≤ n. This property simply follows A(n, m) = m (15) 2,c,d⌋ Θ n⌊2otherwise. from the fact that for evend the all-one vector is a codeword

(n)
of C. In particular we have the following: for all constantm ≥ 2. Here, we only prove the general case 2,c,d *Remark 3.10:* For evend ≥ 2, of q > 2. The case of q = 2 can be proved by a similar [] [] i

(n) (n)argument with the fact B(i) = [1 + (−1)]/2. Suppose that
E A (l) = E A (n − l) (13) 2,c,d 2,c,d(15) holds for2 ≤ m ≤ k with k ≥ 3, then for m = k + 1,

ω2,c,d(x) = ω2,c,d(1 − x). (14) A(n, k + 1) = A(n − 1, k + 1) min{k+1,d} () We close this section with a theorem on theasymptotic ∑ d + A(n − 1, k − i + 1)B(i) behavioroftheaverageweightdistributionforthesmall-i i=2 weight case. () ⌊(k−1)/2⌋ *Theorem 3.11:* For d ≥ 3 and constant weight l ≥ 1, = A(n − 1, k + 1) + Θ (n − 1)  []  0 c = 1 and l = 1 This asymptotic behavior implies that there exits a positive

(n)
E A (l) = 0 ( q = 2 and cl is odd integern₀ such that forn > n₀, q,c,d) −⌈(c−2)l/2⌉ Θ n otherwise. () n−1 ∑ ⌊(k−1)/2⌋ A(n, k + 1) = A(n0, k + 1) + Θ i *Proof:* Thetrick of the proof is to find a precise ap- (cn/d) cl i=n₀ proximation ofcoef(g (x), x) in (2) and to prove it by () q,d ⌊(k+1)/2⌋ induction. For convenience, we define = Θ n. () △ (n) m A(n, m) = coef g (x), x. Thus (15) holds for allm ≥ 2. q,d Finally, it follows from Theorem 3.6 and (15) that After some algebraic manipulations, we have () [] n []n (n) l d() E A (l) = (cn)A(cn/d, cl) ∑ q,c,d (c−1)l

(n)di (q − 1)
g (x) = B(i)xcl q,d  i i=0  0 c = 1 and l = 1 =  0 ( q = 2 and cl is odd where) i i −⌈(c−2)l/2⌉ (q − 1) + (−1) (q − 1) Θ n otherwise B(i) =. q as desired. Then it is observed that *Remark 3.12:* The first and second cases of Theorem 3.11

||( )|have the following alternative proofs: If||c = 1 then the random||
|---|---|---|---|---|---|
|min {m,d} i=0|min {m,d}|(n) q,c,d q,n RM q,n CHK q,d,n/d|(n) q,c,d||CHK q,d,n/d|
||i=2|||LD 2,c,d,n|(n) 2,c,d|
||||||(n)|
||||||2,c,d|

∑ d code C, as the kernel of the reduced mappingf ◦ A(n + 1, m) = A(n, m − i)B(i) i F ◦ Σ, has the same weight distribution as the kernel of () f. In particular,C has no words of weight 1. If c ∑ d = A(n, m) + A(n, m − i)B(i). is odd then every column of the parity-check matrix of C i (i.e. the transformation matrix of F) has odd weight. This Hence we have implies that the all-one vector is in the dual code of C and A(n, 0) = A(1, 0) = 1 hence that all codewords have even weight.

A(n, 1) = A(1, 1) = 0 () IV.P ROPERTIES OF THE FUNCTION δq,d(x) d A(n, 2) = A(n − 1, 2) + A(n − 1, 0)B(2) As an important step towards understanding the function 2 ωq,c,d(x), weanalyzeinthissectionthefunction δq,d(x) d(d − 1)(q − 1) = A(n − 1, 2) + definedby(6).Theproofsoflemmasinthissectionare 2 () presented in Appendix D. 2 ⌋ = Θ n⌊2In the sequel, we shall frequently use the following substi- () tution to facilitate the analysis: d A(n, 3) = A(n − 1, 3) + A(n − 1, 1)B(2) 2 △ qx △ qxˆ () z = 1 −, zˆ = 1 −. (16) d q − 1 q − 1 + A(n − 1, 0)B(3) 3 Note that this transform is bijective and strictly decreasing, so d(d − 1)(d − 2)(q − 1)(q − 2) we have = A(n − 1, 3) + (q − 1)(1 − z) (q − 1)(1 − zˆ) { x =, xˆ = (17) 0 ( q = 2 q q ) = ⌊ ⌋ Θ n otherwise. and z, zˆ ∈ [−1/(q − 1), 1] as x, xˆ ∈ [0, 1].

Our first goal is to study the zeros of the partial derivative ofδq,d(x, xˆ) with respect to xˆ. *Lemma 4.1:* For the functionδq,d(x, xˆ) defined by (7),

∂δq,d(x, xˆ) ∂D(x‖xˆ) dρq,d(ˆx) = d + (18) ∂xˆ ∂xˆ dxˆ qd(ζq,d(ˆz) − z) = − (19) (1 − zˆ)[1 + (q − 1)ˆz]

where △ zˆ + ˆz d−1 + (q − 2)ˆz d ζ q,d(ˆz) =d. (20) 1 + (q − 1)ˆz

Lemma4.1showsthatthezerosof ∂δq,d(x, xˆ)/∂xˆ are determined by the equationζq,d(ˆz) − z = 0. We therefore proceed to analyze the functionζq,d(ˆz). The next three lemmas give the properties ofζq,d(ˆz). *Lemma 4.2:* For q ≥ 2 and d ≥ 3, the function ζq,d(ˆz) is continuously differentiable on[−1/(q−1), 1] and its derivative is positive on(−1/(q − 1), 1). *Lemma 4.3:* For q ≥ 2 and d ≥ 1,

d−1 z (1 − z)[1 + (q − 1)z] ζ q,d(z) − z =d(21) 1 + (q − 1)z

{ ()2 1d− 1 q = 2 and d is odd(22a) ζ q,d− =1 q − 1 − q−1 otherwise(22b)

ζ q,d(0) = 0 (23)

ζ q,d(1) = 1. (24)

*Lemma 4.4:* Let  2   − 1 q = 2 and d is odd (25a) △ d z₁ = 1   − otherwise. (25b) q − 1

The equationζq,d(ˆz) − z = 0 has a unique solution zˆ₁ = ˆz₁(z) in [−1/(q − 1), 1] for each z ∈ [z₁, 1] and has no solution in [−1/(q − 1), 1] for z < z₁. The solutionzˆ₁(z) is continuous on [z₁, 1] andiscontinuouslydifferentiableon (z₁, 1); its ′ derivative is positive on(z₁, 1). Moreover, zˆ₁(z) ∈ Iq,d(z), where 1   {−q−1 } z = z₁  1   (−, z) z ∈ (z₁, 0) and d is odd   q−1  ′△ (z, 0) z ∈ (z, 0) and1d is even I q,d(z) =   {0} z = 0       (0, z) z ∈ (0, 1)  {1} z = 1.

For the functionδq,d(x) defined by (6), we have  ln q x = 0 (27a)       ρq,d(1) x = 1 (27b)      −∞ x ∈ (1 − 1, 1), q = 2,   d and d is odd (27c) δ q,d(x) =  ()   11   ln(2d) − dH² x = 1 − d ,q = 2,   d      and d is odd (27d)  δ q,d(x, xˆ₁) x ∈ (0, x₁) (27e)

where ρq,d(x) is defined by (8) and xˆ₁ = ˆx₁(x) is the unique root in(0, 1) of the equation

∂δq,d(x, xˆ) ∂xˆ = 0 (28)

solved for xˆ as a function of

x. The function xˆ (x) is continu-1
ously differentiable on(0, x ) and its derivative is positive on1 (0, x ). Moreover,1limx→0+ xˆ (x) = 0,1lim x→x − xˆ (x) = 1,1 1 and xˆ (x) ∈ I1 q,d(x), where  1 1  (x, 1 − q ) x ∈ (0, 1 − q )    {1 −1} x = 1 −1 I (x) = △ q q q,d 1  (x, 1)  x ∈ (1 −q, x ) and1d is odd    (1 − 1, x) x ∈ (1 − 1, x₁) and d is even. q q

The functionδq,d(x) is continuous on [0, x₁] and is continu- ously differentiable on(0, x ), in which case,1

dδq,d(x) x(1 − xˆ₁) = d ln. (29) dx xˆ₁(1 − x)

*Proof:* At first, Lemmas 4.1, 4.2, and 4.3 show that

∂δq,d(0, xˆ) ∂xˆ > 0 ∀xˆ ∈ (0, 1)

and ∂δ (1, xˆ) q,d < 0 ∀xˆ ∈ (0, 1). ∂xˆ Therefore we have

δ q,d(0) = xˆ lim →0+ δ q,d(0, xˆ) = ρq,d(0)

and δ q,d(1) = lim δq,d(1, xˆ) = ρq,d(1). xˆ→1− This concludes (27a) and (27b). A similar argument also shows that for oddd [) ∂δ2,d(x, xˆ) 1 < 0 ∀x ∈ 1 −, 1, xˆ ∈ (0, 1) ∂xˆ d

so that

δ 2,d(x) = xˆ lim →1− δ 2,d(x, xˆ)

x) d

|= −dH (x) +|lim ln 1 + (1 − 2ˆ|||
|---|---|---|---|
|2|x ˆ→1|d(1−x)||
||x ˆ →1||d−1 d(1−x)−1|
|2||x ˆ→1|d−1−dx|

2 − d(1−x) (1 − xˆ) 2(1 − 2ˆx) = −dH₂(x) + ln lim −(1 − x)(1 − xˆ)

= −dH (x) + ln (1 − x) lim −(1 − xˆ)

to analyze the functionδq,d(x). *Theorem 4.5:* Letq ≥ 2, d ≥ 3, and { △ 1 − q = 2 and d is odd (26a) x₁ = d otherwise. (26b)

Equipped with Lemmas 4.1–4.4, we are now in a position

which yields (27c) and (27d). Ifq = 2 and d is odd then For x ∈ (0, x₁), Lemma 4.4 shows that there is a unique (

1)
(1) c
zˆ₁ = zˆ₁(z) ∈ (−1/(q − 1), 1) such that ζq,d(ˆz₁) = z = ωq,c,d1 − = (1 − c) H₂ + ln d (33) d d d 1−qx/(q −1). Let xˆ₁ = (q −1)(1−zˆ₁)/q, which is essentially a function of

x. Then it follows from Lemma 4.1 and 4.2 that and ()
1 ∂δq,d(x, xˆ) ωq,c,d(x) = −∞ ∀x ∈ 1 − d, 1. (34) < 0 ∀xˆ ∈ (0, xˆ₁) ∂xˆ Lemma 5.1 is an easy consequence of Theorem 4.5, so its and proof is left to the reader. Next, let us calculate the first-order ∂δq,d(x, xˆ) > 0 ∀xˆ ∈ (ˆx₁, 1). derivative ofωq,c,d(x). ∂xˆ *Lemma 5.2:* For the functionωq,c,d(x) defined by (5) with Therefore, δq,d(x) = δq,d(x, xˆ₁), whichconcludes(27e). q ≥ 2, c ≥ 1, and d ≥ 3, if x belongs to the case (27e) then Furthermore, Lemma 4.4 shows thatxˆ₁(x) is continuously dif- [() c−1()c]

ferentiable on(0, x₁) and its derivative is positive on (0, x₁). It dωq,c,d(x) = ln x 1 − xˆ₁ + ln(q − 1) also shows thatlimx→0+ xˆ₁(x) = 0 and lim x→x − xˆ₁(x) = 1, dx 1 − x xˆ₁ 1 (35) and thatxˆ₁(x) ∈ Iq,d(x). Basedontheaboveanalysis,itisclearthat δq,d(x) is which can be further expressed as   continuously differentiable on(0, x₁). Furthermore, equation  [ d−1]c−1  dωq,c,d(x) 1 + (q − 1)ˆz₁ 1 − zˆ₁ (27e) combined with Lemma B.1 gives (29). = ln d−1 Finally, let us show thatδq,d(x) is continuous at the end- dx  1 − zˆ₁ 1 + (q − 1)ˆz₁ 

points of the interval. Note thatδq,d(x) is the infimum of a col-(36) lection of continuous functions, so it is upper semi-continuous. where xˆ₁ is defined by (28) andzˆ₁ = 1 − qxˆ₁/(q − 1). Then it suffices to show thatlimx→0+ δq,d(x) ≥ δq,d(0) and The next lemma gives the value ofdωq,c,d(x)/dx at some lim x→x − δq,d(x) ≥ δq,d(x₁). Recall that limx→0+ xˆ₁(x) = 0 special points. 1 and lim x→x − xˆ₁(x) = 1, so we have *Lemma 5.3:* Letq ≥ 2, d ≥ 3, and x₁ be defined by (26). 1  ∞ c = 1 (37a) lim + δ q,d(x) ≥ lim + ρq,d(ˆx₁(x)) = ln q dωq,c,d(x) x→0 x→0 lim = ln(d − 1) c = 2 (37b) x→0+dx  lim − δ q,d(x) ≥ lim − ρq,d(ˆx₁(x)) = ρq,d(1) −∞ c ≥ 3. (37c) x→x1x→x1∣∣ dωq,c,d(x) ∣ ∣ = 0. (38) and dx x=1−1 [ d]q 1 + (1 − 2ˆx₁(x)) Ifq = 2 and d is even then lim δ2,d(x) ≥ lim −dH₂(x) + ln x→x − 1x→x − 1 1 − xˆ₁(x)  −∞ c = 1 (39a) ()  1 dωq,c,d(x) = ln(2d) − dH₂ lim − =− ln(d − 1) c = 2 (39b) dx→1 dx ∞ c ≥ 3. (39c) for oddd. The proof is complete. Ifq 6= 2 or d is odd then In Fig. 1 we give an illustration of the graphs ofδq,d(x) for (q, d) = (2, 5), (q, d) = (2, 6), (q, d) = (3, 5), and (q, d) = lim dωq,c,d(x) = −∞. (40) (3, 6).x→x − 1 dx

To have more insights intoωq,c,d(x), we proceed to analyze

V. P ROPERTIES OF THE FUNCTION ωq,c,d(x)
the second-order derivative ofωq,c,d(x). Since 2 ()

|||2 q,c,d|q,c,d|
|---|---|---|---|
|q,c,d||2||

In this section, we proceed to analyze the properties of the d ω (x) d dω (x) dzˆ₁ = · (41) functionω (x) defined by (5). Since LDPC codes are trivial dx dzˆ₁ dx dx when c > d, we shall sometimes assume c ≤ d to exclude and we note that trivial cases. The proofs of lemmas in this section are presented dzˆ₁ q dxˆ₁ in Appendix E. = − At first, we calculate the value ofωq,c,d(x) at some special dx q − 1 dx

points. isnegativeon (0, x₁), ourtaskisnowtocalculatethe *Lemma 5.1:* Letq ≥ 2, c ≥ 1, and d ≥ 3. derivatived(dωq,c,d(x)/dx)/dzˆ₁. *Lemma 5.4:* For the functionωq,c,d(x) defined by (5) with ωq,c,d(0) = 0. (30) q ≥ 2, c ≥ 1, and d ≥ 3, if x belongs to the case (27e) then () () () c d dωq,c,d(x) ωq,c,d1 − = 1 − ln q. (31) q d dzˆ₁ dx

c c = (1 − zˆ qξq,c,d(ˆz₁) (42) ωq,c,d(1) = ln(q − 1) + ρq,d(1) − ln q. (32) d−1

)[1 + (q − 1)ˆz][1 + (q − 1)ˆz
d−1] d d

ON THEORY (VERSION: OCTOBER 26, 2018) ACCEPTED FOR PUBLICATION IN IEEE TRANSACTIONS ON INFORMATI

|1.2||
|---|---|
|ln3 1|q = 2, d = 5 q = 2, d = 6 q = 3, d = 5 q = 3, d = 6|
|0.8 ln2 0.6 0.4 0.2 0 −0.2 0 0.1 0.2 0.3 0.4|0.5 0.6 0.7 0.8 0.9 1|

(q, d) = (3, 6).

Fig. 1.The graphs of δq,d(x) for (q, d) = (2, 5), (q, d) = (2, 6), (q, d) = (3, 5), and

where

d ∑ −3 ξ q,c,d(ˆz) = zˆ i − [(c − 1)(d − 1) − 1]ˆz d−2

i=0 − (q − 1)[(c − 1)(d − 1) − 1]ˆz d−1

2 ∑ d−3 + (q − 1) zˆ i

. (43)
i=d

When c = 1, equation (42) reduces to () d dω2,c,d(x) q =. (44) dzˆ₁ dx (1 − zˆ₁)[1 + (q − 1)ˆz₁]

We go on to analyze the functionξq,c,d(ˆz) for q ≥ 2, c ≥ 2, and d ≥ max{c, 3}. *Lemma 5.5:* Ford ≥ 3, the function ξ2,2,d(ˆz) is positive on (−1, 1). For q ≥ 3 and d ≥ 3, the function ξq,2,d(ˆz) has a positive zerozˆ₂ in (−1/(q − 1), 1), and ξq,2,d(ˆz) is positive on (−1/(q − 1), zˆ₂) and negative on (ˆz₂, 1). For d ≥ c ≥ 3 with d even, the function ξ2,c,d(ˆz) has one zerozˆ₂ in(0, 1) and the other zero zˆ2′in(−1, 0), and ξ2,c,d(ˆz) is positive on(ˆz2′, zˆ₂) and negative on (−1, zˆ2′) ∪ (ˆz₂, 1). Forq ≥ 2 and d ≥ c ≥ 3 with q 6= 2 or d odd, the function ξ q,c,d(ˆz) has a positive zero zˆ₂ in(−1/(q−1), 1), and ξq,c,d(ˆz) is positive on(−1/(q − 1), zˆ₂) and negative on (ˆz₂, 1). We are nowreadytogivethequalitativepropertiesof ωq,c,d(x). *Theorem 5.6:* Let q ≥ 2, c ≥ 1, d ≥ max{c, 3}, and x₁ be defined by (26). The functionωq,c,d(x) defined by (5) is continuous on [0, x₁] and is twice differentiable on (0, x₁). Ifc = 1, then ωq,c,d(x) is concave on (0, x₁), and it is strictly increasing on(0, 1 − 1/q) and strictly decreasing on (1 − 1/q, x₁).

Ifc = 2, then ωq,c,d(x) is strictly increasing on (0, 1 − 1/q) and strictly decreasing on(1 − 1/q, x₁). Moreover, if q = 2, it is concave on(0, x₁); otherwise, it is convex on (0, x₂) and concave on (x₂, 1), where x₂ ∈ (0, 1 − 1/q). Ifc ≥ 3, q = 2, and 1 d is even, then ωq,c,d(x) is symmetric about the axis 1 x = 2. It is convex on 1 (0, x₂) and concave on (x₂, 2 ) for some x₂ ∈ (0, 2 ); it is strictly decreasing on 1 (0, x₃) and strictly increasing on (x₃, 2 ), where 1 x₃ ∈ (0, x₂); consequently, it has a unique zerox₀ in (0, 2], where x₀ ∈ (x₃, 1], and it is negative on (0, x₀) and positive on (x₀, 1 ). For other cases, the function 2 ω (x) is convex on (0, x 2 ) q,c,d 2 and concave on (x₂, x₁), where x₂ ∈ (0, 1 − 1/q); it is strictly decreasing on (0, x₃) ∪ (1 − 1/q, x₁) and strictly increasing on (x₃, 1 2 ), where x₃ ∈ (0, x₂); consequently, it has a unique zerox₀ in (0, 1 − 1/q], where x₀ ∈ (x₃, 1 − 1/q], and it is negative on(0, x₀) and positive on (x₀,1−1/q). To provide an intuitive illustration ofωq,c,d(x) in each case, the graphs ofωq,c,d(x) for typical values of (q, c, d) are plotted in Figs. 2–5. *Sketch of Proof:* Theproofisdirect, and itdepends on Remark 3.10, Theorem 4.5, Lemmas 5.1–5.5, and identity (41). Here, we only give the proof of the last paragraph of statements. Lemma 5.5 and identity (41) show thatωq,c,dis convex on (0, x₂) and concave on (x₂, x₁), where x₂ ∈ (0, 1 − 1/q). Furthermore, Lemmas 5.1 and 5.3 show that () () 1 c ωq,c,d(0) = 0, ωq,c,d1 − = 1 − ln q ≥ 0 q d

and ∣ dωq,c,d(x) = −∞, dωq,c,d(x) ∣∣ lim = 0. x→0+dx dx ∣ x=1−q

||c = 1 c = 2 c = 3||
|---|---|---|
|0.3 0.4 0.5 0.6 0.7 0.8|0.9|1|

0.6
0.5
0.4
0.3
0.2
0.1 0
−0.1 0 0.1 0.2

Fig. 2.The graphs of ω2,c,5(x) for c = 1, c = 2, and c = 3.

||c = 1 c = 2 c = 3||
|---|---|---|
|0.3 0.4 0.5 0.6 0.7 0.8|0.9|1|

0.6
0.5
0.4
0.3
0.2
0.1 0
−0.1

0.1 0.2
Fig. 3.The graphs of ω2,c,6(x) for c = 1, c = 2, and c = 3.

0.9
c = 1 c = 2

0.8 c = 3
0.7
0.6
0.5
0.4
0.3
0.2
0.1 0
−0.1 0 0.1 0.2 0.3 0.4 0.5 0.6 0.7 0.8 0.9 1

Fig. 4.The graphs of ω3,c,5(x) for c = 1, c = 2, and c = 3.

1 c = 1 c = 2 c = 3

0.8
0.6
0.4
0.2 0
−0.2

0.1 0.2 0.3 0.4 0.5 0.6 0.7 0.8 0.9
Fig. 5.The graphs of ω3,c,6(x) for c = 1, c = 2, and c = 3.

[] Therefore,thederivative dωq,c,d(x)/dx hasauniquezero + c x ln 1 + xˆ − xˆ + q(d − 1) xˆ² x₃ in (0, 1 − 1/q), where x₃ ∈ (0, x₂); itisnegative on xˆ 1 − xˆ 2(q − 1) (0, x₃) ∪ (1 − 1/q, x₁) andpositiveon (x₃, 1 − 1/q). In = (c −[1)x ln x + x ln(q − 1)] other words, the functionωq,c,d(x) is strictly decreasing on 1 xˆ² q(d − 1)2 + c x ln + + xˆ (0, x₃) ∪ (1 − 1/q, x₁) and strictly increasing on (x₃, 1 − 1/q). xˆ 1 − xˆ 2(q − 1) The last statement about the unique zero in(0, 1−1/q) clearly(b) follows. = (c − [ 1)x ln x + x ln(q − 1)] *Remark 5.7:* The zero x₀ in Theorem 5.6 just corresponds + c 1 x ln d − 1 + x + qx to the normalized minimum distance of LDPC codes, in an 2 x (d − 1)(1 − xˆ) 2(q − 1) average and asymptotic sense. It is in fact a function ofq, c,(c) ( c) ( c ) < − 1 x ln x + ln(q − 1) + ln(d − 1) + 3c x and d, so we denote it by x₀(q, c, d). We note that 2 2

lim ρq,d(x) = 0 ∀x ∈ (0, 1) where (a) follows from Lemma A.2 andln x ≤ x − 1, (b) from d→∞ (47), and (c) follows fromq ≥ 2, d ≥ 2, and x < ˆ 1/q.

and hence for anyr ∈ (0, 1], Now, let us present the main result on the minimum distance of individual codes in a regular LDPC code ensemble. lim x₀(q, ⌈rd⌉, d) = x0,q,r *Theorem 6.2:* For any code C⊆Fn q, we denote its mini- d→∞ mum distance by dmin(C). Then for q ≥ 2, d ≥ c ≥ 3, l₀ ≥ 1, where x0,q,ris the solution of Hq(x) − r ln q = 0 in (0, 1 − and α ∈ (0, 1 − 1/q), 1/q). The detailed proof is left to the reader. Note that x0,q,r{}

(n)
as well as the equation Hq(x) − r ln q = 0 is closely related to P l₀ ≤ dmin(Cq,c,d) ≤ nα the so-called asymptotic Gilbert-Varshamov (GV) bound over ( −⌈(c−2)(l0+∆)/2⌉ ) ( 3nω q,c,d(α) ) ≤ Θ n + Θ n²e (48) finite fields [14, pp. 94–95]. This implies that regular LDPC codes with largec and d achieve the GV bound. where { △ 1 q = 2 and cl₀ is odd ∆ = (49) VI.M INIMUM DISTANCE OF LDPC C ODES 0 otherwise.

Though we have shown in Remark 5.7 that regular LDPC *Proof:* Since the minimum distance of a linear code is

code ensembles are asymptotically good, we are more inter- the minimum weight of its nonzero codewords, we have {} ested in the performance of individual codes of finite length. In P l ≤ d (C

(n) ) ≤ nα
0 min q,c,d this section, we shall investigate the minimum distance of an   individual code in a regular LDPC code ensemble. To achieve ⌊⋃nα⌋{}

(n)
this goal, we first establish an important inequality. ≤ P Aq,c,d(l) ≥ 1 2   *Theorem 6.1:* For q ≥ 2, c ≥ 1, d ≥ 2, and x ∈ (0, 1/q),l=l0 ( c) ⌊ ∑ nα⌋{} ωq,c,d(x) < − 1 x ln x + κq,c,dx (45) ≤ P A(n)(l) ≥ 1 2 q,c,d l=l₀ where ⌊nα⌋ △ c(a) ∑ E[] κq,c,d= ln(q − 1) + ln(d − 1) + 3c. (46) ≤ A

(n)
(l)
2q,c,d *Proof:* Put √ l=l0

x (b) l ∑ 0 +3()⌊nα⌋ ∑ () △ −⌈(c−2)l/2⌉1nωq,c,d(l/n) xˆ =. (47) ≤ Θ n + Θ n²e d − 1 l=l₀ l=l₀+4 Then for anyx ∈ (0, 1/q²), xˆ ∈ (0, 1/q) ⊂ (0, 1 − 1/q). (c)( −⌈(c−2)l /2⌉ ) ( 3nω ((l +4)/n) ) ≤ Θ n 0 + Θ n²eq,c,d 0 According to the definition (5) ofωq,c,d(x), we have ( 3 ) + Θ n²e nωq,c,d(α) ωq,c,d(x) c

(d)() ()
≤ Hq(x) + (δq,d(x, xˆ) − ln q)−⌈(c−2)l0/2⌉ 2 3−(c−2)(l 0 +4)/2 d ≤ Θ n + Θ n n = Hq(x) + cD(x‖xˆ) (3) [ ()()] + Θ n²e nωq,c,d(α) d c 1 1 qxˆ + ln + 1 − 1 −(e)() ( 3 ) d q q q − 1 ≤ Θ n −⌈(c−2)l0/2⌉ + Θ n²e nωq,c,d(α)

(a)
[ q(d − 1)] ≤ Hq(x) + cD(x‖xˆ) + c −xˆ + xˆ² where (a) follows from Markov’s inequality, (b) from Theo- 2(q − 1) rems 3.6 and 3.11, Lemma A.1, and the inequalityl(n − l) ≤ = −(c − 1)H₂(x) + x ln(q − 1) n²/4, (c) from Theorem 5.6, which shows that ω (x) with [] q,c,d q(d − 1) x ∈ [(l₀ + 4)/n, α] is upper bounded by either ω q,c,d((l₀ + + c x ln + (1 − x) ln − xˆ + xˆ xˆ 1 − xˆ 2(q − 1) 4)/n) or ωq,c,d(α), (d) from Theorem 6.1, and (e) follows < (c − 1)x ln x + x ln(q − 1) from c ≥ 3.

The above inequality holds in all cases. Whenq = 2 and is clear that Φn(C) = 1 is equivalent to dmin(C ) ≥ 2, so it

(n)
follows from (51) that cl₀ is odd, Theorem 3.11 shows that E[A q,c,d (l₀)] = 0, so we can further improve this inequality by simply replacingl₀ [] {}

(n) (n)
withl₀ + 1. The proof is complete. E Φn(Cq,c,d) = P dmin(Cq,c,d)≥2 = Θ(1). *Remark 6.3:* If takingl₀ = 1 in Theorem 6.2, we have {} Consequently, we have

(n)
P dmin(C q,c,d ) ≤ nα { ∣} () ( 3 ) P d min(C

(n) ) ≤ nα∣∣ Φn(C
(n)
) = 1
−⌈(c−2)/2⌉2nωq,c,d(α) 2 q,c,d q,c,d

|n|e|. (50)||( )|(|)|
|---|---|---|---|---|---|---|
|q,c,d (n) min q,c,d|−⌈(c−2)/2⌉|||2−c|nω ONCLUSION|(α)|

≤ Θ + Θ n 2−c3nωq,c,d(α) ≤ Θ n + Θ n²e. (54) Recall thatω (x) has a unique zero x₀(q, c, d) in (0, 1 − 1/q), so we have {} () VII.C P d (C) ≤ nα ≤ Θ n (51)

forany α ∈ (0, x₀(q, c, d)). Moreover,when c ≥ 5, it We provided a thorough analysis of the average weight dis- follows from the Borel-Cantelli lemma that for anyǫ > 0, tributions of regular LDPC code ensembles over finite fields. the probability of the event Theprimaryresultsare Theorems3.11,4.5,5.6,and6.1, {} which are important for any analysis of regular LDPC codes 1(n) based on the weight distribution. Furthermore, we proved a dmin(C q,c,d ) ≤ x₀(q, c, d) − ǫ for infinitely many n n generalresult(Theorem6.2)ontheminimumdistanceof

is zero, so that individual codes ina regular LDPC code ensemble, which {} includes all previous results as special cases. 1(n) P lim inf dmin(Cq,c,d) ≥ x₀(q, c, d) = 1. (52) n→∞ n ACKNOWLEDGMENT The formula (50), for q = 2, was first proved (in a slightly stronger form for a different ensemble) by Gallager in [1]. As The authors would like to thank the anonymous reviewers for the general case of q > 2, Bennatan and Burshtein first for their helpful comments. showed in [8] that there exists someγ > 0 such that {} ()

(n) 1−c/2APPENDIX A
P dmin(C q,c,d ) ≤ nγ ≤ Θ n SOME USEFUL INEQUALITIES which is clearly weaker than (51). In [9], Como and Fagnani proved a result similar to (51). *Lemma A.1:* For any n ∈ N, define the function

Compared withprevious results,theadvantage of Theo- △ ( l ) 1

(n)
rem 6.2 is that we can use it to obtain results much better βn(l) = H₂ n − n ln l ∀l = 0, 1,..., n. than (50) by removing bad codes from the original ensemble. This viewpoint is formulated in the following theorem, which Then is an easy consequence of Theorem 6.2. () 1 l(n − l)−1 *Theorem 6.4:* Let q ≥ 2, d ≥ c ≥ 3, l₀ ≥ 2, and α ∈ 0 ≤ βn(l) ≤ ln + Θ(n) ∀0 < l < n (0, 1 − 1/q). Let Φn: {All subspaces of F n q} → {0, 1} be a 2n n

test function of linear codes such that for every linear code and β (0) = β (n) = 0.

(n) n n
C,n min n

|Φ (C ) = 1 implies||d (C) ≥ l₀. If|E[Φ|(C )]|||
|---|---|---|---|---|---|---|
|n||min||n q,c,d|||
||(n)|(n)||||n λ|
|min|q,c,d −⌈(c−2)(l|n q,c,d +∆)/2⌉|nω|(α)|||

q,c,d ≥ *Sketch of Proof:* Using Stirling’s approximation: Θ(φ(n)) for some map φ(n) : N → [0, 1], then ∣ √ ( n ) {}n ∣ n! = 2πn e ∀n ≥ 1 P d (C) ≤ nα∣ Φ (C) = 1 e ( 0 ) ( 3 q,c,d ) n n²e where 1/(12n + 1) < λn< 1/(12n). ≤ Θ + Θ (53) φ(n) φ(n) *Lemma A.2:* For allx ∈ [0, 1] and d ∈ N,

where ∆ is defined by (49). (1 − x) d ≤1− dx + d(d − 1) x². The proof is left to the reader. 2 *Remark 6.5:* A simpletestfunctioncanbedefinedby *Proof:* The inequality holdstrivially for d = 1. Now checkingwhethertheparity-checkmatrixofalinearcode suppose d ≥ 2, then by Taylor’s theorem, it follows that contains all-zero columns. Then Φn(C ) = 1 if and only if the parity-check matrix of C contains no all-zero columns. It dd(d − 1)(1 − y) d−2 (1 − x) = 1 − dx + x 2−c

|When q = 2 and|c is odd, we have a tighter upper bound|Θ(n) +||
|---|---|---|---|
|Θ(n e|). But for simplicity, we ignore this special case.|||

nω2,c,d (α) for some y ∈ [0, x]. This thus concludes the proposition.

APPENDIX B The continuity is obvious, even ifq = 2 and d is odd. Our DERIVATIVES OF Hq(x), D(x‖xˆ), AND ρq,d(x) task is now to show thatf (ˆz) is positive on (−1/(q − 1), 1).

*Lemma B.1:* The proof consists of two parts. First, we show thatf (ˆz) is positive on [0, 1). Note that the dHq(x) 1 − x coefficients off (ˆz) have signs +, +, +, −, −. By Theorem C.1 = ln + ln(q − 1) dx x it follows thatf (ˆz) has a unique positive zero. Since f (0) = ∂D(x‖xˆ) x(1 − xˆ) 1>0 and f (1) = 0, it is clear that f (ˆz) > 0 for all zˆ ∈ [0, 1). = ln ∂x xˆ(1 − x) Second, we show that f (ˆz) is also positive on (−1/(q − ∂D(x‖xˆ) xˆ − x 1), 0) for both odd and even d. = ∂xˆ xˆ(1 − xˆ) For odd d we have ()d−1 qx f (−zˆ) = 1 − (d − 1)ˆz d−2 + (q − 2)dzˆ d−1 qd 1 −

|dρ|(x)||q − 1||||
|---|---|---|---|---|---|---|
|q,d|||||d|2d−2|
|||||d|||
||||||d−2||
|q,d|||||||
|||PPENDIX|||d−2||
||ESCARTES|ULE OF|IGNS||d−2||

= − (). + (q − 1)(d − 1)ˆz − (q − 1)ˆz. dx qx 1 + (q − 1) 1 − Ifq ≥ 3 then for all zˆ ∈ (0, 1/(q − 1)), q − 1

f (−zˆ) > 1 − (d − 1)ˆz where ρ (x) is defined by (8). The proof is left to the reader. (d − 1) >1− (q − 1)

A C 2 d−1 − (d − 1) ≥ D ’ R S (q − 1)

*Theorem C.1 (Descartes’ Rule of Signs):* If the terms of a ≥ 0.

univariate polynomial with realcoefficients are orderedby As for the case ofq = 2, f (−zˆ) reduces to ascending or descending variable exponent, then the number 1 − (d − 1)ˆz d−2 + (d − 1)ˆz d − zˆ 2d−2 of positive roots of the polynomial (counted with their multi- plicities) is either equal to the number of sign changes between which can be factorized as consecutive nonzero coefficients, or less than it by a multiple [] of 2. Sincethenegative roots ofthepolynomialequation 3 d ∑ −3 (i + 1)(i + 2) (i 2d−5−i) f (x) = 0 are positive roots of the equation f (−x) = 0, the (1 − zˆ) 2 zˆ + ˆz (55)

rule can be readily applied to help count the negative roots as i=0

well. so thatf (−zˆ) > 0 for all zˆ ∈ (0, 1). For a proof we refer the reader to [15]. For evend we have

f (−zˆ) = 1 + (d − 1)ˆz d−2 − (q − 2)dzˆ d−1 APPENDIX Dd 2d−2 PROOFS OF LEMMAS IN SECTION IV − (q − 1)(d − 1)ˆz − (q − 1)ˆz

> zˆ d−2 + (d − 1)ˆz d−2 − (q − 2)d zˆ d−2 *Proof of Lemma4.1:* Bydefinition(7),(18)follows q − 1 immediately. Using Lemma B.1 and the change of variables d − 1d−21d−2 (16) yields − zˆ − zˆ q − 1 q − 1 ∂δq,d(x, xˆ) qd(z − zˆ) qdzˆ d−1 = 0 = − d ∂xˆ (1 − zˆ)[1 + (q − 1)ˆz] 1 + (q − 1)ˆz d−1 d for allzˆ ∈ (0, 1/(q − 1)). The proof is complete. qd{z − zˆ − zˆ − [(q − 2) − (q − 1)z]ˆz} *Sketch of Proof of Lemma 4.3:* Identity (21) is proved = d (1 − zˆ)[1 + (q − 1)ˆz][1 + (q − 1)ˆz] by a straightforward argument using definition (20). Equations qd(ζq,d(ˆz) − z) (22b), (23), and (24) are immediate consequence of (21). As = − (1 − zˆ)[1 + (q − 1)ˆz] for (22a), we note that (21) withq = 2 and odd d gives d−1 ∣ as desired. z (1 − z) ∣ 2 ζ 2,d(−1) + 1 = ∣ = d *Proof of Lemma4.2:* To prove the lemma,wehave 1 − z + z² − · · · + zd−1 ∣ z=−1 toshowthatthederivativeof ζq,d(ˆz) iscontinuouson [−1/(q − 1), 1] and positive on (−1/(q − 1), 1). Some tedious so thatζ2,d(−1) = 2/d − 1. manipulation yields *Proof of Lemma 4.4:* Lemmas 4.2 and 4.3 show that the range ofζq,d(ˆz) for zˆ ∈ [−1/(q − 1), 1] is ′f (ˆz) [ ()] ζ q,d(ˆz) =d 2 1 [1 + (q − 1)ˆz] ζ q,d−, ζq,d(1) = [z₁, 1] q − 1 where

|||||and therefore|the equation||ζ (ˆ z) − z|= 0 has a unique|
|---|---|---|---|---|---|---|---|---|
|d−2 2d−2||d−1||d|||2,d||

△ f (ˆz) = 1 + (d − 1)ˆz + (q − 2)dzˆ − (q − 1)(d − 1)ˆz solution in[−1/(q − 1), 1] for each z ∈ [z₁, 1] and has no

− (q − 1)ˆz. solution in[−1/(q − 1), 1] for z < z₁.

ON THEORY (VERSION: OCTOBER 26, 2018) ACCEPTED FOR PUBLICATION IN IEEE TRANSACTIONS ON INFORMATI

Since ζq,d(ˆz) is continuously differentiable on [−1/(q −

1), 1] and its derivative is positive on (−1/(q−1), 1), it follows from the inverse function theorem that the solutionzˆ₁(z) is continuously differentiable on(z₁, 1) and its derivative is also positive on(z₁, 1). The continuity of zˆ₁(z) at endpoints also follows. Moreover, Lemma 4.3 shows that
1 1 ζ q,d(z) = z₁ ifz = −q− 1 1 ζ, 0) and d is odd q,d(z) > z ifz ∈ (−q− 1 1 ζ q,d(z) < z ifz ∈ (−q−, 0) and d is even ζ q,d(z) = 0 ifz = 0 ζ q,d(z) > z ifz ∈ (0, 1) ζ q,d(z) = 1 ifz = 1. ′ This implies thatzˆ₁(z) ∈ Iq,d(z).

APPENDIX E PROOFS OF LEMMAS IN SECTION V

*Proof of Lemma 5.2:* Definition (5) and equation (29) *Proof of Lemma 5.5:* Since ξq,c,d(0) = 1, it suffices to show that dωq,c,d(x) dHq(x) x(1 − xˆ₁) = + c ln dx dx xˆ₁(1 − x)

(a) 1 − x x(1 − xˆ₁) = ln + ln(q − 1) + c ln x xˆ₁(1 − x) [() ()]
c−1 c x 1 − xˆ₁ = ln + ln(q − 1) 1 − x xˆ₁

where (a) follows from Lemma B.1. By Lemma 4.1, equation (28) is equivalent toζq,d(ˆz₁)−z = 0, where z = 1−qx/(q−1) andzˆ₁ = 1−qxˆ₁/(q−1). After some manipulations, we obtain

x 1 − z 1 − zˆ1d−1 = = xˆ₁ 1 − zˆ₁ 1 + (q − 1)ˆz 1d and

1 − x 1 + (q − 1)z 1 + (q − 1)ˆz1d−1 = =. 1 − xˆ₁ 1 + (q − 1)ˆz₁ 1 + (q − 1)ˆz 1d Then { []} c−1 dωq,c,d(x) (q − 1)(1 − xˆ₁) x(1 − xˆ₁) = ln dx xˆ₁ xˆ₁(1 − x)  []   1 + (q − 1)ˆ z 1 − zˆ d−1 c−1  1 1 = ln d−1.  1 − zˆ₁ 1 + (q − 1)ˆz₁ 

#### The proof is complete.

limx→0+ zˆ₁ = 1. Then equation (36) with c = 1 and c ≥ 3 gives (37a) and (37c), respectively. As forc = 2, we have

dωq,c,d(x) lim + x→0 dx {} d−1 [1 + (q − 1)ˆz₁](1 − zˆ1d−1) = lim ln zˆ →1−(1 − zˆ₁)[1 + (q − 1)ˆz₁] {} [1 + (q − 1)ˆz₁](1 + ˆz₁ + · · · + ˆz₁ d−2 )

|= lim||When q = 2, it reduces to||||
|---|---|---|---|---|---|
|zˆ →1|d−1|2,c,d|d−2||d 2d−2|

ln d−1 −1 + (q − 1)ˆz₁

#### = ln(d − 1).

By the symmetric property (Remark 3.10), we also obtain (39). From Theorem 4.5, it follows that (

1) q(1 − 1/q)
zˆ₁ 1 − = 1 − = 0. q q − 1

This together with equation (36) gives (38). Againby Theorem4.5,itfollowsthat lim x→x − zˆ₁ = −1/(q − 1). Then (36) with q 6= 2 or d odd gives (40). 1

*Proof of Lemma 5.4:* It follows from Lemma 5.2 that () d dωq,c,d(x) dzˆ₁ dx q q(c − 1)(d − 1)ˆz1d−2 = − d−1 d−1 [1 + (q − 1)ˆz₁](1 − zˆ₁) (1 − zˆ₁)[1 + (q − 1)ˆz₁] qξq,c,d(ˆz) = d−1 d−1. (1 − zˆ₁)[1 + (q − 1)ˆz₁][1 + (q − 1)ˆz₁]

This concludes (42), while the first equality withc = 1 gives (44).

determine all zeros ofξq,c,d(ˆz) in (−1/(q − 1), 1). The proof consists of two parts. First, wecheck the zeros of ξq,c,d(ˆz) in (0, 1). We note thatthecoefficientsof ξq,c,d(ˆz) havesigns +,..., +, −, −, +,..., +. By Theorem C.1 it follows that ξq,c,d(ˆz) has zero or two positive zeros. On the other hand,

ξ q,c,d(0) = 1, ξq,c,d(1) = −q(c − 2)(d − 1), ξq,c,d(∞) = ∞

and ′1 ξ q,2,d(1) = 2 (q − 2)(d − 1)(d − 2).

Then for q ≥ 2 and d ≥ c ≥ 3, ξq,c,d(ˆz) has a unique zero zˆ₂ in (0, 1). As for c = 2, ξq,2,d(ˆz) with q ≥ 3 has a unique ′ 2,d zerozˆ₂ in (0, 1) since ξq,2,d(1) = 0 and ξq,(1) > 0, while ξ (ˆz) has only one zero zˆ = 1 in (0, ∞) since ξ ′

(1) = 0
2,2,d 2,2,d (a zero of multiplicity2), so that ξ2,2,d(ˆz) is positive on (0, 1). Second, we check the zeros ofξ (ˆz) in (−1/(q − 1), 1). q,c,d To facilitate the analysis, we consider the function △ f q,c,d(ˆz) = (1 + ˆz)ξq,c,d(−zˆ).

Then the zeros ofξq,c,d(ˆz) in (−1/(q −1), 0) are just the zeros offq,c,d(ˆz) in (0, 1/(q − 1)). Ifd is odd, we have d−1 d−1 f q,c,d(ˆz) = (1 − zˆ)[1 + (q − 1)ˆz] + (c − 1)(d − 1)ˆz d−2 (1 + ˆz)[1 − (q − 1)ˆz]

Ifd is even, we have d−1 d−1 f q,c,d(ˆz) = (1 + ˆz)[1 − (q − 1)ˆz] d−2 − (c − 1)(d − 1)ˆz (1 + ˆz)[1 − (q − 1)ˆz]

= 1 − (c − 1)(d − 1)ˆz d−2

+ (q − 2)[(c − 1)(d − 1) − 1]ˆz d−1

+ (q − 1)(c − 1)(d − 1)ˆz d − (q − 1)ˆz 2d−2.

f (ˆz) = 1 − (c − 1)(d − 1)ˆz + (c − 1)(d − 1)ˆz − zˆ.

*Proof of Lemma 5.3:* From Theorem 4.5, it follows that which is clearly positive for allzˆ ∈ (0, 1/(q − 1)).

Since the coefficients off2,c,d(ˆz) have signs +, −, +, −, it follows from Theorem C.1that f2,c,d(ˆz) hasoneorthree positive zeros. Moreover, we note that

f 2,c,d(0) = 1, f2,c,d(1) = 0, f2,c,d(∞) = −∞

and f 2′,c,d(1) = 2(c − 2)(d − 1).

Then f2,c,d(ˆz) with c ≥ 3 has a unique zero zˆ2′in(0, 1), while f 2,2,d(ˆz) is positive on (0, 1) because of (55). Finally, let us show that fq,c,d(ˆz) is positive on (0, 1/(q − 1)) for q ≥ 3, c ≥ 2, and d ≥ max{c, 4}. Since q ≥ 3, c ≥ 2, d ≥ 4, and z < ˆ 1/(q − 1), d−2 2 f q,c,d(ˆz) > 1 − (c − 1)(d − 1)ˆz (1 − zˆ − 2ˆz) − zˆ d−1 − zˆ 2d−3 (56) d−2 > 1 − (c − 1)(d − 1)ˆz. (57)

For zˆ ∈ (0, 3 1], inequality (57) shows that ()d−2()4−2 2121 f q,c,d(ˆz) > 1 − (d − 1) ≥ 1 − (4 − 1) = 0. 3 3 1 2 For zˆ ∈ ( 3, 5], inequality (56) shows that

2 ()d−2()d−1()2d−3 4(d − 1) 2 2 2 f q,c,d(ˆz) > 1 − − − 9 5 5 5 ()2()3()5 422 2 2 ≥1− · 3 − − 9 5 5 5 893 =. 3125

For zˆ ∈ ( 5 2, 1 2 ), inequality (56) shows that

2 ()d−2()d−1()2d−3 7(d − 1) 1 1 1 f q,c,d(ˆz) > 1 − − − 25 2 2 2 ()2()3()5 721 1 1 ≥1− · 3 − − 25 2 2 2 171 =. 800 The proof is complete.

REFERENCES [1]R. G. Gallager, *Low-Density Parity-Check Codes*. Cambridge, MA: MIT Press, 1963.

codes: Asymptoticdistancedistributions,” *IEEETrans.Inf.Theory*, vol. 48, no. 4, pp. 887–908, Apr. 2002. [3]——,“Distancedistributionsinensemblesofirregularl ow-density

3159, Dec. 2003. [4]D.Burshteinand G.Miller,“Asymptoticenumerationmet hodsfor

1115–1131, Jun. 2004. [5]C. Di, T. J. Richardson, and R. L. Urbanke, “Weight distri bution of low- density parity-check codes,”*IEEE Trans. Inf. Theory*, vol. 52, no. 11, pp. 4839–4855, Nov. 2006. [6]V. Rathi,“On the asymptotic weight and stopping set dist ribution of regular LDPC ensembles,” *IEEE Trans. Inf. Theory*, vol. 52, no. 9, pp. 4212–4218, Sep. 2006. [7]M. F. Flanagan, E. Paolini, M. Chiani, and M. P. C. Fossorier, “Growth rateoftheweightdistributionofdoubly-generalized LDPC codes: General case and efficient evaluation,” in *Proc. IEEE Global Communi-* *cations Conf.*, Honolulu, HI, Nov. 2009, pp. 926–931.

[8]A. Bennatan and D. Burshtein, “On the application of LDPC codes toarbitrary discrete-memoryless channels,” *IEEE Trans. Inf. Theory*, vol. 50, no. 3, pp. 417–437, Mar. 2004. [9]G. Como and F. Fagnani, “Average spectra and minimum dist ances of low-density parity-check codes over abelian groups,”*SIAM J. Discrete* *Math.*, vol. 23, no. 1, pp. 19–53, 2008. [10]I. Andriyanova, V. Rathi, and J.-P. Tillich, “Binary we ight distribution of non-binary LDPC codes,” in *Proc. IEEE Int. Symp. Information Theory*, Coex, Seoul, Korea, Jun. 2009, pp. 65–69. [11]S. Yang, T. Honold, Y. Chen, Z. Zhang, and P. Qiu, “Constructing linear codes with good spectra,”*IEEE Trans. Inf. Theory*, 2009, submitted for

[12]M. G. Luby, M. Mitzenmacher, M. A. Shokrollahi, and D. A. publication. Spielman, “Improved low-density parity-check codes using irregulargraphs,”*IEEE* *Trans. Inf. Theory*, vol. 47, no. 2, pp. 585–598, Feb. 2001. [13]T. J. Richardson and R. L. Urbanke, “The capacity of low- check codes under message-passing decoding,”*IEEE Trans. Inf. Theory* density parity-, vol. 47, no. 2, pp. 599–618, Feb. 2001. [14]W. C. Huffman and V. Pless, *Fundamentals of Error-Correcting Codes*. New York: Cambridge University Press, 2003. [15]X. Wang, “A simple proof of Descartes’s rule of signs,” *The American* *Mathematical Monthly*, vol. 111, no. 6, pp. 525–526, Jun. 2004.

**Shengtian Yang** (S’05–M’06) was born in Hangzhou, Zhejiang, China, in

1976.Hereceived the B.S.and M.S.degrees in biomedicaleng ineering, andthe Ph.D.degreeinelectricalengineeringfrom Zhejian g University, Hangzhou, China in 1999, 2002, and 2005, respectively. From June2005to December2007,hewasa Postdoctoral Fellow at the Department of Information Science and Electronic Engineering, Zhejiang University. From December 2007 to January 2010, he was an Associate Pro- fessor at the Department of Information Science and Electronic Engineering, Zhejiang University. Currently, he is a self-employed Independent Researcher in Hangzhou, China. His research interests include informa
tion theory, coding theory, and design and analysis of algorithms.

**Thomas Honold** (M’95)wasbornin Munich,Germany,in1962.He received his Diplom (1990), doctoral degree (1994) and Habilitation (2000, the qualificationfor universityteaching in Germany) in Mat hematics from TU Munich, Germany. He has held appointments at TU Munich, Un iversity of Eichst¨att, Germany, and the German Institute of Scienceand Technology, Singapore. Since 2007 he is working as Associate Professor f or the Depart- ment of Information Science and Electronic Engineering, Zhejiang University, Hangzhou. His main research interest is coding theory and ge ometry over finite fields and rings.

**Yan Chen** (S’06–M’10) was born in Hangzhou, Zhejiang, China, in 1982.She received the B.Sc. and the Ph. D degree in information and communication

respectively.Shehasbeena Visiting Researcheratthe Depa rtmentof Electronic and Computer Engineering, Hong Kong University of Science and Technology, Hong Kong. After graduation, she joined Huawei Technologies

the Central Research Department.Hercurrentresearchinte restsinclude green network information theory, energy-efficient networ k architecture and

well as the radio technologies and resource allocation optimization algorithms therein.

**Zhaoyang Zhang** (M’02) was born in Huanggang, Hubei, China, in 1973. Hereceivedthe B.Sc.degreeinradiotechnologyandthe Ph.D degree ininformationandcommunicationengineeringfrom Zhejian g University, Hangzhou, China, in 1994 and 1998, respectively.

[2]S. Litsyn and V. Shevelev, “On ensembles of low-density parity-check engineering from Zhejiang University, Hangzhou, China, in2004 and 2009,

parity-check codes,”*IEEE Trans. Inf. Theory*, vol. 49, no. 12, pp. 3140–(Shanghai) Co., Ltd. and is currently working as a Research E ngineer in

analyzing LDPC codes,” *IEEE Trans. Inf. Theory*, vol. 50, no. 6, pp. management,fundamentaltradeoffs on greenwirelessnetwo rkdesign,as

Since 1998, he has been with the Department of Information Science and 1967 and the M.S. degree from the Graduate School of Chinese Academy of Electronic Engineering, Zhejiang University, Hangzhou, C hina, where he is Science, Beijing, in 1981, both in electronics engineering. currently a Professor. His current research interests incl ude information theory From 1968 to 1978, he was a Research Engineer at Jiangnan Electronic and signal processing theory with emphsis on their applicat ions in wireless Technology Institute. Since November1981,hehasbeenwith Zhejiang communications and networks. University,Hangzhou,China,whereheiscurrentlya Profes soratthe Department of Information Science and Electronic Engineer ing. His current researchinterestsincludedigitalcommunications,infor mationtheory, and wireless networks.

**Peiliang Qiu** (M’03) was born in Shanghai, China, in 1944. He received the B.S. degree from the Harbin Institute of Technology, Har bin, China, in
