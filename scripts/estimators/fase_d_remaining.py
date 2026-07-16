"""Run the unmodified non-AGB fase-D Code_estimators categories.

The checkout must first have ``fase_d_hybrid_logsumexp.patch`` applied.  AGB
and AGB2 are deliberately run by their separate, memory-bounded audit scripts.
"""

from esser.regular_ISD import permutation_based_concrete_cost_bigq
from hybrid.hybrid_quick import hybrid_bigq_quick
from lwyy.hardness_of_lpn import Gauss, SD2forq, SD_ISD_q, SDforq


N = 117_440_512
K = 6_520_000
T = 1_792
LOG2_Q = 64


sd_isd = SD_ISD_q(N, K, T, LOG2_Q)
gauss = Gauss(N, K, T)
sd = SDforq(N, K, T)
sd2 = SD2forq(N, K, T, LOG2_Q)
isd = min(sd_isd, gauss, sd, sd2)
hybrid = hybrid_bigq_quick(N, K, T)
regular_isd = permutation_based_concrete_cost_bigq(N, K, T)

print(f"SD-ISD={sd_isd}")
print(f"Gauss={gauss}")
print(f"SD={sd}")
print(f"SD2={sd2}")
print(f"ISD={isd}")
print(f"HYB={hybrid}")
print(f"RISD={regular_isd}")
