# P7 generated result tables

Resident source: `benchmarks/results/p7-integrated-resident-2026-07-13-1fd5195.json`  
Native source: `benchmarks/results/p7-gpu-native-inference-2026-07-13-1fd5195.json`

## Gates

| Gate | Verdict | Value |
| --- | --- | ---: |
| Golden decode | PASS | bit-exact |
| Verifier | PASS | accepted |
| Flat decode cost | PASS | 0.950 |
| Packed response <=200 MB | PASS | 144820930 |
| Explicit device buffers after cleanup | PASS | 0 |
| rho proof prefill <=10 | FAIL | 3707.595 |
| rho proof decode <=2 | FAIL | 95.597 |

## Timings

| Component | Median (s) | MAD (s) |
| --- | ---: | ---: |
| Native GPU prefill | 0.017342 | 0.000062 |
| Native GPU decode50 | 0.599346 | 0.000990 |
| Resident witness prefill | 0.111155 | n/a |
| Resident witness response | 0.247386 | n/a |
| Proof core prefill | 64.295793 | 0.329496 |
| Proof core response | 121.155759 | 0.372825 |
| Proof core decode marginal | 57.295866 | 0.808726 |
| Online-accounted response | 121.774353 | 0.371605 |
| Full local response-session wall | 123.927768 | 0.414698 |
| PCS commit (offline) | 0.765752 | 0.002001 |
| PCS open (online) | 0.610145 | 0.001181 |
| Accounted verifier | 1.044615 | 0.007106 |

## Communication and memory

| Quantity | Bytes |
| --- | ---: |
| Response transcript | 137413808 |
| PCS opening (included above) | 66733504 |
| Packed public logits | 7407122 |
| Packed response total | 144820930 |
| Representative peak device | 5405147708 |
| Workspace after cleanup | 104988720 |
| Explicit resident after cleanup | 0 |

Mock-PCG is the measured baseline and is not production-grade.
