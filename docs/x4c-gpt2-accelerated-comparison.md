# GPT-2 real-weight — confronto CPU, A100 e X4c accelerato

Il terzo dato A100 proviene dal run pulito
`X4c-GPT2-real-weight-online-accelerated` a `6277c3c`, con un warm-up e tre
candidati misurati. I tempi riportati sono gli upper median quando il record
espone la metrica; `n/d` evita di ricostruire separazioni non misurate.

| Voce | CPU locale (4 thread) | A100 RunPod (8 worker Rayon) | A100 RunPod X4c accelerato (8 worker Rayon) |
| --- | ---: | ---: | ---: |
| Prova prefill | 10,10 s | 2,54 s | n/d (non separata nel record) |
| Prova decode marginale | 8,26 s | 1,65 s | n/d (non separata nel record) |
| Prova risposta totale | 18,37 s | 4,18 s | **4,19 s** |
| Sessione online completa | 30,45 s | 5,60 s | **303,19 s** (informativa, PCS incluso) |
| G2 rispetto a fase-D appaiato | **+14,54% — PASS** | **−14,83% — PASS** | **−14,68% — PASS** |
| Flat cost (ultimo/primo) | **1,163 — PASS** | **1,228 — PASS** | n/d (curva non emessa) |
| H2D massimo sessione | n/d | **88,81 MB — PASS** | **18.554,61 MB X4c — PASS** |
| Sync wall massimo | n/d | **0,1149 s — PASS** | n/d (non emesso) |
| Verifica pura | 0,387 s | 0,832 s | **0,668 s** |
| Verifica contabilizzata | 0,468 s | 0,911 s | **0,727 s** |
| Token di decode provati al secondo | 2,72 | 11,95 | **11,93** |
| Setup real-PCG | 67,90 s | 48,84 s | n/d (non emesso) |
| Traffico setup totale | 38,37 MB | 38,37 MB | **38,37 MB** (invariante) |
| Prover → verifier | 31,58 MB | 31,58 MB | **31,58 MB** (invariante) |
| Verifier → prover | 6,79 MB | 6,79 MB | **6,79 MB** (invariante) |
| Transcript / risposta packed | **105,72 MB** | **105,72 MB** | **43,95 MB — PASS** |
| PCS opening (già incluso) | 43,27 MB | 43,27 MB | **2,68 MB — PASS** |
| Logit pubblici packed | **0 MB** | **0 MB** | **0 MB** |
| Primo scambio totale | **144,09 MB** | **144,09 MB** | **82,33 MB** |

Per la nuova colonna, `prova risposta totale` è `model_prove_s`;
`verifica pura` è `model_verify_s`; `verifica contabilizzata` aggiunge
`verify_wall_s`; e la sessione completa è `complete_e2e_wall_s`. Il contatore
H2D copre la sola finestra X4c e non va confrontato come se fosse il vecchio
contatore del solo model prover. La risposta esatta è **43.953.700 B**, di cui
**2.683.236 B** di PCS; il primo scambio somma i **38.371.465 B** invariati di
setup real-PCG.

## Contatori X4c specifici

| Voce | Risultato |
| --- | ---: |
| Fresh rebuild CUDA | **240,623922522 s — PASS** |
| Vecchio fresh rebuild CPU | 2.381,861456293 s |
| Speedup rebuild | **9,90×** |
| Evaluation-table reconstruction | 17,884190806 s |
| X4c proof-ready / session reusable | 51,934139091 / 51,959601330 s |
| X4c open / verify | **0,130465952 / 0,059185522 s — PASS** |
| PCS totale | 298,324984650 s |
| Picco RAM rebuild | 133.544.189.952 B (124,37 GiB) |
| Picco VRAM rebuild | 43.486.546.048 B (40,50 GiB) |
| Scratch read / write / file | **0 / 0 / 0 — PASS** |
| D2D esplicito per risposta | **1.364.224 B — exact** |
| Device-generated, warm-up / misurate | **35.727.436.640 / 35.727.436.512 B — exact** |
| PCS / response | **2.683.236 / 43.953.700 B — exact** |

Record append-only:

- `benchmarks/results/x4c-gpt2-onboarding-2026-07-25-6277c3c.json`
  (`bdf17c56e8e9a4d152b40ed2e1653d34cd665f09f52cb9dfe1cb1f57ae5e165d`);
- `benchmarks/results/x4c-gpt2-online-accelerated-2026-07-25-6277c3c.json`
  (`5a5417c11c0d5b4abe57af1e6ea5fa1191962c709c0f7b86fb780c30af1dac89`).
