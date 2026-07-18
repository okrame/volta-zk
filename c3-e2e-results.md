# Risultati e2e C3b — prompt 100 + risposta 50

| Voce | CPU locale (4 thread) | A100 RunPod (8 worker Rayon) |
|---|---:|---:|
| Prova prefill | 10,10 s | 2,54 s |
| Prova decode marginale | 8,26 s | 1,65 s |
| Prova risposta totale | 18,37 s | 4,18 s |
| Sessione online completa | 30,45 s | 5,60 s |
| G2 vs fase-D appaiato | **+14,54% PASS** | **−14,83% PASS** |
| Flat cost, ultimo/primo | **1,163 PASS** | **1,228 PASS** |
| H2D massimo sessione | n/d | **88,81 MB PASS** |
| Sync wall massimo | n/d | **0,1149 s PASS** |
| Verifica pura | 0,387 s | 0,832 s |
| Verifica contabilizzata | 0,468 s | 0,911 s |
| Token di decode provati/s | 2,72 | 11,95 |
| Setup real-PCG | 67,90 s | 48,84 s |
| Traffico setup totale | 38,37 MB | 38,37 MB |
| ↳ Prover → verifier | 31,58 MB | 31,58 MB |
| ↳ Verifier → prover | 6,79 MB | 6,79 MB |
| Transcript/risposta packed | **105,72 MB** | **105,72 MB** |
| PCS opening, già incluso | 43,27 MB | 43,27 MB |
| Logit pubblici packed | 0 MB | 0 MB |
| Primo scambio totale | **144,09 MB** | **144,09 MB** |

> [!info] Note metodologiche
> Misure **upper-median** di una warm-up più tre ripetizioni su tree pulito (`161fc59`). G1, G2, G3 e G4 sono PASS.
>
> Il workload è **GPT-2 small**, con prompt da **100 token** e **50 token generati**.
>
> - Il setup **real-PCG** è una tantum per connessione e non è incluso nella sessione online.
> - Le due righe direzionali indicano rispettivamente l’upload del prover (download del verifier) e l’upload del verifier (download del prover).
> - La risposta packed è il download del verifier.
> - Il PCS opening da **43,27 MB** è già una componente della risposta packed da **105.717.632 B**: non va sommato una seconda volta.
> - Il primo scambio totale somma setup bidirezionale e prima risposta packed.
> - Prompt applicativo e overhead di trasporto non sono conteggiati.
