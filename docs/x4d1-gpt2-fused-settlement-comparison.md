# GPT-2 real-weight — confronto CPU, A100 e X4d.1 fused settlement

La terza colonna dati è stata sostituita con il pair pulito X4d.1 a
`b83ffc1`: un settlement `k=1` e uno `k=16` sullo stesso host, build, GPU e
split CPU. Il record `k=16` accetta il settlement e mantiene verde il proprio
G1, ma il verdetto appaiato è **FAIL**: il wall cresce di **2,635946x** contro
il limite vincolante **1,30x**. Inoltre il rerun G1 appaiato è rosso perché
`k=1` misura **0,154283455 s** di sync contro il tetto invariato **0,150 s**.

| Voce | CPU locale (4 thread) | A100 RunPod (8 worker Rayon) | A100 RunPod X4d.1 (8 response + 27 settlement worker) |
| --- | ---: | ---: | ---: |
| Prova prefill | 10,10 s | 2,54 s | **2,256217 s — PASS** (`k=16`) |
| Prova decode marginale | 8,26 s | 1,65 s | **1,896501 s — PASS** (`k=16`) |
| Prova risposta totale | 18,37 s | 4,18 s | **4,148145 s** (`k=16`, upper median delle tre misurate) |
| Sessione online completa | 30,45 s | 5,60 s | **4,783942 s — PASS** alla delivery `k=16`; settlement **878,973898 s/batch — FLATNESS FAIL** |
| G2 rispetto a fase-D appaiato | **+14,54% — PASS** | **−14,83% — PASS** | G1 `k=16` PASS; pair G1 **FAIL** per sync `k=1`; interferenza `k=16` **−2,273545% — PASS** |
| Flat cost (ultimo/primo) | **1,163 — PASS** | **1,228 — PASS** | G1 **1,000 — PASS**; settlement `k16/k1` **2,635946 — FAIL** |
| H2D massimo sessione | n/d | **88,81 MB — PASS** | **66,93 MB — PASS** |
| Sync wall massimo | n/d | **0,1149 s — PASS** | pair **0,154283 s — FAIL** (`k=16`: **0,126060 s — PASS**) |
| Verifica pura | 0,387 s | 0,832 s | **0,635883 s** (`k=16`) |
| Verifica contabilizzata | 0,468 s | 0,911 s | **0,639966 s/risposta equivalente** (`0,635883 + 0,065331/16`) |
| Token di decode provati al secondo | 2,72 | 11,95 | **12,05** |
| Setup real-PCG | 67,90 s | 48,84 s | **42,151358 s** |
| Traffico setup totale | 38,37 MB | 38,37 MB | 38,37 MB (invariante fase-D, non ri-emesso) |
| Prover → verifier | 31,58 MB | 31,58 MB | 31,58 MB (invariante fase-D, non ri-emesso) |
| Verifier → prover | 6,79 MB | 6,79 MB | 6,79 MB (invariante fase-D, non ri-emesso) |
| Transcript / risposta packed | **105,72 MB** | **105,72 MB** | **41,270464 MB — exact**, stato `WEIGHT_PENDING` |
| PCS opening (già incluso) | 43,27 MB | 43,27 MB | **0 B/risposta**; **3,564780 MB/batch**, **0,222799 MB/risposta equivalente** |
| Logit pubblici packed | **0 MB** | **0 MB** | **0 MB** |
| Primo scambio totale | **144,09 MB** | **144,09 MB** | **79,641929 MB** alla delivery; settlement differito **3,564780 MB/16** |

## Lettura del verdict

Entrambi i run ricostruiscono le stesse cinque root dal tier durevole esatto.
Il fresh rebuild è **186,102826901 s** a `k=1` e **185,341514633 s** a
`k=16`; non entra nel wall del gate. Anche onboarding, setup fase-D e
trasporto di rete restano fuori dal wall seal→terminale preregistrato.

Il settlement `k=1` è crittograficamente accettato in
**333,456712047 s**, ma il record completo è rosso perché una risposta ABBA
isolata porta il massimo sync a **0,154283455 s**. Non è stato eseguito un
retry selettivo. Il settlement `k=16` è accettato in **878,973897598 s** e il
suo G1 è verde: **4,783941572 s**, sync **0,126060151 s**, risposta esatta
**41.270.464 B**. L'interferenza A1,B1,B2,A2 è
**−0,110727870 s / −2,273545314%**, quindi non regredisce rispetto al tetto
storico **+1,00%** né all'anchor X4d **+0,399684884%**.

Il gate vincolante è applicato letteralmente:

```text
FAIL — FLATNESS IN k:
settlement_wall(k=16) <= 1.30 x settlement_wall(k=1),
con initial_encoded_symbols_read e combined_codeword_symbols uguali
```

Il rapporto osservato è **878,973897598 / 333,456712047 =
2,635946033901128**. I due contatori simboli sono uguali e verdi; il FAIL wall
non viene compensato da questa uguaglianza. Il target X4c **288–307 s** resta
puramente informativo e non entra in `overall_pass`: qui `k=16` è sopra il
target, ma il verdict sarebbe rimasto FAIL anche se quel target non fosse
esistito.

## Dove resta il costo in k

La fusione ha recuperato il singolo percorso fisico oracle/fold:

| Fase settlement | `k=1` | `k=16` | Rapporto / esito |
| --- | ---: | ---: | ---: |
| Claim-coefficient preparation | 167,865042048 s | 716,643018039 s | **4,269162x — residuo non flat** |
| Oracle read + combine | 128,214018848 s | 125,295222121 s | **0,977235x — flat** |
| Fold + Merkle | 21,606032798 s | 20,888810928 s | **0,966805x — flat** |
| Query gather/open | 0,149103243 s | 0,141819753 s | **0,951151x — flat** |
| Proof driver | 317,908618836 s | 863,050484758 s | **2,714775x** |
| Seal → terminale | 333,456712047 s | 878,973897598 s | **2,635946x — FAIL** |

Il residuo è quindi prima del passaggio oracle, nel caller che prepara i
coefficienti delle `102*k` relazioni. Il percorso fuso materializza comunque
solo 102 termini fisici in entrambi i run. Non c'è evidenza di una regressione
nel motore single-pass X4c riusato.

## Contatori X4d.1

| Voce | `k=1` | `k=16` | Esito |
| --- | ---: | ---: | ---: |
| Relazioni di protocollo | 102 | 1.632 | invariato |
| Termini fisici materializzati | 102 | 102 | **flat** |
| Termini fusi | 0 | 1.530 | exact |
| Tabelle / simboli unici | 102 / 601.161.728 | 102 / 601.161.728 | **uguali** |
| Passaggi per tabella | 1 | 1 | **uguali** |
| Initial encoded symbols | 4.809.293.824 | 4.809.293.824 | **gate PASS** |
| Combined-codeword symbols | 1.159.200.768 | 1.159.200.768 | **gate PASS** |
| Query gather | 1 | 1 | **uguali** |
| Peak relation payload CPU | 28.855.762.944 B | 28.855.762.944 B | **uguale** |
| Settlement wire | 2.808.420 B | 3.564.780 B | exact formula |
| Open / verify | 0,149103 / 0,064247 s | 0,141820 / 0,065331 s | **PASS HARD** |

Il cap storico **4.000.000 B** resta quello del PCS per-risposta
X4/X4b/X4c. X4d usa la formula invariata `2.757.996 + 50.424*k`; non esiste
una deroga retroattiva al gate storico. M12 e l'espressione di soundness
restano byte-identici a **80,2553701639904 bit**.

## Record append-only

- `benchmarks/results/x4d1-note6-c3-weights-preflight-2026-07-26-b83ffc1.json`
  (`331ef011b38b76a2a060bad3ceb277dde688d5d530841108818fe093c1f5494b`);
- `benchmarks/results/x4d1-pod-preflight-2026-07-26-b83ffc1.json`
  (`0db4d7f29ef95c0ef83e689f922c7f014afb61cb8d3cb789d2543eed3ba4ec55`);
- `benchmarks/results/x4d1-gpt2-onboarding-2026-07-26-b83ffc1.json`
  (`53a2d03e2581b6d59b81d3a449bdec61c3e4f1fecc35a78046b4d9c3602209cb`);
- `benchmarks/results/x4d1-gpt2-online-k1-2026-07-26-b83ffc1.json`
  (`7cea0665a22e453eb5b695c5bd7fa830a261448a0e9985370d5007c75270ec2e`);
- `benchmarks/results/x4d1-gpt2-online-k16-2026-07-26-b83ffc1.json`
  (`381979e0b6e440b1b995e1e78134a21cdece3651af0bfd621b2b52ef925a5ae6`);
- `benchmarks/results/x4d1-flatness-gate-2026-07-26-b83ffc1.json`
  (`7b041e2d1d3028da1977f13de900d95e2da011f98349c86646596eaccb267250`).
