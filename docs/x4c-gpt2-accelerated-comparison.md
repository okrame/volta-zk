# GPT-2 real-weight — confronto CPU, A100 e X4d deferred settlement

La terza colonna è stata sostituita con il run pulito
`X4d-GPT2-real-weight-deferred-settlement-v1` a `bf4230c`: un warm-up,
tre risposte G1 misurate e una connessione da 19 risposte con settlement
effettivo su 16 risposte. I tempi sono gli upper median esposti o calcolabili
dalle tre righe misurate del record. `n/d` evita di promuovere a misura una
quantità non ri-emessa.

| Voce | CPU locale (4 thread) | A100 RunPod (8 worker Rayon) | A100 RunPod X4d (8 response + 27 settlement worker) |
| --- | ---: | ---: | ---: |
| Prova prefill | 10,10 s | 2,54 s | **2,294197 s — PASS** |
| Prova decode marginale | 8,26 s | 1,65 s | **1,957724 s — PASS** |
| Prova risposta totale | 18,37 s | 4,18 s | **4,264261 s** |
| Sessione online completa | 30,45 s | 5,60 s | **4,900886 s — PASS** alla delivery (`WEIGHT_PENDING`); **3.088,031852 s/batch** al settlement (informativa) |
| G2 rispetto a fase-D appaiato | **+14,54% — PASS** | **−14,83% — PASS** | n/d; G1 assoluto **<=5 s PASS**, interferenza settlement-queued **+0,399685%** informativa |
| Flat cost (ultimo/primo) | **1,163 — PASS** | **1,228 — PASS** | **1,000 — PASS** |
| H2D massimo sessione | n/d | **88,81 MB — PASS** | **66,93 MB — PASS** |
| Sync wall massimo | n/d | **0,1149 s — PASS** | **0,125173 s — PASS** |
| Verifica pura | 0,387 s | 0,832 s | **0,641085 s** |
| Verifica contabilizzata | 0,468 s | 0,911 s | **0,644986 s/risposta equivalente** (`0,641085 + 0,062415/16`) |
| Token di decode provati al secondo | 2,72 | 11,95 | **11,73** |
| Setup real-PCG | 67,90 s | 48,84 s | **43,037916 s** |
| Traffico setup totale | 38,37 MB | 38,37 MB | 38,37 MB (invariante fase-D, non ri-emesso) |
| Prover → verifier | 31,58 MB | 31,58 MB | 31,58 MB (invariante fase-D, non ri-emesso) |
| Verifier → prover | 6,79 MB | 6,79 MB | 6,79 MB (invariante fase-D, non ri-emesso) |
| Transcript / risposta packed | **105,72 MB** | **105,72 MB** | **41,270464 MB — PASS**, stato `WEIGHT_PENDING` |
| PCS opening (già incluso) | 43,27 MB | 43,27 MB | **0 B/risposta**; **3,564780 MB/batch**, **0,222799 MB/risposta equivalente** |
| Logit pubblici packed | **0 MB** | **0 MB** | **0 MB** |
| Primo scambio totale | **144,09 MB** | **144,09 MB** | **79,641929 MB** alla delivery; settlement differito **3,564780 MB/16** |

Come leggere la colonna X4d: onboarding materializza una volta i coefficienti
e le root durevoli per questo modello; il rebuild CUDA ricostruisce una volta
per il processo/sessione pod le cinque root esatte e lo stato GPU residente.
Il setup fase-D apre poi una connessione con uno specifico verifier e genera
le correlazioni real-PCG: il suo traffico fase-D è **38.371.465 B**, valore
invariante ma non ri-emesso dal record X4d.

Con questi prerequisiti già pronti, i **4,900886414 s** G1 non includono
onboarding, rebuild, setup, rete o un separato wall di serving nativo:
misurano prova del modello, verifica e freeze dei claim. Di questi,
**4,264260505 s** sono `model_prove_s`, **0,641085382 s** sono
`model_verify_s` e circa **0,000511270 s** sono il freeze. Sono upper median
selezionati separatamente, quindi non devono essere risommati per ricostruire
il totale G1. I **41.270.464 B** per risposta permettono quindi al verifier di
verificare subito la prova del modello e l'autenticazione dei valori, ma non
ancora la loro consistenza con il commitment statico dei pesi: la delivery
termina correttamente in stato `WEIGHT_PENDING`.

Dopo il seal dei primi 16 response claim-set, il run v1 tratta il settlement
come job in background *schedulato*, non come calcolo realmente concorrente.
Per **10,586787986 s** il settlement resta in coda mentre due nuove risposte
con priorità vengono completate (`response_priority_pause_wall_s`: è una
pausa del settlement, non della risposta). Seguono **5,458699300 s** per
creare il nuovo set di maschere/auxiliary root. Il `proof_driver_wall_s`,
**3.071,972477759 s**, è invece l'intera esecuzione pesante che costruisce la
folding proof sul batch congelato, incluso il sottostadio finale di opening;
nel profilo v1 usa poi la lease CPU/GPU in esclusiva. Gli intervalli di
overlap CPU e GPU misurati sono infatti entrambi zero.

I **3.088,031851727 s** `seal_to_terminal_wall_s` sono il wall end-to-end
dal seal durevole del batch fino al successo terminale: coda per le due
risposte prioritarie + auxiliary materialization + proof driver + breve
contabilità/journaling. Non sono il solo opening e non sono 51 minuti di
verifica. Dopo la costruzione, il prover invia l'intero settlement message da
**3.564.780 B** (chain, fold e query path inclusi): l'opening finale costa al
prover **0,132453794 s** dentro il proof driver e il verifier controlla il
messaggio in **0,062415304 s**. Il run-of-record materializza e verifica questo
wire message nello stesso harness, quindi i wall non includono trasporto di
rete. Solo allora le 16 risposte coperte passano da `WEIGHT_PENDING` a
`WEIGHT_VERIFIED`. La verifica contabilizzata nella tabella è soltanto un
equivalente per-risposta; non rappresenta la latenza reale con cui il pending
set riceve il verdetto.

## Contatori X4d deferred settlement

| Voce | Risultato |
| --- | ---: |
| Onboarding upper median / campagna | **458,541460716 / 1.891 s — PASS** |
| Fresh rebuild CUDA, cinque root esatte | **218,256070550 s — PASS** |
| Setup fase-D | **43,037915783 s** |
| G1 delivery totale / claim-freeze | **4,900886414 / 0,000511270 s — PASS** |
| Risposta | **41.270.464 B, PCS 0 B, `WEIGHT_PENDING` — exact** |
| Settlement union | **16 risposte / 1.632 claim / 816 gruppi** |
| Settlement wire | **3.564.780 B**, **222.798,75 B/risposta — exact** |
| Settlement seal → terminale | **3.088,031851727 s — informativa v1** |
| Folding-proof driver / auxiliary materialization | **3.071,972477759 / 5,458699300 s** |
| Finestra host CPU / lease GPU | **3.077,431177059 / 3.071,972477759 s** |
| Settlement in coda per response priority | **10,586787986 s** |
| Interferenza A1,B1,B2,A2 | **+0,019727179 s / +0,399684884%**, overlap dichiarato **0/0** |
| Settlement open / verify | **0,132453794 / 0,062415304 s — PASS HARD** |
| Freshness | **3 root statiche riusate / 51 mask fresh / 111 query draw** |
| Cap e abort | **3.321° claim respinto; abort terminal-unverified; no retry — PASS** |
| Soundness | **80,2553701639904 bit**, espressione byte-identica |

Il cap storico **4.000.000 B** resta quello del PCS per-risposta
X4/X4b/X4c. Il settlement X4d usa la formula pinnata
`2.757.996 + 50.424*k`: il record `k=16` è quindi **3.564.780 B**, mentre
il riferimento `k=32` è **4.371.564 B**, cioè **136.611,375 B/risposta**
equivalenti. Il precedente riferimento Phase-2 `k=32` da **4.246.380 B**
resta storico e immutabile; l'Amendment-1 aggiunge il padding verificato, non
una deroga retroattiva al gate storico.

Record append-only:

- `benchmarks/results/x4c-note6-c3-weights-preflight-2026-07-26-bf4230c.json`
  (`6f5e272f1b94b686f347d7c449afb31420fe292930f96ad91653e1b30c02ad11`);
- `benchmarks/results/x4d-pod-preflight-2026-07-26-bf4230c-bbd64aa1df41.json`
  (`72fb85c89be9c15c61701c04117533218d3c13f9472ab3d176e9080d75187bd1`,
  preflight FUSE conservato come evidenza, non come storage anchor);
- `benchmarks/results/x4d-pod-preflight-local-2026-07-26-bf4230c-bbd64aa1df41.json`
  (`ca26edfad1053d51e7509fa116bbac124dd8cb1cccbc0466050a226f029d52b0`);
- `benchmarks/results/x4d-x4c-onboarding-2026-07-26-bf4230c-bbd64aa1df41-local.json`
  (`15b8d87fcc0db8200dee06b5c1218c198c0551ad8ad5d062fa9975f3f37043ba`);
- `benchmarks/results/x4d-gpt2-online-2026-07-26-bf4230c-bbd64aa1df41-local.json`
  (`d6017dbadd930baa390b174e57e8d93ec6a413fd886d505ad37ebb484e6dc24b`).
