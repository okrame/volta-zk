# GPT-2 real-weight — confronto CPU, A100, Ligero inline e storico X4

> **Stato 2026-07-27 — documento WIP tracciato.** X4/X4d resta nello storico
> ma la campagna è sospesa. La Phase 1 locale C4 è implementata e verificata;
> C4 torna alla certificazione Ligero inline e preregistra un confronto sulla
> stessa build tra l'ancora T1
> `rate=1/4,Q=120` e il candidato `rate=1/8,Q=97`. I valori C4 sono ancora
> proiezioni analitiche, non misure A100; le colonne sotto restano immutabili
> finché non atterra il nuovo pair. L'avvertenza sulla build T1 obsoleta
> rimane quindi vincolante.
>
> Il primo preflight Phase 2 autorizzato ha confermato A100/RAM/CPU/capacità,
> ma si è fermato prima di checkout, build e workload perché RunPod espone il
> disco container locale come `overlayfs` e `/workspace` come FUSE remoto.
> La correzione di ammissione distingue fail-closed l'esatto overlay Docker
> locale dal volume FUSE; non esiste ancora alcun nuovo tempo o verdetto.

La quarta colonna dati è stata sostituita con il pair pulito X4d.1 a
`b83ffc1`: un settlement `k=1` e uno `k=16` sullo stesso host, build, GPU e
split CPU. Il record `k=16` accetta il settlement e mantiene verde il proprio
G1, ma il verdetto appaiato è **FAIL**: il wall cresce di **2,635946x** contro
il limite vincolante **1,30x**. Inoltre il rerun G1 appaiato è rosso perché
`k=1` misura **0,154283455 s** di sync contro il tetto invariato **0,150 s**.

La terza colonna è il record T1 su A100 a `b14577e`, cioè l'ultima
configurazione **Ligero con boundary thinning** misurata prima della
migrazione X4. Non è una proiezione: tutti i suoi valori vengono da
`t1-a100-realpcg-v4-2026-07-19-b14577e.json`. La sezione «Confronto Ligero
inline vs settlement differito» sotto spiega perché è la colonna di
riferimento corretta per la comparazione delle comunicazioni, e non la
seconda.

| Voce | CPU locale (4 thread) | A100 RunPod (8 worker Rayon) | A100 RunPod T1 (Ligero + boundary thinning) | A100 RunPod X4d.1 (8 response + 27 settlement worker) |
| --- | ---: | ---: | ---: | ---: |
| **PCS e legatura dei pesi** | Ligero rate `1/4`, `Q=120` — apertura **inline** per risposta | Ligero rate `1/4`, `Q=120` — apertura **inline** per risposta | Ligero rate `1/4`, `Q=120` — apertura **inline** per risposta | `x4-zkdeepfold-ud-e29-v4` (BaseFold/DeepFold), rate `1/8`, `s=111` — **settlement differito**, risposta senza blocco PCS |
| Prova prefill | 10,10 s | 2,54 s | **2,412064 s** | **2,256217 s — PASS** (`k=16`) |
| Prova decode marginale | 8,26 s | 1,65 s | **1,618844 s** | **1,896501 s — PASS** (`k=16`) |
| Prova risposta totale | 18,37 s | 4,18 s | **4,031071 s** (mediana di tre) | **4,148145 s** (`k=16`, upper median delle tre misurate) |
| Sessione online completa | 30,45 s | 5,60 s | **5,289038 s**, legatura pesi **inclusa** | **4,783942 s — PASS** alla delivery `k=16`; settlement **878,973898 s/batch — FLATNESS FAIL** |
| G2 rispetto a fase-D appaiato | **+14,54% — PASS** | **−14,83% — PASS** | gate p7b: prefill **2,412064 s ≤10 s** e decode **1,618844 s ≤4 s — PASS**; nessun pair fase-D in questo record | G1 `k=16` PASS; pair G1 **FAIL** per sync `k=1`; interferenza `k=16` **−2,273545% — PASS** |
| Flat cost (ultimo/primo) | **1,163 — PASS** | **1,228 — PASS** | **1,231125 — PASS** | G1 **1,000 — PASS**; settlement `k16/k1` **2,635946 — FAIL** |
| H2D massimo sessione | n/d | **88,81 MB — PASS** | **67,62 MB — PASS** | **66,93 MB — PASS** |
| Sync wall massimo | n/d | **0,1149 s — PASS** | **0,117210 s — PASS** | pair **0,154283 s — FAIL** (`k=16`: **0,126060 s — PASS**) |
| Verifica pura | 0,387 s | 0,832 s | **0,670983 s** | **0,635883 s** (`k=16`) |
| Verifica contabilizzata | 0,468 s | 0,911 s | **0,753988 s** (`0,670983 + 0,083005` PCS) | **0,639966 s/risposta equivalente** (`0,635883 + 0,065331/16`) |
| Token di decode provati al secondo | 2,72 | 11,95 | **12,40** | **12,05** |
| Setup real-PCG | 67,90 s | 48,84 s | **38,845157 s** | **42,151358 s** |
| Traffico setup totale | 38,37 MB | 38,37 MB | 38,37 MB | 38,37 MB (invariante fase-D, non ri-emesso) |
| Prover → verifier | 31,58 MB | 31,58 MB | 31,58 MB | 31,58 MB (invariante fase-D, non ri-emesso) |
| Verifier → prover | 6,79 MB | 6,79 MB | 6,79 MB | 6,79 MB (invariante fase-D, non ri-emesso) |
| Transcript / risposta packed | **105,72 MB** | **105,72 MB** | **84,544352 MB — exact**, stato terminale accettato | **41,270464 MB — exact**, stato `WEIGHT_PENDING` |
| PCS opening (già incluso) | 43,27 MB | 43,27 MB | 43,273888 MB inline; commit/open/verify **0,202692 / 0,297629 / 0,083005 s** | **0 B/risposta**; **3,564780 MB/batch**, **0,222799 MB/risposta equivalente** |
| Logit pubblici packed | **0 MB** | **0 MB** | **0 MB** | **0 MB** |
| Primo scambio totale | **144,09 MB** | **144,09 MB** | **122,915817 MB** | **79,641929 MB** alla delivery; settlement differito **3,564780 MB/16** |
| Latenza al certificato dei pesi | inline | inline | **inline (0,297629 s)** | **333,456712 s** (`k=1`) / **878,973898 s** (`k=16`) dal seal |

## Confronto Ligero inline vs settlement differito

Le prime due colonne sono record dell'era C3b (`161fc59`, pre-T1) e riportano
una risposta di **105,72 MB**. Quel valore non è più il riferimento Ligero
corretto: T1 ha chiuso il 2026-07-19 su `b14577e` portando la risposta a
**84.544.352 B esatti** con lo stesso PCS Ligero e la stessa apertura
**43.273.888 B**. Confrontare X4d.1 con la seconda colonna attribuisce quindi
alla migrazione PCS anche i **21,17 MB** già vinti da T1 sul transcript, che
sono indipendenti dal PCS. La terza colonna rimuove questa confusione.

A parità di generazione dello stack, la sostituzione del PCS vale:

| Grandezza | T1 Ligero inline | X4d.1 `k=16` | Delta |
| --- | ---: | ---: | ---: |
| Prova modello per risposta | 4,031071 s | 4,152718 s | **+0,121647 s** |
| Legatura pesi per risposta | 0,297629 s | 54,935869 s (`878,973898/16`) | **+54,638240 s** |
| Byte per risposta | 84.544.352 B | 41.270.464 B + 222.799 B/risposta equiv. | **−43.051.089 B** |
| Primo scambio | 122,915817 MB | 79,641929 MB | **−43,273888 MB** |

Il rapporto è **184,6x** sul costo di legatura dei pesi a `k=16` e **1.120,4x**
a `k=1`, in cambio di **43,05 MB** per risposta: circa **788 kB risparmiati per
secondo di prover A100 speso**. L'hot path di proving del modello non migliora:
X4d.1 è **+2,904%** più lento di T1.

Il pavimento raggiungibile da X4d è visibile nella decomposizione sotto: le tre
fasi piatte sommano **146,325853 s** a `k=16` e la banda informativa X4c è
**288--307 s**. Anche azzerando tutto il residuo non piatto, il costo per
risposta resta **18,0--19,2 s** a `k=16` e **9,0--9,6 s** al cap `k=32`, cioè
ancora **30--65x** l'apertura Ligero inline misurata. Il verdetto di flatness
di X4d.2 non può quindi cambiare l'ordine di questo confronto.

Riferimenti dei valori T1: `t_prove_prefill_only_s`,
`t_prove_decode_marginal_s`, `t_prove_response_s`, `t_response_session_wall_s`,
`curve_last_over_first`, `p7b_h2d_observed_bytes`,
`p7b_sync_wall_absolute_observed_s`, `t_verify_response_s`,
`t_verifier_accounted_s`, `verified_tokens_per_s`,
`fase_d_setup/total_setup_wall_s`, `comm_response_bytes`,
`pcs_opening_bytes_total`, `pcs_commit_total_s`, `pcs_open_total_s`,
`pcs_verify_total_s`. Il primo scambio è
`84.544.352 + 38.371.465 = 122.915.817 B`.

**Avvertenza di confronto.** T1 è a `b14577e`, quindi precede X1--X3, la
migrazione codec schema-4 e tutto il lavoro CUDA delle fasi X4b--X4d. È un
record A100 reale della configurazione Ligero + boundary thinning, ma non è
appaiato per host, build e GPU con X4d.1 nel senso richiesto dal gate di
flatness. Un confronto vincolante richiederebbe un'ancora Ligero rimisurata
sulla build corrente.

## C4 Ligero inline — prossimo confronto preregistrato

C4 non riapre il settlement differito. Misurerà sulla stessa build, host,
GPU e configurazione a otto worker prima l'ancora T1 `rate=1/4,Q=120`, poi
soltanto se l'ancora è verde il candidato `rate=1/8,Q=97`. Fino al pair A100
questi numeri sono formule verificate localmente, non risultati:

| Grandezza | Ancora T1 corrente da rimisurare | C4 `rate=1/8,Q=97` | Delta |
| --- | ---: | ---: | ---: |
| PCS inline | 43.273.888 B | 38.296.040 B | **−4.977.848 B** |
| Transcript non-PCS | 41.270.464 B | 41.270.464 B | **0 B** |
| Risposta | 84.544.352 B | 79.566.504 B | **−4.977.848 B** |
| Primo scambio, setup incluso | 122.915.817 B | 117.937.969 B | **−4.977.848 B** |
| Media a 5 risposte | 92.218.645 B | 87.240.797 B | **−4.977.848 B/risposta** |
| Soundness statistica | 78,80929487391641 bit | 78,86651649674867 bit | più forte |
| Codeword residenti | 8.623.489.024 B | 17.246.978.048 B | **+8.623.489.024 B** |

Il gate costo è volutamente stretto: sia la mediana superiore del prover sia
quella della sessione completa devono restare entro `1,05x` l'ancora
same-build, oltre a tutti i tetti T1 assoluti. La misura storica T1 resta
visibile sopra, ma non decide questo pair. X4/X4d rimane conservato come
storico immutabile e non è nel percorso di esecuzione C4.

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

La colonna T1 proviene dal record immutabile

- `benchmarks/results/t1-a100-realpcg-v4-2026-07-19-b14577e.json`
  (`1a659df70a5996e2ac0a188f49d190ebc50e3224733536cb9e03c642a6b2f8dc`).
