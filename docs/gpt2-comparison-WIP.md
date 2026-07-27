# GPT-2 real-weight — confronto CPU, A100, Ligero inline e storico X4

> **Stato 2026-07-27 — documento WIP tracciato.** X4/X4d resta nello storico
> e la campagna è sospesa. C4 torna alla certificazione Ligero inline:
> l'ancora T1 `rate=1/4,Q=120` è stata rimisurata su A100 alla build pulita
> `4097179` ed è ufficialmente valida; sostituisce nella terza colonna il
> vecchio record `b14577e`. Il candidato `rate=1/8,Q=97` non ha invece una
> misura: la sola esecuzione autorizzata si è fermata prima di real-PCG,
> warmup e timing per un assert del producer. Le sue cifre restano formule
> verificate localmente e nessun pair o verdetto C4 esiste.
>
> Il primo preflight Phase 2 autorizzato si era fermato prima del checkout
> sull'interpretazione del disco Docker `overlayfs`; la correzione
> preregistrata distingue quel disco locale dal volume FUSE remoto. Sul
> checkpoint pulito `3058c3c`, build, differenziali CUDA, leakage smoke e
> workspace release erano poi risultati verdi. L'invocazione dell'anchor si
> era però fermata fail-closed nell'ammissione, prima
> di caricare pesi o creare store PCG: `cpu.max=1360000 100000` espone 13,6
> CPU effettive, contabilizzate conservativamente come 13 contro il minimo
> congelato di 16. Nessun warmup, candidato, tempo A100 C4 o verdetto esiste;
> il pod è stato fermato. L'Owner Amendment 1 locale riduce il floor futuro a
> 13 CPU effettive: il record T1 A100 immutabile `b14577e` aveva già
> `detected_logical_cpu_cores=13`, 8 Rayon e tutti i gate verdi. Dodici CPU
> continuano a essere respinte.
>
> Il replacement autorizzato su `4097179` ha superato l'intero preflight e
> prodotto l'anchor valida. Solo dopo la sua validazione è partita rate-8:
> il mock prepass ha calcolato correttamente **38.296.040 B**, ma l'assert
> condiviso C3/T1 li ha confrontati con i **43.273.888 B** dell'anchor e ha
> terminato il processo prima di qualsiasi misura candidata. Il fix è locale
> e testato, il pod è fermo, e un nuovo pair richiede comunque un nuovo owner
> GO e due run freschi sullo stesso nuovo SHA.

La quarta colonna dati è stata sostituita con il pair pulito X4d.1 a
`b83ffc1`: un settlement `k=1` e uno `k=16` sullo stesso host, build, GPU e
split CPU. Il record `k=16` accetta il settlement e mantiene verde il proprio
G1, ma il verdetto appaiato è **FAIL**: il wall cresce di **2,635946x** contro
il limite vincolante **1,30x**. Inoltre il rerun G1 appaiato è rosso perché
`k=1` misura **0,154283455 s** di sync contro il tetto invariato **0,150 s**.

La terza colonna è ora il record C4-anchor su A100 a `4097179`, cioè la
configurazione **Ligero con boundary thinning** rimisurata dopo X1--X4d sul
checkpoint corrente della campagna. Non è una proiezione: tutti i valori
provengono da
`c4-ligero-t1-anchor-a100-2026-07-27-4097179.json`, validato dal selettore
ufficiale. La sezione «Confronto Ligero inline vs settlement differito»
sotto spiega perché è la colonna di riferimento corretta per la
comunicazione, e non la seconda.

| Voce | CPU locale (4 thread) | A100 RunPod (8 worker Rayon) | A100 RunPod C4 anchor (Ligero + boundary thinning) | A100 RunPod X4d.1 (8 response + 27 settlement worker) |
| --- | ---: | ---: | ---: | ---: |
| **PCS e legatura dei pesi** | Ligero rate `1/4`, `Q=120` — apertura **inline** per risposta | Ligero rate `1/4`, `Q=120` — apertura **inline** per risposta | Ligero rate `1/4`, `Q=120` — apertura **inline** per risposta | `x4-zkdeepfold-ud-e29-v4` (BaseFold/DeepFold), rate `1/8`, `s=111` — **settlement differito**, risposta senza blocco PCS |
| Prova prefill | 10,10 s | 2,54 s | **2,405747 s** | **2,256217 s — PASS** (`k=16`) |
| Prova decode marginale | 8,26 s | 1,65 s | **1,606140 s** | **1,896501 s — PASS** (`k=16`) |
| Prova risposta totale | 18,37 s | 4,18 s | **4,011648 s** (mediana di tre) | **4,148145 s** (`k=16`, upper median delle tre misurate) |
| Sessione online completa | 30,45 s | 5,60 s | **5,245757 s**, legatura pesi **inclusa** | **4,783942 s — PASS** alla delivery `k=16`; settlement **878,973898 s/batch — FLATNESS FAIL** |
| G2 rispetto a fase-D appaiato | **+14,54% — PASS** | **−14,83% — PASS** | gate p7b: prefill **2,405747 s ≤10 s** e decode **1,606140 s ≤4 s — PASS**; nessun pair C4 | G1 `k=16` PASS; pair G1 **FAIL** per sync `k=1`; interferenza `k=16` **−2,273545% — PASS** |
| Flat cost (ultimo/primo) | **1,163 — PASS** | **1,228 — PASS** | **1,235979 — PASS** | G1 **1,000 — PASS**; settlement `k16/k1` **2,635946 — FAIL** |
| H2D massimo sessione | n/d | **88,81 MB — PASS** | **67,618556 MB — PASS** | **66,93 MB — PASS** |
| Sync wall massimo | n/d | **0,1149 s — PASS** | **0,116591 s — PASS** | pair **0,154283 s — FAIL** (`k=16`: **0,126060 s — PASS**) |
| Verifica pura | 0,387 s | 0,832 s | **0,650482 s** | **0,635883 s** (`k=16`) |
| Verifica contabilizzata | 0,468 s | 0,911 s | **0,731349 s** (`0,650482 + 0,080867` PCS) | **0,639966 s/risposta equivalente** (`0,635883 + 0,065331/16`) |
| Token di decode provati al secondo | 2,72 | 11,95 | **12,46** | **12,05** |
| Setup real-PCG | 67,90 s | 48,84 s | **38,190168 s** | **42,151358 s** |
| Traffico setup totale | 38,37 MB | 38,37 MB | 38,37 MB | 38,37 MB (invariante fase-D, non ri-emesso) |
| Prover → verifier | 31,58 MB | 31,58 MB | 31,58 MB | 31,58 MB (invariante fase-D, non ri-emesso) |
| Verifier → prover | 6,79 MB | 6,79 MB | 6,79 MB | 6,79 MB (invariante fase-D, non ri-emesso) |
| Transcript / risposta packed | **105,72 MB** | **105,72 MB** | **84,544352 MB — exact**, stato terminale accettato | **41,270464 MB — exact**, stato `WEIGHT_PENDING` |
| PCS opening (già incluso) | 43,27 MB | 43,27 MB | 43,273888 MB inline; commit/open/verify **0,202912 / 0,296582 / 0,080867 s** | **0 B/risposta**; **3,564780 MB/batch**, **0,222799 MB/risposta equivalente** |
| Logit pubblici packed | **0 MB** | **0 MB** | **0 MB** | **0 MB** |
| Primo scambio totale | **144,09 MB** | **144,09 MB** | **122,915817 MB** | **79,641929 MB** alla delivery; settlement differito **3,564780 MB/16** |
| Latenza al certificato dei pesi | inline | inline | **inline (0,296582 s)** | **333,456712 s** (`k=1`) / **878,973898 s** (`k=16`) dal seal |

## Confronto Ligero inline vs settlement differito

Le prime due colonne sono record dell'era C3b (`161fc59`, pre-T1) e riportano
una risposta di **105,72 MB**. Quel valore non è più il riferimento Ligero
corretto: la nuova anchor `4097179` conferma **84.544.352 B esatti** con lo
stesso PCS Ligero e la stessa apertura **43.273.888 B**. Confrontare X4d.1
con la seconda colonna attribuisce quindi alla migrazione PCS anche i
**21,17 MB** già vinti da T1 sul transcript, che sono indipendenti dal PCS.
La terza colonna rimuove questa confusione.

A parità di generazione dello stack, la sostituzione del PCS vale:

| Grandezza | T1 Ligero inline | X4d.1 `k=16` | Delta |
| --- | ---: | ---: | ---: |
| Prova modello per risposta | 4,011648 s | 4,152718 s | **+0,141070 s** |
| Legatura pesi per risposta | 0,296582 s | 54,935869 s (`878,973898/16`) | **+54,639287 s** |
| Byte per risposta | 84.544.352 B | 41.270.464 B + 222.799 B/risposta equiv. | **−43.051.089 B** |
| Primo scambio | 122,915817 MB | 79,641929 MB | **−43,273888 MB** |

Il rapporto è **185,2x** sul costo di legatura dei pesi a `k=16` e **1.124,3x**
a `k=1`, in cambio di **43,05 MB** per risposta: circa **788 kB risparmiati per
secondo di prover A100 speso**. L'hot path di proving del modello non migliora:
X4d.1 è **+3,516%** più lento dell'anchor Ligero.

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

**Avvertenza di confronto.** L'anchor Ligero è ora a `4097179`, quindi non
precede più X1--X4d; questo chiude il dubbio sulla portabilità del vecchio
record T1. Non è però appaiata per host, build e GPU con X4d.1 `b83ffc1`, né
può essere appaiata retroattivamente con il futuro rate-8 corretto, che avrà
un nuovo SHA. Il confronto Ligero/X4d resta descrittivo; il gate C4 richiede
due nuovi run sullo stesso checkpoint corretto.

## C4 Ligero inline — prossimo confronto preregistrato

C4 non riapre il settlement differito. L'anchor T1 `rate=1/4,Q=120` è stata
misurata e validata a `4097179`; il candidato `rate=1/8,Q=97` resta non
misurato. La tabella separa quindi l'evidenza A100 dell'anchor dalle formule
candidate:

| Grandezza | Ancora T1 misurata (`4097179`) | C4 `rate=1/8,Q=97` non misurato | Delta analitico |
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
same-build, oltre a tutti i tetti T1 assoluti. L'anchor `4097179` resta
visibile sopra, ma non può decidere un futuro pair su un nuovo SHA. X4/X4d
rimane conservato come storico immutabile e non è nel percorso di esecuzione
C4.

La prima campagna C4 non aveva prodotto il pair. Dopo la verifica completa sul
checkpoint `3058c3c`, il producer dell'anchor ha respinto la quota cgroup di
13,6 CPU prima del caricamento dei pesi; il candidato era quindi vietato e
non è partito. Il record append-only di obstruction è
`c4-phase2-anchor-admission-obstruction-2026-07-27-3058c3c.json` (SHA-256
`535fc314608f94278d2b44cb0703be685f1a8b205bc766ecb65cc8c811dd4f97`);
il teardown è
`c4-control-plane-teardown-2026-07-27-3058c3c.json` (SHA-256
`fe65a850fc68aa653edc22738608c9f65ef2a76b90e26620abd638f841badaea`).
Questi sono record operativi, non misure di prestazione. Le formule della
colonna candidata restano proiezioni e il requisito same-build rimane in
vigore.

L'Owner Amendment 1 corregge soltanto il requisito di ammissione futuro da 16
a **13 CPU effettive**, senza modificare gli 8 worker Rayon. L'evidenza non è
una proiezione: il T1 A100 pulito `b14577e` registra già 13 CPU effettive,
setup real-PCG **38,845157077 s**, sessione **5,289037812 s** e gate verdi.
Il validator rifiuta 12 CPU e richiede ancora identità di host/CPU tra anchor
e candidato; l'anchor deve superare tutti i tetti assoluti prima di avviare
rate8. Il record locale append-only è
`c4-owner-amendment1-cpu-floor-2026-07-27-c7caf4a.json` (SHA-256
`98a1cd87d76f2bbc2bc0fa3103dafa46ac3805a175a6a1e8cd7312be7f4619f3`);
il design pin introdotto dall'emendamento era
`e58a7f965c4a28796a149308828a82128d3c86482d24c81a8c86a8484f4dcbf8`.
La campagna replacement autorizzata ha invece prodotto una nuova anchor
valida su `4097179`:
`c4-ligero-t1-anchor-a100-2026-07-27-4097179.json`, SHA-256
`6778cb837406c705c34aa0d3021da48791d2e6ccc8aa98580b0e19888e1ee18d`.
La sola candidata rate-8 si è fermata dopo il mock prepass ma prima di
real-PCG, warmup e timing per il confronto errato
`38.296.040 != 43.273.888`; nessun JSON candidato o pair esiste. Il fix
seleziona ora il byte count dal profilo ed è coperto localmente, ma non
autorizza un retry. Il record di obstruction è
`c4-phase2-rate8-producer-obstruction-2026-07-27-4097179.json` (SHA-256
`10697ed15949bf6e325309726505cc0ad44a58291a8e70be422b19851ebe55cc`);
il teardown è `c4-control-plane-teardown-2026-07-27-4097179.json`
(SHA-256
`11d02e7f024a88cb9cdf4148c207d48a001861fda8467c6b41704d9f317bbd1c`).
Il design futuro corretto ha digest
`0b8739d6d8d5e1d605e2d4dfa8fb1f064dc046ca77b02d390ecc4d0f20461bcb`;
il record anchor conserva il proprio pin storico `e58a7f...`. Il pod è
stato fermato e l'endpoint SSH rifiuta la connessione. Serve un nuovo owner
GO per un pair fresco sul checkpoint corretto.

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

La colonna Ligero corrente proviene dal record immutabile

- `benchmarks/results/c4-ligero-t1-anchor-a100-2026-07-27-4097179.json`
  (`6778cb837406c705c34aa0d3021da48791d2e6ccc8aa98580b0e19888e1ee18d`).

Il precedente T1 `b14577e` resta storico e immutabile:
`t1-a100-realpcg-v4-2026-07-19-b14577e.json`
(`1a659df70a5996e2ac0a188f49d190ebc50e3224733536cb9e03c642a6b2f8dc`).
