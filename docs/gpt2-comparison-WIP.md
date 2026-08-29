# GPT-2 real-weight — confronto CPU, A100, Ligero inline e storico X4

> **C4.1 real E2E — FUNCTIONAL PASS / PROVER GATE FAIL (2026-08-29).** Clean
> `a3604cf` sullo stesso A100 ha prodotto una prova canonica reale da
> **67.831.020 B**, l'ha deserializzata e verificata con esito `accept`.
> Dimensione, memoria, soundness e weight-ZK passano; il prover misura
> **7,942478252 s = 1,935020839958646x** l'anchor C4 e fallisce il limite
> `<=1,30x`. Come richiesto, il test è arrivato fino alla fine.

> **C6.2 C62GW4 genesis — TIMING HARD STOP (2026-08-19).** Clean `299050d`
> passed CUDA and preflight and generated all 17 setup profiles
> (`101.197.617 B`). The only authorized genesis then established a complete
> inline lower bound of **77,422289502 s > 15,75 s** before any proof.
> It was interrupted once; no retry, verifier, mutation or artifact exists.

> **C6.2 first real A100 E2E attempt — PRE-SESSION FAIL (2026-08-17).** The
> single authorized run used clean source `126dbe3` on one
> A100-SXM4-80GB. The mandatory CUDA gate passed 37 tests and failed two
> bit-exact CPU/GPU checks. It stopped before setup generation. No retry was
> performed. No proof or production artifact exists, so there is no
> valid C6.2 provider, prover, consumer-verifier, byte, or session value to add
> to the main comparison table.

> **Stato 2026-07-28 — documento WIP tracciato.** X4/X4d resta storico e
> sospeso. C4 ha completato un pair A100 same-build pulito a `e99a1e5`:
> l'anchor Ligero inline `rate=1/4,Q=120` passa tutti i gate; il candidato
> `rate=1/8,Q=97` risparmia esattamente **4.977.848 B/risposta** e passa i
> gate di prover puro, soundness e memoria, ma il verdetto complessivo è
> **FAIL**. La sessione completa misura **1,050816638x >1,05x** e una
> ripetizione misura **0,155717607 s >0,150 s** di sincronizzazione. Non è
> stato eseguito alcun retry selettivo. Il product owner ha adottato il
> rate-8 come base di un distinto C5 senza riscrivere questo FAIL. C5
> Packed16 si è però fermato localmente al gate typed-PCG: la risposta
> **61.292.904 B** resta una proiezione, non una nuova colonna misurata. Non
> esistono implementazione, pod, pair o verdict C5.

## Terminologia operativa

- **Prova** significa l'intero artefatto serializzato inviato dal prover. Non
  usiamo “certificate” o “transcript packed” come sinonimi nel testo corrente;
  i nomi macchina storici restano invariati per compatibilità.
- **Prover time** è prefill più decode marginale, cioè
  `t_prove_response_s`. Esclude setup, verifier, codec e il lavoro aggiuntivo
  di una prima prova per legare i pesi. Questi costi sono riportati a parte.
- Il transcript è ancora interattivo/simulato: Fiat--Shamir non è
  implementato. I tempi non includono latenza di rete e non sono credito di
  latenza prodotto.
- Un **lotto** è tutto il preprocessing segreto one-time consumato da una
  risposta. Le **slab** sono semplicemente i grandi array di coefficienti
  polinomiali dentro quel lotto; non sono un'ulteriore fase del protocollo.

## C4.1 reale: confronto con l'anchor C4

Il run pulito esegue davvero

```text
setup -> prover C4.1 -> serialize -> proof <70 MB -> deserialize -> verifier -> accept
```

| Grandezza | C4 anchor | C4.1 reale `a3604cf` | Delta / esito |
| --- | ---: | ---: | ---: |
| Prova | 84.544.352 B | **67.831.020 B** | **−16.713.332 B; PASS <70 MB** |
| Proiezione C4.1 precedente | — | 66.270.953 B | artefatto reale **+1.560.067 B** |
| Prover time | 4,104595717 s | **7,942478252 s** | **1,935020840x; FAIL >1,30x** |
| Prover completamente contabilizzato | — | 8,464356373 s | codec e PCS inclusi |
| Verifier core | 0,632347 s | **3,035212223 s** | misurato dopo deserialize |
| Verifier contabilizzato | 0,713656 s | **3,322998133 s** | deserialize + PCS + verifier |
| Serializzazione / deserializzazione | — | 0,111495902 / 0,295940595 s | round-trip esatto |
| Peak GPU | 17.158.968.308 B | **18.056.184.148 B** | **PASS <30 GB** |
| Traffico setup fase-D | 38.371.465 B | 38.371.465 B | reale/AES |
| Incremento setup typed | — | **2.074.954 B** | totale **40.446.419 B** |
| Primo scambio setup + prova | 122.915.817 B | **108.277.439 B** | **−14.638.378 B** |
| Celle Packed16 / bridge | — | 3.110.400 / 640 | nonzero, consumate davvero |
| Chiusura | degree 1 | **una degree-12** | verifier `accept` |
| Soundness composta | 78,809294874 bit | **78,809294874 bit** | **PASS >78** |
| Zero knowledge dei pesi | >78 bit | **120,017006425 bit** | **PASS >78** |
| Verdetto | PASS anchor | **functional PASS; overall FAIL** | fallisce solo il gate prover |

La prova reale include tutti i campi usati dal verifier: estensioni
stable-softmax, Packed16 `d/e`, 640 bridge, entrambe le aperture PCS,
product/zero e framing. Il suo BLAKE3 è
`de1a1624f357e4f8379255146bc6320968fdb8d135a118ff27adfbd2b4ad6918`.
I `67.780.697 B` di transcript sono una metrica interna; la dimensione della
prova è quella dell'artefatto completo, `67.831.020 B`.

Il setup fase-D reale/AES ha richiesto `32,026404679 s`; il setup typed
`0,064411622 s`. CUDA ABI46 SIMT ha espanso il lotto nonzero e ha eseguito il
fold finale a 12 lane; la preparazione del lotto prover/verifier è stata
`0,533527070 / 0,062183571 s`. La costruzione della query globale usa la
riduzione parallela Rayon. Non abbiamo aggiunto un percorso SIMD CPU
separato: sul carico dominante è già usato il percorso SIMT A100, mentre la
ricarica usa H2D asincrono a chunk pinned da 16 MiB.

Operativamente, un prompt consuma un lotto. Un secondo prompt nella stessa
conversazione deve usare un secondo lotto, ma non deve rifare il setup se il
provider lo ha preparato prima. Il record componente misura `1,9739` nuovi
lotti prover/s e `0,750884772 s` per la ricarica cold di un lotto. Un lotto
provider persistito occupa `1.203.724.912 B`; cinque lotti occupano
`6.018.624.560 B`. Dopo cinque risposte occorre generare un nuovo inventario;
un lotto consumato non può essere riutilizzato.

Il raw record append-only è
`benchmarks/results/c41-real-e2e-a100-2026-08-29-a3604cf.json`, SHA-256
`f5af817f00f3cfd5b85c4b128586e3ce952c0e2c56f545ad8701b847ebda911e`.

La quinta colonna conserva il pair pulito X4d.1 a
`b83ffc1`: un settlement `k=1` e uno `k=16` sullo stesso host, build, GPU e
split CPU. Il record `k=16` accetta il settlement e mantiene verde il proprio
G1, ma il verdetto appaiato è **FAIL**: il wall cresce di **2,635946x** contro
il limite vincolante **1,30x**. Inoltre il rerun G1 appaiato è rosso perché
`k=1` misura **0,154283455 s** di sync contro il tetto invariato **0,150 s**.

La terza e la quarta colonna sono il pair C4 sullo stesso checkpoint, host,
GPU, quota CPU e binary. Tutti i valori vengono dai due record raw validati e
dal selettore paired, non da proiezioni.

## C6.2 admission results

| Field | First authorized attempt | C62GW4 genesis |
| --- | ---: | ---: |
| Source | `126dbe3`, clean | `299050d`, clean |
| Provider hardware | A100-SXM4-80GB, CUDA 12.8 | A100-SXM4-80GB, CUDA 12.8 |
| Mandatory CUDA gate | **37 passed / 2 failed — FAIL** | **7/7 boundary + 4/4 runner — PASS** |
| Setup generation | not started | **17 profiles; 101.197.617 B** |
| Production session | not started | **timing hard stop before proof** |
| A100 prover value | not measured | **>77,422289502 s lower bound — FAIL** |
| Consumer CPU verifier value | not measured | not run |
| Proof and first exchange | not measured | proof not created |
| Retry | none; forbidden | none; forbidden |
| Comparison credit | **none** | **none** |

The first failure is a CPU/GPU exactness mismatch in the attention proof wires
and protocol field algebra. C62GW4 clears that boundary but fails the complete
online wall before a proof, so the main table still remains unchanged.
The first append-only incident record is
`benchmarks/results/c62-a100-preflight-failure-2026-08-17-126dbe3.json`,
SHA-256
`9190621281ce5cb5b2c37d4b30bc945692405170fdc6203e58c3f3e4268f0d6e`.

## C6.4 final R10c disposition

Clean A100 `d441ae6` also supplies no value for “Prova risposta totale”: the
first proof was still absent when the owner stopped the campaign after
`3529.377744423 s`. The compiler phase alone was unfinished after
`3340.554625683 s`. No proof size or verifier measurement exists. These are
incomplete lower bounds, not comparable completed-prover values, so the table
remains unchanged. C6.4 is closed **NO-GO**.

## C6.4 R7 timing disposition

Clean A100 `41b4e07` does not supply a new value for “Prova risposta totale”.
The first proof failed before its serialized envelope when the retained
device-message opening disagreed with its authenticated target. Before that
failure, response construction alone took `65.524719047 s`: provider
`58.727182131 s`, seal `1.266567169 s`, verifier replay `5.433695015 s`.
Residual-owner construction took `11.547041744 s` and projected roots
`5.903876539 s`; the process failed after entering the first native chain.

Thus R7 definitively fails the `<20 s` complete-prover target, but the table row
remains unchanged because there was no complete serialized, reloaded and
verified proof. The earlier `16.800812093-s` figure was a non-credit
component projection and is invalidated by this run, not a measured prover
time. Raw record:
`benchmarks/results/c64-r7-a100-opening-mismatch-2026-08-28-41b4e07.json`.

## C6.4 R6 timing disposition

The row “Prova risposta totale” in the comparison table is not the complete
C6.4 prover/proof interval. Clean `813dd22` recorded **more than
404.726069869 s** from `campaign_start` to the 600-second timebox, with no
proof. Inside that lower bound, response construction was
`66.013804893 s`, residual-owner construction `12.292302782 s`, projected
roots `5.710866424 s`, native four-chain proving `227.869846047 s`, and the
unfinished residual-blind suffix exceeded `92.784116159 s`. The complete
measured process was 600 seconds, but `194.875433059 s` preceded
`campaign_start`; therefore neither 600 seconds nor 66.014 seconds is the
comparable “Prova risposta totale” value. All C6.4 R6 timing and size gates
remain `credit:false`.

| Voce | CPU locale (4 thread) | A100 RunPod (8 worker Rayon) | C4 anchor A100 `1/4,Q=120` | C4 rate-8 A100 `1/8,Q=97` | A100 RunPod X4d.1 (8 response + 27 settlement worker) |
| --- | ---: | ---: | ---: | ---: | ---: |
| **PCS e legatura dei pesi** | Ligero rate `1/4`, `Q=120` — apertura **inline** per risposta | Ligero rate `1/4`, `Q=120` — apertura **inline** per risposta | Ligero rate `1/4`, `Q=120` — **inline**, profilo accettato | Ligero rate `1/8`, `Q=97` — **inline**, C4 raw **FAIL**, owner-adopted C5 base | `x4-zkdeepfold-ud-e29-v4` (BaseFold/DeepFold), rate `1/8`, `s=111` — **settlement differito**, risposta senza blocco PCS |
| Prova prefill | 10,10 s | 2,54 s | **2,459967 s — PASS** | **2,448463 s — PASS** | **2,256217 s — PASS** (`k=16`) |
| Prova decode marginale | 8,26 s | 1,65 s | **1,647298 s — PASS** | **1,637910 s — PASS** | **1,896501 s — PASS** (`k=16`) |
| Prova risposta totale | 18,37 s | 4,18 s | **4,104596 s** | **4,079376 s; 0,993856x — PASS** | **4,148145 s** (`k=16`, upper median delle tre misurate) |
| Sessione online completa | 30,45 s | 5,60 s | **5,322726 s**, legatura inclusa | **5,593209 s; 1,050817x — FAIL** | **4,783942 s — PASS** alla delivery `k=16`; settlement **878,973898 s/batch — FLATNESS FAIL** |
| Gate corrente | **+14,54% — PASS** | **−14,83% — PASS** | tutti i gate assoluti e anchor **PASS** | prover paired **PASS**; sessione paired e sync assoluto **FAIL** | G1 `k=16` PASS; pair G1 **FAIL** per sync `k=1`; interferenza `k=16` **−2,273545% — PASS** |
| Flat cost (ultimo/primo) | **1,163 — PASS** | **1,228 — PASS** | **1,239678 — PASS** | **1,258492 — PASS** | G1 **1,000 — PASS**; settlement `k16/k1` **2,635946 — FAIL** |
| H2D massimo sessione | n/d | **88,81 MB — PASS** | **67,618556 MB — PASS** | **68,273732 MB — PASS** | **66,93 MB — PASS** |
| Sync wall massimo | n/d | **0,1149 s — PASS** | **0,126796 s — PASS** | **0,155718 s — FAIL** | pair **0,154283 s — FAIL** (`k=16`: **0,126060 s — PASS**) |
| Verifica pura | 0,387 s | 0,832 s | **0,632347 s** | **0,649684 s** | **0,635883 s** (`k=16`) |
| Verifica contabilizzata | 0,468 s | 0,911 s | **0,713656 s** | **0,784628 s** | **0,639966 s/risposta equivalente** (`0,635883 + 0,065331/16`) |
| Token di decode provati al secondo | 2,72 | 11,95 | **12,18** | **12,26** | **12,05** |
| Setup real-PCG | 67,90 s | 48,84 s | **37,811301 s** | **38,859739 s** | **42,151358 s** |
| Peak device live | n/d | n/d | **17,158968 GB — PASS** | **30,146106 GB — PASS** | **47,256775 GB** (X4c peak ereditato) |
| Traffico setup totale | 38,37 MB | 38,37 MB | 38,371465 MB | 38,371465 MB | 38,37 MB (invariante fase-D, non ri-emesso) |
| Prover → verifier | 31,58 MB | 31,58 MB | 31,581007 MB | 31,581007 MB | 31,58 MB (invariante fase-D, non ri-emesso) |
| Verifier → prover | 6,79 MB | 6,79 MB | 6,790458 MB | 6,790458 MB | 6,79 MB (invariante fase-D, non ri-emesso) |
| Prova | **105,72 MB** | **105,72 MB** | **84,544352 MB — exact** | **79,566504 MB — exact** | **41,270464 MB — exact**, stato `WEIGHT_PENDING` |
| PCS opening (già incluso) | 43,27 MB | 43,27 MB | 43,273888 MB; commit/open/verify **0,202900 / 0,298579 / 0,081479 s** | 38,296040 MB; commit/open/verify **0,419875 / 0,307923 / 0,135791 s** | **0 B/risposta**; **3,564780 MB/batch**, **0,222799 MB/risposta equivalente** |
| Logit pubblici packed | **0 MB** | **0 MB** | **0 MB** | **0 MB** | **0 MB** |
| Primo scambio totale | **144,09 MB** | **144,09 MB** | **122,915817 MB** | **117,937969 MB** | **79,641929 MB** alla delivery; settlement differito **3,564780 MB/16** |
| Costo della prima prova per legare i pesi | inline | inline | **inline (0,298579 s)** | **inline (0,307923 s)** | **333,456712 s** (`k=1`) / **878,973898 s** (`k=16`) dal seal |

## Confronto Ligero inline vs settlement differito

Le prime due colonne sono record dell'era C3b (`161fc59`, pre-T1) e riportano
una risposta di **105,72 MB**. Quel valore non è più il riferimento Ligero
corretto: la nuova anchor same-build `e99a1e5` conferma **84.544.352 B
esatti** con lo stesso PCS Ligero e la stessa apertura **43.273.888 B**.
Confrontare X4d.1
con la seconda colonna attribuisce quindi alla migrazione PCS anche i
**21,17 MB** già vinti da T1 sul transcript, che sono indipendenti dal PCS.
La terza colonna rimuove questa confusione.

A parità di generazione dello stack, la sostituzione del PCS vale:

| Grandezza | T1 Ligero inline | X4d.1 `k=16` | Delta |
| --- | ---: | ---: | ---: |
| Prova modello per risposta | 4,104596 s | 4,152718 s | **+0,048122 s** |
| Legatura pesi per risposta | 0,298579 s | 54,935869 s (`878,973898/16`) | **+54,637290 s** |
| Byte per risposta | 84.544.352 B | 41.270.464 B + 222.799 B/risposta equiv. | **−43.051.089 B** |
| Primo scambio | 122,915817 MB | 79,641929 MB | **−43,273888 MB** |

Il rapporto è **184,0x** sul costo di legatura dei pesi a `k=16` e **1.116,8x**
a `k=1`, in cambio di **43,05 MB** per risposta: circa **788 kB risparmiati per
secondo di prover A100 speso**. L'hot path di proving del modello non migliora:
X4d.1 è **+1,172%** più lento dell'anchor Ligero.

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

**Avvertenza di confronto.** L'anchor Ligero è ora a `e99a1e5`, quindi non
precede più X1--X4d; questo chiude il dubbio sulla portabilità del vecchio
record T1. Non è però appaiata per host, build e GPU con X4d.1 `b83ffc1`, né
ne condivide la strategia. Il confronto Ligero/X4d resta descrittivo. Il
confronto C4 anchor/rate-8 è invece same-build e vincolante.

## C4 Ligero inline — paired A100

C4 non riapre il settlement differito. Il pair a `e99a1e5` misura
direttamente sia l'anchor `rate=1/4,Q=120` sia rate-8 `rate=1/8,Q=97`:

| Grandezza | Anchor misurata (`e99a1e5`) | Rate-8 misurato (`e99a1e5`) | Delta / esito |
| --- | ---: | ---: | ---: |
| PCS inline | 43.273.888 B | 38.296.040 B | **−4.977.848 B** |
| Transcript non-PCS | 41.270.464 B | 41.270.464 B | **0 B** |
| Risposta | 84.544.352 B | 79.566.504 B | **−4.977.848 B** |
| Primo scambio, setup incluso | 122.915.817 B | 117.937.969 B | **−4.977.848 B** |
| Media a 2 risposte | 103.730.084,5 B | 98.752.236,5 B | **−4.977.848 B/risposta** |
| Media a 5 risposte | 92.218.645 B | 87.240.797 B | **−4.977.848 B/risposta** |
| Soundness statistica | 78,80929487391641 bit | 78,86651649674867 bit | più forte |
| Codeword residenti | 8.623.489.024 B | 17.246.978.048 B | **+8.623.489.024 B** |
| Peak device live misurato | 17.158.968.308 B | 30.146.106.356 B | **+12.987.138.048 B; PASS <40 GB** |
| Prova risposta | 4,104595717 s | 4,079375688 s | **−0,025220029 s; −0,614434%; PASS** |
| Sessione completa | 5,322725729 s | 5,593208756 s | **+0,270483027 s; +5,081664%; FAIL** |
| Setup real-PCG | 37,811300978 s | 38,859738583 s | **+1,048437605 s** |
| PCS commit | 0,202899867 s | 0,419875443 s | **+0,216975576 s; +106,94%** |
| PCS open | 0,298579063 s | 0,307922895 s | **+0,009343832 s; +3,13%** |
| PCS verify | 0,081478679 s | 0,135791215 s | **+0,054312536 s; +66,66%** |
| Sync massimo | 0,126796018 s | 0,155717607 s | **+0,028921589 s; FAIL >0,150 s** |

Il prezzo misurato dei **4,977848 MB** in meno per risposta è quindi:
codeword raddoppiato, **12,987138 GB** di picco GPU aggiuntivo, circa
**1,048 s** di setup in più e **270,483 ms** in più nella sessione completa.
Il prover puro è invece **25,220 ms più veloce**; il costo emerge nel PCS e
nel verifier, non nel protocol core. Il tetto sessione era
**5,588862015 s**: il candidato lo manca per **4,346741 ms**, e fallisce
comunque separatamente il sync assoluto di **5,717607 ms**. Il risparmio
equivale a circa **18,40 MB per secondo di sessione aggiuntivo**, ma il
prodotto resta non ammissibile perché i gate sono congiuntivi e non
negoziabili.

I record append-only del pair sono:

- `c4-ligero-t1-anchor-a100-2026-07-27-e99a1e5.json`, SHA-256
  `c25c3321b10d17b8c8db675af55d9a4ba0accd2895148c715493dd0883303acd`;
- `c4-ligero-rate8-a100-2026-07-27-e99a1e5.json`, SHA-256
  `aeab6ac703f73ca1f6a40ae85737f4d69838d3b0be1e1f21d005c658484c445e`;
- `c4-ligero-paired-a100-2026-07-27-e99a1e5.json`, SHA-256
  `8506de9ccad35bba76f9cd337ef5a4528613fc91894962e597937b63e3ad3e56`.

Il pair è **overall FAIL**; non è stato ritentato. Le precedenti obstruction
`3058c3c` (floor CPU) e `4097179` (assert del producer), i loro teardown e
l'anchor standalone `4097179` restano immutabili come storia operativa. Il
pod del pair è stato fermato via SSH-side `runpodctl` e il nuovo tentativo SSH
ha ricevuto `Connection refused`. X4/X4d resta conservato ma non è nel
percorso di esecuzione C4.

## C5 Packed16 — target valido, typed-PCG localmente ostruita

Il target di wire rimane matematicamente valido sul rate-8 adottato:

| Grandezza | C4 rate-8 misurato | C5 Packed16 condizionale | Delta |
| --- | ---: | ---: | ---: |
| Correzioni eleggibili | 24.883.200 B | 6.609.600 B | **−18.273.600 B** |
| Non-PCS totale | 41.270.464 B | 22.996.864 B | **−18.273.600 B** |
| PCS inline | 38.296.040 B | 38.296.040 B | 0 B |
| Risposta | 79.566.504 B | **61.292.904 B** | **−18.273.600 B** |
| Setup massimo | 38.371.465 B misurati | **56.645.065 B** | al massimo +18.273.600 B |
| Primo scambio massimo | 117.937.969 B | **117.937.969 B** | invariato |

La colonna C5 non viene aggiunta alla tabella principale perché non è stata
realizzata né misurata. Il gate preliminare richiede cinque scorte da
3.110.400 coppie `(u16,bit)`, cioè 15.552.000 coppie. Restano solo **9,4 bit
di setup per coppia** per generatore, conversione, controlli e frame.

Lo screening locale ha chiuso due conti concreti:

- il C2 malicious-COT con lift aritmetico usa 264.384.000 bit sorgente e
  **4.230.144.000 B** di correzioni `Fp2`; persino il solo core Ferret
  proiettato a 0,73 bit/COT vale **24.125.040 B**, già oltre il margine;
- la conversione esatta dal corrente sVOLE Goldilocks può evitare il bias
  rigettando `p-1` e pubblicando quozienti canonici, ma costa ottimisticamente
  **217.728.000 B** prima delle prove di range malicious. Il setup risultante
  è almeno **256.099.465 B**, cioè **199.454.400 B** oltre il gate.

Le famiglie subfield-VOLE restano nello stesso carattere del campo, gli
edaBits citati introducono autenticazioni e conversioni in due domini, e le
PCG/PCF valutate non forniscono una generazione dealerless malicious di
variabili limitate sotto il `Delta` `Fp2` esterno con un costo serializzato
sotto il tetto. Questa è un'ostruzione della costruzione e dei parametri
valutati, non un teorema d'impossibilità generale.

Il record append-only è
`benchmarks/results/c5-typed-pcg-obstruction-2026-07-28-0309320.json`.
Il suo SHA-256 è
`9e292301af185093b1cc81d3a1b7bc229fad61e6ded61e294d84af0dd2844e49`;
il design C5 finale è
`30a999044e8f61d6625814b51088871c184e2ae72a9397b5fc2da9e05e9f34fc`.
Riporta `pod_contacted=false`, `production_pair_started=false` e
`gate_verdict=false`. Per riaprire C5 serve prima una costruzione typed-PCG
con riduzione di sicurezza e formula byte complete; solo dopo un nuovo
checkpoint locale avrebbe senso richiedere un A100.

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

Le colonne Ligero correnti provengono dal pair immutabile

- `benchmarks/results/c4-ligero-t1-anchor-a100-2026-07-27-e99a1e5.json`
  (`c25c3321b10d17b8c8db675af55d9a4ba0accd2895148c715493dd0883303acd`);
- `benchmarks/results/c4-ligero-rate8-a100-2026-07-27-e99a1e5.json`
  (`aeab6ac703f73ca1f6a40ae85737f4d69838d3b0be1e1f21d005c658484c445e`);
- `benchmarks/results/c4-ligero-paired-a100-2026-07-27-e99a1e5.json`
  (`8506de9ccad35bba76f9cd337ef5a4528613fc91894962e597937b63e3ad3e56`).

I precedenti T1 `4097179` e `b14577e` restano storici e immutabili. Il primo
è `c4-ligero-t1-anchor-a100-2026-07-27-4097179.json`
(`6778cb837406c705c34aa0d3021da48791d2e6ccc8aa98580b0e19888e1ee18d`);
il secondo è
`t1-a100-realpcg-v4-2026-07-19-b14577e.json`
(`1a659df70a5996e2ac0a188f49d190ebc50e3224733536cb9e03c642a6b2f8dc`).
