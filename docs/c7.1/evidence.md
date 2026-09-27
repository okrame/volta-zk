# C7.1 — Evidence and validation

[Status](status.md) · [Design](design.md) · [Security](security.md) · [Decisions](decisions.md)

## Canonical calibration row driver

Il [record del ledger candidato a SHA pulita 79634a3](../../benchmarks/results/c71-candidate-ledger-2026-09-26-79634a3938a7.json)
conserva 22 test Python passati in circa 20 s, entro 60 s/2 GiB con un
thread BLAS/OpenMP/Rayon. Una candidata sintetica cambia la prima uscita
RMS a −1: il ledger confronta tutti i 421 tripletti, programmi, gate e
supporti Rust/Python, con riserve a O=0/150/300 e digest della stessa
mappa/tabelle. Il parser degli screen legge anche quel report; il fixture
storico a scale zero mantiene i suoi conteggi. Include le regressioni
del pilot e del wrapper intero. Nessun checkpoint reale o Γ calibrato,
forward completo, prova o misura H100; `h100_preflight_ready:false`.

Il [record del pilot A a SHA pulita 19f53be](../../benchmarks/results/c71-activation-pilot-2026-09-26-19f53bed7022.json)
conserva 13 test Python passati entro 60 s/2 GiB, con un thread
BLAS/OpenMP/Rayon, e il piano logico senza W. Copre tutte le famiglie
di operatori su un piccolo grafo floating, causalità e assorbimento finale,
confini RNE, provenienza/errori e mancata sovrascrittura; controlla anche
la proiezione nativa dei 1.435 ID A e i dieci alias globali pre-norm.
Include le regressioni del codec delle tabelle e del wrapper intero.
Non legge pesi reali né valida un forward intero completo: esponenti reali,
Γ congelato, picco fisico e tempo H100 restano non acquisiti.

Il [record del controller a SHA pulita 5e9d8ff](../../benchmarks/results/c71-calibration-fixed-run-inputs-2026-09-26-5e9d8ff3e827.json)
conserva cinque filtri Rust e cinque test Python passati, ciascuna
invocazione entro 60 s/2 GiB e un worker. I nuovi controlli coprono il
codec completo da 24.414.870 B generato dal riferimento certificato a
scale sintetiche, ricette/riserve nei tre contesti, errori di input e
record di errore/timeout su candidata congelata. Il test del passaggio KV
usa righe sintetiche per 450 token (405.504.000 B), senza forward numerico,
e verifica mancata copia, rifiuto di trial parziali e cambi di scale.
Le regressioni comprendono righe/storage canonici, rifiuto reale a tre
righe AES e proof lookup/GKR/WHIR ridotta con MAC ideali. La socketpair
del registro richiede il permesso locale mirato dopo EPERM nella sandbox;
nessuna rete esterna. Il record non esegue pesi reali, calibrazione,
forward canonico completo o GPU e mantiene `h100_preflight_ready:false`.

Il [record ingest W a SHA pulita 64732b9](../../benchmarks/results/c71-native-weight-ingest-2026-09-26-64732b9735e2.json)
conserva 19 controlli Python/Rust passati entro 60 s/2 GiB: confronto
BF16, selezione automatica degli esponenti su shard sintetici, hashing
dello stesso stream, ordine packed, limiti operativi e mancata pubblicazione
su errore. Il worker usa un solo buffer per tensore; i controlli non
acquisiscono il checkpoint e non producono Γ calibrato o tempi H100.

Il [record a SHA pulita d3690a6](../../benchmarks/results/c71-canonical-calibration-rows-2026-09-26-d3690a6d0abd.json)
registra due filtri nativi separati, ciascuno entro 60 s/2 GiB con un worker:
dispatcher numerico canonico per righe/driver causale sul suffisso ridotto,
e regressione della proof lookup/GKR/WHIR con MAC originali. Entrambi passano.
Il primo usa geometrie O=0/150/300, dati e tabelle sintetici e una scala RMS
nonzero; controlla anche padding EXP30 e contributo pubblico all'istogramma.
La proof di regressione usa il runner ridotto preesistente, non il nuovo
driver canonico. Non sono Γ calibrato reale, forward completo, picco fisico
o misure H100. Il [preflight](preflight.md#real-calibrated-gamma) conserva
gli obblighi aperti del percorso reale e della calibrazione.

Il [record storage a SHA pulita c862023](../../benchmarks/results/c71-canonical-calibration-storage-2026-09-26-c862023d0c8b.json)
aggiunge il raccordo packed W → embedding/affine/RNE, GELU/gate e PV causale
nei tre contesti, con rilascio all'ultimo consumer e conteggi separati.
Passano un test dello storage e la regressione delle righe numeriche,
separatamente entro 60 s/2 GiB. Sono verificati anche ordine sorgenti diverso
dal file, codec invalido, input troncato, lettura dopo rilascio e arresto del
trial dopo errore. Il record conserva i tre trace dei sottografi e dichiara
`calibrated:false`, `full_model_execution:false`, `credit:false`:
nessuna inferenza completa, proof sul nuovo driver o misura del picco GPU.

I risultati sono distinti per ciò che controllano. Un test finito supporta
la derivazione indicata; non dimostra da solo il teorema generale, la
corrispondenza del wrapper completo o la fattibilità hardware. Il diagnostico
conserva `credit:false` per gli screen e mantiene i campi storici dell'harness.

## Current mathematical result

Fonte: commit `9e57199`, 2026-09-10, [dimostrazione completa](security.md),
[diagnostico](../../scripts/c7_1_gemma_plan.py) e
[test algebrici](../../tests/test_c7_1_gemma_plan.py).
`complete_fixed_run_composition` conserva i bound razionali con l'envelope
aggiunto del caller; i valori decimali correnti sono nello [stato](status.md).
Le verifiche coprono anche traslazione dei pad sulle esposizioni della
stessa sorgente, storia accettata e assorbimento del token finale.

| Controllo a `9e57199` | Esito | Ambito |
|---|---:|---|
| `tests/test_c7_1_gemma_plan.py -k B12` | 49 passati, 154 esclusi | Algebra, contabilità delle riduzioni e composizione finita B12 |
| `tests/test_c71_bootstrap.py tests/test_c7_1_baseline_budget.py` | 29 passati | Bootstrap condizionale, budget e conservazione delle decisioni B1–B12 |
| `tests/test_c7_1_gemma_plan.py -k ideal_mac_simulation` | 1 passato, 202 esclusi | Coupling NoPeek riusato da G2 sui veri prefissi FS |
| CLI del diagnostico, default e self-check | passati | Report contabile e JSON valido, senza allocazioni Gemma |

Sono 79 controlli Python mirati. Non è stato eseguito un nuovo Rust E2E,
una build Lean o un benchmark per la chiusura matematica. Non trasformare
`conditional_mathematical_goal_complete` in ammissione del runtime o dell'hardware.
I risultati e le derive complete restano collegati anche al
[notebook congelato](../c7.1-gemma31b-design.md#b12-criterio-di-chiusura-composizione-completa-same-w).

## Streaming and authorized bootstrap screen

Il [diagnostico](../../scripts/c71_streaming_screen.py) riprende il trust
model B12 + EA-LPN-SL-reg* autorizzato e i lower di ripiego, mantenendo
`credit:false`, nessun tempo completo e nessuna ammissione fisica.
La [derivazione](construction-screen.md#screen-dopo-lautorizzazione-ea-lpn-e-ripiego-sui-byte)
distingue capacità base/Fp3, bootstrap unico, intervalli wire e unione
condizionale degli errori. Non modifica i bound del teorema B12 v1.

I [controlli finiti](../../tests/test_c71_streaming_screen.py) verificano:

- sumcheck quadratico in due letture con gli stessi coefficienti/sfide/
  terminali del calcolo denso, più un controesempio al pruning dei supporti;
- riduzione per coset identica alla valutazione RS diretta, inclusi i pad,
  e contabilità dei buffer/scansioni nelle geometrie canoniche;
- variante suffix-first con riordino del punto finale nella stessa
  polinomiale W originale, senza cambiare il commitment;
- radici e antenati del range costruiti per blocchi identici al tree intero;
  conti di liveness e checkpoint dello schedule integrato;
- dal 2026-09-13, gather/rebuild dei round iniziali e successiva
  materializzazione dei figli piegati: stessi coefficienti cubici con sfide
  adattive, stessi terminali e visite/merge contati contro il denso su F97.
  Più di quattro letture sono ora autorizzate; il tempo resta ignoto;
- finestre Gram private non simmetriche, pesi del prefisso e fold su
  entrambi gli assi: stessi quattro coefficienti e terminali del denso
  con sfide adattive; conteggio della schedule variabile da 26 visite.
  L'audit indipendente conferma il minimo del modello parziale, non del tempo.
- frontier Merkle per coset con root/path canonici, replay dei sali da
  offset con rejection sampling e rifiuto di alterazioni; il test usa
  uno stream toy seekable, non l'adapter BLAKE3 nativo;
- FFT quadrata con tre trasposizioni e due FFT locali, naturale in uscita,
  contro il riferimento Goldilocks per M=4/8/16. Nessun kernel CUDA PCS.

I test lavorano su F97 e piccoli vettori, con sfide dipendenti dal prefisso.
Non eseguono maschere MAC, transcript FS nativo, Dory, Merkle o Gemma.
Confrontare gli endpoint algebrici non equivale a provare il refinement
della nuova schedule o una performance H100.

Riproduzione locale: `PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider
tests/test_c71_streaming_screen.py`; report con
`PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/c71_streaming_screen.py`.
Conservare le regressioni `test_c71_fp6_seed_screen`, `test_c71_dory_path_guard`,
`test_c71_dory_split_check`, `test_c71_dory_rom_cggm` e i filtri B12
`canonical_PCS_wire or complete_fixed_run or native_wire_body`.

## Range kernel preflight

Il [microbench CUDA](../../cuda/c71_range_microbench.cu) usa Fp3 Goldilocks
`u^3=2`, merge frazionario, coefficiente cubico fattorizzato 18-mul contro
oracle diretto 27-mul, fold e Gram L=8/16/32. I
[controlli host](../../tests/test_c71_range_microbench.py) verificano
l'aritmetica ai bordi e confronti algebrici indipendenti; il codice GPU
ha un ulteriore confronto CPU/GPU prima delle allocazioni grandi.
Input, seed, SHA sorgente, geometria e limiti sono registrati dall'
[harness](../../scripts/run_c71_range_microbench.py).

Validazione locale aggiornata: **15 controlli Python passati** streaming/range/remainder
entro 60 s/2 GiB, più confronto host della
[FFT a cinque passaggi](../../cuda/c71_fft_microbench.cu) con DFT e FFT
radix-2, inclusi modello delle coppie di tile M64 e copertura delle scritture.
L'[harness FFT](../../scripts/run_c71_fft_microbench.py) registra input e
metadati e contiene un controllo GPU preliminare, non ancora eseguito.

Il [record statico su checkout pulito](../../benchmarks/results/c71-local-cuda-static-2026-09-13-ef2cdabc1afa.json)
fissa SHA `ef2cdabc1afabdb687e280092d0e07f8e40e30f0`,
archivi/toolchain, patch header, errori iniziali, log ptxas, dump SASS
del merge e controlli host dei binari CUDA. `git_dirty:false`,
`gpu_execution:false`, `credit:false`; nessun tempo GPU.

Il [nuovo record statico dei costi dominanti](../../benchmarks/results/c71-dominant-static-2026-09-13-ca29dbd3cc8c.json)
è raccolto su SHA pulita `ca29dbd3cc8c`: compile sm_90 di entrambi i file,
15 test ridotti, controlli host dei binari CUDA, SASS dei probe range e
della FFT ottimizzata, hash e ledger analitico. Conferma 1.183/231
istruzioni per merge6/leaf-pair e 77 nel ciclo butterfly; zero stack/spill,
range max 80 registri, FFT max 40 (row 32). Conserva per riferimento
l'evidenza precedente e la patch temporanea del toolkit. È `credit:false`,
`git_dirty:false`, `gpu_execution:false`: nessun tempo GPU o upper completo.

Range e FFT compilano per sm_90 con CUDA 12.9.1 temporaneo, nvcc 12.9.86,
zero stack/spill ptxas, massimo 80/40 registri rispettivamente. Il toolkit
ARM64 SBSA verificato SHA-256 richiede sulla VM glibc 2.41 la correzione
locale dichiarata di quattro prototipi sinpi/cospi non usati. La prima
compilazione fallita resta evidenza, non viene cancellata dal successo.
Non sono una misura H100, un compiler production intatto o un credito
per il reader/PCS integrati. La Gram materializza H per bucket soltanto
nell'input componente limitato. Il [preflight](preflight.md) riporta il
census SASS del merge e le condizioni dei lower temporali.

Il [test remainder](../../tests/test_c71_query_remainder.py) confronta
quattro FFT online per blocco con divisione ingenua e valutazioni RS,
pad privati non nulli, zeri pubblici e leading block parziale. È algebra
finita, senza PrivateRng/Merkle/codec nativo. Il nuovo ledger include
A corrente/storiche, KV pendente, geometria dei 12 oracoli dati e PCG
lifetime; gli upper di ammissione ignoti restano infiniti. Il confronto split-pad mantiene X^M*pad privato e controlla il layout
contiguo nativo dei coefficienti (una sola coda parziale, non 128).
I nuovi check verificano mul6/leaf-pair, formula dei sottoalberi zero,
ricomposizione i16 esatta e indici FFT shift/mask contro divisioni.
Il range timed resta la baseline mul9: i nuovi kernel sono probe compile-only.
Nessuna misura dei probe è attribuita al driver originale. Il goal fisico
non è dichiarato concluso e non è stata eseguita GPU.

## Trace A/KV, WHIR e PCG della risposta

I nuovi [getter](../../scripts/c71_getter_trace.py),
[WHIR](../../scripts/c71_whir_trace.py), [PCG](../../scripts/c71_pcg_trace.py)
e [ledger temporale](../../scripts/c71_response_trace.py) sono strumenti
locali `credit:false`. Coprono indirizzi/codec dei byte originali, shape
canoniche, ultimo consumer dei tensori, ordine root/OOD/query/fold,
segreti persistenti e burn/carry PCG. I test finiti confrontano singleton
sumcheck e covettori geometrici con il denso; H/EAGen hanno sampler
bounded. Non eseguono Gemma, bootstrap completo, provider o GPU.
La retention controlla tutte le transizioni S1…S11 e il base case:
commit del successore, query del predecessore ancora immutabile e solo
poi fold/fence. Il ledger distingue 36 passaggi della sorgente originale
da 80 degli stati conservati; non li somma come visite equivalenti.
Il precompute P/Q ha un reference finito con uniformità completa ancora
da dimostrare; non è un port FFT/product-tree nativo.

La correzione KV deriva dalle shape pinned e distingue cache originale
dall'incremento A: il [preflight](preflight.md#trace-della-risposta-e-budget-separati)
contiene i conti corretti. I vecchi record immutabili restano preservati.
La partizione temporale impedisce di sottrarre ricostruzioni dal proof-only;
upper mancanti restano null, non sono riempiti dai budget di 3/47/50 s.
Il setup di sessione è addebitato una volta alla prima prova. I lower
condizionali respingono alla terza risposta sia il piano senza retention
sia quello retained con quattro GEMM; non ogni possibile costruzione.

Il [record immutabile dei trace](../../benchmarks/results/c71-response-trace-2026-09-13-aca17d19eb4b.json)
è raccolto su SHA pulita `aca17d19eb4b`, con hash delle sorgenti e del trace
getter completo, ledger WHIR/PCG/risposta e stdout dei controlli.
È `git_dirty:false`, `credit:false`, `gpu_execution:false`; collega il
record dominante precedente per correggere il KV senza sovrascriverlo.

Validazione su quel checkout: **27 test passati in 3,77 s**, controllo link
locali e `git diff --check` senza errori. Nessun Rust/Lean build o GPU.
Riproduzione mirata (60 s/2 GiB):

```sh
ulimit -v 2097152
PYTHONDONTWRITEBYTECODE=1 timeout 60s pytest -q -p no:cacheprovider \
  tests/test_c71_getter_trace.py tests/test_c71_whir_trace.py \
  tests/test_c71_pcg_trace.py tests/test_c71_response_trace.py \
  tests/test_c71_streaming_screen.py
PYTHONDONTWRITEBYTECODE=1 timeout 60s python3 scripts/c71_response_trace.py
```

## Shared RNE byte experiment

**Checkpoint v2 (2026-09-12).** Il primo livello GKR consuma direttamente
il peso delle forme originali; spariscono sumcheck quadratico e MAC della
root separati. Il positivo piccolo passa da 22.436 a **14.552 byte** per
le sole prove RNE, con **10.764 byte** condivisi e **1.055 righe Fp3** nel
controllo composto. Rimangono esclusi i costi esterni elencati sotto.
Passano 21 test Rust distinti: quattro RNE/codec, copertura dei gruppi,
tre range, prodotti, funzioni byte, due confronti joint-inference, gli
otto wrapper nativi e il corpo canonico sintetico; due test Python dello
screen PCS passano. Build mirata offline, un job; invocazioni Rust con
60 s/2 GiB e un worker Rayon. Il test del pool reale ha prima incontrato
il divieto sandbox di creare una socketpair Unix, poi è passato con
l'accesso locale consentito. Nessun run hardware o nuovo bound composto.

I numeri nei paragrafi seguenti documentano **v1 e il suo record congelato**;
non vengono attribuiti al codec v2. La proiezione v2 con gruppi senza
padding è nello [screen attivo](pcs-state-screen.md#rne-eliminare-il-padding-aggiunto-prima-di-confrontare-il-lavoro).

Il [record immutabile](../../benchmarks/results/c71-rne-joint-bytes-2026-09-11-589ce7b8f86c.json)
proviene dal commit `589ce7b8f86c` con `git_dirty:false`, limiti, hash del
binario, comandi e output integrali dei due controlli della candidata.

Il [test di prove valide](../../rust/volta-pcs/src/c71_matrix/rne/batch_tests.rs)
esegue due RNE con shift 2/1, punti distinti, tre/due celle vive, padding
e raw in blocchi fisici non contigui della stessa A/D10. Usa MAC ideali
casuali, trasporto `Wire`, range byte e PCS salata realmente verificata.
La variante [condivisa](design.md#experimental-shared-rne-byte-proofs)
consuma 1.074 righe Fp3 nel controllo composto di queste due RNE/range/PCS.
La serializzazione delle **sole prove RNE**, con prefisso della lista,
passa da **22.436 a 15.180 byte**, un risparmio di 7.256 byte (32,34%).
Il P/S condiviso e la riduzione iniziale occupano 11.392 byte.
Questi valori escludono correzioni dei due output, range, PCS e framing
esterno: non sono la dimensione completa del piccolo certificato.

Output falso, MAC originale alterato, tabella modificata e riordino sono
respinti. Un raw diverso che arrotonda allo stesso output supera le RNE
ma viene respinto alla PCS originale. Il decoder rifiuta i troncamenti;
prover/verifier positivi ricostruiscono lo stesso digest e consumano
esattamente la riserva. La baseline è misurata con il prover corrente in
un transcript indipendente. Non si comprime una fixture nulla per attribuire
un risparmio a una prova valida.

Il [censimento canonico](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical.rs)
visita le 892 richieste nei tre contesti e ottiene due gruppi virtuali
D34/D33. Verifica copertura, allineamento e assenza di sovrapposizioni;
serializza e fa roundtrip dei due nuovi `Wire` con valori sintetici:
40.960 +39.904 = **80.864 byte**, più **12 byte** per i due nuovi frame.
Il primo screen con un gruppo unico aveva respinto il superamento di D34;
non si amplia quel limite nella candidata corretta.

| O | P/S precedenti | Nuove RNE, fixture scale zero | Risparmio incluso framing | Proiezione totale lower–upper |
|---:|---:|---:|---:|---:|
| 0 | 25.210.128 | 5.475.424 | 25.129.252 | 22.711.928–39.923.992 |
| 150 | 25.267.728 | 5.488.384 | 25.186.852 | 29.681.466–53.758.874 |
| 300 | 25.267.728 | 5.488.384 | 25.186.852 | 36.610.532–67.536.452 |

Byte decimali. La colonna RNE include i due payload condivisi ma non i
loro frame, i prefissi esterni o le sonde; il risparmio totale paga anche
i nuovi frame. Le righe Fp3 eliminate sono 839.615/841.535/841.535 per
tentativo. Le proiezioni sottraggono il risparmio dai
[bound completi del codec corrente](design.md#canonical-pcs-wire-accounting):
tutte le PCS, i loro hash/maschere/sali, range, altri operatori, header
e chiusura restano conteggiati con gli stessi parametri. Il lower conserva
le omissioni esplicite di GKR congiunti e fratelli Merkle; non è una
dimensione necessariamente realizzabile. La nuova schedule dovrà usare
un profilo distinto di pari lunghezza, senza metadata scelti dalla prova.

**Ambito:** `credit:false`; positivo componente su dominio piccolo,
geometria/codec sintetici sui descrittori canonici, proiezione dei byte
completi. Nessuna prova Gemma canonica valida, nuova sicurezza composta,
esecuzione AES positiva o misura hardware. Il lower a O=300 supera
ancora 35 MB: questa modifica da sola non basta per tutti i turni.

Filtri riproducibili, con la [build mirata e i limiti usuali](../procedures/build-and-test.md):
`c71_b12_rne_joint_bytes_valid_proofs_and_original_pcs` e
`c71_b12_rne_joint_bytes_canonical_geometry`, ciascuno con
`--test-threads=1 --nocapture`, un worker Rayon, 60 s e 2 GiB.
Sono passati nove test mirati: i due nuovi controlli, le ricette RNE,
RNE ties/overflow/PCS, funzioni byte, Prepare ridotto, composizione nativa
a tre tentativi, rifiuti del certificato e codec canonico completo
sintetico. Le regressioni conservano byte/FS del percorso corrente.
Format dei file Rust toccati, link locali e `git diff --check` passano;
nessuna build workspace o Lean è stata eseguita.

## PCS/state byte and work screen

[Record immutabile](../../benchmarks/results/c71-pcs-state-2026-09-11-fe3b8ebcfaf3.json)
dal commit `fe3b8ebcfaf3`, con `git_dirty:false`, hash del binario, comandi,
output integrali, limiti e rapporto contabile. È evidenza componente/screen,
non un benchmark completo. Conserva anche la disposizione del primo
fallimento della geometria D10.

Lo [screen](pcs-state-screen.md) e il
[diagnostico](../../scripts/c71_pcs_state_screen.py) confrontano i bound del
codec B12 con due schedule candidate, senza ammissione del lavoro completo.
Il [controllo nativo PCS](../../rust/volta-pcs/src/c71_matrix/codec/tuning.rs)
produce PCS D12 valide con gli originali e trasporta il vero codec:
circa 3,17 MB nella baseline, 1,64 MB con tre esposizioni e 1,45 MB con due.
Sono byte PCS, esclusi i due word di scaffolding del test; non una prova
linear o un certificato Gemma completo. Tag/punti cambiano a ogni apertura,
la root installata resta identica; falso target e troncamento sono respinti
e i due ruoli ricostruiscono lo stesso FS. Il primo test D10 1→4 ha fallito
`RateGrowsDomain`; il controllo corretto D12 4→4 non cancella quel fallimento.

Per D35/D34, il test fa roundtrip di fixture sintetiche sia senza fratelli
Merkle sia con frontiere massime: 5.157.568–7.932.608 e
4.434.784–7.136.864 byte rispettivamente. Nessuna root/PCS canonica valida
viene materializzata. Il gamma numerico sperimentale è di 1.517 byte;
lo screen riserva i 2.277 del vecchio profilo per includere la nuova identità.
Il runner test-only non rende selezionabile il profilo dal peer.

Il censimento delle 892 RNE rende esplicito il lavoro aggiunto dai due
vecchi gruppi padded e controlla il nuovo `unpadded_groups`: copertura
unica, layout allineato e identico numero di celle ai prover separati.
Le dimensioni canoniche sono sei/otto/otto gruppi; i byte includono i frame.
Il kernel positivo RNE condiviso preesistente resta verificato. Non c'è
un positivo canonico della nuova schedule RNE/PCS/KV.

Passano **7 test Rust mirati**: PCS valida, geometria/codec PCS candidata,
gruppi esatti, censimento RNE canonico, positivo RNE condiviso, codec PCS
B12 e composizione ridotta a tre tentativi. Passano **4 test Python**:
screen/stato e regressioni `canonical_PCS_wire or native_wire_body or
complete_fixed_run`. Tutti i test Rust usano un worker Rayon e 60 s/2 GiB,
in serie, dopo la build mirata con un job. Il check Python sul prefisso
è un'identità finita MAC/MLE, non una dimostrazione della sicurezza FS.
Le [procedure](../procedures/build-and-test.md) riportano i filtri esatti.

I campi `full_prover_work:null`, `full_work_nonincrease_verified:false` e
`complete_security_proven:false` sono obbligatori per questo screen.
Non sono stati eseguiti benchmark GPU, bootstrap completo o inferenza
Gemma, e non è stata cambiata la costruzione selezionata.

### Retained initial PCS data

[Record immutabile](../../benchmarks/results/c71-pcs-retained-2026-09-11-d84e7da4e24f.json)
dal commit `d84e7da4e24f`, con `git_dirty:false`, hash del binario, build,
comandi e output integrali. Passano nove test Rust mirati (riuso,
PCS valida, salted/codec, tre campo/FS e due composti) e quattro Python
(screen e regressioni dei byte/composizione). I limiti sono 60 s/2 GiB,
un worker Rayon e nessun test Rust parallelo.

Il nuovo confronto in `codec/tuning.rs` esegue sette coppie di aperture:
tre D12 B12, due D12 candidate e due D10 candidate senza switch.
Nei casi D12 byte nativi e FS coincidono esattamente; tutti i casi
verificano PCS e chiusura MAC. D10 mantiene il rifiuto del codec nativo
per oracolo finale base e confronta serde completo, senza cambiare formato.
Il trace del DFT elimina solo l'encode iniziale; i buffer conservati
mantengono i propri indirizzi. È un risultato del kernel, non del wrapper
canonico o dello schedule fisico fuori H100.

Lo [screen aggiornato](pcs-state-screen.md#dati-iniziali-conservati-uguaglianza-della-prova-e-lavoro-evitato)
conta separatamente i commitment iniziali, le PCS fresche, i payload
persistenti e i prodotti dei covettori per ogni prefisso. Conserva la voce
t*M in aumento nella candidata fold-6: il minor encode iniziale non vale
come confronto del lavoro totale. I campi di non ammissione restano falsi.

### Joint W/A/KV state screen

[Record immutabile](../../benchmarks/results/c71-joint-state-2026-09-11-d0191f0127fd.json)
dal commit `d0191f0127fd`, con `git_dirty:false`, hash del binario, build,
comandi e output. Passano tre test Rust (PCS positive, codec sintetico e
regressione del riuso) e cinque Python (screen, routing e tre regressioni).
I test Rust sono seriali, un worker Rayon, 60 s/2 GiB ciascuno. Il record
conserva le esclusioni del primo fold D36 fuori dominio e del conto che
ometteva erroneamente il collegamento all'installazione.

Lo screen aggiunge uno stato unico S/D36 e conserva il link PCS al W/D35
installato prima del primo prompt. Gli upper completi condizionali sono
26.653.252 / 28.444.684 / 28.444.684 byte, due PCS per risposta.
Setup, nuovi commitment e aperture sono contati in ogni prefisso;
il minor costo delle query è distinto dalle maggiori celle dei sumcheck
iniziali. Lavoro totale e sicurezza completa restano non verificati.

Il controllo algebrico finito verifica il trasporto delle forme W/A ai
nuovi offset con gli originali MAC e distingue W installato, ultimo KV,
nuove sorgenti A e padding zero. Non è una composizione FS.
Le geometrie sintetiche PCS aggiunte sono W/D35 a una esposizione
(4.000.792–6.323.480 byte) e S/D36 a due (5.288.656–7.990.736).
Il positivo piccolo copre anche una esposizione e D13/fold iniziale 5,
sempre con target falso e troncamento respinti. Il dispatch C71 e la
costruzione selezionata restano invariati.

### Joint-state native transition and retained wrapper

[Record immutabile](../../benchmarks/results/c71-joint-native-2026-09-11-dc635fc402ae.json)
dal commit `dc635fc402ae`, con `git_dirty:false`, hash del binario, build,
comandi e output dei dodici controlli. Ogni invocazione Rust è seriale,
un worker Rayon, limitata a 60 s/2 GiB. I byte esatti di queste emissioni
sono nel record; dipendono dalle frontiere Merkle delle sfide fresche.

Il nuovo [runner test-only](../../rust/volta-pcs/src/c71_matrix/gemma/native/joint_state.rs)
esegue tre transizioni con W/D12 installato e S/D13: link W/KV con MAC
originali condivisi, range i16 simmetrico W, range byte A, padding zero,
due batch lineari/PCS e record finale nello stesso FS. Il wrapper con
conservazione riusa i dati del commit attraverso `Arc`; quello ordinario
mantiene la rimaterializzazione. Ogni snapshot nasce una volta e il
predecessore viene rilasciato dopo la promozione.

I tre test nuovi passano: sequenza positiva e digest FS concordi;
W iniziale alterato, quarto zero alterato, byte 256 e i16 -32768 respinti;
ultimo KV accettato alterato respinto. Troncamento tardivo non promuove e
brucia la riserva; retry, capacità insufficiente e root ritirata sono
terminali. La capacità ideale consumata è 66.524 / 66.528 / 66.528 righe
Fp3, 199.580 totali, con cursor verificato. Non è un bootstrap PCG reale.

Passano anche nove regressioni: PCS coi nuovi parametri, equivalenza dei
dati conservati, salted/codec, tre campo/FS e due composti B12 ordinari.
Le emissioni sono framing reale di prove valide sui dati sintetici, circa
4,36 / 4,78 / 4,78 MB. Non contengono inferenza o RNE: non sono un
confronto di certificati Gemma, né misure complete di lavoro o sicurezza.
La tabella degli upper canonici rimane una proiezione separata. I cloni del
verifier nei casi negativi sono replay controfattuali di una sola prova.

### Joint-state complete bounded inference comparison

[Record immutabile](../../benchmarks/results/c71-joint-inference-2026-09-11-869e00974eec.json)
dal commit `869e00974eec`, albero pulito prima e dopo i quindici
controlli seriali, con hash binario, build, comandi e output. Il record
conserva separatamente il confronto preliminare con RNE originali da
working tree: non è un run di record né il risultato selezionato qui.

Il [runner](../../rust/volta-pcs/src/c71_matrix/gemma/native/joint_inference.rs)
confronta tre certificati B12 con la candidata W/D12–S/D13, sullo stesso
modello e conversazione. Verifica uguaglianza dei token e dell'intero A
numerico prima del packing, digest FS concordi e riserve esatte. I byte
completi sono **7.741.001 / 10.944.887 / 14.151.777** per B12 e
**5.006.647 / 5.438.291 / 5.446.811** per la candidata. Le PCS sono 2/3/4
contro 2/2/2. Le sette riduzioni RNE originali chiudono in tre gruppi byte
da 128/64/32 celle, senza padding aggiunto; le righe Fp3 ideali totali
sono 265.713 contro 261.992. Non sono misure del prover canonico.

Passano il positivo composto, il negativo con ultima K accettata alterata,
otto regressioni del runner B12, due RNE e tre transizioni sintetiche.
Troncamento tardivo e cardinalità RNE errata sono rifiutati sui cloni
diagnostici del verifier; il tentativo fallito consuma l'intera riserva e
non promuove. Il negativo KV produce prima l'intera continuazione e viene
rifiutato dal MAC del sumcheck finale; un retry non consuma un'altra riserva.
Restano aperti lavoro totale, esecuzione canonica/AES e composizione ROM/ZK
come dichiarato nel [design](design.md).

## Native component evidence

Il [catalogo dei controlli nativi](../procedures/build-and-test.md#rust-and-resource-limits)
conserva filtri, casi negativi, dipendenze e limiti di esecuzione. I suoi
conteggi intermedi descrivono le singole fixture o fasi della costruzione;
non sono profili alternativi all'attuale composizione. Le derivazioni di
ciascun port restano nel [notebook B12](../c7.1-gemma31b-design.md#b12-pcs-unicità-del-messaggio-e-compilazione-privata).
Questa tabella indica come usare l'evidenza, senza ricopiare ogni sottoconto.

| Famiglia | Evidenza disponibile | Limite |
|---|---|---|
| B11 reale/AES e capacità B12 | Ruoli indipendenti, vettori AES/SHAKE, byte fault, seal, burn e arresto del pool | Componente bootstrap; non prova del wrapper Gemma |
| PCS salata/claimless, linear e range | Target originali, segni QuickSilver, falso target/padding respinti; piccoli casi con pool reale o MAC ideali | Configurazioni grandi solo pubbliche; nessun codeword D34/D35 materializzato |
| P0 e layout Gemma | 773 riduzioni compatte e route fisiche/virtuali; piccolo grafo raw con W/A ranged | Metadata e grafi ridotti; placeholder root non acquisiscono accettazione PCS |
| Byte/RNE/RMS/statistiche/lookup/gate-up/RoPE | Kernel e forme originali con casi avversari verso le stesse sorgenti | Profili e domini circoscritti; copertura numerica completa non equivale a esecuzione Gemma |
| QK/PV, residuali, KV | Link originale M→Pi, route O=0/150/300 e PCS fresche delle vecchie A | Le ricevute dei test KV sono ricevute di componente, non storia Gemma completa |
| Output/argmax/ratio/EXP30 | Output e softmax su byte originali; DV retag del dummy e rifiuti semantici | Accettazione del dummy è un controllo della simulazione, non da sola una prova ZK |
| Profilo comune e replay ampio | [profile.rs](../../rust/volta-pcs/src/c71_matrix/gemma/profile.rs), 421 profili/alias, produttori unici e punti MAC originali | Scale sintetiche, con controlli di copertura; non calibrazione del checkpoint |
| Ultimo preflight completo | `c71_b12_preflight`: tre contesti senza espandere le celle, riserva completa e rifiuto prima di getter/FS se capacità insufficiente | 11.187.057 righe base per quel profilo; GELU/softcap/RoPE sono placeholder di forma, non tabelle certificate |
| Ultime sorgenti flat | `c71_b12_flat_sources`: D11, 1.031 valori vivi signed/byte, target oltre indice 1.023 e padding alterato | D34/D35 verificati solo come profilo/framing; runner pubblico sempre n≤128/D14 |

L'upper conservativo del protocollo resta quello di
[security §6](security.md#6-risorse-riuso-formale-e-confine-runtime), non la
riserva inferiore del preflight sintetico. Il codice può accettare geometrie
pubbliche più grandi senza averne eseguito i corpi: distinguere guard del
compilatore, guard del runner e dominio realmente testato. Le vecchie
menzioni di D14/D15/D33 o 131.072 cubi non fissano il profilo completo corrente.

## Native bounded composition

Il 2026-09-10 il [wrapper nativo](../../rust/volta-pcs/src/c71_matrix/gemma/native/protocol.rs)
e il [preparatore](../../rust/volta-pcs/src/c71_matrix/gemma/native/prepare.rs)
sono verificati con otto [test Rust](../../rust/volta-pcs/src/c71_matrix/gemma/native/tests.rs)
e un controllo delle tabelle contro le ricette certificate Python. Si tratta
di verifiche di sviluppo su un grafo piccolo, con correlazioni Fp3 ideali;
non di benchmark su albero pulito, E2E AES o checkpoint Gemma.

| Controllo `c71_b12_native_…` | Proprietà esercitata |
|---|---|
| `prepare` | Tutte le 69 sorgenti, tre contesti, KV dell'ultimo token, ties-to-even e Stop della preparazione |
| `composed` | Tre certificati completi; digest FS uguali nei ruoli; 18 target W, 110 A, uno per vecchia A; riserve esaurite esattamente e promozioni concordi |
| `certificate` | Componente omesso/duplicato/riordinato, cardinalità RNE alterata, byte finali eccedenti, lunghezza ostile e Fp3 non canonico |
| `interrupted` | Troncamento dopo ciascuno dei 17 componenti del primo tentativo; tag finale PCS alterato; nessuna promozione e nessun riuso dopo Stop |
| `context` | W, predecessore, profilo, token, epoch e nonce diversi; replay di una risposta già accettata |
| `consistent_inference` | Calcolo interamente coerente con getter W alterati, mantenendo corpo e root W originali per range/PCS: rifiuto |
| `changed_predecessor` | K dell'ultimo token del predecessore alterata nel getter, con A precedente originale: continuazione respinta e registro fermo alla prima risposta |
| `exhaustion` | Capacità esaurita: Stop terminale, nessuna A pendente/promossa e nessun riavvio |

Il test positivo usa prompt 1 + generato 1 a O=0/2/4, un layer, hidden e
vocabolario 2, W Flat D10 e A Flat D12. Le 942/1.006/1.070 posizioni byte
vive includono tutti i produttori e gli istogrammi; padding fino a D12
verificato. Le PCS per risposta sono 2/3/4; W/A0/A1/A2 hanno 3/3/2/1
esposizioni. Le riserve sono 264.147/265.686/267.306 righe base equivalenti.
I certificati includono kernel, range, PCS, sali/path e framing: i byte
variano con le monete private, senza che questi test forniscano un bound
o una misura del certificato del modello completo.

Le mutazioni del certificato usano fork **solo nella fixture di test**
del registro già verificato e delle relative chiavi, per esperimenti
controfattuali sul medesimo certificato. Nessuna API di fork/import viene
esposta dal protocollo. I casi di getter W/KV alterati generano invece
nuovi certificati avversari e controllano i collegamenti agli originali.

Compilazione mirata `volta-pcs --features c71-b12-pcs --lib --no-run`,
offline/locked, opt-level 2 senza debug/incremental, un job, target canonico.
Ogni filtro sopra viene eseguito separatamente con `--test-threads=1`,
`RAYON_NUM_THREADS=1`, `timeout 60s` e `ulimit -v 2097152`.
Il [test Python](../../tests/test_c7_1_gemma_plan.py)
`-k native_small_profile` confronta GELU, softcap, EXP30 e tutti i sei
coefficienti Q30 con i generatori esatti esistenti. I campi canonici di
ammissione dell'harness rimangono falsi; `native_bounded_composition`
registra questo risultato separato.

Le 797.139 righe base del run composto non sono state espanse con AES:
quel bootstrap supera i limiti dei casi locali descritti nelle procedure.
La verifica positiva del port al pool reale e ai descrittori canonici resta esplicita nel
[design](design.md#native-correspondence). Nessuna esecuzione GPU/provider,
spesa, build Lean o build dell'intero workspace.

Validazione finale: **8 test nativi composti, 6 regressioni native e
81 controlli Python passati**, oltre a CLI/self-check, JSON rigoroso e
controlli documentali. Le regressioni native sono i tre
`c71_matrix::tests::`, `c71_b12_fs_uses_one_tape`,
`c71_b12_salted_merkle` e `c71_b12_real_durable_roles`.
Quest'ultimo ha inizialmente incontrato il divieto sandbox su socketpair;
è passato rieseguendo il solo caso locale con l'autorizzazione prevista
dalle procedure, mantenendo 60 s/2 GiB. Non è un fallimento crittografico.
Il filtro Python combinato è `B12 or ideal_mac_simulation or bootstrap or
budget` nei tre file di test indicati sotto; il controllo delle tabelle
è stato ricontrollato dopo aver adeguato il reader alla formattazione Rust.

## Native canonical and pool extension

Il [compilatore causale](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical.rs)
e l'[adapter reale](../../rust/volta-pcs/src/c71_matrix/gemma/native/pool.rs)
estendono il lavoro locale del 2026-09-10. Il goal resta aperto: questi
controlli non eseguono il preparatore/prover canonico né un'inferenza
composta positiva con AES. Nessun nuovo bound o credito hardware.

| Filtro Rust | Ambito |
|---|---|
| `c71_b12_native_canonical` | Tutte le 3.471 sorgenti hanno un solo produttore; 2.328 produttori ordinati causalmente, 773 P0, 421 RMS, 892 RNE, dieci alias K/V globali, tre contesti; sorgenti omesse/duplicate e ciclo respinti |
| `c71_b12_native_pool_packing` | Tre righe base→Fp3, negazione coerente di Delta, campo canonico e rifiuto di triple incomplete; mutazioni di W, semantica, sessione, seal, epoch, slot, predecessore e cursor |
| `c71_b12_native_pool_real_shortage` | Due ruoli con setup AES reale di tre righe, contesto verifier-owned e capacità insufficiente: Stop prima di prova/promozione, pool inutilizzabile e reopen rifiutato |

Il test con socketpair incontra nel sandbox il divieto di sistema ed è
passato fuori sandbox con gli stessi limiti locali. È un vincolo
dell'ambiente, non un fallimento di verifica crittografica. Non si è
espansa la capacità da 797.139 righe base. I percorsi positivi dell'adapter
sono compilati e condividono i kernel del wrapper ridotto, ma la sola
regressione ideale non ne verifica la composizione AES/journal positiva.
`native_canonical_producers` e i nuovi campi dell'adapter nel diagnostico
espongono questi limiti; le ammissioni canoniche/produzione restano false.

Validazione dell'estensione: **15 test Rust passati** (gli 11 filtri nativi,
tre regressioni lifecycle e `c71_b12_real_durable_roles`) e **81 controlli
Python passati** col filtro B12/NoPeek/bootstrap/budget già indicato.
CLI/self-check e JSON rigoroso passano; verificati link locali, formattazione
e diff. Passa anche `cargo check --lib` senza `cfg(test)`, quindi senza
gli ingressi ideali del wrapper. Build mirate offline/locked, un job, opt-level 2, target canonico
e configurazione `rust/.cargo`; ogni test è seriale entro 60 s/2 GiB.
Sono controlli di sviluppo, non benchmark su albero pulito o test dell'intero
workspace. Nessuna build Lean o esecuzione GPU.

## Integer RMS preparation on canonical descriptors

Il preparatore ridotto usa ora `Norm::prepare_row`, che calcola S/P/Y
con `rms::Integer` e gli stessi coefficienti/limiti del compilatore
booleano. È rimossa la formula privata fissata a due colonne; non cambia
la relazione di verifica né il limite aritmetico u128 ammesso.

`c71_b12_native_norm_rows` esercita una riga sintetica su ciascuna delle
421 norme canoniche (361 pesate, 60 senza parametro), con magnitudini e
segni differenti per testa. Controlla statistiche separate, pesi condivisi,
prodotti originali e output contro il riferimento intero preesistente.
Rifiuta input/weight fuori range, cardinalità e presenza dei pesi errate;
controlla inoltre mezze soglie positive/negative, output zero e overflow.
Non esegue il grafo 100+50, i getter canonici o uno snapshot D34/D35.

`c71_b12_rms_public_circuit` confronta il nuovo rounding con il riferimento
intero e con il replay booleano su cinque ricette, incluse scale non nulle,
conservando gate/depth/row count. Il test ratio copre il limite di larghezza
aritmetica condiviso. Il percorso composto ridotto conserva la propria
verifica nel modello MAC ideale, senza credito AES o canonico completo.

Validazione mirata: **5 test Rust passati** (i cinque filtri indicati nella
[procedura](../procedures/build-and-test.md)) e **2 controlli Python passati**
(`complete_fixed_run`/`native_small_profile`), con limiti seriali 60 s/2 GiB,
un worker Rayon e build offline/locked a un job nel target canonico.
Passa anche `cargo check --lib` senza `cfg(test)`; verificati formattazione,
link locali e diff. Nessun bootstrap, benchmark o esecuzione GPU.

## Integer RNE preparation on canonical descriptors

`Bytes::prepare_rne_row` riusa i controlli di identità/codec/shape del
verifier e chiama `rne::integer` prima dell'encoding. Il preparatore
ridotto usa questo percorso per tutte le proprie RNE; Pi usa la divisione
intera controllata, senza conversioni troncanti da i128 a i64.

`c71_b12_native_rne_rows` copre le 892 coppie nei contesti O=0/150/300,
con una mappa comune di scale che richiede anche uno shift negativo.
Controlla righe signed sintetiche, cardinalità, raw oltre signed-48 e
output con codec sbagliato. `c71_b12_rne_recipes` confronta la nuova
valutazione con il riferimento e i polinomi byte nelle 64 classi, ai tie
e alle soglie di overflow; include shift i32 estremi e denominatori/valori
ai confini i64. Il test ratio confronta anche la divisione del preparatore
con il riferimento e il circuito, nel range ammesso degli operandi.
Non sono istanziati W/A completi o prove canoniche positive.

Validazione mirata: **5 test Rust passati** (`native_rne_rows`,
`rne_recipes`, `ratio_circuit`, `native_prepare`, `native_composed` con
prefisso `c71_b12_`) e **2 controlli Python passati**
(`complete_fixed_run`/`native_small_profile`). Build offline/locked a un
job nel target canonico; test seriali entro 60 s/2 GiB con un worker Rayon.
Passa anche `cargo check --lib` senza `cfg(test)`; verificati formato,
link locali e diff. Nessun bootstrap, GPU o credito canonico positivo.

## Canonical verifier body and prefix

Il [nuovo corpo](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_verify.rs)
implementa tutte le chiamate della schedule con i descrittori canonici;
riusa soltanto decoder e batch interni del percorso ridotto. Il controllo
del prefisso è separato dal wrapper del registro descritto sotto e non
verifica un certificato positivo.

`c71_b12_native_dispatch` passa a O=0/150/300: riserva vuota e profilo
alterato rifiutati senza modificare Fs; riserva ideale completa e frame
pubblico valido raggiungono il guard delle 773 coorti P0, che rifiuta una
prova con zero coorti. Il digest del prefisso coincide con la ricostruzione
delle quattro forme pubbliche e del frame; nessuna chiave è consumata.
Il riordino del primo frame rifiuta prima delle sfide. Le tabelle restano
quelle sintetiche del preflight (EXP30 esatto a e_score=128, le altre solo
di forma); nessun witness o codeword D34/D35 viene materializzato.

Il decoder conserva il cap ridotto di 16 MiB, ora dimostrato insufficiente
dal censimento RNE sotto. Il dimensionamento completo e la verifica
positiva insieme all'header del registro restano aperti.
La presenza delle chiamate a RMS, RNE, lookup,
attenzione e PCS nel corpo compilato non costituisce loro esecuzione
positiva congiunta. Il diagnostico distingue implementazione, prefisso
controllato e verifica positiva assente.

Validazione mirata: **3 test Rust passati** (prefisso e regressioni
`native_composed`/`native_certificate`), **2 test Python passati** col filtro
`complete_fixed_run or native_small_profile`, e `cargo check --lib` passato.
Stessi limiti locali e build mirata di cui sopra, senza nuove esecuzioni
AES, Lean, provider o hardware. Le evidenze precedenti restano distinte.

## Canonical registry and real shortage

Il [wrapper canonico interno](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_state.rs)
collega il corpo al registro locale e a `Pool::attempt`, riusando il
packing delle chiavi del percorso ridotto. `c71_b12_native_registry`
passa con una sola capacità AES di **tre righe base** e due ruoli locali:
il verifier rifiuta la riserva insufficiente, non avanza slot/cursor,
non accetta radici e termina il pool. Un secondo tentativo e il reopen
sono respinti; il journal conserva zero tentativi e testa accettata vuota.
Il test usa socketpair fuori sandbox con i consueti limiti 60 s/2 GiB.

Lo stesso test verifica il binding del modello e nove mutazioni del
contesto, prompt, vocabolario, nonce e freschezza della root. Una storia
sintetica controlla soltanto che ultimo token e ricevuta precedenti
modifichino l'header; viene scartata prima di costruire il verifier reale.
Una tabella softcap di uguale forma ma diverso contenuto cambia Γ senza
cambiare riserva; tabelle non posizionali diverse fra slot sono respinte.
Questi valori sono placeholder di forma e **non** tabelle certificate.

Questo controllo non entra nel corpo dopo un burn completo, né percorre
il journal di successo o una promozione canonica positiva. Il codice
implementa tali collegamenti ma la verifica composta resta aperta, insieme
al preparatore/prover e al codec completo. Non ci sono materializzazioni
D34/D35, bootstrap completo, misure H100 o nuovo credito di sicurezza.

Validazione mirata: **4 test Rust passati** (registro, prefisso canonico,
tre tentativi ideali e codec ridotto) e **2 controlli Python passati**
(`complete_fixed_run`/`native_small_profile`). Passa anche `cargo check --lib`
senza `cfg(test)` con build offline/locked a un job, target canonico e
opt-level 2. Formattazione, destinazioni locali dei link e diff verificati.
Sono controlli di sviluppo, non un run di benchmark su albero pulito.

## Mandatory canonical wire and transport boundary

`c71_b12_native_wire_rne_alone` deriva il censimento wire RNE dai
descrittori canonici posseduti a O=0/150/300. Le somme dei bit di celle
sono 18.935/18.995/18.995. Anche omettendo funzioni e prodotti terminali,
i record richiedono **29.371.448/29.442.008/29.442.008 byte**.
Il precedente cap totale di 16 MiB era quindi insufficiente
indipendentemente dalla calibrazione. È un limite inferiore analitico: esclude altri operatori,
PCS e framing; non è stato generato o misurato un certificato completo.
Per la fixture con scale zero/Pi=-14, il sottototale RNE esatto è
30.604.688/30.675.248/30.675.248 byte. Vedi
[derivazione e lavoro residuo](design.md#mandatory-wire-lower-bound).

`c71_b12_rne_ties_overflow` confronta la formula con `Wire::write` su
una prova componente realmente generata, inclusa la sua prova P/S.
`c71_b12_native_wire_limit` controlla un record di trasporto che termina
esattamente a 16 MiB, con lo stesso digest finale del reader; un byte in
più viene rifiutato senza cambiare writer o Fs. Il writer ometteva i
26 byte del record finale dal controllo della capacità. La correzione
preserva l'encoding e non ammette il certificato canonico. Nessuna
allocazione full-model, PCG o esecuzione hardware.

Il range W richiede 65.535 campi nell'istogramma (`range::verify`),
ognuno di 24 byte più il prefisso u32 del vettore. Questi 1.572.844 byte
sono disgiunti dal sottototale RNE: il limite inferiore congiunto è
30.944.292/31.014.852/31.014.852 byte, già oltre la preferenza di 30 MB.
È un'ulteriore deduzione dal codec; non una misura del range W D35.

Validazione mirata: **5 test Rust passati** (i due `native_wire`,
`rne_ties_overflow`, `native_composed`, `native_certificate`) nei limiti
60 s/2 GiB e un worker Rayon. La build è offline/locked a un job nel target
canonico. Passano anche **2 controlli Python** (`complete_fixed_run` e
`native_small_profile`), `cargo check --lib` senza `cfg(test)`, formato,
link locali e diff. Sono controlli di sviluppo, non benchmark su albero pulito.

## Complete non-PCS wire envelope

Il nuovo controllo Python `native_wire_body_envelope` verifica il
conteggio degli schemi contro i censimenti field preesistenti di P0,
range, QK/PV e GKR congiunto, aggiungendo i prefissi dei vettori e
conservando separati tutti i frame. Il rapporto espone lower/upper,
fixture e header; il rapporto PCS separato fornisce gli upper completi.
Numeri e formule sono nel [design](design.md#analytic-envelope-of-the-complete-non-pcs-body).

Sono conti da descrittori e codice, non prove canoniche serializzate:
`full_native_serialization_checked` resta false per prove valide.
La sufficienza dimensionale dei nuovi cap è verificata separatamente sotto. Il solo corpo supera 35 MB già per la fixture scale
zero/Pi=-14; includendo le PCS sotto, il lower supera l'allarme per ogni
calibrazione. Non viene alterato alcun codec, profilo o limite runtime.

Passano **2 controlli Python** (`native_wire_body or complete_fixed_run`)
e il self-check del diagnostico, con rapporto JSON completo generato in
`/tmp`. Il controllo dell'header ha rilevato e corretto un atteso inferiore
di due byte: il prefisso fisso è 1.321 byte. Verificati 97 link locali e
`git diff --check`; nessuna build Rust/Lean o esecuzione GPU in questo passo.

## Canonical PCS wire census

Il controllo Python `canonical_PCS_wire` verifica i vettori claimless,
le 40 maschere, le 59 aperture salate, i prefissi e la somma di W con
tutte le A storiche/corrente nei tre contesti. Gli intervalli analitici
sono nel [design](design.md#canonical-pcs-wire-accounting). Il limite
superiore dei fratelli segue la ricorrenza del codec; non è una frontiera
osservata su una prova. Nessuna prova valida o inferenza D34/D35 è generata.

Passano **3 controlli Python** (`canonical_PCS_wire or native_wire_body or
complete_fixed_run`), self-check/CLI del diagnostico entro 60 s/2 GiB,
parsing del rapporto JSON in `/tmp`, 98 link locali e `git diff --check`.
Questo primo conteggio non attribuiva credito di serializzazione nativa:
il precedente cap da 8 MiB cadeva dentro l'intervallo PCS.

## Native canonical codecs and complete framing

Il [test PCS](../../rust/volta-pcs/src/c71_matrix/codec.rs) usa le
configurazioni D35/D34 e il vero `decode_linear`/`encode_linear`, senza
witness o alberi Merkle. Conferma byte fissi e frontiere massime, ora
serializzabili entro 16 MiB, e respinge conteggi oltre la frontiera e
input oltre il cap. Ogni gamma canonico è di 2.277 byte.

Il primo confronto aveva fallito con `trailing bytes`: il conteggio
Python usava il messaggio prima del fold finale. Corretto al messaggio
da 32/64 celle, sottraendo 2.304/4.608 byte ad A/W. Il precedente gamma
era di 2.276 byte: il nuovo `cap16MiB` aggiunge un byte per profilo.
Queste correzioni sono distinte da un cambiamento del protocollo numerico.

Il [test del corpo](../../rust/volta-pcs/src/c71_matrix/gemma/native/canonical_wire.rs)
fa roundtrip nei tipi `Wire` di tutte le famiglie con descrittori canonici,
partizione 410/482 RNE e GKR massimi di forma. Ora assembla anche tutti
135/136/137 frame con PCS massime e un header sintetico della lunghezza
canonica: **64.638.068/78.530.550/92.308.128 byte**. Writer e reader
ricostruiscono lo stesso digest; troncamento, riordino e appendice sono
respinti. Il test del confine comprende il footer a 16 e 96 MiB e
rifiuta un byte aggiuntivo prima di cambiare writer/FS.

`native_synthetic_full_framing_checked` è distinto da una prova valida:
questi test non eseguono Prepare o VerifyResponse canonici. I limiti e
il legame al profilo pubblico sono nel
[design](design.md#canonical-transport-limits-and-complete-synthetic-framing).
Il test composto ridotto continua a controllare l'accettazione con MAC
ideali; il test reale preesistente da 180 righe rimane una regressione
matriciale, non il run AES composto da 797.139 righe.

Passano **11 test Rust**: framing completo, cap PCS, confine del trasporto,
composizione ridotta, certificati alterati, dispatcher, registro,
campo/codec, FS, Merkle salato e ruoli durevoli AES. Ogni test è seriale
entro 60 s/2 GiB e un worker; il framing dei tre contesti impiega 1,97 s.
Passano anche **3 test Python** (`canonical_PCS_wire or native_wire_body or
complete_fixed_run`), `cargo check --lib` senza `cfg(test)`, CLI/self-check,
parsing del rapporto in `/tmp`, 101 link locali e `git diff --check`.
Il formato dei moduli modificati passa; il file padre `c71_matrix.rs`
conserva differenze di formato preesistenti fuori dal blocco gamma.
Nessun benchmark su albero pulito, GPU o prova canonica valida è attribuito
a questi controlli.

## Shared affine integer preparation

Il controllo `c71_b12_native_affine_rows` valuta righe sintetiche per tutte
le **181 relazioni affini nei tre contesti canonici**, con coefficienti
del profilo, estremi ammessi e zero. Confronta i prodotti con aritmetica
i128 e controlla il range signed-48; righe corte, input fuori i16, codec
raw errato e coefficienti fuori limite sono respinti prima dei prodotti.
Prepare ridotto e `affine_zero_form` condividono ora la validazione dei
descrittori. La [semantica intera](design.md#shared-integer-preparation)
non introduce arrotondamenti o nuovi MAC.

Validazione del 2026-09-11: **5 test Rust passati** (`native_affine_rows`,
`gemma_affine`, `native_prepare`, `native_composed`, `native_certificate`),
seriali entro 60 s/2 GiB e un worker Rayon. Passano anche **1 test Python**
(`complete_fixed_run`), CLI/self-check con JSON in `/tmp` e
`cargo check --lib` senza `cfg(test)`, offline/locked a un job.
Sono controlli locali di sviluppo: nessuno snapshot canonico completo,
peso reale, bootstrap AES composto, benchmark o esecuzione H100.

## Measured historical records

I file sotto sono immutabili e identificano il codice effettivamente misurato.
Sono risultati locali di componenti; nessuno è una misura del prover Gemma,
del traffico fisico completo o del protocollo composto attuale.

| Milestone e sorgente pulita | Record | Cosa conserva |
|---|---|---|
| B2 `de73f60` | [48×48](../../benchmarks/results/c71-b2-matrix48-20260908-de73f60.json), [128×128](../../benchmarks/results/c71-b2-matrix128-20260908-de73f60.json) | Due risposte matriciali e abort; tuple LPN piccole senza credito di sicurezza |
| B3 `84ab36c` | [census48](../../benchmarks/results/c71-b3-census48-20260908-84ab36c.json), [census128](../../benchmarks/results/c71-b3-census128-20260908-84ab36c.json), [timing128 separato](../../benchmarks/results/c71-b3-timing128-20260908-84ab36c.json) | Operazioni native, heap/RSS e tempi separati; prodotti base e cubic sono viste sovrapposte, non sommabili |
| B9 `fb6c787` | [3 righe](../../benchmarks/results/c71-b9-3-none-20260909-fb6c787.json), [32 righe](../../benchmarks/results/c71-b9-32-none-20260909-fb6c787.json), dieci fault nel budget | MR19/P-521 e COPE/Fp9→Fp3, nove frame e controlli dei due ruoli |
| B11 `8197f42` | [Registro dei dodici casi e relativi link](../c7.1-gemma31b-design.md#b11-selezione-intermedia-aes-a-capacità-finita) | Capacità 180/207 e dieci fault, con AES reale; non il profilo B12 completo |

[Archivio risultati](../../benchmarks/results/) e
[snapshot del ledger](../prototype-status-history-2026-09-10.md) conservano
anche run sporchi, fallimenti socketpair e diagnosi precedenti. I nuovi run
usano file nuovi; il riordino non corregge né sovrascrive questi record.

## Reproduce the narrow checks

Dalla root del repository, senza build Rust/Lean:

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_c7_1_gemma_plan.py -k 'B12 or ideal_mac_simulation'
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_c71_bootstrap.py tests/test_c7_1_baseline_budget.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/c7_1_gemma_plan.py
```

`pytest` è il tool uv globale; gli script usano `.venv/bin/python`.
Il report default mantiene l'harness dei goal a step. `--research-screens`
espone l'inventario storico, non ulteriori termini sommabili al risultato.
Per un cambiamento solo documentale bastano link, coerenza e diff; i
controlli sopra servono qui anche a verificare che il riordino conservi
il contratto del diagnostico. Le [procedure](../procedures/build-and-test.md)
restano l'autorità operativa per build, risorse e pulizia degli artefatti.

## Documentation reorganization validation

Base del riordino: `9e57199`, albero inizialmente pulito. La verifica finale
controlla: prova trasferita integralmente salvo link; snapshot identico;
corpo del notebook identico; percorsi/anchor citati da script e documenti
preservati; diff limitato alla documentazione e agli ingressi README/AGENTS.
Harness, script, test, Rust/Lean, fonti, benchmark e snapshot preesistenti
rimangono invariati.

Esito del 2026-09-10: **79 test passati** (50 B12/NoPeek, 29 bootstrap/budget),
CLI/self-check e JSON rigoroso passati; verificati i valori finali e i campi
dell'harness contro i documenti. I controlli di integrità sopra e dei link
locali/anchor passano, inclusi i riferimenti entranti dai documenti storici. Nessuna build Rust/Lean, esecuzione nativa o misura
nuova è attribuita al riordino. Le correzioni dei guard nelle procedure sono
riconciliate con il codice e i test sorgente attuali, senza rieseguirli.

## Contratto 65 s e margine dell’arena

Il [piano](../../scripts/c71_arena_plan.py) compone i trace con coset A
2^21/S2 2^22 e verifica offset, allineamento e liveness con il
[checker nativo C++](../../cuda/c71_arena_preflight.cpp). Il test compila
soltanto questo programma host, esegue metadati e rifiuta overlap,
rilasci senza fence dichiarata e consumo del margine. Il controllo FFT
finito verifica scatter per parità e ricomposizione naturale, non CUDA.

Il contratto a 65 s modifica le soglie di ammissione, non i vecchi risultati
immutabili. Replay/auth A/KV restano proof-only. I test mirati sono:

```sh
ulimit -v 2097152
PYTHONDONTWRITEBYTECODE=1 timeout 60s pytest -q -p no:cacheprovider \
  tests/test_c71_arena_plan.py tests/test_c71_getter_trace.py \
  tests/test_c71_whir_trace.py tests/test_c71_pcg_trace.py \
  tests/test_c71_response_trace.py tests/test_c71_streaming_screen.py
PYTHONDONTWRITEBYTECODE=1 timeout 60s .venv/bin/python scripts/c71_arena_plan.py
```

Il [record immutabile](../../benchmarks/results/c71-arena65-2026-09-13-2d49690547b9.json)
è raccolto su SHA pulita `2d49690547b9`: 30 test passati in 5,95 s,
report di offset e risposta, hash delle sorgenti e comandi riproducibili.
`git_dirty:false`, `credit:false`, `gpu_execution:false`; nessun modello,
spill o spesa. Collega il record precedente senza modificarlo. Il
risultato è un piano di indirizzi con margine, non il picco fisico completo
o un upper completo di tempo. Il getter full-DAG-per-tessera e il layout
Snapshot denso hanno NO-GO circoscritti nel preflight.

## DAG condiviso e slot reader riusato

Record immutabile: [c71-ordered-getter, 2026-09-13](../../benchmarks/results/c71-ordered-getter-2026-09-13-179acb46e9f5.json),
generato sulla SHA pulita `179acb46e9f5f765e210da22b8f864abd9995e5a`
con `git_dirty:false`. Include i tre trace canonici e i rispettivi hash,
confronto a 1.024 replay, candidata a 512, liveness/offset per tutti gli O,
soglie per fase e stdout della verifica: **29 passati in 11,58 s**.
Il combine dei metadati richiede 9,05 s sul solo host; non è tempo prover.

Il [getter ordinato](../../scripts/c71_ordered_getter.py) compila finestre
A/KV dal DAG esistente e produce conteggi/hash canonici a O=0/150/300.
I [test finiti](../../tests/test_c71_ordered_getter.py) controllano partizione
esatta dei byte, dipendenze condivise, raw contro checkpoint arrotondato,
ultimo consumer, binding del contesto, ordine MSB del range e scatter
lineare fold/coset. Il [piano](../../scripts/c71_arena_plan.py) integra
checkpoint/finestre e riuso del reader nel commit; il checker C++ verifica
gli offset anche per la variante a 512 replay. La proprietà di overwrite
dei digest è un test di indirizzi con hash sostitutivo, non del codec B12.

Il [preflight](preflight.md#dag-condiviso-getter-ordinato-e-riuso-del-reader)
registra NO-GO della schedule seriale 1.024 replay/FFT a batch intero,
la minima alternativa 512 replay e i suoi limiti. Non c'è nuovo credito
Lean, NoPeek, crittografico o GPU. Getter numerico, hash salted in place,
workspace reali e upper completo restano aperti; i ceiling producono lower,
non service floor. Il controllo locale mirato passa 29 test, entro 60 s
per invocazione e 2 GiB, senza eseguire inferenza o workload canonici.


## Getter numerico e hash native a 512 replay

Il [getter Rust](../../rust/volta-pcs/src/c71_matrix/gemma/native/ordered.rs)
confronta tutti i byte originali, istogrammi e padding di tre inferenze
ridotte O=0/2/4, con finestre 1/17/128/1.024. Il replay usa lo stesso
operatore intero del preparatore, una sola generazione di cut i16 e
KV i16 originali. Snapshot denso e A completa appartengono soltanto
al riferimento del test. Root/profilo/token sono metadata fidati:
il test non dimostra il binding del futuro adapter al registro accettato.

I tre [controlli hash](../../rust/volta-pcs/src/c71_matrix/b12/streaming.rs)
confrontano codec/sali/foglie/root con la MMCS nativa: multi-chunk BLAKE3,
seek da offset effettivi, rigetti forzati del sampler, più root consecutive
e coset strided `c+Q*j`. Il prescan e le frontier ricostruiscono la root
originale; i digest sovrascrivono solo le celle della riga consumata.
Questo chiude il confronto CPU delle primitive, non l'encoder WHIR completo,
un kernel CUDA, tutti i workspace o il lifecycle originale.

Il [preflight](preflight.md#getter-numerico-e-hash-nativo-ridotti) integra
subito hash/prescan/cursori nel ledger: lower parziale con lettura leaf
separata **47,497618 / 51,975184 / 56,751469 s**. Il piano nominato resta
quello da 6.166.012.672 B massimi; scratch nativo/GPU non verificato non
acquisisce credito. La 1.024 è chiusa; il combine non la riesamina.
Le [procedure](../procedures/build-and-test.md#getter-e-hash-c71-ridotti)
registrano filtri mirati e limiti. Nessuna GPU, spill o spesa.


Il [record immutabile del 2026-09-18](../../benchmarks/results/c71-native-streaming-2026-09-18-8ad3270ec1c9.json)
è generato su SHA pulita `8ad3270ec1c9`, `git_dirty:false`: **9 test Rust**
e **19 Python** passati, con filtri, stdout, limiti, hash del binario e
build mirata. Il report riusa soltanto i metadati pubblici del record
2026-09-13, identificati da file/digest, e ricalcola ledger 512 e arena.
I tempi CPU registrati riguardano i controlli locali; non sono rate H100
o `T_inference`/`T_proof_only`. Costruzione canonica, lavoro totale e picco
fisico sono esplicitamente incompleti, perciò il gate di spesa resta NO-GO.

## Replay WHIR e codec cGGM ridotti

Il [backend sourcewise](../../rust/volta-pcs/src/c71_matrix/b12/replay.rs)
confronta una catena D10/512 query completa con il prover e il verifier
nativi: root, round, aperture salted, multiproof e codec coincidono.
Il primo record usa HidingMmcs semplice (**2.277.848 B**); il controllo
aggiornato include il binding C7.1 di `ObservedMmcs` (**2.289.176 B**).
Anche FS, cursore dei coin, target affine e chiusura base-case coincidono.
I fallback evals/weights grandi sono rifiutati. Il test dei round copre
anche la contrazione a sette sfide; il replay dell'albero copre fork,
coin consecutive e query duplicate. L'ultimo coset riduce i digest in-place,
senza duplicare 32*L byte. Le query sono rigenerate per sottoalbero e
valutate in gruppo, condividendo la lettura del coefficiente originale.
Il censimento CPU per fase usa l'allocator esistente; non certifica
scratch CUDA, arena canonica o rate H100.

Il [codec PCG](../../rust/volta-pcg/src/c71_ea_lpn.rs) riproduce i vettori
Python H/EAGen e rifiuta esaurimento o forme errate. H preserva slot XOF
fissi di 64 B per componente. Il controllo esaustivo dei ruoli a profondità
1–7 usa offset, primo split indipendente e patch della foglia noti al fixture: non prova OT,
bridge Fp6 o composizione MAC. Le [procedure](../procedures/build-and-test.md#replay-whir-e-codec-cggm-ridotti)
conservano test piccoli e seriali. Nessun nuovo credito Lean o modifica
a transcript, NoPeek, endpoint o trust model.

Il [record corretto a SHA pulita 42f0814](../../benchmarks/results/c71-cggm-first-split-2026-09-26-42f08149164e.json)
conserva quattro test Rust passati entro 60 s/2 GiB, un thread/worker.
Acc/PuncAcc usa ora `(k, offset-k)` al primo livello, come Fig. 3 Dory,
non `k=H(offset)`. Ogni prefisso coincide con le foglie dense; il sender
esegue h−1 chiamate H. Il precedente test dimostrava l'identità additiva
del diverso albero hash-root, non il trasferimento delle coin del setup.
Il record precedente resta immutato. Nessun setup distribuito o credito PCG
composto viene attribuito alla correzione.

Il [record immutabile del 2026-09-19](../../benchmarks/results/c71-sourcewise-2026-09-19-5afc54ceaac5.json)
usa SHA pulita `5afc54ceaac5`, `git_dirty:false`: **16 test Rust e 19 Python**
passati. Il confronto della catena in quel record precede il binding
`ObservedMmcs`: non è evidenza di tale binding C7.1. Conserva build, hash
dei binari, comandi/limiti e stdout, incluso
il censimento per fase. Il picco durante l'apertura D10 comprende anche la
prova di riferimento trattenuta; la fase codec comprende la normalizzazione
JSON del solo test. Questi numeri non sono il picco GPU, né tempi completi
C7.1. I gate di costruzione canonica e spesa restano aperti.


## Getter originale, MAC nativo e Seed6 ridotti

Il test aggiornato usa `ObservedMmcs` e la fase FS C7.1, una maschera di
chiusura non nulla e il vero `verify_pcs`. Il MAC ideale dell'endpoint è
fissato prima delle sfide; una key alterata rifiuta. Il codec D10 misura
2.289.176 B per questo fixture. Il framing lineare esterno rimane un
fixture: non è un nuovo certificato Gemma completo.

Nei casi numerici O=0/2/4 il getter apre la root A del preparatore originale,
senza catturare Snapshot o A completa. Condivide S1 dopo il rilascio del
predecessore; la scansione di materializzazione conserva l'ordine originale
e non copia il corpo in una seconda allocazione. I contatori includono
finestre, righe producer, letture W/A/KV e operazioni sorgente dirette;
RMS/RNE/affine/divide restano chiamate da dettagliare. Il confronto dei
coefficienti include il getter congelato prima/dopo la conservazione.

Seed6 controlla codec K6, sei maschere, check prima di alpha e compressione
in Fp3. Il test reale a 384 OT riusa MR19 con domini separati: 127.515 B
comprensivi di framing e 768 moltiplicazioni scalari fisse/variabili per
ruolo. Il censimento conserva i tentativi effettivi dei sampler. I fixture
con valori/tag noti non sostituiscono COPE, guard, secondo seed con ruoli
opposti o il consumo MAC composto. Nessun credito H100, picco canonico o
composizione crittografica aggiuntiva.

Il [record su SHA pulita `44afc99cc23f`](../../benchmarks/results/c71-original-getter-seed6-2026-09-19-44afc99cc23f.json)
conserva **36 test Rust e 26 Python** passati, build mirate, digest dei binari,
comandi, limiti e censimento allocator/producer. Include separatamente i
fallimenti di sviluppo corretti: socketpair vietata dal sandbox, tipo MMCS
di riferimento e segno del fixture MAC. Non attribuisce quei tentativi alla
SHA pulita. I tempi includono il riferimento denso e la normalizzazione del
solo test; non sono `T_inference`, `T_proof_only` o `T_response_total`.
I conteggi delle query dipendono dalle coin originali dei fixture e sono
quelli di quel run; non sostituiscono il trace canonico O=0/150/300.


## Checkpoint RMS e coefficienti GKR limitati

Il [getter compatto RMS](../../rust/volta-pcs/src/c71_matrix/gemma/rms/caller.rs)
conserva P/Y originali e una S48 per riga, legato alla `Sources` originaria.
Confronta tutti i frame vivi/padded con il reader indipendente, censisce
capacità effettive e propagazione degli errori. Il census canonico di sola
geometria è 2.023.495.038 B di payload e 16.840 B di descrittori; i buffer
riusano lo slot range prima di RNE. Non è un picco allocator/GPU completo.

Il [motore coefficienti](../../rust/volta-pcs/src/c71_matrix/rms/gkr.rs)
confronta la schedule MSB a memoria limitata con i fold densi. Il selettore
è fattorizzato dopo la somma weighted del programma; Copy/Xor sono
specializzati senza cambiare il polinomio. Solo i supporti pubblici
controllano gli skip e le celle dummy non richiamano il reader.
Il [replay Booleano](../../rust/volta-pcs/src/c71_matrix/rms.rs) limitato
conserva due vettori, conta operazioni/capacità e coincide con ogni livello
del riferimento su circuiti reali weighted/unweighted. Il confronto dei
coefficienti usa anche questo replay, senza tracce dense nella candidata.

Il [report pubblico](../../scripts/c71_gkr_screen.py) confronta i circuiti
Python/Rust e tutti i 29×5 supporti RMS nel fixture a scale zero, oltre ai
ratio EXP30 O=0/150/300. Il controllo esaustivo ridotto comprende
assegnazioni intercalate e padding. I conteggi sorgente e SASS dei probe
CUDA restano distinti: non sono tempi del kernel fuso o del prover completo.
Nessun nuovo teorema Lean, credito al profilo calibrato o autorizzazione GPU.

Il [record immutabile su SHA pulita `3e7f24eb332b`](../../benchmarks/results/c71-bounded-rms-gkr-2026-09-19-3e7f24eb332b.json)
conserva **9 test Rust e 17 Python** passati, build Rust/CUDA seriali,
SASS dei tre gate, contatori per O=0/150/300 e arena plan. Tutti i 29×5
supporti RMS coincidono fra Rust e Python. Include separatamente gli
errori di directory/PATH dei tentativi di sviluppo; `git_dirty:false`
riguarda il run registrato. Nessuna esecuzione GPU o misura temporale
completa; restano aperti proof sourcewise, kernel fuso e picco fisico.


## Seed6 reale OT-AES streaming

L'[adapter ridotto](../../rust/volta-pcg/src/c71_seed6/real.rs) esegue due
ruoli separati, n=1/n=3, handshake direction-bound e MR19 384 con COPE AES;
confronta tutti i MAC restituiti. I test contano frame e operazioni e
rifiutano correzioni non canoniche, check alterato e troncamento prima di
alpha. Le capacità dei Vec e i rilasci sono osservati; non comprendono
allocator, stack crittografico o trasporto. I
[vettori indipendenti](../../scripts/c71_seed6_aes_kat.py) usano OpenSSL AES
e hashlib SHAKE. Il ledger include ora le 2.025 righe F_EQ aggiuntive nel
seed principale; i precedenti record con 15.528 righe restano immutabili e
non sono un censimento completo del setup F_EQ.

È un controllo componente test-only: non esegue seal/burn, guard prima di
c, costruttore cGGM separato per ruolo o la F_EQ composta. Il picco fisico,
il tempo congiunto e i gate pre-spesa restano aperti.

Il [record su SHA pulita `d80b0490333d`](../../benchmarks/results/c71-real-seed6-2026-09-19-d80b0490333d.json)
conserva **13 test Rust e 18 Python** passati, KAT indipendenti, ledger e
arena O=0/150/300. Le capacità native di ogni fase coincidono con il modello
Python nei due casi ridotti. Include separatamente l'errore di compilazione
sulla cancellazione delle slice K6, corretto prima del run pulito.


## Guard sui MAC Seed6 originali

Il nuovo consumer riusa il batch prodotti del range, con wrapper FS
invariato. Il fixture reale da nove righe conserva il segno dei tag/key
originali e usa Delta nativo negato. I fixture negativi coprono il cammino
malevolo beta=0, gamma non binario, mutazione delle correzioni/proof e codec.
La sfida del verifier viene fissata prima della prova; il fixture non
implementa FS globale, seal/burn o il trasporto del guard. I tre mask row
sono cancellati mentre split/F_EQ restano disponibili al consumer futuro.
Il [preflight](preflight.md#guard-originale-consumer-nativo) riporta lavoro,
memoria nominata e confine formale senza attribuire credito al bootstrap.

Il [record su SHA pulita `40b1972c8efc`](../../benchmarks/results/c71-seed6-guard-2026-09-19-40b1972c8efc.json)
conserva **17 test Rust e 17 Python** passati, i tre casi Seed6 n=1/3/9,
capacità nominate, ledger e arena. Include le regressioni range e la prova
composta ridotta dopo l'estrazione dell'algebra condivisa. L'ABI CPU osserva
Frozen=72 B, ProverGuard=528 B, VerifierChallenged=552 B e Hasher=1.920 B;
queste dimensioni non sono un upper di stack o allocator.


## WHIR: capacità conservata e FFT odd-log

Il riferimento [sourcewise](../../rust/volta-pcs/src/c71_matrix/b12/sourcewise.rs)
usa una sola allocazione S1 per tutte le generazioni. Le lease degli oracoli
impongono commit-successore, query/rilascio-predecessore, quindi fold. Il
[backend replay](../../rust/volta-pcs/src/c71_matrix/b12/replay.rs) distrugge
il tree prima di rilasciare la lease e registra quest’ultima solo dopo un
commit riuscito. La sorgente iniziale viene trasferita solo dopo validazione;
il fallback A è rimosso dopo la materializzazione S1.

Il test `c71_b12_retained_lifecycle` verifica rifiuto di prefissi e lease
invalidi, promozione anticipata/duplicata, getter obsoleti, uguaglianza dei
valori S2 prima/dopo fold, capacità preservata e rilascio del capture sorgente.
I confronti completi ridotti O=0/2/4 conservano root, byte del proof, FS e
MAC originali. Il controllo adaptive e quello della catena D10 restano
regressioni; la catena canonica accelerata non è eseguita.

Il [microbench FFT](../../cuda/c71_fft_microbench.cu) aggiunge i log dispari
con input `[pari][dispari]`, due trasformate quadrate e un merge in-place.
I controlli `--host-check-odd 1` fino a `4` confrontano con DFT indipendente.
Il device è compilato per sm_90; questo non esegue CUDA e non misura rate.
La tabella n*8 comprende entrambi i gruppi di twiddle. Gli accessi logici
al merge sono espliciti nel [trace](../../scripts/c71_whir_trace.py), distinti
dallo scatter PCS ancora da collegare e dal traffico fisico HBM.

Il [piano arena](../../scripts/c71_arena_plan.py) conserva tutta la capacità
S1 fino alla fine e respinge il vecchio cap S3 2^24. Con cap successori
2^23, i controlli degli span conservano il margine nominato; non certificano
allocator, fence GPU, picco completo o fattibilità temporale.


Il [record su SHA pulita `bfb274a1fcf2`](../../benchmarks/results/c71-retained-capacity-2026-09-19-bfb274a1fcf2.json)
conserva **6 test Rust, 25 Python**, quattro DFT odd-log e il runner host
FFT precedente. La compilazione CUDA 12.9.86/sm_90 ha zero stack/spill,
max 48 registri e 16.896 B shared statici; la FFT righe usa shared dinamico
fino a 32 KiB per le geometrie selezionate. Include comandi, hash del binario,
stdout, trace completo della retention e piano degli indirizzi O=0/150/300.
`credit:false`, nessuna GPU eseguita; picco e lower temporale completi non acquisiti.

### Sourcewise GKR, byte endpoint and two-key Seed6 equality

Il [record su SHA pulita `98b109ba81ab`](../../benchmarks/results/c71-source-proof-2026-09-19-98b109ba81ab.json)
contiene **13 test Rust e 21 Python**, seriali entro 60 s/2 GiB per processo,
senza GPU. I confronti GKR RMS/EXP30, N=1 e il confine u16/N=128 preservano
byte della prova, transcript, punto e Auth originali rispetto al riferimento
denso; i consumer chiudono l'endpoint nella stessa PCS. Il caller RMS usa
`CompactFrames`, il binding degli assegnamenti è streaming e il verifier
mantiene solo P selettori. La LUT dell'endpoint byte sostituisce gli alberi
per cella; il test copre padding, estremi byte, coefficienti Fp3 non base,
funzioni false e sorgenti alterate. I contatori nativi della rigenerazione
sono confrontati con le formule Python, inclusa la scansione terminale.

Il record comprende anche F_EQ con due seed AES/OT a ruoli opposti e i
rifiuti di framing/commitment/apertura. Questo è un consumer locale:
F_Rand globale, riserva disgiunta delle code, cGGM/guard, trasporto e burn
non sono composti. Il report mantiene le capacità native e il ledger arena
con LUT/coefficienti coesistenti con il checkpoint originale. La coda libera
minima nominata resta 276.438.272 B, di cui 268.435.456 B di margine richiesto;
non è il picco fisico completo.

I conteggi scalari canonici sono parziali e usano profili sintetici pubblici.
Non sono un tempo misurato, un lower H100 o credito al profilo calibrato.
Restano lavoro index/MAC/FS/getter, capacità di programmi/prove/correlazioni,
allocator/fence, kernel fusi e costruzione canonica/AES completa.
Le correzioni emerse in sviluppo e review sono conservate nel record.

### Incremental prefix weights and Boolean source folds

Il [record su SHA pulita `e1f3a00f4eb4`](../../benchmarks/results/c71-fold-sharing-2026-09-19-e1f3a00f4eb4.json)
conserva **12 test Rust e 14 Python**, senza GPU. I pesi prefix incrementali
sono confrontati con il riferimento indipendente, incluse sfide 0/1;
il getter riunisce i quattro figli della stessa sorgente. Le righe Boolean
usano maschere canoniche Fp3, con confronto al fold generico e al prover
denso. Passano anche N=1, endpoint byte, RMS/EXP30, confine u16 e composizione
ridotta. I contatori byte nativi coincidono con il ledger Python.
Il ledger della risposta include ora entrambi i producer RMS ed EXP30
per O=0/150/300 e separa maschere, campo e getter. Il record conserva
le voci mancanti: non è un lower temporale completo né il picco fisico.

### Disjoint Seed6 reservation and reusable byte scratch

Il [record su SHA pulita `72f7f8d70d1f`](../../benchmarks/results/c71-tail-reservation-2026-09-19-72f7f8d70d1f.json)
conserva **7 test Rust e 19 Python**. La riserva consuma il seed, copia
soltanto la coda e cancella gli slot prima di troncare il prefisso, mantenendo
la sua capacità. Il caso reale collega i prefissi da nove righe al guard e
le code da tre a F_EQ; seed non separati e forme errate sono respinti.
I contatori Rust coincidono con il ledger Python. Restano aperti cGGM,
F_Rand globale e burn; il fixture non è un bootstrap composto.
Il buffer dei pesi byte è riusato senza riallocazioni; passano confronto
scalare, endpoint byte e prova nativa composta ridotta. Il record conserva
il fallimento iniziale di build corretto prima del run pulito.
Il piano mantiene le capacità extra delle code e il margine nominato,
senza credito al picco fisico completo o all'esecuzione H100.

### EXP30 maximum checkpoint and reused Boolean replay

Il [record su SHA pulita `add6c214c06d`](../../benchmarks/results/c71-maximum-checkpoint-2026-09-19-add6c214c06d.json)
conserva **9 test Rust e 17 Python**. Il massimo a un solo checkpoint è
confrontato con l'albero denso su tutti i figli, inclusi padding e foglia -1,
e conserva proof, punto, Auth, triple, prodotti, consumo MAC e FS. Passano
softmax completo ridotto, GKR RMS/ratio, N=1 e composizione nativa ridotta.
I contatori del sumcheck coincidono con il trace Python. Input/current/next
Boolean mantengono puntatori e capacità dopo la riserva iniziale e vengono
liberati prima della LUT byte. Il piano trattiene i cut originali anche
attraverso lookup/ratio. Il record include gli errori di build e liveness
corretti prima del run pulito, senza GPU o credito al picco completo.
Il lookup denso rimane un blocco distinto, ancora da sostituire.

### Original lookup caches and GKR capacity census

Il [record su SHA pulita `e39324ba5e18`](../../benchmarks/results/c71-original-lookup-2026-09-19-e39324ba5e18.json)
conserva **12 test Rust e 20 Python**. Cache query/istogrammi e cut a 16
foglie conservano wire, MAC, consumo righe e FS del lookup denso, anche con
output i32 fuori i16, blocchi interleaved, padding e sfide Eq 0/1/non-base.
Passano le regressioni GELU, softcap, massimo/ratio EXP30, RMS, N=1 e
composizione ridotta. Tutti i 28 dump dei contatori lookup corrispondono
al ledger Python; il dominio EXP30 include anche il padding causale.
Il census GKR distingue backing delle righe, programmi, prove, triple,
transizioni Eq e LUT byte. Il record conserva esplicitamente le omissioni
individuate: Eq root/leaf byte, riallocazioni del binding, temporanei FS e
allocator/caller. Non attribuisce un upper fisico o temporale completo.
Nessuna GPU; gli errori di compilazione corretti prima del run sono registrati.

### Owned capacities, Eq temporaries and transcript buffers

Il [record su SHA pulita `9ca0882c31e5`](../../benchmarks/results/c71-owned-capacity-2026-09-19-9ca0882c31e5.json)
conserva **12 test Rust e 21 Python**. I 22 dump lookup confrontano anche
righe, prove, triple, punti, scratch e letture cache con il ledger; le
capacità prenotate coincidono con i payload richiesti nei casi ridotti.
Eq root/leaf byte include il transitorio vecchio+nuovo e distingue Lanes
da Sum. I record FS streaming coincidono col frame contiguo, compreso il
caso vuoto; passano KAT indipendente e composizione ridotta. I buffer proof
lookup restano riservati attraverso tutte le catene del piano.
Il test ha respinto la prima ipotesi ABI di CompactBlock=40 B; la dimensione
osservata di 32 B è stata usata prima del run pulito. Restano esclusi
allocator, stack del compilatore, caller e picco fisico/tempo completi.

### Integrated positive and scalar main-cell NO-GO

Il [record su SHA pulita `522476437dee`](../../benchmarks/results/c71-integrated-critical-path-2026-09-19-522476437dee.json)
conserva **5 test Rust e 14 Python**, controlli numerici host, compilazione
CUDA statica `sm_90` e certificato dei cammini del kernel main-cell fuso.
La proof positiva O=0 ridotta collega getter ordinato, lookup streaming,
GKR sourcewise, range e WHIR attraverso runner/verifier originali: consuma
88.049 righe MAC ideali e produce 7.747.977 byte senza materializzare
Snapshot o A completi sul percorso selezionato. I confronti separati
coprono byte numerici, wire, punti, endpoint MAC e FS; passa anche la
regressione nativa densa. Il ledger attribuisce la ricostruzione una sola
volta e separa l'aritmetica dei consumer. Non chiude PCG reale composto,
storia O=150/300, traffico HBM o picco fisico canonico.

Il kernel `c71_gkr_main_cell_fused` conserva 130 registri, 24.576 B shared,
zero stack e zero spill nella compilazione censita. Il record contiene
SASS della funzione, hash, log e la modifica locale dichiarata delle
quattro dichiarazioni sinpi/cospi nell'header del toolkit. Nessuna GPU
è stata eseguita. Il checker pinna il binario e verifica un minimo di
24 risultati INT-multiply per prodotto Fp3 del mapping nominato.
Sotto le [condizioni hardware esplicite](preflight.md#no-go-del-main-cell-scalare-fuso),
i soli coefficienti EXP30 danno lower **13,496178 / 40,300154 / 67,103981 s**
per O=0/150/300. Il terzo caso esclude questo backend dal totale ≤65 s
anche omettendo tutti gli altri costi: NO-GO circoscritto, non impossibilità
universale della variante 512 replay. Il tempo CPU ridotto non vale come
misura H100. Restano distinti inferenza, prova e totale end-to-end.

Sono preservati come fallimenti preliminari, esterni al run di record,
il padding A oltre il dominio del layout e il validatore host con chiavi
obsolete, entrambi corretti prima del run pulito. Nessun credito hardware,
nuovo censimento ABI, pod o spesa.

### Two structural EXP30 alternatives

Il [record su SHA pulita `331a4a1d084f`](../../benchmarks/results/c71-exp30-alternatives-2026-09-19-331a4a1d084f.json)
conserva **3 test Python** e lo
[screen di due sole alternative](preflight.md#due-alternative-strutturali-exp30).
Il predicato intero a residuo coincide con RNE sul reticolo ridotto e
sui tie; il controesempio mostra che istogramma E e somma Pi non bastano
al legame posizionale. Questa alternativa richiederebbe un nuovo transcript.

L'aggregazione privata a pattern ricostruisce gli stessi cubici originali
per prefissi da 2/3/4 bit, con sotto-tabelle, AND/XOR/Copy, padding,
molteplici suffissi e sfide 0/1/non-base. Il campo del controllo è
F97[u]/(u³−2); non è un test del prover Rust completo. Il ledger deriva
la geometria canonica e i gate dal record nativo precedente: per B=16
i bin richiedono 3.548.160 B di payload e il lower condizionale della
coda scalare è 0,852443 / 2,536417 / 4,220242 s. I costi dei bin sono
separati: il lower della coda non viene presentato come tempo EXP30.
Restano producer packed, parità FS/MAC nativa, workspace e tempo congiunti.
Le fonti locali sono identificate da hash; nessun file storico è modificato,
nessun credito hardware o nuova assunzione crittografica è attribuito.

### Native EXP30 late gate weights

Il [record su SHA pulita `9183368ec904`](../../benchmarks/results/c71-exp30-late-weights-2026-09-19-9183368ec904.json)
conserva **4 test Rust, 8 Python e 3 controlli arena Python/C++**.
La prova del piccolo circuito a 32 celle confronta l'intero wire GKR,
FS, punto, consumo MAC ed endpoint originale dopo quattro round a pattern
con i prover sourcewise e denso. I casi alterati sono respinti e la
continuazione range/PCS passa. È un test del nuovo algoritmo con wiring
piccolo, non una misura del circuito EXP30 canonico a 32 celle.
Passano inoltre EXP30 numerico ridotto, la proof integrata senza A/Snapshot
densi e la composizione nativa a tre risposte. Il ledger include separati
contatori del prefisso, senza duplicare il lavoro numerico dei getter.

I conteggi canonici della [fattorizzazione](preflight.md#pesi-di-gate-applicati-dopo-listogramma)
usano i gate del record nativo precedente. A O=300 i prodotti dei pesi
passano da 642.858.403.200 a 428.928.192, ma restano 3.154.116.420 prodotti
Eq posizione, valutazione dei cubici, 3.922.447.766.400 addizioni ai bin
e 9.098.344.541.952 gate Boolean packed. Il record conserva questi costi,
frame logici e liveness dei 441.372.672 B di payload. Il piano mantiene
il margine richiesto, senza credito al picco fisico completo o al tempo.

Restano immutati transcript, endpoint e modello MAC ideale dei test.
Nessuna GPU o spesa. Sono preservati il primo errore di build (`SubAssign`
non disponibile) e i due errori del fixture corretto: padding impegnato
non nullo e fault che violava il circuito prima di poter isolare la PCS.

### Native EXP30 wide accumulators and original cache

Il [record su SHA pulita `1fa2c20d03df`](../../benchmarks/results/c71-exp30-wide-cache-2026-09-19-1fa2c20d03df.json)
verifica sei filtri Rust ridotti, otto controlli Python e tre controlli
Python/C++ del piano arena. Tutti passano. Il positivo integrato usa
7.741.993 B e 88.049 MAC ideali, senza Snapshot/A completi; non è un
risultato canonico o AES-PCG. I tempi CPU sono solo quelli dei test.

Il nuovo accumulatore conserva limb u64 e riporti u32 e riduce una volta
per bin, prima del peso Fp3. Il test controlla carry e riduzione anche al
bound; la parità completa wire/FS/MAC dei quattro round rimane verificata.
La cache E/Pi/Z è confrontata con ogni byte originale e con il padding
causale a tre valori ridotti di O. Il ledger separa il fill, già addebitato
al getter, dalle successive letture interne; il positivo ridotto alloca
30 B di cache. Restano 428.928.192 prodotti dei pesi per risposta, senza
moltiplicazione per il numero di celle, e 1.286.784.576 riduzioni base.

A O=0/150/300 il payload cache canonico è
132.192.000 / 391.392.000 / 650.592.000 B. Il live allineato dell’evento
prefisso diventa 1.613.601.024 / 1.912.125.952 / 2.210.647.552 B;
la high-water nominata della catena EXP30 resta
2.082.995.968 / 3.370.001.152 / 3.851.690.752 B. Tutti i layout censiti
mantengono almeno 256 MiB di margine. Workspace e staging completi,
traffico HBM reale, refinement Lean e tempo totale restano aperti:
`credit:false`, nessuna ammissione H100 e nessuna spesa.

### Native EXP30 replay DAG

Il [record su SHA pulita `d4f8c98f2b96`](../../benchmarks/results/c71-exp30-replay-dag-2026-09-25-d4f8c98f2b96.json)
contiene cinque test Rust ridotti, otto controlli Python e tre controlli
Python/C++ arena, tutti passati. Ogni invocazione nativa ha limite
60 s/2 GiB, un thread e un worker Rayon. Nessuna esecuzione GPU.

Il nuovo test confronta il DAG con il replay originale a tutti i 95
livelli selezionabili del circuito EXP30, con live mask piena, parziale
e vuota. Per il prefisso GKR servono i primi 94 piani. La somma verificata
è 2.695.370 operazioni Boolean per gruppo packed sui livelli, contro il
replay originale comprensivo delle copie. Lo screen confronta i conteggi
originari con il precedente census nativo; non attribuisce costo nullo
alle gather o agli accessi ai valori. Piano e buffer stabili raggiungono
1.943.984 B nel riferimento CPU; lo staging GPU rimane da definire.

La parità dei quattro round mantiene wire, FS e MAC originali, inclusa
la continuazione range/PCS. Il positivo integrato O=0 accetta 7.737.865 B
con 88.049 MAC ideali e senza A/Snapshot completi; passa anche la
regressione a tre risposte. Non è un positivo canonico o AES-PCG.

Il piano inserisce il workspace del DAG insieme agli istogrammi e lo
rilascia prima dei cubici. Il live allineato di quell’evento è
1.615.545.088 / 1.914.070.016 / 2.212.591.616 B a O=0/150/300;
la high-water nominata EXP30 resta
2.082.995.968 / 3.370.001.152 / 3.851.690.752 B. Tutti i layout censiti
mantengono 256 MiB di margine. Il record include hash del binario e dei
sorgenti, log di compilazione, conteggi congiunti e formule canoniche.
È `credit:false`: il DAG riduce del 46,39% il lavoro word del replay,
non dimostra uno speedup GPU né un upper end-to-end entro 65 s.

### EXP30 BMMA component

Il [record pulito `9f730329e8f2`](../../benchmarks/results/c71-exp30-bmma-2026-09-26-9f730329e8f2.json)
contiene tre test Python/C++ passati, oggetto sm_90, SASS, log ptxas, hash
sorgenti/binario e i piani a O=0/150/300. Non esegue GPU. Verifica le somme
native unsigned a 96 bit prima della riduzione modulo p, le mappe dei
frammenti di entrambi i kernel, i cubici nel campo ridotto e le fence/offset
nel checker C++. I conteggi s32 sono protetti dal bound pubblico N<2^31.

Due kernel nativi BMMA, zero stack/spill: And/Xor usa 70 registri e load Eq
vettoriali; Copy usa 40 registri. Il loop Copy è srotolato dal compilatore:
i cinque siti BMMA statici non moltiplicano per cinque il numero dinamico
per tile. Il primo assert del record supponeva erroneamente un solo sito;
il fallimento è conservato e il controllo distingue presenza statica e
conteggio dinamico della schedule. Sono conservati anche un errore iniziale
d’import e il checker arena che esauriva gli ID perché il fixture non
riusava gli handle dopo le fence: corretto il fixture, senza alzare il cap.

Payload candidato massimo 490.859.484 B. Il live allineato della fase
BMMA è 1.442.513.408 / 1.741.038.336 / 2.039.559.936 B, mentre il massimo
nominato EXP30 resta 2.082.995.968 / 3.370.001.152 / 3.851.690.752 B.
Tutti i layout censiti mantengono il margine 256 MiB; non è il picco fisico
completo. Il record distingue lower condizionali, traffico logico e HBM,
e non converte il primo in un upper di tempo. Producer/packing, riduzione
Fp3, adapter nativo e service-rate restano da collegare. `credit:false`,
nessun nuovo protocollo, nessun positivo AES/GPU e nessuna spesa.

### EXP30 moment pipeline

Il [record pulito `8728a8e2bed0`](../../benchmarks/results/c71-exp30-moment-pipeline-2026-09-26-8728a8e2bed0.json)
verifica tre filtri Python/C++, parità nativa dei tile a cinque e un bit,
e la proof integrata ridotta lookup/GKR/WHIR con MAC originali. I momenti
nativi sono ancora un riferimento CPU: non consumano i buffer CUDA.
I sei kernel compilano sm_90 senza stack o spill; packing wire usa 512 B
shared per CTA. I controlli host confrontano trasposizione in-place,
frammenti, ricostruzione dei contatori e riduzione Goldilocks, inclusi
carry al limite e batch parziali. Nessuna GPU viene eseguita.

Il piano libera stage/Eq/replay prima dei momenti canonici, poi libera i
contatori dopo la fence di riduzione. Il payload massimo resta
490.859.484 B; il massimo nominato EXP30 resta invariato nei tre contesti.
Il traffico `Eq_stage_write_bytes` corregge il record BMMA precedente:
include tutti i 94 livelli, per 3.270.586.368 / 9.767.866.368 /
16.265.146.368 B. È traffico logico, non una misura HBM o un upper.

Il [timeout preliminare](../../benchmarks/results/c71-exp30-moment-timeout-2026-09-26-a19344f.json)
conserva il test arena interrotto a 60 s. Il census pubblico identico ora
è riusato tramite cache; ogni filtro del record passa entro il limite,
senza ampliarlo. Producer parallelo, indici originali, adapter/pesi GPU,
picco fisico e tempo completo restano aperti. `credit:false`.

### EXP30 shared producer

Il [record pulito `8bce6b5a90b0`](../../benchmarks/results/c71-exp30-shared-producer-2026-09-26-8bce6b5a90b0.json)
confronta tutti i 95 livelli nativi con la schedule parallela, tre maschere
live ciascuno, e ripete il confronto nel checker C++ sul fixture pubblico
rigenerabile. Include hash del fixture, codice e oggetto sm_90, cinque
test Python/C++ passati, ptxas e SASS dei dieci kernel. Non esegue GPU.
Il primo dump SASS fallì perché `nvdisasm` non era nel PATH: log conservato,
ambiente corretto, nessuna modifica al codice o al limite di risorse.

Il producer usa al massimo 39.792 B shared per CTA e 737.856 B di piano
pubblico per livello. Non conserva intermedi globali. Il checker verifica
che le scritture di uno stage non aliasino alcun suo operando prima della
barriera. Il kernel legge direttamente E/Pi/Z originali; la compattazione
pubblica è verificata nei tre contesti e Eq conserva gli indici originali.
Il check Fp3 confronta packing→conteggi→riduzione→pesi con somme dirette,
inclusi And, Xor, Copy, riporti, padding e sfide 0/1/non-base.

Il payload massimo nominato diventa 489.850.540 B. Il massimo nominato
EXP30 e il margine dei piani complessivi restano compatibili; ciò non
chiude il picco fisico. Il ledger include shared/logical/global reads,
barriere, ballot, tabelle Eq, trasferimenti del piano e pesi tardivi.
Il riferimento nativo di proof/FS/MAC resta il record precedente: questo
record non collega ancora l’aggregato CUDA al prover. `credit:false`,
nessun service-rate, upper temporale, positivo AES/GPU o autorizzazione di spesa.

### Original byte node contraction

Il [record su SHA pulita](../../benchmarks/results/c71-byte-node-contraction-2026-09-26-606ec16ba48a.json)
conserva tre test locali passati, il ledger candidato e il piano arena.
L'[oracolo](../../tests/test_c71_byte_tree_contraction.py) controlla la
diagonalizzazione anche singolare, la parità dei cubici dopo fold non
Booleani, la baseline del padding pubblico e il recupero dei figli
originali. Il checker C++ controlla il piano con due stati disgiunti a
O=0/150/300, cache e LUT originali ancora vive. Sono controlli algebrici
e di indirizzi richiesti: nessuna esecuzione della nuova tree nativa,
CUDA o misura hardware. [Conteggi e limiti](preflight.md#original-byte-node-contraction).

Il [record nativo su SHA pulita](../../benchmarks/results/c71-native-byte-node-contraction-2026-09-26-188ff70d1a78.json)
conserva il test passato, la build e i tentativi preliminari non validi.
Il successivo [oracolo nativo](../../rust/volta-pcs/src/c71_matrix/byte_function/contraction.rs)
confronta direttamente la LUT ByteTrees nel campo originale: 256 byte,
otto livelli, due lane, fold con sfide non Boolean/0/1 e recupero dei
figli da istogramma pesato. Il filtro `c71_byte_node_contraction` passa;
non chiama una proof con il nuovo backend. La base di Lagrange riusa
le valutazioni pubbliche esistenti invece di duplicare il costruttore
polinomiale della tree. Il backend di produzione resta invariato.

### Integrated contracted byte endpoint

Il [record su SHA pulita](../../benchmarks/results/c71-integrated-byte-contraction-2026-09-26-ed509fa1ed83.json)
conserva cinque filtri nativi passati, il controllo Python e il ledger
del singolo positivo integrato, senza doppio conteggio del getter.
Il motore [sourcewise](../../rust/volta-pcs/src/c71_matrix/range.rs) ora
ammette evaluator privati dei cubici e dei quattro figli finali mantenendo
comune autenticazione, transcript e MAC. Il [caller byte](../../rust/volta-pcs/src/c71_matrix/byte_function.rs)
limita il riferimento contratto ai domini completi ≤128 celle. I test
esistenti verificano wire/FS/MAC contro la proof densa, claim errati,
byte cambiati coerentemente ma scollegati dall'originale PCS, prefissi
pattern EXP30 e la proof integrata lookup/GKR/WHIR. Quest'ultima registra
76 round contratti e otto terminali, senza Snapshot/A densi. Il ledger
ridotto separa questi evaluator dai contatori del fallback scalare.
Non sono ancora getter canonico streaming, conteggi completi o misura GPU.

Il successivo getter ridotto rigenera per batch con LUT pubbliche prepesate,
conserva solo il supporto pubblico proiettato dopo il checkpoint e usa
fold con due allocazioni disgiunte. Baseline f(0), massa del padding e
coordinate Eq originali restano nella proof. I test esistenti byte e
pattern confrontano ancora wire/FS/MAC; il positivo lookup/GKR/WHIR passa
senza Snapshot/A densi. Il test byte rifiuta anche un dominio ragged prima
di leggere la sorgente o consumare righe/sfide. Il guard ≤128 resta:
nessun credito ai descrittori canonici, al picco completo o al tempo GPU.
Il [record su SHA pulita](../../benchmarks/results/c71-streamed-byte-contraction-2026-09-26-e95d8a51d6cd.json)
conserva cinque filtri nativi, il controllo del ledger e il positivo
integrato. La parità wire/FS/MAC è verificata nello stesso fixture a
monete fissate. Receipt e dimensione del certificato integrato possono
variare fra run: `fixture()` installa W con `Model::new_in`, che estrae seed
privati dal sistema. Non si richiede uguaglianza fra installazioni diverse.
Il [controllo scartato fra run](../../benchmarks/results/c71-integrated-cross-run-coins-2026-09-26-e95d8a51d6cd.json)
è conservato con provenienza dirty, senza credito di protocollo.

Il [record su SHA pulita](../../benchmarks/results/c71-canonical-byte-support-2026-09-26-9a4d6634de68.json)
verifica il raccordo degli intervalli causali da Softmax al getter,
con proiezione pubblica verificata per ogni round nei tre contesti.
La proof ridotta conserva 12 lane private e recupera analiticamente le
quattro lane byte zero; Eq terminale usa due tabelle fattorizzate.
Il controllo di arena include queste tabelle e non cambia il massimo.
Il guard ≤128 e i limiti di credito restano invariati.

Il [record su SHA pulita](../../benchmarks/results/c71-paired-byte-contraction-2026-09-26-42d6af589cdb.json)
conserva nel getter e nei fold sia f sia d·f e
applica Eq dell’asse corrente dopo la riduzione quadratica. Passano
parità byte/pattern e positivo integrato; il checker indirizzi/fence
conferma che il maggiore stato EXP30 non cambia il massimo globale.
Il kernel CUDA corrispondente compila senza spill e riusa la riduzione
esistente. Il lower congiunto esclude il backend a slot fissi a O=300;
non è una misura GPU né la chiusura del goal locale.
I [primi cinque prodotti per feature](../../benchmarks/results/c71-byte-contract-first-cuda-diagnostic-2026-09-26-281ac61.json)
e il [primo selettore per coppia](../../benchmarks/results/c71-byte-contract-paired-first-diagnostic-2026-09-26-281ac61.json)
sono conservati come diagnostici dirty delle implementazioni scartate.

Il [record carry su SHA pulita](../../benchmarks/results/c71-carry-field-joint-screen-2026-09-26-8662d88cbb8a.json)
conserva il confronto host modulo p per
valori al bordo e input deterministici. Passano anche il cubico contratto
e il checker CPU BMMA. I kernel range e i dieci kernel BMMA compilano
senza spill. Lo screen collega per digest il nuovo coefficiente, i due
merge range e la coda main: sostituisce il vecchio costo range e conserva
il bound IMAD applicabile alla coda. La somma parziale scende sotto 65 s,
senza nuove allocazioni; mancano ancora fasi, profilo RMS e misura GPU.

Il [controllo RMS su SHA pulita](../../benchmarks/results/c71-rms-workload-screen-2026-09-26-b70887bb6bda.json)
riusa i profili sintetici esistenti e il lower del main kernel ricertificato.
Include i selettori per coppia/profilo/livello: la coda dopo quattro round
concessi gratis costa almeno 70,268864 s. Esclude quel backend del fixture,
non altri Γ o prover non scalari; nessun nuovo run nativo o hardware.

### Native moment seam and byte tree screen

Il [record pulito `b63461fa58e8`](../../benchmarks/results/c71-byte-seam-and-tree-screen-2026-09-26-b63461fa58e8.json)
contiene la parità proof/FS/MAC del raccordo privato da 240 Fp3, anche con
momenti quadratici non nulli, il rifiuto di forma/codec, la proof integrata
ridotta positiva e tre controlli Python/C++. Il riferimento CPU produce
l’aggregato: non è esecuzione GPU. Il costo dei cubici e dei 541.440 B di
trasferimento per risposta è esplicito nel ledger.

Il SASS conservato verifica 774 risultati IMAD.WIDE.U32 register-register
non predicati per coppia nel coefficiente fattorizzato originale e 525
nella variante con sei prodotti base/Fp3. Quest’ultima usa 130 registri,
zero stack/spill e coincide con il cubico diretto nel test host. Il
controllo lega hash, guard, corpo senza salti e uscita. Conserva il primo
test fallito del parser su prefisso vuoto, poi corretto; binari diversi
sono respinti. La compilazione usa il toolkit temporaneo già dichiarato.

Sotto le condizioni hardware/schedule esplicite, il lower delle sole
fasi disgiunte byte-coefficienti e range/commit/prime aperture è
49,737497 / 70,116188 / 73,715684 s. Esclude il port letterale a O=150/300
anche concedendo gratis tutti gli altri lavori, compresa inferenza e BMMA.
Non esclude una fattorizzazione della tree né chiude il goal generale.
`credit:false`; niente H100, spesa, upper o picco fisico completo.

## Seed6 guard-to-cGGM and split equality

Il [record su SHA pulita `4382db54e0ef`](../../benchmarks/results/c71-guard-cggm-split-equality-2026-09-26-4382db54e0ef.json)
conserva **25 test Rust e 27 Python/C++** passati, comandi, hash, contatori,
ledger e rifiuti di sviluppo. Ogni processo è seriale entro 60 s/2 GiB;
solo socketpair Unix locali, senza rete esterna o GPU.

Il [raccordo locale](../../rust/volta-pcg/src/c71_seed6/cggm.rs) consuma il
guard prima di produrre c, costruisce il primo split indipendente e separa
le chiavi sender dai tag/cammini receiver. I check a h=1–7 confrontano ogni
prefisso con Acc/PuncAcc e i check split sui MAC originali, anche con beta
zero e due blocchi. Falliscono forme/codec/cammini errati, code non separate,
nonce zero, RNG indisponibile e sampler esaurito.

Il test reale usa seed principali/inversi da 12+3 righe: il positivo arriva
a F_EQ e c/z alterati vengono respinti. Gli stati privati restano pendenti;
non è ancora una sessione con F_Rand globale, seal/burn o output EA.
Il [ledger](../../scripts/c71_pcg_trace.py) corregge il vecchio conteggio H
spacciato per lower comune: due passaggi danno 707.786.100 sender e
707.761.800 receiver. Il piano arena conserva seed, frame e chiavi fino a
F_EQ e non cambia il massimo globale nominato. I callback deterministici
di quel record non danno credito crittografico composto, fisico o H100.

## Native split and equality coins

Il [record su SHA pulita `efd66bad212b`](../../benchmarks/results/c71-seed6-coins-2026-09-27-efd66bad212b.json)
conserva **27 test Rust e 28 Python/C++**, seriali entro 60 s/2 GiB per
processo, hash dei sorgenti/binario, stdout e ledger delle due coin.
Nessuna GPU o rete esterna; socketpair Unix per i soli seed locali.

La [coin nativa](../../rust/volta-pcg/src/c71_seed6/coins.rs) esegue
commit/risposta/apertura a ruoli separati, con fase/prefissi/cardinalità
legati al codec. Uno stream SHAKE e il sampler Fp3 esistente producono le U
senza array denso. Le foglie receiver vengono visitate nello stesso ordine
pubblico del sender; il controllo esaustivo h=1–7 include anche tale ordine.
Il nuovo raccordo reale 12+3 esegue entrambe le coin prima di F_EQ e rifiuta
c/z alterati. Per c alterato anche il sender lega il frame modificato:
entrambi usano le stesse coin, evitando un rigetto solo per prefissi diversi.

Il KAT indipendente Python/Rust verifica quattro Fp3 e i 173 B del dominio;
aperture alterate, fase errata, framing, RNG e consumo non monotono falliscono.
Il ledger distingue XOF locale da wire/HBM e non riconta i 146 B già inclusi
per coin. FS del guard, sealing, burn e trasporto globale rimangono aperti:
non è ancora una realizzazione completa della funzionalità F_Rand con abort,
né credito alla sicurezza composta, al picco fisico o all'H100.

## Seed6 completion seals

Il [record su SHA pulita `0ca1a93fceb1`](../../benchmarks/results/c71-seed6-seal-2026-09-27-0ca1a93fceb1.json)
conserva **29 test Rust e 28 Python/C++** passati, tutti rigorosamente
seriali entro 60 s/2 GiB per processo. Include regressione B12, SHA/hash,
wire e ledger dei due seed. Registra separatamente la sovrapposizione
accidentale di due comandi di sviluppo, esclusi dal run di record.

Il seal condiviso mantiene invariato il formato B12 e aggiunge il dominio
`C71S6S01` ai seed reali, dopo il check e prima degli output. Il binding
usato da guard, code F_EQ e coin include il seal. La handshake v02 respinge
v01 prima degli OT; codec, seal nullo, troncamento e RNG falliscono senza
output. Il positivo reale 12+3 attraversa entrambi i seal e conserva i
rifiuti c/z della catena cGGM/coin/F_EQ.

I 40 B per seed erano già nel budget analitico. Il ledger aggiunge la fase
nativa e gli oggetti/hash nominati, senza alzare il massimo arena globale.
Un identificatore fresco non è un journal non rollbackabile: burn durevole,
FS globale e capacità EA rimangono aperti. I record v01 sono conservati
e non vengono usati per attribuire credito al nuovo completamento.

## Guard challenge from the sealed prefix

Il [record su SHA pulita `ba2e5b962f39`](../../benchmarks/results/c71-seed6-guard-fs-2026-09-27-ba2e5b962f39.json)
conserva **30 test Rust e 28 Python/C++**, seriali entro 60 s/2 GiB per
processo, con stdout, hash, ledger e regressione del seal B12 originale.

Il percorso reale usa ora una sfida SHAKE256 derivata dal prefisso guard
immutabile, che include il binding sigillato e le correzioni ordinate.
I due ruoli la ricostruiscono prima della proof senza lambda fornita dal
caller. Il KAT Python/Rust verifica dominio da 72 B e slot da 192 B;
prefisso/proof alterati falliscono. La catena reale Seed6→guard→cGGM→coin→F_EQ
esegue questa derivazione; le coin prefissate restano nei test algebrici.
Il ledger include sampler e temporanei, senza variare il massimo arena.
Il codec locale non è il transcript globale né il burn senza retry:
nessun nuovo credito al teorema composto, al picco fisico o all'H100.

## Equality-owned pointwise expansion

Il [record su SHA pulita `228ed64332ea`](../../benchmarks/results/c71-seed6-expansion-2026-09-27-228ed64332ea.json)
conserva **32 test Rust e 29 Python/C++**, seriali entro 60 s/2 GiB per
processo. F_EQ trattiene gli stati pendenti fino al successo; la catena
reale da 14+3 seed produce tre MAC base e un packing Fp3 nonzero. I test
coprono anche distruzione su rifiuto, cursore monotono e sampler fail-stop.
Il record conserva due errori di costanti attese nel test del ledger,
corrette usando le lunghezze effettive dei domini, non cambiando il codec.

**Limite trovato in review dopo il run:** il riferimento accumula soltanto
l'albero selezionato, omettendo tutti i blocchi precedenti richiesti dalla
matrice globale A di Dory, Fig. 5. Il fixture reale t=1 non può rilevarlo;
neppure la sola identità MAC multiblocco certificherebbe la distribuzione EA.
Questa versione è quindi NO-GO per t>1. Il record rimane valido come
controllo t=1/ownership, non come EA canonico. Occorrono prefissi globali
e confronto diretto con BAe prima di riusare l'espansione multiblocco.

## Global EA accumulator correction

Il [record su SHA pulita `65623518459b`](../../benchmarks/results/c71-seed6-global-ea-2026-09-27-65623518459b.json)
conserva **32 test Rust e 29 Python/C++**, seriali entro 60 s/2 GiB.
Include il fallimento riprodotto prima del fix: alla seconda riga del
fixture t=2, la precedente espansione restituisce 646327468089327808
invece di 11555904951444293626. Il test usa BAe globale come oracolo,
non la sola uguaglianza MAC; il vecchio record t=1 resta immutato.

Il fix accumula beta/K(beta)/M(beta) fra alberi. La catena reale usa
25+6 righe seed, h=4,t=2,ell=2: sei righe base coincidono con BAe,
mantengono la stessa Delta e formano due MAC Fp3 nonzero. c/z alterati
non rilasciano stato. Ledger e arena contano 21.600 B aggiunti durante
la conversione receiver e 351.000 B heap trattenuti, con rilasci solo
dopo accettazione; i massimi globali nominati non cambiano.
Questo risolve il difetto multiblocco del riferimento, non accordo sul
seed EA, trie batch, trasporto, journal, proof bridge o picco fisico.

## Native two-role equality transport

Il [record su SHA pulita `4f54c8fe12da`](../../benchmarks/results/c71-seed6-equality-wire-2026-09-27-4f54c8fe12da.json)
conserva **33 test Rust e 29 Python/C++**, seriali entro 60 s/2 GiB.
F_EQ ora scambia nove frame fra due endpoint Unix indipendenti usando
`send/recv` del bootstrap, anziché trasferimenti diretti fra stati locali.
I due Audit coincidono: 433 B a t=1, 481 B a t=2; il totale analitico a
t=675 è 32.785 B con la coin. Tag, lunghezze errate e troncamenti sono
respinti prima di allocazioni dipendenti dal peer o uso di RNG.

La catena AES reale mantiene sei righe EA globali, due packing Fp3 e rifiuto
di c/z alterati. Il ledger include 192 B Audit, fino a 96 B read buffer e
27 B aggiuntivi sul bootstrap, ora 61.841.321 B. Le altre fasi non diventano
automaticamente trasporto globale: restano canale autenticato, journal,
accordo sul seed EA, trie batch e integrazione con la proof. Nessun credito
di fairness/atomicità, picco fisico completo o H100.

## EA seed from accepted committed openings

Il [record su SHA pulita `be0f1cab5f03`](../../benchmarks/results/c71-seed6-ea-seed-2026-09-27-be0f1cab5f03.json)
conserva **34 test Rust e 30 Python/C++**, seriali entro 60 s/2 GiB.
Il seed pubblico EA ora deriva con SHAKE dal prefisso F_EQ e dalle due
aperture verificate, in ordine di ruolo. Riusa i blind freschi già
committati, senza parametro seed nel costruttore di espansione né nuovo
messaggio. Il KAT Python/Rust copre 184 B assorbiti e 32 B prodotti;
prefisso, ordine e blind alterati cambiano il seed. La catena reale mantiene
sei righe conformi a BAe, due MAC Fp3 e rifiuto c/z.

Il record conserva l'errore iniziale di compilazione per `read` ambiguo,
risolto selezionando esplicitamente `XofReader::read`. Il ledger separa
l'envelope ROM condizionale aggiuntivo, senza trasferire automaticamente
bound composti o credito Lean. Restano blind freschi e no-retry globali,
setup/trasporto completo, journal, trie batch, proof bridge e picco fisico.

## One-channel Seed6 setup

Il [record su SHA pulita `6dbf6fbf38c5`](../../benchmarks/results/c71-seed6-one-channel-2026-09-27-6dbf6fbf38c5.json)
conserva **37 test Rust e 31 Python/C++**, seriali entro 60 s/2 GiB.
Il nuovo driver attraversa su un unico canale entrambi i Seed6 MR19/AES,
guard, cGGM/coin/split e F_EQ fino allo stato EA. A t=2,h=4,ell=2 usa
25+6 righe seed e produce sei MAC originali; beta viene dal seed e i
cammini sono campionati, non forniti dal fixture. La geometria errata
è respinta prima di I/O/RNG; una ell diversa fra peer viene respinta
prima degli OT. Il nonce deriva dai due binding sigillati.

Gli Audit speculari danno 390.742 B totali. Il ledger canonico include
quattro header prima esclusi e l'adeguamento della coin split: +45 B,
totale primitive 61.841.366 B. Sono contati i buffer temporanei e i tre
Audit restituiti (896 B heap, 672 B valori); il massimo arena nominato
non aumenta. Il percorso byte è completo per questo setup ridotto, non
per il run di inferenza: restano canale autenticato, journal non-rollback,
trie batch, proof bridge, composizione crittografica e picco fisico.

## One-use Seed6 setup journal

Il [record su SHA pulita `8b11a44`](../../benchmarks/results/c71-seed6-journal-2026-09-27-8b11a44aacf7.json)
conserva **46 test Rust e 31 Python/C++**, seriali entro 60 s/2 GiB.
Riusa il journal B12 con record 5 test-only e dominio Seed6: burn fsync
prima di RNG, owner esclusivo durante la vita dello stato EA, rifiuto di
retry/rinnovo/reopen. Il caso RNG fallito lascia il record bruciato;
il setup reale produce sei MAC originali. Passano anche tutte le otto
regressioni del lifetime B12, il cui dominio e record 4 non cambiano.

È conservato il primo fallimento di test: l'assert prevedeva `Other`,
mentre il helper RNG preesistente restituisce `InvalidData`. Il fix
controlla tipo e messaggio senza cambiare la semantica di errore.
Il ledger include 161 B su disco per ruolo, tre sync con installazione,
un lock OS, un BLAKE3 da 201 B e 104 B heap temporanei, senza nuovo wire.
Non-rollback e canale autenticato restano premesse del caller; riserve
per tentativo, NoPeek/promozione, proof, picco completo e H100 sono aperti.

## Bounded Seed6 attempt windows

Il [record su SHA pulita `ec9c242`](../../benchmarks/results/c71-seed6-attempts-2026-09-27-ec9c242d486b.json) conserva
**48 test Rust e 31 Python/C++**, eseguiti rigorosamente in seriale entro
60 s/2 GiB; passa anche il check Rust non-test della libreria condivisa.
Le finestre riusano le transizioni lifetime B12: burn prima delle righe,
iteratore limitato senza Vec della riserva, digest promosso dopo fsync,
stop su errori/panic, consumo incompleto, digest assente/invalido e terzo
tentativo. Sono verificati tre intervalli ideali disgiunti e due reali
Seed6 da tre righe. Le accettazioni sono fixture, non prove PCS/GKR.

Il record preserva l'errore iniziale di compilazione della firma di un
callback di test, corretto con il tipo fn esplicito. Dichiara anche che
i primi check mirati Rust/Python si sono sovrapposti brevemente: non sono
misure o run di riferimento; quelli registrati sono seriali su SHA pulita.
Owner/Audit ora restano nel piano delle tre risposte: +5.120 B allineati,
coda minima nominata 276.291.840 B. Le finestre aggiungono due record
da 57 B e due fsync per accettazione, non wire o heap della riserva.
Restano NoPeek/accettazione completa del wrapper, trie batch, composizione,
picco fisico e Γ reale; nessuna readiness H100.

## Seed6 bounded union-trie batches

Il [record su SHA pulita `c030524`](../../benchmarks/results/c71-seed6-batch-2026-09-27-c030524ce30f.json) conserva
**51 test Rust e 32 Python/C++**, seriali entro 60 s/2 GiB; passa anche
il check non-test del crate. Le finestre bruciate ora alimentano batch
da al massimo 4.096 righe con termini ordinati e trie depth-first comune
ai due ruoli. Il confronto esaustivo h=1..6 copre tutti i prefissi,
puncture e duplicati; quello reale mantiene BAe globale, MAC/Fp3 e rifiuto
c/z. Sei righe richiedono 41/36 SHAKE invece delle 60 sender puntuali.

Il test canonico limitato verifica 45.056 termini pubblici (1.081.344 B),
non un setup canonico. Il test 4.096+5/3 verifica che il prefetch non
oltrepassi la riserva. I picchi heap nominati 1.179.746/1.212.514 B e lo
slot ricorsivo da 64 KiB restano nell'envelope più ampio già prenotato,
senza ridurre il piano o dichiarare stack/alias fisici verificati.
Sono corretti i conti di somme PuncAcc e sottrazioni dei prefissi sender.
Confronti di sort/partizione sono contati a sorgente, non convertiti in
tempo canonico. Restano proof/NoPeek, composizione, CUDA, picco fisico
e Γ reale; nessuna esecuzione o spesa H100.

## Seed6 opt-in external role pools

Il [record su SHA pulita `034e053`](../../benchmarks/results/c71-seed6-public-2026-09-27-034e053eb875.json) conserva
**58 test Rust e 32 Python/C++**, seriali entro 60 s/2 GiB, e il check
non-test della nuova feature `c71-seed6-reference`. Un crate esterno
usa OS RNG e i pool opachi monouso: setup reale 25+6, burn, packing/transfer
Fp3 originale e stop/reopen reject. La ricevuta è un fixture, non prova
di inferenza. Il pubblico non può scegliere seed/Delta o estrarre stato EA.

L'algebra pura è spostata byte per byte in PCG e ri-esportata da MAC,
senza ciclo di dipendenze o formule duplicate. Passano le sei regressioni
MAC, inclusi i controesempi B4/B5 che restano fallimenti delle costruzioni
storiche. I costi wire/heap non cambiano. Il record conserva due errori
iniziali di compilazione (cfg della suite e assert Debug nel test), entrambi
corretti, e i warning di codice diagnostico non usato nella build reference.
Non sono nuovi teoremi, credito GPU o produzione: il bridge PCS/GKR,
Γ reale e picco completo restano aperti.

## Native exact-size correlation streams

Il [record su SHA pulita `958d982`](../../benchmarks/results/c71-seed6-iterator-2026-09-27-958d982f8e97.json) conserva
**otto test Rust e uno Python**, seriali entro 60 s/2 GiB. I consumer
PCS/GKR condivisi accettano `ExactSizeIterator`; il positivo O=0 passa
un `Take` preso in prestito senza raccogliere una seconda riserva Vec.
Consuma ancora 88.049 MAC ideali; il verifier originale ricostruisce
la stessa ricevuta. Passano tre tentativi densi, equivalenza sourcewise
range/linear e rifiuti per framing, contesto, interruzione ed esaurimento.

Il record conserva il primo errore di compilazione: un generico `Iterator`
solo al livello superiore non soddisfaceva né i consumer concreti né i
controlli `len`. La correzione usa il trait standard lungo il call graph,
senza rimuovere controlli o cambiare transcript, algebra o riserva.
Nessun nuovo conteggio canonico, riduzione del picco o credito AES composto;
packing Seed6 e wrapper restano il prossimo raccordo locale.

## Seed6 complete reduced native proof

Il [record su SHA pulita `1e5294a`](../../benchmarks/results/c71-seed6-native-2026-09-27-1e5294ae1004.json) conserva
**otto test Rust e 35 Python/C++**, seriali entro 60 s/2 GiB, e check
non-test del percorso B12 ordinario. La feature PCS opt-in collega pool
Seed6 e packing lazy alla macchina originale Prepare/Verify/journal:
un O=0 completo usa OS RNG, main 107 + inverso 12, t=4/h=19/ell=11 e
264.147 righe base, formando 88.049 MAC Fp3 originali. La stessa ricevuta
del verifier completo compare in entrambi i journal e registri A/KV.

Un secondo run indipendente altera l'ultimo byte del completamento:
burn completo, head zero, nessuna promozione e stop in entrambi i ruoli.
Positivo e rifiuto tardivo durano circa 50,11/50,10 s sulla CPU locale,
non sono tempi H100. I controlli piccoli coprono packing, errore di pull,
consumo parziale, shortage prima di Prepare/decoding; passano anche i
controlli del pool denso e i tre tentativi ideali. Il ledger include
operazioni/codec del packing e i relativi target parziali di throughput.

Il grafo è ancora un layer/hidden2/prompt1+generato1 con Snapshot/A densi.
Non è reader ordinato reale, run AES a tre tentativi, Gemma canonico o
nuovo teorema compositivo; Γ reale e picco completo restano aperti.
I journal precedono le rispettive promozioni, non un commit distribuito
atomico. Il record conserva anche i controlli preliminari su tree sporco
e dichiara l'overlap finale Python/compilazione preliminare; nessuna coppia
di suite di test viene eseguita in parallelo nel run di record.

## Ordered source with real Seed6

Il [record su SHA pulita `e9eab9c`](../../benchmarks/results/c71-ordered-seed6-2026-09-27-e9eab9c60538.json) conserva
**dieci test Rust e uno Python**, seriali entro 60 s/2 GiB, e check
non-test sia B12 ordinario sia reference Seed6. Lo stesso proprietario
Prepare/pending/Verify/promozione ora gestisce Snapshot e reader ordinato;
W/profili sono condivisi immutabilmente, le coin PCS vengono da OS RNG
dopo la preparazione numerica. Il positivo ideale ordinato non usa più
un percorso speciale del test; O>0 non implementato termina senza
sostituire il predecessore già accettato. Il nuovo Prepare coincide
byte per byte con la sorgente densa originale.

Il positivo congiunto ordinato/Seed6 accetta una proof completa O=0
con 88.049 MAC Fp3 e la stessa ricevuta nei due journal, senza Snapshot/A
densi. Usa **t=4/h=19/ell=2**, esplicitamente ridotto per il controllo CPU,
e termina in 47,43 s. Restano ell=11 per il profilo canonico e i controlli
reali densi positivo/rifiuto tardivo, entrambi ripetuti. Passano inoltre
shortage reale e regressioni W/KV/predecessore, incluso il fixture joint.

Non sono credito crittografico del profilo canonico, run AES a tre tentativi,
Γ reale, picco fisico o H100. Il record include il ledger PCG ridotto
con ell=2, non lo sostituisce al canonico; i metadati/refcount Arc non
sono dichiarati gratuiti o un risparmio misurato. Conserva l'errore iniziale
di compilazione nei due argomenti `Option<&Arc<Profile>>`, risolto con
`as_ref` senza modificare le relazioni del fixture.

## Ordered numerical history

Il successivo [controllo completo a due tentativi su SHA pulita `d026986`](../../benchmarks/results/c71-ordered-two-2026-09-27-d026986418a1.json)
è **fallito per timeout locale a 60,01 s**, exit 124. Il log conserva
l'accettazione reale del verifier ideale per il solo slot O=0, con
264.147 righe base e certificato da 7.739.529 B. Non contiene il marker
finale a due accettazioni: non si accredita O=2 completo. Questo non è
un rifiuto algebrico né un lower H100. Il limite non viene esteso; il
test resta nel codice ma è ignorato sul percorso locale, in attesa di
un run/hardware autorizzato separatamente. Nessun run a tre tentativi
ordinati o AES viene dedotto da questo prefisso.

Il [record su SHA pulita `7903bbf`](../../benchmarks/results/c71-ordered-history-2026-09-27-7903bbf7a07f.json)
conserva dieci test Rust seriali entro 60 s/2 GiB e check non-test B12/
Seed6. Il preparatore ordinato passa i predecessori del registro privato
al reader; questo condivide solo i KV Frozen immutabili. Il confronto
O=0/2/4 copre tutti i byte D12, padding pubblico e KV del token finale.
Cardinalità errata, riordino e altra installazione dello stesso plaintext W
sono respinti. Passano inoltre le PCS originali nei tre contesti, Prepare,
O=0 ordinato ideale, tre tentativi densi e il rifiuto del predecessore alterato.
Il positivo ordinato/Seed6 O=0 ad ell=2 è ripetuto in 47,33 s.

Il primo controllo ha rilevato un fixture storico non aggiornato: chiedeva
D12 al getter grezzo dopo che `eebabdb` ne aveva limitato il dominio alla
potenza di due minima dei byte vivi. Il record conserva il fallimento e
collega le evidenze precedenti, anteriori a quel cambio. Il limite runtime
resta invariato: il fixture verifica il dominio minimo e il rifiuto al bordo;
la sua closure PCS aggiunge gli zeri pubblici già previsti dal reader.

Non sono tre proof ordinate accettate né un run AES completo. Gli owner
accettati conservano ancora cut/cache/PCS; Arc e KV condivisi non danno
credito al picco fisico. Γ reale, ledger completo e gate H100 restano aperti.

## Canonical verifier with Seed6 capacity

Il [record su SHA pulita `a2fdf01`](../../benchmarks/results/c71-canonical-seed6-2026-09-27-a2fdf017cdd4.json)
conserva sette test Rust in sei invocazioni seriali entro 60 s/2 GiB,
più check non-test B12 e Seed6. Il verifier canonico riusa il medesimo
adapter di capacità/packing del percorso ridotto, senza Vec obbligatorio
di chiavi. Il controllo del prefisso O=0/150/300 usa un Map diagnostico
lazy: contesto, framing e P0 incompleto sono respinti senza consumo.

Il wrapper aggiunge setup reale Seed6 ridotto 25+6 e verifica lo shortage
prima del decoding, con cursor/slot zero, journal `(1,0)`, head zero e
retry/reopen respinti. Il controllo completo del registro termina in
11,06 s; passa anche il precedente shortage denso B12. Le regressioni
coprono packing, consumo incompleto e shortage del wrapper ridotto.
Nessuna nuova promozione canonica è osservata; transcript, riserve e
ledger del packing restano invariati. Non è Γ reale, run canonico positivo,
picco fisico o gate H100.

## Original P0 compact provider

Il [record su SHA pulita `df22d85`](../../benchmarks/results/c71-original-p0-compact-2026-09-27-df22d854da49.json)
conserva sei test Rust seriali entro 60 s/2 GiB e check non-test matrix-only,
B12 e Seed6. `Auxiliary::compact` usa gli originali C/X/W e i descrittori
del verifier per inner, padding, reshape testa/token e selezione delle
righe finali. Il preparatore nativo lo riusa al posto dei loop hidden=2;
cardinalità dei punti, layout e forme non corrispondenti sono respinti.

La proof P0 piccola con range e PCS W/A originali confronta ogni compact
col precedente oracolo letterale, inclusi reshape a due teste e tied head.
Un controllo separato con inner=3 verifica gli zeri di padding e rifiuta
punti corti/lunghi e layout errato prima dei getter. Passano regressione W
alterato, tre tentativi densi, O=0 ordinato ideale e O=0 ordinato/Seed6 ad
ell=2 in 47,39 s. Non vengono eseguiti i cohort sui pesi canonici.

Il provider non riceve MAC; resta il contratto NoPeek degli originali
immutabili. Il runner ridotto conserva il Vec dei compact. Non è il piano
P0 fisico a quattro letture, una nuova stima del picco o un lower completo;
ledger canonico, Γ reale e gate H100 restano invariati/aperti.

## Calibration failure records

Il [record su SHA pulita `b2697e4`](../../benchmarks/results/c71-calibration-failures-2026-09-27-b2697e49cfc1.json)
conserva nove controlli Python seriali entro 60 s/2 GiB. Il wrapper Γ ora
mantiene stdout/stderr del worker fallito e i prefissi catturati al timeout;
il codice nativo resta distinto dal codice di rifiuto del wrapper. Exit zero
con JSON invalido, non-oggetto, duplicato o trial incompleto produce un
record di fallimento. Passano anche snapshot immutabile della candidata,
provenienza respinta prima della lettura pesante e mancata pubblicazione
delle tabelle fallite. I record esistenti non vengono sovrascritti.

Il worker e la lettura W sono simulati nei casi del report. Anche il
positivo finto conserva `calibrated:false` e `credit:false`: non è un
trial numerico, Γ reale o autorizzazione all'esecuzione completa. Nessuna
build Rust o modifica del ledger/protocollo è necessaria per questo fix.

Il [record successivo `c1bc45b`](../../benchmarks/results/c71-calibration-atomic-2026-09-27-c1bc45b7f5f1.json)
porta i controlli Python a dodici: tabelle, ledger candidato e report
del trial riusano la stessa pubblicazione temporanea con fsync e hard link
esclusivo. Sono verificati successo, errore del produttore e pubblicazione
concorrente: niente file finale parziale, overwrite o temporanei residui
dopo le normali eccezioni. Non è un journal anti-rollback o un commit
distribuito; tutti i limiti di calibrazione e credito restano invariati.

## Replay installed W with ordered A

Il [record su SHA pulita `681def8`](../../benchmarks/results/c71-replay-weight-2026-09-27-681def8befff.json)
conserva nove test Rust seriali entro 60 s/2 GiB, più check non-test B12
e Seed6. Il packed W immutabile è condiviso fra Prepare e ReplayModel;
il controllo D10 confronta valori positivi/negativi e padding con il
precedente oracolo virtuale, e verifica che la corruzione numerica test-only
copy-on-write non cambi il getter committato. Layout e i16::MIN sono respinti.

La proof completa O=0 con W replay e A ordinata termina in 47,56 s con
Seed6 reale t=4/h=19/ell=2, 264.147 righe base / 88.049 MAC Fp3 originali
e una promozione con receipt coincidente dopo i journal dei due ruoli.
Passano anche streaming ideale, tre tentativi densi, W e predecessore
alterati, regressione joint e shortage. Il controllo dell'attributo ignore
non riesegue il precedente test a due accettazioni fuori budget.

Il record conserva due errori di sviluppo corretti: accesso del diagnostic
joint al vecchio campo denso e getter W oltre il dominio minimo della
mappa raw. Il secondo falliva prima del bootstrap; la correzione fornisce
la coda zero pubblica prima della mappa, senza allentarne il controllo.
Nessuna nuova identità crittografica o riserva viene introdotta.

È eliminata la copia virtuale persistente di W nel riferimento ridotto,
non il packed né workspace FFT/hash. Il getter conserva anche metadata
del profilo; non se ne presume la condivisione con i profili dello State
né costo nullo. Non è reader file-backed canonico, Γ calibrato, port GPU,
picco completo o GO H100.

## Native FFT remainder in replay openings

Il [record su SHA pulita `688ce4d`](../../benchmarks/results/c71-native-remainder-2026-09-27-688ce4de3e49.json)
conserva sei test Rust e tre Python seriali entro 60 s/2 GiB, più check
non-test B12 e Seed6. `Code::rows` ora usa la stessa riduzione a blocchi
del precedente oracolo Python, con DFT/iDFT native e fattori comuni alle
colonne. Payload e pad originali rimangono agli offset precedenti.

Il nuovo controllo confronta le righe con Horner indipendente su colonne
base e extension, inclusi pad privati negativi, blocco incompleto, query
duplicate, ordine inverso e batch vuoto. Verifica una sola lettura del
payload per callback e rifiuto pre-getter di dominio/cap invalidi.
La catena WHIR D10 coincide byte per byte con il backend denso originale
a monete fissate, incluso transcript e MAC terminale; il MAC alterato
resta respinto. Passano linear/range sourcewise, O=0 streaming ideale e
O=0 W replay/A ordinata con Seed6 reale ell=2 in 47,36 s.

Il cap ridotto è 1.024 richieste; setup e valutazione del resto sono ancora
quadratici in quel cap. La tree richiama il riduttore per ogni sottoalbero
e per le righe finali: non è la singola scansione dell'apertura canonica,
né il cap 2^21 con product/remainder tree bilanciato. Punti, spettri,
resti, workspace DFT e output sono costi vivi, non scratch gratuito.
Il diagnostic allocator della catena ridotta è conservato nel record,
senza promuoverlo a picco canonico. Nessuna nuova riserva, garanzia Lean,
calibrazione Γ, misura GPU o autorizzazione H100.

## Borrowed RMS correlation intervals

Il [record su SHA pulita `a93ae69`](../../benchmarks/results/c71-rms-borrowed-2026-09-27-a93ae69259a5.json)
conserva sei test Rust seriali entro 60 s/2 GiB e check non-test B12/Seed6.
Il dispatcher RMS usa un `Take` preso in prestito per Auth e Key, invece
di raccogliere preventivamente un altro Vec dell'intera riserva.
Il fixture P0/RMS/RNE/PCS originale verifica che il primo getter privato
avvenga prima dell'espansione completa e che i due ruoli consumino tutte
le 7.746 righe RMS previste sul successo. Restano le verifiche dei W/A
originali e gli errori numerici del fixture.

Passano tre accettazioni dense ideali, rifiuti del certificato, consumo
Seed6 incompleto con burn e O=0 W replay/A ordinata con Seed6 reale ell=2
in 47,90 s. La corruzione terminale del distinto fixture denso ell=11
è respinta in 50,06 s senza promozione e con l'intero intervallo bruciato.

Il burn non coincide con la materializzazione delle righe: un errore
interno può lasciare un suffisso non espanso, mai riutilizzabile dal
wrapper. Questo record non elimina i buffer interni GKR/statistic e degli altri componenti;
nessun nuovo margine arena, picco completo, Γ calibrato o GO H100.

## Borrowed GKR and byte intervals

Il [record su SHA pulita `616b121`](../../benchmarks/results/c71-gkr-borrowed-2026-09-27-616b121b9a70.json)
conserva dieci test Rust seriali entro 60 s/2 GiB e check non-test B12/Seed6.
Anche GKR e byte endpoint sourcewise prendono in prestito Auth/Key:
non raccolgono un altro Vec della propria riserva. Il census mantiene
`row_logical_elements` e separa `row_reserved_payload_bytes` dall'heap
di righe posseduto dal kernel, ora zero. I record storici non cambiano.

La prima lettura del frame originale precede l'espansione completa;
il consumo sul successo resta quello compilato. Le prove sourcewise
coincidono con le dense in wire, FS, punto e MAC originale, incluse una
sola cella, 421 programmi/ID oltre 255, byte ragged/contratti e prefisso
a pattern. Sono conservati i rifiuti per originali alterati e la chiusura
sulle stesse PCS. Passano RMS dispatcher e streaming integrato ideale.

Seed6 reale passa O=0 W replay/A ordinata ell=2 in 46,67 s; il diverso
fixture denso ell=11 rifiuta la corruzione terminale in 50,21 s senza
promozione. Passa anche il consumo parziale con burn. Le riserve non
cambiano e un suffisso non espanso non è riutilizzabile. Restano storage
del caller, workspace PCG, stato inline e buffer di statistic/lookup/RNE
e altri componenti. Non è un picco completo, Γ reale o gate H100.

## Borrowed RNE intervals

Il [record su SHA pulita `3eacdf5`](../../benchmarks/results/c71-rne-borrowed-2026-09-27-3eacdf57d714.json)
conserva dieci test Rust seriali entro 60 s/2 GiB e check non-test B12/Seed6.
Dispatcher delle tabelle e riduzione RNE passano ora `Take` in prestito,
senza nuovi Vec dell'intervallo. Il fixture table RNE osserva zero richieste
all'iteratore prima della prima lettura del probe e consumo esatto sul
successo nei due ruoli. Sono richieste osservate sull'iteratore del fixture,
non una misura della generazione PCG.

Passano ricette signed, ties/overflow, P0/RNE e RMS dispatcher con gli
originali W/A, certificato e streaming integrato. Seed6 reale accetta W
replay/A ordinata O=0 ell=2 in 46,75 s; il fixture denso ell=11 rifiuta
l'alterazione terminale in 49,89 s. Passa anche il burn con consumo parziale.
Il record conserva un comando check iniziale con nome feature inesistente,
poi corretto a `c71-b12-pcs`; non era un errore del codice.

Non cambiano ricette, shift, riserve compilate, transcript o PCS. Restano
altri buffer componenti, storage del caller e workspace PCG; sul fallimento
il suffisso non espanso rimane bruciato dal pool. Nessun nuovo credito
di picco fisico, calibrazione reale o GO H100.

## Borrowed native consumer intervals

Il [primo record su SHA pulita `a1987db`](../../benchmarks/results/c71-component-borrowed-2026-09-27-a1987dbbb81c.json)
conserva un successo e un fallimento: lookup sourcewise mantiene wire,
FS e MAC del denso, ma il fixture negativo pretendeva l'esaurimento
delle righe anche dopo il rifiuto di un originale staccato dalla PCS.
Il rifiuto previsto avveniva; falliva la successiva asserzione di consumo.
Il record conserva anche la prima build respinta dai due helper di prodotto
ancora tipizzati `Vec::IntoIter`, poi adattati a `ExactSizeIterator`.

Le asserzioni equivalenti dei fixture sono corrette insieme: esaurimento
sul successo, suffisso non espanso dopo rifiuto anticipato, senza modificare
i controlli sugli originali o drenare artificialmente l'iteratore. Il burn
dell'intero tentativo resta una proprietà del wrapper/pool, non di questi
test componenti.

Il [record corretto su SHA pulita `184aefa`](../../benchmarks/results/c71-component-borrowed-2026-09-27-184aefae4e5b.json)
conserva **25 test Rust in 24 invocazioni**, tutte entro 60 s/2 GiB, e
check non-test B12/Seed6. Passano lookup ed EXP30, statistic/P0, range/linear,
QK/PV, RoPE, gate-up, KV, RNE, byte, affine e argmax. Il test B12 fixed-run
verifica il rifiuto del reopen dopo il tentativo falso, pur lasciando un
suffisso non richiesto al consumer. Composed e streaming ideali passano.

Seed6 reale accetta W replay/A ordinata O=0 ell=2 in 46,95 s e il fixture
denso ell=11 rifiuta l'alterazione terminale in 50,10 s; passa anche il
consumo parziale con burn. Nessun conto delle riserve o transcript cambia.
Il lookup mantiene cardinalità e dimensione Auth, azzerando solo backing
e copia bulk del proprio intervallo. Adapter B12 denso, diagnostici,
workspace PCG e altri buffer restano distinti. Non è Γ reale, picco
fisico completo o un nuovo GO H100.

## FFT odd harness

Il [record su SHA pulita `5debdbd`](../../benchmarks/results/c71-fft-odd-harness-2026-09-27-5debdbd051b1.json)
conserva quattro test Python/C++ e due comandi host del runner, ciascuno
entro 60 s/2 GiB. Il runner riusa il kernel odd-log già presente, ora
selezionabile con `--odd`; il C++/CUDA non cambia. I controlli eseguono
otto confronti host con DFT, quadrati e dispari per log2_m=1..4, e
respingono report con forma, conteggi, allocazioni o timing alterati.
Il percorso CLI host-only e i nomi distinti append-only sono verificati.

I report CUDA dei test sono simulati: nessuna GPU eseguita né nuova
compilazione CUDA. Resta applicabile il precedente record statico
[odd-log/retention](../../benchmarks/results/c71-retained-capacity-2026-09-19-bfb274a1fcf2.json).
Il modo completo dispari prepara 2^21 elementi ×128, con valori/twiddle
nominati di 2.164.260.864 B, non un picco fisico. Scatter PCS, root/sali/hash,
resti, fence e harness completo restano aperti; nessuna proposta provider
o autorizzazione di spesa deriva da questi controlli.

## Balanced query setup

Il [record su SHA pulita `b9c6ee0`](../../benchmarks/results/c71-balanced-query-2026-09-27-b9c6ee031c7e.json)
conserva cinque test Rust e tre Python, seriali entro 60 s/2 GiB, più
check non-test B12/Seed6. Il modulo delle query usa prodotti FFT
bilanciati; il reciproco del modulo rovesciato usa raddoppio di Newton.
Gli oracoli diretti verificano coefficienti e identità troncata fino a
cap 1.024, con punti zero e ripetuti. Restano ordine, pad e una lettura
per coefficiente nel callback; il limite pubblico non è aumentato.

Passano righe base/extension contro Horner originale, parità completa
wire/FS/MAC della catena WHIR, streaming ideale e O=0 W replay/A ordinata
con Seed6 reale ell=2 in 46,57 s. Non è un tempo H100.
Si conservano livello corrente dei prodotti e intermedi del reciproco,
non l'albero completo per la valutazione multipunto: la valutazione
finale resta quadratica e i sottoalberi vengono ancora rigenerati separati.
Setup/FFT sono lavoro della prova; nessun credito canonico di memoria,
tempo, NoPeek o calibrazione deriva da questi controlli ridotti.

## Native query remainder tree

Il [record su SHA pulita `ffda2ef`](../../benchmarks/results/c71-query-tree-2026-09-27-ffda2efa42c1.json)
conserva cinque test Rust e tre Python, seriali entro 60 s/2 GiB, più
check non-test B12/Seed6. Il callback scende ora nell'albero dei resti
fino ai valori delle foglie, riusando il riduttore dei blocchi sorgente.
Gli spettri di modulo/reciproco sono conservati per ogni nodo; gli oracoli
controllano le forme dei livelli, i fattori della radice e tutte le righe
base/extension contro Horner, inclusi cap 1.024, duplicati e query ragged.

Passano parità wire/FS/MAC della catena WHIR, rifiuto dell'endpoint
alterato, streaming ideale e O=0 W replay/A ordinata con Seed6 reale
ell=2 in 47,79 s. La prima build fallita per tipo numerico ambiguo nel
test è conservata; la correzione esplicita `usize` non cambia l'aritmetica.

La valutazione finale non è più quadratica nel callback, ma ogni
sottoalbero Merkle viene ancora rigenerato separatamente. Gli spettri
di tutti i livelli, i temporanei Newton/FFT, i livelli dei resti e le
righe di output sono memoria posseduta, non gli stessi soli buffer della
radice. Cap canonico, scansione unica dell'apertura, picco fisico, Γ reale
e pipeline GPU restano aperti; nessun nuovo credito hardware.
