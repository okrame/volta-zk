# C7.1 — Evidence and validation

[Status](status.md) · [Design](design.md) · [Security](security.md) · [Decisions](decisions.md)

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
1–7 usa le stesse coin, con root e Delta note al fixture: non prova OT,
bridge Fp6 o composizione MAC. Le [procedure](../procedures/build-and-test.md#replay-whir-e-codec-cggm-ridotti)
conservano test piccoli e seriali. Nessun nuovo credito Lean o modifica
a transcript, NoPeek, endpoint o trust model.

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
