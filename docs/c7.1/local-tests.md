# C7.1 — test locali

[Design](design.md) · [Specifiche](specs.md) · [Sicurezza](security.md) ·
[Test su RunPod](runpod-tests.md) · [Evidenze storiche](../c7.1-history/evidence.md)

## Limiti e ambiente

I controlli locali usano input piccoli, un solo processo di test per volta,
un worker Rayon e 60 s / 2 GiB per invocazione. La compilazione è mirata,
con un solo job, nel target assoluto `rust/target`, senza incremental.
Non eseguire il workspace completo, i pesi reali o i domini PCS D34/D35.
Questi limiti sono locali; quelli CPU/CUDA RunPod sono nel
[runbook](runpod-tests.md#autorizzazione-e-limiti).
Un timeout è un esito negativo da conservare, non un permesso di estensione.
Un filtro che esegue zero test non fornisce una verifica.

Le modifiche documentali richiedono normalmente solo il controllo dei
documenti sotto. Per verificare la corrispondenza fra questo passaggio
di consegne e il codice sono pertinenti anche i gruppi numerici e nativi
seguenti. Non occorre ricompilare Lean: i milestone formali sono congelati
e qui non cambia il loro enunciato.

Il controllo documentale include anche il preflight dei permessi del file
locale `.env`: una fixture `0644` deve fallire e `0600` deve passare, senza
leggere o stampare il valore di alcuna credenziale. Una CLI Runpod fittizia
verifica inoltre che `list` usi soltanto il comando corrente
`runpodctl pod list --all`.

Dalla radice del repository:

```bash
source "$HOME/.cargo/env"
export C71_ROOT="$PWD"
export CARGO_TARGET_DIR="$C71_ROOT/rust/target" CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_DEV_OPT_LEVEL=2
export PYTHONDONTWRITEBYTECODE=1
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 RAYON_NUM_THREADS=1
```

Python usa `.venv/bin/python` con NumPy e pytest. Per ogni comando di test
applicare il limite in un subshell, così non vincola la compilazione:

```bash
(ulimit -v 2097152; timeout -k 5s 60s .venv/bin/python -m pytest -q -p no:cacheprovider tests/test_c71_docs.py)
```

Il [controllo documentale](../../tests/test_c71_docs.py) verifica i cinque
file operativi, i percorsi locali e le ancore, la mappa di migrazione,
l'integrità delle copie congelate e i riferimenti ai test/codice.
Controlla inoltre le identità degli input, la sintassi dei comandi RunPod,
l'arresto della build su errore e il manifest su file temporanei piccoli,
senza chiamare il provider o scaricare pesi.
Le fonti congelate conservano i riferimenti originali secondo la
[mappa storica](../c7.1-history/README.md#conservazione-e-mappa-dei-percorsi).

## Compilazione mirata

```bash
cd "$C71_ROOT/rust"
cargo test --offline --locked -j 1 -p volta-pcs \
  --features c71-seed6-reference --lib --no-run
cargo build --offline --locked -j 1 -p volta-pcs \
  --features c71-b12-pcs --example c71_calibration
cargo build --offline --locked -j 1 -p volta-pcs \
  --features c71-seed6-reference --example c71_canonical_reference
cd "$C71_ROOT"
```

Impostare `C71_PCS_TEST_BINARY` al percorso assoluto dell'eseguibile
`volta_pcs-…` stampato da Cargo, oppure riusato con digest, SHA di build
e compatibilità verificati secondo il [runbook](runpod-tests.md#riuso-del-bundle).
Il solo nome del file non ne dimostra la provenienza. Impostare:

```bash
export C71_CALIBRATION_BINARY="$CARGO_TARGET_DIR/debug/examples/c71_calibration"
test -x "$C71_PCS_TEST_BINARY"
test -x "$C71_CALIBRATION_BINARY"
```

Le socketpair Unix dei test AES sono locali ai due ruoli e non richiedono
rete esterna. Se il sandbox le blocca, l'eccezione riguarda soltanto
quella comunicazione locale. `c71-seed6-reference` è un riferimento CPU
esplicito; non abilita un fallback CPU nel percorso di produzione.

## Semantica, calibrazione e contabilità

### Collegamento del runner CUDA

Il checkpoint comprende `canonical_device`, staging originale fenced,
gather su prefissi KV inizializzati, metriche e selezione esplicita del
backend. Dopo la build mirata, eseguire separatamente i filtri seguenti
con il limite 60 s / 2 GiB e `--test-threads=1 --nocapture`:

```text
c71_canonical_device_
c71_canonical_resident
c71_b12_windowed_native_original_staging
c71_b12_windowed_native_shared
c71_b12_windowed_native_byte
c71_b12_windowed_native_signed
c71_b12_windowed_native_failure
c71_canonical_metrics_
c71_canonical_runner_
c71_b12_native_streaming_lookup_gkr_whir_positive_original_macs
```

La schedule usa tutti i 150 token nei tre contesti, controlla input vivi,
KV causale, checkpoint, 50 decisioni e batch equivalenti (Norm finale:
149 righe, non 150), senza W reale. Lo scanner numerico locale copre una
catena Affine/RNE, getter/cache e finestre originali, non l'intero forward.
I test range condiviso chiudono su PCS/MAC originali ridotti. Le socketpair
del test runner richiedono l'eccezione locale se il sandbox le vieta;
nessuna connessione esterna. Mantenere i log del rifiuto sandbox distinti
da quelli della successiva esecuzione autorizzata.

Se il toolkit è disponibile, compilare libreria completa e diagnostico
senza eseguirli; altrimenti la build CUDA si svolge sul pod autorizzato:

```bash
nvcc -std=c++17 -O2 -arch=sm_90 --shared --cudart static -Xcompiler=-fPIC \
  cuda/c71_dense_i16.cu cuda/c71_range_native.cu cuda/c71_pcs_hash.cu \
  cuda/c71_pcs_weight.cu \
  cuda/c71_range_runtime.cpp \
  -o /tmp/libc71_device_runner.so
nvcc -std=c++17 -O2 -arch=sm_90 --cudart static \
  cuda/c71_nonlinear_parity.cu cuda/c71_dense_i16.cu -o /tmp/c71_device_parity
```

I controlli Python pertinenti sono `tests/test_c71_docs.py`,
`tests/test_c71_dense_i16.py` e `tests/test_c71_range_native.py`, con i
limiti sopra. La parità hardware e il tempo completo sono controlli del
primo esperimento H100 autorizzato, non condizioni locali impossibili.
Le selezioni Rust `c71_b12_native_incremental_hash_exact_roots_and_salt_bands`
e `c71_b12_native_incremental_hash_coset_frontier_and_natural_root`, più
`c71_b12_native_incremental_hash_rejections_and_fail_closed`, compilano
un driver simulato e confrontano le funzioni hash condivise con B12
Rust: 128 colonne, bordi, sali a bande, tutti i livelli Merkle, ordine
naturale/strided, frontier di gruppi e rifiuti
di tipo/ordine/copertura/owner/budget/launch/fence/aritmetica. Restano
`gpu_execution:false`; il [conto del nuovo scratch](../c7.1-history/crypto-w-hash-2026-10-08.md)
non è un picco completo W o una misura H100.
Il [record pulito del componente W](../../benchmarks/results/c71-crypto-w-hash-local-2026-10-08-0bf5814bf9c4.json)
conserva cinque selezioni Rust positive, nove controlli documentali e
due controlli host dell'owner, limiti AS/deadline/RSS per invocazione,
Budget attivo e UBSan. I log di sviluppo e una build annullata da cwd
errato sono separati dalle misure pulite; usare sempre `cd rust` per
caricare anche `rust/.cargo/config.toml` e riusare i flag/cache corretti.
La policy della cache Cargo è descritta nella sezione
[provenienza](#risultati-e-conservazione).
Per [accumuli/FFT W](../c7.1-history/crypto-w-scan-fft-2026-10-08.md)
eseguire separatamente `c71_b12_native_weight_columns_exact_signed_pads_fft_hash`
e `c71_b12_native_weight_rejections_and_fail_closed`, poi il mapping
`c71_b12_gemma_layout_matches_packed_addresses_and_physical_tensor_mles`.
La prima fixture confronta ogni valore di 128 colonne su 32 coset, pad
originali, foglie e livelli Merkle strided; la seconda verifica 24 arresti.
`test_c71_range_native.py` confronta anche 526.336 prefissi di dot con
modulo signed i128 indipendente sotto UBSan. La build mirata può usare
`--config profile.dev.package.volta-pcs.opt-level=0` per il solo crate
locale mantenendo le dipendenze O2, cache e un job; conservare anche le
build fallite e distinguere RSS compiler dai test 60 s / 2 GiB AS.
I tempi Rust O0/C++ O2 non sono un rapporto di accelerazione. Il driver
simulato non compila o esegue CUDA; Tree/transcript del nuovo commitment
restano verifiche del successivo passo locale, hardware del pod autorizzato.
Eseguire separatamente ogni riga della tabella con il comando pytest
limitato sopra. Impostare i due binari prima dei test che li richiedono.

| File / selezione | Proprietà controllata |
|---|---|
| [test_c7_1_gemma_plan.py](../../tests/test_c7_1_gemma_plan.py), `-k 'B12 or canonical_PCS_wire or native_wire_body or complete_fixed_run or native_small_profile'` | Bound composti, parametri, conteggi del codec e tabelle del profilo ridotto |
| [test_c7_1_baseline_budget.py](../../tests/test_c7_1_baseline_budget.py) e [test_c71_bootstrap.py](../../tests/test_c71_bootstrap.py), separati | Budget e bootstrap; non esecuzione canonica |
| [test_c71_calibration.py](../../tests/test_c71_calibration.py) | Tabelle certificate, piano pubblico canonico e validazione fail-closed di DAG/layout W, scale nonzero, input/provenienza, errori, timeout e pubblicazione atomica senza overwrite di report e traccia |
| [test_c71_calibration_oracle.py](../../tests/test_c71_calibration_oracle.py) | Primitive numeriche Python indipendenti, dot product BLAS esatto sotto bound, RMS/RNE/RoPE/softmax/argmax e codec |
| [test_c71_calibration_oracle_driver.py](../../tests/test_c71_calibration_oracle_driver.py) | Schedulazione causale O=0/150/300, tutti i 13 tipi di operatore, RMS C esatto, lookup fail-closed e copertura completa su profilo ridotto |
| [test_c71_calibration_trace.py](../../tests/test_c71_calibration_trace.py) | Framing `C71TRC01`, copertura e confronto esatto su fixture; rifiuto di alterazioni, omissioni, duplicazioni, coordinate errate e troncamenti |
| [test_c71_activation_pilot.py](../../tests/test_c71_activation_pilot.py) | Inizializzatore delle scale su grafo piccolo, ID canonici e conservazione degli errori |
| [test_c7_d126_gemma_native_bf16.py](../../tests/test_c7_d126_gemma_native_bf16.py) e [test_c7_d126_gemma_weight_ingest.py](../../tests/test_c7_d126_gemma_weight_ingest.py), separati | Hash degli stessi byte quantizzati, esponenti minimi, packed e rifiuti su shard piccoli |
| [test_c71_query_remainder.py](../../tests/test_c71_query_remainder.py) | Identità algebriche dei resti, padding e query |
| [test_c71_fft_microbench.py](../../tests/test_c71_fft_microbench.py) | FFT host diretta/inversa, geometria dispari, normalizzazione e contabilità |
| [test_c71_remainder_native.py](../../tests/test_c71_remainder_native.py) | Otto fixture Rust/C++ degli stessi coefficienti, pad, spettri e resti |
| [test_c71_power_native.py](../../tests/test_c71_power_native.py) | Dodici fixture P/Q nella base nativa `v^3-v-1`, alterazioni e input malformati |
| [test_c71_arena_plan.py](../../tests/test_c71_arena_plan.py) | Intervalli, capacità, rilascio e margine del piano; non allocazioni GPU |
| [test_c71_response_trace.py](../../tests/test_c71_response_trace.py), [test_c71_whir_trace.py](../../tests/test_c71_whir_trace.py), [test_c71_pcg_trace.py](../../tests/test_c71_pcg_trace.py), separati | Contabilità congiunta, stati WHIR e generazione delle correlazioni |

I test della calibrazione non leggono checkpoint reali. `calibrated:false`
e `credit:false` restano corretti anche quando le fixture passano.
Il parser della traccia completa la validazione strutturale e la modalità
`trace` esegue il produttore indipendente; finché questo non passa sui pesi
reali non ammette Γ. Il confronto indipendente sui pesi reali e Γ ammesso sono acquisiti nel
[checkpoint H100](runpod-tests.md#stato-e-sequenza-operativa); le fixture
locali restano verifiche ridotte e non ereditano quel credito.
I report GPU simulati dei test FFT non sono misure CUDA.

L'audit del fork censisce 96 sorgenti e 26 delta revisionati, inclusi
l'accesso al flusso dei sali e il lifecycle del replay WHIR. Eseguire
`scripts/audit_c61_p3_fork.py` per il controllo diretto: hash diversi,
nuovi caller della RNG privata o perdita di binding/rilascio falliscono
chiuso. Il [record pulito](../../benchmarks/results/c71-fork-provenance-2026-10-02-4fbfbfb8afd0.json)
conserva la revisione che ha risolto il precedente delta non registrato.

L'[audit dipendenze pulito](../../benchmarks/results/c71-dependency-audit-2026-10-02-dc79276f51b6.json)
usa RustSec `117edb3b` e pip-audit 2.10.1: zero vulnerabilità note e zero crate
ritirate dopo gli aggiornamenti a `crossbeam-epoch 0.9.20` e
`chacha20 0.10.2`; i lint `correctness` e `suspicious` passano sui tre
target C7.1. Rimane l'avviso non-vulnerabilità `RUSTSEC-2024-0436` per
`paste 1.0.15`, dipendenza del commit Plonky3 fissato. La venv locale
ignorata è pulita dopo gli aggiornamenti registrati, ma `pyproject.toml`
non costituisce ancora un lock Python completo e riproducibile.

## Controlli nativi della costruzione corrente

Per telemetria/XOF eseguire separatamente, con 60 s / 2 GiB, un worker e
`--test-threads=1 --nocapture`:

```text
c71_b12_private_coins_
c71_progress_durable_
c71_b12_durable_telemetry_
c71_b12_streaming_
replay_tree_
c71_canonical_metrics_
c71_b12_full_sourcewise_chain
```

XOF confronta fill/u32/u64, seek e snapshot fra refill, ultimo refill/cap;
il benchmark usa 262.144 campioni Goldilocks per modo. Il JSONL verifica
prefisso leggibile prima della chiusura, permessi, no overwrite, fine
incompleta e errore I/O persistente. PCS confronta esattamente root,
valori, sali, padding, aperture duplicate e visite a 128 colonne, e misura
il costo della registrazione. WHIR ridotto conserva transcript e MAC
originali. Sono screen locali `credit:false`, senza credito H100.

Il [checkpoint pulito](../../benchmarks/results/c71-crypto-preparation-local-2026-10-08-04ab8ed1c4ce.json)
conserva 16 test Rust positivi inclusi guard budget e Seed6/AES ridotto,
9 controlli documentali e audit delle 96 sorgenti del fork. Il rifiuto
sandbox della socketpair precede il protocollo e resta nel proprio log;
il retry con sola eccezione locale passa entro 60 s / 2 GiB. Il massimo
RSS osservato nei filtri seriali è 134.553.600 B; per il retry AES resta
disponibile il census congiunto, non un nuovo RSS/HBM completo.

Eseguire un filtro alla volta:

```bash
(ulimit -v 2097152; timeout -k 5s 60s "$C71_PCS_TEST_BINARY" c71_b12_query_remainder --test-threads=1 --nocapture)
```

| Filtro, da eseguire separatamente | Risultato atteso e limite |
|---|---|
| `c71_calibration_trace_codec_is_framed_and_fail_closed` | Framing, digest terminale e rimozione dell'output incompleto su fixture ridotta |
| `c71_b12_native_canonical` | DAG, forme, codec e righe canoniche sintetiche; nessun forward completo |
| `c71_b12_native_registry` | Profilo posseduto, registro e rifiuto reale per capacità insufficiente |
| `c71_b12_native_dispatch_canonical` | Riserva/contesto e rifiuto di P0 incompleto, non accettazione canonica |
| `c71_canonical_ordered_internal_padding_histogram_and_byte_window` | Padding interno, istogrammi, checkpoint, finestre byte e scansione per sorgente con copertura/errori su un operatore canonico sintetico; non preparazione Gemma completa |
| `c71_canonical_ordered_producer_batches_keep_rows_until_last_consumer` | Due producer affine/RNE, 150 righe da checkpoint sintetico, ordine per operatore, input vivi fino al consumer e rifiuti budget/consumer; budget matrice canonica rifiutato prima delle letture |
| `c71_b12_native_canonical_numeric_rows_original_routes` | Include geometrie batch di tutte le matrici nei tre contesti senza eseguirle; batch di tre righe v_source con W condiviso, input zero e segni misti, route lm_head e rifiuti preallocazione; non forward completo |
| `c71_b12_range_window_permutation_and_intersections` | Permutazione MSB e intersezioni contro enumerazione D1–D7; rifiuti geometrici e descrittori delle 26 passate D34 senza allocare finestre canoniche |
| `c71_b12_windowed_range` | Consumer canopy/Gram/retention A D10 e W signed D12: transcript e MAC originali, fold zero/uno/extension, reader alterato e errori a ogni passata; nessuna prova D34/D35 |
| `c71_b12_windowed_native_byte`, `c71_b12_windowed_native_signed`, `c71_b12_windowed_native_failure`, separati | Prover Rust tramite ABI C e owner reale con driver/algebra host simulati: parità D10/D12, MAC originali, 44 finestre byte con errori e rifiuti di launch/fence/output/cleanup/libreria; non CUDA eseguito |
| `c71_b12_windowed_native_dense_chain` | Stesso owner ABI 4: W installato una volta, prodotto raw, RNE per 13 shift contro Rust e root range signed senza download intermedio; driver host simulato, nessun preparatore canonico |
| `c71_b12_windowed_native_shared` | Due prove range D10 con gather residente e stesso owner/W, parità di transcript e PCS sui MAC originali, nessun reader host o nuovo upload; rifiuti terminali di reader/tipo/shape/configurazione. Driver simulato, non runner canonico |
| `c71_b12_windowed_native_descriptor_capacity` | 512 handle piccoli simultanei, rilascio/riuso e rifiuto del 513° senza crescere l'arena |
| `c71_canonical_resident_kv_shared_prefixes` | Tre prefissi sintetici su una sola capacità KV450, QK storico dopo il terzo, nessuna copia di continuazione, rilascio all'ultima vista e rifiuto del fork prima del D2D |
| `c71_b12_windowed_native_abi4_rejects_legacy_stats` | Rifiuto di una libreria host ABI 2 prima di creare l'owner o leggere il ledger esteso |
| `c71_canonical_resident` | Adapter condiviso Matrix/RNE su profilo ridotto con vista di riga e owner W originale; 14 rifiuti di identità/shape/driver/contesto e due rifiuti del dispatcher canonico incompleto; solo driver host simulato |
| `c71_canonical_resident_byte` | Gather dalle tessere originali i48/i32/i16, ordine byte esatto, padding, blocchi fuori ordine, copertura e rifiuti terminali; driver simulato, non scanner GPU completo |
| `c71_canonical_resident_pointwise` | Route Affine/Gate nei tre contesti, righe selezionate da buffer residenti, raw CPU identici prima della RNE, termini zero assenti, coefficienti estremi e 12 rifiuti terminali; input sintetici e driver simulato |
| `c71_canonical_resident_embedding` | Catena ridotta W→embedding→Affine/RNE→range e byte gather, ordine e ripetizioni dei token, D2D conteggiato, 8 rifiuti e metadati canonici nei tre contesti; driver simulato |
| `c71_b12_signed_range_windows_gather_original_ragged_packed_and_padding` | Gather W signed, tessere ragged, estremi ±32767, padding, input invalidi e soli descrittori delle finestre D35 |
| `c71_b12_native_windowed_range_dispatch`, `c71_b12_range_histogram_scan_errors` | Dispatch range A senza getter scalare, istogramma dal commitment e fallimenti del primo scan senza sorgente installata |
| `c71_acceptance_transport` | Completamento legato al certificato/ricevuta pendenti; alterazioni, troncamenti e Stop |
| `c71_canonical_runner_transport_and_default_stop` | Framing della risposta, limiti prima dell'allocazione, contatori I/O e rifiuto del backend implicito; nessuna esecuzione canonica |
| `c71_canonical_runner_packed_input` | Lettura packed senza seconda copia completa, endian, lunghezza e marcatore di overflow su quattro/sei byte |
| `c71_canonical_runner_public_installation_and_request_framing` | Roundtrip dei dati pubblici, installazione e richieste; cap prima del corpo, troncamenti, slot/token errati; tabelle sintetiche, nessuna calibrazione |
| `c71_canonical_runner_counted_socket_protocol_three_slots` | Conteggio effettivo di distribuzione pubblica e tre scambi sullo stesso socket; corpi sintetici, nessun certificato valido |
| `c71_canonical_metrics_nested_failure_and_partial_io` | Fasi annidate/incomplete, I/O parziale e addebito del setup soltanto al primo tentativo |
| `c71_b12_native_norm_rows`, `c71_b12_native_rne_rows`, `c71_b12_native_affine_rows` | Operatori interi sulle route canoniche, con input sintetici |
| `c71_b12_native_prepare`, `c71_b12_native_composed` | Preparazione e tre accettazioni su grafo ridotto, MAC ideali |
| `c71_b12_native_certificate`, `c71_b12_native_context`, `c71_b12_native_interrupted`, `c71_b12_native_exhaustion` | Framing, contesto, terminalità e capacità |
| `c71_b12_native_consistent_inference`, `c71_b12_native_changed_predecessor` | Stesso W e storia accettata |
| `c71_b12_native_streaming_lookup_gkr_whir_positive_original_macs` | O=0 ordinato completo, lookup/GKR/range/PCS e stessi MAC |
| `sourcewise_range_matches_dense_original_wire_and_mac`, `c71_b12_sourcewise_linear_matches_dense_wire_fs_point_and_original_mac` | Parità col riferimento denso a monete fissate |
| `c71_b12_native_weight_replay` | Un solo W packed, padding e immutabilità |
| `c71_b12_query_factors`, `c71_b12_query_remainder`, `c71_b12_query_split` | Prodotti bilanciati, Newton, resti, zeri pubblici e pad originali |
| `c71_b12_replay_base`, `replay_tree`, `c71_b12_retained_initial` | Storage base/extension, batch Merkle e commitment iniziale conservato |
| `c71_b12_scattered` | 512 scansioni iniziali D14; coset extension contro percorso denso, singleton/MLE/OOD e retention con prefissi vivi e ordine non monotono; errori del consumer/produttore senza S1 parziale |
| `c71_b12_query_byte_windows` | Finestre fra colonne, prefissi vivi e pad contro Horner, errori/shape; catena PCS D10 con transcript e MAC originali, S1 trattenuto, getter scalare originale vietato e scansioni contate per fase |
| `c71_b12_canonical_initial_geometry` | Selezione W/A quattro coset 2^20 per scan e rifiuto di geometrie escluse prima di allocazioni/sali; nessuna esecuzione D34/D35 |
| `c71_b12_canonical_extension_geometry`, `c71_b12_sourcewise_geometry` | Tutti gli stadi dei profili D34/D35 senza allocarli, rifiuto di S3 2^24; cache Q/inverso riusata attraverso fold/scaling e rilasciata dopo due round |
| `c71_b12_full_sourcewise_chain_d17` | Parità PCS completa D17 con primo fold a sette bit, scanner, retention, transcript e MAC originali; non modello canonico o Seed6 reale |
| `c71_b12_gemma_biased_bytes_open_original_i48_i32_i16_macs` | Partizione byte per sorgente contro mapping packed indipendente, i16/i32/i48, errori e MAC originali su profilo ridotto |
| `c71_b12_rational_power`, `c71_b12_sourcewise_adaptive`, `c71_b12_full_sourcewise_chain` | Eq/Pow, stato trattenuto e catena WHIR con transcript originale |
| `c71_b12_ordered_sourcewise_o0`, `c71_b12_ordered_sourcewise_o2`, `c71_b12_ordered_sourcewise_o4` | Storia numerica e parità PCS su A originali; non tre accettazioni ordinate |
| `c71_b12_canonical_pcs_codec`, `c71_b12_native_canonical_wire_body` | Cap e roundtrip di corpi completi sintetici, senza verifica crittografica |
| `c71_seed6_native_partial`, `c71_seed6_native_shortage` | Intervalli lazy, rifiuto prima della promozione e burn |
| `c71_seed6_native_replay_w_and_ordered_a` | Un tentativo O=0 con AES reale, t=4/h=19/ell=2, W ricostruita e A ordinata |
| `c71_seed6_native_two_retained_dense` | Due risposte numeriche ridotte sullo stesso registro, Seed6 t=8/h=19/ell=2 e completamento dopo i journal; non getter canonico né tre risposte |
| `c71_seed6_native_full_o0_proof`, `c71_seed6_native_full_o0_late_rejection` | Un tentativo ridotto con A densa piccola, ell=11; positivo e rifiuto terminale |

Per modifiche a operatori/GKR/lookup aggiungere i rispettivi test componenti
esistenti e la parità integrata. Per modifiche a Seed6/Lifetime compilare
miratamente `volta-pcg --features c71-b11 --lib --no-run`, con lo stesso
target/profilo, e verificare separatamente i filtri `c71_seed6_one_channel`,
`c71_seed6_journal`, `c71_seed6_attempt_window`, `c71_seed6_trie`,
`c71_seed6_guard_cggm` e `c71_lifetime::tests`, sempre entro 60 s/2 GiB.

`c71_b12_native_ordered_two_attempts` è ignorato dopo un timeout locale:
anche `c71_seed6_native_three_retained_dense` è ignorato dopo aver superato
60 s con due accettazioni complete. Non usare `--ignored` o un limite
maggiore e non attribuire al timeout copertura del terzo tentativo.
Non eseguire l'intero filtro
`c71_seed6_native` sotto un unico timeout. Le geometrie ridotte non
trasferiscono i bound crittografici o il picco al profilo canonico ell=11.

## CUDA e controlli statici

`c71_canonical_resident_nonlinear_original_routes` confronta le route
GELU, softcap, RoPE, argmax, Norm non ponderate ed EXP30 nei tre contesti con `prepare_row`, usando
input e tabelle sintetici. Osserva l'ordine esatto di tutti gli output
tramite il driver simulato; completa anche un istogramma GELU di 150 righe
per contesto e un istogramma EXP30 completo di 8.192 query (padding
incluso), controllando i conteggi non biased e la shape 1×65.535.
Le route selezionate attraversano `produce_native`; l'arena della fixture
è 64 MiB e include tutte le tabelle pubbliche, non W canonica.
Eseguire separatamente `c71_canonical_resident_rms_exact_u128_coefficients`
(W ridotta, cinque larghezze fino a 5.376, coefficienti ponderati e non,
overflow) e ciascuno dei filtri `c71_canonical_resident_attention_o0`,
`c71_canonical_resident_attention_o150`, `c71_canonical_resident_attention_o300`
(due famiglie QK/PV e code append-only con futuro non inizializzato).
`c71_b12_windowed_native_attention_rejections_are_terminal` copre dieci
rifiuti di coefficienti, overflow, prefisso incompleto, marker, tabella,
score futuro, Pi negativa, padding ripetuto, launch e fence.
Include rifiuti di duplicati, copertura incompleta, input/contesto e
istogramma errati. `c71_b12_windowed_native_nonlinear_rejections_are_terminal`
copre errori di span, tabelle, marker, seal, launch, fence, flag e copie
D2H. Eseguire i due filtri separatamente con i limiti locali consueti.
`c71_b12_windowed_native_distinct_libraries_reject_colliding_handles`
carica due copie distinte della libreria simulata, forza handle uguali e
verifica il rifiuto prima di consumo/rilascio sul runtime sbagliato.
Il diagnostico [CUDA](../../cuda/c71_nonlinear_parity.cu) è compilabile
localmente; il comando di esecuzione è nei [test H100](runpod-tests.md).
Non sostituire questi controlli host alla parità hardware.

Il controllo aggiuntivo `c71_b12_gemma_output_head_rne_softcap_and_public_argmax_share_original_a`
ha rilevato un fallimento nell'asserzione `vrows.next().is_none()` dopo
il rifiuto di una decisione tie alterata. Il test e `linear::verify`
non sono modificati da questo port: l'iteratore preso in prestito può
restare parzialmente consumato su errore. Questo esito resta negativo,
senza attribuire copertura al successivo caso simulatore; non allenta
il burn dell'intera riserva imposto dal registro prima della verifica.

Il test [test_c71_dense_i16.py](../../tests/test_c71_dense_i16.py), separato
entro 60 s/2 GiB, compila con UBSan il modello host del kernel i16.
Controlla anche 216 casi pointwise con riferimento i128 indipendente,
coefficienti fino a ±2^30, termini zero e marcatore i16 rifiutato.
Verifica 65.535 split, 40 matrici contro dot i128, mapping univoco dei
frammenti, somme dei lane, bordi/padding, marcatore −32768 e guardie dei
buffer. K massimo eseguito è 21.504 su una matrice 1x1, non una proiezione
canonica. Verifica inoltre RNE su tutti gli i16 per shift −16..49, estremi
i64/signed-48 e pareggi ±1, contro divisione i128 indipendente sotto UBSan.
La compilazione sm_90 di `cuda/c71_dense_i16.cu` non esegue GPU né misura
GEMM o inference complete.
Il test [test_c71_range_native.py](../../tests/test_c71_range_native.py),
eseguito separatamente con il limite 60 s/2 GiB sopra, compila un controllo
host di 37 casi per root signed/byte, coefficienti cubici, Gram e fold.
Usa al massimo 2.048 valori originali; non esegue CUDA o una prova Rust.
La compilazione di `cuda/c71_range_native.cu` per sm_90 verifica i kernel
e i launcher, non il collegamento al runner o il picco fisico. Compilare
insieme `cuda/c71_range_runtime.cpp` per includere l'owner residente.
Lo stesso test Python compila anche il runtime con un driver CUDA fittizio
differito: arena massima 262.144 B, ritenzione della capacità, riuso,
riduzione dei coefficienti, H/retention e 13 rifiuti terminali. Verifica
che errori di fence/limb non pubblichino output e conserva il fallimento
di cleanup. Aggiunge due batch prodotto/RNE/range sullo stesso W di 20 B,
23 rifiuti densi, una vista della seconda riga e cleanup W/arena sotto UBSan.
Il gather aggiunge 19 rifiuti, estremi dei tre codec, ordine dei byte,
incluso −32768 nel codec byte (lo slack argmax), e il pointwise aggiunge
14 rifiuti di shape/handle/coefficiente/driver. Verifica inoltre
finestra pending non consumabile e rilascio del flag; conta capacità simultanee
e copie, senza scaricare matrici intermedie. Il driver simulato non esegue
o convalida i kernel CUDA. L'embedding aggiunge copie D2D per batch di
1, 4 e 150 token, osservazione dell'ordine esatto e 17 rifiuti, inclusi
token invalidi prima della prima copia ed errori dopo copie parziali.
Il link dell'owner ABI 4 richiede anche
`cuda/c71_dense_i16.cu`; Rust rifiuta librerie della precedente ABI.
Con un toolkit dotato di runtime statico usare `--cudart static` per la libreria;
non dedurre un errore dei kernel dall'assenza di `libcudart.so`.
I filtri `c71_b12_windowed_native_*` compilano ora una libreria host
temporanea del medesimo owner, con simboli CUDA fittizi e algebra di
riferimento, e la caricano nel prover Rust. Non caricano la libreria CUDA
reale. Byte D10 usa finestre da 512 B, signed D12 da 4.096 B; l'arena
simulata è di 262.144 B. I controlli non verificano kernel, D34/D35 o H100.
Per il controllo host della FFT:

```bash
(ulimit -v 2097152; timeout -k 5s 60s .venv/bin/python scripts/run_c71_fft_microbench.py --host-only --odd --inverse --host-log2-m 3 --timeout-seconds 60)
```

Omettere `--host-only` avvia un percorso GPU: richiede la fase autorizzata
di [runpod-tests](runpod-tests.md). Una compilazione `nvcc` per `sm_90`,
con SASS e ptxas conservati, verifica solo il binario. Non misura tempi,
picco o istruzioni realmente eseguite. I modi `--gpu-remainder-native`
e `--gpu-power-native` richiedono lo stesso controllo esplicito.

## Risultati e conservazione

Per ogni verifica conservare SHA del codice, comando, exit code, numero
di test, durata e limiti, distinguendo warning, rifiuti attesi e failure.
I record di riferimento richiedono albero pulito e `git_dirty:false` e
vanno in nuovi file `benchmarks/results/<milestone>-<date>-<gitsha>.json`.
Non riscrivere risultati precedenti, neppure per correggerli.

Lo [stato corrente](design.md#risultati-attuali-e-prossime-ottimizzazioni)
registra Γ ammesso e diagnostica della prova incompleta al 7 ottobre.
Le cronache, i fallimenti e i conteggi dei checkpoint restano nei
[record originali](../../benchmarks/results/) e nell'[archivio](../c7.1-history/README.md).
I fallimenti delle fixture rimangono distinti dalle successive correzioni.

Questa pagina contiene comandi e significato dei test; l'archivio conserva
gli esiti datati. Usare la cache canonica `rust/target` per le build mirate,
conservarlo fino alla conclusione e poi rimuoverlo preservando fixture ed
evidenze, salvo istruzioni diverse del proprietario. Non creare target
alternativi per singoli crate. `.cargo/config.toml` imposta
`target-cpu=native`: i tempi CPU non si trasferiscono a un'altra macchina.

La regressione del pilot confronta byte, contatori e causalità tra
blocchi seriali/paralleli e tra sorgenti streamed/mappate readonly;
la parte a due thread si esegue sul pod, mantenendo i controlli locali
a un thread. I controlli CLI verificano inoltre avanzamento parziale,
tempi per operatore, file privati 0600 e conservazione su timeout/errore.
Senza binario locale compatibile, la selezione `-k 'not parallel and not native_pilot'`
copre queste fixture; le due esclusioni restano da eseguire sul pod,
senza attribuire loro credito locale.
Analisi del codice e fixture ridotte restano locali
entro i limiti sopra; misure sui pesi reali, prove parallele e qualsiasi
esecuzione CUDA si svolgono sul pod autorizzato. L'accelerazione richiede
confronti col riferimento su dati fissati, errori e ordine causale, poi
misure rappresentative sul pod; non autorizza un pilot completo sulla VM.

## Budget simultaneo e rilascio dei workspace

Compilare la stessa lib con `c71-seed6-reference`; eseguire un filtro per
invocazione, sempre 60 s / 2 GiB e un solo worker/thread. Le geometrie
canoniche sotto enumerano metadati, senza allocare D34/D35 o W reale.

```text
c71_temporary_budget_
c71_original_claim_batch_
c71_canonical_device_allocation_geometry
c71_b12_canonical_initial_geometry
c71_b12_canonical_extension_geometry
replay_tree_
c71_b12_query_factors_
c71_b12_scattered_
c71_b12_query_byte_windows
c71_b12_retained_lifecycle
c71_b12_full_sourcewise_chain
c71_b12_windowed_native_
c71_seed6_native_full_o0_proof_promotes_same_receipt_after_role_journals
```

Il test budget controlla rifiuto prima di allocazione, somma host/device,
realloc vecchio+nuovo, singolo owner e restituzione mmap. Le fixture C
controllano callback e fallimento conservativo della free. La prova Seed6
ridotta usa AES reale e termina in verifica/promozione; le prove range
residenti usano CUDA fittizia e MAC originali, non esecuzione GPU.
Conservare i log con `C71_PCS_ALLOCATION_GEOMETRY`,
`C71_DEVICE_ALLOCATION_GEOMETRY` e `C71_TEMPORARY_ALLOCATIONS` e passarne
la directory a [c71_temporary_ledger.py](../../scripts/c71_temporary_ledger.py).
Il report include esplicitamente la riserva fisica non ancora misurata.
Un run di record parte dal commit di implementazione pulito; i record
precedenti, inclusi fallimenti e filtri vuoti, non vanno sovrascritti.
