# C7.1 — test locali

[Design](design.md) · [Specifiche](specs.md) · [Sicurezza](security.md) ·
[Test su RunPod](runpod-tests.md) · [Evidenze storiche](../c7.1-history/evidence.md)

## Limiti e ambiente

I controlli locali usano input piccoli, un solo processo di test per volta,
un worker Rayon e 60 s / 2 GiB per invocazione. La compilazione è mirata,
con un solo job, nel target assoluto `rust/target`, senza incremental.
Non eseguire il workspace completo, i pesi reali o i domini PCS D34/D35.
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
`volta_pcs-…` appena stampato da Cargo, non a un vecchio binario scelto
per nome. Impostare:

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
reali non ammette Γ. Il
[record del driver](../../benchmarks/results/c71-independent-driver-2026-10-02-645e855645d8.json)
registra l'implementazione e i controlli locali, non una misura completa. Il
[readiness audit corrente](../../benchmarks/results/c71-h100-e2e-readiness-2026-10-03-fbd6141e7a1e.json)
registra `NOT_READY` per runtime della calibrazione e integrazione E2E. Il
[record del piano pubblico](../../benchmarks/results/c71-oracle-plan-2026-10-02-55423e496cfc.json)
registra tre DAG canonici validati, ma non esecuzione numerica indipendente. Il
[record delle forme per contesto](../../benchmarks/results/c71-trace-context-shapes-2026-10-02-b634e781795d.json)
registra il binding esatto delle colonne attention variabili al piano canonico. Il
[record degli operatori indipendenti](../../benchmarks/results/c71-independent-operators-2026-10-02-2ed8e2091515.json)
limita esplicitamente la parità corrente alla fixture ridotta. Il
[record pulito](../../benchmarks/results/c71-calibration-trace-2026-10-02-f47b22d7a4c5.json)
conserva i test dell'export e dei rifiuti con questo limite esplicito. Il
[record dei permessi](../../benchmarks/results/c71-calibration-trace-permissions-2026-10-02-a0f46bf8ca7f.json)
collega la correzione successiva che forza `0600` nel writer e nel wrapper.
Il [record del confine i16](../../benchmarks/results/c71-i16-marker-2026-10-02-69e597e7cbd2.json)
verifica il rifiuto di −32768 salvo lo slack argmax biased-u16 previsto
dalla specifica.
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
| `c71_b12_windowed_native_dense_chain` | Stesso owner ABI 3: W installato una volta, prodotto raw, RNE per 13 shift contro Rust e root range signed senza download intermedio; driver host simulato, nessun preparatore canonico |
| `c71_b12_windowed_native_abi3_rejects_legacy_stats` | Rifiuto di una libreria host ABI 2 prima di creare l'owner o leggere il ledger esteso |
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
| `c71_b12_canonical_initial_geometry` | Selezione W/A 2^22 e rifiuto di geometrie escluse prima di allocazioni/sali; nessuna esecuzione D34/D35 |
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
Un candidato separato con W ricostruita, A ordinata e pool Seed6 reale ha
completato il primo tentativo e raggiunto `range_A` del secondo con otto
blocchi, ma è scaduto a 60 s. Il
[record negativo](../../benchmarks/results/c71-real-two-attempts-2026-10-03-262e89febe2c.json)
conserva l'esito; il candidato non è mantenuto nella suite.

## CUDA e controlli statici

Il [checkpoint RMS/attention](../../benchmarks/results/c71-attention-local-2026-10-04-85e77ea66b6f.json)
registra 22 test Rust e 12 Python passati sulla SHA pulita, build/lint e
compilazione sm_90 del runtime e del diagnostico, senza esecuzione CUDA.

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

Il [record Affine/Gate residente](../../benchmarks/results/c71-pointwise-local-2026-10-03-e8566ae6e395.json)
conserva 22 test Rust e 12 Python sulla SHA pulita, build/lint e libreria
sm_90. Verifica 181 route Affine e 60 Gate per ciascuno dei tre contesti,
una sola riga sintetica selezionata per operazione, raw CPU identico e RNE
originale: non sono forward completi. L'arena della fixture è 8 MiB,
senza W caricato. Il record corregge anche il rifiuto errato di −32768
nel solo codec byte condiviso. Il kernel pointwise usa 18 registri,
senza stack o spill; nessuna esecuzione GPU o certificato canonico.

Il [record del gather residente](../../benchmarks/results/c71-byte-resident-local-2026-10-03-2f6d017b1c93.json)
conserva 18 test Rust e 12 Python sulla SHA pulita, build/lint e libreria
sm_90. Verifica 130 finestre sintetiche fino a 128 byte, codec i48/i32/i16,
ordine esatto e 11 rifiuti Rust. L'entry point canonico esegue solo 128 byte
di padding esterno D34, non un replay completo. Il kernel gather compilato
usa 32 registri, senza stack o spill; nessuna esecuzione CUDA acquisita.

Il [record dell'adapter residente](../../benchmarks/results/c71-resident-adapter-local-2026-10-03-c8254c74b41e.json)
conserva 15 test Rust e 12 Python sulla SHA pulita, build e lint
`correctness`/`suspicious`. Collega Matrix/RNE all'owner nativo su un
profilo ridotto, incluse viste di riga senza copie e 14 rifiuti terminali;
il dispatcher canonico rifiuta operatori mancanti e W incompleta.
La libreria sm_90 esporta abort e viste di riga; SASS invariato rispetto
all'owner condiviso. Driver simulato, nessuna esecuzione GPU, nessuno
scanner canonico interamente residente e nessun certificato canonico.

Il [record del batching del preparatore](../../benchmarks/results/c71-producer-batch-local-2026-10-03-4e66ebb93705.json)
conserva 11 test Rust e 9 Python sulla SHA pulita, build e lint
`correctness`/`suspicious`. Esegue tre righe v_source sintetiche con
22.020.096 letture W condivise e un replay affine/RNE da 150 righe;
le 411 geometrie matriciali per contesto sono solo descrittori.
La schedule è collegata allo scanner CPU, non ai buffer GPU residenti.

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
Il [record locale](../../benchmarks/results/c71-dense-i16-local-2026-10-03-dacbd64425f1.json)
conserva 10 controlli passati, hash degli artefatti e quattro istruzioni
IMMA statiche nel SASS; nessuna misura GPU o certificato canonico.
Il [record dell'owner condiviso](../../benchmarks/results/c71-dense-owner-local-2026-10-03-d0fd644ed704.json)
aggiunge 9 test Rust e 12 Python sulla revisione pulita, W residente,
RNE e range nello stesso contesto; conserva anche la build interrotta
per correggere la directory e la semplificazione delle divisioni RNE.

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
Il link dell'owner ABI 3 richiede anche
`cuda/c71_dense_i16.cu`; Rust rifiuta librerie della precedente ABI.
Il toolkit
locale dispone del runtime statico: usare `--cudart static` per la libreria,
non dedurre un errore dei kernel dall'assenza di `libcudart.so`.
Il [checkpoint nativo](../c7.1-history/canonical-native-range-kernels.md)
conserva esiti, errori degli strumenti, stack locale e artefatti compilati;
non contiene esecuzioni GPU o prove canoniche.
Il [record dell'owner residente](../../benchmarks/results/c71-range-owner-local-2026-10-03-20d85df34158.json)
aggiunge undici test Python, controllo UBSan del driver simulato e link
kernel/runtime sulla SHA pulita. Il SASS dei kernel è invariato; il nuovo
owner in quella revisione non era ancora collegato ai callback Rust.
I filtri `c71_b12_windowed_native_*` compilano ora una libreria host
temporanea del medesimo owner, con simboli CUDA fittizi e algebra di
riferimento, e la caricano nel prover Rust. Non caricano la libreria CUDA
reale. Byte D10 usa finestre da 512 B, signed D12 da 4.096 B; l'arena
simulata è di 262.144 B. I controlli non verificano kernel, D34/D35 o H100.
Il [record del collegamento Rust](../../benchmarks/results/c71-range-rust-local-2026-10-03-a7a644cd563d.json)
conserva undici test Rust e undici Python, build e lint sulla revisione
pulita. Distingue la parità attraverso l'ABI dalle regressioni CPU integrate
e conserva i log dei rifiuti iniettati. La cache di build è mantenuta.

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

Il [checkpoint nonlineare](../../benchmarks/results/c71-nonlinear-local-2026-10-04-870ec1faf05d.json)
registra 22 test Rust e 12 Python passati sulla SHA pulita, il fallimento
CPU softcap/argmax descritto sopra, build/lint e compilazione sm_90.
Conserva le correzioni del bias istogramma e dell'identità degli owner,
senza attestare scanner completo, esecuzione CUDA o runner H100 pronto.

Il [record embedding residente](../../benchmarks/results/c71-embedding-local-2026-10-03-27c0db34fe92.json)
registra 25 test Rust e 12 Python sulla revisione pulita, ABI 3, copie D2D
ordinate dal W originale e rifiuti dopo copie parziali. Conserva il fallimento
iniziale della pulizia della fixture ABI e il retry del disassemblatore.
Il SASS resta invariato: embedding usa copie native, non un nuovo kernel.
Quella revisione disponeva di cinque tipi di producer su tredici; le nuove
route nonlineari ne aggiungono quattro. Questo inventario non è una
percentuale di completamento né una prova canonica o GPU.

Per ogni verifica conservare SHA del codice, comando, exit code, numero
di test, durata e limiti, distinguendo warning, rifiuti attesi e failure.
I record di riferimento richiedono albero pulito e `git_dirty:false` e
vanno in nuovi file `benchmarks/results/<milestone>-<date>-<gitsha>.json`.
Non riscrivere risultati precedenti, neppure per correggerli.

Il [record del riferimento canonico CPU](../../benchmarks/results/c71-canonical-reference-local-2026-10-03-dfb0867c6010.json)
conserva i controlli della pipeline, i limiti di copertura e i fallimenti
di sviluppo separati dalle esecuzioni sulla revisione pulita. Non attesta
certificati canonici validi o completamento del lavoro locale per H100.
Il [record della strumentazione](../../benchmarks/results/c71-runner-measurements-local-2026-10-03-187a0b9dc9ce.json)
registra separatamente 9 test Rust, 10 Python e due rifiuti CLI sulla SHA
pulita, con contatori di tre scambi sintetici e rifiuto per capacità reale.
Non è un'esecuzione di tre prove. Conserva inoltre il riscontro statico
del cap 2^18 del replay nella revisione registrata.
Il [record dello scanner iniziale](../../benchmarks/results/c71-initial-scan-local-2026-10-03-83d366ccbc5c.json)
conserva 23 test Rust, 9 Python e due rifiuti CLI sulla revisione pulita
che sostituisce quel limite con la geometria iniziale scelta. Include
la regressione del cap query trovata e corretta durante lo sviluppo.
La parità a 512 passaggi è D14; D34/D35 e picco completo non sono eseguiti.
Il [record delle query a finestre](../../benchmarks/results/c71-query-windows-local-2026-10-03-fa8a1617a674.json)
registra 24 test Rust, 9 Python e due rifiuti CLI sulla SHA pulita,
inclusa la catena PCS D10 con reader byte, S1 e MAC originali. Conserva
l'asserzione errata sul conteggio coset del fixture e la sua correzione;
nessuna allocazione/esecuzione dei domini canonici o misura GPU.
Il [record delle riduzioni sorgente](../../benchmarks/results/c71-residual-scan-local-2026-10-03-989efa70c151.json)
conserva 29 test Rust, 9 Python e due rifiuti CLI sulla SHA pulita, con
singleton/coset/OOD/retention e catena D10 senza getter originale scalare.
Il primo errore di compilazione è conservato; la
[correzione dei metadati](../../benchmarks/results/c71-residual-scan-metadata-correction-2026-10-03-989efa70c151.json)
riporta le durate già presenti negli stdout, senza sovrascrivere il record
o attribuire una nuova esecuzione. D16 e geometrie extension grandi erano
limiti di quella revisione; il [checkpoint successivo](../c7.1-history/canonical-pcs-stages.md)
ne collega il supporto CPU, senza credito canonico, GPU o di picco fisico.
Il [checkpoint del gather range](../c7.1-history/canonical-range-gather.md)
descrive i controlli del nuovo reader riordinato. Il test dei byte biased
copre anche il gather i48/i32/i16 e il test canonico dell'operatore copre
checkpoint, istogrammi e padding. Nessuno dei due attesta un prover range
Gram o una finestra di 2 GiB eseguita. Il
[record pulito](../../benchmarks/results/c71-range-gather-local-2026-10-03-0e61ef0826a5.json)
registra 15 test Rust, 11 Python e i lint di correttezza; distingue le
208 finestre D34 controllate solo come descrittori dalle finestre piccole
eseguite, al massimo 256 byte nel gather.
Il [record del consumer range A](../../benchmarks/results/c71-windowed-range-local-2026-10-03-0c3807f2fecb.json)
registra 28 test Rust, 11 Python, build/lint e due rifiuti CLI sulla SHA
pulita. Include parità D10, chiusura sui MAC originali, reader alterato
e errori a ogni passata ridotta. Le finestre del consumer eseguite sono
al più 1.024 byte; le 26 passate D34 sono selezionate, non eseguite.
Il [checkpoint signed W](../c7.1-history/canonical-signed-range.md) aggiunge
dieci test Rust mirati e nove Python sulla SHA pulita, con parità D12,
MAC originali e una prova integrata ridotta che usa il nuovo range W.
Il massimo buffer signed eseguito è 8.192 byte; le finestre D35 da
256 MiB restano non eseguite. Il record conserva l'errore iniziale della
fixture PCS e distingue la provenienza delle due build.
Il [record degli stadi PCS](../../benchmarks/results/c71-pcs-stages-local-2026-10-03-cc5db06c1796.json)
registra 32 test Rust, 18 Python e due rifiuti CLI sulla SHA pulita,
inclusa la catena PCS D17, conservando gli errori di sviluppo. Una
[correzione collegata](../../benchmarks/results/c71-pcs-stages-block-cap-correction-2026-10-03-cc5db06c1796.json)
distingue il blocco 1.024 dei confronti diretti dal massimo 2.048 dei
test integrati; il cap 2^21 e i domini D34/D35 non sono eseguiti.

La verifica di questa riorganizzazione e gli eventuali fallimenti sono
registrati nell'[audit documentale](../c7.1-history/reorganization-audit.md).
Questa pagina contiene comandi e significato dei test; l'archivio conserva
gli esiti datati. Il proprietario ha autorizzato il 2026-10-03 a conservare
la cache canonica `rust/target` fino alla fine del goal corrente, per evitare
ricompilazioni complete a ogni checkpoint. Alla conclusione del goal rimuovere
la cache, preservando fixture ed evidenze, salvo nuove istruzioni. Non creare target
alternativi per singoli crate. `.cargo/config.toml` imposta
`target-cpu=native`: i tempi CPU non si trasferiscono a un'altra macchina.
