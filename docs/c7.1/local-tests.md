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
| `c71_b12_range_window_permutation_and_intersections` | Permutazione MSB e intersezioni contro enumerazione D1–D7; rifiuti geometrici e descrittori delle 26 passate D34 senza allocare finestre canoniche |
| `c71_b12_windowed_range` | Consumer canopy/Gram/retention A D10 e W signed D12: transcript e MAC originali, fold zero/uno/extension, reader alterato e errori a ogni passata; nessuna prova D34/D35 |
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
Il [record degli stadi PCS](../../benchmarks/results/c71-pcs-stages-local-2026-10-03-cc5db06c1796.json)
registra 32 test Rust, 18 Python e due rifiuti CLI sulla SHA pulita,
inclusa la catena PCS D17, conservando gli errori di sviluppo. Una
[correzione collegata](../../benchmarks/results/c71-pcs-stages-block-cap-correction-2026-10-03-cc5db06c1796.json)
distingue il blocco 1.024 dei confronti diretti dal massimo 2.048 dei
test integrati; il cap 2^21 e i domini D34/D35 non sono eseguiti.

La verifica di questa riorganizzazione e gli eventuali fallimenti sono
registrati nell'[audit documentale](../c7.1-history/reorganization-audit.md).
Questa pagina contiene comandi e significato dei test; l'archivio conserva
gli esiti datati. Dopo il checkpoint e prima di terminare la sessione
rimuovere la cache canonica `rust/target`, preservando fixture ed evidenze;
conservarla richiede un'indicazione del proprietario. Non creare target
alternativi per singoli crate. `.cargo/config.toml` imposta
`target-cpu=native`: i tempi CPU non si trasferiscono a un'altra macchina.
