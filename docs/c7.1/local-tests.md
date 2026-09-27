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
| [test_c71_calibration.py](../../tests/test_c71_calibration.py) | Tabelle certificate, scale nonzero, input/provenienza, errori, timeout e pubblicazione senza overwrite |
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
I report GPU simulati dei test FFT non sono misure CUDA.

Il test della baseline ha attualmente un fallimento preesistente:
26 file del fork modificati contro 25 registrati; manca la revisione
di `merkle-tree/src/hiding_mmcs.rs`. Eseguire
`scripts/audit_c61_p3_fork.py` per il controllo diretto. Conservare
l'esito negativo finché la revisione non è completata; non cambiare
semplicemente il conteggio atteso. [Evidenza](../c7.1-history/reorganization-audit.md#fallimento-preesistente-dellaudit-del-fork).

## Controlli nativi della costruzione corrente

Eseguire un filtro alla volta:

```bash
(ulimit -v 2097152; timeout -k 5s 60s "$C71_PCS_TEST_BINARY" c71_b12_query_remainder --test-threads=1 --nocapture)
```

| Filtro, da eseguire separatamente | Risultato atteso e limite |
|---|---|
| `c71_b12_native_canonical` | DAG, forme, codec e righe canoniche sintetiche; nessun forward completo |
| `c71_b12_native_registry` | Profilo posseduto, registro e rifiuto reale per capacità insufficiente |
| `c71_b12_native_dispatch_canonical` | Riserva/contesto e rifiuto di P0 incompleto, non accettazione canonica |
| `c71_b12_native_norm_rows`, `c71_b12_native_rne_rows`, `c71_b12_native_affine_rows` | Operatori interi sulle route canoniche, con input sintetici |
| `c71_b12_native_prepare`, `c71_b12_native_composed` | Preparazione e tre accettazioni su grafo ridotto, MAC ideali |
| `c71_b12_native_certificate`, `c71_b12_native_context`, `c71_b12_native_interrupted`, `c71_b12_native_exhaustion` | Framing, contesto, terminalità e capacità |
| `c71_b12_native_consistent_inference`, `c71_b12_native_changed_predecessor` | Stesso W e storia accettata |
| `c71_b12_native_streaming_lookup_gkr_whir_positive_original_macs` | O=0 ordinato completo, lookup/GKR/range/PCS e stessi MAC |
| `sourcewise_range_matches_dense_original_wire_and_mac`, `c71_b12_sourcewise_linear_matches_dense_wire_fs_point_and_original_mac` | Parità col riferimento denso a monete fissate |
| `c71_b12_native_weight_replay` | Un solo W packed, padding e immutabilità |
| `c71_b12_query_factors`, `c71_b12_query_remainder`, `c71_b12_query_split` | Prodotti bilanciati, Newton, resti, zeri pubblici e pad originali |
| `c71_b12_replay_base`, `replay_tree`, `c71_b12_retained_initial` | Storage base/extension, batch Merkle e commitment iniziale conservato |
| `c71_b12_rational_power`, `c71_b12_sourcewise_adaptive`, `c71_b12_full_sourcewise_chain` | Eq/Pow, stato trattenuto e catena WHIR con transcript originale |
| `c71_b12_ordered_sourcewise_o0`, `c71_b12_ordered_sourcewise_o2`, `c71_b12_ordered_sourcewise_o4` | Storia numerica e parità PCS su A originali; non tre accettazioni ordinate |
| `c71_b12_canonical_pcs_codec`, `c71_b12_native_canonical_wire_body` | Cap e roundtrip di corpi completi sintetici, senza verifica crittografica |
| `c71_seed6_native_partial`, `c71_seed6_native_shortage` | Intervalli lazy, rifiuto prima della promozione e burn |
| `c71_seed6_native_replay_w_and_ordered_a` | Un tentativo O=0 con AES reale, t=4/h=19/ell=2, W ricostruita e A ordinata |
| `c71_seed6_native_full_o0_proof`, `c71_seed6_native_full_o0_late_rejection` | Un tentativo ridotto con A densa piccola, ell=11; positivo e rifiuto terminale |

Per modifiche a operatori/GKR/lookup aggiungere i rispettivi test componenti
esistenti e la parità integrata. Per modifiche a Seed6/Lifetime compilare
miratamente `volta-pcg --features c71-b11 --lib --no-run`, con lo stesso
target/profilo, e verificare separatamente i filtri `c71_seed6_one_channel`,
`c71_seed6_journal`, `c71_seed6_attempt_window`, `c71_seed6_trie`,
`c71_seed6_guard_cggm` e `c71_lifetime::tests`, sempre entro 60 s/2 GiB.

`c71_b12_native_ordered_two_attempts` è ignorato dopo un timeout locale:
non usare `--ignored` o un limite maggiore. Non eseguire l'intero filtro
`c71_seed6_native` sotto un unico timeout. Le geometrie ridotte non
trasferiscono i bound crittografici o il picco al profilo canonico ell=11.

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

La verifica di questa riorganizzazione e gli eventuali fallimenti sono
registrati nell'[audit documentale](../c7.1-history/reorganization-audit.md).
Questa pagina contiene comandi e significato dei test; l'archivio conserva
gli esiti datati. Dopo il checkpoint e prima di terminare la sessione
rimuovere la cache canonica `rust/target`, preservando fixture ed evidenze;
conservarla richiede un'indicazione del proprietario. Non creare target
alternativi per singoli crate. `.cargo/config.toml` imposta
`target-cpu=native`: i tempi CPU non si trasferiscono a un'altra macchina.
